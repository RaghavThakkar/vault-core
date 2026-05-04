package io.coremetrics.telemetry.sdk.runtime.internal

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import timber.log.Timber
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Hardware-backed AES/GCM encryption — two-tier key design.
 *
 * Single cached key ([cachedKey]):
 *   • Preferred: software SecretKeySpec unwrapped from EncryptedPref via one TEE op.
 *   • Fallback:  hardware TEE key used directly if the software key cannot be loaded.
 *
 * Call [initialize] once from Application.onCreate() AFTER EncryptedPref is initialized.
 * If not called, the key is resolved lazily on first [encrypt]/[decrypt].
 *
 * Migration: rows encrypted with the old hardware key are decrypted transparently on read.
 */
object KeyStoreEngine {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val AES_MODE = "AES/GCM/NoPadding"
    private const val MASTER_KEY_ALIAS = "master_key_v1"
    private const val IV_SIZE = 12
    private const val TAG_SIZE = 128
    private const val SESSION_KEY_PREF = "ks_session_key_v1"

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    /**
     * Single in-memory key cache.
     * Holds a SecretKeySpec (software) on the happy path, or the raw hardware SecretKey
     * if the software session key could not be loaded/created.
     */
    @Volatile private var cachedKey: SecretKey? = null

    private val encryptCipherPool = ThreadLocal.withInitial { Cipher.getInstance(AES_MODE) }
    private val decryptCipherPool = ThreadLocal.withInitial { Cipher.getInstance(AES_MODE) }

    // ── Public API ────────────────────────────────────────────────────────────

    /** Optional warm-up — resolves and caches the key before Room opens the DB. */
    fun initialize() { getOrCreateKey() }

    fun encrypt(plainText: String): String {
        if (plainText.isEmpty()) return ""
        return encryptWithKey(plainText, getOrCreateKey()) ?: ""
    }

    fun decrypt(encryptedText: String): String? {
        if (encryptedText.isEmpty()) return null
        val key = getOrCreateKey()
        val result = decryptWithKey(encryptedText, key)
        if (result != null) return result
        // Migration fallback: row was encrypted directly with the hardware key
        // (only relevant when cachedKey is a software SecretKeySpec)
        if (key is SecretKeySpec) {
            Timber.tag("CryptoEngine").d("KeyStoreEngine: software decrypt miss — trying hardware key (migration)")
            return decryptWithKey(encryptedText, fetchHardwareKey())
        }
        return null
    }

    // ── Key resolution ────────────────────────────────────────────────────────

    @Synchronized
    private fun getOrCreateKey(): SecretKey {
        cachedKey?.let { return it }
        val key = tryLoadSoftwareKey() ?: run {
            Timber.tag("CryptoEngine").w("KeyStoreEngine: software key unavailable — using hardware key")
            fetchHardwareKey()
        }
        cachedKey = key
        Timber.tag("CryptoEngine").d("KeyStoreEngine: cachedKey ready (${if (key is SecretKeySpec) "software" else "hardware"})")
        return key
    }

    private fun tryLoadSoftwareKey(): SecretKeySpec? {
        return try {
            val stored = EncryptedPref.getString(SESSION_KEY_PREF, "")
            if (!stored.isNullOrEmpty()) {
                val keyBase64 = decryptWithKey(stored, fetchHardwareKey())
                if (keyBase64 != null) {
                    SecretKeySpec(Base64.decode(keyBase64, Base64.NO_WRAP), "AES")
                } else {
                    Timber.tag("CryptoEngine").w("KeyStoreEngine: stored session key unreadable — regenerating")
                    generateAndStoreSoftwareKey()
                }
            } else {
                generateAndStoreSoftwareKey()
            }
        } catch (e: Exception) {
            Timber.tag("CryptoEngine").e(e, "KeyStoreEngine: failed to load software key")
            null
        }
    }

    private fun generateAndStoreSoftwareKey(): SecretKeySpec {
        val keyBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val keyBase64 = Base64.encodeToString(keyBytes, Base64.NO_WRAP)
        val wrapped = encryptWithKey(keyBase64, fetchHardwareKey()) ?: ""
        EncryptedPref.save(SESSION_KEY_PREF, wrapped)
        Timber.tag("CryptoEngine").d("KeyStoreEngine: new software session key generated and stored")
        return SecretKeySpec(keyBytes, "AES")
    }

    // ── Hardware key (TEE) ────────────────────────────────────────────────────

    /** Fetches (or generates) the TEE-backed master key. Not cached here —
     *  [cachedKey] is the single cache; hardware key is only needed during key setup. */
    private fun fetchHardwareKey(): SecretKey {
        val existing = keyStore.getEntry(MASTER_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey
        Timber.tag("CryptoEngine").d("KeyStoreEngine: generating hardware master key")
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        kg.init(
            KeyGenParameterSpec.Builder(
                MASTER_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return kg.generateKey()
    }

    // ── Crypto primitives (shared by both key types) ──────────────────────────

    private fun encryptWithKey(plainText: String, key: SecretKey): String? {
        return try {
            val cipher = if (key is SecretKeySpec) encryptCipherPool.get() ?: Cipher.getInstance(AES_MODE)
                         else Cipher.getInstance(AES_MODE)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            val encrypted = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
            Base64.encodeToString(iv + encrypted, Base64.NO_WRAP)
        } catch (e: Exception) {
            Timber.tag("CryptoEngine").e(e, "KeyStoreEngine: encrypt failed")
            null
        }
    }

    private fun decryptWithKey(encryptedText: String, key: SecretKey): String? {
        return try {
            val combined = Base64.decode(encryptedText, Base64.NO_WRAP)
            if (combined.size <= IV_SIZE) return null
            val iv = combined.copyOfRange(0, IV_SIZE)
            val data = combined.copyOfRange(IV_SIZE, combined.size)
            val cipher = if (key is SecretKeySpec) decryptCipherPool.get() ?: Cipher.getInstance(AES_MODE)
                         else Cipher.getInstance(AES_MODE)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_SIZE, iv))
            String(cipher.doFinal(data), Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }
}