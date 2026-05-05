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
 * Fast bulk AES-256-GCM encryption — two-tier key design.
 *
 * Tier 1 – Hardware master key (TEE/StrongBox):
 *   Used exactly ONCE per app launch to wrap/unwrap the software session key.
 *   Never used for individual field encryption.
 *
 * Tier 2 – Software session key (in-memory SecretKeySpec):
 *   Used for ALL encrypt/decrypt calls.
 *   Pure JCE — no TEE round-trips — 50-100× faster than direct hardware key usage.
 *
 * Call [initialize] once from Application.onCreate() AFTER EncryptedPref.initPref().
 * If not called, the session key is resolved lazily on first [encrypt]/[decrypt] call.
 */
object KeyStoreEngine {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val AES_MODE         = "AES/GCM/NoPadding"
    private const val MASTER_KEY_ALIAS = "bulk_master_key_v1"
    private const val IV_SIZE          = 12
    private const val TAG_SIZE         = 128
    private const val SESSION_KEY_PREF = "bulk_session_key_v1"

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    // ── Software session key ──────────────────────────────────────────────────
    @Volatile private var sessionKey: SecretKeySpec? = null

    // ── Hardware key cache (used once per launch during session key wrap/unwrap) ─
    @Volatile private var cachedHwKey: SecretKey? = null

    // ── ThreadLocal Cipher pool — one Cipher per thread, reused via init() ───
    private val cipherPool = ThreadLocal.withInitial { Cipher.getInstance(AES_MODE) }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Optional warm-up — pre-loads the session key before Room opens the DB.
     * Performs exactly ONE hardware KeyStore operation (session key unwrap).
     */
    fun initialize() { getOrCreateSessionKey() }

    fun encrypt(plainText: String): String {
        if (plainText.isEmpty()) return ""
        return encryptWith(plainText, getOrCreateSessionKey()) ?: ""
    }

    fun decrypt(encryptedText: String): String? {
        if (encryptedText.isEmpty()) return null
        return decryptWith(encryptedText, getOrCreateSessionKey())
    }

    // ── Session key management ────────────────────────────────────────────────

    @Synchronized
    private fun getOrCreateSessionKey(): SecretKeySpec {
        sessionKey?.let { return it }
        val key = loadOrCreateSessionKey()
        sessionKey = key
        Timber.tag("CryptoEngine").d("KeyStoreEngine: session key ready")
        return key
    }

    private fun loadOrCreateSessionKey(): SecretKeySpec {
        val stored = EncryptedPref.getString(SESSION_KEY_PREF, "")
        if (!stored.isNullOrEmpty()) {
            val keyBase64 = decryptWith(stored, fetchHwKey())
            if (keyBase64 != null) {
                return SecretKeySpec(Base64.decode(keyBase64, Base64.NO_WRAP), "AES")
            }
            Timber.tag("CryptoEngine").w("KeyStoreEngine: stored session key unreadable — regenerating")
        }
        return generateAndStoreSessionKey()
    }

    private fun generateAndStoreSessionKey(): SecretKeySpec {
        val keyBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val keyBase64 = Base64.encodeToString(keyBytes, Base64.NO_WRAP)
        val wrapped = encryptWith(keyBase64, fetchHwKey()) ?: ""
        EncryptedPref.save(SESSION_KEY_PREF, wrapped)
        Timber.tag("CryptoEngine").d("KeyStoreEngine: new session key generated and stored")
        return SecretKeySpec(keyBytes, "AES")
    }

    // ── Hardware key (TEE-backed, wrap/unwrap only) ───────────────────────────

    @Synchronized
    private fun fetchHwKey(): SecretKey {
        cachedHwKey?.let { return it }
        val existing = keyStore.getEntry(MASTER_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        val key = if (existing != null) {
            existing.secretKey
        } else {
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
            kg.generateKey()
        }
        cachedHwKey = key
        return key
    }

    // ── Crypto primitives ─────────────────────────────────────────────────────

    private fun encryptWith(plainText: String, key: SecretKey): String? {
        return try {
            val cipher = if (key is SecretKeySpec) cipherPool.get()!! else Cipher.getInstance(AES_MODE)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            val encrypted = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
            val out = ByteArray(IV_SIZE + encrypted.size)
            System.arraycopy(iv, 0, out, 0, IV_SIZE)
            System.arraycopy(encrypted, 0, out, IV_SIZE, encrypted.size)
            Base64.encodeToString(out, Base64.NO_WRAP)
        } catch (e: Exception) {
            Timber.tag("CryptoEngine").e(e, "KeyStoreEngine: encrypt failed")
            null
        }
    }

    private fun decryptWith(encryptedText: String, key: SecretKey): String? {
        return try {
            val combined = Base64.decode(encryptedText, Base64.NO_WRAP)
            if (combined.size <= IV_SIZE) return null
            val cipher = if (key is SecretKeySpec) cipherPool.get()!! else Cipher.getInstance(AES_MODE)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_SIZE, combined, 0, IV_SIZE))
            String(cipher.doFinal(combined, IV_SIZE, combined.size - IV_SIZE), Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }
}