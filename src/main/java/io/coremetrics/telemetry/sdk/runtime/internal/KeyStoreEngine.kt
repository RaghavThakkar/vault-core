package io.coremetrics.telemetry.sdk.runtime.internal

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import timber.log.Timber
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Modern Android KeyStore-backed AES/GCM encryption and decryption utilities.
 * Centralizes hardware-backed security logic for use in Preferences and Database.
 */
object KeyStoreEngine {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val AES_MODE = "AES/GCM/NoPadding"
    private const val MASTER_KEY_ALIAS = "master_key_v1"
    private const val IV_SIZE = 12 // Standard GCM IV size
    private const val TAG_SIZE = 128 // Standard GCM Authentication Tag size

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    /**
     * Retrieves the existing master key or generates a new one within the hardware-backed Keystore.
     */
    private fun getOrGenerateMasterKey(): SecretKey {
        val existingKey = keyStore.getEntry(MASTER_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existingKey != null) return existingKey.secretKey

        Timber.Forest.tag("CryptoEngine").d("KeyStoreEngine: Generating new hardware-backed MasterKey")
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()

        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    /**
     * Encrypts plain text using AES/GCM and returns a Base64 encoded string containing [IV + Ciphertext].
     */
    fun encrypt(plainText: String): String {
        if (plainText.isEmpty()) return ""
        return try {
            val cipher = Cipher.getInstance(AES_MODE)
            cipher.init(Cipher.ENCRYPT_MODE, getOrGenerateMasterKey())

            val iv = cipher.iv
            val encrypted = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

            // Package IV and Encrypted data together
            val combined = ByteArray(iv.size + encrypted.size)
            System.arraycopy(iv, 0, combined, 0, iv.size)
            System.arraycopy(encrypted, 0, combined, iv.size, encrypted.size)

            Base64.encodeToString(combined, Base64.NO_WRAP)
        } catch (e: Exception) {
            Timber.Forest.tag("CryptoEngine").e(e, "KeyStoreEngine: Encryption failed")
            ""
        }
    }

    /**
     * Decrypts a Base64 encoded string [IV + Ciphertext] back to plain text.
     */
    fun decrypt(encryptedText: String): String? {
        if (encryptedText.isEmpty()) return null
        return try {
            val combined = Base64.decode(encryptedText, Base64.NO_WRAP)
            if (combined.size < IV_SIZE) {
                Timber.Forest.tag("CryptoEngine").w("KeyStoreEngine: Malformed encrypted data (too short)")
                return null
            }

            // Extract IV
            val iv = ByteArray(IV_SIZE)
            System.arraycopy(combined, 0, iv, 0, iv.size)

            // Extract Ciphertext
            val encrypted = ByteArray(combined.size - iv.size)
            System.arraycopy(combined, iv.size, encrypted, 0, encrypted.size)

            val cipher = Cipher.getInstance(AES_MODE)
            val spec = GCMParameterSpec(TAG_SIZE, iv)
            cipher.init(Cipher.DECRYPT_MODE, getOrGenerateMasterKey(), spec)

            String(cipher.doFinal(encrypted), Charsets.UTF_8)
        } catch (e: Exception) {
            Timber.Forest.tag("CryptoEngine").e(e, "KeyStoreEngine: Decryption failed")
            null
        }
    }
}