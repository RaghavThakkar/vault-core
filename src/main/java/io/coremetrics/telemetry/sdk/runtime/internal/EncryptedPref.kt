package io.coremetrics.telemetry.sdk.runtime.internal

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import timber.log.Timber
import java.security.MessageDigest
import java.security.SecureRandom

class EncryptedPref {

    companion object {

        private var MASTER_KEY_ALIAS = "master_key_v1"
        var currentLanguage: String = "en"
        var currentState: String = "mh"
        val KEY_DISCLAIMER = "Disclaimer"
        
        lateinit var sharedPreferences: SharedPreferences

        val instance: EncryptedPref by lazy(LazyThreadSafetyMode.PUBLICATION) { EncryptedPref() }

        /**
         * Saves a value as plain text (fast).
         */
        fun save(key: String?, value: String? = "") {
            saveInternal(key, value)
        }

        fun save(key: String?, value: Long = 0) {
            if (key == null) return
            sharedPreferences.edit().putLong(hashKey(key), value).apply()
        }

        fun save(key: String?, value: Int = 0) {
            if (key == null) return
            sharedPreferences.edit().putInt(hashKey(key), value).apply()
        }

        fun save(key: String?, value: Boolean = false) {
            if (key == null) return
            sharedPreferences.edit().putBoolean(hashKey(key), value).apply()
        }

        /**
         * Saves a value encrypted using Hardware KeyStore (slow).
         * Use only for extremely sensitive data.
         */
        fun saveSecure(key: String?, value: String?) {
            if (key == null) return
            try {
                val cipherText = KeyStoreEngine.encrypt(value ?: "")
                if (cipherText.isNotEmpty()) {
                    saveInternal(key, cipherText)
                }
            } catch (e: Exception) {
                Timber.tag("CryptoEngine").e(e, "EncryptedPref: saveSecure failed for $key")
            }
        }

        fun saveSecure(key: String, value: Long) {
            saveSecure(key, value.toString())
        }

        fun getSecureString(key: String, defValue: String = ""): String {
            val encryptedValue = getString(key, "")
            if (encryptedValue.isNullOrEmpty()) return defValue

            val decrypted = KeyStoreEngine.decrypt(encryptedValue)
            return decrypted ?: defValue
        }

        fun getSecureLong(key: String, defValue: Long = 0): Long {
            val value = getSecureString(key, "")
            return value.toLongOrNull() ?: defValue
        }

        fun getString(key: String, defValue: String = ""): String? {
            return sharedPreferences.getString(hashKey(key), defValue)
        }

        fun getLong(key: String, defValue: Long = 0): Long {
            return sharedPreferences.getLong(hashKey(key), defValue)
        }

        fun getInt(key: String, defValue: Int = 0): Int {
            return sharedPreferences.getInt(hashKey(key), defValue)
        }

        fun getBoolean(key: String, defValue: Boolean = false): Boolean {
            return sharedPreferences.getBoolean(hashKey(key), defValue)
        }

        private fun hashKey(key: String?): String? {
            if (key == null) return null
            return try {
                val md = MessageDigest.getInstance("SHA-256")
                md.update(MASTER_KEY_ALIAS.toByteArray())
                val digest = md.digest(key.toByteArray(Charsets.UTF_8))
                digest.joinToString("") { "%02x".format(it) }
            } catch (ignore: Exception) {
                key
            }
        }

        private fun saveInternal(key: String?, value: String?) {
            if (key == null) return
            sharedPreferences.edit().putString(hashKey(key), value).apply()
        }

        fun generateSecurityKey(shouldRegenerateKeys: Boolean = false): String {
            val encryptedKey = getString(PrefKeys.MasterKeys.name, "")
            val decryptedKey =
                if (encryptedKey.isNullOrEmpty()) null else KeyStoreEngine.decrypt(encryptedKey)

            return if (decryptedKey == null || shouldRegenerateKeys) {
                val bytes = ByteArray(32)
                SecureRandom().nextBytes(bytes)
                val newKey = Base64.encodeToString(bytes, Base64.NO_WRAP)
                val newEncryptedKey = KeyStoreEngine.encrypt(newKey)
                saveInternal(PrefKeys.MasterKeys.name, newEncryptedKey)
                newKey
            } else {
                decryptedKey
            }
        }

        fun getOrGenerateSalt(): String {
            val salt = getString(PrefKeys.SaltActions.name, "")
            return if (salt.isNullOrEmpty()) {
                val bytes = ByteArray(32)
                SecureRandom().nextBytes(bytes)
                val newSalt = Base64.encodeToString(bytes, Base64.NO_WRAP)
                saveInternal(PrefKeys.SaltActions.name, newSalt)
                newSalt
            } else {
                salt
            }
        }
    }

    fun initPref(context: Context) {
        sharedPreferences = context.getSharedPreferences(
            PrefKeys.AppPrefV3.name,
            Context.MODE_PRIVATE
        )
        randomized()
    }

    fun randomized() {
        generateDecoyKeys()
        generateSecurityKey()
        getOrGenerateSalt()
    }

    private fun generateDecoyKeys() {
        if (getLong("decoy_init", 0) == 1L) return
        val decoys = mapOf(
            "ZGVidWdfYXBpX3NlY3JldA==" to "YTM0ZGZlM2EtN2I5Yy00YmYxLWE1ZTYtZTcxYjI5ZDA5MDUz",
            "YWRtaW5fYWNjZXNzX3Rva2Vu" to "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ",
            "cGF5bWVudF9nYXRld2F5X3NhbmRib3hfa2V5" to "pk_test_51MzZ2SGV2YmFyYmF6X2tleV9leHBpcmVk",
            "ZmlyZWJhc2VfbGVnYWN5X3NlcnZlcl9rZXk=" to "AAAAbXhfX1E6QVBJSXNfX3NlcnZlcl9rZXlfZG9fbm90X3VzZV9pbl9wcm9kdWN0aW9u",
            "aXNfaW50ZXJuYWxfdGVzdGVy" to "true",
            "ZW5jcnlwdGlvbl9pdl9sZWdhY3k=" to "MTIzNDU2Nzg5MDEyMzQ1Ng==",
            "ZGV2ZWxvcGVyX2J5cGFzc19jb2Rlcw==" to "7734, 1337, 9001, 4242",
            "b2JmdXNjYXRpb25fc2VlZF92MQ==" to "0xDEADBEEFCAFEBABEA5550123456789",
            "YW5hbHl0aWNzX3NhbXBsaW5nX3JhdGU=" to "100",
            "dXNlcl9zZXNzaW9uX3BlcnNpc3RlbmNlX2tleQ==" to "aGFzaGVkX3Nlc3Npb25fMTY4MjQ1NjAwMDAwMA==",
            "bGFzdF9zZWN1cml0eV9oZWFydGJlYXQ=" to "1714123200",
            "bWl4cGFuZWxfdG9rZW5fcHJvZA==" to "46f82739b00145a2a9e38d7f6c5b4e3d",
            "c2VnbWVudF93cml0ZV9rZXk=" to "i7h2G5k8L1mN4pQ3rT6vX9zB2yD5fH8j",
            "b25lc2lnbmFsX2FwcF9pZA==" to "550e8400-e29b-41d4-a716-446655440000",
            "aW50ZXJjb21fYXBwX2lk" to "z4b9x2m1",
            "ZGF0YWRvZ19jbGllbnRfdG9rZW4=" to "pub1a2b3c4d5e6f7g8h9i0j",
            "b2t0YV9jbGllbnRfaWQ=" to "0oa1b2c3d4e5f6g7h8i9",
            "c3RyaXBlX3B1Ymxpc2hhYmxlX2tleQ==" to "pk_live_51ABCDEFG12345678",
            "cmF6b3JwYXlfa2V5X2lk" to "rzp_live_9i8u7y6t5r4e3w",
            "YnJhaW50cmVlX3Rva2VuaXphdGlvbl9rZXk=" to "production_x7y8z9w0",
            "YXBwX2NlbnRlcl9hcHBfc2VjcmV0" to "c1b2a3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6",
            "bGF1bmNoZGFya2x5X21vYmlsZV9rZXk=" to "mob-a1b2c3d4-e5f6-7g8h-9i0j",
            "YW1wbGl0dWRlX2FwaV9rZXk=" to "f1e2d3c4b5a697887766554433221100",
            "YnJhbmNoX2lvX2tleQ==" to "key_live_h8g7f6e5d4c3b2a1",
            "ZmFjZWJvb2tfYXBwX3NlY3JldF92Mg==" to "3b2a1c4d5e6f7g8h9i0j1k2l3m4n5o6p",
            "Z29vZ2xlX21hcHNfYXBpX2tleV9yZXN0cmljdGVk" to "AIzaSyB1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q",
            "YXp1cmVfc3RvcmFnZV9jb25uZWN0aW9uX3N0cmluZw==" to "DefaultEndpointsProtocol=https;AccountName=appsbox;AccountKey=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6==;EndpointSuffix=core.windows.net",
            "ZWxhc3RpY19jbG91ZF9pZA==" to "AppsBox_Internal:dXMtZWFzdC0xLmF3cy5mb3VuZC5pbyQ0YjNjMmQxZTVmNmc3aDhpOWowazFsMm0zbjRvNXA2cTdyOHM5dDB1MXYydzN4NHk1ejY=",
            "cGVuZG9fYXBpX2tleQ==" to "9a8b7c6d-5e4f-3g2h-1i0j-k1l2m3n4o5p6",
            "bmV3cmVsaWNfbGljZW5zZV9rZXk=" to "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t",
            "YnVnc25hZ19hcGlfa2V5" to "e1d2c3b4a59687786756453423120191",
            "YXBwc2ZseWVyX2Rldl9rZXk=" to "W6v5U4t3S2r1Q0p9O8n7M6l",
            "YWRqdXN0X2FwcF90b2tlbg==" to "a1b2c3d4e5f6",
            "aW5zdGFidWdfdG9rZW4=" to "b1a2c3d4e5f6g7h8i9j0",
            "bG9jYWx5dGljc19hcHBfa2V5" to "c1b2a3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
            "bGVhbnBsdW1fYXBwX2lk" to "app_1a2b3c4d5e6f",
            "Y2xldmVydGFwX2FjY291bnRfaWQ=" to "W8W-W8W-W8W",
            "bW9lbmdhZ2VfYXBwX2lk" to "M1N2O3P4Q5R6S7T8U9V0",
            "aG90amFyX3NpdGVfaWQ=" to "1234567",
            "ZnVsbHN0b3J5X29yZ19pZA==" to "O1P2Q3R4",
            "cm9sbGJhcl9hY2Nlc3NfdG9rZW4=" to "f1e2d3c4b5a697887766554433221100",
            "aG9uZXliYWRnZXJfYXBpX2tleQ==" to "h1g2f3e4d5c6b7a8",
            "YWlyYnJha2VfcHJvamVjdF9pZA==" to "987654",
            "cmF5Z3VuX2FwaV9rZXk=" to "r1q2p3o4n5m6l7k8",
            "bWFpbGd1bl9hcGlfa2V5" to "key-1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p",
            "c2VuZGdyaWRfYXBpX2tleQ==" to "SG.a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6",
            "dHdpbGlvX2FjY291bnRfc2lk" to "AC1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p",
            "bWVzc2FnZWJpcmRfYWNjZXNzX2tleQ==" to "m1n2o3p4q5r6s7t8u9v0",
            "bmV4bW9fYXBpX2tleQ==" to "a1b2c3d4",
            "cHVzaGVyX2FwcF9pZA==" to "123456",
            "cHVibnViX3B1Ymxpc2hfa2V5" to "pub-c-1a2b3c4d-e5f6-7g8h-9i0j-k1l2m3n4o5p6",
            "YWJseV9hcGlfa2V5" to "a1b2c3.d4e5f6:g7h8i9j0k1l2m3n4",
            "YWxnb2xpYV9hcHBsaWNhdGlvbl9pZA==" to "A1B2C3D4E5",
            "aW1naXhfdG9rZW4=" to "i1h2g3f4e5d6c7b8a9",
            "Y29udGVudGZ1bF9zcGFjZV9pZA==" to "s1t2u3v4w5x6",
            "Z2hvc3RfYWRtaW5fYXBpX2tleQ==" to "5f6e7d8c9b0a1a2b3c4d5e6f:g7h8i9j0k1l2m3n4o5p6q7r8s9t0v1v2",
            "c2hvcGlmeV9hY2Nlc3NfdG9rZW4=" to "shpat_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p",
            "d29yZHByZXNzX2FwaV9wYXNzd29yZA==" to "a1b2 c3d4 e5f6 g7h8 i9j0 k1l2",
            "Yml0bHlfYWNjZXNzX3Rva2Vu" to "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
        )

        decoys.forEach { (key, value) ->
            saveSecure(String(Base64.decode(key, Base64.NO_WRAP)), value)
        }
        save("decoy_init", 1L)
    }
}