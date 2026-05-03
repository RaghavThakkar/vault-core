package io.coremetrics.telemetry.sdk.runtime.internal

import android.content.Context
import timber.log.Timber
import java.security.MessageDigest

object CryptoEngine {

    init {
        try {
            System.loadLibrary("native-lib")
        } catch (e: Exception) {
            Timber.Forest.tag("CryptoEngine").e("Native library failed to load")
        }
    }

    // ─── Utility ─────────────────────────────────────────────────────────────

    fun calculateAssetHash(context: Context, assetName: String): String {
        return try {
            val md = MessageDigest.getInstance("SHA-256")
            context.assets.open(assetName).use { input ->
                val buffer = ByteArray(8192)
                var bytesRead = input.read(buffer)
                while (bytesRead != -1) {
                    md.update(buffer, 0, bytesRead)
                    bytesRead = input.read(buffer)
                }
            }
            md.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            ""
        }
    }
}