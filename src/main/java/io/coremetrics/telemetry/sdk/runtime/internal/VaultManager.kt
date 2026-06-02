package io.coremetrics.telemetry.sdk.runtime.internal

import android.content.Context
import dalvik.annotation.optimization.FastNative
import org.tensorflow.lite.Interpreter
import timber.log.Timber
import java.io.FileInputStream
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel

class VaultManager(private val context: Context) {

    init {
        try {
            System.loadLibrary("native-lib")
        } catch (e: Exception) {
            Timber.tag("VaultManager")
                .e("Native library failed to load, using Kotlin fallback: ${e.message}")
        }
    }

    fun vX8k_M3pL(input: String): ByteArray {
        return try {
            val md = java.security.MessageDigest.getInstance("SHA-512")
            val digest = md.digest(input.toByteArray())
            digest.copyOfRange(0, 16)
        } catch (e: Exception) {
            ByteArray(16)
        }
    }

    @FastNative private external fun mV5xK8pJ(): FloatArray
    private external fun vM2nQ5xR(aiMasterKey: ByteArray): ByteArray
    private external fun nativeExecutePipeline(assetName: String, label: String, rootSeed: ByteArray): String?

    /**
     * PHASE 1: AI Execution + Multi-Factor Fusion → Master Root Seed (32B)
     */
    fun unlockMasterKey(): ByteArray {
        val startTime = System.currentTimeMillis()
        var rootSeed = ByteArray(32)
        try {
            // 1. Get secret constants
            val aiInputs = try {
                mV5xK8pJ()
            } catch (_: Throwable) {
                floatArrayOf(
                    0.64769125f, 0.99691355f, 0.51880324f, 0.65811270f,
                    0.59906346f, 0.75306731f, 0.13624713f, 0.00411712f,
                    0.14950888f, 0.69843900f, 0.59335256f, 0.89991534f,
                    0.44445738f, 0.31678501f, 0.92308176f, 0.46586186f,
                    0.79836458f, 0.19915871f, 0.81451899f, 0.14347456f,
                    0.68348515f, 0.05661583f, 0.78367531f, 0.73656690f,
                    0.77044433f, 0.18667571f, 0.04997537f, 0.88998115f,
                    0.17367290f, 0.77317935f, 0.28343952f, 0.65596682f,
                    0.98916560f, 0.27378929f, 0.41827640f, 0.77468133f,
                    0.25745293f, 0.05423971f, 0.86471438f, 0.25695303f,
                    0.40226847f, 0.30813143f, 0.97151226f, 0.57636458f,
                    0.26928008f, 0.87206155f, 0.07803559f, 0.76783913f,
                    0.64167356f, 0.19411802f, 0.74487513f, 0.95631886f,
                    0.75249320f, 0.67002594f, 0.59444720f, 0.18984810f,
                    0.42716438f, 0.81242037f, 0.75882542f, 0.71038717f,
                    0.10320329f, 0.83518142f, 0.49804452f, 0.54264235f
                )
            }

            // 2. Load TFLite Model
            val tfliteModel = loadModelFile("vault.tflite")
            val tflite = Interpreter(tfliteModel)

            // 3. AI Execution
            val outputBuffer = Array(1) { FloatArray(32) }
            tflite.run(arrayOf(aiInputs), outputBuffer)

            val aiRawSeed = ByteArray(32)
            for (i in 0 until 32) {
                aiRawSeed[i] = (outputBuffer[0][i] * 255.0f).toInt().toByte()
            }
            tflite.close()

            // 4. Multi-Factor Fusion
            try {
                rootSeed = vM2nQ5xR(aiRawSeed)
            } catch (_: Throwable) {
                val sigHash = getAppSignatureHashRawKotlin()
                for (i in 0 until 32) {
                    rootSeed[i] = (sigHash[i].toInt() xor aiRawSeed[i].toInt()).toByte()
                }
            }
            aiRawSeed.fill(0)
            Timber.tag("AI_VAULT").d("success | time: %dms", System.currentTimeMillis() - startTime)
        } catch (e: Exception) {
            Timber.tag("VaultManager").w("TFLite execution failed, using fallback path: ${e.message}")
            val aiRawSeed = "AI_FALLBACK_KEY_32_BYTES_0123456".toByteArray()
            try {
                rootSeed = vM2nQ5xR(aiRawSeed)
            } catch (_: Throwable) {
                val sigHash = getAppSignatureHashRawKotlin()
                for (i in 0 until 32) {
                    rootSeed[i] = (sigHash[i].toInt() xor aiRawSeed[i].toInt()).toByte()
                }
            }
        }
        return rootSeed
    }

    private fun getAppSignatureHashRawKotlin(): ByteArray {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                android.content.pm.PackageManager.GET_SIGNATURES
            )
            val signatures = packageInfo.signatures
            if (signatures != null && signatures.isNotEmpty()) {
                val signature = signatures[0].toByteArray()
                val md = java.security.MessageDigest.getInstance("SHA-256")
                md.digest(signature)
            } else {
                ByteArray(32)
            }
        } catch (e: Exception) {
            ByteArray(32)
        }
    }

    private fun loadModelFile(modelFilename: String): MappedByteBuffer {
        val fileDescriptor = context.assets.openFd(modelFilename)
        val inputStream = FileInputStream(fileDescriptor.fileDescriptor)
        val fileChannel = inputStream.channel
        return fileChannel.map(
            FileChannel.MapMode.READ_ONLY,
            fileDescriptor.startOffset,
            fileDescriptor.declaredLength
        )
    }

    fun executeVaughanPipeline(assetName: String, label: String): String? {
        val rootSeed = unlockMasterKey()
        if (rootSeed.all { it == 0.toByte() }) {
            Timber.tag("VaultManager").e("Pipeline aborted: Master key is all zeros")
            return null
        }
        return try {
            nativeExecutePipeline(assetName, label, rootSeed)
        } catch (e: Exception) {
            Timber.tag("VaultManager").e(e, "Pipeline failed for $assetName")
            null
        } finally {
            rootSeed.fill(0)
        }
    }
}
