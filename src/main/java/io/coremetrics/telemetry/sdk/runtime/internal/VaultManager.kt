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

    // @FastNative: eliminates the ArtMethod->JNI stub transition overhead (2-3× faster dispatch).
    // Safe for API 26+ (minSdk=26). Method may still use JNI freely; GC suspends the thread.
    @FastNative private external fun mV5xK8pJ(): FloatArray
    @FastNative private external fun vM2nQ5xR(aiMasterKey: ByteArray): ByteArray
    @FastNative private external fun getAppSignatureHashRaw(): ByteArray
    @FastNative private external fun nativeExecutePipeline(assetName: String, rootSeed: ByteArray): String?

    /**
     * PHASE 1: AI Execution + Multi-Factor Fusion → Master Root Seed (32B)
     */
    fun unlockMasterKey(): ByteArray {
        val startTime = System.currentTimeMillis()
        var rootSeed = ByteArray(32)
        try {
            // 1. Get secret constants (Attempt native first, then Kotlin fallback)
            val aiInputs = try {
                mV5xK8pJ()
            } catch (_: Throwable) {
                Timber.tag("VaultManager").w("mV5xK8pJ native call failed, using Kotlin fallback")
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

            // 2. Load TFLite Model robustly via Memory Mapping
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
                Timber.tag("VaultManager").d("Native multi-factor fusion successful")
            } catch (_: Throwable) {
                Timber.tag("VaultManager").w("vM2nQ5xR native call failed, using Kotlin fallback")
                val sigHash = try {
                    getAppSignatureHashRaw()
                } catch (ex: Throwable) {
                    Timber.tag("VaultManager")
                        .w("getAppSignatureHashRaw native call failed: ${ex.message}")
                    ByteArray(32)
                }

                if (sigHash.size == 32) {
                    for (i in 0 until 32) {
                        rootSeed[i] = (sigHash[i].toInt() xor aiRawSeed[i].toInt()).toByte()
                    }
                }
                sigHash.fill(0)
            }


            // Scrub secrets
            aiRawSeed.fill(0)
            val duration = System.currentTimeMillis() - startTime
            Timber.tag("AI_VAULT").d("success | time: %dms", duration)
        } catch (e: Exception) {
            Timber.e(e, "DEBUG_AI_VAULT_ERROR: ${e.message}")
            // Fallback key
            return "AI_FALLBACK_KEY_32_BYTES_0123456".toByteArray()
        }
        return rootSeed
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

    fun executeVaughanPipeline(assetName: String): String? {
        val rootSeed = unlockMasterKey()
        if (rootSeed.all { it == 0.toByte() }) {
            Timber.tag("VaultManager").e("Pipeline aborted: Master key is null or all zeros")
            return null
        }
        return try {
            nativeExecutePipeline(assetName, rootSeed)
        } catch (e: Exception) {
            Timber.tag("VaultManager").e(e, "Pipeline failed for $assetName")
            null
        } finally {
            rootSeed.fill(0)
        }
    }
}

