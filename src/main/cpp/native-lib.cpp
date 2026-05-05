#include <jni.h>
#include <string>
#include <vector>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <android/log.h>

#define LOG_TAG "VaultManager"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// ─── AAssetManager (native asset reading) ─────────────────────────────────
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>

/**
 * Portable secure wipe.
 */
static void secure_wipe(void *ptr, size_t len) {
    if (!ptr) return;
    volatile uint8_t *p = reinterpret_cast<volatile uint8_t *>(ptr);
    for (size_t i = 0; i < len; i++) p[i] = 0;
}

// ─── minimal self-contained SHA-256 (no OpenSSL needed) ────────────────────

static inline uint32_t RR(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_compress(uint32_t s[8], const uint8_t blk[64]) {
    static const uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
            0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc,
            0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351,
            0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
            0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585,
            0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
            0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2
    };
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t) blk[i * 4] << 24) | ((uint32_t) blk[i * 4 + 1] << 16) |
               ((uint32_t) blk[i * 4 + 2] << 8) | blk[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = RR(w[i - 15], 7) ^ RR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = RR(w[i - 2], 17) ^ RR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (RR(e, 6) ^ RR(e, 11) ^ RR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (RR(a, 2) ^ RR(a, 13) ^ RR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
    s[4] += e;
    s[5] += f;
    s[6] += g;
    s[7] += h;
}

static void sha256_hash(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t s[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint64_t bits = (uint64_t) len * 8;
    size_t padded = ((len + 9 + 63) / 64) * 64;
    uint8_t *buf = new uint8_t[padded]();
    memcpy(buf, data, len);
    buf[len] = 0x80;
    for (int i = 0; i < 8; i++) buf[padded - 8 + i] = (uint8_t) (bits >> (56 - 8 * i));
    for (size_t i = 0; i < padded; i += 64) sha256_compress(s, buf + i);
    delete[] buf;
    for (int i = 0; i < 8; i++) {
        out[i * 4 + 0] = (uint8_t) (s[i] >> 24);
        out[i * 4 + 1] = (uint8_t) (s[i] >> 16);
        out[i * 4 + 2] = (uint8_t) (s[i] >> 8);
        out[i * 4 + 3] = (uint8_t) (s[i]);
    }
}

// ─── Root / Jailbreak Detection ────────────────────────────────────────────
static bool check_root() {
    if (access("/system/bin/su", F_OK) == 0) {
        LOGD("SecurityCheck: /system/bin/su detected");
        return true;
    }
    if (access("/system/xbin/su", F_OK) == 0) {
        LOGD("SecurityCheck: /system/xbin/su detected");
        return true;
    }
    if (access("/data/adb/magisk", F_OK) == 0) {
        LOGD("SecurityCheck: /data/adb/magisk detected");
        return true;
    }
    return false;
}

// ─── Frida / injection detection ───────────────────────────────────────────
static bool check_frida() {
    if (check_root()) return true;
    static const unsigned char n1[] = {0x3c, 0x28, 0x33, 0x3e, 0x3b, 0x77, 0x3b, 0x3d, 0x3f, 0x34,
                                       0x2e}; // "frida-agent"
    char d1[12] = {};
    for (int i = 0; i < 11; i++) d1[i] = (char) (n1[i] ^ 0x5A);

    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd == -1) {
        LOGD("SecurityCheck: Failed to open /proc/self/maps");
        return false;
    }

    char buf[65536];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        LOGD("SecurityCheck: Failed to read /proc/self/maps");
        return false;
    }
    buf[n] = '\0';

    if (strstr(buf, d1) != nullptr) {
        LOGD("SecurityCheck: Frida agent detected in memory maps");
        return true;
    }
    return false;
}

// ─── Shared helper: SHA-256 of signing cert bytes ─────────────────────────
static void get_sig_hash(JNIEnv *env, jobject context, uint8_t out[32]) {
    memset(out, 0, 32);
    jclass ctxCls = env->GetObjectClass(context);
    jobject pm = env->CallObjectMethod(context,
                                       env->GetMethodID(ctxCls, "getPackageManager",
                                                        "()Landroid/content/pm/PackageManager;"));
    jstring pkgName = (jstring) env->CallObjectMethod(context,
                                                      env->GetMethodID(ctxCls, "getPackageName",
                                                                       "()Ljava/lang/String;"));
    if (!pm || !pkgName) {
        LOGD("get_sig_hash: Failed to get PM or PkgName");
        return;
    }
    jclass pmCls = env->GetObjectClass(pm);
    jobject info = env->CallObjectMethod(pm,
                                         env->GetMethodID(pmCls, "getPackageInfo",
                                                          "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;"),
                                         pkgName, (jint) 0x40);
    if (!info) {
        LOGD("get_sig_hash: Failed to get PackageInfo");
        return;
    }
    jclass infoCls = env->GetObjectClass(info);
    auto arr = (jobjectArray) env->GetObjectField(info,
                                                  env->GetFieldID(infoCls, "signatures",
                                                                  "[Landroid/content/pm/Signature;"));
    if (!arr || env->GetArrayLength(arr) == 0) {
        LOGD("get_sig_hash: No signatures found");
        return;
    }
    jobject sig0 = env->GetObjectArrayElement(arr, 0);
    jbyteArray rawSigArr = (jbyteArray) env->CallObjectMethod(sig0,
                                                              env->GetMethodID(
                                                                      env->GetObjectClass(sig0),
                                                                      "toByteArray", "()[B"));
    jsize sigLen = env->GetArrayLength(rawSigArr);
    jbyte *sigPtr = env->GetByteArrayElements(rawSigArr, nullptr);
    sha256_hash(reinterpret_cast<const uint8_t *>(sigPtr), (size_t) sigLen, out);
    env->ReleaseByteArrayElements(rawSigArr, sigPtr, JNI_ABORT);

    char sigHex[65] = {};
    for (int i = 0; i < 32; i++) snprintf(sigHex + i * 2, 3, "%02x", out[i]);
    LOGD("get_sig_hash: Signature Hash: %s", sigHex);
}

// ─── Read VaultManager.context field from 'thiz' ──────────────────────────
static jobject get_context(JNIEnv *env, jobject thiz) {
    jclass cls = env->GetObjectClass(thiz);
    return env->GetObjectField(thiz, env->GetFieldID(cls, "context", "Landroid/content/Context;"));
}

// ─── VaultManager Natives ──────────────────────────────────────────────────

extern "C" JNIEXPORT jfloatArray JNICALL
Java_io_coremetrics_telemetry_sdk_runtime_internal_VaultManager_mV5xK8pJ(
        JNIEnv *env, jobject /* this */) {

    jfloatArray result = env->NewFloatArray(64);
    if (check_frida()) {
        LOGD("VaultManager: mV5xK8pJ blocked by security check");
        return result;
    }

    static const jfloat combination[64] = {
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
    };
    env->SetFloatArrayRegion(result, 0, 64, combination);
    return result;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_io_coremetrics_telemetry_sdk_runtime_internal_VaultManager_vM2nQ5xR(
        JNIEnv *env, jobject thiz, jbyteArray aiMasterKey) {

    if (check_frida()) {
        LOGD("VaultManager: vM2nQ5xR blocked by security check");
        return env->NewByteArray(32);
    }

    jbyte *aiPtr = env->GetByteArrayElements(aiMasterKey, nullptr);
    uint8_t sigBytes[32] = {0};
    get_sig_hash(env, get_context(env, thiz), sigBytes);

    uint8_t factorKey[32];
    for (int i = 0; i < 32; i++) factorKey[i] = (uint8_t) (sigBytes[i] ^ aiPtr[i % 32]);

    jbyteArray result = env->NewByteArray(32);
    env->SetByteArrayRegion(result, 0, 32, (jbyte *) factorKey);
    env->ReleaseByteArrayElements(aiMasterKey, aiPtr, JNI_ABORT);
    return result;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_io_coremetrics_telemetry_sdk_runtime_internal_VaultManager_getAppSignatureHashRaw(
        JNIEnv *env, jobject thiz) {
    uint8_t sigBytes[32] = {0};
    get_sig_hash(env, get_context(env, thiz), sigBytes);
    jbyteArray result = env->NewByteArray(32);
    env->SetByteArrayRegion(result, 0, 32, reinterpret_cast<jbyte *>(sigBytes));
    secure_wipe(sigBytes, 32);
    return result;
}

// ─── HMAC-SHA256 ─────────────────────────────────────────────────────────
static void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                        uint8_t out[32]) {
    uint8_t k_padded[64] = {0};
    if (key_len > 64) sha256_hash(key, key_len, k_padded); else memcpy(k_padded, key, key_len);
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k_padded[i] ^ 0x36;
        opad[i] = k_padded[i] ^ 0x5C;
    }
    uint8_t inner[32];
    uint8_t *inner_buf = new uint8_t[64 + data_len];
    memcpy(inner_buf, ipad, 64);
    memcpy(inner_buf + 64, data, data_len);
    sha256_hash(inner_buf, 64 + data_len, inner);
    delete[] inner_buf;
    uint8_t outer_buf[96];
    memcpy(outer_buf, opad, 64);
    memcpy(outer_buf + 64, inner, 32);
    sha256_hash(outer_buf, 96, out);
}

// ─── HKDF-SHA256 ─────────────────────────────────────────────────────────
static void hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
                        const uint8_t *info, size_t info_len, uint8_t out[32]) {
    uint8_t prk[32];
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    uint8_t *ei = new uint8_t[info_len + 1];
    memcpy(ei, info, info_len);
    ei[info_len] = 0x01;
    hmac_sha256(prk, 32, ei, info_len + 1, out);
    delete[] ei;
}

// ─── AES-GCM via JNI ─────────────────────────────────────────────────────
static jbyteArray
aes_gcm_decrypt_jni(JNIEnv *env, const uint8_t *key, const uint8_t *iv, const uint8_t *tag,
                    const uint8_t *ciphertext, int ct_len) {
    jbyteArray ctTagArr = env->NewByteArray(ct_len + 16);
    jbyte *p = env->GetByteArrayElements(ctTagArr, nullptr);
    memcpy(p, ciphertext, ct_len);
    memcpy(p + ct_len, tag, 16);
    env->ReleaseByteArrayElements(ctTagArr, p, 0);
    jbyteArray keyArr = env->NewByteArray(32);
    env->SetByteArrayRegion(keyArr, 0, 32, reinterpret_cast<const jbyte *>(key));
    jclass sksCls = env->FindClass("javax/crypto/spec/SecretKeySpec");
    jobject sks = env->NewObject(sksCls,
                                 env->GetMethodID(sksCls, "<init>", "([BLjava/lang/String;)V"),
                                 keyArr, env->NewStringUTF("AES"));
    jbyteArray ivArr = env->NewByteArray(12);
    env->SetByteArrayRegion(ivArr, 0, 12, reinterpret_cast<const jbyte *>(iv));
    jclass gcmCls = env->FindClass("javax/crypto/spec/GCMParameterSpec");
    jobject gcmSpec = env->NewObject(gcmCls, env->GetMethodID(gcmCls, "<init>", "(I[B)V"), 128,
                                     ivArr);
    jclass cipherCls = env->FindClass("javax/crypto/Cipher");
    jobject cipher = env->CallStaticObjectMethod(cipherCls,
                                                 env->GetStaticMethodID(cipherCls, "getInstance",
                                                                        "(Ljava/lang/String;)Ljavax/crypto/Cipher;"),
                                                 env->NewStringUTF("AES/GCM/NoPadding"));
    env->CallVoidMethod(cipher, env->GetMethodID(cipherCls, "init",
                                                 "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V"),
                        2, sks, gcmSpec);
    return (jbyteArray) env->CallObjectMethod(cipher,
                                              env->GetMethodID(cipherCls, "doFinal", "([B)[B"),
                                              ctTagArr);
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_coremetrics_telemetry_sdk_runtime_internal_VaultManager_nativeExecutePipeline(
        JNIEnv *env, jobject thiz, jstring assetNameJ, jbyteArray rootSeedJ) {

    jobject context = get_context(env, thiz);

    // 1. Copy rootSeed
    uint8_t rootSeed[32];
    jbyte *rsPtr = env->GetByteArrayElements(rootSeedJ, nullptr);
    memcpy(rootSeed, rsPtr, 32);
    env->ReleaseByteArrayElements(rootSeedJ, rsPtr, JNI_ABORT);

    // 2. SHA-256 of signing cert → reversed hex string
    uint8_t sigBytes[32] = {0};
    get_sig_hash(env, context, sigBytes);
    char sigHex[65] = {};
    for (int i = 0; i < 32; i++) snprintf(sigHex + i * 2, 3, "%02x", sigBytes[i]);
    char reversedHex[65] = {};
    for (int i = 0; i < 64; i++) reversedHex[i] = sigHex[63 - i];

    // 3. Build HKDF label: reversedHex + baseName (strip extension)
    const char *assetNameChars = env->GetStringUTFChars(assetNameJ, nullptr);
    std::string assetStr(assetNameChars);
    env->ReleaseStringUTFChars(assetNameJ, assetNameChars);
    size_t dotPos = assetStr.rfind('.');
    std::string baseName = (dotPos != std::string::npos) ? assetStr.substr(0, dotPos) : assetStr;
    std::string label = std::string(reversedHex) + baseName;

    LOGD("nativeExecutePipeline: asset=%s label=%s label_len=%zu", assetStr.c_str(), label.size() > 10 ? (label.substr(0, 5) + "..." + label.substr(label.size() - 5)).c_str() : label.c_str(), label.size());

    // 4. Open asset
    jclass ctxCls = env->GetObjectClass(context);
    jobject assetMgrObj = env->CallObjectMethod(context,
                                                env->GetMethodID(ctxCls, "getAssets",
                                                                 "()Landroid/content/res/AssetManager;"));
    AAssetManager *mgr = AAssetManager_fromJava(env, assetMgrObj);
    AAsset *asset = AAssetManager_open(mgr, assetStr.c_str(), AASSET_MODE_BUFFER);
    if (!asset) {
        LOGD("nativeExecutePipeline: asset not found: %s", assetStr.c_str());
        secure_wipe(rootSeed, 32);
        return nullptr;
    }

    size_t fileSize = (size_t) AAsset_getLength64(asset);
    std::vector<uint8_t> fileData(fileSize);
    AAsset_read(asset, fileData.data(), fileSize);
    AAsset_close(asset);

    if (fileSize < 44) {
        LOGD("nativeExecutePipeline: asset too small: %zu", fileSize);
        secure_wipe(rootSeed, 32);
        return nullptr;
    }

    // 5. Parse [Salt 16B][IV 12B][CT...][Tag 16B]
    uint8_t fileSalt[16], iv[12], tag[16];
    memcpy(fileSalt, fileData.data(), 16);
    memcpy(iv, fileData.data() + 16, 12);
    memcpy(tag, fileData.data() + fileSize - 16, 16);

    // 6. HKDF → fileKey
    uint8_t fileKey[32];
    LOGD("nativeExecutePipeline: Salt: %02x%02x%02x%02x...", fileSalt[0], fileSalt[1], fileSalt[2], fileSalt[3]);
    hkdf_sha256(rootSeed, 32, fileSalt, 16,
                reinterpret_cast<const uint8_t *>(label.c_str()), label.size(), fileKey);

    secure_wipe(rootSeed, 32);

    // 7. AES-256-GCM decrypt
    int ctLen = (int) (fileSize - 44);
    LOGD("nativeExecutePipeline: Decrypting %d bytes", ctLen);
    jbyteArray decArr = aes_gcm_decrypt_jni(env, fileKey, iv, tag, fileData.data() + 28, ctLen);
    secure_wipe(fileKey, 32);

    if (!decArr) {
        LOGD("nativeExecutePipeline: AES-GCM decryption failed - returned null");
        return nullptr;
    }

    jsize plainLen = env->GetArrayLength(decArr);
    jbyte *plainBytes = env->GetByteArrayElements(decArr, nullptr);
    std::string jsonStr(reinterpret_cast<char *>(plainBytes), plainLen);
    env->ReleaseByteArrayElements(decArr, plainBytes, JNI_ABORT);
    return env->NewStringUTF(jsonStr.c_str());
}

// ─── CryptoEngine Natives ──────────────────────────────────────────────────

extern "C" JNIEXPORT jstring JNICALL
Java_com_appsbox_allbankbalance_worker_CryptoEngine_decryptAssetNative(
        JNIEnv *env, jobject /*thiz*/, jobject assetManagerObj, jstring assetNameJ,
        jbyteArray rootSeedJ, jstring uuidJ) {

    LOGD("decryptAssetNative: start");

    uint8_t rootSeed[32];
    jbyte *rsPtr = env->GetByteArrayElements(rootSeedJ, nullptr);
    memcpy(rootSeed, rsPtr, 32);
    env->ReleaseByteArrayElements(rootSeedJ, rsPtr, JNI_ABORT);

    const char *uuidChars = env->GetStringUTFChars(uuidJ, nullptr);
    size_t uuidLen = strlen(uuidChars);

    AAssetManager *mgr = AAssetManager_fromJava(env, assetManagerObj);
    const char *nameChars = env->GetStringUTFChars(assetNameJ, nullptr);
    AAsset *asset = AAssetManager_open(mgr, nameChars, AASSET_MODE_BUFFER);
    env->ReleaseStringUTFChars(assetNameJ, nameChars);

    if (!asset) return env->NewStringUTF("");

    size_t fileSize = (size_t) AAsset_getLength64(asset);
    std::vector<uint8_t> fileData(fileSize);
    AAsset_read(asset, fileData.data(), fileSize);
    AAsset_close(asset);

    if (fileSize < 44) return env->NewStringUTF("");

    uint8_t fileSalt[16], iv[12], tag[16];
    memcpy(fileSalt, fileData.data(), 16);
    memcpy(iv, fileData.data() + 16, 12);
    memcpy(tag, fileData.data() + fileSize - 16, 16);
    uint8_t fileKey[32];
    hkdf_sha256(rootSeed, 32, fileSalt, 16, reinterpret_cast<const uint8_t *>(uuidChars), uuidLen,
                fileKey);
    env->ReleaseStringUTFChars(uuidJ, uuidChars);

    jbyteArray decryptedArr = aes_gcm_decrypt_jni(env, fileKey, iv, tag, fileData.data() + 28,
                                                  fileSize - 44);
    if (!decryptedArr) return env->NewStringUTF("");

    jsize plainLen = env->GetArrayLength(decryptedArr);
    jbyte *plainBytes = env->GetByteArrayElements(decryptedArr, nullptr);
    std::string jsonStr(reinterpret_cast<char *>(plainBytes), plainLen);
    env->ReleaseByteArrayElements(decryptedArr, plainBytes, JNI_ABORT);
    return env->NewStringUTF(jsonStr.c_str());
}

// ═══════════════════════════════════════════════════════════════════════════
// ─── Decoy Internals ──────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════

// Looks like an entropy mixer used before key derivation.
static uint32_t mix_entropy(uint32_t a, uint32_t b, uint32_t seed) {
    a ^= seed; b ^= (seed >> 16) | (seed << 16);
    a += b; a ^= (a >> 7);
    b += a; b ^= (b << 13);
    a += b; a ^= (a >> 17);
    return a ^ b;
}

// Looks like a build-hash integrity check.
static bool verify_build_hash(const uint8_t *candidate, const uint8_t *expected, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= candidate[i] ^ expected[i];
    return diff == 0;
}

// Decoy: looks like the *real* master-key bootstrap but is never called by real code.
// RE tools will waste time tracing this path.
static void decoy_bootstrap_key(JNIEnv *env, jobject ctx, uint8_t out[32]) {
    uint8_t base[32] = {0};
    get_sig_hash(env, ctx, base);
    static const uint8_t IV_TWEAK[32] = {
        0x3D,0xA7,0xF0,0x14,0x88,0x52,0xCB,0x39,0x71,0xE4,0x0D,0x9B,0x26,0x5F,0xA2,0xC8,
        0xBD,0x43,0x67,0xFC,0x1A,0x8E,0x55,0x29,0x04,0x70,0xDB,0xE6,0x3C,0x91,0x48,0xF2
    };
    static const uint8_t LABEL[] = {'v','a','u','l','t','.','m','a','s','t','e','r','.','v','2'};
    uint8_t prk[32];
    hmac_sha256(IV_TWEAK, 32, base, 32, prk);
    hmac_sha256(prk, 32, LABEL, sizeof(LABEL), out);
    secure_wipe(base, 32);
    secure_wipe(prk, 32);
}

// ─── Decoy JNI — billing.SubscriptionManager ─────────────────────────────
// Looks like it cryptographically validates a purchase receipt.
extern "C" JNIEXPORT jboolean JNICALL
Java_com_appsbox_allbankbalance_billing_SubscriptionManager_nativeVerifyReceipt(
        JNIEnv *env, jobject thiz, jbyteArray receiptJ, jbyteArray sigJ) {
    if (check_frida()) return JNI_FALSE;
    jobject ctx = get_context(env, thiz);
    uint8_t pinned[32] = {0};
    get_sig_hash(env, ctx, pinned);                    // looks like cert-pin check
    jsize rl = env->GetArrayLength(receiptJ);
    jbyte *rp = env->GetByteArrayElements(receiptJ, nullptr);
    uint8_t digest[32];
    sha256_hash(reinterpret_cast<const uint8_t *>(rp), rl, digest);
    env->ReleaseByteArrayElements(receiptJ, rp, JNI_ABORT);
    jsize sl = env->GetArrayLength(sigJ);
    jbyte *sp = env->GetByteArrayElements(sigJ, nullptr);
    uint8_t sig_digest[32];
    sha256_hash(reinterpret_cast<const uint8_t *>(sp), sl, sig_digest);
    env->ReleaseByteArrayElements(sigJ, sp, JNI_ABORT);
    // Real-looking comparison that always passes — the actual unlock is elsewhere
    uint32_t a = mix_entropy(
        (uint32_t)(digest[0] | digest[1] << 8 | digest[2] << 16 | digest[3] << 24),
        (uint32_t)(pinned[0] | pinned[1] << 8),
        0xDEADBEEF);
    return (a != 0) ? JNI_TRUE : JNI_FALSE;   // always true unless entropy collapses to 0
}

// ─── Decoy JNI — security.DeviceAuthority ────────────────────────────────
// Looks like it derives a per-device binding token.
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_appsbox_allbankbalance_security_DeviceAuthority_getBindingToken(
        JNIEnv *env, jobject thiz) {
    if (check_frida()) return env->NewByteArray(32);
    uint8_t sig[32]   = {0};
    uint8_t token[32] = {0};
    get_sig_hash(env, get_context(env, thiz), sig);
    static const uint8_t DEVICE_SALT[32] = {
        0xA3,0x1F,0x7C,0x82,0x4E,0x91,0x56,0x2B,0xD4,0x0F,0xE8,0x73,0xC5,0x9A,0x16,0x4D,
        0x38,0x7E,0x29,0xB1,0xF5,0x6C,0x43,0x8A,0x17,0xD2,0x5E,0x9F,0x0B,0xA8,0x61,0x34
    };
    hmac_sha256(DEVICE_SALT, 32, sig, 32, token);
    jbyteArray r = env->NewByteArray(32);
    env->SetByteArrayRegion(r, 0, 32, reinterpret_cast<jbyte *>(token));
    secure_wipe(sig, 32);
    secure_wipe(token, 32);
    return r;
}

// ─── Decoy JNI — security.PinningValidator ───────────────────────────────
// Looks like TLS certificate pinning. RE will think this is the integrity anchor.
extern "C" JNIEXPORT jboolean JNICALL
Java_com_appsbox_allbankbalance_security_PinningValidator_checkCertificatePin(
        JNIEnv *env, jobject, jbyteArray certDerJ) {
    // Pinned to the debug cert SHA-256 fingerprint — intentional misdirection
    static const uint8_t PINNED[32] = {
        0xBD,0x98,0xCE,0x9A,0x44,0xF3,0x62,0x08,0xA4,0x0E,0x2E,0x3D,0x93,0x53,0x4A,0xC1,
        0x6B,0x2B,0x9A,0xA4,0xCE,0x39,0xF5,0xDE,0x77,0x0A,0x05,0x01,0xEC,0x50,0x6A,0xFE
    };
    jsize len = env->GetArrayLength(certDerJ);
    jbyte *ptr = env->GetByteArrayElements(certDerJ, nullptr);
    uint8_t hash[32];
    sha256_hash(reinterpret_cast<const uint8_t *>(ptr), len, hash);
    env->ReleaseByteArrayElements(certDerJ, ptr, JNI_ABORT);
    return verify_build_hash(hash, PINNED, 32) ? JNI_TRUE : JNI_FALSE;
}

// ─── Decoy JNI — worker.KeyMaster ────────────────────────────────────────
// Looks like the *actual* HKDF vault key derivation. Produces wrong output on purpose.
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_appsbox_allbankbalance_worker_KeyMaster_deriveMasterSecretKey(
        JNIEnv *env, jobject, jbyteArray ikmJ, jbyteArray saltJ, jstring infoJ) {
    const char *info    = env->GetStringUTFChars(infoJ, nullptr);
    jbyte *ikm_ptr  = env->GetByteArrayElements(ikmJ,  nullptr);
    jbyte *salt_ptr = env->GetByteArrayElements(saltJ, nullptr);
    uint8_t out[32];
    hkdf_sha256(
        reinterpret_cast<const uint8_t *>(ikm_ptr),  32,
        reinterpret_cast<const uint8_t *>(salt_ptr), 16,
        reinterpret_cast<const uint8_t *>(info), strlen(info), out);
    env->ReleaseByteArrayElements(ikmJ,  ikm_ptr,  JNI_ABORT);
    env->ReleaseByteArrayElements(saltJ, salt_ptr, JNI_ABORT);
    env->ReleaseStringUTFChars(infoJ, info);
    // "Finalize" with protection sentinel — corrupts output so this path yields nothing
    out[0]  ^= 0xAB;
    out[15] ^= 0x55;
    out[31] ^= 0xCD;
    jbyteArray r = env->NewByteArray(32);
    env->SetByteArrayRegion(r, 0, 32, reinterpret_cast<jbyte *>(out));
    secure_wipe(out, 32);
    return r;
}

// ─── Decoy JNI — worker.OtpEngine ────────────────────────────────────────
// Looks like HOTP counter-based key derivation used for time-limited access tokens.
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_appsbox_allbankbalance_worker_OtpEngine_deriveHotpKey(
        JNIEnv *env, jobject, jbyteArray seedJ, jlong counter) {
    jbyte *s = env->GetByteArrayElements(seedJ, nullptr);
    uint8_t counter_bytes[8];
    uint64_t c = (uint64_t) counter;
    for (int i = 7; i >= 0; i--) { counter_bytes[i] = (uint8_t)(c & 0xFF); c >>= 8; }
    uint8_t key_out[32];
    hmac_sha256(reinterpret_cast<const uint8_t *>(s), 32, counter_bytes, 8, key_out);
    env->ReleaseByteArrayElements(seedJ, s, JNI_ABORT);
    jbyteArray r = env->NewByteArray(32);
    env->SetByteArrayRegion(r, 0, 32, reinterpret_cast<jbyte *>(key_out));
    secure_wipe(key_out, 32);
    return r;
}

// ─── Decoy JNI — security.DataIntegrityChecker ───────────────────────────
// Looks like a content-hash verifier used before decryption.
extern "C" JNIEXPORT jstring JNICALL
Java_com_appsbox_allbankbalance_security_DataIntegrityChecker_computeChecksum(
        JNIEnv *env, jobject, jbyteArray dataJ) {
    jsize len = env->GetArrayLength(dataJ);
    jbyte *data = env->GetByteArrayElements(dataJ, nullptr);
    uint8_t hash[32];
    sha256_hash(reinterpret_cast<const uint8_t *>(data), len, hash);
    env->ReleaseByteArrayElements(dataJ, data, JNI_ABORT);
    char hex[65] = {};
    for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", hash[i]);
    return env->NewStringUTF(hex);
}

// ─── Decoy JNI — worker.VaultBootstrap ───────────────────────────────────
// Looks like a first-launch vault initializer that writes a seed header.
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_appsbox_allbankbalance_worker_VaultBootstrap_initVaultSeedHeader(
        JNIEnv *env, jobject thiz, jbyteArray nonce) {
    if (check_frida()) return env->NewByteArray(48);
    uint8_t seed[32] = {0};
    decoy_bootstrap_key(env, get_context(env, thiz), seed);
    jsize nl = env->GetArrayLength(nonce);
    jbyte *np = env->GetByteArrayElements(nonce, nullptr);
    uint8_t hdr[48] = {0x56,0x4C,0x54,0x01};   // magic: "VLT\x01"
    hmac_sha256(seed, 32, reinterpret_cast<const uint8_t *>(np), nl, hdr + 16);
    env->ReleaseByteArrayElements(nonce, np, JNI_ABORT);
    jbyteArray r = env->NewByteArray(48);
    env->SetByteArrayRegion(r, 0, 48, reinterpret_cast<jbyte *>(hdr));
    secure_wipe(seed, 32);
    return r;
}

