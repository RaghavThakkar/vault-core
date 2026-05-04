# Vault library consumer ProGuard rules.
# These rules are merged into the consuming app's ProGuard config automatically.

# Preserve JNI bridge — class + all field names so get_context() can find "context" at runtime
-keepclasseswithmembernames class io.coremetrics.telemetry.sdk.runtime.internal.VaultManager {
    # JNI symbol table requires exact native method names
    native <methods>;
    # get_context() reads this field by name from C++
    private android.content.Context context;
}

# LiteRT (TFLite 1.x) — bundled .so uses org.tensorflow.lite classes
-keep class org.tensorflow.lite.** { *; }
-dontwarn org.tensorflow.lite.**
-keep class com.google.ai.edge.litert.** { *; }
-dontwarn com.google.ai.edge.litert.**

# NIO buffers used by TFLite JNI layer
-keep class java.nio.Buffer { *; }
-keep class java.nio.ByteBuffer { *; }
