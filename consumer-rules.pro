# Vault library consumer ProGuard rules.
# These rules are merged into the consuming app's ProGuard config automatically.

# Preserve JNI bridge — class + all field names so get_context() can find "context" at runtime
-keep class io.coremetrics.telemetry.sdk.runtime.internal.VaultManager {
    public <methods>;
    native <methods>;
    <fields>;
}

# LiteRT (TFLite 1.x) — bundled .so uses org.tensorflow.lite classes
-keep class org.tensorflow.lite.** { *; }
-dontwarn org.tensorflow.lite.**
-keep class com.google.ai.edge.litert.** { *; }
-dontwarn com.google.ai.edge.litert.**

# NIO buffers used by TFLite JNI layer
-keep class java.nio.Buffer { *; }
-keep class java.nio.ByteBuffer { *; }

