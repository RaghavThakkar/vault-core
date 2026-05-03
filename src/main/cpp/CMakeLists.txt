cmake_minimum_required(VERSION 3.22.1)

project("allbankbalance")

add_library(
        native-lib
        SHARED
        native-lib.cpp)

# ─── System Library Lookups ───────────────────────────────────────────────
find_library(log-lib     log)
find_library(android-lib android)   # AAssetManager_fromJava, AAssetManager_open etc.

target_link_libraries(
        native-lib
        ${log-lib}
        ${android-lib})

# ─── C++ Compilation Flags for Maximum Obfuscation & Security ─────────────
target_compile_options(native-lib PRIVATE
    # Optimization for size (makes reverse engineering harder)
    -Os

    # Hide symbols by default (only export JNI functions via JNIEXPORT)
    -fvisibility=hidden
    -fvisibility-inlines-hidden

    # Enable stack canaries for additional security
    -fstack-protector-strong

    # Position-independent code
    -fPIC

    # Strip debug information during compilation
    -g0

    # Disable exceptions to reduce binary size and obscure control flow
    -fno-exceptions

    # Disable RTTI to reduce binary size
    -fno-rtti

    # Additional hardening
    -D_FORTIFY_SOURCE=2
)

# ─── Linker Options for Symbol Stripping & Security ──────────────────────
target_link_options(native-lib PRIVATE
    # Ensure 16 KB page alignment for Android 15+ compatibility
    "-Wl,-z,max-page-size=16384"

    # Enable relocation read-only and now binding (full RELRO)
    "LINKER:-z,relro,-z,now"

    # Hide symbols by default (export only JNIEXPORT functions)
    "LINKER:--exclude-libs,ALL"
)
