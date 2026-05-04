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

# ─── C++ Compilation Flags ───────────────────────────────────────────────
target_compile_options(native-lib PRIVATE
    # -Os: optimize for size; also improves cache locality at runtime
    -Os

    # ThinLTO: cross-translation-unit inlining + dead-code elimination
    # (the C++ equivalent of R8 full-mode — runs at link time)
    -flto=thin

    # Dead-code elimination per function/data object.
    # Must be paired with --gc-sections in the linker to take effect.
    -ffunction-sections
    -fdata-sections

    # Hide all symbols by default; only JNIEXPORT functions are visible
    -fvisibility=hidden
    -fvisibility-inlines-hidden

    # Stack canaries
    -fstack-protector-strong

    # Position-independent code
    -fPIC

    # Strip debug information
    -g0

    # Reduce binary size / obfuscate control flow
    -fno-exceptions
    -fno-rtti

    # Harden against buffer overflows
    -D_FORTIFY_SOURCE=2
)

# ─── Linker Options ───────────────────────────────────────────────────────
target_link_options(native-lib PRIVATE
    # ThinLTO link pass — must match the compile flag above
    "-flto=thin"

    # Dead-symbol elimination (works with -ffunction-sections / -fdata-sections)
    "-Wl,--gc-sections"

    # 16 KB page alignment (Android 15+)
    "-Wl,-z,max-page-size=16384"

    # Full RELRO + immediate binding
    "LINKER:-z,relro,-z,now"

    # Hide all archive symbols — only exports what we explicitly mark JNIEXPORT
    "LINKER:--exclude-libs,ALL"

    # Strip ALL remaining debug/symbol info from the final .so
    "-Wl,--strip-all"
)
