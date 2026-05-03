plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.jetbrains.kotlin.android)
}

android {
    namespace = "io.coremetrics.telemetry"
    compileSdk = 36

    defaultConfig {
        minSdk = 26

        consumerProguardFiles("consumer-rules.pro")

        externalNativeBuild {
            cmake {
                cppFlags += "-Os"
                cppFlags += "-fvisibility=hidden"
                cppFlags += "-fstack-protector-strong"
                cppFlags += "-fno-exceptions"
                cppFlags += "-fno-rtti"
                cppFlags += "-g0"
                arguments += "-DANDROID_STL=c++_shared"
                arguments += "-DANDROID_EXT_LINKER_FLAGS=-Wl,-z,max-page-size=16384"
                arguments += "-DCMAKE_BUILD_TYPE=Release"
                arguments += "-DCMAKE_CXX_FLAGS=-Wl,--strip-all"
            }
        }
    }

    buildTypes {
        release {
            // Library: minification controlled by consumer app
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }

    androidResources {
        noCompress += listOf("tflite", "abbe")
    }
}


dependencies {
    implementation(libs.litert)
    implementation(libs.timber)
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

