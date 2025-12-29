plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

fun getGitOutput(vararg args: String, fallback: String): String {
    return try {
        val process = ProcessBuilder(*args)
            .redirectErrorStream(true)
            .start()

        val text = process.inputStream.bufferedReader().readText().trim()

        if (text.contains("fatal") || text.contains("not a git repository", ignoreCase = true)) {
            fallback
        } else {
            text.replace("[^a-zA-Z0-9._-]".toRegex(), "")
                .ifEmpty { fallback }
        }
    } catch (_: Exception) {
        fallback
    }
}

fun getGitCommitCount(): Int {
    val text = getGitOutput("git", "rev-list", "--count", "HEAD", fallback = "1")
    return text.toIntOrNull() ?: 1
}

fun getGitShortHash(): String {
    return getGitOutput("git", "rev-parse", "--short", "HEAD", fallback = "unknown")
}


android {
    namespace = "me.neko.nksu"
    compileSdk = 36

    defaultConfig {
        applicationId = "me.neko.nksu"
        minSdk = 26
        targetSdk = 36

        val commitCount = getGitCommitCount()
        val gitHash = getGitShortHash()

        versionCode = getGitCommitCount()
        versionName = "0.0.13-alpha.r$commitCount.$gitHash"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // NDK 配置 - 支持的 CPU 架构
        ndk {
            // 指定需要支持的 ABI（应用程序二进制接口）
            abiFilters += listOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
        }

        // External Native Build 配置（如果使用 CMake）
        externalNativeBuild {
            cmake {
                // C++ 标准版本
                cppFlags += "-std=c++17"
                // 编译参数
                arguments += listOf(
                    "-DANDROID_STL=c++_shared",  // 使用共享的 C++ 标准库
                    "-DANDROID_PLATFORM=android-26"
                )
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true // 移除未使用的资源
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )

            // Native 调试符号配置
            ndk {
                debugSymbolLevel = "FULL"  // 生成完整的调试符号
            }
        }

        debug {
            // Debug 模式下的 Native 配置
            ndk {
                debugSymbolLevel = "FULL"
            }
        }
    }

    // External Native Build 配置 - CMake 或 ndk-build
    externalNativeBuild {
        // 如果使用 CMake，取消下面的注释
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")  // CMakeLists.txt 的路径
            version = "3.22.1"  // CMake 版本
        }

        // 如果使用 ndk-build，使用下面的配置（二选一）
        // ndkBuild {
        //     path = file("src/main/cpp/Android.mk")
        // }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    // Native 库和资源打包选项
    packaging {
        jniLibs {
            useLegacyPackaging = true
            // 保留所有 native 库
            pickFirsts += listOf(
                "lib/armeabi-v7a/libc++_shared.so",
                "lib/arm64-v8a/libc++_shared.so",
                "lib/x86/libc++_shared.so",
                "lib/x86_64/libc++_shared.so"
            )
        }
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            // 排除重复的 native 库
            excludes += "/lib/armeabi/**"  // 如果不需要旧的 armeabi
        }
    }

    // 自定义 APK 文件名
    android.applicationVariants.all {
        outputs.all {
            if (this is com.android.build.gradle.internal.api.ApkVariantOutputImpl) {
                val config = project.android.defaultConfig
                val versionName = config.versionName
                this.outputFileName = "Nekosu_v${versionName}.apk"
            }
        }
    }

    // NDK 版本（可选，指定特定的 NDK 版本）
    ndkVersion = "27.1.12297006"  // 或者你安装的 NDK 版本
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation("androidx.compose.material:material-icons-extended:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    implementation(libs.androidx.material3)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.gson)
    implementation(libs.okhttp)
    implementation(libs.moshi)
    implementation(libs.moshi.kotlin)
    
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.ui.test.junit4)
    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)
}