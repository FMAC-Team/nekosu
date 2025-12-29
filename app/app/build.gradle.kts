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


        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
        
        signingConfigs {
         create("debug_sig") {
            storeFile=file("debug.keystore") 
            storePassword="android"
            keyAlias="androiddebugkey"
            keyPassword="android"
        }
       }

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
                arguments += listOf(
                    "-DANDROID_STL=c++_shared",
                    "-DANDROID_PLATFORM=android-26"
                )
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )

            ndk {
                debugSymbolLevel = "FULL"
            }
        }

        debug {
        signingConfig = signingConfigs.getByName("debug_sig") 
            ndk {
                debugSymbolLevel = "FULL"
            }
        }
    }


    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
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

    packaging {
        jniLibs {
            useLegacyPackaging = true
            pickFirsts += listOf(
                "lib/arm64-v8a/libc++_shared.so",
                "lib/x86_64/libc++_shared.so"
            )
        }
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "/lib/armeabi/**"
        }
    }

    android.applicationVariants.all {
        outputs.all {
            if (this is com.android.build.gradle.internal.api.ApkVariantOutputImpl) {
                val config = project.android.defaultConfig
                val versionName = config.versionName
                this.outputFileName = "Nekosu_v${versionName}.apk"
            }
        }
    }
    ndkVersion = "27.1.12297006"
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