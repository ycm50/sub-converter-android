plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.subconverter"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    // subconv 的核心是 C++23（用了 std::expected）。NDK r26（Clang 17 / libc++ 17）起
    // 才有 <expected>，所以版本别低于这个。这里钉住一个具体版本是为了构建可复现。
    //
    // 这个值是本机 SDK（A:\AndroidSDK，也是 local.properties 里 sdk.dir 指的那份）
    // 里已经装好的 r28c；换成本机已装的其它 r26+ 版本也可以（r26.1.10909125 同样装好了）。
    // 注意 AGP 找 NDK 的路径是 $SDK/ndk/$ndkVersion —— 这个版本必须在 sdk.dir 那份
    // SDK 的 ndk/ 目录里真的存在，否则会以 "NDK not configured" 直接失败。
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "com.subconverter"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            // arm64-v8a / armeabi-v7a 覆盖真机，x86_64 覆盖模拟器。
            // 32 位 x86 已经没有有意义的设备了，不打进去。
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }

        externalNativeBuild {
            cmake {
                // c++_static：把 libc++ 静态链进 libsubconv.so，APK 里不用再带
                // libc++_shared.so，也少一个 ABI 版本对不上的失败点。
                arguments += "-DANDROID_STL=c++_static"
                // Clash YAML 订阅解析（内置的 yaml-cpp）。
                // 关掉可以显著缩短编译时间，代价是 Clash YAML 不能当输入源。
                arguments += "-DSUBCONV_USE_YAML=ON"
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            // version 刻意不写。查过 AGP 9.2.1 的源码（CmakeLocator.kt）：
            // 不写 version 时的默认要求版本是 CMakeVersion.DEFAULT = 3.22.1，
            // 而 A:\AndroidSDK\cmake\ 下装的正好是 3.22.1，严格相等，直接命中。
            // 找 CMake 的顺序是：local.properties 的 cmake.dir → $SDK/cmake/* →
            // $PATH → $SDK/cmake/*（非标准回退）→ 联网下载。前两步在本机都能命中。
        }
    }

    buildTypes {
        release {
            optimization {
                enable = false
            }
            // 注意：release 没开 minify（isMinifyEnabled 默认 false）。
            // 真开了的话，src/main/keepRules/rules.keep 里那几条 JNI/JS 接口的 keep 规则
            // 就是必需的 —— JNI 与 addJavascriptInterface 都是按名字找方法，R8 看不见。
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    // 刻意不引 appcompat / material：界面里唯一那个 View 是 WebView，Activity 直接继承
    // framework 的 android.app.Activity，主题也换成了 framework 的
    // Theme.DeviceDefault.*.NoActionBar —— 没有任何 AppCompat/Material 组件，
    // 引进来只会白占体积。
    // 同样不引 androidx.core:core-ktx：这个 App 是纯 Java 的（Kotlin 文件一个都没有）。
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
}
