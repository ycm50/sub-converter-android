// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    alias(libs.plugins.android.application) apply false
}

// 上游同步与内核校验两个任务都注册在这个脚本插件里：
//   ./gradlew syncUpstream    拉上游 + 自动套 patches/ 里的 Android 适配补丁 + 自检
//   ./gradlew verifyKernel    核对 APK 里三个 ABI 的 libsubconv.so
// 用 Gradle 写（而不是 shell 脚本）是为了跨平台 —— CI 跑在 ubuntu 上，PowerShell 那套用不了。
apply(from = "gradle/subconv-upstream.gradle.kts")
