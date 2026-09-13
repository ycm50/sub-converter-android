# subconverter (Android)

把 [ycm50/sub-converter](https://github.com/ycm50/sub-converter)（C++23 写的订阅转换工具
**subconv**）移植成 Android App。

**App 的行为 == 在命令行里跑 `subconv serve`，再用 WebView 打开它自己起的那个页面。**
界面里是上游那份原封不动的 Web UI（`data/web/index.html`），API（`POST /api/convert`、
`/sub?target=&url=`、`/api/version`、`/api/rulesets`、`/api/dns`）也全部由 C++ 侧的原服务提供
—— 这个移植没有重写界面，也没有重写转换逻辑。

**Android 这一侧一个原生控件都没有**：没有布局文件、没有进度条、没有状态遮罩、没有「重试」
按钮，也不弹 Toast，视图树里只有 WebView 一个节点（`setContentView(new WebView(this))`）。
`Activity` 继承的是 framework 的 `android.app.Activity`，主题是 framework 的
`Theme.DeviceDefault.*.NoActionBar`，所以 appcompat / material 两个依赖被整个去掉了。

**目录**：[端口为什么是随机的](#端口为什么是随机的以及怎么传出来) · [构建](#构建) · [手动构建](#手动构建github-actions) · [使用](#使用) ·
[目录结构](#目录结构) · [与桌面版的功能差异](#与桌面版的功能差异) · [实现上的取舍](#几个实现上的取舍) ·
[安全边界](#安全边界) · [仓库约定](#仓库约定什么进库什么不进) · [第三方组件与许可](#第三方组件与许可) ·
[已知限制](#已知限制)

```
MainActivity
    │  1. 后台线程调 ServerHost.ensureStarted()
    ▼
ServerHost ──► NativeServer.nativeStart("127.0.0.1", 0)      ← port = 0：内核分配空闲端口
                   │
                   ▼
              jni_bridge.cpp ──► subconv::server::run(opts, on_ready)
                   │                 │
                   │                 ├─ bind + listen + getsockname → 拿到真实端口
                   │                 └─ on_ready(url, port) 回调
                   │
   2. nativeStart 返回实际端口（阻塞等到端口就绪）
   3. WebView.loadUrl("http://127.0.0.1:<port>/")
```

## 端口：为什么是随机的，以及怎么传出来

写死一个端口意味着「撞上系统里别的进程」或「两个实例互抢」；所以这里传 `port = 0`，
由内核从当前空闲端口里挑一个，天然不会冲突。

麻烦的是**内核挑了哪个端口只有 native 侧知道**。上游 `run()` 其实已经 `getsockname()` 取到了
端口，但只用来打印一行 `Web UI: http://...`。嵌入式宿主不该去解析日志，所以给 `run()` 加了
一个 `ReadyHandler` 回调：监听成功、进入 accept 循环之前回调一次，把实际端口交出来；
`nativeStart()` 就在条件变量上等这个回调，拿到端口再返回给 Java。

## 构建

需要（Android Studio 打开工程时会给提示，缺什么装什么）：

| 组件 | 版本 | 为什么 |
|---|---|---|
| **NDK** | r26 或更高（已钉 `28.2.13676358`） | 上游用了 `std::expected`，需要 Clang 17+ / libc++ 17+ |
| CMake | 3.22.1（AGP 9 默认要求的就是它） | `CMakeLists.txt` 声明 3.22，3.22.1 满足 |
| JDK | 21 | Kotlin 一个文件都没有，纯 Java + C++；21 由 Studio 自带的 JBR 提供 |

```bash
./gradlew :app:assembleDebug          # 打 APK
./gradlew :app:connectedAndroidTest   # 跑设备上的冒烟测试（见下）
```

### 本机环境（已经配好了，以及为什么）

下面是让构建在这台机器上真的跑起来所需的全部信息 —— **依据是一次成功构建留下的现场**：
`app/build/outputs/apk/debug/app-debug.apk`（14.4 MB，`lib/{arm64-v8a,armeabi-v7a,x86_64}/
libsubconv.so` 三个 ABI 都在），以及 `.cxx/Debug/*/CMakeCache.txt` 里记下的实际用的
NDK / CMake 路径。

**1. 这个工程夹在两份 SDK 中间 —— 两边都堵上了。**

本机有两份 SDK，`A:\AndroidSDK` 是 C 盘那份的**严格超集**：

| 组件 | `C:\Users\Administrator\AppData\Local\Android\Sdk`（Studio 默认） | `A:\AndroidSDK` |
|---|---|---|
| ndk | **—** | `26.1.10909125`、`28.2.13676358`（r28c） |
| cmake | **—** | `3.22.1`（带 `ninja.exe`） |
| platforms | `36.1`、`37.0` | `36`、`36.1`、`37.0`、`37.1` |
| build-tools | `36.0.0`、`36.1.0`、`37.0.0` | `35.0.0` … `37.0.0` |
| cmdline-tools | **—** | ✓ |
| system-images | **—** | `android-37.1`（x86_64 google_apis_playstore） |
| emulator / extras / sources / platform-tools / licenses | ✓ | ✓ |

AGP 找 NDK 的规则是 `$SDK/ndk/$ndkVersion`，所以只要用的是 C 盘那份，同步就死在这：

```
A problem occurred configuring project ':app'.
> NDK not configured. Download it with SDK manager.
  Preferred NDK version is '28.2.13676358'.
```

**为什么光改 `local.properties` 没用**：Studio 每次同步都会按它自己的设置重写那一行。
AGP 9.2.1 `SdkLocator.kt` 里 `SdkLocationSource` 的枚举顺序是

```
1. TEST_SDK_DIRECTORY    （仅测试代码）
2. LOCAL_SDK_DIR         ← local.properties 的 sdk.dir      ★ 有效即立刻返回
3. LOCAL_ANDROID_DIR     ← local.properties 的 android.dir
4. INJECTED_SDK_HOME     ← ANDROID_SDK_ROOT / ANDROID_HOME / -Dandroid.home
```

`sdk.dir` 只要指向一个存在的目录就算「有效」，走到第 2 个就返回了 —— 它排在
`ANDROID_HOME` 和 `android.home` 前面，所以往 `gradle.properties` 里写
`systemProp.android.home` 也压不住它。Studio 把这个值存在
`%APPDATA%\Google\AndroidStudio2026.1.1\options\android.sdk.path.xml`：

```xml
<component name="AndroidSdkPathStore">
  <option name="androidSdkAbsolutePath" value="A:\AndroidSDK" />
</component>
```

已经改成 `A:\AndroidSDK`，**重启 Studio 后生效**。若被 Studio 覆盖回去，就在
**Settings → Languages & Frameworks → Android SDK → Android SDK Location** 里手动选
`A:\AndroidSDK`。

**2. 为了不用等重启就能同步，C 盘那份 SDK 缺的两块用目录 junction 接上了：**

```
C:\...\Local\Android\Sdk\ndk    --junction-->  A:\AndroidSDK\ndk
C:\...\Local\Android\Sdk\cmake  --junction-->  A:\AndroidSDK\cmake
```

这样不管 AGP 最后落到哪一份 SDK，`$SDK/ndk/28.2.13676358/source.properties` 都读得出
`Pkg.Revision = 28.2.13676358`（与 `ndkVersion` 严格相等 → **不会再尝试联网下载**，日志里
那些 `Failed to download any source lists!` 也就不再出现），`$SDK/cmake/3.22.1/bin` 也都在。

> ⚠️ 副作用：C 盘那份 SDK 现在「看起来」也装了这套 NDK/CMake。**别在 SDK Manager 里卸载
> 它们** —— 删除会穿过 junction 把 `A:\AndroidSDK` 里的真文件一起删掉。等 Studio 稳定跑在
> A 盘之后，把这两个链接删掉最干净（删链接本身不会动目标内容）：
>
> ```powershell
> Remove-Item "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk"
> Remove-Item "C:\Users\Administrator\AppData\Local\Android\Sdk\cmake"
> ```

**3. CMake 不用指定版本。** AGP 9.2.1 的 `CmakeLocator.kt` 里
`CMakeVersion.DEFAULT = LATEST_WITH_FILE_API("3.22.1", "3.22.1")` —— 不写
`externalNativeBuild.cmake.version` 时要求的就是 **3.22.1**，`A:\AndroidSDK\cmake\3.22.1`
正好严格相等，直接命中。查找顺序是：`cmake.dir` → `$SDK/cmake/*` → `$PATH` →
`$SDK/cmake/*`（非标准回退）→ 联网下载；本机在第二步就命中了。

**4. 日志里那堆 `Connection refused` / `Failed to download any source lists!` 是代理没起。**

`~/.gradle/gradle.properties`（用户级，不是本工程的）里有：

```properties
systemProp.http.proxyHost=127.0.0.1
systemProp.http.proxyPort=10808
systemProp.https.proxyHost=127.0.0.1
systemProp.https.proxyPort=10808
```

而 10808 端口上当前没有任何进程在监听（Studio 的 HTTP Proxy 设置也指的是它），
于是 Gradle 的每一个出网请求都被拒。这些 SDK 清单下载失败**只是警告，不影响本机构建**：
需要的依赖（espresso / junit / aapt2 `9.2.1-15009934`；主代码只用 framework，连
appcompat / material 都不需要）都已在 `~/.gradle/caches` 里，NDK 与 CMake 都在本地
—— 整条链路不需要联网。
真要联网时把 10808 的代理起起来，或临时删掉那四行 `systemProp.*`。

**5. JDK 21 是 Studio 自带的，不需要下载。** `gradle/gradle-daemon-jvm.properties` 要求
`toolchainVersion=21`，而 Gradle 守护进程实际用的是 Android Studio 自带的
`A:\Android Studio\jbr`（Java 21）—— `~/.gradle/jdks` 至今是空的，说明没有发生下载。
只有从命令行构建、让 Gradle 自己找 JVM 时才会撞上 `JAVA_HOME=A:\jdk-17.0.12` 是 17：
那时 Gradle 会想要一个 21 的 toolchain，那一步需要外网。
`compileOptions` 里的 Java 11 只是字节码目标，跟跑 Gradle 的 JVM 无关。

### 设备上的冒烟测试

`app/src/androidTest/.../NativeServerTest.java` 验的正是这个移植的核心三件事：

1. `libsubconv.so` 能被加载（JNI 名字没写错、keep 规则没漏）；
2. 服务能在**内核分配的随机端口**上起来（`port = 0` 这条路真的通）；
3. 那个端口上真的吐得出 Web UI 与 `/api/version`。

端口报错位、回调没接上、JNI 桥断了，这三种最常见的移植事故都会在这里挂掉而不是变成白屏。

## 手动构建（GitHub Actions）

[`.github/workflows/manual-build.yml`](.github/workflows/manual-build.yml)：**只在 Actions 页面手动点
"Run workflow" 触发**（Actions →「手动构建 Release APK（含签名）」→ Run workflow，可以选分支），
跑 `:app:assembleRelease` → 现生成密钥签名 → 把**签好的** APK 作为 artifact 传上去。

* **刻意不发布**：workflow 的权限只有 `contents: read`，不创建 GitHub Release、不打 tag、
  不推任何东西 —— 想发布至少得先给它 `write` 权限，而这里没有。
* **CI 上要现装的东西**：NDK `28.2.13676358`、CMake `3.22.1`、`platforms;android-36.1`
  （`compileSdk` 是 `36.1`，带小版本号，不能写成 `android-36`）、`build-tools;36.1.0`。
  包名不是拼的，是照本机 SDK 里各 `package.xml` 的 `localPackage path` 抄的。
* **签名是 workflow 现做的，仓库里不留密钥**：`assembleRelease` 出的还是
  `app-release-unsigned.apk`（`app/build.gradle.kts` 里没有 `signingConfigs`），紧接着那一步用
  `keytool` 生成一把**临时**密钥 —— PKCS12、口令就 `123456`（`-storepass` 与 `-keypass`
  都是它，PKCS12 要求两者一致），不做任何加密 —— 然后按官方的顺序
  `zipalign -f -p 4` → `apksigner sign` 签成 `app-release.apk`，再 `apksigner verify` 自检，
  最后**只上传签好的这一个**（目录里还躺着 unsigned 那个，所以上传路径钉死文件名，不用通配符）。
  所以下载下来的 artifact 是**可以直接装**的，不需要你再去配 Secrets。
* **代价：每次构建的密钥都不一样**（它用完即弃，不是被谁保管着）。这有两个后果：
  一是**覆盖安装会失败**——`adb install -r` / 直接点 APK 都会报签名不一致
  （`INSTALL_FAILED_UPDATE_INCOMPATIBLE`），必须先卸载旧版；二是卸载会**清掉 Web UI 的
  localStorage**（也就是页面里存过的那些设置）。想要签名稳定，就得换成固定密钥：把密钥
  放进仓库 Secrets，然后要么在 `app/build.gradle.kts` 里加 `signingConfigs`，要么把这里手工
  签的 `--ks` 换成 `secrets.RELEASE_KEYSTORE_BASE64` 还原出来的那个文件（后者改动更小）。
  现在的选择是「宁可每次重签，也不往仓库里放私钥」。
* workflow 里有一处交叉核对：`app/build.gradle.kts` 的 `ndkVersion` 必须和 workflow 里的
  `NDK_VERSION` 一致，不一致会在**装 SDK 之前**就报错退出 —— 这两处写在不同文件里，
  改一处忘另一处只会得到一句很难联想的 `NDK not configured`。
* 跑完在 job summary 里能看到产物文件名、大小、SHA-256、**签名证书的指纹**，以及 APK 里
  三个 ABI 的 `libsubconv.so` 列表（native 侧静默编空的检查）。
  想核对下载到的文件是不是这次构建的东西，比一下 SHA-256 就行。

## 使用

装上去、点开，就是那个页面 —— 没有启动页、没有按钮、没有标题栏，App 里唯一的东西是 WebView。

```bash
./gradlew :app:installDebug          # 装到已连接的设备/模拟器
# 也可以 adb install -r app/build/outputs/apk/debug/app-debug.apk
# 或者在 Studio 里点 Run
```

* **首次打开**：后台线程先起内嵌服务（等价于 `subconv serve`），拿到内核分配的随机端口之后
  才加载 `http://127.0.0.1:<port>/`。所以第一帧会等一下子，端口每次冷启动都不同。
* **想在自己电脑上看这个页面**：`adb logcat -s subconv` 里找 `Web UI: http://127.0.0.1:<port>/`，
  然后 `adb forward tcp:8080 tcp:<port>`，浏览器打开 `http://127.0.0.1:8080/`。
* **返回键**：先让页面回退，回不到上一页才退出 App。
* **下载按钮**：文件落进系统「下载」目录（API 29+ 走 MediaStore，不需要任何权限）；
  API 24–28 落进 App 自己的外部目录 `Android/data/com.subconverter/files/Download/`。
  界面里没有任何 Toast，所以下载**没有弹窗提示** —— 去「下载」里找文件，失败原因在 logcat。
* **出问题了看哪**：`adb logcat -s subconv`。C++ 侧的提示（含随机端口那一行）、页面里的
  `console.log`、启动失败原因全在这个 tag 下。如果服务根本没起来，那个 WebView 里会渲染
  一段纯文本说明 —— 那是唯一的错误显示方式。

## 目录结构

```
app/src/main/
├── cpp/                              上游的 C++ 核心 + Android 适配层
│   ├── CMakeLists.txt                Android 版构建脚本（上游那份是给 CLI 用的）
│   ├── UPSTREAM.md                   上游 commit、逐项改动清单、功能差异表 ← 先看这个
│   ├── include/subconv/              上游头文件（+ android_http.hpp 是新增的）
│   ├── src/{core,codec,parse,fetch,emit,server}/   上游源码
│   ├── src/fetch/android_http.cpp    【新增】抓取/证书探测 → Java 的桥
│   ├── android/jni_bridge.cpp        【新增】JNI 入口：nativeStart/nativeStop/...
│   ├── third_party/nlohmann/         上游自带
│   ├── third_party/yaml-cpp/         新 vendor 的 yaml-cpp 0.8.0（离线可构建）
│   └── data/web/index.html           上游 Web UI（配置期内嵌进 .so）
├── java/com/subconverter/
│   ├── MainActivity.java             唯一界面：一个 WebView，没有任何原生控件
│   ├── ServerHost.java               服务单例（进程级，Activity 重建时复用）
│   ├── NativeServer.java             libsubconv.so 的 Java 门面
│   ├── NetBridge.java                被 C++ 调用的网络后端（HttpURLConnection / SSLSocket）
│   └── DownloadBridge.java           让 Web UI 的「下载」按钮能存文件
└── keepRules/rules.keep              JNI / JS 接口的 R8 keep 规则
```

## 与桌面版的功能差异

| 能力 | Android | 说明 |
|---|---|---|
| Web UI + 全部 HTTP 接口 | ✅ | 逐字节同上游 |
| 抓取 http(s) 订阅 | ✅ | 走 Java `HttpURLConnection`（NDK 不带 libcurl） |
| 代理（`http://` / `socks5://` / `socks5h://`） | ✅ | Java `Proxy`，SOCKS 用 `createUnresolved` 让代理解析域名 |
| 分享链接 / Base64 订阅解析 | ✅ | 纯 C++ |
| Clash YAML 订阅解析 | ✅ | 内置 yaml-cpp（`-DSUBCONV_USE_YAML=OFF` 可关掉换取更快编译） |
| `--probe-cert` 证书指纹 | ✅ | 走 Java `SSLSocket` + SHA-256 |
| `-k` / insecure | ✅ | 抓订阅有效；证书探测本来就跳过校验 |
| CLI 子命令 | ❌ | Android 上没有命令行入口 |

细节、改动位置与原因都写在 `app/src/main/cpp/UPSTREAM.md`。

## 几个实现上的取舍

* **一个原生控件都不留**：`setContentView(new WebView(this))` —— 没有布局文件、没有进度条、
  没有状态遮罩、没有「重试」按钮，也不弹 Toast，视图树里只有 WebView 一个节点。失败信息只写
  logcat（tag `subconv`），另外把原因以纯文本塞进这个 WebView —— 那仍然是 WebView 的页面
  内容，不是新控件；不然服务没起来时只剩一块白屏，现场什么线索都没有。`Activity` 用的是
  framework 的 `android.app.Activity` + `Theme.DeviceDefault.*.NoActionBar`，因此
  appcompat / material 两个依赖被去掉。唯一为此新增的代码是给 WebView 自己加系统栏
  padding：targetSdk 35+ 强制边到边，不这么做页面标题会被状态栏压住。
* **为什么抓订阅要绕到 Java**：NDK 既不带 libcurl 也不带 OpenSSL。交叉编译它们（还要自带 CA
  bundle）只为了发一个 GET，不划算；交给 `HttpURLConnection` / `SSLSocket` 就等于复用了
  Android 自己的 TLS、重定向、代理、gzip 和系统 CA。代价是每次抓取跨一次 JNI —— 对「转订阅」
  这种低频单线程操作可以忽略。
* **为什么 yaml-cpp 是 vendor 而不是 FetchContent**：上游在配置期从 GitHub 下载。放到 App
  工程里，构建机没外网时会在一个和 YAML 毫无关系的地方报网络错误。0.8.0 的 `src/`+`include/`
  一共 ~310 KB，直接放进 `third_party/` 换一个离线可复现的构建更划算。
* **Android 上的「控制台」是 logcat**：App 进程没有控制台，`stdout/stderr` 会掉进 `/dev/null`。
  所以 `console::write()` 在 Android 上会同时写 logcat（tag `subconv`），`Web UI: http://...`
  和抓取失败原因都看得到：`adb logcat -s subconv`。
* **TMPDIR 由 Java 注入**：上游 `fs::temp_directory()` 找不到 TMPDIR/TEMP/TMP 就退到 `/tmp`，
  而 Android 上没有 `/tmp`。`nativeSetRuntimeDirs()` 把 TMPDIR 指到 App 私有缓存目录，
  订阅的磁盘缓存也放在那里。
* **停服务用 poll + shutdown 两条路**：`accept()` 阻塞在系统调用里，光改一个标志是退不出来的。
  `request_stop()` 对监听套接字 `shutdown()`（Linux/Android 上立刻叫醒 accept），循环里再叠一层
  500ms 的 `poll()` 超时兜底 —— 这样「停止」在任何平台上都有确定的退出时机。
* **转屏不重建 Activity**：`AndroidManifest.xml` 里列了 `configChanges`，转屏/深色模式切换时
  WebView 里的表单内容与 DOM 都留着，不会白屏重载一次。
* **下载按钮**：Web UI 用 `Blob` + `<a download>` 导出。blob URL 原生侧读不到，而且那个页面
  立刻就把 URL `revoke` 了；所以注入一段脚本给 `URL.createObjectURL` 包一层、记住 Blob 对象，
  点击时直接读那个 Blob 再交回 Java 落盘。

## 安全边界

* 服务只绑 `127.0.0.1`（回环），不监听局域网 —— 上游 `--listen 0.0.0.0` 那条路在这里是刻意
  不用：那个接口可以让人抓取任意 URL，暴露到局域网没有意义。
* WebView **只**加载回环页面，外部链接一律交给系统浏览器。这一点同时是在保护
  `addJavascriptInterface` 暴露出去的方法：它们只对回环页面可见。
* `usesCleartextTraffic` 是开着的：本机服务本身就是明文 HTTP，订阅源里 `http://` 也很常见。

## 仓库约定（什么进库、什么不进）

规则都在根目录的 `.gitignore` 里，只排两类东西：**只对某台机器成立的**和**可再生产的**。

| 路径 | 进库 | 为什么 |
|---|---|---|
| `local.properties` | ❌ | 里面是 `sdk.dir` 这类绝对路径，而且 Studio 每次 Sync 都会按自己的设置重写它（见「本机环境」）。让每个人自己生成 |
| `build/`、`app/build/`、`app/.cxx/`、`.gradle/` | ❌ | 全是可再生的构建产物；本机 `app/.cxx` 一个人就有 400+ MB |
| `.idea/`、`*.iml` | ❌ | 这个工程的构建配置全在 Gradle 里，本机 `.idea` 下只有一个 `workspace.xml`，没有值得共享的东西 |
| `*.jks`、`*.keystore`、`keystore.properties` | ❌ | 签名私钥 |
| `gradle/wrapper/gradle-wrapper.jar` | ✅ | **别忽略**：没有它 `gradlew` 就跑不起来 |
| `gradle/libs.versions.toml`、`gradle.properties`、`gradle/gradle-daemon-jvm.properties` | ✅ | 依赖版本与构建开关，与机器无关 |
| `app/src/main/cpp/third_party/` | ✅ | 依赖是 vendor 进来的，为的就是没外网也能构建 |
| `app/src/main/cpp/data/web/index.html` | ✅ | 上游 Web UI，配置期被 `file(READ)` 内嵌进 `.so` |

按上面的规则，需要进库的源码一共 **约 190 个文件 / 1.7 MB**（其中 C++ 侧 1.6 MB），
没有一个是构建产物。

## 第三方组件与许可

| 组件 | 位置 | 许可 |
|---|---|---|
| **subconv**（上游 [ycm50/sub-converter](https://github.com/ycm50/sub-converter)） | `app/src/main/cpp/` 的绝大部分 | 本目录**没有**附带上游的 `LICENSE` 文件 —— 二次分发前请先确认上游仓库的许可 |
| nlohmann/json **3.12.0**（单头文件） | `app/src/main/cpp/third_party/nlohmann/json.hpp` | MIT（文件头 `SPDX-License-Identifier: MIT`） |
| yaml-cpp **0.8.0** | `app/src/main/cpp/third_party/yaml-cpp/` | MIT（`LICENSE`：Copyright (c) 2008-2015 Jesse Beder） |

这是**移植**，不是上游的分支：上游代码的逐项改动（基线 commit、改了哪几个文件、为什么、
功能差异表）都记在 [`app/src/main/cpp/UPSTREAM.md`](app/src/main/cpp/UPSTREAM.md)。

## 已知限制

* 构建要求 `sdk.dir` 指的那份 SDK 里**同时**有 `ndk/<ndkVersion>` 和 `cmake/3.22.1`；
  缺任何一个都会在 **configure 期**就失败（分别报 `NDK not configured` 和
  `CMake ... was not found in SDK, PATH, or by cmake.dir property`），跟代码无关。
  本机是靠 C 盘那份 SDK 里指向 A 盘的两个目录 junction 满足的（见上面「本机环境」）。
* 这个仓库自己**从来没有运行过编译器 / CMake / Gradle**（那是刻意的：移植只交代码）。
  不过 `app/build/` 里留着一次真实构建的现场：debug APK（14.4 MB）、三个 ABI 的
  `libsubconv.so`、`.cxx/` 下的 CMake 与 ninja 日志，说明 C++ 侧确实编得过。
  ⚠️ 「去掉所有 UI」这一次的改动（`MainActivity` 重写 + 依赖裁剪）**还没有重新构建过**。
* workflow 里那三步签名命令（`keytool -genkeypair` / `zipalign -f -p 4` / `apksigner sign`）
  用同一版 `build-tools;36.1.0` 在本机对着 debug APK 的**副本**预演过：签完
  `apksigner verify` 报 v2 + v3 通过（minSdk 24，v1 JAR 签名按 apksigner 的默认值关掉）。
  但这个 workflow **还没有在 CI 上真正跑过**。
* 签名密钥每次构建现生成 ⇒ 每次签名都不同 ⇒ **覆盖安装会失败**，必须先卸载（会清掉 Web UI
  的 localStorage）。要稳定签名就得换成固定密钥，见「手动构建」一节。
* `port` 随机分配，所以每次冷启动端口都不同 —— 这是刻意的，不是 bug（想在电脑上访问这个
  页面，见上面「使用」一节的办法）。
* `NetBridge` 走的是 JNI 的 modified UTF-8。影响范围只有 URL / 响应头 / 异常消息里的
  emoji（BMP 内的中文日文韩文与 UTF-8 逐字节相同），订阅正文是 base64 过的，不受影响。
* **带认证的代理不支持**：`http://user:pass@host:port` 里的 `user:pass` 会被丢掉。
  Java 侧给 SOCKS 传认证只能靠全局 `java.net.Authenticator`（进程级共享状态，会在别处
  产生难以预料的影响），所以这里选择不实现而不是勉强实现。要带认证的代理，先用本地一个
  免认证的转发端口。
* `--probe-cert` 在 Android 上走 Java，与上游 OpenSSL 行为一致但实现不同；对端不返回证书时
  报的是 Java 侧的措辞。
