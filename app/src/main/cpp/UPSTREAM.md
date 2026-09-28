# 上游来源与本目录的改动

本目录是 **subconv**（上游仓库 [ycm50/sub-converter](https://github.com/ycm50/sub-converter)）的
Android 移植版。上游是一份 C++23 写的订阅转换工具，命令行 `subconv serve` 会起一个
HTTP 服务 + 内嵌 Web UI；本 App 要做的正是这件事：启动即等价于 `subconv serve`，
然后用 WebView 打开它自己起的那个页面。

| 项 | 值 |
|---|---|
| 上游仓库 | `https://github.com/ycm50/sub-converter` |
| 分支 | `main` |
| 移植基线 commit | `8e857b29047e44b9acec9f9eeddd95cce341f8ec`（2026-09-28，`支持生成链式代理 增加前置后置代理`） |
| 上游版本 | 0.1.0 |
| 移植日期 | 2026-09-14 |

## 怎么跟上游同步

本目录里的上游代码是 **vendor 进来的源码**，不是「链接上游的产物」；对它的改动全部固化成
补丁，所以「跟进上游」跑 Gradle 任务就行，不用手工 diff。**同步默认挂在构建上**，
所以日常是一条命令：

```bash
./gradlew :app:assembleRelease     # pull → 套补丁 → 编内核 → .so 进 APK 的 lib/<abi>/
```

单独同步 / 前移锚点 / 只看差多少：

```bash
./gradlew syncUpstream                                                   # 同步到锚点
./gradlew syncUpstream -Psubconv.dryRun=true                              # 离锚点差多少（不写文件）
./gradlew syncUpstream -Psubconv.fetch=true -Psubconv.ref=<新commit> -Psubconv.updatePin=true
./gradlew verifyKernel                                                    # 核对 APK 里三个 ABI 的 .so
```

* 锚点（默认同步到哪个 commit）在 [`tools/upstream-ref.txt`](../../../../tools/upstream-ref.txt)
* 改动清单在 [`patches/`](../../../../patches/)，每个补丁对应下面的一节
* 任务实现、边界清单、属性表在
  [`gradle/subconv-upstream.gradle.kts`](../../../../gradle/subconv-upstream.gradle.kts) /
  [`README.md`](../../../../README.md) 的「跟进上游」
* 不打开 Studio 单独编三份 `.so` 自检：`tools/build-native.ps1`（Windows，
  用法与自检项见 [`tools/README.md`](../../../../tools/README.md)）

本文件下面的「目录对应关系」「对上游代码的改动」就是补丁在做什么 —— 改补丁时两份要一起改。

## 目录对应关系

| 本目录 | 上游 | 说明 |
|---|---|---|
| `include/subconv/` | `include/subconv/` | 原样拷贝 |
| `src/{core,codec,parse,fetch,emit,server}/` | 同名目录 | 拷贝后有下述改动 |
| `third_party/nlohmann/json.hpp` | 同名 | 原样拷贝（单头文件库） |
| `third_party/yaml-cpp/` | — | 新vendor进来的 yaml-cpp **0.8.0**（见下） |
| `data/web/index.html` | `data/web/index.html` | 原样拷贝，配置期被读成 C++ 字符串内嵌进 `.so` |
| `upstream.cmake` | `CMakeLists.txt` | 上游的构建脚本，**改名落地**（AGP 的入口必须叫 `CMakeLists.txt`，同目录放不下两个同名文件）。由入口 `include()` 复用，见 §7 |
| `CMakeLists.txt`（本目录） | — | 新增：Android 自己的 CMake 入口，只关能力开关 + `include(upstream.cmake)`，**不含源文件清单** |
| `android/` | — | 新增：JNI 入口 + Android 侧 HTTP/证书桥 |
| `src/cli/main.cpp` | `src/cli/main.cpp` | **未拷贝**：Android 上没有命令行入口，宿主是 JNI（上游在 `SUBCONV_BUILD_CLI=OFF` 时也不引用它） |
| `tests/`、`build.sh` 等 | 同名 | **未拷贝**：与 App 构建无关 |

## 对上游代码的改动（全部在下面列出，其余逐字节一致）

### 1. `include/subconv/server.hpp` + `src/server/http.cpp` —— 让服务能被嵌进 App

上游 `run()` 是「阻塞 + 自己打印端口」的命令行形态，App 需要的是「拿到端口 + 能停」：

* 新增 `ReadyHandler` 回调与 `run(opts, on_ready)` 重载：监听成功、进入 accept 循环**之前**
  回调一次，把实际绑定的端口交出来。`opts.port == 0` 时端口由系统分配，
  这是唯一能把它带回 Java 的途径（上游本来就 `getsockname()` 取到了端口，只是只用来打印）。
* 新增 `request_stop()`：`shutdown()` 监听套接字让阻塞中的 `accept()` 立刻返回，
  循环检查停止标志后正常退出。用于随 Activity 生命周期关服务。

### 2. `src/fetch/http.cpp` —— 抓订阅的 HTTP 客户端换后端

上游只有 libcurl 一个实现，缺了它「抓取类功能」整块消失。Android 上 NDK 不带 libcurl，
交叉编译 libcurl 又很重，所以这里加了一条后端：**转调 Java 的 `HttpURLConnection`**（见
`src/fetch/android_http.cpp`），TLS、重定向、代理、gzip 全部复用 Android 自己的网络栈。

* `http_get()` 增加 `#elif defined(SUBCONV_HAVE_ANDROID_HTTP)` 分支
* `http_available()` 在 Android 后端存在时同样返回 `true`
* 其余（重试、退避、嗅探、缓存）完全没动

### 3. `src/fetch/certprobe.cpp` —— `--probe-cert` 在 Android 上也能用

上游把「节点遍历」和「OpenSSL 握手」放在同一个 `#ifdef SUBCONV_HAVE_OPENSSL` 里，
Android 上没有 OpenSSL 就会连遍历一起丢掉。这里把它拆成两层：

* `probe_peer_cert_sha256()` —— 后端相关，三选一：OpenSSL / Android 桥 / 无（报错）
* `probe_node_certificates()` —— 节点遍历与后端无关，移出 `#ifdef`，所有后端共用

Android 桥用 `SSLSocket` + 信任所有的 `TrustManager` 拿到对端叶子证书再做 SHA-256，
语义与上游「不管证书对不对先连上」一致。

### 4. `src/fetch/android_http.cpp`（新增）

JNI → Java 的桥：`http_get()` 与 `probe_peer_cert_sha256()` 两个后端实现。
**未**改任何上游头文件签名，只是补齐了上游预留的 `#else` 分支。

### 5. `src/core/console.cpp` —— 让提示进 logcat

App 进程没有控制台，`stdout/stderr` 会掉进 `/dev/null`：`Web UI: http://...`（里面是随机端口）、
抓取失败原因这些信息会全部看不见。所以在 `write()` 里加了一个 `#ifdef __ANDROID__` 分支，
把面向人的提示同时写进 `__android_log_write`（tag `subconv`，stderr → ERROR / stdout → INFO），
原有的 `fwrite` 保留。**只影响提示**：配置载荷从来不走 `console`（见 `console.hpp` 的约定）。

### 6. `CMakeLists.txt`（本目录，Android 自己的 CMake 入口）

只做 Android 与上游不一样的事，**不含任何源文件清单**：

* 能力开关：`SUBCONV_BUILD_CLI` / `SUBCONV_BUILD_TESTS` / `SUBCONV_USE_CURL` /
  `SUBCONV_USE_OPENSSL` 关掉，`SUBCONV_USE_YAML` 打开。必须在 `include` 之前设 ——
  上游用的是 `option()`，而它尊重已经存在的缓存项。
* 内置 yaml-cpp：先 `add_subdirectory(third_party/yaml-cpp)` 建出 `yaml-cpp` 目标，上游那段
  `find_package` 找不到后落到 `TARGET yaml-cpp`，于是自然命中（不需要上游感知 Android）。
* 补一道上游没有的检查：`data/web/index.html` 里一旦出现 `)SUBCONVHTML"` 就直接报错 ——
  那种情况会把生成的 C++ 切断，而报错完全指不到这里。
* `include(upstream.cmake)`，然后补上 Android 专有的 `src/fetch/android_http.cpp`、
  `SUBCONV_HAVE_ANDROID_HTTP=1`、`liblog`，最后定义 JNI 的 `libsubconv.so`。

### 7. `upstream.cmake` —— 复用上游 CMakeLists（补丁 0005）

上游的 `CMakeLists.txt` 是**上游所属**文件：同步任务把它取下来后改名成 `upstream.cmake`
（改名映射只有一处，在 `gradle/subconv-upstream.gradle.kts` 的 `UPSTREAM_RENAMES`），
再由入口 `include()` 进来。

于是**源文件列表、编译选项、C++ 标准探测、依赖发现、Web UI 内嵌都只有上游一份**：上游新增或
删除源文件时，Android 侧一个字都不用改。这条不是靠自觉，`syncUpstream` 第 7 步会反过来盯：
入口里要是又出现写死的 `src/*.cpp`，或者 `upstream.cmake` 没被入口引用、没列全上游自己的
源文件，都会报错（CI 上 `-Psubconv.strict=true` 时直接失败）。

`0005-cmake-embed.patch` 给上游那份加的只有一件事：`SUBCONV_BUILD_CLI`（默认 `ON`），
把 CLI 目标与 `install(TARGETS subconv)` 包起来。`OFF` 时上游只产出 `subconv_core`，
`subconv` 这个名字空出来给 JNI 的 `libsubconv.so` 用；默认 `ON` 保证上游与桌面的构建行为
一字不变（上游自己的 `build.sh` / `build.ps1` 都没提这个开关）。

## 与上游的功能差异（Android 构建）

| 能力 | 状态 | 原因 |
|---|---|---|
| Web UI（`/`） | ✅ | 逐字节同上游 |
| `/api/version` `/api/rulesets` `/api/dns` `POST /api/convert` | ✅ | 同上 |
| `/sub?target=&url=` 等 subconverter 兼容接口 | ✅ | 同上 |
| 抓取 http(s) 订阅 | ✅ | 走 Java `HttpURLConnection` |
| 代理（`http://` / `socks5://`） | ✅ | 同上，SOCKS 用 `Proxy.Type.SOCKS` |
| 分享链接 / Base64 订阅解析 | ✅ | 纯 C++，与上游一致 |
| Clash YAML 订阅解析 | ✅ | 内置 yaml-cpp 0.8.0 |
| `-k` 跳过 TLS 校验 | ⚠️ | 仅作用于抓订阅；Android 侧用信任所有的 TrustManager 实现 |
| `--probe-cert` 证书指纹 | ✅ | 走 Java `SSLSocket` |
| 链式代理（`?chain=` 前置 / `?chain_rear=` 后置；Web UI「前置代理」「后置代理」输入框） | ✅ | 纯 C++（`src/emit/chain.cpp`），与上游一致；`--chain` / `--chain-rear` 那两个 CLI 开关在 Android 上没有入口，等价能力走 HTTP 参数与 Web UI |
| CLI 子命令（convert / version / --list-*） | ❌ | Android 上没有命令行入口 |
| 磁盘缓存的默认目录 | ⚠️ | 由 JNI 注入 App 私有缓存目录（Android 的 `/tmp` 不可用） |

## yaml-cpp 为什么是 vendor 而不是 FetchContent

上游用 `FetchContent` 在配置期从 GitHub 下载。放到 App 工程里有两个问题：
构建机可能没有外网（或访问 GitHub 很慢），而 Android 构建失败时报的是网络错误，
很难让人联想到「一个 YAML 解析库没下下来」。0.8.0 的 `src/` + `include/` 一共只有
~310 KB，直接放进 `third_party/yaml-cpp/` 换一个离线可复现的构建更划算。

只 vendor 了真正需要的部分（`CMakeLists.txt`、`include/`、`src/`、
三个 `*.cmake.in`/`*.pc.in` 配置期模板、`LICENSE`）；`test/`、`util/`、`docs/`、`.github/` 没要。
**文件本身逐字节未改**——包括 `cmake_minimum_required(VERSION 3.4)`：那在 CMake 4.x 上会
被拒，所以由本目录的 `CMakeLists.txt` 在 `add_subdirectory()` 之前设
`CMAKE_POLICY_VERSION_MINIMUM 3.5` 来处理（上游处理同类问题用的是同一招）。
