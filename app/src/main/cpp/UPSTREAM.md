# 上游来源与本目录的改动

本目录是 **subconv**（上游仓库 [ycm50/sub-converter](https://github.com/ycm50/sub-converter)）的
Android 移植版。上游是一份 C++23 写的订阅转换工具，命令行 `subconv serve` 会起一个
HTTP 服务 + 内嵌 Web UI；本 App 要做的正是这件事：启动即等价于 `subconv serve`，
然后用 WebView 打开它自己起的那个页面。

| 项 | 值 |
|---|---|
| 上游仓库 | `https://github.com/ycm50/sub-converter` |
| 分支 | `main` |
| 移植基线 commit | `7ef9a567a4aec653cb5c7f2fbf17e0f9e3a1f2d7`（2026-09-13） |
| 上游版本 | 0.1.0 |
| 移植日期 | 2026-09-14 |

## 目录对应关系

| 本目录 | 上游 | 说明 |
|---|---|---|
| `include/subconv/` | `include/subconv/` | 原样拷贝 |
| `src/{core,codec,parse,fetch,emit,server}/` | 同名目录 | 拷贝后有下述改动 |
| `third_party/nlohmann/json.hpp` | 同名 | 原样拷贝（单头文件库） |
| `third_party/yaml-cpp/` | — | 新vendor进来的 yaml-cpp **0.8.0**（见下） |
| `data/web/index.html` | `data/web/index.html` | 原样拷贝，配置期被读成 C++ 字符串内嵌进 `.so` |
| `android/` | — | 新增：JNI 入口 + Android 侧 HTTP/证书桥 |
| `src/cli/main.cpp` | `src/cli/main.cpp` | **未拷贝**：Android 上没有命令行入口，宿主是 JNI |
| `tests/`、`CMakeLists.txt`、`build.sh` 等 | 同名 | **未拷贝**：与 App 构建无关 |

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

### 6. `CMakeLists.txt`（本目录，重写）

上游那份是给桌面/CLI 用的：会找 libcurl / OpenSSL / yaml-cpp、编 CLI 和单测。
Android 这份：只编 `subconv_core` 静态库 + `libsubconv.so`，内嵌 Web UI 的方式与上游一致
（配置期 `file(READ)` → `generated/web_ui.hpp`）。

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
