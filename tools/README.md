# tools/ —— 不打开 Studio 编内核

| 文件 | 干什么 |
|---|---|
| `build-native.ps1` | 用 NDK 直接编出三份 `libsubconv.so` 并逐项自检（Windows / PowerShell 5.1+） |
| `upstream-ref.txt` | 移植基线锚点（一个 commit hash）；`./gradlew syncUpstream` 默认同步到它 |

**「拉上游 → 套补丁 → 自检」不在这个目录**，它是 Gradle 任务，实现在
[`../gradle/subconv-upstream.gradle.kts`](../gradle/subconv-upstream.gradle.kts)：

```bash
./gradlew syncUpstream                       # 拉上游 + 覆盖 vendor 目录 + 套 patches/ + 自检
./gradlew syncUpstream -Psubconv.dryRun=true # 只看离锚点差多少，一个字都不写
./gradlew verifyKernel                       # 核对 APK 里三个 ABI 的 .so 都在
```

写成 Gradle 任务是为了跨平台 —— `.github/workflows/manual-build.yml` 跑在 ubuntu 上，
这个目录里的 PowerShell 脚本在那儿用不了 —— 而且它**默认挂在构建上**：
`./gradlew :app:assembleDebug` 本身就会先同步、再编内核。

> 这里原来还有一个 `sync-upstream.ps1`，功能与 Gradle 任务完全重合、边界清单还各写了一份
> （两边漂移是迟早的事），已删除。`build-native.ps1` 保留：它换的是**另一条构建驱动**
> （手写 CMake 命令而不是 AGP），算独立验证，不是重复实现。

边界清单、属性表、自检项，以及「CMakeLists 的源文件列表只报警告、不自动改」的原因，
都在[根 README 的「跟进上游」](../README.md#跟进上游)里。

## 典型工作流

```bash
# 1) 看一眼现在离锚点差多少（不动任何文件）
./gradlew syncUpstream -Psubconv.dryRun=true

# 2) 跟进上游新版本、前移锚点（构建前本来就会自动同步，这里也可以单独跑）
./gradlew syncUpstream -Psubconv.fetch=true -Psubconv.ref=<新commit> -Psubconv.updatePin=true

# 3) 走 AGP 出包（会先自动同步），再核对三份 .so 真的进了 APK
./gradlew :app:assembleRelease
./gradlew verifyKernel

# 4) 不打开 Studio，换一条构建路再验一遍「C++ 侧编得过」
powershell -ExecutionPolicy Bypass -File tools\build-native.ps1

# 5) 提交（C++ 源码 + 补丁 + 锚点一起提交，别只提交一半）
git add app/src/main/cpp patches tools gradle && git commit -m "同步上游 <新commit>"
```

上游仓库默认取**同级目录**的 `..\sub-converter`（本地克隆）；不是这个位置就用
`-Psubconv.upstream=<路径或 URL>` 指 —— 给 URL 时会 clone 到 `build/upstream-cache`，
CI 上走的就是这条路。

## build-native.ps1

### 它和 Gradle 的关系

走的是**同一条**构建路：同一个 `CMakeLists.txt`、同一份 NDK、同一组 `-D` 开关，
只是把 AGP 换成手写命令。所以它验证的是「C++ 侧编得过」，不是「APK 打得出来」——
打 APK 仍然走 Gradle（见根 `README.md` 的「构建」）。

它**不碰上游**：不同步、不套补丁，编的就是 `app/src/main/cpp` 当时的样子。
（要先把源码准备成「上游 + 补丁」，先跑 `./gradlew syncUpstream`。）

参数来源也不另立一份：`sdk.dir` 读 `local.properties`，`ndkVersion` / `minSdk` 读
`app/build.gradle.kts`，避免两处版本对不上。

```
源码    : app\src\main\cpp
产物    : build\native-so\<abi>\libsubconv.so      （build\ 已在 .gitignore 里）
缓存    : build\native-so\.cmake\<abi>             （-Clean 会清掉它）
开关    : -DANDROID_STL=c++_static -DCMAKE_BUILD_TYPE=Release -DSUBCONV_USE_YAML=ON
```

### 每个 ABI 验三样

这三样错了都是「编得过、装到手机上才炸」的类型：

1. **ELF 架构**：`e_machine` = `0xB7`(aarch64) / `0x28`(arm) / `0x3E`(x86-64)
2. **libc++ 真的静态链进去了**：`DT_NEEDED` 里**不能**出现 `libc++_shared.so`；
   出现 `libyaml-cpp` / `libcurl` / `libssl` 同理（yaml-cpp 是内置源码静态编的，
   curl/TLS 走 Java 桥）
3. **JNI 入口在**：6 个符号
   `Java_com_subconverter_NativeServer_{nativeVersion,nativeSetRuntimeDirs,nativeStart,nativeStop,nativeLastError,nativeRunning}`
   —— 少一个就是 `UnsatisfiedLinkError`

本机实测（NDK 28.2.13676358 / CMake 3.22.1 / android-24 / Release）：

| ABI | libsubconv.so | e_machine | JNI | DT_NEEDED |
|---|---|---|---|---|
| arm64-v8a | 28,235,824 B | 0xB7 | 6/6 | `liblog.so`, `libm.so`, `libdl.so`, `libc.so` |
| armeabi-v7a | 22,048,304 B | 0x28 | 6/6 | 同上 |
| x86_64 | 26,271,136 B | 0x3E | 6/6 | 同上 |

只依赖系统库 —— 这就是「内核是自包含的、可以整块替换」的意思。
体积主要是没 strip + 静态 libc++；要不要 strip、要不要按 ABI 拆出 `.so` 之外的
内核文件，都在 Gradle 侧的打包配置里定。

`./gradlew verifyKernel` 查的是另一头：**进 APK 的那份**（三个 ABI 齐不齐、
有没有漏出 `libc++_shared.so`）。两个都过，才算「内核真的到了该到的地方」。

### 参数

| 参数 | 说明 |
|---|---|
| `-Abis` | 要编的 ABI，默认 `arm64-v8a,armeabi-v7a,x86_64`（同 `abiFilters`） |
| `-Api` | `ANDROID_PLATFORM`，默认取 `minSdk` |
| `-CppDir` / `-OutDir` / `-BuildDir` | 源目录 / 产物目录 / CMake 缓存目录 |
| `-Sdk` / `-Ndk` / `-Cmake` | 手工指定路径，默认从工程配置推 |
| `-Clean` | 先删 `-BuildDir`，全量重编 |
| `-Install` | 额外拷进 `app\src\main\jniLibs\<abi>\libsubconv.so`（见下） |

### `-Install` 的坑

只有当 Gradle 侧的 `externalNativeBuild` **关掉**时，`jniLibs` 里那份才会是真正进包的那份；
两边同时产出会被资源合并挡下来。所以默认不开 —— 交给 Gradle 编才是常规路径
（而且那条路会先自动同步上游，见上）。

## 注意事项（改这些脚本时别踩）

* **PS 5.1 只认 UTF-8 BOM 的 `.ps1`。** 不带 BOM 的 UTF-8 脚本会被按 GBK 读，
  中文注释直接变语法错误（报 `Unexpected token`）。用别的方式改过 `build-native.ps1`
  之后，记得重新写回 BOM：

  ```powershell
  $f = 'tools\build-native.ps1'
  [IO.File]::WriteAllText($f, [IO.File]::ReadAllText($f, (New-Object Text.UTF8Encoding($false))), (New-Object Text.UTF8Encoding($true)))
  ```

* **`-Abis` 两种写法都行**：PS 里 `-Abis a,b,c` 本来就是数组；从
  `powershell -File script.ps1 -Abis a,b,c` 进来的是一个字符串，脚本自己会按 `,` 拆。
* **脚本里的外部命令不捕获输出。** 需要读 `cmake` / `ninja` 的输出时，是先生成一个临时
  `.cmd` 再执行、结果落日志文件读回来 —— 因为某些受限环境下「把外部命令的输出管道/赋值」
  会被拦掉，表现是命令**根本没跑**却不报错。改这个脚本时别顺手写成 `$x = & cmake ...`。
* **相对路径不许用「字符串长度相减」算。** 这类代码已经踩过一次：`$env:TEMP` 常常是
  8.3 短名（`C:\Users\ADMINI~1\...`），而 `Get-ChildItem` 返回的 `FullName` 是长名
  （`C:\Users\Administrator\...`），两者长度不同，`Substring($Root.Length + 1)` 切出来的
  是一堆垃圾（`ream/include/subconv/a.hpp`），**而且不报错** —— 后续过滤全部静默落空，
  症状是「清单里一个文件都没有」。正确写法是先取规范长路径再切：

  ```powershell
  $prefix = (Get-Item -LiteralPath $Root).FullName.TrimEnd('\')
  $rel = $_.FullName.Substring($prefix.Length + 1)
  ```

* **两种日志编码并存，别统一。** `git` 的 stdout 是 UTF-8 字节（commit 标题是中文时，
  按 ANSI 读会变成「澶氩钩鍙版瀯寤轰笌鍙戝竷」）—— Gradle 任务（读 git 输出）和
  `build-native.ps1`（读 CMake / ninja 的日志）就是两种读法：前者 `UTF-8`，
  后者是**控制台代码页**（中文 Windows 上是 GBK，按 ANSI 读才对）。
  这是刻意不一样的，别顺手「统一」成一种。
* **凡是「读工程里的源码文件」都显式按 UTF-8 读**（`[IO.File]::ReadAllText/AllLines` +
  `UTF8Encoding($false)`）。PS 5.1 的 `Get-Content` 默认按 ANSI 解，中文注释会变乱码，
  更麻烦的是**多字节乱码会把换行吃掉**，于是行首锚定的正则（比如 CMakeLists.txt 的
  源文件列表检查）会漏掉正好跨在被吃掉的换行上的那一项。
* **锚点文件是 LF、无 BOM。** Gradle 任务用 `writeText(Charsets.UTF_8)` 写它（LF、无 BOM）；
  在 PowerShell 里改它别用 `>`（会写成 UTF-16 + CRLF）。

## 验证过的状态

在本机（Windows / PowerShell 5.1.26100 / JDK 21 / NDK 28.2.13676358 / CMake 3.22.1）跑过：

| 项 | 条件 | 结果 |
|---|---|---|
| 同步回归（移植基线） | 锚点 `7ef9a56`，同步进一份 149 文件的副本 `-Psubconv.cppDir=...`，全部走**默认参数** | 副本与 `app/src/main/cpp` **149/149 逐字节一致**（0 差异、0 单边文件），自检「差异恰好等于补丁集」 |
| 同步回归（跟到 67fba3a） | `-Psubconv.ref=67fba3a -Psubconv.updatePin=true -Psubconv.strict=true` | 写入 15 个（覆盖 13 / 新增 2）、删除 0；4 个补丁全 `OK`；自检「与上游不同：5 个（补丁覆盖：5 个）✅」；锚点前移，第二次跑走快路径（`新增 0 覆盖 5`、一个字节不动） |
| 漂移探针（先响、后修） | 加 `CMakeLists.txt` 那一行**之前**，CI 上 `-Psubconv.strict=true` | `:syncUpstream` 直接红：`同步结果不自洽 —— CMakeLists.txt 的源文件列表和上游对不上：src/core/vless_encryption.cpp`；补上该行后同一检查静默通过 |
| release 三 ABI（= CI 那条路） | 同步到 `67fba3a` 后 `./gradlew :app:assembleRelease` | **BUILD SUCCESSFUL in 1m 43s**；APK 5,894,826 B（5.6 MiB）；`buildCMakeRelWithDebInfo[arm64-v8a/armeabi-v7a/x86_64]` 三个全过；stripped `.so` 1.82 / 1.26 / 1.87 MiB |
| APK 内核校验（release） | `./gradlew verifyKernel`（这次对着 `app-release-unsigned.apk`） | 三个 ABI 全 `OK`、无 `libc++_shared.so` |
| 构建即同步（默认开） | `./gradlew :app:assembleDebug` | 任务图里 `:syncUpstream` 排在 `preBuild` 之前；工作区已干净时打印「跳过写入与套补丁」，5 个补丁目标文件 **mtime 一个都没动**，native 侧照旧 `UP-TO-DATE` |
| 构建即同步（关掉） | `-Psubconv.syncOnBuild=false` | 任务图里没有 `:syncUpstream` |
| APK 内核校验 | `./gradlew verifyKernel`（对着 `app-debug.apk`） | 三个 ABI 的 `libsubconv.so` 都在、没有 `libc++_shared.so`，全部通过 |
| 编译三 ABI | `build-native.ps1`（默认参数） | 3 个 ABI 全 `OK`，见上面那张实测表 |

也就是说：**「拉上游 → 套补丁 → 编内核 → `.so` 进 APK → 校验进包」这条链是跑通过的**，
不是只写出来没验证的。

⚠️ 编译必须能在本机起子进程（CMake 要调 ninja）。受限沙箱下会报
`'ninja.exe' '--version' failed with: 拒绝访问` —— 那是环境拦的，不是工程的问题。
