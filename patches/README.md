# Android 补丁系列

这个目录里的 4 个 `.patch` 就是**本工程对上游 C++ 代码的全部改动**。
`app/src/main/cpp/` 里的上游文件是 vendor 进来的，改动不直接长在源码里，而是以补丁形式
存着 —— 上游一动，重新套一遍就回到「上游 + Android 适配」的状态。

* 改动**为什么**是这些：见 [`../app/src/main/cpp/UPSTREAM.md`](../app/src/main/cpp/UPSTREAM.md)（逐项解释）
* 改动**怎么**跟着上游走：见 [`../README.md`](../README.md) 的「跟进上游」——
  拉上游 + 套补丁的是 Gradle 任务 `./gradlew syncUpstream`（实现在
  [`../gradle/subconv-upstream.gradle.kts`](../gradle/subconv-upstream.gradle.kts)），
  而且**默认挂在构建上**（`./gradlew :app:assembleDebug` 会先同步再编）

## 编号与 UPSTREAM.md 的对应

| 补丁 | 覆盖文件 | 对应 UPSTREAM.md | 规模 |
|---|---|---|---|
| `0001-server-embed.patch` | `include/subconv/server.hpp`、`src/server/http.cpp` | §1 让服务能被嵌进 App | +120 / −3 |
| `0002-http-backend.patch` | `src/fetch/http.cpp` | §2 抓订阅的 HTTP 客户端换后端 | +32 / −3 |
| `0003-certprobe-split.patch` | `src/fetch/certprobe.cpp` | §3 `--probe-cert` 在 Android 上也能用 | +25 / −23 |
| `0004-console-logcat.patch` | `src/core/console.cpp` | §5 让提示进 logcat | +18 / −1 |
| `0005-cmake-embed.patch` | `upstream.cmake`（上游 `CMakeLists.txt` 改名落地后的名字） | §7 让上游 CMakeLists 能被复用 | +22 / −11 |

合计 **+217 / −41，6 个文件**。

`UPSTREAM.md` 的 §4（`src/fetch/android_http.cpp`）**不在补丁里**：那是 Android 自己新增的文件，
本来就不属于上游，同步任务也不会碰它（「边界」清单只有一份，在
`gradle/subconv-upstream.gradle.kts` 顶部的 `UPSTREAM_DIRS` / `UPSTREAM_FILES` / `ANDROID_OWNED`）。
Android 的 `CMakeLists.txt` 入口同样不在补丁里 —— 0005 改的是**上游那份**，见下一节。

## `upstream.cmake` 是怎么来的（0005 为什么改的是它）

上游的 `CMakeLists.txt` 也是**上游所属**文件（在 `UPSTREAM_FILES` 里），但它落地时会**改名**成
`upstream.cmake`：AGP 的 CMake 入口必须叫 `CMakeLists.txt`，同一个目录里放不下两个同名文件。
改名映射只有一处定义 —— `gradle/subconv-upstream.gradle.kts` 顶部的 `UPSTREAM_RENAMES`。

于是 `app/src/main/cpp/CMakeLists.txt` 是 Android 自己的入口，它只做三件事：关掉用不到的能力
（CLI / 单测 / curl / OpenSSL）、建出内置的 yaml-cpp 目标、然后 `include(upstream.cmake)`。
**源文件列表、编译选项、C++ 标准探测、依赖发现、Web UI 内嵌全部来自上游那一份** ——
Android 侧不再维护任何源文件清单。这就是「上游新增源文件时不用手工补一行」的原因；
`syncUpstream` 的第 7 步会反过来盯着这件事：入口里要是又出现写死的 `src/*.cpp`，直接报错。

`SUBCONV_BUILD_CLI` 是 0005 加进上游那份的开关（默认 `ON`，所以上游与桌面的构建行为一字不变）：
关掉后上游不产出 CLI 目标，`subconv` 这个名字就空出来给 JNI 的 `libsubconv.so` 用 ——
Android 只链接 `subconv_core`，也不需要把上游的 `src/cli/` vendor 进来。

补丁里的路径写的是 `a/upstream.cmake b/upstream.cmake` —— 这是**从 vendor 目录看**的路径；
同步任务套补丁时的工作目录就是 vendor 目录，所以手工套的时候仍然用下面那条
`--directory=app/src/main/cpp`。

## 为什么是补丁，而不是一条 fork 分支

* **看得见**：改动只有 6 个文件，补丁加起来 ~19 KB，review 的代价是分钟级；
  fork 出去一条分支，代价就变成「和上游比 diff」，上游每动一次都更贵。
* **套得回去**：上游在这 6 个文件上的改动大多是新增分支、拆函数、加一条日志，
  行号会漂但上下文不会 —— 补丁失败时是**明确报错**，不是静默编歪。
* **边界清楚**：同步任务只覆盖「上游所属」的路径，Android 自己的文件（入口 `CMakeLists.txt`、
  JNI 桥、Web UI 之外的适配层、yaml-cpp）永远在射程之外，不存在「顺手把适配层覆盖掉」这种事。
  上游那份 `CMakeLists.txt` 是**共用的**（改名成 `upstream.cmake` 后由入口 include），
  所以它既在射程内、又不需要谁去维护第二份源文件列表。

## 怎么套

正常不用手工套 —— `./gradlew syncUpstream` 会先 vendor 上游源码再按文件名顺序套上这些补丁
（而且构建前会自动跑一次，见根 README）。

手工套（在仓库根目录跑；源码得已经是上游对应版本，补丁路径以 vendor 目录为基准）：

```powershell
# -p1 对应补丁里的 a/ b/ 前缀；两个 -c 是必需的；--directory 是必需的，三个坑都在下面
git -c core.autocrlf=false -c core.eol=lf apply -p1 --directory=app/src/main/cpp patches\0001-server-embed.patch
```

4 个补丁必须**按编号顺序**套（它们互相独立，但固定顺序才可复现）。

### 三个坑

1. **`core.autocrlf=false core.eol=lf` 必须带。** 本仓库 `.gitattributes` 是
   `* text=auto eol=lf`，`git apply` 默认会做 EOL 转换，结果是套完的 5 个文件变成 CRLF
   （实测 4460 字节 vs 正确的 4326 字节，只有这 5 个文件不一样）。补丁本身和工作区都是 LF，
   带这两个开关后套完与工作区**逐字节一致**。
2. **`-p1`**：补丁带 `a/`…`b/` 前缀（由 `git diff` 生成），少这个参数会找不到文件。
3. **在仓库的子目录里直接 `git apply` 会静默不干活。** 这是最坑的一个：vendor 目录
   （`app/src/main/cpp`）本身在 app 仓库里，而 git 一旦认出自己在某个 work tree 里，
   就把补丁路径当成**相对仓库根**解析，于是 `include/subconv/server.hpp` 会被拿去
   仓库根的 `include/` 下找 —— 找不到就当「路径在当前目录之外」**静默忽略**：

   ```
   $ git apply -p1 ../../../../patches/0001-server-embed.patch
   Skipped patch 'include/subconv/server.hpp'.
   Skipped patch 'src/server/http.cpp'.
   $ echo $?
   0                      ← 退出码 0、文件一个字节没变，看起来完全成功
   ```

   两条出路（同步任务用的是第一条的等价做法，它给 git 设了
   `GIT_CEILING_DIRECTORIES=<vendor 目录的上一级>`，让 git 不再往上找 `.git`）：
   * 在仓库根跑，用 `--directory=<vendor 目录>` 指过去（上面那条命令）；
   * 或者把 `GIT_CEILING_DIRECTORIES` 设成 vendor 目录的上一级，再 `cd` 进 vendor 目录套。

   判断有没有踩中：套完 `git status` 应该有 5 个文件被改。**退出码为 0 不代表补丁生效了。**

## 套不上怎么办

上游改了这 5 个文件里的内容，补丁上下文对不上时 `git apply` 会整体失败。两条路：

* **看冲突**：`./gradlew syncUpstream -Psubconv.reject=true` —— 能套的套上，套不上的落 `.rej`
  文件，人工改完再重跑一次干净同步。
* **重新生成**（推荐，冲突是常态）：

  ```powershell
  # 1) 在临时目录里把上游的新版本 checkout 出来
  # 2) 把当前工作区里改过的 5 个文件覆盖进去（它们才是"正确答案"）
  # 3) 生成补丁
  git -c core.autocrlf=false -c core.eol=lf diff --output=0001-server-embed.patch -- include/subconv/server.hpp src/server/http.cpp
  ```

  注意 `--output=` 而不是 `>`：PS 的 `>` 会写成 UTF-16 并把 `\n` 变 CRLF。
  这批补丁当初就是用「临时 git 仓库 + `git diff --output=`」生成的，补丁里没有索引 blob
  之外的机器相关信息。

`git apply --3way` **用不了**：补丁里的 pre-image blob 只存在于上游仓库，
Android 仓库这边没有那些对象，`--3way` 会直接报 `could not build fake ancestor`。

## 什么时候需要动这个目录

| 情况 | 做什么 |
|---|---|
| 上游更新，补丁照常套上 | 什么都不用做，同步任务会自动套（构建前也会） |
| 上游更新，补丁套不上 | 按上面「重新生成」重做补丁，并同步改 `UPSTREAM.md` 的对应小节 |
| 你要**新增**一处 Android 改动 | 先改 `app/src/main/cpp` 里的文件，再把它重新生成进对应补丁；新开一个编号的补丁只适合「独立成块」的改动 |
| 某处改动被上游吸收了 | 删掉对应补丁（或改成空补丁），并从 `UPSTREAM.md` 里移除该条 |

改完补丁**一定要跑一次同步的自检**（`./gradlew syncUpstream`，或直接从 `assembleDebug` 走一遍）：
它会重新和上游逐字节比对，正常输出是「差异恰好等于补丁集」；不一致就说明补丁没套上或者套歪了。
