# ============================================================================
# subconv for Android —— AGP 的入口，只负责「Android 与上游不一样的地方」
#
# 目标产物：libsubconv.so —— 上游 subconv 的 C++ 核心 + 一个 JNI 入口。
# Java 侧（com.subconverter.NativeServer）调它起服务，拿到端口后交给 WebView。
#
# **源文件列表 / 编译选项 / C++ 标准探测 / 依赖发现 / Web UI 内嵌全部复用上游 CMakeLists**：
# 同步任务把上游那份取成 upstream.cmake（见 gradle/subconv-upstream.gradle.kts 里的
# UPSTREAM_RENAMES），下面 include 进来。于是上游新增或删除源文件时，本文件一个字都不用改。
# 本文件里刻意**不出现任何 src/**.cpp 清单** —— 出现就意味着又走回漂移的老路了
# （syncUpstream 会直接把这种情况报成错误，见它第 7 步的复用自检）。
#
# 与上游的差别只有四条：
#   * 不编 CLI / 单测（宿主是 JNI）
#   * 不找 libcurl：抓订阅改走 Java 的 HttpURLConnection（src/fetch/android_http.cpp）
#   * 不找 OpenSSL：--probe-cert 改走 Java 的 SSLSocket（同上）
#   * yaml-cpp 用 third_party/ 里 vendor 的那份静态编进来（离线可构建）
# ============================================================================
cmake_minimum_required(VERSION 3.22)
project(subconv_android LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Android 侧的能力开关
#
# 必须在 include 上游之前设好：上游用的是 option()，而 option() 尊重已经存在的缓存项，
# 所以这里设的就是最终值。关掉 CLI 之后 "subconv" 这个名字空出来，正好给下面的 JNI 用。
# ---------------------------------------------------------------------------
set(SUBCONV_BUILD_CLI       OFF CACHE BOOL "" FORCE)   # 宿主是 JNI，不需要命令行程序
set(SUBCONV_BUILD_TESTS     OFF CACHE BOOL "" FORCE)   # 单测在桌面构建里跑，不进 App
set(SUBCONV_USE_CURL        OFF CACHE BOOL "" FORCE)   # 抓订阅走 Java HttpURLConnection
set(SUBCONV_USE_OPENSSL     OFF CACHE BOOL "" FORCE)   # --probe-cert 走 Java SSLSocket
option(SUBCONV_USE_YAML "启用内置 yaml-cpp 解析 Clash 订阅" ON)

# 对外显示的版本号：/api/version、响应头 X-Subconv-Version、配置首行注释都用它
set(SUBCONV_VERSION "0.1.0-android" CACHE STRING "对外显示的版本号" FORCE)

# ---------------------------------------------------------------------------
# Web UI：内嵌由上游 CMakeLists 负责（读 data/web/index.html 生成 web_ui.hpp）。
# 这里只补一道上游没有的检查 —— 原始字符串的结束标记真出现在 HTML 里，生成的 C++ 会被
# 切断，而那时的报错完全指不到这里。放在 include 之前，代价是一次 file(READ)。
# ---------------------------------------------------------------------------
set(SUBCONV_WEB_UI_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/data/web/index.html")
if(EXISTS "${SUBCONV_WEB_UI_SOURCE}")
  file(READ "${SUBCONV_WEB_UI_SOURCE}" _subconv_web_ui_probe)
  string(FIND "${_subconv_web_ui_probe}" ")SUBCONVHTML\"" _subconv_web_ui_hit)
  if(NOT _subconv_web_ui_hit EQUAL -1)
    message(FATAL_ERROR
      "data/web/index.html 里出现了原始字符串结束标记 )SUBCONVHTML\"，"
      "会给 web_ui.hpp 生成出损坏的源码；请换掉这处文本或改上游的界定符。")
  endif()
  unset(_subconv_web_ui_probe)
endif()

# ---------------------------------------------------------------------------
# yaml-cpp（vendored 0.8.0，离线可构建）
#
# 上游用 FetchContent 在配置期从 GitHub 下载；App 工程那样做会在构建机没外网时报一个和
# YAML 毫无关系的网络错误，所以直接静态编 third_party 里这份。
#
# 上游 CMakeLists 的顺序是 find_package(yaml-cpp QUIET) → 没找到再看 TARGET yaml-cpp。
# 这里先把 yaml-cpp 目标建出来，于是它自然会命中 —— 不需要让上游感知 Android 的存在。
# 同时禁掉 find_package：交叉编译时它有可能摸到构建机上的宿主 yaml-cpp（架构不对，
# 表现是链接期一堆 ABI 错误），而内置那份本来就该是唯一来源。
#
# 注意 yaml-cpp 的 CMakeLists 声明的是 cmake_minimum_required(VERSION 3.4)，CMake 4.0 起
# 不再兼容低于 3.5 的声明。CMAKE_POLICY_VERSION_MINIMUM 是官方过渡开关（3.31+ 认识，
# 更老的版本只当看到一个没用到的变量），必须在 add_subdirectory() 之前设好。
# 这里不动 vendor 进来的文件。
# ---------------------------------------------------------------------------
set(CMAKE_DISABLE_FIND_PACKAGE_yaml-cpp TRUE)
if(SUBCONV_USE_YAML)
  if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/yaml-cpp/CMakeLists.txt")
    message(FATAL_ERROR
      "SUBCONV_USE_YAML=ON 但缺少 third_party/yaml-cpp/；"
      "要么补齐该目录，要么用 -DSUBCONV_USE_YAML=OFF 关掉 Clash YAML 解析。")
  endif()
  if(NOT DEFINED CMAKE_POLICY_VERSION_MINIMUM)
    set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING
        "允许第三方依赖声明低于 3.5 的 cmake_minimum_required")
  endif()
  set(YAML_CPP_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
  set(YAML_CPP_BUILD_TOOLS    OFF CACHE BOOL "" FORCE)
  set(YAML_CPP_BUILD_CONTRIB  OFF CACHE BOOL "" FORCE)
  set(YAML_CPP_INSTALL        OFF CACHE BOOL "" FORCE)
  set(YAML_CPP_FORMAT_SOURCE  OFF CACHE BOOL "" FORCE)
  set(YAML_BUILD_SHARED_LIBS  OFF CACHE BOOL "" FORCE)
  add_subdirectory(third_party/yaml-cpp EXCLUDE_FROM_ALL)
endif()

# ---------------------------------------------------------------------------
# 复用上游 CMakeLists
#
# 用 include() 而不是 add_subdirectory()：上游那份是按「自己就是工程根」写的（相对路径
# 与 ${CMAKE_CURRENT_SOURCE_DIR} 都基于当前目录），include 进来这两者依然对得上，
# 也不必把整棵 vendor 树搬进子目录。
# ---------------------------------------------------------------------------
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/upstream.cmake")
  message(FATAL_ERROR
    "缺少 upstream.cmake（上游 CMakeLists.txt 的同步副本）。先跑一次：\n"
    "  ./gradlew syncUpstream")
endif()
include("${CMAKE_CURRENT_SOURCE_DIR}/upstream.cmake")

# 上游那句「yaml-cpp: 使用系统安装的库」在 Android 上说的就是下面这个内置目标：
# 上游是 find_package 失败后落到 TARGET yaml-cpp，而那份目标正是我们上面先建出来的。
if(SUBCONV_USE_YAML AND TARGET yaml-cpp)
  message(STATUS "yaml-cpp: 用 third_party/ 里 vendor 的 0.8.0 静态编进来（离线可构建）")
endif()

# ---------------------------------------------------------------------------
# Android 专有：抓订阅 / 证书探测的后端桥
#
# 这个文件不属于上游（在同步任务的 ANDROID_OWNED 边界清单里，永远不会被覆盖），
# 所以要在这里自己加进 subconv_core。
# ---------------------------------------------------------------------------
target_sources(subconv_core PRIVATE src/fetch/android_http.cpp)
target_compile_definitions(subconv_core PUBLIC SUBCONV_HAVE_ANDROID_HTTP=1)

# ---------------------------------------------------------------------------
# 平台库
#
#   log：console.cpp 在 Android 上把面向人的提示写进 logcat（没有控制台）。
#   Threads：上游 CMakeLists 已经 find_package + 链接好了，这里不重复。
# ---------------------------------------------------------------------------
find_library(SUBCONV_LOG_LIBRARY log)
if(SUBCONV_LOG_LIBRARY)
  target_link_libraries(subconv_core PUBLIC ${SUBCONV_LOG_LIBRARY})
else()
  message(WARNING "没找到 liblog：console 输出只会走 stdout/stderr，logcat 里看不到")
endif()

# ---------------------------------------------------------------------------
# JNI 入口（App 加载的就是它）
#
# 名字就叫 subconv：上游在 SUBCONV_BUILD_CLI=OFF 时不产出同名目标，这个名字是空的。
# Java 侧 System.loadLibrary("subconv") 对应的就是 libsubconv.so。
# ---------------------------------------------------------------------------
add_library(subconv SHARED android/jni_bridge.cpp)
target_link_libraries(subconv PRIVATE subconv_core)

# Gradle 侧按需读这个属性决定 .so 的文件名（默认就是 libsubconv.so，写出来只是为了明确）
set_target_properties(subconv PROPERTIES OUTPUT_NAME "subconv")

# ---------------------------------------------------------------------------
# 配置摘要：多 ABI 一起构建时，日志里能一眼看清这份产物是什么
# ---------------------------------------------------------------------------
message(STATUS "subconv android ${SUBCONV_VERSION} | ${CMAKE_BUILD_TYPE} | ABI=${ANDROID_ABI} API=${ANDROID_PLATFORM} STL=${ANDROID_STL}")
message(STATUS "  源文件列表与编译选项来自 upstream.cmake（复用上游 CMakeLists，Android 侧不再维护清单）")
