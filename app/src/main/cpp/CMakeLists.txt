# ============================================================================
# subconv for Android
#
# 目标产物：libsubconv.so —— 里面是上游 subconv 的 C++ 核心 + 一个 JNI 入口。
# Java 侧（com.subconverter.NativeServer）调它起服务，拿到端口后交给 WebView。
#
# 与上游 CMakeLists.txt 的差别只有「Android 需要什么」：
#   * 不编 CLI / 单测（Android 没有命令行入口，宿主是 JNI）
#   * 不找 libcurl：抓订阅改走 Java 的 HttpURLConnection（src/fetch/android_http.cpp）
#   * 不找 OpenSSL：--probe-cert 改走 Java 的 SSLSocket（同样在 android_http.cpp 里）
#   * yaml-cpp 用 third_party/ 里 vendor 的那份静态编进来（离线可构建）
#   * Web UI 的内嵌方式与上游完全一致：配置期把 index.html 读成 C++ 原始字符串
# ============================================================================
cmake_minimum_required(VERSION 3.22)
project(subconv_android LANGUAGES CXX)

# ---------------------------------------------------------------------------
# C++ 标准
#
# 上游用了 std::expected（C++23 的库特性）。NDK r26 是 Clang 17 / libc++ 17，
# r27 是 Clang 18 / libc++ 18，两边都已经有 <expected>，所以直接要 C++23 就行，
# 不需要上游那段「试编一段代码挑标准开关」的探测逻辑。
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ---------------------------------------------------------------------------
# 对外显示的版本号：/api/version、响应头 X-Subconv-Version、配置首行注释都用它
# ---------------------------------------------------------------------------
set(SUBCONV_VERSION "0.1.0-android" CACHE STRING "对外显示的版本号")

# ---------------------------------------------------------------------------
# 可选能力开关
#
# 关掉 YAML 后 Clash YAML 订阅就不能当输入源（分享链接 / Base64 不受影响）。
# 默认开着，因为机场订阅有很大一部分是 Clash YAML。
# ---------------------------------------------------------------------------
option(SUBCONV_USE_YAML "启用内置 yaml-cpp 解析 Clash 订阅" ON)

# ---------------------------------------------------------------------------
# Web UI 资源：data/web/index.html 内嵌进 .so，运行时不依赖任何资源路径
# （与上游 data/README.md 里描述的做法一致）
# ---------------------------------------------------------------------------
set(SUBCONV_WEB_UI_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/data/web/index.html")
if(NOT EXISTS "${SUBCONV_WEB_UI_SOURCE}")
  message(FATAL_ERROR "缺少 Web UI 资源: ${SUBCONV_WEB_UI_SOURCE}")
endif()
# 改 HTML 也要重新 configure，否则内嵌的内容不会更新
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${SUBCONV_WEB_UI_SOURCE}")

file(READ "${SUBCONV_WEB_UI_SOURCE}" SUBCONV_WEB_UI_HTML)

# 原始字符串的字面量边界是 )SUBCONVHTML" —— HTML 里真出现这一串就会把 C++ 源码切断，
# 那种报错（一堆莫名其妙的 missing ) ）完全指不到这里，所以直接挡住。
string(FIND "${SUBCONV_WEB_UI_HTML}" ")SUBCONVHTML\"" SUBCONV_WEB_UI_DELIM_HIT)
if(NOT SUBCONV_WEB_UI_DELIM_HIT EQUAL -1)
  message(FATAL_ERROR
    "data/web/index.html 里出现了原始字符串结束标记 )SUBCONVHTML\"，"
    "会给 web_ui.hpp 生成出损坏的源码；请换掉这处文本或改本文件的界定符。")
endif()

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/generated/web_ui.hpp"
"// 本文件由 CMake 从 data/web/index.html 生成 —— 请勿手工编辑。
#pragma once

namespace subconv::server {

inline constexpr const char* kWebUiHtml = R\"SUBCONVHTML(
${SUBCONV_WEB_UI_HTML}
)SUBCONVHTML\";

}  // namespace subconv::server
")

# ---------------------------------------------------------------------------
# yaml-cpp（vendored 0.8.0）
#
# 上游用 FetchContent 在配置期从 GitHub 下载；App 工程里那样做会在构建机没外网时
# 报一个和 YAML 毫无关系的网络错误，所以直接静态编 third_party 里的源码。
#
# 注意：yaml-cpp 的 CMakeLists.txt 声明的是 cmake_minimum_required(VERSION 3.4)，
# CMake 4.0 起不再兼容 < 3.5 的工程声明会直接报错。CMAKE_POLICY_VERSION_MINIMUM
# 是官方给的过渡开关（3.31+ 认识，更老的版本只当看到个没用到的变量），
# 必须在 add_subdirectory() 之前设好。这里不动 vendor 进来的文件。
# ---------------------------------------------------------------------------
set(SUBCONV_YAML_TARGET "")
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
  if(TARGET yaml-cpp::yaml-cpp)
    set(SUBCONV_YAML_TARGET yaml-cpp::yaml-cpp)
  else()
    set(SUBCONV_YAML_TARGET yaml-cpp)
  endif()
  message(STATUS "yaml-cpp: 使用内置源码静态编译 -> 启用 Clash 订阅解析")
else()
  message(STATUS "yaml-cpp: 已关闭 -> 不支持解析 Clash 订阅")
endif()

# ---------------------------------------------------------------------------
# 核心静态库
# ---------------------------------------------------------------------------
add_library(subconv_core STATIC
  src/core/types.cpp
  src/core/fsutil.cpp
  src/core/console.cpp
  src/core/vless_encryption.cpp
  src/codec/base64.cpp
  src/codec/url.cpp
  src/parse/ss.cpp
  src/parse/ssr.cpp
  src/parse/vmess.cpp
  src/parse/vless.cpp
  src/parse/trojan.cpp
  src/parse/hysteria.cpp
  src/parse/tuic.cpp
  src/parse/snell.cpp
  src/parse/uri_common.cpp
  src/parse/clash_yaml.cpp
  src/parse/parse.cpp
  src/fetch/http.cpp
  src/fetch/android_http.cpp
  src/fetch/certprobe.cpp
  src/fetch/load.cpp
  src/emit/yaml.cpp
  src/emit/clash.cpp
  src/emit/xray.cpp
  src/emit/singbox.cpp
  src/emit/sharelink.cpp
  src/emit/xhttp.cpp
  src/emit/rulesets.cpp
  src/emit/dns.cpp
  src/emit/emit.cpp
  src/server/convert.cpp
  src/server/request.cpp
  src/server/http.cpp
)

target_include_directories(subconv_core PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party"
)

# web_ui.hpp 只生成在构建目录里，只有 server/http.cpp 用得到，所以是 PRIVATE
target_include_directories(subconv_core PRIVATE
  "${CMAKE_CURRENT_BINARY_DIR}/generated"
)

target_compile_definitions(subconv_core PUBLIC
  SUBCONV_VERSION="${SUBCONV_VERSION}"
  # 抓订阅 / 证书探测走后端桥（src/fetch/android_http.cpp）
  SUBCONV_HAVE_ANDROID_HTTP=1
)

if(SUBCONV_YAML_TARGET)
  target_link_libraries(subconv_core PUBLIC ${SUBCONV_YAML_TARGET})
  target_compile_definitions(subconv_core PUBLIC SUBCONV_HAVE_YAML=1)
endif()

# ---------------------------------------------------------------------------
# 平台库
#
#   Threads：上游的抓取重试用 std::thread，bionic 里 pthread 在 libc，
#            但走 find_package 更稳（NDK 的 toolchain 文件会正确填 -pthread）。
#   log    ：console.cpp 在 Android 上把面向人的提示写进 logcat（没有控制台）。
#   android：不需要，这里不链。
# ---------------------------------------------------------------------------
find_package(Threads REQUIRED)
target_link_libraries(subconv_core PUBLIC Threads::Threads)

find_library(SUBCONV_LOG_LIBRARY log)
if(SUBCONV_LOG_LIBRARY)
  target_link_libraries(subconv_core PUBLIC ${SUBCONV_LOG_LIBRARY})
else()
  message(WARNING "没找到 liblog：console 输出只会走 stdout/stderr，logcat 里看不到")
endif()

# ---------------------------------------------------------------------------
# JNI 入口（App 加载的就是它）
# ---------------------------------------------------------------------------
add_library(subconv SHARED
  android/jni_bridge.cpp
)

target_link_libraries(subconv PRIVATE subconv_core)

# Gradle 侧按需读这个属性决定 .so 的文件名（默认就是 libsubconv.so，写出来只是为了明确）
set_target_properties(subconv PROPERTIES OUTPUT_NAME "subconv")

# ---------------------------------------------------------------------------
# 配置摘要：多 ABI 一起构建时，日志里能一眼看清这份产物是什么
# ---------------------------------------------------------------------------
message(STATUS "subconv android ${SUBCONV_VERSION} | C++${CMAKE_CXX_STANDARD} | ${CMAKE_BUILD_TYPE}")
message(STATUS "  ABI=${ANDROID_ABI} API=${ANDROID_PLATFORM} STL=${ANDROID_STL} | yaml=${SUBCONV_USE_YAML} | curl=java-bridge openssl=java-bridge")
