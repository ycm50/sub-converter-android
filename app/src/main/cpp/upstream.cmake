cmake_minimum_required(VERSION 3.20)
project(subconv VERSION 0.1.0 LANGUAGES CXX)

# 对外显示的版本号（subconv --version / 配置首行注释 / GET /api/version）。
# CI 发版时用 tag 覆盖它，让二进制里的版本号和 Release 标签一致：
#   cmake -S . -B build -DSUBCONV_VERSION:STRING=1.0
set(SUBCONV_VERSION "${PROJECT_VERSION}" CACHE STRING "对外显示的版本号")

# ---------------------------------------------------------------------------
# 基本设置
# ---------------------------------------------------------------------------
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(SUBCONV_BUILD_TESTS    "构建单元测试" ON)
option(SUBCONV_BUILD_CLI      "构建命令行程序（嵌入式移植可以关掉，只保留 subconv_core 供宿主链接）" ON)
option(SUBCONV_USE_CURL       "启用 libcurl 订阅抓取" ON)
option(SUBCONV_USE_OPENSSL    "启用 OpenSSL（--probe-cert 证书指纹探测）" ON)
option(SUBCONV_USE_YAML       "启用 yaml-cpp 解析 Clash 订阅" ON)
option(SUBCONV_VENDOR_YAMLCPP "下载源码静态编译 yaml-cpp（发行版只有 0.7 包时用它，避免 libyaml-cpp.so.0.7/0.8 不兼容）" OFF)
option(SUBCONV_STATIC_RUNTIME "静态链接 libstdc++ / libgcc（Linux 上少一个运行时依赖，便于跨发行版分发）" OFF)

# ---------------------------------------------------------------------------
# C++ 标准
#
# 代码用到 std::expected —— 它是 C++23 的库特性，GCC 12+ / Clang 16+ / MSVC 19.33+ 才有。
# 麻烦在于「怎么让编译器开到这个标准」各家不统一：
#   * GCC / Clang 用 -std=c++23，但 GCC 11 那一代只认旧的 -std=c++2b（GCC 12 两个都认）
#   * MSVC 要 /std:c++latest
# 而各版本 CMake 对 CMAKE_CXX_STANDARD=23 的映射也不一致（CMake 3.25 和 3.28 就不一样），
# 在交叉编译 / 老发行版上直接用它经常莫名其妙地配置失败。
# 所以这里现场试编一段真用 std::expected 的代码，挑中哪个选项就给所有目标加上；
# 全都不行时给出的也是「编译器太老」这种一眼能懂的报错，而不是一堆找不到 <expected> 的模板错误。
# ---------------------------------------------------------------------------
include(CheckCXXSourceCompiles)

set(_subconv_std_probe [=[
#include <expected>
#include <string>
int main() {
  std::expected<int, std::string> value = 42;
  if (!value.has_value()) return 1;
  return value.value() == 42 ? 0 : 1;
}
]=])

if(MSVC)
  set(_subconv_std_candidates "/std:c++latest" "/std:c++23preview")
else()
  set(_subconv_std_candidates "-std=c++23" "-std=c++2b")
endif()

set(SUBCONV_CXX_STANDARD_FLAG "")
foreach(_flag IN LISTS _subconv_std_candidates)
  string(MAKE_C_IDENTIFIER "subconv_probe${_flag}" _probe_var)
  set(CMAKE_REQUIRED_FLAGS "${_flag}")
  check_cxx_source_compiles("${_subconv_std_probe}" ${_probe_var})
  if(${_probe_var})
    set(SUBCONV_CXX_STANDARD_FLAG "${_flag}")
    break()
  endif()
endforeach()
unset(CMAKE_REQUIRED_FLAGS)

if(NOT SUBCONV_CXX_STANDARD_FLAG)
  message(FATAL_ERROR
    "找不到支持 std::expected（C++23）的编译选项，试过：${_subconv_std_candidates}\n"
    "请换更新的编译器：GCC >= 12 / Clang >= 16 / MSVC >= 19.33。")
endif()

# ---------------------------------------------------------------------------
# 依赖搜索前缀
#
# MSYS2 / Termux / Conda 的库都不在系统默认路径里，靠环境变量指路。两个坑：
#
#   * MSYS2 shell 里 MINGW_PREFIX / MSYSTEM_PREFIX 是 Unix 风格（/ucrt64）。环境变量
#     不像命令行参数那样会被 MSYS 自动翻译成 Windows 路径，原生 CMake 会把 "/ucrt64"
#     理解成「当前盘符下的 \ucrt64」——等于没指路。CI 上就是这里出的事：
#     find_package(OpenSSL) 找不到，掉进下面的 pkg-config 兜底，拿到一个不存在的
#     "/include"，CMake 在生成阶段直接报错（三个 Windows 架构一起挂）。
#     所以这里优先从编译器路径反推前缀（C:/msys64/ucrt64/bin/g++.exe → C:/msys64/ucrt64），
#     再拿 cygpath 把 Unix 风格的候选翻译成 Windows 路径。
#   * MSYS2 shell 里 PREFIX=/usr 指的是 MSYS 根（不是 mingw 前缀），加进搜索路径会误抓
#     ABI 不兼容的 msys-*.dll 的头文件，所以 Windows 上跳过 PREFIX。
# ---------------------------------------------------------------------------
if(WIN32)
  # 从编译器位置反推：<prefix>/bin/g++.exe -> <prefix>
  if(MINGW AND CMAKE_CXX_COMPILER)
    get_filename_component(_subconv_bindir "${CMAKE_CXX_COMPILER}" DIRECTORY)
    get_filename_component(_subconv_guess "${_subconv_bindir}" DIRECTORY)
    if(EXISTS "${_subconv_guess}/include" OR EXISTS "${_subconv_guess}/lib")
      list(APPEND CMAKE_PREFIX_PATH "${_subconv_guess}")
    endif()
  endif()

  foreach(_env MSYS2_PREFIX MSYSTEM_PREFIX MINGW_PREFIX)
    if(NOT DEFINED ENV{${_env}})
      continue()
    endif()
    set(_subconv_cand "$ENV{${_env}}")
    if(_subconv_cand MATCHES "^/")
      # Unix 风格：交给 cygpath 翻译（MSYS 的 /ucrt64 是挂载点，不是真实路径）
      find_program(SUBCONV_CYGPATH NAMES cygpath)
      if(SUBCONV_CYGPATH)
        execute_process(COMMAND "${SUBCONV_CYGPATH}" -m "${_subconv_cand}"
          OUTPUT_VARIABLE _subconv_cand
          OUTPUT_STRIP_TRAILING_WHITESPACE
          ERROR_QUIET)
      endif()
    endif()
    if(_subconv_cand AND EXISTS "${_subconv_cand}/include")
      list(APPEND CMAKE_PREFIX_PATH "${_subconv_cand}")
    endif()
  endforeach()
else()
  # Termux 的 $PREFIX=/data/data/com.termux/files/usr，Conda 的 $CONDA_PREFIX 同理
  foreach(_env PREFIX CONDA_PREFIX)
    if(DEFINED ENV{${_env}} AND EXISTS "$ENV{${_env}}")
      list(APPEND CMAKE_PREFIX_PATH "$ENV{${_env}}")
    endif()
  endforeach()
endif()
if(CMAKE_PREFIX_PATH)
  list(REMOVE_DUPLICATES CMAKE_PREFIX_PATH)
endif()

# pkg-config 的结果先验一遍路径。前缀没解析出来时 pkg-config 会给出 "/include" 这种
# 根本不存在的目录，留着会让 CMake 在生成阶段报
# 「Imported target ... includes non-existent path」并**整个配置失败**。
# 不存在的路径删掉即可：真缺头文件的话，编译期会给出更清楚的报错。
function(subconv_prune_missing_paths _target)
  if(NOT TARGET ${_target})
    return()
  endif()
  foreach(_prop INTERFACE_INCLUDE_DIRECTORIES INTERFACE_LINK_DIRECTORIES)
    get_target_property(_dirs ${_target} ${_prop})
    if(NOT _dirs)
      continue()
    endif()
    set(_kept "")
    foreach(_d ${_dirs})
      if(EXISTS "${_d}")
        list(APPEND _kept "${_d}")
      else()
        message(STATUS "忽略 pkg-config 给出的不存在的路径: ${_d}")
      endif()
    endforeach()
    set_target_properties(${_target} PROPERTIES ${_prop} "${_kept}")
  endforeach()
endfunction()

if(NOT MSVC)
  add_compile_options(-Wall -Wextra)
endif()

add_compile_options("${SUBCONV_CXX_STANDARD_FLAG}")

# libstdc++ / libgcc 静态化：只在「不用动态 C++ 依赖」时安全。
# 这里只会和静态编译的 yaml-cpp 搭配（SUBCONV_VENDOR_YAMLCPP=ON），不会出现两份 libstdc++。
if(SUBCONV_STATIC_RUNTIME AND NOT MSVC)
  add_link_options(-static-libgcc -static-libstdc++)
endif()

# ---------------------------------------------------------------------------
# Web UI 资源：data/web/index.html 内嵌进二进制，避免运行时找资源路径
# ---------------------------------------------------------------------------
set(SUBCONV_WEB_UI_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/data/web/index.html")
if(NOT EXISTS "${SUBCONV_WEB_UI_SOURCE}")
  message(FATAL_ERROR "缺少 Web UI 资源: ${SUBCONV_WEB_UI_SOURCE}")
endif()
# 改 HTML 也要重新 configure，否则内嵌的内容不会更新
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${SUBCONV_WEB_UI_SOURCE}")
file(READ "${SUBCONV_WEB_UI_SOURCE}" SUBCONV_WEB_UI_HTML)
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
  src/parse/wireguard.cpp
  src/parse/wireguard_common.cpp
  src/parse/uri_common.cpp
  src/parse/clash_yaml.cpp
  src/parse/xray_json.cpp
  src/parse/parse.cpp
  src/fetch/http.cpp
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
  src/emit/chain.cpp
  src/emit/emit.cpp
  src/server/convert.cpp
  src/server/request.cpp
  src/server/http.cpp
)

target_include_directories(subconv_core PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party>"
)

target_include_directories(subconv_core PRIVATE
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated>"
)

# --- 套接字库 ---------------------------------------------------------------
# Windows 的 WinSock 要显式链接；Linux/Termux 的 socket 在 libc 里，
# 但 std::thread（缓存 / 重试）在部分平台上仍需要单独 pthread。
find_package(Threads REQUIRED)
target_link_libraries(subconv_core PUBLIC Threads::Threads)

if(WIN32)
  target_link_libraries(subconv_core PUBLIC ws2_32)
endif()

target_compile_definitions(subconv_core PUBLIC
  SUBCONV_VERSION="${SUBCONV_VERSION}"
)

# --- 可选依赖：一律「找不到就优雅降级」，不让构建失败 -------------------------
if(SUBCONV_USE_CURL OR SUBCONV_USE_OPENSSL OR SUBCONV_USE_YAML)
  find_package(PkgConfig QUIET)
endif()

# --- libcurl ---------------------------------------------------------------
if(SUBCONV_USE_CURL)
  find_package(CURL QUIET)
  if(CURL_FOUND)
    target_link_libraries(subconv_core PUBLIC CURL::libcurl)
    target_compile_definitions(subconv_core PUBLIC SUBCONV_HAVE_CURL=1)
    message(STATUS "libcurl: ${CURL_VERSION_STRING} -> 启用订阅抓取")
  elseif(PkgConfig_FOUND)
    # Termux / Alpine 这类发行版 CMake 自带的 FindCURL 常常找不到，pkg-config 更可靠
    pkg_check_modules(PC_CURL QUIET IMPORTED_TARGET libcurl)
    if(TARGET PkgConfig::PC_CURL)
      subconv_prune_missing_paths(PkgConfig::PC_CURL)
      target_link_libraries(subconv_core PUBLIC PkgConfig::PC_CURL)
      target_compile_definitions(subconv_core PUBLIC SUBCONV_HAVE_CURL=1)
      message(STATUS "libcurl: 经 pkg-config (${PC_CURL_VERSION}) -> 启用订阅抓取")
    else()
      message(STATUS "libcurl: 未找到 -> 订阅抓取暂不可用（仅支持本地文件）")
    endif()
  else()
    message(STATUS "libcurl: 未找到 -> 订阅抓取暂不可用（仅支持本地文件）")
  endif()
else()
  message(STATUS "libcurl: 已按 SUBCONV_USE_CURL=OFF 关闭 -> 仅支持本地文件")
endif()

# --- OpenSSL（--probe-cert 探测对端证书指纹）--------------------------------
if(SUBCONV_USE_OPENSSL)
  find_package(OpenSSL QUIET)
  if(OpenSSL_FOUND)
    target_link_libraries(subconv_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(subconv_core PUBLIC SUBCONV_HAVE_OPENSSL=1)
    message(STATUS "OpenSSL: ${OPENSSL_VERSION} -> 启用 --probe-cert 证书指纹探测")
  elseif(PkgConfig_FOUND)
    pkg_check_modules(PC_OPENSSL QUIET IMPORTED_TARGET libssl libcrypto)
    if(TARGET PkgConfig::PC_OPENSSL)
      subconv_prune_missing_paths(PkgConfig::PC_OPENSSL)
      target_link_libraries(subconv_core PUBLIC PkgConfig::PC_OPENSSL)
      target_compile_definitions(subconv_core PUBLIC SUBCONV_HAVE_OPENSSL=1)
      message(STATUS "OpenSSL: 经 pkg-config (${PC_OPENSSL_VERSION}) -> 启用 --probe-cert 证书指纹探测")
    else()
      message(STATUS "OpenSSL: 未找到 -> --probe-cert 不可用（Xray 目标将只用 verifyPeerCertByName）")
    endif()
  else()
    message(STATUS "OpenSSL: 未找到 -> --probe-cert 不可用（Xray 目标将只用 verifyPeerCertByName）")
  endif()
else()
  message(STATUS "OpenSSL: 已按 SUBCONV_USE_OPENSSL=OFF 关闭 -> --probe-cert 不可用")
endif()

# --- yaml-cpp --------------------------------------------------------------
if(SUBCONV_USE_YAML)
  if(SUBCONV_VENDOR_YAMLCPP)
    # 静态编译一份 yaml-cpp：Linux 各发行版的 libyaml-cpp 是 0.7(22.04/12) 还是 0.8(24.04)
    # 并不一致，动态链接的产物会在另一头起不来（libyaml-cpp.so.0.7: cannot open ...）。
    # 直接静态链进去就没有这个问题，也不需要目标机装 yaml-cpp。
    include(FetchContent)
    # 解压出来的源码用「当前时间」当时间戳，否则每次构建都认为源码比目标文件新。
    # CMP0135 是 CMake 3.24 才有的策略，老 CMake 上这个 if 直接跳过即可。
    if(POLICY CMP0135)
      cmake_policy(SET CMP0135 NEW)
    endif()
    set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
    set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
    set(YAML_CPP_INSTALL OFF CACHE BOOL "" FORCE)
    set(YAML_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    # 用发布 tarball 而不是 git clone：这样构建环境里只要有 cmake 和能出网的 https 就行，
    # 不需要额外装 git（Debian 容器里就没装 git，i686 的 MSYS2 里也没有 yaml-cpp 包）。
    #
    # CMake 4.0 起不再兼容声明 cmake_minimum_required(< 3.5) 的工程，而 yaml-cpp 0.8.0
    # 正是这种老声明，会直接报
    #   CMake Error at .../yaml-cpp-src/CMakeLists.txt:2 (cmake_minimum_required):
    #   Compatibility with CMake < 3.5 has been removed from CMake.
    # CMAKE_POLICY_VERSION_MINIMUM 是官方给的过渡开关（CMake 3.31+ 才认识，更老的版本
    # 只是看到一个没用到的变量），把这类老声明按 3.5 处理。
    # 注意它只会**抬高**下限：本工程自己声明的是 3.20，不受影响。
    if(NOT DEFINED CMAKE_POLICY_VERSION_MINIMUM)
      set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING
          "允许第三方依赖声明低于 3.5 的 cmake_minimum_required")
    endif()
    # 国内直连 GitHub 很慢（几十 KB/s，甚至卡在 0 字节），所以和 tools/*.sh 用同一个
    # 环境变量走镜像：SUBCONV_GH_MIRROR=https://gh-proxy.com/ 这样前缀拼在下载地址前面。
    # 默认取同名环境变量，也可以在命令行上用 -DSUBCONV_GH_MIRROR= 指定；留空就是直连。
    set(SUBCONV_GH_MIRROR "$ENV{SUBCONV_GH_MIRROR}" CACHE STRING
        "GitHub 镜像前缀，例如 https://gh-proxy.com/（默认取同名环境变量）")
    set(_subconv_yamlcpp_url "https://github.com/jbeder/yaml-cpp/archive/refs/tags/0.8.0.tar.gz")
    if(SUBCONV_GH_MIRROR)
      set(_subconv_yamlcpp_url "${SUBCONV_GH_MIRROR}${_subconv_yamlcpp_url}")
      message(STATUS "yaml-cpp: 通过镜像下载 ${_subconv_yamlcpp_url}")
    endif()
    FetchContent_Declare(yaml-cpp URL "${_subconv_yamlcpp_url}")
    FetchContent_MakeAvailable(yaml-cpp)
    if(TARGET yaml-cpp::yaml-cpp)
      set(SUBCONV_YAML_TARGET yaml-cpp::yaml-cpp)
    else()
      set(SUBCONV_YAML_TARGET yaml-cpp)
    endif()
    message(STATUS "yaml-cpp: 使用内置源码静态编译 0.8.0 -> 启用 Clash 订阅解析")
  else()
    find_package(yaml-cpp QUIET)
    if(TARGET yaml-cpp::yaml-cpp)
      set(SUBCONV_YAML_TARGET yaml-cpp::yaml-cpp)
    elseif(TARGET yaml-cpp)
      set(SUBCONV_YAML_TARGET yaml-cpp)
    elseif(PkgConfig_FOUND)
      pkg_check_modules(PC_YAMLCPP QUIET IMPORTED_TARGET yaml-cpp)
      if(TARGET PkgConfig::PC_YAMLCPP)
        subconv_prune_missing_paths(PkgConfig::PC_YAMLCPP)
        set(SUBCONV_YAML_TARGET PkgConfig::PC_YAMLCPP)
      endif()
    endif()
    if(SUBCONV_YAML_TARGET)
      message(STATUS "yaml-cpp: 使用系统安装的库 -> 启用 Clash 订阅解析")
    else()
      message(STATUS "yaml-cpp: 未找到 -> 暂不支持解析 Clash 订阅（可加 -DSUBCONV_VENDOR_YAMLCPP=ON 内置编译）")
    endif()
  endif()

  if(SUBCONV_YAML_TARGET)
    target_link_libraries(subconv_core PUBLIC ${SUBCONV_YAML_TARGET})
    target_compile_definitions(subconv_core PUBLIC SUBCONV_HAVE_YAML=1)
  endif()
else()
  message(STATUS "yaml-cpp: 已按 SUBCONV_USE_YAML=OFF 关闭 -> 暂不支持解析 Clash 订阅")
endif()

# ---------------------------------------------------------------------------
# CLI
#
# SUBCONV_BUILD_CLI=OFF 让这个文件**只产出 subconv_core**：嵌入式移植（App / 库）
# 只要那个静态库，而且它们通常根本没有 src/cli（连可编的命令行入口都没有）。
# 关掉之后 "subconv" 这个名字就空出来了，宿主可以拿它命名自己的产物。
# ---------------------------------------------------------------------------
if(SUBCONV_BUILD_CLI)
  add_executable(subconv src/cli/main.cpp)
  target_link_libraries(subconv PRIVATE subconv_core)

  # 把「二进制 + 可能的同级依赖」当成一个可搬运的目录：Linux 上给可执行文件加
  # $ORIGIN 的 rpath —— 用户（或发行包）把 libyaml-cpp.so 之类放在 exe 旁边也能被找到，
  # 同时不影响系统库的查找顺序。注意 $ORIGIN 在 CMake 里要转义。
  if(UNIX)
    set_target_properties(subconv PROPERTIES
      BUILD_RPATH "\$ORIGIN"
      INSTALL_RPATH "\$ORIGIN")
  endif()
else()
  message(STATUS "CLI: 已按 SUBCONV_BUILD_CLI=OFF 关闭 -> 只产出 subconv_core")
endif()

# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------
if(SUBCONV_BUILD_TESTS)
  enable_testing()
  add_executable(subconv_tests tests/test_main.cpp)
  target_link_libraries(subconv_tests PRIVATE subconv_core)
  add_test(NAME subconv_tests COMMAND subconv_tests)
endif()

# ---------------------------------------------------------------------------
# 安装
# ---------------------------------------------------------------------------
if(SUBCONV_BUILD_CLI)
  install(TARGETS subconv RUNTIME DESTINATION bin)
endif()
install(DIRECTORY data/ DESTINATION share/subconv/data OPTIONAL)

# 目标平台摘要：交叉编译 / 多架构发布会同时打好几个包，日志里能一眼看清这份产物是什么
message(STATUS "subconv ${PROJECT_VERSION} | C++ (${SUBCONV_CXX_STANDARD_FLAG}) | ${CMAKE_BUILD_TYPE} | ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "目标平台: ${CMAKE_SYSTEM_NAME} / ${CMAKE_SYSTEM_PROCESSOR} | 静态运行时: ${SUBCONV_STATIC_RUNTIME} | 内置 yaml-cpp: ${SUBCONV_VENDOR_YAMLCPP}")
