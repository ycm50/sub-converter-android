// 文件系统小工具
//
// 为什么不用 <filesystem>：
//   Windows 上 std::filesystem::path 由窄字符串构造时会按 UTF-8 转换，
//   而 MinGW 的 argv / 控制台路径是 ANSI（中文系统为 GBK），于是中文路径
//   会抛 "Illegal byte sequence" 直接崩溃。这里改用 CRT 的窄接口
//   （_access / _mkdir），与 std::ofstream 的编码行为保持一致。
#pragma once

#include <string>

namespace subconv::fs {

/// 路径是否存在（文件或目录）
[[nodiscard]] bool exists(const std::string& path);

/// 是否为目录
[[nodiscard]] bool is_directory(const std::string& path);

/// 递归创建目录；已存在视为成功
[[nodiscard]] bool make_directories(const std::string& path);

/// 拼接目录与文件名（统一用 '/'，Windows 同样接受）
[[nodiscard]] std::string join(const std::string& dir, const std::string& name);

/// 取父目录；无分隔符时返回空串
[[nodiscard]] std::string parent_directory(const std::string& path);

/// 系统临时目录（取自 TMPDIR / TEMP / TMP）
[[nodiscard]] std::string temp_directory();

}  // namespace subconv::fs
