// 控制台输出编码适配
//
// 为什么需要这一层：Windows 控制台（conhost / Windows Terminal）默认代码页是 936(GBK)，
// 而程序内部字符串一律是 UTF-8。若直接把 UTF-8 字节写到控制台，中文会显示成
// 「璁㈤槀閾炬帴」这类乱码 —— PowerShell 与 cmd 读取子进程输出时用的正是控制台代码页，
// 所以「让调用方改用 UTF-8」并不能解决问题，必须由程序按控制台代码页编码输出
// （.NET 的 Console.Out 就是这么做的）。
//
// 约定：
//   * 面向人的提示（用法、进度、告警）走 console::write / write_line —— 自动适配代码页；
//   * 面向机器的载荷（生成的 Clash YAML / Xray JSON）永远写原始 UTF-8 字节，
//     因为它要落盘或交给内核，文件必须是 UTF-8。
#pragma once

#include <cstdio>
#include <string>
#include <string_view>

namespace subconv::console {

/// 当前控制台输出代码页；未附着控制台时返回 0。
[[nodiscard]] unsigned output_code_page() noexcept;

/// UTF-8 文本 → 指定代码页的字节。纯函数，便于单测。
/// code_page 为 0、CP_UTF8 或非 Windows 平台时原样返回；转换失败也原样返回，绝不丢内容。
[[nodiscard]] std::string to_code_page(std::string_view utf8, unsigned code_page);

/// 决定这次输出该按哪个代码页编码。返回 0/65001 表示"不转换，直接写 UTF-8"。
///
/// 终端编码组合比想象中多：cmd / PowerShell 5.1 用控制台代码页解码子进程输出，
/// 而 PowerShell 7 固定按 UTF-8 解码、mintty 这类没有 Windows 控制台。默认按控制台
/// 代码页走，遇到对不上的终端可以用环境变量显式指定：
///   SUBCONV_CONSOLE_ENCODING = auto（默认）| utf-8 | 936（或 gbk 等数字/别名）
[[nodiscard]] unsigned effective_code_page(unsigned console_code_page,
                                           std::string_view override_spec);

/// 读取 SUBCONV_CONSOLE_ENCODING（仅供内部与测试使用）。
[[nodiscard]] std::string_view environment_override();

/// Windows 的 ANSI(ACP) 字节串 → UTF-8。非 Windows、已是 UTF-8 代码页或转换失败时原样返回。
///
/// 为什么需要：`char** argv` 在 Windows 上是 **ACP**（简中即 GBK）编码，而程序内部一律 UTF-8。
/// 只有要写进**配置载荷 / 界面**的文本才转换；文件路径必须保持 ACP 原样，否则
/// `fopen` 打不开带中文的路径 —— 这也是为什么这里不做全局 argv 转换。
[[nodiscard]] std::string ansi_to_utf8(std::string_view ansi);

/// 把 UTF-8 文本按当前控制台代码页写出（无控制台时保持 UTF-8）。
void write(std::FILE* stream, std::string_view utf8);

/// 同上，末尾补一个换行。
void write_line(std::FILE* stream, std::string_view utf8);

}  // namespace subconv::console
