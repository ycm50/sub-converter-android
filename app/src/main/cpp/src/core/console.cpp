#include "subconv/console.hpp"

#include <cstdlib>

#include "subconv/codec.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#ifdef __ANDROID__
// Android 上的 App 进程没有控制台：stdout/stderr 会掉进 /dev/null，
// 于是「服务起在哪个端口」「抓取为什么失败」这类提示全看不见。
// logcat 是 Android 的「控制台」，所以这里把它们同时写进 logcat（tag: subconv）。
// 只影响面向人的提示 —— 配置载荷从来不走 console（见 console.hpp 的约定）。
#include <android/log.h>
#endif

namespace subconv::console {

unsigned output_code_page() noexcept {
#ifdef _WIN32
  return static_cast<unsigned>(::GetConsoleOutputCP());
#else
  return 0;
#endif
}

std::string_view environment_override() {
  const char* value = std::getenv("SUBCONV_CONSOLE_ENCODING");
  return value == nullptr ? std::string_view() : std::string_view(value);
}

unsigned effective_code_page(unsigned console_code_page, std::string_view override_spec) {
  const std::string spec = codec::to_lower(codec::trim(override_spec));
  if (spec.empty() || spec == "auto") return console_code_page;

  if (spec == "utf-8" || spec == "utf8" || spec == "65001" || spec == "utf_8") return 65001;
  if (spec == "gbk" || spec == "cp936" || spec == "ansi") return 936;

  try {
    const long value = std::stol(spec);
    if (value > 0 && value <= 65535) return static_cast<unsigned>(value);
  } catch (...) {
    // 认不出来就退回默认行为，不能因为写错环境变量反而让输出变乱码
  }
  return console_code_page;
}

std::string to_code_page(std::string_view utf8, unsigned code_page) {
#ifdef _WIN32
  if (utf8.empty() || code_page == 0 || code_page == CP_UTF8) return std::string(utf8);

  const int bytes = static_cast<int>(utf8.size());
  const int wide_length =
      ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), bytes, nullptr, 0);
  if (wide_length <= 0) return std::string(utf8);

  std::wstring wide(static_cast<std::size_t>(wide_length), L'\0');
  if (::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), bytes, wide.data(), wide_length) <= 0) {
    return std::string(utf8);
  }

  const int narrow_length = ::WideCharToMultiByte(code_page, 0, wide.data(), wide_length, nullptr, 0,
                                                  nullptr, nullptr);
  if (narrow_length <= 0) return std::string(utf8);

  std::string out(static_cast<std::size_t>(narrow_length), '\0');
  if (::WideCharToMultiByte(code_page, 0, wide.data(), wide_length, out.data(), narrow_length,
                            nullptr, nullptr) <= 0) {
    return std::string(utf8);
  }
  return out;
#else
  (void)code_page;
  return std::string(utf8);
#endif
}

std::string ansi_to_utf8(std::string_view ansi) {
#ifdef _WIN32
  if (ansi.empty()) return std::string(ansi);
  // CP_ACP 已经是 UTF-8（Windows「使用 Unicode UTF-8 提供全球语言支持」）时无需转换，
  // 否则会二次解码把中文弄坏。
  if (::GetACP() == CP_UTF8) return std::string(ansi);

  const int bytes = static_cast<int>(ansi.size());
  const int wide_length = ::MultiByteToWideChar(CP_ACP, 0, ansi.data(), bytes, nullptr, 0);
  if (wide_length <= 0) return std::string(ansi);

  std::wstring wide(static_cast<std::size_t>(wide_length), L'\0');
  if (::MultiByteToWideChar(CP_ACP, 0, ansi.data(), bytes, wide.data(), wide_length) <= 0) {
    return std::string(ansi);
  }

  const int utf8_length = ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), wide_length, nullptr, 0,
                                                nullptr, nullptr);
  if (utf8_length <= 0) return std::string(ansi);

  std::string out(static_cast<std::size_t>(utf8_length), '\0');
  if (::WideCharToMultiByte(CP_UTF8, 0, wide.data(), wide_length, out.data(), utf8_length, nullptr,
                            nullptr) <= 0) {
    return std::string(ansi);
  }
  return out;
#else
  return std::string(ansi);
#endif
}

void write(std::FILE* stream, std::string_view utf8) {
  const std::string text =
      to_code_page(utf8, effective_code_page(output_code_page(), environment_override()));
  if (text.empty()) return;

#ifdef __ANDROID__
  // logcat 要 NUL 结尾的 C 字符串，而 string_view 不保证有；面向人的提示都很短，直接拷一份。
  const std::string line(utf8);
  __android_log_write(stream == stderr ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, "subconv",
                      line.c_str());
#endif

  std::fwrite(text.data(), 1, text.size(), stream);
}

void write_line(std::FILE* stream, std::string_view utf8) {
  write(stream, utf8);
  std::fputc('\n', stream);
}

}  // namespace subconv::console
