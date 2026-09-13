// 错误与结果类型
#pragma once

#include <expected>
#include <string>
#include <string_view>
#include <utility>

namespace subconv {

/// 统一错误类型：只带一条人类可读消息。
struct Error {
  std::string message;

  Error() = default;
  Error(std::string msg) : message(std::move(msg)) {}
  Error(const char* msg) : message(msg) {}

  [[nodiscard]] std::string_view what() const noexcept { return message; }
};

/// 便携 Result<T>：成功持有 T，失败持有 Error。
template <class T>
using Result = std::expected<T, Error>;

inline std::unexpected<Error> fail(std::string msg) {
  return std::unexpected(Error(std::move(msg)));
}
inline std::unexpected<Error> fail(const char* msg) {
  return std::unexpected(Error(msg));
}
/// 把一个 Result 的错误原样转抛给另一个 Result。
inline std::unexpected<Error> fail(Error e) {
  return std::unexpected(std::move(e));
}

/// 便捷：把 Result 的错误消息拼上上下文前缀。
inline std::unexpected<Error> fail_with(std::string_view ctx, const Error& e) {
  return std::unexpected(Error(std::string(ctx) + ": " + e.message));
}

}  // namespace subconv
