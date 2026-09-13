// 编解码与字符串/URI 工具
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "subconv/error.hpp"

namespace subconv::codec {

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------
[[nodiscard]] std::string base64_encode(std::string_view in);
[[nodiscard]] std::string base64_encode_url(std::string_view in);
/// 容错解码：忽略空白、允许 URL-safe 字母表、允许缺失 padding。
/// 遇到非法字符或孤立半字节时报错。
[[nodiscard]] Result<std::string> base64_decode(std::string_view in);
/// 启发式判断（仅用于嗅探订阅内容，不作为正确性保证）。
[[nodiscard]] bool looks_like_base64(std::string_view in);

// ---------------------------------------------------------------------------
// 百分号编码
// ---------------------------------------------------------------------------
[[nodiscard]] std::string percent_decode(std::string_view in, bool plus_as_space = false);
[[nodiscard]] std::string percent_encode(std::string_view in);

// ---------------------------------------------------------------------------
// URI
// ---------------------------------------------------------------------------
struct Uri {
  std::string scheme;
  std::string userinfo;   ///< 已 percent-decode
  std::string host;       ///< IPv6 已去掉方括号
  uint16_t port = 0;
  bool has_port = false;
  std::string path;
  std::string query;      ///< 原始（未解码）
  std::string fragment;   ///< 原始（未解码）
};

[[nodiscard]] Result<Uri> parse_uri(std::string_view s);

/// 拆分 `host:port` / `[v6]:port` / `host`。
[[nodiscard]] Result<std::pair<std::string, std::string>> split_host_port(std::string_view s);
[[nodiscard]] Result<uint16_t> parse_port(std::string_view s);

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------
[[nodiscard]] std::map<std::string, std::string> parse_query(std::string_view q);

// ---------------------------------------------------------------------------
// 字符串
// ---------------------------------------------------------------------------
[[nodiscard]] std::vector<std::string> split(std::string_view s, char delim);
[[nodiscard]] std::string trim(std::string_view s);
[[nodiscard]] std::string to_lower(std::string_view s);
[[nodiscard]] bool iequals(std::string_view a, std::string_view b);
[[nodiscard]] bool starts_with_icase(std::string_view s, std::string_view prefix);
[[nodiscard]] bool is_ipv4(std::string_view s);
[[nodiscard]] bool is_ipv6(std::string_view s);
[[nodiscard]] std::string join(const std::vector<std::string>& parts, std::string_view sep);

}  // namespace subconv::codec
