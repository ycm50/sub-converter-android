// WireGuard 公共逻辑的实现：见 wireguard_common.hpp。
#include "wireguard_common.hpp"

#include <algorithm>
#include <cstdlib>
#include <string_view>

#include "subconv/codec.hpp"

namespace subconv::wireguard_detail {
namespace {

bool is_hex(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return c - 'A' + 10;
}

bool is_base64_char(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' ||
         c == '/' || c == '-' || c == '_';
}

constexpr bool is_space(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

}  // namespace

std::string strip_key_padding(std::string_view key) {
  std::string out = codec::trim(key);
  while (!out.empty() && out.back() == '=') out.pop_back();
  return out;
}

std::string pad_key_base64(std::string_view key) {
  const std::string raw = strip_key_padding(key);
  if (raw.empty()) return {};
  // 64 位 hex 是 Xray 另一种合法写法，原样透传（补成 base64 反而需要先解码成字节）。
  if (raw.size() == 64 && std::all_of(raw.begin(), raw.end(), [](char c) { return is_hex(c); })) {
    return raw;
  }
  // base64 的长度模 4 只可能余 2 或 3（余 1 说明输入本身是坏的），据此补 '='。
  std::string out = raw;
  while (out.size() % 4 != 0) out.push_back('=');
  return out;
}

bool looks_like_key(std::string_view key) {
  const std::string s = strip_key_padding(key);
  if (s.size() == 64) {
    return std::all_of(s.begin(), s.end(), [](char c) { return is_hex(c); });
  }
  if (s.size() == 43) {
    return std::all_of(s.begin(), s.end(), [](char c) { return is_base64_char(c); });
  }
  return false;
}

void parse_reserved_scalar(const std::string& text, std::vector<int>& out) {
  out.clear();
  const std::string s = codec::trim(text);
  if (s.empty()) return;

  // 1) "209,98,59" / "209 98 59"
  {
    std::vector<int> parts;
    std::string current;
    bool ok = true;
    for (std::size_t i = 0; i <= s.size(); ++i) {
      const char c = i < s.size() ? s[i] : ',';
      if (c == ',' || is_space(c)) {
        if (current.empty()) continue;
        char* end = nullptr;
        const long v = std::strtol(current.c_str(), &end, 10);
        if (end == nullptr || *end != '\0' || v < 0 || v > 255) {
          ok = false;
          break;
        }
        parts.push_back(static_cast<int>(v));
        current.clear();
        continue;
      }
      current.push_back(c);
    }
    if (ok && parts.size() == 3) {
      out = std::move(parts);
      return;
    }
  }

  // 2) 6 位 hex（Xray 的 []byte 在 JSON 里常被写成 hex 字符串）
  if (s.size() == 6 && std::all_of(s.begin(), s.end(), [](char c) { return is_hex(c); })) {
    out = {hex_value(s[0]) * 16 + hex_value(s[1]), hex_value(s[2]) * 16 + hex_value(s[3]),
           hex_value(s[4]) * 16 + hex_value(s[5])};
    return;
  }

  // 3) 4 字符 base64 —— WARP 客户端配置导出的写法（"U4An"）
  if (s.size() <= 4 && std::all_of(s.begin(), s.end(), [](char c) { return is_base64_char(c); })) {
    if (auto decoded = codec::base64_decode(s); decoded && decoded->size() == 3) {
      out = {static_cast<unsigned char>((*decoded)[0]),
             static_cast<unsigned char>((*decoded)[1]),
             static_cast<unsigned char>((*decoded)[2])};
      return;
    }
  }
}

void parse_reserved_json(const Json& value, std::vector<int>& out) {
  out.clear();
  if (value.is_array()) {
    std::vector<int> parts;
    for (const auto& item : value) {
      if (item.is_number_integer()) {
        const long long v = item.get<long long>();
        if (v < 0 || v > 255) return;
        parts.push_back(static_cast<int>(v));
      } else if (item.is_number_unsigned()) {
        const unsigned long long v = item.get<unsigned long long>();
        if (v > 255) return;
        parts.push_back(static_cast<int>(v));
      } else if (item.is_string()) {
        const std::string piece = codec::trim(item.get<std::string>());
        char* end = nullptr;
        const long v = std::strtol(piece.c_str(), &end, 10);
        if (end == nullptr || *end != '\0' || v < 0 || v > 255) return;
        parts.push_back(static_cast<int>(v));
      } else {
        return;
      }
    }
    if (parts.size() == 3) out = std::move(parts);
    return;
  }
  if (value.is_string()) {
    parse_reserved_scalar(value.get<std::string>(), out);
    return;
  }
  if (value.is_number_integer()) {
    // 单个整数：一定是误填（reserved 是 3 个字节），忽略而不是猜。
    return;
  }
}

std::vector<std::string> split_allowed_ips(std::string_view text) {
  std::vector<std::string> out;
  for (const auto& piece : codec::split(text, ',')) {
    std::string v = codec::trim(piece);
    if (!v.empty()) out.push_back(std::move(v));
  }
  return out;
}

std::vector<std::string> allowed_ips_from_json(const Json& value) {
  std::vector<std::string> out;
  if (value.is_array()) {
    for (const auto& item : value) {
      if (item.is_string()) {
        std::string v = codec::trim(item.get<std::string>());
        if (!v.empty()) out.push_back(std::move(v));
      }
    }
    return out;
  }
  if (value.is_string()) return split_allowed_ips(value.get<std::string>());
  return out;
}

std::vector<std::string> split_list(std::string_view text) {
  std::vector<std::string> out;
  std::string current;
  for (std::size_t i = 0; i <= text.size(); ++i) {
    const char c = i < text.size() ? text[i] : ',';
    if (c == ',' || is_space(c)) {
      if (!current.empty()) {
        out.push_back(std::move(current));
        current.clear();
      }
      continue;
    }
    current.push_back(c);
  }
  return out;
}

bool address_is_ipv6(std::string_view address) {
  std::string s(address);
  if (const auto slash = s.find('/'); slash != std::string::npos) s.resize(slash);
  return codec::is_ipv6(s);
}

bool address_is_ipv4(std::string_view address) {
  std::string s(address);
  if (const auto slash = s.find('/'); slash != std::string::npos) s.resize(slash);
  return codec::is_ipv4(s);
}

bool split_kv(std::string_view line, std::string& key, std::string& value) {
  const auto eq = line.find('=');
  if (eq == std::string_view::npos) return false;
  key = codec::to_lower(codec::trim(line.substr(0, eq)));
  value = codec::trim(line.substr(eq + 1));
  return !key.empty();
}

}  // namespace subconv::wireguard_detail
