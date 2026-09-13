#include <array>

#include "subconv/codec.hpp"

namespace subconv::codec {
namespace {

constexpr char kStdAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr char kUrlAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string encode_with(std::string_view in, const char* alphabet, bool pad) {
  std::string out;
  out.reserve(((in.size() + 2) / 3) * 4);
  const auto* bytes = reinterpret_cast<const unsigned char*>(in.data());
  std::size_t i = 0;
  while (i + 3 <= in.size()) {
    const unsigned v = (static_cast<unsigned>(bytes[i]) << 16) |
                       (static_cast<unsigned>(bytes[i + 1]) << 8) |
                       static_cast<unsigned>(bytes[i + 2]);
    out.push_back(alphabet[(v >> 18) & 0x3F]);
    out.push_back(alphabet[(v >> 12) & 0x3F]);
    out.push_back(alphabet[(v >> 6) & 0x3F]);
    out.push_back(alphabet[v & 0x3F]);
    i += 3;
  }
  const std::size_t rest = in.size() - i;
  if (rest == 1) {
    const unsigned v = static_cast<unsigned>(bytes[i]) << 16;
    out.push_back(alphabet[(v >> 18) & 0x3F]);
    out.push_back(alphabet[(v >> 12) & 0x3F]);
    if (pad) out.append("==");
  } else if (rest == 2) {
    const unsigned v = (static_cast<unsigned>(bytes[i]) << 16) |
                       (static_cast<unsigned>(bytes[i + 1]) << 8);
    out.push_back(alphabet[(v >> 18) & 0x3F]);
    out.push_back(alphabet[(v >> 12) & 0x3F]);
    out.push_back(alphabet[(v >> 6) & 0x3F]);
    if (pad) out.push_back('=');
  }
  return out;
}

const std::array<std::int8_t, 256>& decode_table() {
  static const std::array<std::int8_t, 256> table = [] {
    std::array<std::int8_t, 256> t{};
    t.fill(-1);
    for (std::int8_t i = 0; i < 64; ++i) {
      t[static_cast<unsigned char>(kStdAlphabet[i])] = i;
    }
    // 兼容 URL-safe 字母表
    t[static_cast<unsigned char>('-')] = 62;
    t[static_cast<unsigned char>('_')] = 63;
    return t;
  }();
  return table;
}

bool is_space(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

}  // namespace

std::string base64_encode(std::string_view in) {
  return encode_with(in, kStdAlphabet, /*pad=*/true);
}

std::string base64_encode_url(std::string_view in) {
  return encode_with(in, kUrlAlphabet, /*pad=*/false);
}

Result<std::string> base64_decode(std::string_view in) {
  const auto& table = decode_table();
  std::string out;
  out.reserve(in.size() / 4 * 3 + 3);
  std::uint32_t buffer = 0;
  int bits = 0;
  for (const char ch : in) {
    if (is_space(ch) || ch == '=') continue;
    const auto v = table[static_cast<unsigned char>(ch)];
    if (v < 0) {
      return fail(std::string("base64 含非法字符 '") + ch + "'");
    }
    buffer = (buffer << 6) | static_cast<std::uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((buffer >> bits) & 0xFF));
    }
  }
  // 合法残留位数为 0/2/4；6 表示末尾有一个无效的孤立字符。
  if (bits == 6) return fail("base64 长度非法（末尾存在孤立字符）");
  return out;
}

bool looks_like_base64(std::string_view in) {
  if (in.size() < 8) return false;
  if (in.find("://") != std::string_view::npos) return false;
  std::size_t real = 0;
  for (const char ch : in) {
    if (is_space(ch)) continue;
    const auto c = static_cast<unsigned char>(ch);
    const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || ch == '+' || ch == '/' || ch == '=' ||
                    ch == '-' || ch == '_';
    if (!ok) return false;
    ++real;
  }
  if (real < 8 || real % 4 == 1) return false;
  return true;
}

}  // namespace subconv::codec
