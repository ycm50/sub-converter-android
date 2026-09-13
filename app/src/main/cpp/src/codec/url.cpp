#include <algorithm>
#include <charconv>
#include <cstdio>

#include "subconv/codec.hpp"

namespace subconv::codec {
namespace {

bool is_hex(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return c - 'A' + 10;
}

bool is_unreserved(unsigned char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
         c == '-' || c == '_' || c == '.' || c == '~';
}

bool is_trim_char(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

}  // namespace

std::string percent_decode(std::string_view in, bool plus_as_space) {
  std::string out;
  out.reserve(in.size());
  for (std::size_t i = 0; i < in.size(); ++i) {
    const char c = in[i];
    if (c == '%' && i + 2 < in.size() && is_hex(in[i + 1]) && is_hex(in[i + 2])) {
      out.push_back(static_cast<char>((hex_value(in[i + 1]) << 4) | hex_value(in[i + 2])));
      i += 2;
    } else if (c == '+' && plus_as_space) {
      out.push_back(' ');
    } else {
      out.push_back(c);
    }
  }
  return out;
}

std::string percent_encode(std::string_view in) {
  static const char* kHex = "0123456789ABCDEF";
  std::string out;
  out.reserve(in.size());
  for (const char ch : in) {
    const auto c = static_cast<unsigned char>(ch);
    if (is_unreserved(c)) {
      out.push_back(ch);
    } else {
      out.push_back('%');
      out.push_back(kHex[c >> 4]);
      out.push_back(kHex[c & 0x0F]);
    }
  }
  return out;
}

std::string trim(std::string_view s) {
  std::size_t b = 0;
  std::size_t e = s.size();
  while (b < e && is_trim_char(s[b])) ++b;
  while (e > b && is_trim_char(s[e - 1])) --e;
  return std::string(s.substr(b, e - b));
}

std::string to_lower(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (const char c : s) {
    out.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c);
  }
  return out;
}

bool iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    char x = a[i];
    char y = b[i];
    if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
    if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
    if (x != y) return false;
  }
  return true;
}

bool starts_with_icase(std::string_view s, std::string_view prefix) {
  if (s.size() < prefix.size()) return false;
  return iequals(s.substr(0, prefix.size()), prefix);
}

std::vector<std::string> split(std::string_view s, char delim) {
  std::vector<std::string> out;
  std::size_t start = 0;
  while (true) {
    const std::size_t pos = s.find(delim, start);
    if (pos == std::string_view::npos) {
      out.emplace_back(s.substr(start));
      break;
    }
    out.emplace_back(s.substr(start, pos - start));
    start = pos + 1;
  }
  return out;
}

std::string join(const std::vector<std::string>& parts, std::string_view sep) {
  std::string out;
  for (std::size_t i = 0; i < parts.size(); ++i) {
    if (i != 0) out.append(sep);
    out.append(parts[i]);
  }
  return out;
}

Result<uint16_t> parse_port(std::string_view s) {
  const std::string t = trim(s);
  if (t.empty()) return fail("端口为空");
  unsigned value = 0;
  const auto* begin = t.data();
  const auto* end = t.data() + t.size();
  const auto [ptr, ec] = std::from_chars(begin, end, value);
  if (ec != std::errc{} || ptr != end) return fail("端口不是合法数字: " + t);
  if (value == 0 || value > 65535) return fail("端口超出范围: " + t);
  return static_cast<uint16_t>(value);
}

Result<std::pair<std::string, std::string>> split_host_port(std::string_view s) {
  std::string_view v = s;
  if (v.empty()) return fail("host:port 为空");
  if (v.front() == '[') {
    const auto close = v.find(']');
    if (close == std::string_view::npos) return fail("IPv6 地址缺少 ']'");
    std::string host(v.substr(1, close - 1));
    std::string_view rest = v.substr(close + 1);
    if (rest.empty() || rest.front() != ':') return fail("IPv6 地址缺少端口");
    return std::pair{std::move(host), std::string(rest.substr(1))};
  }
  const auto pos = v.rfind(':');
  if (pos == std::string_view::npos) return fail("缺少端口（期望 host:port）");
  return std::pair{std::string(v.substr(0, pos)), std::string(v.substr(pos + 1))};
}

Result<Uri> parse_uri(std::string_view s) {
  Uri u;
  const auto scheme_end = s.find("://");
  if (scheme_end == std::string_view::npos || scheme_end == 0) {
    return fail("缺少 scheme://");
  }
  u.scheme = to_lower(s.substr(0, scheme_end));

  std::string_view rest = s.substr(scheme_end + 3);
  if (const auto p = rest.find('#'); p != std::string_view::npos) {
    u.fragment = std::string(rest.substr(p + 1));
    rest = rest.substr(0, p);
  }
  if (const auto p = rest.find('?'); p != std::string_view::npos) {
    u.query = std::string(rest.substr(p + 1));
    rest = rest.substr(0, p);
  }

  std::string_view authority = rest;
  if (const auto p = rest.find('/'); p != std::string_view::npos) {
    authority = rest.substr(0, p);
    u.path = std::string(rest.substr(p));
  }

  if (const auto p = authority.rfind('@'); p != std::string_view::npos) {
    u.userinfo = percent_decode(authority.substr(0, p));
    authority = authority.substr(p + 1);
  }
  if (authority.empty()) return fail("URI 缺少主机名");

  if (authority.front() == '[') {
    const auto close = authority.find(']');
    if (close == std::string_view::npos) return fail("IPv6 地址缺少 ']'");
    u.host = std::string(authority.substr(1, close - 1));
    const std::string_view tail = authority.substr(close + 1);
    if (!tail.empty()) {
      if (tail.front() != ':') return fail("IPv6 地址后存在非法字符");
      const auto port = parse_port(tail.substr(1));
      if (!port) return fail(port.error());
      u.port = *port;
      u.has_port = true;
    }
  } else if (const auto colon = authority.rfind(':'); colon != std::string_view::npos) {
    u.host = std::string(authority.substr(0, colon));
    const auto port = parse_port(authority.substr(colon + 1));
    if (!port) return fail(port.error());
    u.port = *port;
    u.has_port = true;
  } else {
    u.host = std::string(authority);
  }

  if (u.host.empty()) return fail("URI 主机名为空");
  return u;
}

std::map<std::string, std::string> parse_query(std::string_view q) {
  std::map<std::string, std::string> out;
  for (const auto& part : split(q, '&')) {
    if (part.empty()) continue;
    const auto eq = part.find('=');
    if (eq == std::string::npos) {
      out[percent_decode(part)] = std::string();
    } else {
      out[percent_decode(std::string_view(part).substr(0, eq))] =
          percent_decode(std::string_view(part).substr(eq + 1));
    }
  }
  return out;
}

bool is_ipv4(std::string_view s) {
  int parts = 0;
  std::size_t i = 0;
  while (i <= s.size()) {
    const auto dot = s.find('.', i);
    const auto end = (dot == std::string_view::npos) ? s.size() : dot;
    const auto seg = s.substr(i, end - i);
    if (seg.empty() || seg.size() > 3) return false;
    for (const char c : seg) {
      if (c < '0' || c > '9') return false;
    }
    unsigned value = 0;
    for (const char c : seg) value = value * 10 + static_cast<unsigned>(c - '0');
    if (value > 255) return false;
    ++parts;
    if (dot == std::string_view::npos) break;
    i = dot + 1;
  }
  return parts == 4;
}

bool is_ipv6(std::string_view s) {
  if (s.find(':') == std::string_view::npos) return false;
  for (const char c : s) {
    const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F') || c == ':';
    if (!ok) return false;
  }
  return true;
}

}  // namespace subconv::codec
