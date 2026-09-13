#include "subconv/yaml.hpp"

#include <cstdio>
#include <cstring>

#include "subconv/codec.hpp"

namespace subconv {
namespace {

bool ieq_ascii(std::string_view a, const char* b) {
  const std::size_t n = std::strlen(b);
  if (a.size() != n) return false;
  for (std::size_t i = 0; i < n; ++i) {
    char x = a[i];
    if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
    if (x != b[i]) return false;
  }
  return true;
}

bool looks_like_bool_or_null(std::string_view s) {
  static const char* kWords[] = {"true", "false", "yes",  "no",  "on",
                                 "off",  "null",  "nan",  "inf", "~"};
  for (const char* w : kWords) {
    if (ieq_ascii(s, w)) return true;
  }
  return false;
}

bool looks_like_number(std::string_view s) {
  std::size_t i = 0;
  if (i < s.size() && (s[i] == '+' || s[i] == '-')) ++i;
  if (i >= s.size()) return false;

  // 0x / 0o / 0b
  if (s[i] == '0' && i + 1 < s.size()) {
    const char n = s[i + 1];
    if (n == 'x' || n == 'X' || n == 'o' || n == 'O' || n == 'b' || n == 'B') return true;
  }

  bool digits = false;
  bool dot = false;
  bool exp = false;
  for (; i < s.size(); ++i) {
    const char c = s[i];
    if (c >= '0' && c <= '9') {
      digits = true;
    } else if (c == '_') {
      continue;  // YAML 1.1 允许下划线分隔
    } else if (c == '.' && !dot && !exp) {
      dot = true;
    } else if ((c == 'e' || c == 'E') && digits && !exp) {
      exp = true;
      if (i + 1 < s.size() && (s[i + 1] == '+' || s[i + 1] == '-')) ++i;
    } else {
      return false;
    }
  }
  return digits;
}

bool looks_like_timestamp(std::string_view s) {
  // 形如 2024-01-02 会被 YAML 解析成时间戳
  if (s.size() < 8) return false;
  if (!(s[0] >= '0' && s[0] <= '9' && s[1] >= '0' && s[1] <= '9' && s[2] >= '0' &&
        s[2] <= '9' && s[3] >= '0' && s[3] <= '9'))
    return false;
  return s[4] == '-' && (s[5] >= '0' && s[5] <= '9') && (s[6] >= '0' && s[6] <= '9');
}

constexpr std::string_view kFirstCharIndicators = "-?:,[]{}#&*!|>'\"%@`";

}  // namespace

// ---------------------------------------------------------------------------
// 构造
// ---------------------------------------------------------------------------
Yaml Yaml::scalar(std::string v) {
  Yaml y;
  y.kind_ = Kind::Scalar;
  y.scalar_ = std::move(v);
  return y;
}

Yaml Yaml::raw(std::string v) {
  Yaml y;
  y.kind_ = Kind::Scalar;
  y.plain_ = true;
  y.scalar_ = std::move(v);
  return y;
}

Yaml Yaml::integer(long long v) { return raw(std::to_string(v)); }

Yaml Yaml::sequence() {
  Yaml y;
  y.kind_ = Kind::Sequence;
  return y;
}

Yaml Yaml::mapping() {
  Yaml y;
  y.kind_ = Kind::Mapping;
  return y;
}

// ---------------------------------------------------------------------------
// 查询 / 构建
// ---------------------------------------------------------------------------
bool Yaml::empty() const noexcept {
  switch (kind_) {
    case Kind::Null: return true;
    case Kind::Scalar: return scalar_.empty();
    case Kind::Sequence: return seq_.empty();
    case Kind::Mapping: return map_.empty();
  }
  return true;
}

Yaml& Yaml::push(Yaml v) {
  if (kind_ != Kind::Sequence) {
    kind_ = Kind::Sequence;
    seq_.clear();
  }
  seq_.push_back(std::move(v));
  return *this;
}

Yaml& Yaml::set(std::string key, Yaml v) {
  if (kind_ != Kind::Mapping) {
    kind_ = Kind::Mapping;
    map_.clear();
  }
  for (auto& [k, existing] : map_) {
    if (k == key) {
      existing = std::move(v);
      return *this;
    }
  }
  map_.emplace_back(std::move(key), std::move(v));
  return *this;
}

bool Yaml::has(std::string_view key) const noexcept { return get(key) != nullptr; }

const Yaml* Yaml::get(std::string_view key) const noexcept {
  if (kind_ != Kind::Mapping) return nullptr;
  for (const auto& [k, v] : map_) {
    if (k == key) return &v;
  }
  return nullptr;
}

// ---------------------------------------------------------------------------
// 引号策略
// ---------------------------------------------------------------------------
bool Yaml::needs_quoting(std::string_view s) {
  if (s.empty()) return true;
  if (s.front() == ' ' || s.back() == ' ' || s.front() == '\t' || s.back() == '\t') {
    return true;
  }
  for (const char ch : s) {
    const auto c = static_cast<unsigned char>(ch);
    if (c < 0x20 || c == 0x7F) return true;
  }
  if (kFirstCharIndicators.find(s.front()) != std::string_view::npos) return true;
  if (s.find(": ") != std::string_view::npos) return true;
  if (s.find(" #") != std::string_view::npos) return true;
  if (s.back() == ':') return true;
  if (looks_like_bool_or_null(s)) return true;
  if (looks_like_number(s)) return true;
  if (looks_like_timestamp(s)) return true;
  return false;
}

std::string Yaml::quote(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 2);
  out.push_back('"');
  for (const char ch : s) {
    const auto c = static_cast<unsigned char>(ch);
    switch (ch) {
      case '"': out.append("\\\""); break;
      case '\\': out.append("\\\\"); break;
      case '\n': out.append("\\n"); break;
      case '\r': out.append("\\r"); break;
      case '\t': out.append("\\t"); break;
      default:
        if (c < 0x20 || c == 0x7F) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\x%02X", c);
          out.append(buf);
        } else {
          out.push_back(ch);
        }
    }
  }
  out.push_back('"');
  return out;
}

std::string Yaml::render() const {
  switch (kind_) {
    case Kind::Null: return "null";
    case Kind::Sequence: return "[]";
    case Kind::Mapping: return "{}";
    case Kind::Scalar:
      if (plain_ || !needs_quoting(scalar_)) return scalar_;
      return quote(scalar_);
  }
  return "null";
}

// ---------------------------------------------------------------------------
// 序列化
// ---------------------------------------------------------------------------
void Yaml::write_block(std::string& out, int indent) const {
  if (kind_ == Kind::Mapping) {
    write_mapping(out, indent, /*inline_first=*/false);
  } else {
    write_sequence(out, indent);
  }
}

void Yaml::write_mapping(std::string& out, int indent, bool inline_first) const {
  bool first = true;
  for (const auto& [key, value] : map_) {
    if (!(inline_first && first)) out.append(static_cast<std::size_t>(indent), ' ');
    first = false;
    out.append(key);
    out.push_back(':');
    if (value.is_block()) {
      out.push_back('\n');
      value.write_block(out, indent + 2);
    } else {
      out.push_back(' ');
      out.append(value.render());
      out.push_back('\n');
    }
  }
}

void Yaml::write_sequence(std::string& out, int indent) const {
  for (const auto& item : seq_) {
    out.append(static_cast<std::size_t>(indent), ' ');
    out.append("- ");
    if (item.is_mapping() && !item.empty()) {
      item.write_mapping(out, indent + 2, /*inline_first=*/true);
    } else if (item.is_sequence() && !item.empty()) {
      out.push_back('\n');
      item.write_sequence(out, indent + 2);
    } else {
      out.append(item.render());
      out.push_back('\n');
    }
  }
}

std::string Yaml::dump() const {
  std::string out;
  switch (kind_) {
    case Kind::Mapping:
      if (map_.empty()) {
        out = "{}\n";
      } else {
        write_mapping(out, 0, /*inline_first=*/false);
      }
      break;
    case Kind::Sequence:
      if (seq_.empty()) {
        out = "[]\n";
      } else {
        write_sequence(out, 0);
      }
      break;
    default:
      out = render();
      out.push_back('\n');
  }
  return out;
}

}  // namespace subconv
