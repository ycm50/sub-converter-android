// nlohmann/json 的取值辅助：分享链接里的 JSON 字段类型不规范
// （数字可能是字符串，字符串可能是数字），需要统一宽容处理。
#pragma once

#include <string>

#include "subconv/json.hpp"

namespace subconv::parse_detail {

inline std::string jstring(const Json& j, const char* key) {
  const auto it = j.find(key);
  if (it == j.end() || it->is_null()) return {};
  if (it->is_string()) return it->get<std::string>();
  if (it->is_boolean()) return it->get<bool>() ? "true" : "false";
  if (it->is_number_integer()) return std::to_string(it->get<long long>());
  if (it->is_number_unsigned()) return std::to_string(it->get<unsigned long long>());
  if (it->is_number_float()) return it->dump();
  return {};
}

inline long long jint(const Json& j, const char* key, long long fallback = 0) {
  const auto it = j.find(key);
  if (it == j.end() || it->is_null()) return fallback;
  if (it->is_number_integer()) return it->get<long long>();
  if (it->is_number_unsigned()) return static_cast<long long>(it->get<unsigned long long>());
  if (it->is_boolean()) return it->get<bool>() ? 1 : 0;
  if (it->is_string()) {
    try {
      return std::stoll(it->get<std::string>());
    } catch (...) {
      return fallback;
    }
  }
  return fallback;
}

inline bool jbool(const Json& j, const char* key, bool fallback = false) {
  const auto it = j.find(key);
  if (it == j.end() || it->is_null()) return fallback;
  if (it->is_boolean()) return it->get<bool>();
  if (it->is_number()) return it->get<double>() != 0.0;
  if (it->is_string()) {
    const std::string v = it->get<std::string>();
    return v == "1" || v == "true" || v == "yes" || v == "on";
  }
  return fallback;
}

}  // namespace subconv::parse_detail
