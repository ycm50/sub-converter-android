// 请求映射：`/sub` 查询串 与 `POST /api/convert` JSON → ConvertRequest
//
// 全部是纯函数，不涉及 socket，因此可以直接单测 URL 解码、多 url 合并、布尔参数等。
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "subconv/codec.hpp"
#include "subconv/json.hpp"
#include "subconv/server.hpp"

namespace subconv::server {
namespace {

bool parse_bool(std::string_view value, bool fallback) {
  const std::string text = codec::to_lower(codec::trim(value));
  if (text.empty()) return fallback;
  if (text == "1" || text == "true" || text == "yes" || text == "on") return true;
  if (text == "0" || text == "false" || text == "no" || text == "off") return false;
  return fallback;
}

long parse_long(std::string_view value, long fallback) {
  try {
    return std::stol(codec::trim(value));
  } catch (...) {
    return fallback;
  }
}

void append_sources(std::vector<std::string>& out, std::string_view value) {
  for (const auto& piece : codec::split(value, '|')) {
    const std::string item = codec::trim(piece);
    if (!item.empty()) out.push_back(item);
  }
}

/// 收集所有 `url` / `urls` / `s` 参数：允许重复出现，也允许用 `|` 分隔多个链接。
std::vector<std::string> collect_sources(std::string_view query) {
  std::vector<std::string> out;
  for (const auto& raw : codec::split(query, '&')) {
    if (raw.empty()) continue;
    const auto eq = raw.find('=');
    const std::string_view key_view =
        eq == std::string::npos ? std::string_view(raw) : std::string_view(raw).substr(0, eq);
    const std::string key = codec::to_lower(codec::percent_decode(key_view));
    if (key != "url" && key != "urls" && key != "s") continue;
    if (eq == std::string::npos) continue;
    append_sources(out, codec::percent_decode(std::string_view(raw).substr(eq + 1)));
  }
  return out;
}

/// 键存在即覆盖默认值（`emoji=false` 这种写法）。
bool flag(const std::map<std::string, std::string>& params, const char* key, bool fallback) {
  const auto it = params.find(key);
  return it == params.end() ? fallback : parse_bool(it->second, fallback);
}

std::string text_param(const std::map<std::string, std::string>& params, const char* key,
                       const std::string& fallback) {
  const auto it = params.find(key);
  if (it == params.end()) return fallback;
  const std::string value = codec::trim(it->second);
  return value.empty() ? fallback : value;
}

long long_param(const std::map<std::string, std::string>& params, const char* key, long fallback) {
  const auto it = params.find(key);
  return it == params.end() ? fallback : parse_long(it->second, fallback);
}

/// 逗号分隔的列表参数：键不存在返回 nullopt（保留默认值）；
/// 键存在但为空（`?rulesets=`）返回**空列表**，表示「一个规则集都不要」。
std::optional<std::vector<std::string>> list_param(const std::map<std::string, std::string>& params,
                                                   const char* key) {
  const auto it = params.find(key);
  if (it == params.end()) return std::nullopt;
  std::vector<std::string> out;
  for (const auto& piece : codec::split(it->second, ',')) {
    const std::string item = codec::trim(piece);
    if (!item.empty()) out.push_back(item);
  }
  return out;
}

}  // namespace

std::string target_from_path(std::string_view path) {
  std::string name(path);
  if (!name.empty() && name.front() == '/') name.erase(0, 1);
  while (!name.empty() && name.back() == '/') name.pop_back();
  if (name.empty() || name == "sub" || name == "api" || name == "index.html") return {};
  return normalize_target(name);
}

Result<ConvertRequest> request_from_query(std::string_view query, const ServerOptions& defaults) {
  const std::map<std::string, std::string> params = codec::parse_query(query);

  ConvertRequest req;
  req.load = defaults.load;
  req.emit.target = text_param(params, "target", defaults.default_target);
  req.sources = collect_sources(query);
  req.content = text_param(params, "content", std::string());
  req.filename = text_param(params, "filename", std::string());

  req.emit.emoji = flag(params, "emoji", req.emit.emoji);
  req.emit.udp = flag(params, "udp", req.emit.udp);
  req.emit.tfo = flag(params, "tfo", req.emit.tfo);
  req.emit.sort = flag(params, "sort", req.emit.sort);
  req.emit.dedup = flag(params, "dedup", req.emit.dedup);
  req.emit.include_rules = flag(params, "rules", req.emit.include_rules);
  req.emit.clash_legacy = flag(params, "clash_legacy", flag(params, "legacy", req.emit.clash_legacy));
  if (auto sets = list_param(params, "rulesets"); sets.has_value()) {
    req.emit.rule_sets = std::move(*sets);
  }
  if (auto dns = list_param(params, "dns"); dns.has_value()) {
    req.emit.dns = std::move(*dns);
  }
  req.emit.ipv6 = flag(params, "ipv6", req.emit.ipv6);
  req.emit.probe_cert = flag(params, "probe_cert", req.emit.probe_cert);
  req.emit.probe_cert_timeout_seconds = static_cast<int>(
      long_param(params, "probe_cert_timeout", req.emit.probe_cert_timeout_seconds));

  req.load.http.proxy = text_param(params, "proxy", req.load.http.proxy);
  req.load.http.user_agent = text_param(params, "ua", req.load.http.user_agent);
  req.load.http.timeout_seconds = long_param(params, "timeout", req.load.http.timeout_seconds);
  req.load.http.retries = static_cast<int>(long_param(params, "retries", req.load.http.retries));
  req.load.http.insecure = flag(params, "insecure", req.load.http.insecure);
  req.load.cache_dir = text_param(params, "cache_dir", req.load.cache_dir);
  req.load.cache_ttl_seconds = long_param(params, "cache_ttl", req.load.cache_ttl_seconds);
  req.load.no_cache = flag(params, "no_cache", req.load.no_cache);

  if (defaults.verbose) {
    req.load.verbose = true;
    req.load.http.verbose = true;
  }
  return req;
}

Result<ConvertRequest> request_from_json(std::string_view body, const ServerOptions& defaults) {
  const Json root = Json::parse(body, nullptr, false);
  if (root.is_discarded()) return fail("请求体不是合法 JSON");
  if (!root.is_object()) return fail("请求体必须是 JSON 对象");

  auto get_string = [](const Json& object, const char* key, const std::string& fallback) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_string()) return fallback;
    const std::string value = codec::trim(it->get<std::string>());
    return value.empty() ? fallback : value;
  };
  auto get_bool = [](const Json& object, const char* key, bool fallback) {
    const auto it = object.find(key);
    if (it == object.end()) return fallback;
    if (it->is_boolean()) return it->get<bool>();
    if (it->is_string()) return parse_bool(it->get<std::string>(), fallback);
    if (it->is_number_integer()) return it->get<long long>() != 0;
    return fallback;
  };
  auto get_long = [](const Json& object, const char* key, long fallback) {
    const auto it = object.find(key);
    if (it == object.end()) return fallback;
    if (it->is_number_integer()) return static_cast<long>(it->get<long long>());
    if (it->is_string()) return parse_long(it->get<std::string>(), fallback);
    return fallback;
  };
  // 规则集：数组或逗号分隔字符串；显式给空数组 => 空列表（只留 MATCH 兜底）
  auto get_string_list = [](const Json& object, const char* key,
                            std::vector<std::string> fallback) {
    const auto it = object.find(key);
    if (it == object.end()) return fallback;
    std::vector<std::string> out;
    if (it->is_array()) {
      for (const auto& item : *it) {
        if (!item.is_string()) continue;
        const std::string id = codec::trim(item.get<std::string>());
        if (!id.empty()) out.push_back(id);
      }
    } else if (it->is_string()) {
      for (const auto& piece : codec::split(it->get<std::string>(), ',')) {
        const std::string id = codec::trim(piece);
        if (!id.empty()) out.push_back(id);
      }
    }
    return out;
  };

  ConvertRequest req;
  req.load = defaults.load;
  req.emit.target = get_string(root, "target", defaults.default_target);
  req.filename = get_string(root, "filename", std::string());
  req.content = get_string(root, "content", std::string());

  if (const auto it = root.find("sources"); it != root.end()) {
    if (it->is_array()) {
      for (const auto& item : *it) {
        if (item.is_string()) append_sources(req.sources, item.get<std::string>());
      }
    } else if (it->is_string()) {
      append_sources(req.sources, it->get<std::string>());
    }
  }
  if (req.sources.empty()) {
    if (const auto it = root.find("url"); it != root.end() && it->is_string()) {
      append_sources(req.sources, it->get<std::string>());
    }
  }

  if (const auto it = root.find("options"); it != root.end() && it->is_object()) {
    const Json& options = *it;
    req.emit.emoji = get_bool(options, "emoji", req.emit.emoji);
    req.emit.udp = get_bool(options, "udp", req.emit.udp);
    req.emit.tfo = get_bool(options, "tfo", req.emit.tfo);
    req.emit.sort = get_bool(options, "sort", req.emit.sort);
    req.emit.dedup = get_bool(options, "dedup", req.emit.dedup);
    req.emit.include_rules = get_bool(options, "rules", req.emit.include_rules);
    req.emit.clash_legacy = get_bool(options, "clash_legacy", req.emit.clash_legacy);
    req.emit.rule_sets = get_string_list(options, "rulesets", req.emit.rule_sets);
    req.emit.dns = get_string_list(options, "dns", req.emit.dns);
    req.emit.ipv6 = get_bool(options, "ipv6", req.emit.ipv6);
    req.emit.probe_cert = get_bool(options, "probe_cert", req.emit.probe_cert);
    req.emit.probe_cert_timeout_seconds = static_cast<int>(
        get_long(options, "probe_cert_timeout", req.emit.probe_cert_timeout_seconds));
  }

  if (const auto it = root.find("fetch"); it != root.end() && it->is_object()) {
    const Json& fetch = *it;
    req.load.http.proxy = get_string(fetch, "proxy", req.load.http.proxy);
    req.load.http.user_agent = get_string(fetch, "ua", req.load.http.user_agent);
    req.load.http.timeout_seconds = get_long(fetch, "timeout", req.load.http.timeout_seconds);
    req.load.http.retries = static_cast<int>(get_long(fetch, "retries", req.load.http.retries));
    req.load.http.insecure = get_bool(fetch, "insecure", req.load.http.insecure);
    req.load.http.verbose = get_bool(fetch, "verbose", req.load.http.verbose);
    req.load.cache_dir = get_string(fetch, "cache_dir", req.load.cache_dir);
    req.load.cache_ttl_seconds = get_long(fetch, "cache_ttl", req.load.cache_ttl_seconds);
    req.load.no_cache = get_bool(fetch, "no_cache", req.load.no_cache);
    if (const auto headers = fetch.find("headers"); headers != fetch.end() && headers->is_object()) {
      for (const auto& item : headers->items()) {
        if (item.value().is_string()) {
          req.load.http.headers[item.key()] = item.value().get<std::string>();
        }
      }
    }
  }

  if (defaults.verbose) {
    req.load.verbose = true;
    req.load.http.verbose = true;
  }
  return req;
}

}  // namespace subconv::server
