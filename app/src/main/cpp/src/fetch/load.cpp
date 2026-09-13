// 订阅来源加载：URL / 本地文件 + 内容嗅探 + 磁盘缓存
#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>

#include "subconv/codec.hpp"
#include "subconv/console.hpp"
#include "subconv/fetch.hpp"
#include "subconv/fsutil.hpp"
#include "subconv/json.hpp"

namespace subconv::fetch {
namespace {

std::string strip_bom(std::string_view raw) {
  std::string s(raw);
  if (s.size() >= 3 && static_cast<unsigned char>(s[0]) == 0xEF &&
      static_cast<unsigned char>(s[1]) == 0xBB && static_cast<unsigned char>(s[2]) == 0xBF) {
    s.erase(0, 3);
  }
  return s;
}

std::string_view ltrim_view(std::string_view s) {
  std::size_t i = 0;
  while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) ++i;
  return s.substr(i);
}

long long now_seconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

/// FNV-1a 64 位：仅用于生成缓存文件名，不用于安全用途。
std::string fnv1a_hex(std::string_view data) {
  std::uint64_t hash = 1469598103934665603ULL;
  for (const char ch : data) {
    hash ^= static_cast<unsigned char>(ch);
    hash *= 1099511628211ULL;
  }
  // 16 + 16 个十六进制字符 + '\0' = 33，缓冲区必须比 32 大，否则最后一位会被截断
  // （GCC 的 -Wformat-truncation 也会直接报出来）
  char buffer[40];
  std::snprintf(buffer, sizeof(buffer), "%016llx%016zx",
                static_cast<unsigned long long>(hash), data.size());
  return buffer;
}

Result<std::string> read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return fail("无法打开文件: " + path);
  std::ostringstream buffer;
  buffer << in.rdbuf();
  if (in.bad()) return fail("读取文件失败: " + path);
  return buffer.str();
}

}  // namespace

// ---------------------------------------------------------------------------
// 嗅探
// ---------------------------------------------------------------------------
ContentKind sniff_content(std::string_view body, std::string_view content_type) {
  std::string_view s = ltrim_view(body);
  if (s.empty()) return ContentKind::Unknown;

  const char first = s.front();
  if (first == '<') return ContentKind::Html;

  // 判断窗口给到 256KB：JSON 版 Clash 配置的 proxies 段可能排在几千字节的前置配置之后
  // （BPB 面板 `?app=clash` 返回的就是这种，content-type 还是 application/json）。
  const std::string head = codec::to_lower(s.substr(0, std::min<std::size_t>(s.size(), 262144)));

  if (first == '{' || first == '[') {
    // JSON 是 YAML 的子集，mihomo 直接吃 JSON 版 Clash 配置。
    // 只见 Clash 专有键就交给 Clash 解析器；sing-box / Xray / v2ray 仍按 JSON 配置报错。
    if (head.find("\"proxies\"") != std::string::npos ||
        head.find("\"proxy-groups\"") != std::string::npos ||
        head.find("\"proxy-providers\"") != std::string::npos ||
        head.find("\"mixed-port\"") != std::string::npos) {
      return ContentKind::ClashYaml;
    }
    return ContentKind::JsonConfig;
  }

  if (head.find("<html") != std::string::npos || head.find("<!doctype") != std::string::npos) {
    return ContentKind::Html;
  }
  if (head.find("proxies:") != std::string::npos ||
      head.find("proxy-groups:") != std::string::npos ||
      head.find("proxy-providers:") != std::string::npos ||
      head.find("proxy_group") != std::string::npos) {
    return ContentKind::ClashYaml;
  }
  if (head.find("://") != std::string::npos) return ContentKind::ShareLinks;

  // 纯 Base64 列表（整体可能没有 scheme）
  if (codec::looks_like_base64(codec::trim(s))) return ContentKind::ShareLinks;

  // content-type 兜底
  const std::string ct = codec::to_lower(content_type);
  if (ct.find("yaml") != std::string::npos || ct.find("yml") != std::string::npos) {
    return ContentKind::ClashYaml;
  }
  if (ct.find("json") != std::string::npos) return ContentKind::JsonConfig;
  if (ct.find("html") != std::string::npos) return ContentKind::Html;
  return ContentKind::Unknown;
}

SubscriptionInfo parse_userinfo(std::string_view value) {
  SubscriptionInfo info;
  for (const auto& part : codec::split(value, ';')) {
    const auto eq = part.find('=');
    if (eq == std::string::npos) continue;
    const std::string key = codec::to_lower(codec::trim(std::string_view(part).substr(0, eq)));
    const std::string val = codec::trim(std::string_view(part).substr(eq + 1));
    int64_t number = 0;
    try {
      number = std::stoll(val);
    } catch (...) {
      continue;
    }
    if (key == "upload") info.upload = number;
    else if (key == "download") info.download = number;
    else if (key == "total") info.total = number;
    else if (key == "expire") info.expire = number;
  }
  return info;
}

bool is_url(std::string_view source) {
  return codec::starts_with_icase(source, "http://") ||
         codec::starts_with_icase(source, "https://");
}

// ---------------------------------------------------------------------------
// 来源加载
// ---------------------------------------------------------------------------
namespace {

struct CacheEntry {
  std::string body;
  std::string content_type;
  SubscriptionInfo info;
};

std::string cache_key(const std::string& url) { return fnv1a_hex(url); }

Result<CacheEntry> read_cache(const LoadOptions& opts, const std::string& url) {
  if (opts.cache_dir.empty() || opts.no_cache) return fail("未启用缓存");
  const std::string key = cache_key(url);
  const std::string meta_path = fs::join(opts.cache_dir, key + ".json");
  const std::string body_path = fs::join(opts.cache_dir, key + ".body");

  auto meta_text = read_file(meta_path);
  if (!meta_text) return fail("缓存未命中");
  const Json meta = Json::parse(*meta_text, nullptr, false);
  if (meta.is_discarded()) return fail("缓存元数据损坏");

  const long long fetched = meta.value("fetched", 0LL);
  const long long age = now_seconds() - fetched;
  if (opts.cache_ttl_seconds > 0 && age > opts.cache_ttl_seconds) {
    return fail("缓存已过期（" + std::to_string(age) + "s）");
  }

  auto body = read_file(body_path);
  if (!body) return fail("缓存正文缺失");

  CacheEntry entry;
  entry.body = std::move(*body);
  entry.content_type = meta.value("content_type", std::string());
  entry.info = parse_userinfo(meta.value("userinfo", std::string()));
  return entry;
}

/// 读取缓存，忽略 TTL（抓取失败时的降级路径）。
Result<CacheEntry> read_cache_any_age(const LoadOptions& opts, const std::string& url) {
  if (opts.cache_dir.empty()) return fail("未启用缓存");
  const std::string key = cache_key(url);
  auto meta_text = read_file(fs::join(opts.cache_dir, key + ".json"));
  if (!meta_text) return fail("缓存未命中");
  const Json meta = Json::parse(*meta_text, nullptr, false);
  if (meta.is_discarded()) return fail("缓存元数据损坏");
  auto body = read_file(fs::join(opts.cache_dir, key + ".body"));
  if (!body) return fail("缓存正文缺失");

  CacheEntry entry;
  entry.body = std::move(*body);
  entry.content_type = meta.value("content_type", std::string());
  entry.info = parse_userinfo(meta.value("userinfo", std::string()));
  return entry;
}

void write_cache(const LoadOptions& opts, const std::string& url, const std::string& body,
                 const std::string& content_type, const std::string& userinfo) {
  if (opts.cache_dir.empty() || opts.no_cache) return;
  if (!fs::make_directories(opts.cache_dir)) return;

  const std::string key = cache_key(url);
  {
    std::ofstream out(fs::join(opts.cache_dir, key + ".body"),
                      std::ios::binary | std::ios::trunc);
    if (!out) return;
    out.write(body.data(), static_cast<std::streamsize>(body.size()));
  }
  Json meta = Json::object();
  meta["url"] = url;
  meta["fetched"] = now_seconds();
  meta["content_type"] = content_type;
  meta["userinfo"] = userinfo;
  meta["size"] = body.size();
  std::ofstream out(fs::join(opts.cache_dir, key + ".json"),
                    std::ios::binary | std::ios::trunc);
  if (!out) return;
  const std::string text = meta.dump(2);
  out.write(text.data(), static_cast<std::streamsize>(text.size()));
}

}  // namespace

// ---------------------------------------------------------------------------
// 按嗅探结果分派解析
// ---------------------------------------------------------------------------
Result<Subscription> parse_content(std::string_view body, std::string source,
                                   std::string_view content_type) {
  switch (sniff_content(body, content_type)) {
    case ContentKind::Html:
      return fail("来源返回的是网页而不是订阅内容（" + source +
                  "）：可能是机场错误页、需要鉴权，或链接已失效。请检查订阅链接与 User-Agent。");
    case ContentKind::ClashYaml:
      return parse_clash_yaml(body, source);
    case ContentKind::JsonConfig:
      return fail("来源是 JSON 配置（sing-box / Xray / v2ray）而不是订阅（" + source +
                  "）：将 JSON 配置作为输入源计划在后续里程碑支持。");
    case ContentKind::ShareLinks:
    case ContentKind::Unknown:
      break;
  }
  return parse_subscription(body, source);
}

Result<Subscription> load_source(const std::string& source, const LoadOptions& opts) {
  std::string body;
  std::string content_type;
  SubscriptionInfo info;
  const bool remote = is_url(source);

  if (remote) {
    // 1) 命中未过期缓存 → 直接用
    if (auto cached = read_cache(opts, source)) {
      if (opts.verbose) {
        console::write_line(stderr, std::string("[cache] 命中 ") + source);
      }
      auto sub = parse_content(cached->body, source, cached->content_type);
      if (sub) {
        sub->info = cached->info;
        sub->source = source;
        return sub;
      }
      // 缓存内容解析失败：继续走网络
    }

    // 2) 抓取
    auto response = http_get_with_retry(source, opts.http);
    if (!response) {
      // 3) 抓取失败 → 降级到任意龄期的缓存
      if (auto stale = read_cache_any_age(opts, source)) {
        auto sub = parse_content(stale->body, source + "（离线缓存）", stale->content_type);
        if (sub) {
          sub->info = stale->info;
          sub->source = source;
          sub->warnings.push_back("抓取失败，已降级使用本地缓存：" + response.error().message);
          return sub;
        }
      }
      return fail(response.error());
    }

    body = std::move(response->body);
    content_type = response->content_type;
    if (const std::string* userinfo = response->header("subscription-userinfo");
        userinfo != nullptr) {
      info = parse_userinfo(*userinfo);
      write_cache(opts, source, body, content_type, *userinfo);
    } else {
      write_cache(opts, source, body, content_type, {});
    }
  } else {
    auto text = read_file(source);
    if (!text) return fail(text.error());
    body = strip_bom(*text);
  }

  auto sub = parse_content(body, source, content_type);
  if (!sub) return sub;
  sub->info = info;
  sub->source = source;
  return sub;
}

}  // namespace subconv::fetch
