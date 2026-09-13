// 订阅抓取：HTTP 客户端、内容嗅探、来源加载
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "subconv/error.hpp"
#include "subconv/types.hpp"

namespace subconv::fetch {

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------
struct HttpOptions {
  std::string user_agent = "clash-verge/v2.0.0";
  long timeout_seconds = 20;
  long connect_timeout_seconds = 10;
  int retries = 2;
  bool follow_redirects = true;
  long max_redirects = 5;
  bool insecure = false;      ///< 跳过 TLS 证书校验（-k）
  bool verbose = false;
  /// 代理：http:// / https:// / socks5:// / socks4:// 均可
  std::string proxy;
  /// 额外请求头
  std::map<std::string, std::string> headers;
};

struct HttpResponse {
  long status = 0;
  std::string body;
  std::string effective_url;
  std::string content_type;
  std::map<std::string, std::string> headers;

  [[nodiscard]] const std::string* header(std::string_view name) const noexcept;
};

/// 单次 GET。网络错误或非 2xx 返回 Error。
Result<HttpResponse> http_get(const std::string& url, const HttpOptions& opts);

/// 带重试（指数退避）的 GET。
Result<HttpResponse> http_get_with_retry(const std::string& url, const HttpOptions& opts);

/// 是否已链接 libcurl（未启用时 URL 输入不可用）。
[[nodiscard]] bool http_available() noexcept;

/// 实际用于 TLS 校验的 CA bundle 路径；空串表示沿用 libcurl 内置默认。
/// 用于诊断 "error adding trust anchors" 这类只在运行时才暴露的证书问题。
[[nodiscard]] std::string resolved_ca_bundle();

// ---------------------------------------------------------------------------
// 内容嗅探
// ---------------------------------------------------------------------------
enum class ContentKind {
  ShareLinks,   ///< 分享链接列表（可能被 Base64 包裹）
  ClashYaml,    ///< Clash / mihomo 配置
  JsonConfig,   ///< sing-box / Xray / v2ray JSON 配置
  Html,         ///< 网页（通常是机场错误页）
  Unknown,
};

[[nodiscard]] ContentKind sniff_content(std::string_view body, std::string_view content_type = {});

/// 按嗅探结果分派解析：Clash YAML / 分享链接（含 Base64 包裹）；
/// HTML 与 JSON 配置给出针对性报错而不是一堆语法错。
[[nodiscard]] Result<Subscription> parse_content(std::string_view body, std::string source,
                                                 std::string_view content_type = {});

/// 解析 `subscription-userinfo: upload=1; download=2; total=3; expire=4`
[[nodiscard]] SubscriptionInfo parse_userinfo(std::string_view value);

// ---------------------------------------------------------------------------
// 来源加载
// ---------------------------------------------------------------------------
struct LoadOptions {
  HttpOptions http;
  /// 磁盘缓存目录；为空则不使用缓存
  std::string cache_dir;
  /// 缓存有效期（秒）
  long cache_ttl_seconds = 300;
  bool no_cache = false;
  bool verbose = false;
};

/// 从一个来源加载：本地文件路径或 http(s) URL。
/// 自动嗅探内容类型（分享链接 / Clash YAML / HTML 错误页）。
Result<Subscription> load_source(const std::string& source, const LoadOptions& opts);

/// 是否为 http(s) URL。
[[nodiscard]] bool is_url(std::string_view source);

// ---------------------------------------------------------------------------
// 证书指纹探测（--probe-cert）
// ---------------------------------------------------------------------------
/// 连接 host:port（SNI 用 sni，空则用 host）取对端叶子证书，返回 SHA256 指纹
/// （冒号分隔的大写十六进制，Xray `pinnedPeerCertSha256` / v2rayN `pcs` 的格式）。
/// 校验被有意跳过：探测的目的就是"证书不可信/名字不符"的节点也能拿到指纹。
[[nodiscard]] Result<std::string> probe_peer_cert_sha256(std::string_view host, uint16_t port,
                                                       std::string_view sni,
                                                       int timeout_seconds = 5);

/// 为「需要跳过证书校验」的节点补齐 `pinned_cert_sha256`（含 xhttp 下载侧），就地修改 nodes。
/// 返回实际探测成功的次数；warnings 非空时记录失败原因（不改变 nodes 的其余字段）。
std::size_t probe_node_certificates(NodeList& nodes, int timeout_seconds = 5,
                                    std::vector<std::string>* warnings = nullptr);

}  // namespace subconv::fetch

namespace subconv {

/// 从原始文本解析订阅（自动识别 Base64 包裹）—— 定义在 parse/parse.cpp
Result<Subscription> parse_subscription(std::string_view raw, std::string source);

/// 从 Clash YAML 解析节点 —— 定义在 parse/clash_yaml.cpp
Result<Subscription> parse_clash_yaml(std::string_view yaml, std::string source);

}  // namespace subconv
