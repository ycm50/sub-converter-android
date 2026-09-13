// XHTTP（Xray 的 splithttp / mihomo 的 xhttp）输出细节
//
// 三个内核对这个传输的建模方式不一致，这里集中处理，避免各输出器各写一套：
//   * mihomo：`xhttp-opts` 是**扁平**的 YAML 映射，没有 `extra`；下载侧是
//     `download-settings`（代理字段与 xhttp 字段混在同一层）。
//   * Xray  ：`xhttpSettings` 里 `host/path/mode` 是普通字段，其余高级参数既可以
//     写成独立字段，也可以塞进 `extra`（JSON 字符串）；**一旦给了 extra，
//     Xray 的 SplitHTTPConfig.Build() 会用它整体替换掉离散字段**
//     （只保留 host/path/mode），所以两者不能同时写。
//   * sing-box：没有 xhttp 传输（官方 V2Ray 传输只有 http/ws/quic/grpc/httpupgrade），
//     只能在 singbox 目标里跳过这些节点 —— 见 src/emit/singbox.cpp。
#include <string>

#include "emit_internal.hpp"
#include "subconv/codec.hpp"
#include "subconv/json.hpp"

namespace subconv {
namespace {

/// 上游分享链接原样带来的 extra（未建模的 XHTTP 高级参数）。
std::string raw_extra(const ProxyNode& node) {
  const auto it = node.extra.find("xhttpExtra");
  return it == node.extra.end() ? std::string() : it->second;
}

/// 下载侧 SNI：显式给了就用它，否则沿用主节点（mihomo 的 `lo.FromPtrOr(ds.ServerName,
/// v.option.ServerName)` 就是这个语义），再退到下载地址本身。
std::string download_server_name(const ProxyNode& node) {
  const XhttpDownloadOptions& d = node.xhttp.download;
  if (!d.sni.empty()) return d.sni;
  if (!node.tls.sni.empty()) return node.tls.sni;
  return d.server.empty() ? node.server : d.server;
}

}  // namespace

bool xhttp_mode_supported(const std::string& mode) {
  // Xray 遇到别的值直接报 "unsupported mode"；mihomo 的 NormalizedMode 会原样透传。
  // 两边统一按 Xray 的白名单裁剪，写进配置的 mode 一定是内核认的值。
  return mode.empty() || codec::iequals(mode, "auto") || codec::iequals(mode, "packet-up") ||
         codec::iequals(mode, "stream-up") || codec::iequals(mode, "stream-one");
}

std::string xhttp_raw_extra(const ProxyNode& node) { return raw_extra(node); }

Json xhttp_download_settings_json(const ProxyNode& node) {
  const XhttpDownloadOptions& d = node.xhttp.download;

  Json ds = Json::object();
  if (!d.server.empty()) ds["address"] = d.server;
  if (d.port.has_value()) ds["port"] = *d.port;
  ds["network"] = "xhttp";

  Json inner = Json::object();
  if (!d.path.empty()) inner["path"] = d.path;
  if (!d.host.empty()) inner["host"] = d.host;
  ds["xhttpSettings"] = std::move(inner);

  const bool tls_on = d.tls.value_or(node.tls.enabled);
  ds["security"] = tls_on ? "tls" : "none";
  if (tls_on) {
    Json tls = Json::object();
    const std::string sni = download_server_name(node);
    // 下载侧没写 skip-cert-verify 时沿用主节点：mihomo 是
    // lo.FromPtrOr(ds.SkipCertVerify, v.option.SkipCertVerify)，而 Xray 的
    // downloadSettings 是"另起一份 StreamConfig"、不会自动继承，必须显式补上。
    const bool insecure = d.insecure.value_or(node.tls.insecure || node.scv);
    if (!sni.empty()) {
      tls["serverName"] = sni;
      if (insecure) {
        // 与主 TLS 同一套取舍：有指纹就钉指纹（Xray 命中叶子即放行），否则退回按名校验
        if (!d.pinned_cert_sha256.empty()) {
          tls["pinnedPeerCertSha256"] = d.pinned_cert_sha256;
        } else if (!node.tls.pinned_cert_sha256.empty()) {
          tls["pinnedPeerCertSha256"] = node.tls.pinned_cert_sha256;
        } else {
          tls["verifyPeerCertByName"] = sni;
        }
      }
    }
    if (!node.tls.alpn.empty()) tls["alpn"] = node.tls.alpn;
    if (!node.tls.client_fingerprint.empty()) {
      tls["fingerprint"] = node.tls.client_fingerprint;
    }
    ds["tlsSettings"] = std::move(tls);
  }
  return ds;
}

Json xhttp_settings_json(const ProxyNode& node) {
  Json x = Json::object();
  if (!node.xhttp.host.empty()) x["host"] = node.xhttp.host;
  if (!node.xhttp.path.empty()) x["path"] = node.xhttp.path;
  if (!node.xhttp.mode.empty() && xhttp_mode_supported(node.xhttp.mode)) {
    x["mode"] = node.xhttp.mode;
  }
  if (!node.xhttp.headers.empty()) x["headers"] = node.xhttp.headers;

  const std::string raw = raw_extra(node);
  bool wrote = false;
  if (!raw.empty()) {
    const Json extra = Json::parse(raw, nullptr, false);
    if (!extra.is_discarded()) {
      x["extra"] = extra;  // 原样透传：Xray 侧 extra 优先，离散字段会被忽略
      wrote = true;
    }
  }
  if (!wrote && node.xhttp.download.present) {
    x["downloadSettings"] = xhttp_download_settings_json(node);
  }
  return x;
}

Json xhttp_extra_json(const ProxyNode& node) {
  const std::string raw = raw_extra(node);
  if (!raw.empty()) {
    const Json extra = Json::parse(raw, nullptr, false);
    if (!extra.is_discarded() && extra.is_object() && !extra.empty()) return extra;
  }
  if (node.xhttp.download.present) {
    Json root = Json::object();
    root["downloadSettings"] = xhttp_download_settings_json(node);
    return root;
  }
  return Json();
}

bool xhttp_extra_has_untranslatable(const ProxyNode& node) {
  const std::string raw = raw_extra(node);
  if (raw.empty()) return false;
  const Json extra = Json::parse(raw, nullptr, false);
  if (extra.is_discarded() || !extra.is_object()) return false;
  for (const auto& item : extra.items()) {
    if (item.key() != "downloadSettings") return true;
  }
  return false;
}

}  // namespace subconv
