#include "uri_common.hpp"

#include "subconv/codec.hpp"
#include "subconv/json.hpp"

namespace subconv::parse_detail {
namespace {

/// 分享链接里的 `extra=` 是 XHTTP 的高级参数（JSON）。这里只拆出跨内核都成立的
/// download-settings，其余原样留在 node.extra 里透传给能表达它的目标（Xray / 分享链接）。
/// 依据：Xray SplitHTTPConfig.Build()（extra 覆盖整份 xhttp 配置，host/path/mode 除外）
/// 与 v2rayN BaseFmt / V2rayOutboundService 的 extra -> xhttpSettings.extra 直传。
void apply_xhttp_extra(ProxyNode& node, const std::string& text) {
  node.extra["xhttpExtra"] = text;

  const Json j = Json::parse(text, nullptr, false);
  if (j.is_discarded() || !j.is_object()) return;

  const auto ds = j.find("downloadSettings");
  if (ds == j.end() || !ds->is_object()) return;

  XhttpDownloadOptions& d = node.xhttp.download;
  d.present = true;
  d.server = ds->value("address", std::string());
  if (const auto port = ds->find("port"); port != ds->end() && port->is_number_integer()) {
    const int64_t value = port->get<int64_t>();
    if (value > 0 && value <= 65535) d.port = static_cast<uint16_t>(value);
  }
  if (const auto inner = ds->find("xhttpSettings"); inner != ds->end() && inner->is_object()) {
    d.host = inner->value("host", std::string());
    d.path = inner->value("path", std::string());
  }
  if (const auto security = ds->find("security");
      security != ds->end() && security->is_string()) {
    d.tls = codec::iequals(security->get<std::string>(), "tls");
  }
  if (const auto tls = ds->find("tlsSettings"); tls != ds->end() && tls->is_object()) {
    d.sni = tls->value("serverName", std::string());
    if (tls->contains("allowInsecure") || tls->contains("verifyPeerCertByName") ||
        tls->contains("pinnedPeerCertSha256")) {
      d.insecure = true;
    }
    if (const auto pinned = tls->find("pinnedPeerCertSha256");
        pinned != tls->end() && pinned->is_string()) {
      d.pinned_cert_sha256 = pinned->get<std::string>();
    }
  }
}

}  // namespace

const std::string* pick(const std::map<std::string, std::string>& q,
                        std::initializer_list<const char*> keys) {
  for (const char* key : keys) {
    for (const auto& [k, v] : q) {
      if (codec::iequals(k, key)) return &v;
    }
  }
  return nullptr;
}

bool truthy(const std::string* v) {
  if (v == nullptr) return false;
  return *v == "1" || codec::iequals(*v, "true") || codec::iequals(*v, "yes") ||
         codec::iequals(*v, "on");
}

std::vector<std::string> split_alpn(const std::string& s) {
  std::vector<std::string> out;
  for (auto& part : codec::split(s, ',')) {
    const std::string t = codec::trim(part);
    if (!t.empty()) out.push_back(t);
  }
  if (out.empty() && !s.empty()) out.push_back(codec::trim(s));
  return out;
}

std::string name_from_fragment(const std::string& fragment, const std::string& fallback) {
  const std::string name = codec::trim(codec::percent_decode(fragment));
  return name.empty() ? fallback : name;
}

void apply_common_params(ProxyNode& node, const std::map<std::string, std::string>& q) {
  // ---- 传输层（network）----
  std::string header_type;
  if (const auto* v = pick(q, {"headerType", "header-type"})) header_type = *v;

  if (const auto* v = pick(q, {"type", "net", "network"})) {
    if (auto n = network_from_string(*v)) node.network = *n;
  }
  // v2ray 的 tcp + headerType=http 等价于 HTTP 传输层
  if (node.network == Network::Tcp && codec::iequals(header_type, "http")) {
    node.network = Network::Http;
  }
  if (!header_type.empty()) node.extra["headerType"] = header_type;

  // ---- TLS ----
  const std::string* security = pick(q, {"security"});
  if (security != nullptr) {
    if (codec::iequals(*security, "tls") || codec::iequals(*security, "xtls")) {
      node.tls.enabled = true;
    } else if (codec::iequals(*security, "reality")) {
      node.tls.enabled = true;
      node.tls.reality = true;
    } else if (codec::iequals(*security, "none") || codec::iequals(*security, "")) {
      node.tls.enabled = false;
    }
  }
  if (truthy(pick(q, {"tls"}))) node.tls.enabled = true;

  if (const auto* v = pick(q, {"sni", "peer", "serverName", "servername"})) {
    node.tls.sni = *v;
  }
  if (const auto* v = pick(q, {"alpn"})) node.tls.alpn = split_alpn(*v);
  if (const auto* v = pick(q, {"fp", "fingerprint"})) node.tls.client_fingerprint = *v;
  // 证书指纹：v2rayN / v2rayNG 的 `pcs`（ProfileItem.CertSha -> Xray pinnedPeerCertSha256），
  // hysteria2 惯用的 `pinSHA256` 是同一个东西。Xray 25+ 移除 allowInsecure 之后，
  // 这就是「证书与 SNI 对不上」的节点唯一能被放行的参数。
  if (const auto* v = pick(q, {"pcs", "certSha", "pinSHA256"})) {
    node.tls.pinned_cert_sha256 = *v;
  }
  if (const auto* v = pick(q, {"pbk", "publicKey", "public-key"})) {
    node.tls.enabled = true;
    node.tls.reality = true;
    node.tls.reality_public_key = *v;
  }
  if (const auto* v = pick(q, {"sid", "shortId", "short-id"})) {
    node.tls.reality_short_id = *v;
  }
  if (const auto* v = pick(q, {"spx", "spiderX", "spider-x"})) node.extra["spiderX"] = *v;

  if (truthy(pick(q, {"allowInsecure", "insecure", "allow_insecure", "skip-cert-verify",
                      "skipCertVerify"}))) {
    node.tls.insecure = true;
  }
  if (const auto* v = pick(q, {"disableSni", "disable_sni"}); truthy(v)) {
    node.tls.disable_sni = true;
  }

  if (const auto* v = pick(q, {"flow"})) node.flow = *v;
  if (const auto* v = pick(q, {"packetEncoding", "packet-encoding"})) node.packet_encoding = *v;

  // ---- 传输层细节 ----
  const std::string* path = pick(q, {"path"});
  const std::string* host = pick(q, {"host"});
  const std::string* service = pick(q, {"serviceName", "service-name", "servicename"});
  const std::string* mode = pick(q, {"mode"});

  switch (node.network) {
    case Network::Ws: {
      if (path != nullptr) node.ws.path = *path;
      if (host != nullptr) node.ws.host = *host;
      if (const auto* v = pick(q, {"ed", "maxEarlyData"})) {
        try {
          node.ws.max_early_data = std::stoi(*v);
        } catch (...) {
          node.ws.max_early_data = std::nullopt;
        }
      }
      if (const auto* v = pick(q, {"eh", "earlyDataHeaderName"})) {
        node.ws.early_data_header = *v;
      }
      break;
    }
    case Network::Grpc: {
      if (service != nullptr) node.grpc.service_name = *service;
      else if (path != nullptr) node.grpc.service_name = *path;  // 常见误用：grpc 用 path 传 serviceName
      if (mode != nullptr && codec::iequals(*mode, "multi")) node.grpc.multi_mode = true;
      break;
    }
    case Network::H2:
    case Network::Http: {
      if (path != nullptr) node.h2.path = *path;
      if (host != nullptr) node.h2.host = codec::split(*host, ',');
      break;
    }
    case Network::Xhttp: {
      if (path != nullptr) node.xhttp.path = *path;
      if (host != nullptr) node.xhttp.host = *host;
      if (mode != nullptr) node.xhttp.mode = *mode;
      if (const auto* extra = pick(q, {"extra"}); extra != nullptr && !extra->empty()) {
        apply_xhttp_extra(node, *extra);
      }
      break;
    }
    default:
      break;
  }
}

}  // namespace subconv::parse_detail
