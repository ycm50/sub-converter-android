// Xray / V2Ray JSON 配置作为输入源 → ProxyNode
//
// 为什么需要：面板的 `?app=xray` 端点直接下发**完整的 Xray 客户端配置**，不是订阅链接。
// 已见到两种形态（BPB-Worker-Panel 的 `/sub/normal?app=xray` 是后者）：
//   * 单个配置：{ "outbounds": [ { "protocol": "vless", "streamSettings": {…} } ] }
//   * 配置数组：[ { "remarks": "💦 1. VLESS - Domain : 443", "outbounds": [...] }, … ]
//     数组里每份配置只装一个节点，节点名放在根级的 `remarks`（Xray 自己不认识这个键）。
// 这两种以前都会被当成「不支持的 JSON 配置」拒掉，于是面板给的 Xray 链接在 Clash / sing-box
// 侧完全用不了。这里把出站还原成 ProxyNode，好让其它目标也能消费。
//
// 只读**出站**里能当代理用的协议（vless / vmess / trojan / shadowsocks / socks / http），
// freedom / blackhole / dns / loopback 这些内置出站是客户端自己用的，直接忽略；
// inbounds / routing / dns / policy / observatory / stats 与节点无关，同样忽略。
//
// 有意丢弃的东西（都不影响能否连通）：
//   * `mux`：客户端侧的多路复用优化，各目标会按自己的默认值重写；
//   * `streamSettings.fragment`：客户端侧的 TLS 分片（防 DPI），本工具的模型里没有它；
//   * `sockopt.domainStrategy` / `happyEyeballs`：交给目标内核自己决定。
// 会被**告警**而不是静默丢弃的：未知传输层、`dialerProxy`（链式代理）、kcp 的 header/seed。
#include <string>
#include <utility>
#include <vector>

#include "json_util.hpp"
#include "parsers.hpp"
#include "subconv/codec.hpp"
#include "subconv/convert.hpp"
#include "subconv/json.hpp"
#include "subconv/vless_encryption.hpp"

namespace subconv {
namespace {

using parse_detail::jbool;
using parse_detail::jint;
using parse_detail::jstring;

/// 取子节点；不存在 / 是 null / 类型不对都返回 nullptr。
const Json* member(const Json& object, const char* key) {
  if (!object.is_object()) return nullptr;
  const auto it = object.find(key);
  if (it == object.end() || it->is_null()) return nullptr;
  return &(*it);
}

/// 端口：越界（0 / >65535 / 非数字）一律返回 0，由调用方判非法。
uint16_t jport(const Json& object, const char* key) {
  const long long value = jint(object, key, 0);
  if (value <= 0 || value > 65535) return 0;
  return static_cast<uint16_t>(value);
}

/// 字符串数组（也接受单个字符串）—— alpn / host / serverNames / path 都可能是两种形态。
std::vector<std::string> jstrings(const Json& object, const char* key) {
  std::vector<std::string> out;
  const Json* value = member(object, key);
  if (value == nullptr) return out;
  if (value->is_string()) {
    const std::string text = value->get<std::string>();
    if (!text.empty()) out.push_back(text);
    return out;
  }
  if (value->is_array()) {
    for (const auto& item : *value) {
      if (item.is_string()) out.push_back(item.get<std::string>());
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// XHTTP
// ---------------------------------------------------------------------------

/// `xhttpSettings.downloadSettings` —— 上传走主节点、下载走另一台机器的覆盖项。
/// 字段名与分享链接的 `extra=` 解析（src/parse/uri_common.cpp）保持一致：
/// Xray 的 downloadSettings 是一份独立的 StreamConfig，地址键叫 `address`（不是 server），
/// TLS 参数在它自己的 tlsSettings 里、**不会**从主节点继承。
void apply_xhttp_download(ProxyNode& node, const Json& ds) {
  XhttpDownloadOptions& d = node.xhttp.download;
  d.present = true;
  d.server = jstring(ds, "address");
  if (const uint16_t port = jport(ds, "port"); port != 0) d.port = port;
  if (const Json* inner = member(ds, "xhttpSettings")) {
    d.host = jstring(*inner, "host");
    d.path = jstring(*inner, "path");
  }
  if (const std::string security = codec::to_lower(jstring(ds, "security"));
      !security.empty()) {
    d.tls = security == "tls" || security == "xtls";
  }
  if (const Json* tls = member(ds, "tlsSettings")) {
    d.sni = jstring(*tls, "serverName");
    // 钉指纹也是「不校链」，与主节点同一套判断（对照 src/parse/uri_common.cpp）
    d.insecure = jbool(*tls, "allowInsecure") ||
                 member(*tls, "verifyPeerCertByName") != nullptr ||
                 member(*tls, "pinnedPeerCertSha256") != nullptr;
    d.pinned_cert_sha256 = jstring(*tls, "pinnedPeerCertSha256");
  }
}

/// Xray 25 起 splithttp 改名 xhttp，两个键名都要收。
void apply_xhttp(ProxyNode& node, const Json& settings) {
  node.xhttp.path = jstring(settings, "path");
  node.xhttp.host = jstring(settings, "host");
  node.xhttp.mode = jstring(settings, "mode");
  if (const Json* headers = member(settings, "headers")) {
    for (const auto& item : headers->items()) {
      if (item.value().is_string()) {
        node.xhttp.headers[item.key()] = item.value().get<std::string>();
      }
    }
  }

  // `extra` 是 Xray 的高级参数包，语义是「整体替换离散字段」（host/path/mode 除外），
  // 所以原样留在 extra 里透传；同时把它里面的 downloadSettings 拆出来，
  // 好让 mihomo / sing-box 这些没有 extra 概念的目标也能表达下载侧。
  if (const Json* extra = member(settings, "extra"); extra != nullptr && extra->is_object()) {
    node.extra["xhttpExtra"] = extra->dump();
    if (const Json* ds = member(*extra, "downloadSettings")) {
      apply_xhttp_download(node, *ds);
    }
  }
  if (const Json* ds = member(settings, "downloadSettings");
      ds != nullptr && !node.xhttp.download.present) {
    apply_xhttp_download(node, *ds);
  }
}

// ---------------------------------------------------------------------------
// TLS / REALITY
// ---------------------------------------------------------------------------
void apply_tls(ProxyNode& node, const Json& stream) {
  const std::string security = codec::to_lower(codec::trim(jstring(stream, "security")));
  const Json* tls = member(stream, "tlsSettings");
  const Json* reality = member(stream, "realitySettings");

  if (security == "reality" || (reality != nullptr && security.empty())) {
    node.tls.enabled = true;
    node.tls.reality = true;
    if (reality != nullptr) {
      node.tls.sni = jstring(*reality, "serverName");
      if (node.tls.sni.empty()) {
        // 少数面板（含服务端那种写法）用数组
        const auto names = jstrings(*reality, "serverNames");
        if (!names.empty()) node.tls.sni = names.front();
      }
      node.tls.client_fingerprint = jstring(*reality, "fingerprint");
      node.tls.reality_public_key = jstring(*reality, "publicKey");
      node.tls.reality_short_id = jstring(*reality, "shortId");
      if (const std::string spider = jstring(*reality, "spiderX"); !spider.empty()) {
        node.extra["spiderX"] = spider;
      }
      // 服务端形态把公钥/指纹塞在 settings 里，客户端形态不会；都读一下没坏处
      if (const Json* inner = member(*reality, "settings")) {
        if (node.tls.reality_public_key.empty()) {
          node.tls.reality_public_key = jstring(*inner, "publicKey");
        }
        if (node.tls.client_fingerprint.empty()) {
          node.tls.client_fingerprint = jstring(*inner, "fingerprint");
        }
      }
    }
    return;
  }

  if (security == "tls" || security == "xtls" || (tls != nullptr && security.empty())) {
    node.tls.enabled = true;
  }

  if (tls == nullptr) return;
  if (const std::string sni = jstring(*tls, "serverName"); !sni.empty()) node.tls.sni = sni;
  if (const auto alpn = jstrings(*tls, "alpn"); !alpn.empty()) node.tls.alpn = alpn;
  // fingerprint 是 uTLS 的 ClientHello 指纹（chrome / firefox / …），不是证书指纹
  if (const std::string fp = jstring(*tls, "fingerprint"); !fp.empty()) {
    node.tls.client_fingerprint = fp;
  }
  if (jbool(*tls, "allowInsecure")) node.tls.insecure = true;
  // verifyPeerCertByName 是 Xray 25+ 给 allowInsecure 的替代品之一，语义仍是「放行」；
  // pinnedPeerCertSha256 则是证书指纹（逗号分隔的 SHA256），对应模型里的 tls.fingerprint。
  if (const std::string vcn = jstring(*tls, "verifyPeerCertByName"); !vcn.empty()) {
    node.tls.insecure = true;
    if (node.tls.sni.empty()) node.tls.sni = vcn;
  }
  if (const std::string pin = jstring(*tls, "pinnedPeerCertSha256"); !pin.empty()) {
    node.tls.fingerprint = pin;
  }
}

// ---------------------------------------------------------------------------
// 传输层
// ---------------------------------------------------------------------------

/// 返回 false = 这个传输本工具的模型表达不了，调用方应跳过该节点（原因已写进 warnings）。
bool apply_transport(ProxyNode& node, const Json& stream, const std::string& label,
                     std::vector<std::string>& warnings) {
  const std::string network = codec::to_lower(codec::trim(jstring(stream, "network")));
  if (!network.empty()) {
    if (auto mapped = network_from_string(network)) {
      node.network = *mapped;
    } else {
      warnings.push_back("跳过节点 " + label + "：传输层 " + network + " 暂不支持");
      return false;
    }
  }

  // v2ray 的 tcp + headerType=http 在 Xray 里写成 tcpSettings.header.type=http，
  // 模型里对应 Network::Http（clash 的 http-opts / Xray 的 tcp+tcpSettings），不是 h2。
  if (node.network == Network::Tcp) {
    const Json* tcp = member(stream, "tcpSettings");
    const Json* header = tcp != nullptr ? member(*tcp, "header") : nullptr;
    if (header != nullptr && codec::iequals(jstring(*header, "type"), "http")) {
      node.network = Network::Http;
      if (const Json* request = member(*header, "request")) {
        const auto paths = jstrings(*request, "path");
        if (!paths.empty()) node.h2.path = paths.front();
        if (const Json* headers = member(*request, "headers")) {
          node.h2.host = jstrings(*headers, "Host");
        }
      }
    }
  }

  switch (node.network) {
    case Network::Ws: {
      const Json* ws = member(stream, "wsSettings");
      if (ws == nullptr) break;
      node.ws.path = jstring(*ws, "path");
      node.ws.host = jstring(*ws, "host");
      if (const Json* headers = member(*ws, "headers")) {
        for (const auto& item : headers->items()) {
          if (!item.value().is_string()) continue;
          const std::string key = item.key();
          const std::string value = item.value().get<std::string>();
          if (codec::iequals(key, "Host")) {
            node.ws.host = value;  // Xray 侧 Host 头写在这里，wss 的 SNI 也靠它
          } else {
            node.ws.headers[key] = value;
          }
        }
      }
      node.ws.early_data_header = jstring(*ws, "earlyDataHeaderName");
      if (const Json* early = member(*ws, "maxEarlyData"); early != nullptr) {
        const long long value = jint(*ws, "maxEarlyData", 0);
        if (value > 0 && value <= 2147483647LL) node.ws.max_early_data = static_cast<int>(value);
      }
      break;
    }
    case Network::Grpc: {
      const Json* grpc = member(stream, "grpcSettings");
      if (grpc == nullptr) break;
      node.grpc.service_name = jstring(*grpc, "serviceName");
      if (jbool(*grpc, "multiMode")) node.grpc.multi_mode = true;
      break;
    }
    case Network::H2: {
      const Json* http = member(stream, "httpSettings");
      if (http == nullptr) break;
      node.h2.host = jstrings(*http, "host");
      node.h2.path = jstring(*http, "path");
      break;
    }
    case Network::Xhttp: {
      const Json* xhttp = member(stream, "xhttpSettings");
      if (xhttp == nullptr) xhttp = member(stream, "splithttpSettings");
      if (xhttp != nullptr) apply_xhttp(node, *xhttp);
      break;
    }
    case Network::Kcp: {
      // kcp 的 header/seed 没建模：服务端改了默认值时这条线会连不上，明确告警而不是静默丢参
      const Json* kcp = member(stream, "kcpSettings");
      if (kcp != nullptr &&
          (member(*kcp, "header") != nullptr || member(*kcp, "seed") != nullptr)) {
        warnings.push_back("节点 " + label +
                           "：kcp 的 header/seed 参数未建模，服务端非默认配置时可能连不上");
      }
      break;
    }
    default:
      break;
  }
  return true;
}

void apply_sockopt(ProxyNode& node, const Json& stream, const std::string& label,
                   std::vector<std::string>& warnings) {
  const Json* sockopt = member(stream, "sockopt");
  if (sockopt == nullptr) return;
  if (jbool(*sockopt, "tcpFastOpen")) node.tfo = true;
  if (jbool(*sockopt, "tcpMptcp")) node.mptcp = true;
  if (const std::string dialer = jstring(*sockopt, "dialerProxy"); !dialer.empty()) {
    // 链式代理（先走另一条出站再出去）本工具的模型里没有，忽略会变成直连 —— 必须说清楚
    warnings.push_back("节点 " + label + "：出站使用 dialerProxy（链式代理）-> " + dialer +
                       "，本工具不支持链路，已忽略该字段");
  }
}

// ---------------------------------------------------------------------------
// 出站 → 节点
// ---------------------------------------------------------------------------

/// freedom / blackhole / dns / loopback 这类内置出站不是节点，静默忽略。
bool is_builtin_outbound(const std::string& protocol) {
  static const char* kBuiltin[] = {"freedom", "blackhole", "dns",  "loopback",
                                   "direct",  "block",     "blocked"};
  for (const char* name : kBuiltin) {
    if (codec::iequals(protocol, name)) return true;
  }
  return false;
}

/// sing-box 的出站用 `type`，Xray 用 `protocol`。
bool looks_like_singbox_outbound(const Json& outbound) {
  return member(outbound, "type") != nullptr && member(outbound, "protocol") == nullptr;
}

/// 把一份配置里的一个出站展开成若干节点。base_name 是这一组节点的名字
/// （数组形态下取自配置根级的 `remarks`，单配置形态下退到出站 tag）。
void scan_outbound(const Json& outbound, const std::string& base_name, std::size_t fallback_index,
                   Subscription& sub) {
  const std::string proto_text = codec::to_lower(codec::trim(jstring(outbound, "protocol")));
  if (proto_text.empty()) return;
  if (is_builtin_outbound(proto_text)) return;

  const auto protocol = protocol_from_string(proto_text);
  const bool supported = protocol.has_value() &&
                         (*protocol == Protocol::Vless || *protocol == Protocol::Vmess ||
                          *protocol == Protocol::Trojan || *protocol == Protocol::Shadowsocks ||
                          *protocol == Protocol::Socks5 || *protocol == Protocol::Http);
  if (!supported) {
    sub.warnings.push_back("跳过 Xray 出站（协议 " + proto_text + "）：本工具不支持该协议");
    return;
  }

  const Json* settings = member(outbound, "settings");
  const Json* stream = member(outbound, "streamSettings");
  // 节点名：数组形态用配置根级的 remarks（面板加的），
  // 单配置形态退到出站 tag（v2rayN 之类的工具会把节点名写在 tag 上）。
  const std::string base = base_name.empty() ? codec::trim(jstring(outbound, "tag")) : base_name;

  // 一组出站可能对应多个服务端/用户（vnext+users、servers[]），先都收集起来再统一处理。
  NodeList produced;
  if (*protocol == Protocol::Vless || *protocol == Protocol::Vmess) {
    const Json* vnext = settings != nullptr ? member(*settings, "vnext") : nullptr;
    if (vnext == nullptr || !vnext->is_array() || vnext->empty()) {
      sub.warnings.push_back("跳过 Xray 出站（协议 " + proto_text + "）：settings.vnext 缺失");
      return;
    }
    for (const auto& server : *vnext) {
      if (!server.is_object()) continue;
      const std::string address = jstring(server, "address");
      const uint16_t port = jport(server, "port");
      if (address.empty() || port == 0) {
        sub.warnings.push_back("跳过 Xray 出站（协议 " + proto_text + "）：vnext 缺少合法的 address/port");
        continue;
      }
      const Json* users = member(server, "users");
      if (users == nullptr || !users->is_array() || users->empty()) {
        sub.warnings.push_back("跳过 Xray 出站（协议 " + proto_text + "）：vnext.users 缺失");
        continue;
      }
      for (const auto& user : *users) {
        if (!user.is_object()) continue;
        ProxyNode node;
        node.protocol = *protocol;
        node.server = address;
        node.port = port;
        node.uuid = jstring(user, "id");
        if (*protocol == Protocol::Vless) {
          node.flow = jstring(user, "flow");
          // `none` 折成空串（空串即不加密），mlkem768x25519plus.… 原样保留 —— 丢了服务端会静默黑洞
          node.encryption = normalize_vless_encryption(jstring(user, "encryption"));
        } else {
          node.alter_id = static_cast<int>(jint(user, "alterId", 0));
          node.cipher = jstring(user, "security");
        }
        produced.push_back(std::move(node));
      }
    }
  } else {
    const Json* servers = settings != nullptr ? member(*settings, "servers") : nullptr;
    if (servers == nullptr || !servers->is_array() || servers->empty()) {
      sub.warnings.push_back("跳过 Xray 出站（协议 " + proto_text + "）：settings.servers 缺失");
      return;
    }
    for (const auto& server : *servers) {
      if (!server.is_object()) continue;
      ProxyNode node;
      node.protocol = *protocol;
      node.server = jstring(server, "address");
      node.port = jport(server, "port");
      if (node.server.empty() || node.port == 0) {
        sub.warnings.push_back("跳过 Xray 出站（协议 " + proto_text + "）：servers 缺少合法的 address/port");
        continue;
      }
      switch (*protocol) {
        case Protocol::Trojan:
          node.password = jstring(server, "password");
          node.flow = jstring(server, "flow");
          break;
        case Protocol::Shadowsocks:
          node.cipher = jstring(server, "method");
          node.password = jstring(server, "password");
          break;
        case Protocol::Socks5:
        case Protocol::Http: {
          const Json* users = member(server, "users");
          if (users != nullptr && users->is_array() && !users->empty() &&
              users->front().is_object()) {
            node.username = jstring(users->front(), "user");
            node.password = jstring(users->front(), "pass");
          }
          break;
        }
        default:
          break;
      }
      produced.push_back(std::move(node));
    }
  }

  for (std::size_t i = 0; i < produced.size(); ++i) {
    ProxyNode node = std::move(produced[i]);
    node.name = base.empty() ? ("节点 " + std::to_string(fallback_index))
                             : (produced.size() == 1 ? base
                                                     : base + " #" + std::to_string(i + 1));
    const std::string label = node.name;
    if (stream != nullptr) {
      if (!apply_transport(node, *stream, label, sub.warnings)) continue;
      apply_tls(node, *stream);
      apply_sockopt(node, *stream, label, sub.warnings);
    }
    // trojan 在社区实践里恒为 TLS：与 Clash 输入侧（src/parse/clash_yaml.cpp）保持一致，
    // 只有配置**显式**写了 security=none 才当明文处理。
    if (node.protocol == Protocol::Trojan &&
        (stream == nullptr || member(*stream, "security") == nullptr)) {
      node.tls.enabled = true;
    }
    sub.nodes.push_back(std::move(node));
  }
}

/// 出站里全是 sing-box 风格（type 而非 protocol）—— 用来给「暂不支持」的报错定性。
bool looks_like_singbox_config(const Json& config) {
  const Json* outbounds = member(config, "outbounds");
  if (outbounds == nullptr || !outbounds->is_array()) return false;
  for (const auto& outbound : *outbounds) {
    if (outbound.is_object() && looks_like_singbox_outbound(outbound)) return true;
  }
  return false;
}

}  // namespace

Result<Subscription> parse_xray_json(std::string_view json, std::string source) {
  Subscription sub;
  sub.source = std::move(source);

  Json root;
  try {
    root = Json::parse(std::string(json));
  } catch (const std::exception& e) {
    return fail(std::string("Xray JSON 解析失败: ") + e.what());
  }

  std::vector<const Json*> configs;
  if (root.is_object()) {
    configs.push_back(&root);
  } else if (root.is_array()) {
    for (const auto& item : root) {
      if (item.is_object()) configs.push_back(&item);
    }
    if (configs.empty()) return fail("Xray JSON 是数组，但里面没有配置对象");
  } else {
    return fail("Xray JSON 的根节点既不是配置对象也不是配置数组");
  }

  bool saw_singbox = false;
  std::vector<std::string> reasons;
  std::size_t index = 0;
  for (const Json* config : configs) {
    ++index;
    const std::string remarks = codec::trim(jstring(*config, "remarks"));
    const Json* outbounds = member(*config, "outbounds");
    if (outbounds == nullptr || !outbounds->is_array() || outbounds->empty()) {
      if (looks_like_singbox_config(*config)) {
        saw_singbox = true;
      } else {
        reasons.push_back("第 " + std::to_string(index) + " 份配置里没有 outbounds");
      }
      continue;
    }
    const std::size_t before = sub.nodes.size();
    const std::size_t warn_before = sub.warnings.size();
    for (const auto& outbound : *outbounds) {
      if (!outbound.is_object()) continue;
      if (looks_like_singbox_outbound(outbound)) {
        saw_singbox = true;
        continue;
      }
      scan_outbound(outbound, remarks, index, sub);
    }
    // 一个节点都没出、也没留下更具体的告警（例如出站里只有 freedom），才记一条笼统的原因
    if (sub.nodes.size() == before && sub.warnings.size() == warn_before && !saw_singbox) {
      reasons.push_back("第 " + std::to_string(index) + " 份配置里没有可用的代理出站");
    }
  }

  if (sub.nodes.empty()) {
    std::string detail;
    if (saw_singbox) {
      detail = "：这看起来是 sing-box 的 JSON 配置（outbounds[].type），本工具目前只支持 Xray 的 "
               "JSON 配置（outbounds[].protocol）";
    } else {
      std::vector<std::string> notes = reasons;
      if (notes.size() > 3) {
        notes.resize(3);
        notes.push_back("共 " + std::to_string(index) + " 份配置");
      }
      // 告警里往往是真正的原因（未知传输层 / 协议不支持），必须一起报出来
      for (const auto& warning : sub.warnings) {
        if (notes.size() >= 4) break;
        notes.push_back(warning);
      }
      if (!notes.empty()) detail = "：" + codec::join(notes, "；");
    }
    return fail("没有从 JSON 里解析出任何节点" + detail);
  }
  return sub;
}

}  // namespace subconv
