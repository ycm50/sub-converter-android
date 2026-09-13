// 分享链接输出：v2rayNG / v2rayN / Shadowrocket 等客户端通用的节点链接格式
//
// 依据 v2rayNG 源码（2dust/v2rayNG，AngConfigManager 的 configFmtParsers）确定可导入的 scheme：
//   vmess://  ss://  socks://(socks4:// socks5://)  trojan://  vless://  hysteria2://(hy2://)
//   wireguard://
// 明确**不支持**：ssr://、snell://、hysteria://(v1)、tuic://、http:// 链接
//   —— 这些节点会被跳过并汇总成告警，而不是产出对方打不开的链接。
//
// 目标：
//   links  —— 每行一条分享链接（v2rayNG「从剪贴板导入」、也可直接看）
//   base64 —— 上述列表整体 base64（v2rayNG「添加订阅」返回的内容）
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "emit_internal.hpp"
#include "subconv/codec.hpp"
#include "subconv/json.hpp"

namespace subconv {
namespace {

using Query = std::vector<std::pair<std::string, std::string>>;

void q_add(Query& q, const char* key, std::string value) {
  if (!value.empty()) q.emplace_back(key, std::move(value));
}

void q_flag(Query& q, const char* key, bool on) {
  if (on) q.emplace_back(key, "1");
}

std::string q_string(const Query& q) {
  std::string out;
  for (const auto& [key, value] : q) {
    if (!out.empty()) out.push_back('&');
    out += key;
    out.push_back('=');
    out += codec::percent_encode(value);
  }
  return out;
}

std::string host_port(const ProxyNode& node) {
  const std::string host =
      codec::is_ipv6(node.server) ? ("[" + node.server + "]") : node.server;
  return host + ":" + std::to_string(node.port);
}

std::string tag(const ProxyNode& node) { return codec::percent_encode(node.name); }

/// 拼 `?a=1&b=2`（空表返回空串）。
std::string with_query(const Query& q) {
  const std::string text = q_string(q);
  return text.empty() ? std::string() : ("?" + text);
}

/// v2ray 的 `type=`：tcp + headerType=http 要还原成 `type=tcp&headerType=http`
std::string transport_value(const ProxyNode& node) {
  if (node.network == Network::Http) return "tcp";
  return to_string(node.network);
}

std::string header_type(const ProxyNode& node) {
  if (node.network == Network::Http) return "http";
  const auto it = node.extra.find("headerType");
  return it == node.extra.end() ? std::string() : it->second;
}

std::string transport_host(const ProxyNode& node) {
  if (node.network == Network::Ws) return node.ws.host;
  if (node.network == Network::Xhttp) return node.xhttp.host;
  if (node.network == Network::H2 || node.network == Network::Http) {
    return codec::join(node.h2.host, ",");
  }
  return {};
}

std::string transport_path(const ProxyNode& node) {
  if (node.network == Network::Ws) return node.ws.path;
  if (node.network == Network::Xhttp) return node.xhttp.path;
  if (node.network == Network::H2 || node.network == Network::Http) return node.h2.path;
  return {};
}

std::string alpn_value(const ProxyNode& node) { return codec::join(node.tls.alpn, ","); }

std::string extra_of(const ProxyNode& node, const char* key) {
  const auto it = node.extra.find(key);
  return it == node.extra.end() ? std::string() : it->second;
}

/// 证书指纹：探测得到的优先，其次是订阅里直接给的 `fingerprint:`（sha256 pin）。
/// 两者都在 Xray 侧等价于 `pinnedPeerCertSha256`。
std::string pinned_cert(const ProxyNode& node) {
  return node.tls.pinned_cert_sha256.empty() ? node.tls.fingerprint
                                             : node.tls.pinned_cert_sha256;
}

/// 把协议特有的传输层参数补进 query（vless / trojan / socks 等共用）。
void add_transport(Query& q, const ProxyNode& node) {
  q_add(q, "type", transport_value(node));
  if (node.network == Network::Grpc) {
    q_add(q, "serviceName", node.grpc.service_name);
    if (node.grpc.multi_mode) q_add(q, "mode", "multi");
  }
  if (node.network == Network::Xhttp) {
    // v2rayN BaseFmt.ToUriQuery / v2rayNG FmtBase.emitTransportQuery 都是
    // `type=xhttp` + host/path/mode + `extra=<JSON>`（xhttp 的高级参数整包塞 extra）
    if (!node.xhttp.mode.empty() && xhttp_mode_supported(node.xhttp.mode)) {
      q_add(q, "mode", node.xhttp.mode);
    }
    const Json extra = xhttp_extra_json(node);
    if (!extra.is_null()) q_add(q, "extra", extra.dump());
  }
  q_add(q, "host", transport_host(node));
  q_add(q, "path", transport_path(node));
  q_add(q, "headerType", header_type(node));
}

// ---------------------------------------------------------------------------
// Shadowsocks：SIP002 形式（userinfo 用 base64 的 method:password）
// ---------------------------------------------------------------------------
std::string rebuild_plugin(const SsPlugin& plugin) {
  const std::string name = codec::to_lower(plugin.name);
  std::string out = plugin.name.empty() ? std::string("obfs-local") : plugin.name;
  if (name == "v2ray-plugin") {
    if (!plugin.mode.empty()) out += ";mode=" + plugin.mode;
    if (plugin.tls) out += ";tls";
    if (!plugin.host.empty()) out += ";host=" + plugin.host;
    if (!plugin.path.empty()) out += ";path=" + plugin.path;
  } else {
    if (!plugin.obfs_mode.empty()) out += ";obfs=" + plugin.obfs_mode;
    if (!plugin.obfs_host.empty()) out += ";obfs-host=" + plugin.obfs_host;
  }
  return out;
}

std::optional<std::string> build_ss(const ProxyNode& node) {
  if (node.cipher.empty()) return std::nullopt;

  // SIP002 的 userinfo 是 base64(method:password)。用 URL-safe 字母表且不带 padding：
  // 这样既不需要 percent-encode（标准 base64 里的 '+' '/' '=' 在 URI 里会破坏解析），
  // v2rayNG 的自适应解码也照样认。
  const std::string userinfo = codec::base64_encode_url(node.cipher + ":" + node.password);
  Query q;
  if (node.plugin.present) {
    // 解析阶段保留了原始 plugin 串，优先原样回写，避免字段重建丢信息
    std::string plugin = node.plugin.raw;
    if (plugin.empty()) plugin = rebuild_plugin(node.plugin);
    q_add(q, "plugin", plugin);
  }
  return "ss://" + userinfo + "@" + host_port(node) + with_query(q) + "#" + tag(node);
}

// ---------------------------------------------------------------------------
// VMess：vmess://base64(JSON)（v2rayN / v2rayNG 通用）
//   字段顺序与类型对齐 v2rayNG 的 VmessQRCode：18 个键、值一律字符串。
// ---------------------------------------------------------------------------
std::optional<std::string> build_vmess(const ProxyNode& node) {
  if (node.uuid.empty()) return std::nullopt;

  const auto text = [](const std::string& value) { return Json(value); };

  Json payload = Json::object();
  payload["v"] = text("2");
  payload["ps"] = text(node.name);
  payload["add"] = text(node.server);
  payload["port"] = text(std::to_string(node.port));
  payload["id"] = text(node.uuid);
  payload["aid"] = text(std::to_string(node.alter_id));
  payload["scy"] = text(node.cipher.empty() ? "auto" : node.cipher);
  payload["net"] = text(transport_value(node));
  // vmess 的 `type` 在 xhttp 下装的是 xhttp mode，不是 headerType —— 见 v2rayN
  // VmessFmt 的 `nameof(ETransport.xhttp) => item.GetTransportExtra().XhttpMode`
  payload["type"] = text(node.network == Network::Xhttp
                             ? (node.xhttp.mode.empty() ? std::string("none")
                                                        : node.xhttp.mode)
                             : (header_type(node).empty() ? std::string("none")
                                                          : header_type(node)));
  payload["host"] = text(node.network == Network::Grpc ? std::string() : transport_host(node));
  payload["path"] =
      text(node.network == Network::Grpc ? node.grpc.service_name : transport_path(node));
  payload["tls"] = text(node.tls.enabled ? "tls" : "");
  payload["sni"] = text(node.tls.sni);
  payload["alpn"] = text(alpn_value(node));
  payload["fp"] = text(node.tls.client_fingerprint);
  payload["insecure"] = text(node.tls.insecure || node.scv ? "1" : "0");
  payload["vcn"] = text("");
  payload["pcs"] = text("");

  return "vmess://" + codec::base64_encode(payload.dump());
}

// ---------------------------------------------------------------------------
// VLESS / Trojan
// ---------------------------------------------------------------------------
std::optional<std::string> build_vless(const ProxyNode& node) {
  if (node.uuid.empty()) return std::nullopt;

  Query q;
  q_add(q, "encryption", extra_of(node, "encryption").empty() ? std::string("none")
                                                             : extra_of(node, "encryption"));
  if (node.tls.reality) {
    q_add(q, "security", "reality");
  } else {
    q_add(q, "security", node.tls.enabled ? "tls" : "none");
  }
  q_add(q, "sni", node.tls.sni);
  q_add(q, "fp", node.tls.client_fingerprint);
  q_add(q, "pbk", node.tls.reality_public_key);
  q_add(q, "sid", node.tls.reality_short_id);
  q_add(q, "spx", extra_of(node, "spiderX"));
  add_transport(q, node);
  q_add(q, "flow", node.flow);
  q_add(q, "alpn", alpn_value(node));
  q_add(q, "packetEncoding", node.packet_encoding);
  // v2rayN / v2rayNG 都从 `pcs` 读证书指纹（ItemCertSha -> pinnedPeerCertSha256 /
  // pinnedCA256）。Xray 25+ 移除了 allowInsecure，这个参数是它们唯一能放行
  // 「证书与 SNI 对不上」的节点的办法。
  q_add(q, "pcs", pinned_cert(node));
  // v2rayNG 只在 security=tls 时写 allowInsecure，reality 不带该参数
  if (!node.tls.reality) q_flag(q, "allowInsecure", node.tls.insecure || node.scv);

  return "vless://" + node.uuid + "@" + host_port(node) + with_query(q) + "#" + tag(node);
}

std::optional<std::string> build_trojan(const ProxyNode& node) {
  if (node.password.empty()) return std::nullopt;

  Query q;
  q_add(q, "security", "tls");
  q_add(q, "sni", node.tls.sni);
  add_transport(q, node);
  q_add(q, "alpn", alpn_value(node));
  q_add(q, "fp", node.tls.client_fingerprint);
  q_add(q, "pcs", pinned_cert(node));
  q_flag(q, "allowInsecure", node.tls.insecure || node.scv);

  return "trojan://" + codec::percent_encode(node.password) + "@" + host_port(node) +
         with_query(q) + "#" + tag(node);
}

// ---------------------------------------------------------------------------
// Hysteria2
// ---------------------------------------------------------------------------
std::optional<std::string> build_hysteria2(const ProxyNode& node) {
  if (node.password.empty()) return std::nullopt;

  Query q;
  q_add(q, "sni", node.tls.sni);
  q_add(q, "obfs", node.obfs);
  q_add(q, "obfs-password", node.obfs_password);
  q_add(q, "up", node.up);
  q_add(q, "down", node.down);
  q_add(q, "pinSHA256", node.tls.fingerprint);
  q_add(q, "mport", extra_of(node, "ports"));
  q_add(q, "alpn", alpn_value(node));
  // v2rayNG 导入时会用 query 里的 type 覆盖 network（缺省回落成 tcp），
  // 显式给 type=hysteria 才能让它把这条链接认成 hysteria2 出站。
  q_add(q, "type", "hysteria");
  if (node.tls.insecure || node.scv) q.emplace_back("insecure", "1");

  return "hysteria2://" + codec::percent_encode(node.password) + "@" + host_port(node) +
         with_query(q) + "#" + tag(node);
}

// ---------------------------------------------------------------------------
// SOCKS：userinfo 同样是 base64(user:password)（URL-safe、无 padding）
// ---------------------------------------------------------------------------
std::optional<std::string> build_socks(const ProxyNode& node) {
  std::string uri = "socks://";
  if (!node.username.empty() || !node.password.empty()) {
    uri += codec::base64_encode_url(node.username + ":" + node.password) + "@";
  }
  uri += host_port(node);
  return uri + "#" + tag(node);
}

// ---------------------------------------------------------------------------
// v2rayn:// —— v2rayN / v2rayNG 的内部分享格式
//
// 权威来源（核对 2dust/v2rayN 与 2dust/v2rayNG 主线源码、以及 Xray / sing-box 文档）：
//   * v2rayN ServiceLib/Handler/Fmt/InnerFmt.cs 的 ToUriSingle 产出
//       {InnerUriProtocol}{ConfigType.ToString().ToLower()}/{base64url(JSON)}
//     即 `v2rayn://<枚举名小写>/<载荷>`；ResolveSingle 取 `Uri.AbsolutePath.TrimStart('/')`。
//     → **路径段不能省**：只写 `v2rayn://<载荷>` 时，Uri 会把载荷当成 Host，
//       AbsolutePath 退化成 "/"，解码空串后整条被丢弃（v2rayN 侧全军覆没）。
//   * v2rayNG fmt/V2rayNFmt.kt 的 parseShareItem 是
//       `Utils.decode(str.substringAfterLast('/'))` → 取最后一个 '/' 之后的部分，
//     所以带路径段的写法 v2rayNG 照样能读，两端的写法在这里是统一的。
//   * 载荷 JSON 是 PascalCase。v2rayN 的 ProfileItem 把 ProtoExtra / TransportExtra 存成
//     **字符串**，而 InnerFmt.ResolveSingle 会把 ProtoExtraObj / TransportExtraObj 对象
//     就地拍平成字符串（v2rayNG 的 V2rayNShareItem 则只认嵌套对象）——所以这里用嵌套
//     对象写，两端都吃。
//   * ConfigVersion 必须是 4：InnerFmt.ResolveSingle 里 `!= 4` 直接 return null。
//   * CoreType 只允许 null / Xray(2) / sing_box(24)，不写即为合法。
//   * ConfigType 取 **v2rayN 的 EConfigType** 编号：1=VMess 3=Shadowsocks 4=SOCKS
//     5=VLESS 6=Trojan 7=Hysteria2 8=TUIC 9=WireGuard 10=HTTP。
//     注意 v2rayNG 自己的 EConfigType 把 WireGuard / Hysteria2 的编号对调了
//     （WireGuard=7、Hysteria2=9），但它的 V2rayNShareItem.toProfileItem() 是按 **v2rayN**
//     的编号映射的（7 -> HYSTERIA2、9 -> WIREGUARD、10 -> HTTP），故以本表为准。
//   * IndexId 必须唯一：v2rayNG 用 putIfAbsent 去重，重名会**静默丢节点**。
//   * AllowInsecure 两端都是字符串 "true"/"false"（v2rayN 的 ProfileItem.AllowInsecure 就是 string）。
//
// 为什么 http 代理必须走这里：v2rayN 的 FmtHandler.ResolveConfig 与 v2rayNG 的
// configFmtParsers 都**没有**注册 `http://` 解析器，标准分享链接里根本不存在 http 形态；
// 但两端都定义了 EConfigType.HTTP(10)，v2rayN 的 ConfigHandler.AddBatchServers4InnerUri
// 里有 `EConfigType.HTTP => AddHttpServer`，v2rayNG 的 toProfileItem() 里也有 `10 -> HTTP`。
// ---------------------------------------------------------------------------
int v2rayn_config_type(Protocol protocol) {
  switch (protocol) {
    case Protocol::Vmess: return 1;
    case Protocol::Shadowsocks: return 3;
    case Protocol::Socks5: return 4;
    case Protocol::Vless: return 5;
    case Protocol::Trojan: return 6;
    case Protocol::Hysteria2: return 7;
    case Protocol::Http: return 10;
    default: return 0;
  }
}

/// `v2rayn://` 的路径段，取 `EConfigType.ToString().ToLower()`（不是分享链接的 scheme，
/// Shadowsocks 是 "shadowsocks" 而非 "ss"）。返回 nullptr 表示该协议没有 v2rayN 形态。
const char* v2rayn_type_name(Protocol protocol) {
  switch (protocol) {
    case Protocol::Vmess: return "vmess";
    case Protocol::Shadowsocks: return "shadowsocks";
    case Protocol::Socks5: return "socks";
    case Protocol::Vless: return "vless";
    case Protocol::Trojan: return "trojan";
    case Protocol::Hysteria2: return "hysteria2";
    case Protocol::Http: return "http";
    default: return nullptr;
  }
}

/// 取字符串开头连续的整数（"100 Mbps" -> 100）。
int leading_int(const std::string& text) {
  int value = 0;
  bool seen = false;
  for (const char c : text) {
    if (c >= '0' && c <= '9') {
      value = value * 10 + (c - '0');
      seen = true;
    } else if (seen) {
      break;
    }
  }
  return value;
}

std::string v2rayn_security(const ProxyNode& node) {
  if (node.tls.reality) return "reality";
  // hysteria2 / trojan 本身就强制 TLS
  if (node.protocol == Protocol::Hysteria2 || node.protocol == Protocol::Trojan) return "tls";
  return node.tls.enabled ? "tls" : "";
}

std::optional<std::string> build_v2rayn_item(const ProxyNode& node) {
  const char* type_name = v2rayn_type_name(node.protocol);
  const int config_type = v2rayn_config_type(node.protocol);
  if (type_name == nullptr || config_type == 0 || node.server.empty() || node.port == 0) {
    return std::nullopt;
  }

  Json item = Json::object();
  item["IndexId"] = node.name;   // 必须唯一：v2rayNG 按它去重
  item["ConfigType"] = config_type;
  // v2rayN 的 InnerFmt.ResolveSingle 只接受 4，其余一律丢弃整条
  item["ConfigVersion"] = 4;
  item["Subid"] = "";
  item["IsSub"] = false;
  item["PreSocksPort"] = 0;
  item["Remarks"] = node.name;
  item["Address"] = node.server;
  item["Port"] = static_cast<int>(node.port);
  item["Username"] = node.username;
  // hysteria2 的 network 由 toProfileItem() 强制成 hysteria，这里留空即可
  item["Network"] = node.protocol == Protocol::Hysteria2 ? std::string() : transport_value(node);
  item["StreamSecurity"] = v2rayn_security(node);
  item["AllowInsecure"] = (node.tls.insecure || node.scv) ? "true" : "false";
  item["Sni"] = node.tls.sni;
  item["Alpn"] = alpn_value(node);
  item["Fingerprint"] = node.tls.client_fingerprint;
  item["PublicKey"] = node.tls.reality_public_key;
  item["ShortId"] = node.tls.reality_short_id;
  item["SpiderX"] = extra_of(node, "spiderX");
  item["CertSha"] = pinned_cert(node);
  // vmess / vless 把 UUID 放在 Password；其余协议放各自的口令
  item["Password"] = (node.protocol == Protocol::Vmess || node.protocol == Protocol::Vless)
                         ? node.uuid
                         : node.password;

  Json proto = Json::object();
  switch (node.protocol) {
    case Protocol::Vmess:
      proto["AlterId"] = node.alter_id;
      proto["VmessSecurity"] = node.cipher.empty() ? "auto" : node.cipher;
      break;
    case Protocol::Shadowsocks:
      proto["SsMethod"] = node.cipher;
      break;
    case Protocol::Vless:
      proto["VlessEncryption"] =
          extra_of(node, "encryption").empty() ? "none" : extra_of(node, "encryption");
      proto["Flow"] = node.flow;
      break;
    case Protocol::Hysteria2:
      proto["SalamanderPass"] = node.obfs_password;
      proto["UpMbps"] = leading_int(node.up);
      proto["DownMbps"] = leading_int(node.down);
      proto["Ports"] = extra_of(node, "ports");
      break;
    default:
      break;
  }
  if (!proto.empty()) item["ProtoExtraObj"] = std::move(proto);

  Json transport = Json::object();
  transport["Host"] = transport_host(node);
  transport["Path"] = node.network == Network::Grpc ? std::string() : transport_path(node);
  transport["GrpcServiceName"] = node.grpc.service_name;
  transport["GrpcMode"] = node.grpc.multi_mode ? "multi" : std::string();
  if (node.network == Network::Xhttp) {
    // v2rayN TransportExtraItem / v2rayNG V2rayNTransportExtraShareItem 都有这两个字段，
    // 且都把它落到 outbound 的 xhttpSettings.extra（JSON）上
    transport["XhttpMode"] = node.xhttp.mode;
    const Json extra = xhttp_extra_json(node);
    transport["XhttpExtra"] = extra.is_null() ? std::string() : extra.dump();
  }
  const std::string header = header_type(node);
  if (!header.empty() && !codec::iequals(header, "none")) transport["RawHeaderType"] = header;
  item["TransportExtraObj"] = std::move(transport);

  // URL-safe 且不带 padding：标准 base64 里的 '/' 会被 substringAfterLast('/') 截断。
  // 路径段（http / vmess / …）是 v2rayN 的硬要求，见文件上方注释。
  return "v2rayn://" + std::string(type_name) + "/" + codec::base64_encode_url(item.dump());
}

// ---------------------------------------------------------------------------
// 不支持 / 支持
// ---------------------------------------------------------------------------
const char* unsupported_reason(Protocol protocol) {
  switch (protocol) {
    case Protocol::ShadowsocksR:
      return "v2rayNG 不支持 SSR";
    case Protocol::Snell:
      return "v2rayNG 不支持 Snell";
    case Protocol::Hysteria:
      return "v2rayNG 只支持 hysteria2，不支持 hysteria v1";
    case Protocol::Tuic:
      return "v2rayNG 未启用 TUIC";
    case Protocol::Http:
      return "分享链接没有 http 形态，用 -t v2rayn 才能把 http 代理导给 v2rayN/v2rayNG";
    case Protocol::WireGuard:
      return "WireGuard 需要完整的密钥/地址配置，无法用分享链接表达";
    default:
      return "该协议没有 v2rayNG 分享链接格式";
  }
}

std::string skip_detail(const std::vector<std::string>& details) {
  if (details.empty()) return {};
  return "：" + codec::join(details, "；");
}

}  // namespace

std::optional<std::string> build_share_link(const ProxyNode& node) {
  switch (node.protocol) {
    case Protocol::Shadowsocks:
      return build_ss(node);
    case Protocol::Vmess:
      return build_vmess(node);
    case Protocol::Vless:
      return build_vless(node);
    case Protocol::Trojan:
      return build_trojan(node);
    case Protocol::Hysteria2:
      return build_hysteria2(node);
    case Protocol::Socks5:
      return build_socks(node);
    default:
      return std::nullopt;
  }
}

Result<std::string> emit_sharelinks(const NodeList& nodes, const EmitOptions& opts, ShareMode mode,
                                    std::vector<std::string>* warnings) {
  const NodeList prepared = prepare_nodes(nodes, opts);
  const bool v2rayn_mode = mode == ShareMode::V2rayN;

  // 按协议汇总被跳过的节点，避免一个节点一条告警
  struct Skipped {
    int count = 0;
    std::vector<std::string> samples;
  };
  std::map<int, Skipped> skipped;

  std::string text;
  std::size_t need_pin = 0;
  for (const auto& node : prepared) {
    auto line = v2rayn_mode ? build_v2rayn_item(node) : build_share_link(node);
    if (!line) {
      Skipped& entry = skipped[static_cast<int>(node.protocol)];
      ++entry.count;
      if (entry.samples.size() < 3) entry.samples.push_back(node.name);
      continue;
    }
    // 需要跳过证书校验却没有指纹：走 Xray 内核的 vless / trojan 只能靠链接里的 pcs= 放行。
    // hysteria2 / hysteria 不是 Xray 出站，它们的 `insecure` 在客户端里照样生效，不在此列。
    const bool xray_based = node.protocol == Protocol::Vless || node.protocol == Protocol::Trojan;
    if (xray_based && node.tls.insecure && !node.tls.reality && node.is_tls() &&
        pinned_cert(node).empty()) {
      ++need_pin;
    }
    text += *line;
    text.push_back('\n');
  }

  std::vector<std::string> details;
  for (const auto& [protocol, entry] : skipped) {
    std::string line = "已跳过 " + std::to_string(entry.count) + " 个 " +
                       to_string(static_cast<Protocol>(protocol)) + " 节点（" +
                       unsupported_reason(static_cast<Protocol>(protocol));
    if (!entry.samples.empty()) {
      line += "；例：" + codec::join(entry.samples, "、");
      if (entry.count > static_cast<int>(entry.samples.size())) line += " 等";
    }
    line += "）";
    details.push_back(std::move(line));
  }

  // http 节点的 TLS 在两端命运不同，值得单独提示一次：
  //   v2rayN —— V2rayOutboundService 对**所有**协议统一调 FillBoundStreamSettings，
  //             StreamSecurity=tls 会落到 http 出站的 streamSettings；Xray 官方文档
  //             （docs/config/outbounds/http.md）也写明 http 出站的 security/tlsSettings 生效。
  //   v2rayNG —— CoreOutboundBuilder 里每个协议都调 populateTlsSettings，唯独
  //             toOutboundHttp / toOutboundSocks 不调，它的 http 出站只能是明文。
  std::string http_tls_note;
  if (v2rayn_mode) {
    int tls_http = 0;
    for (const auto& node : prepared) {
      if (node.protocol == Protocol::Http && node.tls.enabled) ++tls_http;
    }
    if (tls_http > 0) {
      http_tls_note = "其中 " + std::to_string(tls_http) +
                      " 个 http 节点带 TLS（https 代理）：只有 v2rayN（Xray 内核）能生效，"
                      "v2rayNG 的 http 出站不写 streamSettings，导入后会是明文代理";
    }
  }

  if (warnings != nullptr) {
    for (const auto& detail : details) warnings->push_back(detail);
    if (!http_tls_note.empty()) warnings->push_back(http_tls_note);
    if (need_pin > 0) {
      warnings->push_back(
          "有 " + std::to_string(need_pin) +
          " 个节点要求跳过证书校验但没有证书指纹：v2rayN / v2rayNG 的 Xray 内核已移除 "
          "allowInsecure，只能靠链接里的 pcs= 指纹放行（否则客户端里全是 -1）→ "
          "加 --probe-cert 探测对端证书即可自动写入 pcs=");
    }
  }

  if (text.empty()) {
    return fail(v2rayn_mode ? (std::string("没有任何节点能生成 v2rayN 分享项") + skip_detail(details))
                            : (std::string("没有任何节点能生成分享链接") + skip_detail(details)));
  }

  // v2rayn:// 与 links 都直接给明文列表；base64 再包一层
  if (mode != ShareMode::Base64) return text;
  return codec::base64_encode(text);
}

}  // namespace subconv
