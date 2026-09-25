// WireGuard 解析
//
// 输入形态（四种，都归一到 ProxyNode 的 wireguard 字段）：
//   1. wireguard://<private-key>@<host>:<port>?publickey=..&address=..&...#name
//   2. wireguard-json://base64(JSON)（也可以直接给 base64 串，见下）
//   3. 标准 WireGuard 客户端配置文本：`[Interface]` / `[Peer]`
//   4. Clash YAML / Xray JSON 里的 wireguard 节点（在各自的解析器里调用本文件的辅助函数）
//
// ---------------------------------------------------------------------------
// 关于分享链接：`wireguard://` 是 v2rayN / v2rayNG 的事实约定
// ---------------------------------------------------------------------------
// WireGuard 协议本身没有定义分享链接，但 2dust 家的两个客户端（v2rayN / v2rayNG）都实现了
// 同一个 `wireguard://` 形态（v2rayN 的 `Global.ProtocolShares`、v2rayNG 的
// `fmt/WireguardFmt.kt`），本工具按它的字段约定解析与产出，同时对其它工具的常见别名保持宽容。
//
//   userinfo          -> 客户端私钥（base64，percent-encoded；v2rayNG 直接取 uri.userInfo）
//   host:port         -> 第一个 peer 的 endpoint（IPv6 写作 [addr]:port）
//   ?publickey=       -> 第一个 peer 的公钥（别名 pubkey / serverpublickey / peer）
//   ?presharedkey=    -> PresharedKey（别名 psk / presharedkey）
//   ?address=         -> 客户端地址，**IPv4 与 IPv6 同栏**、逗号分隔
//                        （别名 ip / localaddress / addresses；也接受独立的 ipv6=）
//   ?allowedips=      -> 该 peer 的 AllowedIPs（逗号分隔）。两端都不读它 ——
//                        v2rayNG 由 address 是否含 v6 推导，本工具仅在"与推导结果不同"时写出。
//   ?reserved=        -> WARP 的 3 字节保留位，**逗号分隔十进制**（"209,98,59"，v2rayN 的写法）；
//                        也接受 "U4An"（base64）与 6 位 hex —— mihomo 支持字符串形态。
//   ?keepalive=       -> PersistentKeepalive（秒，别名 persistentkeepalive）
//   ?mtu=             -> MTU
//   ?dns=             -> 远程 DNS（逗号分隔）
//   ?remotednsresolve=?ipstack=?congestioncontroller=   -> 本工具的扩展（v2rayn 没有这些概念）
//   #name             -> 节点名
//
// `wireguard-json://` 的 JSON 字段接受下表和 v2rayN 的 PascalCase 写法
// （PrivateKey / PublicKey / PresharedKey / Address / Reserved / Mtu / WgPublicKey /
// WgPresharedKey / WgInterfaceAddress / WgReserved / WgMtu），
// 这样那种 JSON 载荷可以直接贴进来。
#include <map>
#include <string>

#include "json_util.hpp"
#include "parsers.hpp"
#include "subconv/codec.hpp"
#include "subconv/wireguard.hpp"
#include "uri_common.hpp"
#include "wireguard_common.hpp"

namespace subconv {
namespace {

using wireguard_detail::looks_like_key;
using wireguard_detail::strip_key_padding;

int to_int(const std::string& text, int fallback = 0) {
  if (text.empty()) return fallback;
  try {
    return std::stoi(text);
  } catch (...) {
    return fallback;
  }
}

/// 把 IPv4 / IPv6 地址分别落到 wireguard.ip / wireguard.ipv6。
void add_interface_address(WireGuardOptions& wg, const std::string& address) {
  const std::string value = codec::trim(address);
  if (value.empty()) return;
  if (wireguard_detail::address_is_ipv6(value)) {
    if (wg.ipv6.empty()) wg.ipv6 = value;
    return;
  }
  if (wg.ip.empty()) {
    wg.ip = value;
    return;
  }
  // 同一栏多地址：mihomo 只认单个 `ip`，多余的按逗号拼进去会直接加载失败，
  // 所以只保留第一个（IPv6 另有 `ipv6` 栏，这里不接受更多）。
}

/// 校验一个刚解析出来的 WireGuard 节点：缺了私钥或对端公钥就一定连不上。
/// 同时把两侧的密钥统一成「去掉尾部 '='」的形态 —— 各目标内核都能接受（Xray 的
/// ParseWireGuardKey 自己就 TrimSuffix 掉 '='），但统一后配置与分享链接才是可往返的。
Result<ProxyNode> finish(ProxyNode node, const std::string& fallback_name) {
  if (node.name.empty()) node.name = fallback_name;
  if (!node.wireguard.present) return fail("WireGuard 解析失败");
  node.wireguard.private_key = strip_key_padding(node.wireguard.private_key);
  for (auto& peer : node.wireguard.peers) {
    peer.public_key = strip_key_padding(peer.public_key);
    peer.pre_shared_key = strip_key_padding(peer.pre_shared_key);
  }
  if (node.wireguard.private_key.empty()) {
    return fail("WireGuard 缺少客户端私钥（privatekey / [Interface] PrivateKey）");
  }
  if (!looks_like_key(node.wireguard.private_key)) {
    return fail("WireGuard 私钥不是合法的 base64 / hex（应为 32 字节）");
  }
  if (node.wireguard.peers.empty()) {
    return fail("WireGuard 缺少对端（[Peer] / peers）");
  }
  for (const auto& peer : node.wireguard.peers) {
    if (peer.public_key.empty()) {
      return fail("WireGuard 对端缺少公钥（publickey / [Peer] PublicKey）");
    }
    if (!looks_like_key(peer.public_key)) {
      return fail("WireGuard 对端公钥不是合法的 base64 / hex（应为 32 字节）");
    }
  }
  // 第一个 peer 的 endpoint 回填到 server/port：去重、命名与告警都依赖这两个字段。
  node.server = node.wireguard.peers.front().server;
  node.port = node.wireguard.peers.front().port;
  if (node.server.empty() || node.port == 0) {
    return fail("WireGuard 对端缺少 endpoint（host:port）");
  }
  return node;
}

/// 共享的 JSON → WireGuardOptions（wireguard-json:// 与 v2rayN 载荷共用）。
WireGuardOptions options_from_json(const Json& j) {
  WireGuardOptions wg;
  wg.present = true;

  auto str = [&j](std::initializer_list<const char*> keys) {
    for (const char* key : keys) {
      std::string v = codec::trim(parse_detail::jstring(j, key));
      if (!v.empty()) return v;
    }
    return std::string();
  };

  wg.private_key = strip_key_padding(str({"privateKey", "privatekey", "private_key", "secretKey",
                                          "secret_key", "secret", "WgPrivateKey", "Password"}));
  wg.ip_stack_mode = codec::to_lower(str({"ipStack", "ipstack", "ip_stack", "mode"}));
  wg.mtu = static_cast<int>(parse_detail::jint(j, "mtu", 0));
  if (wg.mtu == 0) wg.mtu = static_cast<int>(parse_detail::jint(j, "WgMtu", 0));

  // address：字符串或数组，IPv4 / IPv6 分栏。
  // `WgInterfaceAddress` 是 v2rayN / v2rayNG 的 V2rayNProtocolExtraShareItem 里的叫法
  // （逗号分隔的字符串），一并接受，这样那种 JSON 可以直接喂进来。
  if (const auto it = j.find("address"); it != j.end()) {
    if (it->is_array()) {
      for (const auto& item : *it) {
        if (item.is_string()) add_interface_address(wg, item.get<std::string>());
      }
    } else if (it->is_string()) {
      for (const auto& piece : wireguard_detail::split_allowed_ips(it->get<std::string>())) {
        add_interface_address(wg, piece);
      }
    }
  }
  add_interface_address(wg, str({"ip", "localAddress", "local_address"}));
  add_interface_address(wg, str({"ipv6", "address6", "ipv6Address", "ipv6_address"}));
  for (const auto& piece :
       wireguard_detail::split_allowed_ips(str({"WgInterfaceAddress", "wgInterfaceAddress"}))) {
    add_interface_address(wg, piece);
  }
  if (wg.ip_stack_mode.empty()) {
    if (const auto it = j.find("ipStack"); it != j.end() && it->is_object()) {
      wg.ip_stack_mode = codec::to_lower(parse_detail::jstring(*it, "mode"));
      wg.congestion_controller = parse_detail::jstring(*it, "congestionController");
      if (wg.congestion_controller.empty()) {
        wg.congestion_controller = parse_detail::jstring(*it, "congestion_controller");
      }
    }
  }
  if (wg.congestion_controller.empty()) {
    wg.congestion_controller =
        str({"congestionController", "congestion_controller", "congestion-controller"});
  }

  if (const auto dns = j.find("dns"); dns != j.end()) {
    std::vector<std::string> servers;
    if (dns->is_array()) {
      for (const auto& item : *dns) {
        if (item.is_string()) servers.push_back(codec::trim(item.get<std::string>()));
      }
    } else if (dns->is_string()) {
      servers = wireguard_detail::split_allowed_ips(dns->get<std::string>());
    }
    for (auto& server : servers) {
      if (!server.empty()) wg.dns.push_back(std::move(server));
    }
  }
  wg.remote_dns_resolve =
      parse_detail::jbool(j, "remoteDnsResolve", parse_detail::jbool(j, "remote_dns_resolve"));

  // peers：数组优先；只有一个对端时也接受平铺字段（v2rayN / 老版 sing-box 的写法）
  WireGuardPeer single;
  single.server = str({"server", "address", "endpoint", "host"});
  single.port = static_cast<uint16_t>(parse_detail::jint(j, "port", 0));
  single.public_key = strip_key_padding(
      str({"publicKey", "publickey", "public_key", "peerPublicKey", "WgPublicKey"}));
  single.pre_shared_key =
      strip_key_padding(str({"preSharedKey", "presharedKey", "pre_shared_key", "psk",
                             "PreSharedKey", "WgPresharedKey"}));
  single.keepalive =
      static_cast<int>(parse_detail::jint(j, "keepalive", parse_detail::jint(j, "persistentKeepalive", 0)));
  if (const auto it = j.find("allowedIPs"); it != j.end()) {
    single.allowed_ips = wireguard_detail::allowed_ips_from_json(*it);
  } else if (const auto it = j.find("allowedIps"); it != j.end()) {
    single.allowed_ips = wireguard_detail::allowed_ips_from_json(*it);
  } else if (const auto it = j.find("allowed_ips"); it != j.end()) {
    single.allowed_ips = wireguard_detail::allowed_ips_from_json(*it);
  }
  if (const auto it = j.find("reserved"); it != j.end()) {
    wireguard_detail::parse_reserved_json(*it, single.reserved);
  }

  bool has_peers = false;
  if (const auto peers = j.find("peers"); peers != j.end() && peers->is_array()) {
    for (const auto& item : *peers) {
      if (!item.is_object()) continue;
      WireGuardPeer peer;
      peer.server = codec::trim(parse_detail::jstring(item, "server"));
      if (peer.server.empty()) peer.server = codec::trim(parse_detail::jstring(item, "address"));
      if (peer.server.empty()) peer.server = codec::trim(parse_detail::jstring(item, "endpoint"));
      // endpoint 可能是 "host:port" 一整串（Xray 的写法）
      if (peer.server.find(':') != std::string::npos && peer.server.find(']') == std::string::npos &&
          !codec::is_ipv6(peer.server)) {
        if (auto hp = codec::split_host_port(peer.server); hp && !hp->second.empty()) {
          peer.server = hp->first;
          if (auto port = codec::parse_port(hp->second); port) peer.port = *port;
        }
      }
      peer.port = static_cast<uint16_t>(parse_detail::jint(item, "port", peer.port));
      peer.public_key = strip_key_padding(parse_detail::jstring(item, "publicKey"));
      if (peer.public_key.empty()) {
        peer.public_key = strip_key_padding(parse_detail::jstring(item, "public_key"));
      }
      peer.pre_shared_key = strip_key_padding(parse_detail::jstring(item, "preSharedKey"));
      if (peer.pre_shared_key.empty()) {
        peer.pre_shared_key = strip_key_padding(parse_detail::jstring(item, "pre_shared_key"));
      }
      peer.keepalive =
          static_cast<int>(parse_detail::jint(item, "keepalive",
                                             parse_detail::jint(item, "persistentKeepalive", 0)));
      if (const auto allowed = item.find("allowedIPs"); allowed != item.end()) {
        peer.allowed_ips = wireguard_detail::allowed_ips_from_json(*allowed);
      } else if (const auto allowed = item.find("allowed_ips"); allowed != item.end()) {
        peer.allowed_ips = wireguard_detail::allowed_ips_from_json(*allowed);
      }
      if (const auto reserved = item.find("reserved"); reserved != item.end()) {
        wireguard_detail::parse_reserved_json(*reserved, peer.reserved);
      }
      wg.peers.push_back(std::move(peer));
      has_peers = true;
    }
  }
  if (!has_peers && (!single.server.empty() || !single.public_key.empty())) {
    wg.peers.push_back(std::move(single));
  }
  return wg;
}

/// 把一行 query 参数填进 WireGuardOptions（wireguard:// 用）。
void options_from_query(WireGuardOptions& wg, const std::map<std::string, std::string>& q) {
  WireGuardPeer peer;

  if (const std::string* v = parse_detail::pick(q, {"publickey", "pubkey", "public-key",
                                                   "serverpublickey", "server_public_key",
                                                   "peer", "peerpublickey"})) {
    peer.public_key = strip_key_padding(*v);
  }
  if (const std::string* v =
          parse_detail::pick(q, {"presharedkey", "pre-shared-key", "psk", "preshared-key"})) {
    peer.pre_shared_key = strip_key_padding(*v);
  }
  if (const std::string* v = parse_detail::pick(q, {"allowedips", "allowed-ips", "allowedip"})) {
    peer.allowed_ips = wireguard_detail::split_allowed_ips(*v);
  }
  if (const std::string* v = parse_detail::pick(q, {"reserved", "reserved_bytes"})) {
    wireguard_detail::parse_reserved_scalar(*v, peer.reserved);
  }
  if (const std::string* v =
          parse_detail::pick(q, {"keepalive", "persistentkeepalive", "persistent-keepalive"})) {
    peer.keepalive = to_int(*v);
  }

  if (const std::string* v =
          parse_detail::pick(q, {"privatekey", "private-key", "secretkey", "secret"})) {
    wg.private_key = strip_key_padding(*v);
  }
  if (const std::string* v = parse_detail::pick(q, {"address", "ip", "localaddress",
                                                    "local_address", "addresses"})) {
    for (const auto& piece : wireguard_detail::split_allowed_ips(*v)) {
      add_interface_address(wg, piece);
    }
  }
  if (const std::string* v = parse_detail::pick(q, {"ipv6", "address6", "ipv6address"})) {
    add_interface_address(wg, *v);
  }
  if (const std::string* v = parse_detail::pick(q, {"mtu"})) wg.mtu = to_int(*v);
  if (const std::string* v = parse_detail::pick(q, {"dns", "remotedns", "remote-dns"})) {
    wg.dns = wireguard_detail::split_allowed_ips(*v);
  }
  if (const std::string* v = parse_detail::pick(q, {"remotednsresolve", "remote-dns-resolve"})) {
    wg.remote_dns_resolve = parse_detail::truthy(v);
  }
  if (const std::string* v = parse_detail::pick(q, {"ipstack", "ip-stack"})) {
    wg.ip_stack_mode = codec::to_lower(*v);
  }
  if (const std::string* v = parse_detail::pick(
          q, {"congestioncontroller", "congestion-controller", "congestion_control"})) {
    wg.congestion_controller = *v;
  }

  if (!peer.public_key.empty() || !peer.allowed_ips.empty() || !peer.reserved.empty() ||
      peer.keepalive != 0) {
    wg.peers.push_back(std::move(peer));
  } else {
    // 只有 endpoint（host:port）时也要留一个占位 peer，好让 finish() 报出
    // 「缺少公钥」而不是「缺少对端」这种更费解的错。
    wg.peers.push_back(WireGuardPeer{});
  }
}

/// 合并「重复出现的 peer（多 peer 写法）」：本工具只对第一个 peer 建模，
/// 多余的 peer 记录到 extra 里，避免静默丢失。
void note_extra_peers(ProxyNode& node, std::size_t total) {
  if (total > 1) {
    node.extra["wireguard-peers"] = std::to_string(total);
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// wireguard:// 分享链接
// ---------------------------------------------------------------------------
Result<ProxyNode> parse_wireguard(std::string_view uri, const std::string& fallback_name) {
  constexpr std::string_view kScheme = "wireguard://";
  constexpr std::string_view kShortScheme = "wg://";
  if (codec::starts_with_icase(uri, kShortScheme)) {
    uri.remove_prefix(kShortScheme.size());
  } else if (codec::starts_with_icase(uri, kScheme)) {
    uri.remove_prefix(kScheme.size());
  } else {
    return fail("不是 wireguard:// 链接");
  }

  std::string_view body = uri;
  std::string fragment;
  if (const auto hash = body.find('#'); hash != std::string_view::npos) {
    fragment = codec::percent_decode(body.substr(hash + 1));
    body = body.substr(0, hash);
  }
  std::string_view query;
  if (const auto mark = body.find('?'); mark != std::string_view::npos) {
    query = body.substr(mark + 1);
    body = body.substr(0, mark);
  }

  ProxyNode node;
  node.protocol = Protocol::WireGuard;
  node.wireguard.present = true;
  node.name = codec::trim(fragment);

  // userinfo 与 host:port —— 私钥里可能有 '+/='，这里不做 percent 解码以外的处理。
  std::string_view hostport = body;
  if (const auto at = body.rfind('@'); at != std::string_view::npos) {
    node.wireguard.private_key = strip_key_padding(codec::percent_decode(body.substr(0, at)));
    hostport = body.substr(at + 1);
  }
  // 去掉可能存在的路径段（wireguard://<key>@host:port/ 这种写法）
  if (const auto slash = hostport.find('/'); slash != std::string_view::npos) {
    hostport = hostport.substr(0, slash);
  }

  auto hp = codec::split_host_port(hostport);
  if (!hp) return fail(std::string("wireguard:// 的 endpoint 无效: ") + hp.error().message);
  WireGuardPeer peer;
  peer.server = hp->first;
  if (!hp->second.empty()) {
    auto port = codec::parse_port(hp->second);
    if (!port) return fail(port.error());
    peer.port = *port;
  }

  const auto q = codec::parse_query(query);
  options_from_query(node.wireguard, q);
  // 私钥优先取 userinfo；userinfo 为空时回落到 ?privatekey= 一类的别名。
  if (node.wireguard.private_key.empty()) {
    if (const std::string* v =
            parse_detail::pick(q, {"privatekey", "private-key", "secretkey", "secret"})) {
      node.wireguard.private_key = strip_key_padding(*v);
    }
  }

  // endpoint 从 host:port 补进第一个 peer
  if (!node.wireguard.peers.empty()) {
    if (node.wireguard.peers.front().server.empty()) node.wireguard.peers.front().server = peer.server;
    if (node.wireguard.peers.front().port == 0) node.wireguard.peers.front().port = peer.port;
  } else {
    node.wireguard.peers.push_back(std::move(peer));
  }
  return finish(std::move(node), fallback_name);
}

// ---------------------------------------------------------------------------
// wireguard-json://<base64(JSON)>（也接受裸 base64 / 裸 JSON）
// ---------------------------------------------------------------------------
Result<ProxyNode> parse_wireguard_json(std::string_view payload, const std::string& fallback_name) {
  std::string text = codec::trim(payload);
  if (text.empty()) return fail("WireGuard JSON 内容为空");

  std::string fragment;
  if (const auto hash = text.find('#'); hash != std::string::npos) {
    fragment = codec::percent_decode(text.substr(hash + 1));
    text = text.substr(0, hash);
  }

  if (text.find('{') == std::string::npos) {
    auto decoded = codec::base64_decode(text);
    if (!decoded) return fail("WireGuard 载荷既不是 JSON 也不是合法 base64");
    text = codec::trim(*decoded);
  }
  const Json j = Json::parse(text, nullptr, false);
  if (j.is_discarded() || !j.is_object()) return fail("WireGuard JSON 解析失败");

  // 支持 { "wireguard": {...} } 或 { "outbound": {...} } 这种包裹一层再来的（v2rayN 的
  // ProtoExtra / v2rayNG 的 V2rayNShareItem 都爱这么嵌套）。
  const Json* source = &j;
  if (j.find("privateKey") == j.end() && j.find("privatekey") == j.end() &&
      j.find("private_key") == j.end()) {
    for (const char* wrapper : {"wireguard", "WireGuard", "outbound", "Outbound", "ProtoExtra",
                                "ProtoExtraObj"}) {
      const auto it = j.find(wrapper);
      if (it == j.end()) continue;
      if (it->is_object()) {
        source = &*it;
        break;
      }
      if (it->is_string()) {
        const Json inner = Json::parse(it->get<std::string>(), nullptr, false);
        if (!inner.is_discarded() && inner.is_object()) {
          source = &inner;
          break;
        }
      }
    }
  }

  ProxyNode node;
  node.protocol = Protocol::WireGuard;
  node.wireguard = options_from_json(*source);
  node.name = codec::trim(parse_detail::jstring(*source, "name"));
  if (node.name.empty()) node.name = codec::trim(parse_detail::jstring(*source, "remarks"));
  if (node.name.empty()) node.name = codec::trim(parse_detail::jstring(*source, "tag"));
  if (node.name.empty()) node.name = codec::trim(parse_detail::jstring(j, "remarks"));
  if (!fragment.empty()) node.name = codec::trim(fragment);
  return finish(std::move(node), fallback_name);
}

// ---------------------------------------------------------------------------
// 标准 WireGuard 客户端配置（wg-quick 的 .conf）
// ---------------------------------------------------------------------------
Result<ProxyNode> parse_wireguard_conf(std::string_view text, const std::string& fallback_name) {
  if (text.find("[Interface]") == std::string_view::npos &&
      text.find("[interface]") == std::string_view::npos) {
    return fail("不是 WireGuard 配置（缺少 [Interface] 段）");
  }

  ProxyNode node;
  node.protocol = Protocol::WireGuard;
  node.wireguard.present = true;

  enum class Section { None, Interface, Peer };
  Section section = Section::None;
  WireGuardPeer current;
  bool in_peer = false;

  auto flush_peer = [&] {
    if (!in_peer) return;
    node.wireguard.peers.push_back(current);
    current = WireGuardPeer{};
    in_peer = false;
  };

  for (const auto& raw_line : codec::split(text, '\n')) {
    std::string line = codec::trim(raw_line);
    if (line.empty()) continue;
    if (line[0] == '#' || line[0] == ';') continue;
    if (line.front() == '[') {
      flush_peer();
      const std::string name = codec::to_lower(codec::trim(
          std::string_view(line).substr(1, line.size() >= 2 && line.back() == ']'
                                               ? line.size() - 2
                                               : std::string::npos)));
      if (name == "interface") {
        section = Section::Interface;
      } else if (name == "peer") {
        section = Section::Peer;
        in_peer = true;
      } else {
        section = Section::None;
      }
      continue;
    }
    std::string key;
    std::string value;
    if (!wireguard_detail::split_kv(line, key, value)) continue;

    if (section == Section::Interface) {
      if (key == "privatekey") {
        node.wireguard.private_key = strip_key_padding(value);
      } else if (key == "address") {
        for (const auto& piece : wireguard_detail::split_allowed_ips(value)) {
          add_interface_address(node.wireguard, piece);
        }
      } else if (key == "dns") {
        node.wireguard.dns = wireguard_detail::split_allowed_ips(value);
      } else if (key == "mtu") {
        node.wireguard.mtu = to_int(value);
      }
      // ListenPort / Table / PreUp 等属于服务端或路由策略，不是节点属性，忽略。
    } else if (section == Section::Peer) {
      if (key == "publickey") {
        current.public_key = strip_key_padding(value);
      } else if (key == "presharedkey") {
        current.pre_shared_key = strip_key_padding(value);
      } else if (key == "allowedips") {
        current.allowed_ips = wireguard_detail::split_allowed_ips(value);
      } else if (key == "endpoint") {
        // Endpoint 可能是 host:port，也可能是 [v6]:port
        if (auto hp = codec::split_host_port(value); hp) {
          current.server = hp->first;
          if (!hp->second.empty()) {
            if (auto port = codec::parse_port(hp->second); port) current.port = *port;
          }
        } else {
          current.server = value;
        }
      } else if (key == "persistentkeepalive") {
        current.keepalive = to_int(value);
      }
    }
  }
  flush_peer();

  if (node.wireguard.dns.empty()) node.wireguard.remote_dns_resolve = false;
  else node.wireguard.remote_dns_resolve = true;
  note_extra_peers(node, node.wireguard.peers.size());
  return finish(std::move(node), fallback_name);
}

}  // namespace subconv
