// sing-box JSON 输出
//
// 能力边界：支持 ss / vmess / vless / trojan / hysteria / hysteria2 / tuic / socks / http；
// 不支持 ssr / snell（sing-box 已移除，交给 mihomo）。
#include <map>
#include <set>
#include <string>
#include <vector>

#include "emit_internal.hpp"
#include "subconv/codec.hpp"
#include "subconv/convert.hpp"
#include "subconv/json.hpp"
#include "../parse/wireguard_common.hpp"

namespace subconv {
namespace {

constexpr const char* kTestUrl = "http://www.gstatic.com/generate_204";

int to_int(const std::string& s, int fallback = 0) {
  if (s.empty()) return fallback;
  try {
    return std::stoi(s);
  } catch (...) {
  }
  // 容忍 "100 Mbps" / "100Mbps" 这类带单位的写法
  std::size_t i = 0;
  while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
  const std::size_t start = i;
  while (i < s.size() && ((s[i] >= '0' && s[i] <= '9') || s[i] == '.')) ++i;
  if (i == start) return fallback;
  try {
    return static_cast<int>(std::stod(s.substr(start, i - start)));
  } catch (...) {
    return fallback;
  }
}

std::string effective_sni(const ProxyNode& n) {
  return n.tls.sni.empty() ? n.server : n.tls.sni;
}

Json build_tls(const ProxyNode& n) {
  Json tls = Json::object();
  tls["enabled"] = true;
  tls["server_name"] = effective_sni(n);
  if (n.tls.insecure) tls["insecure"] = true;
  if (!n.tls.alpn.empty()) tls["alpn"] = n.tls.alpn;
  if (!n.tls.client_fingerprint.empty()) {
    tls["utls"] = Json{{"enabled", true}, {"fingerprint", n.tls.client_fingerprint}};
  }
  if (n.tls.reality) {
    Json reality = Json::object();
    reality["enabled"] = true;
    reality["public_key"] = n.tls.reality_public_key;
    if (!n.tls.reality_short_id.empty()) reality["short_id"] = n.tls.reality_short_id;
    tls["reality"] = std::move(reality);
  }
  return tls;
}

/// sing-box 的 V2Ray 传输层对象。
Json build_transport(const ProxyNode& n) {
  switch (n.network) {
    case Network::Ws: {
      Json ws = Json::object();
      ws["type"] = "ws";
      ws["path"] = n.ws.path.empty() ? "/" : n.ws.path;
      Json headers = Json::object();
      if (!n.ws.host.empty()) headers["Host"] = n.ws.host;
      for (const auto& [k, v] : n.ws.headers) headers[k] = v;
      if (!headers.empty()) ws["headers"] = std::move(headers);
      if (n.ws.max_early_data.has_value()) ws["max_early_data"] = *n.ws.max_early_data;
      if (!n.ws.early_data_header.empty()) {
        ws["early_data_header_name"] = n.ws.early_data_header;
      }
      return ws;
    }
    case Network::Grpc: {
      Json grpc = Json::object();
      grpc["type"] = "grpc";
      grpc["service_name"] = n.grpc.service_name;
      return grpc;
    }
    case Network::H2:
    case Network::Http: {
      Json http = Json::object();
      http["type"] = "http";
      if (!n.h2.host.empty()) http["host"] = n.h2.host;
      if (!n.h2.path.empty()) http["path"] = n.h2.path;
      return http;
    }
    default:
      return Json();
  }
}

/// Shadowsocks 插件的 sing-box 表达方式（plugin + plugin_opts 分号串）。
bool build_ss_plugin(const ProxyNode& n, std::string& plugin, std::string& opts) {
  const std::string name = codec::to_lower(n.plugin.name);
  if (name == "obfs-local" || name == "obfs" || name == "simple-obfs") {
    plugin = "obfs-local";
    opts = "obfs=" + (n.plugin.obfs_mode.empty() ? std::string("http") : n.plugin.obfs_mode);
    if (!n.plugin.obfs_host.empty()) opts += ";obfs-host=" + n.plugin.obfs_host;
    return true;
  }
  if (name == "v2ray-plugin") {
    plugin = "v2ray-plugin";
    opts = "mode=" + (n.plugin.mode.empty() ? std::string("websocket") : n.plugin.mode);
    if (!n.plugin.host.empty()) opts += ";host=" + n.plugin.host;
    if (!n.plugin.path.empty()) opts += ";path=" + n.plugin.path;
    if (n.plugin.tls) opts += ";tls";
    return true;
  }
  return false;   // 未知插件：sing-box 无法表达
}

/// 返回 Null 表示该协议 sing-box 不支持（已记录 warning）。
/// dialer 非空时写 Dial Fields 的 `detour`：本条出站的底层连接交给那条出站去建（链式代理）。
/// 文档：https://sing-box.sagernet.org/configuration/shared/dial/
Json build_outbound(const ProxyNode& n, std::vector<std::string>& warnings,
                    const std::string& dialer = {}) {
  auto reject = [&](std::string why) {
    warnings.push_back(std::string("跳过节点 ") + n.name + "（" + to_string(n.protocol) +
                       "）：sing-box " + why);
    return Json();
  };

  // sing-box 的 V2Ray 传输是枚举死的（option/v2ray_transport.go 的
  // enum:"http,ws,quic,grpc,httpupgrade"），根本没有 xhttp：
  //   $ sing-box check → outbounds[0].transport: unknown transport type: xhttp
  // 与其产出「缺了传输层」的 tcp 配置（能过 check，但连不上），不如明确跳过并告知。
  if (n.network == Network::Xhttp) {
    return reject("没有 xhttp 传输（官方只支持 http/ws/quic/grpc/httpupgrade）；"
                  "该节点请用 -t clash 或 -t xray");
  }

  Json out = Json::object();
  out["tag"] = n.name;
  if (!dialer.empty()) out["detour"] = dialer;

  switch (n.protocol) {
    case Protocol::Shadowsocks: {
      out["type"] = "shadowsocks";
      out["server"] = n.server;
      out["server_port"] = n.port;
      out["method"] = n.cipher;
      out["password"] = n.password;
      if (n.plugin.present) {
        std::string plugin;
        std::string plugin_opts;
        if (!build_ss_plugin(n, plugin, plugin_opts)) {
          return reject("不支持该 shadowsocks 插件");
        }
        out["plugin"] = plugin;
        out["plugin_opts"] = plugin_opts;
      }
      break;
    }
    case Protocol::Vmess: {
      out["type"] = "vmess";
      out["server"] = n.server;
      out["server_port"] = n.port;
      out["uuid"] = n.uuid;
      out["security"] = n.cipher.empty() ? "auto" : n.cipher;
      out["alter_id"] = n.alter_id;
      const Json transport = build_transport(n);
      if (!transport.is_null()) out["transport"] = transport;
      if (n.tls.enabled) out["tls"] = build_tls(n);
      break;
    }
    case Protocol::Vless: {
      // sing-box 的 vless 出站没有 encryption 字段（官方文档 OutboundVLESSOptions 里只有
      // uuid / flow / network / tls / transport / multiplex / packet_encoding），也就是它
      // 至今没实现 VLESS Encryption —— `mlkem768x25519plus` 只存在于 Xray 与 mihomo 系内核。
      // 与其产出一个「能过 sing-box check、连上却必然黑洞」的节点，不如跳过并告知。
      if (!n.encryption.empty()) {
        return reject("没有 VLESS Encryption（encryption=" + n.encryption.substr(0, 32) +
                      "…，这是 Xray/mihomo 的扩展）；该节点请用 -t clash 或 -t xray");
      }
      out["type"] = "vless";
      out["server"] = n.server;
      out["server_port"] = n.port;
      out["uuid"] = n.uuid;
      if (!n.flow.empty()) out["flow"] = n.flow;
      if (!n.packet_encoding.empty()) out["packet_encoding"] = n.packet_encoding;
      const Json transport = build_transport(n);
      if (!transport.is_null()) out["transport"] = transport;
      out["tls"] = build_tls(n);
      break;
    }
    case Protocol::Trojan: {
      out["type"] = "trojan";
      out["server"] = n.server;
      out["server_port"] = n.port;
      out["password"] = n.password;
      const Json transport = build_transport(n);
      if (!transport.is_null()) out["transport"] = transport;
      out["tls"] = build_tls(n);
      break;
    }
    case Protocol::Hysteria: {
      out["type"] = "hysteria";
      out["server"] = n.server;
      out["server_port"] = n.port;
      if (!n.password.empty()) out["auth_str"] = n.password;
      const int up = to_int(n.up);
      const int down = to_int(n.down);
      if (up > 0) out["up_mbps"] = up;
      if (down > 0) out["down_mbps"] = down;
      if (!n.obfs.empty()) out["obfs"] = n.obfs;
      out["tls"] = build_tls(n);
      break;
    }
    case Protocol::Hysteria2: {
      out["type"] = "hysteria2";
      out["server"] = n.server;
      out["server_port"] = n.port;
      out["password"] = n.password;
      const int up = to_int(n.up);
      const int down = to_int(n.down);
      if (up > 0) out["up_mbps"] = up;
      if (down > 0) out["down_mbps"] = down;
      if (!n.obfs.empty()) {
        out["obfs"] = Json{{"type", n.obfs}, {"password", n.obfs_password}};
      }
      out["tls"] = build_tls(n);
      break;
    }
    case Protocol::Tuic: {
      out["type"] = "tuic";
      out["server"] = n.server;
      out["server_port"] = n.port;
      if (!n.uuid.empty()) out["uuid"] = n.uuid;
      if (!n.password.empty()) out["password"] = n.password;
      if (!n.congestion_control.empty()) out["congestion_control"] = n.congestion_control;
      if (!n.udp_relay_mode.empty()) out["udp_relay_mode"] = n.udp_relay_mode;
      out["tls"] = build_tls(n);
      break;
    }
    case Protocol::Socks5: {
      out["type"] = "socks";
      out["server"] = n.server;
      out["server_port"] = n.port;
      out["version"] = "5";
      if (!n.username.empty()) out["username"] = n.username;
      if (!n.password.empty()) out["password"] = n.password;
      break;
    }
    case Protocol::Http: {
      out["type"] = "http";
      out["server"] = n.server;
      out["server_port"] = n.port;
      if (!n.username.empty()) out["username"] = n.username;
      if (!n.password.empty()) out["password"] = n.password;
      if (n.tls.enabled) out["tls"] = build_tls(n);
      break;
    }
    default:
      return reject("不支持该协议");
  }
  return out;
}

/// sing-box 的 WireGuard 是 **endpoint**（1.11 起从 outbound 迁过来的新形态），
/// 字段名见 option/wireguard.go 的 WireGuardEndpointOptions：
///   type / tag / address[] / private_key / peers[]{address,port,public_key,
///   pre_shared_key,allowed_ips,persistent_keepalive_interval,reserved} / mtu / udp_timeout
/// 旧的 `LegacyWireGuardOutboundOptions`（server / server_port / local_address / peer_public_key）
/// 仍被兼容，但既然要产出新配置就用新形态 —— 老形态在后续版本里会消失。
/// 返回 Null 表示该节点无法转换（已记录原因）。
/// dialer 非空时写 Dial Fields 的 `detour`（endpoint 同样是 dial-capable 的）。
Json build_wireguard_endpoint(const ProxyNode& n, std::vector<std::string>& warnings,
                              const std::string& dialer = {}) {
  auto reject = [&](const std::string& why) {
    warnings.push_back("跳过节点 " + n.name + "（wireguard）：sing-box " + why);
    return Json();
  };

  const WireGuardOptions& wg = n.wireguard;
  if (wg.private_key.empty()) return reject("endpoint 必须有 private_key");
  if (wg.peers.empty()) return reject("endpoint 必须有 peers");

  Json endpoint = Json::object();
  endpoint["type"] = "wireguard";
  endpoint["tag"] = n.name;
  if (!dialer.empty()) endpoint["detour"] = dialer;

  // address 是本地网卡地址（CIDR）。裸 IP 要补全掩码：WireGuard 的 Address 允许
  // 不带前缀，但 sing-box 解析的是 netip.Prefix，只认 "10.0.0.2/32" 这种写法。
  Json address = Json::array();
  auto push_address = [&address](const std::string& raw) {
    std::string value = codec::trim(raw);
    if (value.empty()) return;
    if (value.find('/') == std::string::npos) {
      value += codec::is_ipv6(value) ? "/128" : "/32";
    }
    address.push_back(value);
  };
  push_address(wg.ip);
  push_address(wg.ipv6);
  if (address.empty()) return reject("endpoint 必须有本地 address（ip / ipv6）");
  endpoint["address"] = std::move(address);
  endpoint["private_key"] = wireguard_detail::pad_key_base64(wg.private_key);

  Json peers = Json::array();
  for (const auto& peer : wg.peers) {
    Json entry = Json::object();
    if (!peer.server.empty()) entry["address"] = peer.server;
    if (peer.port != 0) entry["port"] = peer.port;
    if (peer.public_key.empty()) return reject("peer 缺少 public_key");
    entry["public_key"] = wireguard_detail::pad_key_base64(peer.public_key);
    if (!peer.pre_shared_key.empty()) {
      entry["pre_shared_key"] = wireguard_detail::pad_key_base64(peer.pre_shared_key);
    }
    std::vector<std::string> allowed = peer.allowed_ips;
    if (allowed.empty()) {
      allowed.push_back("0.0.0.0/0");
      if (!wg.ipv6.empty()) allowed.push_back("::/0");
    }
    entry["allowed_ips"] = allowed;
    if (peer.reserved.size() == 3) entry["reserved"] = peer.reserved;
    if (peer.keepalive > 0) {
      entry["persistent_keepalive_interval"] = peer.keepalive;
    }
    peers.push_back(std::move(entry));
  }
  endpoint["peers"] = std::move(peers);

  if (wg.mtu > 0) endpoint["mtu"] = wg.mtu;
  // remote-dns-resolve / dns 是 mihomo 的概念，sing-box 由 route 的 DNS 规则决定，
  // 这里只提醒一句，免得用户以为「过滤掉了」。
  if (wg.remote_dns_resolve || !wg.dns.empty()) {
    warnings.push_back("节点 " + n.name +
                       "（wireguard）：sing-box 的 endpoint 没有 remote-dns-resolve / dns 字段，"
                       "请改用 route 里的 DNS 规则");
  }
  return endpoint;
}

}  // namespace

Result<std::string> emit_singbox(const NodeList& nodes, const EmitOptions& opts,
                                 std::vector<std::string>* warnings) {
  const NodeList prepared = prepare_nodes(nodes, opts);
  if (prepared.empty()) return fail("去重后没有可输出的节点");

  // 链式代理：链路是用户显式指定的基础设施，任何一跳写不出来就直接报错 ——
  // 静默降级成直连会把流量按真实 IP 放出去。
  auto plan = resolve_chain(prepared, opts, warnings);
  if (!plan) return fail(plan.error());
  const std::map<std::string, std::string> ref_index = build_dialer_index(prepared);
  // 输入自带引用成环时先拦下来：内核不一定拒绝这种配置，真连上去才会死循环 / 超时。
  if (!plan->active()) {
    if (const auto cycle = dialer_cycle(prepared, ref_index); !cycle.empty()) {
      return fail("输入配置的链式代理成环：" + codec::join(cycle, " -> ") +
                  "（detour 首尾相接会死循环，无法转换）");
    }
  }

  std::vector<std::string> skipped;
  std::vector<std::string> chain_caveats;
  Json hop_outbounds = Json::array();
  Json hop_endpoints = Json::array();
  Json node_outbounds = Json::array();
  Json node_endpoints = Json::array();
  Json node_tags = Json::array();
  std::set<std::string> hop_names;

  // 外部链路跳点排在最前，读起来就是「本地 → 跳1 → 跳2 → … → 每个节点」。
  // 引用订阅节点的跳点不重复产出，直接复用节点自己那条出站 / endpoint。
  for (const auto& hop : plan->hops) {
    hop_names.insert(hop.tag);
    // 链路中间那一跳本身也要经上一跳出去 —— 它走 UDP 的话同样链不通，必须一起告警。
    // 这一条要在 `continue` 之前判：引用订阅节点的跳点不在这里产出出站，但 dialer 照样会写。
    if (!hop.dialer.empty()) {
      const std::string caveat = chain_exit_caveat(hop.node);
      if (!caveat.empty()) chain_caveats.push_back(caveat);
    }
    if (!hop.extra) continue;
    std::vector<std::string> hop_warnings;
    Json out = hop.node.protocol == Protocol::WireGuard
                   ? build_wireguard_endpoint(hop.node, hop_warnings, hop.dialer)
                   : build_outbound(hop.node, hop_warnings, hop.dialer);
    if (out.is_null()) {
      return fail("链路节点 " + hop.node.name + " 无法写进 sing-box 配置：" +
                  (hop_warnings.empty() ? std::string("不支持该协议")
                                        : codec::join(hop_warnings, "；")));
    }
    // 产出成功时也可能带告警（例如 wireguard endpoint 的 dns/remote-dns-resolve 提示），
    // 必须在成功分支一并收下，否则用户永远看不到这条提示。
    for (auto& w : hop_warnings) skipped.push_back(std::move(w));
    if (hop.node.protocol == Protocol::WireGuard) {
      hop_endpoints.push_back(std::move(out));
    } else {
      hop_outbounds.push_back(std::move(out));
    }
  }

  for (const auto& node : prepared) {
    const std::string dialer = effective_dialer(node, *plan, ref_index, warnings);
    // 有后置链路时，这个节点自己变成链路里的中间跳点，流量落点是后置链路的末端
    // （末端出站的名字里带着「节点 → 后置」，进 selector / urltest 的是它）。
    const RearChain* rear = plan->rear_for(node.name);
    // wireguard 是 endpoint，其余是 outbound；两者都会进 selector / urltest 的候选。
    std::vector<std::string> node_warnings;
    Json out = node.protocol == Protocol::WireGuard
                   ? build_wireguard_endpoint(node, node_warnings, dialer)
                   : build_outbound(node, node_warnings, dialer);
    if (out.is_null()) {
      if (rear != nullptr || hop_names.count(node.name) != 0) {
        return fail("链路节点 " + node.name + " 无法写进 sing-box 配置：" +
                    (node_warnings.empty() ? std::string("不支持该协议")
                                           : codec::join(node_warnings, "；")) +
                    "（链路是显式指定的，不能静默降级成直连）");
      }
      for (auto& w : node_warnings) skipped.push_back(std::move(w));
      continue;
    }
    // 成功产出时也可能带告警（wireguard endpoint 的 dns/remote-dns-resolve 提示），
    // 必须一并收下 —— 只在失败分支收会让这类提示永远消失。
    for (auto& w : node_warnings) skipped.push_back(std::move(w));
    if (!dialer.empty()) {
      const std::string caveat = chain_exit_caveat(node);
      if (!caveat.empty()) chain_caveats.push_back(caveat);
    }

    if (rear != nullptr) {
      // 后置链路：逐跳产出，hops.back() 才是流量落点。
      // 每一跳都是经上一跳的 TCP 隧道到达的，所以每一跳都要过 UDP 兼容性检查。
      for (const auto& hop : rear->hops) {
        const std::string caveat = chain_exit_caveat(hop.node);
        if (!caveat.empty()) chain_caveats.push_back(caveat);
        std::vector<std::string> hop_warnings;
        Json hout = hop.node.protocol == Protocol::WireGuard
                        ? build_wireguard_endpoint(hop.node, hop_warnings, hop.dialer)
                        : build_outbound(hop.node, hop_warnings, hop.dialer);
        if (hout.is_null()) {
          return fail("后置链路节点 " + hop.node.name + " 无法写进 sing-box 配置：" +
                      (hop_warnings.empty() ? std::string("不支持该协议")
                                            : codec::join(hop_warnings, "；")) +
                      "（链路是显式指定的，不能静默降级成直连）");
        }
        for (auto& w : hop_warnings) skipped.push_back(std::move(w));
        // 链路跳点不进 selector / urltest，与前置链路跳点的处置保持一致。
        if (hop.node.protocol == Protocol::WireGuard) {
          hop_endpoints.push_back(std::move(hout));
        } else {
          hop_outbounds.push_back(std::move(hout));
        }
      }
      node_tags.push_back(rear->target());
    } else {
      node_tags.push_back(node.name);
    }
    if (node.protocol == Protocol::WireGuard) {
      node_endpoints.push_back(std::move(out));
    } else {
      node_outbounds.push_back(std::move(out));
    }
  }
  if (warnings != nullptr) {
    for (const auto& w : skipped) warnings->push_back(w);
    if (!chain_caveats.empty()) {
      warnings->push_back("链路上这些节点的传输本身就依赖 UDP（" +
                          codec::join(chain_caveats, "、") +
                          "）：detour 是按 TCP 建的隧道，链上大概率连不通，建议避开这些节点");
    }
  }
  if (node_tags.empty()) {
    const std::string detail =
        skipped.empty() ? std::string() : ("\n  - " + codec::join(skipped, "\n  - "));
    return fail("没有任何节点能转换为 sing-box 配置" + detail);
  }

  const std::string g_select = opts.emoji ? "🚀 节点选择" : "节点选择";
  const std::string g_auto = opts.emoji ? "♻️ 自动选择" : "自动选择";

  Json selector_list = Json::array();
  selector_list.push_back(g_auto);
  selector_list.push_back("direct");
  for (const auto& tag : node_tags) selector_list.push_back(tag);

  Json outbounds = Json::array();
  outbounds.push_back(Json{{"type", "selector"},
                           {"tag", g_select},
                           {"outbounds", selector_list},
                           {"default", g_auto},
                           {"interrupt_exist_connections", false}});
  outbounds.push_back(Json{{"type", "urltest"},
                           {"tag", g_auto},
                           {"outbounds", node_tags},
                           {"url", kTestUrl},
                           {"interval", "5m"},
                           {"tolerance", 50},
                           {"interrupt_exist_connections", false}});
  // 链路跳点排在节点前面：sing-box 不要求声明顺序，但这样读起来就是链路的顺序。
  for (auto& out : hop_outbounds) outbounds.push_back(std::move(out));
  for (auto& out : node_outbounds) outbounds.push_back(std::move(out));
  outbounds.push_back(Json{{"type", "direct"}, {"tag", "direct"}});
  outbounds.push_back(Json{{"type", "block"}, {"tag", "block"}});

  Json config = Json::object();
  config["log"] = Json{{"level", "warn"}, {"timestamp", true}};
  config["inbounds"] = Json::array({Json{{"type", "mixed"},
                                         {"tag", "mixed-in"},
                                         {"listen", "127.0.0.1"},
                                         {"listen_port", 2080}}});
  // endpoints 必须排在 outbounds 之前（sing-box 要求先声明 endpoint 再引用）；
  // 链路跳点排在节点前面（节点要用 detour 指向它），所以这里显式拼一遍顺序。
  Json endpoints = Json::array();
  for (auto& ep : hop_endpoints) endpoints.push_back(std::move(ep));
  for (auto& ep : node_endpoints) endpoints.push_back(std::move(ep));
  if (!endpoints.empty()) config["endpoints"] = std::move(endpoints);
  config["outbounds"] = std::move(outbounds);
  config["route"] = Json{{"final", g_select}, {"auto_detect_interface", true}};

  return config.dump(2) + "\n";
}

}  // namespace subconv
