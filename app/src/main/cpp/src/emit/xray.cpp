// Xray / V2Ray JSON 输出
//
// Xray 的能力边界与 Clash / sing-box 不同，必须显式区分：
//   支持：ss(AEAD/2022) / vmess / vless / trojan / socks / http
//   不支持：ssr / snell / hysteria / hysteria2 / tuic（这些由 mihomo / sing-box 承载）
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

bool is_aead_cipher(const std::string& cipher) {
  static const char* kOk[] = {"aes-128-gcm",   "aes-256-gcm",        "chacha20-poly1305",
                              "chacha20-ietf-poly1305", "none", "2022-blake3-aes-128-gcm",
                              "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"};
  for (const char* c : kOk) {
    if (codec::iequals(cipher, c)) return true;
  }
  // 2022 系列的带时间戳变体
  return cipher.starts_with("2022-blake3-");
}

std::string effective_sni(const ProxyNode& n) {
  return n.tls.sni.empty() ? n.server : n.tls.sni;
}

/// dialer 非空时写进 `sockopt.dialerProxy`：本出站的底层连接先交给那条出站去建。
/// Xray 文档原话是「一个出站代理的标识……通常用于配置链式代理」，是 Xray 唯一的链路表达。
Json build_stream_settings(const ProxyNode& n, const std::string& dialer = {}) {
  Json stream = Json::object();

  // ---- 传输层 ----
  switch (n.network) {
    case Network::Ws: {
      stream["network"] = "ws";
      Json ws = Json::object();
      ws["path"] = n.ws.path.empty() ? "/" : n.ws.path;
      Json headers = Json::object();
      if (!n.ws.host.empty()) headers["Host"] = n.ws.host;
      for (const auto& [k, v] : n.ws.headers) headers[k] = v;
      if (!headers.empty()) ws["headers"] = std::move(headers);
      if (n.ws.max_early_data.has_value()) ws["maxEarlyData"] = *n.ws.max_early_data;
      if (!n.ws.early_data_header.empty()) ws["earlyDataHeaderName"] = n.ws.early_data_header;
      stream["wsSettings"] = std::move(ws);
      break;
    }
    case Network::Grpc: {
      stream["network"] = "grpc";
      Json grpc = Json::object();
      grpc["serviceName"] = n.grpc.service_name;
      if (n.grpc.multi_mode) grpc["multiMode"] = true;
      stream["grpcSettings"] = std::move(grpc);
      break;
    }
    case Network::H2: {
      stream["network"] = "h2";
      Json http = Json::object();
      if (!n.h2.host.empty()) http["host"] = n.h2.host;
      if (!n.h2.path.empty()) http["path"] = n.h2.path;
      stream["httpSettings"] = std::move(http);
      break;
    }
    case Network::Http: {
      // v2ray 的 tcp + headerType=http，在 Xray 里就是 tcpSettings.header
      stream["network"] = "tcp";
      Json path = Json::array();
      path.push_back(n.h2.path.empty() ? "/" : n.h2.path);
      Json headers = Json::object();
      if (!n.h2.host.empty()) headers["Host"] = n.h2.host;
      Json request = Json::object();
      request["path"] = std::move(path);
      if (!headers.empty()) request["headers"] = std::move(headers);
      Json header = Json::object();
      header["type"] = "http";
      header["request"] = std::move(request);
      stream["tcpSettings"] = Json{{"header", std::move(header)}};
      break;
    }
    case Network::Quic: stream["network"] = "quic"; break;
    case Network::Kcp: stream["network"] = "kcp"; break;
    case Network::Xhttp: {
      stream["network"] = "xhttp";
      stream["xhttpSettings"] = xhttp_settings_json(n);
      break;
    }
    case Network::Tcp: stream["network"] = "tcp"; break;
  }

  // ---- 安全层 ----
  if (n.tls.reality) {
    stream["security"] = "reality";
    Json reality = Json::object();
    reality["serverName"] = effective_sni(n);
    reality["fingerprint"] =
        n.tls.client_fingerprint.empty() ? "chrome" : n.tls.client_fingerprint;
    reality["publicKey"] = n.tls.reality_public_key;
    if (!n.tls.reality_short_id.empty()) reality["shortId"] = n.tls.reality_short_id;
    const auto spider = n.extra.find("spiderX");
    reality["spiderX"] = spider != n.extra.end() && !spider->second.empty() ? spider->second : "/";
    stream["realitySettings"] = std::move(reality);
  } else if (n.tls.enabled) {
    stream["security"] = "tls";
    Json tls = Json::object();
    const std::string sni = effective_sni(n);
    tls["serverName"] = sni;
    // Xray v25+ 移除了 allowInsecure（加载时直接报
    //   The feature "allowInsecure" has been removed and migrated to
    //   "pinnedPeerCertSha256"(pcs) and "verifyPeerCertByName"(vcn).
    // ），而两条替代路径的语义并不相同：
    //   * pinnedPeerCertSha256：命中叶子证书就**立即放行**（不校链、不校名），等价于
    //     skip-cert-verify —— `--probe-cert` 探测出来的正是它；
    //   * verifyPeerCertByName：仍要求"证书链可信 **且** 名字匹配"，机场那种「证书与
    //     SNI 对不上」的节点用它必然失败（客户端表现是所有节点延迟 -1），只能当退路。
    // 注意 pinnedPeerCertSha256 在 Xray 侧是**逗号分隔的字符串**，不是数组。
    if (!n.tls.pinned_cert_sha256.empty()) {
      tls["pinnedPeerCertSha256"] = n.tls.pinned_cert_sha256;
    } else if (!n.tls.fingerprint.empty()) {
      tls["pinnedPeerCertSha256"] = n.tls.fingerprint;
    } else if (n.tls.insecure && !sni.empty()) {
      tls["verifyPeerCertByName"] = sni;
    }
    if (!n.tls.alpn.empty()) tls["alpn"] = n.tls.alpn;
    if (!n.tls.client_fingerprint.empty()) tls["fingerprint"] = n.tls.client_fingerprint;
    stream["tlsSettings"] = std::move(tls);
  } else {
    stream["security"] = "none";
  }

  if (n.tfo || !dialer.empty()) {
    Json sockopt = Json::object();
    if (n.tfo) sockopt["tcpFastOpen"] = true;
    if (!dialer.empty()) sockopt["dialerProxy"] = dialer;
    stream["sockopt"] = std::move(sockopt);
  }
  return stream;
}

/// 返回 Null 表示该协议 Xray 不支持（已记录 warning）。
Json build_outbound(const ProxyNode& n, std::vector<std::string>& warnings,
                    const std::string& dialer = {}) {
  auto reject = [&](const char* why) {
    warnings.push_back(std::string("跳过节点 ") + n.name + "（" + to_string(n.protocol) +
                       "）：Xray " + why);
    return Json();
  };

  Json out = Json::object();
  out["tag"] = n.name;

  switch (n.protocol) {
    case Protocol::Vmess: {
      out["protocol"] = "vmess";
      Json user = Json::object();
      user["id"] = n.uuid;
      user["alterId"] = n.alter_id;
      user["security"] = n.cipher.empty() ? "auto" : n.cipher;
      user["level"] = 0;
      Json vnext = Json::object();
      vnext["address"] = n.server;
      vnext["port"] = n.port;
      vnext["users"] = Json::array({std::move(user)});
      out["settings"] = Json{{"vnext", Json::array({std::move(vnext)})}};
      out["streamSettings"] = build_stream_settings(n, dialer);
      out["mux"] = Json{{"enabled", false}, {"concurrency", 8}};
      break;
    }
    case Protocol::Vless: {
      out["protocol"] = "vless";
      Json user = Json::object();
      user["id"] = n.uuid;
      // Xray 的 encryption 不能留空：不加密要显式写 "none"；开了 VLESS Encryption 就得把
      // 那串 mlkem768x25519plus.… 原样写进去，否则服务端解不开 VLESS 头（静默黑洞）。
      user["encryption"] = n.encryption.empty() ? std::string("none") : n.encryption;
      if (!n.flow.empty()) user["flow"] = n.flow;
      user["level"] = 0;
      Json vnext = Json::object();
      vnext["address"] = n.server;
      vnext["port"] = n.port;
      vnext["users"] = Json::array({std::move(user)});
      out["settings"] = Json{{"vnext", Json::array({std::move(vnext)})}};
      out["streamSettings"] = build_stream_settings(n, dialer);
      out["mux"] = Json{{"enabled", false}, {"concurrency", 8}};
      break;
    }
    case Protocol::Trojan: {
      out["protocol"] = "trojan";
      Json server = Json::object();
      server["address"] = n.server;
      server["port"] = n.port;
      server["password"] = n.password;
      server["level"] = 0;
      out["settings"] = Json{{"servers", Json::array({std::move(server)})}};
      out["streamSettings"] = build_stream_settings(n, dialer);
      out["mux"] = Json{{"enabled", false}, {"concurrency", 8}};
      break;
    }
    case Protocol::Shadowsocks: {
      if (!is_aead_cipher(n.cipher)) {
        return reject("不支持该加密方式（仅支持 AEAD / 2022 系列）");
      }
      out["protocol"] = "shadowsocks";
      Json server = Json::object();
      server["address"] = n.server;
      server["port"] = n.port;
      server["method"] = n.cipher;
      server["password"] = n.password;
      server["uot"] = false;
      server["level"] = 0;
      out["settings"] = Json{{"servers", Json::array({std::move(server)})}};
      out["streamSettings"] = build_stream_settings(n, dialer);
      break;
    }
    case Protocol::Socks5: {
      out["protocol"] = "socks";
      Json server = Json::object();
      server["address"] = n.server;
      server["port"] = n.port;
      if (!n.username.empty()) {
        server["users"] = Json::array(
            {Json{{"user", n.username}, {"pass", n.password}, {"level", 0}}});
      }
      out["settings"] = Json{{"servers", Json::array({std::move(server)})}};
      // socks 出站平时不需要 streamSettings（没有传输层与安全层），但链路的 dialerProxy
      // 就住在 sockopt 里 —— 少了它这个节点会静默变成直连。
      if (!dialer.empty()) out["streamSettings"] = build_stream_settings(n, dialer);
      break;
    }
    case Protocol::Http: {
      out["protocol"] = "http";
      Json server = Json::object();
      server["address"] = n.server;
      server["port"] = n.port;
      if (!n.username.empty()) {
        server["users"] = Json::array(
            {Json{{"user", n.username}, {"pass", n.password}, {"level", 0}}});
      }
      out["settings"] = Json{{"servers", Json::array({std::move(server)})}};
      if (n.tls.enabled || !dialer.empty()) out["streamSettings"] = build_stream_settings(n, dialer);
      break;
    }
    case Protocol::WireGuard: {
      // Xray 的 wireguard 出站是 **complete 形态**：`settings` 里直接写 secretKey / address /
      // peers，字段名见 infra/conf/wireguard.go 的 WireGuardConfig / WireGuardPeerConfig。
      // 几处容易写错的点：
      //   * settings 里没有 server/port —— endpoint 是每个 peer 自己的字段（"host:port"）；
      //   * `address` 是**字符串数组**（IPv4 + IPv6）；
      //   * `reserved` 在 Xray 里是 []byte，JSON 里写 3 个十进制数最稳（base64 字符串它不认）；
      //   * 密钥 base64 / hex 都收，Xray 的 ParseWireGuardKey 两种都解析。
      const WireGuardOptions& wg = n.wireguard;
      if (wg.private_key.empty()) return reject("wireguard 缺少 private-key");
      if (wg.peers.empty()) return reject("wireguard 缺少 peers");

      Json settings = Json::object();
      settings["secretKey"] = wireguard_detail::pad_key_base64(wg.private_key);
      Json address = Json::array();
      if (!wg.ip.empty()) address.push_back(wg.ip);
      if (!wg.ipv6.empty()) address.push_back(wg.ipv6);
      if (address.empty()) {
        return reject("wireguard 缺少本地 address（ip / ipv6）");
      }
      settings["address"] = std::move(address);

      Json peers = Json::array();
      for (const auto& peer : wg.peers) {
        if (peer.public_key.empty()) return reject("wireguard 的 peer 缺少 public-key");
        Json entry = Json::object();
        entry["publicKey"] = wireguard_detail::pad_key_base64(peer.public_key);
        if (!peer.pre_shared_key.empty()) {
          entry["preSharedKey"] = wireguard_detail::pad_key_base64(peer.pre_shared_key);
        }
        if (!peer.server.empty() && peer.port != 0) {
          entry["endpoint"] = peer.server + ":" + std::to_string(peer.port);
        }
        if (peer.keepalive > 0) entry["keepAlive"] = peer.keepalive;
        std::vector<std::string> allowed = peer.allowed_ips;
        if (allowed.empty()) {
          // Xray 自己的默认值就是这两个（见 WireGuardPeerConfig.Build）
          allowed = {"0.0.0.0/0", "::/0"};
        }
        entry["allowedIPs"] = allowed;
        peers.push_back(std::move(entry));
      }
      settings["peers"] = std::move(peers);
      // reserved 是 WARP 专有字段：Xray 的 schema 里有（`reserved` []byte，只接受 3 字节），
      // 但实现侧没有用到它（v26.6.1 的 deviceConfig 没有把 reserved 传给底层），
      // 写进去只是"为将来留个记号"，所以放在最后 —— 解析器会忽略未知/未使用字段。
      for (const auto& peer : wg.peers) {
        if (peer.reserved.size() == 3) {
          settings["reserved"] = peer.reserved;
          break;
        }
      }
      if (wg.mtu > 0) settings["mtu"] = wg.mtu;
      if (!wg.dns.empty()) settings["remoteDNS"] = wg.dns;

      out["protocol"] = "wireguard";
      out["settings"] = std::move(settings);
      // wireguard 出站没有传输层概念，安全层显式写 none；mux 对它也无意义，
      // 但 Xray 的默认 mux 配置会拖慢建连，统一按其它节点写成关闭。
      // 链路照样写进 sockopt：字段本身 Xray 收，但 dialerProxy 是 TCP 隧道而 WG 到
      // endpoint 走的是 UDP，链上大概率连不通 —— 这一条由 chain_exit_caveat 明确告警。
      Json wg_stream = Json::object();
      wg_stream["security"] = "none";
      if (!dialer.empty()) wg_stream["sockopt"] = Json{{"dialerProxy", dialer}};
      out["streamSettings"] = std::move(wg_stream);
      out["mux"] = Json{{"enabled", false}, {"concurrency", 8}};
      break;
    }
    default:
      return reject("不支持该协议");
  }
  return out;
}

}  // namespace

Result<std::string> emit_xray(const NodeList& nodes, const EmitOptions& opts,
                              std::vector<std::string>* warnings) {
  const NodeList prepared = prepare_nodes(nodes, opts);
  if (prepared.empty()) return fail("去重后没有可输出的节点");

  // 链式代理：先解析链路，再决定每个出站的 dialerProxy。
  // 链路是用户显式指定的基础设施 —— 任何一跳写不出来就直接报错，绝不静默降级成直连
  // （那会把所有流量按真实 IP 放出去，是这个工具最不能出的错）。
  auto plan = resolve_chain(prepared, opts, warnings);
  if (!plan) return fail(plan.error());
  const std::map<std::string, std::string> ref_index = build_dialer_index(prepared);
  // 输入自带引用成环时先拦下来：内核不一定拒绝这种配置（实测 Xray 26 对 A→B→A 报
  // Configuration OK），真连上去才会死循环 / 超时。
  if (!plan->active()) {
    if (const auto cycle = dialer_cycle(prepared, ref_index); !cycle.empty()) {
      return fail("输入配置的链式代理成环：" + codec::join(cycle, " -> ") +
                  "（dialerProxy 首尾相接会死循环，无法转换）");
    }
  }

  std::vector<std::string> skipped;
  std::vector<std::string> chain_caveats;
  Json outbounds = Json::array();
  Json node_tags = Json::array();
  std::size_t need_pin = 0;

  // 外部链路跳点排在最前面：读起来就是「本地 → 跳1 → 跳2 → … → 每个节点」。
  // 引用订阅节点的跳点（extra=false）不重复产出，直接复用节点自己那条出站。
  std::set<std::string> hop_names;
  for (const auto& hop : plan->hops) {
    hop_names.insert(hop.tag);
    if (!hop.extra) continue;
    std::vector<std::string> hop_warnings;
    Json out = build_outbound(hop.node, hop_warnings, hop.dialer);
    if (out.is_null()) {
      return fail("链路节点 " + hop.node.name + " 无法写进 Xray 配置：" +
                  (hop_warnings.empty() ? std::string("不支持该协议")
                                        : codec::join(hop_warnings, "；")));
    }
    for (auto& w : hop_warnings) skipped.push_back(std::move(w));
    // 链路中间那一跳本身也要经上一跳出去 —— 它走 UDP 的话同样链不通，必须一起告警。
    if (!hop.dialer.empty()) {
      const std::string caveat = chain_exit_caveat(hop.node);
      if (!caveat.empty()) chain_caveats.push_back(caveat);
    }
    outbounds.push_back(std::move(out));
  }

  for (const auto& node : prepared) {
    const std::string dialer = effective_dialer(node, *plan, ref_index, warnings);
    // 有后置链路时，这个节点自己变成链路里的中间跳点，流量落点是后置链路的末端
    // （末端出站的名字里带着「节点 → 后置」，客户端里选中它才是走链路的路径）。
    const RearChain* rear = plan->rear_for(node.name);
    std::vector<std::string> node_warnings;
    Json out = build_outbound(node, node_warnings, dialer);
    if (out.is_null()) {
      if (rear != nullptr || hop_names.count(node.name) != 0) {
        return fail("链路节点 " + node.name + " 无法写进 Xray 配置：" +
                    (node_warnings.empty() ? std::string("不支持该协议")
                                           : codec::join(node_warnings, "；")) +
                    "（链路是显式指定的，不能静默降级成直连）");
      }
      for (auto& w : node_warnings) skipped.push_back(std::move(w));
      continue;
    }
    // 成功产出时也可能带告警 —— 必须在成功分支一并收下，别让提示消失。
    for (auto& w : node_warnings) skipped.push_back(std::move(w));
    if (!dialer.empty()) {
      const std::string caveat = chain_exit_caveat(node);
      if (!caveat.empty()) chain_caveats.push_back(caveat);
    }
    if (node.tls.insecure && !node.tls.reality && node.tls.pinned_cert_sha256.empty() &&
        node.is_tls()) {
      ++need_pin;
    }

    if (rear != nullptr) {
      // 后置链路：逐跳产出，hops.back() 才是流量落点。
      // 每一跳都是经上一跳的 TCP 隧道到达的，所以每一跳都要过 UDP 兼容性检查。
      for (const auto& hop : rear->hops) {
        const std::string caveat = chain_exit_caveat(hop.node);
        if (!caveat.empty()) chain_caveats.push_back(caveat);
        std::vector<std::string> hop_warnings;
        Json hout = build_outbound(hop.node, hop_warnings, hop.dialer);
        if (hout.is_null()) {
          return fail("后置链路节点 " + hop.node.name + " 无法写进 Xray 配置：" +
                      (hop_warnings.empty() ? std::string("不支持该协议")
                                            : codec::join(hop_warnings, "；")) +
                      "（链路是显式指定的，不能静默降级成直连）");
        }
        for (auto& w : hop_warnings) skipped.push_back(std::move(w));
        outbounds.push_back(std::move(hout));
      }
      node_tags.push_back(rear->target());
    } else {
      node_tags.push_back(node.name);
    }
    outbounds.push_back(std::move(out));
  }
  if (warnings != nullptr) {
    for (const auto& w : skipped) warnings->push_back(w);
    if (!chain_caveats.empty()) {
      warnings->push_back("链路上这些节点的传输本身就依赖 UDP（" +
                          codec::join(chain_caveats, "、") +
                          "）：dialerProxy 是按 TCP 建的隧道，链上大概率连不通，建议避开这些节点");
    }
    if (need_pin > 0) {
      warnings->push_back(
          "有 " + std::to_string(need_pin) +
          " 个节点要求跳过证书校验但没有证书指纹：Xray 25+ 已移除 allowInsecure，这里只能退回 "
          "verifyPeerCertByName（仍要求证书链可信且名字匹配，机场节点几乎都对不上，"
          "客户端会表现为全部 -1）→ 加 --probe-cert 探测对端证书指纹即可放行");
    }
  }
  if (node_tags.empty()) {
    const std::string detail =
        skipped.empty() ? std::string() : ("\n  - " + codec::join(skipped, "\n  - "));
    return fail("没有任何节点能转换为 Xray 配置" + detail);
  }

  outbounds.push_back(Json{{"tag", "direct"}, {"protocol", "freedom"}});
  outbounds.push_back(Json{{"tag", "block"}, {"protocol", "blackhole"}});

  // --- 路由：DNS 拦截 + 私网直连 + 其余走自动测速负载均衡 ---
  Json rules = Json::array();
  rules.push_back(Json{{"type", "field"}, {"port", "53"}, {"outboundTag", "block"}});
  rules.push_back(
      Json{{"type", "field"}, {"domain", Json::array({"localhost"})}, {"outboundTag", "direct"}});
  rules.push_back(Json{{"type", "field"},
                       {"ip", Json::array({"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
                                           "192.168.0.0/16", "::1/128", "fc00::/7",
                                           "fe80::/10"})},
                       {"outboundTag", "direct"}});
  rules.push_back(
      Json{{"type", "field"}, {"network", "tcp,udp"}, {"balancerTag", "auto"}});

  const std::string first_tag = node_tags.empty() ? "direct" : node_tags[0].get<std::string>();
  Json observatory = Json::object();
  observatory["subjectSelector"] = node_tags;
  observatory["probeURL"] = kTestUrl;
  observatory["probeInterval"] = "300s";
  observatory["enableConcurrency"] = true;

  Json routing = Json::object();
  routing["domainStrategy"] = "IPIfNonMatch";
  routing["balancers"] = Json::array({Json{{"tag", "auto"},
                                           {"selector", node_tags},
                                           {"strategy", Json{{"type", "leastPing"}}},
                                           {"fallbackTag", first_tag}}});
  routing["rules"] = std::move(rules);

  Json config = Json::object();
  config["log"] = Json{{"loglevel", "warning"}, {"error", ""}};
  config["inbounds"] = Json::array({
      Json{{"tag", "socks-in"},
           {"listen", "127.0.0.1"},
           {"port", 10808},
           {"protocol", "socks"},
           {"settings", Json{{"auth", "noauth"}, {"udp", true}, {"userLevel", 0}}},
           {"sniffing", Json{{"enabled", true}, {"destOverride", Json::array({"http", "tls"})}}}},
      Json{{"tag", "http-in"},
           {"listen", "127.0.0.1"},
           {"port", 10809},
           {"protocol", "http"},
           {"settings", Json{{"userLevel", 0}}},
           {"sniffing", Json{{"enabled", true}, {"destOverride", Json::array({"http", "tls"})}}}},
  });
  config["outbounds"] = std::move(outbounds);
  config["observatory"] = std::move(observatory);
  config["routing"] = std::move(routing);

  return config.dump(2) + "\n";
}

}  // namespace subconv
