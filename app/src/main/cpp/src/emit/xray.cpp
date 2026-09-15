// Xray / V2Ray JSON 输出
//
// Xray 的能力边界与 Clash / sing-box 不同，必须显式区分：
//   支持：ss(AEAD/2022) / vmess / vless / trojan / socks / http
//   不支持：ssr / snell / hysteria / hysteria2 / tuic（这些由 mihomo / sing-box 承载）
#include <string>
#include <vector>

#include "emit_internal.hpp"
#include "subconv/codec.hpp"
#include "subconv/convert.hpp"
#include "subconv/json.hpp"

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

Json build_stream_settings(const ProxyNode& n) {
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

  if (n.tfo) stream["sockopt"] = Json{{"tcpFastOpen", true}};
  return stream;
}

/// 返回 Null 表示该协议 Xray 不支持（已记录 warning）。
Json build_outbound(const ProxyNode& n, std::vector<std::string>& warnings) {
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
      out["streamSettings"] = build_stream_settings(n);
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
      out["streamSettings"] = build_stream_settings(n);
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
      out["streamSettings"] = build_stream_settings(n);
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
      out["streamSettings"] = build_stream_settings(n);
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
      if (n.tls.enabled) out["streamSettings"] = build_stream_settings(n);
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

  std::vector<std::string> skipped;
  Json outbounds = Json::array();
  Json node_tags = Json::array();
  std::size_t need_pin = 0;
  for (const auto& node : prepared) {
    Json out = build_outbound(node, skipped);
    if (out.is_null()) continue;
    if (node.tls.insecure && !node.tls.reality && node.tls.pinned_cert_sha256.empty() &&
        node.is_tls()) {
      ++need_pin;
    }
    node_tags.push_back(node.name);
    outbounds.push_back(std::move(out));
  }
  if (warnings != nullptr) {
    for (const auto& w : skipped) warnings->push_back(w);
    if (need_pin > 0) {
      warnings->push_back(
          "有 " + std::to_string(need_pin) +
          " 个节点要求跳过证书校验但没有证书指纹：Xray 25+ 已移除 allowInsecure，这里只能退回 "
          "verifyPeerCertByName（仍要求证书链可信且名字匹配，机场节点几乎都对不上，"
          "客户端会表现为全部 -1）→ 加 --probe-cert 探测对端证书指纹即可放行");
    }
  }
  if (outbounds.empty()) {
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
