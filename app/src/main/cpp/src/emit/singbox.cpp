// sing-box JSON 输出
//
// 能力边界：支持 ss / vmess / vless / trojan / hysteria / hysteria2 / tuic / socks / http；
// 不支持 ssr / snell（sing-box 已移除，交给 mihomo）。
#include <string>
#include <vector>

#include "emit_internal.hpp"
#include "subconv/codec.hpp"
#include "subconv/convert.hpp"
#include "subconv/json.hpp"

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

Json build_outbound(const ProxyNode& n, std::vector<std::string>& warnings) {
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

}  // namespace

Result<std::string> emit_singbox(const NodeList& nodes, const EmitOptions& opts,
                                 std::vector<std::string>* warnings) {
  const NodeList prepared = prepare_nodes(nodes, opts);
  if (prepared.empty()) return fail("去重后没有可输出的节点");

  std::vector<std::string> skipped;
  Json node_outbounds = Json::array();
  Json node_tags = Json::array();
  for (const auto& node : prepared) {
    Json out = build_outbound(node, skipped);
    if (out.is_null()) continue;
    node_tags.push_back(node.name);
    node_outbounds.push_back(std::move(out));
  }
  if (warnings != nullptr) {
    for (const auto& w : skipped) warnings->push_back(w);
  }
  if (node_outbounds.empty()) {
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
  for (auto& out : node_outbounds) outbounds.push_back(std::move(out));
  outbounds.push_back(Json{{"type", "direct"}, {"tag", "direct"}});
  outbounds.push_back(Json{{"type", "block"}, {"tag", "block"}});

  Json config = Json::object();
  config["log"] = Json{{"level", "warn"}, {"timestamp", true}};
  config["inbounds"] = Json::array({Json{{"type", "mixed"},
                                         {"tag", "mixed-in"},
                                         {"listen", "127.0.0.1"},
                                         {"listen_port", 2080}}});
  config["outbounds"] = std::move(outbounds);
  config["route"] = Json{{"final", g_select}, {"auto_detect_interface", true}};

  return config.dump(2) + "\n";
}

}  // namespace subconv
