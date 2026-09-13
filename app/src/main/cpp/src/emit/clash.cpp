// Clash / mihomo (Clash.Meta) YAML 输出
//
// 目标内核：mihomo（Clash.Meta 系，含 vless / hysteria2 / tuic / reality）。
// `--clash-legacy` 会跳过 mihomo 专有字段，并拒绝 meta 独有协议，以便原版 Clash 加载。
#include <string>
#include <vector>

#include "emit_internal.hpp"
#include "subconv/codec.hpp"
#include "subconv/convert.hpp"
#include "subconv/yaml.hpp"

namespace subconv {
namespace {

constexpr const char* kTestUrl = "http://www.gstatic.com/generate_204";

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------
std::string clash_plugin_name(const SsPlugin& p) {
  const std::string name = codec::to_lower(p.name);
  if (name == "obfs-local" || name == "obfs" || name == "simple-obfs") return "obfs";
  if (name == "v2ray-plugin") return "v2ray-plugin";
  return p.name;
}

const char* clash_network(Network n) {
  switch (n) {
    case Network::Ws: return "ws";
    case Network::Grpc: return "grpc";
    case Network::H2: return "h2";
    case Network::Http: return "http";
    case Network::Quic: return "quic";
    case Network::Kcp: return "kcp";
    case Network::Xhttp: return "xhttp";
    case Network::Tcp: return "tcp";
  }
  return "tcp";
}

/// 把 "100" 规范成 "100 Mbps"；带单位或空串则原样返回。
std::string bandwidth(const std::string& v) {
  if (v.empty()) return v;
  for (const char c : v) {
    if (!(c >= '0' && c <= '9') && c != '.') return v;  // 已带单位
  }
  if (v == "0") return {};
  return v + " Mbps";
}

std::string fetch_extra(const ProxyNode& n, const char* key) {
  const auto it = n.extra.find(key);
  return it == n.extra.end() ? std::string() : it->second;
}

Yaml string_list(const std::vector<std::string>& items) {
  Yaml seq = Yaml::sequence();
  for (const auto& item : items) seq.push(Yaml::scalar(item));
  return seq;
}

// ---------------------------------------------------------------------------
// 参数块
// ---------------------------------------------------------------------------
/// TLS 字段在不同协议下的键名并不一致，这里按内核实际 schema 分派。
enum class TlsStyle {
  VmessVless,  ///< tls / servername / reality-opts / client-fingerprint
  Trojan,      ///< tls / sni / alpn / client-fingerprint
  Hysteria2,   ///< sni / skip-cert-verify / alpn / fingerprint(cert pin)
  Tuic,        ///< sni / skip-cert-verify / alpn / disable-sni
  Hysteria1,   ///< sni / skip-cert-verify / alpn
};

void add_tls(Yaml& y, const ProxyNode& n, TlsStyle style, bool legacy) {
  const bool force_tls = style == TlsStyle::Trojan || style == TlsStyle::Hysteria2 ||
                         style == TlsStyle::Tuic || style == TlsStyle::Hysteria1;
  if (!n.tls.enabled && !force_tls) return;

  if (style == TlsStyle::VmessVless || style == TlsStyle::Trojan) {
    y.set("tls", Yaml::boolean(true));
  }

  const std::string sni = n.tls.sni.empty() ? n.server : n.tls.sni;
  if (!sni.empty() && !n.tls.disable_sni) {
    y.set(style == TlsStyle::VmessVless ? "servername" : "sni", Yaml::scalar(sni));
  }
  if (n.tls.insecure) y.set("skip-cert-verify", Yaml::boolean(true));
  if (!n.tls.alpn.empty()) y.set("alpn", string_list(n.tls.alpn));

  if (!legacy) {
    if (!n.tls.client_fingerprint.empty() &&
        (style == TlsStyle::VmessVless || style == TlsStyle::Trojan)) {
      y.set("client-fingerprint", Yaml::scalar(n.tls.client_fingerprint));
    }
    if (!n.tls.fingerprint.empty() && style == TlsStyle::Hysteria2) {
      y.set("fingerprint", Yaml::scalar(n.tls.fingerprint));
    }
    if (n.tls.reality && style == TlsStyle::VmessVless) {
      Yaml reality = Yaml::mapping();
      if (!n.tls.reality_public_key.empty()) {
        reality.set("public-key", Yaml::scalar(n.tls.reality_public_key));
      }
      if (!n.tls.reality_short_id.empty()) {
        reality.set("short-id", Yaml::scalar(n.tls.reality_short_id));
      }
      if (!reality.empty()) y.set("reality-opts", std::move(reality));
    }
    if (n.tls.disable_sni && style == TlsStyle::Tuic) {
      y.set("disable-sni", Yaml::boolean(true));
    }
  }
}

void add_transport(Yaml& y, const ProxyNode& n) {
  if (n.network == Network::Tcp) return;
  y.set("network", Yaml::scalar(clash_network(n.network)));

  switch (n.network) {
    case Network::Ws: {
      Yaml ws = Yaml::mapping();
      if (!n.ws.path.empty()) ws.set("path", Yaml::scalar(n.ws.path));
      Yaml headers = Yaml::mapping();
      if (!n.ws.host.empty()) headers.set("Host", Yaml::scalar(n.ws.host));
      for (const auto& [key, value] : n.ws.headers) headers.set(key, Yaml::scalar(value));
      if (!headers.empty()) ws.set("headers", std::move(headers));
      if (n.ws.max_early_data.has_value()) {
        ws.set("max-early-data", Yaml::integer(*n.ws.max_early_data));
      }
      if (!n.ws.early_data_header.empty()) {
        ws.set("early-data-header-name", Yaml::scalar(n.ws.early_data_header));
      }
      if (!ws.empty()) y.set("ws-opts", std::move(ws));
      break;
    }
    case Network::Grpc: {
      Yaml grpc = Yaml::mapping();
      if (!n.grpc.service_name.empty()) {
        grpc.set("grpc-service-name", Yaml::scalar(n.grpc.service_name));
      }
      if (n.grpc.multi_mode) grpc.set("grpc-mode", Yaml::scalar("multi"));
      if (!grpc.empty()) y.set("grpc-opts", std::move(grpc));
      break;
    }
    case Network::H2: {
      Yaml h2 = Yaml::mapping();
      if (!n.h2.host.empty()) h2.set("host", string_list(n.h2.host));
      if (!n.h2.path.empty()) h2.set("path", Yaml::scalar(n.h2.path));
      if (!h2.empty()) y.set("h2-opts", std::move(h2));
      break;
    }
    case Network::Http: {
      Yaml http = Yaml::mapping();
      http.set("method", Yaml::scalar("GET"));
      Yaml paths = Yaml::sequence();
      paths.push(Yaml::scalar(n.h2.path.empty() ? "/" : n.h2.path));
      http.set("path", std::move(paths));
      if (!n.h2.host.empty()) {
        Yaml headers = Yaml::mapping();
        headers.set("Host", string_list(n.h2.host));
        http.set("headers", std::move(headers));
      }
      y.set("http-opts", std::move(http));
      break;
    }
    case Network::Xhttp: {
      // mihomo 的 xhttp-opts 是扁平映射：xhttp 自身字段与 download-settings
      // 下的「代理字段」混在一起，字段名照 transport/xhttp + adapter/outbound/vless.go 抄。
      Yaml xhttp = Yaml::mapping();
      if (!n.xhttp.path.empty()) xhttp.set("path", Yaml::scalar(n.xhttp.path));
      if (!n.xhttp.host.empty()) xhttp.set("host", Yaml::scalar(n.xhttp.host));
      if (!n.xhttp.mode.empty() && xhttp_mode_supported(n.xhttp.mode)) {
        xhttp.set("mode", Yaml::scalar(n.xhttp.mode));
      }
      if (!n.xhttp.headers.empty()) {
        Yaml headers = Yaml::mapping();
        for (const auto& [key, value] : n.xhttp.headers) {
          headers.set(key, Yaml::scalar(value));
        }
        xhttp.set("headers", std::move(headers));
      }
      if (n.xhttp.download.present) {
        const XhttpDownloadOptions& d = n.xhttp.download;
        Yaml ds = Yaml::mapping();
        if (!d.path.empty()) ds.set("path", Yaml::scalar(d.path));
        if (!d.host.empty()) ds.set("host", Yaml::scalar(d.host));
        if (!d.server.empty()) ds.set("server", Yaml::scalar(d.server));
        if (d.port.has_value()) ds.set("port", Yaml::integer(*d.port));
        if (!d.sni.empty()) ds.set("servername", Yaml::scalar(d.sni));
        // tls / skip-cert-verify 留空即「沿用主节点」，不要替内核补默认值
        if (d.tls.has_value()) ds.set("tls", Yaml::boolean(*d.tls));
        if (d.insecure.has_value()) ds.set("skip-cert-verify", Yaml::boolean(*d.insecure));
        if (!ds.empty()) xhttp.set("download-settings", std::move(ds));
      }
      if (!xhttp.empty()) y.set("xhttp-opts", std::move(xhttp));
      break;
    }
    default:
      break;
  }
}

// ---------------------------------------------------------------------------
// 单节点
// ---------------------------------------------------------------------------
/// 返回 Null 表示该节点无法转换（已记录 warning）。
Yaml build_proxy(const ProxyNode& n, const EmitOptions& opts,
                 std::vector<std::string>& warnings) {
  const bool legacy = opts.clash_legacy;

  auto reject = [&](const char* reason) {
    warnings.push_back(std::string("跳过节点 ") + n.name + "（" + to_string(n.protocol) +
                       "）：" + reason);
    return Yaml();
  };

  // xhttp 在 mihomo 里只挂在 vless 出站上（transport/xhttp 仅被 adapter/outbound/vless.go
  // 引用；vmess/trojan 的 StreamConnContext 都没有这个 case），别产出内核加载不了的节点。
  if (n.network == Network::Xhttp) {
    if (legacy) return reject("原版 Clash 不支持 xhttp 传输");
    if (n.protocol != Protocol::Vless) return reject("mihomo 的 xhttp 传输只支持 vless 出站");
    if (xhttp_extra_has_untranslatable(n)) {
      warnings.push_back("节点 " + n.name +
                         "（vless）：xhttp 的 extra 里有 mihomo 表达不了的键，只保留了 download-settings；"
                         "要完整保留请用 -t xray 或 -t links");
    }
  }

  Yaml y = Yaml::mapping();
  y.set("name", Yaml::scalar(n.name));
  y.set("type", Yaml::scalar(clash_type(n.protocol)));
  y.set("server", Yaml::scalar(n.server));
  y.set("port", Yaml::integer(n.port));

  switch (n.protocol) {
    // ---------------------------------------------------------------- ss
    case Protocol::Shadowsocks: {
      y.set("cipher", Yaml::scalar(n.cipher));
      y.set("password", Yaml::scalar(n.password));
      if (opts.udp && n.udp) y.set("udp", Yaml::boolean(true));
      if (n.plugin.present) {
        const std::string pname = clash_plugin_name(n.plugin);
        y.set("plugin", Yaml::scalar(pname));
        Yaml plugin_opts = Yaml::mapping();
        if (pname == "obfs") {
          plugin_opts.set(
              "mode", Yaml::scalar(n.plugin.obfs_mode.empty() ? "http" : n.plugin.obfs_mode));
          if (!n.plugin.obfs_host.empty()) {
            plugin_opts.set("host", Yaml::scalar(n.plugin.obfs_host));
          }
        } else if (pname == "v2ray-plugin") {
          plugin_opts.set("mode",
                          Yaml::scalar(n.plugin.mode.empty() ? "websocket" : n.plugin.mode));
          if (!n.plugin.host.empty()) plugin_opts.set("host", Yaml::scalar(n.plugin.host));
          if (!n.plugin.path.empty()) plugin_opts.set("path", Yaml::scalar(n.plugin.path));
          if (n.plugin.tls) plugin_opts.set("tls", Yaml::boolean(true));
        }
        if (!plugin_opts.empty()) y.set("plugin-opts", std::move(plugin_opts));
      }
      break;
    }

    // --------------------------------------------------------------- ssr
    case Protocol::ShadowsocksR: {
      if (legacy) return reject("原版 Clash 不支持 ssr");
      y.set("cipher", Yaml::scalar(n.cipher));
      y.set("password", Yaml::scalar(n.password));
      y.set("protocol", Yaml::scalar(n.ssr_protocol.empty() ? "origin" : n.ssr_protocol));
      y.set("obfs", Yaml::scalar(n.ssr_obfs.empty() ? "plain" : n.ssr_obfs));
      if (!n.ssr_protocol_param.empty()) {
        y.set("protocol-param", Yaml::scalar(n.ssr_protocol_param));
      }
      if (!n.ssr_obfs_param.empty()) y.set("obfs-param", Yaml::scalar(n.ssr_obfs_param));
      if (opts.udp && n.udp) y.set("udp", Yaml::boolean(true));
      break;
    }

    // ------------------------------------------------------------- vmess
    case Protocol::Vmess: {
      y.set("uuid", Yaml::scalar(n.uuid));
      y.set("alterId", Yaml::integer(n.alter_id));
      y.set("cipher", Yaml::scalar(n.cipher.empty() ? "auto" : n.cipher));
      if (opts.udp && n.udp) y.set("udp", Yaml::boolean(true));
      add_transport(y, n);
      add_tls(y, n, TlsStyle::VmessVless, legacy);
      if (!legacy && !n.packet_encoding.empty()) {
        y.set("packet-encoding", Yaml::scalar(n.packet_encoding));
      }
      break;
    }

    // -------------------------------------------------------------- vless
    case Protocol::Vless: {
      if (legacy) return reject("原版 Clash 不支持 vless");
      y.set("uuid", Yaml::scalar(n.uuid));
      if (opts.udp && n.udp) y.set("udp", Yaml::boolean(true));
      if (!n.flow.empty()) y.set("flow", Yaml::scalar(n.flow));
      add_transport(y, n);
      add_tls(y, n, TlsStyle::VmessVless, legacy);
      if (!n.packet_encoding.empty()) {
        y.set("packet-encoding", Yaml::scalar(n.packet_encoding));
      }
      break;
    }

    // ------------------------------------------------------------- trojan
    case Protocol::Trojan: {
      y.set("password", Yaml::scalar(n.password));
      if (opts.udp && n.udp) y.set("udp", Yaml::boolean(true));
      add_transport(y, n);
      add_tls(y, n, TlsStyle::Trojan, legacy);
      break;
    }

    // ----------------------------------------------------------- hysteria
    case Protocol::Hysteria: {
      if (legacy) return reject("原版 Clash 不支持 hysteria");
      if (!n.password.empty()) y.set("auth-str", Yaml::scalar(n.password));
      const std::string up = bandwidth(n.up);
      const std::string down = bandwidth(n.down);
      if (!up.empty()) y.set("up", Yaml::scalar(up));
      if (!down.empty()) y.set("down", Yaml::scalar(down));
      if (!n.obfs.empty()) y.set("obfs", Yaml::scalar(n.obfs));
      const std::string protocol = fetch_extra(n, "protocol");
      if (!protocol.empty()) y.set("protocol", Yaml::scalar(protocol));
      add_tls(y, n, TlsStyle::Hysteria1, legacy);
      break;
    }

    // ---------------------------------------------------------- hysteria2
    case Protocol::Hysteria2: {
      if (legacy) return reject("原版 Clash 不支持 hysteria2");
      y.set("password", Yaml::scalar(n.password));
      const std::string up = bandwidth(n.up);
      const std::string down = bandwidth(n.down);
      if (!up.empty()) y.set("up", Yaml::scalar(up));
      if (!down.empty()) y.set("down", Yaml::scalar(down));
      if (!n.obfs.empty()) {
        y.set("obfs", Yaml::scalar(n.obfs));
        if (!n.obfs_password.empty()) {
          y.set("obfs-password", Yaml::scalar(n.obfs_password));
        }
      }
      const std::string ports = fetch_extra(n, "ports");
      if (!ports.empty()) y.set("ports", Yaml::scalar(ports));
      add_tls(y, n, TlsStyle::Hysteria2, legacy);
      break;
    }

    // --------------------------------------------------------------- tuic
    case Protocol::Tuic: {
      if (legacy) return reject("原版 Clash 不支持 tuic");
      if (!n.uuid.empty()) y.set("uuid", Yaml::scalar(n.uuid));
      if (!n.password.empty()) y.set("password", Yaml::scalar(n.password));
      if (!n.congestion_control.empty()) {
        y.set("congestion-controller", Yaml::scalar(n.congestion_control));
      }
      if (!n.udp_relay_mode.empty()) {
        y.set("udp-relay-mode", Yaml::scalar(n.udp_relay_mode));
      }
      add_tls(y, n, TlsStyle::Tuic, legacy);
      break;
    }

    // -------------------------------------------------------------- snell
    case Protocol::Snell: {
      if (legacy) return reject("原版 Clash 不支持 snell");
      y.set("psk", Yaml::scalar(n.password));
      y.set("version", Yaml::integer(n.version == 0 ? 3 : n.version));
      if (!n.obfs.empty()) {
        Yaml obfs = Yaml::mapping();
        obfs.set("mode", Yaml::scalar(n.obfs));
        if (!n.obfs_password.empty()) obfs.set("host", Yaml::scalar(n.obfs_password));
        y.set("obfs-opts", std::move(obfs));
      }
      break;
    }

    // ------------------------------------------------------------- socks5
    case Protocol::Socks5: {
      if (!n.username.empty()) y.set("username", Yaml::scalar(n.username));
      if (!n.password.empty()) y.set("password", Yaml::scalar(n.password));
      if (opts.udp && n.udp) y.set("udp", Yaml::boolean(true));
      break;
    }

    // --------------------------------------------------------------- http
    case Protocol::Http: {
      if (!n.username.empty()) y.set("username", Yaml::scalar(n.username));
      if (!n.password.empty()) y.set("password", Yaml::scalar(n.password));
      if (n.tls.enabled) {
        y.set("tls", Yaml::boolean(true));
        if (n.tls.insecure) y.set("skip-cert-verify", Yaml::boolean(true));
        const std::string sni = n.tls.sni.empty() ? n.server : n.tls.sni;
        if (!sni.empty()) y.set("sni", Yaml::scalar(sni));
      }
      break;
    }

    default:
      return reject("该协议尚未支持输出到 clash");
  }

  if (n.tfo) y.set("tfo", Yaml::boolean(true));
  return y;
}

}  // namespace

Result<std::string> emit_clash(const NodeList& nodes, const EmitOptions& opts,
                               std::vector<std::string>* warnings) {
  const NodeList prepared = prepare_nodes(nodes, opts);
  if (prepared.empty()) return fail("去重后没有可输出的节点");

  // 被跳过的节点：既写成配置文件里的注释，也交给调用方（CLI 打到 stderr / Web UI 显示），
  // 与 links / base64 目标保持一致的告知方式
  std::vector<std::string> skipped;
  Yaml proxies = Yaml::sequence();
  for (const auto& node : prepared) {
    Yaml proxy = build_proxy(node, opts, skipped);
    if (!proxy.is_null()) proxies.push(std::move(proxy));
  }
  if (warnings != nullptr) {
    for (const auto& w : skipped) warnings->push_back(w);
  }
  if (proxies.empty()) {
    const std::string detail =
        skipped.empty() ? std::string() : ("：\n  - " + codec::join(skipped, "\n  - "));
    return fail("没有任何节点能转换为 clash 格式" + detail);
  }

  const std::string g_select = opts.emoji ? "🚀 节点选择" : "节点选择";
  const std::string g_auto = opts.emoji ? "♻️ 自动选择" : "自动选择";
  const std::string g_final = opts.emoji ? "🐟 漏网之鱼" : "漏网之鱼";

  Yaml all_names = Yaml::sequence();
  for (const auto& proxy : proxies.items()) {
    const Yaml* name = proxy.get("name");
    all_names.push(Yaml::scalar(name != nullptr ? name->as_string() : std::string()));
  }

  // --- proxy-groups ---
  Yaml groups = Yaml::sequence();

  Yaml select = Yaml::mapping();
  select.set("name", Yaml::scalar(g_select));
  select.set("type", Yaml::scalar("select"));
  {
    Yaml list = Yaml::sequence();
    list.push(Yaml::scalar(g_auto));
    list.push(Yaml::scalar("DIRECT"));
    for (const auto& name : all_names.items()) list.push(Yaml::scalar(name.as_string()));
    select.set("proxies", std::move(list));
  }
  groups.push(std::move(select));

  Yaml auto_group = Yaml::mapping();
  auto_group.set("name", Yaml::scalar(g_auto));
  auto_group.set("type", Yaml::scalar("url-test"));
  auto_group.set("url", Yaml::scalar(kTestUrl));
  auto_group.set("interval", Yaml::integer(300));
  auto_group.set("tolerance", Yaml::integer(50));
  auto_group.set("proxies", all_names);
  groups.push(std::move(auto_group));

  Yaml final_group = Yaml::mapping();
  final_group.set("name", Yaml::scalar(g_final));
  final_group.set("type", Yaml::scalar("select"));
  {
    Yaml list = Yaml::sequence();
    list.push(Yaml::scalar(g_select));
    list.push(Yaml::scalar(g_auto));
    list.push(Yaml::scalar("DIRECT"));
    final_group.set("proxies", std::move(list));
  }
  groups.push(std::move(final_group));

  // --- rules ---
  Yaml rules = Yaml::sequence();
  if (opts.include_rules) {
    for (const auto& line : build_clash_rules(opts.rule_sets, g_final, warnings)) {
      rules.push(Yaml::scalar(line));
    }
  }

  // --- 组装 ---
  Yaml root = Yaml::mapping();
  root.set("mixed-port", Yaml::integer(7890));
  root.set("allow-lan", Yaml::boolean(false));
  root.set("mode", Yaml::scalar("rule"));
  root.set("log-level", Yaml::scalar("info"));
  root.set("ipv6", Yaml::boolean(opts.ipv6));
  root.set("external-controller", Yaml::scalar("127.0.0.1:9090"));

  Yaml dns = Yaml::mapping();
  dns.set("enable", Yaml::boolean(true));
  dns.set("ipv6", Yaml::boolean(opts.ipv6));
  dns.set("enhanced-mode", Yaml::scalar("redir-host"));
  {
    // nameserver 由选中的 DNS 预设 / 字面地址展开（见 src/emit/dns.cpp）
    const std::vector<std::string> servers = resolve_nameservers(opts.dns, opts.ipv6, warnings);
    if (!servers.empty()) {
      Yaml ns = Yaml::sequence();
      for (const auto& server : servers) ns.push(Yaml::scalar(server));
      dns.set("nameserver", std::move(ns));
    }
  }
  root.set("dns", std::move(dns));

  root.set("proxies", std::move(proxies));
  root.set("proxy-groups", std::move(groups));
  if (opts.include_rules) root.set("rules", std::move(rules));

  std::string out = config_header("clash", prepared.size(), opts.filename);
  if (!skipped.empty()) {
    out += "# 告警: " + std::to_string(skipped.size()) + " 个节点被跳过\n";
    for (const auto& w : skipped) out += "#   " + w + "\n";
  }
  out += root.dump();
  return out;
}

}  // namespace subconv
