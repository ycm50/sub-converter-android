// 解析总入口：协议分发 + 订阅内容归一化
#include "subconv/codec.hpp"
#include "subconv/convert.hpp"
#include "subconv/fetch.hpp"
#include "subconv/wireguard.hpp"
#include "parsers.hpp"

namespace subconv {
namespace {

std::string preview(std::string_view s, std::size_t limit = 48) {
  if (s.size() <= limit) return std::string(s);
  return std::string(s.substr(0, limit)) + "...";
}

/// 是否是 WireGuard 的 .conf 文本（只看第一段是不是 [Interface]）。
/// 用来把「整体 Base64 包裹的 wg 配置」与「订阅里直接贴的 wg 配置」都接住。
bool looks_like_wireguard_conf(std::string_view text) {
  const std::string head = codec::to_lower(codec::trim(text.substr(0, 64)));
  return head.rfind("[interface]", 0) == 0;
}

/// socks5:// 与 http(s):// 分享链接
Result<ProxyNode> parse_socks_http(std::string_view uri, Protocol proto,
                                   const std::string& fallback_name) {
  auto u = codec::parse_uri(uri);
  if (!u) return fail(u.error());
  if (!u->has_port) return fail("缺少端口");

  ProxyNode n;
  n.protocol = proto;
  n.server = u->host;
  n.port = u->port;
  n.name = codec::trim(codec::percent_decode(u->fragment));
  if (n.name.empty()) n.name = fallback_name;

  if (!u->userinfo.empty()) {
    std::string userinfo = u->userinfo;
    auto colon = userinfo.find(':');
    if (colon == std::string::npos) {
      // v2rayNG / Shadowrocket 导出的 socks:// 会把 user:password 整体做 base64，
      // 无冒号时按 base64 再试一次（解出来必须含冒号才认）。
      if (auto decoded = codec::base64_decode(userinfo);
          decoded && decoded->find(':') != std::string::npos) {
        userinfo = *decoded;
        colon = userinfo.find(':');
      }
    }
    if (colon == std::string::npos) {
      n.username = userinfo;
    } else {
      n.username = userinfo.substr(0, colon);
      n.password = userinfo.substr(colon + 1);
    }
  }

  if (proto == Protocol::Http && codec::iequals(u->scheme, "https")) {
    n.tls.enabled = true;
    // 分享链接无法携带证书信息；按社区惯例默认跳过校验，用户可显式关闭。
    n.tls.insecure = true;
  }
  return n;
}

std::string normalize_subscription(std::string_view raw) {
  std::string s(raw);
  // 去掉 UTF-8 BOM
  if (s.size() >= 3 && static_cast<unsigned char>(s[0]) == 0xEF &&
      static_cast<unsigned char>(s[1]) == 0xBB && static_cast<unsigned char>(s[2]) == 0xBF) {
    s.erase(0, 3);
  }
  std::string cur = codec::trim(s);
  // WireGuard 的 .conf 文本不做 Base64 解包：`[Interface]` 这串字符恰好也是合法 base64
  // 字母表，looks_like_base64 会误判，"解开" 后得到一堆乱码（实测会被解成 "É..."）。
  if (looks_like_wireguard_conf(cur)) return cur;
  // 最多解两层 Base64 包裹（部分机场会二次编码）
  for (int pass = 0; pass < 2; ++pass) {
    if (cur.find("://") != std::string::npos) break;
    if (!codec::looks_like_base64(cur)) break;
    auto decoded = codec::base64_decode(cur);
    if (!decoded) break;
    cur = codec::trim(*decoded);
  }
  return cur;
}

struct Unimplemented {
  const char* scheme;
  const char* proto;
};

constexpr Unimplemented kUnimplemented[] = {
    {"ssr://", "ShadowsocksR"},   {"vmess://", "VMess"},
    {"vless://", "VLESS"},        {"trojan://", "Trojan"},
    {"hysteria://", "Hysteria"},  {"hysteria2://", "Hysteria2"},
    {"hy2://", "Hysteria2"},      {"tuic://", "TUIC"},
    {"snell://", "Snell"},
};

}  // namespace

Result<ProxyNode> parse_node(std::string_view uri, std::string fallback_name) {
  const std::string text = codec::trim(uri);
  if (text.empty()) return fail("空链接");
  fallback_name = codec::trim(fallback_name);

  // --- 已实现 ---
  if (codec::starts_with_icase(text, "ss://")) return parse_ss(text, fallback_name);
  if (codec::starts_with_icase(text, "ssr://")) return parse_ssr(text, fallback_name);
  if (codec::starts_with_icase(text, "vmess://")) return parse_vmess(text, fallback_name);
  if (codec::starts_with_icase(text, "vless://")) return parse_vless(text, fallback_name);
  if (codec::starts_with_icase(text, "trojan://")) return parse_trojan(text, fallback_name);
  if (codec::starts_with_icase(text, "hysteria2://") ||
      codec::starts_with_icase(text, "hy2://")) {
    return parse_hysteria2(text, fallback_name);
  }
  if (codec::starts_with_icase(text, "hysteria://")) return parse_hysteria(text, fallback_name);
  if (codec::starts_with_icase(text, "tuic://")) return parse_tuic(text, fallback_name);
  if (codec::starts_with_icase(text, "snell://")) return parse_snell(text, fallback_name);
  if (codec::starts_with_icase(text, "wireguard://") ||
      codec::starts_with_icase(text, "wg://")) {
    return parse_wireguard(text, fallback_name);
  }
  if (codec::starts_with_icase(text, "wireguard-json://")) {
    return parse_wireguard_json(text.substr(std::string_view("wireguard-json://").size()),
                                fallback_name);
  }
  if (codec::starts_with_icase(text, "socks5://") ||
      codec::starts_with_icase(text, "socks5h://") ||
      codec::starts_with_icase(text, "socks://")) {
    return parse_socks_http(text, Protocol::Socks5, fallback_name);
  }
  if (codec::starts_with_icase(text, "http://") ||
      codec::starts_with_icase(text, "https://")) {
    return parse_socks_http(text, Protocol::Http, fallback_name);
  }

  // --- 暂未实现 ---
  for (const auto& entry : kUnimplemented) {
    if (codec::starts_with_icase(text, entry.scheme)) {
      return fail(std::string("协议 ") + entry.proto + " 尚未实现: " + entry.scheme);
    }
  }

  return fail("无法识别的链接协议: " + preview(text));
}

Result<Subscription> parse_subscription(std::string_view raw, std::string source) {
  Subscription sub;
  sub.source = std::move(source);

  const std::string content = normalize_subscription(raw);
  if (content.empty()) return fail("订阅内容为空");
  // WireGuard 的 .conf 文本（或整体 Base64 包裹的 .conf）：它内部没有 `://`，
  // 但第一段就是 [Interface]，这里直接当成一个 WireGuard 节点。
  if (looks_like_wireguard_conf(content)) {
    auto node = parse_wireguard_conf(content, "WireGuard");
    if (!node) return fail(node.error().message);
    sub.nodes.push_back(std::move(*node));
    return sub;
  }
  if (content.find("://") == std::string::npos) {
    // 整体 Base64 包裹的配置文件：normalize_subscription 已经把包裹解开，
    // 露出来的是 JSON 就按 Xray JSON 配置再试一次（有些面板把配置整体编码后下发）。
    const char first = content.front();
    if (first == '{' || first == '[') {
      if (auto sub_json = parse_xray_json(content, sub.source)) return sub_json;
    }
    return fail("订阅内容中未发现分享链接（可能是 Clash YAML / Xray JSON / sing-box JSON 等格式，"
                "请直接作为文件或链接输入；Xray JSON 配置已支持，sing-box JSON 暂不支持）");
  }

  std::size_t index = 0;
  for (const auto& raw_line : codec::split(content, '\n')) {
    const std::string line = codec::trim(raw_line);
    if (line.empty()) continue;
    if (line[0] == '#' || line[0] == ';') continue;
    if (line.rfind("//", 0) == 0) continue;
    if (line.find("://") == std::string::npos) {
      sub.warnings.push_back("跳过无法识别的内容: " + preview(line));
      continue;
    }
    ++index;
    auto node = parse_node(line, "节点 " + std::to_string(index));
    if (!node) {
      sub.warnings.push_back("第 " + std::to_string(index) + " 条解析失败: " +
                             node.error().message);
      continue;
    }
    if (node->name.empty()) node->name = "节点 " + std::to_string(index);
    sub.nodes.push_back(std::move(*node));
  }

  if (sub.nodes.empty()) return fail("未从订阅中解析出任何节点");
  return sub;
}

}  // namespace subconv
