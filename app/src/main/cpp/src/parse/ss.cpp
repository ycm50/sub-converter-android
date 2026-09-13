// Shadowsocks (ss://) 解析
// 支持两种形态：
//   1. SIP002  ss://<base64(method:password)>@host:port/?plugin=...#name
//   2. Legacy  ss://<base64(method:password@host:port)>#name
#include <charconv>

#include "subconv/codec.hpp"
#include "subconv/convert.hpp"

namespace subconv {
namespace {

/// 解析 plugin=obfs-local;obfs=http;obfs-host=x 形式
SsPlugin parse_plugin(std::string_view raw) {
  SsPlugin p;
  p.present = true;
  p.raw = std::string(raw);

  const auto parts = codec::split(raw, ';');
  if (!parts.empty()) p.name = parts.front();

  for (std::size_t i = 1; i < parts.size(); ++i) {
    const auto& token = parts[i];
    if (token.empty()) continue;
    const auto eq = token.find('=');
    const std::string key = (eq == std::string::npos) ? token : token.substr(0, eq);
    const std::string value = (eq == std::string::npos) ? std::string() : token.substr(eq + 1);

    if (key == "obfs") {
      p.obfs_mode = value;
    } else if (key == "obfs-host") {
      p.obfs_host = value;
    } else if (key == "mode") {
      p.mode = value;
    } else if (key == "host") {
      p.host = value;
    } else if (key == "path") {
      p.path = value;
    } else if (key == "tls") {
      p.tls = true;
    } else if (key == "tls-host") {
      p.tls_host = value;
    }
  }

  const std::string name_lower = codec::to_lower(p.name);
  if (name_lower == "obfs-local" || name_lower == "obfs") {
    // simple-obfs：无 obfs-host 时回落到 host
    if (p.obfs_host.empty()) p.obfs_host = p.host;
    if (p.obfs_mode.empty()) p.obfs_mode = "http";
  } else if (name_lower == "v2ray-plugin") {
    if (p.host.empty()) p.host = p.tls_host;
  }
  return p;
}

}  // namespace

Result<ProxyNode> parse_ss(std::string_view uri, const std::string& fallback_name) {
  constexpr std::string_view kScheme = "ss://";
  if (!codec::starts_with_icase(uri, kScheme)) return fail("不是 ss:// 链接");

  std::string_view body = uri.substr(kScheme.size());

  // 1) fragment -> 名称
  std::string name;
  if (const auto h = body.find('#'); h != std::string_view::npos) {
    name = codec::percent_decode(body.substr(h + 1));
    body = body.substr(0, h);
  }

  // 2) query -> 插件参数
  std::string_view query;
  if (const auto q = body.find('?'); q != std::string_view::npos) {
    query = body.substr(q + 1);
    body = body.substr(0, q);
  }

  // 去掉 SIP002 中的尾部 '/'
  while (!body.empty() && (body.back() == '/' || body.back() == ' ')) {
    body.remove_suffix(1);
  }

  if (body.empty()) return fail("ss:// 内容为空");

  std::string userinfo;
  std::string hostport;

  if (const auto at = body.rfind('@'); at != std::string_view::npos) {
    // SIP002
    const std::string_view ui = body.substr(0, at);
    hostport = std::string(body.substr(at + 1));
    if (ui.find(':') != std::string_view::npos) {
      userinfo = codec::percent_decode(ui);
    } else {
      // v2rayNG 等客户端会把 base64 的 userinfo 再做一次 percent-encode，
      // 解码前先还原（对未转义的 base64 是无操作）。
      auto decoded = codec::base64_decode(codec::percent_decode(ui));
      if (!decoded) return fail_with("ss:// userinfo 解码失败", decoded.error());
      userinfo = *decoded;
    }
  } else {
    // Legacy：整体 base64
    auto decoded = codec::base64_decode(body);
    if (!decoded) return fail_with("ss:// 内容不是合法 base64", decoded.error());
    const auto at_legacy = decoded->rfind('@');
    if (at_legacy == std::string::npos) {
      return fail("ss:// 解码后缺少 '@'（期望 method:password@host:port）");
    }
    userinfo = decoded->substr(0, at_legacy);
    hostport = decoded->substr(at_legacy + 1);
  }

  // 3) method:password
  const auto colon = userinfo.find(':');
  if (colon == std::string::npos) {
    return fail("ss:// 缺少 method:password 段");
  }
  ProxyNode node;
  node.protocol = Protocol::Shadowsocks;
  node.cipher = userinfo.substr(0, colon);
  node.password = userinfo.substr(colon + 1);
  if (node.cipher.empty()) return fail("ss:// 加密方式为空");

  // 4) host:port
  const auto hp = codec::split_host_port(hostport);
  if (!hp) return fail(hp.error());
  node.server = hp->first;
  const auto port = codec::parse_port(hp->second);
  if (!port) return fail(port.error());
  node.port = *port;

  // 5) 插件
  if (!query.empty()) {
    const auto params = codec::parse_query(query);
    if (const auto it = params.find("plugin"); it != params.end() && !it->second.empty()) {
      node.plugin = parse_plugin(it->second);
    }
  }

  node.name = codec::trim(name);
  if (node.name.empty()) node.name = fallback_name;
  return node;
}

}  // namespace subconv
