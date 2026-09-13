// Trojan 解析
//   trojan://password@host:port?sni=..&type=ws&path=..&host=..&allowInsecure=1#name
#include "parsers.hpp"
#include "subconv/codec.hpp"
#include "uri_common.hpp"

namespace subconv {

Result<ProxyNode> parse_trojan(std::string_view uri, const std::string& fallback_name) {
  auto u = codec::parse_uri(uri);
  if (!u) return fail(u.error());
  if (!u->has_port) return fail("trojan:// 缺少端口");
  if (u->userinfo.empty()) return fail("trojan:// 缺少密码");

  ProxyNode node;
  node.protocol = Protocol::Trojan;
  node.password = u->userinfo;
  node.server = u->host;
  node.port = u->port;
  node.name = parse_detail::name_from_fragment(u->fragment, fallback_name);

  const auto q = codec::parse_query(u->query);
  // Trojan 默认就是 TLS；只有显式 security=none 才关闭。
  node.tls.enabled = true;
  parse_detail::apply_common_params(node, q);

  if (node.tls.sni.empty()) node.tls.sni = node.server;
  if (node.tls.alpn.empty()) node.tls.alpn = {"h2", "http/1.1"};

  return node;
}

}  // namespace subconv
