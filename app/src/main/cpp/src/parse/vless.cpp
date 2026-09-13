// VLESS 解析
//   vless://uuid@host:port?encryption=none&security=tls|reality&sni=..&type=ws&path=..&host=..#name
#include "parsers.hpp"
#include "subconv/codec.hpp"
#include "uri_common.hpp"

namespace subconv {

Result<ProxyNode> parse_vless(std::string_view uri, const std::string& fallback_name) {
  auto u = codec::parse_uri(uri);
  if (!u) return fail(u.error());
  if (!u->has_port) return fail("vless:// 缺少端口");
  if (u->userinfo.empty()) return fail("vless:// 缺少 UUID");

  ProxyNode node;
  node.protocol = Protocol::Vless;
  node.uuid = codec::trim(u->userinfo);
  node.server = u->host;
  node.port = u->port;
  node.name = parse_detail::name_from_fragment(u->fragment, fallback_name);

  const auto q = codec::parse_query(u->query);
  parse_detail::apply_common_params(node, q);

  // encryption=none 是唯一合法值；其他值属于 Xray 私有扩展，原样保留
  if (const auto* enc = parse_detail::pick(q, {"encryption"}); enc != nullptr && !enc->empty() &&
                                                               !codec::iequals(*enc, "none")) {
    node.extra["encryption"] = *enc;
  }
  if (const auto* v = parse_detail::pick(q, {"flow"})) node.flow = *v;
  if (const auto* v = parse_detail::pick(q, {"packetEncoding", "packet-encoding"})) {
    node.packet_encoding = *v;
  }

  return node;
}

}  // namespace subconv
