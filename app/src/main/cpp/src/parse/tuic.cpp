// TUIC 解析
//   tuic://uuid:password@host:port?congestion_control=bbr&alpn=h3&sni=..&udp_relay_mode=native&allow_insecure=1#name
// 也兼容 v4 的 token 形式：tuic://token@host:port?...
#include "parsers.hpp"
#include "subconv/codec.hpp"
#include "uri_common.hpp"

namespace subconv {

Result<ProxyNode> parse_tuic(std::string_view uri, const std::string& fallback_name) {
  auto u = codec::parse_uri(uri);
  if (!u) return fail(u.error());
  if (!u->has_port) return fail("tuic:// 缺少端口");
  if (u->userinfo.empty()) return fail("tuic:// 缺少 UUID/密码");

  ProxyNode node;
  node.protocol = Protocol::Tuic;
  node.server = u->host;
  node.port = u->port;
  node.name = parse_detail::name_from_fragment(u->fragment, fallback_name);

  if (const auto colon = u->userinfo.find(':'); colon == std::string::npos) {
    node.password = u->userinfo;   // v4 token 形式
  } else {
    node.uuid = u->userinfo.substr(0, colon);
    node.password = u->userinfo.substr(colon + 1);
  }

  node.tls.enabled = true;
  const auto q = codec::parse_query(u->query);
  parse_detail::apply_common_params(node, q);

  if (const auto* v = parse_detail::pick(q, {"congestion_control", "congestion-control",
                                             "congestion_controller"})) {
    node.congestion_control = *v;
  }
  if (const auto* v = parse_detail::pick(q, {"udp_relay_mode", "udp-relay-mode"})) {
    node.udp_relay_mode = *v;
  }
  if (node.tls.alpn.empty()) node.tls.alpn = {"h3"};

  return node;
}

}  // namespace subconv
