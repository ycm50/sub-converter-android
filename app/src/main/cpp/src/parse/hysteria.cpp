// Hysteria v1 与 v2 (hysteria2 / hy2) 解析
#include <string>

#include "parsers.hpp"
#include "subconv/codec.hpp"
#include "uri_common.hpp"

namespace subconv {

Result<ProxyNode> parse_hysteria2(std::string_view uri, const std::string& fallback_name) {
  auto u = codec::parse_uri(uri);
  if (!u) return fail(u.error());
  if (!u->has_port) return fail("hysteria2:// 缺少端口");

  ProxyNode node;
  node.protocol = Protocol::Hysteria2;
  node.password = u->userinfo;   // hysteria2 的认证串就是整段 userinfo
  node.server = u->host;
  node.port = u->port;
  node.name = parse_detail::name_from_fragment(u->fragment, fallback_name);

  node.tls.enabled = true;       // hysteria2 强制 TLS
  const auto q = codec::parse_query(u->query);
  parse_detail::apply_common_params(node, q);

  if (const auto* v = parse_detail::pick(q, {"obfs"})) {
    if (!codec::iequals(*v, "none")) node.obfs = *v;
  }
  if (const auto* v = parse_detail::pick(q, {"obfs-password", "obfs_password", "obfspwd"})) {
    node.obfs_password = *v;
  }
  if (const auto* v = parse_detail::pick(q, {"up", "upmbps"})) node.up = *v;
  if (const auto* v = parse_detail::pick(q, {"down", "downmbps"})) node.down = *v;
  if (const auto* v = parse_detail::pick(q, {"pinSHA256", "pinsha256"})) {
    node.tls.fingerprint = *v;
  }
  if (const auto* v = parse_detail::pick(q, {"mport", "ports"})) node.extra["ports"] = *v;

  if (node.tls.alpn.empty()) node.tls.alpn = {"h3"};
  if (node.password.empty()) return fail("hysteria2:// 缺少认证密码");
  return node;
}

Result<ProxyNode> parse_hysteria(std::string_view uri, const std::string& fallback_name) {
  auto u = codec::parse_uri(uri);
  if (!u) return fail(u.error());
  if (!u->has_port) return fail("hysteria:// 缺少端口");

  ProxyNode node;
  node.protocol = Protocol::Hysteria;
  node.server = u->host;
  node.port = u->port;
  node.name = parse_detail::name_from_fragment(u->fragment, fallback_name);
  // hysteria v1 把认证放在 host 前的 userinfo，或 query 的 auth
  if (!u->userinfo.empty()) node.password = u->userinfo;

  node.tls.enabled = true;
  const auto q = codec::parse_query(u->query);
  parse_detail::apply_common_params(node, q);

  if (const auto* v = parse_detail::pick(q, {"auth", "auth_str", "authStr"})) {
    if (node.password.empty()) node.password = *v;
  }
  if (const auto* v = parse_detail::pick(q, {"peer"})) node.tls.sni = *v;
  if (const auto* v = parse_detail::pick(q, {"upmbps", "up"})) node.up = *v;
  if (const auto* v = parse_detail::pick(q, {"downmbps", "down"})) node.down = *v;
  if (const auto* v = parse_detail::pick(q, {"protocol", "protocols"})) {
    node.extra["protocol"] = *v;
  }
  if (const auto* v = parse_detail::pick(q, {"obfs"})) {
    if (!codec::iequals(*v, "none")) node.obfs = *v;
  }
  if (node.tls.alpn.empty()) node.tls.alpn = {"h3"};
  return node;
}

}  // namespace subconv
