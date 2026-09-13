// Snell 解析（Clash 系内核专有协议）
//   snell://psk@host:port?version=4&obfs=http&obfs-host=..&reuse=1#name
//   snell://host:port?psk=..&version=3#name
#include "parsers.hpp"
#include "subconv/codec.hpp"
#include "uri_common.hpp"

namespace subconv {

Result<ProxyNode> parse_snell(std::string_view uri, const std::string& fallback_name) {
  auto u = codec::parse_uri(uri);
  if (!u) return fail(u.error());
  if (!u->has_port) return fail("snell:// 缺少端口");

  ProxyNode node;
  node.protocol = Protocol::Snell;
  node.server = u->host;
  node.port = u->port;
  node.name = parse_detail::name_from_fragment(u->fragment, fallback_name);

  const auto q = codec::parse_query(u->query);

  node.password = u->userinfo;
  if (node.password.empty()) {
    if (const auto* v = parse_detail::pick(q, {"psk", "key", "password"})) node.password = *v;
  }
  if (node.password.empty()) return fail("snell:// 缺少 psk");

  node.version = 3;
  if (const auto* v = parse_detail::pick(q, {"version", "v"})) {
    try {
      node.version = std::stoi(*v);
    } catch (...) {
      node.version = 3;
    }
  }
  if (const auto* v = parse_detail::pick(q, {"obfs"})) {
    if (!codec::iequals(*v, "none")) node.obfs = *v;
  }
  if (const auto* v = parse_detail::pick(q, {"obfs-host", "obfs_host", "host"})) {
    node.obfs_password = *v;   // Clash snell 的 obfs-host 复用该字段
  }
  if (const auto* v = parse_detail::pick(q, {"reuse"})) {
    if (parse_detail::truthy(v)) node.extra["reuse"] = "true";
  }
  return node;
}

}  // namespace subconv
