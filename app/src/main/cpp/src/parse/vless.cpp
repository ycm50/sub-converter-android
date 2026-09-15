// VLESS 解析
//   vless://uuid@host:port?encryption=none&security=tls|reality&sni=..&type=ws&path=..&host=..#name
#include "parsers.hpp"
#include "subconv/codec.hpp"
#include "subconv/vless_encryption.hpp"
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

  // encryption=none 是「不加密」；其余值是 Xray 的 VLESS Encryption（ML-KEM 抗量子层）。
  // 它必须一路带到输出端：丢了它服务端就解不开 VLESS 头，既不回包也不断开，客户端只能
  // 等到拨号超时（「连上了但没数据」的静默黑洞）。别把它塞进 extra —— 那是「尚未建模」
  // 的字段，各输出目标不会主动读，历史版本正是因此把 vless:// 转 clash 时漏掉了它。
  if (const auto* enc = parse_detail::pick(q, {"encryption"})) {
    node.encryption = normalize_vless_encryption(*enc);
  }
  if (const auto* v = parse_detail::pick(q, {"flow"})) node.flow = *v;
  if (const auto* v = parse_detail::pick(q, {"packetEncoding", "packet-encoding"})) {
    node.packet_encoding = *v;
  }

  return node;
}

}  // namespace subconv
