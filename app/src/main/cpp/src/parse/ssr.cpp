// ShadowsocksR 解析
//   ssr://base64url( host:port:protocol:method:obfs:base64url(password)
//                    /?obfsparam=b64&protoparam=b64&remarks=b64&group=b64 )
#include "parsers.hpp"
#include "subconv/codec.hpp"

namespace subconv {
namespace {

/// SSR 的参数字段是 base64url；但也有机场直接塞明文，做容错回落。
std::string b64_or_plain(std::string_view s) {
  const std::string text = codec::trim(codec::percent_decode(s));
  if (text.empty()) return {};
  auto decoded = codec::base64_decode(text);
  if (decoded && !decoded->empty()) return *decoded;
  return text;
}

}  // namespace

Result<ProxyNode> parse_ssr(std::string_view uri, const std::string& fallback_name) {
  constexpr std::string_view kScheme = "ssr://";
  if (!codec::starts_with_icase(uri, kScheme)) return fail("不是 ssr:// 链接");

  std::string_view body = uri.substr(kScheme.size());
  if (const auto h = body.find('#'); h != std::string_view::npos) {
    body = body.substr(0, h);
  }

  auto decoded = codec::base64_decode(body);
  if (!decoded) return fail_with("ssr:// Base64 解码失败", decoded.error());
  const std::string payload = codec::trim(*decoded);
  if (payload.empty()) return fail("ssr:// 内容为空");

  // 主体与参数以第一个 '/' 分隔
  std::string main = payload;
  std::string params;
  if (const auto slash = payload.find('/'); slash != std::string::npos) {
    main = payload.substr(0, slash);
    params = payload.substr(slash + 1);
    if (!params.empty() && params.front() == '?') params.erase(0, 1);
  }

  auto parts = codec::split(main, ':');
  if (parts.size() < 6) {
    return fail("ssr:// 主体字段不足（期望 host:port:protocol:method:obfs:password）");
  }
  // 兼容 IPv6 主机（多余的冒号属于 host）
  const std::size_t n = parts.size();
  std::string host = parts[0];
  for (std::size_t i = 1; i + 5 < n; ++i) host += ":" + parts[i];

  ProxyNode node;
  node.protocol = Protocol::ShadowsocksR;
  node.server = host;
  const auto port = codec::parse_port(parts[n - 5]);
  if (!port) return fail(port.error());
  node.port = *port;
  node.ssr_protocol = parts[n - 4];
  node.cipher = parts[n - 3];
  node.ssr_obfs = parts[n - 2];
  node.password = b64_or_plain(parts[n - 1]);

  if (node.server.empty()) return fail("ssr:// 缺少服务器地址");
  if (node.cipher.empty()) return fail("ssr:// 缺少加密方式");

  std::string name;
  if (!params.empty()) {
    const auto q = codec::parse_query(params);
    for (const auto& [key, value] : q) {
      if (codec::iequals(key, "obfsparam")) node.ssr_obfs_param = b64_or_plain(value);
      else if (codec::iequals(key, "protoparam")) node.ssr_protocol_param = b64_or_plain(value);
      else if (codec::iequals(key, "remarks")) name = b64_or_plain(value);
      else if (codec::iequals(key, "group")) node.extra["group"] = b64_or_plain(value);
    }
  }

  name = codec::trim(name);
  node.name = name.empty() ? fallback_name : name;
  return node;
}

}  // namespace subconv
