// VMess 解析
//   标准：vmess://base64(JSON)     —— v2rayN / v2rayNG 通用格式
//   变体：vmess://cipher:uuid@host:port?...#name   （"vmess1" 老格式）
#include <map>

#include "json_util.hpp"
#include "parsers.hpp"
#include "subconv/codec.hpp"
#include "uri_common.hpp"

namespace subconv {
namespace {

/// 把 vmess JSON 的字段摊平成 apply_common_params 认识的 query 表。
std::map<std::string, std::string> json_to_query(const Json& j) {
  std::map<std::string, std::string> q;
  auto put = [&q, &j](const char* key, const char* json_key) {
    std::string v = parse_detail::jstring(j, json_key);
    if (!v.empty()) q[key] = std::move(v);
  };
  put("net", "net");
  // vmess 的 `type` 字段在 xhttp 下装的是 xhttp mode（v2rayN VmessFmt 的映射就是如此），
  // 其余传输才是 headerType —— 别把 mode 塞进 headerType，否则链接往返会漂成
  // `headerType=stream-up` 这种谁都不认的参数。
  const std::string net = codec::to_lower(parse_detail::jstring(j, "net"));
  if (net == "xhttp" || net == "splithttp") {
    put("mode", "type");
  } else {
    put("headerType", "type");
  }
  put("host", "host");
  put("path", "path");
  put("sni", "sni");
  put("alpn", "alpn");
  put("fp", "fp");
  put("security", "security");
  put("pbk", "pbk");
  put("sid", "sid");
  put("spx", "spx");
  put("serviceName", "serviceName");
  if (codec::iequals(parse_detail::jstring(j, "tls"), "tls")) q["tls"] = "true";
  return q;
}

bool host_port_ok(const std::string& host, const std::string& port) {
  return !host.empty() && !port.empty();
}

}  // namespace

Result<ProxyNode> parse_vmess(std::string_view uri, const std::string& fallback_name) {
  constexpr std::string_view kScheme = "vmess://";
  if (!codec::starts_with_icase(uri, kScheme)) return fail("不是 vmess:// 链接");

  std::string_view body = uri.substr(kScheme.size());
  std::string fragment;
  if (const auto h = body.find('#'); h != std::string_view::npos) {
    fragment = codec::percent_decode(body.substr(h + 1));
    body = body.substr(0, h);
  }
  std::string_view query;
  if (const auto q = body.find('?'); q != std::string_view::npos) {
    query = body.substr(q + 1);
    body = body.substr(0, q);
  }

  auto decoded = codec::base64_decode(body);
  const std::string payload =
      decoded ? codec::trim(*decoded) : std::string(codec::trim(body));
  if (payload.empty()) return fail("vmess:// 内容为空");

  ProxyNode node;
  node.protocol = Protocol::Vmess;

  if (payload.front() == '{') {
    const Json j = Json::parse(payload, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
      return fail("vmess:// 内嵌 JSON 解析失败");
    }
    node.name = codec::trim(parse_detail::jstring(j, "ps"));
    node.server = codec::trim(parse_detail::jstring(j, "add"));
    node.uuid = codec::trim(parse_detail::jstring(j, "id"));
    node.alter_id = static_cast<int>(parse_detail::jint(j, "aid", 0));
    node.cipher = codec::trim(parse_detail::jstring(j, "scy"));
    if (node.cipher.empty()) node.cipher = "auto";

    const std::string port_text = parse_detail::jstring(j, "port");
    if (!host_port_ok(node.server, port_text)) {
      return fail("vmess:// JSON 缺少 add 或 port");
    }
    const auto port = codec::parse_port(port_text);
    if (!port) return fail(port.error());
    node.port = *port;

    if (node.uuid.empty()) return fail("vmess:// JSON 缺少 id (UUID)");

    parse_detail::apply_common_params(node, json_to_query(j));
  } else {
    // vmess1：cipher:uuid@host:port
    const auto at = payload.rfind('@');
    if (at == std::string::npos) return fail("vmess:// 既不是合法 JSON 也不是 vmess1 格式");
    const std::string userinfo = payload.substr(0, at);
    const std::string hostport = payload.substr(at + 1);

    const auto colon = userinfo.find(':');
    if (colon == std::string::npos) return fail("vmess1 缺少 cipher:uuid");
    node.cipher = userinfo.substr(0, colon);
    node.uuid = userinfo.substr(colon + 1);
    if (node.cipher.empty()) node.cipher = "auto";

    const auto hp = codec::split_host_port(hostport);
    if (!hp) return fail(hp.error());
    node.server = hp->first;
    const auto port = codec::parse_port(hp->second);
    if (!port) return fail(port.error());
    node.port = *port;

    parse_detail::apply_common_params(node, codec::parse_query(query));
  }

  if (node.server.empty()) return fail("vmess:// 缺少服务器地址");
  if (!fragment.empty()) node.name = codec::trim(fragment);
  if (node.name.empty()) node.name = fallback_name;
  return node;
}

}  // namespace subconv
