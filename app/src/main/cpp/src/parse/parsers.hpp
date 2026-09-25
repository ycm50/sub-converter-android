// 各协议解析器的内部声明
#pragma once

#include <string>
#include <string_view>

#include "subconv/convert.hpp"

namespace subconv {

Result<ProxyNode> parse_ss(std::string_view uri, const std::string& fallback_name);
Result<ProxyNode> parse_ssr(std::string_view uri, const std::string& fallback_name);
Result<ProxyNode> parse_vmess(std::string_view uri, const std::string& fallback_name);
Result<ProxyNode> parse_vless(std::string_view uri, const std::string& fallback_name);
Result<ProxyNode> parse_trojan(std::string_view uri, const std::string& fallback_name);
Result<ProxyNode> parse_hysteria(std::string_view uri, const std::string& fallback_name);
Result<ProxyNode> parse_hysteria2(std::string_view uri, const std::string& fallback_name);
Result<ProxyNode> parse_tuic(std::string_view uri, const std::string& fallback_name);
Result<ProxyNode> parse_snell(std::string_view uri, const std::string& fallback_name);
// WireGuard 的三个入口在公开头 include/subconv/wireguard.hpp 里声明（Clash YAML /
// Xray JSON 解析器也要调用其中的辅助逻辑）。

}  // namespace subconv
