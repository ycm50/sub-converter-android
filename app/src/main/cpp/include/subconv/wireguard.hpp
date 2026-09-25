// WireGuard 解析入口（分享链接 / 内嵌 JSON / 标准 .conf 配置文本）。
//
// 与其它协议不同，WireGuard 的「节点」不是 server:port，而是一块三层虚拟网卡加一组对端，
// 所以这里提供三个入口，由调用方按输入形态选择；公共的字段约定见 src/parse/wireguard.cpp。
#pragma once

#include <string>
#include <string_view>

#include "subconv/convert.hpp"

namespace subconv {

/// `wireguard://` / `wg://` 分享链接。
[[nodiscard]] Result<ProxyNode> parse_wireguard(std::string_view uri,
                                                const std::string& fallback_name);

/// 内嵌 JSON：接受 `wireguard-json://<base64>`、裸 base64、裸 JSON，
/// 也接受 v2rayN `v2rayn://wireguard/<base64url(JSON)>` 的载荷。
[[nodiscard]] Result<ProxyNode> parse_wireguard_json(std::string_view payload,
                                                     const std::string& fallback_name);

/// 标准 WireGuard 客户端配置文本（wg-quick 的 .conf，含 [Interface] / [Peer]）。
[[nodiscard]] Result<ProxyNode> parse_wireguard_conf(std::string_view text,
                                                     const std::string& fallback_name);

}  // namespace subconv
