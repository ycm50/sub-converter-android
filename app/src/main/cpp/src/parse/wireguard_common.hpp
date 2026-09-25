// WireGuard 的公共逻辑：解析侧（分享链接 / Clash YAML / Xray JSON）与输出侧
// （clash / singbox / xray / links）都要用同一套「键、地址、reserved」的规范化规则，
// 放在这里避免两边漂移。
#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "subconv/json.hpp"
#include "subconv/types.hpp"

namespace subconv::wireguard_detail {

/// 去除 base64 密钥尾部的 '='（Xray 的 ParseWireGuardKey 也是这么干的）。
[[nodiscard]] std::string strip_key_padding(std::string_view key);

/// 把密钥重新编码成**带 '=' 补齐**的标准 base64（44 字符）。
///
/// 为什么需要它：分享链接里带 '=' 会让 URI 解析出岔子，所以链接形态（v2rayN / v2rayNG
/// 与本工具）一律省略 padding；但 mihomo 是 Go 的 `base64.StdEncoding.DecodeString`，
/// **遇到缺 padding 会直接报 `illegal base64 data at input byte 40` 并拒绝加载配置**。
/// 因此所有「写进内核配置文件」的密钥都要经过这里补回来。
/// 已经是 64 位 hex（Xray 也接受）的密钥原样返回，不做转换。
[[nodiscard]] std::string pad_key_base64(std::string_view key);

/// 判断是否为一条像样的 WireGuard 密钥：base64（32 字节 → 44 字符）或 64 位 hex。
/// 宽松判定，只用来在缺字段时决定是否报错，不做密码学校验。
[[nodiscard]] bool looks_like_key(std::string_view key);

/// 从 YAML/JSON 的三种形态里读 reserved：
///   * JSON 数组 / YAML 序列：[209, 98, 59]
///   * 4 字符 base64："U4An"
///   * 6 位 hex（3 字节）："d1623b"
/// 结果放进 peer.reserved（0 或 3 个元素）。
void parse_reserved_scalar(const std::string& text, std::vector<int>& out);
void parse_reserved_json(const Json& value, std::vector<int>& out);

/// allowed-ips：数组形态与逗号分隔的字符串形态都收。
[[nodiscard]] std::vector<std::string> split_allowed_ips(std::string_view text);
[[nodiscard]] std::vector<std::string> allowed_ips_from_json(const Json& value);

/// 把 "AllowedIPs = a, b" 这类文本行拆成 key / value（按第一个 '='）。
[[nodiscard]] bool split_kv(std::string_view line, std::string& key, std::string& value);

/// 把 allowedIPs / allowed-ips 之类的文本（逗号或空白分隔）拆开。
[[nodiscard]] std::vector<std::string> split_list(std::string_view text);

/// 极简 IP 归属判断：用于把 Address 拆成 mihomo 的 `ip` / `ipv6` 两栏。
[[nodiscard]] bool address_is_ipv6(std::string_view address);
[[nodiscard]] bool address_is_ipv4(std::string_view address);

}  // namespace subconv::wireguard_detail
