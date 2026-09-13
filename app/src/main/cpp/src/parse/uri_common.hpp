// 分享链接解析的公共逻辑（vless / trojan / hysteria2 / tuic / vmess 共用）
#pragma once

#include <initializer_list>
#include <map>
#include <string>
#include <vector>

#include "subconv/types.hpp"

namespace subconv::parse_detail {

/// 在 query 参数表里按多个别名查找（键名大小写不敏感）。
const std::string* pick(const std::map<std::string, std::string>& q,
                        std::initializer_list<const char*> keys);

/// 判断参数字符串是否表达"真"（1/true/yes/on）。
bool truthy(const std::string* v);

/// 拆分 alpn=h2,http/1.1
std::vector<std::string> split_alpn(const std::string& s);

/// 从 fragment 取节点名（percent-decode + trim），空则用 fallback。
std::string name_from_fragment(const std::string& fragment, const std::string& fallback);

/// 把分享链接 query 里的通用参数映射到 ProxyNode 的 TLS / 传输层字段。
void apply_common_params(ProxyNode& node, const std::map<std::string, std::string>& q);

}  // namespace subconv::parse_detail
