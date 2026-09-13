// 对外主接口：解析（订阅 -> 节点）与输出（节点 -> 目标配置）
#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "subconv/error.hpp"
#include "subconv/types.hpp"

namespace subconv {

// ---------------------------------------------------------------------------
// 解析
// ---------------------------------------------------------------------------
/// 解析单条分享链接（ss:// vmess:// ...）。
Result<ProxyNode> parse_node(std::string_view uri, std::string fallback_name = {});

/// 解析整份订阅内容：自动识别明文列表 / Base64 包裹 / 混杂内容。
Result<Subscription> parse_subscription(std::string_view raw, std::string source = {});

// ---------------------------------------------------------------------------
// 输出
// ---------------------------------------------------------------------------
/// 一个可选的分流规则集：选中后会展开成若干条 clash 规则写进 `rules:` 段。
struct RuleSetInfo {
  std::string id;      ///< 稳定标识：--rulesets / ?rulesets= / JSON options.rulesets
  std::string name;    ///< 界面显示名
  std::string policy;  ///< 该集合的处置：DIRECT / REJECT
  std::string note;    ///< 一句话说明（含实际用到的匹配方式）
};

/// 全部可选规则集，顺序即界面展示顺序。
/// 注意 `rules:` 里的实际顺序由 build_clash_rules 决定：REJECT 永远排在 DIRECT 之前。
[[nodiscard]] std::vector<RuleSetInfo> rule_set_catalogue();

/// 默认选中的规则集 id（保持与旧版输出一致：本地 + 中国）。
[[nodiscard]] std::vector<std::string> default_rule_sets();

/// 一个可选的 DNS 解析器预设（目前只有 clash/mihomo 目标会写进 dns 段）。
struct DnsPresetInfo {
  std::string id;          ///< 稳定标识：--dns / ?dns= / JSON options.dns
  std::string name;        ///< 界面显示名
  std::string region;      ///< 国外 / 国内
  std::string note;        ///< 一句话说明
  std::vector<std::string> v4;  ///< IPv4 地址
  std::vector<std::string> v6;  ///< IPv6 地址（可能为空）
};

/// 全部 DNS 预设，顺序即界面展示顺序。
[[nodiscard]] std::vector<DnsPresetInfo> dns_catalogue();

/// 默认选中的 DNS 预设 id（国外为主）。
[[nodiscard]] std::vector<std::string> default_dns();

struct EmitOptions {
  std::string target = "clash";
  bool emoji = true;            ///< 节点名插入国旗/地区 emoji
  bool udp = true;
  bool tfo = false;
  bool sort = false;            ///< 按名称排序
  bool dedup = true;            ///< 去重（同协议+同服务器+同端口）
  bool clash_legacy = false;    ///< 输出原版 Clash（Premium）兼容语法
  bool include_rules = true;
  /// 选中的分流规则集 id（见 rule_set_catalogue()）；顺序无关，空表示只留 MATCH 兜底。
  std::vector<std::string> rule_sets = default_rule_sets();
  /// dns 段的 nameserver：预设 id（见 dns_catalogue()）或字面地址（IP / DoH、DoT URL）混写。
  /// 空表示不写 nameserver。
  std::vector<std::string> dns = default_dns();
  bool ipv6 = true;             ///< 根节点与 dns 段的 ipv6，并决定是否带上各预设的 IPv6 地址
  std::string filename;         ///< 订阅名，供 Content-Disposition 与配置头注释使用
  /// 转换前逐节点探测对端证书指纹（需要联网、会主动连接节点）。
  ///
  /// 为什么需要：Xray 25 起移除了 `allowInsecure`，替代品 `verifyPeerCertByName` 仍要求
  /// 「证书链可信 **且** 名字匹配」，机场那种「证书与 SNI 对不上」的节点用它必然握手失败
  /// （客户端表现就是所有节点延迟 -1）。探测到的指纹写进 Xray 的 `pinnedPeerCertSha256`
  /// 或分享链接的 `pcs=`（v2rayN / v2rayNG）即可正常放行。
  bool probe_cert = false;
  int probe_cert_timeout_seconds = 5;  ///< 单个节点的探测超时
};

/// 把节点渲染成目标客户端配置文本。
/// warnings 非空时会被填入「该目标无法表示的节点」等提示（不影响返回值本身）。
Result<std::string> emit_config(const NodeList& nodes, const EmitOptions& opts,
                                std::vector<std::string>* warnings = nullptr);

/// 规范化目标名（别名折叠），返回空串表示无法识别。
[[nodiscard]] std::string normalize_target(std::string_view t);

/// 已实现的目标名。
[[nodiscard]] std::vector<std::string> implemented_targets();

/// 规划中但尚未实现的目标名（用于 --help 与报错提示）。
[[nodiscard]] std::vector<std::string> planned_targets();

}  // namespace subconv
