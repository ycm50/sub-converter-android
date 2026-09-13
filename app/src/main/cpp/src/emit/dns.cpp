// DNS 解析器预设：给 clash/mihomo 的 `dns.nameserver` 提供可勾选的常用解析器。
//
// 取舍：
//   * 只用**明文地址**（IP）与用户手填的 DoH/DoT URL，不引入 `default-nameserver`
//     bootstrap 依赖：预设里全是 IP，mihomo 拿到就能直接用。
//   * 预设分「国外 / 国内」并标注；默认取两个国外的（用户明确要求「以国外为主，国内不推荐」）。
//     国内解析器在跨境场景下常见被污染/劫持，界面上会标出来。
//   * IPv6 地址随 `ipv6` 开关一起给出：关掉时只写 IPv4，避免在无 IPv6 出口的机器上
//     让 mihomo 去连不存在的 v6 解析器。
//   * 华为那一项**故意没有内置**：没能查证到它的公网解析器地址（华为云文档里公开的
//     100.125.1.250 / 100.125.129.250 是 VPC 内网地址，出了华为云就用不了；
//     搜索引擎对「华为 + IP」的查询结果全是华为公司官网，不足为凭）。
//     需要的话直接在自定义里填地址即可 —— 本文件同样接受字面地址。

#include <string>
#include <string_view>
#include <vector>

#include "subconv/convert.hpp"
#include "emit_internal.hpp"

namespace subconv {
namespace {

struct DnsPresetDef {
  std::string_view id;
  std::string_view name;
  std::string_view region;
  std::string_view note;
  std::vector<std::string_view> v4;
  std::vector<std::string_view> v6;
};

const std::vector<DnsPresetDef>& dns_defs() {
  static const std::vector<DnsPresetDef> defs = {
      {"cloudflare", "Cloudflare", "国外", "1.1.1.1 · 无日志",
       {"1.1.1.1", "1.0.0.1"}, {"2606:4700:4700::1111", "2606:4700:4700::1001"}},
      {"google", "Google", "国外", "8.8.8.8 · 老牌稳定",
       {"8.8.8.8", "8.8.4.4"}, {"2001:4860:4860::8888", "2001:4860:4860::8844"}},
      {"quad9", "Quad9", "国外", "9.9.9.9 · 拦截恶意域名",
       {"9.9.9.9", "149.112.112.112"}, {"2620:fe::fe", "2620:fe::9"}},
      {"adguard", "AdGuard", "国外", "94.140.14.14 · 带广告拦截",
       {"94.140.14.14", "94.140.15.15"}, {}},
      {"opendns", "OpenDNS", "国外", "208.67.222.222 · 带家长控制",
       {"208.67.222.222", "208.67.220.220"}, {"2620:0:ccc::2", "2620:0:ccd::2"}},
      {"alidns", "阿里 AliDNS", "国内", "223.5.5.5 · 国内不推荐（跨境易被污染）",
       {"223.5.5.5", "223.6.6.6"}, {"2400:3200::1", "2400:3200:baba::1"}},
      {"dnspod", "腾讯 DNSPod", "国内", "119.29.29.29 · 国内不推荐（跨境易被污染）",
       {"119.29.29.29", "119.28.28.28"}, {"2402:4e00::"}},
      {"dns114", "114 DNS", "国内", "114.114.114.114 · 国内不推荐（广告劫持较多）",
       {"114.114.114.114", "114.114.115.115"}, {}},
  };
  return defs;
}

const DnsPresetDef* find_dns_def(std::string_view id) {
  for (const auto& def : dns_defs()) {
    if (def.id == id) return &def;
  }
  return nullptr;
}

/// 字面地址（IPv4 / IPv6 / DoH、DoT URL）才允许直接透传，
/// 免得把拼错的预设 id 当成解析器写进配置（那样 mihomo 会直接拒绝加载）。
bool looks_like_nameserver(std::string_view token) {
  if (token.find("://") != std::string_view::npos) return true;  // DoH / DoT
  bool has_colon = false;
  int digits = 0;
  int dots = 0;
  for (const char c : token) {
    if (c >= '0' && c <= '9') {
      ++digits;
    } else if (c == '.') {
      ++dots;
    } else if (c == ':') {
      has_colon = true;
    } else if (!((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
      return false;  // 出现了既不是数字、也不是点/冒号、也不是十六进制字母的字符
    }
  }
  if (has_colon) return true;              // 当成 IPv6
  return dots == 3 && digits > 0;          // 当成 IPv4
}

}  // namespace

std::vector<DnsPresetInfo> dns_catalogue() {
  std::vector<DnsPresetInfo> out;
  out.reserve(dns_defs().size());
  for (const auto& def : dns_defs()) {
    DnsPresetInfo info;
    info.id = std::string(def.id);
    info.name = std::string(def.name);
    info.region = std::string(def.region);
    info.note = std::string(def.note);
    for (const auto& ip : def.v4) info.v4.emplace_back(ip);
    for (const auto& ip : def.v6) info.v6.emplace_back(ip);
    out.push_back(std::move(info));
  }
  return out;
}

std::vector<std::string> default_dns() { return {"cloudflare", "google"}; }

std::vector<std::string> resolve_nameservers(const std::vector<std::string>& selected, bool ipv6,
                                             std::vector<std::string>* warnings) {
  std::vector<std::string> out;
  std::vector<std::string> seen;
  std::vector<std::string> unknown;

  auto push_unique = [&out, &seen](const std::string& address) {
    for (const auto& existing : seen) {
      if (existing == address) return;
    }
    seen.push_back(address);
    out.push_back(address);
  };

  for (const auto& token : selected) {
    if (token.empty()) continue;
    if (const DnsPresetDef* def = find_dns_def(token); def != nullptr) {
      for (const auto& ip : def->v4) push_unique(std::string(ip));
      if (ipv6) {
        for (const auto& ip : def->v6) push_unique(std::string(ip));
      }
      continue;
    }
    if (looks_like_nameserver(token)) {
      push_unique(token);
    } else if (unknown.empty() || unknown.back() != token) {
      unknown.push_back(token);
    }
  }

  if (warnings != nullptr && !unknown.empty()) {
    std::string available;
    for (const auto& def : dns_defs()) {
      if (!available.empty()) available += "、";
      available += std::string(def.id);
    }
    std::string detail = "无法识别的 DNS ";
    for (std::size_t i = 0; i < unknown.size(); ++i) {
      if (i > 0) detail += "、";
      detail += "'" + unknown[i] + "'";
    }
    detail += "（已忽略；可用预设：" + available + "；也可直接填 IP 或 https://<IP>/dns-query）";
    warnings->push_back(std::move(detail));
  }
  return out;
}

}  // namespace subconv
