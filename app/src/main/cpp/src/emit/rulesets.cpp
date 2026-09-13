// 分流规则集：把「直连本地 / 中国 / 伊朗 / Cloudflare …」这类可勾选的集合展开成 clash 规则。
//
// 设计取舍（都基于实测，不是照抄模板）：
//   * 只用 mihomo 自带的 GEOSITE / GEOIP 匹配，**不依赖任何远程 rule-provider**。
//     好处：生成的配置离线可用、能在本机用 `mihomo -t` 完整校验，也不存在运行时下载失败
//     导致整份配置起不来的风险（rule-providers 会在 mihomo 启动时去下载，断网即失败）。
//   * `mihomo -t` 会**校验 GEOSITE 类别是否存在**（不存在的会报
//     "list xxx not found in geosite.dat"），所以本文件的类别都是逐个跑 `mihomo -t` 验过的；
//     而 GEOIP 的国家码 `-t` 并不校验（`XX-BOGUS` 也能过），故 GEOIP 只用于通用国家码。
//   * 类别名有坑：伊朗在 v2fly 的 geosite 里叫 `category-ir`（没有 `ir`）。
//
// 规则顺序：clash 是首个命中生效，所以 REJECT 类必须排在 DIRECT 类之前，
// 否则广告域名一旦命中某个 DIRECT 规则就直接放行了。

#include <string>
#include <string_view>
#include <vector>

#include "subconv/convert.hpp"
#include "emit_internal.hpp"

namespace subconv {
namespace {

struct RuleSetDef {
  std::string_view id;
  std::string_view name;
  std::string_view policy;
  std::string_view note;
  std::vector<std::string_view> rules;
};

/// 目录表。展示顺序 = 这里定义的顺序；`rules:` 里的实际顺序见文件头注释。
const std::vector<RuleSetDef>& catalogue_defs() {
  static const std::vector<RuleSetDef> defs = {
      {"local", "直连本地", "DIRECT", "局域网 / 保留地址（GEOIP,LAN + GEOIP,private）",
       {"GEOIP,LAN,DIRECT,no-resolve", "GEOIP,private,DIRECT,no-resolve"}},
      {"cn", "中国直连", "DIRECT", "中国域名与 IP（GEOSITE,cn + GEOIP,CN）",
       {"GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT"}},
      {"ir", "伊朗直连", "DIRECT", "伊朗域名与 IP（GEOSITE,category-ir + GEOIP,IR）",
       {"GEOSITE,category-ir,DIRECT", "GEOIP,IR,DIRECT"}},
      {"cloudflare", "Cloudflare 直连", "DIRECT", "Cloudflare 域名（GEOSITE,cloudflare）",
       {"GEOSITE,cloudflare,DIRECT"}},
      {"apple", "Apple 直连", "DIRECT", "Apple 域名（GEOSITE,apple）",
       {"GEOSITE,apple,DIRECT"}},
      {"microsoft", "微软直连", "DIRECT", "微软域名（GEOSITE,microsoft）",
       {"GEOSITE,microsoft,DIRECT"}},
      {"steam", "Steam 直连", "DIRECT", "Steam 域名（GEOSITE,steam）",
       {"GEOSITE,steam,DIRECT"}},
      {"onedrive", "OneDrive 直连", "DIRECT", "OneDrive 域名（GEOSITE,onedrive）",
       {"GEOSITE,onedrive,DIRECT"}},
      {"ads", "广告拦截", "REJECT", "广告域名直接拒绝（GEOSITE,category-ads-all）",
       {"GEOSITE,category-ads-all,REJECT"}},
  };
  return defs;
}

const RuleSetDef* find_def(std::string_view id) {
  for (const auto& def : catalogue_defs()) {
    if (def.id == id) return &def;
  }
  return nullptr;
}

bool already_selected(const std::vector<std::string>& ids, std::string_view id) {
  for (const auto& existing : ids) {
    if (existing == id) return true;
  }
  return false;
}

}  // namespace

std::vector<RuleSetInfo> rule_set_catalogue() {
  std::vector<RuleSetInfo> out;
  out.reserve(catalogue_defs().size());
  for (const auto& def : catalogue_defs()) {
    out.push_back(RuleSetInfo{std::string(def.id), std::string(def.name), std::string(def.policy),
                              std::string(def.note)});
  }
  return out;
}

std::vector<std::string> default_rule_sets() { return {"local", "cn"}; }

std::vector<std::string> build_clash_rules(const std::vector<std::string>& selected,
                                           const std::string& final_group,
                                           std::vector<std::string>* warnings) {
  // 按**目录顺序**遍历，只留下被选中的 —— 这样 rules 的优先级由目录决定，
  // 与命令行/界面里勾选的先后无关（同一组 id 的任意排列都产出同一份 rules）。
  std::vector<const RuleSetDef*> reject_sets;
  std::vector<const RuleSetDef*> direct_sets;
  for (const auto& def : catalogue_defs()) {
    if (!already_selected(selected, def.id)) continue;
    if (def.policy == "REJECT") {
      reject_sets.push_back(&def);
    } else {
      direct_sets.push_back(&def);
    }
  }

  // 选中了但目录里没有的 id：去重后一次性告警，不影响其它规则
  std::vector<std::string> unknown;
  for (const auto& id : selected) {
    if (find_def(id) != nullptr || already_selected(unknown, id)) continue;
    unknown.push_back(id);
  }

  if (warnings != nullptr && !unknown.empty()) {
    std::string available;
    for (const auto& def : catalogue_defs()) {
      if (!available.empty()) available += "、";
      available += std::string(def.id);
    }
    std::string detail = "无法识别的规则集 ";
    for (std::size_t i = 0; i < unknown.size(); ++i) {
      if (i > 0) detail += "、";
      detail += "'" + unknown[i] + "'";
    }
    detail += "（已忽略；可用：" + available + "）";
    warnings->push_back(std::move(detail));
  }

  std::vector<std::string> rules;
  for (const RuleSetDef* def : reject_sets) {
    for (const auto& rule : def->rules) rules.emplace_back(rule);
  }
  for (const RuleSetDef* def : direct_sets) {
    for (const auto& rule : def->rules) rules.emplace_back(rule);
  }
  rules.push_back("MATCH," + final_group);
  return rules;
}

}  // namespace subconv
