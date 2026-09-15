#include <algorithm>
#include <array>
#include <set>
#include <string>
#include <utility>

#include "emit_internal.hpp"
#include "subconv/codec.hpp"
#include "subconv/types.hpp"
#include "subconv/vless_encryption.hpp"

namespace subconv {

// ---------------------------------------------------------------------------
// 通用工具
// ---------------------------------------------------------------------------
std::string config_header(std::string_view target, std::size_t node_count,
                          std::string_view name) {
  std::string line = "# subconv ";
#ifdef SUBCONV_VERSION
  line += SUBCONV_VERSION;
#else
  line += "dev";
#endif
  line += " | target=";
  line.append(target);
  line += " | nodes=" + std::to_string(node_count);
  if (!name.empty()) line += " | name=" + std::string(name);
  line += "\n# 由 subconv 自动生成；分组与规则集内建于程序（--list-rulesets / --list-dns）\n";
  return line;
}

NodeList prepare_nodes(const NodeList& nodes, const EmitOptions& opts) {
  NodeList out;
  out.reserve(nodes.size());

  std::set<std::string> seen_fingerprint;
  std::set<std::string> seen_name;

  for (const auto& node : nodes) {
    if (opts.dedup) {
      // encryption 也是「同一个服务端上不同的节点」的区分维度：同一个 server:port:uuid
      // 配不同的 VLESS Encryption 参数/密钥就是两条不同的线路，不能当成重复项删掉。
      const std::string fingerprint = std::string(to_string(node.protocol)) + "|" +
                                      node.server + "|" + std::to_string(node.port) + "|" +
                                      node.uuid + "|" + node.password + "|" + node.cipher + "|" +
                                      node.encryption;
      if (!seen_fingerprint.insert(fingerprint).second) continue;
    }

    ProxyNode copy = node;
    std::string base = copy.name;
    if (base.empty()) base = copy.server + ":" + std::to_string(copy.port);

    // Clash 要求 proxy 名称唯一，否则加载失败
    std::string candidate = base;
    int suffix = 2;
    while (!seen_name.insert(candidate).second) {
      candidate = base + " " + std::to_string(suffix++);
      if (suffix > 10000) break;
    }
    copy.name = candidate;
    out.push_back(std::move(copy));
  }

  if (opts.sort) {
    std::stable_sort(out.begin(), out.end(),
                     [](const ProxyNode& a, const ProxyNode& b) { return a.name < b.name; });
  }
  return out;
}

// ---------------------------------------------------------------------------
// 目标名规范化
// ---------------------------------------------------------------------------
namespace {

struct TargetAlias {
  const char* alias;
  const char* canonical;
};

// 别名 -> 规范名
constexpr std::array<TargetAlias, 43> kTargetAliases{{
    {"clash", "clash"},        {"clash.meta", "clash"},   {"clashmeta", "clash"},
    {"meta", "clash"},         {"mihomo", "clash"},       {"clashplus", "clash"},
    {"clash-plus", "clash"},   {"clashr", "clash"},       {"clash-premium", "clash"},
    {"premium", "clash"},      {"clashpremium", "clash"}, {"xray", "xray"},
    {"v2ray", "xray"},         {"xray-json", "xray"},     {"v2ray-json", "xray"},
    {"v2rayjson", "xray"},     {"xrayjson", "xray"},      {"singbox", "singbox"},
    {"sing-box", "singbox"},   {"sb", "singbox"},         {"sing_box", "singbox"},
    {"surge", "surge"},        {"loon", "loon"},          {"quanx", "quanx"},
    {"quantumultx", "quanx"},  {"quantumult", "quanx"},   {"surfboard", "surfboard"},
    {"stash", "stash"},        {"mixed", "mixed"},        {"base64", "base64"},
    {"v2ray-sub", "base64"},   {"trojan-sub", "base64"},  {"sssub", "base64"},
    {"clash-sub", "clash"},    {"v2rayng", "base64"},     {"v2rayng-sub", "base64"},
    {"links", "links"},        {"share", "links"},        {"sharelinks", "links"},
    {"v2rayng-links", "links"}, {"v2rayn", "v2rayn"},     {"v2rayn-share", "v2rayn"},
    {"v2rayn-full", "v2rayn"},
}};

}  // namespace

std::string normalize_target(std::string_view t) {
  const std::string key = codec::to_lower(codec::trim(t));
  if (key.empty()) return {};
  for (const auto& a : kTargetAliases) {
    if (key == a.alias) return a.canonical;
  }
  return {};
}

std::vector<std::string> implemented_targets() {
  return {"clash", "xray", "singbox", "links", "base64", "v2rayn"};
}

std::vector<std::string> planned_targets() {
  return {"surge", "loon", "quanx", "surfboard", "stash", "mixed"};
}

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------
Result<std::string> emit_config(const NodeList& nodes, const EmitOptions& opts,
                                std::vector<std::string>* warnings) {
  if (nodes.empty()) return fail("没有可输出的节点");

  const std::string target = normalize_target(opts.target);
  if (target.empty()) {
    return fail("无法识别的输出目标: " + opts.target +
                "（已实现: " + codec::join(implemented_targets(), ", ") + "）");
  }

  // VLESS Encryption / XTLS Vision 的可移植性告警：这类问题在客户端上的表现都是
  // 「连上了但没有数据 / 全部 -1」，光看配置根本看不出来，所以在这里统一提示一次，
  // 与具体输出目标无关（各渲染器只负责把参数照抄过去）。
  if (warnings != nullptr) {
    for (const auto& node : nodes) {
      std::string warning = vless_encryption_warning(node);
      if (!warning.empty()) warnings->push_back(std::move(warning));
    }
  }

  if (target == "clash") return emit_clash(nodes, opts, warnings);
  if (target == "xray") return emit_xray(nodes, opts, warnings);
  if (target == "singbox") return emit_singbox(nodes, opts, warnings);
  if (target == "links") return emit_sharelinks(nodes, opts, ShareMode::Links, warnings);
  if (target == "base64") return emit_sharelinks(nodes, opts, ShareMode::Base64, warnings);
  if (target == "v2rayn") return emit_sharelinks(nodes, opts, ShareMode::V2rayN, warnings);

  return fail("输出目标 " + target + " 尚未实现（已实现: " +
              codec::join(implemented_targets(), ", ") + "；规划中: " +
              codec::join(planned_targets(), ", ") + "）");
}

}  // namespace subconv
