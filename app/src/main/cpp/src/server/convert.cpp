// 转换核心：来源 / 粘贴内容 → 配置文本
//
// 与 HTTP 层解耦：不创建 socket、不写文件，方便单测直接调用。
#include <algorithm>
#include <utility>

#include "subconv/codec.hpp"
#include "subconv/convert.hpp"
#include "subconv/server.hpp"

namespace subconv::server {

std::string default_filename(std::string_view target) {
  const std::string canonical = normalize_target(target);
  if (canonical.empty()) return "subconv-config.txt";
  if (canonical == "clash") return "subconv-clash.yaml";
  if (canonical == "links") return "subconv-links.txt";
  if (canonical == "base64") return "subconv-subscription.txt";
  if (canonical == "v2rayn") return "subconv-v2rayn.txt";
  return "subconv-" + canonical + ".json";
}

namespace {

/// 扩展名部分是否像扩展名（".yaml"/".7z" 像，订阅名里的 "v1.2" 不像：单字符后缀一律不算）。
bool has_extension(const std::string& name) {
  const std::size_t dot = name.rfind('.');
  if (dot == std::string::npos || dot == 0 || dot + 1 >= name.size()) return false;
  const std::string suffix = name.substr(dot + 1);
  if (suffix.size() < 2 || suffix.size() > 5) return false;
  for (const char c : suffix) {
    const bool alnum = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    if (!alnum) return false;
  }
  return true;
}

/// 默认文件名的扩展名（".yaml" / ".json" / ".txt"）。
std::string default_extension(std::string_view target) {
  const std::string fallback = default_filename(target);
  const std::size_t dot = fallback.rfind('.');
  return dot == std::string::npos ? std::string() : fallback.substr(dot);
}

/// 剔掉路径分隔符与 Windows 非法字符，压掉首尾空白与点。
std::string sanitize_name(const std::string& raw) {
  std::string out;
  out.reserve(raw.size());
  bool last_space = false;
  for (const char c : raw) {
    const unsigned char u = static_cast<unsigned char>(c);
    if (u < 0x20 || c == 0x7F) continue;                       // 控制字符
    if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' ||
        c == '>' || c == '|') {
      continue;                                                // 路径/文件名非法字符
    }
    if (c == ' ' || c == '\t') {
      if (last_space || out.empty()) continue;
      last_space = true;
    } else {
      last_space = false;
    }
    out.push_back(c);
  }
  while (!out.empty() && (out.back() == ' ' || out.back() == '.')) out.pop_back();
  if (out.size() > 96) {
    out.resize(96);
    while (!out.empty() && (static_cast<unsigned char>(out.back()) & 0xC0) == 0x80) out.pop_back();
  }
  return out;
}

}  // namespace

std::string filename_for(std::string_view name, std::string_view target) {
  const std::string cleaned = sanitize_name(codec::trim(name));
  if (cleaned.empty()) return default_filename(target);
  if (has_extension(cleaned)) return cleaned;
  return cleaned + default_extension(target);
}

Result<ConvertResult> convert(const ConvertRequest& req) {
  if (req.sources.empty() && codec::trim(req.content).empty()) {
    return fail("没有输入：请提供订阅链接（url）或订阅内容（content）");
  }

  const std::string target = normalize_target(req.emit.target);
  if (target.empty()) {
    return fail("无法识别的输出目标: " + req.emit.target +
                "（已实现: " + codec::join(implemented_targets(), ", ") + "）");
  }

  NodeList all;
  SubscriptionInfo info;
  std::vector<std::string> warnings;

  auto absorb = [&](const Subscription& sub, const std::string& label) {
    for (const auto& w : sub.warnings) warnings.push_back(label + "：" + w);
    all.insert(all.end(), sub.nodes.begin(), sub.nodes.end());
    if (sub.info.has_any()) {
      info.upload += sub.info.upload;
      info.download += sub.info.download;
      info.total += sub.info.total;
      info.expire = std::max(info.expire, sub.info.expire);
    }
  };

  for (const auto& source : req.sources) {
    if (codec::trim(source).empty()) continue;
    auto sub = fetch::load_source(source, req.load);
    if (!sub) return fail_with("加载 " + source + " 失败", sub.error());
    absorb(*sub, source);
  }

  if (!codec::trim(req.content).empty()) {
    auto sub = fetch::parse_content(req.content, "粘贴内容");
    if (!sub) return fail_with("解析粘贴内容失败", sub.error());
    absorb(*sub, "粘贴内容");
  }

  if (all.empty()) {
    std::string detail;
    if (!warnings.empty()) detail = "；跳过原因：" + codec::join(warnings, "；");
    return fail("没有解析到任何节点" + detail);
  }

  EmitOptions emit = req.emit;
  emit.target = target;
  // 订阅名（可空）：只用于配置首行注释，没给就不写 —— 别把默认名当成用户起的名字
  const std::string given_name =
      !codec::trim(req.filename).empty() ? codec::trim(req.filename) : codec::trim(emit.filename);
  emit.filename = given_name;

  if (emit.probe_cert) {
    const std::size_t probed = fetch::probe_node_certificates(all, emit.probe_cert_timeout_seconds,
                                                              &warnings);
    if (probed > 0) {
      warnings.push_back("已探测 " + std::to_string(probed) + " 个证书指纹（probe_cert=1）");
    }
  }

  auto config = emit_config(all, emit, &warnings);
  if (!config) return fail(config.error());

  ConvertResult out;
  out.nodes = all.size();
  out.config = std::move(*config);
  // 下载文件名：按目标补扩展名 + 剔除 Windows 非法字符；没给名字则回落默认名
  out.filename = filename_for(given_name, target);
  out.warnings = std::move(warnings);
  out.info = info;
  return out;
}

}  // namespace subconv::server
