// VLESS Encryption 参数的解析与校验（见 include/subconv/vless_encryption.hpp）
#include "subconv/vless_encryption.hpp"

#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

#include "subconv/codec.hpp"

namespace subconv {
namespace {

/// 握手方式：目前 Xray 有且仅有这一个，服务端与客户端必须一致。
constexpr const char* kHandshake = "mlkem768x25519plus";

/// padding / delay 块解出来的 `概率-最小-最大`。
/// 刻意不叫 min/max：Windows 的 <windows.h> 会把这两个名字定义成宏，一旦被带进来就会炸。
struct Range {
  int probability = 0;
  int lo = 0;
  int hi = 0;
};

bool parse_uint(std::string_view text, int& out) {
  if (text.empty() || text.size() > 9) return false;
  int value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') return false;
    value = value * 10 + (c - '0');
  }
  out = value;
  return true;
}

/// `概率-最小-最大`：三段都必须是非负整数（负数、少一段、多一段都不合法）。
bool parse_range(std::string_view text, Range& out) {
  const std::size_t first = text.find('-');
  if (first == std::string_view::npos) return false;
  const std::size_t second = text.find('-', first + 1);
  if (second == std::string_view::npos) return false;
  if (text.find('-', second + 1) != std::string_view::npos) return false;
  return parse_uint(text.substr(0, first), out.probability) &&
         parse_uint(text.substr(first + 1, second - first - 1), out.lo) &&
         parse_uint(text.substr(second + 1), out.hi);
}

bool one_of(std::string_view value, std::initializer_list<const char*> candidates) {
  for (const char* candidate : candidates) {
    if (codec::iequals(value, candidate)) return true;
  }
  return false;
}

/// 认证参数动辄上千字符，告警里只引用前一小段。
std::string preview(const std::string& text, std::size_t limit = 24) {
  if (text.size() <= limit) return text;
  return text.substr(0, limit) + "…";
}

}  // namespace

std::string normalize_vless_encryption(std::string_view value) {
  const std::string text = codec::trim(value);
  if (text.empty() || codec::iequals(text, "none")) return {};
  return text;
}

VlessEncryption parse_vless_encryption(std::string_view value) {
  VlessEncryption info;
  info.raw = normalize_vless_encryption(value);
  if (info.raw.empty()) return info;  // present 保持 false：这就是「不加密」
  info.present = true;

  // codec::split 会保留空段，正好能识别 `a..b` / 结尾多一个 `.` 这类手抖
  const std::vector<std::string> blocks = codec::split(info.raw, '.');
  // 只留第一个问题：最靠前的那处通常就是根因，堆一串反而看不清
  const auto bad = [&info](std::string message) {
    if (info.problem.empty()) info.problem = std::move(message);
  };

  if (blocks.size() >= 1) info.handshake = blocks[0];
  if (blocks.size() >= 2) info.appearance = blocks[1];
  if (blocks.size() >= 3) info.rtt = blocks[2];
  if (blocks.size() >= 4) info.key = blocks.back();
  if (blocks.size() > 4) info.padding_blocks = blocks.size() - 4;

  if (blocks.size() < 4) {
    bad("块数不足，至少要有 `握手方式.流量外观.RTT.认证参数` 四块");
  }
  for (std::size_t i = 0; i < blocks.size(); ++i) {
    if (blocks[i].empty()) {
      bad("第 " + std::to_string(i + 1) + " 块是空的（多写了一个 `.`）");
      break;
    }
  }

  if (!info.handshake.empty() && !codec::iequals(info.handshake, kHandshake)) {
    bad("握手方式 \"" + preview(info.handshake) + "\" 不是 Xray 支持的 " + kHandshake);
  }
  if (!info.appearance.empty() && !one_of(info.appearance, {"native", "xorpub", "random"})) {
    bad("流量外观 \"" + preview(info.appearance) + "\" 不是 native / xorpub / random");
  }
  if (!info.rtt.empty() && !one_of(info.rtt, {"0rtt", "1rtt"})) {
    bad("会话恢复 \"" + preview(info.rtt) + "\" 不是 0rtt / 1rtt");
  }

  // 中间的 padding / delay：以 padding 开头、padding 与 delay 交替、以 padding 结尾
  for (std::size_t i = 0; i < info.padding_blocks; ++i) {
    const std::string& text = blocks[3 + i];
    const bool is_padding = (i % 2 == 0);
    Range range;
    if (!parse_range(text, range)) {
      bad("第 " + std::to_string(4 + i) + " 块 \"" + preview(text) +
          "\" 不是 `概率-最小-最大` 形式");
      continue;
    }
    if (range.probability > 100) {
      bad("第 " + std::to_string(4 + i) + " 块 \"" + preview(text) + "\" 的概率超过 100");
    } else if (range.lo > range.hi) {
      bad("第 " + std::to_string(4 + i) + " 块 \"" + preview(text) + "\" 的最小值大于最大值");
    } else if (is_padding && i == 0 && (range.probability != 100 || range.lo == 0)) {
      bad("首个 padding 块要求概率 100% 且最小长度 > 0，实际是 \"" + preview(text) + "\"");
    } else if (!is_padding && i + 1 == info.padding_blocks) {
      bad("padding/delay 必须以 padding 结尾，当前以 delay 块 \"" + preview(text) + "\" 结尾");
    }
  }

  return info;
}

std::string vless_encryption_of(const ProxyNode& node) {
  if (!node.encryption.empty()) return node.encryption;
  const auto it = node.extra.find("encryption");
  if (it == node.extra.end()) return {};
  return normalize_vless_encryption(it->second);
}

bool vless_encryption_enabled(const ProxyNode& node) {
  return !vless_encryption_of(node).empty();
}

std::string vless_encryption_warning(const ProxyNode& node) {
  if (node.protocol != Protocol::Vless) return {};

  const std::string encryption = vless_encryption_of(node);
  if (!encryption.empty()) {
    const VlessEncryption info = parse_vless_encryption(encryption);
    if (info.problem.empty()) return {};
    return "节点 " + node.name + "（vless）的 encryption 参数看着不对：" + info.problem +
           "；已按原样保留，建议用 `xray vlessenc` 重新生成";
  }

  // 没开 VLESS Encryption 时，XTLS Vision 只剩「TCP + TLS/REALITY」这一种合法搭配
  if (node.flow.rfind("xtls-rprx-vision", 0) != 0) return {};
  if (node.network == Network::Tcp && node.tls.enabled) return {};

  return "节点 " + node.name + "（vless）：flow=" + node.flow +
         " 只在「TCP + TLS/REALITY」或「已启用 VLESS Encryption」时可用，当前是 " +
         std::string(to_string(node.network)) +
         (node.tls.enabled ? " + TLS" : " 且没有 TLS") +
         "，握手必然失败（内核报 vision: not a valid supported TLS connection）";
}

}  // namespace subconv
