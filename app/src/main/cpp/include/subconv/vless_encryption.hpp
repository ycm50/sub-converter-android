// VLESS Encryption（Xray 的「VLESS 加密」/ XTLS Vision Seed）参数解析与校验。
//
// 分享链接里的形态是 query 的 `encryption=`，Clash(mihomo) YAML 里是同名的 proxy 字段
// `encryption:`，值是若干用 `.` 连接的块：
//
//   mlkem768x25519plus.native.0rtt.100-111-1111.75-0-111.50-0-3333.<客户端认证参数>
//   └─ 握手方式 ────┘└ 外观 ┘└ RTT ┘└───── padding / delay ─────┘└───── key ─────┘
//
// 依据 Xray 官方文档 config/outbounds/vless.html「VLESS（XTLS Vision Seed）」：
//   * 第 1 块 握手方式：目前有且仅有 `mlkem768x25519plus`，要求与服务端一致；
//   * 第 2 块 流量外观：`native` / `xorpub` / `random`，要求与服务端一致；
//   * 第 3 块 会话恢复：`0rtt`（跟随服务端票据）或 `1rtt`（强制完整握手）；
//   * 之后是 padding.delay.padding(.delay.padding)*，可省略；每块格式 `概率-最小-最大`，
//     首个 padding 块要求概率 100% 且最小长度 > 0；整段省略时内核用
//     `100-111-1111.75-0-111.50-0-3333`；
//   * 最后一块是客户端认证参数（`xray mlkem768` 的 Client 段），必须与服务端对应。
//
// 为什么要单独建模：**它决定了 VLESS 头能否被服务端解开**。丢了这一项，服务端既不回包
// 也不断开连接，客户端看到的只是「连上了但一直没数据」的静默黑洞，最长要等到拨号超时才报错，
// 极难定位。而转发订阅的中间层很容易把它漏掉（把 vless:// 转成 Clash 时最典型）。
//
// 另一条文档里的硬约束（会直接导致握手失败，所以一并给告警）：`flow` 的 XTLS 只在
//   * TCP + TLS/REALITY，或
//   * 已启用 VLESS Encryption（此时底层传输不限，ws / xhttp 都行）
// 这两种搭配下可用。
#pragma once

#include <cstddef>
#include <string>
#include <string_view>

#include "subconv/types.hpp"

namespace subconv {

/// `encryption` 串解析出来的结构。字段都只是「读出来的东西」，不做任何改写。
struct VlessEncryption {
  bool present = false;            ///< 生效（不是空串 / `none`）
  std::string raw;                 ///< 原值（已 trim），输出时照抄
  std::string handshake;           ///< 第 1 块：握手方式
  std::string appearance;          ///< 第 2 块：流量外观
  std::string rtt;                 ///< 第 3 块：会话恢复
  std::size_t padding_blocks = 0;  ///< 中间 padding + delay 块数（0 = 交给内核用默认值）
  std::string key;                 ///< 最后一块：客户端认证参数
  /// 空 = 结构与文档一致；非空 = 一句人话描述的问题。
  /// 注意：**有问题也只告警，值依旧按原样透传** —— 本工具不是 Xray，不替内核判死。
  std::string problem;
};

/// 解析 `encryption=` / `encryption:` 的值（`none` 大小写不敏感地识别）。
[[nodiscard]] VlessEncryption parse_vless_encryption(std::string_view value);

/// 规范化：去首尾空白；`none`（任意大小写）折成空串 —— 空串即「不加密」。
[[nodiscard]] std::string normalize_vless_encryption(std::string_view value);

/// 节点的 VLESS Encryption 原值。先看 ProxyNode::encryption，再回退到 extra["encryption"]
/// （历史版本把该值存在 extra 里，读起来让老调用方也能工作）。
[[nodiscard]] std::string vless_encryption_of(const ProxyNode& node);

/// 该节点是否启用了 VLESS Encryption。
[[nodiscard]] bool vless_encryption_enabled(const ProxyNode& node);

/// 该节点在 VLESS Encryption / XTLS Vision 上的可移植性告警；没问题返回空串。
///
/// 覆盖两类真实踩坑：
///   1. `encryption` 结构对不上文档（被中间层截断、改写，或者客户端 key 抄漏）；
///   2. `flow=xtls-rprx-vision` 但既不是 TCP+TLS/REALITY、也没开 VLESS Encryption ——
///      XTLS Vision 在这种组合下必然握手失败（Xray 报
///      `vision: not a valid supported TLS connection`，mihomo 直接 503）。
[[nodiscard]] std::string vless_encryption_warning(const ProxyNode& node);

}  // namespace subconv
