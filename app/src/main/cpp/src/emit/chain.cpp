// 链式代理（前置 / 后置）：把 EmitOptions.chain / chain_rear 解析成可直接写进产物的链路计划。
//
// 三个内核表达链路的字段完全不同，但语义一样：「本出站的底层连接先交给另一条出站去建」。
//   * Xray    ：`streamSettings.sockopt.dialerProxy`（文档原话：一个出站代理的标识，
//               通常用于配置链式代理）—— https://xtls.github.io/config/transports/sockopt.html
//   * mihomo  ：代理级 `dialer-proxy` —— https://wiki.metacubex.one/config/proxies/dialer-proxy/
//   * sing-box：出站 / endpoint 的 `detour`（Dial Fields：「上游出站的 tag」）
//               —— https://sing-box.sagernet.org/configuration/shared/dial/
//
// 因为字段的含义是「**我**经谁出去」，所以链的方向与「谁拨号到目标」是反的：
//   * 前置 `chain`：本地 → chain[0] → … → chain[n] → 每个节点，**节点自己拨号到目标**，
//     于是每个节点的 dialerProxy 指向 chain 末端。（chain[0] 最外侧，直连出去。）
//   * 后置 `chain_rear`：… → 每个节点 → rear[0] → … → rear[m]，**末端拨号到目标**，
//     于是流量落点是 rear 末端，末端出站反而要指向它前面那一跳。
//     正因为「末端才是落点」，后置必须**每个节点克隆一份**（rear[0] 得经各自的节点出去）。
// 两者可以同时给，合成「本地 → chain… → 节点 → chain_rear… → 目标」。
#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "emit_internal.hpp"
#include "subconv/codec.hpp"
#include "subconv/convert.hpp"

namespace subconv {
namespace {

/// 链路项是不是一条分享链接（而不是订阅里的节点名）。
bool looks_like_link(const std::string& item) {
  return item.find("://") != std::string::npos;
}

/// 在订阅里按名字找节点：先精确、再忽略大小写、最后比对输入侧原名。
const ProxyNode* find_node(const NodeList& nodes, const std::string& wanted) {
  for (const auto& n : nodes) {
    if (n.name == wanted) return &n;
  }
  for (const auto& n : nodes) {
    if (codec::iequals(n.name, wanted)) return &n;
  }
  for (const auto& n : nodes) {
    if (!n.source_name.empty() &&
        (n.source_name == wanted || codec::iequals(n.source_name, wanted))) {
      return &n;
    }
  }
  return nullptr;
}

}  // namespace

const std::string& ChainPlan::tail() const noexcept {
  static const std::string kEmpty;
  return hops.empty() ? kEmpty : hops.back().tag;
}

const std::string& RearChain::target() const noexcept {
  static const std::string kEmpty;
  return hops.empty() ? kEmpty : hops.back().tag;
}

const RearChain* ChainPlan::rear_for(const std::string& node_name) const {
  const auto it = rear.find(node_name);
  if (it == rear.end() || !it->second.active()) return nullptr;
  return &it->second;
}

namespace {

/// 解析一个链路项：分享链接 → 独立出站；订阅节点名（可写 `@名字`）→ 复用该节点的定义。
/// 返回的 hop 只保证 `node` 与 `extra` 有效 —— tag 的唯一化规则前置 / 后置不同，交给调用方。
/// `used_names` 记录这条链里已经用过的订阅节点名，用来挡住自环 / 重复引用。
Result<ChainHop> parse_chain_hop(const std::string& item, const NodeList& prepared,
                                 std::set<std::string>& used_names) {
  ChainHop hop;
  if (looks_like_link(item)) {
    // 名字优先取链接的 fragment（`#名字`）；没有就退到 server:port。
    auto parsed = parse_node(item);
    if (!parsed) {
      return fail("链路项 " + item + " 不是可用的分享链接：" +
                  std::string(parsed.error().what()));
    }
    hop.node = std::move(*parsed);
    if (hop.node.name.empty()) {
      hop.node.name = hop.node.server + ":" + std::to_string(hop.node.port);
    }
    hop.extra = true;
    return hop;
  }

  std::string wanted = item;
  if (!wanted.empty() && wanted.front() == '@') wanted.erase(0, 1);
  wanted = codec::trim(wanted);
  const ProxyNode* found = find_node(prepared, wanted);
  if (found == nullptr) {
    return fail("链路项 " + item + " 既不是分享链接，也不是订阅里的节点名");
  }
  if (!used_names.insert(found->name).second) {
    return fail("链路里节点 " + found->name + " 出现了两次：会形成自环");
  }
  hop.node = *found;
  hop.tag = found->name;
  hop.extra = false;   // 复用节点表里那一条出站，不重复产出
  return hop;
}

/// 把一个节点的后置链路展开出来：模板逐项克隆，**由内到外**接在这个节点后面。
///
/// 出站名刻意**不顶替节点原名**，而是把链路直接写出来（`节点 → 后置`）：
/// 后置的成员是「另一条出站」，让末端冒用节点名会出现「名叫 A 的出站里装的却是 B 的配置」，
/// 那正好是这个项目最不想看到的那种"看起来对、其实链错了"的表述。
RearChain expand_rear(const ProxyNode& node, const std::vector<ChainHop>& tmpl,
                      std::set<std::string>& taken) {
  RearChain rc;
  if (tmpl.empty()) return rc;

  std::string prev = node.name;   // 第 0 跳经这个节点出去
  for (const auto& item : tmpl) {
    ChainHop hop = item;
    hop.extra = true;   // 后置每一跳都要独立产出：它必须经「自己那个节点」出去
    hop.dialer = prev;
    // 名字带节点前缀：既保留链路信息，又保证不同节点的同名后置跳点不会互相撞名。
    hop.tag = unique_name(taken, node.name + " → " + item.node.name);
    hop.node.name = hop.tag;
    prev = hop.tag;
    rc.hops.push_back(std::move(hop));
  }
  return rc;
}

}  // namespace

std::string ChainPlan::dialer_for(const std::string& node_name) const {
  if (hops.empty()) return {};
  // 引用了订阅里节点的跳点本身也是一个可选节点：它用自己那一跳的 dialer，
  // 否则「A 通过 A 出去」就成了自环。
  for (const auto& hop : hops) {
    if (!hop.extra && hop.tag == node_name) return hop.dialer;
  }
  return tail();
}

Result<ChainPlan> resolve_chain(const NodeList& prepared, const EmitOptions& opts,
                                std::vector<std::string>* warnings) {
  ChainPlan plan;
  if (opts.chain.empty() && opts.chain_rear.empty()) return plan;

  std::set<std::string> taken;
  for (const auto& n : prepared) taken.insert(n.name);

  const bool override_input_refs =
      std::any_of(prepared.begin(), prepared.end(),
                  [](const ProxyNode& n) { return !n.dialer_proxy.empty(); });
  if (override_input_refs && warnings != nullptr) {
    warnings->push_back(
        "链路生效：节点自带的 dialerProxy / dialer-proxy 引用已被 --chain / --chain-rear 覆盖");
  }

  // ---- 前置链路：本地 → chain[0] → chain[1] → … → 每个节点 ----
  std::set<std::string> front_used;   // 前置里已经用过的订阅节点名（防自环 / 重复）
  for (const auto& raw : opts.chain) {
    const std::string item = codec::trim(raw);
    if (item.empty()) continue;

    auto parsed = parse_chain_hop(item, prepared, front_used);
    if (!parsed) return fail(parsed.error());
    ChainHop hop = std::move(*parsed);
    if (hop.extra) {
      // 外部分享链接要作为独立出站追加，名字必须与订阅里已有节点、以及链路里其它跳点都不同
      hop.tag = unique_name(taken, hop.node.name);
      hop.node.name = hop.tag;
    }
    // 每一跳的底层连接交给上一跳去建；最外侧那一跳直连出去。
    hop.dialer = plan.hops.empty() ? std::string() : plan.hops.back().tag;
    plan.hops.push_back(std::move(hop));
  }

  // ---- 后置链路：每个节点 → chain_rear[0] → … → 末端（末端才是流量落点）----
  if (!opts.chain_rear.empty()) {
    std::vector<ChainHop> tmpl;      // 模板：tag 不在这里定，按节点各克隆一份
    std::set<std::string> rear_used;
    for (const auto& raw : opts.chain_rear) {
      const std::string item = codec::trim(raw);
      if (item.empty()) continue;
      auto parsed = parse_chain_hop(item, prepared, rear_used);
      if (!parsed) return fail(parsed.error());
      if (parsed->extra) {
        // 模板项不需要全局唯一的 tag，但名字要在（后面拿它拼「节点 · 跳点」）。
        if (parsed->node.name.empty()) {
          parsed->node.name = parsed->node.server + ":" + std::to_string(parsed->node.port);
        }
      }
      tmpl.push_back(std::move(*parsed));
    }
    if (tmpl.empty()) return plan;   // 给的全是空串：等价于没给
    for (const auto& node : prepared) {
      plan.rear.emplace(node.name, expand_rear(node, tmpl, taken));
    }
  }

  return plan;
}

std::map<std::string, std::string> build_dialer_index(const NodeList& prepared) {
  // 值 == "" 表示「这个标识在输入里有歧义」（两条不同出站共用一个 tag / 代理名），
  // 调用方必须拒绝解析而不是按订阅顺序赌一个目标。
  std::map<std::string, std::string> index;
  for (const auto& n : prepared) {
    // 输入侧的引用可能写出站 tag（Xray），也可能写代理名（mihomo），两个都记。
    for (const std::string& key : {n.source_name, n.name}) {
      if (key.empty()) continue;
      auto [it, inserted] = index.try_emplace(key, n.name);
      if (!inserted && it->second != n.name) it->second.clear();   // 歧义：标空
    }
  }
  return index;
}

std::string effective_dialer(const ProxyNode& node, const ChainPlan& plan,
                             const std::map<std::string, std::string>& ref_index,
                             std::vector<std::string>* warnings) {
  if (plan.active()) return plan.dialer_for(node.name);
  if (node.dialer_proxy.empty()) return {};

  const auto it = ref_index.find(node.dialer_proxy);
  if (it != ref_index.end() && it->second.empty()) {
    if (warnings != nullptr) {
      warnings->push_back("节点 " + node.name + "：dialerProxy / dialer-proxy 指向的 " +
                          node.dialer_proxy +
                          " 在输入里有歧义（有两个不同的出站用了同一个标识），已按直连处理");
    }
    return {};
  }
  if (it == ref_index.end()) {
    if (warnings != nullptr) {
      warnings->push_back("节点 " + node.name + "：dialerProxy / dialer-proxy 指向的 " +
                          node.dialer_proxy +
                          " 不在本次输出里，已按直连处理（原配置的链式代理会丢失）");
    }
    return {};
  }
  // 自己指向自己：真写进产物就是个死循环（内核会直接起不来或首连挂死）。
  if (it->second == node.name) {
    if (warnings != nullptr) {
      warnings->push_back("节点 " + node.name +
                          "：dialerProxy / dialer-proxy 指向它自己，已按直连处理");
    }
    return {};
  }
  return it->second;
}

std::vector<std::string> dialer_cycle(const NodeList& prepared,
                                      const std::map<std::string, std::string>& ref_index) {
  // 只看「引用命中且无歧义」的那部分边：命中不到、歧义、以及指向自己的，
  // 都已经在 effective_dialer 里降成直连。
  std::map<std::string, std::string> edges;
  for (const auto& node : prepared) {
    if (node.dialer_proxy.empty()) continue;
    const auto it = ref_index.find(node.dialer_proxy);
    if (it == ref_index.end() || it->second.empty() || it->second == node.name) continue;
    edges[node.name] = it->second;
  }
  if (edges.empty()) return {};

  // 三色 DFS：0 = 未访问、1 = 在当前路径上、2 = 已确认无环
  std::map<std::string, int> color;
  std::vector<std::string> path;
  for (const auto& [start, target] : edges) {
    (void)target;
    if (color[start] != 0) continue;
    path.clear();
    std::string current = start;
    while (true) {
      color[current] = 1;
      path.push_back(current);
      const auto next = edges.find(current);
      if (next == edges.end()) break;               // 走到直连出口：这条链没有环
      if (color[next->second] == 1) {               // 回到当前路径上的节点 = 有环
        std::vector<std::string> cycle;
        bool inside = false;
        for (const auto& name : path) {
          if (name == next->second) inside = true;
          if (inside) cycle.push_back(name);
        }
        cycle.push_back(next->second);
        return cycle;
      }
      if (color[next->second] == 2) break;          // 汇入一条已确认无环的链
      current = next->second;
    }
    for (const auto& name : path) color[name] = 2;
  }
  return {};
}

std::string chain_exit_caveat(const ProxyNode& node) {
  switch (node.protocol) {
    case Protocol::Hysteria:
    case Protocol::Hysteria2:
    case Protocol::Tuic:
    case Protocol::WireGuard:
      return node.name + "（" + std::string(to_string(node.protocol)) + "）";
    default:
      break;
  }
  if (node.network == Network::Quic || node.network == Network::Kcp) {
    return node.name + "（" + std::string(to_string(node.network)) + " 传输）";
  }
  return {};
}

}  // namespace subconv
