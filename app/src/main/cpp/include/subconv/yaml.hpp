// 轻量 YAML 输出器：只做「生成」，不做解析。
// 目标：确定性输出、key 顺序可控、按需加引号，产出 mihomo / Clash 可直接加载的文本。
#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace subconv {

class Yaml {
 public:
  enum class Kind { Null, Scalar, Sequence, Mapping };

  Yaml() = default;

  // --- 构造 ---------------------------------------------------------------
  static Yaml scalar(std::string v);
  static Yaml scalar(const char* v) { return scalar(std::string(v)); }
  /// 预渲染标量：按字面输出，不做引号判断（用于数字、布尔）。
  static Yaml raw(std::string v);
  static Yaml boolean(bool v) { return raw(v ? "true" : "false"); }
  static Yaml integer(long long v);
  static Yaml sequence();
  static Yaml mapping();
  static Yaml null() { return Yaml(); }

  // --- 查询 ---------------------------------------------------------------
  [[nodiscard]] Kind kind() const noexcept { return kind_; }
  [[nodiscard]] bool is_null() const noexcept { return kind_ == Kind::Null; }
  [[nodiscard]] bool is_scalar() const noexcept { return kind_ == Kind::Scalar; }
  [[nodiscard]] bool is_sequence() const noexcept { return kind_ == Kind::Sequence; }
  [[nodiscard]] bool is_mapping() const noexcept { return kind_ == Kind::Mapping; }
  [[nodiscard]] bool empty() const noexcept;
  [[nodiscard]] bool is_block() const noexcept {
    return !empty() && (kind_ == Kind::Sequence || kind_ == Kind::Mapping);
  }

  [[nodiscard]] const std::string& as_string() const noexcept { return scalar_; }
  [[nodiscard]] const std::vector<Yaml>& items() const noexcept { return seq_; }
  [[nodiscard]] const std::vector<std::pair<std::string, Yaml>>& pairs() const noexcept {
    return map_;
  }

  // --- 构建 ---------------------------------------------------------------
  Yaml& push(Yaml v);                       ///< 追加序列元素
  Yaml& set(std::string key, Yaml v);       ///< 设置映射键（保持插入顺序，重复键覆盖）
  [[nodiscard]] bool has(std::string_view key) const noexcept;
  [[nodiscard]] const Yaml* get(std::string_view key) const noexcept;

  // --- 序列化 -------------------------------------------------------------
  [[nodiscard]] std::string dump() const;
  /// 标量/空容器的单行渲染。
  [[nodiscard]] std::string render() const;

  // --- 引号策略（公开以便单测）--------------------------------------------
  [[nodiscard]] static bool needs_quoting(std::string_view s);
  [[nodiscard]] static std::string quote(std::string_view s);

 private:
  void write_block(std::string& out, int indent) const;
  void write_mapping(std::string& out, int indent, bool inline_first) const;
  void write_sequence(std::string& out, int indent) const;

  Kind kind_ = Kind::Null;
  bool plain_ = false;   ///< true 表示标量已预渲染，跳过引号判断
  std::string scalar_;
  std::vector<Yaml> seq_;
  std::vector<std::pair<std::string, Yaml>> map_;
};

}  // namespace subconv
