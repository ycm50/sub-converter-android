// JSON 基础设施：vendor 的 nlohmann/json 单头文件封装
//
// 选用 ordered_json，因为它保留插入顺序 —— 生成的 Xray / sing-box 配置
// 字段顺序稳定，diff 友好。解析也走同一类型，减少心智负担。
#pragma once

#include <nlohmann/json.hpp>

namespace subconv {

using Json = nlohmann::ordered_json;

}  // namespace subconv
