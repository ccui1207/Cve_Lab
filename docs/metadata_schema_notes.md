# Android CVE Metadata Schema Notes

## 1. 设计目标

统一不同 Android CVE case 的结构化记录方式，为后续 condition-to-environment matching 工具做准备。

## 2. 核心字段

- version_condition
- patch_level_condition
- component_condition
- trigger_condition
- permission_condition
- user_context_condition
- sample_condition
- patch_condition
- patch_effect_matrix
- failure_reason_taxonomy

## 3. Janus 与 CVE-2025-32333 的差异

| Case | 主要条件类型 | 示例 |
|---|---|---|
| CVE-2017-13156 Janus | 签名方案 / 补丁级别 / 样本类型 | v1-only、Android 7.0、tampered control |
| CVE-2025-32333 | 组件入口 / 触发输入 / 用户上下文 / patch 机制 | SpaActivity.kt、malformed packageName、cross-user relevance、format check |

## 4. 后续工具用途

后续工具会读取每个 case 的 metadata.yaml，输出：

- CVE 基本信息
- 关键复现条件
- 当前环境缺失项
- patch-effect matrix
- 可能失败原因