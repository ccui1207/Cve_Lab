# Android CVE Metadata Schema Notes

## 1. 设计目标

本文件记录 `metadata.yaml` 的统一结构设计，用于支撑后续 Android CVE case 的标准化记录、复现条件推理、补丁生效验证和工具化分析。

当前仓库中的 `analysis.md` 主要面向人工阅读，记录官方资料、漏洞背景、patch diff、验证矩阵和阶段性结论；`metadata.yaml` 主要面向工具读取，用于后续自动化处理。

统一 metadata 的目标是：

- 让不同 Android CVE case 使用同一套顶层字段。
- 支持后续工具读取每个 case 的复现条件。
- 支持 condition-to-environment matching。
- 支持 patch-effect validation matrix。
- 支持 failure reason taxonomy。
- 避免每个 CVE case 都用完全不同的记录格式。

---

## 2. 默认顶层结构

后续每个 CVE case 的 `metadata.yaml` 默认采用以下顶层字段：

```yaml
cve:
name:
platform:
category:

component:

official_references:

official_description:

patch:

reproduction_conditions:

patch_effect_matrix:

failure_reason_taxonomy:

status:

safety_boundary:

next_steps:
```

其中：

- `cve`：CVE 编号。
- `name`：漏洞简短名称。
- `platform`：平台，当前主要为 Android。
- `category`：漏洞类别，例如 `apk_signature_bypass`、`framework_permission_bypass`。
- `component`：受影响组件、层次、文件和函数。
- `official_references`：官方资料收集状态。
- `official_description`：NVD / CVE Record / Android Security Bulletin 中的官方描述字段。
- `patch`：AOSP patch、commit、修改文件和直接修复点。
- `reproduction_conditions`：复现条件模型。
- `patch_effect_matrix`：补丁前后行为验证矩阵。
- `failure_reason_taxonomy`：复现失败原因分类。
- `status`：当前 case 分析进度。
- `safety_boundary`：安全边界约束。
- `next_steps`：下一步任务。

---

## 3. 核心条件字段

`reproduction_conditions` 是 B 线最核心的字段，后续工具会优先读取该部分。

推荐包含以下子字段：

```yaml
reproduction_conditions:
  version_condition:
  environment_condition:
  component_condition:
  trigger_condition:
  permission_condition:
  user_context_condition:
  sample_condition:
  patch_condition:
```

### 3.1 version_condition

用于描述 Android 版本、SDK 版本、安全补丁级别和 AOSP 版本条件。

典型字段：

```yaml
version_condition:
  affected_or_updated_aosp_versions: []
  android_versions: []
  sdk_versions: []
  security_patch_before:
  security_patch_after_or_equal:
  status:
  note:
```

示例：

- Janus 需要 Android 5.1.1 到 8.0 且未包含 2017-12 安全补丁。
- CVE-2025-32333 当前官方记录明确涉及 Android 14 updated AOSP version。

### 3.2 environment_condition

用于描述设备、模拟器、SELinux、root、系统状态等环境条件。

典型字段：

```yaml
environment_condition:
  required_device_type:
  emulator_suitable:
  physical_device_required:
  selinux_requirement:
  root_required:
  required_system_state: []
```

### 3.3 component_condition

用于描述漏洞相关组件、文件、函数、Activity、Service、Provider 或 Binder service。

典型字段：

```yaml
component_condition:
  required_component:
  required_file:
  required_function:
  required_activity_or_service:
  required_provider:
  required_binder_service:
```

示例：

- Janus：`Package Installer / APK verification path`
- CVE-2025-32333：`Settings / SpaActivity.kt / startSpaActivityForApp`

### 3.4 trigger_condition

用于描述触发入口、触发表面、外部输入字段和示例输入。

典型字段：

```yaml
trigger_condition:
  type:
  surface:
  entrypoint:
  input_field:
  example_input:
  required_intent_action:
  required_uri_scheme:
  required_binder_interface:
  required_api_call:
  known_trigger_uses_malformed_input:
  unconfirmed_payload_elements: []
```

示例：

- Janus：`apk_dex_dual_format_confusion`
- CVE-2025-32333：`Intent data / SPA navigation`，输入字段为 `intent.data.schemeSpecificPart`

### 3.5 permission_condition

用于描述权限边界、缺失权限检查或错误授权问题。

典型字段：

```yaml
permission_condition:
  required_permissions: []
  missing_or_incorrect_permission_check:
  permission_boundary_relevance:
```

### 3.6 user_context_condition

用于描述多用户、Work Profile、secondary user、cross-user 等上下文条件。

典型字段：

```yaml
user_context_condition:
  cross_user_relevance:
  direct_userid_spoofing_supported:
  work_profile_or_secondary_user:
    status:
    reason:
```

示例：

- CVE-2025-32333 被描述为 cross-user permission bypass，但当前已确认的 patch 路径是 malformed packageName 污染 SPA route，而不是直接伪造 userId。

### 3.7 sample_condition

用于描述样本要求，例如 APK 签名方案、是否需要 v1-only APK、是否需要对照样本等。

典型字段：

```yaml
sample_condition:
  required_sample_type:
  required_apk_signature_scheme:
  requires_v1_only_apk:
  requires_v2_disabled_or_absent:
  tampered_sample_is_control:
  tested_samples: []
```

示例：

- Janus 需要 v1-only APK，v2-only APK 可作为对照，普通 tampered APK 是普通篡改对照样本，不是真正 Janus 触发样本。

### 3.8 patch_condition

用于描述补丁条件和补丁直接修复点。

典型字段：

```yaml
patch_condition:
  type:
  check_added:
  blocks_known_trigger_path:
  notes:
```

示例：

- CVE-2025-32333 的 patch condition 是 `input_validation`，直接修复点是 packageName format check。
- Janus 的 patch condition 与 APK/ZIP/DEX 解析一致性检查有关。

---

## 4. Patch-effect Validation Matrix

`patch_effect_matrix` 用于记录修复前后、基线样本、异常样本、修复环境和待验证上下文的行为预期与结论。

推荐结构：

```yaml
patch_effect_matrix:
  baseline_case:
    status:
    note:

  malformed_or_invalid_input:
    status:
    note:

  patched_environment:
    status:
    note:

  unpatched_or_candidate_environment:
    status:
    note:

  context_specific_case:
    status:
    note:
```

不同 case 可以扩展更具体的字段。

### Janus 示例

Janus 可以包含：

- `original_v1_only_apk`
- `tampered_apk`
- `v2_signed_apk`
- `modern_android`
- `old_android_api24`

### CVE-2025-32333 示例

CVE-2025-32333 可以包含：

- `normal_package_name`
- `malformed_package_name`
- `route_segment_pollution`
- `direct_userid_spoofing`
- `work_profile_secondary_user`

---

## 5. Failure Reason Taxonomy

`failure_reason_taxonomy` 用于描述复现失败原因。后续工具应根据 metadata、环境信息和日志输出，尝试给出失败原因候选。

通用失败原因包括：

```yaml
failure_reason_taxonomy:
  - patch_already_applied
  - version_not_affected
  - security_patch_too_new
  - component_not_present
  - trigger_input_invalid
  - trigger_path_not_reachable
  - permission_context_missing
  - user_context_mismatch
  - sample_not_matching_root_cause
  - root_cause_misunderstood
  - patch_effect_confirmed
```

不同 case 可以增加 case-specific 失败原因。

### Janus 相关失败原因

- `signature_scheme_mismatch`
- `ordinary_tampering_detected`
- `missing_apk_dex_dual_format_condition`
- `v2_signature_blocks_structural_change`

### CVE-2025-32333 相关失败原因

- `route_pollution_blocked`
- `trigger_path_not_reachable`
- `user_context_mismatch`
- `root_cause_misunderstood`

---

## 6. Janus 与 CVE-2025-32333 的条件差异

| Case | 主要条件类型 | 示例 |
|---|---|---|
| CVE-2017-13156 Janus | 签名方案 / 补丁级别 / 样本类型 / 文件格式解析差异 | v1-only、Android 7.0、tampered control、APK/DEX dual format |
| CVE-2025-32333 | 组件入口 / 触发输入 / 用户上下文 / patch 机制 | SpaActivity.kt、malformed packageName、cross-user relevance、packageName format check |

这说明，不同 Android CVE 的复现条件并不相同，但可以统一抽象为：

```text
version
environment
component
trigger
permission
user_context
sample
patch
validation
failure_reason
```

---

## 7. 后续工具用途

后续工具会读取每个 case 的 `metadata.yaml`，输出以下信息：

- CVE 基本信息
- 受影响组件
- 关键复现条件
- 当前环境是否满足条件
- 缺失条件列表
- patch-effect matrix
- 可能失败原因
- 下一步验证建议

当前已经有：

```text
tools/print_cve_metadata_summary.py
```

该工具用于读取 metadata 并输出摘要。下一阶段可以在此基础上扩展：

```text
tools/check_cve_environment_match.py
```

未来工具目标：

```text
metadata.yaml + device_info.txt + sample_info.txt
  ↓
condition-to-environment matching
  ↓
satisfied / missing / unknown conditions
  ↓
failure reason candidates
  ↓
patch-effect validation suggestion
```

---

## 8. 安全边界

metadata schema 和后续工具只服务合法的本地验证、补丁生效分析和失败原因诊断。

不做：

- exploit 生成
- 武器化 PoC
- 第三方设备测试
- 批量攻击
- 绕过检测
- 持久化控制

允许：

- 本地授权模拟器验证
- 最小 validation harness
- patch-effect validation
- 环境匹配
- 失败原因分类
- 日志与验证结论记录

## 9. 与 environment matching 工具的关系

`metadata.yaml` 是 `check_cve_environment_match.py` 的主要输入之一。

当前工具会读取：

```text
reproduction_conditions
failure_reason_taxonomy
patch_effect_matrix
```

并结合 `device_profile.yaml` 输出：

```text
satisfied
missing
unknown
failure_reason_candidates
```

因此，metadata schema 的字段命名需要保持稳定，避免每个 CVE case 使用完全不同的字段结构。