# Environment Matching Notes

## 1. 目标

`check_cve_environment_match.py` 用于读取单个 CVE case 的 `metadata.yaml` 和设备环境描述文件 `device_profile.yaml`，判断当前环境是否满足该 CVE 的复现条件。

该工具不运行 PoC、不触发漏洞、不执行攻击行为，只用于合法的本地复现条件判断、补丁验证辅助和失败原因分析。

---

## 2. 输入

### 2.1 CVE metadata

路径示例：

```text
CVE-2017-13156-Janus/metadata.yaml
CVE-2025-32333-cross-user-permission-bypass/metadata.yaml
```

主要读取字段：

```text
reproduction_conditions.version_condition
reproduction_conditions.component_condition
reproduction_conditions.sample_condition
reproduction_conditions.trigger_condition
reproduction_conditions.user_context_condition
failure_reason_taxonomy
```

### 2.2 Device profile

路径示例：

```text
logs/device_profile_android17.yaml
logs/device_profile_api24.yaml
```

主要读取字段：

```text
device.android_version
device.sdk
device.security_patch
device.model
device.selinux
installed_components
sample_info.signature_scheme
```

---

## 3. 输出分类

工具将每个条件分成三类：

| 状态 | 含义 |
|---|---|
| satisfied | 当前环境明确满足该条件 |
| missing | 当前环境明确不满足该条件 |
| unknown | 当前信息不足，无法自动判断 |

其中：

- `missing` 通常可以直接推导出复现失败原因。
- `unknown` 表示需要人工分析、源码确认、validation harness 或更完整的环境信息。
- `satisfied` 仅表示当前 v0.1 支持的字段满足，不等于漏洞一定可复现。

---

## 4. V0.1 支持字段

当前 v0.1 支持：

```text
Android version
SDK version
Security Patch Level
component presence
sample signature scheme
basic trigger condition summary
basic user context condition
failure reason candidates
```

当前 v0.1 不支持：

```text
自动确认复杂权限路径
自动确认 Work Profile / secondary user 行为
自动判断 OEM backport 状态
自动运行 validation harness
自动分析 AOSP patch 是否真实合入
```

---

## 5. 初步验证结果

### 5.1 CVE-2025-32333 + Android 17

工具输出显示：

```text
version_condition.android_version: missing
component_condition.required_component: satisfied
sample_condition: unknown
trigger_condition: unknown
user_context_condition.cross_user: unknown
failure_reason_candidates: version_not_affected
```

解释：

Android 17 profile 与当前 metadata 中记录的 Android 14 条件不匹配，因此该环境不适合作为 CVE-2025-32333 的复现环境。Settings 组件存在，但 trigger condition 和 user context 仍需要后续 validation harness 或更完整的多用户环境信息判断。

### 5.2 CVE-2017-13156 Janus + Android 7.0 / API24

工具输出显示：

```text
version_condition.android_version: satisfied
version_condition.security_patch_before: satisfied
sample_condition.v1_signature: satisfied
sample_condition.v2_signature: satisfied
missing: 0
unknown: 3
failure_reason_candidates: None
```

解释：

Android 7.0 / API24 / 2017-10-05 环境满足 Janus 的主要版本、补丁级别和样本签名条件，可作为历史行为分析或候选验证环境。Package Installer 语义路径和 APK/DEX dual-format trigger 仍需要人工分析或后续 validation harness。

---

## 6. 当前意义

该工具完成了从人工文档到工具判断的第一步：

```text
metadata.yaml
  ↓
device_profile.yaml
  ↓
condition matching
  ↓
satisfied / missing / unknown
  ↓
failure reason candidates
```

这为后续 B 线工具系统中的 `condition-to-environment matching` 模块打下基础。

---

## 7. 下一步计划

V0.2 可以继续增加：

```text
ADB 自动采集 device profile
APK 签名信息自动采集
component presence 更精确判断
Work Profile / secondary user 检查
sample_info 自动填充
更细粒度 failure reason inference
```