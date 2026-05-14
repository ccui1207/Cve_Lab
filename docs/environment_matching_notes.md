# Environment Matching Notes

## 1. 目标

本工具用于读取 CVE case 的 metadata.yaml 和设备 profile，判断当前环境是否满足复现条件。

## 2. 输出分类

- satisfied：当前环境满足该条件
- missing：当前环境明确不满足该条件
- unknown：当前信息不足，无法判断

## 3. 当前 v0.1 支持字段

- Android version
- SDK version
- Security Patch Level
- component presence
- sample signature scheme
- basic failure reason candidates

## 4. 当前限制

- 不运行 PoC
- 不判断复杂权限路径
- 不自动确认 Work Profile / secondary user
- 不判断 OEM patch backport

## V0.1 初步验证结果

当前 `check_cve_environment_match.py` 已完成最小闭环验证。

### CVE-2025-32333 + Android 17

工具输出显示：

- `version_condition.android_version`: missing
- failure reason candidate: `version_not_affected`
- trigger condition: unknown
- user context condition: unknown

解释：

Android 17 profile 与当前 metadata 中记录的 Android 14 条件不匹配，因此该环境不适合作为 CVE-2025-32333 的复现环境。trigger 和 user context 仍需要后续 validation harness 或更完整环境信息判断。

### CVE-2017-13156 Janus + Android 7.0 / API24

工具输出显示：

- Android version: satisfied
- security patch before 2017-12: satisfied
- v1 signature: satisfied
- v2 signature absent: satisfied
- missing: 0
- unknown: 3

解释：

该环境满足 Janus 的主要版本、补丁级别和样本签名条件，可作为历史行为分析 / 候选验证环境。dual-format trigger 和 Package Installer 语义路径仍需人工分析或后续验证。