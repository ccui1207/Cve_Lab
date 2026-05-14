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