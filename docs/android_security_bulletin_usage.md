# Android Security Bulletin 使用方法

Android Security Bulletin 是 Android 官方安全公告，是确认 CVE 影响范围和补丁信息的核心资料来源。

## 查询流程

```text
拿到 CVE 编号
  ↓
搜索 Android Security Bulletin + CVE 编号
  ↓
确认影响组件
  ↓
确认严重性
  ↓
确认修复补丁级别
  ↓
查找 AOSP / kernel / vendor 修复链接
  ↓
对比补丁前后逻辑
```

## 需要记录的信息

| 字段 | 说明 |
|---|---|
| CVE | 漏洞编号 |
| References | 官方引用链接 |
| Type | 漏洞类型 |
| Severity | 严重性 |
| Updated AOSP versions | 受影响或修复版本 |
| Component | 影响组件 |
| Security patch level | 修复补丁日期 |

## 判断设备是否可能受影响

设备安全补丁日期低于官方修复补丁日期时，才可能受影响。

示例：

```text
漏洞修复补丁级别：2024-03-05
设备安全补丁日期：2024-02-05
结论：可能受影响

漏洞修复补丁级别：2024-03-05
设备安全补丁日期：2024-10-05
结论：大概率已修复
```

注意：厂商 ROM 可能存在延迟合并补丁、回移植补丁、部分补丁缺失等情况，所以最终仍需要实际验证。
