# Android CVE Reproduce Lab

本仓库用于记录 Android CVE 漏洞的合法复现、环境搭建、复现现象、根因分析、补丁分析与修复验证过程。

> 项目定位：Android CVE 复现实验仓库  
> 核心目标：复现公开漏洞、理解漏洞原理、分析官方补丁、验证修复效果  
> 使用范围：个人学习、安全研究、论文/毕设材料积累、防御验证

---

## 1. 仓库目标

本仓库不追求收集大量 PoC，而是追求每个漏洞都形成一个完整闭环：

```text
确认影响版本
  ↓
搭建复现环境
  ↓
运行最小 PoC
  ↓
观察漏洞现象
  ↓
分析漏洞根因
  ↓
对比官方补丁
  ↓
验证修复效果
  ↓
整理复现报告
```

---

## 2. 研究范围

当前主要关注以下 Android 漏洞类型：

- APK 签名校验漏洞
- Android Framework 权限绕过漏洞
- PackageManager / PermissionManager 漏洞
- Binder / Parcel 逻辑漏洞
- System Server 崩溃或权限校验问题
- App / SDK 层公开 CVE
- 后续扩展：JNI / Native / Kernel / Vendor 层漏洞

---

## 3. 当前复现计划

| CVE | 漏洞名称 / 类型 | 影响组件 | 当前状态 | 资料 | 根因 | 验证 | 难度 |
|---|---|---|---|---|---|---|---|
| CVE-2017-13156 | Janus / APK 签名校验绕过 | APK Signature / Package Installer | 阶段性完成 | 初版完成 | 初版完成 | 进行中 | 中 |
| CVE-2025-32333 | Cross-user permission bypass | Settings / SpaActivity.kt | 已选定 | 待收集 | 待分析 | 待验证 | 中 |
---

## 4. 单个 CVE 的记录结构

每个 CVE 目录固定包含：

```text
CVE-XXXX-XXXX-Name/
├── README.md           # 漏洞总览
├── env.md              # 复现环境
├── reproduce.md        # 复现过程
├── root_cause.md       # 根因分析
├── patch_analysis.md   # 补丁分析
├── fix_verify.md       # 修复验证
├── references.md       # 参考资料
├── logs/               # 复现日志
└── screenshots/        # 复现截图
```

---

## 5. 基本原则

- 只在本人拥有或被授权的设备、模拟器、测试 ROM 中复现。
- 不针对真实线上目标进行测试。
- 不提供批量攻击、持久化控制、绕过检测、真实投放等内容。
- 优先记录最小复现、现象证明、补丁分析和修复验证。
- 所有 PoC 在运行前都需要进行代码审查。

---

## 6. 常用命令

采集设备信息：

```bash
bash tools/collect_device_info.sh
```

Windows PowerShell：

```powershell
.\tools\collect_device_info.ps1
```

保存 logcat：

```bash
adb logcat -c
adb logcat > logs/logcat.txt
```

查看补丁级别：

```bash
adb shell getprop ro.build.version.security_patch
```

查看 Android 版本：

```bash
adb shell getprop ro.build.version.release
```

查看系统构建指纹：

```bash
adb shell getprop ro.build.fingerprint
```

---
## 7. 推荐复现顺序

新手阶段建议：

1. CVE-2017-13156 Janus  
   学习 APK 签名机制、ZIP/DEX 双格式、安装校验流程、补丁验证和修复后验证。

2. CVE-2025-32333 Cross-user permission bypass  
   学习 Android Settings、SpaActivity.kt、多用户模型、权限边界和 Framework 层 patch diff。

当前顺序说明：

- Janus 用于训练 APK 签名、文件格式解析、环境差异和补丁验证。
- CVE-2025-32333 用于从 APK/安装机制过渡到 Android Framework 权限逻辑。
- 后续再根据资料情况选择 Binder、system_server、PackageManager、Permission 或 native crash 相关 CVE。