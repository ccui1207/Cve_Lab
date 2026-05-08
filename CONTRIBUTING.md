# 贡献说明

本仓库目前以个人学习记录为主。新增 CVE 案例时，请尽量保持统一结构。

## 新增一个 CVE 的流程

1. 在根目录创建目录：

```text
CVE-XXXX-XXXX-short-name/
```

2. 复制 `templates/cve_case_template.md` 的内容到该目录下的 `README.md`。

3. 创建以下文件：

```text
env.md
reproduce.md
root_cause.md
patch_analysis.md
fix_verify.md
references.md
```

4. 创建日志和截图目录：

```text
logs/
screenshots/
```

5. 在根目录 `README.md` 的进度表中登记该漏洞。

## 内容要求

每个漏洞至少说明：

- CVE 编号
- 影响版本
- 影响组件
- 复现环境
- 触发现象
- 根因分析
- 官方补丁
- 修复验证结果
