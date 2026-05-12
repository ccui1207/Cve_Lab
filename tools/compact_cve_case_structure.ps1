# tools/compact_cve_case_structure.ps1
# 用途：将单个 CVE case 目录收缩为 README.md + analysis.md + metadata.yaml + logs/ + legacy_docs/
# 注意：不删除旧文件，只移动到 legacy_docs/ 备份。

$ErrorActionPreference = "Stop"

function Write-Utf8File {
    param(
        [string]$Path,
        [string]$Content
    )
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

function Move-Safely {
    param(
        [string]$Source,
        [string]$DestDir
    )

    if (-not (Test-Path $Source)) {
        return
    }

    if (-not (Test-Path $DestDir)) {
        New-Item -ItemType Directory -Path $DestDir | Out-Null
    }

    $fileName = Split-Path $Source -Leaf
    $dest = Join-Path $DestDir $fileName

    if (Test-Path $dest) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $base = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
        $ext = [System.IO.Path]::GetExtension($fileName)
        $dest = Join-Path $DestDir "$base.$timestamp$ext"
    }

    Move-Item -Path $Source -Destination $dest
}

function Read-IfExists {
    param([string]$Path)

    if (Test-Path $Path) {
        return Get-Content $Path -Raw -Encoding UTF8
    }

    return $null
}

function Build-Analysis {
    param(
        [string]$CaseDir,
        [string]$Title,
        [array]$DocOrder
    )

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add("# $Title Analysis")
    $lines.Add("")
    $lines.Add("> 本文件由脚本从原有分散文档合并生成。后续该 CVE 的主要分析内容优先维护在本文件中。")
    $lines.Add("")
    $lines.Add("## 1. Case Overview")
    $lines.Add("")
    $lines.Add("- Case directory: ``$CaseDir``")
    $lines.Add("- Generated at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $lines.Add("")
    $lines.Add("## 2. Consolidated Notes")
    $lines.Add("")

    foreach ($doc in $DocOrder) {
        $path = Join-Path $CaseDir $doc
        $content = Read-IfExists $path

        if ($null -ne $content -and $content.Trim().Length -gt 0) {
            $sectionName = $doc
            $lines.Add("")
            $lines.Add("---")
            $lines.Add("")
            $lines.Add("## From ``$sectionName``")
            $lines.Add("")
            $lines.Add($content.Trim())
            $lines.Add("")
        }
    }

    $lines.Add("")
    $lines.Add("---")
    $lines.Add("")
    $lines.Add("## 3. Current Maintenance Rule")
    $lines.Add("")
    $lines.Add("后续默认维护：")
    $lines.Add("")
    $lines.Add("- ``README.md``：入口摘要")
    $lines.Add("- ``analysis.md``：官方资料、根因、patch diff、验证矩阵、复现过程、失败原因、结论")
    $lines.Add("- ``metadata.yaml``：结构化条件模型与状态")
    $lines.Add("- ``logs/``：原始命令输出和日志")
    $lines.Add("")
    $lines.Add("旧文档已移动到 ``legacy_docs/``，仅作为历史备份。")
    $lines.Add("")

    return ($lines -join "`r`n")
}

function Build-CompactReadme {
    param(
        [string]$Title,
        [string]$ShortDescription
    )

    return @"
# $Title

## 1. Case Summary

$ShortDescription

## 2. Current Structure

| Path | Purpose |
|---|---|
| analysis.md | Main analysis document: official references, root cause, patch diff, validation matrix, reproduction notes, conclusions |
| metadata.yaml | Structured CVE metadata and condition model |
| logs/ | Raw command outputs, logs, diff summaries, tool outputs |
| legacy_docs/ | Archived old documents kept for history |

## 3. Current Rule

This case now uses a compact structure.

Future updates should primarily go to:

- analysis.md
- metadata.yaml
- logs/

Only create extra documents when the case becomes complex enough to require a dedicated report or specialized analysis file.
"@
}

function Compact-Case {
    param(
        [string]$CaseDir,
        [string]$Title,
        [string]$ShortDescription,
        [array]$DocOrder
    )

    if (-not (Test-Path $CaseDir)) {
        Write-Host "[!] Skip missing case directory: $CaseDir"
        return
    }

    Write-Host "[*] Processing: $CaseDir"

    $legacyDir = Join-Path $CaseDir "legacy_docs"
    if (-not (Test-Path $legacyDir)) {
        New-Item -ItemType Directory -Path $legacyDir | Out-Null
    }

    $logsDir = Join-Path $CaseDir "logs"
    if (-not (Test-Path $logsDir)) {
        New-Item -ItemType Directory -Path $logsDir | Out-Null
    }

    # Backup old README
    $readmePath = Join-Path $CaseDir "README.md"
    if (Test-Path $readmePath) {
        $backupReadme = Join-Path $legacyDir "README.old.md"
        if (Test-Path $backupReadme) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $backupReadme = Join-Path $legacyDir "README.old.$timestamp.md"
        }
        Copy-Item $readmePath $backupReadme
    }

    # Backup old analysis if exists
    $analysisPath = Join-Path $CaseDir "analysis.md"
    if (Test-Path $analysisPath) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupAnalysis = Join-Path $legacyDir "analysis.old.$timestamp.md"
        Copy-Item $analysisPath $backupAnalysis
    }

    # Build new analysis.md from old docs
    $analysis = Build-Analysis -CaseDir $CaseDir -Title $Title -DocOrder $DocOrder
    Write-Utf8File -Path $analysisPath -Content $analysis

    # Write compact README.md
    $compactReadme = Build-CompactReadme -Title $Title -ShortDescription $ShortDescription
    Write-Utf8File -Path $readmePath -Content $compactReadme

    # Move old docs to legacy_docs/
    foreach ($doc in $DocOrder) {
        $path = Join-Path $CaseDir $doc
        if ($doc -ne "README.md" -and $doc -ne "analysis.md" -and $doc -ne "metadata.yaml") {
            Move-Safely -Source $path -DestDir $legacyDir
        }
    }

    # Keep metadata.yaml in place
    $metadata = Join-Path $CaseDir "metadata.yaml"
    if (-not (Test-Path $metadata)) {
        Write-Utf8File -Path $metadata -Content "status:`r`n  overall: compacted`r`n"
    }

    Write-Host "[+] Compacted: $CaseDir"
}

# 需要收缩的两个 CVE case
$janusDocs = @(
    "references.md",
    "env.md",
    "reproduce.md",
    "root_cause.md",
    "patch_analysis.md",
    "fix_verify.md",
    "dual_format_research.md",
    "old_android_env_plan.md"
)

$cve2025Docs = @(
    "references.md",
    "env.md",
    "reproduce.md",
    "root_cause.md",
    "patch_analysis.md",
    "fix_verify.md"
)

Compact-Case `
    -CaseDir "CVE-2017-13156-Janus" `
    -Title "CVE-2017-13156 Janus" `
    -ShortDescription "CVE-2017-13156 Janus is an Android APK signature verification bypass case. This case is used to study APK/ZIP/DEX parsing differences, v1/v2 signature schemes, patch levels, environment sensitivity, and patch-effect validation." `
    -DocOrder $janusDocs

Compact-Case `
    -CaseDir "CVE-2025-32333-cross-user-permission-bypass" `
    -Title "CVE-2025-32333 Cross-user Permission Bypass" `
    -ShortDescription "CVE-2025-32333 is an Android Settings / SpaActivity.kt cross-user permission bypass case. This case is used to study Android Framework permission logic, SPA navigation, malformed packageName validation, patch diff analysis, and patch-effect validation." `
    -DocOrder $cve2025Docs

Write-Host ""
Write-Host "[*] Done."
Write-Host "[*] Suggested next commands:"
Write-Host "    git status"
Write-Host "    git add ."
Write-Host "    git commit -m `"docs: compact CVE case document structure`""
