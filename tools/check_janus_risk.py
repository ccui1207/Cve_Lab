#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import pathlib
import subprocess
import sys
from datetime import datetime

# ZIP 文件的本地文件头签名（PK..）
ZIP_LFH = b"PK\x03\x04"
# DEX 文件的魔数前缀（dex\n）
DEX_MAGIC_PREFIX = b"dex\n"

# 默认的 apksigner 路径（Android SDK build-tools）
DEFAULT_APKSIGNER = r"D:\Android\sdk\build-tools\37.0.0\apksigner.bat"
# 默认的报告输出目录
DEFAULT_OUT_DIR = r"CVE-2017-13156-Janus\logs\tool_outputs"


def read_magic(path: pathlib.Path, size: int = 8) -> bytes:
    """读取文件开头的指定字节（默认8字节），用于识别文件类型。"""
    with path.open("rb") as f:
        return f.read(size)


def run_apksigner(apksigner: str, apk: pathlib.Path) -> str:
    """调用 apksigner 验证 APK 签名，并返回其详细输出。"""
    cmd = [apksigner, "verify", "--verbose", str(apk)]
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # 将 stderr 合并到 stdout
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.stdout


def parse_scheme(output: str, scheme: str) -> str:
    """
    从 apksigner 输出中提取指定签名方案的状态行。
    如果未找到，则返回 "not found"。
    """
    for line in output.splitlines():
        if scheme in line:
            return line.strip()
    return "not found"


def build_report(apk: pathlib.Path, apksigner: str) -> str:
    """构建包含文件检测、签名分析和风险分类的文本报告。"""
    lines = []

    # 报告头部
    lines.append(f"Command:")
    lines.append(f"python tools/check_janus_risk.py {apk}")
    lines.append("")
    lines.append(f"Generated At:")
    lines.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("")
    lines.append(f"APK:")
    lines.append(str(apk))
    lines.append("")

    # 读取并判断魔术字节
    magic = read_magic(apk)
    lines.append(f"First 8 bytes:")
    lines.append(magic.hex(" "))
    lines.append("")

    if magic.startswith(ZIP_LFH):
        magic_result = "ZIP Local File Header"
        lines.append("Offset 0 magic: ZIP Local File Header")
    elif magic.startswith(DEX_MAGIC_PREFIX):
        magic_result = "DEX magic"
        lines.append("Offset 0 magic: DEX magic")
        lines.append("This is suspicious for an APK and should be investigated.")
    else:
        magic_result = "unknown"
        lines.append("Offset 0 magic: neither ZIP LFH nor DEX magic")

    lines.append("")
    lines.append("Running apksigner:")
    lines.append(f"{apksigner} verify --verbose {apk}")
    lines.append("")

    # 执行 apksigner 并保存输出
    output = run_apksigner(apksigner, apk)
    lines.append(output.rstrip())
    lines.append("")

    # 提取各签名方案验证状态
    v1_line = parse_scheme(output, "Verified using v1 scheme")
    v2_line = parse_scheme(output, "Verified using v2 scheme")
    v3_line = parse_scheme(output, "Verified using v3 scheme")
    v4_line = parse_scheme(output, "Verified using v4 scheme")

    lines.append("Signature scheme summary:")
    lines.append(f"  {v1_line}")
    lines.append(f"  {v2_line}")
    lines.append(f"  {v3_line}")
    lines.append(f"  {v4_line}")
    lines.append("")

    # 从输出中提取关键判断标志
    v1_true = "v1 scheme (JAR signing): true" in output
    v2_false = "v2 scheme (APK Signature Scheme v2): false" in output
    does_not_verify = "DOES NOT VERIFY" in output

    lines.append("Janus-related interpretation:")

    # 根据魔数和签名状态给出解释
    if magic.startswith(DEX_MAGIC_PREFIX):
        lines.append("- File starts with DEX magic. For APK files, this is abnormal.")
    elif magic.startswith(ZIP_LFH):
        lines.append("- File starts with normal ZIP Local File Header.")
    else:
        lines.append("- File has unusual starting bytes.")

    if does_not_verify:
        lines.append("- APK signature verification failed.")
        lines.append("- This file is not a valid signed baseline sample.")
    elif v1_true and v2_false:
        lines.append("- APK appears to be v1-only.")
        lines.append("- This matches a key Janus precondition.")
    else:
        lines.append("- APK is not v1-only, or signature state could not be confirmed.")

    lines.append("")
    lines.append("Final classification:")

    # 最终分类逻辑
    if does_not_verify:
        lines.append("normal_tampering_or_invalid_signature_sample")
    elif v1_true and v2_false and magic.startswith(ZIP_LFH):
        # 同时满足 v1 签名有效、v2 不存在且文件头为正常 ZIP 头部，是 Janus 潜在候选
        lines.append("v1_only_janus_candidate")
    elif "v2 scheme (APK Signature Scheme v2): true" in output:
        lines.append("v2_control_sample")
    elif magic.startswith(DEX_MAGIC_PREFIX):
        lines.append("suspicious_dex_prefixed_file")
    else:
        lines.append("unknown_or_unclassified")

    lines.append("")
    lines.append("Note:")
    lines.append("This tool is for defensive analysis and lab documentation only.")
    lines.append("It does not generate or modify APK files.")

    return "\n".join(lines) + "\n"


def output_path_for(apk: pathlib.Path, out_dir: pathlib.Path) -> pathlib.Path:
    """根据 APK 文件名生成对应的报告文件路径（去除空格，添加前缀）。"""
    safe_name = apk.stem.replace(" ", "_")
    return out_dir / f"check_{safe_name}.txt"


def main() -> int:
    # 命令行参数解析
    parser = argparse.ArgumentParser(
        description="Check basic Janus-related APK risk indicators and save report."
    )
    parser.add_argument("apk", help="Path to APK file")
    parser.add_argument(
        "--apksigner",
        default=DEFAULT_APKSIGNER,
        help="Path to apksigner.bat",
    )
    parser.add_argument(
        "--out-dir",
        default=DEFAULT_OUT_DIR,
        help="Directory to save report. Same APK name will overwrite old result.",
    )
    parser.add_argument(
        "--print",
        action="store_true",
        help="Also print report content to console.",
    )

    args = parser.parse_args()

    apk = pathlib.Path(args.apk)

    # 检查输入文件和工具是否存在
    if not apk.exists():
        print(f"[!] APK not found: {apk}")
        return 1

    apksigner = pathlib.Path(args.apksigner)
    if not apksigner.exists():
        print(f"[!] apksigner not found: {apksigner}")
        return 1

    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)  # 确保输出目录存在

    # 生成报告并保存
    report = build_report(apk, str(apksigner))
    out_file = output_path_for(apk, out_dir)

    # 默认覆盖已有报告
    out_file.write_text(report, encoding="utf-8")

    print(f"[+] Report saved: {out_file}")

    # 如果指定了 --print，则在控制台输出报告内容
    if args.print:
        print()
        print(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())