# tools/collect_apk_sample_info.py
# -*- coding: utf-8 -*-

r"""
Collect APK signature scheme information through apksigner and save as YAML.

Usage:
    py -3.12 tools/collect_apk_sample_info.py D:\Apk包\app-release.apk --out logs/sample_info_app_release.yaml

Specify apksigner:
    py -3.12 tools/collect_apk_sample_info.py D:\Apk包\app-release.apk ^
      --apksigner D:\Android\sdk\build-tools\37.0.0\apksigner.bat ^
      --out logs/sample_info_app_release.yaml

This tool only inspects APK signature verification metadata.
It does not generate, modify, exploit, or weaponize any APK.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


try:
    import yaml
except ImportError:
    yaml = None


def run_cmd(cmd: List[str], timeout: int = 60) -> Dict[str, Any]:
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except FileNotFoundError:
        print(f"[!] Command not found: {cmd[0]}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[!] Command timed out:")
        print("    " + " ".join(cmd))
        sys.exit(1)

    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
        "combined": (completed.stdout + "\n" + completed.stderr).strip(),
    }


def find_apksigner(explicit_path: Optional[str]) -> str:
    if explicit_path:
        p = Path(explicit_path)
        if p.exists():
            return str(p)
        print(f"[!] apksigner not found: {explicit_path}")
        sys.exit(1)

    # Common user environment
    candidates: List[Path] = []

    android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if android_home:
        build_tools = Path(android_home) / "build-tools"
        if build_tools.exists():
            for child in sorted(build_tools.iterdir(), reverse=True):
                candidates.append(child / "apksigner.bat")
                candidates.append(child / "apksigner")

    # User's known SDK path
    candidates.extend(
        [
            Path(r"D:\Android\sdk\build-tools\37.0.0\apksigner.bat"),
            Path(r"D:\Android\sdk\build-tools\36.0.0\apksigner.bat"),
            Path(r"D:\Android\sdk\build-tools\35.0.0\apksigner.bat"),
            Path(r"D:\Android\sdk\build-tools\34.0.0\apksigner.bat"),
        ]
    )

    for c in candidates:
        if c.exists():
            return str(c)

    # Last fallback: rely on PATH
    return "apksigner"


def parse_bool_from_line(text: str, pattern: str) -> Optional[bool]:
    m = re.search(pattern, text, flags=re.IGNORECASE)
    if not m:
        return None
    value = m.group(1).strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def parse_apksigner_verbose(output: str) -> Dict[str, Any]:
    """
    Common output:
      Verifies
      Verified using v1 scheme (JAR signing): true
      Verified using v2 scheme (APK Signature Scheme v2): false
      Verified using v3 scheme (APK Signature Scheme v3): false
      Verified using v4 scheme (APK Signature Scheme v4): false

    Failure output:
      DOES NOT VERIFY
      ERROR: ...
    """
    lower = output.lower()

    verifies = None
    if "does not verify" in lower:
        verifies = False
    elif re.search(r"(^|\n)\s*verifies\s*($|\n)", output, flags=re.IGNORECASE):
        verifies = True

    v1 = parse_bool_from_line(
        output,
        r"Verified using v1 scheme.*?:\s*(true|false)",
    )
    v2 = parse_bool_from_line(
        output,
        r"Verified using v2 scheme.*?:\s*(true|false)",
    )
    v3 = parse_bool_from_line(
        output,
        r"Verified using v3 scheme.*?:\s*(true|false)",
    )
    v4 = parse_bool_from_line(
        output,
        r"Verified using v4 scheme.*?:\s*(true|false)",
    )

    errors: List[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("ERROR"):
            errors.append(stripped)
        elif "DOES NOT VERIFY" in stripped.upper():
            errors.append(stripped)

    return {
        "verifies": verifies,
        "signature_scheme": {
            "v1": v1,
            "v2": v2,
            "v3": v3,
            "v4": v4,
        },
        "errors": errors,
    }


def infer_sample_role(parsed: Dict[str, Any]) -> str:
    verifies = parsed.get("verifies")
    sig = parsed.get("signature_scheme", {})
    v1 = sig.get("v1")
    v2 = sig.get("v2")
    v3 = sig.get("v3")
    v4 = sig.get("v4")

    if verifies is False:
        return "invalid_or_tampered_sample"

    if v1 is True and v2 is False and v3 is False and v4 is False:
        return "v1_only_candidate_sample"

    if v2 is True and v1 is False:
        return "v2_control_sample"

    if v1 is True and v2 is True:
        return "multi_scheme_signed_sample"

    if verifies is True:
        return "valid_signed_sample"

    return "unknown"


def collect_sample_info(apk_path: Path, apksigner: str) -> Dict[str, Any]:
    if not apk_path.exists():
        print(f"[!] APK not found: {apk_path}")
        sys.exit(1)

    cmd = [
        apksigner,
        "verify",
        "--verbose",
        str(apk_path),
    ]

    result = run_cmd(cmd)
    parsed = parse_apksigner_verbose(result["combined"])
    sample_role = infer_sample_role(parsed)

    info: Dict[str, Any] = {
        "sample_info": {
            "apk_path": str(apk_path),
            "signature_scheme": parsed["signature_scheme"],
            "verification": {
                "verifies": parsed["verifies"],
                "returncode": result["returncode"],
                "errors": parsed["errors"],
            },
            "sample_role": sample_role,
        },
        "tool_output": {
            "command": " ".join(cmd),
            "raw_output": result["combined"],
        },
    }

    return info


def save_yaml(data: Dict[str, Any], out_path: Path) -> None:
    if yaml is None:
        print("[!] PyYAML is not installed.")
        print("    Install it with:")
        print("    py -3.12 -m pip install pyyaml")
        sys.exit(1)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(
            data,
            f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect APK signature scheme information through apksigner."
    )
    parser.add_argument(
        "apk",
        help="Path to APK file",
    )
    parser.add_argument(
        "--apksigner",
        default=None,
        help="Path to apksigner.bat or apksigner",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output YAML path. Default: logs/sample_info_<apkname>.yaml",
    )

    args = parser.parse_args()

    apk_path = Path(args.apk)
    apksigner = find_apksigner(args.apksigner)

    if args.out:
        out_path = Path(args.out)
    else:
        safe_name = apk_path.name.replace(".apk", "").replace(" ", "_")
        out_path = Path("logs") / f"sample_info_{safe_name}.yaml"

    info = collect_sample_info(apk_path, apksigner)
    save_yaml(info, out_path)

    sig = info["sample_info"]["signature_scheme"]
    verifies = info["sample_info"]["verification"]["verifies"]
    role = info["sample_info"]["sample_role"]

    print(f"[+] APK sample info saved: {out_path}")
    print(f"    apk: {apk_path}")
    print(f"    verifies: {verifies}")
    print(f"    v1: {sig.get('v1')}")
    print(f"    v2: {sig.get('v2')}")
    print(f"    v3: {sig.get('v3')}")
    print(f"    v4: {sig.get('v4')}")
    print(f"    sample_role: {role}")


if __name__ == "__main__":
    main()