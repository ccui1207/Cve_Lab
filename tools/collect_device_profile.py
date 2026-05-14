# tools/collect_device_profile.py
# -*- coding: utf-8 -*-

"""
Collect Android device profile through adb and save as YAML.

Usage:
    py -3.12 tools/collect_device_profile.py --out logs/device_profile_current.yaml

Specify adb:
    py -3.12 tools/collect_device_profile.py ^
      --adb D:\Android\sdk\platform-tools\adb.exe ^
      --out logs/device_profile_current.yaml

This tool only collects environment information.
It does not run PoC, exploit, payload, or any attack behavior.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


try:
    import yaml
except ImportError:
    yaml = None


def run_cmd(cmd: List[str], timeout: int = 15) -> str:
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
        return ""

    output = completed.stdout.strip()
    if not output:
        output = completed.stderr.strip()
    return output.strip()


def adb_shell(adb: str, shell_cmd: str) -> str:
    return run_cmd([adb, "shell", shell_cmd])


def getprop(adb: str, key: str) -> str:
    return adb_shell(adb, f"getprop {key}").strip()


def is_truthy_text(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y"}


def detect_root(adb: str) -> bool:
    out = adb_shell(adb, "id")
    # Common root shell: uid=0(root)
    return "uid=0(" in out or out.startswith("uid=0")


def parse_pm_list_users(output: str) -> Dict[str, Any]:
    """
    Example:
      Users:
        UserInfo{0:Owner:13} running
        UserInfo{10:New user:10}
        UserInfo{11:Work profile:30} running
    """
    users: List[Dict[str, Any]] = []
    secondary_user = False
    work_profile = False

    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("UserInfo{"):
            continue

        raw = line
        inner = line.split("UserInfo{", 1)[1].split("}", 1)[0]
        parts = inner.split(":")
        user_id = parts[0] if len(parts) >= 1 else ""
        user_name = parts[1] if len(parts) >= 2 else ""
        flags = parts[2] if len(parts) >= 3 else ""

        users.append(
            {
                "id": user_id,
                "name": user_name,
                "flags": flags,
                "raw": raw,
            }
        )

        if user_id and user_id != "0":
            secondary_user = True

        text = raw.lower()
        if "work" in text or "managed" in text or "profile" in text:
            work_profile = True

    return {
        "users": users,
        "secondary_user": secondary_user if users else "unknown",
        "work_profile": work_profile if users else "unknown",
    }


def detect_package(adb: str, package_names: List[str]) -> Any:
    out = adb_shell(adb, "pm list packages")
    if not out:
        return "unknown"

    packages = set()
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            packages.add(line.replace("package:", "").strip())

    for name in package_names:
        if name in packages:
            return "present"

    return "missing"


def collect_profile(adb: str) -> Dict[str, Any]:
    model = getprop(adb, "ro.product.model")
    android_version = getprop(adb, "ro.build.version.release")
    sdk = getprop(adb, "ro.build.version.sdk")
    security_patch = getprop(adb, "ro.build.version.security_patch")
    fingerprint = getprop(adb, "ro.build.fingerprint")
    manufacturer = getprop(adb, "ro.product.manufacturer")
    brand = getprop(adb, "ro.product.brand")
    build_type = getprop(adb, "ro.build.type")
    qemu = getprop(adb, "ro.kernel.qemu")

    selinux = adb_shell(adb, "getenforce")
    root = detect_root(adb)

    is_emulator = (
        is_truthy_text(qemu)
        or "sdk" in model.lower()
        or "emulator" in model.lower()
        or "gphone" in model.lower()
    )

    users_out = adb_shell(adb, "pm list users")
    user_info = parse_pm_list_users(users_out)

    settings_status = detect_package(adb, ["com.android.settings"])
    package_installer_status = detect_package(
        adb,
        [
            "com.google.android.packageinstaller",
            "com.android.packageinstaller",
            "com.android.permissioncontroller",
        ],
    )

    profile: Dict[str, Any] = {
        "device": {
            "source": "adb",
            "model": model or "unknown",
            "android_version": android_version or "unknown",
            "sdk": sdk or "unknown",
            "security_patch": security_patch or "unknown",
            "fingerprint": fingerprint or "unknown",
            "selinux": selinux or "unknown",
            "root": root,
        },
        "environment_role": {
            "emulator": is_emulator,
            "physical_device": not is_emulator,
            "aosp_or_oem": "unknown",
            "vendor": manufacturer or brand or "unknown",
            "build_type": build_type or "unknown",
        },
        "installed_components": {
            "settings": settings_status,
            "settings_app": settings_status,
            "package_installer": package_installer_status,
            "work_profile": user_info["work_profile"],
            "secondary_user": user_info["secondary_user"],
        },
        "users": user_info["users"],
        "sample_info": {
            "apk_path": None,
            "signature_scheme": {
                "v1": None,
                "v2": None,
                "v3": None,
                "v4": None,
            },
            "sample_role": None,
        },
    }

    return profile


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
        description="Collect Android device profile through adb."
    )
    parser.add_argument(
        "--adb",
        default="adb",
        help="Path to adb executable. Default: adb",
    )
    parser.add_argument(
        "--out",
        default="logs/device_profile_current.yaml",
        help="Output YAML path.",
    )

    args = parser.parse_args()

    adb = args.adb
    out_path = Path(args.out)

    # Quick adb availability check
    devices = run_cmd([adb, "devices"])
    if "device" not in devices.splitlines()[-1] if devices.splitlines() else True:
        print("[!] No available adb device detected.")
        print("    adb devices output:")
        print(devices)
        sys.exit(1)

    profile = collect_profile(adb)
    save_yaml(profile, out_path)

    print(f"[+] Device profile saved: {out_path}")
    print(f"    model: {profile['device']['model']}")
    print(f"    android_version: {profile['device']['android_version']}")
    print(f"    sdk: {profile['device']['sdk']}")
    print(f"    security_patch: {profile['device']['security_patch']}")
    print(f"    selinux: {profile['device']['selinux']}")


if __name__ == "__main__":
    main()