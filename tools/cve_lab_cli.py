# tools/cve_lab_cli.py
# -*- coding: utf-8 -*-

r"""
Interactive CLI for Android CVE Reproduce Lab.

Usage:
    py -3.12 tools/cve_lab_cli.py

This CLI only orchestrates local defensive validation tools.
It does not run PoC, exploit, payload, adb attack command, or any third-party testing.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


try:
    import yaml
except ImportError:
    yaml = None


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
RUNS = ROOT / "runs"

DEVICE_PROFILE_DIR = RUNS / "device_profiles"
SAMPLE_INFO_DIR = RUNS / "sample_infos"
METADATA_SUMMARY_DIR = RUNS / "metadata_summaries"
ENV_MATCH_DIR = RUNS / "environment_matches"


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except Exception:
        return str(path)


def now_tag() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def ensure_dirs() -> None:
    for d in [
        RUNS,
        DEVICE_PROFILE_DIR,
        SAMPLE_INFO_DIR,
        METADATA_SUMMARY_DIR,
        ENV_MATCH_DIR,
    ]:
        d.mkdir(parents=True, exist_ok=True)


def pause() -> None:
    input("\nPress Enter to continue...")


def print_header(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def run_cmd(cmd: List[str], cwd: Path = ROOT) -> int:
    print("\n[CMD]")
    print(" ".join(str(x) for x in cmd))
    print("")

    completed = subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return completed.returncode


def load_yaml(path: Path) -> Dict[str, Any]:
    if yaml is None:
        print("[!] PyYAML is not installed.")
        print("    Install it with:")
        print("    py -3.12 -m pip install pyyaml")
        return {}

    if not path.exists():
        print(f"[!] YAML file not found: {path}")
        return {}

    try:
        with path.open("r", encoding="utf-8-sig") as f:
            data = yaml.safe_load(f)
    except Exception as exc:
        print(f"[!] Failed to parse YAML: {path}")
        print(f"    Error: {exc}")
        return {}

    if isinstance(data, dict):
        return data
    return {}


def save_yaml(data: Dict[str, Any], path: Path) -> None:
    if yaml is None:
        print("[!] PyYAML is not installed.")
        print("    Install it with:")
        print("    py -3.12 -m pip install pyyaml")
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(
            data,
            f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def read_first_lines(path: Path, max_lines: int = 80) -> str:
    if not path.exists():
        return ""

    lines: List[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                lines.append("\n... [truncated]\n")
                break
            lines.append(line)
    return "".join(lines)


def prompt_default(prompt: str, default: str) -> str:
    value = input(f"{prompt} [{default}]: ").strip()
    return value if value else default


def find_cases() -> List[Path]:
    cases: List[Path] = []
    for p in ROOT.iterdir():
        if not p.is_dir():
            continue
        if not p.name.startswith("CVE-"):
            continue
        if (p / "metadata.yaml").exists():
            cases.append(p)
    return sorted(cases, key=lambda x: x.name)


def choose_item(title: str, items: List[Path]) -> Optional[Path]:
    print_header(title)

    if not items:
        print("[!] No items found.")
        return None

    for idx, item in enumerate(items, start=1):
        print(f"{idx}. {rel(item)}")

    print("0. Cancel")
    print("b. Back")
    print("q. Cancel")

    while True:
        choice = input("\nChoose: ").strip().lower()

        if choice in {"", "0", "b", "back", "q", "quit", "cancel"}:
            return None

        if choice.isdigit():
            i = int(choice)
            if 1 <= i <= len(items):
                return items[i - 1]

        print(f"[!] Invalid choice. Please choose 1-{len(items)}, or 0/b/q to go back.")

def list_yaml_candidates() -> List[Path]:
    candidates: List[Path] = []

    search_roots = [
        RUNS,
        ROOT / "logs",
        ROOT / "templates",
    ]

    for base in search_roots:
        if base.exists():
            candidates.extend(base.rglob("*.yaml"))

    return sorted(set(candidates), key=lambda x: str(x))


def choose_device_profile() -> Optional[Path]:
    all_yaml = list_yaml_candidates()
    profiles = [
        p for p in all_yaml
        if "device_profile" in p.name.lower()
    ]
    return choose_item("Choose device profile", profiles)


def choose_sample_info() -> Optional[Path]:
    all_yaml = list_yaml_candidates()
    samples = [
        p for p in all_yaml
        if "sample_info" in p.name.lower()
    ]
    return choose_item("Choose APK sample info", samples)


def default_adb_path() -> str:
    known = Path(r"D:\Android\sdk\platform-tools\adb.exe")
    if known.exists():
        return str(known)
    return "adb"


def default_apksigner_path() -> str:
    known = Path(r"D:\Android\sdk\build-tools\37.0.0\apksigner.bat")
    if known.exists():
        return str(known)
    return "apksigner"


def action_list_cases() -> None:
    print_header("CVE cases")
    cases = find_cases()
    if not cases:
        print("[!] No CVE cases found.")
    for case in cases:
        meta = load_yaml(case / "metadata.yaml")
        cve = meta.get("cve", case.name)
        name = meta.get("name", "")
        category = meta.get("category", "")
        print(f"- {case.name}")
        print(f"  CVE: {cve}")
        print(f"  Name: {name}")
        print(f"  Category: {category}")
    pause()


def action_show_metadata_summary() -> None:
    case = choose_item("Choose CVE case", find_cases())
    if case is None:
        return

    out_path = METADATA_SUMMARY_DIR / f"{case.name}_{now_tag()}.md"

    code = run_cmd(
        [
            sys.executable,
            str(TOOLS / "print_cve_metadata_summary.py"),
            str(case),
            "--out",
            str(out_path),
        ]
    )

    if code == 0:
        print(f"\n[+] Summary saved: {rel(out_path)}")
        print_header("Preview")
        print(read_first_lines(out_path, 100))
    pause()


def action_collect_device_profile() -> None:
    print_header("Collect current device profile")

    adb = prompt_default("ADB path", default_adb_path())
    out_path = DEVICE_PROFILE_DIR / f"device_profile_{now_tag()}.yaml"

    code = run_cmd(
        [
            sys.executable,
            str(TOOLS / "collect_device_profile.py"),
            "--adb",
            adb,
            "--out",
            str(out_path),
        ]
    )

    if code == 0:
        print(f"\n[+] Device profile saved: {rel(out_path)}")
        print_header("Preview")
        print(read_first_lines(out_path, 80))
    pause()


def action_collect_apk_sample_info() -> None:
    print_header("Collect APK sample info")

    apk = input("APK path: ").strip().strip('"')
    if not apk:
        print("[!] APK path is required.")
        pause()
        return

    apk_path = Path(apk)
    if not apk_path.exists():
        print(f"[!] APK not found: {apk_path}")
        pause()
        return

    apksigner = prompt_default("apksigner path", default_apksigner_path())

    safe_name = apk_path.name.replace(".apk", "").replace(" ", "_")
    out_path = SAMPLE_INFO_DIR / f"sample_info_{safe_name}_{now_tag()}.yaml"

    code = run_cmd(
        [
            sys.executable,
            str(TOOLS / "collect_apk_sample_info.py"),
            str(apk_path),
            "--apksigner",
            apksigner,
            "--out",
            str(out_path),
        ]
    )

    if code == 0:
        print(f"\n[+] Sample info saved: {rel(out_path)}")
        print_header("Preview")
        print(read_first_lines(out_path, 80))
    pause()


def action_merge_sample_into_profile() -> None:
    print_header("Merge sample_info into device_profile")

    profile_path = choose_device_profile()
    if profile_path is None:
        return

    sample_path = choose_sample_info()
    if sample_path is None:
        return

    profile = load_yaml(profile_path)
    sample = load_yaml(sample_path)

    sample_info = sample.get("sample_info")
    if not isinstance(sample_info, dict):
        print("[!] sample_info not found in selected sample YAML.")
        pause()
        return

    profile["sample_info"] = sample_info

    out_name = (
        f"{profile_path.stem}_with_{sample_path.stem}_{now_tag()}.yaml"
    )
    out_path = DEVICE_PROFILE_DIR / out_name

    save_yaml(profile, out_path)

    print(f"[+] Merged profile saved: {rel(out_path)}")
    print_header("Preview")
    print(read_first_lines(out_path, 120))
    pause()


def action_run_environment_match() -> None:
    case = choose_item("Choose CVE case", find_cases())
    if case is None:
        return

    profile = choose_device_profile()
    if profile is None:
        return

    out_path = ENV_MATCH_DIR / f"{case.name}_{profile.stem}_{now_tag()}.md"

    code = run_cmd(
        [
            sys.executable,
            str(TOOLS / "check_cve_environment_match.py"),
            str(case),
            str(profile),
            "--out",
            str(out_path),
        ]
    )

    if code == 0:
        print(f"\n[+] Environment match report saved: {rel(out_path)}")
        print_header("Preview")
        print(read_first_lines(out_path, 120))
    pause()


def action_show_latest_reports() -> None:
    print_header("Latest reports")

    report_files: List[Path] = []

    if RUNS.exists():
        report_files.extend(RUNS.rglob("*.md"))
        report_files.extend(RUNS.rglob("*.txt"))

    for case in find_cases():
        evidence = case / "evidence"
        logs = case / "logs"
        if evidence.exists():
            report_files.extend(evidence.rglob("*.txt"))
            report_files.extend(evidence.rglob("*.md"))
        if logs.exists():
            report_files.extend(logs.rglob("*.txt"))
            report_files.extend(logs.rglob("*.md"))

    report_files = sorted(
        set(report_files),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )

    if not report_files:
        print("[!] No reports found.")
        pause()
        return

    for i, p in enumerate(report_files[:20], start=1):
        print(f"{i}. {rel(p)}")

    print("0. Cancel")

    while True:
        choice = input("\nChoose report to preview: ").strip()
        if choice == "0":
            return
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= min(20, len(report_files)):
                p = report_files[idx - 1]
                print_header(f"Preview: {rel(p)}")
                print(read_first_lines(p, 160))
                pause()
                return
        print("[!] Invalid choice.")


def action_check_required_tools() -> None:
    print_header("Tool availability check")

    required = [
        TOOLS / "print_cve_metadata_summary.py",
        TOOLS / "check_cve_environment_match.py",
        TOOLS / "collect_device_profile.py",
        TOOLS / "collect_apk_sample_info.py",
    ]

    for p in required:
        status = "OK" if p.exists() else "MISSING"
        print(f"- {rel(p)}: {status}")

    print("")
    print(f"- Python executable: {sys.executable}")

    if yaml is None:
        print("- PyYAML: MISSING")
        print("  Install: py -3.12 -m pip install pyyaml")
    else:
        print("- PyYAML: OK")

    pause()


def print_menu() -> None:
    print_header("Android CVE Reproduce Lab - Interactive CLI v0.3")
    print("1. List CVE cases")
    print("2. Show CVE metadata summary")
    print("3. Collect current device profile via ADB")
    print("4. Collect APK sample info via apksigner")
    print("5. Merge sample_info into device_profile")
    print("6. Run environment matching")
    print("7. Show latest reports")
    print("8. Check required tools")
    print("0. Exit")


def main() -> None:
    ensure_dirs()

    while True:
        print_menu()
        choice = input("\nChoose: ").strip()

        if choice == "1":
            action_list_cases()
        elif choice == "2":
            action_show_metadata_summary()
        elif choice == "3":
            action_collect_device_profile()
        elif choice == "4":
            action_collect_apk_sample_info()
        elif choice == "5":
            action_merge_sample_into_profile()
        elif choice == "6":
            action_run_environment_match()
        elif choice == "7":
            action_show_latest_reports()
        elif choice == "8":
            action_check_required_tools()
        elif choice == "0":
            print("Bye.")
            break
        else:
            print("[!] Invalid choice.")
            pause()


if __name__ == "__main__":
    main()