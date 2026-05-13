# tools/print_cve_metadata_summary.py
# -*- coding: utf-8 -*-

"""
Print a concise summary from a CVE case metadata.yaml.

Usage:
    python tools/print_cve_metadata_summary.py CVE-2025-32333-cross-user-permission-bypass
    python tools/print_cve_metadata_summary.py CVE-2017-13156-Janus --save
    python tools/print_cve_metadata_summary.py CVE-2017-13156-Janus --out CVE-2017-13156-Janus/logs/metadata_summary_output.txt

This script is for defensive validation workflow only.
It does not run PoC, exploit, or any attack payload.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


try:
    import yaml
except ImportError:
    yaml = None


def load_yaml(path: Path) -> Dict[str, Any]:
    if yaml is None:
        print("[!] PyYAML is not installed.")
        print("    Install it with:")
        print("    pip install pyyaml")
        sys.exit(1)

    if not path.exists():
        print(f"[!] metadata.yaml not found: {path}")
        sys.exit(1)

    try:
        with path.open("r", encoding="utf-8-sig") as f:
            data = yaml.safe_load(f)
    except Exception as exc:
        print(f"[!] Failed to parse YAML: {path}")
        print(f"    Error: {exc}")
        sys.exit(1)

    if data is None:
        return {}

    if not isinstance(data, dict):
        print(f"[!] metadata.yaml root must be a mapping/dict: {path}")
        sys.exit(1)

    return data


def get_path(data: Dict[str, Any], path: str, default: Any = "N/A") -> Any:
    cur: Any = data
    for key in path.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    if cur is None:
        return default
    return cur


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def stringify(value: Any) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return ", ".join(stringify(v) for v in value)
    if isinstance(value, dict):
        items = []
        for k, v in value.items():
            items.append(f"{k}={stringify(v)}")
        return "; ".join(items)
    return str(value)


def add_section(lines: List[str], title: str) -> None:
    lines.append("")
    lines.append(f"## {title}")
    lines.append("")


def add_kv(lines: List[str], key: str, value: Any) -> None:
    lines.append(f"- {key}: {stringify(value)}")


def add_nested_dict(lines: List[str], data: Any, indent: int = 0) -> None:
    prefix = "  " * indent

    if data is None:
        lines.append(f"{prefix}- N/A")
        return

    if isinstance(data, dict):
        if not data:
            lines.append(f"{prefix}- N/A")
            return
        for k, v in data.items():
            if isinstance(v, dict):
                lines.append(f"{prefix}- {k}:")
                add_nested_dict(lines, v, indent + 1)
            elif isinstance(v, list):
                lines.append(f"{prefix}- {k}:")
                add_nested_dict(lines, v, indent + 1)
            else:
                lines.append(f"{prefix}- {k}: {stringify(v)}")
        return

    if isinstance(data, list):
        if not data:
            lines.append(f"{prefix}- N/A")
            return
        for item in data:
            if isinstance(item, dict):
                lines.append(f"{prefix}-")
                add_nested_dict(lines, item, indent + 1)
            else:
                lines.append(f"{prefix}- {stringify(item)}")
        return

    lines.append(f"{prefix}- {stringify(data)}")


def summarize_metadata(case_dir: Path, meta: Dict[str, Any]) -> str:
    lines: List[str] = []

    cve = get_path(meta, "cve")
    name = get_path(meta, "name")
    platform = get_path(meta, "platform")
    category = get_path(meta, "category", "N/A")

    lines.append("# CVE Metadata Summary")
    lines.append("")
    add_kv(lines, "Case directory", str(case_dir))
    add_kv(lines, "CVE", cve)
    add_kv(lines, "Name", name)
    add_kv(lines, "Platform", platform)
    add_kv(lines, "Category", category)

    add_section(lines, "Component")
    component = get_path(meta, "component", {})
    add_nested_dict(lines, component)

    add_section(lines, "Official Description")
    official_description = get_path(meta, "official_description", {})
    add_nested_dict(lines, official_description)

    add_section(lines, "Official References")
    official_references = get_path(meta, "official_references", {})
    add_nested_dict(lines, official_references)

    add_section(lines, "Patch")
    patch = get_path(meta, "patch", {})
    add_nested_dict(lines, patch)

    add_section(lines, "Key Reproduction Conditions")
    conditions = get_path(meta, "reproduction_conditions", {})
    add_nested_dict(lines, conditions)

    add_section(lines, "Patch-effect Matrix")
    matrix = get_path(meta, "patch_effect_matrix", {})
    add_nested_dict(lines, matrix)

    add_section(lines, "Failure Reason Taxonomy")
    failure_reasons = get_path(meta, "failure_reason_taxonomy", [])
    add_nested_dict(lines, failure_reasons)

    add_section(lines, "Status")
    status = get_path(meta, "status", {})
    add_nested_dict(lines, status)

    add_section(lines, "Safety Boundary")
    safety = get_path(meta, "safety_boundary", {})
    add_nested_dict(lines, safety)

    add_section(lines, "Next Steps")
    next_steps = get_path(meta, "next_steps", [])
    add_nested_dict(lines, next_steps)

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("Generated by `tools/print_cve_metadata_summary.py`.")
    lines.append("This output is for defensive validation and patch-effect analysis only.")
    lines.append("")

    return "\n".join(lines)


def resolve_output_path(case_dir: Path, out: Optional[str], save: bool) -> Optional[Path]:
    if out:
        return Path(out)

    if save:
        logs_dir = case_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        return logs_dir / "metadata_summary_output.txt"

    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Print a summary from a CVE case metadata.yaml."
    )
    parser.add_argument(
        "case_dir",
        help="Path to a CVE case directory containing metadata.yaml",
    )
    parser.add_argument(
        "--out",
        help="Optional output file path",
        default=None,
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Save output to <case_dir>/logs/metadata_summary_output.txt",
    )

    args = parser.parse_args()

    case_dir = Path(args.case_dir).resolve()
    metadata_path = case_dir / "metadata.yaml"

    meta = load_yaml(metadata_path)
    summary = summarize_metadata(case_dir, meta)

    out_path = resolve_output_path(case_dir, args.out, args.save)

    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(summary, encoding="utf-8")
        print(f"[+] Summary saved: {out_path}")
    else:
        print(summary)


if __name__ == "__main__":
    main()