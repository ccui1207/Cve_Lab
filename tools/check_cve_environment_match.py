# tools/check_cve_environment_match.py
# -*- coding: utf-8 -*-

"""
Check whether a device profile satisfies a CVE case's reproduction conditions.

Usage:
    py -3.12 tools/check_cve_environment_match.py CVE-2017-13156-Janus logs/device_profile_android17.yaml --save
    py -3.12 tools/check_cve_environment_match.py CVE-2017-13156-Janus logs/device_profile_api24.yaml --save
    py -3.12 tools/check_cve_environment_match.py CVE-2025-32333-cross-user-permission-bypass logs/device_profile_android17.yaml --save

This tool is for defensive validation and patch-effect analysis only.
It does not run PoC, exploit, payload, adb command, or attack behavior.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


try:
    import yaml
except ImportError:
    yaml = None


Result = Dict[str, str]


def load_yaml(path: Path) -> Dict[str, Any]:
    if yaml is None:
        print("[!] PyYAML is not installed.")
        print("    Use Windows Python if your default python is MSYS:")
        print("    py -3.12 -m pip install pyyaml")
        sys.exit(1)

    if not path.exists():
        print(f"[!] File not found: {path}")
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
        print(f"[!] YAML root must be a mapping/dict: {path}")
        sys.exit(1)

    return data


def get_path(data: Dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = data
    for key in path.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return default if cur is None else cur


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def parse_patch_date(value: Any) -> Optional[datetime]:
    """
    Accept:
      2017-12
      2017-12-01
      2026-04-05
    """
    text = normalize_str(value)
    if not text:
        return None

    for fmt in ("%Y-%m-%d", "%Y-%m"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass

    return None


def add_result(
    results: List[Result],
    category: str,
    status: str,
    detail: str,
    failure_reason: str = "",
) -> None:
    results.append(
        {
            "category": category,
            "status": status,
            "detail": detail,
            "failure_reason": failure_reason,
        }
    )


def check_version_condition(meta: Dict[str, Any], profile: Dict[str, Any]) -> List[Result]:
    results: List[Result] = []

    vc = get_path(meta, "reproduction_conditions.version_condition", {})
    if not isinstance(vc, dict):
        add_result(results, "version_condition", "unknown", "No version_condition found in metadata.")
        return results

    device_android = normalize_str(get_path(profile, "device.android_version"))
    device_sdk = normalize_str(get_path(profile, "device.sdk"))
    device_patch = normalize_str(get_path(profile, "device.security_patch"))

    affected_versions = [
        normalize_str(v)
        for v in as_list(vc.get("affected_android_versions"))
        if normalize_str(v)
    ]

    updated_versions = [
        normalize_str(v)
        for v in as_list(vc.get("affected_or_updated_aosp_versions"))
        if normalize_str(v)
    ]

    android_versions = [
        normalize_str(v)
        for v in as_list(vc.get("android_versions"))
        if normalize_str(v)
    ]

    all_version_candidates = affected_versions or android_versions or updated_versions

    if all_version_candidates:
        if not device_android:
            add_result(
                results,
                "version_condition.android_version",
                "unknown",
                f"Metadata expects one of {all_version_candidates}, but device android_version is missing.",
            )
        elif device_android in all_version_candidates:
            add_result(
                results,
                "version_condition.android_version",
                "satisfied",
                f"Device Android version {device_android} matches metadata versions {all_version_candidates}.",
            )
        else:
            add_result(
                results,
                "version_condition.android_version",
                "missing",
                f"Device Android version {device_android} does not match metadata versions {all_version_candidates}.",
                "version_not_affected",
            )
    else:
        add_result(
            results,
            "version_condition.android_version",
            "unknown",
            "No Android version list found in metadata.",
        )

    sdk_versions = [
        normalize_str(v)
        for v in as_list(vc.get("sdk_versions"))
        if normalize_str(v)
    ]

    if sdk_versions:
        if not device_sdk:
            add_result(
                results,
                "version_condition.sdk",
                "unknown",
                f"Metadata expects SDK in {sdk_versions}, but device sdk is missing.",
            )
        elif device_sdk in sdk_versions:
            add_result(
                results,
                "version_condition.sdk",
                "satisfied",
                f"Device SDK {device_sdk} matches metadata SDK list {sdk_versions}.",
            )
        else:
            add_result(
                results,
                "version_condition.sdk",
                "missing",
                f"Device SDK {device_sdk} does not match metadata SDK list {sdk_versions}.",
                "version_not_affected",
            )

    security_patch_before = vc.get("security_patch_before")
    threshold_before = parse_patch_date(security_patch_before)
    device_patch_date = parse_patch_date(device_patch)

    if threshold_before:
        if not device_patch_date:
            add_result(
                results,
                "version_condition.security_patch_before",
                "unknown",
                f"Metadata requires security patch before {security_patch_before}, but device security_patch is missing or invalid.",
            )
        elif device_patch_date < threshold_before:
            add_result(
                results,
                "version_condition.security_patch_before",
                "satisfied",
                f"Device security patch {device_patch} is before required threshold {security_patch_before}.",
            )
        else:
            add_result(
                results,
                "version_condition.security_patch_before",
                "missing",
                f"Device security patch {device_patch} is not before required threshold {security_patch_before}.",
                "security_patch_too_new",
            )

    security_patch_after = vc.get("security_patch_after_or_equal")
    threshold_after = parse_patch_date(security_patch_after)

    if threshold_after:
        if not device_patch_date:
            add_result(
                results,
                "version_condition.security_patch_after_or_equal",
                "unknown",
                f"Metadata requires security patch after or equal to {security_patch_after}, but device security_patch is missing or invalid.",
            )
        elif device_patch_date >= threshold_after:
            add_result(
                results,
                "version_condition.security_patch_after_or_equal",
                "satisfied",
                f"Device security patch {device_patch} is after or equal to {security_patch_after}.",
            )
        else:
            add_result(
                results,
                "version_condition.security_patch_after_or_equal",
                "missing",
                f"Device security patch {device_patch} is older than {security_patch_after}.",
                "patch_level_mismatch",
            )

    return results


def check_component_condition(meta: Dict[str, Any], profile: Dict[str, Any]) -> List[Result]:
    results: List[Result] = []

    cc = get_path(meta, "reproduction_conditions.component_condition", {})
    if not isinstance(cc, dict):
        add_result(results, "component_condition", "unknown", "No component_condition found in metadata.")
        return results

    required_component = normalize_str(cc.get("required_component"))
    if not required_component:
        add_result(results, "component_condition.required_component", "unknown", "No required_component found.")
        return results

    installed_components = get_path(profile, "installed_components", {})
    if not isinstance(installed_components, dict) or not installed_components:
        add_result(
            results,
            "component_condition.required_component",
            "unknown",
            f"Required component is {required_component}, but device profile has no installed_components data.",
        )
        return results

    key_candidates = [
        required_component.lower().replace(" ", "_"),
        required_component.lower(),
    ]

    found_value = None
    for key in key_candidates:
        if key in installed_components:
            found_value = installed_components[key]
            break

    if found_value is True or normalize_str(found_value).lower() in ("true", "present", "installed", "available"):
        add_result(
            results,
            "component_condition.required_component",
            "satisfied",
            f"Required component appears present: {required_component}.",
        )
    elif found_value is False or normalize_str(found_value).lower() in ("false", "missing", "absent", "not_installed"):
        add_result(
            results,
            "component_condition.required_component",
            "missing",
            f"Required component appears missing: {required_component}.",
            "component_not_present",
        )
    else:
        add_result(
            results,
            "component_condition.required_component",
            "unknown",
            f"Required component is {required_component}, but presence cannot be confirmed from device profile.",
        )

    return results


def check_sample_condition(meta: Dict[str, Any], profile: Dict[str, Any]) -> List[Result]:
    results: List[Result] = []

    sc = get_path(meta, "reproduction_conditions.sample_condition", {})
    if not isinstance(sc, dict) or not sc:
        add_result(results, "sample_condition", "unknown", "No sample_condition found or this case may not require APK sample matching.")
        return results

    sample_info = get_path(profile, "sample_info", {})
    if not isinstance(sample_info, dict) or not sample_info:
        add_result(
            results,
            "sample_condition",
            "unknown",
            "Metadata has sample_condition, but device profile has no sample_info.",
        )
        return results

    signature = sample_info.get("signature_scheme", {})
    if not isinstance(signature, dict):
        signature = {}

    requires_v1_only = bool(sc.get("requires_v1_only_apk", False))
    requires_v2_absent = bool(sc.get("requires_v2_disabled_or_absent", False))

    if requires_v1_only:
        v1 = signature.get("v1")
        if v1 is True:
            add_result(
                results,
                "sample_condition.v1_signature",
                "satisfied",
                "Sample has v1 signature.",
            )
        elif v1 is False:
            add_result(
                results,
                "sample_condition.v1_signature",
                "missing",
                "Sample does not have v1 signature, but metadata requires v1-only APK.",
                "signature_scheme_mismatch",
            )
        else:
            add_result(
                results,
                "sample_condition.v1_signature",
                "unknown",
                "Sample v1 signature status is unknown.",
            )

    if requires_v2_absent:
        v2 = signature.get("v2")
        if v2 is False:
            add_result(
                results,
                "sample_condition.v2_signature",
                "satisfied",
                "Sample does not have v2 signature.",
            )
        elif v2 is True:
            add_result(
                results,
                "sample_condition.v2_signature",
                "missing",
                "Sample has v2 signature, but metadata requires v2 disabled or absent.",
                "signature_scheme_mismatch",
            )
        else:
            add_result(
                results,
                "sample_condition.v2_signature",
                "unknown",
                "Sample v2 signature status is unknown.",
            )

    if not requires_v1_only and not requires_v2_absent:
        add_result(
            results,
            "sample_condition",
            "unknown",
            "Sample condition exists, but no v1/v2 matching rule is configured.",
        )

    return results


def check_trigger_condition(meta: Dict[str, Any], profile: Dict[str, Any]) -> List[Result]:
    results: List[Result] = []

    tc = get_path(meta, "reproduction_conditions.trigger_condition", {})
    if not isinstance(tc, dict):
        add_result(results, "trigger_condition", "unknown", "No trigger_condition found in metadata.")
        return results

    trigger_type = normalize_str(tc.get("type"))
    surface = normalize_str(tc.get("surface"))
    input_field = normalize_str(tc.get("input_field"))

    detail_parts = []
    if trigger_type:
        detail_parts.append(f"type={trigger_type}")
    if surface:
        detail_parts.append(f"surface={surface}")
    if input_field:
        detail_parts.append(f"input_field={input_field}")

    if detail_parts:
        add_result(
            results,
            "trigger_condition",
            "unknown",
            "Trigger condition requires semantic or harness-level validation: " + ", ".join(detail_parts),
        )
    else:
        add_result(
            results,
            "trigger_condition",
            "unknown",
            "Trigger condition exists but does not include enough structured fields.",
        )

    return results


def check_user_context_condition(meta: Dict[str, Any], profile: Dict[str, Any]) -> List[Result]:
    results: List[Result] = []

    uc = get_path(meta, "reproduction_conditions.user_context_condition", {})
    if not isinstance(uc, dict) or not uc:
        add_result(results, "user_context_condition", "unknown", "No user_context_condition found or not applicable.")
        return results

    cross_user = uc.get("cross_user_relevance")
    if cross_user is True:
        secondary_user = get_path(profile, "installed_components.secondary_user")
        work_profile = get_path(profile, "installed_components.work_profile")

        if secondary_user is True or work_profile is True:
            add_result(
                results,
                "user_context_condition.cross_user",
                "satisfied",
                "Device profile indicates secondary_user or work_profile is available.",
            )
        elif secondary_user is False and work_profile is False:
            add_result(
                results,
                "user_context_condition.cross_user",
                "missing",
                "CVE has cross-user relevance, but device profile has no secondary_user or work_profile.",
                "user_context_mismatch",
            )
        else:
            add_result(
                results,
                "user_context_condition.cross_user",
                "unknown",
                "CVE has cross-user relevance, but secondary_user/work_profile status is unknown.",
            )
    else:
        add_result(
            results,
            "user_context_condition",
            "unknown",
            "No explicit cross-user matching rule is configured.",
        )

    return results


def collect_failure_reason_candidates(results: List[Result], meta: Dict[str, Any]) -> List[str]:
    allowed = set(str(x) for x in as_list(get_path(meta, "failure_reason_taxonomy", [])))
    candidates: List[str] = []

    for r in results:
        reason = r.get("failure_reason", "")
        if reason and (not allowed or reason in allowed):
            candidates.append(reason)

    # Extra inference.
    statuses = [r["status"] for r in results]
    if "missing" not in statuses and "unknown" in statuses:
        if not allowed or "trigger_path_not_reachable" in allowed:
            candidates.append("trigger_path_not_reachable")

    # Deduplicate while preserving order.
    seen = set()
    out = []
    for item in candidates:
        if item not in seen:
            seen.add(item)
            out.append(item)

    return out


def summarize(
    case_dir: Path,
    device_profile_path: Path,
    meta: Dict[str, Any],
    profile: Dict[str, Any],
    results: List[Result],
    failure_reasons: List[str],
) -> str:
    lines: List[str] = []

    lines.append("# CVE Environment Match Report")
    lines.append("")
    lines.append(f"- Case directory: {case_dir}")
    lines.append(f"- Device profile: {device_profile_path}")
    lines.append(f"- CVE: {normalize_str(meta.get('cve')) or 'N/A'}")
    lines.append(f"- Name: {normalize_str(meta.get('name')) or 'N/A'}")
    lines.append(f"- Category: {normalize_str(meta.get('category')) or 'N/A'}")
    lines.append("")

    lines.append("## Device")
    lines.append("")
    lines.append(f"- model: {normalize_str(get_path(profile, 'device.model')) or 'N/A'}")
    lines.append(f"- android_version: {normalize_str(get_path(profile, 'device.android_version')) or 'N/A'}")
    lines.append(f"- sdk: {normalize_str(get_path(profile, 'device.sdk')) or 'N/A'}")
    lines.append(f"- security_patch: {normalize_str(get_path(profile, 'device.security_patch')) or 'N/A'}")
    lines.append(f"- selinux: {normalize_str(get_path(profile, 'device.selinux')) or 'N/A'}")
    lines.append("")

    lines.append("## Condition Results")
    lines.append("")
    lines.append("| Condition | Status | Detail | Failure reason |")
    lines.append("|---|---|---|---|")
    for r in results:
        lines.append(
            f"| {r['category']} | {r['status']} | {r['detail']} | {r.get('failure_reason', '')} |"
        )
    lines.append("")

    satisfied = sum(1 for r in results if r["status"] == "satisfied")
    missing = sum(1 for r in results if r["status"] == "missing")
    unknown = sum(1 for r in results if r["status"] == "unknown")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- satisfied: {satisfied}")
    lines.append(f"- missing: {missing}")
    lines.append(f"- unknown: {unknown}")
    lines.append("")

    lines.append("## Failure Reason Candidates")
    lines.append("")
    if failure_reasons:
        for reason in failure_reasons:
            lines.append(f"- {reason}")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Interpretation")
    lines.append("")
    if missing > 0:
        lines.append("Current profile clearly misses at least one required condition.")
    elif unknown > 0:
        lines.append("No clear missing condition was found, but some conditions remain unknown.")
    else:
        lines.append("All currently supported v0.1 checks are satisfied.")
    lines.append("")
    lines.append("This report is generated for defensive validation and patch-effect analysis only.")
    lines.append("")

    return "\n".join(lines)


def resolve_output_path(case_dir: Path, out: Optional[str], save: bool) -> Optional[Path]:
    if out:
        return Path(out)

    if save:
        logs_dir = case_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        return logs_dir / "environment_match_output.txt"

    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check a CVE case metadata.yaml against a device_profile.yaml."
    )
    parser.add_argument("case_dir", help="Path to CVE case directory")
    parser.add_argument("device_profile", help="Path to device_profile.yaml")
    parser.add_argument("--save", action="store_true", help="Save report to <case_dir>/logs/environment_match_output.txt")
    parser.add_argument("--out", default=None, help="Save report to custom output path")

    args = parser.parse_args()

    case_dir = Path(args.case_dir).resolve()
    metadata_path = case_dir / "metadata.yaml"
    device_profile_path = Path(args.device_profile).resolve()

    meta = load_yaml(metadata_path)
    profile = load_yaml(device_profile_path)

    results: List[Result] = []
    results.extend(check_version_condition(meta, profile))
    results.extend(check_component_condition(meta, profile))
    results.extend(check_sample_condition(meta, profile))
    results.extend(check_trigger_condition(meta, profile))
    results.extend(check_user_context_condition(meta, profile))

    failure_reasons = collect_failure_reason_candidates(results, meta)

    report = summarize(
        case_dir=case_dir,
        device_profile_path=device_profile_path,
        meta=meta,
        profile=profile,
        results=results,
        failure_reasons=failure_reasons,
    )

    out_path = resolve_output_path(case_dir, args.out, args.save)
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report, encoding="utf-8")
        print(f"[+] Environment match report saved: {out_path}")
    else:
        print(report)


if __name__ == "__main__":
    main()