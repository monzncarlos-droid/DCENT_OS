#!/usr/bin/env python3
"""Single source of truth and drift gate for DCENT_OS-for-ESP board targets."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

from hardware_evidence import load_evidence_index, production_claim_errors

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "esp-targets.json"

REQUIRED_FIELDS = {
    "board_target",
    "feature",
    "model_variant",
    "device_model",
    "hardware_family",
    "asic",
    "chip_count",
    "release_scope",
    "support_tier",
    "evidence_level",
    "runtime_mode",
    "install_policy",
    "package_policy",
    "flash_layout",
    "blockers",
}
OPTIONAL_FIELDS = {"promotion_receipt_id"}


class MatrixError(ValueError):
    """The target manifest or one of its source mirrors drifted."""


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise MatrixError("target manifest root must be an object")
    return data


def targets_for_scope(data: dict[str, Any], scope: str) -> list[dict[str, Any]]:
    targets = list(data.get("targets") or [])
    if scope == "all":
        return targets
    return [target for target in targets if target.get("release_scope") == scope]


def _unique(values: Iterable[str], label: str) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    if duplicates:
        raise MatrixError(f"duplicate {label}: {sorted(duplicates)}")


def _feature_names(cargo_toml: str) -> set[str]:
    match = re.search(r"(?ms)^\[features\]\s*$\n(.*?)(?=^\[|\Z)", cargo_toml)
    if not match:
        raise MatrixError("dcentaxe/Cargo.toml has no [features] block")
    return {
        item.group(1).strip()
        for item in re.finditer(r"(?m)^([A-Za-z0-9_-]+)\s*=", match.group(1))
    }


def _rust_match_map(source: str, function_name: str) -> dict[str, str]:
    start = source.find(f"pub fn {function_name}")
    if start < 0:
        raise MatrixError(f"board.rs is missing pub fn {function_name}")
    end = source.find("\n    pub fn ", start + 1)
    block = source[start : end if end >= 0 else len(source)]
    return dict(re.findall(r'Self::([A-Za-z0-9_]+)\s*=>\s*"([^"]+)"', block))


def _config_feature_map(source: str) -> dict[str, str]:
    start = source.find("pub(crate) fn default_model_for_build")
    end = source.find("\npub(crate) fn default_profile_for_build", start)
    if start < 0 or end < 0:
        raise MatrixError("config.rs default_model_for_build block was not found")
    block = source[start:end]
    result: dict[str, str] = {}
    pattern = re.compile(
        r'cfg!\(feature\s*=\s*"([^"]+)"\).*?BitAxeModel::([A-Za-z0-9_]+)',
        re.S,
    )
    for feature, variant in pattern.findall(block):
        result[feature] = variant
    return result


def validate_manifest(
    data: dict[str, Any], root: Path = ROOT, validate_evidence: bool = True
) -> list[str]:
    errors: list[str] = []
    if data.get("schema") != 1:
        errors.append("manifest schema must be 1")
    targets = data.get("targets")
    if not isinstance(targets, list) or not targets:
        errors.append("manifest targets must be a non-empty array")
        targets = []

    allowed = {
        "release_scope": {"public", "internal"},
        "support_tier": {"production", "beta", "experimental"},
        "evidence_level": {"none", "host", "focused-run", "sustained-soak"},
        "runtime_mode": {"mining", "identity-only"},
        "install_policy": {"production", "public-beta", "lab-only", "blocked"},
        "package_policy": {"public", "lab", "diagnostic"},
        "flash_layout": {"standard", "n16r8"},
    }

    for index, target in enumerate(targets):
        label = target.get("board_target", f"index {index}") if isinstance(target, dict) else f"index {index}"
        if not isinstance(target, dict):
            errors.append(f"{label}: target must be an object")
            continue
        missing = sorted(REQUIRED_FIELDS - set(target))
        if missing:
            errors.append(f"{label}: missing fields {missing}")
        for field, choices in allowed.items():
            if target.get(field) not in choices:
                errors.append(f"{label}: invalid {field}={target.get(field)!r}")
        if target.get("feature") != target.get("board_target"):
            errors.append(f"{label}: board feature must equal board_target")
        if not isinstance(target.get("chip_count"), int) or target.get("chip_count", 0) < 1:
            errors.append(f"{label}: chip_count must be a positive integer")
        if not isinstance(target.get("blockers"), list):
            errors.append(f"{label}: blockers must be an array")
        if target.get("release_scope") == "public":
            if target.get("package_policy") != "public" or target.get("install_policy") not in {
                "production",
                "public-beta",
            }:
                errors.append(f"{label}: public rows must use public and production/public-beta policies")
            if target.get("runtime_mode") != "mining":
                errors.append(f"{label}: a public row cannot be identity-only")
        if target.get("install_policy") == "blocked" and target.get("runtime_mode") != "identity-only":
            errors.append(f"{label}: blocked rows must be identity-only")
        if str(target.get("board_target", "")).startswith("hammer-"):
            if target.get("runtime_mode") == "identity-only" and (
                target.get("install_policy") != "blocked"
                or target.get("package_policy") != "diagnostic"
            ):
                errors.append(f"{label}: identity-only Hammer rows must stay blocked/diagnostic")
            if target.get("runtime_mode") == "mining" and any(
                blocker in (target.get("blockers") or [])
                for blocker in ("verified-rail-cut", "trusted-thermal")
            ):
                errors.append(
                    f"{label}: Hammer mining mode cannot retain rail-cut or trusted-thermal blockers"
                )
        if (
            target.get("flash_layout") == "n16r8"
            and target.get("release_scope") == "public"
            and target.get("install_policy") != "production"
        ):
            errors.append(f"{label}: public n16r8 targets require the exact-receipt production policy")

    try:
        _unique((target["board_target"] for target in targets), "board_target")
        _unique((target["feature"] for target in targets), "feature")
        _unique((target["model_variant"] for target in targets), "model_variant")
    except (KeyError, MatrixError) as exc:
        errors.append(str(exc))

    try:
        cargo_source = (root / "dcentaxe" / "Cargo.toml").read_text(encoding="utf-8")
        cargo_features = _feature_names(cargo_source)
        manifest_features = {target["feature"] for target in targets}
        missing_features = sorted(manifest_features - cargo_features)
        if missing_features:
            errors.append(f"manifest board features missing from Cargo.toml: {missing_features}")

        build_source = (root / "dcentaxe" / "build.rs").read_text(encoding="utf-8")
        build_targets = set(re.findall(r'selected_targets\.push\("([^"]+)"\)', build_source))
        manifest_targets = {target["board_target"] for target in targets}
        if build_targets != manifest_targets:
            errors.append(
                "build.rs target set drift: "
                f"missing={sorted(manifest_targets - build_targets)} extra={sorted(build_targets - manifest_targets)}"
            )

        config_source = (root / "dcentaxe" / "src" / "config.rs").read_text(encoding="utf-8")
        config_map = _config_feature_map(config_source)
        for target in targets:
            observed = config_map.get(target["feature"])
            if observed != target["model_variant"]:
                errors.append(
                    f"{target['board_target']}: config.rs maps feature to {observed!r}, "
                    f"expected {target['model_variant']!r}"
                )

        board_source = (root / "dcentaxe-hal" / "src" / "board.rs").read_text(encoding="utf-8")
        canonical_map = _rust_match_map(board_source, "canonical_key")
        board_target_map = _rust_match_map(board_source, "board_target")
        for target in targets:
            variant = target["model_variant"]
            if canonical_map.get(variant) != target["device_model"]:
                errors.append(
                    f"{target['board_target']}: canonical_key drift: "
                    f"Rust={canonical_map.get(variant)!r} manifest={target['device_model']!r}"
                )
            if board_target_map.get(variant) != target["board_target"]:
                errors.append(
                    f"{target['board_target']}: board_target drift: "
                    f"Rust={board_target_map.get(variant)!r}"
                )
    except (OSError, MatrixError, KeyError) as exc:
        errors.append(str(exc))

    if validate_evidence:
        try:
            evidence_index = load_evidence_index(root / "hardware-evidence" / "index.json")
            errors.extend(production_claim_errors(data, evidence_index, root))
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"hardware evidence authority: {exc}")

    return errors


def require_valid(
    data: dict[str, Any], root: Path = ROOT, validate_evidence: bool = True
) -> None:
    errors = validate_manifest(data, root, validate_evidence)
    if errors:
        raise MatrixError("\n".join(f"- {error}" for error in errors))


def find_target(data: dict[str, Any], board_target: str) -> dict[str, Any]:
    for target in data["targets"]:
        if target["board_target"] == board_target:
            return target
    raise MatrixError(f"unknown board target {board_target!r}")


def render_targets(targets: list[dict[str, Any]], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(targets, separators=(",", ":"), sort_keys=True)
    if output_format == "github":
        include = [
            {
                "feature": target["feature"],
                "board_target": target["board_target"],
                "device_model": target["device_model"],
                "flash_layout": target["flash_layout"],
                "package_policy": target["package_policy"],
                "publish": target["package_policy"] == "public",
            }
            for target in targets
        ]
        return json.dumps({"include": include}, separators=(",", ":"))
    if output_format == "lines":
        return "\n".join(target["board_target"] for target in targets)
    if output_format == "tsv":
        return "\n".join(
            "\t".join(
                str(target[field])
                for field in ("feature", "board_target", "device_model", "flash_layout", "package_policy")
            )
            for target in targets
        )
    raise MatrixError(f"unsupported output format {output_format!r}")


def render_readiness(targets: list[dict[str, Any]]) -> str:
    lines = [
        "| Target | Family | ASICs | Tier | Offline evidence | Runtime | Install | Remaining gates |",
        "|---|---|---:|---|---|---|---|---|",
    ]
    for target in targets:
        values = dict(target)
        values["blockers"] = ", ".join(target["blockers"]) or "none"
        lines.append(
            "| `{board_target}` | {hardware_family} | {chip_count}x {asic} | {support_tier} | "
            "{evidence_level} | {runtime_mode} | {install_policy} | {blockers} |".format(**values)
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate", help="Validate schema and every Rust/build/package binding")

    list_parser = sub.add_parser("list", help="Render a dynamic target list")
    list_parser.add_argument("--scope", choices=("public", "internal", "all"), default="all")
    list_parser.add_argument("--format", choices=("json", "github", "lines", "tsv"), default="json")
    list_parser.add_argument("--package-policy", choices=("public", "lab", "diagnostic"))

    lookup = sub.add_parser("lookup", help="Read one target field")
    lookup.add_argument("board_target")
    lookup.add_argument("field", choices=sorted(REQUIRED_FIELDS | OPTIONAL_FIELDS))

    row = sub.add_parser("row", help="Render one complete target row")
    row.add_argument("board_target")
    row.add_argument("--format", choices=("json", "tsv"), default="json")

    readiness = sub.add_parser("readiness", help="Render the honest per-target readiness table")
    readiness.add_argument("--scope", choices=("public", "internal", "all"), default="all")

    args = parser.parse_args(argv)
    try:
        data = load_manifest(args.manifest)
        require_valid(data)
        if args.command == "validate":
            print(f"ESP target matrix valid: {len(data['targets'])} targets")
        elif args.command == "list":
            selected = targets_for_scope(data, args.scope)
            if args.package_policy:
                selected = [t for t in selected if t["package_policy"] == args.package_policy]
            print(render_targets(selected, args.format))
        elif args.command == "lookup":
            value = find_target(data, args.board_target).get(args.field)
            if value is not None:
                print(json.dumps(value) if isinstance(value, (list, dict)) else value)
        elif args.command == "row":
            target = find_target(data, args.board_target)
            if args.format == "json":
                print(json.dumps(target, separators=(",", ":"), sort_keys=True))
            else:
                print(
                    "\t".join(
                        str(target[field])
                        for field in (
                            "device_model",
                            "hardware_family",
                            "support_tier",
                            "evidence_level",
                            "runtime_mode",
                            "install_policy",
                            "package_policy",
                            "flash_layout",
                        )
                    )
                )
        elif args.command == "readiness":
            print(render_readiness(targets_for_scope(data, args.scope)))
        return 0
    except (MatrixError, OSError, json.JSONDecodeError) as exc:
        print(f"target matrix error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
