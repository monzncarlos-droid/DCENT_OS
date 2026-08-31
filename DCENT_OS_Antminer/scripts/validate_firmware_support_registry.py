#!/usr/bin/env python3
"""Fail closed on contradictions or invented DCENT_OS public release evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


EXPECTED_MODELS = (
    "s9",
    "s9-se",
    "t17",
    "s17",
    "t17-plus",
    "s17-plus",
    "s19",
    "s19-pro",
    "s19j-pro",
    "s19k-pro",
    "s21",
    "s21-xp",
    "s21-pro",
)

EXPECTED_SCHEMA_VERSION = "1.3.0"
EXPECTED_LOCALIZATION_LOCALE = "fr-CA"
EXPECTED_LOCALIZED_MODEL_FIELDS = (
    "control_board_summary",
    "artifact_statement",
    "mining",
    "install",
    "recovery",
    "summary",
)
LOCALIZED_MODEL_MIN_LENGTHS = {
    "control_board_summary": 10,
    "artifact_statement": 20,
    "mining": 30,
    "install": 30,
    "recovery": 30,
    "summary": 60,
}
FORBIDDEN_LOCALIZED_STATUS_FIELDS = {"availability", "maturity"}

EXPECTED_ARTIFACTS = {
    "s9-xil-sysupgrade": (
        "s9",
        "DCENTOS_XIL1_S9_beta20260709.tar",
        23009280,
        "e0bd9e30c7277a86f0c601bb882f41a7dd311160e29d7aefc4e017d2454ab845",
    ),
    "s9-xil-sd": (
        "s9",
        "DCENTOS_XIL1_S9_SD_beta20260709.img",
        67108864,
        "1c61fde315ce6eadcef5df79690ed15558173c96216680970f8de3360081b266",
    ),
    "s19j-pro-xil-sysupgrade": (
        "s19j-pro",
        "DCENTOS_XIL3_S19jPro_beta20260709.tar",
        26511360,
        "e7afc67cd9f7c9cda0bcd329f61116ef352644c3ae707741e04e1e1e5e7b2a96",
    ),
}

EXPECTED_RELEASE_PROVENANCE = {
    "release_id": "beta20260709",
    "github_release_tag": "v0.3.0",
    "github_release_published_at": "2026-07-13",
    "github_release_url": "https://github.com/DCentralTech/DCENT_OS/releases/tag/v0.3.0",
    "github_release_commit": "a24f246eb36a342f2cdf474e0bbe77050ec2c6b3",
    "github_release_notes_status": "NOT_PUBLISHED",
    "github_release_notes_note": (
        "The public GitHub release has no title or body. The tagged commit subject "
        "below is provenance, not authored release notes."
    ),
    "github_tagged_commit_authored_at": "2026-07-10",
    "github_tagged_commit_subject": (
        "CI, verbatim GPL-3.0 license, honest readiness matrix, dashboard "
        "screenshots, testing guide"
    ),
    "github_public_release_count_at_review": 1,
    "github_public_tag_count_at_review": 1,
    "embedded_manifest_public_key_fingerprint_sha256": (
        "26985575eae77d56c490ceeb9054af012eab5ae59119cd20eaa70dd7e722df83"
    ),
}

FORBIDDEN_RELEASE_PHRASES = (
    "coming soon",
    "unreleased",
    "not released",
    "only selected models are available",
    "only s9 and s19j pro are released",
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("registry root must be an object")
    return value


def reject_localized_status_overrides(
    value: Any, path: str, errors: list[str]
) -> None:
    """Reject locale-owned copies of the canonical release-status axes."""
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in FORBIDDEN_LOCALIZED_STATUS_FIELDS:
                errors.append(
                    f"{child_path}: localized availability or maturity overrides are forbidden"
                )
            reject_localized_status_overrides(child, child_path, errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_localized_status_overrides(child, f"{path}[{index}]", errors)


def validate_localizations(registry: dict[str, Any]) -> list[str]:
    """Validate the complete fr-CA display overlay without duplicating status truth."""
    errors: list[str] = []
    localizations = registry.get("localizations")
    if not isinstance(localizations, dict):
        return ["localizations must be an object containing the fr-CA display overlay"]

    reject_localized_status_overrides(localizations, "localizations", errors)
    actual_locales = tuple(localizations.keys())
    expected_locales = (EXPECTED_LOCALIZATION_LOCALE,)
    if actual_locales != expected_locales:
        errors.append(
            "localization locale keys/order differ from the public display contract: "
            f"expected {expected_locales!r}, got {actual_locales!r}"
        )

    locale = localizations.get(EXPECTED_LOCALIZATION_LOCALE)
    if not isinstance(locale, dict):
        errors.append(f"localizations.{EXPECTED_LOCALIZATION_LOCALE} must be an object")
        return errors

    expected_locale_fields = {"shared", "models"}
    if set(locale.keys()) != expected_locale_fields:
        errors.append(
            f"localizations.{EXPECTED_LOCALIZATION_LOCALE} must contain exactly "
            "shared and models"
        )

    shared = locale.get("shared")
    if not isinstance(shared, dict) or not shared:
        errors.append(
            f"localizations.{EXPECTED_LOCALIZATION_LOCALE}.shared must be a nonempty object"
        )
    else:
        for key, text in shared.items():
            if not isinstance(text, str) or not text.strip():
                errors.append(
                    f"localizations.{EXPECTED_LOCALIZATION_LOCALE}.shared.{key} "
                    "must be a nonempty localized display string"
                )

    localized_models = locale.get("models")
    if not isinstance(localized_models, dict):
        errors.append(
            f"localizations.{EXPECTED_LOCALIZATION_LOCALE}.models must be an object"
        )
        return errors

    actual_model_keys = tuple(localized_models.keys())
    if actual_model_keys != EXPECTED_MODELS:
        errors.append(
            f"localizations.{EXPECTED_LOCALIZATION_LOCALE}.models keys/order differ "
            "from the settled 13-model contract: "
            f"expected {EXPECTED_MODELS!r}, got {actual_model_keys!r}"
        )

    expected_fields = set(EXPECTED_LOCALIZED_MODEL_FIELDS)
    for key in EXPECTED_MODELS:
        localized_model = localized_models.get(key)
        if not isinstance(localized_model, dict):
            errors.append(
                f"localizations.{EXPECTED_LOCALIZATION_LOCALE}.models.{key} "
                "must be an object"
            )
            continue
        if set(localized_model.keys()) != expected_fields:
            errors.append(
                f"localizations.{EXPECTED_LOCALIZATION_LOCALE}.models.{key} must contain "
                f"exactly {EXPECTED_LOCALIZED_MODEL_FIELDS!r}"
            )
        for field, minimum in LOCALIZED_MODEL_MIN_LENGTHS.items():
            text = localized_model.get(field)
            if not isinstance(text, str) or len(text.strip()) < minimum:
                errors.append(
                    f"localizations.{EXPECTED_LOCALIZATION_LOCALE}.models.{key}.{field} "
                    f"must be a localized display string of at least {minimum} characters"
                )

    return errors


def validate_registry(registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != EXPECTED_SCHEMA_VERSION:
        errors.append(f"schema_version must be {EXPECTED_SCHEMA_VERSION}")
    errors.extend(validate_localizations(registry))

    models = registry.get("models")
    if not isinstance(models, dict):
        return ["models must be an object keyed by canonical model key"]

    actual_models = tuple(models.keys())
    if actual_models != EXPECTED_MODELS:
        errors.append(
            "model keys/order differ from the settled 13-model contract: "
            f"expected {EXPECTED_MODELS!r}, got {actual_models!r}"
        )
    if registry.get("scope", {}).get("released_model_count") != len(EXPECTED_MODELS):
        errors.append("scope.released_model_count must equal 13")

    availability = registry.get("canonical_status", {}).get("availability", {})
    maturity = registry.get("canonical_status", {}).get("maturity", {})
    if availability.get("value") != "RELEASED":
        errors.append("canonical availability must be RELEASED")
    if maturity.get("value") != "EXPERIMENTAL":
        errors.append("canonical maturity must be EXPERIMENTAL")
    if availability.get("label_en") != "AVAILABILITY: RELEASED":
        errors.append("canonical English availability label drifted")
    if maturity.get("label_en") != "MATURITY: EXPERIMENTAL":
        errors.append("canonical English maturity label drifted")

    slugs: set[str] = set()
    referenced_artifacts: set[str] = set()
    for key, model in models.items():
        if model.get("availability") != "RELEASED":
            errors.append(f"{key}: availability must be RELEASED")
        if model.get("maturity") != "EXPERIMENTAL":
            errors.append(f"{key}: maturity must be EXPERIMENTAL")
        slug = model.get("slug")
        if not isinstance(slug, str) or not re.fullmatch(r"antminer-[a-z0-9-]+", slug):
            errors.append(f"{key}: invalid public slug {slug!r}")
        elif slug in slugs:
            errors.append(f"{key}: duplicate public slug {slug}")
        else:
            slugs.add(slug)

        artifact_ids = model.get("artifact_ids")
        if not isinstance(artifact_ids, list):
            errors.append(f"{key}: artifact_ids must be a list")
            continue
        referenced_artifacts.update(str(item) for item in artifact_ids)
        if artifact_ids and model.get("artifact_status") != "VERIFIED_PREBUILT":
            errors.append(f"{key}: artifact ids require VERIFIED_PREBUILT")
        if not artifact_ids and model.get("artifact_status") != "NO_VERIFIED_PREBUILT_IN_CURRENT_LEDGER":
            errors.append(f"{key}: empty artifact list must use the explicit no-evidence status")

    artifacts = registry.get("artifact_ledger", {}).get("artifacts")
    ledger = registry.get("artifact_ledger", {})
    for field, expected in EXPECTED_RELEASE_PROVENANCE.items():
        if ledger.get(field) != expected:
            errors.append(
                f"artifact_ledger.{field}: immutable release provenance drifted"
            )
    if not isinstance(artifacts, dict):
        errors.append("artifact_ledger.artifacts must be an object")
        artifacts = {}
    if set(artifacts) != set(EXPECTED_ARTIFACTS):
        errors.append("artifact ledger must contain exactly the three verified public files")
    if referenced_artifacts != set(EXPECTED_ARTIFACTS):
        errors.append("model artifact references must cover exactly the verified artifact ledger")
    for artifact_id, expected in EXPECTED_ARTIFACTS.items():
        artifact = artifacts.get(artifact_id, {})
        actual = (
            artifact.get("model_key"),
            artifact.get("filename"),
            artifact.get("bytes"),
            artifact.get("sha256"),
        )
        if actual != expected:
            errors.append(f"{artifact_id}: immutable artifact receipt drifted: {actual!r}")
        if artifact.get("outer_detached_signature") != "NOT_LOCATED":
            errors.append(f"{artifact_id}: no outer detached signature may be claimed")
    if registry.get("artifact_ledger", {}).get("outer_checksum_list_detached_signature") != "NOT_LOCATED":
        errors.append("SHA256SUMS detached signature must remain NOT_LOCATED")

    serialized = json.dumps(registry, ensure_ascii=False).lower()
    for phrase in FORBIDDEN_RELEASE_PHRASES:
        if phrase in serialized:
            errors.append(f"registry contains stale release-status phrase: {phrase!r}")

    return errors


def main() -> int:
    default_registry = Path(__file__).resolve().parents[1] / "docs" / "release" / "firmware-support-registry.json"
    parser = argparse.ArgumentParser()
    parser.add_argument("registry", nargs="?", type=Path, default=default_registry)
    parser.add_argument("--schema", type=Path, help="also validate with jsonschema when installed")
    args = parser.parse_args()

    try:
        registry = load_json(args.registry)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    errors = validate_registry(registry)
    if args.schema:
        try:
            import jsonschema
        except ImportError:
            errors.append("jsonschema is required when --schema is supplied")
        else:
            try:
                jsonschema.validate(registry, load_json(args.schema))
            except jsonschema.ValidationError as exc:
                errors.append(f"schema validation: {exc.message}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        f"PASS: {len(registry['models'])} models with AVAILABILITY: RELEASED and MATURITY: EXPERIMENTAL; "
        f"{len(registry['artifact_ledger']['artifacts'])} verified artifact receipts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
