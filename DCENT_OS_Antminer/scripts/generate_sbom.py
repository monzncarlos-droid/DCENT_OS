#!/usr/bin/env python3
"""Emit a standard-format CycloneDX SBOM from a Buildroot legal-info manifest.

Motivated by arXiv:2605.03770 recommendation #5 (ship an SBOM for tracked
dependencies). DCENT_OS already runs `make legal-info` and hash-inventories its
output (`buildroot_legal_inventory.py`), but that inventory is deliberately NOT
an SBOM (`is_sbom: False`). This converter closes that gap: it reads the
Buildroot `manifest.csv` (and optional `host-manifest.csv`) that `make
legal-info` emits and produces a CycloneDX 1.5 JSON document — the machine
readable component inventory the paper calls for.

Scope is honest: this is a component/version/license inventory derived from
Buildroot's own manifest. It is NOT a vulnerability assessment, NOT a
license-compliance opinion, and does NOT cover Rust crates, container base
packages, or firmware blobs outside Buildroot legal-info. Those are separate
lanes (Cargo has its own SBOM tooling; note them in `--note`).

Deterministic by default: no timestamp and no random serial number are emitted
unless `--source-date-epoch` / `--serial` are given, so two runs over the same
manifest produce byte-identical output (hashable as a release artifact).

Usage:
  generate_sbom.py --manifest buildroot/output/legal-info/manifest.csv \\
      [--host-manifest .../host-manifest.csv] \\
      --target am2-s19jpro --component-version 0.5.0 \\
      [--source-date-epoch 1723000000] [--output sbom.cdx.json]
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any


CYCLONEDX_SPEC_VERSION = "1.5"

# Buildroot manifest.csv header names we understand (matched case-insensitively).
_PACKAGE_KEYS = ("PACKAGE",)
_VERSION_KEYS = ("VERSION",)
_LICENSE_KEYS = ("LICENSE",)
_SOURCE_SITE_KEYS = ("SOURCE SITE", "SITE")
_SOURCE_ARCHIVE_KEYS = ("SOURCE ARCHIVE", "SOURCE")


def _pick(row: dict[str, str], keys: tuple[str, ...]) -> str:
    for key in keys:
        if key in row and row[key] is not None:
            return row[key].strip()
    return ""


def _purl(name: str, version: str) -> str:
    # Buildroot packages have no universal package namespace; pkg:generic is the
    # honest CycloneDX purl type for a Buildroot-managed source package.
    safe_name = name.strip().replace(" ", "-")
    if version:
        return f"pkg:generic/{safe_name}@{version}"
    return f"pkg:generic/{safe_name}"


def _licenses(license_field: str) -> list[dict[str, Any]]:
    """Buildroot LICENSE is a free-form, comma/space-separated expression.

    We emit each token as a named license entry. We deliberately do NOT claim
    SPDX-ID conformance — Buildroot license strings are not guaranteed SPDX IDs
    (e.g. "GPL-2.0+", "BSD-3c", "PROPRIETARY"), so a `name` field is the honest
    representation rather than a possibly-wrong `id`.
    """
    if not license_field:
        return []
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for token in license_field.replace(",", " ").split():
        token = token.strip()
        if token and token not in seen:
            seen.add(token)
            out.append({"license": {"name": token}})
    return out


def parse_manifest(text: str, scope: str) -> list[dict[str, Any]]:
    """Parse a Buildroot manifest.csv into CycloneDX component dicts.

    ``scope`` is "required" (target manifest) or "optional" (host manifest) and
    is recorded on each component so consumers can filter host-build tooling out
    of a runtime SBOM.
    """
    reader = csv.DictReader(text.splitlines())
    if reader.fieldnames is None:
        return []
    # Normalize header names to upper-case for tolerant matching.
    field_map = {name: name.strip().upper() for name in reader.fieldnames}

    components: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for raw_row in reader:
        row = {field_map.get(k, k): (v or "") for k, v in raw_row.items()}
        name = _pick(row, _PACKAGE_KEYS)
        if not name:
            continue
        version = _pick(row, _VERSION_KEYS)
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)

        component: dict[str, Any] = {
            "type": "library",
            "name": name,
            "bom-ref": _purl(name, version) if version else f"pkg:generic/{name}",
            "purl": _purl(name, version),
            "scope": scope,
        }
        if version:
            component["version"] = version
        licenses = _licenses(_pick(row, _LICENSE_KEYS))
        if licenses:
            component["licenses"] = licenses
        site = _pick(row, _SOURCE_SITE_KEYS)
        archive = _pick(row, _SOURCE_ARCHIVE_KEYS)
        externals = []
        if site:
            externals.append({"type": "distribution", "url": site})
        if archive:
            externals.append({"type": "distribution", "comment": "source-archive", "url": archive})
        if externals:
            component["externalReferences"] = externals
        components.append(component)

    components.sort(key=lambda c: (c["name"], c.get("version", "")))
    return components


def build_sbom(
    components: list[dict[str, Any]],
    target: str,
    component_version: str,
    source_date_epoch: int | None,
    serial: str | None,
    note: str | None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "component": {
            "type": "operating-system",
            "name": f"dcentos-{target}",
            "version": component_version,
        },
        "tools": [{"vendor": "D-Central Technologies", "name": "generate_sbom.py"}],
        "properties": [
            {"name": "dcentos:source", "value": "buildroot-legal-info-manifest"},
            {"name": "dcentos:scope", "value": "buildroot-packages-only"},
            {
                "name": "dcentos:excludes",
                "value": "rust-crates,container-base,firmware-blobs,vulnerability-analysis",
            },
        ],
    }
    if note:
        metadata["properties"].append({"name": "dcentos:note", "value": note})
    if source_date_epoch is not None:
        metadata["timestamp"] = (
            dt.datetime.fromtimestamp(source_date_epoch, tz=dt.timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ")
        )

    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
        "metadata": metadata,
        "components": components,
    }
    if serial is not None:
        sbom["serialNumber"] = serial
    return sbom


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--manifest", required=True, help="Buildroot legal-info manifest.csv (target)")
    p.add_argument("--host-manifest", help="Optional Buildroot host-manifest.csv")
    p.add_argument("--target", required=True, help="Board target label, e.g. am2-s19jpro")
    p.add_argument("--component-version", default="0.0.0", help="DCENT_OS image version")
    p.add_argument(
        "--source-date-epoch",
        type=int,
        default=None,
        help="Unix epoch for a reproducible timestamp; omit for deterministic output",
    )
    p.add_argument("--serial", default=None, help="Optional CycloneDX serialNumber (urn:uuid:...)")
    p.add_argument("--note", default=None, help="Free-text note recorded in metadata properties")
    p.add_argument("--output", default="-", help="Output path, or - for stdout")
    args = p.parse_args(argv)

    manifest_path = Path(args.manifest)
    if not manifest_path.is_file():
        print(f"ERROR: manifest not found: {manifest_path}", file=sys.stderr)
        return 1

    components = parse_manifest(manifest_path.read_text(encoding="utf-8", errors="replace"), "required")
    if args.host_manifest:
        host_path = Path(args.host_manifest)
        if host_path.is_file():
            components += parse_manifest(
                host_path.read_text(encoding="utf-8", errors="replace"), "optional"
            )
        else:
            print(f"WARNING: host manifest not found, skipping: {host_path}", file=sys.stderr)

    if not components:
        print("ERROR: no packages parsed from manifest(s)", file=sys.stderr)
        return 1

    sbom = build_sbom(
        components,
        target=args.target,
        component_version=args.component_version,
        source_date_epoch=args.source_date_epoch,
        serial=args.serial,
        note=args.note,
    )
    text = json.dumps(sbom, indent=2, sort_keys=False) + "\n"

    if args.output == "-":
        sys.stdout.write(text)
    else:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"{out}  ({len(components)} components)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
