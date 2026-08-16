#!/usr/bin/env python3
"""Tests for generate_sbom.py — Buildroot manifest.csv -> CycloneDX SBOM."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from generate_sbom import build_sbom, main, parse_manifest  # noqa: E402


# Buildroot manifest.csv header shape (subset of real columns).
_MANIFEST = (
    "PACKAGE,VERSION,LICENSE,LICENSE FILES,SOURCE ARCHIVE,SOURCE SITE\n"
    "busybox,1.36.1,GPL-2.0,LICENSE,busybox-1.36.1.tar.bz2,https://busybox.net/downloads\n"
    "dropbear,2022.83,MIT,LICENSE,dropbear-2022.83.tar.bz2,https://matt.ucc.asn.au\n"
    "bash,5.2,GPL-3.0+,COPYING,bash-5.2.tar.gz,https://ftp.gnu.org/gnu/bash\n"
)

_HOST_MANIFEST = (
    "PACKAGE,VERSION,LICENSE\n"
    "host-gcc-final,12.3.0,GPL-3.0+\n"
)


def test_parse_manifest_basic():
    comps = parse_manifest(_MANIFEST, "required")
    names = {c["name"] for c in comps}
    assert names == {"busybox", "dropbear", "bash"}
    bb = next(c for c in comps if c["name"] == "busybox")
    assert bb["version"] == "1.36.1"
    assert bb["purl"] == "pkg:generic/busybox@1.36.1"
    assert bb["scope"] == "required"
    assert bb["licenses"] == [{"license": {"name": "GPL-2.0"}}]


def test_parse_manifest_sorted():
    comps = parse_manifest(_MANIFEST, "required")
    assert [c["name"] for c in comps] == ["bash", "busybox", "dropbear"]


def test_parse_manifest_external_refs():
    comps = parse_manifest(_MANIFEST, "required")
    bb = next(c for c in comps if c["name"] == "busybox")
    urls = {r["url"] for r in bb["externalReferences"]}
    assert "https://busybox.net/downloads" in urls


def test_parse_manifest_deduplicates():
    dup = _MANIFEST + "busybox,1.36.1,GPL-2.0,LICENSE,busybox-1.36.1.tar.bz2,https://busybox.net\n"
    comps = parse_manifest(dup, "required")
    assert sum(1 for c in comps if c["name"] == "busybox") == 1


def test_license_expression_split():
    manifest = "PACKAGE,VERSION,LICENSE\nfoo,1.0,GPL-2.0+ or MIT\n"
    comps = parse_manifest(manifest, "required")
    names = [lic["license"]["name"] for lic in comps[0]["licenses"]]
    assert "GPL-2.0+" in names and "MIT" in names and "or" in names  # honest tokenization


def test_case_insensitive_headers():
    manifest = "package,version,license\nfoo,1.0,MIT\n"
    comps = parse_manifest(manifest, "required")
    assert comps[0]["name"] == "foo" and comps[0]["version"] == "1.0"


def test_build_sbom_shape_and_determinism():
    comps = parse_manifest(_MANIFEST, "required")
    a = build_sbom(comps, "am2-s19jpro", "0.5.0", None, None, None)
    b = build_sbom(comps, "am2-s19jpro", "0.5.0", None, None, None)
    assert a["bomFormat"] == "CycloneDX"
    assert a["specVersion"] == "1.5"
    assert a["metadata"]["component"]["name"] == "dcentos-am2-s19jpro"
    # No timestamp / serial by default -> byte-identical (reproducible artifact).
    assert json.dumps(a) == json.dumps(b)
    assert "timestamp" not in a["metadata"]
    assert "serialNumber" not in a


def test_build_sbom_optional_timestamp_and_serial():
    comps = parse_manifest(_MANIFEST, "required")
    s = build_sbom(comps, "s9", "0.5.0", 1723000000, "urn:uuid:abc", "note-x")
    assert s["metadata"]["timestamp"].endswith("Z")
    assert s["serialNumber"] == "urn:uuid:abc"
    assert any(p["value"] == "note-x" for p in s["metadata"]["properties"])


def test_scope_excludes_property_present():
    comps = parse_manifest(_MANIFEST, "required")
    s = build_sbom(comps, "s9", "0.5.0", None, None, None)
    props = {p["name"]: p["value"] for p in s["metadata"]["properties"]}
    assert "rust-crates" in props["dcentos:excludes"]


def test_cli_end_to_end(tmp_path: Path):
    manifest = tmp_path / "manifest.csv"
    manifest.write_text(_MANIFEST)
    host = tmp_path / "host-manifest.csv"
    host.write_text(_HOST_MANIFEST)
    out = tmp_path / "sbom.cdx.json"
    rc = main([
        "--manifest", str(manifest),
        "--host-manifest", str(host),
        "--target", "am2-s19jpro",
        "--component-version", "0.5.0",
        "--output", str(out),
    ])
    assert rc == 0
    doc = json.loads(out.read_text())
    names = {c["name"] for c in doc["components"]}
    assert {"busybox", "dropbear", "bash", "host-gcc-final"} <= names
    host_comp = next(c for c in doc["components"] if c["name"] == "host-gcc-final")
    assert host_comp["scope"] == "optional"


def test_cli_missing_manifest(tmp_path: Path):
    rc = main(["--manifest", str(tmp_path / "nope.csv"), "--target", "s9"])
    assert rc == 1


if __name__ == "__main__":
    raise SystemExit(__import__("pytest").main([__file__, "-q"]))
