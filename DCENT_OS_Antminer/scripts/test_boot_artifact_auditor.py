#!/usr/bin/env python3
"""Hermetic and real-catalog tests for the offline boot-artifact auditor."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from typing import Optional
import zlib

import audit_boot_artifacts as auditor


SCRIPT = Path(__file__).with_name("audit_boot_artifacts.py")
PROJECT = Path(__file__).resolve().parent.parent
WORKSPACE = PROJECT.parent.parent
REAL_CATALOG = PROJECT / "contracts" / "boot-artifacts" / "v1" / "amlogic.json"
SECRET = b"DCENT_BOOT_AUDITOR_SECRET_SENTINEL_4f9d2d"


def make_raw_environment(records: list[bytes], total_size: int = 1024) -> bytes:
    body = b"\x00".join(records) + b"\x00\x00"
    if len(body) > total_size - 4:
        raise ValueError("fixture records exceed the declared environment size")
    payload = body + b"\x00" * (total_size - 4 - len(body))
    return (zlib.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "little") + payload


def default_records(with_i2c_dev: bool = False) -> list[bytes]:
    adapter = b"i2c dev 1;" if with_i2c_dev else b""
    return [
        b"alpha=echo static",
        b"preboot=run alpha;"
        + adapter
        + b"i2c mw 1f 3.1 0 2;i2c mw 1f 1.1 fc 2;run absent",
        b"serial=" + SECRET,
        b"network=192.0.2.77",
        b"fi;fi;fi;",
    ]


def context(presence_policy: str = "local_optional") -> dict[str, object]:
    if presence_policy == "required":
        grade = "repository_tracked"
        association = "tracked_source_current"
    else:
        grade = "derived_unsealed"
        association = "path_label_only_unsealed"
    return {
        "product_declaration": "synthetic-test-only",
        "firmware_declaration": None,
        "capture_id": None,
        "provenance_grade": grade,
        "association": association,
    }


def environment_artifact(
    artifact_id: str,
    path: str,
    content: bytes,
    presence_policy: str = "required",
    findings: Optional[dict[str, object]] = None,
) -> dict[str, object]:
    expected = findings or auditor.decode_raw_environment(content)
    return {
        "id": artifact_id,
        "location": {"root": "project", "path": path},
        "presence_policy": presence_policy,
        "kind": "uboot_env_crc32_le",
        "declared_boot_phase": "pre_linux",
        "integrity": {
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        },
        "declared_context": context(presence_policy),
        "format_profile": {
            "header_bytes": 4,
            "crc32_byte_order": "little",
            "redundancy_flag_bytes": 0,
            "terminator": "double_nul",
            "padding_byte": 0,
        },
        "expected_findings": expected,
    }


def opaque_artifact(
    artifact_id: str,
    path: str,
    content: bytes,
    presence_policy: str = "required",
) -> dict[str, object]:
    return {
        "id": artifact_id,
        "location": {"root": "project", "path": path},
        "presence_policy": presence_policy,
        "kind": "opaque_file",
        "declared_boot_phase": "pre_linux",
        "integrity": {
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        },
        "declared_context": context(presence_policy),
        "format_profile": None,
        "expected_findings": None,
    }


def catalog(artifacts: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema": auditor.CATALOG_SCHEMA,
        "coverage": auditor.COVERAGE,
        "claim": auditor.CLAIM,
        "non_claims": auditor.NON_CLAIMS,
        "artifacts": artifacts,
    }


def write_catalog(path: Path, artifacts: list[dict[str, object]]) -> None:
    with path.open("w", encoding="ascii", newline="\n") as output:
        output.write(json.dumps(catalog(artifacts), indent=2, ensure_ascii=True) + "\n")


class DecoderTests(unittest.TestCase):
    def test_lexical_findings_preserve_anomaly_and_unknown_boundaries(self) -> None:
        content = make_raw_environment(default_records())
        findings = auditor.decode_raw_environment(content)
        self.assertTrue(findings["crc_consistent"])
        self.assertEqual(findings["record_count"], 5)
        self.assertEqual(findings["assignment_count"], 4)
        self.assertEqual(
            findings["non_assignment_record_sha256"],
            [hashlib.sha256(b"fi;fi;fi;").hexdigest()],
        )
        self.assertEqual(findings["direct_run_reference_count"], 2)
        self.assertEqual(findings["direct_run_target_name_present_count"], 1)
        self.assertEqual(
            findings["unresolved_run_target_sha256"],
            [hashlib.sha256(b"absent").hexdigest()],
        )
        self.assertEqual(
            findings["literal_i2c_commands"],
            ["i2c mw 1f 1.1 fc 2", "i2c mw 1f 3.1 0 2"],
        )
        self.assertFalse(findings["command_graph_complete"])
        self.assertEqual(findings["uboot_adapter_identity"], "unknown")
        self.assertEqual(findings["linux_adapter_equivalence"], "not_inferred")

    def test_i2c_dev_changes_only_literal_observation(self) -> None:
        content = make_raw_environment(default_records(with_i2c_dev=True))
        findings = auditor.decode_raw_environment(content)
        self.assertEqual(findings["captured_table_literal_i2c_dev_count"], 1)
        self.assertEqual(findings["uboot_adapter_identity"], "unknown")
        self.assertEqual(findings["linux_adapter_equivalence"], "not_inferred")
        self.assertFalse(findings["command_graph_complete"])

    def test_multi_target_run_is_counted_without_executing_it(self) -> None:
        content = make_raw_environment(
            [
                b"alpha=echo one",
                b"beta=echo two",
                b"preboot=run alpha beta;run absent",
            ]
        )
        findings = auditor.decode_raw_environment(content)
        self.assertEqual(findings["direct_run_reference_count"], 3)
        self.assertEqual(findings["direct_run_target_name_present_count"], 2)
        self.assertEqual(
            findings["unresolved_run_target_sha256"],
            [hashlib.sha256(b"absent").hexdigest()],
        )
        self.assertFalse(findings["command_graph_complete"])

    def test_emitted_i2c_commands_require_canonical_ascii_spaces(self) -> None:
        content = make_raw_environment(
            [b"preboot=i2c\tmw\t1f\t3.1\t0\t2;i2c mw 1f 1.1 fc 2"]
        )
        findings = auditor.decode_raw_environment(content)
        self.assertEqual(findings["literal_i2c_commands"], ["i2c mw 1f 1.1 fc 2"])

    def test_bad_crc_wrong_endian_and_truncation_are_rejected(self) -> None:
        valid = make_raw_environment(default_records())
        payload = valid[4:]
        bad_crc = b"\x00\x00\x00\x00" + payload
        wrong_endian = (zlib.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "big") + payload
        for content in (bad_crc, wrong_endian, valid[:3]):
            with self.subTest(length=len(content)):
                with self.assertRaises(auditor.ArtifactError):
                    auditor.decode_raw_environment(content)

    def test_missing_terminator_and_nonzero_padding_are_rejected(self) -> None:
        no_terminator_payload = b"A" * 1020
        no_terminator = (
            (zlib.crc32(no_terminator_payload) & 0xFFFFFFFF).to_bytes(4, "little")
            + no_terminator_payload
        )
        valid = make_raw_environment(default_records())
        bad_padding_payload = valid[4:-1] + b"\x01"
        bad_padding = (
            (zlib.crc32(bad_padding_payload) & 0xFFFFFFFF).to_bytes(4, "little")
            + bad_padding_payload
        )
        for content in (no_terminator, bad_padding):
            with self.assertRaises(auditor.ArtifactError):
                auditor.decode_raw_environment(content)

    def test_duplicate_variable_names_are_rejected(self) -> None:
        duplicate = make_raw_environment(
            [b"preboot=i2c mw 1f 3.1 0 2", b"alpha=one", b"alpha=two"]
        )
        with self.assertRaisesRegex(auditor.ArtifactError, "duplicate"):
            auditor.decode_raw_environment(duplicate)


class CatalogAndPolicyTests(unittest.TestCase):
    def test_required_optional_integrity_and_strict_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            present = b"present"
            (root / "present.bin").write_bytes(present)
            optional = opaque_artifact(
                "optional-evidence", "missing.bin", b"missing", "local_optional"
            )
            required = opaque_artifact("required-source", "present.bin", present)
            manifest = root / "catalog.json"
            write_catalog(manifest, [optional, required])

            report, status = auditor.audit_catalog(manifest, root, root)
            self.assertEqual(status, 0)
            self.assertEqual(
                report["verdict"],
                "required_entries_match_declared_local_entries_unavailable",
            )
            self.assertFalse(
                report["coverage"]["all_declared_local_optional_entries_present"]
            )

            strict_report, strict_status = auditor.audit_catalog(
                manifest, root, root, require_local_evidence=True
            )
            self.assertEqual(strict_status, 1)
            self.assertEqual(strict_report["verdict"], "failed")

            (root / "present.bin").write_bytes(b"drift")
            drift_report, drift_status = auditor.audit_catalog(manifest, root, root)
            self.assertEqual(drift_status, 1)
            result = next(
                item for item in drift_report["artifacts"] if item["id"] == "required-source"
            )
            self.assertEqual(result["status"], "failed")
            self.assertEqual(
                result["failure_reasons"], ["size_mismatch", "sha256_mismatch"]
            )

            (root / "present.bin").unlink()
            missing_report, missing_status = auditor.audit_catalog(manifest, root, root)
            self.assertEqual(missing_status, 1)
            self.assertEqual(missing_report["coverage"]["missing_required"], 1)

    def test_aliases_form_one_content_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            content = b"same bytes"
            (root / "a.bin").write_bytes(content)
            (root / "b.bin").write_bytes(content)
            manifest = root / "catalog.json"
            write_catalog(
                manifest,
                [
                    opaque_artifact("alias-a", "a.bin", content),
                    opaque_artifact("alias-b", "b.bin", content),
                ],
            )
            report, status = auditor.audit_catalog(manifest, root, root)
            self.assertEqual(status, 0)
            self.assertEqual(report["coverage"]["unique_verified_byte_strings"], 1)
            self.assertEqual(report["exact_byte_groups"][0]["artifact_count"], 2)
            self.assertFalse(report["independent_provenance_established"])

    def test_catalog_order_roots_mtimes_and_modes_do_not_change_report(self) -> None:
        with tempfile.TemporaryDirectory() as first_temp, tempfile.TemporaryDirectory() as second_temp:
            first = Path(first_temp)
            second = Path(second_temp)
            artifacts = [
                opaque_artifact("deterministic-a", "a.bin", b"A"),
                opaque_artifact("deterministic-b", "b.bin", b"B"),
            ]
            for root in (first, second):
                (root / "a.bin").write_bytes(b"A")
                (root / "b.bin").write_bytes(b"B")
            os.utime(first / "a.bin", (1_000_000_000, 1_000_000_000))
            os.utime(second / "a.bin", (1_500_000_000, 1_500_000_000))
            os.chmod(first / "b.bin", 0o600)
            os.chmod(second / "b.bin", 0o644)
            write_catalog(first / "catalog.json", artifacts)
            write_catalog(second / "catalog.json", list(reversed(artifacts)))
            first_report, first_status = auditor.audit_catalog(
                first / "catalog.json", first, first
            )
            second_report, second_status = auditor.audit_catalog(
                second / "catalog.json", second, second
            )
            self.assertEqual((first_status, second_status), (0, 0))
            self.assertEqual(first_report, second_report)

    def test_catalog_rejects_duplicate_keys_unknown_fields_and_unsafe_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"schema":"one","schema":"two"}\n', encoding="ascii")
            with self.assertRaisesRegex(auditor.CatalogError, "duplicate"):
                auditor.read_catalog(duplicate)

            data = b"x"
            base = opaque_artifact("safe-id", "safe.bin", data)
            unsafe_paths = [
                "../escape",
                "/absolute",
                "C:/drive",
                "dir\\file",
                "file:ads",
                "foo.",
                "NUL",
                "con.txt",
                "dir/COM1.bin",
            ]
            for index, unsafe in enumerate(unsafe_paths):
                bad = copy.deepcopy(base)
                bad["location"]["path"] = unsafe
                manifest = root / f"unsafe-{index}.json"
                write_catalog(manifest, [bad])
                with self.subTest(path=unsafe):
                    with self.assertRaises(auditor.CatalogError):
                        auditor.read_catalog(manifest)

            unknown = copy.deepcopy(base)
            unknown["surprise"] = True
            manifest = root / "unknown.json"
            write_catalog(manifest, [unknown])
            with self.assertRaisesRegex(auditor.CatalogError, "exact schema"):
                auditor.read_catalog(manifest)

            empty = root / "empty.json"
            write_catalog(empty, [])
            with self.assertRaisesRegex(auditor.CatalogError, "1..1024"):
                auditor.read_catalog(empty)

    def test_catalog_rejects_casefold_path_collision_and_false_crc_expectation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            content = b"same"
            first = opaque_artifact("case-a", "Dir/file.bin", content)
            second = opaque_artifact("case-b", "dir/FILE.bin", content)
            manifest = root / "collision.json"
            write_catalog(manifest, [first, second])
            with self.assertRaisesRegex(auditor.CatalogError, "case-insensitive"):
                auditor.read_catalog(manifest)

            raw = make_raw_environment(default_records())
            false_crc = environment_artifact("false-crc", "env.bin", raw)
            false_crc["expected_findings"]["crc_consistent"] = False
            manifest = root / "false-crc.json"
            write_catalog(manifest, [false_crc])
            with self.assertRaisesRegex(auditor.CatalogError, "CRC consistency"):
                auditor.read_catalog(manifest)

    def test_catalog_requires_strict_utf8_without_bom(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entry = opaque_artifact("encoding-test", "file.bin", b"file")
            serialized = json.dumps(catalog([entry]), ensure_ascii=True)
            utf16 = root / "utf16.json"
            utf16.write_bytes(serialized.encode("utf-16"))
            with self.assertRaisesRegex(auditor.CatalogError, "UTF-8"):
                auditor.read_catalog(utf16)
            bom = root / "bom.json"
            bom.write_bytes(b"\xef\xbb\xbf" + serialized.encode("utf-8"))
            with self.assertRaisesRegex(auditor.CatalogError, "BOM"):
                auditor.read_catalog(bom)

    def test_catalog_rejects_inconsistent_provenance_and_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entry = opaque_artifact("provenance-test", "file.bin", b"file")
            entry["declared_context"] = context("local_optional")
            manifest = root / "provenance.json"
            write_catalog(manifest, [entry])
            with self.assertRaisesRegex(auditor.CatalogError, "provenance"):
                auditor.read_catalog(manifest)

            same_capture = opaque_artifact(
                "capture-test", "capture.bin", b"capture", "local_optional"
            )
            same_capture["declared_context"]["provenance_grade"] = (
                "operator_associated_unsealed"
            )
            same_capture["declared_context"]["association"] = (
                "same_capture_directory_unsealed"
            )
            manifest = root / "capture.json"
            write_catalog(manifest, [same_capture])
            with self.assertRaisesRegex(auditor.CatalogError, "same-capture"):
                auditor.read_catalog(manifest)

            wrong_phase = opaque_artifact("phase-test", "phase.bin", b"phase")
            wrong_phase["declared_boot_phase"] = "context"
            manifest = root / "phase.json"
            write_catalog(manifest, [wrong_phase])
            with self.assertRaisesRegex(auditor.CatalogError, "declared_boot_phase"):
                auditor.read_catalog(manifest)

    def test_catalog_hardlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "catalog.json"
            write_catalog(
                original, [opaque_artifact("hard-catalog", "file.bin", b"file")]
            )
            hardlink = root / "catalog-hard.json"
            os.link(original, hardlink)
            with self.assertRaisesRegex(auditor.CatalogError, "single-link"):
                auditor.read_catalog(hardlink)

    def test_catalog_file_symlink_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "catalog.json"
            write_catalog(
                original, [opaque_artifact("link-catalog", "file.bin", b"file")]
            )
            link = root / "catalog-link.json"
            try:
                link.symlink_to(original)
            except OSError as error:
                raise unittest.SkipTest("file symlinks unavailable on this host") from error
            with self.assertRaises(auditor.CatalogError):
                auditor.read_catalog(link)

    def test_catalog_parent_symlink_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real_parent = root / "real-parent"
            real_parent.mkdir()
            original = real_parent / "catalog.json"
            write_catalog(
                original, [opaque_artifact("parent-catalog", "file.bin", b"file")]
            )
            link = root / "parent-link"
            try:
                link.symlink_to(real_parent, target_is_directory=True)
            except OSError as error:
                raise unittest.SkipTest("directory symlinks unavailable on this host") from error
            with self.assertRaisesRegex(auditor.CatalogError, "parent"):
                auditor.read_catalog(link / "catalog.json")

    def test_bounded_catalog_and_artifact_read_errors_are_translated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            content = b"content"
            artifact = opaque_artifact("read-error", "file.bin", content)
            (root / "file.bin").write_bytes(content)
            manifest = root / "catalog.json"
            write_catalog(manifest, [artifact])

            with mock.patch.object(auditor.os, "read", side_effect=OSError("sentinel")):
                with self.assertRaisesRegex(auditor.CatalogError, "descriptor read failed"):
                    auditor.read_catalog(manifest)

            with mock.patch.object(auditor.os, "read", side_effect=OSError("sentinel")):
                result = auditor.audit_artifact(artifact, {"project": root, "workspace": root})
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["failure_reasons"], ["unsafe_or_unreadable"])
            self.assertNotIn("sentinel", json.dumps(result))

            chunks = [b"x" * (64 * 1024)] * 17
            with mock.patch.object(auditor.os, "read", side_effect=chunks):
                with self.assertRaisesRegex(auditor.CatalogError, "read bound"):
                    auditor.read_catalog(manifest)

    def test_catalog_cannot_label_a_malformed_environment_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            content = make_raw_environment(default_records())
            (root / "env.bin").write_bytes(content)
            entry = environment_artifact("mislabelled-env", "env.bin", content)
            entry["expected_findings"]["record_shape_status"] = "assignments_only"
            manifest = root / "catalog.json"
            write_catalog(manifest, [entry])
            report, status = auditor.audit_catalog(manifest, root, root)
            self.assertEqual(status, 1)
            self.assertEqual(report["artifacts"][0]["status"], "failed")
            self.assertEqual(
                report["artifacts"][0]["finding_mismatch_fields"],
                ["record_shape_status"],
            )

    def test_file_and_parent_links_and_hardlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.bin"
            target.write_bytes(b"target")

            hard = root / "hard.bin"
            os.link(target, hard)
            hard_manifest = root / "hard.json"
            write_catalog(hard_manifest, [opaque_artifact("hard-link", "hard.bin", b"target")])
            report, status = auditor.audit_catalog(hard_manifest, root, root)
            self.assertEqual(status, 1)
            self.assertEqual(report["artifacts"][0]["failure_reasons"], ["unsafe_or_unreadable"])

            link = root / "link.bin"
            try:
                link.symlink_to(target)
            except OSError:
                return
            link_manifest = root / "link.json"
            write_catalog(link_manifest, [opaque_artifact("file-link", "link.bin", b"target")])
            report, status = auditor.audit_catalog(link_manifest, root, root)
            self.assertEqual(status, 1)
            self.assertEqual(report["artifacts"][0]["failure_reasons"], ["unsafe_or_unreadable"])

            real_parent = root / "real-parent"
            real_parent.mkdir()
            (real_parent / "child.bin").write_bytes(b"child")
            parent_link = root / "parent-link"
            try:
                parent_link.symlink_to(real_parent, target_is_directory=True)
            except OSError:
                return
            parent_manifest = root / "parent.json"
            write_catalog(
                parent_manifest,
                [opaque_artifact("parent-link", "parent-link/child.bin", b"child")],
            )
            report, status = auditor.audit_catalog(parent_manifest, root, root)
            self.assertEqual(status, 1)
            self.assertEqual(report["artifacts"][0]["failure_reasons"], ["unsafe_or_unreadable"])


class CliAndPrivacyTests(unittest.TestCase):
    def test_human_summary_never_calls_missing_local_evidence_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            required_content = b"required"
            (root / "required.bin").write_bytes(required_content)
            manifest = root / "catalog.json"
            write_catalog(
                manifest,
                [
                    opaque_artifact("required-source", "required.bin", required_content),
                    opaque_artifact(
                        "optional-local", "missing.bin", b"missing", "local_optional"
                    ),
                ],
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--catalog",
                    str(manifest),
                    "--project-root",
                    str(root),
                    "--workspace-root",
                    str(root),
                ],
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0)
            self.assertIn(
                b"required_entries_match_declared_local_entries_unavailable",
                completed.stdout,
            )
            self.assertNotIn(b"PASS", completed.stdout.upper())

    def test_cli_report_is_private_canonical_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            content = make_raw_environment(default_records())
            artifact_path = root / "env.bin"
            artifact_path.write_bytes(content)
            manifest = root / "catalog.json"
            write_catalog(manifest, [environment_artifact("private-env", "env.bin", content)])
            before_hash = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
            before_mtime = artifact_path.stat().st_mtime_ns
            command = [
                sys.executable,
                str(SCRIPT),
                "--catalog",
                str(manifest),
                "--project-root",
                str(root),
                "--workspace-root",
                str(root),
                "--json",
            ]
            completed = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8"))
            self.assertTrue(completed.stdout.endswith(b"\n"))
            self.assertNotIn(SECRET, completed.stdout)
            self.assertNotIn(SECRET, completed.stderr)
            self.assertNotIn(b"192.0.2.77", completed.stdout)
            self.assertNotIn(b"mtime", completed.stdout)
            self.assertNotIn(b"timestamp", completed.stdout)
            report = json.loads(completed.stdout)
            self.assertEqual(
                completed.stdout,
                auditor.canonical_json_bytes(report),
            )
            self.assertNotIn(str(root).encode(), completed.stdout)
            self.assertEqual(hashlib.sha256(artifact_path.read_bytes()).hexdigest(), before_hash)
            self.assertEqual(artifact_path.stat().st_mtime_ns, before_mtime)

    def test_invalid_catalog_returns_cli_status_two_without_artifact_leak(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "catalog.json"
            manifest.write_text('{"schema":"bad","schema":"still-bad"}\n', encoding="ascii")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--catalog",
                    str(manifest),
                    "--project-root",
                    str(root),
                    "--workspace-root",
                    str(root),
                    "--json",
                ],
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stdout, b"")
            self.assertNotIn(str(root).encode(), completed.stderr)


class RealCatalogTests(unittest.TestCase):
    def test_checked_in_catalog_is_policy_valid(self) -> None:
        report, status = auditor.audit_catalog(
            REAL_CATALOG, PROJECT, WORKSPACE, require_local_evidence=False
        )
        self.assertEqual(status, 0)
        self.assertIn(
            report["verdict"],
            {
                "declared_inputs_integrity_and_lexical_checks_passed",
                "required_entries_match_declared_local_entries_unavailable",
            },
        )
        current = next(
            item
            for item in report["artifacts"]
            if item["id"] == "amlogic-current-s37-early-userspace-source"
        )
        self.assertEqual(current["status"], "verified_exact_bytes")

        raw_path = (
            WORKSPACE
            / "knowledge-base"
            / "extractions"
            / "s19k"
            / "live-probe-78-2026-04-29"
            / "00-system"
            / "nand_env.bin"
        )
        if raw_path.exists():
            strict_report, strict_status = auditor.audit_catalog(
                REAL_CATALOG, PROJECT, WORKSPACE, require_local_evidence=True
            )
            self.assertEqual(strict_status, 0)
            raw = next(
                item
                for item in strict_report["artifacts"]
                if item["id"] == "s19k-pro-78-bos-nand-env-20260429"
            )
            self.assertEqual(
                raw["status"], "verified_exact_bytes_with_non_assignment_records"
            )
            self.assertFalse(raw["findings"]["command_graph_complete"])


if __name__ == "__main__":
    unittest.main()
