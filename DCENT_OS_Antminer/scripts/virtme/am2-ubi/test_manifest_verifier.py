#!/usr/bin/env python3
"""Host-safe negative fixtures for the AM2 offline module-bundle contract."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_manifest as verifier  # noqa: E402


class ManifestVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temporary.name)
        self.base = self.bundle / "config.base"
        self.effective = self.bundle / "config.effective"
        self.delta = self.bundle / "config.delta"
        self.ubi = self.bundle / "ubi-nofastmap.ko"
        self.ubifs = self.bundle / "ubifs-nofastmap.ko"
        self.base.write_text(
            "CONFIG_MTD_UBI=m\nCONFIG_MTD_UBI_FASTMAP=y\nCONFIG_UBIFS_FS=m\n",
            encoding="utf-8",
        )
        self.effective.write_text(
            "CONFIG_MTD_UBI=m\n# CONFIG_MTD_UBI_FASTMAP is not set\nCONFIG_UBIFS_FS=m\n",
            encoding="utf-8",
        )
        self.delta.write_bytes(b"# CONFIG_MTD_UBI_FASTMAP is not set\n")
        self.ubi.write_bytes(b"synthetic ubi module fixture\n")
        self.ubifs.write_bytes(b"synthetic ubifs module fixture\n")

        lock_path = Path(__file__).resolve().parent / "inputs.lock.json"
        self.lock = verifier.load_json(lock_path)
        self.lock["kernel"]["base_config_sha256"] = verifier.sha256_file(self.base)
        self.lock["kernel"]["effective_config_sha256"] = verifier.sha256_file(
            self.effective
        )
        verifier.validate_lock(self.lock)
        lock_bytes = (
            json.dumps(self.lock, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        self.lock_sha256 = verifier.sha256_bytes(lock_bytes)
        (self.bundle / "inputs.lock.json").write_bytes(lock_bytes)
        self.manifest = verifier.build_manifest_document(
            self.lock,
            self.lock_sha256,
            self.base,
            self.effective,
            self.delta,
            {"ubi": self.ubi, "ubifs": self.ubifs},
            metadata_reader=self.metadata,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def metadata(self, path: Path):
        name = "ubifs" if path.name.startswith("ubifs") else "ubi"
        return {
            "name": name,
            "vermagic": self.lock["kernel"]["vermagic"],
            "srcversion": self.lock["kernel"]["expected_module_srcversions"][name],
            "depends": ",".join(verifier.MODULE_DEPENDS[name]),
            "parm": ["block:synthetic", "mtd:synthetic"] if name == "ubi" else [],
        }

    def assert_rejected(self, manifest) -> None:
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_bundle_document(
                manifest,
                self.bundle,
                self.lock,
                self.lock_sha256,
                metadata_reader=self.metadata,
            )

    def test_valid_synthetic_bundle_passes_without_modinfo_or_linux(self) -> None:
        verifier.verify_bundle_document(
            self.manifest,
            self.bundle,
            self.lock,
            self.lock_sha256,
            metadata_reader=self.metadata,
        )

    def test_negative_manifest_fixtures_fail_closed(self) -> None:
        fixtures = []

        manifest = copy.deepcopy(self.manifest)
        manifest["scope"] = "product"
        fixtures.append(("scope escalation", manifest))

        manifest = copy.deepcopy(self.manifest)
        manifest["product_installable"] = True
        fixtures.append(("product installable", manifest))

        manifest = copy.deepcopy(self.manifest)
        manifest["inputs_lock_sha256"] = "0" * 64
        fixtures.append(("unbound lock", manifest))

        manifest = copy.deepcopy(self.manifest)
        manifest["modules"]["ubi"]["sha256"] = "0" * 64
        fixtures.append(("module hash drift", manifest))

        manifest = copy.deepcopy(self.manifest)
        manifest["modules"]["ubi"]["filename"] = "../ubi.ko"
        fixtures.append(("path traversal", manifest))

        manifest = copy.deepcopy(self.manifest)
        del manifest["modules"]["ubifs"]
        fixtures.append(("unpaired module", manifest))

        manifest = copy.deepcopy(self.manifest)
        manifest["reproducibility"]["byte_identical"] = False
        fixtures.append(("non-identical builds", manifest))

        manifest = copy.deepcopy(self.manifest)
        manifest["non_claims"] = ["physical NAND validated"]
        fixtures.append(("removed non-claims", manifest))

        for label, fixture in fixtures:
            with self.subTest(label=label):
                self.assert_rejected(fixture)

    def test_bundled_input_lock_drift_is_rejected(self) -> None:
        bundled_lock = self.bundle / "inputs.lock.json"
        original = bundled_lock.read_bytes()
        bundled_lock.write_bytes(original + b"\n")
        with self.assertRaisesRegex(verifier.VerificationError, "input-lock bytes"):
            verifier.verify_bundle_document(
                self.manifest,
                self.bundle,
                self.lock,
                self.lock_sha256,
                metadata_reader=self.metadata,
            )

    def test_runtime_metadata_drift_is_rejected(self) -> None:
        def wrong_metadata(path: Path):
            value = dict(self.metadata(path))
            if path.name.startswith("ubifs"):
                value["vermagic"] = "wrong-kernel"
            return value

        with self.assertRaisesRegex(verifier.VerificationError, "vermagic"):
            verifier.verify_bundle_document(
                self.manifest,
                self.bundle,
                self.lock,
                self.lock_sha256,
                metadata_reader=wrong_metadata,
            )

    def test_fastmap_parameter_is_rejected(self) -> None:
        def fastmap_metadata(path: Path):
            value = dict(self.metadata(path))
            value["parm"] = (
                ["fm_autoconvert:Enable fastmap conversion"]
                if path.name.startswith("ubi-")
                else []
            )
            return value

        with self.assertRaisesRegex(verifier.VerificationError, "fastmap parameter"):
            verifier.verify_bundle_document(
                self.manifest,
                self.bundle,
                self.lock,
                self.lock_sha256,
                metadata_reader=fastmap_metadata,
            )

    def test_unexpected_non_fastmap_parameter_is_rejected(self) -> None:
        def extra_metadata(path: Path):
            value = dict(self.metadata(path))
            if path.name.startswith("ubi-"):
                value["parm"] = [*value["parm"], "future:unexpected"]
            return value

        with self.assertRaisesRegex(verifier.VerificationError, "parameter-name"):
            verifier.verify_bundle_document(
                self.manifest,
                self.bundle,
                self.lock,
                self.lock_sha256,
                metadata_reader=extra_metadata,
            )

    def test_package_roles_resolve_from_the_lock(self) -> None:
        self.assertEqual(
            verifier.package_filename_for_role(self.lock, "linux-source-deb"),
            "linux-source-5.15.0_5.15.0-181.191_all.deb",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "not uniquely"):
            verifier.package_filename_for_role(self.lock, "unknown-role")

    def test_debian_control_fields_are_queried_individually(self) -> None:
        package = self.lock["packages"][0]
        responses = [
            mock.Mock(stdout=f"{package['package']}\n"),
            mock.Mock(stdout=f"{package['version']}\n"),
            mock.Mock(stdout=f"{package['architecture']}\n"),
        ]
        with mock.patch.object(
            verifier.subprocess, "run", side_effect=responses
        ) as run:
            verifier.verify_debian_control(self.bundle / "input.deb", package)
        self.assertEqual(run.call_count, 3)
        self.assertEqual(run.call_args_list[0].args[0][-1], "Package")
        self.assertEqual(run.call_args_list[1].args[0][-1], "Version")
        self.assertEqual(run.call_args_list[2].args[0][-1], "Architecture")

    def test_labeled_multi_field_debian_output_is_rejected(self) -> None:
        package = self.lock["packages"][0]
        with mock.patch.object(
            verifier.subprocess,
            "run",
            return_value=mock.Mock(stdout=f"Package: {package['package']}\n"),
        ):
            with self.assertRaisesRegex(verifier.VerificationError, "Package differs"):
                verifier.verify_debian_control(self.bundle / "input.deb", package)

    def test_exact_virtme_kernel_bytes_are_admitted(self) -> None:
        kernel = self.bundle / "vmlinuz"
        kernel.write_bytes(b"synthetic exact kernel")
        relocked = copy.deepcopy(self.lock)
        relocked["kernel"]["vmlinuz_size"] = kernel.stat().st_size
        relocked["kernel"]["vmlinuz_sha256"] = verifier.sha256_file(kernel)
        with mock.patch.object(verifier, "validate_lock", return_value=None):
            verifier.verify_kernel_image(relocked, kernel)
            kernel.write_bytes(b"synthetic drift kernel")
            with self.assertRaisesRegex(verifier.VerificationError, "hash differs"):
                verifier.verify_kernel_image(relocked, kernel)

    def test_second_config_change_is_rejected_even_when_hash_is_relocked(self) -> None:
        changed = self.bundle / "config.changed"
        changed.write_text(
            self.effective.read_text(encoding="utf-8") + "CONFIG_UNRELATED_TEST=y\n",
            encoding="utf-8",
        )
        relocked = copy.deepcopy(self.lock)
        relocked["kernel"]["effective_config_sha256"] = verifier.sha256_file(changed)
        with self.assertRaisesRegex(
            verifier.VerificationError, "single admitted delta"
        ):
            verifier.verify_config_closure(relocked, self.base, changed, self.delta)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        malformed = self.bundle / "duplicate.json"
        malformed.write_text('{"schema":"first","schema":"second"}\n', encoding="utf-8")
        with self.assertRaisesRegex(verifier.VerificationError, "duplicate JSON key"):
            verifier.load_json(malformed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
