#!/usr/bin/env python3
"""Focused tests for the read-only S15/T15 BM1391 carrier extractor."""

from __future__ import annotations

import ast
import dis
import gzip
import hashlib
import importlib.util
import io
import os
import stat
import struct
import sys
import tarfile
import tempfile
import unittest
import zlib
from dataclasses import fields, is_dataclass, replace
from pathlib import Path
from types import CodeType, SimpleNamespace


SCRIPT = Path(__file__).with_name("extract_s15_t15_bm1391_carrier.py")
SPEC = importlib.util.spec_from_file_location("bm1391_carrier", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
carrier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = carrier
SPEC.loader.exec_module(carrier)


def tar_gz(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for info, data in members:
            archive.addfile(info, io.BytesIO(data) if data is not None else None)
    return output.getvalue()


def regular(name: str, data: bytes):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info, data


def assert_receipt_authority_false(testcase, value):
    if is_dataclass(value):
        for item in fields(value):
            child = getattr(value, item.name)
            if item.name.endswith("authority"):
                testcase.assertFalse(child, item.name)
            assert_receipt_authority_false(testcase, child)
    elif isinstance(value, (tuple, list)):
        for child in value:
            assert_receipt_authority_false(testcase, child)


class BoundedPrimitiveTests(unittest.TestCase):
    def test_bounded_gzip_rejects_bomb_trailing_and_truncation(self):
        with self.assertRaises(carrier.EvidenceError):
            carrier.bounded_gzip(gzip.compress(b"123456789"), 8, "test")
        concatenated = gzip.compress(b"one") + gzip.compress(b"two")
        with self.assertRaises(carrier.EvidenceError):
            carrier.bounded_gzip(concatenated, 100, "test")
        with self.assertRaises(carrier.EvidenceError):
            carrier.bounded_gzip(gzip.compress(b"payload")[:-2], 100, "test")

    def test_archive_rejects_unsafe_duplicate_and_nonregular_members(self):
        unsafe = tar_gz([regular("../escape", b"x")])
        with self.assertRaises(carrier.EvidenceError):
            carrier.exact_tar_gz(unsafe, {"../escape"}, "test")

        duplicate = tar_gz([regular("same", b"a"), regular("same", b"b")])
        with self.assertRaises(carrier.EvidenceError):
            carrier.exact_tar_gz(duplicate, {"same"}, "test")

        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "target"
        nonregular = tar_gz([(link, None)])
        with self.assertRaises(carrier.EvidenceError):
            carrier.exact_tar_gz(nonregular, {"link"}, "test")

    def test_archive_schema_is_exact(self):
        archive = tar_gz([regular("expected", b"ok"), regular("extra", b"no")])
        with self.assertRaisesRegex(carrier.EvidenceError, "schema drift"):
            carrier.exact_tar_gz(archive, {"expected"}, "test")

    def test_legacy_uimage_crc_and_metadata_are_checked(self):
        payload = gzip.compress(b"synthetic-ext2", mtime=0)
        data_crc = zlib.crc32(payload) & 0xFFFFFFFF
        fields = [
            carrier.UIMAGE_MAGIC,
            0,
            123,
            len(payload),
            0,
            0,
            data_crc,
            5,
            2,
            3,
            1,
            b"\0" * 32,
        ]
        header = bytearray(struct.pack(">7I4B32s", *fields))
        struct.pack_into(">I", header, 4, zlib.crc32(header) & 0xFFFFFFFF)
        image = bytes(header) + payload
        decoded, metadata = carrier.parse_legacy_ramdisk(image, carrier.sha256(image))
        self.assertEqual(decoded, b"synthetic-ext2")
        self.assertEqual(metadata["type"], "Linux/ARM/ramdisk/gzip")

        damaged = bytearray(image)
        damaged[-1] ^= 1
        with self.assertRaises(carrier.EvidenceError):
            carrier.parse_legacy_ramdisk(bytes(damaged), carrier.sha256(bytes(damaged)))

    def test_contract_never_grants_runtime_or_wire_authority(self):
        receipt = carrier.carrier_contract()
        self.assertFalse(receipt.artifact_association_verified)
        assert_receipt_authority_false(self, receipt)
        contract = receipt.to_dict()
        self.assertEqual(
            contract["derivation"]["method"], "reviewed-static-semantic-profile"
        )
        self.assertFalse(contract["derivation"]["mechanical_extraction"])
        authority = contract["authority"]
        self.assertTrue(authority["evidence_only"])
        for field in (
            "install_authorized",
            "live_probe_authorized",
            "runtime_mutation_authorized",
            "safe_runtime_composition_proven",
            "wire_transactions_authorized",
        ):
            self.assertFalse(authority[field], field)
        self.assertFalse(contract["pic"]["mutation_authorized"])
        self.assertFalse(
            contract["thermal_and_fans"]["external_temperature"]["wire_read_authorized"]
        )
        self.assertIsNone(contract["pll"]["safe_default_frequency_mhz"])
        self.assertFalse(contract["watchdogs"]["safe_shutdown_path_proven"])
        enumeration = contract["bm1391_enumeration"]
        self.assertEqual(
            enumeration["expected_responses_per_present_chain"]["S15"]["count"],
            72,
        )
        self.assertEqual(
            enumeration["expected_responses_per_present_chain"]["T15"]["count"],
            60,
        )
        self.assertFalse(enumeration["physical_topology_authorized"])
        self.assertIn("unresolved", enumeration["caveat"])
        binding = contract["fpga_return_and_work_binding"]
        self.assertEqual(binding["record"]["length_bytes"], 8)
        self.assertEqual(binding["outstanding_work_record_bytes"], 64)
        self.assertEqual(binding["bound_nonce_record_bytes"], 60)
        self.assertEqual(binding["host_ring"]["capacity"], 511)
        self.assertIn("overwrite", binding["host_ring"]["stock_nonce_full_behavior"])
        self.assertIn("refused", binding["host_ring"]["clean_codec_behavior"])
        self.assertFalse(binding["nonce"]["word0_bit6_checked_by_stock"])
        self.assertFalse(binding["runtime_authorized"])


class ExactPathAndTrustTests(unittest.TestCase):
    def test_exact_reader_bounds_eof_overreturn_growth_and_size_before_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "four.bin"
            path.write_bytes(b"ABCD")
            digest = carrier.sha256(b"ABCD")
            self.assertEqual(carrier.checked_blob(path, 4, digest), b"ABCD")

            hash_calls = []
            with self.assertRaisesRegex(carrier.EvidenceError, "size pin"):
                carrier.checked_blob(
                    path,
                    5,
                    digest,
                    _sha256_fn=lambda data: hash_calls.append(data),
                )
            self.assertEqual(hash_calls, [], "wrong size must fail before hashing")

            reads = []

            def early_read(_descriptor, requested):
                reads.append(requested)
                return b"AB" if len(reads) == 1 else b""

            with self.assertRaisesRegex(carrier.EvidenceError, "EOF before"):
                carrier.checked_blob(path, 4, digest, os_read=early_read)
            self.assertEqual(reads, [4, 2])

            with self.assertRaisesRegex(carrier.EvidenceError, "beyond pinned"):
                carrier.checked_blob(
                    path,
                    4,
                    digest,
                    os_read=lambda _descriptor, _requested: b"ABCDE",
                )

            actual_reads = 0

            def growing_read(descriptor, requested):
                nonlocal actual_reads
                actual_reads += 1
                if actual_reads == 1:
                    return os.read(descriptor, requested)
                return b"X"

            with self.assertRaisesRegex(carrier.EvidenceError, "grew beyond"):
                carrier.checked_blob(path, 4, digest, os_read=growing_read)
            self.assertEqual(actual_reads, 2)

    def test_exact_reader_rechecks_mode_link_count_ctime_and_hardlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stable.bin"
            path.write_bytes(b"ABCD")
            actual = path.stat()
            baseline = {
                "st_mode": actual.st_mode,
                "st_nlink": 1,
                "st_size": 4,
                "st_dev": actual.st_dev,
                "st_ino": actual.st_ino,
                "st_mtime_ns": actual.st_mtime_ns,
                "st_ctime_ns": actual.st_ctime_ns,
            }
            cases = (
                ("st_nlink", 2, "regular single-link"),
                ("st_mode", stat.S_IFDIR, "regular single-link"),
                ("st_ctime_ns", actual.st_ctime_ns + 1, "metadata changed"),
            )
            for field, value, message in cases:
                after = dict(baseline)
                after[field] = value
                snapshots = iter(
                    (SimpleNamespace(**baseline), SimpleNamespace(**after))
                )
                with (
                    self.subTest(field=field),
                    self.assertRaisesRegex(carrier.EvidenceError, message),
                ):
                    carrier.checked_blob(
                        path,
                        4,
                        carrier.sha256(b"ABCD"),
                        os_fstat=lambda _descriptor: next(snapshots),
                    )

            hardlink = Path(directory) / "hardlink.bin"
            os.link(path, hardlink)
            with self.assertRaisesRegex(carrier.EvidenceError, "single-link"):
                carrier.checked_blob(path, 4, carrier.sha256(b"ABCD"))

    def test_exact_reader_rejects_path_descriptor_identity_race(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raced.bin"
            path.write_bytes(b"ABCD")
            actual = path.stat()
            forged_descriptor = SimpleNamespace(
                st_mode=actual.st_mode,
                st_nlink=1,
                st_size=4,
                st_dev=actual.st_dev,
                st_ino=actual.st_ino + 1,
                st_mtime_ns=actual.st_mtime_ns,
                st_ctime_ns=actual.st_ctime_ns,
            )
            with self.assertRaisesRegex(carrier.EvidenceError, "identity changed"):
                carrier.checked_blob(
                    path,
                    4,
                    carrier.sha256(b"ABCD"),
                    os_fstat=lambda _descriptor: forged_descriptor,
                )

    def test_symlink_reparse_paths_are_refused(self):
        fake = SimpleNamespace(
            lstat=lambda: SimpleNamespace(
                st_mode=stat.S_IFREG,
                st_file_attributes=0x400,
            )
        )
        self.assertTrue(carrier._is_reparse_or_symlink(fake))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.bin"
            alias = root / "alias.bin"
            source.write_bytes(b"ABCD")
            try:
                os.symlink(source, alias)
            except (OSError, NotImplementedError):
                self.skipTest("file symlink creation unavailable")
            with self.assertRaisesRegex(carrier.EvidenceError, "symlink/reparse"):
                carrier.checked_blob(alias, 4, carrier.sha256(b"ABCD"))

    def test_direct_and_replace_receipts_never_retain_verification(self):
        direct_contract = carrier.CarrierContractReceipt("{}")
        direct = carrier.CarrierEvidenceReceipt(
            schema="forged",
            canonical_models_json="{}",
            shared_carrier_contract=direct_contract,
        )
        self.assertFalse(direct_contract.artifact_association_verified)
        self.assertFalse(direct.receipt_verified)
        assert_receipt_authority_false(self, direct_contract)
        assert_receipt_authority_false(self, direct)

    def test_public_trust_api_rejects_dependency_override_injection(self):
        missing = Path("definitely-absent-s15-t15-package.tar.gz")
        self.assertFalse(hasattr(carrier, "_inspect_model_impl"))
        self.assertFalse(hasattr(carrier, "_carrier_contract_payload"))
        with self.assertRaises(TypeError):
            carrier.build_report(
                missing,
                missing,
                _inspect_model=lambda *_args: {"forged": True},
                _contract_payload_fn=lambda: {"forged": True},
            )
        with self.assertRaises(TypeError):
            carrier.inspect_model(
                "S15",
                missing,
                _checked_blob=lambda *_args: b"forged",
            )
        with self.assertRaises(TypeError):
            carrier.carrier_contract(_payload_fn=lambda: {"forged": True})
        direct_contract = carrier.CarrierContractReceipt("{}")
        direct = carrier.CarrierEvidenceReceipt(
            schema="forged",
            canonical_models_json="{}",
            shared_carrier_contract=direct_contract,
        )
        with self.assertRaises(TypeError):
            direct_contract.to_dict(_loads=lambda _value: {"forged": True})
        with self.assertRaises(TypeError):
            direct.to_dict(_loads=lambda _value: {"forged": True})
        with self.assertRaises(TypeError):
            direct.to_pretty_json(_dumps=lambda *_args, **_kwargs: "forged")

    def test_reachable_function_defaults_cannot_bypass_exact_outer_admission(self):
        self.assertFalse(hasattr(carrier, "_inspect_model_impl"))
        self.assertFalse(
            any(
                getattr(value, "__name__", None) == "_inspect_model_impl"
                for value in vars(carrier).values()
            )
        )
        pending = [carrier.build_report]
        observed = set()
        private_inspector = None
        while pending:
            function = pending.pop()
            if id(function) in observed:
                continue
            observed.add(id(function))
            if getattr(function, "__name__", None) == "_inspect_model_impl":
                private_inspector = function
                break
            for cell in getattr(function, "__closure__", None) or ():
                child = cell.cell_contents
                if hasattr(child, "__code__"):
                    pending.append(child)
        self.assertIsNotNone(private_inspector)
        missing = Path("definitely-absent-default-poison-s15-t15.tar.gz")
        original_defaults = private_inspector.__defaults__
        try:
            private_inspector.__defaults__ = (None,) * len(original_defaults)
            with self.assertRaises((carrier.EvidenceError, OSError)):
                carrier.build_report(missing, missing)
        finally:
            private_inspector.__defaults__ = original_defaults

    def test_sensitive_runtime_code_has_no_module_global_lookups(self):
        functions = [
            carrier.sha256,
            carrier._is_reparse_or_symlink,
            carrier._reject_reparse_components,
            carrier.checked_blob,
            carrier.bounded_gzip,
            carrier._safe_member_name,
            carrier.exact_tar_gz,
            carrier.checked_pin,
            carrier.parse_legacy_ramdisk,
            carrier._file_record,
            carrier.inspect_model,
            carrier.carrier_contract,
            carrier.build_report,
            carrier.parse_args,
            carrier.main,
            carrier.CarrierContractReceipt.to_dict,
            carrier.CarrierEvidenceReceipt.to_dict,
            carrier.CarrierEvidenceReceipt.to_pretty_json,
        ]
        functions.extend(
            getattr(carrier.Ext2Reader, name)
            for name in (
                "__init__",
                "_u16",
                "_u32",
                "_block",
                "_inode",
                "_indirect",
                "_inode_data",
                "_directory",
                "read_regular",
            )
        )

        def code_tree(code):
            yield code
            for constant in code.co_consts:
                if isinstance(constant, CodeType):
                    yield from code_tree(constant)

        observed = {
            (function.__name__, code.co_name, instruction.opname, instruction.argval)
            for function in functions
            for code in code_tree(function.__code__)
            for instruction in dis.get_instructions(code)
            if instruction.opname in {"LOAD_GLOBAL", "LOAD_NAME"}
        }
        self.assertEqual(observed, set())

    def test_module_ast_has_no_device_process_or_network_surface(self):
        source = SCRIPT.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        calls = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    calls.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    calls.add(node.func.attr)
        self.assertTrue(
            imported.isdisjoint(
                {"asyncio", "ctypes", "httpx", "requests", "socket", "subprocess"}
            )
        )
        self.assertTrue(
            calls.isdisjoint(
                {
                    "connect",
                    "exec",
                    "ioctl",
                    "mount",
                    "popen",
                    "run",
                    "send",
                    "system",
                    "umount",
                }
            )
        )


class HeldCorpusRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workspace = Path(__file__).resolve().parents[3]
        cls.s15 = (
            workspace
            / "Latest Bitmain FW"
            / ("Antminer-S15-user-OM-201912131535-sig_4864.tar.gz")
        )
        cls.t15 = (
            workspace
            / "Latest Bitmain FW"
            / ("Antminer-T15-user-OM-201912131546-sig_4867.tar.gz")
        )
        if not cls.s15.is_file() or not cls.t15.is_file():
            raise unittest.SkipTest("operator-held S15/T15 corpus is absent")
        cls.receipt = carrier.build_report(cls.s15, cls.t15)
        cls.report = cls.receipt.to_dict()

    def test_exact_held_packages_and_selected_rootfs_files(self):
        self.assertTrue(self.receipt.receipt_verified)
        self.assertTrue(
            self.receipt.shared_carrier_contract.artifact_association_verified
        )
        assert_receipt_authority_false(self, self.receipt)
        self.assertEqual(
            self.report["schema"], "dcent.s15-t15-bm1391-carrier-evidence.v1"
        )
        for model in ("S15", "T15"):
            evidence = self.report["models"][model]
            self.assertFalse(evidence["boot"]["devicetree_member_present"])
            self.assertEqual(evidence["rootfs"]["ext2_size"], 100 * 1024 * 1024)
            self.assertEqual(len(evidence["rootfs"]["selected_files"]), 7)
            self.assertEqual(
                evidence["artifact"]["signature_evidence"],
                "payload-contained-signature-material-not-an-anchored-root",
            )

        enumeration = self.report["shared_carrier_contract"]["bm1391_enumeration"]
        self.assertEqual(
            enumeration["expected_responses_per_present_chain"]["S15"]["count"],
            72,
        )
        self.assertEqual(
            enumeration["expected_responses_per_present_chain"]["T15"]["count"],
            60,
        )
        self.assertFalse(enumeration["physical_topology_authorized"])

    def test_s15_t15_shared_carrier_bytes_are_identical(self):
        models = self.report["models"]
        self.assertEqual(
            models["S15"]["boot"]["boot_bin"], models["T15"]["boot"]["boot_bin"]
        )
        self.assertEqual(
            models["S15"]["boot"]["kernel"], models["T15"]["boot"]["kernel"]
        )
        selected = {}
        for model in ("S15", "T15"):
            selected[model] = {
                item["path"]: item for item in models[model]["rootfs"]["selected_files"]
            }
        for path in carrier.COMMON_FILE_PINS:
            self.assertEqual(selected["S15"][path], selected["T15"][path])

    def test_output_is_deterministic_and_contains_no_input_paths(self):
        encoded_a = self.receipt.to_pretty_json()
        encoded_b = carrier.build_report(self.s15, self.t15).to_pretty_json()
        self.assertEqual(encoded_a, encoded_b)
        self.assertNotIn(str(self.s15.parent), encoded_a)
        self.assertEqual(len(encoded_a.encode("utf-8")), 15_521)
        self.assertEqual(
            hashlib.sha256(encoded_a.encode("utf-8")).hexdigest(),
            "8e0c0d18ee6ded6e2b8bd87ae71623dab5a91f0fb5c0a7497aba23687b7dc38a",
        )

    def test_cli_report_is_byte_identical_to_the_compatibility_surface(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            result = carrier.main(
                [
                    "--s15",
                    str(self.s15),
                    "--t15",
                    str(self.t15),
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(result, 0)
            encoded = output.read_bytes()
            self.assertEqual(encoded, self.receipt.to_pretty_json().encode("utf-8"))
            self.assertEqual(
                hashlib.sha256(encoded).hexdigest(),
                "8e0c0d18ee6ded6e2b8bd87ae71623dab5a91f0fb5c0a7497aba23687b7dc38a",
            )

    def test_cli_refuses_input_alias_existing_and_link_outputs_without_damage(self):
        s15_size = self.s15.stat().st_size
        s15_digest = hashlib.sha256(self.s15.read_bytes()).hexdigest()
        self.assertEqual(
            carrier.main(
                [
                    "--s15",
                    str(self.s15),
                    "--t15",
                    str(self.t15),
                    "--output",
                    str(self.s15),
                ]
            ),
            1,
        )
        self.assertEqual(self.s15.stat().st_size, s15_size)
        self.assertEqual(hashlib.sha256(self.s15.read_bytes()).hexdigest(), s15_digest)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / "existing.json"
            existing.write_bytes(b"existing-victim")
            self.assertEqual(
                carrier.main(
                    [
                        "--s15",
                        str(self.s15),
                        "--t15",
                        str(self.t15),
                        "--output",
                        str(existing),
                    ]
                ),
                1,
            )
            self.assertEqual(existing.read_bytes(), b"existing-victim")

            hardlink = root / "hardlink.json"
            os.link(existing, hardlink)
            self.assertEqual(
                carrier.main(
                    [
                        "--s15",
                        str(self.s15),
                        "--t15",
                        str(self.t15),
                        "--output",
                        str(hardlink),
                    ]
                ),
                1,
            )
            self.assertEqual(existing.read_bytes(), b"existing-victim")

            symlink = root / "symlink.json"
            try:
                os.symlink(existing, symlink)
            except (OSError, NotImplementedError):
                pass
            else:
                self.assertEqual(
                    carrier.main(
                        [
                            "--s15",
                            str(self.s15),
                            "--t15",
                            str(self.t15),
                            "--output",
                            str(symlink),
                        ]
                    ),
                    1,
                )
                self.assertEqual(existing.read_bytes(), b"existing-victim")

    def test_cli_exclusive_create_refuses_post_preflight_race(self):
        private_functions = {
            getattr(cell.cell_contents, "__name__", ""): cell.cell_contents
            for cell in (carrier.main.__closure__ or ())
            if callable(cell.cell_contents)
        }
        preflight = private_functions["preflight_output"]
        exclusive_write = private_functions["exclusive_write"]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "raced.json"
            absolute, parent_identity = preflight(output, self.s15, self.t15)
            output.write_bytes(b"racing-victim")
            with self.assertRaises(FileExistsError):
                exclusive_write(absolute, b"forged", parent_identity)
            self.assertEqual(output.read_bytes(), b"racing-victim")

    def test_verified_receipts_are_fresh_and_replace_resets_trust(self):
        second = carrier.build_report(self.s15, self.t15)
        self.assertIsNot(second, self.receipt)
        self.assertIsNot(
            second.shared_carrier_contract,
            self.receipt.shared_carrier_contract,
        )
        self.assertIsNot(second.to_dict(), second.to_dict())
        self.assertTrue(second.receipt_verified)
        self.assertTrue(second.shared_carrier_contract.artifact_association_verified)
        self.assertFalse(replace(second).receipt_verified)
        self.assertFalse(
            replace(second.shared_carrier_contract).artifact_association_verified
        )
        forged = replace(second, canonical_models_json='{"forged":true}')
        self.assertFalse(forged.receipt_verified)
        assert_receipt_authority_false(self, forged)

    def test_same_object_receipt_poison_is_refused_by_every_serializer(self):
        poisoned_models = carrier.build_report(self.s15, self.t15)
        object.__setattr__(
            poisoned_models,
            "canonical_models_json",
            '{"S15":{"forged":true},"T15":{"forged":true}}',
        )
        with self.assertRaisesRegex(carrier.EvidenceError, "model evidence"):
            poisoned_models.to_dict()
        with self.assertRaisesRegex(carrier.EvidenceError, "model evidence"):
            poisoned_models.to_pretty_json()

        poisoned_contract = carrier.build_report(self.s15, self.t15)
        object.__setattr__(
            poisoned_contract.shared_carrier_contract,
            "canonical_contract_json",
            '{"authority":{"install_authorized":true}}',
        )
        with self.assertRaisesRegex(carrier.EvidenceError, "carrier contract"):
            poisoned_contract.to_dict()
        with self.assertRaisesRegex(carrier.EvidenceError, "carrier contract"):
            poisoned_contract.to_pretty_json()

    def test_public_global_and_prior_output_poisoning_cannot_change_admission(self):
        first = carrier.build_report(self.s15, self.t15)
        detached = first.to_dict()
        detached["shared_carrier_contract"]["authority"]["install_authorized"] = True
        object.__setattr__(first, "canonical_models_json", '{"forged":true}')
        object.__setattr__(
            first.shared_carrier_contract,
            "canonical_contract_json",
            '{"authority":{"install_authorized":true}}',
        )

        public_model_hash = carrier.MODEL_PINS["S15"]["package_sha256"]
        public_common = dict(carrier.COMMON_FILE_PINS)
        trusted_build_report = carrier.build_report
        trusted_main = carrier.main
        carrier.MODEL_PINS["S15"]["package_sha256"] = "f" * 64
        carrier.COMMON_FILE_PINS.clear()

        class Forged:
            pass

        shadows = {
            "_PRIVATE_MODEL_PIN_ROWS": (("forged",),),
            "_PRIVATE_COMMON_FILE_PIN_ROWS": (),
            "MAX_PACKAGE_BYTES": 0,
            "MAX_TAR_BYTES": 0,
            "MAX_RAMDISK_BYTES": 0,
            "MAX_TAR_MEMBERS": 0,
            "OUTER_MEMBERS": frozenset(),
            "INNER_MEMBERS": frozenset(),
            "BOOT_BIN_PIN": (0, "forged"),
            "KERNEL_PIN": (0, "forged"),
            "CERT_SHA256": "forged",
            "CarrierContractReceipt": Forged,
            "CarrierEvidenceReceipt": Forged,
            "EvidenceError": Forged,
            "Ext2Reader": Forged,
            "Path": Forged,
            "hashlib": None,
            "io": None,
            "json": None,
            "math": None,
            "os": None,
            "posixpath": None,
            "stat": None,
            "struct": None,
            "tarfile": None,
            "zlib": None,
            "checked_blob": lambda *_args, **_kwargs: b"forged",
            "bounded_gzip": lambda *_args, **_kwargs: b"forged",
            "exact_tar_gz": lambda *_args, **_kwargs: {"forged": b"forged"},
            "parse_legacy_ramdisk": lambda *_args, **_kwargs: (b"forged", {}),
            "inspect_model": lambda *_args, **_kwargs: {"forged": True},
            "carrier_contract": lambda: Forged(),
            "build_report": lambda *_args, **_kwargs: Forged(),
            "parse_args": lambda *_args, **_kwargs: Forged(),
            "_trusted_pretty_json": lambda *_args, **_kwargs: "forged\n",
            "_carrier_contract_payload": lambda: {"forged": True},
            "all": lambda *_args: False,
            "any": lambda *_args: False,
            "bool": lambda *_args: False,
            "bytearray": Forged,
            "bytes": Forged,
            "dict": Forged,
            "frozenset": lambda *_args: frozenset(),
            "getattr": lambda *_args: 0,
            "isinstance": lambda *_args: False,
            "len": lambda *_args: 0,
            "list": lambda *_args: [],
            "min": lambda *_args: 0,
            "reversed": lambda *_args: (),
            "sorted": lambda *_args: [],
            "str": lambda *_args: "forged",
            "tuple": lambda *_args: ("forged",),
            "UnicodeDecodeError": Forged,
        }
        previous = {
            name: (hasattr(carrier, name), getattr(carrier, name, None))
            for name in shadows
        }
        receipt_type = type(self.receipt)
        contract_type = type(self.receipt.shared_carrier_contract)
        with tempfile.TemporaryDirectory() as directory:
            cli_output = Path(directory) / "shadowed.json"
            try:
                for name, value in shadows.items():
                    setattr(carrier, name, value)
                second = trusted_build_report(self.s15, self.t15)
                report = second.to_dict()
                self.assertEqual(
                    trusted_main(
                        [
                            "--s15",
                            str(self.s15),
                            "--t15",
                            str(self.t15),
                            "--output",
                            str(cli_output),
                        ]
                    ),
                    0,
                )
                cli_bytes = cli_output.read_bytes()
            finally:
                carrier.MODEL_PINS["S15"]["package_sha256"] = public_model_hash
                carrier.COMMON_FILE_PINS.update(public_common)
                for name, (existed, value) in previous.items():
                    if existed:
                        setattr(carrier, name, value)
                    else:
                        delattr(carrier, name)

        self.assertIs(type(second), receipt_type)
        self.assertIs(type(second.shared_carrier_contract), contract_type)
        self.assertTrue(second.receipt_verified)
        self.assertTrue(second.shared_carrier_contract.artifact_association_verified)
        self.assertEqual(
            report["models"]["S15"]["artifact"]["package_sha256"],
            public_model_hash,
        )
        self.assertFalse(
            report["shared_carrier_contract"]["authority"]["install_authorized"]
        )
        self.assertEqual(
            report["shared_carrier_contract"]["bm1391_enumeration"][
                "expected_responses_per_present_chain"
            ]["S15"]["count"],
            72,
        )
        self.assertEqual(
            hashlib.sha256(cli_bytes).hexdigest(),
            "8e0c0d18ee6ded6e2b8bd87ae71623dab5a91f0fb5c0a7497aba23687b7dc38a",
        )
        assert_receipt_authority_false(self, second)

    def test_package_pin_fails_closed_on_byte_drift(self):
        damaged = bytearray(self.s15.read_bytes())
        damaged[-1] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "damaged.tar.gz"
            path.write_bytes(damaged)
            with self.assertRaisesRegex(carrier.EvidenceError, "package hash drift"):
                carrier.checked_blob(
                    path,
                    len(damaged),
                    carrier.MODEL_PINS["S15"]["package_sha256"],
                )


if __name__ == "__main__":
    unittest.main()
