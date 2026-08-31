#!/usr/bin/env python3
"""Host-only loopback tests for the K210 discovery collector and drill-plan generator.

The fake CGMiner API server binds 127.0.0.1 only. No live miner is ever
contacted by this suite.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import re
import shlex
import socket
import tempfile
import threading
import unittest
from pathlib import Path


def _load(name: str, filename: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector = _load("k210_discovery_collect", "k210_discovery_collect.py")
discovery = _load("k210_discovery_receipt", "k210_discovery_receipt.py")
recovery = _load("k210_recovery_receipt", "k210_recovery_receipt.py")
planner = _load("k210_recovery_drill_plan", "k210_recovery_drill_plan.py")

MANIFEST = (
    Path(__file__).resolve().parent.parent / "gauntlet" / "k210_models.json"
)

UTC_SECOND_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class FakeApiServer:
    """In-thread fake CGMiner 4028 endpoint on 127.0.0.1."""

    def __init__(self, responses: dict[str, bytes]) -> None:
        self.responses = responses
        self.received: list[bytes] = []
        self.connections = 0
        self._stop = threading.Event()
        self._socket = socket.socket()
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(4)
        self._socket.settimeout(0.1)
        self.port = self._socket.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connections += 1
            with connection:
                connection.settimeout(5)
                data = b""
                while not data.endswith(b"\n"):
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                self.received.append(data)
                command = data.decode("ascii", errors="replace").strip()
                payload = self.responses.get(
                    command, b'{"STATUS":[{"Status":"E"}],"id":1}'
                )
                # MM3-era stacks pad responses with trailing NUL bytes.
                connection.sendall(payload + b"\x00\x00")
                connection.shutdown(socket.SHUT_WR)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._socket.close()


def version_payload(
    firmware: str = "22062202_be77c30_a769bbf",
    hwtype: str = "MM3v2_X2",
    swtype: str = "MM315",
    prod: str = "AvalonMiner A1246",
    spelling: str = "VERSION",
    extra: dict | None = None,
) -> bytes:
    entry = {
        spelling: firmware,
        "HWTYPE": hwtype,
        "SWTYPE": swtype,
        "PROD": prod,
        "DNA": "dna-0001",
        "MAC": "02:00:00:00:00:01",
        "UPAPI": 5,
    }
    if extra is not None:
        entry.update(extra)
    return json.dumps(
        {
            "STATUS": [{"Code": 22, "Status": "S", "When": 1655900000}],
            "VERSION": [entry],
            "id": 1,
        }
    ).encode("ascii")


def stats_payload(module_objects: int = 3) -> bytes:
    return json.dumps(
        {
            "STATUS": [{"Code": 68, "Status": "S", "When": 1655900000}],
            "STATS": [
                {"MM ID0": index, "Frequency": 100 + index} for index in range(module_objects)
            ],
            "id": 1,
        }
    ).encode("ascii")


class CollectorTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)
        self.session_dir = self.root / "source"
        self.server = FakeApiServer(
            {
                "version": version_payload(),
                "stats": stats_payload(),
                "estats": stats_payload(module_objects=2),
                "summary": b'{"STATUS":[{"Status":"S"}],"SUMMARY":[{"GHS": 90}],"id":1}',
                "pools": b'{"STATUS":[{"Status":"S"}],"POOLS":[{"URL":"stratum+tcp://pool.example","User":"bench.worker-1"}],"id":1}',
            }
        )
        self.addCleanup(self.server.close)

    def run_collect(self, *extra: str):
        arguments = [
            "collect",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.server.port),
            "--session-dir",
            str(self.session_dir),
            *extra,
        ]
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = collector.main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()


class FramingAndCaptureTests(CollectorTestCase):
    def test_mm3_framing_quirk_request_and_nul_trim(self):
        code, _, _ = self.run_collect("--commands", "version", "stats")
        self.assertEqual(code, 0)
        # One newline-terminated ASCII request per command, no NUL padding.
        self.assertEqual(self.server.received, [b"version\n", b"stats\n"])
        expected_version = mm3_trim(version_payload())
        saved = (self.session_dir / "stock_version_response.json").read_bytes()
        self.assertEqual(saved, expected_version)
        # The fake server appended two NUL bytes; they must be trimmed on save.
        self.assertFalse(saved.endswith(b"\x00"))

    def test_runbook_file_naming(self):
        code, _, _ = self.run_collect(
            "--commands",
            "version",
            "stats",
            "estats",
            "summary",
            "pools",
        )
        self.assertEqual(code, 0)
        for command, filename in collector.RESPONSE_FILENAMES.items():
            self.assertTrue(
                (self.session_dir / filename).is_file(), f"missing {filename}"
            )

    def test_allowlist_refused_at_argparse_layer(self):
        parser = collector.build_parser()
        for forbidden in ("ascset", "setpool", "reboot", "config", "devs", ""):
            with self.assertRaises(SystemExit) as caught:
                parser.parse_args(
                    [
                        "collect",
                        "--host",
                        "127.0.0.1",
                        "--session-dir",
                        str(self.session_dir),
                        "--commands",
                        "version",
                        forbidden,
                    ]
                )
            self.assertEqual(caught.exception.code, 2)
        self.assertEqual(self.server.connections, 0)

    def test_no_raw_command_escape_hatch(self):
        parser = collector.build_parser()
        subparsers = next(
            action
            for action in parser._actions
            if isinstance(action, argparse_subparsers_type())
        )
        collect_parser = subparsers.choices["collect"]
        commands_action = next(
            action
            for action in collect_parser._actions
            if "--commands" in action.option_strings
        )
        self.assertEqual(
            set(commands_action.choices), set(collector.API_COMMAND_ALLOWLIST)
        )
        for action in collect_parser._actions:
            for option in action.option_strings:
                self.assertNotIn("raw", option)
                self.assertNotIn("exec", option)

    def test_transport_error_stops_session(self):
        dead = FakeApiServer({})
        dead.close()  # port now refuses connections
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = collector.main(
                [
                    "collect",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(dead.port),
                    "--session-dir",
                    str(self.session_dir),
                ]
            )
        self.assertEqual(code, 1)
        log = json.loads(
            (self.session_dir / "collection_log.json").read_text(encoding="ascii")
        )
        self.assertIsNotNone(log["stopped_reason"])
        self.assertTrue(log["stopped_reason"].startswith("transport_error"))
        self.assertEqual(len(log["command_results"]), 1)
        self.assertEqual(log["command_results"][0]["status"], "transport_error")
        self.assertFalse(
            list(self.session_dir.glob("stock_*.json")),
            "no response file may be written on a transport error",
        )

    def test_refuses_overwrite_of_existing_evidence(self):
        self.session_dir.mkdir(parents=True)
        (self.session_dir / "stock_version_response.json").write_bytes(b"stale")
        code, _, stderr = self.run_collect("--commands", "version")
        self.assertEqual(code, 2)
        self.assertIn("refusing to overwrite", stderr)
        self.assertEqual(
            (self.session_dir / "stock_version_response.json").read_bytes(), b"stale"
        )


class AnomalyTests(CollectorTestCase):
    def log(self) -> dict:
        return json.loads(
            (self.session_dir / "collection_log.json").read_text(encoding="ascii")
        )

    def test_anomalies_recorded_without_stopping(self):
        self.server.responses["version"] = version_payload(
            firmware="not-a-version", hwtype="MM3v2_X3", swtype="MM315_OOW",
            prod="BitMiner X9", spelling="MISSING",
            extra={"MISSING": "x"},
        )
        code, _, _ = self.run_collect("--commands", "version", "stats")
        self.assertEqual(code, 0)
        codes = {anomaly["code"] for anomaly in self.log()["anomalies"]}
        self.assertIn("version_field_missing", codes)
        self.assertIn("prod_prefix_mismatch", codes)
        self.assertIn("hwtype_differs_from_held_profile", codes)
        self.assertIn("swtype_differs_from_held_profile", codes)
        # The session still continued and saved both responses.
        self.assertTrue((self.session_dir / "stock_stats_response.json").is_file())
        self.assertTrue((self.session_dir / "stock_version_response.json").is_file())

    def test_prod_prefix_and_firmware_shape_anomalies(self):
        self.server.responses["version"] = version_payload(
            firmware="22062202_be77c30_a769bbf", prod="AvalonMiner"
        )
        code, _, _ = self.run_collect("--commands", "version")
        self.assertEqual(code, 0)
        codes = {anomaly["code"] for anomaly in self.log()["anomalies"]}
        self.assertNotIn("prod_prefix_mismatch", codes)
        self.assertNotIn("firmware_shape_unexpected", codes)
        self.assertNotIn("firmware_differs_from_held_profile", codes)

        self.server.received.clear()
        self.server.responses["version"] = version_payload(
            firmware="22062202_be77c30_a769bbf", prod="Miner A1246"
        )
        second = self.root / "second"
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = collector.main(
                [
                    "collect",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(self.server.port),
                    "--session-dir",
                    str(second),
                    "--commands",
                    "version",
                ]
            )
        self.assertEqual(code, 0)
        second_log = json.loads(
            (second / "collection_log.json").read_text(encoding="ascii")
        )
        codes = {anomaly["code"] for anomaly in second_log["anomalies"]}
        self.assertIn("prod_prefix_mismatch", codes)

    def test_verion_typo_spelling_flagged_as_note(self):
        self.server.responses["version"] = version_payload(spelling="VERION")
        code, _, _ = self.run_collect("--commands", "version")
        self.assertEqual(code, 0)
        anomalies = self.log()["anomalies"]
        codes = {anomaly["code"]: anomaly for anomaly in anomalies}
        self.assertIn("version_field_verion_typo", codes)
        self.assertEqual(codes["version_field_verion_typo"]["severity"], "note")
        self.assertNotIn("version_field_missing", codes)
        self.assertNotIn("firmware_shape_unexpected", codes)

    def test_stats_module_count_note(self):
        code, _, _ = self.run_collect("--commands", "stats")
        self.assertEqual(code, 0)
        codes = {anomaly["code"] for anomaly in self.log()["anomalies"]}
        self.assertNotIn("stats_module_count", codes)
        self.assertNotIn("stats_module_count_note", codes)

        third = self.root / "third"
        self.server.responses["stats"] = stats_payload(module_objects=2)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = collector.main(
                [
                    "collect",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(self.server.port),
                    "--session-dir",
                    str(third),
                    "--commands",
                    "stats",
                ]
            )
        self.assertEqual(code, 0)
        log = json.loads((third / "collection_log.json").read_text(encoding="ascii"))
        codes = {anomaly["code"] for anomaly in log["anomalies"]}
        self.assertIn("stats_module_count_note", codes)


class CollectionLogSchemaTests(CollectorTestCase):
    def test_collection_log_schema_and_credential_hygiene(self):
        code, _, _ = self.run_collect(
            "--commands",
            "version",
            "stats",
            "pools",
            "--operator",
            "bench-op",
            "--authorization-reference",
            "DCENT-2026-09-01-A1246-RO-DISCOVERY-bench",
        )
        self.assertEqual(code, 0)
        log = json.loads(
            (self.session_dir / "collection_log.json").read_text(encoding="ascii")
        )
        for key in (
            "session",
            "operator",
            "authorization_reference",
            "tool",
            "host",
            "port",
            "commands",
            "command_results",
            "events",
            "anomalies",
            "notes",
            "stopped_reason",
        ):
            self.assertIn(key, log)
        self.assertEqual(log["tool"]["name"], "k210_discovery_collect")
        self.assertIn("version", log["tool"])
        self.assertEqual(log["host"], "127.0.0.1")
        self.assertEqual(log["port"], self.server.port)
        self.assertEqual(log["commands"], ["version", "stats", "pools"])
        self.assertEqual(len(log["command_results"]), 3)
        for result in log["command_results"]:
            self.assertTrue(UTC_SECOND_RE.match(result["started_at_utc"]))
            self.assertIsInstance(result["duration_ms"], int)
            self.assertGreaterEqual(result["duration_ms"], 0)
            self.assertEqual(
                result["saved_sha256"],
                hashlib.sha256(
                    (self.session_dir / result["file"]).read_bytes()
                ).hexdigest(),
            )
        # Evidence-kind binding: version/stats/estats are bundle kinds,
        # summary/pools are bench observations only.
        kinds = {item["command"]: item["evidence_kind"] for item in log["command_results"]}
        self.assertEqual(kinds["version"], "stock_version_response")
        self.assertEqual(kinds["stats"], "stock_stats_response")
        self.assertIsNone(kinds["pools"])
        # No credentials: the pools user from the fake response must never be
        # echoed into the log, and no credential-shaped keys exist.
        log_text = json.dumps(log)
        self.assertNotIn("bench.worker-1", log_text)
        self.assertNotIn("pool.example", log_text)
        for forbidden in ("password", "secret", "token"):
            self.assertNotIn(forbidden, log_text.lower())

        log["events"].append(
            {
                "time_utc": log["session_closed_at_utc"],
                "event": "completed deenergized_visual_inspection_power_down, visual_identity_inspection, closed_chassis_stock_power_restoration, and stock_read_only_management_queries",
            }
        )
        discovery._validate_collection_log(
            log,
            {
                "authorization": {
                    "operator_reference": log["authorization_reference"],
                    "valid_from_utc": log["session_started_at_utc"],
                },
                "observed_at_utc": log["session_closed_at_utc"],
            },
        )

    def test_non_bundle_captures_carry_relocation_note(self):
        code, _, _ = self.run_collect("--commands", "summary", "pools")
        self.assertEqual(code, 0)
        log = json.loads(
            (self.session_dir / "collection_log.json").read_text(encoding="ascii")
        )
        self.assertTrue(
            any("outside the evidence root" in note for note in log["notes"])
        )


def argparse_subparsers_type():
    import argparse

    return argparse._SubParsersAction


class SkeletonTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)
        self.session_dir = self.root / "a1246-unit-01" / "source"
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.document = collector.skeleton(
            MANIFEST, "a1246", self.session_dir, "a1246-unit-01"
        )

    def test_skeleton_writes_file_and_refuses_overwrite(self):
        path = self.session_dir / "discovery_skeleton.json"
        self.assertTrue(path.is_file())
        with self.assertRaises(collector.CollectError):
            collector.skeleton(MANIFEST, "a1246", self.session_dir, "a1246-unit-01")

    def test_skeleton_nine_kinds_match_receipt_template_exactly(self):
        template = discovery._template(self.manifest, "a1246")
        expected = {
            (item["kind"], item["path"], item["method"], item["media_type"])
            for item in template["evidence"]
        }
        observed = {
            (slot["kind"], slot["path"], slot["method"], slot["media_type"])
            for slot in self.document["evidence_slots"]
            if slot["required"]
        }
        self.assertEqual(observed, expected)
        self.assertEqual(len(observed), 9)
        optional = {
            slot["kind"] for slot in self.document["evidence_slots"] if not slot["required"]
        }
        self.assertEqual(optional, set(discovery.OPTIONAL_EVIDENCE_KINDS))

    def test_skeleton_exact_match_traps(self):
        target = next(
            row for row in self.manifest["targets"] if row["id"] == "a1246"
        )
        binding = self.document["manifest_binding"]
        expectations = self.document["identity_expectations"]
        # The manifest binding retains the generic target row, but operators
        # must fill identity only from the uniquely resolved held variant.
        self.assertEqual(binding["asic_family"], "A3200")
        self.assertEqual(binding["asic_family"], target["asic_family"])
        self.assertEqual(
            expectations["asic_family"], "REPLACE_FROM_RESOLVED_STOCK_PROFILE"
        )
        self.assertIn("never use the generic target family", expectations["asic_family_note"])
        # Marketing model and manufacturer are exact-match constants.
        self.assertEqual(binding["marketing_model"], "AvalonMiner A1246")
        self.assertEqual(expectations["marketing_model"], target["display_name"])
        self.assertEqual(expectations["manufacturer"], "Canaan")
        self.assertEqual(expectations["controller_soc"], "K210")
        self.assertEqual(
            self.document["authorized_actions"],
            sorted(
                [
                    "closed_chassis_stock_power_restoration",
                    "deenergized_visual_inspection_power_down",
                    "stock_read_only_management_queries",
                    "visual_identity_inspection",
                ]
            ),
        )
        # All three held A1246 revision contracts are exposed as alternatives.
        held = {item["id"]: item for item in expectations["held_variants"]}
        self.assertEqual(
            set(held),
            {
                "a1246-a3200lc-2hash",
                "a1246-a3201-2hash",
                "a1246-a3201-temp65",
            },
        )
        self.assertEqual(
            held["a1246-a3200lc-2hash"]["asic_family"], "A3200LC-Plus"
        )
        self.assertEqual(
            held["a1246-a3201-2hash"]["asic_family"], "A3201-Plus"
        )
        self.assertEqual(held["a1246-a3201-temp65"]["hashboard_count"], 3)
        self.assertEqual(
            binding["variant_profiles"], list(held)
        )

    def test_skeleton_collect_command_matches_collector_cli(self):
        commands = self.document["next_commands"]
        collect_steps = [step for step in commands if step["tool"] == collector.TOOL_NAME]
        self.assertEqual(len(collect_steps), 1)
        parts = shlex.split(collect_steps[0]["command"])
        self.assertEqual(parts[:2], ["py", "-3"])
        parsed = collector.build_parser().parse_args(parts[3:])
        self.assertEqual(parsed.command, "collect")
        self.assertEqual(parsed.commands, list(collector.DEFAULT_COMMANDS))
        self.assertEqual(
            Path(parsed.session_dir).resolve(), self.session_dir.resolve()
        )

    def test_skeleton_next_commands_parse_with_receipt_cli(self):
        receipt_parser = discovery.build_parser()
        receipt_steps = [
            step for step in self.document["next_commands"]
            if step["tool"] == "k210_discovery_receipt.py"
        ]
        self.assertEqual(len(receipt_steps), 3)
        purposes = " ".join(step["purpose"] for step in receipt_steps)
        self.assertIn("descriptor", purposes)
        self.assertIn("sign", purposes)
        self.assertIn("verify", purposes)
        for step in receipt_steps:
            parts = shlex.split(step["command"])
            self.assertEqual(parts[:2], ["py", "-3"])
            parsed = receipt_parser.parse_args(parts[3:])
            if parsed.command == "template":
                self.assertEqual(parsed.model, "a1246")
            if parsed.command == "create":
                self.assertEqual(
                    Path(parsed.evidence_root).resolve(),
                    self.session_dir.resolve(),
                )
        create_step = next(
            step for step in receipt_steps if " create " in f" {step['command']} "
        )
        for flag in (
            "--capture",
            "--evidence-root",
            "--private-key",
            "--bundle-out",
        ):
            self.assertIn(flag, create_step["command"])


class DrillPlanTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)
        self.out_dir = self.root / "plans"
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def make_receipt(self, name: str = "receipt.json") -> Path:
        receipt = {
            "receipt_id": "a" * 64,
            "unit_fingerprint_sha256": "b" * 64,
            "unit_label": "a1246-unit-01",
            "target_id": "a1246",
            "identity": {
                "stock_dna": "dna-0001",
                "stock_firmware_version": "22062202_be77c30_a769bbf",
                "stock_hwtype": "MM3v2_X2",
                "stock_swtype": "MM315",
            },
        }
        path = self.root / name
        path.write_text(json.dumps(receipt), encoding="ascii")
        return path


class DrillPlanTests(DrillPlanTestCase):
    def test_all_receipt_required_stages_present(self):
        plan = planner.generate_drill_plan(
            self.manifest, "a1246", "a1246-unit-01", self.make_receipt()
        )
        tags = {tag for stage in plan["stages"] for tag in stage["tags"]}
        required = {
            "explicit_recovery_authorization",
            "admitted_discovery_required",
            "exact_unit_join",
            "per_device_geometry",
            "two_backup_reads",
            "distinct_mechanisms",
            "distinct_tools",
            "external_programmer_backup",
            "existing_flash_independent_route",
            "identical_byte_count",
            "identical_sha256",
            "two_restore_paths",
            "external_programmer_restore",
            "full_write",
            "full_readback_equals_backup",
            "cold_boot_stock",
            "stock_identity_matched",
            "separate_records_per_run",
            "controlled_restore_interruption",
            "destructive_sacrificial_only",
            "recovered_via_other_admitted_path",
            "evidence_slots_complete",
            "dual_signatures",
            "distinct_principals",
            "distinct_keys",
            "admission_step",
            "qualifies_only_stock_restore",
        }
        self.assertEqual(required - tags, set())
        backup_stages = [
            stage for stage in plan["stages"] if "two_backup_reads" in stage["tags"]
        ]
        self.assertEqual(len(backup_stages), 2)
        restore_stages = [
            stage for stage in plan["stages"] if "two_restore_paths" in stage["tags"]
        ]
        self.assertEqual(len(restore_stages), 2)
        interruption = next(
            stage
            for stage in plan["stages"]
            if "controlled_restore_interruption" in stage["tags"]
        )
        self.assertIn(
            "OTHER admitted restore path",
            json.dumps(interruption["requirements"]),
        )

    def test_mechanism_and_action_facts_match_receipt_module(self):
        plan = planner.generate_drill_plan(
            self.manifest, "a1246", "a1246-unit-01", None
        )
        self.assertEqual(plan["mechanism_classes"], sorted(recovery.MECHANISM_CLASSES))
        self.assertEqual(plan["interruption_kinds"], sorted(recovery.INTERRUPTION_KINDS))
        self.assertEqual(plan["authorized_actions"], sorted(recovery.RECOVERY_ACTIONS))
        route_b = plan["route_options"]["backup_read_b"]
        self.assertEqual(
            {option["mechanism_class"] for option in route_b},
            {"k210_rom_isp", "vendor_service_bootrom"},
        )
        self.assertEqual(
            plan["route_options"]["backup_read_a"]["mechanism_class"],
            "external_memory_programmer",
        )

    def test_dual_signature_steps(self):
        plan = planner.generate_drill_plan(
            self.manifest, "a1246", "a1246-unit-01", self.make_receipt()
        )
        signing = plan["signing"]
        self.assertEqual(signing["operator_role"], recovery.OPERATOR_ROLE)
        self.assertEqual(signing["witness_role"], recovery.WITNESS_ROLE)
        self.assertNotEqual(signing["operator_role"], signing["witness_role"])
        self.assertEqual(signing["operator_namespace"], recovery.OPERATOR_NAMESPACE)
        self.assertEqual(signing["witness_namespace"], recovery.WITNESS_NAMESPACE)
        self.assertTrue(signing["distinct_keys_required"])
        self.assertTrue(signing["distinct_principals_required"])
        create_command = next(
            command
            for command in plan["host_commands"]
            if " create " in command["command"]
        )
        for flag in ("--operator-private-key", "--witness-private-key"):
            self.assertIn(flag, create_command["command"])
        verify_command = next(
            command
            for command in plan["host_commands"]
            if " verify " in command["command"]
        )
        for flag in ("--operator-public-key", "--witness-public-key"):
            self.assertIn(flag, verify_command["command"])

    def test_no_executable_flash_commands_in_generated_plan(self):
        plan = planner.generate_drill_plan(
            self.manifest, "a1246", "a1246-unit-01", self.make_receipt()
        )
        markdown = planner.render_markdown(plan)
        checklist = json.dumps(plan)
        for token in planner.FORBIDDEN_EXECUTABLE_TOKENS:
            self.assertNotIn(token, markdown.lower())
            self.assertNotIn(token, checklist.lower())

    def test_evidence_slots_match_receipt_contract(self):
        plan = planner.generate_drill_plan(
            self.manifest, "a1246", "a1246-unit-01", None
        )
        slots = plan["evidence_slots"]
        self.assertEqual(
            {slot["kind"] for slot in slots}, set(recovery.EVIDENCE_KINDS)
        )
        self.assertIn("discovery_receipt_copy", {slot["kind"] for slot in slots})
        self.assertIn("safety_record", {slot["kind"] for slot in slots})
        for slot in slots:
            self.assertIn(slot["media_type"], recovery.MEDIA_TYPES)
            self.assertIn(slot["method"], recovery.EVIDENCE_METHODS)
        paths = [slot["path"] for slot in slots]
        self.assertEqual(len(paths), len(set(paths)))
        # Slot naming mirrors the receipt descriptor template exactly.
        template_paths = {
            path
            for _id, kind, path in planner.EVIDENCE_SLOT_SPECS
        }
        self.assertEqual(set(paths), template_paths)
        self.assertIn("identity/discovery-receipt.json", paths)

    def test_plan_binds_discovery_receipt_exactly(self):
        receipt_path = self.make_receipt()
        plan = planner.generate_drill_plan(
            self.manifest, "a1246", "a1246-unit-01", receipt_path
        )
        binding = plan["discovery_binding"]
        self.assertEqual(binding["discovery_receipt_id"], "a" * 64)
        self.assertEqual(binding["unit_fingerprint_sha256"], "b" * 64)
        self.assertEqual(
            binding["stock_identity"]["stock_firmware_version"],
            "22062202_be77c30_a769bbf",
        )
        self.assertEqual(
            binding["stock_identity"]["stock_hwtype"],
            "MM3v2_X2",
        )

        mismatched = self.make_receipt("mismatch.json")
        document = json.loads(mismatched.read_text(encoding="ascii"))
        document["unit_label"] = "a1246-unit-02"
        mismatched.write_text(json.dumps(document), encoding="ascii")
        with self.assertRaises(planner.DrillPlanError):
            planner.generate_drill_plan(
                self.manifest, "a1246", "a1246-unit-01", mismatched
            )

    def test_rom_isp_option_documented_with_safety_notes(self):
        plan = planner.generate_drill_plan(
            self.manifest, "a1246", "a1246-unit-01", None
        )
        markdown = planner.render_markdown(plan)
        for fact in ("IO_16", "UARTHS", "SLIP", "0xC1", "0xC2", "0xC3", "0xC4", "0xC5", "0xC6", "0xD1"):
            self.assertIn(fact, markdown)
        for safety in ("Fuses B bit 7", "unauthenticated", "brick", "blank or corrupted flash"):
            self.assertIn(safety, markdown)
        annex = plan["route_options"]["backup_read_b"][0]
        self.assertEqual(annex["mechanism_class"], "k210_rom_isp")
        self.assertTrue(any("0x3ff0" in note or "OTP key area" in note for note in annex["safety_notes"]))

    def test_cli_writes_markdown_and_checklist_and_refuses_overwrite(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = planner.main(
                [
                    "--manifest",
                    str(MANIFEST),
                    "plan",
                    "--model",
                    "a1246",
                    "--unit-label",
                    "a1246-unit-01",
                    "--discovery-receipt",
                    str(self.make_receipt()),
                    "--out-dir",
                    str(self.out_dir),
                ]
            )
        self.assertEqual(code, 0)
        markdown_path = self.out_dir / "a1246-unit-01-recovery-drill.md"
        checklist_path = self.out_dir / "a1246-unit-01-recovery-drill-checklist.json"
        self.assertTrue(markdown_path.is_file())
        self.assertTrue(checklist_path.is_file())
        checklist = json.loads(checklist_path.read_text(encoding="ascii"))
        self.assertTrue(checklist["authority"]["generates_plan_only"])
        self.assertFalse(checklist["authority"]["authorizes_any_hardware_action"])
        with contextlib.redirect_stdout(io.StringIO()):
            code = planner.main(
                [
                    "--manifest",
                    str(MANIFEST),
                    "plan",
                    "--model",
                    "a1246",
                    "--unit-label",
                    "a1246-unit-01",
                    "--out-dir",
                    str(self.out_dir),
                ]
            )
        self.assertEqual(code, 2)


def mm3_trim(payload: bytes) -> bytes:
    return payload.rstrip(b"\x00")


if __name__ == "__main__":
    unittest.main()
