#!/usr/bin/env python3
"""Host-only tests for deterministic K210 boot-route adjudication."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = SCRIPT_DIR / "k210_boot_route.py"
MANIFEST_PATH = SCRIPT_DIR.parent / "gauntlet" / "k210_models.json"

spec = importlib.util.spec_from_file_location("k210_boot_route", SCRIPT_PATH)
assert spec is not None and spec.loader is not None
route = importlib.util.module_from_spec(spec)
spec.loader.exec_module(route)


def _sha(character: str) -> str:
    return character * 64


def _verified_boot_result() -> dict[str, object]:
    return {
        "authority_granted": False,
        "boot_policy_gate_eligible": True,
        "candidate_load_contract_compatible": True,
        "discovery_receipt_id": _sha("1"),
        "flash_policy_sha256": _sha("2"),
        "force_decrypt_state": "disabled",
        "jtag_capabilities": {
            "halt_capable": False,
            "read_memory_capable": False,
            "write_memory_capable": False,
        },
        "jtag_state": "locked",
        "operator_key_id_sha256": _sha("3"),
        "plaintext_boot_supported": True,
        "plaintext_probe_performed": True,
        "plaintext_probe_result": "booted",
        "receipt_id": _sha("4"),
        "recovery_receipt_id": _sha("5"),
        "rom_isp_capabilities": {
            "erase_capable": False,
            "existing_flash_independent": False,
            "read_capable": False,
            "write_capable": False,
        },
        "rom_isp_state": "locked",
        "state": "verified_signed_boot_policy_measurement",
        "stock_backup_set_sha256": _sha("6"),
        "target_id": "a1246",
        "unit_fingerprint_sha256": _sha("7"),
        "unit_label": "a1246-unit-01",
        "witness_key_id_sha256": _sha("8"),
    }


def _by_id(result: dict[str, object]) -> dict[str, dict[str, object]]:
    return {item["route_id"]: item for item in result["routes"]}


class BootRouteTests(unittest.TestCase):
    def test_native_aes0_is_selected_only_from_positive_signed_measurement(self) -> None:
        result = route.adjudicate(_verified_boot_result())
        self.assertEqual(result["selected_route"], "native_aes0_flash")
        self.assertEqual(result["selected_route_state"], "measured_compatible")
        self.assertFalse(result["selected_route_is_deployment_ready"])
        self.assertFalse(result["authority_granted"])
        self.assertTrue(all(not item["install_ready"] for item in result["routes"]))
        self.assertTrue(all(not item["authority_granted"] for item in result["routes"]))

    def test_rom_isp_candidate_wins_after_native_flash_is_measured_blocked(self) -> None:
        measured = _verified_boot_result()
        measured["force_decrypt_state"] = "enabled"
        measured["plaintext_boot_supported"] = False
        measured["plaintext_probe_performed"] = False
        measured["plaintext_probe_result"] = "not_run_force_decrypt_enabled"
        measured["rom_isp_state"] = "accessible"
        measured["rom_isp_capabilities"] = {
            "erase_capable": True,
            "existing_flash_independent": True,
            "read_capable": True,
            "write_capable": True,
        }
        result = route.adjudicate(measured)
        routes = _by_id(result)
        self.assertEqual(result["selected_route"], "rom_isp_sram_bootstrap")
        self.assertEqual(
            result["selected_route_state"], "eligible_for_controlled_sram_probe"
        )
        self.assertEqual(routes["native_aes0_flash"]["state"], "measured_blocked")
        self.assertIn(
            "sram_execution_still_requires_separate_proof",
            routes["rom_isp_sram_bootstrap"]["reasons"],
        )

    def test_jtag_candidate_wins_when_flash_and_rom_are_blocked(self) -> None:
        measured = _verified_boot_result()
        measured["force_decrypt_state"] = "enabled"
        measured["plaintext_boot_supported"] = False
        measured["plaintext_probe_performed"] = False
        measured["plaintext_probe_result"] = "not_run_force_decrypt_enabled"
        measured["jtag_state"] = "accessible"
        measured["jtag_capabilities"] = {
            "halt_capable": True,
            "read_memory_capable": True,
            "write_memory_capable": True,
        }
        result = route.adjudicate(measured)
        self.assertEqual(result["selected_route"], "jtag_sram_bootstrap")
        self.assertEqual(
            result["selected_route_state"], "eligible_for_controlled_sram_probe"
        )

    def test_replacement_controller_is_explicit_unqualified_fallback(self) -> None:
        measured = _verified_boot_result()
        measured["force_decrypt_state"] = "enabled"
        measured["plaintext_boot_supported"] = False
        measured["plaintext_probe_performed"] = False
        measured["plaintext_probe_result"] = "not_run_force_decrypt_enabled"
        result = route.adjudicate(measured)
        routes = _by_id(result)
        self.assertEqual(result["selected_route"], "clean_replacement_controller")
        self.assertEqual(
            result["selected_route_state"], "requires_external_qualification"
        )
        self.assertIn(
            "exact_replacement_controller_contract_required",
            routes["clean_replacement_controller"]["reasons"],
        )

    def test_incompatible_load_contract_blocks_all_in_controller_routes(self) -> None:
        measured = _verified_boot_result()
        measured["candidate_load_contract_compatible"] = False
        measured["rom_isp_state"] = "accessible"
        measured["rom_isp_capabilities"] = {
            "erase_capable": True,
            "existing_flash_independent": True,
            "read_capable": True,
            "write_capable": True,
        }
        measured["jtag_state"] = "accessible"
        measured["jtag_capabilities"] = {
            "halt_capable": True,
            "read_memory_capable": True,
            "write_memory_capable": True,
        }
        result = route.adjudicate(measured)
        routes = _by_id(result)
        for route_id in (
            "native_aes0_flash",
            "rom_isp_sram_bootstrap",
            "jtag_sram_bootstrap",
        ):
            self.assertEqual(routes[route_id]["state"], "measured_blocked")
            self.assertIn(
                "candidate_load_contract_incompatible",
                routes[route_id]["reasons"],
            )

    def test_verified_result_tampering_fails_closed(self) -> None:
        cases = []
        authority = _verified_boot_result()
        authority["authority_granted"] = True
        cases.append(authority)
        locked_caps = _verified_boot_result()
        locked_caps["rom_isp_capabilities"]["write_capable"] = True
        cases.append(locked_caps)
        inconsistent_plaintext = _verified_boot_result()
        inconsistent_plaintext["plaintext_boot_supported"] = False
        cases.append(inconsistent_plaintext)
        missing = _verified_boot_result()
        del missing["flash_policy_sha256"]
        cases.append(missing)
        for observed in cases:
            with self.subTest(observed=observed):
                with self.assertRaises(route.BootRouteError):
                    route.adjudicate(observed)

    def test_output_is_deterministic_and_digest_bound(self) -> None:
        first = route.adjudicate(_verified_boot_result())
        second = route.adjudicate(copy.deepcopy(_verified_boot_result()))
        self.assertEqual(first, second)
        digest = first.pop("adjudication_sha256")
        payload = json.dumps(first, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
        self.assertEqual(
            digest,
            route.hashlib.sha256(
                b"DCENT-K210-BOOT-ROUTE-V1\x00" + payload
            ).hexdigest(),
        )

    def test_canonical_cli_refuses_unpinned_manifest_before_bundle_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "route.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--manifest",
                    str(MANIFEST_PATH),
                    "adjudicate",
                    "--boot-policy-bundle",
                    str(Path(temporary) / "absent-bundle"),
                    "--json-out",
                    str(output),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("is not pinned", proc.stderr)
            self.assertFalse(output.exists())

    def test_pinned_keys_use_the_manifest_anchor_path_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = {
                "boot_policy_contract": {
                    "trust_anchors": {
                        "operator": {
                            "key_id_sha256": _sha("a"),
                            "path": "keys/operator.pub",
                            "role": "k210_boot_policy_operator",
                        },
                        "witness": {
                            "key_id_sha256": _sha("b"),
                            "path": "keys/witness.pub",
                            "role": "k210_boot_policy_witness",
                        },
                    }
                }
            }

            def inspect(path: Path) -> dict[str, str]:
                return {
                    "canonical_line": "unused",
                    "key_id_sha256": (
                        _sha("a") if path.name == "operator.pub" else _sha("b")
                    ),
                }

            with mock.patch.object(
                route.discovery, "inspect_public_key", side_effect=inspect
            ):
                operator, witness, operator_id, witness_id = route._pinned_boot_keys(
                    manifest, root
                )
        self.assertEqual(operator, root / "keys" / "operator.pub")
        self.assertEqual(witness, root / "keys" / "witness.pub")
        self.assertEqual(operator_id, _sha("a"))
        self.assertEqual(witness_id, _sha("b"))


if __name__ == "__main__":
    unittest.main()
