#!/usr/bin/env python3
"""Pin the bridge client surface, side effects, evidence, and authority ceiling."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
CRATE_ROOT = DCENTOS_ROOT / "dcentrald" / "dcentrald-bridge"
REGISTRY_PATH = (
    DCENTOS_ROOT
    / "docs"
    / "architecture"
    / "dcentrald_bridge_surface_registry.json"
)

EXPECTED_MODULE_TESTS = {
    "client": {
        "ota_inputs_fail_closed_before_networking",
        "pair_response_proxy_url_accepts_mdns_alias",
        "pair_response_proxy_url_rejects_credentials",
        "pair_response_telemetry_url_accepts_relative_path",
        "pair_response_telemetry_url_accepts_same_origin_absolute",
        "pair_response_telemetry_url_defaults_when_empty",
        "pair_response_telemetry_url_rejects_off_origin",
        "staleness_age_over_5000_is_unavailable",
        "staleness_status_not_ok_is_unavailable",
        "staleness_three_identical_ages_freezes",
        "usable_temperature_predicate",
        "usable_temperature_rejects_absent_and_non_finite_samples",
        "version_regex_fallback",
    },
    "config": {
        "bridge_config_toml_parse_never_panics_on_arbitrary_text",
        "default_is_disabled_with_spec_cadences",
        "empty_toml_section_uses_defaults",
        "partial_toml_fills_defaults",
        "unknown_field_rejected",
    },
    "crypto": {
        "base32_decode_rejects_bad_char",
        "base32_decode_rejects_wrong_length",
        "base32_decode_round_trip",
        "base32_decode_tolerates_lowercase",
        "base32_no_pad_rejects_padding_anywhere",
        "base32_rejects_non_canonical_trailing_bits",
        "bridge_secret_and_signature_helpers_never_panic_on_arbitrary_input",
        "heartbeat_sig_is_body_bound",
        "heartbeat_sig_is_ts_bound",
        "heartbeat_sig_reproduces_frozen_cross_language_kat",
        "ota_pull_sig_differs_from_ota_sig",
        "ota_pull_sig_golden_vector",
        "ota_sig_golden_vector",
        "pair_hmac_golden_vector",
        "pair_hmac_ts_is_decimal_ascii_no_padding",
        "unit_secret_debug_is_redacted",
        "ws_sig_golden_vector",
    },
    "error": set(),
    "protocol": {
        "bridge_json_protocol_decoders_never_panic_on_arbitrary_bytes",
        "health_non_dcent_pack_rejected",
        "health_parses_product_discriminator",
        "heartbeat_request_all_change_b_none_is_byte_identical_to_legacy_shape",
        "heartbeat_request_best_difficulty_passes_free_form_string_through",
        "heartbeat_request_fully_populated_contains_every_change_b_key",
        "heartbeat_request_includes_some_optionals",
        "heartbeat_request_omits_none_optionals",
        "heartbeat_response_paired_false",
        "pair_response_round_trip",
        "telemetry_has_no_value_c_field",
        "telemetry_parses_external_temperature_c",
    },
    "task": {
        "clamp_room_temp_c10_bounds_and_quantization",
        "discovery_predicate_default",
        "discovery_predicate_override",
        "parse_default_gateway_never_panics_on_arbitrary_text",
        "parse_gateway_basic",
        "parse_gateway_customer_router",
        "parse_gateway_none",
    },
}

EXPECTED_PUBLIC = {
    "client": {
        "types": {"BridgeClient", "HeartbeatOutcome"},
        "functions": {"usable_temperature"},
        "methods": {
            "heartbeat",
            "new",
            "ota_pull",
            "ota_upload",
            "pair_once",
            "pair_with_retry",
            "poll_telemetry",
            "probe_health",
            "probe_telemetry_fallback",
            "record_and_extract_temp",
            "reset_staleness",
            "with_http",
        },
        "constants": set(),
    },
    "config": {
        "types": {"BridgeConfig"},
        "functions": set(),
        "methods": set(),
        "constants": set(),
    },
    "crypto": {
        "types": {"SecretDecodeError", "UnitSecret"},
        "functions": {
            "heartbeat_sig",
            "ota_pull_sig",
            "ota_sig",
            "pair_hmac",
            "unit_secret_from_base32",
            "ws_sig",
        },
        "methods": {"as_bytes", "from_bytes"},
        "constants": set(),
    },
    "error": {
        "types": {"BridgeError", "PairError"},
        "functions": set(),
        "methods": {"is_retryable"},
        "constants": set(),
    },
    "protocol": {
        "types": {
            "BridgeAccessories",
            "BridgeTelemetry",
            "BridgeTemperature",
            "HealthMiner",
            "HealthResponse",
            "HeartbeatRequest",
            "HeartbeatResponse",
            "PairRequest",
            "PairResponse",
            "TelemetryPairing",
            "TemperatureFeedback",
        },
        "functions": set(),
        "methods": {"is_dcent_pack"},
        "constants": set(),
    },
    "task": {
        "types": {"BridgeRuntime", "MinerStatusProvider", "RoomTempSink"},
        "functions": {
            "bridge_client_task",
            "is_bridge_gateway",
            "parse_default_gateway",
            "read_default_gateway",
        },
        "methods": set(),
        "constants": {"BRIDGE_GATEWAY_IP"},
    },
}

EXPECTED_REEXPORTS = {
    "BRIDGE_GATEWAY_IP",
    "BridgeClient",
    "BridgeConfig",
    "BridgeError",
    "BridgeRuntime",
    "BridgeTelemetry",
    "BridgeTemperature",
    "HealthResponse",
    "HeartbeatOutcome",
    "HeartbeatRequest",
    "HeartbeatResponse",
    "MinerStatusProvider",
    "PairError",
    "PairRequest",
    "PairResponse",
    "RoomTempSink",
    "SecretDecodeError",
    "UnitSecret",
    "bridge_client_task",
    "heartbeat_sig",
    "is_bridge_gateway",
    "ota_pull_sig",
    "ota_sig",
    "pair_hmac",
    "parse_default_gateway",
    "read_default_gateway",
    "unit_secret_from_base32",
    "usable_temperature",
    "ws_sig",
}


def dependency_keys(manifest: str, section: str) -> set[str]:
    match = re.search(
        rf"^\[{re.escape(section)}\]\s*$\n(?P<body>.*?)(?=^\[|\Z)",
        manifest,
        re.M | re.S,
    )
    if match is None:
        return set()
    return set(
        re.findall(
            r"^([A-Za-z0-9_-]+)(?:\.workspace)?\s*=", match.group("body"), re.M
        )
    )


def public_struct_fields(source: str, name: str) -> set[str]:
    match = re.search(rf"pub struct {name}\s*\{{(?P<body>.*?)\n\}}", source, re.S)
    if match is None:
        return set()
    return set(re.findall(r"^\s+pub ([A-Za-z0-9_]+):", match.group("body"), re.M))


def named_block(source: str, start: str, end: str) -> str:
    return source.split(start, 1)[1].split(end, 1)[0]


def variants(block: str) -> set[str]:
    return set(re.findall(r"^\s{4}([A-Z][A-Za-z0-9_]+)(?:\s*[({]|,)", block, re.M))


class DcentraldBridgeSurfaceRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.modules = {row["module"]: row for row in cls.registry["modules"]}
        cls.sources = {
            name: (CRATE_ROOT / "src" / f"{name}.rs").read_text(encoding="utf-8")
            for name in EXPECTED_MODULE_TESTS
        }
        cls.lib_rs = (CRATE_ROOT / "src" / "lib.rs").read_text(encoding="utf-8")
        cls.cargo = (CRATE_ROOT / "Cargo.toml").read_text(encoding="utf-8")

    def test_modules_public_api_and_root_reexports_are_exact(self) -> None:
        public_modules = set(
            re.findall(r"^pub mod ([A-Za-z0-9_]+);", self.lib_rs, re.M)
        )
        self.assertEqual(public_modules, set(EXPECTED_MODULE_TESTS))
        self.assertEqual(set(self.modules), public_modules)
        self.assertEqual(self.registry["declared_public_modules"], 6)

        for module, expected in EXPECTED_PUBLIC.items():
            with self.subTest(module=module):
                source = self.sources[module]
                actual = {
                    "types": set(
                        re.findall(
                            r"^pub (?:struct|enum|trait|type) ([A-Za-z0-9_]+)",
                            source,
                            re.M,
                        )
                    ),
                    "functions": set(
                        re.findall(
                            r"^pub (?:async )?fn ([A-Za-z0-9_]+)", source, re.M
                        )
                    ),
                    "methods": set(
                        re.findall(
                            r"^    pub (?:async )?fn ([A-Za-z0-9_]+)", source, re.M
                        )
                    ),
                    "constants": set(
                        re.findall(r"^pub const ([A-Za-z0-9_]+)", source, re.M)
                    ),
                }
                self.assertEqual(actual, expected)
                row = self.modules[module]
                self.assertEqual(set(row["public_types"]), expected["types"])
                self.assertEqual(set(row["public_functions"]), expected["functions"])
                self.assertEqual(set(row["public_methods"]), expected["methods"])
                self.assertEqual(
                    set(row.get("public_constants", [])), expected["constants"]
                )
                self.assertEqual(
                    row["source"],
                    f"DCENT_OS_Antminer/dcentrald/dcentrald-bridge/src/{module}.rs",
                )
                self.assertTrue((REPO_ROOT / row["source"]).is_file())

        self.assertEqual(set(self.registry["root_reexports"]), EXPECTED_REEXPORTS)
        self.assertEqual(len(self.registry["root_reexports"]), 29)
        for symbol in EXPECTED_REEXPORTS:
            self.assertRegex(self.lib_rs, rf"\b{re.escape(symbol)}\b")

    def test_public_fields_enum_variants_and_trait_methods_are_exact(self) -> None:
        shapes = self.registry["public_shapes"]
        field_sources = {
            "BridgeClient": self.sources["client"],
            "BridgeConfig": self.sources["config"],
            "BridgeRuntime": self.sources["task"],
            **{
                name: self.sources["protocol"]
                for name in (
                    "BridgeAccessories",
                    "BridgeTelemetry",
                    "BridgeTemperature",
                    "HealthMiner",
                    "HealthResponse",
                    "HeartbeatRequest",
                    "HeartbeatResponse",
                    "PairRequest",
                    "PairResponse",
                    "TelemetryPairing",
                    "TemperatureFeedback",
                )
            },
        }
        self.assertEqual(set(shapes["public_fields"]), set(field_sources))
        for name, source in field_sources.items():
            self.assertEqual(
                set(shapes["public_fields"][name]), public_struct_fields(source, name)
            )

        enum_blocks = {
            "BridgeError": named_block(
                self.sources["error"], "pub enum BridgeError", "impl From<reqwest"
            ),
            "PairError": named_block(
                self.sources["error"], "pub enum PairError", "impl PairError"
            ),
            "HeartbeatOutcome": named_block(
                self.sources["client"], "pub enum HeartbeatOutcome", "pub struct BridgeClient"
            ),
            "SecretDecodeError": named_block(
                self.sources["crypto"], "pub enum SecretDecodeError", "fn base32_decode_nopad"
            ),
        }
        self.assertEqual(set(shapes["enum_variants"]), set(enum_blocks))
        for name, block in enum_blocks.items():
            self.assertEqual(set(shapes["enum_variants"][name]), variants(block))

        task_source = self.sources["task"]
        expected_trait_methods = {}
        for trait, end in (
            ("RoomTempSink", "pub struct BridgeRuntime"),
            ("MinerStatusProvider", "pub fn read_default_gateway"),
        ):
            block = named_block(task_source, f"pub trait {trait}", end)
            expected_trait_methods[trait] = set(
                re.findall(r"^\s+fn ([A-Za-z0-9_]+)\(", block, re.M)
            )
        self.assertEqual(set(shapes["trait_methods"]), set(expected_trait_methods))
        for name, methods in expected_trait_methods.items():
            self.assertEqual(set(shapes["trait_methods"][name]), methods)

    def test_all_test_ownership_and_default_profile_counts_are_exact(self) -> None:
        for module, expected_tests in EXPECTED_MODULE_TESTS.items():
            actual = set(
                re.findall(
                    r"#\[test\]\s+fn ([A-Za-z0-9_]+)\(", self.sources[module]
                )
            )
            self.assertEqual(actual, expected_tests)
            self.assertEqual(self.modules[module]["tests"], len(expected_tests))

        suites = {row["suite"]: row for row in self.registry["integration_suites"]}
        expected_suites = {
            "mock_bridge": {
                "full_pair_heartbeat_telemetry_flow",
                "health_probe_refuses_server_error_and_product_mismatch",
                "heartbeat_paired_false_signals_repair",
            },
            "pair_policy": {
                "fast_fail_variants_do_not_retry",
                "policy_table_retry_decisions",
                "replay_is_distinct_error_variant",
                "server_errors_retry_only_5xx",
            },
        }
        self.assertEqual(set(suites), set(expected_suites))
        for suite, expected_tests in expected_suites.items():
            source = (CRATE_ROOT / "tests" / f"{suite}.rs").read_text(encoding="utf-8")
            actual = set(
                re.findall(
                    r"#\[(?:tokio::)?test\]\s+(?:async )?fn ([A-Za-z0-9_]+)\(",
                    source,
                )
            )
            self.assertEqual(actual, expected_tests)
            self.assertEqual(set(suites[suite]["tests"]), expected_tests)

        self.assertEqual(sum(map(len, EXPECTED_MODULE_TESTS.values())), 54)
        self.assertEqual(sum(map(len, expected_suites.values())), 7)
        self.assertEqual(self.registry["module_scoped_tests"], 54)
        self.assertEqual(self.registry["integration_tests"], 7)
        self.assertEqual(self.registry["total_tests"], 61)
        self.assertEqual(
            self.registry["compile_profiles"],
            [
                {
                    "profile": "default",
                    "features": [],
                    "public_modules": 6,
                    "root_reexports": 29,
                    "module_scoped_tests": 54,
                    "integration_tests": 7,
                    "total_tests": 61,
                }
            ],
        )

    def test_dependency_consumer_and_dormant_high_risk_surface_are_exact(self) -> None:
        self.assertNotIn("[features]", self.cargo)
        dependencies = {
            "anyhow",
            "hmac",
            "reqwest",
            "serde",
            "serde_json",
            "sha2",
            "thiserror",
            "tokio",
            "tokio-util",
            "tracing",
        }
        dev_dependencies = {"axum", "proptest", "serde_json", "tokio", "toml", "tower"}
        self.assertEqual(dependency_keys(self.cargo, "dependencies"), dependencies)
        self.assertEqual(
            dependency_keys(self.cargo, "dev-dependencies"), dev_dependencies
        )
        self.assertEqual(set(self.registry["direct_dependencies"]), dependencies)
        self.assertEqual(set(self.registry["dev_dependencies"]), dev_dependencies)
        self.assertIn(
            'reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }',
            self.cargo,
        )

        consumers = []
        for manifest in (DCENTOS_ROOT / "dcentrald").glob("*/Cargo.toml"):
            if manifest == CRATE_ROOT / "Cargo.toml":
                continue
            if "dcentrald-bridge" in dependency_keys(
                manifest.read_text(encoding="utf-8"), "dependencies"
            ):
                consumers.append(manifest.parent.name)
        self.assertEqual(consumers, ["dcentrald"])
        self.assertEqual(
            [(row["crate"], row["scope"]) for row in self.registry["direct_consumers"]],
            [("dcentrald", "dependency")],
        )

        daemon_source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (DCENTOS_ROOT / "dcentrald" / "dcentrald" / "src").rglob("*.rs")
        )
        self.assertEqual(daemon_source.count("dcentrald_bridge::bridge_client_task("), 1)
        self.assertEqual(daemon_source.count("dcentrald_bridge::unit_secret_from_base32("), 1)
        for forbidden in (".ota_upload(", ".ota_pull(", "dcentrald_bridge::ws_sig("):
            self.assertNotIn(forbidden, daemon_source)
        task = self.sources["task"]
        self.assertNotIn("ota_upload(", task)
        self.assertNotIn("ota_pull(", task)
        self.assertNotIn("ws_sig(", task)

        capabilities = {
            row["capability"]: row for row in self.registry["capability_surfaces"]
        }
        self.assertEqual(
            set(capabilities),
            {
                "http_discover_pair_heartbeat_telemetry",
                "ota_pull",
                "ota_upload",
                "route_discovery_subprocess",
                "websocket",
            },
        )
        for name in ("ota_pull", "ota_upload", "websocket"):
            self.assertFalse(capabilities[name]["automatic"])
            self.assertEqual(capabilities[name]["production_call_sites"], 0)

    def test_fail_closed_network_secret_thermal_ota_and_unsafe_boundaries(self) -> None:
        client = self.sources["client"]
        crypto = self.sources["crypto"]
        task = self.sources["task"]
        config = self.sources["config"]
        daemon = (
            DCENTOS_ROOT / "dcentrald" / "dcentrald" / "src" / "daemon.rs"
        ).read_text(encoding="utf-8")

        for needle in (
            "enabled: false",
            "gateway_override: None",
            "feed_thermal: default_feed_thermal()",
        ):
            self.assertIn(needle, config)
        self.assertIn("if self.config.bridge.enabled {", daemon)
        lifecycle = named_block(task, "pub async fn bridge_client_task", "async fn discover")
        self.assertLess(
            lifecycle.index("if !cfg.enabled"), lifecycle.index("read_default_gateway()")
        )
        self.assertLess(
            lifecycle.index("let secret = match"), lifecycle.index("read_default_gateway()")
        )
        self.assertIn('Command::new("ip")', task)
        self.assertIn('.args(["-4", "route", "show", "default"])', task)
        self.assertNotIn("sh -c", task)

        self.assertIn("if resp.status() == reqwest::StatusCode::NOT_FOUND", client)
        self.assertIn("return Err(BridgeError::Http { status, body });", client)
        self.assertIn("health response did not identify product dcent-pack", client)
        discovery = named_block(task, "async fn discover", "pub(crate) fn clamp_room")
        self.assertIn("health probe failed; refusing legacy telemetry fallback", discovery)
        self.assertRegex(discovery, r"(?s)Err\(e\) => \{.*?return false;")

        heartbeat = named_block(client, "pub async fn heartbeat", "pub async fn poll_telemetry")
        self.assertIn("secret: &UnitSecret", heartbeat)
        self.assertNotIn("Option<&UnitSecret>", heartbeat)
        self.assertIn('header("X-DCent-Heartbeat-Ts"', heartbeat)
        self.assertIn('header("X-DCent-Heartbeat-Sig"', heartbeat)
        self.assertIn("client.heartbeat(&req, secret).await", task)

        for needle in (
            "return Err(SecretDecodeError::InvalidChar(ch));",
            "Err(SecretDecodeError::NonCanonical(bits))",
            "base32_no_pad_rejects_padding_anywhere",
        ):
            self.assertIn(needle, crypto)

        for needle in (
            "t.temperature.present",
            't.temperature.status == "ok"',
            "t.temperature.last_sample_age_ms <= MAX_SAMPLE_AGE_MS",
            "t.temperature.external_temperature_c.is_finite()",
            "cfg.feed_thermal && feedback_enabled",
            "clamp_room_temp_c10(c)",
        ):
            self.assertIn(needle, client if needle.startswith("t.temperature") else task)

        upload = named_block(client, "pub async fn ota_upload", "pub async fn ota_pull")
        self.assertLess(upload.index("validate_ota_upload_image"), upload.index(".post("))
        pull = named_block(client, "pub async fn ota_pull", "pub fn usable_temperature")
        self.assertLess(pull.index("validate_ota_pull_inputs"), pull.index(".post("))
        for needle in (
            "MAX_OTA_UPLOAD_BYTES: usize = 4 * 1024 * 1024",
            "MAX_OTA_PULL_URL_BYTES: usize = 511",
            'strip_prefix("https://")',
            "pull URL must include a non-empty authority",
            "pull URL must not include credentials",
            "expected SHA256 must be exactly 64 lowercase hex characters",
            "caller must obtain operator authorization",
        ):
            self.assertIn(needle, client)

        all_source = "\n".join([self.lib_rs, *self.sources.values()])
        self.assertEqual(len(re.findall(r"\bunsafe\s*\{", all_source)), 1)
        self.assertIn("std::ptr::write_volatile(b, 0);", crypto)
        self.assertEqual(
            self.registry["unsafe_blocks"],
            [
                {
                    "source": "DCENT_OS_Antminer/dcentrald/dcentrald-bridge/src/crypto.rs",
                    "count": 1,
                    "purpose": self.registry["unsafe_blocks"][0]["purpose"],
                }
            ],
        )

    def test_contract_evidence_is_byte_hash_exact_and_non_authorizing(self) -> None:
        expected_paths = [
            "projects/dcent-expansion-pack/docs/DCENT_OS_BRIDGE_CLIENT.md",
            "projects/dcent-expansion-pack/docs/BRIDGE_API.md",
            "projects/dcent-expansion-pack/DCENT_OS_ESP-idf/main/bridge_api.c",
            "projects/dcent-expansion-pack/DCENT_OS_ESP-idf/main/ota_handler.c",
            "projects/dcent-expansion-pack/DCENT_OS_ESP-idf/main/pack_id.c",
        ]
        self.assertEqual(
            [row["path"] for row in self.registry["contract_evidence"]],
            expected_paths,
        )
        for row in self.registry["contract_evidence"]:
            with self.subTest(path=row["path"]):
                payload = (REPO_ROOT / row["path"]).read_bytes()
                self.assertEqual(len(payload), row["bytes"])
                self.assertEqual(hashlib.sha256(payload).hexdigest(), row["sha256"])

        firmware = (
            REPO_ROOT
            / "projects/dcent-expansion-pack/DCENT_OS_ESP-idf/main/ota_handler.c"
        ).read_text(encoding="utf-8")
        for needle in (
            "#define DCENT_OTA_MAX_BYTES (4u * 1024u * 1024u)",
            "char     url[512];",
            'strncmp(url, "https://", 8)',
            "strlen(sha_hex) != 64",
            "esp_ota_set_boot_partition(target)",
            "esp_restart();",
        ):
            self.assertIn(needle, firmware)

        self.assertEqual(self.registry["schema_version"], 1)
        self.assertEqual(self.registry["crate"], "dcentrald-bridge")
        self.assertEqual(self.registry["ledger_rows"], [])
        self.assertGreaterEqual(len(self.registry["ledger_scope_reason"]), 170)
        for row in self.registry["modules"]:
            self.assertEqual(row["ledger_rows"], [])
            self.assertGreaterEqual(len(row["authority_ceiling"]), 150)
        for row in self.registry["integration_suites"]:
            self.assertGreaterEqual(len(row["authority_ceiling"]), 120)
        for needle in (
            "physical bridge identity",
            "unit-secret custody",
            "sensor provenance",
            "operator OTA authorization",
            "WebSocket transport",
            "hardware readiness",
        ):
            self.assertIn(needle, self.registry["authority_ceiling"])

    def test_workflow_aggregate_and_campaign_own_the_complete_suite(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("cargo test --locked -p dcentrald-bridge", workflow)
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_dcentrald_bridge_surface_registry.py -q", aggregate
        )
        campaign = (
            REPO_ROOT
            / "docs"
            / "dev"
            / "2026-08-05-hardware-supremacy-campaign"
            / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("bridge-client surface convergence", campaign)


if __name__ == "__main__":
    unittest.main()
