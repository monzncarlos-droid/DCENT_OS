#!/usr/bin/env python3
"""Pin the gRPC protocol, auth, effects, tests, and authority ceiling."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
CRATE_ROOT = DCENTOS_ROOT / "dcentrald" / "dcentrald-api-grpc"
REGISTRY_PATH = (
    DCENTOS_ROOT
    / "docs"
    / "architecture"
    / "dcentrald_api_grpc_surface_registry.json"
)


EXPECTED_ROOT_TYPES = {
    "BearerAuthInterceptor",
    "FanSvc",
    "GrpcFanReading",
    "GrpcFanSnapshot",
    "GrpcLocate",
    "GrpcMinerStatus",
    "GrpcPoolEntry",
    "GrpcRuntimeSnapshot",
    "GrpcServeError",
    "GrpcSetFanMode",
    "GrpcSetPools",
    "GrpcSetTunerMode",
    "GrpcTokenError",
    "GrpcTunerSnapshot",
    "GrpcWriteDelegate",
    "GrpcWriteOutcome",
    "LocateSvc",
    "MinerSvc",
    "PoolSvc",
    "TunerSvc",
}
EXPECTED_ROOT_FUNCTIONS = {
    "install_runtime_snapshot_rx",
    "install_write_delegate",
    "runtime_snapshot",
    "serve",
}
EXPECTED_ROOT_METHODS = {"ack", "reject"}
EXPECTED_CONSTRAINT_FUNCTIONS = {
    "bm1362_freq_band",
    "build_bm1362_constraints",
    "build_constraints",
    "build_constraints_for_chip",
}
EXPECTED_CONSTRAINT_CONSTANTS = {
    "DEFAULT_BM1362_FREQ_MAX_MHZ",
    "DEFAULT_BM1362_FREQ_MIN_MHZ",
    "DEFAULT_BM1362_FREQ_STEP_MHZ",
    "HOME_FAN_PWM_MAX",
    "NON_HOME_FAN_PWM_MAX",
    "SOURCE_FREQ_ONLY",
    "VOLTAGE_MAX_MV_AM2",
    "VOLTAGE_MIN_MV",
}


def named_brace_block(source: str, declaration: str) -> str:
    start = source.index(declaration)
    brace = source.index("{", start)
    depth = 0
    for offset in range(brace, len(source)):
        char = source[offset]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : offset]
    raise AssertionError(f"unclosed block: {declaration}")


def rust_public_fields(source: str, name: str) -> set[str]:
    block = named_brace_block(source, f"pub struct {name}")
    return set(re.findall(r"^\s+pub ([A-Za-z0-9_]+):", block, re.M))


def rust_enum_variants(source: str, name: str) -> set[str]:
    block = named_brace_block(source, f"pub enum {name}")
    return set(
        re.findall(r"^\s+([A-Z][A-Za-z0-9_]+)(?:\s*\{|\s*\(|,)", block, re.M)
    )


def proto_blocks(source: str, kind: str) -> dict[str, str]:
    return {
        match.group(1): match.group(2)
        for match in re.finditer(
            rf"^{kind} ([A-Za-z0-9_]+)\s*\{{(.*?)^\}}",
            source,
            re.M | re.S,
        )
    }


def proto_message_fields(block: str) -> list[str]:
    fields = []
    for match in re.finditer(
        r"^\s+(repeated\s+)?([A-Za-z0-9_.]+)\s+([A-Za-z0-9_]+)\s*=\s*([0-9]+)",
        block,
        re.M,
    ):
        repeated, field_type, name, number = match.groups()
        field_type = f"repeated {field_type}" if repeated else field_type
        fields.append(f"{number}:{field_type}:{name}")
    return fields


def proto_enum_values(block: str) -> list[str]:
    return [
        f"{number}:{name}"
        for name, number in re.findall(
            r"^\s+([A-Z][A-Z0-9_]+)\s*=\s*([0-9]+)", block, re.M
        )
    ]


def proto_rpcs(block: str) -> list[str]:
    return [
        f"{name}({request})->{response}"
        for name, request, response in re.findall(
            r"^\s+rpc\s+([A-Za-z0-9_]+)\(([A-Za-z0-9_]+)\)\s+returns\s+\(([A-Za-z0-9_]+)\)",
            block,
            re.M,
        )
    ]


def rust_tests(source: str) -> set[str]:
    return set(
        re.findall(
            r"#\[(?:tokio::)?test\]\s+(?:async )?fn ([A-Za-z0-9_]+)\(",
            source,
        )
    )


def dependency_keys(cargo: str, section: str) -> set[str]:
    match = re.search(
        rf"^\[{re.escape(section)}\]\s*\n(.*?)(?=^\[|\Z)",
        cargo,
        re.M | re.S,
    )
    if match is None:
        return set()
    return set(
        re.findall(r"^([A-Za-z0-9_-]+)\s*=", match.group(1), re.M)
    )


class DcentraldApiGrpcSurfaceRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.lib = (CRATE_ROOT / "src" / "lib.rs").read_text(encoding="utf-8")
        cls.constraints = (CRATE_ROOT / "src" / "constraints.rs").read_text(
            encoding="utf-8"
        )
        cls.proto = (CRATE_ROOT / "proto" / "dcent_v1.proto").read_text(
            encoding="utf-8"
        )
        cls.build = (CRATE_ROOT / "build.rs").read_text(encoding="utf-8")
        cls.cargo_text = (CRATE_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        cls.modules = {row["module"]: row for row in cls.registry["modules"]}

    def test_registry_identity_paths_and_ledger_scope_are_exact(self) -> None:
        self.assertEqual(self.registry["schema_version"], 1)
        self.assertEqual(self.registry["generated"], "2026-08-19")
        self.assertEqual(self.registry["crate"], "dcentrald-api-grpc")
        self.assertEqual(
            self.registry["crate_root"],
            "DCENT_OS_Antminer/dcentrald/dcentrald-api-grpc/src/lib.rs",
        )
        self.assertEqual(
            self.registry["proto_source"],
            "DCENT_OS_Antminer/dcentrald/dcentrald-api-grpc/proto/dcent_v1.proto",
        )
        self.assertEqual(set(self.modules), {"crate_root", "constraints"})
        self.assertEqual(self.registry["ledger_rows"], [])
        self.assertGreaterEqual(len(self.registry["ledger_scope_reason"]), 180)
        for row in self.registry["modules"]:
            self.assertEqual(row["ledger_rows"], [])
            self.assertTrue((REPO_ROOT / row["source"]).is_file())
            self.assertGreaterEqual(len(row["authority_ceiling"]), 230)

    def test_handwritten_public_surface_and_shapes_are_exact(self) -> None:
        actual_types = set(
            re.findall(
                r"^pub (?:struct|enum|trait|type) ([A-Za-z0-9_]+)", self.lib, re.M
            )
        )
        actual_functions = set(
            re.findall(r"^pub (?:async )?fn ([A-Za-z0-9_]+)", self.lib, re.M)
        )
        actual_methods = set(
            re.findall(r"^    pub (?:async )?fn ([A-Za-z0-9_]+)", self.lib, re.M)
        )
        self.assertEqual(actual_types, EXPECTED_ROOT_TYPES)
        self.assertEqual(actual_functions, EXPECTED_ROOT_FUNCTIONS)
        self.assertEqual(actual_methods, EXPECTED_ROOT_METHODS)
        root = self.modules["crate_root"]
        self.assertEqual(set(root["public_types"]), EXPECTED_ROOT_TYPES)
        self.assertEqual(set(root["public_functions"]), EXPECTED_ROOT_FUNCTIONS)
        self.assertEqual(set(root["public_methods"]), EXPECTED_ROOT_METHODS)
        self.assertEqual(root["public_constants"], [])

        constraint_functions = set(
            re.findall(
                r"^pub (?:async )?fn ([A-Za-z0-9_]+)", self.constraints, re.M
            )
        )
        constraint_constants = set(
            re.findall(r"^pub const ([A-Za-z0-9_]+)", self.constraints, re.M)
        )
        self.assertEqual(constraint_functions, EXPECTED_CONSTRAINT_FUNCTIONS)
        self.assertEqual(constraint_constants, EXPECTED_CONSTRAINT_CONSTANTS)
        constraint_row = self.modules["constraints"]
        self.assertEqual(
            set(constraint_row["public_functions"]), EXPECTED_CONSTRAINT_FUNCTIONS
        )
        self.assertEqual(
            set(constraint_row["public_constants"]), EXPECTED_CONSTRAINT_CONSTANTS
        )
        self.assertEqual(constraint_row["public_types"], [])
        self.assertIn("pub mod constraints;", self.lib)
        self.assertIn("pub mod dcent {", self.lib)

        shapes = self.registry["root_public_shapes"]
        self.assertEqual(
            set(shapes["public_fields"]),
            {
                "FanSvc",
                "GrpcFanReading",
                "GrpcFanSnapshot",
                "GrpcLocate",
                "GrpcMinerStatus",
                "GrpcPoolEntry",
                "GrpcRuntimeSnapshot",
                "GrpcSetFanMode",
                "GrpcSetPools",
                "GrpcSetTunerMode",
                "GrpcTunerSnapshot",
                "GrpcWriteOutcome",
                "TunerSvc",
            },
        )
        for name, expected in shapes["public_fields"].items():
            self.assertEqual(rust_public_fields(self.lib, name), set(expected))
        self.assertEqual(
            rust_enum_variants(self.lib, "GrpcServeError"),
            set(shapes["enum_variants"]["GrpcServeError"]),
        )
        trait = named_brace_block(self.lib, "pub trait GrpcWriteDelegate")
        actual_trait_methods = set(
            re.findall(r"^\s+async fn ([A-Za-z0-9_]+)\(", trait, re.M)
        )
        self.assertEqual(
            actual_trait_methods,
            set(shapes["trait_methods"]["GrpcWriteDelegate"]),
        )

    def test_proto_message_enum_service_and_numbering_contract_is_exact(self) -> None:
        package = re.search(r"^package ([A-Za-z0-9_.]+);", self.proto, re.M)
        self.assertIsNotNone(package)
        self.assertEqual(package.group(1), self.registry["protocol"]["package"])
        message_blocks = proto_blocks(self.proto, "message")
        enum_blocks = proto_blocks(self.proto, "enum")
        service_blocks = proto_blocks(self.proto, "service")
        actual_messages = {
            name: proto_message_fields(block) for name, block in message_blocks.items()
        }
        actual_enums = {
            name: proto_enum_values(block) for name, block in enum_blocks.items()
        }
        actual_services = {
            name: proto_rpcs(block) for name, block in service_blocks.items()
        }
        protocol = self.registry["protocol"]
        self.assertEqual(actual_messages, protocol["messages"])
        self.assertEqual(actual_enums, protocol["enums"])
        self.assertEqual(actual_services, protocol["services"])
        self.assertEqual(len(actual_messages), protocol["message_count"])
        self.assertEqual(
            sum(map(len, actual_messages.values())), protocol["field_count"]
        )
        self.assertEqual(len(actual_enums), protocol["enum_count"])
        self.assertEqual(len(actual_services), protocol["service_count"])
        self.assertEqual(sum(map(len, actual_services.values())), protocol["rpc_count"])
        self.assertEqual(
            (protocol["message_count"], protocol["field_count"], protocol["service_count"], protocol["rpc_count"]),
            (20, 57, 5, 10),
        )

    def test_rpc_effect_inventory_matches_every_service_method(self) -> None:
        effects = self.registry["rpc_effects"]
        actual_pairs = {
            (service, rpc.split("(", 1)[0])
            for service, rpcs in self.registry["protocol"]["services"].items()
            for rpc in rpcs
        }
        effect_pairs = {(row["service"], row["rpc"]) for row in effects}
        self.assertEqual(effect_pairs, actual_pairs)
        self.assertEqual(
            {row["effect"] for row in effects}, {"read", "pure", "mutation"}
        )
        self.assertEqual(
            sum(row["effect"] == "mutation" for row in effects), 5
        )
        self.assertEqual(sum(row["effect"] == "read" for row in effects), 4)
        self.assertEqual(sum(row["effect"] == "pure" for row in effects), 1)
        for row in effects:
            self.assertGreaterEqual(len(row["authority_ceiling"]), 90)
        for needle in (
            "delegate.reboot().await?",
            ".set_tuner_mode(GrpcSetTunerMode",
            "delegate.set_pools(GrpcSetPools { pools }).await?",
            ".set_fan_mode(GrpcSetFanMode",
            ".locate_device(GrpcLocate",
        ):
            self.assertIn(needle, self.lib)
        self.assertIn("password: String::new()", self.lib)
        self.assertIn("Status::unavailable(SNAPSHOT_UNAVAILABLE_MSG)", self.lib)
        self.assertIn("Status::unimplemented(UNIMPLEMENTED_MSG)", self.lib)

    def test_release_token_and_listener_admission_fail_closed(self) -> None:
        auth = self.registry["authentication_and_startup"]
        self.assertFalse(auth["default_enabled"])
        self.assertEqual(auth["default_bind"], "127.0.0.1")
        self.assertEqual(auth["default_port"], 50051)
        self.assertTrue(auth["default_reflection"])
        self.assertEqual(
            auth["token_files"],
            ["/run/dcentos/grpc_token", "/data/dcent/grpc_token"],
        )
        for needle in (
            "libc::O_CLOEXEC | libc::O_NOFOLLOW",
            "if !metadata.is_file()",
            "metadata.uid()",
            "0o400 | 0o600",
            "GRPC_TOKEN_MIN_LEN: usize = 32",
            "GRPC_TOKEN_MAX_LEN: usize = 1024",
            "byte.is_ascii_graphic()",
            "let mut diff = a.len() ^ b.len();",
            "presented_authorization.and_then(|h| h.strip_prefix(\"Bearer \"))",
            "preflight_grpc_startup(addr)?;",
            "addr.ip().is_loopback()",
        ):
            self.assertIn(needle, self.lib)
        self.assertNotIn(".map(|s| s.trim())", self.lib)
        serve = named_brace_block(self.lib, "pub async fn serve")
        self.assertLess(serve.index("preflight_grpc_startup(addr)?"), serve.index("Server::builder()"))
        self.assertIn("if reflection_enabled", serve)
        self.assertNotIn(".expect(", serve)
        self.assertIn("#![forbid(unsafe_code)]", self.lib)
        self.assertNotRegex(self.lib, r"\bunsafe\s*\{")
        self.assertEqual(self.registry["unsafe_blocks"], 0)
        self.assertFalse(
            self.registry["build_contract"]["panic_on_reflection_error"]
        )

    def test_dependencies_build_and_daemon_consumer_are_exact(self) -> None:
        self.assertNotIn("[features]", self.cargo_text)
        self.assertEqual(
            dependency_keys(self.cargo_text, "dependencies"),
            set(self.registry["direct_dependencies"]),
        )
        self.assertEqual(
            dependency_keys(self.cargo_text, "target.'cfg(unix)'.dependencies"),
            set(self.registry["unix_dependencies"]),
        )
        self.assertEqual(
            dependency_keys(self.cargo_text, "build-dependencies"),
            set(self.registry["build_dependencies"]),
        )
        self.assertEqual(
            dependency_keys(self.cargo_text, "dev-dependencies"),
            set(self.registry["dev_dependencies"]),
        )
        for needle in (
            "protoc_bin_vendored::protoc_bin_path()?",
            ".build_server(true)",
            ".build_client(false)",
            'out_dir.join("dcent_v1_descriptor.bin")',
            'compile_protos(&["proto/dcent_v1.proto"], &["proto"])?',
        ):
            self.assertIn(needle, self.build)

        consumers = []
        for manifest in (DCENTOS_ROOT / "dcentrald").glob("*/Cargo.toml"):
            if manifest == CRATE_ROOT / "Cargo.toml":
                continue
            if re.search(
                r"^dcentrald-api-grpc\s*=", manifest.read_text(encoding="utf-8"), re.M
            ):
                consumers.append(manifest.parent.name)
        self.assertEqual(consumers, ["dcentrald"])
        self.assertEqual(
            self.registry["direct_consumers"][0]["production_calls"],
            ["install_runtime_snapshot_rx", "install_write_delegate", "serve"],
        )
        daemon = (DCENTOS_ROOT / "dcentrald" / "dcentrald" / "src" / "daemon.rs").read_text(
            encoding="utf-8"
        )
        main = (DCENTOS_ROOT / "dcentrald" / "dcentrald" / "src" / "main.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("dcentrald_api_grpc::install_runtime_snapshot_rx", daemon)
        self.assertIn("dcentrald_api_grpc::install_write_delegate", daemon)
        self.assertIn("let grpc_reflection_enabled = config.api.grpc.reflection;", main)
        call = re.search(
            r"dcentrald_api_grpc::serve\(\s*addr,\s*home_mode,\s*grpc_chip_family,\s*grpc_reflection_enabled,\s*\)",
            main,
        )
        self.assertIsNotNone(call)

    def test_config_defaults_and_no_stale_scaffold_claims(self) -> None:
        config = (DCENTOS_ROOT / "dcentrald" / "dcentrald" / "src" / "config.rs").read_text(
            encoding="utf-8"
        )
        default_block = named_brace_block(config, "impl Default for GrpcApiConfig")
        for needle in (
            "enabled: false",
            "port: default_grpc_port()",
            "bind: default_grpc_bind()",
            "reflection: true",
        ):
            self.assertIn(needle, default_block)
        self.assertIn('fn default_grpc_bind() -> String {\n    "127.0.0.1".to_string()', config)
        self.assertIn("fn default_grpc_port() -> u16 {\n    50051", config)
        stale = re.compile(
            r"scaffold|one real|most RPCs|most handlers|reflection is always|no security cost|daemon provisions",
            re.I,
        )
        for path, source in (
            ("Cargo.toml", self.cargo_text),
            ("build.rs", self.build),
            ("src/lib.rs", self.lib),
            ("src/constraints.rs", self.constraints),
            ("proto/dcent_v1.proto", self.proto),
        ):
            with self.subTest(path=path):
                self.assertIsNone(stale.search(source))

    def test_all_tests_and_default_profile_are_exact(self) -> None:
        actual_root = rust_tests(self.lib)
        actual_constraints = rust_tests(self.constraints)
        expected = self.registry["unit_tests"]
        self.assertEqual(actual_root, set(expected["crate_root"]))
        self.assertEqual(actual_constraints, set(expected["constraints"]))
        self.assertEqual((len(actual_root), len(actual_constraints)), (17, 14))
        self.assertEqual(self.modules["crate_root"]["tests"], 17)
        self.assertEqual(self.modules["constraints"]["tests"], 14)
        self.assertEqual(self.registry["total_tests"], 31)
        self.assertEqual(
            self.registry["compile_profiles"],
            [
                {
                    "profile": "default",
                    "features": [],
                    "public_modules": 2,
                    "root_public_types": 20,
                    "root_public_functions": 4,
                    "proto_messages": 20,
                    "proto_fields": 57,
                    "proto_services": 5,
                    "proto_rpcs": 10,
                    "tests": 31,
                }
            ],
        )

    def test_authority_ceiling_capabilities_and_external_ce302_are_truthful(self) -> None:
        self.assertEqual(
            {row["capability"] for row in self.registry["capability_surfaces"]},
            {
                "delegate_mutations",
                "fixed_token_file_reads",
                "reflection",
                "snapshot_reads",
                "tcp_listener",
            },
        )
        self.assertEqual(len(self.registry["rpc_effects"]), 10)
        self.assertEqual(len(self.registry["safety_invariants"]), 12)
        self.assertEqual(len(self.registry["known_external_blockers"]), 2)
        for needle in (
            "authenticated operator",
            "fresh telemetry",
            "physical miner identity",
            "safe actuator custody",
            "accepted share",
            "hardware readiness",
        ):
            self.assertIn(needle, self.registry["authority_ceiling"])
        task_cards = (
            REPO_ROOT
            / "docs"
            / "dev"
            / "2026-07-05-capability-extraction"
            / "TASK_CARDS.md"
        ).read_text(encoding="utf-8")
        ce302 = task_cards.split("## CE-302:", 1)[1].split("\n## CE-303:", 1)[0]
        self.assertIn("fail clearly", ce302)
        self.assertIn("release-image no-token failure", ce302)
        self.assertIn("token file permissions", ce302)
        self.assertFalse(self.registry["authentication_and_startup"]["token_writer_in_crate"])

    def test_workflow_aggregate_and_campaign_own_the_complete_suite(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("cargo test --locked -p dcentrald-api-grpc", workflow)
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_dcentrald_api_grpc_surface_registry.py -q", aggregate
        )
        campaign = (
            REPO_ROOT
            / "docs"
            / "dev"
            / "2026-08-05-hardware-supremacy-campaign"
            / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("gRPC API surface convergence", campaign)


if __name__ == "__main__":
    unittest.main()
