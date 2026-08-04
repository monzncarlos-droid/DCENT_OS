#!/usr/bin/env python3
"""Unit tests for check_cross_compile_matrix_honesty (real shipped gate)."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check_cross_compile_matrix_honesty.py"
REPO_WORKFLOW = (
    Path(__file__).resolve().parents[3]
    / ".github"
    / "workflows"
    / "cross-compile-matrix.yml"
)


def _load():
    spec = importlib.util.spec_from_file_location(
        "check_cross_compile_matrix_honesty", SCRIPT
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _minimal_honest_workflow() -> str:
    return """\
name: DCENT_OS Cross-Compile Matrix

# HONEST EVIDENCE BOUNDARY:
# This workflow's per-target cells run `cargo check --workspace`. That
# proves target configuration + type checking (cfg/type-check). It does
# NOT prove target-crate LLVM object codegen, linking, or release builds
# for every matrix cell.
# workspace-test-compile-gate: generic armv7-musl only — test-profile link evidence.
# armv7-release-object-smoke: release-object smoke on generic armv7-musl only
# with distinct target-release-smoke-armv7 (not full matrix release builds).
# aarch64-release-object-smoke: release-object smoke on generic aarch64-musl only
# with distinct target-release-smoke-aarch64.

jobs:
  cross-check:
    name: cargo check cfg/type-check (${{ matrix.cell.name }})
    runs-on: ubuntu-24.04
    steps:
      - name: cargo check --workspace (cfg/type-check)
        run: |
          cargo +1.90.0 check --workspace --target armv7-unknown-linux-musleabihf --locked

  workspace-test-compile-gate:
    name: workspace test compile-gate (cargo test --no-run, generic armv7-musl only)
    runs-on: ubuntu-24.04
    steps:
      - name: Run canonical workspace test compile-gate
        run: bash scripts/run_dcentrald_tests.sh --native

  armv7-release-object-smoke:
    name: release-object smoke (cargo build --release, generic armv7-musl only)
    runs-on: ubuntu-24.04
    env:
      CARGO_TARGET_DIR: target-release-smoke-armv7
    steps:
      - name: cargo build --release smoke
        run: |
          cargo +1.90.0 build --release --target armv7-unknown-linux-musleabihf \
            -p dcentos-init -p dcentrald-common -p dcentrald-api-types

  aarch64-release-object-smoke:
    name: release-object smoke (cargo build --release, generic aarch64-musl only)
    runs-on: ubuntu-24.04
    env:
      CARGO_TARGET_DIR: target-release-smoke-aarch64
    steps:
      - name: cargo build --release smoke
        run: |
          cargo +1.90.0 build --release --target aarch64-unknown-linux-musl \
            -p dcentos-init -p dcentrald-common -p dcentrald-api-types
"""


class CrossCompileMatrixHonestyTests(unittest.TestCase):
    def test_repo_workflow_passes_shipped_gate(self):
        """Drive the real default path against the checked-in workflow."""
        mod = _load()
        self.assertTrue(REPO_WORKFLOW.is_file(), f"missing {REPO_WORKFLOW}")
        rc = mod.main([str(REPO_WORKFLOW)])
        self.assertEqual(rc, 0, "repo cross-compile-matrix.yml must stay honest")

    def test_default_main_uses_repo_workflow(self):
        mod = _load()
        # No argv → DEFAULT_WORKFLOW (the real file under .github/workflows).
        rc = mod.main([])
        self.assertEqual(rc, 0)

    def test_minimal_honest_fixture_passes(self):
        mod = _load()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "wf.yml"
            path.write_text(_minimal_honest_workflow(), encoding="utf-8")
            failures = mod.check_workflow(path.read_text(encoding="utf-8"))
            self.assertEqual(failures, [], failures)

    def test_codegen_assurance_overclaim_fails(self):
        mod = _load()
        text = _minimal_honest_workflow().replace(
            "proves target configuration + type checking (cfg/type-check).",
            "provides codegen assurance for Cortex-A8 and AArch64.",
        )
        failures = mod.check_workflow(text)
        self.assertTrue(
            any("overclaim" in f or "codegen" in f.lower() for f in failures),
            failures,
        )

    def test_legacy_generic_armv7_codegen_claim_fails(self):
        mod = _load()
        text = _minimal_honest_workflow() + "\n# Generic ARMv7 codegen.\n"
        # Put the overclaim inside the cross-check job body.
        text = text.replace(
            "cargo +1.90.0 check --workspace",
            "# Generic ARMv7 codegen.\ncargo +1.90.0 check --workspace",
        )
        failures = mod.check_workflow(text)
        self.assertTrue(
            any("Generic ARMv7 codegen" in f or "overclaim" in f for f in failures),
            failures,
        )

    def test_cargo_build_in_cross_check_fails(self):
        mod = _load()
        text = _minimal_honest_workflow().replace(
            "cargo +1.90.0 check --workspace --target armv7-unknown-linux-musleabihf --locked",
            "cargo +1.90.0 build --release --workspace --target armv7-unknown-linux-musleabihf --locked",
        )
        failures = mod.check_workflow(text)
        self.assertTrue(
            any("cargo build" in f or "must not run" in f for f in failures),
            failures,
        )

    def test_missing_cfg_type_check_job_name_fails(self):
        mod = _load()
        text = _minimal_honest_workflow().replace(
            "name: cargo check cfg/type-check (${{ matrix.cell.name }})",
            "name: cargo check --workspace (${{ matrix.cell.name }})",
        )
        failures = mod.check_workflow(text)
        self.assertTrue(
            any("cfg/type-check" in f for f in failures),
            failures,
        )

    def test_missing_generic_armv7_only_job_name_fails(self):
        mod = _load()
        text = _minimal_honest_workflow().replace(
            "generic armv7-musl only",
            "armv7-musl",
        )
        failures = mod.check_workflow(text)
        self.assertTrue(
            any("generic armv7-musl only" in f for f in failures),
            failures,
        )

    def test_missing_required_phrase_fails(self):
        mod = _load()
        text = _minimal_honest_workflow().replace(
            "LLVM object codegen",
            "everything about the target",
        )
        failures = mod.check_workflow(text)
        self.assertTrue(
            any("missing required honesty phrase" in f for f in failures),
            failures,
        )

    def test_missing_release_smoke_job_fails(self):
        mod = _load()
        text = _minimal_honest_workflow()
        # Drop both release-smoke job blocks.
        text = text.split("  armv7-release-object-smoke:")[0]
        failures = mod.check_workflow(text)
        self.assertTrue(
            any("armv7-release-object-smoke" in f for f in failures),
            failures,
        )

    def test_missing_aarch64_release_smoke_job_fails(self):
        mod = _load()
        text = _minimal_honest_workflow()
        text = text.split("  aarch64-release-object-smoke:")[0]
        failures = mod.check_workflow(text)
        self.assertTrue(
            any("aarch64-release-object-smoke" in f for f in failures),
            failures,
        )

    def test_release_smoke_without_distinct_target_dir_fails(self):
        mod = _load()
        text = _minimal_honest_workflow().replace(
            "CARGO_TARGET_DIR: target-release-smoke-armv7",
            "CARGO_TERM_COLOR: always",
        ).replace(
            "target-release-smoke-armv7",
            "shared-target",
        )
        failures = mod.check_workflow(text)
        self.assertTrue(
            any("CARGO_TARGET_DIR" in f or "target-release-smoke" in f for f in failures),
            failures,
        )

    def test_release_smoke_shared_target_dir_with_cargo_target_dir_fails(self):
        """G8 critic: bare CARGO_TARGET_DIR without exact token must FAIL.

        Previously the gate accepted any CARGO_TARGET_DIR presence even when
        target-release-smoke-* was missing (fail-open on cache isolation).
        """
        mod = _load()
        text = _minimal_honest_workflow().replace(
            "CARGO_TARGET_DIR: target-release-smoke-armv7",
            "CARGO_TARGET_DIR: shared-target",
        )
        # Drop remaining mentions of the exact token in armv7 smoke comments.
        text = text.replace(
            "with distinct target-release-smoke-armv7 (not full matrix release builds).",
            "with a shared cargo target dir.",
        )
        failures = mod.check_workflow(text)
        self.assertTrue(
            any(
                "target-release-smoke-armv7" in f
                or "distinct CARGO_TARGET_DIR token" in f
                for f in failures
            ),
            failures,
        )

    def test_release_smoke_workspace_build_fails(self):
        """G8 critic: cargo build --release --workspace in smoke must FAIL."""
        mod = _load()
        # Inject --workspace into the armv7 smoke cargo build line only.
        text = _minimal_honest_workflow().replace(
            "cargo +1.90.0 build --release --target armv7-unknown-linux-musleabihf",
            "cargo +1.90.0 build --release --workspace "
            "--target armv7-unknown-linux-musleabihf",
            1,  # first (armv7) smoke only
        )
        self.assertIn(
            "build --release --workspace",
            text,
            "fixture injection failed",
        )
        failures = mod.check_workflow(text)
        self.assertTrue(
            any("--workspace" in f or "must not run cargo build" in f for f in failures),
            failures,
        )

    def test_release_smoke_cortex_target_cpu_fails(self):
        """G8 critic: Cortex-tuned RUSTFLAGS on generic-only smoke must FAIL."""
        mod = _load()
        text = _minimal_honest_workflow().replace(
            "  armv7-release-object-smoke:\n"
            "    name: release-object smoke (cargo build --release, generic armv7-musl only)\n"
            "    runs-on: ubuntu-24.04\n"
            "    env:\n"
            "      CARGO_TARGET_DIR: target-release-smoke-armv7\n",
            "  armv7-release-object-smoke:\n"
            "    name: release-object smoke (cargo build --release, generic armv7-musl only)\n"
            "    runs-on: ubuntu-24.04\n"
            "    env:\n"
            "      CARGO_TARGET_DIR: target-release-smoke-armv7\n"
            "      RUSTFLAGS: -C target-cpu=cortex-a8\n",
        )
        failures = mod.check_workflow(text)
        self.assertTrue(
            any("Cortex-tuned" in f or "cortex-a8" in f.lower() for f in failures),
            failures,
        )

    def test_release_smoke_must_build_dcentos_init(self):
        mod = _load()
        text = _minimal_honest_workflow().replace(
            "-p dcentos-init",
            "-p some-other-crate",
        )
        failures = mod.check_workflow(text)
        self.assertTrue(
            any("dcentos-init" in f for f in failures),
            failures,
        )


if __name__ == "__main__":
    unittest.main()
