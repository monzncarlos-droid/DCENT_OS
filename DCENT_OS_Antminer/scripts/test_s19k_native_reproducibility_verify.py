#!/usr/bin/env python3
"""Adversarial tests for retained two-capsule S19k build evidence."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import build_input_snapshot
import release_invocation
import release_result_stage
import s19k_native_build_verify as native_build
import s19k_native_reproducibility_verify as reproducibility
import source_snapshot
from test_s19k_native_build_verify import CapsuleFixture, aarch64_elf


def cjson(value: object) -> bytes:
    return native_build.canonical_json(value)


def context_from_lines(
    original: dict[str, object],
    lines: list[str],
    *,
    entries: dict[str, str] | None = None,
) -> dict[str, object]:
    data = ("\n".join(lines) + "\n").encode("utf-8")
    result: dict[str, object] = {
        "path": original["path"],
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "lines": lines,
    }
    if entries is not None:
        result["entries"] = dict(sorted(entries.items()))
    return result


def set_builder_image(
    capsule: dict[str, object], image_id: str
) -> dict[str, object]:
    result = copy.deepcopy(capsule)
    builder = result["builder"]
    builder["image_id"] = image_id
    compile_context = result["compile_environment"]
    entries = dict(compile_context["entries"])
    entries["DCENT_BUILDER_IMAGE_ID"] = image_id
    compile_lines = [f"{key}={value}" for key, value in sorted(entries.items())]
    result["compile_environment"] = context_from_lines(
        compile_context, compile_lines, entries=entries
    )
    toolchain = result["toolchain_context"]
    lines = [
        f"builder_image_id={image_id}"
        if line.startswith("builder_image_id=")
        else line
        for line in toolchain["lines"]
    ]
    result["toolchain_context"] = context_from_lines(toolchain, lines)
    return result


def manifest_for(
    artifact: bytes, capsule: bytes, metadata: bytes
) -> dict[str, object]:
    files = [
        {
            "mode": "0755",
            "path": reproducibility.RESULT_ARTIFACT_PATH,
            "sha256": hashlib.sha256(artifact).hexdigest(),
            "size": len(artifact),
        },
        {
            "mode": "0644",
            "path": reproducibility.RESULT_CAPSULE_RECEIPT_PATH,
            "sha256": hashlib.sha256(capsule).hexdigest(),
            "size": len(capsule),
        },
        {
            "mode": "0644",
            "path": reproducibility.RESULT_METADATA_PATH,
            "sha256": hashlib.sha256(metadata).hexdigest(),
            "size": len(metadata),
        },
    ]
    files.sort(key=lambda item: item["path"].encode("utf-8"))
    body = {"directories": [], "files": files}
    return {
        **body,
        "manifest_sha256": hashlib.sha256(
            release_result_stage.canonical_bytes(body)
        ).hexdigest(),
    }


def projection_for(
    invocation: dict[str, object],
    *,
    label: str,
    allocation_nonce: str,
    artifact: bytes,
    capsule: bytes,
    metadata: bytes,
) -> dict[str, object]:
    invocation_digest = hashlib.sha256(
        release_invocation.canonical_bytes(invocation)
    ).hexdigest()
    stage_id = hashlib.sha256(
        f"stage:{label}:{allocation_nonce}".encode("ascii")
    ).hexdigest()
    descriptor_sha256 = hashlib.sha256(
        f"sealed:{label}:{stage_id}".encode("ascii")
    ).hexdigest()
    return {
        "schema": release_result_stage.AUDIT_PROJECTION_SCHEMA,
        "claim": (
            "retained-result-manifest-consistency-not-live-authority-"
            "build-causality-or-reproducibility-proof"
        ),
        "source_descriptor_sha256": descriptor_sha256,
        "invocation": {
            "descriptor_sha256": invocation_digest,
            "invocation_id": invocation["invocation_id"],
            "result_name": invocation["resources"]["result_name"],
        },
        "allocation_nonce": allocation_nonce,
        "result_root": release_result_stage.RESULT_ROOT_NAME,
        "manifest": manifest_for(artifact, capsule, metadata),
        "scope": {
            "claim": release_result_stage.CLAIM,
            "does_not_claim": list(release_result_stage.NON_CLAIMS),
        },
        "stage_id": stage_id,
        "state": "sealed",
    }


class ReproducibilityFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.capsule_fixture = CapsuleFixture(root / "capsule")
        self.phase = root / "phase"
        self.phase.mkdir()
        source_created = source_snapshot.create_snapshot(
            self.capsule_fixture.repo,
            self.capsule_fixture.commit,
            stage_parent=root,
        )
        source_bytes = source_created.snapshot.read_bytes()
        (self.phase / reproducibility.SOURCE_DESCRIPTOR_NAME).write_bytes(
            source_bytes
        )
        source_verification = source_snapshot.verify_descriptor_against_git(
            self.capsule_fixture.repo,
            self.capsule_fixture.commit,
            self.phase / reproducibility.SOURCE_DESCRIPTOR_NAME,
        )

        manifest_path = self.capsule_fixture.repo.joinpath(
            "projects", "dcentos", "scripts", "build_inputs.manifest"
        )
        input_created = build_input_snapshot.create_snapshot(
            self.capsule_fixture.repo,
            manifest_path,
            "cargo-workspace",
            stage_parent=root,
        )
        input_bytes = input_created.snapshot.read_bytes()
        (self.phase / reproducibility.BUILD_INPUT_DESCRIPTOR_NAME).write_bytes(
            input_bytes
        )
        input_descriptor = json.loads(input_bytes)

        self.base_capsule = copy.deepcopy(
            self.capsule_fixture.capsule_receipt
        )
        lineage = self.base_capsule["release_capsule"]
        lineage["source_snapshot_descriptor_sha256"] = source_verification[
            "descriptor_sha256"
        ]
        lineage["source_snapshot_id"] = source_verification["snapshot_id"]
        self.base_capsule["build_inputs"]["evidence"] = (
            build_input_snapshot.snapshot_evidence(input_descriptor)
        )
        self.artifact = self.capsule_fixture.artifact.read_bytes()
        self.metadata = self.capsule_fixture.metadata_data
        self.invocations = {
            "build-a": release_invocation._descriptor("s19k-a", "4" * 64),
            "build-b": release_invocation._descriptor("s19k-b", "8" * 64),
        }
        self.allocations = {"build-a": "a" * 64, "build-b": "b" * 64}
        self.capsules: dict[str, dict[str, object]] = {}
        for label in reproducibility.RUN_LABELS:
            self.write_run(label)

    def write_run(
        self,
        label: str,
        *,
        capsule: dict[str, object] | None = None,
        invocation: dict[str, object] | None = None,
        artifact: bytes | None = None,
        metadata: bytes | None = None,
        allocation_nonce: str | None = None,
    ) -> None:
        invocation = copy.deepcopy(invocation or self.invocations[label])
        artifact = self.artifact if artifact is None else artifact
        metadata = self.metadata if metadata is None else metadata
        capsule = copy.deepcopy(capsule or self.base_capsule)
        capsule["binary"]["sha256"] = hashlib.sha256(artifact).hexdigest()
        capsule["binary"]["size"] = len(artifact)
        lineage = capsule["release_capsule"]
        invocation_bytes = release_invocation.canonical_bytes(invocation)
        lineage["release_invocation_id"] = invocation["invocation_id"]
        lineage["release_invocation_descriptor_sha256"] = hashlib.sha256(
            invocation_bytes
        ).hexdigest()
        capsule_bytes = cjson(capsule)
        artifact_path = self.phase / (
            label + reproducibility.ARTIFACT_SUFFIX
        )
        capsule_path = self.phase / (
            label + reproducibility.CAPSULE_RECEIPT_SUFFIX
        )
        metadata_path = self.phase / (
            label + reproducibility.METADATA_SUFFIX
        )
        native_path = self.phase / (
            label + reproducibility.NATIVE_RECEIPT_SUFFIX
        )
        invocation_path = self.phase / (
            label + reproducibility.INVOCATION_SUFFIX
        )
        projection_path = self.phase / (
            label + reproducibility.RESULT_PROJECTION_SUFFIX
        )
        artifact_path.write_bytes(artifact)
        capsule_path.write_bytes(capsule_bytes)
        metadata_path.write_bytes(metadata)
        invocation_path.write_bytes(invocation_bytes)
        native_receipt = native_build.make_receipt(
            artifact_path,
            capsule_build_receipt=capsule,
            cargo_metadata_data=metadata,
            repo_root=self.capsule_fixture.repo,
        )
        native_path.write_bytes(cjson(native_receipt))
        projection = projection_for(
            invocation,
            label=label,
            allocation_nonce=allocation_nonce or self.allocations[label],
            artifact=artifact,
            capsule=capsule_bytes,
            metadata=metadata,
        )
        projection_path.write_bytes(
            release_result_stage.canonical_bytes(projection)
        )
        self.capsules[label] = capsule
        self.invocations[label] = invocation

    def stage(self) -> dict[str, object]:
        return reproducibility.stage_receipt(
            self.phase, repo_root=self.capsule_fixture.repo
        )


class NativeReproducibilityTests(unittest.TestCase):
    def fixture(
        self,
    ) -> tuple[tempfile.TemporaryDirectory[str], ReproducibilityFixture]:
        temporary = tempfile.TemporaryDirectory()
        return temporary, ReproducibilityFixture(Path(temporary.name))

    def test_two_retained_sealed_capsule_results_verify(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            result = fixture.stage()
            verified = reproducibility.build_result(
                fixture.phase, repo_root=fixture.capsule_fixture.repo
            )
            self.assertEqual(result, verified)
            self.assertTrue(
                result["two_capsule_byte_reproducibility_observed"]
            )
            self.assertFalse(result["build_causality_proven"])
            self.assertFalse(result["independent_compiler_execution_proven"])
            self.assertFalse(result["network_nonuse_proven"])
            self.assertTrue(result["equality"]["exact_builder_image"])
            self.assertEqual(len(result["observations"]), 2)

    def test_capture_retains_two_live_sealed_stages_without_clobber(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            invocation_parent = fixture.root / "capture-invocations"
            invocation_parent.mkdir()
            invocations = {
                label: release_invocation.create_invocation(
                    invocation_parent, f"capture-{label}"
                )
                for label in reproducibility.RUN_LABELS
            }
            results: dict[str, SimpleNamespace] = {}
            projections: dict[str, dict[str, object]] = {}
            for label in reproducibility.RUN_LABELS:
                descriptor = release_invocation.verify_invocation(
                    invocations[label].stage
                ).descriptor
                capsule = copy.deepcopy(fixture.base_capsule)
                descriptor_bytes = release_invocation.canonical_bytes(descriptor)
                lineage = capsule["release_capsule"]
                lineage["release_invocation_id"] = descriptor["invocation_id"]
                lineage["release_invocation_descriptor_sha256"] = hashlib.sha256(
                    descriptor_bytes
                ).hexdigest()
                capsule_bytes = cjson(capsule)
                stage = fixture.root / f"sealed-{label}"
                result_root = stage / release_result_stage.RESULT_ROOT_NAME
                artifact_path = result_root / reproducibility.RESULT_ARTIFACT_PATH
                capsule_path = (
                    result_root / reproducibility.RESULT_CAPSULE_RECEIPT_PATH
                )
                metadata_path = result_root / reproducibility.RESULT_METADATA_PATH
                artifact_path.parent.mkdir(parents=True)
                metadata_path.parent.mkdir(parents=True)
                artifact_path.write_bytes(fixture.artifact)
                capsule_path.write_bytes(capsule_bytes)
                metadata_path.write_bytes(fixture.metadata)
                projections[label] = projection_for(
                    descriptor,
                    label=label,
                    allocation_nonce=fixture.allocations[label],
                    artifact=fixture.artifact,
                    capsule=capsule_bytes,
                    metadata=fixture.metadata,
                )
                results[label] = SimpleNamespace(
                    stage=stage,
                    descriptor={"state": "sealed"},
                )

            def verified_result(path: Path, _invocation: Path) -> SimpleNamespace:
                label = "build-a" if Path(path) == results["build-a"].stage else "build-b"
                return results[label]

            def projected(result: SimpleNamespace) -> dict[str, object]:
                label = "build-a" if result.stage == results["build-a"].stage else "build-b"
                return projections[label]

            captured = fixture.root / "captured"
            with (
                mock.patch.object(
                    release_result_stage,
                    "verify_result_stage",
                    side_effect=verified_result,
                ),
                mock.patch.object(
                    release_result_stage,
                    "audit_projection",
                    side_effect=projected,
                ),
            ):
                result = reproducibility.capture_live_evidence(
                    captured,
                    source_descriptor_path=(
                        fixture.phase / reproducibility.SOURCE_DESCRIPTOR_NAME
                    ),
                    build_input_descriptor_path=(
                        fixture.phase / reproducibility.BUILD_INPUT_DESCRIPTOR_NAME
                    ),
                    build_a_invocation_stage=invocations["build-a"].stage,
                    build_a_result_stage=results["build-a"].stage,
                    build_b_invocation_stage=invocations["build-b"].stage,
                    build_b_result_stage=results["build-b"].stage,
                    repo_root=fixture.capsule_fixture.repo,
                )
            self.assertEqual(
                result,
                reproducibility.verify_workflow_evidence(
                    captured, repo_root=fixture.capsule_fixture.repo
                ),
            )
            self.assertEqual(set(reproducibility.PHASE_FILES), {
                path.name for path in captured.iterdir()
            })
            with self.assertRaisesRegex(
                reproducibility.NativeReproducibilityError, "overwrite"
            ):
                reproducibility.capture_live_evidence(
                    captured,
                    source_descriptor_path=(
                        fixture.phase / reproducibility.SOURCE_DESCRIPTOR_NAME
                    ),
                    build_input_descriptor_path=(
                        fixture.phase / reproducibility.BUILD_INPUT_DESCRIPTOR_NAME
                    ),
                    build_a_invocation_stage=invocations["build-a"].stage,
                    build_a_result_stage=results["build-a"].stage,
                    build_b_invocation_stage=invocations["build-b"].stage,
                    build_b_result_stage=results["build-b"].stage,
                    repo_root=fixture.capsule_fixture.repo,
                )

    def test_same_invocation_and_resources_are_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            fixture.write_run(
                "build-b", invocation=fixture.invocations["build-a"]
            )
            with self.assertRaisesRegex(
                reproducibility.NativeReproducibilityError,
                "distinct release_invocation_id",
            ):
                reproducibility.build_result(
                    fixture.phase, repo_root=fixture.capsule_fixture.repo
                )

    def test_source_descriptor_mismatch_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            capsule = copy.deepcopy(fixture.capsules["build-b"])
            capsule["release_capsule"][
                "source_snapshot_descriptor_sha256"
            ] = "f" * 64
            fixture.write_run("build-b", capsule=capsule)
            with self.assertRaisesRegex(
                reproducibility.NativeReproducibilityError,
                "source descriptor",
            ):
                reproducibility.build_result(
                    fixture.phase, repo_root=fixture.capsule_fixture.repo
                )

    def test_build_input_snapshot_mismatch_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            capsule = copy.deepcopy(fixture.capsules["build-b"])
            capsule["build_inputs"]["evidence"]["snapshot"][
                "snapshot_id"
            ] = "e" * 64
            fixture.write_run("build-b", capsule=capsule)
            with self.assertRaisesRegex(
                reproducibility.NativeReproducibilityError,
                "exact input contract|build-input descriptor",
            ):
                reproducibility.build_result(
                    fixture.phase, repo_root=fixture.capsule_fixture.repo
                )

    def test_different_builder_image_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            capsule = set_builder_image(
                fixture.capsules["build-b"], "sha256:" + "b" * 64
            )
            fixture.write_run("build-b", capsule=capsule)
            with self.assertRaisesRegex(
                reproducibility.NativeReproducibilityError,
                "exact input contract",
            ):
                reproducibility.build_result(
                    fixture.phase, repo_root=fixture.capsule_fixture.repo
                )

    def test_distinct_valid_artifacts_must_be_byte_identical(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            different = aarch64_elf(b"second-valid-artifact")
            fixture.write_run("build-b", artifact=different)
            with self.assertRaisesRegex(
                reproducibility.NativeReproducibilityError,
                "not byte-identical",
            ):
                reproducibility.build_result(
                    fixture.phase, repo_root=fixture.capsule_fixture.repo
                )

    def test_result_manifest_member_tampering_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            path = fixture.phase / (
                "build-b" + reproducibility.RESULT_PROJECTION_SUFFIX
            )
            projection = json.loads(path.read_bytes())
            item = next(
                item
                for item in projection["manifest"]["files"]
                if item["path"] == reproducibility.RESULT_ARTIFACT_PATH
            )
            item["sha256"] = "f" * 64
            body = {
                "directories": projection["manifest"]["directories"],
                "files": projection["manifest"]["files"],
            }
            projection["manifest"]["manifest_sha256"] = hashlib.sha256(
                release_result_stage.canonical_bytes(body)
            ).hexdigest()
            path.write_bytes(release_result_stage.canonical_bytes(projection))
            with self.assertRaisesRegex(
                reproducibility.NativeReproducibilityError,
                "manifest identity",
            ):
                reproducibility.build_result(
                    fixture.phase, repo_root=fixture.capsule_fixture.repo
                )

    def test_projection_invocation_binding_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            path = fixture.phase / (
                "build-b" + reproducibility.RESULT_PROJECTION_SUFFIX
            )
            projection = json.loads(path.read_bytes())
            projection["invocation"]["invocation_id"] = "9" * 64
            path.write_bytes(release_result_stage.canonical_bytes(projection))
            with self.assertRaisesRegex(
                release_result_stage.ResultStageError,
                "disagrees",
            ):
                reproducibility.build_result(
                    fixture.phase, repo_root=fixture.capsule_fixture.repo
                )

    def test_artifact_hard_link_alias_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            first = fixture.phase / (
                "build-a" + reproducibility.ARTIFACT_SUFFIX
            )
            second = fixture.phase / (
                "build-b" + reproducibility.ARTIFACT_SUFFIX
            )
            second.unlink()
            try:
                second.hardlink_to(first)
            except (NotImplementedError, OSError):
                self.skipTest("hard links are unavailable on this platform")
            with self.assertRaisesRegex(
                reproducibility.NativeReproducibilityError,
                "single-link|distinct physical identities",
            ):
                reproducibility.build_result(
                    fixture.phase, repo_root=fixture.capsule_fixture.repo
                )

    def test_stale_receipt_and_extra_file_are_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            fixture.stage()
            receipt = fixture.phase / reproducibility.RECEIPT_NAME
            receipt.write_bytes(
                receipt.read_bytes().replace(
                    b'"network_nonuse_proven":false',
                    b'"network_nonuse_proven":true',
                    1,
                )
            )
            with self.assertRaisesRegex(
                reproducibility.NativeReproducibilityError, "stale"
            ):
                reproducibility.verify_workflow_evidence(
                    fixture.phase, repo_root=fixture.capsule_fixture.repo
                )
            receipt.write_bytes(
                reproducibility.canonical_json(
                    reproducibility.build_result(
                        fixture.phase, repo_root=fixture.capsule_fixture.repo
                    )
                )
            )
            (fixture.phase / "unexpected").write_text("no\n", encoding="ascii")
            with self.assertRaisesRegex(
                reproducibility.NativeReproducibilityError, "file set"
            ):
                reproducibility.verify_workflow_evidence(
                    fixture.phase, repo_root=fixture.capsule_fixture.repo
                )


if __name__ == "__main__":
    unittest.main()
