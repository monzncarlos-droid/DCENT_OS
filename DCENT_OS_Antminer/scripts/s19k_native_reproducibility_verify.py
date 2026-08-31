#!/usr/bin/env python3
"""Verify two retained, sealed S19k AArch64 capsule result observations.

Version 3 authenticates one Git source descriptor and one Cargo external-input
descriptor, then joins two distinct release invocation descriptors and sealed
result-stage audit projections. Each result manifest must bind the copied
dcentrald, generic schema-v4 build receipt, and Cargo metadata bytes. The
native handoff receipt is re-derived from those exact bytes.

The two observations must use the same immutable builder image and complete
input contract, while invocation, Cargo volume, result allocation, and receipt
identities remain distinct. Byte equality is still an observation, not proof
that a compiler caused either result. No release, install, live-contact, or
persistent-mutation authority is granted.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any, Mapping, NoReturn, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_input_snapshot  # noqa: E402
import release_invocation  # noqa: E402
import release_result_stage  # noqa: E402
import s19k_native_build_verify as native_build  # noqa: E402
import source_snapshot  # noqa: E402


REPO_ROOT = SCRIPT_DIR.parent.parent.parent
DEFAULT_EVIDENCE_DIR = (
    REPO_ROOT / ".s19k-gauntlet-evidence/native-build-reproducibility"
)
SCHEMA = "dcentos.s19k-native-build-reproducibility/v3"
PHASE_ID = "native-build-reproducibility"
CLAIM = (
    "two-distinct-sealed-exact-input-manifest-key-pinned-capsule-results-byte-identical-"
    "not-build-causality-or-release-authority"
)
RUN_LABELS = ("build-a", "build-b")
SOURCE_DESCRIPTOR_NAME = "source-snapshot.json"
BUILD_INPUT_DESCRIPTOR_NAME = "build-input-snapshot.json"
INVOCATION_SUFFIX = ".invocation.json"
RESULT_PROJECTION_SUFFIX = ".result-stage.json"
ARTIFACT_SUFFIX = ".dcentrald"
CAPSULE_RECEIPT_SUFFIX = ".dcentrald.build-receipt.json"
METADATA_SUFFIX = ".cargo-metadata.json"
NATIVE_RECEIPT_SUFFIX = ".native-build.json"
RECEIPT_NAME = "verification.json"
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES = native_build.MAX_ARTIFACT_BYTES
RESULT_ARTIFACT_PATH = (
    f"target/{native_build.TARGET}/release/dcentrald"
)
RESULT_CAPSULE_RECEIPT_PATH = RESULT_ARTIFACT_PATH + ".build-receipt.json"
RESULT_METADATA_PATH = (
    f"target/release-inventory/{native_build.TARGET}.metadata.json"
)
PHASE_FILES = (
    SOURCE_DESCRIPTOR_NAME,
    BUILD_INPUT_DESCRIPTOR_NAME,
    *(
        name
        for label in RUN_LABELS
        for name in (
            label + INVOCATION_SUFFIX,
            label + RESULT_PROJECTION_SUFFIX,
            label + ARTIFACT_SUFFIX,
            label + CAPSULE_RECEIPT_SUFFIX,
            label + METADATA_SUFFIX,
            label + NATIVE_RECEIPT_SUFFIX,
        )
    ),
    RECEIPT_NAME,
)


class NativeReproducibilityError(ValueError):
    """Retained two-capsule evidence is absent, aliased, stale, or unequal."""


def fail(message: str) -> NoReturn:
    raise NativeReproducibilityError(message)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or getattr(before, "st_nlink", 1) != 1
    ):
        fail(f"{label} must be a single-link regular non-symlink file")
    if before.st_size <= 0 or before.st_size > maximum:
        fail(f"{label} has an invalid byte count")
    data = path.read_bytes()
    after = path.lstat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or len(data) != before.st_size:
        fail(f"{label} changed while it was read")
    return data


def _json_bytes(data: bytes, label: str, *, canonical: bool = True) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    if canonical and data != canonical_json(value):
        fail(f"{label} is not canonical JSON")
    return value


def _same_file(first: Path, second: Path, label: str) -> None:
    if first.absolute() == second.absolute():
        fail(f"{label} paths must be distinct")
    try:
        aliased = os.path.samefile(first, second)
    except OSError as error:
        fail(f"cannot compare {label} file identities: {error}")
    if aliased:
        fail(f"{label} files must have distinct physical identities")


def _identity(path: str, data: bytes) -> dict[str, Any]:
    return {"path": path, "sha256": digest(data), "bytes": len(data)}


def _write_exclusive(path: Path, data: bytes, label: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail(f"short write while retaining {label}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _manifest_file(
    projection: Mapping[str, Any], path: str, label: str
) -> Mapping[str, Any]:
    manifest = projection.get("manifest")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        fail(f"{label} result manifest is malformed")
    matches = [
        item
        for item in manifest["files"]
        if isinstance(item, dict) and item.get("path") == path
    ]
    if len(matches) != 1:
        fail(f"{label} result manifest must contain exactly one {path}")
    return matches[0]


def _require_manifest_identity(
    projection: Mapping[str, Any], path: str, data: bytes, label: str
) -> None:
    item = _manifest_file(projection, path, label)
    if item.get("sha256") != digest(data) or item.get("size") != len(data):
        fail(f"{label} result manifest identity disagrees with {path}")


def _builder_recipe(builder: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "base_reference": builder.get("base_reference"),
        "image_id": builder.get("image_id"),
        "kind": builder.get("kind"),
        "package_resolution": builder.get("package_resolution"),
    }


def _input_contract(build: Mapping[str, Any]) -> dict[str, Any]:
    capsule = build.get("capsule_build_receipt")
    if not isinstance(capsule, dict):
        fail("native build receipt lacks capsule evidence")
    git = capsule.get("git")
    builder = capsule.get("builder")
    if not isinstance(git, dict) or not isinstance(builder, dict):
        fail("native build capsule source/builder identity is malformed")
    return {
        "native_build_schema": build.get("schema"),
        "target_triple": build.get("target_triple"),
        "cargo_profile": build.get("cargo_profile"),
        "cargo_command": build.get("cargo_command"),
        "semantic_source_files": build.get("semantic_source_files"),
        "semantic_source_files_sha256": build.get(
            "semantic_source_files_sha256"
        ),
        "aarch64_compile_contract": build.get("aarch64_compile_contract"),
        "compile_contract_sha256": build.get("compile_contract_sha256"),
        "local_dependency_closure": build.get("local_dependency_closure"),
        "manifest_public_key_hex": build.get("manifest_public_key_hex"),
        "manifest_public_key_sha256": build.get("manifest_public_key_sha256"),
        "network_contract": build.get("network_contract"),
        "network_nonuse_proven": build.get("network_nonuse_proven"),
        "source_commit": git.get("commit"),
        "source_kind": git.get("source_kind"),
        "source_inventory": capsule.get("source_inventory"),
        "source_inventory_sha256": capsule.get("source_inventory_sha256"),
        "build_inputs": capsule.get("build_inputs"),
        "build_environment": capsule.get("build_environment"),
        "builder": builder,
        "toolchain_context": capsule.get("toolchain_context"),
        "compile_environment": capsule.get("compile_environment"),
        "cargo_metadata": capsule.get("cargo_metadata"),
        "binary_name": capsule.get("binary", {}).get("name")
        if isinstance(capsule.get("binary"), dict)
        else None,
        "binary_path": capsule.get("binary", {}).get("path")
        if isinstance(capsule.get("binary"), dict)
        else None,
    }


def _load_run(
    evidence_dir: Path, label: str, repo_root: Path
) -> dict[str, Any]:
    paths = {
        "invocation": evidence_dir / (label + INVOCATION_SUFFIX),
        "projection": evidence_dir / (label + RESULT_PROJECTION_SUFFIX),
        "artifact": evidence_dir / (label + ARTIFACT_SUFFIX),
        "capsule": evidence_dir / (label + CAPSULE_RECEIPT_SUFFIX),
        "metadata": evidence_dir / (label + METADATA_SUFFIX),
        "native": evidence_dir / (label + NATIVE_RECEIPT_SUFFIX),
    }
    data = {
        "artifact": _read_regular(
            paths["artifact"], MAX_ARTIFACT_BYTES, f"{label} artifact"
        ),
        "capsule": _read_regular(
            paths["capsule"], MAX_JSON_BYTES, f"{label} capsule build receipt"
        ),
        "metadata": _read_regular(
            paths["metadata"], MAX_JSON_BYTES, f"{label} Cargo metadata"
        ),
        "native": _read_regular(
            paths["native"], MAX_JSON_BYTES, f"{label} native build receipt"
        ),
        "invocation": _read_regular(
            paths["invocation"], MAX_JSON_BYTES, f"{label} invocation descriptor"
        ),
        "projection": _read_regular(
            paths["projection"], MAX_JSON_BYTES, f"{label} result projection"
        ),
    }
    capsule = _json_bytes(data["capsule"], f"{label} capsule build receipt")
    _json_bytes(data["metadata"], f"{label} Cargo metadata", canonical=False)
    native_value = _json_bytes(data["native"], f"{label} native build receipt")
    invocation = release_invocation.verify_audit_descriptor(paths["invocation"])
    projection_value = _json_bytes(
        data["projection"], f"{label} result projection"
    )
    projection = release_result_stage.verify_audit_projection(
        projection_value, invocation
    )
    verified_native = native_build.verify_receipt(
        paths["native"], paths["artifact"], repo_root=repo_root
    )
    if verified_native != native_value:
        fail(f"{label} native build verifier changed its canonical value")
    if verified_native.get("capsule_build_receipt") != capsule:
        fail(f"{label} native build receipt does not embed the retained capsule bytes")
    rebuilt = native_build.make_receipt(
        paths["artifact"],
        capsule_build_receipt=capsule,
        cargo_metadata_data=data["metadata"],
        repo_root=repo_root,
    )
    if rebuilt != verified_native or canonical_json(rebuilt) != data["native"]:
        fail(f"{label} native build receipt is not derived from the retained bytes")

    lineage = capsule.get("release_capsule")
    if not isinstance(lineage, dict):
        fail(f"{label} capsule lineage is malformed")
    descriptor_sha256 = digest(data["invocation"])
    if (
        lineage.get("release_invocation_id") != invocation.get("invocation_id")
        or lineage.get("release_invocation_descriptor_sha256")
        != descriptor_sha256
    ):
        fail(f"{label} capsule lineage disagrees with its invocation descriptor")

    _require_manifest_identity(
        projection, RESULT_ARTIFACT_PATH, data["artifact"], label
    )
    _require_manifest_identity(
        projection, RESULT_CAPSULE_RECEIPT_PATH, data["capsule"], label
    )
    _require_manifest_identity(
        projection, RESULT_METADATA_PATH, data["metadata"], label
    )
    cargo_metadata = capsule.get("cargo_metadata")
    if (
        not isinstance(cargo_metadata, dict)
        or cargo_metadata.get("sha256") != digest(data["metadata"])
        or cargo_metadata.get("size") != len(data["metadata"])
    ):
        fail(f"{label} capsule receipt does not bind retained Cargo metadata")

    return {
        "label": label,
        "paths": paths,
        "data": data,
        "capsule": capsule,
        "native": verified_native,
        "invocation": invocation,
        "projection": projection,
        "contract": _input_contract(verified_native),
    }


def _observation(run: Mapping[str, Any]) -> dict[str, Any]:
    label = run["label"]
    data = run["data"]
    native_value = run["native"]
    invocation = run["invocation"]
    projection = run["projection"]
    resources = invocation["resources"]
    return {
        "label": label,
        "release_invocation_id": invocation["invocation_id"],
        "release_invocation_descriptor_sha256": digest(data["invocation"]),
        "cargo_volume": resources["docker_volumes"]["cargo"],
        "output_stage_name": resources["output_stage_name"],
        "result_name": resources["result_name"],
        "result_stage_id": projection["stage_id"],
        "result_stage_descriptor_sha256": projection[
            "source_descriptor_sha256"
        ],
        "result_manifest_sha256": projection["manifest"]["manifest_sha256"],
        "result_allocation_nonce": projection["allocation_nonce"],
        "capsule_build_receipt_sha256": digest(data["capsule"]),
        "cargo_metadata_sha256": digest(data["metadata"]),
        "native_build_verification_id": native_value["verification_id"],
        "artifact_sha256": digest(data["artifact"]),
        "artifact_bytes": len(data["artifact"]),
    }


def build_result(
    evidence_dir: Path, *, repo_root: Path = REPO_ROOT
) -> dict[str, Any]:
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        fail(f"reproducibility evidence directory is absent or unsafe: {evidence_dir}")

    runs = [_load_run(evidence_dir, label, repo_root) for label in RUN_LABELS]
    for kind, suffix in (
        ("invocation descriptor", INVOCATION_SUFFIX),
        ("result projection", RESULT_PROJECTION_SUFFIX),
        ("artifact", ARTIFACT_SUFFIX),
        ("capsule receipt", CAPSULE_RECEIPT_SUFFIX),
        ("Cargo metadata", METADATA_SUFFIX),
        ("native receipt", NATIVE_RECEIPT_SUFFIX),
    ):
        _same_file(
            evidence_dir / (RUN_LABELS[0] + suffix),
            evidence_dir / (RUN_LABELS[1] + suffix),
            kind,
        )

    if runs[0]["data"]["artifact"] != runs[1]["data"]["artifact"]:
        fail("two sealed capsule artifacts are not byte-identical")
    if runs[0]["data"]["metadata"] != runs[1]["data"]["metadata"]:
        fail("two sealed capsule Cargo metadata files are not byte-identical")
    if runs[0]["contract"] != runs[1]["contract"]:
        fail("two sealed capsule builds do not share one exact input contract")

    contracts = runs[0]["contract"]
    source_commit = contracts["source_commit"]
    if not isinstance(source_commit, str):
        fail("capsule source commit is malformed")
    source_path = evidence_dir / SOURCE_DESCRIPTOR_NAME
    source_data = _read_regular(
        source_path, MAX_JSON_BYTES, "retained source snapshot descriptor"
    )
    source_verification = source_snapshot.verify_descriptor_against_git(
        repo_root, source_commit, source_path
    )
    input_path = evidence_dir / BUILD_INPUT_DESCRIPTOR_NAME
    input_data = _read_regular(
        input_path, MAX_JSON_BYTES, "retained build-input descriptor"
    )
    input_descriptor = build_input_snapshot.verify_audit_descriptor(
        input_path, expected_target="cargo-workspace"
    )
    input_evidence = build_input_snapshot.snapshot_evidence(input_descriptor)

    for run in runs:
        capsule = run["capsule"]
        lineage = capsule["release_capsule"]
        if (
            lineage.get("source_snapshot_id")
            != source_verification["snapshot_id"]
            or lineage.get("source_snapshot_descriptor_sha256")
            != source_verification["descriptor_sha256"]
        ):
            fail(
                f"{run['label']} capsule lineage disagrees with the retained "
                "source descriptor"
            )
        build_inputs = capsule.get("build_inputs")
        if (
            not isinstance(build_inputs, dict)
            or build_inputs.get("evidence") != input_evidence
        ):
            fail(
                f"{run['label']} capsule build inputs disagree with the retained "
                "build-input descriptor"
            )

    observations = sorted(
        (_observation(run) for run in runs),
        key=lambda item: item["release_invocation_id"],
    )
    distinct_fields = (
        "release_invocation_id",
        "release_invocation_descriptor_sha256",
        "cargo_volume",
        "output_stage_name",
        "result_name",
        "result_stage_id",
        "result_stage_descriptor_sha256",
        "result_manifest_sha256",
        "result_allocation_nonce",
        "capsule_build_receipt_sha256",
        "native_build_verification_id",
    )
    for field in distinct_fields:
        if observations[0][field] == observations[1][field]:
            fail(f"two capsule observations do not have distinct {field}")

    builder = contracts["builder"]
    if not isinstance(builder, dict):
        fail("exact input contract lacks its builder identity")
    builder_recipe = _builder_recipe(builder)
    local_closure = contracts["local_dependency_closure"]
    toolchain = contracts["toolchain_context"]
    compile_environment = contracts["compile_environment"]
    cargo_metadata = contracts["cargo_metadata"]
    if not all(
        isinstance(item, dict)
        for item in (
            local_closure,
            toolchain,
            compile_environment,
            cargo_metadata,
        )
    ):
        fail("exact input contract contains malformed structured evidence")

    artifact = {
        "path": "dcentrald",
        "sha256": digest(runs[0]["data"]["artifact"]),
        "bytes": len(runs[0]["data"]["artifact"]),
        "elf_class": 64,
        "machine": 183,
    }
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "phase_id": PHASE_ID,
        "claim": CLAIM,
        "classification": "two-distinct-sealed-capsule-results-byte-identical",
        "source": {
            "commit_oid": source_commit,
            "source_snapshot_id": source_verification["snapshot_id"],
            "source_snapshot_descriptor_sha256": source_verification[
                "descriptor_sha256"
            ],
            "source_inventory_sha256": contracts["source_inventory_sha256"],
            "build_input_snapshot_id": input_descriptor["snapshot_id"],
            "build_input_descriptor_sha256": digest(input_data),
        },
        "input_contract": {
            "target_triple": native_build.TARGET,
            "profile": native_build.PROFILE,
            "build_variant": native_build.BUILD_VARIANT,
            "cargo_command": native_build.CARGO_COMMAND,
            "builder_base_reference": builder["base_reference"],
            "builder_image_id": builder["image_id"],
            "builder_recipe_sha256": digest(canonical_json(builder_recipe)),
            "builder_package_resolution": builder["package_resolution"],
            "toolchain_context_sha256": toolchain["sha256"],
            "compile_environment_sha256": compile_environment["sha256"],
            "cargo_metadata_sha256": cargo_metadata["sha256"],
            "local_dependency_closure_sha256": digest(
                canonical_json(local_closure)
            ),
            "manifest_public_key_hex": contracts["manifest_public_key_hex"],
            "manifest_public_key_sha256": contracts[
                "manifest_public_key_sha256"
            ],
        },
        "artifact": artifact,
        "observations": observations,
        "independence": {
            "distinct_invocation_ids": True,
            "distinct_invocation_descriptors": True,
            "distinct_cargo_volumes": True,
            "distinct_output_stage_names": True,
            "distinct_result_names": True,
            "distinct_result_stage_ids": True,
            "distinct_result_stage_descriptors": True,
            "distinct_result_manifests": True,
            "distinct_result_allocation_nonces": True,
            "distinct_capsule_receipts": True,
            "distinct_native_build_receipts": True,
        },
        "equality": {
            "exact_source_snapshot": True,
            "exact_build_input_snapshot": True,
            "exact_builder_image": True,
            "exact_toolchain_context": True,
            "exact_compile_environment": True,
            "exact_cargo_metadata": True,
            "exact_local_dependency_closure": True,
            "exact_manifest_public_key": True,
            "byte_identical_artifact": True,
        },
        "network_contract": copy.deepcopy(native_build.NETWORK_CONTRACT),
        "network_nonuse_proven": False,
        "two_capsule_byte_reproducibility_observed": True,
        "build_causality_proven": False,
        "independent_compiler_execution_proven": False,
        "live_hardware_contacted": False,
        "release_authority_granted": False,
        "installation_authority_granted": False,
        "persistent_mutation_authority_granted": False,
    }
    result["verification_id"] = digest(canonical_json(result))
    return result


def verify_workflow_evidence(
    evidence_dir: Path, *, repo_root: Path = REPO_ROOT
) -> dict[str, Any]:
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        fail(f"reproducibility evidence directory is absent or unsafe: {evidence_dir}")
    observed = {entry.name for entry in evidence_dir.iterdir()}
    if observed != set(PHASE_FILES):
        fail(
            "native reproducibility phase file set is not exact: "
            f"expected={sorted(PHASE_FILES)} observed={sorted(observed)}"
        )
    result = build_result(evidence_dir, repo_root=repo_root)
    receipt_data = _read_regular(
        evidence_dir / RECEIPT_NAME, MAX_JSON_BYTES, "reproducibility receipt"
    )
    if receipt_data != canonical_json(result):
        fail("verification.json is stale, noncanonical, or not freshly reproducible")
    return result


def stage_receipt(
    evidence_dir: Path, *, repo_root: Path = REPO_ROOT
) -> dict[str, Any]:
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        fail(f"reproducibility evidence directory is absent or unsafe: {evidence_dir}")
    observed = {entry.name for entry in evidence_dir.iterdir()}
    inputs = set(PHASE_FILES) - {RECEIPT_NAME}
    if observed not in (inputs, set(PHASE_FILES)):
        fail(f"refusing unsafe reproducibility file set: {sorted(observed)}")
    result = build_result(evidence_dir, repo_root=repo_root)
    expected = canonical_json(result)
    destination = evidence_dir / RECEIPT_NAME
    if destination.exists():
        if _read_regular(
            destination, MAX_JSON_BYTES, "reproducibility receipt"
        ) != expected:
            fail("refusing to overwrite a stale reproducibility receipt")
        return result
    with tempfile.NamedTemporaryFile(
        dir=evidence_dir,
        prefix=f".{RECEIPT_NAME}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
        handle.write(expected)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return result


def capture_live_evidence(
    evidence_dir: Path,
    *,
    source_descriptor_path: Path,
    build_input_descriptor_path: Path,
    build_a_invocation_stage: Path,
    build_a_result_stage: Path,
    build_b_invocation_stage: Path,
    build_b_result_stage: Path,
    repo_root: Path = REPO_ROOT,
) -> dict[str, Any]:
    """Retain two verified sealed result stages without overwriting any path.

    The producer copies only immutable audit descriptors and manifest-bound
    result members. It derives each native S19k receipt from those copied
    bytes, then stages the final reproducibility receipt. A failed capture
    deliberately leaves its newly-created partial directory in place so a
    retry cannot silently hide or replace evidence.
    """

    destination = evidence_dir.absolute()
    if destination.exists() or destination.is_symlink():
        fail(f"refusing to overwrite reproducibility evidence: {destination}")
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        fail("reproducibility evidence parent must be an existing real directory")

    source_path = source_descriptor_path.resolve(strict=True)
    build_input_path = build_input_descriptor_path.resolve(strict=True)
    stage_pairs = {
        "build-a": (
            build_a_invocation_stage.resolve(strict=True),
            build_a_result_stage.resolve(strict=True),
        ),
        "build-b": (
            build_b_invocation_stage.resolve(strict=True),
            build_b_result_stage.resolve(strict=True),
        ),
    }
    for path in (
        source_path,
        build_input_path,
        *(item for pair in stage_pairs.values() for item in pair),
    ):
        if _overlaps(destination, path):
            fail("evidence destination must be disjoint from every source stage")

    source_data = _read_regular(
        source_path, MAX_JSON_BYTES, "source snapshot descriptor"
    )
    build_input_data = _read_regular(
        build_input_path, MAX_JSON_BYTES, "build-input snapshot descriptor"
    )
    _json_bytes(source_data, "source snapshot descriptor")
    _json_bytes(build_input_data, "build-input snapshot descriptor")

    retained: dict[str, dict[str, bytes]] = {}
    live_invocations: list[Path] = []
    live_results: list[Path] = []
    for label, (invocation_stage, result_stage) in stage_pairs.items():
        invocation = release_invocation.verify_invocation(invocation_stage)
        result = release_result_stage.verify_result_stage(
            result_stage, invocation_stage
        )
        if result.descriptor.get("state") != "sealed":
            fail(f"{label} result stage is not sealed")
        projection = release_result_stage.audit_projection(result)
        invocation_data = release_invocation.canonical_bytes(
            invocation.descriptor
        )
        projection_data = release_result_stage.canonical_bytes(projection)
        artifact_path = result.stage / release_result_stage.RESULT_ROOT_NAME / RESULT_ARTIFACT_PATH
        capsule_path = result.stage / release_result_stage.RESULT_ROOT_NAME / RESULT_CAPSULE_RECEIPT_PATH
        metadata_path = result.stage / release_result_stage.RESULT_ROOT_NAME / RESULT_METADATA_PATH
        artifact = _read_regular(artifact_path, MAX_ARTIFACT_BYTES, f"{label} artifact")
        capsule = _read_regular(
            capsule_path, MAX_JSON_BYTES, f"{label} capsule build receipt"
        )
        metadata = _read_regular(
            metadata_path, MAX_JSON_BYTES, f"{label} Cargo metadata"
        )
        _require_manifest_identity(projection, RESULT_ARTIFACT_PATH, artifact, label)
        _require_manifest_identity(
            projection, RESULT_CAPSULE_RECEIPT_PATH, capsule, label
        )
        _require_manifest_identity(projection, RESULT_METADATA_PATH, metadata, label)
        # Re-read the complete authority after copying its selected bytes into
        # memory so a concurrent mutation cannot be retained as one observation.
        release_result_stage.verify_result_stage(result_stage, invocation_stage)
        retained[label] = {
            "invocation": invocation_data,
            "projection": projection_data,
            "artifact": artifact,
            "capsule": capsule,
            "metadata": metadata,
        }
        live_invocations.append(invocation.stage)
        live_results.append(result.stage)

    if os.path.samefile(live_invocations[0], live_invocations[1]):
        fail("build-a and build-b invocation stages must be distinct")
    if os.path.samefile(live_results[0], live_results[1]):
        fail("build-a and build-b result stages must be distinct")

    os.mkdir(destination, 0o700)
    _write_exclusive(
        destination / SOURCE_DESCRIPTOR_NAME,
        source_data,
        "source snapshot descriptor",
    )
    _write_exclusive(
        destination / BUILD_INPUT_DESCRIPTOR_NAME,
        build_input_data,
        "build-input snapshot descriptor",
    )
    for label in RUN_LABELS:
        values = retained[label]
        artifact_path = destination / (label + ARTIFACT_SUFFIX)
        capsule_path = destination / (label + CAPSULE_RECEIPT_SUFFIX)
        metadata_path = destination / (label + METADATA_SUFFIX)
        _write_exclusive(
            destination / (label + INVOCATION_SUFFIX),
            values["invocation"],
            f"{label} invocation descriptor",
        )
        _write_exclusive(
            destination / (label + RESULT_PROJECTION_SUFFIX),
            values["projection"],
            f"{label} result-stage projection",
        )
        _write_exclusive(artifact_path, values["artifact"], f"{label} artifact")
        _write_exclusive(
            capsule_path, values["capsule"], f"{label} capsule build receipt"
        )
        _write_exclusive(
            metadata_path, values["metadata"], f"{label} Cargo metadata"
        )
        native_receipt = native_build.make_receipt(
            artifact_path,
            capsule_build_receipt=_json_bytes(
                values["capsule"], f"{label} capsule build receipt"
            ),
            cargo_metadata_data=values["metadata"],
            repo_root=repo_root,
        )
        _write_exclusive(
            destination / (label + NATIVE_RECEIPT_SUFFIX),
            canonical_json(native_receipt),
            f"{label} native build receipt",
        )
    return stage_receipt(destination, repo_root=repo_root)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("capture", "stage", "verify"))
    parser.add_argument(
        "--evidence-dir", type=Path, default=DEFAULT_EVIDENCE_DIR
    )
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--source-snapshot", type=Path)
    parser.add_argument("--build-input-snapshot", type=Path)
    parser.add_argument("--build-a-invocation-stage", type=Path)
    parser.add_argument("--build-a-result-stage", type=Path)
    parser.add_argument("--build-b-invocation-stage", type=Path)
    parser.add_argument("--build-b-result-stage", type=Path)
    args = parser.parse_args(argv)
    try:
        evidence_dir = args.evidence_dir.resolve()
        repo_root = args.repo_root.resolve()
        if args.command == "capture":
            required = {
                "source snapshot": args.source_snapshot,
                "build-input snapshot": args.build_input_snapshot,
                "build-a invocation stage": args.build_a_invocation_stage,
                "build-a result stage": args.build_a_result_stage,
                "build-b invocation stage": args.build_b_invocation_stage,
                "build-b result stage": args.build_b_result_stage,
            }
            absent = [label for label, value in required.items() if value is None]
            if absent:
                fail(f"capture arguments are absent: {', '.join(absent)}")
            result = capture_live_evidence(
                evidence_dir,
                source_descriptor_path=args.source_snapshot,
                build_input_descriptor_path=args.build_input_snapshot,
                build_a_invocation_stage=args.build_a_invocation_stage,
                build_a_result_stage=args.build_a_result_stage,
                build_b_invocation_stage=args.build_b_invocation_stage,
                build_b_result_stage=args.build_b_result_stage,
                repo_root=repo_root,
            )
        elif args.command == "stage":
            result = stage_receipt(evidence_dir, repo_root=repo_root)
        else:
            observed = {entry.name for entry in evidence_dir.iterdir()}
            if observed != set(PHASE_FILES):
                fail(
                    "native reproducibility phase file set is not exact: "
                    f"expected={sorted(PHASE_FILES)} observed={sorted(observed)}"
                )
            result = build_result(evidence_dir, repo_root=repo_root)
            receipt = _read_regular(
                evidence_dir / RECEIPT_NAME,
                MAX_JSON_BYTES,
                "reproducibility receipt",
            )
            if receipt != canonical_json(result):
                fail(
                    "verification.json is stale, noncanonical, or not freshly reproducible"
                )
    except (
        OSError,
        NativeReproducibilityError,
        native_build.NativeBuildError,
        release_invocation.InvocationError,
        release_result_stage.ResultStageError,
        source_snapshot.SnapshotError,
        build_input_snapshot.SnapshotError,
    ) as error:
        print(f"S19K_NATIVE_REPRODUCIBILITY_REFUSED: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
