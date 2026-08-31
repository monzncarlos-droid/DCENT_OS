#!/usr/bin/env python3
"""Adversarial desk tests for the S19k hermetic image producer."""

from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("s19k_hermetic_image_producer.py")
SPEC = importlib.util.spec_from_file_location("s19k_hermetic_image_producer", SCRIPT)
assert SPEC and SPEC.loader
producer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = producer
SPEC.loader.exec_module(producer)

FIXTURE_SCRIPT = Path(__file__).with_name("test_s19k_persistent_image_verify.py")
FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "s19k_persistent_image_fixture", FIXTURE_SCRIPT
)
assert FIXTURE_SPEC and FIXTURE_SPEC.loader
persistent_fixture = importlib.util.module_from_spec(FIXTURE_SPEC)
sys.modules[FIXTURE_SPEC.name] = persistent_fixture
FIXTURE_SPEC.loader.exec_module(persistent_fixture)


COMMIT = persistent_fixture.COMMIT
EPOCH = persistent_fixture.EPOCH
TOOLCHAIN = persistent_fixture.TOOLCHAIN
BUILDER_IMAGE = "registry.invalid/dcentos/s19k-builder@sha256:" + "3" * 64


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


FIXTURE_AMLOGIC = {
    "devicetree.dtb": b"fixture dtb",
    "fw-info": b"fixture fw info",
    "vmlinux.bin": b"fixture kernel",
}
FIXTURE_TOOLCHAIN = b"fixture toolchain archive"
FIXTURE_BUILDROOT_ARCHIVE = b"fixture Git archive"
FIXTURE_TOOLCHAIN_NAME = (
    "gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz"
)


def fixture_policy() -> dict:
    return {
        "amlogic_inputs": [
            {
                "bytes": len(FIXTURE_AMLOGIC[name]),
                "destination": f"amlogic/s19kpro/{name}",
                "name": name,
                "sha256": digest(FIXTURE_AMLOGIC[name]),
            }
            for name in ("devicetree.dtb", "fw-info", "vmlinux.bin")
        ],
        "authority": "dependency-materialization-only-no-build-release-install-or-flash-authority",
        "builder": {
            "dockerfile": {
                "bytes": 8,
                "path": "DCENT_OS_Antminer/scripts/docker/Dockerfile.s19k-hermetic",
                "sha256": digest(b"fixture\n"),
            },
            "image": BUILDER_IMAGE,
            "linux_amd64_manifest_digest": "sha256:" + "4" * 64,
            "oci_config_digest": "sha256:" + "5" * 64,
            "oci_index_digest": "sha256:" + BUILDER_IMAGE.rsplit("@sha256:", 1)[1],
            "toolchain_id": TOOLCHAIN,
            "versions": {
                "node": "22.23.2",
                "npm": "10.9.8",
                "python_cryptography": "38.0.4",
                "rust": "1.90.0",
                "rust_target": "aarch64-unknown-linux-musl",
                "zig": "0.13.0",
            },
        },
        "buildroot": {
            "commit": "7c8edc1b402efcd7bba2dabfe0b3be877adaed7a",
            "downloads_destination": "buildroot/dl",
            "source_archive_bytes": len(FIXTURE_BUILDROOT_ARCHIVE),
            "source_archive_sha256": digest(FIXTURE_BUILDROOT_ARCHIVE),
            "source_destination": "buildroot/source",
            "url": "https://github.com/buildroot/buildroot.git",
        },
        "cargo": {
            "lock": {"bytes": 1, "path": "Cargo.lock", "sha256": "1" * 64},
            "vendor_destination": "cargo/vendor",
        },
        "dashboard": {
            "lock": {"bytes": 1, "path": "package-lock.json", "sha256": "2" * 64},
            "npm_cache_destination": "dashboard/npm-cache",
        },
        "mandatory_selection_classes": list(producer.REQUIRED_DEPENDENCY_CLASSES),
        "materialization": {
            "builder_image_binding": "authenticated-policy-exact-name-at-sha256",
            "compiled_outputs_forbidden": True,
            "network_phase": "separate-source-fetch-only",
            "output": "source-only-exact-selection-for-later-host-sealing",
        },
        "schema": producer.DEPENDENCY_POLICY_SCHEMA,
        "selection_schema": producer.DEPENDENCY_SELECTION_SCHEMA,
        "source_commit_binding": {
            "policy_path": producer.DEPENDENCY_POLICY_RELATIVE,
            "verification": "admitted-immutable-snapshot-exact-tree-before-and-after",
        },
        "toolchain": {
            "archive": FIXTURE_TOOLCHAIN_NAME,
            "download_root": "buildroot/dl",
            "sha256": digest(FIXTURE_TOOLCHAIN),
            "toolchain_id_binding": "authenticated-policy-exact-token",
            "url": "https://example.invalid/toolchain",
        },
    }


def populate_dependency_fixture(root: Path) -> None:
    write(root / "buildroot/source/buildroot-source.tar", FIXTURE_BUILDROOT_ARCHIVE)
    write(root / "buildroot/dl/source.tar.xz", b"buildroot source archive")
    write(root / f"buildroot/dl/{FIXTURE_TOOLCHAIN_NAME}", FIXTURE_TOOLCHAIN)
    write(root / "cargo/vendor/fixture/src/lib.rs", b"cargo source\n")
    write(root / "dashboard/npm-cache/content-v2/sha512/fixture", b"npm source\n")
    for name, raw in FIXTURE_AMLOGIC.items():
        write(root / f"amlogic/s19kpro/{name}", raw)


def dependency_class(relative: str) -> str:
    if (
        relative.startswith("buildroot/dl/")
        and Path(relative).name == FIXTURE_TOOLCHAIN_NAME
    ):
        return "toolchain-archive"
    if relative.startswith("buildroot/source/"):
        return "buildroot-source"
    if relative.startswith("buildroot/dl/"):
        return "buildroot-download"
    if relative.startswith("cargo/vendor/"):
        return "cargo-source"
    if relative.startswith("dashboard/npm-cache/"):
        return "dashboard-dependency"
    if relative.startswith("amlogic/s19kpro/"):
        return "amlogic-input"
    return "cargo-source"


def write(path: Path, value: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return path


def install_policy_fixture(test_case: unittest.TestCase, root: Path) -> Path:
    raw = producer.canonical_json(fixture_policy())
    patcher = mock.patch.object(producer, "DEPENDENCY_POLICY_SHA256", digest(raw))
    patcher.start()
    test_case.addCleanup(patcher.stop)
    return write(root / "dependency-policy.json", raw)


def selection_for(root: Path, classes: dict[str, str] | None = None) -> dict:
    classes = classes or {}
    inputs = []
    for path in sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda item: item.relative_to(root).as_posix().encode("utf-8"),
    ):
        raw = path.read_bytes()
        relative = path.relative_to(root).as_posix()
        mode = 0o755 if os.stat(path).st_mode & 0o111 else 0o644
        inputs.append(
            {
                "path": relative,
                "class": classes.get(relative, dependency_class(relative)),
                "sha256": digest(raw),
                "bytes": len(raw),
                "mode": mode,
            }
        )
    return {
        "schema": producer.DEPENDENCY_SELECTION_SCHEMA,
        "source_commit": COMMIT,
        "builder_image": BUILDER_IMAGE,
        "toolchain_id": TOOLCHAIN,
        "inputs": inputs,
    }


def make_build_stage(
    root: Path,
    label: str,
    package: bytes,
    *,
    build_id: str | None = None,
    build_root_id: str | None = None,
    source_snapshot_id: str = "1" * 64,
    dependency_bundle_id: str = "2" * 64,
    network_used: bool = False,
) -> Path:
    build_id = build_id or f"build-{label}-fixture"
    build_root_id = build_root_id or f"clean-root-{label}-fixture"
    runtime_id = f"runtime-{label}-fixture"
    stage = root / f"result-{label}"
    stage.mkdir()
    write(stage / "package.tar", package)
    receipt = {
        "schema": producer.BUILD_ATTESTATION_SCHEMA,
        "build_id": build_id,
        "build_root_id": build_root_id,
        "clean_build": True,
        "build_cache_reused": False,
        "network_used": network_used,
        "source_commit": COMMIT,
        "source_date_epoch": EPOCH,
        "build_target": producer.BUILD_TARGET,
        "build_arch": producer.BUILD_ARCH,
        "toolchain_id": TOOLCHAIN,
        "package_name": f"build-{label}.tar",
        "package_sha256": digest(package),
        "package_bytes": len(package),
    }
    write(stage / "receipt.json", producer.canonical_json(receipt))
    observation = {
        "schema": producer.RUNTIME_OBSERVATION_SCHEMA,
        "runtime_id": runtime_id,
        "build_id": build_id,
        "build_root_id": build_root_id,
        "builder_image": BUILDER_IMAGE,
        "source_snapshot_id": source_snapshot_id,
        "dependency_bundle_id": dependency_bundle_id,
        "release_input_id": "9" * 64,
        "network_mode": "bridge" if network_used else "none",
        "network_boundary_inspected": True,
        "read_only_rootfs": True,
        "privileged": False,
        "build_cache_reused": False,
        "exit_code": 0,
        "package_relative_path": f"result/{producer.INNER_PACKAGE_NAME}",
        "build_log_relative_path": "logs/build.log",
    }
    observation_raw = producer.canonical_json(observation)
    inner_log = b"fabricated fixture inner log\n"
    owner = {
        "schema": producer.BUILD_RESULT_SCHEMA,
        "build_id": build_id,
        "build_root_id": build_root_id,
        "builder_image": BUILDER_IMAGE,
        "toolchain_id": TOOLCHAIN,
        "source_commit": COMMIT,
        "source_date_epoch": EPOCH,
        "source_snapshot_id": source_snapshot_id,
        "dependency_bundle_id": dependency_bundle_id,
        "release_input_id": "9" * 64,
        "runtime_id": runtime_id,
        "runtime_observation_sha256": digest(observation_raw),
        "inner_build_log_sha256": digest(inner_log),
        "network_boundary": "oci-network-none-inspected",
        "network_used": network_used,
        "started_empty": True,
        "source_snapshot_verified_before_after": True,
        "dependency_bundle_verified_before_after": True,
        "result_publication": "opened-regular-file-hash-no-replace-fsync",
        "mutable_roots": [
            f"{build_root_id}:{role}" for role in producer.MUTABLE_ROOT_ROLES
        ],
    }
    write(stage / "result-owner.json", producer.canonical_json(owner))
    write(
        stage / "build.log",
        producer.RUNTIME_LOG_PREFIX
        + observation_raw
        + producer.INNER_LOG_PREFIX
        + inner_log,
    )
    return stage


def source_admission(root: Path) -> producer.SourceAdmission:
    snapshot = write(root / "source-stage/snapshot.json", b"{}\n")
    tree = root / "source-stage/tree"
    tree.mkdir()
    body = {
        "schema": producer.SOURCE_SCHEMA,
        "source_commit": COMMIT,
        "source_tree": "4" * 40,
        "source_date_epoch": EPOCH,
        "commit_signature_verified": True,
        "commit_signer_identity": "openpgp:" + "a" * 40,
        "signing_policy_id": "b" * 64,
        "clean_worktree_verified_before_and_after": True,
        "signature_verification_output_sha256": "5" * 64,
        "snapshot_id": "6" * 64,
        "snapshot_descriptor_sha256": "7" * 64,
        "source_files": [
            {
                "path": "DCENT_OS_Antminer/Makefile",
                "sha256": "8" * 64,
                "bytes": 1,
                "git_mode": "100644",
            }
        ],
    }
    receipt = dict(body)
    receipt["admission_id"] = digest(producer.canonical_json(body))
    return producer.SourceAdmission(receipt, snapshot, tree, "9" * 64)


class FakeOfflineRuntime:
    def __init__(
        self,
        package: bytes,
        *,
        network_mode: str = "none",
        interrupt: bool = False,
        after_build=None,
    ) -> None:
        self.package = package
        self.network_mode = network_mode
        self.interrupt = interrupt
        self.after_build = after_build
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        if self.interrupt:
            raise RuntimeError("simulated interrupted build")
        write(request.mutable_paths["result"] / producer.INNER_PACKAGE_NAME, self.package)
        write(request.mutable_paths["logs"] / "build.log", b"offline fixture build\n")
        if self.after_build is not None:
            self.after_build(request)
        return {
            "schema": producer.RUNTIME_OBSERVATION_SCHEMA,
            "runtime_id": f"fake-runtime-{request.label}",
            "build_id": request.build_id,
            "build_root_id": request.build_root_id,
            "builder_image": request.builder_image,
            "source_snapshot_id": request.source_snapshot_id,
            "dependency_bundle_id": request.dependency_bundle_id,
            "release_input_id": request.release_input_id,
            "network_mode": self.network_mode,
            "network_boundary_inspected": True,
            "read_only_rootfs": True,
            "privileged": False,
            "build_cache_reused": False,
            "exit_code": 0,
            "package_relative_path": f"result/{producer.INNER_PACKAGE_NAME}",
            "build_log_relative_path": "logs/build.log",
        }


class FakeIsolatedSignerRuntime:
    def __init__(self, signed: bytes, receipt: bytes) -> None:
        self.signed = signed
        self.receipt = receipt
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        runtime_id = "a" * 64
        signed_stage = request.output_parent / "signed"
        signed_stage.mkdir()
        package_path = write(
            signed_stage / "dcentos-sysupgrade-am3-s19kpro.tar", self.signed
        )
        receipt_path = write(signed_stage / "signing-receipt.json", self.receipt)
        inspect = {
            "Id": runtime_id,
            "Config": {
                "Hostname": "dcent-s19k-signer",
                "Domainname": "signer.invalid",
                "User": "1000:1000",
            },
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapDrop": ["ALL"],
            },
            "NetworkSettings": {"Networks": {"none": {}}},
            "Mounts": [
                {"Destination": "/dcent/source-snapshot"},
                {"Destination": "/dcent/public"},
                {"Destination": "/dcent/private/release.pem"},
                {"Destination": "/dcent/output"},
                {"Destination": "/run"},
            ],
        }
        before = producer.canonical_json(inspect)
        after = producer.canonical_json(inspect)
        log = b"fake isolated signer log\n"
        write(request.inspect_before_path, before)
        write(request.inspect_after_path, after)
        write(request.log_path, log)
        return {
            "schema": producer.SIGNER_RUNTIME_SCHEMA,
            "runtime_id": runtime_id,
            "signing_id": request.signing_id,
            "builder_image": request.builder_image,
            "network_mode": "none",
            "network_boundary_inspected_before_after": True,
            "read_only_rootfs": True,
            "privileged": False,
            "private_key_custody_id": request.private_key_custody["custody_id"],
            "host_preflight_id": request.host_preflight_id,
            "verifier_sha256": request.verifier_sha256,
            "signer_sha256": request.signer_sha256,
            "inspect_before_sha256": digest(before),
            "inspect_after_sha256": digest(after),
            "log_sha256": digest(log),
            "log_bytes": len(log),
            "signed_package_sha256": digest(package_path.read_bytes()),
            "signed_package_bytes": package_path.stat().st_size,
            "signing_receipt_sha256": digest(receipt_path.read_bytes()),
            "signing_receipt_bytes": receipt_path.stat().st_size,
            "container_removed_after_stop_proof": True,
            "install_authority_granted": False,
            "flash_authority_granted": False,
            "mutation_authority_granted": False,
        }


class FakeMaterializerRuntime:
    def __init__(
        self,
        *,
        network_mode: str = "unrestricted-bridge-source-fetch-intent",
        after_materialization=None,
        interrupt: bool = False,
    ) -> None:
        self.network_mode = network_mode
        self.after_materialization = after_materialization
        self.interrupt = interrupt
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        if self.interrupt:
            raise RuntimeError("simulated interrupted materializer")
        request.work_root.mkdir()
        populate_dependency_fixture(request.output_root)
        write(
            request.selection_path,
            producer.canonical_json(selection_for(request.output_root)),
        )
        write(request.log_path, b"source-only materializer fixture\n")
        inspect_before = producer.canonical_json({"phase": "before"})
        inspect_after = producer.canonical_json({"phase": "after"})
        write(request.inspect_before_path, inspect_before)
        write(request.inspect_after_path, inspect_after)
        if self.after_materialization is not None:
            self.after_materialization(request)
        return {
            "schema": producer.MATERIALIZER_OBSERVATION_SCHEMA,
            "runtime_id": "fake-materializer-runtime",
            "materialization_id": request.materialization_id,
            "builder_image": request.builder_image,
            "toolchain_id": request.toolchain_id,
            "source_commit": request.source_commit,
            "source_snapshot_id": request.source_snapshot_id,
            "network_mode": self.network_mode,
            "network_boundary_inspected": "container-config-only-no-egress-proof",
            "read_only_rootfs": True,
            "privileged": False,
            "build_cache_reused": False,
            "exit_code": 0,
            "output_relative_path": "output",
            "selection_relative_path": "selection.json",
            "log_relative_path": "materializer.log",
            "inspect_before_relative_path": "inspect-before.json",
            "inspect_before_sha256": digest(inspect_before),
            "inspect_after_relative_path": "inspect-after.json",
            "inspect_after_sha256": digest(inspect_after),
        }


class DependencyBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.materialized = self.root / "materialized"
        self.materialized.mkdir()
        populate_dependency_fixture(self.materialized)
        self.policy = install_policy_fixture(self, self.root)
        self.parent = self.root / "bundles"
        self.parent.mkdir()

    def write_selection(self, value: dict | None = None) -> Path:
        value = value or selection_for(self.materialized)
        return write(self.root / "selection.json", producer.canonical_json(value))

    def seal(self) -> producer.DependencyBundle:
        return producer.seal_dependency_bundle(
            self.materialized,
            self.write_selection(),
            self.policy,
            self.parent,
            expected_source_commit=COMMIT,
            expected_builder_image=BUILDER_IMAGE,
            expected_toolchain_id=TOOLCHAIN,
            strict_durability=False,
        )

    def test_exact_bundle_seals_reverifies_and_cleans_only_owned_paths(self) -> None:
        write(self.materialized / "cargo/vendor/serde/src/lib.rs", b"pub fn fixture() {}\n")
        write(self.materialized / "buildroot/dl/busybox.tar.xz", b"archive fixture")
        selection = selection_for(
            self.materialized,
            {
                "cargo/vendor/serde/src/lib.rs": "cargo-source",
                "buildroot/dl/busybox.tar.xz": "buildroot-download",
            },
        )
        self.write_selection(selection)
        bundle = producer.seal_dependency_bundle(
            self.materialized,
            self.root / "selection.json",
            self.policy,
            self.parent,
            expected_source_commit=COMMIT,
            expected_builder_image=BUILDER_IMAGE,
            expected_toolchain_id=TOOLCHAIN,
            strict_durability=False,
        )
        verified = producer.verify_dependency_bundle(
            bundle.descriptor,
            expected_source_commit=COMMIT,
            expected_builder_image=BUILDER_IMAGE,
            expected_toolchain_id=TOOLCHAIN,
        )
        self.assertEqual(verified["bundle_id"], bundle.bundle_id)
        producer.destroy_dependency_bundle(bundle.descriptor, bundle.destroy_token)
        self.assertFalse(bundle.stage.exists())

    def test_missing_or_extra_materialized_file_refuses(self) -> None:
        write(self.materialized / "cargo/vendor/a/src/lib.rs", b"a")
        selection = selection_for(self.materialized)
        write(self.materialized / "cargo/vendor/extra/src/lib.rs", b"extra")
        with self.assertRaisesRegex(producer.ProducerError, "exact set"):
            producer.seal_dependency_bundle(
                self.materialized,
                self.write_selection(selection),
                self.policy,
                self.parent,
                strict_durability=False,
            )

    def test_symlink_and_hard_link_ambiguity_refuse(self) -> None:
        source = write(self.materialized / "cargo/vendor/a/src/lib.rs", b"a")
        hard = self.materialized / "cargo/vendor/a/src/alias.rs"
        os.link(source, hard)
        with self.assertRaisesRegex(producer.ProducerError, "exactly one hard link"):
            producer.seal_dependency_bundle(
                self.materialized,
                self.write_selection(),
                self.policy,
                self.parent,
                strict_durability=False,
            )

        hard.unlink()
        link = self.materialized / "cargo/vendor/a/src/link.rs"
        try:
            link.symlink_to(source.name)
        except OSError:
            self.skipTest("host does not permit symlink creation")
        raw_selection = selection_for(self.materialized)
        # Path.is_file follows a link, so the selection is deliberately shaped
        # as an attacker might provide it; the tree audit must still refuse.
        with self.assertRaisesRegex(producer.ProducerError, "regular non-link"):
            producer.seal_dependency_bundle(
                self.materialized,
                self.write_selection(raw_selection),
                self.policy,
                self.parent,
                strict_durability=False,
            )

    def test_compiled_cache_paths_and_mutable_builder_identity_refuse(self) -> None:
        write(self.materialized / "cargo/target/release/dcentrald", b"compiled")
        value = selection_for(self.materialized)
        with self.assertRaisesRegex(producer.ProducerError, "compiled/cache"):
            producer._parse_dependency_selection(producer.canonical_json(value))
        value["inputs"][0]["path"] = "cargo/source/lib.rs"
        value["builder_image"] = "dcentos/s19k-builder:latest"
        with self.assertRaisesRegex(producer.ProducerError, "digest-pinned"):
            producer._parse_dependency_selection(producer.canonical_json(value))

        (self.materialized / "cargo/target/release/dcentrald").unlink()
        value = selection_for(self.materialized)
        value["builder_image"] = "registry.invalid/substituted@sha256:" + "9" * 64
        policy = fixture_policy()
        with self.assertRaisesRegex(producer.ProducerError, "authenticated policy"):
            producer._parse_dependency_selection(
                producer.canonical_json(value), policy=policy
            )

    def test_dependency_drift_and_cleanup_foreign_file_refuse(self) -> None:
        write(self.materialized / "cargo/vendor/a/src/lib.rs", b"a")
        bundle = self.seal()
        retained = bundle.inputs / "cargo/vendor/a/src/lib.rs"
        if os.name != "nt":
            os.chmod(retained, 0o600)
        retained.write_bytes(b"changed")
        with self.assertRaisesRegex(producer.ProducerError, "changed"):
            producer.verify_dependency_bundle(bundle.descriptor)

        # Restore the exact byte, then demonstrate that cleanup refuses an
        # unowned file rather than using a recursive wildcard.
        retained.write_bytes(b"a")
        write(bundle.stage / "foreign.txt", b"do not delete")
        with self.assertRaisesRegex(producer.ProducerError, "unowned"):
            producer.destroy_dependency_bundle(bundle.descriptor, bundle.destroy_token)
        self.assertEqual((bundle.stage / "foreign.txt").read_bytes(), b"do not delete")

    def test_output_collision_never_replaces_existing_stage_input(self) -> None:
        write(self.materialized / "cargo/vendor/a/src/lib.rs", b"a")
        bundle = self.seal()
        original = bundle.descriptor.read_bytes()
        with self.assertRaisesRegex(producer.ProducerError, "replace existing output"):
            producer.write_no_replace(bundle.descriptor, b"replacement")
        self.assertEqual(bundle.descriptor.read_bytes(), original)

    def test_policy_paths_cannot_be_mislabeled_and_nested_toolchain_is_exact(self) -> None:
        selection = selection_for(self.materialized)
        cargo = next(
            item for item in selection["inputs"] if item["class"] == "cargo-source"
        )
        dashboard = next(
            item
            for item in selection["inputs"]
            if item["class"] == "dashboard-dependency"
        )
        cargo["class"], dashboard["class"] = dashboard["class"], cargo["class"]
        with self.assertRaisesRegex(producer.ProducerError, "mislabeled"):
            producer.seal_dependency_bundle(
                self.materialized,
                self.write_selection(selection),
                self.policy,
                self.parent,
                strict_durability=False,
            )

        source = self.materialized / f"buildroot/dl/{FIXTURE_TOOLCHAIN_NAME}"
        nested = self.materialized / (
            "buildroot/dl/toolchain-external-linaro-aarch64/" + FIXTURE_TOOLCHAIN_NAME
        )
        nested.parent.mkdir(parents=True)
        source.replace(nested)
        nested_selection = selection_for(self.materialized)
        nested_path = next(
            item["path"]
            for item in nested_selection["inputs"]
            if item["class"] == "toolchain-archive"
        )
        self.assertEqual(
            nested_path,
            "buildroot/dl/toolchain-external-linaro-aarch64/"
            + FIXTURE_TOOLCHAIN_NAME,
        )
        bundle = producer.seal_dependency_bundle(
            self.materialized,
            self.write_selection(nested_selection),
            self.policy,
            self.parent,
            strict_durability=False,
        )
        self.assertEqual(
            producer.verify_dependency_bundle(bundle.descriptor)["bundle_id"],
            bundle.bundle_id,
        )

    def test_production_parent_requires_non_system_owner_mode_and_ext4(self) -> None:
        metadata = os.stat(self.parent)
        admitted = mock.Mock(
            st_uid=1000,
            st_gid=1000,
            st_mode=stat.S_IFDIR | 0o700,
        )
        with (
            mock.patch.object(producer, "_require_directory", return_value=admitted),
            mock.patch.object(producer.os, "getuid", return_value=1000, create=True),
            mock.patch.object(producer.os, "getgid", return_value=1000, create=True),
            mock.patch.object(
                producer, "_linux_mount_contract", return_value=("ext4", frozenset({"rw"}))
            ),
        ):
            self.assertIs(
                producer._require_private_ext4_parent(self.parent, "fixture parent"),
                admitted,
            )
            admitted.st_mode = stat.S_IFDIR | 0o755
            with self.assertRaisesRegex(producer.ProducerError, "exact mode 0700"):
                producer._require_private_ext4_parent(self.parent, "fixture parent")
            admitted.st_mode = stat.S_IFDIR | 0o700
            with mock.patch.object(producer.os, "getuid", return_value=999, create=True):
                with self.assertRaisesRegex(producer.ProducerError, ">=1000"):
                    producer._require_private_ext4_parent(self.parent, "fixture parent")

        self.assertTrue(stat.S_ISDIR(metadata.st_mode))

    def test_builder_oci_inspection_is_policy_bound(self) -> None:
        policy = fixture_policy()["builder"]
        inspected = {
            "Id": policy["oci_index_digest"],
            "RepoDigests": [BUILDER_IMAGE],
            "Os": "linux",
            "Architecture": "amd64",
            "Descriptor": {
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "digest": policy["oci_index_digest"],
            },
            "Config": {
                "Labels": {
                    "org.dcentral.dcentos.authority": (
                        "build-only-no-release-install-or-flash-authority"
                    ),
                    "org.dcentral.dcentos.rust-target": "aarch64-unknown-linux-musl",
                    "org.dcentral.dcentos.zig-version": "0.13.0",
                }
            },
        }
        adapter = object.__new__(producer.DockerOfflineBuildRuntime)

        def inspect(value):
            adapter._run = mock.Mock(
                return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps([value]).encode("utf-8"), b""
                )
            )

        inspect(inspected)
        self.assertEqual(
            adapter._verify_image(BUILDER_IMAGE, policy), policy["oci_index_digest"]
        )
        classic = copy.deepcopy(inspected)
        classic["Id"] = policy["oci_config_digest"]
        classic.pop("Descriptor")
        inspect(classic)
        self.assertEqual(
            adapter._verify_image(BUILDER_IMAGE, policy), policy["oci_config_digest"]
        )
        for field, replacement in (
            ("Architecture", "arm64"),
            ("Id", "sha256:" + "0" * 64),
        ):
            malformed = copy.deepcopy(inspected)
            malformed[field] = replacement
            inspect(malformed)
            with self.assertRaisesRegex(producer.ProducerError, "OCI policy"):
                adapter._verify_image(BUILDER_IMAGE, policy)


class MaterializerCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = source_admission(self.root)
        fixture_policy_path = install_policy_fixture(self, self.root)
        self.policy = write(
            self.source.tree.joinpath(
                *Path(producer.DEPENDENCY_POLICY_RELATIVE).parts
            ),
            fixture_policy_path.read_bytes(),
        )
        write(
            self.source.tree
            / "DCENT_OS_Antminer/scripts/docker/Dockerfile.s19k-hermetic",
            b"fixture\n",
        )
        self.materializer_parent = self.root / "materializer-runs"
        self.materializer_parent.mkdir()
        self.dependency_parent = self.root / "dependency-stages"
        self.dependency_parent.mkdir()
        self.held = {
            name: write(self.root / "held" / name, raw)
            for name, raw in FIXTURE_AMLOGIC.items()
        }

    def materialize(self, runtime: FakeMaterializerRuntime):
        return producer.materialize_and_seal_dependencies(
            runtime,
            self.source,
            self.materializer_parent,
            self.dependency_parent,
            builder_image=BUILDER_IMAGE,
            toolchain_id=TOOLCHAIN,
            amlogic_kernel=self.held["vmlinux.bin"],
            amlogic_dtb=self.held["devicetree.dtb"],
            amlogic_fw_info=self.held["fw-info"],
            strict_durability=False,
            source_verifier=lambda: None,
            buildroot_verifier=lambda _export, _policy: None,
        )

    def test_fresh_materializer_is_policy_bound_sealed_and_receipted(self) -> None:
        runtime = FakeMaterializerRuntime()
        materialized = self.materialize(runtime)
        self.assertEqual(len(runtime.requests), 1)
        verified = producer.verify_dependency_bundle(
            materialized.bundle.descriptor,
            expected_source_commit=COMMIT,
            expected_builder_image=BUILDER_IMAGE,
            expected_toolchain_id=TOOLCHAIN,
        )
        self.assertEqual(verified["bundle_id"], materialized.bundle.bundle_id)
        receipt = json.loads(materialized.receipt.read_text())
        receipt_id = receipt.pop("receipt_id")
        self.assertEqual(receipt_id, digest(producer.canonical_json(receipt)))
        self.assertEqual(receipt_id, materialized.receipt_id)
        self.assertEqual(receipt["dependency_bundle_id"], verified["bundle_id"])
        self.assertEqual(
            receipt["network_mode"], "unrestricted-bridge-source-fetch-intent"
        )
        self.assertFalse(receipt["install_authority_granted"])
        self.assertFalse(receipt["flash_authority_granted"])
        verified_receipt = producer.verify_materializer_receipt(
            materialized.receipt,
            materialized.bundle.descriptor,
            expected_source_commit=COMMIT,
            expected_builder_image=BUILDER_IMAGE,
            expected_toolchain_id=TOOLCHAIN,
        )
        self.assertEqual(verified_receipt["receipt_id"], materialized.receipt_id)
        materialized.observation_path.write_bytes(
            producer.canonical_json({"substituted": True})
        )
        with self.assertRaisesRegex(producer.ProducerError, "observation differs"):
            producer.verify_materializer_receipt(
                materialized.receipt, materialized.bundle.descriptor
            )

    def test_materializer_refuses_builder_or_dockerfile_outside_policy(self) -> None:
        runtime = FakeMaterializerRuntime()
        with self.assertRaisesRegex(producer.ProducerError, "builder image differs"):
            producer.materialize_and_seal_dependencies(
                runtime,
                self.source,
                self.materializer_parent,
                self.dependency_parent,
                builder_image="registry.invalid/substituted@sha256:" + "9" * 64,
                toolchain_id=TOOLCHAIN,
                amlogic_kernel=self.held["vmlinux.bin"],
                amlogic_dtb=self.held["devicetree.dtb"],
                amlogic_fw_info=self.held["fw-info"],
                strict_durability=False,
                source_verifier=lambda: None,
                buildroot_verifier=lambda _export, _policy: None,
            )
        self.assertEqual(runtime.requests, [])

        dockerfile = (
            self.source.tree
            / "DCENT_OS_Antminer/scripts/docker/Dockerfile.s19k-hermetic"
        )
        dockerfile.write_bytes(b"drifted\n")
        with self.assertRaisesRegex(producer.ProducerError, "Dockerfile differs"):
            self.materialize(runtime)
        self.assertEqual(runtime.requests, [])

    def test_materializer_boundary_drift_and_partial_outputs_refuse(self) -> None:
        for runtime, expected in (
            (FakeMaterializerRuntime(network_mode="bridge"), "network_mode"),
            (FakeMaterializerRuntime(interrupt=True), "simulated interrupted"),
            (
                FakeMaterializerRuntime(
                    after_materialization=lambda request: (
                        request.output_root / "cargo/vendor/unselected-empty"
                    ).mkdir()
                ),
                "exact set of files/directories",
            ),
            (
                FakeMaterializerRuntime(
                    after_materialization=lambda request: request.log_path.write_bytes(b"")
                ),
                "empty log",
            ),
            (
                FakeMaterializerRuntime(
                    after_materialization=lambda request: write(
                        request.runtime_root / "unapproved", b"extra"
                    )
                ),
                "inexact top-level ledger",
            ),
            (
                FakeMaterializerRuntime(
                    after_materialization=lambda request: (
                        request.invocation_root
                        / ".dcentos-s19k-materializer-owner"
                    ).write_bytes(b"changed\n")
                ),
                "owner sentinel changed",
            ),
            (
                FakeMaterializerRuntime(
                    after_materialization=lambda request: request.inspect_after_path.write_bytes(
                        producer.canonical_json({"phase": "substituted"})
                    )
                ),
                "differs from observation",
            ),
        ):
            with self.subTest(expected=expected):
                isolated_parent = self.root / f"run-{len(list(self.root.glob('run-*')))}"
                isolated_parent.mkdir()
                old_parent = self.materializer_parent
                self.materializer_parent = isolated_parent
                try:
                    with self.assertRaisesRegex(
                        (producer.ProducerError, RuntimeError), expected
                    ):
                        self.materialize(runtime)
                finally:
                    self.materializer_parent = old_parent
                failures = list(
                    isolated_parent.glob("dcentos-s19k-materializer-*/failure.json")
                )
                self.assertEqual(len(failures), 1)
                failure = json.loads(failures[0].read_text())
                self.assertEqual(
                    failure["classification"],
                    "network-phase-failed-never-clean-build-evidence",
                )
                self.assertFalse(failure["install_authority_granted"])

    def test_docker_materializer_inspection_binds_network_mounts_and_identity(self) -> None:
        runtime = FakeMaterializerRuntime()
        self.materialize(runtime)
        request = runtime.requests[0]
        adapter = object.__new__(producer.DockerDependencyMaterializer)
        adapter.container_user = "1000:1000"
        expected_sources = {
            "/dcent/source-snapshot": (request.source_snapshot.parent, False),
            "/dcent/held/vmlinux.bin": (request.amlogic_kernel, False),
            "/dcent/held/devicetree.dtb": (request.amlogic_dtb, False),
            "/dcent/held/fw-info": (request.amlogic_fw_info, False),
            "/dcent/materializer": (request.runtime_root, True),
        }
        mounts = [
            {
                "Type": "bind",
                "Source": os.fspath(path.resolve()),
                "Destination": destination,
                "RW": writable,
                "Propagation": "rprivate",
            }
            for destination, (path, writable) in expected_sources.items()
        ]
        inspected = {
            "Image": request.builder_image.rsplit("@", 1)[1],
            "Config": {
                "Image": request.builder_image,
                "User": "1000:1000",
                "WorkingDir": "/dcent/materializer",
                "Hostname": "dcent-s19k-fetch",
                "Domainname": "materializer.invalid",
                "Entrypoint": ["/bin/sh"],
                "Cmd": [producer.DockerDependencyMaterializer.DRIVER],
                "OpenStdin": False,
                "Tty": False,
                "Env": [
                    f"{name}={value}"
                    for name, value in producer.DockerDependencyMaterializer._materializer_environment(
                        request
                    ).items()
                ],
            },
            "HostConfig": {
                "NetworkMode": "bridge",
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapAdd": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "Devices": [],
                "PidsLimit": 8192,
                "PublishAllPorts": False,
                "PortBindings": {},
                "Links": [],
                "ExtraHosts": [],
                "VolumesFrom": [],
                "IpcMode": "none",
                "PidMode": "private",
                "UTSMode": "private",
                "RestartPolicy": {"Name": "no"},
                "LogConfig": {"Type": "none", "Config": {}},
                "Tmpfs": {"/run": "rw,noexec,nosuid,nodev,size=16777216"},
            },
            "Mounts": mounts,
            "NetworkSettings": {"Networks": {"bridge": {}}},
        }
        adapter._verify_materializer_boundary(inspected, request)

        mutations = []
        offline = copy.deepcopy(inspected)
        offline["HostConfig"]["NetworkMode"] = "none"
        mutations.append(offline)
        root_user = copy.deepcopy(inspected)
        root_user["Config"]["User"] = "0:0"
        mutations.append(root_user)
        injected = copy.deepcopy(inspected)
        injected["Config"]["Env"].append("DCENT_FLASH_AUTHORITY=1")
        mutations.append(injected)
        writable_source = copy.deepcopy(inspected)
        writable_source["Mounts"][0]["RW"] = True
        mutations.append(writable_source)
        published_port = copy.deepcopy(inspected)
        published_port["HostConfig"]["PublishAllPorts"] = True
        mutations.append(published_port)
        substituted_image = copy.deepcopy(inspected)
        substituted_image["Image"] = "sha256:" + "0" * 64
        mutations.append(substituted_image)
        inherited_injection = copy.deepcopy(inspected)
        inherited_injection["Config"]["Env"].append("LD_PRELOAD=/tmp/attack.so")
        mutations.append(inherited_injection)
        for index, malformed in enumerate(mutations):
            with self.subTest(mutation=index):
                with self.assertRaises(producer.ProducerError):
                    adapter._verify_materializer_boundary(malformed, request)

    def test_buildroot_archive_is_policy_bound_without_host_git(self) -> None:
        exported = self.root / "exported-buildroot"
        exported.mkdir()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            makefile = tarfile.TarInfo("Makefile")
            makefile.size = 5
            makefile.mode = 0o644
            archive.addfile(makefile, io.BytesIO(b"all:\n"))
            link = tarfile.TarInfo("system/skeleton/dev/fd")
            link.type = tarfile.SYMTYPE
            link.linkname = "/proc/self/fd"
            archive.addfile(link)
        archive_raw = buffer.getvalue()
        write(exported / "buildroot-source.tar", archive_raw)
        policy = {
            "source_archive_bytes": len(archive_raw),
            "source_archive_sha256": digest(archive_raw),
        }
        with mock.patch.object(
            producer, "_git", side_effect=AssertionError("host Git must not run")
        ):
            producer._verify_materialized_buildroot_archive(exported, policy)

        write(exported / "buildroot-source.tar", b"drift")
        with self.assertRaisesRegex(producer.ProducerError, "authenticated policy bytes"):
            producer._verify_materialized_buildroot_archive(exported, policy)

    def test_docker_materializer_execute_removes_only_success_and_retains_failure(self) -> None:
        seed_runtime = FakeMaterializerRuntime()
        self.materialize(seed_runtime)
        seed = seed_runtime.requests[0]
        container_id = "a" * 64

        def request_for(label: str):
            invocation = self.root / f"docker-{label}"
            invocation.mkdir()
            runtime_root = invocation / "runtime"
            runtime_root.mkdir()
            return replace(
                seed,
                materialization_id=f"docker-{label}",
                invocation_root=invocation,
                runtime_root=runtime_root,
                work_root=runtime_root / "work",
                output_root=runtime_root / "output",
                selection_path=runtime_root / "selection.json",
                log_path=invocation / "materializer.log",
                inspect_before_path=invocation / "inspect-before.json",
                inspect_after_path=invocation / "inspect-after.json",
            )

        def adapter_for(after_state):
            adapter = object.__new__(producer.DockerDependencyMaterializer)
            adapter.docker_binary = "docker"
            adapter.timeout_seconds = 10
            adapter.container_user = "1000:1000"
            calls = []

            def fake_run(arguments, **_kwargs):
                calls.append(tuple(arguments))
                stdout = container_id.encode("ascii") + b"\n" if arguments[0] == "create" else b""
                return subprocess.CompletedProcess(arguments, 0, stdout, b"")

            adapter._run = mock.Mock(side_effect=fake_run)
            adapter._verify_image = mock.Mock()
            adapter._inspect = mock.Mock(
                side_effect=[
                    {"phase": "before"},
                    {"phase": "after", "State": after_state},
                    {"State": {"Running": False}},
                ]
            )
            adapter._verify_materializer_boundary = mock.Mock()

            def attach(_container, log_path):
                write(log_path, b"bounded Docker output\n")
                return 0

            adapter._run_attached_to_new_log = mock.Mock(side_effect=attach)
            return adapter, calls

        success_request = request_for("success")
        success_adapter, success_calls = adapter_for(
            {"Running": False, "OOMKilled": False, "ExitCode": 0}
        )
        with mock.patch.object(producer, "_fsync_directory", return_value=None):
            observation = success_adapter.execute(success_request)
        self.assertEqual(observation["runtime_id"], container_id)
        self.assertIn(("rm", container_id), success_calls)
        create = next(call for call in success_calls if call[0] == "create")
        self.assertIn("--user", create)
        self.assertIn("1000:1000", create)
        self.assertNotIn("--pid", create)
        self.assertNotIn("--uts", create)
        self.assertTrue(success_request.inspect_before_path.is_file())
        self.assertTrue(success_request.inspect_after_path.is_file())

        failed_request = request_for("failed")
        failed_adapter, failed_calls = adapter_for(
            {"Running": False, "OOMKilled": True, "ExitCode": 137}
        )
        with mock.patch.object(producer, "_fsync_directory", return_value=None):
            with self.assertRaisesRegex(producer.ProducerError, "retained"):
                failed_adapter.execute(failed_request)
        self.assertNotIn(("rm", container_id), failed_calls)
        self.assertIn(("kill", container_id), failed_calls)

        interrupted_request = request_for("interrupted")
        interrupted_adapter, interrupted_calls = adapter_for(
            {"Running": False, "OOMKilled": False, "ExitCode": 0}
        )
        interrupted_adapter._run_attached_to_new_log = mock.Mock(
            side_effect=KeyboardInterrupt("simulated operator interrupt")
        )
        with mock.patch.object(producer, "_fsync_directory", return_value=None):
            with self.assertRaises(KeyboardInterrupt):
                interrupted_adapter.execute(interrupted_request)
        self.assertIn(("kill", container_id), interrupted_calls)
        self.assertNotIn(("rm", container_id), interrupted_calls)

        collision_request = request_for("name-collision")
        collision_adapter, _ = adapter_for(
            {"Running": False, "OOMKilled": False, "ExitCode": 0}
        )
        collision_adapter._run = mock.Mock(
            side_effect=producer.ProducerError("Docker create name is already in use")
        )
        collision_adapter._stop_and_verify_container = mock.Mock()
        with self.assertRaisesRegex(producer.ProducerError, "already in use"):
            collision_adapter.execute(collision_request)
        collision_adapter._stop_and_verify_container.assert_not_called()

        uncertain = object.__new__(producer.DockerOfflineBuildRuntime)
        uncertain._run = mock.Mock()
        uncertain._inspect = mock.Mock(return_value={"State": {"Running": True}})
        with self.assertRaisesRegex(producer.ProducerError, "unable to prove"):
            uncertain._stop_and_verify_container(container_id)
        uncertain._run = mock.Mock(
            return_value=subprocess.CompletedProcess((), 0, b"malformed\n", b"")
        )
        uncertain._inspect = mock.Mock(side_effect=RuntimeError("inspect unavailable"))
        with self.assertRaisesRegex(producer.ProducerError, "unable to prove"):
            uncertain._stop_and_verify_container(container_id)

        absent = object.__new__(producer.DockerOfflineBuildRuntime)
        absent._run = mock.Mock(
            side_effect=lambda arguments, **_kwargs: subprocess.CompletedProcess(
                arguments, 0, b"", b""
            )
        )
        absent._inspect = mock.Mock(side_effect=RuntimeError("inspect unavailable"))
        absent._stop_and_verify_container(container_id)
        listing = absent._run.call_args_list[-1].args[0]
        self.assertIn(f"id={container_id}", listing)
        self.assertNotIn(f"name=^/{container_id}$", listing)

        retained = object.__new__(producer.DockerOfflineBuildRuntime)
        retained._run = mock.Mock(
            side_effect=lambda arguments, **_kwargs: subprocess.CompletedProcess(
                arguments,
                0,
                container_id.encode("ascii") + b"\n" if arguments[0] == "container" else b"",
                b"",
            )
        )
        retained._inspect = mock.Mock(side_effect=RuntimeError("inspect unavailable"))
        with self.assertRaisesRegex(producer.ProducerError, "unable to prove"):
            retained._stop_and_verify_container(container_id)

        malformed = object.__new__(producer.DockerOfflineBuildRuntime)
        malformed._run = mock.Mock(
            side_effect=lambda arguments, **_kwargs: subprocess.CompletedProcess(
                arguments,
                0,
                b"not-a-canonical-container-id\n" if arguments[0] == "container" else b"",
                b"",
            )
        )
        malformed._inspect = mock.Mock(side_effect=RuntimeError("inspect unavailable"))
        with self.assertRaisesRegex(producer.ProducerError, "unable to prove"):
            malformed._stop_and_verify_container(container_id)


class ReleaseInputAndCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        from cryptography.hazmat.primitives import serialization

        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        fixture_root = self.root / "persistent-fixture"
        fixture_root.mkdir()
        self.fixture = persistent_fixture.Fixture(fixture_root)
        self.private = write(
            self.root / "operator-private.pem",
            self.fixture.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        self.release_parent = self.root / "release-input-stages"
        self.release_parent.mkdir()
        self.release_inputs = producer.seal_release_inputs(
            fixture_root / "trusted-release-key.pem",
            fixture_root / "native-owner-verification.json",
            fixture_root / "stock-recovery-verification.json",
            self.release_parent,
            expected_release_key_sha256=self.fixture.expected_key_sha,
            strict_durability=False,
        )
        self.materialized = self.root / "materialized"
        populate_dependency_fixture(self.materialized)
        self.policy = install_policy_fixture(self, self.root)
        selection_path = write(
            self.root / "dependency-selection.json",
            producer.canonical_json(selection_for(self.materialized)),
        )
        dependency_parent = self.root / "dependency-stages"
        dependency_parent.mkdir()
        self.dependencies = producer.seal_dependency_bundle(
            self.materialized,
            selection_path,
            self.policy,
            dependency_parent,
            expected_source_commit=COMMIT,
            expected_builder_image=BUILDER_IMAGE,
            expected_toolchain_id=TOOLCHAIN,
            strict_durability=False,
        )
        self.source = source_admission(self.root)
        self.build_parent = self.root / "builds"
        self.build_parent.mkdir()
        self.package = (
            fixture_root / persistent_fixture.image.BUILD_PACKAGE_FILES[0]
        ).read_bytes()
        self.signed = (
            fixture_root / persistent_fixture.image.SIGNED_PACKAGE_FILE
        ).read_bytes()
        self.signing_receipt = (
            fixture_root / persistent_fixture.image.SIGNING_RECEIPT_FILE
        ).read_bytes()
        self.host_preflight = json.loads(
            (fixture_root / persistent_fixture.image.HOST_PREFLIGHT_FILE).read_text()
        )

    def execute(self, runtime: FakeOfflineRuntime):
        return producer.execute_two_offline_builds(
            runtime,
            self.source,
            self.dependencies,
            self.release_inputs,
            self.build_parent,
            expected_release_key_sha256=self.fixture.expected_key_sha,
            strict_durability=False,
            source_verifier=lambda: None,
        )

    def publish(self, pair, output: Path, **overrides):
        arguments = {
            "source_commit": COMMIT,
            "source_date_epoch": EPOCH,
            "toolchain_id": TOOLCHAIN,
            "expected_release_key_sha256": self.fixture.expected_key_sha,
            "strict_durability": False,
            "host_preflight": self.host_preflight,
            "dependency_stage": self.dependencies.stage,
            "verifier": persistent_fixture.image,
            "signer_runtime": FakeIsolatedSignerRuntime(
                self.signed, self.signing_receipt
            ),
        }
        arguments.update(overrides)
        return producer.publish_verified_evidence(
            pair,
            self.release_inputs,
            self.private,
            output,
            **arguments,
        )

    def test_release_inputs_are_public_only_no_replace_and_exactly_owned(self) -> None:
        verified = producer.verify_release_inputs(
            self.release_inputs.descriptor,
            expected_release_key_sha256=self.fixture.expected_key_sha,
        )
        self.assertTrue(verified["private_key_excluded"])
        original = self.release_inputs.public_key.read_bytes()
        with self.assertRaisesRegex(producer.ProducerError, "replace existing output"):
            producer.write_no_replace(self.release_inputs.public_key, b"forged")
        self.assertEqual(self.release_inputs.public_key.read_bytes(), original)
        self.assertFalse((self.release_inputs.stage / "private-signing-key.pem").exists())
        producer.destroy_release_inputs(
            self.release_inputs.descriptor,
            self.release_inputs.destroy_token,
            expected_release_key_sha256=self.fixture.expected_key_sha,
        )
        self.assertFalse(self.release_inputs.stage.exists())

    def test_public_input_seal_never_reads_or_stages_private_key(self) -> None:
        parent = self.root / "wrong-input-stage"
        parent.mkdir()
        with mock.patch.object(
            producer, "_admit_private_signing_key_path"
        ) as private_admission:
            sealed = producer.seal_release_inputs(
                self.fixture.root / "trusted-release-key.pem",
                self.fixture.root / "native-owner-verification.json",
                self.fixture.root / "stock-recovery-verification.json",
                parent,
                expected_release_key_sha256=self.fixture.expected_key_sha,
                strict_durability=False,
            )
        private_admission.assert_not_called()
        self.assertFalse((sealed.stage / "private-signing-key.pem").exists())

    def test_coordinator_allocates_distinct_roots_and_passes_real_verifier(self) -> None:
        runtime = FakeOfflineRuntime(self.package)
        pair = self.execute(runtime)
        self.assertEqual(len(runtime.requests), 2)
        self.assertNotEqual(
            runtime.requests[0].build_root_id, runtime.requests[1].build_root_id
        )
        self.assertFalse(
            set(runtime.requests[0].mutable_paths.values())
            & set(runtime.requests[1].mutable_paths.values())
        )
        output = self.root / "coordinated-evidence"
        result = self.publish(pair, output)
        self.assertTrue(result["persistent_image_evidence_verified"])
        self.assertFalse(result["production_ready"])
        self.assertFalse(result["install_authority_granted"])
        self.assertFalse(result["flash_authority_granted"])
        outside = write(self.build_parent / "operator-note.txt", b"keep\n")
        for root, token in zip(pair.build_roots, pair.build_root_destroy_tokens):
            producer.destroy_build_root(root, token, strict_cleanup=False)
            self.assertFalse(root.exists())
        self.assertEqual(outside.read_bytes(), b"keep\n")
        self.assertTrue(pair.build_a.stage.exists())
        self.assertTrue(pair.build_b.stage.exists())

    def test_network_enabled_runtime_and_interruption_retain_failed_nonclean_root(self) -> None:
        for runtime, expected in (
            (FakeOfflineRuntime(self.package, network_mode="bridge"), "network_mode"),
            (FakeOfflineRuntime(self.package, interrupt=True), "simulated interrupted"),
        ):
            with self.subTest(expected=expected):
                isolated_parent = self.root / f"failure-{expected.replace(' ', '-')}"
                isolated_parent.mkdir()
                old_parent = self.build_parent
                self.build_parent = isolated_parent
                try:
                    with self.assertRaisesRegex((producer.ProducerError, RuntimeError), expected):
                        self.execute(runtime)
                finally:
                    self.build_parent = old_parent
                failures = list(isolated_parent.glob("dcentos-s19k-build-a-*/failure.json"))
                self.assertEqual(len(failures), 1)
                value = json.loads(failures[0].read_text())
                self.assertFalse(value["clean_build"])
                self.assertEqual(value["classification"], "failed-not-resumable-as-clean")

    def test_dependency_mutation_after_runtime_refuses_before_clean_attestation(self) -> None:
        retained = self.dependencies.inputs / "cargo/vendor/fixture/src/lib.rs"

        def mutate(_request) -> None:
            if os.name != "nt":
                os.chmod(retained, 0o600)
            retained.write_bytes(b"mutated\n")

        runtime = FakeOfflineRuntime(self.package, after_build=mutate)
        with self.assertRaisesRegex(producer.ProducerError, "changed"):
            self.execute(runtime)
        self.assertEqual(
            len(list(self.build_parent.glob("dcentos-s19k-build-a-*/failure.json"))),
            1,
        )

    def test_fabricated_or_consumed_pair_capability_cannot_publish(self) -> None:
        pair = self.execute(FakeOfflineRuntime(self.package))
        fabricated = producer.ExecutedBuildPair(
            pair.build_a,
            pair.build_b,
            pair.build_roots,
            pair.build_root_destroy_tokens,
            "0" * 64,
        )
        with self.assertRaisesRegex(producer.ProducerError, "unknown, consumed"):
            self.publish(fabricated, self.root / "fabricated")
        self.publish(pair, self.root / "one-use")
        with self.assertRaisesRegex(producer.ProducerError, "unknown, consumed"):
            self.publish(pair, self.root / "replayed")

    def test_ab_mismatch_refuses_before_capability_issuance(self) -> None:
        class MismatchRuntime(FakeOfflineRuntime):
            def execute(self, request):
                self.package = b"build-a" if request.label == "a" else b"build-b"
                return super().execute(request)

        before = set(producer._ISSUED_BUILD_PAIR_CAPABILITIES)
        with self.assertRaisesRegex(producer.ProducerError, "package bytes differ"):
            self.execute(MismatchRuntime(b"unused"))
        self.assertEqual(set(producer._ISSUED_BUILD_PAIR_CAPABILITIES), before)

    def test_wrong_key_preflight_and_existing_output_fail_closed(self) -> None:
        pair = self.execute(FakeOfflineRuntime(self.package))
        with self.assertRaisesRegex(producer.ProducerError, "invalid or stale"):
            self.publish(
                pair,
                self.root / "wrong-key",
                expected_release_key_sha256="0" * 64,
            )
        output = self.root / "existing"
        output.mkdir()
        sentinel = write(output / "sentinel", b"keep")
        with self.assertRaisesRegex(producer.ProducerError, "replace existing evidence"):
            self.publish(pair, output)
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_docker_inspection_binds_exact_sources_and_privilege_boundary(self) -> None:
        runtime = FakeOfflineRuntime(self.package)
        pair = self.execute(runtime)
        self.addCleanup(
            producer._ISSUED_BUILD_PAIR_CAPABILITIES.pop,
            pair.publication_capability,
            None,
        )
        request = runtime.requests[0]
        adapter = object.__new__(producer.DockerOfflineBuildRuntime)
        adapter.container_user = "1000:1000"
        expected_sources = {
            "/dcent/source-snapshot": (request.source_snapshot.parent, False),
            "/dcent/dependencies": (request.dependency_stage, False),
            "/dcent/release-inputs": (request.release_input_stage, False),
        }
        for role, destination in adapter.MUTABLE_MOUNTS.items():
            expected_sources[destination] = (request.mutable_paths[role], True)
        mounts = [
            {
                "Type": "bind",
                "Source": os.fspath(path.resolve()),
                "Destination": destination,
                "RW": writable,
                "Propagation": "rprivate",
            }
            for destination, (path, writable) in expected_sources.items()
        ]
        inspected = {
            "Image": request.builder_image.rsplit("@", 1)[1],
            "Config": {
                "Image": request.builder_image,
                "User": "1000:1000",
                "WorkingDir": "/dcent",
                "Hostname": "dcent-s19k-build",
                "Domainname": "hermetic.invalid",
                "Entrypoint": ["/bin/sh"],
                "Cmd": [
                    "/dcent/source-snapshot/tree/DCENT_OS_Antminer/scripts/"
                    "s19k_hermetic_build_inner.sh"
                ],
                "OpenStdin": False,
                "Tty": False,
                "Env": [
                    f"{name}={value}"
                    for name, value in adapter._build_environment(request).items()
                ],
            },
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapAdd": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "Devices": [],
                "PidsLimit": 8192,
                "PublishAllPorts": False,
                "PortBindings": {},
                "Links": [],
                "ExtraHosts": [],
                "VolumesFrom": [],
                "IpcMode": "none",
                "PidMode": "private",
                "UTSMode": "private",
                "RestartPolicy": {"Name": "no"},
                "LogConfig": {"Type": "none", "Config": {}},
                "Tmpfs": {
                    "/run": "rw,noexec,nosuid,nodev,size=16777216"
                },
            },
            "Mounts": mounts,
            "NetworkSettings": {"Networks": {"none": {}}},
        }
        adapter._verify_container_boundary(inspected, request)

        mutations = []
        network = copy.deepcopy(inspected)
        network["HostConfig"]["NetworkMode"] = "bridge"
        mutations.append(network)
        substituted_image = copy.deepcopy(inspected)
        substituted_image["Image"] = "sha256:" + "0" * 64
        mutations.append(substituted_image)
        reconnected = copy.deepcopy(inspected)
        reconnected["NetworkSettings"]["Networks"] = {"bridge": {}}
        mutations.append(reconnected)
        substituted = copy.deepcopy(inspected)
        substituted["Mounts"][0]["Source"] = os.fspath(self.root.resolve())
        mutations.append(substituted)
        propagated = copy.deepcopy(inspected)
        propagated["Mounts"][0]["Propagation"] = "rshared"
        mutations.append(propagated)
        privileged = copy.deepcopy(inspected)
        privileged["HostConfig"]["Privileged"] = True
        mutations.append(privileged)
        injected_environment = copy.deepcopy(inspected)
        injected_environment["Config"]["Env"].append("LD_PRELOAD=/tmp/attack.so")
        mutations.append(injected_environment)
        logging_enabled = copy.deepcopy(inspected)
        logging_enabled["HostConfig"]["LogConfig"] = {"Type": "json-file"}
        mutations.append(logging_enabled)
        extra = copy.deepcopy(inspected)
        extra["Mounts"].append(
            {
                "Type": "bind",
                "Source": os.fspath(self.root.resolve()),
                "Destination": "/unapproved",
                "RW": False,
                "Propagation": "rprivate",
            }
        )
        mutations.append(extra)
        for index, malformed in enumerate(mutations):
            with self.subTest(mutation=index):
                with self.assertRaises(producer.ProducerError):
                    adapter._verify_container_boundary(malformed, request)


class BuildResultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_network_enabled_or_interrupted_result_cannot_attest_clean(self) -> None:
        stage = make_build_stage(self.root, "a", b"package", network_used=True)
        with self.assertRaisesRegex(producer.ProducerError, "network_used"):
            producer.validate_build_result(
                stage,
                "a",
                source_commit=COMMIT,
                source_date_epoch=EPOCH,
                toolchain_id=TOOLCHAIN,
            )
        (stage / "receipt.json").unlink()
        with self.assertRaisesRegex(producer.ProducerError, "missing"):
            producer.validate_build_result(
                stage,
                "a",
                source_commit=COMMIT,
                source_date_epoch=EPOCH,
                toolchain_id=TOOLCHAIN,
            )

    def test_raw_stage_publication_command_is_not_exposed(self) -> None:
        help_text = producer.parser().format_help()
        self.assertNotIn("publish-evidence", help_text)
        self.assertNotIn("admit-source", help_text)
        produce_help = producer.parser()._subparsers._group_actions[0].choices[
            "produce"
        ].format_help()
        self.assertNotIn("--source-receipt", produce_help)
        self.assertNotIn("--source-snapshot ", produce_help)
        self.assertNotIn("--dependency-descriptor", produce_help)
        self.assertNotIn("--expected-source-commit", produce_help)
        self.assertNotIn("--gpg-binary", produce_help)
        self.assertNotIn("--trusted-gnupg-home", produce_help)
        self.assertNotIn("--private-key", produce_help)
        self.assertNotIn("--materializer-parent", produce_help)
        self.assertNotIn("--dependency-stage-parent", produce_help)
        self.assertNotIn("--builder-image", produce_help)
        with mock.patch.object(producer.subprocess, "run") as run, mock.patch.object(
            producer.tempfile, "mkdtemp"
        ) as allocate:
            self.assertEqual(producer.main(["produce"]), 1)
        run.assert_not_called()
        allocate.assert_not_called()


class SourceAdmissionTests(unittest.TestCase):
    def test_valid_but_unreviewed_openpgp_signer_is_refused(self) -> None:
        reviewed = "openpgp:" + "a" * 40
        unreviewed = "openpgp:" + "b" * 40
        status = (
            b"[GNUPG:] NEWSIG\n[GNUPG:] VALIDSIG "
            + b"b" * 40
            + b" 2026-08-30 0 4 0 1 10 00 "
            + b"b" * 40
            + b"\n"
        )
        observed = producer._openpgp_signer_from_verification(b"", status)
        self.assertEqual(observed, unreviewed)
        with self.assertRaisesRegex(producer.ProducerError, "outside the reviewed policy"):
            producer._require_reviewed_commit_signer(observed, [reviewed])
        producer._require_reviewed_commit_signer(reviewed, [reviewed])

    def test_mismatched_and_unsigned_source_refuse_before_snapshot_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(("git", "init", "-q", os.fspath(root)), check=True)
            subprocess.run(
                ("git", "-C", os.fspath(root), "config", "user.email", "fixture@example.invalid"),
                check=True,
            )
            subprocess.run(
                ("git", "-C", os.fspath(root), "config", "user.name", "Fixture"),
                check=True,
            )
            write(root / "source.txt", b"source\n")
            subprocess.run(("git", "-C", os.fspath(root), "add", "source.txt"), check=True)
            subprocess.run(
                ("git", "-C", os.fspath(root), "commit", "-q", "-m", "unsigned fixture"),
                check=True,
            )
            commit = subprocess.check_output(
                ("git", "-C", os.fspath(root), "rev-parse", "HEAD"), text=True
            ).strip()
            snapshots = root / "snapshots"
            snapshots.mkdir()
            with self.assertRaisesRegex(producer.ProducerError, "differs from selected"):
                producer.authenticate_source(root, "f" * 40, snapshots)
            with self.assertRaisesRegex(producer.ProducerError, "verify-commit"):
                producer.authenticate_source(root, commit, snapshots)
            self.assertEqual(list(snapshots.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
