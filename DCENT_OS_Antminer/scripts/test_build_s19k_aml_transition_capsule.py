# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only

"""Offline tests for the S19k Pro (Amlogic A113D/AXG) AML transition
capsule builder.

Validation tests are pure; signing tests exercise the exact release
signer (openssl + sign_release_artifact.py) and are skipped when openssl
is unavailable. The closing assertion of every signing test is the
TOOLBOX contract verdict: `capsule_ready` under a pinned dev authority,
and the exact release-ceremony gate (dev key vs the pinned production
key) is pinned as its own refusal case.

Dev signing keys are generated into pytest ``tmp_path`` directories
(Python-created temp dirs; never Git-Bash mktemp) per the workspace DACL.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPT = Path(__file__).with_name("build_s19k_aml_transition_capsule.py")
SPEC = importlib.util.spec_from_file_location("build_s19k_aml_transition_capsule", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

TOOLBOX_SOURCE = MODULE.TOOLBOX_SOURCE
if str(TOOLBOX_SOURCE) not in sys.path:
    sys.path.insert(0, str(TOOLBOX_SOURCE))

from dcent_toolbox.core import s19k_aml_first_install as sfi  # noqa: E402
from dcent_toolbox.core.s19k_aml_first_install import (  # noqa: E402
    SOURCE_BRAIINS_AML_S19K,
    SOURCE_LUXOS_AML_S19K,
    inspect_s19k_aml_capsule,
    plan_s19k_aml_first_install,
)

HAS_OPENSSL = shutil.which("openssl") is not None


@pytest.fixture()
def dev_authority(tmp_path: Path):
    key = Ed25519PrivateKey.generate()
    key_pem = tmp_path / "key.pem"
    key_pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    # The exact signer refuses a private key with group/other permission
    # bits (a load-bearing check — never weakened); satisfy it explicitly
    # so the fixture does not depend on the harness umask.
    key_pem.chmod(0o600)
    pub_pem = tmp_path / "pub.pem"
    pub_pem.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return key_pem, pub_pem


def _stage1(tmp_path: Path) -> Path:
    stage1 = tmp_path / "stage1.sh"
    stage1.write_bytes(b"#!/bin/sh\nset -e\n# mtd5 window transition (test)\n")
    return stage1


def _rootfs(tmp_path: Path, size: int = 4096) -> Path:
    # A synthetic-but-structurally-unique rootfs placeholder: the real
    # input is the uImage from build_amlogic_native_install.sh
    # --variant s19kpro (no such image artifact exists yet — see
    # ).
    rootfs = tmp_path / "dcent-rootfs.img"
    rootfs.write_bytes(b"S19K-AML-MTD5-WINDOW-ROOTFS" * (size // 27 + 1))
    with rootfs.open("r+b") as handle:
        handle.truncate(size)
    return rootfs


def _authorizer(tmp_path: Path) -> Path:
    authorizer = tmp_path / "s19k-stage1-authorizer"
    if not authorizer.exists():
        authorizer.write_bytes(b"S19K-STAGE1-AUTHORIZER-TEST-FIXTURE-NOT-EXECUTABLE\n")
    return authorizer


def _custody_inputs(tmp_path: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for role, member in MODULE.CUSTODY_MEMBER_BY_ROLE.items():
        path = tmp_path / f"pytest-{Path(member).name}"
        path.write_bytes(f"{role}-TEST-FIXTURE-NO-AUTHORITY\n".encode("ascii"))
        result[role] = path
    return result


def _base_args(tmp_path: Path, stage1: Path, rootfs: Path) -> list[str]:
    authorizer = _authorizer(tmp_path)
    custody = _custody_inputs(tmp_path)
    args = [
        "--board-target", "am3-s19kpro",
        "--source-layout", SOURCE_BRAIINS_AML_S19K,
        "--version", "v0.1.0-test",
        "--post-install-artifact", "dcentos-sysupgrade-am3-s19kpro.tar",
        "--migration-scope", "serial + pool config inventory",
        "--artifact-class", "test-fixture",
        "--signing-key-id", "c" * 64,
        "--stage1", str(stage1),
        "--stage1-authorizer", str(authorizer),
        "--member", f"{MODULE.CANONICAL_ROOTFS_MEMBER}={rootfs}",
    ]
    for role, path in custody.items():
        args.extend([f"--{role.replace('_', '-')}", str(path)])
    return args


def _mock_production_inputs(
    tmp_path: Path,
    monkeypatch,
    stage1: Path,
    rootfs: Path,
    pub_pem: Path,
    *,
    receipt_overrides: dict[str, object] | None = None,
    receipt_remove: tuple[str, ...] = (),
) -> tuple[Path, str]:
    public_hex = serialization.load_pem_public_key(pub_pem.read_bytes()).public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    monkeypatch.setattr(MODULE, "get_pinned_release_pubkey_hex", lambda: public_hex)
    monkeypatch.setattr(
        MODULE.signing_ceremony,
        "get_pinned_release_pubkey_hex",
        lambda: public_hex,
    )
    audit = tmp_path / "stage1-audit.json"
    audit.write_bytes(b'{"classification":"pytest-only"}\n')
    approval = MODULE.release_policy.Stage1Approval(
        implementation_id="pytest-reviewed-target-writer",
        audit_receipt_path=str(audit),
        audit_receipt_sha256=hashlib.sha256(audit.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        MODULE.release_policy,
        "approved_stage1",
        lambda sha, _root: approval
        if sha == hashlib.sha256(stage1.read_bytes()).hexdigest()
        else None,
    )
    source_commit = "d" * 40
    authorizer_audit = tmp_path / "authorizer-audit.json"
    authorizer_audit.write_bytes(b'{"classification":"pytest-target-kat"}\n')
    authorizer = _authorizer(tmp_path)
    authorizer_approval = MODULE.release_policy.Stage1AuthorizerApproval(
        implementation_id="pytest-reviewed-armv7-authorizer",
        source_snapshot_commit=source_commit,
        audit_receipt_path=str(authorizer_audit),
        audit_receipt_sha256=hashlib.sha256(
            authorizer_audit.read_bytes()
        ).hexdigest(),
        target_kat_verified=True,
    )
    monkeypatch.setattr(
        MODULE.release_policy,
        "approved_stage1_authorizer",
        lambda sha, _root, commit: authorizer_approval
        if sha == hashlib.sha256(authorizer.read_bytes()).hexdigest()
        and commit == source_commit
        else None,
    )
    monkeypatch.setattr(
        MODULE.release_policy,
        "approved_install_custody",
        lambda implementation_id, observed: observed
        if implementation_id == MODULE.release_policy.INSTALL_CUSTODY_IMPLEMENTATION_ID
        else None,
    )
    monkeypatch.setattr(
        MODULE,
        "_verified_source_snapshot",
        lambda expected: {
            "schema": MODULE.release_policy.SOURCE_SNAPSHOT_SCHEMA,
            "commit": expected,
            "tree": "e" * 40,
            "commit_signature_verified": True,
            "clean_worktree_verified": True,
        },
    )
    evidence = tmp_path / "persistent-evidence"
    evidence.mkdir()
    receipt = {
        "schema": MODULE.release_policy.PERSISTENT_IMAGE_SCHEMA,
        "phase_id": "persistent-image",
        "classification": "verified",
        "installable": True,
        "board": "am3-s19k",
        "image_sha256": hashlib.sha256(rootfs.read_bytes()).hexdigest(),
        "image_bytes": rootfs.stat().st_size,
        "package_sha256": "1" * 64,
        "package_bytes": rootfs.stat().st_size + 4096,
        "unsigned_package_sha256": "2" * 64,
        "unsigned_package_bytes": rootfs.stat().st_size + 2048,
        "a_b_unsigned_equality_verified": True,
        "private_key_excluded_from_builds": True,
        "isolated_post_ab_signing_verified": False,
        "post_ab_derivation_and_runtime_metadata_verified": True,
        "isolated_post_ab_signing_nonclaim": (
            MODULE.release_policy.PERSISTENT_IMAGE_SIGNING_ISOLATION_NONCLAIM
        ),
        "post_ab_signing_id": "3" * 64,
        "post_ab_signing_receipt_sha256": "4" * 64,
        "host_preflight_id": "5" * 64,
        "host_preflight_receipt_sha256": "6" * 64,
        "host_preflight_component_sha256": "7" * 64,
        "isolated_signer_runtime_id": "8" * 64,
        "isolated_signer_runtime_receipt_sha256": "9" * 64,
        "isolated_signer_private_key_custody_id": "a" * 64,
        "source_commit": source_commit,
        "source_date_epoch": 1_700_000_000,
        "release_key_sha256": hashlib.sha256(pub_pem.read_bytes()).hexdigest(),
        "release_key_id": "c" * 64,
        "release_manifest_public_key_hex": public_hex,
        "signed_manifest_sha256": "b" * 64,
        "persistent_image_contract_sha256": "c" * 64,
        "native_owner_verification_id": "d" * 64,
        "native_owner_receipt_sha256": "e" * 64,
        "native_owner_artifact_sha256": "f" * 64,
        "native_owner_source_files_sha256": "1" * 64,
        "native_owner_aarch64_compile_contract_bound": True,
        "reproducible_builds_verified": True,
        "signed_manifest_verified": True,
        "native_owner_artifact_bound": True,
        "stock_recovery_receipt_bound": True,
        "native_owner_source_artifact_build_binding_verified": True,
        "native_owner_clean_source_commit_bound": True,
        "stock_recovery_verification_id": "2" * 64,
        "stock_recovery_receipt_sha256": "3" * 64,
        "stock_recovery_device_id": "s19kpro-78",
        "aml_rootfs_geometry": {},
        "safeoff_boot_baseline": {},
        "install_authority_granted": False,
        "mutation_authority_granted": False,
        "nand_write_authorized": False,
        "live_hardware_contacted": False,
        "network_used": False,
    }
    receipt.update(receipt_overrides or {})
    for field_name in receipt_remove:
        receipt.pop(field_name, None)
    receipt["verification_id"] = hashlib.sha256(
        MODULE.persistent_image.canonical_json(receipt)
    ).hexdigest()
    verification = evidence / MODULE.persistent_image.VERIFICATION_FILE
    verification.write_bytes(MODULE.persistent_image.canonical_json(receipt))

    def verify(_directory, *, expected_release_key_sha256=None):
        assert expected_release_key_sha256 == hashlib.sha256(
            pub_pem.read_bytes()
        ).hexdigest()
        return receipt

    monkeypatch.setattr(MODULE.persistent_image, "verify_evidence", verify)
    return evidence, source_commit


# --- plan mode ------------------------------------------------------------------


def test_plan_pins_the_contract_and_writes_nothing(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    output = tmp_path / "capsule.tar.gz"
    rc = MODULE.main(
        _base_args(tmp_path, stage1, rootfs) + ["--plan", "--output", str(output)]
    )
    assert rc == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["transition_mechanism"] == "mtd5_rootfs_window_flag_commit"
    assert plan["board_target"] == "am3-s19kpro"
    assert plan["accepted_source_layouts"] == [SOURCE_BRAIINS_AML_S19K]
    assert plan["rootfs_window_hex"] == "0x02800000"
    authorizer = _authorizer(tmp_path)
    custody = _custody_inputs(tmp_path)
    assert plan["payload_bytes_total"] == (
        stage1.stat().st_size
        + authorizer.stat().st_size
        + rootfs.stat().st_size
        + sum(path.stat().st_size for path in custody.values())
    )
    assert [m["name"] for m in plan["members"]] == [
        "payload/dcent-rootfs.img",
        MODULE.STAGE1_AUTHORIZER_MEMBER,
        "transition/safeoff/dcentrald",
        "transition/safeoff/dcentrald_s19k.toml",
        "transition/safeoff/run_trial",
        "transition/safeoff/stock_restart_helper",
        "transition/safeoff/supervisor_custody_observer",
        "transition/stage1.sh",
    ]
    # the geometry block is the EXACT toolbox pin (never hand-entered)
    assert plan["manifest"]["nand_geometry"] == sfi.s19k_aml_geometry_pins()
    assert plan["manifest"]["schema"] == sfi.CAPSULE_SCHEMA
    assert plan["manifest"]["package_type"] == sfi.CAPSULE_PACKAGE_TYPE
    assert plan["manifest"]["artifact_class"] == "test-fixture"
    assert plan["manifest"]["production_image_attestation"] is None
    assert plan["manifest"]["signing_identity"] == {
        "profile": "test-only",
        "key_id": "c" * 64,
        "public_key_hex": None,
    }
    assert plan["manifest"]["transition_stage1"]["implementation_id"] == (
        "test-fixture-no-production-authority"
    )
    assert plan["manifest"]["transition_stage1_authorizer"] == {
        "schema": MODULE.release_policy.STAGE1_AUTHORIZER_SCHEMA,
        "member": MODULE.STAGE1_AUTHORIZER_MEMBER,
        "sha256": hashlib.sha256(authorizer.read_bytes()).hexdigest(),
        "bytes": authorizer.stat().st_size,
        "implementation_id": "test-fixture-no-production-authority",
        "target_kat_verified": False,
        "source_snapshot_commit": None,
    }
    custody_block = plan["manifest"]["install_custody"]
    assert custody_block["schema"] == MODULE.release_policy.INSTALL_CUSTODY_SCHEMA
    assert custody_block["implementation_id"] == (
        MODULE.release_policy.INSTALL_CUSTODY_IMPLEMENTATION_ID
    )
    assert custody_block["protocol"] == MODULE.release_policy.INSTALL_CUSTODY_PROTOCOL
    assert custody_block["mode"] == "install-custody-safeoff"
    assert custody_block["daemon_flag"] == "--s19k-install-custody-safeoff"
    assert custody_block["physical_safeoff_contract"] == "InstallCustodyGpio437Only"
    assert custody_block["reset_contract"] == "not-attempted"
    assert custody_block["transcript_schema"] == (
        "dcentos.s19k-install-custody-transcript/v1"
    )
    assert custody_block["terminal_receipt_schema"] == (
        "dcentos.s19k-install-custody-terminal-safeoff/v1"
    )
    assert custody_block["safeoff_receipt_schema"] == (
        "dcentos.s19k-install-custody-safeoff/v1"
    )
    assert custody_block["pending_receipt_schema"] == (
        "dcentos.s19k-install-custody-stock-restart-pending/v1"
    )
    assert custody_block["target_reference_config_path"] == (
        "/usr/share/dcentos/install-custody/dcentrald_s19k.toml"
    )
    assert custody_block["staged_config_basename"] == "dcentrald_s19k.toml"
    assert custody_block["source_layouts"] == [SOURCE_BRAIINS_AML_S19K]
    assert custody_block["target_identity_profiles"] == [
        "live88_two_bhb56903_slots_2_3"
    ]
    for role, path in custody.items():
        assert custody_block[role] == {
            "member": MODULE.CUSTODY_MEMBER_BY_ROLE[role],
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size,
        }
    staging = plan["manifest"]["target_staging_budget"]
    assert staging["rootfs_readback_mode"] == "streaming_sha256_no_rootfs_copy"
    assert staging["coexisting_capsule_member_bytes"] == plan["payload_bytes_total"]
    assert staging["required_tmp_free_bytes"] == (
        plan["payload_bytes_total"] + 524288 + 8388608
    )
    assert [item["member"] for item in staging["counted_members"]] == [
        item["name"] for item in plan["members"]
    ]
    assert not output.exists()


def test_default_output_name_is_the_contract_convention(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    rc = MODULE.main(
        _base_args(tmp_path, stage1, rootfs)
        + ["--version", "v1.0.0", "--plan"]
    )
    assert rc == 0
    plan = json.loads(capsys.readouterr().out)
    name = Path(plan["output"]).name
    assert name == "DCENT_FIRSTINSTALL_AM3_S19kPro_v1.0.0.tar.gz"
    assert name == sfi.EXPECTED_CAPSULE_NAME.replace("<version>", "v1.0.0")


# --- refusal cases ---------------------------------------------------------------


def test_stage1_is_required_for_every_capsule(tmp_path, capsys):
    rootfs = _rootfs(tmp_path)
    rc = MODULE.main(
        [
            "--board-target", "am3-s19kpro",
            "--source-layout", SOURCE_BRAIINS_AML_S19K,
            "--version", "v0.1.0-test",
            "--post-install-artifact", "X.tar",
            "--migration-scope", "none",
            "--artifact-class", "test-fixture",
            "--signing-key-id", "pytest-dev-only",
            "--member", f"{MODULE.CANONICAL_ROOTFS_MEMBER}={rootfs}",
            "--plan",
        ]
    )
    assert rc == 2
    assert "--stage1" in capsys.readouterr().err


def test_stage1_authorizer_is_required_for_every_capsule(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    rc = MODULE.main(
        [
            "--board-target", "am3-s19kpro",
            "--source-layout", SOURCE_BRAIINS_AML_S19K,
            "--version", "v0.1.0-test",
            "--post-install-artifact", "X.tar",
            "--migration-scope", "none",
            "--artifact-class", "test-fixture",
            "--signing-key-id", "pytest-dev-only",
            "--stage1", str(stage1),
            "--member", f"{MODULE.CANONICAL_ROOTFS_MEMBER}={rootfs}",
            "--plan",
        ]
    )
    assert rc == 2
    assert "--stage1-authorizer" in capsys.readouterr().err


def test_complete_install_custody_set_is_required(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    args = _base_args(tmp_path, stage1, rootfs)
    flag_index = args.index("--safeoff-config")
    del args[flag_index : flag_index + 2]
    assert MODULE.main(args + ["--plan"]) == 2
    assert "--safeoff-config" in capsys.readouterr().err


def test_stage1_authorizer_over_one_mib_is_refused(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    oversized = tmp_path / "oversized-authorizer"
    with oversized.open("wb") as handle:
        handle.truncate(MODULE.MAX_STAGE1_AUTHORIZER_BYTES + 1)
    args = _base_args(tmp_path, stage1, rootfs)
    args[args.index("--stage1-authorizer") + 1] = str(oversized)
    assert MODULE.main(args + ["--plan"]) == 2
    assert str(MODULE.MAX_STAGE1_AUTHORIZER_BYTES) in capsys.readouterr().err


def test_payload_member_besides_stage1_is_required(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    args = _base_args(tmp_path, stage1, _rootfs(tmp_path))
    member_index = args.index("--member")
    del args[member_index : member_index + 2]
    rc = MODULE.main(args + ["--plan"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "rootfs payload" in err
    assert MODULE.CANONICAL_ROOTFS_MEMBER in err


def test_unknown_target_and_stock_source_refused(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    assert MODULE.main(
        _base_args(tmp_path, stage1, rootfs)
        + ["--board-target", "am2-s19pro", "--plan"]
    ) == 2
    assert "unknown S19k Pro AML first-install board target" in capsys.readouterr().err
    assert MODULE.main(
        _base_args(tmp_path, stage1, rootfs)
        + ["--source-layout", "stock-aml-s19k", "--plan"]
    ) == 2
    err = capsys.readouterr().err
    # Bitmain stock is the Track-2 evidence gap — never an accepted source
    assert "stock" in err
    assert "unknown S19k Pro AML source layout" in err


def test_board_target_aliases_accepted(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    for alias in ("am3-s19k", "am3-aml-s19kpro", "s19kpro"):
        rc = MODULE.main(
            _base_args(tmp_path, stage1, rootfs)
            + ["--board-target", alias, "--plan"]
        )
        assert rc == 0, alias
        assert json.loads(capsys.readouterr().out)["board_target"] == "am3-s19kpro"


def test_one_capsule_may_accept_both_source_dialects(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    rc = MODULE.main(
        _base_args(tmp_path, stage1, rootfs)
        + [
            "--source-layout", SOURCE_LUXOS_AML_S19K,
            "--source-layout", "braiins-aml-s19k",  # dedup + sort
            "--plan",
        ]
    )
    assert rc == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["accepted_source_layouts"] == [
        SOURCE_BRAIINS_AML_S19K,
        SOURCE_LUXOS_AML_S19K,
    ]
    assert len(plan["sources"]) == 2
    assert all(s["dialect_proven"] for s in plan["sources"])


def test_production_custody_scope_refuses_luxos(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    args = _base_args(tmp_path, stage1, rootfs) + [
        "--source-layout", SOURCE_LUXOS_AML_S19K,
        "--artifact-class", "production",
        "--plan",
    ]
    assert MODULE.main(args) == 2
    assert "LuxOS needs its own" in capsys.readouterr().err


def test_unsafe_and_reserved_member_names_rejected(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"data")
    rc = MODULE.main(
        _base_args(tmp_path, stage1, payload)
        + ["--member", f"../evil={payload}", "--plan"]
    )
    assert rc == 2
    assert "unsafe member name" in capsys.readouterr().err
    manifest_decoy = tmp_path / "manifest.json"
    manifest_decoy.write_bytes(b"{}")
    rc = MODULE.main(
        _base_args(tmp_path, stage1, payload)
        + ["--member", f"manifest.json={manifest_decoy}", "--plan"]
    )
    assert rc == 2
    assert "reserved" in capsys.readouterr().err


def test_payload_over_the_mtd5_window_refused(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    # The NAND window bounds the rootfs itself. Custody members are bound by
    # the separate signed target /tmp staging budget.
    big = tmp_path / "big.img"
    needed = MODULE.ROOTFS_WINDOW_BYTES + 1
    with big.open("wb") as handle:
        handle.truncate(needed)
    rc = MODULE.main(
        _base_args(tmp_path, stage1, big)
        + ["--member", f"payload/big.img={big}", "--plan"]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "rootfs window" in err
    assert "0x02800000" in err


def test_real_build_requires_signing_material(tmp_path, capsys, monkeypatch):
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    monkeypatch.delenv("DCENT_RELEASE_SIGNING_KEY", raising=False)
    monkeypatch.delenv("DCENT_RELEASE_PUBKEY_FILE", raising=False)
    rc = MODULE.main(
        _base_args(tmp_path, stage1, rootfs)
        + ["--output", str(tmp_path / "capsule.tar.gz")]
    )
    assert rc == 2
    assert "signing requires" in capsys.readouterr().err


def test_production_requires_verified_image_evidence(tmp_path, capsys, dev_authority):
    _key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    args = _base_args(tmp_path, stage1, rootfs) + [
        "--artifact-class", "production",
        "--pubkey", str(pub_pem),
        "--plan",
    ]
    assert MODULE.main(args) == 2
    assert "persistent-image-evidence-dir" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("receipt_overrides", "receipt_remove", "message"),
    (
        (
            {"schema": "dcentos.s19k-persistent-image-verification/v3"},
            (),
            "schema is not v4",
        ),
        ({}, ("host_preflight_component_sha256",), "key set is not exact v4"),
        (
            {"isolated_post_ab_signing_verified": True},
            (),
            "improperly claims isolated post-A/B signing",
        ),
        (
            {"isolated_post_ab_signing_nonclaim": "isolation-proven"},
            (),
            "signing-isolation nonclaim is not exact",
        ),
    ),
)
def test_production_image_v4_contract_fails_closed(
    tmp_path,
    dev_authority,
    monkeypatch,
    receipt_overrides,
    receipt_remove,
    message,
):
    _key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    evidence, _source_commit = _mock_production_inputs(
        tmp_path,
        monkeypatch,
        stage1,
        rootfs,
        pub_pem,
        receipt_overrides=receipt_overrides,
        receipt_remove=receipt_remove,
    )
    public_hex = serialization.load_pem_public_key(pub_pem.read_bytes()).public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()

    with pytest.raises(MODULE.CapsuleBuildError, match=message):
        MODULE._load_production_image_receipt(
            evidence,
            rootfs,
            pub_pem,
            public_hex,
        )


def test_production_refuses_unapproved_noop_stage1(
    tmp_path, capsys, dev_authority, monkeypatch
):
    _key_pem, pub_pem = dev_authority
    raw = serialization.load_pem_public_key(pub_pem.read_bytes()).public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    monkeypatch.setattr(MODULE, "get_pinned_release_pubkey_hex", lambda: raw)
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    args = _base_args(tmp_path, stage1, rootfs) + [
        "--artifact-class", "production",
        "--pubkey", str(pub_pem),
        "--persistent-image-evidence-dir", str(tmp_path / "not-needed-yet"),
        "--plan",
    ]
    assert MODULE.main(args) == 2
    err = capsys.readouterr().err
    assert "not in the reviewed target-side approval registry" in err
    assert "synthetic no-I/O fixture" in err


def test_production_refuses_unreviewed_extra_payload_member(
    tmp_path, capsys, dev_authority
):
    _key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    extra = tmp_path / "unexplained.bin"
    extra.write_bytes(b"not a reviewed production role")
    args = _base_args(tmp_path, stage1, rootfs) + [
        "--artifact-class", "production",
        "--pubkey", str(pub_pem),
        "--member", f"payload/unexplained.bin={extra}",
        "--plan",
    ]
    assert MODULE.main(args) == 2
    assert "unreviewed extra payload" in capsys.readouterr().err


def test_production_requires_authenticated_source_snapshot(
    tmp_path, capsys, dev_authority, monkeypatch
):
    _key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    evidence, _source_commit = _mock_production_inputs(
        tmp_path, monkeypatch, stage1, rootfs, pub_pem
    )
    args = _base_args(tmp_path, stage1, rootfs) + [
        "--artifact-class", "production",
        "--pubkey", str(pub_pem),
        "--persistent-image-evidence-dir", str(evidence),
        "--plan",
    ]
    assert MODULE.main(args) == 2
    assert "--expected-source-commit" in capsys.readouterr().err


def test_production_signing_key_id_exact_joins_v4_receipt(
    tmp_path, capsys, dev_authority, monkeypatch
):
    _key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    evidence, source_commit = _mock_production_inputs(
        tmp_path,
        monkeypatch,
        stage1,
        rootfs,
        pub_pem,
        receipt_overrides={"release_key_id": "d" * 64},
    )
    args = _base_args(tmp_path, stage1, rootfs) + [
        "--artifact-class",
        "production",
        "--pubkey",
        str(pub_pem),
        "--persistent-image-evidence-dir",
        str(evidence),
        "--expected-source-commit",
        source_commit,
        "--plan",
    ]
    assert MODULE.main(args) == 2
    assert "--signing-key-id does not exact-join" in capsys.readouterr().err


def test_production_refuses_unapproved_stage1_authorizer(
    tmp_path, capsys, dev_authority, monkeypatch
):
    _key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    evidence, source_commit = _mock_production_inputs(
        tmp_path, monkeypatch, stage1, rootfs, pub_pem
    )
    monkeypatch.setattr(
        MODULE.release_policy,
        "approved_stage1_authorizer",
        lambda _sha, _root, _commit: None,
    )
    args = _base_args(tmp_path, stage1, rootfs) + [
        "--artifact-class", "production",
        "--pubkey", str(pub_pem),
        "--persistent-image-evidence-dir", str(evidence),
        "--expected-source-commit", source_commit,
        "--plan",
    ]
    assert MODULE.main(args) == 2
    err = capsys.readouterr().err
    assert "stage1 authorizer is not in the reviewed target-KAT" in err
    assert "dirty/unsigned desk binary is test-only" in err


def test_production_refuses_unapproved_install_custody_bundle(
    tmp_path, capsys, dev_authority, monkeypatch
):
    _key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    evidence, source_commit = _mock_production_inputs(
        tmp_path, monkeypatch, stage1, rootfs, pub_pem
    )
    monkeypatch.setattr(
        MODULE.release_policy,
        "approved_install_custody",
        lambda _implementation_id, _observed: None,
    )
    args = _base_args(tmp_path, stage1, rootfs) + [
        "--artifact-class", "production",
        "--pubkey", str(pub_pem),
        "--persistent-image-evidence-dir", str(evidence),
        "--expected-source-commit", source_commit,
        "--plan",
    ]
    assert MODULE.main(args) == 2
    assert "install-custody bundle" in capsys.readouterr().err


def test_production_refuses_stale_materialized_image_receipt(
    tmp_path, capsys, dev_authority, monkeypatch
):
    _key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    evidence, source_commit = _mock_production_inputs(
        tmp_path, monkeypatch, stage1, rootfs, pub_pem
    )
    (evidence / MODULE.persistent_image.VERIFICATION_FILE).write_bytes(b"{}\n")
    args = _base_args(tmp_path, stage1, rootfs) + [
        "--artifact-class", "production",
        "--pubkey", str(pub_pem),
        "--persistent-image-evidence-dir", str(evidence),
        "--expected-source-commit", source_commit,
        "--plan",
    ]
    assert MODULE.main(args) == 2
    assert "differs from the current authoritative verifier" in capsys.readouterr().err


def test_test_fixture_cannot_claim_production_image_evidence(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    args = _base_args(tmp_path, stage1, rootfs) + [
        "--persistent-image-evidence-dir", str(tmp_path),
        "--plan",
    ]
    assert MODULE.main(args) == 2
    assert "must not claim production" in capsys.readouterr().err


def test_version_charset_enforced(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    args = _base_args(tmp_path, stage1, rootfs) + ["--version", "bad version!", "--plan"]
    assert MODULE.main(args) == 2
    assert "version" in capsys.readouterr().err


def test_post_install_artifact_must_be_bare_id(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    args = _base_args(tmp_path, stage1, rootfs) + [
        "--post-install-artifact", "output/sysupgrade.tar", "--plan",
    ]
    assert MODULE.main(args) == 2
    assert "bare artifact ID" in capsys.readouterr().err


# --- signed builds (exact release signer) ----------------------------------------


def test_production_signer_requires_preauthorization_then_refuses_boundary_nonclaim(
    tmp_path, capsys, dev_authority, monkeypatch
):
    key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    evidence, source_commit = _mock_production_inputs(
        tmp_path, monkeypatch, stage1, rootfs, pub_pem
    )
    output = tmp_path / "DCENT_FIRSTINSTALL_AM3_S19kPro_v0.1.0-test.tar.gz"
    unsigned = tmp_path / "unsigned-manifest.json"
    common = _base_args(tmp_path, stage1, rootfs) + [
        "--artifact-class", "production",
        "--persistent-image-evidence-dir", str(evidence),
        "--expected-source-commit", source_commit,
        "--output", str(output),
        "--pubkey", str(pub_pem),
    ]
    assert MODULE.main(common + ["--emit-unsigned-manifest", str(unsigned)]) == 0
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["private_key_read"] is False
    assert emitted["authority_granted"] is False

    # Even with a usable private key, no authorization means the builder
    # returns before invoking the exact signer and creates no capsule.
    assert MODULE.main(common + ["--key", str(key_pem)]) == 2
    assert "preauthorization" in capsys.readouterr().err
    assert not output.exists()

    authorization = tmp_path / "authorization.json"
    authorization.write_bytes(b"pytest authorization adapter fixture\n")
    observed_authorization = []
    monkeypatch.setattr(
        MODULE.signing_ceremony,
        "verify_authorization",
        lambda receipt, manifest, output_name: observed_authorization.append(
            (receipt, manifest, output_name)
        ),
    )
    assert MODULE.main(
        common
        + [
            "--key", str(key_pem),
            "--signing-authorization-receipt", str(authorization),
            "--json",
        ]
    ) == 2
    assert (
        "independently authenticated signer-boundary projection"
        in capsys.readouterr().err
    )
    assert len(observed_authorization) == 1
    assert observed_authorization[0][0] == authorization
    assert observed_authorization[0][2] == output.name
    assert not output.exists()


@pytest.mark.skipif(not HAS_OPENSSL, reason="exact release signer requires openssl")
def test_built_fixture_is_explicitly_nonproduction(tmp_path, capsys, dev_authority, monkeypatch):
    key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    output = tmp_path / "DCENT_FIRSTINSTALL_AM3_S19kPro_v0.1.0-test.tar.gz"
    rc = MODULE.main(
        _base_args(tmp_path, stage1, rootfs)
        + [
            "--output", str(output),
            "--key", str(key_pem),
            "--pubkey", str(pub_pem),
            "--json",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sha256"]
    assert payload["transition_mechanism"] == "mtd5_rootfs_window_flag_commit"
    assert payload["nand_geometry"]["rootfs_window_hex"] == "0x02800000"
    assert payload["verify_command"].startswith("dcent s19k-aml-first-install inspect")

    # THE loop-closing assertions: the toolbox contract admits the product
    # (under the pinned dev authority — the release ceremony is the
    # pinned-key flip, see the next test) AND the staged plan stays honest
    # (stage 2 satisfied; the apply gate stays refused).
    monkeypatch.setenv("DCENT_RELEASE_PUBKEY_FILE", str(pub_pem))
    report = inspect_s19k_aml_capsule(output)
    assert report.verdict == "capsule_test_fixture"
    assert not report.failures
    assert report.board_target == "am3-s19kpro"
    assert report.signature_state == "verified against the pinned D-Central release key"
    assert report.geometry_state.startswith("agrees")
    assert report.accepted_source_layouts == (SOURCE_BRAIINS_AML_S19K,)
    assert sfi.STAGE1_MEMBER in report.members
    assert MODULE.CANONICAL_ROOTFS_MEMBER in report.members
    assert report.payload_bytes == (
        stage1.stat().st_size
        + _authorizer(tmp_path).stat().st_size
        + rootfs.stat().st_size
        + sum(path.stat().st_size for path in _custody_inputs(tmp_path).values())
    )

    plan = plan_s19k_aml_first_install(
        "am3-s19kpro", SOURCE_BRAIINS_AML_S19K, capsule_path=output
    ).to_dict()
    stages = {s["order"]: s["state"] for s in plan["stages"]}
    assert stages[1] == "satisfied_precedent_not_authority"
    assert stages[2] != "satisfied"
    assert stages[5] == "blocked_by_capsule"
    assert stages[6] in {"blocked_by_capsule", "refused_clear_for_flash_false"}
    assert plan["capsule"]["verdict"] == "capsule_test_fixture"


@pytest.mark.skipif(not HAS_OPENSSL, reason="exact release signer requires openssl")
def test_dev_key_against_the_pinned_release_key_is_the_ceremony_gate(
    tmp_path, capsys, dev_authority, monkeypatch
):
    """A dev-signed capsule fails ONLY the pinned-release-key check.

    This is the documented release-ceremony step: without the dev
    authority pinned (DCENT_RELEASE_PUBKEY_FILE unset), the production
    pin rejects the signature while every other contract dimension
    (geometry, checksums, members, fields) stays green.
    """

    key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    output = tmp_path / "devkey.tar.gz"
    rc = MODULE.main(
        _base_args(tmp_path, stage1, rootfs)
        + ["--output", str(output), "--key", str(key_pem), "--pubkey", str(pub_pem)]
    )
    assert rc == 0
    monkeypatch.delenv("DCENT_RELEASE_PUBKEY_FILE", raising=False)
    monkeypatch.delenv("DCENT_RELEASE_PUBKEY_HEX", raising=False)
    monkeypatch.delenv("DCENT_RELEASE_IMAGE", raising=False)
    report = inspect_s19k_aml_capsule(output)
    assert report.verdict == "capsule_signature_untrusted"
    # the ONLY failures are signature failures — everything else green
    assert report.failures
    assert any(
        "signature" in failure or "INVALID" in failure or "UNVERIFIABLE" in failure
        for failure in report.failures
    )
    assert any("signing_identity.public_key_hex" in failure for failure in report.failures)
    assert report.geometry_state.startswith("agrees")
    assert report.board_target == "am3-s19kpro"
    assert report.transition_mechanism == "mtd5_rootfs_window_flag_commit"
    assert sfi.STAGE1_MEMBER in report.members
    assert MODULE.CANONICAL_ROOTFS_MEMBER in report.members


@pytest.mark.skipif(not HAS_OPENSSL, reason="exact release signer requires openssl")
def test_build_is_deterministic_and_no_replace(tmp_path, capsys, dev_authority):
    key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    common = _base_args(tmp_path, stage1, rootfs) + [
        "--key", str(key_pem), "--pubkey", str(pub_pem), "--json",
    ]
    assert MODULE.main(common + ["--output", str(first)]) == 0
    digest_a = json.loads(capsys.readouterr().out)["sha256"]
    assert MODULE.main(common + ["--output", str(second)]) == 0
    digest_b = json.loads(capsys.readouterr().out)["sha256"]
    assert digest_a == digest_b
    assert first.read_bytes() == second.read_bytes()
    # no-replace: rebuilding over the same path is refused
    assert MODULE.main(common + ["--output", str(first)]) == 2
    assert "no-replace" in capsys.readouterr().err


@pytest.mark.skipif(not HAS_OPENSSL, reason="exact release signer requires openssl")
def test_manifest_geometry_is_the_exact_pin_block(tmp_path, capsys, dev_authority, monkeypatch):
    """The emitted nand_geometry block equals the toolbox pins byte-for-byte
    (hex lowercase, erase counts as integers — the 6 MiB hole trap guard)."""

    import io
    import tarfile

    key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    rootfs = _rootfs(tmp_path)
    output = tmp_path / "geo.tar.gz"
    assert MODULE.main(
        _base_args(tmp_path, stage1, rootfs)
        + ["--output", str(output), "--key", str(key_pem), "--pubkey", str(pub_pem)]
    ) == 0
    with tarfile.open(fileobj=io.BytesIO(output.read_bytes()), mode="r:gz") as tar:
        manifest = json.loads(tar.extractfile("manifest.json").read().decode("utf-8"))
    assert manifest["nand_geometry"] == sfi.s19k_aml_geometry_pins()
    geo = manifest["nand_geometry"]
    assert geo["mtd5_base_hex"] == "0x06700000"  # NOT the 0x06100000 size sum
    assert geo["rootfs_local_offset_hex"] == "0x05100000"
    assert geo["rootfs_window_hex"] == "0x02800000"
    assert geo["rootfs_erase_count"] == 320
    assert geo["eraseblock_size"] == 131072
    assert geo["recovery_flag_local_offset_hex"] == "0x04d00000"
    assert geo["recovery_flag_values"] == {"installed": 1, "first_boot": 2, "successful": 3}
    # every declared member is covered by the checksums block
    assert set(manifest["checksums"]) == {
        sfi.STAGE1_MEMBER,
        MODULE.STAGE1_AUTHORIZER_MEMBER,
        MODULE.CANONICAL_ROOTFS_MEMBER,
        *MODULE.CUSTODY_MEMBER_BY_ROLE.values(),
    }
    # and the capsule re-inspects ready under the dev authority
    monkeypatch.setenv("DCENT_RELEASE_PUBKEY_FILE", str(pub_pem))
    assert inspect_s19k_aml_capsule(output).verdict == "capsule_test_fixture"
