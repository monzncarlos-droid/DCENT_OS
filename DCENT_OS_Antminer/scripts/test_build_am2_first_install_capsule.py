# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only

"""Offline tests for the AM2/XIL first-install capsule builder.

Validation tests are pure; signing tests exercise the exact release
signer (openssl + sign_release_artifact.py) and are skipped when openssl
is unavailable. The closing assertion of every signing test is the
TOOLBOX contract verdict: `capsule_ready`.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPT = Path(__file__).with_name("build_am2_first_install_capsule.py")
SPEC = importlib.util.spec_from_file_location("build_am2_first_install_capsule", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

TOOLBOX_SOURCE = MODULE.TOOLBOX_SOURCE
if str(TOOLBOX_SOURCE) not in sys.path:
    sys.path.insert(0, str(TOOLBOX_SOURCE))

from dcent_toolbox.core.am2_xil_first_install import (  # noqa: E402
    SOURCE_STOCK_3PART,
    inspect_am2_first_install_capsule,
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
    stage1.write_bytes(b"#!/bin/sh\nset -e\n# transition (test)\n")
    return stage1


def _base_args(tmp_path: Path, stage1: Path) -> list[str]:
    return [
        "--board-target", "am2-s19pro",
        "--source-layout", SOURCE_STOCK_3PART,
        "--version", "v0.1.0-test",
        "--post-install-artifact", "DCENTOS_XIL3_S19Pro_20260814.tar",
        "--migration-scope", "serial-number-only",
        "--stage1", str(stage1),
    ]


def test_plan_derives_mechanism_and_writes_nothing(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    output = tmp_path / "capsule.tar.gz"
    rc = MODULE.main(
        _base_args(tmp_path, stage1) + ["--plan", "--output", str(output)]
    )
    assert rc == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["transition_mechanism"] == "boot_chain_repartition"
    assert plan["board_target"] == "am2-s19pro"
    assert [m["name"] for m in plan["members"]] == ["transition/stage1.sh"]
    assert not output.exists()


def test_single_slot_source_requires_stage1(tmp_path, capsys):
    rc = MODULE.main(
        [
            "--board-target", "am2-s19pro",
            "--source-layout", SOURCE_STOCK_3PART,
            "--version", "v0.1.0-test",
            "--post-install-artifact", "X.tar",
            "--migration-scope", "none",
            "--plan",
        ]
    )
    assert rc == 2
    assert "--stage1" in capsys.readouterr().err


def test_dual_ubi_source_refuses_stage1(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    rc = MODULE.main(
        [
            "--board-target", "am2-s19jpro-zynq",
            "--source-layout", "braiins-dual-ubi-mtd7-mtd8",
            "--version", "v0.1.0-test",
            "--post-install-artifact", "X.tar",
            "--migration-scope", "none",
            "--stage1", str(stage1),
            "--plan",
        ]
    )
    assert rc == 2
    assert "applies only to" in capsys.readouterr().err


def test_already_dcent_source_refused(tmp_path, capsys):
    rc = MODULE.main(
        [
            "--board-target", "am2-s19pro",
            "--source-layout", "dcent-dual-ubi-mtd7-mtd8",
            "--version", "v0.1.0-test",
            "--post-install-artifact", "X.tar",
            "--migration-scope", "none",
            "--plan",
        ]
    )
    assert rc == 2
    assert "already DCENT_OS" in capsys.readouterr().err


def test_unsafe_member_names_rejected(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"data")
    rc = MODULE.main(
        _base_args(tmp_path, stage1)
        + ["--member", f"../evil={payload}", "--plan"]
    )
    assert rc == 2
    assert "unsafe member name" in capsys.readouterr().err


def test_reserved_member_names_rejected(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    payload = tmp_path / "manifest.json"
    payload.write_bytes(b"{}")
    rc = MODULE.main(
        _base_args(tmp_path, stage1) + ["--member", f"manifest.json={payload}", "--plan"]
    )
    assert rc == 2
    assert "reserved" in capsys.readouterr().err


def test_real_build_requires_signing_material(tmp_path, capsys, monkeypatch):
    stage1 = _stage1(tmp_path)
    monkeypatch.delenv("DCENT_RELEASE_SIGNING_KEY", raising=False)
    monkeypatch.delenv("DCENT_RELEASE_PUBKEY_FILE", raising=False)
    rc = MODULE.main(
        _base_args(tmp_path, stage1)
        + ["--output", str(tmp_path / "capsule.tar.gz")]
    )
    assert rc == 2
    assert "signing requires" in capsys.readouterr().err


def test_version_charset_enforced(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    args = [
        "--board-target", "am2-s19pro",
        "--source-layout", SOURCE_STOCK_3PART,
        "--version", "bad version!",
        "--post-install-artifact", "X.tar",
        "--migration-scope", "none",
        "--stage1", str(stage1),
        "--plan",
    ]
    assert MODULE.main(args) == 2
    assert "version" in capsys.readouterr().err


@pytest.mark.skipif(not HAS_OPENSSL, reason="exact release signer requires openssl")
def test_built_capsule_reaches_toolbox_capsule_ready(tmp_path, capsys, dev_authority):
    key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    boot = tmp_path / "boot.bin"
    boot.write_bytes(b"AM2-BOOTCHAIN-TEST" * 4)
    output = tmp_path / "capsule.tar.gz"
    rc = MODULE.main(
        _base_args(tmp_path, stage1)
        + [
            "--member", f"boot/boot.bin={boot}",
            "--output", str(output),
            "--key", str(key_pem),
            "--pubkey", str(pub_pem),
            "--json",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sha256"]
    # THE loop-closing assertion: the toolbox contract admits the product
    import os

    old = os.environ.get("DCENT_RELEASE_PUBKEY_FILE")
    os.environ["DCENT_RELEASE_PUBKEY_FILE"] = str(pub_pem)
    try:
        report = inspect_am2_first_install_capsule(output)
    finally:
        if old is None:
            os.environ.pop("DCENT_RELEASE_PUBKEY_FILE", None)
        else:
            os.environ["DCENT_RELEASE_PUBKEY_FILE"] = old
    assert report.verdict == "capsule_ready"
    assert report.board_target == "am2-s19pro"
    assert "transition/stage1.sh" in report.members
    assert "boot/boot.bin" in report.members


@pytest.mark.skipif(not HAS_OPENSSL, reason="exact release signer requires openssl")
def test_build_is_deterministic_and_no_replace(tmp_path, capsys, dev_authority):
    key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    common = _base_args(tmp_path, stage1) + [
        "--key", str(key_pem), "--pubkey", str(pub_pem), "--json",
    ]
    assert MODULE.main(common + ["--output", str(first)]) == 0
    digest_a = json.loads(capsys.readouterr().out)["sha256"]
    assert MODULE.main(common + ["--output", str(second)]) == 0
    digest_b = json.loads(capsys.readouterr().out)["sha256"]
    assert digest_a == digest_b
    # no-replace: rebuilding over the same path is refused
    assert MODULE.main(common + ["--output", str(first)]) == 2
    assert "no-replace" in capsys.readouterr().err
