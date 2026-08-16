# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only

"""Offline tests for the AM335x/BB NAND first-install capsule builder.

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

SCRIPT = Path(__file__).with_name("build_am3_bb_nand_capsule.py")
SPEC = importlib.util.spec_from_file_location("build_am3_bb_nand_capsule", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

TOOLBOX_SOURCE = MODULE.TOOLBOX_SOURCE
if str(TOOLBOX_SOURCE) not in sys.path:
    sys.path.insert(0, str(TOOLBOX_SOURCE))

from dcent_toolbox.core.am3_bb_nand_first_install import (  # noqa: E402
    SOURCE_LUXOS_NVDATA_ROOTFS,
    SOURCE_STOCK_BBCTRL,
    inspect_am3_bb_nand_capsule,
    plan_am3_bb_nand_first_install,
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
        "--board-target", "am3-bb-s19jpro",
        "--source-layout", SOURCE_STOCK_BBCTRL,
        "--version", "v0.1.0-test",
        "--post-install-artifact", "dcentos-am3-bb-s19jpro-sdcard-20260814.tar",
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
    assert plan["transition_mechanism"] == "nvdata_kernel_window"
    assert plan["board_target"] == "am3-bb-s19jpro"
    assert plan["accepted_source_layouts"] == [SOURCE_STOCK_BBCTRL]
    assert plan["sources"][0]["nvdata_mtd"] == "mtd11"
    assert plan["sources"][0]["preserved_mtds"] == ["mtd7", "mtd8"]
    assert [m["name"] for m in plan["members"]] == ["transition/stage1.sh"]
    assert not output.exists()


def test_stage1_is_required_for_every_capsule(tmp_path, capsys):
    rc = MODULE.main(
        [
            "--board-target", "am3-bb-s19jpro",
            "--source-layout", SOURCE_STOCK_BBCTRL,
            "--version", "v0.1.0-test",
            "--post-install-artifact", "X.tar",
            "--migration-scope", "none",
            "--plan",
        ]
    )
    assert rc == 2
    assert "--stage1" in capsys.readouterr().err


def test_one_capsule_may_accept_both_dialects(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    rc = MODULE.main(
        _base_args(tmp_path, stage1)
        + [
            "--source-layout", SOURCE_LUXOS_NVDATA_ROOTFS,
            "--source-layout", "luxos-bb-nvdata-rootfs",  # dedup + sort
            "--plan",
        ]
    )
    assert rc == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["accepted_source_layouts"] == [
        SOURCE_LUXOS_NVDATA_ROOTFS,
        SOURCE_STOCK_BBCTRL,
    ]
    assert len(plan["sources"]) == 2


def test_unknown_target_and_source_refused(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    assert MODULE.main(
        _base_args(tmp_path, stage1)
        + ["--board-target", "am2-s19pro", "--plan"]
    ) == 2
    assert "unknown BB NAND first-install board target" in capsys.readouterr().err
    assert MODULE.main(
        _base_args(tmp_path, stage1)
        + ["--source-layout", "braiins-dual-ubi-mtd7-mtd8", "--plan"]
    ) == 2
    assert "unknown BB NAND first-install source layout" in capsys.readouterr().err


def test_unsafe_and_reserved_member_names_rejected(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"data")
    rc = MODULE.main(
        _base_args(tmp_path, stage1)
        + ["--member", f"../evil={payload}", "--plan"]
    )
    assert rc == 2
    assert "unsafe member name" in capsys.readouterr().err
    manifest_decoy = tmp_path / "manifest.json"
    manifest_decoy.write_bytes(b"{}")
    rc = MODULE.main(
        _base_args(tmp_path, stage1)
        + ["--member", f"manifest.json={manifest_decoy}", "--plan"]
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
        "--board-target", "am3-bb-s19jpro",
        "--source-layout", SOURCE_STOCK_BBCTRL,
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
    kernel = tmp_path / "dcent.img"
    kernel.write_bytes(b"BB-NVDATA-WINDOW-IMAGE" * 8)
    output = tmp_path / "capsule.tar.gz"
    rc = MODULE.main(
        _base_args(tmp_path, stage1)
        + [
            "--member", f"payload/dcent-nvdata.img={kernel}",
            "--output", str(output),
            "--key", str(key_pem),
            "--pubkey", str(pub_pem),
            "--json",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sha256"]
    # THE loop-closing assertions: the toolbox contract admits the product
    # AND the staged plan stays honest (stage 2 satisfied; the SD cold-boot
    # witness stays blocked — a capsule never waives it).
    import os

    old = os.environ.get("DCENT_RELEASE_PUBKEY_FILE")
    os.environ["DCENT_RELEASE_PUBKEY_FILE"] = str(pub_pem)
    try:
        report = inspect_am3_bb_nand_capsule(output)
        assert report.verdict == "capsule_ready"
        assert report.board_target == "am3-bb-s19jpro"
        assert "transition/stage1.sh" in report.members
        assert "payload/dcent-nvdata.img" in report.members
        assert report.accepted_source_layouts == (SOURCE_STOCK_BBCTRL,)

        plan = plan_am3_bb_nand_first_install(
            "am3-bb-s19jpro", SOURCE_STOCK_BBCTRL, capsule_path=output
        ).to_dict()
        stages = {s["order"]: s["state"] for s in plan["stages"]}
        assert stages[1] == "blocked_until_witnessed"
        assert stages[2] == "satisfied"
        assert stages[5] == "ready_for_operator"
        assert plan["capsule"]["verdict"] == "capsule_ready"
    finally:
        if old is None:
            os.environ.pop("DCENT_RELEASE_PUBKEY_FILE", None)
        else:
            os.environ["DCENT_RELEASE_PUBKEY_FILE"] = old


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
