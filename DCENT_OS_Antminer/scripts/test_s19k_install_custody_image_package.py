#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Static, offline packaging locks for the S19k install-custody policy."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "dcentrald" / "dcentrald_s19k_install_custody.toml"
POST_BUILD = (
    ROOT
    / "br2_external_dcentos"
    / "board"
    / "amlogic"
    / "am3-s19kpro"
    / "post-build.sh"
)
POST_IMAGE = POST_BUILD.with_name("post-image.sh")
REFERENCE_PATH = "usr/share/dcentos/install-custody/dcentrald_s19k.toml"


def test_reference_config_is_packaged_at_stable_non_active_path() -> None:
    post_build = POST_BUILD.read_text(encoding="utf-8")
    post_image = POST_IMAGE.read_text(encoding="utf-8")
    assert "dcentrald/dcentrald_s19k_install_custody.toml" in post_build
    assert "usr/share/dcentos/install-custody" in post_build
    assert "dcentrald_s19k.toml" in post_build
    assert f'require_rootfs_path "{REFERENCE_PATH}"' in post_image
    assert '[ ! -L "$INSTALL_CUSTODY_CFG_SRC" ]' in post_build
    assert 'chmod 0444 "$INSTALL_CUSTODY_CFG_DST"' in post_build
    assert 'cmp -s "$INSTALL_CUSTODY_CFG_SRC" "$INSTALL_CUSTODY_CFG_DST"' in post_build


def test_reference_path_cannot_override_any_boot_config() -> None:
    post_build = POST_BUILD.read_text(encoding="utf-8")
    custody_block = post_build.split("# Install an inert, non-active reference copy", 1)[1]
    assert '"${TARGET_DIR}/etc/dcentrald.toml"' not in custody_block
    assert '"${TARGET_DIR}/etc/dcentrald/dcentrald.toml"' not in custody_block
    assert '"${TARGET_DIR}/data/dcentrald.toml"' not in custody_block


def test_packaged_policy_is_pool_free_and_install_mode_only() -> None:
    raw = CONFIG.read_text(encoding="utf-8")
    assert "--s19k-install-custody-safeoff" in raw
    assert "enabled = false" in raw
    forbidden = (
        "stratum+tcp://",
        "stratum+ssl://",
        "stratum2+tcp://",
        "solo.ckpool",
    )
    for token in forbidden:
        assert token not in raw
    assert 'url = ""' in raw
    assert 'pool_url = ""' in raw
    assert 'fallback_pool_url = ""' in raw


def test_rootfs_does_not_package_armv7_custody_executables() -> None:
    post_build = POST_BUILD.read_text(encoding="utf-8")
    for leaf in ("run_trial", "supervisor_custody_observer", "stock_restart_helper"):
        assert f"/usr/share/dcentos/install-custody/{leaf}" not in post_build
