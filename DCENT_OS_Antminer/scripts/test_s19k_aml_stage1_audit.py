#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only

"""Offline contract test for the unapproved S19k AML stage-1 candidate."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


SCRIPT = Path(__file__).with_name("s19k_aml_stage1_audit.py")
SPEC = importlib.util.spec_from_file_location("s19k_aml_stage1_audit", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


def test_fixture_matrix_proves_ordering_and_remains_non_authorizing() -> None:
    receipt = AUDIT.run_audit()

    assert receipt["schema"] == "dcentos.s19k-stage1-audit/v1"
    assert receipt["authority"]["clear_for_flash"] is False
    assert receipt["authority"]["flash_authority_granted"] is False
    assert receipt["authority"]["stock_target_signature_verifier_available"] is False
    assert receipt["conclusions"]["production_admission_ready"] is False
    assert receipt["conclusions"]["request_bytes_produced_by_toolbox_encoder"] is True
    assert receipt["conclusions"]["live_openssl_dependency_removed"] is True
    assert receipt["conclusions"]["live_authorizer_exact_hash_and_size_pinned"] is True
    assert receipt["conclusions"]["live_rootfs_readback_is_streaming_sha256"] is True
    assert receipt["conclusions"]["live_rootfs_sized_readback_file_created"] is False
    assert receipt["noop_fixture"]["rejected"] is True
    assert receipt["authorizer_desk_kat"]["valid_signature_exit_code"] == 0
    assert receipt["authorizer_desk_kat"]["tampered_message_exit_code"] == 3
    assert receipt["authorizer_desk_kat"]["openssl_in_path"] is False
    assert receipt["authorizer_desk_kat"]["stock_target_kat_verified"] is False
    assert (
        receipt["tmp_capacity_contract"]["minimum_available_after_transfers_kib"]
        == 4096
    )
    assert receipt["tmp_capacity_contract"]["live_runtime_extra_max_bytes"] == 524288
    assert (
        receipt["tmp_capacity_contract"]["regular_rootfs_readback_file_live"] is False
    )
    assert (
        receipt["tmp_capacity_contract"][
            "failed_producer_consumer_terminated_and_reaped"
        ]
        is True
    )
    assert receipt["fifo_fail_before_open_kat"]["producer_opened_fifo"] is False
    assert receipt["fifo_fail_before_open_kat"]["consumer_terminated"] is True
    assert receipt["fifo_fail_before_open_kat"]["consumer_reaped"] is True
    assert receipt["fifo_fail_before_open_kat"]["fifo_removed"] is True

    adversarial = {case["name"]: case for case in receipt["adversarial_cases"]}
    assert adversarial["missing_authorizer_hash"]["failure_code"] == (
        "request_key_set_not_exact"
    )
    assert adversarial["wrong_authorizer_hash"]["failure_code"] == (
        "stage1_authorizer_hash_request_mismatch"
    )
    assert adversarial["wrong_authorizer_bytes"]["failure_code"] == (
        "stage1_authorizer_bytes_request_mismatch"
    )
    assert adversarial["tampered_detached_signature"]["failure_code"] == (
        "authorization_signature_invalid"
    )
    assert all(case["fixture_unchanged"] is True for case in adversarial.values())

    cases = {case["name"]: case for case in receipt["dynamic_cases"]}
    assert cases["preflight"]["state"] == "preflight_verified_no_write"
    assert cases["install_success"]["operation_names"][-1] == (
        "install.commit_0x01_full_eraseblock_readback_verified_no_reboot"
    )
    assert cases["install_success"]["fixture_flag_state"] == "candidate_0x01"
    assert cases["install_success"]["rootfs_readback_mode"] == "fixture-file"
    assert cases["restore_success"]["state"] == "stock_recovery_armed_no_reboot"
    assert cases["restore_success"]["fixture_flag_state"] == "original_0x02"
    assert cases["cut_before_rootfs_erase"]["state"] == "refused_pre_mutation"
    assert cases["cut_after_rootfs_erase"]["state"] == (
        "indeterminate_restore_required"
    )
    assert cases["cut_after_flag_write"]["fixture_flag_state"] == "candidate_0x01"
    assert all(case["nand_erase_performed"] is False for case in cases.values())
    assert all(case["nand_write_performed"] is False for case in cases.values())
