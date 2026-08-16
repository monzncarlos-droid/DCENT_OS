#!/usr/bin/env python3
"""Inventory + pin: WorkDispatchLifecycle engine tests must be CI-exact-wired.

Continuous-audit residual (2026-07-29): serial_mining (and hybrid/stock)
`work_dispatch_admission_tests` modules shipped pure lifecycle contracts for the
NO-SHIP work-dispatch admission wire, but none appeared under
`run_exact_cargo_test.sh` in the offline workflow / static inventory. Cargo
`--exact` with a missing selector can exit 0 with zero tests — only explicit
wiring + this pin keep the contracts on the commit path.

Also pins serial + hybrid `tests::` zero-orphan exact-wire ratchets (2026-07-29):
every unit under those modules must appear under `run_exact_cargo_test.sh`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
PROJECT = REPO_ROOT / "projects" / "dcentos"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
STATIC_GATE = PROJECT / "scripts" / "ci_offline_gates.sh"
SERIAL_SRC = PROJECT / "dcentrald" / "dcentrald" / "src" / "serial_mining.rs"
HYBRID_SRC = PROJECT / "dcentrald" / "dcentrald" / "src" / "s19j_hybrid_mining.rs"
STOCK_SRC = PROJECT / "dcentrald" / "dcentrald" / "src" / "stock_mining.rs"
DAEMON_SRC = PROJECT / "dcentrald" / "dcentrald" / "src" / "daemon.rs"

ENGINE_MODULES = (
    ("serial_mining", SERIAL_SRC),
    ("s19j_hybrid_mining", HYBRID_SRC),
    ("stock_mining", STOCK_SRC),
    # Standard FPGA daemon path (2026-07-29 constitution cycle): same pure
    # WorkDispatchLifecycle contract as stock/serial/hybrid.
    ("daemon", DAEMON_SRC),
)

# Extra serial_mining::tests contracts that must stay CI-wired (orphaned
# inventory 2026-07-29). Full orphan list is larger; these are safety/protocol
# tiers expanded in residual waves.
SERIAL_MUST_WIRE_UNDER_TESTS = (
    # Protocol honesty (tier-1)
    "serial_rolled_version_reconstructs_when_pool_did_not_negotiate_mask",
    "serial_rolled_version_accepts_only_negotiated_mask_bits",
    "exact_am2_source_clears_stale_work_when_hash_on_disconnect_is_false",
    # Heartbeat / watchdog / terminal (tier-2, 2026-07-29)
    "bm1362_heartbeat_terminal_limit_precedes_short_watchdog_reset_windows",
    "bm1362_heartbeat_requires_supported_observed_dspic_firmware",
    "bm1362_heartbeat_failure_budget_is_bounded_and_success_resets_it",
    "nopic_fan_loop_disposition_is_terminal_for_every_revoked_state",
    "terminal_barrier_failure_consumes_no_safe_off_leg_before_retry",
    "am2_never_energized_closeout_is_not_terminal_safe_off_evidence",
    # Admission / identity fail-closed (tier-2)
    "exact_am2_bm1362_refuses_unmonitored_uart_trans_routes",
    "validated_serial_admission_binds_exact_route_family_and_separate_geometry",
    "ambiguous_nopic_count_refuses_instead_of_guessing_a_pic_driver",
    "native_serial_voltage_identity_rejects_impossible_model_chip_pairs",
    # Airflow / actor / nonce / experimental admit (tier-3, 2026-07-29)
    "preenergize_airflow_envelope_reports_low_point_and_restore_failures_together",
    "preenergize_airflow_envelope_refuses_low_point_and_restores_maximum",
    "preenergize_airflow_envelope_proves_max_then_min_then_restores_max",
    "bm1362_nonce_safety_distinguishes_startup_midrun_and_disabled",
    "serial_actor_receiver_loss_and_three_read_errors_are_terminal",
    "native_serial_identity_never_comes_from_default_or_explicit_geometry",
    "bm1366_experimental_opt_in_admits_only_the_exact_env_value",
    "bm1366_experimental_admission_consumes_the_real_opt_in_and_observed_identity",
    "am2_apw_stabilization_requires_live_actor_and_successful_progress",
    "serial_execution_terminal_rejects_late_physical_commit",
    "retained_single_owner_safe_off_legs_execute_all_pending_work_and_never_replay_success",
    "exact_serial_actor_freshness_rejects_queued_or_disconnected_required_exits",
    # Cancellation / bring-up / geometry / admission refuse (tier-4, 2026-07-29)
    "am2_bringup_wait_is_immediately_cancellation_aware",
    "am2_cancellation_refuses_every_subsequent_validated_serial_commit",
    "exact_am2_bringup_validates_before_consuming_power_boundary_authority",
    "bm1362_pool_disconnect_requires_announced_authority_and_uart_commit",
    "bm1366_degraded_enumeration_component_cannot_bypass_runtime_refusal",
    "bm1366_enumeration_admission_is_strict_or_explicitly_degraded",
    "validated_serial_admission_rejects_family_cross_use_and_impossible_frame_envelope",
    "assigned_serial_geometry_requires_exact_unique_configured_address_coverage",
    "native_serial_geometry_requires_catalog_evidence_or_explicit_override",
    "native_serial_difficulty_requires_a_registered_profile",
    "serial_runtime_has_no_unbrokered_kernel_i2c_fd_or_ioctl_path",
    "unique_owner_installation_never_replaces_live_or_completed_custody",
    # Final offline-admissible residual batch (tier-5, 2026-07-29): fixtures,
    # identity classifiers, chip-family pins, AM3-BB parsers, actor/APW edges.
    # Inventory classified all 25 remaining orphans as offline unit tests —
    # none live-gated / evidence-exhausted.
    "am3_bb_uart_trans_chain_parser_accepts_deduped_ttyo_list",
    "am3_bb_uart_trans_chain_parser_accepts_single_ttyo_path",
    "am3_bb_uart_trans_chain_parser_rejects_unknown_or_empty_paths",
    "apw_bypass_and_unclassified_state_transitions_are_explicit",
    "bm1368_fixture_interval_agrees_with_the_general_ladder",
    "bm1370_and_bm1368_chip_ids_are_distinct_in_discriminator",
    "bm1370_serial_execution_requires_exact_experimental_chip_authority",
    "bm1398_fixture_validates_full_header_with_rolled_midstate",
    "bm1398_rejects_out_of_range_midstate_even_without_rolling",
    "bm1398_work_id_wraps_on_seven_bit_job_ring",
    "exact_am2_apw_applicability_is_explicit_and_unclassified_state_cannot_close",
    "exact_am2_bm1362_init_uses_constructor_plan_and_retained_observations",
    "exact_am2_power_boundary_remains_crossed_when_gpio_assertion_is_unknown",
    "exact_route_api_lifecycle_distinguishes_never_opened_from_opened_and_closed",
    "native_amlogic_serial_source_has_one_validated_write_and_shutdown_path",
    "nopic_family_classifier_matches_profile_table",
    "pic_enable_cmd_vnish_byte_exact",
    "pic_family_default_path_is_unchanged_for_non_nopic_units",
    "pinned_bm1370_model_wins_over_misleading_chip_count",
    "retired_bhb56_dspic_route_has_no_runtime_capability_surface",
    "s21pro_family_models_resolve_to_bm1370_not_bm1368",
    "serial_actor_distinguishes_empty_poll_liveness_from_committed_work",
    "serial_actor_mints_commit_evidence_only_after_successful_tx",
    "serial_address_ladder_is_unchanged_for_shipped_populations_and_safe_at_one_chip",
    "serial_share_fixture_keeps_target_and_achieved_difficulty_separate",
    # S19k Track-1 2026-08-15/16: industrial PLL policy + Braiins passthrough.
    "industrial_serial_pll_policy_is_exact_route_bound_and_fail_closed",
    "industrial_serial_pll_searches_enforce_vendor_vco_envelope",
    "s19k_braiins_bm1366_passthrough_opens_both_ttys",
    "s19k_braiins_bm1366_passthrough_uses_closed_21_36_builder",
)

EXACT_PREFIX = "sh ../scripts/run_exact_cargo_test.sh "
_TEST_FN = re.compile(
    r"#\[(?:\w+::)?test[^\]]*\]\s*(?:async\s+)?fn\s+(\w+)",
    re.MULTILINE,
)
_MOD_BODY = re.compile(
    r"mod work_dispatch_admission_tests\s*\{",
    re.MULTILINE,
)


def extract_brace_body(text: str, open_brace_index: int) -> str:
    """Return text inside `{...}` starting at open_brace_index (the `{`)."""
    if open_brace_index < 0 or open_brace_index >= len(text) or text[open_brace_index] != "{":
        raise ValueError("open_brace_index must point at '{'")
    depth = 0
    i = open_brace_index
    in_str: str | None = None
    in_line_comment = False
    in_block = False
    while i < len(text):
        c = text[i]
        n = text[i + 1] if i + 1 < len(text) else ""
        if in_line_comment:
            if c == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block:
            if c == "*" and n == "/":
                in_block = False
                i += 2
                continue
            i += 1
            continue
        if in_str is not None:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c == "/" and n == "/":
            in_line_comment = True
            i += 2
            continue
        if c == "/" and n == "*":
            in_block = True
            i += 2
            continue
        if c in "\"'":
            in_str = c
            i += 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace_index + 1 : i]
        i += 1
    raise ValueError("unbalanced braces extracting module body")


def work_dispatch_tests_in_source(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    match = _MOD_BODY.search(text)
    if not match:
        raise SystemExit(f"missing work_dispatch_admission_tests in {path}")
    brace = text.find("{", match.start())
    body = extract_brace_body(text, brace)
    return _TEST_FN.findall(body)


def required_work_dispatch_selectors() -> list[str]:
    selectors: list[str] = []
    for engine, path in ENGINE_MODULES:
        if not path.is_file():
            raise SystemExit(f"missing engine source: {path}")
        for name in work_dispatch_tests_in_source(path):
            selectors.append(f"{engine}::work_dispatch_admission_tests::{name}")
    return selectors


def required_serial_must_wire_selectors() -> list[str]:
    return [
        f"serial_mining::tests::{name}" for name in SERIAL_MUST_WIRE_UNDER_TESTS
    ]


def all_required_selectors() -> list[str]:
    return required_work_dispatch_selectors() + required_serial_must_wire_selectors()


def extract_exact_commands(path: Path) -> list[str]:
    found: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        start = raw.find(EXACT_PREFIX)
        if start < 0:
            continue
        command = raw[start:].strip()
        if command.endswith("\\"):
            command = command[:-1].rstrip()
        command = command.strip("'\"")
        found.append(command)
    return found


def selectors_from_commands(commands: list[str]) -> set[str]:
    out: set[str] = set()
    for command in commands:
        # sh ../scripts/run_exact_cargo_test.sh SELECTOR --locked ...
        rest = command[len(EXACT_PREFIX) :].strip()
        selector = rest.split()[0] if rest else ""
        if selector:
            out.add(selector)
    return out


def inventory_engine_tests_under_tests_mod(src: Path) -> list[str]:
    """Test fn names inside `mod tests { ... }` only (sibling modules excluded)."""
    text = src.read_text(encoding="utf-8")
    marker = "\n#[cfg(test)]\nmod tests {"
    start = text.find(marker)
    if start < 0:
        return []
    brace = text.find("{", start)
    # Stop at sibling work_dispatch module if present (column-0 sibling after tests).
    wd = text.find("\n#[cfg(test)]\nmod work_dispatch_admission_tests {")
    if wd > brace:
        body = text[brace + 1 : wd]
    else:
        body = extract_brace_body(text, brace)
    return _TEST_FN.findall(body)


def inventory_serial_tests_under_tests_mod() -> list[str]:
    return inventory_engine_tests_under_tests_mod(SERIAL_SRC)


def inventory_hybrid_tests_under_tests_mod() -> list[str]:
    return inventory_engine_tests_under_tests_mod(HYBRID_SRC)


def check_coverage(
    workflow_path: Path = WORKFLOW,
    static_path: Path = STATIC_GATE,
) -> list[str]:
    failures: list[str] = []
    required = all_required_selectors()
    if len(required) < 30:
        failures.append(
            f"expected ≥30 work-dispatch selectors across 4 engines (+serial must-wire), got {len(required)}"
        )

    wf_cmds = extract_exact_commands(workflow_path)
    st_cmds = extract_exact_commands(static_path)
    wf_sel = selectors_from_commands(wf_cmds)
    st_sel = selectors_from_commands(st_cmds)

    for selector in required:
        cmd_fragment = f"{EXACT_PREFIX}{selector} "
        # Allow end-of-line without trailing space after selector args start
        in_wf = any(
            c.startswith(f"{EXACT_PREFIX}{selector} ")
            or c.startswith(f"{EXACT_PREFIX}{selector}\t")
            or c == f"{EXACT_PREFIX}{selector}"
            or f"{EXACT_PREFIX}{selector} --" in c
            for c in wf_cmds
        )
        in_st = any(
            c.startswith(f"{EXACT_PREFIX}{selector} ")
            or c.startswith(f"{EXACT_PREFIX}{selector}\t")
            or c == f"{EXACT_PREFIX}{selector}"
            or f"{EXACT_PREFIX}{selector} --" in c
            for c in st_cmds
        )
        if not in_wf:
            failures.append(f"workflow missing exact selector: {selector}")
        if not in_st:
            failures.append(f"static inventory missing exact selector: {selector}")
        # Prefer also present in set for messaging
        _ = cmd_fragment, wf_sel, st_sel

    # Inventory honesty: every serial_mining::tests unit must be exact-wired
    # (tier-5 closed 2026-07-29). New tests without CI wire fail closed.
    under_tests = inventory_serial_tests_under_tests_mod()
    wired_tests = {
        s.removeprefix("serial_mining::tests::")
        for s in wf_sel
        if s.startswith("serial_mining::tests::")
    }
    orphans = sorted(set(under_tests) - wired_tests)
    # Always print inventory for residual ledger consumers.
    print(
        f"serial_mining::tests inventory: total={len(under_tests)} "
        f"wired_exact={len(wired_tests & set(under_tests))} "
        f"orphans={len(orphans)}"
    )
    print(
        f"work_dispatch must-wire selectors: {len(required_work_dispatch_selectors())}"
    )
    print(
        f"serial must-wire under tests:: : {len(SERIAL_MUST_WIRE_UNDER_TESTS)}"
    )
    if orphans:
        preview = ", ".join(orphans[:8])
        more = "" if len(orphans) <= 8 else f" (+{len(orphans) - 8} more)"
        failures.append(
            f"serial_mining::tests has {len(orphans)} unwired exact-selector "
            f"orphans (add to offline-gates + SERIAL_MUST_WIRE_UNDER_TESTS): "
            f"{preview}{more}"
        )
    # SERIAL_MUST_WIRE is the tiered residual list (subset); pre-wired historical
    # contracts need not re-list here. Require the tier list ⊆ inventory ∩ CI.
    unknown_must = sorted(set(SERIAL_MUST_WIRE_UNDER_TESTS) - set(under_tests))
    if unknown_must:
        failures.append(
            f"SERIAL_MUST_WIRE_UNDER_TESTS names not in serial_mining::tests: "
            f"{', '.join(unknown_must[:8])}"
        )

    # Hybrid tests:: zero-orphan ratchet (2026-07-29 continuous-audit).
    hybrid_under = inventory_hybrid_tests_under_tests_mod()
    hybrid_wired = {
        s.removeprefix("s19j_hybrid_mining::tests::")
        for s in wf_sel
        if s.startswith("s19j_hybrid_mining::tests::")
    }
    hybrid_orphans = sorted(set(hybrid_under) - hybrid_wired)
    print(
        f"s19j_hybrid_mining::tests inventory: total={len(hybrid_under)} "
        f"wired_exact={len(hybrid_wired & set(hybrid_under))} "
        f"orphans={len(hybrid_orphans)}"
    )
    if hybrid_orphans:
        preview = ", ".join(hybrid_orphans[:8])
        more = (
            ""
            if len(hybrid_orphans) <= 8
            else f" (+{len(hybrid_orphans) - 8} more)"
        )
        failures.append(
            f"s19j_hybrid_mining::tests has {len(hybrid_orphans)} unwired "
            f"exact-selector orphans (add to offline-gates): {preview}{more}"
        )
    return failures


def main(argv: list[str] | None = None) -> int:
    _ = argv  # reserved
    try:
        failures = check_coverage()
    except SystemExit as exc:
        print(f"check_work_dispatch_ci_coverage: FAIL {exc}", file=sys.stderr)
        return 1
    if failures:
        print("check_work_dispatch_ci_coverage: FAIL", file=sys.stderr)
        for item in failures:
            print(f"  - {item}", file=sys.stderr)
        return 1
    print("check_work_dispatch_ci_coverage: PASS")
    print(f"  required_selectors={len(all_required_selectors())}")
    engines = ",".join(name for name, _ in ENGINE_MODULES)
    print(f"  engines={engines}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
