#!/usr/bin/env python3
"""Static checks for dev_deploy.sh evidence-output support."""

from __future__ import annotations

import shutil
import subprocess
import unittest
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/dev_deploy.sh"
RECOVERY_HELPER = (
    ROOT
    / "br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos"
    / "dcentrald-deploy-recovery.sh"
)
ZYNQ_INIT = (
    ROOT
    / "br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S82dcentrald"
)
AM2_ZYNQ_INITS = (
    ROOT
    / "br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/etc/init.d/S82dcentrald",
    ROOT
    / "br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/etc/init.d/S82dcentrald",
    ROOT
    / "br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/etc/init.d/S82dcentrald",
)
RECOVERY_ADMIN = ROOT / "scripts/dev_deploy_recovery_admin.sh"
UPGRADE_GUARD = (
    ROOT
    / "br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos"
    / "dcentrald-deploy-upgrade-guard.sh"
)
SYSUPGRADE_PATHS = (
    ROOT / "br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/sysupgrade",
    ROOT
    / "br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/usr/sbin/sysupgrade",
    ROOT
    / "br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/usr/sbin/sysupgrade",
    ROOT
    / "br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/usr/sbin/sysupgrade",
)


class DevDeployOutputStaticTest(unittest.TestCase):
    def test_bash_syntax(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not available")
        subprocess.run([bash, "-n", "scripts/dev_deploy.sh"], cwd=ROOT, check=True)
        subprocess.run(
            [bash, "-n", RECOVERY_HELPER.relative_to(ROOT).as_posix()],
            cwd=ROOT,
            check=True,
        )
        subprocess.run(
            [bash, "-n", ZYNQ_INIT.relative_to(ROOT).as_posix()],
            cwd=ROOT,
            check=True,
        )
        subprocess.run(
            [bash, "-n", RECOVERY_ADMIN.relative_to(ROOT).as_posix()],
            cwd=ROOT,
            check=True,
        )
        subprocess.run(
            [bash, "-n", UPGRADE_GUARD.relative_to(ROOT).as_posix()],
            cwd=ROOT,
            check=True,
        )
        for sysupgrade in SYSUPGRADE_PATHS:
            subprocess.run(
                [bash, "-n", sysupgrade.relative_to(ROOT).as_posix()],
                cwd=ROOT,
                check=True,
            )

    def test_json_output_file_option_is_wired(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("JSON_OUTPUT_FILE=\"\"", text)
        self.assertIn("--output)           JSON_OUTPUT_FILE=", text)
        self.assertIn("--output=*)         JSON_OUTPUT_FILE=", text)
        self.assertIn("write_json_payload()", text)
        self.assertIn(
            'json_exit true null "$DASHBOARD_BYTES" false '
            '"Dashboard-only deploy successful"',
            text,
        )
        self.assertNotIn("DASHBOARD_DEPLOY_JSON", text)
        self.assertIn("write_json_payload \"$DEPLOY_JSON\"", text)
        self.assertIn('sync -f "$output_tmp"', text)
        self.assertIn('sync -f "$output_dir"', text)

    def test_json_string_escapes_every_representable_c0_control(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not available")
        text = SCRIPT.read_text(encoding="utf-8")
        function = text.split("json_string() {", 1)[1].split(
            "\n}\n\nwrite_json_payload()", 1
        )[0]
        definition = "json_string() {" + function + "\n}\n"
        sanity = subprocess.run(
            [bash],
            input=(definition + "json_string hello\n").encode("utf-8"),
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            sanity.stdout.decode("utf-8"),
            '"hello"',
            sanity.stderr.decode("utf-8") + definition,
        )
        for code in range(1, 32):
            with self.subTest(code=code):
                value = "prefix" + chr(code) + "suffix"
                program = definition + f"json_string $'prefix\\{code:03o}suffix'"
                result = subprocess.run(
                    [bash],
                    input=(program + "\n").encode("utf-8"),
                    capture_output=True,
                    check=False,
                )
                stderr = result.stderr.decode("utf-8")
                stdout = result.stdout.decode("utf-8")
                self.assertEqual(result.returncode, 0, stderr)
                self.assertEqual(json.loads(stdout), value)
        self.assertIn("json.dumps", text)

    def test_success_receipt_is_atomic_and_failure_reclaims_runtime_launch(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('mktemp "$output_dir/.dcent-deploy.XXXXXX"', text)
        self.assertIn('mv -fT -- "$output_tmp" "$JSON_OUTPUT_FILE"', text)
        self.assertIn('[ -L "$JSON_OUTPUT_FILE" ]', text)
        self.assertIn('[ ! -f "$JSON_OUTPUT_FILE" ]', text)
        self.assertIn('[ "$receipt_publication_status" -ne 2 ]', text)
        self.assertIn("cleanup_runtime_launch || true", text)
        self.assertIn("directory durability is unproven", text)
        self.assertIn(
            'if write_json_payload "$DEPLOY_JSON"; then\n'
            '    receipt_publication_status=0\nelse\n'
            '    receipt_publication_status=$?',
            text,
        )
        self.assertIn("rollback_persistent_files || true", text)
        self.assertIn("trap cleanup_uncommitted_runtime_on_exit EXIT", text)
        self.assertIn('RUNTIME_LAUNCH_ATTEMPTED=false', text)
        self.assertIn("recover_runtime_launch_identity()", text)
        self.assertIn('printf "RUNTIME_DISCOVERY=ambiguous\\n"', text)
        self.assertIn("RUNTIME_LAUNCH_COMMITTED=true", text)
        self.assertIn("trap '' INT TERM HUP", text)
        self.assertIn("DCENT_DEPLOY_LAUNCH_ID=$LAUNCH_ID", text)
        self.assertIn('expected_launch_id=', text)
        self.assertIn('/proc/$pid/environ', text)
        self.assertIn('"receipt_schema": "dcent-dev-deploy-v3"', text)
        self.assertIn('"persistent_transaction_schema":', text)
        self.assertIn('"persistent_transaction_identity_sha256":', text)
        self.assertIn('"persistent_transaction_terminal_path":', text)
        self.assertIn('"deploy_id": $json_deploy_id', text)
        self.assertIn('"cleanup_status": $json_cleanup_status', text)
        self.assertIn("build_receipt_payload()", text)
        self.assertIn(
            '"Deploy successful" "$SUCCESS_CLEANUP_STATUS"', text
        )
        self.assertIn('rm -f -- "$JSON_OUTPUT_FILE"', text)

    def test_absent_config_is_never_blindly_overwritten_or_removed(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        recovery = RECOVERY_HELPER.read_text(encoding="utf-8")
        self.assertIn(
            '[ ! -e "\\$config_path" ] && [ ! -L "\\$config_path" ]',
            text,
        )
        self.assertIn("config_absent_rollback_state=candidate", text)
        self.assertIn('= "$config_candidate_sha" ]', text)
        self.assertIn('= "0:0:600" ]', text)
        self.assertIn('ln -T "\\$config_stage" "\\$config_path"', text)
        self.assertIn("retire_absent_original_config()", text)
        self.assertIn('quarantine_dir=\'"$REMOTE_RUN_DIR/config-retirement"\'', text)
        self.assertIn("reconcile_config_retirement()", text)
        self.assertIn(
            'retire_path "$config_path" "$quarantined_config"', text
        )
        self.assertIn(
            'restore_path_alias "$quarantined_config" "$config_path"', text
        )
        self.assertNotIn('ln -T "$config_path" "$quarantined_config"', text)
        self.assertNotIn('rm -f "$config_path" || return 1', text)
        self.assertNotIn('ln -T "$quarantined_config" "$config_path"', text)
        self.assertIn(
            "deploy_path_helper=/usr/libexec/dcentos/dcentos-deploy-path",
            text,
        )
        self.assertNotIn('ln -sT -- "$quarantined_target" "$config_path"', text)
        self.assertNotIn("dcent-retire", text)
        self.assertIn("dcent_deploy_classify_absent_original_config()", recovery)
        self.assertIn("DCENT_DEPLOY_ABSENT_CONFIG_STATE=candidate", recovery)
        self.assertIn("dcent_deploy_retire_absent_original_config()", recovery)
        self.assertIn(
            'DCENT_DEPLOY_QUARANTINE_DIR="$DCENT_DEPLOY_RUN_DIR/config-retirement"',
            recovery,
        )
        self.assertIn("dcent_deploy_reconcile_config_retirement()", recovery)
        self.assertIn(
            'dcent_deploy_retire_path "$DCENT_DEPLOY_CONFIG_PATH"',
            recovery,
        )
        self.assertIn(
            'dcent_deploy_restore_path_alias "$DCENT_DEPLOY_QUARANTINED_CONFIG"',
            recovery,
        )
        self.assertNotIn(
            'ln -T "$DCENT_DEPLOY_CONFIG_PATH" "$DCENT_DEPLOY_QUARANTINED_CONFIG"',
            recovery,
        )
        self.assertIn(
            "/usr/libexec/dcentos/dcentos-deploy-path", recovery
        )
        self.assertNotIn('rm -f "$DCENT_DEPLOY_CONFIG_PATH" || return 1', recovery)
        self.assertNotIn(
            'ln -T "$DCENT_DEPLOY_QUARANTINED_CONFIG" "$DCENT_DEPLOY_CONFIG_PATH"',
            recovery,
        )
        self.assertNotIn('ln -sT -- "$DCENT_DEPLOY_QUARANTINED_TARGET"', recovery)
        self.assertNotIn("dcent-retire", recovery)
        self.assertIn(
            '= "$DCENT_DEPLOY_CONFIG_CANDIDATE_SHA" ] || return 1', recovery
        )
        self.assertIn(
            '= "$DCENT_DEPLOY_EXPECTED_UID:0:600" ] || return 1', recovery
        )

    def test_runtime_launch_state_closes_lost_output_race(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("runtime-launch.authorized", text)
        self.assertIn("runtime-launch.starting", text)
        self.assertIn("runtime-launch.started", text)
        self.assertIn("runtime-launch.cancelled", text)
        self.assertIn('mv "$authorized" "$cancelled" 2>/dev/null || true', text)
        self.assertIn("for attempt in $(seq 1 30); do", text)
        self.assertIn("RUNTIME_LAUNCH_STATE=dcent-runtime-launch-v2", text)
        self.assertIn('started_schema=$(assignment_value RUNTIME_LAUNCH_STATE', text)
        self.assertIn('[ "\${NEW_EXE:-}" = "$DEPLOY_PATH" ] || {', text)
        self.assertIn('launch_started_new="$REMOTE_RUN_DIR/runtime-launch.started.new"', text)
        self.assertIn(
            '[ -f "$starting" ] && '
            '[ "$(cat "$starting" 2>/dev/null)" = "$expected_launch_id" ]',
            text,
        )
        self.assertIn('if [ "$runtime_cleanup_ok" = true ]; then', text)
        self.assertIn("Preserving private remote launch state for manual recovery", text)
        self.assertIn("launch_recovery_state_retained", text)
        self.assertIn("distributed-transaction hole", text)
        self.assertIn('LAUNCHED_PID="$NEW_PID"', text)
        self.assertIn('LAUNCHED_EXE="$NEW_EXE"', text)
        self.assertIn("verify_committed_launch_state()", text)
        self.assertIn('"LAUNCH_STATE=committed"', text)
        self.assertIn("CONFIG_SOURCE=%s", text)
        self.assertIn("CONFIG_PATH=%s", text)
        self.assertIn("CONFIG_SHA256=%s", text)

    def test_success_rearbitrates_daemon_and_vendor_ownership(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("FINAL_OWNERSHIP=$(ssh_run '", text)
        self.assertIn("dcentral_matches=0", text)
        self.assertIn("vendor_matches=0", text)
        self.assertIn(
            '[ "$dcentral_matches" -eq 1 ] && [ "$vendor_matches" -eq 0 ]',
            text,
        )

    def test_persistent_deploy_is_recoverable_and_never_claims_best_effort_rollback(
        self,
    ) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("persistent deployment requires --output FILE", text)
        self.assertIn("DEPLOY_EXISTING_SHA256", text)
        self.assertIn('PERSISTENT_CONFIG_STAGE_PATH="$REMOTE_RUN_DIR/', text)
        self.assertIn('PERSISTENT_CONFIG_BACKUP_PATH="$REMOTE_RUN_DIR/', text)
        self.assertIn('PERSISTENT_MUTATION_STARTED=true', text)
        self.assertIn("rollback_persistent_files()", text)
        self.assertIn(
            "files_restored_launch_stopped_ownership_unverified", text
        )
        self.assertIn("cleanup_persistent_launch ||", text)
        self.assertIn("refused_owner_unproven_recovery_artifacts_retained", text)
        self.assertIn('existing_sha=', text)
        self.assertIn('sha256sum "\$deploy_path"', text)
        self.assertIn('config_original_sha=', text)
        self.assertIn('config_original_metadata=', text)
        self.assertIn('sha256sum "\$config_path"', text)
        self.assertIn('"original_binary_sha256":', text)
        self.assertIn('"original_binary_metadata":', text)
        self.assertIn('"original_config_sha256":', text)
        self.assertIn('"original_config_metadata":', text)
        self.assertIn('"config_binding_source":', text)
        self.assertIn("CONFIG_BIND_SOURCE=discovered", text)
        self.assertIn("START_ERROR=builtin_config_selection_changed", text)
        self.assertIn('/data/.dcent-deploy-recovery/$DEPLOY_ID', text)
        self.assertIn("verified_durable_retained", text)
        self.assertIn("cp -p '$DEPLOY_PATH' '$BACKUP_PATH'", text)
        self.assertIn("cp -p '$CONFIG_REMOTE' '$PERSISTENT_CONFIG_BACKUP_PATH'", text)
        self.assertIn('cp -p "$backup_path" "$restore_tmp"', text)
        self.assertIn('cp -p "$config_backup" "$restore_tmp"', text)
        self.assertNotIn('ln "$backup_path" "$restore_tmp"', text)
        self.assertNotIn('ln "$config_backup" "$restore_tmp"', text)
        self.assertIn("PERSISTENT_MIN_FREE_RESERVE_BYTES=1048576", text)
        self.assertIn("DEPLOY_FREE_INODES", text)
        self.assertIn('mv -f "\$staging_path" "\$deploy_path"', text)
        self.assertIn('mv -f "\$config_stage" "\$config_path"', text)
        self.assertIn('ln -T "\$config_stage" "\$config_path"', text)
        self.assertNotIn('cp "\$staging_path" "\$deploy_path"', text)
        self.assertIn('"recovery_artifact_path": $json_recovery_path', text)
        self.assertIn('"backup_status": $json_backup_status', text)
        self.assertIn('"rollback_status": $json_rollback_status', text)
        self.assertIn('"binary_sha256": $json_binary_sha256', text)
        self.assertIn('"config_sha256": $json_config_sha256', text)
        self.assertIn('"api_verification_status": $json_api_verification_status', text)
        self.assertIn("PERSISTENT_TX_STATE=dcent-persistent-tx-v4", text)
        self.assertIn("BINARY_ORIGINAL_METADATA=", text)
        self.assertIn("CONFIG_ORIGINAL_METADATA=", text)
        self.assertIn("probe_persistent_recovery_capability()", text)
        self.assertIn('"$init" deploy-recovery-capabilities', text)
        self.assertIn("PERSISTENT_TX_IDENTITY_SHA256", text)
        self.assertIn("PERSISTENT_DEPLOY_LEASE_ACQUIRED", text)
        self.assertIn('if [ -e "$candidate" ] || [ -L "$candidate" ]; then', text)
        self.assertIn(
            "if [ -e '$CONFIG_REMOTE' ] || [ -L '$CONFIG_REMOTE' ]; then",
            text,
        )
        self.assertIn(
            "if [ -e /etc/dcentrald.toml ] || [ -L /etc/dcentrald.toml ]; then",
            text,
        )
        self.assertIn('lease="$base/.deploy-lease"', text)
        self.assertIn('set -- "$base"/*/persistent-transaction.state', text)
        self.assertLess(text.index('mkdir "$lease"'), text.index('mkdir "$run_dir"'))
        self.assertIn("release_persistent_deploy_lease()", text)
        self.assertIn("acquire_deploy_maintenance()", text)
        self.assertLess(
            text.index("if ! acquire_deploy_maintenance; then"),
            text.index("MINER_INFO=$(ssh_run"),
        )
        self.assertIn("/usr/libexec/dcentos/dcentos-deploy-lock", text)
        self.assertIn("maintenance_exclusion_at_receipt_publication", text)
        success_publish = text.rindex('if write_json_payload "$DEPLOY_JSON"; then')
        lease_retire = text.rindex(
            'if [ "$DEPLOY_MODE" = persistent ] && '
            '! release_persistent_deploy_lease; then'
        )
        self.assertLess(success_publish, lease_retire)
        self.assertIn('mv "$lease" "$retired"', text)
        self.assertIn("deploy_lease_status_at_receipt_publication", text)
        self.assertIn("ROLLBACK_CONFIG_SOURCE=", text)
        self.assertIn("rollback_config_source=", text)
        self.assertIn("tx_set_phase prepared mutating", text)
        self.assertIn("tx_set_phase mutating installed", text)
        self.assertIn("finalize_persistent_transaction()", text)
        self.assertIn("mark_persistent_transaction_failed()", text)
        self.assertIn('"persistent_transaction_status":', text)
        self.assertIn('"rollback_config_source":', text)
        self.assertIn('"rollback_config_path":', text)
        self.assertIn('"rollback_config_sha256":', text)
        self.assertIn("persistent-transaction.rolled-back", text)
        self.assertNotIn('chmod +x "$restore_tmp"', text)
        self.assertNotIn("rolled back to backup", text)
        self.assertNotIn("Restored backup, PID=", text)

    def test_boot_recovery_resolves_one_generation_before_daemon_selection(
        self,
    ) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not available")
        helper = RECOVERY_HELPER.read_text(encoding="utf-8")
        init = ZYNQ_INIT.read_text(encoding="utf-8")
        self.assertIn("dcent_recover_pending_deploy()", helper)
        self.assertIn("dcent_deploy_print_capabilities()", helper)
        self.assertIn("DCENT_DEPLOY_RECOVERY_SCHEMA_MIN=3", helper)
        self.assertIn("DCENT_DEPLOY_RECOVERY_SCHEMA_MAX=4", helper)
        self.assertIn("dcent_deploy_path_helper_ready || return 1", helper)
        self.assertIn(
            '"$DCENT_DEPLOY_PATH_HELPER" probe "$DCENT_DEPLOY_PATH_PROBE_DIR"',
            helper,
        )
        self.assertIn("Multiple pending persistent deploy transactions", helper)
        self.assertIn('[ -L "$DCENT_DEPLOY_RECOVERY_BASE" ]', helper)
        self.assertIn('if [ ! -e "$1" ] && [ ! -L "$1" ]; then', helper)
        self.assertIn("Validate every required recovery artifact", helper)
        self.assertIn("persistent-transaction.recovered", helper)
        self.assertIn("persistent-transaction.committed", helper)
        self.assertIn("pidof dcentrald", helper)
        self.assertIn("dcent_deploy_sync || return 1", helper)
        self.assertIn("dcent_verify_resolved_deploy_config()", helper)
        self.assertIn("dcent_verify_resolved_deploy_generation()", helper)
        self.assertIn("dcent_verify_resolved_deploy_binary()", helper)
        self.assertIn("dcent_verify_resolved_deploy_selection()", helper)
        self.assertIn("DCENT_DEPLOY_EXPECTED_FALLBACK_BINARY", helper)

        self.assertIn("dcent_deploy_synthesize_leased_terminal_state()", helper)
        self.assertIn("dcent_deploy_release_matching_lease()", helper)
        self.assertIn('print "PHASE=recovered"', helper)
        self.assertIn("recovered|rolled_back", helper)
        self.assertIn("dcent_deploy_validate_rollback_binding_live", helper)
        self.assertIn("resolve_interrupted_persistent_deploy()", init)
        self.assertIn("deploy-recovery-capabilities)", init)
        self.assertIn("dcent_deploy_print_capabilities", init)
        for am2_init in AM2_ZYNQ_INITS:
            self.assertNotIn(
                "deploy-recovery-capabilities)",
                am2_init.read_text(encoding="utf-8"),
            )
        self.assertIn('exec "$DEPLOY_LOCK_HELPER" --handoff', init)
        self.assertIn('"$DEPLOY_LOCK_HELPER" --ready', init)
        self.assertIn('start-locked)', init)
        self.assertIn("dcent_validate_deploy_lock_handoff()", init)
        self.assertIn('readlink "/proc/$PPID/exe"', init)
        self.assertIn("dcentrald deploy-lock handoff provenance is invalid", init)
        self.assertIn('DEPLOY_MAINTENANCE_MARKER', init)
        start = init.split('    start)', 1)[1]
        locked = start.split('    start-locked)', 1)[1]
        self.assertLess(
            locked.index("dcent_validate_deploy_lock_handoff"),
            locked.index("resolve_interrupted_persistent_deploy"),
        )
        self.assertLess(
            start.index("resolve_interrupted_persistent_deploy"),
            start.index("select_dcentrald_paths"),
        )
        self.assertLess(
            start.index("select_dcentrald_paths"),
            start.index('[ ! -x "$DAEMON" ]'),
        )
        self.assertLess(
            start.index("select_dcentrald_paths"),
            start.index("dcent_verify_resolved_deploy_generation"),
        )
        self.assertGreaterEqual(start.count("dcent_verify_resolved_deploy_generation"), 2)
        self.assertGreaterEqual(start.count("dcent_verify_resolved_deploy_selection"), 2)
        self.assertLess(
            start.rindex("dcent_verify_resolved_deploy_generation"),
            start.index('/bin/sh "$SESSION_LATCH_HELPER" supervise'),
        )
        self.assertNotIn("start-stop-daemon -S -b", start)
        self.assertIn('DCENTOS_SESSION_WRAPPER_PIDFILE="$PIDFILE"', start)

        direct = subprocess.run(
            [bash, ZYNQ_INIT.relative_to(ROOT).as_posix(), "start-locked"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(direct.returncode, 0)
        self.assertIn(
            "dcentrald deploy-lock handoff provenance is invalid",
            direct.stdout + direct.stderr,
        )

    def test_deploy_path_helper_is_built_into_every_target(self) -> None:
        config_in = (ROOT / "br2_external_dcentos/Config.in").read_text(
            encoding="utf-8"
        )
        common = (
            ROOT / "br2_external_dcentos/configs/dcentos-common.fragment"
        ).read_text(encoding="utf-8")
        source = (
            ROOT
            / "br2_external_dcentos/packages/dcentos-deploy-path/src"
            / "dcentos-deploy-path.c"
        ).read_text(encoding="utf-8")
        self.assertIn("packages/dcentos-deploy-path/Config.in", config_in)
        self.assertIn("BR2_PACKAGE_DCENTOS_DEPLOY_PATH=y", common)
        self.assertIn("renameat(", source)
        self.assertIn("linkat(", source)
        self.assertIn("syncfs(", source)
        self.assertIn('#define PROBE_NAMESPACE ".dcent-deploy-path-probe"', source)
        self.assertIn("reconcile_probe_namespace", source)
        self.assertIn("LOCK_EX | LOCK_NB", source)
        self.assertNotIn("getpid()", source)
        self.assertIn("AT_SYMLINK_NOFOLLOW", source)
        self.assertNotIn("SYS_renameat2", source)

    def test_every_init_script_selecting_persistent_binary_uses_shared_lock(
        self,
    ) -> None:
        init_scripts = (
            ROOT / "br2_external_dcentos/board"
        ).glob("**/etc/init.d/S82dcentrald")
        persistent_selectors = []
        for init_script in init_scripts:
            text = init_script.read_text(encoding="utf-8")
            if 'DAEMON="/data/dcentrald"' not in text:
                continue
            persistent_selectors.append(init_script)
            self.assertIn("dcentos-deploy-lock", text, init_script.as_posix())
            self.assertIn(
                'exec "$DEPLOY_LOCK_HELPER" --handoff',
                text,
                init_script.as_posix(),
            )
            self.assertIn('"$DEPLOY_LOCK_HELPER" --ready', text, init_script.as_posix())
        self.assertEqual(persistent_selectors, [ZYNQ_INIT])

    def test_every_zynq_sysupgrade_serializes_and_guards_dev_generation(
        self,
    ) -> None:
        for sysupgrade in SYSUPGRADE_PATHS:
            text = sysupgrade.read_text(encoding="utf-8")
            with self.subTest(sysupgrade=sysupgrade.as_posix()):
                self.assertIn("DCENT_SYSUPGRADE_DEPLOY_LOCK_HELD=1", text)
                self.assertIn(
                    'exec "$DEPLOY_LOCK_HELPER" -- env',
                    text,
                )
                self.assertIn("sysupgrade deploy-lock provenance is invalid", text)
                self.assertIn("dcentrald-deploy-upgrade-guard.sh", text)
                self.assertIn("dcent_deploy_upgrade_guard", text)

    def test_committed_revocation_publishes_rollback_phase_before_unlink(
        self,
    ) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn('mv "$committed" "$state"', text)
        mark = text.split("mark_persistent_transaction_failed() {", 1)[1].split(
            "\n}\n\n# Commit a persistent generation", 1
        )[0]
        rollback = text.split("rollback_persistent_files() {", 1)[1].split(
            "\n}\n\ncleanup_uncommitted_runtime_on_exit", 1
        )[0]
        for block, phase in ((mark, "failed"), (rollback, "rolling_back")):
            self.assertIn(f'print "PHASE={phase}"', block)
            self.assertLess(
                block.index('mv "$revoke_tmp" "$state"'),
                block.index('rm -f "$committed"'),
            )
            between = block[
                block.index('mv "$revoke_tmp" "$state"') :
                block.index('rm -f "$committed"')
            ]
            self.assertIn("sync", between)

    def test_commit_terminal_publication_is_exact_and_durable(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        commit = text.split("finalize_persistent_transaction() {", 1)[1].split(
            "\n}\n\n# Restore only the prior persistent bytes", 1
        )[0]
        self.assertNotIn('mv "$terminal_tmp" "$committed"', commit)
        self.assertNotIn('cat "$state" >"$terminal_tmp"', commit)
        self.assertIn('ln -T "$state" "$committed"', commit)
        publish = commit.index('ln -T "$state" "$committed"')
        retire_temp = commit.index('rm -f "$terminal_tmp"', publish)
        retire_state = commit.index('rm -f "$state"', retire_temp)
        self.assertIn("sync", commit[publish:retire_temp])
        self.assertIn("sync", commit[retire_temp:retire_state])
        self.assertIn('stat -c "%u:%a:%h" "$committed"', commit)

    def test_rollback_terminal_cleanup_validates_legacy_temporary(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        rollback = text.split("rollback_persistent_files() {", 1)[1].split(
            "\n}\n\ncleanup_uncommitted_runtime_on_exit()", 1
        )[0]
        publication = rollback.split('terminal_tmp="$rolled_back.new"', 1)[1]
        cleanup = publication.split('rm -f "$terminal_tmp"', 1)[0]
        self.assertIn('[ -f "$terminal_tmp" ] && [ ! -L "$terminal_tmp" ]', cleanup)
        self.assertIn('stat -c "%u:%a:%h" "$terminal_tmp"', cleanup)
        self.assertIn("0:600:1|0:600:2", cleanup)

    def test_transaction_bound_config_is_not_legacy_migrated(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not available")
        init = ZYNQ_INIT.read_text(encoding="utf-8")
        body = init.split("migrate_legacy_api_port() {", 1)[1].split(
            "\n}\n\nbosminer_pic_bootstrap_enabled()", 1
        )[0]
        function = "migrate_legacy_api_port() {" + body + "\n}\n"
        scenario = r'''
root=$(mktemp -d "${TMPDIR:-/tmp}/dcent-migrate-test.XXXXXX")
trap 'rm -rf "$root"' EXIT HUP INT TERM
CONFIG="$root/dcentrald.toml"
printf '[api]\nhttp_port = 80\n' >"$CONFIG"
DCENT_DEPLOY_CONFIG_BINDING_ACTIVE=1
migrate_legacy_api_port
grep -Fqx 'http_port = 80' "$CONFIG"
DCENT_DEPLOY_CONFIG_BINDING_ACTIVE=0
migrate_legacy_api_port
grep -Fqx 'http_port = 8080' "$CONFIG"
'''
        result = subprocess.run(
            [bash, "-s"],
            input=(function + scenario).encode("utf-8"),
            capture_output=True,
            check=False,
        )
        output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        self.assertEqual(result.returncode, 0, output)

    def test_missing_recovery_helper_rejects_dangling_base(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not available")
        init = ZYNQ_INIT.read_text(encoding="utf-8")
        body = init.split("resolve_interrupted_persistent_deploy() {", 1)[1].split(
            "\n}\n\nPLATFORM=", 1
        )[0]
        function = "resolve_interrupted_persistent_deploy() {" + body + "\n}\n"
        scenario = r'''
root=$(mktemp -d "${TMPDIR:-/tmp}/dcent-missing-helper-test.XXXXXX")
trap 'rm -rf "$root"' EXIT HUP INT TERM
DEPLOY_RECOVERY_HELPER="$root/missing-helper"
DEPLOY_RECOVERY_BASE="$root/recovery"
ln -s "$root/missing-base-target" "$DEPLOY_RECOVERY_BASE"
if resolve_interrupted_persistent_deploy; then
    exit 1
fi
'''
        result = subprocess.run(
            [bash, "-s"],
            input=(function + scenario).encode("utf-8"),
            capture_output=True,
            check=False,
        )
        output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        self.assertEqual(result.returncode, 0, output)

    def test_missing_recovery_helper_rejects_active_deploy_lease(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not available")
        init = ZYNQ_INIT.read_text(encoding="utf-8")
        body = init.split("resolve_interrupted_persistent_deploy() {", 1)[1].split(
            "\n}\n\nPLATFORM=", 1
        )[0]
        function = "resolve_interrupted_persistent_deploy() {" + body + "\n}\n"
        scenario = r'''
root=$(mktemp -d "${TMPDIR:-/tmp}/dcent-missing-helper-lease-test.XXXXXX")
trap 'rm -rf "$root"' EXIT HUP INT TERM
DEPLOY_RECOVERY_HELPER="$root/missing-helper"
DEPLOY_RECOVERY_BASE="$root/recovery"
mkdir -p "$DEPLOY_RECOVERY_BASE/.deploy-lease"
chmod 700 "$DEPLOY_RECOVERY_BASE" "$DEPLOY_RECOVERY_BASE/.deploy-lease"
if resolve_interrupted_persistent_deploy; then
    exit 1
fi
'''
        result = subprocess.run(
            [bash, "-s"],
            input=(function + scenario).encode("utf-8"),
            capture_output=True,
            check=False,
        )
        output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        self.assertEqual(result.returncode, 0, output)

    def test_recovery_admin_prunes_only_old_terminal_transactions(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not available")
        source = RECOVERY_ADMIN.read_text(encoding="utf-8")
        self.assertIn("valid_terminal_manifest()", source)
        self.assertIn('PHASE=$expected_phase', source)
        self.assertIn('stat -c \'%u:%a:%h\'', source)
        remote = source.split("REMOTE_SCRIPT=$(cat <<'EOF'\n", 1)[1].split(
            "\nEOF\n)", 1
        )[0]
        setup = r'''
root=$(mktemp -d "${TMPDIR:-/tmp}/dcent-prune-test.XXXXXX")
trap 'rm -rf "$root"' EXIT HUP INT TERM
printf '#!/bin/sh\nshift\nexec "$@"\n' >"$root/lock-helper"
chmod 755 "$root/lock-helper"
export DCENT_DEPLOY_ADMIN_TEST_AUTHORITY=1
export DCENT_DEPLOY_LOCK_HELPER="$root/lock-helper"
export DCENT_DEPLOY_MAINTENANCE_PATH="$root/maintenance"
base="$root/recovery"
mkdir "$base"
old="$base/11111111111111111111111111111111"
middle="$base/22222222222222222222222222222222"
newest="$base/33333333333333333333333333333333"
recent_second="$base/66666666666666666666666666666666"
recent_newest="$base/77777777777777777777777777777777"
pending="$base/44444444444444444444444444444444"
launch_only="$base/55555555555555555555555555555555"
malformed="$base/00000000000000000000000000000000"
mkdir "$old" "$middle" "$newest" "$recent_second" "$recent_newest" \
    "$pending" "$launch_only" "$malformed"
chmod 700 "$base" "$old" "$middle" "$newest" "$recent_second" \
    "$recent_newest" "$pending" "$launch_only" "$malformed"
write_terminal() {
    dir=$1
    phase=$2
    leaf=$3
    id=${dir##*/}
    marker="$dir/persistent-transaction.$leaf"
    cat >"$marker" <<EOF
PERSISTENT_TX_STATE=dcent-persistent-tx-v4
DEPLOY_ID=$id
PHASE=$phase
BINARY_PATH=/data/dcentrald
BINARY_ORIGINAL_STATUS=present
BINARY_ORIGINAL_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
BINARY_BACKUP_PATH=$dir/dcentrald.backup
BINARY_CANDIDATE_SHA256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
CONFIG_MUTATED=false
CONFIG_SOURCE=builtin
CONFIG_PATH=builtin
CONFIG_ORIGINAL_STATUS=not_captured
CONFIG_ORIGINAL_SHA256=NONE
CONFIG_BACKUP_PATH=NONE
CONFIG_CANDIDATE_SHA256=NONE
ROLLBACK_CONFIG_SOURCE=builtin
ROLLBACK_CONFIG_PATH=builtin
ROLLBACK_CONFIG_SHA256=NONE
BINARY_ORIGINAL_METADATA=0:0:755
CONFIG_ORIGINAL_METADATA=NONE
EOF
    chmod 600 "$marker"
}
write_terminal "$old" recovered recovered
write_terminal "$middle" rolled_back rolled-back
write_terminal "$newest" committed committed
write_terminal "$recent_second" recovered recovered
write_terminal "$recent_newest" committed committed
middle_marker="$middle/persistent-transaction.rolled-back"
sed -i \
    -e '1s/dcent-persistent-tx-v4/dcent-persistent-tx-v3/' \
    -e '9c\CONFIG_MUTATED=true' \
    -e '10c\CONFIG_SOURCE=explicit' \
    -e '11c\CONFIG_PATH=/data/dcentrald.toml' \
    -e '12c\CONFIG_ORIGINAL_STATUS=present' \
    -e '13c\CONFIG_ORIGINAL_SHA256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' \
    -e "14c\\CONFIG_BACKUP_PATH=$middle/dcentrald.toml.backup" \
    -e '15c\CONFIG_CANDIDATE_SHA256=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' \
    -e '16c\ROLLBACK_CONFIG_SOURCE=data' \
    -e '17c\ROLLBACK_CONFIG_PATH=/data/dcentrald.toml' \
    -e '18c\ROLLBACK_CONFIG_SHA256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' \
    "$middle_marker"
sed -i '$d' "$middle_marker"
mkdir "$old/deploy-lease.released"
chmod 700 "$old/deploy-lease.released"
printf '%s\n' "${old##*/}" >"$old/deploy-lease.released/owner"
chmod 600 "$old/deploy-lease.released/owner"
printf 'PERSISTENT_TX_STATE=dcent-persistent-tx-v4\nDEPLOY_ID=%s\nPHASE=mutating\n' \
    "${pending##*/}" >"$pending/persistent-transaction.state"
printf 'x\n' >"$launch_only/runtime-launch.started"
printf 'x\n' >"$malformed/persistent-transaction.committed"
touch -t 202001010101 "$old"
touch -t 202001020202 "$middle"
touch -t 202001030303 "$newest"
touch -t 209901010101 "$recent_second"
touch -t 209902020202 "$recent_newest"
touch -t 202001040404 "$pending"
touch -t 202001050505 "$launch_only"
touch -t 201901010101 "$malformed"
export DCENT_DEPLOY_RECOVERY_BASE="$base"
'''
        assertions = r'''
[ ! -e "$old" ]
[ ! -e "$middle" ]
[ ! -e "$newest" ]
[ -d "$recent_second" ]
[ -d "$recent_newest" ]
[ -d "$pending" ]
[ -d "$launch_only" ]
[ -d "$malformed" ]
printf 'RECOVERY_ADMIN_TEST=ok\n'
'''
        result = subprocess.run(
            [bash, "-s", "--", "prune-terminal", "1", "24"],
            input=(setup + "\n" + remote + "\n" + assertions).encode("utf-8"),
            capture_output=True,
            check=False,
        )
        output = (result.stdout + result.stderr).decode(
            "utf-8", errors="replace"
        )
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("RECOVERY_ADMIN_TEST=ok", output)
        self.assertIn("younger-than-min-age", output)

    def test_recovery_admin_list_never_classifies_dangling_state_as_terminal(
        self,
    ) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not available")
        source = RECOVERY_ADMIN.read_text(encoding="utf-8")
        remote = source.split("REMOTE_SCRIPT=$(cat <<'EOF'\n", 1)[1].split(
            "\nEOF\n)", 1
        )[0]
        setup = r'''
root=$(mktemp -d "${TMPDIR:-/tmp}/dcent-admin-dangling-state-test.XXXXXX")
trap 'rm -rf "$root"' EXIT HUP INT TERM
printf '#!/bin/sh\nshift\nexec "$@"\n' >"$root/lock-helper"
chmod 755 "$root/lock-helper"
export DCENT_DEPLOY_ADMIN_TEST_AUTHORITY=1
export DCENT_DEPLOY_LOCK_HELPER="$root/lock-helper"
export DCENT_DEPLOY_MAINTENANCE_PATH="$root/maintenance"
base="$root/recovery"
id=88888888888888888888888888888888
run="$base/$id"
invalid_id=99999999999999999999999999999999
invalid_run="$base/$invalid_id"
mkdir -p "$run" "$invalid_run" "$base/.deploy-lease"
chmod 700 "$base" "$run" "$invalid_run"
chmod 755 "$base/.deploy-lease"
printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >"$base/.deploy-lease/owner"
chmod 600 "$base/.deploy-lease/owner"
marker="$run/persistent-transaction.committed"
cat >"$marker" <<EOF
PERSISTENT_TX_STATE=dcent-persistent-tx-v4
DEPLOY_ID=$id
PHASE=committed
BINARY_PATH=/data/dcentrald
BINARY_ORIGINAL_STATUS=present
BINARY_ORIGINAL_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
BINARY_BACKUP_PATH=$run/dcentrald.backup
BINARY_CANDIDATE_SHA256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
CONFIG_MUTATED=false
CONFIG_SOURCE=builtin
CONFIG_PATH=builtin
CONFIG_ORIGINAL_STATUS=not_captured
CONFIG_ORIGINAL_SHA256=NONE
CONFIG_BACKUP_PATH=NONE
CONFIG_CANDIDATE_SHA256=NONE
ROLLBACK_CONFIG_SOURCE=builtin
ROLLBACK_CONFIG_PATH=builtin
ROLLBACK_CONFIG_SHA256=NONE
BINARY_ORIGINAL_METADATA=0:0:755
CONFIG_ORIGINAL_METADATA=NONE
EOF
chmod 600 "$marker"
ln -s "$run/missing-state" "$run/persistent-transaction.state"
printf 'PERSISTENT_TX_STATE=dcent-persistent-tx-v4\nDEPLOY_ID=%s\nPHASE=committed\n' \
    "$invalid_id" >"$invalid_run/persistent-transaction.state"
chmod 600 "$invalid_run/persistent-transaction.state"
export DCENT_DEPLOY_RECOVERY_BASE="$base"
'''
        result = subprocess.run(
            [bash, "-s", "--", "list", "4", "24"],
            input=(setup + "\n" + remote).encode("utf-8"),
            capture_output=True,
            check=False,
        )
        output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        self.assertEqual(result.returncode, 0, output)
        self.assertIn(
            "88888888888888888888888888888888\tretained:launch-or-invalid",
            output,
        )
        self.assertIn("LEASE\tinvalid", output)
        self.assertIn(
            "99999999999999999999999999999999\tpending:invalid", output
        )
        self.assertNotIn("\tpending:committed", output)
        self.assertNotIn("\tterminal:", output)

    def test_recovery_admin_prunes_only_aged_known_shape_orphans(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not available")
        source = RECOVERY_ADMIN.read_text(encoding="utf-8")
        remote = source.split("REMOTE_SCRIPT=$(cat <<'EOF'\n", 1)[1].split(
            "\nEOF\n)", 1
        )[0]
        setup = r'''
root=$(mktemp -d "${TMPDIR:-/tmp}/dcent-orphan-test.XXXXXX")
trap 'rm -rf "$root"' EXIT HUP INT TERM
printf '#!/bin/sh\nshift\nexec "$@"\n' >"$root/lock-helper"
chmod 755 "$root/lock-helper"
export DCENT_DEPLOY_ADMIN_TEST_AUTHORITY=1
export DCENT_DEPLOY_LOCK_HELPER="$root/lock-helper"
export DCENT_DEPLOY_MAINTENANCE_PATH="$root/maintenance"
base="$root/recovery"
old="$base/66666666666666666666666666666666"
fresh="$base/77777777777777777777777777777777"
pending="$base/88888888888888888888888888888888"
launch="$base/99999999999999999999999999999999"
unknown="$base/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
hidden="$base/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
prepared_tmp="$base/cccccccccccccccccccccccccccccccc"
dangling="$base/dddddddddddddddddddddddddddddddd"
mkdir -p "$old" "$fresh" "$pending" "$launch" "$unknown" "$hidden" "$prepared_tmp" "$dangling"
chmod 700 "$base" "$old" "$fresh" "$pending" "$launch" "$unknown" \
    "$hidden" "$prepared_tmp" "$dangling"
printf x >"$old/dcentrald.new"
printf x >"$fresh/dcentrald.new"
printf x >"$pending/dcentrald.new"
printf x >"$pending/persistent-transaction.state"
printf x >"$launch/dcentrald.new"
printf x >"$launch/runtime-launch.started"
printf x >"$unknown/unrecognized"
printf x >"$hidden/dcentrald.new"
printf x >"$hidden/.deploy-active"
printf x >"$prepared_tmp/dcentrald.new"
printf x >"$prepared_tmp/persistent-transaction.state.prepared.new"
printf x >"$dangling/dcentrald.new"
ln -s "$dangling/missing" "$dangling/dangling-evidence"
touch -t 202001010101 "$old" "$pending" "$launch" "$unknown" "$hidden" "$prepared_tmp" "$dangling"
export DCENT_DEPLOY_RECOVERY_BASE="$base"
'''
        assertions = r'''
[ ! -e "$old" ]
[ -d "$fresh" ]
[ -d "$pending" ]
[ -d "$launch" ]
[ -d "$unknown" ]
[ -d "$hidden" ]
[ -d "$prepared_tmp" ]
[ -d "$dangling" ]
printf 'RECOVERY_ORPHAN_TEST=ok\n'
'''
        result = subprocess.run(
            [bash, "-s", "--", "prune-orphans", "4", "24"],
            input=(setup + "\n" + remote + "\n" + assertions).encode("utf-8"),
            capture_output=True,
            check=False,
        )
        output = (result.stdout + result.stderr).decode(
            "utf-8", errors="replace"
        )
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("RECOVERY_ORPHAN_TEST=ok", output)

    def test_recovery_admin_refuses_prune_while_deploy_lease_is_active(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not available")
        source = RECOVERY_ADMIN.read_text(encoding="utf-8")
        remote = source.split("REMOTE_SCRIPT=$(cat <<'EOF'\n", 1)[1].split(
            "\nEOF\n)", 1
        )[0]
        setup = r'''
root=$(mktemp -d "${TMPDIR:-/tmp}/dcent-admin-lease-test.XXXXXX")
trap 'rm -rf "$root"' EXIT HUP INT TERM
printf '#!/bin/sh\nshift\nexec "$@"\n' >"$root/lock-helper"
chmod 755 "$root/lock-helper"
export DCENT_DEPLOY_ADMIN_TEST_AUTHORITY=1
export DCENT_DEPLOY_LOCK_HELPER="$root/lock-helper"
export DCENT_DEPLOY_MAINTENANCE_PATH="$root/maintenance"
base="$root/recovery"
orphan="$base/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
mkdir -p "$base/.deploy-lease" "$orphan"
chmod 700 "$base" "$base/.deploy-lease" "$orphan"
printf 'ffffffffffffffffffffffffffffffff\n' >"$base/.deploy-lease/owner"
chmod 600 "$base/.deploy-lease/owner"
printf x >"$orphan/dcentrald.new"
touch -t 202001010101 "$orphan"
export DCENT_DEPLOY_RECOVERY_BASE="$base"
'''
        result = subprocess.run(
            [bash, "-s", "--", "prune-orphans", "4", "24"],
            input=(setup + "\n" + remote).encode("utf-8"),
            capture_output=True,
            check=False,
        )
        output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("pruning is blocked by active deploy lease", output)

    def test_dashboard_integrity_and_api_evidence_fail_closed(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("Dashboard remote SHA256 verification failed", text)
        self.assertNotIn("WARNING: SHA256 mismatch", text)
        self.assertNotIn('[ "$LOCAL_DASHBOARD" -nt "$LOCAL_DASHBOARD_GZ" ]', text)
        self.assertNotIn('[ "$LOCAL_DASHBOARD" -nt "$LOCAL_DASHBOARD_SHA" ]', text)
        self.assertIn("Regenerating bound gzip + SHA256 sidecars", text)
        self.assertIn('gzip -cd "$gzip_stage"', text)
        self.assertIn('gzip -cd "$gzip_file"', text)
        self.assertIn("trap rollback EXIT HUP INT TERM", text)
        self.assertIn('restore_one "$index"', text)
        self.assertIn('mv -f "$index_stage" "$index"', text)
        self.assertIn('REMOTE_DIR/.index.html.$DEPLOY_ID.new', text)
        self.assertIn('"api_healthy": $api_healthy', text)
        self.assertIn('API_VERIFICATION_STATUS="not_performed"', text)
        self.assertIn(
            'json_exit true null "$DASHBOARD_BYTES" false '
            '"Dashboard-only deploy successful"',
            text,
        )
        self.assertIn(
            'json_exit false "$NEW_PID" "$BINARY_SIZE" false '
            '"Final hardware ownership arbitration failed"',
            text,
        )

    def test_final_ownership_scan_is_last_remote_operation_before_receipt(
        self,
    ) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        after_scan = text.split("FINAL_OWNERSHIP=$(ssh_run '", 1)[1]
        before_receipt = after_scan.split(
            "DEPLOY_JSON=$(build_receipt_payload", 1
        )[0]
        self.assertNotIn("ssh_run", before_receipt)

    def test_platform_snapshot_requires_complete_framing_and_transport_success(
        self,
    ) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("if ! MINER_INFO=$(ssh_run '", text)
        self.assertIn("SNAPSHOT_SCHEMA=dcent-miner-info-v1", text)
        self.assertIn("SNAPSHOT_COMPLETE=dcent-miner-info-v1", text)
        self.assertIn("Miner platform snapshot was incomplete", text)
        self.assertIn('single_assignment_value "$MINER_INFO" "$snapshot_key"', text)
        self.assertIn("snapshot field $snapshot_key is missing or duplicated", text)
        self.assertIn("awk 'END { print NR }')\" -ne 16", text)
        self.assertNotIn("MINER_INFO=$(ssh_run '", text.split("if ! MINER_INFO=$(ssh_run '", 1)[0])

    def test_root_staging_uses_fresh_private_remote_directory(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("mktemp -d /tmp/dcent-deploy.XXXXXX", text)
        self.assertIn('stat -c "%u:%a:%h" "$run_dir"', text)
        self.assertIn('STAGING_PATH="$REMOTE_RUN_DIR/dcentrald.new"', text)
        self.assertIn('BACKUP_PATH="$REMOTE_RUN_DIR/dcentrald.backup"', text)
        self.assertIn('EXPECTFILE="/var/run/dcentrald.expected_exit.pid"', text)
        self.assertNotIn('EXPECTFILE="/tmp/dcentrald.expected_exit.pid"', text)
        self.assertIn("DCENT_DEV_DEPLOY_BINARY_OVERRIDE", text)
        self.assertIn("Binary override requires --skip-build", text)

    def test_process_signals_are_bound_to_pid_start_time_and_executable(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("DCENTRALD_UNVERIFIABLE=\"\"", text)
        self.assertIn("stop_exact_launched_process()", text)
        self.assertIn('current_start=$(sed "s/^[^)]*) //"', text)
        self.assertIn('current_exe=$(readlink "/proc/$pid/exe"', text)
        self.assertIn(
            '[ "$current_start" = "$expected_start" ] && '
            '[ "$current_exe" = "$expected_exe" ]',
            text,
        )
        self.assertGreaterEqual(text.count("identity_matches; then\n        kill -9"), 2)
        self.assertNotIn('[ -r "$proc/exe" ] || continue', text)
        self.assertIn("BOS_OWNER_UNVERIFIABLE", text)
        self.assertIn('index($0, "BOS_OWNER_IDENTITIES=") == 1', text)
        self.assertIn("*[!A-Za-z0-9_./+-]*", text)
        self.assertNotIn('eval "$VENDOR_OWNER_INFO"', text)
        self.assertNotIn('eval "$START_OUTPUT"', text)
        self.assertNotIn("\neval ", text)
        self.assertIn('single_assignment_value "$START_OUTPUT" NEW_PID', text)
        self.assertIn(
            'case "$RUNNING_PID" in ""|*[!0-9]*) RUNNING_PID="NONE"', text
        )
        self.assertIn("signal_exact_set -TERM", text)
        self.assertIn("signal_exact_set -KILL", text)
        self.assertNotIn("kill -TERM $BOSMINER_PID", text)
        self.assertNotIn("for pid in \\$(pidof bos-tools", text)

    def test_runtime_config_is_content_addressed_and_rechecked_at_launch(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            'RUNTIME_CONFIG_DIR="/tmp/dcentrald-runtime.${CONFIG_BIND_SHA256}.${DEPLOY_START}.$$"',
            text,
        )
        self.assertIn("requires an explicit --config so the launched process", text)
        self.assertIn("chmod 400 '$CONFIG_REMOTE.new'", text)
        self.assertIn("stat -c '%u:%a:%h'", text)
        self.assertIn('if [ "\\$CONFIG_META" != "0:400:1" ]', text)
        self.assertIn('ACTUAL_CONFIG_SHA256=\\$(sha256sum "$CONFIG_REMOTE"', text)
        self.assertIn(
            'if [ "\\$ACTUAL_CONFIG_SHA256" != "$CONFIG_BIND_SHA256" ]', text
        )
        self.assertIn('CONFIG="--config $CONFIG_REMOTE"', text)


if __name__ == "__main__":
    unittest.main()
