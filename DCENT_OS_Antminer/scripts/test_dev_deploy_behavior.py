#!/usr/bin/env python3
"""Behavioral fake-transport tests for runtime-only dev deployment safety."""

from __future__ import annotations

import hashlib
import gzip
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "dev_deploy.sh"
TARGET_BINARY = (
    ROOT
    / "dcentrald"
    / "target"
    / "armv7-unknown-linux-musleabihf"
    / "release"
    / "dcentrald"
)

RECEIPT_V3_KEYS = {
    "receipt_schema",
    "deploy_id",
    "success",
    "pid",
    "start_ticks",
    "exe",
    "launch_id",
    "cleanup_status",
    "recovery_artifact_path",
    "backup_status",
    "config_backup_status",
    "rollback_status",
    "binary_size",
    "binary_sha256",
    "config_sha256",
    "config_binding_source",
    "original_binary_status",
    "original_binary_sha256",
    "original_binary_metadata",
    "original_config_status",
    "original_config_sha256",
    "original_config_metadata",
    "persistent_transaction_schema",
    "persistent_transaction_identity_sha256",
    "persistent_transaction_state_path",
    "persistent_transaction_terminal_path",
    "persistent_transaction_status",
    "deploy_lease_status_at_receipt_publication",
    "maintenance_exclusion_at_receipt_publication",
    "rollback_config_source",
    "rollback_config_path",
    "rollback_config_sha256",
    "deploy_time_seconds",
    "api_healthy",
    "api_verification_status",
    "miner_ip",
    "platform_family",
    "deploy_mode",
    "config",
    "remote_path",
    "sha256",
    "message",
}


class DevDeployBehaviorTest(unittest.TestCase):
    def _assert_receipt_v3_shape(self, data: dict[str, object]) -> None:
        self.assertEqual(data.get("receipt_schema"), "dcent-dev-deploy-v3")
        self.assertEqual(set(data), RECEIPT_V3_KEYS)

    def _shell_path(self, path: Path) -> str:
        resolved = path.resolve()
        if os.name != "nt":
            return str(resolved)
        drive = resolved.drive.rstrip(":").lower()
        tail = resolved.as_posix().split(":", 1)[1].lstrip("/")
        return f"{self.windows_mount_prefix}/{drive}/{tail}"

    def setUp(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not available")
        self.bash = bash
        self.windows_mount_prefix = ""
        if os.name == "nt":
            probe = subprocess.run(
                [self.bash, "-lc", "test -d /mnt/c && printf wsl || printf msys"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.windows_mount_prefix = "/mnt" if probe.stdout == "wsl" else ""
        self.temp = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp.name)
        self.fake_bin = self.temp_path / "bin"
        self.fake_bin.mkdir()
        self.ssh_log = self.temp_path / "ssh.log"
        self.config = self.temp_path / "runtime.toml"
        self.config.write_text("[api]\nhttp_port = 8080\n", encoding="utf-8")
        self.binary = self.temp_path / "dcentrald"
        self.binary.write_bytes(b"fake-armv7-dcentrald\n")
        self.binary_sha = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.dashboard = self.temp_path / "index.html"
        self.dashboard.write_bytes(b"<html>" + (b"dcent-dashboard" * 9000) + b"</html>\n")
        self.dashboard_sha = hashlib.sha256(self.dashboard.read_bytes()).hexdigest()
        self.config_sha = hashlib.sha256(self.config.read_bytes()).hexdigest()
        self._write_fake_transport()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_fake_transport(self) -> None:
        sync = self.fake_bin / "sync"
        sync.write_text(
            '#!/bin/sh\n'
            'if [ "$1" = -f ] && [ -d "$2" ]; then\n'
            '  counter="${FAKE_SSH_LOG}.sync-count"\n'
            '  count=$(cat "$counter" 2>/dev/null || printf 0)\n'
            '  count=$((count + 1))\n'
            '  printf "%s\\n" "$count" >"$counter"\n'
            '  if [ "${FAKE_RECEIPT_DIRECTORY_SYNC_FAIL:-}" = 1 ] '
            '&& [ "$count" -ge 2 ]; then exit 1; fi\n'
            'fi\n'
            'exec /usr/bin/sync "$@"\n',
            encoding="utf-8",
            newline="\n",
        )
        sync.chmod(0o755)
        ssh = self.fake_bin / "ssh"
        ssh.write_text(
            r'''#!/bin/sh
cmd=""
for arg in "$@"; do cmd=$arg; done
printf '%s\n---\n' "$cmd" >>"$FAKE_SSH_LOG"
case "$cmd" in
  "echo OK") echo OK ;;
  *"deploy-recovery-capabilities"*)
    printf 'DCENT_DEPLOY_RECOVERY_SCHEMA_MIN=3\n'
    printf 'DCENT_DEPLOY_RECOVERY_SCHEMA_MAX=%s\n' "$FAKE_RECOVERY_SCHEMA_MAX"
    ;;
  *"DEPLOY_FREE_KB="*"DEPLOY_EXISTING_SHA256="*)
    printf 'TMP_FREE_BYTES=268435456\nDEPLOY_FREE_BYTES=%s\n' "${FAKE_DEPLOY_FREE_BYTES:-268435456}"
    printf 'DEPLOY_FREE_INODES=%s\n' "${FAKE_DEPLOY_FREE_INODES:-4096}"
    existing_status=${FAKE_DEPLOY_EXISTING_STATUS:-}
    if [ -z "$existing_status" ]; then
      if [ "${FAKE_EXISTING_SHA:-NONE}" = NONE ] && [ "${FAKE_EXISTING_METADATA:-NONE}" = NONE ]; then
        existing_status=absent
      else
        existing_status=present
      fi
    fi
    printf 'DEPLOY_EXISTING_STATUS=%s\n' "$existing_status"
    printf 'DEPLOY_EXISTING_SIZE=%s\n' "${FAKE_DEPLOY_EXISTING_SIZE:-21}"
    printf 'DEPLOY_EXISTING_SHA256=%s\n' "${FAKE_EXISTING_SHA:-NONE}"
    printf 'DEPLOY_EXISTING_METADATA=%s\n' "${FAKE_EXISTING_METADATA:-0:0:755}"
    printf 'CONFIG_EXISTING_SIZE=24\n'
    ;;
  *"TMP_FREE_KB="*)
    printf 'TMP_FREE_KB=262144\nDATA_FREE_KB=262144\n'
    ;;
  *"DEPLOY_MAINTENANCE_READY=true"*)
    [ "${FAKE_ACTIVE_MAINTENANCE:-}" = 1 ] \
      || [ "${FAKE_MAINTENANCE_ACQUIRE_ACK_LOST:-}" = 1 ] \
      || printf 'DEPLOY_MAINTENANCE_READY=true\n'
    ;;
  *"DEPLOY_MAINTENANCE_OBSERVED=held"*)
    [ "${FAKE_MAINTENANCE_ACQUIRE_ACK_LOST:-}" = 1 ] \
      && printf 'DEPLOY_MAINTENANCE_OBSERVED=held\n'
    ;;
  *"DEPLOY_MAINTENANCE_RELEASED=true"*)
    printf 'DEPLOY_MAINTENANCE_RELEASED=true\n'
    ;;
  *"REMOTE_RUN_DIR_READY=true"*)
    [ "${FAKE_ACTIVE_DEPLOY_LEASE:-}" = 1 ] \
      || [ "${FAKE_LEASE_ACQUIRE_ACK_LOST:-}" = 1 ] \
      || printf 'REMOTE_RUN_DIR_READY=true\n'
    ;;
  *"owner.pending"*"PERSISTENT_DEPLOY_LEASE_OBSERVED=held"*)
    [ "${FAKE_LEASE_ACQUIRE_ACK_LOST:-}" = 1 ] \
      && printf 'PERSISTENT_DEPLOY_LEASE_OBSERVED=held\n'
    ;;
  *"mktemp -d /tmp/dcent-deploy.XXXXXX"*)
    printf 'REMOTE_RUN_DIR=/tmp/dcent-deploy.ABC123\n'
    ;;
  *"BOSMINER_PID="*)
    if [ "${FAKE_MINER_INFO_TRUNCATED:-}" = 1 ]; then
      printf 'SNAPSHOT_SCHEMA=dcent-miner-info-v1\nBOSMINER_PID=NONE\nDCENTRALD_UNVERIFIABLE=\n'
      exit 42
    fi
    printf 'SNAPSHOT_SCHEMA=dcent-miner-info-v1\n'
    printf 'BOSMINER_PID=NONE\nBOSTOOLS_PID=NONE\nBOSER_PID=NONE\n'
    printf 'DCENTRALD_PID=NONE\nDCENTRALD_IDENTITIES=\nDCENTRALD_UNVERIFIABLE=\n'
    printf 'OS_VER=NONE\nBOS_VER=NONE\nBOS_PLATFORM=%s\n' "${FAKE_BOS_PLATFORM:-zynq-bm3-am2}"
    printf 'ARCH=armv7l\nSOC=zynq\n'
    [ "${FAKE_MINER_INFO_MISSING:-}" = MODEL ] || printf 'MODEL=%s\n' "${FAKE_MODEL:-S19jPro}"
    [ "${FAKE_MINER_INFO_DUPLICATE:-}" = MODEL ] && printf 'MODEL=duplicate\n'
    printf 'HWID=am2\nUIO_COUNT=20\nSNAPSHOT_COMPLETE=dcent-miner-info-v1\n'
    ;;
  *"BOS_OWNER_IDENTITIES="*)
    printf 'BOS_OWNER_IDENTITIES=\nBOS_OWNER_UNVERIFIABLE=%s\n' "${FAKE_VENDOR_UNVERIFIABLE:-}"
    ;;
  *"CONFIG_BIND_SOURCE=discovered"*)
    if [ "${FAKE_INHERITED_CONFIG:-data}" = none ]; then
      printf 'CONFIG_BIND_SOURCE=builtin\nCONFIG_BIND_PATH=builtin\nCONFIG_BIND_SHA256=NONE\nCONFIG_BIND_METADATA=NONE\n'
    elif [ "${FAKE_INHERITED_CONFIG:-data}" = etc ]; then
      printf 'CONFIG_BIND_SOURCE=discovered\nCONFIG_BIND_PATH=/etc/dcentrald.toml\nCONFIG_BIND_SHA256=%s\nCONFIG_BIND_METADATA=%s\n' \
        "$FAKE_EXISTING_CONFIG_SHA" "${FAKE_DISCOVERED_CONFIG_METADATA:-0:0:644}"
    else
      printf 'CONFIG_BIND_SOURCE=discovered\nCONFIG_BIND_PATH=/data/dcentrald.toml\nCONFIG_BIND_SHA256=%s\nCONFIG_BIND_METADATA=%s\n' \
        "$FAKE_EXISTING_CONFIG_SHA" "${FAKE_DISCOVERED_CONFIG_METADATA:-0:0:644}"
    fi
    ;;
  *"RUNTIME_DISCOVERY=none"*)
    if [ "${FAKE_RECOVERY_FOREIGN:-}" = 1 ]; then
      printf 'RUNTIME_DISCOVERY=ambiguous\n'
    else
      recovery_exe=/tmp/dcentrald_runtime
      [ "${FAKE_BOS_PLATFORM:-}" = zynq-am1-s9 ] && recovery_exe=/data/dcentrald
      printf 'RUNTIME_DISCOVERY=exact\nRUNTIME_PID=4242\nRUNTIME_START_TICKS=99\nRUNTIME_EXE=%s\n' "$recovery_exe"
    fi
    ;;
  *"FINAL_OWNERSHIP=OK"*)
    if [ "${FAKE_VENDOR_RESPAWN:-}" = 1 ]; then
      printf 'FINAL_OWNERSHIP=VENDOR_RESTARTED\n'
    else
      printf 'FINAL_OWNERSHIP=OK\n'
    fi
    ;;
  *"LAUNCH_STATE=committed"*)
    [ "${FAKE_JOURNAL_UNCOMMITTED:-}" = 1 ] || printf 'LAUNCH_STATE=committed\n'
    ;;
  *"PERSISTENT_TX_PREPARED=verified"*)
    [ "${FAKE_TX_PREPARE_FAIL:-}" = 1 ] || printf 'PERSISTENT_TX_PREPARED=verified\n'
    ;;
  *"PERSISTENT_TX_COMMIT=verified"*)
    [ "${FAKE_TX_COMMIT_FAIL:-}" = 1 ] || printf 'PERSISTENT_TX_COMMIT=verified\n'
    ;;
  *"DASHBOARD_SWAP_SHA256="*)
    [ "${FAKE_DASHBOARD_SWAP_FAIL:-}" = 1 ] && exit 42
    printf 'DASHBOARD_SWAP_SHA256=%s\n' "$FAKE_DASHBOARD_SHA"
    ;;
  *"nohup env DCENTOS_EPHEMERAL_RUNTIME=1"*)
    config=$(printf '%s\n' "$cmd" | sed -n 's/^[[:space:]]*echo "CONFIG_USED=\([^"]*\)"/\1/p' | head -n 1)
    launch_exe=/tmp/dcentrald_runtime
    if [ "${FAKE_BOS_PLATFORM:-}" = zynq-am1-s9 ]; then
      config=/data/dcentrald.toml
      launch_exe=/data/dcentrald
    fi
    if [ "${FAKE_START_OUTPUT_PARTIAL:-}" = 1 ]; then
      printf "CONFIG_USED=%s\nNEW_PID=4242\nNEW_START_TICKS=99\n" "$config"
    elif [ "${FAKE_START_OUTPUT_EMPTY:-}" != 1 ]; then
      printf "CONFIG_USED=%s\nNEW_PID=4242\nNEW_START_TICKS=99\nNEW_EXE=%s\n" "$config" "$launch_exe"
    fi
    ;;
  *"/etc/init.d/S82dcentrald start"*"NEW_PID="*)
    printf 'CONFIG_USED=/data/dcentrald.toml\nNEW_PID=4242\nNEW_START_TICKS=99\nNEW_EXE=/data/dcentrald\n'
    ;;
  *"CONFIG_ORIGINAL_EXISTS="*)
    if [ "${FAKE_ORIGINAL_CONFIG:-present}" = absent ]; then
      if [ "${FAKE_ROLLBACK_CONFIG_SOURCE:-builtin}" = etc ]; then
        printf 'CONFIG_ORIGINAL_EXISTS=false\nCONFIG_ORIGINAL_SHA256=NONE\nCONFIG_ORIGINAL_METADATA=NONE\n'
        printf 'ROLLBACK_CONFIG_SOURCE=etc\nROLLBACK_CONFIG_PATH=/etc/dcentrald.toml\nROLLBACK_CONFIG_SHA256=%s\n' "$FAKE_ETC_CONFIG_SHA"
      else
        printf 'CONFIG_ORIGINAL_EXISTS=false\nCONFIG_ORIGINAL_SHA256=NONE\nCONFIG_ORIGINAL_METADATA=NONE\n'
        printf 'ROLLBACK_CONFIG_SOURCE=builtin\nROLLBACK_CONFIG_PATH=builtin\nROLLBACK_CONFIG_SHA256=NONE\n'
      fi
    else
      printf 'CONFIG_ORIGINAL_EXISTS=true\nCONFIG_ORIGINAL_SHA256=%s\nCONFIG_ORIGINAL_METADATA=%s\n' \
        "$FAKE_EXISTING_CONFIG_SHA" "$FAKE_EXISTING_CONFIG_METADATA"
      printf 'ROLLBACK_CONFIG_SOURCE=data\nROLLBACK_CONFIG_PATH=/data/dcentrald.toml\nROLLBACK_CONFIG_SHA256=%s\n' "$FAKE_EXISTING_CONFIG_SHA"
    fi
    ;;
  *"PERSISTENT_ROLLBACK=files_restored_launch_stopped_ownership_unverified"*)
    if [ "${FAKE_ROLLBACK_FAIL:-}" = 1 ]; then
      exit 42
    fi
    printf 'PERSISTENT_ROLLBACK=files_restored_launch_stopped_ownership_unverified\n'
    ;;
  *"pid=4242"*"identity_matches()"*)
    [ "${FAKE_STOP_FAIL:-}" = 1 ] && exit 42
    ;;
  *'mv "$lease" "$retired"'*)
    if [ "${FAKE_LEASE_RELEASE_FAIL:-}" = 1 ] \
      || [ "${FAKE_LEASE_RELEASE_ACK_LOST:-}" = 1 ] \
      || [ "${FAKE_LEASE_RELEASE_AMBIGUOUS:-}" = 1 ]; then
      exit 42
    fi
    printf 'PERSISTENT_DEPLOY_LEASE_RELEASED=true\n'
    ;;
  *"PERSISTENT_DEPLOY_LEASE_OBSERVED=released"*)
    [ "${FAKE_LEASE_RELEASE_AMBIGUOUS:-}" = 1 ] && exit 42
    if [ "${FAKE_LEASE_RELEASE_ACK_LOST:-}" = 1 ]; then
      printf 'PERSISTENT_DEPLOY_LEASE_OBSERVED=released\n'
    else
      printf 'PERSISTENT_DEPLOY_LEASE_OBSERVED=held\n'
    fi
    ;;
  *"config_original_exists="*"tx_set_phase prepared mutating"*)
    [ -z "${FAKE_PREMUTATION_DRIFT:-}" ] || exit 42
    [ "${FAKE_TX_IDENTITY_MISMATCH:-}" = 1 ] && exit 42
    ;;
  *"expected_tx_identity="*)
    [ "${FAKE_TX_IDENTITY_MISMATCH:-}" = 1 ] && exit 42
    ;;
  *"expected_pid=4242"*"matches=0"*) echo 4242 ;;
  *"in_api"*"http_port"*) echo 8080 ;;
  *"sha256sum '/tmp/dcent-deploy.ABC123/dcentrald.new'"*) echo "$FAKE_BINARY_SHA" ;;
  *"sha256sum '/tmp/dcent-deploy.ABC123/dcentrald.backup'"*) echo "$FAKE_EXISTING_SHA" ;;
  *"sha256sum '/tmp/dcent-deploy.ABC123/dcentrald.toml.new'"*) echo "$FAKE_CONFIG_SHA" ;;
  *"cp -p '/data/dcentrald' "*"/dcentrald.backup"*) echo "$FAKE_EXISTING_SHA" ;;
  *"sha256sum '/data/.dcent-deploy-recovery/"*"/dcentrald.toml.new'"*) echo "$FAKE_CONFIG_SHA" ;;
  *"sha256sum '/data/.dcent-deploy-recovery/"*"/dcentrald.new'"*) echo "$FAKE_BINARY_SHA" ;;
  *"sha256sum '/data/dcentrald'"*) echo "$FAKE_BINARY_SHA" ;;
  *"sha256sum '/data/dcentrald.toml'"*) echo "$FAKE_CONFIG_SHA" ;;
  *"sha256sum '/tmp/dcentrald_runtime'"*) echo "$FAKE_BINARY_SHA" ;;
  *"sha256sum '/tmp/dcentrald-runtime."*) echo "$FAKE_CONFIG_SHA" ;;
  *) ;;
esac
exit 0
''',
            encoding="utf-8",
            newline="\n",
        )
        scp = self.fake_bin / "scp"
        scp.write_text(
            '#!/bin/sh\nprintf "%s\\n" "$*" >>"$FAKE_SSH_LOG"\nexit 0\n',
            encoding="utf-8",
            newline="\n",
        )
        ssh.chmod(0o755)
        scp.chmod(0o755)

    def _environment(self) -> dict[str, str]:
        env = os.environ.copy()
        if os.name == "nt" and self.windows_mount_prefix == "/mnt":
            env["PATH"] = (
                self._shell_path(self.fake_bin)
                + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            )
        else:
            env["PATH"] = str(self.fake_bin) + os.pathsep + env.get("PATH", "")
        env["FAKE_SSH_LOG"] = self._shell_path(self.ssh_log)
        env["DCENT_DEV_DEPLOY_BINARY_OVERRIDE"] = self._shell_path(self.binary)
        env["DCENT_DEV_DEPLOY_DASHBOARD_OVERRIDE"] = self._shell_path(
            self.dashboard
        )
        env["FAKE_BINARY_SHA"] = self.binary_sha
        env["FAKE_CONFIG_SHA"] = self.config_sha
        env["FAKE_DASHBOARD_SHA"] = self.dashboard_sha
        env["FAKE_EXISTING_SHA"] = "a" * 64
        env["FAKE_EXISTING_METADATA"] = "0:0:755"
        env["FAKE_EXISTING_CONFIG_SHA"] = "b" * 64
        env["FAKE_EXISTING_CONFIG_METADATA"] = "0:0:600"
        env["FAKE_DISCOVERED_CONFIG_METADATA"] = "0:0:644"
        env["FAKE_RECOVERY_SCHEMA_MAX"] = "4"
        env["FAKE_ETC_CONFIG_SHA"] = "c" * 64
        env["FAKE_DEPLOY_EXISTING_SIZE"] = "21"
        env["FAKE_DEPLOY_FREE_INODES"] = "4096"
        env["FAKE_DEPLOY_FREE_BYTES"] = "268435456"
        env["FAKE_BOS_PLATFORM"] = ""
        env["FAKE_VENDOR_UNVERIFIABLE"] = ""
        env["FAKE_MODEL"] = ""
        env["FAKE_START_OUTPUT_EMPTY"] = ""
        env["FAKE_START_OUTPUT_PARTIAL"] = ""
        env["FAKE_MINER_INFO_TRUNCATED"] = ""
        env["FAKE_MINER_INFO_MISSING"] = ""
        env["FAKE_MINER_INFO_DUPLICATE"] = ""
        env["FAKE_RECOVERY_FOREIGN"] = ""
        env["FAKE_VENDOR_RESPAWN"] = ""
        env["FAKE_ROLLBACK_FAIL"] = ""
        env["FAKE_STOP_FAIL"] = ""
        env["FAKE_JOURNAL_UNCOMMITTED"] = ""
        env["FAKE_INHERITED_CONFIG"] = ""
        env["FAKE_PREMUTATION_DRIFT"] = ""
        env["FAKE_DASHBOARD_SWAP_FAIL"] = ""
        env["FAKE_TX_PREPARE_FAIL"] = ""
        env["FAKE_TX_COMMIT_FAIL"] = ""
        env["FAKE_ORIGINAL_CONFIG"] = ""
        env["FAKE_ROLLBACK_CONFIG_SOURCE"] = ""
        env["FAKE_ACTIVE_DEPLOY_LEASE"] = ""
        env["FAKE_ACTIVE_MAINTENANCE"] = ""
        env["FAKE_MAINTENANCE_ACQUIRE_ACK_LOST"] = ""
        env["FAKE_LEASE_RELEASE_FAIL"] = ""
        env["FAKE_LEASE_RELEASE_ACK_LOST"] = ""
        env["FAKE_LEASE_RELEASE_AMBIGUOUS"] = ""
        env["FAKE_LEASE_ACQUIRE_ACK_LOST"] = ""
        env["FAKE_TX_IDENTITY_MISMATCH"] = ""
        env["FAKE_RECEIPT_DIRECTORY_SYNC_FAIL"] = ""
        if os.name == "nt" and self.windows_mount_prefix == "/mnt":
            inherited_wslenv = env.get("WSLENV", "")
            fake_wslenv = (
                "DCENT_DEV_DEPLOY_BINARY_OVERRIDE:"
                "DCENT_DEV_DEPLOY_DASHBOARD_OVERRIDE:"
                "FAKE_SSH_LOG:FAKE_BINARY_SHA:FAKE_CONFIG_SHA:"
                "FAKE_DASHBOARD_SHA:"
                "FAKE_EXISTING_SHA:FAKE_EXISTING_METADATA:"
                "FAKE_EXISTING_CONFIG_SHA:FAKE_EXISTING_CONFIG_METADATA:"
                "FAKE_DISCOVERED_CONFIG_METADATA:"
                "FAKE_RECOVERY_SCHEMA_MAX:"
                "FAKE_ETC_CONFIG_SHA:"
                "FAKE_DEPLOY_EXISTING_STATUS:FAKE_DEPLOY_EXISTING_SIZE:"
                "FAKE_BOS_PLATFORM:"
                "FAKE_DEPLOY_FREE_INODES:"
                "FAKE_DEPLOY_FREE_BYTES:"
                "FAKE_VENDOR_UNVERIFIABLE:FAKE_MODEL:FAKE_START_OUTPUT_EMPTY"
                ":FAKE_START_OUTPUT_PARTIAL"
                ":FAKE_MINER_INFO_TRUNCATED"
                ":FAKE_MINER_INFO_MISSING:FAKE_MINER_INFO_DUPLICATE"
                ":FAKE_RECOVERY_FOREIGN"
                ":FAKE_VENDOR_RESPAWN"
                ":FAKE_ROLLBACK_FAIL"
                ":FAKE_STOP_FAIL"
                ":FAKE_JOURNAL_UNCOMMITTED"
                ":FAKE_INHERITED_CONFIG"
                ":FAKE_PREMUTATION_DRIFT"
                ":FAKE_DASHBOARD_SWAP_FAIL"
                ":FAKE_TX_PREPARE_FAIL"
                ":FAKE_TX_COMMIT_FAIL"
                ":FAKE_ORIGINAL_CONFIG"
                ":FAKE_ROLLBACK_CONFIG_SOURCE"
                ":FAKE_ACTIVE_DEPLOY_LEASE"
                ":FAKE_ACTIVE_MAINTENANCE"
                ":FAKE_MAINTENANCE_ACQUIRE_ACK_LOST"
                ":FAKE_LEASE_RELEASE_FAIL"
                ":FAKE_LEASE_RELEASE_ACK_LOST"
                ":FAKE_LEASE_RELEASE_AMBIGUOUS"
                ":FAKE_LEASE_ACQUIRE_ACK_LOST"
                ":FAKE_TX_IDENTITY_MISMATCH"
                ":FAKE_RECEIPT_DIRECTORY_SYNC_FAIL"
            )
            env["WSLENV"] = (
                f"{inherited_wslenv}:{fake_wslenv}"
                if inherited_wslenv
                else fake_wslenv
            )
        env.pop("DCENT_PASSWORD", None)
        env.pop("DCENT_SSH_KNOWN_HOSTS", None)
        return env

    def _run_deploy(
        self,
        arguments: list[str],
        environment_overrides: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = self._environment()
        if environment_overrides:
            env.update(environment_overrides)
        command = [self._shell_path(SCRIPT), *arguments]
        if os.name == "nt" and self.windows_mount_prefix == "/mnt":
            linux_path = (
                self._shell_path(self.fake_bin)
                + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            )
            return subprocess.run(
                [
                    self.bash,
                    "-lc",
                    f"export PATH={shlex.quote(linux_path)}; exec {shlex.join(command)}",
                ],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
        return subprocess.run(
            [self.bash, *command],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_dashboard_deploy_rebuilds_and_verifies_the_complete_artifact_set(
        self,
    ) -> None:
        stale_gzip = self.dashboard.with_suffix(".html.gz")
        stale_sha = self.dashboard.with_suffix(".html.sha256")
        stale_gzip.write_bytes(gzip.compress(b"stale"))
        stale_sha.write_text("0" * 64 + "\n", encoding="ascii")
        future = self.dashboard.stat().st_mtime + 3600
        os.utime(stale_gzip, (future, future))
        os.utime(stale_sha, (future, future))
        receipt = self.temp_path / "dashboard-success.json"

        result = self._run_deploy(
            [
                "192.0.2.10",
                "--dashboard-only",
                "--output",
                self._shell_path(receipt),
            ]
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self._assert_receipt_v3_shape(data)
        self.assertTrue(data["success"])
        self.assertEqual(data["deploy_mode"], "dashboard-only")
        self.assertEqual(data["sha256"], self.dashboard_sha)
        self.assertEqual(
            gzip.decompress(stale_gzip.read_bytes()), self.dashboard.read_bytes()
        )
        self.assertEqual(
            stale_sha.read_text(encoding="ascii"), self.dashboard_sha + "\n"
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("restore_one()", log)
        self.assertIn('mv -f "$index_stage" "$index"', log)
        self.assertIn('gzip -cd "$gzip_file"', log)

    def test_dashboard_swap_failure_reports_failure_after_remote_rollback(self) -> None:
        receipt = self.temp_path / "dashboard-failure.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--dashboard-only",
                "--output",
                self._shell_path(receipt),
            ],
            {"FAKE_DASHBOARD_SWAP_FAIL": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self._assert_receipt_v3_shape(data)
        self.assertFalse(data["success"])
        self.assertEqual(
            data["message"], "Dashboard remote SHA256 verification failed"
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("trap rollback EXIT HUP INT TERM", log)
        self.assertIn('restore_one "$index"', log)

    def test_runtime_only_refuses_implicit_remote_config(self) -> None:
        result = self._run_deploy(
            ["192.0.2.10", "--skip-build", "--runtime-only"]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires an explicit --config", result.stdout + result.stderr)
        self.assertNotIn(
            "nohup env DCENTOS_EPHEMERAL_RUNTIME=1",
            self.ssh_log.read_text(encoding="utf-8"),
        )

    def test_remote_platform_fields_are_parsed_as_data_never_local_shell(self) -> None:
        marker = self.temp_path / "remote-output-was-evaluated"
        payload = f"$(touch {self._shell_path(marker)})"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--runtime-only",
                "--config",
                self._shell_path(self.config),
            ],
            {"FAKE_MODEL": payload},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(marker.exists())

    def test_truncated_miner_snapshot_fails_before_any_remote_write_or_stop(self) -> None:
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--runtime-only",
                "--config",
                self._shell_path(self.config),
            ],
            {"FAKE_MINER_INFO_TRUNCATED": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("snapshot transport failed", result.stdout + result.stderr)
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertNotIn("nohup env DCENTOS_EPHEMERAL_RUNTIME=1", log)
        self.assertNotIn('kill -TERM "$pid"', log)
        self.assertNotIn("/tmp/dcentrald_runtime.new", log)

    def test_receipt_publication_failure_reclaims_exact_runtime_identity(self) -> None:
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--runtime-only",
                "--config",
                self._shell_path(self.config),
                "--output",
                "/proc/dcent-deploy-receipt.json",
            ]
        )
        self.assertNotEqual(result.returncode, 0)
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("nohup env DCENTOS_EPHEMERAL_RUNTIME=1", log)
        self.assertIn("pid=4242", log)
        self.assertIn("expected_start=99", log)
        self.assertIn("expected_exe='/tmp/dcentrald_runtime'", log)
        self.assertIn('[ "$current_start" = "$expected_start" ]', log)
        self.assertIn('kill -TERM "$pid"', log)

    def test_existing_output_directory_cannot_be_reported_as_receipt_success(self) -> None:
        receipt_directory = self.temp_path / "receipt-directory"
        receipt_directory.mkdir()
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--runtime-only",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt_directory),
            ]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "JSON output destination must be a regular file or absent",
            result.stdout + result.stderr,
        )
        self.assertTrue(receipt_directory.is_dir())
        self.assertEqual(list(receipt_directory.iterdir()), [])
        log = (
            self.ssh_log.read_text(encoding="utf-8")
            if self.ssh_log.exists()
            else ""
        )
        self.assertNotIn("nohup env DCENTOS_EPHEMERAL_RUNTIME=1", log)
        self.assertNotIn('kill -TERM "$pid"', log)

    def test_visible_receipt_with_unproven_directory_sync_never_rolls_back_target(
        self,
    ) -> None:
        receipt = self.temp_path / "visible-sync-uncertain.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--runtime-only",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {"FAKE_RECEIPT_DIRECTORY_SYNC_FAIL": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(receipt.is_file())
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertTrue(data["success"])
        self.assertIn(
            "directory durability is unproven", result.stdout + result.stderr
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("nohup env DCENTOS_EPHEMERAL_RUNTIME=1", log)
        self.assertNotIn('kill -TERM "$pid"', log)

    def test_prelaunch_refusal_removes_only_the_run_scoped_runtime_config(self) -> None:
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--runtime-only",
                "--config",
                self._shell_path(self.config),
            ],
            {"FAKE_VENDOR_UNVERIFIABLE": "31337"},
        )
        self.assertNotEqual(result.returncode, 0)
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertNotIn("nohup env DCENTOS_EPHEMERAL_RUNTIME=1", log)
        self.assertIn("rm -f '/tmp/dcentrald-runtime.", log)
        self.assertIn("/dcentrald.toml.new' && rmdir '/tmp/dcentrald-runtime.", log)

    def test_lost_start_output_recovers_and_reclaims_exact_runtime_identity(self) -> None:
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--runtime-only",
                "--config",
                self._shell_path(self.config),
            ],
            {"FAKE_START_OUTPUT_EMPTY": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("RUNTIME_DISCOVERY=none", log)
        self.assertIn("expected_exe='/tmp/dcentrald_runtime'", log)
        self.assertIn("pid=4242", log)
        self.assertIn("expected_start=99", log)
        self.assertIn('kill -TERM "$pid"', log)

    def test_lost_output_never_claims_foreign_exact_executable_without_launch_id(
        self,
    ) -> None:
        receipt = self.temp_path / "ambiguous.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--runtime-only",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {"FAKE_START_OUTPUT_EMPTY": "1", "FAKE_RECOVERY_FOREIGN": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(data["cleanup_status"], "incomplete")
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("expected_launch_id=", log)
        self.assertIn('"$proc/environ"', log)
        self.assertNotIn('kill -TERM "$pid"', log)
        self.assertNotIn("runtime-launch.cancelled'; rmdir", log)

    def test_success_receipt_is_versioned_valid_and_captures_final_identity(
        self,
    ) -> None:
        receipt = self.temp_path / "success.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--runtime-only",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ]
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self._assert_receipt_v3_shape(data)
        self.assertEqual(data["receipt_schema"], "dcent-dev-deploy-v3")
        self.assertEqual(data["persistent_transaction_schema"], "not_applicable")
        self.assertEqual(data["persistent_transaction_identity_sha256"], "")
        self.assertEqual(data["persistent_transaction_terminal_path"], "")
        self.assertRegex(data["deploy_id"], r"^[0-9a-f]{32}$")
        self.assertTrue(data["success"])
        self.assertEqual(data["pid"], 4242)
        self.assertEqual(data["start_ticks"], "99")
        self.assertEqual(data["exe"], "/tmp/dcentrald_runtime")
        self.assertRegex(data["launch_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(
            data["cleanup_status"], "launch_recovery_state_retained"
        )
        self.assertEqual(
            data["recovery_artifact_path"], "/tmp/dcent-deploy.ABC123"
        )
        self.assertEqual(data["api_verification_status"], "not_requested")
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("FINAL_OWNERSHIP=OK", log)
        self.assertIn("runtime-launch.authorized", log)
        self.assertIn("runtime-launch.starting", log)
        self.assertIn("runtime-launch.started", log)
        self.assertNotIn("runtime-launch.cancelled'; rmdir", log)

    def test_partial_start_output_rehydrates_identity_before_failure_cleanup(
        self,
    ) -> None:
        receipt = self.temp_path / "partial-start.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--runtime-only",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {"FAKE_START_OUTPUT_PARTIAL": "1", "FAKE_VENDOR_RESPAWN": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(data["pid"], 4242)
        self.assertEqual(data["start_ticks"], "99")
        self.assertEqual(data["exe"], "/tmp/dcentrald_runtime")
        self.assertEqual(data["cleanup_status"], "complete")
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn('kill -TERM "$pid"', log)
        self.assertIn("rm -f '/tmp/dcentrald-runtime.", log)

    def test_failed_exact_stop_preserves_runtime_config_and_launch_journal(
        self,
    ) -> None:
        receipt = self.temp_path / "stop-unproven.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--runtime-only",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {"FAKE_VENDOR_RESPAWN": "1", "FAKE_STOP_FAIL": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(data["cleanup_status"], "incomplete")
        self.assertEqual(
            data["recovery_artifact_path"], "/tmp/dcent-deploy.ABC123"
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn('kill -TERM "$pid"', log)
        self.assertNotIn("rm -f '/tmp/dcentrald-runtime.", log)
        self.assertNotIn("runtime-launch.cancelled'; rmdir", log)

    def test_live_process_without_committed_journal_is_reclaimed(self) -> None:
        receipt = self.temp_path / "journal-uncommitted.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--runtime-only",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {"FAKE_JOURNAL_UNCOMMITTED": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertFalse(data["success"])
        self.assertEqual(
            data["message"], "Launch recovery journal commit was not proven"
        )
        self.assertEqual(data["cleanup_status"], "complete")
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("runtime-launch.started", log)
        self.assertIn('kill -TERM "$pid"', log)

    def test_final_vendor_respawn_fails_and_reclaims_runtime_identity(self) -> None:
        receipt = self.temp_path / "failure.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--runtime-only",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {"FAKE_VENDOR_RESPAWN": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self._assert_receipt_v3_shape(data)
        self.assertEqual(data["receipt_schema"], "dcent-dev-deploy-v3")
        self.assertFalse(data["success"])
        self.assertEqual(data["cleanup_status"], "complete")
        self.assertEqual(data["message"], "Final hardware ownership arbitration failed")
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("FINAL_OWNERSHIP=OK", log)
        self.assertIn("pid=4242", log)
        self.assertIn('kill -TERM "$pid"', log)

    def test_snapshot_requires_exactly_one_of_each_required_field(self) -> None:
        for mode, override in (
            ("missing", {"FAKE_MINER_INFO_MISSING": "MODEL"}),
            ("duplicate", {"FAKE_MINER_INFO_DUPLICATE": "MODEL"}),
        ):
            with self.subTest(mode=mode):
                receipt = self.temp_path / f"snapshot-{mode}.json"
                result = self._run_deploy(
                    [
                        "192.0.2.10",
                        "--skip-build",
                        "--runtime-only",
                        "--config",
                        self._shell_path(self.config),
                        "--output",
                        self._shell_path(receipt),
                    ],
                    override,
                )
                self.assertNotEqual(result.returncode, 0)
                data = json.loads(receipt.read_text(encoding="utf-8"))
                self.assertEqual(data["receipt_schema"], "dcent-dev-deploy-v3")
                self.assertFalse(data["success"])
                self.assertEqual(
                    data["message"], "Miner platform snapshot was incomplete"
                )
                log = self.ssh_log.read_text(encoding="utf-8")
                self.assertNotIn("nohup env DCENTOS_EPHEMERAL_RUNTIME=1", log)
                self.assertNotIn("dcentrald.new", log)
                self.ssh_log.unlink()

    def test_stale_receipt_is_replaced_by_current_failure(self) -> None:
        receipt = self.temp_path / "receipt.json"
        receipt.write_text(
            '{"receipt_schema":"stale","success":true}\n', encoding="utf-8"
        )
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--runtime-only",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {"FAKE_MINER_INFO_MISSING": "MODEL"},
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(data["receipt_schema"], "dcent-dev-deploy-v3")
        self.assertFalse(data["success"])
        self.assertRegex(data["deploy_id"], r"^[0-9a-f]{32}$")

    def test_persistent_deploy_requires_a_retained_receipt(self) -> None:
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(self.config),
            ],
            {"FAKE_BOS_PLATFORM": "zynq-am1-s9"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "persistent deployment requires --output FILE",
            result.stdout + result.stderr,
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertNotIn("dcentrald.backup", log)
        self.assertNotIn("/data/dcentrald.dcent-deploy", log)

    def test_persistent_deploy_requires_explicit_recovery_schema_support(
        self,
    ) -> None:
        receipt = self.temp_path / "unsupported-recovery-schema.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_RECOVERY_SCHEMA_MAX": "3",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self._assert_receipt_v3_shape(data)
        self.assertEqual(
            data["message"],
            "Persistent recovery schema v4 is unsupported by target",
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("deploy-recovery-capabilities", log)
        self.assertNotIn("REMOTE_RUN_DIR_READY=true", log)
        self.assertNotIn("PERSISTENT_TX_PREPARED=verified", log)

    def test_persistent_success_retains_verified_binary_and_config_recovery(
        self,
    ) -> None:
        receipt = self.temp_path / "persistent-success.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {"FAKE_BOS_PLATFORM": "zynq-am1-s9"},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self._assert_receipt_v3_shape(data)
        self.assertTrue(data["success"])
        self.assertEqual(data["deploy_mode"], "persistent")
        self.assertEqual(data["exe"], "/data/dcentrald")
        self.assertEqual(data["cleanup_status"], "recovery_artifacts_retained")
        self.assertEqual(data["backup_status"], "verified_durable_retained")
        self.assertEqual(
            data["config_backup_status"], "verified_durable_retained"
        )
        self.assertEqual(data["binary_sha256"], self.binary_sha)
        self.assertEqual(data["config_sha256"], self.config_sha)
        self.assertEqual(data["config_binding_source"], "explicit")
        self.assertEqual(data["original_binary_status"], "present")
        self.assertEqual(data["original_binary_sha256"], "a" * 64)
        self.assertEqual(data["original_binary_metadata"], "0:0:755")
        self.assertEqual(data["original_config_status"], "present")
        self.assertEqual(data["original_config_sha256"], "b" * 64)
        self.assertEqual(data["original_config_metadata"], "0:0:600")
        self.assertEqual(data["rollback_config_source"], "data")
        self.assertEqual(data["rollback_config_path"], "/data/dcentrald.toml")
        self.assertEqual(data["rollback_config_sha256"], "b" * 64)
        self.assertEqual(data["api_verification_status"], "not_requested")
        self.assertEqual(
            data["persistent_transaction_status"],
            "committed_candidate_generation",
        )
        recovery_path = f"/data/.dcent-deploy-recovery/{data['deploy_id']}"
        self.assertEqual(data["recovery_artifact_path"], recovery_path)
        self.assertEqual(
            data["persistent_transaction_state_path"],
            f"{recovery_path}/persistent-transaction.state",
        )
        self.assertEqual(
            data["persistent_transaction_schema"], "dcent-persistent-tx-v4"
        )
        canonical_manifest = "\n".join(
            (
                "PERSISTENT_TX_STATE=dcent-persistent-tx-v4",
                f"DEPLOY_ID={data['deploy_id']}",
                "PHASE=CANONICAL",
                "BINARY_PATH=/data/dcentrald",
                "BINARY_ORIGINAL_STATUS=present",
                f"BINARY_ORIGINAL_SHA256={'a' * 64}",
                f"BINARY_BACKUP_PATH={recovery_path}/dcentrald.backup",
                f"BINARY_CANDIDATE_SHA256={self.binary_sha}",
                "CONFIG_MUTATED=true",
                "CONFIG_SOURCE=explicit",
                "CONFIG_PATH=/data/dcentrald.toml",
                "CONFIG_ORIGINAL_STATUS=present",
                f"CONFIG_ORIGINAL_SHA256={'b' * 64}",
                f"CONFIG_BACKUP_PATH={recovery_path}/dcentrald.toml.backup",
                f"CONFIG_CANDIDATE_SHA256={self.config_sha}",
                "ROLLBACK_CONFIG_SOURCE=data",
                "ROLLBACK_CONFIG_PATH=/data/dcentrald.toml",
                f"ROLLBACK_CONFIG_SHA256={'b' * 64}",
                "BINARY_ORIGINAL_METADATA=0:0:755",
                "CONFIG_ORIGINAL_METADATA=0:0:600",
            )
        ) + "\n"
        expected_identity = hashlib.sha256(
            canonical_manifest.encode("utf-8")
        ).hexdigest()
        self.assertEqual(
            data["persistent_transaction_identity_sha256"], expected_identity
        )
        self.assertEqual(
            data["persistent_transaction_terminal_path"],
            f"{recovery_path}/persistent-transaction.committed",
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn(f"{recovery_path}/dcentrald.backup", log)
        self.assertIn(f"{recovery_path}/dcentrald.toml.backup", log)
        self.assertIn("DEPLOY_MAINTENANCE_READY=true", log)
        self.assertIn("DEPLOY_MAINTENANCE_RELEASED=true", log)
        self.assertIn('mv -f "$config_stage" "$config_path"', log)
        self.assertIn('mv -f "$staging_path" "$deploy_path"', log)
        self.assertIn("PERSISTENT_TX_STATE=dcent-persistent-tx-v4", log)
        self.assertIn("BINARY_ORIGINAL_METADATA=0:0:755", log)
        self.assertIn("CONFIG_ORIGINAL_METADATA=0:0:600", log)
        self.assertIn("ROLLBACK_CONFIG_SOURCE=data", log)
        self.assertIn("ROLLBACK_CONFIG_PATH=/data/dcentrald.toml", log)
        self.assertLess(
            log.index("PERSISTENT_TX_COMMIT=verified"),
            log.index("FINAL_OWNERSHIP=OK"),
        )
        self.assertNotIn("PHASE=failed", log)

    def test_persistent_success_preserves_a_present_empty_original_binary(
        self,
    ) -> None:
        receipt = self.temp_path / "persistent-empty-original.json"
        empty_sha = hashlib.sha256(b"").hexdigest()
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_DEPLOY_EXISTING_STATUS": "present",
                "FAKE_DEPLOY_EXISTING_SIZE": "0",
                "FAKE_EXISTING_SHA": empty_sha,
                "FAKE_EXISTING_METADATA": "0:0:755",
            },
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self._assert_receipt_v3_shape(data)
        self.assertTrue(data["success"])
        self.assertEqual(data["original_binary_status"], "present")
        self.assertEqual(data["original_binary_sha256"], empty_sha)
        self.assertEqual(data["original_binary_metadata"], "0:0:755")
        self.assertEqual(data["backup_status"], "verified_durable_retained")
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("BINARY_ORIGINAL_STATUS=present", log)
        self.assertIn(f"BINARY_ORIGINAL_SHA256={empty_sha}", log)
        self.assertIn("cp -p '/data/dcentrald'", log)

    def test_explicit_config_binds_prior_etc_fallback_for_rollback(self) -> None:
        receipt = self.temp_path / "persistent-etc-fallback.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_ORIGINAL_CONFIG": "absent",
                "FAKE_ROLLBACK_CONFIG_SOURCE": "etc",
            },
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(data["original_config_status"], "absent")
        self.assertEqual(data["original_config_metadata"], "")
        self.assertEqual(data["config_backup_status"], "original_absent")
        self.assertEqual(data["rollback_config_source"], "etc")
        self.assertEqual(data["rollback_config_path"], "/etc/dcentrald.toml")
        self.assertEqual(data["rollback_config_sha256"], "c" * 64)
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("PERSISTENT_TX_STATE=dcent-persistent-tx-v4", log)
        self.assertIn("ROLLBACK_CONFIG_SOURCE=etc", log)
        self.assertIn("ROLLBACK_CONFIG_PATH=/etc/dcentrald.toml", log)
        self.assertIn(f"ROLLBACK_CONFIG_SHA256={'c' * 64}", log)
        self.assertIn('ln -T "$config_stage" "$config_path"', log)

    def test_persistent_config_backup_metadata_must_be_well_formed(self) -> None:
        receipt = self.temp_path / "persistent-config-metadata.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_EXISTING_CONFIG_METADATA": "root:root:0600",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            data["message"],
            "Persistent config backup metadata verification failed",
        )
        self.assertEqual(data["original_config_metadata"], "root:root:0600")
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertNotIn("PERSISTENT_TX_PREPARED=verified", log)

    def test_inherited_persistent_config_must_not_be_group_or_world_writable(
        self,
    ) -> None:
        receipt = self.temp_path / "unsafe-inherited-config.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_DISCOVERED_CONFIG_METADATA": "0:0:666",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            data["message"],
            "Inherited persistent config metadata was unsafe",
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertNotIn("PERSISTENT_TX_PREPARED=verified", log)

    def test_persistent_preflight_requires_transaction_inode_reserve(self) -> None:
        receipt = self.temp_path / "persistent-inodes.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_DEPLOY_FREE_INODES": "15",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            data["message"],
            "Insufficient persistent storage inodes for durable staging",
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertNotIn("REMOTE_RUN_DIR_READY=true", log)

    def test_persistent_retry_refuses_existing_deploy_lease(self) -> None:
        receipt = self.temp_path / "persistent-existing-lease.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_ACTIVE_DEPLOY_LEASE": "1",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            data["message"],
            "Persistent recovery directory acquisition is ambiguous",
        )
        self.assertEqual(
            data["persistent_transaction_status"],
            "lease_acquisition_ambiguous_no_transaction",
        )
        self.assertNotIn(
            "candidate_committed", data["persistent_transaction_status"]
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn('.deploy-lease', log)
        self.assertNotIn("PERSISTENT_TX_PREPARED=verified", log)

    def test_daemon_deploy_refuses_active_admission_or_maintenance(self) -> None:
        receipt = self.temp_path / "active-maintenance.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_ACTIVE_MAINTENANCE": "1",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(data["message"], "Deploy admission exclusion failed")
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("dcentos-deploy-lock", log)
        self.assertNotIn("REMOTE_RUN_DIR_READY=true", log)

    def test_lost_maintenance_acquire_ack_is_reobserved(self) -> None:
        receipt = self.temp_path / "maintenance-acquire-ack-lost.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_MAINTENANCE_ACQUIRE_ACK_LOST": "1",
            },
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertTrue(data["success"])
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("DEPLOY_MAINTENANCE_OBSERVED=held", log)
        self.assertIn("DEPLOY_MAINTENANCE_RELEASED=true", log)

    def test_lost_persistent_lease_acquire_ack_is_reobserved(self) -> None:
        receipt = self.temp_path / "lease-acquire-ack-lost.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_LEASE_ACQUIRE_ACK_LOST": "1",
            },
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertTrue(data["success"])
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("PERSISTENT_DEPLOY_LEASE_OBSERVED=held", log)
        self.assertIn("PERSISTENT_DEPLOY_LEASE_RELEASED=true", log)

    def test_persistent_lease_release_failure_never_revokes_success(self) -> None:
        receipt = self.temp_path / "persistent-lease-release-failed.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_LEASE_RELEASE_FAIL": "1",
            },
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertTrue(data["success"])
        self.assertEqual(data["deploy_lease_status_at_receipt_publication"], "held")
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertEqual(log.count('mv "$lease" "$retired"'), 1)
        self.assertNotIn("PHASE=failed", log)
        self.assertNotIn('kill -TERM "$pid"', log)
        self.assertIn("lease retirement is held", result.stdout + result.stderr)

    def test_lost_lease_release_ack_is_reobserved_without_rollback(self) -> None:
        receipt = self.temp_path / "persistent-lease-release-ack-lost.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_LEASE_RELEASE_ACK_LOST": "1",
            },
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertTrue(data["success"])
        self.assertEqual(data["deploy_lease_status_at_receipt_publication"], "held")
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("PERSISTENT_DEPLOY_LEASE_OBSERVED=released", log)
        self.assertNotIn("PHASE=failed", log)
        self.assertNotIn('kill -TERM "$pid"', log)

    def test_ambiguous_lease_release_never_mutates_without_exclusion(self) -> None:
        receipt = self.temp_path / "persistent-lease-release-ambiguous.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_LEASE_RELEASE_AMBIGUOUS": "1",
            },
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertTrue(data["success"])
        self.assertEqual(data["deploy_lease_status_at_receipt_publication"], "held")
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertNotIn("PHASE=failed", log)
        self.assertNotIn('kill -TERM "$pid"', log)
        self.assertIn("lease retirement is ambiguous", result.stdout + result.stderr)

    def test_empty_explicit_config_still_budgets_existing_config_backup(
        self,
    ) -> None:
        empty_config = self.temp_path / "empty.toml"
        empty_config.write_bytes(b"")
        receipt = self.temp_path / "persistent-empty-config-space.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(empty_config),
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                # Enough only if the existing config recovery copy is
                # incorrectly omitted from block-rounded accounting.
                "FAKE_DEPLOY_FREE_BYTES": "1058000",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            data["message"],
            "Insufficient persistent storage space for durable staging",
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertNotIn("REMOTE_RUN_DIR_READY=true", log)

    def test_persistent_manifest_publish_failure_precedes_all_live_mutation(
        self,
    ) -> None:
        receipt = self.temp_path / "persistent-manifest-failure.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_TX_PREPARE_FAIL": "1",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertFalse(data["success"])
        self.assertEqual(
            data["message"], "Persistent transaction manifest publication failed"
        )
        self.assertEqual(data["cleanup_status"], "recovery_artifacts_retained")
        self.assertEqual(
            data["persistent_transaction_status"],
            "publication_ambiguous_recovery_artifacts_retained",
        )
        self.assertEqual(
            data["rollback_status"],
            "not_applicable_manifest_publication_ambiguous",
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("PERSISTENT_TX_PREPARED=verified", log)
        self.assertNotIn("tx_set_phase prepared mutating", log)
        self.assertNotIn('mv -f "$staging_path" "$deploy_path"', log)

    def test_persistent_commit_failure_stops_launch_and_leaves_boot_recovery(
        self,
    ) -> None:
        receipt = self.temp_path / "persistent-commit-failure.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_TX_COMMIT_FAIL": "1",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertFalse(data["success"])
        self.assertEqual(
            data["message"], "Persistent transaction commit was not proven"
        )
        self.assertEqual(
            data["persistent_transaction_status"],
            "failed_pending_boot_recovery",
        )
        self.assertEqual(data["persistent_transaction_terminal_path"], "")
        self.assertEqual(
            data["rollback_status"],
            "not_requested_recovery_artifacts_retained",
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("PERSISTENT_TX_COMMIT=verified", log)
        self.assertIn("expected_launch_id=", log)
        self.assertNotIn("FINAL_OWNERSHIP=OK", log)

    def test_persistent_final_arbitration_failure_reopens_committed_rollback(
        self,
    ) -> None:
        receipt = self.temp_path / "persistent-final-arbitration.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(self.config),
                "--rollback-on-fail",
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_VENDOR_RESPAWN": "1",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            data["message"], "Final hardware ownership arbitration failed"
        )
        self.assertEqual(
            data["rollback_status"],
            "files_restored_launch_stopped_ownership_unverified",
        )
        self.assertEqual(
            data["persistent_transaction_status"],
            "rolled_back_prior_generation",
        )
        recovery_path = f"/data/.dcent-deploy-recovery/{data['deploy_id']}"
        self.assertEqual(
            data["persistent_transaction_terminal_path"],
            f"{recovery_path}/persistent-transaction.rolled-back",
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertLess(
            log.index("PERSISTENT_TX_COMMIT=verified"),
            log.index("FINAL_OWNERSHIP=OK"),
        )
        self.assertLess(
            log.index("FINAL_OWNERSHIP=OK"),
            log.index(
                "PERSISTENT_ROLLBACK=files_restored_launch_stopped_ownership_unverified"
            ),
        )
        self.assertNotIn("runtime-launch.cancelled'; rmdir", log)

    def test_persistent_inherited_or_builtin_config_selection_is_bound(
        self,
    ) -> None:
        for inherited, expected_source, expected_hash in (
            ("data", "discovered", "b" * 64),
            ("etc", "discovered", "b" * 64),
            ("none", "builtin", ""),
        ):
            with self.subTest(inherited=inherited):
                receipt = self.temp_path / f"persistent-inherited-{inherited}.json"
                result = self._run_deploy(
                    [
                        "192.0.2.10",
                        "--skip-build",
                        "--output",
                        self._shell_path(receipt),
                    ],
                    {
                        "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                        "FAKE_INHERITED_CONFIG": inherited,
                    },
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                data = json.loads(receipt.read_text(encoding="utf-8"))
                self.assertEqual(data["config_binding_source"], expected_source)
                self.assertEqual(data["config_sha256"], expected_hash)
                self.assertEqual(data["config_backup_status"], "not_required")
                self.assertEqual(data["original_config_status"], "not_captured")
                log = self.ssh_log.read_text(encoding="utf-8")
                if inherited == "none":
                    self.assertIn("CONFIG_EXPECTED_BUILTIN", SCRIPT.read_text())
                else:
                    expected_path = (
                        "/etc/dcentrald.toml"
                        if inherited == "etc"
                        else "/data/dcentrald.toml"
                    )
                    self.assertIn(f"CONFIG_PATH={expected_path}", log)
                self.ssh_log.unlink()

    def test_persistent_pre_mutation_drift_fails_before_launch(self) -> None:
        for drift in ("binary", "config"):
            with self.subTest(drift=drift):
                receipt = self.temp_path / f"persistent-drift-{drift}.json"
                result = self._run_deploy(
                    [
                        "192.0.2.10",
                        "--skip-build",
                        "--config",
                        self._shell_path(self.config),
                        "--output",
                        self._shell_path(receipt),
                    ],
                    {
                        "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                        "FAKE_PREMUTATION_DRIFT": drift,
                    },
                )
                self.assertNotEqual(result.returncode, 0)
                data = json.loads(receipt.read_text(encoding="utf-8"))
                self.assertEqual(
                    data["message"], "Persistent binary/config installation failed"
                )
                log = self.ssh_log.read_text(encoding="utf-8")
                self.assertNotIn("runtime-launch.authorized", log)
                self.assertIn("existing_sha=", log)
                self.ssh_log.unlink()

    def test_manifest_identity_corruption_blocks_phase_advance(self) -> None:
        receipt = self.temp_path / "persistent-identity-corruption.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_TX_IDENTITY_MISMATCH": "1",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            data["message"], "Persistent binary/config installation failed"
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("PHASE=CANONICAL", log)
        self.assertNotIn("runtime-launch.authorized", log)

    def test_persistent_failure_preserves_recovery_or_hash_verified_restore(
        self,
    ) -> None:
        for rollback, expected_status in (
            (False, "not_requested_recovery_artifacts_retained"),
            (True, "files_restored_launch_stopped_ownership_unverified"),
        ):
            with self.subTest(rollback=rollback):
                receipt = self.temp_path / f"persistent-failure-{rollback}.json"
                arguments = [
                    "192.0.2.10",
                    "--skip-build",
                    "--config",
                    self._shell_path(self.config),
                    "--output",
                    self._shell_path(receipt),
                ]
                if rollback:
                    arguments.append("--rollback-on-fail")
                result = self._run_deploy(
                    arguments,
                    {
                        "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                        "FAKE_VENDOR_RESPAWN": "1",
                    },
                )
                self.assertNotEqual(result.returncode, 0)
                data = json.loads(receipt.read_text(encoding="utf-8"))
                self.assertFalse(data["success"])
                self.assertEqual(data["cleanup_status"], "recovery_artifacts_retained")
                self.assertEqual(data["rollback_status"], expected_status)
                self.assertEqual(
                    data["recovery_artifact_path"],
                    f"/data/.dcent-deploy-recovery/{data['deploy_id']}",
                )
                log = self.ssh_log.read_text(encoding="utf-8")
                self.assertIn('kill -TERM "$pid"', log)
                self.assertNotIn("runtime-launch.cancelled'; rmdir", log)
                if rollback:
                    self.assertIn(
                        "PERSISTENT_ROLLBACK="
                        "files_restored_launch_stopped_ownership_unverified",
                        log,
                    )
                self.ssh_log.unlink()

    def test_persistent_rollback_failure_is_never_reported_as_restored(self) -> None:
        receipt = self.temp_path / "persistent-rollback-failed.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
                "--rollback-on-fail",
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_VENDOR_RESPAWN": "1",
                "FAKE_ROLLBACK_FAIL": "1",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(data["cleanup_status"], "incomplete")
        self.assertEqual(
            data["rollback_status"], "failed_recovery_artifacts_retained"
        )
        self.assertEqual(data["backup_status"], "verified_durable_retained")
        self.assertNotIn("rolled back", data["message"].lower())

    def test_persistent_lost_start_output_recovers_before_byte_rollback(
        self,
    ) -> None:
        receipt = self.temp_path / "persistent-lost-output.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
                "--rollback-on-fail",
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_START_OUTPUT_EMPTY": "1",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(data["pid"], 4242)
        self.assertEqual(data["start_ticks"], "99")
        self.assertEqual(data["exe"], "/data/dcentrald")
        self.assertEqual(
            data["rollback_status"],
            "files_restored_launch_stopped_ownership_unverified",
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("expected_exe='/data/dcentrald'", log)
        self.assertIn('kill -TERM "$pid"', log)

    def test_persistent_rollback_is_refused_when_launch_stop_is_unproven(
        self,
    ) -> None:
        receipt = self.temp_path / "persistent-owner-unproven.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
                "--rollback-on-fail",
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_VENDOR_RESPAWN": "1",
                "FAKE_STOP_FAIL": "1",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(data["cleanup_status"], "incomplete")
        self.assertEqual(
            data["rollback_status"],
            "refused_owner_unproven_recovery_artifacts_retained",
        )
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn('kill -TERM "$pid"', log)
        self.assertNotIn(
            "PERSISTENT_ROLLBACK="
            "files_restored_launch_stopped_ownership_unverified",
            log,
        )
        self.assertNotIn("DEPLOY_MAINTENANCE_RELEASED=true", log)

    def test_persistent_rollback_restores_prior_absence_without_claiming_owner(
        self,
    ) -> None:
        receipt = self.temp_path / "persistent-original-absent.json"
        result = self._run_deploy(
            [
                "192.0.2.10",
                "--skip-build",
                "--config",
                self._shell_path(self.config),
                "--output",
                self._shell_path(receipt),
                "--rollback-on-fail",
            ],
            {
                "FAKE_BOS_PLATFORM": "zynq-am1-s9",
                "FAKE_DEPLOY_EXISTING_SIZE": "0",
                "FAKE_EXISTING_SHA": "NONE",
                "FAKE_EXISTING_METADATA": "NONE",
                "FAKE_VENDOR_RESPAWN": "1",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(data["backup_status"], "original_absent")
        self.assertEqual(
            data["rollback_status"],
            "files_restored_launch_stopped_ownership_unverified",
        )
        self.assertEqual(data["pid"], 4242)
        log = self.ssh_log.read_text(encoding="utf-8")
        self.assertIn("existing_size=0", log)
        self.assertNotIn("rolled back to backup", log.lower())


if __name__ == "__main__":
    unittest.main()
