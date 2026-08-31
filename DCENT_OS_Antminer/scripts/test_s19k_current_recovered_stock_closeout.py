#!/usr/bin/env python3
"""Offline gates for the exact 2026-08-20 recovered-stock closeout."""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "dcentrald_s19k_tmp_current_recovered_stock_closeout_20260820.sh"
CUSTODY = ROOT / "scripts" / "dcentrald_s19k_braiins_supervisor_custody.sh"
RUN_LOG = ROOT / "tmp" / "s19k-live-20260820-watchdog" / "track1-run.utf8.log"
RECOVERY_LOG = (
    ROOT / "tmp" / "s19k-live-20260820-watchdog" / "post-run-stock-recovery.utf8.log"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ExactRecoveredStockCloseoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_shell_syntax(self) -> None:
        shell = shutil.which("sh")
        if shell is None:
            self.skipTest("POSIX sh is not on the Windows host PATH")
        subprocess.run([shell, "-n", str(SCRIPT)], check=True)

    def test_exact_transaction_and_process_tree_are_hard_bound(self) -> None:
        required = {
            "TRIAL_DIR=/tmp/dcentrald_bench_t1_20260820130324_61373",
            "ACTIVE_SHA=6c19d422d8a09004cad5909c3d4c92700715b30a4cd17938beb5241a24885fb3",
            "OWNER_SHA=adb44027d9289a1faa220163053afe01bcb45ad09bbdbb48ee4c428787a76b88",
            "WRAPPER_PID=8760",
            "WRAPPER_START=1043943",
            "DCENT_CHILD_PID=9474",
            "DCENT_CHILD_START=1044497",
            "ORIGINAL_BOSMINER_PID=1472",
            "ORIGINAL_BOSMINER_START=1262",
            "SUPERVISOR_PID=1458",
            "SUPERVISOR_START=1251",
            "RECOVERED_CHILD_PID=9495",
            "RECOVERED_CHILD_START=1044815",
            "PIDFILE_SHA=4574cce19d396d4f7936ee9604f4d8ac809067746a51c6a6ba40d81a592d336c",
            "PIDFILE_BYTES=5",
            "custody_observer_sha256=%s",
            "custody_observer_bytes=%s",
            "disposition=stock-recovered-after-dcent-safeoff",
            "handoff_reached=true",
            "uart_mutation_reached=true",
            "reset_gpio_mutation=true",
            "safeoff_gpio437=true",
            "persistent_mutation=false",
            "run_evidence_bytes=%s",
            "stock_recovery_evidence_bytes=%s",
        }
        for anchor in required:
            self.assertIn(anchor, self.source)

    def test_bound_observer_is_current_and_read_only(self) -> None:
        expected_sha = re.search(r"^CUSTODY_SHA=([0-9a-f]{64})$", self.source, re.M)
        expected_bytes = re.search(r"^CUSTODY_BYTES=([0-9]+)$", self.source, re.M)
        self.assertIsNotNone(expected_sha)
        self.assertIsNotNone(expected_bytes)
        self.assertEqual(sha256(CUSTODY), expected_sha.group(1))
        self.assertEqual(CUSTODY.stat().st_size, int(expected_bytes.group(1)))
        self.assertIn("authority=read-only-process-tree-observation", CUSTODY.read_text())

    def test_no_hardware_or_process_mutation_commands(self) -> None:
        executable = "\n".join(
            line for line in self.source.splitlines() if line.strip() and not line.lstrip().startswith("#")
        )
        forbidden = (
            r"(^|[;&|\s])kill(\s|$)",
            r"(^|[;&|\s])(reboot|poweroff|halt)(\s|$)",
            r"(^|[;&|\s])(flash_erase|nandwrite|dd)(\s|$)",
            r"/dev/ttyS[0-9]",
            r"/sys/class/gpio/.*/value[\"']?\s*>",
            r"/etc/init\.d/",
        )
        for pattern in forbidden:
            self.assertIsNone(re.search(pattern, executable), pattern)

    def test_full_revalidation_precedes_fail_closed_release_order(self) -> None:
        final_gate = self.source.index("# Final full admission while the board-global lock is still held.")
        move_active = self.source.index('mv "$ACTIVE" "$RETIRED_ACTIVE"')
        post_move_gate = self.source.index('volatile_state_is_exact "$CUSTODY_TMP"', move_active)
        move_owner = self.source.index('mv "$OWNER" "$RETIRED_OWNER"')
        empty_lock = self.source.index('rmdir "$LOCK"')
        publish = self.source.index('ln "$RECEIPT_TMP" "$CLOSEOUT"')
        self.assertLess(final_gate, move_active)
        self.assertLess(move_active, post_move_gate)
        self.assertLess(post_move_gate, move_owner)
        self.assertLess(move_owner, empty_lock)
        self.assertLess(empty_lock, publish)
        self.assertIn('mv "$RETIRED_ACTIVE" "$ACTIVE"', self.source)
        self.assertIn('mv "$RETIRED_OWNER" "$OWNER"', self.source)

    def test_exact_gpio_direction_active_low_value_and_no_watchdog_fd(self) -> None:
        for anchor in (
            "gpio_is_exact 437 0",
            "gpio_is_exact 454 0",
            "gpio_is_exact 455 1",
            "gpio_is_exact 456 1",
            '"$(cat "$BASE/direction")" = out',
            '"$(cat "$BASE/active_low")" = 0',
            "/dev/watchdog*",
        ):
            self.assertIn(anchor, self.source)

    def test_local_immutable_transcripts_match_when_present(self) -> None:
        if not RUN_LOG.exists() or not RECOVERY_LOG.exists():
            self.skipTest("bench transcripts are intentionally outside the tracked source tree")
        self.assertEqual(sha256(RUN_LOG), "b91ef6c69aaffcb3beb2f1d45e24388acdb56ee17e86ebaa56fdb0385029d8d2")
        self.assertEqual(RUN_LOG.stat().st_size, 17850)
        self.assertEqual(sha256(RECOVERY_LOG), "43d045945a196144d7aa3096e13b198278da80c282607e22da03c3349ad78649")
        self.assertEqual(RECOVERY_LOG.stat().st_size, 9936)

    def test_utf8_transcripts_retain_all_semantic_anchors(self) -> None:
        run = RUN_LOG.read_text(encoding="utf-8")
        recovery = RECOVERY_LOG.read_text(encoding="utf-8")
        for anchor in (
            "S19k Track-1 assumed inherited rails after signal-lease-confirmed bosminer exit",
            "PASSTHROUGH BM1366 — opening ttyS1+ttyS2 required, ttyS3 discover",
            "Track-1 terminal hashboard reset asserted with checked readback",
            "PSU GPIO 437 driven 1 and read back disengaged (am3-s19k T6 SafeOff)",
            "Track-1 terminal GPIO437 SafeOff completed after reset attempts",
        ):
            self.assertIn(anchor, run)
        for anchor in (
            "2026-08-20T17:08:11.688752Z  INFO bosminer_backend::miner: Cooldown temperature reached",
            "2026-08-20T17:08:36.118090Z  INFO bosminer_backend::psu: PSU: Enable",
            "CHAIN/2: Discovered 77 chips (expected 77 chips)",
            "CHAIN/3: Discovered 77 chips (expected 77 chips)",
            "2026-08-20T17:10:14.779605Z  INFO bosminer::client::stratum_v2: log_message=\"Stratum: changing target",
        ):
            self.assertIn(anchor, recovery)
        self.assertEqual(
            recovery.count("Set baud rate @ requested: 3125000, actual: 3125000"),
            2,
        )

    def test_one_use_token_and_no_generic_target_parameters(self) -> None:
        self.assertIn("CLEAR_EXACT_20260820_STOCK_RECOVERED", self.source)
        self.assertIn('[ "$#" -eq 1 ]', self.source)
        self.assertNotIn("expected_supervisor_pid", self.source.lower())
        self.assertNotIn("expected_trial", self.source.lower())

    def test_scratch_is_private_and_atomic_before_redirection(self) -> None:
        acquire = self.source.index('mkdir "$TMP_DIR"')
        first_custody_capture = self.source.index('volatile_state_is_exact "$CUSTODY_TMP"', acquire)
        receipt_redirect = self.source.index('> "$RECEIPT_TMP"')
        self.assertLess(acquire, first_custody_capture)
        self.assertLess(acquire, receipt_redirect)
        self.assertIn('[ ! -e "$TMP_DIR" ] && [ ! -L "$TMP_DIR" ]', self.source)
        self.assertIn('rmdir "$TMP_DIR"', self.source)


if __name__ == "__main__":
    unittest.main()
