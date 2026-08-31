#!/usr/bin/env python3
"""Offline regression tests for the S19k AML mtd5 flash-transaction NAND sim.

Every test is pure simulation: no device, no network, no subprocess. The sim
module is the desk-side proof that the typed ``mtd5_rootfs_window_flag_commit``
transaction (backup -> window write -> flag commit -> rollback -> restore) is
mechanically executable for the exact 2026-08-30 unit geometry, and that every
power-loss cut classifies against the transaction's own atomicity model.
"""

from __future__ import annotations

import hashlib
import importlib
import io
import json
import re
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

sim = importlib.import_module("s19k_aml_flash_transaction_sim")

ROOT = SCRIPT_DIR.parent
INSTALL_SH = ROOT / "scripts" / "install_amlogic_persistent.sh"
GEOMETRY_SH = ROOT / "scripts" / "lib" / "am3_geometry.sh"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")


class GeometryConvergenceTests(unittest.TestCase):
    """The sim's pins must equal the canonical desk contracts exactly."""

    def test_partitions_equal_recovery_verifier_contract(self) -> None:
        verifier = importlib.import_module("s19k_persistent_recovery_verify")
        self.assertEqual(
            [(p.index, p.name, p.offset, p.size, p.erasesize) for p in verifier.PARTITIONS],
            [
                (pin.index, pin.name, pin.offset, pin.size, sim.ERASE_BLOCK)
                for pin in sim.LINUX_PARTITIONS
            ],
        )

    def test_window_and_recovery_pins_equal_am3_geometry_sh(self) -> None:
        source = read(GEOMETRY_SH)
        # direct, unambiguous equality pins
        self.assertIn('DCENT_AM3_ROOTFS_OFFSET_HEX="${DCENT_AM3_ROOTFS_OFFSET_HEX:-0x05100000}"', source)
        self.assertIn('DCENT_AM3_ROOTFS_WINDOW_HEX="${DCENT_AM3_ROOTFS_WINDOW_HEX:-0x02800000}"', source)
        self.assertIn('DCENT_AM3_ROOTFS_ERASE_COUNT="${DCENT_AM3_ROOTFS_ERASE_COUNT:-320}"', source)
        self.assertIn('DCENT_AM3_ROOTFS_ERASESIZE_EXPECTED="${DCENT_AM3_ROOTFS_ERASESIZE_EXPECTED:-131072}"', source)
        self.assertIn('DCENT_AM3_RECOVERY_FLAG_OFFSET_HEX="${DCENT_AM3_RECOVERY_FLAG_OFFSET_HEX:-0x04D00000}"', source)
        self.assertIn('DCENT_AM3_NANDRECOVERY_ENV_LEN="${DCENT_AM3_NANDRECOVERY_ENV_LEN:-0x10000}"', source)
        self.assertIn('DCENT_AM3_RECOVERY_FLAG_GLOBAL="${DCENT_AM3_RECOVERY_FLAG_GLOBAL:-0x0B400000}"', source)
        self.assertIn('DCENT_AM3_NANDROOTFS_GLOBAL="${DCENT_AM3_NANDROOTFS_GLOBAL:-0x0B800000}"', source)
        self.assertIn('DCENT_AM3_NANDRECOVERY_ENV_GLOBAL="${DCENT_AM3_NANDRECOVERY_ENV_GLOBAL:-0x0B000000}"', source)
        # the 6 MiB mtd0->mtd1 hole is explicit (the 0x06100000 size-sum trap)
        self.assertIn('DCENT_AM3_OFFSET_FROM_END_MTD0_TO_MTD1="${DCENT_AM3_OFFSET_FROM_END_MTD0_TO_MTD1:-0x600000}"', source)

    def test_flag_tail_sha_pin_is_the_geometry_lib_value(self) -> None:
        source = read(GEOMETRY_SH)
        self.assertIn(sim.FLAG_TAIL_ALL_FF_SHA256, source)
        self.assertEqual(
            sim.FLAG_TAIL_ALL_FF_SHA256,
            hashlib.sha256(b"\xff" * (sim.ERASE_BLOCK - 1)).hexdigest(),
        )

    def test_window_math_is_erase_exact(self) -> None:
        self.assertEqual(sim.WINDOW_ERASE_COUNT * sim.ERASE_BLOCK, sim.WINDOW_BYTES)
        self.assertEqual(sim.WINDOW_BYTES, 0x02800000)
        self.assertEqual(sim.FLAG_EB_LOCAL // sim.ERASE_BLOCK, 616)
        self.assertEqual(sim.RECOVERY_ENV_LOCAL // sim.ERASE_BLOCK, 584)
        self.assertEqual(sim.LINUX_PARTITIONS[5].erase_blocks, 1224)
        for pin in sim.LINUX_PARTITIONS:
            self.assertEqual(pin.size % sim.ERASE_BLOCK, 0, pin.name)

    def test_uboot_nvdata_span_equals_overlay_plus_system(self) -> None:
        self.assertEqual(
            sim.UBOOT_NVDATA_GLOBAL_END - sim.UBOOT_NVDATA_GLOBAL_START,
            0x0B900000,  # stock mtd6 "nvdata" size in the held stock /proc/mtd
        )
        self.assertEqual(
            sim.UBOOT_NVDATA_GLOBAL_START, sim.LINUX_PARTITIONS[4].offset
        )
        self.assertEqual(
            sim.UBOOT_NVDATA_GLOBAL_END,
            sim.LINUX_PARTITIONS[5].offset + sim.LINUX_PARTITIONS[5].size,
        )

    def test_proc_mtd_rows_are_the_exact_six_row_map(self) -> None:
        rows = sim.proc_mtd_rows()
        for expected in (
            "mtd0: 00200000 00020000 bootloader",
            "mtd1: 00800000 00020000 tpl",
            "mtd2: 03200000 00020000 stock_system",
            "mtd3: 00500000 00020000 stock_config",
            "mtd4: 02000000 00020000 overlay",
            "mtd5: 09900000 00020000 system",
        ):
            self.assertIn(expected, rows)

    def test_install_program_matches_the_typed_shell_writer(self) -> None:
        source = read(INSTALL_SH)
        self.assertIn(
            "flash_erase $ROOTFS_MTD $ROOTFS_OFFSET_HEX $ROOTFS_ERASE_COUNT", source
        )
        self.assertIn(
            "nandwrite -p -s $ROOTFS_OFFSET_HEX $ROOTFS_MTD /proc/self/fd/3", source
        )
        gate = source.index("CLEAR_FOR_FLASH=false")
        writer = source.index(
            "flash_erase $ROOTFS_MTD $ROOTFS_OFFSET_HEX $ROOTFS_ERASE_COUNT"
        )
        self.assertLess(gate, writer, "the shell gate must precede the writer")
        program = sim.install_program(26_000_000)
        window_erase = next(op for op in program if op.leg == "window" and op.op == "erase")
        self.assertEqual(window_erase.offset, sim.WINDOW_LOCAL)
        self.assertEqual(window_erase.length, sim.WINDOW_ERASE_COUNT * sim.ERASE_BLOCK)
        flag_erase = next(op for op in program if op.leg == "commit" and op.op == "erase")
        self.assertEqual(flag_erase.offset, sim.FLAG_EB_LOCAL)
        self.assertEqual(flag_erase.length, sim.ERASE_BLOCK)
        self.assertTrue(flag_erase.commit_window)


class SimPhysicsTests(unittest.TestCase):
    def test_write_to_unerased_stock_flash_fails_loudly(self) -> None:
        bank = sim.build_pristine_bank()
        payload = sim.synthetic_root_payload(2 * sim.ERASE_BLOCK)
        with self.assertRaisesRegex(sim.SimNandError, "erase-before-write"):
            bank["mtd5"].write(sim.WINDOW_LOCAL, payload)

    def test_double_write_fails_and_post_erase_write_verifies(self) -> None:
        bank = sim.build_pristine_bank()
        payload = sim.synthetic_root_payload(sim.ERASE_BLOCK)
        bank["mtd5"].erase(sim.WINDOW_LOCAL, sim.ERASE_BLOCK)
        bank["mtd5"].write(sim.WINDOW_LOCAL, payload)
        with self.assertRaisesRegex(sim.SimNandError, "erase-before-write"):
            bank["mtd5"].write(sim.WINDOW_LOCAL, payload)
        self.assertEqual(
            bank["mtd5"].read(sim.WINDOW_LOCAL, len(payload)), payload
        )
        bank["mtd5"].erase(sim.WINDOW_LOCAL, sim.ERASE_BLOCK)
        bank["mtd5"].write(sim.WINDOW_LOCAL, payload)
        self.assertEqual(
            bank["mtd5"].read(sim.WINDOW_LOCAL, len(payload)), payload
        )

    def test_misaligned_and_out_of_bounds_ops_fail(self) -> None:
        bank = sim.build_pristine_bank()
        with self.assertRaises(sim.SimNandError):
            bank["mtd5"].erase(1, sim.ERASE_BLOCK)
        with self.assertRaises(sim.SimNandError):
            bank["mtd5"].erase(sim.WINDOW_LOCAL, 12345)
        with self.assertRaises(sim.SimNandError):
            bank["mtd5"].read(sim.LINUX_PARTITIONS[5].size, 1)
        with self.assertRaises(sim.SimNandError):
            bank["mtd5"].write(1, b"\x01")

    def test_pristine_bank_seeds_flag_and_env(self) -> None:
        bank = sim.build_pristine_bank()
        self.assertEqual(sim.flag_byte(bank), sim.FLAG_STOCK_REVERT)
        sim.admit_exclusive_flag_eb(
            bank["mtd5"].read(sim.FLAG_EB_LOCAL, sim.ERASE_BLOCK)
        )
        self.assertTrue(
            sim.env_crc_ok(
                bank["mtd5"].read(sim.RECOVERY_ENV_LOCAL, sim.RECOVERY_ENV_LEN)
            )
        )
        self.assertTrue(bank.stock_chain_pristine())
        self.assertTrue(bank["mtd4"].is_stock())

    def test_flag_candidate_and_exclusive_admission(self) -> None:
        candidate = sim.flag_candidate(sim.FLAG_INSTALL_COMMIT)
        self.assertEqual(len(candidate), sim.ERASE_BLOCK)
        self.assertEqual(candidate[0], 0x01)
        self.assertEqual(candidate[1:].count(0xFF), sim.ERASE_BLOCK - 1)
        sim.admit_exclusive_flag_eb(candidate)
        with self.assertRaises(sim.SimNandError):
            sim.flag_candidate(0x09)
        dirty = bytearray(candidate)
        dirty[4096] = 0x5A
        with self.assertRaisesRegex(sim.SimNandError, "all-0xFF"):
            sim.admit_exclusive_flag_eb(bytes(dirty))
        with self.assertRaises(sim.SimNandError):
            sim.admit_exclusive_flag_eb(candidate[:-1])

    def test_env_images_are_crc_self_checking(self) -> None:
        image = sim.make_env_image()
        self.assertEqual(len(image), sim.RECOVERY_ENV_LEN)
        self.assertTrue(sim.env_crc_ok(image))
        corrupted = bytearray(image)
        corrupted[100] ^= 0xFF
        self.assertFalse(sim.env_crc_ok(bytes(corrupted)))
        self.assertFalse(sim.env_crc_ok(image[:-1]))

    def test_payload_bounds_refuse_window_overrun(self) -> None:
        with self.assertRaisesRegex(sim.SimNandError, "exceeds the 0x02800000 window"):
            sim.install_program(sim.WINDOW_BYTES + 1)
        # exact-window payload is admissible and erase-aligned
        program = sim.install_program(sim.WINDOW_BYTES)
        write = next(op for op in program if op.leg == "window" and op.op == "write")
        self.assertEqual(write.length, sim.WINDOW_BYTES)
        # an unaligned payload is 0xFF-padded up to the erase boundary
        program = sim.install_program(26_000_000)
        write = next(op for op in program if op.leg == "window" and op.op == "write")
        self.assertEqual(write.length % sim.ERASE_BLOCK, 0)
        self.assertGreater(write.length, 26_000_000)


class TransactionLegTests(unittest.TestCase):
    """The five legs of the flash transaction, executed clean."""

    def test_leg1_backup_artifact_shape(self) -> None:
        bank = sim.build_pristine_bank()
        artifact = sim.capture_backup(bank)
        self.assertEqual(
            sorted(artifact.dumps),
            sorted(pin.backup_name for pin in sim.LINUX_PARTITIONS),
        )
        for pin in sim.LINUX_PARTITIONS:
            self.assertEqual(len(artifact.dumps[pin.backup_name]), pin.size)
        self.assertEqual(
            artifact.mtd5_pre_install_bin,
            artifact.dumps["mtd5_system.padbad.bin"],
        )
        self.assertEqual(len(artifact.mtd5_pre_install_bin), 0x09900000)
        self.assertEqual(len(artifact.nand_env_bak), 0x10000)
        self.assertEqual(len(artifact.nandrecovery_env_bin), 0x10000)
        self.assertEqual(len(artifact.recovery_flag_eb_bin), 0x20000)
        self.assertTrue(artifact.duplicate_read_equal)
        self.assertTrue(artifact.env_crc_ok)
        self.assertTrue(artifact.recovery_env_crc_ok)
        self.assertTrue(artifact.flag_eb_exclusive)
        # the dump SHA sidecars cover all six partitions
        self.assertEqual(
            sorted(artifact.dump_sha256),
            sorted(pin.backup_name for pin in sim.LINUX_PARTITIONS),
        )

    def test_legs_1_2_3_install_transaction_complete(self) -> None:
        run, bank = sim.run_install_transaction()
        self.assertIsNone(run.error)
        self.assertEqual(run.classification, "transaction_complete")
        self.assertEqual(run.legs_proven, ("backup", "window", "commit"))
        self.assertTrue(run.all_verifies_green)
        self.assertEqual(sim.flag_byte(bank), sim.FLAG_INSTALL_COMMIT)
        self.assertEqual(run.flag_byte, "0x01_install_commit")
        self.assertEqual(run.window_state, "dcent-payload-verified")
        # mtd0..mtd4 never moved
        for entry in run.preserved_stock:
            self.assertTrue(entry["stock_byte_identical"], entry)
        self.assertEqual(
            [e["partition"] for e in run.preserved_stock],
            ["mtd0", "mtd1", "mtd2", "mtd3", "mtd4"],
        )
        # the window tail beyond the padded payload stays erased
        payload = sim.synthetic_root_payload(26_000_000)
        padded = -(-len(payload) // sim.ERASE_BLOCK) * sim.ERASE_BLOCK
        self.assertTrue(
            bank["mtd5"].is_all_ff(
                sim.WINDOW_LOCAL + padded, sim.WINDOW_BYTES - padded
            )
        )
        # the nandrecovery_env and flag regions outside the window are stock
        self.assertTrue(
            sim.env_crc_ok(
                bank["mtd5"].read(sim.RECOVERY_ENV_LOCAL, sim.RECOVERY_ENV_LEN)
            )
        )
        # honesty fields
        self.assertFalse(run.clear_for_flash)
        self.assertTrue(run.simulation)
        self.assertEqual(run.device_contact, "none")
        self.assertFalse(run.authorizes_execution)
        self.assertFalse(run.persistent_write_authorized)

    def test_leg4_rollback_transaction_complete(self) -> None:
        seed, _ = sim.committed_bank()
        self.assertEqual(sim.flag_byte(seed), sim.FLAG_INSTALL_COMMIT)
        run, bank = sim.run_rollback_transaction(seed.copy())
        self.assertIsNone(run.error)
        self.assertEqual(run.classification, "rollback_complete_stock_boots")
        self.assertEqual(run.legs_proven, ("rollback",))
        self.assertTrue(run.all_verifies_green)
        # The 0x02 rewrite was verified mid-transaction (op 3 in the ledger);
        # the vendor nvdata erase then consumes the flag EB along with the
        # whole span, so the FINAL flag state is erased (0xFF).
        flag_verify_op = next(
            e for e in run.ops if e["leg"] == "rollback" and e["op"] == "verify"
        )
        self.assertTrue(flag_verify_op["verified"])
        self.assertIn("byte0=0x02", flag_verify_op["detail"])
        self.assertEqual(sim.flag_byte(bank), 0xFF)
        # nvdata span fully erased: whole mtd4 + whole mtd5
        self.assertTrue(bank["mtd4"].is_all_ff(0, bank["mtd4"].size))
        self.assertTrue(bank["mtd5"].is_all_ff(0, bank["mtd5"].size))
        # the stock boot chain never moved
        self.assertTrue(bank.stock_chain_pristine())
        # op order: the env is read into RAM BEFORE the nvdata erase
        ops = [entry for entry in run.ops if entry["op"] == "uboot"]
        env_read = next(
            e["seq"] for e in ops if "nandrecovery_env" in e["note"]
        )
        env_import = next(e["seq"] for e in ops if "env import" in e["note"])
        nvdata_erase = next(
            e["seq"] for e in ops if e["partition"] == "uboot:nvdata"
        )
        self.assertLess(env_read, nvdata_erase)
        self.assertLess(env_import, nvdata_erase)

    def test_leg5_restore_returns_bank_to_pristine_bytes(self) -> None:
        pristine = sim.build_pristine_bank()
        backup = sim.capture_backup(pristine)
        # a realistic broken state: window half-written, flag EB erased
        broken = sim.build_pristine_bank()
        broken["mtd5"].erase(sim.WINDOW_LOCAL, sim.WINDOW_BYTES)
        broken["mtd5"].write(
            sim.WINDOW_LOCAL, sim.synthetic_root_payload(3 * sim.ERASE_BLOCK)
        )
        broken["mtd5"].erase(sim.FLAG_EB_LOCAL, sim.ERASE_BLOCK)
        run, bank = sim.run_restore_transaction(backup, bank=broken)
        self.assertIsNone(run.error)
        self.assertEqual(run.classification, "restore_verified_bank_pristine")
        self.assertTrue(run.all_verifies_green)
        self.assertEqual(
            bank["mtd5"].snapshot(), pristine["mtd5"].snapshot()
        )
        self.assertEqual(sim.flag_byte(bank), sim.FLAG_STOCK_REVERT)
        self.assertTrue(bank.stock_chain_pristine())
        self.assertTrue(bank["mtd4"].is_stock())
        self.assertIn("mtd5 byte-exact vs mtd5_pre_install.bin: True", run.notes)

    def test_restore_write_op_refuses_without_backup_artifact(self) -> None:
        bank = sim.build_pristine_bank()
        write_op = next(
            op
            for op in sim.restore_program()
            if op.op == "write" and op.length == sim.LINUX_PARTITIONS[5].size
        )
        ledger, error = sim._execute_ops(bank, (write_op,), b"", None)
        self.assertIsNotNone(error)
        self.assertIn("restore without a backup artifact", error)
        self.assertFalse(ledger[-1]["verified"])
        # nothing was written: the bank still equals a fresh pristine bank
        self.assertEqual(
            bank["mtd5"].snapshot(), sim.build_pristine_bank()["mtd5"].snapshot()
        )


class FaultMatrixTests(unittest.TestCase):
    """One power cut at every op boundary, classified against the atomicity
    model. Buckets: before_commit = still boots stock (flag untouched);
    inside_commit_window = flag EB erased/unverified, restore-from-backup;
    after_commit = DCENT boots."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.install_matrix = sim.install_fault_sweep()
        seed, _ = sim.committed_bank()
        cls.rollback_matrix = sim.rollback_fault_sweep()
        cls.restore_matrix = sim.restore_fault_sweep()

    def test_install_sweep_covers_every_op_boundary_plus_progress(self) -> None:
        program = sim.install_program(26_000_000)
        boundaries = {e["cut"] for e in self.install_matrix if isinstance(e["cut"], int)}
        self.assertEqual(
            sorted(boundaries), list(range(-1, len(program)))
        )
        progress = [e["cut"] for e in self.install_matrix if isinstance(e["cut"], str)]
        self.assertEqual(len(progress), 7)

    def test_install_sweep_classification_boundaries(self) -> None:
        by_cut = {e["cut"]: e for e in self.install_matrix}
        # window complete + readback verified, flag still 0x02: boots stock
        self.assertEqual(
            by_cut[13]["bucket"], "before_commit_boots_stock"
        )
        self.assertEqual(by_cut[13]["flag_byte"], "0x02_stock_revert")
        self.assertEqual(by_cut[13]["window_state"], "dcent-payload-verified")
        # commit pre-write read done: still before the flag erase
        self.assertEqual(by_cut[14]["bucket"], "before_commit_boots_stock")
        # the ONE ambiguous state: flag EB erased, not yet rewritten
        self.assertEqual(
            by_cut[15]["bucket"], "inside_commit_window_flag_erased"
        )
        self.assertEqual(by_cut[15]["flag_byte"], "erased_0xFF")
        # flag 0x01 written but unverified: conservatively inside the window
        self.assertEqual(
            by_cut[16]["bucket"], "inside_commit_window_flag_erased"
        )
        self.assertEqual(by_cut[16]["flag_byte"], "0x01_install_commit")
        # flag 0x01 written AND verified: DCENT boots
        self.assertEqual(by_cut[17]["bucket"], "after_commit_dcent_boots")
        # the empty cut: bank pristine
        self.assertEqual(by_cut[-1]["bucket"], "before_commit_boots_stock")
        self.assertEqual(by_cut[-1]["window_state"], "stock-bytes")

    def test_install_sweep_stock_chain_and_operator_actions(self) -> None:
        buckets = {}
        for entry in self.install_matrix:
            self.assertNotEqual(entry["bucket"], "rehearsal_failed", entry)
            self.assertTrue(
                entry["stock_chain_pristine_mtd0_3"],
                f"stock chain touched at cut {entry['cut']}",
            )
            self.assertTrue(entry["operator_action"])
            buckets[entry["bucket"]] = buckets.get(entry["bucket"], 0) + 1
        self.assertEqual(
            buckets,
            {
                "before_commit_boots_stock": 23,
                "inside_commit_window_flag_erased": 2,
                "after_commit_dcent_boots": 1,
            },
        )

    def test_intra_window_progress_cuts_still_boot_stock(self) -> None:
        progress = [e for e in self.install_matrix if isinstance(e["cut"], str)]
        self.assertEqual(len(progress), 7)
        for entry in progress:
            self.assertEqual(entry["bucket"], "before_commit_boots_stock", entry)
            self.assertEqual(entry["flag_byte"], "0x02_stock_revert", entry)
            self.assertIn("partial", entry["window_state"])

    def test_rollback_sweep_classifications(self) -> None:
        self.assertEqual(len(self.rollback_matrix), 9)
        for entry in self.rollback_matrix:
            self.assertNotEqual(entry["bucket"], "rehearsal_failed", entry)
            self.assertTrue(
                entry["stock_chain_pristine_mtd0_3"],
                f"stock chain touched at rollback cut {entry['cut']}",
            )
        by_cut = {e["cut"]: e for e in self.rollback_matrix}
        self.assertEqual(by_cut[-1]["flag_byte"], "0x01_install_commit")
        self.assertEqual(by_cut[3]["flag_byte"], "0x02_stock_revert")
        self.assertEqual(by_cut[6]["bucket"], "rollback_complete_stock_boots")
        self.assertTrue(by_cut[6]["mtd4_overlay_erased"])
        self.assertTrue(by_cut[6]["mtd5_system_erased"])
        self.assertEqual(by_cut[7]["bucket"], "rollback_complete_stock_boots")
        # mid-rollback flag window: erased flag, stock chain intact
        self.assertEqual(by_cut[1]["flag_byte"], "erased_0xFF")
        self.assertEqual(by_cut[1]["bucket"], "rollback_partial_stock_boots")

    def test_restore_sweep_is_always_rerunnable(self) -> None:
        self.assertEqual(len(self.restore_matrix), 6)
        for entry in self.restore_matrix:
            self.assertNotEqual(entry["bucket"], "rehearsal_failed", entry)
            self.assertTrue(
                entry["stock_chain_pristine_mtd0_3"],
                f"stock chain touched at restore cut {entry['cut']}",
            )
            if entry["mtd5_byte_exact"]:
                self.assertEqual(
                    entry["bucket"], "restore_verified_bank_pristine"
                )
            else:
                self.assertEqual(entry["bucket"], "restore_partial_rerunnable")
        by_cut = {e["cut"]: e for e in self.restore_matrix}
        self.assertFalse(by_cut[1]["mtd5_byte_exact"])
        self.assertTrue(by_cut[2]["mtd5_byte_exact"])
        self.assertEqual(by_cut[4]["flag_byte"], "0x02_stock_revert")


class CliTests(unittest.TestCase):
    def test_main_clean_exit_and_sentinel(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            rc = sim.main([])
        self.assertEqual(rc, 0)
        out = buffer.getvalue()
        self.assertIn("S19K_AML_FLASH_TRANSACTION_SIM_OK", out)
        self.assertIn("install: transaction_complete", out)
        self.assertIn("rollback: rollback_complete_stock_boots", out)
        self.assertIn("restore: restore_verified_bank_pristine", out)
        self.assertIn("clear_for_flash=false", out)

    def test_main_json_report_is_honest(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            rc = sim.main(["--json"])
        self.assertEqual(rc, 0)
        raw = buffer.getvalue()
        report = json.loads(raw[: raw.index("S19K_AML")].strip())
        self.assertEqual(
            report["transaction"], "mtd5_rootfs_window_flag_commit"
        )
        self.assertFalse(report["clear_for_flash"])
        self.assertTrue(report["simulation"])
        self.assertEqual(report["device_contact"], "none")
        self.assertFalse(report["authorizes_execution"])
        self.assertEqual(report["geometry"]["mtd5_base"], "0x6700000")
        self.assertEqual(report["geometry"]["window"]["erase_blocks"], 320)


if __name__ == "__main__":
    unittest.main()
