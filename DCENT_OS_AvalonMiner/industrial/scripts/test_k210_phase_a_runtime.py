"""ELF and source-boundary tests for the K210 Phase-A runtimes."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
FIRMWARE = SCRIPT_DIR.parent / "k210-firmware"
TARGET_DIR = FIRMWARE / "target" / "riscv64gc-unknown-none-elf" / "release"
BUILDER_PATH = SCRIPT_DIR / "build_k210_candidate.py"
sys.path.insert(0, str(SCRIPT_DIR))
spec = importlib.util.spec_from_file_location("k210_candidate_builder", BUILDER_PATH)
builder = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["k210_candidate_builder"] = builder
spec.loader.exec_module(builder)


class PhaseARuntimeTests(unittest.TestCase):
    def _audit(self, binary_name: str) -> tuple[Path, dict[str, object]]:
        path = TARGET_DIR / binary_name
        self.assertTrue(path.is_file(), f"build exact target first: {path}")
        facts = builder.inspect_k210_elf(path.read_bytes())
        executable = [
            segment
            for segment in facts["load_segments"]
            if segment["flags"] & 1
        ]
        self.assertEqual(len(executable), 1)
        self.assertEqual(executable[0]["virtual_address"], "0x0000000080000000")
        self.assertGreater(executable[0]["file_size"], 0)
        self.assertFalse(any(
            segment["flags"] & 1 and segment["flags"] & 2
            for segment in facts["load_segments"]
        ), "runtime must not contain a writable executable PT_LOAD")
        self.assertTrue(any(
            segment["flags"] & 2 and segment["memory_size"] >= 16 * 1024
            for segment in facts["load_segments"]
        ), "runtime must reserve a writable 16 KiB stack PT_LOAD")
        return path, facts

    def _instructions(
        self, elf: Path, facts: dict[str, object]
    ) -> list[tuple[int, int]]:
        executable = next(
            segment for segment in facts["load_segments"] if segment["flags"] & 1
        )
        self.assertEqual(
            executable["file_size"] % 4,
            0,
            "physical runtime disables RVC so every instruction is auditable",
        )
        data = elf.read_bytes()
        start = executable["file_offset"]
        end = start + executable["file_size"]
        address = int(executable["virtual_address"], 16)
        return [
            (address + offset * 4, int.from_bytes(data[index:index + 4], "little"))
            for offset, index in enumerate(range(start, end, 4), start=0)
        ]

    def _assert_control_target_in_text(
        self, address: int, immediate: int, text_start: int, text_end: int
    ) -> None:
        target = address + immediate
        self.assertGreaterEqual(target, text_start)
        self.assertLess(target, text_end)
        self.assertEqual(target % 4, 0)

    @staticmethod
    def _sign_extend(value: int, width: int) -> int:
        sign = 1 << (width - 1)
        return (value ^ sign) - sign

    def _raw(self, elf: Path) -> bytes:
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "runtime.bin"
            subprocess.run(
                [str(builder.find_llvm_objcopy()), "-O", "binary", str(elf), str(output)],
                check=True,
            )
            return output.read_bytes()

    def test_physical_runtime_has_one_entry_segment_and_zero_console_payload(self) -> None:
        path, facts = self._audit("dcent-k210-safe-idle-runtime")
        raw = self._raw(path)
        executable = next(s for s in facts["load_segments"] if s["flags"] & 1)
        elf = path.read_bytes()
        expected_prefix = elf[
            executable["file_offset"]:
            executable["file_offset"] + executable["file_size"]
        ]
        self.assertTrue(raw.startswith(expected_prefix))
        self.assertIn(
            b"DCENT-K210 PHASE-A ZERO-MMIO NON-INSTALLABLE v1\n", raw
        )
        self.assertNotIn(b"DCENT-K210 RENODE", raw)

        source = (FIRMWARE / "src" / "bin" / "safe_idle_runtime.rs").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("bsp::UARTHS_BASE", source)
        self.assertNotIn("write_volatile", source)
        self.assertNotIn("0x3800_0000", source)

    def test_physical_runtime_instruction_set_cannot_address_board_mmio(self) -> None:
        path, facts = self._audit("dcent-k210-safe-idle-runtime")
        instructions = self._instructions(path, facts)
        text_start = instructions[0][0]
        text_end = instructions[-1][0] + 4
        allowed_system = {
            0x3004_7073,  # csrci mstatus, 8
            0x3040_1073,  # csrw mie, zero
            0x3440_1073,  # csrw mip, zero
            0x3052_9073,  # csrw mtvec, t0
            0xF140_22F3,  # csrr t0, mhartid
            0x1050_0073,  # wfi
        }
        stores: list[int] = []

        for address, instruction in instructions:
            opcode = instruction & 0x7F
            if opcode == 0x73:
                self.assertIn(instruction, allowed_system)
            elif opcode == 0x23:
                stores.append(instruction)
                self.assertEqual(instruction, 0x0002_B023, "only sd zero, 0(t0) is allowed")
            elif opcode == 0x17:  # AUIPC: every derived base must remain in cached SRAM.
                upper = self._sign_extend(instruction & 0xFFFF_F000, 32)
                derived = address + upper
                self.assertGreaterEqual(derived, 0x8000_0000)
                self.assertLess(derived, 0x8060_0000)
            elif opcode == 0x63:  # conditional branch
                immediate = (
                    ((instruction >> 31) & 0x1) << 12
                    | ((instruction >> 7) & 0x1) << 11
                    | ((instruction >> 25) & 0x3F) << 5
                    | ((instruction >> 8) & 0xF) << 1
                )
                self._assert_control_target_in_text(
                    address,
                    self._sign_extend(immediate, 13),
                    text_start,
                    text_end,
                )
            elif opcode == 0x6F:  # JAL used only for local loops.
                immediate = (
                    ((instruction >> 31) & 0x1) << 20
                    | ((instruction >> 12) & 0xFF) << 12
                    | ((instruction >> 20) & 0x1) << 11
                    | ((instruction >> 21) & 0x3FF) << 1
                )
                self._assert_control_target_in_text(
                    address,
                    self._sign_extend(immediate, 21),
                    text_start,
                    text_end,
                )
            else:
                self.assertEqual(opcode, 0x13, "only bounded integer ADDI is allowed")

        self.assertEqual(stores, [0x0002_B023], "BSS clear is the sole memory write")

    def test_renode_console_is_a_separate_explicit_emulator_payload(self) -> None:
        path, facts = self._audit("dcent-k210-renode-console")
        raw = self._raw(path)
        self.assertIn(b"DCENT-K210 RENODE safe-idle v1\n", raw)
        self.assertTrue(any(s["flags"] == 4 for s in facts["load_segments"]))

    def test_candidate_builder_cannot_select_the_renode_binary(self) -> None:
        builder_source = BUILDER_PATH.read_text(encoding="utf-8")
        self.assertIn("dcent-k210-safe-idle-sentinel", builder_source)
        self.assertNotIn("dcent-k210-renode-console", builder_source)
        self.assertNotIn("dcent-k210-safe-idle-runtime", builder_source)


if __name__ == "__main__":
    unittest.main()
