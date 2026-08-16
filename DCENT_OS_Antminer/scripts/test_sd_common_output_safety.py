#!/usr/bin/env python3
"""Host-only regressions for SD builder output/source identity safety."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
COMMON = SCRIPT_DIR / "lib" / "sd_common.sh"
S17_S19_BUILDER = SCRIPT_DIR / "build_sd_s19pro.sh"
S19J_BUILDER = SCRIPT_DIR / "build_am2_s19jpro_sd_disk_image.sh"


class SdCommonOutputSafetyTests(unittest.TestCase):
    def bash(self) -> str:
        if os.name == "nt":
            candidate = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git/bin/bash.exe"
            if candidate.is_file():
                return str(candidate)
        shell = shutil.which("bash") or shutil.which("sh")
        if shell:
            return shell
        self.skipTest("POSIX shell unavailable")

    def invoke(self, output: Path, source: Path) -> subprocess.CompletedProcess[str]:
        program = (
            'source "$1"; '
            'sd_common::refuse_unsafe_output_alias "$2" "$3"'
        )
        return subprocess.run(
            [self.bash(), "-c", program, "test", COMMON.as_posix(), output.as_posix(), source.as_posix()],
            capture_output=True,
            check=False,
            text=True,
        )

    def test_direct_and_resolved_aliases_refuse_without_source_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "donor.img"
            original = b"held donor bytes survive"
            source.write_bytes(original)
            (root / "nested").mkdir()
            for output in (source, root / "nested" / ".." / source.name):
                with self.subTest(output=output):
                    result = self.invoke(output, source)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("aliases protected source", result.stderr)
                    self.assertEqual(source.read_bytes(), original)

    def test_hardlink_alias_refuses_without_source_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "rootfs.squashfs"
            output = root / "output.img"
            original = b"rootfs bytes survive"
            source.write_bytes(original)
            os.link(source, output)
            result = self.invoke(output, source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("multiply-linked output", result.stderr)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(output.read_bytes(), original)

    def test_hardlink_to_unlisted_file_is_also_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            protected_source = root / "declared-input.img"
            unrelated = root / "operator-data.bin"
            output = root / "output.img"
            protected_source.write_bytes(b"declared input")
            original = b"unrelated operator bytes survive"
            unrelated.write_bytes(original)
            os.link(unrelated, output)

            result = self.invoke(output, protected_source)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("multiply-linked output", result.stderr)
            self.assertEqual(unrelated.read_bytes(), original)
            self.assertEqual(output.read_bytes(), original)

    def test_symlink_output_refuses_without_target_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.img"
            target = root / "unrelated-target.img"
            output = root / "output.img"
            source.write_bytes(b"source")
            target.write_bytes(b"target survives")
            try:
                output.symlink_to(target)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"host cannot create symlinks: {exc}")
            result = self.invoke(output, source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlink output", result.stderr)
            self.assertEqual(target.read_bytes(), b"target survives")

    def test_builders_guard_outputs_before_truncating_writes(self) -> None:
        shared = COMMON.read_text(encoding="utf-8")
        self.assertIn("SD_COMMON_VERSION=4", shared)
        self.assertIn("sd_common::refuse_unsafe_output_alias()", shared)

        builder = S17_S19_BUILDER.read_text(encoding="utf-8")
        self.assertLess(
            builder.index('refuse_unsafe_output_alias "$SD_IMAGE"'),
            builder.index('dd if=/dev/zero of="$SD_IMAGE"'),
        )
        self.assertIn('refuse_unsafe_output_alias "$SD_IMAGE.manifest.json"', builder)

        builder = S19J_BUILDER.read_text(encoding="utf-8")
        self.assertLess(
            builder.index('refuse_unsafe_output_alias "$IMG_FILE"'),
            builder.index('sd_common::create_blank_image "$IMG_FILE"'),
        )
        self.assertIn('refuse_unsafe_output_alias "$IMG_FILE.manifest.json"', builder)


if __name__ == "__main__":
    unittest.main()
