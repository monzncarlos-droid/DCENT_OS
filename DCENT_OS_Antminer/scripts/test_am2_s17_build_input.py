#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
WORKSPACE = SCRIPT_DIR.parents[2]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


closure = _load("s17_source_closure_test", SCRIPT_DIR / "source_closure.py")
snapshot = _load("s17_build_input_snapshot_test", SCRIPT_DIR / "build_input_snapshot.py")


class S17BuildInputTests(unittest.TestCase):
    def _donor_directory(self, root: Path) -> Path:
        directory = root / ""
        directory.mkdir(parents=True)
        return directory

    def test_exact_held_donor_is_the_only_s17_build_input(self) -> None:
        evidence = closure.build_input_evidence(
            WORKSPACE,
            str(SCRIPT_DIR / "build_inputs.manifest"),
            "am2-s17pro",
        )
        self.assertEqual([closure.AM2_S17_DONOR_RELATIVE_PATH], [item["path"] for item in evidence["files"]])
        self.assertEqual(closure.AM2_S17_DONOR_SHA256, evidence["files"][0]["sha256"])
        self.assertEqual(closure.AM2_S17_DONOR_SIZE, evidence["files"][0]["size"])
        self.assertNotIn("am2-s17pro", closure.BLOCKED_BUILD_INPUT_TARGETS)

    def test_private_snapshot_contains_one_read_only_canonical_donor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            created = snapshot.create_snapshot(
                WORKSPACE,
                SCRIPT_DIR / "build_inputs.manifest",
                "am2-s17pro",
                stage_parent=Path(directory),
            )
            try:
                descriptor = snapshot.verify_snapshot(created.snapshot, "am2-s17pro")
                self.assertEqual(1, len(descriptor["files"]))
                item = descriptor["files"][0]
                self.assertEqual(closure.AM2_S17_DONOR_RELATIVE_PATH, item["path"])
                staged = created.stage.joinpath(*Path(item["staged_path"]).parts)
                self.assertEqual(closure.AM2_S17_DONOR_SHA256, item["sha256"])
                if os.name == "posix":
                    self.assertEqual(0, os.lstat(staged).st_mode & stat.S_IWUSR)
            finally:
                snapshot.destroy_snapshot(created.snapshot, created.destroy_token)

    def test_missing_donor_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._donor_directory(root)
            with self.assertRaisesRegex(closure.ClosureError, "missing"):
                closure.discover_am2_s17_donor(root)

    def test_wrong_donor_hash_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            donor = self._donor_directory(root) / Path(closure.AM2_S17_DONOR_RELATIVE_PATH).name
            # Preserve the admitted byte length so this exercises the digest
            # pin rather than receiving an earlier size-only refusal.
            with donor.open("wb") as stream:
                stream.truncate(closure.AM2_S17_DONOR_SIZE)
            with self.assertRaisesRegex(closure.ClosureError, "size/SHA256 mismatch"):
                closure.discover_am2_s17_donor(root)

    def test_symlinked_donor_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            donor_directory = self._donor_directory(root)
            target = donor_directory / "not-a-donor.bin"
            target.write_bytes(b"not a donor")
            donor = donor_directory / Path(closure.AM2_S17_DONOR_RELATIVE_PATH).name
            try:
                donor.symlink_to(target.name)
            except OSError as error:
                self.skipTest(f"symlink creation is unavailable: {error}")
            with self.assertRaisesRegex(
                closure.ClosureError, "symlink|reparse"
            ):
                closure.discover_am2_s17_donor(root)

    def test_ambiguous_donor_candidates_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            donor_directory = self._donor_directory(root)
            (donor_directory / "braiins-os_am2-s17_sd.img").write_bytes(b"candidate one")
            (donor_directory / "braiins-os_am2-s17_sd-copy.img").write_bytes(b"candidate two")
            with self.assertRaisesRegex(closure.ClosureError, "ambiguous"):
                closure.discover_am2_s17_donor(root)

    def test_other_target_input_policies_and_container_env_are_unchanged(self) -> None:
        self.assertEqual(
            (
                "",
                "",
            ),
            closure.TARGET_BUILD_INPUTS["s9"],
        )
        expected_s19 = (
            "",
            "",
        )
        for target in ("am2-s19jpro", "am2-s19jpro-sd", "am2-s19pro"):
            self.assertEqual(expected_s19, closure.TARGET_BUILD_INPUTS[target])

        driver = (SCRIPT_DIR / "build_in_docker.sh").read_text(encoding="utf-8")
        self.assertIn('AM2_S17_DONOR_ENV_ARGS=()', driver)
        self.assertIn(
            '-e "DCENT_AM2_S17_BRAIINS_SD_IMAGE=/dcent-inputs/files/${AM2_S17_DONOR_RELATIVE_PATH}"',
            driver,
        )
        self.assertIn('"${DOCKER_BUILD_INPUT_STAGE}:/dcent-inputs:ro"', driver)
        self.assertNotIn("DCENT_AM2_S17_KERNEL", driver)
        self.assertNotIn("DCENT_AM2_S17_VENDOR_ARCHIVE", driver)
        self.assertIn("S17 package-only manifest must declare installable=false", driver)
        self.assertIn("S17 package-only manifest must not advertise Toolbox commands", driver)


if __name__ == "__main__":
    unittest.main()
