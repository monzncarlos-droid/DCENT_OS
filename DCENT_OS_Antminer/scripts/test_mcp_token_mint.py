#!/usr/bin/env python3
"""Host tests for mcp_server.py --mint-token (no hardware, no server start)."""

from __future__ import annotations

import importlib.util
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OVERLAYS = (
    ROOT
    / "br2_external_dcentos/board/zynq/rootfs-overlay/root/web/mcp_server.py",
    ROOT
    / "br2_external_dcentos/board/amlogic/rootfs-overlay/root/web/mcp_server.py",
)


def load_mcp(path: Path):
    spec = importlib.util.spec_from_file_location("dcentos_mcp_server", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load %s" % path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class MintTokenTests(unittest.TestCase):
    def test_both_overlays_mint_without_starting_server(self) -> None:
        for overlay in OVERLAYS:
            with self.subTest(overlay=str(overlay)):
                self.assertTrue(overlay.is_file(), overlay)
                mod = load_mcp(overlay)
                self.assertTrue(hasattr(mod, "mint_release_tokens"))
                secret = mod.generate_release_token()
                self.assertGreaterEqual(len(secret), 32)
                self.assertTrue(all(c in "0123456789abcdef" for c in secret))
                with tempfile.TemporaryDirectory() as tmp:
                    token, written = mod.mint_release_tokens(tmp, overwrite=False)
                    self.assertEqual(len(token), 64)
                    self.assertEqual(len(written), 3)
                    names = {Path(p).name for p in written}
                    self.assertEqual(names, {"mcp_token", "grpc_token", "mqtt_token"})
                    for path in written:
                        data = Path(path).read_text(encoding="ascii").strip()
                        self.assertEqual(data, token)
                        mode = stat.S_IMODE(os.stat(path).st_mode)
                        # Windows may not keep 0600; Unix overlays must.
                        if os.name != "nt":
                            self.assertEqual(mode, 0o600)
                    with self.assertRaises(FileExistsError):
                        mod.mint_release_tokens(tmp, overwrite=False)
                    again, _ = mod.mint_release_tokens(
                        tmp, overwrite=True, token="a" * 32
                    )
                    self.assertEqual(again, "a" * 32)

    def test_main_mint_token_exits_without_bind(self) -> None:
        overlay = OVERLAYS[0]
        # Exercise the CLI: --mint-token must not serve :3000.
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [
                    sys.executable,
                    str(overlay),
                    "--mint-token",
                    "--token-dir",
                    tmp,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("Minted RELEASE write tokens", proc.stdout)
            self.assertIn("NOT started", proc.stdout)
            self.assertTrue((Path(tmp) / "mcp_token").is_file())
            self.assertNotIn("serve_forever", proc.stdout)


if __name__ == "__main__":
    unittest.main()
