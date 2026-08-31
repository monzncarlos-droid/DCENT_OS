"""Zig CC wrapper for K230 RISC-V Linux cross-compile (industrial Avalon).

Twin of `DCENT_OS_AvalonMiner/home/zig-cc-riscv64.py` — kept per-workspace per
the existing dcentos/zig-cc-{arm,aarch64} pattern instead of symlinked, so the
two Avalon projects can pin different toolchains independently if ever needed.
"""
import os
import pathlib
import subprocess
import sys

ZIG_DIR = pathlib.Path(r"C:\zig-0.13.0")
ZIG = ZIG_DIR / "zig.exe"

env = os.environ.copy()
env["ZIG_LIB_DIR"] = str(ZIG_DIR / "lib")

args = []
for arg in sys.argv[1:]:
    if arg.startswith("--target="):
        continue  # Strip cc-rs target, zig uses its own
    if arg.startswith("-march="):
        continue  # Strip -march, zig handles arch via -target
    args.append(arg)

cmd = [str(ZIG), "cc", "-target", "riscv64-linux-gnu"] + args
sys.exit(subprocess.call(cmd, env=env))
