"""Zig CC wrapper for K230 RISC-V Linux MUSL cross-compile.

Strips --target / -march flags added by cc-rs and substitutes
`-target riscv64-linux-musl`, matching the Rust target
`riscv64gc-unknown-linux-musl`.

Why musl (2026-08-14): the gnu/glibc wrapper (`zig-cc-riscv64.py`) is
blocked on this host — zig 0.13.0 on Windows cannot assemble the glibc
riscv startup files (`sysdeps/riscv/start-2.33.S: unknown directive`),
even against a complete zig lib tree. The musl lane compiles cleanly
(zig vendors musl fully) and yields a fully static binary that runs on
the K230's glibc rootfs — the same static-musl posture the Antminer
dcentrald builds use (`armv7-unknown-linux-musleabihf`).

Mirrors `zig-cc-arm.py` — same ZIG_LIB_DIR work-around for zig 0.13
subprocess resolution failures.
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

cmd = [str(ZIG), "cc", "-target", "riscv64-linux-musl"] + args
sys.exit(subprocess.call(cmd, env=env))
