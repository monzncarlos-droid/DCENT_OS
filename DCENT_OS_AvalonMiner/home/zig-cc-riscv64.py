"""Zig CC wrapper for K230 RISC-V Linux cross-compile.

Strips --target / -march flags added by cc-rs and substitutes
`-target riscv64-linux-gnu`, matching the Rust target
`riscv64gc-unknown-linux-gnu` declared in rust-toolchain.toml.

Mirrors `DCENT_OS_Antminer/dcentrald/zig-cc-arm.py` — same ZIG_LIB_DIR
work-around for zig 0.13 subprocess resolution failures (FileNotFound on
"unable to find zig installation directory" without it).
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
