# DCENT Avalon K210 core

This is the clean `no_std` policy core for the active Avalon K210 firmware
lane. It compiles on the host for tests and for
`riscv64gc-unknown-none-elf`, the closest built-in Rust target to the K210 ISA.

The default library is intentionally **not bootable firmware**. Three explicit
binary surfaces exist, and none is install-authorized:

- `dcent-k210-safe-idle-sentinel` proves the existing ELF/raw/AUP pipeline.
- `dcent-k210-safe-idle-runtime` is the Phase-A physical-runtime baseline. It
  links at `0x80000000`, initializes a 16 KiB stack, clears BSS, disables
  interrupts, installs a local trap vector, parks hart 1, and leaves hart 0 in
  `WFI`. It contains no MMIO, console, Avalon pin, flash, PSU, cooling, or ASIC
  operation. Its raw image embeds the boundary marker
  `DCENT-K210 PHASE-A ZERO-MMIO NON-INSTALLABLE v1`.
- `dcent-k210-renode-console` is a separately feature-gated emulator payload.
  It emits one fixed beacon through Renode's modeled UARTHS and then parks. The
  physical candidate builder cannot select this binary.

No target contains a flash writer, network client, board-bound Avalon BSP,
ASIC driver, cooling driver, PSU driver, GPIO operation, sensor path, or actuator API. The
physical binaries cannot assert fans or hash-power off and are not physically
safe to install. Exact board boot behavior, eFuse/decrypt policy, peripheral
maps, and safety polarity must come from admitted exact-unit evidence.

The current core provides:

- the same ordered ten-gate vocabulary as the host production gauntlet;
- deterministic evidence-ledger and first-blocker computation;
- explicit distinction between physical models, candidates, and firmware
  families;
- an ordered recovery-first runtime phase machine;
- a board-agnostic safety supervisor that requires injected, model-bound limits,
  nonzero and distinct reviewed-profile/session digest joins, fresh watchdog/
  temperature/cooling/cutoff/hash-power feedback, independent monotonic
  sequence and CLINT-tick progression, and both a minimum sample count and an
  injected minimum healthy time span; it latches the first fault, is
  deliberately non-clonable, and can reach only independent review;
- an unrepresentable hardware-allow result: every mutation request is refused
  until a later target-bound crate supplies independently reviewed authority;
- exported, allocation-free K210 Phase-A register facts for SYSCTL, UARTHS,
  GPIOHS, FPIOA, CLINT, and WDT0/1, plus a sealed board profile that grants no
  MMIO or actuation authority.

Build and test:

```bash
cargo +1.90.0 test --locked \
  --manifest-path DCENT_OS_AvalonMiner/k210-firmware/Cargo.toml
cargo +1.90.0 build --release \
  --locked \
  --manifest-path DCENT_OS_AvalonMiner/k210-firmware/Cargo.toml \
  --target riscv64gc-unknown-none-elf \
  --no-default-features \
  --features phase-a \
  --bin dcent-k210-safe-idle-runtime
cargo +1.90.0 build --release \
  --locked \
  --manifest-path DCENT_OS_AvalonMiner/k210-firmware/Cargo.toml \
  --target riscv64gc-unknown-none-elf \
  --no-default-features \
  --features renode-console \
  --bin dcent-k210-renode-console
py -3 -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_phase_a_runtime.py -q
```

A green build means only that the policy core, register facts, and desk
pipeline are internally consistent. Use `../scripts/build_k210_candidate.py`
only for audited non-installable sentinel construction. It cannot package the
Renode payload or turn Phase A into install authority. None of this qualifies
the `replacement_firmware` production gate.

`test_k210_phase_a_runtime.py` audits the final physical ELF, not just Rust
source: W^X load segments, fixed-width RV64 instructions, the exact CSR
allowlist, SRAM-only address derivation, local-only control flow, and one sole
memory store (`sd zero, 0(t0)`) for BSS clearing. These are negative host
guarantees; they do not prove that an A1246 can boot the image or that its hash
and cooling domains are safe.
