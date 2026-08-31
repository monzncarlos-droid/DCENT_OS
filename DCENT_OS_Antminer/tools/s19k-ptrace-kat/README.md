# S19k cross-ABI ptrace lifecycle KAT

Status: **offline source only; NO production authority**.

This standalone package tests the kernel-4.9 ptrace lifecycle contract needed before a
DCENT_OS handoff may rely on an ARMv7 tracer to hold both an AArch64 supervisor and its
multithreaded AArch64 child. It is deliberately separate from the production runner,
daemon, serial, restart, and custody code. The package never opens a device node, never
names or signals a stock mining process, and permits runtime files only below a fresh
private `/tmp/dcent-s19k-ptrace-kat.<alphanumeric>` root plus identity reads from `/proc`.

Nothing in this directory has been built or run as part of its initial creation. In
particular, no WSL, Docker, Cargo, QEMU, or miner execution has occurred. A source review
or successful build is not a kernel KAT and must not clear the J3 production .

## Artifacts

- `tracer`: ARMv7 musl static, raw-libc lifecycle-only ptrace client.
- `fixture`: AArch64 musl static, multithreaded supervisor and child with deterministic
  fork, vfork, clone, exec, and exit churn.
- `kat-manifest.json`: machine-readable scope and negative-authority declaration.
- `verify_elf.py`: stdlib-only host verifier for exact little-endian ELF32 ARM and
  ELF64 AArch64 headers/program-header tables; it rejects `PT_INTERP` and `PT_DYNAMIC`.
- `test_verify_elf.py`: synthetic positive and adversarial ELF fixtures for the parser.
- `build.sh`: pinned native-Windows Git-Bash two-architecture build, ELF/static
  verification, canonical source inputs, hashes, and an immutable
  `dist/kat-build.receipt`. It refuses WSL and containers.
- `run-target.sh`: target-side private-tmp harness with exact receipts for all three
  cases. It accepts only the two hash-bound artifact names beside the script.

## Ptrace contract under test

The tracer issues only `PTRACE_SEIZE`, `PTRACE_INTERRUPT`, `PTRACE_CONT`,
`PTRACE_DETACH`, and `PTRACE_GETEVENTMSG`. It does not read registers or tracee memory
and does not issue any peek, poke, or register request. Initial options are exactly
`TRACEFORK|TRACEVFORK|TRACECLONE|TRACEEXEC|TRACEEXIT`; `EXITKILL` is absent.

Every wait drain uses `waitpid(-1, ..., __WALL|WNOHANG)`. All internal deadlines use
Rust `Instant`; harness deadlines use the monotonic `/proc/uptime` counter. `/proc/TID/stat`
is split after the final `) ` before selecting remainder field 20, so spaces and right
parentheses in `comm` cannot shift `starttime`.

Acquisition and interruption enumerate `/proc/TGID/task/TID` to a double-stable
fixpoint. Every TID is rebound by TGID, starttime, executable device/inode/path,
cmdline root+nonce, and `TracerPid`. Fork/vfork/clone children are admitted only after
`GETEVENTMSG` and post-event `/proc` binding. Every event-message slot begins poisoned
and is surrounded by two `c_ulong` canaries, and the observed ARM32 `c_ulong` width plus canary result is
emitted in the receipts as a KAT outcome. The harness accepts a 32- or 64-bit observed
width only, requires consistency across cases, and requires every exercised canary to
remain intact.

## Cases and authority boundary

1. `events-freeze-detach-rollback-progress` proves every required lifecycle event,
   interrupts all TIDs to a stable fixpoint, detaches, double-snapshots `TracerPid=0`,
   and proves both tracees resume progress.
2. `precommit-tracer-death-without-exitkill` publishes an explicitly uncommitted lease
   receipt, externally kills the tracer, double-snapshots all tracee TIDs untraced, and
   proves both tracees continue. `EXITKILL` remains absent.
3. `committed-supervisor-first-kill-exit-drain-reap` first creates and syncs an exact
   commit receipt. Only after that publication does it deliver the supervisor's
   terminal action, drain group exit events/waits to original PID:start absence,
   revalidate the reparented child without a PPID assumption, then kill and reap the
   child.

The committed case tests ordering; it does not grant production authority. The fixture
contains no hardware, watchdog, UART, GPIO, NAND, service, or stock-process behavior.

## Coordinated build (not yet run)

Only after explicit coordination, from native Windows Git-Bash with the pinned Rust
targets installed:

```sh
cd tools/s19k-ptrace-kat
sh ./build.sh
```

The build refuses existing `target-kat` or `dist` directories so prior evidence cannot
be silently reused or overwritten. Cargo is forced offline, locked, and non-incremental.
The script resolves the bundled `rust-lld.exe` through the pinned sysroot, passes its
exact path for both targets, and binds its hash. Its receipt also binds the complete
canonical package source manifest, lockfile, verifier, toolchain/config, target-component
manifests, compiler identity, artifact hashes, and byte counts. The stdlib-only verifier
emits an exact receipt per ELF and rejects `PT_INTERP` and `PT_DYNAMIC`.

## Coordinated target KAT (not yet run)

Stage only these files into one newly created uid-0 mode-0700 root whose suffix is ASCII
alphanumeric:

```text
/tmp/dcent-s19k-ptrace-kat.<nonce>/tracer-armv7-static
/tmp/dcent-s19k-ptrace-kat.<nonce>/fixture-aarch64-static
/tmp/dcent-s19k-ptrace-kat.<nonce>/run-target.sh
```

Then pass the hashes from `kat-build.receipt`:

```sh
sh /tmp/dcent-s19k-ptrace-kat.<nonce>/run-target.sh \
  --root /tmp/dcent-s19k-ptrace-kat.<nonce> \
  --tracer-sha256 <64-lowercase-hex> \
  --fixture-sha256 <64-lowercase-hex>
```

The harness requires root, exact `aarch64` and `4.9.113`, `CAP_SYS_PTRACE`, and the held
absence of the Yama `ptrace_scope` surface. It verifies both hashes and ELF headers,
copies each binary into a separate 0700 case directory, and refuses any prior case or
results residue. Each Rust process independently requires its executable to be a
canonical direct child of that case directory. On success the top-level result is
`results/kat-summary.receipt`; all case receipts and logs remain under the private tmp
root for collection. A second run requires a new root, preventing absence-based reuse
of stale evidence.

## Acceptance rule

The J3 cross-ABI lifecycle prerequisite remains **** until a coordinated run on the
held kernel tuple produces all exact receipts, the artifact hashes match the offline
build receipt, the complete logs are collected, and an independent reviewer accepts
the results. Physical reset/rails, watchdog custody, UART endurance, accepted shares,
fault injection, cold initialization, and NAND boot/recovery remain separate live debts.
