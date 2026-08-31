# dcent-avalon-proto

Canaan Avalon protocol primitives shared by D-Central's two Avalon firmware projects:

- **`DCENT_OS_AvalonMiner/home/`** — DCENT_axe Avalon (Nano 3 / Nano 3S / Mini 3 home line, K230 RISC-V Linux)
- **`DCENT_OS_AvalonMiner/`** — DCENT_OS Avalon (A14xx / A15xx / A16xx / Avalon Q industrial, K230 + K210)

## Modules

| Module        | Purpose                                                                     |
|---------------|-----------------------------------------------------------------------------|
| `mm_pkg`      | 268-byte SysV-msgq packet shared by Linux little core and RT-Smart big core |
| `aup`         | AUP firmware container parser (industrial K210, home K230 — same shape)     |
| `ascset`      | CGMiner port-4028 `ascset|0,...` command vocabulary (12 public + 15 privileged) |
| `nano3_profile` | Explicit identity-only profile for the original non-S Nano 3             |
| `nano3_uart`  | Strict receive-envelope, nonce, and summary-status decoding                  |
| `nano3_uart_rx` | Bounded stream resynchronization and structural nonce admission           |
| `nano3_uart_tx` | Feature-gated sealed reconstruction of the proven non-S init/job/share contract; live TX and submission fail closed |
| `nano3_uart_transcript` | Transport-free validation plus strict raw-chunk assembly and bounded canonical `.n3cap` encode/decode; returns evidence, never TX authority |
| `transport`   | Linux SysV msgq wrapper over `libc::msgsnd` / `msgrcv` (Unix only)          |

## Offline Nano 3 Saleae conversion

The `nano3-n3cap` binary converts two operator-exported Saleae Async Serial CSV
files from the same `.sal` archive into one canonical `.n3cap` artifact. It is
file-only: input paths must be regular non-symlink files, the output must be a
new `.n3cap` path, Windows device namespaces/names are rejected, and the binary
contains no serial, USB, network, process-control, or transmit path.

```text
cargo run --features nano3-capture-cli --bin nano3-n3cap -- assemble-saleae \
  --source-capture capture.sal \
  --host-to-controller host.csv \
  --controller-to-host controller.csv \
  --capture-end-s 12.500000 \
  --time-semantics start \
  --data-radix hex \
  --output capture.n3cap

cargo run --features nano3-capture-cli --bin nano3-n3cap -- verify \
  --input capture.n3cap

cargo run --features nano3-capture-cli --bin nano3-n3cap -- inventory \
  --input capture.n3cap

cargo run --features nano3-capture-cli --bin nano3-n3cap -- extract \
  --input capture.n3cap \
  --first-event 0 \
  --event-count 7 \
  --output init.n3cap

cargo run --features nano3-capture-cli --bin nano3-n3cap -- validate-init \
  --input init.n3cap \
  --requested-work-level 2

cargo run --features nano3-capture-cli --bin nano3-n3cap -- validate-poll \
  --input poll.n3cap
```

`--capture-end-s` must be the analyzer stop time in the same clock as both CSV
exports. Choose `start` only when the selected CSV time column marks each byte's
start; the converter adds the fixed 115200-baud 8N1 byte duration. Choose `end`
only for a byte-completion column. The command prints hashes for the source
archive, both exact CSV exports, and the artifact, but the operator's claim that
the CSVs came from that archive is not cryptographically bound into `.n3cap`.
`inventory` prints zero-based event indices, direction, timestamp, envelope
metadata, and a frame hash without dumping payload bytes. `extract` copies one
explicit contiguous event range into a new canonical artifact and binds the
source/output hashes in its receipt. A range reaching the final source event
preserves the authentic source capture end. Every non-final range ends exactly
at its last retained frame, so it deliberately carries no post-frame silence
and cannot manufacture timeout evidence; an excluded event at the same
microsecond is refused. Windows device namespaces and reserved names are
rejected for every input and output role.
`validate-init` proves the exact retry/ack-derived work-level/post-sync contract;
`validate-poll` proves response timing or the complete five-attempt timeout and
reports stateful selector/status observations without authorizing them. Each
semantic command requires an artifact scoped to exactly one exchange and
rejects trailing events. Conversion and validation do not authorize attaching
an analyzer, contacting hardware, or transmitting.

## License & sourcing

GPL-3.0. Translated from these clean sources (no BUSL or proprietary code copied verbatim):

- `mm_pkg` — translated from `cg_miner/mm_miner.h` in `Canaan-Creative/Avalon_Nano3s` (BSD-2 file in a GPLv2-derivative repo; its in-file header carries exactly the two BSD clauses, no endorsement clause).
- `aup` — translated from `fmsc/aupparser.py` in `Canaan-Creative/fms-core` (Apache-2.0 Kaitai schema).
- `ascset` — extracted from the public A10 Universal API manual in `Canaan-Creative/avalon10-docs` plus 15 privileged commands surfaced in the Flutter source of `Canaan-Creative/avalon_family`.
- `transport` — implements the standard SysV `msgsnd` / `msgrcv` ABI; no Canaan code touched.

`Canaan-Creative/Avalon_mm` is **BUSL-1.1** (non-commercial, cliffs to GPLv3 in 2029) — used as RE reference only, never copied..

## Build

```sh
cd shared/dcent-avalon-proto
cargo test                 # host-target protocol tests
cargo test --features nano3-native-tx-research  # bounded offline TX-component tests
cargo test --all-features      # includes file-only capture CLI tests
cargo check --target riscv64gc-unknown-linux-gnu --features nano3-capture-cli
cargo check --target riscv64gc-unknown-linux-musl --features nano3-capture-cli
```

## Support development

Support open-source Bitcoin mining firmware through the
[D-Central Open Source Bitcoin Mining Fund](https://d-central.tech/fund/).

## Cross-references

- — full 6-generation protocol reference
- — IPC discovery (§5)
- — AUP container (§1-3)
- — privileged ascset extraction (§1)
- — K230 SoC specifics
