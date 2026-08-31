# K210 digital capture artifact (`.k210cap` v1)

This is the canonical, bounded file format consumed by
`scripts/k210_capture_ingest.py`. It preserves operator-exported digital edges
for clean-room analysis without claiming that a K210 controller-to-ASIC wire
contract has been established.

The tool and format are host-only. They contain no hardware, network, serial,
USB, GPIO, flash, JTAG, ISP, or transmit path. A valid artifact proves file
integrity and deterministic normalization only. Identity and authorization
fields are operator declarations, not cryptographic attestations; signed
capture admission remains a separate gauntlet step.

## Inputs and bounds

- One or two regular, non-symlink Saleae digital CSV exports, each at most
  256 MiB. A mapped signal must occur in exactly one input.
- One UTF-8 `k210-capture-map-v1` JSON file containing exactly `format`,
  `channels`, and `provenance`.
- At most 262,144 normalized edge events, 4,096 canonical provenance bytes,
  4,096 canonical channel-map bytes, and ten documented signal names.
- Time is parsed as bounded decimal seconds and normalized to integer
  picoseconds. Floating-point parsing is never used.
- Simultaneous opposite-direction edges are rejected because their causal
  order is not observable. Restated levels are removed; actual edges remain.

Allowed signal names and directions are documentary probe-orientation facts:

- controller to ASIC: `CI`, `DI`, `RI`, `CKI`, `FBDI`
- ASIC to controller: `CO`, `DO`, `RO`, `CKO`, `FBDO`

No opcode, frame layout, register map, or electrical-level claim follows from
these names.

## Binary layout

All integers are little-endian. The header is exactly 128 bytes:

| Offset | Size | Field |
|---:|---:|---|
| `0x00` | 8 | ASCII magic `DK210CAP` |
| `0x08` | 2 | version (`1`) |
| `0x0a` | 2 | header length (`128`) |
| `0x0c` | 4 | event count |
| `0x10` | 4 | provenance JSON length |
| `0x14` | 4 | channel-map JSON length |
| `0x18` | 8 | capture end, elapsed picoseconds |
| `0x20` | 8 | declared sample rate in hertz |
| `0x28` | 1 | source CSV count (`1` or `2`) |
| `0x29` | 1 | signal count |
| `0x2a` | 2 | reserved, zero |
| `0x2c` | 32 | logical SHA-256 digest |
| `0x4c` | 52 | reserved, zero |

The header is followed by canonical ASCII JSON for provenance, canonical ASCII
JSON for the channel map, and fixed 16-byte event records. Each event is
`u64 elapsed_ps`, `u8 signal_index`, `u8 level`, then six zero reserved bytes.
Events are sorted by `(elapsed_ps, signal_index)`, alternate level per signal,
and may not extend beyond the declared capture end.

Both JSON blocks use sorted keys, no insignificant whitespace, ASCII escapes,
and no duplicate keys. Decoding re-encodes and byte-compares them so alternate
serializations are refused.

## Logical digest

The digest is SHA-256 over the domain
`DCENT-K210-DIGITAL-CAPTURE-V1\0`, followed by the version, event count,
capture end, signal count, length-prefixed canonical provenance, length-prefixed
canonical channel map, and every logical event as `u64/u8/u8`. Header padding
and per-event reserved bytes must independently be zero.

This digest detects accidental or adversarial file modification. It is not a
signature and does not authenticate the operator, unit, revision, stock build,
or authorization reference.

## Commands and claim boundary

`ingest` creates a new artifact without overwriting; `validate` rechecks every
invariant; `inventory` prints indexed events; `extract` copies a contiguous
range to another strictly verified artifact; and `stats` emits bounded
descriptive clock/burst/alignment statistics.

Every command retains these conclusions:

- `wire_contract_claimed=false`
- `authorizes_transmit=false`
- `authorizes_device=false`

Only a separately authorized, exact-revision capture campaign and the clean-
room admission process in `K210_WIRE_CONTRACT_ASSET_CENSUS.md` may advance the
ASIC-protocol lane.
