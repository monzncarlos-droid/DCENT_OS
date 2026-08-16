# ASIC Wire Contract (BM1396 family)

Status: `draft` 
Date: 2026-08-11 
Scope: Clean-room, externally observable BM1396 wire and carrier facts for offline planning only. 
Disposition: Does **not** authorize energization, rail mutation, work dispatch, or live carrier I/O.

This document is a redacted cousin of the detailed BM1396 protocol notes. It records framing, cold-start order, baud/FPGA selectors, work/nonce receive shapes, PIC behavioral ABI, and thermal-to-shutdown outcomes. Private reverse-engineering corpus paths, binary digests, lab host identifiers, and decompiler addresses are intentionally omitted.

## Confidence vocabulary

| Marker | Meaning |
|---|---|
| `CONFIRMED_MULTI_FIRMWARE` | Same behavior independently present in more than one exact signed production miner for the family |
| `CONFIRMED_STATIC_RE` | Behavior directly enforced by machine code in at least one exact signed model binary |
| `STRONGLY_INFERRED` | Consistent control-flow reading; not independently multi-firmware proven |
| `UNKNOWN` | Current exact-binary pass has not established the fact |

No item in this document is `CONFIRMED_HARDWARE`, `BENCH_VERIFIED`, `SOAK_VERIFIED`, or `PRODUCTION_CERTIFIED`.

## Wire identity

`CONFIRMED_MULTI_FIRMWARE`

- Register-zero response high word for this family is `0x1396`.
- Present-chain enumeration fails closed when the identity word mismatches or the required response count for the active model geometry is not met.
- Earlier `0x1397` identity claims belong to a different family/era and must not be substituted into BM1396 admission.

## Register command framing

`CONFIRMED_MULTI_FIRMWARE`

Commands below exclude any transport preamble. `chip_addr` is an 8-bit ASIC address, not a dense ordinal.

### Read register

| Field | Broadcast | Addressed |
|---|---:|---:|
| Header | `0x52` | `0x42` |
| Length | `0x05` | `0x05` |
| Payload | `chip_addr`, `reg_addr` | `chip_addr`, `reg_addr` |
| Trailer | CRC5 over the first 4 bytes | CRC5 over the first 4 bytes |

```text
[header, 0x05, chip_addr, reg_addr, crc5]
```

### Write register

| Field | Broadcast | Addressed |
|---|---:|---:|
| Header | `0x51` | `0x41` |
| Length | `0x09` | `0x09` |
| Payload | `chip_addr`, `reg_addr`, `value_be32` | `chip_addr`, `reg_addr`, `value_be32` |
| Trailer | CRC5 over the first 8 bytes | CRC5 over the first 8 bytes |

```text
[header, 0x09, chip_addr, reg_addr, value_be32[0..4], crc5]
```

### Command CRC5

`CONFIRMED_MULTI_FIRMWARE`

- Width: 5 bits
- Polynomial: `x^5 + x^2 + 1` (`0x05` feedback)
- Initial state: `0x1f`
- Bit order: MSB first
- Read coverage: first 4 bytes; write coverage: first 8 bytes
- Stored as the final command byte

This is the host-command CRC5. It must not be confused with any distinct modified response CRC5 state machine used by some BM13xx parsers.

## Model geometry (present-chain only)

`CONFIRMED_STATIC_RE` per model

Recovered functions operate on caller-selected active/present chains. They do not statically assert a fixed physical population of every FPGA chain slot.

| Model class | Required responses per present chain | Address interval | Address sequence |
|---|---:|---:|---|
| denser BM1396 board | 135 | 1 | `0, 1, ..., 134` |
| sparser BM1396 board | 78 | 3 | `0, 3, ..., 231` |

Rules that remain load-bearing for clean planners:

- Wrong identity or wrong count on a present chain is a hard enumeration failure.
- Missing/disabled slots are filtered by presence flags; do not fabricate failed populated chains.
- Initializers scan at most 16 FPGA chain slots and act only when `chain_exists` is set and detected-count is nonzero.
- Address-reset uses header `0x53` (three times, ~30 ms spacing); assignment uses header `0x40` with the same spacing for `floor(256 / interval)` ordinals.
- Assignment-command count can exceed the responding ASIC count and is not additional chain geometry.

## Cold-start and short-count recovery

`CONFIRMED_MULTI_FIRMWARE` within each release family; release/model differences are `CONFIRMED_STATIC_RE`.

High-level recovered spine (exact microsecond tables belong in implementation tests, not operator runbooks):

1. Assert present-chain FPGA bits and settle.
2. Enable DC/DC through PIC rail opcode `0x15` with payload enable.
3. Settle, clear chain bit, settle again, then enumerate.
4. On mismatch: reset the PIC/application path, reassert, and retry within a release-bounded attempt budget.
5. After terminal exhaustion: isolate the failed slot (disable rail, clear active flag, decrement active count) according to the release-scoped helper.
6. Some releases perform an inter-pass transition (voltage re-target, baud raise, frequency metadata update, second scan). Recording that spine does **not** authorize an executable rail or carrier path.

Vendor software board-voltage envelope recovered from the setters clamps requested board voltage to roughly 18.00-21.00 V. DCENT_OS records this as vendor policy only; it is not a bench-certified absolute safety envelope and does not authorize a live driver.

## Runtime PLL solver (pure plan)

`CONFIRMED_MULTI_FIRMWARE`

- Search order: `refdiv = [2, 1]`, then `postdiv2 = 1..7`, then `postdiv1 = postdiv2..7`.
- Feedback divider must round into 16..250.
- VCO must land in 2000..3200 MHz (tightened when `refdiv = 1`).
- Candidate must be strictly closer than the initial 10 MHz error; first search-order winner takes ties.
- Successful merge preserves a fixed mask and inserts postdiv/refdiv/fbdiv fields.
- Programmer targets PLL index registers, transforms the solved word, and broadcasts the identical value twice back-to-back with no inter-write delay or readback in stock.

DCENT_OS implements the pure double-write plan and represents solver failure as `None` so stock sentinel words cannot be programmed accidentally. Solver acceptance is not a certified safe ASIC output-frequency range.

## Baud transition and FPGA selector

`CONFIRMED_MULTI_FIRMWARE`

- Cold start always uses 115200 baud.
- Operational baud comes from configuration; stock miners do not embed a safe compiled operational default.
- At or below 3,000,000 baud, ASIC divisor uses a 25 MHz clock formula; above that, stock first programs a high-clock prelude pair of register writes, then uses a 400 MHz formula.
- ASIC baud register packing splits the BT8D field across two bit ranges with distinct preserve masks for low-clock vs high-clock paths.
- After the ASIC write, stock delays, then updates an FPGA MMIO selector that repeats a six-bit code in all four byte lanes while preserving a fixed mask.

Known mapped FPGA selectors include 115200, 1.5 M, 3 M, 6 M, 12 M, and 25 M baud. Stock accepts other configured baud rates for ASIC math but can fall back to the 115200 FPGA selector and desynchronize. Clean planners reject every unmapped baud instead of preserving that unsafe quirk.

## FPGA return, work-ready, and command ABI

`CONFIRMED_MULTI_FIRMWARE` for register access and control flow. Handler semantics attached to return bit 31 remain `STRONGLY_INFERRED` where noted.

Observable contract points:

- A return-path enable bit and a low-bit available-word count drive FIFO draining.
- Count `1` is rechecked; stuck observations reassert the enable bit. Count `>1` yields `count >> 1` records.
- Each record begins with a two-word read pair. A sentinel second word marks a two-word record; otherwise a second pair completes a four-word record.
- Word-1 bit 31 selects nonce vs register handler.
- Work-FIFO readiness is reported per chain slot with a bounded poll/delay loop.
- BC command register writes nonnegative words with one readback; negative words poll until nonnegative within a bounded iteration budget. Stock logs timeout without returning error.
- Job dispatch double-buffers external FPGA memory windows and publishes the selected address through MMIO. Scalar fields, version-lane mirrors, and packet words follow a recovered ordered spine.
- Clean planners admit only version-lane shapes 1/2/4/8, refuse truncated payloads, and require DDR/control checks that stock merely logs.

### Nonce and register receive records

`CONFIRMED_MULTI_FIRMWARE`

- FPGA return words are native little-endian u32 pairs.
- Eight-byte nonce record: validity/CRC/chain flags in byte 0; little-endian work id (low 15 bits used); full little-endian nonce in the last four bytes. Core id and wire chip address are taken from high nonce bits and converted through the model address interval with hard bounds.
- Eight-byte register record: chain/CRC flags, register address, chip address, CRC5, register type, and little-endian u32 value. Stock trusts FPGA CRC flags and does not recompute software CRC in these dispatchers.

### Outstanding-work binding (offline accounting only)

`CONFIRMED_MULTI_FIRMWARE` for host-side binding shapes; live publication remains closed.

- Returned work IDs are masked to 15 bits and select a fixed-size outstanding-work entry.
- A bounded host nonce ring receives an immutable logical record binding job id, work id, version, nonce fields, chain, and work-associated bytes.
- Consumers reject duplicates, apply a wrapping three-snapshot job-age test, and only then may reconstruct a target-qualified share for offline accounting.
- Local hash/power-of-two prefilter and full cloned-target comparison are recovered as stock semantics. Authenticated pool-response correlation and accepted-share authority are **not** granted by this contract.

## PIC command transport (behavioral)

`CONFIRMED_MULTI_FIRMWARE`

Generic framed transaction:

```text
[0x55, 0xaa, payload_len + 4, opcode, payload..., sum_hi, sum_lo]
```

- Additive `u16` checksum covers length, opcode, and payload (big-endian on the wire for this path).
- Chain slot selects I2C address `0x20 | (slot & 7)`; logical slot must be retained because slots separated by eight share the same seven-bit address.
- Some releases select among PIC implementation families via board-profile discriminators (not chain number and not a live silicon probe). Physical MCU part and host application ABI are orthogonal; both remain on the BM1396 framed contract.

Named behavioral operations (payloads are short; destructive typed constructors stay feature-gated in clean code):

| Operation | Opcode | Stock caller behavior (summary) |
|---|---|---|
| rail enable/disable | `0x15` | return often discarded; shutdown remains best-effort before GPIO cutoff |
| application reset | `0x07` | failure can clear/decrement the affected chain without global power-off |
| jump to app | `0x06` | stable across single-family and dual-family paths |
| version read | `0x17` | expects a short reply |
| heartbeat | `0x16` | success clears counter; failure only increments/logs in stock |

Stock heartbeat threads visit active slots on a multi-second cadence and have **no** failure threshold, rail cut, or recovery action. That is an observed stock weakness, not a DCENT safety recommendation.

Board-voltage transport uses a separate framed DAC write to a seven-bit application endpoint with additive checksum and bounded retransmit. Exact DAC conversion and stepped-write ordering are encoded in pure planners; rail mutation authority remains closed.

## Fan, thermal, and deterministic shutdown

`CONFIRMED_MULTI_FIRMWARE`

### Fan supervision

- Startup requires a minimum fan count at a high RPM threshold across a bounded sample budget.
- Runtime uses the same fan-count rule at a much lower RPM threshold.
- Exhaustion raises a fatal fan-loss code that enters the global shutdown path.
- Tach decode is FPGA-count based with a release-specific scale factor; one hardware-word sentinel selects a doubled scale.

### Thermal classification (inputs only where noted)

- Core-reopen eligibility requires PCB minimum above a low floor and chip maximum strictly below configured `Alarm_Temp`. Low PCB minima are classified invalid/too low. This recovers input classification, not an independent shutdown proof.
- Hard-monitor loops use absolute PCB/chip ceilings that tighten after a resettable runtime phase byte is set. Equality is admitted. This path does not use configured `Alarm_Temp`.
- Some older releases additionally compare sample-to-sample rise limits and route a distinct error code. Those deltas are not time-normalized C/s values and are not claimed as later-release parity.

### Fault router and ordered shutdown

Stock error routing globally cleans up / powers off / sleeps forever for a fixed set of fatal codes; a smaller set cleans up then asserts; a few codes return immediately. PIC-lost is notably non-global: the caller may disable/decrement one chain while the router does not globally power off.

Recurring per-active-chain register watchdog requires the same response count as cold enumeration. After a consecutive-mismatch budget, stock disables that chain's rail and clears its active flag with **no** re-enumeration.

Deterministic shutdown order recovered from stock:

1. Send rail-disable (`0x15` payload 0) to every slot whose runtime active flag is exactly 1.
2. Drive the stock power GPIO to the power-off polarity and wait.
3. Clear the FPGA main-control run-adjacent bit used in the stock shutdown path.

DCENT_OS encodes decision/order as a pure plan. A live executor remains closed with the carrier. Future recovery must be an explicit policy, not a misdescription of stock's permanent-disable behavior.

## Implementation boundary (clean room)

Pure, host-tested planners may encode:

- frame builders and CRC5;
- geometry/address mapping and fail-closed baud policy;
- startup/retry lifecycle without I/O;
- PIC framing and weak stock response acceptance without rail mutation;
- bounds-checked job parse, nonce/register decode, and offline work-binding;
- thermal/fan/fault classification without actuators.

Live driver registration, generic transport admission, work/version-rolling capability bits, and mining-default-on remain denied for this family until carrier and safety composition are admitted.

## Remaining contract gaps

These are **not** implied by identity/codec/geometry facts:

- PLL lock/readback validation, outer-ramp fault behavior, and an admitted output-frequency safety envelope
- carrier execution for the programmable-logic UART path and an explicitly configured admitted operational baud
- live FPGA buffer ownership/barriers, interrupt behavior, reset composition, ticket semantics, and an executor for the pure plan
- voltage rail enable/disable with certified limits and a fail-closed heartbeat threshold/recovery policy
- fan PWM/control-register mapping, an immutable independent thermal cutoff, sensor attribution, and fail-closed invalid-reading policy
- outstanding-work ID allocation/reuse and cache/completion barriers; authenticated pool-response correlation
- exact physical chain-slot population by board revision
- install, update, rollback, and recovery authority
- bench/soak/production certification

Until those gaps close, this contract authorizes offline parsing and planning only.

## Intentionally omitted

- Private evidence tables, binary digests, and reverse-engineering address maps
- Lab-unit identifiers, fleet IPs/MACs, and personal filesystem paths
- Dump embeds, unlock recipes, and release private-key paths
- Wi-Fi credentials, payout workers, and SSH material
- Live poke/energization recipes (offline parse/plan only)
