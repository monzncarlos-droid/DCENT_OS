# Stock Parity Behavior (Thermal, Fan, Fault Outcomes)

Status: `draft` 
Date: 2026-08-11 
Scope: Cross-generation stock outcome contracts for thermal, fan, and fault handling that DCENT_OS must not accidentally "improve away" without an explicit policy. 
Disposition: Offline parity notes. **No live poke recipes.**

## Purpose

Stock Antminer generations share family resemblances (tach scaling, PWM packing, PIC rail disable, DHASH/run-bit cuts, fatal routers) but differ in thresholds, debounce counts, actuator order, and which thread performs which cut. This document captures **outcome-level** parity expectations across control-board generations so clean planners can replay vendor behavior without importing the wrong release's oracle.

Parity here means: given an exact profile tag and a pure observation, the planner's classification and ordered cut plan should match that profile's stock outcomes. It does **not** mean "copy any sibling binary," and it does not authorize field poking.

## Confidence vocabulary

| Marker | Meaning |
|---|---|
| `CONFIRMED_STATIC_RE` | Exact named release binary behavior |
| `CONFIRMED_MULTI_FIRMWARE` | Same outcome class across multiple exact binaries |
| `CONFIRMED_CAPTURE` | Live/passive capture corroboration |
| `PRIMARY_SOURCE` | Bitmain-derived primary source structure (outranked by exact binaries when they disagree) |
| `POLICY` | DCENT hardening on top of stock |
| `NOT_PARITY` | Explicitly not claimed across generations |

## Cross-generation outcome map

### Fan tach decode

| Generation / profile | Tach scale | FIFO / sweep shape | Minimum working fans (stock-like) | Confidence |
|---|---|---|---|---|
| Ordinary S9 stock-flat (non-R4 intent) | `raw * 120` | two windows of eight reads; IDs may repeat | ≥2 active identities | `PRIMARY_SOURCE` + `CONFIRMED_CAPTURE` |
| S9j exact recovery release (e531 class) | `raw * 120` | two sweeps of eight; presence sticky across calls | <2 identities is fatal criterion | `CONFIRMED_STATIC_RE` |
| S17e/T17e BM1396 production | count-based; optional doubled scale on HW sentinel | up to eight observations; startup vs runtime RPM floors differ | startup high-RPM floor (≥4 fans @ high threshold); runtime lower floor | `CONFIRMED_MULTI_FIRMWARE` |
| Clean-image UIO S9 | distinct ABI (per-lane PWM/tach registers) | not stock FAN_SPEED FIFO | board-specific; do not import stock identity counts | `CONFIRMED_CAPTURE` / `POLICY` |

Parity rule: **never** combine clean-UIO tach lanes with stock FAN_SPEED identity counting without an exact carrier discriminator.

Additional tach outcome notes:

- Stock identity-presence arrays may be sticky across calls while min/max RPM accumulators clear each call.
- Connector ID sets vary by unit; hardcoding a single pair of IDs is incorrect.
- Startup RPM floors and runtime RPM floors are different contracts on BM1396-era production miners.

### PWM packing

Stock-flat S9-class FAN_CONTROL uses a 50-tick packing after a vendor clamp (commonly 20..100%):

```text
high = floor(percent / 2)          # equivalent form: floor(percent * 50 / 100)
low  = floor((100 - percent) / 2)
word = (high << 16) | low
```

Outcome parity: encoded halves are each ≤50 and sum to 50 (even %) or 49 (odd %). Reading a live word proves syntax, not connector wiring or stall safety.

Representative encodings used in offline tests (not live recipes): 20%, 28%, 88%, 100% pack to distinct 50-tick words. Earlier notes that treated the low half as an independent scale misread the packing.

BM1396-era production fan validators emphasize tach presence/RPM floors more than this S9 PWM word in the recovered safety path; do not assume one PWM register map across CB gens.

### Temperature acquisition outcomes

| Topic | S9j e531-class | Ordinary S9 stock | BM1396 S17e/T17e-class |
|---|---|---|---|
| Local/PCB decode | `raw - 64` | family intent via ASIC-I2C; FPGA temp words not passive-safe | channel transforms with model bins; invalid positions can isolate chains |
| Remote/junction | calibrated affine; telemetry, not hard-cut input in examined funcs | mutating acquisition; not read-only preflight | chip max used in reopen/hard-monitor policies |
| Freshness | failed local read keeps cache and forces full fan; not DCENT freshness | stale/missing must not admit work (`POLICY`) | invalid samples marked; all-invalid can isolate |
| Hard cutoff input | independent hard-protect local/PCB ≥90 C | exact ordinary July-2019 boundary **not** certified here | absolute PCB/chip ceilings (phase-dependent); distinct from `Alarm_Temp` reopen |

`NOT_PARITY`: importing e531's 90 C hard-cut + PIC-then-DHASH order into ordinary S9 or into BM1396 monitors without exact evidence.

Curve-shape caution:

- S9j e531 uses a local/PCB curve with floor, hysteresis, and full-fan break points that are release-scoped.
- Fixture/jig miners may share FIFO/PWM syntax but use different curves and permissive identity checks.
- BM1396 hard-monitor ceilings tighten after a resettable phase byte; equality passes; configured `Alarm_Temp` is a different policy input.

### Fault debounce and reported reason

- S9j e531 supervisor: second consecutive bad cycle latches fatal; healthy cycle clears unlatched counter. When overtemperature and fan-loss coincide, overtemperature is the reported reason.
- Ordinary S9: primary source shows multi-conditional family intent; exact debounce for the missing ordinary binary remains bench-required.
- BM1396 production: fan exhaustion and hard-monitor ceilings route through a global fatal router; PIC-lost is a notable non-global exception.
- Some older BM1396-era releases add sample-to-sample rise limits with a distinct error code; that is not claimed as later-release parity.

### Actuator order on cut

| Profile | Observed / recovered order | Notes |
|---|---|---|
| S9j e531 hard-protect | disable each present-chain PIC DAC, then clear DHASH RUN bit | supervisor fatal path is PIC-only (no DHASH call in that function) |
| Ordinary S9 family intent | PIC disable + DHASH paths exist in source | exact ordinary binary order not closed |
| BM1396 production shutdown | rail-disable all active slots → GPIO power-off polarity → clear FPGA main-control bit | deterministic; recovery/re-enumeration not performed by watchdog |

`POLICY` for DCENT home mode: cut hash power before raising noise when possible; fan blast is reserved for measured thermal need after power cut or when immediate airflow is the only safe response. That is a DCENT philosophy layered **on top of** stock parity, not a claim that stock did the same.

## Control-board generation notes

### AM1 / Zynq S9 stock-flat

- Carrier identity needs board target + hardware-word class + char-device/geometry/DMA tuple.
- Passive preflight may read version/tach/PWM words only; it must not write PWM, IIC, work, DMA, or DHASH.
- Temperature acquisition is mutating shared broadcast/IIC state and is outside read-only preflight.
- Two watchdogs exist: PIC rail heartbeat vs Zynq host watchdog. Servicing one never proves the other.
- Retained fabric ownership must cover registers, DMA, fan, IIC/PIC, thermal supervision, and DHASH together.

### AM1 clean UIO

- Different register map and ownership model from stock-flat.
- One physical fan connector mapping to tach lanes is board-specific.
- Stock e531 or ordinary stock-flat fan minima must not be relabeled as clean-image policy.
- Quiet-home PWM floors still require separate tach/RPM evidence because low PWM can sit on a loud physical floor on some boards.

### AM2 / BM1396-era Zynq

- Present-chain geometry and identity word gate enumeration.
- Fan/thermal fatal codes enter a shared router with an ordered rail/GPIO/FPGA shutdown plan.
- Heartbeat threads may log without cutting rails; clean planners must not treat that weakness as a safety feature.
- Domain-voltage and auto-adapt tables are model/release-scoped; cross-producting denser vs sparser boards is forbidden.
- Recurring register watchdogs disable chains without re-enumeration after consecutive mismatches.

### Amlogic / later generations

- Management fabric (PSU/LM75/fan) ownership and GPIO energization order are product-specific.
- Stock parity claims from Zynq S9/S17 documents do not transfer by connector resemblance alone.
- Native NoPic routes require SKU-qualified identity + topology before management-fabric construction.
- Inlet/outlet coverage requirements are product policy, not S9 stock parity.

## Outcome contracts DCENT pure planners should expose

Without granting actuators:

1. **Classify** fan identity sets, RPM floors, and PWM encodings for the exact profile tag.
2. **Classify** temperature samples as fresh/stale/invalid and compute vendor-observed demand curves only when the profile is exact.
3. **Emit** ordered cut plans that match the profile's stock order for replay/diff tests.
4. **Refuse** cross-profile inputs (e531 observation fed to ordinary-S9 matcher, clean-UIO fed to stock-flat matcher, etc.).
5. **Never** return a live receipt from forgeable offline assessment APIs.
6. **Separate** reopen-eligibility inputs from absolute hard-monitor ceilings when stock does.

## Explicit non-goals

- Step-by-step live fault injection recipes
- Register poke sequences for field technicians
- Competitor unlock or signature-bypass instructions
- Pooling of private capture dumps or unit serials
- Claiming production certification from offline parity alone
- Promoting jig/fixture curves into production profiles

## Bench-validation queue (evidence classes only)

These are measurement goals, not poke scripts:

1. Bind exact firmware/module/FPGA/fan/sensor tuples before promoting any threshold.
2. Witness fan-loss and overtemperature coincidence ordering per profile.
3. Witness boundary temperatures adjacent to each profile's hard cut (profile-specific).
4. Prove PIC heartbeat loss and host watchdog reset as independent outcomes.
5. Prove crash/kill teardown cuts load and permits only one clean reacquisition.
6. Prove stall-versus-missing-tach distinctions where the profile claims them.
7. Prove latch/restart behavior after temperatures fall without inventing auto-clear if stock latches.

## Confidence summary

| Claim | Marker |
|---|---|
| Stock-flat vs clean-UIO fabrics are incompatible oracles | `POLICY` + capture |
| S9j e531 thermal/fan outcomes are release-scoped | `CONFIRMED_STATIC_RE` |
| Ordinary S9 exact thermal oracle still open | `UNKNOWN` (matcher offline only) |
| BM1396 fan/hard-monitor/shutdown router outcomes | `CONFIRMED_MULTI_FIRMWARE` |
| DCENT cut-hash-before-noise | `POLICY` (not stock parity) |
| Jig/fixture curves are not production oracles | `POLICY` |

## Related contracts

- `S9J_E531_STOCK_THERMAL_FAN_CONTRACT.md` - exact S9j release oracle
- `S9_ORDINARY_STOCK_CARRIER_THERMAL_PREFLIGHT.md` - ordinary S9 offline envelope
- `ASIC_WIRE_CONTRACT.md` - BM1396 fan/thermal/shutdown spine
- `HASHBOARD_IDENTITY.md` - profile tags that select which oracle applies

## Intentionally omitted

- Live register-poke recipes and executable MMIO sequences
- Private binary paths, SHA digests of private corpora, and Ghidra addresses
- Lab unit IDs, fleet IPs/MACs, and personal filesystem paths
- EEPROM/key material, Wi-Fi credentials, and payout workers
- Competitor unlock/sig-bypass steps and Konduit never-publish claims
