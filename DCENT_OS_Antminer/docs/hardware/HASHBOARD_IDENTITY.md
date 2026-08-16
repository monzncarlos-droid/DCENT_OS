# Hashboard Identity Contract

Status: `draft` 
Date: 2026-08-11 
Scope: Fail-closed identity for Zynq-era and AM2/AM3 hashboards used by DCENT_OS. 
Disposition: Offline admission rules only. No EEPROM secrets, no operator serials, no live mutation.

## Purpose

Hashboard admission must answer three questions before any voltage, reset, UART, or ASIC mutation is contemplated:

1. What **family** of silicon and connector protocol is present?
2. What **board product** (name/SKU/profile) is declared and observed?
3. Do at least **two independent sources** agree before the board is admitted?

A preamble byte pair, a marketing label, or a single EEPROM field is never sufficient identity by itself.

This contract exists because earlier defects showed that short headers and reused catalog labels can authorize the wrong rail, reset, or work codec. DCENT_OS therefore treats identity as a typed proof object, not a string equality check.

## Confidence vocabulary

| Marker | Meaning |
|---|---|
| `CONFIRMED_PRODUCT` | Bound in catalog/`BoardDesc` and enforced by offline tests |
| `CONFIRMED_CAPTURE` | Observed on held units/captures without claiming universal population |
| `CONFIRMED_STATIC_RE` | Recovered from exact signed firmware behavior |
| `POLICY` | Explicit DCENT fail-closed rule, not a vendor guarantee |
| `UNKNOWN` | Not established; admission must refuse |

No item here is production-certified solely by documentation.

## Preamble is not identity

`POLICY` / `CONFIRMED_PRODUCT`

Multiple AM2 EEPROM/board preambles look similar across products. Historical defects showed that treating a short preamble as an exact ASIC or SKU proof authorized the wrong voltage/reset/UART path.

Hard rules:

- EEPROM preamble bytes are **hints**, not ASIC family proof.
- Catalog labels such as "S19 Pro class" or "BHB56 class" are not live ChipID proof.
- `BoardDesc` declared ASIC protocol, observed ChipID family, and engine-required family must **exactly agree** before specialized runtime minting.
- When any source is missing, stale, or contradictory, return `NOT IMPLEMENTED` / refuse admission **before** hardware construction.
- Presence of an EEPROM device on a slot proves an endpoint may exist; it does not prove voltage class, PIC firmware class, or work codec.

Examples of non-identity (do not elevate):

- short EEPROM header fields reused across unrelated boards
- board-name substrings in updater filenames
- auto-adapt profile route integers that select PIC implementation families
- comparative hardware-version words from a different control-board generation
- "same 18-pin connector" folklore without a typed route proof

## Board-name and profile discriminators

`CONFIRMED_PRODUCT`

Admission prefers typed discriminators over free text:

| Discriminator | Role | Fail-closed note |
|---|---|---|
| Declared board target (`am1-s9`, `am2-*`, `am3-*`, …) | Product route | Unknown/empty target refuses |
| `AsicProtocolIdentity` / ChipID family | Silicon family | Must match declared and required |
| Control-board observation label | Carrier class (Zynq AM1/AM2, Amlogic, …) | Producer/consumer labels must converge |
| Hashboard profile / EEPROM class (when present) | Board revision family | Presence ≠ voltage authority |
| Chain geometry expectations | Present-chain count/interval | Model-scoped; do not cross-product |
| Fabric ownership model | Stock-flat vs clean UIO vs hybrid | Competing fabrics refuse each other |
| Controller session class | PIC / dsPIC / NoPic | Observed firmware class where required |

Board-name strings may be logged for operators, but parsers must map them through an exact allowlist. Fuzzy substring matching across generations is prohibited.

### Discriminator anti-patterns

- Accepting `am2-s19pro` management-only boards into a BM1398 mining path without a protocol/work/address plan
- Relabeling NoPic hardware as PIC-managed because an older catalog comment said so
- Using recovery-image board names from a sibling SKU to admit a production route
- Treating stock-flat hardware-version low bytes as sufficient without the co-observed artifact/geometry tuple

## Factory voltage / frequency hints

`CONFIRMED_STATIC_RE` where recovered; otherwise `UNKNOWN`

Factory or auto-adapt tables may publish:

- preferred operating frequency bands
- PCB-temperature-indexed voltage targets
- calibration anchors and stepped-write ordering
- vendor software clamps (for example BM1396-era board envelopes near 18-21 V)

Treat these as **vendor policy evidence** for pure planners:

- Hints never bypass independent thermal/fan safety.
- Hints never authorize energization solely because a table cell exists.
- Cross-model matrices (denser vs sparser boards, earlier vs later releases) are not interchangeable.
- Clean code refuses calibration outside proven anchors even when stock extrapolates.
- Frequency metadata updates in stock bring-up are not proof that a PLL write occurred.
- Stepped DAC ordering recovered from stock is a replay artifact, not a live write permit.

### How hints may be used safely

1. Tag every table with exact model/release/profile scope.
2. Feed only pure planners and offline tests.
3. Require a separate safety admission (thermal/fan/lease) before any future executor discussion.
4. Keep mining-default-off for families whose live driver remains unregistered.

## Two-source admission (fail closed)

`POLICY`

A board may be admitted for a mutating route only when **two independent sources** agree on the load-bearing identity fields for that route.

### Minimum pairs (illustrative)

| Route intent | Source A | Source B | On mismatch |
|---|---|---|---|
| Native ASIC bring-up | Declared `BoardDesc` protocol | Live ChipID family window | Refuse before open |
| AM2 hybrid / PIC routes | Topology + observed controller session | Exact endpoint/firmware class | Refuse cold boot |
| Amlogic NoPic | SKU-qualified identity | UART slot/path + populated-slot topology | Refuse service construction |
| Stock-flat carrier preflight | Declared board target + HW word class | Char-device/geometry/DMA tuple | Offline match only; no live receipt |
| Clean-image UIO runtime | Clean fabric UIO set | Native runtime admission | Stock-flat modules refuse |

### Independence requirements

Sources count as independent only when they do not collapse to the same bytes:

- Declared catalog fields and a second copy of the same catalog fields are one source.
- EEPROM preamble and a filename derived from that preamble are one source.
- ChipID live window and a cached ChipID from a previous boot are one source unless freshness/session binding is proven.

### Non-sources (never count as one of the two)

- marketing SKU from packaging
- operator-entered serial stickers
- comparative digests from a different product's recovery image
- passthrough/external-init rumors without a typed handoff
- single preamble equality checks
- community forum board photos

## ChipID family detect (identity surface only)

`CONFIRMED_PRODUCT`

Broad Zynq-era auto-detection uses ChipID-style family words (examples include BM1387-era, BM1396-era, BM1397-era, BM1398-era, and later Amlogic-era IDs). Same connector and UART framing across many units does **not** imply a blanket production-install promise for mixed control-board/hash-board rigs.

Rules:

- Family detect selects a driver **candidate**, not a mining permit.
- Mixed rigs remain lab-validated route work until the exact tuple is certified.
- Experimental families require exact observed ID policy and stay non-default.
- Address assignment plans are model-scoped; a family word alone does not pick interval/geometry.

## Control-board versus hashboard identity

`POLICY`

Control-board detection and hashboard detection are orthogonal:

| Plane | Proves | Does not prove |
|---|---|---|
| Control board | SoC class, fabric map, fan/PSU topology | ASIC family on the cable |
| Hashboard | Silicon family, geometry, controller class | Clean vs stock fabric on the CB |
| Combined route | Exact supported tuple | Future unlisted mixes |

A valid AM2 control board plus an unexpected hashboard must fail closed rather than "best effort" mining.

## What this document never contains

- EEPROM/XXTEA key material or unlock recipes
- operator or factory serial numbers
- payout worker names, pool credentials, or Wi-Fi secrets
- private reverse-engineering corpus paths or binary SHA inventories
- Ghidra/function addresses
- live unit hostnames, fleet IPs, or SSH material
- raw EEPROM dumps

## Worked refusal scenarios

1. **Preamble-only S19-class claim** - preamble matches a known header, ChipID absent → refuse before voltage.
2. **Catalog BM1366 with NoPic evidence** - contradictory controller class → remove unreachable PIC owners; native path stays `NOT IMPLEMENTED` until a complete NoPic plan exists.
3. **Stock-flat modules on clean image** - competing fabric → refuse stock preflight and refuse native if modules stole the aperture.
4. **Ordinary S9 thermal borrowed from S9j** - sibling artifact → reject as thermal oracle.
5. **Passthrough "already init"** - no typed handoff → refuse native mutation and do not mint mining permits.

## Confidence and gaps

Known solid:

- preamble ≠ identity (`POLICY`, regression-pinned)
- exact protocol admission requiring board/config/observed agreement (`CONFIRMED_PRODUCT`)
- competing fabric refusal (stock-flat vs clean UIO) (`CONFIRMED_PRODUCT` / capture-backed)
- management-only boards must not inherit mining drivers by launcher accident (`CONFIRMED_PRODUCT`)

Open:

- exhaustive physical chain-slot population by every board revision
- complete factory V/F table certification per SKU
- production matrix for every mixed CB/HB combination
- durable crash-surviving identity journals across A/B slot transitions
- authenticated mapping from every field EEPROM class to voltage authority

Until open items close, identity mismatch fails closed and mining stays off.

## Related contracts

- `ASIC_WIRE_CONTRACT.md` - family wire facts after identity is admitted
- `BOOT_AND_RUNTIME_SURFACE.md` - fabric ownership and native vs passthrough
- `STOCK_PARITY_BEHAVIOR.md` - thermal/fan outcome parity across generations

## Intentionally omitted

- EEPROM/XXTEA key hex, key-version blobs, and unlock/write recipes
- Factory or operator serials, lot KATs, and dump tables
- Private RE corpus paths, binary digests, and Ghidra addresses
- Fleet/lab unit IDs, hostnames, IPs, and personal filesystem paths
- Wi-Fi credentials, payout workers, SSH material, and release private-key paths
