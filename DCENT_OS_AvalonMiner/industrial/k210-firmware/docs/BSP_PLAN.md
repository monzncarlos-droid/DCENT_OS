# K210 BSP plan — SoC driver layer and board-bound interface contract

Status: **host-only plan with Phase-A desk implementation**. The exported BSP
contains public K210 register facts and a sealed profile; the physical runtime
performs zero MMIO, while a differently named Renode-only binary owns the sole
console beacon. Exact-unit discovery still must fill every Avalon-specific
assignment below. This work records no hardware contact, advances no gauntlet
gate, and authorizes no probe, write, power, cooling, hashing, or release
action.

Prepared for the `dcent-avalon-k210-core` lane. The library exports
`src/bsp/` but remains hardware-free, `#![forbid(unsafe_code)]`,
zero-dependency, and GPL-3.0-only. Any future board-bound MMIO implementation
belongs behind admitted profile/receipt joins and a separately reviewed,
confined register-access boundary.

## Evidence basis (all public sources, pinned)

| ID | Source | License | Used for |
|----|--------|---------|----------|
| S1 | `kendryte/kendryte-standalone-sdk` @ `02576ba67e8797444f3ee3f34c625b5ed048e707` — `lib/bsp/include/platform.h`, `lib/drivers/include/*.h`, `lib/drivers/{sysctl,wdt}.c`, `lds/kendryte.ld` | Apache-2.0 (Copyright 2018 Canaan Inc.) | Register bases, FPIOA function table, clock tree, WDT math, linker layout |
| S2 | `kendryte/kendryte-doc-datasheet` `en/003.md` (official datasheet, Functional Description) | public documentation | SRAM split/banks, CPU/PLL facts, peripheral inventory, ROM boot behavior, OTP/AES/SHA256 |
| S3 | `laanwj/k210-sdk-stuff` `doc/memory_map.md` (community RE, cross-checked against S1 + ROM dump) | public (reference only, nothing copied) | Full address decode incl. non-cached mirror, boot/ISP sequence, non-cached FP-load gotcha |
| S4 | crates.io API (2026-08-23) | per crate | Rust crate versions + license metadata |
| S5 | `riscv-rust/k210-pac` master (authors' `k210.svd`, vendor "Canaan Inc."; `memory-k210.x`) | ISC | SVD availability, 4-region memory layout cross-check |
| S6 | `riscv-rust/k210-hal` master (module list, `Cargo.toml`) | ISC | Rust HAL coverage/gaps |
| W | This workspace: `DCENT_OS_AvalonMiner/ (K210 gauntlet sections), `gauntlet/K210_{DISCOVERY,REPLACEMENT}_RECEIPTS.md`, `scripts/build_k210_candidate.py`, `k210-firmware/*` | GPL-3.0-only | Policy/safety contracts, receipt requirements, build pipeline |

## 0. Verified SoC facts that shape this plan

Correction to a common assumption (the mission brief asked to verify): the
8 MiB SRAM is **6 MiB general-purpose SRAM + 2 MiB AI SRAM**, not the
inverse (S2 §SRAM; S1 `platform.h` `RAM_SIZE = 6 MiB`, `AI_RAM 2 MiB`).

- **CPU**: two independent RV64GC (IMAFDC) cores, nominal 400 MHz (S2;
  the SDK's compiled-in default is 390 MHz — S1 `sysctl.c` `cpu_freq`).
  Per-core 32 KiB I-cache and 32 KiB D-cache, per-core FPU. The cores are
  **independent SMP-style cores, not lockstep** — PLIC routing is per-core
  and CLINT provides cross-core software interrupts (S2). Never present
  dual-core as a safety redundancy; independence must not be assumed for
  coverage either.
- **Boot**: ROM (128 KiB @ `0x88000000`) copies the application from SPI
  flash to SRAM at `0x80000000`, verifies SHA-256, optionally decrypts
  AES-128-CBC, then jumps (S2 §ROM, S3). ISP ("UOP") mode exists over the
  ISP UART at 115200. Strap `IO_16` selects FLASH vs ISP boot; after reset
  `IO_0..IO_3` are JTAG and `IO_4/IO_5` are ISP UART (S3 quoting the
  datasheet; also recorded in workspace boot-policy receipt vocabulary).
  OTP bits can disable UOP/SHA256/AES (S2) — the exact eFuse/force-decrypt
  posture of any Avalon unit stays **unmeasured** until a
  `boot_policy_receipt` says otherwise (W).
- **Clock tree** (S1 `sysctl.h/.c`): PLL0/PLL1/PLL2; `ACLK = PLL0 /
  (2 << aclk_threshold)` or external `IN0`; CPU/HCLK/DMA/FFT sit on ACLK;
  SRAM0/SRAM1/ROM and APB0/1/2 peripherals are gated, divided children of
  ACLK. `SYSCTL` exposes readable `git_id` and `clk_freq` (base clock)
  registers — record both in every boot log as silicon-revision evidence.
- **FPIOA** (S1 `fpioa.h`, S2): 48 IO pins, 255 selectable functions;
  **every** peripheral signal reaches a pad only through FPIOA. Per-pin
  drive strength (8 steps), pull-up/down, Schmitt trigger, slew rate.
  Function codes relevant to us: `GPIOHS0..31` = 24..55,
  `GPIO0..7` = 56..63, `UART1_RX/TX` = 64/65, `SPI1_*` = 70..75, etc.
- **Interrupts**: PLIC @ `0x0C000000`, 7 priority levels, per-core claim
  (S2). Source IDs used below (S1 `plic.h`): UART1/2/3 = 11/12/13,
  TIMER0A/B..TIMER2A/B = 14..19, WDT0/WDT1 = 21/22, APB GPIO = 23,
  DMA0..5 = 27..32, UARTHS = 33, GPIOHS0..31 = 34..65.
- **CLINT** @ `0x02000000`, SiFive-compatible: `msip` core N @
  `0x02000000 + 4*N`, `mtimecmp` core N @ `0x02004000 + 8*N`, shared
  `mtime` @ `0x0200BFF8` (S1 `clint.h`, S3). This is the monotonic tick
  the safety supervisor needs.
- **SPI3 is the flash controller**: masters are SPI0/SPI1/SPI3, SPI2 is
  slave-only (S2 §SPI). SPI3 (regs `0x54000000`, space to `0x56000000`
  per S3) is quad/octal-frame capable, 32-byte FIFO, DMA, ≤100 MHz
  (datasheet "TBC"), and is the controller wired to boot NOR flash on
  reference boards (Sipeed documents SPI3 as flash-reserved; workspace
  `kflash`/AUP wrapper analysis agrees). The block is a Synopsys
  DWC_ssi: it has XIP mode registers (`xip_mode_bits`, `xip_incr_inst`,
  `xip_wrap_inst`, `xip_ctrl`, `xip_ser`, `xip_cnt_time_out`), and the
  datasheet states "SPI3 supports XIP" — but **no XIP direct-map window
  appears in any published K210 address map**, and neither Kendryte SDK
  ships a runtime flash driver (checked standalone + FreeRTOS trees).
  Conclusion for this plan: phase B flash access is **manual SPI3
  command/read**; XIP is an unmeasured optimization we do not rely on.
- **Watchdogs**: exactly two, WDT0 `0x50400000` and WDT1 `0x50410000`,
  DW-WDT register set (`cr`, `torr`, `ccvr`, `crr`, interrupt-then-reset
  response mode), APB1 domain with independent clock-enable and divider
  (`SYSCTL_THRESHOLD_WDT0/1`), reset scope `RESET_ALL` vs `RESET_CPU`,
  pause mode and accidental-disable protection (S1 `wdt.h/.c`, S2 §WDT).
  There is no third WDT in the timer block.
- **DMA**: 6 channels (S1 `dmac.h`) — the datasheet's "up to eight" is IP
  capability, not this instantiation; use 6. Per-channel PLIC IRQs,
  handshake peripheral selection via `SYSCTL dma_sel0/1` (S1).
- **Hardware crypto exists**: SHA256 accelerator @ `0x502C0000`
  (DMA-capable input) and AES @ `0x50450000` (ECB/CBC/GCM, 128/192/256
  keys, DMA) (S2, S1 headers). OTP @ `0x50420000` is 128 Kbit with 64
  `REGISTER_ENABLE` flags and a write-only AES-key area — **never written
  by DCENT firmware**; reads only, and only after discovery review.

## 1. SoC driver inventory

Phases: **A** = sealed physical safe-idle runtime plus separate emulator-only
console (neither installable), **B** = flash/OTA staging, **C** = ASIC transport
(only after an admissible K210 wire contract exists — none does today),
**D** = safety wiring. "Route" states how Rust code is obtained; see the
license subsection below.

| # | Driver | SoC facts (S1/S2) | Public-source basis (license) | Rust integration route | Phase |
|---|--------|-------------------|-------------------------------|------------------------|-------|
| 1 | Startup / trap / CSR / PLIC / CLINT | ROM enters `0x80000000`; CLINT/PLIC maps above | own `global_asm!` (exists in sentinel); `riscv` crate 0.16.1 (MIT OR Apache-2.0) optional for CSR typed access | **own** — keep the sentinel's minimal asm entry; do **not** adopt `riscv-rt` (its single-hart model, `[0.8]` in k210-pac vs `[0.18]` current, buys nothing over our 20-line startup and adds a dep) | A |
| 2 | FPIOA pinmux | 48 pins, 255 functions, per-pin IO config | S1 `fpioa.h` (Apache-2.0); vendor SVD inside k210-pac (ISC) | **vendored minimal register defs** written from S1/S2 facts (addresses + bit layouts are facts; no code copied). k210-pac acceptable alternative (ISC) but frozen 2019, drags riscv-rt 0.8-era deps | A |
| 3 | SYSCTL clocks/reset | PLL0/1/2, ACLK, periph enables/dividers, `git_id`/`clk_freq`, `power_sel` | S1 `sysctl.{h,c}` (Apache-2.0) | vendored defs, read-only first (`git_id`, `clk_freq`, clock tree measurement), mutation only for UART/SPI enable + fan PWM clocking | A |
| 4 | UART console | UARTHS `0x38000000` (5 Mbaud, 8-byte FIFO, no flow control, PLIC 33) + UART1/2/3 `0x5021..23` (DW 16550-compatible, CTS/RTS, RS485, DMA, PLIC 11-13) | S1 `uart.h`/`uarths.h`; S3 register decode | vendored UARTHS word constructors; **no physical console default**. The physical Phase-A runtime performs zero MMIO. A separate Renode-only payload uses UARTHS at the simulator's modeled address; all Avalon pads/instances remain PENDING-DISCOVERY | A |
| 5 | GPIO read (LEDs, board detect) | GPIOHS 32 pins each own PLIC source 34..65; APB GPIO 8 pins one shared IRQ 23 | S1 `gpio{,hs}.h` | vendored defs; phase A uses **input-only** reads; any output drive waits for D | A |
| 6 | Monotonic tick / scheduler | CLINT `mtime`/`mtimecmp`; TIMER0/1/2 `0x502D..2F` (4×32-bit channels, PWM-capable) | S1 `clint.h`, `timer.h` | vendored defs; CLINT tick drives the safety `sequence`/age clock; TIMERs reserved for PWM (D) | A |
| 7 | WDT0/WDT1 | DW-WDT, `RESET_ALL`/`RESET_CPU`, APB1 clock enables + thresholds | S1 `wdt.{h,c}` (includes timeout math) | vendored defs; **not enabled in phase A** (safe-idle has no actuators to guard); D wiring in §4 | D |
| 8 | SPI0/SPI1 masters | `0x52000000` / `0x53000000`, ≤25 MHz (TBC), 1/2/4/8-wire, 32-byte FIFO, DMA, PLIC 1/2 | S1 `spi.h` | vendored defs; parked until C (ASIC bus candidate — wire contract unresolved, W `asic_control` audit) | C |
| 9 | SPI3 flash read | `0x54000000`, quad frames, DMA; ROM owns boot-time use; no public runtime driver; XIP regs present but no mapped window | S1 `spi.h`; S3; Sipeed docs | vendored defs; manual `READ`/`FAST READ`/quad `EBh` commands into staging buffers; flash map comes from the boot-policy receipt, not guessed | B |
| 10 | DMAC | 6 channels, mem/mem + peripheral handshake, per-channel IRQ | S1 `dmac.h` | vendored defs; used by SHA256 input (B), UART/SPI throughput (C); buffers via non-cached alias or explicit cache maintenance (§2) | B |
| 11 | SHA256 accelerator | `0x502C0000`, DMA input | S1 `sha256.h` | vendored defs; verify staged image digests (B). Software `sha2` crate (MIT OR Apache-2.0) acceptable fallback if hardware behavior needs bench proof | B |
| 12 | AES accelerator | `0x50450000`, ECB/CBC/GCM, DMA | S1 `aes.h` | vendored defs; **deferred** — only if a later gate admits encrypted OTA payloads; ROM boot-time AES-128-CBC posture is a boot-policy measurement, not ours to configure | (B/C, optional) |
| 13 | TIMER PWM (fans/pumps) | TIMER0-2 channels, PWM output mode | S1 `timer.h` | vendored defs; duty/polarity/frequency all profile-bound (D) | D |
| 14 | Tach + cutoff + rail feedback inputs | GPIOHS inputs | S1 `gpiohs.h` | vendored defs; normalization in §4 | D |
| 15 | Temperature/PSU sensors (I2C) | I2C0/1/2 `0x5028..2A` (master or slave, 100/400 kHz) | S1 `i2c.h` | vendored defs; devices/poll rates PENDING-DISCOVERY; many Avalon generations report temps via the ASIC chain instead — do not assume I2C sensors | C/D |
| 16 | Core1 bring-up | independent core, wake via CLINT `msip` + SDK-style entry mailbox (`register_core1`) | S1 `entry.{h,c}` | **default: keep core1 parked** (interrupts off, WFI); optional C/D isolation of ASIC transport behind its own review | C/D, optional |
| 17 | RTC | `0x50460000`, cleared on reset, external-crystal referenced | S1/S2 | optional wall-clock telemetry only; **never** a safety time source (mtime is) | later |

Out of scope forever: KPU/APU/FFT/DVP (no mining use; keep their clocks
gated off), OTP writes, SPI2 slave, JTAG re-enable (boot-policy scope).

### License discipline for the inventory

GPL-3.0-only clean-source verdicts (receipt forbids restricted vendor code
and blobs):

- **Apache-2.0** (Kendryte standalone SDK): FSF-deemed GPLv3-compatible.
  We use it as *factual basis* (addresses, bit layouts, clock formulas);
  our target-bound crate contains our own Rust code, so no Apache NOTICE
  obligations are triggered. If any code snippet is ever copied verbatim,
  Apache-2.0 attribution + notice retention becomes mandatory — plan
  avoids copying.
- **ISC** (`k210-pac` 0.2.0, `k210-hal` 0.2.0, crates.io metadata): ISC is
  a permissive MIT-family license, GPL-3.0-compatible. Risks: (a) both
  frozen on crates.io since 2019; k210-hal's master (embedded-hal 1.0) is
  **unpublished**; (b) neither repo ships a standalone LICENSE file
  (k210-hal carries the ISC text in its README; k210-pac's crate metadata
  is the license record) — acceptable for an SBOM but note it; (c)
  k210-hal has **no WDT and no UARTHS module** (S6), so it cannot cover
  this plan's phases A/D anyway.
- **MIT OR Apache-2.0** (`riscv`, `riscv-rt`, `critical-section`, `vcell`,
  `bare-metal` 1.0): compatible; only `riscv` is even a candidate, and we
  currently prefer zero dependencies.
- **Forbidden / do-not-touch**: Canaan `Avalon_mm`/K230 blobs (BUSL —
  already barred by W), `rustsbi/rustsbi-k210` (**no license file
  detected** — structural reference only, never copy code; RustSBI proper
  is MIT OR Mulan-PSL-2.0), any third-party Avalon firmware binaries
  (TNA-OS et al.), Kendryte SDK `third_party/` trees (gsl-lite,
  nlohmann_json, xtl, nncase — unused by the drivers we mine).
- Note: the crate named `k210-sdk-rs` from the mission brief **does not
  exist** under that name on crates.io or GitHub (searched 2026-08-23);
  the closest artifacts are `laanwj/k210-sdk-stuff` (reference docs) and
  `wyfcyx/k210-soc` (unlicensed educational fork — do not copy).

**Recommended route overall**: vendored, self-written minimal register
definitions (a `dcent-k210-soc` register module written from S1/S2 facts),
zero external dependencies, keeping today's 1-package `Cargo.lock` intact.
That is simultaneously the strongest SBOM, the strongest reproducibility
story (§5), and the cleanest license posture. Every register block gets a
comment citing its S1/S2 source and the `unsafe` confinement is audited in
one module.

## 2. Memory map and budgeting

### 2.1 Physical map (verified S1+S2+S3)

| Region | Cached | Non-cached alias | Size | Notes |
|--------|--------|------------------|------|-------|
| General SRAM **MEM0** | `0x80000000-0x803FFFFF` | `0x40000000-0x403FFFFF` | 4 MiB | ROM load base; text/rodata/data live here |
| General SRAM **MEM1** | `0x80400000-0x805FFFFF` | `0x40400000-0x405FFFFF` | 2 MiB | .bss/staging; DMAC can touch both banks concurrently |
| AI SRAM | `0x80600000-0x807FFFFF` | `0x40600000-0x407FFFFF` | 2 MiB | usable **only** with PLL1 on + KPU idle (S2) — treat as reserve, not budget |
| ROM | `0x88000000-0x8801FFFF` | — | 128 KiB | boot/ISP; never executable data source for us |
| Peripherals | TL `0x3800xxxx`, AXI-IO `0x4xxxxxxx` (non-SRAM parts), AHB/APB `0x50x/52x/53x/54x` | same | — | see §0 |

Gotchas pinned by S3 that the linker/startup must respect:

- The `0x4xxxxxxx` non-cached SRAM mirror **breaks floating-point load
  instructions** (rust-embedded/riscv-rt#25 observation). DMA descriptors
  and buffers may live there, but never let the compiler emit FP accesses
  to it (no `f32/f64` in structures placed in the alias).
- A high-half mirror exists at `0xFFFFFFFF80000000`; the default
  `riscv64gc` code model (medany) already avoids any need for it.
- Cache coherency is software-managed: DMA-visible buffers need either
  placement in the non-cached alias or explicit cache
  flush/invalidate around transfers (the cache module exists in k210-hal
  as a design reference; we implement `fence.i` + dcache maintenance per
  RISC-V CMO/Zicbom availability on this core — bench-verify which works).

### 2.2 Link base `0x80000000` implications

- The ROM contract loads at `0x80000000`; `k210-sentinel.ld` already
  `ASSERT`s the entry and a conservative 6 MiB region. Keep: single
  file-backed `PT_LOAD` (the replacement receipt's ELF audit requires
  exactly that), `VMA == PMA`, raw image = ELF load bytes.
- The implemented Phase-A linker script adds BSS bounds and one aligned
  16 KiB hart-0 stack; hart 1 is parked before stack use. Any later core-1
  bring-up, heap, or flash/OTA staging reservation is a separate reviewed
  change and remains absent.

### 2.3 Budget for a ~1 MiB-class image (vs 8 MiB SRAM)

| Concern | Budget | Rationale |
|---------|--------|-----------|
| text + rodata + data | ≤ 1.5 MiB target ceiling | policy core + drivers + console + JSON-profile-derived const tables; the 42-byte sentinel proves the pipeline, not the budget |
| .bss (state machines, ring buffers) | ≤ 512 KiB in lower MEM1 | deterministic, statically sized, no allocator |
| OTA/flash staging | ≤ 2 MiB upper MEM1 (NOLOAD) | phase B staging only while power latched off |
| Stacks | Phase A: 1 × 16 KiB; later maximum: 2 × 32 KiB | hart 1 is currently parked before stack use; any increase is reviewed with the target-bound runtime |
| AI SRAM | **excluded** from all budgets | PLL1-gated; a future reviewed decision may use it as a 2 MiB scratch expansion |
| Slack | ≥ 3 MiB | headroom for C-phase transport buffers/double-buffering |

## 3. Board-bound layer design

Everything below is the contract that discovery output fills. Two
artifacts:

1. **`dcent-k210-bsp-profile-v1` JSON** — the signed, canonical data file
   (source of truth; satisfies the replacement receipt's "complete BSP
   capability/default-off profile" claim vocabulary).
2. **Generated Rust `const` tables** — a host verifier checks the JSON
   against admitted discovery/boot-policy receipts and a small generator
   emits `const` constructors into the target-bound crate at build time
   (deterministic, no runtime parser, `include_bytes!`-free).

### 3.1 Trait sketch (target-bound crate)

```rust
//! dcent-k210-bsp: board-bound I/O contract. Every constructor returns
//! None until a discovery-admitted profile fills it. No defaults exist.

/// FPIOA pad index, 0..=47 (SoC fact).
pub struct FpioaPad(u8);
/// GPIOHS index, 0..=31 (SoC fact).
pub struct GpiohsIndex(u8);

/// A pin assignment admitted only from signed discovery evidence.
#[derive(Clone, Copy)]
pub struct PinAssignment {
    pub pad: FpioaPad,
    pub function: FpioaFunction,      // from the S1 function table
    pub io_config: IoConfig,          // pull, drive, slew, schmitt — measured
    pub evidence: EvidenceRef,        // digest into the discovery bundle
}

/// Measured polarity. Never defaulted; `Unknown` refuses operation.
pub enum Polarity { ActiveHigh, ActiveHighIsSafe /* etc. — discovery-bound */ }

pub struct ConsoleConfig {
    pub instance: UartInstance,       // Uarths | Uart1 | Uart2 | Uart3
    pub rx: Option<PinAssignment>, pub tx: Option<PinAssignment>,
    pub baud: u32,
}

pub struct FanChannel {
    pub pwm: Option<TimerPwmChannel>, // TIMERn channel + pad + freq + duty polarity
    pub tach: Option<PinAssignment>,  // GPIOhs input + pulses_per_revolution
    pub locked_min_rpm: Option<u32>,  // joins SafetyLimits; None = cannot run
}

pub struct CutoffPath {
    pub command: Option<PinAssignment>,   // output that opens hash power
    pub feedback: Option<PinAssignment>,  // INDEPENDENT read-back line
    pub polarity: Option<Polarity>,       // which level == "cut/de-energized"
}

pub struct SensorChannel {
    pub kind: SensorKind,             // NTC | I2cDevice | AsicChainReported
    pub bus: Option<BusAssignment>,   // I2C instance or ASIC chain source
    pub conversion: ConversionCurve,  // profile-supplied, bounded table
}

pub trait BoardProfile {
    fn identity(&self) -> &'static ProfileIdentity; // model row + receipt digests
    fn console(&self) -> Option<ConsoleConfig>;
    fn cooling(&self) -> &'static [FanChannel];
    fn temperature_sensors(&self) -> &'static [SensorChannel];
    fn hash_power_cutoff(&self) -> CutoffPath;
    fn hash_power_present(&self) -> Option<SensorChannel>; // measured rail sense
    fn psu_control(&self) -> Option<PsuControl>;
    fn psu_monitor(&self) -> Option<SensorChannel>;
    fn leds(&self) -> &'static [PinAssignment];
    fn board_detect(&self) -> Option<PinAssignment>;
    fn asic_bus(&self) -> Option<AsicBusConfig>;    // None until wire contract gate
    fn capabilities(&self) -> CapabilitySet;         // exactly the JSON claims
}
```

Construction rules (fail-closed, mirroring the policy core):

- `BoardProfile::admit(profile_bytes, chain)` is the **only** constructor;
  it verifies the canonical JSON, the signature joins, and that every
  non-null assignment carries an `evidence` digest resolving inside an
  admitted discovery bundle. Anything else yields a `Sealed` profile where
  every accessor returns `None`.
- A capability without a complete pin set + polarity + evidence is
  **absent**, not partially usable. `hash_power_cutoff` specifically
  requires both `command` and `feedback` plus polarity, or the trait
  reports "no cutoff authority" — which keeps `EnergizeHashRail` refused
  (`MutationDisposition::Refuse` stays authoritative).

### 3.2 JSON profile schema sketch

```json
{
  "schema": "dcent-k210-bsp-profile-v1",
  "profile_id": "PENDING-DISCOVERY:<model-row>-<controller-board-rev>",
  "identity": {
    "gauntlet_model_row": null,
    "controller_board_marking": null,
    "soc_git_id": null,
    "joins": {
      "discovery_receipt_sha256": null,
      "boot_policy_receipt_sha256": null
    }
  },
  "console_uart": {
    "instance": null,
    "rx": {"pad": null, "evidence": null},
    "tx": {"pad": null, "evidence": null},
    "baud": null
  },
  "asic_bus": null,
  "cooling": [],
  "temperature_sensors": [],
  "psu": {"control": null, "monitor": null},
  "leds": [],
  "hash_power_cutoff": {
    "command": {"pad": null, "evidence": null},
    "feedback": {"pad": null, "evidence": null},
    "de_energized_polarity": null
  },
  "hash_power_rail_sense": null,
  "board_detect": null,
  "defaults": {
    "hash_power": "off",
    "voltage_control": "off",
    "cooling_before_hash_power": true,
    "watchdog": "fail_closed",
    "interrupts": "fail_closed",
    "startup_state": "safe_idle"
  }
}
```

Every `null` above is an intentional **PENDING-DISCOVERY** placeholder. In
particular: which UART instance is the Avalon debug console, which
SPI/UART instance (if any) reaches the hash boards, fan PWM/tach pads and
pulses-per-rev, pump presence, sensor kinds and buses, PSU control/monitor
lines, LED pads, the independent hash-power cutoff command/feedback pair
and its de-energized polarity, board-detect strap, and the controller
board marking itself are all unmeasured. The `defaults` block is fixed by
the replacement-receipt contract and is not discovery-fillable — it is the
signed safe-claim vocabulary, all default-off. Canonicalization (sorted
keys, no whitespace, UTF-8) matches the existing SSHSIG receipt tooling so
profiles can be signed and embedded verbatim.

## 4. Safety wiring (phase D)

`src/safety.rs` consumes normalized `SafetyObservation`s, injected
`SafetyLimits`, and a `SafetyBinding` carrying distinct nonzero digests for
the externally reviewed model profile and exact run. The core does not
authenticate those opaque digests; the signed receipt layer must do so. Every
verdict repeats the binding to prevent accidental profile/session splicing.
The supervisor is non-`Clone`/non-`Copy`, so a pre-fault snapshot cannot be
retained as an in-process rollback path. Phase D adds exactly one producer
assembly and changes no supervisor semantics:

| `SafetyObservation` field | Producer | Normalization rule (fail-closed) |
|--------------------------|----------|----------------------------------|
| `sequence` | monotonically increasing counter advanced once per supervision pass | never reset while running; any non-increasing value is the supervisor's own replay fault |
| `monotonic_tick` | the CLINT `mtime` value captured with the completed observation | must increase independently of `sequence`; non-increasing time latches, and review requires both the injected sample count and injected minimum healthy tick span |
| `sample_age_ticks` | `mtime - last_completed_sensor_refresh` | a sensor bus timeout or out-of-range raw reading yields `None` downstream fields — never a stale or default value |
| `hottest_temp_mc` | max over all admitted sensor channels, each converted through its profile `ConversionCurve` (bounded table + clamped interpolation) | unconvertible/out-of-bounds raw ⇒ missing feedback ⇒ latched fault |
| `min_cooling_rpm` | min over tach channels: GPIOHS edge count per tick × `60 / pulses_per_rev` | missing pulses ⇒ `None` ⇒ latched fault; `locked_min_rpm` from the profile joins `SafetyLimits.min_cooling_rpm` (limits remain model-bound and injected, never defaulted) |
| `independent_cutoff_asserted` | GPIOhs **read-back of the independent feedback line** (not the command line) | polarity from discovery; `None` while unassigned keeps the gate sealed |
| `hash_power_present` | measured rail sense (PSU good / rail monitor), again read-back not command | `None` ⇒ `HashPowerFeedbackMissing` |
| `watchdog_age_ticks` | `mtime - tick_of_last_accepted_wdt_kick` | see ordering below |

Watchdog ordering (the load-bearing rule):

1. WDT0 is enabled with `RESET_ALL` at the moment the first actuator
   (fan PWM) is first driven — never earlier, and never in phase A
   safe-idle (nothing to guard; a hung safe-idle is already safe).
2. One supervision pass = collect observations → `supervisor.observe`.
   The WDT is kicked **only if** the pass completed with fresh telemetry
   and the supervisor is not `FaultLatched`. Kicking is therefore an
   output of health, not a background liveness ping. `SafetyVerdict` is
   `#[must_use]`; a target runtime must not discard the result.
3. On a latched fault (or stale/missing feedback): drive `hash_power`
   command to the discovery-measured de-energized level, force cooling to
   the profile's fail-safe duty, and **stop kicking**. WDT0 then issues
   `RESET_ALL`; startup re-enters default-off safe idle. The supervisor
   itself still never resets (`SafetySupervisor` has no reset API and cannot
   be cloned or copied — a latched fault requires destroying the instance
   through the reviewed recovery path, exactly as documented).
4. WDT1 stays unassigned by default; the optional phase-C use is an
   independently-clocked guard for a core1 transport loop, admitted only
   with its own review. WDT clock thresholds (`SYSCTL_THRESHOLD_WDTx`)
   are derived from the measured APB1 frequency, not the nominal one.

Interrupt posture: all critical supervision inputs are also polled in the
main loop; interrupts are an optimization whose failure degrades to
slower polling, never to skipped checks (receipt's "interrupts fail
closed" claim).

## 5. Build and reproducibility (two-independent-builds receipt)

The replacement receipt demands two byte-identical builds from one clean
source archive on distinct hosts/workspaces, an SPDX SBOM, and license +
clean-room reviews. Current pipeline assets provide: pinned
`TOOLCHAIN = 1.90.0`, `cargo --locked`, recorded `rustc -vV`/`cargo -Vv`,
Cargo.lock and LLVM objcopy digests (`scripts/build_k210_candidate.py`), ELF64/PT_LOAD audit at
`0x80000000`, deterministic raw extraction and AES0/AUP-v2 wrapping.
Plan additions for the BSP crate:

1. **Toolchain**: keep `rustup` toolchain `1.90.0` pinned. The current
   non-installable builder records compiler/Cargo identity, Cargo.lock, and
   objcopy digests. A replacement receipt additionally requires two
   independent toolchain installs and the complete toolchain manifests it
   defines; the current builder is not that receipt.
2. **Dependencies**: preserve the zero-dependency `Cargo.lock` (strongest
   possible SBOM). If a dependency ever becomes necessary: `--locked` is
   mandatory, sources vendored (`cargo vendor` + checksum manifest) into
   the source archive, licenses restricted to MIT / Apache-2.0 / ISC, and
   the SBOM grows accordingly. Never a git dependency (the k210-hal
   master trap).
3. **Profile artifacts**: the signed BSP profile JSON is embedded by the
   build as a hash-pinned artifact (its SHA-256 recorded in the build
   log), so two builders cannot differ by profile drift.
4. **Determinism knobs**: keep `codegen-units = 1`, fat LTO,
   `opt-level = "s"`, `panic = "abort"`, `strip = "symbols"`; add
   `--remap-path-prefix` (workspace path → `/src`) so no builder-local
   path leaks into any surviving symbol/DWARF; fix `SOURCE_DATE_EPOCH`
   for any host-side packaging step.
5. **Source archive**: zip/tar with normalized metadata — fixed mtimes
   (archive creation date), zeroed uid/gid/uname/gname, sorted entry
   order, no `.git`. The existing gauntlet repack tooling already
   demonstrates deterministic ZIP construction; reuse its approach.
6. **Verification**: the receipt's byte-identity checks (ELF PT_LOAD ==
   raw == AES0/AUP payload incl. SHA-256 trailer) remain the acceptance
   test; both builders' logs + toolchain manifests are snapshot evidence.
7. **SPDX SBOM**: SPDX-2.3 JSON — package = this crate (GPL-3.0-only,
   verification code from the source archive), build tool = rustc 1.90.0,
   zero runtime dependencies; the license-review table of this document
   is the license-review attachment (§1).

## 6. What unblocks when

- The moment an **admitted discovery receipt** lands for a named unit,
  §3's placeholders start filling (console UART pads, cooling class,
  PSU/cooling topology are all discovery-capture fields already defined
  in `gauntlet/K210_DISCOVERY_RECEIPTS.md`).
- Phase A is implemented and host-tested as two intentionally separate
  surfaces: a zero-MMIO physical runtime with a sealed profile and a
  Renode-only UARTHS beacon. Neither is packageable or install-authorized.
- Phase B needs the **boot-policy receipt's measured flash map**.
- Phase C needs the still-missing **K210 controller-to-ASIC wire
  contract** (protocol evidence audit) — nothing in this plan may be read
  as softening that gate.
- Phase D needs model-bound `SafetyLimits` from reviewed evidence and the
  independent-cutoff wiring from discovery; the supervisor's
  fail-closed/latched semantics are already frozen in `src/safety.rs`.
