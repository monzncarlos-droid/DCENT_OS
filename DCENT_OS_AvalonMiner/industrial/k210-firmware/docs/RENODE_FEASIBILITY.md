# Renode feasibility for K210 bare-metal host-testing — w1-renode research spike

**Author:** DCENT_CE (w1-renode lane), from research by the exploration spike
**Date:** 2026-08-23
**Scope:** HOST-ONLY desk verification of Renode (antmicro's open-source simulator) as a pre-hardware host-test lane for the `dcentos-avalon` K210 firmware (`riscv64gc-unknown-none-elf`, linked at `0x80000000`). The separate `dcent-k210-renode-console` ELF has now been built and audited, but Renode itself has not been installed or run. No hardware was contacted and no probe/flash/ISP action was taken or authorized. Web research plus workspace anchors (`BSP_PLAN.md`, `K210_SOC_BOOT_FLASH_ISP_CONTRACT.md`, `src/bin/renode_console.rs`).

> **Boundary (do not soften).** Nothing here advances or substitutes any gauntlet gate. A simulator pass is host-lane evidence of the same class as a unit test: it can never fill a discovery, boot-policy, or replacement receipt field. The K210 boot-policy drill (ROM/OTP/flash/ISP/JTAG measurements) remains a physical, exact-unit gate regardless of how well firmware behaves in Renode.

Evidence tags: **[DOCUMENTED]** — stated by a pinned public source (URL cited). **[INFERRED]** — derived from documented facts plus reasoning. **[UNKNOWN]** — needs hardware or an actual Renode run (not done this session). All Renode repo contents quoted were fetched from raw.githubusercontent.com/renode/renode/master on 2026-08-23.

---

## 0. Headline recommendation

**GO — conditional.** Renode ships a real (if minimal) Kendryte K210 machine model whose memory map matches the parts of BSP Phase A that matter most: dual RV64 harts, CLINT at `0x02000000`, PLIC at `0x0C000000` with 65 sources, and UARTHS at `0x38000000` wired to PLIC source 33 — the exact geometry our vendored register definitions target. The implemented `dcent-k210-renode-console` ELF is separately feature-gated from the zero-MMIO physical runtime and links at `0x80000000`. It is suitable for a future CI boot-to-console lane (UART beacon, trap-entry proof, core1-parked proof, and later mtime-tick proof), but that emulator execution remains unperformed.

Conditions: (1) emulation results are host-lane evidence only — never a gauntlet gate; (2) firmware must tolerate the unmodeled SYSCTL (clock-enable path stubbed or cfg'd out, §4.1); (3) WDT / FPIOA / SPI / pinmux / boot-ROM behavior are untestable and stay hardware-gated (§4).

---

## 1. Does a K210 platform model exist? Which version, which peripherals?

### 1.1 Existence and version history — [DOCUMENTED]

- Platform file: `platforms/cpus/kendryte_k210.repl` — https://github.com/renode/renode/blob/master/platforms/cpus/kendryte_k210.repl
- Demo: `scripts/single-node/kendryte_k210.resc` — https://github.com/renode/renode/blob/master/scripts/single-node/kendryte_k210.resc ; coverage demo: `scripts/complex/coverage/kendryte_k210_coverage.resc` — https://github.com/renode/renode/blob/master/scripts/complex/coverage/kendryte_k210_coverage.resc
- Introduced in **Renode 1.9.0 (2020-03-10)**: CHANGELOG entry "Kendryte K210 platform support" (https://github.com/renode/renode/blob/master/CHANGELOG.rst, under `1.9.0 - 2020.03.10`); Zephyr Project 1.9 release post corroborates: "support for Privileged Architecture 1.1 and Kendryte 210 – an AI capable RISCV64 dual core SoC" — https://zephyrproject.org/renode-1-9-release-with-new-platforms-risc-v-improvements-dual-radio-more/
- Landing commit 2020-02-21, Piotr Zierhoffer (antmicro), PR #17994 — https://github.com/renode/renode/pull/17994
- Latest release: **1.16.1 (2026-02-16)** — https://github.com/renode/renode/releases. K210 still on the supported-boards page (vendor section KENDRYTE: `kendryte_k210`) — https://renode.readthedocs.io/en/latest/introduction/supported-boards.html

Maintenance: the .repl has had exactly **four commits in six years** [DOCUMENTED, GitHub commits API for the path]: 2020-02-21 add (#17994); 2021-03-24 PLIC contexts (#24853); 2023-10-13 default cpuType (#48885); 2024-06-14 rename PrivilegedArchitecture (#60671). **[INFERRED]** No peripheral added since Feb 2020 — stable, minimal, essentially unmaintained; do not expect upstream to close our gaps.

### 1.2 The complete model, verbatim — [DOCUMENTED]

The entire .repl (its smallness is the finding):

```
rom: Memory.MappedMemory @ { sysbus 0x80000000; sysbus 0x0 } size: 0x2000000
cpu1: CPU.RiscV64 @ sysbus
    cpuType: "rv64imacfd_zicsr_zifencei"
    privilegedArchitecture: PrivilegedArchitecture.Priv1_10
    timeProvider: clint
    hartId: 0
cpu2: CPU.RiscV64 @ sysbus
    cpuType: "rv64imafdc_zicsr_zifencei"
    privilegedArchitecture: PrivilegedArchitecture.Priv1_10
    timeProvider: clint
    hartId: 1
uart: UART.SiFive_UART @ sysbus 0x38000000
    -> plic@33
clint: IRQControllers.CoreLevelInterruptor @ sysbus 0x02000000
    [0,1] -> cpu1@[3,7]
    [2,3] -> cpu2@[3,7]
    frequency: 62000000
    numberOfTargets: 2
plic: IRQControllers.PlatformLevelInterruptController @ sysbus 0x0C000000
    [0,1] -> cpu1@[11,9]
    [2,3] -> cpu2@[11,9]
    numberOfSources: 65
    numberOfContexts: 4
```

Quirks: the two cpuType strings differ only in letter order (identical I+M+A+C+F+D + zicsr_zifencei = rv64gc-class); cosmetic cleanup sits in open PR #848 (2025-11-23) — https://github.com/renode/renode/pull/848 — irrelevant to us, we run on hart 0. The RAM region is named `rom` but is writable `Memory.MappedMemory` (32 MiB) at `0x80000000` mirrored at `0x0` (mirror exists for the Linux demo's trap vectors [INFERRED]). CLINT `frequency: 62000000` is a model knob, not a measured K210 value [DOCUMENTED property; INFERRED arbitrary].

### 1.3 SYSCTL is not modeled — the demo stubs it — [DOCUMENTED]

Stock `kendryte_k210.resc` contains:

```
sysbus Tag <0x50440000 0x10000> "SYSCTL"
sysbus Tag <0x50440018 0x4> "pll_lock" 0xFFFFFFFF
sysbus Tag <0x5044000C 0x4> "pll1"
sysbus Tag <0x50440008 0x4> "pll0"
sysbus Tag <0x50440020 0x4> "clk_sel0"
sysbus Tag <0x50440028 0x4> "clk_en_cent"
sysbus Tag <0x5044002C 0x4> "clk_en_peri"
# enable uart tx
uart WriteDoubleWord 0x8 0x1
```

SYSCTL at `0x50440000` is covered by `sysbus Tag` fixed-value stubs (PLL lock reads "always locked" via 0xFFFFFFFF), and UART TX enable is forced by writing the SiFive UART txctrl register (offset 0x8, TXEN=1) directly, bypassing the real clock-enable sequence. The SiFive UART model gates transmission on TXEN (writes to txdata while disabled only log a warning) — `SiFive_UART.cs`, https://github.com/renode/renode-infrastructure/blob/master/src/Emulator/Peripherals/Peripherals/UART/SiFive_UART.cs

### 1.4 What the demo runs — [DOCUMENTED]

The demo loads a vmlinux from antmicro's artifact server and sets `machine SetSerialExecution True` (deterministic serialized execution); the coverage sample runs a small riscv64.elf. Both prove ELF loading works in practice on this machine.

### 1.5 Per-peripheral verdict table (BSP_PLAN §1 inventory vs model)

| K210 peripheral (BSP ref) | SoC address | Renode k210 model | Verdict | Notes |
|---|---|---|---|---|
| CPU cores ×2 (RV64GC) | — | `CPU.RiscV64` ×2, rv64imafdc_zicsr_zifencei, Priv 1.10, hartId 0/1 | **SUPPORTED** | ISA set equals rv64gc; Renode's own tests use `cpuType: "rv64gc_zicsr_zifencei"` (https://github.com/renode/renode/blob/master/tests/unit-tests/riscv-amo-instructions.robot) |
| CLINT (mtime/msip) | `0x02000000` | `CoreLevelInterruptor`, 2 targets, timeProvider of both CPUs | **SUPPORTED** | Frequency is a knob (62 MHz); real tick rate must not be hardcoded [INFERRED] |
| PLIC | `0x0C000000` | `PlatformLevelInterruptController`, 65 sources, 4 contexts, per-core lines (M-ext 11, M-soft 3/7) | **SUPPORTED** | 65 sources matches the K210 source-ID table incl. GPIOHS 34–65 (BSP_PLAN §0) [INFERRED consistent] |
| UARTHS console | `0x38000000`, PLIC 33 | `UART.SiFive_UART` @ 0x38000000, `-> plic@33` | **SUPPORTED** | Exact address + IRQ match; TX needs TXEN; RX modeled [DOCUMENTED, SiFive_UART.cs] |
| SRAM @ `0x80000000` | 8 MiB (6+2) | one flat 32 MiB `MappedMemory` (+ mirror @ 0x0) | **PARTIAL** | Loads work; bank split, 6+2 MiB sizing, AI-SRAM gating, `0x40000000` non-cached alias NOT modeled [DOCUMENTED vs BSP_PLAN §2.1] |
| SYSCTL | `0x50440000` | none — Tag stubs in demo | **UNSUPPORTED** | Clock enables, dividers, git_id/clk_freq, PLL lock untestable without our own stub (§4.1) |
| FPIOA pinmux | `0x502B0000` | none | **UNSUPPORTED** | Absent from .repl; pinmux effects physical anyway [DOCUMENTED absence] |
| GPIOHS / APB GPIO | `0x38001000` / `0x50200000` | none | **UNSUPPORTED** | Phase-A input reads untestable |
| WDT0/WDT1 (DW-WDT) | `0x50400000`/`0x50410000` | none — no Synopsys DW watchdog model exists anywhere in Renode (inventory: Ambiq, Andes, Arm Corstone, CMSDK, CC2538, MPFS, MSP430, NRF52840, NXP, Renesas×2, S32K3, STM32×2 — https://github.com/renode/renode-infrastructure/tree/master/src/Emulator/Peripherals/Peripherals/Timers) | **UNSUPPORTED** | Kick / interrupt-then-reset / RESET_ALL semantics untestable (§4.2) |
| UART1/2/3 (DW 16550) | `0x50210000..` | not instantiated; generic `NS16550.cs` exists | **PARTIAL (addable)** | We could add `UART.NS16550` in a local .repl overlay; K210's DW variant has extra regs (RS485/DMA) the generic model won't cover [INFERRED] |
| SPI0/1/3 (flash ctrl) | `0x52000000`+ | none on k210 platform | **UNSUPPORTED** | Phase-B flash reads stay hardware-gated (boot-policy flash map) |
| TIMER0–2, DMAC, SHA256, AES, OTP, RTC, I2C | various | none | **UNSUPPORTED** | Phase B/C/D; hardware-gated |
| ROM @ `0x88000000` + boot/ISP flow | `0x88000000` | none | **UNSUPPORTED** | Renode loads the ELF directly; ROM boot/ISP is a physical gauntlet item (SoC contract §1.1/§1.4) |

---

## 2. Will a `riscv64gc-unknown-none-elf` ELF at `0x80000000` load and run?

**Yes with high confidence — [INFERRED] from documented facts; not empirically run this session (host-only constraint).**

- **ISA**: riscv64gc = I+M+A+F+D+C; the .repl cores spell the identical set (`rv64imacfd_zicsr_zifencei` / `rv64imafdc_zicsr_zifencei`) [DOCUMENTED, .repl]. Renode's own RISC-V unit tests run `cpuType: "rv64gc_zicsr_zifencei"` [DOCUMENTED] — gc-class strings are first-class.
- **Load address**: `sysbus LoadELF` (used by the demo for a full vmlinux) loads PT_LOAD segments at their VMAs [DOCUMENTED usage]; 32 MiB mapped RAM exists at exactly `0x80000000` [DOCUMENTED, .repl]. Our linker contract (single file-backed PT_LOAD, VMA == PMA `0x80000000`, medany — BSP_PLAN §2.2) needs nothing Renode can't map.
- **Privilege**: Priv 1.10 cores [DOCUMENTED]; our firmware is M-mode bare-metal (mtvec/mie/mstatus, WFI — sentinel source), the normal mode Renode starts RISC-V cores in [INFERRED].
- **Dual hart**: hart 1 exists; the coverage demo parks it with `cpu2 IsHalted true` [DOCUMENTED] — exactly the BSP_PLAN row-16 "core1 parked" posture.
- **mtime**: both CPUs take `timeProvider: clint` [DOCUMENTED] — CLINT-tick tests are meaningful.

Caveats making a pass weaker evidence than silicon [INFERRED, model vs BSP_PLAN §2.1 gotchas]: no caches modeled → fence.i / dcache-maintenance correctness invisible; no `0x40000000` non-cached alias → the "no FP loads via the alias" gotcha cannot regress-test here; 32 MiB flat RAM → budget overflows beyond 6 MiB NOT caught (our ELF audit script stays the budget guard); CLINT frequency is a model constant → wall-clock timing meaningless, only ordering/tick-count logic testable.

---

## 3. Practical harness shape

### 3.1 Recommended `.resc` (e.g. `tests/renode/dcent_k210.resc`) — sketch ours, knobs documented

```
using sysbus

mach create
machine LoadPlatformDescription @platforms/cpus/kendryte_k210.repl
machine SetSerialExecution True     # determinism (stock demo knob)
cpu2 IsHalted true                  # park core1 from tick zero (BSP default)
showAnalyzer uart                   # UARTHS TX -> Renode log

# SYSCTL stubs — stock demo tags so PLL/lock/clock-select reads return sane values
sysbus Tag <0x50440000 0x10000> "SYSCTL"
sysbus Tag <0x50440018 0x4> "pll_lock" 0xFFFFFFFF
sysbus Tag <0x5044000C 0x4> "pll1"
sysbus Tag <0x50440008 0x4> "pll0"
sysbus Tag <0x50440020 0x4> "clk_sel0"
sysbus Tag <0x50440028 0x4> "clk_en_cent"
sysbus Tag <0x5044002C 0x4> "clk_en_peri"

sysbus LoadELF @target/riscv64gc-unknown-none-elf/release/dcent-k210-renode-console
start
```

The Renode-only console writes only the modeled UARTHS TXCTRL/TXDATA pair. It performs no SYSCTL or FPIOA writes. The separately named physical Phase-A runtime performs zero MMIO, so emulator accommodations cannot silently enter that binary.

### 3.2 Robot test — keywords per https://renode.readthedocs.io/en/latest/introduction/testing.html and https://renode.readthedocs.io/en/latest/basic/renode-testing-api.html

```robot
*** Settings ***
Suite Setup       Setup
Suite Teardown    Teardown
Test Teardown     Test Teardown
Resource          ${RENODEKEYWORDS}

*** Test Cases ***
Safe Idle Console Emits Beacon Then Stays Quiet
    Execute Command           include @tests/renode/dcent_k210.resc
    Create Terminal Tester    sysbus.uart
    Wait For Line On Uart     DCENT-K210 safe-idle v1
    Test If Uart Is Idle      1
```

`renode-test` emits robot_output.xml / log.html / report.html, parallel `-j`, CI-mode failure snapshots [DOCUMENTED, testing.html].

### 3.3 Exit detection — options and limits

- No `Should Exit`/machine-exit keyword in the documented testing API, and no RISC-V semihosting documented in Renode (changelog's only semihosting entries concern ARM tests and Xtensa; `tests/unit-tests/arm-semihosting.robot` exists) — [DOCUMENTED absence; INFERRED conclusion]. Do not design around an exit syscall.
- Primary pattern: UART beacon + `Wait For Line On Uart` for success; Robot timeout + `Test If Uart Is Idle` for hang/quiescence. Matches Renode's own platform tests [DOCUMENTED].
- Secondary: `cpu AddHook <address> <python-expression>` for address-hit/register assertions [DOCUMENTED, testing-api].
- Coverage/trace (later): `cpu1 CreateExecutionTracing "trace" $CWD/trace.bin.gz PC isBinary=True compress=True` [DOCUMENTED, K210 coverage .resc].
- Debugging: `machine StartGdbServer 3333` then `target remote :3333` [DOCUMENTED, https://renode.readthedocs.io/en/latest/debugging/gdb.html].
- CI: `antmicro/renode-test-action` ("GitHub Action allowing to run tests in the Renode framework") — https://github.com/antmicro/renode-test-action.

### 3.4 Filling small gaps ourselves — [DOCUMENTED mechanism]

`Python.PythonPeripheral` in a .repl (`script` inline or `filename`), handling `request.IsRead/IsWrite/Value/Offset/Length`, exists exactly for "stubbing hardware blocks that software depends on but that aren't fully modeled" (docs' own Tegra-2 example). Caveat: IronPython 2 syntax today. — https://renode.readthedocs.io/en/latest/basic/using-python.html. This is the sanctioned way to add a fake SYSCTL with read-backable git_id/clk_freq, or a DW-WDT register facade (reset semantics would still be fiction — §4.2).

---

## 4. Gaps vs BSP Phase A (and D) — what is untestable in emulation

1. **SYSCTL unmodeled (top gap).** The official demo itself papers over `0x50440000` with fixed-value Tags [DOCUMENTED, .resc]. The real clock-enable sequence for UARTHS (later SPI/fan-PWM clocking) never executes against a model; `git_id`/`clk_freq` boot-log silicon-revision evidence (BSP_PLAN §0) cannot be produced meaningfully; PLL-lock waits are vacuous. **Stub strategy**: copy the demo's Tag set in our .resc for read-compatibility, plus a `renode` cargo feature gating the clock-enable mutation path; optionally a PythonPeripheral SYSCTL exposing fixed git_id/clk_freq once we want log-field parity. Protected anyway: console code shape, register-layout typos, trap/entry behavior.
2. **No watchdog model at all (phase-D load-bearing rule).** No Synopsys DW-WDT peripheral exists in Renode [DOCUMENTED, Timers inventory]; WDT0/WDT1 are not instantiated. The BSP_PLAN §4 rule — WDT0 `RESET_ALL` armed at first actuator drive, kicked only on healthy supervision passes, stop-kick on latched fault — is untestable in emulation: no interrupt-then-reset response, no reset-scope semantics, no accidental-disable protection. A custom model would assert against our own fiction. Phase D WDT validation stays 100% hardware.
3. **No FPIOA / GPIO / SPI / ROM-ISP / caches / memory fidelity.** FPIOA pinmux (every peripheral-to-pad path), GPIO input reads, all SPI (hence phase-B flash reads), the ROM boot+ISP flow, and cache/alias gotchas are untestable. A passing run says nothing about pinmux, flash, or boot policy — already hardware-gated, so no gate language changes. Flat 32 MiB RAM hides size-budget overflows; CLINT frequency arbitrary; no TIMER/DMA/SHA256/AES models (phase B/C/D).

---

## 5. Alternatives if Renode K210 were inadequate

| Option | K210 support | Verdict |
|---|---|---|
| **QEMU (mainline)** | **None.** No `k210` machine; RISC-V docs list Kendryte K230 (`k230`) but not K210/Canaan/Sipeed Maix — https://www.qemu.org/docs/master/system/target-riscv.html [DOCUMENTED] | **NO-GO as K210.** `virt`/`spike` execute rv64gc code (virt RAM base `0x80000000`) with a 16550 UART at a different address and a test-finisher exit device — a different SoC contract that would fork our register layer and prove less than Renode's address-exact model [INFERRED] |
| **Wokwi** | **None.** Arduino/ESP32*/RP2040/ESP8266 families only — https://docs.wokwi.com/getting-started/supported-hardware [DOCUMENTED] | **NO-GO** |
| **kendryte-standalone-sdk "emulator"** | **Does not exist** — SDK is drivers + linker + headers (BSP_PLAN evidence S1) [DOCUMENTED]. Community MaixPy "simulators" are PC-side API-level shims, not SoC emulators [INFERRED; not individually re-verified this session] | **NO-GO** |
| **Spike (riscv-isa-sim)** | ISA-only, no peripherals, HTIF-based | Only ISA-level tests; strictly weaker here [INFERRED] |

Renode is the only credible pre-hardware lane; there is no second emulator to cross-check against — one more reason Renode results must be scoped as smoke/regression evidence, not correctness proof.

---

## 6. Recommendation, GO conditions, and the phase-A CI lane

**GO** — adopt Renode (any version ≥ 1.9.0; current 1.16.1) as the host-test lane for the K210 firmware crate:

1. **Scope / CI lane for phase A**: a future `renode-test` job that builds `dcent-k210-renode-console` for `riscv64gc-unknown-none-elf`, loads it with the §3.1 `.resc`, and asserts the UART beacon line plus post-beacon quiescence (`Test If Uart Is Idle`) inside the Robot timeout. This would be boot-to-console, entry-path, core1-parked, and later mtime-tick evidence. Host-lane evidence only — never a gauntlet gate or receipt evidence. Until that job exists and runs, the current proof is limited to cross-build and ELF/source-boundary audits.
2. **Divergence management**: `renode` cargo feature (or Tag stubs) covers the SYSCTL clock-enable path; hardware binary unchanged; divergence documented in the BSP crate.
3. **Hardware-only list** (explicit in BSP plan): WDT0/WDT1 behavior, FPIOA/GPIO, SPI3 flash reads, boot-ROM/ISP, OTP, all timing-of-record, git_id/clk_freq evidence, cache-maintenance behavior.
4. **Defer** custom C#/Python WDT or SYSCTL models until a demonstrated phase-D need — a stub proves register layout, not DW-WDT semantics, and a fake model is a maintenance liability.
5. **Keep** the existing ELF-audit builder checks as the link-layout/budget authority (Renode's 32 MiB RAM cannot catch those failures).
