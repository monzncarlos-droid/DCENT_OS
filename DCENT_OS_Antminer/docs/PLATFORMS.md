# Supported Platforms

This page covers the industrial Antminer member in `DCENT_OS_Antminer/`. The
ESP32-S3 / Bitaxe-class member lives in `DCENT_OS_ESP/`. On Antminers,
DCENT_OS targets the Zynq- and Amlogic-era Bitmain fleet. Because `dcentrald`
auto-detects the ASIC via its ChipID and loads the matching driver, **one
firmware architecture covers many models**. Mixed control-board/hash-board
operation is a validated/lab compatibility capability, not a blanket
production-install promise for every board mix.

This page is the honest, per-model picture. **"Mining achieved"** means DCENT_OS has produced accepted
pool shares on that hardware on our bench; cold-boot or nonce evidence alone does not earn that label.
Where a row says **"untested on latest binaries"**, the mining achievement stands on an earlier build of
the daemon and has not yet been re-run on the current release binaries — the code paths are unchanged or
regression-pinned, but we don't re-claim a live proof we haven't re-run. **"Bring-up"** means the driver
paths exist and per-model validation is expanding. The **public install readiness** column is separate
from mining evidence and should match DCENT_Toolbox readiness output; help from the community is welcome
(see the platform-bring-up issue template).

> **Privacy note on published evidence:** live-capture logs and examples published in this repository
> have operator IP and MAC addresses rewritten to RFC 5737 / documentation values (e.g. `203.0.113.x`)
> as a privacy measure. The captures themselves come from real bench hardware.

## Control-board families

| Family | SoC | Examples | Notes |
| --- | --- | --- | --- |
| **Zynq (am1/am2)** | Xilinx Zynq-7000 (ARMv7) | S9, S17, T17, S19, S19 Pro, S19j Pro (Zynq) | FPGA chain via UIO + `/dev/mem`, no kernel modules |
| **CVITEK (cv183x)** | CVITEK CV183x (Cortex-A53/AArch64) | T19, S19j Pro CV1835 | ARM32 compatibility analysis is in development; runtime ownership and persistent installation are `NOT_IMPLEMENTED`, with no executable install route |
| **Amlogic (am3)** | Amlogic A113D (aarch64) | S19j Pro (AML), S19 XP, S19k Pro, S21 | Serial UART chains, sysfs PWM/GPIO, no FPGA |
| **BeagleBone (am3-bb)** | TI AM335x (ARMv7) | S19j Pro on `S19J_IO_BOARD_V2` | Experimental exact route: serial UART chains plus retained raw-LOW GPIO59/watchdog ownership via the IO board; installed default remains management-only |

## Per-model status

| Miner | ASIC | Board | Mining / driver evidence | Public install readiness |
| --- | --- | --- | --- | --- |
| **Antminer S9** | BM1387 | Zynq | **Mining achieved** — sustained standalone cold-boot mining with accepted pool shares | Lab-gated: Toolbox route exists, public artifact + witnessed live-install capstone still required |
| **Antminer S9 SE** | BM1393 | Ctrl_C43 / XC7Z007S | Exact identity and detect-only evidence; no callable mining runtime | Evidence gap: not the classic S9 install path; no install or recovery-write authority |
| **Antminer S19 Pro** | BM1398 | Zynq | Historical `a lab unit` cold-boot produced 146K nonces at 3x114, but no pool-accepted share was proven; current electrical admission remains fail-closed | Evidence gap: no callable native BM1398 runtime and no customer write route |
| **Antminer S19j Pro** | BM1362 | Zynq | **Mining achieved** — standalone cold-boot mining with accepted pool shares | Guarded DCENT_OS-source self-update only; vendor-source first install remains evidence-gap |
| **Antminer S19j Pro** | BM1362 | BeagleBone | Historical accepted-share/all-chain proof; current retained-GPIO59/watchdog lifecycle is **EXPERIMENTAL**, host-validated, and not bench-revalidated | Lab-gated: installed profile has watchdog disabled and is management-only; authorized temporary-config SD/runtime validation required, not a general NAND/sysupgrade production install |
| **Antminer S21** | BM1368 | Amlogic | **Mining achieved** — sustained hashing with accepted pool shares (runtime path); untested on latest binaries | Lab-gated: runtime evidence exists; stock AMLCtrl in-place install remains blocked |
| **Antminer S17 / S17 Pro** | BM1397 | Zynq | Package/driver evidence retained; current BoardDesc is management-only with no callable mining runtime | Evidence gap: no public install route |
| **Antminer T17** | BM1397 | Zynq | Exact identity and driver evidence retained; current BoardDesc is management-only | Evidence gap: no public install route |
| **Antminer S19** | BM1398 | Zynq | Package/identity evidence retained; current BoardDesc is management-only | Evidence gap: does not inherit S19 Pro install readiness |
| **Antminer T19** | BM1398 | Zynq / CVITEK variants | Exact model evidence exists; chip geometry and runtime admission remain unresolved or management-only | Evidence gap: no public install route |
| **Antminer S19 XP** | BM1366 | Amlogic / CVITEK variants | Exact 3×110 Amlogic package/identity evidence; no runtime PIC/PSU authority | Package-only evidence gap: install/update/recovery writes blocked |
| **Antminer S19j XP** | BM1366 | Amlogic | Exact 3×110 package/identity evidence; no runtime PIC/PSU authority | Package-only evidence gap: install/update/recovery writes blocked |
| **Antminer S19j Pro+ (Amlogic)** | BM1362 | Amlogic | Exact identity/package evidence; TD-003 intercepts before runtime dispatch | Evidence gap: no install route |
| **Antminer S19k Pro** | BM1366 | Amlogic | Track-1 `/tmp` mining live-proven to the bounded 2-of-2 UART work proof (COMPLETE 2026-08-29, share accepted, terminal SafeOff, wrapper exit 0); default-off joined native cold-start owner is host-compiled and source-audited | Lab-only source route: endurance, recovery rehearsal, signed two-build image, install, and cold-boot acceptance evidence pending |
| **Antminer T21** | BM1368 | Amlogic | Exact 3×108 desk geometry and package-format evidence; runtime remains unvalidated | Package-only evidence gap: install/update/recovery writes blocked |
| **Antminer S21 XP** | BM1370 | Amlogic | Exact 3×91 A3HB70501/02/03 topology and package-format evidence; management-only runtime | Package-only evidence gap: install/update/recovery writes blocked |
| **AvalonMiner (Canaan)** | — | K230 RISC-V | In development | Not public-install-ready |
| **WhatsMiner (M-series)** | — | H616 | In development | Not public-install-ready |

## Universal hash-board compatibility

The Zynq-era miners share an 18-pin hash-board connector and UART protocol. DCENT_OS detects the
chip via the ChipID command (`0x1387` = S9, `0x1397/0x1398` = S17/S19, `0x1362` = S19j Pro, etc.)
and loads the right driver. In validated/lab configurations that means an inexpensive S9 control
board can drive supported later-generation hash boards. Treat mixed-generation rigs as
compatibility/lab work until their exact control-board, hash-board, power, and recovery path has a
documented install route.

## Power supplies

DCENT_OS does **not** require a "smart PSU" or a Loki board. Three PSU modes are supported:

- **Bypass** — estimate power from frequency/voltage tables; run any dumb PSU.
- **Auto-Detect** — probe a PMBus-capable PSU for live telemetry.
- **PMBus Monitor** — full telemetry from a smart PSU when present.

APW3 / APW7 / APW12 and generic bench supplies are supported through these modes on proven lanes.
120 V household power is supported via PSU bypass on the appropriate hardware. Amlogic and
BeagleBone PSU-bypass behavior remains live-soak gated; do not infer those lanes from S9/AM2 proof.

## Safety before you flash

- Keep a **known-good recovery path** before flashing experimental firmware.
- On a fresh install DCENT_OS boots **management-only** (dashboard/SSH/API up, hash power off) until
  you explicitly enable mining — a fresh flash will not surprise-start a loud miner.
- For bring-up models, treat results as experimental and report what you find.

See [`INSTALL/`](INSTALL/) for per-platform install procedures and
[`CONFIGURATION.md`](CONFIGURATION.md) for tuning.
