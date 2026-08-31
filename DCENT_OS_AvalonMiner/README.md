# DCENT_OS — Avalon (Canaan) support

**Status: experimental. DCENT_OS does not mine on Avalon hardware yet.**

This directory holds the real Canaan port — board support, boot-chain work, the daemon crates, the
recovery and first-light tooling, and the qualification gauntlets. It is published so the work is
inspectable, not because it is installable. Read the honest status below before you flash anything.

## Layout

| Path | What it is |
|---|---|
| `industrial/` | Canaan industrial line — K230 and K210 controllers (A12xx/A14xx-class, Avalon Q), Nano 3 board support, Buildroot integration, recovery images, K210 BSP firmware, and the qualification gauntlets. |
| `home/` | Canaan home line — Nano 3S HAL/ASIC/daemon crates. |
| `../../shared/dcent-avalon-proto/` | The shared Avalon protocol crate both lines depend on: the `mm_pkg` packet codec, the AUP firmware-container parser, the CGMiner `ascset` vocabulary, and the Nano 3 UART envelope/nonce decoding. |

## Honest status

**What is proven.** On the operator-owned non-S Nano 3, DCENT_OS userspace has been brought up live
through the factory boot chain: a rootfs-only image that preserved SPL/U-Boot/env/Linux/app/data
booted real DCENT userspace, accepted key-only SSH, and passed passive-observer coexistence. Stock
slot restore and the recovery path are proven. Persistence survives reboot.

**What is NOT proven — read this carefully.** During that milestone the miner's ~2.1 TH/s and its
accepted shares were produced by the **stock `btcminer`**, which retained sole ownership of every
hardware-control path. DCENT_OS was a coexisting userspace observer, not the miner.

- **There is no accepted-share proof for DCENT_OS's own mining path on Avalon hardware.** The
  `asic_control` gate is `not_implemented`.
- **Unattended production is closed.** A management/thermal soak failed when application services
  stopped responding while TCP still connected.
- Thermal-sensor custody, watchdog wiring, and fault polarity are unproven on this platform.
- The independent power cutoff and the exact 28 V/5 A path are not qualified.
- Release and safety key pins are empty; the local admission ledger is accidental replay protection,
  not a global authority.
- For some K210 targets, `replacement_firmware` is **blocked by measured incompatibility**, not
  merely unimplemented.

Do not contact, flash, energize, or claim production on the software gates alone. When native Avalon
mining is proven it will be documented with the same evidence ladder the Antminer and ESP platforms
use — upload ≠ mined, connected ≠ mining, partial ≠ proven.

## Building

Both lines cross-compile to RISC-V and path-depend on `../../shared/dcent-avalon-proto` and on the
ESP-family crates in `../../DCENT_OS_ESP/`, so build them from a full checkout of this repo rather
than from a copy of this directory alone.

```bash
cd industrial/dcentrald && cargo build --release
cd home              && cargo build --release
```

## Get involved

Avalon hardware, protocol captures, and contributors are welcome — see the repo root
[`CONTRIBUTING.md`](../../CONTRIBUTING.md). If this work is useful to you, you can support it at
[d-central.tech/fund](https://d-central.tech/fund/). Built by the Mining Hackers at
[D-Central Technologies](https://d-central.tech/).
