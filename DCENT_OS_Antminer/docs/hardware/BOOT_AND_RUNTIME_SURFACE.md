# Boot and Runtime Surface

Status: `draft` 
Date: 2026-08-11 
Scope: DCENT_OS clean-rewrite boot chain, FPGA access surface, A/B update, and native vs passthrough runtime. 
Disposition: Architectural contract. Not an install runbook and not a live poke guide.

## Purpose

Describe how DCENT_OS boots on Zynq-era control boards, how userspace owns FPGA resources without stock kernel modules, how A/B sysupgrade and recovery interact, how ChipID family detection feeds driver selection, and why native clean-image runtime is the default support contract.

## Confidence vocabulary

| Marker | Meaning |
|---|---|
| `CONFIRMED_PRODUCT` | Encoded in product images, init, or daemon admission |
| `TESTED` | Explicitly exercised on supported routes (still not universal certification) |
| `POLICY` | Explicit DCENT design rule |
| `UNKNOWN` | Not established for the named route |

## Critical design anchors

Drawn from project Critical Design Decisions (paraphrased; secrets and private paths omitted):

1. **Clean rewrite, not a fork** - original codebase; study other firmwares for reference only.
2. **UIO + `/dev/mem`, not stock kernel modules** - no `bitmain_axi.ko` / `fpga_mem_driver.ko` dependency for the clean image.
3. **S9-first research testbed** - Zynq XC7Z010 class hardware for early bring-up; architecture lessons transfer carefully.
4. **SD card boot with proven boot components** - FSBL + U-Boot + FPGA bitstream + kernel paired with DCENT Buildroot rootfs.
5. **A/B firmware sysupgrade** - write inactive NAND slot, patch U-Boot env, reboot; never mutate the running rootfs in place.
6. **Broad ChipID auto-detection** - family detect loads drivers; mixed rigs are not a blanket production promise.
7. **Quiet home mode / cut-hash-before-noise** - thermal philosophy for home operation (detailed in thermal contracts).
8. **Native-first runtime on clean images** - `passthrough` and legacy PIC-boot helpers are compatibility/bring-up paths, not the default contract.
9. **Clean FPGA bitstream required for native drivers** - stock Bitmain flat fabric is a different register/DMA world.

## Clean FPGA access surface (UIO + `/dev/mem`)

`CONFIRMED_PRODUCT` / `TESTED` on supported S9 clean images

### Why not stock modules

Stock Bitmain userspace often maps a flat register aperture and a large DMA window through character devices created by out-of-tree modules. Those modules hardcode physical bases, couple userspace to a specific kernel ABI, and fight a clean ownership model.

DCENT_OS clean images instead:

- expose programmable-logic blocks as `generic-uio` (and related) devices described by the device tree;
- permit carefully fenced `/dev/mem` mappings only through the daemon's hardware-owner boundary;
- refuse parallel opens from dashboard, MCP, login helpers, or diagnostics for I2C, fan/UIO, PSU, GPIO, or chain UART.

### Ownership boundary

`POLICY` / `CONFIRMED_PRODUCT`

- One post-start hardware owner owns mutating transports.
- Normal REST/diagnostics consume daemon snapshots.
- Compatibility mutations fail closed.
- Research/raw executors stay private, feature-gated, and unmounted on product images.
- Cross-process leases (where implemented) are cooperative exclusion on a shared runtime filesystem; they are not a security boundary against a privileged program that ignores the protocol.
- Process death releases locks and does **not** prove rail SafeOff.
- Persistent unresolved hardware-session markers latch across exits because process status is not electrical disposition.

### Competing fabrics

Stock-flat fabric (single register window + DMA character devices) and clean UIO fabric (split fan/chain/IIC/GPIO blocks) are **mutually exclusive admission worlds**. Presence of clean chain UIO devices is a hard refusal for stock-flat preflight routes, and stock-module assumptions are a hard refusal for native clean drivers.

## Zynq SD boot surface

`CONFIRMED_PRODUCT`

Typical supported research/production-bring-up path:

1. SD-visible boot components provide FSBL, U-Boot, FPGA bitstream, and kernel.
2. Buildroot-produced DCENT rootfs supplies `dcentrald`, overlays, and product init.
3. On NAND-capable units, A/B slots hold durable system images while SD remains a recovery/install vector.
4. Device tree must match the clean bitstream's UIO layout; a stock DTB that omits PL nodes cannot identify the clean carrier by itself.

Boot stages operators should reason about:

| Stage | Responsibility | Failure posture |
|---|---|---|
| FSBL / early boot | SoC + DDR bring-up | Hardware/SD recovery |
| U-Boot | Slot selection, env, bootargs | Keep serial/env recovery |
| FPGA bitstream | Clean PL map for UIO | Wrong bitstream ⇒ refuse native |
| Kernel + DTB | UIO nodes, drivers | Missing nodes ⇒ fail closed |
| Rootfs / init | Daemon, leases, boot-commit | Report-only verify vs mutate |

This document does not publish flash recipes, release signing key paths, or private artifact store locations.

## A/B sysupgrade and recovery

`CONFIRMED_PRODUCT` / `TESTED` on documented round-trips

### Happy path

1. Verify image identity and board applicability offline.
2. Write the payload to the **inactive** NAND slot only.
3. Patch U-Boot environment to select the inactive slot on next boot.
4. Reboot into the new slot.
5. Boot-commit authority remains a single durable init path; verification helpers are report-only and must not raw-fallback into mutation.

### Failure and recovery posture

`POLICY`

- Failed-boot recovery is platform/runbook-gated.
- Keep serial and/or SD recovery available unless rollback has been proven for that exact route.
- Sysupgrade must serialize against unresolved hardware-session admission and refuse crash-latched state before inactive-slot mutation.
- Manual environment rollback can select a slot with independent or older persistent data; typed boot/platform journals remain future work.
- Unresolved hardware-session markers fail closed: process exit is not physical SafeOff evidence.
- Forced stop latches before destructive kill paths so watchdogs/dashboard/MCP cannot silently re-admit.

### What A/B deliberately does not do

- Modify the running rootfs in place
- Claim electrical SafeOff by slot switch alone
- Auto-promote experimental boards without identity proofs
- Embed operator credentials into the image stream

## ChipID family detect at runtime

`CONFIRMED_PRODUCT`

During bring-up, after fabric/lease admission and before work dispatch:

1. Determine control-board class and chain UART topology.
2. Issue family ChipID / register-zero style probes under the admitted protocol.
3. Map observed family word to a driver candidate.
4. Require exact agreement with declared board protocol and engine requirement.
5. Publish chips only from a freshly flushed, successfully queried, exact unique post-assignment address plan where the route demands it.

Response-frame count is not population. Passthrough without a typed external-init handoff is refused on native routes.

### Family detect versus mining permit

ChipID success is necessary for native routes and still insufficient:

- thermal/fan brokers and PSU/guard order must precede energization where the product requires it;
- address plans and work codecs must exist for that family;
- experimental families remain non-default even when the ID is recognized.

## Native vs passthrough

| Mode | Intent | Default on clean images? | Mutation posture |
|---|---|---|---|
| **Native** | DCENT owns PIC/NoPic bring-up, heartbeat, work codec, thermal/fan brokers | Yes | Fail-closed, single owner |
| **Passthrough** | Compatibility with legacy/derived environments that already initialized hardware | No | Non-default; requires explicit handoff; must not silently claim native authority |
| **Legacy PIC-boot helpers** | Bring-up / recovery aids | No | Feature-gated; not the support contract |

`POLICY`: native-first means docs, dashboards, and support matrices describe native behavior. Passthrough bugs are compatibility debt, not blockers for the clean-image default.

### Handoff requirements for passthrough

If a compatibility environment must be supported temporarily:

- external init must produce a typed handoff object;
- native constructors must refuse to invent missing bring-up evidence;
- teardown still attempts checked safe-off / join / fence paths even when watchdog acknowledgement is lost;
- support matrices must label the route as compatibility, not clean-image default.

## Runtime surfaces operators may observe

Safe, non-secret surfaces (names only):

- UIO device nodes for fan, chain, and related PL blocks on clean images
- daemon snapshot APIs for temperatures, tach, chain status
- A/B slot status and boot-commit verification reports
- ChipID family / board target as displayed by diagnostics

Unsafe / out-of-contract for product images:

- ad-hoc `devmem` from shells while the daemon owns the fabric
- loading stock Bitmain out-of-tree modules beside clean UIO
- parallel I2C tools against managed PIC/PSU addresses
- treating passthrough as "native but easier"
- using research REST bodies that product images deliberately unmount

## Init and service topology (names only)

Product images typically separate:

- early hardware-session admission helpers
- `dcentrald` as the mutating owner
- report-only verification services
- upgrade/boot-commit services that never become a second hardware owner

Exact script names may evolve; the load-bearing rule is **one mutating owner** plus fail-closed admission.

## Confidence and gaps

Solid:

- UIO+/dev/mem clean rewrite decision and single hardware-owner boundary
- A/B inactive-slot write policy and boot-commit authority split
- native-first vs passthrough policy
- ChipID exact-agreement admission
- competing fabric refusal

Open:

- full crash-surviving disposition journals across power loss
- every platform's failed-boot automatic rollback proof
- physical pin/rail proof beyond register readback for all reset routes
- production certification matrix per CB/HB/PSU tuple
- pre-userspace GPIO containment on every Amlogic/Zynq variant

## Related contracts

- `HASHBOARD_IDENTITY.md` - what must agree before bring-up
- `ASIC_WIRE_CONTRACT.md` - wire facts after admission
- `STOCK_PARITY_BEHAVIOR.md` - stock thermal/fan outcomes not to mis-import

## Intentionally omitted

- Wi-Fi SSIDs/passwords and payout worker strings
- Release/signing private-key paths and pubkey pins beyond public docs
- Private corpus paths, firmware blobs, and personal workspace paths
- Fleet inventory, live unit IDs, IPs, and MACs
- MMIO poke scripts, unlock/sig-bypass recipes, and Konduit never-publish claims
