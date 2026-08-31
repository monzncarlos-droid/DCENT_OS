# Route-discriminated K210 replacement-artifact receipts

This schema-2 layer admits a reproducible replacement artifact only after one
explicitly reviewed boot route is bound to exact-unit predecessor evidence.
It is a successor to, not a modification of, the native-AES0 schema-1 receipt
in `k210_replacement_receipt.py`.

The verifier is host-only. It has no miner, network, serial, USB, JTAG, ISP,
programmer, GPIO, flash, block-device, power, cooling, install, hashing, or
release transport. A verified artifact can qualify only the replacement-
firmware artifact gate after integration. It grants no future contact,
hardware, install, mining, release, or production authority. This is the
canonical `replacement_firmware_contract` in `k210_models.json`; schema 1 is a
legacy AES0-only compatibility reference.

## Exact predecessor and route joins

Every bundle contains canonical copies of the signed discovery, recovery, and
boot-policy receipts plus the deterministic boot-route adjudication. The
successor reuses all three receipt schema validators and exact-joins:

- target ID, unit label, and unit fingerprint;
- discovery, recovery, and boot-policy receipt IDs; and
- the admitted stock backup-set digest.

The boot-route adjudication is recomputed from the canonical boot receipt. Its
entire JSON object and adjudication digest must match the copy in the bundle.
Production integration must additionally admit the original predecessor
bundles under their manifest-pinned keys and exact-join their verifier results;
the embedded canonical copies do not replace upstream signature admission.

## Explicit dual-reviewed selection

`route_selection` is covered by both the builder and reviewer SSHSIG
signatures. It contains:

- the recomputed adjudication digest;
- the exact ordered candidate-route set;
- one explicit selected route;
- a printable review basis;
- `builder_approved: true`;
- `reviewer_approved: true`; and
- `automatic_priority_selection_used: false`.

The existing adjudicator's first-ranked route is advisory. The successor never
copies that choice automatically. This is particularly important when native
AES0 and an SRAM transport are both available: an explicitly reviewed SRAM
route may be selected, but only with separate execution qualification.

## Route matrix

| Selected route | Reproducible artifacts | Additional admission proof |
| --- | --- | --- |
| `native_aes0_flash` | Two byte-identical RISC-V ELF, raw, and AES0/AUP-v2 sets | Positive plaintext AES0 boot, matching measured load/flash geometry and held AUP tags |
| `rom_isp_sram_bootstrap` | Two byte-identical RISC-V ELF/raw sets | ROM-ISP route eligibility plus exact load, entry, executable size, trace, and completed SRAM execution qualification |
| `jtag_sram_bootstrap` | Two byte-identical RISC-V ELF/raw sets | JTAG route eligibility plus exact load, entry, executable size, trace, and completed SRAM execution qualification |
| `clean_replacement_controller` | Two byte-identical generic controller artifacts | Exact connector, signal, power, cooling, independent-cutoff, recovery, and aggregate interface qualification |

Artifact dictionaries are route-discriminated and exact-keyed. An AUP in an
SRAM build, an ELF/raw set in a replacement-controller build, or any unused
cross-route evidence is rejected.

### AES0

The receipt requires a positive boot-policy result: force-decrypt disabled, a
successful controlled plaintext probe, and a compatible load contract. Each
ELF must have exactly one executable RISC-V load segment at the measured
address; raw bytes must equal that segment; the AUP must contain those exact
raw bytes and match firmware version, target tags, CRCs, inner SHA-256, and
measured capacity.

### ROM-ISP and JTAG SRAM

Transport accessibility, memory write, or halt capability is not execution
proof. Each SRAM route additionally requires a canonical
`dcent_k210_sram_execution_qualification` record binding:

- selected route, target, and unit fingerprint;
- load and entry address;
- exact executable image size and raw SHA-256;
- execution-trace byte count and SHA-256;
- execution start and safe-idle observation;
- physically disconnected hash power and asserted independent cutoff;
- restored stock state after the probe; and
- `authority_granted: false`.

Missing, copied-from-the-other-route, or semantically incomplete qualification
evidence is rejected.

### Clean replacement controller

No K210 artifact shape or public legacy ASIC protocol is inherited. The route
accepts a declared generic controller artifact format and target only when two
independent builds are byte-identical and an aggregate canonical interface
qualification exact-binds six component evidence files:

- connector mapping;
- signal mapping and levels;
- power envelope;
- cooling custody;
- independent cutoff; and
- recovery interface.

The aggregate record must also bind the controller artifact SHA-256, target
and unit, and assert complete connector mapping, qualified signals/power/
cooling/cutoff/recovery and ASIC interface, with no authority granted.

## Reproducibility and source boundary

All routes require two distinct build IDs, hosts, and workspaces, two build
logs, two toolchain manifests, one clean source archive, source manifest, SPDX
SBOM, license review, and clean-room review. The source archive digest must be
identical across builds. Vendor binary blobs and restricted vendor code are
forbidden; the source tree must be clean and `GPL-3.0-only`.

## Signatures and authority

The canonical receipt is signed by distinct Ed25519 keys and principals:

- builder role: `k210_route_replacement_builder`;
- reviewer role: `k210_route_replacement_reviewer`;
- builder namespace: `dcent-k210-route-replacement-builder-v2`;
- reviewer namespace: `dcent-k210-route-replacement-reviewer-v2`.

Both public keys must be pinned by future manifest integration. Optional
expected key IDs are accepted by direct verification. Exact bundle membership
is enforced; symlinks, special files, traversal paths, unreferenced evidence,
and unsigned extra members are rejected.

The receipt fixes all future authority fields false, including contact, debug,
JTAG/ISP, flash write, installation, power/cooling control, production hashing,
release, and production qualification.

## Host-only commands

Create and sign a completed descriptor and evidence tree:

```powershell
py -3 DCENT_OS_AvalonMiner/scripts/k210_route_replacement_receipt.py create `
  --descriptor work/route-replacement-descriptor.json `
  --evidence-root work/evidence `
  --builder-private-key keys/route-builder `
  --reviewer-private-key keys/route-reviewer `
  --bundle-out evidence/route-replacement-a1246
```

Verify directly:

```powershell
py -3 DCENT_OS_AvalonMiner/scripts/k210_route_replacement_receipt.py verify `
  --bundle evidence/route-replacement-a1246 `
  --builder-public-key trust/route-builder.pub `
  --reviewer-public-key trust/route-reviewer.pub `
  --expected-builder-key-id <sha256> `
  --expected-reviewer-key-id <sha256> `
  --format json
```

## Integration contract

Constants:

- `SCHEMA_VERSION = 2`
- `DESCRIPTOR_KIND = dcent_k210_route_replacement_firmware_descriptor`
- `RECEIPT_KIND = dcent_k210_route_replacement_firmware_receipt`
- `BUILDER_ROLE = k210_route_replacement_builder`
- `REVIEWER_ROLE = k210_route_replacement_reviewer`
- `BUILDER_NAMESPACE = dcent-k210-route-replacement-builder-v2`
- `REVIEWER_NAMESPACE = dcent-k210-route-replacement-reviewer-v2`

`verify_bundle(...)` returns exactly:

- `artifact_set_sha256`;
- `authority_granted` (`false`);
- `boot_policy_receipt_id`;
- `builder_key_id_sha256`;
- `discovery_receipt_id`;
- `interface_qualification_sha256`;
- `receipt_id`;
- `recovery_receipt_id`;
- `replacement_firmware_gate_eligible` (`true`);
- `reviewer_key_id_sha256`;
- `route_adjudication_sha256`;
- `selected_route`;
- `state` (`verified_signed_route_replacement_firmware`);
- `stock_backup_set_sha256`;
- `target_id`;
- `unit_fingerprint_sha256`; and
- `unit_label`.

Future gauntlet integration must pin both new roles, admit and exact-join the
three predecessor results, reject duplicate target receipts, and require the
exact state, eligibility, selected route, adjudication digest, artifact digest,
interface digest, and false authority result. It must not replace or silently
reinterpret existing schema-1 receipts.

## Verification

```powershell
py -3 -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_route_replacement_receipt.py -q
py -3 -m ruff check `
  DCENT_OS_AvalonMiner/scripts/k210_route_replacement_receipt.py `
  DCENT_OS_AvalonMiner/scripts/test_k210_route_replacement_receipt.py
```
