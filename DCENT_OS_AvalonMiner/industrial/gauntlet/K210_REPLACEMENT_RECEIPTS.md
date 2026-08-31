# Avalon K210 replacement-firmware receipts

> Legacy schema-1 AES0-only reference. The canonical gauntlet and operator
> workflow now use the route-discriminated schema-2 contract in
> `K210_ROUTE_REPLACEMENT_RECEIPTS.md`. This verifier remains available for
> historical/offline compatibility but is not a production-workflow admission
> path.

This layer admits one clean, reproducible, target-bound DCENT K210 safe-idle
artifact into the `replacement_firmware` gate. It is evidence verification,
not an installer: the tool has no miner, network, serial, USB, programmer,
JTAG, ISP, flash, GPIO, power, cooling, or hashing transport.

An admitted receipt qualifies only `replacement_firmware`. Native ASIC
control, independent thermal/power safety, rollback, mining, endurance, and
release authority remain separate later gates.

## Prerequisite chain

The descriptor must embed the canonical bytes of a valid, positive
`dcent_k210_boot_policy_receipt`. The boot receipt must already exact-join the
same admitted discovery and stock-recovery receipts and must show all three:

- `force_decrypt_state` is `disabled`;
- the controlled AES0 probe booted successfully;
- the measured load-address contract is compatible.

A negative boot-policy receipt remains useful measurement evidence, but it
cannot seed a replacement descriptor.

## Artifact and source contract

The receipt snapshots two completed builds with distinct host and workspace
identities. Both use the same clean source archive but retain independent
build logs and toolchain manifests. The verifier requires byte-identical:

- ELF64 little-endian RISC-V executables with a single file-backed `PT_LOAD`
  at the measured K210 load address;
- raw applications exactly equal to the ELF load bytes;
- AES0 K210 wrappers inside AUP-v2 containers exactly equal to those raw
  applications, including their SHA-256 trailer;
- firmware version and AUP hardware/software tags matching the signed board
  profile; and
- packaged length fitting the measured boot-image region.

The firmware must be classed as `target_bound_safe_idle_runtime`, use a clean
GPL-3.0-only source tree, and include a source archive, source manifest, SPDX
SBOM, license review, and clean-room review. Restricted vendor code and vendor
binary blobs are forbidden.

The board profile must claim the exact required BSP vocabulary and every safe
default: hash power and voltage default off, cooling reaches a safe state
before hash power, watchdog and interrupts fail closed, and startup enters
safe idle. These are signed artifact claims for later hardware validation;
they do not prove physical actuation by themselves.

## Role separation and trust

The builder and reviewer sign the same canonical receipt with distinct
Ed25519 keys and SSHSIG namespaces:

- builder: `dcent-k210-replacement-builder-v1`;
- reviewer: `dcent-k210-replacement-reviewer-v1`.

The canonical manifest intentionally pins neither key. Until reviewed public
keys and their exact SHA-256 IDs are committed under
`replacement_firmware_contract.trust_anchors`, the gauntlet verifies the
schema but rejects every supplied bundle. Both anchors must be added together,
must be role-separated, and must resolve inside the repository.

## Host-only workflow

Generate a descriptor from the canonical positive boot receipt:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_replacement_receipt.py template `
  --boot-policy-receipt evidence/boot-policy/receipt.json `
  --out work/replacement-descriptor.json
```

Replace every placeholder with reviewed facts, produce the two independent
builds, and place each evidence file at the descriptor path. Then snapshot and
sign the immutable bundle:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_replacement_receipt.py create `
  --descriptor work/replacement-descriptor.json `
  --evidence-root work/evidence `
  --builder-private-key keys/builder `
  --reviewer-private-key keys/reviewer `
  --bundle-out evidence/replacement-a1246
```

Direct verification checks the bundle but does not admit it into the gauntlet:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_replacement_receipt.py verify `
  --bundle evidence/replacement-a1246 `
  --builder-public-key trust/builder.pub `
  --reviewer-public-key trust/reviewer.pub
```

After every predecessor and replacement trust anchor is pinned and reviewed,
the complete exact-unit chain is supplied together:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_gauntlet.py check `
  --model a1246 --corpus required `
  --discovery-bundle evidence/discovery-a1246 `
  --fixture-bundle evidence/fixture-a1246 `
  --recovery-bundle evidence/recovery-a1246 `
  --boot-policy-bundle evidence/boot-policy-a1246 `
  --replacement-bundle evidence/replacement-a1246
```

For workflow admission, copy the reviewed bundles into the ignored
`.k210-gauntlet-evidence/<unit>/` transfer root and write a canonical
descriptor such as:

```json
{
  "bundles": {
    "boot_policy_bundle": ".k210-gauntlet-evidence/a1246-unit-01/boot-policy",
    "discovery_bundle": ".k210-gauntlet-evidence/a1246-unit-01/discovery",
    "fixture_bundle": ".k210-gauntlet-evidence/a1246-unit-01/fixture",
    "recovery_bundle": ".k210-gauntlet-evidence/a1246-unit-01/recovery",
    "replacement_bundle": ".k210-gauntlet-evidence/a1246-unit-01/replacement"
  },
  "kind": "dcent_k210_operator_gate_evidence",
  "model": "a1246",
  "schema_version": 1
}
```

Then record the independently reviewed artifact admission:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_unblock_workflow.py complete `
  --lane op-replacement `
  --operator-confirmed `
  --evidence .k210-gauntlet-evidence/a1246-unit-01/op-replacement.json
```

The workflow exact-joins these paths with the earlier semantic receipts,
requires the `replacement_firmware` gate to qualify, and later reconstructs
the same bundle in the terminal production check. It does not qualify release
authority.

No command above grants or performs hardware contact, installation, power or
cooling control, hashing, production release, or future mutation. Those need
separate named-unit authorization and later evidence gates.
