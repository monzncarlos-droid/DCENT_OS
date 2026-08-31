# Avalon K210 exact-route rollback receipts

> Legacy schema-1 AES0-only reference. The canonical gauntlet and operator
> workflow use the schema-2 four-route contract documented in
> `K210_ROUTE_ROLLBACK_RECEIPTS.md`.

This layer records a completed, witnessed rollback qualification for one exact
K210 unit and one evidence-selected replacement route. It is a host-only
evidence verifier, not an installer: the tool has no miner, network, serial,
USB, JTAG, ISP, programmer, GPIO, flash, block-device, power, cooling, hashing,
or release transport.

A verified receipt may be integrated into the `rollback_recovery` gate. It
does not qualify replacement firmware, thermal/power safety, ASIC control,
bench mining, endurance, release, or production readiness. It grants no future
contact or mutation authority.

## Schema-v1 boundary

Schema v1 supports only `native_aes0_flash`. This is deliberate: the current
replacement-firmware receipt admits only a positive native AES0 artifact.
ROM-ISP SRAM, JTAG SRAM, and clean replacement-controller rollback must remain
blocked until their route-specific artifact, install, persistence, and stock
return semantics have separate evidence-backed receipt contracts. They are not
coerced into the native-flash model.

The route adjudication remains non-installable and non-authorizing. A rollback
receipt proves that an independently authorized past ceremony completed; it
does not turn the route adjudication into installation authority.

## Exact predecessor chain

The signed bundle contains canonical copies of all five predecessor records:

1. exact-unit discovery receipt;
2. dual-signed stock-recovery receipt;
3. dual-signed boot-policy receipt;
4. dual-signed replacement-firmware receipt; and
5. deterministic boot-route adjudication.

The verifier reuses each predecessor schema validator. Target ID, unit label,
unit fingerprint, discovery/recovery/boot/replacement receipt IDs, stock backup
set, and stock identity must exact-join. The route adjudication is recomputed
from the canonical boot-policy receipt and must match byte-for-byte as a JSON
object. A copied route choice or digest is not trusted.

The predecessor copies do not independently re-prove their original SSHSIG
signatures. Integration must also admit the original predecessor bundles under
their manifest-pinned role keys and exact-join their verifier results to the
rollback result. The rollback copy validation prevents schema or identity
splicing inside this bundle; upstream admission establishes the predecessor
signatures.

## Required completed evidence

The descriptor and resulting receipt bind:

- a semantic observation of the exact replacement artifact running before
  rollback, including replacement receipt ID, artifact-set digest, selected
  route, target, and unit fingerprint;
- the admitted recovery restore path used for the normal rollback;
- a semantic rollback log with no faults or stops;
- a full-device readback for every flash device in the recovery receipt;
- a cold stock boot and exact stock identity match after rollback;
- explicit absence of the replacement artifact after stock restoration;
- an interruption before the attempted stock restore completes;
- recovery through the other independently admitted restore path;
- a second complete set of full-device readbacks after interruption recovery;
  and
- a second cold stock boot and exact stock identity match.

Every readback byte count and SHA-256 must equal an admitted
`stock_backup_image` from the signed recovery receipt and must cover the full
declared device capacity. Boolean claims alone cannot substitute for matching
readback bytes.

JSON observation records are canonical and semantically exact. Arbitrary
hashed sentinel files such as `{ "passed": true }` are rejected. Extra bundle
members and unreferenced evidence are also rejected.

## Authorization and chronology

The signed descriptor names a bounded authorization window and the exact past
actions:

- `controlled_rollback_interruption`;
- `exact_route_stock_restore`;
- `full_flash_readback`;
- `power_cycle_for_stock_validation`;
- `replacement_artifact_identity_check`; and
- `stock_identity_verification`.

The qualification start, completion, and every evidence acquisition timestamp
must fall inside that window. The authorization is evidence about the
completed ceremony only. The receipt fixes every future authority field false,
including contact, debug, JTAG/ISP, flash write, install, power/cooling,
production hashing, release, and production qualification.

## Role separation and signatures

The operator and witness sign the same canonical receipt with distinct
Ed25519 SSHSIG keys and principals:

- operator role: `k210_rollback_operator`;
- witness role: `k210_rollback_witness`;
- operator namespace: `dcent-k210-rollback-operator-v1`;
- witness namespace: `dcent-k210-rollback-witness-v1`.

The two key IDs must be distinct. Direct verification accepts optional expected
key IDs. Production integration must pin both public keys in the manifest and
pass those IDs to `verify_bundle`; this file does not add or authorize trust
anchors.

## Host-only workflow

Generate a descriptor from canonical predecessor receipts and a canonical
route adjudication:

```powershell
py -3 DCENT_OS_AvalonMiner/scripts/k210_rollback_receipt.py template `
  --discovery-receipt evidence/discovery/receipt.json `
  --recovery-receipt evidence/recovery/receipt.json `
  --boot-policy-receipt evidence/boot-policy/receipt.json `
  --replacement-receipt evidence/replacement/receipt.json `
  --route-adjudication evidence/route.json `
  --out work/rollback-descriptor.json
```

The template names every required evidence file. Copy the exact predecessor
records into those paths, replace all placeholders with completed ceremony
facts, and populate the semantic records and full readbacks. Then snapshot and
sign the immutable bundle:

```powershell
py -3 DCENT_OS_AvalonMiner/scripts/k210_rollback_receipt.py create `
  --descriptor work/rollback-descriptor.json `
  --evidence-root work/evidence `
  --operator-private-key keys/rollback-operator `
  --witness-private-key keys/rollback-witness `
  --bundle-out evidence/rollback-a1246
```

Direct verification checks the rollback signatures, evidence bytes, semantic
records, predecessor copies, route reproduction, stock readbacks, and exact
bundle membership:

```powershell
py -3 DCENT_OS_AvalonMiner/scripts/k210_rollback_receipt.py verify `
  --bundle evidence/rollback-a1246 `
  --operator-public-key trust/rollback-operator.pub `
  --witness-public-key trust/rollback-witness.pub `
  --expected-operator-key-id <sha256> `
  --expected-witness-key-id <sha256> `
  --format json
```

## Integration contract

Python constants:

- `SCHEMA_VERSION = 1`
- `DESCRIPTOR_KIND = dcent_k210_exact_route_rollback_descriptor`
- `RECEIPT_KIND = dcent_k210_exact_route_rollback_receipt`
- `OPERATOR_ROLE = k210_rollback_operator`
- `WITNESS_ROLE = k210_rollback_witness`
- `OPERATOR_NAMESPACE = dcent-k210-rollback-operator-v1`
- `WITNESS_NAMESPACE = dcent-k210-rollback-witness-v1`
- `SUPPORTED_ROUTES = {native_aes0_flash}`

`verify_bundle(...)` returns these exact fields:

- `authority_granted` (`false`);
- `boot_policy_receipt_id`;
- `discovery_receipt_id`;
- `operator_key_id_sha256`;
- `receipt_id`;
- `recovery_receipt_id`;
- `replacement_firmware_receipt_id`;
- `rollback_recovery_gate_eligible` (`true`);
- `route_adjudication_sha256`;
- `selected_route`;
- `state` (`verified_signed_exact_route_rollback`);
- `stock_backup_set_sha256`;
- `stock_restoration_sha256`;
- `target_id`;
- `unit_fingerprint_sha256`;
- `unit_label`; and
- `witness_key_id_sha256`.

The gate integration must reject missing predecessor results, any cross-result
join mismatch, unpinned rollback keys, duplicate rollback receipts for one
target, `authority_granted != false`, or a state/eligibility mismatch. It must
not infer install or release authority from `rollback_recovery_gate_eligible`.

## Verification

```powershell
py -3 -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_rollback_receipt.py -q
py -3 -m ruff check `
  DCENT_OS_AvalonMiner/scripts/k210_rollback_receipt.py `
  DCENT_OS_AvalonMiner/scripts/test_k210_rollback_receipt.py
```
