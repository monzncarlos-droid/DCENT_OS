# Route-aware K210 rollback receipts

This schema-2 host-only layer qualifies a completed rollback drill for one
explicitly selected schema-2 replacement route. It imports and validates
`k210_route_replacement_receipt.py`, then exact-joins canonical copies of the
discovery, recovery, boot-policy, recomputed route adjudication, and
route-replacement receipts. Target, unit label/fingerprint, all predecessor
IDs, stock backup-set digest, selected route, route-adjudication digest,
artifact-set digest, and interface-qualification digest must agree.

The embedded canonical predecessor copies preserve exact joins and allow
deterministic semantic verification. They do not replace admission of the
original signed predecessor bundles under manifest-pinned keys. Integration
must admit those bundles separately and compare their verifier results.

## Route-specific rollback contract

All routes require a controlled interruption, recovery through the previously
admitted `external_memory_programmer` path, byte-exact full stock-flash
readbacks against every admitted baseline image, a stock cold boot, exact
stock identity, candidate-artifact absence, and no clobber.

| Selected route | Required route evidence |
| --- | --- |
| `native_aes0_flash` | Interrupted AES0 update, nonzero update progress, full stock restore, and byte-exact post-restore readback |
| `rom_isp_sram_bootstrap` | Bootstrap abort, route-matched volatile SRAM reset, unchanged full stock flash, stock cold boot, and `candidate_persisted_to_flash: false` |
| `jtag_sram_bootstrap` | Bootstrap abort, route-matched volatile SRAM reset, unchanged full stock flash, stock cold boot, and `candidate_persisted_to_flash: false` |
| `clean_replacement_controller` | Safe replacement-controller disconnect, power/signal isolation, exact stock-controller reconnection, unchanged stock flash, and stock cold boot |

Cross-route evidence is rejected. The SRAM reset must use the selected
transport. Controller disconnect/reconnect records bind the selected artifact
and exact interface-qualification digest. Semantic JSON evidence is canonical
and exact-keyed; assertion-only or accessibility-only substitutes do not pass.

`artifact_set_sha256` is the exact qualified candidate artifact-set identity
inherited from route-replacement schema 2. It is not an installed-artifact
claim. `no_clobber_sha256` canonically binds that identity, selected route,
interface and adjudication joins, stock identity, route assertions,
artifact-absence/no-clobber assertions, and all post-rollback readback hashes.
`stock_restoration_sha256` separately binds the byte-exact restoration set.

## Signatures and authority

The canonical receipt is signed by distinct Ed25519 operator and witness keys
and principals using SSHSIG:

- operator role: `k210_route_rollback_operator`;
- witness role: `k210_route_rollback_witness`;
- operator namespace: `dcent-k210-route-rollback-operator-v2`; and
- witness namespace: `dcent-k210-route-rollback-witness-v2`.

Exact bundle membership is enforced. Traversal paths, links, special files,
unsigned extras, evidence splices, duplicate roles, and unexpected route
evidence fail closed. Every future authority field remains false. A verified
receipt is past rollback evidence only; it grants no hardware contact, debug,
JTAG/ISP access, flash write, install, power/cooling control, production
hashing, qualification, release, or future rollback authority.

## Host-only commands

Create and sign a completed descriptor and evidence tree:

```powershell
py -3 DCENT_OS_AvalonMiner/scripts/k210_route_rollback_receipt.py create `
  --descriptor work/route-rollback-descriptor.json `
  --evidence-root work/evidence `
  --operator-private-key keys/route-rollback-operator `
  --witness-private-key keys/route-rollback-witness `
  --bundle-out evidence/route-rollback-a1246
```

Verify directly:

```powershell
py -3 DCENT_OS_AvalonMiner/scripts/k210_route_rollback_receipt.py verify `
  --bundle evidence/route-rollback-a1246 `
  --operator-public-key trust/route-rollback-operator.pub `
  --witness-public-key trust/route-rollback-witness.pub `
  --expected-operator-key-id <sha256> `
  --expected-witness-key-id <sha256> `
  --format json
```

## Integration contract

Constants:

- `SCHEMA_VERSION = 2`
- `DESCRIPTOR_KIND = dcent_k210_route_rollback_descriptor`
- `RECEIPT_KIND = dcent_k210_route_rollback_receipt`
- `DISPOSITION = past_route_rollback_evidence_only_no_future_authority`
- `OPERATOR_ROLE = k210_route_rollback_operator`
- `WITNESS_ROLE = k210_route_rollback_witness`
- `OPERATOR_NAMESPACE = dcent-k210-route-rollback-operator-v2`
- `WITNESS_NAMESPACE = dcent-k210-route-rollback-witness-v2`

`verify_bundle(...)` returns exactly:

- `artifact_set_sha256`;
- `authority_granted` (`false`);
- `boot_policy_receipt_id`;
- `discovery_receipt_id`;
- `interface_qualification_sha256`;
- `no_clobber_sha256`;
- `operator_key_id_sha256`;
- `receipt_id`;
- `recovery_receipt_id`;
- `rollback_recovery_gate_eligible` (`true`);
- `route_adjudication_sha256`;
- `route_replacement_receipt_id`;
- `selected_route`;
- `state` (`verified_signed_route_rollback`);
- `stock_backup_set_sha256`;
- `stock_restoration_sha256`;
- `target_id`;
- `unit_fingerprint_sha256`;
- `unit_label`; and
- `witness_key_id_sha256`.

Integration must exact-join every cumulative ID and digest, require the exact
state, selected route, eligibility, and false authority, and reject duplicate
target/unit receipts. Physical bench or endurance evidence may bind its own
installed-artifact identity to `artifact_set_sha256`; this receipt itself does
not assert installation.

## Verification

```powershell
py -3 -m pytest -p no:cacheprovider `
  DCENT_OS_AvalonMiner/scripts/test_k210_route_rollback_receipt.py -q
py -3 -m ruff check `
  DCENT_OS_AvalonMiner/scripts/k210_route_rollback_receipt.py `
  DCENT_OS_AvalonMiner/scripts/test_k210_route_rollback_receipt.py
```

The focused suite covers successful AES0, ROM-ISP, JTAG, and clean-controller
rollbacks plus cross-route, cross-unit, persistence, no-clobber, interruption,
readback, predecessor/digest splice, signer, path, and exact-member attacks.
