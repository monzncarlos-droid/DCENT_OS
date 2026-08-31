# K210 gauntlet trust-anchor ceremony

The canonical manifest intentionally begins fail-closed: all 24 trust anchors
are `null`, so no signed discovery, fixture, capture, recovery, boot-policy,
replacement, rollback, staged bench, or release bundle can be admitted. This
host-only ceremony generates and pins the role-separated public keys. It does
not authorize hardware contact, installation, mining, fault injection, or
release.

Private keys never enter this repository. Perform the ceremony on a controlled
host, retain the reviewed manifest change and ceremony receipt, and keep an
offline custody record for every private key.

## Canonical 24-role inventory

The manifest, verifier constants, and this table must agree exactly. Every row
uses a separately generated Ed25519 key, a unique repository public-key path, a
unique role string, and a unique SSHSIG namespace.

| # | Anchor name | Manifest field | Pinned role | SSHSIG namespace |
| ---: | --- | --- | --- | --- |
| 1 | `discovery.signer` | `discovery_contract.trust_anchor` | `k210_discovery_observer` | `dcent-k210-discovery-v1` |
| 2 | `fixture.operator` | `fixture_contract.trust_anchors.operator` | `k210_fixture_operator` | `dcent-k210-fixture-operator-v1` |
| 3 | `fixture.reviewer` | `fixture_contract.trust_anchors.reviewer` | `k210_fixture_ee_reviewer` | `dcent-k210-fixture-reviewer-v1` |
| 4 | `capture.operator` | `capture_contract.trust_anchors.operator` | `k210_capture_operator` | `dcent-k210-capture-operator-v1` |
| 5 | `capture.reviewer` | `capture_contract.trust_anchors.reviewer` | `k210_capture_reviewer` | `dcent-k210-capture-reviewer-v1` |
| 6 | `recovery.operator` | `recovery_contract.trust_anchors.operator` | `k210_recovery_operator` | `dcent-k210-recovery-operator-v1` |
| 7 | `recovery.witness` | `recovery_contract.trust_anchors.witness` | `k210_recovery_witness` | `dcent-k210-recovery-witness-v1` |
| 8 | `boot_policy.operator` | `boot_policy_contract.trust_anchors.operator` | `k210_boot_policy_operator` | `dcent-k210-boot-operator-v1` |
| 9 | `boot_policy.witness` | `boot_policy_contract.trust_anchors.witness` | `k210_boot_policy_witness` | `dcent-k210-boot-witness-v1` |
| 10 | `replacement_firmware.builder` | `replacement_firmware_contract.trust_anchors.builder` | `k210_route_replacement_builder` | `dcent-k210-route-replacement-builder-v2` |
| 11 | `replacement_firmware.reviewer` | `replacement_firmware_contract.trust_anchors.reviewer` | `k210_route_replacement_reviewer` | `dcent-k210-route-replacement-reviewer-v2` |
| 12 | `rollback.operator` | `rollback_contract.trust_anchors.operator` | `k210_route_rollback_operator` | `dcent-k210-route-rollback-operator-v2` |
| 13 | `rollback.witness` | `rollback_contract.trust_anchors.witness` | `k210_route_rollback_witness` | `dcent-k210-route-rollback-witness-v2` |
| 14 | `bench_endurance.first_light_operator` | `bench_endurance_contract.trust_anchors.first_light_operator` | `k210_first_light_operator` | `dcent-k210-first-light-operator-v1` |
| 15 | `bench_endurance.first_light_protocol_reviewer` | `bench_endurance_contract.trust_anchors.first_light_protocol_reviewer` | `k210_first_light_protocol_reviewer` | `dcent-k210-first-light-protocol-reviewer-v1` |
| 16 | `bench_endurance.first_light_safety_reviewer` | `bench_endurance_contract.trust_anchors.first_light_safety_reviewer` | `k210_first_light_ee_safety_reviewer` | `dcent-k210-first-light-ee-safety-reviewer-v1` |
| 17 | `bench_endurance.bench_operator` | `bench_endurance_contract.trust_anchors.bench_operator` | `k210_bench_mining_operator` | `dcent-k210-bench-mining-operator-v1` |
| 18 | `bench_endurance.bench_witness` | `bench_endurance_contract.trust_anchors.bench_witness` | `k210_bench_mining_witness` | `dcent-k210-bench-mining-witness-v1` |
| 19 | `bench_endurance.endurance_operator` | `bench_endurance_contract.trust_anchors.endurance_operator` | `k210_endurance_operator` | `dcent-k210-endurance-operator-v1` |
| 20 | `bench_endurance.endurance_witness` | `bench_endurance_contract.trust_anchors.endurance_witness` | `k210_endurance_witness` | `dcent-k210-endurance-witness-v1` |
| 21 | `release.preauthorizer` | `release_contract.trust_anchors.preauthorizer` | `k210_release_preauthorizer` | `dcent-k210-release-preauthorizer-v1` |
| 22 | `release.reviewer` | `release_contract.trust_anchors.reviewer` | `k210_release_reviewer` | `dcent-k210-release-reviewer-v1` |
| 23 | `release.installer` | `release_contract.trust_anchors.installer` | `k210_release_installer` | `dcent-k210-release-installer-v1` |
| 24 | `release.witness` | `release_contract.trust_anchors.witness` | `k210_release_install_witness` | `dcent-k210-release-install-witness-v1` |

## Generate and inspect each key

Use a unique private-key basename for every row. For example:

```powershell
$KeyRoot = 'C:\secure\dcent-k210'
New-Item -ItemType Directory -Path $KeyRoot -ErrorAction Stop
ssh-keygen -t ed25519 -a 100 -f "$KeyRoot\discovery-observer" -C 'k210_discovery_observer'
ssh-keygen -lf "$KeyRoot\discovery-observer.pub" -E sha256
```

Repeat with 23 other basenames. Never copy, derive, or reuse a private key for
another row. Record the custodian, principal, creation time, public-key
fingerprint, offline backup location, and revocation contact. A human principal
may fill only a role explicitly assigned by the reviewed ceremony plan.

Copy only public keys to unique repository paths beneath
`DCENT_OS_AvalonMiner/gauntlet/trust/`. Use descriptive names such as
`route-replacement-builder.pub`, `first-light-safety-reviewer.pub`, and
`release-install-witness.pub`. Do not overwrite an existing key during
rotation; use a dated new path.

The manifest key ID is the verifier's SHA-256 of the canonical one-line OpenSSH
public key bytes, not the private key, filename, comment, or the base64 text by
itself. After editing, the gauntlet independently reads every public key and
requires the declared ID to match its bytes.

## Reviewed manifest proposal

For each row replace `null` with exactly this object shape:

```json
{
  "key_id_sha256": "<64-lowercase-hex-canonical-public-key-id>",
  "path": "DCENT_OS_AvalonMiner/gauntlet/trust/<unique-role>.pub",
  "role": "<exact-role-from-the-table>"
}
```

Change each contract state in the same reviewed edit:

| Contract | Unpinned state | Pinned state |
| --- | --- | --- |
| discovery | `signed_read_only_schema_no_trust_anchor` | `signed_read_only_receipt_admission` |
| fixture | `dual_signed_schema_no_trust_anchors` | `dual_signed_fixture_admission` |
| capture | `dual_signed_schema_no_trust_anchors` | `dual_signed_p1_capture_admission` |
| recovery | `dual_signed_schema_no_trust_anchors` | `dual_signed_stock_recovery_admission` |
| boot policy | `dual_signed_schema_no_trust_anchors` | `dual_signed_boot_policy_admission` |
| route replacement | `dual_signed_schema_no_trust_anchors` | `dual_signed_route_replacement_admission` |
| route rollback | `dual_signed_schema_no_trust_anchors` | `dual_signed_route_rollback_admission` |
| bench/endurance | `multi_stage_signed_schema_no_trust_anchors` | `multi_stage_signed_bench_endurance_admission` |
| release | `four_role_signed_schema_no_trust_anchors` | `four_role_signed_release_admission` |

All anchors within one multi-role contract must be pinned or absent together.
For `op-ceremony`, all nine contracts and all 24 roles must be pinned. The
gauntlet rejects any repeated key ID, public-key path, or role globally, not
merely within sibling pairs.

## Verify the proposal

From the workspace root run:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_gauntlet.py verify --corpus required
python -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_gauntlet.py -q
python -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_unblock_workflow.py -q
```

This verifies manifest shape, key bytes, role separation, verifier boundaries,
and held corpus. It contacts no hardware. Do not proceed if any role is absent,
any path escapes the repository, any key or role repeats, a contract is only
partially pinned, or the held corpus is unavailable.

## Ceremony receipt

Hash the exact reviewed bytes of
`DCENT_OS_AvalonMiner/gauntlet/k210_models.json`. Create a strict JSON object
with no extra fields:

```json
{
  "anchors": {
    "bench_endurance.bench_operator": "<key-id>",
    "bench_endurance.bench_witness": "<key-id>",
    "bench_endurance.endurance_operator": "<key-id>",
    "bench_endurance.endurance_witness": "<key-id>",
    "bench_endurance.first_light_operator": "<key-id>",
    "bench_endurance.first_light_protocol_reviewer": "<key-id>",
    "bench_endurance.first_light_safety_reviewer": "<key-id>",
    "boot_policy.operator": "<key-id>",
    "boot_policy.witness": "<key-id>",
    "capture.operator": "<key-id>",
    "capture.reviewer": "<key-id>",
    "discovery.signer": "<key-id>",
    "fixture.operator": "<key-id>",
    "fixture.reviewer": "<key-id>",
    "recovery.operator": "<key-id>",
    "recovery.witness": "<key-id>",
    "release.installer": "<key-id>",
    "release.preauthorizer": "<key-id>",
    "release.reviewer": "<key-id>",
    "release.witness": "<key-id>",
    "replacement_firmware.builder": "<key-id>",
    "replacement_firmware.reviewer": "<key-id>",
    "rollback.operator": "<key-id>",
    "rollback.witness": "<key-id>"
  },
  "kind": "dcent_k210_trust_anchor_ceremony_receipt",
  "manifest": "DCENT_OS_AvalonMiner/gauntlet/k210_models.json",
  "manifest_sha256": "<sha256-of-exact-manifest-bytes>",
  "schema_version": 1
}
```

The orchestrator derives this inventory dynamically from every manifest
`trust_anchor` and `trust_anchors` field. It exact-matches all names and IDs,
requires 24 distinct IDs, paths, and roles, re-runs the gauntlet, and binds the
receipt to the current manifest bytes. A stale or hand-shortened list fails.

Record `op-ceremony` only after independent review:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_unblock_workflow.py complete `
  --lane op-ceremony --operator-confirmed --evidence <ceremony-receipt.json>
```

## Custody and rotation

- Repository: public keys only.
- Controlled signer host or hardware token: private keys and passphrases.
- Offline custody log: principal, assigned role, key ID, creation, backups,
  access events, compromise status, and rotation history.
- Receipt bundles: immutable evidence and signatures; never private keys.

If any private key, signer host, or role assignment is suspect, stop admitting
new receipts for that role. Generate a new key, publish it at a new path, update
the exact manifest anchor and state under review, rerun all verification, and
record the old/new IDs and affected receipts. Previously signed bundles remain
historical evidence but do not silently inherit trust under the new key.

Pinning keys changes only signature admission. Every receipt retains its own
authority ceiling, and no ceremony result authorizes contact or production.
