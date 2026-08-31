# A1246 first-light, bench-mining, and endurance receipts

## Authority boundary

**NO-GO for any live action from this document or its verifier.** Every power,
cooling, install, pool, hash-enable, reboot, fault-injection, rollback, or stock
restore action requires a separately reviewed authorization for the exact unit,
time window, limits, and emergency-stop owner.

`scripts/k210_bench_endurance_receipt.py` is host-only. It reads completed
evidence, snapshots it, verifies semantic joins, and signs canonical receipt
bytes. It contains no miner, network, pool, serial, USB, GPIO, flash, power,
cooling, install, process-control, or fault-injection transport. A receipt
records past observations and grants no future authority.

## Three immutable stages

The module emits three independent bundle types under one schema. A later
stage cannot rewrite or retroactively absorb an earlier stage:

1. `first_light` — staged safe idle, then cooling, independent cutoff,
   watchdog, and sensor-freshness confirmation before hash enable; only then a
   bounded isolated-pool first share and safe shutdown/stock return.
2. `bounded_bench_mining` — exact-joins a passing `first_light` receipt as its
   immediate predecessor, then records bounded mining, accepted shares,
   telemetry, configuration persistence, controlled reboot, and stock return.
3. `fault_endurance` — exact-joins a passing `bounded_bench_mining` receipt as
   its immediate predecessor, then records the required injected-fault matrix,
   a six-hour-minimum four-phase endurance run, and stock return.

The stage order is enforced by receipt kind, class, receipt ID, exact target
joins, passing outcome, and predecessor gate result. Adjacent stages must use
different signing keys. Workflow integration should independently verify the
original predecessor bundles before admitting the copied receipt IDs.

## Exact predecessor chain

Every stage contains one canonical copy of each of these receipts:

- discovery;
- fixture qualification;
- P1 passive capture;
- stock recovery;
- boot policy;
- route-discriminated replacement firmware schema 2;
- witnessed route-rollback qualification schema 2.

The verifier structurally validates every copy through its owning receipt
module and exact-joins:

- target ID, unit label, and unit fingerprint across every layer;
- discovery, fixture, capture, recovery, boot-policy, route-replacement, and
  route-rollback receipt IDs;
- fixture evidence-set and variant-profile IDs;
- P1 capture-set SHA-256;
- stock backup-set SHA-256;
- selected-route artifact-set and interface-qualification SHA-256 values;
- the physically observed installed artifact SHA-256 to the selected deployable
  member: AES0 AUP, ROM-ISP/JTAG raw SRAM image, or clean-controller artifact;
- route/adjudication, stock-restoration, and no-clobber evidence back to the
  same recovery, boot, route-replacement, stock backup, and unit;
- the aggregate artifact set separately from the deployable member digest.

All four canonical routes are accepted when their own schema-2 evidence passes:
`native_aes0_flash`, `rom_isp_sram_bootstrap`, `jtag_sram_bootstrap`, and
`clean_replacement_controller`. No route is inferred from a filename or an AUP
assumption.

Generic A1246 labels, mixed units, replacement artifacts outside the admitted
set, stale predecessor IDs, and skipped stage receipts fail closed.

### Rollback integration record

The copies consumed here are validated by the canonical schema-2 contracts:

- `scripts/k210_route_replacement_receipt.py`, kind
  `dcent_k210_route_replacement_firmware_receipt`;
- `scripts/k210_route_rollback_receipt.py`, kind
  `dcent_k210_route_rollback_receipt`;
- `route_replacement_receipt_id`, `selected_route`,
  `route_adjudication_sha256`, `artifact_set_sha256`, and
  `interface_qualification_sha256` exact-join both copies;
- `stock_restoration_sha256` binds all restored readback identities;
- `no_clobber_sha256` binds the route assertions, artifact absence,
  no-clobber result, stock identity, and readback evidence;
- discovery, recovery, boot-policy, stock-backup, target, unit, and fingerprint
  joins remain exact.

The bench/endurance module delegates both route selection/artifact semantics
and rollback/no-clobber semantics to those canonical validators. It does not
maintain shadow predecessor schemas.

The workflow must verify the original signed route-replacement and
route-rollback bundles separately; the bench/endurance signatures bind their
canonical receipt copies and IDs but do not replace either predecessor's
signature checks.

## Evidence inventory

All evidence is duplicate-free canonical JSON. Arbitrary bytes, opaque logs,
unparsed images, and unredacted pool credentials cannot satisfy this contract.
Every kind occurs exactly once.

All stages require:

- the seven predecessor receipt copies;
- `authorization_record`;
- `session_log`;
- `safety_record`;
- `cooling_telemetry_record`;
- `cutoff_telemetry_record`;
- `runtime_telemetry_record`;
- `pool_session_record` with credentials removed;
- `share_accounting_record` with pool/client accepted-share agreement.

Class-specific evidence:

- `first_light`: `first_light_record`;
- `bounded_bench_mining`: `prior_first_light_receipt_copy` and
  `bounded_mining_record`;
- `fault_endurance`: `prior_bench_receipt_copy`, `fault_campaign_record`, and
  `endurance_record`.

## First-light ordering gate

A passing first-light record requires all of these signed facts before any
hash-enable observation:

- replacement runtime entered safe idle;
- cooling was ready;
- independent cutoff and rail feedback were confirmed;
- watchdog behavior was confirmed;
- all required sensors were fresh;
- the hash-enable event followed those prerequisites;
- hash power then started within the authorized temperature, power, time, and
  cutoff-response limits;
- an isolated operator-controlled pool provided work and confirmed at least one
  accepted share;
- the session ended with cutoff feedback, continuing cooling, rollback, and
  stock identity restoration.

The exact event action set includes `staged_safe_idle`,
`verify_independent_cutoff`, `verify_watchdog_and_sensors`, and
`hash_enable_after_safety_prerequisites`. Events are unique and strictly
chronological. A post-hoc combined mining record cannot substitute for this
stage.

## Bench-mining gate

A passing bench receipt requires its passing first-light predecessor plus:

- at least 60 seconds of bounded mining;
- a bounded authorization window, power ceiling, temperature ceiling,
  telemetry-gap ceiling, and cutoff-response ceiling;
- fresh cooling, cutoff, runtime, pool, and share observations;
- at least one pool-confirmed accepted share and exact submitted-share
  classification;
- configuration persistence and a controlled reboot pass;
- zero unexpected errors, restarts, sensor failures, stale samples, watchdog
  faults, transport errors, or unplanned reconnects;
- safe cutoff, rollback, and stock return.

## Fault/endurance gate

A passing endurance receipt requires its passing bench predecessor and exactly
one successful record for each fault class:

- `cooling_loss`;
- `network_disconnect`;
- `overtemperature`;
- `pool_disconnect`;
- `psu_fault`;
- `runtime_stall_watchdog`;
- `sensor_stale`.

Each injected fault must be detected, latched, reach a confirmed cutoff/safe
state within the authorized response time, and recover under the reviewed
procedure. Expected injected faults live only in `fault_campaign_record`;
unexpected faults live in `session_log.faults` and make a passing result
impossible.

The endurance run is at least 21,600 seconds and records exact `cold`, `steady`,
`hot_soak`, and `recovery` phases. It must remain within the authorization's
duration, power, temperature, telemetry, and cutoff bounds, retain accepted
shares, and record zero unexpected errors or restarts.

## Stops, failures, and negative evidence

`outcome` is exactly `passed`, `stopped`, or `failed`.

- A passing receipt requires every stage action and semantic check, with empty
  unexpected fault, stop, and deviation lists.
- A stopped or failed receipt requires a timestamped fault or stop event. It is
  still signed by every role required for that stage and remains immutable, but
  its current stage is not eligible.
- A failed bench receipt preserves only the already admitted first-light result.
  A failed endurance receipt preserves first-light and bench results but cannot
  qualify endurance.
- Prohibited actions always fail bundle creation: unbounded mining, production
  release, bundled pool credentials, or firmware/configuration changes outside
  the exact authorization.

A failed or stopped receipt is never edited into a pass. A new authorization
and a new stage bundle are required.

## Signatures and bundle layout

Each first-light bundle contains exactly:

```text
receipt.json
operator.sig
protocol_reviewer.sig
safety_reviewer.sig
evidence/**
```

Each bench or endurance bundle contains exactly:

```text
receipt.json
operator.sig
witness.sig
evidence/**
```

All signatures are Ed25519 SSHSIG over the same canonical `receipt.json` bytes.
Roles and replay-resistant namespaces are stage-specific:

| Stage | Role | SSHSIG namespace |
|---|---|---|
| first light | `k210_first_light_operator` | `dcent-k210-first-light-operator-v1` |
| first light | `k210_first_light_protocol_reviewer` | `dcent-k210-first-light-protocol-reviewer-v1` |
| first light | `k210_first_light_ee_safety_reviewer` | `dcent-k210-first-light-ee-safety-reviewer-v1` |
| bench mining | `k210_bench_mining_operator` | `dcent-k210-bench-mining-operator-v1` |
| bench mining | `k210_bench_mining_witness` | `dcent-k210-bench-mining-witness-v1` |
| endurance | `k210_endurance_operator` | `dcent-k210-endurance-operator-v1` |
| endurance | `k210_endurance_witness` | `dcent-k210-endurance-witness-v1` |

Within each stage, principals and keys differ. The first-light protocol
reviewer and EE/safety reviewer independently attest different review domains.
Adjacent stage key sets must be disjoint. Manifest integration should pin all
seven stage roles as independent trust anchors.

Receipt and evidence-set hashes use these domains:

```text
DCENT-K210-BENCH-ENDURANCE-EVIDENCE-SET-V1\0
DCENT-K210-BENCH-ENDURANCE-RECEIPT-ID-V1\0
```

## Host-only commands

Generate a predecessor-bound template; the emitted placeholder values are
deliberately not usable until replaced with reviewed session limits and times:

```powershell
py -3 DCENT_OS_AvalonMiner/scripts/k210_bench_endurance_receipt.py template `
  --qualification-class first_light `
  --discovery-receipt <receipt.json> `
  --fixture-receipt <receipt.json> `
  --capture-receipt <receipt.json> `
  --recovery-receipt <receipt.json> `
  --boot-policy-receipt <receipt.json> `
  --route-replacement-receipt <receipt.json> `
  --route-rollback-receipt <receipt.json> `
  --out <descriptor.json>
```

For bench or endurance, add `--prior-stage-receipt` pointing to the immediately
preceding passing receipt. Copy the named predecessor and semantic records into
the descriptor's evidence paths.

Create and verify first light with three distinct trust domains:

```powershell
py -3 DCENT_OS_AvalonMiner/scripts/k210_bench_endurance_receipt.py create `
  --descriptor <descriptor.json> --evidence-root <evidence> `
  --operator-private-key <operator-key> `
  --protocol-reviewer-private-key <protocol-reviewer-key> `
  --safety-reviewer-private-key <ee-safety-reviewer-key> `
  --bundle-out <new-bundle>

py -3 DCENT_OS_AvalonMiner/scripts/k210_bench_endurance_receipt.py verify `
  --bundle <bundle> --operator-public-key <operator.pub> `
  --protocol-reviewer-public-key <protocol-reviewer.pub> `
  --safety-reviewer-public-key <ee-safety-reviewer.pub> `
  --expected-operator-key-id <64-hex> `
  --expected-protocol-reviewer-key-id <64-hex> `
  --expected-safety-reviewer-key-id <64-hex>
```

Create and verify bench or endurance with a distinct operator and witness:

```powershell
py -3 DCENT_OS_AvalonMiner/scripts/k210_bench_endurance_receipt.py create `
  --descriptor <descriptor.json> --evidence-root <evidence> `
  --operator-private-key <operator-key> --witness-private-key <witness-key> `
  --bundle-out <new-bundle>

py -3 DCENT_OS_AvalonMiner/scripts/k210_bench_endurance_receipt.py verify `
  --bundle <bundle> --operator-public-key <operator.pub> `
  --witness-public-key <witness.pub> `
  --expected-operator-key-id <64-hex> --expected-witness-key-id <64-hex>
```

Never commit private keys, pool credentials, or unredacted operator/customer
identifiers.

## Workflow integration fields

The verifier returns:

```text
state
qualification_class
outcome
receipt_id
evidence_set_sha256
target_id
unit_label
unit_fingerprint_sha256
variant_profile_id
controller_board_revision
discovery_receipt_id
fixture_receipt_id
fixture_evidence_set_sha256
capture_receipt_id
capture_set_sha256
recovery_receipt_id
stock_backup_set_sha256
boot_policy_receipt_id
route_replacement_receipt_id
artifact_set_sha256
interface_qualification_sha256
replacement_firmware_version
installed_artifact_sha256
route_rollback_receipt_id
selected_route
route_adjudication_sha256
no_clobber_sha256
stock_restoration_sha256
prior_stage_receipt_id
prior_stage_evidence_set_sha256
first_light_gate_eligible
bench_mining_gate_eligible
endurance_faults_gate_eligible
operator_key_id_sha256
protocol_reviewer_key_id_sha256
safety_reviewer_key_id_sha256
witness_key_id_sha256
authority_granted=false
```

Suggested workflow claims are `exact_unit_first_light_verified`,
`exact_unit_bench_mining_verified`, and
`exact_unit_fault_endurance_verified`. A workflow validator must select the
claim matching `qualification_class`, require `outcome=passed`, independently
verify every supplied predecessor bundle, exact-match the copied receipt IDs,
and replay the current bundle verifier on every ledger load.
