# K210 unlock workflow — current wave

Host-only dispatch state. Desk lanes are executed by expert agents under the
coordinating session; operator nodes pause the workflow until the operator
confirms the runbook step. Nothing here qualifies gauntlet gates by itself.

- done: 18 / 39 lanes
- ready to dispatch: (none)
- awaiting operator: op-ceremony
- locked pending validator: (none)
- registry SHA-256: `1c885d0da83800c27d8b0c2d220de7299c8b536b2d4785253ab814e50db213f8`
- state SHA-256: `1f75a09babd07dfe2280a3a59c7c0d82653cfb06a90880eed6344ddf242233bb`

## Ready desk lanes

## Awaiting operator

- **op-ceremony** — Operator: generate + pin every role-separated trust-anchor key → runbook: `DCENT_OS_AvalonMiner/gauntlet/K210_TRUST_ANCHOR_CEREMONY.md`

## Locked pending semantic validator


## Blocked (missing dependencies)

- **op-discovery** — missing: op-ceremony
- **op-fixture** — missing: op-discovery
- **op-recovery** — missing: op-discovery, op-fixture
- **op-bootpolicy** — missing: op-recovery
- **op-capture** — missing: op-discovery, op-fixture
- **w2-codec** — missing: op-capture
- **w2-route** — missing: op-bootpolicy, op-discovery, op-fixture
- **w2-firmware** — missing: w2-route, op-discovery
- **op-replacement** — missing: w2-firmware, w2-route, op-bootpolicy, op-capture
- **w2-safety** — missing: w2-firmware, w2-codec
- **w3-executor** — missing: w2-firmware, op-bootpolicy, op-replacement
- **w3-validation** — missing: w2-firmware, w2-safety, w3-executor
- **w3-rollback** — missing: w3-executor, w2-safety, op-recovery
- **op-rollback** — missing: w3-rollback
- **op-firstlight** — missing: w3-validation, op-rollback
- **op-bench** — missing: op-firstlight
- **op-endurance** — missing: op-bench
- **op-preauthorize** — missing: op-endurance
- **op-release** — missing: op-preauthorize
- **terminal** — missing: op-bench, op-bootpolicy, op-capture, op-ceremony, op-discovery, op-endurance, op-firstlight, op-fixture, op-preauthorize, op-recovery, op-release, op-replacement, op-rollback, w2-codec, w2-firmware, w2-route, w2-safety, w3-executor, w3-rollback, w3-validation

## Gauntlet gates (a1246 snapshot)

- ❌ `asic_control`: not_implemented
- ❌ `bench_mining`: not_run
- ❌ `boot_policy`: missing_measurement
- ❌ `endurance_faults`: not_run
- ❌ `exact_model_identity`: documentary_only
- ❌ `release_authority`: not_admitted
- ❌ `replacement_firmware`: packaged_safe_idle_pipeline_sentinel_only
- ❌ `rollback_recovery`: missing_hardware_proof
- ❌ `stock_restore`: held_package_verified
- ❌ `thermal_power_safety`: generic_fail_closed_supervisor_only
