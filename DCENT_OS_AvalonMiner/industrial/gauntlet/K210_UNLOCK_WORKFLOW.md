# K210 unlock workflow — dynamic multi-agent orchestration

This is the dispatch plan for enabling DCENT_OS on the Canaan AvalonMiner
A1246 (K210). It is executed by the **workflow orchestrator**
(`DCENT_OS_AvalonMiner/scripts/k210_unblock_workflow.py`), which reads the
lane-completion ledger (`gauntlet/unlock_state.json`) plus the live gauntlet
gate state and emits the current wave manifest
(`gauntlet/K210_UNLOCK_WAVE.{md,json}`).

**Design contract.** Desk lanes are executed by expert agents under a
coordinating session. Operator nodes pause the workflow until the operator
confirms the runbook step — these are physical actions on operator-owned
hardware (key ceremony, bench sessions, capture campaigns) that no agent may
perform or simulate. Nothing in this workflow qualifies gauntlet gates by
itself: gates advance only through the signed receipt layers, exactly as the
gauntlet enforces. "By all means" therefore means *every* desk lane is
automated and every operator node is staged with an exact runbook — not that
safety gates are bypassed.

## Driving the workflow

```bash
py -3 DCENT_OS_AvalonMiner/scripts/k210_unblock_workflow.py status   # lane table
py -3 DCENT_OS_AvalonMiner/scripts/k210_unblock_workflow.py wave     # emit wave manifest
py -3 DCENT_OS_AvalonMiner/scripts/k210_unblock_workflow.py complete --lane <id>            # desk lane (runs verify commands)
py -3 DCENT_OS_AvalonMiner/scripts/k210_unblock_workflow.py complete --lane op-<id> --operator-confirmed --evidence <receipt-or-witness-manifest>
```

Physical runbooks may collect under `C:\evidence`. Before workflow admission,
copy the reviewed bundles into the Git-ignored
`.k210-gauntlet-evidence/<unit>/` transfer root. This satisfies the
orchestrator's repo-relative, forward-slash, non-symlink path contract without
tracking photos, serials, analyzer exports, or other unit evidence.

For every gauntlet-backed operator lane from `op-discovery` through
`op-release`, the evidence argument
is a schema-1 `dcent_k210_operator_gate_evidence` JSON object with
`model: "a1246"` and a `bundles` object. Bundle paths are forward-slash,
repo-relative, non-symlink paths. The exact bundle set grows with the chain:
discovery only; discovery + fixture + recovery; then discovery + fixture +
recovery + `boot_policy_bundle`; replacement adds capture and the route-specific
artifact; rollback adds the exact-route restoration proof; first light, bench,
and endurance add their three immutable stage bundles; preauthorization adds
the signed exact install scope; final release adds the witnessed capstone. The
final descriptor therefore carries 12 exact-joined bundle paths. `op-fixture`
and `op-capture` use their own
narrow descriptor kinds documented in `K210_A1246_FIXTURE_QUALIFICATION.md`
and `K210_CAPTURE_RECEIPTS.md`. Extra or missing bundle fields fail closed. The
ceremony descriptor has its exact schema in `K210_TRUST_ANCHOR_CEREMONY.md`.

Desk-lane completion runs the lane's pinned verify commands plus an internal
mission-specific deliverable proof before recording; there is no CLI
verification bypass. Report-only lanes that formerly checked `Path.is_file`
must match a reviewed SHA-256 content digest as well as minimum size, heading
depth, substantive-line count, and exact load-bearing semantic tokens. Any
revision requires an explicit workflow-contract re-audit; a filename, empty
file, or padded generic report cannot complete those lanes.

Six implementation lanes have stronger named contracts:

- `w2-codec` requires a substantive clean-room codec implementation and at
  least eight non-ignored, assertion-bearing Rust admission tests, including
  named round-trip and negative cases binding capture-set, exact unit,
  revision, encoder, decoder, rejection, and false authority semantics;
- `w2-firmware` requires a target-bound implementation and at least eight tests
  covering all four canonical routes, exact unit/artifact-set binding, safe
  idle, and false authority;
- `w2-safety` requires real safety code and at least eight tests covering
  independent cutoff, watchdog, stale telemetry, latched faults, cooling, and
  hash-power custody;
- `w3-executor` requires the dedicated
  `k210_install_executor.py` and `test_k210_install_executor.py` surfaces with
  at least ten tests and exact route/replacement/rollback/install/no-clobber/
  release-authority joins. The locked planner test alone cannot qualify it;
- `w3-validation` must retain both immutable-stage and release-capstone APIs
  plus their signer separation, immediate-predecessor, all-route, splice, and
  pinned-anchor regressions;
- `w3-rollback` must retain schema-2 four-route rollback, no-clobber,
  restoration, cross-route/unit/digest-splice, and readback/signer attack
  regressions.

These proofs run both on completion and whenever a persisted desk completion
is loaded. A green zero-test Cargo target, a vacuous Python test file, or the
old locked install-plan precursor therefore cannot advance the ledger.
Operator-lane completion requires both explicit attestation and a bounded JSON
evidence descriptor accepted by that lane's semantic validator. The ceremony
validator exact-matches all 24 pinned manifest anchors and reruns the full
corpus gauntlet; all gauntlet-backed operator validators rerun the
gauntlet with the exact descriptor-bound bundle chain and require their named
gate to qualify for `a1246`. `op-firstlight` requires both ASIC-control and
thermal/power-safety gates. `op-preauthorize` requires a narrow exact-scope
preauthorization while `release_authority` stays red; only the later witnessed
install may qualify that gate. The
ledger records the original descriptor hash, its canonical JSON content and
digest, validator, qualified claim, and validated subject hash. Persisted
operator evidence is semantically replayed against the current manifest and
gauntlet whenever state is loaded. Every persisted desk completion also reruns
its active registry verifier; edited completion lists cannot substitute for
passing evidence. Completion claims must be dependency-closed, operator
receipts must correspond exactly to completed operator lanes, and a persisted
terminal claim reconstructs all 12 discovery-through-release bundle arguments,
rejects cross-lane bundle-path
splicing, and reruns the production gate instead of being trusted.
Duplicate-key state JSON is rejected. State changes are lock-protected and
atomically replaced so concurrent agents cannot lose one another's
completions; every completion also regenerates the JSON/Markdown wave pair.
The registry enforces unique ids, acyclic dependencies, runbooks on operator
lanes, mission-specific verify commands on every desk lane including terminal,
and directory-aware ownership exclusion.

## Phase DAG (39 lanes; 18 complete)

```
wave 0 (done 2026-08-23):  d0-ingest d0-census d0-soc d0-crossera
                           d0-registry d0-rail d0-runbooks d0-bspplan
wave 1 (desk):
  w1-bspa          sealed BSP Phase A         (done)
  w1-capture       .k210cap ingest + tests    (done)
  w1-installplan   locked install planner     (done)
  w1-discoverytool 4028 collector + drill gen (done)
  w1-renode        emulation feasibility      (done)
  w1-identityschema revision-bound identity   (done)
  w1-fixtureplan   EE fixture contract        (done)
  w1-fixturevalidator signed fixture admission (done)
  w1-capturevalidator source-bound P1 admission (done)
  w1-routeengine    four-path boot policy engine (done)
operator 1 (pauses workflow):
  op-ceremony      24-key trust-anchor pinning (needs d0-runbooks)
                   -> K210_TRUST_ANCHOR_CEREMONY.md
  op-discovery     A1246 first contact        (also needs w1-identityschema)
                   -> K210_A1246_FIRST_CONTACT_RUNBOOK.md   [gate: exact_model_identity]
  op-fixture       exact-unit EE qualification (needs discovery,fixture validator)
                   -> K210_A1246_FIXTURE_QUALIFICATION.md
operator 2 (parallel only after fixture qualification):
  op-recovery      dual-path backup/restore   (needs op-fixture, d0-soc)
                   -> K210_RECOVERY_RECEIPTS.md             [gate: stock_restore]
  op-capture       signed raw P1 corpus        (needs op-fixture,capture validator)
                   -> K210_CAPTURE_RECEIPTS.md               [claim only; no gate]
operator 3:
  op-bootpolicy    fuses/ISP/JTAG/AES0 probe  (needs op-recovery)
                   -> K210_SOC_BOOT_FLASH_ISP_CONTRACT.md   [gate: boot_policy]
wave 2 (desk, unlocked by operator evidence):
  w2-codec         ASIC codec from captures   (needs op-capture)
  w2-route         adjudicate AES0 flash, ROM-ISP SRAM, JTAG SRAM, and
                   replacement-controller paths (needs route engine + boot/fixture evidence)
  w2-firmware      implement selected runtime (needs w1-bspa,w2-route,identity)
  op-replacement   builder/reviewer replacement admission
                   (needs firmware, route, boot policy) [gate: replacement_firmware]
  w2-safety        thermal/power custody      (needs w2-firmware, w2-codec)
wave 3:
  w3-executor      toolbox install executor   (also needs op-replacement)
  w3-validation    staged evidence + release validators
                   (needs w2-firmware, w2-safety, w3-executor)
  w3-rollback      exact-route rollback harness (needs executor,safety,recovery)
operator 4:
  op-rollback      witnessed rollback proof    (needs w3-rollback)     [gate: rollback_recovery]
  op-firstlight    protocol+safety first light (needs validation+rollback)
                   [gates: asic_control, thermal_power_safety]
  op-bench         witnessed bounded mining    (needs op-firstlight)   [gate: bench_mining]
  op-endurance     fault/endurance campaign    (needs op-bench)       [gate: endurance_faults]
  op-preauthorize  exact-scope install authority (needs op-endurance) [gate stays red]
  op-release       witnessed install capstone  (needs op-preauthorize) [gate: release_authority]
terminal:
  DCENT_OS enabled on A1246 — completes only when every lane above is done
  and the 12 reconstructed admitted bundles make `k210_gauntlet.py check
  --model a1246 --corpus required --require-production` succeed. The terminal
  verifier cannot be skipped.
```

## Current desk-verifier audit disposition

The workflow/QA replay intentionally distinguishes implemented host proof from
future dependency readiness:

- `w2-codec`, `w2-firmware`, and `w2-safety` remain fail-closed because their
  mission-specific implementation modules and admission test targets do not
  yet exist. Merely creating an empty Cargo test target still fails the
  semantic minimum and required-field checks.
- `w3-executor` now has a dedicated route-neutral implementation and a
  ten-test-or-greater suite; the locked install-plan precursor alone still
  cannot qualify it. The executor replays the exact eleven preinstall bundles,
  exact-binds unit/route/artifact/scope, requires one-shot authorization and
  fail-safe recovery/cutoff/cooling/hash-off preflight, restores stock after any
  failed deploy/readback, and leaves success release-capstone-pending. It has no
  built-in physical route adapter, so the lane remains dependency-blocked on
  admitted physical evidence rather than desk-validator weakness.
- `w3-validation` and `w3-rollback` have strong host-only implementations and
  focused regression suites, including all-route, signer, predecessor,
  no-clobber, restoration, and splice attacks. Their semantic deliverable
  proofs pass, but their workflow lanes remain dependency-blocked; host proof
  grants no operator or hardware authority.
- The seven report/plan lanes that used file or marker checks now replay
  structured semantic report contracts. Their physical unknowns remain
  unknown; document validation does not promote a physical claim.

## What each wave-1 lane delivers

- **w1-bspa** — real `no_std` code in `k210-firmware/`: exported register
  facts (SYSCTL, UARTHS, GPIOHS, FPIOA, CLINT, WDT0/1), a sealed zero-MMIO
  physical runtime, and a differently named Renode-only console ELF. Zero
  external dependencies, no board pin claims, and no candidate-builder route
  to the emulator payload.
- **w1-capture** — `scripts/k210_capture_ingest.py` + `.k210cap` canonical
  artifact + codec bench: turns the operator's future logic-analyzer session
  into immediately analyzable evidence (channel→signal mapping, clock
  recovery, descriptive frame statistics — no wire-contract claims).
- **w1-installplan** — toolbox `core/k210_install_plan.py`: a structured
  AUP/install plan generator whose every step requires admitted receipts;
  with zero receipts it emits the canonical refusal enumerating missing
  gates. The executor unlock is a separate later lane (w3-executor).
- **w1-discoverytool** — `scripts/k210_discovery_collect.py` (allowlisted
  read-only 4028 client with the MM3 trailing-NUL quirk, evidence-kind file
  layout, bundle skeleton) + `k210_recovery_drill_plan.py`.
- **w1-renode** — feasibility report: can Renode's k210 platform host-test
  the BSP runtime and candidates pre-hardware?
- **w1-identityschema** — revision-bound A1246/A1246N identity derivation and
  semantic evidence validation. Four held stock-profile contracts now resolve
  only when stock JSON, fully decoded bounded canonical PNG evidence,
  controller/hashboard topology, and ASIC family agree instead of being
  operator-forced to a generic row. The resolved profile feeds the gauntlet's
  stock-restore decision.
- **w1-fixtureplan** — exact-unit EE gates for controller supply, back-power,
  1.8 V probing, flash/programmer isolation, independent hash cutoff, cooling,
  ESD, instruments, and stop conditions. Recovery and capture both depend on
  the witnessed physical qualification.
- **w1-fixturevalidator** — canonical dual-reviewed fixture receipts with
  semantic measurements, decoded photos, exact discovery/variant joins, and a
  no-future-authority ceiling. Its claim is deliberately narrower than
  `thermal_power_safety`.
- **w1-capturevalidator** — dedicated capture principals plus byte-reproduction
  of both `.k210cap` files from signed physical maps and source CSVs. It admits
  the safe-idle/bounded-work P1 corpus while keeping `asic_control` false until
  the downstream clean-room codec is implemented and validated.

## Invariants (do not regress)

1. The orchestrator is host-only; it never contacts hardware and never
   mutates gauntlet gates or receipts.
2. Operator nodes complete only with explicit attestation plus lane-specific
   semantic admission. Arbitrary hashed files are rejected; an operator lane
   with no implemented validator is locked.
3. First contact remains NO-GO until revision-bound semantic identity passes;
   recovery/capture remain blocked until the exact fixture qualifies.
4. The terminal lane depends on every other lane, reconstructs and exact-joins
   all 12 bundle paths from stored semantic receipts, and independently
   requires production gauntlet success on completion and every subsequent
   ledger load; there is no shortcut or skip-verification flag.
5. Verify commands and the lane's semantic deliverable proof must pass before
   a desk lane is recorded and rerun whenever persisted completion state is
   evaluated. File presence, marker strings, zero tests, locked precursors, and
   placeholder APIs are not completion evidence.
6. Lane ownership overlaps only along dependency order, including directory
   versus descendant-file scopes.
7. Negative AES0 boot policy does not terminate the objective: ROM-ISP SRAM,
   JTAG SRAM, and replacement-controller paths remain explicit adjudications.
8. Persisted desk verifiers and operator descriptors are replayed; stale source,
   manifest, bundle, gate, claim, or validator state fails closed.
