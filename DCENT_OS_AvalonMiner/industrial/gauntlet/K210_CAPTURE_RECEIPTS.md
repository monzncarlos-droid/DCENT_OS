# K210 P1 passive-capture receipts

This contract turns a separately authorized A1246 logic-analyzer campaign into
reviewable evidence for `op-capture`. It does not contact a miner, drive a
signal, infer a protocol, admit a codec, or qualify `asic_control`.

The receipt accepts only `p1_controller_passive` evidence from the exact
controller-to-hashboard path. P3 chip-fixture traffic is useful supplementary
research but cannot complete this lane.

## Prerequisites and authority boundary

Before collection, all of these must already be true:

- the discovery receipt is admitted for the named A1246 unit and held-stock
  variant;
- the exact fixture receipt is admitted and its passive-capture, cutoff, and
  cooling dispositions are true;
- dedicated capture operator and reviewer public keys are pinned by the trust
  ceremony;
- the operator has a named-unit, named-action, UTC-bounded authorization for
  the five capture actions in `k210_capture_receipt.py`;
- every connection is closed-chassis and passive; the analyzer/fixture never
  drives a signal;
- safe-idle and bounded stock-work states are separately controlled and
  observed.

A signed receipt records past observations only. It grants no future contact,
power, cooling, capture, transmit, read, write, install, mining, release, codec,
or production authority.

## Required P1 corpus

The bundle contains exactly one `safe_idle_detection` and one
`bounded_work_exchange` capture. Each capture binds:

- its canonical physical-channel map, retaining the original analyzer channel
  numbers;
- one or two original digital CSV exports;
- the canonical `.k210cap` artifact;
- at least the core signals `CI, DI, RI, CKI, CO, DO, RO, CKO`;
- a declared rate of at least 50 MS/s;
- the exact unit serial, stock AUP SHA-256, stock firmware build, ASIC family,
  controller revision, and complete hashboard revision set.

Verification re-runs CSV parsing and normalization from the signed map and
source files and requires byte-for-byte equality with the signed `.k210cap`.
The two physical maps must be identical. The bounded-work artifact must contain
nonempty controller-to-ASIC and ASIC-to-controller edge evidence; a zero-event
artifact cannot satisfy the lane.

The remaining canonical JSON records prove:

- stable read-only stock identity before and after the campaign;
- independently monitored hash-rail absence for the full safe-idle capture;
- closed-chassis state controls for both states;
- bounded, pool-less stock work with job, status, and nonce observation;
- continuous cooling telemetry, working fans/pumps, no telemetry gap, and a
  measured maximum below the recorded limit;
- one log event for every authorized action and empty deviation, fault, and
  stop arrays.

## Create the bundle

Keep raw/live evidence outside Git while collecting it. After review, use the
ignored repository-local transfer root so the workflow can resolve canonical
repo-relative paths without tracking sensitive unit evidence:

```powershell
New-Item -ItemType Directory -Force .k210-gauntlet-evidence\a1246 | Out-Null
Copy-Item -Recurse -LiteralPath C:\evidence\a1246-discovery-bundle `
  -Destination .k210-gauntlet-evidence\a1246\discovery-bundle
Copy-Item -Recurse -LiteralPath C:\evidence\a1246-fixture-bundle `
  -Destination .k210-gauntlet-evidence\a1246\fixture-bundle
```

Verify the copied predecessor bundles before using their receipt files. Then
generate the capture descriptor:

```powershell
py -3 DCENT_OS_AvalonMiner/scripts/k210_capture_receipt.py template `
  --discovery-receipt .k210-gauntlet-evidence/a1246/discovery-bundle/receipt.json `
  --fixture-receipt .k210-gauntlet-evidence/a1246/fixture-bundle/receipt.json `
  --out C:\evidence\a1246-capture-descriptor.json
```

Fill every placeholder and create all canonical records, maps, CSVs, and
`.k210cap` files under the evidence root. Create and verify the dual-signed
bundle:

```powershell
py -3 DCENT_OS_AvalonMiner/scripts/k210_capture_receipt.py create `
  --descriptor C:\evidence\a1246-capture-descriptor.json `
  --evidence-root C:\evidence\a1246-capture-evidence `
  --operator-private-key C:\secure\dcent-k210-capture-operator `
  --reviewer-private-key C:\secure\dcent-k210-capture-reviewer `
  --bundle-out C:\evidence\a1246-capture-bundle

py -3 DCENT_OS_AvalonMiner/scripts/k210_capture_receipt.py verify `
  --bundle C:\evidence\a1246-capture-bundle `
  --operator-public-key DCENT_OS_AvalonMiner/gauntlet/trust/k210-capture-operator.pub `
  --reviewer-public-key DCENT_OS_AvalonMiner/gauntlet/trust/k210-capture-reviewer.pub
```

Copy the finished bundle into
`.k210-gauntlet-evidence/a1246/capture-bundle`, then run full manifest-pinned
admission:

```powershell
py -3 DCENT_OS_AvalonMiner/scripts/k210_gauntlet.py check `
  --model a1246 --corpus required --format json `
  --discovery-bundle .k210-gauntlet-evidence/a1246/discovery-bundle `
  --fixture-bundle .k210-gauntlet-evidence/a1246/fixture-bundle `
  --capture-bundle .k210-gauntlet-evidence/a1246/capture-bundle
```

The JSON must contain
`passive_capture_admission.state=verified_signed_p1_passive_capture` while
`gates.asic_control.qualifies` remains `false`.

## Complete `op-capture`

Create this exact workflow descriptor:

```json
{
  "bundles": {
    "capture_bundle": ".k210-gauntlet-evidence/a1246/capture-bundle",
    "discovery_bundle": ".k210-gauntlet-evidence/a1246/discovery-bundle",
    "fixture_bundle": ".k210-gauntlet-evidence/a1246/fixture-bundle"
  },
  "kind": "dcent_k210_operator_capture_evidence",
  "model": "a1246",
  "schema_version": 1
}
```

Then explicitly record the operator lane:

```powershell
py -3 DCENT_OS_AvalonMiner/scripts/k210_unblock_workflow.py complete `
  --lane op-capture --operator-confirmed `
  --evidence C:\evidence\op-capture-descriptor.json
```

The workflow independently reruns all predecessor signature, identity,
source-reproduction, cutoff, work, cooling, and authority-ceiling checks. Only
the narrow claim `p1_passive_capture_admitted` is persisted. `w2-codec` may
then derive and test a revision-bound codec; the raw receipt never claims that
the derivation is correct.
