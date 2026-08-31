# DCENTaxe retained hardware evidence

This directory is the fail-closed authority for exact-SKU production promotion.
Offline build ledgers do not belong here and cannot authorize a device.

## Layout

- `index.json` lists immutable receipt IDs, `receipts/...` paths, and receipt
  SHA-256 values.
- `receipts/<receipt-id>.json` binds one exact board target, model, unit,
  firmware update image, witnessed session, and its effective gates.
- `artifacts/<receipt-id>/promotion-candidate.json` retains the exact canonical,
  non-publishable descriptor used to build the qualified payload.
- `artifacts/...` also contains the typed identity, serial/telemetry captures,
  rollback proof, share proof, broker transcript, and soak result referenced by
  each gate.

All indexed paths are relative to this directory. The validator refuses absolute
paths, `..`, missing files, and digest drift.

## Receipt shape

```json
{
  "schema": 1,
  "receipt_id": "board-target-unit-a-yyyymmdd",
  "board_target": "exact-registry-target",
  "device_model": "exact_canonical_model",
  "unit_fingerprint_sha256": "64-lowercase-hex",
  "firmware": {
    "version": "x.y.z",
    "update_sha256": "64-lowercase-hex"
  },
  "promotion_candidate": {
    "candidate_id": "64-lowercase-hex",
    "descriptor_sha256": "64-lowercase-hex",
    "descriptor_artifact": "artifacts/<receipt-id>/promotion-candidate.json",
    "source_git_commit": "40-lowercase-hex",
    "source_date_epoch": "decimal-string",
    "source_registry_sha256": "64-lowercase-hex"
  },
  "operator": "named operator",
  "witness": "different named witness",
  "live_device_contact": true,
  "session": {
    "started_at": "2026-08-20T00:00:00Z",
    "finished_at": "2026-08-23T00:00:00Z",
    "duration_seconds": 259200
  },
  "gates": {
    "exact-sku-identity": {
      "passed": true,
      "artifact": "artifacts/<target>/<receipt-id>/identity.json",
      "sha256": "64-lowercase-hex"
    }
  }
}
```

Include every gate returned by:

```bash
python scripts/hardware_evidence.py status --scope all
```

The universal set is `exact-sku-identity`, `safe-boot`,
`fail-safe-power-cut`, `trusted-thermal`, `accepted-share`, `ota-rollback`,
`sustained-soak`, and `mqtt-command-roundtrip`. Effective additions come from
`production_gate_contract` in `esp-targets.json`.

## Promotion sequence

1. From a clean committed source tree, create a descriptor with
   `promotion_candidate.py create`, then use `production_gauntlet.py
   --candidate ... --stage package --dist-root <retained-directory>` to build a
   signed, non-publishable exact binary. Candidate mode refuses a temporary-only
   output location.
2. Run `hardware_session.py plan` with that descriptor, signed manifest,
   privacy-safe unit fingerprint, operator, and distinct witness. Planning is
   offline and does not authorize device contact.
3. Obtain explicit exact-unit authorization, then run `hardware_session.py
   authorize ... --confirm authorize-live-<receipt-id>`. Execute only the
   operator-approved bench steps and fill the generated typed gate JSON files
   from observations. The exact identity artifact must report the compiled
   promotion receipt ID from `/api/system/info`.
4. After at least 72 hours, run `hardware_session.py status`, then
   `hardware_session.py finalize ... --confirm finalize-<receipt-id>`. The
   finalizer validates all semantics, retains the descriptor and artifacts,
   writes the receipt, and atomically updates `index.json` without overwriting
   existing evidence.
5. Run `python scripts/hardware_evidence.py validate`. In one reviewed registry
   change, replace the row with the descriptor's exact `registry_row`; do not
   retype or partially copy it.
6. Run `promotion_candidate.py admit-check` with the retained update SHA/version,
   then `promotion_candidate.py admit-package` with the retained candidate
   manifest and production public key. It copies the exact signed factory/update
   bytes and emits registry/evidence-state metadata without running Cargo.
   Production readiness requires the package version and update SHA-256 to
   match the receipt and both signatures to verify.

Never copy credentials or private identifiers into retained artifacts. Never
reuse a receipt after any firmware rebuild, and never treat an offline package
ledger as live-device evidence.
