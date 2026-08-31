# K210 exact-scope release receipts

`scripts/k210_release_receipt.py` is a host-only evidence tool for the A1246
K210 release capstone. It does not open a serial port, invoke a programmer, or
contact hardware. Hardware actions remain manual, separately controlled work.

The safe lane order is:

```text
op-endurance -> op-preauthorize -> op-release -> terminal
```

The preauthorization is only for the final witnessed install capstone. It does
not authorize the earlier rollback, first-light, bench, or endurance campaigns.
Those stages retain their own authorization contracts.

## Authority separation

Four different people, keys, roles, and SSHSIG namespaces are mandatory:

| Phase | Role | SSHSIG namespace |
|---|---|---|
| Before final contact | `k210_release_preauthorizer` | `dcent-k210-release-preauthorizer-v1` |
| Before final contact | `k210_release_reviewer` | `dcent-k210-release-reviewer-v1` |
| Completed install | `k210_release_installer` | `dcent-k210-release-installer-v1` |
| Completed install | `k210_release_install_witness` | `dcent-k210-release-install-witness-v1` |

The verifier rejects self-approval and any principal or key reuse across the
four release roles. Public keys supplied to verification are trust anchors;
production workflow descriptors should also pin their expected SHA-256 key IDs.

The signed preauthorization admits one exact unit and one exact replacement
scope during one UTC window. Its permitted action set is fixed to:

- boot the exact replacement;
- exercise the upgrade runbook;
- install the exact replacement artifact;
- restore stock on failure;
- run post-install acceptance;
- verify a full readback;
- verify preflight controls; and
- verify the restore runbook.

It explicitly denies other units, other artifacts, generic future contact,
generic future installation, production hashing, and release publication.
Verification reports `install_authority_scope_eligible=true`; this is an
eligibility result for the signed exact scope and window, not generic authority.

## 1. Create and admit the preauthorization

Generate a descriptor from the already verified final endurance bundle. The
endurance operator and witness keys must be the independently provisioned trust
anchors for that bundle.

```powershell
py -3 scripts/k210_release_receipt.py preauthorize-template `
  --endurance-bundle C:\evidence\op-endurance `
  --endurance-operator-public-key C:\trust\endurance-operator.pub `
  --endurance-witness-public-key C:\trust\endurance-witness.pub `
  --expected-endurance-operator-key-id <64-lowercase-hex> `
  --expected-endurance-witness-key-id <64-lowercase-hex> `
  --out C:\ceremony\release-preauthorization-descriptor.json
```

Review and replace every placeholder. In particular, set distinct
`preauthorizer_id` and `reviewer_id`, and set `issued_at_utc`,
`preauthorizer_signed_at_utc`, `reviewer_signed_at_utc`, `valid_from_utc`, and
`valid_until_utc` as canonical `YYYY-MM-DDTHH:MM:SSZ` instants. Issuance must be
no earlier than endurance completion. Both declared signature instants must be
at or after issuance and strictly earlier than the window start, so the signed
ceremony necessarily precedes final contact.

Do not edit the derived `predecessor_chain`, `release_scope`, or
`permitted_actions`. They bind the exact target, variant, controller revision,
unit label and fingerprint, selected route and adjudication digest, replacement
artifact set, installed artifact, firmware version and route-replacement
receipt, interface-qualification digest, no-clobber digest, exact-unit
population, and the cumulative predecessor chain. These names follow the v2
route-replacement/route-rollback contract and work for every route in
`k210_bench_endurance_receipt.ROUTES`; they are not AES0-only.

Sign the immutable object:

```powershell
py -3 scripts/k210_release_receipt.py preauthorize `
  --descriptor C:\ceremony\release-preauthorization-descriptor.json `
  --preauthorizer-private-key C:\keys\release-preauthorizer `
  --reviewer-private-key C:\keys\release-reviewer `
  --bundle-out C:\evidence\op-preauthorize
```

Admit that object as a standalone workflow lane before final contact:

```powershell
py -3 scripts/k210_release_receipt.py verify-preauthorization `
  --bundle C:\evidence\op-preauthorize `
  --preauthorizer-public-key C:\trust\release-preauthorizer.pub `
  --reviewer-public-key C:\trust\release-reviewer.pub `
  --expected-preauthorizer-key-id <64-lowercase-hex> `
  --expected-reviewer-key-id <64-lowercase-hex>
```

The JSON result includes the preauthorization ID, exact release-scope digest,
UTC window, actions, unit, route, adjudication, artifact set, installed-artifact
digest, firmware version, route-replacement receipt, interface qualification,
no-clobber digest, and immediate endurance receipt/evidence-set pair. Preserve
this result as the `op-preauthorize` semantic-verifier result.

## 2. Record the completed capstone

Generate the final descriptor from the verified preauthorization:

```powershell
py -3 scripts/k210_release_receipt.py template `
  --preauthorization-bundle C:\evidence\op-preauthorize `
  --preauthorizer-public-key C:\trust\release-preauthorizer.pub `
  --reviewer-public-key C:\trust\release-reviewer.pub `
  --expected-preauthorizer-key-id <64-lowercase-hex> `
  --expected-reviewer-key-id <64-lowercase-hex> `
  --out C:\ceremony\release-capstone-descriptor.json
```

Set distinct installer and witness principals; the actual start/completion
instants; and `installer_signed_at_utc` and `witness_signed_at_utc`. The entire
capstone must satisfy `valid_from <= started < completed <= valid_until`, and
both signed-at instants must satisfy `completed <= signed_at <= valid_until`.
The descriptor must retain the exact preauthorization ID/digest, scope, chain,
action set, and fixed `predecessor/endurance_bundle` path.

Create exactly one canonical JSON evidence record for each row below. Extra
fields fail verification.

| Evidence kind | Exact JSON keys | Required semantic claim |
|---|---|---|
| `artifact_custody_record` | `kind`, `artifact_set_sha256`, `firmware_version`, `route_replacement_receipt_id`, `custody_complete`, `custody_log_sha256`, `unexplained_gaps` | Complete custody, no unexplained gaps, exact artifact set/version/replacement receipt |
| `reproducibility_record` | `kind`, `artifact_set_sha256`, `independent_build_count`, `artifact_bytes_match`, `build_inputs_pinned`, `source_archive_sha256` | At least two independent builds, pinned inputs, byte-identical artifact, source archive digest |
| `artifact_signing_record` | `kind`, `artifact_set_sha256`, `route_replacement_receipt_id`, `builder_key_id_sha256`, `reviewer_key_id_sha256`, `signatures_verified` | Verified artifact signatures from distinct builder and reviewer keys |
| `sbom_record` | `kind`, `artifact_set_sha256`, `sbom_sha256`, `complete` | Complete SBOM bound to the exact artifact set |
| `license_review_record` | `kind`, `artifact_set_sha256`, `review_sha256`, `approved`, `restricted_vendor_code_included` | Approved review with no restricted vendor code included |
| `upgrade_runbook_record` | `kind`, `artifact_set_sha256`, `selected_route`, `runbook_sha256`, `tested`, `rollback_on_failure` | Tested route-specific upgrade with rollback-on-failure |
| `restore_runbook_record` | `kind`, `selected_route`, `stock_backup_set_sha256`, `runbook_sha256`, `tested` | Tested route-specific restore bound to the stock backup set |
| `install_execution_record` | `kind`, `preauthorization_id`, `artifact_set_sha256`, `installed_artifact_sha256`, `unit_fingerprint_sha256`, `started_at_utc`, `completed_at_utc`, `actions_performed`, `full_readback_matches`, `unauthorized_actions_performed`, `errors` | Exact preauthorization/actions/unit/artifacts/times, full readback match, no errors or unauthorized action |
| `postinstall_acceptance_record` | `kind`, `artifact_set_sha256`, `firmware_version`, `target_id`, `unit_fingerprint_sha256`, `accepted`, `boot_succeeded`, `runtime_identity_matches`, `safety_controls_ready`, `telemetry_ready`, `rollback_ready`, `anomalies` | Exact unit/artifact/version, successful boot/identity/safety/telemetry/rollback readiness, no anomalies |

The record-level `kind` values, in the same order, are
`dcent_k210_release_artifact_custody`,
`dcent_k210_release_reproducibility_review`,
`dcent_k210_release_artifact_signing_review`,
`dcent_k210_release_sbom_review`, `dcent_k210_release_license_review`,
`dcent_k210_release_upgrade_runbook`, `dcent_k210_release_restore_runbook`,
`dcent_k210_release_install_execution`, and
`dcent_k210_release_postinstall_acceptance`.

Use the paths in the generated descriptor. Offline review records may predate
the install but cannot postdate capstone completion. Install and post-install
records must be acquired between the declared start and completion instants.

After the separately authorized manual procedure has completed, create the
final bundle:

```powershell
py -3 scripts/k210_release_receipt.py create `
  --descriptor C:\ceremony\release-capstone-descriptor.json `
  --evidence-root C:\ceremony\release-evidence `
  --preauthorization-bundle C:\evidence\op-preauthorize `
  --preauthorizer-public-key C:\trust\release-preauthorizer.pub `
  --reviewer-public-key C:\trust\release-reviewer.pub `
  --endurance-bundle C:\evidence\op-endurance `
  --endurance-operator-public-key C:\trust\endurance-operator.pub `
  --endurance-witness-public-key C:\trust\endurance-witness.pub `
  --installer-private-key C:\keys\release-installer `
  --witness-private-key C:\keys\release-install-witness `
  --expected-preauthorizer-key-id <64-lowercase-hex> `
  --expected-reviewer-key-id <64-lowercase-hex> `
  --expected-endurance-operator-key-id <64-lowercase-hex> `
  --expected-endurance-witness-key-id <64-lowercase-hex> `
  --bundle-out C:\evidence\op-release
```

`create` re-verifies both copied predecessor bundles after snapshotting. It
refuses an existing output path and fails on source mutation, digest drift,
links/reparse points, special files, path traversal, missing evidence, or extra
members.

## 3. Verify the terminal release gate

```powershell
py -3 scripts/k210_release_receipt.py verify `
  --bundle C:\evidence\op-release `
  --preauthorizer-public-key C:\trust\release-preauthorizer.pub `
  --reviewer-public-key C:\trust\release-reviewer.pub `
  --endurance-operator-public-key C:\trust\endurance-operator.pub `
  --endurance-witness-public-key C:\trust\endurance-witness.pub `
  --installer-public-key C:\trust\release-installer.pub `
  --witness-public-key C:\trust\release-install-witness.pub `
  --expected-preauthorizer-key-id <64-lowercase-hex> `
  --expected-reviewer-key-id <64-lowercase-hex> `
  --expected-endurance-operator-key-id <64-lowercase-hex> `
  --expected-endurance-witness-key-id <64-lowercase-hex> `
  --expected-installer-key-id <64-lowercase-hex> `
  --expected-witness-key-id <64-lowercase-hex>
```

Only a completed, passing, exact-scope bundle returns all of:

```json
{
  "authority_granted": false,
  "exact_scope_release_admitted": true,
  "generic_future_authority_granted": false,
  "release_authority_gate_eligible": true,
  "state": "verified_exact_scope_release_capstone"
}
```

The full result also exports the preauthorization ID/digest, release-scope
digest, immediate endurance receipt/evidence-set pair, release receipt/evidence
set, target/unit/variant, route/adjudication, and replacement artifact/version/
receipt joins. These are the fields the terminal workflow gate should pin and
replay. A successful result authorizes no other unit, artifact, action, time
window, publication, hashing operation, or future install.

This file and the receipt tool do not themselves add workflow lanes or trust
anchors. The manifest/workflow integration must supply independently managed
keys and preserve the lane ordering above.
