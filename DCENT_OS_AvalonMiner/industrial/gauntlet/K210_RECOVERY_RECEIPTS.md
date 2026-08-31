# K210 exact-unit stock-recovery receipts

This contract proves that one already-discovered AvalonMiner can be returned to
its exact stock controller image through two independent recovery mechanisms.
It is an evidence verifier, not a recovery executor. The tool has no miner,
programmer, serial, USB, GPIO, power, flash, or block-device transport.

A receipt records a completed, separately authorized recovery drill and grants
no future authority. Do not contact, open, power-cycle, read, write, interrupt,
or restore a miner merely because this schema exists. Every hardware action
requires explicit authorization for the named unit and action, a reviewed
model-specific procedure, and appropriate electrical/thermal controls.

## Default state

`k210_models.json` intentionally pins neither recovery role. With both trust
anchors `null`, bundles can be built and checked directly against supplied
public keys, but the gauntlet admits none and cannot advance `stock_restore`.

Recovery admission requires two distinct SSHSIG/Ed25519 roles:

- `k210_recovery_operator` signs the operator's exact execution record;
- `k210_recovery_witness` independently signs the same canonical receipt.

The roles must use different principals, private keys, public-key paths, and
key IDs. Keep private keys outside the repository.

## Prerequisite

Start from the canonical `receipt.json` inside an exact-unit discovery bundle.
That discovery bundle must separately be admitted by the gauntlet. Recovery is
rejected if its discovery receipt ID, unit fingerprint, unit label, target, or
stock identity does not exact-match the admitted discovery result.

Create a structurally valid descriptor template:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_recovery_receipt.py template `
  --discovery-receipt C:\evidence\a1246-unit-01\discovery\receipt.json `
  --out C:\evidence\a1246-unit-01\recovery-descriptor.json
```

Copy that exact discovery receipt to
`identity/discovery-receipt.json` below the recovery evidence root. Replace all
template placeholders, dates, flash geometry, capacity, tool identities, and
evidence paths before the drill. A placeholder-filled template is not proof.

## Admission requirements

For every controller flash device, the signed evidence must contain:

- exact technology, manufacturer, model, and full capacity;
- two full-device backup reads through distinct mechanisms and distinct tools;
- identical byte count and SHA-256 for those independent reads;
- an external memory programmer as one backup and restore route;
- a second existing-flash-independent route, such as measured K210 ROM ISP or
  a documented vendor service BootROM;
- a full write, full readback equal to the stock backup, cold stock boot, and
  exact stock identity check through each route;
- a controlled interrupted restore followed by recovery through the other
  admitted route, another full readback, and another stock cold-boot/identity
  check;
- separate logs, readbacks, boot records, and identity records for each run.

The interruption drill is destructive by design. Run it only on a sacrificial
unit after both ordinary recovery paths have succeeded and only under a
specific authorization that includes controlled interruption and power-cycle
actions. A stock update API alone is not an existing-flash-independent recovery
path.

## Sign and verify the completed evidence

The operator and witness independently review the same completed descriptor and
evidence tree. Create the canonical bundle with their distinct keys:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_recovery_receipt.py create `
  --descriptor C:\evidence\a1246-unit-01\recovery-descriptor.json `
  --evidence-root C:\evidence\a1246-unit-01\recovery-evidence `
  --operator-private-key C:\secure\k210-recovery-operator `
  --witness-private-key C:\secure\k210-recovery-witness `
  --bundle-out C:\evidence\a1246-unit-01\recovery-bundle
```

Check both signatures and every snapshotted byte directly:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_recovery_receipt.py verify `
  --bundle C:\evidence\a1246-unit-01\recovery-bundle `
  --operator-public-key C:\secure\k210-recovery-operator.pub `
  --witness-public-key C:\secure\k210-recovery-witness.pub
```

Direct verification proves consistency with the supplied keys. It does not
make either key trusted by the gauntlet.

## Trust-anchor admission

After independent review, copy only the two public keys into separate
repository-controlled trust paths. Change the recovery contract state to
`dual_signed_stock_recovery_admission` and pin each role with exactly its
repository-relative path, role, and lowercase SHA-256 key ID.

Supply both exact-unit bundles together:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_gauntlet.py report `
  --corpus required `
  --discovery-bundle C:\evidence\a1246-unit-01\discovery `
  --recovery-bundle C:\evidence\a1246-unit-01\recovery-bundle
```

An admitted recovery receipt qualifies only `stock_restore`, after its linked
discovery receipt qualifies `exact_model_identity`. `boot_policy` then becomes
the first blocker. The receipt does not qualify custom-firmware boot,
ASIC control, thermal/power safety, rollback of a DCENT update, mining,
endurance, release, or production readiness.
