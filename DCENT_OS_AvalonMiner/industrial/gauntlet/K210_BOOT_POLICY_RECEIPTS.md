# K210 exact-unit boot-policy receipts

This contract closes the measurement portion of the `boot_policy` gate for one
already-discovered, recovery-proven AvalonMiner controller. It records the
exact unit's flash layout, boot/load address, force-decrypt posture, ROM ISP,
JTAG, and controlled plaintext-boot outcome. It is an evidence verifier, not a
measurement executor: the tool has no miner, programmer, serial, USB, JTAG,
GPIO, power, flash, or block-device transport.

A receipt may validly report incompatibility. For example, force-decrypt may be
enabled, JTAG may be locked, or a controlled `aes_enable=0` image may be
rejected. That still resolves the measurement gate; it does not make the clean
DCENT candidate compatible. `replacement_firmware` remains blocked on the
specific negative result and, in all cases today, on the missing target BSP and
physical safety control.

The receipt records a completed, separately authorized measurement and grants
no future authority. Do not contact, open, power-cycle, probe, read, write, or
restore a miner merely because this schema exists. Each physical action needs
explicit authorization for the named unit and action, a reviewed procedure,
electrical controls, and the already-admitted two-path stock recovery proof.

## Default state

`k210_models.json` intentionally pins neither boot-policy role. With both trust
anchors `null`, bundles can be built and checked directly against supplied
public keys, but the gauntlet admits none and cannot advance `boot_policy`.

Admission requires distinct SSHSIG/Ed25519 roles:

- `k210_boot_policy_operator` signs the exact execution record;
- `k210_boot_policy_witness` independently signs the same canonical receipt.

The roles must use different principals, private keys, public-key paths, and
key IDs. Keep private keys outside the repository.

## Prerequisite and exact joins

Start from the canonical `receipt.json` inside an exact-unit recovery bundle.
The discovery and recovery bundles must separately be admitted by the
gauntlet. Boot-policy admission rejects any mismatch in target, unit label,
unit fingerprint, discovery receipt ID, recovery receipt ID, stock backup-set
digest, stock identity, or recovered flash-device identity.

Create a descriptor template bound to that recovery receipt:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_boot_policy_receipt.py template `
  --recovery-receipt C:\evidence\a1246-unit-01\recovery-bundle\receipt.json `
  --out C:\evidence\a1246-unit-01\boot-policy-descriptor.json
```

Copy the same canonical recovery receipt to
`identity/recovery-receipt.json` below the boot-policy evidence root. Replace
every placeholder, date, transport, region, and measured outcome. The template
uses a full-device boot-region placeholder only to remain structurally valid;
it is not a claim about a real flash map.

## Safety and measurement invariants

Before a receipt can verify, its signed record must establish all of these:

- controller-only power, with hash power physically disconnected and an
  independent hash-power cutoff asserted;
- a cooling posture explicitly reviewed as safe for controller-only work;
- full, ordered, contiguous, non-overlapping coverage of every flash device
  recorded by recovery, with exact technology, manufacturer, model, and
  capacity matches;
- an identified boot-image region and measured boot/load address;
- a resolved force-decrypt state of `enabled` or `disabled`, never `unknown`;
- an OTP-key posture record without requiring or claiming secret-key
  extraction;
- measured ROM ISP and JTAG states, including capabilities only when the route
  is actually accessible;
- stock boot/identity checks before and after measurement;
- no hash-power energizing or production hashing.

If force-decrypt is enabled, the canonical negative outcome performs no
plaintext write and records `not_run_force_decrypt_enabled`. If force-decrypt
is disabled, the contract requires an actual controlled AES0 probe, its exact
artifact, an independent observation, full stock restore through the already
proven route, and post-restore stock identity. The signed action disclosure
must agree with whether a custom image was written and restored.

This contract deliberately does not read or recover OTP key material. The held
AUP corpus proves only that eight stock packages carry encrypted K210
containers; it does not prove an AES key, an OTP recovery route, or an exact
unit's force-decrypt setting.

## Required evidence

Exactly one of each is required:

- recovery receipt copy;
- controller-only safety-isolation record;
- full flash-map record;
- eFuse/force-decrypt record;
- ROM ISP record;
- JTAG record;
- boot/load-address record;
- plaintext-probe record, including a policy-based non-run when force-decrypt
  is enabled;
- stock pre-measurement boot record;
- stock post-measurement boot and identity record.

A plaintext probe artifact is additionally mandatory when the probe was
performed. An updater-parser record is optional. The verifier snapshots every
file, pins its size and SHA-256, rejects links/reparse points and unexpected
bundle members, and signs canonical JSON under separate operator and witness
namespaces.

## Sign and verify completed evidence

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_boot_policy_receipt.py create `
  --descriptor C:\evidence\a1246-unit-01\boot-policy-descriptor.json `
  --evidence-root C:\evidence\a1246-unit-01\boot-policy-evidence `
  --operator-private-key C:\secure\k210-boot-operator `
  --witness-private-key C:\secure\k210-boot-witness `
  --bundle-out C:\evidence\a1246-unit-01\boot-policy-bundle
```

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_boot_policy_receipt.py verify `
  --bundle C:\evidence\a1246-unit-01\boot-policy-bundle `
  --operator-public-key C:\secure\k210-boot-operator.pub `
  --witness-public-key C:\secure\k210-boot-witness.pub
```

The verified result includes the signed ROM-ISP and JTAG capability booleans
needed by the non-authorizing route policy. Once the same keys are pinned in
the canonical manifest, rank all four engineering paths with
`k210_boot_route.py`; see
`K210_BOOT_ROUTE_ADJUDICATION.md`. A ROM/JTAG result can establish only
controlled SRAM-probe eligibility until execution and recovery are separately
proven.

Direct verification proves consistency with the supplied keys and embedded
recovery receipt. It does not make those keys or the linked discovery/recovery
receipts trusted by the gauntlet.

## Trust-anchor admission

After independent review, copy only the two public keys into separate
repository-controlled trust paths. Change the boot-policy contract state to
`dual_signed_boot_policy_admission` and pin each role with its exact
repository-relative path, role, and lowercase SHA-256 key ID.

Supply all three exact-unit bundles together:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_gauntlet.py report `
  --corpus required `
  --discovery-bundle C:\evidence\a1246-unit-01\discovery-bundle `
  --recovery-bundle C:\evidence\a1246-unit-01\recovery-bundle `
  --boot-policy-bundle C:\evidence\a1246-unit-01\boot-policy-bundle
```

An admitted receipt qualifies only the completeness of `boot_policy`, after
the linked identity and stock-recovery gates qualify. It does not qualify the
DCENT firmware, ASIC control, thermal/power safety, rollback, mining,
endurance, release, or production readiness. A positive AES0/load result is a
prerequisite, not install authority; a negative result is a measured blocker,
not permission to bypass the device's security policy.
