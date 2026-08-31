# K210 exact-unit discovery receipts

This is the evidence bridge from a documentary model row to one observed
physical AvalonMiner. The receipt binds the controller, ASIC family, stock
identity, PSU, cooling, and hashboard topology to snapshotted evidence and an
observer SSHSIG/Ed25519 signature.

It grants no authority. In particular, a valid receipt does not authorize
future contact, configuration, reboot, power or cooling control, hashing,
firmware writes, recovery work, or release. Collection requires a pre-existing
operator authorization for the named unit and four exact historical phase
actions: de-energized inspection power-down, visual inspection, closed-chassis
stock power restoration, and read-only management queries. The receipt
truthfully records that required power-state transition while every mutation
field remains false. The tools contain no miner transport.

## Default state

`k210_models.json` intentionally has `trust_anchor: null`. In that state:

- templates and offline bundles can be created;
- a bundle can be checked directly against an explicitly supplied public key;
- the gauntlet cannot admit any bundle or advance `exact_model_identity`.

Pinning an observer key is a separate reviewed repository change. Do not commit
private keys, raw credentials, pool secrets, or unredacted personal data.

## Bundle workflow

Generate an unencrypted Ed25519 observer key in an access-controlled location
outside the repository. Protect the private key according to the operator's
custody policy.

```powershell
ssh-keygen -t ed25519 -N "" -f C:\secure\dcent-k210-observer
```

Create a descriptor for an exact physical-model row:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_discovery_receipt.py template `
  --model a1246 `
  --out C:\evidence\a1246-unit-01\capture.json
```

Replace every placeholder. The authorization interval and reference must name
the authorization that already covered collection. Each required evidence file
must exist below `--evidence-root` at its descriptor path. Remove credentials
and unrelated personal identifiers before bundling, and record the applicable
redaction state. Each collection-log event set must contain the four exact
phase action identifiers emitted by the template contract; any stop reason,
collector fault, failed command, or unknown top-level stop/deviation field is
inadmissible.

Create the immutable snapshot and signature:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_discovery_receipt.py create `
  --capture C:\evidence\a1246-unit-01\capture.json `
  --evidence-root C:\evidence\a1246-unit-01\source `
  --private-key C:\secure\dcent-k210-observer `
  --bundle-out C:\evidence\a1246-unit-01\signed-bundle
```

Verify the bundle directly before any admission review:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_discovery_receipt.py verify `
  --bundle C:\evidence\a1246-unit-01\signed-bundle `
  --public-key C:\secure\dcent-k210-observer.pub
```

Direct verification proves consistency with the supplied key; it does not make
that key trusted by the gauntlet.

## Trust-anchor admission

After independent review, copy only the public key into a repository-controlled
trust path. Change the manifest discovery state to
`signed_read_only_receipt_admission` and set exactly:

```json
{
  "key_id_sha256": "lowercase SHA-256 key ID reported by verification",
  "path": "repository-relative/path/to/observer.pub",
  "role": "k210_discovery_observer"
}
```

The gauntlet checks the key bytes against the pinned ID. It accepts at most one
receipt per target row, rejects duplicate receipt IDs and unit fingerprints,
rejects linked or unexpected bundle members, and refuses family/candidate rows
or physical rows whose ASIC family is still unknown. Resolve the canonical
model row before signing; do not force an observation into a near neighbor.
Supply admitted bundles explicitly:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_gauntlet.py report `
  --corpus required `
  --discovery-bundle C:\evidence\a1246-unit-01\signed-bundle
```

A valid admitted bundle qualifies only `exact_model_identity`. For A1246 and
A1246N, the gauntlet carries the semantically resolved held variant profile
into the stock-restore decision; it does not fall back to the generic target's
default profile. The next gate is still `stock_restore`; all write, boot, ASIC,
thermal/power, mining, endurance, and release work remains blocked until its
own evidence contract qualifies.

## Required evidence

- Collection log
- Controller front and back photos
- Cooling topology photo
- Hashboard topology record
- Miner label photo
- PSU label photo
- Stock `stats` response
- Stock `version` response

Optional evidence supports flash marking, stock `estats`, and UART-pad photos.
Every admitted photo must be a non-interlaced 8-bit RGB/RGBA PNG. The verifier
checks chunks and CRCs, fully inflates the bounded IDAT stream, validates each
scanline, and rejects JPEG or corrupt payloads. The receipt records file sizes
and SHA-256 digests, canonicalizes its JSON, and is signed under the fixed
`dcent-k210-discovery-v1` SSHSIG namespace.
