# A1246 pre-hardware fixture qualification

This is the EE admission contract that must be completed for the exact owned
A1246 revision before any recovery write, controller-to-hashboard capture,
ROM-ISP/JTAG experiment, plaintext-boot probe, or custom-firmware first light.
It is a planning and evidence contract only; it authorizes no hardware action.

## Current disposition

**NO-GO for powered probing, recovery, capture, or custom writes.** The exact
MM3 controller revision, flash part and voltage, controller supply path,
hashboard connector levels, independent hash-power cutoff, cooling custody,
and safe in-circuit programmer isolation have not been measured on a named
unit. The held AUPs and repair references cannot substitute for those facts.

## Separate operator authorizations

Qualification is split into individually authorized stages. Approval for one
stage never grants the next:

1. de-energized visual inspection and label/connector census;
2. de-energized continuity/resistance work under an approved discharge and ESD
   procedure;
3. controller-only isolated power characterization with all hash power
   physically disconnected;
4. closed-chassis stock-powered passive voltage/logic capture;
5. external-programmer identification/read-only backup work; and
6. later recovery/write drills, each separately authorized after review.

Every stage names the exact unit, controller PCB revision, hashboard revision,
operator, witness, UTC window, instruments, probe points, stop conditions, and
the evidence directory. Normal stock power is never combined with an open-
cover photographic or continuity stage.

## Required evidence before `op-fixture` may complete

### Identity and isolation

- Controller PCB model/revision and every populated connector are recorded in
  de-energized photographs.
- Hashboard count/revision and the exact stock HWTYPE/SWTYPE/build are joined to
  an admitted discovery receipt; A3200LC-Plus, A3201-Plus, and A3200-Plus are
  not interchangeable labels.
- The hash-power domain is physically disconnected for controller-only work,
  with an independently witnessed disconnect and a separate feedback method
  proving the rail remains absent.
- Back-power paths through USB/UART/JTAG/programmer grounds and signal pins are
  enumerated. The procedure defines one common-ground point and forbids an
  instrument from energizing an unpowered domain through protection diodes.

### Power and electrical levels

- Controller input connector, nominal voltage, current limit, polarity, inrush,
  steady-state draw, and current-limited bench-supply settings are measured.
- Every candidate UART/SPI/JTAG/ISP/flash/hashboard signal has idle voltage,
  direction, reference ground, and absolute maximum/probe loading documented.
  Repair-guide hints that some A11/A12 signals are 1.8 V are treated as a probe
  warning, not as a measured A1246 fact.
- Level shifters and logic-analyzer inputs are qualified for the measured
  voltage. Five-volt and unverified 3.3-volt adapters are forbidden on an
  unresolved signal.
- ESD controls, isolated bench supply, fused/current-limited feeds, probe clips,
  and strain relief are listed and photographed before power is applied.

### Flash and recovery fixture

- Exact flash manufacturer/part/capacity/package and all supply rails are read
  from the named board and checked against a primary datasheet.
- In-circuit programmer use is proven not to contend with the K210 or back-power
  the board. Chip-select isolation, reset/hold state, any required series
  isolation, and 1.8 V adaptation are explicit.
- A flash-independent recovery path is physically distinct from the installed
  flash. At least one path must be an external programmer; ROM ISP/JTAG counts
  only after its entry wiring and exact-unit behavior are measured.
- Two byte-identical full-device reads are required before any erase/write.
  Restore, readback, cold-stock-boot, and interrupted-restore drills remain the
  separately authorized `op-recovery` stage.

### Cooling and cutoff custody

- Controller-only work cannot energize a hash rail. A physical disconnect or
  independently asserted cutoff and separate rail feedback are mandatory.
- Fan/pump topology, stock cooling controller, tach feedback, airflow direction,
  and a safe closed-chassis stock baseline are recorded before bounded work.
- No custom firmware may energize hash power until cooling is already proven,
  watchdog custody is active, temperatures are fresh, and cutoff feedback says
  the hash domain is de-energized. On any uncertainty, cut hash power before
  increasing fan noise.

## Instrument and stop gates

The reviewed stage card records calibrated instrument models, probe bandwidth,
sample rate, attenuation, ground method, programmer voltage/current limits, and
photos of the final connection. Stop immediately on unexpected voltage,
current-limit entry, heating, odor, smoke, unstable cooling, missing rail
feedback, ground potential difference, ambiguous pin identity, or any need to
move a probe while energized.

## Completion evidence

`op-fixture` requires a dual-reviewed evidence manifest, not a checkbox. It
binds the admitted discovery receipt/unit fingerprint, controller and
hashboard revisions, all measurement files and photographs by SHA-256, the
operator and independent EE reviewer, deviations, unresolved points, and an
explicit disposition for each later action:

- `recovery_fixture_ready`
- `passive_capture_fixture_ready`
- `rom_isp_probe_ready`
- `jtag_probe_ready`
- `controller_only_power_ready`
- `independent_cutoff_ready`
- `cooling_custody_ready`

Any unresolved or false item keeps its dependent workflow lane blocked. The
manifest records completed evidence and grants no future contact, power,
probe, capture, write, install, mining, or release authority.

## Machine-verifiable receipt

`scripts/k210_fixture_receipt.py` implements the completion contract. Its
bundle contains canonical `receipt.json`, distinct operator and EE-reviewer
SSHSIG signatures, and the exact evidence set. The verifier parses the
measurement records, validates fully decoded canonical PNGs, exact-joins the
discovery receipt and unit fingerprint, resolves the held-stock variant,
checks calibrated instruments and every signal class, requires byte-identical
full-device flash reads, and rejects any anomaly, stop, deviation, unresolved
point, false disposition, extra member, or gained authority.

Generate a descriptor only after the separately authorized work is complete:

```powershell
py -3 DCENT_OS_AvalonMiner/scripts/k210_fixture_receipt.py template `
  --discovery-receipt C:\evidence\a1246-discovery-bundle\receipt.json `
  --out C:\evidence\a1246-fixture-descriptor.json
```

Fill every placeholder and create the ten exact evidence files, then create
and independently verify the bundle:

```powershell
py -3 DCENT_OS_AvalonMiner/scripts/k210_fixture_receipt.py create `
  --descriptor C:\evidence\a1246-fixture-descriptor.json `
  --evidence-root C:\evidence\a1246-fixture-evidence `
  --operator-private-key C:\secure\dcent-k210-fixture-operator `
  --reviewer-private-key C:\secure\dcent-k210-fixture-reviewer `
  --bundle-out C:\evidence\a1246-fixture-bundle

py -3 DCENT_OS_AvalonMiner/scripts/k210_fixture_receipt.py verify `
  --bundle C:\evidence\a1246-fixture-bundle `
  --operator-public-key DCENT_OS_AvalonMiner/gauntlet/trust/k210-fixture-operator.pub `
  --reviewer-public-key DCENT_OS_AvalonMiner/gauntlet/trust/k210-fixture-reviewer.pub
```

Copy the discovery and fixture bundles into the Git-ignored
`.k210-gauntlet-evidence/a1246/` transfer root. This preserves the workflow's
repo-relative, non-symlink path checks without tracking unit photos or
measurements. Admit both bundles with the gauntlet, then complete `op-fixture`
using this exact descriptor:

```json
{
  "bundles": {
    "discovery_bundle": ".k210-gauntlet-evidence/a1246/discovery-bundle",
    "fixture_bundle": ".k210-gauntlet-evidence/a1246/fixture-bundle"
  },
  "kind": "dcent_k210_operator_fixture_evidence",
  "model": "a1246",
  "schema_version": 1
}
```

The lane persists only `exact_unit_fixture_qualified`. This is a prerequisite
claim, not a production gate: `thermal_power_safety` must remain false until
the later model-bound firmware, real BSP I/O, independent cutoff, cooling, and
fault-injection work is implemented and admitted.
