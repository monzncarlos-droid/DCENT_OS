# Nano 3 independent safety interlock

**Document state:** buildable desk specification; live qualification pending
**Target:** Canaan Avalon Nano 3 running stock coexistence or future native
DCENT_OS
**Safety claim:** none. In particular, this package does **not** claim a
verified ASIC-rail cut, verified trip time, or certified functional-safety
rating.

## 1. Why this fixture exists

The held Nano 3 recovery image exposes no proven independent hash-power cut.
Stock `softoff`/`softon` are stubs, the observed `hashpower 0` path does not
send a shutdown command, GPIO 61 is a short controller reset pulse, and the
K230 watchdog resets only the host. Live testing also showed that hashing can
continue while management and thermal observability stop responding.

Until a rail-level cutoff is physically found and measured, the production
boundary is therefore outside the miner: remove input power from the original
Canaan power adapter. This fixture puts two independently controlled,
normally-open contactors in series ahead of that adapter. Loss of control
power, heartbeat, temperature validity, fan motion, or supervisor health
drops both coils. One welded contact is detected by mechanically linked
feedback and the other contactor still opens.

The evidence basis is
. The
machine-readable status and parameters are in `interlock-contract.json`.

## 2. Safety boundary

The controlled output supplies only the stock Nano 3 power adapter. The
fixture's isolated low-voltage control supply is connected before the cutoff
so the supervisor remains alive after a trip. Protective earth is never
switched.

```text
 AC inlet
    |
  QF1/F1 ---- PS1 isolated 24 V control supply ---------------------+
    |                                                               |
  K1 NO main poles -- K2 NO main poles -- controlled receptacle     |
                                            |                       |
                                  stock Canaan adapter              |
                                            |                       |
                                          Nano 3                    |
                                                                    |
 E-stop -- temperature limits -- fan monitor -- heartbeat watchdog |
    |                                                               |
   SR1 safety supervisor <--- K1/K2 mirror contacts                 |
    |                    <--- independent hardware watchdog --------+
    +---- independent safety outputs ---- K1 coil / K2 coil
```

Switch all current-carrying conductors required by the local wiring code.
Keep protective earth continuous and bonded to the enclosure. Mains wiring,
clearance, creepage, fusing, strain relief, conductor gauge, terminal
protection, and enclosure selection require review by a qualified electrical
safety engineer for the deployment region.

This architecture deliberately cuts the **whole device**, not an assumed ASIC
rail. It is independent of Linux, Wi-Fi, `btcminer`, `/dev/ttyS1`, and the K230
watchdog. It also stops the stock fan. Whole-device containment is therefore
acceptable for production only after the worst-case hot-soak passive
coast-down proves that stored heat cannot exceed component/material limits
after the contacts open. If that cannot be proven with margin, production
requires a hash-domain-only cut that leaves control and cooling powered. Such
a design must first trace the PCB, identify the ASIC supply or VRM enable, and
measure that rail falling below its defined off threshold.

The held unit is powered through USB-C Power Delivery. The cutoff remains on
the AC input to the charger; this avoids inserting an unqualified switch into
the high-current USB-C/PD path. Two exact, alternative candidate assemblies are
controlled: the Canaan-bundled `TP14A1` with its captive USB-C lead, and
Plugable `PS-EPR-140C1` plus Plugable `USB4-240W-1M`. Neither is approved or an
interchangeable class. `USB_C_POWER_CHAIN_QUALIFICATION.md` records source
review, unresolved authenticity/nameplate/certification fields, cold/warm PD
captures, sustained thermal procedure, and substitution controls. Marketplace
fields such as `12 V/11.67 A`, a generic cable, a wattage label by itself, or a
third-party anecdote are not acceptance results. Changing any power-assembly
component requires full requalification.

## 3. Required channels

### 3.1 K1/K2 power path and feedback

- K1 and K2 are normally-open, positively guided/force-guided switching
  devices in series. Each must be capable of interrupting the adapter's
  measured steady-state current and inrush at the actual mains voltage.
- SR1 has separate safety outputs for the two coils. A single ordinary MCU pin
  must not be able to keep both energized.
- Normally-closed guided mirror contacts provide state-dependent external-
  device monitoring (EDM). They must prove open main poles before arm, make
  the expected feedback transition after pickup, and prove open main poles
  again after a trip. They are not a continuously series-connected coil
  permit; `WIRING.md` defines the commanded-state checks.
- A welded K1 must still be cleared by K2, and vice versa. A detected weld
  latches `EDM_FAULT` and requires repair; reset must not re-energize either
  coil.
- A local lockable upstream disconnect remains required for service and the
  dual-weld fault.

### 3.2 Independent temperature limits

Use two separately powered/supervised sensor channels:

- TH1 is mechanically retained against the hottest repeatably accessible
  heatsink point identified during thermal mapping.
- TH2 measures a second independent point, preferably exhaust temperature or
  a second heatsink location that detects a detached/blocked primary sensor.
- Each channel uses a hardware temperature-limit relay/window comparator with
  lead open/short detection. A detached, open, shorted, implausible, or
  over-limit channel is a trip, not an ignored sample.
- The hardwired temperature contacts remain authoritative in every state,
  including the boot grace window and while diagnostic firmware is absent.
- `T_trip`, `T_reset`, allowed sensor disagreement, and sensor placement are
  intentionally `TBD_LIVE_VALIDATION`. They must be locked from instrumented
  thermal characterization, component tolerances, and the safe temperature of
  the materials actually used. They must not be copied from an unverified UI
  temperature.

### 3.3 Independent fan-motion channel

The preferred fan input is an independent optical or Hall pickup that does not
load the stock fan wiring. A high-impedance isolated tap of the fan tach may be
used only after its voltage, polarity, pull-up, and pulses/revolution are
measured on the Nano 3.

FS1 is a hardware frequency-window monitor. Missing pulses, stuck high, stuck
low, under-speed, over-range/noise, or interface power loss must open its
healthy contact. The production minimum RPM and debounce window are
`TBD_LIVE_VALIDATION`. Fan validity is not inferred from PWM command, process
liveness, noise, network state, or mining shares.

### 3.4 Dynamic custody heartbeat

The production heartbeat is an isolated physical signal into J2. It is not a
TCP check, miner API response, share counter, diagnostic collector completion,
or periodic timer unrelated to thermal custody.

The provisional electrical contract is a 24 V fixture-side opto-isolated
input accepting a dry-contact or open-collector return. An adapter may be
needed on the Nano side; no spare Nano 3 GPIO is assumed by this document.
The runtime waveform contract is:

1. Nominal 2 Hz square wave, 20--80% duty cycle.
2. WD1 validates both rising and falling edges. Stuck-high and stuck-low are
   equivalent to absence.
3. Six consecutive valid cycles are required before `HB_VALID`.
4. Missing or invalid edges drop `HB_VALID` within 1.5 seconds. This is a
   conservative commissioning value, not a qualified safe trip time; the
   final value must be no greater than the measured safe cutoff budget.
5. The DCENT runtime may toggle the output only after one complete control
   iteration has obtained fresh temperature inputs, applied the intended fan
   command, observed valid fan feedback, and found no controller fault. A
   free-running heartbeat thread is forbidden.
6. The output starts inactive and stops immediately on shutdown, process
   failure, stale inputs, UART loss, fan-custody loss, or an internal
   consistency failure.

For stronger diagnostic coverage, the fixture controller may issue a changing
challenge on J2 and require a matching response. That extension cannot weaken
the hardwired temperature, fan, watchdog, or E-stop chain.

The current stock-coexistence image has **no proven physical heartbeat source**.
The `nano3-health-snapshot.sh` markers explicitly are not a heartbeat. A stock
Nano 3 therefore cannot pass the automatic production-arm gate from the held
evidence. Laboratory operation needs direct supervision and the independent
thermal/fan cutoff; native takeover remains closed until the physical signal
and its software coupling are demonstrated.

### 3.5 Supervisor watchdog

Any programmable logger/controller U1 is supervised by a separate hardware
watchdog WD2. WD2's healthy relay is required in the coil-enable chain. WD2
must de-energize on U1 clock failure, firmware hang, brownout, invalid
sequence, or loss of its retrigger signal. U1 may record diagnostics but cannot
override E-stop, temperature, fan, heartbeat, EDM, or WD2.

## 4. Operating state machine

| State | Main contacts | Entry and behavior |
|---|---:|---|
| `SAFE_OFF` | Open | Power-up default. No automatic start after power return. |
| `SELF_TEST` | Open | Manual ARM requested; verify sensors, E-stop, WD2, and both open mirror contacts. |
| `START_WINDOW` | Closed | Bounded boot grace. Hard temperature limits and E-stop remain active. Fan tach and heartbeat must become valid before the qualified deadlines. |
| `RUN` | Closed | Every healthy input must remain true continuously. Any fault drops both coils. |
| `TRIPPED_LATCHED` | Open | Fault is logged and latched. Clearing the cause does not restart the miner. |
| `EDM_FAULT` | Open commanded | A main contact did not prove open. Lockout until physical repair and test. |

Manual RESET/ARM may leave `TRIPPED_LATCHED` only when temperatures are below
the characterized reset threshold, both sensor channels are plausible, the
E-stop loop is healthy, the contactors prove open, WD2 is healthy, and no
bypass is fitted. Fan and heartbeat are allowed to become valid only inside
the bounded `START_WINDOW`, because neither can exist while whole-device power
is removed. The window lengths must be derived from cold/warm boot tests and
the measured no-fan thermal rise; the unqualified fixture must never be left
unattended during that characterization.

There is no production bypass. A commissioning-only bypass, if a safety
engineer permits one, must be keyed, spring-return, conspicuously indicated,
logged, excluded from acceptance results, and incapable of bypassing E-stop or
the hard temperature limits.

## 5. Low-voltage interface

| Connector | Direction | Contract |
|---|---|---|
| J1 | Input | 24 VDC/0 V from PS1; fused at the fixture. |
| J2 | Bidirectional option | Isolated heartbeat return plus optional challenge; no shared Nano ground required. |
| J3 | Input | Independent fan sensor / isolated tach interface. |
| J4/J5 | Input | TH1/TH2 sensor pairs with lead-fault detection. |
| J6 | Input | Dual-channel normally-closed E-stop loop. |
| J7 | Input | Momentary manual RESET/ARM; no maintained auto-run input. |
| J8 | Output | Independently fused K1 and K2 coil drives. |
| J9 | Input | K1/K2 positively guided mirror contacts for EDM. |
| J10 | Output | Galvanically isolated diagnostic port; read-only with respect to the safety chain. |

Mains input/output are touch-safe certified connectors inside the enclosure,
not generic PCB headers. Sensor connectors must be keyed and cannot be
interchanged with coil, heartbeat, or mains wiring.

`WIRING.md` defines the two-channel permit logic, contact allocation, and the
bounded startup bypass. It is a functional interconnect, not a certified
construction drawing.

The checked-in desk contract must also remain fail-closed:

```text
py -3 DCENT_OS_AvalonMiner/scripts/validate_nano3_power_contract.py
```

This validator joins `interlock-contract.json`, `bom.csv`,
`fault-injection-matrix.csv`, and `qualification-record.template.json`. It
pins both USB-C candidate identities/PDO sets, the required unselected BOM,
the exact pending fault campaign, state-dependent EDM/reset invariants, source
artifact hashes, and the no-authority qualification template. It rejects any
premature approval/native-takeover bit or deletion/reordering of a required
fault. It validates documentation state only and cannot replace physical
measurements or review.

`qualification-record.template.json` is a capture checklist, not a record that
can be promoted by editing `qualification_status`. It deliberately has null
numeric limits, 63 pending fault results, no evidence artifacts, pending
reviews, and all authority fields false. Copy it into an external controlled
evidence workspace for a future campaign. The checked-in validator admits only
the unqualified template; a signed completed-record compiler and verifier must
be implemented and independently reviewed before any result can be compiled
into `dcentrald`'s separate production-qualification latch.

## 6. Build and qualification sequence

1. Select exact components against `bom.csv`, adapter nameplate data, measured
   inrush, USB PD negotiation, exact charger/cable identities, deployment
   voltage/frequency, enclosure environment, and regional code. Record
   manufacturer datasheets and derating calculations.
2. Assemble and electrically inspect the fixture with a non-mining dummy load.
   Verify PE continuity, insulation, polarity, fusing, contact separation,
   coil suppression, and E-stop operation.
3. Run every non-Nano fault in `fault-injection-matrix.csv` using the dummy
   load. Measure contact opening and prove both single-weld cases with one
   contact mechanically held closed only in a controlled test fixture.
4. With the Nano behind an additional current-limited upstream disconnect,
   map input current, adapter output, candidate ASIC rail, heatsink/exhaust
   temperatures, fan behavior, hash disappearance, and the complete passive
   thermal coast-down after the whole-device cut. The unit is attended
   throughout.
5. Derive and lock temperature limits, fan threshold, boot grace, heartbeat
   timeout, and maximum cutoff budget in an external copy of
   `qualification-record.template.json`. Attach content hashes for every raw
   trace and independent review. Do not change the checked-in desk contract or
   Rust release latches merely because a worksheet is filled in.
6. Repeat cold, hot, warm-restart, soak, and every relevant injected fault.
   A pass requires measured loss of hashing and the candidate ASIC rail below
   its regulator/ASIC-defined off threshold within the qualified budget.
7. Obtain electrical and functional-safety review before production use.
8. Implement and review the still-missing signed qualification-record compiler
   and verifier, then bind its exact record ID/SHA-256 and numeric envelope in
   the same reviewed change that releases the Rust energization latches.

## 7. Release gates

The fixture is not production-ready until all of these are true:

- exact K1/K2, SR1, WD1/WD2, PS1, sensors, protection, enclosure, and wiring
  are reviewed and controlled;
- actual adapter inrush and interruption ratings are inside component limits;
- the exact USB PD charger/output-cable assembly negotiates only an accepted
  profile and passes sustained cable/connector thermal testing with margin;
- temperature and fan thresholds are tied to traceable measurements;
- startup and cutoff budgets pass worst-case hot-soak testing;
- after a worst-case hot-soak whole-device trip, passive temperature rise and
  peak temperature remain below reviewed component/material limits with
  margin, or a qualified hash-domain cut keeps cooling powered;
- K1-weld, K2-weld, U1-hang, heartbeat-stuck, fan-loss, sensor open/short,
  E-stop, control-power-loss, and management-starvation tests all pass;
- contactor opening is correlated with input current, ASIC-rail collapse, and
  cessation of valid hashing;
- loss of power never causes automatic re-arm; and
- the completed matrix, raw traces, calibration records, and independent
  review are attached to the release record.

Until then, the only accurate description is **prototype external whole-unit
cutoff fixture, qualification pending**.
