# Functional wiring contract

This file defines logic and separation for the prototype interlock. It is not
a PCB layout, certified panel drawing, or permission to wire mains without a
qualified reviewer.

## Contact conventions

Every `*_OK` contact is closed only while its monitor is powered, internally
healthy, and observing a valid input. Loss of monitor power opens the contact.
Components that feed both safety channels must provide two suitable guided or
safety-rated contacts; do not bridge one ordinary relay contact into both
channels.

| Signal | Channel A | Channel B | Healthy meaning |
|---|---|---|---|
| Emergency stop | `ESTOP_A` | `ESTOP_B` | Both positively opening NC loops closed |
| Temperature | `TH1_OK` | `TH2_OK` | Separate sensor/limit channel plausible and below trip |
| Fan monitor | `FAN_OK_A` | `FAN_OK_B` | Dynamic fan pulses in the characterized window |
| Heartbeat | `HB_OK_A` | `HB_OK_B` | Both edges satisfy the physical heartbeat window |
| Supervisor watchdog | `WD2_OK_A` | `WD2_OK_B` | U1 hardware watchdog is being correctly retriggered |
| Startup timer | `START_A` | `START_B` | Independent non-retriggerable boot window has not expired |
| SR1 output | `OUT_A` | `OUT_B` | Both SR1 input channels and EDM are accepted |
| Contactor feedback | `K1_MIRROR` | `K2_MIRROR` | State-dependent guided feedback: open poles proved before arm/after trip and the commanded energized transition proved after pickup |

## Permit equations

The functional input equations are:

```text
RUNTIME_A = FAN_OK_A & HB_OK_A
RUNTIME_B = FAN_OK_B & HB_OK_B

PREARM_A = ESTOP_A & TH1_OK & WD2_OK_A
PREARM_B = ESTOP_B & TH2_OK & WD2_OK_B

INPUT_A = ESTOP_A & TH1_OK & WD2_OK_A & (START_A | RUNTIME_A)
INPUT_B = ESTOP_B & TH2_OK & WD2_OK_B & (START_B | RUNTIME_B)

OPEN_PROOF = K1_MIRROR_CLOSED & K2_MIRROR_CLOSED
RESET_PERMITTED = PREARM_A & PREARM_B & OPEN_PROOF & ARM_EDGE & NO_LATCHED_FAULT
RUN_HEALTHY = INPUT_A & INPUT_B
```

`SR1` implements the dual-channel discrepancy checks; the equations are not a
request to collapse the design into a single combinational MCU output.
`OUT_A` drives only K1 and `OUT_B` drives only K2. Both contactors are required
closed to power the load, while either one opening must remove power.

EDM is deliberately **not** shown as a continuously series-connected
`EDM_OK` term. The normally-closed guided mirror contacts used for open-pole
proof change state when K1/K2 pick up. Treating `K1_MIRROR & K2_MIRROR` as a
continuous coil permit would either chatter immediately after pickup or tempt
an unsafe feedback bypass. SR1 must instead evaluate feedback against the
commanded state:

- before an ARM edge, both mirror contacts prove both main poles open;
- after K1/K2 are commanded on, both feedback channels must make the expected
  energized transition inside the selected contactor/SR1 discrepancy time;
- after any trip, both must return to the proved-open state inside the
  qualified release/EDM time; and
- a missing, early, late, contradictory, or static transition latches
  `EDM_FAULT` and prevents a new arm.

The manual reset is an edge accepted by SR1, not an externally maintained
`MANUAL_RESET_LATCH` signal. Any safety trip, channel discrepancy, loss of
control power, or failed EDM transition clears the internal run latch. A reset
input held closed through a fault or power cycle must not restart the fixture;
it must be released and pressed again after the open-pole proof succeeds.

The ARM edge starts the two startup timers only after `RESET_PERMITTED`; fan
and heartbeat are intentionally not pre-arm inputs because neither exists
while the whole device is off. The hard-temperature and E-stop contacts are
outside the `START_*` branches
and are therefore active during boot. `START_A` and `START_B` are independent
hardware one-shots. They:

- can start only after a manual ARM edge while EDM proves both contactors open;
- cannot be retriggered or extended until both contactors again prove open;
- have separately generated timing paths;
- open at or before the characterized startup deadline; and
- create a channel discrepancy and trip if only one remains closed.

The final timer settings are `TBD_LIVE_VALIDATION`. Before they expire,
`RUNTIME_A/B` must close from valid fan and heartbeat signals. Otherwise SR1
drops both outputs. A normal transition may briefly have both the startup and
runtime branches closed; runtime custody remains after the timers open.

## Power wiring

```text
L/N as required by local code:

INLET -> lockable disconnect/branch protection -> K1 main -> K2 main
      -> touch-safe controlled receptacle -> original Canaan adapter

Branch before K1/K2:

protected mains -> PS1 -> fused 24 V control buses

PE:

INLET PE -> enclosure bond -> controlled receptacle PE
```

Never route PE through K1 or K2. The exact number of switched poles, neutral
treatment, overcurrent device, disconnect, wire size, contact rating, and
enclosure class follow the local electrical code and the reviewed deployment
drawing.

Coil suppression must be selected with measured release time in mind. A plain
flyback diode can make a DC contactor release materially slower; use the
contactor manufacturer's approved suppression or a reviewed TVS/diode network
and include its worst-case release in the safe cutoff budget.

## EDM and reset order

1. On power-up, SR1 outputs are open and the fixture is `SAFE_OFF`.
2. Both K1/K2 mirror contacts must prove the main poles open.
3. E-stop, both temperature limits, and WD2 must be healthy.
4. A deliberate RESET/ARM edge starts KT1/KT2 and permits SR1 to energize K1
   and K2.
5. The Nano boots inside the bounded window. Fan and heartbeat must validate.
6. KT1/KT2 expire. SR1 remains energized only through `RUNTIME_A/B`.
7. Any fault opens both SR1 outputs. EDM must then prove both contactors open.
8. A missing mirror contact enters `EDM_FAULT`; a new reset is rejected.
9. A maintained or welded RESET input is rejected as a reset edge and cannot
   re-arm after the fault clears or power returns.

Closing an E-stop, cooling a sensor, restoring heartbeat, or restoring mains
never restarts the Nano. Every trip requires a new manual reset after the
cause is cleared and the open-contact proof succeeds.

## Diagnostic separation

U1 may read isolated copies of state signals and write a timestamped fault
record. Its diagnostic connector cannot drive `INPUT_A`, `INPUT_B`, reset,
the startup timers, or either contactor coil. Firmware update mode holds WD2
invalid and therefore keeps the controlled receptacle off.
