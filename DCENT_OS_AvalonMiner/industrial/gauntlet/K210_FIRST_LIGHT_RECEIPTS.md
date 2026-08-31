# A1246 staged first-light admission

This is the operator runbook for `op-firstlight`. The canonical schema, safety
boundary, descriptor commands, and evidence formats are in
[`K210_BENCH_ENDURANCE_RECEIPTS.md`](K210_BENCH_ENDURANCE_RECEIPTS.md). This
stage records a separately authorized session that already occurred; it does
not itself authorize hardware contact.

## Immutable inputs

Use the exact admitted discovery, fixture, passive-capture, recovery,
boot-policy, route-replacement, and route-rollback receipts for one A1246 unit.
Do not mix units, variants, routes, artifact members, or prior campaigns. The
installed artifact digest is the actual route-specific member: AUP for native
AES0, raw image for ROM-ISP/JTAG SRAM, or controller artifact for the clean
replacement-controller route.

## Session and review

Obtain a narrow written authorization naming the unit, time window, power,
temperature, telemetry-gap, cutoff-response, pool, emergency-stop owner, and
the exact first-light actions. Follow the canonical ordered safe-idle,
cooling/cutoff/watchdog/sensor, hash-enable, pool, stop, rollback, and
stock-identity checks. Preserve failed and stopped outcomes.

After the session, create a `first_light` bundle. The operator, protocol
reviewer, and independent EE/safety reviewer must use the three distinct
manifest-pinned keys and review the immutable evidence before signing. Verify
the bundle locally, then submit an `op-firstlight` workflow descriptor carrying
the seven predecessor bundle paths plus `first_light_bundle`.

The lane may qualify both `asic_control` and `thermal_power_safety`; it cannot
qualify bench mining, endurance, release, or grant future authority.

