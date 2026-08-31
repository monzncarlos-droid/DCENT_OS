# A1246 fault and endurance admission

This is the operator runbook for `op-endurance`. The canonical schema,
commands, thresholds, fault vocabulary, and evidence formats are in
[`K210_BENCH_ENDURANCE_RECEIPTS.md`](K210_BENCH_ENDURANCE_RECEIPTS.md). It is an
immutable record of separately authorized past work, not permission to begin
or repeat testing.

## Preconditions

Use the complete exact-unit route chain plus passing, admitted first-light and
bounded-bench receipts. The bench receipt ID/evidence digest must exact-join the
embedded predecessor, and the bench receipt must itself join the admitted
first-light receipt. Reconfirm the route-specific installed artifact, recovery,
no-clobber, stock restoration, independent cutoff, cooling, sensors, watchdog,
and emergency-stop custody.

## Campaign and witness

Obtain a new narrow authorization covering the named unit, time window,
duration, pool, limits, complete required fault set, and emergency-stop owner.
Run the canonical endurance action sequence and every required injected fault;
retain chronological session, runtime, cooling, cutoff, share, safety, fault,
and endurance records. Stop on any out-of-scope action, missing telemetry,
failed cutoff, thermal breach, or custody loss. Preserve negative outcomes.

After the campaign, create a `fault_endurance` bundle. Its operator and witness
must use the distinct manifest-pinned endurance keys. Verify locally, then
submit an `op-endurance` descriptor carrying all cumulative predecessor,
first-light, bench, and endurance bundle paths.

This lane may qualify `endurance_faults`; only a later exact-scope release
preauthorization and witnessed-install capstone may qualify release authority.

