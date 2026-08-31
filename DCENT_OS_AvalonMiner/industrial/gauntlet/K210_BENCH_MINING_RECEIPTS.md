# A1246 bounded bench-mining admission

This is the operator runbook for `op-bench`. The canonical schema, commands,
limits, and evidence formats are in
[`K210_BENCH_ENDURANCE_RECEIPTS.md`](K210_BENCH_ENDURANCE_RECEIPTS.md). A bundle
records a separately authorized session that already occurred and grants no
future authority.

## Preconditions

Use the complete exact-unit route chain and a passing, admitted `first_light`
receipt. The first-light receipt ID and evidence-set digest must exact-join the
copy embedded in this bundle. Reconfirm cooling, independent cutoff, watchdog,
sensors, emergency-stop custody, route, installed artifact, and stock recovery
before the bounded session.

## Session and witness

Obtain a new narrow authorization for the named unit, window, pool, duration,
power, temperature, telemetry gap, and cutoff response. Run only the canonical
bounded-mining action sequence, retain complete session/share/runtime/cooling/
cutoff/safety records, stop on any limit or deviation, and restore the safe
terminal state.

After the session, create a `bounded_bench_mining` bundle. Its operator and
witness must use distinct manifest-pinned bench keys that are also distinct
from every earlier role key. Verify locally, then submit an `op-bench`
descriptor carrying the cumulative predecessor paths, `first_light_bundle`,
and `bench_bundle`.

This lane may qualify `bench_mining`; it cannot qualify endurance or release.

