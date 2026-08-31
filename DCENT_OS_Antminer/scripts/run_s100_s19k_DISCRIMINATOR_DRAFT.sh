#!/bin/sh
# =============================================================================
# DRAFT — NOT OPERATOR-AUTHORIZED — DO NOT RUN
# =============================================================================
# run_s100_s19k_DISCRIMINATOR_DRAFT.sh
#
# GAP2 desk proposal (2026-08-19), companion to:
#   DCENT_OS_Antminer/
#
# Purpose: stage (NOT execute) the next live discriminator for the S19k Pro
# `.88` Track-1 MULTI/RX-death blocker (no session has survived to T+600 s).
#
# D1 (this script's core): launcher-side kernel serial-counter sampling while
# an ALREADY-AUTHORIZED soak of an ALREADY-STAGED binary runs. Read-only procfs
# `cat`s only. No SSH, no staging, no Miner contact, no GPIO, no flash happens
# by creating this file. Every target-side action below remains operator-gated.
#
# Decision table this sampling answers at RX death:
#   kernel rx still climbing, host MULTI_RX silent  -> host reader stall
#   kernel rx climbing + overrun/frame/parity delta -> kernel FIFO overrun (RX backpressure real)
#   kernel rx frozen, zero error deltas, host-silent-> chips stopped sending (BM1366-side cliff)
#   wire bytes but no assembled frame               -> frame-assembler cliff (parser class exists)
#
# Honest caveats (from the report):
#   - kernel 4.9 aarch64 meson-uart may NOT populate /proc/tty/driver/serial
#     (8250-family interface); the script probes once and falls back to
#     /proc/interrupts serial-IRQ deltas. If both are unusable, D2
#     (env-gated TIOCGICOUNT telemetry in serial_mining.rs, owned by the
#     sibling agent) is required instead.
#   - IRQ lines may be shared/coarse; DELTAS between samples are the signal.
#
# FLASH false. GPIO437 never written. S99 restore remains the operator's path.
# =============================================================================

# --- Guard: refuse to actually do anything without an explicit operator flag ---
if [ "$1" != "--OPERATOR-AUTHORIZED-LIVE-SOAK" ]; then
    echo "DRAFT — NOT OPERATOR-AUTHORIZED — DO NOT RUN" >&2
    echo "This launcher is a desk-staged proposal. It has never been executed." >&2
    echo "If the operator authorizes the soak, re-read every command below first." >&2
    exit 78  # EX_CONFIG: safe refusal, not a crash
fi

# Everything below this line is the PROPOSED procedure (unexecuted).
# It assumes the operator has already, under their own gates:
#   - confirmed .88 reachable, bosminer killed per the Track-1 recipe (PWM held 100),
#   - gpio437=0 read-only confirmed,
#   - staged the current soak binary + dcentrald_s19k.toml per the live44x run dirs,
#   - started dcentrald exactly as in the live440 run dir (same env set).
# This script adds ONLY passive observations around that authorized soak.

SAMPLE_DIR=/tmp/s100_rx_death_samples   # target-side, same /tmp staging policy as prior runs
mkdir -p "$SAMPLE_DIR"

probe_kernel_serial_stats() {
    # One-shot capability probe BEFORE the soak, so a silent/empty source is
    # discovered up front rather than after a dead run.
    {
        echo "== probe $(date -u +%FT%TZ)"
        echo "-- /proc/tty/driver/serial:"
        cat /proc/tty/driver/serial 2>&1
        echo "-- /proc/interrupts (serial lines):"
        grep -i -E 'serial|uart|tty' /proc/interrupts 2>&1
        echo "-- ttyS1/S2 in /proc/tty/drivers:"
        cat /proc/tty/drivers 2>&1
    } | tee "$SAMPLE_DIR/probe.txt"
}

sample_counters() {
    # Called every 10 s while the authorized soak runs. Read-only.
    ts=$(date -u +%FT%T.%NZ)
    {
        echo "== sample $ts"
        cat /proc/tty/driver/serial 2>/dev/null
        grep -i -E 'serial|uart|tty' /proc/interrupts 2>/dev/null
    } >> "$SAMPLE_DIR/counters.log"
    # Marker comments for the desk join: the soak's run.log carries the
    # MULTI_RX/parser/death timeline; counters.log carries the kernel-side view.
    # The desk analysis then diffs consecutive samples around the death time.
}

# PROPOSED main loop (never run):
#
#     probe_kernel_serial_stats
#     # while the operator-authorized dcentrald soak is alive:
#     #     sample_counters ; sleep 10
#     # on soak exit (rx_dead / wrap_rx>=7 / T+600 / operator stop):
#     #     sample_counters   # final death-adjacent sample
#     #     cp the run.log alongside counters.log for a single retained bundle
#
# Desk-side post-processing (host, not target):
#   - align counters.log samples to run.log timestamps;
#   - per ttyS1/ttyS2: diff rx/tx counters (and overrun/frame/parity/break when
#     present) across the interval containing the last MULTI_RX;
#   - apply the decision table at the top of this file;
#   - record the outcome in the GAP2 report as the D1 result (n=+1).

echo "DRAFT — NOT OPERATOR-AUTHORIZED — DO NOT RUN (refused safely)" >&2
exit 78
