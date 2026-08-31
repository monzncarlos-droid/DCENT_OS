#!/bin/sh
#
# cargo-deny host gate for the DCENT_OS daemon workspace.
#
# QA owns scripts/ci_offline_gates.sh — do not fold this check into that
# file. CI / `make verify` should invoke THIS script as a separate job:
#   sh DCENT_OS_Antminer/scripts/run_cargo_deny.sh
#
# Config: DCENT_OS_Antminer/dcentrald/deny.toml
# Install: cargo install cargo-deny --locked
#
# POSIX sh. Does not contact hardware. Does not require network when the
# advisory db is already cached; `cargo deny check` fetches advisories on
# first run (licenses/bans/sources are offline).
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
DCENTOS_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)
WS="$DCENTOS_DIR/dcentrald"

if [ ! -f "$WS/deny.toml" ]; then
    echo "ERROR: deny.toml missing at $WS/deny.toml" >&2
    exit 1
fi

cd "$WS"

cargo_deny_ok=0
if command -v cargo-deny >/dev/null 2>&1; then
    cargo_deny_ok=1
elif command -v cargo >/dev/null 2>&1 && cargo deny --version >/dev/null 2>&1; then
    cargo_deny_ok=1
fi

if [ "$cargo_deny_ok" -eq 0 ]; then
    echo "cargo-deny is not installed (need the cargo-deny binary / cargo deny subcommand)." >&2
    echo "Install: cargo install cargo-deny --locked" >&2
    echo "CI note: wire this script as a host job; do not edit ci_offline_gates.sh (QA sibling)." >&2
    case "${DCENT_REQUIRE_CARGO_DENY:-0}" in
        1|true|TRUE|yes|YES|y|Y)
            echo "ERROR: DCENT_REQUIRE_CARGO_DENY=1 and cargo-deny is missing" >&2
            exit 1
            ;;
    esac
    echo "SKIP: cargo deny check (set DCENT_REQUIRE_CARGO_DENY=1 to fail closed)"
    exit 0
fi

echo "cargo deny check — workspace $WS"
# advisories + licenses + bans + sources (deny.toml)
cargo deny check
echo "PASS: cargo deny check"
