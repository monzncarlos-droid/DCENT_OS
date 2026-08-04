#!/bin/sh
# Fixture command for the compiled parent-death boundary lifecycle test.

set -eu

ready=$1
received=$2
pidfile=$3

# Parent-loss containment must not depend on the command cooperating with TERM.
trap ': >"$received"' TERM
printf '%s\n' "$$" >"$pidfile"
: >"$ready"
while :; do
    sleep 1
done
