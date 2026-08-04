#!/bin/sh
# Offline semantics for slot-transition exclusion around persistent dev deploys.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
HELPER="$ROOT/br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-deploy-upgrade-guard.sh"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dcent-deploy-upgrade-guard.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

. "$HELPER"

BASE="$TEST_ROOT/recovery"
BINARY="$TEST_ROOT/dcentrald"
MAINTENANCE="$TEST_ROOT/maintenance"
mkdir "$BASE"
chmod 700 "$BASE"

dcent_deploy_upgrade_guard "$BASE" "$BINARY" "$MAINTENANCE"

chmod 755 "$BASE"
if dcent_deploy_upgrade_guard "$BASE" "$BINARY" "$MAINTENANCE"; then
    echo "FAIL: unsafe recovery base metadata was accepted" >&2
    exit 1
fi
chmod 700 "$BASE"

mkdir "$MAINTENANCE"
if dcent_deploy_upgrade_guard "$BASE" "$BINARY" "$MAINTENANCE"; then
    echo "FAIL: active maintenance was accepted" >&2
    exit 1
fi
rmdir "$MAINTENANCE"

mkdir "$BASE/.deploy-lease"
if dcent_deploy_upgrade_guard "$BASE" "$BINARY" "$MAINTENANCE"; then
    echo "FAIL: active deploy lease was accepted" >&2
    exit 1
fi
rmdir "$BASE/.deploy-lease"

RUN="$BASE/11111111111111111111111111111111"
mkdir "$RUN"
printf 'pending\n' >"$RUN/persistent-transaction.state"
if dcent_deploy_upgrade_guard "$BASE" "$BINARY" "$MAINTENANCE"; then
    echo "FAIL: pending deploy transaction was accepted" >&2
    exit 1
fi
rm "$RUN/persistent-transaction.state"

ln -s "$RUN/missing" "$RUN/persistent-transaction.state"
if dcent_deploy_upgrade_guard "$BASE" "$BINARY" "$MAINTENANCE"; then
    echo "FAIL: dangling deploy transaction was accepted" >&2
    exit 1
fi
rm "$RUN/persistent-transaction.state"

printf 'dev binary\n' >"$BINARY"
if dcent_deploy_upgrade_guard "$BASE" "$BINARY" "$MAINTENANCE"; then
    echo "FAIL: persistent dev binary override was accepted" >&2
    exit 1
fi
rm "$BINARY"

rmdir "$RUN" "$BASE"
ln -s "$TEST_ROOT/missing-recovery" "$BASE"
if dcent_deploy_upgrade_guard "$BASE" "$BINARY" "$MAINTENANCE"; then
    echo "FAIL: malformed recovery base was accepted" >&2
    exit 1
fi

printf 'dcentrald deploy upgrade guard: passed\n'
