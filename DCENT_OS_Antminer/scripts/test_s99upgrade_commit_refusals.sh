#!/bin/sh
# Host-side transaction tests for the Zynq S99upgrade environment commit.
# The real init script runs against isolated command shims; no hardware or host
# firmware paths are read or mutated.
set -eu

DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
S99="$DIR/br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S99upgrade"

if [ ! -f "$S99" ]; then
    echo "SKIP: zynq S99upgrade not found at $S99" >&2
    exit 0
fi

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dcent-s99-commit.XXXXXX")
ALIVE_PID=
cleanup() {
    if [ -n "$ALIVE_PID" ]; then
        kill "$ALIVE_PID" 2>/dev/null || true
        wait "$ALIVE_PID" 2>/dev/null || true
    fi
    rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

make_common_shims() {
    shim=$1

    cat >"$shim/ip" <<'EOF'
#!/bin/sh
if [ "${1:-}" = addr ]; then
    echo "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500"
    echo "    inet 192.0.2.10/24 brd 192.0.2.255 scope global eth0"
    exit 0
fi
exit 1
EOF

    cat >"$shim/netstat" <<'EOF'
#!/bin/sh
echo "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN"
EOF

    cat >"$shim/pidof" <<'EOF'
#!/bin/sh
if [ "${1:-}" = dcentrald ] && [ -n "${S99_TEST_PID:-}" ]; then
    echo "$S99_TEST_PID"
    exit 0
fi
exit 1
EOF

    cat >"$shim/wget" <<'EOF'
#!/bin/sh
case "$*" in
    *"/api/system/health"*) printf '%s' '{"daemon":{"uptime_s":42}}' ;;
esac
exit 0
EOF

    cat >"$shim/sleep" <<'EOF'
#!/bin/sh
exit 0
EOF

    cat >"$shim/sync" <<'EOF'
#!/bin/sh
exit 0
EOF

    chmod 0755 "$shim"/*
    for cmd in awk cat cmp grep head rm sed seq tr wc; do
        src=$(command -v "$cmd" || true)
        if [ -z "$src" ]; then
            echo "SKIP: required host test command not found: $cmd" >&2
            exit 0
        fi
        ln -s "$src" "$shim/$cmd"
    done
}

make_fw_printenv() {
    shim=$1

    cat >"$shim/fw_printenv" <<'EOF'
#!/bin/sh
echo "$*" >> "$S99_TEST_WORK/fw_printenv.log"
[ "${1:-}" = -c ] || exit 96
[ "${2:-}" = "$S99_TEST_WORK/fw_env.config" ] || exit 97
[ "$#" -eq 2 ] || exit 98

reads=$(cat "$S99_TEST_WORK/read-count" 2>/dev/null || printf '%s\n' 0)
reads=$((reads + 1))
printf '%s\n' "$reads" > "$S99_TEST_WORK/read-count"

if [ "$reads" -eq 1 ]; then
    case "$S99_TEST_MODE" in
        read_failure) exit 9 ;;
        bad_crc)
            echo "Warning: Bad CRC, using default environment"
            exit 0
            ;;
        duplicate_stage)
            printf '%s\n' firmware=1 upgrade_stage=1 upgrade_stage=0 first_boot=yes bootdelay=3 custom=value
            exit 0
            ;;
    esac
fi

if [ "$reads" -eq 2 ]; then
    case "$S99_TEST_MODE" in
        invalid_firmware)
            printf '%s\n' firmware=3 upgrade_stage=1 first_boot=yes bootdelay=3 custom=value
            exit 0
            ;;
        empty_stage)
            printf '%s\n' firmware=1 upgrade_stage= first_boot=yes bootdelay=3 custom=value
            exit 0
            ;;
        wrong_first_boot)
            printf '%s\n' firmware=1 upgrade_stage=1 first_boot=no bootdelay=3 custom=value
            exit 0
            ;;
        duplicate_unrelated)
            printf '%s\n' firmware=1 upgrade_stage=1 first_boot=yes bootdelay=3 custom=value custom=other
            exit 0
            ;;
    esac
fi

state=$(cat "$S99_TEST_WORK/state")
case "$state" in
    old)
        printf '%s\n' firmware=1 upgrade_stage=1 first_boot=yes bootdelay=3 custom=value
        ;;
    desired)
        printf '%s\n' firmware=1 bootdelay=3 custom=value
        ;;
    first_boot_only)
        printf '%s\n' firmware=1 first_boot=yes bootdelay=3 custom=value
        ;;
    firmware_drift)
        printf '%s\n' firmware=2 bootdelay=3 custom=value
        ;;
    unrelated_drift)
        printf '%s\n' firmware=1 bootdelay=3 custom=changed
        ;;
    order_drift)
        printf '%s\n' firmware=1 custom=value bootdelay=3
        ;;
    duplicate_verify)
        printf '%s\n' firmware=1 bootdelay=3 custom=value custom=other
        ;;
    unreadable)
        exit 8
        ;;
    *)
        exit 99
        ;;
esac
EOF
    chmod 0755 "$shim/fw_printenv"
}

make_fw_setenv() {
    shim=$1

    cat >"$shim/fw_setenv" <<'EOF'
#!/bin/sh
echo "$*" >> "$S99_TEST_WORK/fw_setenv.log"
[ "${1:-}" = -c ] || exit 96
[ "${2:-}" = "$S99_TEST_WORK/fw_env.config" ] || exit 97
[ "${3:-}" = --script ] || exit 98
[ "${4:-}" = - ] || exit 99
[ "$#" -eq 4 ] || exit 95

attempt=$(cat "$S99_TEST_WORK/store-count" 2>/dev/null || printf '%s\n' 0)
attempt=$((attempt + 1))
printf '%s\n' "$attempt" > "$S99_TEST_WORK/store-count"
cat > "$S99_TEST_WORK/stdin.$attempt"
cmp -s "$S99_TEST_WORK/expected-stdin" "$S99_TEST_WORK/stdin.$attempt" || exit 94

case "$S99_TEST_MODE" in
    success|late_error_desired)
        printf '%s\n' desired > "$S99_TEST_WORK/state"
        ;;
    retry_then_desired)
        if [ "$attempt" -ge 2 ]; then
            printf '%s\n' desired > "$S99_TEST_WORK/state"
        fi
        ;;
    mixed_state)
        printf '%s\n' first_boot_only > "$S99_TEST_WORK/state"
        ;;
    firmware_drift)
        printf '%s\n' firmware_drift > "$S99_TEST_WORK/state"
        ;;
    unrelated_drift)
        printf '%s\n' unrelated_drift > "$S99_TEST_WORK/state"
        ;;
    order_drift)
        printf '%s\n' order_drift > "$S99_TEST_WORK/state"
        ;;
    duplicate_verify)
        printf '%s\n' duplicate_verify > "$S99_TEST_WORK/state"
        ;;
    unreadable_verify)
        printf '%s\n' unreadable > "$S99_TEST_WORK/state"
        ;;
    old_state)
        ;;
esac

[ "$S99_TEST_MODE" != late_error_desired ] || exit 17
exit 0
EOF
    chmod 0755 "$shim/fw_setenv"
}

run_case() {
    label=$1
    mode=$2
    expected_marker=$3
    expected_stores=$4
    expected_text=$5
    retries=${6:-3}

    work="$ROOT/$label"
    shim="$work/shims"
    mkdir -p "$shim" "$work/etc/dcentos" "$work/etc/default" \
        "$work/root/.ssh" "$work/data/keys/dropbear"
    : > "$work/mtd4"
    : > "$work/fw_env.config"
    : > "$work/dcentrald"
    : > "$work/fw_printenv.log"
    : > "$work/fw_setenv.log"
    printf '%s\n' old > "$work/state"
    printf '%s\n' 'first_boot=' 'upgrade_stage=' > "$work/expected-stdin"
    printf '%s\n' dcent-s99upgrade-offline-test-v1 > "$work/offline.marker"
    cat >"$work/uboot-env-admission.sh" <<'EOF'
dcent_zynq_uboot_env_admit() { [ "$#" -eq 4 ] && [ -f "$1" ]; }
EOF
    chmod 0755 "$work/dcentrald"

    make_common_shims "$shim"
    case "$mode" in
        missing_fw_printenv) make_fw_setenv "$shim" ;;
        missing_fw_setenv) make_fw_printenv "$shim" ;;
        *)
            make_fw_printenv "$shim"
            make_fw_setenv "$shim"
            ;;
    esac
    if [ "$mode" = missing_fw_env_config ]; then
        rm -f "$work/fw_env.config"
    fi

    /bin/sleep 300 &
    ALIVE_PID=$!
    out="$work/s99.out"
    set +e
    PATH="$shim" \
    S99_TEST_WORK="$work" \
    S99_TEST_MODE="$mode" \
    S99_TEST_PID="$ALIVE_PID" \
    DCENTOS_MTD4_NODE="$work/mtd4" \
    DCENTOS_FW_ENV_CONFIG="$work/fw_env.config" \
    DCENTOS_S99_OFFLINE_TEST=1 \
    DCENTOS_S99_OFFLINE_MARKER="$work/offline.marker" \
    DCENTOS_UBOOT_ENV_ADMISSION_HELPER="$work/uboot-env-admission.sh" \
    DCENTOS_UBOOT_ENV_PROC_MTD="$work/proc-mtd" \
    DCENTOS_UBOOT_ENV_SYSFS_MTD_ROOT="$work/sys-class-mtd" \
    DCENTOS_DCENTRALD_BIN="$work/dcentrald" \
    DCENTOS_UPGRADE_COMMIT_MARKER="$work/commit-marker" \
    DCENTOS_BOOT_SUCCESS_WINDOW_S=1 \
    DCENTOS_FW_COMMIT_RETRIES="$retries" \
    DCENTOS_FW_COMMIT_SETTLE_S=0 \
    DCENTOS_CONFIG_DIR="$work/etc/dcentos" \
    DCENTOS_DROPBEAR_DEFAULTS="$work/etc/default/dropbear" \
    DCENTOS_ROOT_AUTHORIZED_KEYS="$work/root/.ssh/authorized_keys" \
    DCENTOS_DATA_AUTHORIZED_KEYS="$work/data/keys/dropbear/authorized_keys" \
        /bin/sh "$S99" start >"$out" 2>&1
    rc=$?
    set -e

    kill "$ALIVE_PID" 2>/dev/null || true
    wait "$ALIVE_PID" 2>/dev/null || true
    ALIVE_PID=

    if [ "$rc" -ne 0 ]; then
        cat "$out" >&2
        echo "FAIL: $label exited $rc" >&2
        exit 1
    fi
    grep -F "$expected_text" "$out" >/dev/null || {
        cat "$out" >&2
        echo "FAIL: $label missing expected text: $expected_text" >&2
        exit 1
    }
    grep -Fx "$expected_marker" "$work/commit-marker" >/dev/null 2>&1 || {
        cat "$out" >&2
        echo "FAIL: $label expected marker $expected_marker" >&2
        exit 1
    }

    actual_stores=$(cat "$work/store-count" 2>/dev/null || printf '%s\n' 0)
    if [ "$actual_stores" -ne "$expected_stores" ]; then
        cat "$out" >&2
        echo "FAIL: $label expected $expected_stores stores, got $actual_stores" >&2
        exit 1
    fi
    attempt=1
    while [ "$attempt" -le "$actual_stores" ]; do
        cmp -s "$work/expected-stdin" "$work/stdin.$attempt" || {
            echo "FAIL: $label store $attempt did not consume the exact deletion script" >&2
            exit 1
        }
        attempt=$((attempt + 1))
    done

    echo "ok - $label"
}

run_case missing_fw_setenv missing_fw_setenv blocked 0 "fw_setenv missing"
run_case missing_fw_printenv missing_fw_printenv blocked 0 "fw_printenv missing"
run_case missing_fw_env_config missing_fw_env_config blocked 0 "canonical U-Boot environment admission failed"
run_case bad_crc bad_crc blocked 0 "current U-Boot env reads Bad CRC / default"
run_case read_failure read_failure blocked 0 "could not read a CRC-valid current U-Boot environment"
run_case duplicate_stage duplicate_stage blocked 0 "duplicate upgrade_stage records"
run_case invalid_firmware invalid_firmware blocked 0 "firmware must be exactly one selector"
run_case empty_stage empty_stage blocked 0 "upgrade_stage must be present and non-empty"
run_case wrong_first_boot wrong_first_boot blocked 0 "first_boot must be exactly yes"
run_case duplicate_unrelated duplicate_unrelated blocked 0 "malformed or duplicated"
run_case success success committed 1 "committed via one fw_setenv store"
run_case late_error_desired late_error_desired committed 1 "committed via one fw_setenv store"
run_case retry_then_desired retry_then_desired committed 2 "committed via one fw_setenv store"
run_case old_state old_state blocked 2 "could NOT be cleared after 2 proven-old retries" 2
run_case mixed_state mixed_state blocked 1 "Manual resolution required"
run_case firmware_drift firmware_drift blocked 1 "Manual resolution required"
run_case unrelated_drift unrelated_drift blocked 1 "Manual resolution required"
run_case order_drift order_drift blocked 1 "Manual resolution required"
run_case duplicate_verify duplicate_verify blocked 1 "Manual resolution required"
run_case unreadable_verify unreadable_verify blocked 1 "Manual resolution required"

echo "S99UPGRADE_COMMIT_REFUSALS_OK"
