#!/bin/sh
# Mount-free concurrency and stale-owner tests for the Zynq updater lock.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
HELPER=$PROJECT_ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/sysupgrade-transaction-lock.sh
WORK_ROOT=${TMPDIR:-/tmp}/dcent-sysupgrade-lock-test.$$
LOCK_PARENT=$WORK_ROOT/run
LOCK_DIR=$LOCK_PARENT/dcentos-sysupgrade.lock
PROC_ROOT=$WORK_ROOT/proc
BOOT_ID_PATH=$WORK_ROOT/boot_id
failures=0
tests=0

cleanup()
{
    DCENT_SYSUPGRADE_LOCK_PRESERVE=0
    dcent_sysupgrade_lock_release >/dev/null 2>&1 || true
    rm -rf "$WORK_ROOT"
}
trap cleanup EXIT HUP INT TERM

# shellcheck source=/dev/null
. "$HELPER"

pass() { tests=$((tests + 1)); printf 'PASS: %s\n' "$1"; }
fail() { tests=$((tests + 1)); failures=$((failures + 1)); printf 'FAIL: %s\n' "$1" >&2; }
expect_success()
{
    _label=$1
    shift
    if "$@"; then pass "$_label"; else fail "$_label"; fi
}
expect_failure()
{
    _label=$1
    shift
    if "$@" >/dev/null 2>&1; then fail "$_label (unexpected success)"; else pass "$_label"; fi
}

expect_status()
{
    _label=$1
    _expected=$2
    shift 2
    if "$@" >/dev/null 2>&1; then
        _actual=0
    else
        _actual=$?
    fi
    if [ "$_actual" -eq "$_expected" ]; then
        pass "$_label"
    else
        fail "$_label (expected status $_expected, got $_actual)"
    fi
}

write_proc_stat()
{
    _pid=$1
    _start=$2
    mkdir -p "$PROC_ROOT/$_pid"
    # After the closing comm parenthesis, starttime (field 22) is token 20.
    printf '%s\n' "$_pid (sysupgrade) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 $_start 20" \
        >"$PROC_ROOT/$_pid/stat"
}

write_owner_receipt()
{
    _owner_boot=$1
    _owner_pid=$2
    _owner_start=$3
    _owner_phase=$4
    mkdir "$LOCK_DIR"
    chmod 700 "$LOCK_DIR"
    (umask 077; printf '%s\n' \
        'schema=dcentos-sysupgrade-lock-v2' \
        "boot_id=$_owner_boot" \
        "pid=$_owner_pid" \
        "starttime=$_owner_start" \
        "phase=$_owner_phase" \
        'owner=zynq-sysupgrade' >"$LOCK_DIR/owner")
    chmod 600 "$LOCK_DIR/owner"
}

write_dead_active_receipt()
{
    write_owner_receipt \
        01234567-89ab-cdef-0123-456789abcdef 999999 1 active
}

remove_owner_fixture()
{
    rm -f "$LOCK_DIR/owner"
    rmdir "$LOCK_DIR"
}

mkdir -p "$LOCK_PARENT" "$PROC_ROOT"
chmod 700 "$LOCK_PARENT"
printf '%s\n' '01234567-89ab-cdef-0123-456789abcdef' >"$BOOT_ID_PATH"
write_proc_stat $$ 424242

expect_success "first writer acquires the transaction lock" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "lock receipt records the exact owner PID" \
    grep -q "^pid=$$\$" "$LOCK_DIR/owner"
expect_success "lock receipt records the exact process starttime" \
    grep -q '^starttime=424242$' "$LOCK_DIR/owner"
expect_success "lock receipt deliberately uses schema v2" \
    grep -q '^schema=dcentos-sysupgrade-lock-v2$' "$LOCK_DIR/owner"
expect_success "owned lock exposes one canonical colocated ledger path" \
    test "$(dcent_sysupgrade_lock_ledger_path)" = "$LOCK_DIR/ledger"

SECOND=$WORK_ROOT/second-writer.sh
cat >"$SECOND" <<'EOF_SECOND'
#!/bin/sh
set -u
. "$1"
mkdir -p "$3/$$"
printf '%s\n' "$$ (second-writer) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 515151 20" \
    >"$3/$$/stat"
dcent_sysupgrade_lock_acquire "$2" "$3" "$4"
EOF_SECOND
chmod 700 "$SECOND"
expect_failure "a concurrent second process is refused while the owner is live" \
    sh "$SECOND" "$HELPER" "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "live-owner refusal leaves the first receipt untouched" \
    grep -q "^pid=$$\$" "$LOCK_DIR/owner"
expect_success "owner releases its exact lock" dcent_sysupgrade_lock_release
expect_success "release removes the lock directory" test ! -e "$LOCK_DIR"
expect_failure "ledger path is unavailable without lock ownership" \
    dcent_sysupgrade_lock_ledger_path

# A complete same-boot receipt whose PID no longer exists is proven stale.
mkdir "$LOCK_DIR"
chmod 700 "$LOCK_DIR"
cat >"$LOCK_DIR/owner" <<'EOF_STALE'
schema=dcentos-sysupgrade-lock-v2
boot_id=01234567-89ab-cdef-0123-456789abcdef
pid=999999
starttime=1
phase=active
owner=zynq-sysupgrade
EOF_STALE
chmod 600 "$LOCK_DIR/owner"
expect_success "a complete dead-owner receipt is replaced safely" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "replacement receipt belongs to this process" \
    grep -q "^pid=$$\$" "$LOCK_DIR/owner"
expect_success "replacement owner releases normally" dcent_sysupgrade_lock_release

# PID reuse is stale only when /proc starttime disagrees with the receipt.
mkdir "$LOCK_DIR"
chmod 700 "$LOCK_DIR"
cat >"$LOCK_DIR/owner" <<EOF_REUSED
schema=dcentos-sysupgrade-lock-v2
boot_id=01234567-89ab-cdef-0123-456789abcdef
pid=$$
starttime=111111
phase=active
owner=zynq-sysupgrade
EOF_REUSED
chmod 600 "$LOCK_DIR/owner"
expect_success "PID reuse with a different starttime is replaced" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "PID-reuse replacement releases normally" dcent_sysupgrade_lock_release

# Process ownership is deliberately tri-state. Only a stable missing PID is
# proven absent; every malformed or partially present proc entry is unknown.
expect_status "a twice-absent PID is classified as proven absent" 1 \
    dcent_sysupgrade_lock_process_starttime "$PROC_ROOT" 777777
mkdir "$PROC_ROOT/777777"
expect_status "a PID directory without stat evidence is classified unknown" 2 \
    dcent_sysupgrade_lock_process_starttime "$PROC_ROOT" 777777
printf '%s\n' 'malformed process evidence' >"$PROC_ROOT/777777/stat"
expect_status "a malformed stat record is classified unknown" 2 \
    dcent_sysupgrade_lock_process_starttime "$PROC_ROOT" 777777
rm -f "$PROC_ROOT/777777/stat"
rmdir "$PROC_ROOT/777777"
ln -s "$PROC_ROOT/$$" "$PROC_ROOT/777777"
expect_status "a symlink PID container is classified unknown" 2 \
    dcent_sysupgrade_lock_process_starttime "$PROC_ROOT" 777777
rm -f "$PROC_ROOT/777777"
expect_status "a stable canonical stat record is admitted" 0 \
    dcent_sysupgrade_lock_process_starttime "$PROC_ROOT" $$

# Canonical receipt grammar and metadata are part of ownership authority, not
# advisory hygiene. None of these ambiguous states may authorize deletion.
write_owner_receipt 01234567-89ab-cdef-0123-456789abcdef 777777 1 active
mkdir "$PROC_ROOT/777777"
expect_failure "present PID with missing stat evidence fails closed" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "unknown-liveness refusal preserves the owner receipt" \
    test -f "$LOCK_DIR/owner"
rmdir "$PROC_ROOT/777777"
remove_owner_fixture

write_owner_receipt 01234567-89ab-cdef-0123-456789abcdef 999999 1 active
chmod 666 "$LOCK_DIR/owner"
expect_failure "world-writable owner metadata fails closed" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "wrong-mode owner evidence remains for inspection" \
    test -f "$LOCK_DIR/owner"
chmod 600 "$LOCK_DIR/owner"
remove_owner_fixture

write_owner_receipt 01234567-89ab-cdef-0123-456789abcdef 999999 1 active
ln "$LOCK_DIR/owner" "$WORK_ROOT/owner-hardlink"
expect_failure "multiply linked owner evidence fails closed" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "hard-linked owner evidence remains for inspection" \
    test -f "$LOCK_DIR/owner"
rm -f "$WORK_ROOT/owner-hardlink"
remove_owner_fixture

write_owner_receipt 01234567-89ab-cdef-0123-456789abcdef 999999 1 active
chmod 755 "$LOCK_DIR"
expect_failure "non-private lock-directory metadata fails closed" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "wrong-mode lock evidence remains for inspection" \
    test -f "$LOCK_DIR/owner"
chmod 700 "$LOCK_DIR"
remove_owner_fixture

for _invalid_owner_tuple in \
    '- 999999 1' \
    '01234567-89AB-cdef-0123-456789abcdef 999999 1' \
    '01234567-89ab-cdef-0123-456789abcdef 0 1' \
    '01234567-89ab-cdef-0123-456789abcdef 099 1' \
    '01234567-89ab-cdef-0123-456789abcdef 2147483648 1' \
    '01234567-89ab-cdef-0123-456789abcdef 999999 0' \
    '01234567-89ab-cdef-0123-456789abcdef 999999 01' \
    '01234567-89ab-cdef-0123-456789abcdef 999999 18446744073709551616'; do
    set -- $_invalid_owner_tuple
    write_owner_receipt "$1" "$2" "$3" active
    expect_failure "noncanonical owner tuple is refused: $_invalid_owner_tuple" \
        dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
    expect_success "noncanonical owner tuple remains intact: $_invalid_owner_tuple" \
        test -f "$LOCK_DIR/owner"
    remove_owner_fixture
done

mkdir "$LOCK_DIR"
chmod 700 "$LOCK_DIR"
(umask 077; printf '%s\n' \
    'schema=dcentos-sysupgrade-lock-v2' \
    'pid=999999' \
    'boot_id=01234567-89ab-cdef-0123-456789abcdef' \
    'starttime=1' \
    'phase=active' \
    'owner=zynq-sysupgrade' >"$LOCK_DIR/owner")
expect_failure "reordered owner fields fail exact grammar admission" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "reordered owner evidence remains for inspection" \
    test -f "$LOCK_DIR/owner"
remove_owner_fixture

# The current boot identifier has the same exact canonical contract.
printf '%s\n' '01234567-89AB-cdef-0123-456789abcdef' >"$BOOT_ID_PATH"
expect_failure "uppercase boot-id input is rejected" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
printf '%s\n%s\n' \
    '01234567-89ab-cdef-0123-456789abcdef' \
    '11111111-2222-3333-4444-555555555555' >"$BOOT_ID_PATH"
expect_failure "multi-line boot-id input is rejected" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
printf '%s' '01234567-89ab-cdef-0123-456789abcdef' >"$BOOT_ID_PATH"
expect_failure "boot-id input without a terminating newline is rejected" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
printf '%s\n' '01234567-89ab-cdef-0123-456789abcdef' >"$BOOT_ID_PATH"

# Ambiguous ownership must never trigger deletion.
mkdir "$LOCK_DIR"
chmod 700 "$LOCK_DIR"
printf '%s\n' 'incomplete' >"$LOCK_DIR/owner"
chmod 600 "$LOCK_DIR/owner"
expect_failure "malformed owner receipt fails closed" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "malformed owner receipt remains for inspection" \
    grep -q '^incomplete$' "$LOCK_DIR/owner"
rm -f "$LOCK_DIR/owner"
rmdir "$LOCK_DIR"

# Schema v1 is intentionally not migrated in place.  The deployed lock lives
# in volatile /run, so accepting an old receipt would weaken the v2 exact-child
# contract without providing a legitimate reboot-persistence benefit.
mkdir "$LOCK_DIR"
chmod 700 "$LOCK_DIR"
cat >"$LOCK_DIR/owner" <<'EOF_V1'
schema=dcentos-sysupgrade-lock-v1
boot_id=01234567-89ab-cdef-0123-456789abcdef
pid=999999
starttime=1
phase=active
owner=zynq-sysupgrade
EOF_V1
chmod 600 "$LOCK_DIR/owner"
expect_failure "legacy v1 receipt fails closed instead of being silently migrated" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "legacy receipt remains intact for inspection" \
    grep -q '^schema=dcentos-sysupgrade-lock-v1$' "$LOCK_DIR/owner"
rm -f "$LOCK_DIR/owner"
rmdir "$LOCK_DIR"

mkdir "$WORK_ROOT/target"
ln -s "$WORK_ROOT/target" "$LOCK_DIR"
expect_failure "symlink lock path is refused without touching its target" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "symlink target survives refusal" test -d "$WORK_ROOT/target"
rm -f "$LOCK_DIR"

expect_success "owner acquires before an abortable env transaction" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
LEDGER_DIR=$(dcent_sysupgrade_lock_ledger_path)
mkdir "$LEDGER_DIR"
chmod 700 "$LEDGER_DIR"
expect_failure "a concurrent writer is refused while the live owner has a ledger" \
    sh "$SECOND" "$HELPER" "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_failure "abort from active phase is refused" \
    dcent_sysupgrade_lock_abort_env_commit
expect_success "env mutation can arm while a canonical ledger coexists" \
    dcent_sysupgrade_lock_arm_env_commit
expect_success "a proven failed env mutation can return to active with the ledger intact" \
    dcent_sysupgrade_lock_abort_env_commit
expect_success "phase replacement preserves the canonical ledger" test -d "$LEDGER_DIR"
expect_failure "normal active-phase release refuses a remaining ledger" \
    dcent_sysupgrade_lock_release
expect_success "ledger refusal leaves the lock continuously present" test -d "$LOCK_DIR"
rmdir "$LEDGER_DIR"
expect_success "aborted transaction releases after ledger reconciliation" \
    dcent_sysupgrade_lock_release

# A complete ledger is still an unresolved external-resource receipt.  Neither
# same-boot PID death nor a synthetic boot-id change authorizes lock acquire to
# remove it.  Reconciliation must happen while the lock path remains present.
write_dead_active_receipt
mkdir "$LOCK_DIR/ledger"
chmod 700 "$LOCK_DIR/ledger"
LEDGER_REFUSAL_LOG=$WORK_ROOT/ledger-refusal.log
expect_failure "dead active owner with a ledger requires reconciliation" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
if dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH" \
    >/dev/null 2>"$LEDGER_REFUSAL_LOG"; then
    fail "ledger refusal emits a reconciliation-required diagnosis (unexpected success)"
elif grep -q 'reconciliation is required' "$LEDGER_REFUSAL_LOG"; then
    pass "ledger refusal emits a reconciliation-required diagnosis"
else
    fail "ledger refusal emits a reconciliation-required diagnosis"
fi
expect_success "ledger refusal preserves the dead owner receipt" \
    grep -q '^pid=999999$' "$LOCK_DIR/owner"
expect_success "ledger refusal preserves the canonical ledger" \
    test -d "$LOCK_DIR/ledger"
printf '%s\n' 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff' >"$BOOT_ID_PATH"
expect_failure "boot-id change still cannot discard a retained ledger" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
printf '%s\n' '01234567-89ab-cdef-0123-456789abcdef' >"$BOOT_ID_PATH"
rmdir "$LOCK_DIR/ledger"
rm -f "$LOCK_DIR/owner"
rmdir "$LOCK_DIR"

# Only a private real directory at the canonical child name is admitted as a
# ledger container.  Lock acquisition never repairs or removes malformed state.
write_dead_active_receipt
printf '%s\n' malformed >"$LOCK_DIR/ledger"
expect_failure "regular-file ledger fails closed" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "regular-file ledger remains untouched" test -f "$LOCK_DIR/ledger"
rm -f "$LOCK_DIR/ledger" "$LOCK_DIR/owner"
rmdir "$LOCK_DIR"

mkdir "$WORK_ROOT/ledger-target"
chmod 700 "$WORK_ROOT/ledger-target"
write_dead_active_receipt
ln -s "$WORK_ROOT/ledger-target" "$LOCK_DIR/ledger"
expect_failure "symlink ledger fails closed without touching its target" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "symlink-ledger target survives refusal" test -d "$WORK_ROOT/ledger-target"
rm -f "$LOCK_DIR/ledger" "$LOCK_DIR/owner"
rmdir "$LOCK_DIR"

write_dead_active_receipt
mkdir "$LOCK_DIR/ledger"
chmod 755 "$LOCK_DIR/ledger"
expect_failure "non-private ledger mode fails closed" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "wrong-mode ledger remains for inspection" test -d "$LOCK_DIR/ledger"
rm -rf "$LOCK_DIR/ledger"
rm -f "$LOCK_DIR/owner"
rmdir "$LOCK_DIR"

# An unresolved workspace/resource cleanup is ambiguous for the rest of this
# boot even when no U-Boot environment mutation was attempted.
expect_success "owner acquires before publishing cleanup-required state" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "active transaction can require manual cleanup" \
    dcent_sysupgrade_lock_require_cleanup
expect_success "cleanup-required phase is recorded exactly" \
    grep -q '^phase=cleanup-required$' "$LOCK_DIR/owner"
expect_success "release is a no-op while cleanup remains unresolved" \
    dcent_sysupgrade_lock_release
rm -f "$PROC_ROOT/$$/stat"
expect_failure "same-boot cleanup-required receipt refuses a new writer after owner death" \
    sh "$SECOND" "$HELPER" "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
write_proc_stat $$ 424242
DCENT_SYSUPGRADE_LOCK_HELD=0
DCENT_SYSUPGRADE_LOCK_PRESERVE=0
printf '%s\n' 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff' >"$BOOT_ID_PATH"
expect_success "previous-boot cleanup-required receipt is recoverable after reboot" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "post-cleanup-reboot owner releases normally" dcent_sysupgrade_lock_release
printf '%s\n' '01234567-89ab-cdef-0123-456789abcdef' >"$BOOT_ID_PATH"

# Owner death while env mutation is armed remains ambiguous for the whole
# boot. A boot-id transition is the only automatic recovery boundary.
mkdir "$LOCK_DIR"
chmod 700 "$LOCK_DIR"
cat >"$LOCK_DIR/owner" <<'EOF_ARMED'
schema=dcentos-sysupgrade-lock-v2
boot_id=01234567-89ab-cdef-0123-456789abcdef
pid=999999
starttime=1
phase=env-commit-armed
owner=zynq-sysupgrade
EOF_ARMED
chmod 600 "$LOCK_DIR/owner"
expect_failure "same-boot armed receipt refuses a new writer after owner death" \
    sh "$SECOND" "$HELPER" "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
printf '%s\n' 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' >"$BOOT_ID_PATH"
expect_success "previous-boot armed receipt is recoverable after reboot" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "post-armed-reboot owner releases normally" dcent_sysupgrade_lock_release
printf '%s\n' '01234567-89ab-cdef-0123-456789abcdef' >"$BOOT_ID_PATH"

# A phase-write interruption or any unexpected directory entry must preserve
# the complete receipt for forensic inspection instead of partially deleting
# a proven-stale lock.
mkdir "$LOCK_DIR"
chmod 700 "$LOCK_DIR"
cat >"$LOCK_DIR/owner" <<'EOF_EXTRA'
schema=dcentos-sysupgrade-lock-v2
boot_id=01234567-89ab-cdef-0123-456789abcdef
pid=999999
starttime=1
phase=active
owner=zynq-sysupgrade
EOF_EXTRA
chmod 600 "$LOCK_DIR/owner"
printf '%s\n' 'partial replacement' >"$LOCK_DIR/.owner.new.999999"
expect_failure "interrupted phase replacement fails closed" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "interrupted phase refusal preserves the owner receipt" \
    test -f "$LOCK_DIR/owner"
expect_success "interrupted phase refusal preserves the temporary receipt" \
    test -f "$LOCK_DIR/.owner.new.999999"
rm -f "$LOCK_DIR/owner" "$LOCK_DIR/.owner.new.999999"
rmdir "$LOCK_DIR"

expect_success "owner can preserve the lock through reboot disposition" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "successful transaction arms before commit" \
    dcent_sysupgrade_lock_arm_env_commit
expect_success "preserve marks the owned lock" dcent_sysupgrade_lock_preserve
expect_success "release is a no-op after preserve" dcent_sysupgrade_lock_release
expect_success "preserved lock remains until reboot clears /run" test -f "$LOCK_DIR/owner"
rm -f "$PROC_ROOT/$$/stat"
expect_failure "same-boot committed receipt refuses a new writer after owner death" \
    sh "$SECOND" "$HELPER" "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
write_proc_stat $$ 424242
DCENT_SYSUPGRADE_LOCK_PRESERVE=0
# A committed same-boot receipt is intentionally not releasable. Emulate the
# reboot boundary by changing boot-id; the next owner may then recover it.
DCENT_SYSUPGRADE_LOCK_HELD=0
DCENT_SYSUPGRADE_LOCK_PRESERVE=0
printf '%s\n' '11111111-2222-3333-4444-555555555555' >"$BOOT_ID_PATH"
expect_success "previous-boot committed receipt is recoverable after reboot" \
    dcent_sysupgrade_lock_acquire "$LOCK_DIR" "$PROC_ROOT" "$BOOT_ID_PATH"
expect_success "post-reboot owner releases normally" dcent_sysupgrade_lock_release

if [ "$failures" -ne 0 ]; then
    printf '\nsysupgrade transaction-lock tests failed: %s/%s failed\n' "$failures" "$tests" >&2
    exit 1
fi
printf '\nsysupgrade transaction-lock tests passed: %s assertions\n' "$tests"
