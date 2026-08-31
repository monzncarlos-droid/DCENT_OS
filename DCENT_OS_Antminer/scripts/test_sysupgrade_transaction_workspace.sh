#!/bin/sh
# Mount-free adversarial tests for the Zynq sysupgrade private workspace.

set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
HELPER=$PROJECT_ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/sysupgrade-transaction-workspace.sh
WORK_ROOT=${TMPDIR:-/tmp}/dcent-sysupgrade-workspace-test.$$
SAFE_ROOT=$WORK_ROOT/run
MOUNTS=$WORK_ROOT/mounts
failures=0
tests=0

cleanup()
{
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
reset_workspace_state()
{
    # These are public state consumed by the sourced helper after this reset.
    # shellcheck disable=SC2034
    DCENT_SYSUPGRADE_WORKSPACE=
    # shellcheck disable=SC2034
    DCENT_SYSUPGRADE_WORKSPACE_ROOT=
    # shellcheck disable=SC2034
    DCENT_SYSUPGRADE_WORKSPACE_ID=
    # shellcheck disable=SC2034
    DCENT_SYSUPGRADE_WORKSPACE_OWNED=0
}

TEST_UID=$(id -u)
expect_success "deployed workspace policy admits only uid 0" \
    test "$(dcent_sysupgrade_workspace_expected_uid)" = 0
# Test-local policy override: this does not alter the sourced production file.
# It lets a non-root GitHub runner exercise the complete positive lifecycle.
dcent_sysupgrade_workspace_expected_uid()
{
    printf '%s\n' "$TEST_UID"
}

mkdir -p "$SAFE_ROOT"
chmod 1777 "$SAFE_ROOT"
: >"$MOUNTS"

expect_failure "filesystem root is refused as the workspace root" \
    dcent_sysupgrade_workspace_create /

mkdir "$WORK_ROOT/symlink-target"
chmod 1777 "$WORK_ROOT/symlink-target"
ln -s "$WORK_ROOT/symlink-target" "$WORK_ROOT/symlink-root"
expect_failure "symlinked workspace root is refused" \
    dcent_sysupgrade_workspace_create "$WORK_ROOT/symlink-root"
expect_success "symlink-root refusal leaves its target untouched" \
    test -d "$WORK_ROOT/symlink-target"

OTHER_UID=$((TEST_UID + 1))
expect_failure "foreign workspace-root owner is refused by the pure predicate" \
    dcent_sysupgrade_workspace_owner_is_expected "$OTHER_UID"

mkdir "$WORK_ROOT/writable"
chmod 777 "$WORK_ROOT/writable"
expect_failure "non-sticky writable workspace root is refused" \
    dcent_sysupgrade_workspace_create "$WORK_ROOT/writable"

# A malicious or broken mktemp implementation must not launder a preexisting
# directory into workspace ownership. This also pins the post-mktemp empty-dir
# validation without mounting anything.
PREEXISTING=$SAFE_ROOT/dcentos-sysupgrade.preexisting
mkdir "$PREEXISTING"
chmod 700 "$PREEXISTING"
printf '%s\n' sentinel >"$PREEXISTING/foreign-child"
# shellcheck disable=SC2317
mktemp()
{
    printf '%s\n' "$PREEXISTING"
}
expect_failure "mktemp result with preexisting children is refused" \
    dcent_sysupgrade_workspace_create "$SAFE_ROOT"
expect_success "preexisting-child refusal does not delete foreign content" \
    grep -q '^sentinel$' "$PREEXISTING/foreign-child"
unset -f mktemp

ATTACK_TMP=$WORK_ROOT/attacker-tmpdir
mkdir "$ATTACK_TMP"
chmod 777 "$ATTACK_TMP"
TMPDIR=$ATTACK_TMP
export TMPDIR
expect_success "private workspace is created beneath the admitted root" \
    dcent_sysupgrade_workspace_create "$SAFE_ROOT"
FIRST_WORKSPACE=$DCENT_SYSUPGRADE_WORKSPACE
case "$FIRST_WORKSPACE" in
    "$SAFE_ROOT"/dcentos-sysupgrade.*) pass "explicit root is used instead of attacker-controlled TMPDIR" ;;
    *) fail "explicit root is used instead of attacker-controlled TMPDIR" ;;
esac
expect_success "workspace is owned by the admitted test uid" \
    test "$(stat -c %u "$FIRST_WORKSPACE")" = "$TEST_UID"
expect_success "workspace mode is exactly 0700" \
    test "$(stat -c %a "$FIRST_WORKSPACE")" = 700
expect_success "workspace starts empty" \
    dcent_sysupgrade_workspace_is_empty "$FIRST_WORKSPACE"

PRIVATE_FILE=$(dcent_sysupgrade_workspace_path env-script) || exit 1
expect_success "fresh direct child is admitted" \
    dcent_sysupgrade_workspace_require_absent "$PRIVATE_FILE"
printf '%s\n' firmware=2 >"$PRIVATE_FILE"
expect_success "inherited umask creates workspace files as 0600" \
    test "$(stat -c %a "$PRIVATE_FILE")" = 600
expect_failure "preexisting direct child is refused" \
    dcent_sysupgrade_workspace_require_absent "$PRIVATE_FILE"
expect_success "preexisting-child refusal preserves its content" \
    grep -q '^firmware=2$' "$PRIVATE_FILE"
expect_failure "nested workspace child is refused" \
    dcent_sysupgrade_workspace_require_absent "$FIRST_WORKSPACE/nested/file"
expect_failure "unsafe workspace leaf is refused" \
    dcent_sysupgrade_workspace_path '../escape'

printf 'ubi1:rootfs_data %s/inactive-data ubifs rw 0 0\n' \
    "$FIRST_WORKSPACE" >"$MOUNTS"
expect_failure "cleanup refuses a simulated live child mount" \
    dcent_sysupgrade_workspace_cleanup "$MOUNTS"
expect_success "mount-ambiguous cleanup preserves the exact workspace" \
    test -d "$FIRST_WORKSPACE"
: >"$MOUNTS"
expect_success "cleanup removes the exact workspace after mount ambiguity clears" \
    dcent_sysupgrade_workspace_cleanup "$MOUNTS"
expect_success "successful cleanup removes the owned workspace" \
    test ! -e "$FIRST_WORKSPACE"

expect_success "a later transaction receives another private workspace" \
    dcent_sysupgrade_workspace_create "$SAFE_ROOT"
SECOND_WORKSPACE=$DCENT_SYSUPGRADE_WORKSPACE
if [ "$SECOND_WORKSPACE" != "$FIRST_WORKSPACE" ]; then
    pass "workspace names are not reused across adjacent transactions"
else
    fail "workspace names are not reused across adjacent transactions"
fi

# Replace the path with another directory after saving the original inode.
# Cleanup must refuse the substitution and leave both directories untouched.
MOVED_WORKSPACE=$SECOND_WORKSPACE.saved
mv "$SECOND_WORKSPACE" "$MOVED_WORKSPACE"
mkdir "$SECOND_WORKSPACE"
chmod 700 "$SECOND_WORKSPACE"
printf '%s\n' replacement >"$SECOND_WORKSPACE/foreign-child"
expect_failure "workspace inode substitution is refused" \
    dcent_sysupgrade_workspace_cleanup "$MOUNTS"
expect_success "inode-substitution refusal preserves replacement content" \
    grep -q '^replacement$' "$SECOND_WORKSPACE/foreign-child"
expect_success "inode-substitution refusal preserves the original workspace" \
    test -d "$MOVED_WORKSPACE"
reset_workspace_state

caller_workspace_follows_lock()
{
    _ws_order_caller=$1
    _ws_order_lock_line=$(grep -n '^dcent_sysupgrade_lock_acquire ' "$_ws_order_caller" | sed -n '1s/:.*//p')
    _ws_order_workspace_line=$(grep -n '^dcent_sysupgrade_workspace_create ' "$_ws_order_caller" | sed -n '1s/:.*//p')
    case "$_ws_order_lock_line:$_ws_order_workspace_line" in
        *[!0-9:]*|:|*:|*:*:*) return 1 ;;
    esac
    [ "$_ws_order_workspace_line" -gt "$_ws_order_lock_line" ]
}

for _caller_spec in \
    "am1-s9:$PROJECT_ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/sysupgrade" \
    "am2-s19jpro:$PROJECT_ROOT/br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/usr/sbin/sysupgrade" \
    "am2-s19pro:$PROJECT_ROOT/br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/usr/sbin/sysupgrade" \
    "am2-s17pro:$PROJECT_ROOT/br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/usr/sbin/sysupgrade"; do
    _ws_caller_label=${_caller_spec%%:*}
    _ws_caller_path=${_caller_spec#*:}
    expect_success "$_ws_caller_label creates scratch only after transaction-lock acquisition" \
        caller_workspace_follows_lock "$_ws_caller_path"
    expect_success "$_ws_caller_label defaults scratch to validated /tmp" \
        grep -Fq 'SYSUPGRADE_WORKSPACE_ROOT="/tmp"' "$_ws_caller_path"
    # The following grep needles intentionally assert literal shell syntax.
    # shellcheck disable=SC2016
    expect_success "$_ws_caller_label derives persistence mountpoint inside the workspace" \
        grep -Fq 'PERSIST_MOUNT_ROOT=$(dcent_sysupgrade_workspace_path inactive-data)' "$_ws_caller_path"
    # shellcheck disable=SC2016
    expect_success "$_ws_caller_label derives fw_setenv input inside the workspace" \
        grep -Fq 'FW_SETENV_SCRIPT=$(dcent_sysupgrade_workspace_path fw-setenv.env)' "$_ws_caller_path"
    # shellcheck disable=SC2016
    expect_success "$_ws_caller_label streams bounded readback bytes instead of storing images" \
        grep -Fq '| head -c "$_size" | sha256sum' "$_ws_caller_path"
    expect_failure "$_ws_caller_label contains no historical predictable scratch path" \
        grep -E '(/tmp/(inactive_data|kernel[.]bin|dcent_preflip|uboot_env_pre|dcent_fw_setenv)|_FW_SETENV_SCRIPT)' "$_ws_caller_path"
done

if [ "$failures" -ne 0 ]; then
    printf '\nsysupgrade transaction-workspace tests failed: %s/%s failed\n' \
        "$failures" "$tests" >&2
    exit 1
fi
printf '\nsysupgrade transaction-workspace tests passed: %s assertions\n' "$tests"
