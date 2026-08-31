#!/bin/sh
set -eu

# The admission contract proves root-only node ownership (mknod/chown) and an
# unprivileged refusal boundary. Exercise the literal boundaries instead of a
# weaker test-only ownership policy. GitHub's hosted Linux runners provide
# noninteractive sudo; local non-root environments must provide the same
# narrow capability explicitly (same pattern as test_dcentos_receipt_store.sh).
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        exec sudo -n sh "$0" "$@"
    fi
    echo "FAIL: UBI node admission tests require root or noninteractive sudo" >&2
    exit 1
fi

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
HELPER=$ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/sysupgrade-ubi-node.sh
TMP=${TMPDIR:-/tmp}/dcent-ubi-node-test.$$
PASS=0

cleanup()
{
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM

fail()
{
    printf '%s\n' "not ok - $*" >&2
    exit 1
}

ok()
{
    PASS=$((PASS + 1))
    printf '%s\n' "ok $PASS - $*"
}

expect_fail()
{
    _label=$1
    shift
    if "$@" >/dev/null 2>&1; then
        fail "$_label unexpectedly succeeded"
    fi
    ok "$_label"
}

mkdir -p "$TMP/sys/class/ubi/ubi1" "$TMP/sys/class/ubi/ubi1_0" \
    "$TMP/sys/class/misc/ubi_ctrl" "$TMP/dev"
printf '%s\n' '250:0' >"$TMP/sys/class/ubi/ubi1/dev"
printf '%s\n' '250:1' >"$TMP/sys/class/ubi/ubi1_0/dev"
printf '%s\n' '10:63' >"$TMP/sys/class/misc/ubi_ctrl/dev"

# shellcheck source=/dev/null
. "$HELPER"

expect_fail 'admit rejects missing arguments' dcent_ubi_node_admit
expect_fail 'ensure rejects missing arguments' dcent_ubi_node_ensure
expect_fail 'admit rejects relative sysfs authority' \
    dcent_ubi_node_admit relative/dev "$TMP/dev" ubi1
expect_fail 'admit rejects non-dev sysfs basename' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/device" "$TMP/dev" ubi1
expect_fail 'admit rejects relative device root' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" relative ubi1
expect_fail 'admit rejects filesystem root as device root' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" / ubi1
ln -s "$TMP/dev" "$TMP/dev-link"
expect_fail 'admit rejects symlink device root' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev-link" ubi1
expect_fail 'admit rejects unsafe node name' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ../ubi1
expect_fail 'admit rejects suffix after device number' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1evil
expect_fail 'admit rejects suffix after volume number' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1_0/dev" "$TMP/dev" ubi1_0evil
expect_fail 'admit rejects multiple volume separators' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1_0/dev" "$TMP/dev" ubi1_0_1
expect_fail 'admit binds node name to sysfs authority' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi2
expect_fail 'admit rejects missing node' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1

cp "$TMP/sys/class/ubi/ubi1/dev" "$TMP/good-dev"
printf '%s\n' '250' >"$TMP/sys/class/ubi/ubi1/dev"
expect_fail 'admit rejects authority without separator' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1
printf '%s\n' '250:0:1' >"$TMP/sys/class/ubi/ubi1/dev"
expect_fail 'admit rejects authority with multiple separators' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1
printf '%s\n' '250:x' >"$TMP/sys/class/ubi/ubi1/dev"
expect_fail 'admit rejects non-decimal authority' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1
printf '%s\n' '08:0' >"$TMP/sys/class/ubi/ubi1/dev"
expect_fail 'admit rejects leading-zero major authority' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1
printf '%s\n' '250:00' >"$TMP/sys/class/ubi/ubi1/dev"
expect_fail 'admit rejects leading-zero minor authority' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1
printf '%s\n%s\n' '250:0' '250:0' >"$TMP/sys/class/ubi/ubi1/dev"
expect_fail 'admit rejects multiline authority' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1
printf '%s\n' '4096:0' >"$TMP/sys/class/ubi/ubi1/dev"
expect_fail 'admit rejects out-of-range major' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1
mv "$TMP/good-dev" "$TMP/sys/class/ubi/ubi1/dev"
mv "$TMP/sys/class/ubi/ubi1/dev" "$TMP/sys/class/ubi/ubi1/dev-real"
ln -s "$TMP/sys/class/ubi/ubi1/dev-real" "$TMP/sys/class/ubi/ubi1/dev"
expect_fail 'admit rejects symlink authority' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1
rm "$TMP/sys/class/ubi/ubi1/dev"
mv "$TMP/sys/class/ubi/ubi1/dev-real" "$TMP/sys/class/ubi/ubi1/dev"

expect_fail 'admit rejects empty UBI device number' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi
expect_fail 'admit rejects missing device before volume separator' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi_1
expect_fail 'admit rejects missing volume after separator' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1_
expect_fail 'admit rejects leading-zero UBI device number' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi01
expect_fail 'admit rejects leading-zero UBI volume number' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1_0/dev" "$TMP/dev" ubi1_00

mkdir "$TMP/dev/ubi1"
expect_fail 'admit rejects directory in node position' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1
rmdir "$TMP/dev/ubi1"
ln -s /dev/null "$TMP/dev/ubi1"
expect_fail 'admit rejects node symlink' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1
rm "$TMP/dev/ubi1"

mknod -m 600 "$TMP/dev/ubi1" c 1 3
expect_fail 'admit rejects wrong character-device identity' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1
rm "$TMP/dev/ubi1"
mknod -m 660 "$TMP/dev/ubi1" c 250 0
expect_fail 'admit rejects permissive character-device mode' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1
chmod 600 "$TMP/dev/ubi1"
chown 1:1 "$TMP/dev/ubi1"
expect_fail 'admit rejects non-root character-device owner' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1
chown 0:0 "$TMP/dev/ubi1"
ln "$TMP/dev/ubi1" "$TMP/dev/ubi1-alias"
expect_fail 'admit rejects a hard-linked device-node alias' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1
rm "$TMP/dev/ubi1-alias"
ORIGINAL_IFS=$IFS
dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1 || \
    fail 'exact existing node was rejected'
ok 'admit accepts exact root-only character device'
[ "$IFS" = "$ORIGINAL_IFS" ] || fail 'admission leaked its metadata parser IFS'
ok 'admit restores caller IFS after metadata parsing'

mkdir "$TMP/mock-bin"
REAL_STAT=$(command -v stat)
cat >"$TMP/mock-bin/stat" <<'EOF'
#!/bin/sh
case "$*" in
    *'%t:%T'*) printf '%s\n' '250:9' >"$DCENT_TEST_MUTATE_AUTHORITY" ;;
esac
exec "$DCENT_TEST_REAL_STAT" "$@"
EOF
chmod 755 "$TMP/mock-bin/stat"
export DCENT_TEST_MUTATE_AUTHORITY="$TMP/sys/class/ubi/ubi1/dev"
export DCENT_TEST_REAL_STAT="$REAL_STAT"
OLD_PATH=$PATH
PATH=$TMP/mock-bin:$PATH
export PATH
expect_fail 'admit rejects sysfs authority drift during metadata inspection' \
    dcent_ubi_node_admit "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1
PATH=$OLD_PATH
export PATH
printf '%s\n' '250:0' >"$TMP/sys/class/ubi/ubi1/dev"

DCENT_UBI_NODE_CREATED=stale
dcent_ubi_node_ensure "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1 || \
    fail 'ensure rejected exact existing node'
[ "$DCENT_UBI_NODE_CREATED" = 0 ] || fail 'existing-node ensure reported creation'
ok 'ensure validates existing node without claiming ownership'

rm "$TMP/dev/ubi1"
dcent_ubi_node_ensure "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1 || \
    fail 'ensure did not create missing exact node'
[ "$DCENT_UBI_NODE_CREATED" = 1 ] || fail 'new-node ensure did not report creation'
[ "$(stat -c '%u:%g:%a:%t:%T' "$TMP/dev/ubi1")" = '0:0:600:fa:0' ] || \
    fail 'created node metadata or identity differs'
ok 'ensure creates exact root-only node and reports ownership'

rm "$TMP/dev/ubi1"
mknod -m 660 "$TMP/dev/ubi1" c 250 0
expect_fail 'ensure never repairs an existing permissive node' \
    dcent_ubi_node_ensure "$TMP/sys/class/ubi/ubi1/dev" "$TMP/dev" ubi1
[ "$(stat -c '%a' "$TMP/dev/ubi1")" = 660 ] || fail 'ensure changed existing node mode'
ok 'failed ensure preserved existing object unchanged'

rm "$TMP/dev/ubi1"
dcent_ubi_node_ensure "$TMP/sys/class/misc/ubi_ctrl/dev" "$TMP/dev" ubi_ctrl || \
    fail 'ubi_ctrl creation was rejected'
[ "$(stat -c '%u:%g:%a:%t:%T' "$TMP/dev/ubi_ctrl")" = '0:0:600:a:3f' ] || \
    fail 'ubi_ctrl node metadata or identity differs'
ok 'same authority model covers ubi_ctrl'

rm -f "$TMP/dev/ubi_ctrl"
dcent_ubi_node_ensure "$TMP/sys/class/ubi/ubi1_0/dev" "$TMP/dev" ubi1_0 || \
    fail 'volume-node creation was rejected'
[ "$(stat -c '%u:%g:%a:%t:%T' "$TMP/dev/ubi1_0")" = '0:0:600:fa:1' ] || \
    fail 'volume node metadata or identity differs'
ok 'same authority model covers exact volume nodes'

# Run a command as an unprivileged identity. Prefer `su nobody` (PAM-backed
# on CI); fall back to setpriv where a broken/PAM-less environment (e.g. some
# WSL images) makes `su` fail even for root. If neither mechanism can drop
# privilege, say so and skip only the unprivileged assertions.
UNPRIV_RC=0
unprivileged()
{
    script=$1
    shift
    if [ "$UNPRIV_RC" -eq 1 ]; then
        su nobody -s /bin/sh -c "$script" sh "$@"
    elif [ "$UNPRIV_RC" -eq 2 ]; then
        setpriv --reuid=65534 --regid=65534 --clear-groups \
            sh -c "$script" sh "$@"
    else
        return 125
    fi
}
if su nobody -s /bin/sh -c true >/dev/null 2>&1; then
    UNPRIV_RC=1
elif command -v setpriv >/dev/null 2>&1 \
    && setpriv --reuid=65534 --regid=65534 --clear-groups true >/dev/null 2>&1; then
    UNPRIV_RC=2
else
    echo "not ok - no unprivileged identity mechanism (su/setpriv); skipping unprivileged assertions" >&2
fi

if [ "$UNPRIV_RC" -ne 0 ]; then
    chmod 755 "$TMP" "$TMP/sys" "$TMP/sys/class" "$TMP/sys/class/ubi" \
        "$TMP/sys/class/ubi/ubi1_0" "$TMP/dev"
    unprivileged \
        '. "$1"; dcent_ubi_node_admit "$2" "$3" ubi1_0' \
        "$HELPER" "$TMP/sys/class/ubi/ubi1_0/dev" "$TMP/dev" || \
        fail 'unprivileged exact admission failed'
    ok 'exact admission is independently usable without privilege'
    rm "$TMP/dev/ubi1_0"
    if unprivileged \
        '. "$1"; dcent_ubi_node_ensure "$2" "$3" ubi1_0' \
        "$HELPER" "$TMP/sys/class/ubi/ubi1_0/dev" "$TMP/dev" \
        >/dev/null 2>&1; then
        fail 'unprivileged ensure created a missing node'
    fi
    [ ! -e "$TMP/dev/ubi1_0" ] || fail 'unprivileged ensure left an object'
    ok 'unprivileged ensure cannot create a missing node'
fi

printf '%s\n' "1..$PASS"
