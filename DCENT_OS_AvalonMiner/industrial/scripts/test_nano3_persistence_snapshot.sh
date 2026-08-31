#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
snapshot=$project_dir/stock-runtime-overlay/etc/dcentos/nano3-persistence-snapshot.sh
verifier=$script_dir/verify_nano3_persistence_snapshots.py
run_id=1111111111111111111111111111111111111111111111111111111111111111

test_root=$(mktemp -d "${TMPDIR:-/tmp}/dcent-persistence-test.XXXXXX")
cleanup() {
    rm -rf "$test_root"
}
trap cleanup 0 1 2 15

proc_root=$test_root/proc
sys_root=$test_root/sys
data_root=$test_root/data
run_root=$test_root/run
mkdir -p "$proc_root/sys/kernel/random" \
    "$sys_root/class/ubi/ubi2" "$sys_root/class/ubi/ubi2_0" \
    "$data_root/usrcon" "$run_root/dcentos-data-ready"
printf '/dev/ubi2_0 %s ubifs rw 0 0\n' "$data_root" >"$proc_root/mounts"
printf '%s\n' 12 >"$sys_root/class/ubi/ubi2/mtd_num"
printf '%s\n' ubi_data_part >"$sys_root/class/ubi/ubi2_0/name"
printf '%s\n' '11111111-2222-3333-4444-555555555555' \
    >"$proc_root/sys/kernel/random/boot_id"
cat >"$data_root/usrcon/systemcfg.ini" <<'EOF'
[systemcfg]
ssid = private-wifi-name
password = wifi-secret-must-not-leak
mode = client
EOF
cat >"$data_root/usrcon/cgminer.ini" <<'EOF'
[cgminercfg]
url0 = stratum+tcp://private.pool.invalid:3333
user0 = private-worker-name
pass0 = pool-secret-must-not-leak
standard = --lowmem --real-quiet
EOF
chmod 0600 "$data_root/usrcon/systemcfg.ini" "$data_root/usrcon/cgminer.ini"

snapshot_env() {
    DCENT_PERSIST_TEST_MODE=1 \
    DCENT_PERSIST_PROC_ROOT=$proc_root \
    DCENT_PERSIST_SYS_ROOT=$sys_root \
    DCENT_PERSIST_DATA_ROOT=$data_root \
    DCENT_PERSIST_RUN_ROOT=$run_root \
        sh "$snapshot" "$@"
}

before=$test_root/before.txt
after=$test_root/after.txt
snapshot_env pre-reboot "$run_id" >"$before"
printf '%s\n' 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' \
    >"$proc_root/sys/kernel/random/boot_id"
snapshot_env post-reboot "$run_id" >"$after"

for secret in \
    private-wifi-name wifi-secret-must-not-leak \
    private.pool.invalid private-worker-name pool-secret-must-not-leak; do
    ! grep -F "$secret" "$before" "$after"
done
grep -qx 'configuration_values_printed=false' "$before"
grep -qx 'configuration_values_printed=false' "$after"
grep -qx 'authorizes_device=false' "$before"
grep -qx 'authorizes_reboot=false' "$after"

receipt=$test_root/receipt.txt
PYTHONDONTWRITEBYTECODE=1 python3 "$verifier" \
    --before "$before" --after "$after" >"$receipt"
grep -qx 'persistence_contract=pass' "$receipt"
grep -qx 'snapshot_provenance=operator-supplied-unsigned' "$receipt"
grep -qx 'configuration_values_printed=false' "$receipt"
grep -qx 'authorizes_device=false' "$receipt"
grep -qx 'authorizes_reboot=false' "$receipt"
grep -qx 'systemcfg_sha256=d8db5481f676acc488440cc57d9ac5754f22b43ae04494da6299129d0c8b5d91' \
    "$receipt"
grep -qx 'systemcfg_structure_sha256=888bb093a5790183c8aea494a9d83fa935d74fe34e5e07a258cef509fbeb1a75' \
    "$receipt"
grep -qx 'cgminer_sha256=b68d1c46985a6318bbf118324be6b67679c9d83840433e1d7b3e861fce5b1621' \
    "$receipt"
grep -qx 'cgminer_structure_sha256=19722d2010805347dcbeab366c4797cbb9ab8a7c7282cb71a91be672bcb4fa9a' \
    "$receipt"
for secret in \
    private-wifi-name wifi-secret-must-not-leak \
    private.pool.invalid private-worker-name pool-secret-must-not-leak; do
    ! grep -F "$secret" "$receipt"
done

# Content drift across boots must fail without echoing the changed secret.
cp "$data_root/usrcon/cgminer.ini" "$test_root/cgminer.saved"
printf '%s\n' '[cgminercfg]' 'url0 = changed-pool-secret' \
    'user0 = changed-worker' 'pass0 = changed-password' \
    >"$data_root/usrcon/cgminer.ini"
chmod 0600 "$data_root/usrcon/cgminer.ini"
changed=$test_root/changed.txt
snapshot_env post-reboot "$run_id" >"$changed"
if PYTHONDONTWRITEBYTECODE=1 python3 "$verifier" \
    --before "$before" --after "$changed" \
    >"$test_root/changed.out" 2>"$test_root/changed.err"; then
    echo 'changed persistent configuration unexpectedly passed' >&2
    exit 1
fi
! grep -F 'changed-pool-secret' "$test_root/changed.out" "$test_root/changed.err"
mv "$test_root/cgminer.saved" "$data_root/usrcon/cgminer.ini"

# A post snapshot from the same boot cannot be promoted into reboot proof.
printf '%s\n' '11111111-2222-3333-4444-555555555555' \
    >"$proc_root/sys/kernel/random/boot_id"
same_boot=$test_root/same-boot.txt
snapshot_env post-reboot "$run_id" >"$same_boot"
if PYTHONDONTWRITEBYTECODE=1 python3 "$verifier" \
    --before "$before" --after "$same_boot" >/dev/null 2>&1; then
    echo 'same-boot snapshots unexpectedly passed' >&2
    exit 1
fi

# Symlinked config, malformed INI, wrong mount identity, and malformed run IDs
# fail before any snapshot stdout is emitted.
mv "$data_root/usrcon/systemcfg.ini" "$test_root/systemcfg.saved"
ln -s "$test_root/systemcfg.saved" "$data_root/usrcon/systemcfg.ini"
if snapshot_env pre-reboot "$run_id" >"$test_root/symlink.out" 2>/dev/null; then
    echo 'symlinked configuration unexpectedly passed' >&2
    exit 1
fi
[ ! -s "$test_root/symlink.out" ]
rm "$data_root/usrcon/systemcfg.ini"
mv "$test_root/systemcfg.saved" "$data_root/usrcon/systemcfg.ini"

printf '%s\n' 'value-without-section-or-key' \
    >"$data_root/usrcon/systemcfg.ini"
if snapshot_env pre-reboot "$run_id" >"$test_root/ini.out" 2>/dev/null; then
    echo 'malformed INI unexpectedly passed' >&2
    exit 1
fi
[ ! -s "$test_root/ini.out" ]

printf '/dev/other %s ubifs rw 0 0\n' "$data_root" >"$proc_root/mounts"
if snapshot_env pre-reboot "$run_id" >"$test_root/mount.out" 2>/dev/null; then
    echo 'wrong mount identity unexpectedly passed' >&2
    exit 1
fi
[ ! -s "$test_root/mount.out" ]

if snapshot_env pre-reboot abc >"$test_root/run-id.out" 2>/dev/null; then
    echo 'malformed run ID unexpectedly passed' >&2
    exit 1
fi
[ ! -s "$test_root/run-id.out" ]

echo 'Nano 3 secret-safe persistence snapshot tests: PASS'
