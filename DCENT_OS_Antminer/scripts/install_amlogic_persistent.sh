#!/bin/bash
# DCENTos - Amlogic persistent NAND install (exact am3-aml lab targets)
# D-Central Technologies, 2026
#
# Bridge-firmware-required workflow: target must be on BraiinsOS+ (or
# LuxOS) with root SSH BEFORE this script runs. Stock S19j Pro Amlogic
# only has miner:miner SSH; that path is not yet adapter-backed.
# See plans/zesty-cooking-bee.md Phase R for full context.
#
# Run from operator's host. Performs:
#   0. Local package-only validation (prefix, manifest, SHA256SUMS, uImage).
#   1. SSH preflight: root shell, required tools (nandwrite, flash_erase,
#      fw_setenv, sha256sum), platform=am3-aml.
#   2. Backup /dev/nand_env + /dev/mtd5 + fw_printenv to --artifact-dir.
#   3. SCP sysupgrade tar to /data, verify SHA256 (uses /data not /tmp --
# for rationale).
#   4. Extract tar, verify SHA256SUMS, validate MANIFEST.json board.
#   5. (--dry-run halts here; mining services are not stopped.)
#   6. Confirm destructive operation.
#   7. Stop bosminer/boser/bos-tools cleanly.
#   8. flash_erase + nandwrite rootfs to mtd5 LOCAL offset 0x05100000.
#   9. nanddump readback; install commit is recovery-flag 0x01
#      eraseblock rewrite (firstboot is S99 WAL companion only).
#  10. Print monitoring instructions.
#
# After reboot: operator polls `dcent detect <ip>` for DCENTOS state.
# Rollback is recovery-flag 0x02 → recover_to_stock (env restore + erase
# nvdata), not a direct bootm of mtd2. firstboot is a DCENT/S99upgrade
# env key; .78 bootcmd never reads it.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/am3_geometry.sh"
. "$SCRIPT_DIR/lib/amlogic_identity_guard.sh"
ROOTFS_MTD="$DCENT_AM3_ROOTFS_MTD"
ROOTFS_OFFSET_HEX="$DCENT_AM3_ROOTFS_OFFSET_HEX"
ROOTFS_WINDOW_HEX="$DCENT_AM3_ROOTFS_WINDOW_HEX"
ROOTFS_ERASE_COUNT="$DCENT_AM3_ROOTFS_ERASE_COUNT"
ROOTFS_ERASESIZE_EXPECTED="$DCENT_AM3_ROOTFS_ERASESIZE_EXPECTED"
ROOTFS_OFFSET_DEC="$DCENT_AM3_ROOTFS_OFFSET_DEC"
ROOTFS_WINDOW_DEC="$DCENT_AM3_ROOTFS_WINDOW_DEC"
ROOTFS_END_DEC="$DCENT_AM3_ROOTFS_END_DEC"

usage() {
    cat >&2 <<USAGE
Usage: $(basename "$0") <miner_ip> --artifact-dir <dir> [--firmware <sysupgrade.tar>] [--variant s19jpro-aml|s19jproplus|s19xp|s19jxp|s19kpro|s21|s21pro|s21xp|t21] [--backup-only] [--dry-run] [--yes]

Required:
  <miner_ip>             Target miner IP (must be on BraiinsOS+/LuxOS with root SSH)
  --artifact-dir <dir>   Local dir to store nand_env + mtd5 backup + fw_env

Options:
  --firmware <tar>       Path to a DCENT_OS AM3 sysupgrade tar (required unless --backup-only)
  --variant s19jpro-aml|s19jproplus|s19xp|s19jxp|s19kpro|s21|s21pro|s21xp|t21
                         Package variant to validate/write (default: s19kpro)
  --backup-only          nand_env + mtd5 + gpio437 backup only; never flash
  --dry-run              Run preflight + backup + SHA256 verify only; no flash
  --yes                  Skip interactive destructive-step confirmation

Braiins AML L3: some images lack fw_printenv/fw_setenv. Backup still runs.
FLASH / env-flip is refused until those tools exist. CLEAR_FOR_FLASH stays false.

Environment:
  DCENT_PASSWORD         Optional SSH password (else SSH agent / keys)
USAGE
    exit 2
}

[ $# -ge 1 ] || usage
MINER_IP="$1"
shift

FIRMWARE=""
ARTIFACT_DIR=""
VARIANT="s19kpro"
DRY_RUN=false
SKIP_CONFIRM=false
BACKUP_ONLY=false

while [ $# -gt 0 ]; do
    case "$1" in
        --firmware)     FIRMWARE="${2:?--firmware requires path}"; shift 2 ;;
        --artifact-dir) ARTIFACT_DIR="${2:?--artifact-dir requires path}"; shift 2 ;;
        --variant)      VARIANT="${2:?--variant requires s19jpro-aml, s19jproplus, s19xp, s19jxp, s19kpro, s21, s21pro, s21xp, or t21}"; shift 2 ;;
        --backup-only)  BACKUP_ONLY=true; shift ;;
        --dry-run)      DRY_RUN=true; shift ;;
        --yes)          SKIP_CONFIRM=true; shift ;;
        -h|--help)      usage ;;
        *)              echo "Unknown arg: $1" >&2; usage ;;
    esac
done

[ -n "$ARTIFACT_DIR" ] || { echo "ERROR: --artifact-dir required" >&2; exit 2; }
if [ "$BACKUP_ONLY" != true ]; then
    [ -n "$FIRMWARE" ] || { echo "ERROR: --firmware required (or pass --backup-only)" >&2; exit 2; }
    [ -f "$FIRMWARE" ] || { echo "ERROR: $FIRMWARE not found" >&2; exit 2; }
fi
mkdir -p "$ARTIFACT_DIR"

case "$VARIANT" in
    s19jpro-aml|s19jpro|s19j)
        BOARD_PKG_NAME="am3-s19jpro-aml"
        PACKAGE_PREFIX="sysupgrade-am3-s19jpro-aml"
        ;;
    s19jproplus|s19j-pro-plus|s19jpro+)
        VARIANT="s19jproplus"
        BOARD_PKG_NAME="am3-s19jproplus"
        PACKAGE_PREFIX="sysupgrade-am3-s19jproplus"
        ;;
    s19xp)
        BOARD_PKG_NAME="am3-s19xp"
        PACKAGE_PREFIX="sysupgrade-am3-s19xp"
        ;;
    s19jxp|s19j-xp)
        VARIANT="s19jxp"
        BOARD_PKG_NAME="am3-s19jxp"
        PACKAGE_PREFIX="sysupgrade-am3-s19jxp"
        ;;
    s19kpro|s19k)
        BOARD_PKG_NAME="am3-s19k"
        PACKAGE_PREFIX="sysupgrade-am3-s19k"
        ;;
    s21)
        BOARD_PKG_NAME="am3-s21"
        PACKAGE_PREFIX="sysupgrade-am3-s21"
        ;;
    s21pro)
        BOARD_PKG_NAME="am3-s21pro"
        PACKAGE_PREFIX="sysupgrade-am3-s21pro"
        ;;
    s21xp)
        BOARD_PKG_NAME="am3-s21xp"
        PACKAGE_PREFIX="sysupgrade-am3-s21xp"
        ;;
    t21)
        BOARD_PKG_NAME="am3-t21"
        PACKAGE_PREFIX="sysupgrade-am3-t21"
        ;;
    *)
        echo "ERROR: unsupported --variant: $VARIANT (supported: s19jpro-aml, s19jproplus, s19xp, s19jxp, s19kpro, s21, s21pro, s21xp, t21)" >&2
        exit 2
        ;;
esac
REMOTE_PREFIX="/data/sysupgrade/$PACKAGE_PREFIX"

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=no"
log() { printf '[install_amlogic_persistent] %s\n' "$*"; }

ssh_run() {
    if [ -n "${DCENT_PASSWORD:-}" ] && command -v sshpass >/dev/null 2>&1; then
        sshpass -p "$DCENT_PASSWORD" ssh $SSH_OPTS "root@${MINER_IP}" "$1"
    else
        ssh $SSH_OPTS "root@${MINER_IP}" "$1"
    fi
}

scp_put() {
    if [ -n "${DCENT_PASSWORD:-}" ] && command -v sshpass >/dev/null 2>&1; then
        sshpass -p "$DCENT_PASSWORD" scp -O $SSH_OPTS "$1" "root@${MINER_IP}:$2"
    else
        scp -O $SSH_OPTS "$1" "root@${MINER_IP}:$2"
    fi
}

scp_get() {
    if [ -n "${DCENT_PASSWORD:-}" ] && command -v sshpass >/dev/null 2>&1; then
        sshpass -p "$DCENT_PASSWORD" scp -O $SSH_OPTS "root@${MINER_IP}:$1" "$2"
    else
        scp -O $SSH_OPTS "root@${MINER_IP}:$1" "$2"
    fi
}

local_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    elif command -v shasum  >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
    else echo ""; fi
}

require_uint() {
    case "$2" in
        ''|*[!0-9]*) log "ERROR: $1 is not numeric: '$2'"; exit 1 ;;
    esac
}

normalize_target_signal() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]'
}

require_exact_amlogic_variant() {
    local variant="$1"
    local platform="$2"
    local identity
    local board_target
    local model
    local hwid
    local normalized
    local board_norm
    local model_norm
    local soc_norm
    local pcb_norm
    local identity_lower

    identity=$(ssh_run '
        printf "BOARD_TARGET=%s\n" "$(cat /etc/dcentos/board_target 2>/dev/null | head -1 | tr -d "[:space:]")"
        printf "MODEL=%s\n" "$(cat /config/CONF_MINER_TYPE 2>/dev/null | head -1)"
        printf "HWID=%s\n" "$(cat /config/CONF_HARDWARE_ID 2>/dev/null | head -1)"
        printf "PCB=%s\n" "$(for f in /config/CONF_CONTROL_BOARD /config/CONF_CTRL_BOARD_TYPE /config/CONF_BOARD_TYPE /etc/dcentos/pcb; do [ -r "$f" ] && { head -1 "$f"; break; }; done)"
        printf "BOS_MODEL=%s\n" "$(grep "^model" /etc/bosminer.toml 2>/dev/null | head -1)"
        printf "DT_MODEL=%s\n" "$(tr "\000" "\n" < /proc/device-tree/model 2>/dev/null | head -1)"
        printf "DT_COMPATIBLE=%s\n" "$(tr "\000" "\n" < /proc/device-tree/compatible 2>/dev/null | tr "\n" " ")"
        printf "CPU_SYSTEM=%s\n" "$(sed -n "s/^Hardware[[:space:]]*:[[:space:]]*//p;s/^model name[[:space:]]*:[[:space:]]*//p" /proc/cpuinfo 2>/dev/null | head -2 | tr "\n" " ")"
    ') || { log "ERROR: unable to read exact Amlogic target identity"; exit 1; }

    board_target=$(printf '%s\n' "$identity" | sed -n 's/^BOARD_TARGET=//p' | head -1)
    model=$(printf '%s\n' "$identity" | sed -n 's/^MODEL=//p' | head -1)
    hwid=$(printf '%s\n' "$identity" | sed -n 's/^HWID=//p' | head -1)
    normalized=$(normalize_target_signal "$identity")
    board_norm=$(normalize_target_signal "$board_target")
    model_norm=$(printf '%s\n' "$identity" | sed -n '/^MODEL=/p;/^HWID=/p;/^BOS_MODEL=/p' | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]')
    soc_norm=$(printf '%s\n' "$identity" | sed -n '/^DT_MODEL=/p;/^DT_COMPATIBLE=/p;/^CPU_SYSTEM=/p' | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]')
    pcb_norm=$(printf '%s\n' "$identity" | sed -n '/^PCB=/p;/^HWID=/p;/^DT_MODEL=/p;/^DT_COMPATIBLE=/p' | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]')
    identity_lower=$(printf '%s' "$identity" | tr '[:upper:]' '[:lower:]')

    if sibling_rejection=$(
        dcent_amlogic_sibling_rejection "$variant" "$normalized" "$identity_lower"
    ); then
        log "ERROR: $sibling_rejection; refusing destructive flash"
        exit 1
    fi

    if tuple_receipt=$(dcent_amlogic_identity_record_admit "$variant" "$identity"); then
        log "  exact target OK: $tuple_receipt"
        return 0
    fi
    log "ERROR: $tuple_receipt; refusing destructive flash"
    log "$identity"
    exit 1

    # Kept below as unreachable reference logic until the tuple gate has
    # accumulated exact-unit observations for every historical spelling.
    case "$normalized" in
        *s19jxp*)
            if [ "$variant" != "s19jxp" ]; then
                log "ERROR: ${model:-${hwid:-unknown}} is not the selected installer variant; refusing destructive flash"
                exit 1
            fi
            ;;
        *s19jproplus*)
            if [ "$variant" != "s19jproplus" ]; then
                log "ERROR: ${model:-${hwid:-unknown}} is not the selected installer variant; refusing destructive flash"
                exit 1
            fi
            ;;
        *t19*|*s17*|*t17*)
            log "ERROR: ${model:-${hwid:-unknown}} is an Experimental feature / In development target for this installer; refusing destructive flash"
            exit 1
            ;;
    esac

    case "$variant" in
        s19jpro-aml|s19jpro|s19j)
            case "$identity_lower" in
                *s19j\ pro+*|*s19jpro+*|*s19j\ pro\ plus*|*s19jproplus*)
                    log "ERROR: --variant s19jpro-aml refuses S19j Pro+ identity"
                    exit 1
                    ;;
            esac
            case "$normalized" in
                *s19jxp*|*s19jproplus*)
                    log "ERROR: --variant s19jpro-aml refuses S19j XP / S19j Pro+ identity"
                    exit 1
                    ;;
            esac
            case "$board_norm" in
                am3s19jproaml|amlogics19j|amlogics19jpro)
                    case "$normalized" in
                        *s19jpro*)
                            log "  exact target OK: board_target=$board_target"
                            return 0
                            ;;
                    esac
                    ;;
            esac
            case "$normalized" in
                *s19jpro*) ;;
                *)
                    log "ERROR: --variant s19jpro-aml requires exact S19j Pro Amlogic target identity before flash"
                    log "$identity"
                    exit 1
                    ;;
            esac
            ;;
        s19jproplus)
            case "$identity_lower" in
                *s19j\ xp*|*s19jxp*|*s19\ xp*|*s19xp*|*hydro*)
                    log "ERROR: --variant s19jproplus requires exact S19j Pro+ identity; refusing S19 XP / S19j XP / Hydro variants"
                    exit 1
                    ;;
            esac
            case "$board_norm" in
                am3s19jproplus|amlogics19jproplus)
                    case "$identity_lower" in
                        *s19j\ pro+*|*s19jpro+*|*s19j\ pro\ plus*|*s19jproplus*)
                            log "  exact target OK: board_target=$board_target"
                            return 0
                            ;;
                    esac
                    ;;
            esac
            case "$identity_lower" in
                *s19j\ pro+*|*s19jpro+*|*s19j\ pro\ plus*|*s19jproplus*) ;;
                *)
                    log "ERROR: --variant s19jproplus requires exact S19j Pro+ Amlogic target identity before flash"
                    log "$identity"
                    exit 1
                    ;;
            esac
            ;;
        s19xp)
            case "$identity_lower" in
                *s19j\ xp*|*s19jxp*|*s19\ xp+*|*s19xp+*|*s19\ xp\ plus*|*s19xpplus*|*hydro*)
                    log "ERROR: --variant s19xp requires exact air-cooled S19 XP identity; refusing S19j XP / XP+ / Hydro variants"
                    exit 1
                    ;;
            esac
            case "$board_norm" in
                am3s19xp|amlogics19xp)
                    case "$normalized" in
                        *s19xp*)
                            log "  exact target OK: board_target=$board_target"
                            return 0
                            ;;
                    esac
                    ;;
            esac
            case "$normalized" in
                *s19xp*) ;;
                *)
                    log "ERROR: --variant s19xp requires exact S19 XP Amlogic target identity before flash"
                    log "$identity"
                    exit 1
                    ;;
            esac
            ;;
        s19jxp)
            case "$identity_lower" in
                *s19\ xp*|*s19xp*)
                    case "$identity_lower" in
                        *s19j\ xp*|*s19jxp*) ;;
                        *)
                            log "ERROR: --variant s19jxp refuses plain S19 XP identity"
                            exit 1
                            ;;
                    esac
                    ;;
                *hydro*)
                    log "ERROR: --variant s19jxp refuses Hydro variants"
                    exit 1
                    ;;
            esac
            case "$board_norm" in
                am3s19jxp|amlogics19jxp)
                    case "$normalized" in
                        *s19jxp*)
                            log "  exact target OK: board_target=$board_target"
                            return 0
                            ;;
                    esac
                    ;;
            esac
            case "$normalized" in
                *s19jxp*) ;;
                *)
                    log "ERROR: --variant s19jxp requires exact S19j XP Amlogic target identity before flash"
                    log "$identity"
                    exit 1
                    ;;
            esac
            ;;
        s19kpro|s19k)
            case "$board_norm" in
                am3s19k|amlogics19k)
                    log "  exact target OK: board_target=$board_target"
                    return 0
                    ;;
            esac
            case "$normalized" in
                *s19k*) ;;
                *)
                    log "ERROR: --variant $variant requires exact S19K target identity before flash"
                    log "$identity"
                    exit 1
                    ;;
            esac
            ;;
        s21)
            case "$normalized" in
                *s21pro*|*s21xp*)
                    log "ERROR: --variant s21 is base-S21 only; use --variant s21pro or --variant s21xp for distinct S21 Pro / S21 XP carriers"
                    exit 1
                    ;;
            esac
            case "$board_norm" in
                am3s21|amlogics21)
                    log "  exact target OK: board_target=$board_target"
                    return 0
                    ;;
            esac
            case "$normalized" in
                *s21*) ;;
                *)
                    log "ERROR: --variant s21 requires exact base-S21 target identity before flash"
                    log "$identity"
                    exit 1
                    ;;
            esac
            ;;
        s21pro)
            case "$normalized" in
                *s21xp*)
                    log "ERROR: --variant s21pro refuses S21 XP identity; use --variant s21xp"
                    exit 1
                    ;;
            esac
            case "$board_norm" in
                am3s21pro|amlogics21pro)
                    case "$normalized" in
                        *s21pro*)
                            log "  exact target OK: board_target=$board_target"
                            return 0
                            ;;
                    esac
                    ;;
            esac
            case "$normalized" in
                *s21pro*) ;;
                *)
                    log "ERROR: --variant s21pro requires exact S21 Pro target identity before flash"
                    log "$identity"
                    exit 1
                    ;;
            esac
            ;;
        s21xp)
            case "$normalized" in
                *s21pro*)
                    log "ERROR: --variant s21xp refuses S21 Pro identity; use --variant s21pro"
                    exit 1
                    ;;
            esac
            case "$board_norm" in
                am3s21xp|amlogics21xp)
                    case "$normalized" in
                        *s21xp*)
                            log "  exact target OK: board_target=$board_target"
                            return 0
                            ;;
                    esac
                    ;;
            esac
            case "$normalized" in
                *s21xp*) ;;
                *)
                    log "ERROR: --variant s21xp requires exact S21 XP target identity before flash"
                    log "$identity"
                    exit 1
                    ;;
            esac
            ;;
        t21)
            case "$board_norm" in
                am3t21|amlogict21)
                    case "$normalized" in
                        *t21*)
                            log "  exact target OK: board_target=$board_target"
                            return 0
                            ;;
                    esac
                    ;;
            esac
            case "$normalized" in
                *t21*) ;;
                *)
                    log "ERROR: --variant t21 requires exact T21 target identity before flash"
                    log "$identity"
                    exit 1
                    ;;
            esac
            ;;
        *)
            log "ERROR: unsupported variant identity gate: $variant"
            exit 1
            ;;
    esac
    log "  exact target OK: ${model:-${hwid:-$platform}}"
}

# --- Step 0: local package-only validation --------------------------------
if [ "$BACKUP_ONLY" != true ]; then
    log "Step 0/10: local package-only validation for $FIRMWARE ($BOARD_PKG_NAME)"
    bash "$SCRIPT_DIR/pre_flash_validate.sh" --package-only "$FIRMWARE" "$BOARD_PKG_NAME"
else
    log "Step 0/10: --backup-only — skip package validation (no flash)"
fi

# --- Step 1: SSH + tool preflight ----------------------------------------
log "Step 1/10: SSH preflight on root@$MINER_IP"
ssh_run "echo SSH_OK" >/dev/null || { log "ERROR: SSH failed"; exit 1; }

PLATFORM=$(ssh_run "cat /etc/bos_platform 2>/dev/null || cat /etc/dcentos-platform 2>/dev/null || echo unknown")
log "  platform: $PLATFORM"
case "$PLATFORM" in
    am3-aml*) ;;
    *) log "ERROR: not am3-aml - refusing destructive flash on $PLATFORM"; exit 1 ;;
esac
require_exact_amlogic_variant "$VARIANT" "$PLATFORM"

MISSING_BACKUP=$(ssh_run 'for t in sha256sum nanddump tar dd; do command -v $t >/dev/null 2>&1 || echo $t; done')
if [ -n "$MISSING_BACKUP" ]; then
    log "ERROR: missing backup tools on target: $MISSING_BACKUP"
    exit 1
fi
MISSING_FLASH=$(ssh_run 'for t in nandwrite flash_erase fw_setenv fw_printenv; do command -v $t >/dev/null 2>&1 || echo $t; done')
FLASH_TOOLS_OK=true
if [ -n "$MISSING_FLASH" ]; then
    FLASH_TOOLS_OK=false
    log "  FLASH blocked (Braiins L3 / missing env tools): $MISSING_FLASH"
    log "  backup nand_env+mtd5 still required; env-flip/flash refused"
    if [ "$BACKUP_ONLY" != true ] && [ "$DRY_RUN" != true ]; then
        log "ERROR: flash tools missing ($MISSING_FLASH). Use --backup-only on this image."
        exit 1
    fi
else
    log "  tools OK: nandwrite flash_erase fw_setenv nanddump tar sha256sum dd"
fi

MTD5_NAME=$(ssh_run "cat /sys/class/mtd/mtd5/name 2>/dev/null || echo unknown")
MTD5_SIZE=$(ssh_run "cat /sys/class/mtd/mtd5/size 2>/dev/null || echo 0")
MTD5_ERASESIZE=$(ssh_run "cat /sys/class/mtd/mtd5/erasesize 2>/dev/null || echo 0")
require_uint "mtd5 size" "$MTD5_SIZE"
require_uint "mtd5 erasesize" "$MTD5_ERASESIZE"
if [ "$MTD5_ERASESIZE" -ne "$ROOTFS_ERASESIZE_EXPECTED" ]; then
    log "ERROR: mtd5 erasesize $MTD5_ERASESIZE != expected $ROOTFS_ERASESIZE_EXPECTED"
    exit 1
fi
if [ "$MTD5_SIZE" -lt "$ROOTFS_END_DEC" ]; then
    log "ERROR: mtd5 size $MTD5_SIZE too small for rootfs window end $ROOTFS_END_DEC"
    exit 1
fi
log "  mtd5 geometry OK: name=$MTD5_NAME size=$MTD5_SIZE erasesize=$MTD5_ERASESIZE window=${ROOTFS_OFFSET_HEX}+${ROOTFS_WINDOW_HEX}"

# --- Step 2: backup nand_env + mtd5 + fw_env -----------------------------
log "Step 2/10: backup nand_env + mtd5 + fw_printenv to $ARTIFACT_DIR"
if ssh_run "command -v fw_printenv >/dev/null 2>&1"; then
    ssh_run "fw_printenv" > "$ARTIFACT_DIR/fw_env_pre.txt"
    [ -s "$ARTIFACT_DIR/fw_env_pre.txt" ] || { log "ERROR: fw_printenv backup is empty"; exit 1; }
    FW_PRINTENV_PRESENT=true
else
    printf '%s\n' "ABSENT_BRAIINS_L3" > "$ARTIFACT_DIR/fw_env_pre.txt"
    FW_PRINTENV_PRESENT=false
    log "  fw_printenv ABSENT_BRAIINS_L3 — nand_env dd is the env backup"
fi
GPIO437_VAL=$(ssh_run 'if [ -f /sys/class/gpio/gpio437/value ]; then cat /sys/class/gpio/gpio437/value; else echo unexported; fi')
printf '%s\n' "$GPIO437_VAL" > "$ARTIFACT_DIR/gpio437.value"
log "  gpio437.value=$GPIO437_VAL"
NAND_ENV_REMOTE_SHA=$(ssh_run "dd if=/dev/nand_env of=/tmp/nand_env_pre.bin bs=64K count=1 >/dev/null 2>&1 && sha256sum /tmp/nand_env_pre.bin | awk '{print \$1}'")
scp_get "/tmp/nand_env_pre.bin" "$ARTIFACT_DIR/nand_env.bak"
ssh_run "rm -f /tmp/nand_env_pre.bin"
NAND_ENV_SIZE=$(wc -c < "$ARTIFACT_DIR/nand_env.bak")
require_uint "nand_env backup size" "$NAND_ENV_SIZE"
[ "$NAND_ENV_SIZE" -eq 65536 ] || { log "ERROR: nand_env backup size $NAND_ENV_SIZE != 65536"; exit 1; }
NAND_ENV_LOCAL_SHA=$(local_sha256 "$ARTIFACT_DIR/nand_env.bak")
[ "$NAND_ENV_REMOTE_SHA" = "$NAND_ENV_LOCAL_SHA" ] || {
    log "ERROR: nand_env backup SHA mismatch: remote $NAND_ENV_REMOTE_SHA local $NAND_ENV_LOCAL_SHA"
    exit 1
}
log "  nand_env.bak: $NAND_ENV_SIZE bytes sha256=$NAND_ENV_LOCAL_SHA"

MTD5_REMOTE_SHA=$(ssh_run "nanddump --bb=skipbad -f /tmp/mtd5_pre.bin $ROOTFS_MTD >/dev/null 2>&1 && sha256sum /tmp/mtd5_pre.bin | awk '{print \$1}'")
scp_get "/tmp/mtd5_pre.bin" "$ARTIFACT_DIR/mtd5_pre_install.bin"
ssh_run "rm -f /tmp/mtd5_pre.bin"
MTD5_LOCAL_SHA=$(local_sha256 "$ARTIFACT_DIR/mtd5_pre_install.bin")
[ "$MTD5_REMOTE_SHA" = "$MTD5_LOCAL_SHA" ] || {
    log "ERROR: mtd5 backup SHA mismatch: remote $MTD5_REMOTE_SHA local $MTD5_LOCAL_SHA"
    exit 1
}
MTD5_BACKUP_SIZE=$(wc -c < "$ARTIFACT_DIR/mtd5_pre_install.bin")
require_uint "mtd5 backup size" "$MTD5_BACKUP_SIZE"
[ "$MTD5_BACKUP_SIZE" -gt 0 ] || { log "ERROR: mtd5 backup is empty"; exit 1; }
log "  mtd5_pre_install.bin: $MTD5_BACKUP_SIZE bytes sha256=$MTD5_LOCAL_SHA"

LIVE_BT=$(ssh_run "cat /etc/dcentos/board_target 2>/dev/null" | tr -d ' \t\r\n')
if [ -n "$LIVE_BT" ]; then
    BOARD_TARGET=$LIVE_BT
    BOARD_TARGET_SOURCE=live
else
    # Honesty: do not invent board_target from --variant / $BOARD_PKG_NAME.
    BOARD_TARGET=
    BOARD_TARGET_SOURCE=package
fi
log "  board_target='$BOARD_TARGET' board_target_source=$BOARD_TARGET_SOURCE package=$BOARD_PKG_NAME (record_s19k_backup_board_target)"
PROC_MTD=$(ssh_run "tr '\n' '|' < /proc/mtd" || true)
printf '%s\n' "$PROC_MTD" | tr '|' '\n' > "$ARTIFACT_DIR/proc_mtd.txt"
COMPUTED_MTD5_BASE=$(dcent_am3_mtd5_base_from_proc_mtd "$ARTIFACT_DIR/proc_mtd.txt" || true)
COMPUTED_ROOTFS_LOCAL=
COMPUTED_FLAG_LOCAL=
if [ -n "${COMPUTED_MTD5_BASE:-}" ]; then
    COMPUTED_ROOTFS_LOCAL=$(printf '0x%08X' $((DCENT_AM3_NANDROOTFS_GLOBAL - COMPUTED_MTD5_BASE)))
    COMPUTED_FLAG_LOCAL=$(printf '0x%08X' $((DCENT_AM3_RECOVERY_FLAG_GLOBAL - COMPUTED_MTD5_BASE)))
    if [ "$COMPUTED_MTD5_BASE" = "0x06100000" ]; then
        log "ERROR: computed mtd5 base 0x06100000 is size-sum without the 6MiB hole; refuse"
        exit 1
    fi
    if [ "$COMPUTED_ROOTFS_LOCAL" != "$DCENT_AM3_ROOTFS_OFFSET_HEX" ] || \
       [ "$COMPUTED_FLAG_LOCAL" != "$DCENT_AM3_RECOVERY_FLAG_OFFSET_HEX" ]; then
        log "ERROR: planned locals $DCENT_AM3_ROOTFS_OFFSET_HEX/$DCENT_AM3_RECOVERY_FLAG_OFFSET_HEX != computed $COMPUTED_ROOTFS_LOCAL/$COMPUTED_FLAG_LOCAL (base $COMPUTED_MTD5_BASE)"
        exit 1
    fi
    log "  computed mtd5_base=$COMPUTED_MTD5_BASE rootfs_local=$COMPUTED_ROOTFS_LOCAL flag_local=$COMPUTED_FLAG_LOCAL"
else
    log "ERROR: could not compute mtd5 base from /proc/mtd; refuse geometry-blind backup"
    exit 1
fi

# : rust InstallArm commit plan (geometry + FirstBosThenSetFlag2).
# Extra lines (e.g. dry_run=true) are appended. Does not write NAND.
write_install_commit_plan() {
    FLAG_HEX="$COMPUTED_FLAG_LOCAL"
    BASE_HEX="$COMPUTED_MTD5_BASE"
    ERASESIZE=${ROOTFS_ERASESIZE_EXPECTED:-131072}
    FLAG_DEC=$((FLAG_HEX))
    EB_INDEX=$((FLAG_DEC / ERASESIZE))
    EB_START=$((EB_INDEX * ERASESIZE))
    EB_OFF=$((FLAG_DEC % ERASESIZE))
    EB_START_HEX=$(printf '0x%08X' "$EB_START")
    EB_OFF_HEX=$(printf '0x%X' "$EB_OFF")
    {
        echo "schema=dcentos.amlogic-install-commit/v1"
        echo "intent=InstallArm"
        echo "value=0x01"
        echo "local_offset=$FLAG_HEX"
        echo "mtd5_base=$BASE_HEX"
        echo "target_mtd=5"
        echo "eraseblock_index=$EB_INDEX"
        echo "eraseblock_start=$EB_START_HEX"
        echo "byte_in_block=$EB_OFF_HEX"
        echo "erase_count=1"
        echo "rewriter=eraseblock_rewrite"
        echo "uboot_action=FirstBosThenSetFlag2"
        echo "firstboot=S99_WAL_companion_only"
        echo "bootcmd_reads_firstboot=false"
        echo "bootm_mtd2=false"
        echo "recover_to_stock=false"
        echo "nandwrite=false"
        echo "gpio_write=false"
        echo "execute=CLEAR_FOR_FLASH"
        echo "clear_for_flash=false"
        if [ -n "${1:-}" ]; then
            echo "$1"
        fi
    } > "$ARTIFACT_DIR/INSTALL_COMMIT_PLAN.txt"
}
dcent_am3_mtd5_covers_recovery "$MTD5_BACKUP_SIZE" "$COMPUTED_MTD5_BASE" || {
    log "ERROR: mtd5 backup shorter than recovery-flag/nandrecovery_env window"
    exit 1
}
# recover_to_stock imports this window, never nand_env.bak.
dcent_am3_extract_nandrecovery_env \
    "$ARTIFACT_DIR/mtd5_pre_install.bin" \
    "$COMPUTED_MTD5_BASE" \
    "$ARTIFACT_DIR/nandrecovery_env.bin" || {
    log "ERROR: failed to slice nandrecovery_env.bin from mtd5 backup"
    exit 1
}
NANDRECOVERY_ENV_SIZE=$(wc -c < "$ARTIFACT_DIR/nandrecovery_env.bin")
if [ "$NANDRECOVERY_ENV_SIZE" -ne $((DCENT_AM3_NANDRECOVERY_ENV_LEN)) ]; then
    log "ERROR: nandrecovery_env.bin size $NANDRECOVERY_ENV_SIZE != $DCENT_AM3_NANDRECOVERY_ENV_LEN"
    exit 1
fi
NANDRECOVERY_ENV_SHA=$(local_sha256 "$ARTIFACT_DIR/nandrecovery_env.bin")
COMPUTED_ENV_LOCAL=$(printf '0x%08X' $((DCENT_AM3_NANDRECOVERY_ENV_GLOBAL - COMPUTED_MTD5_BASE)))
if command -v py >/dev/null 2>&1; then
    NAND_ENV_CRC_PY=py
elif command -v python3 >/dev/null 2>&1; then
    NAND_ENV_CRC_PY=python3
else
    log "ERROR: py/python3 missing; cannot CRC-admit nandrecovery_env.bin"
    exit 1
fi
"$NAND_ENV_CRC_PY" -3 "$SCRIPT_DIR/s19k_nand_env_crc.py" "$ARTIFACT_DIR/nandrecovery_env.bin" \
    || "$NAND_ENV_CRC_PY" "$SCRIPT_DIR/s19k_nand_env_crc.py" "$ARTIFACT_DIR/nandrecovery_env.bin" \
    || { log "ERROR: nandrecovery_env.bin CRC32 mismatch"; exit 1; }
"$NAND_ENV_CRC_PY" -3 "$SCRIPT_DIR/s19k_nand_env_crc.py" "$ARTIFACT_DIR/nand_env.bak" \
    || "$NAND_ENV_CRC_PY" "$SCRIPT_DIR/s19k_nand_env_crc.py" "$ARTIFACT_DIR/nand_env.bak" \
    || { log "ERROR: nand_env.bak CRC32 mismatch"; exit 1; }
NANDRECOVERY_ENV_CRC_OK=true
NAND_ENV_CRC_OK=true
log "  nandrecovery_env.bin: $NANDRECOVERY_ENV_SIZE bytes sha256=$NANDRECOVERY_ENV_SHA local=$COMPUTED_ENV_LOCAL crc_ok=true"
{
    echo "schema=dcentos.amlogic-backup/v1"
    echo "board_target=$BOARD_TARGET"
    echo "board_target_source=$BOARD_TARGET_SOURCE"
    echo "board_target_package=$BOARD_PKG_NAME"
    echo "clear_for_flash=false"
    echo "gpio437_value=$GPIO437_VAL"
    echo "fw_printenv_present=$FW_PRINTENV_PRESENT"
    echo "nand_env=nand_env.bak"
    echo "mtd5_window=mtd5_pre_install.bin"
    echo "nandrecovery_env=nandrecovery_env.bin"
    echo "nandrecovery_env_local=$COMPUTED_ENV_LOCAL"
    echo "nandrecovery_env_sha256=$NANDRECOVERY_ENV_SHA"
    echo "nandrecovery_env_crc_ok=$NANDRECOVERY_ENV_CRC_OK"
    echo "nand_env_crc_ok=$NAND_ENV_CRC_OK"
    echo "nand_env_bak_is_not_nandrecovery_env=true"
    echo "nand_env_len=$NAND_ENV_SIZE"
    echo "mtd5_len=$MTD5_BACKUP_SIZE"
    echo "nand_env_sha256=$NAND_ENV_LOCAL_SHA"
    echo "mtd5_sha256=$MTD5_LOCAL_SHA"
    echo "fw_setenv_present=$FLASH_TOOLS_OK"
    echo "backup_tools_ok=true"
    echo "flash_tools_ok=$FLASH_TOOLS_OK"
    echo "braiins_success_is_not_stock_go=true"
    echo "l3_hint=Braiins AML image may lack fw_printenv/fw_setenv; backup nand_env+mtd5 is still required, env-flip/flash is refused"
    echo "proc_mtd=$PROC_MTD"
    echo "mtd5_name=$MTD5_NAME"
    echo "nandrootfs_global=$DCENT_AM3_NANDROOTFS_GLOBAL"
    echo "recovery_flag_global=$DCENT_AM3_RECOVERY_FLAG_GLOBAL"
    echo "recovery_flag_local=$DCENT_AM3_RECOVERY_FLAG_OFFSET_HEX"
    echo "rootfs_local=$DCENT_AM3_ROOTFS_OFFSET_HEX"
    echo "computed_mtd5_base=${COMPUTED_MTD5_BASE:-unknown}"
    echo "computed_rootfs_local=${COMPUTED_ROOTFS_LOCAL:-unknown}"
    echo "computed_flag_local=${COMPUTED_FLAG_LOCAL:-unknown}"
} > "$ARTIFACT_DIR/BACKUP_LEDGER.txt"
log "  BACKUP_LEDGER.txt written (CLEAR_FOR_FLASH=false)"

# : rust already formats recover-to-stock. The installer must emit
# the plan next to the CRC-admitted sidecar. Execute stays FLASH-refused.
{
    echo "schema=dcentos.amlogic-recover-to-stock/v1"
    echo "intent=UbootStockRevert"
    echo "flag_value=0x02"
    echo "flag_local=$COMPUTED_FLAG_LOCAL"
    echo "nandrecovery_env_local=$COMPUTED_ENV_LOCAL"
    echo "recover_env_source=nandrecovery_env.bin"
    echo "nand_env_bak_is_not_nandrecovery_env=true"
    echo "env_crc_ok=true"
    echo "step0=ImportNandrecoveryEnv"
    echo "step1=EraseNvdata"
    echo "step2=Reset"
    echo "nand_erase_part=nvdata"
    echo "bootm_mtd2=false"
    echo "uboot_recover_env=nand read + env import -d -c"
    echo "uboot_recover_to_stock=run recover_env; nand erase.part nvdata; reset"
    echo "execute=CLEAR_FOR_FLASH"
    echo "clear_for_flash=false"
} > "$ARTIFACT_DIR/RECOVER_TO_STOCK_PLAN.txt"
{
    echo "schema=dcentos.amlogic-recover-execute/v1"
    echo "execute=refused"
    echo "reason=CLEAR_FOR_FLASH"
    echo "clear_for_flash=false"
    echo "flag_value=0x02"
    echo "flag_local=$COMPUTED_FLAG_LOCAL"
    echo "nandrecovery_env_local=$COMPUTED_ENV_LOCAL"
    echo "recover_env_source=nandrecovery_env.bin"
    echo "recover_env_ram=0x01060000"
    echo "env_import_size=0x10000"
    echo "nandrecovery_env_offset=0x0B000000"
    echo "env_size=0x10000"
    echo "step0=ImportNandrecoveryEnv"
    echo "step1=EraseNvdata"
    echo "step2=Reset"
    echo "nand_erase_part=nvdata"
    echo "bootm_mtd2=false"
    echo "pass=admit_s19k_recover_execute_returns_ClearForFlashNotYet"
    echo "fail=nand_erase_or_env_import_without_admit"
} > "$ARTIFACT_DIR/RECOVER_EXECUTE_REFUSE.txt"
log "  RECOVER_TO_STOCK_PLAN.txt written (plan-only; flag 0x02 / nandrecovery_env)"
log "  RECOVER_EXECUTE_REFUSE.txt written (execute=refused reason=CLEAR_FOR_FLASH)"

# : a plan without a successful walk is not a backup artifact.
RECOVER_RUNNER="$SCRIPT_DIR/recover_amlogic_to_stock.sh"
if [ ! -r "$RECOVER_RUNNER" ]; then
    log "ERROR: missing $RECOVER_RUNNER; backup artifact is not walkable"
    exit 1
fi
if ! sh "$RECOVER_RUNNER" --artifact-dir "$ARTIFACT_DIR" --dry-run; then
    log "ERROR: recover-to-stock --dry-run failed; refusing successful backup"
    exit 1
fi
if [ ! -f "$ARTIFACT_DIR/RECOVER_WALK.txt" ]; then
    log "ERROR: recover-to-stock --dry-run did not write RECOVER_WALK.txt"
    exit 1
fi
log "  recover-to-stock --dry-run OK (RECOVER_WALK.txt; FLASH/NAND still refused)"

# : a backup without a walked 0x01 fixture is not InstallArm-ready.
FLAG_HELPER="$SCRIPT_DIR/s19k_write_recovery_flag.sh"
if [ ! -r "$FLAG_HELPER" ]; then
    log "ERROR: missing $FLAG_HELPER; backup artifact is not InstallArm-walkable"
    exit 1
fi
write_install_commit_plan "walk=flag_01_fixture"
dcent_am3_extract_recovery_flag_eraseblock \
    "$ARTIFACT_DIR/mtd5_pre_install.bin" \
    "$COMPUTED_MTD5_BASE" \
    "$ARTIFACT_DIR/recovery_flag_eb.bin" || {
    log "ERROR: failed to slice recovery_flag_eb.bin from mtd5 backup"
    exit 1
}
if ! sh "$FLAG_HELPER" --value 0x01 --mtd5-base "$COMPUTED_MTD5_BASE" \
    --fixture-in "$ARTIFACT_DIR/recovery_flag_eb.bin" \
    --fixture-out "$ARTIFACT_DIR/recovery_flag_eb.0x01.bin" \
    --verify-only > "$ARTIFACT_DIR/INSTALL_COMMIT_WALK.txt"; then
    log "ERROR: recovery-flag 0x01 fixture walk failed; refusing successful backup"
    exit 1
fi
if ! grep -q '^fixture_value=0x01$' "$ARTIFACT_DIR/INSTALL_COMMIT_WALK.txt"; then
    log "ERROR: 0x01 fixture walk did not write fixture_value=0x01"
    exit 1
fi
if [ ! -f "$ARTIFACT_DIR/recovery_flag_eb.0x01.bin" ]; then
    log "ERROR: 0x01 fixture-out missing after walk"
    exit 1
fi
FLAG_01_OUT="$ARTIFACT_DIR/recovery_flag_eb.0x01.bin"
FLAG_01_LEN=$(wc -c < "$FLAG_01_OUT" | tr -d ' \t')
if [ "$FLAG_01_LEN" -ne "$DCENT_AM3_ROOTFS_ERASESIZE_EXPECTED" ]; then
    log "ERROR: 0x01 fixture-out length $FLAG_01_LEN != $DCENT_AM3_ROOTFS_ERASESIZE_EXPECTED"
    exit 1
fi
FLAG_01_BYTE=$(od -An -tx1 -N1 "$FLAG_01_OUT" | tr -d ' \t\n')
if [ "$FLAG_01_BYTE" != "01" ]; then
    log "ERROR: 0x01 fixture-out byte0=$FLAG_01_BYTE (want 01); refusing successful backup"
    exit 1
fi
log "  recovery-flag 0x01 fixture walk OK (INSTALL_COMMIT_WALK.txt; byte0=01 len=$FLAG_01_LEN; FLASH/NAND still refused)"

if [ "$BACKUP_ONLY" = true ]; then
    log "[BACKUP-ONLY] nand_env+mtd5+gpio437 staged. FLASH not started."
    exit 0
fi

# --- Step 3: SCP tar + SHA256 verify -------------------------------------
# Stage on /data not /tmp -- sysupgrade tarball + extracted squashfs blow the
# 64 MB tmpfs at /tmp on S9 and leave little headroom on Amlogic /tmp either.
#.
log "Step 3/10: /data free-space preflight on $MINER_IP"
DATA_FREE_KB=$(ssh_run "df -Pk /data 2>/dev/null | awk 'NR==2 {print \$4}'")
case "$DATA_FREE_KB" in
    ''|*[!0-9]*) log "ERROR: could not determine /data free space (got '$DATA_FREE_KB')"; exit 1 ;;
esac
log "  /data free: $((DATA_FREE_KB / 1024)) MB"
if [ "$DATA_FREE_KB" -lt 51200 ]; then
    log "ERROR: /data has only $((DATA_FREE_KB / 1024)) MB free; need >= 50 MB for sysupgrade tar + extraction. Clear /data/dcentos-sysupgrade.tar and /data/sysupgrade/ first."
    exit 1
fi
DATA_WRITABLE=$(ssh_run "touch /data/.dcent_stage_check 2>/dev/null && rm -f /data/.dcent_stage_check && echo yes || echo no")
[ "$DATA_WRITABLE" = "yes" ] || { log "ERROR: /data not writable on $MINER_IP"; exit 1; }
log "Step 3/10: SCP $FIRMWARE -> /data/dcentos-sysupgrade.tar"
LOCAL_SHA=$(local_sha256 "$FIRMWARE")
[ -n "$LOCAL_SHA" ] || { log "ERROR: cannot compute local sha256"; exit 1; }
log "  local SHA256: $LOCAL_SHA"
cat > "$ARTIFACT_DIR/install_preflight_manifest.json" <<EOF
{
  "stage": "backup_verified",
  "miner_ip": "$MINER_IP",
  "platform": "$PLATFORM",
  "rootfs_mtd": "$ROOTFS_MTD",
  "rootfs_offset": "$ROOTFS_OFFSET_HEX",
  "rootfs_window": "$ROOTFS_WINDOW_HEX",
  "mtd5_name": "$MTD5_NAME",
  "mtd5_size": $MTD5_SIZE,
  "mtd5_erasesize": $MTD5_ERASESIZE,
  "nand_env_sha256": "$NAND_ENV_LOCAL_SHA",
  "mtd5_backup_sha256": "$MTD5_LOCAL_SHA",
  "firmware_sha256": "$LOCAL_SHA",
  "dry_run": $DRY_RUN
}
EOF
log "  recovery manifest: $ARTIFACT_DIR/install_preflight_manifest.json"

scp_put "$FIRMWARE" "/data/dcentos-sysupgrade.tar"
REMOTE_SHA=$(ssh_run "sha256sum /data/dcentos-sysupgrade.tar | awk '{print \$1}'")
log "  remote SHA256: $REMOTE_SHA"
[ "$LOCAL_SHA" = "$REMOTE_SHA" ] || { log "ERROR: SHA256 mismatch after upload"; exit 1; }

# --- Step 4: extract + verify SHA256SUMS + validate MANIFEST -------------
log "Step 4/10: extract tar + verify SHA256SUMS + check MANIFEST.json"
ssh_run 'rm -rf /data/sysupgrade && mkdir -p /data/sysupgrade && cd /data/sysupgrade && tar xf /data/dcentos-sysupgrade.tar'
ssh_run "cd '$REMOTE_PREFIX' && sha256sum -c SHA256SUMS" \
    || { log "ERROR: SHA256SUMS check failed on target"; exit 1; }

BOARD=$(ssh_run "grep -o '\"board\":[[:space:]]*\"[^\"]*\"' '$REMOTE_PREFIX/MANIFEST.json' | head -1")
log "  manifest: $BOARD"
echo "$BOARD" | grep -q "$BOARD_PKG_NAME" || { log "ERROR: MANIFEST board != $BOARD_PKG_NAME"; exit 1; }

# --- Step 4b: in-band ed25519 re-verify (defense-in-depth, sentinel-gated) ----
# wf_c00e5d9e: if the on-device DCENT_OS exposes the verify-bundle capability
# sentinel (dropped by a verb-capable dcentrald at startup -- see main.rs), use its
# OWN pinned-key ed25519 verifier to re-check the INCOMING bundle ON-DEVICE before
# flashing -- defense-in-depth against a compromised install host. The normal case
# is already gated by host-side ed25519 + the on-device SHA256SUMS + MANIFEST checks
# above; this adds the on-device signature authority. The sentinel GUARANTEES the
# verb exists, so invoking it is SAFE (no risk of starting the daemon on a pre-verb
# binary -- the probe-safety problem). Skips gracefully when absent (fresh
# stock->DCENT_OS install, or a dcentrald predating the verb). A failed verify
# ABORTS before any flash (fail-closed).
if ssh_run "[ -f /data/dcentos/caps/verify-bundle ]"; then
    DCENTRALD_BIN=$(ssh_run "command -v dcentrald 2>/dev/null || echo /usr/bin/dcentrald")
    log "Step 4b/10: in-band ed25519 re-verify via on-device $DCENTRALD_BIN --verify-bundle"
    if ssh_run "'$DCENTRALD_BIN' --verify-bundle '$REMOTE_PREFIX'"; then
        log "  in-band ed25519 signature + MANIFEST verified on-device (known-good binary verified the incoming bundle)"
    else
        log "ERROR: in-band ed25519 re-verify FAILED -- aborting before flash (on-device verifier rejected the bundle)"
        exit 1
    fi
else
    log "Step 4b/10: in-band ed25519 re-verify SKIPPED -- no verify-bundle capability sentinel on-device (host-side ed25519 + on-device SHA256SUMS + MANIFEST already verified this bundle)"
fi

ROOT_SIZE=$(ssh_run "stat -c %s '$REMOTE_PREFIX/root'")
require_uint "root payload size" "$ROOT_SIZE"
if [ "$ROOT_SIZE" -gt "$ROOTFS_WINDOW_DEC" ]; then
    log "ERROR: root payload $ROOT_SIZE exceeds rootfs window $ROOTFS_WINDOW_DEC"
    exit 1
fi
ROOT_SHA=$(ssh_run "sha256sum '$REMOTE_PREFIX/root' | awk '{print \$1}'")
log "  root payload: $ROOT_SIZE bytes (expect ~25.6 MB)"
KERNEL_SIZE=$(ssh_run "stat -c %s '$REMOTE_PREFIX/kernel'")
require_uint "kernel payload size" "$KERNEL_SIZE"
KERNEL_SHA=$(ssh_run "sha256sum '$REMOTE_PREFIX/kernel' | awk '{print \$1}'")
log "  kernel payload: $KERNEL_SIZE bytes (expect ~16.5 MB)"
cat > "$ARTIFACT_DIR/install_preflight_manifest.json" <<EOF
{
  "stage": "payload_verified",
  "miner_ip": "$MINER_IP",
  "platform": "$PLATFORM",
  "rootfs_mtd": "$ROOTFS_MTD",
  "rootfs_offset": "$ROOTFS_OFFSET_HEX",
  "rootfs_window": "$ROOTFS_WINDOW_HEX",
  "mtd5_name": "$MTD5_NAME",
  "mtd5_size": $MTD5_SIZE,
  "mtd5_erasesize": $MTD5_ERASESIZE,
  "nand_env_size": $NAND_ENV_SIZE,
  "nand_env_sha256": "$NAND_ENV_LOCAL_SHA",
  "mtd5_backup_size": $MTD5_BACKUP_SIZE,
  "mtd5_backup_sha256": "$MTD5_LOCAL_SHA",
  "firmware_sha256": "$LOCAL_SHA",
  "remote_firmware_sha256": "$REMOTE_SHA",
  "package_board": "$BOARD_PKG_NAME",
  "root_payload_size": $ROOT_SIZE,
  "root_payload_sha256": "$ROOT_SHA",
  "kernel_payload_size": $KERNEL_SIZE,
  "kernel_payload_sha256": "$KERNEL_SHA",
  "dry_run": $DRY_RUN
}
EOF
log "  recovery manifest updated with payload hashes"

# --- Step 5: dry-run halts here ------------------------------------------
if [ "$DRY_RUN" = true ]; then
    log "[DRY RUN] preflight + backup + SHA256 + manifest + extract OK"
    log "[DRY RUN] mining services were not stopped."
    log "[DRY RUN] would now: GPIO437 SafeOff (SKU-scoped; s19kpro=1), flash_erase $ROOTFS_MTD $ROOTFS_OFFSET_HEX, nandwrite root, readback SHA verify, recovery-flag 0x01 eraseblock_rewrite (InstallArm; firstboot is S99 WAL companion only, not bootcmd), reboot"
    write_install_commit_plan "dry_run=true"
    {
        echo "schema=dcentos.amlogic-install-payload/v1"
        echo "nandwrite_target=root"
        echo "rootfs_local=$DCENT_AM3_ROOTFS_OFFSET_HEX"
        echo "rootfs_window=$DCENT_AM3_ROOTFS_WINDOW_HEX"
        echo "package_kernel_nandwrite=false"
        echo "nandrecovery_env_local=$COMPUTED_ENV_LOCAL"
        echo "recovery_flag_local=$COMPUTED_FLAG_LOCAL"
        echo "clear_for_flash=false"
        echo "dry_run=true"
    } > "$ARTIFACT_DIR/INSTALL_PAYLOAD_PLAN.txt"
    log "[DRY RUN] wrote $ARTIFACT_DIR/INSTALL_COMMIT_PLAN.txt (refusing firstboot-only)"
    log "[DRY RUN] wrote $ARTIFACT_DIR/INSTALL_PAYLOAD_PLAN.txt (root-window-only; kernel not nandwritten)"
    log "[DRY RUN] no destructive action taken. Exiting."
    exit 0
fi

# : rust admit_s19k_flash is ClearForFlashNotYet. This shell must not
# nandwrite / fw_setenv while that pin is false. --backup-only and --dry-run
# already exited. Do not treat --yes as a flash override.
CLEAR_FOR_FLASH=false
if [ "$CLEAR_FOR_FLASH" != true ]; then
    log "ERROR: CLEAR_FOR_FLASH=false — refusing flash_erase/nandwrite/fw_setenv. Backup is staged. FLASH NOT_YET. Use --backup-only."
    log "recover_execute=refused reason=CLEAR_FOR_FLASH pass=admit_s19k_recover_execute_returns_ClearForFlashNotYet"
    log "install_commit=recovery-flag 0x01 eraseblock_rewrite (InstallArm); refusing firstboot-only"
    write_install_commit_plan
    exit 1
fi

# --- Step 6: destructive confirmation gate -------------------------------
if [ "$SKIP_CONFIRM" != true ]; then
    cat >&2 <<EOF

  *** DESTRUCTIVE OPERATION ***
  About to flash DCENT_OS to $MINER_IP ${ROOTFS_MTD} LOCAL offset ${ROOTFS_OFFSET_HEX}.
  Backup of pre-state is in: $ARTIFACT_DIR
  Recovery: flag 0x02 arms recover_to_stock (env restore + erase nvdata), not a direct mtd2 bootm.
  Type YES (uppercase) to proceed:
EOF
    read -r CONFIRM
    [ "$CONFIRM" = "YES" ] || { log "User declined. Exiting."; exit 1; }
fi

# --- Step 7: stop bosminer cleanly ---------------------------------------
log "Step 7/10: stop bosminer/boser/bos-tools (after confirmation, graceful TERM, then KILL)"
ssh_run 'for p in bos-tools bosminer boser; do
    pid=$(pidof $p 2>/dev/null || true)
    [ -n "$pid" ] && kill -TERM $pid 2>/dev/null || true
done; sleep 5
for p in bos-tools bosminer boser; do
    pid=$(pidof $p 2>/dev/null || true)
    [ -n "$pid" ] && kill -9 $pid 2>/dev/null || true
done; true'


# --- Step 7b: GPIO437 SafeOff before any NAND slot/rootfs mutation -------
# SKU-scoped polarity (T6 2026-08-12). Never invent auto-detect.
#   s19kpro / s19k: am3-s19k-active-low — 0=ON, SafeOff=1 (DISABLE).
#                   Driving 0 ENGAGES rails. Default VARIANT is s19kpro.
#   other AML (S21-family / RE-4C): active HIGH — 1=ON, SafeOff=0.
# Identity was proven by require_exact_amlogic_variant; refuse if VARIANT
# polarity would disagree with a proven s21/s19k board_target.
case "$VARIANT" in
    s19kpro|s19k)
        GPIO437_SAFE_OFF=1
        GPIO437_SAFE_DIR=high
        GPIO437_POLARITY=am3-s19k-active-low
        ;;
    *)
        GPIO437_SAFE_OFF=0
        GPIO437_SAFE_DIR=low
        GPIO437_POLARITY=re4c-active-high
        ;;
esac
log "Step 7b/10: GPIO437 PWR_EN SafeOff (variant=$VARIANT polarity=$GPIO437_POLARITY value=$GPIO437_SAFE_OFF) before NAND mutation"
ssh_run "PWR_GPIO=437
SAFE_OFF=$GPIO437_SAFE_OFF
SAFE_DIR=$GPIO437_SAFE_DIR
SYS=/sys/class/gpio
if [ ! -d \"\$SYS/gpio\$PWR_GPIO\" ]; then
  echo \"\$PWR_GPIO\" > \"\$SYS/export\" 2>/dev/null || true
fi
[ -d \"\$SYS/gpio\$PWR_GPIO\" ] || { echo \"ERROR: gpio\$PWR_GPIO missing after export\" >&2; exit 1; }
echo 0 > \"\$SYS/gpio\$PWR_GPIO/active_low\"
echo \"\$SAFE_DIR\" > \"\$SYS/gpio\$PWR_GPIO/direction\"
echo \"\$SAFE_OFF\" > \"\$SYS/gpio\$PWR_GPIO/value\"
AL=\$(cat \"\$SYS/gpio\$PWR_GPIO/active_low\")
DIR=\$(cat \"\$SYS/gpio\$PWR_GPIO/direction\")
VAL=\$(cat \"\$SYS/gpio\$PWR_GPIO/value\")
[ \"\$AL\" = \"0\" ] || { echo \"ERROR: gpio437 active_low=\$AL (want 0)\" >&2; exit 1; }
[ \"\$DIR\" = \"out\" ] || { echo \"ERROR: gpio437 direction=\$DIR (want out)\" >&2; exit 1; }
[ \"\$VAL\" = \"\$SAFE_OFF\" ] || { echo \"ERROR: gpio437 value=\$VAL after SafeOff (want \$SAFE_OFF)\" >&2; exit 1; }
echo \"gpio437 SafeOff OK polarity=$GPIO437_POLARITY active_low=\$AL direction=\$DIR value=\$VAL\"
" \
    || { log "ERROR: GPIO437 SafeOff failed — refusing NAND mutation"; exit 1; }
log "  GPIO437 SafeOff verified (polarity=$GPIO437_POLARITY value=$GPIO437_SAFE_OFF)"

# --- Step 8: flash_erase + nandwrite -------------------------------------
log "Step 8/10: flash_erase $ROOTFS_MTD $ROOTFS_OFFSET_HEX $ROOTFS_ERASE_COUNT  (${ROOTFS_ERASE_COUNT} erase blocks of ${ROOTFS_ERASESIZE_EXPECTED} bytes)"
ssh_run "flash_erase $ROOTFS_MTD $ROOTFS_OFFSET_HEX $ROOTFS_ERASE_COUNT" || { log "ERROR: flash_erase failed"; exit 1; }

log "Step 9/10: nandwrite -p -s $ROOTFS_OFFSET_HEX $ROOTFS_MTD root  ($ROOT_SIZE bytes)"
ssh_run "nandwrite -p -s $ROOTFS_OFFSET_HEX $ROOTFS_MTD '$REMOTE_PREFIX/root'" \
    || { log "ERROR: nandwrite failed"; exit 1; }

log "Step 9b/10: readback verify written rootfs SHA256"
READBACK_SHA=$(ssh_run "nanddump --bb=skipbad -s $ROOTFS_OFFSET_HEX -l $ROOT_SIZE -q -f /tmp/dcentos_root_readback.uimage $ROOTFS_MTD >/dev/null 2>&1 && sha256sum /tmp/dcentos_root_readback.uimage | awk '{print \$1}'")
scp_get "/tmp/dcentos_root_readback.uimage" "$ARTIFACT_DIR/root_write_readback.uimage"
ssh_run "rm -f /tmp/dcentos_root_readback.uimage"
LOCAL_READBACK_SHA=$(local_sha256 "$ARTIFACT_DIR/root_write_readback.uimage")
[ "$READBACK_SHA" = "$ROOT_SHA" ] && [ "$LOCAL_READBACK_SHA" = "$ROOT_SHA" ] || {
    log "ERROR: rootfs readback SHA mismatch: expected $ROOT_SHA got remote $READBACK_SHA local $LOCAL_READBACK_SHA"
    log "Backup is retained at $ARTIFACT_DIR; firstboot was not set and reboot was not triggered."
    exit 1
}
log "  rootfs readback verified: $READBACK_SHA"

# --- Step 10: install commit is recovery-flag 0x01, not firstboot --------
# .78 bootcmd never reads firstboot. firstboot is S99 WAL companion only.
log "Step 10/10: recovery-flag 0x01 eraseblock_rewrite (InstallArm); refusing firstboot-only"
write_install_commit_plan
log "ERROR: refusing firstboot-only install commit; flag 0x01 rewrite stays operator-authorized"
log "Backup retained at: $ARTIFACT_DIR (INSTALL_COMMIT_PLAN.txt written)"
exit 1
log "If install fails: flag 0x02 arms recover_to_stock (not a direct mtd2 bootm)."
