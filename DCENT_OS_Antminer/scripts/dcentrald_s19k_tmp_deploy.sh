#!/bin/sh
# Reproducible Braiins Track-1 /tmp deploy for S19k Pro (am3-s19k).
# Stages armv7 musleabihf dcentrald, observes GPIO437, does not flash.
#
# Usage:
#   ./scripts/dcentrald_s19k_tmp_deploy.sh [--dry-run] [--allow-loud] \
#     [--handoff-no-work | --bounded-work-proof | --mining-on-passthrough | \
#      --endurance-work-proof --endurance-baseline FILE] \
#     [--expected-artifact-sha256 HEX --expected-artifact-bytes N] \
#     [--known-hosts FILE --expected-host-key-sha256 SHA256:...] \
#     <miner_ip> <dcentrald_armv7_binary> [config.toml]
# Artifact custody is defined only by the tracked S19k campaign manifest plus
# the operator-selected exact digest/byte pins. A mutable target/ build output
# is never a deployable artifact.
#
# Rails: the runner passes the exact Braiins run-and-watch supervisor+bosminer
# process tree to dcentrald.  dcentrald arms the watchdog, kills the supervisor
# before its child, and owns exit+GPIO437 handoff before UART.
# `/etc/init.d/S99bosminer stop` remains forbidden because it cuts rails.
# Mining stays disabled in the default config. Dual ttyS1+ttyS2 is required.

set -eu
umask 077
DRY_RUN=false
ALLOW_LOUD=false
HANDOFF_NO_WORK=false
BOUNDED_WORK_PROOF=false
ENDURANCE_WORK_PROOF=false
MINING_ON_PASSTHROUGH=false
ENDURANCE_BASELINE=
KNOWN_HOSTS=${DCENT_SSH_KNOWN_HOSTS:-}
EXPECTED_HOST_KEY_SHA256=${DCENT_EXPECTED_HOST_KEY_SHA256:-}
EXPECTED_ARTIFACT_SHA256=${DCENT_S19K_EXPECTED_ARTIFACT_SHA256:-}
EXPECTED_ARTIFACT_BYTES=${DCENT_S19K_EXPECTED_ARTIFACT_BYTES:-}
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --allow-loud) ALLOW_LOUD=true; shift ;;
    --handoff-no-work) HANDOFF_NO_WORK=true; shift ;;
    --bounded-work-proof) BOUNDED_WORK_PROOF=true; shift ;;
    --endurance-work-proof) ENDURANCE_WORK_PROOF=true; shift ;;
    --mining-on-passthrough) MINING_ON_PASSTHROUGH=true; shift ;;
    --endurance-baseline) ENDURANCE_BASELINE=${2:?--endurance-baseline requires a file}; shift 2 ;;
    --known-hosts) KNOWN_HOSTS=${2:?--known-hosts requires a file}; shift 2 ;;
    --expected-artifact-sha256)
      EXPECTED_ARTIFACT_SHA256=${2:?--expected-artifact-sha256 requires a SHA-256 digest}
      shift 2
      ;;
    --expected-artifact-bytes)
      EXPECTED_ARTIFACT_BYTES=${2:?--expected-artifact-bytes requires a positive byte count}
      shift 2
      ;;
    --expected-host-key-sha256)
      EXPECTED_HOST_KEY_SHA256=${2:?--expected-host-key-sha256 requires an OpenSSH SHA256 fingerprint}
      shift 2
      ;;
    *) break ;;
  esac
done
MINER_IP=${1:?miner_ip}
BIN_SOURCE=${2:?dcentrald_binary}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CFG_SOURCE=${3:-"$ROOT/dcentrald/dcentrald_s19k.toml"}
REMOTE_RUN_HELPER_SOURCE="$ROOT/scripts/dcentrald_s19k_tmp_remote_run.sh"
SUPERVISOR_CUSTODY_SOURCE="$ROOT/scripts/dcentrald_s19k_braiins_supervisor_custody.sh"
STOCK_RESTART_HELPER_SOURCE="$ROOT/scripts/dcentrald_s19k_stock_restart_from_safeoff.sh"
BUILD_ARTIFACT_VERIFIER_SOURCE="$ROOT/scripts/s19k_tmp_build_artifact.py"
ENDURANCE_COLLECTOR_SOURCE="$ROOT/scripts/s19k_endurance_collect.py"
ENDURANCE_VERIFIER_SOURCE="$ROOT/scripts/s19k_endurance_verify.py"
ENDURANCE_BASELINE_BUILDER_SOURCE="$ROOT/scripts/s19k_endurance_baseline.py"
BOUNDED_TRANSCRIPT_VERIFIER_SOURCE="$ROOT/scripts/s19k_bounded_transcript_verify.py"
NO_WORK_VERIFIER_SOURCE="$ROOT/scripts/s19k_no_work_verify.py"
PHASE12_NORMALIZER_SOURCE="$ROOT/scripts/s19k_phase12_normalize.py"
PHASE3_PHYSICAL_VERIFIER_SOURCE="$ROOT/scripts/s19k_phase3_physical_verify.py"
ENDURANCE_BASELINE_SOURCE=$ENDURANCE_BASELINE

for INPUT in "$BIN_SOURCE" "$CFG_SOURCE" "$REMOTE_RUN_HELPER_SOURCE" \
  "$SUPERVISOR_CUSTODY_SOURCE" "$STOCK_RESTART_HELPER_SOURCE" \
  "$BUILD_ARTIFACT_VERIFIER_SOURCE" "$ENDURANCE_COLLECTOR_SOURCE" \
  "$ENDURANCE_VERIFIER_SOURCE" "$ENDURANCE_BASELINE_BUILDER_SOURCE" \
  "$BOUNDED_TRANSCRIPT_VERIFIER_SOURCE" "$NO_WORK_VERIFIER_SOURCE" \
  "$PHASE12_NORMALIZER_SOURCE" "$PHASE3_PHYSICAL_VERIFIER_SOURCE"; do
  test -f "$INPUT" && test ! -L "$INPUT" || {
    echo "ERROR: deploy input must be a regular non-symlink file: $INPUT" >&2
    exit 1
  }
done
if [ "$ENDURANCE_WORK_PROOF" = true ]; then
  [ -n "$ENDURANCE_BASELINE" ] && [ -f "$ENDURANCE_BASELINE" ] && [ ! -L "$ENDURANCE_BASELINE" ] || {
    echo "ERROR: --endurance-work-proof requires a regular non-symlink --endurance-baseline file" >&2
    exit 1
  }
elif [ -n "$ENDURANCE_BASELINE" ]; then
  echo "ERROR: --endurance-baseline is valid only with --endurance-work-proof" >&2
  exit 1
fi

# Freeze every target and host-verifier input before parsing, hashing, or copying. This makes
# the plan and the bytes sent by scp one transaction instead of mutable reads of
# mutable caller paths.
HOST_STAGE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/dcent-s19k-deploy.XXXXXX") || {
  echo "ERROR: could not allocate private local deploy snapshot" >&2
  exit 1
}
cleanup_host_stage() {
  rm -f "$HOST_STAGE_DIR/dcentrald" "$HOST_STAGE_DIR/dcentrald_s19k.toml" \
    "$HOST_STAGE_DIR/run_trial" "$HOST_STAGE_DIR/supervisor_custody_observer" \
    "$HOST_STAGE_DIR/stock_restart_helper" \
    "$HOST_STAGE_DIR/s19k_tmp_build_artifact.py" \
    "$HOST_STAGE_DIR/s19k_endurance_collect.py" \
    "$HOST_STAGE_DIR/s19k_endurance_verify.py" \
    "$HOST_STAGE_DIR/s19k_endurance_baseline.py" \
    "$HOST_STAGE_DIR/s19k_bounded_transcript_verify.py" \
    "$HOST_STAGE_DIR/s19k_no_work_verify.py" \
    "$HOST_STAGE_DIR/s19k_phase12_normalize.py" \
    "$HOST_STAGE_DIR/s19k_phase3_physical_verify.py" \
    "$HOST_STAGE_DIR/endurance_baseline.kv" \
    2>/dev/null || true
  rmdir "$HOST_STAGE_DIR" 2>/dev/null || true
}
trap cleanup_host_stage 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15
cp -p "$BIN_SOURCE" "$HOST_STAGE_DIR/dcentrald"
cp -p "$CFG_SOURCE" "$HOST_STAGE_DIR/dcentrald_s19k.toml"
cp -p "$REMOTE_RUN_HELPER_SOURCE" "$HOST_STAGE_DIR/run_trial"
cp -p "$SUPERVISOR_CUSTODY_SOURCE" "$HOST_STAGE_DIR/supervisor_custody_observer"
cp -p "$STOCK_RESTART_HELPER_SOURCE" "$HOST_STAGE_DIR/stock_restart_helper"
cp -p "$BUILD_ARTIFACT_VERIFIER_SOURCE" "$HOST_STAGE_DIR/s19k_tmp_build_artifact.py"
cp -p "$ENDURANCE_COLLECTOR_SOURCE" "$HOST_STAGE_DIR/s19k_endurance_collect.py"
cp -p "$ENDURANCE_VERIFIER_SOURCE" "$HOST_STAGE_DIR/s19k_endurance_verify.py"
cp -p "$ENDURANCE_BASELINE_BUILDER_SOURCE" "$HOST_STAGE_DIR/s19k_endurance_baseline.py"
cp -p "$BOUNDED_TRANSCRIPT_VERIFIER_SOURCE" "$HOST_STAGE_DIR/s19k_bounded_transcript_verify.py"
cp -p "$NO_WORK_VERIFIER_SOURCE" "$HOST_STAGE_DIR/s19k_no_work_verify.py"
cp -p "$PHASE12_NORMALIZER_SOURCE" "$HOST_STAGE_DIR/s19k_phase12_normalize.py"
cp -p "$PHASE3_PHYSICAL_VERIFIER_SOURCE" "$HOST_STAGE_DIR/s19k_phase3_physical_verify.py"
[ "$ENDURANCE_WORK_PROOF" != true ] || cp -p "$ENDURANCE_BASELINE" "$HOST_STAGE_DIR/endurance_baseline.kv"
BIN="$HOST_STAGE_DIR/dcentrald"
CFG="$HOST_STAGE_DIR/dcentrald_s19k.toml"
REMOTE_RUN_HELPER="$HOST_STAGE_DIR/run_trial"
SUPERVISOR_CUSTODY="$HOST_STAGE_DIR/supervisor_custody_observer"
STOCK_RESTART_HELPER="$HOST_STAGE_DIR/stock_restart_helper"
BUILD_ARTIFACT_VERIFIER="$HOST_STAGE_DIR/s19k_tmp_build_artifact.py"
ENDURANCE_COLLECTOR="$HOST_STAGE_DIR/s19k_endurance_collect.py"
ENDURANCE_VERIFIER="$HOST_STAGE_DIR/s19k_endurance_verify.py"
[ "$ENDURANCE_WORK_PROOF" != true ] || ENDURANCE_BASELINE="$HOST_STAGE_DIR/endurance_baseline.kv"

# L1: path triple is not enough — refuse ELF64 / AArch64 / non-ELF (admit_s19k_armhf_elf).
# Paths and filenames are not architecture evidence; parse every artifact.
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v py >/dev/null 2>&1; then
  PY="py -3"
else
  echo "ERROR: python3/py required to admit ELF32 ARM header" >&2
  exit 1
fi
ADMIT_OUT=$($PY - "$BIN" <<'PY'
import sys
path = sys.argv[1]
try:
    blob = open(path, "rb").read()
except OSError as exc:
    print("ERROR: cannot read ELF:", exc, file=sys.stderr)
    sys.exit(1)
if len(blob) < 52 or blob[:4] != b"\x7fELF" or blob[4] != 1:
    print("ERROR: admit_s19k_armhf_elf refused — not ELF32 (Track 1 Braiins userspace is armhf)", file=sys.stderr)
    sys.exit(1)
if blob[5] != 1 or blob[6] != 1:
    print("ERROR: admit_s19k_armhf_musl_static refused — not LSB", file=sys.stderr)
    sys.exit(1)
elf_type = int.from_bytes(blob[16:18], "little")
if elf_type not in (2, 3):
    print("ERROR: admit_s19k_armhf_elf refused - not ET_EXEC/ET_DYN", file=sys.stderr)
    sys.exit(1)
machine = int.from_bytes(blob[18:20], "little")
if machine != 40:
    print("ERROR: admit_s19k_armhf_elf refused — e_machine=%s (want EM_ARM=40, not AArch64=183)" % machine, file=sys.stderr)
    sys.exit(1)
if int.from_bytes(blob[20:24], "little") != 1:
    print("ERROR: admit_s19k_armhf_elf refused - unsupported ELF version", file=sys.stderr)
    sys.exit(1)
entry = int.from_bytes(blob[24:28], "little")
if entry == 0:
    print("ERROR: admit_s19k_armhf_elf refused - zero entry point", file=sys.stderr)
    sys.exit(1)
flags = int.from_bytes(blob[36:40], "little")
if flags & 0xff000000 != 0x05000000 or flags & 0x400 == 0:
    print("ERROR: admit_s19k_armhf_musl_static refused — require ARM EABI5 and hard_float EF_ARM_ABI_FLOAT_HARD", file=sys.stderr)
    sys.exit(1)
phoff = int.from_bytes(blob[28:32], "little")
ehsize = int.from_bytes(blob[40:42], "little")
phentsize = int.from_bytes(blob[42:44], "little")
phnum = int.from_bytes(blob[44:46], "little")
if ehsize != 52 or phentsize != 32 or phnum in (0, 0xffff):
    print("ERROR: admit_s19k_armhf_elf refused - invalid ELF32/program-header geometry", file=sys.stderr)
    sys.exit(1)
if phoff < 52 or phoff + phentsize * phnum > len(blob):
    print("ERROR: admit_s19k_armhf_elf refused - program-header table outside file", file=sys.stderr)
    sys.exit(1)
interp = None
entry_in_executable_load = False
for i in range(phnum):
    off = phoff + i * phentsize
    if len(blob) < off + 20:
        print("ERROR: admit_s19k_armhf_musl_static refused — truncated program headers", file=sys.stderr)
        sys.exit(1)
    p_type = int.from_bytes(blob[off:off+4], "little")
    p_offset = int.from_bytes(blob[off+4:off+8], "little")
    p_vaddr = int.from_bytes(blob[off+8:off+12], "little")
    p_filesz = int.from_bytes(blob[off+16:off+20], "little")
    p_memsz = int.from_bytes(blob[off+20:off+24], "little")
    p_flags = int.from_bytes(blob[off+24:off+28], "little")
    if p_type == 1:
        if p_filesz > p_memsz or p_offset + p_filesz > len(blob):
            print("ERROR: admit_s19k_armhf_elf refused - PT_LOAD outside file", file=sys.stderr)
            sys.exit(1)
        if p_flags & 1 and p_vaddr <= entry < p_vaddr + p_filesz:
            entry_in_executable_load = True
    if p_type != 3:
        continue
    if p_filesz == 0 or p_offset + p_filesz > len(blob):
        print("ERROR: admit_s19k_armhf_musl_static refused - PT_INTERP outside file", file=sys.stderr)
        sys.exit(1)
    raw = blob[p_offset:p_offset+p_filesz]
    interp = raw.split(b"\x00", 1)[0].decode("ascii", "replace")
if not entry_in_executable_load:
    print("ERROR: admit_s19k_armhf_elf refused - entry point is not in file-backed executable PT_LOAD", file=sys.stderr)
    sys.exit(1)
if interp:
    if "ld-linux" in interp:
        print("ERROR: admit_s19k_armhf_musl_static refused — glibc ld-linux interp", file=sys.stderr)
        sys.exit(1)
    print("ERROR: admit_s19k_armhf_musl_static refused — PT_INTERP=%s (static musl only)" % interp, file=sys.stderr)
    sys.exit(1)
import hashlib
print("SHA256=" + hashlib.sha256(blob).hexdigest())
print("BYTES=%d" % len(blob))
print("ELF32 ARM musl-static admitted (class=1 machine=40 arm_eabi=5 hard_float=1 pt_interp=none)")
PY
)
# The build-lane verifier is the authoritative artifact contract. Keep the
# historical inline parser as a compatibility precheck, but never let its
# narrower checks mint `musl_static=true`: the shared verifier additionally
# rejects EF_ARM_ABI_FLOAT_SOFT and any PT_DYNAMIC DT_NEEDED entry.
ADMIT_OUT=$($PY "$BUILD_ARTIFACT_VERIFIER" verify-elf "$BIN")
echo "$ADMIT_OUT"
LOCAL_SHA=$(printf '%s\n' "$ADMIT_OUT" | sed -n 's/^SHA256=//p' | head -n 1)
LOCAL_BYTES=$(printf '%s\n' "$ADMIT_OUT" | sed -n 's/^BYTES=//p' | head -n 1)
case "$LOCAL_SHA" in
  [0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]*) ;;
  *)
    echo "ERROR: local SHA256 missing after ELF admit" >&2
    exit 1
    ;;
esac
test -n "$LOCAL_BYTES" && [ "$LOCAL_BYTES" -gt 0 ] || {
  echo "ERROR: local BYTES missing after ELF admit" >&2
  exit 1
}

# A sealed live transaction must name the candidate the operator intended, not
# merely record whichever valid ARM ELF happened to occupy a mutable build
# output path.  Authority-bearing dry runs use the same requirement so their
# plans cannot be mistaken for exact no-work/bounded/endurance admissions.
if { [ -n "$EXPECTED_ARTIFACT_SHA256" ] && [ -z "$EXPECTED_ARTIFACT_BYTES" ]; } || \
   { [ -z "$EXPECTED_ARTIFACT_SHA256" ] && [ -n "$EXPECTED_ARTIFACT_BYTES" ]; }; then
  echo "ERROR: expected artifact SHA-256 and byte count must be supplied together" >&2
  exit 1
fi
if [ "$DRY_RUN" != true ] || [ "$HANDOFF_NO_WORK" = true ] || \
   [ "$BOUNDED_WORK_PROOF" = true ] || [ "$ENDURANCE_WORK_PROOF" = true ]; then
  [ -n "$EXPECTED_ARTIFACT_SHA256" ] && [ -n "$EXPECTED_ARTIFACT_BYTES" ] || {
    echo "ERROR: exact sealed artifact authority requires --expected-artifact-sha256 and --expected-artifact-bytes" >&2
    exit 1
  }
fi
if [ -n "$EXPECTED_ARTIFACT_SHA256" ]; then
  printf '%s\n' "$EXPECTED_ARTIFACT_SHA256" | grep -Eq '^[0-9a-fA-F]{64}$' || {
    echo "ERROR: --expected-artifact-sha256 must be exactly 64 hexadecimal characters" >&2
    exit 1
  }
  printf '%s\n' "$EXPECTED_ARTIFACT_BYTES" | grep -Eq '^[1-9][0-9]*$' || {
    echo "ERROR: --expected-artifact-bytes must be a positive canonical decimal integer" >&2
    exit 1
  }
  EXPECTED_ARTIFACT_SHA256=$(printf '%s' "$EXPECTED_ARTIFACT_SHA256" | tr 'A-F' 'a-f')
  [ "$LOCAL_SHA" = "$EXPECTED_ARTIFACT_SHA256" ] && \
    [ "$LOCAL_BYTES" = "$EXPECTED_ARTIFACT_BYTES" ] || {
      echo "ERROR: selected artifact does not match exact sealed operator authority" >&2
      echo "  expected sha256=$EXPECTED_ARTIFACT_SHA256 bytes=$EXPECTED_ARTIFACT_BYTES" >&2
      echo "  observed sha256=$LOCAL_SHA bytes=$LOCAL_BYTES" >&2
      exit 1
    }
  ARTIFACT_OPERATOR_PIN=required-and-matched
else
  ARTIFACT_OPERATOR_PIN=not-supplied-stage-only-dry-run
  EXPECTED_ARTIFACT_SHA256=not-supplied
  EXPECTED_ARTIFACT_BYTES=not-supplied
fi

CONFIG_ADMIT_OUT=$($PY - "$CFG" <<'PY'
import sys
try:
    import tomllib
except ImportError:
    tomllib = None
try:
    if tomllib is not None:
        with open(sys.argv[1], "rb") as handle:
            document = tomllib.load(handle)
    else:
        # Python <3.11 fallback: deliberately parse only the four scalar keys
        # that authorize this transaction, scoped to exact table headers.
        import re
        document = {"platform": {}, "mining": {}}
        counts = {"platform": 0, "mining": 0}
        section = None
        with open(sys.argv[1], "r", encoding="utf-8") as handle:
            for number, raw in enumerate(handle, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                table = re.fullmatch(r"\[([A-Za-z0-9_-]+)\]\s*(?:#.*)?", line)
                if table:
                    section = table.group(1)
                    if section in counts:
                        counts[section] += 1
                    continue
                if section == "platform":
                    match = re.fullmatch(r'(target|board_target)\s*=\s*"([^"\\]*)"\s*(?:#.*)?', line)
                elif section == "mining":
                    match = re.fullmatch(r'(enabled|passthrough)\s*=\s*(true|false)\s*(?:#.*)?', line)
                else:
                    continue
                if match:
                    key, value = match.groups()
                    if key in document[section]:
                        raise ValueError("duplicate [%s].%s" % (section, key))
                    document[section][key] = value == "true" if section == "mining" else value
                elif re.match(r"(target|board_target|enabled|passthrough)\s*=", line):
                    raise ValueError("malformed authority at line %d" % number)
        if counts != {"platform": 1, "mining": 1}:
            raise ValueError("authority tables must each appear exactly once")
except (OSError, ValueError) as exc:
    print("ERROR: config is not valid scoped TOML: %s" % exc, file=sys.stderr)
    sys.exit(1)
except Exception as exc:
    if tomllib is not None and isinstance(exc, tomllib.TOMLDecodeError):
        print("ERROR: config is not valid TOML: %s" % exc, file=sys.stderr)
        sys.exit(1)
    raise
platform = document.get("platform")
mining = document.get("mining")
if not isinstance(platform, dict) or not isinstance(mining, dict):
    print("ERROR: config requires [platform] and [mining] tables", file=sys.stderr)
    sys.exit(1)
target = platform.get("target")
board_target = platform.get("board_target")
enabled = mining.get("enabled")
passthrough = mining.get("passthrough")
if target != "am3-aml-s19k":
    print("ERROR: [platform].target must be am3-aml-s19k", file=sys.stderr)
    sys.exit(1)
if board_target not in ("am3-s19k", "am3-s19kpro", "am3-aml-s19kpro"):
    print("ERROR: [platform].board_target is not a live S19k AML alias", file=sys.stderr)
    sys.exit(1)
if type(enabled) is not bool or type(passthrough) is not bool:
    print("ERROR: [mining].enabled and passthrough must be booleans", file=sys.stderr)
    sys.exit(1)
if enabled and not passthrough:
    print("ERROR: NativeMiningOn - mining.enabled=true requires passthrough=true", file=sys.stderr)
    sys.exit(1)
print("BOARD_TARGET=" + board_target)
print("MINING_ENABLED=" + ("true" if enabled else "false"))
print("MINING_PASSTHROUGH=" + ("true" if passthrough else "false"))
PY
)
CFG_BT=$(printf '%s\n' "$CONFIG_ADMIT_OUT" | sed -n 's/^BOARD_TARGET=//p')
MINING_ENABLED=$(printf '%s\n' "$CONFIG_ADMIT_OUT" | sed -n 's/^MINING_ENABLED=//p')
MINING_PASSTHROUGH=$(printf '%s\n' "$CONFIG_ADMIT_OUT" | sed -n 's/^MINING_PASSTHROUGH=//p')
case "$CFG_BT:$MINING_ENABLED:$MINING_PASSTHROUGH" in
  am3-s19k:true:true|am3-s19kpro:true:true|am3-aml-s19kpro:true:true)
    MINING_ON=1
    ;;
  am3-s19k:false:true|am3-s19kpro:false:true|am3-aml-s19kpro:false:true|\
  am3-s19k:false:false|am3-s19kpro:false:false|am3-aml-s19kpro:false:false)
    MINING_ON=0
    ;;
  *)
    echo "ERROR: scoped TOML admission returned an impossible config tuple" >&2
    exit 1
    ;;
esac

if [ "$MINING_ON" -eq 1 ] && [ "$ALLOW_LOUD" != true ]; then
  echo "ERROR: mining-on Track-1 requires the operator's explicit --allow-loud authority" >&2
  exit 1
fi
if [ "$MINING_ON" -eq 0 ] && [ "$ALLOW_LOUD" = true ]; then
  echo "ERROR: --allow-loud is valid only for an admitted mining-on passthrough config" >&2
  exit 1
fi
if [ "$HANDOFF_NO_WORK" = true ] && [ "$MINING_ON" -ne 1 ]; then
  echo "ERROR: --handoff-no-work requires an admitted mining-enabled passthrough config" >&2
  exit 1
fi
if [ "$BOUNDED_WORK_PROOF" = true ] && [ "$MINING_ON" -ne 1 ]; then
  echo "ERROR: --bounded-work-proof requires an admitted mining-enabled passthrough config" >&2
  exit 1
fi
if [ "$ENDURANCE_WORK_PROOF" = true ] && [ "$MINING_ON" -ne 1 ]; then
  echo "ERROR: --endurance-work-proof requires an admitted mining-enabled passthrough config" >&2
  exit 1
fi
if [ "$MINING_ON_PASSTHROUGH" = true ] && [ "$MINING_ON" -ne 1 ]; then
  echo "ERROR: --mining-on-passthrough requires an admitted mining-enabled passthrough config" >&2
  exit 1
fi
WORK_MODE_COUNT=0
[ "$HANDOFF_NO_WORK" != true ] || WORK_MODE_COUNT=$((WORK_MODE_COUNT + 1))
[ "$BOUNDED_WORK_PROOF" != true ] || WORK_MODE_COUNT=$((WORK_MODE_COUNT + 1))
[ "$ENDURANCE_WORK_PROOF" != true ] || WORK_MODE_COUNT=$((WORK_MODE_COUNT + 1))
[ "$MINING_ON_PASSTHROUGH" != true ] || WORK_MODE_COUNT=$((WORK_MODE_COUNT + 1))
if [ "$WORK_MODE_COUNT" -gt 1 ]; then
  echo "ERROR: --handoff-no-work, --bounded-work-proof, --endurance-work-proof, and --mining-on-passthrough are mutually exclusive" >&2
  exit 1
fi
if [ "$MINING_ON" -eq 1 ] && [ "$WORK_MODE_COUNT" -ne 1 ]; then
  echo "ERROR: mining-enabled passthrough requires exactly one explicit deploy mode; no implicit work authority" >&2
  exit 1
fi

COLLECTOR_SHA=$($PY -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$ENDURANCE_COLLECTOR")
COLLECTOR_BYTES=$($PY -c "import os,sys; print(os.path.getsize(sys.argv[1]))" "$ENDURANCE_COLLECTOR")
ENDURANCE_VERIFIER_SHA=$($PY -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$ENDURANCE_VERIFIER")
ENDURANCE_VERIFIER_BYTES=$($PY -c "import os,sys; print(os.path.getsize(sys.argv[1]))" "$ENDURANCE_VERIFIER")
if [ "$ENDURANCE_WORK_PROOF" = true ]; then
  $PY "$ENDURANCE_VERIFIER" baseline "$ENDURANCE_BASELINE"
  ENDURANCE_BASELINE_SHA=$($PY -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$ENDURANCE_BASELINE")
  ENDURANCE_BASELINE_BYTES=$($PY -c "import os,sys; print(os.path.getsize(sys.argv[1]))" "$ENDURANCE_BASELINE")
else
  ENDURANCE_BASELINE_SHA=not-applicable
  ENDURANCE_BASELINE_BYTES=0
fi

STAMP=$(date +%Y%m%d%H%M%S)
if [ "$DRY_RUN" = true ]; then
  REMOTE_DIR="/tmp/dcentrald_bench_t1_DRYRUN"
else
  REMOTE_DIR="/tmp/dcentrald_bench_t1_${STAMP}_$$"
fi
REMOTE_BIN="$REMOTE_DIR/dcentrald"
REMOTE_CFG="$REMOTE_DIR/dcentrald_s19k.toml"
REMOTE_HELPER="$REMOTE_DIR/run_trial"
REMOTE_CUSTODY="$REMOTE_DIR/supervisor_custody_observer"
REMOTE_STOCK_RESTART_HELPER="$REMOTE_DIR/stock_restart_helper"
CFG_SHA=$($PY -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$CFG")
CFG_BYTES=$($PY -c "import os,sys; print(os.path.getsize(sys.argv[1]))" "$CFG")
HELPER_SHA=$($PY -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$REMOTE_RUN_HELPER")
HELPER_BYTES=$($PY -c "import os,sys; print(os.path.getsize(sys.argv[1]))" "$REMOTE_RUN_HELPER")
CUSTODY_SHA=$($PY -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$SUPERVISOR_CUSTODY")
CUSTODY_BYTES=$($PY -c "import os,sys; print(os.path.getsize(sys.argv[1]))" "$SUPERVISOR_CUSTODY")
STOCK_RESTART_HELPER_SHA=$($PY -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$STOCK_RESTART_HELPER")
STOCK_RESTART_HELPER_BYTES=$($PY -c "import os,sys; print(os.path.getsize(sys.argv[1]))" "$STOCK_RESTART_HELPER")
MINER_TARGET_SHA=$($PY -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode('utf-8')).hexdigest())" "$MINER_IP")

# A no-contact dry run may omit SSH authority entirely.  Any contacting run,
# and any dry run that is asked to validate an operator pin, requires one exact
# target entry whose independently calculated OpenSSH fingerprint matches the
# explicit expected value.  GlobalKnownHostsFile is disabled below so this is
# the sole trust root rather than one of several implicit host-key sources.
if [ -z "$KNOWN_HOSTS" ] && [ -z "$EXPECTED_HOST_KEY_SHA256" ]; then
  if [ "$DRY_RUN" != true ]; then
    echo "ERROR: live SSH requires --known-hosts and --expected-host-key-sha256 (or their DCENT_* environment variables)" >&2
    exit 2
  fi
  SSH_HOST_KEY_ADMISSION=not-applicable-no-contact
  SSH_HOST_KEY_PLAN=not-supplied
else
  [ -n "$KNOWN_HOSTS" ] && [ -n "$EXPECTED_HOST_KEY_SHA256" ] || {
    echo "ERROR: --known-hosts and --expected-host-key-sha256 must be supplied together" >&2
    exit 2
  }
  [ -f "$KNOWN_HOSTS" ] && [ ! -L "$KNOWN_HOSTS" ] && [ -s "$KNOWN_HOSTS" ] || {
    echo "ERROR: known-hosts must be a non-empty regular non-symlink file: $KNOWN_HOSTS" >&2
    exit 2
  }
  printf '%s\n' "$EXPECTED_HOST_KEY_SHA256" | grep -Eq '^SHA256:[A-Za-z0-9+/]{43}$' || {
    echo "ERROR: expected host key must be an OpenSSH SHA256 fingerprint" >&2
    exit 2
  }
  command -v ssh-keygen >/dev/null 2>&1 || {
    echo "ERROR: ssh-keygen is required for exact host-key admission" >&2
    exit 2
  }
  PINNED_FINGERPRINTS=$(
    ssh-keygen -F "$MINER_IP" -f "$KNOWN_HOSTS" 2>/dev/null |
      awk '!/^#/ && NF >= 3 {print}' |
      while IFS= read -r key; do
        printf '%s\n' "$key" |
          ssh-keygen -lf - -E sha256 2>/dev/null |
          awk '{print $2}'
      done
  )
  PINNED_FINGERPRINT_COUNT=$(printf '%s\n' "$PINNED_FINGERPRINTS" | sed '/^$/d' | wc -l | awk '{print $1}')
  [ "$PINNED_FINGERPRINT_COUNT" = 1 ] && [ "$PINNED_FINGERPRINTS" = "$EXPECTED_HOST_KEY_SHA256" ] || {
    echo "ERROR: known-hosts must contain exactly the expected key for $MINER_IP" >&2
    exit 2
  }
  SSH_HOST_KEY_ADMISSION=exact-operator-pin
  SSH_HOST_KEY_PLAN=$EXPECTED_HOST_KEY_SHA256
fi
if [ "$MINING_ON" -eq 1 ]; then
  if [ "$HANDOFF_NO_WORK" = true ]; then
    DEPLOY_MODE=handoff-no-work
    WORK_AUTHORITY=disabled
  elif [ "$BOUNDED_WORK_PROOF" = true ]; then
    DEPLOY_MODE=bounded-work-proof
    WORK_AUTHORITY=bounded-proof
  elif [ "$ENDURANCE_WORK_PROOF" = true ]; then
    DEPLOY_MODE=endurance-work-proof
    WORK_AUTHORITY=endurance-proof
  elif [ "$MINING_ON_PASSTHROUGH" = true ]; then
    DEPLOY_MODE=mining-on-passthrough
    WORK_AUTHORITY=enabled
  else
    echo "ERROR: internal deploy-mode admission failure" >&2
    exit 1
  fi
  LOUD_AUTHORITY=true
else
  DEPLOY_MODE=stage-only
  WORK_AUTHORITY=not-applicable
  LOUD_AUTHORITY=false
fi
RUN_COMMAND="$REMOTE_HELPER run $REMOTE_DIR $CFG_BT $DEPLOY_MODE $LOCAL_SHA $LOCAL_BYTES $CFG_SHA $CFG_BYTES $HELPER_SHA $HELPER_BYTES $CUSTODY_SHA $CUSTODY_BYTES $STOCK_RESTART_HELPER_SHA $STOCK_RESTART_HELPER_BYTES"
IDENTITY_COMMAND="$REMOTE_HELPER identity $REMOTE_DIR $CFG_BT $DEPLOY_MODE $LOCAL_SHA $LOCAL_BYTES $CFG_SHA $CFG_BYTES $HELPER_SHA $HELPER_BYTES $CUSTODY_SHA $CUSTODY_BYTES $STOCK_RESTART_HELPER_SHA $STOCK_RESTART_HELPER_BYTES"
RECOVERY_COMMAND="$REMOTE_HELPER restore $REMOTE_DIR $CFG_BT recovery $LOCAL_SHA $LOCAL_BYTES $CFG_SHA $CFG_BYTES $HELPER_SHA $HELPER_BYTES $CUSTODY_SHA $CUSTODY_BYTES $STOCK_RESTART_HELPER_SHA $STOCK_RESTART_HELPER_BYTES"
TMP_DEPLOY_PLAN=$(mktemp "./TMP_DEPLOY_PLAN.${STAMP}.$$.XXXXXX") || {
  echo "ERROR: could not allocate a private unique tmp-deploy evidence path" >&2
  exit 1
}
{
  echo "schema=dcentos.s19k-tmp-deploy/v12"
  echo "triple=armv7-unknown-linux-musleabihf"
  echo "elf_class=32"
  echo "e_machine=40"
  echo "arm_eabi=5"
  echo "hard_float=true"
  echo "pt_interp=none"
  echo "musl_static=true"
  echo "sha256=$LOCAL_SHA"
  echo "bytes=$LOCAL_BYTES"
  echo "operator_artifact_pin=$ARTIFACT_OPERATOR_PIN"
  echo "expected_artifact_sha256=$EXPECTED_ARTIFACT_SHA256"
  echo "expected_artifact_bytes=$EXPECTED_ARTIFACT_BYTES"
  echo "post_scp=sha256sum"
  echo "re_admit=elf32_arm_musl_static"
  echo "remote_dir=$REMOTE_DIR"
  echo "remote_bin=$REMOTE_BIN"
  echo "config_sha256=$CFG_SHA"
  echo "config_bytes=$CFG_BYTES"
  echo "runner_sha256=$HELPER_SHA"
  echo "runner_bytes=$HELPER_BYTES"
  echo "custody_observer_sha256=$CUSTODY_SHA"
  echo "custody_observer_bytes=$CUSTODY_BYTES"
  echo "stock_restart_helper_sha256=$STOCK_RESTART_HELPER_SHA"
  echo "stock_restart_helper_bytes=$STOCK_RESTART_HELPER_BYTES"
  echo "endurance_collector_sha256=$COLLECTOR_SHA"
  echo "endurance_collector_bytes=$COLLECTOR_BYTES"
  echo "endurance_verifier_sha256=$ENDURANCE_VERIFIER_SHA"
  echo "endurance_verifier_bytes=$ENDURANCE_VERIFIER_BYTES"
  echo "endurance_baseline_sha256=$ENDURANCE_BASELINE_SHA"
  echo "endurance_baseline_bytes=$ENDURANCE_BASELINE_BYTES"
  echo "identity_probe=$IDENTITY_COMMAND"
  echo "launch=$RUN_COMMAND"
  echo "runtime_recovery=$RECOVERY_COMMAND"
  echo "runtime_reverify=bin+config+runner+custody-observer+stock-restart-helper-sha256-and-bytes"
  echo "persistent_mutation=false"
  echo "ephemeral_runtime_env=DCENTOS_EPHEMERAL_RUNTIME=1"
  echo "serial_mode_flag=--serial-mining"
  echo "explicit_loud_authority=$LOUD_AUTHORITY"
  echo "loud_flag=--allow-loud"
  echo "no_work_flag=--s19k-track1-no-work"
  echo "bounded_work_proof_flag=--s19k-track1-bounded-work-proof"
  echo "endurance_work_proof_flag=--s19k-track1-endurance-work-proof"
  echo "unbounded_work_flag=--mining-on-passthrough"
  echo "work_proof_timeout_s=600"
  echo "work_evidence=content-bound-terminal-transcript+all-crc-admitted-rx+all-required-path-tx+exact-pool-result-origin"
  echo "work_proof_success=accepted-share-per-required-logical-uart+checked-terminal-safeoff"
  echo "work_authority=$WORK_AUTHORITY"
  echo "endurance_minimum_s=86400"
  echo "endurance_maximum_s=93600"
  echo "endurance_interval_s=60"
  echo "endurance_acceptance_windows=4x6h-per-required-uart"
  echo "endurance_collector_ack_timeout_s=300"
  echo "endurance_max_unacked_segments=6"
  echo "endurance_max_unacked_bytes=524288"
  echo "endurance_evidence=hash-chained-minute-aggregates+accepted-share-lineage+off-target-manifest-acks"
  echo "endurance_terminal=manifest-head+terminal-handoff+checked-safeoff+host-semantic-verification"
  echo "chmod=755"
  echo "required_ports=population-selected:/dev/ttyS3,/dev/ttyS2,/dev/ttyS1"
  echo "baud=3000000"
  echo "keep_rails=dcentrald-exact-braiins-supervisor-and-child-handoff"
  echo "handoff_identity=supervisor+child-pid+start+ppid+pgrp+session+comm+exe+argv-sha256"
  echo "handoff_watchdog=armed-before-signal"
  echo "handoff_signal=j3-ptrace-all-thread-freeze+supervisor-first-sigkill-terminal+child-second-sigkill-terminal+event-drain"
  echo "live_identity_schema=dcentos.s19k-braiins-live-identity/v2"
  echo "live_identity_profile_rule=mutually-exclusive-complete-tuple"
  echo "live_identity_profile_live88_two_bhb56903_slots_2_3=2xBHB56903@2,3+addr1-undetected-placeholder+eeprom-0x50-absent-0x51-0x52-0511"
  echo "live_identity_profile_held78_three_bhb56902_slots_1_2_3=3xBHB56902@1,2,3+eeprom-0x50-0x51-0x52-0511"
  echo "live_identity_profile_bhb56902_only=one-to-three-BHB56902+exact-address/eeprom-join"
  echo "live_identity_profile_bhb56903_only=one-to-three-BHB56903+exact-address/eeprom-join"
  echo "live_identity_profile_mixed_bhb56902_bhb56903=one-to-three-mixed-boards+exact-address/eeprom-join"
  echo "live_identity_profile_all_three_uarts_populated=addresses-1,2,3+ttyS3,ttyS2,ttyS1"
  echo "live_identity_evidence=aarch64+a113d-cpu+bos-platform-mode+exact-mtd+typed-profile"
  echo "live_identity_recheck=pre-handoff+pre-recovery-safeoff"
  echo "runtime_receipt_schema=dcentos.s19k-tmp-runtime/v5"
  echo "runtime_lock=board-global-atomic-mkdir+v6-artifact-bound-owner+typed-pending-retention"
  echo "receipt_clear=checked-safeoff-to-exact-stock-restart-helper-only"
  echo "recovery_safeoff_receipt=dcentos.s19k-track1-safeoff/v1"
  echo "runtime_log_ring=/tmp/dcent/log"
  echo "forbidden_stop=/etc/init.d/S99bosminer stop"
  echo "mode=$DEPLOY_MODE"
  echo "native_bm1366=refused"
  echo "clear_for_flash=false"
  echo "execute=CLEAR_FOR_FLASH"
  echo "dry_run=$DRY_RUN"
  echo "miner_target_sha256=$MINER_TARGET_SHA"
  echo "miner_target_record=sha256-only"
  echo "ssh_host_key_admission=$SSH_HOST_KEY_ADMISSION"
  echo "ssh_host_key_sha256=$SSH_HOST_KEY_PLAN"
  echo "ssh_global_known_hosts=disabled-on-contact"
} > "$TMP_DEPLOY_PLAN"
echo "  wrote $TMP_DEPLOY_PLAN"

if [ "$DRY_RUN" = true ]; then
  echo "[DRY RUN] writing TMP_DEPLOY_PLAN before SSH..."
  echo "[DRY RUN] no ssh, no scp, no chmod, no /etc/dcentos write"
  if [ "$BOUNDED_WORK_PROOF" = true ]; then
    echo "mode=$DEPLOY_MODE work_authority=$WORK_AUTHORITY work_proof_timeout_s=600"
  elif [ "$ENDURANCE_WORK_PROOF" = true ]; then
    echo "mode=$DEPLOY_MODE work_authority=$WORK_AUTHORITY minimum_s=86400 maximum_s=93600 collector_ack_timeout_s=300"
    echo "Resume failed collector only: $PY $ENDURANCE_COLLECTOR_SOURCE --resume-failure --plan $TMP_DEPLOY_PLAN --miner-ip $MINER_IP --known-hosts $KNOWN_HOSTS --expected-host-key-sha256 $EXPECTED_HOST_KEY_SHA256 --baseline $ENDURANCE_BASELINE_SOURCE --phase3-plan <accepted-live-bounded-plan> --phase3-trial-dir <copied-phase3-trial-dir> --phase3-wall-power-csv <canonical-phase3-meter.csv> --phase3-physical-dir <sealed-phase3-physical-evidence-dir> --evidence-dir <original-evidence-dir> --wall-power-csv <canonical-endurance-meter.csv>"
  else
    echo "mode=$DEPLOY_MODE work_authority=$WORK_AUTHORITY"
  fi
  echo "Run: $RUN_COMMAND"
  echo "FLASH NOT_YET. Not mining-achieved. Not stock GO."
  exit 0
fi

ssh_trial() {
  ssh -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS" \
    -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=10 "$@"
}
scp_trial() {
  scp -O -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS" \
    -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=10 "$@"
}

ssh_trial "root@$MINER_IP" "umask 077 && mkdir '$REMOTE_DIR'"
scp_trial "$BIN" "root@$MINER_IP:$REMOTE_BIN"
scp_trial "$CFG" "root@$MINER_IP:$REMOTE_CFG"
scp_trial "$REMOTE_RUN_HELPER" "root@$MINER_IP:$REMOTE_HELPER"
scp_trial "$SUPERVISOR_CUSTODY" "root@$MINER_IP:$REMOTE_CUSTODY"
scp_trial "$STOCK_RESTART_HELPER" "root@$MINER_IP:$REMOTE_STOCK_RESTART_HELPER"
REMOTE_SUM=$(ssh_trial "root@$MINER_IP" "sha256sum '$REMOTE_BIN' | awk '{print \$1}'")
REMOTE_BYTES=$(ssh_trial "root@$MINER_IP" "wc -c < '$REMOTE_BIN'" | tr -d ' \t\r\n')
REMOTE_CFG_SUM=$(ssh_trial "root@$MINER_IP" "sha256sum '$REMOTE_CFG' | awk '{print \$1}'")
REMOTE_CFG_BYTES=$(ssh_trial "root@$MINER_IP" "wc -c < '$REMOTE_CFG'" | tr -d ' \t\r\n')
REMOTE_HELPER_SUM=$(ssh_trial "root@$MINER_IP" "sha256sum '$REMOTE_HELPER' | awk '{print \$1}'")
REMOTE_HELPER_BYTES=$(ssh_trial "root@$MINER_IP" "wc -c < '$REMOTE_HELPER'" | tr -d ' \t\r\n')
REMOTE_CUSTODY_SUM=$(ssh_trial "root@$MINER_IP" "sha256sum '$REMOTE_CUSTODY' | awk '{print \$1}'")
REMOTE_CUSTODY_BYTES=$(ssh_trial "root@$MINER_IP" "wc -c < '$REMOTE_CUSTODY'" | tr -d ' \t\r\n')
REMOTE_STOCK_RESTART_HELPER_SUM=$(ssh_trial "root@$MINER_IP" "sha256sum '$REMOTE_STOCK_RESTART_HELPER' | awk '{print \$1}'")
REMOTE_STOCK_RESTART_HELPER_BYTES=$(ssh_trial "root@$MINER_IP" "wc -c < '$REMOTE_STOCK_RESTART_HELPER'" | tr -d ' \t\r\n')
if [ -z "$REMOTE_SUM" ] || [ "$REMOTE_SUM" != "$LOCAL_SHA" ] || [ "$REMOTE_BYTES" != "$LOCAL_BYTES" ]; then
  echo "ERROR: admit_s19k_tmp_deploy_post_scp refused — sha256/bytes mismatch (plan=$LOCAL_SHA/$LOCAL_BYTES remote=$REMOTE_SUM/$REMOTE_BYTES)" >&2
  exit 1
fi
if [ "$REMOTE_CFG_SUM" != "$CFG_SHA" ] || [ "$REMOTE_CFG_BYTES" != "$CFG_BYTES" ]; then
  echo "ERROR: staged config sha256/bytes mismatch" >&2
  exit 1
fi
if [ "$REMOTE_HELPER_SUM" != "$HELPER_SHA" ] || [ "$REMOTE_HELPER_BYTES" != "$HELPER_BYTES" ]; then
  echo "ERROR: staged trial runner sha256/bytes mismatch" >&2
  exit 1
fi
if [ "$REMOTE_CUSTODY_SUM" != "$CUSTODY_SHA" ] || [ "$REMOTE_CUSTODY_BYTES" != "$CUSTODY_BYTES" ]; then
  echo "ERROR: staged supervisor custody observer sha256/bytes mismatch" >&2
  exit 1
fi
if [ "$REMOTE_STOCK_RESTART_HELPER_SUM" != "$STOCK_RESTART_HELPER_SHA" ] || [ "$REMOTE_STOCK_RESTART_HELPER_BYTES" != "$STOCK_RESTART_HELPER_BYTES" ]; then
  echo "ERROR: staged stock restart helper sha256/bytes mismatch" >&2
  exit 1
fi
ssh_trial "root@$MINER_IP" "chmod 755 '$REMOTE_BIN' '$REMOTE_HELPER' '$REMOTE_CUSTODY' '$REMOTE_STOCK_RESTART_HELPER'"

# The content-bound helper, rather than the staged TOML or a DCENT marker,
# admits a fresh read-only Braiins/SoC/MTD/EEPROM identity tuple.  This runs
# before any stock-process handoff or fixed-polarity hardware action.
LIVE_IDENTITY_OBS=$(ssh_trial "root@$MINER_IP" "$IDENTITY_COMMAND")
printf '%s\n' "$LIVE_IDENTITY_OBS"
[ "$(printf '%s\n' "$LIVE_IDENTITY_OBS" | wc -l | tr -d ' \t\r\n')" -eq 1 ] || {
  echo "ERROR: content-bound helper returned an inexact live S19k identity receipt set" >&2
  exit 1
}
printf '%s\n' "$LIVE_IDENTITY_OBS" | grep -Eq '^DCENT_S19K_LIVE_IDENTITY schema=dcentos\.s19k-braiins-live-identity/v2 profile=(live88_two_bhb56903_slots_2_3|held78_three_bhb56902_slots_1_2_3|(bhb56902-only|bhb56903-only|mixed-bhb56902-bhb56903):(partial-logical-uarts-populated|all-three-uarts-populated)) sha256=[0-9a-f]{64} model_sha256=[0-9a-f]{64} board_names=BHB5690(2|3)(,BHB5690(2|3)){0,2} physical_addresses=[1-3](,[1-3]){0,2} eeprom=0x50=(absent|05:11),0x51=(absent|05:11),0x52=(absent|05:11)$' || {
  echo "ERROR: content-bound helper returned no exact live S19k identity receipt" >&2
  exit 1
}

# Observe only. Do not write GPIO437. Do not S99 stop.
OBS=$(ssh_trial "root@$MINER_IP" 'sh -s' <<'OBS'
set -eu
G=/sys/class/gpio/gpio437/value
if [ -f "$G" ]; then
  echo "GPIO437=$(cat "$G")"
else
  echo "GPIO437=unexported"
fi
echo -n "BOSMINER="
pidof bosminer 2>/dev/null || echo none
ls -l /dev/ttyS1 /dev/ttyS2 /dev/ttyS3 /dev/uart_trans 2>/dev/null || true
if [ -e /dev/uart_trans ]; then
  echo "ERROR: /dev/uart_trans present — Braiins Track-1 refuses this node" >&2
  exit 1
fi
OBS
)
echo "$OBS"
echo "$OBS" | grep -q '/dev/ttyS1' || {
  echo "ERROR: /dev/ttyS1 missing — refuse S19k Track-1 /tmp deploy" >&2
  exit 1
}
echo "$OBS" | grep -q '/dev/ttyS2' || {
  echo "ERROR: /dev/ttyS2 missing — refuse single-port /tmp deploy" >&2
  exit 1
}
if echo "$OBS" | grep -q 'GPIO437=1'; then
  if [ "$MINING_ON" -eq 1 ]; then
    echo "ERROR: GPIO437=1 means PSU OFF on am3-s19k. Refuse mining-on; exact handoff requires stock-held engaged rails." >&2
    exit 1
  fi
  echo "WARN: GPIO437=1 means PSU OFF on am3-s19k; stage-only remains non-mutating." >&2
fi
if [ "$MINING_ON" -eq 1 ] && echo "$OBS" | grep -q 'BOSMINER=none'; then
  echo "ERROR: exact daemon-owned handoff requires one live bosminer; external pre-kill is refused." >&2
  exit 1
fi
if [ "$MINING_ON" -eq 1 ]; then
  STOCK_CUSTODY_OBS=$(ssh_trial "root@$MINER_IP" "'$REMOTE_CUSTODY' capture /proc /var/run/bosminer.pid")
  printf '%s\n' "$STOCK_CUSTODY_OBS"
  [ "$(printf '%s\n' "$STOCK_CUSTODY_OBS" | wc -l | tr -d ' \t\r\n')" -eq 23 ] \
    && printf '%s\n' "$STOCK_CUSTODY_OBS" | grep -Fxq 'schema=dcentos.s19k-braiins-supervisor-custody/v1' \
    && printf '%s\n' "$STOCK_CUSTODY_OBS" | grep -Fxq 'authority=read-only-process-tree-observation' || {
      echo "ERROR: exact Braiins supervisor+bosminer custody tree was not admitted" >&2
      exit 1
    }
fi

echo "Staged $REMOTE_DIR"
echo "Required baseline ports: /dev/ttyS1 /dev/ttyS2 @ 3000000; /dev/ttyS3 is optional and promoted only by strict Complete77 at 3M"
if [ "$HANDOFF_NO_WORK" = true ]; then
  echo "Expected UART work after handoff: none; jobs are discarded, dispatch remains unadmitted, and the actor rejects queued TX"
elif [ "$BOUNDED_WORK_PROOF" = true ]; then
  echo "Expected bounded proof: every committed 88-byte TX and CRC-admitted 11-byte RX is retained in the content-bound transcript; automatic checked closeout follows one accepted share per required logical UART or the 600s deadline"
elif [ "$ENDURANCE_WORK_PROOF" = true ]; then
  echo "Expected endurance proof: complete hash-chained minute aggregates for 24h, accepted share per required UART in every fixed 6h window, collector acknowledgement within 300s, and automatic checked closeout before 26h"
else
  echo "Expected first job prefix after mining-on: 55 AA 21 36"
fi
echo "Keep rails: dcentrald exact bos-tools supervisor then bosminer child handoff   FORBIDDEN: external pre-kill or S99bosminer stop"
if [ "$HANDOFF_NO_WORK" = true ]; then
  echo "MODE=handoff-no-work passthrough=true explicit_allow_loud=true work_authority=disabled"
elif [ "$BOUNDED_WORK_PROOF" = true ]; then
  echo "MODE=bounded-work-proof passthrough=true explicit_allow_loud=true work_authority=bounded-proof timeout_s=600"
elif [ "$ENDURANCE_WORK_PROOF" = true ]; then
  echo "MODE=endurance-work-proof passthrough=true explicit_allow_loud=true work_authority=endurance-proof minimum_s=86400 maximum_s=93600"
elif [ "$MINING_ON" -eq 1 ]; then
  echo "MODE=mining-on passthrough=true explicit_allow_loud=true (native BM1366 still refused)"
else
  echo "MODE=stage-only mining.enabled=false"
fi
echo "Run (fresh live identity + config policy; no persistent marker mutation):"
echo "  $RUN_COMMAND"
if [ "$ENDURANCE_WORK_PROOF" = true ]; then
  echo "Run endurance only through the content-bound host collector; direct launch cannot satisfy segment acknowledgements:"
  echo "  $PY $ENDURANCE_COLLECTOR_SOURCE --plan $TMP_DEPLOY_PLAN --miner-ip $MINER_IP --known-hosts $KNOWN_HOSTS --expected-host-key-sha256 $EXPECTED_HOST_KEY_SHA256 --baseline $ENDURANCE_BASELINE_SOURCE --phase3-plan <accepted-live-bounded-plan> --phase3-trial-dir <copied-phase3-trial-dir> --phase3-wall-power-csv <canonical-phase3-meter.csv> --phase3-physical-dir <sealed-phase3-physical-evidence-dir> --evidence-dir ./S19K_ENDURANCE_${STAMP} --wall-power-csv <canonical-endurance-meter.csv>"
  echo "If the collector process itself was killed, wait for fail-closed target shutdown and drain the same directory without relaunching mining:"
  echo "  $PY $ENDURANCE_COLLECTOR_SOURCE --resume-failure --plan $TMP_DEPLOY_PLAN --miner-ip $MINER_IP --known-hosts $KNOWN_HOSTS --expected-host-key-sha256 $EXPECTED_HOST_KEY_SHA256 --baseline $ENDURANCE_BASELINE_SOURCE --phase3-plan <accepted-live-bounded-plan> --phase3-trial-dir <copied-phase3-trial-dir> --phase3-wall-power-csv <canonical-phase3-meter.csv> --phase3-physical-dir <sealed-phase3-physical-evidence-dir> --evidence-dir ./S19K_ENDURANCE_${STAMP} --wall-power-csv <canonical-endurance-meter.csv>"
fi
echo "Stop/recover an orphaned temporary runtime after an ungraceful wrapper kill:"
echo "  $RECOVERY_COMMAND"
echo "FLASH NOT_YET. Not mining-achieved. Not stock GO."
