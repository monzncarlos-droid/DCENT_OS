#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/amlogic_identity_guard.sh"

failures=0

expect_rejected() {
    label=$1
    variant=$2
    normalized=$3
    lower=$4
    if reason=$(dcent_amlogic_sibling_rejection "$variant" "$normalized" "$lower"); then
        printf 'PASS: %s (%s)\n' "$label" "$reason"
    else
        printf 'FAIL: %s was admitted\n' "$label" >&2
        failures=$((failures + 1))
    fi
}

expect_allowed() {
    label=$1
    variant=$2
    normalized=$3
    lower=$4
    if reason=$(dcent_amlogic_sibling_rejection "$variant" "$normalized" "$lower"); then
        printf 'FAIL: %s was rejected (%s)\n' "$label" "$reason" >&2
        failures=$((failures + 1))
    else
        printf 'PASS: %s\n' "$label"
    fi
}

expect_tuple_allowed() {
    label=$1
    shift
    if receipt=$(dcent_amlogic_exact_tuple_admit "$@"); then
        printf 'PASS: %s (%s)\n' "$label" "$receipt"
    else
        printf 'FAIL: %s was rejected (%s)\n' "$label" "$receipt" >&2
        failures=$((failures + 1))
    fi
}

expect_tuple_rejected() {
    label=$1
    shift
    if receipt=$(dcent_amlogic_exact_tuple_admit "$@"); then
        printf 'FAIL: %s was admitted (%s)\n' "$label" "$receipt" >&2
        failures=$((failures + 1))
    else
        printf 'PASS: %s (%s)\n' "$label" "$receipt"
    fi
}

expect_record_allowed() {
    label=$1
    variant=$2
    identity=$3
    if receipt=$(dcent_amlogic_identity_record_admit "$variant" "$identity"); then
        printf 'PASS: %s (%s)\n' "$label" "$receipt"
    else
        printf 'FAIL: %s was rejected (%s)\n' "$label" "$receipt" >&2
        failures=$((failures + 1))
    fi
}

expect_record_rejected() {
    label=$1
    variant=$2
    identity=$3
    if receipt=$(dcent_amlogic_identity_record_admit "$variant" "$identity"); then
        printf 'FAIL: %s was admitted (%s)\n' "$label" "$receipt" >&2
        failures=$((failures + 1))
    else
        printf 'PASS: %s (%s)\n' "$label" "$receipt"
    fi
}

expect_rejected 'base S19j Pro refuses Pro-A' s19jpro-aml antminers19jproa 'model=antminer s19j pro-a'
expect_rejected 'base S21 refuses S21+' s21 antminers21 'model=antminer s21+'
expect_rejected 'base S21 refuses S21++' s21 antminers21 'model=antminer s21++'
expect_rejected 'base S21 refuses S21 Imm' s21 antminers21imm 'model=antminer s21 imm'
expect_rejected 'base S21 refuses S21e Hydro' s21 antminers21ehydro 'model=antminer s21e hydro'
expect_rejected 'S21 Pro refuses Pro+' s21pro antminers21pro 'model=antminer s21 pro+'
expect_rejected 'S21 XP refuses XP Imm' s21xp antminers21xpimm 'model=antminer s21 xp imm'
expect_rejected 'S21 XP refuses XP Hydro' s21xp antminers21xphydro 'model=antminer s21 xp hydro'
expect_rejected 'T21 refuses Hydro sibling' t21 antminert21hydro 'model=antminer t21 hydro'

expect_allowed 'exact S19j Pro remains eligible for positive gate' s19jpro-aml antminers19jpro 'model=antminer s19j pro'
expect_allowed 'exact S19k Pro remains eligible for positive gate' s19kpro antminers19kpro 'model=antminer s19k pro'
expect_allowed 'exact S21 remains eligible for positive gate' s21 antminers21 'model=antminer s21'
expect_allowed 'exact S21 Pro remains eligible for positive gate' s21pro antminers21pro 'model=antminer s21 pro'
expect_allowed 'exact S21 XP remains eligible for positive gate' s21xp antminers21xp 'model=antminer s21 xp'
expect_allowed 'exact T21 remains eligible for positive gate' t21 antminert21 'model=antminer t21'

# Full terminal tuple gate: model-only and generic-Amlogic observations must
# never authorize the destructive installer.
expect_tuple_rejected 'S21 Pro model-only bypass is closed' \
    s21pro '' antminers21pro amlogicgeneric '' 'model=antminer s21 pro'
expect_tuple_rejected 'S21 Pro requires CBE even with A113D' \
    s21pro '' antminers21pro amlogica113d c83 'model=antminer s21 pro'
expect_tuple_rejected 'S21 Pro requires A113D/AXG even with CBE' \
    s21pro '' antminers21pro amlogicgeneric cbe 'model=antminer s21 pro'
expect_tuple_rejected 'conflicting board target is refused' \
    s21pro am3s21xp antminers21pro amlogica113d cbe 'model=antminer s21 pro'
expect_tuple_rejected 'base S21 never admits S21+' \
    s21 am3s21 antminers21 amlogica113d c81 'model=antminer s21+'
expect_tuple_allowed 'exact S21 Pro CBE/A113D tuple is admitted' \
    s21pro am3s21pro antminers21pro amlogica113d cbe 'model=antminer s21 pro'
expect_tuple_allowed 'exact T21 C83/AXG tuple is admitted without board_target' \
    t21 '' antminert21 amlogicmesonaxg c83 'model=antminer t21'
expect_tuple_allowed 'exact S19j XP C83/A113D tuple is admitted' \
    s19jxp am3s19jxp antminers19jxp amlogica113d c83 'model=antminer s19j xp'
expect_tuple_allowed 'exact S19j Pro C76/A113D tuple is admitted' \
    s19jpro-aml am3s19jproaml antminers19jpro amlogica113d c76 'model=antminer s19j pro'
expect_tuple_allowed 'exact S19j Pro+ C81/A113D tuple is admitted' \
    s19jproplus am3s19jproplus antminers19jproplus amlogica113d c81 'model=antminer s19j pro plus'
expect_tuple_allowed 'exact S19 XP C81/A113D tuple is admitted' \
    s19xp am3s19xp antminers19xp amlogica113d c81 'model=antminer s19 xp'
expect_tuple_allowed 'exact S19k Pro C81/A113D tuple is admitted' \
    s19kpro am3s19k antminers19kpro amlogica113d c81 'model=antminer s19k pro'
expect_tuple_allowed 'exact S19k Pro C83/A113D tuple is admitted' \
    s19kpro am3s19k antminers19kpro amlogica113d c83 'model=antminer s19k pro'
expect_tuple_allowed 'held S19k Pro NoPic C81/A113D tuple is admitted' \
    s19kpro am3s19k antminers19kpronopic amlogica113d c81 'model=antminer s19k pro nopic'
expect_tuple_allowed 'exact base S21 C81/A113D tuple is admitted' \
    s21 am3s21 antminers21 amlogica113d c81 'model=antminer s21'
expect_tuple_allowed 'exact S21 XP CBE/A113D tuple is admitted' \
    s21xp am3s21xp antminers21xp amlogica113d cbe 'model=antminer s21 xp'
expect_tuple_rejected 'C810 cannot impersonate exact C81' \
    s19kpro am3s19k antminers19kpro amlogica113d c810 'model=antminer s19k pro'
expect_tuple_rejected 'C830 cannot impersonate exact C83' \
    s19kpro am3s19k antminers19kpro amlogica113d c830 'model=antminer s19k pro'
expect_tuple_rejected 'AC810 cannot impersonate exact C81' \
    s19kpro am3s19k antminers19kpro amlogica113d ac810 'model=antminer s19k pro'
expect_tuple_rejected 'A113D0 cannot impersonate exact A113D' \
    s19kpro am3s19k antminers19kpro amlogica113d0 c81 'model=antminer s19k pro'
expect_tuple_rejected 'NotA113D cannot impersonate exact A113D' \
    s19kpro am3s19k antminers19kpro nota113d c81 'model=antminer s19k pro'
expect_tuple_rejected 'MesonAXG0 cannot impersonate exact AXG' \
    s19kpro am3s19k antminers19kpro mesonaxg0 c81 'model=antminer s19k pro'
expect_tuple_rejected 'S19KX cannot impersonate exact S19k Pro' \
    s19kpro am3s19k antminers19kx amlogica113d c81 'model=antminer s19kx'
expect_tuple_rejected 'S19KProFoo cannot extend exact S19k Pro' \
    s19kpro am3s19k antminers19kprofoo amlogica113d c81 'model=antminer s19k pro foo'
expect_tuple_rejected 'S210 cannot impersonate exact base S21' \
    s21 am3s21 antminers210 amlogica113d c81 'model=antminer s210'
expect_tuple_rejected 'T210 cannot impersonate exact T21' \
    t21 am3t21 antminert210 amlogica113d c81 'model=antminer t210'

model_only_record='BOARD_TARGET=
MODEL=Antminer S21 Pro
HWID=
PCB=
BOS_MODEL=
DT_MODEL=Amlogic generic
DT_COMPATIBLE=
CPU_SYSTEM='
expect_record_rejected 'full installer record closes the model-only bypass' s21pro "$model_only_record"

exact_record='BOARD_TARGET=am3-s21pro
MODEL=Antminer S21 Pro
HWID=control-board-CBE
PCB=CBE
BOS_MODEL=model = "Antminer S21 Pro"
DT_MODEL=Bitmain CBE Amlogic A113D
DT_COMPATIBLE=amlogic,a113d
CPU_SYSTEM=Amlogic Meson AXG'
expect_record_allowed 'full installer record admits exact S21 Pro/CBE/A113D' s21pro "$exact_record"

near_miss_pcb_record='BOARD_TARGET=am3-s19k
MODEL=Antminer S19k Pro
HWID=control-board-C810
PCB=C810
BOS_MODEL=model = "Antminer S19K Pro NoPic"
DT_MODEL=Bitmain C810 Amlogic A113D
DT_COMPATIBLE=amlogic,a113d
CPU_SYSTEM=Amlogic Meson AXG'
expect_record_rejected 'record parser refuses boundary-near C810 PCB evidence' s19kpro "$near_miss_pcb_record"

conflicting_model_record='BOARD_TARGET=am3-s19k
MODEL=Antminer S19k Pro
HWID=control-board-C81
PCB=C81
BOS_MODEL=model = "Antminer S19kX"
DT_MODEL=Bitmain C81 Amlogic A113D
DT_COMPATIBLE=amlogic,a113d
CPU_SYSTEM=Amlogic Meson AXG'
expect_record_rejected 'record parser refuses a conflicting near-model observation' s19kpro "$conflicting_model_record"

duplicate_board_record="$exact_record
BOARD_TARGET=am3-s21xp"
expect_record_rejected 'record parser refuses duplicate board authority' s21pro "$duplicate_board_record"

duplicate_model_record="$exact_record
MODEL=Antminer S21 Pro"
expect_record_rejected 'record parser refuses duplicate model evidence' s21pro "$duplicate_model_record"

missing_cpu_record=$(printf '%s\n' "$exact_record" | sed '/^CPU_SYSTEM=/d')
expect_record_rejected 'record parser refuses an incomplete identity field set' s21pro "$missing_cpu_record"

extra_authority_record="$exact_record
UNKNOWN_AUTHORITY=accepted"
expect_record_rejected 'record parser refuses unknown extra identity authority' s21pro "$extra_authority_record"

near_soc_record=$(printf '%s\n' "$exact_record" | sed 's/A113D/A113D0/g;s/AXG/AXG0/g;s/a113d/a113d0/g')
expect_record_rejected 'record parser refuses near-suffix SoC evidence' s21pro "$near_soc_record"

# --- Braiins model+SoC dialect (2026-08-30): the live .88 refusal shape ----
# BraiinsOS ships no /config CONF_* files, no sysfs eeprom node, and its
# device tree carries no cXX token, so the direct carrier-PCB observation is
# genuinely unavailable.  The operator-scoped alternative path requires the
# exact NoPic BOS_MODEL, an AXG SoC token, zero PCB tokens in any stock
# channel, and conflict-free held-family (05:11) hashboard evidence.

expect_tuple_allowed 'exact S19k Pro braiins-dialect tuple admits without PCB token' \
    s19kpro am3s19k antminers19kpronopic amlogicmesonaxg '' 'model=antminer s19k pro nopic' unavailable-braiins
expect_tuple_rejected 'same tuple without the dialect marker stays refused' \
    s19kpro am3s19k antminers19kpronopic amlogicmesonaxg '' 'model=antminer s19k pro nopic'
expect_tuple_rejected 'dialect marker beside a compatible PCB token is contradictory' \
    s19kpro am3s19k antminers19kpro amlogica113d c81 'model=antminer s19k pro' unavailable-braiins
expect_tuple_rejected 'dialect marker cannot rescue an observed C76 conflict' \
    s19kpro am3s19k antminers19kpro amlogica113d c76 'model=antminer s19k pro' unavailable-braiins
expect_tuple_rejected 'dialect is not held evidence for base S21' \
    s21 am3s21 antminers21 amlogica113d '' 'model=antminer s21' unavailable-braiins

braiins_record='BOARD_TARGET=
MODEL=
HWID=
PCB=
BOS_MODEL=model = "Antminer S19K Pro NoPic"
DT_MODEL=Amlogic
DT_COMPATIBLE=amlogic, axg
CPU_SYSTEM=Amlogic
PCB_OBSERVATION=unavailable-braiins
HASHBOARD_EEPROM=0x50=absent,0x51=05:11,0x52=05:11'
expect_record_allowed 'braiins dialect admits exact NoPic model + AXG + 05:11 evidence' s19kpro "$braiins_record"

braiins_unmarked_record=$(printf '%s\n' "$braiins_record" | sed 's/^PCB_OBSERVATION=.*/PCB_OBSERVATION=direct/')
expect_record_rejected 'same Braiins unit without the operator marker stays refused' s19kpro "$braiins_unmarked_record"

expect_record_rejected 'braiins dialect is not held evidence outside S19k' s21 "$braiins_record"

braiins_readerless_record=$(printf '%s\n' "$braiins_record" | sed 's/^HASHBOARD_EEPROM=.*/HASHBOARD_EEPROM=reader-unavailable/')
expect_record_allowed 'reader-unavailable braiins unit admits with the gap recorded' s19kpro "$braiins_readerless_record"

braiins_foreign_record=$(printf '%s\n' "$braiins_record" | sed 's/0x51=05:11/0x51=foreign:0x04:0x11/')
expect_record_rejected 'braiins dialect refuses a foreign BHB42-family preamble' s19kpro "$braiins_foreign_record"

braiins_partial_record=$(printf '%s\n' "$braiins_record" | sed 's/0x52=05:11/0x52=partial:0x05/')
expect_record_rejected 'braiins dialect refuses a partial populated-slot read' s19kpro "$braiins_partial_record"

braiins_conflict_record=$(printf '%s\n' "$braiins_record" | sed 's/^DT_MODEL=Amlogic/DT_MODEL=Bitmain A113D C76/')
expect_record_rejected 'operator override cannot relabel an observed C76 conflict' s19kpro "$braiins_conflict_record"

braiins_sibling_record=$(printf '%s\n' "$braiins_record" | sed 's/Antminer S19K Pro NoPic/Antminer S19k Pro+/')
expect_record_rejected 'braiins dialect still refuses S19k Pro+ siblings' s19kpro "$braiins_sibling_record"

braiins_ambiguous_record=$(printf '%s\n' "$braiins_record" | sed 's/^MODEL=$/MODEL=Antminer S19j Pro/')
expect_record_rejected 'braiins dialect refuses an ambiguous model observation' s19kpro "$braiins_ambiguous_record"

braiins_bosless_record=$(printf '%s\n' "$braiins_record" | sed 's/^BOS_MODEL=.*/BOS_MODEL=/')
expect_record_rejected 'braiins dialect requires the BOS_MODEL model source' s19kpro "$braiins_bosless_record"

braiins_legacy_shape=$(printf '%s\n' "$braiins_record" | sed '/^PCB_OBSERVATION=/d;/^HASHBOARD_EEPROM=/d')
expect_record_rejected 'legacy-shaped braiins record cannot ride the dialect' s19kpro "$braiins_legacy_shape"

stock_direct_record='BOARD_TARGET=
MODEL=Antminer S19k Pro
HWID=S19k Pro C81
PCB=C81
BOS_MODEL=model = "Antminer S19K Pro NoPic"
DT_MODEL=Bitmain A113D C81
DT_COMPATIBLE=amlogic,a113d
CPU_SYSTEM=Amlogic Meson AXG
PCB_OBSERVATION=direct
HASHBOARD_EEPROM=reader-unavailable'
expect_record_allowed 'ten-field stock record keeps the original direct receipt' s19kpro "$stock_direct_record"

legacy_stock_record=$(printf '%s\n' "$stock_direct_record" | sed '/^PCB_OBSERVATION=/d;/^HASHBOARD_EEPROM=/d')
expect_record_allowed 'historical eight-field transcripts still re-admit for recovery' s19kpro "$legacy_stock_record"

nine_field_record=$(printf '%s\n' "$braiins_record" | sed '/^HASHBOARD_EEPROM=/d')
expect_record_rejected 'partial schema extension is refused' s19kpro "$nine_field_record"

bad_dialect_record=$(printf '%s\n' "$braiins_record" | sed 's/^PCB_OBSERVATION=.*/PCB_OBSERVATION=braiins/')
expect_record_rejected 'unknown dialect marker is refused' s19kpro "$bad_dialect_record"

[ "$failures" -eq 0 ] || exit 1
printf 'AMLOGIC_IDENTITY_GUARD_OK\n'
