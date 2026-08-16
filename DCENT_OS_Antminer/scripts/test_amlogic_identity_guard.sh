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

[ "$failures" -eq 0 ] || exit 1
printf 'AMLOGIC_IDENTITY_GUARD_OK\n'
