#!/bin/sh
# Exact-variant guards shared by host-side Amlogic installers.
#
# dcent_amlogic_sibling_rejection returns 0 and prints a reason when a held but
# unsupported sibling is detected.
#
# dcent_amlogic_exact_tuple_admit returns 0 only when all of these independent
# observations agree:
#   * the requested package variant and model identity;
#   * an A113D/AXG device-tree/CPU observation; and
#   * a directly observed, model-compatible C76/C81/C83/CBE PCB code.
#
# A model name or DCENT board_target is deliberately insufficient on its own.
# Cross-flashing the wrong Amlogic carrier can make the only recovery path a
# physical control-board replacement.

dcent_amlogic_sibling_rejection() {
    dcent_variant=$1
    dcent_normalized=$2
    dcent_identity_lower=$3

    case "$dcent_variant" in
        s19jpro-aml|s19jpro|s19j)
            case "$dcent_normalized" in
                *s19jproa*)
                    printf '%s\n' 'S19j Pro-A is a distinct carrier without an exact DCENT_OS package target'
                    return 0
                    ;;
            esac
            ;;
        s19kpro|s19k)
            case "$dcent_normalized" in
                *s19kplus*|*s19kxp*|*s19kimm*|*s19khydro*)
                    printf '%s\n' 'S19k sibling/immersion identity is outside the exact S19k Pro target'
                    return 0
                    ;;
            esac
            case "$dcent_identity_lower" in
                *s19k+*)
                    printf '%s\n' 'S19k+ is a distinct carrier without an exact DCENT_OS package target'
                    return 0
                    ;;
            esac
            ;;
        s21)
            case "$dcent_normalized" in
                *s21pro*|*s21xp*|*s21plus*|*s21imm*|*s21hydro*|*s21e*)
                    printf '%s\n' 'base S21 target refuses Pro/XP/Plus/Immersion/Hydro/e siblings'
                    return 0
                    ;;
            esac
            case "$dcent_identity_lower" in
                *s21+*)
                    printf '%s\n' 'S21+ and S21++ are distinct carriers without exact DCENT_OS package targets'
                    return 0
                    ;;
            esac
            ;;
        s21pro)
            case "$dcent_normalized" in
                *s21xp*|*s21proplus*|*s21proimm*|*s21prohydro*|*s21proe*)
                    printf '%s\n' 'S21 Pro target refuses XP/Plus/Immersion/Hydro/e siblings'
                    return 0
                    ;;
            esac
            case "$dcent_identity_lower" in
                *s21\ pro+*|*s21pro+*)
                    printf '%s\n' 'S21 Pro+ is a distinct carrier without an exact DCENT_OS package target'
                    return 0
                    ;;
            esac
            ;;
        s21xp)
            case "$dcent_normalized" in
                *s21pro*|*s21xpplus*|*s21xpimm*|*s21xphydro*|*s21xpe*)
                    printf '%s\n' 'S21 XP target refuses Pro/Plus/Immersion/Hydro/e siblings'
                    return 0
                    ;;
            esac
            case "$dcent_identity_lower" in
                *s21\ xp+*|*s21xp+*)
                    printf '%s\n' 'S21 XP+ is a distinct carrier without an exact DCENT_OS package target'
                    return 0
                    ;;
            esac
            ;;
        t21)
            case "$dcent_normalized" in
                *t21plus*|*t21imm*|*t21hydro*|*t21e*)
                    printf '%s\n' 'T21 sibling/immersion identity is outside the exact T21 target'
                    return 0
                    ;;
            esac
            case "$dcent_identity_lower" in
                *t21+*)
                    printf '%s\n' 'T21+ is a distinct carrier without an exact DCENT_OS package target'
                    return 0
                    ;;
            esac
            ;;
    esac
    return 1
}

dcent_amlogic_exact_tuple_admit() {
    dcent_tuple_variant=$1
    dcent_tuple_board=$2
    dcent_tuple_model=$3
    dcent_tuple_soc=$4
    dcent_tuple_pcb=$5
    dcent_tuple_identity_lower=$6

    if dcent_tuple_reason=$(
        dcent_amlogic_sibling_rejection \
            "$dcent_tuple_variant" "$dcent_tuple_model" "$dcent_tuple_identity_lower"
    ); then
        printf '%s\n' "$dcent_tuple_reason"
        return 1
    fi

    case "$dcent_tuple_soc" in
        *a113d*|*mesonaxg*) ;;
        *)
            printf '%s\n' 'exact Amlogic A113D/AXG SoC observation is missing'
            return 1
            ;;
    esac

    case "$dcent_tuple_variant" in
        s19jpro-aml|s19jpro|s19j)
            dcent_tuple_targets='am3s19jproaml am3s19jpro amlogics19j amlogics19jpro'
            dcent_tuple_pcbs='c76 c81'
            case "$dcent_tuple_model" in *s19jpro*) ;; *)
                printf '%s\n' 'exact S19j Pro model observation is missing'; return 1 ;;
            esac
            case "$dcent_tuple_identity_lower" in
                *s19j\ pro+*|*s19jpro+*|*s19j\ pro\ plus*|*s19jproplus*)
                    printf '%s\n' 'S19j Pro+ is not the S19j Pro Amlogic target'; return 1 ;;
            esac
            ;;
        s19jproplus)
            dcent_tuple_targets='am3s19jproplus amlogics19jproplus'
            dcent_tuple_pcbs='c76 c81'
            case "$dcent_tuple_model:$dcent_tuple_identity_lower" in
                *s19jproplus*:*|*:*s19j\ pro+*|*:*s19jpro+*|*:*s19j\ pro\ plus*) ;;
                *) printf '%s\n' 'exact S19j Pro+ model observation is missing'; return 1 ;;
            esac
            ;;
        s19xp)
            dcent_tuple_targets='am3s19xp amlogics19xp'
            dcent_tuple_pcbs='c76 c81 c83'
            case "$dcent_tuple_model" in *s19xp*) ;; *)
                printf '%s\n' 'exact S19 XP model observation is missing'; return 1 ;;
            esac
            ;;
        s19jxp)
            dcent_tuple_targets='am3s19jxp amlogics19jxp'
            dcent_tuple_pcbs='c83'
            case "$dcent_tuple_model" in *s19jxp*) ;; *)
                printf '%s\n' 'exact S19j XP model observation is missing'; return 1 ;;
            esac
            ;;
        s19kpro|s19k)
            dcent_tuple_targets='am3s19k am3s19kpro amlogics19k amlogics19kpro'
            dcent_tuple_pcbs='c81 c83'
            case "$dcent_tuple_model" in *s19kpro*|*s19k*) ;; *)
                printf '%s\n' 'exact S19k Pro model observation is missing'; return 1 ;;
            esac
            ;;
        s21)
            dcent_tuple_targets='am3s21 amlogics21'
            dcent_tuple_pcbs='c81 c83'
            case "$dcent_tuple_model" in *s21*) ;; *)
                printf '%s\n' 'exact base-S21 model observation is missing'; return 1 ;;
            esac
            ;;
        s21pro)
            dcent_tuple_targets='am3s21pro amlogics21pro'
            dcent_tuple_pcbs='cbe'
            case "$dcent_tuple_model" in *s21pro*) ;; *)
                printf '%s\n' 'exact S21 Pro model observation is missing'; return 1 ;;
            esac
            ;;
        s21xp)
            dcent_tuple_targets='am3s21xp amlogics21xp'
            dcent_tuple_pcbs='cbe'
            case "$dcent_tuple_model" in *s21xp*) ;; *)
                printf '%s\n' 'exact S21 XP model observation is missing'; return 1 ;;
            esac
            ;;
        t21)
            dcent_tuple_targets='am3t21 amlogict21'
            dcent_tuple_pcbs='c81 c83'
            case "$dcent_tuple_model" in *t21*) ;; *)
                printf '%s\n' 'exact T21 model observation is missing'; return 1 ;;
            esac
            ;;
        *)
            printf '%s\n' "unsupported Amlogic identity-gate variant: $dcent_tuple_variant"
            return 1
            ;;
    esac

    if [ -n "$dcent_tuple_board" ]; then
        dcent_tuple_target_ok=false
        for dcent_tuple_expected in $dcent_tuple_targets; do
            if [ "$dcent_tuple_board" = "$dcent_tuple_expected" ]; then
                dcent_tuple_target_ok=true
                break
            fi
        done
        if [ "$dcent_tuple_target_ok" != true ]; then
            printf '%s\n' "board_target '$dcent_tuple_board' conflicts with $dcent_tuple_variant"
            return 1
        fi
    fi

    dcent_tuple_pcb_ok=false
    dcent_tuple_observed_pcb=''
    for dcent_tuple_expected in $dcent_tuple_pcbs; do
        case "$dcent_tuple_pcb" in
            *"$dcent_tuple_expected"*)
                dcent_tuple_pcb_ok=true
                dcent_tuple_observed_pcb=$dcent_tuple_expected
                break
                ;;
        esac
    done
    if [ "$dcent_tuple_pcb_ok" != true ]; then
        printf '%s\n' "exact compatible PCB observation is missing (expected one of: $dcent_tuple_pcbs)"
        return 1
    fi

    printf '%s\n' "model/SoC/PCB tuple admitted: variant=$dcent_tuple_variant pcb=$dcent_tuple_observed_pcb soc=A113D/AXG"
    return 0
}

dcent_amlogic_normalize_signal() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]'
}

# Parse the exact KEY=value record emitted by the destructive installer and
# apply the terminal tuple gate. Keeping this parser in the tested library
# prevents the live caller from acquiring a second, weaker success path.
dcent_amlogic_identity_record_admit() {
    dcent_record_variant=$1
    dcent_record_identity=$2
    dcent_record_board=$(printf '%s\n' "$dcent_record_identity" | sed -n 's/^BOARD_TARGET=//p' | head -1)
    dcent_record_model=$(printf '%s\n' "$dcent_record_identity" | sed -n '/^MODEL=/p;/^HWID=/p;/^BOS_MODEL=/p')
    dcent_record_soc=$(printf '%s\n' "$dcent_record_identity" | sed -n '/^DT_MODEL=/p;/^DT_COMPATIBLE=/p;/^CPU_SYSTEM=/p')
    dcent_record_pcb=$(printf '%s\n' "$dcent_record_identity" | sed -n '/^PCB=/p;/^HWID=/p;/^DT_MODEL=/p;/^DT_COMPATIBLE=/p')
    dcent_record_lower=$(printf '%s' "$dcent_record_identity" | tr '[:upper:]' '[:lower:]')

    dcent_record_board=$(dcent_amlogic_normalize_signal "$dcent_record_board")
    dcent_record_model=$(dcent_amlogic_normalize_signal "$dcent_record_model")
    dcent_record_soc=$(dcent_amlogic_normalize_signal "$dcent_record_soc")
    dcent_record_pcb=$(dcent_amlogic_normalize_signal "$dcent_record_pcb")

    dcent_amlogic_exact_tuple_admit \
        "$dcent_record_variant" \
        "$dcent_record_board" \
        "$dcent_record_model" \
        "$dcent_record_soc" \
        "$dcent_record_pcb" \
        "$dcent_record_lower"
}
