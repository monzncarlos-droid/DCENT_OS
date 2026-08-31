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
#
# Braiins dialect (2026-08-30, S19k Pro only): stock Bitmain firmware exposes
# the carrier PCB revision in /config/CONF_CONTROL_BOARD (the C76/C81/C83/CBE
# token source).  BraiinsOS does not ship /config at all, its device tree
# carries no cXX token, and it exposes no sysfs eeprom node, so the direct PCB
# observation is genuinely UNOBSERVABLE under Braiins -- there is no readable
# carrier-PCB source to "fix" the probe with.  For that one dialect an
# explicitly operator-scoped alternative path exists (7th argument
# "unavailable-braiins", set only by install_amlogic_persistent.sh
# --accept-braiins-model-soc-identity): it requires the exact S19k Pro model
# token from the Braiins bosminer.toml observation, the same A113D/AXG SoC
# token, the unchanged sibling rejection, ZERO known PCB tokens in any stock
# channel (a present-but-conflicting token still refuses; the override can
# never relabel physical evidence), and a hashboard EEPROM observation free of
# foreign/partial chain preambles (the held S19k BHB56902/BHB56903 family
# preamble is 05:11).  The receipt records pcb_observation=unavailable-braiins
# honestly.  The stock-source branch above is untouched: any unit that CAN
# observe a PCB code still needs a compatible one.

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
                # Held Bitmain bmminer decomp names the distinct miner type
                # "Antminer S19k Pro+".  Normalization removes '+' and yields
                # s19kproplus, which does not contain the older s19kplus
                # substring.  Deny it explicitly before the positive
                # `s19kpro` model match below.
                *s19kplus*|*s19kproplus*|*s19kxp*|*s19kimm*|*s19khydro*)
                    printf '%s\n' 'S19k sibling/immersion identity is outside the exact S19k Pro target'
                    return 0
                    ;;
            esac
            case "$dcent_identity_lower" in
                *s19k\ pro+*|*s19kpro+*|*s19k\ pro\ plus*|*s19kproplus*)
                    printf '%s\n' 'S19k Pro+ is a distinct miner type without an exact DCENT_OS package target'
                    return 0
                    ;;
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
    dcent_tuple_soc=$(dcent_amlogic_exact_soc_tokens "$4")
    dcent_tuple_pcb=$(dcent_amlogic_exact_pcb_tokens "$5")
    dcent_tuple_identity_lower=$6
    # 7th argument is the PCB-observation dialect marker from the identity
    # record: empty (legacy direct callers) or "direct" keeps the strict
    # stock-source contract; "unavailable-braiins" selects the explicitly
    # operator-scoped Braiins alternative path below.
    case "${7:-}" in
        ''|direct) dcent_tuple_pcb_dialect=direct ;;
        unavailable-braiins) dcent_tuple_pcb_dialect=unavailable-braiins ;;
        *)
            printf '%s\n' "unsupported PCB observation dialect '${7:-}'"
            return 1
            ;;
    esac
    if [ "$dcent_tuple_pcb_dialect" = unavailable-braiins ]; then
        case "$dcent_tuple_variant" in
            s19kpro|s19k) ;;
            *)
                printf '%s\n' \
                    "Braiins model+SoC identity dialect is not held evidence for variant $dcent_tuple_variant"
                return 1
                ;;
        esac
    fi

    if dcent_tuple_reason=$(
        dcent_amlogic_sibling_rejection \
            "$dcent_tuple_variant" "$dcent_tuple_model" "$dcent_tuple_identity_lower"
    ); then
        printf '%s\n' "$dcent_tuple_reason"
        return 1
    fi

    if [ -z "$dcent_tuple_soc" ]; then
        printf '%s\n' 'exact Amlogic A113D/AXG SoC observation is missing'
        return 1
    fi

    case "$dcent_tuple_variant" in
        s19jpro-aml|s19jpro|s19j)
            dcent_tuple_targets='am3s19jproaml am3s19jpro amlogics19j amlogics19jpro'
            dcent_tuple_pcbs='c76 c81'
            dcent_tuple_models='antminers19jpro'
            case "$dcent_tuple_identity_lower" in
                *s19j\ pro+*|*s19jpro+*|*s19j\ pro\ plus*|*s19jproplus*)
                    printf '%s\n' 'S19j Pro+ is not the S19j Pro Amlogic target'; return 1 ;;
            esac
            ;;
        s19jproplus)
            dcent_tuple_targets='am3s19jproplus amlogics19jproplus'
            dcent_tuple_pcbs='c76 c81'
            dcent_tuple_models='antminers19jproplus'
            ;;
        s19xp)
            dcent_tuple_targets='am3s19xp amlogics19xp'
            dcent_tuple_pcbs='c76 c81 c83'
            dcent_tuple_models='antminers19xp'
            ;;
        s19jxp)
            dcent_tuple_targets='am3s19jxp amlogics19jxp'
            dcent_tuple_pcbs='c83'
            dcent_tuple_models='antminers19jxp'
            ;;
        s19kpro|s19k)
            dcent_tuple_targets='am3s19k am3s19kpro amlogics19k amlogics19kpro'
            dcent_tuple_pcbs='c81 c83'
            # Held `a lab unit` exposes both the commercial vendor name and the
            # Braiins NoPic model discriminator as independent observations.
            dcent_tuple_models='antminers19kpro antminers19kpronopic'
            ;;
        s21)
            dcent_tuple_targets='am3s21 amlogics21'
            dcent_tuple_pcbs='c81 c83'
            dcent_tuple_models='antminers21'
            ;;
        s21pro)
            dcent_tuple_targets='am3s21pro amlogics21pro'
            dcent_tuple_pcbs='cbe'
            dcent_tuple_models='antminers21pro'
            ;;
        s21xp)
            dcent_tuple_targets='am3s21xp amlogics21xp'
            dcent_tuple_pcbs='cbe'
            dcent_tuple_models='antminers21xp'
            ;;
        t21)
            dcent_tuple_targets='am3t21 amlogict21'
            dcent_tuple_pcbs='c81 c83'
            dcent_tuple_models='antminert21'
            ;;
        *)
            printf '%s\n' "unsupported Amlogic identity-gate variant: $dcent_tuple_variant"
            return 1
            ;;
    esac

    dcent_tuple_model_seen=false
    for dcent_tuple_observed_model in $dcent_tuple_model; do
        dcent_tuple_model_match=false
        for dcent_tuple_expected_model in $dcent_tuple_models; do
            if [ "$dcent_tuple_observed_model" = "$dcent_tuple_expected_model" ]; then
                dcent_tuple_model_match=true
                dcent_tuple_model_seen=true
                break
            fi
        done
        if [ "$dcent_tuple_model_match" != true ]; then
            printf '%s\n' "unknown or conflicting model observation '$dcent_tuple_observed_model' for $dcent_tuple_variant"
            return 1
        fi
    done
    if [ "$dcent_tuple_model_seen" != true ]; then
        printf '%s\n' "exact model observation is missing (expected one of: $dcent_tuple_models)"
        return 1
    fi

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
        for dcent_tuple_observed in $dcent_tuple_pcb; do
            if [ "$dcent_tuple_observed" = "$dcent_tuple_expected" ]; then
                dcent_tuple_pcb_ok=true
                dcent_tuple_observed_pcb=$dcent_tuple_observed
                break 2
            fi
        done
    done
    if [ "$dcent_tuple_pcb_ok" = true ]; then
        if [ "$dcent_tuple_pcb_dialect" != direct ]; then
            # The record claims the direct PCB channels are unavailable while a
            # compatible token was in fact observed.  The dialect marker must
            # never coexist with the evidence it says is missing.
            printf '%s\n' \
                "braiins dialect marker contradicts an observed compatible PCB token '$dcent_tuple_observed_pcb'"
            return 1
        fi
        printf '%s\n' "model/SoC/PCB tuple admitted: variant=$dcent_tuple_variant pcb=$dcent_tuple_observed_pcb soc=A113D/AXG"
        return 0
    fi
    if [ -n "$dcent_tuple_pcb" ]; then
        # A known carrier PCB code WAS observed in a stock channel but matches
        # no PCB admitted for this variant.  That is conflicting physical
        # evidence, and neither the stock branch nor the operator-scoped
        # Braiins override may relabel it.
        printf '%s\n' \
            "observed PCB code '$dcent_tuple_pcb' conflicts with $dcent_tuple_variant (expected one of: $dcent_tuple_pcbs)"
        return 1
    fi
    if [ "$dcent_tuple_pcb_dialect" != unavailable-braiins ]; then
        printf '%s\n' "exact compatible PCB observation is missing (expected one of: $dcent_tuple_pcbs)"
        return 1
    fi

    # Operator-scoped Braiins dialect: exact model + AXG SoC were proven above,
    # every stock PCB channel is empty, and the record-level hashboard EEPROM
    # conflict gate already ran in dcent_amlogic_identity_record_admit.
    printf '%s\n' \
        "model/SoC tuple admitted (braiins dialect, operator override): variant=$dcent_tuple_variant pcb_observation=unavailable-braiins soc=A113D/AXG"
    return 0
}

dcent_amlogic_normalize_signal() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]'
}

# Return only exact, boundary-delimited PCB identifiers. The identity sources
# are free-form strings, so substring matching would let C810, C830, or AC810
# impersonate the held C81/C83 carrier evidence.
dcent_amlogic_exact_pcb_tokens() {
    printf '%s' "$1" |
        tr '[:upper:]' '[:lower:]' |
        tr -cs '[:alnum:]' '\n' |
        sed -n '/^c76$/p;/^c81$/p;/^c83$/p;/^cbe$/p' |
        tr '\n' ' '
}

# Accept only boundary-delimited held SoC identifiers. Exact historical
# normalized forms are retained for direct callers, but near-prefix/suffix
# strings such as NotA113D, A113D0, or MesonAXG0 are never evidence.
dcent_amlogic_exact_soc_tokens() {
    dcent_soc_raw=$1
    dcent_soc_normalized=$(dcent_amlogic_normalize_signal "$dcent_soc_raw")
    case "$dcent_soc_normalized" in
        amlogica113d) printf 'a113d ' ;;
        amlogicmesonaxg|mesonaxg) printf 'axg ' ;;
    esac
    printf '%s' "$dcent_soc_raw" |
        tr '[:upper:]' '[:lower:]' |
        tr -cs '[:alnum:]' '\n' |
        sed -n '/^a113d$/p;/^axg$/p' |
        tr '\n' ' '
}

dcent_amlogic_exact_model_tokens() {
    printf '%s\n' "$1" | while IFS= read -r dcent_model_line; do
        dcent_model_value=${dcent_model_line#*=}
        dcent_model_value=$(dcent_amlogic_normalize_signal "$dcent_model_value")
        case "$dcent_model_value" in modelantminer*) dcent_model_value=${dcent_model_value#model} ;; esac
        if [ -n "$dcent_model_value" ]; then
            printf '%s ' "$dcent_model_value"
        fi
    done
    return 0
}

# Parse the exact KEY=value record emitted by the destructive installer and
# apply the terminal tuple gate. Keeping this parser in the tested library
# prevents the live caller from acquiring a second, weaker success path.
#
# Schema (2026-08-30): the historical eight fields plus two explicitly added
# observation fields.  PCB_OBSERVATION records whether any direct carrier-PCB
# channel produced a token (direct) or the operator-scoped Braiins dialect is
# in effect (unavailable-braiins); HASHBOARD_EEPROM records the chain-bus slot
# EEPROM preamble observation used as the Braiins-dialect conflict gate.
dcent_amlogic_identity_record_admit() {
    dcent_record_variant=$1
    dcent_record_identity=$2
    dcent_record_lines=$(printf '%s\n' "$dcent_record_identity" | wc -l | tr -d ' \t\r\n')
    dcent_record_legacy=false
    case "$dcent_record_lines" in
        8) dcent_record_legacy=true ;;
        10) ;;
        *)
            printf '%s\n' 'identity record requires the exact ten-field schema (historical eight-field transcripts remain admissible as direct-observation records)'
            return 1
            ;;
    esac
    for dcent_record_key in BOARD_TARGET MODEL HWID PCB BOS_MODEL DT_MODEL DT_COMPATIBLE CPU_SYSTEM; do
        dcent_record_count=$(printf '%s\n' "$dcent_record_identity" | grep -c "^$dcent_record_key=" || true)
        if [ "$dcent_record_count" -ne 1 ]; then
            printf '%s\n' "identity record requires exactly one $dcent_record_key field"
            return 1
        fi
    done
    # Historical eight-field transcripts (retained artifact dirs produced
    # before 2026-08-30) carry neither new field; they can only ever re-admit
    # through the direct/stock branch because the Braiins dialect REQUIRES the
    # explicit PCB_OBSERVATION marker, so accepting them is not a weakening.
    for dcent_record_key in PCB_OBSERVATION HASHBOARD_EEPROM; do
        dcent_record_count=$(printf '%s\n' "$dcent_record_identity" | grep -c "^$dcent_record_key=" || true)
        if [ "$dcent_record_legacy" = true ]; then
            if [ "$dcent_record_count" -ne 0 ]; then
                printf '%s\n' "legacy eight-field record must not carry a $dcent_record_key field"
                return 1
            fi
        elif [ "$dcent_record_count" -ne 1 ]; then
            printf '%s\n' "identity record requires exactly one $dcent_record_key field"
            return 1
        fi
    done
    dcent_record_board=$(printf '%s\n' "$dcent_record_identity" | sed -n 's/^BOARD_TARGET=//p' | head -1)
    dcent_record_model=$(printf '%s\n' "$dcent_record_identity" | sed -n '/^MODEL=/p;/^BOS_MODEL=/p')
    dcent_record_soc=$(printf '%s\n' "$dcent_record_identity" | sed -n '/^DT_MODEL=/p;/^DT_COMPATIBLE=/p;/^CPU_SYSTEM=/p')
    dcent_record_pcb=$(printf '%s\n' "$dcent_record_identity" | sed -n '/^PCB=/p;/^HWID=/p;/^DT_MODEL=/p;/^DT_COMPATIBLE=/p')
    dcent_record_lower=$(printf '%s' "$dcent_record_identity" | tr '[:upper:]' '[:lower:]')

    if [ "$dcent_record_legacy" = true ]; then
        dcent_record_dialect=direct
        dcent_record_hb=''
        dcent_record_hb_conflict=false
    else
        dcent_record_dialect=$(printf '%s\n' "$dcent_record_identity" | sed -n 's/^PCB_OBSERVATION=//p' | head -1)
    case "$dcent_record_dialect" in
        direct|unavailable-braiins) ;;
        *)
            printf '%s\n' "PCB_OBSERVATION dialect '$dcent_record_dialect' is not exact"
            return 1
            ;;
    esac

    # Hashboard chain-bus EEPROM observation grammar.  The installer probes the
    # three held S19k slot addresses (0x50/0x51/0x52 on bus 1) with the same
    # /usr/sbin/i2cget byte reads the Track-1 live identity runner proved on
    # .88.  "absent" is a failed/empty read; "05:11" is the held BHB56902/
    # BHB56903 family preamble; "foreign:"/"partial:" mark populated slots that
    # did not read back the held preamble and are hard conflicts for the
    # Braiins dialect.
    dcent_record_hb=$(printf '%s\n' "$dcent_record_identity" | sed -n 's/^HASHBOARD_EEPROM=//p' | head -1)
    dcent_record_hb_conflict=false
    case "$dcent_record_hb" in
        reader-unavailable) ;;
        0x50=*,0x51=*,0x52=*)
            dcent_record_hb_rest=$dcent_record_hb
            dcent_record_hb_index=0
            while [ -n "$dcent_record_hb_rest" ]; do
                dcent_record_hb_entry=${dcent_record_hb_rest%%,*}
                dcent_record_hb_index=$((dcent_record_hb_index + 1))
                case "$dcent_record_hb_index:$dcent_record_hb_entry" in
                    1:0x50=*|2:0x51=*|3:0x52=*) ;;
                    *)
                        printf '%s\n' 'HASHBOARD_EEPROM observation grammar is not exact'
                        return 1
                        ;;
                esac
                case "$dcent_record_hb_entry" in
                    0x50=absent|0x51=absent|0x52=absent|0x50=05:11|0x51=05:11|0x52=05:11) ;;
                    0x50=foreign:*|0x51=foreign:*|0x52=foreign:*|0x50=partial:*|0x51=partial:*|0x52=partial:*)
                        dcent_record_hb_conflict=true
                        ;;
                    *)
                        printf '%s\n' 'HASHBOARD_EEPROM observation grammar is not exact'
                        return 1
                        ;;
                esac
                if [ "$dcent_record_hb_rest" = "$dcent_record_hb_entry" ]; then
                    dcent_record_hb_rest=''
                else
                    dcent_record_hb_rest=${dcent_record_hb_rest#*,}
                fi
            done
            [ "$dcent_record_hb_index" -eq 3 ] || {
                printf '%s\n' 'HASHBOARD_EEPROM observation grammar is not exact'
                return 1
            }
            ;;
        *)
            printf '%s\n' 'HASHBOARD_EEPROM observation grammar is not exact'
            return 1
            ;;
    esac

    if [ "$dcent_record_dialect" = unavailable-braiins ]; then
        # The exact S19k Pro model proof must come from the one model source
        # Braiins actually ships (/etc/bosminer.toml -> BOS_MODEL), never from
        # a stock /config remnant riding the operator override.
        dcent_record_bos=$(printf '%s\n' "$dcent_record_identity" | sed -n '/^BOS_MODEL=/p')
        dcent_record_bos=$(dcent_amlogic_exact_model_tokens "$dcent_record_bos")
        if [ -z "$dcent_record_bos" ]; then
            printf '%s\n' 'braiins dialect requires an exact BOS_MODEL model observation'
            return 1
        fi
        if [ "$dcent_record_hb_conflict" = true ]; then
            printf '%s\n' \
                'braiins dialect refuses a foreign or partial hashboard EEPROM preamble (held S19k family is 05:11)'
            return 1
        fi
    fi
    fi

    dcent_record_board=$(dcent_amlogic_normalize_signal "$dcent_record_board")
    dcent_record_model=$(dcent_amlogic_exact_model_tokens "$dcent_record_model")
    dcent_amlogic_exact_tuple_admit \
        "$dcent_record_variant" \
        "$dcent_record_board" \
        "$dcent_record_model" \
        "$dcent_record_soc" \
        "$dcent_record_pcb" \
        "$dcent_record_lower" \
        "$dcent_record_dialect"
}
