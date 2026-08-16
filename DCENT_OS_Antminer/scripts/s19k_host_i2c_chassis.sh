#!/bin/sh
#
# Read-only host i2c-1 AT24 chassis observe for S19k Pro.
# Names seated slots from i2cdetect 0x50/0x51/0x52 and optional
# bosminer eeprom-parse |S/N| tables. Never binds a tty.
#
#   --from-detect FILE   parse an i2cdetect grid (host-testable)
#   --from-parse FILE    parse bosminer eeprom-parse / platform table
#   --live               i2cdetect -y 1 only if DCENT_S19K_HOST_I2C_LIVE=1
#
# Never i2cset. Never opens /dev/ttyS*. CLEAR_FOR_FLASH stays false.

set -eu

FROM_DETECT=""
FROM_PARSE=""
LIVE=false

usage() {
    cat >&2 <<USAGE
Usage: $(basename "$0") [--from-detect FILE] [--from-parse FILE] [--live]
  host i2c-1 AT24 chassis observe. Never i2cset. Never binds tty.
USAGE
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --from-detect)
            [ $# -ge 2 ] || usage
            FROM_DETECT=$2
            shift 2
            ;;
        --from-parse)
            [ $# -ge 2 ] || usage
            FROM_PARSE=$2
            shift 2
            ;;
        --live)
            LIVE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "ERROR: unknown arg: $1" >&2
            usage
            ;;
    esac
done

if [ "$LIVE" = true ]; then
    if [ "${DCENT_S19K_HOST_I2C_LIVE:-}" != "1" ]; then
        echo "ERROR: --live requires DCENT_S19K_HOST_I2C_LIVE=1" >&2
        exit 1
    fi
    command -v i2cdetect >/dev/null 2>&1 || {
        echo "ERROR: i2cdetect missing" >&2
        exit 1
    }
    FROM_DETECT_TEXT=$(i2cdetect -y 1)
else
    [ -n "$FROM_DETECT" ] || {
        echo "ERROR: --from-detect FILE required unless --live" >&2
        exit 1
    }
    [ -f "$FROM_DETECT" ] || {
        echo "ERROR: missing $FROM_DETECT" >&2
        exit 1
    }
    FROM_DETECT_TEXT=$(cat "$FROM_DETECT")
fi

ROW=$(printf '%s\n' "$FROM_DETECT_TEXT" | sed -n 's/^[[:space:]]*50:[[:space:]]*//p' | head -1)
[ -n "$ROW" ] || {
    echo "ERROR: i2cdetect grid missing 50: row" >&2
    exit 1
}

P50=false
P51=false
P52=false
I2C_LIST=""
IDX=0
for TOK in $ROW; do
    ADDR=$((0x50 + IDX))
    case $ADDR in
        80)
            if [ "$TOK" != "--" ]; then
                P50=true
                I2C_LIST="${I2C_LIST}0x50,"
            fi
            ;;
        81)
            if [ "$TOK" != "--" ]; then
                P51=true
                I2C_LIST="${I2C_LIST}0x51,"
            fi
            ;;
        82)
            if [ "$TOK" != "--" ]; then
                P52=true
                I2C_LIST="${I2C_LIST}0x52,"
            fi
            ;;
    esac
    IDX=$((IDX + 1))
done
I2C_LIST=${I2C_LIST%,}

SERIALS=""
PHYSICALS=""
if [ -n "$FROM_PARSE" ]; then
    [ -f "$FROM_PARSE" ] || {
        echo "ERROR: missing $FROM_PARSE" >&2
        exit 1
    }
    SERIALS=$(sed -n 's/^[[:space:]]*|S\/N[[:space:]]*|//p' "$FROM_PARSE" | awk -F'|' '{
        s=$1
        gsub(/^[ \t]+|[ \t]+$/, "", s)
        if (length(s)==17) print s
    }')
    for S in $SERIALS; do
        case $S in
            JYZZYR6BCJHCA0JRG) PHYSICALS="${PHYSICALS}1," ;;
            JYZZYR6BCJHCA0KRG) PHYSICALS="${PHYSICALS}2," ;;
            JYZZYR6BCJHCA0HNX) PHYSICALS="${PHYSICALS}3," ;;
        esac
    done
    PHYSICALS=${PHYSICALS%,}
    SERIALS=$(printf '%s\n' "$SERIALS" | tr '\n' ',' | sed 's/,$//')
fi

echo "schema=dcentos.s19k-host-i2c-chassis/v1"
echo "i2c_bus=1"
echo "at24_0x50=$P50"
echo "at24_0x51=$P51"
echo "at24_0x52=$P52"
echo "i2cset=false"
echo "tty_bound=false"
echo "S19K_HOST_I2C chassis=${PHYSICALS:-} i2c=${I2C_LIST} serial=${SERIALS:-} tty=unbound"
echo "note=host i2c-1 AT24 names chassis; refuse as board#↔tty"
