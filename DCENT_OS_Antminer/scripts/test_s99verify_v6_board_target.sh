#!/bin/sh
# WS-F6: S99verify V6 is board_target-scoped. Not every am3-aml is TAS5782M.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
src="$root/br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S99verify"
[ -r "$src" ] || { echo "FAIL: S99verify missing at $src" >&2; exit 1; }

grep -q 'not all am3-aml = TAS5782M' "$src" \
  || { echo "FAIL: V6 must refuse unknown am3-aml as TAS5782M" >&2; exit 1; }
grep -q 'S19k-class, not TAS5782M' "$src" \
  || { echo "FAIL: V6 must skip S19k without claiming TAS5782M" >&2; exit 1; }
grep -q 'board_target=\$bt: TAS5782M audio DAC voltage' "$src" \
  || { echo "FAIL: V6 TAS5782M skip must name board_target" >&2; exit 1; }

for copy in \
  "$root/br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S99verify" \
  "$root/br2_external_dcentos/board/cvitek/cv1835-s19jpro/rootfs-overlay/etc/init.d/S99verify" \
  "$root/br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/rootfs-overlay/etc/init.d/S99verify"
do
  grep -q 'not all am3-aml = TAS5782M' "$copy" \
    || { echo "FAIL: $copy missing V6 board_target scope" >&2; exit 1; }
done

echo "PASS: S99verify V6 is board_target-scoped (not all am3-aml = TAS5782M)"
