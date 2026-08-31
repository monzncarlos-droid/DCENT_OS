#!/bin/sh
#
# T21 stock-revert compatibility entrypoint.
#
# The previous implementation copied the S21 Amlogic rootfs window and U-Boot
# environment contract without T21-specific storage evidence. That is not a
# recovery method. Keep the historical command name discoverable, but refuse
# every invocation before reading a target, archive, device, or environment.

set -eu

EX_UNAVAILABLE=69

case "${1:-}" in
    -h|--help)
        cat <<'EOF'
Usage: revert_to_stock_am3_aml_t21.sh

Unavailable: no T21 controller-specific stock-revert contract is implemented.
Required evidence includes /proc/mtd geometry, U-Boot environment layout,
write/readback behavior, boot selection, rollback, and physical recovery.
EOF
        ;;
esac

echo "ERROR: T21 stock revert is unavailable; controller-specific storage and recovery contracts are unproven." >&2
exit "$EX_UNAVAILABLE"
