#!/bin/sh
#
# Fail-closed gate for customer/public firmware artifacts.
# Lab/DEV builds (DCENT_PACKAGE_STATUS=lab_unsigned, --lab-unsigned,
# DCENT_PUBLIC_ARTIFACT unset) are unchanged.
#
# Usage (sourced):
#   . scripts/lib/public_artifact_release_gate.sh
#   dcent_require_release_image_for_public_artifact || exit 1
#
# A public/customer run is any of:
#   - DCENT_PUBLIC_ARTIFACT=1
#   - DCENT_CUSTOMER_IMAGE=1
#   - DCENT_PACKAGE_STATUS in {release,production,stable} (default packagers)
#
# Those runs require DCENT_RELEASE_IMAGE=1. Do not use this helper to
# lock lab images.

dcent_public_artifact_truthy() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|y|Y) return 0 ;;
        *) return 1 ;;
    esac
}

dcent_public_artifact_release_status() {
    case "${1:-}" in
        release|production|stable) return 0 ;;
        *) return 1 ;;
    esac
}

dcent_is_public_or_customer_firmware_artifact() {
    if dcent_public_artifact_truthy "${DCENT_PUBLIC_ARTIFACT:-0}"; then
        return 0
    fi
    if dcent_public_artifact_truthy "${DCENT_CUSTOMER_IMAGE:-0}"; then
        return 0
    fi
    dcent_public_artifact_release_status "${DCENT_PACKAGE_STATUS:-}"
}

# Returns 0 when this packaging run may proceed.
# Returns 1 when a public/customer artifact would be produced without RELEASE.
dcent_require_release_image_for_public_artifact() {
    if ! dcent_is_public_or_customer_firmware_artifact; then
        return 0
    fi
    if dcent_public_artifact_truthy "${DCENT_RELEASE_IMAGE:-0}"; then
        return 0
    fi
    echo "ERROR: public/customer firmware artifact requires DCENT_RELEASE_IMAGE=1 (got '${DCENT_RELEASE_IMAGE:-0}', DCENT_PACKAGE_STATUS='${DCENT_PACKAGE_STATUS:-}', DCENT_PUBLIC_ARTIFACT='${DCENT_PUBLIC_ARTIFACT:-0}', DCENT_CUSTOMER_IMAGE='${DCENT_CUSTOMER_IMAGE:-0}')." >&2
    echo "       Lab/DEV builds: leave DCENT_PUBLIC_ARTIFACT/DCENT_CUSTOMER_IMAGE unset and use DCENT_PACKAGE_STATUS=lab_unsigned (or --lab-unsigned)." >&2
    return 1
}
