#!/bin/sh
# Host tests for scripts/lib/public_artifact_release_gate.sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/lib/public_artifact_release_gate.sh"

fail_test() {
    echo "public artifact release gate test failed: $*" >&2
    exit 1
}

# Lab/DEV: no public flags, non-release status — must be a no-op.
DCENT_RELEASE_IMAGE=0
DCENT_PACKAGE_STATUS=lab_unsigned
DCENT_PUBLIC_ARTIFACT=0
DCENT_CUSTOMER_IMAGE=0
dcent_require_release_image_for_public_artifact \
    || fail_test "lab_unsigned DEV build was blocked"

# Default packager status is customer-facing.
DCENT_PACKAGE_STATUS=release
DCENT_RELEASE_IMAGE=0
if dcent_require_release_image_for_public_artifact; then
    fail_test "release-status without DCENT_RELEASE_IMAGE=1 was allowed"
fi

DCENT_PACKAGE_STATUS=release
DCENT_RELEASE_IMAGE=1
dcent_require_release_image_for_public_artifact \
    || fail_test "release-status + DCENT_RELEASE_IMAGE=1 was blocked"

# Explicit public flag even with lab_unsigned must fail closed.
DCENT_PACKAGE_STATUS=lab_unsigned
DCENT_RELEASE_IMAGE=0
DCENT_PUBLIC_ARTIFACT=1
if dcent_require_release_image_for_public_artifact; then
    fail_test "DCENT_PUBLIC_ARTIFACT=1 without RELEASE was allowed"
fi

DCENT_PUBLIC_ARTIFACT=0
DCENT_CUSTOMER_IMAGE=1
if dcent_require_release_image_for_public_artifact; then
    fail_test "DCENT_CUSTOMER_IMAGE=1 without RELEASE was allowed"
fi

DCENT_CUSTOMER_IMAGE=1
DCENT_RELEASE_IMAGE=1
dcent_require_release_image_for_public_artifact \
    || fail_test "customer image with RELEASE was blocked"

echo "public artifact release gate tests passed"
