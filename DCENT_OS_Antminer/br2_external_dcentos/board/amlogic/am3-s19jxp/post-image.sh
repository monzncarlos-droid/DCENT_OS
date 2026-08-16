#!/bin/sh
#
# DCENTos post-image script - am3-s19jxp (S19j XP Amlogic exact package lane).
#
# S19j XP reuses the shared A113D rootfs-window package writer while carrying
# its own overlay, defconfig, exact build-input binding, and output identity.
#

set -e

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
exec "$SCRIPT_DIR/../am3-s21/post-image.sh" "$@"
