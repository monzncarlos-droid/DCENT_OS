#!/bin/sh
# Compatibility entry point for the hardened S19k Track-1 /tmp deployer.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$SCRIPT_DIR/dcentrald_s19k_tmp_deploy.sh" "$@"
