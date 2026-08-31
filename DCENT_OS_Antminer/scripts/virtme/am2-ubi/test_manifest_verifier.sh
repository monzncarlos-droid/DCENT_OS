#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 "$SCRIPT_DIR/test_manifest_verifier.py"
