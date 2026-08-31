#!/bin/sh
# Hermetic parser tests plus the declared local Amlogic evidence catalog.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
WORKSPACE_DIR=$(CDPATH= cd -- "$PROJECT_DIR/../.." && pwd)
CATALOG="$PROJECT_DIR/contracts/boot-artifacts/v1/amlogic.json"
RAW_ENV="$WORKSPACE_DIR/knowledge-base/extractions/s19k/live-probe-78-2026-04-29/00-system/nand_env.bin"

command -v python3 >/dev/null 2>&1 || {
    echo "ERROR: boot-artifact auditor tests require python3" >&2
    exit 1
}

python3 "$SCRIPT_DIR/test_boot_artifact_auditor.py" -q
python3 "$SCRIPT_DIR/audit_boot_artifacts.py" \
    --catalog "$CATALOG" \
    --project-root "$PROJECT_DIR" \
    --workspace-root "$WORKSPACE_DIR"

# A public checkout legitimately lacks ignored capture bytes. When this raw
# archive is present, require the entire declared local evidence set so an
# incomplete maintainer corpus cannot masquerade as an archive-closeout pass.
if [ -f "$RAW_ENV" ]; then
    python3 "$SCRIPT_DIR/audit_boot_artifacts.py" \
        --catalog "$CATALOG" \
        --project-root "$PROJECT_DIR" \
        --workspace-root "$WORKSPACE_DIR" \
        --require-local-evidence
fi

echo "boot-artifact gate: parser and applicable-policy checks completed"
