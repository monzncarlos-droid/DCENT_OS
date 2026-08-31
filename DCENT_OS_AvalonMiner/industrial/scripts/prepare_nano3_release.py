#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only

"""Prepare or rehearse a local, donor-bound Nano 3 release bundle.

This entry point never signs, flashes, opens USB, or copies donor bytes.  The
``manifest`` command hashes the operator-held factory donor and rollback
artifact and writes canonical unsigned v5 JSON for an external release-key
ceremony.  The ``rehearse`` command accepts only a completed signed bundle and
emits the deterministic interruption campaign bound to the actual
recovery-first executor profile.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
TOOLBOX_SRC = WORKSPACE_ROOT / "projects" / "dcent-toolbox" / "src"
sys.path.insert(0, str(TOOLBOX_SRC))

from dcent_toolbox.core.k230_release_manifest import (  # noqa: E402
    K230_RELEASE_MANIFEST_SCHEMA,
    K230_RELEASE_PHASE_FIRST_DEPLOYMENT,
    K230_RELEASE_PHASE_PRODUCTION,
    K230_FIRST_DEPLOYMENT_PROOF_LEVEL,
    K230BuildProvenance,
    build_k230_release_manifest,
    default_k230_release_manifest_path,
    verify_k230_release_bundle,
)
from dcent_toolbox.core.k230_rootfs_transaction import (  # noqa: E402
    canonical_nano3_rootfs_rehearsal_bytes,
    rehearse_nano3_rootfs_transaction,
)
from dcent_toolbox.core.nano3_production_qualification import (  # noqa: E402
    NANO3_PROTECTED_COEXISTENCE_SCOPE,
)


DEFAULT_BUILDER = Path(
    "DCENT_OS_AvalonMiner/scripts/build_nano3_stock_chain_firstlight.sh"
)
DEFAULT_IMAGE_TOOL = Path(
    "projects/dcent-toolbox/src/dcent_toolbox/core/k230_image_build.py"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=WORKSPACE_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _workspace_path(relative: Path, label: str) -> Path:
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} must be a workspace-relative path")
    resolved = (WORKSPACE_ROOT / relative).resolve()
    try:
        resolved.relative_to(WORKSPACE_ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} escapes the workspace") from exc
    if not resolved.is_file():
        raise ValueError(f"{label} does not exist: {relative}")
    return resolved


def _write_new(path: Path, data: bytes) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _manifest(args: argparse.Namespace) -> int:
    source_revision = _git("rev-parse", "HEAD")
    status = _git("status", "--porcelain", "--untracked-files=all")
    clean_tree = not bool(status)
    if args.require_clean_source and not clean_tree:
        raise RuntimeError(
            "source worktree is dirty; use an isolated clean worktree for a production manifest"
        )

    builder_path = _workspace_path(args.builder, "builder")
    image_tool_path = _workspace_path(args.image_tool, "image tool")
    provenance = K230BuildProvenance(
        source_revision=source_revision,
        clean_tree=clean_tree,
        builder_id=args.builder.as_posix(),
        builder_sha256=_sha256(builder_path),
        image_tool_id=args.image_tool.as_posix(),
        image_tool_sha256=_sha256(image_tool_path),
        container_image=args.container_image,
        container_digest=args.container_digest,
    )
    proof_level = args.proof_level or (
        K230_FIRST_DEPLOYMENT_PROOF_LEVEL
        if args.release_phase == K230_RELEASE_PHASE_FIRST_DEPLOYMENT
        else "bench-stock-hashing-observed"
    )
    manifest = build_k230_release_manifest(
        image_path=args.image,
        donor_path=args.donor,
        rollback_path=args.rollback,
        model="nano3",
        expected_mutation_slots=("rootfs_1", "rootfs_2"),
        build_provenance=provenance,
        release_generation=args.generation,
        safety_qualification_path=args.safety_qualification,
        safety_qualification_signature_path=args.safety_signature,
        safety_public_key_path=args.safety_public_key,
        safety_evidence_root=args.safety_evidence_root,
        authorization_class=args.authorization_class,
        verification_time_utc=args.verification_time_utc,
        release_phase=args.release_phase,
        protected_live_proof_path=args.live_proof,
        protected_live_proof_signature_path=args.live_proof_signature,
        protected_live_proof_evidence_root=args.live_proof_evidence_root,
        predecessor_manifest_path=args.predecessor_manifest,
        predecessor_signature_path=args.predecessor_signature,
        predecessor_deployment_permit_path=args.predecessor_deployment_permit,
        predecessor_deployment_permit_signature_path=(
            args.predecessor_deployment_permit_signature
        ),
        proof_level=proof_level,
        rollback_proof_level=args.rollback_proof_level,
        proof_evidence_paths=args.proof_evidence,
        rollback_evidence_paths=args.rollback_evidence,
    )
    output = args.output or default_k230_release_manifest_path(args.image)
    _write_new(output, manifest)
    result = {
        "manifest": str(output),
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "schema": K230_RELEASE_MANIFEST_SCHEMA,
        "source_revision": source_revision,
        "clean_tree": clean_tree,
        "release_phase": args.release_phase,
        "signed": False,
        "production_authorized": False,
        "next_step": "external Ed25519 release-key signature over exact manifest bytes",
    }
    print(json.dumps(result, sort_keys=True))
    return 0


def _rehearse(args: argparse.Namespace) -> int:
    verification = verify_k230_release_bundle(
        image_path=args.image,
        model="nano3",
        erase_data=False,
        manifest_path=args.manifest,
        signature_path=args.signature,
        rollback_path=args.rollback,
        safety_qualification_path=args.safety_qualification,
        safety_qualification_signature_path=args.safety_signature,
        safety_public_key_path=args.safety_public_key,
        safety_evidence_root=args.safety_evidence_root,
        expected_authorization_class=args.authorization_class,
        protected_live_proof_path=args.live_proof,
        protected_live_proof_signature_path=args.live_proof_signature,
        protected_live_proof_evidence_root=args.live_proof_evidence_root,
        verification_time_utc=args.verification_time_utc,
    )
    report = rehearse_nano3_rootfs_transaction(verification)
    encoded = canonical_nano3_rootfs_rehearsal_bytes(report)
    if args.output:
        _write_new(args.output, encoded)
    else:
        sys.stdout.buffer.write(encoded)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    manifest = subparsers.add_parser(
        "manifest", help="build canonical unsigned v5 manifest from a local donor"
    )
    manifest.add_argument("--image", type=Path, required=True)
    manifest.add_argument("--donor", type=Path, required=True)
    manifest.add_argument("--rollback", type=Path, required=True)
    manifest.add_argument("--output", type=Path)
    manifest.add_argument("--generation", type=int, required=True)
    manifest.add_argument("--container-image", required=True)
    manifest.add_argument("--container-digest", required=True)
    manifest.add_argument("--builder", type=Path, default=DEFAULT_BUILDER)
    manifest.add_argument("--image-tool", type=Path, default=DEFAULT_IMAGE_TOOL)
    manifest.add_argument("--require-clean-source", action="store_true")
    manifest.add_argument("--safety-qualification", type=Path, required=True)
    manifest.add_argument("--safety-signature", type=Path, required=True)
    manifest.add_argument("--safety-public-key", type=Path, required=True)
    manifest.add_argument("--safety-evidence-root", type=Path, required=True)
    manifest.add_argument(
        "--authorization-class",
        choices=(NANO3_PROTECTED_COEXISTENCE_SCOPE,),
        required=True,
    )
    manifest.add_argument(
        "--verification-time-utc", type=int, default=int(time.time())
    )
    manifest.add_argument(
        "--release-phase",
        choices=(
            K230_RELEASE_PHASE_FIRST_DEPLOYMENT,
            K230_RELEASE_PHASE_PRODUCTION,
        ),
        required=True,
    )
    manifest.add_argument("--live-proof", type=Path)
    manifest.add_argument("--live-proof-signature", type=Path)
    manifest.add_argument("--live-proof-evidence-root", type=Path)
    manifest.add_argument("--predecessor-manifest", type=Path)
    manifest.add_argument("--predecessor-signature", type=Path)
    manifest.add_argument("--predecessor-deployment-permit", type=Path)
    manifest.add_argument(
        "--predecessor-deployment-permit-signature", type=Path
    )
    manifest.add_argument(
        "--proof-level",
    )
    manifest.add_argument(
        "--rollback-proof-level",
        default="bench-factory-restore-boot-observed",
    )
    manifest.add_argument("--proof-evidence", type=Path, action="append", default=[])
    manifest.add_argument(
        "--rollback-evidence", type=Path, action="append", default=[]
    )
    manifest.set_defaults(func=_manifest)

    rehearse = subparsers.add_parser(
        "rehearse", help="verify signed bundle and run offline interruption campaign"
    )
    rehearse.add_argument("--image", type=Path, required=True)
    rehearse.add_argument("--manifest", type=Path, required=True)
    rehearse.add_argument("--signature", type=Path, required=True)
    rehearse.add_argument("--rollback", type=Path, required=True)
    rehearse.add_argument("--safety-qualification", type=Path, required=True)
    rehearse.add_argument("--safety-signature", type=Path, required=True)
    rehearse.add_argument("--safety-public-key", type=Path, required=True)
    rehearse.add_argument("--safety-evidence-root", type=Path, required=True)
    rehearse.add_argument(
        "--authorization-class",
        choices=(NANO3_PROTECTED_COEXISTENCE_SCOPE,),
        required=True,
    )
    rehearse.add_argument(
        "--verification-time-utc", type=int, default=int(time.time())
    )
    rehearse.add_argument("--live-proof", type=Path)
    rehearse.add_argument("--live-proof-signature", type=Path)
    rehearse.add_argument("--live-proof-evidence-root", type=Path)
    rehearse.add_argument("--output", type=Path)
    rehearse.set_defaults(func=_rehearse)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        return args.func(args)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
