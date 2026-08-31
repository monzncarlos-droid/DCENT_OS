#!/usr/bin/env python3
"""Run the repeatable, offline DCENT_OS-for-ESP production gauntlet."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hardware_evidence import INDEX_PATH, load_evidence_index, promotion_status, sha256_file
from promotion_candidate import (
    candidate_source_is_clean,
    git_fact,
    git_head,
    load_descriptor,
    require_valid_descriptor,
    workspace_version,
)
from target_matrix import find_target, load_manifest, require_valid, targets_for_scope

ROOT = Path(__file__).resolve().parents[1]
STAGES = ("static", "host", "check", "package")


def source_date_epoch() -> str:
    result = subprocess.run(
        ["git", "log", "-1", "--format=%ct", "--", "."],
        cwd=ROOT,
        text=True,
        encoding="ascii",
        errors="strict",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    value = result.stdout.strip()
    if result.returncode != 0 or not value.isdigit():
        raise RuntimeError("cannot derive deterministic SOURCE_DATE_EPOCH from git")
    return value


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def create_owned_build_root() -> Path:
    if os.name != "nt":
        return Path(tempfile.mkdtemp(prefix="dcentaxe-gauntlet-"))
    drive = os.environ.get("SystemDrive", "C:")
    for suffix in "0123456789abcdefghijklmnopqrstuvwxyz":
        candidate = Path(f"{drive}\\d{suffix}")
        try:
            candidate.mkdir()
            return candidate
        except FileExistsError:
            continue
    raise RuntimeError("no short C:\\d? build root is available")


def target_build_dir(build_root: Path, board_target: str) -> Path:
    if os.name == "nt":
        short_name = hashlib.sha256(board_target.encode("ascii")).hexdigest()[:4]
        return build_root / short_name
    return build_root / board_target


def run_command(command: list[str], env: dict[str, str] | None = None) -> dict[str, Any]:
    started = utc_now()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output = completed.stdout or ""
    return {
        "command": command,
        "started_at": started,
        "finished_at": utc_now(),
        "exit_code": completed.returncode,
        "passed": completed.returncode == 0,
        "output_tail": output[-12000:],
    }


def host_environment() -> dict[str, str]:
    """Return a native host build environment, including MSVC when available."""
    env = dict(os.environ)
    if os.name != "nt" or shutil.which("link", path=env.get("PATH")):
        return env
    vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if not vswhere.is_file():
        return env
    located = subprocess.run(
        [str(vswhere), "-latest", "-products", "*", "-property", "installationPath"],
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        check=False,
    )
    install_root = Path(located.stdout.strip())
    vcvars = install_root / "VC/Auxiliary/Build/vcvars64.bat"
    if located.returncode != 0 or not vcvars.is_file():
        return env
    initialized = subprocess.run(
        f'cmd.exe /d /c ""{vcvars}" >nul && set"',
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        check=False,
    )
    if initialized.returncode != 0:
        return env
    for line in initialized.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key:
            env[key] = value
            if key.lower() == "path":
                env["PATH"] = value
    return env


def target_environment(
    target: dict[str, Any],
    build_dir: Path,
    candidate_path: Path | None = None,
    candidate_descriptor: dict[str, Any] | None = None,
) -> tuple[dict[str, str], Path]:
    env = dict(os.environ)
    env.setdefault("CC_xtensa_esp32s3_espidf", "xtensa-esp32s3-elf-gcc")
    jobs = env.get("DCENT_GAUNTLET_JOBS", "2")
    env["CARGO_BUILD_JOBS"] = jobs
    env["CMAKE_BUILD_PARALLEL_LEVEL"] = jobs
    env["CARGO_TARGET_DIR"] = str(build_dir)
    env.setdefault("SOURCE_DATE_EPOCH", source_date_epoch())
    if candidate_descriptor is not None:
        assert candidate_path is not None
        candidate_id = candidate_descriptor["candidate_id"]
        env["SOURCE_DATE_EPOCH"] = candidate_descriptor["source"]["source_date_epoch"]
        env["DCENTAXE_PROMOTION_CANDIDATE_PATH"] = str(candidate_path.resolve())
        env["DCENTAXE_PROMOTION_CANDIDATE_VALIDATED"] = candidate_id
        env["DCENTAXE_PROMOTION_CANDIDATE_CONFIRM"] = f"build-{target['board_target']}"
    if target["flash_layout"] == "n16r8":
        env["ESP_IDF_SDKCONFIG_DEFAULTS"] = "sdkconfig.defaults;sdkconfig.defaults.16mb"
        partitions = ROOT / "partitions-16mb.csv"
    else:
        env["ESP_IDF_SDKCONFIG_DEFAULTS"] = "sdkconfig.defaults"
        partitions = ROOT / "partitions.csv"
    return env, partitions


def cargo_command(action: str, target: dict[str, Any]) -> list[str]:
    command = [
        "cargo",
        action,
        "--locked",
        "-p",
        "dcentaxe",
        "--no-default-features",
        "--features",
        target["feature"],
    ]
    if action == "build":
        command.insert(2, "--release")
    return command


def static_gate() -> dict[str, Any]:
    commands = [
        [sys.executable, "scripts/target_matrix.py", "validate"],
        [sys.executable, "scripts/test_target_matrix.py"],
        [sys.executable, "scripts/hardware_evidence.py", "validate"],
        [sys.executable, "scripts/test_hardware_evidence.py"],
        [sys.executable, "scripts/test_promotion_candidate.py"],
        [sys.executable, "scripts/test_hardware_session.py"],
    ]
    results = [run_command(command) for command in commands]
    return {"stage": "static", "passed": all(item["passed"] for item in results), "commands": results}


def host_gate() -> dict[str, Any]:
    commands = [["cargo", "+stable", "fmt", "--all", "--", "--check"]]
    crates = (
        ("dcentaxe-bap", ["--no-default-features"]),
        ("dcentaxe-stratum", []),
        ("dcentaxe-mining", []),
        ("dcentaxe-stratum-v2", []),
        ("dcentaxe-asic", []),
        ("dcentaxe-core", []),
        ("dcentaxe-lora", []),
        ("dcentaxe-hal", ["--no-default-features", "--features", "pins-bitaxe"]),
        ("dcentaxe-asic", ["--features", "asic-lt0051"]),
    )
    native_target = "x86_64-pc-windows-msvc" if os.name == "nt" else "x86_64-unknown-linux-gnu"
    for crate, extra in crates:
        commands.append(
            [
                "cargo",
                "+stable",
                "test",
                "-p",
                crate,
                *extra,
                "--lib",
                "--locked",
                "--target",
                native_target,
            ]
        )
    env = host_environment()
    results = [run_command(command, env) for command in commands]
    return {"stage": "host", "passed": all(item["passed"] for item in results), "commands": results}


def check_gate(
    target: dict[str, Any],
    build_dir: Path,
    candidate_path: Path | None = None,
    candidate_descriptor: dict[str, Any] | None = None,
) -> dict[str, Any]:
    env, _partitions = target_environment(
        target, build_dir, candidate_path, candidate_descriptor
    )
    result = run_command(cargo_command("check", target), env)
    return {"stage": "check", "passed": result["passed"], "commands": [result]}


def package_gate(
    target: dict[str, Any],
    build_dir: Path,
    dist_dir: Path,
    candidate_path: Path | None = None,
    candidate_descriptor: dict[str, Any] | None = None,
) -> dict[str, Any]:
    env, partitions = target_environment(
        target, build_dir, candidate_path, candidate_descriptor
    )
    qualification = candidate_descriptor is not None
    effective_target = candidate_descriptor["registry_row"] if qualification else target
    production_signature_required = effective_target["install_policy"] == "production"
    if production_signature_required:
        env["DCENT_ENFORCE_SIGNED_OTA"] = "1"
    if qualification:
        env["DCENTAXE_PROMOTION_CANDIDATE_PACKAGE_CONFIRM"] = (
            f"package-{target['board_target']}"
        )
    build = run_command(cargo_command("build", target), env)
    commands = [build]
    if not build["passed"]:
        return {"stage": "package", "passed": False, "commands": commands}

    release_dir = build_dir / "xtensa-esp32s3-espidf" / "release"
    out_dir = dist_dir / target["board_target"]
    if os.name == "nt":
        shell = shutil.which("pwsh") or shutil.which("powershell") or "powershell"
        package = [
            shell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ROOT / "scripts" / "package-firmware.ps1"),
            "-TargetDir",
            str(release_dir),
            "-BoardTarget",
            target["board_target"],
            "-OutDir",
            str(out_dir),
            "-PartitionsCsv",
            str(partitions),
        ]
    else:
        package = [str(ROOT / "scripts" / "package-firmware.sh")]
        env.update(
            {
                "TARGET_DIR": str(release_dir),
                "BOARD_TARGET": target["board_target"],
                "OUT_DIR": str(out_dir),
                "PARTITIONS_CSV": str(partitions),
            }
        )
    packaged = run_command(package, env)
    commands.append(packaged)
    if not packaged["passed"]:
        return {"stage": "package", "passed": False, "commands": commands}

    manifests = sorted(out_dir.glob("*-manifest.json"))
    if len(manifests) != 1:
        return {
            "stage": "package",
            "passed": False,
            "commands": commands,
            "error": f"expected one manifest under {out_dir}, found {len(manifests)}",
        }
    verify = [
        sys.executable,
        "scripts/verify_ota_package.py",
        str(manifests[0]),
        "--partitions-csv",
        str(partitions),
    ]
    if qualification:
        assert candidate_path is not None
        verify.extend(
            [
                "--allow-qualification-candidate",
                "--candidate",
                str(candidate_path.resolve()),
            ]
        )
    elif target["package_policy"] != "public":
        verify.append("--allow-internal-target")
    if production_signature_required:
        public_key = env.get("DCENT_OTA_PUBLIC_KEY_HEX", "").strip()
        if not public_key:
            return {
                "stage": "package",
                "passed": False,
                "commands": commands,
                "manifest": str(manifests[0]),
                "error": "production package verification requires DCENT_OTA_PUBLIC_KEY_HEX",
                "production_signatures_verified": False,
            }
        verify.extend(["--require-signatures", "--strict-public", "--public-key-hex", public_key])
    verified = run_command(verify, env)
    commands.append(verified)
    return {
        "stage": "package",
        "passed": verified["passed"],
        "commands": commands,
        "manifest": str(manifests[0]),
        "production_signatures_verified": production_signature_required and verified["passed"],
    }


def readiness(
    target: dict[str, Any],
    passed: bool,
    matrix: dict[str, Any],
    evidence_index: dict[str, Any],
    package_update_sha256: str | None,
    package_version: str | None,
    production_signatures_verified: bool,
    root: Path = ROOT,
    qualification_candidate: bool = False,
) -> dict[str, Any]:
    code_ready = passed
    promotion = promotion_status(evidence_index, matrix, target, root)
    receipt_firmware_matches_package = bool(
        promotion["qualified"]
        and package_update_sha256
        and package_update_sha256 == promotion.get("firmware_update_sha256")
        and package_version
        and package_version == promotion.get("firmware_version")
    )
    production_ready = (
        code_ready
        and not qualification_candidate
        and target["support_tier"] == "production"
        and target["runtime_mode"] == "mining"
        and target["install_policy"] == "production"
        and target["evidence_level"] == "sustained-soak"
        and not target["blockers"]
        and promotion["qualified"]
        and receipt_firmware_matches_package
        and production_signatures_verified
    )
    return {
        "code_ready": code_ready,
        "production_ready": production_ready,
        "evidence_level": target["evidence_level"],
        "install_policy": target["install_policy"],
        "runtime_mode": target["runtime_mode"],
        "remaining_blockers": target["blockers"],
        "promotion_evidence": promotion,
        "package_update_sha256": package_update_sha256,
        "package_version": package_version,
        "receipt_firmware_matches_package": receipt_firmware_matches_package,
        "production_signatures_verified": production_signatures_verified,
        "qualification_candidate": qualification_candidate,
    }


def packaged_artifact_facts(record: dict[str, Any]) -> tuple[str | None, str | None, bool]:
    """Return the verified OTA hash/version and production-signature gate result."""
    attempts = record.get("attempts") or []
    if not attempts:
        return None, None, False
    gates = attempts[-1].get("gates") or []
    package_gate = next((gate for gate in gates if gate.get("stage") == "package"), None)
    if not package_gate or not package_gate.get("passed"):
        return None, None, False
    manifest_path = package_gate.get("manifest")
    if not isinstance(manifest_path, str):
        return None, None, False
    path = Path(manifest_path)
    if not path.is_absolute():
        path = ROOT / path
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, None, False
    payloads = manifest.get("payloads") or []
    update = next(
        (payload for payload in payloads if isinstance(payload, dict) and payload.get("name") == "update"),
        None,
    )
    sha256 = update.get("sha256") if update else None
    version = manifest.get("version")
    return (
        sha256 if isinstance(sha256, str) else None,
        version if isinstance(version, str) else None,
        package_gate.get("production_signatures_verified") is True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", choices=("public", "internal", "all"), default="public")
    parser.add_argument("--target", action="append", default=[], help="Run one board target; repeatable")
    parser.add_argument("--stage", choices=(*STAGES, "all"), default="all")
    parser.add_argument("--max-rounds", type=int, default=2)
    parser.add_argument("--build-root", type=Path)
    parser.add_argument("--dist-root", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "gauntlet-ledger.json")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--candidate",
        type=Path,
        help="Build and package one signed, non-publishable promotion candidate",
    )
    args = parser.parse_args(argv)
    if args.max_rounds < 1:
        parser.error("--max-rounds must be at least 1")

    matrix = load_manifest()
    require_valid(matrix)
    evidence_index = load_evidence_index()
    selected = targets_for_scope(matrix, args.scope)
    candidate_descriptor: dict[str, Any] | None = None
    candidate_path: Path | None = None
    if args.candidate is not None:
        if args.dist_root is None:
            parser.error("--candidate requires an explicit retained --dist-root")
        if not candidate_source_is_clean():
            parser.error(
                "--candidate requires a clean repository checkout"
            )
        candidate_path = args.candidate.resolve()
        candidate_descriptor = load_descriptor(candidate_path)
        require_valid_descriptor(
            candidate_descriptor,
            matrix,
            sha256_file(ROOT / "esp-targets.json"),
            git_head(),
            git_fact("%ct"),
            workspace_version(),
        )
        candidate_target = find_target(matrix, candidate_descriptor["board_target"])
        if args.target and args.target != [candidate_target["board_target"]]:
            parser.error("--candidate cannot be combined with a different --target")
        selected = [candidate_target]
    if args.target:
        selected = [find_target(matrix, board_target) for board_target in args.target]
    stages = list(STAGES) if args.stage == "all" else [args.stage]

    ledger: dict[str, Any] = {
        "schema": 1,
        "product": "DCENT_OS-for-ESP",
        "authority": "offline-build-and-package-only",
        "live_device_contact": False,
        "started_at": utc_now(),
        "scope": args.scope,
        "stages": stages,
        "max_rounds": args.max_rounds,
        "hardware_evidence_authority": {
            "index": str(INDEX_PATH.relative_to(ROOT)),
            "index_sha256": sha256_file(INDEX_PATH),
            "retained_receipts": len(evidence_index["receipts"]),
        },
        "targets": {},
        "global_gates": [],
        "promotion_candidate": (
            {
                "candidate_id": candidate_descriptor["candidate_id"],
                "descriptor": str(candidate_path),
                "disposition": "qualification-only-not-publishable",
                "publishable": False,
            }
            if candidate_descriptor is not None
            else None
        ),
    }
    if args.dry_run:
        ledger["planned_targets"] = [target["board_target"] for target in selected]
        ledger["finished_at"] = utc_now()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
        print(f"Gauntlet dry run planned {len(selected)} targets: {args.output}")
        return 0

    owned_build_root = args.build_root is None
    temporary_root = create_owned_build_root() if owned_build_root else args.build_root
    assert temporary_root is not None
    build_root = temporary_root if os.name == "nt" else temporary_root / "build"
    dist_root = args.dist_root or temporary_root / "dist"
    try:
        global_passed = True
        if "static" in stages:
            gate = static_gate()
            ledger["global_gates"].append(gate)
            global_passed &= gate["passed"]
        if "host" in stages:
            gate = host_gate()
            ledger["global_gates"].append(gate)
            global_passed &= gate["passed"]

        per_target_stages = [stage for stage in stages if stage in ("check", "package")]
        pending = list(selected)
        for round_number in range(1, args.max_rounds + 1):
            if not pending:
                break
            failed: list[dict[str, Any]] = []
            for target in pending:
                board_target = target["board_target"]
                target_record = ledger["targets"].setdefault(
                    board_target,
                    {"metadata": target, "attempts": []},
                )
                gates = []
                for stage in per_target_stages:
                    target_build = target_build_dir(build_root, board_target)
                    if stage == "check":
                        gate = check_gate(
                            target,
                            target_build,
                            candidate_path,
                            candidate_descriptor,
                        )
                    else:
                        gate = package_gate(
                            target,
                            target_build,
                            dist_root,
                            candidate_path,
                            candidate_descriptor,
                        )
                    gates.append(gate)
                    if not gate["passed"]:
                        break
                attempt_passed = global_passed and all(gate["passed"] for gate in gates)
                target_record["attempts"].append(
                    {"round": round_number, "passed": attempt_passed, "gates": gates}
                )
                if not attempt_passed:
                    failed.append(target)
            pending = failed

        for target in selected:
            record = ledger["targets"].setdefault(target["board_target"], {"metadata": target, "attempts": []})
            passed = bool(record["attempts"] and record["attempts"][-1]["passed"])
            if not per_target_stages:
                passed = global_passed
            package_sha256, package_version, production_signatures_verified = packaged_artifact_facts(
                record
            )
            record["readiness"] = readiness(
                target,
                passed,
                matrix,
                evidence_index,
                package_sha256,
                package_version,
                production_signatures_verified,
                qualification_candidate=candidate_descriptor is not None,
            )
        ledger["passed"] = global_passed and not pending
        ledger["finished_at"] = utc_now()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
        print(f"Gauntlet {'passed' if ledger['passed'] else 'failed'}: {args.output.resolve()}")
        return 0 if ledger["passed"] else 1
    finally:
        if owned_build_root:
            shutil.rmtree(temporary_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
