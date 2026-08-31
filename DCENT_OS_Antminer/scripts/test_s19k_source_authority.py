#!/usr/bin/env python3
"""Adversarial tests with an in-memory, explicitly test-only authority record."""

from __future__ import annotations

import copy
from dataclasses import dataclass, replace
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("s19k_source_authority.py")
SPEC = importlib.util.spec_from_file_location("s19k_source_authority", SCRIPT)
assert SPEC and SPEC.loader
authority = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = authority
SPEC.loader.exec_module(authority)


SIGNER_A = "openpgp:" + "3" * 40
SIGNER_B = "openpgp:" + "4" * 40
INDEX = "sha256:" + "5" * 64
MANIFEST = "sha256:" + "6" * 64
CONFIG = "sha256:" + "7" * 64
CAMPAIGN_ID = "test-fixture-s19k-source-authority"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git_oid(object_type: str, raw: bytes) -> str:
    hasher = hashlib.sha1(usedforsecurity=False)
    hasher.update(f"{object_type} {len(raw)}\0".encode("ascii"))
    hasher.update(raw)
    return hasher.hexdigest()


def write(path: Path, raw: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return path


def identity(path: Path, *, recorded_path: str | None = None) -> dict[str, object]:
    raw = path.read_bytes()
    return {
        "bytes": len(raw),
        "path": str(path.absolute()) if recorded_path is None else recorded_path,
        "sha256": digest(raw),
    }


def relative_identity(root: Path, relative: str) -> dict[str, object]:
    return identity(
        root.joinpath(*PurePosixPath(relative).parts), recorded_path=relative
    )


def trust_ledger(root: Path) -> tuple[list[str], list[dict[str, object]]]:
    directories = sorted(
        [path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_dir()],
        key=lambda value: value.encode("utf-8"),
    )
    files = sorted(
        [
            relative_identity(root, path.relative_to(root).as_posix())
            for path in root.rglob("*")
            if path.is_file()
        ],
        key=lambda value: str(value["path"]).encode("utf-8"),
    )
    return directories, files


def build_tree_object_bundle(
    source_root: Path, bundle_root: Path
) -> tuple[str, Path]:
    objects: dict[str, bytes] = {}

    def build(directory: Path) -> str:
        entries: list[tuple[bytes, bytes]] = []
        for path in directory.iterdir():
            name = path.name.encode("utf-8")
            if path.is_dir():
                oid = build(path)
                mode = b"40000"
                sort_key = name + b"/"
            else:
                raw = path.read_bytes()
                oid = git_oid("blob", raw)
                mode = b"100644"
                sort_key = name
            entry = mode + b" " + name + b"\0" + bytes.fromhex(oid)
            entries.append((sort_key, entry))
        raw_tree = b"".join(entry for _, entry in sorted(entries))
        oid = git_oid("tree", raw_tree)
        objects[oid] = raw_tree
        return oid

    root_oid = build(source_root)
    object_root = bundle_root / "tree-objects"
    records = []
    for oid in sorted(objects):
        relative = f"tree-objects/{oid}.raw"
        path = write(object_root / f"{oid}.raw", objects[oid])
        records.append(
            {
                "bytes": len(objects[oid]),
                "oid": oid,
                "path": relative,
                "sha256": digest(path.read_bytes()),
            }
        )
    ledger = {
        "object_format": "sha1",
        "objects": records,
        "root_tree_oid": root_oid,
        "schema": authority.TREE_LEDGER_SCHEMA,
    }
    ledger_path = write(
        bundle_root / "tree-object-ledger.json", authority.canonical_json(ledger)
    )
    return root_oid, ledger_path


def signing_policy_id(openpgp: dict[str, object]) -> str:
    gpg = openpgp["gpg_binary"]
    trust = openpgp["trust_root"]
    assert isinstance(gpg, dict) and isinstance(trust, dict)
    policy = {
        "schema": authority.SIGNING_POLICY_SCHEMA,
        "allowed_signers": openpgp["allowed_signers"],
        "gpg_binary": gpg["path"],
        "gpg_binary_sha256": gpg["sha256"],
        "gpg_binary_bytes": gpg["bytes"],
        "trust_root": trust["path"],
        "trust_files": trust["files"],
        "trust_directories": trust["directories"],
        "git_system_config": "disabled",
        "git_global_config": "disabled",
        "signature_format": "openpgp",
    }
    return digest(authority.canonical_json(policy))


def seal_record(record: dict[str, object]) -> bytes:
    body = dict(record)
    body.pop("authority_id", None)
    record["authority_id"] = digest(authority.canonical_json(body))
    return authority.canonical_json(record)


@dataclass
class Fixture:
    root: Path
    source_root: Path
    authority_path: Path
    campaign_path: Path
    git_path: Path
    gpg_path: Path
    trust_root: Path
    release_key: Path
    record: dict[str, object]
    pin: authority.TrustedCampaignPin

    def publish_record(self, record: dict[str, object], *, canonical: bool = True) -> None:
        self.record = record
        raw = seal_record(record)
        if not canonical:
            raw = json.dumps(record, sort_keys=True, indent=2).encode("ascii") + b"\n"
        self.authority_path.write_bytes(raw)
        self.pin = replace(
            self.pin,
            authority_sha256=digest(raw),
            authority_bytes=len(raw),
        )

    def refresh_signing_policy(self, record: dict[str, object]) -> None:
        openpgp = record["openpgp"]
        assert isinstance(openpgp, dict)
        openpgp["signing_policy_id"] = signing_policy_id(openpgp)


def make_fixture(root: Path) -> Fixture:
    source_root = root / "admitted-source"
    helper = write(
        source_root.joinpath(*PurePosixPath(authority.SOURCE_SNAPSHOT_PATH).parts),
        b"# test-only source snapshot helper\n",
    )
    persistent = write(
        source_root.joinpath(*PurePosixPath(authority.PERSISTENT_VERIFIER_PATH).parts),
        b"# test-only persistent verifier\n",
    )
    release_signer = write(
        source_root.joinpath(*PurePosixPath(authority.RELEASE_SIGNER_PATH).parts),
        b"# test-only isolated release signer\n",
    )
    host_preflight = write(
        source_root.joinpath(*PurePosixPath(authority.HOST_PREFLIGHT_PATH).parts),
        b"# test-only hermetic host preflight\n",
    )
    dependency_path = source_root.joinpath(
        *PurePosixPath(authority.DEPENDENCY_POLICY_PATH).parts
    )
    dependency_policy = {
        "builder": {
            "image": "fixture.invalid/s19k-builder@" + INDEX,
            "linux_amd64_manifest_digest": MANIFEST,
            "oci_config_digest": CONFIG,
            "oci_index_digest": INDEX,
        },
        "schema": authority.DEPENDENCY_POLICY_SCHEMA,
        "test_fixture_only": True,
    }
    write(dependency_path, authority.canonical_json(dependency_policy))
    tree_oid, tree_ledger_path = build_tree_object_bundle(
        source_root, root / "source-object-bundle"
    )
    commit_raw = (
        f"tree {tree_oid}\n"
        "author Test Fixture <fixture.invalid> 0 +0000\n"
        "committer Test Fixture <fixture.invalid> 0 +0000\n"
        "\n"
        "test-only source authority fixture\n"
    ).encode("ascii")
    commit_oid = git_oid("commit", commit_raw)
    commit_path = write(root / "source-object-bundle" / "commit.raw", commit_raw)

    git_path = write(root / "tools" / "git-fixture", b"test-only git binary\n")
    gpg_path = write(root / "tools" / "gpg-fixture", b"test-only gpg binary\n")
    trust_root = root / "trust"
    write(trust_root / "pubring.kbx", b"test-only trust root\n")
    write(
        trust_root / "openpgp-revocs.d" / "fixture.rev",
        b"test-only revocation\n",
    )
    release_key = write(root / "release" / "public.pem", b"test-only public key\n")
    directories, files = trust_ledger(trust_root)

    campaign_path = root / "campaign.json"
    campaign_raw = authority.canonical_json(
        {
            "campaign_id": CAMPAIGN_ID,
            "schema": authority.CAMPAIGN_SCHEMA,
            "test_fixture_only": True,
        }
    )
    campaign_canonical = authority.canonical_json(json.loads(campaign_raw))
    write(campaign_path, campaign_raw)
    dependency_descriptor_body = {
        "schema": authority.DEPENDENCY_BUNDLE_SCHEMA,
        "test_fixture_only": True,
    }
    dependency_bundle_id = digest(
        authority.canonical_json(dependency_descriptor_body)
    )
    dependency_descriptor = {
        **dependency_descriptor_body,
        "bundle_id": dependency_bundle_id,
    }
    dependency_descriptor_path = write(
        root / "approved-dependency" / "dependency-bundle.json",
        authority.canonical_json(dependency_descriptor),
    )

    openpgp: dict[str, object] = {
        "allowed_signers": [SIGNER_A, SIGNER_B],
        "git_binary": identity(git_path),
        "gpg_binary": identity(gpg_path),
        "signing_policy_id": "0" * 64,
        "trust_root": {
            "directories": directories,
            "files": files,
            "path": str(trust_root.absolute()),
        },
    }
    openpgp["signing_policy_id"] = signing_policy_id(openpgp)
    record: dict[str, object] = {
        "authority_id": "0" * 64,
        "approved_dependency_bundle": {
            "bundle_id": dependency_bundle_id,
            "descriptor": identity(dependency_descriptor_path),
        },
        "builder": {
            "linux_amd64_manifest_digest": MANIFEST,
            "oci_config_digest": CONFIG,
            "oci_index_digest": INDEX,
        },
        "campaign": {
            "campaign_id": CAMPAIGN_ID,
            "canonical_bytes": len(campaign_canonical),
            "canonical_sha256": digest(campaign_canonical),
            "manifest_schema": authority.CAMPAIGN_SCHEMA,
            "raw_bytes": len(campaign_raw),
            "raw_sha256": digest(campaign_raw),
        },
        "claim": authority.AUTHORITY_CLAIM,
        "dependency_policy": relative_identity(
            source_root, authority.DEPENDENCY_POLICY_PATH
        ),
        "openpgp": openpgp,
        "release_public_key": identity(release_key),
        "schema": authority.AUTHORITY_SCHEMA,
        "scope": dict(authority._SCOPE),
        "source": {
            "commit_object": identity(commit_path),
            "commit_oid": commit_oid,
            "object_format": "sha1",
            "tree_object_ledger": identity(tree_ledger_path),
            "tree_oid": tree_oid,
        },
        "verifiers": {
            "host_preflight": relative_identity(
                source_root, authority.HOST_PREFLIGHT_PATH
            ),
            "persistent_image": relative_identity(
                source_root, authority.PERSISTENT_VERIFIER_PATH
            ),
            "release_signer": relative_identity(
                source_root, authority.RELEASE_SIGNER_PATH
            ),
            "source_snapshot": relative_identity(
                source_root, authority.SOURCE_SNAPSHOT_PATH
            ),
        },
    }
    raw = seal_record(record)
    authority_path = write(root / "authority.json", raw)
    pin = authority.TrustedCampaignPin(
        campaign_id=CAMPAIGN_ID,
        campaign_raw_sha256=digest(campaign_raw),
        campaign_raw_bytes=len(campaign_raw),
        campaign_canonical_sha256=digest(campaign_canonical),
        campaign_canonical_bytes=len(campaign_canonical),
        authority_sha256=digest(raw),
        authority_bytes=len(raw),
        authority_validator_path=str(SCRIPT.absolute()),
        authority_validator_sha256=digest(SCRIPT.read_bytes()),
        authority_validator_bytes=SCRIPT.stat().st_size,
    )
    # Keep references alive for tests that deliberately replace them.
    assert (
        helper.is_file()
        and persistent.is_file()
        and release_signer.is_file()
        and host_preflight.is_file()
    )
    return Fixture(
        root=root,
        source_root=source_root,
        authority_path=authority_path,
        campaign_path=campaign_path,
        git_path=git_path,
        gpg_path=gpg_path,
        trust_root=trust_root,
        release_key=release_key,
        record=record,
        pin=pin,
    )


class SourceAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = make_fixture(Path(self.temporary.name))

    def verify(self) -> dict[str, object]:
        return authority.verify_source_authority(
            self.fixture.authority_path,
            self.fixture.campaign_path,
            self.fixture.source_root,
            self.fixture.pin,
        )

    def mutate_record(self) -> dict[str, object]:
        return copy.deepcopy(self.fixture.record)

    def assert_rejected(self, pattern: str) -> None:
        with self.assertRaisesRegex(authority.SourceAuthorityError, pattern):
            self.verify()

    def test_test_only_fixture_validates_without_granting_authority(self) -> None:
        result = self.verify()
        self.assertTrue(result["policy_inputs_verified"])
        self.assertFalse(result["commit_signature_verified"])
        self.assertEqual(
            result["source_commit"], self.fixture.record["source"]["commit_oid"]
        )
        self.assertEqual(
            result["source_tree"], self.fixture.record["source"]["tree_oid"]
        )
        self.assertEqual(result["scope"], authority._SCOPE)
        self.assertFalse(any(result["scope"].values()))
        self.assertEqual(result["validated_authority"], self.fixture.record)
        authority.canonical_json(result)

    def test_record_requires_exact_out_of_band_pin(self) -> None:
        record = self.mutate_record()
        record["source"]["commit_oid"] = "8" * 40
        self.fixture.authority_path.write_bytes(seal_record(record))
        self.assert_rejected("out-of-band campaign pin")

    def test_mapping_cannot_substitute_for_typed_pin(self) -> None:
        with self.assertRaisesRegex(authority.SourceAuthorityError, "typed out-of-band"):
            authority.verify_source_authority(
                self.fixture.authority_path,
                self.fixture.campaign_path,
                self.fixture.source_root,
                self.fixture.pin.__dict__,
            )

    def test_noncanonical_authority_json_is_rejected_even_when_pinned(self) -> None:
        self.fixture.publish_record(self.mutate_record(), canonical=False)
        self.assert_rejected("exact canonical JSON")

    def test_duplicate_json_key_is_rejected_even_when_pinned(self) -> None:
        raw = self.fixture.authority_path.read_bytes()
        duplicate = raw.replace(b"{", b'{"schema":"duplicate",', 1)
        self.fixture.authority_path.write_bytes(duplicate)
        self.fixture.pin = replace(
            self.fixture.pin,
            authority_sha256=digest(duplicate),
            authority_bytes=len(duplicate),
        )
        self.assert_rejected("duplicate object key")

    def test_extra_and_missing_record_keys_are_rejected(self) -> None:
        for mutation in ("extra", "missing"):
            with self.subTest(mutation=mutation):
                record = self.mutate_record()
                if mutation == "extra":
                    record["clear_for_flash"] = True
                else:
                    record.pop("builder")
                self.fixture.publish_record(record)
                self.assert_rejected("invalid key set")
                self.fixture = make_fixture(self.fixture.root / mutation)

    def test_every_authority_grant_must_remain_false(self) -> None:
        for field in authority._SCOPE:
            with self.subTest(field=field):
                fixture = make_fixture(self.fixture.root / field)
                record = copy.deepcopy(fixture.record)
                record["scope"][field] = True
                fixture.publish_record(record)
                with self.assertRaisesRegex(authority.SourceAuthorityError, "authority grant"):
                    authority.verify_source_authority(
                        fixture.authority_path,
                        fixture.campaign_path,
                        fixture.source_root,
                        fixture.pin,
                    )

        record = self.mutate_record()
        record["scope"]["flash_authority_granted"] = 0
        self.fixture.publish_record(record)
        self.assert_rejected("authority grant")

    def test_wrong_campaign_identifier_is_rejected(self) -> None:
        raw = authority.canonical_json(
            {
                "campaign_id": "test-fixture-wrong-campaign",
                "schema": authority.CAMPAIGN_SCHEMA,
            }
        )
        self.fixture.campaign_path.write_bytes(raw)
        record = self.mutate_record()
        canonical = authority.canonical_json(json.loads(raw))
        record["campaign"]["raw_sha256"] = digest(raw)
        record["campaign"]["raw_bytes"] = len(raw)
        record["campaign"]["canonical_sha256"] = digest(canonical)
        record["campaign"]["canonical_bytes"] = len(canonical)
        self.fixture.publish_record(record)
        self.fixture.pin = replace(
            self.fixture.pin,
            campaign_raw_sha256=digest(raw),
            campaign_raw_bytes=len(raw),
            campaign_canonical_sha256=digest(canonical),
            campaign_canonical_bytes=len(canonical),
        )
        self.assert_rejected("campaign identifier")

    def test_raw_and_canonical_campaign_identities_are_distinct_and_joined(self) -> None:
        value = json.loads(self.fixture.campaign_path.read_bytes())
        noncanonical_raw = (
            json.dumps(value, sort_keys=False, indent=2).encode("ascii") + b"\n"
        )
        canonical = authority.canonical_json(value)
        self.assertNotEqual(noncanonical_raw, canonical)
        self.fixture.campaign_path.write_bytes(noncanonical_raw)
        record = self.mutate_record()
        record["campaign"]["raw_sha256"] = digest(noncanonical_raw)
        record["campaign"]["raw_bytes"] = len(noncanonical_raw)
        record["campaign"]["canonical_sha256"] = digest(canonical)
        record["campaign"]["canonical_bytes"] = len(canonical)
        self.fixture.publish_record(record)
        self.fixture.pin = replace(
            self.fixture.pin,
            campaign_raw_sha256=digest(noncanonical_raw),
            campaign_raw_bytes=len(noncanonical_raw),
            campaign_canonical_sha256=digest(canonical),
            campaign_canonical_bytes=len(canonical),
        )
        result = self.verify()
        self.assertEqual(result["campaign_raw_sha256"], digest(noncanonical_raw))
        self.assertEqual(result["campaign_canonical_sha256"], digest(canonical))

        self.fixture.pin = replace(
            self.fixture.pin,
            campaign_canonical_sha256="9" * 64,
        )
        self.assert_rejected("canonical S19k campaign")

    def test_unsorted_duplicate_and_abbreviated_signers_are_rejected(self) -> None:
        cases = (
            [SIGNER_B, SIGNER_A],
            [SIGNER_A, SIGNER_A],
            ["openpgp:" + "a" * 16],
        )
        for index, signers in enumerate(cases):
            with self.subTest(signers=signers):
                fixture = make_fixture(self.fixture.root / f"signers-{index}")
                record = copy.deepcopy(fixture.record)
                record["openpgp"]["allowed_signers"] = signers
                fixture.refresh_signing_policy(record)
                fixture.publish_record(record)
                with self.assertRaises(authority.SourceAuthorityError):
                    authority.verify_source_authority(
                        fixture.authority_path,
                        fixture.campaign_path,
                        fixture.source_root,
                        fixture.pin,
                    )

    def test_signing_policy_id_is_recomputed_not_trusted(self) -> None:
        record = self.mutate_record()
        record["openpgp"]["signing_policy_id"] = "9" * 64
        self.fixture.publish_record(record)
        self.assert_rejected("does not match the exact reviewed policy")

    def test_git_gpg_and_release_key_mutations_are_rejected(self) -> None:
        for role, path in (
            ("Git", self.fixture.git_path),
            ("GPG", self.fixture.gpg_path),
            ("release", self.fixture.release_key),
        ):
            with self.subTest(role=role):
                fixture = make_fixture(self.fixture.root / role)
                target = {
                    "Git": fixture.git_path,
                    "GPG": fixture.gpg_path,
                    "release": fixture.release_key,
                }[role]
                target.write_bytes(target.read_bytes() + b"mutation")
                with self.assertRaises(authority.SourceAuthorityError):
                    authority.verify_source_authority(
                        fixture.authority_path,
                        fixture.campaign_path,
                        fixture.source_root,
                        fixture.pin,
                    )

    def test_source_helper_persistent_verifier_and_policy_mutations_are_rejected(self) -> None:
        relatives = (
            authority.SOURCE_SNAPSHOT_PATH,
            authority.PERSISTENT_VERIFIER_PATH,
            authority.RELEASE_SIGNER_PATH,
            authority.HOST_PREFLIGHT_PATH,
            authority.DEPENDENCY_POLICY_PATH,
        )
        for index, relative in enumerate(relatives):
            with self.subTest(relative=relative):
                fixture = make_fixture(self.fixture.root / f"source-{index}")
                target = fixture.source_root.joinpath(*PurePosixPath(relative).parts)
                target.write_bytes(target.read_bytes() + b"mutation")
                with self.assertRaises(authority.SourceAuthorityError):
                    authority.verify_source_authority(
                        fixture.authority_path,
                        fixture.campaign_path,
                        fixture.source_root,
                        fixture.pin,
                    )

    def test_raw_commit_tree_ledger_and_tree_object_tamper_are_rejected(self) -> None:
        for case in ("commit", "ledger", "tree-object"):
            with self.subTest(case=case):
                fixture = make_fixture(self.fixture.root / case)
                source = fixture.record["source"]
                if case == "commit":
                    target = Path(source["commit_object"]["path"])
                elif case == "ledger":
                    target = Path(source["tree_object_ledger"]["path"])
                else:
                    ledger = json.loads(
                        Path(source["tree_object_ledger"]["path"]).read_text(
                            encoding="ascii"
                        )
                    )
                    target = Path(source["tree_object_ledger"]["path"]).parent.joinpath(
                        *PurePosixPath(ledger["objects"][0]["path"]).parts
                    )
                target.write_bytes(target.read_bytes() + b"tamper")
                with self.assertRaises(authority.SourceAuthorityError):
                    authority.verify_source_authority(
                        fixture.authority_path,
                        fixture.campaign_path,
                        fixture.source_root,
                        fixture.pin,
                    )

    def test_raw_commit_oid_and_tree_header_are_independently_recomputed(self) -> None:
        record = self.mutate_record()
        record["source"]["commit_oid"] = "8" * 40
        self.fixture.publish_record(record)
        self.assert_rejected("Git object identifier")

    def test_authority_validator_implementation_has_an_out_of_band_pin(self) -> None:
        self.fixture.pin = replace(
            self.fixture.pin,
            authority_validator_sha256="9" * 64,
        )
        self.assert_rejected("validator bytes")

    def test_path_environment_cannot_select_a_different_git_or_gpg(self) -> None:
        malicious = self.fixture.root / "malicious-path"
        write(malicious / "git", b"malicious")
        write(malicious / "gpg", b"malicious")
        with mock.patch.dict(os.environ, {"PATH": str(malicious)}):
            self.verify()

    def test_dependency_policy_builder_identity_must_match_authority(self) -> None:
        record = self.mutate_record()
        record["builder"]["oci_config_digest"] = "sha256:" + "8" * 64
        self.fixture.publish_record(record)
        self.assert_rejected("dependency policy builder oci_config_digest")

    def test_only_the_reviewed_dependency_bundle_descriptor_is_admitted(self) -> None:
        descriptor = Path(
            self.fixture.record["approved_dependency_bundle"]["descriptor"]["path"]
        )
        descriptor.write_bytes(descriptor.read_bytes() + b"tamper")
        self.assert_rejected("approved dependency descriptor")

        fixture = make_fixture(self.fixture.root / "wrong-bundle-id")
        record = copy.deepcopy(fixture.record)
        record["approved_dependency_bundle"]["bundle_id"] = "8" * 64
        fixture.publish_record(record)
        with self.assertRaisesRegex(
            authority.SourceAuthorityError, "bundle identifier differs"
        ):
            authority.verify_source_authority(
                fixture.authority_path,
                fixture.campaign_path,
                fixture.source_root,
                fixture.pin,
            )

    def test_noncanonical_dependency_policy_is_rejected_when_hash_is_updated(self) -> None:
        path = self.fixture.source_root.joinpath(
            *PurePosixPath(authority.DEPENDENCY_POLICY_PATH).parts
        )
        value = json.loads(path.read_text(encoding="ascii"))
        raw = json.dumps(value, sort_keys=True, indent=2).encode("ascii") + b"\n"
        path.write_bytes(raw)
        record = self.mutate_record()
        record["dependency_policy"] = relative_identity(
            self.fixture.source_root, authority.DEPENDENCY_POLICY_PATH
        )
        self.fixture.publish_record(record)
        self.assert_rejected("exact canonical JSON")

    def test_trust_mutation_extra_file_and_hardlink_are_rejected(self) -> None:
        cases = ("mutation", "extra", "hardlink")
        for case in cases:
            with self.subTest(case=case):
                fixture = make_fixture(self.fixture.root / case)
                trust_file = fixture.trust_root / "pubring.kbx"
                if case == "mutation":
                    trust_file.write_bytes(b"changed")
                elif case == "extra":
                    write(fixture.trust_root / "unexpected", b"unexpected")
                else:
                    os.link(trust_file, fixture.root / "trust-alias")
                with self.assertRaises(authority.SourceAuthorityError):
                    authority.verify_source_authority(
                        fixture.authority_path,
                        fixture.campaign_path,
                        fixture.source_root,
                        fixture.pin,
                    )

    def test_exact_empty_trust_marker_is_allowed_when_it_is_in_the_ledger(self) -> None:
        write(self.fixture.trust_root / ".gpg-v21-migrated", b"")
        directories, files = trust_ledger(self.fixture.trust_root)
        record = self.mutate_record()
        record["openpgp"]["trust_root"]["directories"] = directories
        record["openpgp"]["trust_root"]["files"] = files
        self.fixture.refresh_signing_policy(record)
        self.fixture.publish_record(record)
        self.verify()

    def test_trust_ledger_path_traversal_and_case_collision_are_rejected(self) -> None:
        cases = ("traversal", "collision", "windows-reserved")
        for case in cases:
            with self.subTest(case=case):
                fixture = make_fixture(self.fixture.root / case)
                record = copy.deepcopy(fixture.record)
                files = record["openpgp"]["trust_root"]["files"]
                if case == "traversal":
                    files[0]["path"] = "../pubring.kbx"
                elif case == "collision":
                    duplicate = copy.deepcopy(files[-1])
                    duplicate["path"] = duplicate["path"].upper()
                    files.append(duplicate)
                    files.sort(key=lambda item: item["path"].encode("utf-8"))
                else:
                    files[0]["path"] = "CON.fixture"
                fixture.refresh_signing_policy(record)
                fixture.publish_record(record)
                with self.assertRaises(authority.SourceAuthorityError):
                    authority.verify_source_authority(
                        fixture.authority_path,
                        fixture.campaign_path,
                        fixture.source_root,
                        fixture.pin,
                    )

    def test_relative_tool_path_and_absolute_role_alias_are_rejected(self) -> None:
        for case in ("relative", "alias"):
            with self.subTest(case=case):
                fixture = make_fixture(self.fixture.root / case)
                record = copy.deepcopy(fixture.record)
                if case == "relative":
                    record["openpgp"]["git_binary"]["path"] = "git"
                else:
                    record["openpgp"]["gpg_binary"] = copy.deepcopy(
                        record["openpgp"]["git_binary"]
                    )
                fixture.refresh_signing_policy(record)
                fixture.publish_record(record)
                with self.assertRaises(authority.SourceAuthorityError):
                    authority.verify_source_authority(
                        fixture.authority_path,
                        fixture.campaign_path,
                        fixture.source_root,
                        fixture.pin,
                    )

    def test_hardlinks_for_authority_campaign_and_bound_source_are_rejected(self) -> None:
        cases = ("authority", "campaign", "source")
        for case in cases:
            with self.subTest(case=case):
                fixture = make_fixture(self.fixture.root / case)
                target = {
                    "authority": fixture.authority_path,
                    "campaign": fixture.campaign_path,
                    "source": fixture.source_root.joinpath(
                        *PurePosixPath(authority.SOURCE_SNAPSHOT_PATH).parts
                    ),
                }[case]
                os.link(target, fixture.root / f"{case}-hardlink")
                with self.assertRaisesRegex(authority.SourceAuthorityError, "hard-link"):
                    authority.verify_source_authority(
                        fixture.authority_path,
                        fixture.campaign_path,
                        fixture.source_root,
                        fixture.pin,
                    )

    def test_symlink_or_reparse_drift_is_rejected_when_supported(self) -> None:
        fixture = make_fixture(self.fixture.root / "symlink")
        target = fixture.source_root.joinpath(
            *PurePosixPath(authority.PERSISTENT_VERIFIER_PATH).parts
        )
        outside = write(fixture.root / "outside-verifier", target.read_bytes())
        target.unlink()
        try:
            target.symlink_to(outside)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        with self.assertRaisesRegex(authority.SourceAuthorityError, "symlink or reparse"):
            authority.verify_source_authority(
                fixture.authority_path,
                fixture.campaign_path,
                fixture.source_root,
                fixture.pin,
            )

    def test_cli_exposes_no_caller_selected_policy_or_pin_flags(self) -> None:
        with mock.patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
            authority.main(["--gpg-binary", str(self.fixture.gpg_path)])
        output = io.StringIO()
        with mock.patch("sys.stdout", new=output):
            self.assertEqual(authority.main(["--describe"]), 0)
        self.assertIn('"production_cli_verification":false', output.getvalue())


if __name__ == "__main__":
    unittest.main()
