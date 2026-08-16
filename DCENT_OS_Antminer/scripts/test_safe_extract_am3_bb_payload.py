import binascii
import gzip
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
from typing import Optional

import pytest


SCRIPT = Path(__file__).with_name("safe_extract_am3_bb_payload.py")
VNISH_BUILDER = Path(__file__).with_name("build_am3_bb_sd_vnish_bootbin_image.sh")
RESIDENT_BUILDER = Path(__file__).with_name("build_am3_bb_sd_resident_uboot_image.sh")
DISK_BUILDER = Path(__file__).with_name("build_am3_bb_sd_disk_image.sh")
DOCKER_BUILDER = Path(__file__).with_name("build_in_docker.sh")
SPEC = importlib.util.spec_from_file_location("safe_extract_am3_bb_payload", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _sha(payload: bytes) -> str:
    import hashlib

    return hashlib.sha256(payload).hexdigest()


def _cpio_gzip() -> bytes:
    # Admission validates the bounded gzip stream and source-defined newc
    # magic. A complete nested rootfs parser is deliberately out of scope.
    return gzip.compress(b"070701" + b"fixture-cpio-body", mtime=0)


def _legacy_ramdisk(payload: bytes) -> bytes:
    name = b"DCENT_OS am3-bb-s19jpro initramfs"[:32].ljust(32, b"\x00")
    data_crc = binascii.crc32(payload) & 0xFFFFFFFF
    header = struct.pack(
        ">7I4B32s",
        0x27051956,
        0,
        0,
        len(payload),
        0,
        0,
        data_crc,
        5,
        2,
        3,
        1,
        name,
    )
    header_crc = binascii.crc32(header) & 0xFFFFFFFF
    header = header[:4] + struct.pack(">I", header_crc) + header[8:]
    return header + payload


def _package_files(target: str, *, signed: bool = False) -> tuple[str, dict[str, bytes]]:
    profile = MODULE._PROFILES[target]
    raw = _cpio_gzip()
    files: dict[str, bytes] = {"uramdisk.image.gz": raw}
    if target == "am3-bb-s19jpro":
        files["ramdisk.gz"] = _legacy_ramdisk(raw)
    files["README.txt"] = f"DCENT_OS {target}\n".encode()
    if signed:
        files["release_ed25519.pub"] = b"fixture-public-key"

    payload_order = [leaf for leaf in profile.payload_order if leaf in files]
    payloads = {
        leaf: {
            "path": f"{profile.prefix}/{leaf}",
            "size": len(files[leaf]),
            "sha256": _sha(files[leaf]),
        }
        for leaf in payload_order
    }
    if signed:
        payloads["verification_key"] = {
            "path": f"{profile.prefix}/release_ed25519.pub",
            "size": len(files["release_ed25519.pub"]),
            "sha256": _sha(files["release_ed25519.pub"]),
        }
    manifest = {
        "schema": 1,
        "product": "DCENT_OS",
        "family": "antminer",
        "package_type": "sdcard_payload",
        "board_family": "am3-bb",
        "board": target,
        "board_target": target,
        "version": "0.test",
        "created_at_utc": "1970-01-01T00:00:00Z",
        "status": "release" if signed else "lab_unsigned",
        "provenance": {
            "source_commit": "a" * 40 if signed else "unbound",
            "source_tree_state": "clean" if signed else "unbound",
            "source_date_epoch": 0,
            "source_commit_epoch": 0,
            "build_target": target,
            "build_arch": "armv7",
            "toolchain_id": "fixture",
        },
        "nand_install": False,
        "payloads": payloads,
    }
    checksum_leaves = list(payload_order)
    if signed:
        checksum_leaves.append("release_ed25519.pub")
    files["SHA256SUMS"] = "".join(
        f"{_sha(files[leaf])}  {leaf}\n" for leaf in checksum_leaves
    ).encode("ascii")
    files["MANIFEST.json"] = (json.dumps(manifest, indent=2) + "\n").encode("ascii")
    if signed:
        files["MANIFEST.sig"] = b"S" * 64
    return profile.prefix, files


def _rebind_payload(files: dict[str, bytes], target: str, leaf: str) -> None:
    document = json.loads(files["MANIFEST.json"])
    document["payloads"][leaf]["size"] = len(files[leaf])
    document["payloads"][leaf]["sha256"] = _sha(files[leaf])
    files["MANIFEST.json"] = (json.dumps(document, indent=2) + "\n").encode("ascii")
    order = MODULE._PROFILES[target].payload_order
    files["SHA256SUMS"] = "".join(
        f"{_sha(files[name])}  {name}\n" for name in order if name in files
    ).encode("ascii")


def _tar(
    path: Path,
    prefix: str,
    files: dict[str, bytes],
    *,
    root: bool = True,
    extras: Optional[list[tarfile.TarInfo]] = None,
    mode: str = "w",
) -> None:
    with tarfile.open(path, mode) as handle:
        if root:
            info = tarfile.TarInfo(f"{prefix}/")
            info.type = tarfile.DIRTYPE
            handle.addfile(info)
        for leaf, data in files.items():
            info = tarfile.TarInfo(f"{prefix}/{leaf}")
            info.size = len(data)
            handle.addfile(info, io.BytesIO(data))
        for info in extras or []:
            body = b"x" * info.size
            handle.addfile(info, io.BytesIO(body) if info.isreg() else None)


def _extract(
    tmp_path: Path,
    target: str,
    files: Optional[dict[str, bytes]] = None,
):
    prefix, defaults = _package_files(target)
    archive = tmp_path / "payload.tar"
    output = tmp_path / "out"
    output.mkdir()
    _tar(archive, prefix, files if files is not None else defaults)
    result = MODULE.extract_payload(archive, output, expected_target=target)
    return result, output


@pytest.mark.parametrize("target", ["am3-bb", "am3-bb-s19jpro"])
def test_admits_exact_target_source_schema_without_install_authority(tmp_path, target):
    result, output = _extract(tmp_path, target)

    assert result["source_schema_admitted"] is True
    assert result["board_target"] == target
    assert result["signature_scope"] == "unsigned-lab"
    assert result["installable"] is False
    assert result["install_authority"] == "none"
    assert result["device_contact"] == "none"
    assert (output / result["prefix"] / "uramdisk.image.gz").is_file()


def test_signed_shape_requires_embedded_signature_consistency(monkeypatch, tmp_path):
    prefix, files = _package_files("am3-bb-s19jpro", signed=True)
    archive = tmp_path / "payload.tar"
    output = tmp_path / "out"
    output.mkdir()
    _tar(archive, prefix, files)
    checked = []
    monkeypatch.setattr(MODULE, "_verify_embedded_signature", lambda root: checked.append(root))

    result = MODULE.extract_payload(
        archive, output, expected_target="am3-bb-s19jpro"
    )

    assert result["signature_scope"] == "embedded-key-self-consistency-only"
    assert len(checked) == 1
    assert result["install_authority"] == "none"


def test_wrong_target_prefix_is_refused(tmp_path):
    prefix, files = _package_files("am3-bb-s19jpro")
    archive = tmp_path / "payload.tar"
    output = tmp_path / "out"
    output.mkdir()
    _tar(archive, prefix, files)

    with pytest.raises(MODULE.PayloadArchiveError, match="unexpected target"):
        MODULE.extract_payload(archive, output, expected_target="am3-bb")
    assert list(output.iterdir()) == []


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda files: files.pop("MANIFEST.json"), "missing required"),
        (lambda files: files.pop("SHA256SUMS"), "missing required"),
        (
            lambda files: files.__setitem__(
                "MANIFEST.json",
                files["MANIFEST.json"].replace(
                    b'"board_target": "am3-bb-s19jpro"',
                    b'"board_target": "am3-bb"',
                ),
            ),
            "field mismatch: board_target",
        ),
        (
            lambda files: files.__setitem__(
                "uramdisk.image.gz", files["uramdisk.image.gz"] + b"tamper"
            ),
            "manifest payload binding mismatch",
        ),
        (
            lambda files: files.__setitem__(
                "ramdisk.gz", files["ramdisk.gz"][:-1] + b"x"
            ),
            "manifest payload binding mismatch",
        ),
    ],
)
def test_late_contract_failures_publish_nothing(tmp_path, mutation, match):
    prefix, files = _package_files("am3-bb-s19jpro")
    mutation(files)
    archive = tmp_path / "payload.tar"
    output = tmp_path / "out"
    output.mkdir()
    _tar(archive, prefix, files)

    with pytest.raises(MODULE.PayloadArchiveError, match=match):
        MODULE.extract_payload(archive, output, expected_target="am3-bb-s19jpro")
    assert list(output.iterdir()) == []


def test_duplicate_manifest_key_is_refused(tmp_path):
    prefix, files = _package_files("am3-bb-s19jpro")
    files["MANIFEST.json"] = files["MANIFEST.json"].replace(
        b'"schema": 1,', b'"schema": 1,\n  "schema": 1,'
    )
    archive = tmp_path / "payload.tar"
    output = tmp_path / "out"
    output.mkdir()
    _tar(archive, prefix, files)

    with pytest.raises(MODULE.PayloadArchiveError, match="duplicate JSON key"):
        MODULE.extract_payload(archive, output, expected_target="am3-bb-s19jpro")
    assert list(output.iterdir()) == []


def test_hash_bound_but_wrong_legacy_wrapper_is_refused(tmp_path):
    prefix, files = _package_files("am3-bb-s19jpro")
    files["ramdisk.gz"] = files["ramdisk.gz"][:-1] + b"x"
    _rebind_payload(files, "am3-bb-s19jpro", "ramdisk.gz")
    archive = tmp_path / "payload.tar"
    output = tmp_path / "out"
    output.mkdir()
    _tar(archive, prefix, files)

    with pytest.raises(MODULE.PayloadArchiveError, match="data size/CRC mismatch"):
        MODULE.extract_payload(archive, output, expected_target="am3-bb-s19jpro")
    assert list(output.iterdir()) == []


def test_nonzero_trailing_archive_data_is_refused(tmp_path):
    prefix, files = _package_files("am3-bb-s19jpro")
    archive = tmp_path / "payload.tar"
    output = tmp_path / "out"
    output.mkdir()
    _tar(archive, prefix, files)
    archive.write_bytes(archive.read_bytes() + b"trailing")

    with pytest.raises(MODULE.PayloadArchiveError, match="non-zero data"):
        MODULE.extract_payload(archive, output, expected_target="am3-bb-s19jpro")
    assert list(output.iterdir()) == []


@pytest.mark.parametrize("kind", ["traversal", "symlink", "hardlink", "pax"])
def test_refuses_hostile_tar_member_types_and_headers(tmp_path, kind):
    prefix, files = _package_files("am3-bb-s19jpro")
    if kind == "traversal":
        info = tarfile.TarInfo("../../escape")
        info.size = 1
    elif kind == "symlink":
        info = tarfile.TarInfo(f"{prefix}/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../escape"
    elif kind == "hardlink":
        info = tarfile.TarInfo(f"{prefix}/link")
        info.type = tarfile.LNKTYPE
        info.linkname = f"{prefix}/README.txt"
    else:
        info = tarfile.TarInfo(f"{prefix}/extra")
        info.size = 1
        info.pax_headers = {"GNU.sparse.map": "0,1"}
    archive = tmp_path / "payload.tar"
    output = tmp_path / "out"
    output.mkdir()
    _tar(archive, prefix, files, extras=[info])

    with pytest.raises(MODULE.PayloadArchiveError):
        MODULE.extract_payload(archive, output, expected_target="am3-bb-s19jpro")
    assert not (tmp_path / "escape").exists()
    assert list(output.iterdir()) == []


def test_refuses_missing_root_entry_and_compressed_outer_tar(tmp_path):
    prefix, files = _package_files("am3-bb-s19jpro")
    output = tmp_path / "out"
    output.mkdir()
    missing_root = tmp_path / "missing-root.tar"
    _tar(missing_root, prefix, files, root=False)
    with pytest.raises(MODULE.PayloadArchiveError, match="canonical root"):
        MODULE.extract_payload(
            missing_root, output, expected_target="am3-bb-s19jpro"
        )
    compressed = tmp_path / "compressed.tar.gz"
    _tar(compressed, prefix, files, mode="w:gz")
    with pytest.raises(MODULE.PayloadArchiveError):
        MODULE.extract_payload(
            compressed, output, expected_target="am3-bb-s19jpro"
        )


def test_refuses_symlink_archive_and_nonempty_output(tmp_path):
    prefix, files = _package_files("am3-bb-s19jpro")
    backing = tmp_path / "backing.tar"
    _tar(backing, prefix, files)
    link = tmp_path / "payload.tar"
    try:
        link.symlink_to(backing)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    output = tmp_path / "out"
    output.mkdir()
    with pytest.raises(MODULE.PayloadArchiveError, match="symlink"):
        MODULE.extract_payload(link, output, expected_target="am3-bb-s19jpro")

    (output / "keep").write_bytes(b"keep")
    with pytest.raises(MODULE.PayloadArchiveError, match="must be empty"):
        MODULE.extract_payload(backing, output, expected_target="am3-bb-s19jpro")
    assert (output / "keep").read_bytes() == b"keep"


def test_all_am3_tar_consumers_use_exact_s19jpro_admission():
    for builder in (VNISH_BUILDER, RESIDENT_BUILDER, DISK_BUILDER):
        text = builder.read_text(encoding="utf-8")
        assert '"$PAYLOAD_EXTRACTOR"' in text
        assert "--expected-target am3-bb-s19jpro" in text
        assert 'tar -xf "$PAYLOAD_TAR"' not in text
        assert "find \"$PAYLOAD_TMP\" -type f" not in text

    docker = DOCKER_BUILDER.read_text(encoding="utf-8")
    anchor = (
        '            am3-bb|am3-bb-s19jpro)\n'
        '            echo ""\n'
        '            echo "SD-card payload validation:"'
    )
    phase8 = docker[docker.index(anchor) :]
    phase8 = phase8[: phase8.index("esac\n    '")]
    assert "python3 ./scripts/safe_extract_am3_bb_payload.py" in phase8
    assert '--expected-target "\'"$TARGET"\'"' in phase8
    assert 'tar xf /out/\'"$TARBALL_NAME"\' -C /tmp' not in phase8


def test_vnish_builder_orders_exact_proof_and_alias_gates_before_image_creation():
    text = VNISH_BUILDER.read_text(encoding="utf-8")
    analyzer = text.index('--verify --analyze-rsa-bypass')
    alias_gate = text.index('sd_common::refuse_unsafe_output_alias "$IMG_FILE"')
    create = text.index('sd_common::create_blank_image_sectors "$IMG_FILE"')
    assert analyzer < alias_gate < create
    assert 'if [ "$ACCEPT_BOOTBIN_MISMATCH" = "1" ]' not in text
    assert 'boot_bin_rsa_verify_behavior": "runtime-patch-to-success-statically-proven"' in text


def test_vnish_builder_defaults_to_held_exact_s19jpro_boot_artifacts():
    text = VNISH_BUILDER.read_text(encoding="utf-8")
    assert "s19jpro-bb-v1.2.6/_partitions/p1_fat" in text
    assert 'DEFAULT_BOOTBIN_PATH="$VNISH_HELD_ARTIFACT_DIR/boot.bin"' in text
    assert 'DEFAULT_UENV_PATH="$VNISH_HELD_ARTIFACT_DIR/uEnv.txt"' in text
