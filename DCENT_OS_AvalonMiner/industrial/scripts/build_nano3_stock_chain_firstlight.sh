#!/usr/bin/env bash
# Build a conservative Nano 3 image around Canaan's proven boot chain.  The
# factory SPL, U-Boot, environment, Linux, and app slots remain byte-identical.
# Only rootfs A/B are rebuilt.
#
# PROFILE=ssh (default) adds key-only OpenSSH only.
# PROFILE=coexistence additionally stages the real static dcentrald-avalon
# binary, but does not autostart it; stock btcminer retains all hardware,
# UI and network ownership.
#
# OUTPUT_SCOPE=rootfs-only (default) emits only the two locally rebuilt rootfs
# mutations. OUTPUT_SCOPE=both also emits a donor-derived full stock-chain
# wrapper and therefore requires the literal local-only acknowledgement below.
# Neither locally generated artifact is redistributable without legal review.
#
# Run inside dcent/k230-sdk with:
#   STOCK_MASTER=/firmware/heater_nano3_master_image.img \
#   ADMIN_AUTHORIZED_KEY=/release-input/admin_ed25519.pub \
#   OUT_DIR=/dcent/build/image \
#   /dcent/scripts/build_nano3_stock_chain_firstlight.sh

set -euo pipefail

DCENT_DIR="${DCENT_DIR:-/dcent}"
TOOLBOX_DIR="${TOOLBOX_DIR:-/toolbox}"
STOCK_MASTER="${STOCK_MASTER:-/firmware/heater_nano3_master_image.img}"
OUT_DIR="${OUT_DIR:-$DCENT_DIR/build/image}"
WORK_DIR="${WORK_DIR:-/work/dcent-nano3-stock-chain}"
PROFILE="${PROFILE:-ssh}"
OUTPUT_SCOPE="${OUTPUT_SCOPE:-rootfs-only}"
ACKNOWLEDGE_LOCAL_FACTORY_BYTES="${ACKNOWLEDGE_LOCAL_FACTORY_BYTES:-}"
ADMIN_AUTHORIZED_KEY="${ADMIN_AUTHORIZED_KEY:-}"
RUNTIME_OVERLAY="$DCENT_DIR/stock-runtime-overlay"
DCENTRALD_BIN="${DCENTRALD_BIN:-$DCENT_DIR/dcentrald/target/riscv64gc-unknown-linux-musl/release/dcentrald-avalon}"

EXPECTED_SIZE=134217728
EXPECTED_SHA256=b99a2358592224b07b4ef9428181715d0dd8ed15585044a94d01e8c78fb830be
PEB_SIZE=131072
LEB_SIZE=126976
ROOTFS_SLOT_SIZE=25165824
ROOTFS_MAX_LEBS=181
ROOTFS_RESERVED_PEBS=182
EXPECTED_STOCK_RCS_SHA256=66b4cfc834793fdcab719a96605265872c82869ac61f2f0b5a095e09b4695f36
EXPECTED_BTCMINER_SHA256=e6c11630a187d677f55178fa1dc7f2f1a52805856c538fae70cfbf0038ca6751

case "$PROFILE" in
    ssh) ;;
    coexistence)
        [ -n "$ADMIN_AUTHORIZED_KEY" ] && [ -s "$ADMIN_AUTHORIZED_KEY" ] || {
            echo "coexistence profile requires explicit ADMIN_AUTHORIZED_KEY" >&2
            exit 1
        }
        [ -f "$DCENTRALD_BIN" ] || {
            echo "coexistence profile requires dcentrald: $DCENTRALD_BIN" >&2
            exit 1
        }
        [ -d "$RUNTIME_OVERLAY" ] || {
            echo "coexistence overlay not found: $RUNTIME_OVERLAY" >&2
            exit 1
        }
        readelf -h "$DCENTRALD_BIN" | grep -q 'Machine:.*RISC-V' || {
            echo "dcentrald is not a RISC-V ELF" >&2
            exit 1
        }
        if readelf -l "$DCENTRALD_BIN" | grep -q 'INTERP' ||
           readelf -d "$DCENTRALD_BIN" 2>/dev/null | grep -q '(NEEDED)'; then
            echo "dcentrald must be static; dynamic dependency found" >&2
            exit 1
        fi
        strings "$DCENTRALD_BIN" |
            grep -F -- '--stock-observer-once' >/dev/null || {
            echo "dcentrald lacks the fail-closed stock observer entry point" >&2
            exit 1
        }
        strings "$DCENTRALD_BIN" |
            grep -F -- '--nano3-read-only-observer-once' >/dev/null || {
            echo "dcentrald lacks the non-authorizing Nano 3 safety observer" >&2
            exit 1
        }
        /bin/sh "$DCENT_DIR/scripts/test_nano3_priority_guard.sh"
        ;;
    *)
        echo "unknown PROFILE '$PROFILE' (ssh|coexistence)" >&2
        exit 1
        ;;
esac

case "$OUTPUT_SCOPE" in
    rootfs-only) ;;
    both)
        [ "$ACKNOWLEDGE_LOCAL_FACTORY_BYTES" = user-owned-donor-local-only ] || {
            echo "OUTPUT_SCOPE=both requires ACKNOWLEDGE_LOCAL_FACTORY_BYTES=user-owned-donor-local-only" >&2
            exit 1
        }
        ;;
    *)
        echo "unknown OUTPUT_SCOPE '$OUTPUT_SCOPE' (rootfs-only|both)" >&2
        exit 1
        ;;
esac

if [ "$PROFILE" = ssh ]; then
    ROOTFS_OUTPUT=DCENT_NANO3_ROOTFS_FIRSTLIGHT.kdimg
    WRAPPER_OUTPUT=DCENT_NANO3_STOCK_CHAIN_FIRSTLIGHT.kdimg
    DESCRIPTION_OUTPUT=describe-nano3-stock-chain.json
else
    ROOTFS_OUTPUT=DCENT_NANO3_ROOTFS_COEXISTENCE.kdimg
    WRAPPER_OUTPUT=DCENT_NANO3_STOCK_CHAIN_COEXISTENCE.kdimg
    DESCRIPTION_OUTPUT=describe-nano3-stock-coexistence.json
fi

refuse_existing_output() {
    output_path=$1
    [ ! -e "$output_path" ] && [ ! -L "$output_path" ] || {
        echo "refusing to overwrite existing output: $output_path" >&2
        exit 1
    }
}

KEY_DIR="$OUT_DIR/nano3-firstlight-ssh"
refuse_existing_output "$KEY_DIR"
refuse_existing_output "$OUT_DIR/$ROOTFS_OUTPUT"
refuse_existing_output "$OUT_DIR/$ROOTFS_OUTPUT.sha256"
if [ "$OUTPUT_SCOPE" = both ]; then
    refuse_existing_output "$OUT_DIR/$WRAPPER_OUTPUT"
    refuse_existing_output "$OUT_DIR/$WRAPPER_OUTPUT.sha256"
    refuse_existing_output "$OUT_DIR/$DESCRIPTION_OUTPUT"
fi

case "$WORK_DIR" in
    /work/dcent-nano3-stock-chain|/work/dcent-nano3-stock-chain/*) ;;
    *) echo "refusing unsafe WORK_DIR: $WORK_DIR" >&2; exit 1 ;;
esac

[ -f "$STOCK_MASTER" ] || {
    echo "stock master not found: $STOCK_MASTER" >&2
    exit 1
}
[ "$(stat -c %s "$STOCK_MASTER")" = "$EXPECTED_SIZE" ] || {
    echo "stock master has the wrong size" >&2
    exit 1
}
[ "$(sha256sum "$STOCK_MASTER" | awk '{print $1}')" = "$EXPECTED_SHA256" ] || {
    echo "stock master SHA-256 mismatch" >&2
    exit 1
}

rm -rf -- "$WORK_DIR"
mkdir -p "$WORK_DIR" "$KEY_DIR"

if [ "$PROFILE" = coexistence ]; then
    [ "$(awk 'NF { count++ } END { print count + 0 }' \
        "$ADMIN_AUTHORIZED_KEY")" = 1 ] || {
        echo "ADMIN_AUTHORIZED_KEY must contain exactly one nonempty line" >&2
        exit 1
    }
    [ "$(awk 'NF { print $1; exit }' "$ADMIN_AUTHORIZED_KEY")" = ssh-ed25519 ] || {
        echo "ADMIN_AUTHORIZED_KEY must be exactly one ssh-ed25519 public key" >&2
        exit 1
    }
    ssh-keygen -l -f "$ADMIN_AUTHORIZED_KEY" >/dev/null || {
        echo "ADMIN_AUTHORIZED_KEY is not a valid SSH public key" >&2
        exit 1
    }
    install -m 0644 "$ADMIN_AUTHORIZED_KEY" \
        "$KEY_DIR/admin_authorized_key.pub"
    AUTHORIZED_KEY_FILE="$KEY_DIR/admin_authorized_key.pub"
else
    if [ ! -s "$KEY_DIR/id_ed25519" ]; then
        ssh-keygen -q -t ed25519 -N '' -C dcent-nano3-firstlight \
            -f "$KEY_DIR/id_ed25519"
    fi
    chmod 0600 "$KEY_DIR/id_ed25519"
    AUTHORIZED_KEY_FILE="$KEY_DIR/id_ed25519.pub"
fi

build_slot() {
    slot_name="$1"
    slot_letter="$2"
    skip_blocks="$3"
    volume_name="ubi_rootfs_part_$slot_letter"
    raw="$WORK_DIR/$slot_name.factory.ubi"
    extract="$WORK_DIR/extract-$slot_name"

    dd if="$STOCK_MASTER" of="$raw" bs="$PEB_SIZE" \
        skip="$skip_blocks" count=192 status=none
    mkdir -p "$extract"
    ubireader_extract_files -k -o "$extract" "$raw"
    root="$(find "$extract" -type d -name "$volume_name" -print -quit)"
    [ -n "$root" ] && [ -d "$root" ] || {
        echo "could not extract $volume_name from factory slot" >&2
        exit 1
    }

    [ "$(sha256sum "$root/etc/init.d/rcS" | awk '{print $1}')" = \
      "$EXPECTED_STOCK_RCS_SHA256" ] || {
        echo "$slot_name factory rcS hash mismatch" >&2
        exit 1
    }

    cp -a "$DCENT_DIR/stock-rootfs-overlay/." "$root/"
    if [ "$PROFILE" = coexistence ]; then
        cp -a "$RUNTIME_OVERLAY/." "$root/"
        install -d -m 0755 "$root/usr/libexec/dcentos"
        install -m 0755 "$DCENTRALD_BIN" \
            "$root/usr/libexec/dcentos/dcentrald-avalon"
        install -m 0644 \
            "$RUNTIME_OVERLAY/etc/dcentos/dcent-data-migrate.sh" \
            "$root/etc/dcentos/dcent-data-migrate.sh"
        sha256sum "$DCENTRALD_BIN" | awk '{print $1}' > \
            "$root/etc/dcentos/dcentrald-avalon.sha256"
        chmod 0755 "$root/etc/user_permission_chg.sh" \
                   "$root/etc/init.d/S98dcent-data" \
                   "$root/etc/init.d/S99dcent-observer" \
                   "$root/etc/init.d/S99dcent-priority-guard" \
                   "$root/etc/dcentos/nano3-health-snapshot.sh" \
                   "$root/etc/dcentos/nano3-persistence-snapshot.sh" \
                   "$root/etc/init.d/dcentrald"
        chmod 0644 "$root/etc/dcentos/dcentrald-avalon.toml.example" \
                   "$root/etc/dcentos/dcentrald-avalon.sha256" \
                   "$root/etc/dcentos/runtime-mode" \
                   "$root/etc/dcentos/nano3-priority-guard.enabled" \
                   "$root/README.md"
        bash -n "$root/etc/user_permission_chg.sh" \
            "$root/etc/init.d/S98dcent-data" \
            "$root/etc/dcentos/dcent-data-migrate.sh" \
            "$root/etc/dcentos/nano3-health-snapshot.sh" \
            "$root/etc/dcentos/nano3-persistence-snapshot.sh" \
            "$root/etc/init.d/S99dcent-priority-guard"
        # The priority guard must fail closed on exact held binary/thread/nice
        # state and remain inert unless the deliberate enable flag is present.
        grep -Fq '[ -f "$enable_flag" ] || exit 0' \
            "$root/etc/init.d/S99dcent-priority-guard" || {
            echo "$slot_name priority guard lacks its enable-flag gate" >&2
            exit 1
        }
        grep -Fqx \
            "expected_btcminer_sha256=$EXPECTED_BTCMINER_SHA256" \
            "$root/etc/init.d/S99dcent-priority-guard" || {
            echo "$slot_name priority guard lacks the exact btcminer admission hash" >&2
            exit 1
        }
        grep -Fq 'is_exact_mount "$run_root" tmpfs || exit 0' \
            "$root/etc/init.d/S99dcent-priority-guard" || {
            echo "$slot_name priority guard lacks its /run tmpfs admission" >&2
            exit 1
        }
        grep -Fq 'watchpool_threa)' \
            "$root/etc/init.d/S99dcent-priority-guard" || {
            echo "$slot_name priority guard lacks the exact truncated live comm" >&2
            exit 1
        }
        if grep -qw 'watchpool_thread' \
            "$root/etc/init.d/S99dcent-priority-guard"; then
            echo "$slot_name priority guard admits the impossible untruncated comm" >&2
            exit 1
        fi
        grep -Fq 'guard_initial_admission=success' \
            "$root/etc/init.d/S99dcent-priority-guard" || {
            echo "$slot_name priority guard lacks its initial admission sentinel" >&2
            exit 1
        }
        if sed '/^[[:space:]]*#/d' \
            "$root/etc/init.d/S99dcent-priority-guard" |
            grep -q 'cgminer_thread'; then
            echo "$slot_name priority guard selects the mining thread" >&2
            exit 1
        fi
    fi
    # The factory UBIFS ships /etc world-writable. That is tolerated by the
    # stock services but sudo correctly rejects a world-writable include
    # directory. Lock the configuration root and our sudo include directory
    # before rebuilding the image.
    chmod 0755 "$root/etc"
    chmod 0750 "$root/etc/sudoers.d"
    chmod 0755 "$root/etc/init.d/S50dcent-firstlight"
    chmod 0600 "$root/etc/ssh/sshd_config"
    chmod 0440 "$root/etc/sudoers.d/dcent-firstlight"
    bash -n "$root/etc/init.d/S50dcent-firstlight"
    [ -x "$root/bin/nice" ] || {
        echo "$slot_name rootfs lacks the nice launcher" >&2
        exit 1
    }
    grep -qx 'MANAGEMENT_NICE=-5' \
        "$root/etc/init.d/S50dcent-firstlight" || {
        echo "$slot_name lacks the bounded SSH priority reservation" >&2
        exit 1
    }
    grep -Fq '/bin/nice -n "$MANAGEMENT_NICE" /sbin/start-stop-daemon \' \
        "$root/etc/init.d/S50dcent-firstlight" || {
        echo "$slot_name does not launch sshd through the priority reservation" >&2
        exit 1
    }
    for required_sshd_line in \
        'PermitRootLogin no' \
        'PasswordAuthentication no' \
        'AllowUsers admin' \
        'AllowTcpForwarding no' \
        'AllowAgentForwarding no' \
        'X11Forwarding no' \
        'PermitTunnel no' \
        'Compression no' \
        'MaxSessions 2' \
        'MaxStartups 2'; do
        grep -Fqx "$required_sshd_line" "$root/etc/ssh/sshd_config" || {
            echo "$slot_name lacks required SSH boundary: $required_sshd_line" >&2
            exit 1
        }
    done

    # Keep the stock launcher byte-identical and forbid any automatic DCENT
    # mining daemon. S99dcent-observer is read-only; its later diagnostics and
    # passive thermal/PWM readback are bounded, non-authorizing, and boot-local.
    # The manual launcher intentionally has no S?? prefix.
    [ "$(sha256sum "$root/etc/init.d/rcS" | awk '{print $1}')" = \
      "$EXPECTED_STOCK_RCS_SHA256" ] || {
        echo "$slot_name overlay changed stock rcS" >&2
        exit 1
    }
    if find "$root/etc/init.d" -maxdepth 1 -type f \
            -name 'S*dcentrald*' | grep -q .; then
        echo "$slot_name contains an autostarting dcentrald service" >&2
        exit 1
    fi

    grep -q '^sshd:' "$root/etc/group" || printf '%s\n' 'sshd:x:74:' >> "$root/etc/group"
    grep -q '^sshd:' "$root/etc/passwd" || \
        printf '%s\n' 'sshd:x:74:74:Privilege-separated SSH:/var/empty:/bin/false' \
        >> "$root/etc/passwd"

    install -d -m 0700 -o 1001 -g 1002 "$root/home/admin/.ssh"
    install -m 0600 -o 1001 -g 1002 "$AUTHORIZED_KEY_FILE" \
        "$root/home/admin/.ssh/authorized_keys"

    ubifs="$WORK_DIR/$slot_name.ubifs"
    cfg="$WORK_DIR/$slot_name-ubinize.cfg"
    output="$WORK_DIR/$slot_name.ubi"
    mkfs.ubifs -q -r "$root" -o "$ubifs" -m 2048 -e "$LEB_SIZE" \
        -c "$ROOTFS_MAX_LEBS"
    cat > "$cfg" <<EOF
[rootfs]
mode=ubi
image=$ubifs
vol_id=0
vol_type=dynamic
vol_name=$volume_name
vol_alignment=1
vol_size=$((ROOTFS_RESERVED_PEBS * LEB_SIZE))
vol_flags=autoresize
EOF
    ubinize -o "$output" -m 2048 -p "$PEB_SIZE" "$cfg"
    [ "$(stat -c %s "$output")" -le "$ROOTFS_SLOT_SIZE" ] || {
        echo "$slot_name exceeds its 24 MiB NAND slot" >&2
        exit 1
    }
}

# 0x01400000 / 0x20000 = 160; 0x02c00000 / 0x20000 = 352.
build_slot rootfs_1 a 160
build_slot rootfs_2 b 352

PYTHONPATH="$TOOLBOX_DIR/src" python3 - \
    "$STOCK_MASTER" "$WORK_DIR" "$OUT_DIR" "$PROFILE" "$OUTPUT_SCOPE" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

from dcent_toolbox.core.k230_image_build import (
    NAND_ERASE_BLOCK,
    build_stock_hybrid_kdimg,
    image_map_for,
)
from dcent_toolbox.core.kdimg import KdimgPartSpec, build_kdimg


def write_new(path: Path, data: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(data)

master_path, work_dir, out_dir = map(Path, sys.argv[1:4])
profile = sys.argv[4]
output_scope = sys.argv[5]
master = master_path.read_bytes()
replacements = {
    "rootfs_1": (work_dir / "rootfs_1.ubi").read_bytes(),
    "rootfs_2": (work_dir / "rootfs_2.ubi").read_bytes(),
}
if profile == "ssh":
    image_filename = "DCENT_NANO3_STOCK_CHAIN_FIRSTLIGHT.kdimg"
    description_filename = "describe-nano3-stock-chain.json"
    rootfs_filename = "DCENT_NANO3_ROOTFS_FIRSTLIGHT.kdimg"
    image_info = "DCENT Nano 3 stock-chain first light (key-only SSH)"
    rootfs_info = "DCENT Nano 3 rootfs-only first light (key-only SSH)"
    board_info = "Canaan k230_heater + DCENT userspace access"
else:
    image_filename = "DCENT_NANO3_STOCK_CHAIN_COEXISTENCE.kdimg"
    description_filename = "describe-nano3-stock-coexistence.json"
    rootfs_filename = "DCENT_NANO3_ROOTFS_COEXISTENCE.kdimg"
    image_info = "DCENT Nano 3 stock-chain coexistence (SSH + staged dcentrald)"
    rootfs_info = "DCENT Nano 3 rootfs-only coexistence (SSH + staged dcentrald)"
    board_info = "Canaan k230_heater + non-autostart DCENT userspace"

if output_scope == "both":
    result = build_stock_hybrid_kdimg(
        master,
        "nano3",
        replacements,
        image_info=image_info,
        board_info=board_info,
    )
    result.image.verify_all()

    # Every non-rootfs slot must remain an exact byte-for-byte master-image
    # slice. This protects the factory boot chain, app/UI/Wi-Fi owner and data
    # policy from accidental expansion of the replacement set.
    for part in result.image.partitions:
        if part.name in replacements:
            continue
        actual = result.image.read_part_data(part)
        expected = master[part.nand_offset : part.nand_offset + part.part_size]
        if actual != expected:
            raise RuntimeError(f"non-rootfs partition changed: {part.name}")

    image_path = out_dir / image_filename
    write_new(image_path, result.data)
    description_path = out_dir / description_filename
    write_new(
        description_path,
        json.dumps(result.image.describe(), indent=2).encode("utf-8"),
    )
    digest = hashlib.sha256(result.data).hexdigest()
    write_new(
        out_dir / f"{image_filename}.sha256",
        f"{digest}  {image_path.name}\n".encode("ascii"),
    )
    print(f"wrote local-only factory-byte wrapper {image_path} ({len(result.data)} bytes)")
    print(f"sha256 {digest}")
    print(f"partitions {[p.name for p in result.image.partitions]}")

# Minimal second gate after a separately verified stock restore: only rootfs
# A/B are writable. This is the preferred bench artifact because a flasher
# bug or interrupted session cannot rewrite a working boot stage.
rootfs = next(part for part in image_map_for("nano3") if part.name == "rootfs")
rootfs_result = build_kdimg(
    [
        KdimgPartSpec(
            name=f"rootfs_{index}",
            data=replacements[f"rootfs_{index}"],
            nand_offset=slot.offset,
            part_size=slot.size,
            erase_size=NAND_ERASE_BLOCK,
        )
        for index, slot in enumerate(rootfs.slots, start=1)
    ],
    image_info=rootfs_info,
    chip_info="k230",
    board_info=board_info,
)
rootfs_result.image.verify_all()
rootfs_path = out_dir / rootfs_filename
write_new(rootfs_path, rootfs_result.data)
rootfs_digest = hashlib.sha256(rootfs_result.data).hexdigest()
write_new(
    out_dir / f"{rootfs_filename}.sha256",
    f"{rootfs_digest}  {rootfs_path.name}\n".encode("ascii"),
)
print(f"wrote {rootfs_path} ({len(rootfs_result.data)} bytes)")
print(f"sha256 {rootfs_digest}")
print(f"partitions {[p.name for p in rootfs_result.image.partitions]}")
print("artifact_contains_factory_derived_bytes=true")
print("redistribution_authorized=false")
PY

if [ "$PROFILE" = coexistence ]; then
    echo "authorized SSH public key: $AUTHORIZED_KEY_FILE"
else
    echo "private SSH key: $KEY_DIR/id_ed25519"
fi
echo "persistent data is preserved by default; never use --erase-data for an update"
echo "reconnect the stock Wi-Fi dongle after reboot"
