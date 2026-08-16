#!/bin/sh
#
# Fail-closed Zynq external-media runtime posture.
#
# The marker is baked only into a DCENT external-media initramfs. Normal
# squashfs/NAND images do not contain it. This helper deliberately provides no
# MTD, UBI, boot-environment, or update operation: it only prepares volatile
# /data and /etc state and proves that /data is backed by tmpfs.

DCENT_EXTERNAL_MEDIA_MARKER=${DCENTOS_EXTERNAL_MEDIA_MARKER:-/etc/dcentos/external-media-ephemeral-root}
DCENT_EXTERNAL_MEDIA_DATA_DIR=${DCENTOS_EXTERNAL_MEDIA_DATA_DIR:-/data}
DCENT_EXTERNAL_MEDIA_ETC_DIR=${DCENTOS_EXTERNAL_MEDIA_ETC_DIR:-/etc}
DCENT_EXTERNAL_MEDIA_TMP_DIR=${DCENTOS_EXTERNAL_MEDIA_TMP_DIR:-/tmp}
DCENT_EXTERNAL_MEDIA_RUN_DIR=${DCENTOS_EXTERNAL_MEDIA_RUN_DIR:-/run}
DCENT_EXTERNAL_MEDIA_MOUNTS_FILE=${DCENTOS_MOUNTS_FILE:-/proc/mounts}
DCENT_EXTERNAL_MEDIA_READY_FILE=${DCENTOS_EXTERNAL_MEDIA_READY_FILE:-$DCENT_EXTERNAL_MEDIA_RUN_DIR/dcentos/external-media-ephemeral-ready}

dcent_external_media_marker_present() {
    [ -e "$DCENT_EXTERNAL_MEDIA_MARKER" ] || [ -L "$DCENT_EXTERNAL_MEDIA_MARKER" ]
}

dcent_external_media_marker_is_valid() {
    [ -f "$DCENT_EXTERNAL_MEDIA_MARKER" ] && [ ! -L "$DCENT_EXTERNAL_MEDIA_MARKER" ]
}

dcent_external_media_data_is_ephemeral() {
    [ -r "$DCENT_EXTERNAL_MEDIA_MOUNTS_FILE" ] || return 1
    awk -v path="$DCENT_EXTERNAL_MEDIA_DATA_DIR" '
        $2 == path {
            mounts++
            if ($1 == "tmpfs" && $3 == "tmpfs") {
                count = split($4, options, ",")
                for (i = 1; i <= count; i++)
                    if (options[i] == "rw")
                        writable_tmpfs++
            }
        }
        END { exit (mounts == 1 && writable_tmpfs == 1) ? 0 : 1 }
    ' "$DCENT_EXTERNAL_MEDIA_MOUNTS_FILE"
}

dcent_external_media_prepare_ephemeral_root() {
    dcent_external_media_marker_is_valid || {
        echo "[!!] External-media marker is absent or unsafe; persistent storage remains barred" >&2
        return 1
    }

    rm -f "$DCENT_EXTERNAL_MEDIA_READY_FILE" 2>/dev/null || true
    mkdir -p "$DCENT_EXTERNAL_MEDIA_DATA_DIR" || return 1
    if ! mount -t tmpfs -o size=16m,mode=0755,nosuid,nodev,noexec \
        tmpfs "$DCENT_EXTERNAL_MEDIA_DATA_DIR"; then
        echo "[!!] External-media /data tmpfs mount failed; persistent storage remains barred" >&2
        return 1
    fi
    if ! dcent_external_media_data_is_ephemeral; then
        echo "[!!] External-media /data backing is not exactly one writable tmpfs mount" >&2
        return 1
    fi

    mkdir -p \
        "$DCENT_EXTERNAL_MEDIA_DATA_DIR/dcent" \
        "$DCENT_EXTERNAL_MEDIA_DATA_DIR/config" \
        "$DCENT_EXTERNAL_MEDIA_DATA_DIR/profiles" \
        "$DCENT_EXTERNAL_MEDIA_DATA_DIR/keys" \
        "$DCENT_EXTERNAL_MEDIA_DATA_DIR/logs" || return 1
    chmod 0700 "$DCENT_EXTERNAL_MEDIA_DATA_DIR/dcent" 2>/dev/null || return 1

    _upper="$DCENT_EXTERNAL_MEDIA_TMP_DIR/dcentos-external-etc/upper"
    _work="$DCENT_EXTERNAL_MEDIA_TMP_DIR/dcentos-external-etc/work"
    mkdir -p "$_upper" "$_work" || return 1
    if ! mount -t overlay overlay \
        -o "lowerdir=$DCENT_EXTERNAL_MEDIA_ETC_DIR,upperdir=$_upper,workdir=$_work,nodev,nosuid" \
        "$DCENT_EXTERNAL_MEDIA_ETC_DIR"; then
        echo "[!!] External-media volatile /etc overlay failed" >&2
        return 1
    fi
    mkdir -p "$DCENT_EXTERNAL_MEDIA_ETC_DIR/dropbear" || return 1

    mkdir -p "$(dirname "$DCENT_EXTERNAL_MEDIA_READY_FILE")" || return 1
    : > "$DCENT_EXTERNAL_MEDIA_READY_FILE" || return 1
    chmod 0600 "$DCENT_EXTERNAL_MEDIA_READY_FILE" 2>/dev/null || return 1
    echo "[OK] External-media ephemeral root active (/data tmpfs; /etc volatile overlay)"
    return 0
}
