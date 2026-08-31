#!/bin/sh
# Build an offline-test-only UBI+UBIFS no-fastmap pair twice and compare bytes.
set -eu

export LC_ALL=C
export LANG=C
export SOURCE_DATE_EPOCH=1747911960
export KBUILD_BUILD_TIMESTAMP='2025-05-22 10:06:00 +0000'
export KBUILD_BUILD_USER=dcentos-offline
export KBUILD_BUILD_HOST=dcentos-reproducible
export PYTHONDONTWRITEBYTECODE=1

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
LOCK="$SCRIPT_DIR/inputs.lock.json"
DELTA="$SCRIPT_DIR/config.delta"
VERIFY="$SCRIPT_DIR/verify_manifest.py"

usage() {
    cat <<'EOF'
Usage: build-module-bundle.sh --cache-dir DIR --output DIR

Builds a paired, unsigned UBI/UBIFS module bundle for offline virtme+nandsim
tests. DIR must contain the exact .deb files pinned by inputs.lock.json.
The output directory must be absent or empty. No network or product tree is used.
EOF
}

CACHE_DIR=''
OUTPUT_DIR=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --cache-dir)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            CACHE_DIR=$2
            shift 2
            ;;
        --output)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            OUTPUT_DIR=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'error: unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

[ -n "$CACHE_DIR" ] && [ -n "$OUTPUT_DIR" ] || { usage >&2; exit 2; }
[ -d "$CACHE_DIR" ] || { printf 'error: cache directory is unavailable: %s\n' "$CACHE_DIR" >&2; exit 1; }
[ ! -e "$OUTPUT_DIR" ] || [ -d "$OUTPUT_DIR" ] || {
    printf 'error: output path exists and is not a directory: %s\n' "$OUTPUT_DIR" >&2
    exit 1
}

for command_name in python3 dpkg-deb tar make gcc ld strip modinfo cmp sed grep install; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf 'error: required command is unavailable: %s\n' "$command_name" >&2
        exit 1
    }
done

[ "$(gcc -dumpfullversion -dumpversion)" = '11.4.0' ] || {
    printf 'error: gcc 11.4.0 is required\n' >&2
    exit 1
}
[ "$(gcc -dumpmachine)" = 'x86_64-linux-gnu' ] || {
    printf 'error: x86_64-linux-gnu compiler architecture is required\n' >&2
    exit 1
}
make --version | grep -Fq 'GNU Make 4.3' || {
    printf 'error: GNU make 4.3 is required\n' >&2
    exit 1
}
ld --version | sed -n '1p' | grep -Fq '2.38' || {
    printf 'error: GNU binutils 2.38 is required\n' >&2
    exit 1
}

python3 "$VERIFY" verify-lock --lock "$LOCK"
python3 "$VERIFY" verify-inputs --lock "$LOCK" --cache-dir "$CACHE_DIR"
SOURCE_DEB=$(python3 "$VERIFY" package-filename --lock "$LOCK" --role linux-source-deb)
COMMON_HEADERS_DEB=$(python3 "$VERIFY" package-filename --lock "$LOCK" --role linux-headers-common-deb)
GENERIC_HEADERS_DEB=$(python3 "$VERIFY" package-filename --lock "$LOCK" --role linux-headers-generic-deb)

if [ -e "$OUTPUT_DIR" ] && [ -n "$(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
    printf 'error: output directory must be absent or empty: %s\n' "$OUTPUT_DIR" >&2
    exit 1
fi

WORK_DIR='/tmp/dcentos-am2-ubi-reproducible-build'
if ! mkdir "$WORK_DIR" 2>/dev/null; then
    printf 'error: fixed build root is busy or stale: %s\n' "$WORK_DIR" >&2
    printf 'error: verify that no build is active before removing a stale root\n' >&2
    exit 1
fi
cleanup() {
    if [ "$WORK_DIR" = '/tmp/dcentos-am2-ubi-reproducible-build' ]; then
        rm -rf -- "$WORK_DIR"
    else
        printf 'warning: refusing to clean unexpected work path: %s\n' "$WORK_DIR" >&2
    fi
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$WORK_DIR/results"

build_once() {
    result_name=$1
    # Reuse the same absolute path for both independent extractions. This also
    # prevents Kbuild's source-version machinery from learning build-a/build-b
    # path differences that compiler prefix maps cannot affect.
    run_dir="$WORK_DIR/build"
    [ ! -e "$run_dir" ] || {
        printf 'error: fixed build path was not cleaned before %s\n' "$result_name" >&2
        exit 1
    }
    sysroot="$run_dir/sysroot"
    source_package="$run_dir/source-package"
    source_unpack="$run_dir/source"
    artifacts="$run_dir/artifacts"
    mkdir -p "$sysroot" "$source_package" "$source_unpack" "$artifacts"

    dpkg-deb -x "$CACHE_DIR/$SOURCE_DEB" "$source_package"
    dpkg-deb -x "$CACHE_DIR/$COMMON_HEADERS_DEB" "$sysroot"
    dpkg-deb -x "$CACHE_DIR/$GENERIC_HEADERS_DEB" "$sysroot"

    source_tar="$source_package/usr/src/linux-source-5.15.0/linux-source-5.15.0.tar.bz2"
    python3 "$VERIFY" verify-embedded --lock "$LOCK" --path "$source_tar"
    tar --extract --bzip2 --file "$source_tar" --directory "$source_unpack"

    kernel_source="$source_unpack/linux-source-5.15.0"
    kernel_build="$sysroot/usr/src/linux-headers-5.15.0-181-generic"
    ubi_source="$kernel_source/drivers/mtd/ubi"
    ubifs_source="$kernel_source/fs/ubifs"
    [ -d "$ubi_source" ] && [ -d "$ubifs_source" ] && [ -f "$kernel_build/.config" ] || {
        printf 'error: extracted kernel source/header layout differs from the pinned Ubuntu packages\n' >&2
        exit 1
    }

    cp -p "$kernel_build/.config" "$artifacts/config.base"
    fastmap_count=$(grep -c '^CONFIG_MTD_UBI_FASTMAP=y$' "$kernel_build/.config" || true)
    [ "$fastmap_count" -eq 1 ] || {
        printf 'error: base config does not contain exactly one enabled fastmap symbol\n' >&2
        exit 1
    }
    sed -i 's/^CONFIG_MTD_UBI_FASTMAP=y$/# CONFIG_MTD_UBI_FASTMAP is not set/' "$kernel_build/.config"
    sed -i '/^CONFIG_MTD_UBI_FASTMAP=y$/d' "$kernel_build/include/config/auto.conf"
    sed -i '/^#define CONFIG_MTD_UBI_FASTMAP 1$/d' "$kernel_build/include/generated/autoconf.h"
    touch -r "$kernel_build/Module.symvers" \
        "$kernel_build/.config" \
        "$kernel_build/include/config/auto.conf" \
        "$kernel_build/include/generated/autoconf.h"
    cp -p "$kernel_build/.config" "$artifacts/config.effective"
    python3 "$VERIFY" verify-config \
        --lock "$LOCK" \
        --base "$artifacts/config.base" \
        --effective "$artifacts/config.effective" \
        --delta "$DELTA"

    canonical_source='/usr/src/dcentos-linux-source-5.15.0'
    canonical_build='/usr/src/dcentos-linux-headers-5.15.0-181-generic'
    canonical_sysroot='/usr/src/dcentos-sysroot'
    prefix_flags="-ffile-prefix-map=$kernel_source=$canonical_source -fdebug-prefix-map=$kernel_source=$canonical_source -fmacro-prefix-map=$kernel_source=$canonical_source -ffile-prefix-map=$kernel_build=$canonical_build -fdebug-prefix-map=$kernel_build=$canonical_build -fmacro-prefix-map=$kernel_build=$canonical_build -ffile-prefix-map=$sysroot=$canonical_sysroot -fdebug-prefix-map=$sysroot=$canonical_sysroot -fmacro-prefix-map=$sysroot=$canonical_sysroot"

    env KCFLAGS="$prefix_flags" make -j1 -C "$kernel_build" M="$ubi_source" modules
    env KCFLAGS="$prefix_flags" KBUILD_EXTRA_SYMBOLS="$ubi_source/Module.symvers" \
        make -j1 -C "$kernel_build" M="$ubifs_source" modules

    install -m 0644 "$ubi_source/ubi.ko" "$artifacts/ubi-nofastmap.ko"
    install -m 0644 "$ubifs_source/ubifs.ko" "$artifacts/ubifs-nofastmap.ko"
    strip --strip-debug "$artifacts/ubi-nofastmap.ko" "$artifacts/ubifs-nofastmap.ko"
    mv "$artifacts" "$WORK_DIR/results/$result_name"
    rm -rf -- "$run_dir"
}

build_once build-a
build_once build-b

for artifact in ubi-nofastmap.ko ubifs-nofastmap.ko config.base config.effective; do
    if ! cmp -s "$WORK_DIR/results/build-a/$artifact" "$WORK_DIR/results/build-b/$artifact"; then
        printf 'error: independent builds differ for %s\n' "$artifact" >&2
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"
for artifact in ubi-nofastmap.ko ubifs-nofastmap.ko config.base config.effective; do
    install -m 0644 "$WORK_DIR/results/build-a/$artifact" "$OUTPUT_DIR/$artifact"
done
install -m 0644 "$DELTA" "$OUTPUT_DIR/config.delta"
install -m 0644 "$LOCK" "$OUTPUT_DIR/inputs.lock.json"

python3 "$VERIFY" generate \
    --lock "$OUTPUT_DIR/inputs.lock.json" \
    --base "$OUTPUT_DIR/config.base" \
    --effective "$OUTPUT_DIR/config.effective" \
    --delta "$OUTPUT_DIR/config.delta" \
    --ubi "$OUTPUT_DIR/ubi-nofastmap.ko" \
    --ubifs "$OUTPUT_DIR/ubifs-nofastmap.ko" \
    --output "$OUTPUT_DIR/manifest.json"
python3 "$VERIFY" verify-bundle \
    --manifest "$OUTPUT_DIR/manifest.json" \
    --lock "$OUTPUT_DIR/inputs.lock.json" \
    --bundle-dir "$OUTPUT_DIR"

printf 'offline-only paired module bundle written to %s\n' "$OUTPUT_DIR"
