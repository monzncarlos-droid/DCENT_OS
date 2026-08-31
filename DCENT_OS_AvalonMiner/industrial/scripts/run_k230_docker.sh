#!/usr/bin/env bash
# Host-side driver: run a command inside the DCENT K230 SDK build container.
#
# Usage (Git Bash, from anywhere):
#   MSYS_NO_PATHCONV=1 bash DCENT_OS_AvalonMiner/scripts/run_k230_docker.sh \
#       bash /dcent/scripts/build_k230_in_docker.sh
#
# Builds the dcent/k230-sdk image on first use, then runs the given command
# with:
#   <sdk clone>                  -> /sdk
#   DCENT_OS_AvalonMiner      -> /dcent
#   DCENT_OS_AvalonMiner/build/opt-toolchain -> /opt/toolchain (cached)
#
# The SDK checkout is expected at
#    (override with K230_SDK_DIR).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROJECT_DIR="$REPO_ROOT/DCENT_OS_AvalonMiner"
SDK_DIR="${K230_SDK_DIR:-$REPO_ROOT/knowledge-base/repos/k230_linux_sdk}"
IMAGE="dcent/k230-sdk:latest"

if [ ! -f "$SDK_DIR/Makefile" ]; then
    echo "run: SDK checkout not found at $SDK_DIR (set K230_SDK_DIR)" >&2
    exit 1
fi

mkdir -p "$PROJECT_DIR/build/opt-toolchain"

# Git Bash rewrites leading-slash container paths; disable that.
export MSYS_NO_PATHCONV=1

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "run: building $IMAGE (one-time)..."
    docker build \
        -f "$PROJECT_DIR/scripts/docker/Dockerfile" \
        -t "$IMAGE" "$PROJECT_DIR/scripts/docker"
fi

if [ "$#" -eq 0 ]; then
    echo "usage: $0 <command...>  (joined and run via bash -lc in the container)" >&2
    exit 2
fi

# Build workspace is a named volume, NOT the Windows bind mount: Docker
# Desktop's 9p/gRPC-FUSE timestamp granularity makes cpio skip files during
# buildroot package extraction ("newer or same age version exists"), which
# breaks the build. The build script syncs the SDK checkout into the volume;
# artifacts sync back out to the bind mounts.
exec docker run --rm -h k230-build \
    -v "$SDK_DIR:/sdk" \
    -v "$PROJECT_DIR:/dcent" \
    -v "$REPO_ROOT/projects/dcent-toolbox:/toolbox" \
    -v "$PROJECT_DIR/build/opt-toolchain:/opt/toolchain" \
    -v k230-work:/work \
    -w /sdk "$IMAGE" bash -lc "$*"
