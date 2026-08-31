# DCENT K230 SDK build environment.
#
# Derived from kendryte/k230_linux_sdk tools/docker/Dockerfile (Ubuntu 22.04
# base + the SDK's documented build dependencies), with two DCENT changes:
#   - no apt/pip mirror rewrites (the vendor file forces Tsinghua mirrors)
#   - adds mtd-utils (ubinize/ubiformat) for DCENT SPI-NAND UBI rootfs
#     assembly, device-tree-compiler for fail-closed DTB inspection, and
#     genimage is pulled in by Buildroot itself (host package)
#
# Build:
#   docker build -f scripts/docker/Dockerfile -t dcent/k230-sdk scripts/docker
#
# Run (see scripts/build_k230_in_docker.sh):
#   MSYS_NO_PATHCONV=1 docker run --rm -h k230-build \
#     -v "<sdk>:/sdk" -v "<toolchain-dir>:/opt/toolchain" \
#     -w /sdk dcent/k230-sdk <command>

FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        sudo git sed make binutils build-essential diffutils gcc g++ bash \
        patch gzip bzip2 perl tar cpio unzip rsync file bc findutils wget \
        libncurses-dev python3 python3-pip libssl-dev gawk cmake bison flex \
        parted curl xz-utils file mtd-utils dosfstools fakeroot swig \
        openssh-client device-tree-compiler \
        libglib2.0-dev ncurses-term && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# pcpp: the SDK's post-build scripts preprocess config headers with it.
RUN pip3 install --no-cache-dir pcpp ubi_reader

# The SDK build runs as whatever uid owns the mounted SDK checkout; give that
# uid passwordless sudo (vendor container does the same).
RUN echo 'ALL ALL = (ALL) NOPASSWD: ALL' >> /etc/sudoers
