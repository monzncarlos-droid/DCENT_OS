# AM2 offline no-fastmap UBI module bundle

This directory owns a deliberately narrow test artifact: an ABI-matched pair of
`ubi.ko` and `ubifs.ko` modules with `CONFIG_MTD_UBI_FASTMAP` disabled for the
Ubuntu 22.04 `5.15.0-181-generic` virtme+nandsim environment. It is not a product
kernel path, a firmware package, or permission to install modules on a miner.

The pair closes a reproducibility problem in the AM2 NAND geometry test. Stock
Ubuntu reserves two additional physical eraseblocks whenever UBI fastmap is
compiled in, even when `fm_autoconvert=0`. A no-fastmap UBI module produces the
same 456-PEB / 40-reserved-PEB / 412-available-PEB accounting expected from the
AM2 geometry. `ubifs.ko` must be rebuilt with it: Ubuntu enables
`CONFIG_MODVERSIONS`, and changing UBI changes CRCs for symbols consumed by
UBIFS. Loading only the replacement `ubi.ko` is therefore an invalid module
closure.

## Trust and scope

- `inputs.lock.json` pins every admitted package by Debian package name,
  filename, version, architecture, and SHA-256. The verifier checks both the
  archive digest and its control fields. The builder resolves its three inputs
  by lock role instead of carrying a second filename authority. The source
  tarball embedded inside the source package is pinned separately. Runtime-only
  packages are recorded but are not required by the module builder.
- `config.delta` is intentionally one line. Both generation and verification
  compare the complete base and effective symbol maps and reject any second
  config change.
- The builder extracts the exact `.181` source package instead of using the
  mutable `/usr/src/linux-source-5.15.0` symlink/directory.
- UBI is built first. UBIFS consumes the new UBI `Module.symvers` through
  `KBUILD_EXTRA_SYMBOLS`, making the pair explicit.
- Two fresh source/header extractions are built serially. Source and header
  paths use a concurrency-guarded fixed `/tmp` root and are additionally
  prefix-mapped to canonical values. The stripped module bytes are compared,
  and the build fails if either module differs. A stale fixed root is never
  removed automatically because another build may own it. Kernel dynamic-debug
  strings retain that fixed root even where compiler prefix maps do not apply;
  the path is therefore deliberately stable across separate invocations.
- The manifest is bound to the input-lock bytes and verifies scope, the kernel
  release/vermagic, full config closure, module pairing, dependency metadata,
  srcversions, the exact parameter-name surface (`ubi`: `block,mtd`; `ubifs`:
  empty), sizes, and SHA-256 hashes. Symlinks and path traversal are rejected.

The resulting modules are unsigned, out-of-tree test artifacts. Their expected
guest taint is not a production trust statement. Emulation does not prove
physical NAND behavior.

## Offline build

Run on the pinned Ubuntu 22.04 x86-64 environment with GCC 11.4.0, binutils
2.38, GNU make 4.3, kmod, dpkg, bzip2, and Python 3.9 or newer. No network is
used. The cache directory must contain at least the three build packages marked
`required_for_build` in the lock.

```sh
scripts/virtme/am2-ubi/build-module-bundle.sh \
  --cache-dir /var/cache/apt/archives \
  --output /tmp/dcentos-am2-ubi-bundle
```

The output contains `ubi-nofastmap.ko`, `ubifs-nofastmap.ko`, the base and
effective configs, the one-line delta, the copied input lock, and
`manifest.json`. Keep generated bundles outside the repository; module binaries
must not be committed.

An existing bundle can be checked independently:

```sh
python3 scripts/virtme/am2-ubi/verify_manifest.py verify-bundle \
  --manifest /tmp/dcentos-am2-ubi-bundle/manifest.json \
  --lock scripts/virtme/am2-ubi/inputs.lock.json \
  --bundle-dir /tmp/dcentos-am2-ubi-bundle
```

The exact geometry-only lane re-verifies the bundle and the byte-exact pinned
kernel before entering the VM, refuses preloaded stock UBI/UBIFS modules, loads
the pair in dependency order, and requires the complete live AM2 tuple:

```sh
scripts/sysupgrade_offline_virtme_nandsim_runner.sh \
  --target am2-s19jpro \
  --kernel /boot/vmlinuz-5.15.0-181-generic \
  --am2-ubi-bundle /tmp/dcentos-am2-ubi-bundle \
  --geometry-only --require-nandsim
```

This mode does not parse a firmware package or claim a sysupgrade write/boot
result. Its distinct module-pair and geometry sentinels prove only the loaded
module closure and emulated UBI accounting.

## CI boundary

`test_manifest_verifier.sh` is host-safe: it uses synthetic module bytes and an
injected metadata reader, so it executes on Windows and Linux without root,
Docker, QEMU, kmod, package downloads, or kernel-module loading. It includes
negative fixtures for scope escalation, unpaired modules, hash drift, path
traversal, metadata drift, fastmap leakage, config-closure expansion, and
duplicate JSON keys.

The host-safe verifier is wired into the ordinary offline gate. The expensive
Linux builder and privileged guest runner are intentionally not scheduled in
ordinary CI; they require the pinned package cache, exact kernel, generated
external module bundle, virtme/QEMU, and root-capable nandsim guest.
