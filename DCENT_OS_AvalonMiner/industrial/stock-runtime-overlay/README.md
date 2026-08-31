# Nano 3 stock-chain runtime overlay

This overlay stages the real static `dcentrald-avalon` userspace while leaving
Canaan's boot chain, app partition and runtime ownership intact.

The Nano 3 factory app is one monolithic `btcminer` process. It owns
`/dev/ttyS1`, mining, thermal control, the front-panel UI, Wi-Fi and the web
server. Unlike the Nano 3S reference architecture, this held Nano 3 binary does
not import the SysV message-queue functions used by the current DCENT shim.

Consequently:

- `S98dcent-data` repairs only Canaan's evidenced empty Nano 3 data UBI:
  exact K230 identity, `ubi.mtd=8`, and the 28 MiB `mtd12` geometry are
  required; zero volumes creates `ubi_data_part`, while any unknown existing
  layout is left untouched. Before stock rcS can mount over the rootfs `/data`
  underlay, only `usrcon/systemcfg.ini` and `usrcon/cgminer.ini` are staged.
  After the real volume is mounted, a staged file is restored only when the
  corresponding persistent file is absent; existing Wi-Fi, web, and pool
  credentials always win. A missing `/data/usrcon` is created even when there
  was no underlay configuration to stage, allowing stock's direct `w+` saves
  on a factory-empty volume; a symlink or non-directory at that path is
  refused. The migration never formats,
  deletes, resizes, or generically copies data from the underlay.
- Interrupted config publication is restart-safe. Private root-only
  `.dcentos-config-{init,migrate}.*` work directories contain only prepared
  files; the next locked pass removes them only when every entry is an expected
  regular non-symlink config. A hard-linked complete destination survives that
  cleanup, while a pre-publication partial is discarded and regenerated.
  Unexpected or indirect scratch state blocks launch instead of broad deletion.
  The same exact-layout rule removes stranded `/tmp/dcentos-data-seed.*`
  directories from a prior interrupted boot without printing staged values. A
  boot-local `/run/dcentos-data-init-lock` serializes cleanup, staging, and the
  asynchronous worker; a non-owner cannot remove the lock.
- The stock `/etc/user_permission_chg.sh` hook is also the synchronous
  post-mount/pre-`btcminer` barrier. It waits for the exact data volume and a
  boot-local marker published only after the asynchronous migration completes,
  preserves every nonempty config, restores only an absent/zero system config,
  and installs a valid no-secret `[cgminercfg]` skeleton only when the pool
  config is absent/zero. If readiness cannot be proven it blocks stock launch,
  because stock `rcS` ignores helper exit codes.
- `dcentrald-avalon` is installed under `/usr/libexec/dcentos/`; its normal
  mining path is never autostarted.
- `S99dcent-observer` waits for stock startup, invokes the daemon's fail-closed
  `--stock-observer-once` branch, then invokes its separately bounded
  `--nano3-read-only-observer-once` branch at nice 19. The latter reads the
  exact held IIO temperature and PWM readback attributes with bounded async
  reads and reports explicitly non-authorizing evidence. It does not enable or
  read timer5, open UART/watchdog, claim an interlock, or write an actuator.
  Both branches return before config, pool, IPC, or ASIC-driver initialization;
  their read-only inventory is `/tmp/dcentos-stock-coexistence.txt`.
- The observer also launches the diagnostic-only
  `nano3-health-snapshot.sh` at nice 19. It writes seven bounded, root-only
  `/proc` snapshots under `/run/dcentos-health` around the observed five-minute
  management-starvation window, but only after verifying `/run` is tmpfs. It
  never reads configs, command lines, environments, devices, or IPC and never
  signals or reprioritizes `btcminer`; all snapshots disappear on reboot.
  `collector_complete` proves only that the shell finished. It is explicitly
  not a temperature, fan, thermal-loop, watchdog, controller, or rail-safety
  heartbeat, and it never authorizes continued hashing.
- `S99dcent-priority-guard` is a candidate mitigation for a stock management-
  thread demotion mechanism that could explain the 2026-08-22 soak stall; no
  controlled live A/B has yet proved causation or efficacy. The held binary
  applies `nice(+10)` to its
  own `API`, `watchdog_thread`, and source/DWARF `watchpool_thread` at creation
  while `cgminer_thread` runs `nice(-10)`. Linux `TASK_COMM_LEN=16` truncates
  that last 16-character source name to exact live `/proc` comm
  `watchpool_threa`, which is the only value the guard matches. Under two-core
  saturation this disparity can starve the demoted accept loops while the
  kernel still completes TCP handshakes. The guard raises exactly those three
  thread names back to the
  stock default nice 0 via `busybox renice` on their task IDs (the applet is
  present in the held rootfs busybox; there is no `/bin/renice` symlink). It
  never touches `cgminer_thread`, never signals, stops, restarts, or wraps
  `btcminer`, and opens no device or configuration. Before each mutation it
  admits only the exact held running `btcminer` SHA-256, requires one and only
  one of every target thread, and accepts only nice 10 or an already-corrected
  nice 0. It revalidates the PID/hash/task identities around each mutation,
  post-checks `/proc` nice 0, and emits locale-independent per-pass hash/nice
  evidence. A distinct `guard_initial_admission=success` appears immediately
  after the complete first correction is post-checked, while final window
  status remains separate. Any mismatch is terminally non-passing.
  It writes its root-only lock/report only after proving `/run` is an exact
  tmpfs mount. It re-asserts for a bounded 30-minute window (60 passes x 30 s)
  after stock startup, refuses to act if `pidof btcminer` reports more than
  one pid, and is inert unless the image stages
  `/etc/dcentos/nano3-priority-guard.enabled`. This is the first overlay
  component that deliberately changes a stock process's runtime behavior:
  it is a scheduling correction for stock's own management threads, not a
  thermal/fan/watchdog heartbeat, not an interlock, and not permission to
  leave the ASIC energized. Evidence and rationale:
  ;
  host checks in `scripts/test_nano3_priority_guard.sh`. Because this adds
  overlay files, the successor image and its container/verifier pins must be
  rebuilt before the next flash candidate.
- `nano3-persistence-snapshot.sh` is a separately invoked, read-only acceptance
  collector for one explicitly authorized pre- or post-reboot observation. It
  requires the exact `/dev/ubi2_0` UBIFS mount, mtd12/`ubi_data_part` identity,
  boot-local readiness marker, and two bounded regular nonempty INI files. It
  emits only fixed metadata, whole-file/section-key digests, modes, owners, and
  false authority fields; configuration values never enter stdout or errors.
  The host `scripts/verify_nano3_persistence_snapshots.py` requires the same
  run ID, distinct boot IDs, and byte-identical metadata/digests. The snapshots
  remain unsigned operator-supplied evidence and grant no reboot/contact right.
- `/etc/init.d/dcentrald` requires stock `btcminer` to be stopped, an explicit
  config, and a one-shot risk acknowledgement before a laboratory start.

The production fix is a Nano 3 transport that speaks its evidenced `/dev/ttyS1`
Avalon protocol, not concurrent access to the stock miner's hardware or a
guessed SysV queue.
