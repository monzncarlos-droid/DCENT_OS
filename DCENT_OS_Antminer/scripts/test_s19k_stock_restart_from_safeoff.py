#!/usr/bin/env python3
"""Offline adversarial tests for the terminal-SafeOff stock restart helper."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent
HELPER_SOURCE = SCRIPTS / "dcentrald_s19k_stock_restart_from_safeoff.sh"
CUSTODY_SOURCE = SCRIPTS / "dcentrald_s19k_braiins_supervisor_custody.sh"
PROFILE = "live88_two_bhb56903_slots_2_3"
IDENTITY_SHA = "1" * 64
MODEL_SHA = "2" * 64
IDENTITY_NAMES = "BHB56903,BHB56903"
IDENTITY_ADDRESSES = "2,3"
IDENTITY_EEPROM = "0x50=absent,0x51=05:11,0x52=05:11"
WSL = ["wsl.exe", "-d", "Ubuntu-22.04", "--exec"]


def sha_bytes(path: Path) -> tuple[str, int]:
    blob = path.read_bytes()
    return hashlib.sha256(blob).hexdigest(), len(blob)


def line_file(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


class StockRestartFixture:
    def __init__(self, variant: str = "success", *, native_wsl: bool = False) -> None:
        self.variant = variant
        self._wsl_native_paths: list[str] = []
        self._temp = None
        if native_wsl:
            native_root = subprocess.run(
                [*WSL, "mktemp", "-d", "/tmp/dcent-s19k-stock-restart.XXXXXX"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.wsl_root = native_root.stdout.strip()
            if not self.wsl_root.startswith("/tmp/dcent-s19k-stock-restart."):
                raise AssertionError(
                    f"unexpected native fixture root: {native_root.stdout!r}"
                )
            self._wsl_native_paths.append(self.wsl_root)
            self.root = Path(
                r"\\wsl.localhost\Ubuntu-22.04" + self.wsl_root.replace("/", "\\")
            )
        else:
            self._temp = tempfile.TemporaryDirectory(
                prefix="dcent-s19k-stock-restart-"
            )
            self.root = Path(self._temp.name)
            self.wsl_root = self._wsl_path(self.root)
        native = subprocess.run(
            [*WSL, "mktemp", "-d", "/tmp/dcent-s19k-wdt-fixture.XXXXXX"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.wsl_watchdog_root = native.stdout.strip()
        if not self.wsl_watchdog_root.startswith("/tmp/dcent-s19k-wdt-fixture."):
            raise AssertionError(f"unexpected native fixture path: {native.stdout!r}")
        self._wsl_native_paths.append(self.wsl_watchdog_root)
        subprocess.run(
            [
                *WSL,
                "sh",
                "-c",
                "set -eu; "
                f"mknod '{self.wsl_watchdog_root}/watchdog' c 10 130; "
                f"mknod '{self.wsl_watchdog_root}/watchdog0' c 249 0; "
                f"chmod 000 '{self.wsl_watchdog_root}/watchdog' "
                f"'{self.wsl_watchdog_root}/watchdog0'",
            ],
            check=True,
        )
        self.prefix = f"{self.wsl_root}/trial_"
        self.trial = self.root / "trial_case"
        self.trial.mkdir()
        self.wsl_trial = f"{self.wsl_root}/trial_case"
        self.proc = self.root / "proc"
        self.proc.mkdir()
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()
        self.gpio = self.root / "gpio"
        self.gpio.mkdir()
        for number, value in ((437, "1"), (454, "0"), (455, "0"), (456, "0")):
            target = self.gpio / f"gpio{number}"
            target.mkdir()
            line_file(target / "value", [value])
        self.log = self.root / "bosminer.log"
        line_file(self.log, ["fixture baseline"])
        self._chmod_mode("600", self.log)
        self.s99 = self.root / "S99bosminer"
        self.start_count = self.root / "start.count"
        self._write_s99(variant)
        self.busybox = self.root / "busybox"
        self.busybox.write_text(
            "#!/bin/sh\nset -eu\n"
            'case "${0##*/}:$1" in\n'
            '  sh:*) exec /bin/sh "$@" ;;\n'
            '  *:env) shift; exec /usr/bin/env "$@" ;;\n'
            '  *:ls) shift; exec /bin/ls "$@" ;;\n'
            '  *:tail) shift; exec /usr/bin/tail "$@" ;;\n'
            '  *:sha256sum) shift; exec /usr/bin/sha256sum "$@" ;;\n'
            '  *:awk) shift; exec /usr/bin/awk "$@" ;;\n'
            '  *:dd) shift; exec /bin/dd "$@" ;;\n'
            '  *:sync) shift; exec /bin/sync "$@" ;;\n'
            '  *) exit 64 ;;\n'
            'esac\n',
            encoding="utf-8",
            newline="\n",
        )
        self.bos_defaults = self.root / "bos-defaults.sh"
        self.bos_defaults.write_bytes(b"# fixture pinned bos defaults\n")
        self.stock_bos_tools = self.root / "bos-tools"
        self.stock_bos_tools.write_bytes(b"fixture pinned bos-tools executable\n")
        self.stock_bosminer = self.root / "bosminer"
        self.stock_bosminer.write_bytes(b"fixture pinned bosminer executable\n")
        self.start_stop_daemon = self.root / "start-stop-daemon"
        self._symlink("busybox", self.start_stop_daemon)
        self.shell_interpreter = self.root / "sh"
        self._symlink("busybox", self.shell_interpreter)
        self.busybox_ld = self.root / "ld-target"
        self.busybox_ld.write_bytes(b"fixture loader\n")
        self.busybox_ld_link = self.root / "ld-link"
        self._symlink("ld-target", self.busybox_ld_link)
        self.busybox_libm = self.root / "libm-target"
        self.busybox_libm.write_bytes(b"fixture libm\n")
        self.busybox_libm_link = self.root / "libm-link"
        self._symlink("libm-target", self.busybox_libm_link)
        self.busybox_libc = self.root / "libc-target"
        self.busybox_libc.write_bytes(b"fixture libc\n")
        self.busybox_libc_link = self.root / "libc-link"
        self._symlink("libc-target", self.busybox_libc_link)
        self.runner = self.trial / "run_trial"
        self._write_runner(wrong_identity=variant == "wrong_identity")
        self.custody = self.trial / "supervisor_custody_observer"
        shutil.copyfile(CUSTODY_SOURCE, self.custody)
        self.binary = self.trial / "dcentrald"
        self.binary.write_bytes(b"fixture dcentrald\n")
        self.config = self.trial / "dcentrald_s19k.toml"
        self.config.write_bytes(b"[fixture]\nvalue = true\n")
        self.helper = self.trial / "stock_restart_helper"
        self._write_helper()
        self._chmod(
            self.s99,
            self.busybox,
            self.bos_defaults,
            self.stock_bos_tools,
            self.stock_bosminer,
            self.runner,
            self.custody,
            self.binary,
            self.helper,
        )
        self._write_contract()
        if variant == "preexisting_stock":
            self.make_process(
                9495,
                "bosminer",
                "/usr/bin/bosminer",
                1,
                9495,
                9495,
                100,
                ["/usr/bin/bosminer", "--log-to-file"],
            )
        elif variant == "preexisting_pidfile":
            line_file(self.run_dir / "bosminer.pid", ["9495"])
        elif variant == "watchdog_fd":
            self.make_process(333, "other", "/bin/other", 1, 333, 333, 99, ["/bin/other"])
            fd = self.proc / "333" / "task" / "333" / "fd"
            self._symlink(f"{self.wsl_watchdog_root}/watchdog0", fd / "4")
        elif variant == "nonleader_watchdog_fd":
            self.make_process(333, "other", "/bin/other", 1, 333, 333, 99, ["/bin/other"])
            leader = self.proc / "333" / "task" / "333"
            worker = self.proc / "333" / "task" / "334"
            (worker / "fd").mkdir(parents=True)
            for name in ("comm", "cmdline", "status", "environ"):
                shutil.copyfile(leader / name, worker / name)
            self._symlink("/bin/other", worker / "exe")
            self._symlink("/", worker / "cwd")
            for fd_number in ("0", "1", "2"):
                self._symlink("/dev/null", worker / "fd" / fd_number)
            line_file(
                worker / "stat",
                ["334 (worker) S 1 333 333 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100"],
            )
            self._symlink(f"{self.wsl_watchdog_root}/watchdog0", worker / "fd" / "4")
        elif variant == "preexisting_launcher":
            self.make_process(
                333,
                "start-stop-daem",
                "/bin/busybox",
                1,
                333,
                333,
                99,
                [
                    "start-stop-daemon",
                    "-S",
                    "-p",
                    "/var/run/bosminer.pid",
                    "--exec",
                    "/usr/bin/bos-tools",
                    "--",
                    "run-and-watch",
                    "--",
                    "/usr/bin/bosminer",
                ],
            )
        elif variant == "wrong_busybox":
            self.busybox.write_bytes(b"substituted launcher\n")
        elif variant == "wrong_s99":
            self.s99.write_bytes(b"substituted stock init\n")
        elif variant == "wrong_bos_defaults":
            self.bos_defaults.write_bytes(b"substituted bos defaults\n")
        elif variant == "wrong_busybox_loader":
            self.busybox_ld.write_bytes(b"substituted loader\n")
        elif variant == "wrong_busybox_libm":
            self.busybox_libm.write_bytes(b"substituted libm\n")
        elif variant == "wrong_busybox_libc":
            self.busybox_libc.write_bytes(b"substituted libc\n")
        elif variant == "wrong_stock_bos_tools":
            self.stock_bos_tools.write_bytes(b"substituted bos-tools\n")
        elif variant == "wrong_stock_bosminer":
            self.stock_bosminer.write_bytes(b"substituted bosminer\n")
        elif variant == "malformed_nonleader_task":
            self.make_process(333, "other", "/bin/other", 1, 333, 333, 99, ["/bin/other"])
            malformed = self.proc / "333" / "task" / "334"
            (malformed / "fd").mkdir(parents=True)
            line_file(malformed / "stat", ["malformed task stat"])
        elif variant in (
            "live_writer_space_comm",
            "live_writer_right_paren_space",
            "writer_missing_stat",
            "writer_truncated_stat",
        ):
            writer_comm = (
                "run) trial wrapper"
                if variant == "live_writer_right_paren_space"
                else "run trial wrapper"
            )
            self.make_process(
                7777,
                writer_comm,
                "/bin/other",
                1,
                7777,
                7777,
                123,
                ["/bin/other"],
            )
            if variant == "writer_missing_stat":
                (self.proc / "7777" / "stat").unlink()
            elif variant == "writer_truncated_stat":
                line_file(self.proc / "7777" / "stat", ["7777 (truncated) S 1"])

    def close(self) -> None:
        for path in self._wsl_native_paths:
            subprocess.run([*WSL, "rm", "-rf", path], check=False)
        if self._temp is not None:
            self._temp.cleanup()

    @staticmethod
    def _wsl_path(path: Path) -> str:
        resolved = path.resolve()
        resolved_text = str(resolved)
        unc_prefix = "\\\\wsl.localhost\\Ubuntu-22.04\\"
        if resolved_text.casefold().startswith(unc_prefix.casefold()):
            return "/" + resolved_text[len(unc_prefix) :].replace("\\", "/")
        drive, tail = os.path.splitdrive(str(resolved))
        if len(drive) != 2 or drive[1] != ":":
            raise AssertionError(
                f"fixture path is not on a WSL-mounted drive: {resolved}"
            )
        normalized_tail = tail.lstrip("\\/").replace("\\", "/")
        return f"/mnt/{drive[0].lower()}/{normalized_tail}"

    def _chmod(self, *paths: Path) -> None:
        subprocess.run(
            [*WSL, "chmod", "755", *(self._wsl_path(path) for path in paths)],
            check=True,
        )

    def _chmod_mode(self, mode: str, *paths: Path) -> None:
        subprocess.run(
            [*WSL, "chmod", mode, *(self._wsl_path(path) for path in paths)],
            check=True,
        )

    def _symlink(self, target: str, path: Path) -> None:
        subprocess.run([*WSL, "ln", "-s", target, self._wsl_path(path)], check=True)

    def _write_runner(self, *, wrong_identity: bool) -> None:
        identity_sha = "9" * 64 if wrong_identity else IDENTITY_SHA
        self.runner.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            'test "$1" = identity\n'
            "printf '%s\\n' "
            f"'DCENT_S19K_LIVE_IDENTITY schema=dcentos.s19k-braiins-live-identity/v2 "
            f"profile={PROFILE} sha256={identity_sha} model_sha256={MODEL_SHA} "
            f"board_names={IDENTITY_NAMES} physical_addresses={IDENTITY_ADDRESSES} "
            f"eeprom={IDENTITY_EEPROM}'\n",
            encoding="utf-8",
            newline="\n",
        )

    def _write_s99(self, variant: str) -> None:
        duplicate = variant == "duplicate_supervisor"
        stale_log = variant == "stale_log"
        init_failure = variant == "init_failure"
        process_block = f"""
make_stat() {{
  printf '%s (%s) S %s %s %s 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %s\\n' "$1" "$2" "$3" "$4" "$5" "$6"
}}
make_process() {{
  pid=$1 comm=$2 exe=$3 ppid=$4 pgrp=$5 session=$6 start=$7
  shift 7
  mkdir -p '{self.wsl_root}/proc/'"$pid"
  make_stat "$pid" "$comm" "$ppid" "$pgrp" "$session" "$start" > '{self.wsl_root}/proc/'"$pid"'/stat'
  printf '%s\\n' "$comm" > '{self.wsl_root}/proc/'"$pid"'/comm'
  ln -s "$exe" '{self.wsl_root}/proc/'"$pid"'/exe'
  : > '{self.wsl_root}/proc/'"$pid"'/cmdline'
  for arg in "$@"; do printf '%s\\000' "$arg" >> '{self.wsl_root}/proc/'"$pid"'/cmdline'; done
  mkdir -p '{self.wsl_root}/proc/'"$pid"'/task/'"$pid"'/fd'
  cp '{self.wsl_root}/proc/'"$pid"'/stat' '{self.wsl_root}/proc/'"$pid"'/task/'"$pid"'/stat'
  cp '{self.wsl_root}/proc/'"$pid"'/comm' '{self.wsl_root}/proc/'"$pid"'/task/'"$pid"'/comm'
  cp '{self.wsl_root}/proc/'"$pid"'/cmdline' '{self.wsl_root}/proc/'"$pid"'/task/'"$pid"'/cmdline'
  ln -s "$exe" '{self.wsl_root}/proc/'"$pid"'/task/'"$pid"'/exe'
  ln -s / '{self.wsl_root}/proc/'"$pid"'/task/'"$pid"'/cwd'
  printf 'Umask:\\t0022\\n' > '{self.wsl_root}/proc/'"$pid"'/task/'"$pid"'/status'
  ln -s /dev/null '{self.wsl_root}/proc/'"$pid"'/task/'"$pid"'/fd/0'
  ln -s /dev/null '{self.wsl_root}/proc/'"$pid"'/task/'"$pid"'/fd/1'
  ln -s /dev/null '{self.wsl_root}/proc/'"$pid"'/task/'"$pid"'/fd/2'
  printf 'CONSOLE=/dev/console\\000HOME=/\\000INIT_VERSION=sysvinit-2.9n\\000PATH=/sbin:/usr/sbin:/bin:/usr/bin\\000PREVLEVEL=N\\000PWD=/\\000RUNLEVEL=3\\000SHELL=/bin/sh\\000SHLVL=3\\000TERM=linux\\000jtag=disable\\000logo=,loaded,androidboot.selinux=enforcing\\000' > '{self.wsl_root}/proc/'"$pid"'/task/'"$pid"'/environ'
  if [ "$comm" = bosminer ]; then printf '   =/usr/bin/bos-tools\\000' >> '{self.wsl_root}/proc/'"$pid"'/task/'"$pid"'/environ'; fi
}}
printf 'start\\n' >> '{self.wsl_root}/start.count'
printf '1458\\n' > '{self.wsl_root}/run/bosminer.pid'
chmod 0644 '{self.wsl_root}/run/bosminer.pid'
make_process 1458 bos-tools /usr/bin/bos-tools 1 1457 1457 1251 /usr/bin/bos-tools run-and-watch -- /usr/bin/bosminer --log-to-file
make_process 9495 bosminer /usr/bin/bosminer 1458 1457 1457 1044815 /usr/bin/bosminer --log-to-file
"""
        if variant == "nonleader_stock_watchdog":
            process_block += f"""
mkdir -p '{self.wsl_root}/proc/1458/task/1459/fd'
make_stat 1459 'bos-tools worker' 1 1457 1457 1252 > '{self.wsl_root}/proc/1458/task/1459/stat'
printf '%s\n' 'bos-tools worker' > '{self.wsl_root}/proc/1458/task/1459/comm'
printf '/usr/bin/bos-tools\000run-and-watch\000--\000/usr/bin/bosminer\000' > '{self.wsl_root}/proc/1458/task/1459/cmdline'
ln -s /usr/bin/bos-tools '{self.wsl_root}/proc/1458/task/1459/exe'
ln -s / '{self.wsl_root}/proc/1458/task/1459/cwd'
printf 'Umask:\t0022\n' > '{self.wsl_root}/proc/1458/task/1459/status'
ln -s /dev/null '{self.wsl_root}/proc/1458/task/1459/fd/0'
ln -s /dev/null '{self.wsl_root}/proc/1458/task/1459/fd/1'
ln -s /dev/null '{self.wsl_root}/proc/1458/task/1459/fd/2'
ln -s '{self.wsl_watchdog_root}/watchdog0' '{self.wsl_root}/proc/1458/task/1459/fd/4'
"""
        elif variant in ("stock_watchdog", "mixed_stock_foreign_watchdog"):
            process_block += (
                f"ln -s '{self.wsl_watchdog_root}/watchdog0' "
                f"'{self.wsl_root}/proc/1458/task/1458/fd/4'\n"
            )
        if variant in ("foreign_watchdog", "mixed_stock_foreign_watchdog"):
            process_block += f"""
make_process 333 other /bin/other 1 333 333 99 /bin/other
ln -s '{self.wsl_watchdog_root}/watchdog0' '{self.wsl_root}/proc/333/task/333/fd/4'
"""
        elif variant == "alternate_path_exact_watchdog":
            process_block += f"""
mknod '{self.wsl_watchdog_root}/alternate-not-named-watchdog' c 10 130
chmod 000 '{self.wsl_watchdog_root}/alternate-not-named-watchdog'
ln -s '{self.wsl_watchdog_root}/alternate-not-named-watchdog' '{self.wsl_root}/proc/1458/task/1458/fd/4'
"""
        elif variant == "regular_watchdog_lookalike":
            process_block += f"""
: > '{self.wsl_watchdog_root}/watchdog-status'
ln -s '{self.wsl_watchdog_root}/watchdog-status' '{self.wsl_root}/proc/1458/task/1458/fd/4'
"""
        elif variant == "wrong_rdev_watchdog_lookalike":
            process_block += f"""
mknod '{self.wsl_watchdog_root}/watchdog-lookalike' c 1 3
ln -s '{self.wsl_watchdog_root}/watchdog-lookalike' '{self.wsl_root}/proc/1458/task/1458/fd/4'
"""
        elif variant == "poststart_malformed_task":
            process_block += f"""
mkdir -p '{self.wsl_root}/proc/333/task/334/fd'
printf '%s\n' 'malformed task stat' > '{self.wsl_root}/proc/333/task/334/stat'
"""
        elif variant == "poststart_inaccessible_task":
            process_block += f"""
mkdir -p '{self.wsl_root}/proc/333/task/334/fd'
"""
        if variant == "wrong_stock_env":
            process_block += f": > '{self.wsl_root}/proc/1458/task/1458/environ'\n"
        elif variant == "wrong_stock_cwd":
            process_block += (
                f"rm -f '{self.wsl_root}/proc/1458/task/1458/cwd'\n"
                f"ln -s /tmp '{self.wsl_root}/proc/1458/task/1458/cwd'\n"
            )
        elif variant == "wrong_stock_umask":
            process_block += (
                f"printf 'Umask:\\t0077\\n' > "
                f"'{self.wsl_root}/proc/1458/task/1458/status'\n"
            )
        elif variant == "wrong_stock_fd":
            process_block += (
                f"rm -f '{self.wsl_root}/proc/1458/task/1458/fd/2'\n"
                f"ln -s /tmp/not-null '{self.wsl_root}/proc/1458/task/1458/fd/2'\n"
            )
        elif variant == "wrong_pidfile_content":
            process_block += f"printf '9999\\n' > '{self.wsl_root}/run/bosminer.pid'\n"
        if duplicate:
            process_block += (
                "make_process 2222 bos-tools /usr/bin/bos-tools 1 2221 2221 777 "
                "/usr/bin/bos-tools run-and-watch -- /usr/bin/bosminer --log-to-file\n"
            )
        process_block += f"""
printf '0\\n' > '{self.wsl_root}/gpio/gpio437/value'
printf '0\\n' > '{self.wsl_root}/gpio/gpio454/value'
printf '1\\n' > '{self.wsl_root}/gpio/gpio455/value'
printf '1\\n' > '{self.wsl_root}/gpio/gpio456/value'
"""
        if not stale_log:
            process_block += f"""
cat >> '{self.wsl_root}/bosminer.log' <<'EOF'
INFO bosminer::client::stratum_v2: Connected Stratum V1 to: fixture.invalid:3333
INFO bosminer::backend: --- RESUME --- no longer paused by dead pools
INFO bosminer_backend::psu: PSU: Enable
INFO bosminer_backend::hashchain: CHAIN/2: Initializing hashchain
INFO bosminer_backend::hashchain: CHAIN/3: Initializing hashchain
INFO bosminer_backend: Resolved monitor config: Config {{ fan_config: FanControlConfig {{ mode: FixedSpeed(Speed(100)), min_fans: 0, min_fan_rpm: 2000, rpm_epsilon: 600, immersion_mode: false, min_fan_speed: None, max_fan_speed: None }}, temp_config: TempControlConfig {{ target_temp: 65.0, dangerous_temp: 90.0, hot_temp: 80.0 }}, max_fans: 4 }}
INFO bosminer_backend::hashchain: Using sensor hb2.73[Lm75BCCnCopy-0] for Inlet temperature monitoring
INFO bosminer_backend::hashchain: Using sensor hb2.77[Lm75BCCnCopy-0] for Outlet temperature monitoring
INFO bosminer_backend::hashchain: Using sensor hb3.74[Lm75BCCnCopy-0] for Inlet temperature monitoring
INFO bosminer_backend::hashchain: Using sensor hb3.78[Lm75BCCnCopy-0] for Outlet temperature monitoring
INFO bosminer_hal::monitor: CHAIN/2, address: 73, position: Inlet, temperature: 27.5C
INFO bosminer_hal::monitor: CHAIN/2, address: 77, position: Outlet, temperature: 29.5C
INFO bosminer_hal::monitor: CHAIN/3, address: 74, position: Inlet, temperature: 27.5C
INFO bosminer_hal::monitor: CHAIN/3, address: 78, position: Outlet, temperature: 29.5C
INFO bosminer_backend::hashchain: CHAIN/2: Monitor watchdog temperature task started
INFO bosminer_backend::hashchain: CHAIN/3: Monitor watchdog temperature task started
EOF
"""
        if variant == "missing_cooling_evidence":
            process_block = process_block.replace(
                "INFO bosminer_backend::hashchain: CHAIN/3: Monitor watchdog temperature task started\n",
                "",
            )
        if init_failure:
            process_block += f"""
printf '%s\\n' 'WARN bosminer_backend::hashchain: CHAIN/2: Init failed: fixture' >> '{self.wsl_root}/bosminer.log'
"""
        if variant == "poststart_bosminer_replaced":
            process_block += f"""
printf '%s\\n' 'post-start replacement' >> '{self.wsl_root}/bosminer'
"""
        self.s99.write_text(
            "#!/bin/sh\nset -eu\n"
            '[ "$#" -eq 1 ] && [ "$1" = start ] || exit 64\n' + process_block,
            encoding="utf-8",
            newline="\n",
        )

    def _write_helper(self) -> None:
        s99_sha, s99_bytes = sha_bytes(self.s99)
        busybox_sha, busybox_bytes = sha_bytes(self.busybox)
        bos_defaults_sha, bos_defaults_bytes = sha_bytes(self.bos_defaults)
        stock_bos_tools_sha, stock_bos_tools_bytes = sha_bytes(self.stock_bos_tools)
        stock_bosminer_sha, stock_bosminer_bytes = sha_bytes(self.stock_bosminer)
        busybox_ld_sha, busybox_ld_bytes = sha_bytes(self.busybox_ld)
        busybox_libm_sha, busybox_libm_bytes = sha_bytes(self.busybox_libm)
        busybox_libc_sha, busybox_libc_bytes = sha_bytes(self.busybox_libc)
        source = HELPER_SOURCE.read_text(encoding="utf-8")
        replacements = {
            "PREFIX=/tmp/dcentrald_bench_t1_": f"PREFIX={self.prefix}",
            "LOCK=/tmp/dcent-s19k-track1-runtime-lock": f"LOCK={self.wsl_root}/runtime-lock",
            "INVOKE_LOCK=/tmp/dcent-s19k-stock-restart-helper-lock": f"INVOKE_LOCK={self.wsl_root}/restart-helper-lock",
            "REQUIRE_NEUTRAL_MUTEX_MODE=true": "REQUIRE_NEUTRAL_MUTEX_MODE=false",
            "PROC_ROOT=/proc": f"PROC_ROOT={self.wsl_root}/proc",
            "PIDFILE=/var/run/bosminer.pid": f"PIDFILE={self.wsl_root}/run/bosminer.pid",
            "GPIO_ROOT=/sys/class/gpio": f"GPIO_ROOT={self.wsl_root}/gpio",
            "S99=/etc/init.d/S99bosminer": f"S99={self.wsl_root}/S99bosminer",
            "BOS_DEFAULTS=/lib/functions/bos-defaults.sh": f"BOS_DEFAULTS={self.wsl_root}/bos-defaults.sh",
            "STOCK_BOS_TOOLS=/usr/bin/bos-tools": f"STOCK_BOS_TOOLS={self.wsl_root}/bos-tools",
            "STOCK_BOSMINER=/usr/bin/bosminer": f"STOCK_BOSMINER={self.wsl_root}/bosminer",
            "LOG=/var/log/bosminer/bosminer.log": f"LOG={self.wsl_root}/bosminer.log",
            "LOG_RESOLVED=/etc/log/bosminer/bosminer.log": f"LOG_RESOLVED={self.wsl_root}/bosminer.log",
            "WATCHDOG_NODE_ROOT=/dev": f"WATCHDOG_NODE_ROOT={self.wsl_watchdog_root}",
            "REQUIRE_EXACT_LOG_MOUNT=true": "REQUIRE_EXACT_LOG_MOUNT=false",
            "REQUIRE_EXACT_LOG_METADATA=true": "REQUIRE_EXACT_LOG_METADATA=false",
            "REQUIRE_EXACT_STARTUP_OBJECT_METADATA=true": "REQUIRE_EXACT_STARTUP_OBJECT_METADATA=false",
            "BUSYBOX=/bin/busybox": f"BUSYBOX={self.wsl_root}/busybox",
            "SHELL_INTERPRETER=/bin/sh": f"SHELL_INTERPRETER={self.wsl_root}/sh",
            "SHELL_INTERPRETER_LINK=busybox": "SHELL_INTERPRETER_LINK=busybox",
            "START_STOP_DAEMON=/sbin/start-stop-daemon": f"START_STOP_DAEMON={self.wsl_root}/start-stop-daemon",
            "START_STOP_DAEMON_LINK=../bin/busybox": "START_STOP_DAEMON_LINK=busybox",
            "BUSYBOX_LD_LINK=/lib/ld-linux-armhf.so.3": f"BUSYBOX_LD_LINK={self.wsl_root}/ld-link",
            "BUSYBOX_LD_TARGET=/lib/ld-2.19-2014.08-1-git.so": f"BUSYBOX_LD_TARGET={self.wsl_root}/ld-target",
            "BUSYBOX_LIBM_LINK=/lib/libm.so.6": f"BUSYBOX_LIBM_LINK={self.wsl_root}/libm-link",
            "BUSYBOX_LIBM_TARGET=/lib/libm-2.19-2014.08-1-git.so": f"BUSYBOX_LIBM_TARGET={self.wsl_root}/libm-target",
            "BUSYBOX_LIBC_LINK=/lib/libc.so.6": f"BUSYBOX_LIBC_LINK={self.wsl_root}/libc-link",
            "BUSYBOX_LIBC_TARGET=/lib/libc-2.19-2014.08-1-git.so": f"BUSYBOX_LIBC_TARGET={self.wsl_root}/libc-target",
            "MAX_WAIT_SECONDS=300": "MAX_WAIT_SECONDS=2",
            "STABILITY_WAIT_SECONDS=5": "STABILITY_WAIT_SECONDS=0",
            "REQUIRE_EXACT_PIDFILE_METADATA=true": "REQUIRE_EXACT_PIDFILE_METADATA=false",
            "AUDITED_S99_SHA=6d9cce12caa49249396b48296101b0fbbcc6456cb3fa09bdbe2858bdcba948c9": f"AUDITED_S99_SHA={s99_sha}",
            "AUDITED_S99_BYTES=1330": f"AUDITED_S99_BYTES={s99_bytes}",
            "AUDITED_BOS_DEFAULTS_SHA=a5380fafcbd2cb4dc36c20b34353d40b97f5e2fcf3ed27f1741c55a2269ff85b": f"AUDITED_BOS_DEFAULTS_SHA={bos_defaults_sha}",
            "AUDITED_BOS_DEFAULTS_BYTES=434": f"AUDITED_BOS_DEFAULTS_BYTES={bos_defaults_bytes}",
            "AUDITED_STOCK_BOS_TOOLS_SHA=c597b12e1cd7ec614005b1007af0ce55058da888c9e83e5c11cf9fb5531bcad8": f"AUDITED_STOCK_BOS_TOOLS_SHA={stock_bos_tools_sha}",
            "AUDITED_STOCK_BOS_TOOLS_BYTES=1061080": f"AUDITED_STOCK_BOS_TOOLS_BYTES={stock_bos_tools_bytes}",
            "AUDITED_STOCK_BOSMINER_SHA=c5f9a28af02e7d6c318af955f746aaf43c6fa2502ecef09cd0ef209f394e4d22": f"AUDITED_STOCK_BOSMINER_SHA={stock_bosminer_sha}",
            "AUDITED_STOCK_BOSMINER_BYTES=9113388": f"AUDITED_STOCK_BOSMINER_BYTES={stock_bosminer_bytes}",
            "AUDITED_BUSYBOX_SHA=6f79b1c7794f14ed0334d88287eb85877aeed4f4a1a6c28f2b19c9d22bb7e98f": f"AUDITED_BUSYBOX_SHA={busybox_sha}",
            "AUDITED_BUSYBOX_BYTES=384088": f"AUDITED_BUSYBOX_BYTES={busybox_bytes}",
            "AUDITED_BUSYBOX_LD_SHA=b073c9de0008b6abc77a3860772f354252c346adc076ac15890425fc441dc0d5": f"AUDITED_BUSYBOX_LD_SHA={busybox_ld_sha}",
            "AUDITED_BUSYBOX_LD_BYTES=123325": f"AUDITED_BUSYBOX_LD_BYTES={busybox_ld_bytes}",
            "AUDITED_BUSYBOX_LIBM_SHA=4b135549c92b3e38e799313b6273582565477b238640581524c114d18d22550f": f"AUDITED_BUSYBOX_LIBM_SHA={busybox_libm_sha}",
            "AUDITED_BUSYBOX_LIBM_BYTES=407060": f"AUDITED_BUSYBOX_LIBM_BYTES={busybox_libm_bytes}",
            "AUDITED_BUSYBOX_LIBC_SHA=9e7cd88df51f7f236796e2d23bac2f57a767b89d0e7b11df79147d844e5afa6e": f"AUDITED_BUSYBOX_LIBC_SHA={busybox_libc_sha}",
            "AUDITED_BUSYBOX_LIBC_BYTES=907032": f"AUDITED_BUSYBOX_LIBC_BYTES={busybox_libc_bytes}",
        }
        for old, new in replacements.items():
            if source.count(old) != 1:
                raise AssertionError(f"fixture patch marker changed: {old}")
            source = source.replace(old, new)
        fault_markers = {
            "fault_after_invocation_scratch": (
                '    write_invocation_owner_record "$INVOKE_SCRATCH" || return 1\n',
                '    write_invocation_owner_record "$INVOKE_SCRATCH" || return 1\n'
                f"    if [ ! -e '{self.wsl_trial}/.fault_after_invocation_scratch' ]; then "
                f": > '{self.wsl_trial}/.fault_after_invocation_scratch'; exit 86; fi\n",
            ),
            "fault_after_invocation_link": (
                '    ln "$INVOKE_SCRATCH" "$INVOKE_OWNER" 2>/dev/null || { rm -f "$INVOKE_SCRATCH"; return 1; }\n',
                '    ln "$INVOKE_SCRATCH" "$INVOKE_OWNER" 2>/dev/null || { rm -f "$INVOKE_SCRATCH"; return 1; }\n'
                f"    if [ ! -e '{self.wsl_trial}/.fault_after_invocation_link' ]; then "
                f": > '{self.wsl_trial}/.fault_after_invocation_link'; exit 86; fi\n",
            ),
            "fault_after_invocation_scratch_remove": (
                '    ln "$INVOKE_SCRATCH" "$INVOKE_OWNER" 2>/dev/null || { rm -f "$INVOKE_SCRATCH"; return 1; }\n'
                '    rm -f "$INVOKE_SCRATCH" || return 1\n',
                '    ln "$INVOKE_SCRATCH" "$INVOKE_OWNER" 2>/dev/null || { rm -f "$INVOKE_SCRATCH"; return 1; }\n'
                '    rm -f "$INVOKE_SCRATCH" || return 1\n'
                f"    if [ ! -e '{self.wsl_trial}/.fault_after_invocation_scratch_remove' ]; then "
                f": > '{self.wsl_trial}/.fault_after_invocation_scratch_remove'; exit 86; fi\n",
            ),
            "fault_after_claim_mkdir": (
                "    write_claim prestart-admitted || {\n",
                f"    if [ ! -e '{self.wsl_trial}/.fault_after_claim_mkdir' ]; then "
                f": > '{self.wsl_trial}/.fault_after_claim_mkdir'; exit 86; fi\n"
                "    write_claim prestart-admitted || {\n",
            ),
            "fault_claim_commit_zero": (
                '    [ ! -e "$CLAIM_TMP" ] && [ ! -L "$CLAIM_TMP" ] || return 1\n',
                '    [ ! -e "$CLAIM_TMP" ] && [ ! -L "$CLAIM_TMP" ] || return 1\n'
                f"    if [ \"$CLAIM_PHASE\" = start-invocation-committed ] "
                f"&& [ ! -e '{self.wsl_trial}/.fault_claim_commit_zero' ]; then "
                f": > \"$CLAIM_TMP\"; : > '{self.wsl_trial}/.fault_claim_commit_zero'; exit 86; fi\n",
            ),
            "fault_claim_commit_partial": (
                "        printf 'schema=dcentos.s19k-stock-restart-claim/v3\\n'\n"
                "        printf 'phase=%s\\n' \"$CLAIM_PHASE\"\n"
                "        printf 'trial_dir=%s\\n' \"$TRIAL_DIR\"\n"
                "        printf 'helper_sha256=%s\\n' \"$EXPECTED_HELPER_SHA\"\n"
                "        printf 'helper_bytes=%s\\n' \"$EXPECTED_HELPER_BYTES\"\n"
                "        printf 'pending_sha256=%s\\n' \"$PENDING_SHA\"\n"
                "        printf 'pending_bytes=%s\\n' \"$PENDING_BYTES\"\n"
                "        printf 'source_kind=%s\\n' \"$SOURCE_KIND\"\n",
                "        printf 'schema=dcentos.s19k-stock-restart-claim/v3\\n'\n"
                "        printf 'phase=%s\\n' \"$CLAIM_PHASE\"\n"
                "        printf 'trial_dir=%s\\n' \"$TRIAL_DIR\"\n"
                "        printf 'helper_sha256=%s\\n' \"$EXPECTED_HELPER_SHA\"\n"
                "        printf 'helper_bytes=%s\\n' \"$EXPECTED_HELPER_BYTES\"\n"
                "        printf 'pending_sha256=%s\\n' \"$PENDING_SHA\"\n"
                "        printf 'pending_bytes=%s\\n' \"$PENDING_BYTES\"\n"
                f"        if [ \"$CLAIM_PHASE\" = start-invocation-committed ] "
                f"&& [ ! -e '{self.wsl_trial}/.fault_claim_commit_partial' ]; then "
                f": > '{self.wsl_trial}/.fault_claim_commit_partial'; exit 86; fi\n"
                "        printf 'source_kind=%s\\n' \"$SOURCE_KIND\"\n",
            ),
            "fault_during_claim_scratch": (
                "        printf 'schema=dcentos.s19k-stock-restart-claim/v3\\n'\n"
                "        printf 'phase=%s\\n' \"$CLAIM_PHASE\"\n"
                "        printf 'trial_dir=%s\\n' \"$TRIAL_DIR\"\n"
                "        printf 'helper_sha256=%s\\n' \"$EXPECTED_HELPER_SHA\"\n"
                "        printf 'helper_bytes=%s\\n' \"$EXPECTED_HELPER_BYTES\"\n"
                "        printf 'pending_sha256=%s\\n' \"$PENDING_SHA\"\n"
                "        printf 'pending_bytes=%s\\n' \"$PENDING_BYTES\"\n"
                "        printf 'source_kind=%s\\n' \"$SOURCE_KIND\"\n",
                "        printf 'schema=dcentos.s19k-stock-restart-claim/v3\\n'\n"
                "        printf 'phase=%s\\n' \"$CLAIM_PHASE\"\n"
                "        printf 'trial_dir=%s\\n' \"$TRIAL_DIR\"\n"
                "        printf 'helper_sha256=%s\\n' \"$EXPECTED_HELPER_SHA\"\n"
                "        printf 'helper_bytes=%s\\n' \"$EXPECTED_HELPER_BYTES\"\n"
                "        printf 'pending_sha256=%s\\n' \"$PENDING_SHA\"\n"
                "        printf 'pending_bytes=%s\\n' \"$PENDING_BYTES\"\n"
                f"        if [ ! -e '{self.wsl_trial}/.fault_during_claim_scratch' ]; then "
                f": > '{self.wsl_trial}/.fault_during_claim_scratch'; exit 86; fi\n"
                "        printf 'source_kind=%s\\n' \"$SOURCE_KIND\"\n",
            ),
            "fault_after_claim_publish": (
                '    mv -f "$CLAIM_TMP" "$CLAIM" || return 1\n',
                '    mv -f "$CLAIM_TMP" "$CLAIM" || return 1\n'
                f"    if [ ! -e '{self.wsl_trial}/.fault_after_claim_publish' ]; then "
                f": > '{self.wsl_trial}/.fault_after_claim_publish'; exit 86; fi\n",
            ),
            "fault_after_commit": (
                '    admit_claim && [ "$CLAIM_PHASE" = start-invocation-committed ] || {\n',
                f"    if [ ! -e '{self.wsl_trial}/.fault_after_commit' ]; then "
                f": > '{self.wsl_trial}/.fault_after_commit'; exit 86; fi\n"
                '    admit_claim && [ "$CLAIM_PHASE" = start-invocation-committed ] || {\n',
            ),
            "fault_stock_tree_zero": (
                '        [ ! -e "$CLAIM_TREE_TMP" ] && [ ! -L "$CLAIM_TREE_TMP" ] || return 1\n',
                '        [ ! -e "$CLAIM_TREE_TMP" ] && [ ! -L "$CLAIM_TREE_TMP" ] || return 1\n'
                f"        if [ ! -e '{self.wsl_trial}/.fault_stock_tree_zero' ]; then "
                f": > \"$CLAIM_TREE_TMP\"; : > '{self.wsl_trial}/.fault_stock_tree_zero'; exit 86; fi\n",
            ),
            "fault_stock_tree_partial": (
                '        printf \'%s\\n\' "$STOCK_TREE" > "$CLAIM_TREE_TMP" || return 1\n',
                f"        if [ ! -e '{self.wsl_trial}/.fault_stock_tree_partial' ]; then "
                f"printf '%s\\n' 'schema=partial' > \"$CLAIM_TREE_TMP\"; "
                f": > '{self.wsl_trial}/.fault_stock_tree_partial'; exit 86; fi\n"
                '        printf \'%s\\n\' "$STOCK_TREE" > "$CLAIM_TREE_TMP" || return 1\n',
            ),
            "fault_stock_tree_complete_prelink": (
                '        "$BUSYBOX" sync -d "$CLAIM_TREE_TMP" || return 1\n',
                '        "$BUSYBOX" sync -d "$CLAIM_TREE_TMP" || return 1\n'
                f"        if [ ! -e '{self.wsl_trial}/.fault_stock_tree_complete_prelink' ]; then "
                f": > '{self.wsl_trial}/.fault_stock_tree_complete_prelink'; exit 86; fi\n",
            ),
            "fault_stock_tree_postlink": (
                '        ln "$CLAIM_TREE_TMP" "$CLAIM_TREE" || return 1\n',
                '        ln "$CLAIM_TREE_TMP" "$CLAIM_TREE" || return 1\n'
                f"        if [ ! -e '{self.wsl_trial}/.fault_stock_tree_postlink' ]; then "
                f": > '{self.wsl_trial}/.fault_stock_tree_postlink'; exit 86; fi\n",
            ),
            "fault_watchdog_zero": (
                '        [ ! -e "$CLAIM_WATCHDOG_TMP" ] && [ ! -L "$CLAIM_WATCHDOG_TMP" ] || return 1\n',
                '        [ ! -e "$CLAIM_WATCHDOG_TMP" ] && [ ! -L "$CLAIM_WATCHDOG_TMP" ] || return 1\n'
                f"        if [ ! -e '{self.wsl_trial}/.fault_watchdog_zero' ]; then "
                f": > \"$CLAIM_WATCHDOG_TMP\"; : > '{self.wsl_trial}/.fault_watchdog_zero'; exit 86; fi\n",
            ),
            "fault_watchdog_partial": (
                '        printf \'%s\\n\' "$STOCK_WATCHDOG_EVIDENCE" > "$CLAIM_WATCHDOG_TMP" || return 1\n',
                f"        if [ ! -e '{self.wsl_trial}/.fault_watchdog_partial' ]; then "
                f"printf '%s\\n' 'schema=partial' > \"$CLAIM_WATCHDOG_TMP\"; "
                f": > '{self.wsl_trial}/.fault_watchdog_partial'; exit 86; fi\n"
                '        printf \'%s\\n\' "$STOCK_WATCHDOG_EVIDENCE" > "$CLAIM_WATCHDOG_TMP" || return 1\n',
            ),
            "fault_watchdog_complete_prelink": (
                '        "$BUSYBOX" sync -d "$CLAIM_WATCHDOG_TMP" || return 1\n',
                '        "$BUSYBOX" sync -d "$CLAIM_WATCHDOG_TMP" || return 1\n'
                f"        if [ ! -e '{self.wsl_trial}/.fault_watchdog_complete_prelink' ]; then "
                f": > '{self.wsl_trial}/.fault_watchdog_complete_prelink'; exit 86; fi\n",
            ),
            "fault_watchdog_postlink": (
                '        ln "$CLAIM_WATCHDOG_TMP" "$CLAIM_WATCHDOG" || return 1\n',
                '        ln "$CLAIM_WATCHDOG_TMP" "$CLAIM_WATCHDOG" || return 1\n'
                f"        if [ ! -e '{self.wsl_trial}/.fault_watchdog_postlink' ]; then "
                f": > '{self.wsl_trial}/.fault_watchdog_postlink'; exit 86; fi\n",
            ),
            "fault_log_zero": (
                '    [ ! -e "$CLAIM_LOG_TMP" ] && [ ! -L "$CLAIM_LOG_TMP" ] || return 1\n',
                '    [ ! -e "$CLAIM_LOG_TMP" ] && [ ! -L "$CLAIM_LOG_TMP" ] || return 1\n'
                f"    if [ ! -e '{self.wsl_trial}/.fault_log_zero' ]; then "
                f": > \"$CLAIM_LOG_TMP\"; : > '{self.wsl_trial}/.fault_log_zero'; exit 86; fi\n",
            ),
            "fault_log_partial": (
                "        printf 'schema=dcentos.s19k-stock-log-window/v1\\n'\n",
                "        printf 'schema=dcentos.s19k-stock-log-window/v1\\n'\n"
                f"        if [ ! -e '{self.wsl_trial}/.fault_log_partial' ]; then "
                f": > '{self.wsl_trial}/.fault_log_partial'; exit 86; fi\n",
            ),
            "fault_log_complete_prelink": (
                '    "$BUSYBOX" sync -d "$CLAIM_LOG_TMP" || return 1\n',
                '    "$BUSYBOX" sync -d "$CLAIM_LOG_TMP" || return 1\n'
                f"    if [ ! -e '{self.wsl_trial}/.fault_log_complete_prelink' ]; then "
                f": > '{self.wsl_trial}/.fault_log_complete_prelink'; exit 86; fi\n",
            ),
            "fault_log_postlink": (
                '    ln "$CLAIM_LOG_TMP" "$CLAIM_LOG" || return 1\n',
                '    ln "$CLAIM_LOG_TMP" "$CLAIM_LOG" || return 1\n'
                f"    if [ ! -e '{self.wsl_trial}/.fault_log_postlink' ]; then "
                f": > '{self.wsl_trial}/.fault_log_postlink'; exit 86; fi\n",
            ),
            "fault_unresolved_zero": (
                '    [ ! -e "$UNRESOLVED_TMP" ] && [ ! -L "$UNRESOLVED_TMP" ] \\\n',
                '    [ ! -e "$UNRESOLVED_TMP" ] && [ ! -L "$UNRESOLVED_TMP" ] \\\n'
                f"        && [ -e '{self.wsl_trial}/.fault_unresolved_zero' ] || {{ "
                f": > \"$UNRESOLVED_TMP\"; : > '{self.wsl_trial}/.fault_unresolved_zero'; exit 86; }}\n",
            ),
            "fault_unresolved_partial": (
                '    emit_unresolved_receipt > "$UNRESOLVED_TMP" || return 1\n',
                f"    if [ ! -e '{self.wsl_trial}/.fault_unresolved_partial' ]; then "
                f"printf '%s\\n' 'schema=dcentos.s19k-' > \"$UNRESOLVED_TMP\"; "
                f": > '{self.wsl_trial}/.fault_unresolved_partial'; exit 86; fi\n"
                '    emit_unresolved_receipt > "$UNRESOLVED_TMP" || return 1\n',
            ),
            "fault_unresolved_complete_prelink": (
                '    "$BUSYBOX" sync -d "$UNRESOLVED_TMP" || return 1\n',
                '    "$BUSYBOX" sync -d "$UNRESOLVED_TMP" || return 1\n'
                f"    if [ ! -e '{self.wsl_trial}/.fault_unresolved_complete_prelink' ]; then "
                f": > '{self.wsl_trial}/.fault_unresolved_complete_prelink'; exit 86; fi\n",
            ),
            "fault_unresolved_postlink": (
                '    ln "$UNRESOLVED_TMP" "$UNRESOLVED" || return 1\n',
                '    ln "$UNRESOLVED_TMP" "$UNRESOLVED" || return 1\n'
                f"    if [ ! -e '{self.wsl_trial}/.fault_unresolved_postlink' ]; then "
                f": > '{self.wsl_trial}/.fault_unresolved_postlink'; exit 86; fi\n",
            ),
            "fault_terminal_zero": (
                '    [ ! -e "$TERMINAL_TMP" ] && [ ! -L "$TERMINAL_TMP" ] || return 1\n',
                '    [ ! -e "$TERMINAL_TMP" ] && [ ! -L "$TERMINAL_TMP" ] || return 1\n'
                f"    if [ ! -e '{self.wsl_trial}/.fault_terminal_zero' ]; then "
                f": > \"$TERMINAL_TMP\"; : > '{self.wsl_trial}/.fault_terminal_zero'; exit 86; fi\n",
            ),
            "fault_terminal_partial": (
                "        printf 'disposition=stock-restart-proven\\n'\n",
                "        printf 'disposition=stock-restart-proven\\n'\n"
                f"        if [ ! -e '{self.wsl_trial}/.fault_terminal_partial' ]; then "
                f": > '{self.wsl_trial}/.fault_terminal_partial'; exit 86; fi\n",
            ),
            "fault_terminal_complete_prelink": (
                '    "$BUSYBOX" sync -d "$TERMINAL_TMP" || return 1\n',
                '    "$BUSYBOX" sync -d "$TERMINAL_TMP" || return 1\n'
                f"    if [ ! -e '{self.wsl_trial}/.fault_terminal_complete_prelink' ]; then "
                f": > '{self.wsl_trial}/.fault_terminal_complete_prelink'; exit 86; fi\n",
            ),
            "fault_terminal_postlink": (
                '    ln "$TERMINAL_TMP" "$TERMINAL" || { rm -f "$TERMINAL_TMP"; return 1; }\n',
                '    ln "$TERMINAL_TMP" "$TERMINAL" || { rm -f "$TERMINAL_TMP"; return 1; }\n'
                f"    if [ ! -e '{self.wsl_trial}/.fault_terminal_postlink' ]; then "
                f": > '{self.wsl_trial}/.fault_terminal_postlink'; exit 86; fi\n",
            ),
            "fault_after_terminal": (
                '    rm -f "$TERMINAL_TMP" || return 1\n    transaction_scratches_absent\n}\n\nterminal_evidence_file()',
                '    rm -f "$TERMINAL_TMP" || return 1\n'
                f"    if [ ! -e '{self.wsl_trial}/.fault_after_terminal' ]; then "
                f": > '{self.wsl_trial}/.fault_after_terminal'; exit 86; fi\n"
                "    transaction_scratches_absent\n"
                "}\n\nterminal_evidence_file()",
            ),
            "fault_after_active_move": (
                '        mv "$ACTIVE" "$CONSUMED" || return 1\n',
                '        mv "$ACTIVE" "$CONSUMED" || return 1\n'
                f"        if [ ! -e '{self.wsl_trial}/.fault_after_active_move' ]; then "
                f": > '{self.wsl_trial}/.fault_after_active_move'; exit 86; fi\n",
            ),
            "fault_after_claim_remove": (
                '            "$CLAIM_DIR/s99_start.stdout" "$CLAIM_DIR/s99_start.stderr" "$CLAIM" || return 1\n',
                '            "$CLAIM_DIR/s99_start.stdout" "$CLAIM_DIR/s99_start.stderr" "$CLAIM" || return 1\n'
                f"        if [ ! -e '{self.wsl_trial}/.fault_after_claim_remove' ]; then "
                f": > '{self.wsl_trial}/.fault_after_claim_remove'; exit 86; fi\n",
            ),
            "fault_after_owner_remove": (
                '        rm -f "$OWNER" || return 1\n',
                '        rm -f "$OWNER" || return 1\n'
                f"        if [ ! -e '{self.wsl_trial}/.fault_after_owner_remove' ]; then "
                f": > '{self.wsl_trial}/.fault_after_owner_remove'; exit 86; fi\n",
            ),
        }
        if self.variant in fault_markers:
            old, new = fault_markers[self.variant]
            if source.count(old) != 1:
                raise AssertionError(f"fixture fault marker changed: {self.variant}")
            source = source.replace(old, new)
        if self.variant == "poststart_task_churn":
            old = "    done\n}\n\nfilter_relevant_task_effects()"
            new = (
                "    done\n"
                f"    if [ -e '{self.wsl_root}/run/bosminer.pid' ]; then\n"
                f"        CHURN_FILE='{self.wsl_trial}/.fault_task_churn_count'\n"
                "        CHURN_COUNT=0\n"
                "        [ ! -e \"$CHURN_FILE\" ] || CHURN_COUNT=$(cat \"$CHURN_FILE\")\n"
                "        CHURN_COUNT=$((CHURN_COUNT + 1))\n"
                "        printf '%s\\n' \"$CHURN_COUNT\" > \"$CHURN_FILE\"\n"
                "        [ $((CHURN_COUNT % 2)) -eq 0 ] || "
                "printf 'F|333|334|4|rdev=249:0|target=/alternate/path\\n'\n"
                "    fi\n"
                "}\n\nfilter_relevant_task_effects()"
            )
            if source.count(old) != 1:
                raise AssertionError("fixture churn marker changed")
            source = source.replace(old, new)
        self.helper.write_text(source, encoding="utf-8", newline="\n")

    def _write_contract(self) -> None:
        receiptless = self.variant.startswith("receiptless_")
        startup_prefix = self.variant.startswith("startup_")
        bin_sha, bin_bytes = sha_bytes(self.binary)
        cfg_sha, cfg_bytes = sha_bytes(self.config)
        runner_sha, runner_bytes = sha_bytes(self.runner)
        custody_sha, custody_bytes = sha_bytes(self.custody)
        self.helper_sha, self.helper_bytes = sha_bytes(self.helper)
        s99_sha, s99_bytes = sha_bytes(self.s99)
        self.pre = self.trial / "runtime_active_pre_safeoff"
        pre_lines = [
            "schema=dcentos.s19k-tmp-runtime/v5",
            "phase=child-live-or-recovery-required",
            "wrapper_pid=7777",
            "wrapper_start=123",
            "child_pid=8888",
            "child_start=456",
            "supervisor_pid=1458",
            "supervisor_start=1251",
            "supervisor_ppid=1",
            "supervisor_pgrp=1457",
            "supervisor_session=1457",
            "supervisor_exe=/usr/bin/bos-tools",
            "supervisor_cmdline_sha256=" + "3" * 64,
            "supervisor_cmdline_bytes=70",
            "bosminer_pid=9495",
            "bosminer_start=1044815",
            "bosminer_ppid=1458",
            "bosminer_pgrp=1457",
            "bosminer_session=1457",
            "bosminer_exe=/usr/bin/bosminer",
            "bosminer_cmdline_sha256=" + "4" * 64,
            "bosminer_cmdline_bytes=38",
            "stock_pidfile_path=/var/run/bosminer.pid",
            "stock_pidfile_sha256="
            + hashlib.sha256(b"1458\n").hexdigest(),
            "stock_pidfile_bytes=5",
            f"binary_sha256={bin_sha}",
            f"binary_bytes={bin_bytes}",
            f"config_sha256={cfg_sha}",
            f"config_bytes={cfg_bytes}",
            f"runner_sha256={runner_sha}",
            f"runner_bytes={runner_bytes}",
            f"custody_observer_sha256={custody_sha}",
            f"custody_observer_bytes={custody_bytes}",
            f"stock_restart_helper_sha256={self.helper_sha}",
            f"stock_restart_helper_bytes={self.helper_bytes}",
            "live_identity_schema=dcentos.s19k-braiins-live-identity/v2",
            f"live_identity_profile={PROFILE}",
            f"live_identity_sha256={IDENTITY_SHA}",
            "deploy_mode=mining-on-passthrough",
            "persistent_mutation=false",
        ]
        if receiptless or startup_prefix:
            pre_sha, pre_bytes = "", 0
        else:
            line_file(self.pre, pre_lines)
            pre_sha, pre_bytes = sha_bytes(self.pre)
        terminal_handoff_sha = ""
        terminal_handoff_bytes = 0
        if self.variant.startswith("v2_"):
            globally_absent = self.variant != "v2_global_stock_present"
            supervisor_gone = globally_absent
            child_gone = globally_absent
            terminal_handoff = self.trial / "runtime_terminal_safeoff"
            terminal_handoff_lines = [
                "schema=dcentos.s19k-terminal-safeoff-partial-stock-owner/v1",
                "disposition=terminal-safeoff-partial-stock-owner",
                f"runtime_active_sha256={pre_sha}",
                f"runtime_active_bytes={pre_bytes}",
                "terminal_safeoff=true",
                "watchdog_magic_close=true",
                "watchdog_worker_joined=true",
                "resets=454:0,455:0,456:0",
                "psu=437:1",
                "inherited_rails=true",
                "supervisor_signal_attempted=true",
                f"supervisor_gone={str(supervisor_gone).lower()}",
                f"supervisor_remnant={'absent' if supervisor_gone else 'original-lifetime-outcome-unknown'}",
                "supervisor_lease_kind=pidfd",
                "child_signal_attempted=true",
                f"child_gone={str(child_gone).lower()}",
                f"child_remnant={'absent' if child_gone else 'original-lifetime-outcome-unknown'}",
                "child_lease_kind=pidfd",
                f"global_stock_absence={str(globally_absent).lower()}",
                f"replacement_or_ambiguity={str(not globally_absent).lower()}",
                "remnant_authority=all-thread-ptrace-or-pidfd-recovery-only",
                "supervisor_pid=1458",
                "supervisor_start=1251",
                "supervisor_ppid=1",
                "supervisor_pgrp=1457",
                "supervisor_session=1457",
                "supervisor_exe=/usr/bin/bos-tools",
                "supervisor_cmdline_sha256=" + "3" * 64,
                "supervisor_cmdline_bytes=70",
                "bosminer_pid=9495",
                "bosminer_start=1044815",
                "bosminer_ppid=1458",
                "bosminer_pgrp=1457",
                "bosminer_session=1457",
                "bosminer_exe=/usr/bin/bosminer",
                "bosminer_cmdline_sha256=" + "4" * 64,
                "bosminer_cmdline_bytes=38",
                f"binary_sha256={bin_sha}",
                f"binary_bytes={bin_bytes}",
                f"config_sha256={cfg_sha}",
                f"config_bytes={cfg_bytes}",
                f"runner_sha256={runner_sha}",
                f"runner_bytes={runner_bytes}",
                f"custody_observer_sha256={custody_sha}",
                f"custody_observer_bytes={custody_bytes}",
                f"stock_restart_helper_sha256={self.helper_sha}",
                f"stock_restart_helper_bytes={self.helper_bytes}",
                "live_identity_schema=dcentos.s19k-braiins-live-identity/v2",
                f"live_identity_profile={PROFILE}",
                f"live_identity_sha256={IDENTITY_SHA}",
                f"live_identity_model_sha256={MODEL_SHA}",
                "persistent_mutation=false",
                "publication=no-clobber-hard-link-after-fsync",
            ]
            line_file(terminal_handoff, terminal_handoff_lines)
            terminal_handoff_sha, terminal_handoff_bytes = sha_bytes(terminal_handoff)
        self.safeoff = self.trial / "runtime_safeoff_terminal_receipt"
        safeoff_line = (
            "DCENT_S19K_TRACK1_SAFEOFF_RECEIPT "
            "schema=dcentos.s19k-track1-safeoff/v1 "
            f"live_identity_sha256={IDENTITY_SHA} live_identity_profile={PROFILE} "
            f"live_identity_model_sha256={MODEL_SHA} live_identity_board_count=2 "
            f"live_identity_physical_addresses={IDENTITY_ADDRESSES} "
            f"live_identity_board_names={IDENTITY_NAMES} "
            f"live_identity_eeprom={IDENTITY_EEPROM} "
            "resets=454:0,455:0,456:0 psu=437:1"
        )
        line_file(self.safeoff, [safeoff_line])
        safe_sha, safe_bytes = sha_bytes(self.safeoff)
        startup_source_sha = ""
        startup_source_bytes = 0
        if startup_prefix:
            preserved_owner = self.trial / "runtime_startup_owner_pre_safeoff"
            fifo_path = f"/tmp/dcent-s19k-stock-restart-fifo-{os.getpid()}-{id(self)}"
            self.startup_preserved_owner = preserved_owner
            self.startup_fifo_path = fifo_path
            self._wsl_native_paths.append(fifo_path)
            subprocess.run([*WSL, "mkfifo", fifo_path], check=True)
            subprocess.run([*WSL, "chmod", "600", fifo_path], check=True)
            transcript = self.trial / ".startup_daemon_transcript.7777.123"
            self.startup_transcript = transcript
            transcript.write_bytes(b"fixture startup transcript\n")
            self._chmod_mode("600", transcript)
            transcript_sha, transcript_bytes = sha_bytes(transcript)
            pidfile_blob = b"1458\n"
            pidfile_sha = hashlib.sha256(pidfile_blob).hexdigest()
            pidfile_bytes = len(pidfile_blob)
            j0_lines = [
                "schema=dcentos.s19k-startup-j0-prefork/v1",
                "transaction_id=" + "6" * 64,
                "ordinal=0",
                "predecessor_schema=none",
                "predecessor_sha256=none",
                "predecessor_bytes=0",
                f"trial_dir={self.wsl_trial}",
                "runtime_active_path=not-published",
                "runtime_active_sha256=none",
                "runtime_active_bytes=0",
                "runtime_active_phase=not-published",
                f"runtime_owner_path={self.wsl_root}/runtime-lock/owner",
                "runtime_owner_binding=self-hardlink",
                f"fifo_path={fifo_path}",
                "fifo_mnt_id=1",
                "fifo_inode=1",
                "fifo_mode=prw-------",
                "fifo_uid=0",
                "fifo_gid=0",
                "writer_role=wrapper",
                "writer_pid=7777",
                "writer_start=123",
                "writer_ppid=7000",
                "daemon_pid=0",
                "daemon_start=0",
                "wrapper_pid=7777",
                "wrapper_start=123",
                "wrapper_ppid=7000",
                "wrapper_comm=run_trial",
                f"wrapper_exe={self.wsl_trial}/run_trial",
                "wrapper_cmdline_sha256=" + "8" * 64,
                "wrapper_cmdline_bytes=64",
                "expected_daemon_cmdline_sha256=" + "9" * 64,
                "expected_daemon_cmdline_bytes=128",
                "daemon_environment_sha256=" + "a" * 64,
                "daemon_environment_bytes=256",
                "daemon_environment_count=10",
                "supervisor_pid=1458",
                "supervisor_start=1251",
                "supervisor_ppid=1",
                "supervisor_pgrp=1457",
                "supervisor_session=1457",
                "supervisor_exe=/usr/bin/bos-tools",
                "supervisor_cmdline_sha256=" + "3" * 64,
                "supervisor_cmdline_bytes=70",
                "bosminer_pid=9495",
                "bosminer_start=1044815",
                "bosminer_ppid=1458",
                "bosminer_pgrp=1457",
                "bosminer_session=1457",
                "bosminer_exe=/usr/bin/bosminer",
                "bosminer_cmdline_sha256=" + "4" * 64,
                "bosminer_cmdline_bytes=38",
                "stock_pidfile_path=/var/run/bosminer.pid",
                f"stock_pidfile_sha256={pidfile_sha}",
                f"stock_pidfile_bytes={pidfile_bytes}",
                f"binary_sha256={bin_sha}",
                f"binary_bytes={bin_bytes}",
                f"config_sha256={cfg_sha}",
                f"config_bytes={cfg_bytes}",
                f"runner_sha256={runner_sha}",
                f"runner_bytes={runner_bytes}",
                f"custody_observer_sha256={custody_sha}",
                f"custody_observer_bytes={custody_bytes}",
                f"stock_restart_helper_sha256={self.helper_sha}",
                f"stock_restart_helper_bytes={self.helper_bytes}",
                "live_identity_schema=dcentos.s19k-braiins-live-identity/v2",
                f"live_identity_profile={PROFILE}",
                f"live_identity_sha256={IDENTITY_SHA}",
                "gpio_raw=437:0,454:0,455:1,456:1",
                "watchdog_start_intent=false",
                "watchdog_armed=false",
                "signal_attempted=false",
                "inherited_rails=false",
                "route_or_uart_opened=false",
                "hardware_opened=false",
                "parent_release=false",
                "persistent_mutation=false",
                "publication=no-clobber-hard-link-after-fsync",
            ]
            line_file(preserved_owner, j0_lines)
            preserved_owner_sha, preserved_owner_bytes = sha_bytes(preserved_owner)
            startup_source = self.trial / "runtime_startup_prefix_pre_safeoff"
            self.startup_source = startup_source
            none_paths = {
                "c1": self.trial / "runtime_startup_c1_child_identity",
                "j1": self.trial / "runtime_startup_j1_daemon_blocked",
                "j2": self.trial / "runtime_startup_j2_child_bound",
                "release": self.trial / "runtime_startup_release",
                "parent_lost": self.trial / "runtime_startup_parent_lost",
                "terminal": self.trial / "runtime_startup_retired_terminal",
                "cleanup": self.trial / "runtime_startup_retire_cleanup_commit",
                "preserved_active": self.trial / "runtime_startup_active_pre_safeoff",
            }
            startup_highest = "j0"
            history: dict[str, tuple[str, int]] = {
                name: ("none", 0)
                for name in ("c1", "j1", "active", "j2", "release", "parent_lost")
            }
            terminal_present = False
            terminal_sha, terminal_bytes = "none", 0
            if self.variant in (
                "startup_active_terminal",
                "startup_j2_terminal",
                "startup_release_terminal",
                "startup_cleanup_terminal_consumed",
            ):
                startup_highest = {
                    "startup_active_terminal": "active",
                    "startup_j2_terminal": "j2",
                    "startup_release_terminal": "release",
                    "startup_cleanup_terminal_consumed": "release",
                }[self.variant]
                line_file(none_paths["preserved_active"], pre_lines)
                active_history_sha, active_history_bytes = sha_bytes(
                    none_paths["preserved_active"]
                )
                history.update(
                    {
                        "c1": ("b" * 64, 47),
                        "j1": ("c" * 64, 87),
                        "active": (active_history_sha, active_history_bytes),
                    }
                )
                if startup_highest in ("j2", "release"):
                    history["j2"] = ("d" * 64, 87)
                if startup_highest == "release":
                    history["release"] = ("e" * 64, 30)
                terminal_lines = [
                    "schema=dcentos.s19k-startup-retired-terminal/v1",
                    "transaction_id=" + "6" * 64,
                    "phase=startup-no-effect-retired",
                    f"highest_phase={startup_highest}",
                    f"owner_sha256={preserved_owner_sha}",
                    f"owner_bytes={preserved_owner_bytes}",
                    f"c1_sha256={history['c1'][0]}",
                    f"c1_bytes={history['c1'][1]}",
                    f"j1_sha256={history['j1'][0]}",
                    f"j1_bytes={history['j1'][1]}",
                    f"active_sha256={history['active'][0]}",
                    f"active_bytes={history['active'][1]}",
                    f"j2_sha256={history['j2'][0]}",
                    f"j2_bytes={history['j2'][1]}",
                    f"release_sha256={history['release'][0]}",
                    f"release_bytes={history['release'][1]}",
                    "parent_lost_sha256=none",
                    "parent_lost_bytes=0",
                    f"fifo_path={fifo_path}",
                    "fifo_mnt_id=1",
                    "fifo_inode=1",
                    f"transcript_path={self._wsl_path(transcript)}",
                    "transcript_mnt_id=1",
                    "transcript_inode=1",
                    "transcript_mode=0600",
                    "transcript_uid=0",
                    "transcript_gid=0",
                    f"transcript_sha256={transcript_sha}",
                    f"transcript_bytes={transcript_bytes}",
                    "supervisor_pid=1458",
                    "supervisor_start=1251",
                    "supervisor_ppid=1",
                    "supervisor_pgrp=1457",
                    "supervisor_session=1457",
                    "supervisor_exe=/usr/bin/bos-tools",
                    "supervisor_cmdline_sha256=" + "3" * 64,
                    "supervisor_cmdline_bytes=70",
                    "bosminer_pid=9495",
                    "bosminer_start=1044815",
                    "bosminer_ppid=1458",
                    "bosminer_pgrp=1457",
                    "bosminer_session=1457",
                    "bosminer_exe=/usr/bin/bosminer",
                    "bosminer_cmdline_sha256=" + "4" * 64,
                    "bosminer_cmdline_bytes=38",
                    "stock_pidfile_path=/var/run/bosminer.pid",
                    f"stock_pidfile_sha256={pidfile_sha}",
                    f"stock_pidfile_bytes={pidfile_bytes}",
                    f"binary_sha256={bin_sha}",
                    f"binary_bytes={bin_bytes}",
                    f"config_sha256={cfg_sha}",
                    f"config_bytes={cfg_bytes}",
                    f"runner_sha256={runner_sha}",
                    f"runner_bytes={runner_bytes}",
                    f"custody_observer_sha256={custody_sha}",
                    f"custody_observer_bytes={custody_bytes}",
                    f"stock_restart_helper_sha256={self.helper_sha}",
                    f"stock_restart_helper_bytes={self.helper_bytes}",
                    f"live_identity_profile={PROFILE}",
                    f"live_identity_sha256={IDENTITY_SHA}",
                    "watchdog_start_intent=false",
                    "watchdog_armed=false",
                    "signal_attempted=false",
                    "inherited_rails=false",
                    "route_or_uart_opened=false",
                    "hardware_opened=false",
                    "stock_tree_revalidated=true",
                    "live_identity_revalidated=true",
                    "gpio_raw=437:0,454:0,455:1,456:1",
                    "gpio_stock_baseline_revalidated=true",
                    "gpio437_engaged=true",
                    "dcentrald_all_threads_absent=true",
                    "watchdog_all_threads_absent=true",
                    "persistent_mutation=false",
                    "publication=no-clobber-hard-link-after-fsync",
                ]
                if len(terminal_lines) != 75:
                    raise AssertionError(
                        f"startup terminal fixture has {len(terminal_lines)} fields"
                    )
                line_file(none_paths["terminal"], terminal_lines)
                terminal_sha, terminal_bytes = sha_bytes(none_paths["terminal"])
                terminal_present = True
            startup_lines = [
                "schema=dcentos.s19k-startup-prefix-safeoff-source/v1",
                "transaction_id=" + "6" * 64,
                "phase=startup-prefix-stock-loss-admitted",
                f"highest_phase={startup_highest}",
                f"trial_dir={self.wsl_trial}",
                "source_kind=startup-prefix",
                "owner_present=true",
                f"owner_path={self.wsl_trial}/runtime_startup_owner_pre_safeoff",
                f"owner_sha256={preserved_owner_sha}",
                f"owner_bytes={preserved_owner_bytes}",
            ]
            for name in ("c1", "j1"):
                history_sha, history_bytes = history[name]
                startup_lines.extend(
                    [
                        f"{name}_present=false",
                        f"{name}_path={self._wsl_path(none_paths[name])}",
                        f"{name}_sha256={history_sha}",
                        f"{name}_bytes={history_bytes}",
                    ]
                )
            active_present = history["active"] != ("none", 0)
            startup_lines.extend(
                [
                    f"active_present={str(active_present).lower()}",
                    f"active_path={self._wsl_path(none_paths['preserved_active']) if active_present else 'none'}",
                    f"active_sha256={history['active'][0]}",
                    f"active_bytes={history['active'][1]}",
                ]
            )
            for name in ("j2", "release", "parent_lost"):
                history_sha, history_bytes = history[name]
                startup_lines.extend(
                    [
                        f"{name}_present=false",
                        f"{name}_path={self._wsl_path(none_paths[name])}",
                        f"{name}_sha256={history_sha}",
                        f"{name}_bytes={history_bytes}",
                    ]
                )
            startup_lines.extend(
                [
                    f"terminal_present={str(terminal_present).lower()}",
                    f"terminal_path={self._wsl_path(none_paths['terminal'])}",
                    f"terminal_sha256={terminal_sha}",
                    f"terminal_bytes={terminal_bytes}",
                    "cleanup_present=false",
                    f"cleanup_path={self._wsl_path(none_paths['cleanup'])}",
                    "cleanup_sha256=none",
                    "cleanup_bytes=0",
                ]
            )
            startup_lines.extend(
                [
                    "preserved_owner_present=true",
                    f"preserved_owner_path={self.wsl_trial}/runtime_startup_owner_pre_safeoff",
                    f"preserved_owner_sha256={preserved_owner_sha}",
                    f"preserved_owner_bytes={preserved_owner_bytes}",
                    f"preserved_active_present={str(active_present).lower()}",
                    f"preserved_active_path={self.wsl_trial}/runtime_startup_active_pre_safeoff",
                    f"preserved_active_sha256={history['active'][0]}",
                    f"preserved_active_bytes={history['active'][1]}",
                    "fifo_present=true",
                    f"fifo_path={fifo_path}",
                    "fifo_mnt_id=1",
                    "fifo_inode=1",
                    "transcript_present=true",
                    f"transcript_path={self._wsl_path(transcript)}",
                    "transcript_mnt_id=1",
                    "transcript_inode=1",
                    "transcript_mode=0600",
                    "transcript_uid=0",
                    "transcript_gid=0",
                    f"transcript_sha256={transcript_sha}",
                    f"transcript_bytes={transcript_bytes}",
                    "supervisor_pid=1458",
                    "supervisor_start=1251",
                    "supervisor_ppid=1",
                    "supervisor_pgrp=1457",
                    "supervisor_session=1457",
                    "supervisor_exe=/usr/bin/bos-tools",
                    "supervisor_cmdline_sha256=" + "3" * 64,
                    "supervisor_cmdline_bytes=70",
                    "bosminer_pid=9495",
                    "bosminer_start=1044815",
                    "bosminer_ppid=1458",
                    "bosminer_pgrp=1457",
                    "bosminer_session=1457",
                    "bosminer_exe=/usr/bin/bosminer",
                    "bosminer_cmdline_sha256=" + "4" * 64,
                    "bosminer_cmdline_bytes=38",
                    "stock_pidfile_path=/var/run/bosminer.pid",
                    f"stock_pidfile_sha256={pidfile_sha}",
                    f"stock_pidfile_bytes={pidfile_bytes}",
                    f"binary_sha256={bin_sha}",
                    f"binary_bytes={bin_bytes}",
                    f"config_sha256={cfg_sha}",
                    f"config_bytes={cfg_bytes}",
                    f"runner_sha256={runner_sha}",
                    f"runner_bytes={runner_bytes}",
                    f"custody_observer_sha256={custody_sha}",
                    f"custody_observer_bytes={custody_bytes}",
                    f"stock_restart_helper_sha256={self.helper_sha}",
                    f"stock_restart_helper_bytes={self.helper_bytes}",
                    "live_identity_schema=dcentos.s19k-braiins-live-identity/v2",
                    f"live_identity_profile={PROFILE}",
                    f"live_identity_sha256={IDENTITY_SHA}",
                    "stock_supervisor=absent",
                    "stock_bosminer=absent",
                    "dcentrald=absent",
                    "watchdog_fd=absent",
                    "competing_wrapper=absent",
                    "watchdog_start_intent=false",
                    "watchdog_armed=false",
                    "signal_attempted=false",
                    "inherited_rails=false",
                    "route_or_uart_opened=false",
                    "hardware_opened=false",
                    "persistent_mutation=false",
                    "publication=no-clobber-hard-link-after-fsync",
                ]
            )
            if self.variant == "startup_cleanup_terminal_consumed":
                cleanup_commit_source = (
                    self.trial
                    / ".runtime_startup_retire_cleanup_commit.source.7777.123"
                )
                cleanup_lines = [
                    "schema=dcentos.s19k-startup-retire-cleanup-commit/v1",
                    "transaction_id=" + "6" * 64,
                    "phase=startup-no-effect-cleanup-committed",
                    f"highest_phase={startup_highest}",
                    f"trial_dir={self.wsl_trial}",
                    "terminal_schema=dcentos.s19k-startup-retired-terminal/v1",
                    f"terminal_sha256={terminal_sha}",
                    f"terminal_bytes={terminal_bytes}",
                    f"owner_sha256={preserved_owner_sha}",
                    f"owner_bytes={preserved_owner_bytes}",
                    f"active_sha256={history['active'][0]}",
                    f"active_bytes={history['active'][1]}",
                    f"fifo_path={fifo_path}",
                    f"transcript_path={self._wsl_path(transcript)}",
                    "transcript_mnt_id=1",
                    "transcript_inode=1",
                    "transcript_mode=0600",
                    "transcript_uid=0",
                    "transcript_gid=0",
                    f"transcript_sha256={transcript_sha}",
                    f"transcript_bytes={transcript_bytes}",
                    "residue_count=0",
                    "residue_manifest_sha256="
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    f"commit_source_path={self._wsl_path(cleanup_commit_source)}",
                    "supervisor_pid=1458",
                    "supervisor_start=1251",
                    "supervisor_ppid=1",
                    "supervisor_pgrp=1457",
                    "supervisor_session=1457",
                    "supervisor_exe=/usr/bin/bos-tools",
                    "supervisor_cmdline_sha256=" + "3" * 64,
                    "supervisor_cmdline_bytes=70",
                    "bosminer_pid=9495",
                    "bosminer_start=1044815",
                    "bosminer_ppid=1458",
                    "bosminer_pgrp=1457",
                    "bosminer_session=1457",
                    "bosminer_exe=/usr/bin/bosminer",
                    "bosminer_cmdline_sha256=" + "4" * 64,
                    "bosminer_cmdline_bytes=38",
                    "stock_pidfile_path=/var/run/bosminer.pid",
                    f"stock_pidfile_sha256={pidfile_sha}",
                    f"stock_pidfile_bytes={pidfile_bytes}",
                    f"binary_sha256={bin_sha}",
                    f"binary_bytes={bin_bytes}",
                    f"config_sha256={cfg_sha}",
                    f"config_bytes={cfg_bytes}",
                    f"runner_sha256={runner_sha}",
                    f"runner_bytes={runner_bytes}",
                    f"custody_observer_sha256={custody_sha}",
                    f"custody_observer_bytes={custody_bytes}",
                    f"stock_restart_helper_sha256={self.helper_sha}",
                    f"stock_restart_helper_bytes={self.helper_bytes}",
                    f"live_identity_profile={PROFILE}",
                    f"live_identity_sha256={IDENTITY_SHA}",
                    "gpio_raw=437:0,454:0,455:1,456:1",
                    "watchdog_start_intent=false",
                    "watchdog_armed=false",
                    "signal_attempted=false",
                    "inherited_rails=false",
                    "route_or_uart_opened=false",
                    "hardware_opened=false",
                    "persistent_mutation=false",
                    "publication=no-clobber-hard-link-after-fsync",
                ]
                if len(cleanup_lines) != 64:
                    raise AssertionError(
                        f"startup cleanup fixture has {len(cleanup_lines)} fields"
                    )
                line_file(none_paths["cleanup"], cleanup_lines)
                cleanup_sha, cleanup_bytes = sha_bytes(none_paths["cleanup"])
                cleanup_overrides = {
                    "source_kind": "startup-cleanup-commit",
                    "owner_present": "false",
                    "owner_path": "none",
                    "active_present": "false",
                    "active_path": "none",
                    "terminal_present": "false",
                    "terminal_sha256": terminal_sha,
                    "terminal_bytes": str(terminal_bytes),
                    "cleanup_present": "true",
                    "cleanup_sha256": cleanup_sha,
                    "cleanup_bytes": str(cleanup_bytes),
                    "preserved_owner_present": "false",
                    "preserved_owner_sha256": "none",
                    "preserved_owner_bytes": "0",
                    "preserved_active_present": "false",
                    "preserved_active_sha256": "none",
                    "preserved_active_bytes": "0",
                    "fifo_present": "false",
                    "fifo_mnt_id": "none",
                    "fifo_inode": "none",
                    "transcript_present": "false",
                }
                for historical_name in (
                    "c1",
                    "j1",
                    "j2",
                    "release",
                    "parent_lost",
                ):
                    cleanup_overrides[f"{historical_name}_sha256"] = "none"
                    cleanup_overrides[f"{historical_name}_bytes"] = "0"
                startup_lines = [
                    f"{key}={cleanup_overrides[key]}"
                    if key in cleanup_overrides
                    else line
                    for line in startup_lines
                    for key in (line.split("=", 1)[0],)
                ]
                preserved_owner.unlink()
                none_paths["preserved_active"].unlink()
                none_paths["terminal"].unlink()
                transcript.unlink()
                subprocess.run([*WSL, "rm", "-f", fifo_path], check=True)
            self.assert_startup_source_lines = startup_lines
            line_file(startup_source, startup_lines)
            startup_source_sha, startup_source_bytes = sha_bytes(startup_source)
        self.active = self.trial / "runtime_active"
        active_lines = [
            "schema="
            + (
                "dcentos.s19k-startup-prefix-stock-restart-pending/v1"
                if startup_prefix
                else "dcentos.s19k-receiptless-stock-restart-pending/v2"
                if receiptless
                else (
                    "dcentos.s19k-stock-restart-pending/v4"
                    if self.variant.startswith("v2_")
                    else "dcentos.s19k-stock-restart-pending/v3"
                )
            ),
            "phase=terminal-safeoff-stock-restart-pending",
            "terminal=true",
            f"trial_dir={self.wsl_trial}",
            "source_runtime_active_schema=dcentos.s19k-tmp-runtime/v5",
            f"source_runtime_active_path={self.wsl_trial}/runtime_active_pre_safeoff",
            f"source_runtime_active_sha256={pre_sha}",
            f"source_runtime_active_bytes={pre_bytes}",
            f"binary_sha256={bin_sha}",
            f"binary_bytes={bin_bytes}",
            f"config_sha256={cfg_sha}",
            f"config_bytes={cfg_bytes}",
            f"runner_sha256={runner_sha}",
            f"runner_bytes={runner_bytes}",
            f"custody_observer_sha256={custody_sha}",
            f"custody_observer_bytes={custody_bytes}",
            f"stock_restart_helper_sha256={self.helper_sha}",
            f"stock_restart_helper_bytes={self.helper_bytes}",
            "live_identity_schema=dcentos.s19k-braiins-live-identity/v2",
            f"live_identity_profile={PROFILE}",
            f"live_identity_sha256={IDENTITY_SHA}",
            f"live_identity_model_sha256={MODEL_SHA}",
            "live_identity_board_count=2",
            f"live_identity_physical_addresses={IDENTITY_ADDRESSES}",
            f"live_identity_board_names={IDENTITY_NAMES}",
            f"live_identity_eeprom={IDENTITY_EEPROM}",
            "safeoff_receipt_schema=dcentos.s19k-track1-safeoff/v1",
            f"safeoff_receipt_path={self.wsl_trial}/runtime_safeoff_terminal_receipt",
            f"safeoff_receipt_sha256={safe_sha}",
            f"safeoff_receipt_bytes={safe_bytes}",
            "resets=454:0,455:0,456:0",
            "psu=437:1",
            "gpio_raw=437:1,454:0,455:0,456:0",
            "dcentrald=absent",
            "writer_wrapper_pid=7777",
            "writer_wrapper_start=123",
            "wrapper_exit_required=true",
            "stock_supervisor=absent",
            "stock_bosminer=absent",
            "watchdog_fd=absent",
            f"stock_init_path={self.wsl_root}/S99bosminer",
            f"stock_init_sha256={s99_sha}",
            f"stock_init_bytes={s99_bytes}",
            "persistent_mutation=false",
            "next_authority=exact-stock-restart-helper-only",
        ]
        if startup_prefix:
            active_lines = (
                active_lines[:4]
                + [
                    "transaction_id=" + "6" * 64,
                    f"highest_phase={startup_highest}",
                    "source_receipt_schema=dcentos.s19k-startup-prefix-safeoff-source/v1",
                    f"source_receipt_path={self.wsl_trial}/runtime_startup_prefix_pre_safeoff",
                    f"source_receipt_sha256={startup_source_sha}",
                    f"source_receipt_bytes={startup_source_bytes}",
                ]
                + active_lines[8:]
            )
        elif receiptless:
            active_lines = (
                active_lines[:4]
                + ["source=receiptless-recovery-no-v4-active"]
                + active_lines[8:]
            )
        if self.variant.startswith("v2_"):
            active_lines.extend(
                [
                    "terminal_handoff_receipt_schema=dcentos.s19k-terminal-safeoff-partial-stock-owner/v1",
                    f"terminal_handoff_receipt_path={self.wsl_trial}/runtime_terminal_safeoff",
                    f"terminal_handoff_receipt_sha256={terminal_handoff_sha}",
                    f"terminal_handoff_receipt_bytes={terminal_handoff_bytes}",
                ]
            )
        line_file(self.active, active_lines)
        self.active_sha, self.active_bytes = sha_bytes(self.active)
        self.lock = self.root / "runtime-lock"
        self.lock.mkdir()
        self.owner = self.lock / "owner"
        owner_lines = [
            "schema="
            + (
                "dcentos.s19k-track1-runtime-lock/v10"
                if startup_prefix
                else "dcentos.s19k-track1-runtime-lock/v9"
                if receiptless
                else (
                    "dcentos.s19k-track1-runtime-lock/v8"
                    if self.variant.startswith("v2_")
                    else "dcentos.s19k-track1-runtime-lock/v7"
                )
            ),
            "owner_kind="
            + (
                "startup-prefix-stock-restart-pending"
                if startup_prefix
                else "receiptless-stock-restart-pending"
                if receiptless
                else "stock-restart-pending"
            ),
            f"trial_dir={self.wsl_trial}",
            f"runner_sha256={runner_sha}",
            f"runner_bytes={runner_bytes}",
            f"custody_observer_sha256={custody_sha}",
            f"custody_observer_bytes={custody_bytes}",
            f"stock_restart_helper_sha256={self.helper_sha}",
            f"stock_restart_helper_bytes={self.helper_bytes}",
            f"live_identity_sha256={IDENTITY_SHA}",
            f"active_sha256={self.active_sha}",
            f"active_bytes={self.active_bytes}",
            f"source_runtime_active_sha256={pre_sha}",
            f"safeoff_receipt_sha256={safe_sha}",
        ]
        if startup_prefix:
            owner_lines = owner_lines[:12] + [
                    "transaction_id=" + "6" * 64,
                    f"highest_phase={startup_highest}",
                    f"source_receipt_sha256={startup_source_sha}",
                    f"safeoff_receipt_sha256={safe_sha}",
                ]
        elif receiptless:
            owner_lines.pop(-2)
        if self.variant.startswith("v2_"):
            owner_lines.append(
                f"terminal_handoff_receipt_sha256={terminal_handoff_sha}"
            )
        line_file(self.owner, owner_lines)

    @staticmethod
    def _replace_field(path: Path, key: str, value: str) -> None:
        lines = path.read_text(encoding="utf-8").splitlines()
        matches = [index for index, line in enumerate(lines) if line.startswith(f"{key}=")]
        if len(matches) != 1:
            raise AssertionError(f"fixture field {key!r} is not unique in {path}")
        lines[matches[0]] = f"{key}={value}"
        line_file(path, lines)

    def mutate_startup_source_and_rebind(self, key: str, value: str) -> None:
        """Mutate inner startup evidence while keeping every outer digest truthful."""
        self._replace_field(self.startup_source, key, value)
        source_sha, source_bytes = sha_bytes(self.startup_source)
        self._replace_field(self.active, "source_receipt_sha256", source_sha)
        self._replace_field(self.active, "source_receipt_bytes", str(source_bytes))
        self.active_sha, self.active_bytes = sha_bytes(self.active)
        self._replace_field(self.owner, "active_sha256", self.active_sha)
        self._replace_field(self.owner, "active_bytes", str(self.active_bytes))
        self._replace_field(self.owner, "source_receipt_sha256", source_sha)

    def make_process(
        self,
        pid: int,
        comm: str,
        exe: str,
        ppid: int,
        pgrp: int,
        session: int,
        start: int,
        argv: list[str],
    ) -> None:
        process = self.proc / str(pid)
        process.mkdir(parents=True, exist_ok=True)
        line_file(process / "comm", [comm])
        line_file(
            process / "stat",
            [
                f"{pid} ({comm}) S {ppid} {pgrp} {session} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {start}"
            ],
        )
        (process / "cmdline").write_bytes(
            b"".join(arg.encode("utf-8") + b"\0" for arg in argv)
        )
        self._symlink(exe, process / "exe")
        task = process / "task" / str(pid)
        (task / "fd").mkdir(parents=True)
        shutil.copyfile(process / "stat", task / "stat")
        shutil.copyfile(process / "comm", task / "comm")
        shutil.copyfile(process / "cmdline", task / "cmdline")
        self._symlink(exe, task / "exe")
        self._symlink("/", task / "cwd")
        line_file(task / "status", ["Umask:\t0022"])
        for fd in ("0", "1", "2"):
            self._symlink("/dev/null", task / "fd" / fd)
        env = [
            "CONSOLE=/dev/console",
            "HOME=/",
            "INIT_VERSION=sysvinit-2.9n",
            "PATH=/sbin:/usr/sbin:/bin:/usr/bin",
            "PREVLEVEL=N",
            "PWD=/",
            "RUNLEVEL=3",
            "SHELL=/bin/sh",
            "SHLVL=3",
            "TERM=linux",
            "jtag=disable",
            "logo=,loaded,androidboot.selinux=enforcing",
        ]
        if comm == "bosminer":
            env.append("   =/usr/bin/bos-tools")
        (task / "environ").write_bytes(
            b"".join(item.encode("utf-8") + b"\0" for item in env)
        )

    def argv(self, mode: str = "start") -> list[str]:
        token = (
            "START_STOCK_FROM_TERMINAL_SAFEOFF"
            if mode == "start"
            else "PROVE_STOCK_RESTART"
        )
        return [
            *WSL,
            "/bin/sh",
            f"{self.wsl_trial}/stock_restart_helper",
            mode,
            self.wsl_trial,
            self.active_sha,
            str(self.active_bytes),
            self.helper_sha,
            str(self.helper_bytes),
            token,
        ]

    def run(
        self, mode: str = "start", *, timeout: int = 180
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.argv(mode),
            text=True,
            capture_output=True,
            timeout=timeout,
        )

    def timeout_diagnostic(self, error: subprocess.TimeoutExpired) -> str:
        def rendered_output(value: bytes | str | None) -> str:
            if value is None:
                return "<none>"
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="backslashreplace")
            return value

        def rendered_path(path: Path) -> str:
            try:
                if path.is_symlink():
                    return f"symlink->{os.readlink(path)}"
                if path.is_file():
                    data = path.read_bytes()
                    return (
                        f"regular bytes={len(data)} sha256={hashlib.sha256(data).hexdigest()} "
                        f"content={data!r}"
                    )
                if path.is_dir():
                    return "directory children=" + repr(
                        sorted(item.name for item in path.iterdir())
                    )
                return "absent"
            except OSError as error:
                return f"inaccessible error={error!r}"

        state_paths = (
            self.startup_source,
            self.active,
            self.owner,
            self.safeoff,
            self.root / "restart-helper-lock",
            self.root / "restart-helper-lock" / "owner",
            self.lock / "stock_restart_claim",
            self.lock / "stock_restart_claim" / "owner",
            self.trial / "runtime_stock_restart_complete",
            self.trial / "runtime_stock_restart_unresolved",
        )
        lines = [
            f"timeout={error.timeout}",
            f"partial_stdout={rendered_output(error.stdout)!r}",
            f"partial_stderr={rendered_output(error.stderr)!r}",
        ]
        lines.extend(f"state[{path}]={rendered_path(path)}" for path in state_paths)
        for path in sorted(self.proc.rglob("*"), key=lambda item: str(item)):
            lines.append(f"proc[{path.relative_to(self.proc)}]={rendered_path(path)}")
        return "\n".join(lines)


@unittest.skipUnless(
    os.name == "nt", "behavioral fixtures exercise held BusyBox-like WSL"
)
class S19kStockRestartTests(unittest.TestCase):
    def test_exact_pending_safeoff_restarts_once_and_preserves_evidence(self) -> None:
        fixture = StockRestartFixture()
        try:
            result = fixture.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("stock restart proven", result.stdout)
            self.assertEqual(fixture.start_count.read_text(encoding="utf-8"), "start\n")
            self.assertFalse(fixture.active.exists())
            self.assertTrue(
                (fixture.trial / "runtime_stock_restart_pending.consumed").is_file()
            )
            self.assertTrue(
                (fixture.trial / "runtime_stock_restart_complete").is_file()
            )
            terminal_text = (
                fixture.trial / "runtime_stock_restart_complete"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "dcent_direct_hardware_or_flash_writer=false\n", terminal_text
            )
            self.assertIn(
                "stock_restart_mutation=expected-tmpfs-pidfile+stock-daemon-state+"
                "persistent-ubifs-bosminer-log-append\n",
                terminal_text,
            )
            self.assertIn(
                "cooling_recovery=configured-monitoring-only-physical-fan-rpm-not-"
                "proven-min_fans-0\n",
                terminal_text,
            )
            self.assertIn(
                "watchdog_fd_authority=bounded-all-tid-hardware-watchdog-absence\n",
                terminal_text,
            )
            watchdog_evidence = fixture.trial / "runtime_stock_restart_watchdog_fds"
            evidence_text = watchdog_evidence.read_text(encoding="utf-8")
            self.assertIn("matching_watchdog_rdev_fd_count=0\n", evidence_text)
            self.assertIn(
                "live_nonobservation_sha256="
                "24676e15bb15f075345bd8f455a70a800c6c684db3d3fc7683cffc45193afa75\n",
                evidence_text,
            )
            self.assertTrue(fixture.pre.is_file())
            self.assertTrue(fixture.safeoff.is_file())
            self.assertFalse(fixture.lock.exists())
        finally:
            fixture.close()

    def test_nonleader_stock_owned_watchdog_fd_retains_committed_obligation(
        self,
    ) -> None:
        fixture = StockRestartFixture("nonleader_stock_watchdog")
        try:
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(fixture.start_count.read_text(encoding="utf-8"), "start\n")
            self.assertTrue(fixture.active.is_file())
            self.assertTrue(fixture.lock.is_dir())
        finally:
            fixture.close()

    def test_non_watchdog_lookalikes_do_not_masquerade_as_hardware_wdt(self) -> None:
        for variant in ("regular_watchdog_lookalike", "wrong_rdev_watchdog_lookalike"):
            with self.subTest(variant=variant):
                fixture = StockRestartFixture(variant)
                try:
                    result = fixture.run()
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(
                        fixture.start_count.read_text(encoding="utf-8"), "start\n"
                    )
                finally:
                    fixture.close()

    def test_preexisting_stock_pidfile_or_watchdog_refuses_before_start(self) -> None:
        for variant in (
            "preexisting_stock",
            "preexisting_pidfile",
            "watchdog_fd",
            "nonleader_watchdog_fd",
            "malformed_nonleader_task",
            "preexisting_launcher",
            "wrong_busybox",
            "wrong_s99",
            "wrong_bos_defaults",
            "wrong_busybox_loader",
            "wrong_busybox_libm",
            "wrong_busybox_libc",
            "wrong_stock_bos_tools",
            "wrong_stock_bosminer",
            "live_writer_space_comm",
            "live_writer_right_paren_space",
            "writer_missing_stat",
            "writer_truncated_stat",
        ):
            with self.subTest(variant=variant):
                fixture = StockRestartFixture(variant)
                try:
                    result = fixture.run()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(fixture.start_count.exists())
                    self.assertTrue(fixture.active.is_file())
                    self.assertTrue(fixture.lock.is_dir())
                finally:
                    fixture.close()

    def test_exact_terminal_partial_handoff_v2_admits_but_live_remnant_refuses(
        self,
    ) -> None:
        admitted = StockRestartFixture("v2_exact_global_absence")
        try:
            try:
                result = admitted.run(timeout=180)
            except subprocess.TimeoutExpired as error:
                self.fail(
                    "terminal partial-handoff admit exceeded its evidence-bounded 180s limit:\n"
                    + admitted.timeout_diagnostic(error)
                )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                admitted.start_count.read_text(encoding="utf-8"), "start\n"
            )
        finally:
            admitted.close()
        refused = StockRestartFixture("v2_global_stock_present")
        try:
            try:
                result = refused.run(timeout=180)
            except subprocess.TimeoutExpired as error:
                self.fail(
                    "terminal partial-handoff refusal exceeded its evidence-bounded 180s limit:\n"
                    + refused.timeout_diagnostic(error)
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(refused.start_count.exists())
            self.assertTrue(refused.active.is_file())
            self.assertTrue(refused.lock.is_dir())
        finally:
            refused.close()

    def test_exact_receiptless_pending_and_v5_owner_restart_stock(self) -> None:
        fixture = StockRestartFixture("receiptless_exact")
        try:
            result = fixture.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(fixture.start_count.read_text(encoding="utf-8"), "start\n")
            self.assertFalse(fixture.pre.exists())
            terminal = fixture.trial / "runtime_stock_restart_complete"
            self.assertIn(
                "source_kind=receiptless-recovery-no-v4-active",
                terminal.read_text(encoding="utf-8"),
            )
        finally:
            fixture.close()

    def test_exact_startup_prefix_j0_pending_and_v10_owner_restart_stock(self) -> None:
        self.assertEqual(
            sha_bytes(HELPER_SOURCE),
            (
                "63685a39d502f74b06420ed7c719edc732a99410d7a97fbc59604f2907ee4a43",
                163789,
            ),
        )
        fixture = StockRestartFixture("startup_j0_exact", native_wsl=True)
        try:
            try:
                result = fixture.run(timeout=180)
            except subprocess.TimeoutExpired as error:
                self.fail(
                    "deep startup-prefix J0 fixture exceeded its evidence-bounded 180s limit:\n"
                    + fixture.timeout_diagnostic(error)
                )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(fixture.start_count.read_text(encoding="utf-8"), "start\n")
            self.assertTrue(
                (fixture.trial / "runtime_startup_owner_pre_safeoff").is_file()
            )
            self.assertTrue(
                (fixture.trial / "runtime_startup_prefix_pre_safeoff").is_file()
            )
        finally:
            fixture.close()

    def test_startup_inner_evidence_corruption_and_object_state_refuse(self) -> None:
        variants = (
            "recomputed-source-stock-start",
            "fifo-false-but-live",
            "fifo-true-but-missing",
            "transcript-false-but-live",
            "transcript-true-but-missing",
            "transition-tmp-residue",
            "transition-claim-residue",
            "transition-completed-residue",
            "pending-tmp-residue",
        )
        for variant in variants:
            with self.subTest(variant=variant):
                fixture = StockRestartFixture("startup_j0_exact")
                try:
                    if variant == "recomputed-source-stock-start":
                        fixture.mutate_startup_source_and_rebind(
                            "supervisor_start", "1252"
                        )
                    elif variant == "fifo-false-but-live":
                        fixture.mutate_startup_source_and_rebind(
                            "fifo_present", "false"
                        )
                    elif variant == "fifo-true-but-missing":
                        subprocess.run(
                            [*WSL, "rm", "-f", fixture.startup_fifo_path],
                            check=True,
                        )
                    elif variant == "transcript-false-but-live":
                        fixture.mutate_startup_source_and_rebind(
                            "transcript_present", "false"
                        )
                    elif variant == "transcript-true-but-missing":
                        fixture.startup_transcript.unlink()
                    elif variant.startswith("transition-") or variant == "pending-tmp-residue":
                        residue_name = {
                            "transition-tmp-residue": ".runtime_startup_j1_daemon_blocked.tmp.999",
                            "transition-claim-residue": ".runtime_startup_j2_child_bound.claim.999",
                            "transition-completed-residue": ".runtime_startup_release.completed.999",
                            "pending-tmp-residue": ".runtime_stock_restart_pending.tmp.999",
                        }[variant]
                        (fixture.trial / residue_name).write_bytes(
                            b"unresolved producer scratch\n"
                        )
                    result = fixture.run()
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(fixture.start_count.exists())
                    self.assertTrue(fixture.active.is_file())
                    self.assertTrue(fixture.lock.is_dir())
                finally:
                    fixture.close()

    def test_terminal_backed_release_chain_admits_and_recomputed_mismatch_refuses(
        self,
    ) -> None:
        admitted = StockRestartFixture("startup_release_terminal")
        try:
            try:
                result = admitted.run(timeout=360)
            except subprocess.TimeoutExpired as error:
                self.fail(
                    "terminal-backed release fixture exceeded its WSL/DrvFs 360s limit:\n"
                    + admitted.timeout_diagnostic(error)
                )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(admitted.start_count.read_text(encoding="utf-8"), "start\n")
        finally:
            admitted.close()
        corrupted = StockRestartFixture("startup_release_terminal")
        try:
            corrupted.mutate_startup_source_and_rebind("release_sha256", "f" * 64)
            result = corrupted.run()
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertFalse(corrupted.start_count.exists())
            self.assertTrue(corrupted.active.is_file())
            self.assertTrue(corrupted.lock.is_dir())
        finally:
            corrupted.close()

    def test_terminal_backed_active_and_j2_chains_admit(self) -> None:
        for variant in ("startup_active_terminal", "startup_j2_terminal"):
            with self.subTest(variant=variant):
                fixture = StockRestartFixture(variant)
                try:
                    result = fixture.run(timeout=180)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(
                        fixture.start_count.read_text(encoding="utf-8"), "start\n"
                    )
                finally:
                    fixture.close()

    def test_cleanup_suffix_consumed_history_admits_and_recomputed_mismatch_refuses(
        self,
    ) -> None:
        admitted = StockRestartFixture("startup_cleanup_terminal_consumed")
        try:
            result = admitted.run(timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(admitted.start_count.read_text(encoding="utf-8"), "start\n")
        finally:
            admitted.close()
        corrupted = StockRestartFixture("startup_cleanup_terminal_consumed")
        try:
            corrupted.mutate_startup_source_and_rebind("terminal_sha256", "f" * 64)
            result = corrupted.run()
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertFalse(corrupted.start_count.exists())
            self.assertTrue(corrupted.active.is_file())
            self.assertTrue(corrupted.lock.is_dir())
        finally:
            corrupted.close()

    def test_board_global_invocation_mutex_permits_only_one_start(self) -> None:
        fixture = StockRestartFixture()
        first: subprocess.Popen[str] | None = None
        second: subprocess.Popen[str] | None = None
        try:
            first = subprocess.Popen(
                fixture.argv(), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            second = subprocess.Popen(
                fixture.argv(), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            first_out, first_err = first.communicate(timeout=70)
            second_out, second_err = second.communicate(timeout=70)
            self.assertEqual(
                sorted((first.returncode, second.returncode)),
                [0, 1],
                f"first={first_out!r}/{first_err!r}; second={second_out!r}/{second_err!r}",
            )
            self.assertEqual(fixture.start_count.read_text(encoding="utf-8"), "start\n")
        finally:
            for process in (first, second):
                if process is not None and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
            fixture.close()

    def test_safeoff_or_identity_contradiction_refuses_before_start(self) -> None:
        safeoff = StockRestartFixture()
        try:
            safeoff.safeoff.write_text("forged\n", encoding="utf-8", newline="\n")
            result = safeoff.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(safeoff.start_count.exists())
        finally:
            safeoff.close()
        identity = StockRestartFixture("wrong_identity")
        try:
            result = identity.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(identity.start_count.exists())
        finally:
            identity.close()

    def test_ambiguous_poststart_retains_committed_obligation_and_never_retries(
        self,
    ) -> None:
        for variant in (
            "duplicate_supervisor",
            "stale_log",
            "init_failure",
            "poststart_bosminer_replaced",
            "wrong_stock_env",
            "wrong_stock_cwd",
            "wrong_stock_umask",
            "wrong_stock_fd",
            "wrong_pidfile_content",
            "missing_cooling_evidence",
            "stock_watchdog",
            "nonleader_stock_watchdog",
            "foreign_watchdog",
            "mixed_stock_foreign_watchdog",
            "alternate_path_exact_watchdog",
            "poststart_malformed_task",
            "poststart_inaccessible_task",
            "poststart_task_churn",
        ):
            with self.subTest(variant=variant):
                fixture = StockRestartFixture(variant)
                try:
                    first = fixture.run()
                    self.assertNotEqual(first.returncode, 0)
                    self.assertEqual(
                        fixture.start_count.read_text(encoding="utf-8"), "start\n"
                    )
                    claim = fixture.lock / "stock_restart_claim" / "owner"
                    self.assertIn(
                        "phase=start-invocation-committed",
                        claim.read_text(encoding="utf-8"),
                    )
                    second = fixture.run("prove")
                    self.assertNotEqual(second.returncode, 0)
                    self.assertEqual(
                        fixture.start_count.read_text(encoding="utf-8"), "start\n"
                    )
                    self.assertTrue(fixture.active.is_file())
                    self.assertTrue(fixture.lock.is_dir())
                finally:
                    fixture.close()

    def test_committed_before_exec_crash_is_prove_only_and_typed_unresolved(
        self,
    ) -> None:
        fixture = StockRestartFixture("fault_after_commit")
        try:
            crashed = fixture.run()
            self.assertEqual(crashed.returncode, 86, crashed.stderr)
            self.assertFalse(fixture.start_count.exists())
            proved = fixture.run("prove")
            self.assertNotEqual(proved.returncode, 0)
            self.assertFalse(fixture.start_count.exists())
            unresolved = fixture.trial / "runtime_stock_restart_unresolved"
            self.assertIn(
                "start_retry=forbidden", unresolved.read_text(encoding="utf-8")
            )
            self.assertTrue(fixture.active.is_file())
            self.assertTrue(fixture.lock.is_dir())
            self.assertFalse(list((fixture.lock / "stock_restart_claim").glob(".owner.*")))
        finally:
            fixture.close()

    def test_committed_claim_zero_and_partial_scratch_resume_start_once(self) -> None:
        for variant in ("fault_claim_commit_zero", "fault_claim_commit_partial"):
            with self.subTest(variant=variant):
                fixture = StockRestartFixture(variant)
                try:
                    crashed = fixture.run()
                    self.assertEqual(crashed.returncode, 86, crashed.stderr)
                    self.assertFalse(fixture.start_count.exists())
                    scratches = list(
                        (fixture.lock / "stock_restart_claim").glob(".owner.*")
                    )
                    self.assertEqual(len(scratches), 1)
                    resumed = fixture.run()
                    self.assertEqual(resumed.returncode, 0, resumed.stderr)
                    repeated = fixture.run("prove")
                    self.assertEqual(repeated.returncode, 0, repeated.stderr)
                    self.assertEqual(
                        fixture.start_count.read_text(encoding="utf-8"), "start\n"
                    )
                    self.assertFalse(fixture.lock.exists())
                finally:
                    fixture.close()

    def test_stock_tree_and_terminal_publication_cutpoints_resume_without_replay(
        self,
    ) -> None:
        variants = (
            "fault_stock_tree_zero",
            "fault_stock_tree_partial",
            "fault_stock_tree_complete_prelink",
            "fault_stock_tree_postlink",
            "fault_watchdog_zero",
            "fault_watchdog_partial",
            "fault_watchdog_complete_prelink",
            "fault_watchdog_postlink",
            "fault_terminal_zero",
            "fault_terminal_partial",
            "fault_terminal_complete_prelink",
            "fault_terminal_postlink",
        )
        for variant in variants:
            with self.subTest(variant=variant):
                fixture = StockRestartFixture(variant)
                try:
                    crashed = fixture.run()
                    self.assertEqual(crashed.returncode, 86, crashed.stderr)
                    self.assertEqual(
                        fixture.start_count.read_text(encoding="utf-8"), "start\n"
                    )
                    resumed = fixture.run("prove")
                    self.assertEqual(resumed.returncode, 0, resumed.stderr)
                    repeated = fixture.run("prove")
                    self.assertEqual(repeated.returncode, 0, repeated.stderr)
                    self.assertEqual(
                        fixture.start_count.read_text(encoding="utf-8"), "start\n"
                    )
                    self.assertFalse(fixture.lock.exists())
                    self.assertFalse(
                        list(fixture.trial.glob(".runtime_stock_restart_complete.*"))
                    )
                    claim_dir = fixture.lock / "stock_restart_claim"
                    self.assertFalse(list(claim_dir.glob(".stock_tree.*")))
                    self.assertFalse(list(claim_dir.glob(".watchdog_fds.*")))
                finally:
                    fixture.close()

    def test_preclaim_crashes_revalidate_and_resume_without_duplicate_start(
        self,
    ) -> None:
        for variant in (
            "fault_after_claim_mkdir",
            "fault_during_claim_scratch",
            "fault_after_claim_publish",
        ):
            with self.subTest(variant=variant):
                fixture = StockRestartFixture(variant)
                try:
                    crashed = fixture.run()
                    self.assertEqual(crashed.returncode, 86, crashed.stderr)
                    self.assertFalse(fixture.start_count.exists())
                    resumed = fixture.run()
                    self.assertEqual(resumed.returncode, 0, resumed.stderr)
                    self.assertEqual(
                        fixture.start_count.read_text(encoding="utf-8"), "start\n"
                    )
                    self.assertFalse(fixture.lock.exists())
                finally:
                    fixture.close()

    def test_invocation_owner_publication_crashes_resume_exactly_once(self) -> None:
        for variant in (
            "fault_after_invocation_scratch",
            "fault_after_invocation_link",
            "fault_after_invocation_scratch_remove",
        ):
            with self.subTest(variant=variant):
                fixture = StockRestartFixture(variant)
                try:
                    crashed = fixture.run()
                    self.assertEqual(crashed.returncode, 86, crashed.stderr)
                    self.assertFalse(fixture.start_count.exists())
                    resumed = fixture.run()
                    self.assertEqual(resumed.returncode, 0, resumed.stderr)
                    self.assertEqual(
                        fixture.start_count.read_text(encoding="utf-8"), "start\n"
                    )
                    self.assertFalse(fixture.lock.exists())
                    self.assertFalse((fixture.root / "restart-helper-lock").exists())
                finally:
                    fixture.close()

    def test_terminal_suffix_crashes_resume_without_second_start(self) -> None:
        for variant in (
            "fault_after_terminal",
            "fault_after_active_move",
            "fault_after_claim_remove",
            "fault_after_owner_remove",
        ):
            with self.subTest(variant=variant):
                fixture = StockRestartFixture(variant)
                try:
                    crashed = fixture.run()
                    self.assertEqual(crashed.returncode, 86, crashed.stderr)
                    self.assertEqual(
                        fixture.start_count.read_text(encoding="utf-8"), "start\n"
                    )
                    resumed = fixture.run("prove")
                    self.assertEqual(resumed.returncode, 0, resumed.stderr)
                    repeated = fixture.run("prove")
                    self.assertEqual(repeated.returncode, 0, repeated.stderr)
                    self.assertEqual(
                        fixture.start_count.read_text(encoding="utf-8"), "start\n"
                    )
                    self.assertFalse(fixture.active.exists())
                    self.assertFalse(fixture.lock.exists())
                    self.assertTrue(
                        (fixture.trial / "runtime_stock_restart_complete").is_file()
                    )
                finally:
                    fixture.close()
        for variant in ("fault_after_claim_remove", "fault_after_owner_remove"):
            with self.subTest(variant=f"{variant}-corrupt-terminal-log-tuple"):
                fixture = StockRestartFixture(variant)
                try:
                    crashed = fixture.run()
                    self.assertEqual(crashed.returncode, 86, crashed.stderr)
                    terminal = fixture.trial / "runtime_stock_restart_complete"
                    fixture._replace_field(terminal, "log_mount_id", "999999")
                    resumed = fixture.run("prove")
                    self.assertNotEqual(resumed.returncode, 0, resumed.stderr)
                    self.assertEqual(
                        fixture.start_count.read_text(encoding="utf-8"), "start\n"
                    )
                    self.assertTrue(terminal.is_file())
                    self.assertTrue(
                        (fixture.trial / "runtime_stock_restart_pending.consumed").is_file()
                    )
                finally:
                    fixture.close()


class S19kStockRestartStaticTests(unittest.TestCase):
    def test_runner_and_restart_helper_cover_every_live_deploy_mode(self) -> None:
        helper = HELPER_SOURCE.read_text(encoding="utf-8")
        runner = (SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh").read_text(
            encoding="utf-8"
        )
        live_modes = (
            "mining-on-passthrough|install-custody-safeoff|handoff-no-work|bounded-work-proof|"
            "endurance-work-proof"
        )
        self.assertIn(f"        {live_modes}) ;;", helper)
        self.assertIn(f"        {live_modes}) return 0 ;;", runner)
        self.assertIn(
            '[ "$(field "$RUNTIME_RECORD" persistent_mutation)" = false ]',
            helper,
        )

    def test_production_helper_has_one_start_and_no_destructive_fallback(self) -> None:
        source = HELPER_SOURCE.read_text(encoding="utf-8")
        executable = "\n".join(
            line for line in source.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertEqual(executable.count('"$S99" start'), 1)
        self.assertNotRegex(executable, r'"\$S99"\s+(stop|restart|reload)')
        self.assertNotRegex(executable, r"(?m)(^|[;&|\s])kill(?:\s|$)")
        self.assertNotIn("nandwrite", executable)
        self.assertNotIn("flash_erase", executable)
        self.assertNotRegex(executable, r">\s*/sys/class/gpio")
        self.assertNotRegex(executable, r"(?m)(^|[;&|\s])stat(?:\s|$)")
        self.assertNotRegex(executable, r"(?m)(^|[;&|\s])od(?:\s|$)")
        self.assertIn("write_claim start-invocation-committed", source)
        self.assertIn("start_retry=forbidden", source)
        self.assertIn("terminal-finalizer-only", source)
        self.assertIn("bounded stock recovery proof not reached", source)
        self.assertIn("PROC_REST=${PROC_STAT##*) }", source)
        self.assertNotIn("PROC_REST=${PROC_STAT#*) }", source)
        self.assertIn("dcentos.s19k-stock-restart-complete/v4", source)
        self.assertIn(
            "watchdog_fd_authority=bounded-all-tid-hardware-watchdog-absence",
            source,
        )
        self.assertIn(
            "terminal_live_revalidate() {\n"
            "    poststart_runtime_predicates \\\n"
            '        && [ -n "${TERMINAL_LOG_FILE:-}" ] \\\n'
            '        && build_watchdog_absence_evidence "$TERMINAL_LOG_FILE" || return 1\n',
            source,
        )
        self.assertIn("matching_watchdog_rdev_fd_count=0", source)
        self.assertIn("case \"$FD_WATCHDOG_RDEV\" in 10:130|249:0)", source)
        namespace_gate = (
            'case "$FD_TARGET" in\n'
            '                    "$WATCHDOG_NODE_ROOT"/*) ;;\n'
            '                    *) continue ;;\n'
            "                esac"
        )
        self.assertIn(namespace_gate, source)
        self.assertLess(
            source.index(namespace_gate),
            source.index('if fd_watchdog_rdev "$FD"; then'),
        )
        self.assertNotIn("case \"$FD_TARGET\" in /dev/watchdog*", source)
        for scratch in (
            '"$CLAIM_DIR/.owner.$SELF_PID.$SELF_START"',
            '"$CLAIM_DIR/.stock_tree.$SELF_PID.$SELF_START"',
            '"$CLAIM_DIR/.watchdog_fds.$SELF_PID.$SELF_START"',
            '"$TRIAL_DIR/.runtime_stock_restart_complete.$SELF_PID.$SELF_START"',
        ):
            self.assertIn(scratch, source)
        self.assertIn("dcentos.s19k-stock-restart-pending/v3", source)
        self.assertIn(
            "6d9cce12caa49249396b48296101b0fbbcc6456cb3fa09bdbe2858bdcba948c9",
            source,
        )
        self.assertIn('cd /\n        umask 0022\n        "$BUSYBOX" env -i', source)
        self.assertIn(
            "CONSOLE=/dev/console HOME=/ INIT_VERSION=sysvinit-2.9n", source
        )
        self.assertIn("expected-tmpfs-pidfile+stock-daemon-state+persistent-ubifs-", source)

    def test_helper_pins_both_pending_contracts_and_partial_handoff_absence(
        self,
    ) -> None:
        source = HELPER_SOURCE.read_text(encoding="utf-8")
        for marker in (
            "dcentos.s19k-stock-restart-pending/v3",
            "dcentos.s19k-stock-restart-pending/v4",
            "dcentos.s19k-track1-runtime-lock/v7",
            "dcentos.s19k-track1-runtime-lock/v8",
            "dcentos.s19k-receiptless-stock-restart-pending/v2",
            "dcentos.s19k-track1-runtime-lock/v9",
            "dcentos.s19k-terminal-safeoff-partial-stock-owner/v1",
            "dcentos.s19k-install-custody-stock-restart-pending/v1",
            "dcentos.s19k-install-custody-safeoff/v1",
            "dcentos.s19k-install-custody-terminal-safeoff/v1",
            "dcentos.s19k-startup-prefix-stock-restart-pending/v1",
            "dcentos.s19k-startup-prefix-safeoff-source/v1",
            "dcentos.s19k-track1-runtime-lock/v10",
            "admit_runtime_active_v5_at",
            '"$TG_DIR"/task/[0-9]*',
            "dcentos.s19k-stock-restart-helper-owner/v1",
            'global_stock_absence)" = true',
            'replacement_or_ambiguity)" = false',
            'supervisor_remnant)" = absent',
            'child_remnant)" = absent',
        ):
            self.assertIn(marker, source)

    def test_install_custody_restart_accepts_gpio437_without_reset_claims(self) -> None:
        source = HELPER_SOURCE.read_text(encoding="utf-8")
        self.assertIn("PENDING_VERSION=install-custody", source)
        self.assertIn(
            '[ "$(field "$PENDING_RECORD" resets)" = not-attempted ]', source
        )
        self.assertIn(
            '[ "$(field "$PENDING_RECORD" gpio_raw)" = 437:1 ]', source
        )
        gpio_gate = source[
            source.index("pending_gpio_safeoff_is_exact() {") : source.index(
                "prestart_core_predicates() {"
            )
        ]
        self.assertIn('[ "$(capture_gpio437)" = 437:1 ]', gpio_gate)
        install_leg = gpio_gate.split(
            'if [ "$PENDING_VERSION" = install-custody ]; then', 1
        )[1].split("else", 1)[0]
        self.assertNotIn("capture_gpio)", install_leg)
        self.assertNotRegex(install_leg, r"454|455|456")
        self.assertIn(
            '[ "$PENDING_GPIO" = 437:1,454:0,455:0,456:0 ]', gpio_gate
        )
        self.assertNotRegex(source, r"(?m)^\s*(?:echo\s+)?(?:kill|pkill|killall)\b")
        self.assertEqual(
            "\n".join(
                line
                for line in source.splitlines()
                if not line.lstrip().startswith("#")
            ).count('"$S99" start'),
            1,
        )


if __name__ == "__main__":
    unittest.main()
