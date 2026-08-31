#!/usr/bin/env python3
"""Bench-side UART console logger for the BB SD boot-loop diagnosis.

Campaign s19j-pro-complete-enablement-20260826, phase bb-sd-coldboot-diagnosis.

This is a LOCAL serial-port logger only. It opens one operator-named COM port,
streams bytes at 115200 8N1, and writes timestamped lines into the phase
evidence directory. It contacts no miner over the network, touches no GPIO,
flashes nothing, and grants no authority: running it at the bench is itself a
live-hardware action that requires the operator's fresh exact authorization
per the campaign contact policy and the workspace Live-Hardware Safety rule.

Usage (at the bench, after operator authorization):
    py -3 bb_uart_console_capture.py --port COM7 \
        --evidence-dir <repo>/.s19jpro-enablement-evidence/bb-sd-coldboot-diagnosis \
        --label sd-inserted-cold-boot

One run = one capture file under serial-capture/ named
<utc-ts>-<label>.txt. Keep the logger running across the full power-on ->
loop cycles (capture at least 3 loop periods, ~30 s) and across the
SD-removed control boot if performed in the same session.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

try:
    import serial
except ImportError:  # pragma: no cover - bench host dependency
    print("pyserial is required: pip install pyserial", file=sys.stderr)
    raise SystemExit(2)

BAUD = 115_200
TIMEOUT_S = 0.2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default=None, help="operator-named COM port (e.g. COM7)")
    parser.add_argument("--evidence-dir", type=Path, default=None)
    parser.add_argument("--label", default="capture")
    parser.add_argument(
        "--list-ports", action="store_true", help="list candidate serial ports and exit"
    )
    args = parser.parse_args(argv)

    if args.list_ports:
        from serial.tools import list_ports

        for port in list_ports.comports():
            print(f"{port.device}\t{port.description}\t{port.hwid}")
        return 0

    if not args.port or args.evidence_dir is None:
        parser.error("--port and --evidence-dir are required to capture")

    capture_dir = args.evidence_dir / "serial-capture"
    capture_dir.mkdir(parents=True, exist_ok=True)
    stamp = (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
        .replace(":", "")
    )
    out_path = capture_dir / f"{stamp}-{args.label}.txt"

    header = [
        f"# bb-sd-coldboot-diagnosis UART console capture",
        f"# port={args.port} baud={BAUD} 8N1",
        f"# started_utc={stamp} label={args.label}",
        f"# BB debug header: GND + board TX only; NEVER connect the 3.3V pin.",
        f"# Stop with Ctrl-C after >= 3 loop periods (~30 s) or the control boot.",
    ]
    print("\n".join(header))
    with (
        serial.Serial(
            port=args.port,
            baudrate=BAUD,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=TIMEOUT_S,
        ) as con,
        out_path.open("wb") as out,
    ):
        out.write(("\n".join(header) + "\n").encode("utf-8"))
        out.flush()
        print(f"capturing -> {out_path} (Ctrl-C to stop)")
        while True:
            try:
                chunk = con.read(4096)
            except KeyboardInterrupt:
                break
            if not chunk:
                continue
            stamp_line = (
                dt.datetime.now(dt.timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )
            out.write(f"[{stamp_line}] ".encode("utf-8") + chunk + b"\n")
            out.flush()
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
    print(f"\nwrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
