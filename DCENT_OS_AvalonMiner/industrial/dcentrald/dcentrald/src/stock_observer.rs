// SPDX-License-Identifier: GPL-3.0-or-later
//
// Nano 3 stock-coexistence proof.
//
// This path executes before config loading, Stratum setup, SysV message-queue
// creation, or AvalonShimDriver construction. It only reads procfs, the
// device-tree identity, and DCENT's immutable rootfs marker. It deliberately
// does not open /dev/ttyS1 or any GPIO, timer, watchdog, thermal, display, or
// networking endpoint owned by the factory btcminer process.

use anyhow::{ensure, Context, Result};
use std::fs;
use std::path::Path;
use tracing::info;

const RUNTIME_MODE_PATH: &str = "/etc/dcentos/runtime-mode";
const STOCK_CHAIN_DEVICE: &str = "/dev/ttyS1";

pub fn run_once() -> Result<()> {
    let compatible =
        fs::read("/proc/device-tree/compatible").context("reading /proc/device-tree/compatible")?;
    ensure!(
        compatible_is_k230(&compatible),
        "stock observer requires a K230-compatible device tree"
    );

    let cmdline = fs::read_to_string("/proc/cmdline").context("reading /proc/cmdline")?;
    ensure!(
        cmdline_has_nano3_rootfs(&cmdline),
        "stock observer requires the evidenced Nano 3 ubi.mtd=8 boot contract"
    );

    let runtime_mode =
        fs::read_to_string(RUNTIME_MODE_PATH).context("reading DCENT runtime-mode marker")?;
    ensure!(
        runtime_mode_is_passive(&runtime_mode),
        "runtime-mode does not assert stock-coexistence with DCENT autostart disabled"
    );

    ensure!(
        Path::new(STOCK_CHAIN_DEVICE).exists(),
        "evidenced Nano 3 chain device {STOCK_CHAIN_DEVICE} is absent"
    );

    let btcminer_pid = find_process_by_comm("btcminer")?
        .ok_or_else(|| anyhow::anyhow!("btcminer is not running"))?;

    info!(
        observer_schema = 1,
        dcentrald_version = env!("CARGO_PKG_VERSION"),
        stock_owner = "btcminer",
        btcminer_pid,
        stock_chain_device = STOCK_CHAIN_DEVICE,
        hardware_access = "none",
        network_access = "none",
        ipc_access = "none",
        "Nano 3 stock-coexistence observation passed"
    );
    Ok(())
}

fn find_process_by_comm(wanted: &str) -> Result<Option<u32>> {
    for entry in fs::read_dir("/proc").context("scanning /proc")? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let Some(pid) = numeric_pid(&entry.file_name().to_string_lossy()) else {
            continue;
        };
        let comm = match fs::read_to_string(entry.path().join("comm")) {
            Ok(comm) => comm,
            Err(_) => continue,
        };
        if comm.trim() == wanted {
            return Ok(Some(pid));
        }
    }
    Ok(None)
}

fn numeric_pid(raw: &str) -> Option<u32> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

fn compatible_is_k230(raw: &[u8]) -> bool {
    raw.split(|byte| *byte == 0)
        .filter_map(|token| std::str::from_utf8(token).ok())
        .any(|token| token.eq_ignore_ascii_case("kendryte,k230"))
}

fn cmdline_has_nano3_rootfs(raw: &str) -> bool {
    raw.split_ascii_whitespace()
        .any(|token| token == "ubi.mtd=8")
}

fn runtime_mode_is_passive(raw: &str) -> bool {
    let has = |expected: &str| raw.lines().any(|line| line.trim() == expected);
    has("profile=stock-coexistence") && has("dcentrald_autostart=0") && has("stock_owner=btcminer")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatible_requires_exact_k230_token() {
        assert!(compatible_is_k230(b"kendryte,k230\0"));
        assert!(compatible_is_k230(b"vendor,board\0KENDRYTE,K230\0"));
        assert!(!compatible_is_k230(b"kendryte,k230d-not-the-same-token\0"));
    }

    #[test]
    fn cmdline_requires_exact_evidenced_rootfs_index() {
        assert!(cmdline_has_nano3_rootfs(
            "ubi.mtd=8 rootfstype=ubifs root=ubi0_0"
        ));
        assert!(!cmdline_has_nano3_rootfs("ubi.mtd=9 root=ubi0_0"));
        assert!(!cmdline_has_nano3_rootfs("foo=ubi.mtd=8 root=ubi0_0"));
    }

    #[test]
    fn runtime_marker_must_keep_stock_as_owner() {
        let good = "profile=stock-coexistence\ndcentrald_autostart=0\nstock_owner=btcminer\n";
        assert!(runtime_mode_is_passive(good));
        assert!(!runtime_mode_is_passive(
            "profile=stock-coexistence\ndcentrald_autostart=1\nstock_owner=btcminer\n"
        ));
        assert!(!runtime_mode_is_passive(
            "profile=stock-coexistence\ndcentrald_autostart=0\nstock_owner=dcentrald\n"
        ));
    }

    #[test]
    fn proc_pid_names_are_strictly_numeric() {
        assert_eq!(numeric_pid("169"), Some(169));
        assert_eq!(numeric_pid(""), None);
        assert_eq!(numeric_pid("self"), None);
        assert_eq!(numeric_pid("169x"), None);
    }
}
