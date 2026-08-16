//! Braiins Track-1 mining-off wire try executor.
//!
//! Enable (Bench GO — CURRENT stays false):
//! ```text
//! export DCENT_BRAIINS_TTYS_BENCH_GO=1
//! # OR
//! touch /etc/dcentos/braiins_ttys_bench_go
//! ```
//! Optional legacy: `DCENT_S19K_BRAIINS_WIRE_TRY=1` (still requires Bench GO admit).
//!
//! On am3-s19k with mining.enabled=false, after
//! `admit_s19k_bm1366_wire_runtime_try(current_with_runtime_bench_go(), BraiinsRawTtyS, …)`
//! opens `/dev/ttyS1` then `/dev/ttyS2` @ 3 Mbaud and writes CLOSED set_address
//! frames (interval=2). No GPIO437 write, no uart_trans mmap, no job frames, no mining.
//!
//! Unix-only I/O. Host tests cover admit/plan in dcentrald-common.

use std::path::Path;
use std::time::Duration;

use tracing::{info, warn};

use crate::config::DcentraldConfig;
use crate::daemon_lifecycle::PlatformIdentitySnapshot;
use dcentrald_common::s19k_bm1366_wire_b::{
    braiins_ttys_bench_go_from_runtime, current_with_runtime_bench_go, S19kWireDeskPending,
};
use dcentrald_common::s19k_braiins_wire_try::{
    admit_braiins_mining_off_wire_try, env_requests_wire_try, parse_gpio437_sysfs,
    planned_set_address_frames, BraiinsWireTryPlan, BraiinsWireTryRequest, ENV_BRAIINS_WIRE_TRY,
    GPIO437_SYSFS_VALUE,
};
use dcentrald_common::s19k_uart_trans_job::UART_TRANS_PATH;

/// Run the mining-off probe when runtime Bench GO is set (or legacy wire-try env).
/// Fail-closed on admit; port-open/write errors are logged per tty and do
/// not abort the daemon (API stay-up). Never claims mining-achieved.
pub fn maybe_run_s19k_braiins_wire_try(
    identity: &PlatformIdentitySnapshot,
    config: &DcentraldConfig,
) {
    let env_raw = std::env::var(ENV_BRAIINS_WIRE_TRY).ok();
    let runtime_bench_go = braiins_ttys_bench_go_from_runtime();
    let legacy = env_requests_wire_try(env_raw.as_deref());
    // Lead Bench GO is mandatory for admit/open/TX. Legacy env alone is not enough.
    if !runtime_bench_go {
        if legacy {
            warn!(
                "S19K_BRAIINS_WIRE_TRY set but DCENT_BRAIINS_TTYS_BENCH_GO/file unset — refuse (CURRENT stays false)"
            );
        }
        return;
    }

    // Prove CURRENT is untouched; admit uses runtime snapshot only.
    debug_assert!(!S19kWireDeskPending::CURRENT.braiins_ttys_bench_go);
    let runtime_pending = current_with_runtime_bench_go();
    if runtime_pending.braiins_ttys_bench_go != runtime_bench_go {
        warn!("S19K_BRAIINS_WIRE_TRY: runtime pending bench_go mismatch; refuse");
        return;
    }

    let gpio437_value = read_gpio437_value();
    let req = BraiinsWireTryRequest {
        env_raw: env_raw.as_deref(),
        mining_enabled: config.mining.enabled,
        board_target: identity.board_target(),
        gpio437_value,
        uart_trans_present: Path::new(UART_TRANS_PATH).exists(),
        runtime_bench_go,
    };

    let plan = match admit_braiins_mining_off_wire_try(req) {
        Ok(plan) => plan,
        Err(err) => {
            warn!(
                error = %err,
                gpio437 = ?gpio437_value,
                runtime_bench_go,
                current_bench_go = S19kWireDeskPending::CURRENT.braiins_ttys_bench_go,
                "S19K_BRAIINS_WIRE_TRY refused (fail-closed; no tty open)"
            );
            return;
        }
    };

    info!(
        paths = ?plan.paths,
        baud = plan.baud,
        addr_interval = plan.addr_interval,
        set_address_count = plan.set_address_count,
        send_job_frames = plan.send_job_frames,
        write_gpio437 = plan.write_gpio437,
        gpio437 = ?gpio437_value,
        gpio437_not_low_warning = plan.gpio437_not_low_warning,
        runtime_bench_go,
        current_bench_go = S19kWireDeskPending::CURRENT.braiins_ttys_bench_go,
        "S19K_BRAIINS_WIRE_TRY admitted (mining-off raw ttyS; CURRENT.braiins_ttys_bench_go stays false)"
    );

    execute_plan(&plan);
}

fn read_gpio437_value() -> Option<u8> {
    let raw = std::fs::read_to_string(GPIO437_SYSFS_VALUE).ok()?;
    parse_gpio437_sysfs(&raw).ok()
}

fn execute_plan(plan: &BraiinsWireTryPlan) {
    #[cfg(unix)]
    {
        execute_plan_unix(plan);
    }
    #[cfg(not(unix))]
    {
        warn!(
            paths = ?plan.paths,
            "S19K_BRAIINS_WIRE_TRY: plan admitted but this host is not unix; no tty open"
        );
    }
}

#[cfg(unix)]
fn execute_plan_unix(plan: &BraiinsWireTryPlan) {
    use dcentrald_hal::serial::SerialChain;

    let frames = planned_set_address_frames();
    debug_assert_eq!(frames.len(), plan.set_address_count);

    for path in plan.paths {
        // Discover-on-bench: try each candidate; never invent success.
        if !Path::new(path).exists() {
            warn!(path, "S19K_BRAIINS_WIRE_TRY: candidate missing; skip");
            continue;
        }
        match SerialChain::open(path, plan.baud) {
            Ok(mut port) => {
                if let Err(err) = port.flush_io() {
                    warn!(path, error = %err, "S19K_BRAIINS_WIRE_TRY: flush before TX failed");
                }
                let mut tx = 0usize;
                for frame in &frames {
                    if let Err(err) = port.write_bytes(frame) {
                        warn!(
                            path,
                            tx,
                            error = %err,
                            "S19K_BRAIINS_WIRE_TRY: set_address write failed; stop this port"
                        );
                        break;
                    }
                    tx += 1;
                    let _ = port.flush();
                    std::thread::sleep(Duration::from_millis(1));
                }
                let mut rx_total = 0usize;
                let mut rx_sample = [0u8; 64];
                let mut sample_len = 0usize;
                let mut buf = [0u8; 256];
                for _ in 0..4 {
                    match port.read_bytes(&mut buf) {
                        Ok(0) => {}
                        Ok(n) => {
                            if sample_len < rx_sample.len() {
                                let take = (rx_sample.len() - sample_len).min(n);
                                rx_sample[sample_len..sample_len + take]
                                    .copy_from_slice(&buf[..take]);
                                sample_len += take;
                            }
                            rx_total += n;
                        }
                        Err(err) => {
                            warn!(path, error = %err, "S19K_BRAIINS_WIRE_TRY: RX read error");
                            break;
                        }
                    }
                }
                let rx_hex = hex_preview(&rx_sample[..sample_len]);
                info!(
                    path,
                    exclusive_open = true,
                    tx_set_address = tx,
                    rx_bytes = rx_total,
                    rx_hex = %rx_hex,
                    "S19K_BRAIINS_WIRE_TRY port done (no mining claim; GPIO437 unread-for-write)"
                );
            }
            Err(err) => {
                warn!(
                    path,
                    error = %err,
                    "S19K_BRAIINS_WIRE_TRY: exclusive open failed (bosminer still holding?)"
                );
            }
        }
    }
}

fn hex_preview(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::from("-");
    }
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::hex_preview;
    use dcentrald_common::s19k_bm1366_wire_b::S19kWireDeskPending;
    use dcentrald_common::s19k_braiins_wire_try::{
        admit_braiins_mining_off_wire_try, BraiinsWireTryRequest, ENV_BRAIINS_WIRE_TRY,
    };

    #[test]
    fn env_name_is_stable_and_admit_needs_runtime_bench_go() {
        assert_eq!(ENV_BRAIINS_WIRE_TRY, "DCENT_S19K_BRAIINS_WIRE_TRY");
        assert_eq!(hex_preview(&[]), "-");
        assert_eq!(hex_preview(&[0x55, 0xaa]), "55 aa");
        assert!(!S19kWireDeskPending::CURRENT.braiins_ttys_bench_go);
        assert!(admit_braiins_mining_off_wire_try(BraiinsWireTryRequest {
            env_raw: Some("1"),
            mining_enabled: false,
            board_target: "am3-s19k",
            gpio437_value: Some(0),
            uart_trans_present: false,
            runtime_bench_go: false,
        })
        .is_err());
        let plan = admit_braiins_mining_off_wire_try(BraiinsWireTryRequest {
            env_raw: Some("1"),
            mining_enabled: false,
            board_target: "am3-s19k",
            gpio437_value: Some(0),
            uart_trans_present: false,
            runtime_bench_go: true,
        })
        .unwrap();
        assert!(!plan.send_job_frames);
        assert!(!plan.write_gpio437);
        assert!(!S19kWireDeskPending::CURRENT.braiins_ttys_bench_go);
    }
}
