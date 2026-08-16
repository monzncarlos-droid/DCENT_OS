//! S19k Braiins Track-1 mining-off wire try — host-testable admit + plan.
//!
//! Wire CLEAR_BRAIINS_TTY + Lead Bench GO authorize a **diagnostic** that:
//! - opens raw `/dev/ttyS1`, `/dev/ttyS2`, and `/dev/ttyS3` @ 3_000_000 8N1
//! - writes full userspace `set_address` frames (`55 AA 40 05 <addr> 00 <crc5>`)
//!   at AML interval **2** (desk 11g)
//! - never uses `/dev/ttyS0`, never loads `/dev/uart_trans`, never writes GPIO437
//! - never enables mining / rails / open-core / job dispatch
//!
//! [`S19kWireDeskPending::CURRENT.braiins_ttys_bench_go`] stays **false**.
//! Live open/TX is gated by
//! [`admit_s19k_bm1366_wire_runtime_try`]`(current_with_runtime_bench_go(), BraiinsRawTtyS, …)`
//! so Bench GO comes from env `DCENT_BRAIINS_TTYS_BENCH_GO=1` or file
//! `/etc/dcentos/braiins_ttys_bench_go` (see [`braiins_ttys_bench_go_from_runtime`]).
//! Optional legacy opt-in [`ENV_BRAIINS_WIRE_TRY`] still required by the daemon
//! executor unless Bench GO alone is used as the run trigger.
//!
//! board#↔ttyS mapping is discover-on-bench (do not hardcode board2=ttyS1).

use crate::s19k_bm1366_nopic_beta::S19K_AM3_BOARD_TARGET;
use crate::s19k_bm1366_wire_b::{
    admit_s19k_bm1366_wire_runtime_try, pack_set_address_uart_trans, s19k_aml_linear_addresses,
    S19K_AML_ADDR_INTERVAL, S19K_WIRE_MIDSTATE_NUMBER, S19kTrack1TransportKind,
    S19kWireDeskPending, S19kWireRuntimeTryError,
};
use crate::s19k_uart_trans_job::{
    admit_braiins_job_tx_path, BRAIINS_RAW_TTYS_PINS, BRAIINS_TTYS_BAUD, BRAIINS_TTYS_DISCOVER,
};

/// Legacy explicit diagnostic opt-in (daemon may still honor). Exact token `1`.
pub const ENV_BRAIINS_WIRE_TRY: &str = "DCENT_S19K_BRAIINS_WIRE_TRY";
pub const ENV_BRAIINS_WIRE_TRY_TOKEN: &str = "1";

/// Sysfs path we **read** only (never export, never write).
pub const GPIO437_SYSFS_VALUE: &str = "/sys/class/gpio/gpio437/value";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BraiinsWireTryRequest<'a> {
    pub env_raw: Option<&'a str>,
    pub mining_enabled: bool,
    pub board_target: &'a str,
    /// `Some(v)` when sysfs is readable; `None` if the node is not exported.
    pub gpio437_value: Option<u8>,
    pub uart_trans_present: bool,
    /// From [`crate::s19k_bm1366_wire_b::current_with_runtime_bench_go`] —
    /// must be true for runtime-try admit (CURRENT stays false).
    pub runtime_bench_go: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BraiinsWireTryPlan {
    pub paths: &'static [&'static str],
    pub baud: u32,
    pub addr_interval: u8,
    pub set_address_count: usize,
    pub write_full_wire_frame: bool,
    pub send_job_frames: bool,
    pub write_gpio437: bool,
    /// Sysfs observation only. am3-s19k: 0=engaged, 1=cooldown (T6).
    /// `gpio437_not_low_warning` stays named for existing tests: it is true
    /// when value==1 (rails down / S99 stop). That is expected after a
    /// clean stop, not a polarity inversion.
    pub gpio437_observed: Option<u8>,
    pub gpio437_not_low_warning: bool,
}

/// Per-path open/TX outcome (never invent success).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraiinsTtyWirePathReport {
    pub path: String,
    pub opened: bool,
    pub tx_set_address: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraiinsTtyWireTryReport {
    pub admitted: bool,
    pub runtime_bench_go: bool,
    pub current_bench_go_still_false: bool,
    pub paths: Vec<BraiinsTtyWirePathReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BraiinsWireTryAdmitError {
    EnvNotSet,
    EnvTokenMustBeExactlyOne { observed: String },
    MiningMustStayOff,
    BoardTargetMismatch { observed: String },
    UartTransPresentUseTrack2,
    RuntimeTryRefused(S19kWireRuntimeTryError),
    MiningAchievedClaimForbidden,
}

impl core::fmt::Display for BraiinsWireTryAdmitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EnvNotSet => write!(
                f,
                "S19k Braiins wire try: {ENV_BRAIINS_WIRE_TRY} not set (need ={ENV_BRAIINS_WIRE_TRY_TOKEN}) and/or runtime Bench GO unset"
            ),
            Self::EnvTokenMustBeExactlyOne { observed } => write!(
                f,
                "S19k Braiins wire try: {ENV_BRAIINS_WIRE_TRY} must be exactly {ENV_BRAIINS_WIRE_TRY_TOKEN:?}, got {observed:?}"
            ),
            Self::MiningMustStayOff => {
                write!(f, "S19k Braiins wire try: mining.enabled must stay false")
            }
            Self::BoardTargetMismatch { observed } => write!(
                f,
                "S19k Braiins wire try: board_target {observed:?} is not {S19K_AM3_BOARD_TARGET}"
            ),
            Self::UartTransPresentUseTrack2 => write!(
                f,
                "S19k Braiins wire try: /dev/uart_trans present — refuse raw ttyS (Track 2 / stock path)"
            ),
            Self::RuntimeTryRefused(e) => write!(
                f,
                "S19k Braiins wire try: admit_s19k_bm1366_wire_runtime_try refused ({e:?}) — need DCENT_BRAIINS_TTYS_BENCH_GO=1 or /etc/dcentos/braiins_ttys_bench_go"
            ),
            Self::MiningAchievedClaimForbidden => write!(
                f,
                "S19k Braiins wire try: refuse mining-achieved claim"
            ),
        }
    }
}

/// True only for the exact opt-in token `1` (after trim).
pub fn env_requests_wire_try(raw: Option<&str>) -> bool {
    raw.map(str::trim) == Some(ENV_BRAIINS_WIRE_TRY_TOKEN)
}

/// Parse GPIO437 sysfs text (`"0\n"`). Empty / non-0-1 is an error.
pub fn parse_gpio437_sysfs(raw: &str) -> Result<u8, &'static str> {
    match raw.trim() {
        "0" => Ok(0),
        "1" => Ok(1),
        _ => Err("GPIO437 sysfs value must be 0 or 1"),
    }
}

/// Planned on-wire set_address frames for AML interval=2 (77 chips).
pub fn planned_set_address_frames() -> Vec<[u8; 7]> {
    s19k_aml_linear_addresses()
        .into_iter()
        .map(pack_set_address_uart_trans)
        .collect()
}

/// Build the pending snapshot used for live Braiins admit (CURRENT + runtime GO bit).
pub fn pending_for_braiins_live_admit(runtime_bench_go: bool) -> S19kWireDeskPending {
    let mut p = S19kWireDeskPending::CURRENT;
    p.braiins_ttys_bench_go = runtime_bench_go;
    p
}

/// Fail-closed admit for the mining-off Braiins raw-tty probe.
///
/// Does **not** flip [`S19kWireDeskPending::CURRENT`]. Requires
/// `req.runtime_bench_go` so [`admit_s19k_bm1366_wire_runtime_try`] can Ok
/// under BraiinsRawTtyS while CURRENT stays false.
pub fn admit_braiins_mining_off_wire_try(
    req: BraiinsWireTryRequest<'_>,
) -> Result<BraiinsWireTryPlan, BraiinsWireTryAdmitError> {
    // Legacy env token: if provided and non-empty, must be exact "1".
    // Empty/None is allowed when runtime_bench_go alone is the trigger.
    match req.env_raw.map(str::trim) {
        None | Some("") => {}
        Some(ENV_BRAIINS_WIRE_TRY_TOKEN) => {}
        Some(other) => {
            return Err(BraiinsWireTryAdmitError::EnvTokenMustBeExactlyOne {
                observed: other.to_string(),
            });
        }
    }
    if req.mining_enabled {
        return Err(BraiinsWireTryAdmitError::MiningMustStayOff);
    }
    if req.board_target.trim() != S19K_AM3_BOARD_TARGET {
        return Err(BraiinsWireTryAdmitError::BoardTargetMismatch {
            observed: req.board_target.to_string(),
        });
    }
    // Read-only. Do not refuse wire-try on 1: mining-off after S99 stop
    // leaves am3-s19k GPIO437=1 (OFF). Polarity is board-scoped CLOSED
    // (0=ON, 1=OFF). We still never write GPIO437.
    if req.uart_trans_present {
        return Err(BraiinsWireTryAdmitError::UartTransPresentUseTrack2);
    }

    // Hard gate: runtime Bench GO via admit (CURRENT remains false).
    let pending = pending_for_braiins_live_admit(req.runtime_bench_go);
    debug_assert!(!S19kWireDeskPending::CURRENT.braiins_ttys_bench_go);
    admit_s19k_bm1366_wire_runtime_try(
        pending,
        S19kTrack1TransportKind::BraiinsRawTtyS,
        S19K_WIRE_MIDSTATE_NUMBER,
        false,
        false,
    )
    .map_err(BraiinsWireTryAdmitError::RuntimeTryRefused)?;

    for path in BRAIINS_TTYS_DISCOVER {
        admit_braiins_job_tx_path(path).expect("Wire CLEAR discover ports must admit");
    }
    let addrs = s19k_aml_linear_addresses();
    Ok(BraiinsWireTryPlan {
        paths: BRAIINS_TTYS_DISCOVER,
        baud: BRAIINS_TTYS_BAUD,
        addr_interval: S19K_AML_ADDR_INTERVAL,
        set_address_count: addrs.len(),
        write_full_wire_frame: BRAIINS_RAW_TTYS_PINS.write_full_wire_frame,
        send_job_frames: false,
        write_gpio437: false,
        gpio437_observed: req.gpio437_value,
        gpio437_not_low_warning: req.gpio437_value == Some(1),
    })
}

/// Gate-only host helper: mining-off + runtime Bench GO admit, no I/O.
pub fn braiins_ttys_mining_off_wire_try_admit(
    mining_enabled: bool,
    board_target: &str,
    runtime_bench_go: bool,
) -> Result<BraiinsWireTryPlan, BraiinsWireTryAdmitError> {
    admit_braiins_mining_off_wire_try(BraiinsWireTryRequest {
        env_raw: None,
        mining_enabled,
        board_target,
        gpio437_value: None,
        uart_trans_present: false,
        runtime_bench_go,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s19k_bm1366_wire_b::{
        braiins_ttys_bench_go_from_runtime_parts, current_with_runtime_bench_go,
    };
    use crate::s19k_uart_trans_job::admit_job_tx_path;

    fn ok_req() -> BraiinsWireTryRequest<'static> {
        BraiinsWireTryRequest {
            env_raw: Some("1"),
            mining_enabled: false,
            board_target: "am3-s19k",
            gpio437_value: Some(0),
            uart_trans_present: false,
            runtime_bench_go: true,
        }
    }

    #[test]
    fn env_token_is_exact_one_only() {
        assert!(env_requests_wire_try(Some("1")));
        assert!(env_requests_wire_try(Some(" 1 \n")));
        assert!(!env_requests_wire_try(None));
        assert!(!env_requests_wire_try(Some("true")));
        assert!(!env_requests_wire_try(Some("yes")));
        assert!(!env_requests_wire_try(Some("TRUE")));
        assert!(!env_requests_wire_try(Some("")));
    }

    #[test]
    fn admit_happy_path_plans_ttys1_s2_3m_interval2_no_jobs_no_gpio_write() {
        let plan = admit_braiins_mining_off_wire_try(ok_req()).expect("admit");
        assert_eq!(plan.paths, &["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"]);
        assert_eq!(plan.baud, 3_000_000);
        assert_eq!(plan.addr_interval, 2);
        assert_eq!(plan.set_address_count, 77);
        assert!(plan.write_full_wire_frame);
        assert!(!plan.send_job_frames);
        assert!(!plan.write_gpio437);
        assert_eq!(plan.gpio437_observed, Some(0));
        assert!(!plan.gpio437_not_low_warning);
        assert!(!plan.paths.contains(&"/dev/ttyS0"));
        assert!(plan.paths.contains(&"/dev/ttyS3"));
    }

    #[test]
    fn admit_refuses_without_runtime_bench_go() {
        let mut req = ok_req();
        req.runtime_bench_go = false;
        assert!(matches!(
            admit_braiins_mining_off_wire_try(req),
            Err(BraiinsWireTryAdmitError::RuntimeTryRefused(
                S19kWireRuntimeTryError::BraiinsTtyBenchGoRequired
            ))
        ));
        // CURRENT stays false
        assert!(!S19kWireDeskPending::CURRENT.braiins_ttys_bench_go);
    }

    #[test]
    fn admit_refuses_wrong_legacy_env_token() {
        let mut req = ok_req();
        req.env_raw = Some("true");
        assert!(matches!(
            admit_braiins_mining_off_wire_try(req),
            Err(BraiinsWireTryAdmitError::EnvTokenMustBeExactlyOne { .. })
        ));
    }

    #[test]
    fn admit_refuses_mining_on_wrong_target_uart_trans() {
        let mut req = ok_req();
        req.mining_enabled = true;
        assert!(matches!(
            admit_braiins_mining_off_wire_try(req),
            Err(BraiinsWireTryAdmitError::MiningMustStayOff)
        ));
        req = ok_req();
        req.board_target = "am3-aml-s21";
        assert!(matches!(
            admit_braiins_mining_off_wire_try(req),
            Err(BraiinsWireTryAdmitError::BoardTargetMismatch { .. })
        ));
        req = ok_req();
        req.uart_trans_present = true;
        assert!(matches!(
            admit_braiins_mining_off_wire_try(req),
            Err(BraiinsWireTryAdmitError::UartTransPresentUseTrack2)
        ));
        req = ok_req();
        let plan = admit_braiins_mining_off_wire_try(req).expect("happy");
        assert!(!plan.paths.contains(&"/dev/ttyS0"));
        assert!(plan.paths.contains(&"/dev/ttyS3"));
        let sh = include_str!("../../../scripts/s19k_braiins_wire_try.sh");
        assert!(sh.contains("probe /dev/ttyS3"));
        assert!(!sh.contains("probe /dev/ttyS0"));
    }

    #[test]
    fn gpio437_high_is_warning_not_refuse_we_still_do_not_write() {
        // Live 2026-08-12: S99bosminer stop left sysfs=1 (am3-s19k OFF).
        let mut req = ok_req();
        req.gpio437_value = Some(1);
        let plan = admit_braiins_mining_off_wire_try(req).expect("observe-only");
        assert!(!plan.write_gpio437);
        assert_eq!(plan.gpio437_observed, Some(1));
        assert!(plan.gpio437_not_low_warning);
    }

    #[test]
    fn unexported_gpio437_does_not_block_when_we_will_not_write() {
        let mut req = ok_req();
        req.gpio437_value = None;
        assert!(admit_braiins_mining_off_wire_try(req).is_ok());
    }

    #[test]
    fn planned_frames_match_desk_11g_interval2() {
        let frames = planned_set_address_frames();
        assert_eq!(frames.len(), 77);
        assert_eq!(frames[0], [0x55, 0xAA, 0x40, 0x05, 0x00, 0x00, 0x1c]);
        assert_eq!(frames[1], [0x55, 0xAA, 0x40, 0x05, 0x02, 0x00, 0x01]);
        assert_eq!(frames[76], pack_set_address_uart_trans(152));
        assert_eq!(parse_gpio437_sysfs("0\n"), Ok(0));
        assert_eq!(parse_gpio437_sysfs("1"), Ok(1));
        assert!(parse_gpio437_sysfs("2").is_err());
    }

    #[test]
    fn wire_try_admit_does_not_flip_current_engine_gate() {
        assert!(!S19kWireDeskPending::CURRENT.braiins_ttys_bench_go);
        assert!(S19kWireDeskPending::CURRENT.uart_trans_runtime_unowned);
        assert!(matches!(
            admit_s19k_bm1366_wire_runtime_try(
                S19kWireDeskPending::CURRENT,
                S19kTrack1TransportKind::BraiinsRawTtyS,
                8,
                false,
                false,
            ),
            Err(S19kWireRuntimeTryError::BraiinsTtyBenchGoRequired)
        ));
        assert!(admit_job_tx_path("/dev/ttyS1").is_err());
        assert!(admit_braiins_job_tx_path("/dev/ttyS1").is_ok());
        assert!(admit_braiins_mining_off_wire_try(ok_req()).is_ok());
        assert!(!S19kWireDeskPending::CURRENT.braiins_ttys_bench_go);
        // Gate-only helper
        assert!(braiins_ttys_mining_off_wire_try_admit(false, "am3-s19k", true).is_ok());
        assert!(braiins_ttys_mining_off_wire_try_admit(false, "am3-s19k", false).is_err());
        assert!(braiins_ttys_mining_off_wire_try_admit(true, "am3-s19k", true).is_err());
        // parts helper still fail-closed without knobs
        assert!(!braiins_ttys_bench_go_from_runtime_parts(
            None,
            "/no/such/braiins_ttys_bench_go_wire_try"
        ));
        let _ = current_with_runtime_bench_go();
        assert!(!S19kWireDeskPending::CURRENT.braiins_ttys_bench_go);
    }
}
