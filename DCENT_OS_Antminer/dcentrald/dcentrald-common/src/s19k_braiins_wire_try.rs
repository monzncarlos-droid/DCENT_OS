//! Retired S19k Braiins mining-off raw-UART wire-try interface.
//!
//! The old executor could transmit `SetAddress` without the content-bound
//! target identity, bosminer handoff, cooling, watchdog, reset, and terminal
//! SafeOff custody required by Track-1. It is permanently fail-closed. Pure
//! parsing/frame helpers remain only for offline protocol fixtures; target
//! execution must use the v6 `/tmp` deployment transaction.

use crate::s19k_bm1366_wire_b::{
    pack_set_address_uart_trans, s19k_aml_linear_addresses, S19K_AML_ADDR_INTERVAL,
};

/// Retired legacy opt-in. Kept only so stale configurations can be identified.
pub const ENV_BRAIINS_WIRE_TRY: &str = "DCENT_S19K_BRAIINS_WIRE_TRY";
pub const ENV_BRAIINS_WIRE_TRY_TOKEN: &str = "1";

/// Historical read-only path retained for fixture parsing. No executor uses it.
pub const GPIO437_SYSFS_VALUE: &str = "/sys/class/gpio/gpio437/value";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BraiinsWireTryRequest<'a> {
    pub env_raw: Option<&'a str>,
    pub mining_enabled: bool,
    pub board_target: &'a str,
    pub gpio437_value: Option<u8>,
    pub uart_trans_present: bool,
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
    pub gpio437_observed: Option<u8>,
    pub gpio437_not_low_warning: bool,
}

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
    RetiredUseContentBoundTmpDeploy,
}

impl core::fmt::Display for BraiinsWireTryAdmitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RetiredUseContentBoundTmpDeploy => write!(
                f,
                "S19k Braiins raw wire try is retired; use scripts/dcentrald_s19k_tmp_deploy.sh with a pinned known_hosts file"
            ),
        }
    }
}

/// Parse the legacy opt-in for audit/diagnostics only.
pub fn env_requests_wire_try(raw: Option<&str>) -> bool {
    raw.map(str::trim) == Some(ENV_BRAIINS_WIRE_TRY_TOKEN)
}

/// Parse a historical GPIO sample (`"0\n"`) without performing target I/O.
pub fn parse_gpio437_sysfs(raw: &str) -> Result<u8, &'static str> {
    match raw.trim() {
        "0" => Ok(0),
        "1" => Ok(1),
        _ => Err("GPIO437 sysfs value must be 0 or 1"),
    }
}

/// Produce offline fixture frames for the evidenced 77-chip, stride-two chain.
pub fn planned_set_address_frames() -> Vec<[u8; 7]> {
    debug_assert_eq!(S19K_AML_ADDR_INTERVAL, 2);
    s19k_aml_linear_addresses()
        .into_iter()
        .map(pack_set_address_uart_trans)
        .collect()
}

/// Permanently refuse the obsolete raw-UART executor for every request.
pub fn admit_braiins_mining_off_wire_try(
    _req: BraiinsWireTryRequest<'_>,
) -> Result<BraiinsWireTryPlan, BraiinsWireTryAdmitError> {
    Err(BraiinsWireTryAdmitError::RetiredUseContentBoundTmpDeploy)
}

/// Compatibility entry point; also permanently refused.
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

    fn request() -> BraiinsWireTryRequest<'static> {
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
    fn legacy_admission_is_unconditionally_retired() {
        let mut requests = [request(), request(), request(), request()];
        requests[1].mining_enabled = true;
        requests[2].board_target = "am3-s21";
        requests[3].runtime_bench_go = false;
        for req in requests {
            assert_eq!(
                admit_braiins_mining_off_wire_try(req),
                Err(BraiinsWireTryAdmitError::RetiredUseContentBoundTmpDeploy)
            );
        }
        assert_eq!(
            braiins_ttys_mining_off_wire_try_admit(false, "am3-s19k", true),
            Err(BraiinsWireTryAdmitError::RetiredUseContentBoundTmpDeploy)
        );
    }

    #[test]
    fn daemon_and_script_cannot_reach_the_retired_executor() {
        let main = include_str!("../../dcentrald/src/main.rs");
        assert!(!main.contains("mod s19k_braiins_wire_try"));
        assert!(!main.contains("maybe_run_s19k_braiins_wire_try"));

        let script = include_str!("../../../scripts/s19k_braiins_wire_try.sh");
        assert!(script.contains("legacy S19k wire-try is retired"));
        assert!(script.contains("dcentrald_s19k_tmp_deploy.sh"));
        assert!(script.contains("exit 64"));
        for forbidden in [
            "ssh",
            "scp",
            "stty",
            "dd if=",
            "/dev/tty",
            "/sys/class/gpio",
            "\\x55\\xAA",
        ] {
            assert!(
                !script.contains(forbidden),
                "legacy tombstone contains {forbidden}"
            );
        }
    }

    #[test]
    fn pure_historical_fixtures_remain_available_without_io_authority() {
        assert!(env_requests_wire_try(Some(" 1\n")));
        assert!(!env_requests_wire_try(Some("true")));
        assert_eq!(parse_gpio437_sysfs("0\n"), Ok(0));
        assert!(parse_gpio437_sysfs("2").is_err());
        let frames = planned_set_address_frames();
        assert_eq!(frames.len(), 77);
        assert_eq!(frames[0], [0x55, 0xAA, 0x40, 0x05, 0x00, 0x00, 0x1c]);
        assert_eq!(frames[76], pack_set_address_uart_trans(152));
    }
}
