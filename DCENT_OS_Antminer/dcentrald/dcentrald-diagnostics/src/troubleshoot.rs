//! Instant troubleshooting tools.
//!
//! Diagnostic tools that return results immediately:
//! - Network test (DNS, gateway, pool connectivity, Stratum handshake)
//! - Passive PSU snapshot (caller-supplied unattested values, or Unavailable)
//! - Passive FPGA status (caller-supplied unattested values, or Unavailable)
//! - ASIC comm test (GetAddress broadcast, count responses, CRC errors)
//! - Passive I2C endpoint observations retained by the serialized bus owner

use serde::{Deserialize, Serialize};

/// Network diagnostic test result.
///
/// Legacy active-probe DTO. The production diagnostic lifecycle publishes the
/// provenance-capped [`NetworkTestSnapshot`] instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTest {
    /// DNS resolution test passed.
    pub dns: bool,
    /// Default gateway reachable.
    pub gateway: bool,
    /// Pool TCP connection successful.
    pub pool_reachable: bool,
    /// Round-trip latency to pool in milliseconds.
    pub latency_ms: u32,
    /// Stratum handshake completed successfully.
    pub stratum_connected: bool,
    /// Error message (if any test failed).
    pub error: Option<String>,
}

const MAX_NETWORK_STAGE_DETAIL_BYTES: usize = 16 * 1024;
const MAX_NETWORK_POOL_STATUS_BYTES: usize = 128;

/// Exact outcome class for one bounded network-probe stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProbeStatus {
    Ok,
    Skipped,
    Busy,
    SpawnError,
    NonZeroExit,
    Timeout,
    Cancelled,
    OutputTooLarge,
    InvalidOutput,
    WorkerError,
}

/// One bounded network-probe stage and its optional diagnostic detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkProbeStageTelemetry {
    pub status: NetworkProbeStatus,
    pub detail: Option<String>,
}

impl NetworkProbeStageTelemetry {
    fn validate(&self, stage: &str) -> Result<(), String> {
        if self.detail.as_deref().is_some_and(|detail| {
            detail.trim().is_empty() || detail.len() > MAX_NETWORK_STAGE_DETAIL_BYTES
        }) {
            return Err(format!(
                "unattested network {stage} detail is empty or overlong"
            ));
        }
        Ok(())
    }
}

/// Results supplied by the bounded production network route for publication.
///
/// The diagnostic crate does not own the subprocesses or sysfs reads and thus
/// treats these values as caller-supplied and unattested. The fixed publisher
/// records their age and never converts stage success into a health/pass grade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnattestedNetworkTelemetry {
    pub telemetry_source: String,
    pub captured_at_ms: u64,
    pub interface: Option<String>,
    pub ip_cidr: Option<String>,
    pub ip_address: Option<String>,
    pub mac: Option<String>,
    pub link_up: Option<bool>,
    pub gateway: Option<String>,
    pub gateway_reachable: Option<bool>,
    pub dns_test_host: Option<String>,
    pub dns_ok: Option<bool>,
    pub cached_pool_status: Option<String>,
    pub cached_pool_connected: bool,
    pub ip_address_probe: NetworkProbeStageTelemetry,
    pub route_probe: NetworkProbeStageTelemetry,
    pub gateway_probe: NetworkProbeStageTelemetry,
    pub dns_probe: NetworkProbeStageTelemetry,
}

impl UnattestedNetworkTelemetry {
    fn validate(&self) -> Result<(), String> {
        if self.telemetry_source.trim().is_empty()
            || self.telemetry_source.len() > MAX_TELEMETRY_SOURCE_BYTES
        {
            return Err("unattested network telemetry source is blank or overlong".to_string());
        }

        for (name, stage) in [
            ("IP-address", &self.ip_address_probe),
            ("route", &self.route_probe),
            ("gateway", &self.gateway_probe),
            ("DNS", &self.dns_probe),
        ] {
            stage.validate(name)?;
        }

        if self.interface.as_deref().is_some_and(|interface| {
            let bytes = interface.as_bytes();
            bytes.is_empty()
                || bytes.len() > 15
                || !bytes[0].is_ascii_alphanumeric()
                || !bytes.iter().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
                })
        }) {
            return Err("unattested network interface is invalid".to_string());
        }

        let parsed_ip = match self.ip_address.as_deref() {
            Some(value) => Some(
                value
                    .parse::<std::net::Ipv4Addr>()
                    .map_err(|_| "unattested network IPv4 address is invalid".to_string())?,
            ),
            None => None,
        };
        let parsed_cidr_ip = match self.ip_cidr.as_deref() {
            Some(value) => {
                let (address, prefix) = value
                    .split_once('/')
                    .ok_or_else(|| "unattested network IPv4 CIDR is invalid".to_string())?;
                let address = address
                    .parse::<std::net::Ipv4Addr>()
                    .map_err(|_| "unattested network IPv4 CIDR address is invalid".to_string())?;
                let prefix = prefix
                    .parse::<u8>()
                    .map_err(|_| "unattested network IPv4 CIDR prefix is invalid".to_string())?;
                if prefix > 32 {
                    return Err("unattested network IPv4 CIDR prefix exceeds 32".to_string());
                }
                Some(address)
            }
            None => None,
        };
        if parsed_ip != parsed_cidr_ip {
            return Err(
                "unattested network IPv4 address and CIDR must be present and agree".to_string(),
            );
        }
        if (parsed_ip.is_some()) != (self.ip_address_probe.status == NetworkProbeStatus::Ok) {
            return Err(
                "unattested network address values and IP probe completion disagree".to_string(),
            );
        }
        if self.route_probe.status == NetworkProbeStatus::Ok && self.interface.is_none() {
            return Err("OK network route probe has no interface".to_string());
        }
        if self.interface.is_none()
            && (self.mac.is_some()
                || self.link_up.is_some()
                || self.gateway.is_some()
                || self.gateway_reachable.is_some())
        {
            return Err("unattested network values exist without an interface".to_string());
        }

        if self
            .gateway
            .as_deref()
            .is_some_and(|value| value.parse::<std::net::IpAddr>().is_err())
        {
            return Err("unattested network gateway is invalid".to_string());
        }
        match self.gateway_reachable {
            Some(true) if self.gateway_probe.status != NetworkProbeStatus::Ok => {
                return Err("reachable gateway lacks an OK probe".to_string())
            }
            Some(false) if self.gateway_probe.status != NetworkProbeStatus::NonZeroExit => {
                return Err("unreachable gateway lacks a non-zero probe result".to_string())
            }
            Some(_) if self.gateway.is_none() => {
                return Err("gateway reachability exists without a gateway".to_string())
            }
            None if matches!(
                self.gateway_probe.status,
                NetworkProbeStatus::Ok | NetworkProbeStatus::NonZeroExit
            ) =>
            {
                return Err("completed gateway probe lacks a reachability result".to_string())
            }
            _ => {}
        }

        if self.mac.as_deref().is_some_and(|mac| {
            let mut count = 0usize;
            let valid = mac.split(':').all(|part| {
                count += 1;
                part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
            !valid || count != 6
        }) {
            return Err("unattested network MAC address is invalid".to_string());
        }

        if self.dns_test_host.as_deref().is_some_and(|host| {
            let host = host.trim();
            host.is_empty()
                || host.len() > 253
                || host.starts_with('-')
                || !host.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
                })
        }) {
            return Err("unattested network DNS host is invalid".to_string());
        }
        match self.dns_ok {
            Some(true) if self.dns_probe.status != NetworkProbeStatus::Ok => {
                return Err("successful DNS result lacks an OK probe".to_string())
            }
            Some(false) if self.dns_probe.status != NetworkProbeStatus::NonZeroExit => {
                return Err("failed DNS result lacks a non-zero probe result".to_string())
            }
            Some(_) if self.dns_test_host.is_none() => {
                return Err("DNS result exists without a test host".to_string())
            }
            None if matches!(
                self.dns_probe.status,
                NetworkProbeStatus::Ok | NetworkProbeStatus::NonZeroExit
            ) =>
            {
                return Err("completed DNS probe lacks a result".to_string())
            }
            _ => {}
        }

        if self.cached_pool_status.as_deref().is_some_and(|status| {
            status.trim().is_empty() || status.len() > MAX_NETWORK_POOL_STATUS_BYTES
        }) {
            return Err("cached pool status is empty or overlong".to_string());
        }
        if self.cached_pool_connected && self.cached_pool_status.is_none() {
            return Err("cached connected pool has no source status".to_string());
        }
        Ok(())
    }
}

/// Provenance-capped diagnostic lifecycle result for a bounded network probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkTestSnapshot {
    schema: String,
    source: String,
    provenance: PassiveTelemetryProvenance,
    telemetry_source: String,
    freshness: UnattestedTelemetryFreshness,
    interface: Option<String>,
    ip_cidr: Option<String>,
    ip_address: Option<String>,
    mac: Option<String>,
    link_up: Option<bool>,
    gateway: Option<String>,
    gateway_reachable: Option<bool>,
    dns_test_host: Option<String>,
    dns_ok: Option<bool>,
    cached_pool_status: Option<String>,
    cached_pool_connected: bool,
    pool_connectivity_source: String,
    live_pool_probe_performed: bool,
    ip_address_probe: NetworkProbeStageTelemetry,
    route_probe: NetworkProbeStageTelemetry,
    gateway_probe: NetworkProbeStageTelemetry,
    dns_probe: NetworkProbeStageTelemetry,
}

impl NetworkTestSnapshot {
    pub const SCHEMA: &'static str = "diagnostics.network_test v1";
    pub const SOURCE: &'static str =
        "bounded route snapshot publisher; no hardware access or live pool-connect probe";
    pub const POOL_CONNECTIVITY_SOURCE: &'static str = "cached_runtime_state";

    pub(crate) fn from_unattested_at(
        telemetry: UnattestedNetworkTelemetry,
        publication_time_ms: u64,
    ) -> Result<Self, String> {
        telemetry.validate()?;
        let freshness = UnattestedTelemetryFreshness::classify_unattested(
            telemetry.captured_at_ms,
            publication_time_ms,
        )?;
        let snapshot = Self {
            schema: Self::SCHEMA.to_string(),
            source: Self::SOURCE.to_string(),
            provenance: PassiveTelemetryProvenance::CallerSuppliedUnattested,
            telemetry_source: telemetry.telemetry_source,
            freshness,
            interface: telemetry.interface,
            ip_cidr: telemetry.ip_cidr,
            ip_address: telemetry.ip_address,
            mac: telemetry.mac,
            link_up: telemetry.link_up,
            gateway: telemetry.gateway,
            gateway_reachable: telemetry.gateway_reachable,
            dns_test_host: telemetry.dns_test_host,
            dns_ok: telemetry.dns_ok,
            cached_pool_status: telemetry.cached_pool_status,
            cached_pool_connected: telemetry.cached_pool_connected,
            pool_connectivity_source: Self::POOL_CONNECTIVITY_SOURCE.to_string(),
            live_pool_probe_performed: false,
            ip_address_probe: telemetry.ip_address_probe,
            route_probe: telemetry.route_probe,
            gateway_probe: telemetry.gateway_probe,
            dns_probe: telemetry.dns_probe,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub(crate) fn publication_warnings(&self) -> Vec<String> {
        let mut warnings = vec![
            "network probe values are route-supplied and unattested; stage success is not a miner health or pass verdict"
                .to_string(),
            "pool connectivity is cached runtime state; no live pool-connect or Stratum handshake probe was performed"
                .to_string(),
        ];
        if self.freshness.availability == UnattestedTelemetryAvailability::StaleUnattested {
            warnings.push(format!(
                "network telemetry is stale at publication (age {} ms; fixed threshold {} ms)",
                self.freshness.age_ms.unwrap_or_default(),
                PASSIVE_TELEMETRY_STALE_AFTER_MS
            ));
        }
        if [
            &self.ip_address_probe,
            &self.route_probe,
            &self.gateway_probe,
            &self.dns_probe,
        ]
        .iter()
        .any(|stage| {
            !matches!(
                stage.status,
                NetworkProbeStatus::Ok | NetworkProbeStatus::Skipped
            )
        }) {
            warnings.push(
                "one or more bounded network probe stages did not complete successfully"
                    .to_string(),
            );
        }
        warnings
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != Self::SCHEMA
            || self.source != Self::SOURCE
            || self.provenance != PassiveTelemetryProvenance::CallerSuppliedUnattested
            || self.pool_connectivity_source != Self::POOL_CONNECTIVITY_SOURCE
            || self.live_pool_probe_performed
        {
            return Err("unexpected network diagnostic snapshot identity or authority".to_string());
        }
        self.freshness.validate()?;
        let captured_at_ms = self
            .freshness
            .captured_at_ms
            .ok_or_else(|| "network snapshot has no capture timestamp".to_string())?;
        UnattestedNetworkTelemetry {
            telemetry_source: self.telemetry_source.clone(),
            captured_at_ms,
            interface: self.interface.clone(),
            ip_cidr: self.ip_cidr.clone(),
            ip_address: self.ip_address.clone(),
            mac: self.mac.clone(),
            link_up: self.link_up,
            gateway: self.gateway.clone(),
            gateway_reachable: self.gateway_reachable,
            dns_test_host: self.dns_test_host.clone(),
            dns_ok: self.dns_ok,
            cached_pool_status: self.cached_pool_status.clone(),
            cached_pool_connected: self.cached_pool_connected,
            ip_address_probe: self.ip_address_probe.clone(),
            route_probe: self.route_probe.clone(),
            gateway_probe: self.gateway_probe.clone(),
            dns_probe: self.dns_probe.clone(),
        }
        .validate()
    }
}

/// Legacy active-probe PSU result DTO.
///
/// No production publisher currently constructs this type. Missing values must
/// never be synthesized as zero; passive publication uses [`PsuProbeSnapshot`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsuProbe {
    /// Whether a PMBus PSU was detected.
    pub detected: bool,
    /// Input voltage (V).
    pub vin_v: f32,
    /// Output voltage (V).
    pub vout_v: f32,
    /// Output current (A).
    pub iout_a: f32,
    /// Input power (W).
    pub pin_w: f32,
    /// Output power (W).
    pub pout_w: f32,
    /// Calculated efficiency (%).
    pub efficiency_pct: f32,
    /// PSU internal temperature (C).
    pub temp_c: f32,
    /// PSU fan speed (RPM, if reported).
    pub fan_rpm: Option<u32>,
    /// Active fault codes.
    pub faults: Vec<String>,
    /// Raw PMBus status word.
    pub status_word: Option<u16>,
}

/// Legacy active-probe per-chain FPGA status DTO.
///
/// No production publisher currently constructs this type. Passive publication
/// uses [`FpgaStatusSnapshot`] and optional unattested fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpgaStatus {
    /// Chain ID.
    pub chain_id: u8,
    /// FPGA IP core version (hex).
    pub version: String,
    /// Control register value (decoded).
    pub ctrl_reg: u32,
    /// Chain enabled.
    pub enabled: bool,
    /// BM139X mode active.
    pub bm139x_mode: bool,
    /// Current baud rate divisor.
    pub baud_reg: u32,
    /// Calculated baud rate.
    pub baud_rate: u32,
    /// CRC error count.
    pub error_count: u32,
    /// CMD TX FIFO empty.
    pub cmd_tx_empty: bool,
    /// CMD RX FIFO empty.
    pub cmd_rx_empty: bool,
    /// Work TX FIFO empty.
    pub work_tx_empty: bool,
    /// Work RX FIFO empty (no pending nonces).
    pub work_rx_empty: bool,
}

/// Publication-time freshness window for passive, unattested telemetry.
///
/// Current power telemetry is normally refreshed every five seconds. A fixed
/// 30-second ceiling tolerates scheduler delay while preventing a caller from
/// selecting an unbounded policy that re-labels an old sample as fresh.
pub const PASSIVE_TELEMETRY_STALE_AFTER_MS: u64 = 30_000;

const MAX_TELEMETRY_SOURCE_BYTES: usize = 256;
const MAX_UNAVAILABLE_REASON_BYTES: usize = 512;
const MAX_PSU_FAULTS: usize = 128;
const MAX_PSU_FAULT_BYTES: usize = 256;
const MAX_FPGA_CHAINS: usize = 256;
const MAX_FPGA_VERSION_BYTES: usize = 128;
// Mirrors dcentrald_hal::fpga_chain::FPGA_CLK_HZ for the S9/am1 carrier.
// The am2 carrier intentionally does not publish a derived baud rate until its
// fabric-clock contract is independently proven.
const S9_FPGA_TELEMETRY_CLOCK_HZ: u64 = 200_000_000;

/// Provenance ceiling for a passive snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PassiveTelemetryProvenance {
    /// Values were sampled by the runtime component that already owns the
    /// hardware transport, then retained for a read-only consumer. This is
    /// source ownership, not a calibration or measured-pass receipt.
    RuntimeOwnedRetainedObservation,
    /// Values and their capture timestamp were supplied by a caller. The
    /// publisher checks age at publication but has no producer receipt.
    CallerSuppliedUnattested,
    /// No telemetry values were supplied or published.
    Unavailable,
}

/// Publication-time availability of passive, unattested telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnattestedTelemetryAvailability {
    /// The caller-supplied timestamp is within the fixed publication window.
    FreshUnattested,
    /// The caller-supplied timestamp is outside the fixed publication window.
    StaleUnattested,
    /// No telemetry values are present.
    Unavailable,
}

/// Private-construction freshness envelope for passive snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnattestedTelemetryFreshness {
    availability: UnattestedTelemetryAvailability,
    captured_at_ms: Option<u64>,
    evaluated_at_ms: Option<u64>,
    age_ms: Option<u64>,
    stale_after_ms: u64,
    unavailable_reason: Option<String>,
}

impl UnattestedTelemetryFreshness {
    fn classify_unattested(captured_at_ms: u64, evaluated_at_ms: u64) -> Result<Self, String> {
        if captured_at_ms == 0 {
            return Err("unattested telemetry has no capture timestamp".to_string());
        }
        let age_ms = evaluated_at_ms.checked_sub(captured_at_ms).ok_or_else(|| {
            "unattested telemetry capture timestamp is in the future at publication".to_string()
        })?;
        Ok(Self {
            availability: if age_ms <= PASSIVE_TELEMETRY_STALE_AFTER_MS {
                UnattestedTelemetryAvailability::FreshUnattested
            } else {
                UnattestedTelemetryAvailability::StaleUnattested
            },
            captured_at_ms: Some(captured_at_ms),
            evaluated_at_ms: Some(evaluated_at_ms),
            age_ms: Some(age_ms),
            stale_after_ms: PASSIVE_TELEMETRY_STALE_AFTER_MS,
            unavailable_reason: None,
        })
    }

    fn try_unavailable(reason: impl Into<String>) -> Result<Self, String> {
        let reason = reason.into();
        let reason = reason.trim();
        if reason.is_empty() {
            return Err("unavailable telemetry requires a non-blank reason".to_string());
        }
        if reason.len() > MAX_UNAVAILABLE_REASON_BYTES {
            return Err(format!(
                "unavailable telemetry reason exceeds {MAX_UNAVAILABLE_REASON_BYTES} bytes"
            ));
        }
        Ok(Self {
            availability: UnattestedTelemetryAvailability::Unavailable,
            captured_at_ms: None,
            evaluated_at_ms: None,
            age_ms: None,
            stale_after_ms: PASSIVE_TELEMETRY_STALE_AFTER_MS,
            unavailable_reason: Some(reason.to_string()),
        })
    }

    pub const fn availability(&self) -> UnattestedTelemetryAvailability {
        self.availability
    }

    pub const fn captured_at_ms(&self) -> Option<u64> {
        self.captured_at_ms
    }

    pub const fn evaluated_at_ms(&self) -> Option<u64> {
        self.evaluated_at_ms
    }

    pub const fn age_ms(&self) -> Option<u64> {
        self.age_ms
    }

    pub const fn stale_after_ms(&self) -> u64 {
        self.stale_after_ms
    }

    pub fn unavailable_reason(&self) -> Option<&str> {
        self.unavailable_reason.as_deref()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.stale_after_ms != PASSIVE_TELEMETRY_STALE_AFTER_MS {
            return Err("passive telemetry freshness policy is not the fixed policy".to_string());
        }
        match self.availability {
            UnattestedTelemetryAvailability::FreshUnattested
            | UnattestedTelemetryAvailability::StaleUnattested => {
                let captured_at_ms = self.captured_at_ms.ok_or_else(|| {
                    "available unattested telemetry has no capture timestamp".to_string()
                })?;
                if captured_at_ms == 0 {
                    return Err(
                        "available unattested telemetry capture timestamp is zero".to_string()
                    );
                }
                let evaluated_at_ms = self.evaluated_at_ms.ok_or_else(|| {
                    "available unattested telemetry has no publication timestamp".to_string()
                })?;
                let age_ms = self
                    .age_ms
                    .ok_or_else(|| "available unattested telemetry has no age".to_string())?;
                if evaluated_at_ms.checked_sub(captured_at_ms) != Some(age_ms) {
                    return Err(
                        "unattested telemetry age disagrees with capture/publication timestamps"
                            .to_string(),
                    );
                }
                if self.unavailable_reason.is_some() {
                    return Err(
                        "available unattested telemetry carries an unavailable reason".to_string(),
                    );
                }
                let expected = if age_ms <= PASSIVE_TELEMETRY_STALE_AFTER_MS {
                    UnattestedTelemetryAvailability::FreshUnattested
                } else {
                    UnattestedTelemetryAvailability::StaleUnattested
                };
                if self.availability != expected {
                    return Err(
                        "unattested telemetry availability disagrees with publication age"
                            .to_string(),
                    );
                }
            }
            UnattestedTelemetryAvailability::Unavailable => {
                if self.captured_at_ms.is_some()
                    || self.evaluated_at_ms.is_some()
                    || self.age_ms.is_some()
                {
                    return Err("unavailable telemetry carries capture timing".to_string());
                }
                let reason = self
                    .unavailable_reason
                    .as_deref()
                    .ok_or_else(|| "unavailable telemetry has no reason".to_string())?;
                if reason.trim().is_empty() || reason.len() > MAX_UNAVAILABLE_REASON_BYTES {
                    return Err("unavailable telemetry reason is invalid".to_string());
                }
            }
        }
        Ok(())
    }
}

/// Optional PSU values supplied by a caller from an existing in-memory sample.
///
/// This input is explicitly unattested. `telemetry_source` is an explanatory
/// caller label, not proof of a daemon, PMBus, or hardware producer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnattestedPsuTelemetry {
    pub telemetry_source: String,
    pub captured_at_ms: u64,
    pub detected: Option<bool>,
    pub vin_v: Option<f32>,
    pub vout_v: Option<f32>,
    pub iout_a: Option<f32>,
    pub board_power_w: Option<f64>,
    pub wall_power_w: Option<f64>,
    pub efficiency_pct: Option<f32>,
    pub temp_c: Option<f32>,
    pub fan_rpm: Option<u32>,
    pub faults: Option<Vec<String>>,
    pub status_word: Option<u16>,
    pub calibrated: Option<bool>,
}

impl UnattestedPsuTelemetry {
    fn has_observation(&self) -> bool {
        self.detected.is_some()
            || self.vin_v.is_some()
            || self.vout_v.is_some()
            || self.iout_a.is_some()
            || self.board_power_w.is_some()
            || self.wall_power_w.is_some()
            || self.efficiency_pct.is_some()
            || self.temp_c.is_some()
            || self.fan_rpm.is_some()
            || self.faults.is_some()
            || self.status_word.is_some()
            || self.calibrated.is_some()
    }

    fn validate(&self) -> Result<(), String> {
        if self.telemetry_source.trim().is_empty()
            || self.telemetry_source.len() > MAX_TELEMETRY_SOURCE_BYTES
        {
            return Err("unattested PSU telemetry source is blank or overlong".to_string());
        }
        if !self.has_observation() {
            return Err("unattested PSU telemetry contains no observations".to_string());
        }
        for (name, value) in [
            ("vin_v", self.vin_v.map(f64::from)),
            ("vout_v", self.vout_v.map(f64::from)),
            ("iout_a", self.iout_a.map(f64::from)),
            ("board_power_w", self.board_power_w),
            ("wall_power_w", self.wall_power_w),
            ("efficiency_pct", self.efficiency_pct.map(f64::from)),
        ] {
            if value.is_some_and(|value| !value.is_finite() || value < 0.0) {
                return Err(format!(
                    "unattested PSU {name} is not finite and non-negative"
                ));
            }
        }
        if self.temp_c.is_some_and(|value| !value.is_finite()) {
            return Err("unattested PSU temp_c is not finite".to_string());
        }
        if self
            .efficiency_pct
            .is_some_and(|value| !(0.0..=100.0).contains(&value))
        {
            return Err("unattested PSU efficiency_pct exceeds 100".to_string());
        }
        if self.faults.as_ref().is_some_and(|faults| {
            faults.len() > MAX_PSU_FAULTS
                || faults
                    .iter()
                    .any(|fault| fault.trim().is_empty() || fault.len() > MAX_PSU_FAULT_BYTES)
        }) {
            return Err("unattested PSU faults are empty, overlong, or too numerous".to_string());
        }
        Ok(())
    }
}

/// Passive PSU diagnostic snapshot with a private construction boundary.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PsuProbeSnapshot {
    schema: String,
    source: String,
    provenance: PassiveTelemetryProvenance,
    telemetry_source: Option<String>,
    freshness: UnattestedTelemetryFreshness,
    detected: Option<bool>,
    vin_v: Option<f32>,
    vout_v: Option<f32>,
    iout_a: Option<f32>,
    board_power_w: Option<f64>,
    wall_power_w: Option<f64>,
    efficiency_pct: Option<f32>,
    temp_c: Option<f32>,
    fan_rpm: Option<u32>,
    faults: Option<Vec<String>>,
    status_word: Option<u16>,
    calibrated: Option<bool>,
}

impl PsuProbeSnapshot {
    pub const SCHEMA: &'static str = "diagnostics.psu_probe v1";
    pub const SOURCE: &'static str =
        "passive snapshot publisher; no PMBus, I2C, UART, or device access issued";

    pub(crate) fn from_unattested_at(
        telemetry: UnattestedPsuTelemetry,
        publication_time_ms: u64,
    ) -> Result<Self, String> {
        telemetry.validate()?;
        let freshness = UnattestedTelemetryFreshness::classify_unattested(
            telemetry.captured_at_ms,
            publication_time_ms,
        )?;
        let snapshot = Self {
            schema: Self::SCHEMA.to_string(),
            source: Self::SOURCE.to_string(),
            provenance: PassiveTelemetryProvenance::CallerSuppliedUnattested,
            telemetry_source: Some(telemetry.telemetry_source),
            freshness,
            detected: telemetry.detected,
            vin_v: telemetry.vin_v,
            vout_v: telemetry.vout_v,
            iout_a: telemetry.iout_a,
            board_power_w: telemetry.board_power_w,
            wall_power_w: telemetry.wall_power_w,
            efficiency_pct: telemetry.efficiency_pct,
            temp_c: telemetry.temp_c,
            fan_rpm: telemetry.fan_rpm,
            faults: telemetry.faults,
            status_word: telemetry.status_word,
            calibrated: telemetry.calibrated,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub(crate) fn try_unavailable(reason: impl Into<String>) -> Result<Self, String> {
        let snapshot = Self {
            schema: Self::SCHEMA.to_string(),
            source: Self::SOURCE.to_string(),
            provenance: PassiveTelemetryProvenance::Unavailable,
            telemetry_source: None,
            freshness: UnattestedTelemetryFreshness::try_unavailable(reason)?,
            detected: None,
            vin_v: None,
            vout_v: None,
            iout_a: None,
            board_power_w: None,
            wall_power_w: None,
            efficiency_pct: None,
            temp_c: None,
            fan_rpm: None,
            faults: None,
            status_word: None,
            calibrated: None,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn freshness(&self) -> &UnattestedTelemetryFreshness {
        &self.freshness
    }

    pub(crate) fn publication_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        match self.freshness.availability {
            UnattestedTelemetryAvailability::FreshUnattested => warnings.push(
                "PSU values and capture timestamp are caller-supplied and unattested; publication-time age is not producer provenance or a health/pass verdict".to_string(),
            ),
            UnattestedTelemetryAvailability::StaleUnattested => {
                warnings.push(
                    "PSU values and capture timestamp are caller-supplied and unattested; publication-time age is not producer provenance or a health/pass verdict".to_string(),
                );
                let age = self.freshness.age_ms.map_or_else(
                    || "unknown".to_string(),
                    |age| age.to_string(),
                );
                warnings.push(format!(
                    "unattested PSU telemetry is stale at publication (age {age} ms; fixed threshold {} ms)",
                    PASSIVE_TELEMETRY_STALE_AFTER_MS
                ));
            }
            UnattestedTelemetryAvailability::Unavailable => {
                let reason = self
                    .freshness
                    .unavailable_reason
                    .as_deref()
                    .map_or("unknown reason", str::trim);
                warnings.push(format!("PSU telemetry is unavailable: {reason}"));
            }
        }
        if self.detected == Some(false) {
            warnings.push(
                "caller-supplied PSU sample reports detected=false; no healthy/present verdict is authorized"
                    .to_string(),
            );
        }
        if self
            .faults
            .as_ref()
            .is_some_and(|faults| !faults.is_empty())
        {
            let count = self.faults.as_ref().map_or(0, Vec::len);
            warnings.push(format!(
                "caller-supplied PSU sample reports {count} non-empty fault entr{}; values are unattested and no pass verdict is authorized",
                if count == 1 { "y" } else { "ies" }
            ));
        }
        if self.status_word.is_some_and(|status| status != 0) {
            warnings.push(
                "caller-supplied PSU sample reports a non-zero status word; value is unattested and no pass verdict is authorized"
                    .to_string(),
            );
        }
        warnings
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != Self::SCHEMA || self.source != Self::SOURCE {
            return Err("unexpected passive PSU snapshot identity".to_string());
        }
        self.freshness.validate()?;
        match self.freshness.availability {
            UnattestedTelemetryAvailability::Unavailable => {
                if self.provenance != PassiveTelemetryProvenance::Unavailable
                    || self.telemetry_source.is_some()
                    || self.detected.is_some()
                    || self.vin_v.is_some()
                    || self.vout_v.is_some()
                    || self.iout_a.is_some()
                    || self.board_power_w.is_some()
                    || self.wall_power_w.is_some()
                    || self.efficiency_pct.is_some()
                    || self.temp_c.is_some()
                    || self.fan_rpm.is_some()
                    || self.faults.is_some()
                    || self.status_word.is_some()
                    || self.calibrated.is_some()
                {
                    return Err(
                        "unavailable passive PSU snapshot carries telemetry values".to_string()
                    );
                }
            }
            UnattestedTelemetryAvailability::FreshUnattested
            | UnattestedTelemetryAvailability::StaleUnattested => {
                if self.provenance != PassiveTelemetryProvenance::CallerSuppliedUnattested {
                    return Err("available PSU snapshot has invalid provenance".to_string());
                }
                let telemetry_source = self.telemetry_source.clone().ok_or_else(|| {
                    "available passive PSU snapshot has no telemetry source".to_string()
                })?;
                let captured_at_ms = self.freshness.captured_at_ms.ok_or_else(|| {
                    "available passive PSU snapshot has no capture timestamp".to_string()
                })?;
                UnattestedPsuTelemetry {
                    telemetry_source,
                    captured_at_ms,
                    detected: self.detected,
                    vin_v: self.vin_v,
                    vout_v: self.vout_v,
                    iout_a: self.iout_a,
                    board_power_w: self.board_power_w,
                    wall_power_w: self.wall_power_w,
                    efficiency_pct: self.efficiency_pct,
                    temp_c: self.temp_c,
                    fan_rpm: self.fan_rpm,
                    faults: self.faults.clone(),
                    status_word: self.status_word,
                    calibrated: self.calibrated,
                }
                .validate()?;
            }
        }
        Ok(())
    }
}

/// Register layout attached to a retained FPGA observation.
///
/// The S9/am1 and am2 bitstreams assign different meanings to common-block
/// offsets and CTRL bits. Keeping the layout explicit prevents a raw word from
/// being decoded under the wrong carrier contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FpgaRegisterLayout {
    Am1S9,
    Am2,
}

/// One optional FPGA chain observation.
///
/// Caller-supplied snapshots may leave fields absent. Runtime-owned retained
/// snapshots use [`RuntimeOwnedFpgaTelemetry`] and must satisfy the stricter
/// cross-field contract in `validate_runtime_owned`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnattestedFpgaChainTelemetry {
    pub chain_id: u8,
    #[serde(default)]
    pub register_layout: Option<FpgaRegisterLayout>,
    #[serde(default)]
    pub identity_word: Option<u32>,
    pub version: Option<String>,
    #[serde(default)]
    pub build_id: Option<u32>,
    pub ctrl_reg: Option<u32>,
    pub enabled: Option<bool>,
    pub bm139x_mode: Option<bool>,
    pub baud_reg: Option<u32>,
    pub baud_rate: Option<u32>,
    #[serde(default)]
    pub work_time: Option<u32>,
    pub error_count: Option<u32>,
    pub cmd_tx_empty: Option<bool>,
    pub cmd_rx_empty: Option<bool>,
    pub work_tx_empty: Option<bool>,
    pub work_rx_empty: Option<bool>,
}

impl UnattestedFpgaChainTelemetry {
    fn has_observation(&self) -> bool {
        self.register_layout.is_some()
            || self.identity_word.is_some()
            || self.version.is_some()
            || self.build_id.is_some()
            || self.ctrl_reg.is_some()
            || self.enabled.is_some()
            || self.bm139x_mode.is_some()
            || self.baud_reg.is_some()
            || self.baud_rate.is_some()
            || self.work_time.is_some()
            || self.error_count.is_some()
            || self.cmd_tx_empty.is_some()
            || self.cmd_rx_empty.is_some()
            || self.work_tx_empty.is_some()
            || self.work_rx_empty.is_some()
    }

    fn validate(&self) -> Result<(), String> {
        if !self.has_observation() {
            return Err(format!(
                "unattested FPGA chain {} contains no observations",
                self.chain_id
            ));
        }
        if self.version.as_deref().is_some_and(|version| {
            version.trim().is_empty() || version.len() > MAX_FPGA_VERSION_BYTES
        }) {
            return Err(format!(
                "unattested FPGA chain {} has an empty or overlong version",
                self.chain_id
            ));
        }
        Ok(())
    }

    fn validate_runtime_owned(&self) -> Result<(), String> {
        self.validate()?;
        let layout = self.register_layout.ok_or_else(|| {
            format!(
                "runtime-owned FPGA chain {} has no register layout",
                self.chain_id
            )
        })?;
        let identity_word = self.identity_word.ok_or_else(|| {
            format!(
                "runtime-owned FPGA chain {} has no identity word",
                self.chain_id
            )
        })?;
        let build_id = self
            .build_id
            .ok_or_else(|| format!("runtime-owned FPGA chain {} has no build ID", self.chain_id))?;
        let ctrl_reg = self.ctrl_reg.ok_or_else(|| {
            format!(
                "runtime-owned FPGA chain {} has no CTRL register",
                self.chain_id
            )
        })?;
        let enabled = self.enabled.ok_or_else(|| {
            format!(
                "runtime-owned FPGA chain {} has no enabled decode",
                self.chain_id
            )
        })?;
        let baud_reg = self.baud_reg.ok_or_else(|| {
            format!(
                "runtime-owned FPGA chain {} has no baud register",
                self.chain_id
            )
        })?;
        for (name, present) in [
            ("CMD TX-empty", self.cmd_tx_empty.is_some()),
            ("CMD RX-empty", self.cmd_rx_empty.is_some()),
            ("WORK TX-empty", self.work_tx_empty.is_some()),
            ("WORK RX-empty", self.work_rx_empty.is_some()),
        ] {
            if !present {
                return Err(format!(
                    "runtime-owned FPGA chain {} has no {name} observation",
                    self.chain_id
                ));
            }
        }

        match layout {
            FpgaRegisterLayout::Am1S9 => {
                let expected_version = format!("0x{identity_word:08X}");
                if self.version.as_deref() != Some(expected_version.as_str()) {
                    return Err(format!(
                        "runtime-owned S9 FPGA chain {} version does not match its identity word",
                        self.chain_id
                    ));
                }
                let expected_enabled = ctrl_reg & (1 << 3) != 0;
                if enabled != expected_enabled {
                    return Err(format!(
                        "runtime-owned S9 FPGA chain {} enabled decode contradicts CTRL",
                        self.chain_id
                    ));
                }
                let expected_bm139x = ctrl_reg & (1 << 4) != 0;
                if self.bm139x_mode != Some(expected_bm139x) {
                    return Err(format!(
                        "runtime-owned S9 FPGA chain {} BM139X decode contradicts CTRL",
                        self.chain_id
                    ));
                }
                let divisor = u64::from(baud_reg);
                let expected_baud = S9_FPGA_TELEMETRY_CLOCK_HZ / (16 * (divisor + 1));
                if self.baud_rate != u32::try_from(expected_baud).ok() {
                    return Err(format!(
                        "runtime-owned S9 FPGA chain {} baud rate contradicts its divisor",
                        self.chain_id
                    ));
                }
                if self.work_time.is_none() {
                    return Err(format!(
                        "runtime-owned S9 FPGA chain {} has no WORK_TIME observation",
                        self.chain_id
                    ));
                }
                if self.error_count.is_none() {
                    return Err(format!(
                        "runtime-owned S9 FPGA chain {} has no error-counter observation",
                        self.chain_id
                    ));
                }
            }
            FpgaRegisterLayout::Am2 => {
                if identity_word != build_id {
                    return Err(format!(
                        "runtime-owned am2 FPGA chain {} identity/build words disagree",
                        self.chain_id
                    ));
                }
                if self.version.is_some()
                    || self.bm139x_mode.is_some()
                    || self.baud_rate.is_some()
                    || self.work_time.is_some()
                {
                    return Err(format!(
                        "runtime-owned am2 FPGA chain {} relabels carrier-specific fields",
                        self.chain_id
                    ));
                }
                if self.error_count.is_some() {
                    return Err(format!(
                        "runtime-owned am2 FPGA chain {} relabels unproven common+0x18 as an error counter",
                        self.chain_id
                    ));
                }
                let expected_enabled = ctrl_reg & (1 << 1) != 0;
                if enabled != expected_enabled {
                    return Err(format!(
                        "runtime-owned am2 FPGA chain {} enabled decode contradicts CTRL",
                        self.chain_id
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Caller-supplied FPGA aggregate awaiting publication-time age evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnattestedFpgaTelemetry {
    pub telemetry_source: String,
    pub captured_at_ms: u64,
    pub chains: Vec<UnattestedFpgaChainTelemetry>,
}

impl UnattestedFpgaTelemetry {
    fn validate(&self) -> Result<(), String> {
        if self.telemetry_source.trim().is_empty()
            || self.telemetry_source.len() > MAX_TELEMETRY_SOURCE_BYTES
        {
            return Err("unattested FPGA telemetry source is blank or overlong".to_string());
        }
        if self.chains.is_empty() || self.chains.len() > MAX_FPGA_CHAINS {
            return Err("unattested FPGA telemetry has an invalid chain count".to_string());
        }
        let mut chain_ids = std::collections::HashSet::new();
        for chain in &self.chains {
            if !chain_ids.insert(chain.chain_id) {
                return Err(format!(
                    "duplicate unattested FPGA chain ID {}",
                    chain.chain_id
                ));
            }
            chain.validate()?;
        }
        Ok(())
    }
}

/// Source-owned FPGA register snapshot retained by the mining runtime.
///
/// The producer must already own each chain transport. Publishing this value
/// never grants the API permission to open MMIO/UIO/devmem independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeOwnedFpgaTelemetry {
    pub telemetry_source: String,
    pub captured_at_ms: u64,
    pub chains: Vec<UnattestedFpgaChainTelemetry>,
}

impl RuntimeOwnedFpgaTelemetry {
    fn validate(&self) -> Result<(), String> {
        if self.telemetry_source.trim().is_empty()
            || self.telemetry_source.len() > MAX_TELEMETRY_SOURCE_BYTES
        {
            return Err("runtime-owned FPGA telemetry source is blank or overlong".to_string());
        }
        if self.chains.is_empty() || self.chains.len() > MAX_FPGA_CHAINS {
            return Err("runtime-owned FPGA telemetry has an invalid chain count".to_string());
        }
        let mut chain_ids = std::collections::HashSet::new();
        for chain in &self.chains {
            if !chain_ids.insert(chain.chain_id) {
                return Err(format!(
                    "duplicate runtime-owned FPGA chain ID {}",
                    chain.chain_id
                ));
            }
            chain.validate_runtime_owned()?;
        }
        Ok(())
    }
}

/// Passive FPGA diagnostic snapshot with a private construction boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FpgaStatusSnapshot {
    schema: String,
    source: String,
    provenance: PassiveTelemetryProvenance,
    telemetry_source: Option<String>,
    freshness: UnattestedTelemetryFreshness,
    chain_count: Option<usize>,
    chains: Option<Vec<UnattestedFpgaChainTelemetry>>,
}

impl FpgaStatusSnapshot {
    pub const SCHEMA: &'static str = "diagnostics.fpga_status v2";
    pub const SOURCE: &'static str =
        "passive snapshot publisher; no MMIO, UIO, devmem, or device access issued";

    pub(crate) fn from_runtime_owned_at(
        telemetry: RuntimeOwnedFpgaTelemetry,
        publication_time_ms: u64,
    ) -> Result<Self, String> {
        telemetry.validate()?;
        let freshness = UnattestedTelemetryFreshness::classify_unattested(
            telemetry.captured_at_ms,
            publication_time_ms,
        )?;
        let snapshot = Self {
            schema: Self::SCHEMA.to_string(),
            source: Self::SOURCE.to_string(),
            provenance: PassiveTelemetryProvenance::RuntimeOwnedRetainedObservation,
            telemetry_source: Some(telemetry.telemetry_source),
            freshness,
            chain_count: Some(telemetry.chains.len()),
            chains: Some(telemetry.chains),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub(crate) fn from_unattested_at(
        telemetry: UnattestedFpgaTelemetry,
        publication_time_ms: u64,
    ) -> Result<Self, String> {
        telemetry.validate()?;
        let freshness = UnattestedTelemetryFreshness::classify_unattested(
            telemetry.captured_at_ms,
            publication_time_ms,
        )?;
        let snapshot = Self {
            schema: Self::SCHEMA.to_string(),
            source: Self::SOURCE.to_string(),
            provenance: PassiveTelemetryProvenance::CallerSuppliedUnattested,
            telemetry_source: Some(telemetry.telemetry_source),
            freshness,
            chain_count: Some(telemetry.chains.len()),
            chains: Some(telemetry.chains),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub(crate) fn try_unavailable(reason: impl Into<String>) -> Result<Self, String> {
        let snapshot = Self {
            schema: Self::SCHEMA.to_string(),
            source: Self::SOURCE.to_string(),
            provenance: PassiveTelemetryProvenance::Unavailable,
            telemetry_source: None,
            freshness: UnattestedTelemetryFreshness::try_unavailable(reason)?,
            chain_count: None,
            chains: None,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn freshness(&self) -> &UnattestedTelemetryFreshness {
        &self.freshness
    }

    pub(crate) fn publication_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        match self.freshness.availability {
            UnattestedTelemetryAvailability::FreshUnattested => warnings.push(match self.provenance {
                PassiveTelemetryProvenance::RuntimeOwnedRetainedObservation =>
                    "FPGA values come from a retained runtime-owner snapshot; this is read-only operational telemetry, not a calibration, health/pass, or manufacturing receipt".to_string(),
                _ => "FPGA values and capture timestamp are caller-supplied and unattested; publication-time age is not producer provenance or a health/pass verdict".to_string(),
            }),
            UnattestedTelemetryAvailability::StaleUnattested => {
                warnings.push(match self.provenance {
                    PassiveTelemetryProvenance::RuntimeOwnedRetainedObservation =>
                        "FPGA values come from a retained runtime-owner snapshot; this is read-only operational telemetry, not a calibration, health/pass, or manufacturing receipt".to_string(),
                    _ => "FPGA values and capture timestamp are caller-supplied and unattested; publication-time age is not producer provenance or a health/pass verdict".to_string(),
                });
                let age = self.freshness.age_ms.map_or_else(
                    || "unknown".to_string(),
                    |age| age.to_string(),
                );
                warnings.push(format!(
                    "FPGA telemetry is stale at publication (age {age} ms; fixed threshold {} ms)",
                    PASSIVE_TELEMETRY_STALE_AFTER_MS
                ));
            }
            UnattestedTelemetryAvailability::Unavailable => {
                let reason = self
                    .freshness
                    .unavailable_reason
                    .as_deref()
                    .map_or("unknown reason", str::trim);
                warnings.push(format!("FPGA telemetry is unavailable: {reason}"));
            }
        }
        let error_chains = self
            .chains
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|chain| chain.error_count.is_some_and(|count| count > 0))
            .count();
        if error_chains > 0 {
            let evidence = match self.provenance {
                PassiveTelemetryProvenance::RuntimeOwnedRetainedObservation => {
                    "runtime-owned retained"
                }
                _ => "caller-supplied unattested",
            };
            warnings.push(format!(
                "{evidence} FPGA sample reports non-zero error counters on {error_chains} chain(s); operational values grant no pass verdict"
            ));
        }
        warnings
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != Self::SCHEMA || self.source != Self::SOURCE {
            return Err("unexpected passive FPGA snapshot identity".to_string());
        }
        self.freshness.validate()?;
        match self.freshness.availability {
            UnattestedTelemetryAvailability::Unavailable => {
                if self.provenance != PassiveTelemetryProvenance::Unavailable
                    || self.telemetry_source.is_some()
                    || self.chain_count.is_some()
                    || self.chains.is_some()
                {
                    return Err(
                        "unavailable passive FPGA snapshot carries telemetry values".to_string()
                    );
                }
            }
            UnattestedTelemetryAvailability::FreshUnattested
            | UnattestedTelemetryAvailability::StaleUnattested => {
                let telemetry_source = self
                    .telemetry_source
                    .clone()
                    .ok_or_else(|| "available FPGA snapshot has no telemetry source".to_string())?;
                let captured_at_ms = self.freshness.captured_at_ms.ok_or_else(|| {
                    "available FPGA snapshot has no capture timestamp".to_string()
                })?;
                let chain_count = self.chain_count.ok_or_else(|| {
                    "available FPGA snapshot has no observed chain count".to_string()
                })?;
                let chains = self.chains.clone().ok_or_else(|| {
                    "available FPGA snapshot has no observed chain values".to_string()
                })?;
                if chain_count != chains.len() {
                    return Err("FPGA snapshot chain_count does not match chains".to_string());
                }
                match self.provenance {
                    PassiveTelemetryProvenance::CallerSuppliedUnattested => {
                        UnattestedFpgaTelemetry {
                            telemetry_source,
                            captured_at_ms,
                            chains,
                        }
                        .validate()?;
                    }
                    PassiveTelemetryProvenance::RuntimeOwnedRetainedObservation => {
                        RuntimeOwnedFpgaTelemetry {
                            telemetry_source,
                            captured_at_ms,
                            chains,
                        }
                        .validate()?;
                    }
                    PassiveTelemetryProvenance::Unavailable => {
                        return Err("available FPGA snapshot has invalid provenance".to_string());
                    }
                }
            }
        }
        Ok(())
    }
}

/// ASIC communication test result (per chain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsicCommTest {
    /// Chain ID.
    pub chain_id: u8,
    /// Number of chips that responded.
    pub chip_count: u8,
    /// Chip type detected (e.g., "BM1387").
    pub chip_type: String,
    /// Chip ID hex (e.g., "0x1387").
    pub chip_id: String,
    /// CRC errors during test.
    pub crc_errors: u32,
    /// Response time in milliseconds.
    pub response_time_ms: u32,
    /// Whether communication was successful.
    pub success: bool,
    /// Error message (if failed).
    pub error: Option<String>,
}

/// Read-only per-chain communication observation from daemon mining telemetry.
///
/// This is deliberately not [`AsicCommTest`]: it issues no GetAddress command,
/// measures no response latency, and does not independently identify silicon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsicCommChainSnapshot {
    pub chain_id: u8,
    pub responding_chips: u8,
    pub comm_ok: bool,
    pub crc_errors: u32,
    pub status: String,
}

/// Immediate ASIC communication snapshot published by the production REST
/// route from daemon-owned telemetry only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsicCommSnapshot {
    pub schema: String,
    pub source: String,
    pub chain_count: usize,
    pub chains_with_comm: usize,
    pub total_responding_chips: u32,
    pub chains: Vec<AsicCommChainSnapshot>,
}

impl AsicCommSnapshot {
    pub const SCHEMA: &'static str = "diagnostics.asic_comm v1";
    pub const SOURCE: &'static str =
        "live mining telemetry (state_rx); no live GetAddress broadcast issued";

    /// Build a canonical aggregate from already-retained daemon telemetry.
    pub fn from_chains(chains: Vec<AsicCommChainSnapshot>) -> Self {
        let chain_count = chains.len();
        let chains_with_comm = chains.iter().filter(|chain| chain.comm_ok).count();
        let total_responding_chips = chains
            .iter()
            .map(|chain| u32::from(chain.responding_chips))
            .sum();
        Self {
            schema: Self::SCHEMA.to_string(),
            source: Self::SOURCE.to_string(),
            chain_count,
            chains_with_comm,
            total_responding_chips,
            chains,
        }
    }

    /// Validate the canonical aggregate without probing or mutating hardware.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != Self::SCHEMA {
            return Err(format!(
                "unexpected ASIC communication schema {:?}",
                self.schema
            ));
        }
        if self.source != Self::SOURCE {
            return Err(format!(
                "unexpected ASIC communication source {:?}",
                self.source
            ));
        }
        if self.chain_count != self.chains.len() {
            return Err("ASIC communication chain_count does not match chains".to_string());
        }

        let mut chain_ids = std::collections::HashSet::new();
        let mut chains_with_comm = 0usize;
        let mut total_responding_chips = 0u32;
        for chain in &self.chains {
            if !chain_ids.insert(chain.chain_id) {
                return Err(format!(
                    "duplicate ASIC communication chain ID {}",
                    chain.chain_id
                ));
            }
            let expected_comm_ok = chain.responding_chips > 0;
            if chain.comm_ok != expected_comm_ok {
                return Err(format!(
                    "chain {} comm_ok disagrees with responding_chips",
                    chain.chain_id
                ));
            }
            chains_with_comm += usize::from(chain.comm_ok);
            total_responding_chips = total_responding_chips
                .checked_add(u32::from(chain.responding_chips))
                .ok_or_else(|| "ASIC communication responding-chip total overflow".to_string())?;
        }
        if self.chains_with_comm != chains_with_comm {
            return Err("ASIC communication chains_with_comm does not match chains".to_string());
        }
        if self.total_responding_chips != total_responding_chips {
            return Err(
                "ASIC communication total_responding_chips does not match chains".to_string(),
            );
        }
        Ok(())
    }
}

/// I2C bus scan result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct I2cScan {
    /// List of devices found on the bus.
    pub devices: Vec<I2cDevice>,
}

/// A single I2C device found during scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct I2cDevice {
    /// 7-bit I2C address.
    pub addr: u8,
    /// Address in hex format (e.g., "0x55").
    pub addr_hex: String,
    /// Identified device type.
    pub device_type: String,
    /// Human-readable description.
    pub description: String,
}

impl I2cDevice {
    /// Identify a known device at the given I2C address.
    pub fn identify(addr: u8) -> Self {
        let (device_type, description) = match addr {
            // NOTE: platform-agnostic identification. On S9 (am1) 0x55-0x57 are
            // PIC16F1704 voltage controllers; on am2 hashboards 0x50-0x57 are
            // write-protected serial EEPROMs (HAL write-denylist) — NOT PICs.
            // The description disambiguates so an am2 operator isn't misled into
            // treating these as voltage targets. (gap-swarm HAL-safety #10)
            0x55 => (
                "PIC16F1704",
                "Chain 6 (J6) voltage controller (S9) / write-protected EEPROM (am2)",
            ),
            0x56 => (
                "PIC16F1704",
                "Chain 7 (J7) voltage controller (S9) / write-protected EEPROM (am2)",
            ),
            0x57 => (
                "PIC16F1704",
                "Chain 8 (J8) voltage controller (S9) / write-protected EEPROM (am2)",
            ),
            0x48..=0x4F => ("TMP75", "Temperature sensor"),
            0x50..=0x57 => ("EEPROM", "Serial EEPROM (24C02 or similar)"),
            _ => ("Unknown", "Unknown device"),
        };

        Self {
            addr,
            addr_hex: format!("0x{:02X}", addr),
            device_type: device_type.to_string(),
            description: description.to_string(),
        }
    }
}

const MAX_I2C_OBSERVED_ENDPOINTS: usize = 1024;

/// Successful operation shape retained by the runtime I2C owner.
///
/// These labels describe evidence, not device identity. In particular, a
/// controller-shaped exchange cannot prove a PIC/dsPIC part number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum I2cObservedOperationKind {
    PicHeartbeat,
    PicVoltageCommand,
    PicSafeOff,
    DspicVoltageCommand,
    PicBootloaderStateRead,
    GenericWrite,
    GenericBytewiseWrite,
    GenericRead,
    HashboardEepromRead,
    Lm75TemperatureRead,
    GenericWriteRead,
    CompoundTransaction,
}

/// Conservative endpoint role supported by an operation's protocol shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum I2cObservedEndpointRole {
    ControllerProtocolEndpoint,
    HashboardEepromEndpoint,
    TemperatureSensorEndpoint,
    UnclassifiedEndpoint,
}

impl I2cObservedOperationKind {
    const fn expected_role(self) -> I2cObservedEndpointRole {
        match self {
            Self::HashboardEepromRead => I2cObservedEndpointRole::HashboardEepromEndpoint,
            Self::Lm75TemperatureRead => I2cObservedEndpointRole::TemperatureSensorEndpoint,
            Self::PicHeartbeat
            | Self::PicVoltageCommand
            | Self::PicSafeOff
            | Self::DspicVoltageCommand
            | Self::PicBootloaderStateRead => I2cObservedEndpointRole::ControllerProtocolEndpoint,
            Self::GenericWrite
            | Self::GenericBytewiseWrite
            | Self::GenericRead
            | Self::GenericWriteRead
            | Self::CompoundTransaction => I2cObservedEndpointRole::UnclassifiedEndpoint,
        }
    }
}

/// One source-owned positive I2C observation awaiting publication-time checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeOwnedI2cEndpointObservation {
    pub bus: u8,
    pub address: u8,
    pub operation: I2cObservedOperationKind,
    pub endpoint_role: I2cObservedEndpointRole,
    pub observed_at_ms: u64,
    pub successful_operation_count: u64,
}

/// Positive I2C evidence retained by serialized runtime owners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeOwnedI2cTelemetry {
    pub telemetry_source: String,
    /// Timestamp of the newest endpoint observation in `endpoints`.
    pub captured_at_ms: u64,
    pub endpoints: Vec<RuntimeOwnedI2cEndpointObservation>,
}

impl RuntimeOwnedI2cTelemetry {
    fn validate(&self) -> Result<(), String> {
        if self.telemetry_source.trim().is_empty()
            || self.telemetry_source.len() > MAX_TELEMETRY_SOURCE_BYTES
        {
            return Err("runtime-owned I2C telemetry source is blank or overlong".to_string());
        }
        if self.endpoints.is_empty() || self.endpoints.len() > MAX_I2C_OBSERVED_ENDPOINTS {
            return Err("runtime-owned I2C telemetry has an invalid endpoint count".to_string());
        }
        let mut keys = std::collections::HashSet::new();
        let mut newest = 0_u64;
        for endpoint in &self.endpoints {
            if endpoint.address > 0x7f {
                return Err(format!(
                    "runtime-owned I2C endpoint on bus {} has non-7-bit address 0x{:02X}",
                    endpoint.bus, endpoint.address
                ));
            }
            if !keys.insert((endpoint.bus, endpoint.address)) {
                return Err(format!(
                    "duplicate runtime-owned I2C endpoint bus {} address 0x{:02X}",
                    endpoint.bus, endpoint.address
                ));
            }
            if endpoint.endpoint_role != endpoint.operation.expected_role() {
                return Err(format!(
                    "runtime-owned I2C endpoint bus {} address 0x{:02X} relabels its operation role",
                    endpoint.bus, endpoint.address
                ));
            }
            if endpoint.observed_at_ms == 0 || endpoint.successful_operation_count == 0 {
                return Err(format!(
                    "runtime-owned I2C endpoint bus {} address 0x{:02X} lacks positive observation evidence",
                    endpoint.bus, endpoint.address
                ));
            }
            newest = newest.max(endpoint.observed_at_ms);
        }
        if self.captured_at_ms != newest {
            return Err(
                "runtime-owned I2C capture timestamp is not its newest endpoint observation"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// Coverage ceiling for the compatibility `I2cScan` diagnostic identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum I2cObservationCoverage {
    SuccessfulRuntimeOperationsOnly,
    Unavailable,
}

/// Publication-time endpoint view with independently evaluated age.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct I2cPublishedEndpointObservation {
    pub bus: u8,
    pub address: u8,
    pub address_hex: String,
    pub operation: I2cObservedOperationKind,
    pub endpoint_role: I2cObservedEndpointRole,
    pub observed_at_ms: u64,
    pub age_ms: u64,
    pub successful_operation_count: u64,
}

/// Passive compatibility result for the public `I2cScan` identity.
///
/// No scan is performed. The snapshot contains only positive acknowledgements
/// retained from operations that the serialized owner had already executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct I2cScanSnapshot {
    schema: String,
    source: String,
    provenance: PassiveTelemetryProvenance,
    telemetry_source: Option<String>,
    coverage: I2cObservationCoverage,
    scan_performed: bool,
    absence_inference_authorized: bool,
    evaluated_at_ms: Option<u64>,
    latest_observation_at_ms: Option<u64>,
    latest_observation_age_ms: Option<u64>,
    endpoint_count: Option<usize>,
    endpoints: Option<Vec<I2cPublishedEndpointObservation>>,
    unavailable_reason: Option<String>,
}

impl I2cScanSnapshot {
    pub const SCHEMA: &'static str = "diagnostics.i2c_scan v2";
    pub const SOURCE: &'static str = "serialized runtime-owner retained successful operations; no scan, probe, or new I2C transaction issued";

    pub(crate) fn from_runtime_owned_at(
        telemetry: RuntimeOwnedI2cTelemetry,
        publication_time_ms: u64,
    ) -> Result<Self, String> {
        telemetry.validate()?;
        let latest_age_ms = publication_time_ms
            .checked_sub(telemetry.captured_at_ms)
            .ok_or_else(|| {
                "runtime-owned I2C observation timestamp is in the future at publication"
                    .to_string()
            })?;
        let mut endpoints = Vec::with_capacity(telemetry.endpoints.len());
        for endpoint in telemetry.endpoints {
            let age_ms = publication_time_ms
                .checked_sub(endpoint.observed_at_ms)
                .ok_or_else(|| {
                    format!(
                        "runtime-owned I2C endpoint bus {} address 0x{:02X} is in the future at publication",
                        endpoint.bus, endpoint.address
                    )
                })?;
            endpoints.push(I2cPublishedEndpointObservation {
                bus: endpoint.bus,
                address: endpoint.address,
                address_hex: format!("0x{:02X}", endpoint.address),
                operation: endpoint.operation,
                endpoint_role: endpoint.endpoint_role,
                observed_at_ms: endpoint.observed_at_ms,
                age_ms,
                successful_operation_count: endpoint.successful_operation_count,
            });
        }
        endpoints.sort_by_key(|endpoint| (endpoint.bus, endpoint.address));
        let snapshot = Self {
            schema: Self::SCHEMA.to_string(),
            source: Self::SOURCE.to_string(),
            provenance: PassiveTelemetryProvenance::RuntimeOwnedRetainedObservation,
            telemetry_source: Some(telemetry.telemetry_source),
            coverage: I2cObservationCoverage::SuccessfulRuntimeOperationsOnly,
            scan_performed: false,
            absence_inference_authorized: false,
            evaluated_at_ms: Some(publication_time_ms),
            latest_observation_at_ms: Some(telemetry.captured_at_ms),
            latest_observation_age_ms: Some(latest_age_ms),
            endpoint_count: Some(endpoints.len()),
            endpoints: Some(endpoints),
            unavailable_reason: None,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub(crate) fn try_unavailable(reason: impl Into<String>) -> Result<Self, String> {
        let reason = reason.into();
        let reason = reason.trim();
        if reason.is_empty() || reason.len() > MAX_UNAVAILABLE_REASON_BYTES {
            return Err("unavailable I2C observation reason is blank or overlong".to_string());
        }
        let snapshot = Self {
            schema: Self::SCHEMA.to_string(),
            source: Self::SOURCE.to_string(),
            provenance: PassiveTelemetryProvenance::Unavailable,
            telemetry_source: None,
            coverage: I2cObservationCoverage::Unavailable,
            scan_performed: false,
            absence_inference_authorized: false,
            evaluated_at_ms: None,
            latest_observation_at_ms: None,
            latest_observation_age_ms: None,
            endpoint_count: None,
            endpoints: None,
            unavailable_reason: Some(reason.to_string()),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub(crate) fn publication_warnings(&self) -> Vec<String> {
        match self.coverage {
            I2cObservationCoverage::SuccessfulRuntimeOperationsOnly => vec![
                "I2C endpoint list is incomplete historical positive evidence from successful runtime-owner operations; unlisted addresses are unknown, not absent, and no device identity or health/pass verdict is granted".to_string(),
            ],
            I2cObservationCoverage::Unavailable => vec![format!(
                "I2C endpoint observations are unavailable: {}",
                self.unavailable_reason.as_deref().unwrap_or("unknown reason")
            )],
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != Self::SCHEMA || self.source != Self::SOURCE {
            return Err("unexpected passive I2C snapshot identity".to_string());
        }
        if self.scan_performed || self.absence_inference_authorized {
            return Err("passive I2C snapshot claims scan or absence authority".to_string());
        }
        match self.coverage {
            I2cObservationCoverage::Unavailable => {
                if self.provenance != PassiveTelemetryProvenance::Unavailable
                    || self.telemetry_source.is_some()
                    || self.evaluated_at_ms.is_some()
                    || self.latest_observation_at_ms.is_some()
                    || self.latest_observation_age_ms.is_some()
                    || self.endpoint_count.is_some()
                    || self.endpoints.is_some()
                    || self.unavailable_reason.as_deref().is_none_or(str::is_empty)
                {
                    return Err("unavailable passive I2C snapshot carries observations".to_string());
                }
            }
            I2cObservationCoverage::SuccessfulRuntimeOperationsOnly => {
                if self.provenance != PassiveTelemetryProvenance::RuntimeOwnedRetainedObservation
                    || self.unavailable_reason.is_some()
                {
                    return Err("available passive I2C snapshot has invalid provenance".to_string());
                }
                let telemetry_source = self.telemetry_source.clone().ok_or_else(|| {
                    "available passive I2C snapshot has no telemetry source".to_string()
                })?;
                let evaluated_at_ms = self.evaluated_at_ms.ok_or_else(|| {
                    "available passive I2C snapshot has no evaluation timestamp".to_string()
                })?;
                let captured_at_ms = self.latest_observation_at_ms.ok_or_else(|| {
                    "available passive I2C snapshot has no observation timestamp".to_string()
                })?;
                let endpoints = self.endpoints.clone().ok_or_else(|| {
                    "available passive I2C snapshot has no endpoint observations".to_string()
                })?;
                if self.endpoint_count != Some(endpoints.len()) {
                    return Err("passive I2C endpoint_count does not match endpoints".to_string());
                }
                let telemetry = RuntimeOwnedI2cTelemetry {
                    telemetry_source,
                    captured_at_ms,
                    endpoints: endpoints
                        .iter()
                        .map(|endpoint| RuntimeOwnedI2cEndpointObservation {
                            bus: endpoint.bus,
                            address: endpoint.address,
                            operation: endpoint.operation,
                            endpoint_role: endpoint.endpoint_role,
                            observed_at_ms: endpoint.observed_at_ms,
                            successful_operation_count: endpoint.successful_operation_count,
                        })
                        .collect(),
                };
                telemetry.validate()?;
                for endpoint in &endpoints {
                    if evaluated_at_ms.checked_sub(endpoint.observed_at_ms) != Some(endpoint.age_ms)
                    {
                        return Err(format!(
                            "passive I2C endpoint bus {} address 0x{:02X} age disagrees with timestamps",
                            endpoint.bus, endpoint.address
                        ));
                    }
                }
                if evaluated_at_ms.checked_sub(captured_at_ms) != self.latest_observation_age_ms {
                    return Err(
                        "passive I2C latest observation age disagrees with timestamps".to_string(),
                    );
                }
            }
        }
        Ok(())
    }
}
