// SPDX-License-Identifier: GPL-3.0-or-later
//
// Minimal TOML config loader for the Avalon industrial daemon.
//
// Load order (first hit wins):
//   1. `$DCENTRALD_AVALON_CONFIG` env var path
//   2. `/data/dcentrald-avalon.toml` (Linux on K230 rootfs)
//   3. `./dcentrald-avalon.toml` (next to the binary, dev convenience)
//   4. fail closed when none exists (there is no compiled mining fallback)
//
// No compiled mining fallback exists: missing identity, pool, or operating
// parameters stop startup before any transport is opened.

use anyhow::{bail, Context, Result};
use dcent_avalon_proto::{
    board::{self, AvalonBoardProfile},
    nano3_profile::{self, Nano3TargetProfile},
};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub pool: PoolConfig,
    pub miner: MinerConfig,
}

#[derive(Deserialize, Debug, Clone)]
pub struct PoolConfig {
    pub url: String,
    pub port: u16,
    pub worker_name: String,
    pub password: String,
    #[serde(default)]
    pub version_rolling: bool,
    #[serde(default)]
    pub suggest_difficulty: u32,
}

#[derive(Deserialize, Debug, Clone)]
pub struct MinerConfig {
    pub frequency_mhz: f32,
    /// Optional explicit chip count; 0 means "let `driver.init` figure it out".
    #[serde(default)]
    pub asic_count: u8,
    /// Optional Avalon target id or product token (e.g. `"nano3"`, `"a15x"`).
    ///
    /// ADDITIVE and optional: when absent nothing changes. When present it is
    /// resolved against the separate Nano 3 profile and industrial board
    /// registry. An identity we do not hold evidence for is a HARD startup
    /// error. Nano 3S is explicitly unknown and never inherits Nano 3.
    ///
    /// Resolving a target supplies identity only. It does not supply mining or
    /// TX authority, frequency, voltage, tuning, or safety custody.
    #[serde(default)]
    pub model: Option<String>,
}

/// A resolved target keeps the K230 home profile distinct from the K210
/// industrial registry. In particular, Nano 3 telemetry must never make it an
/// `AvalonBoardProfile`, and Nano 3S must never inherit this non-S row.
#[derive(Debug, Clone, Copy)]
pub enum ResolvedTargetProfile {
    Industrial(&'static AvalonBoardProfile),
    Nano3(&'static Nano3TargetProfile),
}

const ENV_VAR: &str = "DCENTRALD_AVALON_CONFIG";
const SYS_PATH: &str = "/data/dcentrald-avalon.toml";
const LOCAL_PATH: &str = "./dcentrald-avalon.toml";

/// Load config from env-var path → /data → CWD → compiled defaults.
pub fn load() -> Result<Config> {
    if let Ok(env_path) = std::env::var(ENV_VAR) {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return load_from(&p).with_context(|| format!("loading {}", p.display()));
        }
    }
    let sys = Path::new(SYS_PATH);
    if sys.exists() {
        return load_from(sys).with_context(|| format!("loading {}", sys.display()));
    }
    let local = Path::new(LOCAL_PATH);
    if local.exists() {
        return load_from(local).with_context(|| format!("loading {}", local.display()));
    }
    bail!("no dcentrald-avalon config found; set {ENV_VAR} or install {SYS_PATH}")
}

fn load_from(p: &Path) -> Result<Config> {
    let raw = std::fs::read_to_string(p)?;
    let cfg: Config = toml::from_str(&raw)?;
    Ok(cfg)
}

impl Config {
    /// Test-only fixture. Production builds do not contain a fallback config.
    #[cfg(test)]
    pub fn default_for_avalon() -> Self {
        Self {
            pool: PoolConfig {
                url: "127.0.0.1".to_string(),
                port: 1,
                worker_name: "test.worker".to_string(),
                password: "x".to_string(),
                version_rolling: true,
                suggest_difficulty: 0,
            },
            miner: MinerConfig {
                // Per dcentaxe_asic::AsicModel::Avalon::default_frequency()
                // — 500 MHz mid-range estimate from AVALON_ASIC_PROTOCOL.md §8.
                frequency_mhz: 100.0,
                asic_count: 0,
                // No model is asserted by default. We do not guess a SKU.
                model: None,
            },
        }
    }

    /// Resolve `[miner].model` against the industrial Avalon board registry.
    ///
    /// * `Ok(None)`   — no model configured; the registry is not consulted.
    /// * `Ok(Some(p))`— a SKU we hold firmware bytes for.
    /// * `Err(..)`    — configured but unknown. Fail-closed by design.
    pub fn resolve_board(&self) -> Result<Option<&'static AvalonBoardProfile>> {
        match self.miner.model.as_deref() {
            None => Ok(None),
            Some(m) => board::resolve(m).map(Some).map_err(anyhow::Error::from),
        }
    }

    /// Resolve either the explicit non-S Nano 3 profile or an industrial board.
    ///
    /// Nano-family resolution runs first only to distinguish Nano 3S as a
    /// separate unknown target. Unrelated models then go to the existing K210
    /// industrial registry; no profile is projected between the two.
    pub fn resolve_target(&self) -> Result<Option<ResolvedTargetProfile>> {
        let Some(model) = self.miner.model.as_deref() else {
            return Ok(None);
        };
        if let Some(profile) = nano3_profile::resolve(model).map_err(anyhow::Error::from)? {
            return Ok(Some(ResolvedTargetProfile::Nano3(profile)));
        }
        board::resolve(model)
            .map(ResolvedTargetProfile::Industrial)
            .map(Some)
            .map_err(anyhow::Error::from)
    }

    /// Validate all mining inputs and require a target profile whose chain
    /// parameters and safety custody have been explicitly approved.
    ///
    /// Current descriptive-only profiles intentionally fail here. The passive
    /// stock observer returns before config loading, so it remains available.
    pub fn validate_for_mining(&self) -> Result<ResolvedTargetProfile> {
        if self.pool.url.trim().is_empty() {
            bail!("[pool].url must not be empty");
        }
        if self.pool.port == 0 {
            bail!("[pool].port must be non-zero");
        }
        if self.pool.worker_name.trim().is_empty() {
            bail!("[pool].worker_name must not be empty");
        }
        if !self.miner.frequency_mhz.is_finite() || self.miner.frequency_mhz <= 0.0 {
            bail!("[miner].frequency_mhz must be finite and positive");
        }

        let profile = self
            .resolve_target()?
            .context("[miner].model is required; model guessing is forbidden")?;
        match profile {
            ResolvedTargetProfile::Nano3(nano3) => {
                nano3.validate_for_mining().map_err(anyhow::Error::from)?;
            }
            ResolvedTargetProfile::Industrial(board) if !board.is_energizable() => {
                bail!(
                    "board profile {} is descriptive-only; chain parameters and safety custody are not production-approved",
                    board.model_id
                );
            }
            ResolvedTargetProfile::Industrial(_) => {}
        }
        Ok(profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_model(model: Option<&str>) -> Config {
        let mut c = Config::default_for_avalon();
        c.miner.model = model.map(str::to_string);
        c
    }

    /// PRODUCTION-WIRING TEST. `board::resolve` having its own tests proves the
    /// resolver; this proves the DAEMON actually calls it and with the operator's
    /// value — the gap that lets a capability go test-only-reachable.
    #[test]
    fn a_configured_model_is_resolved_through_the_registry() {
        let p = cfg_with_model(Some("a15x"))
            .resolve_board()
            .expect("a held SKU must resolve")
            .expect("Some");
        assert_eq!(p.model_id, "a15x");
        assert_eq!(p.silicon.archive_token(), "A3197S");

        // Product tokens work too, and so does the two-product image name.
        assert_eq!(
            cfg_with_model(Some("A1466HS_A14x"))
                .resolve_board()
                .unwrap()
                .unwrap()
                .model_id,
            "a1466hs"
        );
    }

    #[test]
    fn nano3_resolves_through_a_distinct_non_s_k230_profile() {
        let target = cfg_with_model(Some("nano3"))
            .resolve_target()
            .expect("held non-S target must resolve")
            .expect("Some");
        let ResolvedTargetProfile::Nano3(profile) = target else {
            panic!("Nano 3 must not resolve through the industrial board registry")
        };
        assert_eq!(profile.controller_soc.to_string(), "K230");
        assert_eq!(profile.linux_chain_uart, "/dev/ttyS1");
        assert_eq!(profile.required_observed_asic_count, 10);
        assert_eq!(profile.enumeration_baud, 115_200);
        assert!(!profile.native_tx_authorized());
        assert!(!profile.is_energizable());

        // The existing industrial-only API remains unable to project Nano 3
        // into a K210/A3198S row.
        assert!(cfg_with_model(Some("nano3")).resolve_board().is_err());
    }

    #[test]
    fn an_unknown_model_is_a_hard_startup_error_not_a_fallback() {
        // Avalon Q is genuinely in this daemon's product scope, and we hold no
        // firmware for it — it must NOT silently resolve to a neighbour.
        for unknown in ["avalon-q", "a16xx", "nano3s", "totally-made-up"] {
            let err = cfg_with_model(Some(unknown))
                .resolve_board()
                .expect_err("unknown model must fail closed");
            assert!(err.to_string().contains(unknown), "{err}");
        }
    }

    #[test]
    fn nano3s_is_a_separate_unknown_target_not_a_nano3_alias() {
        let err = cfg_with_model(Some("nano3s"))
            .resolve_target()
            .expect_err("Nano 3S must not inherit the non-S profile");
        assert!(err.to_string().contains("separate and unknown"), "{err}");
    }

    #[test]
    fn no_model_means_the_registry_is_not_consulted() {
        assert!(cfg_with_model(None).resolve_board().unwrap().is_none());
        assert!(Config::default_for_avalon().miner.model.is_none());
    }

    #[test]
    fn mining_validation_requires_identity_and_approved_chain_parameters() {
        let missing = cfg_with_model(None)
            .validate_for_mining()
            .expect_err("missing identity must fail before transport open");
        assert!(
            missing.to_string().contains("model is required"),
            "{missing}"
        );

        let descriptive = cfg_with_model(Some("a15x"))
            .validate_for_mining()
            .expect_err("descriptive profile must not energize hardware");
        assert!(
            descriptive.to_string().contains("descriptive-only"),
            "{descriptive}"
        );

        let nano3 = cfg_with_model(Some("nano3"))
            .validate_for_mining()
            .expect_err("Nano 3 identity alone must not authorize mining");
        let message = nano3.to_string();
        for required in [
            "independent normally-open whole-device hash-power cut",
            "complete native Nano 3 init/job contract",
            "cooling-actuator custody",
            "temperature-sensor custody",
            "watchdog custody",
        ] {
            assert!(
                message.contains(required),
                "missing `{required}` in {message}"
            );
        }
    }

    #[test]
    fn mining_validation_rejects_invalid_pool_and_frequency() {
        let mut cfg = cfg_with_model(Some("a15x"));
        cfg.pool.url.clear();
        assert!(cfg
            .validate_for_mining()
            .unwrap_err()
            .to_string()
            .contains("url"));

        let mut cfg = cfg_with_model(Some("a15x"));
        cfg.pool.port = 0;
        assert!(cfg
            .validate_for_mining()
            .unwrap_err()
            .to_string()
            .contains("port"));

        let mut cfg = cfg_with_model(Some("a15x"));
        cfg.miner.frequency_mhz = f32::NAN;
        assert!(cfg
            .validate_for_mining()
            .unwrap_err()
            .to_string()
            .contains("frequency"));
    }

    /// Resolving a board must not hand the daemon anything it could energize.
    #[test]
    fn resolving_a_board_yields_no_frequency_voltage_or_preset() {
        let p = cfg_with_model(Some("a1566hs"))
            .resolve_board()
            .unwrap()
            .unwrap();
        assert!(!p.is_energizable());
        assert!(p.chain_parameters().is_err());
        assert!(p.tuning_presets.is_empty());
    }

    #[test]
    fn the_model_field_is_optional_in_toml_and_absent_by_default() {
        // Pre-existing configs (no `model` key) must still parse unchanged.
        let legacy = r#"
            [pool]
            url = "solo.ckpool.org"
            port = 3333
            worker_name = "w"
            password = "x"

            [miner]
            frequency_mhz = 480.0
        "#;
        let cfg: Config = toml::from_str(legacy).expect("legacy config must still parse");
        assert_eq!(cfg.miner.frequency_mhz, 480.0);
        assert!(cfg.miner.model.is_none());
        assert!(cfg.resolve_board().unwrap().is_none());

        let with_model = format!("{legacy}\n            model = \"a14xi\"\n");
        let cfg: Config = toml::from_str(&with_model).expect("model key must parse");
        assert_eq!(cfg.resolve_board().unwrap().unwrap().model_id, "a14xi");
    }
}
