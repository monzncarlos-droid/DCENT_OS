// SPDX-License-Identifier: GPL-3.0-or-later
//
// Minimal TOML config loader for the Avalon home daemon.
//
// Load order (first hit wins):
//   1. `$DCENTAXE_NANO3S_CONFIG` env var path
//   2. `/data/dcentaxe-nano3s.toml` (Linux on K230 rootfs)
//   3. `./dcentaxe-nano3s.toml` (next to the binary, dev convenience)
//   4. compiled-in defaults (solo.ckpool.org:3333 + AsicModel::Avalon defaults)
//
// Compiled defaults let the daemon start without a config file present so
// the wiring path is exercised end-to-end for smoke tests.

use anyhow::{Context, Result};
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
}

const ENV_VAR: &str = "DCENTAXE_NANO3S_CONFIG";
const SYS_PATH: &str = "/data/dcentaxe-nano3s.toml";
const LOCAL_PATH: &str = "./dcentaxe-nano3s.toml";

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
    Ok(Config::default_for_avalon())
}

fn load_from(p: &Path) -> Result<Config> {
    let raw = std::fs::read_to_string(p)?;
    let cfg: Config = toml::from_str(&raw)?;
    Ok(cfg)
}

impl Config {
    /// Compiled-in fallback. Pool points at solo.ckpool.org:3333 with a
    /// throwaway worker so the daemon does *something* when no config file
    /// is present. Replace via TOML in production.
    pub fn default_for_avalon() -> Self {
        Self {
            pool: PoolConfig {
                url: "solo.ckpool.org".to_string(),
                port: 3333,
                worker_name: "bc1qexampleworkerreplacewithyours".to_string(),
                password: "x".to_string(),
                version_rolling: true,
                suggest_difficulty: 0,
            },
            miner: MinerConfig {
                // Per dcentaxe_asic::AsicModel::Avalon::default_frequency()
                // — 500 MHz mid-range estimate from AVALON_ASIC_PROTOCOL.md §8.
                frequency_mhz: 500.0,
                asic_count: 0,
            },
        }
    }
}
