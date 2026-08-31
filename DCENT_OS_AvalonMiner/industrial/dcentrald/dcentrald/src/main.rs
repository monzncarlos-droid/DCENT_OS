// SPDX-License-Identifier: GPL-3.0-or-later
//
// DCENT_OS Avalon — mining daemon for explicitly profiled Canaan targets.
//
// Industrial scope (Plan 1 / 2 locked):
//   - Avalon Q (1700W full box — industrial per its PSU class)
//   - A14xx (BM/A3198S, K230)
//   - A15xx (A3197S, K230) — current top of the industrial line
//   - A16xx (when shipped) — likely K230
//   - K210 industrial (A1346/A1146/A1066) — research stub only, FreeRTOS bare-metal
// Home target kept distinct from those industrial profiles:
//   - Avalon Nano 3 non-S (K230) — identity/RX facts only; TX/mining fail closed
//
// PLAN 3 (2026-05-02): full run-loop wiring. Mirror of the home daemon
// (`dcentaxe-nano3s`). Single-chain only — multi-hashboard TCA9546A I2C mux
// support deferred to a future plan once we have an A14xx/A15xx unit.
//
// References:
//   -  (Plan 3)
//   - dcentos-esp/dcentaxe/src/main.rs:1868-2020 — wiring template
//
//   -  — Avalon_mm is BUSL-1.1, cleanroom RE only

mod bridge;
mod config;
mod nano3_observer;
pub mod nano3_safety;
pub mod nano3_watchdog;
pub mod nano3_watchdog_backend;
mod ownership;
mod platform;
mod stock_observer;

use anyhow::Result;
use tracing::{error, info};

#[cfg(unix)]
const LOOP_TICK_MS: u64 = 10;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--stock-observer-once"))
    {
        return stock_observer::run_once();
    }

    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new("--nano3-read-only-observer-once"))
    {
        #[cfg(not(unix))]
        anyhow::bail!("Nano 3 read-only observation requires a Unix target");

        #[cfg(unix)]
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(nano3_observer::run_once());
    }

    info!("dcentrald-avalon {} starting", env!("CARGO_PKG_VERSION"));
    info!("target: explicitly profiled Canaan Avalon devices (Nano 3 non-S + industrial)");

    let board = platform::detect_platform();
    info!(?board, "platform detection complete");

    let cfg = config::load()?;
    info!(
        pool_url = %cfg.pool.url,
        pool_port = cfg.pool.port,
        worker = %cfg.pool.worker_name,
        target_freq = cfg.miner.frequency_mhz,
        "config loaded"
    );

    // Resolve and report identity before the fail-closed mining gate. This is
    // still pure data: no transport or actuator is opened here. Nano 3 has its
    // own K230/non-S identity-only profile and is never projected into the K210
    // industrial registry.
    match cfg.resolve_target()? {
        Some(config::ResolvedTargetProfile::Industrial(profile)) => info!(
            model = profile.model_id,
            product = profile.product_token,
            silicon = %profile.silicon,
            hw_tag = profile.mm_hw_tag,
            firmware_ver = profile.firmware_ver,
            energizable = profile.is_energizable(),
            "board profile resolved from registry (descriptive only — no chain parameters)"
        ),
        Some(config::ResolvedTargetProfile::Nano3(profile)) => info!(
            model = profile.model_id,
            product = profile.product_name,
            variant = %profile.variant,
            controller_soc = %profile.controller_soc,
            chain_uart = profile.linux_chain_uart,
            required_observed_asics = profile.required_observed_asic_count,
            enumeration_baud = profile.enumeration_baud,
            native_tx_authorized = profile.native_tx_authorized(),
            energizable = profile.is_energizable(),
            "Nano 3 target profile resolved (identity only; non-3S; no TX or mining authority)"
        ),
        None => info!("no [miner].model configured; target registries not consulted"),
    }

    // Final fail-closed gate before `run_unix_main` can open mm_pkg or any
    // future native UART transport. The explicit Nano 3 error names every
    // missing independent cut/TX/cooling/sensor/watchdog custody requirement.
    let _production_profile = cfg.validate_for_mining()?;

    #[cfg(not(unix))]
    {
        error!("dcentrald-avalon requires a Unix host (SysV msgq is unsupported on Windows)");
        return Ok(());
    }

    #[cfg(unix)]
    {
        run_unix_main(&cfg)
    }
}

#[cfg(unix)]
fn run_unix_main(cfg: &config::Config) -> Result<()> {
    use std::cell::RefCell;
    use std::sync::mpsc;
    use std::time::Duration;

    use tracing::{debug, warn};

    use dcentaxe_asic::common::{AsicModel, AsicResult};
    use dcentaxe_asic::AsicDriver;
    use dcentaxe_mining::dispatcher::{DispatcherConfig, MiningDispatcher};
    use dcentaxe_stratum::{MiningEvent, MiningWork, StratumClient, StratumConfig, StratumEvent};
    use dcentrald_avalon_asic::AvalonShimDriver;

    let mut driver = match AvalonShimDriver::open_default() {
        Ok(d) => {
            info!("AvalonShimDriver opened");
            d
        }
        Err(e) => {
            warn!(error = %e, "AvalonShimDriver::open_default() failed (no asic_miner blob running?)");
            return Ok(());
        }
    };

    let chip_count_hint = cfg.miner.asic_count;
    let detected = match driver.init(cfg.miner.frequency_mhz, chip_count_hint, 256.0) {
        Ok(n) => {
            info!(chips = n, "driver.init() succeeded");
            n
        }
        Err(e) => {
            warn!(error = %e, "driver.init() failed — daemon exiting (Plan 4 will add a retry loop)");
            return Ok(());
        }
    };

    let driver_cell: RefCell<Box<dyn AsicDriver>> = RefCell::new(Box::new(driver));

    let (event_tx, event_rx) = mpsc::channel::<StratumEvent>();
    let (share_tx, share_rx) = mpsc::channel::<MiningEvent>();

    let stratum_config = StratumConfig {
        url: cfg.pool.url.clone(),
        port: cfg.pool.port,
        worker_name: cfg.pool.worker_name.clone(),
        password: cfg.pool.password.clone(),
        suggest_difficulty: cfg.pool.suggest_difficulty,
        version_rolling: cfg.pool.version_rolling,
    };
    let _stratum = std::thread::Builder::new()
        .name("stratum".into())
        .spawn(move || {
            let mut client = StratumClient::new(stratum_config, event_tx, share_rx);
            client.run();
            warn!("StratumClient::run returned — pool thread exiting");
        })
        .expect("failed to spawn stratum thread");

    // Industrial single-chain bring-up uses the host's chip-count hint (or
    // detected count from init). Multi-hashboard mux (TCA9546A) deferred —
    // this constructor pretends one big chain.
    let asic_count_for_cfg = if detected > 0 { detected } else { 100 };
    let dispatcher_cfg = DispatcherConfig::for_avalon(cfg.miner.frequency_mhz, asic_count_for_cfg);
    let mut dispatcher = MiningDispatcher::new(event_rx, share_tx, dispatcher_cfg);
    info!("MiningDispatcher constructed (single-chain — mux deferred)");

    let mut send_work_fn = |work: &MiningWork, job_id: u8| -> Result<(), String> {
        let job = bridge::avalon_work_to_job(work, job_id);
        driver_cell
            .borrow_mut()
            .send_work(&job)
            .map_err(|e| e.to_string())
    };

    let mut process_work_fn = || -> Vec<(u8, u32, u32, u32, u8)> {
        match driver_cell.borrow_mut().read_responses(LOOP_TICK_MS as u16) {
            Ok(rs) => rs
                .into_iter()
                .filter_map(|r| match r {
                    AsicResult::Nonce {
                        job_id,
                        nonce,
                        rolled_version,
                        rolled_ntime,
                        asic_nr,
                        ..
                    } => Some((job_id, nonce, rolled_version, rolled_ntime, asic_nr)),
                    AsicResult::Register { .. } => None,
                })
                .collect(),
            Err(e) => {
                debug!(error = %e, "read_responses failed");
                Vec::new()
            }
        }
    };

    let mut apply_hw_fn = |new_diff: Option<f64>, new_mask: Option<u32>| {
        if let Some(mask) = new_mask {
            if let Err(e) = driver_cell.borrow_mut().set_version_mask(mask) {
                error!(error = %e, "set_version_mask failed");
            }
        }
        if let Some(diff) = new_diff {
            if let Err(e) = driver_cell.borrow_mut().set_difficulty(diff) {
                error!(error = %e, "set_difficulty failed");
            }
        }
    };

    info!("entering mining loop (Plan 4 will fill SET_JOB sub-frame layout)");
    let max = AsicModel::Avalon.max_frequency();
    let min = AsicModel::Avalon.min_frequency();
    info!(min_freq = min, max_freq = max, "Avalon frequency envelope");

    loop {
        dispatcher.run_once(&mut send_work_fn, &mut process_work_fn, &mut apply_hw_fn);
        std::thread::sleep(Duration::from_millis(LOOP_TICK_MS));
    }
}
