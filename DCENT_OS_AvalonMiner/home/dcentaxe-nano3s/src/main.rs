// SPDX-License-Identifier: GPL-3.0-or-later
//
// DCENT_axe Avalon — entry point for the Canaan Avalon Nano 3 / Nano 3S / Mini 3.
//
// PLAN 3 (2026-05-02): full run-loop wiring. Connects to a Stratum pool,
// dispatches jobs into the AvalonShimDriver (which talks SysV msgq → Canaan's
// asic_miner_e RT-Smart blob), polls for nonces.
//
// Will not produce real shares until Plan 4 fills in the SET_JOB sub-frame
// payload layout (currently a Plan-2 stub). The wiring path is exercised
// end-to-end so we know the types compose and the process starts.
//
// References:
//   -  (Plan 3)
//   - dcentos-esp/dcentaxe/src/main.rs:1868-2020 — wiring template
//

mod bridge;
mod config;

use anyhow::Result;
use tracing::{error, info};

/// Mining-loop pacing. The dispatcher's own job-dispatch interval governs
/// rate; this just keeps the busy loop from pegging the CPU between ticks.
#[cfg(unix)]
const LOOP_TICK_MS: u64 = 10;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("dcentaxe-nano3s {} starting", env!("CARGO_PKG_VERSION"));
    info!("target: Canaan Avalon Nano 3 / Nano 3S / Mini 3 (K230 RISC-V Linux)");

    let board = dcentaxe_nano3s_hal::detect_platform();
    info!(?board, "platform detection complete");

    let cfg = config::load()?;
    info!(
        pool_url = %cfg.pool.url,
        pool_port = cfg.pool.port,
        worker = %cfg.pool.worker_name,
        target_freq = cfg.miner.frequency_mhz,
        "config loaded"
    );

    // ── ASIC driver ──────────────────────────────────────────────────────────
    //
    // On Unix: open the SysV msgq AvalonShimDriver and run init(). On Windows
    // (or non-Unix host): exit gracefully — the SysV msgq transport is Unix-only.
    #[cfg(not(unix))]
    {
        error!("dcentaxe-nano3s requires a Unix host (SysV msgq is unsupported on Windows)");
        return Ok(());
    }

    #[cfg(unix)]
    {
        run_unix_main(&cfg)
    }
}

/// Lab-only escape hatch for the pre-loop SoC-die temp guard. Same operator
/// vocabulary as the ESP tree's bench bypass. Default OFF; bypassing is
/// loudly logged.
#[cfg(unix)]
const UNSAFE_LAB_SAFETY_BYPASS_ENV: &str = "DCENTAXE_UNSAFE_LAB_SAFETY_BYPASS";

/// K230 on-die sensor documented range: -40..=125 °C (±3 °C), per
/// . Readings outside
/// this window mean a broken/implausible sensor, which counts as NO telemetry.
#[cfg(unix)]
const K230_DIE_MILLIC_MIN: i32 = -40_000;
#[cfg(unix)]
const K230_DIE_MILLIC_MAX: i32 = 125_000;

/// Pre-loop thermal guard — **SoC-die-only. This is NOT hashboard thermal
/// protection.**
///
/// HONEST LABEL (Wave 6 R4c): the only sensors this can see are the K230's
/// hwmon inputs (on-die sensor). The hashboard NTCs are not wired up in this
/// HAL (temp.rs header: they "wait on teardown confirmation"), so a hashboard
/// can overheat without this guard ever noticing. All this guard proves is
/// that we do not enter an unbounded mining loop with ZERO thermal telemetry
/// of any kind. It is a one-shot startup check; there is no in-loop thermal
/// supervision yet.
///
/// Returns true when at least one plausible SoC-die reading resolved (or the
/// explicit lab bypass is set).
#[cfg(unix)]
fn soc_die_only_preloop_temp_guard() -> bool {
    use tracing::warn;

    let ok = match dcentaxe_nano3s_hal::temp::read_all_temps() {
        Ok(temps) => {
            for (label, millic) in &temps {
                info!(
                    label = %label,
                    millicelsius = millic,
                    "pre-loop SoC-die-only temp reading"
                );
            }
            temps
                .iter()
                .any(|(_, mc)| (K230_DIE_MILLIC_MIN..=K230_DIE_MILLIC_MAX).contains(mc))
        }
        Err(e) => {
            error!(error = %e, "SoC-die-only pre-loop temp guard: hwmon read failed");
            false
        }
    };
    if ok {
        return true;
    }
    if std::env::var(UNSAFE_LAB_SAFETY_BYPASS_ENV).ok().as_deref() == Some("1") {
        warn!(
            "{}=1 set — entering mining loop with NO SoC-die temperature telemetry (lab only). \
             Reminder: this guard was SoC-die-only anyway; hashboard NTCs are not wired either way.",
            UNSAFE_LAB_SAFETY_BYPASS_ENV
        );
        return true;
    }
    false
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
    use dcentaxe_nano3s_asic::AvalonShimDriver;
    use dcentaxe_stratum::{MiningEvent, MiningWork, StratumClient, StratumConfig, StratumEvent};

    // ── Pre-loop thermal guard (SoC-die-only — NOT hashboard protection) ────
    // Runs BEFORE the driver is opened so we refuse before engaging any
    // hardware at all (cut-hash-power-first posture).
    if !soc_die_only_preloop_temp_guard() {
        error!(
            "refusing to enter mining loop: no plausible SoC-die temperature reading resolved. \
             This guard is SoC-die-only (hashboard NTCs are not wired in this HAL), so passing it \
             is NOT hashboard thermal protection — but running with zero thermal telemetry is \
             worse. Bench override: {}=1.",
            UNSAFE_LAB_SAFETY_BYPASS_ENV
        );
        return Ok(());
    }

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

    // Wrap in RefCell so all three dispatcher closures can borrow_mut.
    // !Send so the run loop must stay on the main thread (we don't spawn a
    // tokio task here); StratumClient handles its own thread.
    let driver_cell: RefCell<Box<dyn AsicDriver>> = RefCell::new(Box::new(driver));

    // ── Channels ─────────────────────────────────────────────────────────────
    //
    // event_tx (StratumClient) → event_rx (MiningDispatcher): jobs, diff, mask.
    // share_tx (MiningDispatcher) → share_rx (StratumClient): shares to submit.
    let (event_tx, event_rx) = mpsc::channel::<StratumEvent>();
    let (share_tx, share_rx) = mpsc::channel::<MiningEvent>();

    // ── Stratum client thread ────────────────────────────────────────────────
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

    // ── Dispatcher ───────────────────────────────────────────────────────────
    let asic_count_for_cfg = if detected > 0 { detected } else { 12 };
    let dispatcher_cfg = DispatcherConfig::for_avalon(cfg.miner.frequency_mhz, asic_count_for_cfg);
    let mut dispatcher = MiningDispatcher::new(event_rx, share_tx, dispatcher_cfg);
    info!("MiningDispatcher constructed");

    // ── Closures ─────────────────────────────────────────────────────────────
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

    info!("entering mining loop (Plan 4 will add SET_JOB sub-frame layout for real hashes)");
    let max = AsicModel::Avalon.max_frequency();
    let min = AsicModel::Avalon.min_frequency();
    info!(min_freq = min, max_freq = max, "Avalon frequency envelope");

    // ── Mining loop ──────────────────────────────────────────────────────────
    loop {
        dispatcher.run_once(&mut send_work_fn, &mut process_work_fn, &mut apply_hw_fn);
        std::thread::sleep(Duration::from_millis(LOOP_TICK_MS));
    }
}
