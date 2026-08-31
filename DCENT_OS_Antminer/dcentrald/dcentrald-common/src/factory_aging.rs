//! In-miner factory aging / frequency-scan planner (desk-only).
//!
//! Capability-first: geometry, sweep tables, and force-mode dispatch are
//! data. The first filled profile is the held T11 `freq_scan.c` tree used by
//! S9k and S9 SE. Adding another package/bin is another row, not a new
//! executor.
//!
//! Evidence (this increment):
//! - S9k unstripped `cgminer` SHA-256
//!   `d09c482f9f5f7358f355dea427005eb9fc7db87efdd52e8dbe3f14e0f38118e7`
//!   `init_sweep_config@26590`, `scan_freq_init_info@30E04`,
//!   `boardsweep_get_next_freq@394B6`, `asic_sweep_stat_end@38468`,
//!   `.rodata` VA `0x27310` aging offset `0.4` V.
//! - Official S9 SE OM-20190918 `cgminer` SHA-256
//!   `4c05228fac5f682887c8da8b851793ae3759f72167a0bd443b60a7373197c82e`
//!   and HiveOS sibling `e113eab6…c9fb` both contain
//!   `sweep config for eco mode`, `scan_freq_scan_by_column`,
//!   `minertest64-BM1393`, `freq_scan.c`. Official/Hive do **not** contain
//!   the `boardsweep` / `is_force_mode` strings (those stay S9k-named).
//!
//! This module never opens UART, mmap, EEPROM, or a rail. Pattern-file
//! prefixes are labels, not filesystem authority.

use crate::s9se_enum::S9SE_CHIPS_PER_CHAIN;
use crate::s9se_identity::FACTORY_VOLTAGE_TOKEN;
use crate::s9se_voltage::FACTORY_CONF_VOLTAGE_V;

/// S9k / S9 SE `scan_freq_init_info` `AsicNum`.
pub const SCAN_ASIC_NUM: u16 = 60;
/// `scan_freq_init_info` `CoreNum` / `open_core_bm1393`.
pub const SCAN_CORE_NUM: u16 = 208;
/// `60 * 208` — `boardsweep_send_work_and_check_result` hashrate scale.
pub const SCAN_HASHRATE_SCALE: u32 = 12_480;
/// `scan_freq_init_info` `freq_step = 5`.
pub const SCAN_FREQ_STEP_MHZ: u16 = 5;
/// `boardsweep_get_next_freq`: `next = 2 * freq_step + base`.
pub const BOARDSWEEP_STEP_MULTIPLIER: u16 = 2;
/// Column loop `column <= 9`.
pub const SCAN_COLUMN_COUNT: u8 = 10;
/// Chain slot loop `chain <= 15`.
pub const SCAN_CHAIN_SLOT_COUNT: u8 = 16;
/// `freq_index_max[chain][column] = 40`.
pub const SCAN_FREQ_INDEX_MAX: u8 = 40;
/// `asic_sweep_stat_end` per-chip stride.
pub const SWEEP_STATE_PER_CHIP: u32 = 40;
/// Per-chain stride `2400 = 60 * 40`.
pub const SWEEP_STATE_PER_CHAIN: u32 = 2_400;
/// `40 * chip + 2400 * chain + level < 38400`.
pub const SWEEP_STATE_TOTAL: u32 = 38_400;
/// `scan_freq_init_info` `PassNonceRate = 0.99`.
pub const SCAN_PASS_NONCE_RATE_NUM: u32 = 99;
pub const SCAN_PASS_NONCE_RATE_DEN: u32 = 100;
/// `boardsweep_send_work_and_check_result` `AsicWorkCount * 0.98`.
pub const BOARDSWEEP_PASS_NONCE_RATE_NUM: u32 = 98;
pub const BOARDSWEEP_PASS_NONCE_RATE_DEN: u32 = 100;
/// `succeed_freq_cnt <= 1` marks the ASIC bad (`asic_sweep_stat_end`).
pub const BAD_ASIC_MAX_SUCCEED_FREQ: u32 = 1;
/// `freq_scan_error_code_set(14, chain)`.
pub const SWEEP_ERROR_FEW_SUCCEED_FREQ: u8 = 14;
/// S9k `.rodata` VA `0x27310` little-endian double.
pub const AGING_VOLTAGE_OFFSET_MV: u32 = 400;
/// `scan_freq_init_info` work prefix. Not a path open.
pub const SCAN_WORK_PATH_PREFIX: &str = "/log/minertest64-BM1393/btc-asic-";
pub const SCAN_WORK_FILE_PREFIX: &str = "/btc-core-";

pub const S9K_CGMINER_SHA256: &str =
    "d09c482f9f5f7358f355dea427005eb9fc7db87efdd52e8dbe3f14e0f38118e7";
pub const S9SE_OFFICIAL_CGMINER_SHA256: &str =
    "4c05228fac5f682887c8da8b851793ae3759f72167a0bd443b60a7373197c82e";
pub const S9SE_HIVE_CGMINER_SHA256: &str =
    "e113eab6d2480ec1596f23992ce013b855196821b276760441c2bc060d9bc9fb";

/// EEPROM byte 248 bits[5:3] `0` is BSL (`statusServiceThread`). Other
/// package names are used as selector keys; their numeric codes are not
/// invented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChipPackage {
    Bsl,
    Be,
    BBgm,
    BeBgm,
    Ce,
}

/// EEPROM byte 248 bits[7:6] `0` is BIN1. Sequential BIN2/3/4 follow the
/// `if (bin_level)` / `> BIN2` / `== BIN3` nest in `init_sweep_config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChipBin {
    Bin1,
    Bin2,
    Bin3,
    Bin4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepMode {
    Eco,
    Hpf,
}

/// `bitmain_soc_init` force-mode branch after `init_sweep_config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForceModeDispatch {
    /// `is_column_sweep()` → `sweep_freq_by_column()`.
    SweepByColumn,
    /// `is_board_sweep()` → `boardsweep_task()`.
    BoardSweep,
    /// else → `scan_freq_scan_by_column()`.
    ScanByColumn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepConfig {
    pub min_freq_mhz: u16,
    pub max_freq_mhz: u16,
    pub start_voltage_mv: u32,
    pub max_aging_voltage_mv: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepPair {
    pub eco: SweepConfig,
    pub hpf: SweepConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanGeometry {
    pub asic_num: u16,
    pub core_num: u16,
    pub freq_step_mhz: u16,
    pub columns: u8,
    pub chain_slots: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactoryAgingError {
    UnknownSweepTable,
    FrequencyRangeInvalid,
    FactoryTokenIsNotSweepStart,
    PatternPathIsNotRuntimeWork,
    ExecuteRefused,
}

pub const T11_SCAN_GEOMETRY: ScanGeometry = ScanGeometry {
    asic_num: SCAN_ASIC_NUM,
    core_num: SCAN_CORE_NUM,
    freq_step_mhz: SCAN_FREQ_STEP_MHZ,
    columns: SCAN_COLUMN_COUNT,
    chain_slots: SCAN_CHAIN_SLOT_COUNT,
};

/// S9 SE is `cgminer_1393` CE. BIN1/BIN2 share this table
/// (`init_sweep_config` PKG_CE / `_g_bin_level <= BIN2`).
pub const T11_CE_BIN1_OR_BIN2: SweepPair = SweepPair {
    eco: SweepConfig {
        min_freq_mhz: 300,
        max_freq_mhz: 380,
        start_voltage_mv: 8_600,
        max_aging_voltage_mv: 8_600 + AGING_VOLTAGE_OFFSET_MV,
    },
    hpf: SweepConfig {
        min_freq_mhz: 415,
        max_freq_mhz: 465,
        start_voltage_mv: 9_200,
        max_aging_voltage_mv: 9_200 + AGING_VOLTAGE_OFFSET_MV,
    },
};

/// PKG_CE / `_g_bin_level > BIN2`.
pub const T11_CE_BIN3_OR_BIN4: SweepPair = SweepPair {
    eco: SweepConfig {
        min_freq_mhz: 310,
        max_freq_mhz: 360,
        start_voltage_mv: 9_100,
        max_aging_voltage_mv: 9_100 + AGING_VOLTAGE_OFFSET_MV,
    },
    hpf: SweepConfig {
        min_freq_mhz: 400,
        max_freq_mhz: 450,
        start_voltage_mv: 9_400,
        max_aging_voltage_mv: 9_400 + AGING_VOLTAGE_OFFSET_MV,
    },
};

pub fn admit_scan_geometry() -> Result<ScanGeometry, FactoryAgingError> {
    if u16::from(S9SE_CHIPS_PER_CHAIN) != SCAN_ASIC_NUM {
        return Err(FactoryAgingError::UnknownSweepTable);
    }
    if SCAN_HASHRATE_SCALE != u32::from(SCAN_ASIC_NUM) * u32::from(SCAN_CORE_NUM) {
        return Err(FactoryAgingError::UnknownSweepTable);
    }
    if SWEEP_STATE_PER_CHAIN != u32::from(SCAN_ASIC_NUM) * SWEEP_STATE_PER_CHIP {
        return Err(FactoryAgingError::UnknownSweepTable);
    }
    if SWEEP_STATE_TOTAL != u32::from(SCAN_CHAIN_SLOT_COUNT) * SWEEP_STATE_PER_CHAIN {
        return Err(FactoryAgingError::UnknownSweepTable);
    }
    Ok(T11_SCAN_GEOMETRY)
}

/// `is_column_sweep`: T11 && minor != 0 && minor != B_BGM.
/// `is_board_sweep`: T11 && (BSL || B_BGM).
/// S9k `is_T11()` is the constant `1`.
pub fn force_mode_dispatch(package: ChipPackage) -> ForceModeDispatch {
    match package {
        ChipPackage::Bsl | ChipPackage::BBgm => ForceModeDispatch::BoardSweep,
        ChipPackage::Be | ChipPackage::BeBgm | ChipPackage::Ce => ForceModeDispatch::SweepByColumn,
    }
}

/// S9 SE default package is CE. Bin is not in the factory conf — both CE
/// tables stay visible; a single envelope requires an explicit bin.
pub fn sweep_pair_for(package: ChipPackage, bin: ChipBin) -> Result<SweepPair, FactoryAgingError> {
    match (package, bin) {
        (ChipPackage::Ce, ChipBin::Bin1 | ChipBin::Bin2) => Ok(T11_CE_BIN1_OR_BIN2),
        (ChipPackage::Ce, ChipBin::Bin3 | ChipBin::Bin4) => Ok(T11_CE_BIN3_OR_BIN4),
        _ => Err(FactoryAgingError::UnknownSweepTable),
    }
}

pub fn sweep_config(pair: SweepPair, mode: SweepMode) -> SweepConfig {
    match mode {
        SweepMode::Eco => pair.eco,
        SweepMode::Hpf => pair.hpf,
    }
}

/// `level_num = (max - min) / freq_step`.
pub fn sweep_level_num(cfg: SweepConfig, freq_step_mhz: u16) -> Result<u16, FactoryAgingError> {
    if cfg.max_freq_mhz < cfg.min_freq_mhz || freq_step_mhz == 0 {
        return Err(FactoryAgingError::FrequencyRangeInvalid);
    }
    Ok((cfg.max_freq_mhz - cfg.min_freq_mhz) / freq_step_mhz)
}

/// Inclusive column/scan steps `min, min+step, ...` while `<= max`.
pub fn plan_scan_freq_steps(
    cfg: SweepConfig,
    freq_step_mhz: u16,
) -> Result<Vec<u16>, FactoryAgingError> {
    if cfg.max_freq_mhz < cfg.min_freq_mhz || freq_step_mhz == 0 {
        return Err(FactoryAgingError::FrequencyRangeInvalid);
    }
    let mut out = Vec::new();
    let mut freq = cfg.min_freq_mhz;
    while freq <= cfg.max_freq_mhz {
        out.push(freq);
        match freq.checked_add(freq_step_mhz) {
            Some(next) => freq = next,
            None => break,
        }
    }
    Ok(out)
}

/// `boardsweep_get_next_freq` step. `None` means `test_done`.
pub fn plan_boardsweep_next_freq(base_mhz: u16, freq_step_mhz: u16, max_mhz: u16) -> Option<u16> {
    let next = base_mhz.saturating_add(BOARDSWEEP_STEP_MULTIPLIER.saturating_mul(freq_step_mhz));
    if next <= max_mhz {
        Some(next)
    } else {
        None
    }
}

/// `max_hashrate = 12480 * freq / 1000`.
pub fn planned_max_hashrate(freq_mhz: u16) -> u32 {
    SCAN_HASHRATE_SCALE * u32::from(freq_mhz) / 1_000
}

pub fn asic_work_count(test_8pattern: bool) -> u32 {
    let cores = u32::from(SCAN_CORE_NUM);
    if test_8pattern {
        8 * cores
    } else {
        cores
    }
}

pub fn required_chain_nonce(test_8pattern: bool, check_column_nonce: bool) -> u32 {
    let work = asic_work_count(test_8pattern);
    let full = u32::from(SCAN_ASIC_NUM) * work;
    if check_column_nonce {
        full / 10
    } else {
        full
    }
}

pub fn scan_pass_nonce_num(work_count: u32) -> u32 {
    work_count * SCAN_PASS_NONCE_RATE_NUM / SCAN_PASS_NONCE_RATE_DEN
}

pub fn boardsweep_pass_nonce_num(work_count: u32) -> u32 {
    work_count * BOARDSWEEP_PASS_NONCE_RATE_NUM / BOARDSWEEP_PASS_NONCE_RATE_DEN
}

pub fn classify_asic_succeed_freq(succeed_freq_cnt: u32) -> bool {
    succeed_freq_cnt > BAD_ASIC_MAX_SUCCEED_FREQ
}

/// Factory `"bitmain-voltage": "950"` is 9.50 V identity, not a sweep start.
pub fn refuse_factory_voltage_token_as_sweep_start(token: u16) -> Result<(), FactoryAgingError> {
    if token == FACTORY_VOLTAGE_TOKEN {
        return Err(FactoryAgingError::FactoryTokenIsNotSweepStart);
    }
    let _ = FACTORY_CONF_VOLTAGE_V;
    Ok(())
}

pub fn refuse_pattern_path_as_runtime_work(path: &str) -> Result<(), FactoryAgingError> {
    if path.starts_with(SCAN_WORK_PATH_PREFIX) || path.contains(SCAN_WORK_FILE_PREFIX) {
        return Err(FactoryAgingError::PatternPathIsNotRuntimeWork);
    }
    Ok(())
}

/// No executor. Planning is not a factory-test permit.
pub fn refuse_factory_aging_execute() -> Result<(), FactoryAgingError> {
    Err(FactoryAgingError::ExecuteRefused)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t11_ce_bin1_tables_and_dispatch_are_exact() {
        let geo = admit_scan_geometry().unwrap();
        assert_eq!(geo.asic_num, 60);
        assert_eq!(geo.core_num, 208);
        assert_eq!(geo.freq_step_mhz, 5);
        assert_eq!(geo.columns, 10);
        assert_eq!(geo.chain_slots, 16);
        assert_eq!(
            force_mode_dispatch(ChipPackage::Ce),
            ForceModeDispatch::SweepByColumn
        );
        assert_eq!(
            force_mode_dispatch(ChipPackage::Bsl),
            ForceModeDispatch::BoardSweep
        );
        let pair = sweep_pair_for(ChipPackage::Ce, ChipBin::Bin1).unwrap();
        let hpf = sweep_config(pair, SweepMode::Hpf);
        assert_eq!(hpf.min_freq_mhz, 415);
        assert_eq!(hpf.max_freq_mhz, 465);
        assert_eq!(hpf.start_voltage_mv, 9_200);
        assert_eq!(hpf.max_aging_voltage_mv, 9_600);
        assert_eq!(sweep_level_num(hpf, SCAN_FREQ_STEP_MHZ).unwrap(), 10);
        let steps = plan_scan_freq_steps(hpf, SCAN_FREQ_STEP_MHZ).unwrap();
        assert_eq!(steps.first().copied(), Some(415));
        assert_eq!(steps.last().copied(), Some(465));
        assert_eq!(steps.len(), 11);
        assert_eq!(
            plan_boardsweep_next_freq(415, SCAN_FREQ_STEP_MHZ, 465),
            Some(425)
        );
        assert_eq!(
            plan_boardsweep_next_freq(465, SCAN_FREQ_STEP_MHZ, 465),
            None
        );
        assert_eq!(planned_max_hashrate(1_000), SCAN_HASHRATE_SCALE);
        assert_eq!(planned_max_hashrate(415), 12_480 * 415 / 1_000);
        assert!(sweep_pair_for(ChipPackage::Bsl, ChipBin::Bin1).is_err());
    }

    #[test]
    fn scan_work_counts_and_refusals_drive_shipped_functions() {
        assert_eq!(asic_work_count(false), 208);
        assert_eq!(asic_work_count(true), 1_664);
        assert_eq!(required_chain_nonce(false, false), 12_480);
        assert_eq!(required_chain_nonce(false, true), 1_248);
        assert_eq!(scan_pass_nonce_num(208), 205);
        assert_eq!(boardsweep_pass_nonce_num(208), 203);
        assert!(!classify_asic_succeed_freq(1));
        assert!(classify_asic_succeed_freq(2));
        assert_eq!(
            refuse_factory_voltage_token_as_sweep_start(FACTORY_VOLTAGE_TOKEN),
            Err(FactoryAgingError::FactoryTokenIsNotSweepStart)
        );
        assert_eq!(
            refuse_pattern_path_as_runtime_work("/log/minertest64-BM1393/btc-asic-00"),
            Err(FactoryAgingError::PatternPathIsNotRuntimeWork)
        );
        assert_eq!(
            refuse_factory_aging_execute(),
            Err(FactoryAgingError::ExecuteRefused)
        );
        let bin3 = sweep_pair_for(ChipPackage::Ce, ChipBin::Bin3).unwrap();
        assert_eq!(bin3.eco.min_freq_mhz, 310);
        assert_eq!(bin3.hpf.max_freq_mhz, 450);
        assert_eq!(
            S9SE_HIVE_CGMINER_SHA256,
            crate::s9se_identity::CGMINER_SHA256
        );
        assert_eq!(
            S9SE_OFFICIAL_CGMINER_SHA256,
            crate::s9se_identity::OFFICIAL_CGMINER_SHA256
        );
        let official = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../");
        let bytes = std::fs::read(&official).expect("held official S9 SE cgminer");
        assert_eq!(bytes.len(), crate::s9se_identity::OFFICIAL_CGMINER_SIZE);
        for needle in [
            b"sweep config for eco mode" as &[u8],
            b"scan_freq_scan_by_column",
            b"minertest64-BM1393",
            b"freq_scan.c",
        ] {
            assert!(
                bytes.windows(needle.len()).any(|w| w == needle),
                "official S9 SE cgminer missing {needle:?}"
            );
        }
        assert_eq!(SWEEP_ERROR_FEW_SUCCEED_FREQ, 14);
        assert_eq!(SCAN_FREQ_INDEX_MAX, 40);
        assert_eq!(SWEEP_STATE_TOTAL, 38_400);
    }
}
