//! BM1397 / S17 (BHB07601) bring-up skeleton — host-testable IMPLEMENT items 1–13.
//!
//! Source:
//!
//!
//!
//!
//!
//!
//! Public S17 `single-board-test.dec` literals only. This module is **constants +
//! validation helpers + CMD templates**. It does not energize rails, open UART,
//! flash, claim mining, or invent Fan-Preserve (absent in jig binary).
//!
//! Config.ini `baudrate=` is the FPGA/ASIC **enum/divider** (0/1/3/4/5/26), **not**
//! a bps integer — see item 13 map helpers.
//!
//! BENCH_HOLD (48-ASIC HW nonce parity, PLL accuracy / voltage envelope) and
//! DESK_PENDING item 14 (Freq/OpenCoreGap/timeout_percent defaults — refuse
//! inventing; no BHB07601 Config.ini in PUBLIC) are documented as refuse/hold —
//! not faked. Item 13 baud↔enum map is **IMPLEMENT**. Item 17 domain nonce
//! math (`DAEMON_CHECKLIST_DELTA_DOMAIN.md`) is **IMPLEMENT**. Item 18 sensor
//! model matrix (`DAEMON_CHECKLIST_DELTA_SENSOR.md`) is **IMPLEMENT**; item 19
//! production `sensor_model` / TempSensor1..4 stays **DESK_PENDING**.

use crate::stock_fpga_policy::stock_bitmain_crc5;

// --- Ready-to-code constants (checklist copy block) ---
pub const BM1397_ASICS_S17_BHB07601: u8 = 48;
pub const BM1397_ASIC_INTERVAL: u8 = 5;
pub const BM1397_CORES: u16 = 672;
pub const BM1397_OPENCORE_OUTER: u8 = 84;
pub const BM1397_OPENCORE_STRIDE: u8 = 84;
pub const BM1397_ENABLE_CORE_MAGIC: u16 = 0x84AA;
pub const BM1397_ENABLE_CORE_REG: u8 = 0x3C;
pub const BM1397_CHAIN_INACTIVE_HDR: u8 = 0x53;
pub const BM1397_SET_ADDRESS_HDR: u8 = 0x40;
pub const BM1397_SET_CONFIG_BCAST: u8 = 0x51;
pub const BM1397_SET_CONFIG_UNICAST: u8 = 0x41;
pub const BM1397_BC_WRITE: u32 = 0x8080_0000;
pub const BM1397_MISC_DEFAULT: u16 = 0x3A01;
pub const BM1397_MISC_CONTROL_REG: u8 = 0x18;
pub const BM1397_BAUD_EXT_0X68: u32 = 0xC070_0111;
pub const BM1397_BAUD_EXT_0X28: u32 = 0x0600_000F;
pub const BM1397_BAUD_EXT_REG_0X68: u8 = 0x68;
pub const BM1397_BAUD_EXT_REG_0X28: u8 = 0x28;
pub const BM1397_FPGA_BAUD_INIT: u8 = 26; // 0x1A
pub const BM1397_TW_WORK: u32 = 0x0100_0000;
pub const BM1397_TW_OPENCORE: u32 = 0x0100_0080;
pub const BM1397_WORK_ID_RING: u8 = 128;
pub const BM1397_PLL_FALLBACK: u32 = 0xC078_0111;
pub const BM1397_FREQ_SLOW_START_MHZ: u32 = 50;
pub const BM1397_FREQ_SLOW_STEP_MHZ: u32 = 25;
pub const BM1397_ASICTYPE_CODE: u16 = 5015; // 0x1397
pub const BM1397_CHIP_ID: u16 = 0x1397;
pub const BM1397_BOARD_NAME: &str = "BHB07601";
pub const BM1397_PLL_PARAM_REG: u8 = 0x08;
pub const BM1397_PLL_POSTDIV_REG: u8 = 0x70;
pub const BM1397_BOARD_SET_ADDRESS_GAP_US: u32 = 5_000;
pub const BM1397_SOFTWARE_SET_ADDRESS_GAP_US: u32 = 2_000;
pub const BM1397_FAN_PRESERVE_PRESENT: bool = false;
pub const BM1397_MINING_DEFAULT_ENABLED: bool = false;

// --- Item 13: Config.ini baudrate= enum/divider ↔ bps (NOT raw bps in ini) ---
// From PUBLIC T17/S17e get_bt8d_fpga_divider + S17 single_BM1397_set_baud.
pub const BM1397_BAUD_ENUM_115200: u8 = 26;
pub const BM1397_BAUD_ENUM_1M5: u8 = 1;
pub const BM1397_BAUD_ENUM_3M: u8 = 0;
pub const BM1397_BAUD_ENUM_6M: u8 = 3;
pub const BM1397_BAUD_ENUM_12M: u8 = 4;
pub const BM1397_BAUD_ENUM_25M: u8 = 5;

const _: () = assert!(BM1397_FPGA_BAUD_INIT == BM1397_BAUD_ENUM_115200);

/// Map bps → Config.ini / FPGA baud enum (six known rates only).
pub fn bm1397_baud_enum_from_bps(bps: u32) -> Option<u8> {
    match bps {
        115_200 => Some(BM1397_BAUD_ENUM_115200),
        1_500_000 => Some(BM1397_BAUD_ENUM_1M5),
        3_000_000 => Some(BM1397_BAUD_ENUM_3M),
        6_000_000 => Some(BM1397_BAUD_ENUM_6M),
        12_000_000 => Some(BM1397_BAUD_ENUM_12M),
        25_000_000 => Some(BM1397_BAUD_ENUM_25M),
        _ => None,
    }
}

/// Map Config.ini / FPGA baud enum → bps (six known enums only).
pub fn bm1397_baud_bps_from_enum(enum_div: u8) -> Option<u32> {
    match enum_div {
        BM1397_BAUD_ENUM_115200 => Some(115_200),
        BM1397_BAUD_ENUM_1M5 => Some(1_500_000),
        BM1397_BAUD_ENUM_3M => Some(3_000_000),
        BM1397_BAUD_ENUM_6M => Some(6_000_000),
        BM1397_BAUD_ENUM_12M => Some(12_000_000),
        BM1397_BAUD_ENUM_25M => Some(25_000_000),
        _ => None,
    }
}

/// Chip BT divider for baud > 3M: `400_000_000 / (8 * baud) - 1`.
/// Cross-check: 6M→7, 12M→3, 25M→1 (used with `set_baud_ext`; ≤3M uses raw BT).
pub fn bm1397_chip_div_from_bps_over_3m(bps: u32) -> Option<u8> {
    if bps <= 3_000_000 {
        return None;
    }
    let denom = 8u64.checked_mul(bps as u64)?;
    if denom == 0 {
        return None;
    }
    let div = 400_000_000u64 / denom;
    if div == 0 {
        return None;
    }
    u8::try_from(div - 1).ok()
}

// --- Item 17: BHB07601 / BM1397 S17 domain nonce topology (jig get_result) ---
// From PUBLIC calculate_how_many_nonce_per_domain_get + BHB07601_get_result.
pub const BM1397_DOMAIN_AXIS: u32 = 4; // BHB07601_ASIC_NUMBER/12 (= 672/168)
pub const BM1397_DOMAIN_ASICS: u32 = 4; // ASICs summed per small domain
pub const BM1397_DOMAIN_CORE_SLICE: u32 = 168; // cores per ASIC per small domain
pub const BM1397_DOMAIN_COUNT: u32 = 48; // D[0..47]; hard loop bound in get_result
pub const BM1397_DOMAIN_BIG_COUNT: u32 = 12; // D_BIG[0..11] = ASIC_NUMBER/4
pub const BM1397_DOMAIN_EXPECT_NONCES_PER_PATTERN: u32 =
    BM1397_DOMAIN_AXIS * BM1397_DOMAIN_CORE_SLICE; // 672

const _: () = assert!(BM1397_DOMAIN_EXPECT_NONCES_PER_PATTERN == 672);
const _: () = assert!(BM1397_DOMAIN_BIG_COUNT == BM1397_ASICS_S17_BHB07601 as u32 / 4);
const _: () = assert!(BM1397_DOMAIN_AXIS == BM1397_ASICS_S17_BHB07601 as u32 / 12);

/// Validate small-domain index `d` is in `0 .. BM1397_DOMAIN_COUNT`.
pub const fn domain_index_valid(d: u32) -> bool {
    d < BM1397_DOMAIN_COUNT
}

/// ASIC base for small domain `d`: `DOMAIN_ASICS * (d / DOMAIN_AXIS)`.
/// Returns `None` if `d >= DOMAIN_COUNT`.
pub const fn domain_asic_base(d: u32) -> Option<u32> {
    if d >= BM1397_DOMAIN_COUNT {
        return None;
    }
    Some(BM1397_DOMAIN_ASICS * (d / BM1397_DOMAIN_AXIS))
}

/// Core base for small domain `d`: `DOMAIN_CORE_SLICE * (d % DOMAIN_AXIS)`.
/// Returns `None` if `d >= DOMAIN_COUNT`.
pub const fn domain_core_base(d: u32) -> Option<u32> {
    if d >= BM1397_DOMAIN_COUNT {
        return None;
    }
    Some(BM1397_DOMAIN_CORE_SLICE * (d % BM1397_DOMAIN_AXIS))
}

/// Expected nonces per small domain for `pattern` count: `672 * pattern`.
pub const fn domain_expect_nonces(pattern: u32) -> u32 {
    BM1397_DOMAIN_EXPECT_NONCES_PER_PATTERN.saturating_mul(pattern)
}

/// Big-domain index for small domain `d`: `d >> 2` (== `d / 4`).
/// Returns `None` if `d >= DOMAIN_COUNT`.
pub const fn domain_big_index(d: u32) -> Option<u32> {
    if d >= BM1397_DOMAIN_COUNT {
        return None;
    }
    Some(d >> 2)
}

// --- Item 18: sensor_model matrix (jig status-thread dispatch + I2C hi) ---
// From PUBLIC BHB07601_show_status_func / read_config / BM1397_read_asic_temperature_*.
// Item 19 production sensor_model / TempSensor1..4 stays DESK_PENDING (no BHB07601 ini).
pub const BM1397_SENSOR_MODEL_LOCAL_REMOTE_MIN: u8 = 1;
pub const BM1397_SENSOR_MODEL_LOCAL_REMOTE_MAX: u8 = 2;
pub const BM1397_SENSOR_MODEL_LOCAL_MIN: u8 = 3;
pub const BM1397_SENSOR_MODEL_LOCAL_MAX: u8 = 8;

pub const BM1397_SENSOR_I2C_HI_DEFAULT: u32 = 0x0098_0000; // models != 6 && != 7
pub const BM1397_SENSOR_I2C_HI_MODEL6: u32 = 0x009A_0000;
pub const BM1397_SENSOR_I2C_HI_MODEL7: u32 = 0x009C_0000;

pub const BM1397_MISC_TEMP_I2C_OR: u32 = 0x4030; // OR into MISC @ reg 0x18
pub const BM1397_REG_GENERAL_I2C_CMD: u8 = 0x1C; // 28
pub const BM1397_SENSOR_SOFT_RESET_CMD: u32 = 0x0001_0006; // 65542
pub const BM1397_SENSOR_EXT_MODE_WR: u32 = 0x0101_0904; // OR with i2c_hi
pub const BM1397_SENSOR_EXT_MODE_RD: u32 = 0x0100_0300; // after & 0xFEFEFCFF on i2c_hi
pub const BM1397_SENSOR_I2C_REMOTE: u32 = 0x0100_0100; // after & 0xFEFEFEFF on i2c_hi
pub const BM1397_SENSOR_I2C_LOCAL: u32 = 0x0100_0000; // after & 0xFEFEFFFF on i2c_hi
pub const BM1397_SENSOR_TEMP_OFFSET: i16 = 64; // temp_C = (uint8)reg - 64

/// Status-thread temperature reader kind for `sensor_model`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorReaderKind {
    /// models 1..=2 → `BM1397_read_asic_temperature_local_remote`
    LocalRemote,
    /// models 3..=8 → `BM1397_read_asic_temperature_local`
    Local,
    /// outside 1..=8 → config error / no read
    Invalid,
}

/// Dispatch `sensor_model` → reader kind (jig status thread predicate).
pub const fn sensor_reader_kind(model: u8) -> SensorReaderKind {
    if model >= BM1397_SENSOR_MODEL_LOCAL_REMOTE_MIN
        && model <= BM1397_SENSOR_MODEL_LOCAL_REMOTE_MAX
    {
        SensorReaderKind::LocalRemote
    } else if model >= BM1397_SENSOR_MODEL_LOCAL_MIN && model <= BM1397_SENSOR_MODEL_LOCAL_MAX {
        SensorReaderKind::Local
    } else {
        SensorReaderKind::Invalid
    }
}

/// `gSensor_i2c_addr_high_4_bit` from `sensor_model=` (model 6/7 special; else default).
pub const fn sensor_i2c_hi(model: u8) -> u32 {
    match model {
        6 => BM1397_SENSOR_I2C_HI_MODEL6,
        7 => BM1397_SENSOR_I2C_HI_MODEL7,
        _ => BM1397_SENSOR_I2C_HI_DEFAULT,
    }
}

/// Temperature decode: `(reg_low8 as i16) - TEMP_OFFSET`.
pub const fn decode_sensor_temp_c(reg_low8: u8) -> i16 {
    (reg_low8 as i16) - BM1397_SENSOR_TEMP_OFFSET
}

/// Pack remote (ASIC die) I2C command data @ GENERAL_I2C_CMD.
pub const fn pack_i2c_remote(i2c_hi: u32) -> u32 {
    (i2c_hi & 0xFEFE_FEFF) | BM1397_SENSOR_I2C_REMOTE
}

/// Pack local (Hash Board / PCB) I2C command data @ GENERAL_I2C_CMD.
pub const fn pack_i2c_local(i2c_hi: u32) -> u32 {
    (i2c_hi & 0xFEFE_FFFF) | BM1397_SENSOR_I2C_LOCAL
}

/// Chip address for 1-based TempSensorN: `interval * (N - 1)`.
/// Returns `None` if `temp_sensor_n_1based == 0`.
pub const fn temp_sensor_chip_addr(temp_sensor_n_1based: u8, interval: u8) -> Option<u8> {
    if temp_sensor_n_1based == 0 {
        return None;
    }
    Some(interval.saturating_mul(temp_sensor_n_1based - 1))
}

/// Refuse inventing BHB07601 production `sensor_model` / TempSensor1..4 (item 19).
pub fn refuse_invent_production_sensor_config() -> Result<(), Bm1397S17HoldError> {
    Err(Bm1397S17HoldError::DeskPending {
        item: 19,
        reason: "no PUBLIC BHB07601 Config.ini — refuse inventing sensor_model / TempSensor1..4",
    })
}

/// Refuse inventing BHB07601 Config.ini Freq / OpenCoreGap / timeout_percent.
pub fn refuse_invent_bhb07601_config_defaults() -> Result<(), Bm1397S17HoldError> {
    Err(Bm1397S17HoldError::DeskPending {
        item: 14,
        reason: "no PUBLIC BHB07601 Config.ini — refuse inventing Freq/OpenCoreGap/timeout_percent",
    })
}

/// Checklist tags for IMPLEMENT / DESK_PENDING / BENCH_HOLD honesty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1397S17ChecklistTag {
    Implement,
    DeskPending,
    BenchHold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1397S17ChecklistItem {
    pub id: u8,
    pub name: &'static str,
    pub tag: Bm1397S17ChecklistTag,
}

/// Items 1–13 + 17–18 IMPLEMENT; 14 + 19 DESK_PENDING; 15–16 BENCH_HOLD.
pub const BM1397_S17_CHECKLIST: &[Bm1397S17ChecklistItem] = &[
    Bm1397S17ChecklistItem {
        id: 1,
        name: "chain_inactive_opcode",
        tag: Bm1397S17ChecklistTag::Implement,
    },
    Bm1397S17ChecklistItem {
        id: 2,
        name: "set_address_opcode_interval",
        tag: Bm1397S17ChecklistTag::Implement,
    },
    Bm1397S17ChecklistItem {
        id: 3,
        name: "software_vs_board_set_address",
        tag: Bm1397S17ChecklistTag::Implement,
    },
    Bm1397S17ChecklistItem {
        id: 4,
        name: "work_tw_header_open_core_tw",
        tag: Bm1397S17ChecklistTag::Implement,
    },
    Bm1397S17ChecklistItem {
        id: 5,
        name: "nonce_asic_core_pattern_decode",
        tag: Bm1397S17ChecklistTag::Implement,
    },
    Bm1397S17ChecklistItem {
        id: 6,
        name: "core_count_open_core_geometry",
        tag: Bm1397S17ChecklistTag::Implement,
    },
    Bm1397S17ChecklistItem {
        id: 7,
        name: "baud_ext_immediates",
        tag: Bm1397S17ChecklistTag::Implement,
    },
    Bm1397S17ChecklistItem {
        id: 8,
        name: "fpga_baud_bringup_divisor",
        tag: Bm1397S17ChecklistTag::Implement,
    },
    Bm1397S17ChecklistItem {
        id: 9,
        name: "misc_default",
        tag: Bm1397S17ChecklistTag::Implement,
    },
    Bm1397S17ChecklistItem {
        id: 10,
        name: "pll_slow_ramp",
        tag: Bm1397S17ChecklistTag::Implement,
    },
    Bm1397S17ChecklistItem {
        id: 11,
        name: "enable_core_data",
        tag: Bm1397S17ChecklistTag::Implement,
    },
    Bm1397S17ChecklistItem {
        id: 12,
        name: "fan_preserve_absent",
        tag: Bm1397S17ChecklistTag::Implement,
    },
    Bm1397S17ChecklistItem {
        id: 13,
        name: "config_ini_baud_enum_map",
        tag: Bm1397S17ChecklistTag::Implement,
    },
    Bm1397S17ChecklistItem {
        id: 14,
        name: "freq_timeout_opencoregap_defaults",
        tag: Bm1397S17ChecklistTag::DeskPending,
    },
    Bm1397S17ChecklistItem {
        id: 15,
        name: "hw_nonce_parity_48_asic",
        tag: Bm1397S17ChecklistTag::BenchHold,
    },
    Bm1397S17ChecklistItem {
        id: 16,
        name: "pll_accuracy_voltage_envelope",
        tag: Bm1397S17ChecklistTag::BenchHold,
    },
    Bm1397S17ChecklistItem {
        id: 17,
        name: "domain_nonce_math",
        tag: Bm1397S17ChecklistTag::Implement,
    },
    Bm1397S17ChecklistItem {
        id: 18,
        name: "sensor_model_matrix",
        tag: Bm1397S17ChecklistTag::Implement,
    },
    Bm1397S17ChecklistItem {
        id: 19,
        name: "production_sensor_model_tempsensor",
        tag: Bm1397S17ChecklistTag::DeskPending,
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1397S17HoldError {
    BenchHold { item: u8, reason: &'static str },
    DeskPending { item: u8, reason: &'static str },
    MiningDefaultMustStayOff,
    FanPreserveInventedForbidden,
}

impl core::fmt::Display for Bm1397S17HoldError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BenchHold { item, reason } => {
                write!(f, "BM1397 S17 BENCH_HOLD item {item}: {reason}")
            }
            Self::DeskPending { item, reason } => {
                write!(f, "BM1397 S17 DESK_PENDING item {item}: {reason}")
            }
            Self::MiningDefaultMustStayOff => {
                write!(f, "BM1397 S17: mining_default_enabled must stay false")
            }
            Self::FanPreserveInventedForbidden => {
                write!(f, "BM1397 S17: Fan Preserve absent in jig — do not invent")
            }
        }
    }
}

/// Refuse board-only BENCH_HOLD claims (items 15–16).
pub fn refuse_bench_hold(item: u8) -> Result<(), Bm1397S17HoldError> {
    match item {
        15 => Err(Bm1397S17HoldError::BenchHold {
            item: 15,
            reason: "48-ASIC HW nonce parity requires hashboard",
        }),
        16 => Err(Bm1397S17HoldError::BenchHold {
            item: 16,
            reason: "PLL accuracy / voltage envelope requires board + PSU",
        }),
        _ => Ok(()),
    }
}

/// Refuse DESK_PENDING Config.ini-driven inventing (items 14 + 19; 13/18 IMPLEMENT).
pub fn refuse_desk_pending(item: u8) -> Result<(), Bm1397S17HoldError> {
    match item {
        14 => Err(Bm1397S17HoldError::DeskPending {
            item: 14,
            reason: "Freq/timeout/OpenCoreGap defaults are config-driven — refuse inventing",
        }),
        19 => Err(Bm1397S17HoldError::DeskPending {
            item: 19,
            reason: "production sensor_model / TempSensor1..4 are config-driven — refuse inventing",
        }),
        _ => Ok(()), // items 13 baud map + 18 sensor matrix are IMPLEMENT
    }
}

pub fn admit_mining_default_off(mining_default_enabled: bool) -> Result<(), Bm1397S17HoldError> {
    if mining_default_enabled || BM1397_MINING_DEFAULT_ENABLED {
        return Err(Bm1397S17HoldError::MiningDefaultMustStayOff);
    }
    Ok(())
}

pub fn admit_fan_preserve_absent(claim_preserve: bool) -> Result<(), Bm1397S17HoldError> {
    if claim_preserve || BM1397_FAN_PRESERVE_PRESENT {
        return Err(Bm1397S17HoldError::FanPreserveInventedForbidden);
    }
    Ok(())
}

fn crc5_cmd(body: &[u8]) -> u8 {
    stock_bitmain_crc5(body, body.len() * 8)
}

/// Item 1 — chain inactive broadcast: `53 05 00 00 CRC5`.
pub fn cmd_chain_inactive_bcast() -> [u8; 5] {
    let mut f = [BM1397_CHAIN_INACTIVE_HDR, 0x05, 0x00, 0x00, 0];
    f[4] = crc5_cmd(&f[..4]);
    f
}

/// Item 2 — set_address: `40 05 AA 00 CRC5`.
pub fn cmd_set_address(addr: u8) -> [u8; 5] {
    let mut f = [BM1397_SET_ADDRESS_HDR, 0x05, addr, 0x00, 0];
    f[4] = crc5_cmd(&f[..4]);
    f
}

/// Item 2 — address ladder for BHB07601: 0,5,10,…,235.
pub fn bhb07601_address_ladder() -> Vec<u8> {
    (0..BM1397_ASICS_S17_BHB07601)
        .map(|i| i.saturating_mul(BM1397_ASIC_INTERVAL))
        .collect()
}

/// BC write command word: `(get & 0xFFF0FFFF) | (chain<<16) | 0x80800000`.
pub const fn bc_write_command(prev: u32, chain: u8) -> u32 {
    (prev & 0xFFF0_FFFF) | ((chain as u32) << 16) | BM1397_BC_WRITE
}

/// Item 3 — main path uses board helper gap (5 ms), not software (2 ms).
pub const fn set_address_gap_us_main_path() -> u32 {
    BM1397_BOARD_SET_ADDRESS_GAP_US
}

/// Item 4 — work TW header: `0x01000000 | (chain|0x80)<<16`.
pub const fn tw_work_header(chain: u8) -> u32 {
    BM1397_TW_WORK | (((chain | 0x80) as u32) << 16)
}

/// Item 4 — open-core TW header: `0x01000080 | chain<<16`.
pub const fn tw_opencore_header(chain: u8) -> u32 {
    BM1397_TW_OPENCORE | ((chain as u32) << 16)
}

/// Item 5 — ASIC index from nonce: `(nonce>>14)/interval` (low 8 of that).
pub const fn nonce_asic_index(nonce: u32, interval: u8) -> u8 {
    let raw = ((nonce >> 14) as u8) as u16;
    if interval == 0 {
        return 0;
    }
    (raw / interval as u16) as u8
}

/// Item 5 — `BM1397_get_core_id`: `(nonce>>31) | (2*((nonce>>22)&0x1FF))`.
pub const fn get_core_id(nonce: u32) -> u16 {
    let hi = (nonce >> 31) as u16;
    let mid = ((nonce >> 22) & 0x1FF) as u16;
    hi | (2 * mid)
}

/// Item 5 — pattern idx from return buf0: `buf0>>23` as u8.
pub const fn nonce_pattern_idx(buf0: u32) -> u8 {
    (buf0 >> 23) as u8
}

/// Item 5 — nonce flag: `(data & 0xE0) == 0x80`.
pub const fn check_nonce_flag(data: u32) -> bool {
    (data & 0xE0) == 0x80
}

/// Item 6 — open-core enable bases for outer index `base` (0..83): +{0,84,168,252}.
pub fn opencore_enable_ids(base: u8) -> [u16; 4] {
    let b = base as u16;
    let s = BM1397_OPENCORE_STRIDE as u16;
    [b, b + s, b + 2 * s, b + 3 * s]
}

/// Item 11 — enable-core reg data: `(core_id<<16) | 0x84AA` @ reg 0x3C.
pub const fn enable_core_data(core_id: u16) -> u32 {
    ((core_id as u32) << 16) | (BM1397_ENABLE_CORE_MAGIC as u32)
}

/// 9-byte set_config frame.
pub fn cmd_set_config(broadcast: bool, chip_addr: u8, reg: u8, value: u32) -> [u8; 9] {
    let mut f = [
        if broadcast {
            BM1397_SET_CONFIG_BCAST
        } else {
            BM1397_SET_CONFIG_UNICAST
        },
        0x09,
        chip_addr,
        reg,
        ((value >> 24) & 0xff) as u8,
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
        0,
    ];
    f[8] = crc5_cmd(&f[..8]);
    f
}

/// Item 7 — baud_ext immediates as set_config frames (broadcast).
pub fn cmd_baud_ext_0x68_bcast() -> [u8; 9] {
    cmd_set_config(true, 0, BM1397_BAUD_EXT_REG_0X68, BM1397_BAUD_EXT_0X68)
}

pub fn cmd_baud_ext_0x28_bcast() -> [u8; 9] {
    cmd_set_config(true, 0, BM1397_BAUD_EXT_REG_0X28, BM1397_BAUD_EXT_0X28)
}

/// Item 8 — pack FPGA baud divisor into reg15 bits [21:16].
pub const fn pack_fpga_baud_reg15(prev: u32, asic_baud: u8) -> u32 {
    (prev & 0xFFC0_FFFF) | (((asic_baud as u32) & 0x3F) << 16)
}

/// Item 10 — PLL slow-ramp frequency steps: 50, +25, … until within 50 of target, then exact.
pub fn pll_slow_ramp_mhz(target_mhz: u32) -> Vec<u32> {
    let mut out = Vec::new();
    if target_mhz == 0 {
        return out;
    }
    // Checklist: start 50 MHz, +25 MHz steps, final exact target.
    let mut f = BM1397_FREQ_SLOW_START_MHZ;
    while f < target_mhz {
        out.push(f);
        f = f.saturating_add(BM1397_FREQ_SLOW_STEP_MHZ);
    }
    if out.last().copied() != Some(target_mhz) {
        out.push(target_mhz);
    }
    out
}

/// Validate IMPLEMENT geometry constants (host pin).
pub fn validate_implement_geometry() -> Result<(), &'static str> {
    if BM1397_ASICS_S17_BHB07601 != 48 {
        return Err("ASIC count must be 48");
    }
    if BM1397_ASIC_INTERVAL != 5 {
        return Err("interval must be 5");
    }
    if BM1397_CORES != 672 {
        return Err("cores must be 672");
    }
    if BM1397_OPENCORE_OUTER != 84 || BM1397_OPENCORE_STRIDE != 84 {
        return Err("open-core outer/stride must be 84");
    }
    if BM1397_CHAIN_INACTIVE_HDR != 0x53 || BM1397_SET_ADDRESS_HDR != 0x40 {
        return Err("inactive/set_address opcodes mismatch");
    }
    if BM1397_FPGA_BAUD_INIT != 26 {
        return Err("FPGA baud init must be 26");
    }
    if BM1397_MISC_DEFAULT != 0x3A01 {
        return Err("misc default must be 0x3A01");
    }
    if BM1397_FAN_PRESERVE_PRESENT {
        return Err("Fan Preserve must be absent");
    }
    if BM1397_MINING_DEFAULT_ENABLED {
        return Err("mining must stay off by default");
    }
    let ladder = bhb07601_address_ladder();
    if ladder.len() != 48 || ladder[0] != 0 || ladder[47] != 235 {
        return Err("address ladder must be 0..235 step 5");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implement_constants_match_checklist_copy_block() {
        assert_eq!(BM1397_ASICS_S17_BHB07601, 48);
        assert_eq!(BM1397_ASIC_INTERVAL, 5);
        assert_eq!(BM1397_CORES, 672);
        assert_eq!(BM1397_OPENCORE_OUTER, 84);
        assert_eq!(BM1397_OPENCORE_STRIDE, 84);
        assert_eq!(BM1397_ENABLE_CORE_MAGIC, 0x84AA);
        assert_eq!(BM1397_CHAIN_INACTIVE_HDR, 0x53);
        assert_eq!(BM1397_SET_ADDRESS_HDR, 0x40);
        assert_eq!(BM1397_SET_CONFIG_BCAST, 0x51);
        assert_eq!(BM1397_SET_CONFIG_UNICAST, 0x41);
        assert_eq!(BM1397_BC_WRITE, 0x8080_0000);
        assert_eq!(BM1397_MISC_DEFAULT, 0x3A01);
        assert_eq!(BM1397_BAUD_EXT_0X68, 0xC070_0111);
        assert_eq!(BM1397_BAUD_EXT_0X28, 0x0600_000F);
        assert_eq!(BM1397_FPGA_BAUD_INIT, 26);
        assert_eq!(BM1397_TW_WORK, 0x0100_0000);
        assert_eq!(BM1397_TW_OPENCORE, 0x0100_0080);
        assert_eq!(BM1397_WORK_ID_RING, 128);
        assert_eq!(BM1397_PLL_FALLBACK, 0xC078_0111);
        assert_eq!(BM1397_FREQ_SLOW_START_MHZ, 50);
        assert_eq!(BM1397_FREQ_SLOW_STEP_MHZ, 25);
        assert_eq!(BM1397_ASICTYPE_CODE, 5015);
        assert_eq!(BM1397_CHIP_ID, 0x1397);
        assert_eq!(BM1397_BOARD_NAME, "BHB07601");
        assert!(validate_implement_geometry().is_ok());
    }

    #[test]
    fn item1_2_inactive_and_set_address_frames() {
        assert_eq!(cmd_chain_inactive_bcast(), [0x53, 0x05, 0x00, 0x00, 0x03]);
        assert_eq!(cmd_set_address(0), [0x40, 0x05, 0x00, 0x00, 0x1c]);
        assert_eq!(cmd_set_address(5), [0x40, 0x05, 0x05, 0x00, 0x1f]);
        assert_eq!(cmd_set_address(235), [0x40, 0x05, 0xEB, 0x00, 0x0f]);
        let ladder = bhb07601_address_ladder();
        assert_eq!(ladder.len(), 48);
        assert_eq!(ladder[0], 0);
        assert_eq!(ladder[1], 5);
        assert_eq!(ladder[47], 235);
        assert_eq!(bc_write_command(0, 0), 0x8080_0000);
        assert_eq!(bc_write_command(0x0001_0000, 2), 0x8082_0000);
    }

    #[test]
    fn item3_board_helper_gap_is_main_path() {
        assert_eq!(set_address_gap_us_main_path(), 5_000);
        assert_ne!(
            BM1397_BOARD_SET_ADDRESS_GAP_US,
            BM1397_SOFTWARE_SET_ADDRESS_GAP_US
        );
        assert_eq!(BM1397_SOFTWARE_SET_ADDRESS_GAP_US, 2_000);
    }

    #[test]
    fn item4_tw_headers() {
        assert_eq!(tw_work_header(0), 0x0180_0000);
        assert_eq!(tw_work_header(1), 0x0181_0000);
        assert_eq!(tw_opencore_header(0), 0x0100_0080);
        assert_eq!(tw_opencore_header(3), 0x0103_0080);
    }

    #[test]
    fn item5_nonce_decode_helpers() {
        // nonce with (nonce>>14) low8 = 10 → asic 10/5 = 2
        let nonce = (10u32) << 14;
        assert_eq!(nonce_asic_index(nonce, 5), 2);
        // core_id: bit31 | 2*((nonce>>22)&0x1FF)
        let nonce2 = (1u32 << 31) | (3u32 << 22);
        assert_eq!(get_core_id(nonce2), 1 | (2 * 3));
        assert_eq!(nonce_pattern_idx(0x0080_0000), 1);
        assert!(check_nonce_flag(0x80));
        assert!(!check_nonce_flag(0x00));
        assert!(!check_nonce_flag(0xA0));
    }

    #[test]
    fn item6_11_opencore_and_enable_core() {
        assert_eq!(opencore_enable_ids(0), [0, 84, 168, 252]);
        assert_eq!(opencore_enable_ids(1), [1, 85, 169, 253]);
        assert_eq!(enable_core_data(0), 0x0000_84AA);
        assert_eq!(enable_core_data(1), 0x0001_84AA);
        assert_eq!(
            cmd_set_config(true, 0, BM1397_ENABLE_CORE_REG, enable_core_data(0)),
            [0x51, 0x09, 0x00, 0x3C, 0x00, 0x00, 0x84, 0xAA, 0x0a]
        );
    }

    #[test]
    fn item7_8_9_baud_misc() {
        assert_eq!(BM1397_BAUD_EXT_0X68, 0xC070_0111);
        assert_eq!(BM1397_BAUD_EXT_0X28, 0x0600_000F);
        let r = pack_fpga_baud_reg15(0, BM1397_FPGA_BAUD_INIT);
        assert_eq!((r >> 16) & 0x3F, 0x1A);
        assert_eq!(BM1397_MISC_DEFAULT, 0x3A01);
        assert_eq!(BM1397_MISC_DEFAULT as u32, 14849);
        let _ = cmd_baud_ext_0x68_bcast();
        let _ = cmd_baud_ext_0x28_bcast();
    }

    #[test]
    fn item10_pll_slow_ramp() {
        assert_eq!(pll_slow_ramp_mhz(50), vec![50]);
        assert_eq!(pll_slow_ramp_mhz(100), vec![50, 75, 100]);
        assert_eq!(pll_slow_ramp_mhz(200), vec![50, 75, 100, 125, 150, 175, 200]);
        assert_eq!(BM1397_PLL_PARAM_REG, 0x08);
        assert_eq!(BM1397_PLL_POSTDIV_REG, 0x70);
        assert_eq!(BM1397_PLL_FALLBACK, 0xC078_0111);
    }

    #[test]
    fn item12_fan_preserve_absent_and_mining_off() {
        assert!(!BM1397_FAN_PRESERVE_PRESENT);
        assert!(admit_fan_preserve_absent(false).is_ok());
        assert!(admit_fan_preserve_absent(true).is_err());
        assert!(admit_mining_default_off(false).is_ok());
        assert!(admit_mining_default_off(true).is_err());
    }

    #[test]
    fn bench_hold_and_desk_pending_refuse() {
        assert!(matches!(
            refuse_bench_hold(15),
            Err(Bm1397S17HoldError::BenchHold { item: 15, .. })
        ));
        assert!(matches!(
            refuse_bench_hold(16),
            Err(Bm1397S17HoldError::BenchHold { item: 16, .. })
        ));
        assert!(refuse_bench_hold(1).is_ok());
        // Item 13 baud map is IMPLEMENT — no longer DeskPending refuse.
        assert!(refuse_desk_pending(13).is_ok());
        assert!(matches!(
            refuse_desk_pending(14),
            Err(Bm1397S17HoldError::DeskPending { item: 14, .. })
        ));
        let implement: Vec<_> = BM1397_S17_CHECKLIST
            .iter()
            .filter(|i| i.tag == Bm1397S17ChecklistTag::Implement)
            .map(|i| i.id)
            .collect();
        let mut expect: Vec<u8> = (1..=13).collect();
        expect.push(17);
        expect.push(18);
        assert_eq!(implement, expect);
        assert!(matches!(
            refuse_desk_pending(19),
            Err(Bm1397S17HoldError::DeskPending { item: 19, .. })
        ));
    }

    #[test]
    fn item13_config_ini_baud_enum_map() {
        assert_eq!(BM1397_FPGA_BAUD_INIT, BM1397_BAUD_ENUM_115200);
        assert_eq!(bm1397_baud_enum_from_bps(115_200), Some(26));
        assert_eq!(bm1397_baud_enum_from_bps(1_500_000), Some(1));
        assert_eq!(bm1397_baud_enum_from_bps(3_000_000), Some(0));
        assert_eq!(bm1397_baud_enum_from_bps(6_000_000), Some(3));
        assert_eq!(bm1397_baud_enum_from_bps(12_000_000), Some(4));
        assert_eq!(bm1397_baud_enum_from_bps(25_000_000), Some(5));
        assert_eq!(bm1397_baud_bps_from_enum(26), Some(115_200));
        assert_eq!(bm1397_baud_bps_from_enum(1), Some(1_500_000));
        assert_eq!(bm1397_baud_bps_from_enum(0), Some(3_000_000));
        assert_eq!(bm1397_baud_bps_from_enum(3), Some(6_000_000));
        assert_eq!(bm1397_baud_bps_from_enum(4), Some(12_000_000));
        assert_eq!(bm1397_baud_bps_from_enum(5), Some(25_000_000));
        assert_eq!(bm1397_baud_enum_from_bps(9_600), None);
        assert_eq!(bm1397_baud_bps_from_enum(2), None);
        // >3M chip BT cross-check (6M→BT7, 12M→BT3, 25M→BT1); ≤3M raw BT / None here
        assert_eq!(bm1397_chip_div_from_bps_over_3m(6_000_000), Some(7));
        assert_eq!(bm1397_chip_div_from_bps_over_3m(12_000_000), Some(3));
        assert_eq!(bm1397_chip_div_from_bps_over_3m(25_000_000), Some(1));
        assert_eq!(bm1397_chip_div_from_bps_over_3m(3_000_000), None);
        assert!(matches!(
            refuse_invent_bhb07601_config_defaults(),
            Err(Bm1397S17HoldError::DeskPending { item: 14, .. })
        ));
        let item13 = BM1397_S17_CHECKLIST
            .iter()
            .find(|i| i.id == 13)
            .expect("item 13");
        assert_eq!(item13.tag, Bm1397S17ChecklistTag::Implement);
        assert_eq!(item13.name, "config_ini_baud_enum_map");
        let item14 = BM1397_S17_CHECKLIST
            .iter()
            .find(|i| i.id == 14)
            .expect("item 14");
        assert_eq!(item14.tag, Bm1397S17ChecklistTag::DeskPending);
    }

    #[test]
    fn item17_domain_nonce_math_map() {
        assert_eq!(BM1397_DOMAIN_AXIS, 4);
        assert_eq!(BM1397_DOMAIN_ASICS, 4);
        assert_eq!(BM1397_DOMAIN_CORE_SLICE, 168);
        assert_eq!(BM1397_DOMAIN_COUNT, 48);
        assert_eq!(BM1397_DOMAIN_BIG_COUNT, 12);
        assert_eq!(BM1397_DOMAIN_EXPECT_NONCES_PER_PATTERN, 672);
        assert_eq!(
            BM1397_DOMAIN_EXPECT_NONCES_PER_PATTERN,
            BM1397_DOMAIN_AXIS * BM1397_DOMAIN_CORE_SLICE
        );

        // d=0 → asic0 core0; d=1 → asic0 core168; d=4 → asic4 core0; d=47 → asic44 core504
        assert_eq!(domain_asic_base(0), Some(0));
        assert_eq!(domain_core_base(0), Some(0));
        assert_eq!(domain_asic_base(1), Some(0));
        assert_eq!(domain_core_base(1), Some(168));
        assert_eq!(domain_asic_base(4), Some(4));
        assert_eq!(domain_core_base(4), Some(0));
        assert_eq!(domain_asic_base(47), Some(44));
        assert_eq!(domain_core_base(47), Some(504));

        assert_eq!(domain_expect_nonces(1), 672);
        assert_eq!(domain_expect_nonces(2), 1344);
        assert_eq!(domain_expect_nonces(0), 0);

        assert_eq!(domain_big_index(0), Some(0));
        assert_eq!(domain_big_index(3), Some(0));
        assert_eq!(domain_big_index(4), Some(1));
        assert_eq!(domain_big_index(47), Some(11));

        assert!(domain_index_valid(0));
        assert!(domain_index_valid(47));
        assert!(!domain_index_valid(48));
        assert_eq!(domain_asic_base(48), None);
        assert_eq!(domain_core_base(48), None);
        assert_eq!(domain_big_index(48), None);

        let item17 = BM1397_S17_CHECKLIST
            .iter()
            .find(|i| i.id == 17)
            .expect("item 17");
        assert_eq!(item17.tag, Bm1397S17ChecklistTag::Implement);
        assert_eq!(item17.name, "domain_nonce_math");
        // Item 14 still DESK_PENDING — refuse inventing Freq/OpenCoreGap/timeout.
        assert!(matches!(
            refuse_invent_bhb07601_config_defaults(),
            Err(Bm1397S17HoldError::DeskPending { item: 14, .. })
        ));
    }

    #[test]
    fn item18_sensor_model_matrix() {
        assert_eq!(BM1397_SENSOR_MODEL_LOCAL_REMOTE_MIN, 1);
        assert_eq!(BM1397_SENSOR_MODEL_LOCAL_REMOTE_MAX, 2);
        assert_eq!(BM1397_SENSOR_MODEL_LOCAL_MIN, 3);
        assert_eq!(BM1397_SENSOR_MODEL_LOCAL_MAX, 8);
        assert_eq!(BM1397_SENSOR_I2C_HI_DEFAULT, 0x0098_0000);
        assert_eq!(BM1397_SENSOR_I2C_HI_MODEL6, 0x009A_0000);
        assert_eq!(BM1397_SENSOR_I2C_HI_MODEL7, 0x009C_0000);
        assert_eq!(BM1397_MISC_TEMP_I2C_OR, 0x4030);
        assert_eq!(BM1397_REG_GENERAL_I2C_CMD, 0x1C);
        assert_eq!(BM1397_SENSOR_SOFT_RESET_CMD, 0x0001_0006);
        assert_eq!(BM1397_SENSOR_EXT_MODE_WR, 0x0101_0904);
        assert_eq!(BM1397_SENSOR_EXT_MODE_RD, 0x0100_0300);
        assert_eq!(BM1397_SENSOR_I2C_REMOTE, 0x0100_0100);
        assert_eq!(BM1397_SENSOR_I2C_LOCAL, 0x0100_0000);
        assert_eq!(BM1397_SENSOR_TEMP_OFFSET, 64);

        // models 1–2 → LocalRemote; 3–8 → Local; else Invalid
        for m in 1u8..=2 {
            assert_eq!(sensor_reader_kind(m), SensorReaderKind::LocalRemote);
        }
        for m in 3u8..=8 {
            assert_eq!(sensor_reader_kind(m), SensorReaderKind::Local);
        }
        assert_eq!(sensor_reader_kind(0), SensorReaderKind::Invalid);
        assert_eq!(sensor_reader_kind(9), SensorReaderKind::Invalid);

        // I2C hi table: 6→9A, 7→9C, else 98
        assert_eq!(sensor_i2c_hi(1), 0x0098_0000);
        assert_eq!(sensor_i2c_hi(5), 0x0098_0000);
        assert_eq!(sensor_i2c_hi(6), 0x009A_0000);
        assert_eq!(sensor_i2c_hi(7), 0x009C_0000);
        assert_eq!(sensor_i2c_hi(8), 0x0098_0000);

        // temp decode: (uint8)reg - 64
        assert_eq!(decode_sensor_temp_c(64), 0);
        assert_eq!(decode_sensor_temp_c(100), 36);
        assert_eq!(decode_sensor_temp_c(0), -64);
        assert_eq!(decode_sensor_temp_c(255), 191);

        let hi = BM1397_SENSOR_I2C_HI_DEFAULT;
        assert_eq!(pack_i2c_remote(hi), (hi & 0xFEFE_FEFF) | 0x0100_0100);
        assert_eq!(pack_i2c_local(hi), (hi & 0xFEFE_FFFF) | 0x0100_0000);
        assert_eq!(
            pack_i2c_remote(BM1397_SENSOR_I2C_HI_MODEL6),
            (0x009A_0000 & 0xFEFE_FEFF) | 0x0100_0100
        );

        assert_eq!(temp_sensor_chip_addr(1, 5), Some(0));
        assert_eq!(temp_sensor_chip_addr(2, 5), Some(5));
        assert_eq!(temp_sensor_chip_addr(18, 5), Some(85));
        assert_eq!(temp_sensor_chip_addr(0, 5), None);

        assert!(matches!(
            refuse_invent_production_sensor_config(),
            Err(Bm1397S17HoldError::DeskPending { item: 19, .. })
        ));

        let item18 = BM1397_S17_CHECKLIST
            .iter()
            .find(|i| i.id == 18)
            .expect("item 18");
        assert_eq!(item18.tag, Bm1397S17ChecklistTag::Implement);
        assert_eq!(item18.name, "sensor_model_matrix");
        let item19 = BM1397_S17_CHECKLIST
            .iter()
            .find(|i| i.id == 19)
            .expect("item 19");
        assert_eq!(item19.tag, Bm1397S17ChecklistTag::DeskPending);
        // Item 14 still DESK_PENDING
        let item14 = BM1397_S17_CHECKLIST
            .iter()
            .find(|i| i.id == 14)
            .expect("item 14");
        assert_eq!(item14.tag, Bm1397S17ChecklistTag::DeskPending);
        // Baud + domain must remain present (no regression)
        assert_eq!(BM1397_BAUD_ENUM_115200, 26);
        assert_eq!(BM1397_DOMAIN_COUNT, 48);
        assert_eq!(BM1397_DOMAIN_EXPECT_NONCES_PER_PATTERN, 672);
    }
}
