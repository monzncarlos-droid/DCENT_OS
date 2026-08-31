//! S19k BM1366 Wire Gaps B pack (B1–B5) — host-testable pins for G7–G11.
//!
//! Source:  § Gaps B
//! + `AML_REFUSE_MATRIX.md` (runtime engine try refuse while DESK_PENDING)
//! + § Desk pass 2026-08-11g (AML `asic_addr_interval` = **2** for BHB5690x).
//!
//! This module is **policy + CMD template pins only**. It does not open UART,
//! energize rails, construct a mining engine, or claim mining. Desk 11d/11e
//! closed am3 UART framing + work-frame bytes; MS8 fan-out is CLOSED. Desk 11g
//! pinned AML addr_interval=2 (refuse public floor=3). Runtime-try stays
//! fail-closed while `/dev/uart_trans` transport is unowned (stock) **or**
//! while `braiins_ttys_bench_go` is false (Braiins Track-1).
//!
//! Wire CLEAR_BRAIINS_TTY: Braiins raw ports are `/dev/ttyS1`+`/dev/ttyS2`
//! (required) and `/dev/ttyS3` (discover; `a lab unit` dmesg wakes all three)
//! @ 3_000_000 8N1 (never ttyS0 console).
//! Userspace writes full CLOSED frames (`pack_set_address_uart_trans`,
//! `pack_uart_trans_job`). Runtime-try on BraiinsRawTtyS still requires
//! explicit Bench GO (`braiins_ttys_bench_go=true`); CURRENT defaults false.
//! Runtime override: [`current_with_runtime_bench_go`] via env
//! `DCENT_BRAIINS_TTYS_BENCH_GO=1` or file `/etc/dcentos/braiins_ttys_bench_go`.
//!
//! Live am3 set_address stream capture remains DESK_PENDING (templates only) —
//! that note does **not** block pinning the interval constant (desk 11g).

use crate::chain_transport::{
    bitmain_jig_addr_interval, bm1397plus_addr_interval, linear_chip_addresses,
};
use crate::stock_fpga_policy::stock_bitmain_crc5;

/// HashSource / Lead geometry for S19k BM1366 (same as checklist A).
pub const S19K_WIRE_ASIC_NUM: u8 = 77;
/// Jig `Config.ini` `Voltage_Domain` for BHB56902. Not a UART register.
pub const S19K_JIG_VOLTAGE_DOMAIN: u8 = 11;
/// Jig `Asic_Num_Per_Voltage_Domain`. 11×7 = 77.
pub const S19K_JIG_ASICS_PER_DOMAIN: u8 = 7;
pub const S19K_WIRE_CHIP_ID: u16 = 0x1366;
pub const S19K_WIRE_MIDSTATE_NUMBER: u8 = 8;
pub const S19K_WIRE_RESPONSE_BYTES: usize = 11;
pub const S19K_WIRE_HASH_COUNTING: u32 = 0x0000_115A;
pub const S19K_WIRE_JOB_ID_STEP: u8 = 8;
pub const S19K_WIRE_JOB_ID_MOD: u8 = 128;

// --- B1 CMD opcodes / templates (jig FPGA CMD builders; CRC5 via stock_bitmain_crc5) ---
/// UART GetAddress header (`55 AA 52 05 …`). Was misnamed `CMD_CHAIN_INACTIVE`.
pub const CMD_GET_ADDRESS: u8 = 0x52;
/// Real UART chain-inactive (`55 AA 53 05 00 00 03`). ESP `_send_chain_inactive`.
pub const CMD_CHAIN_INACTIVE: u8 = 0x53;
pub const CMD_SET_ADDRESS: u8 = 0x40;
pub const CMD_SET_CONFIG_BCAST: u8 = 0x51;
pub const CMD_SET_CONFIG_UNICAST: u8 = 0x41;

/// Public floor SSOT for 77 chips: floor(256/77) = 3.
/// **Refused** as S19k AML / BHB5690x SoT — see `refuse_s19k_public_floor_as_aml_interval`
/// (`BM1366_WIRE_BRINGUP.md` § Desk 2026-08-11g).
pub const S19K_PUBLIC_ADDR_INTERVAL: u8 = 3;
/// AML Track 1 / BHB5690x preferred `asic_addr_interval` (bmminer_4cc0 conf+0x34).
/// Desk 11g CLOSED: use **2**, not public floor=3. Slot count hint: 256/2 = 128.
pub const S19K_AML_ADDR_INTERVAL: u8 = 2;
/// Jig bucket for 65–128 chips = 2 (same dialect as AML preferred; desk 11b/11g).
pub const S19K_JIG_ADDR_INTERVAL: u8 = S19K_AML_ADDR_INTERVAL;
/// AML set-addr slot count when step=2: `256 / addr_interval` (4cc0 `__aeabi_uidiv`).
pub const S19K_AML_ADDR_SLOT_COUNT: u16 = 128;

// Open-core / stage_2 core-regs (EVIDENCED)
pub const CORE_REG_HASH_CLOCK: u32 = 0x8000_8540;
pub const CORE_REG_CLOCK_DELAY: u32 = 0x8000_8020; // Pwth_Sel=4, CCdly=0, Swpf=0
pub const CORE_REG_ASICBOOST: u32 = 0x8000_82AA;
pub const REG_ANALOG_MUX: u8 = 0x54;
pub const REG_CORE: u8 = 0x3C;
pub const ANALOG_MUX_DIODE_VDD_SEL: u32 = 0x0000_0003;

// --- B2 PLL ---
pub const REG_PLL0: u8 = 0x08;
pub const REG_PLL1: u8 = 0x60;
pub const PLL_RAMP_START_MHZ: u32 = 50;
pub const PUBLIC_FASTUART_REG: u8 = 0x28;
pub const PUBLIC_FASTUART_VALUE: u32 = 0x1130_0200; // 1 Mbps class
pub const JIG_CONFIG_BAUD_HZ: u32 = 12_000_000;

// --- B3 ticket / hw_error ---
pub const REG_TICKET_MASK: u8 = 0x14;
pub const TICKET_MASK_PLAIN_DIFF_MINUS_ONE_256: u32 = 0x0000_00FF;
pub const MOST_HW_NUM: u16 = 128;

// --- B4 public FPGA job header (AML uart_trans job ABI CLOSED 11d/11e/11f) ---
pub const PUBLIC_FPGA_JOB_HDR: u8 = 0x21;
pub const PUBLIC_FPGA_JOB_LEN: u8 = 0x56;
pub const REG_VERSION_ROLL: u8 = 0xA4;

// --- B5 UART_RELAY packing (public chip0) ---
pub const REG_UART_RELAY: u8 = 0x2C;
pub const REG_HASH_COUNTING: u8 = 0x10;
/// Public chip0 UART_RELAY value: CO=1, RO=1, dist=0x7C → `CO|(RO<<1)|(dist<<16)`.
pub const UART_RELAY_CHIP0_PUBLIC: u32 = 0x007C_0003;
pub const UART_RELAY_CHIP0_DIST: u16 = 0x007C;

/// Pack UART_RELAY per wire B5 / `sub_78448`: `CO | (RO << 1) | (dist << 16)`.
/// `nonce_gap_en` is 0 (Braiins `FUN_0083ca30` flags bit 2).
pub const fn pack_uart_relay(co_en: bool, ro_en: bool, dist: u16) -> u32 {
    pack_uart_relay_braiins(co_en, ro_en, false, dist)
}

/// Braiins `UartRelayReg` (`FUN_0083ca30`).
///
/// In-memory: `gap_cnt` u16 @0, `nonce_gap_en` @2, `ro_relay_en` @3,
/// `co_relay_en` @4. Packed LE word is `REV16(gap) | flags<<24` with
/// flags = `CO | RO<<1 | nonce_gap<<2`. `cmd_set_config` BE of the
/// logical u32 below emits the same wire bytes `[gap_hi, gap_lo, 0, flags]`.
pub const BOSMINER_UART_RELAY_PACK_FN_VA: u64 = 0x0083_CA30;
pub const BOSMINER_UART_RELAY_REV16_VA: u64 = 0x0083_CAB0;
pub const BOSMINER_UART_RELAY_REV16_INSN: u32 = 0x5AC0_094A;
pub const BOSMINER_UART_RELAY_STR_VA: u64 = 0x0083_CAF4;
pub const BOSMINER_UART_RELAY_CO_BIT: u32 = 0;
pub const BOSMINER_UART_RELAY_RO_BIT: u32 = 1;
pub const BOSMINER_UART_RELAY_NONCE_GAP_BIT: u32 = 2;

pub const fn pack_uart_relay_braiins(
    co_en: bool,
    ro_en: bool,
    nonce_gap_en: bool,
    dist: u16,
) -> u32 {
    let co = if co_en { 1u32 } else { 0 };
    let ro = if ro_en {
        1u32 << BOSMINER_UART_RELAY_RO_BIT
    } else {
        0
    };
    let ng = if nonce_gap_en {
        1u32 << BOSMINER_UART_RELAY_NONCE_GAP_BIT
    } else {
        0
    };
    ((dist as u32) << 16) | co | ro | ng
}

pub fn admit_bosminer_uart_relay_pack_matches_public_chip0() -> Result<(), &'static str> {
    if pack_uart_relay_braiins(true, true, false, UART_RELAY_CHIP0_DIST) != UART_RELAY_CHIP0_PUBLIC
    {
        return Err("chip0 public 0x007C0003 is CO+RO, nonce_gap=0, gap=0x7C");
    }
    if pack_uart_relay_braiins(true, true, true, UART_RELAY_CHIP0_DIST)
        != (UART_RELAY_CHIP0_PUBLIC | (1 << BOSMINER_UART_RELAY_NONCE_GAP_BIT))
    {
        return Err("nonce_gap_en is flags bit 2 (logical 0x007C0007)");
    }
    if BOSMINER_UART_RELAY_REV16_INSN != 0x5AC0_094A {
        return Err("FUN_0083ca30 REV16 W10,W10 pin drifted");
    }
    Ok(())
}

pub fn refuse_uart_relay_without_nonce_gap_field() -> Result<(), &'static str> {
    Err("Braiins UartRelayReg has nonce_gap_en at +2 → flags bit 2; pack_uart_relay leaves it 0")
}

/// Broadcast set_config for S19k stock hash counting (`0x0000115A` @ reg `0x10`).
pub fn cmd_hash_counting_s19k_bcast() -> [u8; 9] {
    cmd_set_config(true, 0, REG_HASH_COUNTING, S19K_WIRE_HASH_COUNTING)
}

/// Unicast UART_RELAY write for chip0 (public value).
pub fn cmd_uart_relay_chip0() -> [u8; 9] {
    cmd_set_config(false, 0, REG_UART_RELAY, UART_RELAY_CHIP0_PUBLIC)
}

/// AML refuse-matrix hard gates (R1–R10) as host-testable labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kAmlRefuseGate {
    R1Identity,
    R2NoPicClass,
    R3S21Fuse,
    R4Lm75BeforeProbe,
    R5Watchdog,
    R6BaudDialect,
    R7RailEnable,
    R8MiningDefault,
    R9EngineConstruct,
    R10PublicClaim,
}

/// Evaluate hard refuse triggers from claimed inputs (desk/host only).
pub fn aml_hard_refuse(
    board_name_ok: bool,
    chip_id_ok: bool,
    offers_pic_owner: bool,
    s21_fuse: bool,
    lm75_before_probe: bool,
    watchdog_ok: bool,
    baud_dialects_merged: bool,
    rail_enable_before_gates: bool,
    mining_default_enabled: bool,
    engine_construct_while_pending: bool,
    public_mining_achieved_claim: bool,
) -> Option<S19kAmlRefuseGate> {
    if !board_name_ok || !chip_id_ok {
        return Some(S19kAmlRefuseGate::R1Identity);
    }
    if offers_pic_owner {
        return Some(S19kAmlRefuseGate::R2NoPicClass);
    }
    if s21_fuse {
        return Some(S19kAmlRefuseGate::R3S21Fuse);
    }
    if !lm75_before_probe {
        return Some(S19kAmlRefuseGate::R4Lm75BeforeProbe);
    }
    if !watchdog_ok {
        return Some(S19kAmlRefuseGate::R5Watchdog);
    }
    if baud_dialects_merged {
        return Some(S19kAmlRefuseGate::R6BaudDialect);
    }
    if rail_enable_before_gates {
        return Some(S19kAmlRefuseGate::R7RailEnable);
    }
    if mining_default_enabled {
        return Some(S19kAmlRefuseGate::R8MiningDefault);
    }
    if engine_construct_while_pending {
        return Some(S19kAmlRefuseGate::R9EngineConstruct);
    }
    if public_mining_achieved_claim {
        return Some(S19kAmlRefuseGate::R10PublicClaim);
    }
    None
}

/// B1 stage_2 ordered steps (EVIDENCED `set_asic_register_stage_2` / `sub_5F848`).
/// Host-testable order only — does not claim am3 ttyS framing closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum S19kWireStage2Step {
    AnalogMux = 0,
    ChainInactive = 1,
    SetAddress = 2,
    CoreHashClock = 3,
    CoreClockDelay = 4,
    UartRelayIfDomainsGt9 = 5,
}

#[derive(Debug, Default)]
pub struct S19kWireStage2Latch {
    highest: Option<S19kWireStage2Step>,
}

impl S19kWireStage2Latch {
    pub fn advance(&mut self, next: S19kWireStage2Step) -> Result<(), String> {
        let required = match next {
            S19kWireStage2Step::AnalogMux => None,
            S19kWireStage2Step::ChainInactive => Some(S19kWireStage2Step::AnalogMux),
            S19kWireStage2Step::SetAddress => Some(S19kWireStage2Step::ChainInactive),
            S19kWireStage2Step::CoreHashClock => Some(S19kWireStage2Step::SetAddress),
            S19kWireStage2Step::CoreClockDelay => Some(S19kWireStage2Step::CoreHashClock),
            S19kWireStage2Step::UartRelayIfDomainsGt9 => Some(S19kWireStage2Step::CoreClockDelay),
        };
        if let Some(prev) = required {
            match self.highest {
                Some(h) if h >= prev => {}
                _ => {
                    return Err(format!(
                        "S19k Wire stage_2 refused: cannot enter {next:?} before {prev:?}"
                    ));
                }
            }
        }
        self.highest = Some(match self.highest {
            Some(h) if h > next => h,
            _ => next,
        });
        Ok(())
    }
}

/// S19k has 11 voltage domains → UART relay path is required after stage_2 core regs.
pub const S19K_VOLTAGE_DOMAINS: u8 = 11;
pub const fn s19k_requires_uart_relay() -> bool {
    S19K_VOLTAGE_DOMAINS > 9
}

/// Track-1 transport select for runtime-try admit (Wire CLEAR_BRAIINS_TTY).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kTrack1TransportKind {
    /// Stock AML `/dev/uart_trans` mmap/ioctl path (Track 2 / stock image).
    StockUartTrans,
    /// Braiins raw `/dev/ttyS1`+`/dev/ttyS2` @ 3M 8N1 (Track-1 opt-in).
    BraiinsRawTtyS,
}

/// Soft DESK_PENDING / ownership gates that keep runtime engine try refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kWireDeskPending {
    /// am3 UART framing vs jig CMD — CLOSED desk 11d/11e → false.
    pub am3_uart_framing_unconfirmed: bool,
    /// jig/AML interval-2 vs public floor-3 — **reconciled desk 11g** (prefer 2) → false.
    /// Live am3 set_address capture stays DESK_PENDING in comments only; does not re-open this flag.
    pub addr_interval_unreconciled: bool,
    /// work-frame bytes / uart_trans pack — CLOSED desk 11d/11e/11f → false.
    pub work_frame_bytes_unpinned: bool,
    /// Stock `/dev/uart_trans` runtime ownership not claimed by Lead — stock path refuse.
    /// Refuse reason is **stock uart_trans unowned**, NOT open MS8 fan-out (CLOSED Wire 11e).
    /// BraiinsRawTtyS path **ignores** this flag (uses `braiins_ttys_bench_go` instead).
    pub uart_trans_runtime_unowned: bool,
    /// Braiins Track-1 Bench GO. DEFAULT false — fail-closed until explicit Bench GO.
    /// When false, `admit_s19k_bm1366_wire_runtime_try(..., BraiinsRawTtyS, ...)` refuses
    /// with [`S19kWireRuntimeTryError::BraiinsTtyBenchGoRequired`].
    pub braiins_ttys_bench_go: bool,
}

impl S19kWireDeskPending {
    /// Current honest desk state for S19k Wire B pack (post desk 11d/11e/11f/11g + CLEAR_BRAIINS_TTY).
    /// `addr_interval_unreconciled` cleared desk 11g (AML preferred=2). Lead does **not**
    /// auto-clear `uart_trans_runtime_unowned` (stock) or `braiins_ttys_bench_go` (Braiins).
    pub const CURRENT: Self = Self {
        am3_uart_framing_unconfirmed: false,
        addr_interval_unreconciled: false, // CLOSED desk 11g — AML addr_interval=2
        work_frame_bytes_unpinned: false,
        uart_trans_runtime_unowned: true, // stock still blocked
        braiins_ttys_bench_go: false,     // Braiins fail-closed until Bench GO
    };

    /// Legacy helper: true while **stock** uart_trans path soft-gates still block.
    pub const fn blocks_runtime_engine_try(self) -> bool {
        self.blocks_runtime_engine_try_for(S19kTrack1TransportKind::StockUartTrans)
    }

    /// Transport-aware soft-gate block (framing/work_frame/addr + ownership/GO).
    pub const fn blocks_runtime_engine_try_for(self, transport: S19kTrack1TransportKind) -> bool {
        let soft = self.am3_uart_framing_unconfirmed
            || self.addr_interval_unreconciled
            || self.work_frame_bytes_unpinned;
        match transport {
            S19kTrack1TransportKind::StockUartTrans => soft || self.uart_trans_runtime_unowned,
            S19kTrack1TransportKind::BraiinsRawTtyS => soft || !self.braiins_ttys_bench_go,
        }
    }
}

/// Env knob for Braiins Track-1 Bench GO (runtime override; does not mutate CURRENT).
pub const BRAIINS_TTYS_BENCH_GO_ENV: &str = "DCENT_BRAIINS_TTYS_BENCH_GO";
/// File knob for Braiins Track-1 Bench GO (regular non-symlink file, any content / empty OK).
pub const BRAIINS_TTYS_BENCH_GO_FILE: &str = "/etc/dcentos/braiins_ttys_bench_go";

/// True if env `DCENT_BRAIINS_TTYS_BENCH_GO` is `"1"` or `"true"` (case-insensitive)
/// **or** if `/etc/dcentos/braiins_ttys_bench_go` is a regular non-symlink file
/// (any content / empty OK). Else false. Fail-closed on errors and special
/// objects. Does **not** mutate [`S19kWireDeskPending::CURRENT`].
pub fn braiins_ttys_bench_go_from_runtime() -> bool {
    braiins_ttys_bench_go_from_runtime_parts(
        std::env::var_os(BRAIINS_TTYS_BENCH_GO_ENV),
        BRAIINS_TTYS_BENCH_GO_FILE,
    )
}

/// Testable core for [`braiins_ttys_bench_go_from_runtime`].
pub fn braiins_ttys_bench_go_from_runtime_parts(
    env_val: Option<std::ffi::OsString>,
    file_path: &str,
) -> bool {
    if let Some(v) = env_val {
        let s = v.to_string_lossy();
        let t = s.trim();
        if t.eq_ignore_ascii_case("1") || t.eq_ignore_ascii_case("true") {
            return true;
        }
    }
    std::fs::symlink_metadata(file_path)
        .map(|metadata| metadata.file_type().is_file() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

/// Copy of [`S19kWireDeskPending::CURRENT`] with `braiins_ttys_bench_go` taken from
/// [`braiins_ttys_bench_go_from_runtime`]. CURRENT itself stays false.
pub fn current_with_runtime_bench_go() -> S19kWireDeskPending {
    let mut p = S19kWireDeskPending::CURRENT;
    p.braiins_ttys_bench_go = braiins_ttys_bench_go_from_runtime();
    p
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S19kWireRuntimeTryError {
    Am3UartFramingDeskPending,
    AddrIntervalUnreconciled {
        public: u8,
        jig: u8,
    },
    WorkFrameBytesDeskPending,
    /// Stock `/dev/uart_trans` transport unowned — NOT MS8 fan-out (fan-out CLOSED Wire 11e).
    UartTransRuntimeUnowned,
    /// Braiins raw ttyS path requires explicit Bench GO (`braiins_ttys_bench_go`).
    BraiinsTtyBenchGoRequired,
    MidstateSixteenForbidden,
    BaudDialectMergeForbidden,
    PicOwnerForbidden,
}

/// Fail-closed gate for **runtime engine try** (AML refuse matrix R9 / soft gates).
/// Install-route lab_only / checklist A may still ship; this refuses GetAddress/work dispatch
/// claims while the selected transport soft-gate remains closed.
/// - StockUartTrans: refuse while `uart_trans_runtime_unowned` (Track 2 ownership).
/// - BraiinsRawTtyS: **ignore** stock unowned; refuse while `!braiins_ttys_bench_go`.
/// Cleared framing / work_frame / addr_interval flags do **not** refuse; MS8 fan-out is CLOSED
/// (Wire 11e); addr_interval pinned desk 11g. Lead does **not** auto-clear ownership / Bench GO.
pub fn admit_s19k_bm1366_wire_runtime_try(
    pending: S19kWireDeskPending,
    transport: S19kTrack1TransportKind,
    midstate_number: u8,
    merge_jig_12m_with_public_1m: bool,
    offers_pic_owner: bool,
) -> Result<(), S19kWireRuntimeTryError> {
    if offers_pic_owner {
        return Err(S19kWireRuntimeTryError::PicOwnerForbidden);
    }
    if midstate_number != S19K_WIRE_MIDSTATE_NUMBER {
        return Err(S19kWireRuntimeTryError::MidstateSixteenForbidden);
    }
    if merge_jig_12m_with_public_1m {
        return Err(S19kWireRuntimeTryError::BaudDialectMergeForbidden);
    }
    match transport {
        S19kTrack1TransportKind::StockUartTrans => {
            if pending.uart_trans_runtime_unowned {
                return Err(S19kWireRuntimeTryError::UartTransRuntimeUnowned);
            }
        }
        S19kTrack1TransportKind::BraiinsRawTtyS => {
            // Ignore stock uart_trans unowned — Braiins gated on Bench GO only.
            if !pending.braiins_ttys_bench_go {
                return Err(S19kWireRuntimeTryError::BraiinsTtyBenchGoRequired);
            }
        }
    }
    if pending.am3_uart_framing_unconfirmed {
        return Err(S19kWireRuntimeTryError::Am3UartFramingDeskPending);
    }
    if pending.addr_interval_unreconciled {
        return Err(S19kWireRuntimeTryError::AddrIntervalUnreconciled {
            public: S19K_PUBLIC_ADDR_INTERVAL,
            jig: S19K_JIG_ADDR_INTERVAL,
        });
    }
    if pending.work_frame_bytes_unpinned {
        return Err(S19kWireRuntimeTryError::WorkFrameBytesDeskPending);
    }
    Ok(())
}

/// Public floor helper (`bm1397plus_addr_interval(77)` → 3). Documented only —
/// **do not** bind as S19k AML SoT; call [`refuse_s19k_public_floor_as_aml_interval`].
pub fn s19k_public_floor_addr_interval() -> u8 {
    let public = bm1397plus_addr_interval(S19K_WIRE_ASIC_NUM);
    debug_assert_eq!(public, S19K_PUBLIC_ADDR_INTERVAL);
    public
}

/// Prefer AML / BHB5690x interval **2** (desk 11g). Public floor=3 is refused for this family.
pub fn s19k_preferred_addr_interval() -> u8 {
    // Assert preferred is 2, not public floor(256/77)=3.
    debug_assert_eq!(S19K_AML_ADDR_INTERVAL, 2);
    debug_assert_ne!(S19K_AML_ADDR_INTERVAL, S19K_PUBLIC_ADDR_INTERVAL);
    let _ = refuse_s19k_public_floor_as_aml_interval(S19K_AML_ADDR_INTERVAL);
    S19K_AML_ADDR_INTERVAL
}

/// Jig bucket interval for the same population (equals AML preferred; desk 11b/11g).
pub fn s19k_jig_addr_interval() -> u8 {
    bitmain_jig_addr_interval(S19K_WIRE_ASIC_NUM).unwrap_or(0)
}

/// Refuse inventing public `bm1397plus_addr_interval(77)=3` as S19k AML SoT
/// (`BM1366_WIRE_BRINGUP.md` § Desk 2026-08-11g). Preferred interval is **2**, not 3.
pub fn refuse_s19k_public_floor_as_aml_interval(interval: u8) -> Result<(), &'static str> {
    if interval == S19K_PUBLIC_ADDR_INTERVAL {
        return Err(
            "S19k BHB5690x / am3-s19kpro AML: refuse public floor(256/77)=3; preferred asic_addr_interval=2 (desk 11g)",
        );
    }
    if interval != S19K_AML_ADDR_INTERVAL {
        return Err(
            "S19k BHB5690x / am3-s19kpro AML: preferred asic_addr_interval is 2 (BM1366_WIRE_BRINGUP.md § Desk 2026-08-11g)",
        );
    }
    Ok(())
}

/// Enum / set_address addresses for S19k AML: `linear_chip_addresses(77, 2)`.
/// ASIC count remains [`S19K_WIRE_ASIC_NUM`] (77). Slot count hint: 256/2 = 128.
pub fn s19k_aml_linear_addresses() -> Vec<u8> {
    linear_chip_addresses(S19K_WIRE_ASIC_NUM, S19K_AML_ADDR_INTERVAL)
}

/// Alias: preferred linear map is AML step-2 (desk 11g). Not public floor step-3.
pub fn s19k_public_linear_addresses() -> Vec<u8> {
    s19k_aml_linear_addresses()
}

fn crc5_cmd(body: &[u8]) -> u8 {
    stock_bitmain_crc5(body, body.len() * 8)
}

/// 5-byte GetAddress broadcast: `52 05 00 00 CRC5` (`0x0A`).
pub fn cmd_get_address_bcast() -> [u8; 5] {
    cmd_read_register_bcast(0x00)
}

/// Broadcast `read_register(reg)`: `52 05 00 RR CRC5`.
/// GetAddress is `reg=0x00`. FastUART is `reg=0x28`.
/// Not single-chip `42 05 AA RR`.
pub fn cmd_read_register_bcast(reg: u8) -> [u8; 5] {
    let mut f = [CMD_GET_ADDRESS, 0x05, 0x00, reg, 0];
    f[4] = crc5_cmd(&f[..4]);
    f
}

/// Full UART TX: `55 AA` + [`cmd_read_register_bcast`].
pub fn pack_read_register_bcast_uart(reg: u8) -> [u8; 7] {
    let body = cmd_read_register_bcast(reg);
    [0x55, 0xAA, body[0], body[1], body[2], body[3], body[4]]
}

/// 5-byte chain-inactive broadcast: `53 05 00 00 CRC5` (`0x03`).
pub fn cmd_chain_inactive_bcast() -> [u8; 5] {
    let mut f = [CMD_CHAIN_INACTIVE, 0x05, 0x00, 0x00, 0];
    f[4] = crc5_cmd(&f[..4]);
    f
}

/// Pre- `cmd_chain_inactive_bcast` emitted GetAddress `0x52`.
pub fn refuse_get_address_bytes_as_chain_inactive(body: &[u8]) -> Result<(), &'static str> {
    if body == [0x52u8, 0x05, 0x00, 0x00, 0x0A] {
        return Err("52 05 00 00 0A is GetAddress; chain-inactive is 53 05 00 00 03");
    }
    Ok(())
}

/// 5-byte set_address: `40 05 AA 00 CRC5`.
pub fn cmd_set_address(addr: u8) -> [u8; 5] {
    let mut f = [CMD_SET_ADDRESS, 0x05, addr, 0x00, 0];
    f[4] = crc5_cmd(&f[..4]);
    f
}

/// On-wire set_address for uart_trans / Braiins raw ttyS (desk 11g deepen): TX prepends `55 AA`.
///
/// CLOSED template: `55 AA 40 05 <addr> 00 <crc5>`. Live am3 capture still DESK_PENDING —
/// templates only; Braiins userspace writes this full frame under CLEAR_BRAIINS_TTY.
pub fn pack_set_address_uart_trans(addr: u8) -> [u8; 7] {
    let body = cmd_set_address(addr);
    [0x55, 0xAA, body[0], body[1], body[2], body[3], body[4]]
}

/// 9-byte set_config: `51/41 09 AA RR VV VV VV VV CRC5`.
pub fn cmd_set_config(broadcast: bool, chip_addr: u8, reg: u8, value: u32) -> [u8; 9] {
    let mut f = [
        if broadcast {
            CMD_SET_CONFIG_BCAST
        } else {
            CMD_SET_CONFIG_UNICAST
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

pub fn next_job_id(prev: u8) -> u8 {
    prev.wrapping_add(S19K_WIRE_JOB_ID_STEP) % S19K_WIRE_JOB_ID_MOD
}

pub fn pattern_number_ok_for_midstate8(pattern_number: u8) -> bool {
    pattern_number == S19K_WIRE_MIDSTATE_NUMBER && pattern_number % 2 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b1_cmd_templates_match_wire_desk_crc5() {
        assert_eq!(cmd_get_address_bcast(), [0x52, 0x05, 0x00, 0x00, 0x0a]);
        assert_eq!(cmd_read_register_bcast(0x00), cmd_get_address_bcast());
        assert_eq!(
            pack_read_register_bcast_uart(0x00),
            [0x55, 0xAA, 0x52, 0x05, 0x00, 0x00, 0x0A]
        );
        let r28 = cmd_read_register_bcast(PUBLIC_FASTUART_REG);
        assert_eq!(&r28[..4], &[0x52, 0x05, 0x00, 0x28]);
        assert_ne!(r28[4], 0);
        assert_ne!(r28, cmd_get_address_bcast());
        assert_eq!(
            pack_read_register_bcast_uart(PUBLIC_FASTUART_REG)[2],
            0x52,
            "broadcast read is 0x52, not single-chip 0x42"
        );
        assert_eq!(cmd_chain_inactive_bcast(), [0x53, 0x05, 0x00, 0x00, 0x03]);
        assert!(
            refuse_get_address_bytes_as_chain_inactive(&[0x52, 0x05, 0x00, 0x00, 0x0A]).is_err()
        );
        assert_eq!(CMD_GET_ADDRESS, 0x52);
        assert_eq!(CMD_CHAIN_INACTIVE, 0x53);
        assert_eq!(
            S19K_JIG_VOLTAGE_DOMAIN * S19K_JIG_ASICS_PER_DOMAIN,
            S19K_WIRE_ASIC_NUM
        );
        assert_eq!(cmd_set_address(0), [0x40, 0x05, 0x00, 0x00, 0x1c]);
        assert_eq!(cmd_set_address(2), [0x40, 0x05, 0x02, 0x00, 0x01]);
        assert_eq!(cmd_set_address(3), [0x40, 0x05, 0x03, 0x00, 0x1d]);
    }

    #[test]
    fn b1_interval_aml_pinned_step2_refuse_public_floor3() {
        // Public floor helper still reports 3 — but S19k AML must not bind it (desk 11g).
        assert_eq!(bm1397plus_addr_interval(77), S19K_PUBLIC_ADDR_INTERVAL);
        assert_eq!(bitmain_jig_addr_interval(77), Some(S19K_AML_ADDR_INTERVAL));
        assert_eq!(S19K_AML_ADDR_INTERVAL, 2);
        assert_eq!(S19K_AML_ADDR_SLOT_COUNT, 128);
        assert_eq!(s19k_preferred_addr_interval(), 2);
        assert_eq!(s19k_jig_addr_interval(), 2);
        assert_eq!(s19k_preferred_addr_interval(), s19k_jig_addr_interval());
        assert_ne!(s19k_preferred_addr_interval(), S19K_PUBLIC_ADDR_INTERVAL);
        assert!(refuse_s19k_public_floor_as_aml_interval(3).is_err());
        assert!(refuse_s19k_public_floor_as_aml_interval(2).is_ok());
        let addrs = s19k_aml_linear_addresses();
        assert_eq!(addrs.len(), usize::from(S19K_WIRE_ASIC_NUM));
        assert_eq!(addrs[0], 0);
        assert_eq!(addrs[1], 2);
        assert_eq!(addrs[76], 152); // (77-1)*2
        assert!(!S19kWireDeskPending::CURRENT.addr_interval_unreconciled);
    }

    #[test]
    fn b1_open_core_regs_and_stage2_set_config_frames() {
        assert_eq!(CORE_REG_HASH_CLOCK, 0x8000_8540);
        assert_eq!(CORE_REG_CLOCK_DELAY, 0x8000_8020);
        assert_eq!(CORE_REG_ASICBOOST, 0x8000_82AA);
        assert_eq!(
            cmd_set_config(true, 0, REG_ANALOG_MUX, ANALOG_MUX_DIODE_VDD_SEL),
            [0x51, 0x09, 0x00, 0x54, 0x00, 0x00, 0x00, 0x03, 0x1d]
        );
        assert_eq!(
            cmd_set_config(true, 0, REG_CORE, CORE_REG_HASH_CLOCK),
            [0x51, 0x09, 0x00, 0x3c, 0x80, 0x00, 0x85, 0x40, 0x0c]
        );
        assert_eq!(
            cmd_set_config(true, 0, REG_CORE, CORE_REG_CLOCK_DELAY),
            [0x51, 0x09, 0x00, 0x3c, 0x80, 0x00, 0x80, 0x20, 0x19]
        );
        assert_eq!(
            cmd_set_config(false, 0, REG_CORE, CORE_REG_ASICBOOST),
            [0x41, 0x09, 0x00, 0x3c, 0x80, 0x00, 0x82, 0xaa, 0x05]
        );
    }

    #[test]
    fn b2_pll_and_baud_dialects_not_merged() {
        assert_eq!(REG_PLL0, 0x08);
        assert_eq!(REG_PLL1, 0x60);
        assert_eq!(PLL_RAMP_START_MHZ, 50);
        assert_eq!(PUBLIC_FASTUART_VALUE, 0x1130_0200);
        assert_eq!(JIG_CONFIG_BAUD_HZ, 12_000_000);
        assert!(matches!(
            admit_s19k_bm1366_wire_runtime_try(
                S19kWireDeskPending {
                    am3_uart_framing_unconfirmed: false,
                    addr_interval_unreconciled: false,
                    work_frame_bytes_unpinned: false,
                    uart_trans_runtime_unowned: false,
                    braiins_ttys_bench_go: false,
                },
                S19kTrack1TransportKind::StockUartTrans,
                8,
                true,
                false,
            ),
            Err(S19kWireRuntimeTryError::BaudDialectMergeForbidden)
        ));
    }

    #[test]
    fn b3_ticket_mask_frame_and_most_hw_num() {
        assert_eq!(MOST_HW_NUM, 128);
        assert_eq!(
            cmd_set_config(
                true,
                0,
                REG_TICKET_MASK,
                TICKET_MASK_PLAIN_DIFF_MINUS_ONE_256
            ),
            [0x51, 0x09, 0x00, 0x14, 0x00, 0x00, 0x00, 0xff, 0x08]
        );
    }

    #[test]
    fn b4_midstate8_abi_pins_and_refuses_s21_sixteen() {
        assert_eq!(S19K_WIRE_MIDSTATE_NUMBER, 8);
        assert!(pattern_number_ok_for_midstate8(8));
        assert!(!pattern_number_ok_for_midstate8(16));
        assert_eq!(PUBLIC_FPGA_JOB_HDR, 0x21);
        assert_eq!(PUBLIC_FPGA_JOB_LEN, 0x56);
        assert_eq!(S19K_WIRE_RESPONSE_BYTES, 11);
        assert_eq!(S19K_WIRE_HASH_COUNTING, 0x0000_115A);
        assert_eq!(next_job_id(0), 8);
        assert_eq!(next_job_id(120), 0);
        assert!(matches!(
            admit_s19k_bm1366_wire_runtime_try(
                S19kWireDeskPending::CURRENT,
                S19kTrack1TransportKind::StockUartTrans,
                16,
                false,
                false
            ),
            Err(S19kWireRuntimeTryError::MidstateSixteenForbidden)
        ));
        assert!(!S19kWireDeskPending::CURRENT.work_frame_bytes_unpinned);
        assert!(S19kWireDeskPending::CURRENT.uart_trans_runtime_unowned);
    }

    #[test]
    fn b5_asic_register_config_knobs() {
        // Config.ini: CCdly=0 Pwth=4 Swpf=0 Clk_Sel=0 Diode_Vdd_Mux_Sel=3
        assert_eq!(CORE_REG_CLOCK_DELAY, 0x8000_8020);
        assert_eq!(CORE_REG_HASH_CLOCK, 0x8000_8540); // Clk_Sel=0
        assert_eq!(ANALOG_MUX_DIODE_VDD_SEL, 3);
        // Pulse_Mode=1 bit placement remains DESK_PENDING — we do not invent packing here.
    }

    #[test]
    fn runtime_try_refused_while_desk_pending() {
        assert!(S19kWireDeskPending::CURRENT.blocks_runtime_engine_try());
        assert!(S19kWireDeskPending::CURRENT.uart_trans_runtime_unowned);
        assert!(!S19kWireDeskPending::CURRENT.braiins_ttys_bench_go);
        assert!(!S19kWireDeskPending::CURRENT.am3_uart_framing_unconfirmed);
        assert!(!S19kWireDeskPending::CURRENT.work_frame_bytes_unpinned);
        assert!(!S19kWireDeskPending::CURRENT.addr_interval_unreconciled); // cleared desk 11g
                                                                           // CURRENT refuse is transport unowned only — NOT addr_interval (CLOSED 11g),
                                                                           // NOT framing, NOT MS8 fan-out (CLOSED Wire 11e). Lead does not auto-clear ownership.
        assert!(matches!(
            admit_s19k_bm1366_wire_runtime_try(
                S19kWireDeskPending::CURRENT,
                S19kTrack1TransportKind::StockUartTrans,
                8,
                false,
                false
            ),
            Err(S19kWireRuntimeTryError::UartTransRuntimeUnowned)
        ));
        assert!(matches!(
            admit_s19k_bm1366_wire_runtime_try(
                S19kWireDeskPending {
                    am3_uart_framing_unconfirmed: false,
                    addr_interval_unreconciled: true,
                    work_frame_bytes_unpinned: false,
                    uart_trans_runtime_unowned: false,
                    braiins_ttys_bench_go: false,
                },
                S19kTrack1TransportKind::StockUartTrans,
                8,
                false,
                false,
            ),
            Err(S19kWireRuntimeTryError::AddrIntervalUnreconciled { public: 3, jig: 2 })
        ));
        assert!(matches!(
            admit_s19k_bm1366_wire_runtime_try(
                S19kWireDeskPending {
                    am3_uart_framing_unconfirmed: false,
                    addr_interval_unreconciled: false,
                    work_frame_bytes_unpinned: true,
                    uart_trans_runtime_unowned: false,
                    braiins_ttys_bench_go: false,
                },
                S19kTrack1TransportKind::StockUartTrans,
                8,
                false,
                false,
            ),
            Err(S19kWireRuntimeTryError::WorkFrameBytesDeskPending)
        ));
        assert!(matches!(
            admit_s19k_bm1366_wire_runtime_try(
                S19kWireDeskPending {
                    am3_uart_framing_unconfirmed: false,
                    addr_interval_unreconciled: false,
                    work_frame_bytes_unpinned: false,
                    uart_trans_runtime_unowned: false,
                    braiins_ttys_bench_go: false,
                },
                S19kTrack1TransportKind::StockUartTrans,
                8,
                false,
                true,
            ),
            Err(S19kWireRuntimeTryError::PicOwnerForbidden)
        ));
    }

    #[test]
    fn b5_uart_relay_packing_matches_public_chip0() {
        assert_eq!(
            pack_uart_relay(true, true, UART_RELAY_CHIP0_DIST),
            UART_RELAY_CHIP0_PUBLIC
        );
        assert_eq!(UART_RELAY_CHIP0_PUBLIC, 0x007C_0003);
        assert_eq!(REG_UART_RELAY, 0x2C);
        assert!(admit_bosminer_uart_relay_pack_matches_public_chip0().is_ok());
        assert!(refuse_uart_relay_without_nonce_gap_field().is_err());
        assert_eq!(
            pack_uart_relay_braiins(true, true, true, UART_RELAY_CHIP0_DIST),
            0x007C_0007
        );
        assert_eq!(BOSMINER_UART_RELAY_PACK_FN_VA, 0x0083_CA30);
        let f = cmd_uart_relay_chip0();
        assert_eq!(f[0], CMD_SET_CONFIG_UNICAST);
        assert_eq!(f[2], 0x00);
        assert_eq!(f[3], REG_UART_RELAY);
        assert_eq!(&f[4..8], &[0x00, 0x7c, 0x00, 0x03]);
        assert_eq!(f[8], stock_bitmain_crc5(&f[..8], 64));
    }

    #[test]
    fn b4_hash_counting_set_config_frame() {
        assert_eq!(REG_HASH_COUNTING, 0x10);
        let body = [0x51u8, 0x09, 0x00, 0x10, 0x00, 0x00, 0x11, 0x5a];
        let mut expect = [0u8; 9];
        expect[..8].copy_from_slice(&body);
        expect[8] = stock_bitmain_crc5(&body, 64);
        assert_eq!(cmd_hash_counting_s19k_bcast(), expect);
    }

    #[test]
    fn aml_refuse_matrix_r1_through_r10() {
        assert_eq!(
            aml_hard_refuse(
                true, true, false, false, true, true, false, false, false, false, false
            ),
            None
        );
        assert_eq!(
            aml_hard_refuse(
                false, true, false, false, true, true, false, false, false, false, false
            ),
            Some(S19kAmlRefuseGate::R1Identity)
        );
        assert_eq!(
            aml_hard_refuse(true, true, true, false, true, true, false, false, false, false, false),
            Some(S19kAmlRefuseGate::R2NoPicClass)
        );
        assert_eq!(
            aml_hard_refuse(true, true, false, true, true, true, false, false, false, false, false),
            Some(S19kAmlRefuseGate::R3S21Fuse)
        );
        assert_eq!(
            aml_hard_refuse(
                true, true, false, false, false, true, false, false, false, false, false
            ),
            Some(S19kAmlRefuseGate::R4Lm75BeforeProbe)
        );
        assert_eq!(
            aml_hard_refuse(
                true, true, false, false, true, false, false, false, false, false, false
            ),
            Some(S19kAmlRefuseGate::R5Watchdog)
        );
        assert_eq!(
            aml_hard_refuse(true, true, false, false, true, true, true, false, false, false, false),
            Some(S19kAmlRefuseGate::R6BaudDialect)
        );
        assert_eq!(
            aml_hard_refuse(true, true, false, false, true, true, false, true, false, false, false),
            Some(S19kAmlRefuseGate::R7RailEnable)
        );
        assert_eq!(
            aml_hard_refuse(true, true, false, false, true, true, false, false, true, false, false),
            Some(S19kAmlRefuseGate::R8MiningDefault)
        );
        assert_eq!(
            aml_hard_refuse(true, true, false, false, true, true, false, false, false, true, false),
            Some(S19kAmlRefuseGate::R9EngineConstruct)
        );
        assert_eq!(
            aml_hard_refuse(true, true, false, false, true, true, false, false, false, false, true),
            Some(S19kAmlRefuseGate::R10PublicClaim)
        );
        assert!(S19kWireDeskPending::CURRENT.blocks_runtime_engine_try());
    }

    #[test]
    fn b1_stage2_order_latch_and_uart_relay_required() {
        assert!(s19k_requires_uart_relay());
        let mut latch = S19kWireStage2Latch::default();
        assert!(latch.advance(S19kWireStage2Step::SetAddress).is_err());
        latch.advance(S19kWireStage2Step::AnalogMux).unwrap();
        latch.advance(S19kWireStage2Step::ChainInactive).unwrap();
        latch.advance(S19kWireStage2Step::SetAddress).unwrap();
        latch.advance(S19kWireStage2Step::CoreHashClock).unwrap();
        latch.advance(S19kWireStage2Step::CoreClockDelay).unwrap();
        latch
            .advance(S19kWireStage2Step::UartRelayIfDomainsGt9)
            .unwrap();
    }

    #[test]
    fn desk_11g_set_address_uart_trans_preamble() {
        assert_eq!(
            pack_set_address_uart_trans(0),
            [0x55, 0xAA, 0x40, 0x05, 0x00, 0x00, 0x1c]
        );
        assert_eq!(
            pack_set_address_uart_trans(2),
            [0x55, 0xAA, 0x40, 0x05, 0x02, 0x00, 0x01]
        );
        let addrs = s19k_aml_linear_addresses();
        assert_eq!(addrs[0], 0);
        assert_eq!(addrs[1], 2); // interval=2
        assert_eq!(
            pack_set_address_uart_trans(addrs[1]),
            [0x55, 0xAA, 0x40, 0x05, 0x02, 0x00, 0x01]
        );
    }

    #[test]
    fn clear_braiins_ttys_runtime_try_gated_on_bench_go() {
        // CURRENT + BraiinsRawTtyS → BenchGoRequired (not silent Ok; ignores stock unowned)
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
        // CURRENT + StockUartTrans → UartTransRuntimeUnowned
        assert!(matches!(
            admit_s19k_bm1366_wire_runtime_try(
                S19kWireDeskPending::CURRENT,
                S19kTrack1TransportKind::StockUartTrans,
                8,
                false,
                false,
            ),
            Err(S19kWireRuntimeTryError::UartTransRuntimeUnowned)
        ));
        // Bench GO + Braiins + midstate 8 → Ok (stock unowned ignored)
        let go = S19kWireDeskPending {
            am3_uart_framing_unconfirmed: false,
            addr_interval_unreconciled: false,
            work_frame_bytes_unpinned: false,
            uart_trans_runtime_unowned: true, // still true — Braiins ignores
            braiins_ttys_bench_go: true,
        };
        assert_eq!(
            admit_s19k_bm1366_wire_runtime_try(
                go,
                S19kTrack1TransportKind::BraiinsRawTtyS,
                8,
                false,
                false,
            ),
            Ok(())
        );
        // midstate 16 still hard-forbid under Braiins GO
        assert!(matches!(
            admit_s19k_bm1366_wire_runtime_try(
                go,
                S19kTrack1TransportKind::BraiinsRawTtyS,
                16,
                false,
                false,
            ),
            Err(S19kWireRuntimeTryError::MidstateSixteenForbidden)
        ));
        assert!(go.blocks_runtime_engine_try_for(S19kTrack1TransportKind::StockUartTrans));
        assert!(!go.blocks_runtime_engine_try_for(S19kTrack1TransportKind::BraiinsRawTtyS));
        assert!(S19kWireDeskPending::CURRENT
            .blocks_runtime_engine_try_for(S19kTrack1TransportKind::BraiinsRawTtyS));
    }

    #[test]
    fn clear_braiins_ttys_pins_baud_3m_never_ttys0() {
        use crate::s19k_uart_trans_job::{
            admit_braiins_job_tx_path, admit_job_tx_path, admit_job_tx_path_for_transport,
            BRAIINS_RAW_TTYS_PINS, BRAIINS_TTYS_BAUD, BRAIINS_TTYS_CANDIDATES,
            BRAIINS_TTYS_FORBIDDEN,
        };
        assert_eq!(BRAIINS_TTYS_BAUD, 3_000_000);
        assert_eq!(BRAIINS_RAW_TTYS_PINS.baud, 3_000_000);
        assert_eq!(BRAIINS_TTYS_CANDIDATES, &["/dev/ttyS1", "/dev/ttyS2"]);
        assert_eq!(BRAIINS_TTYS_FORBIDDEN, &["/dev/ttyS0"]);
        assert!(!BRAIINS_TTYS_CANDIDATES.contains(&"/dev/ttyS0"));
        assert!(!BRAIINS_TTYS_CANDIDATES.contains(&"/dev/ttyS3"));
        assert!(admit_braiins_job_tx_path("/dev/ttyS1").is_ok());
        assert!(admit_braiins_job_tx_path("/dev/ttyS2").is_ok());
        assert!(admit_braiins_job_tx_path("/dev/ttyS3").is_ok());
        assert!(admit_braiins_job_tx_path("/dev/ttyS0").is_err());
        assert!(admit_job_tx_path("/dev/ttyS1").is_err()); // stock unchanged
        assert!(admit_job_tx_path_for_transport(false, "/dev/ttyS1").is_ok());
        assert!(admit_job_tx_path_for_transport(false, "/dev/ttyS3").is_ok());
    }

    #[test]
    fn runtime_bench_go_override_env_and_current_stays_false() {
        assert!(!S19kWireDeskPending::CURRENT.braiins_ttys_bench_go);
        // Explicit parts: no env, missing file → false (fail-closed)
        assert!(!braiins_ttys_bench_go_from_runtime_parts(
            None,
            "/no/such/braiins_ttys_bench_go_zzz"
        ));
        assert!(!braiins_ttys_bench_go_from_runtime_parts(
            Some(std::ffi::OsString::from("0")),
            "/no/such/braiins_ttys_bench_go_zzz",
        ));
        assert!(!braiins_ttys_bench_go_from_runtime_parts(
            Some(std::ffi::OsString::from("yes")),
            "/no/such/braiins_ttys_bench_go_zzz",
        ));
        assert!(braiins_ttys_bench_go_from_runtime_parts(
            Some(std::ffi::OsString::from("1")),
            "/no/such/braiins_ttys_bench_go_zzz",
        ));
        assert!(braiins_ttys_bench_go_from_runtime_parts(
            Some(std::ffi::OsString::from("TRUE")),
            "/no/such/braiins_ttys_bench_go_zzz",
        ));
        assert!(braiins_ttys_bench_go_from_runtime_parts(
            Some(std::ffi::OsString::from(" true ")),
            "/no/such/braiins_ttys_bench_go_zzz",
        ));
        // Regular-file presence (temp) → true even without env.
        let dir = std::env::temp_dir();
        let path = dir.join("dcent_braiins_ttys_bench_go_unit");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"").expect("temp marker");
        assert!(braiins_ttys_bench_go_from_runtime_parts(
            None,
            path.to_str().expect("utf8 temp path"),
        ));
        let _ = std::fs::remove_file(&path);
        assert!(!braiins_ttys_bench_go_from_runtime_parts(
            None,
            dir.to_str().expect("utf8 temp directory"),
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let target = dir.join("dcent_braiins_ttys_bench_go_target_unit");
            let link = dir.join("dcent_braiins_ttys_bench_go_symlink_unit");
            let _ = std::fs::remove_file(&target);
            let _ = std::fs::remove_file(&link);
            std::fs::write(&target, b"").expect("temp marker target");
            symlink(&target, &link).expect("temp marker symlink");
            assert!(!braiins_ttys_bench_go_from_runtime_parts(
                None,
                link.to_str().expect("utf8 temp symlink"),
            ));
            let _ = std::fs::remove_file(&link);
            let _ = std::fs::remove_file(&target);
        }
        // CURRENT must remain false after helpers
        assert!(!S19kWireDeskPending::CURRENT.braiins_ttys_bench_go);
        // current_with_runtime_bench_go mirrors CURRENT except bench_go from runtime env/file.
        // Under default host env (no knob) → false; with env parts we already proved true.
        let pending_false = {
            let mut p = S19kWireDeskPending::CURRENT;
            p.braiins_ttys_bench_go = braiins_ttys_bench_go_from_runtime_parts(
                None,
                "/no/such/braiins_ttys_bench_go_zzz",
            );
            p
        };
        assert!(!pending_false.braiins_ttys_bench_go);
        assert!(matches!(
            admit_s19k_bm1366_wire_runtime_try(
                pending_false,
                S19kTrack1TransportKind::BraiinsRawTtyS,
                8,
                false,
                false,
            ),
            Err(S19kWireRuntimeTryError::BraiinsTtyBenchGoRequired)
        ));
        let pending_true = {
            let mut p = S19kWireDeskPending::CURRENT;
            p.braiins_ttys_bench_go = braiins_ttys_bench_go_from_runtime_parts(
                Some(std::ffi::OsString::from("1")),
                "/no/such/braiins_ttys_bench_go_zzz",
            );
            p
        };
        assert!(pending_true.braiins_ttys_bench_go);
        assert_eq!(
            admit_s19k_bm1366_wire_runtime_try(
                pending_true,
                S19kTrack1TransportKind::BraiinsRawTtyS,
                8,
                false,
                false,
            ),
            Ok(())
        );
        assert!(!S19kWireDeskPending::CURRENT.braiins_ttys_bench_go);
    }
}
