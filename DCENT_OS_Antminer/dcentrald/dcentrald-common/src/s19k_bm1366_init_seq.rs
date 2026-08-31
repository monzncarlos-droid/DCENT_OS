//! S19k BM1366 **EXPERIMENTAL** native init program (host-testable).
//!
//! Does not open UART, energize rails, or claim mining. Native BM1366
//! cold-init remains refused in `serial_mining.rs`. This module pins the
//! evidence-supported UART bytes without inventing opcodes. The typed
//! [`S19kBm1366NativeExecutionProgram`] owns exact command ordering, per-command
//! dwells, the stock FastUART pair, and the requested target PLL used by the
//! dormant executor. It is still **not** a production transaction: hot-start
//! reset admission, fresh query barriers, multi-UART route ownership, cooling,
//! rails, rollback, and terminal SafeOff remain engine/physical gates.
//!
//! : `wire_b::CMD_CHAIN_INACTIVE = 0x53`. GetAddress is `CMD_GET_ADDRESS = 0x52`.

use crate::bm1366_pll_reg_and_actual;
use crate::s19k_bm1366_uart_rx::{
    S19kRxDiag, CHAIN_INACTIVE_UART, ESP_BM1366_CHIP_ID_RX_LEN, GET_ADDRESS_UART, UART_RESP_LEN,
};
use crate::s19k_bm1366_wire_b::{
    cmd_set_config, pack_set_address_uart_trans, pack_uart_relay, s19k_aml_linear_addresses,
    CORE_REG_ASICBOOST, CORE_REG_CLOCK_DELAY, CORE_REG_HASH_CLOCK, PLL_RAMP_START_MHZ,
    PUBLIC_FASTUART_REG, PUBLIC_FASTUART_VALUE, REG_PLL0, REG_TICKET_MASK, REG_UART_RELAY,
    REG_VERSION_ROLL, S19K_WIRE_HASH_COUNTING, TICKET_MASK_PLAIN_DIFF_MINUS_ONE_256,
    UART_RELAY_CHIP0_PUBLIC,
};
use crate::s19k_uart_trans_job::{BRAIINS_TTYS_BAUD, BRAIINS_TTYS_DISCOVER};

/// On-chip version rolling register (desk 11e / ESP-Miner family).
pub const INIT_REG_VERSION_ROLL: u8 = REG_VERSION_ROLL;
/// Ticket mask register.
pub const INIT_REG_TICKET_MASK: u8 = REG_TICKET_MASK;
/// Hash counting register (stock S19k `0x0000115A`).
pub const INIT_REG_HASH_COUNTING: u8 = 0x10;
/// Init-control / mystery register (ESP-Miner `init4` + per-chip `set_a8`).
pub const INIT_REG_INIT_CTRL: u8 = 0xA8;
/// ESP-Miner BM1366 broadcast `0xA8` (`55 AA 51 09 00 A8 00 07 00 00 …`).
pub const INIT_CTRL_A8_BCAST: u32 = 0x0007_0000;
/// ESP-Miner BM1366 per-chip `0xA8` (`41 09 <addr> A8 00 07 01 F0`).
pub const INIT_CTRL_A8_UNICAST: u32 = 0x0007_01F0;
/// ESP-Miner per-chip MiscCtrl (`41 09 <addr> 18 F0 00 C1 00`).
pub const MISC_CTRL_UNICAST: u32 = 0xF000_C100;
/// `FIRMWARE_INTERNALS.md` BM1366 per-chip `0xA8 = 0xF0010700` contradicts
/// the ESP UART bytes. Refuse it as the S19k program value.
pub const REFUSED_INTERNALS_A8_PER_CHIP: u32 = 0xF001_0700;
/// `bosminer.unpacked` file offset of bytes `00 00 11 5A`.
/// PHDR maps this to VA `0x019A20A6` (NOT file+0x400000).
pub const BOSMINER_115A_BE_FILE_OFF: u64 = 0x0159_20A6;
pub const BOSMINER_115A_BE_VA: u64 = 0x019A_20A6;
/// Sole Ghidra data xref near this constant: tuner `FUN_0065f830` @ `0x664c0c`
/// (string `bosminer_plus_tuner`). **Not** a UART `set_config` writer.
pub const BOSMINER_115A_TUNER_XREF_VA: u64 = 0x0066_4C0C;
/// `FUN_008434e0` logs “HCN divider / serial versions / frequency / max work
/// time” using `12_500_000 / freq`. Work-time arithmetic, **not** a UART
/// `set_config(reg=0x10)` writer.
pub const BOSMINER_HCN_DIVIDER_LOG_FN_VA: u64 = 0x0084_34E0;
/// Crystal used by that log for max-work-time, not a hash-count register.
pub const BOSMINER_HCN_DIVIDER_LOG_XTAL_HZ: u32 = 12_500_000;
/// ASCII `hash_counting_number`. Ghidra xref is metrics registrar
/// `FUN_0041ea18` @ `0x41ee38` (`PARAM`), not a UART `set_config`.
pub const BOSMINER_HASH_COUNTING_NUMBER_STR_VA: u64 = 0x0139_DB65;
pub const BOSMINER_HASH_COUNTING_NUMBER_XREF_FN_VA: u64 = 0x0041_EA18;
/// Serde `TicketMaskReg` → `ticket_mask`. Not a UART writer.
pub const BOSMINER_TICKET_MASK_SERDE_FN_VA: u64 = 0x0086_F5E0;
/// Count of 4-aligned ARM64 `MOVZ Wd, #0x51` in `bosminer.unpacked`.
/// Sample `FUN_008c4bfc` allocates a 0x51-byte VoltageController panic
/// string — **not** UART set_config `0x51`.
pub const BOSMINER_MOVZ51_HITS: usize = 33;
pub const BOSMINER_MOVZ51_VOLTAGE_ALLOC_VA: u64 = 0x008C_4BFC;
/// ESP-Miner `BM1366_set_max_baud` FastUART host rate. Not 3 M / 115200.
pub const ESP_FASTUART_HOST_BAUD: u32 = 1_000_000;
/// `a lab unit` dmesg: meson wake 9600→115200 and **hold** (no 3M step).
pub const S19K_78_DMESG_HOLD_BAUD: u32 = 115_200;
/// ESP `BM1366_set_default_baud` writes **MiscCtrl 0x18**, not FastUART 0x28.
/// Payload `{0x00,0x00,0b01111010,0b00110001}` = `0x00007A31`. Divider 26
/// (`11010`) in bits 9-13. Formula `25e6/((div+1)*8)` = 115740; ESP returns
/// 115749. Neither is a Track-1 `0x28` leave-115200 encoding.
pub const ESP_BM1366_MISCCTRL_DEFAULT_BAUD_REG: u8 = 0x18;
pub const ESP_BM1366_MISCCTRL_DEFAULT_BAUD_VALUE: u32 = 0x0000_7A31;
pub const ESP_BM1366_MISCCTRL_DEFAULT_BAUD_DIV: u32 = 26;
pub const ESP_BM1366_MISCCTRL_XTAL_HZ: u32 = 25_000_000;
pub const ESP_BM1366_SET_DEFAULT_BAUD_RETURN_HZ: u32 = 115_749;
/// bosminer-hal write_reg / read_register live in `command.rs`.
pub const BOSMINER_HAL_COMMAND_RS_VA: u64 = 0x0130_3F89;
/// `CHAIN/: Set baud rate @ requested: ..., actual: ...` string pieces.
/// Generic `AntminerDriver::init` at `0x00836e2c` references the descriptor
/// at `0x019bb508`; the string itself starts here with `CHAIN/`.
pub const BOSMINER_SET_BAUD_RATE_STR_VA: u64 = 0x0131_B8D5;
pub const BOSMINER_SET_BAUD_RATE_REQUESTED_STR_VA: u64 = 0x0131_B8DB;
pub const BOSMINER_SET_BAUD_RATE_ACTUAL_STR_VA: u64 = 0x0131_B8F8;
pub const BOSMINER_SET_BAUD_RATE_LOG_DESCRIPTOR_VA: u64 = 0x019B_B508;
pub const BOSMINER_ANTMINER_DRIVER_INIT_FUTURE_FN_VA: u64 = 0x0083_6E2C;
/// packed_struct field blob including `ext_baud_enable` (FastUartReg).
/// Adjacent names: `unknown_bits_31_28` … `rfs` … `tfs`.
pub const BOSMINER_FASTUART_FIELDS_STR_VA: u64 = 0x0132_0C4B;
/// Bible BM1366 3.125 Mbaud FastUART at reg `0x28`. Not S19k host `3_000_000`.
pub const : u32 = 0x0000_3001;
/// Bible / live BM1362 3.125 Mbaud FastUART at reg `0x28`.
pub const : u32 = 0x0000_3011;
/// Host rate that matches the bible BM1366 encoding. Distinct from Track-1 3M.
pub const : u32 = 3_125_000;
/// Exact stock BM1366 builder result for requested 3.125 Mbaud. This is not
/// the public-bible `0x3001`: the held S19k bosminer BM1366 vtable selects
/// `FUN_008dd3b8`, whose `mode=2` input to the common `0x28` packer produces
/// `0x00003011`. Stock BM1362 uses the same numeric word, so chip/platform
/// provenance remains mandatory.
pub const BOSMINER_BM1366_FASTUART_3M125: u32 = 0x0000_3011;
/// The other baud admitted by bosminer's common selector, requested 1 Mbaud.
pub const BOSMINER_BM1366_FASTUART_1M: u32 = 0x0002_3011;
pub const BOSMINER_BM1366_FASTUART_REG: u8 = 0x28;
pub const BOSMINER_BM1366_REQUESTED_FAST_BAUD: u32 = 3_125_000;
/// `antminer_aml.rs` accepts requested 3.125 Mbaud but configures Linux
/// `B3000000`; this is the exact stock S19k semantic/termios pairing.
pub const BOSMINER_BM1366_AML_HOST_BAUD: u32 = 3_000_000;
/// Exact held AMTC S19k Pro repair-jig binary used for the clean-room
/// `set_chain_baud` reconstruction below.
pub const AMTC_BM1366_JIG_SHA256: &str =
    "cd1b4c047d40d6de9e040dbda537a4944ff8290b278d22bc885ea9cae020c4eb";
/// Ghidra function address in [`AMTC_BM1366_JIG_SHA256`].
pub const AMTC_BM1366_SET_CHAIN_BAUD_FN_VA: u64 = 0x0007_51AC;
pub const AMTC_BM1366_CHAIN_INIT_FN_VA: u64 = 0x0005_ED10;
pub const AMTC_BM1366_STRICT_ENUM_FN_VA: u64 = 0x0002_4C18;
pub const AMTC_BM1366_SET_ADDRESS_LADDER_FN_VA: u64 = 0x0007_5140;
pub const AMTC_BM1366_UART_RELAY_FN_VA: u64 = 0x0005_DF08;
pub const AMTC_BM1366_POST_RESET_INIT_FN_VA: u64 = 0x0005_E030;
/// AMTC FPGA RX thread and its register-response enqueue helper. The helper
/// consumes a repacked eight-byte record; it is not the raw `AA 55` UART view.
pub const AMTC_BM1366_RX_THREAD_FN_VA: u64 = 0x0005_EA90;
pub const AMTC_BM1366_REGISTER_RESPONSE_ENQUEUE_FN_VA: u64 = 0x0005_E7B4;
/// AMTC local register-cache accessors and the write-and-cache wrapper.
pub const AMTC_BM1366_REGISTER_CACHE_GET_FN_VA: u64 = 0x0007_6270;
pub const AMTC_BM1366_REGISTER_CACHE_UPDATE_FN_VA: u64 = 0x0007_6364;
pub const AMTC_BM1366_WRITE_AND_CACHE_FN_VA: u64 = 0x0007_4C1C;
/// Called with argument `3` after the optional successful readdress branch.
/// Its broader semantic name remains unresolved; do not label it an ASIC ACK.
pub const AMTC_BM1366_POST_SUCCESS_HOOK_FN_VA: u64 = 0x0002_5544;
/// AMTC ticket-mask byte-LUT writer and the LUT virtual address.
pub const AMTC_BM1366_TICKET_MASK_WRITE_FN_VA: u64 = 0x0007_5310;
pub const AMTC_BM1366_TICKET_MASK_BIT_REVERSE_LUT_VA: u64 = 0x001A_3300;
/// Enclosing factory-flow calls following successful board/chain setup. At
/// `0x000643ee` the caller passes `(50, effective_target_mhz)` to
/// `FUN_0005e314`, immediately calls `FUN_0005e484`, then dwells one second.
pub const AMTC_BM1366_FACTORY_FREQ_CALLER_VA: u64 = 0x0006_43EE;
pub const AMTC_BM1366_POST_INIT_FREQ_FN_VA: u64 = 0x0005_E314;
pub const AMTC_BM1366_STANDARD_FREQ_RAMP_FN_VA: u64 = 0x0005_D8D4;
pub const AMTC_BM1366_ALTERNATE_FREQ_RAMP_FN_VA: u64 = 0x0005_DAF8;
pub const AMTC_BM1366_POST_RAMP_FASTUART_CALL_VA: u64 = 0x0005_E3BE;
pub const AMTC_BM1366_POST_FREQ_CONFIG_FN_VA: u64 = 0x0005_E484;
pub const AMTC_BM1366_POST_FREQ_CONFIG_CALL_VA: u64 = 0x0006_43F6;
pub const AMTC_BM1366_FACTORY_POST_CONFIG_DWELL_MS: u32 = 1_000;
pub const AMTC_BM1366_FREQ_RAMP_START_MHZ: u32 = 50;
pub const AMTC_BM1366_FREQ_RAMP_STEP_X100_MHZ: u32 = 625;
pub const AMTC_BM1366_STANDARD_FREQ_WRITE_DWELL_MS: u32 = 300;
pub const AMTC_BM1366_POST_FREQ_TICKET_LOGICAL: u32 = 0x0000_007F;
pub const AMTC_BM1366_POST_FREQ_TICKET_WIRE: u32 = 0x0000_00FE;
/// `CMP baud, 0x002dc6c1; BLS low_path`: 3,000,000 uses the 25 MHz
/// reference; 3,000,001 and above use the PLL1-assisted 400 MHz path.
pub const AMTC_BM1366_PLL1_BAUD_THRESHOLD: u32 = 3_000_001;
pub const AMTC_BM1366_UART_LOW_CLOCK_HZ: u32 = 25_000_000;
pub const AMTC_BM1366_UART_PLL1_CLOCK_HZ: u32 = 400_000_000;
/// Reset/default values documented for the BM1366 register file. These are
/// useful golden inputs, not permission to skip response validation. AMTC
/// `FUN_000751ac` itself reads the jig's local broadcast cache, not the RX ring.
pub const AMTC_BM1366_PLL1_RESET: u32 = 0x0064_0111;
pub const AMTC_BM1366_FASTUART_RESET: u32 = 0x0130_1A00;

/// Which held AMTC ramp routine config byte `+0xf5` selects. These names
/// describe the control-flow provenance only; the alternate routine's
/// feedback source and dwell policy remain unresolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmtcBm1366FrequencyRampRoutine {
    StandardFixedDwell,
    AlternateConfigSelected,
}

/// AMTC-specific post-chain-init frequency evidence. This is not a complete
/// executor plan: `effective_target_mhz` was produced by the enclosing jig
/// helper, and neither that helper's flex policy nor PLL acceptance is modeled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmtcBm1366PostInitFrequencyPlan {
    pub start_mhz: u32,
    pub effective_target_mhz: u32,
    pub step_x100_mhz: u32,
    pub ramp_routine: AmtcBm1366FrequencyRampRoutine,
    pub ramp_function_va: u64,
    /// Only the standard routine has a fixed 300 ms dwell proven here.
    pub fixed_write_dwell_ms: Option<u32>,
    /// Both branches reconverge at `0x0005e3b6`, load config `+0x240`, and
    /// call `FUN_000751ac` after the ramp.
    pub reapplies_fast_uart_after_ramp: bool,
}

pub const fn amtc_bm1366_post_init_frequency_plan(
    effective_target_mhz: u32,
    alternate_ramp_selected: bool,
) -> AmtcBm1366PostInitFrequencyPlan {
    let (ramp_routine, ramp_function_va, fixed_write_dwell_ms) = if alternate_ramp_selected {
        (
            AmtcBm1366FrequencyRampRoutine::AlternateConfigSelected,
            AMTC_BM1366_ALTERNATE_FREQ_RAMP_FN_VA,
            None,
        )
    } else {
        (
            AmtcBm1366FrequencyRampRoutine::StandardFixedDwell,
            AMTC_BM1366_STANDARD_FREQ_RAMP_FN_VA,
            Some(AMTC_BM1366_STANDARD_FREQ_WRITE_DWELL_MS),
        )
    };
    AmtcBm1366PostInitFrequencyPlan {
        start_mhz: AMTC_BM1366_FREQ_RAMP_START_MHZ,
        effective_target_mhz,
        step_x100_mhz: AMTC_BM1366_FREQ_RAMP_STEP_X100_MHZ,
        ramp_routine,
        ramp_function_va,
        fixed_write_dwell_ms,
        reapplies_fast_uart_after_ramp: true,
    }
}

/// Number of PLL writes made by held standard ramp `FUN_0005d8d4` after its
/// setup-only 50 MHz PLL calculation. The routine uses 6.25 MHz steps, clips
/// to the integer-MHz target, and deliberately emits the clipped target once
/// more: `ceil(abs(target-50)/6.25) + 1` writes.
pub fn amtc_bm1366_standard_ramp_write_count(effective_target_mhz: u32) -> u32 {
    let start_x100 = u64::from(AMTC_BM1366_FREQ_RAMP_START_MHZ) * 100;
    let target_x100 = u64::from(effective_target_mhz) * 100;
    let delta_x100 = start_x100.abs_diff(target_x100);
    let step = u64::from(AMTC_BM1366_FREQ_RAMP_STEP_X100_MHZ);
    ((delta_x100 + step - 1) / step) as u32 + 1
}

/// Exact centi-MHz frequency submitted to `FUN_000755f8` for a one-based
/// standard-ramp write index. This intentionally excludes the preceding
/// setup-only `FUN_00075444(50.0)` calculation, which is not passed to the
/// writer in the held binary.
pub fn amtc_bm1366_standard_ramp_write_frequency_x100(
    effective_target_mhz: u32,
    one_based_write_index: u32,
) -> Result<u64, &'static str> {
    let write_count = amtc_bm1366_standard_ramp_write_count(effective_target_mhz);
    if one_based_write_index == 0 || one_based_write_index > write_count {
        return Err("AMTC standard-ramp write index is outside the held loop");
    }
    let start_x100 = u64::from(AMTC_BM1366_FREQ_RAMP_START_MHZ) * 100;
    let target_x100 = u64::from(effective_target_mhz) * 100;
    let delta_x100 = start_x100.abs_diff(target_x100);
    let travelled = (u64::from(one_based_write_index)
        * u64::from(AMTC_BM1366_FREQ_RAMP_STEP_X100_MHZ))
    .min(delta_x100);
    Ok(if target_x100 >= start_x100 {
        start_x100 + travelled
    } else {
        start_x100 - travelled
    })
}

/// Ticket selection in held post-frequency function `FUN_0005e484`. Only the
/// `config[0x114] == 0 && config[0x10d] != 0` branch writes logical all-ones;
/// every other observed branch writes logical `0x7f`. The wire value retains
/// AMTC's bytewise bit-reversal provenance and must not be generalized to the
/// Braiins or ESP dialect without independent evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmtcBm1366PostFrequencyTicketPlan {
    pub logical_value: u32,
    pub wire_value: u32,
}

pub const fn amtc_bm1366_post_frequency_ticket_plan(
    config_0x114_nonzero: bool,
    config_0x10d_nonzero: bool,
) -> AmtcBm1366PostFrequencyTicketPlan {
    let logical_value = if !config_0x114_nonzero && config_0x10d_nonzero {
        0x0000_FFFF
    } else {
        AMTC_BM1366_POST_FREQ_TICKET_LOGICAL
    };
    AmtcBm1366PostFrequencyTicketPlan {
        logical_value,
        wire_value: amtc_bm1366_ticket_mask_wire_value(logical_value),
    }
}

/// Provenance of a register value inside the held AMTC jig.
///
/// `FUN_00076270` selects either a local broadcast/per-ASIC cache. Fresh wire
/// responses instead enter the separate ring through `FUN_0005e7b4`. Keeping
/// these variants typed prevents a cache lookup from being reported as a
/// fresh ASIC response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmtcBm1366RegisterValueSource {
    LocalBroadcastCache,
    LocalPerAsicCache,
    WireResponseRing,
}

impl AmtcBm1366RegisterValueSource {
    pub const fn is_fresh_wire_response(self) -> bool {
        matches!(self, Self::WireResponseRing)
    }
}

/// Pure reconstruction of the AMTC BM1366 jig's register writes. It models
/// bytes only: it does not authorize UART I/O, choose a host baud, or prove
/// that a board accepted/read back either write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmtcBm1366FastUartPlan {
    /// `FUN_000751ac` obtains both RMW inputs from the local broadcast cache.
    pub rmw_input_source: AmtcBm1366RegisterValueSource,
    pub target_baud: u32,
    pub reference_clock_hz: u32,
    pub divider_minus_one: u8,
    pub pll1_write: Option<u32>,
    /// High path only: the jig writes PLL1 twice.
    pub pll1_write_repetitions: u8,
    /// Dwell after each PLL1 write in the jig function.
    pub pll1_post_write_dwell_ms: u16,
    pub fast_uart_write: u32,
    /// The jig waits 10 ms + 50 ms after FastUART before changing the host.
    pub fast_uart_post_write_dwell_ms: u16,
}

/// Reproduce `FUN_000751ac` from the held S19k Pro jig.
///
/// Do not replace this with `dcentrald-asic`'s BM1362 transform. A fresh
/// side-by-side disassembly of BM1362 `FUN_0002cb14` shows that BM1366 alone
/// performs the extra high-byte `BFI ..., 2, #3, #2` on both branches. The
/// older corpus note calling these functions byte-identical was incorrect.
///
/// The effective high-speed fixed bits are `0x9450_0000`, even though the
/// final ARM instruction ORs `0x8450_0000`: an earlier `BFI high_byte,2,3,2`
/// contributes the additional `0x1000_0000`. Likewise the low path forces
/// high-byte bits 4:3 to `0b10` before clearing bits 6 and 2. Keeping those
/// operations explicit prevents the mask simplification bug that previously
/// lost the mode bit.
pub fn amtc_bm1366_fast_uart_plan(
    pll1_cached_value: u32,
    fast_uart_cached_value: u32,
    target_baud: u32,
) -> Result<AmtcBm1366FastUartPlan, &'static str> {
    let denominator = target_baud
        .checked_mul(8)
        .ok_or("BM1366 target baud overflows baud*8")?;
    if denominator == 0 {
        return Err("BM1366 target baud must be nonzero");
    }

    let high_path = target_baud >= AMTC_BM1366_PLL1_BAUD_THRESHOLD;
    let reference_clock_hz = if high_path {
        AMTC_BM1366_UART_PLL1_CLOCK_HZ
    } else {
        AMTC_BM1366_UART_LOW_CLOCK_HZ
    };
    let divider = reference_clock_hz / denominator;
    if !(1..=256).contains(&divider) {
        return Err("BM1366 jig UART divider is outside its 8-bit encoded range");
    }
    let divider_minus_one = (divider - 1) as u8;

    // Thumb `BFI ..., #8, #9` clears bits 8..=16, but the source was first
    // narrowed by `UXTB`, so the inserted bit 16 is always zero.
    let with_divider =
        (fast_uart_cached_value & !0x0001_FF00) | (u32::from(divider_minus_one) << 8);

    let (pll1_write, fast_uart_write) = if high_path {
        // PLL1: exact BFI/BFC sequence, written twice by the jig with 10 ms
        // between writes before FastUART is changed.
        let pll1_write = (pll1_cached_value & 0xD000_C088) | 0x5060_0111;

        // FastUART: BFI high-byte bits 3..4 = 2; BFI upper-half bits 4..9 =
        // 5; then OR high byte with 0x84. This simplifies to the mask below.
        let fast_uart_write = (with_divider & 0xE40E_FFFF) | 0x9450_0000;
        (Some(pll1_write), fast_uart_write)
    } else {
        // FastUART: BFI high-byte bits 3..4 = 2, clear high-byte bits 6 and
        // 2. PLL1 is untouched on this branch.
        let fast_uart_write = (with_divider & 0xA3FE_FFFF) | 0x1000_0000;
        (None, fast_uart_write)
    };

    Ok(AmtcBm1366FastUartPlan {
        rmw_input_source: AmtcBm1366RegisterValueSource::LocalBroadcastCache,
        target_baud,
        reference_clock_hz,
        divider_minus_one,
        pll1_write,
        pll1_write_repetitions: if high_path { 2 } else { 0 },
        pll1_post_write_dwell_ms: if high_path { 10 } else { 0 },
        fast_uart_write,
        fast_uart_post_write_dwell_ms: 60,
    })
}

/// Exact S19k factory-jig chain-init region beginning with the first strict
/// enumeration and ending at its three-count/expected-count evaluation. The
/// jig records the minimum count on disagreement before a later status gate;
/// an evidence-backed production executor should fail closed at this point.
/// Platform setup,
/// fan ownership, GPIO power sequencing, and the earlier one-second FPGA
/// reset are deliberately outside this manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmtcBm1366ChainInitOp {
    /// "Strict" names `FUN_00024c18`'s chip-ID/address-response checks. A pass
    /// count mismatch does not immediately abort: the caller retries once and
    /// defers the success/failure decision until all three counts are compared.
    StrictEnumerate {
        pass: u8,
        retry_once: bool,
    },
    ChainInactive,
    SetAddress {
        address: u8,
    },
    WriteUartRelay {
        voltage_domain: u8,
        address: u8,
        value: u32,
    },
    SetIoDriverHighNibbleF {
        voltage_domain: u8,
        address: u8,
    },
    SetChipAndHostBaud {
        plan: AmtcBm1366FastUartPlan,
    },
    FpgaChainResetAssert,
    FpgaChainResetRelease,
    SetHostBaudDivider {
        divider: u8,
    },
    ResetHostUartBuffers,
    PostResetA8MiscRmw {
        plan: AmtcBm1366A8MiscRmwPlan,
    },
    TicketMaskAllOnes,
    ClearRxFifo,
    /// Model the branch after the third enumeration. The held jig marks the
    /// chain-init stage successful only when pass 1, pass 2, pass 3, and the
    /// configured expected count all agree. On disagreement it stores the
    /// minimum observed count and falls through to a later board-status gate;
    /// it does not immediately return from this comparison block.
    EvaluateThreeEnumCountsAgainstExpected {
        expected_count: u8,
        mismatch_records_minimum: bool,
    },
    /// Opaque held-jig hook after the optional successful readdress sequence.
    /// Only the call target and argument are proven.
    PostSuccessHook {
        function_va: u64,
        argument: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmtcBm1366ChainInitStep {
    pub op: AmtcBm1366ChainInitOp,
    pub dwell_after_ms: u16,
}

/// One voltage-domain iteration of AMTC `FUN_0005df08`. Each iteration
/// writes UART_RELAY at two boundary chips and sets IO-driver register 0x58's
/// high nibble to `0xF` at the second boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmtcBm1366RelayDomainPlan {
    pub voltage_domain: u8,
    pub first_address: u8,
    pub first_uart_relay_value: u32,
    pub second_address: u8,
    pub second_uart_relay_value: u32,
    pub io_driver_address: u8,
    pub io_driver_high_nibble: u8,
}

/// Exact register read-modify-write output of AMTC `FUN_00075aa4(chain, 0)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmtcBm1366A8MiscRmwPlan {
    /// Both inputs come from `FUN_00076270(level=0)`, not the response ring.
    pub rmw_input_source: AmtcBm1366RegisterValueSource,
    pub init_control_a8_write: u32,
    pub misc_control_18_write: u32,
}

pub const fn amtc_bm1366_post_reset_rmw_plan(
    init_control_a8_cached_value: u32,
    misc_control_18_cached_value: u32,
) -> AmtcBm1366A8MiscRmwPlan {
    AmtcBm1366A8MiscRmwPlan {
        rmw_input_source: AmtcBm1366RegisterValueSource::LocalBroadcastCache,
        init_control_a8_write: init_control_a8_cached_value & 0xFFFF_FFF0,
        misc_control_18_write: (misc_control_18_cached_value & 0x00FF_FFFF) | 0xFF0F_0000,
    }
}

/// Exact `FUN_00075140` ladder arithmetic: send `floor(256 / interval)`
/// commands, starting at zero and adding `interval` after every command.
/// This is deliberately not the separate ESP-derived 77-chip ladder.
pub fn amtc_bm1366_set_address_ladder(address_interval: u8) -> Result<Vec<u8>, &'static str> {
    if address_interval == 0 {
        return Err("AMTC SetAddress interval must be nonzero");
    }
    let command_count = 256usize / usize::from(address_interval);
    Ok((0..command_count)
        .map(|index| (index * usize::from(address_interval)) as u8)
        .collect())
}

/// Outcome of the comparison block after AMTC's third enumeration pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmtcBm1366ThreePassEvaluation {
    pub expected_count: u16,
    pub observed_counts: [u16; 3],
    pub stage_marked_success: bool,
    /// On disagreement the jig publishes the minimum of the three observations.
    pub recorded_count: u16,
    /// Config byte `+0x5a` triggers inactive + the complete address ladder only
    /// after all three observations equal the expected count.
    pub post_success_readdress: bool,
}

/// Reproduce the exact comparison/optional-readdress decision in
/// `FUN_0005ed10`. Each individual pass has already received at most one retry
/// before its count reaches this function.
pub const fn amtc_bm1366_evaluate_three_passes(
    expected_count: u16,
    observed_counts: [u16; 3],
    software_set_address_enabled: bool,
) -> AmtcBm1366ThreePassEvaluation {
    let success = observed_counts[0] == expected_count
        && observed_counts[1] == observed_counts[0]
        && observed_counts[2] == observed_counts[0];
    let minimum = if observed_counts[0] < observed_counts[1] {
        if observed_counts[0] < observed_counts[2] {
            observed_counts[0]
        } else {
            observed_counts[2]
        }
    } else if observed_counts[1] < observed_counts[2] {
        observed_counts[1]
    } else {
        observed_counts[2]
    };
    AmtcBm1366ThreePassEvaluation {
        expected_count,
        observed_counts,
        stage_marked_success: success,
        recorded_count: if success { observed_counts[2] } else { minimum },
        post_success_readdress: success && software_set_address_enabled,
    }
}

/// Materialize the optional branch controlled by config byte `+0x5a` after
/// three-pass success: inactive, the same complete `floor(256/interval)`
/// ladder, then the opaque `FUN_00025544(3)` hook. A mismatch never enters it.
pub fn amtc_bm1366_post_success_readdress_manifest(
    evaluation: AmtcBm1366ThreePassEvaluation,
    address_interval: u8,
) -> Result<Vec<AmtcBm1366ChainInitStep>, &'static str> {
    if !evaluation.post_success_readdress {
        return Ok(Vec::new());
    }
    let addresses = amtc_bm1366_set_address_ladder(address_interval)?;
    let mut steps = Vec::with_capacity(addresses.len() + 2);
    steps.push(AmtcBm1366ChainInitStep {
        op: AmtcBm1366ChainInitOp::ChainInactive,
        dwell_after_ms: 10,
    });
    for address in addresses {
        steps.push(AmtcBm1366ChainInitStep {
            op: AmtcBm1366ChainInitOp::SetAddress { address },
            dwell_after_ms: 10,
        });
    }
    steps.push(AmtcBm1366ChainInitStep {
        op: AmtcBm1366ChainInitOp::PostSuccessHook {
            function_va: AMTC_BM1366_POST_SUCCESS_HOOK_FN_VA,
            argument: 3,
        },
        dwell_after_ms: 0,
    });
    Ok(steps)
}

/// AMTC FPGA-side register record after `FUN_0006eccc` has repacked FIFO
/// words. This is not an `AA 55` UART frame. The held ARM32 code loads bytes
/// 4..7 with `LDR`, hence the explicit little-endian host-word interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmtcBm1366RegisterResponse {
    pub chain: u8,
    pub flags: u8,
    pub asic_address: u8,
    pub register_address: u8,
    pub value_host_le: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmtcBm1366RegisterResponseError {
    NonRegisterRecord,
    CrcFlagBitsSet { flags: u8 },
    WrongChain { observed: u8, expected: u8 },
}

/// Model the admission checks split across AMTC `FUN_0005ea90` and
/// `FUN_0005e7b4`. The hardware-provided `flags & 0x60` test is not a software
/// CRC5 recomputation and must not be presented as one.
pub fn amtc_bm1366_decode_fpga_register_response(
    record: [u8; 8],
    expected_chain: u8,
) -> Result<AmtcBm1366RegisterResponse, AmtcBm1366RegisterResponseError> {
    let flags = record[3];
    if flags & 0x80 != 0 {
        return Err(AmtcBm1366RegisterResponseError::NonRegisterRecord);
    }
    if flags & 0x60 != 0 {
        return Err(AmtcBm1366RegisterResponseError::CrcFlagBitsSet { flags });
    }
    let chain = record[0] & 0x0F;
    if chain != expected_chain {
        return Err(AmtcBm1366RegisterResponseError::WrongChain {
            observed: chain,
            expected: expected_chain,
        });
    }
    Ok(AmtcBm1366RegisterResponse {
        chain,
        flags,
        asic_address: record[2],
        register_address: record[1],
        value_host_le: u32::from_le_bytes([record[4], record[5], record[6], record[7]]),
    })
}

/// Address-response view used by AMTC strict-enumeration mode. The held code
/// checks chip ID in value bits 31:16 and divides value bits 7:0 by the address
/// interval. It does not require the value address to equal the separately
/// queued ASIC-address byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmtcBm1366AddressResponseView {
    pub chip_id: u16,
    pub value_address: u8,
    pub slot_floor: u8,
    pub interval_aligned: bool,
}

pub fn amtc_bm1366_address_response_view(
    response: AmtcBm1366RegisterResponse,
    address_interval: u8,
) -> Result<AmtcBm1366AddressResponseView, &'static str> {
    if address_interval == 0 {
        return Err("AMTC address-response interval must be nonzero");
    }
    let value_address = (response.value_host_le & 0xFF) as u8;
    Ok(AmtcBm1366AddressResponseView {
        chip_id: (response.value_host_le >> 16) as u16,
        value_address,
        slot_floor: value_address / address_interval,
        interval_aligned: value_address % address_interval == 0,
    })
}

/// AMTC `FUN_00075310` transforms every byte through the held bit-reversal
/// LUT before writing register `0x14`. The earlier chain-init all-ones call is
/// invariant, but post-frequency `FUN_0005e484` supplies the non-invariant
/// AMTC vector logical `0x7f` -> wire `0xfe`. This still does not establish
/// the Braiins or ESP production encoding.
pub const fn amtc_bm1366_ticket_mask_wire_value(logical_value: u32) -> u32 {
    crate::bit_reverse_u32_bytewise(logical_value)
}

/// Reconstruct the exact 11-domain / 7-chip S19k relay topology programmed by
/// AMTC `FUN_0005df08`. It is intentionally distinct from the single chip-0
/// Braiins value `0x007c0003`; neither strategy is evidence that the other can
/// be omitted.
pub fn amtc_bm1366_uart_relay_domain_plan(
    address_interval: u8,
    asic_count: u8,
    voltage_domains: u8,
    chips_per_domain: u8,
) -> Result<Vec<AmtcBm1366RelayDomainPlan>, &'static str> {
    if (
        address_interval,
        asic_count,
        voltage_domains,
        chips_per_domain,
    ) != (2, 77, 11, 7)
    {
        return Err("AMTC S19k relay plan requires exact interval2/77-chip/11x7 geometry");
    }
    let relay_base = u16::from(asic_count) + u16::from(chips_per_domain) + 13;
    let mut plans = Vec::with_capacity(usize::from(voltage_domains));
    for voltage_domain in (0..voltage_domains).rev() {
        let first_index = u16::from(voltage_domain) * u16::from(chips_per_domain);
        let second_index = first_index + u16::from(chips_per_domain) - 1;
        let first_address = u16::from(address_interval) * first_index;
        let second_address = u16::from(address_interval) * second_index;
        if first_address > u16::from(u8::MAX) || second_address > u16::from(u8::MAX) {
            return Err("AMTC S19k relay boundary overflows the ASIC address space");
        }
        let first_gap = relay_base - first_index;
        let second_gap = relay_base - second_index;
        plans.push(AmtcBm1366RelayDomainPlan {
            voltage_domain,
            first_address: first_address as u8,
            first_uart_relay_value: pack_uart_relay(true, true, first_gap),
            second_address: second_address as u8,
            second_uart_relay_value: pack_uart_relay(true, true, second_gap),
            io_driver_address: second_address as u8,
            io_driver_high_nibble: 0xF,
        });
    }
    Ok(plans)
}

/// Build the factory-jig chain-init evidence manifest for the exact S19k
/// interval (`2`). This is a descriptive, offline-testable sequence, not an
/// executable hardware authority.
///
/// The four RMW inputs are AMTC local broadcast-cache values. The returned
/// base sequence ends at the comparison block because this function has no
/// config-byte input; use [`amtc_bm1366_evaluate_three_passes`] followed by
/// [`amtc_bm1366_post_success_readdress_manifest`] for the optional `+0x5a`
/// branch.
///
/// The FastUART target is a bounded factory-test phase: it precedes pass 2,
/// then the jig asserts/releases chain reset, restores host divisor `0x1a`,
/// clears host buffers, performs post-reset writes, and only then runs pass 3.
/// This ordering is evidence for a high-baud validation pass, not proof that
/// production mining should remain at that target after reset.
///
/// Important difference from the ESP-derived native byte manifest below:
/// `FUN_00075140` sends `256 / address_interval` SetAddress commands. For the
/// S19k interval 2 that is 128 addresses (`0..=254`), not merely 77 commands.
pub fn amtc_bm1366_chain_init_manifest(
    address_interval: u8,
    pll1_cached_value: u32,
    fast_uart_cached_value: u32,
    init_control_a8_cached_value: u32,
    misc_control_18_cached_value: u32,
    target_baud: u32,
) -> Result<Vec<AmtcBm1366ChainInitStep>, &'static str> {
    if address_interval != 2 {
        return Err("held S19k AMTC chain-init manifest is exact only for address interval 2");
    }
    let baud_plan =
        amtc_bm1366_fast_uart_plan(pll1_cached_value, fast_uart_cached_value, target_baud)?;
    let post_reset_plan =
        amtc_bm1366_post_reset_rmw_plan(init_control_a8_cached_value, misc_control_18_cached_value);
    let mut steps = Vec::with_capacity(174);
    steps.push(AmtcBm1366ChainInitStep {
        op: AmtcBm1366ChainInitOp::StrictEnumerate {
            pass: 1,
            retry_once: true,
        },
        dwell_after_ms: 0,
    });
    steps.push(AmtcBm1366ChainInitStep {
        op: AmtcBm1366ChainInitOp::ChainInactive,
        dwell_after_ms: 10,
    });
    for address in amtc_bm1366_set_address_ladder(address_interval)? {
        steps.push(AmtcBm1366ChainInitStep {
            op: AmtcBm1366ChainInitOp::SetAddress { address },
            dwell_after_ms: 10,
        });
    }
    let relay = amtc_bm1366_uart_relay_domain_plan(address_interval, 77, 11, 7)?;
    for (index, domain) in relay.iter().enumerate() {
        steps.push(AmtcBm1366ChainInitStep {
            op: AmtcBm1366ChainInitOp::WriteUartRelay {
                voltage_domain: domain.voltage_domain,
                address: domain.first_address,
                value: domain.first_uart_relay_value,
            },
            dwell_after_ms: 0,
        });
        steps.push(AmtcBm1366ChainInitStep {
            op: AmtcBm1366ChainInitOp::WriteUartRelay {
                voltage_domain: domain.voltage_domain,
                address: domain.second_address,
                value: domain.second_uart_relay_value,
            },
            dwell_after_ms: 0,
        });
        steps.push(AmtcBm1366ChainInitStep {
            op: AmtcBm1366ChainInitOp::SetIoDriverHighNibbleF {
                voltage_domain: domain.voltage_domain,
                address: domain.io_driver_address,
            },
            // FUN_0005df08 has no per-domain sleep. Its caller waits 10 ms
            // once, after all 11 domains have been configured.
            dwell_after_ms: if index + 1 == relay.len() { 10 } else { 0 },
        });
    }
    steps.push(AmtcBm1366ChainInitStep {
        op: AmtcBm1366ChainInitOp::SetChipAndHostBaud { plan: baud_plan },
        // Additional caller dwell after FUN_000751ac returns.
        dwell_after_ms: 50,
    });
    steps.push(AmtcBm1366ChainInitStep {
        op: AmtcBm1366ChainInitOp::StrictEnumerate {
            pass: 2,
            retry_once: true,
        },
        dwell_after_ms: 0,
    });
    steps.push(AmtcBm1366ChainInitStep {
        op: AmtcBm1366ChainInitOp::FpgaChainResetAssert,
        dwell_after_ms: 500,
    });
    steps.push(AmtcBm1366ChainInitStep {
        op: AmtcBm1366ChainInitOp::FpgaChainResetRelease,
        dwell_after_ms: 500,
    });
    steps.push(AmtcBm1366ChainInitStep {
        op: AmtcBm1366ChainInitOp::SetHostBaudDivider { divider: 0x1A },
        dwell_after_ms: 10,
    });
    steps.push(AmtcBm1366ChainInitStep {
        op: AmtcBm1366ChainInitOp::ResetHostUartBuffers,
        dwell_after_ms: 10,
    });
    steps.push(AmtcBm1366ChainInitStep {
        op: AmtcBm1366ChainInitOp::PostResetA8MiscRmw {
            plan: post_reset_plan,
        },
        dwell_after_ms: 0,
    });
    steps.push(AmtcBm1366ChainInitStep {
        op: AmtcBm1366ChainInitOp::TicketMaskAllOnes,
        dwell_after_ms: 0,
    });
    steps.push(AmtcBm1366ChainInitStep {
        op: AmtcBm1366ChainInitOp::ClearRxFifo,
        dwell_after_ms: 50,
    });
    steps.push(AmtcBm1366ChainInitStep {
        op: AmtcBm1366ChainInitOp::StrictEnumerate {
            pass: 3,
            retry_once: true,
        },
        dwell_after_ms: 0,
    });
    steps.push(AmtcBm1366ChainInitStep {
        op: AmtcBm1366ChainInitOp::EvaluateThreeEnumCountsAgainstExpected {
            expected_count: 77,
            mismatch_records_minimum: true,
        },
        dwell_after_ms: 0,
    });
    Ok(steps)
}
/// bosminer DATA: `28 00 00 00 30 11` (reg `0x28` + BE `0x00003011`).
/// Second LOAD: file + `0x410000` → VA.
pub const BOSMINER_REG28_3011_FILE_OFF: u64 = 0x013B_0A28;
pub const BOSMINER_REG28_3011_VA: u64 = 0x017C_0A28;
/// bosminer DATA: `28 00 00 00 30 01` (reg `0x28` + BE `0x00003001`).
pub const BOSMINER_REG28_3001_FILE_OFF: u64 = 0x0141_FA28;
pub const BOSMINER_REG28_3001_VA: u64 = 0x0182_FA28;
/// `MOVZ X1,#0x3001` sites. A later `MOVK X1,#imm16,LSL#16` completes a
/// 64-bit pointer — not a FastUART immediate.
pub const BOSMINER_MOVZ_X1_3001_VA_A: u64 = 0x010B_A39C;
pub const BOSMINER_MOVZ_X1_3001_VA_B: u64 = 0x010C_49D8;
/// `command.rs` `read_register` — logs `Hashchip: no response for read_register`.
pub const BOSMINER_COMMAND_RS_READ_REGISTER_FN_VA: u64 = 0x008A_9044;
pub const BOSMINER_COMMAND_RS_READ_REGISTER_STR_VA: u64 = 0x0130_3FC0;
/// 4-byte BE UART payload send. Callers: ticket mask + send-self + MiscCtrl.
/// This is the write primitive, not a dedicated `write_reg` symbol.
pub const BOSMINER_UART_BE4_SEND_FN_VA: u64 = 0x008A_200C;
/// `Modifying MiscCtrl for chip` — ASIC `0x18` path, not FastUART `0x28`.
pub const BOSMINER_MISCCTRL_MODIFY_FN_VA: u64 = 0x008B_40DC;
/// Generic `hashchain.rs` ticket-mask future. Its log is `Setting ticket mask
/// register for difficulty ..., value ...` and it writes register `0x14`.
/// This was previously mislabeled as the set-baud future.
pub const BOSMINER_TICKET_MASK_FUTURE_FN_VA: u64 = 0x0083_6934;
/// Exact BM1366 trait construction and baud-build path in the held stock ELF.
pub const BOSMINER_BM1366_FACTORY_FN_VA: u64 = 0x008D_BDF4;
pub const BOSMINER_BM1366_FACTORY_PTR_VA: u64 = 0x01AC_DAE8;
pub const BOSMINER_BM1366_FACTORY_PTR_FILE_OFF: u64 = 0x016B_DAE8;
pub const BOSMINER_BM1366_TRAIT_VTABLE_VA: u64 = 0x019C_7B00;
pub const BOSMINER_BM1366_TRAIT_VTABLE_FILE_OFF: u64 = 0x015B_7B00;
pub const BOSMINER_BM1366_SET_BAUD_VTABLE_SLOT: u64 = 0x50;
pub const BOSMINER_BM1366_SET_BAUD_BUILD_FN_VA: u64 = 0x008D_D3B8;
/// `AntminerDriver::init` future and its retained 13-entry async jump table.
pub const BOSMINER_BM1366_STOCK_INIT_FUTURE_END_VA: u64 = 0x0083_9C78;
pub const BOSMINER_BM1366_STOCK_INIT_DISPATCH_BASE_VA: u64 = 0x0083_6E7C;
pub const BOSMINER_BM1366_STOCK_INIT_JUMP_TABLE_VA: u64 = 0x0131_B3C8;
pub const BOSMINER_BM1366_STOCK_INIT_JUMP_TABLE_FILE_OFF: u64 = 0x00F1_B3C8;
pub const BOSMINER_BM1366_STOCK_INIT_JUMP_OFFSETS: [u16; 13] = [
    0, 0x3E5, 0x3E2, 0x59, 0x51, 0x6D, 0x46, 0x13, 0x38, 0x65, 0x0A, 0x25, 0x75,
];
pub const BOSMINER_BM1366_STOCK_INIT_RESUME_VA: [u64; 13] = [
    0x0083_6E7C,
    0x0083_7E10,
    0x0083_7E04,
    0x0083_6FE0,
    0x0083_6FC0,
    0x0083_7030,
    0x0083_6F94,
    0x0083_6EC8,
    0x0083_6F5C,
    0x0083_7010,
    0x0083_6EA4,
    0x0083_6F10,
    0x0083_7050,
];

/// The call sites appear in this address order in `.text`. Rust async lowering
/// does not preserve source/execution order, so this list must not be used as
/// an init sequence.
pub const BOSMINER_BM1366_STOCK_INIT_CALLSITE_SLOT_ORDER: [u8; 7] =
    [0x40, 0x38, 0x50, 0x30, 0x78, 0x48, 0x28];

/// Exact successful execution order recovered by following each future's
/// Ready/Ok continuation through the async state machine. This deliberately
/// differs from [`BOSMINER_BM1366_STOCK_INIT_CALLSITE_SLOT_ORDER`].
pub const BOSMINER_BM1366_STOCK_INIT_EXECUTION_SLOT_ORDER: [u8; 7] =
    [0x40, 0x48, 0x28, 0x38, 0x50, 0x78, 0x30];

/// Exact direct-generic corridor constants between the BM1366 trait calls.
/// These are evidence inputs only; they do not authorize transport or power.
pub const BOSMINER_BM1366_GENERIC_CHAIN_INACTIVE_REPETITIONS: u8 = 3;
pub const BOSMINER_BM1366_GENERIC_CHAIN_INACTIVE_WAIT_NS: u32 = 300_000_000;
pub const BOSMINER_BM1366_GENERIC_POST_SLOT48_WAIT_NS: u32 = 50_000_000;
pub const BOSMINER_BM1366_GENERIC_POST_CORE3C_WAIT_NS: u32 = 50_000_000;
pub const BOSMINER_BM1366_GENERIC_BROADCAST_DEST_BUILDER_VA: u64 = 0x0092_0910;
pub const BOSMINER_BM1366_GENERIC_UNICAST_DEST_BUILDER_VA: u64 = 0x0092_08D8;
pub const BOSMINER_BM1366_GENERIC_DEST_FROM_INDEX_VA: u64 = 0x00BF_31C8;
pub const BOSMINER_BM1366_GENERIC_READ_REGISTER_ZERO_DESCRIPTOR_VA: u64 = 0x012E_7CB0;
pub const BOSMINER_BM1366_GENERIC_CORE3C_DESCRIPTOR_VA: u64 = 0x012E_7E40;

/// One direct-generic SetAddress destination in the pre-discovery ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerBm1366StockSetAddressStep {
    pub chip_index: u16,
    pub wire_address: u8,
}

/// Build the caller-sized address ladder proven between stock slots `+0x40`
/// and `+0x48`: ascending chip indexes with `wire=address_gap*index`.
pub fn bosminer_bm1366_stock_set_address_plan(
    address_gap: u8,
    asic_count: u16,
) -> Result<Vec<BosminerBm1366StockSetAddressStep>, &'static str> {
    if address_gap == 0 || asic_count == 0 {
        return Err("stock BM1366 SetAddress plan requires nonzero address gap/count");
    }
    let last_address = u32::from(address_gap) * u32::from(asic_count - 1);
    if last_address > u32::from(u8::MAX) {
        return Err("stock BM1366 SetAddress destination exceeds one-byte wire address");
    }
    Ok((0..asic_count)
        .map(|chip_index| BosminerBm1366StockSetAddressStep {
            chip_index,
            wire_address: (u32::from(address_gap) * u32::from(chip_index)) as u8,
        })
        .collect())
}

/// Reproduce the caller-derived generic register-`0x3c` value assembled after
/// slot `+0x48`. The eight bytes are copied from the common hashchain object at
/// offsets `0x218..0x21f`; stripped field names are intentionally not guessed.
pub fn bosminer_bm1366_stock_generic_core3c_value(fields: [u8; 8]) -> u32 {
    let mut low = u32::from(fields[5] & 0x7F);
    if fields[0] == 0 {
        low |= 0x80;
    }
    let mut high_middle = u32::from(fields[4]);
    if fields[1] == 0 {
        high_middle |= 0x80;
    }
    if fields[2] == 0 {
        high_middle |= 0x40;
    }
    if fields[3] == 0 {
        high_middle |= 0x20;
    }
    (u32::from(fields[7]) << 24) | (high_middle << 16) | (u32::from(fields[6]) << 8) | low
}

/// Evidence-safe names for the seven BM1366 dynamic calls made by the held
/// stock generic init. These describe observed bodies and wire effects, not
/// recovered Rust trait identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BosminerBm1366StockInitEvidenceStage {
    /// `bm1366.rs:93`: A4 three times, A8, then MiscCtrl, with retained waits.
    PreconfigureRegisterBlock,
    /// The `+0x38` future stores Ready/Ok discriminant 8 and returns; no I/O.
    ImmediateReadyNoIoSlot38,
    /// Exact `FastUartReg` builder; 3.125 Mbaud produces `0x28=0x00003011`.
    SetFastUart,
    /// `bm1366.rs:166`: per-chip A8/MiscCtrl/core-register program plus an
    /// additional register-0x0c distribution, HCN, and VersionMask tail.
    PerChipRegisterProgram,
    /// The `+0x78` future stores Ready/Ok discriminant 8 and returns; no I/O.
    ImmediateReadyNoIoSlot78,
    /// `bm1366.rs:127`: broadcast core-register-control `0x3c=0x80008540`.
    CoreRegisterHashClock,
    /// AnalogMux `0x54=3`, caller-derived IoDriver `0x58` writes, then the
    /// domain-boundary UART-relay `0x2c` program.
    AnalogMuxIoDriverAndDomainRelay,
}

/// One stock dynamic-dispatch site. `source_line` is present only where the
/// exact `bm1366.rs` source-location/future record is retained and correctly
/// associated. It is deliberately absent for shared/default futures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerBm1366StockInitDispatch {
    pub ordinal: u8,
    pub stage: BosminerBm1366StockInitEvidenceStage,
    pub vtable_slot: u8,
    pub slot_load_va: u64,
    pub invoke_va: u64,
    pub method_va: u64,
    pub poll_va: Option<u64>,
    pub source_line: Option<u16>,
}

/// Successful execution order, not ascending call-site address order.
pub const BOSMINER_BM1366_STOCK_INIT_DISPATCH: [BosminerBm1366StockInitDispatch; 7] = [
    BosminerBm1366StockInitDispatch {
        ordinal: 1,
        stage: BosminerBm1366StockInitEvidenceStage::PreconfigureRegisterBlock,
        vtable_slot: 0x40,
        slot_load_va: 0x0083_6E94,
        invoke_va: 0x0083_6E98,
        method_va: 0x008D_CF38,
        poll_va: Some(0x008D_CFBC),
        source_line: Some(93),
    },
    BosminerBm1366StockInitDispatch {
        ordinal: 2,
        stage: BosminerBm1366StockInitEvidenceStage::CoreRegisterHashClock,
        vtable_slot: 0x48,
        slot_load_va: 0x0083_862C,
        invoke_va: 0x0083_8630,
        method_va: 0x008D_D480,
        poll_va: Some(0x008D_D4C8),
        source_line: Some(127),
    },
    BosminerBm1366StockInitDispatch {
        ordinal: 3,
        stage: BosminerBm1366StockInitEvidenceStage::AnalogMuxIoDriverAndDomainRelay,
        vtable_slot: 0x28,
        slot_load_va: 0x0083_89F8,
        invoke_va: 0x0083_89FC,
        method_va: 0x008D_C7A4,
        poll_va: Some(0x008D_C828),
        source_line: None,
    },
    BosminerBm1366StockInitDispatch {
        ordinal: 4,
        stage: BosminerBm1366StockInitEvidenceStage::ImmediateReadyNoIoSlot38,
        vtable_slot: 0x38,
        slot_load_va: 0x0083_7668,
        invoke_va: 0x0083_766C,
        method_va: 0x008D_F9CC,
        poll_va: Some(0x008D_FA14),
        source_line: None,
    },
    BosminerBm1366StockInitDispatch {
        ordinal: 5,
        stage: BosminerBm1366StockInitEvidenceStage::SetFastUart,
        vtable_slot: 0x50,
        slot_load_va: 0x0083_76FC,
        invoke_va: 0x0083_7704,
        method_va: 0x008D_D3B8,
        poll_va: None,
        source_line: None,
    },
    BosminerBm1366StockInitDispatch {
        ordinal: 6,
        stage: BosminerBm1366StockInitEvidenceStage::ImmediateReadyNoIoSlot78,
        vtable_slot: 0x78,
        slot_load_va: 0x0083_7DD8,
        invoke_va: 0x0083_7DDC,
        method_va: 0x008D_FCAC,
        poll_va: Some(0x008D_FD00),
        source_line: None,
    },
    BosminerBm1366StockInitDispatch {
        ordinal: 7,
        stage: BosminerBm1366StockInitEvidenceStage::PerChipRegisterProgram,
        vtable_slot: 0x30,
        slot_load_va: 0x0083_7BC8,
        invoke_va: 0x0083_7BCC,
        method_va: 0x008D_D5B8,
        poll_va: Some(0x008D_D63C),
        source_line: Some(166),
    },
];

/// Exact successful path after the ASIC FastUART broadcast and host baud
/// setter complete. Stock proceeds through a no-I/O Ready future directly
/// into the per-chip write program; it does not perform a dedicated fresh
/// readback or handshake at the new baud in this init future.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BosminerBm1366StockPostBaudStep {
    HostBaudSetterCompletes,
    ImmediateReadyNoIoSlot78,
    PerChipWriteProgramSlot30,
}

pub const BOSMINER_BM1366_STOCK_POST_BAUD_PATH: [BosminerBm1366StockPostBaudStep; 3] = [
    BosminerBm1366StockPostBaudStep::HostBaudSetterCompletes,
    BosminerBm1366StockPostBaudStep::ImmediateReadyNoIoSlot78,
    BosminerBm1366StockPostBaudStep::PerChipWriteProgramSlot30,
];

/// Exact wire-level values recovered inside the named portions of the stock
/// method bodies. This remains an evidence record, not a complete init plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerBm1366StockRegisterFacts {
    pub preconfig_version_mask: u32,
    pub preconfig_version_mask_repetitions: u8,
    pub preconfig_init_control: u32,
    pub preconfig_misc_control: u32,
    pub preconfig_inter_write_wait_ns: u32,
    pub per_chip_init_control: u32,
    pub per_chip_misc_control: u32,
    pub per_chip_core_register_values: [u32; 3],
    pub post_hcn_wait_ns: u32,
    pub post_version_mask_wait_ns: u32,
    pub hash_clock_core_register_value: u32,
    pub analog_mux_value: u32,
}

pub const BOSMINER_BM1366_STOCK_REGISTER_FACTS: BosminerBm1366StockRegisterFacts =
    BosminerBm1366StockRegisterFacts {
        preconfig_version_mask: 0x9000_FFFF,
        preconfig_version_mask_repetitions: 3,
        preconfig_init_control: 0x0007_0000,
        preconfig_misc_control: 0xFF0F_C100,
        preconfig_inter_write_wait_ns: 100_000_000,
        per_chip_init_control: 0x0007_01F0,
        per_chip_misc_control: 0xF000_C100,
        per_chip_core_register_values: [0x8000_8540, 0x8000_8020, 0x8000_82AA],
        post_hcn_wait_ns: 10_000_000,
        post_version_mask_wait_ns: 100_000_000,
        hash_clock_core_register_value: 0x8000_8540,
        analog_mux_value: 3,
    };

/// Stock backend lifecycle surrounding the generic ASIC init future. These
/// addresses belong to the custody-pinned S19k bosminer ELF. The outer future
/// provides a bounded start retry policy; the inner future owns reset and the
/// ten-second init timeout.
pub const BOSMINER_HASHCHAIN_START_WRAPPER_FN_VA: u64 = 0x0071_78F4;
pub const BOSMINER_HASHCHAIN_START_POLL_FN_VA: u64 = 0x0071_9868;
pub const BOSMINER_HASHCHAIN_START_POLL_END_VA: u64 = 0x0071_DFAF;
pub const BOSMINER_HASHCHAIN_START_RETRY_BUDGET: u8 = 4;
pub const BOSMINER_HASHCHAIN_START_RETRY_DELAY_NS: u64 = 10_000_000_000;
pub const BOSMINER_HASHCHAIN_INIT_TIMEOUT_NS: u64 = 10_000_000_000;
pub const BOSMINER_HASHCHAIN_CONDITIONAL_PREINIT_WAIT_NS: u64 = 5_000_000_000;
pub const BOSMINER_HASHCHAIN_FAN_PENDING_WAIT_NS: u64 = 1_000_000_000;
pub const BOSMINER_HASHCHAIN_TIMEOUT_WRAPPER_FN_VA: u64 = 0x006A_3F08;
/// Stripped helper interpreted only from its two call sites and the retained
/// fan-wait/Fans-OK control flow. This is not a recovered symbol name.
pub const BOSMINER_HASHCHAIN_FAN_READY_SNAPSHOT_FN_VA: u64 = 0x00B5_BBAC;
pub const BOSMINER_HASHCHAIN_FAN_READY_INITIAL_CALL_VA: u64 = 0x0071_BF84;
pub const BOSMINER_HASHCHAIN_FAN_READY_RECHECK_CALL_VA: u64 = 0x0071_CE94;
pub const BOSMINER_HASHCHAIN_FAN_PENDING_LOOP_BACKEDGE_VA: u64 = 0x0071_D19C;
/// The context-bound snapshot clone reads this byte from its retained watch
/// value. The exact join from this enclosing snapshot offset to one of the
/// separately recovered `FanStatus` fields is not proven.
pub const BOSMINER_HASHCHAIN_FAN_READY_SNAPSHOT_STATUS_BYTE_LOAD_VA: u64 = 0x00B5_BCE4;
pub const BOSMINER_HASHCHAIN_FAN_READY_SNAPSHOT_STATUS_BYTE_OFFSET: u16 = 0x016C;

/// Held-platform registry facts that bind the captured `am3-aml` identity to
/// platform code 3, the ordered Antminer/Braiins-Fixture builder subset, and
/// the S19K Pro NoPic/BHB56902 Antminer candidate. These are identity and
/// factory-selection facts only; they grant no reset, GPIO, rail, or mining
/// authority.
pub const BOSMINER_PLATFORM_NAMES: [&[u8]; 8] = [
    b"am1-s9",
    b"am2-s17",
    b"am3-bbb",
    b"am3-aml",
    b"zynq-bm3-am2",
    b"cvitek-bm1-am2",
    b"stm32mp157c-ii1-am2",
    b"stm32mp157c-ii2-bmm1",
];
pub const BOSMINER_PLATFORM_NAME_VAS: [u64; 8] = [
    0x0160_483F,
    0x0160_4845,
    0x0160_484C,
    0x0160_4853,
    0x0160_485A,
    0x0160_4866,
    0x0160_4874,
    0x0160_4887,
];
pub const BOSMINER_PLATFORM_NAME_TABLE_FILE_OFF: u64 = 0x016B_8E00;
pub const BOSMINER_AM3_AML_PLATFORM_CODE: u8 = 3;
pub const BOSMINER_PLATFORM_ENUM_DISPLAY_FN_VA: u64 = 0x0126_F798;
pub const BOSMINER_PLATFORM_REGISTRY_INIT_FN_VA: u64 = 0x0040_A1E4;
pub const BOSMINER_PLATFORM_REGISTRY_INIT_PTR_FILE_OFF: u64 = 0x016C_9310;
pub const BOSMINER_AM3_AML_FACTORY_RECORD_FILE_OFF: u64 = 0x015B_7130;
pub const BOSMINER_AM3_AML_FACTORY_FN_VA: u64 = 0x008D_77F8;
pub const BOSMINER_AM3_AML_PLATFORM_VTABLE_VA: u64 = 0x019C_9088;
pub const BOSMINER_BUILDER_REGISTRY_INIT_FN_VA: u64 = 0x0077_7CD8;
pub const BOSMINER_BUILDER_REGISTRY_INIT_PTR_FILE_OFF: u64 = 0x016C_9428;
pub const BOSMINER_BUILDER_FILTER_FN_VA: u64 = 0x007E_BC58;
pub const BOSMINER_BUILDER_FIRST_SUCCESS_FN_VA: u64 = 0x0079_4C48;
pub const BOSMINER_BUILDER_REGISTRY_LAZY_PTR_FILE_OFF: u64 = 0x016B_F780;
pub const BOSMINER_BUILDER_REGISTRY_STORAGE_VA: u64 = 0x01AD_9428;
pub const BOSMINER_ANTMINER_BUILDER_VTABLE_VA: u64 = 0x019A_C828;
pub const BOSMINER_ANTMINER_BUILDER_VTABLE_FILE_OFF: u64 = 0x0159_C828;
pub const BOSMINER_BRAIINS_FIXTURE_BUILDER_VTABLE_VA: u64 = 0x019A_C880;
pub const BOSMINER_BRAIINS_FIXTURE_BUILDER_VTABLE_FILE_OFF: u64 = 0x0159_C880;
pub const BOSMINER_THIRD_BUILDER_VTABLE_FILE_OFF: u64 = 0x0159_AA40;
pub const BOSMINER_AM3_AML_FILTERED_BUILDERS: [&[u8]; 2] = [b"Antminer", b"Braiins Fixture"];
pub const BOSMINER_ANTMINER_SUPPORTED_PLATFORM_CODES: [u8; 5] = [4, 3, 2, 6, 5];
pub const BOSMINER_BRAIINS_FIXTURE_SUPPORTED_PLATFORM_CODES: [u8; 2] = [3, 6];
pub const BOSMINER_THIRD_BUILDER_SUPPORTED_PLATFORM_CODES: [u8; 2] = [6, 7];
pub const BOSMINER_ANTMINER_PROVIDER_BUILD_FN_VA: u64 = 0x006F_7780;
pub const BOSMINER_BRAIINS_FIXTURE_PROVIDER_BUILD_FN_VA: u64 = 0x006F_C37C;
pub const BOSMINER_THIRD_PROVIDER_BUILD_FN_VA: u64 = 0x006E_53C0;
pub const BOSMINER_ANTMINER_PROVIDER_BYTES: u16 = 0x03D0;
pub const BOSMINER_ANTMINER_PROVIDER_ALIGN: u8 = 0x10;
pub const BOSMINER_ANTMINER_PROVIDER_VTABLE_VA: u64 = 0x019A_C978;
pub const BOSMINER_ANTMINER_PROVIDER_VTABLE_FILE_OFF: u64 = 0x0159_C978;
pub const BOSMINER_ANTMINER_LIFECYCLE_HOOK_METHOD_VA: u64 = 0x0070_539C;
pub const BOSMINER_ANTMINER_CHILD_METHOD_VA: u64 = 0x0070_53A0;
pub const BOSMINER_ANTMINER_CANDIDATE_VALIDATE_METHOD_VA: u64 = 0x0070_A82C;
pub const BOSMINER_ANTMINER_CHILD_RESULT_BYTES: u16 = 0x0340;
pub const BOSMINER_ANTMINER_CHILD_RESULT_VTABLE_VA: u64 = 0x019A_CE50;
pub const BOSMINER_BRAIINS_FIXTURE_PROVIDER_BYTES: u16 = 0x03C0;
pub const BOSMINER_BRAIINS_FIXTURE_PROVIDER_ALIGN: u8 = 0x10;
pub const BOSMINER_BRAIINS_FIXTURE_PROVIDER_VTABLE_VA: u64 = 0x019A_C9B8;
pub const BOSMINER_BRAIINS_FIXTURE_PROVIDER_VTABLE_FILE_OFF: u64 = 0x0159_C9B8;
pub const BOSMINER_BRAIINS_FIXTURE_LIFECYCLE_HOOK_METHOD_VA: u64 = 0x0070_57FC;
pub const BOSMINER_BRAIINS_FIXTURE_CHILD_METHOD_VA: u64 = 0x0070_5800;
pub const BOSMINER_BRAIINS_FIXTURE_CANDIDATE_VALIDATE_METHOD_VA: u64 = 0x0070_A824;
pub const BOSMINER_BRAIINS_FIXTURE_CHILD_RESULT_BYTES: u16 = 0x0300;
pub const BOSMINER_BRAIINS_FIXTURE_CHILD_RESULT_VTABLE_VA: u64 = 0x019A_CE70;
pub const BOSMINER_CODE3_BUILDER_VTABLE_VAS: [u64; 2] = [
    BOSMINER_ANTMINER_BUILDER_VTABLE_VA,
    BOSMINER_BRAIINS_FIXTURE_BUILDER_VTABLE_VA,
];
pub const BOSMINER_CODE3_PROVIDER_VTABLE_VAS: [u64; 2] = [
    BOSMINER_ANTMINER_PROVIDER_VTABLE_VA,
    BOSMINER_BRAIINS_FIXTURE_PROVIDER_VTABLE_VA,
];
pub const BOSMINER_CODE3_CANDIDATE_VALIDATE_METHOD_VAS: [u64; 2] = [
    BOSMINER_ANTMINER_CANDIDATE_VALIDATE_METHOD_VA,
    BOSMINER_BRAIINS_FIXTURE_CANDIDATE_VALIDATE_METHOD_VA,
];
pub const BOSMINER_CODE3_LIFECYCLE_HOOK_METHOD_VAS: [u64; 2] = [
    BOSMINER_ANTMINER_LIFECYCLE_HOOK_METHOD_VA,
    BOSMINER_BRAIINS_FIXTURE_LIFECYCLE_HOOK_METHOD_VA,
];
pub const BOSMINER_CODE3_CHILD_METHOD_VAS: [u64; 2] = [
    BOSMINER_ANTMINER_CHILD_METHOD_VA,
    BOSMINER_BRAIINS_FIXTURE_CHILD_METHOD_VA,
];
pub const BOSMINER_CODE3_CHILD_RESULT_BYTES: [u16; 2] = [
    BOSMINER_ANTMINER_CHILD_RESULT_BYTES,
    BOSMINER_BRAIINS_FIXTURE_CHILD_RESULT_BYTES,
];
pub const BOSMINER_CODE3_CHILD_RESULT_VTABLE_VAS: [u64; 2] = [
    BOSMINER_ANTMINER_CHILD_RESULT_VTABLE_VA,
    BOSMINER_BRAIINS_FIXTURE_CHILD_RESULT_VTABLE_VA,
];
pub const BOSMINER_ANTMINER_PROVIDER_VTABLE: [u64; 8] = [
    0x006F_4A90,
    BOSMINER_ANTMINER_PROVIDER_BYTES as u64,
    BOSMINER_ANTMINER_PROVIDER_ALIGN as u64,
    BOSMINER_ANTMINER_LIFECYCLE_HOOK_METHOD_VA,
    BOSMINER_ANTMINER_CHILD_METHOD_VA,
    BOSMINER_ANTMINER_CANDIDATE_VALIDATE_METHOD_VA,
    0x0070_545C,
    0x0070_A834,
];
pub const BOSMINER_BRAIINS_FIXTURE_PROVIDER_VTABLE: [u64; 8] = [
    0x006F_4E58,
    BOSMINER_BRAIINS_FIXTURE_PROVIDER_BYTES as u64,
    BOSMINER_BRAIINS_FIXTURE_PROVIDER_ALIGN as u64,
    BOSMINER_BRAIINS_FIXTURE_LIFECYCLE_HOOK_METHOD_VA,
    BOSMINER_BRAIINS_FIXTURE_CHILD_METHOD_VA,
    BOSMINER_BRAIINS_FIXTURE_CANDIDATE_VALIDATE_METHOD_VA,
    0x0070_59C0,
    0x0070_A838,
];
pub const BOSMINER_ANTMINER_AM3_AML_CANDIDATE_TABLE_FILE_OFF: u64 = 0x0159_CD68;
pub const BOSMINER_ANTMINER_AM3_AML_CANDIDATE_COUNT: u8 = 0x15;
pub const BOSMINER_S19K_NOPIC_CANDIDATE_INDEX: u8 = 8;
pub const BOSMINER_S19K_NOPIC_CANDIDATE_OBJECT_VA: u64 = 0x01AD_53D0;
pub const BOSMINER_S19K_NOPIC_CANDIDATE_INIT_PTR_FILE_OFF: u64 = 0x016C_53D0;
pub const BOSMINER_S19K_NOPIC_CANDIDATE_INIT_FN_VA: u64 = 0x006B_B7BC;
pub const BOSMINER_S19K_NOPIC_MODEL_NAME_VA: u64 = 0x0141_C081;
pub const BOSMINER_S19K_NOPIC_MODEL_NAME: &[u8] = b"Antminer S19K Pro NoPic";
pub const BOSMINER_S19K_NOPIC_BOARD_ID_VA: u64 = 0x012E_C080;
pub const BOSMINER_S19K_NOPIC_BOARD_ID: &[u8] = b"BHB56902";

pub const BOSMINER_S19K_PLATFORM_RESOLUTION_PINS: [(u64, u32); 7] = [
    (0x0040_A1E4, 0xD103_C3FF),
    (0x0077_7CD8, 0xD102_C3FF),
    (0x007E_BC58, 0xD102_83FF),
    (0x0079_4C48, 0xA9BD_5FFE),
    (0x006F_7780, 0xF81B_0FFD),
    (0x006B_B7BC, 0xD100_83FF),
    (0x006B_B7F8, 0x9400_6523),
];

/// Exact live per-chain object lineage consumed by
/// [`BOSMINER_HASHCHAIN_START_POLL_FN_VA`]. This corrects an earlier false
/// join: the initial task payload's `+0x200/+0x208` words are Vec metadata,
/// not the reset receiver. Two distinct 0x570-byte layouts occur:
///
/// * `FUN_007081cc` builds a contiguous raw record and stores a separately
///   owned Arc pointer at raw `+0x510`;
/// * `FUN_00b87980` later stages and constructs a `HashchainManager` inside a
///   0x570-byte Arc allocation (0x10-byte header plus 0x560-byte payload).
///
/// The collection path tests allocation `+0x568` and exports payload
/// `P=A+0x10` at item `+0x60`. Item `+0x30` is a cloned
/// `triggered::Listener`; `FUN_007178f4` and `FUN_00719868` carry the two on
/// distinct lanes. The nested state initially stages that listener at `+0x3a0`
/// but `0x0071ab58` overwrites the slot with the self pointer of a locally
/// constructed per-chain object. The listener inner is saved temporarily at
/// `sp+0x48` and consumed on its own construction lane at `0x0071a2d8`.
/// Separately, the byte Vec at `HashchainManager P+0x10` is cloned before a
/// pair is prestaged at `sp+0xb10/+0xb18`: its data half is overwritten with
/// `P+0x538`, while its dispatch-table half remains the cloned Vec data
/// pointer. The runtime-selected code-3 provider at `P+0x230/+0x238` is called
/// through slot `+0x18` at `0x0071a51c`. The held ELF has two ordered code-3
/// candidates: Antminer (`0x019ac978`) and Braiins Fixture (`0x019ac9b8`).
/// Their slot-`+0x18` methods are both one-instruction returns, respectively
/// `FUN_0070539c` and `FUN_007057fc`, so either candidate leaves the prestaged
/// pair unchanged. `0x0071a528` then overwrites the temporary listener stack slot
/// with the prestaged data half; the pair becomes local `+0x210/+0x218` and
/// dispatch `0x0071b098` uses dispatch-table slot `+0x28`. This path does not
/// use `P+0x1c0`.  corrects the attempted upstream join: the B879 clone
/// cap/data/len are forwarded into the manager-prefix Vec at
/// `sp+0xa30/+0xa38/+0xa40` before the old `sp+0xbf0` slot is reused. The
/// prefix then travels through `sp+0xa20 -> sp+0xc10` and constructor argument
/// 7.  retracts the stronger claim that static first-success ordering
/// proves Antminer wins: success is conditional at runtime. Therefore the
/// selected provider, P's `+0x10` bytes, and the final slot target remain
/// dynamic. This is not
/// GPIO, polarity, pulse-width, electrical-reset, or SafeOff authority.
pub const BOSMINER_RAW_CHAIN_RECORD_BUILD_FN_VA: u64 = 0x0070_81CC;
pub const BOSMINER_RAW_CHAIN_RECORD_BYTES: u16 = 0x0570;
pub const BOSMINER_RAW_CHAIN_RECORD_ARC_OFFSET: u16 = 0x0510;
pub const BOSMINER_RAW_CHAIN_RECORD_ENABLED_OFFSET: u16 = 0x0568;
pub const BOSMINER_LIVE_CHAIN_ARC_BUILD_FN_VA: u64 = 0x00B8_7980;
pub const BOSMINER_LIVE_CHAIN_PAYLOAD_BUILD_FN_VA: u64 = 0x00B5_C168;
pub const BOSMINER_LIVE_CHAIN_ARC_DROP_FN_VA: u64 = 0x00B4_0F30;
pub const BOSMINER_LIVE_CHAIN_ARC_ALLOCATION_BYTES: u16 = 0x0570;
pub const BOSMINER_LIVE_CHAIN_ARC_ALIGN: u8 = 0x10;
pub const BOSMINER_LIVE_CHAIN_ARC_HEADER_BYTES: u8 = 0x10;
pub const BOSMINER_LIVE_CHAIN_ARC_PAYLOAD_BYTES: u16 = 0x0560;
pub const BOSMINER_LIVE_CHAIN_PAYLOAD_PREFIX_COPY_BYTES: u16 = 0x01F0;
pub const BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_NAME: &str = "HashchainManager";
pub const BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL_VA: u64 = 0x0138_E7E0;
pub const BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL: &[u8] = b"HashchainManager ";
pub const BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL_DESCRIPTOR_FILE_OFF: u64 = 0x015E_7F30;
pub const BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_VTABLE_VA: u64 = 0x019F_B178;
pub const BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_VTABLE_FILE_OFF: u64 = 0x015E_B178;
pub const BOSMINER_LIVE_CHAIN_PAYLOAD_DROP_FN_VA: u64 = 0x00B7_5194;
pub const BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_ID_FN_VA: u64 = 0x00B5_9AF8;
pub const BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_FN_VA: u64 = 0x00B5_D364;
pub const BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_VTABLE_PREFIX: [u64; 5] = [
    BOSMINER_LIVE_CHAIN_PAYLOAD_DROP_FN_VA,
    BOSMINER_LIVE_CHAIN_ARC_PAYLOAD_BYTES as u64,
    BOSMINER_LIVE_CHAIN_ARC_ALIGN as u64,
    BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_ID_FN_VA,
    BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_FN_VA,
];
pub const BOSMINER_LIVE_CHAIN_ARC_ENABLED_OFFSET: u16 = 0x0568;
pub const BOSMINER_LIVE_CHAIN_PAYLOAD_ENABLED_OFFSET: u16 = 0x0558;
pub const BOSMINER_LIVE_CHAIN_COLLECTION_FN_VA: u64 = 0x007E_CAC4;
pub const BOSMINER_LIVE_CHAIN_PAYLOAD_EXPORT_VA: u64 = 0x007E_CB3C;
pub const BOSMINER_LIVE_CHAIN_ITEM_BYTES: u16 = 0x06E0;
pub const BOSMINER_LIVE_CHAIN_ITEM_TRIGGERED_LISTENER_OFFSET: u8 = 0x30;
pub const BOSMINER_LIVE_CHAIN_ITEM_PAYLOAD_OFFSET: u16 = 0x0060;
pub const BOSMINER_TRIGGERED_INNER_ARC_ALLOCATION_BYTES: u8 = 0x58;
pub const BOSMINER_TRIGGERED_LISTENER_TYPE_NAME: &str = "triggered::Listener";
pub const BOSMINER_TRIGGERED_LISTENER_CLONE_FN_VA: u64 = 0x00BB_D3DC;
pub const BOSMINER_TRIGGERED_LISTENER_NEXT_ID_OFFSET: u8 = 0x48;
pub const BOSMINER_TRIGGERED_PANIC_STRING_VA: u64 = 0x0139_1057;
pub const BOSMINER_TRIGGERED_SOURCE_STRING_VA: u64 = 0x0139_1079;
pub const BOSMINER_TRIGGERED_PANIC_STRING: &[u8] = b"Some Trigger/Listener has panicked";
pub const BOSMINER_TRIGGERED_SOURCE_STRING: &[u8] = b"/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-vendor-cargo-deps/c19b7c6f923b580ac259164a89f2577984ad5ab09ee9d583b888f934adbbe8d0/triggered-0.1.2/src/lib.rs";
pub const BOSMINER_LIFECYCLE_OUTER_WORKING_LISTENER_OFFSET: u16 = 0x0040;
pub const BOSMINER_LIFECYCLE_OUTER_RETAINED_PAYLOAD_OFFSET: u16 = 0x0050;
pub const BOSMINER_LIFECYCLE_OUTER_NESTED_FUTURE_OFFSET: u16 = 0x0070;
pub const BOSMINER_LIFECYCLE_OUTER_CLONED_LISTENER_OFFSET: u16 = 0x03D0;
pub const BOSMINER_LIFECYCLE_OUTER_RETAINED_PAYLOAD_FOR_NESTED_OFFSET: u16 = 0x03F8;
pub const BOSMINER_LIFECYCLE_STATE_LISTENER_INPUT_OFFSET: u16 = 0x0360;
pub const BOSMINER_LIFECYCLE_STATE_INPUT_PAYLOAD_OFFSET: u16 = 0x0388;
pub const BOSMINER_LIFECYCLE_STATE_RETAINED_PAYLOAD_OFFSET: u16 = 0x0370;
pub const BOSMINER_LIFECYCLE_STATE_REUSED_LISTENER_SELF_SLOT_OFFSET: u16 = 0x03A0;
pub const BOSMINER_LIFECYCLE_STATE_DISPATCH_SELF_SLOT_OFFSET: u16 = 0x03B8;
pub const BOSMINER_LIFECYCLE_STACK_LISTENER_INNER_OFFSET: u8 = 0x48;
pub const BOSMINER_LIFECYCLE_PAYLOAD_HOOK_TRAIT_DATA_OFFSET: u16 = 0x0230;
pub const BOSMINER_LIFECYCLE_PAYLOAD_HOOK_TRAIT_VTABLE_OFFSET: u16 = 0x0238;
pub const BOSMINER_LIFECYCLE_PAYLOAD_HOOK_METHOD_SLOT: u8 = 0x18;
pub const BOSMINER_LIFECYCLE_PAYLOAD_HOOK_DISPATCH_VA: u64 = 0x0071_A51C;
pub const BOSMINER_LIFECYCLE_PRESTAGE_VEC_SOURCE_OFFSET: u8 = 0x10;
pub const BOSMINER_LIFECYCLE_PRESTAGE_VEC_CLONE_FN_VA: u64 = 0x012D_276C;
pub const BOSMINER_LIFECYCLE_PRESTAGE_VEC_CLONE_DISPATCH_VA: u64 = 0x0071_9B34;
pub const BOSMINER_LIFECYCLE_PRESTAGED_DATA_OFFSET: u16 = 0x0538;
pub const BOSMINER_LIFECYCLE_STACK_PRESTAGED_DATA_OFFSET: u16 = 0x0B10;
pub const BOSMINER_LIFECYCLE_STACK_PRESTAGED_DISPATCH_TABLE_OFFSET: u16 = 0x0B18;
pub const BOSMINER_LIFECYCLE_STACK_LISTENER_INNER_OVERWRITE_VA: u64 = 0x0071_A528;
pub const BOSMINER_LIFECYCLE_LOCAL_OBJECT_PREFIX_COPY_BYTES: u16 = 0x01E0;
pub const BOSMINER_LIFECYCLE_LOCAL_OBJECT_TRAIT_DATA_OFFSET: u16 = 0x0210;
pub const BOSMINER_LIFECYCLE_LOCAL_OBJECT_DISPATCH_TABLE_OFFSET: u16 = 0x0218;
pub const BOSMINER_LIFECYCLE_RESET_METHOD_SLOT: u8 = 0x28;
pub const BOSMINER_LIFECYCLE_RESET_METHOD_DISPATCH_VA: u64 = 0x0071_B098;

pub const BOSMINER_PAYLOAD_HOOK_REGISTRY_SELECT_FN_VA: u64 = 0x0079_4C48;
pub const BOSMINER_PAYLOAD_HOOK_REGISTRY_VEC_DATA_OFFSET: u8 = 0x08;
pub const BOSMINER_PAYLOAD_HOOK_REGISTRY_VEC_LEN_OFFSET: u8 = 0x10;
pub const BOSMINER_PAYLOAD_HOOK_REGISTRY_ENTRY_BYTES: u8 = 0x10;
pub const BOSMINER_PAYLOAD_HOOK_REGISTRY_ENTRY_METHOD_SLOT: u8 = 0x30;
pub const BOSMINER_PAYLOAD_HOOK_REGISTRY_SELECT_CALL_VAS: [u64; 3] =
    [0x0047_1804, 0x004C_1FC8, 0x004E_F814];
pub const BOSMINER_PAYLOAD_HOOK_SELECTED_PAIR_OFFSETS: [u16; 2] = [0x0450, 0x0458];
pub const BOSMINER_PAYLOAD_HOOK_OPTION_WRAP_FN_VA: u64 = 0x0056_14C0;
pub const BOSMINER_PAYLOAD_HOOK_OPTION_WRAP_CALL_VAS: [u64; 3] =
    [0x0047_8D30, 0x004C_94F4, 0x004F_6D40];
pub const BOSMINER_PAYLOAD_HOOK_WRAPPED_PAIR_OFFSETS: [u16; 2] = [0x07C0, 0x07C8];
pub const BOSMINER_PAYLOAD_HOOK_PARENT_CHILD_STATE_OFFSET: u16 = 0x0D40;
pub const BOSMINER_PAYLOAD_HOOK_PARENT_CAPTURE_OFFSETS: [u16; 2] = [0x11F0, 0x11F8];
pub const BOSMINER_PAYLOAD_HOOK_CHILD_CAPTURE_OFFSETS: [u16; 2] = [0x04B0, 0x04B8];
pub const BOSMINER_PAYLOAD_HOOK_CHILD_WORKING_OFFSETS: [u16; 2] = [0x04F0, 0x04F8];
pub const BOSMINER_PAYLOAD_HOOK_CHILD_METHOD_SLOT: u8 = 0x20;
pub const BOSMINER_PAYLOAD_HOOK_CHILD_DISPATCH_VAS: [u64; 3] =
    [0x0047_AB50, 0x004C_B318, 0x004F_8B64];
pub const BOSMINER_PAYLOAD_HOOK_CHILD_RESULT_OFFSETS: [u16; 2] = [0x0A00, 0x0A08];
pub const BOSMINER_PAYLOAD_HOOK_MATERIALIZE_FN_VA: u64 = 0x00B2_58B8;
pub const BOSMINER_PAYLOAD_HOOK_MATERIALIZE_CALL_VAS: [u64; 3] =
    [0x0047_BC98, 0x004C_C410, 0x004F_9C5C];
pub const BOSMINER_PAYLOAD_HOOK_MATERIALIZE_FINAL_ARG_PAIR_OFFSET: u8 = 0x30;
pub const BOSMINER_PAYLOAD_HOOK_MATERIALIZED_PAIR_OFFSETS: [u16; 2] = [0x04C0, 0x04C8];
pub const BOSMINER_PAYLOAD_HOOK_PREFIX_COPY_BYTES: u16 = 0x0660;
pub const BOSMINER_PRESTAGE_REFUTED_RUNTIME_OBJECT_STATE_OFFSET: u16 = 0x2940;
pub const BOSMINER_PRESTAGE_REFUTED_RUNTIME_OBJECT_TAIL_OFFSETS: [u8; 2] = [0x50, 0x58];
pub const BOSMINER_PRESTAGE_REFUTED_MAIN_FUTURE_FOOTER_BYTES: u8 = 0x60;
pub const BOSMINER_PRESTAGE_REFUTED_FOOTER_TAIL_OFFSETS: [u8; 2] = [0x50, 0x58];
pub const BOSMINER_PRESTAGE_REFUTED_ROTATED_TAIL_OFFSET: u8 = 0x50;
pub const BOSMINER_PRESTAGE_B90C_ENTRY_PREFIX_OFFSET: u8 = 0x60;
pub const BOSMINER_PRESTAGE_B90C_ENTRY_VEC_OFFSET: u8 = 0x70;
pub const BOSMINER_PRESTAGE_B90C_SNAPSHOT_PREFIX_OFFSET: u16 = 0x0730;
pub const BOSMINER_PRESTAGE_B90C_OWNED_PREFIX_OFFSET: u16 = 0x0E10;
pub const BOSMINER_PRESTAGE_B879_INPUT_PREFIX_OFFSET: u8 = 0x00;
pub const BOSMINER_PRESTAGE_B879_SNAPSHOT_PREFIX_OFFSET: u16 = 0x06E0;
pub const BOSMINER_PRESTAGE_B879_CLONE_STACK_OFFSET: u16 = 0x0BF0;
pub const BOSMINER_PRESTAGE_B879_CLONE_FORWARD_CAP_DATA_STACK_OFFSET: u16 = 0x0BD0;
pub const BOSMINER_PRESTAGE_B879_CLONE_FORWARD_LEN_STACK_OFFSET: u16 = 0x0BE0;
pub const BOSMINER_PRESTAGE_B879_CLONE_LATER_OVERWRITE_FN_VA: u64 = 0x00B6_00A4;
pub const BOSMINER_PRESTAGE_PAYLOAD_PREFIX_SOURCE_STACK_OFFSET: u16 = 0x0A20;
pub const BOSMINER_PRESTAGE_PAYLOAD_VEC_STACK_OFFSETS: [u16; 3] = [0x0A30, 0x0A38, 0x0A40];
pub const BOSMINER_PRESTAGE_PAYLOAD_PREFIX_STAGING_STACK_OFFSET: u16 = 0x0C10;
pub const BOSMINER_PRESTAGE_PAYLOAD_PREFIX_STAGING_BYTES: u16 = 0x0190;
pub const BOSMINER_PRESTAGE_PAYLOAD_PREFIX_CONSTRUCTOR_ARG_INDEX: u8 = 7;
pub const BOSMINER_PRESTAGE_B90C_CLONE_REACHES_PAYLOAD_PREFIX: bool = true;
pub const BOSMINER_PRESTAGE_PROVIDER_PAIR_STATE_OFFSETS: [u16; 2] = [0x04B0, 0x04B8];
pub const BOSMINER_PRESTAGE_PROVIDER_METHOD_SLOT: u8 = 0x18;
pub const BOSMINER_PRESTAGE_PROVIDER_PRESERVED_DATA_STATE_OFFSET: u16 = 0x0EA8;
pub const BOSMINER_PRESTAGE_PROVIDER_DATA_CLONE_FN_VA: u64 = 0x0046_8B24;
pub const BOSMINER_PRESTAGE_PROVIDER_PREFIX_CLONE_FN_VA: u64 = 0x0046_85AC;
pub const BOSMINER_PRESTAGE_PROVIDER_VEC_OFFSET: u8 = 0x10;
pub const BOSMINER_PRESTAGE_MATERIALIZER_INPUT_PREFIX_BYTES: u16 = 0x02A0;
pub const BOSMINER_PRESTAGE_MATERIALIZED_PREFIX_BYTES: u16 = 0x0660;
pub const BOSMINER_HASHCHAIN_MANAGER_VEC_OFFSETS: [u8; 3] = [0x10, 0x18, 0x20];
pub const BOSMINER_HASHCHAIN_MANAGER_DROP_FN_VA: u64 = 0x00B7_5924;
pub const BOSMINER_PAYLOAD_HOOK_MAIN_FUTURE_BUILD_FN_VA: u64 = 0x00B2_6FE8;
pub const BOSMINER_PAYLOAD_HOOK_MAIN_FUTURE_BUILD_CALL_VAS: [u64; 3] =
    [0x0047_CDB0, 0x004C_D4E8, 0x004F_AD34];
pub const BOSMINER_PAYLOAD_HOOK_MAIN_FUTURE_POLL_FN_VA: u64 = 0x00B2_70B4;
pub const BOSMINER_PAYLOAD_HOOK_MAIN_FUTURE_SNAPSHOT_OFFSET: u16 = 0x06C0;
pub const BOSMINER_PAYLOAD_HOOK_MAIN_FUTURE_SNAPSHOT_PAIR_OFFSETS: [u16; 2] = [0x0B80, 0x0B88];
pub const BOSMINER_PAYLOAD_HOOK_LISTENER_BUILD_FN_VA: u64 = 0x00B8_7980;
pub const BOSMINER_PAYLOAD_HOOK_LISTENER_SNAPSHOT_OFFSET: u16 = 0x06E0;
pub const BOSMINER_PAYLOAD_HOOK_LISTENER_SOURCE_PAIR_OFFSETS: [u16; 2] = [0x04C0, 0x04C8];
pub const BOSMINER_PAYLOAD_HOOK_LISTENER_WORKING_PAIR_OFFSETS: [u16; 2] = [0x0BA0, 0x0BA8];
pub const BOSMINER_PAYLOAD_HOOK_LISTENER_METHOD_SLOT: u8 = 0x18;
pub const BOSMINER_PAYLOAD_HOOK_LISTENER_DISPATCH_VA: u64 = 0x00B8_7AE4;
pub const BOSMINER_PAYLOAD_HOOK_CANDIDATE_BYTES: u8 = 0x10;
pub const BOSMINER_PAYLOAD_HOOK_SELECTED_CANDIDATE_OFFSETS: [u16; 2] = [0x0E20, 0x0E28];
pub const BOSMINER_PAYLOAD_HOOK_CANDIDATE_VALIDATE_METHOD_SLOT: u8 = 0x28;
pub const BOSMINER_PAYLOAD_HOOK_CANDIDATE_VALIDATE_DISPATCH_VA: u64 = 0x00B8_96F4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BosminerPayloadHookProducerResolutionBoundary {
    /// `FUN_00794c48` implements first-success across ordered Antminer and
    /// Braiins Fixture code-3 builders. Static analysis proves both possible
    /// provider vtables and both no-op lifecycle hooks, but not which builder
    /// succeeds for a runtime lookup. The hook preserves provider data, whose
    /// `+0x10` Vec lineage is exact through cloning, materialization, B90c,
    /// B879, and `HashchainManager P+0x10`. The runtime selection, Vec bytes,
    /// and final table slot-`+0x28` target remain dynamic.
    Code3FirstSuccessProviderCandidatesAndPrestageLineageResolvedRuntimeSelectionBytesAndFinalMethodRemainDynamic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BosminerPayloadHookDisposition {
    NoOpRetainsPrestagedPair,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerPayloadHookProducerEvidence {
    pub registry_select_fn_va: u64,
    pub registry_vec_data_offset: u8,
    pub registry_vec_len_offset: u8,
    pub registry_entry_bytes: u8,
    pub registry_entry_method_slot: u8,
    pub registry_select_call_vas: [u64; 3],
    pub selected_pair_offsets: [u16; 2],
    pub option_wrap_fn_va: u64,
    pub option_wrap_call_vas: [u64; 3],
    pub wrapped_pair_offsets: [u16; 2],
    pub parent_child_state_offset: u16,
    pub parent_capture_offsets: [u16; 2],
    pub child_capture_offsets: [u16; 2],
    pub child_working_offsets: [u16; 2],
    pub child_method_slot: u8,
    pub child_dispatch_vas: [u64; 3],
    pub child_result_offsets: [u16; 2],
    pub materialize_fn_va: u64,
    pub materialize_call_vas: [u64; 3],
    pub materialize_final_arg_pair_offset: u8,
    pub materialized_pair_offsets: [u16; 2],
    pub prefix_copy_bytes: u16,
    /// The runtime-object footer is a separate control/ownership tail and not
    /// the byte source of the manager's prestage Vec.
    pub refuted_runtime_object_state_offset: u16,
    pub refuted_runtime_object_tail_offsets: [u8; 2],
    pub refuted_main_future_footer_bytes: u8,
    pub refuted_footer_tail_offsets: [u8; 2],
    pub refuted_rotated_tail_offset: u8,
    /// B879 clones the active B90c Vec at `sp+0xbf0`, forwards cap/data via
    /// `sp+0xbd0` and length via `sp+0xbe0`, and installs the three words at
    /// payload-prefix `+0x10/+0x18/+0x20` before the old clone slot is reused.
    pub b90c_entry_prefix_offset: u8,
    pub b90c_entry_vec_offset: u8,
    pub b90c_snapshot_prefix_offset: u16,
    pub b90c_owned_prefix_offset: u16,
    pub b879_input_prefix_offset: u8,
    pub b879_snapshot_prefix_offset: u16,
    pub b879_clone_stack_offset: u16,
    pub b879_clone_forward_cap_data_stack_offset: u16,
    pub b879_clone_forward_len_stack_offset: u16,
    pub b879_clone_later_overwrite_fn_va: u64,
    pub payload_prefix_source_stack_offset: u16,
    pub payload_vec_stack_offsets: [u16; 3],
    pub payload_prefix_staging_stack_offset: u16,
    pub payload_prefix_staging_bytes: u16,
    pub payload_prefix_constructor_arg_index: u8,
    pub b90c_clone_reaches_payload_prefix: bool,
    pub prestage_provider_pair_state_offsets: [u16; 2],
    pub prestage_provider_method_slot: u8,
    pub prestage_provider_preserved_data_state_offset: u16,
    pub prestage_provider_data_clone_fn_va: u64,
    pub prestage_provider_prefix_clone_fn_va: u64,
    pub prestage_provider_vec_offset: u8,
    pub prestage_materializer_input_prefix_bytes: u16,
    pub prestage_materialized_prefix_bytes: u16,
    pub hashchain_manager_vec_offsets: [u8; 3],
    pub hashchain_manager_drop_fn_va: u64,
    pub main_future_build_fn_va: u64,
    pub main_future_build_call_vas: [u64; 3],
    pub main_future_poll_fn_va: u64,
    pub main_future_snapshot_offset: u16,
    pub main_future_snapshot_pair_offsets: [u16; 2],
    pub listener_build_fn_va: u64,
    pub listener_snapshot_offset: u16,
    pub listener_source_pair_offsets: [u16; 2],
    pub listener_working_pair_offsets: [u16; 2],
    pub listener_method_slot: u8,
    pub listener_dispatch_va: u64,
    pub candidate_bytes: u8,
    pub selected_candidate_offsets: [u16; 2],
    pub candidate_validate_method_slot: u8,
    pub candidate_validate_dispatch_va: u64,
    pub payload_candidate_offsets: [u16; 2],
    pub code3_builder_vtable_vas: [u64; 2],
    pub code3_provider_vtable_vas: [u64; 2],
    pub candidate_validate_method_vas: [u64; 2],
    pub lifecycle_hook_method_vas: [u64; 2],
    pub child_method_vas: [u64; 2],
    pub child_result_bytes: [u16; 2],
    pub child_result_vtable_vas: [u64; 2],
    pub lifecycle_hook_disposition: BosminerPayloadHookDisposition,
    pub prestage_vec_source_offset: u8,
    pub prestage_vec_clone_fn_va: u64,
    pub prestage_vec_clone_dispatch_va: u64,
    pub prestaged_data_offset: u16,
    pub concrete_prestaged_dispatch_table_va: Option<u64>,
    pub resolution_boundary: BosminerPayloadHookProducerResolutionBoundary,
}

pub const BOSMINER_PAYLOAD_HOOK_PRODUCER_EVIDENCE: BosminerPayloadHookProducerEvidence =
    BosminerPayloadHookProducerEvidence {
        registry_select_fn_va: BOSMINER_PAYLOAD_HOOK_REGISTRY_SELECT_FN_VA,
        registry_vec_data_offset: BOSMINER_PAYLOAD_HOOK_REGISTRY_VEC_DATA_OFFSET,
        registry_vec_len_offset: BOSMINER_PAYLOAD_HOOK_REGISTRY_VEC_LEN_OFFSET,
        registry_entry_bytes: BOSMINER_PAYLOAD_HOOK_REGISTRY_ENTRY_BYTES,
        registry_entry_method_slot: BOSMINER_PAYLOAD_HOOK_REGISTRY_ENTRY_METHOD_SLOT,
        registry_select_call_vas: BOSMINER_PAYLOAD_HOOK_REGISTRY_SELECT_CALL_VAS,
        selected_pair_offsets: BOSMINER_PAYLOAD_HOOK_SELECTED_PAIR_OFFSETS,
        option_wrap_fn_va: BOSMINER_PAYLOAD_HOOK_OPTION_WRAP_FN_VA,
        option_wrap_call_vas: BOSMINER_PAYLOAD_HOOK_OPTION_WRAP_CALL_VAS,
        wrapped_pair_offsets: BOSMINER_PAYLOAD_HOOK_WRAPPED_PAIR_OFFSETS,
        parent_child_state_offset: BOSMINER_PAYLOAD_HOOK_PARENT_CHILD_STATE_OFFSET,
        parent_capture_offsets: BOSMINER_PAYLOAD_HOOK_PARENT_CAPTURE_OFFSETS,
        child_capture_offsets: BOSMINER_PAYLOAD_HOOK_CHILD_CAPTURE_OFFSETS,
        child_working_offsets: BOSMINER_PAYLOAD_HOOK_CHILD_WORKING_OFFSETS,
        child_method_slot: BOSMINER_PAYLOAD_HOOK_CHILD_METHOD_SLOT,
        child_dispatch_vas: BOSMINER_PAYLOAD_HOOK_CHILD_DISPATCH_VAS,
        child_result_offsets: BOSMINER_PAYLOAD_HOOK_CHILD_RESULT_OFFSETS,
        materialize_fn_va: BOSMINER_PAYLOAD_HOOK_MATERIALIZE_FN_VA,
        materialize_call_vas: BOSMINER_PAYLOAD_HOOK_MATERIALIZE_CALL_VAS,
        materialize_final_arg_pair_offset:
            BOSMINER_PAYLOAD_HOOK_MATERIALIZE_FINAL_ARG_PAIR_OFFSET,
        materialized_pair_offsets: BOSMINER_PAYLOAD_HOOK_MATERIALIZED_PAIR_OFFSETS,
        prefix_copy_bytes: BOSMINER_PAYLOAD_HOOK_PREFIX_COPY_BYTES,
        refuted_runtime_object_state_offset:
            BOSMINER_PRESTAGE_REFUTED_RUNTIME_OBJECT_STATE_OFFSET,
        refuted_runtime_object_tail_offsets:
            BOSMINER_PRESTAGE_REFUTED_RUNTIME_OBJECT_TAIL_OFFSETS,
        refuted_main_future_footer_bytes:
            BOSMINER_PRESTAGE_REFUTED_MAIN_FUTURE_FOOTER_BYTES,
        refuted_footer_tail_offsets: BOSMINER_PRESTAGE_REFUTED_FOOTER_TAIL_OFFSETS,
        refuted_rotated_tail_offset: BOSMINER_PRESTAGE_REFUTED_ROTATED_TAIL_OFFSET,
        b90c_entry_prefix_offset: BOSMINER_PRESTAGE_B90C_ENTRY_PREFIX_OFFSET,
        b90c_entry_vec_offset: BOSMINER_PRESTAGE_B90C_ENTRY_VEC_OFFSET,
        b90c_snapshot_prefix_offset: BOSMINER_PRESTAGE_B90C_SNAPSHOT_PREFIX_OFFSET,
        b90c_owned_prefix_offset: BOSMINER_PRESTAGE_B90C_OWNED_PREFIX_OFFSET,
        b879_input_prefix_offset: BOSMINER_PRESTAGE_B879_INPUT_PREFIX_OFFSET,
        b879_snapshot_prefix_offset: BOSMINER_PRESTAGE_B879_SNAPSHOT_PREFIX_OFFSET,
        b879_clone_stack_offset: BOSMINER_PRESTAGE_B879_CLONE_STACK_OFFSET,
        b879_clone_forward_cap_data_stack_offset:
            BOSMINER_PRESTAGE_B879_CLONE_FORWARD_CAP_DATA_STACK_OFFSET,
        b879_clone_forward_len_stack_offset:
            BOSMINER_PRESTAGE_B879_CLONE_FORWARD_LEN_STACK_OFFSET,
        b879_clone_later_overwrite_fn_va:
            BOSMINER_PRESTAGE_B879_CLONE_LATER_OVERWRITE_FN_VA,
        payload_prefix_source_stack_offset:
            BOSMINER_PRESTAGE_PAYLOAD_PREFIX_SOURCE_STACK_OFFSET,
        payload_vec_stack_offsets: BOSMINER_PRESTAGE_PAYLOAD_VEC_STACK_OFFSETS,
        payload_prefix_staging_stack_offset:
            BOSMINER_PRESTAGE_PAYLOAD_PREFIX_STAGING_STACK_OFFSET,
        payload_prefix_staging_bytes: BOSMINER_PRESTAGE_PAYLOAD_PREFIX_STAGING_BYTES,
        payload_prefix_constructor_arg_index:
            BOSMINER_PRESTAGE_PAYLOAD_PREFIX_CONSTRUCTOR_ARG_INDEX,
        b90c_clone_reaches_payload_prefix:
            BOSMINER_PRESTAGE_B90C_CLONE_REACHES_PAYLOAD_PREFIX,
        prestage_provider_pair_state_offsets: BOSMINER_PRESTAGE_PROVIDER_PAIR_STATE_OFFSETS,
        prestage_provider_method_slot: BOSMINER_PRESTAGE_PROVIDER_METHOD_SLOT,
        prestage_provider_preserved_data_state_offset:
            BOSMINER_PRESTAGE_PROVIDER_PRESERVED_DATA_STATE_OFFSET,
        prestage_provider_data_clone_fn_va: BOSMINER_PRESTAGE_PROVIDER_DATA_CLONE_FN_VA,
        prestage_provider_prefix_clone_fn_va: BOSMINER_PRESTAGE_PROVIDER_PREFIX_CLONE_FN_VA,
        prestage_provider_vec_offset: BOSMINER_PRESTAGE_PROVIDER_VEC_OFFSET,
        prestage_materializer_input_prefix_bytes:
            BOSMINER_PRESTAGE_MATERIALIZER_INPUT_PREFIX_BYTES,
        prestage_materialized_prefix_bytes: BOSMINER_PRESTAGE_MATERIALIZED_PREFIX_BYTES,
        hashchain_manager_vec_offsets: BOSMINER_HASHCHAIN_MANAGER_VEC_OFFSETS,
        hashchain_manager_drop_fn_va: BOSMINER_HASHCHAIN_MANAGER_DROP_FN_VA,
        main_future_build_fn_va: BOSMINER_PAYLOAD_HOOK_MAIN_FUTURE_BUILD_FN_VA,
        main_future_build_call_vas: BOSMINER_PAYLOAD_HOOK_MAIN_FUTURE_BUILD_CALL_VAS,
        main_future_poll_fn_va: BOSMINER_PAYLOAD_HOOK_MAIN_FUTURE_POLL_FN_VA,
        main_future_snapshot_offset: BOSMINER_PAYLOAD_HOOK_MAIN_FUTURE_SNAPSHOT_OFFSET,
        main_future_snapshot_pair_offsets:
            BOSMINER_PAYLOAD_HOOK_MAIN_FUTURE_SNAPSHOT_PAIR_OFFSETS,
        listener_build_fn_va: BOSMINER_PAYLOAD_HOOK_LISTENER_BUILD_FN_VA,
        listener_snapshot_offset: BOSMINER_PAYLOAD_HOOK_LISTENER_SNAPSHOT_OFFSET,
        listener_source_pair_offsets: BOSMINER_PAYLOAD_HOOK_LISTENER_SOURCE_PAIR_OFFSETS,
        listener_working_pair_offsets: BOSMINER_PAYLOAD_HOOK_LISTENER_WORKING_PAIR_OFFSETS,
        listener_method_slot: BOSMINER_PAYLOAD_HOOK_LISTENER_METHOD_SLOT,
        listener_dispatch_va: BOSMINER_PAYLOAD_HOOK_LISTENER_DISPATCH_VA,
        candidate_bytes: BOSMINER_PAYLOAD_HOOK_CANDIDATE_BYTES,
        selected_candidate_offsets: BOSMINER_PAYLOAD_HOOK_SELECTED_CANDIDATE_OFFSETS,
        candidate_validate_method_slot: BOSMINER_PAYLOAD_HOOK_CANDIDATE_VALIDATE_METHOD_SLOT,
        candidate_validate_dispatch_va:
            BOSMINER_PAYLOAD_HOOK_CANDIDATE_VALIDATE_DISPATCH_VA,
        payload_candidate_offsets: [
            BOSMINER_LIFECYCLE_PAYLOAD_HOOK_TRAIT_DATA_OFFSET,
            BOSMINER_LIFECYCLE_PAYLOAD_HOOK_TRAIT_VTABLE_OFFSET,
        ],
        code3_builder_vtable_vas: BOSMINER_CODE3_BUILDER_VTABLE_VAS,
        code3_provider_vtable_vas: BOSMINER_CODE3_PROVIDER_VTABLE_VAS,
        candidate_validate_method_vas: BOSMINER_CODE3_CANDIDATE_VALIDATE_METHOD_VAS,
        lifecycle_hook_method_vas: BOSMINER_CODE3_LIFECYCLE_HOOK_METHOD_VAS,
        child_method_vas: BOSMINER_CODE3_CHILD_METHOD_VAS,
        child_result_bytes: BOSMINER_CODE3_CHILD_RESULT_BYTES,
        child_result_vtable_vas: BOSMINER_CODE3_CHILD_RESULT_VTABLE_VAS,
        lifecycle_hook_disposition: BosminerPayloadHookDisposition::NoOpRetainsPrestagedPair,
        prestage_vec_source_offset: BOSMINER_LIFECYCLE_PRESTAGE_VEC_SOURCE_OFFSET,
        prestage_vec_clone_fn_va: BOSMINER_LIFECYCLE_PRESTAGE_VEC_CLONE_FN_VA,
        prestage_vec_clone_dispatch_va: BOSMINER_LIFECYCLE_PRESTAGE_VEC_CLONE_DISPATCH_VA,
        prestaged_data_offset: BOSMINER_LIFECYCLE_PRESTAGED_DATA_OFFSET,
        concrete_prestaged_dispatch_table_va: None,
        resolution_boundary: BosminerPayloadHookProducerResolutionBoundary::Code3FirstSuccessProviderCandidatesAndPrestageLineageResolvedRuntimeSelectionBytesAndFinalMethodRemainDynamic,
    };

/// Exact instructions for the three sibling provider-selection lanes, their
/// common registry walk and option wrapper, the child slot-`+0x20` producer,
/// `FUN_00b258b8` final-argument projection, 0x660-byte future snapshots, the
/// listener slot-`+0x18` candidate-vector producer, candidate slot-`+0x28`
/// validation, and installation at `HashchainManager P+0x230/+0x238`.
/// These pins establish the common provenance; the finite code-3 provider set
/// is admitted by [`BOSMINER_PAYLOAD_HOOK_CODE3_CANDIDATE_PINS`]. No physical
/// reset/GPIO effect is inferred.
pub const BOSMINER_PAYLOAD_HOOK_PRODUCER_LINEAGE_PINS: [(u64, u32); 167] = [
    (0x0079_4C54, 0xA940_A408),
    (0x0079_4C64, 0xD37C_ED36),
    (0x0079_4C6C, 0xA940_250B),
    (0x0079_4C80, 0xF940_092A),
    (0x0079_4C84, 0xF940_1929),
    (0x0079_4C98, 0xD63F_0120),
    (0x0079_4C9C, 0xD100_42D6),
    (0x0079_4CA4, 0xB4FF_FE20),
    (0x0047_17E8, 0x912A_6276),
    (0x0047_1804, 0x940C_8D11),
    (0x0047_181C, 0xF902_2A60),
    (0x0047_1820, 0xF902_2E61),
    (0x004C_1FAC, 0x912A_6276),
    (0x004C_1FC8, 0x940B_4B20),
    (0x004C_1FE0, 0xF902_2A60),
    (0x004C_1FE4, 0xF902_2E61),
    (0x004E_F7F8, 0x912A_6276),
    (0x004E_F814, 0x940A_950D),
    (0x004E_F82C, 0xF902_2A60),
    (0x004E_F830, 0xF902_2E61),
    (0x0056_14D4, 0xAA08_03F5),
    (0x0056_1500, 0xB400_0133),
    (0x0056_1504, 0xF100_0AFF),
    (0x0056_151C, 0xA900_52B3),
    (0x0047_8AA0, 0xF942_2A7A),
    (0x0047_8AA4, 0xF942_2E79),
    (0x0047_8D20, 0x911F_0268),
    (0x0047_8D24, 0xAA1A_03E0),
    (0x0047_8D2C, 0xAA19_03E1),
    (0x0047_8D30, 0x9403_A1E4),
    (0x004C_9264, 0xF942_2A7A),
    (0x004C_9268, 0xF942_2E79),
    (0x004C_94E4, 0x911F_0268),
    (0x004C_94E8, 0xAA1A_03E0),
    (0x004C_94F0, 0xAA19_03E1),
    (0x004C_94F4, 0x9402_5FF3),
    (0x004F_6AB0, 0xF942_2A7A),
    (0x004F_6AB4, 0xF942_2E79),
    (0x004F_6D30, 0x911F_0268),
    (0x004F_6D34, 0xAA1A_03E0),
    (0x004F_6D3C, 0xAA19_03E1),
    (0x004F_6D40, 0x9401_A9E0),
    (0x0047_906C, 0x3DC1_F260),
    (0x0047_9080, 0x3D80_17E0),
    (0x0047_9378, 0xAD42_03E1),
    (0x0047_9388, 0x3D84_7E60),
    (0x0046_E110, 0x9135_0261),
    (0x0046_E11C, 0x9400_3187),
    (0x004C_9830, 0x3DC1_F260),
    (0x004C_9844, 0x3D80_17E0),
    (0x004C_9B3C, 0xAD42_03E1),
    (0x004C_9B4C, 0x3D84_7E60),
    (0x004B_E8D4, 0x9135_0261),
    (0x004B_E8E0, 0x9400_3187),
    (0x004F_707C, 0x3DC1_F260),
    (0x004F_7090, 0x3D80_17E0),
    (0x004F_7388, 0xAD42_03E1),
    (0x004F_7398, 0x3D84_7E60),
    (0x004E_C120, 0x9135_0261),
    (0x004E_C12C, 0x9400_3187),
    (0x0047_A7C4, 0xF942_5B34),
    (0x0047_A7C8, 0xF942_5F35),
    (0x0047_A7F0, 0xF902_7B34),
    (0x0047_A7F4, 0xF902_7F35),
    (0x0047_AB28, 0xF942_7F28),
    (0x0047_AB38, 0xF942_7B20),
    (0x0047_AB40, 0xF940_1108),
    (0x0047_AB50, 0xD63F_0100),
    (0x0047_AB78, 0xF905_0320),
    (0x0047_AB7C, 0xF905_0721),
    (0x004C_AF90, 0xF942_5A74),
    (0x004C_AF94, 0xF942_5E75),
    (0x004C_AFBC, 0xF902_7A74),
    (0x004C_AFC0, 0xF902_7E75),
    (0x004C_B2F0, 0xF942_7E68),
    (0x004C_B300, 0xF942_7A60),
    (0x004C_B308, 0xF940_1108),
    (0x004C_B318, 0xD63F_0100),
    (0x004C_B340, 0xF905_0260),
    (0x004C_B344, 0xF905_0661),
    (0x004F_87DC, 0xF942_5A74),
    (0x004F_87E0, 0xF942_5E75),
    (0x004F_8808, 0xF902_7A74),
    (0x004F_880C, 0xF902_7E75),
    (0x004F_8B3C, 0xF942_7E68),
    (0x004F_8B4C, 0xF942_7A60),
    (0x004F_8B54, 0xF940_1108),
    (0x004F_8B64, 0xD63F_0100),
    (0x004F_8B8C, 0xF905_0260),
    (0x004F_8B90, 0xF905_0661),
    (0x0047_BC38, 0x3DC2_8321),
    (0x0047_BC68, 0x3D87_33E1),
    (0x0047_BC78, 0x9140_07E7),
    (0x0047_BC94, 0x9133_00E7),
    (0x0047_BC98, 0x941A_A708),
    (0x004C_C3B0, 0x3DC2_8261),
    (0x004C_C3E0, 0x3D87_33E1),
    (0x004C_C3F0, 0x9140_07E7),
    (0x004C_C40C, 0x9133_00E7),
    (0x004C_C410, 0x9419_652A),
    (0x004F_9BFC, 0x3DC2_8261),
    (0x004F_9C2C, 0x3D87_33E1),
    (0x004F_9C3C, 0x9140_07E7),
    (0x004F_9C58, 0x9133_00E7),
    (0x004F_9C5C, 0x9418_AF17),
    (0x00B2_5AC4, 0xAD41_82C2),
    (0x00B2_5AD0, 0x3D81_37E2),
    (0x00B2_5B44, 0x9100_43E1),
    (0x00B2_5B4C, 0x5280_9C02),
    (0x00B2_5B58, 0x9402_8D22),
    (0x0047_C1EC, 0x5280_CC02),
    (0x0047_C1FC, 0x941D_3379),
    (0x0047_C200, 0x913C_433B),
    (0x0047_C234, 0x941D_336B),
    (0x0047_CD7C, 0x5284_4808),
    (0x0047_CD84, 0x5280_CC02),
    (0x0047_CD94, 0x941D_3093),
    (0x0047_CDB0, 0x941A_A88E),
    (0x004C_C958, 0x5280_CC02),
    (0x004C_C968, 0x941B_F19E),
    (0x004C_C96C, 0x913C_427D),
    (0x004C_C9A0, 0x941B_F190),
    (0x004C_D4B4, 0x5284_4808),
    (0x004C_D4BC, 0x5280_CC02),
    (0x004C_D4CC, 0x941B_EEC5),
    (0x004C_D4E8, 0x9419_66C0),
    (0x004F_A1A4, 0x5280_CC02),
    (0x004F_A1B4, 0x941B_3B8B),
    (0x004F_A1B8, 0x913C_427D),
    (0x004F_A1EC, 0x941B_3B7D),
    (0x004F_AD00, 0x5284_4808),
    (0x004F_AD08, 0x5280_CC02),
    (0x004F_AD18, 0x941B_38B2),
    (0x004F_AD34, 0x9418_B0AD),
    (0x00B2_7004, 0xAA00_03E1),
    (0x00B2_7008, 0x9100_03E0),
    (0x00B2_700C, 0x5280_CC02),
    (0x00B2_7010, 0x9402_87F4),
    (0x00B2_7124, 0x911B_0260),
    (0x00B2_7128, 0xAA13_03E1),
    (0x00B2_712C, 0x5280_CC02),
    (0x00B2_7140, 0x9402_87A8),
    (0x00B3_D8AC, 0x9101_8100),
    (0x00B3_D8B0, 0x9101_8261),
    (0x00B3_D8B4, 0x5280_CC02),
    (0x00B3_D8CC, 0x9402_2DC5),
    (0x00B7_B89C, 0xAA13_03E1),
    (0x00B7_B8A0, 0x5284_BE02),
    (0x00B7_B8A4, 0x9100_3100),
    (0x00B7_B8D8, 0xB900_33FF),
    (0x00B7_B91C, 0x9401_35B1),
    (0x00B8_7A38, 0x911B_8260),
    (0x00B8_7A3C, 0xAA13_03E1),
    (0x00B8_7A40, 0x5280_CC02),
    (0x00B8_7A50, 0x9401_0564),
    (0x00B8_7A64, 0xF945_D260),
    (0x00B8_7AAC, 0xF945_D668),
    (0x00B8_7ADC, 0xF940_0D09),
    (0x00B8_7AE4, 0xD63F_0120),
    (0x00B8_96D4, 0xA940_2808),
    (0x00B8_96D8, 0x393C_0269),
    (0x00B8_96E0, 0xF907_0E6A),
    (0x00B8_96E8, 0xF907_166A),
    (0x00B8_96EC, 0xF940_1549),
    (0x00B8_96F4, 0xD63F_0120),
    (0x00B5_C26C, 0xF901_1B29),
    (0x00B5_C270, 0xF901_1F28),
];

/// Exact corrected lineage for the byte Vec installed at
/// `HashchainManager P+0x10`. The provider slot-`+0x18` no-op preserves the
/// selected provider data; its `+0x10` Vec is cloned through the 0x2a0-byte materializer
/// prefix, the 0x660-byte future prefix, B90c, and B879. B879 forwards the
/// clone's cap/data/len into `sp+0xa30/+0xa38/+0xa40` before `sp+0xbf0` is
/// reused; the 0x190-byte prefix copy and `FUN_00b5c168` then install it at
/// manager `P+0x10/+0x18/+0x20`. The drop glue independently consumes those
/// offsets as a byte Vec. Runtime bytes, the provider method target, and the
/// final table slot-`+0x28` method remain dynamic.
pub const BOSMINER_PRESTAGE_VEC_BOUNDARY_PINS: [(u64, u32); 200] = [
    (0x0047_A918, 0xF940_0EA9),
    (0x0047_A91C, 0xAA14_03E0),
    (0x0047_A920, 0xD63F_0120),
    (0x0047_A928, 0xF907_5720),
    (0x0047_B96C, 0xF947_5721),
    (0x0047_B978, 0x913B_C3E0),
    (0x0047_B97C, 0x97FF_B46A),
    (0x0046_85F0, 0x9103_83E8),
    (0x0046_85F4, 0x9100_4280),
    (0x0046_85F8, 0x9439_A85D),
    (0x0046_8B54, 0x9101_03E0),
    (0x0046_8B58, 0xAA14_03E1),
    (0x0046_8B5C, 0x97FF_FE94),
    (0x0047_BC6C, 0x9140_07E8),
    (0x0047_BC88, 0x913B_C3E0),
    (0x00B2_58E0, 0xAA08_03F7),
    (0x00B2_58DC, 0xAA00_03F4),
    (0x00B2_59E4, 0x9116_43E0),
    (0x00B2_59EC, 0xAA14_03E1),
    (0x00B2_59F0, 0x5280_5402),
    (0x00B2_5A30, 0x9402_8D6C),
    (0x00B2_5AE4, 0x9100_43E0),
    (0x00B2_5AF0, 0x9116_43E1),
    (0x00B2_5AFC, 0x5280_5402),
    (0x00B2_5B38, 0x9402_8D2A),
    (0x00B2_5B48, 0xAA17_03E0),
    (0x0047_C1C8, 0x9140_07E8),
    (0x0047_C1D4, 0x9135_4108),
    (0x0047_C1D8, 0x9100_4120),
    (0x0047_C1DC, 0x9100_4101),
    (0x0047_C1E0, 0x941D_3380),
    (0x0047_C1E4, 0x913B_C3E0),
    (0x0047_C1E8, 0x9122_43E1),
    (0x0047_C1F0, 0xF904_4BF3),
    (0x0047_C204, 0x913B_C3E1),
    (0x0047_C20C, 0xAA1B_03E0),
    (0x0047_C210, 0x941D_3374),
    (0x0047_C218, 0x5282_AE14),
    (0x0047_C220, 0xAA1B_03E1),
    (0x0047_C224, 0x8B14_0320),
    (0x0047_C228, 0x5280_CC02),
    (0x0047_C608, 0x9140_07E0),
    (0x0047_C60C, 0x5280_CC02),
    (0x0047_C610, 0x9135_4000),
    (0x0047_C618, 0x8B14_0261),
    (0x0047_C61C, 0x941D_3271),
    (0x0047_C620, 0x5283_7C08),
    (0x0047_C62C, 0x8B08_0278),
    (0x0047_C634, 0xAA18_03E0),
    (0x0047_C638, 0x941D_326A),
    (0x0047_C64C, 0x5284_4814),
    (0x0047_C658, 0x8B14_0260),
    (0x0047_C65C, 0xAA18_03E1),
    (0x0047_C660, 0x5280_CC02),
    (0x0047_C66C, 0x941D_325D),
    (0x0047_CD80, 0x9140_0BE0),
    (0x0047_CD88, 0x912E_8000),
    (0x0047_CD8C, 0x8B08_0321),
    (0x00B8_A39C, 0x3DC0_77A0),
    (0x00B8_A3A0, 0xF946_03E8),
    (0x00B8_A3B4, 0x3D80_6FA0),
    (0x00B8_A3C0, 0xF905_F3E8),
    (0x00B8_A434, 0xF945_F3F0),
    (0x00B8_A450, 0x3DC0_6FA3),
    (0x00B8_A458, 0x3D80_6383),
    (0x00B8_A4C4, 0xF905_23F0),
    (0x012D_2780, 0xF940_0813),
    (0x012D_2788, 0xF940_0415),
    (0x012D_27D0, 0xA900_5A93),
    (0x012D_27D4, 0xF900_0A93),
    (0x00B7_5944, 0xF940_0A61),
    (0x00B7_594C, 0xF940_0E60),
    (0x0047_CC80, 0xF954_A32C),
    (0x0047_CC90, 0xF940_2D88),
    (0x0047_CD00, 0x3CC4_8180),
    (0x0047_CD24, 0x3DCC_B3E1),
    (0x0047_CD28, 0xF959_6BE9),
    (0x0047_CD2C, 0x3DCA_EBE2),
    (0x0047_CD30, 0x3DCA_EFE3),
    (0x0047_CD3C, 0xF915_A3EA),
    (0x0047_CD60, 0x3C83_8143),
    (0x0047_CD64, 0x3C82_8142),
    (0x0047_CD68, 0x3C84_8140),
    (0x0047_CD70, 0xF915_CFE8),
    (0x0047_CD7C, 0x5284_4808),
    (0x0047_CD94, 0x941D_3093),
    (0x0047_CDB0, 0x941A_A88E),
    (0x00B2_7000, 0xAA01_03F4),
    (0x00B2_7004, 0xAA00_03E1),
    (0x00B2_700C, 0x5280_CC02),
    (0x00B2_7010, 0x9402_87F4),
    (0x00B2_7030, 0xAD42_0680),
    (0x00B2_7034, 0x3D81_ABE0),
    (0x00B2_7038, 0x3D81_AFE1),
    (0x00B2_703C, 0xAD40_0680),
    (0x00B2_7040, 0x3D81_9BE0),
    (0x00B2_7044, 0x3D81_9FE1),
    (0x00B2_7124, 0x911B_0260),
    (0x00B2_7128, 0xAA13_03E1),
    (0x00B2_712C, 0x5280_CC02),
    (0x00B2_7140, 0x9402_87A8),
    (0x00B2_7164, 0x3DC1_AE61),
    (0x00B2_7168, 0x3D83_5A60),
    (0x00B2_717C, 0x3DC1_9E60),
    (0x00B2_7180, 0x3D83_5E61),
    (0x00B2_9304, 0x9101_8280),
    (0x00B2_930C, 0x911B_0261),
    (0x00B2_9318, 0x3DC3_5E60),
    (0x00B2_9324, 0xAD08_83E2),
    (0x00B2_9340, 0x9402_7F28),
    (0x00B2_937C, 0x9103_43E1),
    (0x00B2_E35C, 0x9101_83E8),
    (0x00B2_E360, 0xAA13_03E1),
    (0x00B2_E368, 0x9100_8100),
    (0x00B2_E398, 0x5280_E402),
    (0x00B2_E944, 0xA942_5E76),
    (0x00B2_E948, 0x911C_43E0),
    (0x00B2_E950, 0x5280_DC02),
    (0x00B2_E9AC, 0x9100_42A0),
    (0x00B2_E9C8, 0x9400_3B90),
    (0x00B3_D8A4, 0xAD41_0660),
    (0x00B3_D8B0, 0x9101_8261),
    (0x00B3_D8B4, 0x5280_CC02),
    (0x00B3_D8CC, 0x9402_2DC5),
    (0x00B3_D924, 0x9140_0BE0),
    (0x00B3_D930, 0x5280_D802),
    (0x00B6_4304, 0x9400_5D49),
    (0x00B7_B89C, 0xAA13_03E1),
    (0x00B7_B8A4, 0x9100_3100),
    (0x00B7_B8BC, 0x5280_0688),
    (0x00B7_B8C0, 0x9140_0BE1),
    (0x00B7_B8CC, 0x5284_BF82),
    (0x00B7_B91C, 0x9401_35B1),
    (0x00B7_E804, 0x9100_8260),
    (0x00B7_E80C, 0x9400_491F),
    (0x00B9_0D0C, 0x9101_8100),
    (0x00B9_0D10, 0x9101_8261),
    (0x00B9_0D44, 0x9400_E0A7),
    (0x00B9_0D70, 0x911B_4274),
    (0x00B9_0DB4, 0x9138_4260),
    (0x00B9_0DB8, 0x911C_C261),
    (0x00B9_0DF4, 0x9400_E07B),
    (0x00B9_229C, 0x9138_4261),
    (0x00B9_2344, 0x9140_07E1),
    (0x00B9_23DC, 0x97FF_D569),
    (0x00B8_7A38, 0x911B_8260),
    (0x00B8_7A3C, 0xAA13_03E1),
    (0x00B8_7A40, 0x5280_CC02),
    (0x00B8_7A50, 0x9401_0564),
    (0x00B8_A224, 0x912F_C3E8),
    (0x00B8_A228, 0x9100_42A0),
    (0x00B8_A5D4, 0x9130_43E7),
    (0x00B8_A5F4, 0x97FF_46DD),
    (0x00B5_C1D8, 0xAA19_03E0),
    (0x00B5_C1DC, 0xAA1C_03E1),
    (0x00B5_C1E0, 0x5280_3E02),
    (0x00B5_C1E4, 0xAD0F_8720),
    (0x00B5_C1F0, 0x9401_B37C),
    (0x00B9_0D14, 0x5280_CC02),
    (0x00B9_0D50, 0x9101_C3E0),
    (0x00B9_0D5C, 0x913A_43E1),
    (0x00B9_0D64, 0x5280_D802),
    (0x00B9_0D6C, 0x9400_E09D),
    (0x00B9_0D74, 0x9101_C3E1),
    (0x00B9_0D78, 0x5280_D802),
    (0x00B9_0D80, 0x9400_E098),
    (0x00B9_0DBC, 0x5280_CC02),
    (0x00B9_228C, 0x9140_07E0),
    (0x00B9_2294, 0x9115_4000),
    (0x00B9_22A0, 0x9400_DB50),
    (0x00B9_2348, 0x913A_43E0),
    (0x00B9_234C, 0x5280_CC02),
    (0x00B9_2350, 0x9115_4021),
    (0x00B9_2354, 0x9400_DB23),
    (0x00B9_2360, 0x911F_43E0),
    (0x00B9_2368, 0x913A_43E1),
    (0x00B9_236C, 0x5280_D802),
    (0x00B9_2394, 0x9400_DB13),
    (0x00B9_239C, 0x911F_43E1),
    (0x00B9_23A0, 0x5280_D802),
    (0x00B9_23A4, 0x8B17_0260),
    (0x00B9_23A8, 0x9400_DB0E),
    (0x00B9_23D4, 0x8B18_0260),
    (0x00B8_9F00, 0x911B_826A),
    (0x00B8_9F0C, 0xF907_BE6A),
    (0x00B8_A1E0, 0xF944_AFF5),
    (0x00B8_A22C, 0x941D_2150),
    (0x00B8_A418, 0xF905_17FA),
    (0x00B8_A468, 0xF905_13F4),
    (0x00B8_A500, 0x912F_C3E8),
    (0x00B8_A504, 0x9107_42A0),
    (0x00B8_A508, 0x97FF_56E7),
    (0x00B8_A50C, 0x9130_43E0),
    (0x00B8_A510, 0x9128_83E1),
    (0x00B8_A514, 0x5280_3202),
    (0x00B8_A518, 0x9400_FAB2),
    (0x00B8_A51C, 0x3DC0_7660),
    (0x00B8_A534, 0x3D80_7520),
    (0x00B8_A5F0, 0xF900_03EB),
    (0x00B5_C198, 0xAA07_03FC),
];

/// Exact finite join from the lazy three-entry builder registry to the two
/// ordered code-3 candidates. Antminer and Braiins Fixture success is
/// conditional at runtime; their provider vtables, child constructors,
/// candidate validators, and no-op lifecycle hooks are all pinned. The final instructions pin the
/// prestaging of `{data=P+0x538, dispatch_table=clone(P+0x10).data}` and prove
/// that the no-op leaves it unchanged. The cloned dispatch-table contents and
/// final slot-`+0x28` method remain a dynamic boundary.
pub const BOSMINER_PAYLOAD_HOOK_CODE3_CANDIDATE_PINS: [(u64, u32); 114] = [
    (0x0077_7CD8, 0xD102_C3FF),
    (0x0077_7D18, 0x9100_42C8),
    (0x0077_7D1C, 0x97FD_FE00),
    (0x0077_7D48, 0xB000_91B8),
    (0x0077_7D4C, 0x9120_A318),
    (0x0077_7D54, 0xA900_63E0),
    (0x0077_7D64, 0x9100_4328),
    (0x0077_7D68, 0x97FE_03B9),
    (0x0077_7D94, 0xB000_91B9),
    (0x0077_7D98, 0x9122_0339),
    (0x0077_7DA0, 0xA901_67E0),
    (0x0077_7DB0, 0x9100_4348),
    (0x0077_7DB4, 0x97FD_B12D),
    (0x0077_7DD8, 0xAD41_07E0),
    (0x0077_7DDC, 0xF000_9188),
    (0x0077_7DE0, 0x9129_0108),
    (0x0077_7DE4, 0xA900_6275),
    (0x0077_7DEC, 0xA902_2260),
    (0x0077_7DFC, 0xA901_6676),
    (0x0077_7E00, 0xA949_57F6),
    (0x0077_7E04, 0xA900_4E88),
    (0x0077_7E0C, 0xF900_0A88),
    (0x0079_4818, 0xF000_99D5),
    (0x0079_4838, 0xA940_A6A8),
    (0x0079_483C, 0x8B09_1109),
    (0x0079_4840, 0xA907_27E8),
    (0x0079_485C, 0x9401_5CFF),
    (0x0079_4880, 0xA900_526A),
    (0x0079_4884, 0xA901_2269),
    (0x0079_4888, 0xF900_126B),
    (0x0046_E88C, 0x9118_43E8),
    (0x0046_E890, 0x2A15_03E0),
    (0x0046_E894, 0x940C_97A2),
    (0x0046_E8F8, 0xF905_5268),
    (0x0046_E8FC, 0x912A_A268),
    (0x0046_E90C, 0xF905_4E69),
    (0x0046_E910, 0x3D80_0100),
    (0x0046_E914, 0xF905_5E6B),
    (0x006F_78C0, 0xAA1F_03E0),
    (0x006F_78C4, 0xB000_95A1),
    (0x006F_78C8, 0x9125_E021),
    (0x006F_7A64, 0x97FB_F405),
    (0x006F_7A6C, 0x9121_C3E1),
    (0x006F_7A70, 0x5280_7A02),
    (0x006F_7A74, 0xAA00_03F3),
    (0x006F_7A78, 0x9413_455A),
    (0x006F_7A7C, 0xAA13_03E0),
    (0x006F_7A80, 0x17FF_FF91),
    (0x006F_C4BC, 0xAA1F_03E0),
    (0x006F_C4C0, 0x9000_9581),
    (0x006F_C4C4, 0x9126_E021),
    (0x006F_C63C, 0x9121_43E0),
    (0x006F_C644, 0x5280_7802),
    (0x006F_C648, 0x9413_3266),
    (0x006F_C650, 0x5280_7800),
    (0x006F_C654, 0x5280_0201),
    (0x006F_C660, 0x97FB_E106),
    (0x006F_C664, 0xB400_00E0),
    (0x006F_C668, 0x9121_43E1),
    (0x006F_C66C, 0x5280_7802),
    (0x006F_C674, 0x9413_325B),
    (0x006F_C678, 0xAA13_03E0),
    (0x006F_C67C, 0x17FF_FF91),
    (0x00B8_96D4, 0xA940_2808),
    (0x00B8_96DC, 0xF907_0A68),
    (0x00B8_96E0, 0xF907_0E6A),
    (0x00B8_96E4, 0xF907_1268),
    (0x00B8_96E8, 0xF907_166A),
    (0x00B8_96EC, 0xF940_1549),
    (0x00B8_96F0, 0xAA08_03E0),
    (0x00B8_96F4, 0xD63F_0120),
    (0x00B5_C24C, 0xA942_A3E9),
    (0x00B5_C26C, 0xF901_1B29),
    (0x00B5_C270, 0xF901_1F28),
    (0x0070_539C, 0xD65F_03C0),
    (0x0070_53B4, 0xF941_D801),
    (0x0070_53BC, 0x97FF_C0BD),
    (0x0070_53EC, 0x5280_6800),
    (0x0070_53F0, 0x5280_0201),
    (0x0070_5400, 0x97FB_BD9E),
    (0x0070_540C, 0x5280_6802),
    (0x0070_5418, 0xF000_9521),
    (0x0070_541C, 0x9139_4021),
    (0x0070_5420, 0xAA13_03E0),
    (0x0070_5430, 0xD65F_03C0),
    (0x0070_57FC, 0xD65F_03C0),
    (0x0070_5824, 0xF941_D814),
    (0x0070_5830, 0x97FF_C020),
    (0x0070_58DC, 0x5280_6000),
    (0x0070_58E4, 0x5280_0201),
    (0x0070_5954, 0x97FB_BC49),
    (0x0070_5960, 0x5280_6002),
    (0x0070_596C, 0xF000_9521),
    (0x0070_5970, 0x9139_C021),
    (0x0070_5974, 0xAA13_03E0),
    (0x0070_5994, 0xD65F_03C0),
    (0x0070_A824, 0xF941_5000),
    (0x0070_A828, 0x1413_4E2D),
    (0x0070_A82C, 0xF941_5000),
    (0x0070_A830, 0x1413_4E2B),
    (0x0071_9B2C, 0x912F_83E8),
    (0x0071_9B30, 0x9100_42A0),
    (0x0071_9B34, 0x942E_E30E),
    (0x0071_9DE4, 0x3DC2_FBE0),
    (0x0071_9DFC, 0x3D82_C7E0),
    (0x0071_A024, 0xF901_C3FA),
    (0x0071_A028, 0xF942_9D19),
    (0x0071_A05C, 0xF905_8BF9),
    (0x0071_A4A4, 0xA940_2100),
    (0x0071_A50C, 0xF940_0D09),
    (0x0071_A510, 0x912C_43E8),
    (0x0071_A51C, 0xD63F_0120),
    (0x0071_A520, 0xF945_8BF4),
    (0x0071_A524, 0xF945_8FF9),
];

/// Exact upstream provenance of the separately owned Arc stored at raw chain
/// record `+0x510`.
///
/// The 0x9a0-byte tuner object owns primary and derived vectors of 0x38-byte
/// chain descriptors. `FUN_006aab08` copies each primary descriptor and
/// increments the Arc strong count at descriptor `+0x20`; `FUN_006cf9c4`
/// filters/moves complete accepted descriptors into the derived vector at
/// tuner `+0x7d0/+0x7d8/+0x7e0`. `FUN_007e9e30` clones that derived vector,
/// again preserving `+0x20/+0x28` and incrementing the Arc count. The callback
/// installed at tuner `+0x978` receives the cloned Vec in `x0`, iterates it via
/// `FUN_007dee4c`/`FUN_006b51cc`, and `FUN_007081cc` copies descriptor
/// `+0x20/+0x28` to raw record `+0x510/+0x518`.
///
/// `FUN_007e9c24` builds those descriptors directly from the source Arc vector:
/// it tests allocation `A+0x568`, increments the count at A, and writes A plus
/// `*(A+0x558)` to descriptor `+0x20/+0x28`. The specialized drop path
/// deallocates A as 0x570 bytes at alignment 0x10, joining this descriptor Arc
/// to the live Arc layout below. `FUN_00b5c168` constructs the 0x560-byte
/// payload, whose type metadata and exact debug label identify it as
/// `HashchainManager`. Item `+0x30` is a distinct `triggered::Listener`. Its
/// inner pointer is temporarily saved at `sp+0x48`, then consumed separately.
/// A byte Vec at `P+0x10` supplies the prestaged dispatch-table pointer and
/// `P+0x538` supplies its data half. Both possible code-3 provider hooks at
/// `P+0x230/+0x238` are no-ops, so this prestaged pair overwrites `sp+0x48`
/// and is installed as the local object's `+0x210/+0x218` dispatch pair. The
/// cloned dispatch-table contents and final method remain unresolved, so this
/// is still non-executable.
pub const BOSMINER_CHAIN_DESCRIPTOR_BYTES: u8 = 0x38;
pub const BOSMINER_CHAIN_DESCRIPTOR_ARC_OFFSET: u8 = 0x20;
pub const BOSMINER_CHAIN_DESCRIPTOR_ARC_COMPANION_OFFSET: u8 = 0x28;
pub const BOSMINER_TUNER_OBJECT_BYTES: u16 = 0x09A0;
pub const BOSMINER_TUNER_SOURCE_OWNER_OFFSET: u16 = 0x0950;
pub const BOSMINER_SOURCE_ARC_VEC_DATA_OFFSET: u16 = 0x06A8;
pub const BOSMINER_SOURCE_ARC_VEC_LEN_OFFSET: u16 = 0x06B0;
pub const BOSMINER_SOURCE_ARC_COMPANION_OFFSET: u16 = 0x0558;
pub const BOSMINER_TUNER_PRIMARY_DESCRIPTOR_VEC_CAP_OFFSET: u16 = 0x07B8;
pub const BOSMINER_TUNER_PRIMARY_DESCRIPTOR_VEC_DATA_OFFSET: u16 = 0x07C0;
pub const BOSMINER_TUNER_PRIMARY_DESCRIPTOR_VEC_LEN_OFFSET: u16 = 0x07C8;
pub const BOSMINER_TUNER_DERIVED_DESCRIPTOR_VEC_CAP_OFFSET: u16 = 0x07D0;
pub const BOSMINER_TUNER_DERIVED_DESCRIPTOR_VEC_DATA_OFFSET: u16 = 0x07D8;
pub const BOSMINER_TUNER_DERIVED_DESCRIPTOR_VEC_LEN_OFFSET: u16 = 0x07E0;
pub const BOSMINER_TUNER_CHAIN_CALLBACK_OFFSET: u16 = 0x0978;
pub const BOSMINER_TUNER_CHAIN_CALLBACK_FN_VA: u64 = 0x0070_A168;
pub const BOSMINER_TUNER_CHAIN_CALLBACK_DISPATCH_VA: u64 = 0x0066_2554;
pub const BOSMINER_CHAIN_DESCRIPTOR_BUILD_FN_VA: u64 = 0x007E_9C24;
pub const BOSMINER_CHAIN_DESCRIPTOR_COPY_FN_VA: u64 = 0x006A_AB08;
pub const BOSMINER_CHAIN_DESCRIPTOR_FILTER_FN_VA: u64 = 0x006C_F9C4;
pub const BOSMINER_CHAIN_DESCRIPTOR_CLONE_FN_VA: u64 = 0x007E_9E30;
pub const BOSMINER_CHAIN_DESCRIPTOR_COLLECT_FN_VA: u64 = 0x007D_EE4C;
pub const BOSMINER_CHAIN_DESCRIPTOR_TO_RAW_RECORD_FN_VA: u64 = 0x006B_51CC;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BosminerChainDescriptorArcResolutionBoundary {
    /// The raw record owns the exact live `Arc<HashchainManager>` allocation;
    /// the later reset pair is prestaged before a no-op hook in its payload.
    RawRecordOwnsLiveHashchainManagerDispatchPairIsPrestaged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerChainDescriptorArcEvidence {
    pub tuner_object_bytes: u16,
    pub descriptor_bytes: u8,
    pub descriptor_arc_offset: u8,
    pub descriptor_arc_companion_offset: u8,
    pub source_owner_offset: u16,
    pub source_arc_vec_data_offset: u16,
    pub source_arc_vec_len_offset: u16,
    pub source_arc_companion_offset: u16,
    pub descriptor_build_fn_va: u64,
    pub derived_vec_data_offset: u16,
    pub derived_vec_len_offset: u16,
    pub callback_offset: u16,
    pub callback_fn_va: u64,
    pub callback_dispatch_va: u64,
    pub raw_record_arc_offset: u16,
    pub concrete_arc_allocation_bytes: Option<u16>,
    pub concrete_arc_payload_bytes: Option<u16>,
    pub concrete_arc_payload_prefix_copy_bytes: Option<u16>,
    pub concrete_arc_payload_type_name: Option<&'static str>,
    pub concrete_arc_payload_type_vtable_va: Option<u64>,
    pub concrete_arc_payload_drop_fn_va: Option<u64>,
    pub concrete_arc_payload_debug_fn_va: Option<u64>,
    pub resolution_boundary: BosminerChainDescriptorArcResolutionBoundary,
}

pub const BOSMINER_CHAIN_DESCRIPTOR_ARC_EVIDENCE: BosminerChainDescriptorArcEvidence =
    BosminerChainDescriptorArcEvidence {
        tuner_object_bytes: BOSMINER_TUNER_OBJECT_BYTES,
        descriptor_bytes: BOSMINER_CHAIN_DESCRIPTOR_BYTES,
        descriptor_arc_offset: BOSMINER_CHAIN_DESCRIPTOR_ARC_OFFSET,
        descriptor_arc_companion_offset: BOSMINER_CHAIN_DESCRIPTOR_ARC_COMPANION_OFFSET,
        source_owner_offset: BOSMINER_TUNER_SOURCE_OWNER_OFFSET,
        source_arc_vec_data_offset: BOSMINER_SOURCE_ARC_VEC_DATA_OFFSET,
        source_arc_vec_len_offset: BOSMINER_SOURCE_ARC_VEC_LEN_OFFSET,
        source_arc_companion_offset: BOSMINER_SOURCE_ARC_COMPANION_OFFSET,
        descriptor_build_fn_va: BOSMINER_CHAIN_DESCRIPTOR_BUILD_FN_VA,
        derived_vec_data_offset: BOSMINER_TUNER_DERIVED_DESCRIPTOR_VEC_DATA_OFFSET,
        derived_vec_len_offset: BOSMINER_TUNER_DERIVED_DESCRIPTOR_VEC_LEN_OFFSET,
        callback_offset: BOSMINER_TUNER_CHAIN_CALLBACK_OFFSET,
        callback_fn_va: BOSMINER_TUNER_CHAIN_CALLBACK_FN_VA,
        callback_dispatch_va: BOSMINER_TUNER_CHAIN_CALLBACK_DISPATCH_VA,
        raw_record_arc_offset: BOSMINER_RAW_CHAIN_RECORD_ARC_OFFSET,
        concrete_arc_allocation_bytes: Some(BOSMINER_LIVE_CHAIN_ARC_ALLOCATION_BYTES),
        concrete_arc_payload_bytes: Some(BOSMINER_LIVE_CHAIN_ARC_PAYLOAD_BYTES),
        concrete_arc_payload_prefix_copy_bytes: Some(
            BOSMINER_LIVE_CHAIN_PAYLOAD_PREFIX_COPY_BYTES,
        ),
        concrete_arc_payload_type_name: Some(BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_NAME),
        concrete_arc_payload_type_vtable_va: Some(BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_VTABLE_VA),
        concrete_arc_payload_drop_fn_va: Some(BOSMINER_LIVE_CHAIN_PAYLOAD_DROP_FN_VA),
        concrete_arc_payload_debug_fn_va: Some(BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_FN_VA),
        resolution_boundary: BosminerChainDescriptorArcResolutionBoundary::RawRecordOwnsLiveHashchainManagerDispatchPairIsPrestaged,
    };

/// Pins the `HashchainManager` construction ABI, its 0x1f0-byte staged-prefix
/// copy, installation of the exact type vtable, the payload-relative drop call,
/// and the formatter's exact debug-label record.
pub const BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_PINS: [(u64, u32); 20] = [
    (0x00B8_A438, 0xF940_E2BA),
    (0x00B8_A570, 0xF906_EBFA),
    (0x00B8_A5D4, 0x9130_43E7),
    (0x00B8_A5E0, 0x9106_03E8),
    (0x00B8_A5F4, 0x97FF_46DD),
    (0x00B5_C184, 0xAA08_03F9),
    (0x00B5_C198, 0xAA07_03FC),
    (0x00B5_C1D8, 0xAA19_03E0),
    (0x00B5_C1DC, 0xAA1C_03E1),
    (0x00B5_C1E0, 0x5280_3E02),
    (0x00B5_C1F0, 0x9401_B37C),
    (0x00B8_A660, 0xB000_7388),
    (0x00B8_A664, 0x9105_E108),
    (0x00B8_A668, 0xF907_EA68),
    (0x00B8_B20C, 0x9100_42A0),
    (0x00B8_B210, 0x97FF_A7E1),
    (0x00B5_D370, 0x9115_200A),
    (0x00B5_D38C, 0xD000_74C9),
    (0x00B5_D390, 0x913C_C129),
    (0x00B5_D394, 0xA900_23E9),
];

/// Exact instructions for the 0x9a0-byte tuner copy, callback installation,
/// 0x38-byte descriptor Arc clones, callback ABI, iterator handoff and final
/// descriptor `+0x20/+0x28` to raw `+0x510/+0x518` copy, including the
/// source live-Arc builder and its exact allocation/drop layout.
pub const BOSMINER_CHAIN_DESCRIPTOR_ARC_LINEAGE_PINS: [(u64, u32); 117] = [
    (0x0067_8A60, 0x5281_3402),
    (0x0064_D52C, 0x5282_6A08),
    (0x0064_D534, 0x5281_3402),
    (0x0064_D538, 0x8B08_0260),
    (0x0064_D540, 0x9415_EEA8),
    (0x0067_92EC, 0xB000_0488),
    (0x0067_92F0, 0x9105_A108),
    (0x0067_9300, 0xF904_BE68),
    (0x006A_AB20, 0xF940_0838),
    (0x006A_AB24, 0x5280_0708),
    (0x006A_ABA8, 0xA942_358E),
    (0x006A_ABB0, 0xC85F_7DCF),
    (0x006A_ABB8, 0xC811_7DD0),
    (0x006A_ABBC, 0x35FF_FFB1),
    (0x006A_ABC8, 0xAD40_0580),
    (0x006A_ABD8, 0xAD00_05E0),
    (0x006A_ABDC, 0xA902_35EE),
    (0x006A_AC7C, 0xF902_0A95),
    (0x006A_AC80, 0xF902_0E98),
    (0x006A_AC98, 0x9400_934B),
    (0x006A_AD1C, 0x3D81_0900),
    (0x006A_AD20, 0xF902_1909),
    (0x0066_23F4, 0xF948_2E68),
    (0x0066_2400, 0xF943_F109),
    (0x0066_2404, 0xF943_ED00),
    (0x0066_2408, 0xF944_BD17),
    (0x0066_240C, 0x9B0A_0121),
    (0x0066_2410, 0x9140_07E8),
    (0x0066_2420, 0x9406_1E84),
    (0x0066_2534, 0x9140_07E0),
    (0x0066_2538, 0x9140_0BE1),
    (0x0066_2544, 0x910F_4000),
    (0x0066_2548, 0x9120_4021),
    (0x0066_2550, 0xAA15_03E3),
    (0x0066_2554, 0xD63F_02E0),
    (0x007E_9E9C, 0x5280_070A),
    (0x007E_9EA4, 0xA942_2DAC),
    (0x007E_9EA8, 0xC85F_7D8E),
    (0x007E_9EB0, 0xC810_7D8F),
    (0x007E_9EB4, 0x35FF_FFB0),
    (0x007E_9EC0, 0xAD40_05A0),
    (0x007E_9ED4, 0xA902_2DCC),
    (0x007E_9EE0, 0xA900_0268),
    (0x007E_9EE8, 0xF900_0A68),
    (0x0070_A178, 0xA940_A009),
    (0x0070_A17C, 0x5280_070A),
    (0x0070_A190, 0x9B0A_2508),
    (0x0070_A1A0, 0xF940_000A),
    (0x0070_A1C8, 0x9100_E3E0),
    (0x0070_A1CC, 0x9403_5320),
    (0x007D_EF30, 0x9100_83E0),
    (0x007D_EF34, 0x9101_23E1),
    (0x007D_EF38, 0x97FB_58A5),
    (0x006B_5228, 0xAD40_0341),
    (0x006B_5230, 0x3DC0_0B42),
    (0x006B_5234, 0x9100_E35A),
    (0x006B_5278, 0x3DC1_67E0),
    (0x006B_5280, 0x3DC1_6FE2),
    (0x006B_528C, 0x3D81_7FE0),
    (0x006B_529C, 0x3D81_87E2),
    (0x006B_52A0, 0xF903_13E8),
    (0x006B_5328, 0x9117_C3E0),
    (0x006B_5340, 0x9401_4BA3),
    (0x0070_8338, 0xAD40_0660),
    (0x0070_8344, 0x3DC0_0A60),
    (0x0070_834C, 0x3D81_4700),
    (0x0067_91BC, 0xF944_AA68),
    (0x0067_91CC, 0xF943_5509),
    (0x0067_91D0, 0xF943_5908),
    (0x0067_91D4, 0x8B08_0D28),
    (0x0067_91D8, 0xA912_23E9),
    (0x0067_91E8, 0x9405_C28F),
    (0x007E_9C54, 0x3955_A328),
    (0x007E_9C58, 0x7100_051F),
    (0x007E_9C64, 0xF942_AF28),
    (0x007E_9C68, 0xC85F_7F29),
    (0x007E_9C6C, 0x9100_052A),
    (0x007E_9C70, 0xC80B_7F2A),
    (0x007E_9C74, 0x35FF_FFAB),
    (0x007E_9C80, 0xF900_1FF9),
    (0x007E_9C94, 0xA901_A7FF),
    (0x007E_9C98, 0xA902_A7FF),
    (0x007E_9CA4, 0xF900_23E8),
    (0x007E_9CC4, 0x3CC3_83E2),
    (0x007E_9CD8, 0x3D80_0802),
    (0x007E_9CF4, 0x3955_A348),
    (0x007E_9CF8, 0x7100_051F),
    (0x007E_9D00, 0xF942_AF48),
    (0x007E_9D04, 0xC85F_7F49),
    (0x007E_9D08, 0x9100_052A),
    (0x007E_9D0C, 0xC80B_7F4A),
    (0x007E_9D10, 0x35FF_FFAB),
    (0x007E_9D1C, 0xA903_A3FA),
    (0x007E_9D54, 0x9B19_0288),
    (0x007E_9D5C, 0x3CC3_83E0),
    (0x007E_9D70, 0xAD00_8101),
    (0x007E_9D74, 0x3D80_0102),
    (0x006A_AC18, 0x9B16_6B60),
    (0x006A_AC20, 0xF842_0C08),
    (0x006A_AC3C, 0x9412_58BD),
    (0x006A_ACC0, 0x9B16_56E0),
    (0x006A_ACC8, 0xF842_0C08),
    (0x006A_ACE4, 0x9412_5893),
    (0x00B8_A5F8, 0x5280_0028),
    (0x00B8_A5FC, 0x9100_42A0),
    (0x00B8_A600, 0x9106_03E1),
    (0x00B8_A608, 0x5280_AC02),
    (0x00B8_A60C, 0x3D80_0360),
    (0x00B8_A618, 0x5280_AE00),
    (0x00B8_A61C, 0x5280_0201),
    (0x00B8_A620, 0x97E9_A916),
    (0x00B8_A628, 0x9130_43E1),
    (0x00B8_A62C, 0x5280_AE02),
    (0x00B8_A634, 0x9400_FA6B),
    (0x00B4_1140, 0x5280_AE01),
    (0x00B4_1148, 0x5280_0202),
    (0x00B4_1150, 0x17EA_CE4B),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BosminerHashchainLifecycleReceiverResolutionBoundary {
    /// `HashchainManager` and `triggered::Listener` occupy separate item/state
    /// lanes. The listener inner is only temporary at `sp+0x48`; a prestaged
    /// pair overwrites it and supplies local `+0x210/+0x218`. Its table pointer
    /// came from a cloned byte Vec whose provider-object lineage is exact
    /// through materialization and B879 forwarding. The runtime contents,
    /// runtime provider selection, Vec bytes, and concrete slot targets have
    /// not been recovered. Slot `+0x28` is not the last cloned-table dispatch:
    /// the same pair is reloaded and slot `+0x48` follows.
    PayloadPrestageProviderCandidatesLineageResolvedRuntimeSelectionBytesAndFinalMethodRemainDynamic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerHashchainLifecycleReceiverEvidence {
    pub raw_record_bytes: u16,
    pub raw_record_arc_offset: u16,
    pub arc_build_fn_va: u64,
    pub arc_allocation_bytes: u16,
    pub arc_align: u8,
    pub arc_header_bytes: u8,
    pub arc_payload_bytes: u16,
    pub arc_payload_type_name: &'static str,
    pub arc_payload_type_vtable_va: u64,
    pub enabled_allocation_offset: u16,
    pub item_triggered_listener_offset: u8,
    pub item_payload_offset: u16,
    pub listener_type_name: &'static str,
    pub listener_clone_fn_va: u64,
    pub listener_next_id_offset: u8,
    pub outer_working_listener_offset: u16,
    pub outer_retained_payload_offset: u16,
    pub outer_nested_future_offset: u16,
    pub outer_cloned_listener_offset: u16,
    pub outer_retained_payload_for_nested_offset: u16,
    pub state_listener_input_offset: u16,
    pub state_payload_input_offset: u16,
    pub state_retained_payload_offset: u16,
    pub state_reused_listener_self_slot_offset: u16,
    pub state_dispatch_self_slot_offset: u16,
    pub stack_listener_inner_offset: u8,
    pub payload_hook_trait_data_offset: u16,
    pub payload_hook_trait_vtable_offset: u16,
    pub payload_hook_method_slot: u8,
    pub payload_hook_dispatch_va: u64,
    pub payload_hook_method_vas: [u64; 2],
    pub payload_hook_is_noop: bool,
    pub prestage_vec_source_offset: u8,
    pub prestage_vec_clone_fn_va: u64,
    pub prestage_vec_clone_dispatch_va: u64,
    pub prestaged_data_offset: u16,
    pub stack_prestaged_data_offset: u16,
    pub stack_prestaged_dispatch_table_offset: u16,
    pub stack_listener_inner_overwrite_va: u64,
    pub local_object_prefix_copy_bytes: u16,
    pub local_object_trait_data_offset: u16,
    pub local_object_dispatch_table_offset: u16,
    pub method_slot: u8,
    pub method_dispatch_va: u64,
    pub concrete_dispatch_data: Option<u64>,
    pub concrete_dispatch_table_va: Option<u64>,
    pub concrete_method_va: Option<u64>,
    pub resolution_boundary: BosminerHashchainLifecycleReceiverResolutionBoundary,
}

pub const BOSMINER_HASHCHAIN_LIFECYCLE_RECEIVER_EVIDENCE:
    BosminerHashchainLifecycleReceiverEvidence = BosminerHashchainLifecycleReceiverEvidence {
    raw_record_bytes: BOSMINER_RAW_CHAIN_RECORD_BYTES,
    raw_record_arc_offset: BOSMINER_RAW_CHAIN_RECORD_ARC_OFFSET,
    arc_build_fn_va: BOSMINER_LIVE_CHAIN_ARC_BUILD_FN_VA,
    arc_allocation_bytes: BOSMINER_LIVE_CHAIN_ARC_ALLOCATION_BYTES,
    arc_align: BOSMINER_LIVE_CHAIN_ARC_ALIGN,
    arc_header_bytes: BOSMINER_LIVE_CHAIN_ARC_HEADER_BYTES,
    arc_payload_bytes: BOSMINER_LIVE_CHAIN_ARC_PAYLOAD_BYTES,
    arc_payload_type_name: BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_NAME,
    arc_payload_type_vtable_va: BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_VTABLE_VA,
    enabled_allocation_offset: BOSMINER_LIVE_CHAIN_ARC_ENABLED_OFFSET,
    item_triggered_listener_offset: BOSMINER_LIVE_CHAIN_ITEM_TRIGGERED_LISTENER_OFFSET,
    item_payload_offset: BOSMINER_LIVE_CHAIN_ITEM_PAYLOAD_OFFSET,
    listener_type_name: BOSMINER_TRIGGERED_LISTENER_TYPE_NAME,
    listener_clone_fn_va: BOSMINER_TRIGGERED_LISTENER_CLONE_FN_VA,
    listener_next_id_offset: BOSMINER_TRIGGERED_LISTENER_NEXT_ID_OFFSET,
    outer_working_listener_offset: BOSMINER_LIFECYCLE_OUTER_WORKING_LISTENER_OFFSET,
    outer_retained_payload_offset: BOSMINER_LIFECYCLE_OUTER_RETAINED_PAYLOAD_OFFSET,
    outer_nested_future_offset: BOSMINER_LIFECYCLE_OUTER_NESTED_FUTURE_OFFSET,
    outer_cloned_listener_offset: BOSMINER_LIFECYCLE_OUTER_CLONED_LISTENER_OFFSET,
    outer_retained_payload_for_nested_offset:
        BOSMINER_LIFECYCLE_OUTER_RETAINED_PAYLOAD_FOR_NESTED_OFFSET,
    state_listener_input_offset: BOSMINER_LIFECYCLE_STATE_LISTENER_INPUT_OFFSET,
    state_payload_input_offset: BOSMINER_LIFECYCLE_STATE_INPUT_PAYLOAD_OFFSET,
    state_retained_payload_offset: BOSMINER_LIFECYCLE_STATE_RETAINED_PAYLOAD_OFFSET,
    state_reused_listener_self_slot_offset:
        BOSMINER_LIFECYCLE_STATE_REUSED_LISTENER_SELF_SLOT_OFFSET,
    state_dispatch_self_slot_offset: BOSMINER_LIFECYCLE_STATE_DISPATCH_SELF_SLOT_OFFSET,
    stack_listener_inner_offset: BOSMINER_LIFECYCLE_STACK_LISTENER_INNER_OFFSET,
    payload_hook_trait_data_offset: BOSMINER_LIFECYCLE_PAYLOAD_HOOK_TRAIT_DATA_OFFSET,
    payload_hook_trait_vtable_offset: BOSMINER_LIFECYCLE_PAYLOAD_HOOK_TRAIT_VTABLE_OFFSET,
    payload_hook_method_slot: BOSMINER_LIFECYCLE_PAYLOAD_HOOK_METHOD_SLOT,
    payload_hook_dispatch_va: BOSMINER_LIFECYCLE_PAYLOAD_HOOK_DISPATCH_VA,
    payload_hook_method_vas: BOSMINER_CODE3_LIFECYCLE_HOOK_METHOD_VAS,
    payload_hook_is_noop: true,
    prestage_vec_source_offset: BOSMINER_LIFECYCLE_PRESTAGE_VEC_SOURCE_OFFSET,
    prestage_vec_clone_fn_va: BOSMINER_LIFECYCLE_PRESTAGE_VEC_CLONE_FN_VA,
    prestage_vec_clone_dispatch_va: BOSMINER_LIFECYCLE_PRESTAGE_VEC_CLONE_DISPATCH_VA,
    prestaged_data_offset: BOSMINER_LIFECYCLE_PRESTAGED_DATA_OFFSET,
    stack_prestaged_data_offset: BOSMINER_LIFECYCLE_STACK_PRESTAGED_DATA_OFFSET,
    stack_prestaged_dispatch_table_offset:
        BOSMINER_LIFECYCLE_STACK_PRESTAGED_DISPATCH_TABLE_OFFSET,
    stack_listener_inner_overwrite_va: BOSMINER_LIFECYCLE_STACK_LISTENER_INNER_OVERWRITE_VA,
    local_object_prefix_copy_bytes: BOSMINER_LIFECYCLE_LOCAL_OBJECT_PREFIX_COPY_BYTES,
    local_object_trait_data_offset: BOSMINER_LIFECYCLE_LOCAL_OBJECT_TRAIT_DATA_OFFSET,
    local_object_dispatch_table_offset: BOSMINER_LIFECYCLE_LOCAL_OBJECT_DISPATCH_TABLE_OFFSET,
    method_slot: BOSMINER_LIFECYCLE_RESET_METHOD_SLOT,
    method_dispatch_va: BOSMINER_LIFECYCLE_RESET_METHOD_DISPATCH_VA,
    concrete_dispatch_data: None,
    concrete_dispatch_table_va: None,
    concrete_method_va: None,
    resolution_boundary: BosminerHashchainLifecycleReceiverResolutionBoundary::PayloadPrestageProviderCandidatesLineageResolvedRuntimeSelectionBytesAndFinalMethodRemainDynamic,
};

/// Pins the raw-record/Arc distinction, the distinct listener and manager item
/// lanes, the `triggered::Listener` clone, the manager payload handoff, the
/// local per-chain object construction, the listener-slot-to-self overwrite,
/// the separate listener consumption, Vec-based result prestaging, the
/// `P+0x230/+0x238` no-op hook, the prestaged overwrite into local
/// `+0x210/+0x218`, and the final reset-phase indirect dispatch. These prove
/// layout and control flow only; they do not identify the cloned dispatch
/// table's slot target.
pub const BOSMINER_HASHCHAIN_LIFECYCLE_RECEIVER_LINEAGE_PINS: [(u64, u32); 92] = [
    (0x007A_01AC, 0xA941_2269),
    (0x007A_0230, 0xF81A_6F08),
    (0x007A_0250, 0xA918_63F7),
    (0x007A_0268, 0x9401_3217),
    (0x007E_CAFC, 0x3955_A2A8),
    (0x007E_CB00, 0x7100_051F),
    (0x007E_CB08, 0xA941_5019),
    (0x007E_CB10, 0xF940_0288),
    (0x007E_CB14, 0x3940_033A),
    (0x007E_CB1C, 0xAA14_03E0),
    (0x007E_CB20, 0x940F_422F),
    (0x007E_CB3C, 0x9100_42A8),
    (0x007E_CB44, 0xA905_07E0),
    (0x007E_CB48, 0x5280_DC00),
    (0x007E_CB4C, 0x5280_0201),
    (0x007E_CB50, 0xF900_43E8),
    (0x007E_CB70, 0x9100_83E1),
    (0x007E_CB74, 0x5280_DC02),
    (0x007E_CB80, 0x940F_7118),
    (0x00BB_D3DC, 0xF940_0000),
    (0x00BB_D3E0, 0xC85F_7C08),
    (0x00BB_D3F4, 0x9101_2008),
    (0x00BB_D3F8, 0xC85F_FD01),
    (0x00BB_D408, 0xD65F_03C0),
    (0x00B5_C1B8, 0xA902_8BE1),
    (0x00B5_C24C, 0xA942_A3E9),
    (0x00B5_C26C, 0xF901_1B29),
    (0x00B5_C270, 0xF901_1F28),
    (0x0071_7968, 0xF940_3268),
    (0x0071_7970, 0x3DC0_0E60),
    (0x0071_7974, 0xF900_2A68),
    (0x0071_797C, 0x3D80_1260),
    (0x0071_799C, 0xF844_0D09),
    (0x0071_79A0, 0xF940_0917),
    (0x0071_79A8, 0xB500_3349),
    (0x0071_8010, 0xAA08_03E0),
    (0x0071_8014, 0x9412_94F2),
    (0x0071_8018, 0xF901_EA60),
    (0x0071_801C, 0xF901_EE61),
    (0x0071_8020, 0xF901_FE77),
    (0x0071_99AC, 0xF941_C669),
    (0x0071_99B8, 0xF941_B26B),
    (0x0071_99BC, 0xF941_B66A),
    (0x0071_99C0, 0xF901_BA69),
    (0x0071_99D4, 0xF901_D26B),
    (0x0071_99D8, 0xF901_D66A),
    (0x0071_99DC, 0xF901_DE68),
    (0x0071_9ACC, 0xF941_BA69),
    (0x0071_9AE0, 0x9108_C129),
    (0x0071_9AE4, 0xF908_EFE9),
    (0x0071_9AFC, 0xF941_BA75),
    (0x0071_9DFC, 0x3D82_C7E0),
    (0x0071_9E68, 0xF940_E2B7),
    (0x0071_9F84, 0xF905_1BF7),
    (0x0071_A020, 0xF941_BA68),
    (0x0071_A028, 0xF942_9D19),
    (0x0071_A04C, 0xF941_D272),
    (0x0071_A050, 0xF941_D677),
    (0x0071_A05C, 0xF905_8BF9),
    (0x0071_A19C, 0xF900_27F2),
    (0x0071_A240, 0xF900_23E9),
    (0x0071_A2D8, 0xF940_27F6),
    (0x0071_A488, 0xF948_EFE8),
    (0x0071_A4A4, 0xA940_2100),
    (0x0071_A50C, 0xF940_0D09),
    (0x0071_A510, 0x912C_43E8),
    (0x0071_A51C, 0xD63F_0120),
    (0x0071_A520, 0xF945_8BF4),
    (0x0071_A524, 0xF945_8FF9),
    (0x0071_A528, 0xF900_27F4),
    (0x0071_AA54, 0x5280_0028),
    (0x0071_AA58, 0x9100_4260),
    (0x0071_AA60, 0x5280_3C02),
    (0x0071_AA68, 0xA900_7274),
    (0x0071_AACC, 0xA944_27E8),
    (0x0071_AAD8, 0xF901_0E79),
    (0x0071_AAE0, 0xF901_0A69),
    (0x0071_AB2C, 0xAA13_03E9),
    (0x0071_AB3C, 0xF901_D673),
    (0x0071_AB58, 0xF901_D269),
    (0x0071_AB60, 0xF941_0D28),
    (0x0071_AB64, 0xF941_0920),
    (0x0071_AB68, 0xF940_0D08),
    (0x0071_AB6C, 0xD63F_0100),
    (0x0071_AE18, 0xF941_D268),
    (0x0071_AE2C, 0x910E_E277),
    (0x0071_AE3C, 0xF901_DE68),
    (0x0071_B088, 0xF940_02E8),
    (0x0071_B08C, 0xF941_0D09),
    (0x0071_B090, 0xF941_0900),
    (0x0071_B094, 0xF940_1528),
    (0x0071_B098, 0xD63F_0100),
];

/// Exact cloned-table dispatch after local `+0x210/+0x218` construction.
/// Slot `+0x28` at `0x0071b098` is not terminal: after that result is polled
/// at returned `+0x18` and dropped, stock reloads the same pair from
/// `[X19+0x3a0]` (`X22`) and dispatches slot `+0x48`. Each Ready/Ok check is
/// `TBZ W0,#0`; failures use immediate `4` then `5`. Slot `+0x50` is a later
/// `LDP` from overwritten state `+0x3c0`, not this pair. Slot `+0x20` uses the
/// distinct local pair at `+0x220/+0x228`. Concrete method VAs stay `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerClonedTableDispatchStep {
    pub slot: u8,
    pub object_load_va: u64,
    pub table_load_va: u64,
    pub data_load_va: u64,
    pub slot_load_va: u64,
    pub slot_load_word: u32,
    pub blr_va: u64,
    pub result_data_state_offset: u16,
    pub result_vtable_state_offset: u16,
    pub poll_slot: u8,
    pub poll_blr_va: u64,
    pub fail_imm: u8,
    pub fail_imm_va: u64,
    pub fail_branch_va: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerClonedTableTwoSlotSequenceEvidence {
    pub local_data_offset: u16,
    pub local_table_offset: u16,
    pub self_slot_offset: u16,
    pub first: BosminerClonedTableDispatchStep,
    pub second: BosminerClonedTableDispatchStep,
    pub refused_slot_0x50_source_offset: u16,
    pub refused_slot_0x50_ldp_va: u64,
    pub refused_slot_0x50_load_va: u64,
    pub distinct_pair_data_offset: u16,
    pub distinct_pair_table_offset: u16,
    pub distinct_pair_slot: u8,
    pub distinct_pair_blr_va: u64,
    pub concrete_method_va: Option<u64>,
}

pub const BOSMINER_CLONED_TABLE_FIRST_STEP: BosminerClonedTableDispatchStep =
    BosminerClonedTableDispatchStep {
        slot: 0x28,
        object_load_va: 0x0071_B088,
        table_load_va: 0x0071_B08C,
        data_load_va: 0x0071_B090,
        slot_load_va: 0x0071_B094,
        slot_load_word: 0xF940_1528,
        blr_va: 0x0071_B098,
        result_data_state_offset: 0x03D8,
        result_vtable_state_offset: 0x03E0,
        poll_slot: 0x18,
        poll_blr_va: 0x0071_B0B0,
        fail_imm: 4,
        fail_imm_va: 0x0071_B0B8,
        fail_branch_va: 0x0071_DD34,
    };

pub const BOSMINER_CLONED_TABLE_SECOND_STEP: BosminerClonedTableDispatchStep =
    BosminerClonedTableDispatchStep {
        slot: 0x48,
        object_load_va: 0x0071_B118,
        table_load_va: 0x0071_B11C,
        data_load_va: 0x0071_B120,
        slot_load_va: 0x0071_B124,
        slot_load_word: 0xF940_2528,
        blr_va: 0x0071_B128,
        result_data_state_offset: 0x03B8,
        result_vtable_state_offset: 0x03C0,
        poll_slot: 0x18,
        poll_blr_va: 0x0071_B13C,
        fail_imm: 5,
        fail_imm_va: 0x0071_B144,
        fail_branch_va: 0x0071_DD40,
    };

pub const BOSMINER_CLONED_TABLE_TWO_SLOT_SEQUENCE_EVIDENCE:
    BosminerClonedTableTwoSlotSequenceEvidence = BosminerClonedTableTwoSlotSequenceEvidence {
    local_data_offset: 0x0210,
    local_table_offset: 0x0218,
    self_slot_offset: 0x03A0,
    first: BOSMINER_CLONED_TABLE_FIRST_STEP,
    second: BOSMINER_CLONED_TABLE_SECOND_STEP,
    refused_slot_0x50_source_offset: 0x03C0,
    refused_slot_0x50_ldp_va: 0x0071_B218,
    refused_slot_0x50_load_va: 0x0071_B21C,
    distinct_pair_data_offset: 0x0220,
    distinct_pair_table_offset: 0x0228,
    distinct_pair_slot: 0x20,
    distinct_pair_blr_va: 0x0071_B800,
    concrete_method_va: None,
};

pub const BOSMINER_CLONED_TABLE_TWO_SLOT_SEQUENCE_PINS: [(u64, u32); 40] = [
    (0x0071_AAF0, 0x910E_8276),
    (0x0071_B088, 0xF940_02E8),
    (0x0071_B08C, 0xF941_0D09),
    (0x0071_B090, 0xF941_0900),
    (0x0071_B094, 0xF940_1528),
    (0x0071_B098, 0xD63F_0100),
    (0x0071_B09C, 0xF901_EE60),
    (0x0071_B0A4, 0xF901_F261),
    (0x0071_B0A8, 0xF940_0C28),
    (0x0071_B0B0, 0xD63F_0100),
    (0x0071_B0B4, 0x3600_0060),
    (0x0071_B0B8, 0x5280_0088),
    (0x0071_B0BC, 0x1400_0B1E),
    (0x0071_B0C0, 0xF941_F275),
    (0x0071_B0C4, 0xF941_EE79),
    (0x0071_B0EC, 0x97FB_6664),
    (0x0071_B118, 0xF940_02C8),
    (0x0071_B11C, 0xF941_0D09),
    (0x0071_B120, 0xF941_0900),
    (0x0071_B124, 0xF940_2528),
    (0x0071_B128, 0xD63F_0100),
    (0x0071_B12C, 0xF901_DE60),
    (0x0071_B130, 0xF901_E261),
    (0x0071_B134, 0xF940_0C28),
    (0x0071_B13C, 0xD63F_0100),
    (0x0071_B140, 0x3600_0060),
    (0x0071_B144, 0x5280_00A8),
    (0x0071_B148, 0x1400_0AFE),
    (0x0071_B14C, 0xF941_E275),
    (0x0071_B150, 0xF941_DE77),
    (0x0071_B178, 0x97FB_6641),
    (0x0071_B210, 0xF941_E268),
    (0x0071_B218, 0xA943_A500),
    (0x0071_B21C, 0xF940_2928),
    (0x0071_B220, 0xD63F_0100),
    (0x0071_B7F0, 0xF940_02C8),
    (0x0071_B7F4, 0xF941_1509),
    (0x0071_B7F8, 0xF941_1100),
    (0x0071_B7FC, 0xF940_1128),
    (0x0071_B800, 0xD63F_0100),
];

pub const BOSMINER_HASHCHAIN_RESET_LOG_DESCRIPTOR_FILE_OFF: u64 = 0x015A_0358;
pub const BOSMINER_HASHCHAIN_INIT_LOG_DESCRIPTOR_FILE_OFF: u64 = 0x015A_03A8;
pub const BOSMINER_HASHCHAIN_FAN_WAIT_LOG_DESCRIPTOR_FILE_OFF: u64 = 0x015A_00B0;
pub const BOSMINER_HASHCHAIN_FANS_OK_LOG_DESCRIPTOR_FILE_OFF: u64 = 0x015A_0100;
pub const BOSMINER_HASHCHAIN_RETRY_LOG_DESCRIPTOR_FILE_OFF: u64 = 0x0159_FCC8;
pub const BOSMINER_HASHCHAIN_START_FAILED_LOG_DESCRIPTOR_FILE_OFF: u64 = 0x0159_FD00;
pub const BOSMINER_HASHCHAIN_LOG_PREFIX_VA: u64 = 0x0131_24FB;
pub const BOSMINER_HASHCHAIN_RESET_LOG_MESSAGE_VA: u64 = 0x0131_27C4;
pub const BOSMINER_HASHCHAIN_INIT_LOG_MESSAGE_VA: u64 = 0x0131_27DA;
pub const BOSMINER_HASHCHAIN_FAN_WAIT_LOG_MESSAGE_VA: u64 = 0x012E_E18F;
pub const BOSMINER_HASHCHAIN_FANS_OK_LOG_MESSAGE_VA: u64 = 0x0131_26C3;
pub const BOSMINER_HASHCHAIN_RETRY_LOG_MESSAGE_VA: u64 = 0x0131_2501;
pub const BOSMINER_HASHCHAIN_START_FAILED_LOG_MESSAGE_VA: u64 = 0x012E_7960;
pub const BOSMINER_HASHCHAIN_SOURCE_VA: u64 = 0x0131_251E;
pub const BOSMINER_HASHCHAIN_SOURCE: &[u8] =
    b"/build/source/open/bosminer/bosminer-backend/src/hashchain.rs";
pub const BOSMINER_MINER_SOURCE_VA: u64 = 0x0131_23FC;
pub const BOSMINER_MINER_SOURCE: &[u8] =
    b"/build/source/open/bosminer/bosminer-backend/src/miner.rs";
pub const BOSMINER_HASHCHAIN_RESET_LOG_MESSAGE: &[u8] = b": Resetting hash board";
pub const BOSMINER_HASHCHAIN_INIT_LOG_MESSAGE: &[u8] = b": Initializing hashchain";
pub const BOSMINER_HASHCHAIN_FAN_WAIT_LOG_MESSAGE: &[u8] = b": Waiting for fans to spin up...";
pub const BOSMINER_HASHCHAIN_FANS_OK_LOG_MESSAGE: &[u8] = b": Fans OK";
pub const BOSMINER_HASHCHAIN_RETRY_LOG_MESSAGE: &[u8] = b": Retrying hashboard start...";
pub const BOSMINER_HASHCHAIN_START_FAILED_LOG_MESSAGE: &[u8] = b": Start failed: ";

/// Exact platform-stage order inside the per-hashboard stock future. A false
/// fan snapshot takes the one-second pending cadence and rechecks; a true
/// snapshot emits `Fans OK` and permits the later init dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BosminerHashchainPlatformStage {
    ResetDispatch,
    FanReadinessGateOneSecondPendingCadence,
    InitDispatchWithTenSecondTimeout,
}

pub const BOSMINER_HASHCHAIN_PLATFORM_ORDER: [BosminerHashchainPlatformStage; 3] = [
    BosminerHashchainPlatformStage::ResetDispatch,
    BosminerHashchainPlatformStage::FanReadinessGateOneSecondPendingCadence,
    BosminerHashchainPlatformStage::InitDispatchWithTenSecondTimeout,
];

/// Exact serde-visible layout recovered from the custody-pinned stock ELF.
/// This proves the `FanStatus` field names and value offsets accepted by its
/// serializer; it does not prove which field the hashchain snapshot helper
/// reads from its larger retained watch value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BosminerFanStatusValueKind {
    U64,
    Bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerFanStatusField {
    pub name: &'static [u8],
    pub name_va: u64,
    pub value_offset: u8,
    pub value_kind: BosminerFanStatusValueKind,
}

pub const BOSMINER_FAN_STATUS_SERIALIZER_FN_VA: u64 = 0x00B7_FD68;
pub const BOSMINER_FAN_STATUS_TYPE_NAME_VA: u64 = 0x0139_0364;
pub const BOSMINER_FAN_STATUS_TYPE_NAME: &[u8] = b"FanStatus";
pub const BOSMINER_FAN_STATUS_FIELDS: [BosminerFanStatusField; 5] = [
    BosminerFanStatusField {
        name: b"num_fans_at_ok_speed",
        name_va: 0x0139_036D,
        value_offset: 0x00,
        value_kind: BosminerFanStatusValueKind::U64,
    },
    BosminerFanStatusField {
        name: b"rpm_of_slowest_fan",
        name_va: 0x0139_0381,
        value_offset: 0x08,
        value_kind: BosminerFanStatusValueKind::U64,
    },
    BosminerFanStatusField {
        name: b"fan_rpm_ok",
        name_va: 0x0139_0393,
        value_offset: 0x10,
        value_kind: BosminerFanStatusValueKind::Bool,
    },
    BosminerFanStatusField {
        name: b"required_fans_above_min_speed",
        name_va: 0x0139_039D,
        value_offset: 0x11,
        value_kind: BosminerFanStatusValueKind::Bool,
    },
    BosminerFanStatusField {
        name: b"all_fans_stopped",
        name_va: 0x012F_9FAB,
        value_offset: 0x12,
        value_kind: BosminerFanStatusValueKind::Bool,
    },
];

/// Instruction pins joining every field name, its length, and value offset to
/// the exact five-field `FanStatus` serializer call.
pub const BOSMINER_FAN_STATUS_SERIALIZER_PINS: [(u64, u32); 24] = [
    (BOSMINER_FAN_STATUS_SERIALIZER_FN_VA, 0xD102_43FF),
    (0x00B7_FD6C, 0x9100_480A), // value +0x12
    (0x00B7_FD70, 0x5280_020D), // all_fans_stopped length 16
    (0x00B7_FD74, 0x9100_440C), // value +0x11
    (0x00B7_FD94, 0xD000_3BCA),
    (0x00B7_FD98, 0x913E_AD4A), // all_fans_stopped
    (0x00B7_FDAC, 0x5280_03AA), // required_fans... length 29
    (0x00B7_FDB0, 0x9100_2009), // value +0x08
    (0x00B7_FDB8, 0xB000_408C),
    (0x00B7_FDBC, 0x910E_758C), // required_fans_above_min_speed
    (0x00B7_FDC0, 0x9100_400B), // value +0x10
    (0x00B7_FDC4, 0xB000_408A),
    (0x00B7_FDC8, 0x910E_4D4A), // fan_rpm_ok
    (0x00B7_FDD8, 0x5280_014C), // fan_rpm_ok length 10
    (0x00B7_FDDC, 0x5280_024D), // rpm_of_slowest_fan length 18
    (0x00B7_FDE0, 0xB000_4081),
    (0x00B7_FDE4, 0x910D_9021), // FanStatus
    (0x00B7_FDE8, 0xB000_4083),
    (0x00B7_FDEC, 0x910D_B463), // num_fans_at_ok_speed
    (0x00B7_FDF0, 0xB000_4087),
    (0x00B7_FDF4, 0x910E_04E7), // rpm_of_slowest_fan
    (0x00B7_FDFC, 0x5280_0122), // FanStatus length 9
    (0x00B7_FE00, 0x5280_0284), // num_fans_at_ok_speed length 20
    (0x00B7_FE10, 0x941D_71CE), // five-field struct serializer
];

/// Eight identical resolved-monitor-config observations in the frozen S19k
/// departure log. These are runtime observations from that exact captured
/// configuration, not a universal Braiins default or DCENT_OS policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerS19kObservedFanPolicy {
    pub resolved_config_observations: u8,
    pub fixed_speed_percent: u8,
    pub min_fans: u8,
    pub min_fan_rpm: u16,
    pub rpm_epsilon: u16,
    pub immersion_mode: bool,
    pub min_fan_speed_percent: Option<u8>,
    pub max_fan_speed_percent: Option<u8>,
    pub max_fans: u8,
    pub pause_cooldown_fan_speed_percent: u8,
    pub pause_cooldown_is_indefinite: bool,
    pub start_cooldown_fan_speed_percent: u8,
}

pub const BOSMINER_S19K_DEPARTURE_FAN_POLICY: BosminerS19kObservedFanPolicy =
    BosminerS19kObservedFanPolicy {
        resolved_config_observations: 8,
        fixed_speed_percent: 100,
        min_fans: 0,
        min_fan_rpm: 2_000,
        rpm_epsilon: 600,
        immersion_mode: false,
        min_fan_speed_percent: None,
        max_fan_speed_percent: None,
        max_fans: 4,
        pause_cooldown_fan_speed_percent: 100,
        pause_cooldown_is_indefinite: true,
        start_cooldown_fan_speed_percent: 100,
    };

/// Inclusive terminal failure tail in the outer start wrapper. The retained
/// error is copied into the future output and returned from this range.
pub const BOSMINER_HASHCHAIN_TERMINAL_FAILURE_TAIL_START_VA: u64 = 0x0071_8060;
pub const BOSMINER_HASHCHAIN_TERMINAL_FAILURE_TAIL_END_VA: u64 = 0x0071_819C;

/// Every direct `BL` in the terminal failure tail. These are cleanup/drop
/// helpers; the bounded tail contains no `BLR` hardware dispatch. This proves
/// only that the local wrapper has no reset/APW rollback call, not that a
/// higher service layer cannot react after the error is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerHashchainTerminalFailureCall {
    pub call_va: u64,
    pub target_va: u64,
}

pub const BOSMINER_HASHCHAIN_TERMINAL_FAILURE_CALLS: [BosminerHashchainTerminalFailureCall; 4] = [
    BosminerHashchainTerminalFailureCall {
        call_va: 0x0071_808C,
        target_va: 0x00BB_D410,
    },
    BosminerHashchainTerminalFailureCall {
        call_va: 0x0071_80B0,
        target_va: 0x00B4_1604,
    },
    BosminerHashchainTerminalFailureCall {
        call_va: 0x0071_8100,
        target_va: 0x0072_78DC,
    },
    BosminerHashchainTerminalFailureCall {
        call_va: 0x0071_8160,
        target_va: 0x0127_0C78,
    },
];

/// Evidence-safe stock outer-wrapper failure dispositions. A retry waits ten
/// seconds and re-enters the inner start future, whose next attempt owns the
/// reset dispatch. Exhaustion instead returns the retained error without a
/// local reset/APW rollback dispatch in the outer terminal tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BosminerHashchainStartFailureDisposition {
    RetryAfterTenSecondsThenNewInnerReset,
    TerminalReturnRetainedErrorNoLocalHardwareRollback,
}

pub const BOSMINER_HASHCHAIN_START_FAILURE_POLICY: [BosminerHashchainStartFailureDisposition; 2] = [
    BosminerHashchainStartFailureDisposition::RetryAfterTenSecondsThenNewInnerReset,
    BosminerHashchainStartFailureDisposition::TerminalReturnRetainedErrorNoLocalHardwareRollback,
];

/// One interval measured from the frozen 2026-08-21 stock S19k log. These are
/// observations, not executor delay targets or safety ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerS19kLifecycleTimingEnvelope {
    pub samples: u8,
    pub min_us: u32,
    pub max_us: u32,
}

/// Successful stock lifecycle observations retained before the office unit
/// went offline. Eight complete dual-chain cycles plus one partial chain-3
/// cycle yielded 17 per-chain observations and no start/init/retry error log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerS19kLifecycleCapture {
    pub complete_dual_chain_cycles: u8,
    pub chain3_partial_cycles: u8,
    pub successful_per_chain_observations: u8,
    /// The retained log has a preceding `PSU: Enable` for both resets in each
    /// complete cycle. The partial chain-3 cycle has no retained enable line.
    pub power_enable_to_reset: BosminerS19kLifecycleTimingEnvelope,
    pub reset_to_init: BosminerS19kLifecycleTimingEnvelope,
    pub init_to_discovered: BosminerS19kLifecycleTimingEnvelope,
    pub discovered_to_baud: BosminerS19kLifecycleTimingEnvelope,
    pub baud_to_watchdog_start: BosminerS19kLifecycleTimingEnvelope,
}

pub const BOSMINER_S19K_DEPARTURE_LIFECYCLE_CAPTURE: BosminerS19kLifecycleCapture =
    BosminerS19kLifecycleCapture {
        complete_dual_chain_cycles: 8,
        chain3_partial_cycles: 1,
        successful_per_chain_observations: 17,
        power_enable_to_reset: BosminerS19kLifecycleTimingEnvelope {
            samples: 16,
            min_us: 2_060_449,
            max_us: 2_071_063,
        },
        reset_to_init: BosminerS19kLifecycleTimingEnvelope {
            samples: 17,
            min_us: 2_001_614,
            max_us: 2_003_610,
        },
        init_to_discovered: BosminerS19kLifecycleTimingEnvelope {
            samples: 17,
            min_us: 1_717_210,
            max_us: 1_728_356,
        },
        discovered_to_baud: BosminerS19kLifecycleTimingEnvelope {
            samples: 17,
            min_us: 3_759,
            max_us: 4_987,
        },
        baud_to_watchdog_start: BosminerS19kLifecycleTimingEnvelope {
            samples: 17,
            min_us: 2_032_260,
            max_us: 2_042_962,
        },
    };

/// Backend init errors retained in the exact hashchain/BM1366 cluster.
/// Descriptions are deliberately evidence-safe and do not invent recovery
/// semantics that were not present in the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerHashchainInitErrorEvidence {
    pub code: &'static str,
    pub description: &'static str,
}

pub const BOSMINER_HASHCHAIN_INIT_ERROR_EVIDENCE: [BosminerHashchainInitErrorEvidence; 5] = [
    BosminerHashchainInitErrorEvidence {
        code: "{ERR:I2}",
        description: "too many chips",
    },
    BosminerHashchainInitErrorEvidence {
        code: "{ERR:I3}",
        description: "no chips",
    },
    BosminerHashchainInitErrorEvidence {
        code: "{ERR:I4}",
        description: "reset detect timeout",
    },
    BosminerHashchainInitErrorEvidence {
        code: "{ERR:I5}",
        description: "not enough chips",
    },
    BosminerHashchainInitErrorEvidence {
        code: "{ERR:I8}",
        description: "initialization timeout",
    },
];

/// Delay before each stock start attempt. Attempt one is immediate; attempts
/// two through four follow a failed attempt by the exact ten-second wait.
pub const fn bosminer_hashchain_start_attempt_delays_ns() -> [u64; 4] {
    [0, 10_000_000_000, 10_000_000_000, 10_000_000_000]
}

/// Additional stock-tail register descriptors and helper identities recovered
/// from the custody-pinned ELF. These are static-analysis anchors, not names
/// recovered from stripped Rust symbols.
pub const BOSMINER_BM1366_STOCK_REG0C_DESCRIPTOR_FILE_OFF: u64 = 0x00EE_7F50;
pub const BOSMINER_BM1366_STOCK_REG0C_REGISTER: u8 = 0x0C;
pub const BOSMINER_BM1366_STOCK_UART_RELAY_DESCRIPTOR_FILE_OFF: u64 = 0x00EE_7EB0;
pub const BOSMINER_BM1366_STOCK_UART_RELAY_REGISTER: u8 = 0x2C;
pub const BOSMINER_BM1366_STOCK_IO_VECTOR_FN_VA: u64 = 0x0091_B0D8;
pub const BOSMINER_BM1366_STOCK_RELAY_VECTOR_FN_VA: u64 = 0x0091_AD28;
pub const BOSMINER_BM1366_STOCK_RELAY_ITER_NEXT_FN_VA: u64 = 0x0092_3AAC;
pub const BOSMINER_BM1366_STOCK_FINALIZE_POLL_VTABLE_FILE_OFF: u64 = 0x015B_83B0;
pub const BOSMINER_BM1366_STOCK_FINALIZE_POLL_VTABLE: [u64; 4] =
    [0x008D_850C, 0x160, 8, 0x008D_FE6C];
pub const BOSMINER_BM1366_STOCK_REG0C_SPAN: u16 = u16::MAX;
pub const BOSMINER_BM1366_STOCK_REG0C_ENABLE_BIT: u32 = 0x8000_0000;
pub const BOSMINER_BM1366_STOCK_IO_DRIVER_FIXED_BITS: u32 = 0x0211_0111;
pub const BOSMINER_BM1366_STOCK_UART_RELAY_FLAGS: u32 = 0x0000_0003;
pub const BOSMINER_BM1366_STOCK_UART_RELAY_GAP_BIAS: u16 = 14;

/// One caller-indexed register-`0x0c` write in the tail of stock slot `+0x30`.
/// `wire_address` is the generic destination conversion
/// `address_gap * chip_index` proven at `FUN_00bf31c8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerBm1366StockReg0cStep {
    pub chip_index: u16,
    pub wire_address: u8,
    pub value: u32,
}

/// Build the exact register-`0x0c` value/address schedule expressed by
/// `FUN_008dd63c`: `step=floor(0xffff/asic_count)`, then, for every ascending
/// chip index, `0x80000000 | step*index`.
pub fn bosminer_bm1366_stock_reg0c_plan(
    address_gap: u8,
    asic_count: u16,
) -> Result<Vec<BosminerBm1366StockReg0cStep>, &'static str> {
    if address_gap == 0 || asic_count == 0 {
        return Err("stock BM1366 register-0x0c plan requires nonzero address gap/count");
    }
    let last_address = u32::from(address_gap) * u32::from(asic_count - 1);
    if last_address > u32::from(u8::MAX) {
        return Err("stock BM1366 register-0x0c destination exceeds one-byte wire address");
    }
    let value_step = u32::from(BOSMINER_BM1366_STOCK_REG0C_SPAN) / u32::from(asic_count);
    Ok((0..asic_count)
        .map(|chip_index| BosminerBm1366StockReg0cStep {
            chip_index,
            wire_address: (u32::from(address_gap) * u32::from(chip_index)) as u8,
            value: BOSMINER_BM1366_STOCK_REG0C_ENABLE_BIT | value_step * u32::from(chip_index),
        })
        .collect())
}

/// The stock IoDriver packer keeps all other fields fixed and inserts a
/// caller-provided four-bit value into semantic register bits 15:12.
pub fn bosminer_bm1366_stock_io_driver_value(high_nibble: u8) -> Result<u32, &'static str> {
    if high_nibble > 0x0F {
        return Err("stock BM1366 IoDriver field is a four-bit value");
    }
    Ok(BOSMINER_BM1366_STOCK_IO_DRIVER_FIXED_BITS | (u32::from(high_nibble) << 12))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerBm1366StockIoDriverDomainStep {
    pub voltage_domain: u16,
    pub chip_index: u16,
    pub wire_address: u8,
    pub value: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerBm1366StockUartRelayDomainStep {
    pub voltage_domain: u16,
    pub first_chip_index: u16,
    pub first_wire_address: u8,
    pub second_chip_index: u16,
    pub second_wire_address: u8,
    pub gap_count: u16,
    pub value: u32,
}

/// Ordered stock slot-`+0x28` register evidence. The method performs the
/// broadcast writes first, all `io_driver_domains` next, and all
/// `uart_relay_domains` last. It contains no sleeps between those domain
/// writes. The two IoDriver nibbles are caller fields at object offsets
/// `0x240` and `0x241`; this function does not invent them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BosminerBm1366StockFinalizePlan {
    pub analog_mux_broadcast_value: u32,
    pub io_driver_broadcast_value: u32,
    pub io_driver_domains: Vec<BosminerBm1366StockIoDriverDomainStep>,
    pub uart_relay_domains: Vec<BosminerBm1366StockUartRelayDomainStep>,
}

/// Flatten `FUN_008dc828`/`FUN_0091b0d8`/`FUN_0091ad28` for a divisible
/// voltage-domain geometry. This is exact for the S19k `2/77/7` inputs and
/// deliberately refuses geometries whose final stock iterator would exercise
/// an unsigned partial-domain edge case.
pub fn bosminer_bm1366_stock_finalize_plan(
    address_gap: u8,
    asic_count: u16,
    asics_per_voltage_domain: u16,
    broadcast_io_high_nibble: u8,
    domain_io_high_nibble: u8,
) -> Result<BosminerBm1366StockFinalizePlan, &'static str> {
    if address_gap == 0 || asic_count == 0 || asics_per_voltage_domain == 0 {
        return Err("stock BM1366 finalize plan requires nonzero geometry");
    }
    if asic_count % asics_per_voltage_domain != 0 {
        return Err("stock BM1366 typed finalize plan refuses a partial voltage domain");
    }
    let last_wire_address = u32::from(address_gap) * u32::from(asic_count - 1);
    if last_wire_address > u32::from(u8::MAX) {
        return Err("stock BM1366 finalize destination exceeds one-byte wire address");
    }

    let io_driver_broadcast_value =
        bosminer_bm1366_stock_io_driver_value(broadcast_io_high_nibble)?;
    let domain_io_value = bosminer_bm1366_stock_io_driver_value(domain_io_high_nibble)?;
    let domain_count = asic_count / asics_per_voltage_domain;
    let mut io_driver_domains = Vec::with_capacity(usize::from(domain_count));
    let mut uart_relay_domains = Vec::with_capacity(usize::from(domain_count));

    for from_chain_end in 1..=domain_count {
        let voltage_domain = domain_count - from_chain_end;
        let first_chip_index = asic_count - from_chain_end * asics_per_voltage_domain;
        let second_chip_index = asic_count - (from_chain_end - 1) * asics_per_voltage_domain - 1;
        let first_wire_address = (u32::from(address_gap) * u32::from(first_chip_index)) as u8;
        let second_wire_address = (u32::from(address_gap) * u32::from(second_chip_index)) as u8;
        let gap_count = from_chain_end
            .checked_mul(asics_per_voltage_domain)
            .and_then(|value| value.checked_add(BOSMINER_BM1366_STOCK_UART_RELAY_GAP_BIAS))
            .ok_or("stock BM1366 UART-relay gap count overflowed")?;

        io_driver_domains.push(BosminerBm1366StockIoDriverDomainStep {
            voltage_domain,
            chip_index: second_chip_index,
            wire_address: second_wire_address,
            value: domain_io_value,
        });
        uart_relay_domains.push(BosminerBm1366StockUartRelayDomainStep {
            voltage_domain,
            first_chip_index,
            first_wire_address,
            second_chip_index,
            second_wire_address,
            gap_count,
            value: (u32::from(gap_count) << 16) | BOSMINER_BM1366_STOCK_UART_RELAY_FLAGS,
        });
    }

    Ok(BosminerBm1366StockFinalizePlan {
        analog_mux_broadcast_value: BOSMINER_BM1366_STOCK_REGISTER_FACTS.analog_mux_value,
        io_driver_broadcast_value,
        io_driver_domains,
        uart_relay_domains,
    })
}
pub const BOSMINER_FASTUART_BAUD_SELECTOR_FN_VA: u64 = 0x0091_B024;
pub const BOSMINER_FASTUART_REG_PACK_FN_VA: u64 = 0x0084_ED8C;
pub const BOSMINER_FASTUART_REG_DESCRIPTOR_VA: u64 = 0x012E_8010;
pub const BOSMINER_FASTUART_REG_DESCRIPTOR_FILE_OFF: u64 = 0x00EE_8010;
pub const BOSMINER_SET_BAUD_RATE_LOG_DESCRIPTOR_FILE_OFF: u64 = 0x015A_B508;
/// Packed UART `51 09 00 28` (set_config FastUART) hits in `bosminer.unpacked`.
pub const BOSMINER_SETCFG_51_09_00_28_HITS: usize = 0;
/// First-LOAD `BL` to [`BOSMINER_UART_BE4_SEND_FN_VA`]. Ticket-mask / send-self / MiscCtrl.
pub const BOSMINER_UART_BE4_SEND_BL_HITS: usize = 4;
pub const BOSMINER_UART_BE4_SEND_BL_VA: [u64; 4] =
    [0x0083_6C3C, 0x008A_2300, 0x008A_255C, 0x008B_4504];
/// Sole code caller of host termios `FUN_00bbe3d4`.
pub const BOSMINER_HOST_TERMIOS_CALLER_FN_VA: u64 = 0x008F_E748;
pub const BOSMINER_HOST_TERMIOS_FN_VA: u64 = 0x00BB_E3D4;
/// : first-LOAD `MOVZ #0xC6C0` sites that complete `3_000_000` with `MOVK #0x2D,LSL#16`.
pub const BOSMINER_HOST_3M_BAUD: u32 = 3_000_000;
pub const BOSMINER_HOST_3M_MOVZ_HITS: usize = 4;
pub const BOSMINER_HOST_3M_MOVZ_VA: [u64; 4] = [0x00BB_E5BC, 0x00BC_00EC, 0x00BC_1F94, 0x00BC_7020];
pub const BOSMINER_HOST_3M_MOVZ_INSN: [u32; 4] =
    [0x5298_D808, 0x5298_D802, 0x5298_D802, 0x5298_D808];
/// Termios compare: `MOVZ/MOVK` are consecutive. AML open is `+0x20`.
pub const BOSMINER_HOST_3M_TERMIOS_MOVK_VA: u64 = 0x00BB_E5C0;
pub const BOSMINER_HOST_3M_TERMIOS_MOVK_INSN: u32 = 0x72A0_05A8;
pub const BOSMINER_AML_OPEN_3M_MOVK_VA: u64 = 0x00BC_1FB4;
pub const BOSMINER_AML_OPEN_3M_MOVK_INSN: u32 = 0x72A0_05A2;
/// Linux ARM `B3000000` = `0010015` octal = `0x100D`.
pub const BOSMINER_B3000000_SPEED_T: u32 = 0x100D;
pub const BOSMINER_B3000000_MOVZ_HITS: usize = 3;
pub const BOSMINER_B3000000_MOVZ_VA: [u64; 3] = [0x00BB_E5CC, 0x00BC_2918, 0x00BC_7130];
pub const BOSMINER_B3000000_MOVZ_INSN: [u32; 3] = [0x5282_01A1, 0x5282_01A2, 0x5282_01A1];
pub const BOSMINER_ANTMINER_AML_RS: &[u8] = b"open/utils-rs/serial-driver/src/antminer_aml.rs";
pub const BOSMINER_ANTMINER_AML_RS_FILE_OFF: u64 = 0x00F9_2558;
pub const BOSMINER_SETTING_SPEED_STR: &[u8] = b"setting speed";
pub const BOSMINER_NIX_TERMIOS_RS: &[u8] = b"nix-0.26.4/src/sys/termios.rs";
pub const BOSMINER_NIX_TERMIOS_RS_FILE_OFF: u64 = 0x00F9_B584;
/// `open/utils-rs/serial-driver/src/antminer_aml.rs` — host tty speed, not chip.
pub const BOSMINER_ANTMINER_AML_RS_VA: u64 = 0x0139_2558;
/// `packed_struct-0.10.1/src/packing.rs` — generic Command packer crate.
/// : this is how bosminer builds set_config at runtime (no ASCII `set_config`).
pub const BOSMINER_PACKED_STRUCT_PACKING_RS_VA: u64 = 0x0131_BE45;
/// File offset of `values were not written correctly to register`.
pub const BOSMINER_WRITE_VERIFY_STR_FILE_OFF: u64 = 0x00F2_0197;
pub const BOSMINER_WRITE_VERIFY_STR_VA: u64 = 0x0132_0197;
/// `command.rs` packed_struct 4-byte value pack (alloc 4, bit fields 0x10/8/4).
/// : the only first-LOAD `BL` sites are inside `FUN_008b1b98` /
/// `FUN_008b2b34` (bm1398.rs loc table). Not an exclusive S19k AML packer.
pub const BOSMINER_PACKED_STRUCT_PACK_FN_VA: u64 = 0x008A_8D28;
/// Historical name.  loc table attributes this FN to
/// `bosminer-am2-s17/src/hashchain/bm1398.rs`, not `command.rs`.
pub const BOSMINER_COMMAND_RS_WRITE_FN_VA: u64 = 0x008B_1B98;
/// Same loc table as the write FN (`bm1398.rs`). 0 `BL` / 0 `B`.
pub const BOSMINER_BM1398_READ_FN_VA: u64 = 0x008B_2B34;
/// `BL FUN_008a8d28` sites: write+0x1e8, read+0x260, read+0x3b4.
pub const BOSMINER_PACK_BL_HITS: usize = 3;
pub const BOSMINER_PACK_BL_VA: [u64; 3] = [0x008B_1D80, 0x008B_2D94, 0x008B_2EE8];
pub const BOSMINER_WRITE_BL_HITS: usize = 0;
pub const BOSMINER_READ_FN_BL_HITS: usize = 0;
/// Second-LOAD rustc loc record: `fn` then filename `&str`.
pub const BOSMINER_WRITE_LOC_PTR_FILE_OFF: u64 = 0x015B_4590;
pub const BOSMINER_WRITE_LOC_PTR_VA: u64 = 0x019C_4590;
pub const BOSMINER_READ_LOC_PTR_FILE_OFF: u64 = 0x015B_46A8;
pub const BOSMINER_READ_LOC_PTR_VA: u64 = 0x019C_46A8;
pub const BOSMINER_BM1398_RS_LOC_STR: &[u8] =
    b"open/bosminer/bosminer-am2-s17/src/hashchain/bm1398.rs";
pub const BOSMINER_BM1398_RS_LOC_STR_FILE_OFF: u64 = 0x00F2_1135;
pub const BOSMINER_BM1398_RS_LOC_STR_VA: u64 = 0x0132_1135;
pub const BOSMINER_BM1398_RS_LOC_STR_LEN: u32 = 0x36;
/// : hashchain/bm1366.rs loc FNs. None `BL` PACK/WRITE/BE4.
pub const BOSMINER_BM1366_RS_LOC_STR: &[u8] =
    b"open/bosminer/bosminer-am2-s17/src/hashchain/bm1366.rs";
pub const BOSMINER_BM1366_RS_LOC_STR_FILE_OFF: u64 = 0x00F2_32F5;
pub const BOSMINER_BM1366_RS_LOC_STR_VA: u64 = 0x0132_32F5;
pub const BOSMINER_BM1366_RS_LOC_STR_LEN: u32 = 54;
/// First BM1366 method source record and its following Rust future vtable.
/// `FUN_008dc828` belongs to the preceding `pic0xfe.rs:44` future.
pub const BOSMINER_BM1366_FIRST_METHOD_FN_VA: u64 = 0x008D_CFBC;
pub const BOSMINER_BM1366_FIRST_METHOD_LOC_FILE_OFF: u64 = 0x015B_7EB0;
pub const BOSMINER_BM1366_FIRST_METHOD_VTABLE_FILE_OFF: u64 = 0x015B_7EC8;
pub const BOSMINER_BM1366_FIRST_METHOD_LOC_LINE: u32 = 93;
pub const BOSMINER_BM1366_FIRST_METHOD_LOC_COL: u32 = 64;
pub const BOSMINER_BM1366_LOC_FNS: [u64; 6] = [
    0x008D_CFBC,
    0x008D_D4C8,
    0x008D_D63C,
    0x008D_E274,
    0x008D_E430,
    0x008D_E984,
];
///  correction: both `0x28=0x0600000F` pack sites are legacy S17
/// families. The first poll is `bm1397.rs:103`; the clone is `bm1396.rs:101`.
/// Neither value is admissible as a BM1366/S19k FastUART contract.
pub const BOSMINER_LEGACY_S17_REG28_VALUE: u32 = 0x0600_000F;
pub const BOSMINER_BM1397_REG28_POLL_VA: u64 = 0x008D_F138;
pub const BOSMINER_BM1397_REG28_LOC_FILE_OFF: u64 = 0x015B_80A8;
pub const BOSMINER_BM1397_REG28_VTABLE_FILE_OFF: u64 = 0x015B_80C0;
pub const BOSMINER_BM1397_REG28_LOC_LINE: u32 = 103;
pub const BOSMINER_BM1397_REG28_LOC_COL: u32 = 64;
pub const BOSMINER_BM1397_REG28_MOVZ_VA: u64 = 0x008D_F2B0;
pub const BOSMINER_BM1397_REG28_MOVZ_INSN: u32 = 0x5280_0500;
pub const BOSMINER_BM1397_REG28_VAL_MOVZ_VA: u64 = 0x008D_F2A8;
pub const BOSMINER_BM1397_REG28_VAL_MOVZ_INSN: u32 = 0x5280_01E1;
pub const BOSMINER_BM1397_REG28_VAL_MOVK_VA: u64 = 0x008D_F2B4;
pub const BOSMINER_BM1397_REG28_VAL_MOVK_INSN: u32 = 0x72A0_C001;
pub const BOSMINER_BM1397_REG28_BL_VA: u64 = 0x008D_F2B8;
pub const BOSMINER_BM1397_REG28_BL_INSN: u32 = 0x940C_4FF5;
pub const BOSMINER_LEGACY_REG28_PACK_FN_VA: u64 = 0x00BF_328C;
pub const BOSMINER_LEGACY_REG28_PACK_REV_VA: u64 = 0x00BF_32C0;
pub const BOSMINER_LEGACY_REG28_PACK_REV_INSN: u32 = 0x5AC0_0AA8;
pub const BOSMINER_BM1396_REG28_POLL_VA: u64 = 0x0084_6384;
pub const BOSMINER_BM1396_REG28_LOC_FILE_OFF: u64 = 0x015A_C768;
pub const BOSMINER_BM1396_REG28_VTABLE_FILE_OFF: u64 = 0x015A_C780;
pub const BOSMINER_BM1396_REG28_LOC_LINE: u32 = 101;
pub const BOSMINER_BM1396_REG28_LOC_COL: u32 = 64;
pub const BOSMINER_BM1396_REG28_VAL_MOVZ_VA: u64 = 0x0084_64F4;
pub const BOSMINER_BM1396_REG28_VAL_MOVZ_INSN: u32 = 0x5280_01E1;
pub const BOSMINER_BM1396_REG28_MOVZ_VA: u64 = 0x0084_64FC;
pub const BOSMINER_BM1396_REG28_MOVZ_INSN: u32 = 0x5280_0500;
pub const BOSMINER_BM1396_REG28_VAL_MOVK_VA: u64 = 0x0084_6500;
pub const BOSMINER_BM1396_REG28_VAL_MOVK_INSN: u32 = 0x72A0_C001;
pub const BOSMINER_BM1396_REG28_BL_VA: u64 = 0x0084_6504;
pub const BOSMINER_BM1396_REG28_BL_INSN: u32 = 0x940E_B362;
pub const BOSMINER_LEGACY_REG28_PACK_CALL_HITS: usize = 2;
/// Packed-struct enum dispatch used by those methods (`LDRB [X0,#0x70]` + `BLR X8`).
pub const BOSMINER_BM1366_PACKED_DISPATCH_FN_VA: u64 = 0x008D_823C;
pub const BOSMINER_BM1366_PACKED_DISPATCH_LDRB_VA: u64 = 0x008D_8244;
pub const BOSMINER_BM1366_PACKED_DISPATCH_LDRB_INSN: u32 = 0x3941_C008;
pub const BOSMINER_BM1366_PACKED_DISPATCH_BLR_VA: u64 = 0x008D_826C;
pub const BOSMINER_BM1366_PACKED_DISPATCH_BLR_INSN: u32 = 0xD63F_0100;
/// Same `LDRB [X0,#0x70]` at the bm1398 packer entry+0xc.
pub const BOSMINER_PACK_LDRB_VA: u64 = 0x008A_8D34;
pub const BOSMINER_BM1366_DISPATCH_BL_HITS: usize = 48;
pub const BOSMINER_BM1366_DISPATCH_BL_IN_LOC_CLUSTER: usize = 31;
/// : `+0x70` tag. Only 3 and 4 are taken; other tags RET.
pub const BOSMINER_BM1366_DISPATCH_TAG_OFF: u8 = 0x70;
pub const BOSMINER_BM1366_DISPATCH_TAG3: u8 = 3;
pub const BOSMINER_BM1366_DISPATCH_TAG4: u8 = 4;
pub const BOSMINER_BM1366_DISPATCH_CMP3_VA: u64 = 0x008D_824C;
pub const BOSMINER_BM1366_DISPATCH_CMP3_INSN: u32 = 0x7100_0D1F;
pub const BOSMINER_BM1366_DISPATCH_BEQ3_VA: u64 = 0x008D_8250;
pub const BOSMINER_BM1366_DISPATCH_BEQ3_INSN: u32 = 0x5400_0220;
pub const BOSMINER_BM1366_DISPATCH_CMP4_VA: u64 = 0x008D_8254;
pub const BOSMINER_BM1366_DISPATCH_CMP4_INSN: u32 = 0x7100_111F;
/// Tag 4: `LDP X21, X20, [X19, #0x78]` fat pointer, then `LDR X8,[X20]` `BLR X8`.
pub const BOSMINER_BM1366_DISPATCH_LDP_VA: u64 = 0x008D_825C;
pub const BOSMINER_BM1366_DISPATCH_LDP_INSN: u32 = 0xA947_D275;
pub const BOSMINER_BM1366_DISPATCH_FAT_PTR_OFF: u8 = 0x78;
pub const BOSMINER_BM1366_DISPATCH_LDR_V0_VA: u64 = 0x008D_8260;
pub const BOSMINER_BM1366_DISPATCH_LDR_V0_INSN: u32 = 0xF940_0288;
/// Tag 3: `LDR X8, [X8, #0x18]` then `BLR X8` (`0x8d82d0`).
pub const BOSMINER_BM1366_DISPATCH_TAG3_SLOT_LDR_VA: u64 = 0x008D_82CC;
pub const BOSMINER_BM1366_DISPATCH_TAG3_SLOT_LDR_INSN: u32 = 0xF940_0D08;
pub const BOSMINER_BM1366_DISPATCH_TAG3_BLR_VA: u64 = 0x008D_82D0;
pub const BOSMINER_BM1366_DISPATCH_VTABLE_SLOT: u8 = 0x18;
/// `CBZ X1` then exclusive-load/atomic. Rust Arc/refcount, not UART.
pub const BOSMINER_DISPATCH_ARC_LIKE_FN_VA: u64 = 0x011F_2764;
pub const BOSMINER_DISPATCH_ARC_LIKE_CBZ_INSN: u32 = 0xB400_0241;
pub const BOSMINER_DISPATCH_DROP_GLUE_FN_VA: u64 = 0x005F_4A7C;
/// : one `+0x78` fat-ptr vtable installed by `FUN_008ddb0c`.
/// `drop=0`, `size=0x30`, `align=8`, method `+0x18` = `FUN_011de81c`.
pub const BOSMINER_FAT_PTR_VTABLE_VA: u64 = 0x019C_7900;
pub const BOSMINER_FAT_PTR_VTABLE_FILE_OFF: u64 = 0x015B_7900;
pub const BOSMINER_FAT_PTR_VTABLE_DROP: u64 = 0;
pub const BOSMINER_FAT_PTR_VTABLE_SIZE: u64 = 0x30;
pub const BOSMINER_FAT_PTR_VTABLE_ALIGN: u64 = 8;
pub const BOSMINER_FAT_PTR_VTABLE_METHOD_VA: u64 = 0x011D_E81C;
pub const BOSMINER_FAT_PTR_VTABLE_ADRP_VA: u64 = 0x008D_DB0C;
pub const BOSMINER_FAT_PTR_VTABLE_ADD_VA: u64 = 0x008D_DB10;
pub const BOSMINER_FAT_PTR_VTABLE_ADD_INSN: u32 = 0x9124_0129;
pub const BOSMINER_FAT_PTR_STP_VA: u64 = 0x008D_DB58;
pub const BOSMINER_FAT_PTR_STP_INSN: u32 = 0xA907_A67F;
pub const BOSMINER_PSU_PROTOCOL_RS: &[u8] =
    b"open/bosminer/bosminer-am2-s17/src/hardware/antminer/psu_protocol.rs";
pub const BOSMINER_PSU_PROTOCOL_RS_FILE_OFF: u64 = 0x00F2_31EE;
pub const BOSMINER_PSU_PROTOCOL_RS_VA: u64 = 0x0132_31EE;
/// `FUN_011de81c` head: `MOV X8,X0` then `BR X4` trampoline.
pub const BOSMINER_VTABLE_METHOD_MOV_INSN: u32 = 0xAA00_03E8;
pub const BOSMINER_VTABLE_METHOD_BR_VA: u64 = 0x011D_E834;
pub const BOSMINER_VTABLE_METHOD_BR_INSN: u32 = 0xD61F_0080;
/// `packing.rs` string adjacent to AML `command.rs` @ `0x131e720`.
pub const BOSMINER_AML_PACKING_RS_VA: u64 = 0x0131_E7BC;
/// `open/utils-rs/serial-driver/src/antminer_aml.rs` open path (exclusive AML host UART).
pub const BOSMINER_ANTMINER_AML_OPEN_FN_VA: u64 = 0x00BC_1F28;
/// Hashchain/session caller of that AML open.
pub const BOSMINER_AML_SERIAL_SESSION_FN_VA: u64 = 0x008F_8018;
/// : `FUN_008dfe6c` loc is `hashchain.rs:112:32`, not `psu_protocol.rs`.
pub const BOSMINER_HASHCHAIN_RS_LOC_STR: &[u8] = b"open/bosminer/bosminer-am2-s17/src/hashchain.rs";
pub const BOSMINER_HASHCHAIN_RS_LOC_STR_FILE_OFF: u64 = 0x00F2_3527;
pub const BOSMINER_HASHCHAIN_RS_LOC_STR_VA: u64 = 0x0132_3527;
pub const BOSMINER_HASHCHAIN_RS_LOC_STR_LEN: u32 = 0x2F;
pub const BOSMINER_HASHCHAIN_PLUS78_FN_VA: u64 = 0x008D_FE6C;
pub const BOSMINER_HASHCHAIN_PLUS78_LOC_FILE_OFF: u64 = 0x015B_83C8;
pub const BOSMINER_HASHCHAIN_PLUS78_LOC_LINE: u32 = 112;
pub const BOSMINER_HASHCHAIN_PLUS78_LOC_COL: u32 = 32;
/// `STP X8,X9,[X19,#0x78]` — data=`*(*(obj+0x20))+0x10`, meta=`obj+0x158`.
pub const BOSMINER_HASHCHAIN_PLUS78_STP_VA: u64 = 0x008D_FF48;
pub const BOSMINER_HASHCHAIN_PLUS78_STP_INSN: u32 = 0xA907_A668;
pub const BOSMINER_HASHCHAIN_PLUS78_INNER_LDR_VA: u64 = 0x008D_FF24;
pub const BOSMINER_HASHCHAIN_PLUS78_INNER_LDR_INSN: u32 = 0xF940_126C;
pub const BOSMINER_HASHCHAIN_PLUS78_DEREF_VA: u64 = 0x008D_FF34;
pub const BOSMINER_HASHCHAIN_PLUS78_DEREF_INSN: u32 = 0xF940_018A;
pub const BOSMINER_HASHCHAIN_PLUS78_ADD158_VA: u64 = 0x008D_FF3C;
pub const BOSMINER_HASHCHAIN_PLUS78_ADD158_INSN: u32 = 0x9105_6269;
pub const BOSMINER_HASHCHAIN_PLUS78_ADD10_VA: u64 = 0x008D_FF44;
pub const BOSMINER_HASHCHAIN_PLUS78_ADD10_INSN: u32 = 0x9100_4148;
pub const BOSMINER_HASHCHAIN_PLUS78_INLINE_OFF: u16 = 0x158;
pub const BOSMINER_HASHCHAIN_PACKED_OBJ_OFF: u16 = 0x68;
pub const BOSMINER_HASHCHAIN_PACKED_X0_ADD_VA: u64 = 0x008D_FF4C;
pub const BOSMINER_HASHCHAIN_PACKED_X0_ADD_INSN: u32 = 0x9101_A260;
/// Sibling packed-tag helper: same `LDRB [X0,#0x70]`, CMP#2/#3.
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_FN_VA: u64 = 0x008D_5F9C;
/// `MOV X19,X0` so later `LDP [X19,#0x10]` is relative to the packed object.
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_MOV_X19_VA: u64 = 0x008D_5FAC;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_MOV_X19_INSN: u32 = 0xAA00_03F3;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_LDRB_VA: u64 = 0x008D_5FA8;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_CMP2_VA: u64 = 0x008D_5FB4;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_CMP2_INSN: u32 = 0x7100_091F;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_CMP3_VA: u64 = 0x008D_5FBC;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_LDP10_VA: u64 = 0x008D_5FD0;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_LDP10_INSN: u32 = 0xA941_5A68;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_BL_HITS: usize = 2;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_BL_VA: [u64; 2] = [0x008D_F010, 0x008D_FF54];
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_BL_INSN: u32 = 0x97FF_D812;
pub const BOSMINER_HASHCHAIN_DISPATCH_BL_VA: u64 = 0x008D_FF64;
pub const BOSMINER_HASHCHAIN_DISPATCH_BL_INSN: u32 = 0x97FF_E0B6;
/// : `bosminer-antminer` `bm139x.rs` legacy FastUartReg panic string.
pub const BOSMINER_LEGACY_FASTUART_FAIL_STR: &[u8] = b"BUG: Failed to build legacy FastUartReg";
pub const BOSMINER_LEGACY_FASTUART_FAIL_STR_FILE_OFF: u64 = 0x00F2_51D0;
pub const BOSMINER_LEGACY_FASTUART_FAIL_STR_VA: u64 = 0x0132_51D0;
pub const BOSMINER_BM139X_RS_LOC_STR: &[u8] = b"open/bosminer/bosminer-antminer/src/bm139x.rs";
pub const BOSMINER_BM139X_RS_LOC_STR_FILE_OFF: u64 = 0x00F2_51A3;
pub const BOSMINER_BM139X_RS_LOC_STR_VA: u64 = 0x0132_51A3;
pub const BOSMINER_BM139X_RS_LOC_STR_LEN: u32 = 0x2D;
/// Cold panic stub. `ADRP`+`ADD #0x1d0` is the only former of the fail string.
pub const BOSMINER_LEGACY_FASTUART_PANIC_FN_VA: u64 = 0x0091_AFE8;
pub const BOSMINER_LEGACY_FASTUART_PANIC_ADRP_VA: u64 = 0x0091_AFF4;
pub const BOSMINER_LEGACY_FASTUART_PANIC_ADD_VA: u64 = 0x0091_AFF8;
pub const BOSMINER_LEGACY_FASTUART_PANIC_ADD_INSN: u32 = 0x9107_4000;
///  name. : this VA is the **divisor** leaf, not the field packer.
pub const BOSMINER_LEGACY_FASTUART_PACK_FN_VA: u64 = 0x0091_AF14;
/// `FUN_0091af14`: baud-divisor math. 0 static `BL`. `LDRB [X0,#7/8/9]` then `UDIV`.
pub const BOSMINER_LEGACY_FASTUART_DIV_FN_VA: u64 = 0x0091_AF14;
pub const BOSMINER_LEGACY_FASTUART_DIV_LDRB7_INSN: u32 = 0x3940_1C08;
pub const BOSMINER_LEGACY_FASTUART_DIV_LSR24_VA: u64 = 0x0091_AF30;
pub const BOSMINER_LEGACY_FASTUART_DIV_LSR24_INSN: u32 = 0x5318_7C2B;
pub const BOSMINER_LEGACY_FASTUART_DIV_CMP255_VA: u64 = 0x0091_AF34;
pub const BOSMINER_LEGACY_FASTUART_DIV_CMP255_INSN: u32 = 0x7103_FD7F;
pub const BOSMINER_LEGACY_FASTUART_DIV_UDIV_RET_VA: u64 = 0x0091_AF54;
pub const BOSMINER_LEGACY_FASTUART_DIV_UDIV_RET_INSN: u32 = 0x9AC9_0900;
pub const BOSMINER_LEGACY_FASTUART_DIV_BL_HITS: usize = 0;
/// Second-LOAD qword slot whose value is `FUN_0091af14`. Neighbors are DATA, not `.text`.
pub const BOSMINER_LEGACY_FASTUART_DIV_FPTR_FILE_OFF: u64 = 0x016B_E820;
pub const BOSMINER_LEGACY_FASTUART_DIV_FPTR_VA: u64 = 0x01AC_E820;
pub const BOSMINER_LEGACY_FASTUART_DIV_FPTR_PREV: u64 = 0x01AE_5350;
pub const BOSMINER_LEGACY_FASTUART_DIV_FPTR_NEXT: u64 = 0x01AE_4948;
/// : `LDP X0,X8,[X8]` then the same pair is stored at `+0x78` and `+0x88`.
pub const BOSMINER_HASHCHAIN_DUP78_LDP_VA: u64 = 0x008D_3A78;
pub const BOSMINER_HASHCHAIN_DUP78_LDP_INSN: u32 = 0xA940_2100;
pub const BOSMINER_HASHCHAIN_DUP78_STP_VA: u64 = 0x008D_3A7C;
pub const BOSMINER_HASHCHAIN_DUP78_STP_INSN: u32 = 0xA907_A260;
pub const BOSMINER_HASHCHAIN_DUP88_STP_VA: u64 = 0x008D_3A80;
pub const BOSMINER_HASHCHAIN_DUP88_STP_INSN: u32 = 0xA908_A260;
/// `STP X0,X1,[X19,#0x78]` after a `BLR` in the same cluster (Result/fat-ptr consume).
pub const BOSMINER_HASHCHAIN_BLR78_STP_VA: u64 = 0x008D_54F4;
pub const BOSMINER_HASHCHAIN_BLR78_STP_INSN: u32 = 0xA907_8660;
/// : seven byte-identical clones `MOV X0,X21; BLR X8; STP X0,X1,[X19,#0x78]`.
pub const BOSMINER_HASHCHAIN_BLR78_FAMILY_HITS: usize = 7;
pub const BOSMINER_HASHCHAIN_BLR78_MOV_INSN: u32 = 0xAA15_03E0;
pub const BOSMINER_HASHCHAIN_BLR78_BLR_INSN: u32 = 0xD63F_0100;
pub const BOSMINER_HASHCHAIN_BLR78_FAMILY_VA: [u64; 7] = [
    0x008D_54F4,
    0x008D_57D8,
    0x008D_5AD8,
    0x008D_5DEC,
    0x008D_60E8,
    0x008D_641C,
    0x008D_66B4,
];
/// Field packer leaf. Sole static `BL` is bm1398 write `@ 0x8b20fc`.
pub const BOSMINER_LEGACY_FASTUART_FIELDS_FN_VA: u64 = 0x0091_AF6C;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_UBFX_INSN: u32 = 0x5303_1009;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CMP1_VA: u64 = 0x0091_AF70;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CMP1_INSN: u32 = 0x7100_053F;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_BL_VA: u64 = 0x008B_20FC;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_BL_INSN: u32 = 0x9401_A39C;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0_VA: u64 = 0x008B_20F0;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0_INSN: u32 = 0x5280_00C0;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0: u32 = 6;
/// : sole caller also `MOVZ W2,#0x80` / `MOVZ W3,#0xF` (`FUN_008b1b98`).
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2_VA: u64 = 0x008B_20F4;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2_INSN: u32 = 0x5280_1002;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2: u32 = 0x80;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3_VA: u64 = 0x008B_20F8;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3_INSN: u32 = 0x5280_01E3;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3: u32 = 0x0F;
/// W1 is `LDRB [*(obj+8),#0x22c]; SUB #1`, not an immediate.
pub const BOSMINER_LEGACY_FASTUART_W1_LDR8_VA: u64 = 0x008B_20E0;
pub const BOSMINER_LEGACY_FASTUART_W1_LDR8_INSN: u32 = 0xF940_0668;
pub const BOSMINER_LEGACY_FASTUART_W1_LDRB_VA: u64 = 0x008B_20E4;
pub const BOSMINER_LEGACY_FASTUART_W1_LDRB_INSN: u32 = 0x3948_B108;
pub const BOSMINER_LEGACY_FASTUART_W1_SUB1_VA: u64 = 0x008B_20E8;
pub const BOSMINER_LEGACY_FASTUART_W1_SUB1_INSN: u32 = 0x5100_0501;
pub const BOSMINER_LEGACY_FASTUART_W1_LDRB_OFF: u16 = 0x22C;
/// : sibling `FUN_008b24b8` loads the same `+0x22c` byte from `X0`.
pub const BOSMINER_FASTUART_22C_SIBLING_FN_VA: u64 = 0x008B_24B8;
pub const BOSMINER_FASTUART_22C_SIBLING_LDRB_VA: u64 = 0x008B_24DC;
pub const BOSMINER_FASTUART_22C_SIBLING_LDRB_INSN: u32 = 0x3948_B009;
pub const BOSMINER_FASTUART_22C_XTAL_MOVZ_VA: u64 = 0x008B_24F0;
pub const BOSMINER_FASTUART_22C_XTAL_MOVZ_INSN: u32 = 0x528F_0801;
pub const BOSMINER_FASTUART_22C_XTAL_MOVK_VA: u64 = 0x008B_24F4;
pub const BOSMINER_FASTUART_22C_XTAL_MOVK_INSN: u32 = 0x72A0_2FA1;
pub const BOSMINER_FASTUART_22C_XTAL_HZ: u32 = 25_000_000;
pub const BOSMINER_FASTUART_22C_LDRB_HITS: usize = 12;
/// `25_000_000 / 8 = 3_125_000`. Not Track-1 host `3_000_000`.
pub const BOSMINER_FASTUART_22C_: u8 = 8;
/// `UBFIZ W13,W0,#4,#2` then `BFXIL W13,W1,#4,#4`. Dest byte 5 stores W13.
pub const BOSMINER_LEGACY_FASTUART_W13_UBFIZ_VA: u64 = 0x0091_AF84;
pub const BOSMINER_LEGACY_FASTUART_W13_UBFIZ_INSN: u32 = 0x531C_040D;
pub const BOSMINER_LEGACY_FASTUART_W13_BFXIL_VA: u64 = 0x0091_AFA4;
pub const BOSMINER_LEGACY_FASTUART_W13_BFXIL_INSN: u32 = 0x3304_1C2D;
pub const BOSMINER_LEGACY_FASTUART_STRB_5_VA: u64 = 0x0091_AFD4;
pub const BOSMINER_LEGACY_FASTUART_STRB_5_INSN: u32 = 0x3900_150D;
/// packed_struct dest offsets written by `FUN_0091af6c` (14 bytes).
pub const BOSMINER_LEGACY_FASTUART_DEST_W2_OFF: usize = 0;
pub const BOSMINER_LEGACY_FASTUART_DEST_W13_OFF: usize = 5;
pub const BOSMINER_LEGACY_FASTUART_DEST_ENUM_OFF: usize = 0x0C;
/// rustc names at `BOSMINER_FASTUART_FIELDS_STR_VA`. Not dest-byte labels.
pub const BOSMINER_FASTUART_FIELDS_STR: &[u8] = b"unknown_bits_31_28";
pub const BOSMINER_FASTUART_FIELDS_STR_FILE_OFF: u64 = 0x00F2_0C4B;
pub const BOSMINER_FASTUART_EXT_BAUD_ENABLE_STR: &[u8] = b"ext_baud_enable";
/// : rustc concatenated FastUartReg names (no NUL). Widths only
/// from identifiers that include a bit range. `rfs`/`tfs` width unbound.
pub const BOSMINER_FASTUART_NAMED_BIT_BLOB: &[u8] =
    b"unknown_bits_31_28unknown_bits_27_23unknown_bit_22unknown_bits_21_17\
ext_baud_enableunknown_bit_15rfsunknown_bit_13unknown_bit_7_reserved_bit_6tfs";
pub const BOSMINER_FASTUART_BIT76_STR: &[u8] = b"unknown_bit_7_reserved_bit_6";
pub const BOSMINER_FASTUART_RFS_STR: &[u8] = b"rfs";
pub const BOSMINER_FASTUART_TFS_STR: &[u8] = b"tfs";
pub const BOSMINER_FASTUART_EXT_BAUD_ENABLE_BIT: u32 = 16;
pub const BOSMINER_FASTUART_NAMED_BIT_15: u32 = 15;
pub const BOSMINER_FASTUART_NAMED_BIT_13: u32 = 13;
pub const BOSMINER_FASTUART_NAMED_BITS_31_28_SHIFT: u32 = 28;
pub const BOSMINER_FASTUART_NAMED_BITS_27_23_SHIFT: u32 = 23;
pub const BOSMINER_FASTUART_NAMED_BIT_22: u32 = 22;
pub const BOSMINER_FASTUART_NAMED_BITS_21_17_SHIFT: u32 = 17;
pub const BOSMINER_FASTUART_NAMED_BITS_7_6_SHIFT: u32 = 6;
/// : `STR Xt,[X19,#0x88]` of `*(obj+0x30)+0x18`. Not engine nonce `.text`.
pub const BOSMINER_NESTED88_HITS: usize = 2;
pub const BOSMINER_NESTED88_STR_VA: [u64; 2] = [0x008B_27EC, 0x008D_EA60];
pub const BOSMINER_NESTED88_STR_INSN: [u32; 2] = [0xF900_466A, 0xF900_4668];
pub const BOSMINER_NESTED88_LDR30_VA: [u64; 2] = [0x008B_27D0, 0x008D_EA3C];
pub const BOSMINER_NESTED88_LDR30_INSN: u32 = 0xF940_1A6A;
pub const BOSMINER_NESTED88_ADD18_VA: [u64; 2] = [0x008B_27E0, 0x008D_EA54];
pub const BOSMINER_NESTED88_ADD18_INSN: [u32; 2] = [0x9100_614A, 0x9100_6148];
pub const BOSMINER_NESTED88_ADD_IMM: u16 = 0x18;
pub const BOSMINER_LEGACY_FASTUART_PACKED_LEN: usize = 0x0E;
pub const BOSMINER_LEGACY_FASTUART_STRH0_VA: u64 = 0x0091_AFD0;
pub const BOSMINER_LEGACY_FASTUART_STRH0_INSN: u32 = 0x7900_010E;
pub const BOSMINER_LEGACY_FASTUART_STRB_C_VA: u64 = 0x0091_AF8C;
pub const BOSMINER_LEGACY_FASTUART_STRB_C_INSN: u32 = 0x3900_3109;
pub const BOSMINER_LEGACY_FASTUART_STRB_D_VA: u64 = 0x0091_AFE0;
pub const BOSMINER_LEGACY_FASTUART_STRB_D_INSN: u32 = 0x3900_350B;
/// DATA pin length: `28 00 00 00` + BE low-16. Not [`BOSMINER_LEGACY_FASTUART_PACKED_LEN`].
pub const BOSMINER_REG28_FASTUART_DATA_LEN: usize = 6;
pub const BOSMINER_LEGACY_FASTUART_PACK_BEQ_VA: u64 = 0x0091_AF74;
pub const BOSMINER_LEGACY_FASTUART_PACK_BEQ_INSN: u32 = 0x5400_03A0;
pub const BOSMINER_LEGACY_FASTUART_PACK_RET_VA: u64 = 0x0091_AFE4;
pub const BOSMINER_LEGACY_FASTUART_PACK_RET_INSN: u32 = 0xD65F_03C0;
/// rustc loc `bm139x.rs:659:26` next to the fail string.
pub const BOSMINER_BM139X_FASTUART_LOC_FILE_OFF: u64 = 0x015B_A080;
pub const BOSMINER_BM139X_FASTUART_LOC_LINE: u32 = 659;
pub const BOSMINER_BM139X_FASTUART_LOC_COL: u32 = 26;
/// Parallel constructor: packed at `+0x30`, fat ptr at `+0x40`, inline `+0x120`.
pub const BOSMINER_HASHCHAIN_ALT_PACKED_OFF: u16 = 0x30;
pub const BOSMINER_HASHCHAIN_ALT_FAT_OFF: u16 = 0x40;
pub const BOSMINER_HASHCHAIN_ALT_INLINE_OFF: u16 = 0x120;
pub const BOSMINER_HASHCHAIN_ALT_STP_VA: u64 = 0x008D_F004;
pub const BOSMINER_HASHCHAIN_ALT_STP_INSN: u32 = 0xA904_2668;

/// AML host UART open is not a chip set_config packer.
pub fn refuse_bosminer_aml_open_as_set_config() -> Result<(), &'static str> {
    Err("FUN_00bc1f28 is antminer_aml.rs serial open; not chip set_config")
}

/// Byte-presence pin only. Does not prove the write path.
pub fn admit_bosminer_contains_s19k_hcn_be(blob: &[u8]) -> Result<(), &'static str> {
    let off = BOSMINER_115A_BE_FILE_OFF as usize;
    if blob.len() < off + 4 {
        return Err("bosminer blob shorter than 0x115A BE pin");
    }
    if &blob[off..off + 4] != &[0x00, 0x00, 0x11, 0x5A] {
        return Err("bosminer file 0x15920A6 is not BE 0000115A");
    }
    Ok(())
}

///  inference that this pin is the HCN UART writer is **false**.
pub fn refuse_bosminer_115a_file_pin_as_hcn_writer() -> Result<(), &'static str> {
    Err(
        "bosminer 00 00 11 5A @ file 0x15920A6 / VA 0x19A20A6 xrefs FUN_0065f830 tuner; not a reg 0x10 writer",
    )
}

/// : the HCN-divider log FN is not the UART HCN writer either.
pub fn refuse_bosminer_hcn_divider_log_as_reg10_writer() -> Result<(), &'static str> {
    Err("FUN_008434e0 logs 12.5 MHz/freq work-time; not a UART set_config(0x10) writer")
}

/// : telemetry field name, not a UART packer.
pub fn refuse_bosminer_hash_counting_number_string_as_hcn_writer() -> Result<(), &'static str> {
    Err(
        "hash_counting_number @ VA 0x139db65 xrefs FUN_0041ea18 metrics registrar; not UART reg 0x10",
    )
}

pub fn refuse_bosminer_ticket_mask_serde_as_uart_writer() -> Result<(), &'static str> {
    Err("FUN_0086f5e0 is serde TicketMaskReg; not a UART ticket-mask writer")
}

/// : `MOVZ #0x51` is not the set_config packer.
pub fn refuse_bosminer_movz51_as_set_config_packer() -> Result<(), &'static str> {
    Err(
        "33 MOVZ Wd,#0x51 are alloc/panic/serde (FUN_008c4bfc 0x51-byte VoltageController); not UART 0x51",
    )
}

/// HCN UART write is generic set_config(reg=0x10), not a dedicated bosminer FN.
pub fn s19k_hcn_set_config_uart() -> [u8; 11] {
    pack_experimental_init_write(*HASH_COUNTING_BCAST_WRITE)
}

/// : AM2 `FUN_008a200c` is not the S19k AML set_config packer.
pub fn refuse_bosminer_be4_send_as_s19k_set_config() -> Result<(), &'static str> {
    Err("FUN_008a200c direct callers are ticket-mask/send-self/MiscCtrl; BM1366 FastUART uses the runtime trait/command path")
}

fn le_u64_at(blob: &[u8], off: u64) -> Option<u64> {
    let i = off as usize;
    blob.get(i..i + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
}

fn le_u16_file_at(blob: &[u8], off: u64) -> Option<u16> {
    let i = off as usize;
    blob.get(i..i + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
}

/// Admit the complete static identity chain for stock S19k BM1366 baud setup:
/// chip-id `0x1366` registry pointer -> BM1366 factory -> trait vtable slot
/// `+0x50` -> baud builder -> two-value selector -> register-`0x28` packer.
/// It also pins the generic init call site and exact set-baud log descriptor.
pub fn admit_bosminer_bm1366_stock_baud_static(blob: &[u8]) -> Result<(), &'static str> {
    if le_u64_at(blob, BOSMINER_BM1366_FACTORY_PTR_FILE_OFF) != Some(BOSMINER_BM1366_FACTORY_FN_VA)
    {
        return Err("chip-id 0x1366 registry pointer is not the held BM1366 factory");
    }
    let slot_off = BOSMINER_BM1366_TRAIT_VTABLE_FILE_OFF + BOSMINER_BM1366_SET_BAUD_VTABLE_SLOT;
    if le_u64_at(blob, slot_off) != Some(BOSMINER_BM1366_SET_BAUD_BUILD_FN_VA) {
        return Err("BM1366 trait vtable +0x50 is not FUN_008dd3b8");
    }
    if le_u64_at(blob, BOSMINER_FASTUART_REG_DESCRIPTOR_FILE_OFF) != Some(4)
        || le_u64_at(blob, BOSMINER_FASTUART_REG_DESCRIPTOR_FILE_OFF + 8)
            != Some(u64::from(BOSMINER_BM1366_FASTUART_REG))
    {
        return Err("FastUartReg packer descriptor is not len=4, register=0x28");
    }
    let log = BOSMINER_SET_BAUD_RATE_LOG_DESCRIPTOR_FILE_OFF;
    let want_log = [
        BOSMINER_SET_BAUD_RATE_STR_VA,
        6,
        BOSMINER_SET_BAUD_RATE_REQUESTED_STR_VA,
        29,
        BOSMINER_SET_BAUD_RATE_ACTUAL_STR_VA,
        10,
    ];
    for (index, expected) in want_log.into_iter().enumerate() {
        if le_u64_at(blob, log + index as u64 * 8) != Some(expected) {
            return Err("set-baud log descriptor drifted");
        }
    }
    let string_off = (BOSMINER_SET_BAUD_RATE_STR_VA - 0x0040_0000) as usize;
    let string = b"CHAIN/: Set baud rate @ requested: , actual: ";
    if blob.get(string_off..string_off + string.len()) != Some(string) {
        return Err("set-baud log string pieces drifted");
    }

    let pins = [
        (0x008D_D3D8, 0x9400_F713), // BL baud selector
        (0x008D_D414, 0x5280_004A), // MOV W10,#2 (BM1362/BM1366 mode)
        (0x008D_D418, 0x3900_53EA), // STRB mode into FastUartReg input
        (0x008D_D468, 0x97FD_C649), // BL register packer
        (0x0091_B034, 0xF109_013F), // selector compare: 1,000,000
        (0x0091_B03C, 0x5295_E109), // 3,125,000 low half
        (0x0091_B040, 0x72A0_05E9), // 3,125,000 high half
        (0x0083_76FC, 0xF940_2929), // generic init: load vtable +0x50
        (0x0083_7704, 0xD63F_0120), // invoke baud builder
        (0x0083_7BC8, 0xF940_1928), // later load vtable +0x30
    ];
    for (va, expected) in pins {
        if le_u32_at(blob, va) != Some(expected) {
            return Err("stock BM1366 baud-path instruction pin drifted");
        }
    }
    Ok(())
}

/// Admit the seven stock BM1366 trait calls made by the held generic
/// `AntminerDriver::init` future, in successful execution order. This pins the
/// vtable, call instructions, async resume table, source/future records,
/// register descriptors, generic continuation corridors, and both
/// immediate-Ready/no-I/O futures.
///
/// It intentionally does not claim complete method semantics or authorize a
/// UART/power executor. The `+0x30` and `+0x28` register tails are flattened,
/// but platform power and host-switch validation/rollback remain outside this
/// descriptor.
pub fn admit_bosminer_bm1366_stock_init_order_static(blob: &[u8]) -> Result<(), &'static str> {
    for (index, expected_offset) in BOSMINER_BM1366_STOCK_INIT_JUMP_OFFSETS
        .into_iter()
        .enumerate()
    {
        let file_off = BOSMINER_BM1366_STOCK_INIT_JUMP_TABLE_FILE_OFF + index as u64 * 2;
        if le_u16_file_at(blob, file_off) != Some(expected_offset) {
            return Err("stock BM1366 init async jump table drifted");
        }
        let resume = BOSMINER_BM1366_STOCK_INIT_DISPATCH_BASE_VA + u64::from(expected_offset) * 4;
        if resume != BOSMINER_BM1366_STOCK_INIT_RESUME_VA[index]
            || !(BOSMINER_ANTMINER_DRIVER_INIT_FUTURE_FN_VA
                ..BOSMINER_BM1366_STOCK_INIT_FUTURE_END_VA)
                .contains(&resume)
        {
            return Err("stock BM1366 init async resume target escaped its poll range");
        }
    }

    let instruction_pins: [(u64, u32, u64, u32); 7] = [
        (0x0083_6E94, 0xF940_2128, 0x0083_6E98, 0xD63F_0100),
        (0x0083_862C, 0xF940_2528, 0x0083_8630, 0xD63F_0100),
        (0x0083_89F8, 0xF940_1528, 0x0083_89FC, 0xD63F_0100),
        (0x0083_7668, 0xF940_1D28, 0x0083_766C, 0xD63F_0100),
        (0x0083_76FC, 0xF940_2929, 0x0083_7704, 0xD63F_0120),
        (0x0083_7DD8, 0xF940_3D28, 0x0083_7DDC, 0xD63F_0100),
        (0x0083_7BC8, 0xF940_1928, 0x0083_7BCC, 0xD63F_0100),
    ];
    for (index, stage) in BOSMINER_BM1366_STOCK_INIT_DISPATCH.iter().enumerate() {
        if stage.ordinal != index as u8 + 1
            || stage.vtable_slot != BOSMINER_BM1366_STOCK_INIT_EXECUTION_SLOT_ORDER[index]
        {
            return Err("stock BM1366 init execution order drifted");
        }
        if le_u64_at(
            blob,
            BOSMINER_BM1366_TRAIT_VTABLE_FILE_OFF + u64::from(stage.vtable_slot),
        ) != Some(stage.method_va)
        {
            return Err("stock BM1366 init vtable method drifted");
        }
        let (slot_load_va, slot_load_word, invoke_va, invoke_word) = instruction_pins[index];
        if stage.slot_load_va != slot_load_va
            || stage.invoke_va != invoke_va
            || le_u32_at(blob, slot_load_va) != Some(slot_load_word)
            || le_u32_at(blob, invoke_va) != Some(invoke_word)
        {
            return Err("stock BM1366 init dynamic-call instruction drifted");
        }
    }
    let mut callsite_order = BOSMINER_BM1366_STOCK_INIT_DISPATCH;
    callsite_order.sort_by_key(|stage| stage.slot_load_va);
    if callsite_order.map(|stage| stage.vtable_slot)
        != BOSMINER_BM1366_STOCK_INIT_CALLSITE_SLOT_ORDER
    {
        return Err("stock BM1366 init call-site address order drifted");
    }

    let source_records: [(u64, u32, u32, u64); 3] = [
        (0x015B_7EB0, 93, 64, 0x008D_CFBC),
        (0x015B_7EE8, 127, 66, 0x008D_D4C8),
        (0x015B_7F20, 166, 72, 0x008D_D63C),
    ];
    for (file_off, line, column, poll_va) in source_records {
        if le_u64_at(blob, file_off) != Some(BOSMINER_BM1366_RS_LOC_STR_VA)
            || le_u64_at(blob, file_off + 8) != Some(u64::from(BOSMINER_BM1366_RS_LOC_STR_LEN))
            || le_u64_at(blob, file_off + 16) != Some(u64::from(line) | (u64::from(column) << 32))
            || le_u64_at(blob, file_off + 48) != Some(poll_va)
        {
            return Err("stock BM1366 init source/future record drifted");
        }
    }

    let register_descriptors: [(u64, u64); 10] = [
        (0x00EE_7E40, 0x3C),
        (0x00EE_7E60, 0xA8),
        (0x00EE_7E80, 0x10),
        (0x00EE_7E90, 0xA4),
        (0x00EE_7EA0, 0x58),
        (0x00EE_7EB0, 0x2C),
        (0x00EE_7F20, 0x54),
        (0x00EE_7F50, 0x0C),
        (0x00EE_7FE0, 0x18),
        (0x00EE_8010, 0x28),
    ];
    for (file_off, register) in register_descriptors {
        if le_u64_at(blob, file_off) != Some(4) || le_u64_at(blob, file_off + 8) != Some(register) {
            return Err("stock BM1366 init register descriptor drifted");
        }
    }

    let no_io_heads: [(u64, [u32; 9]); 2] = [
        (
            0x008D_FA14,
            [
                0xF81F_0FFE,
                0x3940_2009,
                0x3500_00E9,
                0x5280_0109,
                0x5280_002A,
                0xF900_0109,
                0x3900_200A,
                0xF841_07FE,
                0xD65F_03C0,
            ],
        ),
        (
            0x008D_FD00,
            [
                0xF81F_0FFE,
                0x3940_4009,
                0x3500_00E9,
                0x5280_0109,
                0x5280_002A,
                0xF900_0109,
                0x3900_400A,
                0xF841_07FE,
                0xD65F_03C0,
            ],
        ),
    ];
    for (head_va, words) in no_io_heads {
        for (index, expected) in words.into_iter().enumerate() {
            if le_u32_at(blob, head_va + index as u64 * 4) != Some(expected) {
                return Err("stock BM1366 immediate-Ready/no-I/O future drifted");
            }
        }
    }

    let successful_arm_pins: [(u64, u32); 6] = [
        (0x0083_76DC, 0xF100_231F),
        (0x0083_76E0, 0x5400_0381),
        (0x0083_86A8, 0xF100_237F),
        (0x0083_86AC, 0x5400_1941),
        (0x0083_89E4, 0xF100_237F),
        (0x0083_89E8, 0x5400_0101),
    ];
    for (va, expected) in successful_arm_pins {
        if le_u32_at(blob, va) != Some(expected) {
            return Err("stock BM1366 successful-arm instruction drifted");
        }
    }

    for (index, expected) in BOSMINER_BM1366_STOCK_FINALIZE_POLL_VTABLE
        .into_iter()
        .enumerate()
    {
        if le_u64_at(
            blob,
            BOSMINER_BM1366_STOCK_FINALIZE_POLL_VTABLE_FILE_OFF + index as u64 * 8,
        ) != Some(expected)
        {
            return Err("stock BM1366 slot-0x28 final future vtable drifted");
        }
    }

    // Tail pins cover the count/divide/multiply register-0x0c schedule, the
    // HCN and VersionMask calls, caller-derived IoDriver-vector construction,
    // descending domain-pair iterator, register-0x2c packer, and generic
    // chip-index -> one-byte wire-address conversion.
    let tail_pins: [(u64, u32); 33] = [
        (0x008D_D980, 0xF940_A508),
        (0x008D_D988, 0x529F_FFE9),
        (0x008D_D990, 0x9AC8_0928),
        (0x008D_DEA0, 0x1B08_7D2B),
        (0x008D_DF14, 0x5AC0_070A),
        (0x008D_DF24, 0x2A0A_4129),
        (0x008D_DFA0, 0x940C_548A),
        (0x008D_DB70, 0x9400_F5A9),
        (0x008D_DB9C, 0x97FF_DEC2),
        (0x008D_DC7C, 0x12BF_DFC9),
        (0x008D_DCA4, 0x97FF_DF39),
        (0x008D_CB1C, 0x3949_0422),
        (0x008D_CB2C, 0x9400_F96B),
        (0x0091_B0F4, 0xF940_A835),
        (0x0091_B100, 0xF940_A428),
        (0x0091_B14C, 0x9AD5_0916),
        (0x0091_B178, 0x9B15_52C9),
        (0x0091_B19C, 0x381F_D11C),
        (0x008D_CD74, 0x9400_F7ED),
        (0x0091_AD30, 0xF940_A809),
        (0x0091_AD38, 0xF940_A40B),
        (0x0092_3B70, 0xA954_DD16),
        (0x0092_3B80, 0xCB17_02AA),
        (0x0092_3B94, 0x4B0A_02CB),
        (0x0092_3B9C, 0x1100_396A),
        (0x008D_FF54, 0x97FF_D812),
        (0x008D_6004, 0x3940_0AC8),
        (0x008D_601C, 0x5AC0_094A),
        (0x008D_6030, 0x2A08_0168),
        (0x008D_6050, 0x2A08_6148),
        (0x00BF_31CC, 0xF940_0008),
        (0x00BF_31D0, 0x9B02_7D08),
        (0x00BF_31E0, 0x2A08_03E1),
    ];
    for (va, expected) in tail_pins {
        if le_u32_at(blob, va) != Some(expected) {
            return Err("stock BM1366 register-tail instruction drifted");
        }
    }

    // These anchors distinguish source/execution order from ascending `.text`
    // layout and bind the direct generic operations between trait calls.
    let generic_path_pins = [
        (0x0083_6EA0, 0x1400_0051), // slot +0x40 future -> its poll
        (0x0083_70B8, 0xF100_237F), // +0x40 Ready/Ok discriminant 8
        (0x0083_749C, 0x9403_A51D), // broadcast destination builder
        (0x0083_74D4, 0x5280_0069), // three ChainInactive repetitions
        (0x0083_8C0C, 0x1100_0508), // increment repetition counter
        (0x0083_8C5C, 0x72A2_3C29), // 300,000,000 ns high half
        (0x0083_8CA0, 0x6B09_011F), // compare repetition counter/limit
        (0x0083_8CA4, 0x54FF_FB4B), // loop while below three
        (0x0083_8524, 0x940E_EB29), // address_gap*chip_index destination
        (0x0083_8544, 0x9403_A0E5), // unicast SetAddress destination builder
        (0x0083_85CC, 0xEB08_005F), // address index/count comparison
        (0x0083_85D0, 0x5400_01E2), // ladder complete -> slot +0x48
        (0x0083_86A8, 0xF100_237F), // +0x48 Ready/Ok discriminant 8
        (0x0083_86B4, 0x529E_1009), // 50,000,000 ns low half
        (0x0083_86B8, 0x72A0_5F49), // 50,000,000 ns high half
        (0x0083_87C4, 0x3DC3_9140), // generic register-0x3c descriptor
        (0x0083_8918, 0x529E_1009), // second 50,000,000 ns wait
        (0x0083_8920, 0x72A0_5F49),
        (0x0083_89E4, 0xF100_237F), // generic corridor Ready -> slot +0x28
        (0x0083_8A04, 0x17FF_F957), // slot +0x28 future -> poll
        (0x0083_7138, 0xF100_237F), // +0x28 Ready/Ok discriminant 8
        (0x0083_72F4, 0x3DC3_2D60), // read-register-0 descriptor
        (0x0083_99A4, 0x17FF_F541), // discovery/accounting tail -> next poll
        (0x0083_71EC, 0xB500_D759), // success continues to platform lookup
        (0x0083_71FC, 0x3600_21E0), // supported platform -> slot +0x38
        (0x0083_76DC, 0xF100_231F), // +0x38 Ready/Ok -> slot +0x50
        (0x0083_7718, 0xEB09_015F), // FastUART builder Result success
        (0x0083_7894, 0x97FF_FBD3), // set-baud tracing corridor
        (0x0083_7DA0, 0xB400_0179), // generic baud corridor -> slot +0x78
        (0x0083_7600, 0xF100_231F), // +0x78 Ready/Ok
        (0x0083_7608, 0xAA1F_03F9), // success clears error carrier
        (0x0083_760C, 0x1400_01E7), // join continuation before slot +0x30
        (0x0083_7DB8, 0x3607_EFA8), // success branch to slot +0x30
        (0x0083_7BD4, 0x17FF_FD20), // slot +0x30 future -> poll
        (0x0083_71B0, 0xF100_237F), // +0x30 Ready/Ok final result
        (0x0092_08D8, 0x3600_00E1), // unicast destination is mandatory
        (0x0092_0910, 0x3940_2C08), // broadcast destination source field
        (0x00BF_31CC, 0xF940_0008), // address gap
        (0x00BF_31D0, 0x9B02_7D08), // address_gap*chip_index
    ];
    for (va, expected) in generic_path_pins {
        if le_u32_at(blob, va) != Some(expected) {
            return Err("stock BM1366 generic init/control-flow instruction drifted");
        }
    }
    let read_zero_off = BOSMINER_BM1366_GENERIC_READ_REGISTER_ZERO_DESCRIPTOR_VA - 0x0040_0000;
    if le_u64_at(blob, read_zero_off) != Some(0) || le_u64_at(blob, read_zero_off + 8) != Some(4) {
        return Err("stock BM1366 generic read-register-0 descriptor drifted");
    }
    Ok(())
}

/// Admit the stock backend lifecycle that surrounds the generic BM1366 init:
/// reset dispatch, fan-readiness gate with a one-second pending cadence, init
/// dispatch, a ten-second timeout around the init future, and the outer
/// four-attempt/ten-second retry policy. The conditional five-second wait
/// inside the backend is pinned but intentionally not named a retry delay
/// because its controlling flag semantics remain unrecovered.
pub fn admit_bosminer_hashchain_lifecycle_static(blob: &[u8]) -> Result<(), &'static str> {
    let descriptors = [
        (
            BOSMINER_HASHCHAIN_RESET_LOG_DESCRIPTOR_FILE_OFF,
            BOSMINER_HASHCHAIN_RESET_LOG_MESSAGE_VA,
            BOSMINER_HASHCHAIN_RESET_LOG_MESSAGE.len() as u64,
            BOSMINER_HASHCHAIN_SOURCE_VA,
            BOSMINER_HASHCHAIN_SOURCE.len() as u64,
            512u32,
            14u32,
        ),
        (
            BOSMINER_HASHCHAIN_INIT_LOG_DESCRIPTOR_FILE_OFF,
            BOSMINER_HASHCHAIN_INIT_LOG_MESSAGE_VA,
            BOSMINER_HASHCHAIN_INIT_LOG_MESSAGE.len() as u64,
            BOSMINER_HASHCHAIN_SOURCE_VA,
            BOSMINER_HASHCHAIN_SOURCE.len() as u64,
            777u32,
            9u32,
        ),
        (
            BOSMINER_HASHCHAIN_FAN_WAIT_LOG_DESCRIPTOR_FILE_OFF,
            BOSMINER_HASHCHAIN_FAN_WAIT_LOG_MESSAGE_VA,
            BOSMINER_HASHCHAIN_FAN_WAIT_LOG_MESSAGE.len() as u64,
            BOSMINER_HASHCHAIN_SOURCE_VA,
            BOSMINER_HASHCHAIN_SOURCE.len() as u64,
            453u32,
            17u32,
        ),
        (
            BOSMINER_HASHCHAIN_FANS_OK_LOG_DESCRIPTOR_FILE_OFF,
            BOSMINER_HASHCHAIN_FANS_OK_LOG_MESSAGE_VA,
            BOSMINER_HASHCHAIN_FANS_OK_LOG_MESSAGE.len() as u64,
            BOSMINER_HASHCHAIN_SOURCE_VA,
            BOSMINER_HASHCHAIN_SOURCE.len() as u64,
            466u32,
            32u32,
        ),
        (
            BOSMINER_HASHCHAIN_RETRY_LOG_DESCRIPTOR_FILE_OFF,
            BOSMINER_HASHCHAIN_RETRY_LOG_MESSAGE_VA,
            BOSMINER_HASHCHAIN_RETRY_LOG_MESSAGE.len() as u64,
            BOSMINER_MINER_SOURCE_VA,
            BOSMINER_MINER_SOURCE.len() as u64,
            319u32,
            21u32,
        ),
        (
            BOSMINER_HASHCHAIN_START_FAILED_LOG_DESCRIPTOR_FILE_OFF,
            BOSMINER_HASHCHAIN_START_FAILED_LOG_MESSAGE_VA,
            BOSMINER_HASHCHAIN_START_FAILED_LOG_MESSAGE.len() as u64,
            BOSMINER_MINER_SOURCE_VA,
            BOSMINER_MINER_SOURCE.len() as u64,
            327u32,
            21u32,
        ),
    ];
    for (file_off, message_va, message_len, source_va, source_len, line, column) in descriptors {
        let expected = [
            BOSMINER_HASHCHAIN_LOG_PREFIX_VA,
            6,
            message_va,
            message_len,
            source_va,
            source_len,
            u64::from(line) | (u64::from(column) << 32),
        ];
        for (index, value) in expected.into_iter().enumerate() {
            if le_u64_at(blob, file_off + index as u64 * 8) != Some(value) {
                return Err("stock hashchain platform lifecycle log descriptor drifted");
            }
        }
    }

    for (va, expected) in [
        (BOSMINER_HASHCHAIN_LOG_PREFIX_VA, b"CHAIN/".as_slice()),
        (
            BOSMINER_HASHCHAIN_RESET_LOG_MESSAGE_VA,
            BOSMINER_HASHCHAIN_RESET_LOG_MESSAGE,
        ),
        (
            BOSMINER_HASHCHAIN_INIT_LOG_MESSAGE_VA,
            BOSMINER_HASHCHAIN_INIT_LOG_MESSAGE,
        ),
        (
            BOSMINER_HASHCHAIN_FAN_WAIT_LOG_MESSAGE_VA,
            BOSMINER_HASHCHAIN_FAN_WAIT_LOG_MESSAGE,
        ),
        (
            BOSMINER_HASHCHAIN_FANS_OK_LOG_MESSAGE_VA,
            BOSMINER_HASHCHAIN_FANS_OK_LOG_MESSAGE,
        ),
        (
            BOSMINER_HASHCHAIN_RETRY_LOG_MESSAGE_VA,
            BOSMINER_HASHCHAIN_RETRY_LOG_MESSAGE,
        ),
        (
            BOSMINER_HASHCHAIN_START_FAILED_LOG_MESSAGE_VA,
            BOSMINER_HASHCHAIN_START_FAILED_LOG_MESSAGE,
        ),
        (BOSMINER_HASHCHAIN_SOURCE_VA, BOSMINER_HASHCHAIN_SOURCE),
        (BOSMINER_MINER_SOURCE_VA, BOSMINER_MINER_SOURCE),
    ] {
        let off = (va - 0x0040_0000) as usize;
        if blob.get(off..off + expected.len()) != Some(expected) {
            return Err("stock hashchain lifecycle source/log string drifted");
        }
    }

    let pins: [(u64, u32); 81] = [
        // Outer bounded start wrapper: budget=4, call, decrement, terminal
        // branch, then a ten-second sleep before the next attempt.
        (0x0071_7988, 0x5280_0088),
        (0x0071_798C, 0xF900_2E68),
        (0x0071_79F0, 0x9400_079E),
        (0x0071_7D28, 0xF940_2E68),
        (0x0071_7D2C, 0xF100_0508),
        (0x0071_7D30, 0xF900_2E68),
        (0x0071_7D34, 0x5400_1960),
        (0x0071_7D44, 0x5280_0140),
        (0x0071_7D48, 0x2A1F_03E1),
        (0x0071_7D4C, 0x942B_AFBF),
        (0x0071_7D80, 0x9101_C260),
        (0x0071_7D84, 0xAA14_03E1),
        (0x0071_7D88, 0x942B_B1EB),
        (0x0071_8030, 0x17FF_FE6D),
        // Terminal exhaustion: load the retained error, run only the exact
        // four cleanup calls, store the error result, and return.
        (0x0071_8060, 0xF940_2A68),
        (0x0071_8064, 0x3CCE_8260),
        (0x0071_8068, 0xF940_7E69),
        (0x0071_806C, 0xF940_7277),
        (0x0071_808C, 0x9412_94E1),
        (0x0071_80B0, 0x9410_A555),
        (0x0071_8100, 0x9400_3DF7),
        (0x0071_8160, 0x942D_62C6),
        (0x0071_8170, 0xA900_5E68),
        (0x0071_8178, 0x3C81_0260),
        (0x0071_817C, 0xA902_5A68),
        (0x0071_819C, 0xD65F_03C0),
        // Backend reset/control trait pair at +0x210/+0x218, method +0x28.
        (0x0071_B088, 0xF940_02E8),
        (0x0071_B08C, 0xF941_0D09),
        (0x0071_B090, 0xF941_0900),
        (0x0071_B094, 0xF940_1528),
        (0x0071_B098, 0xD63F_0100),
        // Conditional five-second wait: retained as an unnamed pre-init gate,
        // not promoted to retry policy.
        (0x0071_B70C, 0x394E_4668),
        (0x0071_B720, 0x5280_00A0),
        (0x0071_B724, 0x2A1F_03E1),
        (0x0071_B728, 0x942B_A148),
        // Initial fan-ready snapshot. Ready skips to the Fans-OK path; pending
        // initializes the retry state and jumps to the repeated check.
        (BOSMINER_HASHCHAIN_FAN_READY_SNAPSHOT_FN_VA, 0xFC16_0FEE),
        (
            BOSMINER_HASHCHAIN_FAN_READY_SNAPSHOT_STATUS_BYTE_LOAD_VA,
            0x3945_B276,
        ),
        (BOSMINER_HASHCHAIN_FAN_READY_INITIAL_CALL_VA, 0x9410_FF0A),
        (0x0071_BF88, 0x3700_A520),
        (0x0071_BF90, 0x1400_03C0),
        // Repeated fan-ready snapshot; true reaches the Fans-OK arm.
        (0x0071_CE90, 0xF941_F260),
        (BOSMINER_HASHCHAIN_FAN_READY_RECHECK_CALL_VA, 0x9410_FB46),
        (0x0071_CE98, 0x3700_1840),
        // Both async logging arms load the retained waiting descriptor.
        (0x0071_CF2C, 0x9000_94A8),
        (0x0071_CF30, 0x9102_C108),
        (0x0071_D0A8, 0xF000_9489),
        (0x0071_D0AC, 0x9102_C129),
        // Increment the pending-loop counter, construct Duration(1 s, 0 ns)
        // with the exact source record, poll it, and branch back to recheck.
        (0x0071_D11C, 0xF941_F668),
        (0x0071_D120, 0x9100_0508),
        (0x0071_D124, 0xF901_F668),
        (0x0071_D128, 0xF000_9482),
        (0x0071_D12C, 0x9103_4042),
        (0x0071_D134, 0x5280_0020),
        (0x0071_D138, 0x2A1F_03E1),
        (0x0071_D13C, 0x942B_9AC3),
        (0x0071_D184, 0x910F_C260),
        (0x0071_D188, 0xAA1A_03E1),
        (0x0071_D18C, 0x942B_9CEA),
        (BOSMINER_HASHCHAIN_FAN_PENDING_LOOP_BACKEDGE_VA, 0x17FF_FF3D),
        // Both ready arms load/store the exact Fans-OK descriptor before
        // converging on the later init path.
        (0x0071_D210, 0xF000_9488),
        (0x0071_D214, 0x9104_0108),
        (0x0071_D224, 0xA911_2BE8),
        (0x0071_D3A8, 0xF000_9489),
        (0x0071_D3AC, 0x9104_0129),
        (0x0071_D3C4, 0xA911_2BE9),
        // Init trait pair at +0x220/+0x228, method +0x18.
        (0x0071_D89C, 0xF941_DE68),
        (0x0071_D8A0, 0x394F_4261),
        (0x0071_D8A4, 0xF941_1509),
        (0x0071_D8A8, 0xF941_1100),
        (0x0071_D8AC, 0xF940_0D28),
        (0x0071_D8B0, 0xD63F_0100),
        (0x0071_D8B4, 0xAA00_03E2),
        (0x0071_D8B8, 0xAA01_03E3),
        // Duration(10 s, 0 ns) passed to the recovered timeout wrapper.
        (0x0071_D8C8, 0x5280_0140),
        (0x0071_D8CC, 0x2A1F_03E1),
        (0x0071_D8D4, 0x97FE_198D),
        // Function/range and duration facts stay independently asserted even
        // though their values are also visible in the pins above.
        (BOSMINER_HASHCHAIN_START_WRAPPER_FN_VA, 0xA9BA_7BFD),
        (BOSMINER_HASHCHAIN_START_POLL_FN_VA, 0xFC19_0FE8),
        (BOSMINER_HASHCHAIN_TIMEOUT_WRAPPER_FN_VA, 0xD102_C3FF),
        (0x0071_D8C0, 0x912D_4084),
        (0x0071_D8D0, 0xF940_73F7),
    ];
    for (va, expected) in pins {
        if le_u32_at(blob, va) != Some(expected) {
            return Err("stock hashchain lifecycle instruction pin drifted");
        }
    }

    let mut terminal_calls = Vec::new();
    for va in (BOSMINER_HASHCHAIN_TERMINAL_FAILURE_TAIL_START_VA
        ..=BOSMINER_HASHCHAIN_TERMINAL_FAILURE_TAIL_END_VA)
        .step_by(4)
    {
        let word = le_u32_at(blob, va).ok_or("stock hashchain terminal failure tail truncated")?;
        if word & 0xFFFF_FC1F == 0xD63F_0000 {
            return Err("stock hashchain terminal failure tail gained a BLR dispatch");
        }
        if let Some(target_va) = aarch64_direct_bl_target(va, word) {
            terminal_calls.push(BosminerHashchainTerminalFailureCall {
                call_va: va,
                target_va,
            });
        }
    }
    if terminal_calls.as_slice() != BOSMINER_HASHCHAIN_TERMINAL_FAILURE_CALLS.as_slice() {
        return Err("stock hashchain terminal failure direct-call set drifted");
    }

    if BOSMINER_HASHCHAIN_START_RETRY_BUDGET != 4
        || bosminer_hashchain_start_attempt_delays_ns()
            != [0, 10_000_000_000, 10_000_000_000, 10_000_000_000]
        || BOSMINER_HASHCHAIN_START_RETRY_DELAY_NS != 10_000_000_000
        || BOSMINER_HASHCHAIN_INIT_TIMEOUT_NS != 10_000_000_000
        || BOSMINER_HASHCHAIN_CONDITIONAL_PREINIT_WAIT_NS != 5_000_000_000
        || BOSMINER_HASHCHAIN_FAN_PENDING_WAIT_NS != 1_000_000_000
        || BOSMINER_HASHCHAIN_PLATFORM_ORDER
            != [
                BosminerHashchainPlatformStage::ResetDispatch,
                BosminerHashchainPlatformStage::FanReadinessGateOneSecondPendingCadence,
                BosminerHashchainPlatformStage::InitDispatchWithTenSecondTimeout,
            ]
    {
        return Err("stock hashchain lifecycle duration contract drifted");
    }
    Ok(())
}

/// Admit the exact held platform table, code-3 registry/builder selection,
/// and S19K Pro NoPic candidate identity. This is a software identity gate,
/// not hardware authority.
pub fn admit_bosminer_s19k_platform_resolution_static(blob: &[u8]) -> Result<(), &'static str> {
    for (index, expected_name) in BOSMINER_PLATFORM_NAMES.into_iter().enumerate() {
        let row_off = BOSMINER_PLATFORM_NAME_TABLE_FILE_OFF + index as u64 * 16;
        if le_u64_at(blob, row_off) != Some(BOSMINER_PLATFORM_NAME_VAS[index])
            || le_u64_at(blob, row_off + 8) != Some(expected_name.len() as u64)
        {
            return Err("stock platform name table descriptor drifted");
        }
        let name_off = first_load_off(BOSMINER_PLATFORM_NAME_VAS[index])
            .ok_or("stock platform name is outside the first ELF load")?;
        if blob.get(name_off..name_off + expected_name.len()) != Some(expected_name) {
            return Err("stock platform name bytes drifted");
        }
    }
    for (va, expected) in BOSMINER_S19K_PLATFORM_RESOLUTION_PINS {
        if le_u32_at(blob, va) != Some(expected) {
            return Err("stock S19k platform resolution instruction pin drifted");
        }
    }
    let model_off = first_load_off(BOSMINER_S19K_NOPIC_MODEL_NAME_VA)
        .ok_or("stock S19k model name is outside the first ELF load")?;
    let board_off = first_load_off(BOSMINER_S19K_NOPIC_BOARD_ID_VA)
        .ok_or("stock S19k board ID is outside the first ELF load")?;
    if blob.get(model_off..model_off + BOSMINER_S19K_NOPIC_MODEL_NAME.len())
        != Some(BOSMINER_S19K_NOPIC_MODEL_NAME)
        || blob.get(board_off..board_off + BOSMINER_S19K_NOPIC_BOARD_ID.len())
            != Some(BOSMINER_S19K_NOPIC_BOARD_ID)
        || !blob
            .windows(BOSMINER_AM3_AML_FILTERED_BUILDERS[0].len())
            .any(|window| window == BOSMINER_AM3_AML_FILTERED_BUILDERS[0])
        || !blob
            .windows(BOSMINER_AM3_AML_FILTERED_BUILDERS[1].len())
            .any(|window| window == BOSMINER_AM3_AML_FILTERED_BUILDERS[1])
    {
        return Err("stock S19k platform/model identity string drifted");
    }
    if le_u64_at(blob, BOSMINER_PLATFORM_REGISTRY_INIT_PTR_FILE_OFF)
        != Some(BOSMINER_PLATFORM_REGISTRY_INIT_FN_VA)
        || le_u64_at(blob, BOSMINER_AM3_AML_FACTORY_RECORD_FILE_OFF)
            != Some(BOSMINER_AM3_AML_FACTORY_FN_VA)
        || le_u64_at(blob, BOSMINER_BUILDER_REGISTRY_LAZY_PTR_FILE_OFF)
            != Some(BOSMINER_BUILDER_REGISTRY_STORAGE_VA)
        || le_u64_at(blob, BOSMINER_BUILDER_REGISTRY_INIT_PTR_FILE_OFF)
            != Some(BOSMINER_BUILDER_REGISTRY_INIT_FN_VA)
        || le_u64_at(blob, BOSMINER_ANTMINER_BUILDER_VTABLE_FILE_OFF + 0x30)
            != Some(BOSMINER_ANTMINER_PROVIDER_BUILD_FN_VA)
        || le_u64_at(
            blob,
            BOSMINER_BRAIINS_FIXTURE_BUILDER_VTABLE_FILE_OFF + 0x30,
        ) != Some(BOSMINER_BRAIINS_FIXTURE_PROVIDER_BUILD_FN_VA)
        || le_u64_at(blob, BOSMINER_THIRD_BUILDER_VTABLE_FILE_OFF + 0x30)
            != Some(BOSMINER_THIRD_PROVIDER_BUILD_FN_VA)
        || le_u64_at(
            blob,
            BOSMINER_ANTMINER_AM3_AML_CANDIDATE_TABLE_FILE_OFF
                + u64::from(BOSMINER_S19K_NOPIC_CANDIDATE_INDEX) * 8,
        ) != Some(BOSMINER_S19K_NOPIC_CANDIDATE_OBJECT_VA)
        || le_u64_at(blob, BOSMINER_S19K_NOPIC_CANDIDATE_INIT_PTR_FILE_OFF)
            != Some(BOSMINER_S19K_NOPIC_CANDIDATE_INIT_FN_VA)
    {
        return Err("stock S19k registry/builder/model pointer lineage drifted");
    }
    for (provider_vtable, expected) in [
        (
            BOSMINER_ANTMINER_PROVIDER_VTABLE_FILE_OFF,
            BOSMINER_ANTMINER_PROVIDER_VTABLE,
        ),
        (
            BOSMINER_BRAIINS_FIXTURE_PROVIDER_VTABLE_FILE_OFF,
            BOSMINER_BRAIINS_FIXTURE_PROVIDER_VTABLE,
        ),
    ] {
        let actual = [
            le_u64_at(blob, provider_vtable),
            le_u64_at(blob, provider_vtable + 8),
            le_u64_at(blob, provider_vtable + 0x10),
            le_u64_at(blob, provider_vtable + 0x18),
            le_u64_at(blob, provider_vtable + 0x20),
            le_u64_at(blob, provider_vtable + 0x28),
            le_u64_at(blob, provider_vtable + 0x30),
            le_u64_at(blob, provider_vtable + 0x38),
        ];
        if actual != expected.map(Some) {
            return Err("stock code-3 provider vtable drifted");
        }
    }
    if BOSMINER_AM3_AML_PLATFORM_CODE != 3
        || BOSMINER_PLATFORM_NAMES[BOSMINER_AM3_AML_PLATFORM_CODE as usize] != b"am3-aml"
        || BOSMINER_AM3_AML_PLATFORM_VTABLE_VA != 0x019C_9088
        || BOSMINER_ANTMINER_AM3_AML_CANDIDATE_COUNT != 0x15
        || BOSMINER_ANTMINER_SUPPORTED_PLATFORM_CODES != [4, 3, 2, 6, 5]
        || BOSMINER_BRAIINS_FIXTURE_SUPPORTED_PLATFORM_CODES != [3, 6]
        || BOSMINER_THIRD_BUILDER_SUPPORTED_PLATFORM_CODES != [6, 7]
    {
        return Err("stock S19k platform resolution descriptor drifted");
    }
    Ok(())
}

/// Admit the descriptor Arc as the exact 0x570-byte live
/// `Arc<HashchainManager>` allocation owned by raw record `+0x510`. The later
/// payload-hook dispatch is admitted separately; either code-3 no-op retains a
/// prestaged pair whose cloned dispatch table and final method remain outside
/// this static admission.
pub fn admit_bosminer_chain_descriptor_arc_lineage_static(blob: &[u8]) -> Result<(), &'static str> {
    for (va, expected) in BOSMINER_CHAIN_DESCRIPTOR_ARC_LINEAGE_PINS {
        if le_u32_at(blob, va) != Some(expected) {
            return Err("stock chain descriptor Arc lineage instruction pin drifted");
        }
    }
    for (va, expected) in BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_PINS {
        if le_u32_at(blob, va) != Some(expected) {
            return Err("stock live HashchainManager payload type instruction pin drifted");
        }
    }
    let debug_label_off = first_load_off(BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL_VA)
        .ok_or("stock HashchainManager debug label is outside the first ELF load")?;
    if blob.get(debug_label_off..debug_label_off + BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL.len())
        != Some(BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL)
    {
        return Err("stock HashchainManager debug label drifted");
    }
    if le_u64_at(
        blob,
        BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL_DESCRIPTOR_FILE_OFF,
    ) != Some(BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL_VA)
        || le_u64_at(
            blob,
            BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL_DESCRIPTOR_FILE_OFF + 8,
        ) != Some(BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL.len() as u64)
    {
        return Err("stock HashchainManager debug-label descriptor drifted");
    }
    for (index, expected) in BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_VTABLE_PREFIX
        .into_iter()
        .enumerate()
    {
        if le_u64_at(
            blob,
            BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_VTABLE_FILE_OFF + index as u64 * 8,
        ) != Some(expected)
        {
            return Err("stock HashchainManager type-vtable prefix drifted");
        }
    }
    let evidence = BOSMINER_CHAIN_DESCRIPTOR_ARC_EVIDENCE;
    if evidence.tuner_object_bytes != 0x09A0
        || evidence.descriptor_bytes != 0x38
        || evidence.descriptor_arc_offset != 0x20
        || evidence.descriptor_arc_companion_offset != 0x28
        || evidence.source_owner_offset != 0x0950
        || evidence.source_arc_vec_data_offset != 0x06A8
        || evidence.source_arc_vec_len_offset != 0x06B0
        || evidence.source_arc_companion_offset != 0x0558
        || evidence.descriptor_build_fn_va != 0x007E_9C24
        || evidence.derived_vec_data_offset != 0x07D8
        || evidence.derived_vec_len_offset != 0x07E0
        || evidence.callback_offset != 0x0978
        || evidence.callback_fn_va != 0x0070_A168
        || evidence.callback_dispatch_va != 0x0066_2554
        || evidence.raw_record_arc_offset != 0x0510
        || evidence.concrete_arc_allocation_bytes != Some(0x0570)
        || evidence.concrete_arc_payload_bytes != Some(0x0560)
        || evidence.concrete_arc_payload_prefix_copy_bytes != Some(0x01F0)
        || evidence.concrete_arc_payload_type_name != Some("HashchainManager")
        || evidence.concrete_arc_payload_type_vtable_va != Some(0x019F_B178)
        || evidence.concrete_arc_payload_drop_fn_va != Some(0x00B7_5194)
        || evidence.concrete_arc_payload_debug_fn_va != Some(0x00B5_D364)
        || evidence.resolution_boundary
            != BosminerChainDescriptorArcResolutionBoundary::RawRecordOwnsLiveHashchainManagerDispatchPairIsPrestaged
        || BOSMINER_TUNER_PRIMARY_DESCRIPTOR_VEC_CAP_OFFSET != 0x07B8
        || BOSMINER_TUNER_PRIMARY_DESCRIPTOR_VEC_DATA_OFFSET != 0x07C0
        || BOSMINER_TUNER_PRIMARY_DESCRIPTOR_VEC_LEN_OFFSET != 0x07C8
        || BOSMINER_TUNER_DERIVED_DESCRIPTOR_VEC_CAP_OFFSET != 0x07D0
        || BOSMINER_CHAIN_DESCRIPTOR_COPY_FN_VA != 0x006A_AB08
        || BOSMINER_CHAIN_DESCRIPTOR_FILTER_FN_VA != 0x006C_F9C4
        || BOSMINER_CHAIN_DESCRIPTOR_CLONE_FN_VA != 0x007E_9E30
        || BOSMINER_CHAIN_DESCRIPTOR_COLLECT_FN_VA != 0x007D_EE4C
        || BOSMINER_CHAIN_DESCRIPTOR_TO_RAW_RECORD_FN_VA != 0x006B_51CC
    {
        return Err("stock chain descriptor Arc evidence descriptor drifted");
    }
    Ok(())
}

/// Admit only the live per-chain Arc payload, separate `triggered::Listener`
/// lane, listener slot reuse, payload-hook/prestaged buffer, and locally
/// constructed receiver lineage. The checked endpoint remains a dynamic table
/// dispatch: admission does not prove its concrete method or physical effect.
pub fn admit_bosminer_hashchain_lifecycle_receiver_lineage_static(
    blob: &[u8],
) -> Result<(), &'static str> {
    for (va, expected) in BOSMINER_HASHCHAIN_LIFECYCLE_RECEIVER_LINEAGE_PINS {
        if le_u32_at(blob, va) != Some(expected) {
            return Err("stock hashchain lifecycle receiver lineage instruction pin drifted");
        }
    }
    for (va, expected) in [
        (
            BOSMINER_TRIGGERED_PANIC_STRING_VA,
            BOSMINER_TRIGGERED_PANIC_STRING,
        ),
        (
            BOSMINER_TRIGGERED_SOURCE_STRING_VA,
            BOSMINER_TRIGGERED_SOURCE_STRING,
        ),
    ] {
        let off = first_load_off(va)
            .ok_or("stock triggered::Listener evidence is outside the first ELF load")?;
        if blob.get(off..off + expected.len()) != Some(expected) {
            return Err("stock triggered::Listener source/string evidence drifted");
        }
    }
    let evidence = BOSMINER_HASHCHAIN_LIFECYCLE_RECEIVER_EVIDENCE;
    if evidence.raw_record_bytes != 0x0570
        || evidence.raw_record_arc_offset != 0x0510
        || evidence.arc_build_fn_va != BOSMINER_LIVE_CHAIN_ARC_BUILD_FN_VA
        || evidence.arc_allocation_bytes != 0x0570
        || evidence.arc_align != 0x10
        || evidence.arc_header_bytes != 0x10
        || evidence.arc_payload_bytes != 0x0560
        || evidence.arc_payload_type_name != "HashchainManager"
        || evidence.arc_payload_type_vtable_va != 0x019F_B178
        || evidence.arc_payload_bytes + u16::from(evidence.arc_header_bytes)
            != evidence.arc_allocation_bytes
        || evidence.enabled_allocation_offset != 0x0568
        || evidence.enabled_allocation_offset - u16::from(evidence.arc_header_bytes)
            != BOSMINER_LIVE_CHAIN_PAYLOAD_ENABLED_OFFSET
        || evidence.item_triggered_listener_offset != 0x30
        || evidence.item_payload_offset != 0x0060
        || evidence.listener_type_name != "triggered::Listener"
        || evidence.listener_clone_fn_va != 0x00BB_D3DC
        || evidence.listener_next_id_offset != 0x48
        || evidence.outer_working_listener_offset != 0x0040
        || evidence.outer_retained_payload_offset != 0x0050
        || evidence.outer_nested_future_offset != 0x0070
        || evidence.outer_cloned_listener_offset != 0x03D0
        || evidence.outer_retained_payload_for_nested_offset != 0x03F8
        || evidence.state_listener_input_offset != 0x0360
        || evidence.state_payload_input_offset != 0x0388
        || evidence.state_retained_payload_offset != 0x0370
        || evidence.state_reused_listener_self_slot_offset != 0x03A0
        || evidence.state_dispatch_self_slot_offset != 0x03B8
        || evidence.stack_listener_inner_offset != 0x48
        || evidence.payload_hook_trait_data_offset != 0x0230
        || evidence.payload_hook_trait_vtable_offset != 0x0238
        || evidence.payload_hook_method_slot != 0x18
        || evidence.payload_hook_dispatch_va != 0x0071_A51C
        || evidence.payload_hook_method_vas != [0x0070_539C, 0x0070_57FC]
        || !evidence.payload_hook_is_noop
        || evidence.prestage_vec_source_offset != 0x10
        || evidence.prestage_vec_clone_fn_va != 0x012D_276C
        || evidence.prestage_vec_clone_dispatch_va != 0x0071_9B34
        || evidence.prestaged_data_offset != 0x0538
        || evidence.stack_prestaged_data_offset != 0x0B10
        || evidence.stack_prestaged_dispatch_table_offset != 0x0B18
        || evidence.stack_listener_inner_overwrite_va != 0x0071_A528
        || evidence.local_object_prefix_copy_bytes != 0x01E0
        || evidence.local_object_trait_data_offset != 0x0210
        || evidence.local_object_dispatch_table_offset != 0x0218
        || evidence.method_slot != 0x28
        || evidence.method_dispatch_va != 0x0071_B098
        || evidence.concrete_dispatch_data.is_some()
        || evidence.concrete_dispatch_table_va.is_some()
        || evidence.concrete_method_va.is_some()
        || evidence.resolution_boundary
            != BosminerHashchainLifecycleReceiverResolutionBoundary::PayloadPrestageProviderCandidatesLineageResolvedRuntimeSelectionBytesAndFinalMethodRemainDynamic
        || BOSMINER_RAW_CHAIN_RECORD_ENABLED_OFFSET != evidence.enabled_allocation_offset
        || BOSMINER_LIVE_CHAIN_ITEM_BYTES != 0x06E0
        || BOSMINER_TRIGGERED_INNER_ARC_ALLOCATION_BYTES != 0x58
        || BOSMINER_LIFECYCLE_STATE_INPUT_PAYLOAD_OFFSET != 0x0388
        || BOSMINER_LIFECYCLE_STATE_RETAINED_PAYLOAD_OFFSET != 0x0370
    {
        return Err("stock hashchain lifecycle receiver evidence descriptor drifted");
    }
    Ok(())
}

/// Admit the upstream provenance and finite code-3 identities of the pair
/// installed at `HashchainManager P+0x230/+0x238`. This proves the registry
/// walk, the three sibling provider lanes, the copied-future projection,
/// candidate-vector production, candidate validation, final installation,
/// lifecycle no-op hook, and prestaged pair lineage. The runtime-object footer
/// is a separate control tail, while the active prefix lane carries the
/// selected provider data's `+0x10` Vec through B90c and B879 into manager P
/// `+0x10`. Runtime selection, bytes, and final slot-`+0x28` method remain
/// dynamic; first-success ordering alone does not prove Antminer succeeds.
pub fn admit_bosminer_payload_hook_producer_lineage_static(
    blob: &[u8],
) -> Result<(), &'static str> {
    for (va, expected) in BOSMINER_PAYLOAD_HOOK_PRODUCER_LINEAGE_PINS {
        if le_u32_at(blob, va) != Some(expected) {
            return Err("stock payload-hook producer lineage instruction pin drifted");
        }
    }
    for (va, expected) in BOSMINER_PAYLOAD_HOOK_CODE3_CANDIDATE_PINS {
        if le_u32_at(blob, va) != Some(expected) {
            return Err("stock payload-hook code-3 candidate instruction pin drifted");
        }
    }
    for (va, expected) in BOSMINER_PRESTAGE_VEC_BOUNDARY_PINS {
        if le_u32_at(blob, va) != Some(expected) {
            return Err("stock prestage Vec provenance instruction pin drifted");
        }
    }
    let evidence = BOSMINER_PAYLOAD_HOOK_PRODUCER_EVIDENCE;
    if evidence.registry_select_fn_va != 0x0079_4C48
        || evidence.registry_vec_data_offset != 0x08
        || evidence.registry_vec_len_offset != 0x10
        || evidence.registry_entry_bytes != 0x10
        || evidence.registry_entry_method_slot != 0x30
        || evidence.registry_select_call_vas != [0x0047_1804, 0x004C_1FC8, 0x004E_F814]
        || evidence.selected_pair_offsets != [0x0450, 0x0458]
        || evidence.option_wrap_fn_va != 0x0056_14C0
        || evidence.option_wrap_call_vas != [0x0047_8D30, 0x004C_94F4, 0x004F_6D40]
        || evidence.wrapped_pair_offsets != [0x07C0, 0x07C8]
        || evidence.parent_child_state_offset != 0x0D40
        || evidence.parent_capture_offsets != [0x11F0, 0x11F8]
        || evidence.child_capture_offsets != [0x04B0, 0x04B8]
        || evidence.child_working_offsets != [0x04F0, 0x04F8]
        || evidence.child_method_slot != 0x20
        || evidence.child_dispatch_vas != [0x0047_AB50, 0x004C_B318, 0x004F_8B64]
        || evidence.child_result_offsets != [0x0A00, 0x0A08]
        || evidence.materialize_fn_va != 0x00B2_58B8
        || evidence.materialize_call_vas != [0x0047_BC98, 0x004C_C410, 0x004F_9C5C]
        || evidence.materialize_final_arg_pair_offset != 0x30
        || evidence.materialized_pair_offsets != [0x04C0, 0x04C8]
        || evidence.prefix_copy_bytes != 0x0660
        || evidence.refuted_runtime_object_state_offset != 0x2940
        || evidence.refuted_runtime_object_tail_offsets != [0x50, 0x58]
        || evidence.refuted_main_future_footer_bytes != 0x60
        || evidence.refuted_footer_tail_offsets != [0x50, 0x58]
        || evidence.refuted_rotated_tail_offset != 0x50
        || evidence.b90c_entry_prefix_offset != 0x60
        || evidence.b90c_entry_vec_offset != 0x70
        || evidence.b90c_snapshot_prefix_offset != 0x0730
        || evidence.b90c_owned_prefix_offset != 0x0E10
        || evidence.b879_input_prefix_offset != 0x00
        || evidence.b879_snapshot_prefix_offset != 0x06E0
        || evidence.b879_clone_stack_offset != 0x0BF0
        || evidence.b879_clone_forward_cap_data_stack_offset != 0x0BD0
        || evidence.b879_clone_forward_len_stack_offset != 0x0BE0
        || evidence.b879_clone_later_overwrite_fn_va != 0x00B6_00A4
        || evidence.payload_prefix_source_stack_offset != 0x0A20
        || evidence.payload_vec_stack_offsets != [0x0A30, 0x0A38, 0x0A40]
        || evidence.payload_prefix_staging_stack_offset != 0x0C10
        || evidence.payload_prefix_staging_bytes != 0x0190
        || evidence.payload_prefix_constructor_arg_index != 7
        || !evidence.b90c_clone_reaches_payload_prefix
        || evidence.prestage_provider_pair_state_offsets != [0x04B0, 0x04B8]
        || evidence.prestage_provider_method_slot != 0x18
        || evidence.prestage_provider_preserved_data_state_offset != 0x0EA8
        || evidence.prestage_provider_data_clone_fn_va != 0x0046_8B24
        || evidence.prestage_provider_prefix_clone_fn_va != 0x0046_85AC
        || evidence.prestage_provider_vec_offset != 0x10
        || evidence.prestage_materializer_input_prefix_bytes != 0x02A0
        || evidence.prestage_materialized_prefix_bytes != 0x0660
        || evidence.hashchain_manager_vec_offsets != [0x10, 0x18, 0x20]
        || evidence.hashchain_manager_drop_fn_va != 0x00B7_5924
        || evidence.main_future_build_fn_va != 0x00B2_6FE8
        || evidence.main_future_build_call_vas != [0x0047_CDB0, 0x004C_D4E8, 0x004F_AD34]
        || evidence.main_future_poll_fn_va != 0x00B2_70B4
        || evidence.main_future_snapshot_offset != 0x06C0
        || evidence.main_future_snapshot_pair_offsets != [0x0B80, 0x0B88]
        || evidence.listener_build_fn_va != 0x00B8_7980
        || evidence.listener_snapshot_offset != 0x06E0
        || evidence.listener_source_pair_offsets != [0x04C0, 0x04C8]
        || evidence.listener_working_pair_offsets != [0x0BA0, 0x0BA8]
        || evidence.listener_method_slot != 0x18
        || evidence.listener_dispatch_va != 0x00B8_7AE4
        || evidence.candidate_bytes != 0x10
        || evidence.selected_candidate_offsets != [0x0E20, 0x0E28]
        || evidence.candidate_validate_method_slot != 0x28
        || evidence.candidate_validate_dispatch_va != 0x00B8_96F4
        || evidence.payload_candidate_offsets != [0x0230, 0x0238]
        || evidence.code3_builder_vtable_vas != [0x019A_C828, 0x019A_C880]
        || evidence.code3_provider_vtable_vas != [0x019A_C978, 0x019A_C9B8]
        || evidence.candidate_validate_method_vas != [0x0070_A82C, 0x0070_A824]
        || evidence.lifecycle_hook_method_vas != [0x0070_539C, 0x0070_57FC]
        || evidence.child_method_vas != [0x0070_53A0, 0x0070_5800]
        || evidence.child_result_bytes != [0x0340, 0x0300]
        || evidence.child_result_vtable_vas != [0x019A_CE50, 0x019A_CE70]
        || evidence.lifecycle_hook_disposition
            != BosminerPayloadHookDisposition::NoOpRetainsPrestagedPair
        || evidence.prestage_vec_source_offset != 0x10
        || evidence.prestage_vec_clone_fn_va != 0x012D_276C
        || evidence.prestage_vec_clone_dispatch_va != 0x0071_9B34
        || evidence.prestaged_data_offset != 0x0538
        || evidence.concrete_prestaged_dispatch_table_va.is_some()
        || evidence.resolution_boundary
            != BosminerPayloadHookProducerResolutionBoundary::Code3FirstSuccessProviderCandidatesAndPrestageLineageResolvedRuntimeSelectionBytesAndFinalMethodRemainDynamic
    {
        return Err("stock payload-hook producer evidence descriptor drifted");
    }
    Ok(())
}

/// Admit only the exact serde-visible stock `FanStatus` schema. The serializer
/// exposes two counters and three booleans, while the hashchain gate reads an
/// enclosing watch-snapshot byte at `+0x16c`; no exact cross-layout field join
/// is asserted here.
pub fn admit_bosminer_fan_status_schema_static(blob: &[u8]) -> Result<(), &'static str> {
    let type_off = first_load_off(BOSMINER_FAN_STATUS_TYPE_NAME_VA)
        .ok_or("stock FanStatus type name is outside the first ELF load")?;
    if blob.get(type_off..type_off + BOSMINER_FAN_STATUS_TYPE_NAME.len())
        != Some(BOSMINER_FAN_STATUS_TYPE_NAME)
    {
        return Err("stock FanStatus type name drifted");
    }
    for field in BOSMINER_FAN_STATUS_FIELDS {
        let off = first_load_off(field.name_va)
            .ok_or("stock FanStatus field name is outside the first ELF load")?;
        if blob.get(off..off + field.name.len()) != Some(field.name) {
            return Err("stock FanStatus field name drifted");
        }
    }
    for (va, expected) in BOSMINER_FAN_STATUS_SERIALIZER_PINS {
        if le_u32_at(blob, va) != Some(expected) {
            return Err("stock FanStatus serializer instruction pin drifted");
        }
    }
    if BOSMINER_HASHCHAIN_FAN_READY_SNAPSHOT_STATUS_BYTE_OFFSET != 0x016C
        || BOSMINER_FAN_STATUS_FIELDS.map(|field| field.value_offset)
            != [0x00, 0x08, 0x10, 0x11, 0x12]
    {
        return Err("stock FanStatus layout descriptor drifted");
    }
    Ok(())
}

/// Stock's exact post-baud path is useful negative evidence, not permission
/// for DCENT_OS to omit validation. A native executor must obtain a fresh
/// response at the switched host/ASIC baud and fail closed before work TX.
pub fn refuse_bosminer_post_baud_path_as_fresh_validation() -> Result<(), &'static str> {
    Err(
        "stock host-baud success proceeds through slot +0x78 no-I/O into per-chip writes; DCENT_OS requires a fresh post-switch response before work TX",
    )
}

/// Observation after an S19k host/ASIC baud decision. This is not Track-1
/// [`crate::s19k_passthrough_preflight::S19kDualBaudWorkTxKind::ChipProofAt3M`]:
/// passthrough must not switch baud, and a native fresh response is not a
/// Braiins handoff admit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kPostBaudObservation {
    /// Track-1 inherited 3M; DCENT did not switch host baud.
    HostBaudUnchangedPassthrough,
    /// Native host/ASIC baud was switched and a fresh chip response was
    /// admitted at the current baud.
    FreshSwitchedBaudResponseAdmitted,
    /// Native baud was switched but no fresh chip response was admitted.
    SwitchedBaudWithoutFreshResponse,
    /// Native path did not switch baud. That is not a post-switch proof.
    NativeHostBaudUnchangedIsNotPostSwitchProof,
}

/// Work-TX policy after [`classify_s19k_post_baud_observation`]. A native
/// fresh-response admit is still not production (`refuse_native_as_production`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kPostBaudWorkTxDisposition {
    /// Passthrough work TX stays the separate ChipProofAt3M gate.
    PassthroughChipProofSeparate,
    /// Native 21 36 is still experimental and still production-refused.
    NativeWorkTxAllowedAfterFreshResponse,
    /// Native 21 36 is forbidden; rollback before fill.
    FailClosedRollbackBeforeWorkTx,
}

/// Classify a post-baud observation from the real dialect and two measured
/// booleans. Passthrough must not switch host baud.
pub fn classify_s19k_post_baud_observation(
    dialect: S19kInitDialect,
    host_baud_changed: bool,
    fresh_chip_response_at_current_baud: bool,
) -> Result<S19kPostBaudObservation, &'static str> {
    match dialect {
        S19kInitDialect::BraiinsPassthrough => {
            if host_baud_changed {
                return Err("passthrough must not switch host baud; refuse post-baud native gate as Track-1");
            }
            let _ = fresh_chip_response_at_current_baud;
            Ok(S19kPostBaudObservation::HostBaudUnchangedPassthrough)
        }
        S19kInitDialect::NativeExperimental => {
            if !host_baud_changed {
                return Ok(S19kPostBaudObservation::NativeHostBaudUnchangedIsNotPostSwitchProof);
            }
            if fresh_chip_response_at_current_baud {
                Ok(S19kPostBaudObservation::FreshSwitchedBaudResponseAdmitted)
            } else {
                Ok(S19kPostBaudObservation::SwitchedBaudWithoutFreshResponse)
            }
        }
    }
}

pub fn s19k_post_baud_work_tx_disposition(
    dialect: S19kInitDialect,
    observation: S19kPostBaudObservation,
) -> S19kPostBaudWorkTxDisposition {
    match dialect {
        S19kInitDialect::BraiinsPassthrough => {
            S19kPostBaudWorkTxDisposition::PassthroughChipProofSeparate
        }
        S19kInitDialect::NativeExperimental => match observation {
            S19kPostBaudObservation::FreshSwitchedBaudResponseAdmitted => {
                S19kPostBaudWorkTxDisposition::NativeWorkTxAllowedAfterFreshResponse
            }
            S19kPostBaudObservation::HostBaudUnchangedPassthrough
            | S19kPostBaudObservation::SwitchedBaudWithoutFreshResponse
            | S19kPostBaudObservation::NativeHostBaudUnchangedIsNotPostSwitchProof => {
                S19kPostBaudWorkTxDisposition::FailClosedRollbackBeforeWorkTx
            }
        },
    }
}

/// Native 21 36 requires a fresh switched-baud response. Passthrough is not
/// this gate. A pass is still not production.
pub fn admit_s19k_native_work_tx_after_post_baud(
    dialect: S19kInitDialect,
    observation: S19kPostBaudObservation,
) -> Result<(), &'static str> {
    match s19k_post_baud_work_tx_disposition(dialect, observation) {
        S19kPostBaudWorkTxDisposition::NativeWorkTxAllowedAfterFreshResponse => Ok(()),
        S19kPostBaudWorkTxDisposition::PassthroughChipProofSeparate => {
            Err("passthrough work TX is ChipProofAt3M, not a native post-baud admit")
        }
        S19kPostBaudWorkTxDisposition::FailClosedRollbackBeforeWorkTx => Err(
            "native work TX refused: no fresh switched-baud response; fail-closed rollback before 21 36",
        ),
    }
}

/// A native post-baud admit is still not production BM1366 mining.
pub fn refuse_native_post_baud_pass_as_production(
    dialect: S19kInitDialect,
    observation: S19kPostBaudObservation,
) -> Result<(), &'static str> {
    if admit_s19k_native_work_tx_after_post_baud(dialect, observation).is_ok() {
        return Err(
            "native fresh switched-baud response is still EXPERIMENTAL; production refuses native BM1366",
        );
    }
    Err("native post-baud did not admit work TX; production refuse is a separate gate")
}

/// Failed native post-baud is rollback, never 21 36 fill.
pub fn s19k_post_baud_failure_is_rollback_not_work_tx(
    disposition: S19kPostBaudWorkTxDisposition,
) -> bool {
    disposition == S19kPostBaudWorkTxDisposition::FailClosedRollbackBeforeWorkTx
}

/// The UART-byte native program is not a post-baud response gate.
pub fn admit_s19k_native_init_program_lacks_post_baud_response_barrier() -> Result<(), &'static str>
{
    let program = s19k_bm1366_init_program(S19kInitDialect::NativeExperimental);
    if program
        .iter()
        .any(|step| step.name.contains("post_baud") || step.name.contains("response_gate"))
    {
        return Err("native UART dump must not be relabeled as a post-baud response gate");
    }
    if !program.iter().any(|step| step.name == "get_address") {
        return Err("native experimental program must still start at GetAddress");
    }
    Ok(())
}

pub fn refuse_s19k_native_init_program_as_work_tx_grant() -> Result<(), &'static str> {
    admit_s19k_native_init_program_lacks_post_baud_response_barrier()?;
    Err(
        "native init program has no post-baud response barrier; work TX requires classify_s19k_post_baud_observation plus fail-closed rollback",
    )
}

pub fn refuse_stock_post_baud_omission_as_native_work_tx_grant() -> Result<(), &'static str> {
    match refuse_bosminer_post_baud_path_as_fresh_validation() {
        Err(_) => Err("stock omitted post-baud check is not DCENT native work-TX authority"),
        Ok(()) => Err("stock post-baud refuse must stay fail-closed"),
    }
}

/// Production native BM1366 transport exists only behind the exact default-off
/// request and retained joined owner. This source admission grants no live
/// authority and rejects a test-only token issuer.
pub fn admit_s19k_production_native_transport_requires_joined_owner(
    src: &str,
) -> Result<(), &'static str> {
    if !src.contains("DCENT_S19K_NATIVE_COLD_START")
        || !src.contains("S19kNativeColdStartOwner")
        || !src.contains("native_exact_mapping: true")
        || !src.contains("shutdown arrived during native S19k population cold init")
    {
        return Err("production native BM1366 transport lacks its exact joined owner");
    }
    if src.contains("issue_s19k_native_pre_serial_for_test") {
        return Err("test-only native authority issuer reached production source");
    }
    Ok(())
}

/// A stock start/reset/init lifecycle is not evidence of terminal power-down.
/// NoPIC APW control, GPIO437 polarity/readback, rail decay, fan custody, and
/// faulted-path closeout still require a physical SafeOff proof.
pub fn refuse_bosminer_stock_lifecycle_as_safeoff_proof() -> Result<(), &'static str> {
    Err(
        "stock lifecycle retry/timeout evidence is not SafeOff proof; APW, GPIO437, rail decay, cooling custody, and terminal closeout remain live gates",
    )
}

/// The exact live Arc payload, separate `triggered::Listener` lane, local-self
/// overwrite, finite code-3 candidates, no-op hooks, and prestaged pair
/// transfer are recovered, but the cloned dispatch-table contents and final
/// method remain unresolved. Do not promote pointer continuity into GPIO
/// authority.
pub fn refuse_bosminer_hashchain_lifecycle_receiver_as_concrete_gpio_authority(
) -> Result<(), &'static str> {
    Err(
        "stock item+0x30 is a separate triggered::Listener lane; its inner pointer is only temporary at sp+0x48 and is consumed at 0x0071a2d8; code-3 first-success can select Antminer provider vtable 0x019ac978 or Braiins Fixture provider vtable 0x019ac9b8 depending on runtime success, and both slot +0x18 methods are one-instruction no-ops (FUN_0070539c/FUN_007057fc); either no-op retains prestaged {data=P+0x538, dispatch_table=clone(P+0x10).data}, which becomes local +0x210/+0x218; the B90c/B879 clone cap/data/len reaches manager P+0x10/+0x18/+0x20 through sp+0xa30/+0xa38/+0xa40 before the old sp+0xbf0 slot is reused; P+0x1c0 is not the receiver; cloned-table slot +0x28 is followed by slot +0x48 on the same pair; runtime provider selection, P+0x10 bytes, concrete slot methods, GPIO, polarity, pulse, electrical reset, and power/reset transaction remain unproven",
    )
}

fn aarch64_ldr64_unsigned_imm(word: u32) -> Option<(u8, u8, u16)> {
    if word & 0xFFC0_0000 != 0xF940_0000 {
        return None;
    }
    let rt = (word & 0x1F) as u8;
    let rn = ((word >> 5) & 0x1F) as u8;
    let imm = (((word >> 10) & 0xFFF) * 8) as u16;
    Some((rt, rn, imm))
}

fn aarch64_str64_unsigned_imm(word: u32) -> Option<(u8, u8, u16)> {
    if word & 0xFFC0_0000 != 0xF900_0000 {
        return None;
    }
    let rt = (word & 0x1F) as u8;
    let rn = ((word >> 5) & 0x1F) as u8;
    let imm = (((word >> 10) & 0xFFF) * 8) as u16;
    Some((rt, rn, imm))
}

fn aarch64_movz_w_imm(word: u32) -> Option<u16> {
    if word & 0xFF80_0000 != 0x5280_0000 {
        return None;
    }
    if (word >> 21) & 0x3 != 0 {
        return None;
    }
    Some(((word >> 5) & 0xFFFF) as u16)
}

fn aarch64_b_target(va: u64, word: u32) -> Option<u64> {
    if word & 0xFC00_0000 != 0x1400_0000 {
        return None;
    }
    let imm26 = i64::from(word & 0x03FF_FFFF);
    let signed = if imm26 & (1 << 25) != 0 {
        imm26 - (1 << 26)
    } else {
        imm26
    };
    Some(va.wrapping_add((signed * 4) as u64))
}

fn aarch64_add_imm12(word: u32) -> Option<(u8, u8, u16)> {
    if word & 0xFF00_0000 != 0x9100_0000 {
        return None;
    }
    let rd = (word & 0x1F) as u8;
    let rn = ((word >> 5) & 0x1F) as u8;
    let mut imm = ((word >> 10) & 0xFFF) as u16;
    if (word >> 22) & 1 == 1 {
        imm = imm.checked_shl(12)?;
    }
    Some((rd, rn, imm))
}

fn cloned_table_step_matches_pins(
    blob: &[u8],
    step: &BosminerClonedTableDispatchStep,
    table_off: u16,
    data_off: u16,
) -> Result<(), &'static str> {
    let table = le_u32_at(blob, step.table_load_va)
        .and_then(aarch64_ldr64_unsigned_imm)
        .ok_or("cloned-table table load is not LDR Xt, [Xn, #imm]")?;
    if table.2 != table_off {
        return Err("cloned-table table load offset drifted");
    }
    let data = le_u32_at(blob, step.data_load_va)
        .and_then(aarch64_ldr64_unsigned_imm)
        .ok_or("cloned-table data load is not LDR Xt, [Xn, #imm]")?;
    if data.2 != data_off {
        return Err("cloned-table data load offset drifted");
    }
    let slot = le_u32_at(blob, step.slot_load_va)
        .and_then(aarch64_ldr64_unsigned_imm)
        .ok_or("cloned-table slot load is not LDR Xt, [Xn, #imm]")?;
    if slot.2 != u16::from(step.slot)
        || step.slot_load_word != le_u32_at(blob, step.slot_load_va).unwrap_or(0)
    {
        return Err("cloned-table slot load offset drifted");
    }
    if le_u32_at(blob, step.blr_va) != Some(0xD63F_0100) {
        return Err("cloned-table slot BLR drifted");
    }
    let data_store_va = match step.slot {
        0x28 => 0x0071_B09C,
        0x48 => 0x0071_B12C,
        _ => return Err("cloned-table result store is only admitted for slots +0x28 and +0x48"),
    };
    let vtable_store_va = match step.slot {
        0x28 => 0x0071_B0A4,
        0x48 => 0x0071_B130,
        _ => return Err("cloned-table result store is only admitted for slots +0x28 and +0x48"),
    };
    let data_store = le_u32_at(blob, data_store_va)
        .and_then(aarch64_str64_unsigned_imm)
        .ok_or("cloned-table result data store is not STR")?;
    let vtable_store = le_u32_at(blob, vtable_store_va)
        .and_then(aarch64_str64_unsigned_imm)
        .ok_or("cloned-table result vtable store is not STR")?;
    if data_store.2 != step.result_data_state_offset
        || vtable_store.2 != step.result_vtable_state_offset
    {
        return Err("cloned-table result pair state offsets drifted");
    }
    let poll = le_u32_at(blob, step.poll_blr_va.wrapping_sub(8))
        .and_then(aarch64_ldr64_unsigned_imm)
        .ok_or("cloned-table poll load is not LDR")?;
    if poll.2 != u16::from(step.poll_slot) {
        return Err("cloned-table returned poll is not slot +0x18");
    }
    if le_u32_at(blob, step.poll_blr_va) != Some(0xD63F_0100) {
        return Err("cloned-table returned poll BLR drifted");
    }
    if aarch64_movz_w_imm(le_u32_at(blob, step.fail_imm_va).unwrap_or(0))
        != Some(u16::from(step.fail_imm))
    {
        return Err("cloned-table fail immediate drifted");
    }
    if aarch64_b_target(
        step.fail_imm_va + 4,
        le_u32_at(blob, step.fail_imm_va + 4).unwrap_or(0),
    ) != Some(step.fail_branch_va)
    {
        return Err("cloned-table fail branch target drifted");
    }
    Ok(())
}

/// Admit the exact cloned-table two-slot sequence from the held ELF bytes.
/// Slot `+0x28` is not terminal; slot `+0x48` follows on the same pair.
/// This does not recover a concrete method VA or GPIO/electrical authority.
pub fn admit_bosminer_cloned_table_two_slot_sequence_static(
    blob: &[u8],
) -> Result<(), &'static str> {
    let evidence = BOSMINER_CLONED_TABLE_TWO_SLOT_SEQUENCE_EVIDENCE;
    for (va, expected) in BOSMINER_CLONED_TABLE_TWO_SLOT_SEQUENCE_PINS {
        if le_u32_at(blob, va) != Some(expected) {
            return Err("stock cloned-table two-slot sequence pin drifted");
        }
    }
    if evidence.local_data_offset != 0x0210
        || evidence.local_table_offset != 0x0218
        || evidence.self_slot_offset != 0x03A0
        || evidence.first.slot != 0x28
        || evidence.second.slot != 0x48
        || evidence.first.poll_slot != 0x18
        || evidence.second.poll_slot != 0x18
        || evidence.first.fail_imm != 4
        || evidence.second.fail_imm != 5
        || evidence.first.blr_va != 0x0071_B098
        || evidence.second.blr_va != 0x0071_B128
        || evidence.refused_slot_0x50_source_offset != 0x03C0
        || evidence.refused_slot_0x50_ldp_va != 0x0071_B218
        || evidence.distinct_pair_data_offset != 0x0220
        || evidence.distinct_pair_table_offset != 0x0228
        || evidence.distinct_pair_slot != 0x20
        || evidence.concrete_method_va.is_some()
        || BOSMINER_CLONED_TABLE_TWO_SLOT_SEQUENCE_PINS.len() != 40
    {
        return Err("cloned-table two-slot sequence descriptor drifted");
    }
    let self_add = le_u32_at(blob, 0x0071_AAF0)
        .and_then(aarch64_add_imm12)
        .ok_or("X22 self-slot ADD drifted")?;
    if self_add != (22, 19, evidence.self_slot_offset) {
        return Err("X22 is not X19+0x3a0 for the second cloned-table reload");
    }
    cloned_table_step_matches_pins(
        blob,
        &evidence.first,
        evidence.local_table_offset,
        evidence.local_data_offset,
    )?;
    cloned_table_step_matches_pins(
        blob,
        &evidence.second,
        evidence.local_table_offset,
        evidence.local_data_offset,
    )?;
    let slot50_src = le_u32_at(blob, 0x0071_B210)
        .and_then(aarch64_ldr64_unsigned_imm)
        .ok_or("slot +0x50 source load drifted")?;
    if slot50_src.2 != evidence.refused_slot_0x50_source_offset {
        return Err("slot +0x50 source is not overwritten state +0x3c0");
    }
    let slot50 = le_u32_at(blob, evidence.refused_slot_0x50_load_va)
        .and_then(aarch64_ldr64_unsigned_imm)
        .ok_or("slot +0x50 load drifted")?;
    if slot50.2 != 0x50 {
        return Err("refused slot +0x50 load offset drifted");
    }
    if le_u32_at(blob, evidence.refused_slot_0x50_ldp_va) != Some(0xA943_A500) {
        return Err("slot +0x50 LDP from overwritten +0x3c0 drifted");
    }
    let distinct_table = le_u32_at(blob, 0x0071_B7F4)
        .and_then(aarch64_ldr64_unsigned_imm)
        .ok_or("distinct-pair table load drifted")?;
    let distinct_data = le_u32_at(blob, 0x0071_B7F8)
        .and_then(aarch64_ldr64_unsigned_imm)
        .ok_or("distinct-pair data load drifted")?;
    let distinct_slot = le_u32_at(blob, 0x0071_B7FC)
        .and_then(aarch64_ldr64_unsigned_imm)
        .ok_or("distinct-pair slot load drifted")?;
    if distinct_table.2 != evidence.distinct_pair_table_offset
        || distinct_data.2 != evidence.distinct_pair_data_offset
        || distinct_slot.2 != u16::from(evidence.distinct_pair_slot)
        || le_u32_at(blob, evidence.distinct_pair_blr_va) != Some(0xD63F_0100)
    {
        return Err("distinct local pair +0x220/+0x228 slot +0x20 drifted");
    }
    Ok(())
}

/// Slot `+0x28` is followed by slot `+0x48` on the same cloned pair.
pub fn refuse_bosminer_cloned_table_slot_0x28_as_terminal_dispatch() -> Result<(), &'static str> {
    let evidence = BOSMINER_CLONED_TABLE_TWO_SLOT_SEQUENCE_EVIDENCE;
    if evidence.second.slot != 0x48 || evidence.first.slot != 0x28 {
        return Err("cloned-table two-slot sequence lost slot +0x48 after +0x28");
    }
    if evidence.second.blr_va <= evidence.first.blr_va {
        return Err("cloned-table slot +0x48 must execute after slot +0x28");
    }
    Err(
        "cloned-table slot +0x28 is followed by slot +0x48 on the same local +0x210/+0x218 pair; it is not the terminal cloned-table dispatch",
    )
}

/// Slot `+0x50` is reached from overwritten state `+0x3c0`, not the cloned pair.
pub fn refuse_bosminer_cloned_table_slot_0x50_as_same_pair() -> Result<(), &'static str> {
    let evidence = BOSMINER_CLONED_TABLE_TWO_SLOT_SEQUENCE_EVIDENCE;
    if evidence.refused_slot_0x50_source_offset == evidence.local_table_offset {
        return Err("slot +0x50 source must not be relabeled as cloned +0x218");
    }
    Err(
        "slot +0x50 loads via LDP from overwritten state +0x3c0 after the +0x48 result is dropped; it is not the cloned +0x210/+0x218 table",
    )
}

/// Slot `+0x20` dispatches a distinct local pair, not cloned `P+0x10`.
pub fn refuse_bosminer_cloned_table_slot_0x20_as_cloned_p10_table() -> Result<(), &'static str> {
    let evidence = BOSMINER_CLONED_TABLE_TWO_SLOT_SEQUENCE_EVIDENCE;
    if evidence.distinct_pair_table_offset == evidence.local_table_offset {
        return Err("slot +0x20 pair must stay distinct from cloned +0x218");
    }
    Err(
        "slot +0x20 dispatches the distinct local pair at +0x220/+0x228, not cloned P+0x10 table at +0x210/+0x218",
    )
}

/// The exact captured S19k policy set `min_fans=0`. Therefore its stock
/// `Fans OK` gate cannot establish a positive fan-count invariant, even though
/// the same resolved configuration carries a 2,000 RPM threshold. DCENT_OS
/// must retain independent positive per-channel tach/RPM freshness and must
/// not relabel tach motion as proof of physical airflow rate.
pub fn refuse_bosminer_s19k_fan_gate_as_positive_cooling_proof() -> Result<(), &'static str> {
    Err(
        "captured stock S19k fan policy has min_fans=0; Fans OK is not positive fan-count, fresh per-channel RPM/tach, or physical-airflow proof",
    )
}

/// `FUN_0071ede4` is the chip telemetry watchdog. Its one-second sleep is
/// telemetry cadence and must not be reused as reset or start retry timing.
pub fn refuse_bosminer_telemetry_cadence_as_retry_delay() -> Result<(), &'static str> {
    Err("FUN_0071ede4 one-second sleep is telemetry cadence, not reset/start retry delay")
}

/// The stock dispatch manifest is descriptive evidence only. It lacks the
/// complete power/reset/host-switch/validation/rollback contract and must not
/// be treated as a native cold-init execution authority.
pub fn refuse_bosminer_bm1366_stock_init_manifest_as_executable() -> Result<(), &'static str> {
    Err(
        "stock BM1366 execution/register order is evidence-only; platform power, validation, rollback, and SafeOff contracts refuse native execution",
    )
}

/// Loc table at `0x19c4590`: `FUN_008b1b98` + `bm1398.rs` (len 0x36). Not a vtable.
pub fn admit_bosminer_write_loc_is_bm1398_rs(blob: &[u8]) -> Result<(), &'static str> {
    let fn_ptr = le_u64_at(blob, BOSMINER_WRITE_LOC_PTR_FILE_OFF)
        .ok_or("bosminer shorter than write loc ptr")?;
    if fn_ptr != BOSMINER_COMMAND_RS_WRITE_FN_VA {
        return Err("write loc qword is not FUN_008b1b98");
    }
    let str_va = le_u64_at(blob, BOSMINER_WRITE_LOC_PTR_FILE_OFF + 8)
        .ok_or("bosminer shorter than write loc str")?;
    if str_va != BOSMINER_BM1398_RS_LOC_STR_VA {
        return Err("write loc filename VA is not bm1398.rs");
    }
    let str_len = le_u64_at(blob, BOSMINER_WRITE_LOC_PTR_FILE_OFF + 16)
        .ok_or("bosminer shorter than write loc len")?;
    if str_len != u64::from(BOSMINER_BM1398_RS_LOC_STR_LEN) {
        return Err("write loc filename len is not 0x36");
    }
    let s_off = BOSMINER_BM1398_RS_LOC_STR_FILE_OFF as usize;
    let want = BOSMINER_BM1398_RS_LOC_STR;
    if blob.get(s_off..s_off + want.len()) != Some(want) {
        return Err("file 0xf21135 is not bosminer-am2-s17 hashchain/bm1398.rs");
    }
    Ok(())
}

/// Same loc filename as the write FN.
pub fn admit_bosminer_read_loc_is_bm1398_rs(blob: &[u8]) -> Result<(), &'static str> {
    let fn_ptr = le_u64_at(blob, BOSMINER_READ_LOC_PTR_FILE_OFF)
        .ok_or("bosminer shorter than read loc ptr")?;
    if fn_ptr != BOSMINER_BM1398_READ_FN_VA {
        return Err("read loc qword is not FUN_008b2b34");
    }
    let str_va = le_u64_at(blob, BOSMINER_READ_LOC_PTR_FILE_OFF + 8)
        .ok_or("bosminer shorter than read loc str")?;
    if str_va != BOSMINER_BM1398_RS_LOC_STR_VA {
        return Err("read loc filename VA is not bm1398.rs");
    }
    Ok(())
}

/// 3 `BL` to the 4-byte packer, all inside the bm1398 write/read bodies.
pub fn admit_bosminer_pack_bl_sites() -> Result<(), &'static str> {
    if BOSMINER_PACK_BL_HITS != 3 {
        return Err("pack BL census drifted");
    }
    if BOSMINER_PACK_BL_VA[0] != BOSMINER_COMMAND_RS_WRITE_FN_VA + 0x1E8 {
        return Err("first pack BL is not WRITE+0x1e8");
    }
    if BOSMINER_PACK_BL_VA[1] != BOSMINER_BM1398_READ_FN_VA + 0x260 {
        return Err("second pack BL is not READ+0x260");
    }
    if BOSMINER_PACK_BL_VA[2] != BOSMINER_BM1398_READ_FN_VA + 0x3B4 {
        return Err("third pack BL is not READ+0x3b4");
    }
    Ok(())
}

///  named this command.rs. Loc table is bm1398.rs. Not S19k AML.
pub fn refuse_command_rs_write_as_s19k_aml_set_config() -> Result<(), &'static str> {
    Err("FUN_008b1b98 loc is bosminer-am2-s17 hashchain/bm1398.rs; 0 BL; not S19k AML set_config")
}

/// Pack helper is only BL-called from that bm1398 write/read pair.
pub fn refuse_pack_fn_as_s19k_exclusive_set_config() -> Result<(), &'static str> {
    Err(
        "FUN_008a8d28 has 3 BL (WRITE+0x1e8 / READ+0x260 / READ+0x3b4) in bm1398.rs; not S19k AML exclusive",
    )
}

/// The DATA qword is a rustc loc record, not a dispatch vtable.
pub fn refuse_write_loc_ptr_as_aml_vtable() -> Result<(), &'static str> {
    Err("u64 @ 0x19c4590 is fn+bm1398.rs loc (len 0x36); not an AML write_reg vtable")
}

fn first_load_off(va: u64) -> Option<usize> {
    va.checked_sub(0x400_000).map(|o| o as usize)
}

fn le_u32_at(blob: &[u8], va: u64) -> Option<u32> {
    let i = first_load_off(va)?;
    blob.get(i..i + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
}

fn aarch64_direct_bl_target(va: u64, word: u32) -> Option<u64> {
    if word & 0xFC00_0000 != 0x9400_0000 {
        return None;
    }
    let imm26 = i64::from(word & 0x03FF_FFFF);
    let signed_imm26 = if imm26 & 0x0200_0000 != 0 {
        imm26 - 0x0400_0000
    } else {
        imm26
    };
    Some((va as i64 + signed_imm26 * 4) as u64)
}

/// Source record followed by the first hashchain/bm1366.rs future vtable.
pub fn admit_bosminer_bm1366_first_method_loc(blob: &[u8]) -> Result<(), &'static str> {
    let s_off = BOSMINER_BM1366_RS_LOC_STR_FILE_OFF as usize;
    let want = BOSMINER_BM1366_RS_LOC_STR;
    if blob.get(s_off..s_off + want.len()) != Some(want) {
        return Err("file 0xf232f5 is not hashchain/bm1366.rs");
    }
    let str_va = le_u64_at(blob, BOSMINER_BM1366_FIRST_METHOD_LOC_FILE_OFF)
        .ok_or("bosminer shorter than bm1366 first-method source")?;
    if str_va != BOSMINER_BM1366_RS_LOC_STR_VA {
        return Err("bm1366 first-method source filename VA mismatch");
    }
    let str_len = le_u64_at(blob, BOSMINER_BM1366_FIRST_METHOD_LOC_FILE_OFF + 8)
        .ok_or("bosminer shorter than bm1366 source len")?;
    if str_len != u64::from(BOSMINER_BM1366_RS_LOC_STR_LEN) {
        return Err("bm1366 first-method source filename len is not 54");
    }
    let line_col = le_u64_at(blob, BOSMINER_BM1366_FIRST_METHOD_LOC_FILE_OFF + 16)
        .ok_or("bosminer shorter than bm1366 source line")?;
    if line_col
        != (u64::from(BOSMINER_BM1366_FIRST_METHOD_LOC_LINE)
            | (u64::from(BOSMINER_BM1366_FIRST_METHOD_LOC_COL) << 32))
    {
        return Err("bm1366 first-method source is not line 93 column 64");
    }
    let fn_ptr = le_u64_at(blob, BOSMINER_BM1366_FIRST_METHOD_VTABLE_FILE_OFF + 24)
        .ok_or("bosminer shorter than bm1366 first-method vtable")?;
    if fn_ptr != BOSMINER_BM1366_FIRST_METHOD_FN_VA {
        return Err("bm1366 first-method vtable poll is not FUN_008dcfbc");
    }
    Ok(())
}

/// `FUN_008d823c` shares PACK's `LDRB [X0,#0x70]` then `BLR X8`.
pub fn admit_bosminer_bm1366_packed_dispatch(blob: &[u8]) -> Result<(), &'static str> {
    let ldrb = le_u32_at(blob, BOSMINER_BM1366_PACKED_DISPATCH_LDRB_VA)
        .ok_or("bosminer shorter than dispatch LDRB")?;
    if ldrb != BOSMINER_BM1366_PACKED_DISPATCH_LDRB_INSN {
        return Err("FUN_008d823c+8 is not LDRB W8,[X0,#0x70]");
    }
    let pack_ldrb =
        le_u32_at(blob, BOSMINER_PACK_LDRB_VA).ok_or("bosminer shorter than pack LDRB")?;
    if pack_ldrb != BOSMINER_BM1366_PACKED_DISPATCH_LDRB_INSN {
        return Err("FUN_008a8d28+0xc is not the same LDRB [X0,#0x70]");
    }
    let blr = le_u32_at(blob, BOSMINER_BM1366_PACKED_DISPATCH_BLR_VA)
        .ok_or("bosminer shorter than dispatch BLR")?;
    if blr != BOSMINER_BM1366_PACKED_DISPATCH_BLR_INSN {
        return Err("FUN_008d823c+0x30 is not BLR X8");
    }
    Ok(())
}

/// Hashchain/bm1366.rs methods do not `BL` the bm1398 pack/write/send FNs.
pub fn refuse_bm1366_loc_fns_as_direct_pack_callers() -> Result<(), &'static str> {
    Err("6 hashchain/bm1366.rs poll FNs have 0 BL to PACK/WRITE/BE4; they BLR via FUN_008d823c")
}

/// The dispatch is enum/vtable, not a named FastUART 51 09 00 28 writer.
pub fn refuse_bm1366_packed_dispatch_as_named_fastuart() -> Result<(), &'static str> {
    Err(
        "FUN_008d823c is packed_struct LDRB#0x70 + BLR X8 (48 BL, 39 in bm1366 cluster); not a static FastUART set_config",
    )
}

/// Tag at `+0x70` is 3 or 4. `B.EQ` tag3 / `CMP #4` encodings.
pub fn admit_bosminer_dispatch_tag_3_or_4(blob: &[u8]) -> Result<(), &'static str> {
    let cmp3 = le_u32_at(blob, BOSMINER_BM1366_DISPATCH_CMP3_VA)
        .ok_or("bosminer shorter than dispatch CMP#3")?;
    if cmp3 != BOSMINER_BM1366_DISPATCH_CMP3_INSN {
        return Err("FUN_008d824c is not CMP W8,#3");
    }
    let beq = le_u32_at(blob, BOSMINER_BM1366_DISPATCH_BEQ3_VA)
        .ok_or("bosminer shorter than dispatch B.EQ")?;
    if beq != BOSMINER_BM1366_DISPATCH_BEQ3_INSN {
        return Err("FUN_008d8250 is not B.EQ tag3");
    }
    let cmp4 = le_u32_at(blob, BOSMINER_BM1366_DISPATCH_CMP4_VA)
        .ok_or("bosminer shorter than dispatch CMP#4")?;
    if cmp4 != BOSMINER_BM1366_DISPATCH_CMP4_INSN {
        return Err("FUN_008d8254 is not CMP W8,#4");
    }
    Ok(())
}

/// Tag 4 `BLR X8` is `vtable[0]` of the fat pointer at `[obj+0x78]`.
pub fn admit_bosminer_blr_x8_is_fat_ptr_vtable0(blob: &[u8]) -> Result<(), &'static str> {
    let ldp = le_u32_at(blob, BOSMINER_BM1366_DISPATCH_LDP_VA)
        .ok_or("bosminer shorter than dispatch LDP")?;
    if ldp != BOSMINER_BM1366_DISPATCH_LDP_INSN {
        return Err("FUN_008d825c is not LDP X21,X20,[X19,#0x78]");
    }
    let ldr = le_u32_at(blob, BOSMINER_BM1366_DISPATCH_LDR_V0_VA)
        .ok_or("bosminer shorter than dispatch LDR vtable0")?;
    if ldr != BOSMINER_BM1366_DISPATCH_LDR_V0_INSN {
        return Err("FUN_008d8260 is not LDR X8,[X20]");
    }
    let blr = le_u32_at(blob, BOSMINER_BM1366_PACKED_DISPATCH_BLR_VA)
        .ok_or("bosminer shorter than dispatch BLR")?;
    if blr != BOSMINER_BM1366_PACKED_DISPATCH_BLR_INSN {
        return Err("FUN_008d826c is not BLR X8");
    }
    Ok(())
}

/// Tag 3 `BLR X8` is `vtable[+0x18]` loaded from `[obj+0xa8]`.
pub fn admit_bosminer_tag3_blr_is_vtable_plus18(blob: &[u8]) -> Result<(), &'static str> {
    let ldr = le_u32_at(blob, BOSMINER_BM1366_DISPATCH_TAG3_SLOT_LDR_VA)
        .ok_or("bosminer shorter than tag3 LDR #0x18")?;
    if ldr != BOSMINER_BM1366_DISPATCH_TAG3_SLOT_LDR_INSN {
        return Err("FUN_008d82cc is not LDR X8,[X8,#0x18]");
    }
    let blr = le_u32_at(blob, BOSMINER_BM1366_DISPATCH_TAG3_BLR_VA)
        .ok_or("bosminer shorter than tag3 BLR")?;
    if blr != BOSMINER_BM1366_PACKED_DISPATCH_BLR_INSN {
        return Err("FUN_008d82d0 is not BLR X8");
    }
    Ok(())
}

/// No unique .text VA for those `BLR`s. Do not name a write_reg callee.
pub fn refuse_blr_x8_as_named_text_write_reg() -> Result<(), &'static str> {
    Err(
        "BLR X8 is vtable[0] of [obj+0x78] (tag4) or vtable[+0x18] of [obj+0xa8] (tag3); runtime, not a unique .text write_reg",
    )
}

/// `FUN_011f2764` is CBZ+exclusive-load / refcount, not UART.
pub fn refuse_dispatch_arc_like_as_uart_write(blob: &[u8]) -> Result<(), &'static str> {
    let w = le_u32_at(blob, BOSMINER_DISPATCH_ARC_LIKE_FN_VA)
        .ok_or("bosminer shorter than 0x11f2764")?;
    if w != BOSMINER_DISPATCH_ARC_LIKE_CBZ_INSN {
        return Err("FUN_011f2764 does not start CBZ X1");
    }
    Err("FUN_011f2764 is CBZ X1 + exclusive-load/atomic (Arc/refcount); not UART write_reg")
}

/// `0x19c7900` is drop=0 / size=0x30 / align=8 / method=`FUN_011de81c`.
pub fn admit_bosminer_fat_ptr_vtable_layout(blob: &[u8]) -> Result<(), &'static str> {
    let off = BOSMINER_FAT_PTR_VTABLE_FILE_OFF;
    let drop = le_u64_at(blob, off).ok_or("bosminer shorter than fat-ptr vtable")?;
    if drop != BOSMINER_FAT_PTR_VTABLE_DROP {
        return Err("fat-ptr vtable[0] drop is not 0");
    }
    let size = le_u64_at(blob, off + 8).ok_or("bosminer shorter than fat-ptr size")?;
    if size != BOSMINER_FAT_PTR_VTABLE_SIZE {
        return Err("fat-ptr vtable size is not 0x30");
    }
    let align = le_u64_at(blob, off + 16).ok_or("bosminer shorter than fat-ptr align")?;
    if align != BOSMINER_FAT_PTR_VTABLE_ALIGN {
        return Err("fat-ptr vtable align is not 8");
    }
    let meth = le_u64_at(blob, off + 24).ok_or("bosminer shorter than fat-ptr method")?;
    if meth != BOSMINER_FAT_PTR_VTABLE_METHOD_VA {
        return Err("fat-ptr vtable[+0x18] is not FUN_011de81c");
    }
    Ok(())
}

/// Adjacent loc string is `psu_protocol.rs`, not hashchain/bm1366.rs.
pub fn admit_bosminer_fat_ptr_vtable_loc_is_psu_protocol(blob: &[u8]) -> Result<(), &'static str> {
    let off = BOSMINER_PSU_PROTOCOL_RS_FILE_OFF as usize;
    let want = BOSMINER_PSU_PROTOCOL_RS;
    if blob.get(off..off + want.len()) != Some(want) {
        return Err("file 0xf231ee is not psu_protocol.rs");
    }
    Ok(())
}

/// `ADRP 0x19c7000` + `ADD #0x900` + `STP XZR,X9,[X19,#0x78]`.
pub fn admit_bosminer_fat_ptr_vtable_install(blob: &[u8]) -> Result<(), &'static str> {
    let add = le_u32_at(blob, BOSMINER_FAT_PTR_VTABLE_ADD_VA)
        .ok_or("bosminer shorter than fat-ptr ADD #0x900")?;
    if add != BOSMINER_FAT_PTR_VTABLE_ADD_INSN {
        return Err("FUN_008ddb10 is not ADD X9,X9,#0x900");
    }
    let stp =
        le_u32_at(blob, BOSMINER_FAT_PTR_STP_VA).ok_or("bosminer shorter than fat-ptr STP")?;
    if stp != BOSMINER_FAT_PTR_STP_INSN {
        return Err("FUN_008ddb58 is not STP XZR,X9,[X19,#0x78]");
    }
    Ok(())
}

/// `FUN_011de81c` is `MOV X8,X0` / `BR X4` — a rustc trampoline, not UART.
pub fn refuse_vtable_method_as_uart_write_reg(blob: &[u8]) -> Result<(), &'static str> {
    let mov = le_u32_at(blob, BOSMINER_FAT_PTR_VTABLE_METHOD_VA)
        .ok_or("bosminer shorter than FUN_011de81c")?;
    if mov != BOSMINER_VTABLE_METHOD_MOV_INSN {
        return Err("FUN_011de81c does not start MOV X8,X0");
    }
    let br = le_u32_at(blob, BOSMINER_VTABLE_METHOD_BR_VA)
        .ok_or("bosminer shorter than FUN_011de81c BR")?;
    if br != BOSMINER_VTABLE_METHOD_BR_INSN {
        return Err("FUN_011de81c+0x18 is not BR X4");
    }
    Err(
        "FUN_011de81c is a rustc MOV/BR trampoline; fat-ptr vtable loc is psu_protocol.rs, not BM1366 FastUART",
    )
}

/// `FUN_008dfe6c` rustc loc is `hashchain.rs:112:32`.
pub fn admit_bosminer_plus78_fn_loc_is_hashchain_rs(blob: &[u8]) -> Result<(), &'static str> {
    let s_off = BOSMINER_HASHCHAIN_RS_LOC_STR_FILE_OFF as usize;
    let want = BOSMINER_HASHCHAIN_RS_LOC_STR;
    if blob.get(s_off..s_off + want.len()) != Some(want) {
        return Err("file 0xf23527 is not hashchain.rs");
    }
    if want != crate::s19k_braiins_job::BOSMINER_HASHCHAIN_RS.as_bytes() {
        return Err("hashchain.rs loc string drifted from BOSMINER_HASHCHAIN_RS");
    }
    let fn_ptr = le_u64_at(blob, BOSMINER_HASHCHAIN_PLUS78_LOC_FILE_OFF)
        .ok_or("bosminer shorter than hashchain +0x78 loc fn")?;
    if fn_ptr != BOSMINER_HASHCHAIN_PLUS78_FN_VA {
        return Err("hashchain +0x78 loc fn is not FUN_008dfe6c");
    }
    let str_va = le_u64_at(blob, BOSMINER_HASHCHAIN_PLUS78_LOC_FILE_OFF + 8)
        .ok_or("bosminer shorter than hashchain +0x78 loc str")?;
    if str_va != BOSMINER_HASHCHAIN_RS_LOC_STR_VA {
        return Err("hashchain +0x78 loc filename VA is not hashchain.rs");
    }
    let str_len = le_u64_at(blob, BOSMINER_HASHCHAIN_PLUS78_LOC_FILE_OFF + 16)
        .ok_or("bosminer shorter than hashchain +0x78 loc len")?;
    if str_len != u64::from(BOSMINER_HASHCHAIN_RS_LOC_STR_LEN) {
        return Err("hashchain +0x78 loc filename len is not 0x2f");
    }
    let line_col = le_u64_at(blob, BOSMINER_HASHCHAIN_PLUS78_LOC_FILE_OFF + 24)
        .ok_or("bosminer shorter than hashchain +0x78 line/col")?;
    let line = line_col as u32;
    let col = (line_col >> 32) as u32;
    if line != BOSMINER_HASHCHAIN_PLUS78_LOC_LINE {
        return Err("hashchain +0x78 loc line is not 112");
    }
    if col != BOSMINER_HASHCHAIN_PLUS78_LOC_COL {
        return Err("hashchain +0x78 loc col is not 32");
    }
    Ok(())
}

/// `0x8dff48` stores `(*(*(obj+0x20))+0x10, obj+0x158)`, not `0x19c7900`.
pub fn admit_bosminer_hashchain_plus78_operands(blob: &[u8]) -> Result<(), &'static str> {
    let inner = le_u32_at(blob, BOSMINER_HASHCHAIN_PLUS78_INNER_LDR_VA)
        .ok_or("bosminer shorter than hashchain LDR [X19,#0x20]")?;
    if inner != BOSMINER_HASHCHAIN_PLUS78_INNER_LDR_INSN {
        return Err("FUN_008dfe6c is missing LDR X12,[X19,#0x20]");
    }
    let deref = le_u32_at(blob, BOSMINER_HASHCHAIN_PLUS78_DEREF_VA)
        .ok_or("bosminer shorter than hashchain LDR [X12]")?;
    if deref != BOSMINER_HASHCHAIN_PLUS78_DEREF_INSN {
        return Err("FUN_008dfe6c is missing LDR X10,[X12]");
    }
    let add158 = le_u32_at(blob, BOSMINER_HASHCHAIN_PLUS78_ADD158_VA)
        .ok_or("bosminer shorter than hashchain ADD #0x158")?;
    if add158 != BOSMINER_HASHCHAIN_PLUS78_ADD158_INSN {
        return Err("FUN_008dfe6c is missing ADD X9,X19,#0x158");
    }
    let add10 = le_u32_at(blob, BOSMINER_HASHCHAIN_PLUS78_ADD10_VA)
        .ok_or("bosminer shorter than hashchain ADD #0x10")?;
    if add10 != BOSMINER_HASHCHAIN_PLUS78_ADD10_INSN {
        return Err("FUN_008dfe6c is missing ADD X8,X10,#0x10");
    }
    let stp = le_u32_at(blob, BOSMINER_HASHCHAIN_PLUS78_STP_VA)
        .ok_or("bosminer shorter than hashchain STP #0x78")?;
    if stp != BOSMINER_HASHCHAIN_PLUS78_STP_INSN {
        return Err("0x8dff48 is not STP X8,X9,[X19,#0x78]");
    }
    Ok(())
}

/// `FUN_008d5f9c` is the same packed `+0x70` tag family; tag<=2 uses `[X0+#0x10]`.
pub fn admit_bosminer_sibling_pack_tag_dispatch(blob: &[u8]) -> Result<(), &'static str> {
    let mov = le_u32_at(blob, BOSMINER_HASHCHAIN_SIBLING_PACK_MOV_X19_VA)
        .ok_or("bosminer shorter than sibling MOV X19,X0")?;
    if mov != BOSMINER_HASHCHAIN_SIBLING_PACK_MOV_X19_INSN {
        return Err("FUN_008d5f9c+0x10 is not MOV X19,X0");
    }
    let ldrb = le_u32_at(blob, BOSMINER_HASHCHAIN_SIBLING_PACK_LDRB_VA)
        .ok_or("bosminer shorter than sibling LDRB #0x70")?;
    if ldrb != BOSMINER_BM1366_PACKED_DISPATCH_LDRB_INSN {
        return Err("FUN_008d5f9c+0xc is not LDRB W8,[X0,#0x70]");
    }
    let cmp2 = le_u32_at(blob, BOSMINER_HASHCHAIN_SIBLING_PACK_CMP2_VA)
        .ok_or("bosminer shorter than sibling CMP#2")?;
    if cmp2 != BOSMINER_HASHCHAIN_SIBLING_PACK_CMP2_INSN {
        return Err("FUN_008d5f9c is not CMP W8,#2");
    }
    let cmp3 = le_u32_at(blob, BOSMINER_HASHCHAIN_SIBLING_PACK_CMP3_VA)
        .ok_or("bosminer shorter than sibling CMP#3")?;
    if cmp3 != BOSMINER_BM1366_DISPATCH_CMP3_INSN {
        return Err("FUN_008d5f9c is not CMP W8,#3");
    }
    let ldp10 = le_u32_at(blob, BOSMINER_HASHCHAIN_SIBLING_PACK_LDP10_VA)
        .ok_or("bosminer shorter than sibling LDP #0x10")?;
    if ldp10 != BOSMINER_HASHCHAIN_SIBLING_PACK_LDP10_INSN {
        return Err("FUN_008d5f9c tag<=2 is not LDP X8,X22,[X19,#0x10]");
    }
    if BOSMINER_HASHCHAIN_SIBLING_PACK_BL_HITS != 2 {
        return Err("sibling pack BL census drifted");
    }
    if BOSMINER_HASHCHAIN_SIBLING_PACK_BL_VA != [0x008D_F010, 0x008D_FF54] {
        return Err("sibling pack BL sites drifted");
    }
    Ok(())
}

/// After the `+0x78` store: `X0=self+0x68`, `BL FUN_008d5f9c`, then `BL FUN_008d823c`.
pub fn admit_bosminer_hashchain_plus78_calls_sibling_then_dispatch(
    blob: &[u8],
) -> Result<(), &'static str> {
    let add = le_u32_at(blob, BOSMINER_HASHCHAIN_PACKED_X0_ADD_VA)
        .ok_or("bosminer shorter than ADD X0,#0x68")?;
    if add != BOSMINER_HASHCHAIN_PACKED_X0_ADD_INSN {
        return Err("0x8dff4c is not ADD X0,X19,#0x68");
    }
    let bl_sib = le_u32_at(blob, BOSMINER_HASHCHAIN_SIBLING_PACK_BL_VA[1])
        .ok_or("bosminer shorter than BL FUN_008d5f9c")?;
    if bl_sib != BOSMINER_HASHCHAIN_SIBLING_PACK_BL_INSN {
        return Err("0x8dff54 is not BL FUN_008d5f9c");
    }
    let bl_disp = le_u32_at(blob, BOSMINER_HASHCHAIN_DISPATCH_BL_VA)
        .ok_or("bosminer shorter than BL FUN_008d823c")?;
    if bl_disp != BOSMINER_HASHCHAIN_DISPATCH_BL_INSN {
        return Err("0x8dff64 is not BL FUN_008d823c");
    }
    Ok(())
}

/// Parallel site: fat ptr at `+0x40` (= packed `+0x30` + `+0x10`), inline `+0x120`.
pub fn admit_bosminer_hashchain_alt_fat_ptr_pattern(blob: &[u8]) -> Result<(), &'static str> {
    let stp = le_u32_at(blob, BOSMINER_HASHCHAIN_ALT_STP_VA)
        .ok_or("bosminer shorter than alt STP #0x40")?;
    if stp != BOSMINER_HASHCHAIN_ALT_STP_INSN {
        return Err("0x8df004 is not STP X8,X9,[X19,#0x40]");
    }
    if BOSMINER_HASHCHAIN_ALT_PACKED_OFF + 0x10 != BOSMINER_HASHCHAIN_ALT_FAT_OFF {
        return Err("alt fat ptr is not packed+0x10");
    }
    if BOSMINER_HASHCHAIN_PACKED_OBJ_OFF + 0x10 != BOSMINER_BM1366_DISPATCH_FAT_PTR_OFF as u16 {
        return Err("0x8dff48 is not packed(+0x68)+0x10");
    }
    Ok(())
}

/// 's rodata vtable is a different store (`STP XZR,X9` @ `0x8ddb58`).
pub fn refuse_hashchain_plus78_as_psu_rodata_vtable() -> Result<(), &'static str> {
    Err(
        "0x8dff48 STP X8,X9,[X19,#0x78] is hashchain.rs:112 (inner+0x10, self+0x158); not 0x19c7900 psu_protocol vtable",
    )
}

/// Second qword is `ADD X9,X19,#0x158`, not a `.text` FastUART writer.
pub fn refuse_hashchain_plus78_second_as_text_fastuart() -> Result<(), &'static str> {
    Err(
        "0x8dff48 second qword is obj+0x158 inline buffer/metadata; not a named .text FastUART / write_reg",
    )
}

/// Fail string lives in `bosminer-antminer/src/bm139x.rs` rodata.
pub fn admit_bosminer_legacy_fastuart_fail_str(blob: &[u8]) -> Result<(), &'static str> {
    let off = BOSMINER_LEGACY_FASTUART_FAIL_STR_FILE_OFF as usize;
    let want = BOSMINER_LEGACY_FASTUART_FAIL_STR;
    if blob.get(off..off + want.len()) != Some(want) {
        return Err("file 0xf251d0 is not BUG: Failed to build legacy FastUartReg");
    }
    let rs = BOSMINER_BM139X_RS_LOC_STR_FILE_OFF as usize;
    if blob.get(rs..rs + BOSMINER_BM139X_RS_LOC_STR.len()) != Some(BOSMINER_BM139X_RS_LOC_STR) {
        return Err("file 0xf251a3 is not bosminer-antminer bm139x.rs");
    }
    Ok(())
}

/// rustc loc next to the fail string is `bm139x.rs:659:26`.
pub fn admit_bosminer_legacy_fastuart_loc_is_bm139x_rs(blob: &[u8]) -> Result<(), &'static str> {
    let str_va = le_u64_at(blob, BOSMINER_BM139X_FASTUART_LOC_FILE_OFF)
        .ok_or("bosminer shorter than bm139x FastUart loc")?;
    if str_va != BOSMINER_BM139X_RS_LOC_STR_VA {
        return Err("FastUart loc filename VA is not bm139x.rs");
    }
    let str_len = le_u64_at(blob, BOSMINER_BM139X_FASTUART_LOC_FILE_OFF + 8)
        .ok_or("bosminer shorter than bm139x FastUart loc len")?;
    if str_len != u64::from(BOSMINER_BM139X_RS_LOC_STR_LEN) {
        return Err("bm139x.rs loc len is not 0x2d");
    }
    let line_col = le_u64_at(blob, BOSMINER_BM139X_FASTUART_LOC_FILE_OFF + 16)
        .ok_or("bosminer shorter than bm139x FastUart line/col")?;
    if line_col as u32 != BOSMINER_BM139X_FASTUART_LOC_LINE {
        return Err("bm139x FastUart loc line is not 659");
    }
    if (line_col >> 32) as u32 != BOSMINER_BM139X_FASTUART_LOC_COL {
        return Err("bm139x FastUart loc col is not 26");
    }
    Ok(())
}

/// `FUN_0091afe8` is the only `ADRP`+`ADD #0x1d0` former of the fail string.
pub fn admit_bosminer_legacy_fastuart_panic_former(blob: &[u8]) -> Result<(), &'static str> {
    let add = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_PANIC_ADD_VA)
        .ok_or("bosminer shorter than FastUart panic ADD")?;
    if add != BOSMINER_LEGACY_FASTUART_PANIC_ADD_INSN {
        return Err("FUN_0091afe8+0x10 is not ADD X0,X0,#0x1d0");
    }
    Ok(())
}

/// Packer `B.EQ` `@ 0x91af74` is the only branch into the panic stub.
pub fn admit_bosminer_legacy_fastuart_pack_beq_panic(blob: &[u8]) -> Result<(), &'static str> {
    let beq = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_PACK_BEQ_VA)
        .ok_or("bosminer shorter than FastUart pack B.EQ")?;
    if beq != BOSMINER_LEGACY_FASTUART_PACK_BEQ_INSN {
        return Err("0x91af74 is not B.EQ FUN_0091afe8");
    }
    let ret = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_PACK_RET_VA)
        .ok_or("bosminer shorter than FastUart pack RET")?;
    if ret != BOSMINER_LEGACY_FASTUART_PACK_RET_INSN {
        return Err("0x91afe4 is not RET");
    }
    Ok(())
}

/// The panic stub never transmits UART. It is a rustc cold path.
pub fn refuse_legacy_fastuart_panic_as_uart_write() -> Result<(), &'static str> {
    Err(
        "FUN_0091afe8 only materializes BUG: Failed to build legacy FastUartReg; 0 BL; not a write_reg",
    )
}

/// bm139x.rs FastUartReg is not Track-1 host 3_000_000 and not a packed 51 09 00 28.
pub fn refuse_legacy_fastuart_as_s19k_host_3m() -> Result<(), &'static str> {
    Err(
        "bm139x.rs legacy FastUartReg packer/panic is not Braiins S19k host 3_000_000 and not a static 51 09 00 28 writer",
    )
}

/// `FUN_0091af14` loads divisor bytes and returns `UDIV`; it does not store 0x3001.
pub fn admit_bosminer_legacy_fastuart_divisor_path(blob: &[u8]) -> Result<(), &'static str> {
    let ldrb = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_DIV_FN_VA + 4)
        .ok_or("bosminer shorter than divisor LDRB #7")?;
    if ldrb != BOSMINER_LEGACY_FASTUART_DIV_LDRB7_INSN {
        return Err("FUN_0091af14+4 is not LDRB W8,[X0,#7]");
    }
    let lsr = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_DIV_LSR24_VA)
        .ok_or("bosminer shorter than divisor LSR #24")?;
    if lsr != BOSMINER_LEGACY_FASTUART_DIV_LSR24_INSN {
        return Err("FUN_0091af14 is missing LSR W11,W1,#24");
    }
    let cmp = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_DIV_CMP255_VA)
        .ok_or("bosminer shorter than divisor CMP #255")?;
    if cmp != BOSMINER_LEGACY_FASTUART_DIV_CMP255_INSN {
        return Err("FUN_0091af14 is missing CMP W11,#255");
    }
    let udiv = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_DIV_UDIV_RET_VA)
        .ok_or("bosminer shorter than divisor UDIV")?;
    if udiv != BOSMINER_LEGACY_FASTUART_DIV_UDIV_RET_INSN {
        return Err("FUN_0091af14 return is not UDIV X0,X8,X9");
    }
    if BOSMINER_LEGACY_FASTUART_DIV_BL_HITS != 0 {
        return Err("divisor BL census drifted");
    }
    Ok(())
}

/// Field leaf starts `UBFX #3,#2` / `CMP #1`; stores a 14-byte map to `[X8]`.
pub fn admit_bosminer_legacy_fastuart_fields_layout(blob: &[u8]) -> Result<(), &'static str> {
    let ubfx = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_FIELDS_FN_VA)
        .ok_or("bosminer shorter than fields UBFX")?;
    if ubfx != BOSMINER_LEGACY_FASTUART_FIELDS_UBFX_INSN {
        return Err("FUN_0091af6c does not start UBFX W9,W0,#3,#2");
    }
    let cmp1 = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_FIELDS_CMP1_VA)
        .ok_or("bosminer shorter than fields CMP #1")?;
    if cmp1 != BOSMINER_LEGACY_FASTUART_FIELDS_CMP1_INSN {
        return Err("FUN_0091af70 is not CMP W9,#1");
    }
    let strh = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_STRH0_VA)
        .ok_or("bosminer shorter than fields STRH #0")?;
    if strh != BOSMINER_LEGACY_FASTUART_STRH0_INSN {
        return Err("0x91afd0 is not STRH W14,[X8,#0]");
    }
    let strc = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_STRB_C_VA)
        .ok_or("bosminer shorter than fields STRB #0xc")?;
    if strc != BOSMINER_LEGACY_FASTUART_STRB_C_INSN {
        return Err("0x91af8c is not STRB W9,[X8,#0xc]");
    }
    let strd = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_STRB_D_VA)
        .ok_or("bosminer shorter than fields STRB #0xd")?;
    if strd != BOSMINER_LEGACY_FASTUART_STRB_D_INSN {
        return Err("0x91afe0 is not STRB W11,[X8,#0xd]");
    }
    if BOSMINER_LEGACY_FASTUART_PACKED_LEN != 0x0E {
        return Err("FastUartReg packed_struct store map is not 14 bytes");
    }
    Ok(())
}

/// Sole static caller is `FUN_008b1b98` (bm1398.rs write) with `MOVZ W0,#6`.
pub fn admit_bosminer_legacy_fastuart_fields_caller(blob: &[u8]) -> Result<(), &'static str> {
    let bl = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_FIELDS_BL_VA)
        .ok_or("bosminer shorter than fields BL")?;
    if bl != BOSMINER_LEGACY_FASTUART_FIELDS_BL_INSN {
        return Err("0x8b20fc is not BL FUN_0091af6c");
    }
    let w0 = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0_VA)
        .ok_or("bosminer shorter than fields MOVZ W0,#6")?;
    if w0 != BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0_INSN {
        return Err("bm1398 write does not MOVZ W0,#6 before FastUartReg pack");
    }
    if BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0 != 6 {
        return Err("caller W0 immediate drifted");
    }
    Ok(())
}

/// DATA `28 00 00 00 30 01` is 6 bytes. Field packer writes 14 bytes to `[X8]`.
pub fn refuse_reg28_3001_as_legacy_fastuart_pack() -> Result<(), &'static str> {
    Err(
        "DATA 28 00 00 00 30 01 is a 6-byte reg+BE pin; FUN_0091af6c stores 14 packed_struct field bytes, not 0x00003001",
    )
}

/// Divisor `UDIV` return is a quotient, not bible FastUART 0x00003001.
pub fn refuse_legacy_fastuart_divisor_as_3001() -> Result<(), &'static str> {
    Err(
        "FUN_0091af14 returns UDIV X0,X8,X9 (bytes at +7/+8/+9); 0 BL; not DATA 0x00003001 / host 3M",
    )
}

/// Sole packer caller passes W0=6, not 0x3001 or 0x3011.
pub fn refuse_bm1398_pack_call_as_bible_3001() -> Result<(), &'static str> {
    Err("0x8b20fc MOVZ W0,#6 then BL FUN_0091af6c; not bible 0x00003001 / 0x00003011 / S19k 3M")
}

/// Second-LOAD slot `@ file 0x16be820` holds `FUN_0091af14`.
pub fn admit_bosminer_legacy_fastuart_div_fptr(blob: &[u8]) -> Result<(), &'static str> {
    let slot = le_u64_at(blob, BOSMINER_LEGACY_FASTUART_DIV_FPTR_FILE_OFF)
        .ok_or("bosminer shorter than divisor fptr slot")?;
    if slot != BOSMINER_LEGACY_FASTUART_DIV_FN_VA {
        return Err("file 0x16be820 is not FUN_0091af14");
    }
    let prev = le_u64_at(blob, BOSMINER_LEGACY_FASTUART_DIV_FPTR_FILE_OFF - 8)
        .ok_or("bosminer shorter than divisor fptr prev")?;
    if prev != BOSMINER_LEGACY_FASTUART_DIV_FPTR_PREV {
        return Err("divisor fptr prev qword is not 0x1ae5350");
    }
    let next = le_u64_at(blob, BOSMINER_LEGACY_FASTUART_DIV_FPTR_FILE_OFF + 8)
        .ok_or("bosminer shorter than divisor fptr next")?;
    if next != BOSMINER_LEGACY_FASTUART_DIV_FPTR_NEXT {
        return Err("divisor fptr next qword is not 0x1ae4948");
    }
    Ok(())
}

/// Neighbor qwords are second-LOAD DATA, not a `.text` UART writer table.
pub fn refuse_div_fptr_neighbors_as_uart_write() -> Result<(), &'static str> {
    Err(
        "0x16be820 holds FUN_0091af14 between DATA 0x1ae5350/0x1ae4948; not a .text FastUART write_reg table",
    )
}

/// `LDP X0,X8,[X8]` then the same pair is `STP` to `+0x78` and `+0x88`.
pub fn admit_bosminer_hashchain_dup78_88_copy(blob: &[u8]) -> Result<(), &'static str> {
    let ldp =
        le_u32_at(blob, BOSMINER_HASHCHAIN_DUP78_LDP_VA).ok_or("bosminer shorter than dup LDP")?;
    if ldp != BOSMINER_HASHCHAIN_DUP78_LDP_INSN {
        return Err("0x8d3a78 is not LDP X0,X8,[X8]");
    }
    let s78 = le_u32_at(blob, BOSMINER_HASHCHAIN_DUP78_STP_VA)
        .ok_or("bosminer shorter than dup STP #0x78")?;
    if s78 != BOSMINER_HASHCHAIN_DUP78_STP_INSN {
        return Err("0x8d3a7c is not STP X0,X8,[X19,#0x78]");
    }
    let s88 = le_u32_at(blob, BOSMINER_HASHCHAIN_DUP88_STP_VA)
        .ok_or("bosminer shorter than dup STP #0x88")?;
    if s88 != BOSMINER_HASHCHAIN_DUP88_STP_INSN {
        return Err("0x8d3a80 is not STP X0,X8,[X19,#0x88]");
    }
    Ok(())
}

/// That `+0x88` store is a duplicated fat-ptr copy, not the engine nonce callee.
pub fn refuse_hashchain_dup88_as_engine_nonce_fn() -> Result<(), &'static str> {
    Err("0x8d3a80 STP X0,X8,[X19,#0x88] copies the same pair as +0x78; not engine+0x88 nonce .text")
}

/// `0x8d54f4` stores a `BLR` return pair at `+0x78` (consume), not a vtable install.
pub fn admit_bosminer_hashchain_blr78_consume(blob: &[u8]) -> Result<(), &'static str> {
    let stp = le_u32_at(blob, BOSMINER_HASHCHAIN_BLR78_STP_VA)
        .ok_or("bosminer shorter than BLR +0x78 STP")?;
    if stp != BOSMINER_HASHCHAIN_BLR78_STP_INSN {
        return Err("0x8d54f4 is not STP X0,X1,[X19,#0x78]");
    }
    Ok(())
}

/// All seven `+0x78` STP clones are `MOV X0,X21; BLR X8; STP X0,X1,[X19,#0x78]`.
pub fn admit_bosminer_hashchain_blr78_family(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHCHAIN_BLR78_FAMILY_HITS != 7 {
        return Err("BLR +0x78 family census drifted");
    }
    if BOSMINER_HASHCHAIN_BLR78_FAMILY_VA[0] != BOSMINER_HASHCHAIN_BLR78_STP_VA {
        return Err("family[0] is not the Wave-140 consume site");
    }
    for &va in &BOSMINER_HASHCHAIN_BLR78_FAMILY_VA {
        let mov = le_u32_at(blob, va - 8).ok_or("bosminer shorter than BLR78 MOV")?;
        if mov != BOSMINER_HASHCHAIN_BLR78_MOV_INSN {
            return Err("BLR78 clone is missing MOV X0,X21");
        }
        let blr = le_u32_at(blob, va - 4).ok_or("bosminer shorter than BLR78 BLR")?;
        if blr != BOSMINER_HASHCHAIN_BLR78_BLR_INSN {
            return Err("BLR78 clone is missing BLR X8");
        }
        let stp = le_u32_at(blob, va).ok_or("bosminer shorter than BLR78 STP")?;
        if stp != BOSMINER_HASHCHAIN_BLR78_STP_INSN {
            return Err("BLR78 clone is not STP X0,X1,[X19,#0x78]");
        }
    }
    Ok(())
}

/// Those seven sites consume a `BLR` Result at `+0x78`. They do not name engine+0x88.
pub fn refuse_blr78_family_as_engine_plus88() -> Result<(), &'static str> {
    Err(
        "7 MOV X0,X21; BLR X8; STP X0,X1,[X19,#0x78] clones consume a Result at +0x78; not engine+0x88 .text",
    )
}

/// : `W13 = (W0[1:0] << 4) | W1[7:4]` (`UBFIZ` then `BFXIL`).
pub fn bosminer_legacy_fastuart_w13(w0: u32, w1: u32) -> u8 {
    (((w0 & 3) << 4) | ((w1 >> 4) & 0xF)) as u8
}

/// dest[0x0C] enum nibble. `FUN_0091af6c` panics when this equals 1.
pub fn bosminer_legacy_fastuart_enum_field(w0: u32) -> u8 {
    ((w0 >> 3) & 3) as u8
}

pub fn bosminer_legacy_fastuart_enum_ok(w0: u32) -> bool {
    bosminer_legacy_fastuart_enum_field(w0) != 1
}

/// Exact 14-byte `[X8]` map from `FUN_0091af6c` STRB/STRH sites.
pub fn pack_bosminer_legacy_fastuart_fields(w0: u32, w1: u32, w2: u32, w3: u32) -> [u8; 14] {
    [
        (w2 & 0xFF) as u8,
        (w1 & 1) as u8,
        ((w0 >> 6) & 1) as u8,
        ((w0 >> 5) & 1) as u8,
        ((w0 >> 2) & 1) as u8,
        bosminer_legacy_fastuart_w13(w0, w1),
        ((w1 >> 2) & 3) as u8,
        ((w1 >> 1) & 1) as u8,
        ((w3 >> 7) & 1) as u8,
        ((w3 >> 5) & 3) as u8,
        ((w3 >> 4) & 1) as u8,
        (w3 & 0xF) as u8,
        bosminer_legacy_fastuart_enum_field(w0),
        ((w0 >> 7) & 1) as u8,
    ]
}

/// Sole static caller: `W0=6`, `W2=0x80`, `W3=0xF`; `W1` is the `+0x22c` byte minus 1.
pub fn pack_bosminer_legacy_fastuart_bm1398_write_instance(w1: u32) -> [u8; 14] {
    pack_bosminer_legacy_fastuart_fields(
        BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0,
        w1,
        BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2,
        BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3,
    )
}

/// `UBFIZ`/`BFXIL`/`STRB #5` plus caller `MOVZ W2/#W3`.
pub fn admit_bosminer_legacy_fastuart_w13_map(blob: &[u8]) -> Result<(), &'static str> {
    let ubfiz = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_W13_UBFIZ_VA)
        .ok_or("bosminer shorter than W13 UBFIZ")?;
    if ubfiz != BOSMINER_LEGACY_FASTUART_W13_UBFIZ_INSN {
        return Err("0x91af84 is not UBFIZ W13,W0,#4,#2");
    }
    let bfxil = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_W13_BFXIL_VA)
        .ok_or("bosminer shorter than W13 BFXIL")?;
    if bfxil != BOSMINER_LEGACY_FASTUART_W13_BFXIL_INSN {
        return Err("0x91afa4 is not BFXIL W13,W1,#4,#4");
    }
    let str5 = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_STRB_5_VA)
        .ok_or("bosminer shorter than STRB #5")?;
    if str5 != BOSMINER_LEGACY_FASTUART_STRB_5_INSN {
        return Err("0x91afd4 is not STRB W13,[X8,#5]");
    }
    let w2 = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2_VA)
        .ok_or("bosminer shorter than MOVZ W2,#0x80")?;
    if w2 != BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2_INSN {
        return Err("bm1398 write does not MOVZ W2,#0x80 before FastUartReg pack");
    }
    let w3 = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3_VA)
        .ok_or("bosminer shorter than MOVZ W3,#0xF")?;
    if w3 != BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3_INSN {
        return Err("bm1398 write does not MOVZ W3,#0xF before FastUartReg pack");
    }
    if BOSMINER_LEGACY_FASTUART_DEST_W13_OFF != 5 {
        return Err("W13 dest offset drifted");
    }
    Ok(())
}

/// W1 is `LDR X8,[X19,#8]; LDRB [X8,#0x22c]; SUB #1` immediately before the pack BL.
pub fn admit_bosminer_legacy_fastuart_w1_ldrb_sub1(blob: &[u8]) -> Result<(), &'static str> {
    let ldr = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_W1_LDR8_VA)
        .ok_or("bosminer shorter than W1 LDR [X19,#8]")?;
    if ldr != BOSMINER_LEGACY_FASTUART_W1_LDR8_INSN {
        return Err("0x8b20e0 is not LDR X8,[X19,#8]");
    }
    let ldrb = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_W1_LDRB_VA)
        .ok_or("bosminer shorter than W1 LDRB #0x22c")?;
    if ldrb != BOSMINER_LEGACY_FASTUART_W1_LDRB_INSN {
        return Err("0x8b20e4 is not LDRB W8,[X8,#0x22c]");
    }
    let sub1 = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_W1_SUB1_VA)
        .ok_or("bosminer shorter than W1 SUB #1")?;
    if sub1 != BOSMINER_LEGACY_FASTUART_W1_SUB1_INSN {
        return Err("0x8b20e8 is not SUB W1,W8,#1");
    }
    if BOSMINER_LEGACY_FASTUART_W1_LDRB_OFF != 0x22C {
        return Err("W1 LDRB offset drifted");
    }
    Ok(())
}

pub fn admit_bosminer_fastuart_field_name_blob(blob: &[u8]) -> Result<(), &'static str> {
    let off = BOSMINER_FASTUART_FIELDS_STR_FILE_OFF as usize;
    let head = BOSMINER_FASTUART_FIELDS_STR;
    if blob.get(off..off + head.len()) != Some(head) {
        return Err("file 0xf20c4b is not unknown_bits_31_28");
    }
    let window = blob
        .get(off..off + 0x80)
        .ok_or("bosminer shorter than FastUART field-name window")?;
    if !window
        .windows(BOSMINER_FASTUART_EXT_BAUD_ENABLE_STR.len())
        .any(|w| w == BOSMINER_FASTUART_EXT_BAUD_ENABLE_STR)
    {
        return Err("ext_baud_enable missing next to unknown_bits_31_28");
    }
    Ok(())
}

/// dest[5] is W13 (W0[1:0]<<4 | W1[7:4]), not a named 32-bit slice and not 0x3001.
pub fn refuse_legacy_fastuart_dest5_as_bible_3001() -> Result<(), &'static str> {
    Err(
        "FUN_0091af6c dest[5] stores W13=(W0[1:0]<<4)|W1[7:4]; not DATA 0x00003001 and not ext_baud_enable",
    )
}

/// rustc `unknown_bits_*`/`ext_baud_enable` names are 32-bit register fields, not dest bytes.
pub fn refuse_fastuart_field_names_as_dest_byte_map() -> Result<(), &'static str> {
    Err(
        "unknown_bits_31_28..ext_baud_enable..tfs is the 32-bit FastUartReg rustc name blob; not the 14-byte [X8] dest map",
    )
}

/// Two `STR Xt,[X19,#0x88]` of `*(obj+0x30)+0x18` (bm1398 write + hashchain twin).
pub fn admit_bosminer_nested88_plus18_family(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_NESTED88_HITS != 2 {
        return Err("nested +0x88 census drifted");
    }
    for i in 0..BOSMINER_NESTED88_HITS {
        let ldr = le_u32_at(blob, BOSMINER_NESTED88_LDR30_VA[i])
            .ok_or("bosminer shorter than nested88 LDR #0x30")?;
        if ldr != BOSMINER_NESTED88_LDR30_INSN {
            return Err("nested +0x88 site is missing LDR X10,[X19,#0x30]");
        }
        let add = le_u32_at(blob, BOSMINER_NESTED88_ADD18_VA[i])
            .ok_or("bosminer shorter than nested88 ADD #0x18")?;
        if add != BOSMINER_NESTED88_ADD18_INSN[i] {
            return Err("nested +0x88 site is missing ADD #0x18");
        }
        let str88 = le_u32_at(blob, BOSMINER_NESTED88_STR_VA[i])
            .ok_or("bosminer shorter than nested88 STR #0x88")?;
        if str88 != BOSMINER_NESTED88_STR_INSN[i] {
            return Err("nested +0x88 site is not STR Xt,[X19,#0x88]");
        }
    }
    if BOSMINER_NESTED88_ADD_IMM != 0x18 {
        return Err("nested +0x88 ADD immediate drifted");
    }
    Ok(())
}

pub fn refuse_nested88_plus18_as_engine_nonce_fn() -> Result<(), &'static str> {
    Err("0x8b27ec/0x8dea60 store *(obj+0x30)+0x18 at +0x88; nested/fat-ptr, not engine nonce .text")
}

/// rustc FastUartReg slices whose names include an explicit bit range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerFastUartRegNamedBits {
    pub unknown_bits_31_28: u8,
    pub unknown_bits_27_23: u8,
    pub unknown_bit_22: bool,
    pub unknown_bits_21_17: u8,
    pub ext_baud_enable: bool,
    pub unknown_bit_15: bool,
    pub unknown_bit_13: bool,
    pub unknown_bit_7_reserved_bit_6: u8,
}

/// Named 32-bit slices only. Does not assign `rfs`/`tfs` widths.
pub fn decode_bosminer_fastuart_reg_named(value: u32) -> BosminerFastUartRegNamedBits {
    BosminerFastUartRegNamedBits {
        unknown_bits_31_28: ((value >> BOSMINER_FASTUART_NAMED_BITS_31_28_SHIFT) & 0xF) as u8,
        unknown_bits_27_23: ((value >> BOSMINER_FASTUART_NAMED_BITS_27_23_SHIFT) & 0x1F) as u8,
        unknown_bit_22: (value >> BOSMINER_FASTUART_NAMED_BIT_22) & 1 == 1,
        unknown_bits_21_17: ((value >> BOSMINER_FASTUART_NAMED_BITS_21_17_SHIFT) & 0x1F) as u8,
        ext_baud_enable: (value >> BOSMINER_FASTUART_EXT_BAUD_ENABLE_BIT) & 1 == 1,
        unknown_bit_15: (value >> BOSMINER_FASTUART_NAMED_BIT_15) & 1 == 1,
        unknown_bit_13: (value >> BOSMINER_FASTUART_NAMED_BIT_13) & 1 == 1,
        unknown_bit_7_reserved_bit_6: ((value >> BOSMINER_FASTUART_NAMED_BITS_7_6_SHIFT) & 0x3)
            as u8,
    }
}

pub fn admit_bosminer_fastuart_named_bit_blob(blob: &[u8]) -> Result<(), &'static str> {
    let off = BOSMINER_FASTUART_FIELDS_STR_FILE_OFF as usize;
    let want = BOSMINER_FASTUART_NAMED_BIT_BLOB;
    if blob.get(off..off + want.len()) != Some(want) {
        return Err("file 0xf20c4b is not the rustc FastUartReg named-bit blob");
    }
    if !want
        .windows(BOSMINER_FASTUART_BIT76_STR.len())
        .any(|w| w == BOSMINER_FASTUART_BIT76_STR)
    {
        return Err("named-bit blob missing unknown_bit_7_reserved_bit_6");
    }
    Ok(())
}

/// Bible `0x00003001` has bit 16 clear — it is not `ext_baud_enable`.
pub fn refuse_bible_3001_as_ext_baud_enable(value: u32) -> Result<(), &'static str> {
    let bits = decode_bosminer_fastuart_reg_named(value);
    if value ==  && !bits.ext_baud_enable {
        return Err(
            "bible 0x00003001 has ext_baud_enable bit16=0; not the FastUartReg enable flag",
        );
    }
    Err("value is not bible 0x00003001 or has ext_baud_enable set")
}

/// `rfs`/`tfs` appear in the rustc blob but their bit widths are not in the identifier.
pub fn refuse_rfs_tfs_width_as_named() -> Result<(), &'static str> {
    Err("rfs/tfs are rustc FastUartReg names without a bit-range; width is unbound")
}

/// `25_000_000 / div` when it divides evenly. `div=8` is bible 3.125 M, not host 3M.
pub fn bosminer_xtal25_divisor_baud(div: u8) -> Option<u32> {
    if div == 0 {
        return None;
    }
    let xtal = BOSMINER_FASTUART_22C_XTAL_HZ;
    if xtal % u32::from(div) != 0 {
        return None;
    }
    Some(xtal / u32::from(div))
}

/// Raw `+0x22c` byte is `W1 + 1` on the FastUartReg pack path.
pub fn bosminer_fastuart_w1_to_div_byte(w1: u32) -> Option<u8> {
    w1.checked_add(1)?.try_into().ok()
}

pub fn admit_bosminer_fastuart_22c_xtal25(blob: &[u8]) -> Result<(), &'static str> {
    let ldrb = le_u32_at(blob, BOSMINER_FASTUART_22C_SIBLING_LDRB_VA)
        .ok_or("bosminer shorter than +0x22c sibling LDRB")?;
    if ldrb != BOSMINER_FASTUART_22C_SIBLING_LDRB_INSN {
        return Err("0x8b24dc is not LDRB W9,[X0,#0x22c]");
    }
    let movz = le_u32_at(blob, BOSMINER_FASTUART_22C_XTAL_MOVZ_VA)
        .ok_or("bosminer shorter than 25M MOVZ")?;
    if movz != BOSMINER_FASTUART_22C_XTAL_MOVZ_INSN {
        return Err("0x8b24f0 is not MOVZ W1,#0x7840");
    }
    let movk = le_u32_at(blob, BOSMINER_FASTUART_22C_XTAL_MOVK_VA)
        .ok_or("bosminer shorter than 25M MOVK")?;
    if movk != BOSMINER_FASTUART_22C_XTAL_MOVK_INSN {
        return Err("0x8b24f4 is not MOVK W1,#0x017D,LSL#16");
    }
    if BOSMINER_FASTUART_22C_XTAL_HZ != 25_000_000 {
        return Err("xtal immediate is not 25_000_000");
    }
    if BOSMINER_FASTUART_22C_LDRB_HITS != 12 {
        return Err("+0x22c LDRB census drifted");
    }
    Ok(())
}

/// `25e6/8=3.125M` is bible BM1366, not Track-1 host `3_000_000`.
pub fn refuse_xtal25_div8_as_s19k_host_3m() -> Result<(), &'static str> {
    Err(
        "FUN_008b24b8 pairs +0x22c with 25_000_000; 25e6/8=3_125_000 bible FastUART, not S19k host 3_000_000",
    )
}

pub fn refuse_plus22c_as_engine_nonce_fn() -> Result<(), &'static str> {
    Err("+0x22c is a baud-div byte (LDRB then SUB#1 / 25 MHz sibling); not engine+0x88 .text")
}

/// Linux ARM `B3000000` (`0010015` octal). Host termios speed, not chip FastUART.
pub fn linux_b3000000_speed_t() -> u32 {
    BOSMINER_B3000000_SPEED_T
}

/// Four first-LOAD `MOVZ #0xC6C0` sites that complete `3_000_000`.
pub fn admit_bosminer_host_3m_movz_sites(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HOST_3M_MOVZ_HITS != 4 {
        return Err("host-3M MOVZ census drifted");
    }
    if BOSMINER_HOST_3M_BAUD != 3_000_000 {
        return Err("host-3M baud constant drifted");
    }
    for i in 0..BOSMINER_HOST_3M_MOVZ_HITS {
        let w = le_u32_at(blob, BOSMINER_HOST_3M_MOVZ_VA[i])
            .ok_or("bosminer shorter than host-3M MOVZ")?;
        if w != BOSMINER_HOST_3M_MOVZ_INSN[i] {
            return Err("host-3M MOVZ site is not MOVZ #0xC6C0");
        }
    }
    Ok(())
}

/// `FUN_00bbe3d4` compares `3_000_000` then `MOVZ W1,#0x100D` (`B3000000`).
pub fn admit_bosminer_host_3m_termios_b3000000(blob: &[u8]) -> Result<(), &'static str> {
    let movz = le_u32_at(blob, BOSMINER_HOST_3M_MOVZ_VA[0])
        .ok_or("bosminer shorter than termios 3M MOVZ")?;
    if movz != BOSMINER_HOST_3M_MOVZ_INSN[0] {
        return Err("0xbbe5bc is not MOVZ W8,#0xC6C0");
    }
    let movk = le_u32_at(blob, BOSMINER_HOST_3M_TERMIOS_MOVK_VA)
        .ok_or("bosminer shorter than termios 3M MOVK")?;
    if movk != BOSMINER_HOST_3M_TERMIOS_MOVK_INSN {
        return Err("0xbbe5c0 is not MOVK W8,#0x2D,LSL#16");
    }
    let speed = le_u32_at(blob, BOSMINER_B3000000_MOVZ_VA[0])
        .ok_or("bosminer shorter than B3000000 MOVZ")?;
    if speed != BOSMINER_B3000000_MOVZ_INSN[0] {
        return Err("0xbbe5cc is not MOVZ W1,#0x100D");
    }
    if linux_b3000000_speed_t() != 0x100D {
        return Err("B3000000 speed_t drifted");
    }
    Ok(())
}

/// AML serial open materializes host `3_000_000` in `W2` (`FUN_00bc1f28`).
pub fn admit_bosminer_aml_open_host_3m(blob: &[u8]) -> Result<(), &'static str> {
    let movz = le_u32_at(blob, BOSMINER_HOST_3M_MOVZ_VA[2])
        .ok_or("bosminer shorter than AML-open 3M MOVZ")?;
    if movz != BOSMINER_HOST_3M_MOVZ_INSN[2] {
        return Err("0xbc1f94 is not MOVZ W2,#0xC6C0");
    }
    let movk = le_u32_at(blob, BOSMINER_AML_OPEN_3M_MOVK_VA)
        .ok_or("bosminer shorter than AML-open 3M MOVK")?;
    if movk != BOSMINER_AML_OPEN_3M_MOVK_INSN {
        return Err("0xbc1fb4 is not MOVK W2,#0x2D,LSL#16");
    }
    let off = BOSMINER_ANTMINER_AML_RS_FILE_OFF as usize;
    if blob.get(off..off + BOSMINER_ANTMINER_AML_RS.len()) != Some(BOSMINER_ANTMINER_AML_RS) {
        return Err("file 0xf92558 is not antminer_aml.rs");
    }
    Ok(())
}

pub fn admit_bosminer_nix_termios_rs(blob: &[u8]) -> Result<(), &'static str> {
    let off = BOSMINER_NIX_TERMIOS_RS_FILE_OFF as usize;
    if blob.get(off..off + BOSMINER_NIX_TERMIOS_RS.len()) != Some(BOSMINER_NIX_TERMIOS_RS) {
        return Err("file 0xf9b584 is not nix-0.26.4 termios.rs");
    }
    Ok(())
}

/// Host 3M is `tcsetattr` / `B3000000`, not chip `set_config(0x28)`.
pub fn refuse_host_3m_termios_as_chip_fastuart_28() -> Result<(), &'static str> {
    Err(
        "bosminer host 3_000_000 is antminer_aml.rs + nix termios B3000000 (0x100D); the separate BM1366 trait path runtime-packs chip 0x28=0x00003011",
    )
}

/// The 14-byte bm1398 packer and 25e6/8 sibling are not this host-3M path.
pub fn refuse_legacy_pack_and_xtal25_as_host_3m_writer() -> Result<(), &'static str> {
    Err(
        "FUN_0091af6c dest map and FUN_008b24b8 25e6/8 are bm1398.rs chip fields; host 3M is termios B3000000",
    )
}

/// `bm1397.rs:103` packs `0x28=0x0600000F` through the generic REV-to-BE
/// command packer. This is legacy S17 evidence, not BM1366/S19k evidence.
pub fn admit_bosminer_bm1397_reg28_0600000f(blob: &[u8]) -> Result<(), &'static str> {
    let movz = le_u32_at(blob, BOSMINER_BM1397_REG28_MOVZ_VA)
        .ok_or("bosminer shorter than bm1397 0x28 MOVZ")?;
    if movz != BOSMINER_BM1397_REG28_MOVZ_INSN {
        return Err("0x8df2b0 is not MOVZ W0,#0x28");
    }
    let vlo = le_u32_at(blob, BOSMINER_BM1397_REG28_VAL_MOVZ_VA)
        .ok_or("bosminer shorter than bm1397 0x28 value MOVZ")?;
    if vlo != BOSMINER_BM1397_REG28_VAL_MOVZ_INSN {
        return Err("0x8df2a8 is not MOVZ W1,#0xF");
    }
    let vhi = le_u32_at(blob, BOSMINER_BM1397_REG28_VAL_MOVK_VA)
        .ok_or("bosminer shorter than bm1397 0x28 value MOVK")?;
    if vhi != BOSMINER_BM1397_REG28_VAL_MOVK_INSN {
        return Err("0x8df2b4 is not MOVK W1,#0x600,LSL#16");
    }
    let bl = le_u32_at(blob, BOSMINER_BM1397_REG28_BL_VA)
        .ok_or("bosminer shorter than bm1397 0x28 BL")?;
    if bl != BOSMINER_BM1397_REG28_BL_INSN {
        return Err("0x8df2b8 is not BL FUN_00bf328c");
    }
    let rev = le_u32_at(blob, BOSMINER_LEGACY_REG28_PACK_REV_VA)
        .ok_or("bosminer shorter than legacy 0x28 REV")?;
    if rev != BOSMINER_LEGACY_REG28_PACK_REV_INSN {
        return Err("0xbf32c0 is not REV W8,W21");
    }
    let source = BOSMINER_BM1397_REG28_LOC_FILE_OFF;
    if le_u64_at(blob, source) != Some(0x0132_34D2)
        || le_u64_at(blob, source + 8) != Some(54)
        || le_u64_at(blob, source + 16)
            != Some(
                u64::from(BOSMINER_BM1397_REG28_LOC_LINE)
                    | (u64::from(BOSMINER_BM1397_REG28_LOC_COL) << 32),
            )
        || le_u64_at(blob, BOSMINER_BM1397_REG28_VTABLE_FILE_OFF + 24)
            != Some(BOSMINER_BM1397_REG28_POLL_VA)
    {
        return Err("0x0600000F primary site is not bm1397.rs:103 poll 0x8df138");
    }
    Ok(())
}

pub fn admit_bosminer_bm1396_reg28_0600000f(blob: &[u8]) -> Result<(), &'static str> {
    let vlo = le_u32_at(blob, BOSMINER_BM1396_REG28_VAL_MOVZ_VA)
        .ok_or("bosminer shorter than bm1396 0x28 value MOVZ")?;
    if vlo != BOSMINER_BM1396_REG28_VAL_MOVZ_INSN {
        return Err("0x8464f4 is not MOVZ W1,#0xF");
    }
    let movz = le_u32_at(blob, BOSMINER_BM1396_REG28_MOVZ_VA)
        .ok_or("bosminer shorter than bm1396 0x28 MOVZ")?;
    if movz != BOSMINER_BM1396_REG28_MOVZ_INSN {
        return Err("0x8464fc is not MOVZ W0,#0x28");
    }
    let movk = le_u32_at(blob, BOSMINER_BM1396_REG28_VAL_MOVK_VA)
        .ok_or("bosminer shorter than bm1396 0x28 MOVK")?;
    if movk != BOSMINER_BM1396_REG28_VAL_MOVK_INSN {
        return Err("0x846500 is not MOVK W1,#0x600,LSL#16");
    }
    let bl = le_u32_at(blob, BOSMINER_BM1396_REG28_BL_VA)
        .ok_or("bosminer shorter than bm1396 0x28 BL")?;
    if bl != BOSMINER_BM1396_REG28_BL_INSN {
        return Err("0x846504 is not BL FUN_00bf328c");
    }
    let source = BOSMINER_BM1396_REG28_LOC_FILE_OFF;
    if le_u64_at(blob, source) != Some(0x0131_C3B8)
        || le_u64_at(blob, source + 8) != Some(54)
        || le_u64_at(blob, source + 16)
            != Some(
                u64::from(BOSMINER_BM1396_REG28_LOC_LINE)
                    | (u64::from(BOSMINER_BM1396_REG28_LOC_COL) << 32),
            )
        || le_u64_at(blob, BOSMINER_BM1396_REG28_VTABLE_FILE_OFF + 24)
            != Some(BOSMINER_BM1396_REG28_POLL_VA)
    {
        return Err("0x0600000F clone is not bm1396.rs:101 poll 0x846384");
    }
    if BOSMINER_LEGACY_REG28_PACK_CALL_HITS != 2 {
        return Err("0x28 pack-call census drifted");
    }
    Ok(())
}

/// Pure frame reproduction for the legacy S17 value. It grants no S19k lane.
pub fn pack_legacy_s17_reg28_uart() -> [u8; 11] {
    s19k_generic_set_config_uart(0x28, BOSMINER_LEGACY_S17_REG28_VALUE)
}

pub fn refuse_legacy_s17_reg28_0600000f_as_bm1366() -> Result<(), &'static str> {
    Err("0x0600000F sites are bm1397.rs:103 and bm1396.rs:101; refuse as BM1366/S19k evidence")
}

/// Integer ESP MiscCtrl formula. Not the ESP return 115749 and not FastUART 0x28.
pub fn esp_bm1366_miscctrl_formula_baud_hz() -> u32 {
    ESP_BM1366_MISCCTRL_XTAL_HZ / ((ESP_BM1366_MISCCTRL_DEFAULT_BAUD_DIV + 1) * 8)
}

/// ESP default ~115200 is MiscCtrl 0x18, not a FastUART 0x28 write.
pub fn refuse_esp_miscctrl_default_baud_as_fastuart_28() -> Result<(), &'static str> {
    Err(
        "ESP BM1366_set_default_baud writes MiscCtrl 0x18=0x00007A31 (div 26); not FastUART 0x28 leave-115200",
    )
}

/// ESP return 115749 ≠ integer 25e6/((26+1)*8)=115740. Neither is 0x28.
pub fn refuse_esp_default_baud_return_as_formula_hz() -> Result<(), &'static str> {
    if esp_bm1366_miscctrl_formula_baud_hz() == ESP_BM1366_SET_DEFAULT_BAUD_RETURN_HZ {
        return Err("ESP return unexpectedly equals integer formula; still not FastUART 0x28");
    }
    Err(
        "ESP BM1366_set_default_baud returns 115749; 25e6/((26+1)*8)=115740; neither is a FastUART 0x28 leave-115200 encoding",
    )
}

/// Admit only the exact stock BM1366 word as the stock leave-115200
/// transition. Other held dialects remain explicitly refused.
pub fn admit_s19k_stock_fastuart_28_write_as_leave_115200(value: u32) -> Result<(), &'static str> {
    match value {
        PUBLIC_FASTUART_VALUE => {
            Err("0x11300200 is ESP BM1366_set_max_baud 1 Mbps; not Track-1 leave-115200 to 3M")
        }
         => Err(
            "0x00003001 is bible BM1366 3.125M FastUART; not Track-1 host 3_000_000 leave-115200",
        ),
        BOSMINER_BM1366_FASTUART_3M125 => Ok(()),
        BOSMINER_LEGACY_S17_REG28_VALUE => Err(
            "0x0600000F is legacy BM1396/BM1397; not BM1366 and not a leave-115200-to-3M encoding",
        ),
        ESP_BM1366_MISCCTRL_DEFAULT_BAUD_VALUE => {
            Err("0x00007A31 is ESP MiscCtrl 0x18 default baud, not a FastUART 0x28 word")
        }
        _ => {
            Err("unknown chip FastUART 0x28 value; refuse inventing a leave-115200-to-3M encoding")
        }
    }
}

/// Track-1 115200 retry must read 0x28 and must not write 0x28 to leave 115200.
pub fn admit_s19k_production_track1_reads_not_writes_fastuart_28(
    src: &str,
) -> Result<(), &'static str> {
    let start = src
        .find("PASSTHROUGH BM1366")
        .ok_or("missing Track-1 PASSTHROUGH BM1366")?;
    let rest = src.get(start..).unwrap_or("");
    let end = rest
        .find("} else if passthrough")
        .unwrap_or(rest.len().min(80_000));
    let win = rest.get(..end).unwrap_or("");
    if !win.contains("send_read_reg_broadcast_bm1397plus") {
        return Err("Track-1 must broadcast-read FastUART 0x28");
    }
    if win.contains("send_write_reg_broadcast_bm1397plus(0x28")
        || win.contains("send_write_reg_broadcast_bm1397plus(PUBLIC_FASTUART_REG")
    {
        return Err("Track-1 must not write FastUART 0x28 to leave 115200 (encoding ungrounded)");
    }
    Ok(())
}

/// Bosminer has no `set_config` ASCII. Writes are packed_struct Command at runtime.
pub fn refuse_bosminer_ascii_set_config_as_packer() -> Result<(), &'static str> {
    Err("bosminer has no set_config symbol; packer is packed_struct-0.10.1 packing.rs + command.rs")
}

/// Generic BM1366 set_config UART (55 AA + 51 09 …). Same SSOT as `cmd_set_config`.
pub fn s19k_generic_set_config_uart(reg: u8, value: u32) -> [u8; 11] {
    let body = cmd_set_config(true, 0, reg, value);
    let mut uart = [0u8; 11];
    uart[0] = 0x55;
    uart[1] = 0xAA;
    uart[2..11].copy_from_slice(&body);
    uart
}

/// Reconstruct the exact stock BM1366 `FastUartReg` word built by
/// `FUN_008dd3b8` + `FUN_0091b024` + `FUN_0084ed8c`. The selector admits only
/// these two requested rates. This is a pure evidence model; it performs no
/// UART or host-termios mutation.
pub fn bosminer_bm1366_fastuart_value(requested_baud: u32) -> Result<u32, &'static str> {
    match requested_baud {
        1_000_000 => Ok(BOSMINER_BM1366_FASTUART_1M),
        BOSMINER_BM1366_REQUESTED_FAST_BAUD => Ok(BOSMINER_BM1366_FASTUART_3M125),
        _ => Err("stock bosminer BM1366 baud selector admits only 1M or 3.125M"),
    }
}

/// Exact runtime-packed stock broadcast frame for register `0x28`.
pub fn bosminer_bm1366_fastuart_uart(requested_baud: u32) -> Result<[u8; 11], &'static str> {
    let value = bosminer_bm1366_fastuart_value(requested_baud)?;
    Ok(s19k_generic_set_config_uart(
        BOSMINER_BM1366_FASTUART_REG,
        value,
    ))
}

pub fn admit_bosminer_contains_write_verify_str(blob: &[u8]) -> Result<(), &'static str> {
    let off = BOSMINER_WRITE_VERIFY_STR_FILE_OFF as usize;
    let needle = b"values were not written correctly to register";
    if blob.len() < off + needle.len() {
        return Err("bosminer blob shorter than write-verify pin");
    }
    if &blob[off..off + needle.len()] != needle {
        return Err("bosminer file 0xf20197 is not write-verify string");
    }
    Ok(())
}

/// ESP FastUART `0x28=0x11300200` is 1 Mbps. Refuse 3M/115200 host merge.
pub fn admit_s19k_fastuart_with_host_baud(host_baud: u32) -> Result<(), &'static str> {
    if host_baud == ESP_FASTUART_HOST_BAUD {
        Ok(())
    } else {
        Err("ESP FastUART 0x11300200 requires host 1_000_000; refuse 3M/115200 merge")
    }
}

/// Three evidence-backed S19k UART dialects. Do not merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kUartBaudDialect {
    /// `a lab unit` dmesg: 9600→115200 hold. No chip FastUART observed.
    Dmesg78Hold115200,
    /// 2026-08-12 Track-1: host ttyS `3_000_000` 8N1. Chip FastUART unknown.
    BraiinsHost3M,
    /// Exact stock S19k pairing: BM1366 register `0x28=0x00003011`, semantic
    /// request 3.125 Mbaud, and Amlogic Linux host termios `B3000000`.
    BraiinsStockBm1366FastUart,
    /// ESP-Miner `BM1366_set_max_baud`: chip `0x28=0x11300200`, host 1 Mbps.
    EspChipFastUart1M,
}

/// packed_struct byte lanes named in bosminer (`unknown_bits_31_24` …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kFastUartRegBytes {
    pub b31_24: u8,
    pub b23_16: u8,
    pub b15_8: u8,
    pub b7_0: u8,
}

pub fn split_s19k_fastuart_reg(value: u32) -> S19kFastUartRegBytes {
    S19kFastUartRegBytes {
        b31_24: (value >> 24) as u8,
        b23_16: (value >> 16) as u8,
        b15_8: (value >> 8) as u8,
        b7_0: value as u8,
    }
}

/// : ESP 1M FastUART is not Braiins 3M host termios.
pub fn refuse_esp_fastuart_as_s19k_braiins_3m(value: u32) -> Result<(), &'static str> {
    if value == PUBLIC_FASTUART_VALUE {
        return Err(
            "0x11300200 is ESP BM1366_set_max_baud 1 Mbps; not Braiins S19k 3M host termios",
        );
    }
    Ok(())
}

/// : bible BM1366 `0x00003001` is 3.125 Mbaud, not Track-1 host 3M.
pub fn refuse_bm1366_3001_as_s19k_braiins_3m(value: u32) -> Result<(), &'static str> {
    if value ==  {
        return Err(
            "0x00003001 is bible BM1366 3.125M FastUART; not Braiins S19k 3_000_000 host termios",
        );
    }
    Ok(())
}

/// A bare BM1362 attribution is not sufficient S19k evidence even though the
/// exact stock BM1366 builder is now proven to produce the same numeric word.
pub fn refuse_bm1362_3011_as_s19k_braiins_3m(value: u32) -> Result<(), &'static str> {
    if value ==  {
        return Err(
            "bare BM1362 0x00003011 provenance is insufficient; require the exact stock BM1366 vtable/packer + AML B3000000 chain",
        );
    }
    Ok(())
}

/// `MOVZ X1,#0x3001` in bosminer is followed by `MOVK` — not chip FastUART.
pub fn refuse_bosminer_movz_3001_as_fastuart() -> Result<(), &'static str> {
    Err("MOVZ X1,#0x3001 @ 0x10ba39c/0x10c49d8 is pointer materialization (MOVK follows); not FastUART")
}

/// The formerly mislabeled future is ticket-mask logic, not chip baud logic.
pub fn refuse_bosminer_ticket_mask_future_as_fastuart() -> Result<(), &'static str> {
    Err("FUN_00836934 maps difficulty and writes ticket-mask register 0x14; the BM1366 FastUART builder is FUN_008dd3b8")
}

/// Tuner Display enum is not UART `write_reg`.
pub fn refuse_bosminer_tuner_write_reg_display_as_uart() -> Result<(), &'static str> {
    Err("FUN_00645898 formats write_reg/soft_reset/reset_counters/work_time; not UART write_reg")
}

/// MiscCtrl modify is ASIC `0x18`, not FastUART `0x28`.
pub fn refuse_bosminer_miscctrl_modify_as_fastuart_28() -> Result<(), &'static str> {
    Err("FUN_008b40dc logs Modifying MiscCtrl for chip; not FastUART reg 0x28")
}

/// No packed `51 09 00 28` in the file. FastUART is runtime-packed.
pub fn refuse_bosminer_file_setcfg_28_as_s19k_fastuart(hits: usize) -> Result<(), &'static str> {
    if hits == 0 {
        return Err("0 literal 51 09 00 28 in bosminer.unpacked; the exact BM1366 command is runtime-packed through FUN_008dd3b8/FUN_0084ed8c");
    }
    Err("unexpected packed set_config 0x28 in bosminer file")
}

/// The four direct BE4-send callers are ticket-mask, send-self, and MiscCtrl.
/// BM1366 FastUART uses its trait builder plus the generic command path, so
/// this direct-call census cannot exclude the stock write.
pub fn refuse_uart_be4_send_callers_as_s19k_aml_fastuart() -> Result<(), &'static str> {
    Err(
        "4 direct BL UART_BE4_SEND @ 0x836c3c/0x8a2300/0x8a255c/0x8b4504 are ticket-mask/send-self/MiscCtrl; BM1366 FastUART is runtime-packed through the trait path",
    )
}

/// `MOVZ #0x28` is a common immediate, not a unique reg-0x28 writer.
pub fn refuse_movz_imm28_as_fastuart_reg(hits: usize) -> Result<(), &'static str> {
    if hits == 0 {
        return Ok(());
    }
    Err("MOVZ #0x28 is a common immediate; not a unique FastUART reg writer")
}

/// Byte-presence of `reg=0x28` + BE FastUART word. Does not prove a write site.
pub fn admit_bosminer_contains_reg28_fastuart_be(
    blob: &[u8],
    file_off: u64,
    value: u32,
) -> Result<(), &'static str> {
    let off = file_off as usize;
    if blob.len() < off + 6 {
        return Err("bosminer blob shorter than reg28 FastUART pin");
    }
    let be = value.to_be_bytes();
    let want = [0x28, 0x00, 0x00, 0x00, be[2], be[3]];
    if blob[off..off + 6] != want {
        return Err("bosminer file is not 28 00 00 00 || FastUART BE low");
    }
    Ok(())
}

/// Bible 3.125M chip FastUART may pair only with host 3.125M — never 3M/115200/1M.
pub fn admit_s19k_bible_fastuart_3125k_with_host_baud(host_baud: u32) -> Result<(), &'static str> {
    if host_baud ==  {
        Ok(())
    } else {
        Err("bible BM1366 0x00003001 requires host 3_125_000; refuse 3M/115200/1M merge")
    }
}

/// Exact stock S19k pairing. Bosminer requests 3.125 Mbaud from the BM1366
/// builder, writes `0x28=0x00003011`, and its AML driver maps that semantic
/// request to Linux `B3000000`.
pub fn admit_s19k_bosminer_stock_fastuart_with_host_baud(
    host_baud: u32,
) -> Result<(), &'static str> {
    if host_baud == BOSMINER_BM1366_AML_HOST_BAUD {
        Ok(())
    } else {
        Err("stock BM1366 0x00003011 on am3-aml requires host B3000000")
    }
}

/// Classify host baud + optional chip FastUART. Merge is refused.
pub fn classify_s19k_uart_baud_dialect(
    host_baud: u32,
    chip_fastuart: Option<u32>,
) -> Result<S19kUartBaudDialect, &'static str> {
    if let Some(v) = chip_fastuart {
        if v == PUBLIC_FASTUART_VALUE {
            if host_baud != ESP_FASTUART_HOST_BAUD {
                return Err("ESP FastUART 0x11300200 cannot pair with 3M/115200 host");
            }
            return Ok(S19kUartBaudDialect::EspChipFastUart1M);
        }
        if v ==  {
            return Err(
                "0x00003001 is bible BM1366 3.125M; refuse pairing as S19k Braiins 3M dialect",
            );
        }
        if v == BOSMINER_BM1366_FASTUART_3M125 {
            admit_s19k_bosminer_stock_fastuart_with_host_baud(host_baud)?;
            return Ok(S19kUartBaudDialect::BraiinsStockBm1366FastUart);
        }
        if v == BOSMINER_LEGACY_S17_REG28_VALUE {
            return Err("0x0600000F is legacy BM1396/BM1397; refuse as a BM1366/S19k dialect");
        }
        return Err("unknown chip FastUART value; refuse inventing a 3M encoding");
    }
    match host_baud {
        BRAIINS_PASSTHROUGH_BAUD => Ok(S19kUartBaudDialect::BraiinsHost3M),
        S19K_78_DMESG_HOLD_BAUD => Ok(S19kUartBaudDialect::Dmesg78Hold115200),
        ESP_FASTUART_HOST_BAUD => Err("host 1M without chip FastUART is not an S19k dialect"),
         => {
            Err("host 3.125M without an admitted chip FastUART is not an S19k dialect")
        }
        _ => Err("unrecognized S19k host baud"),
    }
}

/// Optional chip FastUART from `DCENT_S19K_CHIP_FASTUART` (hex). Unset = none.
pub fn s19k_track1_chip_fastuart_from_env(value: Option<&str>) -> Option<u32> {
    let s = value?.trim();
    if s.is_empty() {
        return None;
    }
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u32::from_str_radix(hex, 16).ok()
}

/// Type Track-1 host baud + optional FastUART for RX classify.
/// `baud.is_err()` turns GetAddress silence into `UartConfigMismatch`.
pub fn s19k_track1_classify_rx_baud(
    host_baud: u32,
    chip_fastuart_env: Option<&str>,
) -> Result<(), &'static str> {
    s19k_track1_classify_rx_baud_with_reg28(host_baud, chip_fastuart_env, None)
}

/// Observed chip `0x28` outranks the env hint. Unread stays env-only.
pub fn s19k_track1_classify_rx_baud_with_reg28(
    host_baud: u32,
    chip_fastuart_env: Option<&str>,
    observed_reg28: Option<u32>,
) -> Result<(), &'static str> {
    let chip = observed_reg28.or_else(|| s19k_track1_chip_fastuart_from_env(chip_fastuart_env));
    classify_s19k_uart_baud_dialect(host_baud, chip).map(|_| ())
}

/// What a read of chip FastUART `0x28` means. Unread is not 3M proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kChipFastUartKind {
    Unread,
    ZeroOrDefault,
    BibleBm1366_3m125,
    BosminerBm1362Bm1366_3m125,
    Esp1M,
    LegacyBm1396Bm1397_0600000F,
    Unknown(u32),
}

pub fn classify_s19k_chip_fastuart_word(v: Option<u32>) -> S19kChipFastUartKind {
    match v {
        None => S19kChipFastUartKind::Unread,
        Some(0) => S19kChipFastUartKind::ZeroOrDefault,
        Some => S19kChipFastUartKind::BibleBm1366_3m125,
        Some(BOSMINER_BM1366_FASTUART_3M125) => S19kChipFastUartKind::BosminerBm1362Bm1366_3m125,
        Some(PUBLIC_FASTUART_VALUE) => S19kChipFastUartKind::Esp1M,
        Some(BOSMINER_LEGACY_S17_REG28_VALUE) => S19kChipFastUartKind::LegacyBm1396Bm1397_0600000F,
        Some(other) => S19kChipFastUartKind::Unknown(other),
    }
}

/// Host 3M + unread `0x28` is not chip-115200 proof and not ASIC-uninit proof.
pub fn refuse_unread_fastuart_28_as_host_3m_chip_state() -> Result<(), &'static str> {
    Err("unread chip FastUART 0x28 cannot distinguish host 3M from 115200 chip; send 52 05 00 28")
}

/// Opt-in EXPERIMENTAL 115200 GetAddress retry after ChipFastUartUnread.
/// Default unset: do not change host baud. Restore is always 3M.
pub const S19K_TRACK1_RETRY_115200_ENV: &str = "DCENT_S19K_TRACK1_RETRY_115200";

pub fn s19k_track1_retry_115200_from_env(value: Option<&str>) -> Result<bool, &'static str> {
    match value {
        None | Some("") => Ok(false),
        Some("1") => Ok(true),
        Some(_) => Err("DCENT_S19K_TRACK1_RETRY_115200 must be 1 or unset"),
    }
}

/// Host baud after a 115200 retry. Always Track-1 3M, never leave 115200.
pub fn s19k_track1_retry_restore_baud() -> u32 {
    BRAIINS_PASSTHROUGH_BAUD
}

/// Ordered steps. Restore is last even if GetAddress / 0x28 fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kTrack1115200RetryStep {
    SetHost115200,
    GetAddress,
    /// Only after `GetAddressSilenceAt115200`.
    FastUart28IfGetAddressSilent,
    RestoreHost3M,
}

pub fn s19k_track1_115200_retry_steps() -> [S19kTrack1115200RetryStep; 4] {
    [
        S19kTrack1115200RetryStep::SetHost115200,
        S19kTrack1115200RetryStep::GetAddress,
        S19kTrack1115200RetryStep::FastUart28IfGetAddressSilent,
        S19kTrack1115200RetryStep::RestoreHost3M,
    ]
}

/// Probe chip FastUART 0x28 at 115200 only when GetAddress was silent.
pub fn s19k_track1_should_probe_fastuart_28_at_115200(getaddress_115200: S19kRxDiag) -> bool {
    getaddress_115200 == S19kRxDiag::GetAddressSilenceAt115200
}

/// Retry only when 3M GetAddress did not prove ChipAddress, 0x28 is unread,
/// host is 3M, and the env opt-in is set.
pub fn s19k_track1_should_retry_115200(
    getaddress_diag: S19kRxDiag,
    fastuart_diag: S19kRxDiag,
    host_baud: u32,
    env: Option<&str>,
) -> Result<bool, &'static str> {
    let want = s19k_track1_retry_115200_from_env(env)?;
    if !want {
        return Ok(false);
    }
    if host_baud != BRAIINS_PASSTHROUGH_BAUD {
        return Err("115200 retry requires host 3_000_000 so restore is well-defined");
    }
    if getaddress_diag == S19kRxDiag::ChipAddressOk
        || getaddress_diag == S19kRxDiag::ChainFailShortEnum
    {
        return Ok(false);
    }
    if fastuart_diag == S19kRxDiag::FastUartRegOk {
        return Ok(false);
    }
    if fastuart_diag != S19kRxDiag::ChipFastUartUnread
        && getaddress_diag != S19kRxDiag::AsicResetOrUninit
    {
        return Ok(false);
    }
    Ok(true)
}

/// A 115200 ChipAddress is not 3M work-TX proof.
pub fn refuse_chip_heard_at_115200_as_3m_work_proof(diag: S19kRxDiag) -> Result<(), &'static str> {
    if diag == S19kRxDiag::ChipHeardAt115200 {
        return Err("ChipHeardAt115200 is diagnostic; work TX stays on restored 3M GetAddress");
    }
    Ok(())
}

pub fn refuse_115200_retry_without_restore(
    steps: &[S19kTrack1115200RetryStep],
) -> Result<(), &'static str> {
    match steps.last() {
        Some(S19kTrack1115200RetryStep::RestoreHost3M) => Ok(()),
        _ => Err("115200 retry must end with RestoreHost3M"),
    }
}

/// Host-testable restore obligation. Production Drop calls `set_baud`.
pub struct S19kTrack1BaudRestoreGuard {
    restore_to: u32,
    armed: bool,
}

impl S19kTrack1BaudRestoreGuard {
    pub fn arm_after_115200() -> Self {
        Self {
            restore_to: s19k_track1_retry_restore_baud(),
            armed: true,
        }
    }

    pub fn restore_owed(&self) -> bool {
        self.armed
    }

    /// Explicit restore. Drop is a no-op after this.
    pub fn take_restore(&mut self) -> Option<u32> {
        if !self.armed {
            return None;
        }
        self.armed = false;
        Some(self.restore_to)
    }
}

impl Drop for S19kTrack1BaudRestoreGuard {
    fn drop(&mut self) {
        let _ = self.take_restore();
    }
}

/// Drop while armed must still produce the 3M restore baud.
pub fn s19k_track1_baud_restore_on_drop(armed: bool) -> Option<u32> {
    if armed {
        Some(s19k_track1_retry_restore_baud())
    } else {
        None
    }
}

/// Production 115200 retry is env-gated and must restore 3M after the probe.
pub fn admit_s19k_production_115200_retry_is_gated(src: &str) -> Result<(), &'static str> {
    if !src.contains("s19k_track1_should_retry_115200") {
        return Err("production must consult the 115200 retry gate");
    }
    if !src.contains("S19K_TRACK1_RETRY_115200_ENV") {
        return Err("115200 retry must be DCENT_S19K_TRACK1_RETRY_115200 opt-in");
    }
    if !src.contains("s19k_track1_retry_restore_baud")
        && !src.contains("BRAIINS_TTYS_BAUD")
        && !src.contains("3_000_000")
    {
        return Err("115200 retry must restore Track-1 3M");
    }
    if !src.contains("impl Drop for Track1HostBaudRestore") {
        return Err("115200 retry must restore 3M in Drop, not only sequentially");
    }
    let set115 = src
        .find("S19K_78_DMESG_HOLD_BAUD")
        .or_else(|| src.find("115_200"));
    let guard = src.find("Track1HostBaudRestore::arm");
    match (set115, guard) {
        (Some(a), Some(b)) if a < b => Ok(()),
        _ => Err("Track1HostBaudRestore must arm after the 115200 set_baud"),
    }
}

/// Production Drop must call restore baud, not only disarm.
pub fn admit_s19k_production_115200_retry_drop_restores(src: &str) -> Result<(), &'static str> {
    let start = src
        .find("impl Drop for Track1HostBaudRestore")
        .ok_or("missing Track1HostBaudRestore Drop")?;
    let rest = &src[start..];
    let end = rest.find("\n}").ok_or("cannot bound Drop impl")?;
    let body = &rest[..end];
    if !body.contains("set_baud") {
        return Err("Drop must call set_baud");
    }
    if !body.contains("s19k_track1_retry_restore_baud") && !body.contains("restore_to") {
        return Err("Drop must restore Track-1 3M");
    }
    Ok(())
}

/// First restore + one retry. Two failures are not 3M work-TX proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kTrack1RestoreBaudAttempt {
    FirstOk,
    RetryOk,
    FailedAfterRetry,
}

pub fn s19k_track1_restore_baud_attempt(
    first_ok: bool,
    retry_ok: bool,
) -> S19kTrack1RestoreBaudAttempt {
    if first_ok {
        S19kTrack1RestoreBaudAttempt::FirstOk
    } else if retry_ok {
        S19kTrack1RestoreBaudAttempt::RetryOk
    } else {
        S19kTrack1RestoreBaudAttempt::FailedAfterRetry
    }
}

/// Host baud after restore. 115200 (or any non-3M) is not work-TX capable.
pub fn refuse_work_tx_if_host_not_3m_after_restore(host_baud: u32) -> Result<(), &'static str> {
    if host_baud == s19k_track1_retry_restore_baud() {
        Ok(())
    } else {
        Err("host UART is not 3M after 115200 restore; refuse work TX at 115200")
    }
}

pub fn refuse_restore_failed_as_3m_work_proof(
    attempt: S19kTrack1RestoreBaudAttempt,
) -> Result<(), &'static str> {
    match attempt {
        S19kTrack1RestoreBaudAttempt::FailedAfterRetry => {
            Err("restore to 3M failed after retry; not 3M work-TX proof")
        }
        S19kTrack1RestoreBaudAttempt::FirstOk | S19kTrack1RestoreBaudAttempt::RetryOk => Ok(()),
    }
}

/// Drop must retry set_baud; production must refuse work TX if host stayed off 3M.
pub fn admit_s19k_production_restore_retries_then_refuses(src: &str) -> Result<(), &'static str> {
    if !src.contains("refuse_work_tx_if_host_not_3m_after_restore") {
        return Err("production must refuse work TX if host baud is not 3M after restore");
    }
    let start = src
        .find("impl Drop for Track1HostBaudRestore")
        .ok_or("missing Track1HostBaudRestore Drop")?;
    let rest = &src[start..];
    let end = rest.find("\n}").ok_or("cannot bound Drop impl")?;
    let body = &rest[..end];
    if body.matches("set_baud").count() < 2 {
        return Err("Drop must retry set_baud after the first restore failure");
    }
    Ok(())
}

/// 50 MHz is the public ramp **start**, not S19k stock mining frequency.
pub fn refuse_pll0_50mhz_as_s19k_stock_mining_freq(mhz: u32) -> Result<(), &'static str> {
    if mhz == PLL_RAMP_START_MHZ {
        return Err("50 MHz is PLL ramp start, not S19k stock mining frequency");
    }
    Ok(())
}

/// PLL0 at an explicit target. Same SSOT as `serial_mining`.
pub fn s19k_native_pll0_write(target_mhz: u16) -> S19kExperimentalInitWrite {
    let (reg, _) = bm1366_pll_reg_and_actual(target_mhz);
    init_write("pll0", REG_PLL0, reg, true, 0)
}

/// Opt-in FastUART write. Not part of the default native program.
pub fn s19k_native_fastuart_write() -> S19kExperimentalInitWrite {
    init_write(
        "fastuart_1m",
        PUBLIC_FASTUART_REG,
        PUBLIC_FASTUART_VALUE,
        true,
        0,
    )
}

/// Opt-in bible BM1366 3.125M FastUART (`0x28=0x00003001`).
/// Not in the default native program. Not Braiins S19k 3M termios.
pub fn s19k_native_fastuart_bible_3125k_write() -> S19kExperimentalInitWrite {
    init_write(
        "fastuart_bible_3125k",
        PUBLIC_FASTUART_REG,
        ,
        true,
        0,
    )
}

/// PLL0 at the public ramp-start (50 MHz). Same SSOT as `serial_mining`.
pub fn s19k_native_pll0_start_write() -> S19kExperimentalInitWrite {
    let (reg, _) = bm1366_pll_reg_and_actual(PLL_RAMP_START_MHZ as u16);
    init_write("pll0_50mhz", REG_PLL0, reg, true, 0)
}

/// Braiins Track-1 stays at host 3 Mbaud. Do not merge with jig 12 M.
pub const BRAIINS_PASSTHROUGH_BAUD: u32 = BRAIINS_TTYS_BAUD;
/// Native / jig class (HashSource PT). Separate dialect — never merge.
pub const NATIVE_JIG_BAUD_HZ: u32 = 12_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kInitDialect {
    /// Rails already up; do not reset; do not change baud.
    BraiinsPassthrough,
    /// Cold native — EXPERIMENTAL, not production-admitted.
    NativeExperimental,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kInitStep {
    pub name: &'static str,
    pub uart: Vec<u8>,
}

/// Ordered UART-byte manifest. Passthrough skips reset / baud / analog-mux.
///
/// This must not be treated as a complete executor plan: steps carry no
/// commit receipt, dwell, response barrier, or requested target frequency.
pub fn s19k_bm1366_init_program(dialect: S19kInitDialect) -> Vec<S19kInitStep> {
    let mut steps = Vec::new();
    match dialect {
        S19kInitDialect::BraiinsPassthrough => {
            steps.push(S19kInitStep {
                name: "get_address",
                uart: GET_ADDRESS_UART.to_vec(),
            });
            // After bosminer kill-9, re-arm hashing regs without reset/baud.
            // Ticket 0xFF (diff-256) + HCN 0x115A. Not ESP VR 0xA4=0x9000FFFF.
            for w in s19k_passthrough_rearm_writes() {
                steps.push(S19kInitStep {
                    name: w.name,
                    uart: pack_experimental_init_write(w).to_vec(),
                });
            }
        }
        S19kInitDialect::NativeExperimental => {
            // ESP-Miner BM1366_init order, AML interval 2 (not 256/n).
            // PLL0 @ 50 MHz after per-chip (ESP frequency transition).
            // The later requested-target PLL transition is not modeled here.
            // FastUART 0x28 stays opt-in: 1 Mbps host only.
            steps.push(S19kInitStep {
                name: "get_address",
                uart: GET_ADDRESS_UART.to_vec(),
            });
            steps.push(step_from_write(*INIT_CTRL_A8_BCAST_WRITE));
            steps.push(step_from_write(*MISC_CTRL_BCAST_WRITE));
            steps.push(S19kInitStep {
                name: "chain_inactive",
                uart: CHAIN_INACTIVE_UART.to_vec(),
            });
            for addr in s19k_aml_linear_addresses() {
                steps.push(S19kInitStep {
                    name: "set_address",
                    uart: pack_set_address_uart_trans(addr).to_vec(),
                });
            }
            steps.push(step_from_write(*CORE_HASH_CLOCK_BCAST_WRITE));
            steps.push(step_from_write(*CORE_CLOCK_DELAY_BCAST_WRITE));
            steps.push(step_from_write(*TICKET_MASK_BCAST_WRITE));
            steps.push(step_from_write(*ANALOG_MUX_BCAST_WRITE));
            steps.push(step_from_write(*IO_DRIVER_BCAST_WRITE));
            steps.push(step_from_write(*UART_RELAY_CHIP0_WRITE));
            for addr in s19k_aml_linear_addresses() {
                for w in s19k_native_per_chip_core_writes(addr) {
                    steps.push(step_from_write(w));
                }
            }
            steps.push(step_from_write(s19k_native_pll0_start_write()));
            steps.push(step_from_write(*HASH_COUNTING_BCAST_WRITE));
            // : do not arm ESP 0xA4=0x9000FFFF. Fill hashes packed ver0.
        }
    }
    steps
}

pub fn admit_init_dialect_baud(dialect: S19kInitDialect, baud: u32) -> Result<(), &'static str> {
    match dialect {
        S19kInitDialect::BraiinsPassthrough => {
            if baud != BRAIINS_PASSTHROUGH_BAUD {
                return Err("passthrough must keep bosminer 3_000_000; refuse baud change");
            }
        }
        S19kInitDialect::NativeExperimental => {
            if baud != NATIVE_JIG_BAUD_HZ
                && baud != BRAIINS_PASSTHROUGH_BAUD
                && baud != S19K_78_DMESG_HOLD_BAUD
            {
                return Err(
                    "native experimental baud must be 12M jig, 3M Braiins host, or 115200 .78 hold",
                );
            }
        }
    }
    Ok(())
}

/// ESP-Miner `BM1366_CHIP_ID_RESPONSE_LENGTH` is 11. BM1397 is 9.
pub fn refuse_bm1397_9byte_as_bm1366_getaddress_rx(len: usize) -> Result<(), &'static str> {
    if len == 9 {
        return Err("BM1397 GetAddress RX is 9 bytes; BM1366 ESP CHIP_ID response is 11");
    }
    if len == ESP_BM1366_CHIP_ID_RX_LEN && len == UART_RESP_LEN {
        return Ok(());
    }
    Err("BM1366 GetAddress RX length is 11")
}

pub fn refuse_native_as_production(dialect: S19kInitDialect) -> Result<(), &'static str> {
    match dialect {
        S19kInitDialect::BraiinsPassthrough => Ok(()),
        S19kInitDialect::NativeExperimental => {
            Err("native BM1366 cold-init is EXPERIMENTAL; production still refuses")
        }
    }
}

pub fn init_ports() -> &'static [&'static str] {
    BRAIINS_TTYS_DISCOVER
}

/// Passthrough re-arm after GetAddress on an answering ttyS. No reset, no
/// set_address, no baud change. Ticket+HCN+analog-mux. Not ESP VersionMask,
/// not MiscCtrl (baud bits), not core clock.
///
/// : held `bosminer.unpacked` (sha256 `5a49dcbe…`) names
/// `hash_counting_number` as the version-rolling clock divider and
/// `work_time` as TX interval, not extra chip regs. `FUN_008434e0` is
/// software max-work-time (`HCN / (12.5e6/freq)`), not a UART writer.
/// Analog mux `0x54=3` is the leftover-safe extra from the ESP/jig INIT
/// list (not baud, not VersionMask). live414 ticket+HCN-only died wrap-7.
pub fn s19k_passthrough_rearm_writes() -> impl Iterator<Item = S19kExperimentalInitWrite> {
    S19K_EXPERIMENTAL_INIT_WRITES.iter().copied().filter(|w| {
        matches!(
            w.name,
            "ticket_mask_diff256" | "hash_counting_s19k" | "analog_mux"
        )
    })
}

/// EXPERIMENTAL register writes (jig + ESP-Miner agree on values).
/// Not a production cold-init. Host baud must match before FastUART 0x28.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kExperimentalInitWrite {
    pub name: &'static str,
    pub reg: u8,
    pub value: u32,
    pub bcast: bool,
    pub chip_addr: u8,
}

const fn init_write(
    name: &'static str,
    reg: u8,
    value: u32,
    bcast: bool,
    chip_addr: u8,
) -> S19kExperimentalInitWrite {
    S19kExperimentalInitWrite {
        name,
        reg,
        value,
        bcast,
        chip_addr,
    }
}

pub const INIT_CTRL_A8_BCAST_WRITE: &S19kExperimentalInitWrite = &init_write(
    "init_ctrl_a8_bcast",
    INIT_REG_INIT_CTRL,
    INIT_CTRL_A8_BCAST,
    true,
    0,
);
pub const MISC_CTRL_BCAST_WRITE: &S19kExperimentalInitWrite =
    &init_write("misc_ctrl_bcast", 0x18, 0xFF0F_C100, true, 0);
pub const CORE_HASH_CLOCK_BCAST_WRITE: &S19kExperimentalInitWrite =
    &init_write("core_hash_clock", 0x3C, CORE_REG_HASH_CLOCK, true, 0);
pub const CORE_CLOCK_DELAY_BCAST_WRITE: &S19kExperimentalInitWrite =
    &init_write("core_clock_delay", 0x3C, CORE_REG_CLOCK_DELAY, true, 0);
pub const TICKET_MASK_BCAST_WRITE: &S19kExperimentalInitWrite = &init_write(
    "ticket_mask_diff256",
    INIT_REG_TICKET_MASK,
    TICKET_MASK_PLAIN_DIFF_MINUS_ONE_256,
    true,
    0,
);
pub const ANALOG_MUX_BCAST_WRITE: &S19kExperimentalInitWrite =
    &init_write("analog_mux", 0x54, 0x0000_0003, true, 0);
pub const IO_DRIVER_BCAST_WRITE: &S19kExperimentalInitWrite =
    &init_write("io_driver", 0x58, 0x0211_1111, true, 0);
pub const UART_RELAY_CHIP0_WRITE: &S19kExperimentalInitWrite = &init_write(
    "uart_relay_chip0",
    REG_UART_RELAY,
    UART_RELAY_CHIP0_PUBLIC,
    false,
    0,
);
pub const HASH_COUNTING_BCAST_WRITE: &S19kExperimentalInitWrite = &init_write(
    "hash_counting_s19k",
    INIT_REG_HASH_COUNTING,
    S19K_WIRE_HASH_COUNTING,
    true,
    0,
);
/// ESP-Miner `BM1366_init` live default (S19XP). Not the S19k rearm word.
pub const ESP_BM1366_HASH_COUNTING_S19XP: u32 = 0x0000_151C;

/// ESP-Miner BM1366 VersionMask (S19XP / Bitaxe). Not a Braiins fill re-arm.
pub const ESP_BM1366_VERSION_ROLL_MASK: u32 = 0x9000_FFFF;
/// Sole `90 00 FF FF` in first-LOAD is UTF-16 `U+0090` next to `0xFFFF` pad.
pub const BOSMINER_9000FFFF_BE_FILE_OFF: u64 = 0x011F_D4B0;
pub const BOSMINER_9000FFFF_BE_VA: u64 = 0x015F_D4B0;
/// Preceding UTF-16 unit `U+0080` then `U+0090`.
pub const BOSMINER_9000FFFF_PREV_U16: u16 = 0x0080;
/// Sole first-LOAD `MOVZ Wd,#0xA4` is `ldr [x0,x8]` object+0xA4, not set_config.
pub const BOSMINER_MOVZ_A4_VA: u64 = 0x00E7_A568;
pub const BOSMINER_MOVZ_A4_INSN: u32 = 0x5280_1488;
pub const BOSMINER_MOVZ_A4_LDR_INSN: u32 = 0xB868_6808;

/// ESP `0xA4=0x9000FFFF` would roll BIP320 under a packed-ver0 fill job.
pub fn refuse_esp_9000ffff_as_braiins_fill_rearm(reg: u8, value: u32) -> Result<(), &'static str> {
    if reg == INIT_REG_VERSION_ROLL && value == ESP_BM1366_VERSION_ROLL_MASK {
        return Err(
            "Braiins fill hashes packed ver0; refuse ESP 0xA4=0x9000FFFF as fill/native re-arm",
        );
    }
    Ok(())
}

pub fn admit_s19k_passthrough_rearm_omits_version_roll(names: &[&str]) -> Result<(), &'static str> {
    if names.iter().any(|n| *n == "version_roll") {
        return Err("S19k init program must not write ESP VersionMask");
    }
    if !names.iter().any(|n| *n == "ticket_mask_diff256") {
        return Err("passthrough re-arm must keep ticket_mask");
    }
    if !names.iter().any(|n| *n == "hash_counting_s19k") {
        return Err("passthrough re-arm must keep HCN 0x115A");
    }
    Ok(())
}

/// Mid-run keep-alive after live414 wrap-7. Analog mux is extra; MiscCtrl
/// stays out (baud bits). VersionMask stays refused.
pub fn admit_s19k_midrun_rearm_includes_analog_mux(names: &[&str]) -> Result<(), &'static str> {
    admit_s19k_passthrough_rearm_omits_version_roll(names)?;
    if !names.iter().any(|n| *n == "analog_mux") {
        return Err("mid-run re-arm must include analog_mux 0x54=3 (live414 wrap-7)");
    }
    if names
        .iter()
        .any(|n| *n == "misc_ctrl_bcast" || *n == "version_roll")
    {
        return Err("mid-run re-arm must not write MiscCtrl baud bits or VersionMask");
    }
    Ok(())
}

/// Six-byte window at `BOSMINER_9000FFFF_BE_FILE_OFF-2`: `80 00 90 00 FF FF`.
pub fn refuse_bosminer_9000ffff_utf16_as_version_mask(window: &[u8]) -> Result<(), &'static str> {
    if window.len() < 6 {
        return Err("UTF-16 pad window must be 6 bytes");
    }
    if u16::from_le_bytes([window[0], window[1]]) != BOSMINER_9000FFFF_PREV_U16 {
        return Err("9000FFFF is not preceded by UTF-16 U+0080");
    }
    if window[2..6] != [0x90, 0x00, 0xFF, 0xFF] {
        return Err("expected 90 00 FF FF UTF-16 pad");
    }
    Err("bosminer 90 00 FF FF is UTF-16 U+0090 + 0xFFFF pad, not VersionMask")
}

/// `MOVZ W8,#0xA4` then `LDR W8,[X0,X8]` is a field compare, not set_config.
pub fn refuse_bosminer_movz_a4_as_set_config(movz: u32, ldr: u32) -> Result<(), &'static str> {
    if movz != BOSMINER_MOVZ_A4_INSN {
        return Err("0xe7a568 is not MOVZ W8,#0xA4");
    }
    if ldr != BOSMINER_MOVZ_A4_LDR_INSN {
        return Err("0xe7a56c is not LDR W8,[X0,X8]");
    }
    Err("MOVZ #0xA4 is object+0xA4 compare, not UART set_config(reg=0xA4)")
}

pub fn refuse_esp_s19xp_hcn_as_s19k_rearm(value: u32) -> Result<(), &'static str> {
    if value == ESP_BM1366_HASH_COUNTING_S19XP {
        return Err("S19k rearm HCN must be 0x115A; ESP/S19XP default is 0x151C");
    }
    if value != S19K_WIRE_HASH_COUNTING {
        return Err("S19k HCN must be 0x115A");
    }
    Ok(())
}
pub const VERSION_ROLL_BCAST_WRITE: &S19kExperimentalInitWrite =
    &init_write("version_roll", INIT_REG_VERSION_ROLL, 0x9000_FFFF, true, 0);

pub const S19K_EXPERIMENTAL_INIT_WRITES: &[S19kExperimentalInitWrite] = &[
    *ANALOG_MUX_BCAST_WRITE,
    *CORE_HASH_CLOCK_BCAST_WRITE,
    *CORE_CLOCK_DELAY_BCAST_WRITE,
    *TICKET_MASK_BCAST_WRITE,
    *HASH_COUNTING_BCAST_WRITE,
    *VERSION_ROLL_BCAST_WRITE,
    *MISC_CTRL_BCAST_WRITE,
    *IO_DRIVER_BCAST_WRITE,
    *UART_RELAY_CHIP0_WRITE,
    *INIT_CTRL_A8_BCAST_WRITE,
];

/// ESP-Miner per-chip core program after addressing. Interval-2 AML addrs.
pub fn s19k_native_per_chip_core_writes(chip_addr: u8) -> [S19kExperimentalInitWrite; 5] {
    [
        init_write(
            "init_ctrl_a8_unicast",
            INIT_REG_INIT_CTRL,
            INIT_CTRL_A8_UNICAST,
            false,
            chip_addr,
        ),
        init_write(
            "misc_ctrl_unicast",
            0x18,
            MISC_CTRL_UNICAST,
            false,
            chip_addr,
        ),
        init_write(
            "core_hash_clock_unicast",
            0x3C,
            CORE_REG_HASH_CLOCK,
            false,
            chip_addr,
        ),
        init_write(
            "core_clock_delay_unicast",
            0x3C,
            CORE_REG_CLOCK_DELAY,
            false,
            chip_addr,
        ),
        init_write(
            "core_asicboost_unicast",
            0x3C,
            CORE_REG_ASICBOOST,
            false,
            chip_addr,
        ),
    ]
}

/// One effect-free command in the exact native BM1366 execution program.
/// Runtime code must translate this enum through its retained serial commit
/// owner; raw UART bytes are retained only by the legacy evidence manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kBm1366NativeCommandOp {
    ChainInactive,
    SetAddress { address: u8 },
    WriteRegister(S19kExperimentalInitWrite),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kBm1366NativeCommand {
    pub name: &'static str,
    pub op: S19kBm1366NativeCommandOp,
    /// Conservative DCENT engine policy, not a recovered stock timing claim.
    pub dwell_after_ms: u64,
}

/// Exact 77-chip S19k DCENT command program split at the two response barriers.
///
/// The section boundaries are load-bearing:
///
/// - `pre_baud_commands` may execute only after a fresh 115200 enumeration;
/// - `fast_uart_command` is followed by the exact host transition and a fresh
///   switched-baud enumeration;
/// - `post_baud_commands` and `final_commands` require the move-only
///   switched-baud admission held by the daemon; and
/// - work remains separately production-refused after final enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kBm1366NativeExecutionProgram {
    pub expected_chip_count: u8,
    pub address_interval: u8,
    pub initial_host_baud: u32,
    pub requested_fast_baud: u32,
    pub fast_host_baud: u32,
    pub pre_baud_commands: Vec<S19kBm1366NativeCommand>,
    pub fast_uart_command: S19kBm1366NativeCommand,
    pub post_host_baud_settle_ms: u64,
    pub post_baud_commands: Vec<S19kBm1366NativeCommand>,
    pub post_baud_tail_settle_ms: u64,
    pub final_commands: Vec<S19kBm1366NativeCommand>,
    pub actual_frequency_mhz: u16,
}

fn native_command(
    name: &'static str,
    op: S19kBm1366NativeCommandOp,
    dwell_after_ms: u64,
) -> S19kBm1366NativeCommand {
    S19kBm1366NativeCommand {
        name,
        op,
        dwell_after_ms,
    }
}

fn native_write_command(
    write: S19kExperimentalInitWrite,
    dwell_after_ms: u64,
) -> S19kBm1366NativeCommand {
    native_command(
        write.name,
        S19kBm1366NativeCommandOp::WriteRegister(write),
        dwell_after_ms,
    )
}

/// Build the exact DCENT program with the held-stock FastUART pair consumed by
/// the dormant native executor. The S19k route is deliberately fixed to its
/// evidenced 77-chip geometry; S19XP/Bitaxe or AMTC 128-command ladders require
/// other builders.
pub fn s19k_bm1366_native_execution_program(
    expected_chip_count: u8,
    target_frequency_mhz: u16,
) -> Result<S19kBm1366NativeExecutionProgram, &'static str> {
    let addresses = s19k_aml_linear_addresses();
    if expected_chip_count as usize != addresses.len() {
        return Err("S19k native execution program requires exact 77-chip geometry");
    }
    refuse_pll0_50mhz_as_s19k_stock_mining_freq(u32::from(target_frequency_mhz))?;

    let mut pre_baud_commands = vec![
        native_write_command(*INIT_CTRL_A8_BCAST_WRITE, 5),
        native_write_command(*MISC_CTRL_BCAST_WRITE, 5),
        native_command(
            "chain_inactive",
            S19kBm1366NativeCommandOp::ChainInactive,
            10,
        ),
    ];
    for (index, address) in addresses.iter().copied().enumerate() {
        let one_based = index + 1;
        let mut dwell_after_ms = if one_based % 16 == 0 { 2 } else { 0 };
        if one_based == addresses.len() {
            dwell_after_ms += 10;
        }
        pre_baud_commands.push(native_command(
            "set_address",
            S19kBm1366NativeCommandOp::SetAddress { address },
            dwell_after_ms,
        ));
    }
    pre_baud_commands.extend([
        native_write_command(*CORE_HASH_CLOCK_BCAST_WRITE, 5),
        native_write_command(*CORE_CLOCK_DELAY_BCAST_WRITE, 5),
        native_write_command(*TICKET_MASK_BCAST_WRITE, 5),
        native_write_command(*ANALOG_MUX_BCAST_WRITE, 5),
        native_write_command(*IO_DRIVER_BCAST_WRITE, 5),
        native_write_command(*UART_RELAY_CHIP0_WRITE, 5),
    ]);

    let fast_uart_value = bosminer_bm1366_fastuart_value(BOSMINER_BM1366_REQUESTED_FAST_BAUD)?;
    admit_s19k_stock_fastuart_28_write_as_leave_115200(fast_uart_value)?;
    admit_s19k_bosminer_stock_fastuart_with_host_baud(BOSMINER_BM1366_AML_HOST_BAUD)?;
    let fast_uart_command = native_write_command(
        init_write(
            "fastuart_stock_3m125",
            BOSMINER_BM1366_FASTUART_REG,
            fast_uart_value,
            true,
            0,
        ),
        10,
    );

    let mut post_baud_commands = Vec::with_capacity(addresses.len() * 5);
    for address in addresses.iter().copied() {
        for (index, write) in s19k_native_per_chip_core_writes(address)
            .into_iter()
            .enumerate()
        {
            post_baud_commands.push(native_write_command(write, if index == 4 { 5 } else { 0 }));
        }
    }

    let (pll_register, actual_frequency_mhz) = bm1366_pll_reg_and_actual(target_frequency_mhz);
    let final_commands = vec![
        native_write_command(
            init_write("pll0_target", REG_PLL0, pll_register, true, 0),
            100,
        ),
        native_write_command(*HASH_COUNTING_BCAST_WRITE, 10),
    ];

    Ok(S19kBm1366NativeExecutionProgram {
        expected_chip_count,
        address_interval: crate::s19k_bm1366_wire_b::S19K_AML_ADDR_INTERVAL,
        initial_host_baud: S19K_78_DMESG_HOLD_BAUD,
        requested_fast_baud: BOSMINER_BM1366_REQUESTED_FAST_BAUD,
        fast_host_baud: BOSMINER_BM1366_AML_HOST_BAUD,
        pre_baud_commands,
        fast_uart_command,
        post_host_baud_settle_ms: 50,
        post_baud_commands,
        post_baud_tail_settle_ms: 50,
        final_commands,
        actual_frequency_mhz,
    })
}

pub fn refuse_firmware_internals_a8_as_s19k_per_chip(value: u32) -> Result<(), &'static str> {
    if value == REFUSED_INTERNALS_A8_PER_CHIP {
        return Err(
            "FIRMWARE_INTERNALS 0xA8=0xF0010700 contradicts ESP UART 00 07 01 F0; refuse as S19k",
        );
    }
    if value != INIT_CTRL_A8_UNICAST {
        return Err("S19k per-chip 0xA8 must be ESP 0x000701F0");
    }
    Ok(())
}

fn step_from_write(w: S19kExperimentalInitWrite) -> S19kInitStep {
    S19kInitStep {
        name: w.name,
        uart: pack_experimental_init_write(w).to_vec(),
    }
}

/// Compact bench/log summary. Does not execute UART.
pub fn format_s19k_native_init_summary(steps: &[S19kInitStep]) -> String {
    let set_addr = steps.iter().filter(|s| s.name == "set_address").count();
    let a8_u = steps
        .iter()
        .filter(|s| s.name == "init_ctrl_a8_unicast")
        .count();
    format!(
        "S19K_NATIVE_INIT steps={} set_address={} a8_unicast={} owner_required=true authority_minted=false",
        steps.len(),
        set_addr,
        a8_u,
    )
}

pub fn pack_experimental_init_write(w: S19kExperimentalInitWrite) -> [u8; 11] {
    let mut uart = [0x55, 0xAA, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let body = cmd_set_config(w.bcast, w.chip_addr, w.reg, w.value);
    uart[2..].copy_from_slice(&body);
    uart
}

///  / production-firmware evidence — S19k Pro AML control-board GPIO
/// map. VNish ("Awesome") S19k Pro AML installer v1.3.3
/// (`awesome-s19kpro-aml-nand-v1.3.3-install.tar.gz`, initramfs
/// `etc/init.d/S11board`) exports at boot:
///
/// - `pwr_en` GPIO **437** out, boot value **1** — production firmware holds
///   the rail OFF at board init, independently confirming the live `.88`
///   finding that 0=ON for am3-s19k (do NOT flip S21 polarity from this).
/// - chain resets: `ch0_rst` **454**, `ch1_rst` **455**, `ch2_rst` **456**
///   (out) — closes the wire-doc open question "GPIO numbers for chain
///   reset on am3-s19kpro" with production evidence.
/// - plug detect: `ch0/1/2_plug` **439/440/441** (in, pull-down) — matches
///   the BM1368-fabric populated-slot topology inputs.
/// - fan tachs: `fan_front_speed0/1` **447/448**, `fan_rear_speed0/1`
///   **449/450** (in, falling edge); PWM `pwmchip0` pwm0=rear (FAN2/FAN4),
///   pwm1=front (FAN1/FAN3), period 100_000 ns, duty 100_000 at boot.
/// - `led_green` **453**, `led_red` **438**, `gpio_recovery` **446** (in),
///   `gpio_ip_get` **445** (in).
///
/// Constants + admission only: nothing here authorizes a live write, and the
/// native BM1366 dialect stays experimental/refused until its own gates pass.
pub const S19K_AML_PWR_EN_GPIO: u32 = 437;
/// am3-s19k / Braiins S19k Pro software SoT (live 2026-08-12 + VNish
/// S11board boot value 1 = rail OFF). Do not reuse S21 1=ON / SafeOff=0.
pub const S19K_AML_PWR_EN_ON: u8 = 0;
pub const S19K_AML_PWR_EN_OFF: u8 = 1;

pub fn s19k_aml_pwr_en_is_on(value: u8) -> bool {
    value == S19K_AML_PWR_EN_ON
}

/// Track-1 leftover handoff is only legal while the rail is already ON.
/// We never write GPIO437; gpio=1 is a refuse, not a flip.
pub fn s19k_track1_leftover_handoff_gpio437_ok(value: Option<u8>) -> bool {
    matches!(value, Some(S19K_AML_PWR_EN_ON))
}

/// Track-1 leftover work TX is only legal while gpio437=0 (rail already ON).
/// gpio=1 / unread is a skip, never a write.
pub fn s19k_track1_refuse_work_tx_if_gpio437_not_on(value: Option<u8>) -> Result<(), &'static str> {
    if s19k_track1_leftover_handoff_gpio437_ok(value) {
        Ok(())
    } else {
        Err("Track-1 leftover work TX requires gpio437=0 (rail ON); never write GPIO437")
    }
}

/// Production dispatch must refuse 21 36 TX when leftover handoff is not ON.
pub fn admit_s19k_production_refuses_tx_when_gpio437_off(src: &str) -> Result<(), &'static str> {
    if !src.contains("s19k_track1_refuse_work_tx_if_gpio437_not_on") {
        return Err("dispatch must refuse work TX when gpio437 is not leftover-ON");
    }
    if !src.contains("S19k leftover handoff gpio437 not ON") {
        return Err("dispatch must log gpio437 leftover-handoff refuse");
    }
    Ok(())
}

pub fn refuse_s19k_s21_pwr_en_polarity_as_am3_s19k() -> Result<(), &'static str> {
    Err("S21 NoPic 1=ON / SafeOff=0 is not am3-s19k; software SoT is 0=ON 1=OFF")
}
pub const S19K_AML_CHAIN_RESET_GPIOS: [u32; 3] = [454, 455, 456];
pub const S19K_AML_CHAIN_PLUG_GPIOS: [u32; 3] = [439, 440, 441];
pub const S19K_AML_FAN_TACH_GPIOS: [u32; 4] = [447, 448, 449, 450];
pub const S19K_AML_LED_GREEN_GPIO: u32 = 453;
pub const S19K_AML_LED_RED_GPIO: u32 = 438;

/// Native experimental cold-init reset ownership must use the
/// production-firmware chain-reset numbers, not guessed sysfs lines.
pub fn admit_s19k_aml_chain_reset_gpios(gpios: [u32; 3]) -> Result<(), &'static str> {
    if gpios != S19K_AML_CHAIN_RESET_GPIOS {
        return Err("S19k AML chain reset GPIOs must be 454/455/456 (VNish v1.3.3 S11board)");
    }
    Ok(())
}

/// The plug-detect inputs must match the BM1368-fabric topology pins.
pub fn admit_s19k_aml_chain_plug_gpios(gpios: [u32; 3]) -> Result<(), &'static str> {
    if gpios != S19K_AML_CHAIN_PLUG_GPIOS {
        return Err("S19k AML chain plug GPIOs must be 439/440/441 (VNish v1.3.3 S11board)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bosminer_bm1366_stock_baud_static_chain_is_fail_closed() {
        let mut fixture = vec![0u8; BOSMINER_BM1366_FACTORY_PTR_FILE_OFF as usize + 8];
        let put_u16 = |buf: &mut [u8], off: u64, value: u16| {
            buf[off as usize..off as usize + 2].copy_from_slice(&value.to_le_bytes());
        };
        let put_u64 = |buf: &mut [u8], off: u64, value: u64| {
            buf[off as usize..off as usize + 8].copy_from_slice(&value.to_le_bytes());
        };
        let put_insn = |buf: &mut [u8], va: u64, value: u32| {
            let off = (va - 0x0040_0000) as usize;
            buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
        };
        put_u64(
            &mut fixture,
            BOSMINER_BM1366_FACTORY_PTR_FILE_OFF,
            BOSMINER_BM1366_FACTORY_FN_VA,
        );
        put_u64(
            &mut fixture,
            BOSMINER_BM1366_TRAIT_VTABLE_FILE_OFF + BOSMINER_BM1366_SET_BAUD_VTABLE_SLOT,
            BOSMINER_BM1366_SET_BAUD_BUILD_FN_VA,
        );
        put_u64(&mut fixture, BOSMINER_FASTUART_REG_DESCRIPTOR_FILE_OFF, 4);
        put_u64(
            &mut fixture,
            BOSMINER_FASTUART_REG_DESCRIPTOR_FILE_OFF + 8,
            u64::from(BOSMINER_BM1366_FASTUART_REG),
        );
        for (index, value) in [
            BOSMINER_SET_BAUD_RATE_STR_VA,
            6,
            BOSMINER_SET_BAUD_RATE_REQUESTED_STR_VA,
            29,
            BOSMINER_SET_BAUD_RATE_ACTUAL_STR_VA,
            10,
        ]
        .into_iter()
        .enumerate()
        {
            put_u64(
                &mut fixture,
                BOSMINER_SET_BAUD_RATE_LOG_DESCRIPTOR_FILE_OFF + index as u64 * 8,
                value,
            );
        }
        let string_off = (BOSMINER_SET_BAUD_RATE_STR_VA - 0x0040_0000) as usize;
        let string = b"CHAIN/: Set baud rate @ requested: , actual: ";
        fixture[string_off..string_off + string.len()].copy_from_slice(string);
        for (va, value) in [
            (0x008D_D3D8, 0x9400_F713),
            (0x008D_D414, 0x5280_004A),
            (0x008D_D418, 0x3900_53EA),
            (0x008D_D468, 0x97FD_C649),
            (0x0091_B034, 0xF109_013F),
            (0x0091_B03C, 0x5295_E109),
            (0x0091_B040, 0x72A0_05E9),
            (0x0083_76FC, 0xF940_2929),
            (0x0083_7704, 0xD63F_0120),
            (0x0083_7BC8, 0xF940_1928),
        ] {
            put_insn(&mut fixture, va, value);
        }
        assert!(admit_bosminer_bm1366_stock_baud_static(&fixture).is_ok());

        for (index, offset) in BOSMINER_BM1366_STOCK_INIT_JUMP_OFFSETS
            .into_iter()
            .enumerate()
        {
            put_u16(
                &mut fixture,
                BOSMINER_BM1366_STOCK_INIT_JUMP_TABLE_FILE_OFF + index as u64 * 2,
                offset,
            );
        }
        for stage in BOSMINER_BM1366_STOCK_INIT_DISPATCH {
            put_u64(
                &mut fixture,
                BOSMINER_BM1366_TRAIT_VTABLE_FILE_OFF + u64::from(stage.vtable_slot),
                stage.method_va,
            );
        }
        for (va, value) in [
            (0x0083_6E94, 0xF940_2128),
            (0x0083_6E98, 0xD63F_0100),
            (0x0083_7668, 0xF940_1D28),
            (0x0083_766C, 0xD63F_0100),
            (0x0083_76FC, 0xF940_2929),
            (0x0083_7704, 0xD63F_0120),
            (0x0083_7BC8, 0xF940_1928),
            (0x0083_7BCC, 0xD63F_0100),
            (0x0083_7DD8, 0xF940_3D28),
            (0x0083_7DDC, 0xD63F_0100),
            (0x0083_862C, 0xF940_2528),
            (0x0083_8630, 0xD63F_0100),
            (0x0083_89F8, 0xF940_1528),
            (0x0083_89FC, 0xD63F_0100),
            (0x0083_76DC, 0xF100_231F),
            (0x0083_76E0, 0x5400_0381),
            (0x0083_86A8, 0xF100_237F),
            (0x0083_86AC, 0x5400_1941),
            (0x0083_89E4, 0xF100_237F),
            (0x0083_89E8, 0x5400_0101),
            (0x0083_6EA0, 0x1400_0051),
            (0x0083_70B8, 0xF100_237F),
            (0x0083_749C, 0x9403_A51D),
            (0x0083_74D4, 0x5280_0069),
            (0x0083_8C0C, 0x1100_0508),
            (0x0083_8C5C, 0x72A2_3C29),
            (0x0083_8CA0, 0x6B09_011F),
            (0x0083_8CA4, 0x54FF_FB4B),
            (0x0083_8524, 0x940E_EB29),
            (0x0083_8544, 0x9403_A0E5),
            (0x0083_85CC, 0xEB08_005F),
            (0x0083_85D0, 0x5400_01E2),
            (0x0083_86B4, 0x529E_1009),
            (0x0083_86B8, 0x72A0_5F49),
            (0x0083_87C4, 0x3DC3_9140),
            (0x0083_8918, 0x529E_1009),
            (0x0083_8920, 0x72A0_5F49),
            (0x0083_8A04, 0x17FF_F957),
            (0x0083_7138, 0xF100_237F),
            (0x0083_72F4, 0x3DC3_2D60),
            (0x0083_99A4, 0x17FF_F541),
            (0x0083_71EC, 0xB500_D759),
            (0x0083_71FC, 0x3600_21E0),
            (0x0083_7718, 0xEB09_015F),
            (0x0083_7894, 0x97FF_FBD3),
            (0x0083_7DA0, 0xB400_0179),
            (0x0083_7600, 0xF100_231F),
            (0x0083_7608, 0xAA1F_03F9),
            (0x0083_760C, 0x1400_01E7),
            (0x0083_7DB8, 0x3607_EFA8),
            (0x0083_7BD4, 0x17FF_FD20),
            (0x0083_71B0, 0xF100_237F),
            (0x0092_08D8, 0x3600_00E1),
            (0x0092_0910, 0x3940_2C08),
        ] {
            put_insn(&mut fixture, va, value);
        }
        put_u64(
            &mut fixture,
            BOSMINER_BM1366_GENERIC_READ_REGISTER_ZERO_DESCRIPTOR_VA - 0x0040_0000,
            0,
        );
        put_u64(
            &mut fixture,
            BOSMINER_BM1366_GENERIC_READ_REGISTER_ZERO_DESCRIPTOR_VA - 0x0040_0000 + 8,
            4,
        );
        for (file_off, line, column, poll_va) in [
            (0x015B_7EB0, 93u32, 64u32, 0x008D_CFBC),
            (0x015B_7EE8, 127, 66, 0x008D_D4C8),
            (0x015B_7F20, 166, 72, 0x008D_D63C),
        ] {
            put_u64(&mut fixture, file_off, BOSMINER_BM1366_RS_LOC_STR_VA);
            put_u64(
                &mut fixture,
                file_off + 8,
                u64::from(BOSMINER_BM1366_RS_LOC_STR_LEN),
            );
            put_u64(
                &mut fixture,
                file_off + 16,
                u64::from(line) | (u64::from(column) << 32),
            );
            put_u64(&mut fixture, file_off + 48, poll_va);
        }
        for (file_off, register) in [
            (0x00EE_7E40, 0x3Cu64),
            (0x00EE_7E60, 0xA8),
            (0x00EE_7E80, 0x10),
            (0x00EE_7E90, 0xA4),
            (0x00EE_7EA0, 0x58),
            (0x00EE_7EB0, 0x2C),
            (0x00EE_7F20, 0x54),
            (0x00EE_7F50, 0x0C),
            (0x00EE_7FE0, 0x18),
            (0x00EE_8010, 0x28),
        ] {
            put_u64(&mut fixture, file_off, 4);
            put_u64(&mut fixture, file_off + 8, register);
        }
        for (head_va, words) in [
            (
                0x008D_FA14,
                [
                    0xF81F_0FFE,
                    0x3940_2009,
                    0x3500_00E9,
                    0x5280_0109,
                    0x5280_002A,
                    0xF900_0109,
                    0x3900_200A,
                    0xF841_07FE,
                    0xD65F_03C0,
                ],
            ),
            (
                0x008D_FD00,
                [
                    0xF81F_0FFE,
                    0x3940_4009,
                    0x3500_00E9,
                    0x5280_0109,
                    0x5280_002A,
                    0xF900_0109,
                    0x3900_400A,
                    0xF841_07FE,
                    0xD65F_03C0,
                ],
            ),
        ] {
            for (index, word) in words.into_iter().enumerate() {
                put_insn(&mut fixture, head_va + index as u64 * 4, word);
            }
        }
        for (index, value) in BOSMINER_BM1366_STOCK_FINALIZE_POLL_VTABLE
            .into_iter()
            .enumerate()
        {
            put_u64(
                &mut fixture,
                BOSMINER_BM1366_STOCK_FINALIZE_POLL_VTABLE_FILE_OFF + index as u64 * 8,
                value,
            );
        }
        for (va, value) in [
            (0x008D_D980, 0xF940_A508),
            (0x008D_D988, 0x529F_FFE9),
            (0x008D_D990, 0x9AC8_0928),
            (0x008D_DEA0, 0x1B08_7D2B),
            (0x008D_DF14, 0x5AC0_070A),
            (0x008D_DF24, 0x2A0A_4129),
            (0x008D_DFA0, 0x940C_548A),
            (0x008D_DB70, 0x9400_F5A9),
            (0x008D_DB9C, 0x97FF_DEC2),
            (0x008D_DC7C, 0x12BF_DFC9),
            (0x008D_DCA4, 0x97FF_DF39),
            (0x008D_CB1C, 0x3949_0422),
            (0x008D_CB2C, 0x9400_F96B),
            (0x0091_B0F4, 0xF940_A835),
            (0x0091_B100, 0xF940_A428),
            (0x0091_B14C, 0x9AD5_0916),
            (0x0091_B178, 0x9B15_52C9),
            (0x0091_B19C, 0x381F_D11C),
            (0x008D_CD74, 0x9400_F7ED),
            (0x0091_AD30, 0xF940_A809),
            (0x0091_AD38, 0xF940_A40B),
            (0x0092_3B70, 0xA954_DD16),
            (0x0092_3B80, 0xCB17_02AA),
            (0x0092_3B94, 0x4B0A_02CB),
            (0x0092_3B9C, 0x1100_396A),
            (0x008D_FF54, 0x97FF_D812),
            (0x008D_6004, 0x3940_0AC8),
            (0x008D_601C, 0x5AC0_094A),
            (0x008D_6030, 0x2A08_0168),
            (0x008D_6050, 0x2A08_6148),
            (0x00BF_31CC, 0xF940_0008),
            (0x00BF_31D0, 0x9B02_7D08),
            (0x00BF_31E0, 0x2A08_03E1),
        ] {
            put_insn(&mut fixture, va, value);
        }
        assert!(admit_bosminer_bm1366_stock_init_order_static(&fixture).is_ok());
        assert_eq!(
            BOSMINER_BM1366_STOCK_INIT_DISPATCH.map(|stage| stage.vtable_slot),
            BOSMINER_BM1366_STOCK_INIT_EXECUTION_SLOT_ORDER
        );
        assert_eq!(
            BOSMINER_BM1366_STOCK_INIT_CALLSITE_SLOT_ORDER,
            [0x40, 0x38, 0x50, 0x30, 0x78, 0x48, 0x28]
        );
        assert_eq!(
            BOSMINER_BM1366_STOCK_INIT_EXECUTION_SLOT_ORDER,
            [0x40, 0x48, 0x28, 0x38, 0x50, 0x78, 0x30]
        );
        assert_eq!(
            BOSMINER_BM1366_STOCK_REGISTER_FACTS.per_chip_core_register_values,
            [0x8000_8540, 0x8000_8020, 0x8000_82AA]
        );
        let reg0c = bosminer_bm1366_stock_reg0c_plan(2, 77).unwrap();
        assert_eq!(reg0c.len(), 77);
        assert_eq!(reg0c[0].value, 0x8000_0000);
        assert_eq!(reg0c[1].value, 0x8000_0353);
        assert_eq!(reg0c[76].wire_address, 152);
        assert_eq!(reg0c[76].value, 0x8000_FCA4);

        let set_addresses = bosminer_bm1366_stock_set_address_plan(2, 77).unwrap();
        assert_eq!(set_addresses.len(), 77);
        assert_eq!(set_addresses[0].wire_address, 0);
        assert_eq!(set_addresses[1].wire_address, 2);
        assert_eq!(set_addresses[76].wire_address, 152);
        assert!(bosminer_bm1366_stock_set_address_plan(4, 77).is_err());
        assert_eq!(
            bosminer_bm1366_stock_generic_core3c_value([1, 1, 1, 1, 0, 0x40, 0x85, 0x80]),
            0x8000_8540
        );

        let finalize = bosminer_bm1366_stock_finalize_plan(2, 77, 7, 1, 0xF).unwrap();
        assert_eq!(finalize.analog_mux_broadcast_value, 3);
        assert_eq!(finalize.io_driver_broadcast_value, 0x0211_1111);
        assert_eq!(finalize.io_driver_domains.len(), 11);
        assert_eq!(finalize.io_driver_domains[0].voltage_domain, 10);
        assert_eq!(finalize.io_driver_domains[0].chip_index, 76);
        assert_eq!(finalize.io_driver_domains[0].wire_address, 152);
        assert_eq!(finalize.io_driver_domains[0].value, 0x0211_F111);
        assert_eq!(finalize.io_driver_domains[10].chip_index, 6);
        assert_eq!(finalize.io_driver_domains[10].wire_address, 12);
        assert_eq!(finalize.uart_relay_domains.len(), 11);
        assert_eq!(finalize.uart_relay_domains[0].voltage_domain, 10);
        assert_eq!(finalize.uart_relay_domains[0].first_chip_index, 70);
        assert_eq!(finalize.uart_relay_domains[0].first_wire_address, 140);
        assert_eq!(finalize.uart_relay_domains[0].second_chip_index, 76);
        assert_eq!(finalize.uart_relay_domains[0].second_wire_address, 152);
        assert_eq!(finalize.uart_relay_domains[0].gap_count, 21);
        assert_eq!(finalize.uart_relay_domains[0].value, 0x0015_0003);
        assert_eq!(finalize.uart_relay_domains[10].voltage_domain, 0);
        assert_eq!(finalize.uart_relay_domains[10].first_wire_address, 0);
        assert_eq!(finalize.uart_relay_domains[10].second_wire_address, 12);
        assert_eq!(finalize.uart_relay_domains[10].gap_count, 91);
        assert_eq!(finalize.uart_relay_domains[10].value, 0x005B_0003);
        assert!(bosminer_bm1366_stock_finalize_plan(2, 77, 10, 1, 0xF).is_err());
        assert!(refuse_bosminer_bm1366_stock_init_manifest_as_executable().is_err());
        fixture[(0x0083_86AC - 0x0040_0000) as usize] ^= 1;
        assert!(admit_bosminer_bm1366_stock_init_order_static(&fixture).is_err());
        fixture[(0x0083_86AC - 0x0040_0000) as usize] ^= 1;
        fixture[(0x008D_D414 - 0x0040_0000) as usize] ^= 1;
        assert!(admit_bosminer_bm1366_stock_baud_static(&fixture).is_err());
    }

    #[test]
    fn bosminer_hashchain_lifecycle_is_bounded_and_not_safeoff_authority() {
        let mut fixture = vec![0u8; BOSMINER_HASHCHAIN_INIT_LOG_DESCRIPTOR_FILE_OFF as usize + 56];
        let put_u64 = |buf: &mut [u8], off: u64, value: u64| {
            buf[off as usize..off as usize + 8].copy_from_slice(&value.to_le_bytes());
        };
        let put_insn = |buf: &mut [u8], va: u64, value: u32| {
            let off = (va - 0x0040_0000) as usize;
            buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
        };
        for (file_off, message_va, message_len, source_va, source_len, line, column) in [
            (
                BOSMINER_HASHCHAIN_RESET_LOG_DESCRIPTOR_FILE_OFF,
                BOSMINER_HASHCHAIN_RESET_LOG_MESSAGE_VA,
                BOSMINER_HASHCHAIN_RESET_LOG_MESSAGE.len() as u64,
                BOSMINER_HASHCHAIN_SOURCE_VA,
                BOSMINER_HASHCHAIN_SOURCE.len() as u64,
                512u32,
                14u32,
            ),
            (
                BOSMINER_HASHCHAIN_INIT_LOG_DESCRIPTOR_FILE_OFF,
                BOSMINER_HASHCHAIN_INIT_LOG_MESSAGE_VA,
                BOSMINER_HASHCHAIN_INIT_LOG_MESSAGE.len() as u64,
                BOSMINER_HASHCHAIN_SOURCE_VA,
                BOSMINER_HASHCHAIN_SOURCE.len() as u64,
                777u32,
                9u32,
            ),
            (
                BOSMINER_HASHCHAIN_FAN_WAIT_LOG_DESCRIPTOR_FILE_OFF,
                BOSMINER_HASHCHAIN_FAN_WAIT_LOG_MESSAGE_VA,
                BOSMINER_HASHCHAIN_FAN_WAIT_LOG_MESSAGE.len() as u64,
                BOSMINER_HASHCHAIN_SOURCE_VA,
                BOSMINER_HASHCHAIN_SOURCE.len() as u64,
                453u32,
                17u32,
            ),
            (
                BOSMINER_HASHCHAIN_FANS_OK_LOG_DESCRIPTOR_FILE_OFF,
                BOSMINER_HASHCHAIN_FANS_OK_LOG_MESSAGE_VA,
                BOSMINER_HASHCHAIN_FANS_OK_LOG_MESSAGE.len() as u64,
                BOSMINER_HASHCHAIN_SOURCE_VA,
                BOSMINER_HASHCHAIN_SOURCE.len() as u64,
                466u32,
                32u32,
            ),
            (
                BOSMINER_HASHCHAIN_RETRY_LOG_DESCRIPTOR_FILE_OFF,
                BOSMINER_HASHCHAIN_RETRY_LOG_MESSAGE_VA,
                BOSMINER_HASHCHAIN_RETRY_LOG_MESSAGE.len() as u64,
                BOSMINER_MINER_SOURCE_VA,
                BOSMINER_MINER_SOURCE.len() as u64,
                319u32,
                21u32,
            ),
            (
                BOSMINER_HASHCHAIN_START_FAILED_LOG_DESCRIPTOR_FILE_OFF,
                BOSMINER_HASHCHAIN_START_FAILED_LOG_MESSAGE_VA,
                BOSMINER_HASHCHAIN_START_FAILED_LOG_MESSAGE.len() as u64,
                BOSMINER_MINER_SOURCE_VA,
                BOSMINER_MINER_SOURCE.len() as u64,
                327u32,
                21u32,
            ),
        ] {
            for (index, value) in [
                BOSMINER_HASHCHAIN_LOG_PREFIX_VA,
                6,
                message_va,
                message_len,
                source_va,
                source_len,
                u64::from(line) | (u64::from(column) << 32),
            ]
            .into_iter()
            .enumerate()
            {
                put_u64(&mut fixture, file_off + index as u64 * 8, value);
            }
        }
        for (va, value) in [
            (BOSMINER_HASHCHAIN_LOG_PREFIX_VA, b"CHAIN/".as_slice()),
            (
                BOSMINER_HASHCHAIN_RESET_LOG_MESSAGE_VA,
                BOSMINER_HASHCHAIN_RESET_LOG_MESSAGE,
            ),
            (
                BOSMINER_HASHCHAIN_INIT_LOG_MESSAGE_VA,
                BOSMINER_HASHCHAIN_INIT_LOG_MESSAGE,
            ),
            (
                BOSMINER_HASHCHAIN_FAN_WAIT_LOG_MESSAGE_VA,
                BOSMINER_HASHCHAIN_FAN_WAIT_LOG_MESSAGE,
            ),
            (
                BOSMINER_HASHCHAIN_FANS_OK_LOG_MESSAGE_VA,
                BOSMINER_HASHCHAIN_FANS_OK_LOG_MESSAGE,
            ),
            (
                BOSMINER_HASHCHAIN_RETRY_LOG_MESSAGE_VA,
                BOSMINER_HASHCHAIN_RETRY_LOG_MESSAGE,
            ),
            (
                BOSMINER_HASHCHAIN_START_FAILED_LOG_MESSAGE_VA,
                BOSMINER_HASHCHAIN_START_FAILED_LOG_MESSAGE,
            ),
            (BOSMINER_HASHCHAIN_SOURCE_VA, BOSMINER_HASHCHAIN_SOURCE),
            (BOSMINER_MINER_SOURCE_VA, BOSMINER_MINER_SOURCE),
        ] {
            let off = (va - 0x0040_0000) as usize;
            fixture[off..off + value.len()].copy_from_slice(value);
        }
        for (va, value) in [
            (0x0071_7988, 0x5280_0088),
            (0x0071_798C, 0xF900_2E68),
            (0x0071_79F0, 0x9400_079E),
            (0x0071_7D28, 0xF940_2E68),
            (0x0071_7D2C, 0xF100_0508),
            (0x0071_7D30, 0xF900_2E68),
            (0x0071_7D34, 0x5400_1960),
            (0x0071_7D44, 0x5280_0140),
            (0x0071_7D48, 0x2A1F_03E1),
            (0x0071_7D4C, 0x942B_AFBF),
            (0x0071_7D80, 0x9101_C260),
            (0x0071_7D84, 0xAA14_03E1),
            (0x0071_7D88, 0x942B_B1EB),
            (0x0071_8030, 0x17FF_FE6D),
            (0x0071_8060, 0xF940_2A68),
            (0x0071_8064, 0x3CCE_8260),
            (0x0071_8068, 0xF940_7E69),
            (0x0071_806C, 0xF940_7277),
            (0x0071_808C, 0x9412_94E1),
            (0x0071_80B0, 0x9410_A555),
            (0x0071_8100, 0x9400_3DF7),
            (0x0071_8160, 0x942D_62C6),
            (0x0071_8170, 0xA900_5E68),
            (0x0071_8178, 0x3C81_0260),
            (0x0071_817C, 0xA902_5A68),
            (0x0071_819C, 0xD65F_03C0),
            (0x0071_B088, 0xF940_02E8),
            (0x0071_B08C, 0xF941_0D09),
            (0x0071_B090, 0xF941_0900),
            (0x0071_B094, 0xF940_1528),
            (0x0071_B098, 0xD63F_0100),
            (0x0071_B70C, 0x394E_4668),
            (0x0071_B720, 0x5280_00A0),
            (0x0071_B724, 0x2A1F_03E1),
            (0x0071_B728, 0x942B_A148),
            (BOSMINER_HASHCHAIN_FAN_READY_SNAPSHOT_FN_VA, 0xFC16_0FEE),
            (
                BOSMINER_HASHCHAIN_FAN_READY_SNAPSHOT_STATUS_BYTE_LOAD_VA,
                0x3945_B276,
            ),
            (BOSMINER_HASHCHAIN_FAN_READY_INITIAL_CALL_VA, 0x9410_FF0A),
            (0x0071_BF88, 0x3700_A520),
            (0x0071_BF90, 0x1400_03C0),
            (0x0071_CE90, 0xF941_F260),
            (BOSMINER_HASHCHAIN_FAN_READY_RECHECK_CALL_VA, 0x9410_FB46),
            (0x0071_CE98, 0x3700_1840),
            (0x0071_CF2C, 0x9000_94A8),
            (0x0071_CF30, 0x9102_C108),
            (0x0071_D0A8, 0xF000_9489),
            (0x0071_D0AC, 0x9102_C129),
            (0x0071_D11C, 0xF941_F668),
            (0x0071_D120, 0x9100_0508),
            (0x0071_D124, 0xF901_F668),
            (0x0071_D128, 0xF000_9482),
            (0x0071_D12C, 0x9103_4042),
            (0x0071_D134, 0x5280_0020),
            (0x0071_D138, 0x2A1F_03E1),
            (0x0071_D13C, 0x942B_9AC3),
            (0x0071_D184, 0x910F_C260),
            (0x0071_D188, 0xAA1A_03E1),
            (0x0071_D18C, 0x942B_9CEA),
            (BOSMINER_HASHCHAIN_FAN_PENDING_LOOP_BACKEDGE_VA, 0x17FF_FF3D),
            (0x0071_D210, 0xF000_9488),
            (0x0071_D214, 0x9104_0108),
            (0x0071_D224, 0xA911_2BE8),
            (0x0071_D3A8, 0xF000_9489),
            (0x0071_D3AC, 0x9104_0129),
            (0x0071_D3C4, 0xA911_2BE9),
            (0x0071_D89C, 0xF941_DE68),
            (0x0071_D8A0, 0x394F_4261),
            (0x0071_D8A4, 0xF941_1509),
            (0x0071_D8A8, 0xF941_1100),
            (0x0071_D8AC, 0xF940_0D28),
            (0x0071_D8B0, 0xD63F_0100),
            (0x0071_D8B4, 0xAA00_03E2),
            (0x0071_D8B8, 0xAA01_03E3),
            (0x0071_D8C8, 0x5280_0140),
            (0x0071_D8CC, 0x2A1F_03E1),
            (0x0071_D8D4, 0x97FE_198D),
            (BOSMINER_HASHCHAIN_START_WRAPPER_FN_VA, 0xA9BA_7BFD),
            (BOSMINER_HASHCHAIN_START_POLL_FN_VA, 0xFC19_0FE8),
            (BOSMINER_HASHCHAIN_TIMEOUT_WRAPPER_FN_VA, 0xD102_C3FF),
            (0x0071_D8C0, 0x912D_4084),
            (0x0071_D8D0, 0xF940_73F7),
        ] {
            put_insn(&mut fixture, va, value);
        }

        assert!(admit_bosminer_hashchain_lifecycle_static(&fixture).is_ok());
        assert_eq!(BOSMINER_HASHCHAIN_START_RETRY_BUDGET, 4);
        assert_eq!(
            bosminer_hashchain_start_attempt_delays_ns(),
            [0, 10_000_000_000, 10_000_000_000, 10_000_000_000]
        );
        assert_eq!(
            BOSMINER_S19K_DEPARTURE_LIFECYCLE_CAPTURE.power_enable_to_reset,
            BosminerS19kLifecycleTimingEnvelope {
                samples: 16,
                min_us: 2_060_449,
                max_us: 2_071_063,
            }
        );
        assert_eq!(
            BOSMINER_S19K_DEPARTURE_LIFECYCLE_CAPTURE.reset_to_init,
            BosminerS19kLifecycleTimingEnvelope {
                samples: 17,
                min_us: 2_001_614,
                max_us: 2_003_610,
            }
        );
        assert_eq!(BOSMINER_HASHCHAIN_INIT_ERROR_EVIDENCE[4].code, "{ERR:I8}");
        assert_eq!(
            BOSMINER_HASHCHAIN_START_FAILURE_POLICY,
            [
                BosminerHashchainStartFailureDisposition::RetryAfterTenSecondsThenNewInnerReset,
                BosminerHashchainStartFailureDisposition::TerminalReturnRetainedErrorNoLocalHardwareRollback,
            ]
        );
        assert_eq!(BOSMINER_HASHCHAIN_TERMINAL_FAILURE_CALLS.len(), 4);
        assert_eq!(
            BOSMINER_HASHCHAIN_PLATFORM_ORDER,
            [
                BosminerHashchainPlatformStage::ResetDispatch,
                BosminerHashchainPlatformStage::FanReadinessGateOneSecondPendingCadence,
                BosminerHashchainPlatformStage::InitDispatchWithTenSecondTimeout,
            ]
        );
        assert!(refuse_bosminer_post_baud_path_as_fresh_validation().is_err());
        assert!(refuse_bosminer_stock_lifecycle_as_safeoff_proof().is_err());
        assert!(refuse_bosminer_s19k_fan_gate_as_positive_cooling_proof().is_err());
        assert!(refuse_bosminer_telemetry_cadence_as_retry_delay().is_err());
        fixture[(0x0071_D8C8 - 0x0040_0000) as usize] ^= 1;
        assert!(admit_bosminer_hashchain_lifecycle_static(&fixture).is_err());
        fixture[(0x0071_D8C8 - 0x0040_0000) as usize] ^= 1;
        put_insn(&mut fixture, 0x0071_8070, 0xD63F_0100);
        assert!(admit_bosminer_hashchain_lifecycle_static(&fixture).is_err());
    }

    #[test]
    fn bosminer_s19k_platform_registry_enumerates_code3_candidates_and_antminer_model() {
        let mut fixture = vec![0u8; BOSMINER_BUILDER_REGISTRY_INIT_PTR_FILE_OFF as usize + 8];
        let put_qword = |bytes: &mut [u8], off: u64, value: u64| {
            bytes[off as usize..off as usize + 8].copy_from_slice(&value.to_le_bytes());
        };
        for (index, name) in BOSMINER_PLATFORM_NAMES.into_iter().enumerate() {
            let row = BOSMINER_PLATFORM_NAME_TABLE_FILE_OFF + index as u64 * 16;
            put_qword(&mut fixture, row, BOSMINER_PLATFORM_NAME_VAS[index]);
            put_qword(&mut fixture, row + 8, name.len() as u64);
            let name_off = (BOSMINER_PLATFORM_NAME_VAS[index] - 0x0040_0000) as usize;
            fixture[name_off..name_off + name.len()].copy_from_slice(name);
        }
        for (va, value) in BOSMINER_S19K_PLATFORM_RESOLUTION_PINS {
            let off = (va - 0x0040_0000) as usize;
            fixture[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }
        let model_off = (BOSMINER_S19K_NOPIC_MODEL_NAME_VA - 0x0040_0000) as usize;
        fixture[model_off..model_off + BOSMINER_S19K_NOPIC_MODEL_NAME.len()]
            .copy_from_slice(BOSMINER_S19K_NOPIC_MODEL_NAME);
        let fixture_builder_off = model_off + BOSMINER_S19K_NOPIC_MODEL_NAME.len() + 1;
        fixture[fixture_builder_off
            ..fixture_builder_off + BOSMINER_AM3_AML_FILTERED_BUILDERS[1].len()]
            .copy_from_slice(BOSMINER_AM3_AML_FILTERED_BUILDERS[1]);
        let board_off = (BOSMINER_S19K_NOPIC_BOARD_ID_VA - 0x0040_0000) as usize;
        fixture[board_off..board_off + BOSMINER_S19K_NOPIC_BOARD_ID.len()]
            .copy_from_slice(BOSMINER_S19K_NOPIC_BOARD_ID);
        put_qword(
            &mut fixture,
            BOSMINER_PLATFORM_REGISTRY_INIT_PTR_FILE_OFF,
            BOSMINER_PLATFORM_REGISTRY_INIT_FN_VA,
        );
        put_qword(
            &mut fixture,
            BOSMINER_AM3_AML_FACTORY_RECORD_FILE_OFF,
            BOSMINER_AM3_AML_FACTORY_FN_VA,
        );
        put_qword(
            &mut fixture,
            BOSMINER_BUILDER_REGISTRY_LAZY_PTR_FILE_OFF,
            BOSMINER_BUILDER_REGISTRY_STORAGE_VA,
        );
        put_qword(
            &mut fixture,
            BOSMINER_BUILDER_REGISTRY_INIT_PTR_FILE_OFF,
            BOSMINER_BUILDER_REGISTRY_INIT_FN_VA,
        );
        for (off, value) in [
            (
                BOSMINER_ANTMINER_BUILDER_VTABLE_FILE_OFF + 0x30,
                BOSMINER_ANTMINER_PROVIDER_BUILD_FN_VA,
            ),
            (
                BOSMINER_BRAIINS_FIXTURE_BUILDER_VTABLE_FILE_OFF + 0x30,
                BOSMINER_BRAIINS_FIXTURE_PROVIDER_BUILD_FN_VA,
            ),
            (
                BOSMINER_THIRD_BUILDER_VTABLE_FILE_OFF + 0x30,
                BOSMINER_THIRD_PROVIDER_BUILD_FN_VA,
            ),
            (
                BOSMINER_ANTMINER_AM3_AML_CANDIDATE_TABLE_FILE_OFF
                    + u64::from(BOSMINER_S19K_NOPIC_CANDIDATE_INDEX) * 8,
                BOSMINER_S19K_NOPIC_CANDIDATE_OBJECT_VA,
            ),
            (
                BOSMINER_S19K_NOPIC_CANDIDATE_INIT_PTR_FILE_OFF,
                BOSMINER_S19K_NOPIC_CANDIDATE_INIT_FN_VA,
            ),
        ] {
            put_qword(&mut fixture, off, value);
        }
        for (vtable_off, vtable) in [
            (
                BOSMINER_ANTMINER_PROVIDER_VTABLE_FILE_OFF,
                BOSMINER_ANTMINER_PROVIDER_VTABLE,
            ),
            (
                BOSMINER_BRAIINS_FIXTURE_PROVIDER_VTABLE_FILE_OFF,
                BOSMINER_BRAIINS_FIXTURE_PROVIDER_VTABLE,
            ),
        ] {
            for (index, value) in vtable.into_iter().enumerate() {
                put_qword(&mut fixture, vtable_off + index as u64 * 8, value);
            }
        }

        assert!(admit_bosminer_s19k_platform_resolution_static(&fixture).is_ok());
        assert_eq!(BOSMINER_AM3_AML_PLATFORM_CODE, 3);
        assert_eq!(BOSMINER_S19K_NOPIC_CANDIDATE_INDEX, 8);

        fixture[(0x006B_B7F8 - 0x0040_0000) as usize] ^= 1;
        assert!(admit_bosminer_s19k_platform_resolution_static(&fixture).is_err());
    }

    #[test]
    fn bosminer_chain_descriptor_arc_payload_has_prestaged_dispatch_boundary() {
        let max_va = BOSMINER_CHAIN_DESCRIPTOR_ARC_LINEAGE_PINS
            .iter()
            .chain(BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_PINS.iter())
            .map(|(va, _)| *va)
            .max()
            .unwrap();
        let fixture_len = ((max_va - 0x0040_0000) as usize + 4)
            .max(
                (BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL_VA - 0x0040_0000) as usize
                    + BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL.len(),
            )
            .max(BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL_DESCRIPTOR_FILE_OFF as usize + 16)
            .max(BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_VTABLE_FILE_OFF as usize + 5 * 8);
        let mut fixture = vec![0u8; fixture_len];
        let put_qword = |bytes: &mut [u8], off: u64, value: u64| {
            bytes[off as usize..off as usize + 8].copy_from_slice(&value.to_le_bytes());
        };
        for (va, value) in BOSMINER_CHAIN_DESCRIPTOR_ARC_LINEAGE_PINS {
            let off = (va - 0x0040_0000) as usize;
            fixture[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (va, value) in BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_PINS {
            let off = (va - 0x0040_0000) as usize;
            fixture[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }
        let debug_label_off = (BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL_VA - 0x0040_0000) as usize;
        fixture[debug_label_off..debug_label_off + BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL.len()]
            .copy_from_slice(BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL);
        put_qword(
            &mut fixture,
            BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL_DESCRIPTOR_FILE_OFF,
            BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL_VA,
        );
        put_qword(
            &mut fixture,
            BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL_DESCRIPTOR_FILE_OFF + 8,
            BOSMINER_LIVE_CHAIN_PAYLOAD_DEBUG_LABEL.len() as u64,
        );
        for (index, value) in BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_VTABLE_PREFIX
            .into_iter()
            .enumerate()
        {
            put_qword(
                &mut fixture,
                BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_VTABLE_FILE_OFF + index as u64 * 8,
                value,
            );
        }

        assert!(admit_bosminer_chain_descriptor_arc_lineage_static(&fixture).is_ok());
        assert_eq!(BOSMINER_CHAIN_DESCRIPTOR_ARC_LINEAGE_PINS.len(), 117);
        assert_eq!(BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_PINS.len(), 20);
        assert_eq!(
            BOSMINER_CHAIN_DESCRIPTOR_ARC_EVIDENCE,
            BosminerChainDescriptorArcEvidence {
                tuner_object_bytes: 0x09A0,
                descriptor_bytes: 0x38,
                descriptor_arc_offset: 0x20,
                descriptor_arc_companion_offset: 0x28,
                source_owner_offset: 0x0950,
                source_arc_vec_data_offset: 0x06A8,
                source_arc_vec_len_offset: 0x06B0,
                source_arc_companion_offset: 0x0558,
                descriptor_build_fn_va: 0x007E_9C24,
                derived_vec_data_offset: 0x07D8,
                derived_vec_len_offset: 0x07E0,
                callback_offset: 0x0978,
                callback_fn_va: 0x0070_A168,
                callback_dispatch_va: 0x0066_2554,
                raw_record_arc_offset: 0x0510,
                concrete_arc_allocation_bytes: Some(0x0570),
                concrete_arc_payload_bytes: Some(0x0560),
                concrete_arc_payload_prefix_copy_bytes: Some(0x01F0),
                concrete_arc_payload_type_name: Some("HashchainManager"),
                concrete_arc_payload_type_vtable_va: Some(0x019F_B178),
                concrete_arc_payload_drop_fn_va: Some(0x00B7_5194),
                concrete_arc_payload_debug_fn_va: Some(0x00B5_D364),
                resolution_boundary: BosminerChainDescriptorArcResolutionBoundary::RawRecordOwnsLiveHashchainManagerDispatchPairIsPrestaged,
            }
        );
        assert!(refuse_bosminer_hashchain_lifecycle_receiver_as_concrete_gpio_authority().is_err());

        fixture[(0x007E_9ED4 - 0x0040_0000) as usize] ^= 1;
        assert!(admit_bosminer_chain_descriptor_arc_lineage_static(&fixture).is_err());
    }

    #[test]
    fn bosminer_lifecycle_receiver_stops_at_the_dynamic_prestaged_table_boundary() {
        let pin_max_va = BOSMINER_HASHCHAIN_LIFECYCLE_RECEIVER_LINEAGE_PINS
            .iter()
            .map(|(va, _)| *va)
            .max()
            .unwrap();
        let max_va = pin_max_va.max(
            BOSMINER_TRIGGERED_SOURCE_STRING_VA + BOSMINER_TRIGGERED_SOURCE_STRING.len() as u64,
        );
        let mut fixture = vec![0u8; (max_va - 0x0040_0000) as usize + 4];
        for (va, value) in BOSMINER_HASHCHAIN_LIFECYCLE_RECEIVER_LINEAGE_PINS {
            let off = (va - 0x0040_0000) as usize;
            fixture[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (va, value) in [
            (
                BOSMINER_TRIGGERED_PANIC_STRING_VA,
                BOSMINER_TRIGGERED_PANIC_STRING,
            ),
            (
                BOSMINER_TRIGGERED_SOURCE_STRING_VA,
                BOSMINER_TRIGGERED_SOURCE_STRING,
            ),
        ] {
            let off = (va - 0x0040_0000) as usize;
            fixture[off..off + value.len()].copy_from_slice(value);
        }

        assert!(admit_bosminer_hashchain_lifecycle_receiver_lineage_static(&fixture).is_ok());
        assert_eq!(BOSMINER_HASHCHAIN_LIFECYCLE_RECEIVER_LINEAGE_PINS.len(), 92);
        assert_eq!(
            BOSMINER_HASHCHAIN_LIFECYCLE_RECEIVER_EVIDENCE,
            BosminerHashchainLifecycleReceiverEvidence {
                raw_record_bytes: 0x0570,
                raw_record_arc_offset: 0x0510,
                arc_build_fn_va: 0x00B8_7980,
                arc_allocation_bytes: 0x0570,
                arc_align: 0x10,
                arc_header_bytes: 0x10,
                arc_payload_bytes: 0x0560,
                arc_payload_type_name: "HashchainManager",
                arc_payload_type_vtable_va: 0x019F_B178,
                enabled_allocation_offset: 0x0568,
                item_triggered_listener_offset: 0x30,
                item_payload_offset: 0x0060,
                listener_type_name: "triggered::Listener",
                listener_clone_fn_va: 0x00BB_D3DC,
                listener_next_id_offset: 0x48,
                outer_working_listener_offset: 0x0040,
                outer_retained_payload_offset: 0x0050,
                outer_nested_future_offset: 0x0070,
                outer_cloned_listener_offset: 0x03D0,
                outer_retained_payload_for_nested_offset: 0x03F8,
                state_listener_input_offset: 0x0360,
                state_payload_input_offset: 0x0388,
                state_retained_payload_offset: 0x0370,
                state_reused_listener_self_slot_offset: 0x03A0,
                state_dispatch_self_slot_offset: 0x03B8,
                stack_listener_inner_offset: 0x48,
                payload_hook_trait_data_offset: 0x0230,
                payload_hook_trait_vtable_offset: 0x0238,
                payload_hook_method_slot: 0x18,
                payload_hook_dispatch_va: 0x0071_A51C,
                payload_hook_method_vas: [0x0070_539C, 0x0070_57FC],
                payload_hook_is_noop: true,
                prestage_vec_source_offset: 0x10,
                prestage_vec_clone_fn_va: 0x012D_276C,
                prestage_vec_clone_dispatch_va: 0x0071_9B34,
                prestaged_data_offset: 0x0538,
                stack_prestaged_data_offset: 0x0B10,
                stack_prestaged_dispatch_table_offset: 0x0B18,
                stack_listener_inner_overwrite_va: 0x0071_A528,
                local_object_prefix_copy_bytes: 0x01E0,
                local_object_trait_data_offset: 0x0210,
                local_object_dispatch_table_offset: 0x0218,
                method_slot: 0x28,
                method_dispatch_va: 0x0071_B098,
                concrete_dispatch_data: None,
                concrete_dispatch_table_va: None,
                concrete_method_va: None,
                resolution_boundary: BosminerHashchainLifecycleReceiverResolutionBoundary::PayloadPrestageProviderCandidatesLineageResolvedRuntimeSelectionBytesAndFinalMethodRemainDynamic,
            }
        );
        assert!(refuse_bosminer_hashchain_lifecycle_receiver_as_concrete_gpio_authority().is_err());

        fixture[(0x0071_AE2C - 0x0040_0000) as usize] ^= 1;
        assert!(admit_bosminer_hashchain_lifecycle_receiver_lineage_static(&fixture).is_err());
    }

    #[test]
    fn bosminer_cloned_table_slot_0x48_follows_slot_0x28_on_the_same_pair() {
        let pin_max_va = BOSMINER_CLONED_TABLE_TWO_SLOT_SEQUENCE_PINS
            .iter()
            .map(|(va, _)| *va)
            .max()
            .unwrap();
        let mut fixture = vec![0u8; (pin_max_va - 0x0040_0000) as usize + 4];
        for (va, value) in BOSMINER_CLONED_TABLE_TWO_SLOT_SEQUENCE_PINS {
            let off = (va - 0x0040_0000) as usize;
            fixture[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }

        assert!(admit_bosminer_cloned_table_two_slot_sequence_static(&fixture).is_ok());
        let evidence = BOSMINER_CLONED_TABLE_TWO_SLOT_SEQUENCE_EVIDENCE;
        assert_eq!(evidence.local_data_offset, 0x0210);
        assert_eq!(evidence.local_table_offset, 0x0218);
        assert_eq!(evidence.first.slot, 0x28);
        assert_eq!(evidence.second.slot, 0x48);
        assert_eq!(evidence.first.fail_imm, 4);
        assert_eq!(evidence.second.fail_imm, 5);
        assert_eq!(evidence.first.blr_va, 0x0071_B098);
        assert_eq!(evidence.second.blr_va, 0x0071_B128);
        assert!(evidence.second.blr_va > evidence.first.blr_va);
        assert_eq!(evidence.concrete_method_va, None);
        assert_eq!(
            aarch64_ldr64_unsigned_imm(evidence.first.slot_load_word).map(|(_, _, imm)| imm),
            Some(u16::from(evidence.first.slot))
        );
        assert_eq!(
            aarch64_ldr64_unsigned_imm(evidence.second.slot_load_word).map(|(_, _, imm)| imm),
            Some(u16::from(evidence.second.slot))
        );
        assert!(refuse_bosminer_cloned_table_slot_0x28_as_terminal_dispatch().is_err());
        assert!(refuse_bosminer_cloned_table_slot_0x50_as_same_pair().is_err());
        assert!(refuse_bosminer_cloned_table_slot_0x20_as_cloned_p10_table().is_err());
        assert!(refuse_bosminer_hashchain_lifecycle_receiver_as_concrete_gpio_authority().is_err());
        let refuse_28 = refuse_bosminer_cloned_table_slot_0x28_as_terminal_dispatch().unwrap_err();
        assert!(refuse_28.contains("slot +0x48"));
        assert!(refuse_28.contains("not the terminal"));
        let refuse_50 = refuse_bosminer_cloned_table_slot_0x50_as_same_pair().unwrap_err();
        assert!(refuse_50.contains("+0x3c0"));
        let refuse_20 = refuse_bosminer_cloned_table_slot_0x20_as_cloned_p10_table().unwrap_err();
        assert!(refuse_20.contains("+0x220/+0x228"));

        fixture[(0x0071_B124 - 0x0040_0000) as usize] ^= 1;
        assert!(admit_bosminer_cloned_table_two_slot_sequence_static(&fixture).is_err());
        fixture[(0x0071_B124 - 0x0040_0000) as usize] ^= 1;
        fixture[(0x0071_B144 - 0x0040_0000) as usize] ^= 1;
        assert!(admit_bosminer_cloned_table_two_slot_sequence_static(&fixture).is_err());
    }

    #[test]
    fn s19k_native_post_baud_work_tx_fail_closes_without_fresh_switched_response() {
        let passthrough =
            classify_s19k_post_baud_observation(S19kInitDialect::BraiinsPassthrough, false, true)
                .expect("passthrough without baud change");
        assert_eq!(
            passthrough,
            S19kPostBaudObservation::HostBaudUnchangedPassthrough
        );
        assert!(classify_s19k_post_baud_observation(
            S19kInitDialect::BraiinsPassthrough,
            true,
            true
        )
        .is_err());
        assert_eq!(
            s19k_post_baud_work_tx_disposition(S19kInitDialect::BraiinsPassthrough, passthrough),
            S19kPostBaudWorkTxDisposition::PassthroughChipProofSeparate
        );
        assert!(admit_s19k_native_work_tx_after_post_baud(
            S19kInitDialect::BraiinsPassthrough,
            passthrough
        )
        .is_err());

        let native_fresh =
            classify_s19k_post_baud_observation(S19kInitDialect::NativeExperimental, true, true)
                .expect("native switched baud with fresh response");
        assert_eq!(
            native_fresh,
            S19kPostBaudObservation::FreshSwitchedBaudResponseAdmitted
        );
        assert_eq!(
            s19k_post_baud_work_tx_disposition(S19kInitDialect::NativeExperimental, native_fresh),
            S19kPostBaudWorkTxDisposition::NativeWorkTxAllowedAfterFreshResponse
        );
        assert!(admit_s19k_native_work_tx_after_post_baud(
            S19kInitDialect::NativeExperimental,
            native_fresh
        )
        .is_ok());
        assert!(refuse_native_as_production(S19kInitDialect::NativeExperimental).is_err());
        assert!(refuse_native_post_baud_pass_as_production(
            S19kInitDialect::NativeExperimental,
            native_fresh
        )
        .is_err());

        let native_silent =
            classify_s19k_post_baud_observation(S19kInitDialect::NativeExperimental, true, false)
                .expect("native switched baud without response");
        assert_eq!(
            native_silent,
            S19kPostBaudObservation::SwitchedBaudWithoutFreshResponse
        );
        let silent_disp =
            s19k_post_baud_work_tx_disposition(S19kInitDialect::NativeExperimental, native_silent);
        assert_eq!(
            silent_disp,
            S19kPostBaudWorkTxDisposition::FailClosedRollbackBeforeWorkTx
        );
        assert!(s19k_post_baud_failure_is_rollback_not_work_tx(silent_disp));
        let silent_err = admit_s19k_native_work_tx_after_post_baud(
            S19kInitDialect::NativeExperimental,
            native_silent,
        )
        .unwrap_err();
        assert!(silent_err.contains("fail-closed rollback"));
        assert!(silent_err.contains("21 36"));

        let native_unchanged =
            classify_s19k_post_baud_observation(S19kInitDialect::NativeExperimental, false, true)
                .expect("native without baud change");
        assert_eq!(
            native_unchanged,
            S19kPostBaudObservation::NativeHostBaudUnchangedIsNotPostSwitchProof
        );
        assert!(admit_s19k_native_work_tx_after_post_baud(
            S19kInitDialect::NativeExperimental,
            native_unchanged
        )
        .is_err());

        assert!(admit_s19k_native_init_program_lacks_post_baud_response_barrier().is_ok());
        assert!(refuse_s19k_native_init_program_as_work_tx_grant().is_err());
        assert!(refuse_stock_post_baud_omission_as_native_work_tx_grant().is_err());
        assert!(refuse_bosminer_post_baud_path_as_fresh_validation().is_err());

        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_native_transport_requires_joined_owner(serial).is_ok());
    }

    #[test]
    fn bosminer_payload_hook_producer_resolves_code3_candidates_and_stops_at_runtime_selection() {
        let max_va = BOSMINER_PAYLOAD_HOOK_PRODUCER_LINEAGE_PINS
            .iter()
            .chain(BOSMINER_PAYLOAD_HOOK_CODE3_CANDIDATE_PINS.iter())
            .chain(BOSMINER_PRESTAGE_VEC_BOUNDARY_PINS.iter())
            .map(|(va, _)| *va)
            .max()
            .unwrap();
        let mut fixture = vec![0u8; (max_va - 0x0040_0000) as usize + 4];
        for (va, value) in BOSMINER_PAYLOAD_HOOK_PRODUCER_LINEAGE_PINS {
            let off = (va - 0x0040_0000) as usize;
            fixture[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (va, value) in BOSMINER_PAYLOAD_HOOK_CODE3_CANDIDATE_PINS {
            let off = (va - 0x0040_0000) as usize;
            fixture[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (va, value) in BOSMINER_PRESTAGE_VEC_BOUNDARY_PINS {
            let off = (va - 0x0040_0000) as usize;
            fixture[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }

        assert!(admit_bosminer_payload_hook_producer_lineage_static(&fixture).is_ok());
        assert_eq!(BOSMINER_PAYLOAD_HOOK_PRODUCER_LINEAGE_PINS.len(), 167);
        assert_eq!(BOSMINER_PAYLOAD_HOOK_CODE3_CANDIDATE_PINS.len(), 114);
        assert_eq!(BOSMINER_PRESTAGE_VEC_BOUNDARY_PINS.len(), 200);
        let evidence = BOSMINER_PAYLOAD_HOOK_PRODUCER_EVIDENCE;
        assert_eq!(evidence.registry_select_fn_va, 0x0079_4C48);
        assert_eq!(evidence.registry_entry_method_slot, 0x30);
        assert_eq!(
            evidence.registry_select_call_vas,
            [0x0047_1804, 0x004C_1FC8, 0x004E_F814]
        );
        assert_eq!(evidence.selected_pair_offsets, [0x0450, 0x0458]);
        assert_eq!(evidence.wrapped_pair_offsets, [0x07C0, 0x07C8]);
        assert_eq!(evidence.parent_capture_offsets, [0x11F0, 0x11F8]);
        assert_eq!(evidence.child_capture_offsets, [0x04B0, 0x04B8]);
        assert_eq!(evidence.child_method_slot, 0x20);
        assert_eq!(
            evidence.child_dispatch_vas,
            [0x0047_AB50, 0x004C_B318, 0x004F_8B64]
        );
        assert_eq!(evidence.child_result_offsets, [0x0A00, 0x0A08]);
        assert_eq!(evidence.materialize_fn_va, 0x00B2_58B8);
        assert_eq!(evidence.materialize_final_arg_pair_offset, 0x30);
        assert_eq!(evidence.materialized_pair_offsets, [0x04C0, 0x04C8]);
        assert_eq!(evidence.prefix_copy_bytes, 0x0660);
        assert_eq!(evidence.refuted_runtime_object_state_offset, 0x2940);
        assert_eq!(evidence.refuted_runtime_object_tail_offsets, [0x50, 0x58]);
        assert_eq!(evidence.refuted_main_future_footer_bytes, 0x60);
        assert_eq!(evidence.refuted_footer_tail_offsets, [0x50, 0x58]);
        assert_eq!(evidence.refuted_rotated_tail_offset, 0x50);
        assert_eq!(evidence.b90c_entry_prefix_offset, 0x60);
        assert_eq!(evidence.b90c_entry_vec_offset, 0x70);
        assert_eq!(evidence.b90c_snapshot_prefix_offset, 0x0730);
        assert_eq!(evidence.b90c_owned_prefix_offset, 0x0E10);
        assert_eq!(evidence.b879_input_prefix_offset, 0x00);
        assert_eq!(evidence.b879_snapshot_prefix_offset, 0x06E0);
        assert_eq!(evidence.b879_clone_stack_offset, 0x0BF0);
        assert_eq!(evidence.b879_clone_forward_cap_data_stack_offset, 0x0BD0);
        assert_eq!(evidence.b879_clone_forward_len_stack_offset, 0x0BE0);
        assert_eq!(evidence.b879_clone_later_overwrite_fn_va, 0x00B6_00A4);
        assert_eq!(evidence.payload_prefix_source_stack_offset, 0x0A20);
        assert_eq!(evidence.payload_vec_stack_offsets, [0x0A30, 0x0A38, 0x0A40]);
        assert_eq!(evidence.payload_prefix_staging_stack_offset, 0x0C10);
        assert_eq!(evidence.payload_prefix_staging_bytes, 0x0190);
        assert_eq!(evidence.payload_prefix_constructor_arg_index, 7);
        assert!(evidence.b90c_clone_reaches_payload_prefix);
        assert_eq!(
            evidence.prestage_provider_pair_state_offsets,
            [0x04B0, 0x04B8]
        );
        assert_eq!(evidence.prestage_provider_method_slot, 0x18);
        assert_eq!(
            evidence.prestage_provider_preserved_data_state_offset,
            0x0EA8
        );
        assert_eq!(evidence.prestage_provider_data_clone_fn_va, 0x0046_8B24);
        assert_eq!(evidence.prestage_provider_prefix_clone_fn_va, 0x0046_85AC);
        assert_eq!(evidence.prestage_provider_vec_offset, 0x10);
        assert_eq!(evidence.prestage_materializer_input_prefix_bytes, 0x02A0);
        assert_eq!(evidence.prestage_materialized_prefix_bytes, 0x0660);
        assert_eq!(evidence.hashchain_manager_vec_offsets, [0x10, 0x18, 0x20]);
        assert_eq!(evidence.hashchain_manager_drop_fn_va, 0x00B7_5924);
        assert_eq!(evidence.listener_working_pair_offsets, [0x0BA0, 0x0BA8]);
        assert_eq!(evidence.listener_method_slot, 0x18);
        assert_eq!(evidence.listener_dispatch_va, 0x00B8_7AE4);
        assert_eq!(evidence.candidate_bytes, 0x10);
        assert_eq!(evidence.selected_candidate_offsets, [0x0E20, 0x0E28]);
        assert_eq!(evidence.candidate_validate_method_slot, 0x28);
        assert_eq!(evidence.candidate_validate_dispatch_va, 0x00B8_96F4);
        assert_eq!(evidence.payload_candidate_offsets, [0x0230, 0x0238]);
        assert_eq!(
            evidence.code3_builder_vtable_vas,
            [0x019A_C828, 0x019A_C880]
        );
        assert_eq!(
            evidence.code3_provider_vtable_vas,
            [0x019A_C978, 0x019A_C9B8]
        );
        assert_eq!(
            evidence.candidate_validate_method_vas,
            [0x0070_A82C, 0x0070_A824]
        );
        assert_eq!(
            evidence.lifecycle_hook_method_vas,
            [0x0070_539C, 0x0070_57FC]
        );
        assert_eq!(evidence.child_method_vas, [0x0070_53A0, 0x0070_5800]);
        assert_eq!(evidence.child_result_bytes, [0x0340, 0x0300]);
        assert_eq!(evidence.child_result_vtable_vas, [0x019A_CE50, 0x019A_CE70]);
        assert_eq!(
            evidence.lifecycle_hook_disposition,
            BosminerPayloadHookDisposition::NoOpRetainsPrestagedPair
        );
        assert_eq!(evidence.prestage_vec_source_offset, 0x10);
        assert_eq!(evidence.prestage_vec_clone_fn_va, 0x012D_276C);
        assert_eq!(evidence.prestaged_data_offset, 0x0538);
        assert_eq!(evidence.concrete_prestaged_dispatch_table_va, None);
        assert!(refuse_bosminer_hashchain_lifecycle_receiver_as_concrete_gpio_authority().is_err());

        fixture[(0x0070_539C - 0x0040_0000) as usize] ^= 1;
        assert!(admit_bosminer_payload_hook_producer_lineage_static(&fixture).is_err());

        fixture[(0x0070_539C - 0x0040_0000) as usize] ^= 1;
        fixture[(0x0070_57FC - 0x0040_0000) as usize] ^= 1;
        assert!(admit_bosminer_payload_hook_producer_lineage_static(&fixture).is_err());

        fixture[(0x0070_57FC - 0x0040_0000) as usize] ^= 1;
        fixture[(0x0047_CC90 - 0x0040_0000) as usize] ^= 1;
        assert!(admit_bosminer_payload_hook_producer_lineage_static(&fixture).is_err());
    }

    #[test]
    fn bosminer_fan_status_schema_and_zero_min_fans_are_not_cooling_authority() {
        let fixture_len =
            (0x0139_039D - 0x0040_0000) as usize + b"required_fans_above_min_speed".len();
        let mut fixture = vec![0u8; fixture_len];
        let type_off = (BOSMINER_FAN_STATUS_TYPE_NAME_VA - 0x0040_0000) as usize;
        fixture[type_off..type_off + BOSMINER_FAN_STATUS_TYPE_NAME.len()]
            .copy_from_slice(BOSMINER_FAN_STATUS_TYPE_NAME);
        for field in BOSMINER_FAN_STATUS_FIELDS {
            let off = (field.name_va - 0x0040_0000) as usize;
            fixture[off..off + field.name.len()].copy_from_slice(field.name);
        }
        for (va, value) in BOSMINER_FAN_STATUS_SERIALIZER_PINS {
            let off = (va - 0x0040_0000) as usize;
            fixture[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }

        assert!(admit_bosminer_fan_status_schema_static(&fixture).is_ok());
        assert_eq!(
            BOSMINER_FAN_STATUS_FIELDS.map(|field| field.value_offset),
            [0x00, 0x08, 0x10, 0x11, 0x12]
        );
        assert_eq!(BOSMINER_S19K_DEPARTURE_FAN_POLICY.min_fans, 0);
        assert_eq!(BOSMINER_S19K_DEPARTURE_FAN_POLICY.min_fan_rpm, 2_000);
        assert_eq!(
            BOSMINER_S19K_DEPARTURE_FAN_POLICY.resolved_config_observations,
            8
        );
        assert!(refuse_bosminer_s19k_fan_gate_as_positive_cooling_proof().is_err());

        fixture[(0x00B7_FE10 - 0x0040_0000) as usize] ^= 1;
        assert!(admit_bosminer_fan_status_schema_static(&fixture).is_err());
    }

    #[test]
    fn s19k_aml_production_gpio_map_admits_only_vnish_s11board_numbers() {
        assert_eq!(S19K_AML_PWR_EN_GPIO, 437);
        assert_eq!(S19K_AML_PWR_EN_ON, 0);
        assert_eq!(S19K_AML_PWR_EN_OFF, 1);
        assert!(s19k_aml_pwr_en_is_on(0));
        assert!(!s19k_aml_pwr_en_is_on(1));
        assert!(s19k_track1_leftover_handoff_gpio437_ok(Some(0)));
        assert!(!s19k_track1_leftover_handoff_gpio437_ok(Some(1)));
        assert!(!s19k_track1_leftover_handoff_gpio437_ok(None));
        assert!(s19k_track1_refuse_work_tx_if_gpio437_not_on(Some(0)).is_ok());
        assert!(s19k_track1_refuse_work_tx_if_gpio437_not_on(Some(1)).is_err());
        assert!(s19k_track1_refuse_work_tx_if_gpio437_not_on(None).is_err());
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_refuses_tx_when_gpio437_off(serial).is_ok());
        assert!(refuse_s19k_s21_pwr_en_polarity_as_am3_s19k().is_err());
        assert!(admit_s19k_aml_chain_reset_gpios(S19K_AML_CHAIN_RESET_GPIOS).is_ok());
        assert!(admit_s19k_aml_chain_reset_gpios([454, 455, 457]).is_err());
        assert!(admit_s19k_aml_chain_plug_gpios(S19K_AML_CHAIN_PLUG_GPIOS).is_ok());
        assert!(admit_s19k_aml_chain_plug_gpios([439, 440, 442]).is_err());
        assert_eq!(S19K_AML_FAN_TACH_GPIOS, [447, 448, 449, 450]);
        assert_eq!(S19K_AML_LED_GREEN_GPIO, 453);
        assert_eq!(S19K_AML_LED_RED_GPIO, 438);
    }

    #[test]
    fn amtc_bm1366_fast_uart_reconstruction_pins_thumb_bfi_semantics() {
        assert_eq!(AMTC_BM1366_SET_CHAIN_BAUD_FN_VA, 0x0007_51AC);
        assert_eq!(AMTC_BM1366_CHAIN_INIT_FN_VA, 0x0005_ED10);
        assert_eq!(AMTC_BM1366_STRICT_ENUM_FN_VA, 0x0002_4C18);
        assert_eq!(AMTC_BM1366_SET_ADDRESS_LADDER_FN_VA, 0x0007_5140);
        assert_eq!(AMTC_BM1366_UART_RELAY_FN_VA, 0x0005_DF08);
        assert_eq!(AMTC_BM1366_POST_RESET_INIT_FN_VA, 0x0005_E030);
        assert_eq!(AMTC_BM1366_PLL1_BAUD_THRESHOLD, 3_000_001);
        assert_eq!(AMTC_BM1366_JIG_SHA256.len(), 64);

        let at_3m = amtc_bm1366_fast_uart_plan(
            AMTC_BM1366_PLL1_RESET,
            AMTC_BM1366_FASTUART_RESET,
            3_000_000,
        )
        .unwrap();
        assert_eq!(at_3m.reference_clock_hz, 25_000_000);
        assert_eq!(
            at_3m.rmw_input_source,
            AmtcBm1366RegisterValueSource::LocalBroadcastCache
        );
        assert!(!at_3m.rmw_input_source.is_fresh_wire_response());
        assert_eq!(at_3m.divider_minus_one, 0);
        assert_eq!(at_3m.pll1_write, None);
        assert_eq!(at_3m.fast_uart_write, 0x1130_0000);
        assert_ne!(at_3m.fast_uart_write, 0x0130_0000);

        let just_above = amtc_bm1366_fast_uart_plan(
            AMTC_BM1366_PLL1_RESET,
            AMTC_BM1366_FASTUART_RESET,
            3_000_001,
        )
        .unwrap();
        assert_eq!(just_above.reference_clock_hz, 400_000_000);
        assert_eq!(just_above.pll1_write, Some(0x5060_0111));

        let at_3125k = amtc_bm1366_fast_uart_plan(
            AMTC_BM1366_PLL1_RESET,
            AMTC_BM1366_FASTUART_RESET,
            3_125_000,
        )
        .unwrap();
        assert_eq!(at_3125k.divider_minus_one, 0x0F);
        assert_eq!(at_3125k.pll1_write, Some(0x5060_0111));
        assert_eq!(at_3125k.pll1_write_repetitions, 2);
        assert_eq!(at_3125k.pll1_post_write_dwell_ms, 10);
        assert_eq!(at_3125k.fast_uart_write, 0x9450_0F00);
        assert_eq!(at_3125k.fast_uart_post_write_dwell_ms, 60);
        assert_ne!(at_3125k.fast_uart_write, 0x8450_0F00);
        assert_ne!(at_3125k.fast_uart_write, );

        let at_jig_12m = amtc_bm1366_fast_uart_plan(
            AMTC_BM1366_PLL1_RESET,
            AMTC_BM1366_FASTUART_RESET,
            12_000_000,
        )
        .unwrap();
        assert_eq!(at_jig_12m.divider_minus_one, 3);
        assert_eq!(at_jig_12m.fast_uart_write, 0x9450_0300);

        let at_1m = amtc_bm1366_fast_uart_plan(
            AMTC_BM1366_PLL1_RESET,
            AMTC_BM1366_FASTUART_RESET,
            1_000_000,
        )
        .unwrap();
        assert_eq!(at_1m.pll1_write, None);
        assert_eq!(at_1m.divider_minus_one, 2);
        assert_eq!(at_1m.fast_uart_write, 0x1130_0200);
    }

    #[test]
    fn amtc_bm1366_fast_uart_preserves_only_binary_selected_bits_and_refuses_aliases() {
        let high = amtc_bm1366_fast_uart_plan(u32::MAX, u32::MAX, 3_125_000).unwrap();
        assert_eq!(high.pll1_write, Some(0xD060_C199));
        assert_eq!(high.fast_uart_write, 0xF45E_0FFF);

        let low = amtc_bm1366_fast_uart_plan(u32::MAX, u32::MAX, 115_200).unwrap();
        assert_eq!(low.pll1_write, None);
        assert_eq!(low.divider_minus_one, 0x1A);
        assert_eq!(low.fast_uart_write, 0xB3FE_1AFF);

        assert!(amtc_bm1366_fast_uart_plan(0, 0, 0).is_err());
        assert!(amtc_bm1366_fast_uart_plan(0, 0, u32::MAX).is_err());
        assert!(amtc_bm1366_fast_uart_plan(0, 0, 1).is_err());
    }

    #[test]
    fn amtc_bm1366_post_init_ramp_and_ticket_paths_remain_dialect_scoped() {
        assert_eq!(AMTC_BM1366_FACTORY_FREQ_CALLER_VA, 0x0006_43EE);
        assert_eq!(AMTC_BM1366_POST_INIT_FREQ_FN_VA, 0x0005_E314);
        assert_eq!(AMTC_BM1366_STANDARD_FREQ_RAMP_FN_VA, 0x0005_D8D4);
        assert_eq!(AMTC_BM1366_ALTERNATE_FREQ_RAMP_FN_VA, 0x0005_DAF8);
        assert_eq!(AMTC_BM1366_POST_RAMP_FASTUART_CALL_VA, 0x0005_E3BE);
        assert_eq!(AMTC_BM1366_POST_FREQ_CONFIG_FN_VA, 0x0005_E484);
        assert_eq!(AMTC_BM1366_POST_FREQ_CONFIG_CALL_VA, 0x0006_43F6);
        assert_eq!(AMTC_BM1366_FACTORY_POST_CONFIG_DWELL_MS, 1_000);

        let standard = amtc_bm1366_post_init_frequency_plan(670, false);
        assert_eq!(standard.start_mhz, 50);
        assert_eq!(standard.effective_target_mhz, 670);
        assert_eq!(standard.step_x100_mhz, 625);
        assert_eq!(
            standard.ramp_routine,
            AmtcBm1366FrequencyRampRoutine::StandardFixedDwell
        );
        assert_eq!(standard.ramp_function_va, 0x0005_D8D4);
        assert_eq!(standard.fixed_write_dwell_ms, Some(300));
        assert!(standard.reapplies_fast_uart_after_ramp);

        let alternate = amtc_bm1366_post_init_frequency_plan(670, true);
        assert_eq!(
            alternate.ramp_routine,
            AmtcBm1366FrequencyRampRoutine::AlternateConfigSelected
        );
        assert_eq!(alternate.ramp_function_va, 0x0005_DAF8);
        assert_eq!(alternate.fixed_write_dwell_ms, None);
        assert!(alternate.reapplies_fast_uart_after_ramp);

        // The standard loop's extra terminal iteration is intentional and
        // must not be optimized away by an eventual AMTC-compatible executor.
        assert_eq!(amtc_bm1366_standard_ramp_write_count(50), 1);
        assert_eq!(
            amtc_bm1366_standard_ramp_write_frequency_x100(50, 1),
            Ok(5_000)
        );
        assert_eq!(amtc_bm1366_standard_ramp_write_count(0), 9);
        assert_eq!(amtc_bm1366_standard_ramp_write_frequency_x100(0, 8), Ok(0));
        assert_eq!(amtc_bm1366_standard_ramp_write_frequency_x100(0, 9), Ok(0));
        assert_eq!(amtc_bm1366_standard_ramp_write_count(75), 5);
        assert_eq!(
            amtc_bm1366_standard_ramp_write_frequency_x100(75, 1),
            Ok(5_625)
        );
        assert_eq!(
            amtc_bm1366_standard_ramp_write_frequency_x100(75, 4),
            Ok(7_500)
        );
        assert_eq!(
            amtc_bm1366_standard_ramp_write_frequency_x100(75, 5),
            Ok(7_500)
        );
        assert_eq!(amtc_bm1366_standard_ramp_write_count(670), 101);
        assert_eq!(
            amtc_bm1366_standard_ramp_write_frequency_x100(670, 99),
            Ok(66_875)
        );
        assert_eq!(
            amtc_bm1366_standard_ramp_write_frequency_x100(670, 100),
            Ok(67_000)
        );
        assert_eq!(
            amtc_bm1366_standard_ramp_write_frequency_x100(670, 101),
            Ok(67_000)
        );
        assert_eq!(amtc_bm1366_standard_ramp_write_count(40), 3);
        assert_eq!(
            amtc_bm1366_standard_ramp_write_frequency_x100(40, 1),
            Ok(4_375)
        );
        assert_eq!(
            amtc_bm1366_standard_ramp_write_frequency_x100(40, 2),
            Ok(4_000)
        );
        assert_eq!(
            amtc_bm1366_standard_ramp_write_frequency_x100(40, 3),
            Ok(4_000)
        );
        assert!(amtc_bm1366_standard_ramp_write_frequency_x100(670, 0).is_err());
        assert!(amtc_bm1366_standard_ramp_write_frequency_x100(670, 102).is_err());
        let max_count = amtc_bm1366_standard_ramp_write_count(u32::MAX);
        assert_eq!(max_count, 687_194_761);
        assert_eq!(
            amtc_bm1366_standard_ramp_write_frequency_x100(u32::MAX, max_count),
            Ok(u64::from(u32::MAX) * 100)
        );

        let ordinary = amtc_bm1366_post_frequency_ticket_plan(false, false);
        assert_eq!(ordinary.logical_value, AMTC_BM1366_POST_FREQ_TICKET_LOGICAL);
        assert_eq!(ordinary.wire_value, AMTC_BM1366_POST_FREQ_TICKET_WIRE);
        assert_eq!(
            amtc_bm1366_post_frequency_ticket_plan(true, false),
            ordinary
        );
        assert_eq!(amtc_bm1366_post_frequency_ticket_plan(true, true), ordinary);
        let override_all_ones = amtc_bm1366_post_frequency_ticket_plan(false, true);
        assert_eq!(override_all_ones.logical_value, 0x0000_FFFF);
        assert_eq!(override_all_ones.wire_value, 0x0000_FFFF);

        // This is now a real non-invariant AMTC vector, but it remains a
        // dialect divergence rather than authority to rewrite global policy.
        assert_eq!(crate::resolve_ticket_mask(0x1366, 128), 0x0000_007F);
        assert_ne!(ordinary.wire_value, crate::resolve_ticket_mask(0x1366, 128));
    }

    #[test]
    fn amtc_bm1366_cache_ladder_three_pass_and_fpga_response_semantics_are_explicit() {
        assert_eq!(AMTC_BM1366_RX_THREAD_FN_VA, 0x0005_EA90);
        assert_eq!(AMTC_BM1366_REGISTER_RESPONSE_ENQUEUE_FN_VA, 0x0005_E7B4);
        assert_eq!(AMTC_BM1366_REGISTER_CACHE_GET_FN_VA, 0x0007_6270);
        assert_eq!(AMTC_BM1366_REGISTER_CACHE_UPDATE_FN_VA, 0x0007_6364);
        assert_eq!(AMTC_BM1366_WRITE_AND_CACHE_FN_VA, 0x0007_4C1C);
        assert_eq!(AMTC_BM1366_POST_SUCCESS_HOOK_FN_VA, 0x0002_5544);
        assert_eq!(AMTC_BM1366_TICKET_MASK_WRITE_FN_VA, 0x0007_5310);
        assert_eq!(AMTC_BM1366_TICKET_MASK_BIT_REVERSE_LUT_VA, 0x001A_3300);
        assert!(AmtcBm1366RegisterValueSource::WireResponseRing.is_fresh_wire_response());
        assert!(!AmtcBm1366RegisterValueSource::LocalPerAsicCache.is_fresh_wire_response());

        let all_addresses = amtc_bm1366_set_address_ladder(1).unwrap();
        assert_eq!(all_addresses.len(), 256);
        assert_eq!(all_addresses.first(), Some(&0));
        assert_eq!(all_addresses.last(), Some(&255));
        let s19k_addresses = amtc_bm1366_set_address_ladder(2).unwrap();
        assert_eq!(s19k_addresses.len(), 128);
        assert_eq!(s19k_addresses.first(), Some(&0));
        assert_eq!(s19k_addresses.last(), Some(&254));
        let floor_division = amtc_bm1366_set_address_ladder(3).unwrap();
        assert_eq!(floor_division.len(), 85);
        assert_eq!(floor_division.last(), Some(&252));
        assert!(amtc_bm1366_set_address_ladder(0).is_err());

        let exact = amtc_bm1366_evaluate_three_passes(77, [77, 77, 77], true);
        assert!(exact.stage_marked_success);
        assert_eq!(exact.recorded_count, 77);
        assert!(exact.post_success_readdress);
        let post_success = amtc_bm1366_post_success_readdress_manifest(exact, 2).unwrap();
        assert_eq!(post_success.len(), 130);
        assert_eq!(post_success[0].op, AmtcBm1366ChainInitOp::ChainInactive);
        assert_eq!(post_success[0].dwell_after_ms, 10);
        let post_addresses: Vec<_> = post_success
            .iter()
            .filter_map(|step| match step.op {
                AmtcBm1366ChainInitOp::SetAddress { address } => Some(address),
                _ => None,
            })
            .collect();
        assert_eq!(post_addresses.len(), 128);
        assert_eq!(post_addresses.first(), Some(&0));
        assert_eq!(post_addresses.last(), Some(&254));
        assert_eq!(
            post_success.last().unwrap().op,
            AmtcBm1366ChainInitOp::PostSuccessHook {
                function_va: 0x0002_5544,
                argument: 3
            }
        );
        let exact_without_readdress = amtc_bm1366_evaluate_three_passes(77, [77, 77, 77], false);
        assert!(exact_without_readdress.stage_marked_success);
        assert!(!exact_without_readdress.post_success_readdress);
        assert!(
            amtc_bm1366_post_success_readdress_manifest(exact_without_readdress, 2)
                .unwrap()
                .is_empty()
        );
        let disagreement = amtc_bm1366_evaluate_three_passes(77, [77, 75, 76], true);
        assert!(!disagreement.stage_marked_success);
        assert_eq!(disagreement.recorded_count, 75);
        assert!(!disagreement.post_success_readdress);
        assert!(amtc_bm1366_post_success_readdress_manifest(disagreement, 2)
            .unwrap()
            .is_empty());
        let stable_but_wrong = amtc_bm1366_evaluate_three_passes(77, [76, 76, 76], true);
        assert!(!stable_but_wrong.stage_marked_success);
        assert_eq!(stable_but_wrong.recorded_count, 76);
        assert!(!stable_but_wrong.post_success_readdress);

        // Internal AMTC FPGA record: chain, register, ASIC, flags, then a host
        // LE word. It is deliberately not the raw AA55/BE UART byte layout.
        let internal = [0x02, 0x00, 0x04, 0x00, 0x04, 0x00, 0x66, 0x13];
        let response = amtc_bm1366_decode_fpga_register_response(internal, 2).unwrap();
        assert_eq!(response.chain, 2);
        assert_eq!(response.register_address, 0);
        assert_eq!(response.asic_address, 4);
        assert_eq!(response.value_host_le, 0x1366_0004);
        let raw_uart = crate::s19k_bm1366_uart_rx::bm1366_command_reply_uart(0x1366_0004, 4, 0);
        assert_eq!(&raw_uart[2..6], &[0x13, 0x66, 0x00, 0x04]);
        assert_eq!(&internal[4..8], &[0x04, 0x00, 0x66, 0x13]);
        match crate::s19k_bm1366_uart_rx::classify_bm1366_uart_rx_checked(&raw_uart).unwrap() {
            crate::s19k_bm1366_uart_rx::S19kUartRxKind::ChipAddress {
                chip_id,
                value_address,
                responder_address,
            } => {
                assert_eq!((chip_id, value_address, responder_address), (0x1366, 4, 4));
            }
            other => panic!("unexpected raw-UART response: {other:?}"),
        }
        let address = amtc_bm1366_address_response_view(response, 2).unwrap();
        assert_eq!(address.chip_id, 0x1366);
        assert_eq!(address.value_address, 4);
        assert_eq!(address.slot_floor, 2);
        assert!(address.interval_aligned);

        let odd_internal = [0x02, 0x00, 0x08, 0x00, 0x05, 0x00, 0x66, 0x13];
        let odd = amtc_bm1366_decode_fpga_register_response(odd_internal, 2).unwrap();
        let odd_address = amtc_bm1366_address_response_view(odd, 2).unwrap();
        assert_eq!(odd_address.slot_floor, 2, "held jig uses floor division");
        assert!(!odd_address.interval_aligned);
        assert!(amtc_bm1366_address_response_view(odd, 0).is_err());
        assert_eq!(
            amtc_bm1366_decode_fpga_register_response([0x01, 0, 0, 0, 0, 0, 0, 0], 2),
            Err(AmtcBm1366RegisterResponseError::WrongChain {
                observed: 1,
                expected: 2
            })
        );
        assert_eq!(
            amtc_bm1366_decode_fpga_register_response(internal, 0x12),
            Err(AmtcBm1366RegisterResponseError::WrongChain {
                observed: 2,
                expected: 0x12
            }),
            "held code masks only the record nibble, not the expected-chain global"
        );
        assert_eq!(
            amtc_bm1366_decode_fpga_register_response([0x02, 0, 0, 0x20, 0, 0, 0, 0], 2),
            Err(AmtcBm1366RegisterResponseError::CrcFlagBitsSet { flags: 0x20 })
        );
        assert_eq!(
            amtc_bm1366_decode_fpga_register_response([0x02, 0, 0, 0x80, 0, 0, 0, 0], 2),
            Err(AmtcBm1366RegisterResponseError::NonRegisterRecord)
        );

        assert_eq!(amtc_bm1366_ticket_mask_wire_value(0xFFFF_FFFF), 0xFFFF_FFFF);
        assert_eq!(amtc_bm1366_ticket_mask_wire_value(0x0000_007F), 0x0000_00FE);
        assert_eq!(amtc_bm1366_ticket_mask_wire_value(0x1234_5678), 0x482C_6A1E);
        // Industrial/ESP policy is separate: even the non-invariant AMTC
        // post-frequency vector must not silently rewrite another dialect.
        assert_eq!(crate::resolve_ticket_mask(0x1366, 128), 0x0000_007F);
        assert_ne!(
            amtc_bm1366_ticket_mask_wire_value(crate::resolve_ticket_mask(0x1366, 128)),
            crate::resolve_ticket_mask(0x1366, 128)
        );
    }

    #[test]
    fn amtc_bm1366_chain_init_manifest_pins_128_address_factory_sequence() {
        let relay = amtc_bm1366_uart_relay_domain_plan(2, 77, 11, 7).unwrap();
        assert_eq!(relay.len(), 11);
        assert_eq!(
            relay[0],
            AmtcBm1366RelayDomainPlan {
                voltage_domain: 10,
                first_address: 140,
                first_uart_relay_value: 0x001B_0003,
                second_address: 152,
                second_uart_relay_value: 0x0015_0003,
                io_driver_address: 152,
                io_driver_high_nibble: 0xF,
            }
        );
        assert_eq!(relay.last().unwrap().voltage_domain, 0);
        assert_eq!(relay.last().unwrap().first_address, 0);
        assert_eq!(relay.last().unwrap().first_uart_relay_value, 0x0061_0003);
        assert_eq!(relay.last().unwrap().second_address, 12);
        assert_eq!(relay.last().unwrap().second_uart_relay_value, 0x005B_0003);
        assert!(!relay.iter().any(|domain| {
            domain.first_uart_relay_value == UART_RELAY_CHIP0_PUBLIC
                || domain.second_uart_relay_value == UART_RELAY_CHIP0_PUBLIC
        }));
        assert!(amtc_bm1366_uart_relay_domain_plan(2, 76, 11, 7).is_err());

        let steps = amtc_bm1366_chain_init_manifest(
            2,
            AMTC_BM1366_PLL1_RESET,
            AMTC_BM1366_FASTUART_RESET,
            INIT_CTRL_A8_UNICAST,
            MISC_CTRL_UNICAST,
            12_000_000,
        )
        .unwrap();
        assert_eq!(steps.len(), 174);
        assert_eq!(
            steps[0].op,
            AmtcBm1366ChainInitOp::StrictEnumerate {
                pass: 1,
                retry_once: true
            }
        );
        assert_eq!(steps[1].op, AmtcBm1366ChainInitOp::ChainInactive);
        assert_eq!(steps[1].dwell_after_ms, 10);

        let addresses: Vec<_> = steps
            .iter()
            .filter_map(|step| match step.op {
                AmtcBm1366ChainInitOp::SetAddress { address } => Some(address),
                _ => None,
            })
            .collect();
        assert_eq!(addresses.len(), 128);
        assert_eq!(addresses.first(), Some(&0));
        assert_eq!(addresses.last(), Some(&254));
        assert!(addresses.windows(2).all(|pair| pair[1] - pair[0] == 2));
        assert!(steps
            .iter()
            .filter(|step| matches!(step.op, AmtcBm1366ChainInitOp::SetAddress { .. }))
            .all(|step| step.dwell_after_ms == 10));
        assert_eq!(
            steps
                .iter()
                .filter(|step| matches!(step.op, AmtcBm1366ChainInitOp::WriteUartRelay { .. }))
                .count(),
            22
        );
        assert_eq!(
            steps
                .iter()
                .filter(|step| matches!(
                    step.op,
                    AmtcBm1366ChainInitOp::SetIoDriverHighNibbleF { .. }
                ))
                .count(),
            11
        );

        let enum_passes: Vec<_> = steps
            .iter()
            .filter_map(|step| match step.op {
                AmtcBm1366ChainInitOp::StrictEnumerate { pass, retry_once } => {
                    assert!(retry_once);
                    Some(pass)
                }
                _ => None,
            })
            .collect();
        assert_eq!(enum_passes, [1, 2, 3]);
        let assert_idx = steps
            .iter()
            .position(|step| step.op == AmtcBm1366ChainInitOp::FpgaChainResetAssert)
            .unwrap();
        let release_idx = steps
            .iter()
            .position(|step| step.op == AmtcBm1366ChainInitOp::FpgaChainResetRelease)
            .unwrap();
        let post_reset_idx = steps
            .iter()
            .position(|step| matches!(step.op, AmtcBm1366ChainInitOp::PostResetA8MiscRmw { .. }))
            .unwrap();
        let baud_idx = steps
            .iter()
            .position(|step| matches!(step.op, AmtcBm1366ChainInitOp::SetChipAndHostBaud { .. }))
            .unwrap();
        let pass2_idx = steps
            .iter()
            .position(|step| {
                matches!(
                    step.op,
                    AmtcBm1366ChainInitOp::StrictEnumerate { pass: 2, .. }
                )
            })
            .unwrap();
        let host_default_baud_idx = steps
            .iter()
            .position(|step| {
                step.op == (AmtcBm1366ChainInitOp::SetHostBaudDivider { divider: 0x1A })
            })
            .unwrap();
        let pass3_idx = steps
            .iter()
            .position(|step| {
                matches!(
                    step.op,
                    AmtcBm1366ChainInitOp::StrictEnumerate { pass: 3, .. }
                )
            })
            .unwrap();
        assert!(
            baud_idx < pass2_idx
                && pass2_idx < assert_idx
                && assert_idx < release_idx
                && release_idx < host_default_baud_idx
                && host_default_baud_idx < post_reset_idx
                && post_reset_idx < pass3_idx
        );
        assert_eq!(steps[baud_idx].dwell_after_ms, 50);
        assert_eq!(steps[assert_idx].dwell_after_ms, 500);
        assert_eq!(steps[release_idx].dwell_after_ms, 500);
        assert_eq!(
            steps[post_reset_idx].op,
            AmtcBm1366ChainInitOp::PostResetA8MiscRmw {
                plan: AmtcBm1366A8MiscRmwPlan {
                    rmw_input_source: AmtcBm1366RegisterValueSource::LocalBroadcastCache,
                    init_control_a8_write: 0x0007_01F0,
                    misc_control_18_write: 0xFF0F_C100,
                }
            }
        );
        assert_eq!(
            steps.last().unwrap().op,
            AmtcBm1366ChainInitOp::EvaluateThreeEnumCountsAgainstExpected {
                expected_count: 77,
                mismatch_records_minimum: true,
            }
        );
        assert!(amtc_bm1366_chain_init_manifest(
            4,
            AMTC_BM1366_PLL1_RESET,
            AMTC_BM1366_FASTUART_RESET,
            INIT_CTRL_A8_UNICAST,
            MISC_CTRL_UNICAST,
            12_000_000
        )
        .is_err());
    }

    #[test]
    fn held_jigs_pin_bm1366_extra_mode_bfi_and_bm1362_divergence() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../..");
        let bm1366 = std::fs::read(
            root.join(""),
        )
        .expect("held BM1366 AMTC jig");
        assert_eq!(bm1366.len(), 2_087_696);
        // First LOAD is VA=file+0x10000. These are the high- and low-branch
        // Thumb BFI instructions that add the BM1366-only mode field.
        assert_eq!(&bm1366[0x6527E..0x65282], &[0x66, 0xF3, 0xC4, 0x02]);
        assert_eq!(&bm1366[0x652FC..0x65300], &[0x61, 0xF3, 0xC4, 0x03]);
        let expected_bit_reverse_lut: Vec<u8> = (0u16..=255)
            .map(|value| (value as u8).reverse_bits())
            .collect();
        assert_eq!(
            &bm1366[0x193300..0x193400],
            expected_bit_reverse_lut.as_slice(),
            "BM1366 FUN_00075310 LUT bytes at VA 0x001a3300"
        );
        // Enclosing factory caller: r1=effective target, r0=50, call the
        // frequency wrapper, immediately call post-frequency configuration.
        assert_eq!(
            &bm1366[0x543EE..0x543FA],
            &[0x29, 0x46, 0x32, 0x20, 0xF9, 0xF7, 0x8F, 0xFF, 0xFA, 0xF7, 0x45, 0xF8]
        );
        // Standard branch passes step=6.25 to FUN_0005d8d4 and then falls
        // through to config +0x240 / FUN_000751ac FastUART reapplication.
        assert_eq!(
            &bm1366[0x4E3A4..0x4E3C2],
            &[
                0x4B, 0x46, 0x42, 0x46, 0x91, 0xF8, 0x58, 0x12, 0xB1, 0xEE, 0x09, 0x0A, 0x30, 0x78,
                0xFF, 0xF7, 0x8F, 0xFA, 0x2B, 0x68, 0x30, 0x78, 0xD3, 0xF8, 0x40, 0x12, 0x16, 0xF0,
                0xF5, 0xFE,
            ]
        );
        // One-second caller dwell immediately follows post-frequency config.
        assert_eq!(
            &bm1366[0x543FA..0x5440A],
            &[
                0x44, 0xF2, 0x40, 0x20, 0x40, 0xF2, 0x2D, 0x15, 0xC0, 0xF2, 0x0F, 0x00, 0xB1, 0xF7,
                0xD6, 0xEF,
            ]
        );
        // Alternate branch also reconverges at 0x5e3b6, so it cannot be used
        // as evidence that FastUART reapplication is standard-branch-only.
        assert_eq!(
            &bm1366[0x4E456..0x4E46C],
            &[
                0x29, 0x68, 0x4B, 0x46, 0x42, 0x46, 0xB1, 0xEE, 0x09, 0x0A, 0x30, 0x78, 0x91, 0xF8,
                0x58, 0x12, 0xFF, 0xF7, 0x47, 0xFB, 0xA4, 0xE7,
            ]
        );
        // Standard ramp loads 300,000 us, writes via FUN_000755f8, sleeps,
        // then tests its loop count.
        assert_eq!(
            &bm1366[0x4D9F2..0x4DA0A],
            &[
                0x07, 0xEE, 0x90, 0xBA, 0x0A, 0xAF, 0xB8, 0xEE, 0x67, 0x9A, 0x49, 0xF2, 0xE0, 0x3A,
                0xDD, 0xED, 0x05, 0x7A, 0x3E, 0x46, 0xC0, 0xF2, 0x04, 0x0A,
            ]
        );
        // Float/double count arithmetic: convert abs delta, add step,
        // subtract the held 0.01 epsilon, divide by 6.25, truncate, then +1.
        assert_eq!(
            &bm1366[0x4D98A..0x4D9B0],
            &[
                0x07, 0xEE, 0x90, 0x3A, 0xB8, 0xEE, 0x67, 0x7A, 0x37, 0xEE, 0x28, 0x7A, 0xB7, 0xEE,
                0xC7, 0x7A, 0x37, 0xEE, 0x46, 0x7B, 0x87, 0xEE, 0x09, 0x6B, 0xBC, 0xEE, 0xC6, 0x6B,
                0x16, 0xEE, 0x10, 0x3A, 0x01, 0x33, 0x1D, 0x46, 0x06, 0x93,
            ]
        );
        assert_eq!(
            &bm1366[0x4DAE0..0x4DAF0],
            &[
                0x7B, 0x14, 0xAE, 0x47, 0xE1, 0x7A, 0x84, 0x3F, // f64 0.01
                0xB8, 0xDE, 0x19, 0x00, 0x00, 0x00, 0x48, 0x42, // ptr, f32 50.0
            ]
        );
        assert_eq!(
            &bm1366[0x4DA4C..0x4DA64],
            &[
                0x19, 0x46, 0x07, 0x98, 0x96, 0xE8, 0x0C, 0x00, 0x17, 0xF0, 0xD0, 0xFD, 0x50, 0x46,
                0xB8, 0xF7, 0xAC, 0xEC, 0x06, 0x9B, 0xAB, 0x42, 0x16, 0xD3,
            ]
        );
        // Post-frequency selection has two logical-0x7f paths and one
        // logical-0xffff override path before FUN_00075310's LUT transform.
        assert_eq!(
            &bm1366[0x4E490..0x4E4B6],
            &[
                0x23, 0x68, 0x93, 0xF8, 0x14, 0x21, 0x00, 0x2A, 0x40, 0xF0, 0xA2, 0x80, 0x93, 0xF8,
                0x0D, 0x31, 0x48, 0xF2, 0xFC, 0x56, 0x00, 0x2B, 0x6C, 0xD1, 0xC0, 0xF2, 0x21, 0x06,
                0x7F, 0x21, 0x30, 0x78, 0x6D, 0x46, 0x16, 0xF0, 0x2D, 0xFF,
            ]
        );
        assert_eq!(
            &bm1366[0x4E582..0x4E592],
            &[
                0xC0, 0xF2, 0x21, 0x06, 0x4F, 0xF6, 0xFF, 0x71, 0x30, 0x78, 0x6D, 0x46, 0x16, 0xF0,
                0xBF, 0xFE,
            ]
        );
        assert_eq!(
            &bm1366[0x4E5E0..0x4E5F2],
            &[
                0x48, 0xF2, 0xFC, 0x56, 0x7F, 0x21, 0xC0, 0xF2, 0x21, 0x06, 0x6D, 0x46, 0x30, 0x78,
                0x16, 0xF0, 0x8F, 0xFE,
            ]
        );

        let bm1362 = std::fs::read(
            root.join(""),
        )
        .expect("held BM1362 AMTC jig");
        assert_eq!(bm1362.len(), 195_892);
        // The corresponding BM1362 sites proceed directly to LSRS; no mode
        // BFI is present. This is why its existing transform must stay
        // separate even though the PLL1/divider skeleton is shared.
        assert_eq!(&bm1362[0x1CBDE..0x1CBE0], &[0x1A, 0x0C]);
        assert_eq!(&bm1362[0x1CC4E..0x1CC50], &[0x13, 0x0E]);
        assert_eq!(
            &bm1362[0x2D408..0x2D508],
            expected_bit_reverse_lut.as_slice(),
            "BM1362 FUN_0002cc60 shares the LUT transform; do not infer FastUART parity"
        );
    }

    #[test]
    fn chain_inactive_is_53_not_52() {
        assert_eq!(
            CHAIN_INACTIVE_UART,
            [0x55, 0xAA, 0x53, 0x05, 0x00, 0x00, 0x03]
        );
        assert_eq!(GET_ADDRESS_UART[2], 0x52);
        assert_ne!(CHAIN_INACTIVE_UART[2], 0x52);
        assert_eq!(crate::s19k_bm1366_wire_b::S19K_AML_ADDR_INTERVAL, 2);
        assert_eq!(INIT_REG_VERSION_ROLL, 0xA4);
        assert!(refuse_bm1397_9byte_as_bm1366_getaddress_rx(9).is_err());
        assert!(refuse_bm1397_9byte_as_bm1366_getaddress_rx(11).is_ok());
        assert_eq!(ESP_BM1366_CHIP_ID_RX_LEN, 11);
    }

    #[test]
    fn passthrough_program_is_get_address_then_rearm_at_3m() {
        let p = s19k_bm1366_init_program(S19kInitDialect::BraiinsPassthrough);
        assert_eq!(p[0].name, "get_address");
        assert_eq!(p[0].uart, GET_ADDRESS_UART);
        let names: Vec<_> = p.iter().map(|s| s.name).collect();
        assert_eq!(
            names,
            [
                "get_address",
                "analog_mux",
                "ticket_mask_diff256",
                "hash_counting_s19k",
            ]
        );
        assert!(admit_s19k_passthrough_rearm_omits_version_roll(names.as_slice()).is_ok());
        let midrun: Vec<_> = s19k_passthrough_rearm_writes().map(|w| w.name).collect();
        assert_eq!(
            midrun,
            ["analog_mux", "ticket_mask_diff256", "hash_counting_s19k"]
        );
        assert!(admit_s19k_midrun_rearm_includes_analog_mux(&midrun).is_ok());
        assert_eq!(ANALOG_MUX_BCAST_WRITE.reg, 0x54);
        assert_eq!(ANALOG_MUX_BCAST_WRITE.value, 0x0000_0003);
        assert!(
            refuse_esp_9000ffff_as_braiins_fill_rearm(0xA4, ESP_BM1366_VERSION_ROLL_MASK).is_err()
        );
        assert!(refuse_esp_9000ffff_as_braiins_fill_rearm(INIT_REG_TICKET_MASK, 0xFF).is_ok());
        assert!(!p
            .iter()
            .any(|s| s.name == "chain_inactive" || s.name == "set_address"));
        let ticket = p.iter().find(|s| s.name == "ticket_mask_diff256").unwrap();
        assert_eq!(ticket.uart[2], 0x51);
        assert_eq!(ticket.uart[5], 0x14);
        assert!(admit_init_dialect_baud(S19kInitDialect::BraiinsPassthrough, 3_000_000).is_ok());
        assert!(admit_init_dialect_baud(S19kInitDialect::BraiinsPassthrough, 12_000_000).is_err());
        assert!(refuse_native_as_production(S19kInitDialect::BraiinsPassthrough).is_ok());
        assert!(refuse_native_as_production(S19kInitDialect::NativeExperimental).is_err());
        assert_eq!(init_ports(), &["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"]);
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(
            serial.contains("s19k_passthrough_rearm_writes"),
            "production GetAddress path must call shipped re-arm writes"
        );
        assert!(refuse_bosminer_movz_a4_as_set_config(
            BOSMINER_MOVZ_A4_INSN,
            BOSMINER_MOVZ_A4_LDR_INSN
        )
        .is_err());
        assert!(refuse_bosminer_9000ffff_utf16_as_version_mask(&[
            0x80, 0x00, 0x90, 0x00, 0xFF, 0xFF
        ])
        .is_err());
    }

    #[test]
    fn native_program_set_address_interval_2_and_77_slots() {
        let p = s19k_bm1366_init_program(S19kInitDialect::NativeExperimental);
        assert_eq!(p[0].name, "get_address");
        assert_eq!(p[0].uart, GET_ADDRESS_UART);
        assert_eq!(p[1].name, "init_ctrl_a8_bcast");
        assert_eq!(&p[1].uart[2..8], &[0x51, 0x09, 0x00, 0xA8, 0x00, 0x07]);
        assert_eq!(p[2].name, "misc_ctrl_bcast");
        assert_eq!(p[3].uart, CHAIN_INACTIVE_UART);
        // This is the separate ESP-derived 77-chip byte manifest. The AMTC
        // factory ladder above sends 128 SetAddress commands at interval 2;
        // neither count is interchangeable or silently promoted.
        let set_addr: Vec<_> = p.iter().filter(|s| s.name == "set_address").collect();
        assert_eq!(set_addr.len(), 77);
        assert_eq!(
            &set_addr[0].uart[..6],
            &[0x55, 0xAA, 0x40, 0x05, 0x00, 0x00]
        );
        // interval 2: second chip at address 2
        assert_eq!(set_addr[1].uart[4], 2);
        assert!(p.iter().any(|s| s.name == "ticket_mask_diff256"));
        assert!(p.iter().any(|s| s.name == "hash_counting_s19k"));
        assert!(!p.iter().any(|s| s.name == "version_roll"));
        let native_names: Vec<_> = p.iter().map(|s| s.name).collect();
        assert!(admit_s19k_passthrough_rearm_omits_version_roll(native_names.as_slice()).is_ok());
        assert!(refuse_esp_9000ffff_as_braiins_fill_rearm(
            VERSION_ROLL_BCAST_WRITE.reg,
            VERSION_ROLL_BCAST_WRITE.value
        )
        .is_err());
        assert!(p.iter().any(|s| s.name == "analog_mux"));
        assert!(p.iter().any(|s| s.name == "core_hash_clock"));
        assert!(p.iter().any(|s| s.name == "core_clock_delay"));
        let clock = p.iter().find(|s| s.name == "core_hash_clock").unwrap();
        assert_eq!(&clock.uart[2..8], &[0x51, 0x09, 0x00, 0x3c, 0x80, 0x00]);
        assert_eq!(clock.uart[8], 0x85);
        assert_eq!(clock.uart[9], 0x40);
        assert!(p.iter().any(|s| s.name == "misc_ctrl_bcast"));
        assert!(p.iter().any(|s| s.name == "io_driver"));
        let relay = p.iter().find(|s| s.name == "uart_relay_chip0").unwrap();
        assert_eq!(relay.uart[2], 0x41, "UART_RELAY is unicast to chip0");
        assert_eq!(relay.uart[5], 0x2C);
        assert_eq!(VERSION_ROLL_BCAST_WRITE.reg, INIT_REG_VERSION_ROLL);
        assert_eq!(VERSION_ROLL_BCAST_WRITE.value, ESP_BM1366_VERSION_ROLL_MASK);
        assert_eq!(
            pack_experimental_init_write(*VERSION_ROLL_BCAST_WRITE)[5],
            0xA4
        );
        let ticket = *TICKET_MASK_BCAST_WRITE;
        assert_eq!(ticket.reg, 0x14);
        assert_eq!(ticket.value, 0xFF);
        let hcn = *HASH_COUNTING_BCAST_WRITE;
        assert_eq!(hcn.value, 0x0000_115A);
        assert_ne!(hcn.value, 0x0000_151C, "S19XP stock HCN is not S19k");
        assert!(refuse_esp_s19xp_hcn_as_s19k_rearm(hcn.value).is_ok());
        assert!(refuse_esp_s19xp_hcn_as_s19k_rearm(ESP_BM1366_HASH_COUNTING_S19XP).is_err());
        let packed = pack_experimental_init_write(ticket);
        assert_eq!(&packed[..2], &[0x55, 0xAA]);
        assert_eq!(packed[2], 0x51);
        assert_eq!(packed[5], 0x14);
        let a8 = p
            .iter()
            .filter(|s| s.name == "init_ctrl_a8_unicast")
            .collect::<Vec<_>>();
        assert_eq!(a8.len(), 77);
        assert_eq!(a8[0].uart[2], 0x41);
        assert_eq!(a8[0].uart[4], 0);
        assert_eq!(a8[0].uart[5], 0xA8);
        assert_eq!(&a8[0].uart[6..10], &[0x00, 0x07, 0x01, 0xF0]);
        assert_eq!(a8[1].uart[4], 2);
        let boost = p
            .iter()
            .filter(|s| s.name == "core_asicboost_unicast")
            .collect::<Vec<_>>();
        assert_eq!(boost.len(), 77);
        assert_eq!(&boost[0].uart[6..10], &[0x80, 0x00, 0x82, 0xAA]);
        let misc_u = p
            .iter()
            .filter(|s| s.name == "misc_ctrl_unicast")
            .collect::<Vec<_>>();
        assert_eq!(&misc_u[0].uart[6..10], &[0xF0, 0x00, 0xC1, 0x00]);
        assert!(refuse_firmware_internals_a8_as_s19k_per_chip(0xF001_0700).is_err());
        assert!(refuse_firmware_internals_a8_as_s19k_per_chip(INIT_CTRL_A8_UNICAST).is_ok());
        assert!(refuse_native_as_production(S19kInitDialect::NativeExperimental).is_err());
        let get_idx = p.iter().position(|s| s.name == "get_address").unwrap();
        let inact_idx = p.iter().position(|s| s.name == "chain_inactive").unwrap();
        let per_idx = p
            .iter()
            .position(|s| s.name == "init_ctrl_a8_unicast")
            .unwrap();
        let hcn_idx = p
            .iter()
            .position(|s| s.name == "hash_counting_s19k")
            .unwrap();
        let pll_idx = p.iter().position(|s| s.name == "pll0_50mhz").unwrap();
        assert!(get_idx < inact_idx);
        assert!(inact_idx < per_idx);
        assert!(per_idx < pll_idx);
        assert!(pll_idx < hcn_idx);
        let pll = p.iter().find(|s| s.name == "pll0_50mhz").unwrap();
        assert_eq!(pll.uart[2], 0x51);
        assert_eq!(pll.uart[5], REG_PLL0);
        let scale = pll.uart[6];
        assert!(scale == 0x40 || scale == 0x50, "pll scale={scale:#04x}");
        assert!(!p.iter().any(|s| s.name == "fastuart_1m"));
        assert!(admit_s19k_fastuart_with_host_baud(ESP_FASTUART_HOST_BAUD).is_ok());
        assert!(admit_s19k_fastuart_with_host_baud(3_000_000).is_err());
        assert!(admit_s19k_fastuart_with_host_baud(115_200).is_err());
        let fu = s19k_native_fastuart_write();
        assert_eq!(fu.reg, PUBLIC_FASTUART_REG);
        assert_eq!(fu.value, PUBLIC_FASTUART_VALUE);
        let fu_uart = pack_experimental_init_write(fu);
        assert_eq!(&fu_uart[..2], &[0x55, 0xAA]);
        assert_eq!(
            &fu_uart[2..10],
            &[0x51, 0x09, 0x00, 0x28, 0x11, 0x30, 0x02, 0x00]
        );
        assert_eq!(s19k_hcn_set_config_uart()[5], INIT_REG_HASH_COUNTING);
        assert_eq!(
            &s19k_hcn_set_config_uart()[6..10],
            &[0x00, 0x00, 0x11, 0x5A]
        );
        assert!(refuse_bosminer_movz51_as_set_config_packer().is_err());
        assert_eq!(BOSMINER_MOVZ51_HITS, 33);
        assert_eq!(BOSMINER_MOVZ51_VOLTAGE_ALLOC_VA, 0x008C_4BFC);
        assert!(refuse_pll0_50mhz_as_s19k_stock_mining_freq(50).is_err());
        assert!(refuse_pll0_50mhz_as_s19k_stock_mining_freq(400).is_ok());
        let pll400 = s19k_native_pll0_write(400);
        assert_eq!(pll400.reg, REG_PLL0);
        assert_eq!(pll400.value, 0x40A0_0240);
        assert!(refuse_esp_fastuart_as_s19k_braiins_3m(PUBLIC_FASTUART_VALUE).is_err());
        assert!(refuse_esp_fastuart_as_s19k_braiins_3m(0).is_ok());
        let lanes = split_s19k_fastuart_reg(PUBLIC_FASTUART_VALUE);
        assert_eq!(
            (lanes.b31_24, lanes.b23_16, lanes.b15_8, lanes.b7_0),
            (0x11, 0x30, 0x02, 0x00)
        );
        assert_eq!(
            classify_s19k_uart_baud_dialect(3_000_000, None).unwrap(),
            S19kUartBaudDialect::BraiinsHost3M
        );
        assert_eq!(
            classify_s19k_uart_baud_dialect(
                BOSMINER_BM1366_AML_HOST_BAUD,
                Some(BOSMINER_BM1366_FASTUART_3M125)
            )
            .unwrap(),
            S19kUartBaudDialect::BraiinsStockBm1366FastUart
        );
        assert_eq!(
            classify_s19k_uart_baud_dialect(115_200, None).unwrap(),
            S19kUartBaudDialect::Dmesg78Hold115200
        );
        assert_eq!(
            classify_s19k_uart_baud_dialect(1_000_000, Some(PUBLIC_FASTUART_VALUE)).unwrap(),
            S19kUartBaudDialect::EspChipFastUart1M
        );
        assert!(s19k_track1_classify_rx_baud(3_000_000, None).is_ok());
        assert!(s19k_track1_classify_rx_baud(3_000_000, Some("")).is_ok());
        assert!(s19k_track1_classify_rx_baud(3_000_000, Some("0x00003001")).is_err());
        assert!(s19k_track1_classify_rx_baud(1_000_000, None).is_err());
        assert_eq!(
            classify_s19k_chip_fastuart_word(None),
            S19kChipFastUartKind::Unread
        );
        assert_eq!(
            classify_s19k_chip_fastuart_word(Some(0)),
            S19kChipFastUartKind::ZeroOrDefault
        );
        assert_eq!(
            classify_s19k_chip_fastuart_word(Some),
            S19kChipFastUartKind::BibleBm1366_3m125
        );
        assert_eq!(
            classify_s19k_chip_fastuart_word(Some(BOSMINER_BM1366_FASTUART_3M125)),
            S19kChipFastUartKind::BosminerBm1362Bm1366_3m125
        );
        assert_eq!(
            classify_s19k_chip_fastuart_word(Some(BOSMINER_LEGACY_S17_REG28_VALUE)),
            S19kChipFastUartKind::LegacyBm1396Bm1397_0600000F
        );
        assert!(refuse_unread_fastuart_28_as_host_3m_chip_state().is_err());
        assert!(s19k_track1_classify_rx_baud_with_reg28(3_000_000, None, None).is_ok());
        assert!(s19k_track1_classify_rx_baud_with_reg28(
            3_000_000,
            None,
            Some
        )
        .is_err());
        assert!(s19k_track1_classify_rx_baud_with_reg28(
            BOSMINER_BM1366_AML_HOST_BAUD,
            None,
            Some(BOSMINER_BM1366_FASTUART_3M125)
        )
        .is_ok());
        assert!(
            classify_s19k_uart_baud_dialect(3_000_000, Some(BOSMINER_LEGACY_S17_REG28_VALUE))
                .is_err()
        );
        assert!(s19k_track1_classify_rx_baud_with_reg28(
            3_000_000,
            Some("0x00003001"),
            Some(BOSMINER_LEGACY_S17_REG28_VALUE)
        )
        .is_err());
        assert!(!s19k_track1_retry_115200_from_env(None).unwrap());
        assert!(s19k_track1_retry_115200_from_env(Some("1")).unwrap());
        assert!(s19k_track1_retry_115200_from_env(Some("true")).is_err());
        assert_eq!(s19k_track1_retry_restore_baud(), 3_000_000);
        assert!(refuse_115200_retry_without_restore(&s19k_track1_115200_retry_steps()).is_ok());
        assert_eq!(
            s19k_track1_115200_retry_steps()[2],
            S19kTrack1115200RetryStep::FastUart28IfGetAddressSilent
        );
        assert!(s19k_track1_should_probe_fastuart_28_at_115200(
            S19kRxDiag::GetAddressSilenceAt115200
        ));
        assert!(!s19k_track1_should_probe_fastuart_28_at_115200(
            S19kRxDiag::ChipHeardAt115200
        ));
        assert!(!s19k_track1_should_probe_fastuart_28_at_115200(
            S19kRxDiag::ChipAddressOk
        ));
        assert!(refuse_115200_retry_without_restore(&[
            S19kTrack1115200RetryStep::SetHost115200,
            S19kTrack1115200RetryStep::GetAddress
        ])
        .is_err());
        assert!(s19k_track1_should_retry_115200(
            S19kRxDiag::AsicResetOrUninit,
            S19kRxDiag::ChipFastUartUnread,
            3_000_000,
            Some("1")
        )
        .unwrap());
        assert!(!s19k_track1_should_retry_115200(
            S19kRxDiag::AsicResetOrUninit,
            S19kRxDiag::ChipFastUartUnread,
            3_000_000,
            None
        )
        .unwrap());
        assert!(!s19k_track1_should_retry_115200(
            S19kRxDiag::ChipAddressOk,
            S19kRxDiag::ChipFastUartUnread,
            3_000_000,
            Some("1")
        )
        .unwrap());
        assert!(s19k_track1_should_retry_115200(
            S19kRxDiag::AsicResetOrUninit,
            S19kRxDiag::ChipFastUartUnread,
            115_200,
            Some("1")
        )
        .is_err());
        assert!(
            refuse_chip_heard_at_115200_as_3m_work_proof(S19kRxDiag::ChipHeardAt115200).is_err()
        );
        assert!(refuse_chip_heard_at_115200_as_3m_work_proof(S19kRxDiag::ChipAddressOk).is_ok());
        const SERIAL: &str = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_115200_retry_is_gated(SERIAL).is_ok());
        assert!(admit_s19k_production_115200_retry_drop_restores(SERIAL).is_ok());
        assert!(admit_s19k_production_restore_retries_then_refuses(SERIAL).is_ok());
        assert_eq!(
            s19k_track1_restore_baud_attempt(true, false),
            S19kTrack1RestoreBaudAttempt::FirstOk
        );
        assert_eq!(
            s19k_track1_restore_baud_attempt(false, true),
            S19kTrack1RestoreBaudAttempt::RetryOk
        );
        assert_eq!(
            s19k_track1_restore_baud_attempt(false, false),
            S19kTrack1RestoreBaudAttempt::FailedAfterRetry
        );
        assert!(
            refuse_restore_failed_as_3m_work_proof(S19kTrack1RestoreBaudAttempt::FirstOk).is_ok()
        );
        assert!(
            refuse_restore_failed_as_3m_work_proof(S19kTrack1RestoreBaudAttempt::RetryOk).is_ok()
        );
        assert!(refuse_restore_failed_as_3m_work_proof(
            S19kTrack1RestoreBaudAttempt::FailedAfterRetry
        )
        .is_err());
        assert!(refuse_work_tx_if_host_not_3m_after_restore(3_000_000).is_ok());
        assert!(refuse_work_tx_if_host_not_3m_after_restore(115_200).is_err());
        assert!(refuse_work_tx_if_host_not_3m_after_restore(1_000_000).is_err());
        let mut guard = S19kTrack1BaudRestoreGuard::arm_after_115200();
        assert!(guard.restore_owed());
        assert_eq!(guard.take_restore(), Some(3_000_000));
        assert!(!guard.restore_owed());
        assert_eq!(guard.take_restore(), None);
        {
            let g = S19kTrack1BaudRestoreGuard::arm_after_115200();
            assert!(g.restore_owed());
        }
        assert_eq!(s19k_track1_baud_restore_on_drop(true), Some(3_000_000));
        assert_eq!(s19k_track1_baud_restore_on_drop(false), None);
        assert_eq!(
            s19k_track1_chip_fastuart_from_env(Some("0x00003001")),
            Some(0x0000_3001)
        );
        assert_eq!(s19k_track1_chip_fastuart_from_env(None), None);
        assert!(classify_s19k_uart_baud_dialect(3_000_000, Some(PUBLIC_FASTUART_VALUE)).is_err());
        assert!(classify_s19k_uart_baud_dialect(115_200, Some(PUBLIC_FASTUART_VALUE)).is_err());
        assert!(refuse_bm1366_3001_as_s19k_braiins_3m.is_err());
        assert!(refuse_bm1366_3001_as_s19k_braiins_3m(0).is_ok());
        assert!(refuse_bm1362_3011_as_s19k_braiins_3m.is_err());
        assert!(refuse_bm1362_3011_as_s19k_braiins_3m(0).is_ok());
        assert!(refuse_bosminer_movz_3001_as_fastuart().is_err());
        assert!(refuse_bosminer_ticket_mask_future_as_fastuart().is_err());
        assert!(refuse_bosminer_tuner_write_reg_display_as_uart().is_err());
        assert!(refuse_bosminer_miscctrl_modify_as_fastuart_28().is_err());
        assert!(
            classify_s19k_uart_baud_dialect(3_000_000, Some).is_err()
        );
        assert_eq!(
            classify_s19k_uart_baud_dialect(
                BOSMINER_BM1366_AML_HOST_BAUD,
                Some(BOSMINER_BM1366_FASTUART_3M125)
            )
            .unwrap(),
            S19kUartBaudDialect::BraiinsStockBm1366FastUart
        );
        assert!(classify_s19k_uart_baud_dialect(3_125_000, None).is_err());
        assert!(
            admit_s19k_bible_fastuart_3125k_with_host_baud.is_ok()
        );
        assert!(admit_s19k_bible_fastuart_3125k_with_host_baud(3_000_000).is_err());
        assert!(admit_s19k_bible_fastuart_3125k_with_host_baud(115_200).is_err());
        let fu3125 = s19k_native_fastuart_bible_3125k_write();
        assert_eq!(fu3125.reg, PUBLIC_FASTUART_REG);
        assert_eq!(fu3125.value, );
        let fu3125_uart = pack_experimental_init_write(fu3125);
        assert_eq!(
            &fu3125_uart[2..10],
            &[0x51, 0x09, 0x00, 0x28, 0x00, 0x00, 0x30, 0x01]
        );
        assert!(!p.iter().any(|s| s.name == "fastuart_bible_3125k"));
        let constructed_3011 = {
            let mut v = vec![0u8; BOSMINER_REG28_3011_FILE_OFF as usize + 6];
            v[BOSMINER_REG28_3011_FILE_OFF as usize..]
                .copy_from_slice(&[0x28, 0x00, 0x00, 0x00, 0x30, 0x11]);
            v
        };
        assert!(admit_bosminer_contains_reg28_fastuart_be(
            &constructed_3011,
            BOSMINER_REG28_3011_FILE_OFF,
            
        )
        .is_ok());
        let constructed_3001 = {
            let mut v = vec![0u8; BOSMINER_REG28_3001_FILE_OFF as usize + 6];
            v[BOSMINER_REG28_3001_FILE_OFF as usize..]
                .copy_from_slice(&[0x28, 0x00, 0x00, 0x00, 0x30, 0x01]);
            v
        };
        assert!(admit_bosminer_contains_reg28_fastuart_be(
            &constructed_3001,
            BOSMINER_REG28_3001_FILE_OFF,
            
        )
        .is_ok());
        assert!(admit_bosminer_contains_reg28_fastuart_be(
            &[0u8; 8],
            0,
            
        )
        .is_err());
        assert_eq!(BOSMINER_REG28_3011_VA, 0x017C_0A28);
        assert_eq!(BOSMINER_REG28_3001_VA, 0x0182_FA28);
        assert_eq!(BOSMINER_COMMAND_RS_READ_REGISTER_FN_VA, 0x008A_9044);
        assert_eq!(BOSMINER_UART_BE4_SEND_FN_VA, 0x008A_200C);
        assert_eq!(BOSMINER_MISCCTRL_MODIFY_FN_VA, 0x008B_40DC);
        assert_eq!(BOSMINER_TICKET_MASK_FUTURE_FN_VA, 0x0083_6934);
        assert_eq!(BOSMINER_ANTMINER_DRIVER_INIT_FUTURE_FN_VA, 0x0083_6E2C);
        assert_eq!(BOSMINER_BM1366_FACTORY_FN_VA, 0x008D_BDF4);
        assert_eq!(BOSMINER_BM1366_TRAIT_VTABLE_VA, 0x019C_7B00);
        assert_eq!(BOSMINER_BM1366_SET_BAUD_VTABLE_SLOT, 0x50);
        assert_eq!(BOSMINER_BM1366_SET_BAUD_BUILD_FN_VA, 0x008D_D3B8);
        assert_eq!(BOSMINER_FASTUART_BAUD_SELECTOR_FN_VA, 0x0091_B024);
        assert_eq!(BOSMINER_FASTUART_REG_PACK_FN_VA, 0x0084_ED8C);
        assert_eq!(
            bosminer_bm1366_fastuart_value(BOSMINER_BM1366_REQUESTED_FAST_BAUD).unwrap(),
            0x0000_3011
        );
        assert_eq!(
            bosminer_bm1366_fastuart_value(1_000_000).unwrap(),
            0x0002_3011
        );
        assert!(bosminer_bm1366_fastuart_value(3_000_000).is_err());
        assert_eq!(
            bosminer_bm1366_fastuart_uart(BOSMINER_BM1366_REQUESTED_FAST_BAUD).unwrap(),
            [0x55, 0xAA, 0x51, 0x09, 0x00, 0x28, 0x00, 0x00, 0x30, 0x11, 0x12]
        );
        assert_eq!(
            bosminer_bm1366_fastuart_uart(1_000_000).unwrap(),
            [0x55, 0xAA, 0x51, 0x09, 0x00, 0x28, 0x00, 0x02, 0x30, 0x11, 0x07]
        );
        assert!(
            admit_s19k_bosminer_stock_fastuart_with_host_baud(BOSMINER_BM1366_AML_HOST_BAUD)
                .is_ok()
        );
        assert!(admit_s19k_bosminer_stock_fastuart_with_host_baud(3_125_000).is_err());
        assert_eq!(BOSMINER_SETCFG_51_09_00_28_HITS, 0);
        assert_eq!(BOSMINER_UART_BE4_SEND_BL_HITS, 4);
        assert_eq!(BOSMINER_UART_BE4_SEND_BL_VA[0], 0x0083_6C3C);
        assert!(refuse_bosminer_file_setcfg_28_as_s19k_fastuart(0).is_err());
        assert!(refuse_uart_be4_send_callers_as_s19k_aml_fastuart().is_err());
        assert!(refuse_movz_imm28_as_fastuart_reg(1897).is_err());
        assert_eq!(BOSMINER_HOST_TERMIOS_CALLER_FN_VA, 0x008F_E748);
        assert_eq!(BOSMINER_HOST_TERMIOS_FN_VA, 0x00BB_E3D4);
        assert_eq!(BOSMINER_ANTMINER_AML_RS_VA, 0x0139_2558);
        assert_eq!(BOSMINER_MOVZ_X1_3001_VA_A, 0x010B_A39C);
        assert_eq!(BOSMINER_MOVZ_X1_3001_VA_B, 0x010C_49D8);
        assert!(refuse_bosminer_be4_send_as_s19k_set_config().is_err());
        assert!(refuse_bosminer_ascii_set_config_as_packer().is_err());
        assert_eq!(BOSMINER_PACKED_STRUCT_PACKING_RS_VA, 0x0131_BE45);
        assert_eq!(BOSMINER_WRITE_VERIFY_STR_FILE_OFF, 0x00F2_0197);
        assert_eq!(BOSMINER_WRITE_VERIFY_STR_VA, 0x0132_0197);
        let generic = s19k_generic_set_config_uart(0x10, 0x0000_115A);
        assert_eq!(&generic[..2], &[0x55, 0xAA]);
        assert_eq!(
            &generic[2..10],
            &[0x51, 0x09, 0x00, 0x10, 0x00, 0x00, 0x11, 0x5A]
        );
        assert_eq!(generic, s19k_hcn_set_config_uart());
        let constructed_wv = {
            let mut v = vec![0u8; BOSMINER_WRITE_VERIFY_STR_FILE_OFF as usize + 48];
            let n = b"values were not written correctly to register";
            v[BOSMINER_WRITE_VERIFY_STR_FILE_OFF as usize
                ..BOSMINER_WRITE_VERIFY_STR_FILE_OFF as usize + n.len()]
                .copy_from_slice(n);
            v
        };
        assert!(admit_bosminer_contains_write_verify_str(&constructed_wv).is_ok());
        assert!(admit_bosminer_contains_write_verify_str(&[0u8; 8]).is_err());
        assert_eq!(BOSMINER_PACKED_STRUCT_PACK_FN_VA, 0x008A_8D28);
        assert_eq!(BOSMINER_COMMAND_RS_WRITE_FN_VA, 0x008B_1B98);
        assert_eq!(BOSMINER_BM1398_READ_FN_VA, 0x008B_2B34);
        assert_eq!(BOSMINER_PACK_BL_HITS, 3);
        assert!(admit_bosminer_pack_bl_sites().is_ok());
        assert!(refuse_command_rs_write_as_s19k_aml_set_config().is_err());
        assert!(refuse_pack_fn_as_s19k_exclusive_set_config().is_err());
        assert!(refuse_write_loc_ptr_as_aml_vtable().is_err());
        assert_eq!(
            BOSMINER_BM1398_RS_LOC_STR.len(),
            BOSMINER_BM1398_RS_LOC_STR_LEN as usize
        );
        let mut loc = vec![0u8; BOSMINER_READ_LOC_PTR_FILE_OFF as usize + 24];
        let woff = BOSMINER_WRITE_LOC_PTR_FILE_OFF as usize;
        loc[woff..woff + 8].copy_from_slice(&BOSMINER_COMMAND_RS_WRITE_FN_VA.to_le_bytes());
        loc[woff + 8..woff + 16].copy_from_slice(&BOSMINER_BM1398_RS_LOC_STR_VA.to_le_bytes());
        loc[woff + 16..woff + 24]
            .copy_from_slice(&u64::from(BOSMINER_BM1398_RS_LOC_STR_LEN).to_le_bytes());
        let soff = BOSMINER_BM1398_RS_LOC_STR_FILE_OFF as usize;
        loc[soff..soff + BOSMINER_BM1398_RS_LOC_STR.len()]
            .copy_from_slice(BOSMINER_BM1398_RS_LOC_STR);
        let roff = BOSMINER_READ_LOC_PTR_FILE_OFF as usize;
        loc[roff..roff + 8].copy_from_slice(&BOSMINER_BM1398_READ_FN_VA.to_le_bytes());
        loc[roff + 8..roff + 16].copy_from_slice(&BOSMINER_BM1398_RS_LOC_STR_VA.to_le_bytes());
        assert!(admit_bosminer_write_loc_is_bm1398_rs(&loc).is_ok());
        assert!(admit_bosminer_read_loc_is_bm1398_rs(&loc).is_ok());
        loc[woff] ^= 1;
        assert!(admit_bosminer_write_loc_is_bm1398_rs(&loc).is_err());
        assert_eq!(
            BOSMINER_BM1366_RS_LOC_STR,
            crate::s19k_braiins_job::BOSMINER_BM1366_RS.as_bytes()
        );
        assert_eq!(
            BOSMINER_BM1366_LOC_FNS[0],
            BOSMINER_BM1366_FIRST_METHOD_FN_VA
        );
        assert_eq!(BOSMINER_BM1366_DISPATCH_BL_HITS, 48);
        assert_eq!(BOSMINER_BM1366_DISPATCH_BL_IN_LOC_CLUSTER, 31);
        assert!(refuse_bm1366_loc_fns_as_direct_pack_callers().is_err());
        assert!(refuse_bm1366_packed_dispatch_as_named_fastuart().is_err());
        let dfile = (BOSMINER_BM1366_PACKED_DISPATCH_FN_VA - 0x400_000) as usize;
        let pfile = (BOSMINER_PACK_LDRB_VA - 0x400_000) as usize;
        let moff = BOSMINER_BM1366_FIRST_METHOD_LOC_FILE_OFF as usize;
        let s66 = BOSMINER_BM1366_RS_LOC_STR_FILE_OFF as usize;
        let afile = (BOSMINER_DISPATCH_ARC_LIKE_FN_VA - 0x400_000) as usize;
        let vtable = BOSMINER_BM1366_FIRST_METHOD_VTABLE_FILE_OFF as usize;
        let need = (moff + 24)
            .max(vtable + 32)
            .max(dfile + 0x98)
            .max(pfile + 4)
            .max(afile + 4)
            .max(s66 + BOSMINER_BM1366_RS_LOC_STR.len());
        let mut loc66 = vec![0u8; need];
        loc66[moff..moff + 8].copy_from_slice(&BOSMINER_BM1366_RS_LOC_STR_VA.to_le_bytes());
        loc66[moff + 8..moff + 16]
            .copy_from_slice(&u64::from(BOSMINER_BM1366_RS_LOC_STR_LEN).to_le_bytes());
        let first_lc = u64::from(BOSMINER_BM1366_FIRST_METHOD_LOC_LINE)
            | (u64::from(BOSMINER_BM1366_FIRST_METHOD_LOC_COL) << 32);
        loc66[moff + 16..moff + 24].copy_from_slice(&first_lc.to_le_bytes());
        loc66[vtable + 24..vtable + 32]
            .copy_from_slice(&BOSMINER_BM1366_FIRST_METHOD_FN_VA.to_le_bytes());
        loc66[s66..s66 + BOSMINER_BM1366_RS_LOC_STR.len()]
            .copy_from_slice(BOSMINER_BM1366_RS_LOC_STR);
        loc66[dfile + 8..dfile + 12]
            .copy_from_slice(&BOSMINER_BM1366_PACKED_DISPATCH_LDRB_INSN.to_le_bytes());
        loc66[dfile + 0x10..dfile + 0x14]
            .copy_from_slice(&BOSMINER_BM1366_DISPATCH_CMP3_INSN.to_le_bytes());
        loc66[dfile + 0x14..dfile + 0x18]
            .copy_from_slice(&BOSMINER_BM1366_DISPATCH_BEQ3_INSN.to_le_bytes());
        loc66[dfile + 0x18..dfile + 0x1C]
            .copy_from_slice(&BOSMINER_BM1366_DISPATCH_CMP4_INSN.to_le_bytes());
        loc66[dfile + 0x20..dfile + 0x24]
            .copy_from_slice(&BOSMINER_BM1366_DISPATCH_LDP_INSN.to_le_bytes());
        loc66[dfile + 0x24..dfile + 0x28]
            .copy_from_slice(&BOSMINER_BM1366_DISPATCH_LDR_V0_INSN.to_le_bytes());
        loc66[dfile + 0x30..dfile + 0x34]
            .copy_from_slice(&BOSMINER_BM1366_PACKED_DISPATCH_BLR_INSN.to_le_bytes());
        loc66[dfile + 0x90..dfile + 0x94]
            .copy_from_slice(&BOSMINER_BM1366_DISPATCH_TAG3_SLOT_LDR_INSN.to_le_bytes());
        loc66[dfile + 0x94..dfile + 0x98]
            .copy_from_slice(&BOSMINER_BM1366_PACKED_DISPATCH_BLR_INSN.to_le_bytes());
        loc66[pfile..pfile + 4]
            .copy_from_slice(&BOSMINER_BM1366_PACKED_DISPATCH_LDRB_INSN.to_le_bytes());
        loc66[afile..afile + 4].copy_from_slice(&BOSMINER_DISPATCH_ARC_LIKE_CBZ_INSN.to_le_bytes());
        assert!(admit_bosminer_bm1366_first_method_loc(&loc66).is_ok());
        assert!(admit_bosminer_bm1366_packed_dispatch(&loc66).is_ok());
        assert!(admit_bosminer_dispatch_tag_3_or_4(&loc66).is_ok());
        assert!(admit_bosminer_blr_x8_is_fat_ptr_vtable0(&loc66).is_ok());
        assert!(admit_bosminer_tag3_blr_is_vtable_plus18(&loc66).is_ok());
        assert!(refuse_blr_x8_as_named_text_write_reg().is_err());
        assert!(refuse_dispatch_arc_like_as_uart_write(&loc66).is_err());
        assert_eq!(BOSMINER_BM1366_DISPATCH_FAT_PTR_OFF, 0x78);
        assert_eq!(BOSMINER_BM1366_DISPATCH_VTABLE_SLOT, 0x18);
        let voff = BOSMINER_FAT_PTR_VTABLE_FILE_OFF as usize;
        let need2 = need
            .max(voff + 32)
            .max(BOSMINER_PSU_PROTOCOL_RS_FILE_OFF as usize + BOSMINER_PSU_PROTOCOL_RS.len())
            .max((BOSMINER_FAT_PTR_VTABLE_METHOD_VA - 0x400_000) as usize + 0x1C)
            .max((BOSMINER_FAT_PTR_VTABLE_ADD_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_FAT_PTR_STP_VA - 0x400_000) as usize + 4);
        loc66.resize(need2, 0);
        loc66[voff..voff + 8].copy_from_slice(&BOSMINER_FAT_PTR_VTABLE_DROP.to_le_bytes());
        loc66[voff + 8..voff + 16].copy_from_slice(&BOSMINER_FAT_PTR_VTABLE_SIZE.to_le_bytes());
        loc66[voff + 16..voff + 24].copy_from_slice(&BOSMINER_FAT_PTR_VTABLE_ALIGN.to_le_bytes());
        loc66[voff + 24..voff + 32]
            .copy_from_slice(&BOSMINER_FAT_PTR_VTABLE_METHOD_VA.to_le_bytes());
        let psu = BOSMINER_PSU_PROTOCOL_RS_FILE_OFF as usize;
        loc66[psu..psu + BOSMINER_PSU_PROTOCOL_RS.len()].copy_from_slice(BOSMINER_PSU_PROTOCOL_RS);
        let mva = (BOSMINER_FAT_PTR_VTABLE_METHOD_VA - 0x400_000) as usize;
        loc66[mva..mva + 4].copy_from_slice(&BOSMINER_VTABLE_METHOD_MOV_INSN.to_le_bytes());
        loc66[mva + 0x18..mva + 0x1C]
            .copy_from_slice(&BOSMINER_VTABLE_METHOD_BR_INSN.to_le_bytes());
        let addf = (BOSMINER_FAT_PTR_VTABLE_ADD_VA - 0x400_000) as usize;
        loc66[addf..addf + 4].copy_from_slice(&BOSMINER_FAT_PTR_VTABLE_ADD_INSN.to_le_bytes());
        let stpf = (BOSMINER_FAT_PTR_STP_VA - 0x400_000) as usize;
        loc66[stpf..stpf + 4].copy_from_slice(&BOSMINER_FAT_PTR_STP_INSN.to_le_bytes());
        assert!(admit_bosminer_fat_ptr_vtable_layout(&loc66).is_ok());
        assert!(admit_bosminer_fat_ptr_vtable_loc_is_psu_protocol(&loc66).is_ok());
        assert!(admit_bosminer_fat_ptr_vtable_install(&loc66).is_ok());
        assert!(refuse_vtable_method_as_uart_write_reg(&loc66).is_err());
        let hstr = BOSMINER_HASHCHAIN_RS_LOC_STR_FILE_OFF as usize;
        let hloc = BOSMINER_HASHCHAIN_PLUS78_LOC_FILE_OFF as usize;
        let stp78 = (BOSMINER_HASHCHAIN_PLUS78_STP_VA - 0x400_000) as usize;
        let sib = (BOSMINER_HASHCHAIN_SIBLING_PACK_FN_VA - 0x400_000) as usize;
        let alt = (BOSMINER_HASHCHAIN_ALT_STP_VA - 0x400_000) as usize;
        let need3 = need2
            .max(hstr + BOSMINER_HASHCHAIN_RS_LOC_STR.len())
            .max(hloc + 32)
            .max(stp78 + 4)
            .max((BOSMINER_HASHCHAIN_PLUS78_INNER_LDR_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_HASHCHAIN_PLUS78_DEREF_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_HASHCHAIN_PLUS78_ADD158_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_HASHCHAIN_PLUS78_ADD10_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_HASHCHAIN_PACKED_X0_ADD_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_HASHCHAIN_DISPATCH_BL_VA - 0x400_000) as usize + 4)
            .max(sib + 0x38)
            .max(alt + 4);
        loc66.resize(need3, 0);
        loc66[hstr..hstr + BOSMINER_HASHCHAIN_RS_LOC_STR.len()]
            .copy_from_slice(BOSMINER_HASHCHAIN_RS_LOC_STR);
        loc66[hloc..hloc + 8].copy_from_slice(&BOSMINER_HASHCHAIN_PLUS78_FN_VA.to_le_bytes());
        loc66[hloc + 8..hloc + 16].copy_from_slice(&BOSMINER_HASHCHAIN_RS_LOC_STR_VA.to_le_bytes());
        loc66[hloc + 16..hloc + 24]
            .copy_from_slice(&u64::from(BOSMINER_HASHCHAIN_RS_LOC_STR_LEN).to_le_bytes());
        let line_col = u64::from(BOSMINER_HASHCHAIN_PLUS78_LOC_LINE)
            | (u64::from(BOSMINER_HASHCHAIN_PLUS78_LOC_COL) << 32);
        loc66[hloc + 24..hloc + 32].copy_from_slice(&line_col.to_le_bytes());
        let put_insn = |buf: &mut [u8], va: u64, insn: u32| {
            let o = (va - 0x400_000) as usize;
            buf[o..o + 4].copy_from_slice(&insn.to_le_bytes());
        };
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_PLUS78_INNER_LDR_VA,
            BOSMINER_HASHCHAIN_PLUS78_INNER_LDR_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_PLUS78_DEREF_VA,
            BOSMINER_HASHCHAIN_PLUS78_DEREF_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_PLUS78_ADD158_VA,
            BOSMINER_HASHCHAIN_PLUS78_ADD158_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_PLUS78_ADD10_VA,
            BOSMINER_HASHCHAIN_PLUS78_ADD10_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_PLUS78_STP_VA,
            BOSMINER_HASHCHAIN_PLUS78_STP_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_PACKED_X0_ADD_VA,
            BOSMINER_HASHCHAIN_PACKED_X0_ADD_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_SIBLING_PACK_BL_VA[1],
            BOSMINER_HASHCHAIN_SIBLING_PACK_BL_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_DISPATCH_BL_VA,
            BOSMINER_HASHCHAIN_DISPATCH_BL_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_SIBLING_PACK_MOV_X19_VA,
            BOSMINER_HASHCHAIN_SIBLING_PACK_MOV_X19_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_SIBLING_PACK_LDRB_VA,
            BOSMINER_BM1366_PACKED_DISPATCH_LDRB_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_SIBLING_PACK_CMP2_VA,
            BOSMINER_HASHCHAIN_SIBLING_PACK_CMP2_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_SIBLING_PACK_CMP3_VA,
            BOSMINER_BM1366_DISPATCH_CMP3_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_SIBLING_PACK_LDP10_VA,
            BOSMINER_HASHCHAIN_SIBLING_PACK_LDP10_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_ALT_STP_VA,
            BOSMINER_HASHCHAIN_ALT_STP_INSN,
        );
        assert!(admit_bosminer_plus78_fn_loc_is_hashchain_rs(&loc66).is_ok());
        assert!(admit_bosminer_hashchain_plus78_operands(&loc66).is_ok());
        assert!(admit_bosminer_sibling_pack_tag_dispatch(&loc66).is_ok());
        assert!(admit_bosminer_hashchain_plus78_calls_sibling_then_dispatch(&loc66).is_ok());
        assert!(admit_bosminer_hashchain_alt_fat_ptr_pattern(&loc66).is_ok());
        assert!(refuse_hashchain_plus78_as_psu_rodata_vtable().is_err());
        assert!(refuse_hashchain_plus78_second_as_text_fastuart().is_err());
        assert_eq!(BOSMINER_HASHCHAIN_PLUS78_INLINE_OFF, 0x158);
        assert_eq!(BOSMINER_HASHCHAIN_PACKED_OBJ_OFF, 0x68);
        let fu_str = BOSMINER_LEGACY_FASTUART_FAIL_STR_FILE_OFF as usize;
        let fu_rs = BOSMINER_BM139X_RS_LOC_STR_FILE_OFF as usize;
        let fu_loc = BOSMINER_BM139X_FASTUART_LOC_FILE_OFF as usize;
        let need4 = need3
            .max(fu_str + BOSMINER_LEGACY_FASTUART_FAIL_STR.len())
            .max(fu_rs + BOSMINER_BM139X_RS_LOC_STR.len())
            .max(fu_loc + 24)
            .max((BOSMINER_LEGACY_FASTUART_PANIC_ADD_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_LEGACY_FASTUART_PACK_RET_VA - 0x400_000) as usize + 4);
        loc66.resize(need4, 0);
        loc66[fu_str..fu_str + BOSMINER_LEGACY_FASTUART_FAIL_STR.len()]
            .copy_from_slice(BOSMINER_LEGACY_FASTUART_FAIL_STR);
        loc66[fu_rs..fu_rs + BOSMINER_BM139X_RS_LOC_STR.len()]
            .copy_from_slice(BOSMINER_BM139X_RS_LOC_STR);
        loc66[fu_loc..fu_loc + 8].copy_from_slice(&BOSMINER_BM139X_RS_LOC_STR_VA.to_le_bytes());
        loc66[fu_loc + 8..fu_loc + 16]
            .copy_from_slice(&u64::from(BOSMINER_BM139X_RS_LOC_STR_LEN).to_le_bytes());
        let fu_lc = u64::from(BOSMINER_BM139X_FASTUART_LOC_LINE)
            | (u64::from(BOSMINER_BM139X_FASTUART_LOC_COL) << 32);
        loc66[fu_loc + 16..fu_loc + 24].copy_from_slice(&fu_lc.to_le_bytes());
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_PANIC_ADD_VA,
            BOSMINER_LEGACY_FASTUART_PANIC_ADD_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_PACK_BEQ_VA,
            BOSMINER_LEGACY_FASTUART_PACK_BEQ_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_PACK_RET_VA,
            BOSMINER_LEGACY_FASTUART_PACK_RET_INSN,
        );
        assert!(admit_bosminer_legacy_fastuart_fail_str(&loc66).is_ok());
        assert!(admit_bosminer_legacy_fastuart_loc_is_bm139x_rs(&loc66).is_ok());
        assert!(admit_bosminer_legacy_fastuart_panic_former(&loc66).is_ok());
        assert!(admit_bosminer_legacy_fastuart_pack_beq_panic(&loc66).is_ok());
        assert!(refuse_legacy_fastuart_panic_as_uart_write().is_err());
        assert!(refuse_legacy_fastuart_as_s19k_host_3m().is_err());
        let need5 = need4
            .max((BOSMINER_LEGACY_FASTUART_DIV_UDIV_RET_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_LEGACY_FASTUART_FIELDS_BL_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_LEGACY_FASTUART_STRB_D_VA - 0x400_000) as usize + 4);
        loc66.resize(need5, 0);
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_DIV_FN_VA + 4,
            BOSMINER_LEGACY_FASTUART_DIV_LDRB7_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_DIV_LSR24_VA,
            BOSMINER_LEGACY_FASTUART_DIV_LSR24_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_DIV_CMP255_VA,
            BOSMINER_LEGACY_FASTUART_DIV_CMP255_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_DIV_UDIV_RET_VA,
            BOSMINER_LEGACY_FASTUART_DIV_UDIV_RET_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_FIELDS_FN_VA,
            BOSMINER_LEGACY_FASTUART_FIELDS_UBFX_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_FIELDS_CMP1_VA,
            BOSMINER_LEGACY_FASTUART_FIELDS_CMP1_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_STRH0_VA,
            BOSMINER_LEGACY_FASTUART_STRH0_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_STRB_C_VA,
            BOSMINER_LEGACY_FASTUART_STRB_C_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_STRB_D_VA,
            BOSMINER_LEGACY_FASTUART_STRB_D_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_FIELDS_BL_VA,
            BOSMINER_LEGACY_FASTUART_FIELDS_BL_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0_VA,
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0_INSN,
        );
        assert!(admit_bosminer_legacy_fastuart_divisor_path(&loc66).is_ok());
        assert!(admit_bosminer_legacy_fastuart_fields_layout(&loc66).is_ok());
        assert!(admit_bosminer_legacy_fastuart_fields_caller(&loc66).is_ok());
        assert!(refuse_reg28_3001_as_legacy_fastuart_pack().is_err());
        assert!(refuse_legacy_fastuart_divisor_as_3001().is_err());
        assert!(refuse_bm1398_pack_call_as_bible_3001().is_err());
        assert_ne!(
            BOSMINER_LEGACY_FASTUART_PACKED_LEN,
            BOSMINER_REG28_FASTUART_DATA_LEN
        );
        assert_ne!(
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0,
            
        );
        assert_ne!(
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0,
            
        );
        assert_eq!(
            BOSMINER_LEGACY_FASTUART_DIV_FN_VA,
            BOSMINER_LEGACY_FASTUART_PACK_FN_VA
        );
        let fptr = BOSMINER_LEGACY_FASTUART_DIV_FPTR_FILE_OFF as usize;
        let need6 = need5
            .max(fptr + 16)
            .max((BOSMINER_HASHCHAIN_DUP88_STP_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_HASHCHAIN_BLR78_STP_VA - 0x400_000) as usize + 4);
        loc66.resize(need6, 0);
        loc66[fptr..fptr + 8].copy_from_slice(&BOSMINER_LEGACY_FASTUART_DIV_FN_VA.to_le_bytes());
        loc66[fptr - 8..fptr]
            .copy_from_slice(&BOSMINER_LEGACY_FASTUART_DIV_FPTR_PREV.to_le_bytes());
        loc66[fptr + 8..fptr + 16]
            .copy_from_slice(&BOSMINER_LEGACY_FASTUART_DIV_FPTR_NEXT.to_le_bytes());
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_DUP78_LDP_VA,
            BOSMINER_HASHCHAIN_DUP78_LDP_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_DUP78_STP_VA,
            BOSMINER_HASHCHAIN_DUP78_STP_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_DUP88_STP_VA,
            BOSMINER_HASHCHAIN_DUP88_STP_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_BLR78_STP_VA,
            BOSMINER_HASHCHAIN_BLR78_STP_INSN,
        );
        assert!(admit_bosminer_legacy_fastuart_div_fptr(&loc66).is_ok());
        assert!(refuse_div_fptr_neighbors_as_uart_write().is_err());
        assert!(admit_bosminer_hashchain_dup78_88_copy(&loc66).is_ok());
        assert!(refuse_hashchain_dup88_as_engine_nonce_fn().is_err());
        assert!(admit_bosminer_hashchain_blr78_consume(&loc66).is_ok());
        let mut need7 = need6;
        for &va in &BOSMINER_HASHCHAIN_BLR78_FAMILY_VA {
            need7 = need7.max((va - 0x400_000) as usize + 4);
        }
        loc66.resize(need7, 0);
        for &va in &BOSMINER_HASHCHAIN_BLR78_FAMILY_VA {
            put_insn(&mut loc66, va - 8, BOSMINER_HASHCHAIN_BLR78_MOV_INSN);
            put_insn(&mut loc66, va - 4, BOSMINER_HASHCHAIN_BLR78_BLR_INSN);
            put_insn(&mut loc66, va, BOSMINER_HASHCHAIN_BLR78_STP_INSN);
        }
        assert!(admit_bosminer_hashchain_blr78_family(&loc66).is_ok());
        assert!(refuse_blr78_family_as_engine_plus88().is_err());
        assert_eq!(BOSMINER_HASHCHAIN_BLR78_FAMILY_HITS, 7);
        assert_eq!(
            crate::s19k_braiins_job::BOSMINER_HASHCHAIN_STR88_SELF_PTR_HITS,
            5
        );
        let need8 = need7
            .max((BOSMINER_LEGACY_FASTUART_STRB_5_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_LEGACY_FASTUART_W1_LDR8_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_NESTED88_STR_VA[1] - 0x400_000) as usize + 4)
            .max(
                BOSMINER_FASTUART_FIELDS_STR_FILE_OFF as usize
                    + BOSMINER_FASTUART_NAMED_BIT_BLOB.len(),
            );
        loc66.resize(need8, 0);
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_W13_UBFIZ_VA,
            BOSMINER_LEGACY_FASTUART_W13_UBFIZ_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_W13_BFXIL_VA,
            BOSMINER_LEGACY_FASTUART_W13_BFXIL_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_STRB_5_VA,
            BOSMINER_LEGACY_FASTUART_STRB_5_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2_VA,
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3_VA,
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_W1_LDR8_VA,
            BOSMINER_LEGACY_FASTUART_W1_LDR8_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_W1_LDRB_VA,
            BOSMINER_LEGACY_FASTUART_W1_LDRB_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_W1_SUB1_VA,
            BOSMINER_LEGACY_FASTUART_W1_SUB1_INSN,
        );
        for i in 0..BOSMINER_NESTED88_HITS {
            put_insn(
                &mut loc66,
                BOSMINER_NESTED88_LDR30_VA[i],
                BOSMINER_NESTED88_LDR30_INSN,
            );
            put_insn(
                &mut loc66,
                BOSMINER_NESTED88_ADD18_VA[i],
                BOSMINER_NESTED88_ADD18_INSN[i],
            );
            put_insn(
                &mut loc66,
                BOSMINER_NESTED88_STR_VA[i],
                BOSMINER_NESTED88_STR_INSN[i],
            );
        }
        let fname = BOSMINER_FASTUART_FIELDS_STR_FILE_OFF as usize;
        loc66[fname..fname + BOSMINER_FASTUART_NAMED_BIT_BLOB.len()]
            .copy_from_slice(BOSMINER_FASTUART_NAMED_BIT_BLOB);
        assert!(admit_bosminer_legacy_fastuart_w13_map(&loc66).is_ok());
        assert!(admit_bosminer_legacy_fastuart_w1_ldrb_sub1(&loc66).is_ok());
        assert!(admit_bosminer_fastuart_field_name_blob(&loc66).is_ok());
        assert!(admit_bosminer_fastuart_named_bit_blob(&loc66).is_ok());
        assert!(admit_bosminer_nested88_plus18_family(&loc66).is_ok());
        assert!(refuse_legacy_fastuart_dest5_as_bible_3001().is_err());
        assert!(refuse_fastuart_field_names_as_dest_byte_map().is_err());
        assert!(refuse_nested88_plus18_as_engine_nonce_fn().is_err());
        assert!(bosminer_legacy_fastuart_enum_ok(
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0
        ));
        assert!(!bosminer_legacy_fastuart_enum_ok(0b1000));
        assert_eq!(bosminer_legacy_fastuart_w13(6, 0), 0x20);
        assert_eq!(bosminer_legacy_fastuart_w13(6, 0x53), 0x25);
        let packed0 = pack_bosminer_legacy_fastuart_bm1398_write_instance(0);
        assert_eq!(packed0, [0x80, 0, 0, 0, 1, 0x20, 0, 0, 0, 0, 0, 0x0F, 0, 0]);
        assert_eq!(
            packed0[BOSMINER_LEGACY_FASTUART_DEST_W13_OFF],
            bosminer_legacy_fastuart_w13(6, 0)
        );
        assert_eq!(
            packed0[BOSMINER_LEGACY_FASTUART_DEST_W2_OFF],
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2 as u8
        );
        assert_eq!(
            packed0[BOSMINER_LEGACY_FASTUART_DEST_ENUM_OFF],
            bosminer_legacy_fastuart_enum_field(6)
        );
        assert_ne!(
            u32::from_be_bytes([packed0[0], packed0[1], packed0[2], packed0[3]]),
            
        );
        let packed53 = pack_bosminer_legacy_fastuart_bm1398_write_instance(0x53);
        assert_eq!(packed53[1], 1);
        assert_eq!(packed53[5], 0x25);
        assert_eq!(packed53[6], 0);
        assert_eq!(packed53[7], 1);
        assert_eq!(BOSMINER_NESTED88_HITS, 2);
        assert_eq!(BOSMINER_LEGACY_FASTUART_W1_LDRB_OFF, 0x22C);
        let named_3001 = decode_bosminer_fastuart_reg_named;
        assert!(!named_3001.ext_baud_enable);
        assert!(named_3001.unknown_bit_13);
        assert!(!named_3001.unknown_bit_15);
        assert_eq!(named_3001.unknown_bits_31_28, 0);
        let named_3011 = decode_bosminer_fastuart_reg_named;
        assert!(!named_3011.ext_baud_enable);
        assert!(named_3011.unknown_bit_13);
        assert!(refuse_bible_3001_as_ext_baud_enable.is_err());
        assert!(refuse_rfs_tfs_width_as_named().is_err());
        assert!(BOSMINER_FASTUART_NAMED_BIT_BLOB
            .windows(3)
            .any(|w| w == BOSMINER_FASTUART_RFS_STR));
        assert!(BOSMINER_FASTUART_NAMED_BIT_BLOB
            .windows(3)
            .any(|w| w == BOSMINER_FASTUART_TFS_STR));
        assert_eq!(BOSMINER_FASTUART_EXT_BAUD_ENABLE_BIT, 16);
        let need9 = need8
            .max((BOSMINER_FASTUART_22C_XTAL_MOVK_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_FASTUART_22C_SIBLING_LDRB_VA - 0x400_000) as usize + 4);
        loc66.resize(need9, 0);
        put_insn(
            &mut loc66,
            BOSMINER_FASTUART_22C_SIBLING_LDRB_VA,
            BOSMINER_FASTUART_22C_SIBLING_LDRB_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_FASTUART_22C_XTAL_MOVZ_VA,
            BOSMINER_FASTUART_22C_XTAL_MOVZ_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_FASTUART_22C_XTAL_MOVK_VA,
            BOSMINER_FASTUART_22C_XTAL_MOVK_INSN,
        );
        assert!(admit_bosminer_fastuart_22c_xtal25(&loc66).is_ok());
        assert!(refuse_xtal25_div8_as_s19k_host_3m().is_err());
        assert!(refuse_plus22c_as_engine_nonce_fn().is_err());
        assert_eq!(
            bosminer_xtal25_divisor_baud(BOSMINER_FASTUART_22C_),
            Some
        );
        assert_ne!(
            bosminer_xtal25_divisor_baud(BOSMINER_FASTUART_22C_).unwrap(),
            3_000_000
        );
        assert_eq!(
            bosminer_xtal25_divisor_baud(25),
            Some(ESP_FASTUART_HOST_BAUD)
        );
        assert_eq!(bosminer_fastuart_w1_to_div_byte(7), Some(8));
        assert_eq!(BOSMINER_FASTUART_22C_LDRB_HITS, 12);
        assert_eq!(BOSMINER_FASTUART_22C_XTAL_HZ, 25_000_000);
        let mut need10 = need9
            .max(BOSMINER_ANTMINER_AML_RS_FILE_OFF as usize + BOSMINER_ANTMINER_AML_RS.len())
            .max(BOSMINER_NIX_TERMIOS_RS_FILE_OFF as usize + BOSMINER_NIX_TERMIOS_RS.len());
        for &va in BOSMINER_HOST_3M_MOVZ_VA
            .iter()
            .chain(BOSMINER_B3000000_MOVZ_VA.iter())
        {
            need10 = need10.max((va - 0x400_000) as usize + 4);
        }
        loc66.resize(need10, 0);
        for i in 0..BOSMINER_HOST_3M_MOVZ_HITS {
            put_insn(
                &mut loc66,
                BOSMINER_HOST_3M_MOVZ_VA[i],
                BOSMINER_HOST_3M_MOVZ_INSN[i],
            );
        }
        put_insn(
            &mut loc66,
            BOSMINER_HOST_3M_TERMIOS_MOVK_VA,
            BOSMINER_HOST_3M_TERMIOS_MOVK_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_AML_OPEN_3M_MOVK_VA,
            BOSMINER_AML_OPEN_3M_MOVK_INSN,
        );
        for i in 0..BOSMINER_B3000000_MOVZ_HITS {
            put_insn(
                &mut loc66,
                BOSMINER_B3000000_MOVZ_VA[i],
                BOSMINER_B3000000_MOVZ_INSN[i],
            );
        }
        let aml = BOSMINER_ANTMINER_AML_RS_FILE_OFF as usize;
        loc66[aml..aml + BOSMINER_ANTMINER_AML_RS.len()].copy_from_slice(BOSMINER_ANTMINER_AML_RS);
        let nix = BOSMINER_NIX_TERMIOS_RS_FILE_OFF as usize;
        loc66[nix..nix + BOSMINER_NIX_TERMIOS_RS.len()].copy_from_slice(BOSMINER_NIX_TERMIOS_RS);
        assert!(admit_bosminer_host_3m_movz_sites(&loc66).is_ok());
        assert!(admit_bosminer_host_3m_termios_b3000000(&loc66).is_ok());
        assert!(admit_bosminer_aml_open_host_3m(&loc66).is_ok());
        assert!(admit_bosminer_nix_termios_rs(&loc66).is_ok());
        assert!(refuse_host_3m_termios_as_chip_fastuart_28().is_err());
        assert!(refuse_legacy_pack_and_xtal25_as_host_3m_writer().is_err());
        assert_eq!(linux_b3000000_speed_t(), 0x100D);
        assert_eq!(BOSMINER_HOST_3M_BAUD, 3_000_000);
        assert_eq!(BOSMINER_HOST_3M_MOVZ_HITS, 4);
        assert_eq!(BOSMINER_B3000000_MOVZ_HITS, 3);
        assert_eq!(BOSMINER_HOST_3M_MOVZ_VA[2], 0x00BC_1F94);
        assert_eq!(BOSMINER_SETCFG_51_09_00_28_HITS, 0);
        let bm1397_loc = BOSMINER_BM1397_REG28_LOC_FILE_OFF as usize;
        let bm1396_loc = BOSMINER_BM1396_REG28_LOC_FILE_OFF as usize;
        let need11 = need10
            .max(bm1397_loc + 24)
            .max((BOSMINER_BM1397_REG28_VTABLE_FILE_OFF + 32) as usize)
            .max(bm1396_loc + 24)
            .max((BOSMINER_BM1396_REG28_VTABLE_FILE_OFF + 32) as usize)
            .max((BOSMINER_LEGACY_REG28_PACK_REV_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_BM1396_REG28_BL_VA - 0x400_000) as usize + 4);
        loc66.resize(need11, 0);
        loc66[bm1397_loc..bm1397_loc + 8].copy_from_slice(&0x0132_34D2u64.to_le_bytes());
        loc66[bm1397_loc + 8..bm1397_loc + 16].copy_from_slice(&54u64.to_le_bytes());
        let bm1397_lc = u64::from(BOSMINER_BM1397_REG28_LOC_LINE)
            | (u64::from(BOSMINER_BM1397_REG28_LOC_COL) << 32);
        loc66[bm1397_loc + 16..bm1397_loc + 24].copy_from_slice(&bm1397_lc.to_le_bytes());
        let bm1397_poll = (BOSMINER_BM1397_REG28_VTABLE_FILE_OFF + 24) as usize;
        loc66[bm1397_poll..bm1397_poll + 8]
            .copy_from_slice(&BOSMINER_BM1397_REG28_POLL_VA.to_le_bytes());
        loc66[bm1396_loc..bm1396_loc + 8].copy_from_slice(&0x0131_C3B8u64.to_le_bytes());
        loc66[bm1396_loc + 8..bm1396_loc + 16].copy_from_slice(&54u64.to_le_bytes());
        let bm1396_lc = u64::from(BOSMINER_BM1396_REG28_LOC_LINE)
            | (u64::from(BOSMINER_BM1396_REG28_LOC_COL) << 32);
        loc66[bm1396_loc + 16..bm1396_loc + 24].copy_from_slice(&bm1396_lc.to_le_bytes());
        let bm1396_poll = (BOSMINER_BM1396_REG28_VTABLE_FILE_OFF + 24) as usize;
        loc66[bm1396_poll..bm1396_poll + 8]
            .copy_from_slice(&BOSMINER_BM1396_REG28_POLL_VA.to_le_bytes());
        put_insn(
            &mut loc66,
            BOSMINER_BM1397_REG28_MOVZ_VA,
            BOSMINER_BM1397_REG28_MOVZ_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_BM1397_REG28_VAL_MOVZ_VA,
            BOSMINER_BM1397_REG28_VAL_MOVZ_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_BM1397_REG28_VAL_MOVK_VA,
            BOSMINER_BM1397_REG28_VAL_MOVK_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_BM1397_REG28_BL_VA,
            BOSMINER_BM1397_REG28_BL_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_REG28_PACK_REV_VA,
            BOSMINER_LEGACY_REG28_PACK_REV_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_BM1396_REG28_VAL_MOVZ_VA,
            BOSMINER_BM1396_REG28_VAL_MOVZ_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_BM1396_REG28_MOVZ_VA,
            BOSMINER_BM1396_REG28_MOVZ_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_BM1396_REG28_VAL_MOVK_VA,
            BOSMINER_BM1396_REG28_VAL_MOVK_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_BM1396_REG28_BL_VA,
            BOSMINER_BM1396_REG28_BL_INSN,
        );
        assert!(admit_bosminer_bm1397_reg28_0600000f(&loc66).is_ok());
        assert!(admit_bosminer_bm1396_reg28_0600000f(&loc66).is_ok());
        assert!(refuse_legacy_s17_reg28_0600000f_as_bm1366().is_err());
        assert_eq!(BOSMINER_LEGACY_S17_REG28_VALUE, 0x0F | (0x600 << 16));
        assert_ne!(BOSMINER_LEGACY_S17_REG28_VALUE, );
        assert_ne!(BOSMINER_LEGACY_S17_REG28_VALUE, );
        assert_ne!(BOSMINER_LEGACY_S17_REG28_VALUE, PUBLIC_FASTUART_VALUE);
        let u28 = pack_legacy_s17_reg28_uart();
        assert_eq!(&u28[..2], &[0x55, 0xAA]);
        assert_eq!(
            &u28[2..10],
            &[0x51, 0x09, 0x00, 0x28, 0x06, 0x00, 0x00, 0x0F]
        );
        assert_eq!(u28, s19k_generic_set_config_uart(0x28, 0x0600_000F));
        assert_eq!(BOSMINER_LEGACY_REG28_PACK_CALL_HITS, 2);
        assert!(!BOSMINER_BM1366_LOC_FNS.contains(&BOSMINER_BM1397_REG28_POLL_VA));
        assert!(!BOSMINER_BM1366_LOC_FNS.contains(&BOSMINER_BM1396_REG28_POLL_VA));
        assert_eq!(BOSMINER_AML_PACKING_RS_VA, 0x0131_E7BC);
        assert_eq!(BOSMINER_ANTMINER_AML_OPEN_FN_VA, 0x00BC_1F28);
        assert_eq!(BOSMINER_AML_SERIAL_SESSION_FN_VA, 0x008F_8018);
        assert!(refuse_bosminer_aml_open_as_set_config().is_err());
        assert!(admit_init_dialect_baud(S19kInitDialect::NativeExperimental, 115_200).is_ok());
        assert_eq!(BOSMINER_HAL_COMMAND_RS_VA, 0x0130_3F89);
        assert_eq!(BOSMINER_SET_BAUD_RATE_STR_VA, 0x0131_B8D5);
        assert_eq!(BOSMINER_FASTUART_FIELDS_STR_VA, 0x0132_0C4B);
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        let bm1366_init = serial
            .split("fn init_bm1366_chain(")
            .nth(1)
            .and_then(|s| s.split("fn init_bm1370_chain(").next())
            .expect("init_bm1366_chain");
        assert!(
            bm1366_init.contains("native_program.final_commands"),
            "shipped native init must consume the typed terminal PLL/HCN phase"
        );
        assert!(bm1366_init.contains("native_program.fast_uart_command"));
        assert!(bm1366_init.contains("set_baud(native_program.fast_host_baud)"));
        assert!(bm1366_init.contains("Bm1366NativePostBaudAdmission::from_response_window"));
        assert!(bm1366_init
            .contains("BM1366 final CRC-valid geometry matched the fresh switched-baud admission"));
        assert!(
            !bm1366_init.contains("PUBLIC_FASTUART_VALUE"),
            "BM1366 native transition must not emit the ESP 1M FastUART word"
        );
        let summary = format_s19k_native_init_summary(&p);
        assert!(summary.contains("set_address=77"));
        assert!(summary.contains("a8_unicast=77"));
        assert!(summary.contains("owner_required=true"));
        assert!(summary.contains("authority_minted=false"));

        let execution =
            s19k_bm1366_native_execution_program(77, 670).expect("exact S19k execution program");
        assert_eq!(execution.expected_chip_count, 77);
        assert_eq!(execution.address_interval, 2);
        assert_eq!(execution.initial_host_baud, 115_200);
        assert_eq!(
            execution.requested_fast_baud,
            BOSMINER_BM1366_REQUESTED_FAST_BAUD
        );
        assert_eq!(execution.fast_host_baud, BOSMINER_BM1366_AML_HOST_BAUD);
        assert_eq!(execution.pre_baud_commands.len(), 86);
        assert_eq!(execution.post_baud_commands.len(), 77 * 5);
        assert_eq!(execution.final_commands.len(), 2);
        assert_eq!(execution.post_host_baud_settle_ms, 50);
        assert_eq!(execution.post_baud_tail_settle_ms, 50);
        assert_eq!(execution.fast_uart_command.name, "fastuart_stock_3m125");
        assert_eq!(execution.fast_uart_command.dwell_after_ms, 10);
        assert!(matches!(
            execution.fast_uart_command.op,
            S19kBm1366NativeCommandOp::WriteRegister(S19kExperimentalInitWrite {
                reg: BOSMINER_BM1366_FASTUART_REG,
                value: BOSMINER_BM1366_FASTUART_3M125,
                bcast: true,
                ..
            })
        ));
        let set_addresses = execution
            .pre_baud_commands
            .iter()
            .filter_map(|command| match command.op {
                S19kBm1366NativeCommandOp::SetAddress { address } => Some(address),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(set_addresses.len(), 77);
        assert_eq!(set_addresses[0], 0);
        assert_eq!(set_addresses[1], 2);
        assert_eq!(set_addresses[76], 152);
        assert_eq!(
            execution
                .pre_baud_commands
                .iter()
                .find(|command| command.name == "set_address" && command.dwell_after_ms == 10)
                .and_then(|command| match command.op {
                    S19kBm1366NativeCommandOp::SetAddress { address } => Some(address),
                    _ => None,
                }),
            Some(152)
        );
        let (expected_pll, expected_actual) = bm1366_pll_reg_and_actual(670);
        assert_eq!(execution.actual_frequency_mhz, expected_actual);
        assert!(matches!(
            execution.final_commands[0].op,
            S19kBm1366NativeCommandOp::WriteRegister(S19kExperimentalInitWrite {
                name: "pll0_target",
                reg: REG_PLL0,
                value,
                ..
            }) if value == expected_pll
        ));
        assert!(matches!(
            execution.final_commands[1].op,
            S19kBm1366NativeCommandOp::WriteRegister(S19kExperimentalInitWrite {
                reg: INIT_REG_HASH_COUNTING,
                value: S19K_WIRE_HASH_COUNTING,
                ..
            })
        ));
        assert!(s19k_bm1366_native_execution_program(76, 670).is_err());
        assert!(s19k_bm1366_native_execution_program(77, 50).is_err());

        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(
            serial.contains("s19k_bm1366_native_execution_program"),
            "serial_mining native init must consume the typed execution program"
        );
        assert!(serial.contains("native_program.pre_baud_commands"));
        assert!(serial.contains("native_program.fast_uart_command"));
        assert!(serial.contains("native_program.post_baud_commands"));
        assert!(serial.contains("native_program.final_commands"));
        assert!(!serial.contains("const BM1366_REG_A8_PER_CHIP"));
        assert!(!serial.contains("const BM1366_HASH_COUNTING_S19K"));
        assert!(!serial.contains("const BM1366_MISC_CTRL_PER_CHIP"));
        let constructed = {
            let mut v = vec![0u8; BOSMINER_115A_BE_FILE_OFF as usize + 4];
            v[BOSMINER_115A_BE_FILE_OFF as usize..].copy_from_slice(&[0x00, 0x00, 0x11, 0x5A]);
            v
        };
        assert!(admit_bosminer_contains_s19k_hcn_be(&constructed).is_ok());
        assert!(admit_bosminer_contains_s19k_hcn_be(&[0u8; 8]).is_err());
        assert!(refuse_bosminer_115a_file_pin_as_hcn_writer().is_err());
        assert!(refuse_bosminer_hcn_divider_log_as_reg10_writer().is_err());
        assert_eq!(BOSMINER_115A_BE_VA, 0x019A_20A6);
        assert_eq!(BOSMINER_115A_TUNER_XREF_VA, 0x0066_4C0C);
        assert_eq!(BOSMINER_HCN_DIVIDER_LOG_FN_VA, 0x0084_34E0);
        assert_eq!(BOSMINER_HCN_DIVIDER_LOG_XTAL_HZ, 12_500_000);
        assert!(refuse_bosminer_hash_counting_number_string_as_hcn_writer().is_err());
        assert!(refuse_bosminer_ticket_mask_serde_as_uart_writer().is_err());
        assert_eq!(BOSMINER_HASH_COUNTING_NUMBER_STR_VA, 0x0139_DB65);
        assert_eq!(BOSMINER_HASH_COUNTING_NUMBER_XREF_FN_VA, 0x0041_EA18);
        assert_eq!(BOSMINER_TICKET_MASK_SERDE_FN_VA, 0x0086_F5E0);
    }

    #[test]
    fn s19k_fastuart_28_stock_transition_is_exact_and_other_dialects_are_refused() {
        assert_eq!(ESP_BM1366_MISCCTRL_DEFAULT_BAUD_REG, 0x18);
        assert_eq!(ESP_BM1366_MISCCTRL_DEFAULT_BAUD_VALUE, 0x0000_7A31);
        assert_eq!(ESP_BM1366_MISCCTRL_DEFAULT_BAUD_DIV, 26);
        assert_eq!(esp_bm1366_miscctrl_formula_baud_hz(), 115_740);
        assert_ne!(
            esp_bm1366_miscctrl_formula_baud_hz(),
            ESP_BM1366_SET_DEFAULT_BAUD_RETURN_HZ
        );
        assert!(refuse_esp_miscctrl_default_baud_as_fastuart_28().is_err());
        assert!(refuse_esp_default_baud_return_as_formula_hz().is_err());
        assert!(admit_s19k_stock_fastuart_28_write_as_leave_115200(PUBLIC_FASTUART_VALUE).is_err());
        assert!(
            admit_s19k_stock_fastuart_28_write_as_leave_115200
                .is_err()
        );
        assert!(
            admit_s19k_stock_fastuart_28_write_as_leave_115200(BOSMINER_BM1366_FASTUART_3M125)
                .is_ok()
        );
        assert!(admit_s19k_stock_fastuart_28_write_as_leave_115200(
            BOSMINER_LEGACY_S17_REG28_VALUE
        )
        .is_err());
        assert!(admit_s19k_stock_fastuart_28_write_as_leave_115200(
            ESP_BM1366_MISCCTRL_DEFAULT_BAUD_VALUE
        )
        .is_err());
        assert!(admit_s19k_stock_fastuart_28_write_as_leave_115200(0).is_err());
        assert!(admit_s19k_stock_fastuart_28_write_as_leave_115200(0xDEAD_BEEF).is_err());
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_track1_reads_not_writes_fastuart_28(serial).is_ok());
        assert!(admit_s19k_production_track1_reads_not_writes_fastuart_28(
            "PASSTHROUGH BM1366\nsend_write_reg_broadcast_bm1397plus(0x28, 1)\n} else if passthrough"
        )
        .is_err());
        assert!(admit_s19k_production_track1_reads_not_writes_fastuart_28(
            "PASSTHROUGH BM1366\n} else if passthrough"
        )
        .is_err());
    }
}
