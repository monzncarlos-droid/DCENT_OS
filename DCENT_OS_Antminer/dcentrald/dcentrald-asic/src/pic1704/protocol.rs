//! PIC1704 protocol primitives — short-form I2C register access.
//!
//! This module is **host-safe**: it has no I2C bus dependency and is fully
//! unit-testable on Windows. It owns the PIC1704 register map, the version
//! classifier, and helpers that build ordered `I2cTransactionStep` sequences
//! for the service-thread to execute on-target.
//!
//! ## Protocol summary (source: SOURCE_HAL/pic1704.{h,c} from dev-kit)
//!
//! - 7-bit I2C slave address: `0x20`.
//! - **Short-form register access**: every operation writes the register
//!   address byte first, then reads or writes payload. This is fundamentally
//!   different from the dsPIC framed protocol (`[55 AA LEN CMD ... SUM]`)
//!   used by `crate::dspic`. See the comparison block below.
//! - Bootloader→app jump: write `0x5A` to `REG_VERSION`, then `0x01` to
//!   `REG_CONTROL`. After the jump command, the PIC resets and re-enumerates
//!   as one of the application firmware revisions (`0x88`/`0x89`/`0x8A`).
//! - Heartbeat: write `0x02` to `REG_CONTROL` every 2 s (rate-limited).
//!
//! ## Why PIC1704 is NOT a dsPIC
//!
//! Despite the "PIC" name, this is a different chip family from
//! `dcentrald-asic::dspic` (dsPIC33EP16GS202, S17/S19) and from
//! `dcentrald-asic::pic` (PIC16F1704, S9). The 16-zero-byte parser flush
//! mandated by  is a **dsPIC-only**
//! rule — it exists because the dsPIC's MSSP-driven framed parser can be
//! left in a half-consumed state by a NACK. PIC1704 uses a stateless
//! short-form register protocol (`[reg_addr] [data]` per write,
//! `[reg_addr]` then `read N` per read), so a NACK loses only the in-flight
//! transaction, not future ones. Future readers: do NOT add a 16-zero
//! parser flush here — it would be a no-op at best and a corrupting probe
//! at worst (writing zeros to whatever register lookup-table the chip
//! happens to land on).
//!
//! ## Platforms
//!
//! Used on:
//! - S19j Pro CV1835 (Sophgo CV1835 SoC, eMMC-rooted)
//! - AM335x BB (BeagleBone-class control board, S19j Pro variant)
//! - Amlogic S19j Pro variants
//!
//! Construction is gated by the `Pic1704Authorized` sealed trait in
//! `super::service` — only platforms whose marker types implement that
//! trait can build a `Pic1704Service`. This is the platform-isolation
//! guarantee per the W2 RE deliverable spec.

use dcentrald_hal::i2c::I2cTransactionStep;

// ===========================================================================
//  I2C address + register map (source: pic1704.h:13-24)
// ===========================================================================

/// 7-bit I2C slave address for PIC1704 voltage controllers.
pub const PIC1704_I2C_ADDR: u8 = 0x20;

/// Firmware version register (R). Returns one of the `VER_*` constants.
pub const REG_VERSION: u8 = 0x00;
/// Primary temperature register (R). 1 byte, signed tenths-of-degrees-C.
/// `0x00` and `0xFF` are sentinel "no reading" values; fall back to `REG_TEMP_ALT`.
pub const REG_TEMP: u8 = 0x01;
/// Voltage reading low byte (R). Little-endian word at `[0x02, 0x03]`, mV.
pub const REG_VOLTAGE_L: u8 = 0x02;
/// Voltage reading high byte (R).
pub const REG_VOLTAGE_H: u8 = 0x03;
/// Current reading low byte (R). Little-endian word at `[0x04, 0x05]`, mA.
pub const REG_CURRENT_L: u8 = 0x04;
/// Current reading high byte (R).
pub const REG_CURRENT_H: u8 = 0x05;
/// Alternate temperature register (R). Used when `REG_TEMP` returns 0x00/0xFF.
pub const REG_TEMP_ALT: u8 = 0x06;
/// Status register (R). Bitfield — see `STATUS_*` constants.
pub const REG_STATUS: u8 = 0x08;
/// Control register (W). DC-DC enable, heartbeat, RESET (gated). See `CTRL_*`.
pub const REG_CONTROL: u8 = 0x09;

// ===========================================================================
//  Bootloader unlock + version values (source: pic1704.h:27-34)
// ===========================================================================

/// Bootloader unlock magic — written to `REG_VERSION` before `BL_CMD_JUMP`.
pub const BL_MAGIC: u8 = 0x5A;
/// Bootloader jump-to-application command — written to `REG_CONTROL` after
/// `BL_MAGIC` to trigger the boot transition.
pub const BL_CMD_JUMP: u8 = 0x01;

/// Bootloader firmware version (no application running yet).
pub const VER_BOOTLOADER: u8 = 0x86;
/// Application firmware revision A.
pub const VER_REV_A: u8 = 0x88;
/// Application firmware (canonical "current shipping" revision).
pub const VER_APPLICATION: u8 = 0x89;
/// Application firmware revision B.
pub const VER_REV_B: u8 = 0x8A;

// ===========================================================================
//  Status register bits (source: pic1704.h:37-40)
// ===========================================================================

/// `REG_STATUS` bit 0 — DC-DC converter is currently enabled.
pub const STATUS_DC_DC_ON: u8 = 1 << 0;
/// `REG_STATUS` bit 1 — application firmware is running (vs bootloader).
pub const STATUS_APP_RUNNING: u8 = 1 << 1;
/// `REG_STATUS` bit 2 — fault latched (over-current / under-voltage / etc.).
pub const STATUS_FAULT: u8 = 1 << 2;
/// `REG_STATUS` bit 3 — over-temperature protection asserted.
pub const STATUS_OTP: u8 = 1 << 3;

// ===========================================================================
//  Control register commands (source: pic1704.h:43-46)
// ===========================================================================

/// `REG_CONTROL`: disable DC-DC output.
pub const CTRL_DC_DC_OFF: u8 = 0x00;
/// `REG_CONTROL`: enable DC-DC output.
pub const CTRL_DC_DC_ON: u8 = 0x01;
/// `REG_CONTROL`: heartbeat tick (rate-limited to 2 s).
pub const CTRL_HEARTBEAT: u8 = 0x02;
/// `REG_CONTROL`: hardware RESET. **Destructive protocol constant retained as
/// data only.** Mutating helpers are research/test-only behind `recovery-tool`,
/// which no shipped package enables..
pub const CTRL_RESET: u8 = 0x80;

// ===========================================================================
//  Timing
// ===========================================================================

/// Heartbeat interval — `pic1704.c` rate-limits writes to one every 2000 ms.
pub const HEARTBEAT_INTERVAL_MS: u64 = 2_000;

/// Bootloader→app poll interval inside `wait_for_app`.
pub const POLL_INTERVAL_MS: u64 = 100;

/// Default timeout for the bootloader→app transition.
pub const WAIT_APP_TIMEOUT_MS: u64 = 5_000;

// ===========================================================================
//  Runtime state classification
// ===========================================================================

/// PIC1704 runtime state derived from `REG_VERSION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pic1704State {
    /// `REG_VERSION` was unreadable or returned an unrecognised value.
    Unknown,
    /// Firmware version `0x86` — bootloader. Send `start_app` to transition.
    Bootloader,
    /// Firmware version `0x88` / `0x89` / `0x8A` — application running.
    /// Voltage / current / temperature reads are valid in this state.
    Application,
    /// Last operation returned an I2C / protocol error.
    Error,
}

impl Pic1704State {
    /// True if this state permits reading voltage/current/temperature.
    pub fn is_application(&self) -> bool {
        matches!(self, Pic1704State::Application)
    }

    /// True if `start_app` is a valid call from this state.
    pub fn is_bootloader(&self) -> bool {
        matches!(self, Pic1704State::Bootloader)
    }
}

/// Classify a raw `REG_VERSION` byte into a `Pic1704State`.
///
/// Source: `pic1704.c` lines 130-136 (open path) and 175-181 (wait_for_app).
pub fn classify_version(ver: u8) -> Pic1704State {
    match ver {
        VER_BOOTLOADER => Pic1704State::Bootloader,
        VER_REV_A | VER_APPLICATION | VER_REV_B => Pic1704State::Application,
        _ => Pic1704State::Unknown,
    }
}

/// True if the byte represents an application firmware revision.
pub fn is_application_version(ver: u8) -> bool {
    matches!(ver, VER_REV_A | VER_APPLICATION | VER_REV_B)
}

// ===========================================================================
//  Wire-format helpers
// ===========================================================================

/// Decode a little-endian 16-bit word read from `[REG_VOLTAGE_L, REG_VOLTAGE_H]`
/// or `[REG_CURRENT_L, REG_CURRENT_H]`.
///
/// Returns `None` if the slice is shorter than 2 bytes.
pub fn decode_le_word(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 2 {
        return None;
    }
    Some(u16::from(bytes[0]) | (u16::from(bytes[1]) << 8))
}

/// Build the `I2cTransactionStep` sequence for the bootloader→app jump.
///
/// Order is load-bearing: `BL_MAGIC` to `REG_VERSION` MUST happen before
/// `BL_CMD_JUMP` to `REG_CONTROL`. The reference C implementation
/// (`pic1704.c` lines 213-220) enforces this with two sequential writes; we
/// pack them into one service transaction so no other I2C client can
/// interleave between the two writes.
pub fn start_app_steps() -> Vec<I2cTransactionStep> {
    vec![
        I2cTransactionStep::Write(vec![REG_VERSION, BL_MAGIC]),
        I2cTransactionStep::Write(vec![REG_CONTROL, BL_CMD_JUMP]),
    ]
}

/// Build the steps for a single-byte short-form register read.
///
/// This is the canonical PIC1704 read pattern: write the register address,
/// then read N bytes from the same slave with a repeated-START. We use the
/// `WriteRead` step variant because the i2cdev backend issues this as one
/// `I2C_RDWR` ioctl, which matches the reference C code's `write(addr_byte)
/// + read(buf, len)` shape and works on the kernel xiic-i2c backend.
pub fn read_register_steps(reg: u8, len: usize) -> Vec<I2cTransactionStep> {
    vec![I2cTransactionStep::WriteRead {
        write_data: vec![reg],
        read_len: len,
    }]
}

/// Build the steps for a short-form single-byte register write.
pub fn write_register_steps(reg: u8, value: u8) -> Vec<I2cTransactionStep> {
    vec![I2cTransactionStep::Write(vec![reg, value])]
}

/// Build steps for a heartbeat write.
///
/// Equivalent to `pic1704.c::pic1704_heartbeat` minus the rate-limit check
/// (the rate-limit lives in `Pic1704Service::heartbeat` so this helper
/// stays host-testable).
pub fn heartbeat_steps() -> Vec<I2cTransactionStep> {
    write_register_steps(REG_CONTROL, CTRL_HEARTBEAT)
}

/// Build steps for an enable/disable DC-DC write.
pub fn enable_dc_dc_steps(enable: bool) -> Vec<I2cTransactionStep> {
    let val = if enable {
        CTRL_DC_DC_ON
    } else {
        CTRL_DC_DC_OFF
    };
    write_register_steps(REG_CONTROL, val)
}

// ===========================================================================
//  Register access class (set_mv evidence — SOURCE_HAL pic1704.h map)
// ===========================================================================

/// Access class for short-form PIC1704 registers (host-pure).
///
/// Source: `SOURCE_HAL/pic1704.h` register map as mirrored in this module's
/// constants. Used to fail-closed VoltageRail `set_mv` without inventing a
/// write path that does not exist on the held short-form protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pic1704RegisterAccess {
    /// Measure / status — reads only in application firmware.
    ReadOnly,
    /// Control / bootloader unlock path — writes (and version read for probe).
    WriteOrProbe,
    /// Not part of the held short-form map.
    Unknown,
}

/// Classify a register address by access role on the short-form protocol.
///
/// **Voltage set-point:** there is **no** writable millivolt/DAC register in
/// the held map. `REG_VOLTAGE_L/H` (0x02/0x03) are **read-only feedback**.
/// Rail energize is `REG_CONTROL` DC-DC on/off only. PSU (or board topology)
/// sets the absolute rail; PIC1704 gates it.
pub fn register_access(reg: u8) -> Pic1704RegisterAccess {
    match reg {
        REG_TEMP | REG_VOLTAGE_L | REG_VOLTAGE_H | REG_CURRENT_L | REG_CURRENT_H | REG_TEMP_ALT
        | REG_STATUS => Pic1704RegisterAccess::ReadOnly,
        // REG_VERSION is read for probe and written only with BL_MAGIC for start_app.
        // REG_CONTROL is write-only control (enable/HB/jump/reset research).
        REG_VERSION | REG_CONTROL => Pic1704RegisterAccess::WriteOrProbe,
        _ => Pic1704RegisterAccess::Unknown,
    }
}

/// True if any short-form register is a writable voltage set-point (mV/DAC).
///
/// Always false on the held SOURCE_HAL map — evidence for VoltageRail set_mv
/// **NOT IMPLEMENTED** (not "missing because live hardware unvalidated").
pub const fn short_form_has_writable_voltage_setpoint() -> bool {
    dcentrald_common::pic1704_short_form_has_writable_voltage_setpoint()
}

/// Pure admission for Pic1704 VoltageRail `set_mv`.
///
/// Thin-wraps host-safe [`dcentrald_common::admit_pic1704_short_form_set_mv`]
/// and pins local register_access R-only invariants for REG_VOLTAGE_*.
pub fn admit_short_form_set_mv(mv: u16) -> Result<(), dcentrald_common::VoltageRailError> {
    debug_assert!(!short_form_has_writable_voltage_setpoint());
    debug_assert_eq!(
        register_access(REG_VOLTAGE_L),
        Pic1704RegisterAccess::ReadOnly
    );
    debug_assert_eq!(
        register_access(REG_VOLTAGE_H),
        Pic1704RegisterAccess::ReadOnly
    );
    // Register address constants must stay aligned with common SSOT pins.
    debug_assert_eq!(REG_VOLTAGE_L, dcentrald_common::PIC1704_REG_VOLTAGE_L);
    debug_assert_eq!(REG_VOLTAGE_H, dcentrald_common::PIC1704_REG_VOLTAGE_H);
    debug_assert_eq!(REG_CONTROL, dcentrald_common::PIC1704_REG_CONTROL);
    dcentrald_common::admit_pic1704_short_form_set_mv(mv)
}

// ===========================================================================
//  Tests (host-safe, no I2C bus required)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_version_bootloader() {
        assert_eq!(classify_version(0x86), Pic1704State::Bootloader);
    }

    #[test]
    fn classify_version_application_rev_a() {
        assert_eq!(classify_version(0x88), Pic1704State::Application);
    }

    #[test]
    fn classify_version_application_canonical() {
        assert_eq!(classify_version(0x89), Pic1704State::Application);
    }

    #[test]
    fn classify_version_application_rev_b() {
        assert_eq!(classify_version(0x8A), Pic1704State::Application);
    }

    #[test]
    fn classify_version_unknown_zeros() {
        assert_eq!(classify_version(0x00), Pic1704State::Unknown);
    }

    #[test]
    fn classify_version_unknown_ones() {
        assert_eq!(classify_version(0xFF), Pic1704State::Unknown);
    }

    #[test]
    fn classify_version_unknown_random() {
        // Not in {0x86, 0x88, 0x89, 0x8A}.
        assert_eq!(classify_version(0x42), Pic1704State::Unknown);
        assert_eq!(classify_version(0x87), Pic1704State::Unknown);
        assert_eq!(classify_version(0x90), Pic1704State::Unknown);
    }

    #[test]
    fn is_application_version_matrix() {
        assert!(!is_application_version(0x86));
        assert!(is_application_version(0x88));
        assert!(is_application_version(0x89));
        assert!(is_application_version(0x8A));
        assert!(!is_application_version(0x00));
        assert!(!is_application_version(0xFF));
    }

    #[test]
    fn voltage_feedback_registers_are_read_only_on_short_form_map() {
        assert_eq!(
            register_access(REG_VOLTAGE_L),
            Pic1704RegisterAccess::ReadOnly
        );
        assert_eq!(
            register_access(REG_VOLTAGE_H),
            Pic1704RegisterAccess::ReadOnly
        );
        assert_eq!(register_access(REG_TEMP), Pic1704RegisterAccess::ReadOnly);
        assert_eq!(register_access(REG_STATUS), Pic1704RegisterAccess::ReadOnly);
        // Control is the only rail-gate write (DC-DC / HB), not an mV setpoint.
        assert_eq!(
            register_access(REG_CONTROL),
            Pic1704RegisterAccess::WriteOrProbe
        );
        assert!(!short_form_has_writable_voltage_setpoint());
    }

    #[test]
    fn admit_short_form_set_mv_is_evidence_exhausted_unsupported() {
        let err = admit_short_form_set_mv(13_700).unwrap_err();
        assert!(matches!(
            err,
            dcentrald_common::VoltageRailError::Unsupported { .. }
        ));
        let msg = err.to_string();
        assert!(
            msg.contains("REG_VOLTAGE") || msg.contains("read-only"),
            "error must cite read-only voltage feedback: {msg}"
        );
        assert!(
            msg.contains("evidence-exhausted") || msg.contains("Evidence-exhausted"),
            "error must mark evidence-exhausted not live-gated: {msg}"
        );
        // Must not be Ok(()) — historical silent-success class.
        assert_ne!(format!("{err}"), "");
    }

    #[test]
    fn enable_dc_dc_writes_control_not_voltage_regs() {
        let on = enable_dc_dc_steps(true);
        let off = enable_dc_dc_steps(false);
        for steps in [&on, &off] {
            match &steps[0] {
                I2cTransactionStep::Write(buf) => {
                    assert_eq!(buf[0], REG_CONTROL);
                    assert_ne!(buf[0], REG_VOLTAGE_L);
                    assert_ne!(buf[0], REG_VOLTAGE_H);
                }
                other => panic!("expected Write, got {other:?}"),
            }
        }
    }

    #[test]
    fn start_app_emits_magic_then_jump_in_order() {
        let steps = start_app_steps();
        assert_eq!(steps.len(), 2, "start_app must emit exactly two writes");

        match &steps[0] {
            I2cTransactionStep::Write(buf) => {
                assert_eq!(
                    buf,
                    &vec![REG_VERSION, BL_MAGIC],
                    "first write must be 0x5A → REG_VERSION (bootloader unlock)",
                );
            }
            other => panic!("first step expected Write, got {:?}", other),
        }

        match &steps[1] {
            I2cTransactionStep::Write(buf) => {
                assert_eq!(
                    buf,
                    &vec![REG_CONTROL, BL_CMD_JUMP],
                    "second write must be 0x01 → REG_CONTROL (jump command)",
                );
            }
            other => panic!("second step expected Write, got {:?}", other),
        }
    }

    #[test]
    fn decode_le_word_canonical() {
        // 0x12 0x34 little-endian → 0x3412
        assert_eq!(decode_le_word(&[0x12, 0x34]), Some(0x3412));
    }

    #[test]
    fn decode_le_word_realistic_voltage() {
        // 13.7 V → 13700 mV → 0x3584. LE: 0x84 0x35.
        assert_eq!(decode_le_word(&[0x84, 0x35]), Some(13_700));
    }

    #[test]
    fn decode_le_word_zero() {
        assert_eq!(decode_le_word(&[0x00, 0x00]), Some(0));
    }

    #[test]
    fn decode_le_word_max() {
        assert_eq!(decode_le_word(&[0xFF, 0xFF]), Some(0xFFFF));
    }

    #[test]
    fn decode_le_word_short_slice() {
        assert_eq!(decode_le_word(&[]), None);
        assert_eq!(decode_le_word(&[0x12]), None);
    }

    #[test]
    fn decode_le_word_extra_bytes_ignored() {
        // Only the first 2 bytes are used.
        assert_eq!(decode_le_word(&[0x84, 0x35, 0xFF, 0xFF]), Some(13_700));
    }

    #[test]
    fn read_register_steps_uses_writeread() {
        let steps = read_register_steps(REG_VOLTAGE_L, 2);
        assert_eq!(steps.len(), 1);
        match &steps[0] {
            I2cTransactionStep::WriteRead {
                write_data,
                read_len,
            } => {
                assert_eq!(write_data, &vec![REG_VOLTAGE_L]);
                assert_eq!(*read_len, 2);
            }
            other => panic!("expected WriteRead, got {:?}", other),
        }
    }

    #[test]
    fn write_register_steps_packs_reg_then_value() {
        let steps = write_register_steps(REG_CONTROL, CTRL_HEARTBEAT);
        assert_eq!(steps.len(), 1);
        match &steps[0] {
            I2cTransactionStep::Write(buf) => {
                assert_eq!(buf, &vec![REG_CONTROL, CTRL_HEARTBEAT]);
            }
            other => panic!("expected Write, got {:?}", other),
        }
    }

    #[test]
    fn heartbeat_steps_target_control_register() {
        let steps = heartbeat_steps();
        match &steps[0] {
            I2cTransactionStep::Write(buf) => {
                assert_eq!(buf[0], REG_CONTROL);
                assert_eq!(buf[1], CTRL_HEARTBEAT);
            }
            other => panic!("expected Write, got {:?}", other),
        }
    }

    #[test]
    fn enable_dc_dc_emits_correct_byte() {
        let on = enable_dc_dc_steps(true);
        match &on[0] {
            I2cTransactionStep::Write(buf) => assert_eq!(buf, &vec![REG_CONTROL, CTRL_DC_DC_ON]),
            other => panic!("expected Write, got {:?}", other),
        }
        let off = enable_dc_dc_steps(false);
        match &off[0] {
            I2cTransactionStep::Write(buf) => assert_eq!(buf, &vec![REG_CONTROL, CTRL_DC_DC_OFF]),
            other => panic!("expected Write, got {:?}", other),
        }
    }

    #[test]
    fn pic1704_state_helpers() {
        assert!(Pic1704State::Application.is_application());
        assert!(!Pic1704State::Bootloader.is_application());
        assert!(Pic1704State::Bootloader.is_bootloader());
        assert!(!Pic1704State::Application.is_bootloader());
        assert!(!Pic1704State::Unknown.is_application());
        assert!(!Pic1704State::Error.is_application());
    }

    #[test]
    fn status_bit_constants_are_canonical() {
        assert_eq!(STATUS_DC_DC_ON, 0x01);
        assert_eq!(STATUS_APP_RUNNING, 0x02);
        assert_eq!(STATUS_FAULT, 0x04);
        assert_eq!(STATUS_OTP, 0x08);
    }

    #[test]
    fn control_byte_constants_are_canonical() {
        assert_eq!(CTRL_DC_DC_OFF, 0x00);
        assert_eq!(CTRL_DC_DC_ON, 0x01);
        assert_eq!(CTRL_HEARTBEAT, 0x02);
        assert_eq!(CTRL_RESET, 0x80);
    }

    #[test]
    fn i2c_address_is_0x20() {
        assert_eq!(PIC1704_I2C_ADDR, 0x20);
    }
}
