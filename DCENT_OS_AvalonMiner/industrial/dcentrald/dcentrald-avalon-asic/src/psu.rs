// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies — dcentrald-avalon-asic :: K230 industrial PSU I2C map
//
// Wave 3.2 (2026-08-05): the industrial PSU I2C command-register map, beside the
// `hashboard_mux`/`chain_io` extensions. PURE DATA (register codes only, no
// hardware I/O); the K230 HAL performs the actual I2C transactions once
// bench-validated. The RW (write) codes — on/off, set-voltage — are documented
// here only as the wire vocabulary; nothing in this crate energizes a rail.
//
// ⚠️ LICENSE WARNING (2026-08-05): `Canaan-Creative/Avalon_mm` (`big/` + `little/mm_miner/`)
// is **BUSL-1.1**, NOT GPL — commercial production use needs a separate Canaan license
// (4-yr cliff to GPLv3); only `little/cgminer/` is BSD-3-Clause. `AVALON_MM_K230_INDUSTRIAL_RE.md:7`
// calls it "a major footgun for D-Central". The register codes below are hardware FACTS
// (believed uncopyrightable), transcribed for interop — OPERATOR LEGAL REVIEW required
// before shipping in GPL-3.0 DCENT_OS.
//
// GROUND TRUTH — byte-exact from Canaan-Creative Avalon_mm (BUSL-1.1)
// `Avalon_mm/little/mm_miner/platform/power_i2c.h:23-33`. `RO`=read-only,
// `RW`=read-write; the `1`/`2` suffix is the vendor's command-group tag.
//
// Support D-Central's open-source mining work: https://d-central.tech/fund/

#![allow(dead_code)] // pure constants; consumed by the K230 industrial HAL once bench-validated.

/// PSU 7-bit I2C address (`power_i2c.h:23` `POWER_I2C_ADDR`).
pub const POWER_I2C_ADDR: u8 = 0x2C;

/// Read PSU firmware version (`PCMD_RO1_VERSION`).
pub const PCMD_RO1_VERSION: u8 = 0x00;
/// PSU on/off control — WRITE (`PCMD_RW1_ONOFF`).
pub const PCMD_RW1_ONOFF: u8 = 0x02;
/// Read PSU error code (`PCMD_RO2_ERRCODE`).
pub const PCMD_RO2_ERRCODE: u8 = 0x05;
/// Read 12 V rail output voltage (`PCMD_RO2_VOUT12V`).
pub const PCMD_RO2_VOUT12V: u8 = 0x06;
/// Read main output voltage (`PCMD_RO2_VOUT`).
pub const PCMD_RO2_VOUT: u8 = 0x07;
/// Read output current (`PCMD_RO2_IOUT`).
pub const PCMD_RO2_IOUT: u8 = 0x08;
/// Read output power (`PCMD_RO2_POUT`).
pub const PCMD_RO2_POUT: u8 = 0x09;
/// Set output voltage — WRITE (`PCMD_RW2_VOUTCMD`).
pub const PCMD_RW2_VOUTCMD: u8 = 0x12;
/// AC power pin control (`PCMD_POWER_PIN_AC`).
pub const PCMD_POWER_PIN_AC: u8 = 0x30;

/// Whether a PSU command is a WRITE (mutates PSU state) vs a read-only telemetry
/// query. The K230 HAL uses this to keep energize/set-voltage on the gated path.
pub fn is_write_command(cmd: u8) -> bool {
    matches!(cmd, PCMD_RW1_ONOFF | PCMD_RW2_VOUTCMD | PCMD_POWER_PIN_AC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psu_register_map_matches_open_source() {
        // power_i2c.h:23-33 byte-exact.
        assert_eq!(POWER_I2C_ADDR, 0x2C);
        assert_eq!(PCMD_RO1_VERSION, 0x00);
        assert_eq!(PCMD_RW1_ONOFF, 0x02);
        assert_eq!(PCMD_RO2_ERRCODE, 0x05);
        assert_eq!(PCMD_RO2_VOUT12V, 0x06);
        assert_eq!(PCMD_RO2_VOUT, 0x07);
        assert_eq!(PCMD_RO2_IOUT, 0x08);
        assert_eq!(PCMD_RO2_POUT, 0x09);
        assert_eq!(PCMD_RW2_VOUTCMD, 0x12);
        assert_eq!(PCMD_POWER_PIN_AC, 0x30);
    }

    #[test]
    fn write_commands_are_classified_for_the_gated_path() {
        // The RW/energize codes are writes; telemetry reads are not.
        assert!(is_write_command(PCMD_RW1_ONOFF));
        assert!(is_write_command(PCMD_RW2_VOUTCMD));
        assert!(is_write_command(PCMD_POWER_PIN_AC));
        assert!(!is_write_command(PCMD_RO2_VOUT));
        assert!(!is_write_command(PCMD_RO1_VERSION));
        assert!(!is_write_command(PCMD_RO2_POUT));
    }
}
