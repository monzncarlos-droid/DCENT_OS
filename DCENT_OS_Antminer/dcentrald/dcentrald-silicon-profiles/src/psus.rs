//! 9 (2026-05-09): PSU catalog — every Bitmain PSU we know how to
//! identify across the Antminer line.
//!
//! Source-cite: `DCENT_OS_DEVELOPMENT_KITRE2/DCENT_OS_DEVELOPMENT_KIT/`
//! `DCENT_OS_HARDWARE_CATALOG.md` §5 (lines 460-528).
//!
//! This module is **catalog metadata** only. The driver implementations
//! live elsewhere:
//! - `dcentrald-asic::psu::Apw121215a` — am2 Zynq dsPIC-coupled PSU.
//! - `dcentrald-hal` W11.2 `Apw12SmbusBackend` — APW12 SMBus opcode-based
//!   driver (CV1835 / BB / AML S19j Pro).
//! - `dcentrald-hal::psu_apw12_plus` retains host-testable historical
//!   register-model evidence and exact framed-protocol builders. Its register
//!   backend is test-only because three later RE sources refuted that model for
//!   real S21 APW121215f hardware.
//!
//! Two distinct families are easy to confuse:
//! - **APW12** (S19j Pro / S19 / T19) is **opcode-based SMBus** at I²C
//!   `0x10` with 16+ opcodes (RE2 §5.2). Enable via GPIO 412.
//! - **APW12+** is a legacy catalog label whose earlier register-at-`0x10`,
//!   GPIO-907, and S21-family binding is contradicted by later held Bitmain,
//!   VNish, and PSU-firmware evidence. It remains explicitly unresolved and
//!   cannot select a production backend.
//!
//! and
//!  for the routing
//! rules tying each PSU back to the platform classification it lives on.

use serde::{Deserialize, Serialize};

/// PSU control protocol family. Used by routing code to pick the right
/// driver backend at platform-classify time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PsuProtocol {
    /// Conflicting evidence does not settle a production wire protocol.
    /// This is a mandatory fail-closed catalog state, never a probe fallback.
    Unresolved,
    /// PMBus 1.2+ standard. APW3++ at I²C 0x58/0x59; APW10/APW11 remain
    /// partial catalog rows. APW9 is explicitly NOT in this family.
    /// Standard PMBus opcodes (READ_VOUT, READ_IOUT, etc.).
    PmBus,
    /// APW9 proprietary framed I²C interface at 7-bit address `0x10`.
    ///
    /// Exact held S17/S17 Pro factory-jig bytes use bus 1, register `0x11`,
    /// and framed command/reply traffic. This tag is descriptive only:
    /// DCENT_OS ships no APW9 backend, telemetry reader, or voltage-command
    /// encoder. Consumers must fail closed.
    Apw9FramedI2c,
    /// Bitmain proprietary v1 — opcode-based SMBus on the older Zynq
    /// boards. Used by APW111721b/c, APW11A1216-1a, APW11Go, NBS1902.
    BitmainProtoV1,
    /// Bitmain proprietary v2 — opcode-based SMBus, refined later
    /// generation. Used by APW17, PW380X12.
    BitmainProtoV2,
    /// APW12 SMBus opcode-based protocol, 16+ opcodes (RE2 §5.2). Used
    /// on S19j Pro / S19 / T19. Implemented by W11.2
    /// `Apw12SmbusBackend`.
    Apw12Smbus,
    /// Historical APW12+ register-based hypothesis. Retained for serialized
    /// compatibility and host-side evidence tests; no production catalog row
    /// currently selects it.
    Apw12PlusRegister,
    /// am2 Zynq APW121215a — dsPIC-coupled, no PMBus telemetry on
    /// fw=0x71. Implemented by `dcentrald-asic::psu::Apw121215a`. Per
    /// : GET_VOLTAGE / GET_CURRENT
    /// / GET_POWER are not available; use multimeter or chain-byte-count
    /// probes for rail engagement evidence.
    Apw121215a,
    /// No control or telemetry interface is physically exposed. APW7's
    /// first-party guide shows only AC input and fixed DC output terminals.
    NoControlInterface,
}

/// GPIO line that asserts the PSU enable / chassis power-good signal.
///
/// Stored as a numeric pin per the per-platform GPIO maps in
/// `gpio_maps.rs`. Multi-platform PSUs (e.g. APW12 ships on CV1835 with
/// GPIO 412 and on AM335x with GPIO 65) carry the canonical platform
/// pin in this field; routing code overrides at platform-classify time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PsuEnableGpio {
    pub pin: u32,
    /// Human-readable platform tag for the canonical pin assignment.
    pub canonical_platform: &'static str,
}

/// One PSU catalog entry.
///
/// `Deserialize` is intentionally NOT derived — `used_in` is a
/// `&'static [&'static str]` slice that can't be borrowed during a
/// deserialize round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PsuCatalogEntry {
    /// Vendor model string as it appears in firmware / labels.
    pub model: &'static str,
    /// 7-bit I²C slave address, or `None` when the physical unit exposes no
    /// signal/control terminal.
    pub i2c_address: Option<u8>,
    /// Control protocol family.
    pub protocol: PsuProtocol,
    /// Maximum continuous output power in watts. 0 if not pinned by
    /// RE2 (see `verification_partial`).
    pub max_power_w: u32,
    /// Legacy single-rail nominal voltage in volts. `0` means that flattening
    /// the physical topology to one integer would be false. APW9 uses `0`
    /// because it has a 14.5-21 V adjustable main rail plus a fixed 12.3 V
    /// auxiliary rail; use the cross-catalog APW/maintenance-guide spec.
    pub nominal_voltage_v: u8,
    /// GPIO that gates the PSU output (for register/opcode-based PSUs).
    /// `None` for PMBus-only PSUs that turn on at AC apply.
    pub enable_gpio: Option<PsuEnableGpio>,
    /// Antminer models known to ship this PSU.
    pub used_in: &'static [&'static str],
    /// `true` if RE2 confidence is "PARTIAL" — the row exists in the
    /// catalog but max_power / variant assignment aren't fully pinned.
    pub verification_partial: bool,
}

/// PSU enum — used as a catalog key. Mirror the rows in RE2 §5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Psu {
    /// APW3++ — first-gen S9 PSU. PMBus at 0x58/0x59, ~1600 W.
    Apw3PlusPlus,
    /// APW7 — fixed-output PSU with no signal/control terminal.
    Apw7,
    /// APW9 — S17 / S17 Pro, proprietary framed I²C, 3600 W.
    Apw9,
    /// APW10 — transitional, PMBus, ~3300 W. Catalog placeholder; RE2
    /// confidence = PARTIAL.
    Apw10,
    /// APW11 — transitional, ~3500 W. Catalog placeholder; RE2
    /// confidence = PARTIAL.
    Apw11,
    /// APW111721b / APW111721c — Bitmain proto v1, ~1200 W (S9 / T9 /
    /// S11). Two SKUs with the same protocol; we treat them as one
    /// catalog row.
    Apw111721b,
    Apw111721c,
    /// APW11A1216-1a — Bitmain proto v1, ~1600 W (S15 / S17).
    Apw11A1216_1a,
    /// APW11Go — Bitmain proto v1, ~1200 W.
    Apw11Go,
    /// APW12 — S19j Pro / S19 / T19. SMBus opcode-based at I²C 0x10,
    /// GPIO 412 enable. Implemented by W11.2 `Apw12SmbusBackend`.
    Apw12,
    /// APW12+ label from the earlier catalog. Exact S21 PSU model/protocol,
    /// GPIO polarity, and power envelope remain unresolved.
    Apw12Plus,
    /// APW17 — S17 / T17 transitional, Bitmain proto v2, ~1700 W.
    Apw17,
    /// NBS1902 — Zynq boards, Bitmain proto v1, ~1900 W.
    Nbs1902,
    /// PW380X12 — S19 high-power, Bitmain proto v2, 380 W × 12 = 4560 W.
    Pw380X12,
    /// APW121215a — am2 Zynq APW with dsPIC fw=0x71, no telemetry. Per
    /// . Implemented by
    /// `dcentrald-asic::psu::Apw121215a`.
    Apw121215a,
}

impl Psu {
    /// Catalog row for this PSU. RE2 §5.1 lines 466-478 are the source.
    pub const fn catalog(self) -> PsuCatalogEntry {
        match self {
            Psu::Apw3PlusPlus => PsuCatalogEntry {
                model: "APW3++",
                i2c_address: Some(0x58),
                protocol: PsuProtocol::PmBus,
                max_power_w: 1600,
                nominal_voltage_v: 12,
                enable_gpio: None,
                used_in: &["S9"],
                verification_partial: false,
            },
            Psu::Apw7 => PsuCatalogEntry {
                model: "APW7",
                i2c_address: None,
                protocol: PsuProtocol::NoControlInterface,
                max_power_w: 1800,
                nominal_voltage_v: 12,
                enable_gpio: None,
                used_in: &["S9", "S9i", "L3+", "D3", "T9+", "Z9"],
                verification_partial: false,
            },
            Psu::Apw9 => PsuCatalogEntry {
                model: "APW9",
                // Exact S17/S17 Pro factory-jig bytes emit the FPGA-I2C word
                // shape `0x052011xx`: 7-bit address 0x10, bus 1, register
                // 0x11. The T17-path cgminer previously cited here is a
                // misfiled BM1391/S11-era binary and provides no provenance.
                i2c_address: Some(0x10),
                protocol: PsuProtocol::Apw9FramedI2c,
                // APW9 maintenance guide pp.3/5: 14.5-21 V, 170 A, 3600 W
                // main rail plus 12.3 V / 12 A auxiliary rail.
                max_power_w: 3600,
                nominal_voltage_v: 0,
                // Guide p.5: EN is active low. Held S17/S17 Pro jig
                // `open_power_control@1AA54` drives gpio907 low.
                enable_gpio: Some(PsuEnableGpio {
                    pin: 907,
                    canonical_platform: "zynq-7007s",
                }),
                used_in: &["S17", "S17 Pro"],
                verification_partial: false,
            },
            Psu::Apw10 => PsuCatalogEntry {
                model: "APW10",
                i2c_address: Some(0x58),
                protocol: PsuProtocol::PmBus,
                max_power_w: 3300,
                nominal_voltage_v: 12,
                enable_gpio: None,
                used_in: &[],
                verification_partial: true,
            },
            Psu::Apw11 => PsuCatalogEntry {
                model: "APW11",
                i2c_address: Some(0x58),
                protocol: PsuProtocol::PmBus,
                max_power_w: 3500,
                nominal_voltage_v: 12,
                enable_gpio: None,
                used_in: &[],
                verification_partial: true,
            },
            Psu::Apw111721b => PsuCatalogEntry {
                model: "APW111721b",
                i2c_address: Some(0x10),
                protocol: PsuProtocol::BitmainProtoV1,
                max_power_w: 1200,
                nominal_voltage_v: 12,
                enable_gpio: Some(PsuEnableGpio {
                    pin: 65,
                    canonical_platform: "am335x-bb",
                }),
                used_in: &["S9", "T9", "S11"],
                verification_partial: false,
            },
            Psu::Apw111721c => PsuCatalogEntry {
                model: "APW111721c",
                i2c_address: Some(0x10),
                protocol: PsuProtocol::BitmainProtoV1,
                max_power_w: 1200,
                nominal_voltage_v: 12,
                enable_gpio: Some(PsuEnableGpio {
                    pin: 65,
                    canonical_platform: "am335x-bb",
                }),
                used_in: &["S9", "T9", "S11"],
                verification_partial: false,
            },
            Psu::Apw11A1216_1a => PsuCatalogEntry {
                model: "APW11A1216-1a",
                i2c_address: Some(0x10),
                protocol: PsuProtocol::BitmainProtoV1,
                max_power_w: 1600,
                nominal_voltage_v: 12,
                enable_gpio: Some(PsuEnableGpio {
                    pin: 65,
                    canonical_platform: "am335x-bb",
                }),
                used_in: &["S15", "S17"],
                verification_partial: false,
            },
            Psu::Apw11Go => PsuCatalogEntry {
                model: "APW11Go",
                i2c_address: Some(0x10),
                protocol: PsuProtocol::BitmainProtoV1,
                max_power_w: 1200,
                nominal_voltage_v: 12,
                enable_gpio: Some(PsuEnableGpio {
                    pin: 65,
                    canonical_platform: "am335x-bb",
                }),
                used_in: &[],
                verification_partial: false,
            },
            Psu::Apw12 => PsuCatalogEntry {
                model: "APW12",
                i2c_address: Some(0x10),
                // RE2 §5.2 lines 480-503 — 17 opcodes (0x00..=0x10),
                // SMBus opcode-based. Catalog tag is `Apw12Smbus`.
                protocol: PsuProtocol::Apw12Smbus,
                max_power_w: 3500,
                nominal_voltage_v: 12,
                enable_gpio: Some(PsuEnableGpio {
                    pin: 412,
                    canonical_platform: "cv1835",
                }),
                used_in: &["S19", "S19j Pro", "T19"],
                verification_partial: false,
            },
            Psu::Apw12Plus => PsuCatalogEntry {
                model: "APW12+",
                i2c_address: None,
                protocol: PsuProtocol::Unresolved,
                max_power_w: 0,
                nominal_voltage_v: 0,
                enable_gpio: None,
                used_in: &[],
                verification_partial: true,
            },
            Psu::Apw17 => PsuCatalogEntry {
                model: "APW17",
                i2c_address: Some(0x10),
                protocol: PsuProtocol::BitmainProtoV2,
                max_power_w: 1700,
                nominal_voltage_v: 12,
                enable_gpio: Some(PsuEnableGpio {
                    pin: 65,
                    canonical_platform: "am335x-bb",
                }),
                used_in: &["S17", "T17"],
                verification_partial: false,
            },
            Psu::Nbs1902 => PsuCatalogEntry {
                model: "NBS1902",
                i2c_address: Some(0x10),
                protocol: PsuProtocol::BitmainProtoV1,
                max_power_w: 1900,
                nominal_voltage_v: 12,
                enable_gpio: Some(PsuEnableGpio {
                    pin: 907,
                    canonical_platform: "zynq-7007s",
                }),
                used_in: &["Zynq boards"],
                verification_partial: false,
            },
            Psu::Pw380X12 => PsuCatalogEntry {
                model: "PW380X12",
                i2c_address: Some(0x10),
                protocol: PsuProtocol::BitmainProtoV2,
                max_power_w: 4560,
                nominal_voltage_v: 12,
                enable_gpio: Some(PsuEnableGpio {
                    pin: 412,
                    canonical_platform: "cv1835",
                }),
                used_in: &["S19 high-power"],
                verification_partial: false,
            },
            Psu::Apw121215a => PsuCatalogEntry {
                model: "APW121215a",
                // I²C 0x10 (driver truth: see `dcentrald-hal::psu`
                // `PSU_I2C_ADDR` / `APW12_FRAMED_ADDR`).
                // Coexists at 0x10 with Apw12Smbus / Apw12Plus — disambiguate
                // by platform marker, not by I²C address (per
                // ).
                // am2 Zynq APW + dsPIC fw=0x71. No PMBus telemetry per
                // .
                i2c_address: Some(0x10),
                protocol: PsuProtocol::Apw121215a,
                max_power_w: 3000,
                nominal_voltage_v: 12,
                enable_gpio: Some(PsuEnableGpio {
                    pin: 907,
                    canonical_platform: "zynq-7007s",
                }),
                used_in: &["S19j Pro (am2 Zynq)"],
                verification_partial: false,
            },
        }
    }

    /// Vendor model string.
    pub const fn model(self) -> &'static str {
        self.catalog().model
    }
}

/// A27 (goldmine 2026-06-10): S21 XP power-down hold delay in milliseconds,
/// lifted from the Bitmain S21 XP single-board-test jig `power_down@57DF4`.
/// The jig holds the PSU disabled for this long before treating the rail as
/// safely de-energized. DATA ONLY — recorded for a future S21 XP power-down
/// path; not referenced by any live path in this crate or `dcentrald`.
pub const S21XP_POWER_DOWN_HOLD_MS: u32 = 2000;

/// Every PSU in the catalog (15 entries: 14 distinct + APW121215a, with
/// APW111721b/c counted as two SKUs sharing one protocol).
pub const ALL_PSUS: &[Psu] = &[
    Psu::Apw3PlusPlus,
    Psu::Apw7,
    Psu::Apw9,
    Psu::Apw10,
    Psu::Apw11,
    Psu::Apw111721b,
    Psu::Apw111721c,
    Psu::Apw11A1216_1a,
    Psu::Apw11Go,
    Psu::Apw12,
    Psu::Apw12Plus,
    Psu::Apw17,
    Psu::Nbs1902,
    Psu::Pw380X12,
    Psu::Apw121215a,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_psus_present() {
        // 15 PSU entries — covers RE2 §5.1 plus existing Apw121215a.
        assert_eq!(ALL_PSUS.len(), 15);
    }

    #[test]
    fn s21xp_power_down_hold_ms_pinned() {
        // A27 (goldmine 2026-06-10): jig power_down@57DF4 = 2000 ms hold.
        // DATA ONLY — no live caller references it yet.
        assert_eq!(S21XP_POWER_DOWN_HOLD_MS, 2000);
    }

    #[test]
    fn each_psu_has_unique_model_string() {
        let mut seen = std::collections::HashSet::new();
        for psu in ALL_PSUS {
            assert!(
                seen.insert(psu.model()),
                "duplicate PSU model: {}",
                psu.model()
            );
        }
    }

    #[test]
    fn apw12_smbus_uses_opcode_protocol() {
        // RE2 §5.2 — APW12 is opcode-based SMBus at I²C 0x10, GPIO 412
        // enable.
        let cat = Psu::Apw12.catalog();
        assert_eq!(cat.protocol, PsuProtocol::Apw12Smbus);
        assert_eq!(cat.i2c_address, Some(0x10));
        let gpio = cat.enable_gpio.expect("APW12 must have GPIO enable");
        assert_eq!(gpio.pin, 412, "APW12 canonical enable pin is GPIO 412");
    }

    #[test]
    fn apw12_plus_stays_unresolved_and_unroutable() {
        // Later Bitmain jig, VNish, and PSU-firmware RE all refute the old
        // register abstraction for real APW121215f hardware.
        let cat = Psu::Apw12Plus.catalog();
        assert_eq!(cat.protocol, PsuProtocol::Unresolved);
        assert_eq!(cat.i2c_address, None);
        assert_eq!(cat.enable_gpio, None);
        assert_eq!(cat.max_power_w, 0);
        assert!(cat.used_in.is_empty());
        assert!(cat.verification_partial);
    }

    #[test]
    fn pmbus_psus_have_no_gpio_enable() {
        // PMBus rows turn on at AC apply and expose no separate GPIO enable.
        for psu in [Psu::Apw3PlusPlus, Psu::Apw10, Psu::Apw11] {
            let cat = psu.catalog();
            assert_eq!(cat.protocol, PsuProtocol::PmBus);
            assert!(
                cat.enable_gpio.is_none(),
                "{} should have no GPIO enable",
                cat.model
            );
        }
    }

    #[test]
    fn apw_pmbus_address_pinned_to_058() {
        // APW9 is deliberately excluded; held stock code pins it to the
        // proprietary framed-I²C path at 0x10 instead.
        for psu in [Psu::Apw3PlusPlus, Psu::Apw10, Psu::Apw11] {
            assert_eq!(psu.catalog().i2c_address, Some(0x58));
        }
    }

    #[test]
    fn apw9_contract_is_exact_and_has_no_shipped_control_authority() {
        use dcentrald_api_types::psu_maintenance::{GuideControlInterface, GuidePsuFamily};

        let cat = Psu::Apw9.catalog();
        let guide = GuidePsuFamily::Apw9.spec();

        assert_eq!(cat.i2c_address, Some(0x10));
        assert_eq!(cat.protocol, PsuProtocol::Apw9FramedI2c);
        assert_eq!(cat.max_power_w, 3600);
        assert_eq!(cat.nominal_voltage_v, 0);
        assert_eq!(cat.used_in, &["S17", "S17 Pro"]);
        assert_eq!(guide.main_output.volts_min, 14.5);
        assert_eq!(guide.main_output.volts_max, 21.0);
        assert_eq!(guide.main_output.rated_current_a, Some(170));
        let aux = guide
            .aux_output
            .expect("APW9 guide pins the auxiliary rail");
        assert_eq!((aux.volts_min, aux.volts_max), (12.2, 12.4));
        assert_eq!(aux.rated_current_a, Some(12));
        assert_eq!(
            guide.control_interface,
            GuideControlInterface::I2cPicWithEnActiveLow
        );
        let gpio = cat.enable_gpio.expect("held stock code pins APW9 enable");
        assert_eq!(gpio.pin, 907);
    }

    #[test]
    fn apw7_has_no_bus_or_control_protocol() {
        // First-party APW7 guide pp.2-4: no signal terminal is present; the
        // fixed 12 V output appears at AC apply. Never synthesize an address.
        let cat = Psu::Apw7.catalog();
        assert_eq!(cat.i2c_address, None);
        assert_eq!(cat.protocol, PsuProtocol::NoControlInterface);
        assert!(cat.enable_gpio.is_none());
        assert_eq!(cat.max_power_w, 1800);
        assert_eq!(cat.used_in, &["S9", "S9i", "L3+", "D3", "T9+", "Z9"]);
    }

    #[test]
    fn apw121215a_uses_dedicated_protocol_not_pmbus() {
        // am2 Zynq fw=0x71 has no PMBus telemetry per
        // . The catalog protocol
        // tag must reflect that.
        assert_eq!(Psu::Apw121215a.catalog().protocol, PsuProtocol::Apw121215a);
    }

    #[test]
    fn s21_psu_does_not_route_from_the_apw12_plus_label() {
        let cat = Psu::Apw12Plus.catalog();
        assert!(cat.used_in.is_empty());
        assert_eq!(cat.protocol, PsuProtocol::Unresolved);
    }

    #[test]
    fn s9_t9_s11_route_to_v1_psus() {
        // RE2 §5.1 — APW111721b/c and APW11A1216-1a are the
        // proto-v1 family used on the older Zynq fleet.
        for psu in [Psu::Apw111721b, Psu::Apw111721c] {
            let cat = psu.catalog();
            assert_eq!(cat.protocol, PsuProtocol::BitmainProtoV1);
            assert!(cat.used_in.iter().any(|m| *m == "S9" || *m == "T9"));
        }
    }
}
