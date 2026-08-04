// SPDX-License-Identifier: GPL-3.0-or-later
//! Hammer ST7789 i80 panel pin truth and collision guards.
//!
//! This module is intentionally pure: it records the byte-verified vendor pin
//! map and host-tests ownership without initializing the panel. GPIO15 remains
//! a bench blocker because it is a shared board-power + LCD-power net and the
//! vendor sequence drives it low; no runtime display code may touch it yet.

/// ST7789 i80 signal map shared by every held Hammer image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct St7789I80PinMap {
    pub dc: i32,
    pub wr: i32,
    pub cs: i32,
    pub data: [i32; 8],
    /// Shared board-power + LCD-power net. Metadata only; never drive from the
    /// current firmware.
    pub shared_power: i32,
}

pub const ST7789_DC_GPIO: i32 = 7;
pub const ST7789_WR_GPIO: i32 = 8;
pub const ST7789_CS_GPIO: i32 = 6;
pub const ST7789_DATA_GPIOS: [i32; 8] = [39, 40, 41, 42, 45, 46, 47, 48];
pub const ST7789_SHARED_POWER_GPIO: i32 = 15;

pub const fn st7789_i80_pin_map() -> St7789I80PinMap {
    St7789I80PinMap {
        dc: ST7789_DC_GPIO,
        wr: ST7789_WR_GPIO,
        cs: ST7789_CS_GPIO,
        data: ST7789_DATA_GPIOS,
        shared_power: ST7789_SHARED_POWER_GPIO,
    }
}

/// Every GPIO physically claimed by the panel block, including the shared
/// power net that must not be borrowed by another compiled peripheral.
pub const ST7789_ALL_GPIOS: [i32; 12] = [
    ST7789_DC_GPIO,
    ST7789_WR_GPIO,
    ST7789_CS_GPIO,
    ST7789_DATA_GPIOS[0],
    ST7789_DATA_GPIOS[1],
    ST7789_DATA_GPIOS[2],
    ST7789_DATA_GPIOS[3],
    ST7789_DATA_GPIOS[4],
    ST7789_DATA_GPIOS[5],
    ST7789_DATA_GPIOS[6],
    ST7789_DATA_GPIOS[7],
    ST7789_SHARED_POWER_GPIO,
];

pub fn overlap(left: &[i32], right: &[i32]) -> Vec<i32> {
    left.iter()
        .copied()
        .filter(|pin| right.contains(pin))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn hammer_st7789_pin_map_is_byte_verified_and_unique() {
        let pins = st7789_i80_pin_map();
        assert_eq!((pins.dc, pins.wr, pins.cs), (7, 8, 6));
        assert_eq!(pins.data, [39, 40, 41, 42, 45, 46, 47, 48]);
        assert_eq!(pins.shared_power, 15);
        assert_eq!(
            ST7789_ALL_GPIOS
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len(),
            ST7789_ALL_GPIOS.len(),
            "the panel map must not assign one GPIO to two panel signals"
        );
    }

    #[test]
    fn hammer_i2c_and_control_outputs_never_reuse_a_panel_gpio() {
        assert!(overlap(&ST7789_ALL_GPIOS, &[44, 43]).is_empty());
        // GPIO46 was previously driven push-pull as a fake buck-enable. It is
        // panel D5, so Hammer now uses the explicit -1/no-buck sentinel.
        assert!(ST7789_ALL_GPIOS.contains(&46));
        for model in [
            crate::board::BitAxeModel::HammerBc01,
            crate::board::BitAxeModel::HammerBc01Pro,
            crate::board::BitAxeModel::HammerBc02,
            crate::board::BitAxeModel::HammerBc04,
            crate::board::BitAxeModel::HammerDc02,
            crate::board::BitAxeModel::HammerDc04,
            crate::board::BitAxeModel::HammerDc06,
        ] {
            let cfg = crate::board::BoardConfig::for_model(model);
            assert_eq!((cfg.i2c_sda_pin, cfg.i2c_scl_pin), (44, 43));
            assert_eq!(cfg.buck_enable_pin, -1, "{model:?}");
            for pin in [
                cfg.i2c_sda_pin,
                cfg.i2c_scl_pin,
                cfg.asic_reset_pin,
                cfg.led_pin,
            ] {
                assert!(
                    !ST7789_ALL_GPIOS.contains(&pin),
                    "{model:?} binds GPIO{pin}, which belongs to the panel"
                );
            }
        }
    }

    #[cfg(feature = "pins-lora")]
    #[test]
    fn lora_collision_set_is_exact_and_requires_compile_refusal() {
        use crate::lora_pins::*;
        let lora = [
            LORA_SCLK_GPIO,
            LORA_MOSI_GPIO,
            LORA_MISO_GPIO,
            LORA_NSS_GPIO,
            LORA_BUSY_GPIO,
            LORA_DIO1_GPIO,
            LORA_NRESET_GPIO,
            LORA_TXEN_GPIO,
            LORA_RXEN_GPIO,
        ];
        assert_eq!(overlap(&ST7789_ALL_GPIOS, &lora), [7, 8, 6, 15]);
    }

    #[cfg(feature = "eth-w5500")]
    #[test]
    fn bap_w5500_collision_set_is_exact_and_requires_compile_refusal() {
        use crate::eth::*;
        let w5500 = [
            W5500_MISO_GPIO,
            W5500_MOSI_GPIO,
            W5500_SCLK_GPIO,
            W5500_CS_GPIO,
        ];
        assert_eq!(overlap(&ST7789_ALL_GPIOS, &w5500), [39, 40, 41, 42]);
    }
}
