//! Pure, release-scoped S15/T15 BM1391 startup-policy evidence.
//!
//! This module describes exact observations from the held stock releases. It
//! performs no I/O and grants no carrier, rail, ASIC-driver, work-dispatch, or
//! energization authority. In particular, stock voltage tokens and stock
//! tuning bounds are not electrical safety limits.

pub const BM1391_STOCK_PLL_TABLE_MAX_INDEX: u8 = 178;
pub const BM1391_STOCK_PLL_TABLE_ENTRY_COUNT: usize = 179;
/// Enable byte ORed into the host-order byte buffer between the stock
/// caller's two 32-bit byte swaps.
pub const BM1391_STOCK_PLL_ENABLE_BIT: u32 = 0x40;
pub const BM1391_STOCK_PLL_REGISTER: u8 = 0x08;
pub const BM1391_STOCK_PLL_DIVIDER_REGISTER: u8 = 0x70;
pub const BM1391_STOCK_PLL_DIVIDER_FILL: u32 = 0x0f0f_0f00;
pub const BM1391_STOCK_PLL_SOLVER_FALLBACK_WORD: u32 = 0x0078_0111;
pub const BM1391_STOCK_PLL_SOLVER_FALLBACK_DIVIDER: u8 = 0x0f;
pub const BM1391_STOCK_PLL_SOLVER_FAILURE_STATUS: i32 = -1;
/// The operational caller ignores the solver status and consumes the output
/// word and divider even when the solver reports failure.
pub const BM1391_STOCK_OPERATIONAL_PLL_CHECKS_SOLVER_STATUS: bool = false;
/// Payload passed to the stock register-write helper after byte-swap, enable,
/// and byte-swap. Kept as an independent evidence pin for the fallback path.
pub const BM1391_STOCK_PLL_SOLVER_FALLBACK_REGISTER_PAYLOAD: u32 = 0x4078_0111;

pub const BM1391_STOCK_VOLTAGE_TOKEN_DIVISOR: u16 = 100;
pub const BM1391_STOCK_EEPROM_VOLTAGE_BYTE_OFFSET: u16 = 200;
pub const BM1391_STOCK_EEPROM_VOLTAGE_NUMERATOR: u16 = 5;
pub const BM1391_STOCK_EEPROM_VOLTAGE_SPREAD_LIMIT_MV: u16 = 200;
/// Raw bounds returned by the stock tuning-policy helper. These are evidence,
/// not a safe electrical envelope.
pub const BM1391_STOCK_TUNING_VOLTAGE_TOKEN_MIN: u16 = 1603;
pub const BM1391_STOCK_TUNING_VOLTAGE_TOKEN_MAX: u16 = 2028;

/// The stock IIC-power setters discard their low-level I2C result and have no
/// verified voltage readback. These facts do not describe the isolated framed
/// PIC setter. Never promote them into mutation authority.
pub const BM1391_STOCK_IIC_VOLTAGE_SETTER_PROPAGATES_TRANSPORT_FAILURE: bool = false;
pub const BM1391_STOCK_IIC_SLOW_RAMP_OBSERVES_TRANSPORT_FAILURE: bool = false;
pub const BM1391_STOCK_IIC_VOLTAGE_SETTER_HAS_VERIFIED_READBACK: bool = false;
pub const BM1391_STOCK_STARTUP_CONTRACT_AUTHORIZES_IO: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockRelease {
    S15_20191213,
    T15_20191213,
}

impl Bm1391StockRelease {
    pub const fn version_number(self) -> &'static str {
        match self {
            Self::S15_20191213 => "1.92992.0.14",
            Self::T15_20191213 => "1.92992.0.13",
        }
    }

    pub const fn chips_per_chain(self) -> usize {
        match self {
            Self::S15_20191213 => 72,
            Self::T15_20191213 => 60,
        }
    }

    /// Exact factory rootfs token. `O` is not a numeric frequency.
    pub const fn factory_frequency_token(self) -> &'static str {
        let _ = self;
        "O"
    }

    /// Exact factory rootfs token, interpreted by stock as hundredths of a
    /// volt. Its presence does not prove that applying it is electrically safe.
    pub const fn factory_voltage_token(self) -> u16 {
        match self {
            Self::S15_20191213 => 1650,
            Self::T15_20191213 => 1850,
        }
    }

    /// There is no release-static numeric factory frequency in the held
    /// rootfs. Runtime EEPROM/default-index provenance is required.
    pub const fn factory_fixed_frequency_mhz(self) -> Option<u16> {
        let _ = self;
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockRegisterWrite {
    pub register: u8,
    pub value: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockStartupError {
    MissingFrequencyIndices,
    WrongFrequencyIndexCount { expected: usize, observed: usize },
    FrequencyIndexOutOfRange { position: usize, index: u8 },
    ZeroPllDivider,
}

/// Validate the per-ASIC EEPROM index vector consumed by the exact release.
///
/// The stock table contains indices 0..=178. This validator deliberately has
/// no default fallback because the producer of the runtime per-chain default
/// index was not recovered exactly.
pub fn validate_bm1391_stock_frequency_indices(
    release: Bm1391StockRelease,
    indices: Option<&[u8]>,
) -> Result<(), Bm1391StockStartupError> {
    let indices = indices.ok_or(Bm1391StockStartupError::MissingFrequencyIndices)?;
    let expected = release.chips_per_chain();
    if indices.len() != expected {
        return Err(Bm1391StockStartupError::WrongFrequencyIndexCount {
            expected,
            observed: indices.len(),
        });
    }
    for (position, index) in indices.iter().copied().enumerate() {
        if index > BM1391_STOCK_PLL_TABLE_MAX_INDEX {
            return Err(Bm1391StockStartupError::FrequencyIndexOutOfRange { position, index });
        }
    }
    Ok(())
}

/// Apply the exact operational caller's PLL-word byte transforms.
///
/// Stock first byte-swaps the raw solver/table word into a byte buffer, ORs
/// `0x40` into that buffer's first byte, then byte-swaps the 32-bit buffer when
/// passing it to the register-write helper.
pub const fn bm1391_stock_pll_register_payload(raw_pll_word: u32) -> u32 {
    (raw_pll_word.swap_bytes() | BM1391_STOCK_PLL_ENABLE_BIT).swap_bytes()
}

/// Build the exact four-write operational PLL sequence used by both releases.
///
/// `raw_pll_word` is the word emitted by the solver or selected table row,
/// before the operational caller's byte transforms. This is a data-only plan
/// and cannot execute I/O.
pub const fn bm1391_stock_operational_pll_plan(
    raw_pll_word: u32,
    divider: u8,
) -> Result<[Bm1391StockRegisterWrite; 4], Bm1391StockStartupError> {
    if divider == 0 {
        return Err(Bm1391StockStartupError::ZeroPllDivider);
    }
    let divider_value = BM1391_STOCK_PLL_DIVIDER_FILL | (divider - 1) as u32;
    let divider_write = Bm1391StockRegisterWrite {
        register: BM1391_STOCK_PLL_DIVIDER_REGISTER,
        value: divider_value,
    };
    let pll_write = Bm1391StockRegisterWrite {
        register: BM1391_STOCK_PLL_REGISTER,
        value: bm1391_stock_pll_register_payload(raw_pll_word),
    };
    Ok([divider_write, pll_write, divider_write, pll_write])
}

pub const fn bm1391_stock_solver_fallback_plan() -> [Bm1391StockRegisterWrite; 4] {
    match bm1391_stock_operational_pll_plan(
        BM1391_STOCK_PLL_SOLVER_FALLBACK_WORD,
        BM1391_STOCK_PLL_SOLVER_FALLBACK_DIVIDER,
    ) {
        Ok(plan) => plan,
        Err(_) => unreachable!(),
    }
}

/// Convert the stock fixed-voltage token to millivolts without admitting it as
/// safe. Stock divides the token by the exact double constant 100.0.
pub const fn bm1391_stock_voltage_token_mv(token: u16) -> u32 {
    token as u32 * 10
}

/// Exact EEPROM-byte calibration used by both held releases:
/// `(byte + 200) * 5 / 100` volts, expressed here losslessly in millivolts.
pub const fn bm1391_stock_eeprom_voltage_mv(raw: u8) -> u16 {
    (raw as u16 + BM1391_STOCK_EEPROM_VOLTAGE_BYTE_OFFSET) * 50
}

/// Stock accepts the cross-chain EEPROM-voltage comparison only when its
/// maximum-minus-minimum is no greater than 0.20 V. This observation is not a
/// rail-safety admission.
pub fn bm1391_stock_eeprom_spread_admitted_mv(values_mv: &[u16]) -> bool {
    let Some((&first, rest)) = values_mv.split_first() else {
        return false;
    };
    let (mut min, mut max) = (first, first);
    for value in rest.iter().copied() {
        min = min.min(value);
        max = max.max(value);
    }
    max - min <= BM1391_STOCK_EEPROM_VOLTAGE_SPREAD_LIMIT_MV
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_factory_tokens_are_exact_but_frequency_is_not_numeric() {
        assert_eq!(
            Bm1391StockRelease::S15_20191213.factory_voltage_token(),
            1650
        );
        assert_eq!(
            Bm1391StockRelease::T15_20191213.factory_voltage_token(),
            1850
        );
        assert_eq!(
            Bm1391StockRelease::S15_20191213.factory_frequency_token(),
            "O"
        );
        assert_eq!(
            Bm1391StockRelease::T15_20191213.factory_frequency_token(),
            "O"
        );
        assert_eq!(
            Bm1391StockRelease::S15_20191213.factory_fixed_frequency_mhz(),
            None
        );
        assert_eq!(
            Bm1391StockRelease::T15_20191213.factory_fixed_frequency_mhz(),
            None
        );
        assert_eq!(bm1391_stock_voltage_token_mv(1650), 16_500);
        assert_eq!(bm1391_stock_voltage_token_mv(1850), 18_500);
    }

    #[test]
    fn frequency_indices_are_release_sized_and_fail_closed() {
        assert_eq!(BM1391_STOCK_PLL_TABLE_ENTRY_COUNT, 179);
        assert_eq!(
            BM1391_STOCK_PLL_TABLE_ENTRY_COUNT,
            BM1391_STOCK_PLL_TABLE_MAX_INDEX as usize + 1
        );
        let s15 = [178_u8; 72];
        let t15 = [0_u8; 60];
        assert_eq!(
            validate_bm1391_stock_frequency_indices(Bm1391StockRelease::S15_20191213, Some(&s15)),
            Ok(())
        );
        assert_eq!(
            validate_bm1391_stock_frequency_indices(Bm1391StockRelease::T15_20191213, Some(&t15)),
            Ok(())
        );
        assert_eq!(
            validate_bm1391_stock_frequency_indices(Bm1391StockRelease::S15_20191213, None),
            Err(Bm1391StockStartupError::MissingFrequencyIndices)
        );
        assert_eq!(
            validate_bm1391_stock_frequency_indices(
                Bm1391StockRelease::S15_20191213,
                Some(&[0_u8; 71])
            ),
            Err(Bm1391StockStartupError::WrongFrequencyIndexCount {
                expected: 72,
                observed: 71,
            })
        );

        let mut invalid = [0_u8; 60];
        invalid[31] = 179;
        assert_eq!(
            validate_bm1391_stock_frequency_indices(
                Bm1391StockRelease::T15_20191213,
                Some(&invalid)
            ),
            Err(Bm1391StockStartupError::FrequencyIndexOutOfRange {
                position: 31,
                index: 179,
            })
        );
    }

    #[test]
    fn solver_fallback_write_order_is_divider_pll_twice() {
        assert_eq!(BM1391_STOCK_PLL_SOLVER_FAILURE_STATUS, -1);
        assert!(!BM1391_STOCK_OPERATIONAL_PLL_CHECKS_SOLVER_STATUS);
        assert_eq!(
            bm1391_stock_pll_register_payload(BM1391_STOCK_PLL_SOLVER_FALLBACK_WORD),
            BM1391_STOCK_PLL_SOLVER_FALLBACK_REGISTER_PAYLOAD
        );
        assert_eq!(bm1391_stock_pll_register_payload(0x1122_3344), 0x5122_3344);
        assert_eq!(
            bm1391_stock_solver_fallback_plan(),
            [
                Bm1391StockRegisterWrite {
                    register: 0x70,
                    value: 0x0f0f_0f0e,
                },
                Bm1391StockRegisterWrite {
                    register: 0x08,
                    value: 0x4078_0111,
                },
                Bm1391StockRegisterWrite {
                    register: 0x70,
                    value: 0x0f0f_0f0e,
                },
                Bm1391StockRegisterWrite {
                    register: 0x08,
                    value: 0x4078_0111,
                },
            ]
        );
        assert_eq!(
            bm1391_stock_operational_pll_plan(0, 0),
            Err(Bm1391StockStartupError::ZeroPllDivider)
        );
    }

    #[test]
    fn voltage_calibration_and_spread_boundary_are_exact() {
        assert_eq!(BM1391_STOCK_VOLTAGE_TOKEN_DIVISOR, 100);
        assert_eq!(BM1391_STOCK_EEPROM_VOLTAGE_BYTE_OFFSET, 200);
        assert_eq!(BM1391_STOCK_EEPROM_VOLTAGE_NUMERATOR, 5);
        assert_eq!(bm1391_stock_eeprom_voltage_mv(0), 10_000);
        assert_eq!(bm1391_stock_eeprom_voltage_mv(255), 22_750);
        assert!(bm1391_stock_eeprom_spread_admitted_mv(&[16_500, 16_700]));
        assert!(!bm1391_stock_eeprom_spread_admitted_mv(&[16_500, 16_701]));
        assert!(!bm1391_stock_eeprom_spread_admitted_mv(&[]));
        assert_eq!(BM1391_STOCK_TUNING_VOLTAGE_TOKEN_MIN, 1603);
        assert_eq!(BM1391_STOCK_TUNING_VOLTAGE_TOKEN_MAX, 2028);
        assert!(!BM1391_STOCK_IIC_VOLTAGE_SETTER_PROPAGATES_TRANSPORT_FAILURE);
        assert!(!BM1391_STOCK_IIC_SLOW_RAMP_OBSERVES_TRANSPORT_FAILURE);
        assert!(!BM1391_STOCK_IIC_VOLTAGE_SETTER_HAS_VERIFIED_READBACK);
        assert!(!BM1391_STOCK_STARTUP_CONTRACT_AUTHORIZES_IO);
    }
}
