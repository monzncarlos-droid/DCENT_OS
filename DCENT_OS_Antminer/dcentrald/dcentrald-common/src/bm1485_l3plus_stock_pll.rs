//! Exact-release BM1485/L3+ stock PLL lookup and publication replay.
//!
//! The held 2017 L3+ `cgminer` contains a 100-row frequency table and
//! broadcasts the selected word to register `0x08` on every active chain.
//! This module preserves the stock lookup-miss behavior and the misleading
//! requested-frequency shadow, but never authorizes UART access or ASIC writes.

use crate::bm1485_l3plus_stock::BM1485_L3PLUS_STOCK_CHAIN_COUNT;
use crate::stock_fpga_policy::stock_bitmain_crc5;

pub const BM1485_STOCK_PLL_REGISTER: u8 = 0x08;
pub const BM1485_STOCK_PLL_TABLE_ROWS: usize = 100;
pub const BM1485_STOCK_PLL_TABLE_RAW_SHA256: &str =
    "588e7194c85961f9fea836241ff0c2f41e93983aee0d317a291045387f83e8e7";
pub const BM1485_STOCK_PLL_TABLE_RAW_FNV1A64: u64 = 0x534e_51ce_083e_aa2d;
pub const BM1485_STOCK_PLL_LOOKUP_MISS_INDEX: usize = 4;
pub const BM1485_STOCK_PLL_LOOKUP_MISS_FREQUENCY_MHZ: u16 = 125;
pub const BM1485_STOCK_PLL_LOOKUP_MISS_VALUE: u32 = 0x0046_0271;
pub const BM1485_STOCK_PLL_DELAY_AFTER_CHAIN_WRITE_US: u32 = 10_000;
pub const BM1485_L3PLUS_FACTORY_FREQUENCY_MHZ: u16 = 384;
pub const BM1485_L3PLUS_COMPILED_OPTION_DEFAULT_MHZ: u16 = 100;

pub const BM1485_STOCK_PLL_IDENTIFIES_PHYSICAL_BOARD: bool = false;
pub const BM1485_STOCK_PLL_AUTHORIZES_UART_IO: bool = false;
pub const BM1485_STOCK_PLL_AUTHORIZES_ASIC_WRITES: bool = false;
pub const BM1485_STOCK_PLL_AUTHORIZES_RAIL_MUTATION: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485StockPllEntry {
    pub frequency_mhz: u16,
    /// Exact opaque register word. Field-level PLL semantics are not promoted.
    pub register_value: u32,
}

/// Byte-exact rows at virtual address `0x54d88` in the held stock `cgminer`.
pub const BM1485_STOCK_PLL_TABLE: [Bm1485StockPllEntry; BM1485_STOCK_PLL_TABLE_ROWS] = [
    Bm1485StockPllEntry {
        frequency_mhz: 100,
        register_value: 0x0040_0242,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 106,
        register_value: 0x0044_0242,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 112,
        register_value: 0x0048_0242,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 118,
        register_value: 0x0042_0271,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 125,
        register_value: 0x0046_0271,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 131,
        register_value: 0x003f_0261,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 137,
        register_value: 0x0042_0232,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 142,
        register_value: 0x0044_0261,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 148,
        register_value: 0x0047_0261,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 154,
        register_value: 0x004a_0261,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 160,
        register_value: 0x004d_0232,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 166,
        register_value: 0x005d_0271,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 172,
        register_value: 0x0045_0251,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 178,
        register_value: 0x0047_0251,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 184,
        register_value: 0x0067_0271,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 190,
        register_value: 0x005b_0232,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 196,
        register_value: 0x005e_0261,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 200,
        register_value: 0x0040_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 206,
        register_value: 0x0042_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 212,
        register_value: 0x0044_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 217,
        register_value: 0x0057_0251,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 223,
        register_value: 0x006b_0232,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 229,
        register_value: 0x006e_0261,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 235,
        register_value: 0x0071_0232,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 242,
        register_value: 0x0061_0251,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 248,
        register_value: 0x0077_0232,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 254,
        register_value: 0x007a_0232,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 260,
        register_value: 0x007d_0232,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 267,
        register_value: 0x006b_0251,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 273,
        register_value: 0x006d_0251,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 279,
        register_value: 0x0043_0231,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 285,
        register_value: 0x0072_0251,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 294,
        register_value: 0x002f_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 300,
        register_value: 0x0060_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 306,
        register_value: 0x0031_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 312,
        register_value: 0x0064_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 319,
        register_value: 0x0066_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 325,
        register_value: 0x004e_0231,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 331,
        register_value: 0x006a_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 338,
        register_value: 0x0051_0231,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 344,
        register_value: 0x006e_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 350,
        register_value: 0x0054_0231,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 353,
        register_value: 0x0071_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 356,
        register_value: 0x0072_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 359,
        register_value: 0x0073_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 362,
        register_value: 0x0057_0231,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 366,
        register_value: 0x0075_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 369,
        register_value: 0x0076_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 375,
        register_value: 0x005a_0231,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 378,
        register_value: 0x0079_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 381,
        register_value: 0x003d_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 384,
        register_value: 0x007b_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 387,
        register_value: 0x005d_0231,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 391,
        register_value: 0x007d_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 394,
        register_value: 0x003f_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 397,
        register_value: 0x007f_0241,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 400,
        register_value: 0x0060_0231,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 406,
        register_value: 0x0041_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 412,
        register_value: 0x0042_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 419,
        register_value: 0x0043_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 425,
        register_value: 0x0044_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 431,
        register_value: 0x0045_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 437,
        register_value: 0x0046_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 438,
        register_value: 0x0046_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 444,
        register_value: 0x0047_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 450,
        register_value: 0x0048_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 456,
        register_value: 0x0049_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 462,
        register_value: 0x004a_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 469,
        register_value: 0x004b_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 475,
        register_value: 0x004c_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 481,
        register_value: 0x004d_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 487,
        register_value: 0x004e_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 494,
        register_value: 0x004f_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 500,
        register_value: 0x0050_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 506,
        register_value: 0x0051_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 512,
        register_value: 0x0052_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 519,
        register_value: 0x0053_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 525,
        register_value: 0x0054_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 531,
        register_value: 0x0055_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 537,
        register_value: 0x0056_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 544,
        register_value: 0x0057_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 550,
        register_value: 0x0058_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 556,
        register_value: 0x0059_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 562,
        register_value: 0x005a_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 569,
        register_value: 0x005b_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 575,
        register_value: 0x005c_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 581,
        register_value: 0x005d_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 587,
        register_value: 0x005e_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 588,
        register_value: 0x005e_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 594,
        register_value: 0x005f_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 600,
        register_value: 0x0060_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 606,
        register_value: 0x0061_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 612,
        register_value: 0x0062_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 619,
        register_value: 0x0063_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 625,
        register_value: 0x0064_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 631,
        register_value: 0x0065_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 637,
        register_value: 0x0066_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 638,
        register_value: 0x0066_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 644,
        register_value: 0x0067_0221,
    },
    Bm1485StockPllEntry {
        frequency_mhz: 650,
        register_value: 0x0068_0221,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485StockPllSelectionSource {
    ExactTableRow,
    /// Stock silently selects row 4 while retaining the unsupported request in
    /// its software shadow. Clean executors must not treat this as admission.
    StockLookupMissFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485StockPllSelection {
    pub requested_frequency_mhz: u16,
    pub selected_index: usize,
    pub selected_entry: Bm1485StockPllEntry,
    pub shadow_frequency_mhz: u16,
    pub source: Bm1485StockPllSelectionSource,
}

impl Bm1485StockPllSelection {
    pub const fn authorizes_execution(self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485StockPllChainWrite {
    pub chain_slot: u8,
    /// Exact nine-byte BM1485 broadcast register-write frame.
    pub frame: [u8; 9],
    /// Stock updates this shadow to the request even on a table miss.
    pub shadow_frequency_mhz: u16,
    pub delay_after_write_us: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485StockPllWritePlan {
    pub selection: Bm1485StockPllSelection,
    /// Slot-preserving plan; inactive slots remain `None`.
    pub chain_writes: [Option<Bm1485StockPllChainWrite>; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
}

impl Bm1485StockPllWritePlan {
    pub const fn authorizes_execution(self) -> bool {
        false
    }
}

pub fn bm1485_stock_pll_select(requested_frequency_mhz: u16) -> Bm1485StockPllSelection {
    let exact = BM1485_STOCK_PLL_TABLE
        .iter()
        .position(|entry| entry.frequency_mhz == requested_frequency_mhz);
    let (selected_index, source) = match exact {
        Some(index) => (index, Bm1485StockPllSelectionSource::ExactTableRow),
        None => (
            BM1485_STOCK_PLL_LOOKUP_MISS_INDEX,
            Bm1485StockPllSelectionSource::StockLookupMissFallback,
        ),
    };
    Bm1485StockPllSelection {
        requested_frequency_mhz,
        selected_index,
        selected_entry: BM1485_STOCK_PLL_TABLE[selected_index],
        shadow_frequency_mhz: requested_frequency_mhz,
        source,
    }
}

fn pll_broadcast_frame(register_value: u32) -> [u8; 9] {
    let mut frame = [0_u8; 9];
    frame[0] = 0x51;
    frame[1] = 0x08;
    frame[2] = 0;
    frame[3] = BM1485_STOCK_PLL_REGISTER;
    frame[4..8].copy_from_slice(&register_value.to_le_bytes());
    frame[8] = stock_bitmain_crc5(&frame[..8], 64);
    frame
}

/// Replays the hardware-facing spine of stock `FUN_0003e25c` without I/O.
pub fn bm1485_stock_pll_write_plan(
    requested_frequency_mhz: u16,
    active_chains: [bool; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
) -> Bm1485StockPllWritePlan {
    let selection = bm1485_stock_pll_select(requested_frequency_mhz);
    let frame = pll_broadcast_frame(selection.selected_entry.register_value);
    let mut chain_writes = [None; BM1485_L3PLUS_STOCK_CHAIN_COUNT];
    for (slot, active) in active_chains.into_iter().enumerate() {
        if active {
            chain_writes[slot] = Some(Bm1485StockPllChainWrite {
                chain_slot: slot as u8,
                frame,
                shadow_frequency_mhz: selection.shadow_frequency_mhz,
                delay_after_write_us: BM1485_STOCK_PLL_DELAY_AFTER_CHAIN_WRITE_US,
            });
        }
    }
    Bm1485StockPllWritePlan {
        selection,
        chain_writes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_table_shape_boundaries_duplicates_and_hash_are_pinned() {
        assert_eq!(BM1485_STOCK_PLL_TABLE.len(), 100);
        assert_eq!(
            BM1485_STOCK_PLL_TABLE[0],
            Bm1485StockPllEntry {
                frequency_mhz: 100,
                register_value: 0x0040_0242,
            }
        );
        assert_eq!(
            BM1485_STOCK_PLL_TABLE[99],
            Bm1485StockPllEntry {
                frequency_mhz: 650,
                register_value: 0x0068_0221,
            }
        );
        assert_eq!(
            BM1485_STOCK_PLL_TABLE[62].register_value,
            BM1485_STOCK_PLL_TABLE[63].register_value
        );
        assert_eq!(
            BM1485_STOCK_PLL_TABLE[87].register_value,
            BM1485_STOCK_PLL_TABLE[88].register_value
        );
        assert_eq!(
            BM1485_STOCK_PLL_TABLE[96].register_value,
            BM1485_STOCK_PLL_TABLE[97].register_value
        );
        assert_eq!(
            BM1485_STOCK_PLL_TABLE_RAW_SHA256,
            "588e7194c85961f9fea836241ff0c2f41e93983aee0d317a291045387f83e8e7"
        );
        let mut fnv = 0xcbf2_9ce4_8422_2325_u64;
        for entry in BM1485_STOCK_PLL_TABLE {
            for byte in (entry.frequency_mhz as u32)
                .to_le_bytes()
                .into_iter()
                .chain(entry.register_value.to_le_bytes())
            {
                fnv ^= u64::from(byte);
                fnv = fnv.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        assert_eq!(fnv, BM1485_STOCK_PLL_TABLE_RAW_FNV1A64);
    }

    #[test]
    fn factory_384_mhz_selects_exact_row_51_and_little_endian_frame() {
        let plan = bm1485_stock_pll_write_plan(
            BM1485_L3PLUS_FACTORY_FREQUENCY_MHZ,
            [true, true, true, true],
        );
        assert_eq!(plan.selection.selected_index, 51);
        assert_eq!(plan.selection.selected_entry.register_value, 0x007b_0241);
        assert_eq!(
            plan.selection.source,
            Bm1485StockPllSelectionSource::ExactTableRow
        );
        assert_eq!(
            plan.chain_writes[0].unwrap().frame,
            [0x51, 0x08, 0x00, 0x08, 0x41, 0x02, 0x7b, 0x00, 0x0f]
        );
        assert_eq!(plan.chain_writes[3].unwrap().delay_after_write_us, 10_000);
        assert!(!plan.authorizes_execution());
    }

    #[test]
    fn lookup_miss_preserves_stock_fallback_and_misleading_shadow() {
        let selection = bm1485_stock_pll_select(385);
        assert_eq!(selection.selected_index, 4);
        assert_eq!(selection.selected_entry.frequency_mhz, 125);
        assert_eq!(selection.selected_entry.register_value, 0x0046_0271);
        assert_eq!(selection.shadow_frequency_mhz, 385);
        assert_eq!(
            selection.source,
            Bm1485StockPllSelectionSource::StockLookupMissFallback
        );
        assert!(!selection.authorizes_execution());
    }

    #[test]
    fn inactive_slots_are_not_written_and_slot_order_is_preserved() {
        let plan = bm1485_stock_pll_write_plan(600, [false, true, false, true]);
        assert_eq!(plan.chain_writes[0], None);
        assert_eq!(plan.chain_writes[1].unwrap().chain_slot, 1);
        assert_eq!(plan.chain_writes[2], None);
        assert_eq!(plan.chain_writes[3].unwrap().chain_slot, 3);
        assert_eq!(plan.chain_writes[1].unwrap().shadow_frequency_mhz, 600);
    }

    #[test]
    fn artifact_scope_never_mints_runtime_or_rail_authority() {
        assert!(!BM1485_STOCK_PLL_IDENTIFIES_PHYSICAL_BOARD);
        assert!(!BM1485_STOCK_PLL_AUTHORIZES_UART_IO);
        assert!(!BM1485_STOCK_PLL_AUTHORIZES_ASIC_WRITES);
        assert!(!BM1485_STOCK_PLL_AUTHORIZES_RAIL_MUTATION);
    }
}
