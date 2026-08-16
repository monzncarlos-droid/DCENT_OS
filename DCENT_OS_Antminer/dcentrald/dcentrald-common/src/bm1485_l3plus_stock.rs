//! Exact-release BM1485/L3+ UART and address-assignment facts.
//!
//! This is a pure replay of the held stock L3+ `cgminer` compiled on
//! 2017-04-19. It deliberately does not identify a physical board or authorize
//! UART access, ASIC writes, work dispatch, voltage mutation, or mining.

use crate::stock_fpga_policy::stock_bitmain_crc5;

pub const BM1485_L3PLUS_STOCK_CGMINER_SIZE: usize = 330_836;
pub const BM1485_L3PLUS_STOCK_CGMINER_MD5: &str = "364f38dbe9bb73f259ec37698237d47f";
pub const BM1485_L3PLUS_STOCK_CGMINER_SHA256: &str =
    "eb5872ea31257be343495b45d02d2d3a27756ba21b008e42d48a3dfaaa2a8889";
pub const BM1485_L3PLUS_STOCK_CGMINER_BUILD_ID: &str = "20ad58a265e536c0287f420b186879ceadab94b1";
pub const BM1485_L3PLUS_STOCK_COMPILE_TIME: &str = "Wed Apr 19 12:51:35 CST 2017";

pub const BM1485_L3PLUS_STOCK_CHAIN_COUNT: usize = 4;
pub const BM1485_L3PLUS_STOCK_CHIPS_PER_CHAIN: usize = 72;
pub const BM1485_L3PLUS_STOCK_HOST_BAUD: u32 = 115_200;
pub const BM1485_L3PLUS_STOCK_CHIP_BT8D: u8 = 26;
pub const BM1485_L3PLUS_STOCK_CHIP_REFERENCE_HZ: u32 = 25_000_000;
pub const BM1485_L3PLUS_STOCK_CHIP_BAUD: u32 =
    BM1485_L3PLUS_STOCK_CHIP_REFERENCE_HZ / ((BM1485_L3PLUS_STOCK_CHIP_BT8D as u32 + 1) * 8);
pub const BM1485_L3PLUS_STOCK_ADDRESS_INTERVAL: u8 = 3;
pub const BM1485_L3PLUS_STOCK_LAST_CHIP_ADDRESS: u8 = 213;

pub const BM1485_REGISTER_MISC_CONTROL: u8 = 0x18;
pub const BM1485_WRITE_BROADCAST_HEADER: u8 = 0x51;
pub const BM1485_WRITE_ADDRESSED_HEADER: u8 = 0x41;
pub const BM1485_WRITE_FRAME_LENGTH: u8 = 0x08;
pub const BM1485_STOCK_MISC_BROADCAST_VALUE: u32 = 0x103a_4041;
pub const BM1485_STOCK_MISC_ADDRESSED_VALUE: u32 = 0x707a_4041;
pub const BM1485_STOCK_MISC_FIRST_ADDRESS: u8 = 0x0c;
pub const BM1485_STOCK_MISC_SECOND_ADDRESS: u8 = 0xc9;
pub const BM1485_STOCK_MISC_WRITE_DELAY_MS: u32 = 2;
pub const BM1485_STOCK_MISC_FINAL_DELAY_MS: u32 = 100;

/// Exact stock release behavior: no post-enumeration high-speed baud switch is
/// present. This does not prove that every L3/L3+/L3++ firmware shares it.
pub const BM1485_L3PLUS_STOCK_HAS_HIGH_SPEED_BAUD_TRANSITION: bool = false;

/// Immutable authority boundary for this artifact-scoped static evidence.
pub const BM1485_L3PLUS_STOCK_IDENTIFIES_PHYSICAL_BOARD: bool = false;
pub const BM1485_L3PLUS_STOCK_AUTHORIZES_UART_IO: bool = false;
pub const BM1485_L3PLUS_STOCK_AUTHORIZES_ASIC_WRITES: bool = false;
pub const BM1485_L3PLUS_STOCK_AUTHORIZES_RAIL_MUTATION: bool = false;
pub const BM1485_L3PLUS_STOCK_AUTHORIZES_WORK_DISPATCH: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3PlusStockError {
    ChipIndexOutOfRange(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485StockMiscControlPlan {
    pub broadcast: [u8; 9],
    pub first_addressed: [u8; 9],
    pub second_addressed: [u8; 9],
    /// Exact delay after each of the three writes, including the broadcast.
    pub delay_after_each_write_ms: u32,
    pub final_delay_ms: u32,
}

impl Bm1485StockMiscControlPlan {
    pub const fn authorizes_execution(self) -> bool {
        false
    }
}

/// Exact `FUN_0003db34` result for the held 72-chip release:
/// `floor(256 / 72) == 3`.
pub const fn bm1485_l3plus_stock_address_interval() -> u8 {
    bm1485_l3plus_stock_address_interval_for_configured_count(
        BM1485_L3PLUS_STOCK_CHIPS_PER_CHAIN as u8,
    )
}

/// Exact stock interval calculation, including its zero-count fallback and
/// byte truncation. This is observational replay, not a safe generic policy.
pub const fn bm1485_l3plus_stock_address_interval_for_configured_count(configured_count: u8) -> u8 {
    if configured_count == 0 {
        7
    } else {
        (256_u32 / configured_count as u32) as u8
    }
}

/// Exact held-release address publication: `index * 3`, for indexes 0..71.
pub fn bm1485_l3plus_stock_chip_address(chip_index: usize) -> Result<u8, Bm1485L3PlusStockError> {
    if chip_index >= BM1485_L3PLUS_STOCK_CHIPS_PER_CHAIN {
        return Err(Bm1485L3PlusStockError::ChipIndexOutOfRange(chip_index));
    }
    Ok((chip_index as u8) * BM1485_L3PLUS_STOCK_ADDRESS_INTERVAL)
}

fn misc_write_frame(broadcast: bool, chip_address: u8, value: u32) -> [u8; 9] {
    let mut frame = [0_u8; 9];
    frame[0] = if broadcast {
        BM1485_WRITE_BROADCAST_HEADER
    } else {
        BM1485_WRITE_ADDRESSED_HEADER
    };
    frame[1] = BM1485_WRITE_FRAME_LENGTH;
    frame[2] = if broadcast { 0 } else { chip_address };
    frame[3] = BM1485_REGISTER_MISC_CONTROL;
    // Exact ARM host behavior in FUN_0003d894: the native u32 is copied to
    // the frame, so the little-endian AM335x emits least-significant byte first.
    frame[4..8].copy_from_slice(&value.to_le_bytes());
    frame[8] = stock_bitmain_crc5(&frame[..8], 64);
    frame
}

/// The complete hardware-facing MISC_CONTROL write spine recovered from
/// `FUN_0003e158`. It preserves `bt8d=26`; it is not a baud-upgrade plan.
pub fn bm1485_l3plus_stock_misc_control_plan() -> Bm1485StockMiscControlPlan {
    Bm1485StockMiscControlPlan {
        broadcast: misc_write_frame(true, 0, BM1485_STOCK_MISC_BROADCAST_VALUE),
        first_addressed: misc_write_frame(
            false,
            BM1485_STOCK_MISC_FIRST_ADDRESS,
            BM1485_STOCK_MISC_ADDRESSED_VALUE,
        ),
        second_addressed: misc_write_frame(
            false,
            BM1485_STOCK_MISC_SECOND_ADDRESS,
            BM1485_STOCK_MISC_ADDRESSED_VALUE,
        ),
        delay_after_each_write_ms: BM1485_STOCK_MISC_WRITE_DELAY_MS,
        final_delay_ms: BM1485_STOCK_MISC_FINAL_DELAY_MS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_artifact_and_no_authority_boundary_are_pinned() {
        assert_eq!(BM1485_L3PLUS_STOCK_CGMINER_SIZE, 330_836);
        assert_eq!(
            BM1485_L3PLUS_STOCK_CGMINER_MD5,
            "364f38dbe9bb73f259ec37698237d47f"
        );
        assert_eq!(
            BM1485_L3PLUS_STOCK_CGMINER_SHA256,
            "eb5872ea31257be343495b45d02d2d3a27756ba21b008e42d48a3dfaaa2a8889"
        );
        assert_eq!(
            BM1485_L3PLUS_STOCK_CGMINER_BUILD_ID,
            "20ad58a265e536c0287f420b186879ceadab94b1"
        );
        assert_eq!(
            BM1485_L3PLUS_STOCK_COMPILE_TIME,
            "Wed Apr 19 12:51:35 CST 2017"
        );
        assert_eq!(BM1485_L3PLUS_STOCK_CHAIN_COUNT, 4);
        assert!(!BM1485_L3PLUS_STOCK_IDENTIFIES_PHYSICAL_BOARD);
        assert!(!BM1485_L3PLUS_STOCK_AUTHORIZES_UART_IO);
        assert!(!BM1485_L3PLUS_STOCK_AUTHORIZES_ASIC_WRITES);
        assert!(!BM1485_L3PLUS_STOCK_AUTHORIZES_RAIL_MUTATION);
        assert!(!BM1485_L3PLUS_STOCK_AUTHORIZES_WORK_DISPATCH);
    }

    #[test]
    fn held_stock_release_stays_at_nominal_host_and_bt8d_26_chip_baud() {
        assert_eq!(BM1485_L3PLUS_STOCK_HOST_BAUD, 115_200);
        assert_eq!(BM1485_L3PLUS_STOCK_CHIP_BT8D, 26);
        assert_eq!(BM1485_L3PLUS_STOCK_CHIP_BAUD, 115_740);
        assert!(!BM1485_L3PLUS_STOCK_HAS_HIGH_SPEED_BAUD_TRANSITION);
    }

    #[test]
    fn seventy_two_chip_address_assignment_is_stride_three_and_bounded() {
        assert_eq!(bm1485_l3plus_stock_address_interval(), 3);
        assert_eq!(
            bm1485_l3plus_stock_address_interval_for_configured_count(0),
            7
        );
        assert_eq!(
            bm1485_l3plus_stock_address_interval_for_configured_count(1),
            0,
            "stock truncates 256 to a byte"
        );
        assert_eq!(
            bm1485_l3plus_stock_address_interval_for_configured_count(2),
            128
        );
        assert_eq!(
            bm1485_l3plus_stock_address_interval_for_configured_count(72),
            3
        );
        assert_eq!(
            bm1485_l3plus_stock_address_interval_for_configured_count(255),
            1
        );
        assert_eq!(bm1485_l3plus_stock_chip_address(0), Ok(0));
        assert_eq!(bm1485_l3plus_stock_chip_address(1), Ok(3));
        assert_eq!(bm1485_l3plus_stock_chip_address(71), Ok(213));
        assert_eq!(
            bm1485_l3plus_stock_chip_address(72),
            Err(Bm1485L3PlusStockError::ChipIndexOutOfRange(72))
        );
    }

    #[test]
    fn misc_control_frames_are_little_endian_and_preserve_bt8d_26() {
        let plan = bm1485_l3plus_stock_misc_control_plan();
        assert_eq!(
            plan.broadcast,
            [0x51, 0x08, 0x00, 0x18, 0x41, 0x40, 0x3a, 0x10, 0x00]
        );
        assert_eq!(
            plan.first_addressed,
            [0x41, 0x08, 0x0c, 0x18, 0x41, 0x40, 0x7a, 0x70, 0x10]
        );
        assert_eq!(
            plan.second_addressed,
            [0x41, 0x08, 0xc9, 0x18, 0x41, 0x40, 0x7a, 0x70, 0x02]
        );
        for frame in [plan.broadcast, plan.first_addressed, plan.second_addressed] {
            assert_eq!(frame[6] & 0x1f, BM1485_L3PLUS_STOCK_CHIP_BT8D);
        }
        assert_eq!(plan.delay_after_each_write_ms, 2);
        assert_eq!(plan.final_delay_ms, 100);
        assert!(!plan.authorizes_execution());
    }
}
