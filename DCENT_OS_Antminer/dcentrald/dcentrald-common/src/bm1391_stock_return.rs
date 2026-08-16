//! Pure decoder and outstanding-work binding for the stock BM1391 FPGA return
//! path used by the held S15 and T15 cgminer binaries.
//!
//! Exact S15 `FUN_00046780` and T15 `FUN_000467b4` read two little-endian
//! 32-bit words from the FPGA FIFO. Word-zero bit 31 selects nonce versus
//! register traffic. The two miners have the same record, queue, and binding
//! layout; this module deliberately does not promote their different stock
//! enumeration counts into physical board geometry.
//!
//! This is an offline codec only. It owns no FPGA mapping, DMA buffer, chain,
//! voltage rail, or runtime admission and cannot authorize hardware I/O.

pub const BM1391_STOCK_FPGA_RETURN_RECORD_LEN: usize = 8;
pub const BM1391_STOCK_RETURN_NONCE_BIT: u32 = 1 << 31;
pub const BM1391_STOCK_NONCE_VALID_BIT: u32 = 1 << 7;
pub const BM1391_STOCK_REGISTER_CRC_ERROR_BIT: u32 = 1 << 6;
pub const BM1391_STOCK_RETURN_CHAIN_MASK: u32 = 0x0f;
pub const BM1391_STOCK_WORK_ID_MASK: u32 = 0x7fff;
pub const BM1391_STOCK_REGISTER_CRC5_MASK: u32 = 0x1f;
pub const BM1391_STOCK_REGISTER_TYPE_MASK: u32 = 0x03;
pub const BM1391_STOCK_OUTSTANDING_WORK_RECORD_LEN: usize = 0x40;
pub const BM1391_STOCK_BOUND_NONCE_RECORD_LEN: usize = 0x3c;
pub const BM1391_STOCK_RETURN_RING_CAPACITY: u16 = 511;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockNonceReturn {
    pub chain_slot: u8,
    pub work_id: u16,
    pub nonce: u32,
    /// Exact packet bit checked by stock before binding the return to work.
    pub stock_valid: bool,
    /// Raw bit 6 is retained because the BM1391 stock nonce branch does not
    /// test it. Calling it a CRC failure here would import BM1396 semantics.
    pub status_bit6_set: bool,
}

impl Bm1391StockNonceReturn {
    /// Exact stock nonce-branch admission. The separate global enable is a
    /// caller-owned runtime state bit in both held miners.
    pub const fn stock_binding_eligible(self, global_nonce_path_enabled: bool) -> bool {
        global_nonce_path_enabled && self.stock_valid
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockRegisterReturn {
    pub chain_slot: u8,
    pub register: u8,
    pub chip_address: u8,
    pub crc5: u8,
    pub register_type: u8,
    pub value: u32,
    pub fpga_crc_error: bool,
}

impl Bm1391StockRegisterReturn {
    /// Exact stock queue gate after the caller has rejected CRC-error records.
    /// Register type bits are logged by stock but do not suppress queuing.
    pub const fn stock_queue_eligible(self, include_register_0x40: bool) -> bool {
        !self.fpga_crc_error && (include_register_0x40 || self.register != 0x40)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockFpgaReturn {
    Nonce(Bm1391StockNonceReturn),
    Register(Bm1391StockRegisterReturn),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockReturnDecodeError {
    WrongLength { observed: usize },
}

pub fn decode_bm1391_stock_fpga_return(
    record: &[u8],
) -> Result<Bm1391StockFpgaReturn, Bm1391StockReturnDecodeError> {
    let record: &[u8; BM1391_STOCK_FPGA_RETURN_RECORD_LEN] =
        record
            .try_into()
            .map_err(|_| Bm1391StockReturnDecodeError::WrongLength {
                observed: record.len(),
            })?;
    let word0 = u32::from_le_bytes([record[0], record[1], record[2], record[3]]);
    let word1 = u32::from_le_bytes([record[4], record[5], record[6], record[7]]);

    if word0 & BM1391_STOCK_RETURN_NONCE_BIT != 0 {
        return Ok(Bm1391StockFpgaReturn::Nonce(Bm1391StockNonceReturn {
            chain_slot: (word0 & BM1391_STOCK_RETURN_CHAIN_MASK) as u8,
            work_id: ((word0 >> 16) & BM1391_STOCK_WORK_ID_MASK) as u16,
            nonce: word1,
            stock_valid: word0 & BM1391_STOCK_NONCE_VALID_BIT != 0,
            status_bit6_set: word0 & BM1391_STOCK_REGISTER_CRC_ERROR_BIT != 0,
        }));
    }

    Ok(Bm1391StockFpgaReturn::Register(Bm1391StockRegisterReturn {
        chain_slot: (word0 & BM1391_STOCK_RETURN_CHAIN_MASK) as u8,
        register: ((word0 >> 8) & 0xff) as u8,
        chip_address: ((word0 >> 16) & 0xff) as u8,
        crc5: ((word0 >> 24) & BM1391_STOCK_REGISTER_CRC5_MASK) as u8,
        register_type: ((word0 >> 29) & BM1391_STOCK_REGISTER_TYPE_MASK) as u8,
        value: word1,
        fpga_crc_error: word0 & BM1391_STOCK_REGISTER_CRC_ERROR_BIT != 0,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1391StockBoundNonce {
    pub job_id: u32,
    pub work_id: u16,
    pub outstanding_word_04: u32,
    pub outstanding_word_08: u32,
    pub outstanding_word_0c: u32,
    pub nonce: u32,
    pub chain_slot: u8,
    pub outstanding_tail_20_3f: [u8; 32],
}

impl Bm1391StockBoundNonce {
    /// Exact 60-byte logical queue record written by both stock miners.
    pub fn to_stock_queue_bytes(&self) -> [u8; BM1391_STOCK_BOUND_NONCE_RECORD_LEN] {
        let mut out = [0u8; BM1391_STOCK_BOUND_NONCE_RECORD_LEN];
        out[0x00..0x04].copy_from_slice(&self.job_id.to_le_bytes());
        out[0x04..0x08].copy_from_slice(&u32::from(self.work_id).to_le_bytes());
        out[0x08..0x0c].copy_from_slice(&self.outstanding_word_04.to_le_bytes());
        out[0x0c..0x10].copy_from_slice(&self.outstanding_word_08.to_le_bytes());
        out[0x10..0x14].copy_from_slice(&self.outstanding_word_0c.to_le_bytes());
        out[0x14..0x18].copy_from_slice(&self.nonce.to_le_bytes());
        out[0x18..0x1c].copy_from_slice(&u32::from(self.chain_slot).to_le_bytes());
        out[0x1c..0x3c].copy_from_slice(&self.outstanding_tail_20_3f);
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockWorkBindError {
    NonceNotStockEligible,
    WrongOutstandingLength { observed: usize },
}

/// Bind an exact stock-eligible nonce return to the caller-selected 64-byte
/// outstanding-work snapshot. Selecting the snapshot by `work_id` remains the
/// caller's responsibility; this function refuses to pretend it owns the
/// stock miners' global table.
pub fn bind_bm1391_stock_nonce(
    nonce: Bm1391StockNonceReturn,
    global_nonce_path_enabled: bool,
    outstanding: &[u8],
) -> Result<Bm1391StockBoundNonce, Bm1391StockWorkBindError> {
    if !nonce.stock_binding_eligible(global_nonce_path_enabled) {
        return Err(Bm1391StockWorkBindError::NonceNotStockEligible);
    }
    let outstanding: &[u8; BM1391_STOCK_OUTSTANDING_WORK_RECORD_LEN] = outstanding
        .try_into()
        .map_err(|_| Bm1391StockWorkBindError::WrongOutstandingLength {
            observed: outstanding.len(),
        })?;
    let read_u32 = |offset: usize| {
        u32::from_le_bytes([
            outstanding[offset],
            outstanding[offset + 1],
            outstanding[offset + 2],
            outstanding[offset + 3],
        ])
    };
    let mut tail = [0u8; 32];
    tail.copy_from_slice(&outstanding[0x20..0x40]);
    Ok(Bm1391StockBoundNonce {
        job_id: read_u32(0x00),
        work_id: nonce.work_id,
        outstanding_word_04: read_u32(0x04),
        outstanding_word_08: read_u32(0x08),
        outstanding_word_0c: read_u32(0x0c),
        nonce: nonce.nonce,
        chain_slot: nonce.chain_slot,
        outstanding_tail_20_3f: tail,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockRingState {
    pub write_index: u16,
    pub queued: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockRingError {
    WriteIndexOutOfRange { observed: u16 },
    QueuedCountOutOfRange { observed: u16 },
    Full,
}

/// Clean fail-closed post-enqueue state. Index/count arithmetic matches stock
/// below capacity, but unlike the BM1391 nonce producer this refuses a full
/// ring before an unread record can be overwritten.
pub fn advance_bm1391_stock_ring(
    state: Bm1391StockRingState,
) -> Result<Bm1391StockRingState, Bm1391StockRingError> {
    if state.write_index >= BM1391_STOCK_RETURN_RING_CAPACITY {
        return Err(Bm1391StockRingError::WriteIndexOutOfRange {
            observed: state.write_index,
        });
    }
    if state.queued > BM1391_STOCK_RETURN_RING_CAPACITY {
        return Err(Bm1391StockRingError::QueuedCountOutOfRange {
            observed: state.queued,
        });
    }
    if state.queued == BM1391_STOCK_RETURN_RING_CAPACITY {
        return Err(Bm1391StockRingError::Full);
    }
    Ok(Bm1391StockRingState {
        write_index: if state.write_index + 1 == BM1391_STOCK_RETURN_RING_CAPACITY {
            0
        } else {
            state.write_index + 1
        },
        queued: state.queued + 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_s15_t15_nonce_and_register_words_decode_without_bm1396_policy() {
        let nonce_word = BM1391_STOCK_RETURN_NONCE_BIT
            | BM1391_STOCK_NONCE_VALID_BIT
            | BM1391_STOCK_REGISTER_CRC_ERROR_BIT
            | (0x1234 << 16)
            | 0x05;
        let mut bytes = [0u8; 8];
        bytes[0..4].copy_from_slice(&nonce_word.to_le_bytes());
        bytes[4..8].copy_from_slice(&0x89ab_cdefu32.to_le_bytes());
        let nonce = match decode_bm1391_stock_fpga_return(&bytes).unwrap() {
            Bm1391StockFpgaReturn::Nonce(nonce) => nonce,
            Bm1391StockFpgaReturn::Register(_) => panic!("expected nonce"),
        };
        assert_eq!(nonce.chain_slot, 5);
        assert_eq!(nonce.work_id, 0x1234);
        assert_eq!(nonce.nonce, 0x89ab_cdef);
        assert!(nonce.stock_valid);
        assert!(nonce.status_bit6_set);
        assert!(nonce.stock_binding_eligible(true));

        let register_word: u32 = (2 << 29) | (0x1d << 24) | (0x72 << 16) | (0x40 << 8) | 3;
        bytes[0..4].copy_from_slice(&register_word.to_le_bytes());
        bytes[4..8].copy_from_slice(&0x1391_0000u32.to_le_bytes());
        let register = match decode_bm1391_stock_fpga_return(&bytes).unwrap() {
            Bm1391StockFpgaReturn::Register(register) => register,
            Bm1391StockFpgaReturn::Nonce(_) => panic!("expected register"),
        };
        assert_eq!(register.chain_slot, 3);
        assert_eq!(register.register, 0x40);
        assert_eq!(register.chip_address, 0x72);
        assert_eq!(register.crc5, 0x1d);
        assert_eq!(register.register_type, 2);
        assert_eq!(register.value, 0x1391_0000);
        assert!(!register.stock_queue_eligible(false));
        assert!(register.stock_queue_eligible(true));
    }

    #[test]
    fn binding_reconstructs_exact_sixty_byte_queue_record() {
        let nonce = Bm1391StockNonceReturn {
            chain_slot: 2,
            work_id: 0x3456,
            nonce: 0x1122_3344,
            stock_valid: true,
            status_bit6_set: false,
        };
        let mut outstanding = [0u8; 0x40];
        outstanding[0x00..0x04].copy_from_slice(&0xaabb_ccddu32.to_le_bytes());
        outstanding[0x04..0x08].copy_from_slice(&0x0102_0304u32.to_le_bytes());
        outstanding[0x08..0x0c].copy_from_slice(&0x0506_0708u32.to_le_bytes());
        outstanding[0x0c..0x10].copy_from_slice(&0x090a_0b0cu32.to_le_bytes());
        for (index, byte) in outstanding[0x20..0x40].iter_mut().enumerate() {
            *byte = index as u8;
        }
        let bound = bind_bm1391_stock_nonce(nonce, true, &outstanding).unwrap();
        let bytes = bound.to_stock_queue_bytes();
        assert_eq!(bytes.len(), 0x3c);
        assert_eq!(&bytes[0x00..0x04], &0xaabb_ccddu32.to_le_bytes());
        assert_eq!(&bytes[0x04..0x08], &0x3456u32.to_le_bytes());
        assert_eq!(&bytes[0x14..0x18], &0x1122_3344u32.to_le_bytes());
        assert_eq!(&bytes[0x18..0x1c], &2u32.to_le_bytes());
        assert_eq!(&bytes[0x1c..0x3c], &outstanding[0x20..0x40]);
    }

    #[test]
    fn binding_and_ring_arithmetic_fail_closed_at_exact_boundaries() {
        let nonce = Bm1391StockNonceReturn {
            chain_slot: 0,
            work_id: 0,
            nonce: 0,
            stock_valid: false,
            status_bit6_set: false,
        };
        assert_eq!(
            bind_bm1391_stock_nonce(nonce, true, &[0; 0x40]),
            Err(Bm1391StockWorkBindError::NonceNotStockEligible)
        );
        assert_eq!(
            advance_bm1391_stock_ring(Bm1391StockRingState {
                write_index: 510,
                queued: 510,
            }),
            Ok(Bm1391StockRingState {
                write_index: 0,
                queued: 511,
            })
        );
        assert_eq!(
            advance_bm1391_stock_ring(Bm1391StockRingState {
                write_index: 0,
                queued: 511,
            }),
            Err(Bm1391StockRingError::Full)
        );
        assert!(matches!(
            advance_bm1391_stock_ring(Bm1391StockRingState {
                write_index: 511,
                queued: 0,
            }),
            Err(Bm1391StockRingError::WriteIndexOutOfRange { .. })
        ));
        assert!(matches!(
            advance_bm1391_stock_ring(Bm1391StockRingState {
                write_index: 0,
                queued: 512,
            }),
            Err(Bm1391StockRingError::QueuedCountOutOfRange { .. })
        ));
    }
}
