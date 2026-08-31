//! Typed WORK_TX length + kind. Packing admits a buffer or returns an error.
//!
//! This module does **not** write FPGA FIFOs. Live BM1398 WORK_TX dispatch
//! stays on the existing ChipDriver path (BENCH_HOLD). Unknown chip IDs
//! refuse instead of inheriting BM1387's 36-word / 4-slot FIFO.

use dcentrald_api_types::asic_protocol_spec::BM136X_SERIAL_WORK_WIRE_BYTES;

/// FPGA WORK_TX header words (work_id, nbits, ntime, merkle_tail).
pub const FPGA_WORK_TX_HEADER_WORDS: usize = 4;
/// Midstate slot width on the FPGA WORK_TX FIFO.
pub const FPGA_WORK_TX_WORDS_PER_SLOT: usize = 8;

/// Work-transport kind with an expected on-wire / FIFO length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkTxKind {
    /// FPGA WORK_TX midstate FIFO: 4 header words + `midstate_slots` × 8.
    FpgaMidstateFifo { chip_id: u16, midstate_slots: u8 },
    /// UART full-header job (BM136x serial catalog, 88-byte wire frame).
    UartFullHeader { chip_id: u16, wire_frame_bytes: u8 },
}

/// Expected payload size for a [`WorkTxKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkTxExpectedLen {
    FifoWords(usize),
    WireBytes(usize),
}

/// Typed WORK_TX packing / kind errors. Never a silent length or chip alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkTxError {
    UnknownChip {
        chip_id: u16,
    },
    UnsupportedSlots {
        chip_id: u16,
        midstate_slots: u8,
    },
    LengthMismatch {
        kind: WorkTxKind,
        expected: WorkTxExpectedLen,
        actual: usize,
    },
    KindMismatch {
        kind: WorkTxKind,
    },
}

impl std::fmt::Display for WorkTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownChip { chip_id } => {
                write!(
                    f,
                    "unknown chip ID 0x{chip_id:04X}: refuse silent WORK_TX kind"
                )
            }
            Self::UnsupportedSlots {
                chip_id,
                midstate_slots,
            } => write!(
                f,
                "chip 0x{chip_id:04X} does not admit {midstate_slots} FPGA midstate slots"
            ),
            Self::LengthMismatch {
                kind,
                expected,
                actual,
            } => write!(
                f,
                "WORK_TX length mismatch for {kind:?}: expected {expected:?}, got {actual}"
            ),
            Self::KindMismatch { kind } => {
                write!(f, "WORK_TX payload kind does not match {kind:?}")
            }
        }
    }
}

impl std::error::Error for WorkTxError {}

impl WorkTxKind {
    /// Expected FIFO-word or UART-byte length for this kind.
    pub const fn expected_len(self) -> WorkTxExpectedLen {
        match self {
            Self::FpgaMidstateFifo { midstate_slots, .. } => WorkTxExpectedLen::FifoWords(
                FPGA_WORK_TX_HEADER_WORDS + (midstate_slots as usize) * FPGA_WORK_TX_WORDS_PER_SLOT,
            ),
            Self::UartFullHeader {
                wire_frame_bytes, ..
            } => WorkTxExpectedLen::WireBytes(wire_frame_bytes as usize),
        }
    }
}

/// FPGA WORK_TX kind for a known production/scaffold dispatch chip.
///
/// `midstate_slots` is the slot count (4 or 8), **not** the FPGA log2 field.
/// Unknown chip IDs error. BM1398 4-slot (36 words) and 8-slot (68 words) are
/// distinct; this function does not rewrite the live BM1398 FIFO.
pub fn fpga_work_tx_kind(chip_id: u16, midstate_slots: u8) -> Result<WorkTxKind, WorkTxError> {
    let allowed: &[u8] = match chip_id {
        0x1387 | 0x1397 | 0x1362 | 0x1366 | 0x1368 | 0x1370 => &[4],
        0x1398 => &[4, 8],
        _ => return Err(WorkTxError::UnknownChip { chip_id }),
    };
    if !allowed.contains(&midstate_slots) {
        return Err(WorkTxError::UnsupportedSlots {
            chip_id,
            midstate_slots,
        });
    }
    Ok(WorkTxKind::FpgaMidstateFifo {
        chip_id,
        midstate_slots,
    })
}

/// UART full-header WORK_TX kind (BM136x serial catalog). Unknown chips error.
pub fn uart_work_tx_kind(chip_id: u16) -> Result<WorkTxKind, WorkTxError> {
    match chip_id {
        0x1362 | 0x1366 | 0x1368 | 0x1370 => Ok(WorkTxKind::UartFullHeader {
            chip_id,
            wire_frame_bytes: BM136X_SERIAL_WORK_WIRE_BYTES,
        }),
        _ => Err(WorkTxError::UnknownChip { chip_id }),
    }
}

/// Admit a FIFO-word payload whose length matches `kind`. Does not write hardware.
pub fn pack_work_tx_words<'a>(
    kind: WorkTxKind,
    words: &'a [u32],
) -> Result<&'a [u32], WorkTxError> {
    match kind.expected_len() {
        WorkTxExpectedLen::FifoWords(expected) if words.len() == expected => Ok(words),
        WorkTxExpectedLen::FifoWords(expected) => Err(WorkTxError::LengthMismatch {
            kind,
            expected: WorkTxExpectedLen::FifoWords(expected),
            actual: words.len(),
        }),
        WorkTxExpectedLen::WireBytes(_) => Err(WorkTxError::KindMismatch { kind }),
    }
}

/// Admit a UART-byte payload whose length matches `kind`. Does not write hardware.
pub fn pack_work_tx_bytes<'a>(kind: WorkTxKind, bytes: &'a [u8]) -> Result<&'a [u8], WorkTxError> {
    match kind.expected_len() {
        WorkTxExpectedLen::WireBytes(expected) if bytes.len() == expected => Ok(bytes),
        WorkTxExpectedLen::WireBytes(expected) => Err(WorkTxError::LengthMismatch {
            kind,
            expected: WorkTxExpectedLen::WireBytes(expected),
            actual: bytes.len(),
        }),
        WorkTxExpectedLen::FifoWords(_) => Err(WorkTxError::KindMismatch { kind }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcentrald_api_types::asic_protocol_spec::MIDSTATE_FIFO_WORK_WORDS;

    #[test]
    fn fpga_four_slot_is_canonical_36_words() {
        assert_eq!(MIDSTATE_FIFO_WORK_WORDS, 36);
        for chip in [0x1387u16, 0x1397, 0x1398, 0x1362] {
            let kind = fpga_work_tx_kind(chip, 4).expect("4-slot FPGA kind");
            assert_eq!(
                kind.expected_len(),
                WorkTxExpectedLen::FifoWords(MIDSTATE_FIFO_WORK_WORDS as usize)
            );
            let words = [0u32; 36];
            assert_eq!(pack_work_tx_words(kind, &words).unwrap().len(), 36);
        }
    }

    #[test]
    fn bm1398_eight_slot_is_68_words_not_aliased_to_four() {
        let four = fpga_work_tx_kind(0x1398, 4).unwrap();
        let eight = fpga_work_tx_kind(0x1398, 8).unwrap();
        assert_eq!(four.expected_len(), WorkTxExpectedLen::FifoWords(36));
        assert_eq!(eight.expected_len(), WorkTxExpectedLen::FifoWords(68));
        assert_ne!(four, eight);
        let words68 = [0u32; 68];
        assert_eq!(pack_work_tx_words(eight, &words68).unwrap().len(), 68);
        assert!(matches!(
            pack_work_tx_words(eight, &[0u32; 36]),
            Err(WorkTxError::LengthMismatch { actual: 36, .. })
        ));
    }

    #[test]
    fn packing_refuses_length_mismatch_and_kind_mismatch() {
        let kind = fpga_work_tx_kind(0x1387, 4).unwrap();
        assert!(matches!(
            pack_work_tx_words(kind, &[0u32; 20]),
            Err(WorkTxError::LengthMismatch { actual: 20, .. })
        ));
        assert!(matches!(
            pack_work_tx_bytes(kind, &[0u8; 88]),
            Err(WorkTxError::KindMismatch { .. })
        ));
        let uart = uart_work_tx_kind(0x1362).unwrap();
        assert_eq!(
            uart.expected_len(),
            WorkTxExpectedLen::WireBytes(BM136X_SERIAL_WORK_WIRE_BYTES as usize)
        );
        let bytes = [0u8; BM136X_SERIAL_WORK_WIRE_BYTES as usize];
        assert_eq!(
            pack_work_tx_bytes(uart, &bytes).unwrap().len(),
            BM136X_SERIAL_WORK_WIRE_BYTES as usize
        );
        assert!(matches!(
            pack_work_tx_words(uart, &[0u32; 36]),
            Err(WorkTxError::KindMismatch { .. })
        ));
    }

    #[test]
    fn unknown_chip_and_illegal_slots_refuse() {
        assert_eq!(
            fpga_work_tx_kind(0xFFFF, 4),
            Err(WorkTxError::UnknownChip { chip_id: 0xFFFF })
        );
        assert_eq!(
            uart_work_tx_kind(0x1387),
            Err(WorkTxError::UnknownChip { chip_id: 0x1387 })
        );
        assert_eq!(
            fpga_work_tx_kind(0x1387, 8),
            Err(WorkTxError::UnsupportedSlots {
                chip_id: 0x1387,
                midstate_slots: 8,
            })
        );
        assert_eq!(
            fpga_work_tx_kind(0x1397, 8),
            Err(WorkTxError::UnsupportedSlots {
                chip_id: 0x1397,
                midstate_slots: 8,
            })
        );
    }

    #[test]
    fn module_does_not_write_hardware() {
        let src = include_str!("work_tx.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("work_tx production boundary");
        for banned in [
            "write_work",
            "write_reg",
            "REG_WORK_TX",
            "flush_work_tx",
            "CTRL_REG",
        ] {
            assert!(
                !production.contains(banned),
                "work_tx production must not mention {banned} (no live FIFO write)"
            );
        }
    }
}
