//! Braiins/Bosminer BM1366 UART nonce attribution.
//!
//! This is deliberately separate from the ESP-Miner/AMTC `bits 17..24`
//! address decoder.  Bosminer `FUN_0091c0a0` byte-swaps the payload low
//! word before calling the BM1366 engine callback at `0x009256ac`.  That
//! callback returns `(encoded_chip_address, core_id)`; it does not return a
//! transformed share nonce.  The parser stores the original payload low word
//! separately in `WorkResponse+0x30`.

/// SHA-256 of the held `a lab unit` `bosminer.unpacked` used for these pins.
pub const BOSMINER_78_SHA256: &str =
    "5A49DCBE2E2D9F4FB047ECA856E71440BD73FC020A817E808B5AF3B45A7C8707";
pub const BOSMINER_WORK_RESPONSE_PARSE_VA: u64 = 0x0091_C0A0;
pub const BOSMINER_BM1366_ENGINE_CONSTRUCTOR_VA: u64 = 0x0092_5518;
pub const BOSMINER_BM1366_ATTRIBUTION_CALLBACK_VA: u64 = 0x0092_56AC;
pub const BOSMINER_ADDRESS_DIVIDER_VA: u64 = 0x00BF_3264;
pub const BOSMINER_BM1366_NAME_VA: u64 = 0x0132_5FEF;
/// First `PT_LOAD` maps file offset zero at VA `0x0040_0000`.
pub const BOSMINER_BM1366_ATTRIBUTION_FILE_OFF: usize = 0x0052_56C0;
pub const BOSMINER_WORK_RESPONSE_LOAD_RAW_NONCE_FILE_OFF: usize = 0x0051_C0D8;
pub const BOSMINER_WORK_RESPONSE_LOAD_RAW_NONCE_INSN: u32 = 0xF940_0118;
pub const BOSMINER_WORK_RESPONSE_LOAD_CALLBACK_FILE_OFF: usize = 0x0051_C0DC;
pub const BOSMINER_WORK_RESPONSE_LOAD_CALLBACK_INSN: u32 = 0xF940_4428;
pub const BOSMINER_WORK_RESPONSE_REV_FILE_OFF: usize = 0x0051_C0E0;
pub const BOSMINER_WORK_RESPONSE_REV_INSN: u32 = 0x5AC0_0B00;
pub const BOSMINER_WORK_RESPONSE_BLR_FILE_OFF: usize = 0x0051_C0E4;
pub const BOSMINER_WORK_RESPONSE_BLR_INSN: u32 = 0xD63F_0100;
pub const BOSMINER_WORK_RESPONSE_STORE_RAW_NONCE_FILE_OFF: usize = 0x0051_C140;
pub const BOSMINER_WORK_RESPONSE_STORE_RAW_NONCE_INSN: u32 = 0xB900_3278;

/// AArch64 LE words for `0x9256c0..0x9256e8`:
/// `and #ffff; mov #ffff; udiv; ubfx #9,#16; udiv; ldr +158;
/// lsr #25; mul; mov; ...; ret`.
pub const BOSMINER_BM1366_ATTRIBUTION_INSNS: [u32; 11] = [
    0x1200_3D08,
    0x529F_FFE9,
    0x1AC8_0928,
    0x5309_6009,
    0x1AC8_0928,
    0xF940_AC29,
    0x5319_7C01,
    0x9B08_7D28,
    0xAA08_03E0,
    0xF841_07FE,
    0xD65F_03C0,
];

fn bosminer_u32_at(blob: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        blob.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// Pin the complete raw-word → `REV` → BM1366 callback → raw-store path in
/// the held Bosminer image.  This admits code identity only; it does not turn
/// the accepted-share log or physical attribution into live DCENT proof.
pub fn admit_held_bosminer_bm1366_nonce_code_path(blob: &[u8]) -> Result<(), &'static str> {
    for (index, expected) in BOSMINER_BM1366_ATTRIBUTION_INSNS.iter().enumerate() {
        let offset = BOSMINER_BM1366_ATTRIBUTION_FILE_OFF + index * 4;
        if bosminer_u32_at(blob, offset) != Some(*expected) {
            return Err("held Bosminer BM1366 attribution callback instructions differ");
        }
    }
    for (offset, expected) in [
        (
            BOSMINER_WORK_RESPONSE_LOAD_RAW_NONCE_FILE_OFF,
            BOSMINER_WORK_RESPONSE_LOAD_RAW_NONCE_INSN,
        ),
        (
            BOSMINER_WORK_RESPONSE_LOAD_CALLBACK_FILE_OFF,
            BOSMINER_WORK_RESPONSE_LOAD_CALLBACK_INSN,
        ),
        (
            BOSMINER_WORK_RESPONSE_REV_FILE_OFF,
            BOSMINER_WORK_RESPONSE_REV_INSN,
        ),
        (
            BOSMINER_WORK_RESPONSE_BLR_FILE_OFF,
            BOSMINER_WORK_RESPONSE_BLR_INSN,
        ),
        (
            BOSMINER_WORK_RESPONSE_STORE_RAW_NONCE_FILE_OFF,
            BOSMINER_WORK_RESPONSE_STORE_RAW_NONCE_INSN,
        ),
    ] {
        if bosminer_u32_at(blob, offset) != Some(expected) {
            return Err("held Bosminer work-response nonce path instructions differ");
        }
    }
    Ok(())
}

pub const BM1366_PHYSICAL_BIG_CORES: u8 = crate::s19k_bm1366_amtc_pattern::BM1366_BIG_CORES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BraiinsBm1366NonceWords {
    /// LE interpretation of UART payload bytes 0..4.  Bosminer stores this
    /// unmodified at `WorkResponse+0x30`; it is DCENT's pool-submit word.
    pub payload_low32_le: u32,
    /// `REV W0,W24` argument passed to the engine callback.  This is the
    /// BE/canonical interpretation of the same four UART bytes.
    pub callback_nonce_be: u32,
}

pub fn bosminer_bm1366_nonce_words(payload: &[u8]) -> Option<BraiinsBm1366NonceWords> {
    let bytes: [u8; 4] = payload.get(..4)?.try_into().ok()?;
    let payload_low32_le = u32::from_le_bytes(bytes);
    Some(BraiinsBm1366NonceWords {
        payload_low32_le,
        callback_nonce_be: payload_low32_le.swap_bytes(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraiinsBm1366AttributionConfigError {
    ZeroChipCount,
    ChipCountExceedsU16,
    ZeroCallbackAddressInterval,
    ZeroDividerAddressInterval,
}

/// Exact arithmetic output of the BM1366 callback plus common divider.
///
/// `chip_count` names the observed `engine+0x148` input by behavior; the
/// stripped binary does not retain a field name.  Likewise the callback's
/// `engine+0x158` multiplier and the common divider's dereferenced input are
/// passed separately so equality is an explicit S19k configuration
/// assumption, not silently promoted to a binary fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BraiinsBm1366Attribution {
    pub partition_field: u16,
    pub partition_span: u16,
    pub partition_bucket: u16,
    pub encoded_chip_address: u64,
    pub chip_address_low8: u8,
    pub asic_index: u64,
    pub core_id: u8,
    /// The common divider masks encoded address to eight bits.  `true`
    /// means information was lost and the result must not be treated as a
    /// trustworthy physical attribution.
    pub encoded_address_aliased: bool,
}

pub fn decode_bosminer_bm1366_attribution(
    callback_nonce_be: u32,
    chip_count: u64,
    callback_address_interval: u64,
    divider_address_interval: u64,
) -> Result<BraiinsBm1366Attribution, BraiinsBm1366AttributionConfigError> {
    if chip_count == 0 {
        return Err(BraiinsBm1366AttributionConfigError::ZeroChipCount);
    }
    if chip_count > u64::from(u16::MAX) {
        return Err(BraiinsBm1366AttributionConfigError::ChipCountExceedsU16);
    }
    if callback_address_interval == 0 {
        return Err(BraiinsBm1366AttributionConfigError::ZeroCallbackAddressInterval);
    }
    if divider_address_interval == 0 {
        return Err(BraiinsBm1366AttributionConfigError::ZeroDividerAddressInterval);
    }

    let partition_span = u16::MAX / chip_count as u16;
    // chip_count<=u16::MAX and !=0 guarantees a non-zero span.
    let partition_field = ((callback_nonce_be >> 9) & u32::from(u16::MAX)) as u16;
    let partition_bucket = partition_field / partition_span;
    let encoded_chip_address = callback_address_interval * u64::from(partition_bucket);
    let chip_address_low8 = (encoded_chip_address & 0xFF) as u8;
    let asic_index = u64::from(chip_address_low8) / divider_address_interval;

    Ok(BraiinsBm1366Attribution {
        partition_field,
        partition_span,
        partition_bucket,
        encoded_chip_address,
        chip_address_low8,
        asic_index,
        core_id: (callback_nonce_be >> 25) as u8,
        encoded_address_aliased: encoded_chip_address > u64::from(u8::MAX),
    })
}

/// Decode with the held S19k Pro facts: 77 BM1366 ASICs and interval 2 for
/// both the callback multiplier and common divider.
pub fn decode_s19k_braiins_bm1366_attribution(
    callback_nonce_be: u32,
) -> Result<BraiinsBm1366Attribution, BraiinsBm1366AttributionConfigError> {
    decode_bosminer_bm1366_attribution(
        callback_nonce_be,
        u64::from(crate::s19k_bm1366_wire_b::S19K_WIRE_ASIC_NUM),
        u64::from(crate::s19k_bm1366_wire_b::S19K_AML_ADDR_INTERVAL),
        u64::from(crate::s19k_bm1366_wire_b::S19K_AML_ADDR_INTERVAL),
    )
}

/// Physical-range admission is intentionally separate from arithmetic
/// decode: `FUN_009256ac` itself does not reject the small rounding tail
/// whose bucket equals `chip_count`, nor core values 112..127.
pub fn s19k_braiins_bm1366_attribution_is_physical(attribution: &BraiinsBm1366Attribution) -> bool {
    !attribution.encoded_address_aliased
        && attribution.asic_index < u64::from(crate::s19k_bm1366_wire_b::S19K_WIRE_ASIC_NUM)
        && attribution.core_id < BM1366_PHYSICAL_BIG_CORES
}

/// Braiins fill `payload[5] >> log0` consumes the entire byte as work-id.
/// It supplies no independently decoded ESP-style small-core field.
pub fn s19k_braiins_fill_small_core() -> Option<u8> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce_with_partition_and_core(field: u16, core: u8) -> u32 {
        (u32::from(field) << 9) | (u32::from(core) << 25)
    }

    #[test]
    fn live412_keeps_payload_and_callback_endianness_separate() {
        // Held accepted share: UART bytes / callback word / submitted word.
        let words = bosminer_bm1366_nonce_words(&[0x0D, 0x90, 0x3E, 0x4E, 0, 0, 0, 0])
            .expect("four nonce bytes");
        assert_eq!(words.payload_low32_le, 0x4E3E_900D);
        assert_eq!(words.callback_nonce_be, 0x0D90_3E4E);

        let attr = decode_s19k_braiins_bm1366_attribution(words.callback_nonce_be).unwrap();
        assert_eq!(attr.partition_span, 851);
        assert_eq!(attr.partition_field, 51_231);
        assert_eq!(attr.partition_bucket, 60);
        assert_eq!(attr.encoded_chip_address, 120);
        assert_eq!(attr.chip_address_low8, 120);
        assert_eq!(attr.asic_index, 60);
        assert_eq!(attr.core_id, 6);
        assert!(s19k_braiins_bm1366_attribution_is_physical(&attr));
    }

    #[test]
    fn callback_partition_boundaries_include_explicit_rounding_tail() {
        let span = u16::MAX / 77;
        assert_eq!(span, 851);
        for (field, expected_bucket) in [
            (0, 0),
            (span - 1, 0),
            (span, 1),
            (76 * span, 76),
            (77 * span - 1, 76),
            (77 * span, 77),
            (u16::MAX, 77),
        ] {
            let attr =
                decode_s19k_braiins_bm1366_attribution(nonce_with_partition_and_core(field, 0))
                    .unwrap();
            assert_eq!(attr.partition_bucket, expected_bucket, "field={field}");
            assert_eq!(attr.asic_index, u64::from(expected_bucket));
        }
        let tail =
            decode_s19k_braiins_bm1366_attribution(nonce_with_partition_and_core(u16::MAX, 0))
                .unwrap();
        assert!(!s19k_braiins_bm1366_attribution_is_physical(&tail));
    }

    #[test]
    fn core_boundary_is_marked_without_claiming_callback_rejection() {
        let core111 =
            decode_s19k_braiins_bm1366_attribution(nonce_with_partition_and_core(0, 111)).unwrap();
        let core112 =
            decode_s19k_braiins_bm1366_attribution(nonce_with_partition_and_core(0, 112)).unwrap();
        assert!(s19k_braiins_bm1366_attribution_is_physical(&core111));
        assert!(!s19k_braiins_bm1366_attribution_is_physical(&core112));
    }

    #[test]
    fn invalid_configuration_is_refused_and_aliasing_is_marked() {
        assert_eq!(
            decode_bosminer_bm1366_attribution(0, 0, 2, 2),
            Err(BraiinsBm1366AttributionConfigError::ZeroChipCount)
        );
        assert_eq!(
            decode_bosminer_bm1366_attribution(0, 65_536, 2, 2),
            Err(BraiinsBm1366AttributionConfigError::ChipCountExceedsU16)
        );
        assert_eq!(
            decode_bosminer_bm1366_attribution(0, 77, 0, 2),
            Err(BraiinsBm1366AttributionConfigError::ZeroCallbackAddressInterval)
        );
        assert_eq!(
            decode_bosminer_bm1366_attribution(0, 77, 2, 0),
            Err(BraiinsBm1366AttributionConfigError::ZeroDividerAddressInterval)
        );

        let aliased = decode_bosminer_bm1366_attribution(
            nonce_with_partition_and_core(u16::MAX, 0),
            77,
            4,
            4,
        )
        .unwrap();
        assert_eq!(aliased.encoded_chip_address, 308);
        assert!(aliased.encoded_address_aliased);
        assert!(!s19k_braiins_bm1366_attribution_is_physical(&aliased));
    }

    #[test]
    fn held_accepted_share_corpus_fits_exact_decoder_not_esp_decoder() {
        // Numeric pool-submit words from 35 held ACCEPTED lines.  Swap gives
        // the callback's REV word.  Exact BM1366 attribution is physical for
        // all 35; the ESP/AMTC bits17 decoder is out of range for 15.
        let submitted: [u32; 35] = [
            0x5D79_3985,
            0x9AEA_565C,
            0x0033_0511,
            0x2870_11BB,
            0xC15A_724A,
            0x4E3E_900D,
            0x6DE7_F0C4,
            0xE5D3_C50D,
            0x9E45_E36E,
            0xB9E5_7CD1,
            0xF552_0F0C,
            0x0061_7451,
            0x97BB_F42B,
            0xEEAB_1C38,
            0x61B2_1B30,
            0xADFE_CA91,
            0xD081_C53B,
            0xD272_543F,
            0x09A9_BAAE,
            0x2798_7407,
            0x9D9A_57BC,
            0xAB96_F056,
            0x0D76_7986,
            0x37F3_5172,
            0xADC0_15DA,
            0x20A9_4ACA,
            0x6302_0455,
            0x6875_B8CB,
            0x3A9A_9A10,
            0x5EF5_E691,
            0xFDDF_8B26,
            0x0193_BE97,
            0x4C4A_C4B1,
            0x4D25_8644,
            0x5A3C_A44F,
        ];
        let mut esp_out_of_range = 0;
        for submit_word in submitted {
            let callback_word = submit_word.swap_bytes();
            let attr = decode_s19k_braiins_bm1366_attribution(callback_word).unwrap();
            assert!(
                s19k_braiins_bm1366_attribution_is_physical(&attr),
                "submit={submit_word:08x} callback={callback_word:08x} attr={attr:?}"
            );
            let esp_asic = ((callback_word >> 17) & 0xFF) / 2;
            if esp_asic >= 77 {
                esp_out_of_range += 1;
            }
        }
        assert_eq!(esp_out_of_range, 15);
    }

    #[test]
    fn fill_job_byte_does_not_mint_an_esp_small_core() {
        assert_eq!(s19k_braiins_fill_small_core(), None);
    }

    #[test]
    #[ignore = "requires the held 23.9 MB Bosminer extraction"]
    fn held_bosminer_binary_pins_complete_nonce_code_path() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../../../\
             live-probe-78-2026-04-29/04-binaries/bosminer.unpacked",
        );
        let mut blob = std::fs::read(path).expect("held .78 bosminer.unpacked");
        assert!(admit_held_bosminer_bm1366_nonce_code_path(&blob).is_ok());

        blob[BOSMINER_WORK_RESPONSE_REV_FILE_OFF] ^= 1;
        assert_eq!(
            admit_held_bosminer_bm1366_nonce_code_path(&blob),
            Err("held Bosminer work-response nonce path instructions differ")
        );
    }
}
