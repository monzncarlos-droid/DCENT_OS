//! S19k BM1366 raw-UART GetAddress + 11-byte RX classify (T4/T5 desk 2026-08-12).
//!
//! Pure pack/parse. No open, no mining.
//! Job CRC5: ESP-Miner `crc5(frame[2..], 9) == 0` remainder is the BM1366
//! RX check. RTL payload-only init `0x1B` is **refused** as a drop
//! (fails every held BM136x job frame). No retained **BM1366** nonce
//! vector yet — remainder is proven on live BM1362 + S21 BM1368.
//!
//! GetAddress TX (BM1397+ / BM136x, **not** BM1387 `0x54`):
//! `55 AA 52 05 00 00 0A`
//!
//! : `wire_b::cmd_chain_inactive_bcast` now emits `53 05 00 00 03`.
//! GetAddress is `cmd_get_address_bcast` / [`GET_ADDRESS_UART`].
//!
//! RX (full UART, preamble kept): `AA 55` + 9-byte body.
//! Trailer bit7 = 1 → job/nonce; bit7 = 0 → ChipAddress/command.
//! BM1366 job_id = `id & 0xF8` (not BM1368 `(id & 0xF0) >> 1`).

/// Full GetAddress TX including preamble + command CRC5.
pub const GET_ADDRESS_UART: [u8; 7] = [0x55, 0xAA, 0x52, 0x05, 0x00, 0x00, 0x0A];
/// Chain-inactive is a **different** opcode (do not send 0x52 and call it inactive).
pub const CHAIN_INACTIVE_UART: [u8; 7] = [0x55, 0xAA, 0x53, 0x05, 0x00, 0x00, 0x03];

pub const UART_RESP_PREAMBLE: [u8; 2] = [0xAA, 0x55];
/// Full UART response including `AA 55`. ESP-Miner
/// `BM1366_CHIP_ID_RESPONSE_LENGTH`. Not a HAL **body** length.
pub const UART_RESP_LEN: usize = 11;
/// : BM1366 UART **body** after `AA 55` is **9**
/// (nonce/value 4 + mid/addr 1 + job/reg 1 + version 2 + trailer 1).
/// HAL `DEFAULT_RESP_BODY_LEN` / `BM139X_RESP_BODY_LEN` is **7**
/// (9-byte wire, no version). `set_response_len(11)` as a **body**
/// hunts a 13-byte frame. Do not merge those three numbers.
pub const BM1366_UART_RESP_BODY_LEN: usize = 9;
/// HAL serial_chain default / `BM139X_RESP_BODY_LEN` (BM1387-shaped).
pub const BM139X_HAL_DEFAULT_RESP_BODY_LEN: usize = 7;
/// Wire total if someone passes `UART_RESP_LEN` into `set_response_len`.
pub const SET_RESPONSE_LEN_11_AS_BODY_WIRE: usize = 2 + UART_RESP_LEN;
pub const BM1366_JOB_ID_MASK: u8 = 0xF8;
pub const BM1366_SMALL_CORE_MASK: u8 = 0x07;
pub const JOB_TRAILER_BIT: u8 = 0x80;

/// ESP-Miner `bm1366_asic_result_cmd_t` / `job_t` body offsets (after `AA 55`).
pub const ESP_RX_VALUE_OR_NONCE_OFF: usize = 2;
pub const ESP_RX_ASIC_OR_MIDSTATE_OFF: usize = 6;
pub const ESP_RX_REG_OR_JOB_ID_OFF: usize = 7;
pub const ESP_RX_VERSION_OFF: usize = 8;
/// Trailer bit7 = `is_job_response` (ESP packed struct; comment `10:8` is wrong).
pub const ESP_RX_IS_JOB_BIT: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kUartRxKind {
    /// ESP-Miner command reply (GetAddress / `read_register`).
    /// `chip_id` is `value_be >> 16` when the chip reports 0x1366 there.
    CommandReply {
        value_be: u32,
        asic_address: u8,
        register_address: u8,
    },
    /// Compatibility view of a GetAddress-shaped command reply.
    ChipAddress {
        chip_id: u16,
        value_address: u8,
        responder_address: u8,
    },
    JobNonce {
        nonce_be: u32,
        midstate_num: u8,
        /// ESP-Miner `id & 0xF8`. Not the Braiins fill work_id.
        job_id: u8,
        /// Raw job byte. Braiins fill log 0 uses this as `work_id`.
        raw_job_byte: u8,
        small_core: u8,
        version_be: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kUartRxError {
    Length { observed: usize },
    BadPreamble,
}

pub fn pack_get_address_uart() -> [u8; 7] {
    GET_ADDRESS_UART
}

/// Command/register response CRC5 init (Braiins `crc5_resp_serial.vhd`).
pub const RESP_CRC5_INIT_COMMAND: u8 = 0x03;
/// Job-response CRC5 init named by Braiins RTL. **FALSIFIED** as a
/// payload-only drop: live BM1362 / S21 BM1368 trailers do not match
/// `0x1B`. Keep the constant so tests can refuse it.
pub const RESP_CRC5_INIT_JOB_EXPERIMENTAL: u8 = 0x1B;
/// ESP-Miner `crc.c` host/RX CRC5 initial value (poly x⁵+x²+1).
pub const ESP_ASIC_CRC5_INIT: u8 = 0x1F;
/// ESP-Miner `BM1366_CHIP_ID_RESPONSE_LENGTH`.
pub const ESP_BM1366_CHIP_ID_RX_LEN: usize = 11;
/// S21 live comparative BM1368 job frame (not BM1366).
pub const HELD_BM1368_S21_JOB: [u8; 11] = [
    0xAA, 0x55, 0x60, 0x96, 0x39, 0x4C, 0x02, 0x14, 0x03, 0x04, 0x8E,
];
/// Live AM3-BB BM1362 job frames from `a lab unit` 2026-05-14 accepted-share log.
/// Comparative family evidence, **not** S19k BM1366.
pub const HELD_BM1362_JOB_FRAMES: &[[u8; 11]] = &[
    [0xAA, 0x55, 0x3E, 0x00, 0x17, 0xBE, 0x01, 0x3E, 0x10, 0x5E, 0x9C],
    [0xAA, 0x55, 0x32, 0x00, 0xE3, 0xB3, 0x00, 0x3C, 0x58, 0x54, 0x95],
    [0xAA, 0x55, 0x7C, 0x01, 0x09, 0x6F, 0x01, 0x31, 0x04, 0xD9, 0x9E],
    [0xAA, 0x55, 0x00, 0x01, 0x68, 0x37, 0x00, 0x6F, 0x02, 0x9F, 0x99],
    [0xAA, 0x55, 0x6C, 0x02, 0x14, 0xFE, 0x00, 0x7B, 0x01, 0x7B, 0x85],
    [0xAA, 0x55, 0x26, 0x02, 0x03, 0xD1, 0x01, 0x44, 0x70, 0xC4, 0x84],
    [0xAA, 0x55, 0x50, 0x02, 0x64, 0x92, 0x01, 0x2C, 0x00, 0x2C, 0x9F],
    [0xAA, 0x55, 0x54, 0x02, 0x67, 0x11, 0x00, 0x10, 0x55, 0x58, 0x91],
];

/// BM13xx *response* CRC5 (not the host-command poly/init `0x05`/`0x1F`).
///
/// Payload only: exclude `AA 55` and the trailer byte. Trailer bits 4:0
/// are the CRC; bit7 is the job/command discriminator.
pub fn bm1366_response_crc5(payload: &[u8], init: u8) -> u8 {
    let mut crc = init & 0x1F;
    for &byte in payload {
        for bit_index in (0..8).rev() {
            let data_bit = (byte >> bit_index) & 1;
            let feedback = data_bit ^ ((crc >> 4) & 1);
            crc = (((crc >> 3) & 1) << 4)
                | ((((crc >> 2) & 1) ^ data_bit) << 3)
                | ((((crc >> 1) & 1) ^ feedback) << 2)
                | ((crc & 1) << 1)
                | feedback;
        }
    }
    crc
}

pub fn command_response_crc5(payload: &[u8]) -> u8 {
    bm1366_response_crc5(payload, RESP_CRC5_INIT_COMMAND)
}

pub fn job_response_crc5_experimental(payload: &[u8]) -> u8 {
    bm1366_response_crc5(payload, RESP_CRC5_INIT_JOB_EXPERIMENTAL)
}

/// ESP-Miner `crc.c` `crc5()` — poly x⁵+x²+1, init `0x1F`, MSB-first.
/// Used for **TX append** and **RX remainder** (`crc5(buf+2, n) == 0`).
pub fn esp_asic_crc5(data: &[u8]) -> u8 {
    let mut crc = ESP_ASIC_CRC5_INIT;
    for &mut_byte in data {
        let mut byte = mut_byte;
        for _ in 0..8 {
            let bit = (byte >> 7) & 1;
            byte = byte.wrapping_shl(1);
            let new_bit = ((crc >> 4) ^ bit) & 1;
            crc = ((crc << 1) | new_bit) ^ (new_bit << 2);
            crc &= 0x1F;
        }
    }
    crc
}

/// ESP `receive_work` / `count_asic_chips`: CRC covers every byte after
/// `AA 55`, **including** the trailer. Valid ⇒ remainder 0.
pub fn esp_rx_crc5_remainder(frame: &[u8]) -> Result<u8, S19kUartRxError> {
    if frame.len() < 3 {
        return Err(S19kUartRxError::Length {
            observed: frame.len(),
        });
    }
    if frame[0] != UART_RESP_PREAMBLE[0] || frame[1] != UART_RESP_PREAMBLE[1] {
        return Err(S19kUartRxError::BadPreamble);
    }
    Ok(esp_asic_crc5(&frame[2..]))
}

pub fn admit_esp_rx_crc5_remainder(frame: &[u8]) -> Result<(), &'static str> {
    match esp_rx_crc5_remainder(frame) {
        Ok(0) => Ok(()),
        Ok(_) => Err("ESP crc5 remainder is not 0"),
        Err(_) => Err("ESP crc5 remainder: bad frame"),
    }
}

/// RTL `0x1B` payload-only does not match held live job trailers.
/// Never use it as a nonce drop.
pub fn refuse_rtl_1b_payload_as_job_crc_drop(frame: &[u8]) -> Result<(), &'static str> {
    if frame.len() != UART_RESP_LEN {
        return Err("not an 11-byte UART response");
    }
    if job_response_crc5_experimental(&frame[2..10]) == frame[10] & 0x1F {
        return Ok(());
    }
    Err("RTL 0x1B payload-only does not match this job trailer; refuse as drop")
}

/// These frames are BM1362/BM1368. Do not label them BM1366.
pub fn refuse_held_bm1362_job_as_bm1366_vector(chip: u16) -> Result<(), &'static str> {
    if chip == 0x1366 {
        return Ok(());
    }
    Err("held live job frames are BM1362/BM1368 comparative, not BM1366")
}

/// Live `.88` leftover after `kill -9` bosminer, before Track-1 open.
/// ttyS1 11-byte `AA 55` JobNonce (trailer bit7=1). Not `a lab unit` `00 00 AA`.
pub const S19K_LIVE88_S1_LEFTOVER_JOB_NONCE: [u8; 11] = [
    0xAA, 0x55, 0x40, 0x1B, 0x16, 0x52, 0x00, 0x4F, 0x66, 0x5F, 0x8D,
];
/// Live `.88` leftover ttyS2 twin. Also JobNonce. ttyS3 leftover was 0 bytes.
pub const S19K_LIVE88_S2_LEFTOVER_JOB_NONCE: [u8; 11] = [
    0xAA, 0x55, 0x22, 0x4E, 0x64, 0xC8, 0x00, 0x48, 0x72, 0xC0, 0x90,
];

/// Pinned 2026-08-15 from live `.88` ttyS1 leftover (Track-1 preflight).
pub const S19K_HELD_BM1366_JOB_NONCE: Option<&[u8]> =
    Some(&S19K_LIVE88_S1_LEFTOVER_JOB_NONCE);

/// Retired: a live S19k JobNonce now exists. Kept so host_verify still
/// finds the symbol. Call [`admit_s19k_live88_held_bm1366_job_nonce`].
pub fn admit_s19k_no_held_bm1366_job_nonce() -> Result<(), &'static str> {
    Err("retired 2026-08-15: live .88 leftover JobNonce is pinned")
}

pub fn admit_s19k_live88_held_bm1366_job_nonce() -> Result<(), &'static str> {
    let Some(frame) = S19K_HELD_BM1366_JOB_NONCE else {
        return Err("S19K_HELD_BM1366_JOB_NONCE must be the live .88 leftover");
    };
    if frame != S19K_LIVE88_S1_LEFTOVER_JOB_NONCE.as_slice() {
        return Err("held BM1366 JobNonce must be the live .88 ttyS1 leftover");
    }
    match classify_bm1366_uart_rx(frame) {
        Ok(S19kUartRxKind::JobNonce { .. }) => {}
        Ok(_) => return Err("live .88 leftover must classify as JobNonce"),
        Err(_) => return Err("live .88 leftover failed classify"),
    }
    match classify_bm1366_uart_rx(&S19K_LIVE88_S2_LEFTOVER_JOB_NONCE) {
        Ok(S19kUartRxKind::JobNonce { .. }) => Ok(()),
        Ok(_) => Err("live .88 ttyS2 leftover must classify as JobNonce"),
        Err(_) => Err("live .88 ttyS2 leftover failed classify"),
    }
}

pub fn refuse_held_s21_job_as_s19k_bm1366_nonce(frame: &[u8]) -> Result<(), &'static str> {
    if frame == HELD_BM1368_S21_JOB {
        return Err("S21 BM1368 HELD_BM1368_S21_JOB is comparative, not S19k BM1366 nonce");
    }
    Ok(())
}

/// First ChipAddress in held S21 `our_command_response.bin` / `asic_response_raw.bin`.
pub const S21_HELD_CHIPADDRESS_1368: [u8; 11] = [
    0xAA, 0x55, 0x13, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F,
];
/// Needle count of `13 68` in each 4096-byte S21 capture (108 chips, interval 2).
pub const S21_HELD_UART_CA1368_COUNT: usize = 108;
/// Needle count of `13 66` in those captures.
pub const S21_HELD_UART_CA1366_COUNT: usize = 0;

pub fn count_s21_held_chip_id_pairs(blob: &[u8], id: [u8; 2]) -> usize {
    blob.windows(2).filter(|w| w == &id).count()
}

/// Held S21 UART captures are BM1368 ChipAddress (`0x1368`), not BM1366 (`0x1366`).
pub fn admit_s21_held_uart_chip_id_is_1368_not_1366(blob: &[u8]) -> Result<(), &'static str> {
    if blob.len() < UART_RESP_LEN {
        return Err("S21 UART capture shorter than one 11-byte frame");
    }
    let n68 = count_s21_held_chip_id_pairs(blob, [0x13, 0x68]);
    let n66 = count_s21_held_chip_id_pairs(blob, [0x13, 0x66]);
    if n66 != S21_HELD_UART_CA1366_COUNT {
        return Err("held S21 UART must have 0 0x1366 ChipAddress pairs");
    }
    if n68 != S21_HELD_UART_CA1368_COUNT {
        return Err("held S21 UART must have 108 0x1368 ChipAddress pairs");
    }
    if !blob.windows(UART_RESP_LEN).any(|w| w == S21_HELD_CHIPADDRESS_1368) {
        return Err("held S21 UART missing first 0x1368 ChipAddress frame");
    }
    Ok(())
}

pub fn refuse_s21_held_uart_capture_as_s19k_jobnonce(blob: &[u8]) -> Result<(), &'static str> {
    admit_s21_held_uart_chip_id_is_1368_not_1366(blob)?;
    Err("S21 UART capture is BM1368 ChipAddress/JobNonce; not an S19k BM1366 JobNonce vector")
}

pub fn refuse_held_bm1362_frames_as_s19k_bm1366_nonce(frame: &[u8]) -> Result<(), &'static str> {
    if HELD_BM1362_JOB_FRAMES.iter().any(|f| f.as_slice() == frame) {
        return Err(".79 BM1362 HELD_BM1362_JOB_FRAMES are comparative, not S19k BM1366 nonce");
    }
    Ok(())
}

/// Exhaustive offline sweep: which 5-bit inits reproduce `observed` trailer bits.
/// Used to re-challenge RTL-named init `0x1B` against held comparative frames.
/// Matching an init here does **not** make job CRC a drop condition.
pub fn job_crc5_inits_matching(payload: &[u8], observed: u8) -> Vec<u8> {
    let want = observed & 0x1F;
    (0u8..=0x1F)
        .filter(|&init| bm1366_response_crc5(payload, init) == want)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kRxCrcStatus {
    NotChecked,
    /// ESP-Miner remainder `crc5(frame[2..]) == 0` (job **and** command).
    EspRemainderOk,
    CommandMatch,
    JobMatchExperimental,
    Mismatch { expected: u8, observed: u8 },
}

/// Verify RX CRC. ESP remainder-0 is the BM1366 check (`receive_work`).
/// RTL `0x1B` payload-only is reported only if it happens to match; it
/// is not a drop.
pub fn verify_bm1366_uart_rx_crc(frame: &[u8]) -> Result<S19kRxCrcStatus, S19kUartRxError> {
    if frame.len() != UART_RESP_LEN {
        return Err(S19kUartRxError::Length {
            observed: frame.len(),
        });
    }
    if frame[0] != UART_RESP_PREAMBLE[0] || frame[1] != UART_RESP_PREAMBLE[1] {
        return Err(S19kUartRxError::BadPreamble);
    }
    if esp_asic_crc5(&frame[2..]) == 0 {
        return Ok(S19kRxCrcStatus::EspRemainderOk);
    }
    let payload = &frame[2..10];
    let observed = frame[10] & 0x1F;
    let expected = if frame[10] & JOB_TRAILER_BIT != 0 {
        job_response_crc5_experimental(payload)
    } else {
        command_response_crc5(payload)
    };
    if expected == observed {
        if frame[10] & JOB_TRAILER_BIT != 0 {
            Ok(S19kRxCrcStatus::JobMatchExperimental)
        } else {
            Ok(S19kRxCrcStatus::CommandMatch)
        }
    } else {
        Ok(S19kRxCrcStatus::Mismatch {
            expected,
            observed,
        })
    }
}

/// Classify one 11-byte UART response. Does **not** verify response CRC5.
pub fn classify_bm1366_uart_rx(frame: &[u8]) -> Result<S19kUartRxKind, S19kUartRxError> {
    if frame.len() != UART_RESP_LEN {
        return Err(S19kUartRxError::Length {
            observed: frame.len(),
        });
    }
    if frame[0] != UART_RESP_PREAMBLE[0] || frame[1] != UART_RESP_PREAMBLE[1] {
        return Err(S19kUartRxError::BadPreamble);
    }
    let trailer = frame[10];
    if trailer & JOB_TRAILER_BIT != 0 {
        let id = frame[ESP_RX_REG_OR_JOB_ID_OFF];
        Ok(S19kUartRxKind::JobNonce {
            nonce_be: u32::from_be_bytes([frame[2], frame[3], frame[4], frame[5]]),
            midstate_num: frame[ESP_RX_ASIC_OR_MIDSTATE_OFF],
            job_id: id & BM1366_JOB_ID_MASK,
            raw_job_byte: id,
            small_core: id & BM1366_SMALL_CORE_MASK,
            version_be: u16::from_be_bytes([frame[8], frame[9]]),
        })
    } else {
        Ok(command_reply_from_frame(frame))
    }
}

/// ESP-Miner command layout. GetAddress-shaped 0x1366 replies also
/// surface as [`S19kUartRxKind::ChipAddress`] for existing callers.
pub fn command_reply_from_frame(frame: &[u8]) -> S19kUartRxKind {
    let value_be = u32::from_be_bytes([frame[2], frame[3], frame[4], frame[5]]);
    let asic_address = frame[ESP_RX_ASIC_OR_MIDSTATE_OFF];
    let register_address = frame[ESP_RX_REG_OR_JOB_ID_OFF];
    let chip_id = (value_be >> 16) as u16;
    if chip_id == 0x1366 && register_address == 0 {
        S19kUartRxKind::ChipAddress {
            chip_id,
            value_address: frame[5],
            responder_address: asic_address,
        }
    } else {
        S19kUartRxKind::CommandReply {
            value_be,
            asic_address,
            register_address,
        }
    }
}

/// First CommandReply whose register is FastUART `0x28`.
pub const S19K_FASTUART_REG: u8 = 0x28;

pub fn extract_s19k_fastuart_reg28_from_obs(obs: &S19kUartRxObservation) -> Option<u32> {
    match obs {
        S19kUartRxObservation::Frames { frames, .. } => extract_s19k_fastuart_reg28(frames),
        _ => None,
    }
}

pub fn extract_s19k_fastuart_reg28(frames: &[S19kUartRxKind]) -> Option<u32> {
    frames.iter().find_map(|k| match k {
        S19kUartRxKind::CommandReply {
            value_be,
            register_address: S19K_FASTUART_REG,
            ..
        } => Some(*value_be),
        _ => None,
    })
}

/// `read_register(0x0)` enum: asic addresses present in command replies.
pub fn enum_asic_addrs_from_rx(frames: &[S19kUartRxKind]) -> Vec<u8> {
    frames
        .iter()
        .filter_map(|k| match k {
            S19kUartRxKind::CommandReply { asic_address, .. }
            | S19kUartRxKind::ChipAddress {
                responder_address: asic_address,
                ..
            } => Some(*asic_address),
            S19kUartRxKind::JobNonce { .. } => None,
        })
        .collect()
}

/// : GetAddress completeness is not the same as ChipAddressOk.
/// One `0x1366` reply proves the **port** answered. Braiins `a lab unit` still
/// demands 77 unique `read_register(0x0)` addresses (interval 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kChipEnumCompleteness {
    Silence,
    NotEnum,
    Complete77,
    Short { got: u32, missing: u8 },
}

/// Unique asic addresses in a GetAddress observation.
pub fn classify_s19k_chip_enum_complete(
    obs: &S19kUartRxObservation,
) -> S19kChipEnumCompleteness {
    match obs {
        S19kUartRxObservation::Silence { .. } => S19kChipEnumCompleteness::Silence,
        S19kUartRxObservation::Frames { frames, .. } => {
            let addrs = enum_asic_addrs_from_rx(frames);
            if addrs.is_empty() {
                return S19kChipEnumCompleteness::NotEnum;
            }
            let missing = first_missing_enum_addr(
                &addrs,
                crate::s19k_bm1366_wire_b::S19K_AML_ADDR_INTERVAL,
                crate::s19k_bosminer_enum::S19K_BHB56902_CHIP_COUNT,
            );
            let mut seen = [false; 256];
            let mut got = 0u32;
            for addr in addrs {
                let i = usize::from(addr);
                if !seen[i] {
                    seen[i] = true;
                    got = got.saturating_add(1);
                }
            }
            if got == crate::s19k_bosminer_enum::S19K_BHB56902_CHIP_COUNT && missing.is_none()
            {
                S19kChipEnumCompleteness::Complete77
            } else {
                S19kChipEnumCompleteness::Short {
                    got,
                    missing: missing.unwrap_or(0),
                }
            }
        }
        _ => S19kChipEnumCompleteness::NotEnum,
    }
}

/// One (or any count ≠ 77) ChipAddress is not BHB56902 enum-complete.
pub fn refuse_one_chipaddress_as_77_chip_complete(
    status: S19kChipEnumCompleteness,
) -> Result<(), &'static str> {
    match status {
        S19kChipEnumCompleteness::Complete77 => Ok(()),
        S19kChipEnumCompleteness::Short { got: 1, .. } => {
            Err("one 0x1366 ChipAddress is port-answered, not 77-chip complete")
        }
        S19kChipEnumCompleteness::Short { got, .. } => Err(
            if got == 0 {
                "zero unique enum addrs is not 77-chip complete"
            } else {
                "short read_register(0x0) enum is not 77-chip complete"
            },
        ),
        S19kChipEnumCompleteness::Silence => {
            Err("GetAddress silence is not 77-chip complete")
        }
        S19kChipEnumCompleteness::NotEnum => {
            Err("non-enum RX is not 77-chip complete")
        }
    }
}

/// Port `ChipAddress { chip_id, count }` is a frame count, not 77 unique addrs.
pub fn refuse_s19k_chipaddress_count_as_77_complete(
    chip_id: u16,
    count: usize,
) -> Result<(), &'static str> {
    if chip_id != 0x1366 {
        return Err("port answer is not a 0x1366 ChipAddress enum");
    }
    if count == 1 {
        return Err("one ChipAddress {0x1366} is not 77-chip complete");
    }
    if count == crate::s19k_bosminer_enum::S19K_BHB56902_CHIP_COUNT as usize {
        return Err(
            "ChipAddress count==77 is not unique-addr proof; classify_s19k_chip_enum_complete",
        );
    }
    Err("ChipAddress frame count is not 77 unique interval-2 addrs")
}

/// Constructed interval-2 77-reply GetAddress stream. Not a live sniff.
pub fn bm1366_constructed_77_chip_enum() -> Vec<u8> {
    let n = crate::s19k_bosminer_enum::S19K_BHB56902_CHIP_COUNT;
    let step = crate::s19k_bm1366_wire_b::S19K_AML_ADDR_INTERVAL;
    let mut out = Vec::with_capacity((n as usize).saturating_mul(UART_RESP_LEN));
    for i in 0..n {
        let addr = (i as u16 * u16::from(step)) as u8;
        out.extend_from_slice(&bm1366_chip_address_uart(addr));
    }
    out
}

/// Split a BM1366 UART stream the way HAL `try_extract_frame(9)` does:
/// scan `AA 55`, copy 9 body bytes, consume 11. Not a live sniff.
pub fn extract_s19k_hal_bm1366_bodies(stream: &[u8]) -> Vec<Vec<u8>> {
    extract_s19k_aa55_bodies(stream, BM1366_UART_RESP_BODY_LEN)
}

/// Preamble scan + fixed body length. `body_len=7` on an 11-byte wire
/// leaves version+trailer in the stream (HAL DEFAULT 7 miss).
pub fn extract_s19k_aa55_bodies(stream: &[u8], body_len: usize) -> Vec<Vec<u8>> {
    let frame_len = 2usize.saturating_add(body_len);
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < stream.len() {
        if stream[i] == UART_RESP_PREAMBLE[0] && stream[i + 1] == UART_RESP_PREAMBLE[1] {
            if i + frame_len <= stream.len() {
                out.push(stream[i + 2..i + frame_len].to_vec());
                i += frame_len;
                continue;
            }
            break;
        }
        i += 1;
    }
    out
}

/// Same scan as [`extract_s19k_aa55_bodies`], plus leftover bytes after the
/// last consumed frame. Body-7 on an 11-byte wire leaves 2 residue bytes.
pub fn extract_s19k_aa55_bodies_and_residue(
    stream: &[u8],
    body_len: usize,
) -> (Vec<Vec<u8>>, Vec<u8>) {
    let frame_len = 2usize.saturating_add(body_len);
    let mut out = Vec::new();
    let mut i = 0;
    let mut last_consume: Option<usize> = None;
    while i + 1 < stream.len() {
        if stream[i] == UART_RESP_PREAMBLE[0] && stream[i + 1] == UART_RESP_PREAMBLE[1] {
            if i + frame_len <= stream.len() {
                out.push(stream[i + 2..i + frame_len].to_vec());
                i += frame_len;
                last_consume = Some(i);
                continue;
            }
            break;
        }
        i += 1;
    }
    (out, stream[last_consume.unwrap_or(i)..].to_vec())
}

/// Body-7 residue is leftover version+trailer, not a frame / preamble.
pub fn refuse_s19k_body7_residue_as_frame(residue: &[u8]) -> Result<(), &'static str> {
    if residue.len() == UART_RESP_LEN {
        return Ok(());
    }
    if residue.len() >= 2
        && residue[0] == UART_RESP_PREAMBLE[0]
        && residue[1] == UART_RESP_PREAMBLE[1]
    {
        return Ok(());
    }
    if classify_bm1366_uart_rx(residue).is_ok() {
        return Ok(());
    }
    Err("HAL body-7 residue is leftover bytes, not a BM1366 frame")
}

/// Two concatenated 11-byte frames at body 7 yield two 7-byte cuts + 2-byte residue.
pub fn admit_s19k_body7_two_frame_leaves_residue(
    stream: &[u8],
) -> Result<(Vec<Vec<u8>>, Vec<u8>), &'static str> {
    if stream.len() != UART_RESP_LEN.saturating_mul(2) {
        return Err("two-frame stream must be 22 bytes");
    }
    let (bodies, residue) = extract_s19k_aa55_bodies_and_residue(stream, 7);
    if bodies.len() != 2 || bodies.iter().any(|b| b.len() != 7) {
        return Err("body-7 extract of two 11-byte frames must yield two 7-byte bodies");
    }
    if residue.len() != 2 {
        return Err("body-7 extract of two 11-byte frames must leave 2 residue bytes");
    }
    Ok((bodies, residue))
}

/// Same 22-byte stream at body 9 yields two 9-byte bodies and empty residue.
pub fn admit_s19k_body9_two_frame_no_residue(stream: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    if stream.len() != UART_RESP_LEN.saturating_mul(2) {
        return Err("two-frame stream must be 22 bytes");
    }
    let (bodies, residue) = extract_s19k_aa55_bodies_and_residue(stream, BM1366_UART_RESP_BODY_LEN);
    if bodies.len() != 2 || bodies.iter().any(|b| b.len() != BM1366_UART_RESP_BODY_LEN) {
        return Err("body-9 extract of two 11-byte frames must yield two 9-byte bodies");
    }
    if !residue.is_empty() {
        return Err("body-9 extract of two 11-byte frames must leave no residue");
    }
    Ok(bodies)
}

/// After a body-7 cut of `first` (11-byte wire), switch to body 9 on
/// `residue + next` (next is another 11-byte wire). Recover the next frame.
pub fn admit_s19k_body7_residue_then_body9_recovers_next(
    first: &[u8],
    next: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if first.len() != UART_RESP_LEN || next.len() != UART_RESP_LEN {
        return Err("first and next must be 11-byte UART frames");
    }
    let (cut7, residue) = extract_s19k_aa55_bodies_and_residue(first, 7);
    if cut7.len() != 1 || cut7[0].len() != 7 {
        return Err("body-7 extract of first frame must yield one 7-byte body");
    }
    if residue.len() != 2 {
        return Err("body-7 extract of first 11-byte frame must leave 2 residue bytes");
    }
    if refuse_s19k_body7_residue_as_frame(&residue).is_ok() {
        return Err("first-frame residue must not be a frame");
    }
    let mut stitched = residue;
    stitched.extend_from_slice(next);
    if stitched.len() != 13 {
        return Err("residue + next must be 13 bytes");
    }
    let (recovered, leftover) =
        extract_s19k_aa55_bodies_and_residue(&stitched, BM1366_UART_RESP_BODY_LEN);
    if recovered.len() != 1 || recovered[0].len() != BM1366_UART_RESP_BODY_LEN {
        return Err("body-9 extract of residue+next must recover one 9-byte body");
    }
    if !leftover.is_empty() {
        return Err("body-9 recovery of residue+next must leave no leftover");
    }
    if recovered[0].as_slice() != &next[2..] {
        return Err("recovered body-9 must match the next frame body");
    }
    Ok(recovered.into_iter().next().unwrap())
}

/// HAL source must actually extract BM1366 at body 9, not only name the constant.
pub fn admit_s19k_hal_extracts_bm1366_body9(src: &str) -> Result<(), &'static str> {
    if !src.contains("fn try_extract_frame") {
        return Err("HAL must keep RxBuffer::try_extract_frame");
    }
    if !src.contains("try_extract_frame(BM1366_UART_RESP_BODY_LEN") {
        return Err("HAL tests must call try_extract_frame(BM1366_UART_RESP_BODY_LEN)");
    }
    if !src.contains("rx_buffer_extracts_complete_bm1366_frame") {
        return Err("HAL must test BM1366 11-byte wire extract at body 9");
    }
    if !src.contains("rx_buffer_body7_on_bm1366_wire_leaves_trailer") {
        return Err("HAL must test body-7 cut of an 11-byte BM1366 wire");
    }
    Ok(())
}

/// HAL RxBuffer must mid-stream switch body 7 → 9 and recover the next frame.
pub fn admit_s19k_hal_midstream_body7_then_body9(src: &str) -> Result<(), &'static str> {
    if !src.contains("fn rx_buffer_body7_then_body9_recovers_next") {
        return Err("HAL must test RxBuffer body-7 then body-9 mid-stream recovery");
    }
    if !src.contains("try_extract_frame(BM139X_RESP_BODY_LEN") {
        return Err("HAL mid-stream test must extract at body 7 first");
    }
    let mid = src
        .split("fn rx_buffer_body7_then_body9_recovers_next")
        .nth(1)
        .unwrap_or("");
    if !mid.contains("try_extract_frame(BM1366_UART_RESP_BODY_LEN") {
        return Err("HAL mid-stream test must then extract at body 9");
    }
    Ok(())
}

pub fn refuse_s19k_hal_body7_extract_as_bm1366_frame() -> Result<(), &'static str> {
    Err("try_extract_frame(7) on an 11-byte BM1366 wire is a 7-byte cut, not a BM1366 frame")
}

/// Production GetAddress adapter must classify 77 HAL bodies as Complete77.
pub fn admit_s19k_hal_bodies_77_complete(
    status: S19kChipEnumCompleteness,
) -> Result<(), &'static str> {
    match status {
        S19kChipEnumCompleteness::Complete77 => Ok(()),
        _ => Err("77 constructed HAL bodies must classify Complete77"),
    }
}

/// Production must log incomplete enum and must not treat ChipAddressOk as 77.
pub fn admit_s19k_production_logs_77_enum_incomplete(src: &str) -> Result<(), &'static str> {
    if !src.contains("classify_s19k_chip_enum_complete") {
        return Err("production must classify GetAddress enum completeness");
    }
    if !src.contains("refuse_one_chipaddress_as_77_chip_complete") {
        return Err("production must refuse one ChipAddress as 77-complete");
    }
    if !src.contains("not 77-chip complete") {
        return Err("production must log that GetAddress is not 77-chip complete");
    }
    Ok(())
}

/// First expected interval-2 address not present. Does **not** prove
/// the live 8-reply set; only reports the first hole in `got`.
pub fn first_missing_enum_addr(got: &[u8], interval: u8, expected: u32) -> Option<u8> {
    if interval == 0 {
        return None;
    }
    for i in 0..expected {
        let addr = (i as u16 * u16::from(interval)) as u8;
        if !got.contains(&addr) {
            return Some(addr);
        }
    }
    None
}

/// Byte 5 is the LSB of the u32 value, not a register address.
pub fn refuse_rx_byte5_as_register_address(off: usize) -> Result<(), &'static str> {
    if off == 5 {
        return Err("ESP cmd byte5 is value LSB, not register_address (byte7)");
    }
    Ok(())
}

/// Chip address from a job nonce (BE interpret, bits 24:17). Interval=2 SoT.
pub fn chip_addr_from_nonce_be(nonce_be: u32) -> u8 {
    ((nonce_be >> 17) & 0xff) as u8
}

pub fn core_id_from_nonce_be(nonce_be: u32) -> u8 {
    ((nonce_be >> 25) & 0x7f) as u8
}

/// ASIC index on interval=2 boards. Refuse public floor=3.
pub fn asic_index_from_nonce_be(nonce_be: u32) -> u8 {
    chip_addr_from_nonce_be(nonce_be) / 2
}

/// Stream-level observation. Distinguishes silence from framing from ASIC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S19kUartRxObservation {
    /// Zero bytes in the read window. Not a parse error.
    Silence { window_ms: u32 },
    /// Bytes present but no `AA 55` hunter hit.
    NoPreamble {
        nbytes: usize,
        first8: [u8; 8],
        first8_len: usize,
    },
    /// Found `55 AA` (host TX echo or wrong polarity). Not a response.
    HostPreambleEcho { at: usize },
    /// `AA 55` found but fewer than 9 body bytes follow.
    ShortFrame { at: usize, available: usize },
    /// One or more classified 11-byte frames.
    Frames {
        frames: Vec<S19kUartRxKind>,
        crc: Vec<S19kRxCrcStatus>,
        trailing_unparsed: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kRxExpectedAfter {
    GetAddress,
    SetAddress,
    WorkDispatch,
    /// : broadcast `read_register(0x28)` FastUART.
    FastUart28,
    /// : EXPERIMENTAL GetAddress after host drop to 115200.
    GetAddress115200Retry,
    /// : broadcast `52 05 00 28` while host is temporarily 115200.
    FastUart28At115200,
    /// : reset / chain-inactive / init rearm / refused 21 56.
    Reset,
    ChainInactive,
    InitRearm,
    WorkDispatch2156,
}

/// What RX is *allowed* to look like after a TX class. Silence after a
/// wrong job shape is **not** proof chips ignored us (T4 refuse).
pub fn expected_rx_after(after: S19kRxExpectedAfter) -> &'static str {
    match after {
        S19kRxExpectedAfter::GetAddress => {
            "up to 77 AA 55 ChipAddress / read_register(reg=0x0) replies (chip_id 0x1366); .78 CHAIN/1 got 8 missing 0x02; silence means rail/UART/reset, not parser"
        }
        S19kRxExpectedAfter::SetAddress => {
            "optional ChipAddress / register echo; silence alone is inconclusive"
        }
        S19kRxExpectedAfter::WorkDispatch => {
            "AA 55 JobNonce (trailer bit7=1) after CLOSED 21 36; Braiins fill work_id is the raw job byte (log 0), not ESP id&0xF8; engine work-type must be 1 (bm1398_6x.rs:344); 0 nonces after refused 21 56 is not parser proof"
        }
        S19kRxExpectedAfter::FastUart28 => {
            "AA 55 CommandReply register 0x28 after 55 AA 52 05 00 28; silence at host 3M is ChipFastUartUnread (unread 115200 vs 3M), not AsicResetOrUninit"
        }
        S19kRxExpectedAfter::GetAddress115200Retry => {
            "EXPERIMENTAL host 115200 GetAddress after ChipFastUartUnread; silence is GetAddressSilenceAt115200 not ChipFastUartUnread; ChipAddress is ChipHeardAt115200 not 3M work proof; always restore 3M"
        }
        S19kRxExpectedAfter::FastUart28At115200 => {
            "EXPERIMENTAL 52 05 00 28 at host 115200 after GetAddressSilenceAt115200; CommandReply 0x28 is FastUart28HeardAt115200 not ChipHeardAt115200; silence is FastUart28SilenceAt115200 not ChipFastUartUnread; always restore 3M"
        }
        S19kRxExpectedAfter::Reset | S19kRxExpectedAfter::ChainInactive => {
            "silence or optional ChipAddress after 53 05 00 00 03; do not claim enum"
        }
        S19kRxExpectedAfter::InitRearm => {
            "silence is not 21 36 proof; CommandReply reg 0x14 ticket / 0x10 HCN 0x115A is RearmRegOk; refuse ESP 0xA4=0x9000FFFF"
        }
        S19kRxExpectedAfter::WorkDispatch2156 => {
            "0 nonces after 55 AA 21 56 is not parser proof (live 2026-08-12 FPGA/ESP miss)"
        }
    }
}

/// : typed RX-after-TX diagnosis. Silence is never a parser fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kRxDiag {
    Silence,
    FramingOrEcho,
    UartConfigMismatch,
    AsicResetOrUninit,
    ChainFailShortEnum,
    ChipAddressOk,
    JobNonceFillOk,
    Inconclusive,
    WrongJobShapeSilence,
    /// : one required tty answered, the other Silence.
    /// Not dual-chain / 2-board proof.
    SinglePortNotDualProof,
    /// : CommandReply ticket 0x14 or HCN 0x10 after InitRearm.
    RearmRegOk,
    /// : ChipAddress / CommandReply after SetAddress. Not enum.
    SetAddressEcho,
    /// : broadcast `52 05 00 28` got no CommandReply reg 0x28.
    /// Host 3M cannot be told from an unread 115200 chip.
    ChipFastUartUnread,
    /// : CommandReply register 0x28 present.
    FastUartRegOk,
    /// : GetAddress ChipAddress while host was temporarily 115200.
    /// Not 3M work-TX proof.
    ChipHeardAt115200,
    /// : GetAddress at host 115200 returned silence.
    /// Not ChipFastUartUnread (that is broadcast `52 05 00 28`).
    GetAddressSilenceAt115200,
    /// : CommandReply reg 0x28 while host was temporarily 115200.
    /// Chip UART is alive at 115200. Not GetAddress ChipHeardAt115200.
    FastUart28HeardAt115200,
    /// : `52 05 00 28` at 115200 returned silence.
    /// Not ChipFastUartUnread (that tag is the 3M 0x28 unread).
    FastUart28SilenceAt115200,
}

/// T4/T5 constructed ChipAddress core encoding. BM1366/1368/1370 = 0x00.
pub const BM1366_CHIP_ADDRESS_CORE: u8 = 0x00;
/// BM1362 ChipAddress core encoding. Not BM1366.
pub const BM1362_CHIP_ADDRESS_CORE: u8 = 0x03;
/// Held `a lab unit` `cap_serial/ttyS3.rx.bin` (3 bytes). Not a BM1366 frame.
pub const HELD_78_CAP_SERIAL_S3: [u8; 3] = [0x00, 0x00, 0xAA];
/// CLOSED Track-1 work prefix. Used only to prove HAL leftover-`AA` stitch.
pub const S19K_CLOSED_SEND_WORK_PREFIX: [u8; 4] = [0x55, 0xAA, 0x21, 0x36];

/// HAL `try_extract_frame` no-preamble path: keep last byte only.
pub fn s19k_hal_rxbuf_keep_last_byte(stream: &[u8]) -> Vec<u8> {
    match stream.last() {
        Some(b) => vec![*b],
        None => Vec::new(),
    }
}

/// Held `a lab unit` S3 last byte is not a BM1366 preamble. HAL keep-last-byte
/// + next `55 AA 21 36` TX echo stitches a false `AA 55` CommandReply.
pub fn refuse_s19k_rxbuf_leftover_aa_plus_tx55_as_jobnonce(
    leftover: &[u8],
    tx_echo_prefix: &[u8],
) -> Result<(), &'static str> {
    if leftover != HELD_78_CAP_SERIAL_S3.as_slice() {
        return Err("fixture must be held .78 ttyS3 00 00 AA");
    }
    if tx_echo_prefix.get(..4) != Some(&S19K_CLOSED_SEND_WORK_PREFIX) {
        return Err("TX echo fixture must be CLOSED 21 36");
    }
    let mut stream = s19k_hal_rxbuf_keep_last_byte(leftover);
    stream.extend_from_slice(tx_echo_prefix);
    if stream.len() < UART_RESP_LEN {
        return Err("stitched stream shorter than 11-byte wire");
    }
    let bodies = extract_s19k_aa55_bodies(&stream, BM1366_UART_RESP_BODY_LEN);
    if bodies.len() != 1 || bodies[0].len() != BM1366_UART_RESP_BODY_LEN {
        return Err("last-byte AA + 55 AA TX must stitch one 9-byte body");
    }
    let mut frame = [0u8; UART_RESP_LEN];
    frame[0] = UART_RESP_PREAMBLE[0];
    frame[1] = UART_RESP_PREAMBLE[1];
    frame[2..].copy_from_slice(&bodies[0]);
    match classify_bm1366_uart_rx(&frame) {
        Ok(S19kUartRxKind::JobNonce { .. }) => Ok(()),
        Ok(_) => Err(
            "held S3 last-AA + TX 55 AA is CommandReply desync, not JobNonce",
        ),
        Err(_) => Err("stitched frame is not JobNonce"),
    }
}

pub fn refuse_s19k_held_s3_aa_as_preamble_seed() -> Result<(), &'static str> {
    Err(
        "held ttyS3 00 00 AA last byte is not AA 55; keeping it seeds a false AA 55 on the next 55 AA TX",
    )
}

/// After GetAddress Silence/NoPreamble, production must drop the 1-byte seed
/// before the next TX so a later `55 AA` cannot stitch.
pub fn admit_s19k_production_flush_rx_after_getaddress_nopreamble(
    src: &str,
) -> Result<(), &'static str> {
    if !src.contains("flush leftover RX after empty GetAddress") {
        return Err(
            "Track-1 must flush RxBuffer after empty GetAddress before the next TX",
        );
    }
    if !src.contains("HAL last-byte AA") {
        return Err("flush comment must name HAL last-byte AA stitch");
    }
    Ok(())
}

/// FastUART `52 05 00 28` TX is also `55 AA`. Empty 0x28 RX must flush
/// the same leftover-`AA` seed before 115200 retry or work TX.
pub fn admit_s19k_production_flush_rx_after_fastuart_empty(
    src: &str,
) -> Result<(), &'static str> {
    if !src.contains("flush leftover RX after empty FastUART") {
        return Err(
            "Track-1 must flush RxBuffer after empty FastUART 0x28 before the next TX",
        );
    }
    Ok(())
}

/// 115200-retry GetAddress TX is also `55 AA`. Empty retry RX must flush
/// leftover-`AA` before FastUART-at-115200 or restore-to-3M work TX.
pub fn admit_s19k_production_flush_rx_after_115200_retry_empty(
    src: &str,
) -> Result<(), &'static str> {
    if !src.contains("flush leftover RX after empty 115200-retry GetAddress") {
        return Err(
            "Track-1 must flush RxBuffer after empty 115200-retry GetAddress before the next TX",
        );
    }
    Ok(())
}

/// FastUART-at-115200 TX is also `55 AA`. Empty RX must flush leftover-`AA`
/// before restore-to-3M work TX.
pub fn admit_s19k_production_flush_rx_after_fastuart_115200_empty(
    src: &str,
) -> Result<(), &'static str> {
    if !src.contains("flush leftover RX after empty FastUART-at-115200") {
        return Err(
            "Track-1 must flush RxBuffer after empty FastUART-at-115200 before restore-to-3M work TX",
        );
    }
    Ok(())
}

/// T4/T5 constructed 11-byte ChipAddress UART (`AA 55 13 66 00 <addr> <addr> 00 00 00 <crc>`).
/// Not a live S19k sniff. Trailer is command CRC5 init 0x03 (bit7=0).
pub fn bm1366_chip_address_uart(addr: u8) -> [u8; 11] {
    let mut frame = [
        UART_RESP_PREAMBLE[0],
        UART_RESP_PREAMBLE[1],
        0x13,
        0x66,
        BM1366_CHIP_ADDRESS_CORE,
        addr,
        addr,
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    frame[10] = command_response_crc5(&frame[2..10]);
    frame
}

/// Constructed CommandReply (not a live sniff). Trailer bit7=0 + command CRC5.
pub fn bm1366_command_reply_uart(value_be: u32, asic: u8, reg: u8) -> [u8; 11] {
    let v = value_be.to_be_bytes();
    let mut frame = [
        UART_RESP_PREAMBLE[0],
        UART_RESP_PREAMBLE[1],
        v[0],
        v[1],
        v[2],
        v[3],
        asic,
        reg,
        0x00,
        0x00,
        0x00,
    ];
    frame[10] = command_response_crc5(&frame[2..10]);
    frame
}

/// Ticket mask echo: reg 0x14 value 0x000000FF.
pub fn bm1366_rearm_ticket_reply_uart() -> [u8; 11] {
    bm1366_command_reply_uart(0x0000_00FF, 0, 0x14)
}

/// HCN echo: reg 0x10 value 0x0000115A.
pub fn bm1366_rearm_hcn_reply_uart() -> [u8; 11] {
    bm1366_command_reply_uart(0x0000_115A, 0, 0x10)
}

/// ESP VersionMask echo. Not a Braiins fill re-arm.
pub fn bm1366_esp_version_mask_reply_uart() -> [u8; 11] {
    bm1366_command_reply_uart(0x9000_FFFF, 0, 0xA4)
}

/// Ticket 0x14 or HCN 0x10. ESP 0xA4 is refused.
pub fn s19k_rearm_reply_is_ticket_or_hcn(kind: S19kUartRxKind) -> bool {
    matches!(
        kind,
        S19kUartRxKind::CommandReply {
            register_address: 0x14 | 0x10,
            ..
        }
    )
}

pub fn refuse_esp_a4_reply_as_fill_rearm_ok(kind: S19kUartRxKind) -> Result<(), &'static str> {
    if let S19kUartRxKind::CommandReply {
        register_address: 0xA4,
        value_be: 0x9000_FFFF,
        ..
    } = kind
    {
        return Err("ESP 0xA4=0x9000FFFF CommandReply is not Braiins fill RearmRegOk");
    }
    Ok(())
}

/// Synthetic JobNonce with trailer bit7=1. CRC is not a drop (T4).
pub fn bm1366_fill_job_nonce_uart(raw_job_byte: u8) -> [u8; 11] {
    [
        UART_RESP_PREAMBLE[0],
        UART_RESP_PREAMBLE[1],
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        raw_job_byte,
        0x00,
        0x00,
        JOB_TRAILER_BIT,
    ]
}

/// BM1366 UART body after `AA 55` is 9. Wire total is 11.
pub fn admit_bm1366_uart_resp_body_len(body: usize) -> Result<(), &'static str> {
    if BM1366_UART_RESP_BODY_LEN != 9 {
        return Err("BM1366 UART body must stay 9");
    }
    if UART_RESP_LEN != UART_RESP_PREAMBLE.len() + BM1366_UART_RESP_BODY_LEN {
        return Err("wire total must stay preamble+9");
    }
    if ESP_BM1366_CHIP_ID_RX_LEN != UART_RESP_LEN {
        return Err("ESP chip-id RX length must stay the 11-byte wire");
    }
    if HELD_BM1368_S21_JOB.len() != UART_RESP_LEN {
        return Err("held S21 job is 11-byte wire, not a 7-byte body");
    }
    if body != BM1366_UART_RESP_BODY_LEN {
        return Err("BM1366 UART body must be 9");
    }
    Ok(())
}

/// HAL `BM139X_RESP_BODY_LEN` / default **7** is not the BM1366 UART body.
pub fn refuse_bm139x_default_body7_as_bm1366_uart(body: usize) -> Result<(), &'static str> {
    if body != BM139X_HAL_DEFAULT_RESP_BODY_LEN {
        return Ok(());
    }
    Err("HAL default body 7 is the 9-byte BM1387-shaped wire; BM1366 UART body is 9 (11-byte wire)")
}

/// `set_response_len(11)` is the **wire** total. Passing it as body hunts 13 bytes.
pub fn refuse_response_bytes_11_as_set_response_len(body: usize) -> Result<(), &'static str> {
    if body != UART_RESP_LEN {
        return Ok(());
    }
    if SET_RESPONSE_LEN_11_AS_BODY_WIRE != 13 {
        return Ok(());
    }
    Err("UART_RESP_LEN 11 is the wire total; set_response_len(11) as body hunts 13 bytes")
}

/// Production `set_response_len` for S19k BM1366 must name body 9.
pub fn admit_s19k_production_set_response_len_is_bm1366_body(
    src: &str,
) -> Result<(), &'static str> {
    let start = src
        .find("let resp_body_len")
        .ok_or("missing resp_body_len")?;
    let window = src.get(start..start.saturating_add(500)).unwrap_or("");
    if !window.contains("is_bm1366") {
        return Err("resp_body_len must branch on is_bm1366");
    }
    if !window.contains("BM1366_UART_RESP_BODY_LEN") {
        return Err("BM1366 hunter must name BM1366_UART_RESP_BODY_LEN, not the BM1362 alias");
    }
    if !src.contains("set_response_len(resp_body_len)") {
        return Err("production must set_response_len from resp_body_len");
    }
    Ok(())
}

/// A 7-byte cut of an 11-byte job is not JobNonce / ChipAddress.
pub fn refuse_hal_body7_cut_as_job_or_chip(frame: &[u8]) -> Result<(), &'static str> {
    if frame.len() == UART_RESP_LEN {
        return Ok(());
    }
    if classify_bm1366_uart_rx(frame).is_ok() {
        return Ok(());
    }
    Err("7-byte HAL cut is Length, not JobNonce/ChipAddress; do not treat as parser-ok")
}

/// Wire bytes if HAL default body 7 is used as a hunter window including preamble.
pub const S19K_HAL_BODY7_WIRE_CUT: usize = 2 + BM139X_HAL_DEFAULT_RESP_BODY_LEN;

/// First `AA 55` + 7 body bytes of an 11-byte UART response.
pub fn s19k_hal_body7_wire_cut(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < S19K_HAL_BODY7_WIRE_CUT {
        return None;
    }
    Some(&frame[..S19K_HAL_BODY7_WIRE_CUT])
}

/// Constructed fill JobNonce (11-byte) must correlate with `55 AA 21 36` TX job_id.
pub fn admit_constructed_fill_nonce_correlates(
    tx_wire: &[u8],
    raw_job: u8,
) -> Result<(), &'static str> {
    let rx = bm1366_fill_job_nonce_uart(raw_job);
    if rx.len() != UART_RESP_LEN {
        return Err("constructed fill nonce must be 11-byte wire");
    }
    admit_fill_work_id_tx_rx_correlate(tx_wire, &rx)
}

/// HAL body-7 cut of that same constructed nonce is not JobNonce and does not correlate.
pub fn refuse_constructed_fill_body7_as_job_nonce(
    tx_wire: &[u8],
    raw_job: u8,
) -> Result<(), &'static str> {
    let rx = bm1366_fill_job_nonce_uart(raw_job);
    let cut = s19k_hal_body7_wire_cut(&rx).ok_or("constructed fill nonce shorter than body-7 cut")?;
    if cut.len() != S19K_HAL_BODY7_WIRE_CUT {
        return Err("HAL body-7 wire cut must be 9 bytes");
    }
    if classify_bm1366_uart_rx(cut).is_ok() {
        return Ok(());
    }
    if admit_fill_work_id_tx_rx_correlate(tx_wire, cut).is_ok() {
        return Ok(());
    }
    Err("constructed fill nonce HAL body-7 cut is Length, not a correlating JobNonce")
}

/// Observing the body-7 cut is ShortFrame/FramingOrEcho, not JobNonceFillOk or Silence.
pub fn refuse_constructed_fill_body7_observe_as_job_or_silence(
    raw_job: u8,
) -> Result<(), &'static str> {
    let rx = bm1366_fill_job_nonce_uart(raw_job);
    let cut = s19k_hal_body7_wire_cut(&rx).ok_or("constructed fill nonce shorter than body-7 cut")?;
    let obs = observe_bm1366_uart_rx(cut, 10);
    if matches!(obs, S19kUartRxObservation::Silence { .. }) {
        return Err("constructed fill body-7 cut is not Silence");
    }
    if matches!(obs, S19kUartRxObservation::Frames { .. }) {
        return Ok(());
    }
    let baud_ok: Result<(), &'static str> = Ok(());
    if classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::WorkDispatch, &obs, baud_ok)
        == S19kRxDiag::JobNonceFillOk
    {
        return Ok(());
    }
    Err("constructed fill nonce HAL body-7 cut is ShortFrame/FramingOrEcho, not JobNonceFillOk")
}

/// Admit a constructed ChipAddress for `addr` (chip_id 0x1366, core 0x00, dup addr).
pub fn admit_expected_chip_address_rx(frame: &[u8], addr: u8) -> Result<(), &'static str> {
    if frame.len() != UART_RESP_LEN {
        return Err("ChipAddress fixture must be 11 bytes");
    }
    if frame[4] != BM1366_CHIP_ADDRESS_CORE {
        return Err("BM1366 ChipAddress core encoding is 0x00");
    }
    match classify_bm1366_uart_rx(frame) {
        Ok(S19kUartRxKind::ChipAddress {
            chip_id,
            value_address,
            responder_address,
        }) if chip_id == 0x1366 && value_address == addr && responder_address == addr => Ok(()),
        Ok(_) => Err("frame is not ChipAddress 0x1366 with matching addrs"),
        Err(_) => Err("ChipAddress fixture failed classify"),
    }
}

/// BM1362 core encoding 0x03 is not a BM1366 ChipAddress.
pub fn refuse_bm1362_core03_as_bm1366_chip_address(frame: &[u8]) -> Result<(), &'static str> {
    if frame.len() == UART_RESP_LEN && frame[4] == BM1362_CHIP_ADDRESS_CORE {
        return Err("byte4 0x03 is BM1362 core encoding, not BM1366 ChipAddress");
    }
    Ok(())
}

/// Join TX class + observation + pre-classified baud into a typed diag.
/// `baud` is `classify_s19k_uart_baud_dialect(...).map(|_| ())` — this
/// module must not import `init_seq` (cycle).
pub fn classify_s19k_bm1366_rx_after(
    after: S19kRxExpectedAfter,
    obs: &S19kUartRxObservation,
    baud: Result<(), &'static str>,
) -> S19kRxDiag {
    match after {
        S19kRxExpectedAfter::GetAddress => match obs {
            S19kUartRxObservation::Silence { .. } => {
                if baud.is_err() {
                    S19kRxDiag::UartConfigMismatch
                } else {
                    S19kRxDiag::AsicResetOrUninit
                }
            }
            S19kUartRxObservation::NoPreamble {
                first8,
                first8_len,
                ..
            } if *first8_len >= 3 && first8[..3] == HELD_78_CAP_SERIAL_S3 => {
                S19kRxDiag::FramingOrEcho
            }
            S19kUartRxObservation::NoPreamble { .. }
            | S19kUartRxObservation::HostPreambleEcho { .. }
            | S19kUartRxObservation::ShortFrame { .. } => S19kRxDiag::FramingOrEcho,
            S19kUartRxObservation::Frames { frames, .. } => {
                let addrs = enum_asic_addrs_from_rx(frames);
                if frames.len() >= 2 && first_missing_enum_addr(&addrs, 2, 77).is_some() {
                    S19kRxDiag::ChainFailShortEnum
                } else if frames.iter().any(|k| {
                    matches!(
                        k,
                        S19kUartRxKind::ChipAddress {
                            chip_id: 0x1366,
                            ..
                        }
                    )
                }) {
                    S19kRxDiag::ChipAddressOk
                } else {
                    S19kRxDiag::FramingOrEcho
                }
            }
        },
        S19kRxExpectedAfter::GetAddress115200Retry => match obs {
            S19kUartRxObservation::Silence { .. } => S19kRxDiag::GetAddressSilenceAt115200,
            S19kUartRxObservation::Frames { frames, .. } => {
                if frames.iter().any(|k| {
                    matches!(
                        k,
                        S19kUartRxKind::ChipAddress {
                            chip_id: 0x1366,
                            ..
                        }
                    )
                }) {
                    S19kRxDiag::ChipHeardAt115200
                } else {
                    S19kRxDiag::FramingOrEcho
                }
            }
            _ => S19kRxDiag::FramingOrEcho,
        },
        S19kRxExpectedAfter::FastUart28 => match obs {
            S19kUartRxObservation::Silence { .. } => {
                if baud.is_err() {
                    S19kRxDiag::UartConfigMismatch
                } else {
                    S19kRxDiag::ChipFastUartUnread
                }
            }
            S19kUartRxObservation::Frames { frames, .. } => {
                if extract_s19k_fastuart_reg28(frames).is_some() {
                    S19kRxDiag::FastUartRegOk
                } else {
                    S19kRxDiag::FramingOrEcho
                }
            }
            _ => S19kRxDiag::FramingOrEcho,
        },
        S19kRxExpectedAfter::FastUart28At115200 => match obs {
            S19kUartRxObservation::Silence { .. } => S19kRxDiag::FastUart28SilenceAt115200,
            S19kUartRxObservation::Frames { frames, .. } => {
                if extract_s19k_fastuart_reg28(frames).is_some() {
                    S19kRxDiag::FastUart28HeardAt115200
                } else {
                    S19kRxDiag::FramingOrEcho
                }
            }
            _ => S19kRxDiag::FramingOrEcho,
        },
        S19kRxExpectedAfter::WorkDispatch => match obs {
            S19kUartRxObservation::Frames { frames, .. }
                if frames
                    .iter()
                    .any(|k| matches!(k, S19kUartRxKind::JobNonce { .. })) =>
            {
                S19kRxDiag::JobNonceFillOk
            }
            S19kUartRxObservation::Silence { .. } => S19kRxDiag::Silence,
            _ => S19kRxDiag::FramingOrEcho,
        },
        S19kRxExpectedAfter::WorkDispatch2156 => match obs {
            S19kUartRxObservation::Silence { .. } => S19kRxDiag::WrongJobShapeSilence,
            _ => S19kRxDiag::FramingOrEcho,
        },
        S19kRxExpectedAfter::InitRearm => match obs {
            S19kUartRxObservation::Silence { .. } => S19kRxDiag::Inconclusive,
            S19kUartRxObservation::Frames { frames, .. } => {
                if frames.iter().any(|k| {
                    matches!(
                        k,
                        S19kUartRxKind::CommandReply {
                            register_address: 0xA4,
                            value_be: 0x9000_FFFF,
                            ..
                        }
                    )
                }) {
                    S19kRxDiag::FramingOrEcho
                } else if frames.iter().copied().any(s19k_rearm_reply_is_ticket_or_hcn) {
                    S19kRxDiag::RearmRegOk
                } else {
                    S19kRxDiag::Inconclusive
                }
            }
            _ => S19kRxDiag::FramingOrEcho,
        },
        S19kRxExpectedAfter::SetAddress => match obs {
            S19kUartRxObservation::Silence { .. } => S19kRxDiag::Inconclusive,
            S19kUartRxObservation::Frames { frames, .. }
                if frames.iter().any(|k| {
                    matches!(
                        k,
                        S19kUartRxKind::ChipAddress { .. } | S19kUartRxKind::CommandReply { .. }
                    )
                }) =>
            {
                S19kRxDiag::SetAddressEcho
            }
            S19kUartRxObservation::Frames { .. } => S19kRxDiag::Inconclusive,
            _ => S19kRxDiag::FramingOrEcho,
        },
        S19kRxExpectedAfter::Reset | S19kRxExpectedAfter::ChainInactive => match obs {
            S19kUartRxObservation::Silence { .. }
            | S19kUartRxObservation::Frames { .. } => S19kRxDiag::Inconclusive,
            _ => S19kRxDiag::FramingOrEcho,
        },
    }
}

/// Dual-UART join of two required-port observations (ttyS1 + ttyS2).
/// One JobNonce + one Silence is **not** dual-chain work proof.
pub fn classify_s19k_dual_uart_rx_after(
    after: S19kRxExpectedAfter,
    s1: &S19kUartRxObservation,
    s2: &S19kUartRxObservation,
    baud: Result<(), &'static str>,
) -> S19kRxDiag {
    let d1 = classify_s19k_bm1366_rx_after(after, s1, baud);
    let d2 = classify_s19k_bm1366_rx_after(after, s2, baud);
    match after {
        S19kRxExpectedAfter::WorkDispatch => match (d1, d2) {
            (S19kRxDiag::JobNonceFillOk, S19kRxDiag::JobNonceFillOk) => {
                S19kRxDiag::JobNonceFillOk
            }
            (S19kRxDiag::JobNonceFillOk, S19kRxDiag::Silence)
            | (S19kRxDiag::Silence, S19kRxDiag::JobNonceFillOk) => {
                S19kRxDiag::SinglePortNotDualProof
            }
            (S19kRxDiag::Silence, S19kRxDiag::Silence) => S19kRxDiag::Silence,
            (S19kRxDiag::UartConfigMismatch, _) | (_, S19kRxDiag::UartConfigMismatch) => {
                S19kRxDiag::UartConfigMismatch
            }
            _ => S19kRxDiag::FramingOrEcho,
        },
        S19kRxExpectedAfter::WorkDispatch2156 => match (d1, d2) {
            (S19kRxDiag::WrongJobShapeSilence, S19kRxDiag::WrongJobShapeSilence) => {
                S19kRxDiag::WrongJobShapeSilence
            }
            _ => S19kRxDiag::FramingOrEcho,
        },
        S19kRxExpectedAfter::GetAddress => match (d1, d2) {
            (S19kRxDiag::ChipAddressOk, S19kRxDiag::ChipAddressOk) => S19kRxDiag::ChipAddressOk,
            (S19kRxDiag::ChipAddressOk, S19kRxDiag::Silence)
            | (S19kRxDiag::Silence, S19kRxDiag::ChipAddressOk)
            | (S19kRxDiag::ChipAddressOk, S19kRxDiag::AsicResetOrUninit)
            | (S19kRxDiag::AsicResetOrUninit, S19kRxDiag::ChipAddressOk) => {
                S19kRxDiag::SinglePortNotDualProof
            }
            (S19kRxDiag::AsicResetOrUninit, S19kRxDiag::AsicResetOrUninit) => {
                S19kRxDiag::AsicResetOrUninit
            }
            (S19kRxDiag::UartConfigMismatch, _) | (_, S19kRxDiag::UartConfigMismatch) => {
                S19kRxDiag::UartConfigMismatch
            }
            (S19kRxDiag::ChainFailShortEnum, _) | (_, S19kRxDiag::ChainFailShortEnum) => {
                S19kRxDiag::ChainFailShortEnum
            }
            (S19kRxDiag::ChipFastUartUnread, S19kRxDiag::ChipFastUartUnread) => {
                S19kRxDiag::ChipFastUartUnread
            }
            _ => S19kRxDiag::FramingOrEcho,
        },
        S19kRxExpectedAfter::GetAddress115200Retry => match (d1, d2) {
            (S19kRxDiag::ChipHeardAt115200, S19kRxDiag::ChipHeardAt115200) => {
                S19kRxDiag::ChipHeardAt115200
            }
            (S19kRxDiag::GetAddressSilenceAt115200, S19kRxDiag::GetAddressSilenceAt115200) => {
                S19kRxDiag::GetAddressSilenceAt115200
            }
            (S19kRxDiag::ChipHeardAt115200, S19kRxDiag::GetAddressSilenceAt115200)
            | (S19kRxDiag::GetAddressSilenceAt115200, S19kRxDiag::ChipHeardAt115200) => {
                S19kRxDiag::SinglePortNotDualProof
            }
            _ => S19kRxDiag::Inconclusive,
        },
        S19kRxExpectedAfter::FastUart28 => match (d1, d2) {
            (S19kRxDiag::FastUartRegOk, S19kRxDiag::FastUartRegOk) => S19kRxDiag::FastUartRegOk,
            (S19kRxDiag::ChipFastUartUnread, S19kRxDiag::ChipFastUartUnread) => {
                S19kRxDiag::ChipFastUartUnread
            }
            (S19kRxDiag::UartConfigMismatch, _) | (_, S19kRxDiag::UartConfigMismatch) => {
                S19kRxDiag::UartConfigMismatch
            }
            (S19kRxDiag::FastUartRegOk, _) | (_, S19kRxDiag::FastUartRegOk) => {
                S19kRxDiag::SinglePortNotDualProof
            }
            _ => S19kRxDiag::FramingOrEcho,
        },
        S19kRxExpectedAfter::FastUart28At115200 => match (d1, d2) {
            (S19kRxDiag::FastUart28HeardAt115200, S19kRxDiag::FastUart28HeardAt115200) => {
                S19kRxDiag::FastUart28HeardAt115200
            }
            (S19kRxDiag::FastUart28SilenceAt115200, S19kRxDiag::FastUart28SilenceAt115200) => {
                S19kRxDiag::FastUart28SilenceAt115200
            }
            (S19kRxDiag::FastUart28HeardAt115200, S19kRxDiag::FastUart28SilenceAt115200)
            | (S19kRxDiag::FastUart28SilenceAt115200, S19kRxDiag::FastUart28HeardAt115200) => {
                S19kRxDiag::SinglePortNotDualProof
            }
            _ => S19kRxDiag::Inconclusive,
        },
        _ => {
            if d1 == d2 {
                d1
            } else {
                S19kRxDiag::Inconclusive
            }
        }
    }
}

/// One required port JobNonce + one Silence is not 2-board work proof.
pub fn refuse_one_port_work_as_dual_chain_proof(diag: S19kRxDiag) -> Result<(), &'static str> {
    if diag == S19kRxDiag::SinglePortNotDualProof {
        return Err("one required tty JobNonce/ChipAddress, the other silent; not dual-chain proof");
    }
    Ok(())
}

/// 115200 GetAddress silence is not a FastUART 0x28 unread.
pub fn refuse_getaddress_115200_silence_as_fastuart_unread(
    diag: S19kRxDiag,
) -> Result<(), &'static str> {
    if diag == S19kRxDiag::ChipFastUartUnread {
        return Err(
            "GetAddress115200Retry silence is GetAddressSilenceAt115200, not ChipFastUartUnread",
        );
    }
    Ok(())
}

pub fn refuse_fastuart_28_heard_at_115200_as_3m_work_proof(
    diag: S19kRxDiag,
) -> Result<(), &'static str> {
    if diag == S19kRxDiag::FastUart28HeardAt115200 {
        return Err(
            "FastUart28HeardAt115200 is diagnostic; work TX stays on restored 3M GetAddress",
        );
    }
    Ok(())
}

pub fn refuse_fastuart_28_heard_at_115200_as_getaddress_chip(
    diag: S19kRxDiag,
) -> Result<(), &'static str> {
    if diag == S19kRxDiag::FastUart28HeardAt115200 {
        return Err("0x28 CommandReply at 115200 is not GetAddress ChipHeardAt115200");
    }
    Ok(())
}

pub fn refuse_fastuart_28_silence_at_115200_as_fastuart_unread(
    diag: S19kRxDiag,
) -> Result<(), &'static str> {
    if diag == S19kRxDiag::ChipFastUartUnread {
        return Err(
            "FastUart28At115200 silence is FastUart28SilenceAt115200, not ChipFastUartUnread",
        );
    }
    Ok(())
}

pub fn admit_s19k_115200_fastuart_28_is_typed(src: &str) -> Result<(), &'static str> {
    let start = src
        .find("S19kRxExpectedAfter::FastUart28At115200 => match obs")
        .ok_or("missing FastUart28At115200 match")?;
    let rest = &src[start..];
    let end = rest.find("S19kRxExpectedAfter::WorkDispatch").unwrap_or(rest.len());
    let body = &rest[..end];
    if body.contains("ChipFastUartUnread") {
        return Err("115200 FastUART 0x28 silence must not be ChipFastUartUnread");
    }
    if body.contains("ChipHeardAt115200") && !body.contains("FastUart28HeardAt115200") {
        return Err("115200 FastUART 0x28 reply must not be ChipHeardAt115200");
    }
    if !body.contains("FastUart28HeardAt115200") || !body.contains("FastUart28SilenceAt115200") {
        return Err("115200 FastUART 0x28 must have heard/silence diags");
    }
    Ok(())
}

pub fn admit_s19k_production_probes_fastuart_28_at_115200(src: &str) -> Result<(), &'static str> {
    if !src.contains("s19k_track1_should_probe_fastuart_28_at_115200") {
        return Err("production must gate 115200 FastUART 0x28 on GetAddress silence");
    }
    if !src.contains("S19kRxExpectedAfter::FastUart28At115200") {
        return Err("production must classify FastUart28At115200");
    }
    let arm = src
        .find("Track1HostBaudRestore::arm")
        .ok_or("missing restore arm")?;
    let ga = src
        .find("S19kRxExpectedAfter::GetAddress115200Retry")
        .ok_or("missing 115200 GetAddress classify")?;
    let fu = src
        .find("S19kRxExpectedAfter::FastUart28At115200")
        .ok_or("missing FastUart28At115200 classify")?;
    if arm < ga && ga < fu {
        Ok(())
    } else {
        Err("restore arm, then 115200 GetAddress, then 115200 FastUART 0x28")
    }
}

pub fn admit_s19k_115200_getaddress_silence_is_typed(src: &str) -> Result<(), &'static str> {
    let start = src
        .find("S19kRxExpectedAfter::GetAddress115200Retry => match obs")
        .ok_or("missing GetAddress115200Retry match")?;
    let rest = &src[start..];
    let end = rest.find("S19kRxExpectedAfter::FastUart28").unwrap_or(rest.len());
    let body = &rest[..end];
    if body.contains("ChipFastUartUnread") {
        return Err("115200 GetAddress silence must not be ChipFastUartUnread");
    }
    if !body.contains("GetAddressSilenceAt115200") {
        return Err("115200 GetAddress silence must be GetAddressSilenceAt115200");
    }
    Ok(())
}

/// : GetAddress baud must be typed, not hardcoded `Ok(())`.
pub fn admit_s19k_production_types_getaddress_baud(src: &str) -> Result<(), &'static str> {
    if !src.contains("s19k_track1_classify_rx_baud") {
        return Err("production GetAddress must type baud via s19k_track1_classify_rx_baud");
    }
    let ga = src
        .find("S19kRxExpectedAfter::GetAddress")
        .ok_or("missing GetAddress classify")?;
    let observe = src[ga..]
        .find("S19k GetAddress observe")
        .ok_or("missing GetAddress observe log")?;
    let window = &src[ga..ga + observe];
    if window.contains("Ok(())") {
        return Err("GetAddress classify must not hardcode Ok(()) baud");
    }
    if !window.contains("track1_baud") && !window.contains("s19k_track1_classify_rx_baud") {
        return Err("GetAddress classify must consume the typed Track-1 baud");
    }
    Ok(())
}

/// : Track-1 must broadcast-read FastUART 0x28 (52 05 00 28),
/// not single-chip 0x42 and not skip the probe.
pub fn admit_s19k_production_reads_fastuart_28(src: &str) -> Result<(), &'static str> {
    if !src.contains("S19kRxExpectedAfter::FastUart28") {
        return Err("production must classify FastUart28 after 0x28 read");
    }
    if !src.contains("send_read_reg_broadcast_bm1397plus")
        && !src.contains("[0x52, 0x05, 0x00, 0x28]")
        && !src.contains("pack_read_register_bcast_uart")
    {
        return Err("production must TX broadcast 52 05 00 28, not skip 0x28");
    }
    if src.contains("send_read_reg_bm1397plus(0, 0x28)")
        || src.contains("send_read_reg_bm1397plus(0x00, 0x28)")
    {
        return Err("0x42 single-chip read is not broadcast FastUART 0x28");
    }
    Ok(())
}

/// Production must classify InitRearm RX after ticket/HCN writes.
pub fn admit_s19k_production_classifies_init_rearm_rx(src: &str) -> Result<(), &'static str> {
    if !src.contains("S19kRxExpectedAfter::InitRearm") {
        return Err("production must classify InitRearm after ticket/HCN re-arm");
    }
    if !src.contains("S19k InitRearm observe") {
        return Err("production must log InitRearm observe");
    }
    Ok(())
}

/// Observational admit: returns the typed diag. Never claims live shares.
pub fn admit_s19k_rx_after(
    after: S19kRxExpectedAfter,
    obs: &S19kUartRxObservation,
    baud: Result<(), &'static str>,
) -> Result<S19kRxDiag, &'static str> {
    Ok(classify_s19k_bm1366_rx_after(after, obs, baud))
}

/// Silence after GetAddress is rail/UART/reset, not a parser fault.
pub fn refuse_silence_after_getaddress_as_parser_fault(
    obs: &S19kUartRxObservation,
) -> Result<(), &'static str> {
    if matches!(obs, S19kUartRxObservation::Silence { .. }) {
        return Err("GetAddress silence is rail/UART/reset, not a parser fault");
    }
    Ok(())
}

/// Zero RX after the refused `21 56` prefix is not parser proof.
pub fn refuse_zero_nonce_after_2156_as_parser_proof(
    tx_prefix: &[u8],
    obs: &S19kUartRxObservation,
) -> Result<(), &'static str> {
    use crate::s19k_braiins_job::{classify_job_wire_prefix, JobWirePrefixKind};
    if classify_job_wire_prefix(tx_prefix) == JobWirePrefixKind::FpgaEspLiveMiss
        && matches!(obs, S19kUartRxObservation::Silence { .. })
    {
        return Err("0 nonces after 55 AA 21 56 is not parser proof");
    }
    Ok(())
}

/// Fill-path TX `21 36` job_id (log 0) must equal RX raw job byte.
/// ESP `id & 0xF8` is refused as the fill history key.
pub fn admit_fill_work_id_tx_rx_correlate(
    tx_wire: &[u8],
    rx_frame: &[u8],
) -> Result<(), &'static str> {
    use crate::s19k_braiins_job::{
        classify_job_wire_prefix, s19k_braiins_fill_job_id, JobWirePrefixKind, CLOSED_11D_PREFIX,
    };
    if tx_wire.len() < 5 {
        return Err("TX wire shorter than prefix+job_id");
    }
    if classify_job_wire_prefix(tx_wire) != JobWirePrefixKind::Closed11d {
        return Err("fill TX prefix must be 55 AA 21 36");
    }
    if tx_wire[0..4] != CLOSED_11D_PREFIX {
        return Err("CLOSED_11D_PREFIX drift");
    }
    let kind = classify_bm1366_uart_rx(rx_frame).map_err(|_| "RX is not an 11-byte UART frame")?;
    let S19kUartRxKind::JobNonce { raw_job_byte, .. } = kind else {
        return Err("RX is not JobNonce");
    };
    let tx_id = tx_wire[4];
    if tx_id == s19k_braiins_fill_job_id(raw_job_byte) {
        return Ok(());
    }
    Err("TX job_id is not fill identity of RX raw job byte")
}

/// Hunt `AA 55` 11-byte frames in a raw UART read. Never invents success.
pub fn observe_bm1366_uart_rx(buf: &[u8], window_ms: u32) -> S19kUartRxObservation {
    if buf.is_empty() {
        return S19kUartRxObservation::Silence { window_ms };
    }
    if let Some(at) = find_subslice(buf, &[0x55, 0xAA]) {
        if find_subslice(buf, &UART_RESP_PREAMBLE).is_none() {
            return S19kUartRxObservation::HostPreambleEcho { at };
        }
    }
    let Some(first) = find_subslice(buf, &UART_RESP_PREAMBLE) else {
        let n = buf.len().min(8);
        let mut first8 = [0u8; 8];
        first8[..n].copy_from_slice(&buf[..n]);
        return S19kUartRxObservation::NoPreamble {
            nbytes: buf.len(),
            first8,
            first8_len: n,
        };
    };
    if buf.len() - first < UART_RESP_LEN {
        return S19kUartRxObservation::ShortFrame {
            at: first,
            available: buf.len() - first,
        };
    }
    let mut frames = Vec::new();
    let mut crc = Vec::new();
    let mut i = first;
    while i + UART_RESP_LEN <= buf.len() {
        if buf[i] != UART_RESP_PREAMBLE[0] || buf[i + 1] != UART_RESP_PREAMBLE[1] {
            i += 1;
            continue;
        }
        let slice = &buf[i..i + UART_RESP_LEN];
        match classify_bm1366_uart_rx(slice) {
            Ok(kind) => {
                frames.push(kind);
                crc.push(verify_bm1366_uart_rx_crc(slice).unwrap_or(S19kRxCrcStatus::NotChecked));
                i += UART_RESP_LEN;
            }
            Err(_) => i += 1,
        }
    }
    if frames.is_empty() {
        return S19kUartRxObservation::ShortFrame {
            at: first,
            available: buf.len() - first,
        };
    }
    S19kUartRxObservation::Frames {
        trailing_unparsed: buf.len() - i,
        frames,
        crc,
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Braiins fill log 0: the raw job byte is the work_id.
pub fn braiins_fill_work_id_from_kind(kind: S19kUartRxKind) -> Result<u8, S19kUartRxError> {
    match kind {
        S19kUartRxKind::JobNonce { raw_job_byte, .. } => Ok(raw_job_byte),
        _ => Err(S19kUartRxError::BadPreamble),
    }
}

/// ESP `id & 0xF8` drops the low 3 bits Braiins fill uses as work_id.
pub fn refuse_esp_masked_job_id_as_braiins_fill_work_id(
    masked: u8,
    raw: u8,
) -> Result<(), &'static str> {
    if masked != raw {
        return Err("ESP id&0xF8 is not Braiins fill work_id (raw job byte, log 0)");
    }
    Ok(())
}

/// Compact diagnostic line for bench logs.
pub fn format_rx_observation(obs: &S19kUartRxObservation) -> String {
    match obs {
        S19kUartRxObservation::Silence { window_ms } => {
            format!("S19K_RX silence window_ms={window_ms} (silence is not a parser fault)")
        }
        S19kUartRxObservation::NoPreamble {
            nbytes,
            first8,
            first8_len,
        } => {
            let hex: String = first8[..*first8_len]
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            format!("S19K_RX no_preamble nbytes={nbytes} first8={hex}")
        }
        S19kUartRxObservation::HostPreambleEcho { at } => {
            format!("S19K_RX host_tx_echo 55AA at={at} (not ASIC RX)")
        }
        S19kUartRxObservation::ShortFrame { at, available } => {
            format!("S19K_RX short AA55 at={at} available={available}")
        }
        S19kUartRxObservation::Frames {
            frames,
            crc,
            trailing_unparsed,
        } => {
            format!(
                "S19K_RX frames={} crc={:?} trailing={trailing_unparsed} first={:?}",
                frames.len(),
                crc,
                frames.first()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s19k_bm1366_wire_b::{
        cmd_chain_inactive_bcast, cmd_get_address_bcast, refuse_s19k_public_floor_as_aml_interval,
        S19K_AML_ADDR_INTERVAL, S19K_WIRE_CHIP_ID,
    };

    #[test]
    fn get_address_is_55_aa_52_not_54_or_53() {
        assert_eq!(pack_get_address_uart(), [0x55, 0xAA, 0x52, 0x05, 0x00, 0x00, 0x0A]);
        assert_ne!(&pack_get_address_uart()[2..], &[0x54, 0x05, 0x00, 0x00, 0x0A]);
        assert_ne!(pack_get_address_uart(), CHAIN_INACTIVE_UART);
        assert_eq!(cmd_get_address_bcast(), [0x52, 0x05, 0x00, 0x00, 0x0A]);
        assert_eq!(cmd_chain_inactive_bcast(), [0x53, 0x05, 0x00, 0x00, 0x03]);
        assert_eq!(S19K_AML_ADDR_INTERVAL, 2);
        assert!(refuse_s19k_public_floor_as_aml_interval(3).is_err());
        assert_eq!(S19K_WIRE_CHIP_ID, 0x1366);
        eprintln!(
            "S19K_GET_ADDRESS {}",
            pack_get_address_uart()
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    #[test]
    fn chipid_fixture_classifies_0x1366() {
        // Constructed ChipAddress with command CRC5 init 0x03.
        let mut frame = [
            0xAA, 0x55, 0x13, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        frame[10] = command_response_crc5(&frame[2..10]);
        assert_eq!(
            verify_bm1366_uart_rx_crc(&frame).unwrap(),
            S19kRxCrcStatus::EspRemainderOk
        );
        match classify_bm1366_uart_rx(&frame).unwrap() {
            S19kUartRxKind::ChipAddress {
                chip_id,
                value_address,
                responder_address,
            } => {
                assert_eq!(chip_id, 0x1366);
                assert_eq!(value_address, 0);
                assert_eq!(responder_address, 0);
            }
            other => panic!("expected ChipAddress, got {other:?}"),
        }
    }

    #[test]
    fn job_nonce_uses_bm1366_id_mask_not_bm1368_shift() {
        // S21 live comparative `AA 55 60 96 39 4C 02 14 03 04 8E` decoded with BM1366 masks.
        let frame = [
            0xAA, 0x55, 0x60, 0x96, 0x39, 0x4C, 0x02, 0x14, 0x03, 0x04, 0x8E,
        ];
        match classify_bm1366_uart_rx(&frame).unwrap() {
            S19kUartRxKind::JobNonce {
                nonce_be,
                midstate_num,
                job_id,
                raw_job_byte,
                small_core,
                version_be,
            } => {
                assert_eq!(nonce_be, 0x6096_394C);
                assert_eq!(midstate_num, 0x02);
                assert_eq!(job_id, 0x10); // 0x14 & 0xF8
                assert_eq!(raw_job_byte, 0x14);
                assert_eq!(
                    braiins_fill_work_id_from_kind(S19kUartRxKind::JobNonce {
                        nonce_be,
                        midstate_num,
                        job_id,
                        raw_job_byte,
                        small_core,
                        version_be,
                    })
                    .unwrap(),
                    0x14
                );
                assert!(refuse_esp_masked_job_id_as_braiins_fill_work_id(0x10, 0x14).is_err());
                assert_eq!(small_core, 0x04);
                eprintln!("S19K_UART_RX_JOB_ID {job_id:#04x}");
                assert_eq!(version_be, 0x0304);
                assert_eq!(chip_addr_from_nonce_be(nonce_be), ((0x6096_394C >> 17) & 0xff) as u8);
                assert_eq!(core_id_from_nonce_be(nonce_be), ((0x6096_394C >> 25) & 0x7f) as u8);
                assert_eq!(asic_index_from_nonce_be(nonce_be), chip_addr_from_nonce_be(nonce_be) / 2);
            }
            other => panic!("expected JobNonce, got {other:?}"),
        }
        assert!(classify_bm1366_uart_rx(&[0x00, 0x00, 0xAA]).is_err());
        assert!(classify_bm1366_uart_rx(&[0x55, 0xAA, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn silence_is_not_a_framing_error() {
        let obs = observe_bm1366_uart_rx(&[], 45_000);
        assert_eq!(obs, S19kUartRxObservation::Silence { window_ms: 45_000 });
        assert!(format_rx_observation(&obs).contains("silence"));
        assert!(format_rx_observation(&obs).contains("silence is not a parser fault"));
        assert!(!format_rx_observation(&obs).contains("framing error"));
        assert!(expected_rx_after(S19kRxExpectedAfter::WorkDispatch).contains("21 36"));
        assert!(expected_rx_after(S19kRxExpectedAfter::WorkDispatch).contains("21 56"));
        let work = expected_rx_after(S19kRxExpectedAfter::WorkDispatch);
        assert!(work.contains("raw job byte"));
        assert!(work.contains("not ESP id&0xF8"));
        assert!(work.contains("work-type must be 1"));
        assert!(!work.contains("job_id = id & 0xF8"));
    }

    #[test]
    fn hunter_distinguishes_host_echo_garbage_and_chip_address() {
        let echo = observe_bm1366_uart_rx(&[0x00, 0x55, 0xAA, 0x21, 0x36], 10);
        assert!(matches!(echo, S19kUartRxObservation::HostPreambleEcho { at: 1 }));

        let garbage = observe_bm1366_uart_rx(&[0x00, 0x00, 0xFF, 0x11], 10);
        assert!(matches!(
            garbage,
            S19kUartRxObservation::NoPreamble { nbytes: 4, .. }
        ));

        let short = observe_bm1366_uart_rx(&[0xAA, 0x55, 0x13, 0x66], 10);
        assert!(matches!(
            short,
            S19kUartRxObservation::ShortFrame {
                at: 0,
                available: 4
            }
        ));

        let frame = [
            0xAA, 0x55, 0x13, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        match observe_bm1366_uart_rx(&frame, 10) {
            S19kUartRxObservation::Frames { frames, .. } => {
                assert!(matches!(
                    frames[0],
                    S19kUartRxKind::ChipAddress { chip_id: 0x1366, .. }
                ));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn s21_comparative_nonce_does_not_close_job_crc5_init_1b() {
        // Comparative BM1368 live nonce. Trailer 0x8E bits4:0 = 0x0E.
        // RTL-named job init 0x1B does **not** reproduce 0x0E (host scan:
        // 0x1B→0x15). Do not fail-closed on job CRC. Layout/masks still hold.
        let frame = [
            0xAA, 0x55, 0x60, 0x96, 0x39, 0x4C, 0x02, 0x14, 0x03, 0x04, 0x8E,
        ];
        let payload = &frame[2..10];
        assert_ne!(job_response_crc5_experimental(payload), frame[10] & 0x1F);
        assert_eq!(
            verify_bm1366_uart_rx_crc(&frame).unwrap(),
            S19kRxCrcStatus::EspRemainderOk
        );
        assert!(admit_esp_rx_crc5_remainder(&frame).is_ok());
        assert!(refuse_rtl_1b_payload_as_job_crc_drop(&frame).is_err());
        assert_eq!(command_response_crc5(&[]), RESP_CRC5_INIT_COMMAND);
        assert!(command_response_crc5(payload) < 0x20);
        let matching = job_crc5_inits_matching(payload, 0x0E);
        assert!(
            !matching.contains(&RESP_CRC5_INIT_JOB_EXPERIMENTAL),
            "RTL-named init 0x1B must stay DESK_PENDING against this comparative trailer"
        );
        assert_eq!(ESP_RX_REG_OR_JOB_ID_OFF, 7);
        assert_eq!(ESP_RX_IS_JOB_BIT, JOB_TRAILER_BIT);
        assert!(refuse_rx_byte5_as_register_address(5).is_err());
        assert!(refuse_rx_byte5_as_register_address(7).is_ok());
        // read_register(0x0) reply: value=0x13660000, asic=0x04, reg=0x00
        // still ChipAddress because chip_id high-16 is 0x1366 and reg=0.
        let mut enum0 = [0xAA, 0x55, 0x13, 0x66, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
        enum0[10] = command_response_crc5(&enum0[2..10]);
        match classify_bm1366_uart_rx(&enum0).unwrap() {
            S19kUartRxKind::ChipAddress {
                chip_id,
                responder_address,
                ..
            } => {
                assert_eq!(chip_id, 0x1366);
                assert_eq!(responder_address, 0x04);
            }
            other => panic!("{other:?}"),
        }
        // Different register: CommandReply, not ChipAddress.
        let mut reg10 = [0xAA, 0x55, 0x00, 0x00, 0x11, 0x5A, 0x08, 0x10, 0x00, 0x00, 0x00];
        reg10[10] = command_response_crc5(&reg10[2..10]);
        match classify_bm1366_uart_rx(&reg10).unwrap() {
            S19kUartRxKind::CommandReply {
                value_be,
                asic_address,
                register_address,
            } => {
                assert_eq!(value_be, 0x0000_115A);
                assert_eq!(asic_address, 0x08);
                assert_eq!(register_address, 0x10);
            }
            other => panic!("{other:?}"),
        }
        let addrs = enum_asic_addrs_from_rx(&[
            classify_bm1366_uart_rx(&enum0).unwrap(),
            classify_bm1366_uart_rx(&reg10).unwrap(),
        ]);
        assert_eq!(addrs, vec![0x04, 0x08]);
        assert_eq!(first_missing_enum_addr(&[0, 4, 6, 8], 2, 77), Some(0x02));
        assert_eq!(first_missing_enum_addr(&[0, 2, 4], 2, 3), None);
        assert!(
            !matching.is_empty(),
            "sweep must find at least one init that fits the comparative trailer"
        );
        // Still never fail-closed: a matching comparative init is not a BM1366 vector.
        assert_ne!(job_response_crc5_experimental(payload), 0x0E);
    }

    #[test]
    fn held_bm136x_job_frames_pass_esp_remainder_not_rtl_1b() {
        assert_eq!(esp_asic_crc5(&[0x52, 0x05, 0x00, 0x00]), 0x0A);
        assert_eq!(ESP_BM1366_CHIP_ID_RX_LEN, UART_RESP_LEN);
        assert_eq!(HELD_BM1368_S21_JOB, [
            0xAA, 0x55, 0x60, 0x96, 0x39, 0x4C, 0x02, 0x14, 0x03, 0x04, 0x8E,
        ]);
        assert!(admit_esp_rx_crc5_remainder(&HELD_BM1368_S21_JOB).is_ok());
        assert!(refuse_held_bm1362_job_as_bm1366_vector(0x1362).is_err());
        assert!(refuse_held_bm1362_job_as_bm1366_vector(0x1368).is_err());
        assert!(refuse_held_bm1362_job_as_bm1366_vector(0x1366).is_ok());
        assert!(admit_s19k_no_held_bm1366_job_nonce().is_err());
        assert!(admit_s19k_live88_held_bm1366_job_nonce().is_ok());
        assert_eq!(
            S19K_HELD_BM1366_JOB_NONCE,
            Some(S19K_LIVE88_S1_LEFTOVER_JOB_NONCE.as_slice())
        );
        assert!(refuse_held_s21_job_as_s19k_bm1366_nonce(&HELD_BM1368_S21_JOB).is_err());
        assert!(refuse_held_s21_job_as_s19k_bm1366_nonce(&[0xAA, 0x55]).is_ok());
        for frame in HELD_BM1362_JOB_FRAMES {
            assert!(refuse_held_bm1362_frames_as_s19k_bm1366_nonce(frame).is_err());
        }
        assert!(refuse_held_bm1362_frames_as_s19k_bm1366_nonce(&HELD_BM1368_S21_JOB).is_ok());
        for frame in HELD_BM1362_JOB_FRAMES {
            assert_eq!(frame[0], 0xAA);
            assert_eq!(frame[1], 0x55);
            assert_ne!(frame[10] & JOB_TRAILER_BIT, 0);
            assert_eq!(esp_rx_crc5_remainder(frame).unwrap(), 0);
            assert_eq!(
                verify_bm1366_uart_rx_crc(frame).unwrap(),
                S19kRxCrcStatus::EspRemainderOk
            );
            assert!(refuse_rtl_1b_payload_as_job_crc_drop(frame).is_err());
            assert_ne!(
                job_response_crc5_experimental(&frame[2..10]),
                frame[10] & 0x1F
            );
            match classify_bm1366_uart_rx(frame).unwrap() {
                S19kUartRxKind::JobNonce { job_id, .. } => {
                    assert_eq!(job_id, frame[7] & BM1366_JOB_ID_MASK);
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(HELD_BM1362_JOB_FRAMES.len(), 8);
    }

    #[test]
    fn expected_rx_fixtures_and_diag_are_not_parser_proof() {
        use crate::s19k_bm1366_init_seq::{
            classify_s19k_uart_baud_dialect, , BRAIINS_PASSTHROUGH_BAUD,
        };
        use crate::s19k_bm1366_wire_b::PUBLIC_FASTUART_VALUE;
        use crate::s19k_braiins_job::{
            build_s19k_braiins_mining_on_work_wire, classify_job_wire_prefix,
            s19k_braiins_fill_job_id, JobWirePrefixKind, LIVE_20260812_FPGA_PREFIX,
        };

        let baud_3m = classify_s19k_uart_baud_dialect(BRAIINS_PASSTHROUGH_BAUD, None).map(|_| ());
        assert!(baud_3m.is_ok());
        let baud_3001 =
            classify_s19k_uart_baud_dialect(BRAIINS_PASSTHROUGH_BAUD, Some)
                .map(|_| ());
        assert!(baud_3001.is_err());
        let baud_esp =
            classify_s19k_uart_baud_dialect(BRAIINS_PASSTHROUGH_BAUD, Some(PUBLIC_FASTUART_VALUE))
                .map(|_| ());
        assert!(baud_esp.is_err());

        let ca0 = bm1366_chip_address_uart(0);
        let ca2 = bm1366_chip_address_uart(2);
        assert_eq!(&ca2[0..7], &[0xAA, 0x55, 0x13, 0x66, 0x00, 0x02, 0x02]);
        assert_eq!(ca2[4], BM1366_CHIP_ADDRESS_CORE);
        match classify_bm1366_uart_rx(&ca2).unwrap() {
            S19kUartRxKind::ChipAddress {
                chip_id,
                value_address,
                responder_address,
            } => {
                assert_eq!(chip_id, 0x1366);
                assert_eq!(value_address, 2);
                assert_eq!(responder_address, 2);
            }
            other => panic!("{other:?}"),
        }
        assert!(admit_expected_chip_address_rx(&ca0, 0).is_ok());
        assert!(admit_expected_chip_address_rx(&ca2, 2).is_ok());
        assert!(admit_expected_chip_address_rx(&ca2, 0).is_err());
        assert!(refuse_bm1362_core03_as_bm1366_chip_address(&ca2).is_ok());
        let mut bm1362 = ca2;
        bm1362[4] = BM1362_CHIP_ADDRESS_CORE;
        assert!(refuse_bm1362_core03_as_bm1366_chip_address(&bm1362).is_err());

        let silence = observe_bm1366_uart_rx(&[], 45_000);
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::GetAddress, &silence, baud_3m),
            S19kRxDiag::AsicResetOrUninit
        );
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::FastUart28, &silence, baud_3m),
            S19kRxDiag::ChipFastUartUnread
        );
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::FastUart28, &silence, baud_3001),
            S19kRxDiag::UartConfigMismatch
        );
        let fu_frame = bm1366_command_reply_uart(0x0000_3001, 0x00, S19K_FASTUART_REG);
        match classify_bm1366_uart_rx(&fu_frame).unwrap() {
            S19kUartRxKind::CommandReply {
                value_be,
                register_address,
                ..
            } => {
                assert_eq!(value_be, 0x0000_3001);
                assert_eq!(register_address, 0x28);
            }
            other => panic!("{other:?}"),
        }
        let fu_obs = observe_bm1366_uart_rx(&fu_frame, 10);
        assert_eq!(extract_s19k_fastuart_reg28_from_obs(&fu_obs), Some(0x0000_3001));
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::FastUart28, &fu_obs, baud_3m),
            S19kRxDiag::FastUartRegOk
        );
        assert!(expected_rx_after(S19kRxExpectedAfter::FastUart28).contains("ChipFastUartUnread"));
        assert_eq!(
            classify_s19k_bm1366_rx_after(
                S19kRxExpectedAfter::GetAddress115200Retry,
                &silence,
                baud_3m
            ),
            S19kRxDiag::GetAddressSilenceAt115200
        );
        assert!(refuse_getaddress_115200_silence_as_fastuart_unread(
            S19kRxDiag::ChipFastUartUnread
        )
        .is_err());
        assert!(refuse_getaddress_115200_silence_as_fastuart_unread(
            S19kRxDiag::GetAddressSilenceAt115200
        )
        .is_ok());
        const UART_RX: &str = include_str!("s19k_bm1366_uart_rx.rs");
        assert!(admit_s19k_115200_getaddress_silence_is_typed(UART_RX).is_ok());
        let ca_obs_115200 = observe_bm1366_uart_rx(&ca2, 10);
        assert_eq!(
            classify_s19k_bm1366_rx_after(
                S19kRxExpectedAfter::GetAddress115200Retry,
                &ca_obs_115200,
                baud_3m
            ),
            S19kRxDiag::ChipHeardAt115200
        );
        assert!(expected_rx_after(S19kRxExpectedAfter::GetAddress115200Retry).contains("restore 3M"));
        assert_eq!(
            classify_s19k_bm1366_rx_after(
                S19kRxExpectedAfter::FastUart28At115200,
                &silence,
                baud_3m
            ),
            S19kRxDiag::FastUart28SilenceAt115200
        );
        assert_eq!(
            classify_s19k_bm1366_rx_after(
                S19kRxExpectedAfter::FastUart28At115200,
                &fu_obs,
                baud_3m
            ),
            S19kRxDiag::FastUart28HeardAt115200
        );
        assert!(refuse_fastuart_28_heard_at_115200_as_3m_work_proof(
            S19kRxDiag::FastUart28HeardAt115200
        )
        .is_err());
        assert!(refuse_fastuart_28_heard_at_115200_as_getaddress_chip(
            S19kRxDiag::FastUart28HeardAt115200
        )
        .is_err());
        assert!(refuse_fastuart_28_silence_at_115200_as_fastuart_unread(
            S19kRxDiag::ChipFastUartUnread
        )
        .is_err());
        assert!(refuse_fastuart_28_silence_at_115200_as_fastuart_unread(
            S19kRxDiag::FastUart28SilenceAt115200
        )
        .is_ok());
        assert!(admit_s19k_115200_fastuart_28_is_typed(UART_RX).is_ok());
        assert!(expected_rx_after(S19kRxExpectedAfter::FastUart28At115200)
            .contains("FastUart28HeardAt115200"));
        assert!(refuse_silence_after_getaddress_as_parser_fault(&silence).is_err());
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::GetAddress, &silence, baud_3001),
            S19kRxDiag::UartConfigMismatch
        );
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::GetAddress, &silence, baud_esp),
            S19kRxDiag::UartConfigMismatch
        );

        let s3 = observe_bm1366_uart_rx(&HELD_78_CAP_SERIAL_S3, 10);
        assert!(matches!(s3, S19kUartRxObservation::NoPreamble { nbytes: 3, .. }));
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::GetAddress, &s3, baud_3m),
            S19kRxDiag::FramingOrEcho
        );

        let mut short_enum = Vec::new();
        for addr in [0u8, 4, 6, 8, 10, 12, 14, 16] {
            short_enum.extend_from_slice(&bm1366_chip_address_uart(addr));
        }
        let short_obs = observe_bm1366_uart_rx(&short_enum, 10);
        match &short_obs {
            S19kUartRxObservation::Frames { frames, .. } => {
                let addrs = enum_asic_addrs_from_rx(frames);
                assert_eq!(first_missing_enum_addr(&addrs, 2, 77), Some(0x02));
                assert_eq!(frames.len(), 8);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::GetAddress, &short_obs, baud_3m),
            S19kRxDiag::ChainFailShortEnum
        );
        assert_ne!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::GetAddress, &short_obs, baud_3m),
            S19kRxDiag::Silence
        );

        let ca_obs = observe_bm1366_uart_rx(&ca2, 10);
        assert_eq!(
            admit_s19k_rx_after(S19kRxExpectedAfter::GetAddress, &ca_obs, baud_3m).unwrap(),
            S19kRxDiag::ChipAddressOk
        );
        let one = classify_s19k_chip_enum_complete(&ca_obs);
        assert!(matches!(
            one,
            S19kChipEnumCompleteness::Short { got: 1, missing: 0 }
        ));
        assert!(refuse_one_chipaddress_as_77_chip_complete(one).is_err());
        assert!(refuse_s19k_chipaddress_count_as_77_complete(0x1366, 1).is_err());
        assert!(refuse_s19k_chipaddress_count_as_77_complete(0x1366, 77).is_err());
        let complete_bytes = bm1366_constructed_77_chip_enum();
        assert_eq!(complete_bytes.len(), 77 * UART_RESP_LEN);
        let complete_obs = observe_bm1366_uart_rx(&complete_bytes, 10);
        assert_eq!(
            classify_s19k_chip_enum_complete(&complete_obs),
            S19kChipEnumCompleteness::Complete77
        );
        assert!(refuse_one_chipaddress_as_77_chip_complete(
            S19kChipEnumCompleteness::Complete77
        )
        .is_ok());
        assert!(refuse_one_chipaddress_as_77_chip_complete(
            classify_s19k_chip_enum_complete(&short_obs)
        )
        .is_err());
        let hal_bodies = extract_s19k_hal_bm1366_bodies(&complete_bytes);
        assert_eq!(hal_bodies.len(), 77);
        assert!(hal_bodies.iter().all(|b| b.len() == BM1366_UART_RESP_BODY_LEN));
        assert_eq!(hal_bodies[0][0..2], [0x13, 0x66]);
        let body7 = extract_s19k_aa55_bodies(&complete_bytes[..UART_RESP_LEN], 7);
        assert_eq!(body7.len(), 1);
        assert_eq!(body7[0].len(), 7);
        assert!(refuse_s19k_hal_body7_extract_as_bm1366_frame().is_err());
        let body11 = extract_s19k_aa55_bodies(&complete_bytes[..UART_RESP_LEN], 11);
        assert!(body11.is_empty(), "body_len=11 hunts 13-byte wire");
        let hal_obs = crate::s19k_braiins_chain_discover::observe_get_address_bodies(&hal_bodies, 10);
        assert_eq!(
            classify_s19k_chip_enum_complete(&hal_obs),
            S19kChipEnumCompleteness::Complete77
        );
        assert!(admit_s19k_hal_bodies_77_complete(classify_s19k_chip_enum_complete(
            &hal_obs
        ))
        .is_ok());
        let mut short_bodies = Vec::new();
        for addr in [0u8, 4, 6, 8, 10, 12, 14, 16] {
            short_bodies.push(bm1366_chip_address_uart(addr)[2..].to_vec());
        }
        let short_hal = crate::s19k_braiins_chain_discover::observe_get_address_bodies(&short_bodies, 10);
        assert!(matches!(
            classify_s19k_chip_enum_complete(&short_hal),
            S19kChipEnumCompleteness::Short { missing: 0x02, .. }
        ));
        const HAL: &str = include_str!("../../dcentrald-hal/src/serial_chain.rs");
        assert!(admit_s19k_hal_extracts_bm1366_body9(HAL).is_ok());
        assert!(admit_s19k_hal_midstream_body7_then_body9(HAL).is_ok());
        assert!(admit_s19k_hal_midstream_body7_then_body9(
            "fn try_extract_frame\ntry_extract_frame(BM1366_UART_RESP_BODY_LEN)"
        )
        .is_err());
        assert!(admit_s19k_hal_extracts_bm1366_body9(
            "fn try_extract_frame\ntry_extract_frame(BM139X_RESP_BODY_LEN)"
        )
        .is_err());
        let mut two = Vec::from(bm1366_fill_job_nonce_uart(2));
        two.extend_from_slice(&bm1366_chip_address_uart(0));
        let (b7, r7) = admit_s19k_body7_two_frame_leaves_residue(&two).unwrap();
        assert_eq!(b7.len(), 2);
        assert_eq!(r7.len(), 2);
        assert!(refuse_s19k_body7_residue_as_frame(&r7).is_err());
        let b9 = admit_s19k_body9_two_frame_no_residue(&two).unwrap();
        assert_eq!(b9.len(), 2);
        assert_eq!(b9[0].len(), 9);
        let first = bm1366_fill_job_nonce_uart(2);
        let next = bm1366_fill_job_nonce_uart(3);
        let recovered = admit_s19k_body7_residue_then_body9_recovers_next(&first, &next).unwrap();
        assert_eq!(recovered.len(), 9);
        assert_eq!(recovered.as_slice(), &next[2..]);
        assert!(admit_s19k_body7_residue_then_body9_recovers_next(&first[..10], &next).is_err());

        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::Reset, &silence, baud_3m),
            S19kRxDiag::Inconclusive
        );
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::ChainInactive, &silence, baud_3m),
            S19kRxDiag::Inconclusive
        );
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::InitRearm, &silence, baud_3m),
            S19kRxDiag::Inconclusive
        );
        let ticket_obs = observe_bm1366_uart_rx(&bm1366_rearm_ticket_reply_uart(), 10);
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::InitRearm, &ticket_obs, baud_3m),
            S19kRxDiag::RearmRegOk
        );
        let hcn_obs = observe_bm1366_uart_rx(&bm1366_rearm_hcn_reply_uart(), 10);
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::InitRearm, &hcn_obs, baud_3m),
            S19kRxDiag::RearmRegOk
        );
        let a4_kind = classify_bm1366_uart_rx(&bm1366_esp_version_mask_reply_uart()).unwrap();
        assert!(refuse_esp_a4_reply_as_fill_rearm_ok(a4_kind).is_err());
        let a4_obs = observe_bm1366_uart_rx(&bm1366_esp_version_mask_reply_uart(), 10);
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::InitRearm, &a4_obs, baud_3m),
            S19kRxDiag::FramingOrEcho
        );
        let set_obs = observe_bm1366_uart_rx(&bm1366_chip_address_uart(0x02), 10);
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::SetAddress, &set_obs, baud_3m),
            S19kRxDiag::SetAddressEcho
        );
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::SetAddress, &silence, baud_3m),
            S19kRxDiag::Inconclusive
        );
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::Reset, &set_obs, baud_3m),
            S19kRxDiag::Inconclusive
        );
        assert!(expected_rx_after(S19kRxExpectedAfter::Reset).contains("do not claim enum"));
        assert!(expected_rx_after(S19kRxExpectedAfter::InitRearm).contains("not 21 36 proof"));
        assert!(expected_rx_after(S19kRxExpectedAfter::InitRearm).contains("0x14"));
        assert!(expected_rx_after(S19kRxExpectedAfter::InitRearm).contains("0x10"));

        let tx = build_s19k_braiins_mining_on_work_wire(2, 0, [0; 32], [0; 32], 0, 0);
        assert_eq!(tx[3], 0x36);
        assert_eq!(tx[4], 2);
        assert_eq!(s19k_braiins_fill_job_id(2), 2);
        assert_eq!(classify_job_wire_prefix(&tx), JobWirePrefixKind::Closed11d);
        let rx = bm1366_fill_job_nonce_uart(2);
        match classify_bm1366_uart_rx(&rx).unwrap() {
            S19kUartRxKind::JobNonce {
                raw_job_byte,
                job_id,
                ..
            } => {
                assert_eq!(raw_job_byte, 2);
                assert_eq!(job_id, 2 & BM1366_JOB_ID_MASK);
                assert_eq!(job_id, 0);
                assert!(refuse_esp_masked_job_id_as_braiins_fill_work_id(job_id, raw_job_byte).is_err());
            }
            other => panic!("{other:?}"),
        }
        assert!(admit_fill_work_id_tx_rx_correlate(&tx, &rx).is_ok());
        assert!(admit_constructed_fill_nonce_correlates(&tx, 2).is_ok());
        assert_eq!(S19K_HAL_BODY7_WIRE_CUT, 9);
        let cut_fill = s19k_hal_body7_wire_cut(&rx).unwrap();
        assert_eq!(cut_fill.len(), 9);
        assert!(classify_bm1366_uart_rx(cut_fill).is_err());
        assert!(refuse_constructed_fill_body7_as_job_nonce(&tx, 2).is_err());
        assert!(refuse_constructed_fill_body7_observe_as_job_or_silence(2).is_err());
        let cut_obs = observe_bm1366_uart_rx(cut_fill, 10);
        assert!(matches!(cut_obs, S19kUartRxObservation::ShortFrame { .. }));
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::WorkDispatch, &cut_obs, baud_3m),
            S19kRxDiag::FramingOrEcho
        );
        let rx_obs = observe_bm1366_uart_rx(&rx, 10);
        assert_eq!(
            classify_s19k_bm1366_rx_after(S19kRxExpectedAfter::WorkDispatch, &rx_obs, baud_3m),
            S19kRxDiag::JobNonceFillOk
        );

        assert_eq!(
            classify_job_wire_prefix(&LIVE_20260812_FPGA_PREFIX),
            JobWirePrefixKind::FpgaEspLiveMiss
        );
        assert_eq!(
            classify_s19k_bm1366_rx_after(
                S19kRxExpectedAfter::WorkDispatch2156,
                &silence,
                baud_3m
            ),
            S19kRxDiag::WrongJobShapeSilence
        );
        assert!(refuse_zero_nonce_after_2156_as_parser_proof(
            &LIVE_20260812_FPGA_PREFIX,
            &silence
        )
        .is_err());
        assert!(refuse_zero_nonce_after_2156_as_parser_proof(&tx, &silence).is_ok());
        assert!(expected_rx_after(S19kRxExpectedAfter::WorkDispatch2156).contains("21 56"));

        assert!(admit_bm1366_uart_resp_body_len(9).is_ok());
        assert!(admit_bm1366_uart_resp_body_len(7).is_err());
        assert!(admit_bm1366_uart_resp_body_len(11).is_err());
        assert!(refuse_bm139x_default_body7_as_bm1366_uart(7).is_err());
        assert!(refuse_bm139x_default_body7_as_bm1366_uart(9).is_ok());
        assert!(refuse_response_bytes_11_as_set_response_len(11).is_err());
        assert!(refuse_response_bytes_11_as_set_response_len(9).is_ok());
        assert_eq!(BM1366_UART_RESP_BODY_LEN, 9);
        assert_eq!(UART_RESP_LEN, 11);
        const SERIAL: &str = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_set_response_len_is_bm1366_body(SERIAL).is_ok());
        assert!(admit_s19k_production_logs_77_enum_incomplete(SERIAL).is_ok());
        assert!(admit_s19k_production_types_getaddress_baud(SERIAL).is_ok());
        assert!(admit_s19k_production_reads_fastuart_28(SERIAL).is_ok());
        assert!(admit_s19k_production_probes_fastuart_28_at_115200(SERIAL).is_ok());
        assert!(admit_s19k_production_reads_fastuart_28("GetAddress only").is_err());
        assert!(admit_s19k_production_reads_fastuart_28(
            "S19kRxExpectedAfter::FastUart28\nsend_read_reg_bm1397plus(0, 0x28)"
        )
        .is_err());
        assert!(admit_s19k_production_types_getaddress_baud(
            "S19kRxExpectedAfter::GetAddress,\n                                &obs,\n                                Ok(()),\n                            );\n                                \"S19k GetAddress observe\""
        )
        .is_err());
        assert!(admit_s19k_production_set_response_len_is_bm1366_body(
            "let resp_body_len: usize = if is_bm1398 { 7 } else { 9 };"
        )
        .is_err());
        assert_eq!(SET_RESPONSE_LEN_11_AS_BODY_WIRE, 13);
        let cut7 = &HELD_BM1368_S21_JOB[..2 + BM139X_HAL_DEFAULT_RESP_BODY_LEN];
        assert_eq!(cut7.len(), 9);
        assert!(classify_bm1366_uart_rx(cut7).is_err());
        assert!(refuse_hal_body7_cut_as_job_or_chip(cut7).is_err());
        assert!(refuse_hal_body7_cut_as_job_or_chip(&HELD_BM1368_S21_JOB).is_ok());
        match classify_bm1366_uart_rx(&HELD_BM1368_S21_JOB).unwrap() {
            S19kUartRxKind::JobNonce { .. } => {}
            other => panic!("{other:?}"),
        }
        let ca_body = &ca2[2..];
        assert_eq!(ca_body.len(), BM1366_UART_RESP_BODY_LEN);

        assert_eq!(
            classify_s19k_dual_uart_rx_after(
                S19kRxExpectedAfter::WorkDispatch,
                &rx_obs,
                &rx_obs,
                baud_3m
            ),
            S19kRxDiag::JobNonceFillOk
        );
        assert_eq!(
            classify_s19k_dual_uart_rx_after(
                S19kRxExpectedAfter::WorkDispatch,
                &rx_obs,
                &silence,
                baud_3m
            ),
            S19kRxDiag::SinglePortNotDualProof
        );
        assert!(refuse_one_port_work_as_dual_chain_proof(S19kRxDiag::SinglePortNotDualProof).is_err());
        assert!(refuse_one_port_work_as_dual_chain_proof(S19kRxDiag::JobNonceFillOk).is_ok());
        assert_eq!(
            classify_s19k_dual_uart_rx_after(
                S19kRxExpectedAfter::WorkDispatch,
                &silence,
                &silence,
                baud_3m
            ),
            S19kRxDiag::Silence
        );
        assert_eq!(
            classify_s19k_dual_uart_rx_after(
                S19kRxExpectedAfter::WorkDispatch2156,
                &silence,
                &silence,
                baud_3m
            ),
            S19kRxDiag::WrongJobShapeSilence
        );
        let ca_obs2 = observe_bm1366_uart_rx(&ca0, 10);
        assert_eq!(
            classify_s19k_dual_uart_rx_after(
                S19kRxExpectedAfter::GetAddress,
                &ca_obs,
                &ca_obs2,
                baud_3m
            ),
            S19kRxDiag::ChipAddressOk
        );
        assert_eq!(
            classify_s19k_dual_uart_rx_after(
                S19kRxExpectedAfter::GetAddress,
                &ca_obs,
                &silence,
                baud_3m
            ),
            S19kRxDiag::SinglePortNotDualProof
        );
        assert!(admit_fill_work_id_tx_rx_correlate(&tx, &rx).is_ok());
    }

    #[test]
    fn s19k_rxbuf_leftover_aa_plus_tx55_is_not_jobnonce() {
        let mut tx = S19K_CLOSED_SEND_WORK_PREFIX.to_vec();
        tx.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(refuse_s19k_rxbuf_leftover_aa_plus_tx55_as_jobnonce(
            &HELD_78_CAP_SERIAL_S3,
            &tx
        )
        .is_err());
        assert!(refuse_s19k_held_s3_aa_as_preamble_seed().is_err());
        assert_eq!(s19k_hal_rxbuf_keep_last_byte(&HELD_78_CAP_SERIAL_S3), vec![0xAA]);
        const SERIAL: &str = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_flush_rx_after_getaddress_nopreamble(SERIAL).is_ok());
        assert!(admit_s19k_production_flush_rx_after_fastuart_empty(SERIAL).is_ok());
        assert!(admit_s19k_production_flush_rx_after_115200_retry_empty(SERIAL).is_ok());
        assert!(admit_s19k_production_flush_rx_after_fastuart_115200_empty(SERIAL).is_ok());
    }

    #[test]
    fn s19k_s21_held_uart_is_1368_not_1366_jobnonce() {
        const ASIC: &[u8] = include_bytes!(
            "../../../../../"
        );
        const CMD: &[u8] = include_bytes!(
            "../../../../../"
        );
        assert_eq!(ASIC.len(), 4096);
        assert_eq!(CMD.len(), 4096);
        assert_eq!(&ASIC[..UART_RESP_LEN], HELD_BM1368_S21_JOB);
        assert!(admit_s21_held_uart_chip_id_is_1368_not_1366(ASIC).is_ok());
        assert!(admit_s21_held_uart_chip_id_is_1368_not_1366(CMD).is_ok());
        assert!(refuse_s21_held_uart_capture_as_s19k_jobnonce(ASIC).is_err());
        assert!(refuse_s21_held_uart_capture_as_s19k_jobnonce(CMD).is_err());
        assert_eq!(count_s21_held_chip_id_pairs(ASIC, [0x13, 0x66]), 0);
        assert_eq!(count_s21_held_chip_id_pairs(ASIC, [0x13, 0x68]), 108);
        assert!(admit_s19k_no_held_bm1366_job_nonce().is_err());
        assert!(admit_s19k_live88_held_bm1366_job_nonce().is_ok());
        assert_eq!(
            S19K_HELD_BM1366_JOB_NONCE,
            Some(S19K_LIVE88_S1_LEFTOVER_JOB_NONCE.as_slice())
        );
        assert_ne!(
            S19K_LIVE88_S1_LEFTOVER_JOB_NONCE.as_slice(),
            HELD_78_CAP_SERIAL_S3.as_slice()
        );
        assert_eq!(S19K_LIVE88_S1_LEFTOVER_JOB_NONCE[0], 0xAA);
        assert_eq!(S19K_LIVE88_S1_LEFTOVER_JOB_NONCE[1], 0x55);
        assert_ne!(S19K_LIVE88_S1_LEFTOVER_JOB_NONCE[10] & JOB_TRAILER_BIT, 0);
        assert_ne!(S19K_LIVE88_S2_LEFTOVER_JOB_NONCE[10] & JOB_TRAILER_BIT, 0);
    }

    #[test]
    fn s19k_live88_leftover_classifies_as_jobnonce_not_78_s3() {
        assert!(admit_s19k_live88_held_bm1366_job_nonce().is_ok());
        assert!(S19K_HELD_BM1366_JOB_NONCE.is_some());
        match classify_bm1366_uart_rx(&S19K_LIVE88_S1_LEFTOVER_JOB_NONCE) {
            Ok(S19kUartRxKind::JobNonce { .. }) => {}
            other => panic!("ttyS1 leftover must be JobNonce via shipped classifier: {other:?}"),
        }
        match classify_bm1366_uart_rx(&S19K_LIVE88_S2_LEFTOVER_JOB_NONCE) {
            Ok(S19kUartRxKind::JobNonce { .. }) => {}
            other => panic!("ttyS2 leftover must be JobNonce via shipped classifier: {other:?}"),
        }
        assert_ne!(
            S19K_LIVE88_S1_LEFTOVER_JOB_NONCE.as_slice(),
            HELD_78_CAP_SERIAL_S3.as_slice()
        );
        assert_ne!(
            S19K_LIVE88_S2_LEFTOVER_JOB_NONCE.as_slice(),
            HELD_78_CAP_SERIAL_S3.as_slice()
        );
        assert_eq!(HELD_78_CAP_SERIAL_S3, [0x00, 0x00, 0xAA]);
        assert_ne!(S19K_LIVE88_S1_LEFTOVER_JOB_NONCE[10] & JOB_TRAILER_BIT, 0);
        assert_ne!(S19K_LIVE88_S2_LEFTOVER_JOB_NONCE[10] & JOB_TRAILER_BIT, 0);
    }
}
