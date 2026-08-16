//! S9 SE `BOOT.bin` identity (desk-only).
//!
//! Held HiveOS inner `BOOT.bin` is a Zynq first-stage image. The file
//! names a bitstream *loader* (FSBL / `fpga_loadbitstream`) but does
//! **not** contain a raw `0xAA995566` fabric bitstream. This module
//! pins identity bytes. It does not invent an AXI fabric ABI.

/// Inner `BOOT.bin` size.
pub const BOOT_BIN_SIZE: usize = 2_752_048;
pub const BOOT_BIN_SHA256: &str =
    "e7353cb4a4b06434f3fc36b203fb0c794c54dc70491d319c23b0df3bfdaab222";
/// Image identification at byte `0x24` (`XNLX`).
pub const BOOT_IMAGE_IDENT: [u8; 4] = *b"XNLX";
pub const BOOT_IMAGE_IDENT_OFF: usize = 0x24;
/// Word at `0x20` is the Zynq header copy of `0xAA995566` stored LE.
pub const BOOT_HEADER_SYNC_OFF: usize = 0x20;
pub const BOOT_HEADER_SYNC_LE: u32 = 0xAA99_5566;
/// U-Boot FPGA-part table includes `7z007s` among other Zynq SKUs.
pub const BOOT_STRING_7Z007S: &str = "7z007s";
/// FSBL names a bitstream download path. That is not a register map.
pub const BOOT_FSBL_BITSTREAM_NEEDLE: &str = "PCAP Bitstream Download Failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeBootError {
    WrongSize { observed: usize },
    IdentMismatch,
    SyncMismatch,
    BitstreamAbiNotInImage,
}

pub fn admit_boot_header(bytes: &[u8]) -> Result<(), S9SeBootError> {
    if bytes.len() != BOOT_BIN_SIZE {
        return Err(S9SeBootError::WrongSize {
            observed: bytes.len(),
        });
    }
    let ident = bytes
        .get(BOOT_IMAGE_IDENT_OFF..BOOT_IMAGE_IDENT_OFF + 4)
        .ok_or(S9SeBootError::IdentMismatch)?;
    if ident != BOOT_IMAGE_IDENT {
        return Err(S9SeBootError::IdentMismatch);
    }
    let sync = u32::from_le_bytes(
        bytes
            .get(BOOT_HEADER_SYNC_OFF..BOOT_HEADER_SYNC_OFF + 4)
            .ok_or(S9SeBootError::SyncMismatch)?
            .try_into()
            .map_err(|_| S9SeBootError::SyncMismatch)?,
    );
    if sync != BOOT_HEADER_SYNC_LE {
        return Err(S9SeBootError::SyncMismatch);
    }
    Ok(())
}

/// No raw fabric bitstream is present to map AXI slaves from.
pub fn refuse_boot_bitstream_abi(has_raw_aa995566_payload: bool) -> Result<(), S9SeBootError> {
    if !has_raw_aa995566_payload {
        return Err(S9SeBootError::BitstreamAbiNotInImage);
    }
    // A raw sync word still would not be a DCENT fabric map.
    Err(S9SeBootError::BitstreamAbiNotInImage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_constants_match_held_image_metadata() {
        assert_eq!(BOOT_BIN_SIZE, 2_752_048);
        assert_eq!(BOOT_BIN_SHA256.len(), 64);
        assert_eq!(BOOT_IMAGE_IDENT, *b"XNLX");
        assert_eq!(BOOT_HEADER_SYNC_LE, 0xAA99_5566);
        assert!(BOOT_STRING_7Z007S.contains("7z007"));
        assert_eq!(
            refuse_boot_bitstream_abi(false),
            Err(S9SeBootError::BitstreamAbiNotInImage)
        );
        assert_eq!(
            refuse_boot_bitstream_abi(true),
            Err(S9SeBootError::BitstreamAbiNotInImage)
        );
    }

    #[test]
    fn admit_boot_header_checks_size_ident_and_sync() {
        let mut fake = vec![0u8; BOOT_BIN_SIZE];
        fake[BOOT_HEADER_SYNC_OFF..BOOT_HEADER_SYNC_OFF + 4]
            .copy_from_slice(&BOOT_HEADER_SYNC_LE.to_le_bytes());
        fake[BOOT_IMAGE_IDENT_OFF..BOOT_IMAGE_IDENT_OFF + 4].copy_from_slice(&BOOT_IMAGE_IDENT);
        admit_boot_header(&fake).unwrap();
        assert!(admit_boot_header(&fake[..10]).is_err());
        fake[BOOT_IMAGE_IDENT_OFF] = b'Z';
        assert_eq!(admit_boot_header(&fake), Err(S9SeBootError::IdentMismatch));
    }

    #[test]
    fn admit_boot_header_accepts_held_s9se_image() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../");
        let bytes = std::fs::read(&path).expect("held S9 SE BOOT.bin");
        assert_eq!(bytes.len(), BOOT_BIN_SIZE);
        admit_boot_header(&bytes).unwrap();
        assert!(!bytes.windows(4).any(|w| w == [0xAA, 0x99, 0x55, 0x66]));
        assert!(bytes.windows(BOOT_STRING_7Z007S.len()).any(|w| w == BOOT_STRING_7Z007S.as_bytes()));
    }
}
