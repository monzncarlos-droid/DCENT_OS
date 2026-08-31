//! Loaded-fabric identity and UIO-discovered PL surface reports.
//!
//! S9 `VERSION` at common+0x00 is `0x00901002`, which is also live AM2 `CTRL`
//! at the same offset. BUILD_ID at +0x04 is the discriminator:
//! s9io `0x5FCA47E9` vs AM2 `0x63848B7B`. A mismatch must refuse CTRL/BAUD/FIFO
//! writes, not warn-and-continue.
//!
//! [`PlSurfaceReport`] is filled from kernel UIO sysfs (name + map0 addr/size).
//! Addresses are never invented and never copied from ePIC device trees.

use crate::HalError;

/// Braiins s9io v1.0.2 BUILD_ID (unix timestamp 2020-12-04), live-read on S9
/// chain-common +0x04.
pub const BRAIINS_S9IO_BITSTREAM_BUILD_ID: u32 = 0x5FCA_47E9;

/// BraiinsOS am2 BUILD_ID, live-captured 2026-05-22 on `a lab unit` chain-common +0x04.
pub const BRAIINS_AM2_BITSTREAM_BUILD_ID: u32 = 0x6384_8B7B;

/// S9 VERSION at +0x00 **and** AM2 CTRL at +0x00. Not a BUILD_ID.
pub const S9_VERSION_AM2_CTRL_COLLISION: u32 = 0x0090_1002;

/// Loaded FPGA fabric class keyed by BUILD_ID, not by the colliding +0x00 word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FabricClass {
    /// Braiins s9io (S9 / am1) bitstream.
    S9io,
    /// BraiinsOS am2 bitstream (S17/S19-family Zynq).
    Am2,
}

impl FabricClass {
    /// BUILD_ID that admits this class.
    pub const fn expected_build_id(self) -> u32 {
        match self {
            Self::S9io => BRAIINS_S9IO_BITSTREAM_BUILD_ID,
            Self::Am2 => BRAIINS_AM2_BITSTREAM_BUILD_ID,
        }
    }
}

impl std::fmt::Display for FabricClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::S9io => f.write_str("s9io"),
            Self::Am2 => f.write_str("am2"),
        }
    }
}

/// Fail-closed BUILD_ID class mismatch. Callers must not continue with
/// CTRL/BAUD/FIFO writes after this error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricIdentityError {
    /// BUILD_ID actually read from common+0x04.
    pub observed_build_id: u32,
    /// Class the caller required (AM2 for BM1362 FPGA-FIFO init).
    pub expected_class: FabricClass,
    /// BUILD_ID that would have admitted `expected_class`.
    pub expected_build_id: u32,
    /// Classification of `observed_build_id`, if any.
    pub classified_as: Option<FabricClass>,
}

impl std::fmt::Display for FabricIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FPGA fabric BUILD_ID 0x{:08X} (classified {:?}) is not {} \
             (expected 0x{:08X}); S9 VERSION 0x{:08X} collides with AM2 CTRL \
             at +0x00 — BUILD_ID is the discriminator (s9io 0x{:08X} vs AM2 0x{:08X})",
            self.observed_build_id,
            self.classified_as,
            self.expected_class,
            self.expected_build_id,
            S9_VERSION_AM2_CTRL_COLLISION,
            BRAIINS_S9IO_BITSTREAM_BUILD_ID,
            BRAIINS_AM2_BITSTREAM_BUILD_ID,
        )
    }
}

impl std::error::Error for FabricIdentityError {}

impl From<FabricIdentityError> for HalError {
    fn from(err: FabricIdentityError) -> Self {
        HalError::Platform(err.to_string())
    }
}

/// One kernel-published UIO mapping of a PL IP block.
///
/// `physaddr`/`size` come from `/sys/class/uio/uioN/maps/map0/{addr,size}`
/// when those files exist. `build_id` is MMIO-only and stays `None` for a
/// sysfs census.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlSurfaceReport {
    /// Kernel UIO `name` attribute (e.g. `chain6-common`, `fan-control`).
    pub name: String,
    /// map0 physical address, if sysfs published one.
    pub physaddr: Option<u64>,
    /// map0 size in bytes, if sysfs published one.
    pub size: Option<u64>,
    /// BUILD_ID from common+0x04 after an explicit MMIO read. Census-only
    /// reports leave this `None`.
    pub build_id: Option<u32>,
}

impl PlSurfaceReport {
    /// Census constructor: name + optional sysfs map0 fields, no BUILD_ID.
    pub fn from_sysfs(name: impl Into<String>, physaddr: Option<u64>, size: Option<u64>) -> Self {
        Self {
            name: name.into(),
            physaddr,
            size,
            build_id: None,
        }
    }

    /// Attach a BUILD_ID read from MMIO. Does not invent an address.
    pub fn with_build_id(mut self, build_id: u32) -> Self {
        self.build_id = Some(build_id);
        self
    }
}

/// Classify a common+0x04 BUILD_ID word. The colliding VERSION/CTRL value
/// `0x00901002` is **not** a class.
pub fn classify_fabric_build_id(build_id: u32) -> Option<FabricClass> {
    match build_id {
        BRAIINS_S9IO_BITSTREAM_BUILD_ID => Some(FabricClass::S9io),
        BRAIINS_AM2_BITSTREAM_BUILD_ID => Some(FabricClass::Am2),
        _ => None,
    }
}

/// Admit `observed_build_id` as exactly `expected`. Fail closed on mismatch,
/// unknown, or the VERSION/CTRL collision word.
pub fn admit_fabric_class(
    observed_build_id: u32,
    expected: FabricClass,
) -> Result<FabricClass, FabricIdentityError> {
    let classified_as = classify_fabric_build_id(observed_build_id);
    if classified_as == Some(expected) {
        Ok(expected)
    } else {
        Err(FabricIdentityError {
            observed_build_id,
            expected_class: expected,
            expected_build_id: expected.expected_build_id(),
            classified_as,
        })
    }
}

/// Parse a UIO sysfs hex word (`0x43c00000`, `0X00001000`, or bare hex).
/// Returns `None` rather than substituting a known AXI address.
pub fn parse_uio_sysfs_hex(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_id_constants_are_the_live_discriminators() {
        assert_eq!(BRAIINS_S9IO_BITSTREAM_BUILD_ID, 0x5FCA_47E9);
        assert_eq!(BRAIINS_AM2_BITSTREAM_BUILD_ID, 0x6384_8B7B);
        assert_eq!(S9_VERSION_AM2_CTRL_COLLISION, 0x0090_1002);
        assert_ne!(
            BRAIINS_S9IO_BITSTREAM_BUILD_ID,
            BRAIINS_AM2_BITSTREAM_BUILD_ID
        );
        assert_ne!(
            S9_VERSION_AM2_CTRL_COLLISION,
            BRAIINS_S9IO_BITSTREAM_BUILD_ID
        );
        assert_ne!(
            S9_VERSION_AM2_CTRL_COLLISION,
            BRAIINS_AM2_BITSTREAM_BUILD_ID
        );
    }

    #[test]
    fn collision_word_is_not_a_fabric_class() {
        assert_eq!(
            classify_fabric_build_id(S9_VERSION_AM2_CTRL_COLLISION),
            None
        );
        assert_eq!(classify_fabric_build_id(0), None);
        assert_eq!(classify_fabric_build_id(0xFFFF_FFFF), None);
    }

    #[test]
    fn admit_am2_accepts_only_am2_build_id() {
        assert_eq!(
            admit_fabric_class(BRAIINS_AM2_BITSTREAM_BUILD_ID, FabricClass::Am2).unwrap(),
            FabricClass::Am2
        );

        let s9 = admit_fabric_class(BRAIINS_S9IO_BITSTREAM_BUILD_ID, FabricClass::Am2).unwrap_err();
        assert_eq!(s9.classified_as, Some(FabricClass::S9io));
        assert_eq!(s9.expected_class, FabricClass::Am2);
        assert_eq!(s9.expected_build_id, BRAIINS_AM2_BITSTREAM_BUILD_ID);

        let collision =
            admit_fabric_class(S9_VERSION_AM2_CTRL_COLLISION, FabricClass::Am2).unwrap_err();
        assert_eq!(collision.classified_as, None);
        assert_eq!(collision.observed_build_id, S9_VERSION_AM2_CTRL_COLLISION);
    }

    #[test]
    fn admit_s9io_accepts_only_s9_build_id() {
        assert_eq!(
            admit_fabric_class(BRAIINS_S9IO_BITSTREAM_BUILD_ID, FabricClass::S9io).unwrap(),
            FabricClass::S9io
        );
        assert!(admit_fabric_class(BRAIINS_AM2_BITSTREAM_BUILD_ID, FabricClass::S9io).is_err());
    }

    #[test]
    fn identity_error_converts_to_hal_platform_without_continuing() {
        let err =
            admit_fabric_class(BRAIINS_S9IO_BITSTREAM_BUILD_ID, FabricClass::Am2).unwrap_err();
        match HalError::from(err) {
            HalError::Platform(msg) => {
                assert!(msg.contains("0x5FCA47E9"), "{msg}");
                assert!(msg.contains("am2"), "{msg}");
                assert!(msg.contains("discriminator"), "{msg}");
            }
            other => panic!("expected Platform, got {other:?}"),
        }
    }

    #[test]
    fn pl_surface_report_does_not_invent_axi_addresses() {
        let missing = PlSurfaceReport::from_sysfs("chain6-common", None, None);
        assert_eq!(missing.physaddr, None);
        assert_eq!(missing.size, None);
        assert_eq!(missing.build_id, None);
        // ePIC / S9 live bases must not appear as defaults.
        assert_ne!(missing.physaddr, Some(0x43C0_0000));
        assert_ne!(missing.physaddr, Some(0x4127_0000));

        let from_sysfs = PlSurfaceReport::from_sysfs(
            "chain1-common",
            parse_uio_sysfs_hex("0x43c00000"),
            parse_uio_sysfs_hex("0x00001000"),
        )
        .with_build_id(BRAIINS_AM2_BITSTREAM_BUILD_ID);
        assert_eq!(from_sysfs.physaddr, Some(0x43C0_0000));
        assert_eq!(from_sysfs.size, Some(0x1000));
        assert_eq!(from_sysfs.build_id, Some(BRAIINS_AM2_BITSTREAM_BUILD_ID));
    }

    #[test]
    fn parse_uio_sysfs_hex_accepts_kernel_forms_and_rejects_garbage() {
        assert_eq!(parse_uio_sysfs_hex("0x43c00000\n"), Some(0x43C0_0000));
        assert_eq!(parse_uio_sysfs_hex("0X00001000"), Some(0x1000));
        assert_eq!(parse_uio_sysfs_hex("43C00000"), Some(0x43C0_0000));
        assert_eq!(parse_uio_sysfs_hex(""), None);
        assert_eq!(parse_uio_sysfs_hex("0x"), None);
        assert_eq!(parse_uio_sysfs_hex("not-hex"), None);
        assert_eq!(parse_uio_sysfs_hex("0x41270000zz"), None);
    }
}
