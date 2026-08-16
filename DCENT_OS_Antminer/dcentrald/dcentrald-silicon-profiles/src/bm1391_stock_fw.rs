//! Official Bitmain **stock firmware** evidence for the S11 / S15 / T15
//! generation — the BM1391 geometry question, re-adjudicated from vendor bytes.
//!
//! The held signed S15/T15 images settle the ASIC family. They do **not** both
//! settle one universal physical geometry: instruction-level analysis proves
//! that the exact binaries require different per-present-chain BM1391 response
//! counts (S15 72, T15 60), while Bitmain's official S15 maintenance guide
//! states 60 chips twice but also says six chips in each of 12 domains,
//! implying 72. That is a real source-internal and release/board conflict, not
//! merely a filename-label ambiguity.
//!
//! **This module deliberately declares no [`crate::SiliconTable`].** BM1391
//! already has exactly one profile table ([`crate::bm1391::BM1391_TABLE`],
//! `ChipStatus::NamedOnly`, no power/voltage row); a second table for the same
//! silicon would be a rival registry, and none of the evidence below unlocks a
//! voltage or power envelope. This is an evidence record plus the negative
//! pins that keep the refused datums refused.
//!
//! # Held artifacts
//!
//! All three are official Bitmain signed release tarballs
//! (`cert.pem` + `fw.tar.gz` + `runme.sh`, each with a detached `.sig`),
//! operator-held at repo-root `Latest Bitmain FW/` (not committed — 1.3 GB
//! corpus). Read-only inspection; no unit was contacted.
//!
//! | model | tarball | `usr/bin/compile_time` | rootfs |
//! |---|---|---|---|
//! | S11 | `Antminer-S11-all-user-201908011639-sig.tar.gz` | `Antminer S11` / `V2.1.25` | **two** payloads (below) |
//! | S15 | `Antminer-S15-user-OM-201912131535-sig_4864.tar.gz` | `Antminer S15` | ext2 `uramdisk.image.gz` |
//! | T15 | `Antminer-T15-user-OM-201912131546-sig_4867.tar.gz` | `Antminer T15` | ext2 `uramdisk.image.gz` |
//!
//! The `uramdisk.image.gz` payloads are U-Boot-wrapped gzip'd **ext2** images
//! (superblock magic `0xEF53` at byte `0x438`), read with `debugfs -R`. The S11
//! `xilinx/angstrom_rootfs.jffs2` is a **UBI** image (magic `UBI#`), consistent
//! with .
//!
//! # S15 / T15 — chip family settled; stock response counts are profile facts
//!
//! The S15 and T15 `usr/bin/cgminer` binaries share source commit `53156cb` and
//! size `691180`, but they are not byte-identical. Offline Ghidra decompilation
//! of their model predicates and pattern loader establishes the selected paths:
//!
//! ```text
//! S15 cgminer: /dev/91602_patten_72.txt
//! T15 cgminer: /dev/91602_patten_60.txt
//! ```
//!
//! Each image ships the correspondingly named file in `/etc`:
//!
//! | model | shipped file | lines |
//! |---|---|---|
//! | S15 | `/etc/91602_patten_72.txt` | `147456` |
//! | T15 | `/etc/91602_patten_60.txt` | `122880` |
//!
//! Fresh instruction-level Ghidra/objdump analysis closes what the filename
//! sweep alone could not. In the S15 `FUN_00041248`, register-zero replies
//! increment the per-chain count only when `value >> 16 == 0x1391`
//! (`0x417b4..0x417b8`), and the success comparison is exactly 72 at `0x4171c`.
//! T15 `FUN_00041250` is the model-specific counterpart: the same ChipID test
//! is at `0x417c4..0x417c8`, but the success comparison is exactly 60 at
//! `0x4172c`. These are runtime expectations for the exact held binaries, not
//! passive pattern labels.
//!
//! The official S15 maintenance guide (sha256
//! [`S15_MAINTENANCE_GUIDE_SHA256`]) states 12 voltage domains × 5 BM1391 = 60
//! chips twice, 3 chains, and the hashrate equation `frequency × 256 cores ×
//! 60 chips`. Its LDO section separately says six chips per domain, which
//! implies 72. The guide is internally inconsistent and the held S15 binary
//! enforces a 72-response profile. Neither number may be promoted to universal
//! physical geometry without a board/release discriminator. T15's held
//! binary enforces 60 responses per present chain, but no independent held T15
//! topology source establishes its physical chip or chain count.
//!
//! Chip identity is direct: both binaries compile `chip1391.c` and export
//! `open_core_bm1391` / `open_core_BM1391_pre_open`, and log to
//! `/log/minertest64-BM1391/`. `BM1391` occurs exactly once as a standalone
//! token in each (anchored match — the `IBM####` GDB-charset trap from
//!  does not apply here
//! because the hit is inside a path literal and a function symbol, both
//! verified in context). This settles S15/T15 BM1391 identity, but no voltage,
//! carrier, GPIO, FIFO, or safe initialization authority.
//!
//! # S11 — the cited evidence refutes the claim it supports
//!
//! `dcentrald-re-catalog/src/model_catalog.rs:55` declares `s11 → 0x1391`
//! (`EvidenceStrength::Structural`) and cites
//! .
//!
//! That held binary is **byte-identical** (sha256
//! [`S11_BMMINER_SHA256`]) to `usr/bin/bmminer` inside the official
//! `Antminer-S11-all-user` image — so its provenance is now confirmed, and so
//! is the fact that it does not say what the row claims:
//!
//! - it contains **zero** `BM139x` strings ([`S11_BMMINER_BM139X_STRING_COUNT`]);
//! - its translation units are `driver-btm-c5.c` + `dSPIC33EP16GS202.c` — the
//!   S9-family C5 driver, **not** `chip1391.c`;
//! - `is_S11()` and `is_S9_plus()` both compile to `return 1`
//!   (`bmminer.dec/is_S11@37CF0.c`, `bmminer.dec/is_S9_plus@37CD8.c`), while
//!   `is_S9`, `is_S9i`, `is_S9_Hydro` all return `0` — the S11 build *is* the
//!   S9+ build;
//! - it exports `set_Voltage_S9_plus_plus_BM1387_54` and
//!   `write_iic_of_S9_plus_power`;
//! - its `/etc/bmminer.conf.factory` uses the S9-family 4-hex-digit PIC word
//!   [`S11_BMMINER_VOLTAGE_TOKEN`], not the decimal token the BM1391 cgminer
//!   uses ([`S15_CGMINER_VOLTAGE_TOKEN`] / [`T15_CGMINER_VOLTAGE_TOKEN`]);
//! - the image's factory jig config `/etc/config/Config.ini` byte-states
//!   `AsicType=1387`, `AsicNum=63`, `CoreNum=114` — internally cross-checked,
//!   since `ValidNonce1 = 57456 = DataCount(912) × AsicNum(63)`.
//!
//! A BM1391 `cgminer` **is** present in the S11 image's `7007` payload, but
//! `/etc/init.d/cgminer.sh` sets `DAEMON=/usr/bin/bmminer` and its `do_start`
//! actually launches `single-board-test`; and the S11's **other** payload (the
//! `XILINX` carrier's UBI rootfs) ships **no `cgminer` at all** — only
//! `bmminer` + `single-board-test`. Nothing in either payload ever starts the
//! BM1391 binary.
//!
//! **Therefore the S11 chip identity is UNSETTLED and stays refused.** The
//! evidence leans BM1387/S9-family, but the image whose bytes say so is a
//! factory *hashboard-test* firmware whose `Config.ini` is titled
//! `Name=S9 HASH board`, so promoting `s11 → 0x1387` would trade one
//! under-evidenced claim for another. [`S11_CHIPS_PER_CHAIN`] and
//! [`S11_ASIC_IDENTITY_SETTLED`] encode the refusal;
//! `s11_chip_identity_stays_refused` is the negative test that pins it.
//!
//! # Carrier — no new device tree; one product, two known carriers
//!
//! The S11 package ships two `devicetree.dtb` files and **both are byte-copies
//! of device trees already in the census**
//! (
//! which hashes with md5):
//!
//! | payload | md5 | census family |
//! |---|---|---|
//! | `7007/devicetree.dtb` | [`S11_CTRL_7007_DTB_MD5`] | `42edf047` — the S17/S17e/S17Pro/T17/T17e/T17+ 6-partition map |
//! | `xilinx/devicetree.dtb` | [`S11_CTRL_XILINX_DTB_MD5`] | `2a08498e` — the S9/S9i/S9j 3-partition map |
//!
//! This is the census's headline result proved *inside a single vendor
//! package*: one model, two control boards, two different device trees, each
//! already claimed by a different model set. A DTB is a carrier discriminator
//! and never a model discriminator.
//!
//! S15 and T15 ship **no** device tree (their `runme.sh` writes only
//! `BOOT.bin`, `uImage` and `uramdisk.image.gz`), so they add nothing to the
//! census and their carrier stays UNCONFIRMED. Their `BOOT.bin` and `uImage`
//! are byte-identical to each other (md5 `fcf3a226…` / `2b47ce67…`), so S15 and
//! T15 do share one carrier as each other — which is all that can be said.

/// `usr/bin/compile_time` model line, S11 image.
pub const S11_COMPILE_TIME_MODEL: &str = "Antminer S11";
/// `usr/bin/compile_time` model line, S15 image.
pub const S15_COMPILE_TIME_MODEL: &str = "Antminer S15";
/// `usr/bin/compile_time` model line, T15 image.
pub const T15_COMPILE_TIME_MODEL: &str = "Antminer T15";

/// `version_number` from the signed S11 tarball.
pub const S11_STOCK_FW_VERSION: &str = "V2.1.25";
/// `version_number` from the signed S15 tarball.
pub const S15_STOCK_FW_VERSION: &str = "1.92992.0.14";
/// `version_number` from the signed T15 tarball.
pub const T15_STOCK_FW_VERSION: &str = "1.92992.0.13";

/// sha256 of the held signed S15 release tarball.
pub const S15_STOCK_FW_SHA256: &str =
    "68a1ba8f3597b6775c2d226482e72bcc8095358020cd3bb2c07a8eec886f5e71";
/// sha256 of the held signed T15 release tarball.
pub const T15_STOCK_FW_SHA256: &str =
    "7bd2c1105267be53545ffe5a87e75a6049524caab34cb4af8f14700e79eff7b4";
/// sha256 of `usr/bin/cgminer` from the S15 rootfs.
pub const S15_CGMINER_SHA256: &str =
    "3cf4302b87d5c5588f3c6cbfb2eb3e46dc7545da4d62f715651e84e0dde119c8";
/// sha256 of `usr/bin/cgminer` from the T15 rootfs.
pub const T15_CGMINER_SHA256: &str =
    "fdeaf71ab1d8e1613e9dd0353621cd07c349179d450999d51e31e0df308cdf01";

/// sha256 of Bitmain's held `S15 Maintenance Guide.pdf` (2019-07-02).
pub const S15_MAINTENANCE_GUIDE_SHA256: &str =
    "4496807c14291da95bdc4ba399097f8a3d5f1c15d0cab882dcd57c10e5e2ab27";

/// Numeric family label embedded in the S15/T15 pattern-file names.
///
/// It is retained as a filename fact, not promoted to an observed physical PCB
/// marking; the S17 factory jig independently uses BHB916xx BM1391 names.
pub const BHB91602_BOARD_ID: u32 = 91_602;

/// Line count of the S15 image's `/etc/91602_patten_72.txt`.
pub const S15_PATTERN_FILE_LINES: u32 = 147_456;
/// Line count of the T15 image's `/etc/91602_patten_60.txt`.
pub const T15_PATTERN_FILE_LINES: u32 = 122_880;

/// Numeric selector label chosen by the held S15 cgminer's model predicate.
/// It is **not** physical geometry authority; the guide itself contains both
/// 60-chip statements and a six-per-domain line implying 72.
pub const S15_SELECTED_PATTERN_LABEL: u32 = 72;
/// Numeric selector label chosen by the held T15 cgminer's model predicate.
/// It is not promoted into physical topology without an independent T15 source.
pub const T15_SELECTED_PATTERN_LABEL: u32 = 60;

/// Exact BM1391 register-zero response count required by the held S15 cgminer
/// for one present chain (`FUN_00041248`, compare at `0x4171c`).
///
/// This is a stock software-profile fact. It conflicts with the guide's
/// repeated 60-chip statements while agreeing with its separate six-per-domain
/// implication; it cannot be promoted to physical or model-wide geometry.
pub const S15_STOCK_CGMINER_EXPECTED_RESPONSES_PER_PRESENT_CHAIN: u32 = 72;

/// Exact BM1391 register-zero response count required by the held T15 cgminer
/// for one present chain (`FUN_00041250`, compare at `0x4172c`).
///
/// This is direct runtime enforcement, stronger than the `60` pattern filename,
/// but remains one-source software-profile evidence rather than an independent
/// statement of physical T15 topology or chain-slot population.
pub const T15_STOCK_CGMINER_EXPECTED_RESPONSES_PER_PRESENT_CHAIN: u32 = 60;

/// Official-guide S15 chain count (pages 1 and 3).
pub const S15_CHAIN_COUNT: u32 = 3;
/// Physical chips per S15 chain remain unresolved across the internally
/// inconsistent guide and exact stock response profile.
pub const S15_CHIPS_PER_CHAIN: Option<u32> = None;
/// S15 guide pages 1 and 3 explicitly state this physical count.
pub const S15_GUIDE_REPEATED_CHIPS_PER_CHAIN: u32 = 60;
/// The same guide's LDO paragraph says six chips in each of twelve domains.
pub const S15_GUIDE_CONFLICTING_IMPLIED_CHIPS_PER_CHAIN: u32 = 72;
pub const S15_CORES_PER_CHIP: u32 = 256;
pub const S15_VOLTAGE_DOMAIN_COUNT: u32 = 12;
pub const S15_GUIDE_REPEATED_CHIPS_PER_VOLTAGE_DOMAIN: u32 = 5;
pub const S15_GUIDE_CONFLICTING_CHIPS_PER_VOLTAGE_DOMAIN: u32 = 6;
pub const BM1391_INTERNAL_VOLTAGE_DOMAIN_COUNT: u32 = 3;
pub const S15_OSCILLATOR_HZ: u32 = 25_000_000;
pub const S15_TEMPERATURE_SENSE_COUNT: u32 = 4;
pub const S15_PSU_MODEL: &str = "APW8";
pub const S15_PIC_MODEL: &str = "PIC16(L)F1704";

/// No held T15 maintenance/manual/capture source independently states physical
/// chips per chain or chain count. Its pattern selector is not such a source.
pub const T15_CHIPS_PER_CHAIN: Option<u32> = None;
pub const T15_CHAIN_COUNT: Option<u32> = None;

/// The S15 chips-per-chain value carried before this evidence landed
/// (`bm1391::BM1391_CHIPS_PER_CHAIN_S15_SCAFFOLD`). It was copied from the
/// mislabelled `S11/` jig, whose `84` is S9+'s `AsicNum` — the copy-across the
/// [`crate::bm1391`] module doc already flagged as *suspect*. Retained as a
/// named refuted value so it cannot quietly return.
pub const REFUTED_S15_SCAFFOLD_CHIPS: u32 = 84;

/// A 72-chip physical interpretation remains possible but unproved: the exact
/// binary enforces 72 replies and one guide paragraph implies 72.
pub const UNRESOLVED_S15_72_CHIP_INTERPRETATION: u32 = 72;

/// Unsupported T15 value from an RE-Dev-Kit transcription. It is not called
/// refuted because the held sources do not establish a replacement count.
pub const UNPROVEN_T15_DEVKIT_CHIPS: u32 = 63;

/// `"bitmain-voltage"` token in the S15 image's `/etc/cgminer.conf.factory`.
///
/// **Kept as an opaque string on purpose.** The BM1391 cgminer's unit for this
/// field is not established by any held byte, so it must not be parsed into
/// millivolts and must never seed a rail. `voltage_unit_is_not_inferred` pins
/// that.
pub const S15_CGMINER_VOLTAGE_TOKEN: &str = "1650";
/// `"bitmain-voltage"` token in the T15 image's `/etc/cgminer.conf.factory`.
/// Same refusal as [`S15_CGMINER_VOLTAGE_TOKEN`].
pub const T15_CGMINER_VOLTAGE_TOKEN: &str = "1850";

/// `"bitmain-freq"` token shipped by both S15 and T15
/// (`/etc/cgminer.conf.factory`). It is the **letter `O`**, not a number — the
/// factory default defers frequency to the hashboard PIC/EEPROM
/// (`cgminer` logs `Chain[J%d] has no freq in PIC, set default freq=%dM`).
/// No default frequency is therefore settled for S15 or T15.
pub const S15_T15_CGMINER_FREQ_TOKEN: &str = "O";

/// `"bitmain-voltage"` token in the S11 image's `/etc/bmminer.conf.factory`.
/// Four hex digits — the S9-family PIC DAC word format, structurally unlike
/// the decimal token the BM1391 cgminer uses.
pub const S11_BMMINER_VOLTAGE_TOKEN: &str = "0706";

/// The `cgminer` translation unit that proves BM1391 silicon in the S15/T15
/// (and the unused S11) binaries.
pub const BM1391_CGMINER_TRANSLATION_UNIT: &str = "chip1391.c";

/// The PIC translation unit compiled into the S15/T15 `cgminer` **and** the
/// S11 `bmminer`; the S11 image additionally ships
/// `/etc/config/dsPIC33EP16GS202_app.txt`.
///
/// Recorded as a **string fact only**. It does not promote any board's
/// `voltage_controller` off `RuntimeDiscovered` — same discipline Round 14
/// applied to S9i/S9j, whose jig names this part 17 times.
pub const S11_S15_T15_PIC_TRANSLATION_UNIT: &str = "dspic33ep16gs202.c";

// ---------------------------------------------------------------------------
// S11: the refuted citation, pinned.
// ---------------------------------------------------------------------------

/// sha256 of `usr/bin/bmminer` in the official `Antminer-S11-all-user` image.
/// Byte-identical to the held
/// , which is what
/// `model_catalog.rs:55` cites as evidence for `s11 → 0x1391`.
pub const S11_BMMINER_SHA256: &str =
    "a9417924750b7f9f2cd998f20d2cd402d542595f547635bcd54155f5aa24b8a2";

/// sha256 of `usr/bin/single-board-test` in the same image; likewise
/// byte-identical to the held `…/S11/single-board-test`.
pub const S11_SINGLE_BOARD_TEST_SHA256: &str =
    "b0ce1c078c99b911c3d030cdb04db705ea8333937e016a553d4bed0bd961da00";

/// Count of anchored `BM139x` tokens in the S11 `bmminer` — **zero**.
/// The binary cited as BM1391 evidence never names BM1391.
pub const S11_BMMINER_BM139X_STRING_COUNT: u32 = 0;

/// `bmminer.dec/is_S11@37CF0.c` → `return 1`.
pub const S11_BMMINER_IS_S11_RETURNS: u32 = 1;
/// `bmminer.dec/is_S9_plus@37CD8.c` → `return 1`. The S11 build is the S9+
/// build; the two predicates are simultaneously true.
pub const S11_BMMINER_IS_S9_PLUS_RETURNS: u32 = 1;

/// `AsicType` in the S11 image's factory jig config `/etc/config/Config.ini`.
pub const S11_JIG_CONFIG_ASIC_TYPE: u32 = 1387;
/// `AsicNum` from the same file.
pub const S11_JIG_CONFIG_ASIC_NUM: u32 = 63;
/// `CoreNum` from the same file.
pub const S11_JIG_CONFIG_CORE_NUM: u32 = 114;
/// `DataCount` from the same file.
pub const S11_JIG_CONFIG_DATA_COUNT: u32 = 912;
/// `ValidNonce1` from the same file. Equals `DataCount × AsicNum`, which is the
/// internal cross-check that makes the `AsicNum=63` reading trustworthy.
pub const S11_JIG_CONFIG_VALID_NONCE1: u32 = 57_456;
/// `Name` from the same file — the reason `AsicType=1387` cannot be promoted to
/// "the S11 product's hashboard chip" without a second source.
pub const S11_JIG_CONFIG_BOARD_NAME: &str = "S9 HASH board";

/// **S11 chips per hashboard: REFUSED.** No held byte states it for the S11
/// *product*; the only count in the image ([`S11_JIG_CONFIG_ASIC_NUM`]) belongs
/// to a config the vendor titled [`S11_JIG_CONFIG_BOARD_NAME`].
pub const S11_CHIPS_PER_CHAIN: Option<u32> = None;

/// **S11 ASIC identity: NOT settled.** See the module doc. The only cited
/// evidence for `0x1391` refutes itself; the counter-evidence points at the
/// S9/BM1387 family but arrives via a factory hashboard-test image.
pub const S11_ASIC_IDENTITY_SETTLED: bool = false;

/// S11 chain count remains refused by the exact product evidence reviewed here.
pub const S11_CHAIN_COUNT: Option<u32> = None;

// ---------------------------------------------------------------------------
// Carrier / device tree.
// ---------------------------------------------------------------------------

/// md5 of `7007/devicetree.dtb` in the S11 package — census family `42edf047`
/// (S17 / S17e / S17Pro / T17 / T17e / T17+).
pub const S11_CTRL_7007_DTB_MD5: &str = "42edf047f3c2715f5a4c70c523b670e0";

/// md5 of `xilinx/devicetree.dtb` in the same package — census family
/// `2a08498e` (S9 / S9i / S9j).
pub const S11_CTRL_XILINX_DTB_MD5: &str = "2a08498e8fb631b5f039aa344d119281";

/// `usr/bin/ctrl_bd` in the S11 `7007` payload.
pub const S11_CTRL_BD_7007: &str = "7007";
/// `usr/bin/ctrl_bd` in the S11 `xilinx` payload; `runme.sh` branches on
/// `grep "XILINX" /usr/bin/ctrl_bd`.
pub const S11_CTRL_BD_XILINX: &str = "XILINX";

/// Number of distinct device trees the single S11 package carries.
pub const S11_DISTINCT_DTB_COUNT: u32 = 2;

/// Number of *new* device trees this drop adds to the 7-DTB census: **zero**.
pub const NEW_DTBS_ADDED_TO_CENSUS: u32 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    /// Exact stock response counts are retained separately from physical
    /// topology so the S15 72-vs-60 conflict cannot be silently collapsed.
    #[test]
    fn stock_response_profiles_do_not_authorize_physical_geometry() {
        assert_eq!(S15_SELECTED_PATTERN_LABEL, 72);
        assert_eq!(T15_SELECTED_PATTERN_LABEL, 60);
        assert_eq!(S15_PATTERN_FILE_LINES, 147_456);
        assert_eq!(T15_PATTERN_FILE_LINES, 122_880);
        assert_eq!(S15_STOCK_CGMINER_EXPECTED_RESPONSES_PER_PRESENT_CHAIN, 72);
        assert_eq!(T15_STOCK_CGMINER_EXPECTED_RESPONSES_PER_PRESENT_CHAIN, 60);
        assert_eq!(S15_CHIPS_PER_CHAIN, None);
        assert_ne!(
            S15_STOCK_CGMINER_EXPECTED_RESPONSES_PER_PRESENT_CHAIN,
            S15_GUIDE_REPEATED_CHIPS_PER_CHAIN,
            "the exact S15 stock binary and repeated guide statement conflict; require a board/release discriminator"
        );
        assert_eq!(
            S15_STOCK_CGMINER_EXPECTED_RESPONSES_PER_PRESENT_CHAIN,
            S15_GUIDE_CONFLICTING_IMPLIED_CHIPS_PER_CHAIN
        );
        assert_eq!(T15_CHIPS_PER_CHAIN, None);
        assert_eq!(T15_CHAIN_COUNT, None);
    }

    /// The official S15 guide's internally conflicting readings remain
    /// machine-visible without creating physical geometry authority.
    #[test]
    fn s15_maintenance_guide_conflict_is_exact_and_cross_registry_bound() {
        assert_eq!(S15_CHAIN_COUNT, 3);
        assert_eq!(S15_CHIPS_PER_CHAIN, None);
        assert_eq!(S15_CORES_PER_CHIP, 256);
        assert_eq!(S15_VOLTAGE_DOMAIN_COUNT, 12);
        assert_eq!(
            S15_VOLTAGE_DOMAIN_COUNT * S15_GUIDE_REPEATED_CHIPS_PER_VOLTAGE_DOMAIN,
            S15_GUIDE_REPEATED_CHIPS_PER_CHAIN
        );
        assert_eq!(
            S15_VOLTAGE_DOMAIN_COUNT * S15_GUIDE_CONFLICTING_CHIPS_PER_VOLTAGE_DOMAIN,
            S15_GUIDE_CONFLICTING_IMPLIED_CHIPS_PER_CHAIN
        );
        assert_eq!(BM1391_INTERNAL_VOLTAGE_DOMAIN_COUNT, 3);
        assert_eq!(S15_OSCILLATOR_HZ, 25_000_000);
        assert_eq!(S15_TEMPERATURE_SENSE_COUNT, 4);
        assert_eq!(S15_PSU_MODEL, "APW8");
        assert_eq!(S15_PIC_MODEL, "PIC16(L)F1704");
        assert_eq!(
            crate::bm1391::BM1391_CHIPS_PER_CHAIN_S15_SCAFFOLD,
            S15_CHIPS_PER_CHAIN
        );
        assert_eq!(
            crate::bm1391::BM1391_CHIPS_PER_CHAIN_T15_SCAFFOLD,
            T15_CHIPS_PER_CHAIN
        );
    }

    /// Negative pins for unresolved S15/T15 physical geometry.
    #[test]
    fn unresolved_s15_and_t15_geometry_never_return() {
        assert_eq!(S15_CHIPS_PER_CHAIN, None);
        assert_eq!(crate::bm1391::BM1391_CHIPS_PER_CHAIN_S15_SCAFFOLD, None);
        assert_eq!(REFUTED_S15_SCAFFOLD_CHIPS, 84);
        assert_eq!(UNRESOLVED_S15_72_CHIP_INTERPRETATION, 72);
        assert_eq!(crate::bm1391::BM1391_CHIPS_PER_CHAIN_T15_SCAFFOLD, None);
        assert_eq!(T15_CHIPS_PER_CHAIN, None);
        assert_eq!(UNPROVEN_T15_DEVKIT_CHIPS, 63);
    }

    /// NEGATIVE PIN — S11 chip identity and chip count stay refused.
    ///
    /// This is the guard the mission's fail-closed rule requires: the S11 is the
    /// one model of the three whose silicon the bytes do NOT settle, and the
    /// temptation in both directions is real (a `0x1391` row already exists, and
    /// the counter-evidence reads like a clean `0x1387`). Refuse both.
    #[test]
    fn s11_chip_identity_stays_refused() {
        assert!(
            !S11_ASIC_IDENTITY_SETTLED,
            "no held byte settles the S11 product's ASIC; do not promote either candidate"
        );
        assert_eq!(
            S11_CHIPS_PER_CHAIN, None,
            "the only chip count in the S11 image belongs to a config titled \
             'S9 HASH board' and must not be adopted as the S11 product geometry"
        );
        assert_eq!(S11_CHAIN_COUNT, None);
        // The jig config's own numbers are internally consistent — that is why
        // they are trustworthy *about the config*, and only about the config.
        assert_eq!(
            S11_JIG_CONFIG_DATA_COUNT * S11_JIG_CONFIG_ASIC_NUM,
            S11_JIG_CONFIG_VALID_NONCE1
        );
        assert_eq!(S11_JIG_CONFIG_BOARD_NAME, "S9 HASH board");
    }

    /// The `model_catalog.rs:55` citation is self-refuting: the binary it names
    /// contains no BM139x token at all, and compiles both `is_S11` and
    /// `is_S9_plus` to `1`.
    #[test]
    fn s11_cited_bm1391_evidence_contains_no_bm139x_token() {
        assert_eq!(
            S11_BMMINER_BM139X_STRING_COUNT, 0,
            "if this ever becomes non-zero the citation was re-read; re-adjudicate"
        );
        assert_eq!(S11_BMMINER_IS_S11_RETURNS, 1);
        assert_eq!(S11_BMMINER_IS_S9_PLUS_RETURNS, 1);
        assert_eq!(S11_BMMINER_IS_S11_RETURNS, S11_BMMINER_IS_S9_PLUS_RETURNS);
        // Distinct binaries, both byte-bound to the held corpus copies.
        assert_ne!(S11_BMMINER_SHA256, S11_SINGLE_BOARD_TEST_SHA256);
        assert_eq!(S11_BMMINER_SHA256.len(), 64);
        assert_eq!(S11_SINGLE_BOARD_TEST_SHA256.len(), 64);
    }

    /// The S11 and the BM1391 models encode voltage in structurally different
    /// config formats — four hex digits vs a decimal token. Neither is parsed
    /// into a rail unit here, and this test exists to keep it that way.
    #[test]
    fn voltage_unit_is_not_inferred() {
        assert_eq!(S11_BMMINER_VOLTAGE_TOKEN.len(), 4);
        assert!(S11_BMMINER_VOLTAGE_TOKEN.starts_with('0'));
        assert_ne!(S15_CGMINER_VOLTAGE_TOKEN, T15_CGMINER_VOLTAGE_TOKEN);
        // The BM1391 tokens are digits but their UNIT is unheld. If someone
        // later adds a millivolt constant, they must delete this assertion
        // deliberately rather than reinterpret a string in place.
        assert!(S15_CGMINER_VOLTAGE_TOKEN.parse::<u32>().is_ok());
        assert!(T15_CGMINER_VOLTAGE_TOKEN.parse::<u32>().is_ok());
        // Frequency default is a letter, not a number: nothing to seed.
        assert!(S15_T15_CGMINER_FREQ_TOKEN.parse::<u32>().is_err());
        assert_eq!(S15_T15_CGMINER_FREQ_TOKEN, "O");
    }

    /// One vendor package, one model, two device trees — each byte-identical to
    /// a *different* existing census family. This is the DTB census's
    /// "carrier, not model" result proved from inside a single release.
    #[test]
    fn s11_package_adds_no_new_device_tree_and_spans_two_carriers() {
        assert_eq!(S11_DISTINCT_DTB_COUNT, 2);
        assert_eq!(NEW_DTBS_ADDED_TO_CENSUS, 0);
        assert_ne!(S11_CTRL_7007_DTB_MD5, S11_CTRL_XILINX_DTB_MD5);
        // Census key prefixes, as published in DTB_EQUIVALENCE_CENSUS_20260807.md.
        assert!(
            S11_CTRL_7007_DTB_MD5.starts_with("42edf047"),
            "7007 carrier must remain the S17-class DTB family"
        );
        assert!(
            S11_CTRL_XILINX_DTB_MD5.starts_with("2a08498e"),
            "XILINX carrier must remain the S9/S9i/S9j DTB family"
        );
        assert_eq!(S11_CTRL_7007_DTB_MD5.len(), 32);
        assert_eq!(S11_CTRL_XILINX_DTB_MD5.len(), 32);
        assert_ne!(S11_CTRL_BD_7007, S11_CTRL_BD_XILINX);
    }

    /// Provenance strings must stay attached to the models they came from.
    #[test]
    fn model_identity_strings_are_distinct_and_named() {
        assert_eq!(S11_COMPILE_TIME_MODEL, "Antminer S11");
        assert_eq!(S15_COMPILE_TIME_MODEL, "Antminer S15");
        assert_eq!(T15_COMPILE_TIME_MODEL, "Antminer T15");
        assert_ne!(S15_STOCK_FW_VERSION, T15_STOCK_FW_VERSION);
        assert_eq!(BHB91602_BOARD_ID, 91_602);
        assert_eq!(BM1391_CGMINER_TRANSLATION_UNIT, "chip1391.c");
        assert_eq!(S11_S15_T15_PIC_TRANSLATION_UNIT, "dspic33ep16gs202.c");
        for digest in [
            S15_STOCK_FW_SHA256,
            T15_STOCK_FW_SHA256,
            S15_CGMINER_SHA256,
            T15_CGMINER_SHA256,
            S15_MAINTENANCE_GUIDE_SHA256,
        ] {
            assert_eq!(digest.len(), 64);
        }
        assert_ne!(S15_CGMINER_SHA256, T15_CGMINER_SHA256);
    }

    /// BM1391 power/voltage remains unknown. Settling *geometry* must not leak
    /// into an energization envelope: the one BM1391 table stays `NamedOnly`
    /// with no watts and no hashrate.
    #[test]
    fn geometry_evidence_does_not_unlock_energization() {
        let row = crate::bm1391::BM1391_TABLE
            .default_profile()
            .expect("BM1391 planning row");
        assert_eq!(row.wall_watts, None);
        assert_eq!(row.hashrate_ths, None);
        assert_eq!(
            crate::bm1391::BM1391_TABLE.live_status,
            crate::ChipStatus::NamedOnly
        );
    }
}
