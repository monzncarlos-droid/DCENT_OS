//! BM1390 / BM1390P / BM1390S — held-evidence record and refusal pins
//! (Round 16, team B7, 2026-08-07).
//!
//! Round 15 recorded BM1390 geometry as *"genuinely unmoved; nothing in the
//! drop mentions it"* and carried it forward as an **acquisition ask**. An
//! exhaustive, ignore-blind, gzip-aware sweep of every held corpus
//! (`knowledge-base/{extractions,repos,firmware-archive,…}`, the
//! `DCENT_OS_DEVELOPMENT_KITRE2` tree, `Latest Bitmain FW`,
//! `HammerFirmwares`, `NEW WAVE VNISH SD CARDS`) found that the negative is
//! **wrong**: we hold three independent BM1390 sources, and one of them
//! settles the core count the same way the accepted BM1387P = 128 proof was
//! settled — by counting Bitmain's own per-core pattern files.
//!
//! This module declares **no `SiliconTable`**. BM1390 has no `AsicChip`
//! variant, no driver, and no energization envelope; a table here would be a
//! rival registry with nothing to route to. Everything below is evidence,
//! arithmetic, and refusals.
//!
//! # 1. What is held (exhaustive; see §5 for the search method)
//!
//! | # | artifact | what it states |
//! |---|---|---|
//! | S1 |  | `Name=S11 HASH board`, `AsicType=1390`, `AsicNum=60`, `CoreNum=128`, `Voltage1=1060`, `DataCount=1024`, `ValidNonce1=22528` |
//! | S2 |  | `Name=Single BM1390P`, `AsicType=1390`, `AsicNum=1`, `CoreNum=128`, `Voltage1=890`, `DataCount=1`, `ValidNonce1=128` |
//! | S3 | ++-SD-recover-NAND.img` | a complete **AMTC single-board-test jig SD filesystem** carrying `minertest64-BM1390/`, `single-BM1390-ASIC-test/`, the symbols `set_core_number_BM1390` / `set_core_pm_BM1390` / `enable_core_clock_BM1390`, and a captured engineer shell transcript containing `singleBoardTest_V11_BM1390S_32: AsicType = 1390 / asicNum = 32 / real AsicNum = 32` |
//! | S4 |  and `.../S9k/cgminer{,.dec}` (plus their HashSource duplicates) | functions **named** `set_core_number_BM1390` / `enable_core_clock_BM1390` whose payload is BM1393 — see §4 |
//! | **S5** |  Guide.pdf` (Bitmain first-party, 16 pp.) | *"S11 is composed of **28 voltage domains** connected in series. There are **3 BM1387 chips in each voltage domain**, and there are **84 BM1387 chips** on the [board]"*; *"The **BM1387BF** chip used by S11 is a low-voltage chip"*; CLK/TX/RX described as flowing *"from chip 01 to chip 84"* |
//! | **S6** |  S9SE Maintenance Guide.pdf` (Bitmain first-party, 13 pp.) | *"There are **208 cores on a single BM1393 chip**, the domain voltage is 1.6V"* — first-party confirmation of the §4 wire decode |
//!
//! S3 is the material Round 15 missed. It is misfiled under `l3plus/`
//! (it is an L3++ SD *recovery* card that happens to carry the whole
//! BM1385/BM1387/BM1387P/BM1390 jig toolkit), which is why every S11/BM1390
//! sweep that scoped itself to S11/S9 directories came back empty.
//!
//! S5 and S6 are Bitmain **product** documentation. Neither had ever been
//! read for chip geometry; both were surfaced by the bare-`1390` pass of the
//! §5 sweep.
//!
//! ## 1a. BM1390 is NOT the S11's production chip
//!
//! S5 states the S11's silicon directly and repeatedly: **84 × BM1387BF**,
//! `28 domains × 3 chips`, with the chip pinout figures labelled BM1387 and
//! the temperature path described through *"the 15th and 16th pins of
//! BM1387"*. The two independent geometry statements agree (`28 × 3 = 84`)
//! and the signal-path text independently counts to 84 (*"from chip 01 to
//! chip 84"*, *"from the 84th chip to the 28th pin of the 01th chip"*).
//!
//! Therefore the `Name=S11 HASH board` label on S1 is **not reliable
//! evidence about the Antminer S11 product** — the same failure mode as the
//! S11 firmware package's own jig `Config.ini`, whose title reads
//! `Name=S9 HASH board`. AMTC config titles name the *jig fixture*, not the
//! product.
//!
//! This also removes the last positive reason to associate BM1390 with any
//! shipped Antminer. **We hold a core count for BM1390 and no host.**
//!
//! # 2. Core count — 128, CONFIRMED (triple-sourced)
//!
//! `single-BM1390-ASIC-test/` on the S3 jig filesystem holds exactly
//! **128 gap-free `btc-core-NNN.txt` per-core pattern files, indices 000..127**
//! (bounded read: the enumeration is terminated by the FAT
//! `System Volume Information` entry, so no neighbouring directory bleeds in;
//! every index in `0..=127` is present and none is missing).
//!
//! That is the *identical* method the chip bible already accepts for
//! BM1387P = 128 (`minertest64-BM1387P/btc-asic-NN/btc-core-NN.txt`,
//! indices 0..127). It agrees with S1 and S2's `CoreNum=128`, and S2's
//! `ValidNonce1 = 128 = CoreNum` for `AsicNum=1` is internally self-checking.
//!
//! # 3. Chips per chain — REFUSED (three mutually inconsistent figures)
//!
//! | source | figure | status |
//! |---|---|---|
//! | S1 `Config.ini-V11-S` `AsicNum=60` | 60 | **fails the AMTC arithmetic oracle** (§3a) |
//! | S3 jig transcript `V11_BM1390S_32` | 32 | a *different* V11 board config; also `BM1390S`, a fourth part suffix |
//! | S3 `minertest64-BM1390/btc-asic-00..63` | 64 | **not a chip count** — harness capacity (the directory family is literally `minertest64`; `minertest64-BM1385` and `minertest64-BM1387` are the same size while those boards carry 45/54 and 63 chips) |
//!
//! Nothing here can be promoted. `BM1390_CHIPS_PER_CHAIN` stays `None`.
//!
//! ## 3a. The AMTC arithmetic oracle, and the one config that fails it
//!
//! Across the nine held `amtc-testing/s9/Config.ini*` files, every
//! multi-chip config satisfies `ValidNonce1 == DataCount * AsicNum`, and
//! every single-chip config satisfies `ValidNonce1 == CoreNum`:
//!
//! | config | DataCount | AsicNum | CoreNum | ValidNonce1 | oracle |
//! |---|---|---|---|---|---|
//! | `-S7-45` | 400 | 45 | 50 | 18 000 | pass |
//! | `-S7-54` | 400 | 54 | 50 | 21 600 | pass |
//! | `-S9` | 912 | 63 | 114 | 57 456 | pass |
//! | `-S9+` | 912 | 84 | 114 | 76 608 | pass |
//! | `-T9` | 912 | 57 | 114 | 51 984 | pass |
//! | `-T9+` | 912 | 18 | 114 | 16 416 | pass |
//! | `-single-ASIC` | 3 | 1 | 114 | 114 | pass (single-chip form) |
//! | `-single-BM1390P` | 1 | 1 | 128 | 128 | pass (single-chip form) |
//! | **`-V11-S` (the S11 / BM1390 board)** | 1024 | **60** | 128 | **22 528** | **FAIL** — `1024 * 60 = 61 440` |
//!
//! Six of six multi-chip configs pass; the only failure in the family is the
//! one config that names the S11 and BM1390. `22 528 / 1024 = 22`, which is
//! not 60 and is not any other number the file states, so the triple is
//! mutually inconsistent rather than merely surprising. **`AsicNum=60` is
//! therefore not trustworthy evidence about the S11.**
//!
//! This also **refutes**
//! §4, which offers `ValidNonce = AsicNum × CoreNum × (PassCount/DataCount) ×
//! pattern_repeat_num` and asserts *"60 × 128 … × 3 boards = 22528 (matches
//! measured)"*. `60 × 128 = 7 680` and `7 680 × 3 = 23 040`, not `22 528`;
//! and the same formula gives `63 × 114 = 7 182` for the S9, whose file says
//! `57 456`. The formula reproduces **zero** of the nine held configs.
//!
//! # 4. There is no BM1390 numeric identity anywhere in the held corpus
//!
//! Two held Bitmain binaries carry BM1390 in a **function name**:
//! `S9SES9KTestJig/bmminer` and `S9k/cgminer`. Read as *numeric comparison
//! literals* rather than as strings, the payload they emit is BM1393's:
//!
//! ```text
//! set_core_number_BM1390(chain, chip_addr):
//!     buf = [0x41, 0x09, 0x00, 0x00, 0x13, 0x93, 0xD0, chip_addr, CRC5]
//!            cmd   len   addr  reg   <-------- register payload -------->
//! ```
//!
//! The two binaries encode this identically (`S9k/cgminer.dec` writes it as
//! the two little-endian words `2369 = 0x0000_0941` and
//! `13 669 139 = 0x00D0_9313`; the `S9SES9KTestJig` copy writes the same nine
//! bytes field by field). Calibrated against `set_address` in the same
//! binary — `[0x40, 0x05, address, 0x00, CRC5]`, a documented BM1387-family
//! VIL frame — the payload decodes as the register-0 tuple
//! `[CHIP_ID_HI, CHIP_ID_LO, CORE_NUM, ADDR]` = **`0x1393`, `0xD0 = 208`**.
//!
//! `0xD0 = 208` is independently corroborated inside the same binaries:
//! `open_core_bm1393` sets `loop = 208` and runs
//! `for core_id in 0..=51 { for slot in 0..=3 { enable_core_clock(52*slot + core_id) } }`
//! = **exactly 208 core-clock enables**.
//!
//! Consequences, both load-bearing:
//!
//! 1. **The BM1390 function name is a stale label, not evidence.** A string
//!    sweep that stopped at the name would have "found BM1390 register
//!    behaviour" and been wrong. No `0x1390` chip-ID comparison literal
//!    exists in any held Bitmain miner or jig binary (§5).
//! 2. **`AsicChip::Bm1393.catalog().cores` was a `52` under-read — CORRECTED to
//!    `208` in Round 17 (B1).** The `52` was the *outer* loop bound; the loop
//!    opens four cores per iteration (`52 * slot + core_id`, slot 0..=3) and the
//!    chip is told `CORE_NUM = 0xD0 = 208` on the wire. The catalog now records
//!    208, citing all three sources below plus the first-party maintenance
//!    guide. This is safe metadata: BM1393 has no `MinerProfile`, so the
//!    corrected value never reaches the `nonce_attribution_cores` autotuner /
//!    rank-3 consistency path (the direction the earlier "not changed here"
//!    caution was guarding). The constants below stay as the machine-checkable
//!    provenance for the correction.
//!
//! # 5. Search method (so the negatives are reproducible and not re-run)
//!
//! Ignore-blind, binary-as-text, decompressing, **untruncated**:
//!
//! ```text
//! rg -a --no-ignore -z --no-messages -o -n -H -i \
//!    '(BM[-_ ]?1390|0x1390|chip1390|1390P|1390_|_1390)' \
//!    knowledge-base/{extractions,repos,firmware-archive,ARCTesterHashboardCaptures,Hashboard-Captures,digests,esp-miner-src} \
//!    DCENT_OS_DEVELOPMENT_KITRE2 'Latest Bitmain FW' HammerFirmwares 'NEW WAVE VNISH SD CARDS'
//! ```
//!
//! 411 matches. After removing two false-positive families they reduce to the
//! four sources in §1:
//!
//! - **`usr/bin/gdb`** — the `IBM####` charset table
//!. Present in ~20
//!   stock/VNish rootfs images; anchoring with `(?<![0-9A-Za-z])` removes it.
//! - **NEW: `lib/udev/hwdb.d/20-usb-vendor-model.hwdb`** — 91 of the 411
//!   matches are the lowercase token `1390p` inside udev's USB
//!   vendor/model database, which ships in every VNish/stock initramfs.
//!   Recorded here so the next sweep does not re-adjudicate it.
//!
//! `0x1390` occurs only in Amlogic S922X/A311D datasheets (a register offset)
//! and in RetDec disassembly artifacts (an address) — **never as a chip-ID
//! comparison**.
//!
//! # 6. Narrowed acquisition ask
//!
//! Core count is closed; the residue is much smaller than "a live S11":
//!
//! 1. **Extract S3's `single-board-test` and `bmminer` binaries** out of the
//!    L3++ jig image. This is a *desk* task, not a purchase: the image is
//!    held, and its `single-board-test` is the only held binary that carries
//!    `set_core_pm_BM1390` (absent from both §4 binaries). It is the shortest
//!    path to a real BM1390 register/PLL map.
//! 2. **A `Config.ini-V11-BM1390S-32`** (or the matching board's own config)
//!    would settle chips-per-chain against the oracle. The shell transcript
//!    proves such a config existed on that engineer's card.
//! 3. Only if 1 and 2 both fail: an S11 hashboard EEPROM dump, or a chip
//!    marking photograph.
//!
//! # 7. Records this evidence contradicts (reported, not edited here)
//!
//! - `DCENT_OS_Antminer/ "AMTC Test Jig Intel": *"BM1390P = 128
//!   cores (S11 chip, 1060 mV operating voltage)"* conflates two configs —
//!   `1060` mV is the **V11-S / S11 HASH board** step-1 jig test voltage;
//!   the **BM1390P single-chip** config says `890`. Neither is an operating
//!   envelope.
//! -  §4
//!   ValidNonce formula and its "matches measured" claim (§3a).
//! - `dcentrald-silicon-profiles/src/asics.rs` `AsicChip::Bm1393` cores (§4).

/// `Config.ini-V11-S` — the only held Bitmain config that names the S11 and
/// BM1390 together.
pub const V11_S_CONFIG_PATH: &str = "";

/// `Config.ini-single-BM1390P` — the single-chip BM1390P functional test.
pub const SINGLE_BM1390P_CONFIG_PATH: &str =
    "";

/// The AMTC jig SD filesystem that Round 15's sweep missed.
pub const JIG_SD_IMAGE_PATH: &str = concat!(
    "",
    "201904231425-L3++-SD-recover-NAND.img"
);

/// Bitmain's first-party S11 maintenance guide (S5).
pub const S11_MAINTENANCE_GUIDE_PATH: &str =
    " Guide.pdf";

/// Bitmain's first-party S9k / S9 SE maintenance guide (S6).
pub const S9K_S9SE_MAINTENANCE_GUIDE_PATH: &str =
    " S9SE Maintenance Guide.pdf";

/// The two held binaries carrying a BM1390-**named** function (§4).
pub const BM1390_NAMED_FUNCTION_BINARIES: &[&str] = &[
    "",
    "",
];

// ---------------------------------------------------------------------------
// Core count — CONFIRMED
// ---------------------------------------------------------------------------

/// BM1390 cores per chip. **128, triple-sourced** (§2). Same evidence class
/// as the accepted BM1387P = 128.
pub const BM1390_CORE_NUM: u32 = 128;

/// Number of distinct `btc-core-NNN.txt` files under
/// `single-BM1390-ASIC-test/` on [`JIG_SD_IMAGE_PATH`].
pub const BM1390_CORE_PATTERN_FILE_COUNT: u32 = 128;

/// Highest `btc-core-NNN.txt` index in that directory. The enumeration is
/// gap-free from `0`, which is what makes the count a core count rather than
/// a file count.
pub const BM1390_CORE_PATTERN_MAX_INDEX: u32 = 127;

// ---------------------------------------------------------------------------
// Geometry that is REFUSED
// ---------------------------------------------------------------------------

/// BM1390 chips per chain. **Refused** — three mutually inconsistent held
/// figures (§3). Never fill this from any single source.
pub const BM1390_CHIPS_PER_CHAIN: Option<u32> = None;

/// `Config.ini-V11-S` `AsicNum`. Recorded so it cannot be quietly promoted:
/// this is the figure that **fails** the AMTC arithmetic oracle.
pub const V11_S_ASICNUM_ORACLE_FAILING: u32 = 60;

/// The jig transcript's `V11_BM1390S_32` chip count — a *different* V11 board
/// config, and a fourth part suffix (`BM1390S`).
pub const V11_BM1390S_TRANSCRIPT_ASICNUM: u32 = 32;

/// `minertest64-BM1390/btc-asic-00..63`. **Harness capacity, not a chip
/// count** — `minertest64-BM1385` and `minertest64-BM1387` are the same size
/// for boards with 45/54 and 63 chips.
pub const MINERTEST64_HARNESS_SLOTS_NOT_A_CHIP_COUNT: u32 = 64;

/// Number of chains a BM1390 board carries. Nothing held states it.
pub const BM1390_CHAIN_COUNT: Option<u32> = None;

// ---------------------------------------------------------------------------
// Voltage — jig test steps only, NOT an envelope
// ---------------------------------------------------------------------------

/// `Config.ini-V11-S` `Voltage1` (mV) at `Freq1 = 200`. A jig **test step**,
/// not an operating envelope, and not a per-chip rail claim.
pub const V11_S_JIG_STEP1_VOLTAGE_MV: u32 = 1060;

/// `Config.ini-single-BM1390P` `Voltage1` (mV) at `Freq1 = 200`.
pub const SINGLE_BM1390P_JIG_STEP1_VOLTAGE_MV: u32 = 890;

/// BM1390 operating voltage envelope. **Refused** — no held source states an
/// operating envelope, only jig test steps, and no BM1390 unit has ever been
/// contacted.
pub const BM1390_OPERATING_VOLTAGE_MV: Option<u32> = None;

/// Whether any BM1390 datum in this module came from live silicon. Always
/// `false`.
pub const BM1390_HAS_LIVE_DATA: bool = false;

// ---------------------------------------------------------------------------
// Chip identity — the string/numeric split (§4)
// ---------------------------------------------------------------------------

/// Whether a `0x1390` chip-ID **comparison literal** exists anywhere in the
/// held corpus. It does not. `0x1390` occurs only as an Amlogic datasheet
/// register offset and as RetDec disassembly addresses.
pub const BM1390_CHIP_ID_LITERAL_IS_HELD: bool = false;

/// The nine wire bytes emitted by the BM1390-**named** `set_core_number_BM1390`
/// in both §4 binaries. Byte 7 is the chip address and byte 8 is CRC5, both
/// runtime-computed, so they are `0x00` placeholders here.
pub const SET_CORE_NUMBER_BM1390_FRAME: [u8; 9] =
    [0x41, 0x09, 0x00, 0x00, 0x13, 0x93, 0xD0, 0x00, 0x00];

/// The chip ID that BM1390-named function actually writes: **BM1393**.
pub const BM1390_NAMED_FUNCTION_PAYLOAD_CHIP_ID: u16 = 0x1393;

/// The core count that BM1390-named function actually writes: `0xD0` = 208.
pub const BM1390_NAMED_FUNCTION_PAYLOAD_CORE_NUM: u8 = 0xD0;

/// `open_core_bm1393` outer-loop bound in both held binaries. This is the
/// per-bank count; the shipped `asics.rs` catalog records the *total* (208 =
/// this × [`BM1393_OPEN_CORE_SLOTS`]) since Round 17 (B1). Retained as the
/// distinct per-bank fact so the total can never be silently reconciled to it.
pub const BM1393_OPEN_CORE_OUTER_LOOP: u32 = 52;

/// Slots per outer iteration in `open_core_bm1393`
/// (`core_index = 52 * slot + core_id`, `slot in 0..=3`).
pub const BM1393_OPEN_CORE_SLOTS: u32 = 4;

/// Total core-clock enables `open_core_bm1393` performs, and the value
/// `set_core_number_BM1390` writes into the chip's `CORE_NUM` field.
pub const BM1393_OPEN_CORE_TOTAL_ENABLES: u32 = 208;

/// BM1393 cores per chip, stated verbatim by Bitmain's own S9k/S9 SE
/// maintenance guide (S6): *"There are 208 cores on a single BM1393 chip"*.
/// A **third, first-party, non-binary** source for the same number.
pub const BM1393_CORES_MAINTENANCE_GUIDE: u32 = 208;

// ---------------------------------------------------------------------------
// S11 product geometry, from Bitmain's own maintenance guide (S5, §1a)
// ---------------------------------------------------------------------------

/// S11 chips per computing board. First-party, and double-stated inside the
/// same document (`28 × 3` and an explicit "84 BM1387 chips").
pub const S11_CHIPS_PER_BOARD_MAINTENANCE_GUIDE: u32 = 84;

/// S11 series voltage domains per computing board.
pub const S11_VOLTAGE_DOMAINS: u32 = 28;

/// S11 chips per voltage domain (parallel within the domain).
pub const S11_CHIPS_PER_DOMAIN: u32 = 3;

/// The exact chip part the S11 maintenance guide names.
pub const S11_CHIP_NAME_MAINTENANCE_GUIDE: &str = "BM1387BF";

/// Whether BM1390 is the Antminer S11's production silicon. **No** — S5 says
/// BM1387BF, twice, with an independent signal-path count to 84 (§1a).
pub const BM1390_IS_THE_S11_PRODUCTION_CHIP: bool = false;

/// Whether any held artifact names a **shipped product** that uses BM1390.
/// None does: S1's `S11 HASH board` title is a jig-fixture label refuted by
/// S5, and S2/S3 describe single-chip and `BM1390S` test fixtures.
pub const BM1390_HAS_A_KNOWN_PRODUCT_HOST: bool = false;

// ---------------------------------------------------------------------------
// AMTC arithmetic oracle (§3a)
// ---------------------------------------------------------------------------

/// One held `amtc-testing/s9/Config.ini*` row, reduced to the four fields the
/// oracle needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmtcConfigRow {
    /// File suffix, e.g. `"-V11-S"`.
    pub file_suffix: &'static str,
    /// The config's own `Name=` line.
    pub name: &'static str,
    /// `AsicType=`.
    pub asic_type: u32,
    /// `AsicNum=`.
    pub asic_num: u32,
    /// `CoreNum=`.
    pub core_num: u32,
    /// `DataCount=`.
    pub data_count: u32,
    /// `ValidNonce1=`.
    pub valid_nonce_1: u32,
}

impl AmtcConfigRow {
    /// Whether this row satisfies the AMTC arithmetic oracle.
    ///
    /// Multi-chip configs must satisfy `ValidNonce1 == DataCount * AsicNum`;
    /// single-chip configs must satisfy `ValidNonce1 == CoreNum`.
    #[must_use]
    pub const fn satisfies_oracle(&self) -> bool {
        if self.asic_num == 1 {
            self.valid_nonce_1 == self.core_num
        } else {
            self.valid_nonce_1 == self.data_count * self.asic_num
        }
    }
}

/// All nine held `amtc-testing/s9/Config.ini*` rows, transcribed verbatim.
pub const AMTC_CONFIG_ROWS: &[AmtcConfigRow] = &[
    AmtcConfigRow {
        file_suffix: "-S7-45",
        name: "S7 HASH board",
        asic_type: 1385,
        asic_num: 45,
        core_num: 50,
        data_count: 400,
        valid_nonce_1: 18_000,
    },
    AmtcConfigRow {
        file_suffix: "-S7-54",
        name: "S7 HASH board",
        asic_type: 1385,
        asic_num: 54,
        core_num: 50,
        data_count: 400,
        valid_nonce_1: 21_600,
    },
    AmtcConfigRow {
        file_suffix: "-S9",
        name: "S9 HASH board",
        asic_type: 1387,
        asic_num: 63,
        core_num: 114,
        data_count: 912,
        valid_nonce_1: 57_456,
    },
    AmtcConfigRow {
        file_suffix: "-S9+",
        name: "S9+ HASH board",
        asic_type: 1387,
        asic_num: 84,
        core_num: 114,
        data_count: 912,
        valid_nonce_1: 76_608,
    },
    AmtcConfigRow {
        file_suffix: "-T9",
        name: "T9 HASH board",
        asic_type: 1387,
        asic_num: 57,
        core_num: 114,
        data_count: 912,
        valid_nonce_1: 51_984,
    },
    AmtcConfigRow {
        file_suffix: "-T9+",
        name: "T9+ HASH board",
        asic_type: 1387,
        asic_num: 18,
        core_num: 114,
        data_count: 912,
        valid_nonce_1: 16_416,
    },
    AmtcConfigRow {
        file_suffix: "-single-ASIC",
        name: "S9 HASH board",
        asic_type: 1387,
        asic_num: 1,
        core_num: 114,
        data_count: 3,
        valid_nonce_1: 114,
    },
    AmtcConfigRow {
        file_suffix: "-single-BM1390P",
        name: "Single BM1390P",
        asic_type: 1390,
        asic_num: 1,
        core_num: 128,
        data_count: 1,
        valid_nonce_1: 128,
    },
    AmtcConfigRow {
        file_suffix: "-V11-S",
        name: "S11 HASH board",
        asic_type: 1390,
        asic_num: 60,
        core_num: 128,
        data_count: 1024,
        valid_nonce_1: 22_528,
    },
];

/// The single AMTC config in the family that fails the oracle. Named so a
/// future change that "fixes" the row by editing a number trips a test.
pub const ORACLE_FAILING_CONFIG_SUFFIX: &str = "-V11-S";

// ---------------------------------------------------------------------------
// False-positive families (§5)
// ---------------------------------------------------------------------------

/// Known false-positive sources for an unanchored `BM1390` / `1390` sweep.
/// A hit in one of these files is worth nothing.
pub const BM1390_SWEEP_FALSE_POSITIVE_FILES: &[&str] = &[
    // GDB's IBM#### charset table — already recorded as
    // .
    "usr/bin/gdb",
    // NEW (Round 16 B7): udev's USB vendor/model database contributes 91 of
    // the 411 raw matches as the lowercase token `1390p`.
    "lib/udev/hwdb.d/20-usb-vendor-model.hwdb",
];

/// Raw match count of the §5 sweep across all held corpora.
pub const BM1390_SWEEP_RAW_MATCH_COUNT: u32 = 411;

/// Of those, how many are the udev-hwdb `1390p` false positive.
pub const BM1390_SWEEP_UDEV_HWDB_FALSE_POSITIVES: u32 = 91;

#[cfg(test)]
mod tests {
    // Panicking is the assertion mechanism in tests; the workspace lints that
    // ban `unwrap`/indexing in production code are inverted here.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn core_count_is_128_and_triple_sourced() {
        assert_eq!(BM1390_CORE_NUM, 128);
        // The on-disk per-core pattern enumeration must agree exactly, and
        // must be gap-free from zero (count == max index + 1).
        assert_eq!(BM1390_CORE_PATTERN_FILE_COUNT, BM1390_CORE_NUM);
        assert_eq!(
            BM1390_CORE_PATTERN_MAX_INDEX + 1,
            BM1390_CORE_PATTERN_FILE_COUNT,
            "btc-core-NNN enumeration must be gap-free from 0"
        );
        // Both AMTC configs that declare AsicType=1390 must say 128.
        for row in AMTC_CONFIG_ROWS.iter().filter(|r| r.asic_type == 1390) {
            assert_eq!(
                row.core_num, BM1390_CORE_NUM,
                "{} disagrees on BM1390 core count",
                row.file_suffix
            );
        }
    }

    #[test]
    fn chips_per_chain_and_chain_count_stay_refused() {
        assert!(
            BM1390_CHIPS_PER_CHAIN.is_none(),
            "three held sources disagree (60 / 32 / a 64-slot harness); \
             none may be promoted"
        );
        assert!(BM1390_CHAIN_COUNT.is_none());
        // The three contradicting figures must all still be distinct, or the
        // reason for the refusal has been edited away.
        assert_ne!(V11_S_ASICNUM_ORACLE_FAILING, V11_BM1390S_TRANSCRIPT_ASICNUM);
        assert_ne!(
            V11_S_ASICNUM_ORACLE_FAILING,
            MINERTEST64_HARNESS_SLOTS_NOT_A_CHIP_COUNT
        );
        assert_ne!(
            V11_BM1390S_TRANSCRIPT_ASICNUM,
            MINERTEST64_HARNESS_SLOTS_NOT_A_CHIP_COUNT
        );
    }

    #[test]
    fn amtc_oracle_passes_on_every_row_except_the_s11_board() {
        let failing: Vec<&str> = AMTC_CONFIG_ROWS
            .iter()
            .filter(|r| !r.satisfies_oracle())
            .map(|r| r.file_suffix)
            .collect();
        assert_eq!(
            failing,
            vec![ORACLE_FAILING_CONFIG_SUFFIX],
            "exactly one held AMTC config may fail the oracle, and it is the \
             one that names the S11 and BM1390"
        );
    }

    #[test]
    fn the_oracle_has_enough_passing_rows_to_be_an_oracle() {
        // A rule validated on one row is not a rule. Six multi-chip rows and
        // two single-chip rows must pass before the single failure means
        // anything.
        let multi_pass = AMTC_CONFIG_ROWS
            .iter()
            .filter(|r| r.asic_num > 1 && r.satisfies_oracle())
            .count();
        let single_pass = AMTC_CONFIG_ROWS
            .iter()
            .filter(|r| r.asic_num == 1 && r.satisfies_oracle())
            .count();
        assert_eq!(multi_pass, 6);
        assert_eq!(single_pass, 2);
    }

    #[test]
    fn v11_s_row_is_transcribed_exactly_and_is_the_failure() {
        let row = AMTC_CONFIG_ROWS
            .iter()
            .find(|r| r.file_suffix == "-V11-S")
            .expect("-V11-S row must exist");
        assert_eq!(row.name, "S11 HASH board");
        assert_eq!(row.asic_type, 1390);
        assert_eq!(row.asic_num, 60);
        assert_eq!(row.core_num, 128);
        assert_eq!(row.data_count, 1024);
        assert_eq!(row.valid_nonce_1, 22_528);
        assert!(!row.satisfies_oracle());
        // The arithmetic the file would need in order to be consistent.
        assert_eq!(row.data_count * row.asic_num, 61_440);
    }

    #[test]
    fn mining_bible_validnonce_formula_reproduces_no_multi_chip_config() {
        // bm1390.md §4: ValidNonce = AsicNum * CoreNum * (PassCount/DataCount)
        //               * pattern_repeat_num, with PassCount == DataCount and
        //               pattern_repeat_num == 1 in every held config.
        //
        // Scoped to multi-chip rows on purpose. On a single-chip row the bible
        // formula degenerates to `1 * CoreNum`, which coincides with the real
        // single-chip rule `ValidNonce1 == CoreNum` — a coincidence, not a
        // confirmation, and exactly the two rows the bible's author would have
        // checked.
        let mut checked = 0_u32;
        for row in AMTC_CONFIG_ROWS.iter().filter(|r| r.asic_num > 1) {
            let bible = row.asic_num * row.core_num;
            assert_ne!(
                bible, row.valid_nonce_1,
                "the bm1390.md formula must not reproduce {}; if it ever \
                 does, re-adjudicate which formula is right",
                row.file_suffix
            );
            checked += 1;
        }
        // Seven multi-chip rows exist; six satisfy the real oracle and the
        // seventh (`-V11-S`) is the failure §3a is about. All seven are
        // checked here — the bible formula must reproduce none of them.
        assert_eq!(checked, 7, "all seven multi-chip rows must be checked");
        // And specifically the "matches measured" claim: 60 * 128 * 3 boards.
        assert_ne!(60_u32 * 128 * 3, 22_528);
    }

    #[test]
    fn bm1390_named_function_payload_is_bm1393_not_bm1390() {
        // This is the whole "numeric literals, never strings" lesson in one
        // assertion: the function is named BM1390 and writes BM1393.
        let f = SET_CORE_NUMBER_BM1390_FRAME;
        assert_eq!(f[0], 0x41, "VIL SetConfig command byte");
        assert_eq!(f[1], 0x09, "frame length");
        let payload_chip_id = (u16::from(f[4]) << 8) | u16::from(f[5]);
        assert_eq!(payload_chip_id, BM1390_NAMED_FUNCTION_PAYLOAD_CHIP_ID);
        assert_eq!(payload_chip_id, 0x1393);
        assert_ne!(
            payload_chip_id, 0x1390,
            "the BM1390-named function must never be recorded as writing 0x1390"
        );
        assert_eq!(f[6], BM1390_NAMED_FUNCTION_PAYLOAD_CORE_NUM);
        assert_eq!(u32::from(f[6]), BM1393_OPEN_CORE_TOTAL_ENABLES);
    }

    #[test]
    fn bm1393_open_core_arithmetic_is_self_consistent() {
        assert_eq!(
            BM1393_OPEN_CORE_OUTER_LOOP * BM1393_OPEN_CORE_SLOTS,
            BM1393_OPEN_CORE_TOTAL_ENABLES
        );
        // The contradiction this module reports and deliberately does not
        // "fix": the shipped catalog records the outer-loop bound.
        assert_ne!(
            BM1393_OPEN_CORE_OUTER_LOOP, BM1393_OPEN_CORE_TOTAL_ENABLES,
            "if these ever become equal the reported asics.rs contradiction \
             has been silently resolved and this record must be re-read"
        );
        assert_eq!(
            u32::from(BM1390_NAMED_FUNCTION_PAYLOAD_CORE_NUM),
            BM1393_OPEN_CORE_TOTAL_ENABLES,
            "the wire CORE_NUM byte and the open-core enable count are the \
             two independent sources for 208; they must agree"
        );
    }

    #[test]
    fn no_chip_id_literal_and_no_live_data_is_ever_claimed() {
        assert!(!BM1390_CHIP_ID_LITERAL_IS_HELD);
        assert!(!BM1390_HAS_LIVE_DATA);
        assert!(BM1390_OPERATING_VOLTAGE_MV.is_none());
    }

    #[test]
    fn jig_test_voltages_are_two_distinct_steps_not_one_envelope() {
        // `DCENT_OS_Antminer/ conflates these into a single
        // "1060 mV operating voltage" for the BM1390P. They are different
        // configs and neither is an envelope.
        assert_ne!(
            V11_S_JIG_STEP1_VOLTAGE_MV,
            SINGLE_BM1390P_JIG_STEP1_VOLTAGE_MV
        );
        assert_eq!(V11_S_JIG_STEP1_VOLTAGE_MV, 1060);
        assert_eq!(SINGLE_BM1390P_JIG_STEP1_VOLTAGE_MV, 890);
        assert!(BM1390_OPERATING_VOLTAGE_MV.is_none());
    }

    #[test]
    fn false_positive_families_stay_recorded() {
        assert!(BM1390_SWEEP_FALSE_POSITIVE_FILES
            .iter()
            .any(|f| f.ends_with("gdb")));
        assert!(BM1390_SWEEP_FALSE_POSITIVE_FILES
            .iter()
            .any(|f| f.contains("20-usb-vendor-model.hwdb")));
        assert!(BM1390_SWEEP_UDEV_HWDB_FALSE_POSITIVES < BM1390_SWEEP_RAW_MATCH_COUNT);
    }

    #[test]
    fn bm1390_is_never_recorded_as_the_s11_production_chip() {
        // Bitmain's own S11 maintenance guide says BM1387BF, twice, with an
        // independent signal-path count to 84.
        assert!(!BM1390_IS_THE_S11_PRODUCTION_CHIP);
        assert!(!BM1390_HAS_A_KNOWN_PRODUCT_HOST);
        assert_eq!(
            S11_VOLTAGE_DOMAINS * S11_CHIPS_PER_DOMAIN,
            S11_CHIPS_PER_BOARD_MAINTENANCE_GUIDE,
            "the guide's two independent geometry statements must agree"
        );
        assert_eq!(S11_CHIP_NAME_MAINTENANCE_GUIDE, "BM1387BF");
        assert!(
            !S11_CHIP_NAME_MAINTENANCE_GUIDE.contains("1390")
                && !S11_CHIP_NAME_MAINTENANCE_GUIDE.contains("1391"),
            "neither refused candidate may be re-attached to the S11 here"
        );
    }

    #[test]
    fn bm1393_core_count_has_three_independent_sources() {
        // (a) the wire byte in set_core_number_BM1390, (b) the open-core
        // enable count, (c) Bitmain's S9k/S9 SE maintenance guide.
        assert_eq!(
            u32::from(BM1390_NAMED_FUNCTION_PAYLOAD_CORE_NUM),
            BM1393_CORES_MAINTENANCE_GUIDE
        );
        assert_eq!(
            BM1393_OPEN_CORE_TOTAL_ENABLES,
            BM1393_CORES_MAINTENANCE_GUIDE
        );
        assert_eq!(BM1393_CORES_MAINTENANCE_GUIDE, 208);
        // And it is emphatically not the per-bank outer-loop bound of 52 (which
        // the shipped catalog under-recorded until the Round 17 B1 correction).
        assert_ne!(BM1393_CORES_MAINTENANCE_GUIDE, BM1393_OPEN_CORE_OUTER_LOOP);
    }

    #[test]
    fn provenance_paths_point_at_held_corpora() {
        for p in [
            V11_S_CONFIG_PATH,
            SINGLE_BM1390P_CONFIG_PATH,
            JIG_SD_IMAGE_PATH,
            S11_MAINTENANCE_GUIDE_PATH,
            S9K_S9SE_MAINTENANCE_GUIDE_PATH,
        ] {
            assert!(p.starts_with("knowledge-base/"), "{p} must be a held path");
        }
        assert_eq!(BM1390_NAMED_FUNCTION_BINARIES.len(), 2);
        for p in BM1390_NAMED_FUNCTION_BINARIES {
            assert!(p.starts_with(""));
        }
    }
}
