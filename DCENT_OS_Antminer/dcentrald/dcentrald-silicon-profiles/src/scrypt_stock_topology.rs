//! Scrypt product-line topology recovered **byte-exactly from authentic
//! Bitmain stock images** (Round 15, 2026-08-07).
//!
//! This module is deliberately *only* a transcription surface. Every field is
//! `Option`, and a field is `Some` **only** when a held stock artifact states
//! it literally. Nothing here is interpolated, averaged, inherited from a
//! sibling chip, or carried over from a research document. When the stock
//! bytes are silent, the field is `None` and the consumer must refuse — the
//! §"Fail closed on absent evidence" rule of the hardware-enablement
//! constitution.
//!
//! It exists because the previously-held Scrypt numbers came from repair
//! guides, vendor listings and third-party (VNish) binaries. Those are
//! secondary sources. The rows below are primary.
//!
//! # Held artifacts (all under the operator drop `Latest Bitmain FW/`)
//!
//! | Image | SHA-256 | Result |
//! |---|---|---|
//! | `Antminer-L3+-201907101440-384M.tar.gz` | `5b3fbe11…31953c1` | plaintext |
//! | `Antminer-L7-release-202301300939.bmu` | `eccc9394…8a21cac7` | rootfs **encrypted** |
//! | `FR-1.19(260302-L9).bmu` | `2af05a34…05c3aa827` | CVCtrl rootfs **plaintext** |
//!
//! # ⚠ CORRECTION — the L9 is BM1491, not BM1489
//!
//! Every prior in-tree statement that the Antminer L9 uses the **BM1489**
//! (`bm1489.rs`, `drivers/bm1489.rs`, `registry.rs:516`'s "Scrypt L3+/L7/L9"
//! comment) is contradicted by the authentic L9 stock image. Its
//! `etc/topol.conf` states, in plaintext:
//!
//! ```text
//! "asic_id": "BM1491",
//! "chip_type": "0x1491",
//! ```
//!
//! and its `etc/cgminer.conf.factory` selects `"algo": "ltc_1491"`. The L9
//! miner binary `usr/bin/godminer` carries a dedicated
//! `backend/backend_ltc_1491/` source tree. See [`L9_BSL41601`].
//!
//! This simultaneously settles two open questions in
//! `dcentrald-silicon-profiles/src/bm1491.rs`: that file records "**No
//! `0x1491` literal** in any decoded binary" and picks hypothesis (b)
//! ("reserved enum slot … better-supported") over (a) ("BM1489 successor for
//! next-gen Scrypt L7/L9"). The held stock bytes carry the literal `0x1491`
//! and bind it to a Litecoin/Scrypt algorithm on a real shipping product, so
//! **hypothesis (a) is correct and (b) is falsified**. `bm1491.rs` is outside
//! this wave's file grant; the corrections are proposed as a patch in
//! .
//!
//! # ⚠ The L7 row is almost entirely `None` — on purpose
//!
//! The stock L7 `.bmu` unpacks cleanly, but only its **boot chain** is
//! plaintext (`BOOT.bin` carries the Xilinx `0x6655_99AA`/`XNLX` bootrom
//! header, `devicetree.dtb` names `arm,cortex-a9` + `arm,pl353-nand-r2p1` +
//! `cdns,uart-r1p8`, kernel string `Linux-4.6.0-xilinx-g03c746f7`). The three
//! payloads that would carry the miner — `minerfs.image.gz`,
//! `update.image.gz`, `miner.btm.tar.gz` — are high-entropy with no container
//! magic (Shannon 7.98/7.98/7.88 bits per byte over the first 200 KiB) and no
//! held key. So the L7's ASIC identity is **not** established by stock bytes;
//! the "L7 = BM1489" attribution rests entirely on third-party VNish
//! binaries. [`L7_STOCK`] therefore records the control board (which the
//! plaintext boot chain does prove) and refuses everything else.

/// One Scrypt product row, transcribed from authentic Bitmain stock bytes.
///
/// `None` means *the held stock image does not state this*. It never means
/// zero, and it must never be filled in from a sibling chip or a research
/// doc — do that and the whole point of this module is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScryptStockTopology {
    /// Marketing model name.
    pub model: &'static str,
    /// Bitmain internal machine/board id, when the image declares one.
    pub machine_id: Option<&'static str>,
    /// Control-board SoC family, when the plaintext boot chain proves it.
    pub control_board: Option<&'static str>,
    /// ASIC part name **as stated by the stock image itself**.
    pub asic_id: Option<&'static str>,
    /// Numeric chip type **as stated by the stock image itself**.
    pub chip_type: Option<u16>,
    /// Hashboard chains per miner.
    pub chain_count: Option<u32>,
    /// ASICs per chain.
    pub chips_per_chain: Option<u32>,
    /// Big (hashing) cores per ASIC.
    pub asic_big_core_num: Option<u32>,
    /// Little cores per ASIC.
    pub asic_little_core_num: Option<u32>,
    /// Little cores per big core.
    pub core_little_core_num: Option<u32>,
    /// Chip-address stride used during enumeration.
    pub asic_addr_interval: Option<u32>,
    /// Voltage domains per chain.
    pub chain_domain_num: Option<u32>,
    /// ASICs per voltage domain.
    pub domain_asic_num: Option<u32>,
    /// Factory default chain frequency, MHz.
    pub default_freq_mhz: Option<u32>,
    /// Factory default **ASIC-rail** voltage, millivolts. This is the chip
    /// domain rail, NOT the chain rail the `SiliconTable` rows carry.
    pub default_asic_voltage_mv: Option<u32>,
    /// Rated wall power, watts.
    pub rated_watts: Option<u32>,
    /// PSU family string.
    pub psu_family: Option<&'static str>,
    /// Hashboard EEPROM 7-bit I²C address.
    pub eeprom_i2c_addr: Option<u8>,
    /// Whether the board carries a hashboard PIC/MCU.
    pub has_board_pic: Option<bool>,
    /// Exact provenance sentence for this row.
    pub evidence: &'static str,
}

impl ScryptStockTopology {
    /// Total ASICs per miner, but **only** when both factors are stock-stated.
    ///
    /// Returns `None` rather than substituting a default for either factor.
    pub const fn total_chips(&self) -> Option<u32> {
        match (self.chain_count, self.chips_per_chain) {
            (Some(chains), Some(per)) => Some(chains * per),
            _ => None,
        }
    }

    /// `true` when this row carries enough stock-stated geometry to describe
    /// a chain: chip identity, chain count, and chips per chain.
    ///
    /// Deliberately does **not** consider frequency/voltage — a row can be
    /// geometrically complete and still have no safe energization envelope.
    pub const fn geometry_complete(&self) -> bool {
        self.asic_id.is_some() && self.chain_count.is_some() && self.chips_per_chain.is_some()
    }
}

// ---------------------------------------------------------------------------
// L3+ — Antminer-L3+-201907101440-384M.tar.gz
// ---------------------------------------------------------------------------

/// Antminer L3+ stock row, firmware `V1.0.41` (`version_number`), build
/// `201907101440`.
///
/// Unpack path: outer `tar.gz` → `fw.tar.gz` → `initramfs.bin.SD`
/// (u-boot legacy uImage, RAMDisk, gzip) → strip the 64-byte uImage header →
/// gzip → SVR4 cpio → rootfs.
///
/// What the image states, and where:
/// - `etc/cgminer.conf.factory` (SHA-256 `1b0b71ad…d69f9ebb`):
///   `"bitmain-freq" : "384"`. This is the **only** operating-point datum in
///   the entire L3+ config surface — there is no `bitmain-voltage` key.
/// - `etc/init.d/cgminer.sh` exports exactly four board-detect GPIOs
///   (`PLUG0..3` = gpio 51/48/47/44) and four chain resets (`RST0..3` =
///   gpio 5/4/27/22) ⇒ **4 chains**. Corroborated in `usr/bin/cgminer`
///   (SHA-256 `56d65a0a…960e026b`) by the chain-scan loop bound
///   `cmp r4, #4` at `.text` `0x3f6d4`.
/// - `fw.tar.gz` ships `am335x-boneblack-bitmainer.dtb`, whose nodes are
///   `ti,omap3-uart` serials at `0x44e09000`/`0x48022000`/`0x48024000`/
///   `0x481a6000`/`0x481a8000`/`0x481aa000` with `pinmux_bb_uart{2,3,5,6}_pins`
///   ⇒ **AM335x BeagleBone, kernel UARTs, no FPGA and no UIO**.
///
/// What the image does **not** state, and is therefore `None` here:
/// - **chips per chain.** The widely-repeated `72` comes from
///   `SCRYPT_ASIC_CHIPS.md` §77-81 (re-cited by `bm1485.rs:96` and
///   `drivers/bm1485.rs:203`), not from these bytes. The stock binary
///   discovers chain length at runtime — its own log line is
///   `%s: chain %d has %d ASIC, and addrInterval is %d`, and
///   `drivers/bm1485.rs:160-176` already documents that BM1485 has no
///   readable chip id and is detected by chain length. So the stock image
///   *cannot* state a chip count, and this row must not invent one.
/// - **cores per chip.** `BM1485_CORE_NUM = 12` is a `cgminer-ltc` **source**
///   constant, a different artifact from this binary.
/// - **ASIC voltage.** No `bitmain-voltage` key exists in the L3+ config.
pub const L3PLUS_STOCK: ScryptStockTopology = ScryptStockTopology {
    model: "Antminer L3+",
    machine_id: None,
    control_board: Some("AM335x BeagleBone"),
    // The L3+ config/binary never names its ASIC. "BM1485" is a correct
    // attribution from other sources, but it is not in *these* bytes, and
    // this module only carries what the stock image says.
    asic_id: None,
    chip_type: None,
    chain_count: Some(4),
    chips_per_chain: None,
    asic_big_core_num: None,
    asic_little_core_num: None,
    core_little_core_num: None,
    asic_addr_interval: None,
    chain_domain_num: None,
    domain_asic_num: None,
    default_freq_mhz: Some(384),
    default_asic_voltage_mv: None,
    rated_watts: None,
    psu_family: None,
    eeprom_i2c_addr: None,
    has_board_pic: None,
    evidence: "Antminer-L3+-201907101440-384M.tar.gz \
               (sha256 5b3fbe1132f050d770f25f91a97312b098496aba856f76e52c336c69c31953c1); \
               etc/cgminer.conf.factory bitmain-freq=384; \
               etc/init.d/cgminer.sh PLUG0..3 + RST0..3; \
               am335x-boneblack-bitmainer.dtb ti,omap3-uart",
};

// ---------------------------------------------------------------------------
// L3+ chain-UART baud — the BM1485 dispute, settled from stock bytes
// ---------------------------------------------------------------------------

/// The **complete** set of chain-UART baud rates the stock L3+ firmware will
/// accept, decoded from its own numeric-rate → termios mapper.
///
/// `usr/bin/cgminer` (SHA-256 `56d65a0a…960e026b`) contains a leaf function at
/// `.text` `0x3b698..0x3b750` that takes the requested numeric rate in `r0`
/// and returns a termios `Bxxxx` constant, or `0` for "unsupported". It is a
/// flat compare-and-return chain with no table indirection, so the decode is
/// exhaustive:
///
/// ```text
///   0x3b698  mov r3,#0xc200 / movt r3,#1   ; 0x0001c200 =   115200
///   0x3b74c  movw r0,#0x1002               ; B115200
///   0x3b6ac  mov r3,#0x800  / movt r3,#7   ; 0x00070800 =   460800
///   0x3b724  movw r0,#0x1004               ; B460800
///   0x3b6c0  cmp r0,#0xe1000               ;              921600
///   0x3b73c  movw r0,#0x1007               ; B921600
///   0x3b6c8  movw r3,#0xc6c0/movt r3,#0x2d ; 0x002dc6c0 = 3000000
///   0x3b6d8  movw r0,#0x100d               ; B3000000
///   0x3b6e0  cmp r0,#0x4b00                ;               19200
///   0x3b744  mov  r0,#0xe                  ; B19200
///   0x3b6ec  cmp r0,#0x9600                ;               38400
///   0x3b734  mov  r0,#0xf                  ; B38400
///   0x3b6f4  cmp r0,#0xe100                ;               57600
///   0x3b6fc  movw r0,#0x1001               ; B57600
///   0x3b704  cmp r0,#0x38400               ;              230400
///   0x3b72c  movw r0,#0x1003               ; B230400
///   0x3b714  cmp r0,#0x2580                ;                9600
///   0x3b71c  mov  r0,#0xd                  ; B9600
///   0x3b70c  mov  r0,#0                    ; <unsupported>
/// ```
///
/// All nine returned values match `asm-generic/termbits.h` exactly
/// (`B9600=0o15`, `B19200=0o16`, `B38400=0o17`, `B57600=0o10001`,
/// `B115200=0o10002`, `B230400=0o10003`, `B460800=0o10004`, `B921600=0o10007`,
/// `B3000000=0o10015`), which independently validates the decode.
///
/// The caller at `.text` `0x3f788` does `bl 0x3b698`; on a `0` return it logs
/// `Unrecognized baud rate: %d,set default baud` (`.rodata` `0x569c8`) and
/// falls back to `movw r3, #0x1002` — see [`L3PLUS_STOCK_DEFAULT_BAUD`].
///
/// # Second source — independently confirmed
///
/// The same decode was re-run against the *other* stock L3+ `cgminer` already
/// held in-repo,
///
/// (SHA-256 `eb5872ea31257be343495b45d02d2d3a27756ba21b008e42d48a3dfaaa2a8889`,
/// 330,836 bytes, dated 2017 — a different build from the 2019 drop's
/// 333,716-byte `56d65a0a…960e026b`). Its mapper sits at a different address
/// but compares **exactly the same nine rates** and returns **exactly the same
/// nine termios constants**. Two independent Bitmain builds two years apart
/// agree, and neither contains `390_625` or `1_562_500`.
pub const L3PLUS_STOCK_ACCEPTED_BAUDS: [u32; 9] = [
    9_600, 19_200, 38_400, 57_600, 115_200, 230_400, 460_800, 921_600, 3_000_000,
];

/// The rate the stock L3+ falls back to when the mapper returns `0`
/// (`movw r3, #0x1002` = `B115200` at `.text` `0x3f7ec`, and the identical
/// silent path at `0x3f7c0`).
pub const L3PLUS_STOCK_DEFAULT_BAUD: u32 = 115_200;

/// The two rival "BM1485 operational baud" figures that this module refuses.
///
/// Earlier documentation left the operational rate **UNRESOLVED** between
/// `390_625` (bt8d=7) and `1_562_500` (bt8d=1). A 2026-08-11
/// instruction-level pass supersedes that uncertainty for exact 2017 stock:
/// `FUN_0004285c` selects host baud 115200, and the sole MISC_CONTROL writer
/// preserves bt8d=26. The two values below remain refused cross-release
/// candidates, not candidates for that exact artifact.
///
/// **Both are now falsified for the L3+ platform**, and by *positive*
/// evidence rather than absence:
///
/// 1. Neither value is in [`L3PLUS_STOCK_ACCEPTED_BAUDS`]. The stock mapper
///    is exhaustive, so the stock host UART **cannot be set to either rate**;
///    a request for either returns `0` → "Unrecognized" → `B115200`.
/// 2. Neither is reachable on the hardware regardless of software. Our own
///    `dcentrald-hal/src/serial.rs:1213-1214` records the AM335x
///    `clock-frequency = 48000000` ⇒ `base_baud = 48e6/16 = 3_000_000`;
///    `3e6/1_562_500 = 1.92` and `3e6/390_625 = 7.68`, neither integral.
///    (`drivers/bm1485.rs:119-121` already derived this arithmetic; the
///    mapper decode is what upgrades it from inference to held evidence.)
/// 3. Both figures *are* exactly generable by the **Zynq FPGA** divisor
///    formula `200e6/(16*(div+1))` used on S9/S17/S19 chains
///    (root : "Baud: 200M/(16*(div+1))"): `div=7 → 1_562_500`,
///    `div=31 → 390_625`. The L3+ has no FPGA. Both numbers are therefore
///    best explained as a Zynq-family formula misapplied to an AM335x
///    product.
///
/// This module does not authorize UART I/O. It records why both high-speed
/// values are inapplicable to exact stock and remain unbound elsewhere.
pub const BM1485_REFUSED_OPERATIONAL_BAUDS: [u32; 2] = [390_625, 1_562_500];

/// Whether the stock L3+ firmware can drive its chain UART at `baud`.
///
/// Fail-closed: anything not literally enumerated by the stock mapper is
/// rejected.
pub const fn l3plus_stock_baud_supported(baud: u32) -> bool {
    let mut i = 0;
    while i < L3PLUS_STOCK_ACCEPTED_BAUDS.len() {
        if L3PLUS_STOCK_ACCEPTED_BAUDS[i] == baud {
            return true;
        }
        i += 1;
    }
    false
}

// ---------------------------------------------------------------------------
// L7 — Antminer-L7-release-202301300939.bmu
// ---------------------------------------------------------------------------

/// Antminer L7 stock row, release `202301300939`.
///
/// The BMU parses cleanly (`tools/bmu_parser.py extract`, 15 members) but the
/// miner-bearing payloads are encrypted, so this row can only carry what the
/// plaintext boot chain proves:
///
/// - `BOOT.bin` begins `fe ff ff ea × 8` then `66 55 99 AA` `X N L X` — the
///   Xilinx Zynq bootrom header.
/// - `devicetree.dtb` declares `arm,cortex-a9`, `arm,cortex-a9-gic`,
///   `arm,pl353-nand-r2p1`, `arm,pl310-cache`, `cdns,uart-r1p8`, `cdns,gem`,
///   and `/amba@0/serial@e0001000`; version string
///   `Linux-4.6.0-xilinx-g03c746f7`.
///
/// Encrypted (Shannon entropy over first 200 KiB, no container magic):
/// `minerfs.image.gz` 7.979 (sha256 `50fef468…99939324`),
/// `update.image.gz` 7.980, `miner.btm.tar.gz` 7.884.
///
/// Consequently **the L7's ASIC is not identified by stock bytes.** Every
/// "L7 = BM1489" claim in-tree traces to third-party VNish binaries
/// (`drivers/bm1489.rs:40` cites VNish `libbitmain aml/chip.c`), never to a
/// Bitmain image. `asic_id` stays `None`.
pub const L7_STOCK: ScryptStockTopology = ScryptStockTopology {
    model: "Antminer L7",
    machine_id: None,
    control_board: Some("Zynq-7000"),
    asic_id: None,
    chip_type: None,
    chain_count: None,
    chips_per_chain: None,
    asic_big_core_num: None,
    asic_little_core_num: None,
    core_little_core_num: None,
    asic_addr_interval: None,
    chain_domain_num: None,
    domain_asic_num: None,
    default_freq_mhz: None,
    default_asic_voltage_mv: None,
    rated_watts: None,
    psu_family: None,
    eeprom_i2c_addr: None,
    has_board_pic: None,
    evidence: "Antminer-L7-release-202301300939.bmu \
               (sha256 eccc9394baed32b268903f00c14105664320793a4130e5fda612f3bb8a21cac7); \
               BOOT.bin Xilinx 0x665599AA/XNLX + devicetree.dtb arm,cortex-a9 / \
               arm,pl353-nand-r2p1 / Linux-4.6.0-xilinx; \
               minerfs.image.gz + update.image.gz + miner.btm.tar.gz ENCRYPTED (H>7.88), key not held",
};

// ---------------------------------------------------------------------------
// L9 — FR-1.19(260302-L9).bmu, CVCtrl variant
// ---------------------------------------------------------------------------

/// Antminer L9 stock row, release `FR-1.19` (`260302`), **CVCtrl** variant.
///
/// The L9 `.bmu` is a container of two sub-BMUs:
/// - `00_Antminer_L9_CVCtrl_L9.bmu` — CVitek CV183x control board. Its
///   `BOOT.bin` is a plain **gzip'd SVR4 cpio** (magic `1f 8b 08 00`,
///   20,039,680 bytes inflated) — a complete plaintext rootfs. This row comes
///   from it.
/// - `01_Antminer_L9_AMLCtrl_BSL4160X.bmu` — Amlogic control board, a single
///   `ANDROID!` boot image whose kernel and ramdisk payloads are **encrypted**
///   (headers plaintext, contents Shannon 7.993, no gzip magic). Not usable.
///
/// Every field below is a literal from `etc/topol.conf`
/// (SHA-256 `f0ea6b60…14af5da0`) except the two operating-point fields, which
/// come from `etc/cgminer.conf.factory` (SHA-256 `8b758573…2ddb6c44`):
/// `"algo":"ltc_1491"`, `"bitmain-freq":"1225"`, `"bitmain-voltage":"1330"`.
///
/// `topol.conf` verbatim highlights:
/// ```text
/// "machine": "BSL41601",  "processor": {"type": "CV183x"},
/// "max_custom_power": 4200, "min_custom_power": 4200,
/// "power": {"type":"APW17", "i2c_addr":16, "gpio":412, "check_asic_voltage":1450},
/// "chain": { "chain_num":3, "chain_row":10, "chain_column":11,
///            "chain_domain_num":22, "chain_asic_num":110, "domain_asic_num":5,
///            "pic_mcu_en": false, "sensor_num": 2,
///   "asic": { "asic_id":"BM1491", "chip_type":"0x1491",
///             "asic_big_core_num":136, "asic_little_core_num":2048,
///             "core_little_core_num":16, "asic_domain_num":1,
///             "asic_addr_interval":2 },
///   "eeprom": { "type":"AT24C02D", "i2c_addr":80 } }
/// ```
///
/// Cross-checks inside the same image:
/// - `usr/bin/godminer` (SHA-256 `7b088dcb…3c038487`) ships a per-algorithm
///   backend tree; the L9's is `backend/backend_ltc_1491/`
///   (`backend_ltc_1491.c`, `chip_reg_io_ltc_1491.c`,
///   `chip_setting_ltc_1491.c`), and `ltc_1491` occurs 78× in `.rodata`.
/// - `pic_mcu_en: false` ⇒ NoPic, consistent with `godminer`'s PMIC drivers
///   being `isl68127.c` / `mps2973.c` rather than a hashboard PIC.
/// - `22 domains × 5 ASICs = 110 = chain_asic_num`, and
///   `chain_row 10 × chain_column 11 = 110`. Internally consistent.
///
/// **One vendor inconsistency is preserved, not reconciled:** the core
/// numbers do not multiply out. `asic_big_core_num 136 × core_little_core_num
/// 16 = 2176`, but `asic_little_core_num` is stated as `2048` (= 128 × 16).
/// On BM1368 the same three fields are consistent (80 × 16 = 1280), so this
/// is a real property of the L9 data — plausibly 136 physical vs 128 enabled
/// big cores, or a Bitmain slip. Both readings are transcribed verbatim and
/// pinned by
/// `negative_l9_core_numbers_do_not_multiply_out_and_must_not_be_reconciled`,
/// because core counts feed hashrate projection and editing either side would
/// fabricate one.
///
/// **Not** taken from this image: `etc/levels.json` ships 16 `BHB426xx`/
/// `BHB428xx` (S19-family) miner blocks and **zero** rows for `BSL41601`, so
/// it carries no L9 operating points. `godminer` is a unified multi-product
/// build; its other backends (`l11_1493`, `ks7_2384`, `x7_2044`, `x9_2046`,
/// `zec_1746`, `zec_1748`, `ini_2560`) are name-only evidence about other
/// machines and are not transcribed here.
pub const L9_BSL41601: ScryptStockTopology = ScryptStockTopology {
    model: "Antminer L9",
    machine_id: Some("BSL41601"),
    control_board: Some("CVitek CV183x"),
    asic_id: Some("BM1491"),
    chip_type: Some(0x1491),
    chain_count: Some(3),
    chips_per_chain: Some(110),
    asic_big_core_num: Some(136),
    asic_little_core_num: Some(2048),
    core_little_core_num: Some(16),
    asic_addr_interval: Some(2),
    chain_domain_num: Some(22),
    domain_asic_num: Some(5),
    default_freq_mhz: Some(1225),
    default_asic_voltage_mv: Some(1330),
    rated_watts: Some(4200),
    psu_family: Some("APW17"),
    eeprom_i2c_addr: Some(0x50),
    has_board_pic: Some(false),
    evidence: "FR-1.19(260302-L9).bmu \
               (sha256 2af05a3465ae8f3bdb32a74058f8beb0c4f9246da409441e09d922f05c3aa827) \
               -> 00_Antminer_L9_CVCtrl_L9.bmu -> BOOT.bin (gzip cpio) -> \
               etc/topol.conf (sha256 f0ea6b60c843ebf9f0ddffc74afb6e7848e8b1030006bf5561bfe5fe14af5da0) \
               + etc/cgminer.conf.factory algo=ltc_1491 freq=1225 voltage=1330",
};

/// All Scrypt stock rows recovered in Round 15, newest product last.
pub const SCRYPT_STOCK_TOPOLOGIES: [ScryptStockTopology; 3] = [L3PLUS_STOCK, L7_STOCK, L9_BSL41601];

/// Look up a Scrypt stock row by marketing model name.
pub fn stock_topology_for_model(model: &str) -> Option<&'static ScryptStockTopology> {
    SCRYPT_STOCK_TOPOLOGIES.iter().find(|t| t.model == model)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // POSITIVE — the L9 row must match etc/topol.conf byte-for-byte
    // -----------------------------------------------------------------

    #[test]
    fn l9_row_matches_stock_topol_conf_verbatim() {
        let l9 = L9_BSL41601;
        assert_eq!(l9.machine_id, Some("BSL41601"));
        assert_eq!(l9.control_board, Some("CVitek CV183x"));
        assert_eq!(l9.asic_id, Some("BM1491"));
        assert_eq!(l9.chip_type, Some(0x1491));
        assert_eq!(l9.chain_count, Some(3));
        assert_eq!(l9.chips_per_chain, Some(110));
        assert_eq!(l9.asic_big_core_num, Some(136));
        assert_eq!(l9.asic_little_core_num, Some(2048));
        assert_eq!(l9.core_little_core_num, Some(16));
        assert_eq!(l9.asic_addr_interval, Some(2));
        assert_eq!(l9.chain_domain_num, Some(22));
        assert_eq!(l9.domain_asic_num, Some(5));
        assert_eq!(l9.default_freq_mhz, Some(1225));
        assert_eq!(l9.default_asic_voltage_mv, Some(1330));
        assert_eq!(l9.rated_watts, Some(4200));
        assert_eq!(l9.psu_family, Some("APW17"));
        assert_eq!(l9.eeprom_i2c_addr, Some(0x50));
        assert_eq!(l9.has_board_pic, Some(false));
        assert_eq!(l9.total_chips(), Some(330));
    }

    #[test]
    fn l9_chain_geometry_is_internally_consistent() {
        let l9 = L9_BSL41601;
        // chain_domain_num * domain_asic_num == chain_asic_num
        assert_eq!(
            l9.chain_domain_num.unwrap() * l9.domain_asic_num.unwrap(),
            l9.chips_per_chain.unwrap(),
            "22 domains x 5 ASICs must equal chain_asic_num 110"
        );
        // chain_row * chain_column == chain_asic_num (10 x 11 = 110).
        assert_eq!(10 * 11, l9.chips_per_chain.unwrap());
    }

    /// The L9's own core numbers do **not** multiply out, and that is
    /// recorded rather than reconciled.
    ///
    /// `topol.conf` states `asic_big_core_num: 136`,
    /// `core_little_core_num: 16`, `asic_little_core_num: 2048`. But
    /// `136 × 16 = 2176`, not `2048` (`2048 = 128 × 16`). On BM1368 the same
    /// three fields *are* consistent (80 × 16 = 1280, root
    /// "1280 cores per BM1368 (80 big × 16 small)"), so the relationship is
    /// normally expected to hold and its failure here is a real property of
    /// the vendor data — plausibly 136 physical vs 128 enabled big cores, or
    /// a Bitmain transcription slip.
    ///
    /// This test pins the discrepancy so nobody "tidies" 136 → 128 (or
    /// 2048 → 2176) to make the arithmetic work. Whichever number is wrong,
    /// editing one to match the other would fabricate a core count, and core
    /// counts feed hashrate projection.
    #[test]
    fn negative_l9_core_numbers_do_not_multiply_out_and_must_not_be_reconciled() {
        let l9 = L9_BSL41601;
        let big = l9.asic_big_core_num.unwrap();
        let per_big = l9.core_little_core_num.unwrap();
        let little = l9.asic_little_core_num.unwrap();

        // Exactly the three values stock states — unedited.
        assert_eq!((big, per_big, little), (136, 16, 2048));

        // And they are genuinely inconsistent. If this ever starts passing
        // as "equal", someone has silently changed vendor data.
        assert_ne!(
            big * per_big,
            little,
            "136 x 16 = 2176 != 2048; the discrepancy is vendor-stated and \
             must be preserved, not reconciled"
        );
        assert_eq!(big * per_big, 2176);
    }

    #[test]
    fn l9_is_bm1491_and_never_bm1489() {
        // The whole point of the Round 15 correction. If someone
        // "harmonises" the L9 back onto BM1489, this fails.
        assert_eq!(L9_BSL41601.asic_id, Some("BM1491"));
        assert_ne!(L9_BSL41601.asic_id, Some("BM1489"));
        assert_eq!(L9_BSL41601.chip_type, Some(0x1491));
        assert_ne!(L9_BSL41601.chip_type, Some(0x1489));
    }

    #[test]
    fn l3plus_carries_only_what_stock_states() {
        assert_eq!(L3PLUS_STOCK.default_freq_mhz, Some(384));
        assert_eq!(L3PLUS_STOCK.chain_count, Some(4));
        assert_eq!(L3PLUS_STOCK.control_board, Some("AM335x BeagleBone"));
    }

    // -----------------------------------------------------------------
    // NEGATIVE — every datum this wave REFUSED must stay refused
    // -----------------------------------------------------------------

    #[test]
    fn negative_l3plus_chips_per_chain_is_refused() {
        // The stock L3+ image discovers chain length at runtime and never
        // states a chip count. `72` is from SCRYPT_ASIC_CHIPS.md, a
        // different artifact. Do NOT backfill it here.
        assert_eq!(L3PLUS_STOCK.chips_per_chain, None);
        assert_eq!(L3PLUS_STOCK.total_chips(), None);
        assert!(!L3PLUS_STOCK.geometry_complete());
    }

    #[test]
    fn negative_l3plus_asic_identity_and_cores_are_refused() {
        // BM1485 has no silicon-readable chip id (drivers/bm1485.rs:160-184)
        // and the stock config never names the part. Cores-per-chip (12)
        // is a cgminer-ltc source constant, not in this binary.
        assert_eq!(L3PLUS_STOCK.asic_id, None);
        assert_eq!(L3PLUS_STOCK.chip_type, None);
        assert_eq!(L3PLUS_STOCK.asic_big_core_num, None);
        assert_eq!(L3PLUS_STOCK.asic_little_core_num, None);
        assert_eq!(L3PLUS_STOCK.core_little_core_num, None);
    }

    #[test]
    fn negative_l3plus_voltage_is_refused() {
        // etc/cgminer.conf.factory has bitmain-freq but NO bitmain-voltage.
        // Nothing may energize silicon off an invented Scrypt voltage.
        assert_eq!(L3PLUS_STOCK.default_asic_voltage_mv, None);
        assert_eq!(L3PLUS_STOCK.rated_watts, None);
        assert_eq!(L3PLUS_STOCK.psu_family, None);
    }

    #[test]
    fn negative_l7_asic_identity_is_refused_rootfs_encrypted() {
        // The stock L7 rootfs is encrypted and no held key decrypts it.
        // "L7 = BM1489" rests on third-party VNish binaries only.
        assert_eq!(L7_STOCK.asic_id, None);
        assert_eq!(L7_STOCK.chip_type, None);
        assert_eq!(L7_STOCK.chain_count, None);
        assert_eq!(L7_STOCK.chips_per_chain, None);
        assert_eq!(L7_STOCK.default_freq_mhz, None);
        assert_eq!(L7_STOCK.default_asic_voltage_mv, None);
        assert!(!L7_STOCK.geometry_complete());
        // The one thing the plaintext boot chain DOES prove.
        assert_eq!(L7_STOCK.control_board, Some("Zynq-7000"));
    }

    #[test]
    fn negative_only_l9_has_complete_geometry() {
        let complete: Vec<&str> = SCRYPT_STOCK_TOPOLOGIES
            .iter()
            .filter(|t| t.geometry_complete())
            .map(|t| t.model)
            .collect();
        assert_eq!(complete, vec!["Antminer L9"]);
    }

    // -----------------------------------------------------------------
    // The BM1485 baud adjudication
    // -----------------------------------------------------------------

    #[test]
    fn l3plus_accepted_bauds_are_the_decoded_termios_ladder() {
        assert_eq!(
            L3PLUS_STOCK_ACCEPTED_BAUDS,
            [9_600, 19_200, 38_400, 57_600, 115_200, 230_400, 460_800, 921_600, 3_000_000]
        );
        for b in L3PLUS_STOCK_ACCEPTED_BAUDS {
            assert!(l3plus_stock_baud_supported(b), "{b} decoded but rejected");
        }
        assert!(l3plus_stock_baud_supported(L3PLUS_STOCK_DEFAULT_BAUD));
    }

    #[test]
    fn negative_both_disputed_bm1485_bauds_are_unreachable_on_stock() {
        // THE Round 15 result. 390_625 and 1_562_500 are absent from the
        // stock mapper's exhaustive compare chain at .text 0x3b698, so the
        // stock host UART cannot be set to either.
        for b in BM1485_REFUSED_OPERATIONAL_BAUDS {
            assert!(
                !l3plus_stock_baud_supported(b),
                "{b} must NOT be reachable on stock L3+"
            );
            assert!(!L3PLUS_STOCK_ACCEPTED_BAUDS.contains(&b));
        }
        assert_eq!(BM1485_REFUSED_OPERATIONAL_BAUDS, [390_625, 1_562_500]);
    }

    #[test]
    fn negative_disputed_bauds_are_not_integral_divisions_of_am335x_base() {
        // Independent of the decode: dcentrald-hal/src/serial.rs:1213-1214
        // pins AM335x base_baud = 48_000_000 / 16 = 3_000_000.
        const AM335X_BASE_BAUD: u32 = 3_000_000;
        assert_eq!(48_000_000u32 / 16, AM335X_BASE_BAUD);
        for b in BM1485_REFUSED_OPERATIONAL_BAUDS {
            assert_ne!(
                AM335X_BASE_BAUD % b,
                0,
                "{b} would be an integral AM335x divisor, which would weaken the refusal"
            );
        }
        // ...whereas the top accepted rate IS exactly the base rate.
        assert_eq!(AM335X_BASE_BAUD % 3_000_000, 0);
    }

    #[test]
    fn negative_disputed_bauds_are_exactly_zynq_fpga_divisors() {
        // Explains WHERE the two rival numbers came from: the Zynq chain
        // formula 200e6/(16*(div+1)) (root ), on a product that
        // has no FPGA at all.
        let zynq = |div: u32| 200_000_000 / (16 * (div + 1));
        assert_eq!(zynq(7), 1_562_500);
        assert_eq!(zynq(31), 390_625);
        // And the L3+ DTB proves AM335x kernel UARTs, not a Zynq FPGA.
        assert_eq!(L3PLUS_STOCK.control_board, Some("AM335x BeagleBone"));
    }

    #[test]
    fn baud_lookup_rejects_unknown_rates() {
        for b in [0, 1, 115_384, 115_740, 1_000_000, 3_125_000, u32::MAX] {
            assert!(!l3plus_stock_baud_supported(b), "{b} must be rejected");
        }
    }

    // -----------------------------------------------------------------
    // Table hygiene
    // -----------------------------------------------------------------

    #[test]
    fn every_row_carries_a_hash_bound_evidence_string() {
        for t in SCRYPT_STOCK_TOPOLOGIES {
            assert!(
                t.evidence.contains("sha256"),
                "{} evidence must name a hashed artifact",
                t.model
            );
            assert!(t.evidence.len() > 60, "{} evidence too thin", t.model);
        }
    }

    #[test]
    fn model_lookup_round_trips_and_rejects_unknown() {
        for t in SCRYPT_STOCK_TOPOLOGIES {
            assert_eq!(
                stock_topology_for_model(t.model).map(|r| r.model),
                Some(t.model)
            );
        }
        assert!(stock_topology_for_model("Antminer L11").is_none());
        assert!(stock_topology_for_model("").is_none());
    }
}
