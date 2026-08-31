//! Braiins Track-1 board# ↔ ttyS **discover** policy (T8). No hardcoded map.
//!
//! Live 2026-08-12: physical 2+3 present, physical 1 missing. Mining-on opened
//! only ttyS1 — that cannot separate wrong job shape from wrong slot.
//!
//! Descend-AML (ePIC / VNish comparative, **not a pin**):
//! physical 1→ttyS3, 2→ttyS2, 3→ttyS1. Implement discover, not that table.
//!
//! Policy: require ttyS1+ttyS2; discover ttyS3 (`a lab unit` dmesg 9600→115200 on
//! S1+S2+S3). Never ttyS0 (console). Do not hardcode board#→ttyS.

use crate::s19k_uart_trans_job::{
    admit_braiins_job_tx_path, BRAIINS_TTYS_BAUD, BRAIINS_TTYS_CANDIDATES, BRAIINS_TTYS_DISCOVER,
    BRAIINS_TTYS_THIRD,
};

/// Comparative-only descending hypothesis. **Do not bind** as SoT.
pub const DESCENDING_AML_HYPOTHESIS: &[(&str, &str)] = &[
    ("physical_1", "/dev/ttyS3"),
    ("physical_2", "/dev/ttyS2"),
    ("physical_3", "/dev/ttyS1"),
];

pub fn braiins_ttys_to_open() -> &'static [&'static str] {
    BRAIINS_TTYS_DISCOVER
}

/// Required pair. ttyS3 is discover/optional-open.
pub fn braiins_ttys_required() -> &'static [&'static str] {
    BRAIINS_TTYS_CANDIDATES
}

/// ttyS3 open failure is warn-not-fatal. S1+S2 are required.
pub fn s19k_port_open_is_optional(path: &str) -> bool {
    path == BRAIINS_TTYS_THIRD
}

pub fn refuse_hardcoded_physical_to_tty(
    path: &str,
    physical_address: u8,
) -> Result<(), &'static str> {
    for (label, hyp) in DESCENDING_AML_HYPOTHESIS {
        if *hyp == path && label.ends_with(&physical_address.to_string()) {
            return Err("T8: refuse hardcoded physical_address→ttyS; discover which port answers");
        }
    }
    // Still refuse inventing CHAIN/N = ttySN.
    if path == "/dev/ttyS1" && physical_address == 1 {
        return Err("T8: refuse naive CHAIN/1=ttyS1; discover, do not hardcode");
    }
    Err("T8: refuse hardcoded physical_address→ttyS map")
}

pub fn admit_discover_open_path(path: &str) -> Result<(), &'static str> {
    admit_braiins_job_tx_path(path)
}

/// Mining-on must include ttyS1+ttyS2. ttyS3 is the evidenced third hash UART.
/// Single-port dispatch cannot separate wrong job shape from wrong slot.
pub fn admit_braiins_mining_on_ports(paths: &[&str]) -> Result<(), &'static str> {
    if paths.contains(&"/dev/ttyS0") {
        return Err("T8: refuse ttyS0 (console)");
    }
    for required in BRAIINS_TTYS_CANDIDATES {
        if !paths.contains(required) {
            return Err(
                "T8: mining-on missing a Track-1 candidate; refuse single-port / omitted ttyS",
            );
        }
        admit_discover_open_path(required)?;
    }
    match paths.len() {
        2 => Ok(()),
        3 => {
            if !paths.contains(&BRAIINS_TTYS_THIRD) {
                return Err("T8: a 3-port plan must include /dev/ttyS3");
            }
            admit_discover_open_path(BRAIINS_TTYS_THIRD)?;
            Ok(())
        }
        _ => Err("T8: mining-on must open ttyS1+ttyS2 (ttyS3 optional third)"),
    }
}

/// Per-port RX after GetAddress / work. Overall ChipAnswered must not hide a silent twin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kPortRxMatrix {
    pub s1: S19kPortAnswer,
    pub s2: S19kPortAnswer,
    pub s3: S19kPortAnswer,
}

fn port_answered_1366(a: S19kPortAnswer) -> bool {
    matches!(
        a,
        S19kPortAnswer::ChipAddress {
            chip_id: 0x1366,
            count,
        } if count > 0
    ) || matches!(a, S19kPortAnswer::JobNonce { count } if count > 0)
}

fn port_answered(a: S19kPortAnswer) -> bool {
    port_answered_1366(a)
}

/// How many of the required pair (ttyS1, ttyS2) returned ChipAddress or a nonce.
pub fn s19k_required_ports_answered(m: S19kPortRxMatrix) -> usize {
    usize::from(port_answered(m.s1)) + usize::from(port_answered(m.s2))
}

/// One required UART answering is not 2-board / dual-chain proof.
pub fn refuse_one_required_port_as_dual_chain_proof(
    m: S19kPortRxMatrix,
) -> Result<(), &'static str> {
    if s19k_required_ports_answered(m) == 1 {
        return Err("one of ttyS1/ttyS2 answered; not dual-chain or 2-board proof");
    }
    Ok(())
}

/// : zero required answers is not dual-chain proof (includes S3-only).
pub fn refuse_zero_required_ports_as_dual_chain_proof(
    m: S19kPortRxMatrix,
) -> Result<(), &'static str> {
    if s19k_required_ports_answered(m) == 0 {
        return Err("neither ttyS1 nor ttyS2 answered; not dual-chain or 2-board proof");
    }
    Ok(())
}

/// ttyS3 ChipAddress/JobNonce is discover, not the required pair.
pub fn refuse_s3_only_as_required_pair_proof(m: S19kPortRxMatrix) -> Result<(), &'static str> {
    if s19k_required_ports_answered(m) == 0 && port_answered_1366(m.s3) {
        return Err("ttyS3-only ChipAddress/JobNonce is discover, not required-pair proof");
    }
    Ok(())
}

pub fn format_s19k_port_rx_matrix(m: S19kPortRxMatrix) -> String {
    fn tag(a: S19kPortAnswer) -> &'static str {
        match a {
            S19kPortAnswer::Silence => "silence",
            S19kPortAnswer::ChipAddress { .. } => "chip",
            S19kPortAnswer::JobNonce { .. } => "nonce",
            S19kPortAnswer::FramingOrEcho => "echo",
        }
    }
    format!(
        "S19K_PORT_RX ttyS1={} ttyS2={} ttyS3={} required_answered={}",
        tag(m.s1),
        tag(m.s2),
        tag(m.s3),
        s19k_required_ports_answered(m)
    )
}

/// Parse a hexdump (`aa 55 …` or `aa55…`). Odd nibble / non-hex → error.
pub fn parse_uart_hex_bytes(hex: &str) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    let mut nibble: Option<u8> = None;
    for c in hex.chars() {
        if c.is_ascii_whitespace() || c == '-' {
            continue;
        }
        let Some(d) = c.to_digit(16) else {
            return Err("non-hex in UART dump");
        };
        match nibble {
            None => nibble = Some(d as u8),
            Some(hi) => {
                out.push((hi << 4) | d as u8);
                nibble = None;
            }
        }
    }
    if nibble.is_some() {
        return Err("odd nibble count");
    }
    Ok(out)
}

/// Classify one port's hex dump. Empty / `-` is silence, not a parser error.
pub fn classify_port_rx_hex(hex: &str) -> S19kPortAnswer {
    let t = hex.trim();
    if t.is_empty() || t == "-" {
        return S19kPortAnswer::Silence;
    }
    match parse_uart_hex_bytes(t) {
        Ok(bytes) => classify_port_rx_bytes(&bytes),
        Err(_) => S19kPortAnswer::FramingOrEcho,
    }
}

/// Held `a lab unit` `cap_serial/ttyS*.rx.bin` (bosminer init capture).
/// S1/S2 are empty files. S3 is 3 bytes `00 00 AA` — not `AA 55`.
pub const HELD_78_CAP_SERIAL_S1: &[u8] = &[];
pub const HELD_78_CAP_SERIAL_S2: &[u8] = &[];
pub const HELD_78_CAP_SERIAL_S3: &[u8] = &[0x00, 0x00, 0xAA];

/// Empty vs 3-byte noise vs 11-byte `AA 55`. This capture is not a nonce golden.
pub fn refuse_held_78_cap_serial_as_bm1366_golden() -> Result<(), &'static str> {
    use crate::s19k_bm1366_uart_rx::{observe_bm1366_uart_rx, S19kUartRxObservation};
    if classify_port_rx_bytes(HELD_78_CAP_SERIAL_S1) != S19kPortAnswer::Silence {
        return Ok(());
    }
    if classify_port_rx_bytes(HELD_78_CAP_SERIAL_S2) != S19kPortAnswer::Silence {
        return Ok(());
    }
    match observe_bm1366_uart_rx(HELD_78_CAP_SERIAL_S3, 0) {
        S19kUartRxObservation::NoPreamble { nbytes: 3, .. } => {}
        _ => return Ok(()),
    }
    match classify_port_rx_bytes(HELD_78_CAP_SERIAL_S3) {
        S19kPortAnswer::ChipAddress { .. } | S19kPortAnswer::JobNonce { .. } => Ok(()),
        S19kPortAnswer::Silence => Err("S3 00 00 AA is noise, not empty silence"),
        S19kPortAnswer::FramingOrEcho => {
            Err("held .78 cap_serial is silence + 3-byte noise; not a BM1366 golden RX")
        }
    }
}

pub fn classify_port_rx_bytes(bytes: &[u8]) -> S19kPortAnswer {
    if bytes.is_empty() {
        return S19kPortAnswer::Silence;
    }
    let mut i = 0usize;
    let mut chip = 0usize;
    let mut nonce = 0usize;
    let mut chip_id = 0u16;
    while i + 11 <= bytes.len() {
        if bytes[i] == 0xAA && bytes[i + 1] == 0x55 {
            if let Ok(kind) =
                crate::s19k_bm1366_uart_rx::classify_bm1366_uart_rx_checked(&bytes[i..i + 11])
            {
                match kind {
                    crate::s19k_bm1366_uart_rx::S19kUartRxKind::ChipAddress {
                        chip_id: id, ..
                    } => {
                        chip = chip.saturating_add(1);
                        chip_id = id;
                    }
                    crate::s19k_bm1366_uart_rx::S19kUartRxKind::CommandReply { .. } => {
                        // Ticket 0x14 / HCN 0x10 / other register echoes are
                        // not GetAddress enum. GetAddress 0x1366 already
                        // surfaces as ChipAddress.
                    }
                    crate::s19k_bm1366_uart_rx::S19kUartRxKind::JobNonce { .. } => {
                        nonce = nonce.saturating_add(1);
                    }
                }
                i = i.saturating_add(11);
                continue;
            }
        }
        i = i.saturating_add(1);
    }
    if nonce > 0 {
        return S19kPortAnswer::JobNonce { count: nonce };
    }
    if chip > 0 {
        return S19kPortAnswer::ChipAddress {
            chip_id,
            count: chip,
        };
    }
    S19kPortAnswer::FramingOrEcho
}

pub fn port_rx_matrix_from_hex(s1: &str, s2: &str, s3: &str) -> S19kPortRxMatrix {
    S19kPortRxMatrix {
        s1: classify_port_rx_hex(s1),
        s2: classify_port_rx_hex(s2),
        s3: classify_port_rx_hex(s3),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kPortAnswer {
    Silence,
    ChipAddress { chip_id: u16, count: usize },
    JobNonce { count: usize },
    FramingOrEcho,
}

/// Bind physical_address **only** from which port answered. Never from
/// DESCENDING_AML_HYPOTHESIS. ChipAddress proves the **port** answered;
/// chassis slot stays unbound until a unique plug/EEPROM tag exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kPortBind {
    Unbound,
    AnsweredGetAddress { chip_id: u16, count: usize },
}

pub fn bind_port_after_rx(
    path: &str,
    answer: S19kPortAnswer,
) -> Result<S19kPortBind, &'static str> {
    admit_discover_open_path(path)?;
    match answer {
        S19kPortAnswer::ChipAddress { chip_id, count } if chip_id == 0x1366 && count > 0 => {
            Ok(S19kPortBind::AnsweredGetAddress { chip_id, count })
        }
        _ => Ok(S19kPortBind::Unbound),
    }
}

pub fn bind_physical_by_answer(
    path: &str,
    answer: S19kPortAnswer,
) -> Result<Option<u8>, &'static str> {
    // Never invent physical_address from RX count or the descending table.
    let _ = bind_port_after_rx(path, answer)?;
    Ok(None)
}

/// Held `a lab unit` chassis identity. Unique EEPROM serial ↔ I²C ↔ `physical_address`.
/// None of these rows name a tty. Source: `bosminer_model.json` + `hb{0,1,2}.parsed.json`
/// (`i2c-1` `0x50+idx` via `dump_and_parse.sh`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kChassisIdentity {
    pub physical: u8,
    pub i2c: u8,
    pub serial: &'static str,
}

pub const HELD_78_CHASSIS: &[S19kChassisIdentity] = &[
    S19kChassisIdentity {
        physical: 1,
        i2c: 0x50,
        serial: "JYZZYR6BCJHCA0JRG",
    },
    S19kChassisIdentity {
        physical: 2,
        i2c: 0x51,
        serial: "JYZZYR6BCJHCA0KRG",
    },
    S19kChassisIdentity {
        physical: 3,
        i2c: 0x52,
        serial: "JYZZYR6BCJHCA0HNX",
    },
];

pub fn bind_s19k_chassis_from_eeprom_serial(serial: &str) -> Option<u8> {
    HELD_78_CHASSIS
        .iter()
        .find(|row| row.serial == serial)
        .map(|row| row.physical)
}

pub fn bind_s19k_chassis_from_i2c(i2c: u8) -> Option<u8> {
    HELD_78_CHASSIS
        .iter()
        .find(|row| row.i2c == i2c)
        .map(|row| row.physical)
}

pub fn admit_s19k_78_chassis_rows_unique() -> Result<(), &'static str> {
    if HELD_78_CHASSIS.len() != 3 {
        return Err(".78 chassis fixture must name three seated BHB56902 boards");
    }
    for (i, a) in HELD_78_CHASSIS.iter().enumerate() {
        if a.physical == 0 || a.physical > 3 {
            return Err(".78 physical_address is 1..=3");
        }
        if a.i2c != 0x50 + (a.physical - 1) {
            return Err(".78 dump_and_parse.sh uses i2c 0x50+chain_idx for hb0..hb2");
        }
        if a.serial.len() != 17 {
            return Err(".78 BHB56902 serial is 17 ASCII chars");
        }
        for b in HELD_78_CHASSIS.iter().skip(i + 1) {
            if a.serial == b.serial {
                return Err(".78 EEPROM serials must be unique");
            }
            if a.i2c == b.i2c {
                return Err(".78 EEPROM I2C addresses must be unique");
            }
            if a.physical == b.physical {
                return Err(".78 physical_address values must be unique");
            }
        }
    }
    Ok(())
}

/// How a caller claims a board#↔tty bind. Only ASIC-EEPROM-on-UART is admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kBoardTtyEvidenceKind {
    /// EEPROM serial read through the hash UART (ASIC I²C). Unique serial names
    /// the chassis slot; the named tty is the observation.
    AsicEepromSerialOnTty,
    DescendingAml,
    NaiveChainN,
    PlugCount,
    RxCount,
    PlugGpio,
    S19jXilinxTransfer,
    Live106IrqCorrelation,
    PopulationHint,
    /// Host `i2c-1` AT24 at 0x50/0x51/0x52. Names chassis only.
    HostI2cChassis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kBoardTtyEvidence {
    pub kind: S19kBoardTtyEvidenceKind,
    pub path: &'static str,
    pub serial: Option<&'static str>,
    pub physical_claim: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kBoardTtyBind {
    Unbound,
    Bound {
        physical: u8,
        path: &'static str,
        serial: &'static str,
    },
}

/// Bind chassis slot to a tty **only** from a unique `a lab unit` serial observed on
/// an admitted hash UART. Descending AML, CHAIN/N=ttySN, plug-count, RX-count,
/// plug GPIO, S19j Xilinx maps, and `a lab unit` IRQ correlation are refused.
pub fn bind_s19k_board_tty(ev: S19kBoardTtyEvidence) -> Result<S19kBoardTtyBind, &'static str> {
    match ev.kind {
        S19kBoardTtyEvidenceKind::DescendingAml => {
            Err("T8: refuse descending AML physical_1→ttyS3 as board#↔tty bind")
        }
        S19kBoardTtyEvidenceKind::NaiveChainN => {
            Err("T8: refuse naive CHAIN/N=ttySN as board#↔tty bind")
        }
        S19kBoardTtyEvidenceKind::PlugCount => Err("T8: plug count does not name a tty"),
        S19kBoardTtyEvidenceKind::RxCount => Err("T8: RX count does not name a chassis slot"),
        S19kBoardTtyEvidenceKind::PlugGpio => {
            Err("T8: plug GPIO does not bind board#↔tty (.78 three plugs + two Braiins UARTs)")
        }
        S19kBoardTtyEvidenceKind::S19jXilinxTransfer => {
            Err("T8: refuse S19j Xilinx FPGA tty map as S19k Amlogic board#↔tty")
        }
        S19kBoardTtyEvidenceKind::Live106IrqCorrelation => {
            Err("T8: .106 idle ttyS2 + empty slot 2 does not prove ttyS1=physical_1")
        }
        S19kBoardTtyEvidenceKind::PopulationHint => {
            Err("T8: bosminer population hint is not a tty map")
        }
        S19kBoardTtyEvidenceKind::HostI2cChassis => {
            Err("T8: host i2c-1 AT24 names chassis slot, not a tty")
        }
        S19kBoardTtyEvidenceKind::AsicEepromSerialOnTty => {
            admit_discover_open_path(ev.path)?;
            let Some(serial) = ev.serial else {
                return Err("T8: ASIC-EEPROM-on-UART bind needs the unique serial");
            };
            let Some(physical) = bind_s19k_chassis_from_eeprom_serial(serial) else {
                return Err("T8: serial is not a unique held .78 chassis identity");
            };
            if let Some(claim) = ev.physical_claim {
                if claim != physical {
                    return Err("T8: physical_claim contradicts held .78 serial");
                }
            }
            Ok(S19kBoardTtyBind::Bound {
                physical,
                path: ev.path,
                serial,
            })
        }
    }
}

pub fn refuse_s19k_held_corpus_as_serial_tty_map() -> Result<(), &'static str> {
    admit_s19k_78_chassis_rows_unique()?;
    Err("held .78 chassis rows name serial/I2C/physical; no serial↔tty column")
}

pub fn refuse_s19k_106_irq_as_physical_1_ttys1() -> Result<(), &'static str> {
    let ev = S19kBoardTtyEvidence {
        kind: S19kBoardTtyEvidenceKind::Live106IrqCorrelation,
        path: "/dev/ttyS1",
        serial: None,
        physical_claim: Some(1),
    };
    match bind_s19k_board_tty(ev) {
        Err(_) => Err("T8: .106 IRQ correlation is not physical_1→ttyS1"),
        Ok(_) => Ok(()),
    }
}

pub fn refuse_s19k_xilinx_s19j_as_aml_tty_map() -> Result<(), &'static str> {
    let ev = S19kBoardTtyEvidence {
        kind: S19kBoardTtyEvidenceKind::S19jXilinxTransfer,
        path: "/dev/ttyS3",
        serial: None,
        physical_claim: Some(3),
    };
    match bind_s19k_board_tty(ev) {
        Err(_) => Err("T8: S19j Xilinx tty map is not S19k Amlogic"),
        Ok(_) => Ok(()),
    }
}

/// Fill per-port chassis slots from unique serial-on-tty evidence.
/// `physical_bound` is Some only when exactly one port is bound.
pub fn observe_s19k_board_tty_discover(
    s1: S19kPortAnswer,
    s2: S19kPortAnswer,
    s3: S19kPortAnswer,
    evidence: &[S19kBoardTtyEvidence],
) -> S19kTopologyObserve {
    let mut obs = observe_s19k_triple_port_topology(s1, s2, s3);
    for ev in evidence {
        let Ok(S19kBoardTtyBind::Bound { physical, path, .. }) = bind_s19k_board_tty(*ev) else {
            continue;
        };
        let slot = match path {
            "/dev/ttyS1" => &mut obs.board_on_s1,
            "/dev/ttyS2" => &mut obs.board_on_s2,
            "/dev/ttyS3" => &mut obs.board_on_s3,
            _ => continue,
        };
        if slot.is_some() && *slot != Some(physical) {
            *slot = None;
            continue;
        }
        *slot = Some(physical);
    }
    let mut n = 0u8;
    let mut only = None;
    for b in [obs.board_on_s1, obs.board_on_s2, obs.board_on_s3] {
        if let Some(p) = b {
            n = n.saturating_add(1);
            only = Some(p);
        }
    }
    obs.physical_bound = if n == 1 { only } else { None };
    obs
}

/// Operator env sibling of `DCENT_S19K_I2CDETECT`. File is a named-tty
/// hex/ASCII capture, not host `i2cdetect` / `eeprom-parse`.
pub const ENV_S19K_UART_EEPROM: &str = "DCENT_S19K_UART_EEPROM";

/// Constructed UART-EEPROM capture: hex of `JYZZYR6BCJHCA0JRG` on ttyS2.
/// Not a live ASIC-I²C sniff. Host i2cdetect / `|S/N` tables are refused.
pub const S19K_UART_EEPROM_TTYS2_JRG_FIXTURE: &str = "\
# ASIC I2C serial observed on a hash UART (not host i2c-1)
path=/dev/ttyS2
hex=4a595a5a59523642434a484341304a5247
";

fn intern_s19k_hash_uart_path(path: &str) -> Option<&'static str> {
    match path {
        "/dev/ttyS1" => Some("/dev/ttyS1"),
        "/dev/ttyS2" => Some("/dev/ttyS2"),
        "/dev/ttyS3" => Some("/dev/ttyS3"),
        _ => None,
    }
}

fn intern_held_78_serial(serial: &str) -> Option<&'static str> {
    HELD_78_CHASSIS
        .iter()
        .find(|row| row.serial == serial)
        .map(|row| row.serial)
}

fn decode_hex_bytes(text: &str) -> Option<Vec<u8>> {
    let hex: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() < 2 || hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = char::from(bytes[i]).to_digit(16)?;
        let lo = char::from(bytes[i + 1]).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

fn serial_from_uart_eeprom_bytes(bytes: &[u8]) -> Option<&'static str> {
    for row in HELD_78_CHASSIS {
        if bytes.windows(17).any(|w| w == row.serial.as_bytes()) {
            return Some(row.serial);
        }
    }
    None
}

fn looks_like_host_i2cdetect_grid(text: &str) -> bool {
    text.contains("i2cdetect")
        || text.lines().any(|line| {
            let t = line.trim();
            t.starts_with("50:") && (t.contains("50") || t.contains("--"))
        })
}

/// Host i2cdetect / bosminer eeprom-parse is not ASIC-EEPROM-on-UART.
pub fn refuse_s19k_host_i2c_file_as_uart_eeprom(text: &str) -> Result<(), &'static str> {
    if looks_like_host_i2cdetect_grid(text) {
        return Err("host i2cdetect is not UART-EEPROM serial-on-tty");
    }
    if text.contains("|S/N") || text.contains("\"serial_number\"") {
        return Err("bosminer eeprom-parse is host chassis, not UART-EEPROM on tty");
    }
    if text.contains("i2c-1") && !text.contains("path=/dev/ttyS") {
        return Err("host i2c-1 is not a hash UART");
    }
    Ok(())
}

fn push_uart_eeprom_record(
    out: &mut Vec<S19kBoardTtyEvidence>,
    path: Option<&'static str>,
    serial: Option<&'static str>,
) -> Result<(), &'static str> {
    let (Some(path), Some(serial)) = (path, serial) else {
        return Ok(());
    };
    out.push(S19kBoardTtyEvidence {
        kind: S19kBoardTtyEvidenceKind::AsicEepromSerialOnTty,
        path,
        serial: Some(serial),
        physical_claim: None,
    });
    Ok(())
}

/// Parse a named-tty hex/ASCII capture into bind-API evidence.
/// Serials intern to held `a lab unit` rows; unknown 17-char strings do not bind.
pub fn parse_s19k_uart_eeprom_named_tty(
    text: &str,
) -> Result<Vec<S19kBoardTtyEvidence>, &'static str> {
    refuse_s19k_host_i2c_file_as_uart_eeprom(text)?;
    let mut out = Vec::new();
    let mut path = None;
    let mut serial = None;
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some(rest) = t.strip_prefix("path=") {
            push_uart_eeprom_record(&mut out, path, serial)?;
            path = intern_s19k_hash_uart_path(rest.trim());
            serial = None;
            if path.is_none() {
                return Err("UART-EEPROM path must be ttyS1/ttyS2/ttyS3");
            }
            continue;
        }
        if let Some(rest) = t.strip_prefix("serial=") {
            serial = intern_held_78_serial(rest.trim());
            if serial.is_none() {
                return Err("UART-EEPROM serial is not a unique held .78 chassis identity");
            }
            continue;
        }
        if let Some(rest) = t.strip_prefix("hex=") {
            let bytes = decode_hex_bytes(rest).ok_or("UART-EEPROM hex is not 17 ASCII bytes")?;
            serial = serial_from_uart_eeprom_bytes(&bytes);
            if serial.is_none() {
                return Err("UART-EEPROM hex is not a unique held .78 chassis identity");
            }
            continue;
        }
        if t.starts_with("/dev/ttyS") {
            push_uart_eeprom_record(&mut out, path, serial)?;
            let mut parts = t.split_whitespace();
            let Some(p) = parts.next() else {
                continue;
            };
            path = intern_s19k_hash_uart_path(p);
            if path.is_none() {
                return Err("UART-EEPROM path must be ttyS1/ttyS2/ttyS3");
            }
            serial = None;
            if let Some(rest) = parts.next() {
                if rest.len() == 17 {
                    serial = intern_held_78_serial(rest);
                } else if let Some(bytes) = decode_hex_bytes(rest) {
                    serial = serial_from_uart_eeprom_bytes(&bytes);
                }
                if serial.is_none() {
                    return Err("UART-EEPROM one-liner serial is not a held .78 identity");
                }
            }
            continue;
        }
        if path.is_some() && serial.is_none() {
            if let Some(bytes) = decode_hex_bytes(t) {
                if bytes.len() >= 17 {
                    serial = serial_from_uart_eeprom_bytes(&bytes);
                    if serial.is_none() {
                        return Err("UART-EEPROM hex line is not a held .78 identity");
                    }
                    continue;
                }
            }
        }
        return Err("UART-EEPROM fixture line is not path=/ serial=/ hex=");
    }
    push_uart_eeprom_record(&mut out, path, serial)?;
    if out.is_empty() {
        return Err("UART-EEPROM fixture has no named-tty serial records");
    }
    Ok(out)
}

/// Production must parse `DCENT_S19K_UART_EEPROM` into the bind API.
pub fn admit_s19k_production_uses_uart_eeprom_fixture(src: &str) -> Result<(), &'static str> {
    if !src.contains("DCENT_S19K_UART_EEPROM") {
        return Err("production must read DCENT_S19K_UART_EEPROM");
    }
    if !src.contains("parse_s19k_uart_eeprom_named_tty") {
        return Err("production must parse the named-tty hex fixture");
    }
    if !src.contains("observe_s19k_board_tty_discover") {
        return Err("parsed evidence must feed observe_s19k_board_tty_discover");
    }
    Ok(())
}

/// `a lab unit` `cap_init/i2cdetect.before` bus 1: TMP75 0x48-0x4A/0x4C-0x4E + AT24 0x50-0x52.
pub const S19K_78_I2CDETECT_FIXTURE: &str = "\
     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
00:          -- -- -- -- -- -- -- -- -- -- -- -- -- 
10: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- 
20: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- 
30: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- 
40: -- -- -- -- -- -- -- -- 48 49 4a -- 4c 4d 4e -- 
50: 50 51 52 -- -- -- -- -- -- -- -- -- -- -- -- -- 
60: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- 
70: -- -- -- -- -- -- -- --                         
";

/// Which of I²C 0x50/0x51/0x52 ACK on a host `i2cdetect` grid. Not a tty map.
pub fn parse_s19k_i2cdetect_at24(grid: &str) -> [bool; 3] {
    let mut present = [false; 3];
    for line in grid.lines() {
        let line = line.trim();
        let Some((left, right)) = line.split_once(':') else {
            continue;
        };
        let Ok(row) = u8::from_str_radix(left.trim(), 16) else {
            continue;
        };
        if row != 0x50 {
            continue;
        }
        for (i, tok) in right.split_whitespace().enumerate() {
            let addr = match row.checked_add(i as u8) {
                Some(a) => a,
                None => continue,
            };
            if (0x50..=0x52).contains(&addr) {
                present[(addr - 0x50) as usize] = tok != "--";
            }
        }
    }
    present
}

/// Bosminer `eeprom-parse` / platform table `|S/N |SERIAL|` plus JSON `"serial_number"`.
pub fn parse_s19k_bosminer_eeprom_serials(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("|S/N") {
            if let Some(serial) = rest.split('|').nth(1) {
                let s = serial.trim();
                if s.len() == 17 && !out.iter().any(|have| have == s) {
                    out.push(s.to_string());
                }
            }
            continue;
        }
        if let Some(idx) = t.find("\"serial_number\"") {
            let after = &t[idx..];
            if let Some(q1) = after.find(':') {
                let rest = after[q1 + 1..].trim();
                if let Some(stripped) = rest.strip_prefix('"') {
                    if let Some(end) = stripped.find('"') {
                        let s = &stripped[..end];
                        if s.len() == 17 && !out.iter().any(|have| have == s) {
                            out.push(s.to_string());
                        }
                    }
                }
            }
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kHostI2cChassis {
    pub at24_present: [bool; 3],
    pub serials: Vec<String>,
    pub physicals: Vec<u8>,
}

/// Host `i2c-1` AT24 + bosminer parse → chassis slots. `tty` stays unbound.
pub fn observe_s19k_host_i2c_chassis(i2cdetect: &str, eeprom_parse: &str) -> S19kHostI2cChassis {
    let at24_present = parse_s19k_i2cdetect_at24(i2cdetect);
    let serials = parse_s19k_bosminer_eeprom_serials(eeprom_parse);
    let physicals = serials
        .iter()
        .filter_map(|s| bind_s19k_chassis_from_eeprom_serial(s))
        .collect();
    S19kHostI2cChassis {
        at24_present,
        serials,
        physicals,
    }
}

pub fn format_s19k_host_i2c_chassis(obs: &S19kHostI2cChassis) -> String {
    let i2c: Vec<String> = (0..3)
        .filter(|&i| obs.at24_present[i])
        .map(|i| format!("0x{:02X}", 0x50 + i))
        .collect();
    let phys: Vec<String> = obs.physicals.iter().map(|p| p.to_string()).collect();
    format!(
        "S19K_HOST_I2C chassis={} i2c={} serial={} tty=unbound",
        phys.join(","),
        i2c.join(","),
        obs.serials.join(","),
    )
}

/// Bench script is read-only host I²C. Never i2cset, never tty bind.
pub fn admit_s19k_host_i2c_chassis_script(script: &str) -> Result<(), &'static str> {
    if script.contains("i2cset")
        && !script.contains("Never i2cset")
        && !script.contains("i2cset=false")
    {
        return Err("host i2c chassis script must not call i2cset");
    }
    if script.contains("i2cset -y") || script.contains("i2cset -f") {
        return Err("host i2c chassis script must not invoke i2cset");
    }
    if !script.contains("i2cset=false") {
        return Err("host i2c chassis script must emit i2cset=false");
    }
    if !script.contains("tty=unbound") {
        return Err("host i2c chassis script must keep tty unbound");
    }
    if !script.contains("S19K_HOST_I2C") {
        return Err("host i2c chassis script must emit S19K_HOST_I2C");
    }
    if !script.contains("DCENT_S19K_HOST_I2C_LIVE=1") {
        return Err("live i2cdetect must be opt-in");
    }
    if script.contains("physical_1") && script.contains("ttyS3") && script.contains("bind") {
        return Err("script must not hardcode descending AML");
    }
    Ok(())
}

pub fn refuse_s19k_host_i2c_as_tty_bind() -> Result<(), &'static str> {
    match bind_s19k_board_tty(S19kBoardTtyEvidence {
        kind: S19kBoardTtyEvidenceKind::HostI2cChassis,
        path: "/dev/ttyS1",
        serial: Some("JYZZYR6BCJHCA0JRG"),
        physical_claim: Some(1),
    }) {
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }
}

/// Evidence that may lift the ttyS3 hold (empty slot 1 on the 2026-08-12 unit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct S19kTtys3Evidence {
    pub plug439_present: bool,
    pub eeprom_0x50_admitted: bool,
    pub irq14_ticking: bool,
    pub getaddress_rx: bool,
}

impl S19kTtys3Evidence {
    /// Plug 439 present does **not** lift ttyS3. `a lab unit` 2025-12-04 logged
    /// three BHB56902 boards (`Address(1..3)`) and g439=g440=g441=1 while
    /// Braiins still used only ttyS1+ttyS2. Lifting on plug439 is the
    /// descending AML hardcode this module refuses.
    pub fn lifts_hold(self) -> bool {
        self.getaddress_rx
    }
}

/// Map a GetAddress RX observation to a port answer. Silence is not a
/// parser error; ChipAddress proves the **port** answered.
pub fn s19k_port_answer_from_rx(
    obs: &crate::s19k_bm1366_uart_rx::S19kUartRxObservation,
) -> S19kPortAnswer {
    use crate::s19k_bm1366_uart_rx::{S19kUartRxKind, S19kUartRxObservation};
    match obs {
        S19kUartRxObservation::Silence { .. } => S19kPortAnswer::Silence,
        S19kUartRxObservation::NoPreamble { .. }
        | S19kUartRxObservation::HostPreambleEcho { .. }
        | S19kUartRxObservation::ShortFrame { .. } => S19kPortAnswer::FramingOrEcho,
        S19kUartRxObservation::Frames { frames, .. } => {
            let mut chip = 0usize;
            let mut nonce = 0usize;
            let mut chip_id = 0u16;
            for frame in frames {
                match *frame {
                    S19kUartRxKind::ChipAddress { chip_id: id, .. } => {
                        chip = chip.saturating_add(1);
                        chip_id = id;
                    }
                    S19kUartRxKind::CommandReply { .. } => {
                        // Rearm ticket/HCN is FramingOrEcho at the port SSOT.
                    }
                    S19kUartRxKind::JobNonce { .. } => nonce = nonce.saturating_add(1),
                }
            }
            if chip > 0 {
                S19kPortAnswer::ChipAddress {
                    chip_id,
                    count: chip,
                }
            } else if nonce > 0 {
                S19kPortAnswer::JobNonce { count: nonce }
            } else {
                S19kPortAnswer::FramingOrEcho
            }
        }
    }
}

/// Dual/triple-port observe report. Records which ttyS answered GetAddress.
/// Never fills `physical_bound` from the descending AML table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kTopologyObserve {
    pub tty_s1: S19kPortBind,
    pub tty_s2: S19kPortBind,
    pub tty_s3: S19kPortBind,
    pub tty_s3_held: bool,
    /// Set only when exactly one unique serial-on-tty bind exists.
    pub physical_bound: Option<u8>,
    /// Per-port chassis slots from unique serial-on-UART evidence. Not descending AML.
    pub board_on_s1: Option<u8>,
    pub board_on_s2: Option<u8>,
    pub board_on_s3: Option<u8>,
}

pub fn observe_s19k_triple_port_topology(
    s1: S19kPortAnswer,
    s2: S19kPortAnswer,
    s3: S19kPortAnswer,
) -> S19kTopologyObserve {
    let tty_s3 = bind_port_after_rx("/dev/ttyS3", s3).unwrap_or(S19kPortBind::Unbound);
    S19kTopologyObserve {
        tty_s1: bind_port_after_rx("/dev/ttyS1", s1).unwrap_or(S19kPortBind::Unbound),
        tty_s2: bind_port_after_rx("/dev/ttyS2", s2).unwrap_or(S19kPortBind::Unbound),
        tty_s3,
        tty_s3_held: !matches!(tty_s3, S19kPortBind::AnsweredGetAddress { .. }),
        physical_bound: None,
        board_on_s1: None,
        board_on_s2: None,
        board_on_s3: None,
    }
}

pub fn observe_s19k_dual_port_topology(
    s1: S19kPortAnswer,
    s2: S19kPortAnswer,
) -> S19kTopologyObserve {
    observe_s19k_triple_port_topology(s1, s2, S19kPortAnswer::Silence)
}

pub fn format_s19k_topology_observe(obs: &S19kTopologyObserve) -> String {
    fn bind(b: S19kPortBind) -> String {
        match b {
            S19kPortBind::Unbound => "unbound".into(),
            S19kPortBind::AnsweredGetAddress { chip_id, count } => {
                format!("answered chip_id=0x{chip_id:04X} count={count}")
            }
        }
    }
    fn board(b: Option<u8>) -> String {
        match b {
            None => "unbound".into(),
            Some(n) => n.to_string(),
        }
    }
    format!(
        "S19K_TOPO ttyS1={} ttyS2={} ttyS3={} physical={} boards=s1:{} s2:{} s3:{}",
        bind(obs.tty_s1),
        bind(obs.tty_s2),
        if obs.tty_s3_held { "held" } else { "admitted" },
        match obs.physical_bound {
            None => "unbound".into(),
            Some(n) => format!("{n}"),
        },
        board(obs.board_on_s1),
        board(obs.board_on_s2),
        board(obs.board_on_s3),
    )
}

pub fn admit_ttys3_open(evidence: S19kTtys3Evidence) -> Result<(), &'static str> {
    if evidence.lifts_hold() {
        Ok(())
    } else {
        Err("T8: ttyS3 held until GetAddress RX on that port; plugs do not lift")
    }
}

/// Live 2026-08-12 population: physical 2+3 present, 1 missing.
/// Discover still opens both ttyS; does not skip a candidate because a
/// bosminer JSON said a slot is empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kBosminerPopulationHint {
    pub physical_present: &'static [u8],
    pub physical_missing: &'static [u8],
}

pub const LIVE_20260812_POPULATION: S19kBosminerPopulationHint = S19kBosminerPopulationHint {
    physical_present: &[2, 3],
    physical_missing: &[1],
};

/// `a lab unit` 2025-12-04 `bosminer.log.before`: all three BHB56902 seated.
pub const LIVE_78_20251204_POPULATION: S19kBosminerPopulationHint = S19kBosminerPopulationHint {
    physical_present: &[1, 2, 3],
    physical_missing: &[],
};

/// Three plugs should include ttyS3 in the **plan**. Opening S3 may still
/// fail on a given image; S1+S2 remain required.
pub fn admit_s19k_plug_count_vs_uart_count(
    plug_present: usize,
    uart_paths: &[&str],
) -> Result<(), &'static str> {
    admit_braiins_mining_on_ports(uart_paths)?;
    if plug_present >= 3 && !uart_paths.contains(&BRAIINS_TTYS_THIRD) {
        return Err("T8: three plugs: discover plan must include ttyS3 (.78 dmesg wakes S1+S2+S3)");
    }
    Ok(())
}

pub fn discover_plan_paths() -> &'static [&'static str] {
    BRAIINS_TTYS_DISCOVER
}

/// Shipped mining-on open plan. A leftover `serial_device=/dev/ttyS2` is a
/// **hint**, never sufficient. Always admit both Track-1 candidates.
/// Refuse console ttyS0 in the configured string.
pub fn plan_s19k_braiins_mining_on_ports(
    configured_serial_device: Option<&str>,
) -> Result<&'static [&'static str], &'static str> {
    if let Some(raw) = configured_serial_device {
        for part in raw.split(',') {
            let path = part.trim();
            if path.is_empty() {
                continue;
            }
            if path == "/dev/ttyS0"
                || crate::s19k_uart_trans_job::BRAIINS_TTYS_FORBIDDEN.contains(&path)
            {
                return Err("T8: never /dev/ttyS0 on mining-on plan");
            }
        }
    }
    admit_braiins_mining_on_ports(BRAIINS_TTYS_DISCOVER)?;
    Ok(BRAIINS_TTYS_DISCOVER)
}

/// Work TX is required only on ttyS1+ttyS2. Discover/optional ttyS3 is RX-only
/// so a flaky Silent S3 cannot fail the required pair.
pub fn s19k_multi_send_work_tx_required(path: &str) -> bool {
    BRAIINS_TTYS_CANDIDATES.contains(&path)
}

/// Evidence-gated work plan for the third logical hash UART. ttyS1+ttyS2
/// remain the held required pair. ttyS3 joins TX only after that same port
/// produced complete, CRC-admitted 77-chip geometry; this does not assign a
/// physical slot number to the UART.
pub fn s19k_work_tx_required_after_enum(path: &str, enum_complete_77: bool) -> bool {
    s19k_multi_send_work_tx_required(path) || (path == BRAIINS_TTYS_THIRD && enum_complete_77)
}

/// A complete 77-chip enumeration is work-TX proof only when it was observed
/// at the admitted Braiins Track-1 host baud. A diagnostic 115200 retry may
/// explain a silent chain, but must never promote ttyS3 after the host is
/// restored to 3 Mbaud.
pub fn s19k_complete77_is_work_baud_proof(host_baud: u32, enum_complete_77: bool) -> bool {
    enum_complete_77 && host_baud == BRAIINS_TTYS_BAUD
}

/// A nonce may enter fill attribution only on a UART that received the work.
/// This replaces the old path-name-only ttyS3 refusal once a populated third
/// UART has been admitted dynamically.
pub fn admit_s19k_fill_hunt_on_tx_path(
    path: &str,
    work_tx_paths: &[&str],
) -> Result<(), &'static str> {
    if !work_tx_paths.contains(&path) {
        return Err("UART RX is observe-only because that path did not receive this work stream");
    }
    Ok(())
}

/// ttyS3 work TX is discover, not required-pair proof.
pub fn refuse_s3_tx_as_required_send_work(path: &str) -> Result<(), &'static str> {
    if path == BRAIINS_TTYS_THIRD || s19k_port_open_is_optional(path) {
        return Err("T8: ttyS3 is discover/RX-only; work TX is ttyS1+ttyS2");
    }
    Ok(())
}

/// ttyS3 RX may be observed, but must not bind S1+S2 outstanding fill work.
pub fn refuse_s3_rx_as_fill_hunt(path: &str) -> Result<(), &'static str> {
    if !s19k_multi_send_work_tx_required(path) {
        return Err(
            "discover/optional UART RX is observe-only; do not fill-hunt against S1+S2 outstanding",
        );
    }
    Ok(())
}

/// Production BM1366 nonce arm must refuse fill-hunt on discover/optional UARTs.
pub fn admit_s19k_production_fill_hunt_skips_discover(src: &str) -> Result<(), &'static str> {
    if !src.contains("admit_s19k_fill_hunt_on_tx_path") {
        return Err("production fill hunt must require evidence that the RX path received work");
    }
    if !src.contains("did not receive work") {
        return Err("production fill hunt must skip RX from paths outside the active TX plan");
    }
    Ok(())
}

/// Dual-port work TX: both required Track-1 backends must accept the frame.
/// `opened` may include discover ttyS3 (RX-only). `succeeded` counts required
/// ttyS1+ttyS2 TX. `ok == 2` of `opened == 3` is the required pair with
/// optional S3 present. `ok == 1` of `opened == 2` is the live 2026-08-12
/// single-tty regression.
pub fn admit_s19k_multi_send_work(succeeded: usize, opened: usize) -> Result<(), &'static str> {
    if opened < BRAIINS_TTYS_CANDIDATES.len() {
        return Err("T8: multi-tty send_work opened fewer than both Track-1 ports");
    }
    if succeeded < BRAIINS_TTYS_CANDIDATES.len() {
        return Err(
            "T8: multi-tty send_work must succeed on both required Track-1 ttyS; partial TX is a single-port regression",
        );
    }
    if succeeded > opened {
        return Err("T8: multi-tty send_work succeeded more than opened");
    }
    Ok(())
}

/// Production Multi send_work must skip discover/optional UARTs.
pub fn admit_s19k_production_multi_send_skips_discover(src: &str) -> Result<(), &'static str> {
    let start = src
        .find("impl SerialWorkTransport")
        .ok_or("missing SerialWorkTransport")?;
    let win = src.get(start..start.saturating_add(1800)).unwrap_or("");
    if !win.contains("s19k_multi_send_work_tx_required") {
        return Err("Multi send_work must isolate discover/optional UARTs from TX");
    }
    if !win.contains("admit_s19k_multi_send_work") {
        return Err("Multi send_work must still admit required-pair TX");
    }
    Ok(())
}

/// Round-robin start index so a busy ttyS1 cannot starve ttyS2 forever.
pub fn s19k_multi_rx_start(cursor: usize, opened: usize) -> Option<usize> {
    if opened == 0 {
        None
    } else {
        Some(cursor % opened)
    }
}

/// Visit every opened port from `start`. `drain_all=false` is first-hit
/// ( production). `drain_all=true` collects every ready sibling.
pub fn s19k_multi_rx_ready_indices(ready: &[bool], start: usize, drain_all: bool) -> Vec<usize> {
    let n = ready.len();
    if n == 0 {
        return Vec::new();
    }
    let start = start % n;
    let mut out = Vec::new();
    for i in 0..n {
        let idx = (start + i) % n;
        if ready[idx] {
            out.push(idx);
            if !drain_all {
                break;
            }
        }
    }
    out
}

/// First-hit Multi RX is not a dual-port drain. Live `.88` : ttyS1
/// went silent at T+21s while ttyS2 kept producing until T+61s.
pub fn refuse_s19k_first_hit_as_dual_port_drain(
    ready: &[bool],
    start: usize,
) -> Result<(), &'static str> {
    let first = s19k_multi_rx_ready_indices(ready, start, false);
    let all = s19k_multi_rx_ready_indices(ready, start, true);
    if first.len() < all.len() {
        return Err("first-hit Multi RX left a ready sibling unread");
    }
    Ok(())
}

/// Mining-on first WORK #1 timestamp from `live401/run.log`.
pub const S19K_LIVE401_MINING_ON_UTC: &str = "2026-08-15T23:14:32.465233Z";
/// Last `S19K_MULTI_RX` on ttyS1.
pub const S19K_LIVE401_S1_LAST_RX_UTC: &str = "2026-08-15T23:14:53.255582Z";
/// Last `S19K_MULTI_RX` on ttyS2. Actor kept TX after this (3541 work @ T+90).
pub const S19K_LIVE401_S2_LAST_RX_UTC: &str = "2026-08-15T23:15:33.406937Z";
pub const S19K_LIVE401_S1_LAST_RX_MS: u32 = 20_790;
pub const S19K_LIVE401_S2_LAST_RX_MS: u32 = 60_941;

pub fn admit_s19k_live401_stall_is_sequential_s1_then_s2() -> Result<(), &'static str> {
    if S19K_LIVE401_S1_LAST_RX_MS >= S19K_LIVE401_S2_LAST_RX_MS {
        return Err("live401 S1 last RX must precede S2 last RX");
    }
    if S19K_LIVE401_S2_LAST_RX_MS.saturating_sub(S19K_LIVE401_S1_LAST_RX_MS) < 30_000 {
        return Err("live401 S2 kept producing ≥30s after S1 went silent");
    }
    Ok(())
}

pub fn refuse_s19k_live401_stall_as_simultaneous_dual_death() -> Result<(), &'static str> {
    Err("live401 ttyS1 died ~T+21s; ttyS2 died ~T+61s; work TX continued — not one dual-port crash")
}

/// live403 ( binary): first WORK 01:16:34.709; S1 last MULTI_RX 01:17:15.223.
pub const S19K_LIVE403_S1_LAST_RX_MS: u32 = 40_513;
/// S2 last MULTI_RX 01:17:18.550. Both silent before T+45.
pub const S19K_LIVE403_S2_LAST_RX_MS: u32 = 43_841;
pub const S19K_LIVE403_S1_MULTI_RX: u32 = 388;
pub const S19K_LIVE403_S2_MULTI_RX: u32 = 404;
pub const S19K_LIVE401_S1_MULTI_RX: u32 = 366;
pub const S19K_LIVE401_S2_MULTI_RX: u32 = 600;

/// Drain-all kept S1 alive past the live401 T+21s death.
pub fn admit_s19k_live403_s1_survived_past_live401_s1() -> Result<(), &'static str> {
    if S19K_LIVE403_S1_LAST_RX_MS <= S19K_LIVE401_S1_LAST_RX_MS {
        return Err("live403 S1 last RX must outlast live401 S1 T+21s");
    }
    Ok(())
}

///  did not close the stall: both ports silent before T+90.
pub fn refuse_s19k_live403_as_stall_closed() -> Result<(), &'static str> {
    if S19K_LIVE403_S1_LAST_RX_MS < 90_000 && S19K_LIVE403_S2_LAST_RX_MS < 90_000 {
        return Err(
            "live403 both ports silent before T+90 (S1 T+40.5s, S2 T+43.8s); stall not closed",
        );
    }
    Ok(())
}

/// live403 actor counters at the last MULTI_RX window (`Serial I/O:` 01:17:18).
pub const S19K_LIVE403_ACTOR_TX_AT_LAST_RX: u32 = 25;
pub const S19K_LIVE403_ACTOR_RX_AT_LAST_RX: u32 = 792;
/// Next 10s diag after silence (01:17:29): TX accelerated, RX stayed 792.
pub const S19K_LIVE403_ACTOR_TX_10S_AFTER_SILENCE: u32 = 58;

/// Shared ~T+40s stop is actor TX starve (1 work per ~32 nonce drain), not
/// a missing first ticket/HCN write. live403 re-armed once at start.
pub fn admit_s19k_live403_actor_tx_starved_during_rx() -> Result<(), &'static str> {
    if S19K_LIVE403_ACTOR_TX_AT_LAST_RX == 0 {
        return Err("live403 actor TX at last RX must be non-zero");
    }
    if S19K_LIVE403_ACTOR_RX_AT_LAST_RX / S19K_LIVE403_ACTOR_TX_AT_LAST_RX < 20 {
        return Err("live403 RX/TX ratio must show the 31-followup drain (~792/25)");
    }
    if S19K_LIVE403_ACTOR_TX_10S_AFTER_SILENCE <= S19K_LIVE403_ACTOR_TX_AT_LAST_RX {
        return Err("live403 actor TX must accelerate after both ports go silent");
    }
    Ok(())
}

pub fn refuse_s19k_live403_as_passthrough_never_rearmed() -> Result<(), &'static str> {
    Err(
        "live403 wrote ticket+HCN once before mining-on; stall is actor TX starve (25 TX vs 792 RX), not a missing first re-arm",
    )
}

/// live404 first WORK 01:45:30.474; S1 last MULTI_RX 01:45:59.854.
pub const S19K_LIVE404_S1_LAST_RX_MS: u32 = 29_380;
/// S2 last MULTI_RX 01:46:05.262.
pub const S19K_LIVE404_S2_LAST_RX_MS: u32 = 34_788;
pub const S19K_LIVE404_S1_MULTI_RX: u32 = 281;
pub const S19K_LIVE404_S2_MULTI_RX: u32 = 307;
/// Actor at T+10s after mining-on: 1:1 TX/RX (live403 was 6/192).
pub const S19K_LIVE404_ACTOR_TX_T10: u32 = 181;
pub const S19K_LIVE404_ACTOR_RX_T10: u32 = 181;

///  follow-up-drain=0 closed the 32:1 TX starve. live403 6 TX / 192 RX.
pub fn admit_s19k_live404_actor_tx_kept_up_with_rx() -> Result<(), &'static str> {
    if S19K_LIVE404_ACTOR_TX_T10 != S19K_LIVE404_ACTOR_RX_T10 {
        return Err("live404 T+10s actor TX must match RX (181/181)");
    }
    if S19K_LIVE404_ACTOR_TX_T10 <= S19K_LIVE403_ACTOR_TX_AT_LAST_RX {
        return Err("live404 T+10s TX must exceed live403's 25-TX starve window");
    }
    Ok(())
}

/// live404 5s rolling TH/s ×100 at T+25 (still 21.11) and T+35 (cliff 5.28).
pub const S19K_LIVE404_THS_T25_X100: u32 = 2111;
pub const S19K_LIVE404_THS_T35_X100: u32 = 528;
/// Actor TX at the T+30 Serial I/O line (past the first 256 job-id wrap).
pub const S19K_LIVE404_ACTOR_TX_T30: u32 = 564;

/// First 256-wrap is not the cliff: T+15/T+25 still 21 TH/s after ~256 TX.
pub fn refuse_s19k_live404_as_jobid_wrap() -> Result<(), &'static str> {
    Err("live404 first job-id wrap ~T+14s still 21 TH/s at T+15/T+25; cliff is T+29–35")
}

/// live404 one-shot discover re-arm then a dual-port hashrate cliff.
pub fn admit_s19k_live404_oneshot_rearm_then_cliff() -> Result<(), &'static str> {
    if S19K_LIVE404_THS_T25_X100 < 2000 {
        return Err("live404 T+25 must still be ~21 TH/s");
    }
    if S19K_LIVE404_THS_T35_X100 >= 1000 {
        return Err("live404 T+35 must be the cliff (<10 TH/s)");
    }
    if S19K_LIVE404_ACTOR_TX_T30 < 256 {
        return Err("live404 T+30 TX must be past the first 256 job-id wrap");
    }
    Ok(())
}

/// live404 still silent on both required ports before T+90.
pub fn refuse_s19k_live404_as_stall_closed() -> Result<(), &'static str> {
    if S19K_LIVE404_S1_LAST_RX_MS < 90_000 && S19K_LIVE404_S2_LAST_RX_MS < 90_000 {
        return Err(
            "live404 both ports silent before T+90 (S1 T+29.4s, S2 T+34.8s); stall not closed",
        );
    }
    Ok(())
}

/// BM1366 must not run the 31-frame RX follow-up drain (1 TX / 32 RX).
pub fn admit_s19k_production_bm1366_skips_rx_followup_drain(src: &str) -> Result<(), &'static str> {
    if !src.contains("BM1366_SERIAL_RX_FOLLOWUP_DRAIN") {
        return Err("BM1366 must name BM1366_SERIAL_RX_FOLLOWUP_DRAIN");
    }
    let start = src
        .find("let rx_followup_drain = if is_bm1366")
        .ok_or("missing rx_followup_drain selection")?;
    let win = src.get(start..start.saturating_add(220)).unwrap_or("");
    if !win.contains("BM1366_SERIAL_RX_FOLLOWUP_DRAIN") {
        return Err("BM1366 rx_followup_drain must be BM1366_SERIAL_RX_FOLLOWUP_DRAIN");
    }
    if !src.contains("for _ in 0..rx_followup_drain") {
        return Err("actor follow-up drain must use rx_followup_drain, not a hard 31");
    }
    Ok(())
}

/// live405 first WORK 02:13:39.419; S1 last MULTI_RX 02:14:50.658.
pub const S19K_LIVE405_S1_LAST_RX_MS: u32 = 71_239;
/// S2 last MULTI_RX 02:15:02.307.
pub const S19K_LIVE405_S2_LAST_RX_MS: u32 = 82_887;
pub const S19K_LIVE405_S1_MULTI_RX: u32 = 683;
pub const S19K_LIVE405_S2_MULTI_RX: u32 = 739;

/// Mid-run re-arm pushed past the live404 T+35 cliff.
pub fn admit_s19k_live405_survived_past_live404_cliff() -> Result<(), &'static str> {
    if S19K_LIVE405_S1_LAST_RX_MS <= S19K_LIVE404_S2_LAST_RX_MS {
        return Err("live405 S1 last RX must outlast the live404 T+35 cliff");
    }
    Ok(())
}

/// live405 UART TX at ~18.1/s reaches the 5th 256-slot wrap at ~70.7s.
pub const S19K_LIVE405_WRAP5_TX: u32 = 1280;
pub const S19K_LIVE405_WRAP5_EST_MS: u32 = 70_718;

/// S1 silence tracks wrap-5, not a failed mid-run re-arm (8 rearms already
/// succeeded; post-silence re-arm did not revive).
pub fn admit_s19k_live405_s1_died_at_wrap5() -> Result<(), &'static str> {
    let delta = S19K_LIVE405_S1_LAST_RX_MS.abs_diff(S19K_LIVE405_WRAP5_EST_MS);
    if delta > 1_000 {
        return Err("live405 S1 last RX must sit within 1s of the 5th 256-slot wrap");
    }
    if S19K_LIVE405_S1_LAST_RX_MS <= 4 * 256 * 1000 / 19 {
        return Err("live405 S1 must have survived wraps 1–4");
    }
    Ok(())
}

pub fn refuse_s19k_live405_as_failed_midrun_rearm() -> Result<(), &'static str> {
    Err(
        "live405 mid-run re-arm succeeded 8 times through T+63.6s; S1 died at wrap-5 T+71.2s; re-arm after silence did not revive",
    )
}

/// live405 still silent on both required ports before T+90.
pub fn refuse_s19k_live405_as_stall_closed() -> Result<(), &'static str> {
    if S19K_LIVE405_S1_LAST_RX_MS < 90_000 && S19K_LIVE405_S2_LAST_RX_MS < 90_000 {
        return Err(
            "live405 both ports silent before T+90 (S1 T+71.2s, S2 T+82.9s); stall not closed",
        );
    }
    Ok(())
}

/// BM1366 Track-1 must refresh ticket+HCN from the actor, not only at discover.
pub fn admit_s19k_production_bm1366_midrun_rearm(src: &str) -> Result<(), &'static str> {
    if !src.contains("BM1366_PASSTHROUGH_REARM_EVERY_S") {
        return Err("BM1366 must name BM1366_PASSTHROUGH_REARM_EVERY_S");
    }
    let start = src
        .find("let rearm_every = if is_bm1366")
        .ok_or("missing rearm_every selection")?;
    let win = src.get(start..start.saturating_add(240)).unwrap_or("");
    if !win.contains("BM1366_PASSTHROUGH_REARM_EVERY_S") {
        return Err("BM1366 rearm_every must be BM1366_PASSTHROUGH_REARM_EVERY_S");
    }
    if !src.contains("S19k passthrough mid-run re-arm") {
        return Err("actor must log mid-run re-arm");
    }
    if !src.contains("s19k_passthrough_rearm_writes()") {
        return Err("mid-run re-arm must reuse s19k_passthrough_rearm_writes");
    }
    Ok(())
}

/// Must match `BM1366_SERIAL_TX_MIN_INTERVAL_MS` in serial_mining.rs.
pub const S19K_BM1366_TX_MIN_INTERVAL_MS: u32 = 120;
/// live407 ran at 80 ms. Do not rewrite that wrap-5 survival against 120 ms.
pub const S19K_LIVE407_TX_MIN_INTERVAL_MS: u32 = 80;

/// 80 ms × 1280 works = 102.4 s, after the T+90 dual-port bar.
pub fn admit_s19k_tx_pace_puts_wrap5_after_t90() -> Result<(), &'static str> {
    let wrap5_ms = S19K_BM1366_TX_MIN_INTERVAL_MS.saturating_mul(S19K_LIVE405_WRAP5_TX);
    if wrap5_ms < 90_000 {
        return Err("paced wrap-5 must land at or after T+90");
    }
    Ok(())
}

/// Braiins fill UART registry is 0x100 (log 0). Wrap-5 is 5×256, not ESP 16-slot.
pub fn admit_s19k_fill_registry_is_256() -> Result<(), &'static str> {
    if crate::s19k_braiins_job::BOSMINER_UART_REGISTRY_SIZE_BASE != 0x100 {
        return Err("Braiins UART registry base must be 0x100");
    }
    if S19K_LIVE405_WRAP5_TX != 5 * crate::s19k_braiins_job::BOSMINER_UART_REGISTRY_SIZE_BASE {
        return Err("wrap-5 TX count must be 5×0x100");
    }
    Ok(())
}

/// BM1366 UART TX must be paced so wrap-5 (~1280 works) is after T+90.
pub fn admit_s19k_production_bm1366_tx_min_interval(src: &str) -> Result<(), &'static str> {
    if !src.contains("BM1366_SERIAL_TX_MIN_INTERVAL_MS") {
        return Err("BM1366 must name BM1366_SERIAL_TX_MIN_INTERVAL_MS");
    }
    let start = src
        .find("let min_tx_interval = if is_bm1366")
        .ok_or("missing min_tx_interval selection")?;
    let win = src.get(start..start.saturating_add(220)).unwrap_or("");
    if !win.contains("BM1366_SERIAL_TX_MIN_INTERVAL_MS") {
        return Err("BM1366 min_tx_interval must be BM1366_SERIAL_TX_MIN_INTERVAL_MS");
    }
    if !src.contains("const BM1366_SERIAL_TX_MIN_INTERVAL_MS: u64 = 120") {
        return Err("shipped TX pace must stay 120 ms (wrap-3 after T+90)");
    }
    Ok(())
}

/// live406a/b Track-1 on `.88`: S1+S2 Complete77, then ttyS3 leftover **9600**.
/// Drain/`read_all_responses` never returned (meson VTIME not sufficient).
/// Log ended at ttyS3 open; no WORK #1 / MULTI_RX. Pace untested.
pub const S19K_LIVE406_TTYS3_LEFTOVER_BAUD: u32 = 9600;
pub const S19K_LIVE406_REACHED_WORK1: bool = false;
pub const S19K_LIVE406_S1_LAST_RX_MS: u32 = 0;
pub const S19K_LIVE406_S2_LAST_RX_MS: u32 = 0;

/// Discover-only ttyS3 at a leftover baud that is not Braiins 3M must not
/// enter drain/GetAddress. live405 leftover was 3M (safe). live406 was 9600
/// and hung the 130s launch before mining-on.
pub fn s19k_discover_skip_rx_when_leftover_baud_not_track1_3m(path: &str, baud: u32) -> bool {
    path == BRAIINS_TTYS_THIRD && baud != crate::s19k_uart_trans_job::BRAIINS_TTYS_BAUD
}

pub fn admit_s19k_live406_hung_on_ttys3_9600() -> Result<(), &'static str> {
    if S19K_LIVE406_TTYS3_LEFTOVER_BAUD != 9600 {
        return Err("live406 ttyS3 leftover must stay pinned at 9600");
    }
    if S19K_LIVE406_REACHED_WORK1 {
        return Err("live406 must stay pinned as never reached WORK #1");
    }
    if S19K_LIVE406_S1_LAST_RX_MS != 0 || S19K_LIVE406_S2_LAST_RX_MS != 0 {
        return Err("live406 has no MULTI_RX timestamps; last-RX must stay 0");
    }
    Ok(())
}

/// live406 did not exercise wrap-5 pace. Stall remains open.
pub fn refuse_s19k_live406_as_stall_closed() -> Result<(), &'static str> {
    if !S19K_LIVE406_REACHED_WORK1 {
        return Err(
            "live406 hung at ttyS3@9600 before WORK #1; no T+90 dual-port MULTI_RX; stall not closed",
        );
    }
    Ok(())
}

/// Required S1/S2 must still drain even at a weird leftover baud.
pub fn refuse_s19k_skip_required_port_rx_for_9600() -> Result<(), &'static str> {
    if s19k_discover_skip_rx_when_leftover_baud_not_track1_3m("/dev/ttyS1", 9600)
        || s19k_discover_skip_rx_when_leftover_baud_not_track1_3m("/dev/ttyS2", 9600)
    {
        return Err("required ttyS1/ttyS2 must not skip GetAddress because leftover is 9600");
    }
    Ok(())
}

/// Production must skip discover RX when leftover baud is not Track-1 3M.
pub fn admit_s19k_production_skips_discover_rx_when_leftover_not_3m(
    src: &str,
) -> Result<(), &'static str> {
    if !src.contains("s19k_discover_skip_rx_when_leftover_baud_not_track1_3m") {
        return Err(
            "serial_mining must call s19k_discover_skip_rx_when_leftover_baud_not_track1_3m",
        );
    }
    if !src.contains("skip drain/GetAddress") {
        return Err("serial_mining must log the live406 ttyS3@9600 skip");
    }
    Ok(())
}

/// live407 first WORK 19:39:56.137; S1 last MULTI_RX 19:41:52.636.
pub const S19K_LIVE407_S1_LAST_RX_MS: u32 = 116_498;
/// S2 last MULTI_RX 19:41:43.531.
pub const S19K_LIVE407_S2_LAST_RX_MS: u32 = 107_394;
pub const S19K_LIVE407_S1_MULTI_RX: u32 = 766;
pub const S19K_LIVE407_S2_MULTI_RX: u32 = 680;
/// live407 logged SHARE # count. Ticket-valid hashes existed; none submitted.
pub const S19K_LIVE407_ACCEPTED_SHARES: u32 = 0;

/// Track-1 T+90 dual-port bar. live407 both required ports still MULTI_RX after 90s.
pub fn admit_s19k_live407_dual_port_past_t90() -> Result<(), &'static str> {
    if S19K_LIVE407_S1_LAST_RX_MS < 90_000 || S19K_LIVE407_S2_LAST_RX_MS < 90_000 {
        return Err("live407 both required ports must have MULTI_RX after T+90");
    }
    Ok(())
}

/// 80 ms pace puts wrap-5 at 102.4s. live407 both ports outlasted that.
pub fn admit_s19k_live407_survived_paced_wrap5() -> Result<(), &'static str> {
    let wrap5_ms = S19K_LIVE407_TX_MIN_INTERVAL_MS.saturating_mul(S19K_LIVE405_WRAP5_TX);
    if S19K_LIVE407_S1_LAST_RX_MS < wrap5_ms || S19K_LIVE407_S2_LAST_RX_MS < wrap5_ms {
        return Err("live407 both ports must outlast paced wrap-5 (80ms×1280=102.4s)");
    }
    Ok(())
}

pub fn admit_s19k_live407_zero_shares() -> Result<(), &'static str> {
    if S19K_LIVE407_ACCEPTED_SHARES != 0 {
        return Err("live407 must stay pinned at 0 accepted shares");
    }
    Ok(())
}

/// T+90 dual-port is not a pool share and not production.
pub fn refuse_s19k_live407_as_share_closed() -> Result<(), &'static str> {
    if S19K_LIVE407_ACCEPTED_SHARES == 0 {
        return Err(
            "live407 accepted 0 shares (UART vbits zeroed; ticket hashes not submitted); share not closed",
        );
    }
    Ok(())
}

pub fn refuse_s19k_t90_only_as_production_ready() -> Result<(), &'static str> {
    Err("T+90 dual-port MULTI_RX is not production-ready; FLASH/customer-writable stay false")
}

pub fn refuse_s19k_t90_only_as_customer_writable() -> Result<(), &'static str> {
    Err("T+90-only / live407 is not customer-writable")
}

/// live408 first WORK 21:13:04.261; S1 last MULTI_RX T+60272 ms.
pub const S19K_LIVE408_S1_LAST_RX_MS: u32 = 60_272;
/// S2 last MULTI_RX T+65238 ms.
pub const S19K_LIVE408_S2_LAST_RX_MS: u32 = 65_238;
pub const S19K_LIVE408_S1_MULTI_RX: u32 = 376;
pub const S19K_LIVE408_S2_MULTI_RX: u32 = 425;
/// ckpool accepted SHARE #1 nonce 0x5d793985 at pool diff 10000.
pub const S19K_LIVE408_ACCEPTED_SHARES: u32 = 1;
pub const S19K_LIVE408_SHARE_NONCE: u32 = 0x5D79_3985;

pub fn admit_s19k_live408_pool_accepted_one_share() -> Result<(), &'static str> {
    if S19K_LIVE408_ACCEPTED_SHARES < 1 {
        return Err("live408 must pin at least one pool-accepted share");
    }
    if S19K_LIVE408_SHARE_NONCE != 0x5D79_3985 {
        return Err("live408 accepted nonce must stay 0x5D793985");
    }
    Ok(())
}

pub fn refuse_s19k_live408_as_t90_dual_port() -> Result<(), &'static str> {
    if S19K_LIVE408_S1_LAST_RX_MS < 90_000 || S19K_LIVE408_S2_LAST_RX_MS < 90_000 {
        return Err("live408 both ports silent before T+90 (S1 T+60.3s, S2 T+65.2s)");
    }
    Ok(())
}

/// Same-run bar: accepted share AND T+90 dual-port. live407 had T+90/0 shares;
/// live408 had 1 share / no T+90.
pub fn refuse_s19k_live408_as_share_and_t90() -> Result<(), &'static str> {
    if S19K_LIVE408_ACCEPTED_SHARES >= 1
        && (S19K_LIVE408_S1_LAST_RX_MS < 90_000 || S19K_LIVE408_S2_LAST_RX_MS < 90_000)
    {
        return Err(
            "live408 accepted 1 share but MULTI_RX died before T+90; same-run bar not closed",
        );
    }
    Ok(())
}

/// live408 MULTI_RX died at wrap-3 of the 256-slot registry at 80 ms
/// (768 × 80 = 61.44 s). TX kept going (749 at T+60 → 1019).
pub const S19K_LIVE408_WRAP3_TX: u32 = 768;
pub const S19K_LIVE408_ACTOR_TX_AT_CLIFF: u32 = 749;
pub const S19K_LIVE408_NONCES_AT_CLIFF: u32 = 768;

pub fn admit_s19k_live408_died_at_wrap3() -> Result<(), &'static str> {
    if S19K_LIVE408_S1_LAST_RX_MS > 70_000 || S19K_LIVE408_S2_LAST_RX_MS > 70_000 {
        return Err("live408 last MULTI_RX must stay pinned before T+70 (wrap-3 class)");
    }
    if S19K_LIVE408_WRAP3_TX != 3 * crate::s19k_braiins_job::BOSMINER_UART_REGISTRY_SIZE_BASE {
        return Err("wrap-3 TX count must be 3×0x100");
    }
    if S19K_LIVE408_NONCES_AT_CLIFF != S19K_LIVE408_WRAP3_TX {
        return Err("live408 nonce cliff must stay 768 (wrap-3)");
    }
    Ok(())
}

/// 120 ms × 768 = 92.16 s, after the T+90 dual-port bar.
pub fn admit_s19k_tx_pace_puts_wrap3_after_t90() -> Result<(), &'static str> {
    let wrap3_ms = S19K_BM1366_TX_MIN_INTERVAL_MS.saturating_mul(S19K_LIVE408_WRAP3_TX);
    if wrap3_ms < 90_000 {
        return Err("paced wrap-3 must land at or after T+90 (live408 died at 80ms×768)");
    }
    Ok(())
}

/// live409 /tmp launch parked at BoardDesc ManagementOnly; no WORK #1.
pub const S19K_LIVE409_REACHED_WORK1: bool = false;
pub const S19K_LIVE409_S1_LAST_RX_MS: u32 = 0;
pub const S19K_LIVE409_S2_LAST_RX_MS: u32 = 0;
pub const S19K_LIVE409_ACCEPTED_SHARES: u32 = 0;

pub fn admit_s19k_live409_parked_boarddesc_management_only() -> Result<(), &'static str> {
    if S19K_LIVE409_REACHED_WORK1 {
        return Err("live409 must stay pinned as BoardDesc park (no WORK #1)");
    }
    if S19K_LIVE409_S1_LAST_RX_MS != 0 || S19K_LIVE409_S2_LAST_RX_MS != 0 {
        return Err("live409 has no MULTI_RX; last-RX must stay 0");
    }
    Ok(())
}

pub fn refuse_s19k_live409_as_share_and_t90() -> Result<(), &'static str> {
    if !S19K_LIVE409_REACHED_WORK1 || S19K_LIVE409_ACCEPTED_SHARES == 0 {
        return Err(
            "live409 parked management-only (no WORK #1 / 0 shares); same-run bar not closed",
        );
    }
    Ok(())
}

/// live410 first WORK 22:24:37.152; S1 last MULTI_RX 22:26:34.142.
pub const S19K_LIVE410_S1_LAST_RX_MS: u32 = 116_990;
/// S2 last MULTI_RX 22:26:34.383.
pub const S19K_LIVE410_S2_LAST_RX_MS: u32 = 117_231;
pub const S19K_LIVE410_S1_MULTI_RX: u32 = 487;
pub const S19K_LIVE410_S2_MULTI_RX: u32 = 502;
/// ckpool accepted SHARE #1 nonce 0x9aea565c at pool diff 8192.
pub const S19K_LIVE410_ACCEPTED_SHARES: u32 = 1;
pub const S19K_LIVE410_SHARE_NONCE: u32 = 0x9AEA_565C;

pub fn admit_s19k_live410_share_and_t90() -> Result<(), &'static str> {
    if S19K_LIVE410_ACCEPTED_SHARES < 1 {
        return Err("live410 must pin at least one pool-accepted share");
    }
    if S19K_LIVE410_SHARE_NONCE != 0x9AEA_565C {
        return Err("live410 accepted nonce must stay 0x9AEA565C");
    }
    if S19K_LIVE410_S1_LAST_RX_MS < 90_000 || S19K_LIVE410_S2_LAST_RX_MS < 90_000 {
        return Err("live410 both required ports must have MULTI_RX after T+90");
    }
    Ok(())
}

pub fn refuse_s19k_live410_as_production_ready() -> Result<(), &'static str> {
    Err("live410 same-run share+T+90 is Track-1 /tmp only; FLASH/customer-writable stay false")
}

pub fn refuse_s19k_live410_as_multi_share_closed() -> Result<(), &'static str> {
    if S19K_LIVE410_ACCEPTED_SHARES < 2 {
        return Err("live410 accepted 1 share; two-share same-run bar not closed");
    }
    Ok(())
}

pub fn refuse_s19k_live410_as_customer_writable() -> Result<(), &'static str> {
    Err("live410 one-share+T+90 is not customer-writable")
}

/// live411 first WORK 23:31:47.493; S1 last MULTI_RX T+118283 ms.
pub const S19K_LIVE411_S1_LAST_RX_MS: u32 = 118_283;
/// S2 last MULTI_RX T+118043 ms.
pub const S19K_LIVE411_S2_LAST_RX_MS: u32 = 118_043;
pub const S19K_LIVE411_S1_MULTI_RX: u32 = 492;
pub const S19K_LIVE411_S2_MULTI_RX: u32 = 491;
/// Five SHARE # submitted; at least two pool-accepted (ckpool 8192).
pub const S19K_LIVE411_ACCEPTED_SHARES: u32 = 5;
pub const S19K_LIVE411_SHARE1_NONCE: u32 = 0xC15A_724A;
pub const S19K_LIVE411_SHARE2_NONCE: u32 = 0x0033_0511;

pub fn admit_s19k_live411_multi_share_and_t90() -> Result<(), &'static str> {
    if S19K_LIVE411_ACCEPTED_SHARES < 2 {
        return Err("live411 must pin at least two submitted/accepted shares");
    }
    if S19K_LIVE411_SHARE1_NONCE != 0xC15A_724A {
        return Err("live411 SHARE #1 nonce must stay 0xC15A724A");
    }
    if S19K_LIVE411_SHARE2_NONCE != 0x0033_0511 {
        return Err("live411 SHARE #2 nonce must stay 0x00330511");
    }
    if S19K_LIVE411_S1_LAST_RX_MS < 90_000 || S19K_LIVE411_S2_LAST_RX_MS < 90_000 {
        return Err("live411 both required ports must have MULTI_RX after T+90");
    }
    Ok(())
}

pub fn refuse_s19k_live411_as_production_ready() -> Result<(), &'static str> {
    Err("live411 multi-share+T+90 is Track-1 /tmp only; FLASH/customer-writable stay false")
}

/// live411 was SIGTERM ~T+118. T+180 dual-port soak is not that log.
pub fn refuse_s19k_live411_as_t180_soak() -> Result<(), &'static str> {
    if S19K_LIVE411_S1_LAST_RX_MS < 180_000 || S19K_LIVE411_S2_LAST_RX_MS < 180_000 {
        return Err("live411 both ports last MULTI before T+180 (killed ~T+118); soak not closed");
    }
    Ok(())
}

pub fn refuse_s19k_t90_multi_share_as_soak() -> Result<(), &'static str> {
    Err("T+90 multi-share is not a T+180 soak; FLASH/customer-writable stay false")
}

pub fn refuse_s19k_live411_as_customer_writable() -> Result<(), &'static str> {
    Err("live411 multi-share+T+90 is not customer-writable")
}

/// live412 first WORK 00:37:26.587657Z; S1 last MULTI_RX T+187186 ms.
pub const S19K_LIVE412_S1_LAST_RX_MS: u32 = 187_186;
/// S2 last MULTI_RX T+188012 ms (SIGTERM ~T+188).
pub const S19K_LIVE412_S2_LAST_RX_MS: u32 = 188_012;
pub const S19K_LIVE412_S1_MULTI_RX: u32 = 779;
pub const S19K_LIVE412_S2_MULTI_RX: u32 = 790;
/// Eight SHARE # submitted; at least three ckpool-accepted (diff 10000).
pub const S19K_LIVE412_ACCEPTED_SHARES: u32 = 8;
pub const S19K_LIVE412_SHARE1_NONCE: u32 = 0x4E3E_900D;
pub const S19K_LIVE412_SHARE2_NONCE: u32 = 0xE5D3_C50D;

pub fn admit_s19k_live412_multi_share_and_t180() -> Result<(), &'static str> {
    if S19K_LIVE412_ACCEPTED_SHARES < 2 {
        return Err("live412 must pin at least two submitted/accepted shares");
    }
    if S19K_LIVE412_SHARE1_NONCE != 0x4E3E_900D {
        return Err("live412 SHARE #1 nonce must stay 0x4E3E900D");
    }
    if S19K_LIVE412_SHARE2_NONCE != 0xE5D3_C50D {
        return Err("live412 SHARE #2 nonce must stay 0xE5D3C50D");
    }
    if S19K_LIVE412_S1_LAST_RX_MS < 180_000 || S19K_LIVE412_S2_LAST_RX_MS < 180_000 {
        return Err("live412 both required ports must have MULTI_RX after T+180");
    }
    Ok(())
}

/// 120 ms × 1280 = 153.6 s. live412 last-RX is after that wrap.
pub fn admit_s19k_live412_survived_paced_wrap5() -> Result<(), &'static str> {
    let wrap5_ms = S19K_BM1366_TX_MIN_INTERVAL_MS.saturating_mul(S19K_LIVE405_WRAP5_TX);
    if S19K_LIVE412_S1_LAST_RX_MS <= wrap5_ms || S19K_LIVE412_S2_LAST_RX_MS <= wrap5_ms {
        return Err("live412 both ports must last MULTI after paced wrap-5");
    }
    Ok(())
}

pub fn refuse_s19k_live412_as_production_ready() -> Result<(), &'static str> {
    Err("live412 multi-share+T+180 is Track-1 /tmp only; FLASH/customer-writable stay false")
}

pub fn refuse_s19k_t180_tmp_as_production_ready() -> Result<(), &'static str> {
    Err("T+180 Track-1 /tmp soak is not NAND GO, native BM1366, or customer-writable")
}

pub fn refuse_s19k_live412_as_customer_writable() -> Result<(), &'static str> {
    Err("live412 multi-share+T+180 is not customer-writable")
}

/// live414 WORK 02:13:42.300868Z; S1 last MULTI T+228031 ms.
pub const S19K_LIVE414_S1_LAST_RX_MS: u32 = 228_031;
/// S2 last MULTI T+213744 ms (died first).
pub const S19K_LIVE414_S2_LAST_RX_MS: u32 = 213_744;
pub const S19K_LIVE414_S1_MULTI_RX: u32 = 1011;
pub const S19K_LIVE414_S2_MULTI_RX: u32 = 889;
pub const S19K_LIVE414_ACCEPTED_SHARES: u32 = 3;
pub const S19K_LIVE414_SHARE1_NONCE: u32 = 0xEEAB_1C38;
pub const S19K_LIVE414_SHARE2_NONCE: u32 = 0x97BB_F42B;
/// 256-slot UART wrap 7 = 7×256. 120 ms × 1792 = 215.04 s.
pub const S19K_LIVE414_WRAP7_TX: u32 = 1_792;

pub fn admit_s19k_live414_thermal_ready_and_t180() -> Result<(), &'static str> {
    if S19K_LIVE414_ACCEPTED_SHARES < 2 {
        return Err("live414 must pin at least two accepted shares");
    }
    if S19K_LIVE414_SHARE1_NONCE != 0xEEAB_1C38 {
        return Err("live414 SHARE #1 nonce must stay 0xEEAB1C38");
    }
    if S19K_LIVE414_SHARE2_NONCE != 0x97BB_F42B {
        return Err("live414 SHARE #2 nonce must stay 0x97BBF42B");
    }
    if S19K_LIVE414_S1_LAST_RX_MS < 180_000 || S19K_LIVE414_S2_LAST_RX_MS < 180_000 {
        return Err("live414 both required ports must have MULTI_RX after T+180");
    }
    Ok(())
}

pub fn admit_s19k_live414_died_at_wrap7() -> Result<(), &'static str> {
    let wrap7_ms = S19K_BM1366_TX_MIN_INTERVAL_MS.saturating_mul(S19K_LIVE414_WRAP7_TX);
    if S19K_LIVE414_S2_LAST_RX_MS + 3_000 < wrap7_ms {
        return Err("live414 S2 last-RX is too early to be paced wrap-7");
    }
    if S19K_LIVE414_S2_LAST_RX_MS > wrap7_ms + 5_000 {
        return Err("live414 S2 last-RX is too late to be paced wrap-7");
    }
    Ok(())
}

pub fn refuse_s19k_live414_as_t600_soak() -> Result<(), &'static str> {
    if S19K_LIVE414_S1_LAST_RX_MS >= 600_000 && S19K_LIVE414_S2_LAST_RX_MS >= 600_000 {
        return Ok(());
    }
    Err("live414 last MULTI is T+228/T+213; T+600 dual-port soak is not closed")
}

pub fn refuse_s19k_live414_as_production_ready() -> Result<(), &'static str> {
    Err("live414 Ready+T+180 is Track-1 /tmp only; FLASH/customer-writable stay false")
}

pub fn refuse_s19k_live414_as_customer_writable() -> Result<(), &'static str> {
    Err("live414 Ready+T+180 is not customer-writable")
}

/// live415 drain+rearm wrap-barrier binary `6ae62e3b`. Ready, 0 shares.
/// MULTI died T+26.5 before wrap-1 T+34.3 (leftover fluke or other).
pub const S19K_LIVE415_S1_LAST_RX_MS: u32 = 26_517;
pub const S19K_LIVE415_S2_LAST_RX_MS: u32 = 26_397;
pub const S19K_LIVE415_S1_MULTI_RX: u32 = 110;
pub const S19K_LIVE415_S2_MULTI_RX: u32 = 110;
pub const S19K_LIVE415_ACCEPTED_SHARES: u32 = 0;
pub const S19K_LIVE415_FIRST_WRAP_MS: u32 = 34_331;

/// live416 same `6ae62e3b`. Ready + 2 ckpool accepts. wrap-1 survived.
/// MULTI died T+73.6 after wrap-2 drain+ticket+HCN T+61.5.
pub const S19K_LIVE416_S1_LAST_RX_MS: u32 = 73_609;
pub const S19K_LIVE416_S2_LAST_RX_MS: u32 = 73_729;
pub const S19K_LIVE416_S1_MULTI_RX: u32 = 340;
pub const S19K_LIVE416_S2_MULTI_RX: u32 = 340;
pub const S19K_LIVE416_ACCEPTED_SHARES: u32 = 2;
pub const S19K_LIVE416_SHARE1_NONCE: u32 = 0xADFE_CA91;
pub const S19K_LIVE416_SHARE2_NONCE: u32 = 0x61B2_1B30;
pub const S19K_LIVE416_WRAP1_MS: u32 = 30_698;
pub const S19K_LIVE416_WRAP2_MS: u32 = 61_486;

pub fn admit_s19k_live415_died_before_wrap1() -> Result<(), &'static str> {
    if S19K_LIVE415_ACCEPTED_SHARES != 0 {
        return Err("live415 must stay 0 accepted shares");
    }
    if S19K_LIVE415_S1_LAST_RX_MS >= S19K_LIVE415_FIRST_WRAP_MS
        || S19K_LIVE415_S2_LAST_RX_MS >= S19K_LIVE415_FIRST_WRAP_MS
    {
        return Err("live415 MULTI died before wrap-1");
    }
    if S19K_LIVE415_S1_MULTI_RX != 110 || S19K_LIVE415_S2_MULTI_RX != 110 {
        return Err("live415 MULTI counts must stay 110/110");
    }
    Ok(())
}

pub fn refuse_s19k_live415_as_t600_soak() -> Result<(), &'static str> {
    if S19K_LIVE415_S1_LAST_RX_MS >= 600_000 && S19K_LIVE415_S2_LAST_RX_MS >= 600_000 {
        return Ok(());
    }
    Err("live415 last MULTI is T+26.5; T+600 dual-port soak is not closed")
}

pub fn refuse_s19k_live415_as_production_ready() -> Result<(), &'static str> {
    Err("live415 T+26 death is Track-1 /tmp only; FLASH/customer-writable stay false")
}

pub fn refuse_s19k_live415_as_customer_writable() -> Result<(), &'static str> {
    Err("live415 T+26 death is not customer-writable")
}

pub fn admit_s19k_live416_died_after_wrap2_drain_rearm() -> Result<(), &'static str> {
    if S19K_LIVE416_ACCEPTED_SHARES < 2 {
        return Err("live416 must pin at least two accepted shares");
    }
    if S19K_LIVE416_SHARE1_NONCE != 0xADFE_CA91 {
        return Err("live416 SHARE #1 nonce must stay 0xADFECA91");
    }
    if S19K_LIVE416_SHARE2_NONCE != 0x61B2_1B30 {
        return Err("live416 SHARE #2 nonce must stay 0x61B21B30");
    }
    if S19K_LIVE416_S1_LAST_RX_MS <= S19K_LIVE416_WRAP2_MS
        || S19K_LIVE416_S2_LAST_RX_MS <= S19K_LIVE416_WRAP2_MS
    {
        return Err("live416 MULTI died after wrap-2, not before");
    }
    if S19K_LIVE416_S1_LAST_RX_MS >= 90_000 || S19K_LIVE416_S2_LAST_RX_MS >= 90_000 {
        return Err("live416 MULTI died at T+74, not T+90");
    }
    Ok(())
}

pub fn refuse_s19k_live416_as_t600_soak() -> Result<(), &'static str> {
    if S19K_LIVE416_S1_LAST_RX_MS >= 600_000 && S19K_LIVE416_S2_LAST_RX_MS >= 600_000 {
        return Ok(());
    }
    Err("live416 last MULTI is T+73.6; T+600 dual-port soak is not closed")
}

pub fn refuse_s19k_live416_as_production_ready() -> Result<(), &'static str> {
    Err("live416 wrap-2 drain+rearm death is Track-1 /tmp; FLASH stay false")
}

pub fn refuse_s19k_live416_as_customer_writable() -> Result<(), &'static str> {
    Err("live416 wrap-2 drain+rearm death is not customer-writable")
}

pub fn refuse_s19k_live415_416_drain_rearm_as_wrap_survival() -> Result<(), &'static str> {
    Err("live415/416 32-read VTIME drain + ticket+HCN at wrap is not wrap-7 survival")
}

/// live417 quiet TX-skip wrap-barrier `e8ca29ac`. Ready + 1 accept.
/// wrap-1..5 survived (~9 TH/s); MULTI died T+176 before wrap-6 T+191.
pub const S19K_LIVE417_S1_LAST_RX_MS: u32 = 169_044;
pub const S19K_LIVE417_S2_LAST_RX_MS: u32 = 175_997;
pub const S19K_LIVE417_S1_MULTI_RX: u32 = 705;
pub const S19K_LIVE417_S2_MULTI_RX: u32 = 762;
pub const S19K_LIVE417_ACCEPTED_SHARES: u32 = 1;
pub const S19K_LIVE417_SHARE1_NONCE: u32 = 0xD081_C53B;
pub const S19K_LIVE417_WRAP5_MS: u32 = 154_012;
pub const S19K_LIVE417_WRAP6_MS: u32 = 191_410;

pub fn admit_s19k_live417_died_at_wrap6() -> Result<(), &'static str> {
    if S19K_LIVE417_ACCEPTED_SHARES != 1 {
        return Err("live417 must stay one accepted share");
    }
    if S19K_LIVE417_SHARE1_NONCE != 0xD081_C53B {
        return Err("live417 SHARE #1 nonce must stay 0xD081C53B");
    }
    if S19K_LIVE417_S1_LAST_RX_MS <= S19K_LIVE417_WRAP5_MS
        || S19K_LIVE417_S2_LAST_RX_MS <= S19K_LIVE417_WRAP5_MS
    {
        return Err("live417 MULTI survived wrap-5");
    }
    if S19K_LIVE417_S1_LAST_RX_MS >= S19K_LIVE417_WRAP6_MS
        || S19K_LIVE417_S2_LAST_RX_MS >= S19K_LIVE417_WRAP6_MS
    {
        return Err("live417 MULTI died before wrap-6");
    }
    Ok(())
}

pub fn refuse_s19k_live417_as_t600_soak() -> Result<(), &'static str> {
    if S19K_LIVE417_S1_LAST_RX_MS >= 600_000 && S19K_LIVE417_S2_LAST_RX_MS >= 600_000 {
        return Ok(());
    }
    Err("live417 last MULTI is T+176; T+600 dual-port soak is not closed")
}

pub fn refuse_s19k_live417_as_production_ready() -> Result<(), &'static str> {
    Err("live417 wrap-6 death is Track-1 /tmp; FLASH/customer-writable stay false")
}

pub fn refuse_s19k_live417_as_customer_writable() -> Result<(), &'static str> {
    Err("live417 wrap-6 death is not customer-writable")
}

/// 8s ticket+HCN must not share a loop with work TX (half-duplex).
/// live418 re-arm-skips-TX `1e4cb889`. Ready + 1 accept. S1 last MULTI
/// T+184926 at wrap-6 T+184719; S2 T+176802 before wrap-6.
pub const S19K_LIVE418_S1_LAST_RX_MS: u32 = 184_926;
pub const S19K_LIVE418_S2_LAST_RX_MS: u32 = 176_802;
pub const S19K_LIVE418_S1_MULTI_RX: u32 = 826;
pub const S19K_LIVE418_S2_MULTI_RX: u32 = 757;
pub const S19K_LIVE418_ACCEPTED_SHARES: u32 = 1;
pub const S19K_LIVE418_SHARE1_NONCE: u32 = 0xD272_543F;
pub const S19K_LIVE418_WRAP6_MS: u32 = 184_719;

pub fn admit_s19k_live418_died_at_wrap6() -> Result<(), &'static str> {
    if S19K_LIVE418_ACCEPTED_SHARES != 1 {
        return Err("live418 must stay one accepted share");
    }
    if S19K_LIVE418_SHARE1_NONCE != 0xD272_543F {
        return Err("live418 SHARE #1 nonce must stay 0xD272543F");
    }
    if S19K_LIVE418_S2_LAST_RX_MS >= S19K_LIVE418_WRAP6_MS {
        return Err("live418 S2 died before wrap-6");
    }
    let delta = S19K_LIVE418_S1_LAST_RX_MS.abs_diff(S19K_LIVE418_WRAP6_MS);
    if delta > 1_000 {
        return Err("live418 S1 last-RX must sit on wrap-6");
    }
    Ok(())
}

pub fn refuse_s19k_live418_as_t600_soak() -> Result<(), &'static str> {
    if S19K_LIVE418_S1_LAST_RX_MS >= 600_000 && S19K_LIVE418_S2_LAST_RX_MS >= 600_000 {
        return Ok(());
    }
    Err("live418 last MULTI is T+185; T+600 dual-port soak is not closed")
}

pub fn refuse_s19k_live418_as_production_ready() -> Result<(), &'static str> {
    Err("live418 wrap-6 death is Track-1 /tmp; FLASH/customer-writable stay false")
}

pub fn refuse_s19k_live418_as_customer_writable() -> Result<(), &'static str> {
    Err("live418 wrap-6 death is not customer-writable")
}

/// live419 wrap log-only after rails-off leftover. Ready 28.75°C, 0 shares.
/// MULTI died T+38 after wrap-1 (cold leftover, not a wrap-7 result).
pub const S19K_LIVE419_S1_LAST_RX_MS: u32 = 38_374;
pub const S19K_LIVE419_S2_LAST_RX_MS: u32 = 38_254;
pub const S19K_LIVE419_S1_MULTI_RX: u32 = 150;
pub const S19K_LIVE419_S2_MULTI_RX: u32 = 150;
pub const S19K_LIVE419_ACCEPTED_SHARES: u32 = 0;
pub const S19K_LIVE419_WRAP1_MS: u32 = 32_001;

pub fn admit_s19k_live419_died_after_wrap1_cold_leftover() -> Result<(), &'static str> {
    if S19K_LIVE419_ACCEPTED_SHARES != 0 {
        return Err("live419 must stay 0 accepted shares");
    }
    if S19K_LIVE419_S1_LAST_RX_MS <= S19K_LIVE419_WRAP1_MS
        || S19K_LIVE419_S2_LAST_RX_MS <= S19K_LIVE419_WRAP1_MS
    {
        return Err("live419 MULTI died after wrap-1, not before");
    }
    if S19K_LIVE419_S1_LAST_RX_MS >= 60_000 || S19K_LIVE419_S2_LAST_RX_MS >= 60_000 {
        return Err("live419 MULTI died at T+38, not T+60");
    }
    Ok(())
}

pub fn refuse_s19k_live419_as_t600_soak() -> Result<(), &'static str> {
    if S19K_LIVE419_S1_LAST_RX_MS >= 600_000 && S19K_LIVE419_S2_LAST_RX_MS >= 600_000 {
        return Ok(());
    }
    Err("live419 last MULTI is T+38; T+600 dual-port soak is not closed")
}

pub fn refuse_s19k_live419_as_production_ready() -> Result<(), &'static str> {
    Err("live419 cold-leftover T+38 death is Track-1 /tmp; FLASH stay false")
}

pub fn refuse_s19k_live419_as_customer_writable() -> Result<(), &'static str> {
    Err("live419 cold-leftover T+38 death is not customer-writable")
}

/// live420 same `8011fad8` after warmer leftover. Ready 42.9°C, 0 shares.
/// S2 last T+126767 just after wrap-4 T+123039; S1 T+136902.
pub const S19K_LIVE420_S1_LAST_RX_MS: u32 = 136_902;
pub const S19K_LIVE420_S2_LAST_RX_MS: u32 = 126_767;
pub const S19K_LIVE420_S1_MULTI_RX: u32 = 623;
pub const S19K_LIVE420_S2_MULTI_RX: u32 = 538;
pub const S19K_LIVE420_ACCEPTED_SHARES: u32 = 0;
pub const S19K_LIVE420_WRAP4_MS: u32 = 123_039;

pub fn admit_s19k_live420_died_after_wrap4() -> Result<(), &'static str> {
    if S19K_LIVE420_ACCEPTED_SHARES != 0 {
        return Err("live420 must stay 0 accepted shares");
    }
    if S19K_LIVE420_S1_LAST_RX_MS <= S19K_LIVE420_WRAP4_MS
        || S19K_LIVE420_S2_LAST_RX_MS <= S19K_LIVE420_WRAP4_MS
    {
        return Err("live420 MULTI died after wrap-4, not before");
    }
    if S19K_LIVE420_S1_LAST_RX_MS >= 180_000 || S19K_LIVE420_S2_LAST_RX_MS >= 180_000 {
        return Err("live420 MULTI died at T+137, not T+180");
    }
    Ok(())
}

pub fn refuse_s19k_live420_as_t600_soak() -> Result<(), &'static str> {
    if S19K_LIVE420_S1_LAST_RX_MS >= 600_000 && S19K_LIVE420_S2_LAST_RX_MS >= 600_000 {
        return Ok(());
    }
    Err("live420 last MULTI is T+137; T+600 dual-port soak is not closed")
}

pub fn refuse_s19k_live420_as_production_ready() -> Result<(), &'static str> {
    Err("live420 wrap-4 death is Track-1 /tmp; FLASH/customer-writable stay false")
}

pub fn refuse_s19k_live420_as_customer_writable() -> Result<(), &'static str> {
    Err("live420 wrap-4 death is not customer-writable")
}

/// Desk  analog-mux re-arm is not a T+600 soak.
pub fn refuse_s19k_analog_mux_rearm_as_t600_soak() -> Result<(), &'static str> {
    Err("analog_mux 0x54=3 mid-run re-arm is desk-only; T+600 not live-proven")
}

/// live414 first WORK 02:13:42.300868Z. SHARE #6 (last) 02:14:32.983575Z.
pub const S19K_LIVE414_LAST_SHARE_MS: u32 = 50_683;
/// Mid-run clean job 6a72bdc000008c9b at 02:14:48.596814Z. Zero SHARE after.
pub const S19K_LIVE414_MIDRUN_CLEAN_MS: u32 = 66_296;
/// live417 SHARE #1 T+22453; first mid-run clean 17:17:57.506031Z (T+81015).
pub const S19K_LIVE417_LAST_SHARE_MS: u32 = 22_453;
pub const S19K_LIVE417_MIDRUN_CLEAN_MS: u32 = 81_015;
/// live418 SHARE #1 T+55231; mid-run clean 17:50:26.960018Z (T+83387).
pub const S19K_LIVE418_LAST_SHARE_MS: u32 = 55_231;
pub const S19K_LIVE418_MIDRUN_CLEAN_MS: u32 = 83_387;
/// live412 SHARE #8 00:40:16.823035Z; no mid-run clean. Shares through wrap-5.
pub const S19K_LIVE412_LAST_SHARE_MS: u32 = 170_255;
/// live412 first WORK 00:37:26.587657Z; RAW_NOTIFY `...8bd1` 00:37:34.407263Z.
pub const S19K_LIVE412_8BD1_NOTIFY_AFTER_FIRST_WORK_MS: u32 = 7_819;
/// 7819 / 120 ms ≈ 65 TX into the first 256-slot fill.
pub const S19K_LIVE412_8BD1_TX_EST: u32 = 65;

/// Mid-run stratum clean stops pool-valid shares while leftover MULTI continues.
pub fn admit_s19k_live414_shares_stopped_after_midrun_clean() -> Result<(), &'static str> {
    if S19K_LIVE414_LAST_SHARE_MS >= S19K_LIVE414_MIDRUN_CLEAN_MS {
        return Err("live414 last SHARE must be before the mid-run clean");
    }
    if S19K_LIVE414_S2_LAST_RX_MS <= S19K_LIVE414_MIDRUN_CLEAN_MS {
        return Err("live414 MULTI continued after the mid-run clean");
    }
    if S19K_LIVE417_LAST_SHARE_MS >= S19K_LIVE417_MIDRUN_CLEAN_MS {
        return Err("live417 last SHARE must be before the mid-run clean");
    }
    if S19K_LIVE418_LAST_SHARE_MS >= S19K_LIVE418_MIDRUN_CLEAN_MS {
        return Err("live418 last SHARE must be before the mid-run clean");
    }
    if S19K_LIVE412_LAST_SHARE_MS < 150_000 {
        return Err("live412 last SHARE must stay after T+150 (no mid-run clean)");
    }
    Ok(())
}

pub fn refuse_s19k_midrun_clean_as_chip_reload() -> Result<(), &'static str> {
    Err("host clean_jobs is not a BM1366 work-replace; leftover slots keep pre-clean jobs")
}

/// live412 `...8bd1` arrived 7.819 s / ~65 TX after first WORK — still inside
/// the first 256-slot fill. Shares on that job_id do not prove same-slot
/// replacement after the UART registry is full.
pub fn refuse_s19k_live412_8bd1_as_same_slot_replace() -> Result<(), &'static str> {
    Err("live412 8bd1 notify is first-fill occupancy (~65 TX), not occupied-slot replace")
}

pub fn admit_s19k_live412_8bd1_is_first_fill() -> Result<(), &'static str> {
    if S19K_LIVE412_8BD1_NOTIFY_AFTER_FIRST_WORK_MS >= 30_720 {
        return Err("live412 8bd1 must arrive before paced wrap-1 (256×120 ms)");
    }
    let est = S19K_LIVE412_8BD1_NOTIFY_AFTER_FIRST_WORK_MS / S19K_BM1366_TX_MIN_INTERVAL_MS;
    if est != S19K_LIVE412_8BD1_TX_EST {
        return Err("live412 8bd1 TX estimate must stay 65");
    }
    if est >= S19K_UART_REGISTRY_WRAP_TX {
        return Err("live412 8bd1 must stay inside the first 256-slot fill");
    }
    Ok(())
}

/// Session-start accepted shares follow GetAddress/discover. live415 died
/// when that sequence ran mid-run. Do not treat first-load shares as proof
/// that occupied 21 36 slots accept a later mid-run rewrite.
pub fn refuse_s19k_session_start_shares_as_occupied_slot_replace() -> Result<(), &'static str> {
    Err("session-start shares follow GetAddress/discover; live415 died mid-run; not occupied-slot replace")
}

pub fn refuse_s19k_fill_cursor_reset_as_t600_soak() -> Result<(), &'static str> {
    Err("resetting fill 0..255 on clean is desk-only; T+600 not live-proven")
}

/// live414 first WORK 02:13:42.300868Z; S2 last MULTI T+213744. After the
/// T+66296 clean the actor still paced 120 ms TX for ~147 s ≈ 5 wraps.
pub const S19K_LIVE414_POST_CLEAN_TX_EST: u32 = 1_228;

pub fn admit_s19k_live414_resent_full_registry_after_clean() -> Result<(), &'static str> {
    let post_ms = S19K_LIVE414_S2_LAST_RX_MS.saturating_sub(S19K_LIVE414_MIDRUN_CLEAN_MS);
    let est = post_ms / S19K_BM1366_TX_MIN_INTERVAL_MS;
    if est < 2 * S19K_UART_REGISTRY_WRAP_TX {
        return Err("live414 post-clean TX must cover at least two full 256-slot wraps");
    }
    if S19K_LIVE414_POST_CLEAN_TX_EST != est {
        return Err("live414 post-clean TX estimate must stay 1228");
    }
    Ok(())
}

pub fn refuse_s19k_fill_cursor_reset_as_chip_work_replace() -> Result<(), &'static str> {
    Err("live414 already re-sent every fill job_id after clean; cursor reset is not chip work-replace")
}

/// Pause 8s ticket+HCN+analog_mux for one 256-TX wrap after a mid-run clean.
/// live414 kept that re-arm running while five post-clean wraps produced zero SHARE.
/// ESP `BM1366_send_work` writes jobs only (no mid-run regs). Not GetAddress
/// (live415). Not a proven chip invalidate.
pub fn s19k_track1_pause_rearm_until_tx(total_tx: u64) -> u64 {
    total_tx.saturating_add(u64::from(S19K_UART_REGISTRY_WRAP_TX))
}

pub fn admit_s19k_track1_pause_rearm_one_wrap() -> Result<(), &'static str> {
    if s19k_track1_pause_rearm_until_tx(0) != u64::from(S19K_UART_REGISTRY_WRAP_TX) {
        return Err("clean pause must cover one 256-slot wrap");
    }
    if s19k_track1_pause_rearm_until_tx(1_761) != 2_017 {
        return Err("clean pause must be current TX + 256");
    }
    Ok(())
}

pub fn admit_s19k_production_pauses_rearm_one_wrap_after_clean(
    src: &str,
) -> Result<(), &'static str> {
    if !src.contains("s19k_track1_pause_rearm_until_tx") {
        return Err("actor/mining loop must call s19k_track1_pause_rearm_until_tx");
    }
    if !src.contains("pause mid-run re-arm after clean") {
        return Err("actor must log the clean re-arm pause");
    }
    if !src.contains("total_tx < pause_until") {
        return Err("actor must skip ticket+HCN while total_tx < pause_until");
    }
    let start = src
        .find("live414/417/418: mid-run clean left fill cursor running")
        .ok_or("missing live414/417/418 clean comment")?;
    let end = src[start..]
        .find("work_builder.reset_extranonce2()")
        .map(|offset| start + offset)
        .ok_or("missing post-clean work-builder reset")?;
    let win = &src[start..end];
    if !win.contains("if midrun_clean") {
        return Err("HCN pause must stay inside midrun_clean (live424 session-start pause)");
    }
    if !win.contains("s19k_track1_pause_rearm_until_tx") {
        return Err("BM1366 clean_jobs must arm the one-wrap re-arm pause");
    }
    Ok(())
}

pub fn refuse_s19k_hcn_pause_as_t600_soak() -> Result<(), &'static str> {
    Err("pausing 8s HCN for one wrap after clean is desk-only; T+600 not live-proven")
}

pub fn refuse_s19k_hcn_pause_as_chip_work_replace() -> Result<(), &'static str> {
    Err("HCN pause is a leftover-safe hypothesis; not a proven BM1366 work-invalidate")
}

pub fn refuse_s19k_getaddress_as_midrun_invalidate() -> Result<(), &'static str> {
    Err("mid-run GetAddress is not the Track-1 invalidate (live415 died before wrap-1)")
}

pub fn refuse_s19k_analog_mux_as_wrap7_survival() -> Result<(), &'static str> {
    Err("analog_mux 0x54=3 is not wrap-7 leftover-job survival")
}

/// Track-1 NEW BLOCK must restart fill 0..255 (live414/417/418 share cliff).
pub fn admit_s19k_production_clean_resets_fill_cursor(src: &str) -> Result<(), &'static str> {
    if !src.contains("reset_s19k_braiins_fill") {
        return Err("serial_mining must call reset_s19k_braiins_fill");
    }
    let start = src
        .find("live414/417/418: mid-run clean left fill cursor running")
        .ok_or("missing live414/417/418 fill-cursor-reset comment")?;
    let end = src[start..]
        .find("work_builder.reset_extranonce2()")
        .map(|offset| start + offset)
        .ok_or("missing post-clean work-builder reset")?;
    let win = &src[start..end];
    if !win.contains("if midrun_clean") {
        return Err("fill-cursor reset must stay inside midrun_clean (live424)");
    }
    if !win.contains("bookkeeping.reset_s19k_braiins_fill()") {
        return Err("BM1366 clean_jobs must reset the Braiins fill cursor");
    }
    Ok(())
}

/// live424 first WORK 13:15:25.986342Z; ttyS2 last MULTI 13:16:52.977523Z.
pub const S19K_LIVE424_S2_LAST_RX_MS: u32 = 86_991;
/// live424 ttyS1 last MULTI 13:17:08.040138Z.
pub const S19K_LIVE424_S1_LAST_RX_MS: u32 = 102_054;
pub const S19K_LIVE424_S1_MULTI_RX: u32 = 526;
pub const S19K_LIVE424_S2_MULTI_RX: u32 = 366;
pub const S19K_LIVE424_ACCEPTED_SHARES: u32 = 3;
pub const S19K_LIVE424_SHARE1_NONCE: u32 = 0x09A9_BAAE;
pub const S19K_LIVE424_SESSION_START_PAUSE_TX: u32 = 37;
pub const S19K_LIVE424_FUNNEL_ARMED: u32 = 0;

pub fn admit_s19k_live424_session_start_paused_rearm() -> Result<(), &'static str> {
    if S19K_LIVE424_SESSION_START_PAUSE_TX == 0 {
        return Err("live424 session-start clean_jobs paused HCN at TX=37");
    }
    if S19K_LIVE424_FUNNEL_ARMED != 0 {
        return Err("live424 armed no mid-run funnel (session-start only)");
    }
    if S19K_LIVE424_ACCEPTED_SHARES != 3 {
        return Err("live424 accepted exactly 3 first-fill shares");
    }
    if S19K_LIVE424_S2_LAST_RX_MS >= 100_000 || S19K_LIVE424_S1_LAST_RX_MS >= 180_000 {
        return Err("live424 MULTI died S2 T+87 / S1 T+102");
    }
    Ok(())
}

pub fn refuse_s19k_live424_as_leftover_hit_soak() -> Result<(), &'static str> {
    Err("live424 had no mid-run clean; leftover_hit vs NewBlockShare is unmeasured")
}

pub fn refuse_s19k_session_start_hcn_pause() -> Result<(), &'static str> {
    Err("session-start clean_jobs must not pause 8s HCN (live424 TX=37 pause)")
}

/// live425 first WORK 13:48:43.381567Z; ttyS1 last MULTI 13:52:28.828234Z.
pub const S19K_LIVE425_S1_LAST_RX_MS: u32 = 225_447;
/// live425 ttyS2 last MULTI 13:52:35.628128Z.
pub const S19K_LIVE425_S2_LAST_RX_MS: u32 = 232_247;
pub const S19K_LIVE425_ACCEPTED_SHARES: u32 = 1;
pub const S19K_LIVE425_SHARE1_NONCE: u32 = 0xAB96_F056;
pub const S19K_LIVE425_FIRST_CLEAN_MS: u32 = 85_589;
pub const S19K_LIVE425_LEFTOVER_HIT: u32 = 6;
pub const S19K_LIVE425_MEETS: u32 = 0;
pub const S19K_LIVE425_SESSION_START_PAUSE: u32 = 0;

pub fn admit_s19k_live425_leftover_hit_and_wrap7() -> Result<(), &'static str> {
    if S19K_LIVE425_SESSION_START_PAUSE != 0 {
        return Err("live425 session-start must not pause HCN");
    }
    if S19K_LIVE425_FIRST_CLEAN_MS <= 80_000 {
        return Err("live425 first mid-run clean is T+85.6 s");
    }
    if S19K_LIVE425_LEFTOVER_HIT == 0 || S19K_LIVE425_MEETS != 0 {
        return Err("live425 leftover_hit=6 and meets=0 after the first mid-run clean");
    }
    if S19K_LIVE425_S1_LAST_RX_MS <= 215_040 || S19K_LIVE425_S2_LAST_RX_MS <= 215_040 {
        return Err("live425 MULTI survived wrap-7 (215.04 s)");
    }
    if S19K_LIVE425_ACCEPTED_SHARES != 1 {
        return Err("live425 accepted only the pre-clean share");
    }
    Ok(())
}

pub fn refuse_s19k_live425_as_t600_soak() -> Result<(), &'static str> {
    Err("live425 MULTI died T+225/T+232; T+600 dual-port still open")
}

/// live427 first WORK 14:16:33.182566Z; ttyS1 last MULTI 14:19:40.858876Z.
pub const S19K_LIVE427_S1_LAST_RX_MS: u32 = 187_676;
/// live427 ttyS2 last MULTI 14:19:48.868150Z.
pub const S19K_LIVE427_S2_LAST_RX_MS: u32 = 195_686;
pub const S19K_LIVE427_FIRST_FILL_SHARES: u32 = 5;
pub const S19K_LIVE427_MIDRUN_CLEANS: u32 = 0;
pub const S19K_LIVE427_INACTIVE_QUEUED: u32 = 0;
/// 6 × 256 work × 120 ms.
pub const S19K_TRACK1_WRAP6_MS: u32 = 184_320;

pub fn admit_s19k_live427_wrap6_without_clean() -> Result<(), &'static str> {
    if S19K_LIVE427_MIDRUN_CLEANS != 0 || S19K_LIVE427_INACTIVE_QUEUED != 0 {
        return Err("live427 mid-run clean and inactive must be 0");
    }
    if S19K_LIVE427_S1_LAST_RX_MS <= S19K_TRACK1_WRAP6_MS {
        return Err("live427 S1 last RX is at wrap-6 (184.32 s), not before");
    }
    if S19K_LIVE427_S1_LAST_RX_MS >= 215_040 || S19K_LIVE427_S2_LAST_RX_MS >= 215_040 {
        return Err("live427 MULTI died before wrap-7 (215.04 s)");
    }
    if S19K_LIVE427_FIRST_FILL_SHARES != 5 {
        return Err("live427 submitted 5 first-fill shares");
    }
    Ok(())
}

pub fn refuse_s19k_live427_as_chain_inactive_result() -> Result<(), &'static str> {
    Err("live427 never queued chain-inactive; MULTI died wrap-6 with 0 mid-run cleans")
}

/// live428 first WORK 14:50:11.379412Z; ttyS1 last MULTI 14:51:58.122623Z.
pub const S19K_LIVE428_S1_LAST_RX_MS: u32 = 106_743;
/// live428 ttyS2 last MULTI 14:52:02.552121Z.
pub const S19K_LIVE428_S2_LAST_RX_MS: u32 = 111_173;
pub const S19K_LIVE428_FIRST_FILL_SHARES: u32 = 4;
pub const S19K_LIVE428_MIDRUN_CLEANS: u32 = 0;

pub fn admit_s19k_live428_rx_died_before_wrap4_gpio_on() -> Result<(), &'static str> {
    if S19K_LIVE428_MIDRUN_CLEANS != 0 {
        return Err("live428 mid-run clean must be 0");
    }
    if S19K_LIVE428_S1_LAST_RX_MS >= 122_880 || S19K_LIVE428_S2_LAST_RX_MS >= 122_880 {
        return Err("live428 MULTI died before wrap-4 (122.88 s)");
    }
    if S19K_LIVE428_FIRST_FILL_SHARES != 4 {
        return Err("live428 submitted 4 first-fill shares");
    }
    Ok(())
}

pub fn refuse_s19k_live428_as_chain_inactive_result() -> Result<(), &'static str> {
    Err("live428 MULTI died T+107/T+111 with gpio437=0 and 0 mid-run cleans")
}

/// live430 same leftover-TX binary as live429 (`46effc29`). 5 first-fill
/// shares; MULTI froze at 1074 nonces ~T+130 (wrap-4) with gpio437=0.
/// A mid-run clean armed the funnel at T+617 (`outstanding=0`) after RX
/// was already dead — leftover_hit=0 / rxs=0. Not leftover proof, not
/// live429 SIGTERM. That is why soak_rx_dead=90 exists.
pub const S19K_LIVE430_FREEZE_NONCES: u32 = 1074;
pub const S19K_LIVE430_FIRST_FILL_SHARES: u32 = 5;
pub const S19K_LIVE430_SHARE1_NONCE: u32 = 0x0193_BE97;
pub const S19K_LIVE430_MIDRUN_CLEAN_AFTER_RX_DEAD: bool = true;
pub const S19K_LIVE430_FUNNEL_RXS_AFTER_CLEAN: u32 = 0;
pub const S19K_LIVE430_WRAP_AT_FREEZE: u32 = 4;
/// live430 first WORK/alive 15:25:09.053880Z; ttyS1 last MULTI 15:27:11.658811Z.
pub const S19K_LIVE430_S1_LAST_RX_MS: u32 = 122_605;
/// live430 ttyS2 last MULTI 15:27:17.052118Z.
pub const S19K_LIVE430_S2_LAST_RX_MS: u32 = 127_998;

pub fn admit_s19k_live430_wrap4_gpio_on_no_clean() -> Result<(), &'static str> {
    if !S19K_LIVE430_MIDRUN_CLEAN_AFTER_RX_DEAD {
        return Err("live430 mid-run clean landed after MULTI death");
    }
    if S19K_LIVE430_FUNNEL_RXS_AFTER_CLEAN != 0 {
        return Err("live430 post-clean funnel rxs must stay 0 (RX already dead)");
    }
    if S19K_LIVE430_FIRST_FILL_SHARES != 5 {
        return Err("live430 submitted 5 first-fill shares");
    }
    if S19K_LIVE430_SHARE1_NONCE != 0x0193_BE97 {
        return Err("live430 SHARE #1 nonce must stay 0x0193BE97");
    }
    if S19K_LIVE430_FREEZE_NONCES != 1074 {
        return Err("live430 froze at 1074 nonces");
    }
    if S19K_LIVE430_WRAP_AT_FREEZE != 4 {
        return Err("live430 freeze is wrap-4 class");
    }
    if S19K_LIVE430_S1_LAST_RX_MS >= 122_880 || S19K_LIVE430_S2_LAST_RX_MS >= 184_320 {
        return Err("live430 MULTI died at wrap-4 (122.88 s), not wrap-6");
    }
    Ok(())
}

pub fn refuse_s19k_live430_as_leftover_or_sigterm() -> Result<(), &'static str> {
    Err("live430 MULTI died wrap-4 gpio437=0; mid-run clean at T+617 had rxs=0; leftover_hit unmeasured; not live429 SIGTERM")
}

/// live431 first alive 16:11:54.055827Z; ttyS1 last MULTI 16:15:14.425838Z.
pub const S19K_LIVE431_S1_LAST_RX_MS: u32 = 200_370;
/// live431 ttyS2 last MULTI 16:15:23.512184Z.
pub const S19K_LIVE431_S2_LAST_RX_MS: u32 = 209_456;
pub const S19K_LIVE431_CLEAN_MS: u32 = 25_697;
pub const S19K_LIVE431_WRAP_AT_S1_DEATH: u32 = 6;

pub fn admit_s19k_live431_wrap6_after_live_clean() -> Result<(), &'static str> {
    if S19K_LIVE431_CLEAN_MS >= S19K_LIVE431_S1_LAST_RX_MS {
        return Err("live431 mid-run clean must precede last MULTI");
    }
    if S19K_LIVE431_S1_LAST_RX_MS < 184_320 {
        return Err("live431 S1 last RX must be past wrap-6 (184.32 s)");
    }
    if S19K_LIVE431_S1_LAST_RX_MS >= 215_040 {
        return Err("live431 S1 died before wrap-7 (215.04 s)");
    }
    if S19K_LIVE431_WRAP_AT_S1_DEATH != 6 {
        return Err("live431 S1 death is wrap-6");
    }
    Ok(())
}

pub fn refuse_s19k_live431_as_wrap7_t600() -> Result<(), &'static str> {
    Err("live431 last MULTI is wrap-6 T+200/T+209; soak stopped at T+220; T+600 wrap-7 is open")
}

/// live432 first alive 16:24:14.383783Z; first clean+inactive 16:25:00.098.
pub const S19K_LIVE432_FIRST_INACTIVE_MS: u32 = 45_715;
/// ttyS1 last MULTI 16:26:49.416115Z.
pub const S19K_LIVE432_S1_LAST_RX_MS: u32 = 155_032;
/// ttyS2 last MULTI 16:26:55.288207Z.
pub const S19K_LIVE432_S2_LAST_RX_MS: u32 = 160_904;
pub const S19K_LIVE432_FROZEN_NONCES: u32 = 1114;
pub const S19K_LIVE432_SHARE1_NONCE: u32 = 0x5A3C_A44F;

pub fn admit_s19k_live432_rx_died_after_first_clean_inactive() -> Result<(), &'static str> {
    if S19K_LIVE432_FIRST_INACTIVE_MS >= S19K_LIVE432_S1_LAST_RX_MS {
        return Err("live432 first inactive must precede last MULTI");
    }
    if S19K_LIVE432_S1_LAST_RX_MS >= 184_320 {
        return Err("live432 S1 died before wrap-6 (184.32 s), not wrap-7 RX");
    }
    if S19K_LIVE432_FROZEN_NONCES != 1114 {
        return Err("live432 froze at 1114 nonces");
    }
    if S19K_LIVE432_SHARE1_NONCE != 0x5A3C_A44F {
        return Err("live432 SHARE #1 must stay 0x5A3CA44F");
    }
    Ok(())
}

pub fn refuse_s19k_live432_tx_wrap7_as_rx_survival() -> Result<(), &'static str> {
    Err("live432 wrap_idx=7+ is TX after MULTI death; last RX is T+155/T+161; not wrap-7 dual-port soak")
}

pub fn refuse_s19k_live432_first_clean_inactive_as_leftover_admit() -> Result<(), &'static str> {
    Err("live432 first clean queued inactive at leftover_hit=0; live431 leftover is measured after the first clean")
}

/// live433 first alive 16:51:54.667030Z; ttyS1 last MULTI 16:55:03.709094Z.
pub const S19K_LIVE433_S1_LAST_RX_MS: u32 = 189_042;
/// live433 ttyS2 last MULTI 16:55:14.268223Z.
pub const S19K_LIVE433_S2_LAST_RX_MS: u32 = 199_601;
/// live433 first mid-run clean 16:54:19.880168Z (identity; inactive=0).
pub const S19K_LIVE433_CLEAN_MS: u32 = 145_213;
pub const S19K_LIVE433_FROZEN_NONCES: u32 = 1460;
pub const S19K_LIVE433_SHARE1_NONCE: u32 = 0x8A97_C7BE;
pub const S19K_LIVE433_WRAP_RX: u32 = 6;
pub const S19K_LIVE433_INACTIVE_QUEUED: u32 = 0;
pub const S19K_LIVE433_LEFTOVER_HIT: u32 = 0;
pub const S19K_LIVE433_CORRELATE_FAIL: u32 = 199;

/// leftover-admitted planner: first clean identity, then wrap-6 MULTI
/// death with gpio437=0. Independent of leftover and of first-clean
/// inactive (live432).
pub fn admit_s19k_live433_wrap6_identity_death() -> Result<(), &'static str> {
    if S19K_LIVE433_INACTIVE_QUEUED != 0 {
        return Err("live433 leftover-admitted planner queued no chain-inactive");
    }
    if S19K_LIVE433_LEFTOVER_HIT != 0 {
        return Err("live433 leftover_hit stayed 0 (correlate_fail never hunted retired)");
    }
    if S19K_LIVE433_CLEAN_MS >= S19K_LIVE433_S1_LAST_RX_MS {
        return Err("live433 identity first-clean must precede last MULTI");
    }
    if S19K_LIVE433_S1_LAST_RX_MS < 184_320 {
        return Err("live433 S1 last RX must be past wrap-6 (184.32 s)");
    }
    if S19K_LIVE433_S1_LAST_RX_MS >= 215_040 {
        return Err("live433 S1 died before wrap-7 (215.04 s)");
    }
    if S19K_LIVE433_WRAP_RX != 6 {
        return Err("live433 wrap_rx at MULTI death is 6");
    }
    if S19K_LIVE433_FROZEN_NONCES != 1460 {
        return Err("live433 froze at 1460 nonces");
    }
    if S19K_LIVE433_SHARE1_NONCE != 0x8A97_C7BE {
        return Err("live433 SHARE #1 must stay 0x8A97C7BE");
    }
    if S19K_LIVE433_CORRELATE_FAIL != 199 {
        return Err("live433 correlate_fail must stay 199");
    }
    let class = classify_s19k_track1_rx_death(Some(0), 11, 6, 1, 0, None, false);
    if class != S19kTrack1RxDeathClass::WrapNoClean {
        return Err("live433 wrap-6 identity death is WrapNoClean, not FirstCleanInactive");
    }
    if !s19k_track1_tx_wrap_after_rx_death(11, 6) {
        return Err("live433 TX wrap after RX death must stay true and not change the class");
    }
    Ok(())
}

pub fn refuse_s19k_live433_as_first_clean_inactive() -> Result<(), &'static str> {
    Err("live433 first clean identity leftover_hit=0 inactive=0; wrap-6 MULTI death is independent of leftover/inactive")
}

pub fn refuse_s19k_live433_leftover_hit0_as_no_leftover() -> Result<(), &'static str> {
    Err("live433 leftover_hit=0 with 199 correlate_fail; outstanding hunt misses retired 21 36")
}

/// live434 first alive 17:29:03.603326Z; ttyS1 last MULTI 17:31:21.666709Z.
pub const S19K_LIVE434_S1_LAST_RX_MS: u32 = 138_063;
/// live434 ttyS2 last MULTI 17:31:28.828211Z.
pub const S19K_LIVE434_S2_LAST_RX_MS: u32 = 145_225;
/// First mid-run clean 17:32:30.609860Z — after MULTI death (rxs=0).
pub const S19K_LIVE434_CLEAN_MS: u32 = 207_007;
pub const S19K_LIVE434_FROZEN_NONCES: u32 = 1211;
pub const S19K_LIVE434_SHARE1_NONCE: u32 = 0x8195_835F;
pub const S19K_LIVE434_WRAP_RX: u32 = 4;
pub const S19K_LIVE434_INACTIVE_QUEUED: u32 = 0;

pub fn admit_s19k_live434_wrap4_identity_death() -> Result<(), &'static str> {
    if S19K_LIVE434_INACTIVE_QUEUED != 0 {
        return Err("live434 queued no chain-inactive");
    }
    if S19K_LIVE434_CLEAN_MS <= S19K_LIVE434_S2_LAST_RX_MS {
        return Err("live434 first clean must be after last MULTI");
    }
    if S19K_LIVE434_S1_LAST_RX_MS >= 153_600 {
        return Err("live434 S1 died in wrap-4 (before wrap-5 153.6 s)");
    }
    if S19K_LIVE434_WRAP_RX != 4 {
        return Err("live434 wrap_rx at MULTI death is 4");
    }
    if S19K_LIVE434_FROZEN_NONCES != 1211 {
        return Err("live434 froze at 1211 nonces");
    }
    if S19K_LIVE434_SHARE1_NONCE != 0x8195_835F {
        return Err("live434 SHARE #1 must stay 0x8195835F");
    }
    if !s19k_track1_clean_after_rx_death_ms(S19K_LIVE434_CLEAN_MS, S19K_LIVE434_S2_LAST_RX_MS) {
        return Err("live434 first clean is after last MULTI");
    }
    if s19k_track1_clean_after_rx_death_ms(S19K_LIVE433_CLEAN_MS, S19K_LIVE433_S1_LAST_RX_MS) {
        return Err("live433 first clean precedes last MULTI");
    }
    let class = classify_s19k_track1_rx_death(Some(0), 6, 4, 1, 0, None, true);
    if class != S19kTrack1RxDeathClass::CleanAfterRxDeath {
        return Err("live434 RX death is CleanAfterRxDeath; leftover_hit=0 is unmeasured");
    }
    if !s19k_track1_tx_wrap_after_rx_death(6, 4) {
        return Err("live434 wrap_idx=6 wrap_rx=4 is TX after death");
    }
    Ok(())
}

pub fn refuse_s19k_live434_as_wrap6_or_leftover_replace() -> Result<(), &'static str> {
    Err("live434 wrap_rx=4 MULTI death; clean after RX death rxs=0; leftover vs meets unproven")
}

/// live435 first alive 18:33:20.720467Z; ttyS1 last MULTI 18:37:30.356128Z.
pub const S19K_LIVE435_S1_LAST_RX_MS: u32 = 249_636;
/// live435 ttyS2 last MULTI 18:37:22.801552Z.
pub const S19K_LIVE435_S2_LAST_RX_MS: u32 = 242_081;
pub const S19K_LIVE435_FROZEN_NONCES: u32 = 2077;
pub const S19K_LIVE435_WRAP_RX: u32 = 8;
pub const S19K_LIVE435_LEFTOVER_HIT: u32 = 0;
pub const S19K_LIVE435_CLEANS: u32 = 0;
pub const S19K_LIVE435_SHARES: u32 = 0;

/// Dual-port MULTI past wrap-7 (215.04 s). S1 also past wrap-8 (245.76 s).
/// No mid-run clean. leftover_hit=0 means wrap overwrite was accepted.
/// T+600 still unmet (last RX T+249/T+242).
pub fn admit_s19k_live435_dual_port_wrap7() -> Result<(), &'static str> {
    if S19K_LIVE435_S1_LAST_RX_MS <= 215_040 || S19K_LIVE435_S2_LAST_RX_MS <= 215_040 {
        return Err("live435 both ports must last past wrap-7 215.04 s");
    }
    if S19K_LIVE435_S1_LAST_RX_MS <= 245_760 {
        return Err("live435 S1 last RX must be past wrap-8 245.76 s");
    }
    if S19K_LIVE435_WRAP_RX != 8 {
        return Err("live435 wrap_rx at MULTI death is 8");
    }
    if S19K_LIVE435_FROZEN_NONCES != 2077 {
        return Err("live435 froze at 2077 nonces");
    }
    if S19K_LIVE435_LEFTOVER_HIT != 0 || S19K_LIVE435_CLEANS != 0 {
        return Err("live435 leftover_hit=0 with no mid-run clean");
    }
    if S19K_LIVE435_SHARES != 0 {
        return Err("live435 submitted 0 pool shares (pool_diff 10000)");
    }
    let class = classify_s19k_track1_rx_death(Some(0), 9, 8, 0, 0, None, false);
    if class != S19kTrack1RxDeathClass::WrapNoClean {
        return Err("live435 RX death is WrapNoClean");
    }
    Ok(())
}

pub fn refuse_s19k_live435_as_wrap7_t600() -> Result<(), &'static str> {
    Err("live435 last MULTI is wrap-8 T+249 / wrap-7 T+242; soak stopped silent=90 at T+350; T+600 open")
}

pub fn refuse_s19k_live435_leftover0_as_replace() -> Result<(), &'static str> {
    Err("live435 leftover_hit=0 with no mid-run clean is wrap overwrite accepted, not occupied-slot replace")
}

/// live436 first alive 18:46:46.152722Z; ttyS1 last MULTI 18:49:12.376764Z.
pub const S19K_LIVE436_S1_LAST_RX_MS: u32 = 146_224;
/// live436 ttyS2 last MULTI 18:49:19.900116Z.
pub const S19K_LIVE436_S2_LAST_RX_MS: u32 = 153_747;
pub const S19K_LIVE436_FROZEN_NONCES: u32 = 1292;
pub const S19K_LIVE436_WRAP_RX: u32 = 4;
pub const S19K_LIVE436_INACTIVE_QUEUED: u32 = 0;

/// wrap-retire leftover_hit=3 before wrap-4 MULTI death. No mid-run
/// clean, so leftover-admitted inactive never queued. First clean
/// would have admitted (same bar as live431 leftover_hit=4).
pub fn admit_s19k_live436_wrap4_death_with_wrap_retire_leftover() -> Result<(), &'static str> {
    if S19K_LIVE436_INACTIVE_QUEUED != 0 {
        return Err("live436 queued no chain-inactive (no mid-run clean)");
    }
    if crate::s19k_braiins_job::S19K_LIVE436_WRAP_RETIRE_LEFTOVER_HIT != 3 {
        return Err("live436 wrap-retire leftover_hit must stay 3");
    }
    if crate::s19k_braiins_job::S19K_LIVE436_WRAP_RETIRE_CLEANS != 0 {
        return Err("live436 leftover is wrap-retire, not post-clean");
    }
    if S19K_LIVE436_S1_LAST_RX_MS >= 153_600 {
        return Err("live436 S1 died in wrap-4 (before wrap-5 153.6 s)");
    }
    if S19K_LIVE436_WRAP_RX != 4 {
        return Err("live436 wrap_rx at MULTI death is 4");
    }
    if S19K_LIVE436_FROZEN_NONCES != 1292 {
        return Err("live436 froze at 1292 nonces");
    }
    let class = classify_s19k_track1_rx_death(Some(0), 6, 4, 0, 3, None, false);
    if class != S19kTrack1RxDeathClass::WrapNoClean {
        return Err("live436 RX death is WrapNoClean leftover_hit=3");
    }
    if !crate::s19k_braiins_job::s19k_leftover_hit_admits_experimental_inactive(3, 0, 0) {
        return Err("live436 leftover_hit=3 would leftover-admit the first mid-run clean");
    }
    if crate::s19k_braiins_job::s19k_leftover_hit_vs_meets_replace_proven(3, 0, 0, false) {
        return Err("live436 leftover-admit never queued; not occupied-slot replace");
    }
    Ok(())
}

pub fn refuse_s19k_live436_as_wrap7_t600_or_replace() -> Result<(), &'static str> {
    Err("live436 wrap_rx=4 leftover_hit=3 no mid-run clean; leftover-admitted inactive never queued; T+600 open")
}

/// live437 first alive 19:01:17.453543Z; wrap-4 snapshot 19:03:22.445222Z.
pub const S19K_LIVE437_WRAP4_SNAPSHOT_MS: u32 = 124_992;
pub const S19K_LIVE437_WRAP4_SNAPSHOT_LEFTOVER_HIT: u32 = 4;
/// ttyS1 last MULTI 19:04:16.901658Z.
pub const S19K_LIVE437_S1_LAST_RX_MS: u32 = 179_448;
/// ttyS2 last MULTI 19:04:25.384117Z.
pub const S19K_LIVE437_S2_LAST_RX_MS: u32 = 187_931;
pub const S19K_LIVE437_FROZEN_NONCES: u32 = 1572;
pub const S19K_LIVE437_WRAP_RX: u32 = 6;
pub const S19K_LIVE437_INACTIVE_QUEUED: u32 = 0;
pub const S19K_LIVE437_LEFTOVER_HEADER_AFTER_ARM: u32 = 8;

/// wrap-4 early snapshot fired while RX live at leftover_hit=4
/// leftover_header=0. Second-tick leftover-admit refused after
/// leftover_header climbed. Death LeftoverAfterClean wrap_rx=6.
pub fn admit_s19k_live437_wrap4_snapshot_without_inactive() -> Result<(), &'static str> {
    if S19K_LIVE437_INACTIVE_QUEUED != 0 {
        return Err("live437 queued no chain-inactive (header climb blocked second tick)");
    }
    if S19K_LIVE437_WRAP4_SNAPSHOT_LEFTOVER_HIT != 4 {
        return Err("live437 wrap-4 snapshot leftover_hit must stay 4");
    }
    if S19K_LIVE437_WRAP4_SNAPSHOT_MS >= S19K_LIVE437_S1_LAST_RX_MS {
        return Err("live437 wrap-4 snapshot must precede last MULTI");
    }
    if S19K_LIVE437_S2_LAST_RX_MS <= 184_320 {
        return Err("live437 S2 last RX must be past wrap-6 184.32 s");
    }
    if S19K_LIVE437_WRAP_RX != 6 {
        return Err("live437 wrap_rx at MULTI death is 6");
    }
    if S19K_LIVE437_FROZEN_NONCES != 1572 {
        return Err("live437 froze at 1572 nonces");
    }
    let class = classify_s19k_track1_rx_death(Some(0), 7, 6, 1, 4, None, false);
    if class != S19kTrack1RxDeathClass::LeftoverAfterClean {
        return Err("live437 RX death is LeftoverAfterClean leftover_hit=4");
    }
    if crate::s19k_braiins_job::s19k_leftover_hit_vs_meets_replace_proven(4, 8, 0, false) {
        return Err("live437 leftover-admit never queued; not occupied-slot replace");
    }
    if crate::s19k_braiins_job::s19k_plan_wrap4_early_leftover_safe(
        4,
        None,
        false,
        true,
        0,
        S19K_LIVE437_LEFTOVER_HEADER_AFTER_ARM,
        0,
        true,
    )
    .chain_inactive
    {
        return Err("leftover_header-only after wrap-4 arm must not leftover-admit");
    }
    Ok(())
}

pub fn refuse_s19k_live437_as_leftover_admit_or_t600() -> Result<(), &'static str> {
    Err("live437 wrap-4 snapshot leftover_hit=4 leftover_header=0; inactive never queued; wrap_rx=6; T+600 open")
}

/// live438 same-tick wrap-4 leftover-admit. Snapshot 19:28:45.014787Z,
/// CMD=3 queue 19:28:45.015488Z. leftover_hit=6 leftover_header=0.
pub const S19K_LIVE438_WRAP4_ADMIT_LEFTOVER_HIT: u32 = 6;
pub const S19K_LIVE438_WRAP4_ADMIT_LEFTOVER_HEADER: u32 = 0;
pub const S19K_LIVE438_WRAP4_ADMIT_MS: u32 = 124_991;
pub const S19K_LIVE438_INACTIVE_QUEUED: u32 = 1;
/// ttyS1 last MULTI 19:29:11.846664Z.
pub const S19K_LIVE438_S1_LAST_RX_MS: u32 = 151_822;
/// ttyS2 last MULTI 19:29:18.288221Z.
pub const S19K_LIVE438_S2_LAST_RX_MS: u32 = 158_264;
pub const S19K_LIVE438_FROZEN_NONCES: u32 = 1321;
pub const S19K_LIVE438_WRAP_RX: u32 = 5;
pub const S19K_LIVE438_POST_FLUSH_LEFTOVER_HIT: u32 = 0;
pub const S19K_LIVE438_POST_FLUSH_MEETS: u32 = 0;

/// Same-tick leftover-admit queued CMD=3 at leftover_header=0 before
/// leftover_header could climb. Not occupied-slot replace (meets still 0
/// at admit). Production wrap-4 early stays default OFF.
pub fn admit_s19k_live438_wrap4_same_tick_queued_cmd3() -> Result<(), &'static str> {
    if S19K_LIVE438_INACTIVE_QUEUED != 1 {
        return Err("live438 wrap-4 leftover-admit queued CMD=3 once");
    }
    if S19K_LIVE438_WRAP4_ADMIT_LEFTOVER_HIT != 6 {
        return Err("live438 leftover-admit leftover_hit must stay 6");
    }
    if S19K_LIVE438_WRAP4_ADMIT_LEFTOVER_HEADER != 0 {
        return Err("live438 leftover-admit leftover_header must stay 0");
    }
    if !crate::s19k_braiins_job::s19k_leftover_hit_admits_experimental_inactive(6, 0, 0) {
        return Err("live438 leftover_hit=6 leftover_header=0 admits experimental inactive");
    }
    let plan = crate::s19k_braiins_job::s19k_plan_wrap4_early_leftover_safe(
        4, None, false, true, 6, 0, 0, false,
    );
    if !plan.chain_inactive || !plan.refill {
        return Err(
            "same-tick wrap-4 leftover_hit=6 leftover_header=0 must queue inactive+snapshot",
        );
    }
    if crate::s19k_braiins_job::s19k_leftover_hit_vs_meets_replace_proven(6, 0, 0, true) {
        return Err("leftover-admitted CMD=3 is not occupied-slot replace");
    }
    if !crate::s19k_braiins_job::s19k_post_inactive_replace_proven(Some(6), 0, 0, 7) {
        return Err("post-flush meets>leftover is still the replace bar");
    }
    if S19K_LIVE438_S1_LAST_RX_MS <= S19K_LIVE438_WRAP4_ADMIT_MS {
        return Err("live438 last MULTI must be after leftover-admit CMD=3");
    }
    if S19K_LIVE438_POST_FLUSH_MEETS != 0 {
        return Err("live438 post-flush meets stayed 0 (replace unproven)");
    }
    if S19K_LIVE438_POST_FLUSH_LEFTOVER_HIT != 0 {
        return Err("live438 post-flush leftover_hit=0 after leftover-admit reset");
    }
    if !crate::s19k_braiins_job::s19k_post_inactive_flush_measured_not_replace(
        Some(S19K_LIVE438_WRAP4_ADMIT_LEFTOVER_HIT),
        S19K_LIVE438_POST_FLUSH_LEFTOVER_HIT,
        3,
        S19K_LIVE438_POST_FLUSH_MEETS,
    ) {
        return Err("live438 leftover_hit=0 after leftover-admit is flush measurement");
    }
    Ok(())
}

pub fn refuse_s19k_live438_admit_as_replace() -> Result<(), &'static str> {
    Err("live438 leftover-admitted CMD=3 at leftover_header=0 is UART flush queue, not meets>leftover replace")
}

/// live439 first alive 20:01:45.071780Z; wrap-4 leftover-admit 20:03:50.062734Z.
pub const S19K_LIVE439_WRAP4_ADMIT_LEFTOVER_HIT: u32 = 2;
pub const S19K_LIVE439_WRAP4_ADMIT_LEFTOVER_HEADER: u32 = 0;
pub const S19K_LIVE439_WRAP4_ADMIT_MS: u32 = 124_990;
pub const S19K_LIVE439_INACTIVE_QUEUED: u32 = 1;
pub const S19K_LIVE439_SHARE1_NONCE: u32 = 0xC902_97DF;
/// Last observed dual-port MULTI still live at wrap_rx=7 T+215.
pub const S19K_LIVE439_WRAP_RX_ALIVE: u32 = 7;
pub const S19K_LIVE439_ALIVE_MS: u32 = 215_000;
pub const S19K_LIVE439_ALIVE_NONCES: u32 = 1560;
pub const S19K_LIVE439_SECOND_CLEAN_LEFTOVER_HIT: u32 = 216;
pub const S19K_LIVE439_SECOND_CLEAN_LEFTOVER_HEADER: u32 = 1;
pub const S19K_LIVE439_SECOND_CLEAN_MEETS: u32 = 0;

/// live439 same-tick leftover-admit then wrap-7 still hashing. Second
/// identity clean re-accumulated leftover_hit=216 leftover_header=1.
/// Occupied-slot replace unproven (meets=0). T+600 / death class unknown
/// (unit dropped off LAN before soak stop).
pub fn admit_s19k_live439_wrap7_after_leftover_admit() -> Result<(), &'static str> {
    if S19K_LIVE439_INACTIVE_QUEUED != 1 {
        return Err("live439 wrap-4 leftover-admit queued CMD=3 once");
    }
    if S19K_LIVE439_WRAP4_ADMIT_LEFTOVER_HIT != 2 {
        return Err("live439 leftover-admit leftover_hit must stay 2");
    }
    if S19K_LIVE439_WRAP4_ADMIT_LEFTOVER_HEADER != 0 {
        return Err("live439 leftover-admit leftover_header must stay 0");
    }
    if S19K_LIVE439_SHARE1_NONCE != 0xC902_97DF {
        return Err("live439 SHARE #1 nonce must stay 0xC90297DF");
    }
    if S19K_LIVE439_WRAP_RX_ALIVE != 7 {
        return Err("live439 last observed wrap_rx must stay 7");
    }
    if S19K_LIVE439_ALIVE_MS <= S19K_LIVE439_WRAP4_ADMIT_MS {
        return Err("live439 wrap-7 alive must be after leftover-admit");
    }
    if S19K_LIVE439_ALIVE_NONCES != 1560 {
        return Err("live439 last observed nonce count must stay 1560");
    }
    if !crate::s19k_braiins_job::s19k_leftover_hit_admits_experimental_inactive(
        S19K_LIVE439_SECOND_CLEAN_LEFTOVER_HIT,
        S19K_LIVE439_SECOND_CLEAN_LEFTOVER_HEADER,
        S19K_LIVE439_SECOND_CLEAN_MEETS,
    ) {
        return Err("live439 leftover_hit=216 leftover_header=1 must leftover-admit");
    }
    if crate::s19k_braiins_job::s19k_leftover_header_admits_second_cmd3(0, 3, 0) {
        return Err("live438 leftover_header-only still cannot leftover-admit");
    }
    if crate::s19k_braiins_job::s19k_leftover_hit_vs_meets_replace_proven(
        S19K_LIVE439_SECOND_CLEAN_LEFTOVER_HIT,
        S19K_LIVE439_SECOND_CLEAN_LEFTOVER_HEADER,
        S19K_LIVE439_SECOND_CLEAN_MEETS,
        true,
    ) {
        return Err("live439 leftover_hit=216 meets=0 is not occupied-slot replace");
    }
    if !crate::s19k_braiins_job::s19k_wrap7_leftover_readmit_due(
        u64::from(S19K_LIVE439_WRAP_RX_ALIVE),
        Some(S19K_LIVE439_WRAP4_ADMIT_LEFTOVER_HIT),
        S19K_LIVE439_SECOND_CLEAN_LEFTOVER_HIT,
        S19K_LIVE439_SECOND_CLEAN_LEFTOVER_HEADER,
        S19K_LIVE439_SECOND_CLEAN_MEETS,
        false,
        false,
        true,
    ) {
        return Err("live439 wrap-7 leftover_hit=216 leftover-readmits after leftover-admit flush");
    }
    Ok(())
}

pub fn refuse_s19k_live439_as_replace_or_t600() -> Result<(), &'static str> {
    Err("live439 wrap-7 after leftover-admit leftover_hit=216 meets=0 is not replace; T+600 unknown")
}

/// live440 first alive 15:22:02.118Z; wrap-4 leftover-admit 15:24:07.103719Z.
pub const S19K_LIVE440_WRAP4_ADMIT_LEFTOVER_HIT: u32 = 1;
pub const S19K_LIVE440_WRAP4_ADMIT_LEFTOVER_HEADER: u32 = 0;
pub const S19K_LIVE440_WRAP4_ADMIT_MS: u32 = 125_000;
pub const S19K_LIVE440_INACTIVE_QUEUED: u32 = 1;
pub const S19K_LIVE440_WRAP7_READMIT_QUEUED: u32 = 0;
pub const S19K_LIVE440_S1_LAST_RX_MS: u32 = 227_575;
pub const S19K_LIVE440_S2_LAST_RX_MS: u32 = 240_146;
pub const S19K_LIVE440_FROZEN_NONCES: u32 = 1967;
pub const S19K_LIVE440_WRAP_RX: u32 = 7;
pub const S19K_LIVE440_POST_FLUSH_LEFTOVER_HIT: u32 = 0;
pub const S19K_LIVE440_POST_FLUSH_LEFTOVER_HEADER: u32 = 3;
pub const S19K_LIVE440_POST_FLUSH_MEETS: u32 = 0;

/// live440 wrap-7 after leftover-admit. leftover_hit stayed 0;
/// leftover_header=3 is remapped leftover and must not wrap-7 leftover-readmit.
/// Parser both ports host-silent (not wire-only). Replace unproven. T+600 unmet.
pub fn admit_s19k_live440_wrap7_header_only_does_not_readmit() -> Result<(), &'static str> {
    if S19K_LIVE440_INACTIVE_QUEUED != 1 {
        return Err("live440 wrap-4 leftover-admit queued CMD=3 once");
    }
    if S19K_LIVE440_WRAP7_READMIT_QUEUED != 0 {
        return Err("live440 wrap-7 leftover-readmit must stay 0");
    }
    if S19K_LIVE440_WRAP4_ADMIT_LEFTOVER_HIT != 1 {
        return Err("live440 leftover-admit leftover_hit must stay 1");
    }
    if S19K_LIVE440_WRAP_RX != 7 {
        return Err("live440 wrap_rx at MULTI death is 7");
    }
    if S19K_LIVE440_S1_LAST_RX_MS <= S19K_LIVE440_WRAP4_ADMIT_MS {
        return Err("live440 last S1 MULTI must be after leftover-admit");
    }
    if S19K_LIVE440_POST_FLUSH_MEETS != 0 {
        return Err("live440 post-flush meets stayed 0");
    }
    if crate::s19k_braiins_job::s19k_leftover_hit_admits_experimental_inactive(
        S19K_LIVE440_POST_FLUSH_LEFTOVER_HIT,
        S19K_LIVE440_POST_FLUSH_LEFTOVER_HEADER,
        S19K_LIVE440_POST_FLUSH_MEETS,
    ) {
        return Err("live440 leftover_hit=0 leftover_header=3 must not leftover-admit");
    }
    if crate::s19k_braiins_job::s19k_wrap7_leftover_readmit_due(
        u64::from(S19K_LIVE440_WRAP_RX),
        Some(S19K_LIVE440_WRAP4_ADMIT_LEFTOVER_HIT),
        S19K_LIVE440_POST_FLUSH_LEFTOVER_HIT,
        S19K_LIVE440_POST_FLUSH_LEFTOVER_HEADER,
        S19K_LIVE440_POST_FLUSH_MEETS,
        false,
        false,
        true,
    ) {
        return Err("live440 wrap-7 leftover_header-only must not leftover-readmit");
    }
    if crate::s19k_braiins_job::s19k_post_inactive_replace_proven(
        Some(S19K_LIVE440_WRAP4_ADMIT_LEFTOVER_HIT),
        S19K_LIVE440_POST_FLUSH_LEFTOVER_HIT,
        S19K_LIVE440_POST_FLUSH_LEFTOVER_HEADER,
        S19K_LIVE440_POST_FLUSH_MEETS,
    ) {
        return Err("live440 leftover_hit=0 meets=0 is flush, not replace");
    }
    Ok(())
}

pub fn refuse_s19k_live440_as_replace_or_t600() -> Result<(), &'static str> {
    Err("live440 wrap-7 after leftover-admit leftover_hit=0 leftover_header=3 is not replace; T+600 unmet")
}

/// live441 first alive 16:08:17.438Z; wrap-4 leftover-admit 16:10:22.472872Z.
pub const S19K_LIVE441_WRAP4_ADMIT_LEFTOVER_HIT: u32 = 4;
pub const S19K_LIVE441_WRAP4_ADMIT_MS: u32 = 125_035;
pub const S19K_LIVE441_S1_LAST_RX_MS: u32 = 182_498;
pub const S19K_LIVE441_S2_LAST_RX_MS: u32 = 190_862;
pub const S19K_LIVE441_FROZEN_NONCES: u32 = 1605;
pub const S19K_LIVE441_WRAP_RX: u32 = 6;
pub const S19K_LIVE441_WRAP7_SNAP_QUEUED: u32 = 0;
pub const S19K_LIVE441_WRAP7_READMIT_QUEUED: u32 = 0;

/// live441 leftover-admit leftover_hit=4 leftover_at=4 leftover_header=0.
/// MULTI died wrap_rx=6 before wrap-7 snapshot due. leftover_hit stayed 0
/// leftover_header=4. Parser host-silent. Not replace. T+600 unmet.
pub fn admit_s19k_live441_wrap6_death_before_wrap7_snapshot() -> Result<(), &'static str> {
    if S19K_LIVE441_WRAP4_ADMIT_LEFTOVER_HIT != 4 {
        return Err("live441 leftover-admit leftover_hit must stay 4");
    }
    if S19K_LIVE441_WRAP_RX != 6 {
        return Err("live441 wrap_rx at MULTI death is 6");
    }
    if S19K_LIVE441_WRAP7_SNAP_QUEUED != 0 {
        return Err("live441 wrap-7 snapshot must stay 0 (wrap_rx=6)");
    }
    if crate::s19k_braiins_job::s19k_wrap7_leftover_snapshot_due(6, Some(4), false, false, true) {
        return Err("wrap-6 is not wrap-7 leftover snapshot");
    }
    if !crate::s19k_braiins_job::s19k_wrap7_leftover_snapshot_due(7, Some(4), false, false, true) {
        return Err("wrap_rx=7 leftover_at=4 still snapshots POST-admit 21 36");
    }
    if crate::s19k_braiins_job::s19k_wrap7_leftover_readmit_due(
        6,
        Some(4),
        0,
        4,
        0,
        false,
        false,
        true,
    ) {
        return Err("live441 leftover_hit=0 leftover_header=4 must not leftover-readmit");
    }
    Ok(())
}

pub fn refuse_s19k_live441_as_replace_or_t600() -> Result<(), &'static str> {
    Err("live441 wrap_rx=6 after leftover-admit leftover_hit=0 leftover_header=4 is not replace; T+600 unmet")
}

/// live442 first alive 16:59:10.146076Z; wrap-4 leftover-admit 17:01:15.179681Z.
pub const S19K_LIVE442_WRAP4_ADMIT_LEFTOVER_HIT: u32 = 6;
pub const S19K_LIVE442_WRAP4_ADMIT_MS: u32 = 125_034;
pub const S19K_LIVE442_WRAP5_SNAP_MS: u32 = 155_029;
pub const S19K_LIVE442_S1_LAST_RX_MS: u32 = 253_350;
pub const S19K_LIVE442_S2_LAST_RX_MS: u32 = 246_792;
pub const S19K_LIVE442_FROZEN_NONCES: u32 = 2045;
pub const S19K_LIVE442_WRAP_RX: u32 = 8;
pub const S19K_LIVE442_WRAP5_SNAP_QUEUED: u32 = 1;
pub const S19K_LIVE442_WRAP5_READMIT_QUEUED: u32 = 0;
pub const S19K_LIVE442_POST_FLUSH_LEFTOVER_HIT: u32 = 0;
pub const S19K_LIVE442_POST_FLUSH_LEFTOVER_HEADER: u32 = 9;

/// live442 leftover-admit leftover_hit=6 leftover_at=6 leftover_header=0.
/// wrap-5 POST-admit leftover snapshot LIVE at wrap_rx=5 leftover_hit=0
/// leftover_header=2. leftover-readmit not queued: leftover_hit stayed 0
/// leftover_header=9. Survived wrap-6; MULTI died wrap_rx=8. Parser
/// host-silent. Not replace. T+600 unmet.
pub fn admit_s19k_live442_wrap5_snapshot_header_only_does_not_readmit() -> Result<(), &'static str>
{
    if S19K_LIVE442_WRAP4_ADMIT_LEFTOVER_HIT != 6 {
        return Err("live442 leftover-admit leftover_hit must stay 6");
    }
    if S19K_LIVE442_WRAP5_SNAP_QUEUED != 1 {
        return Err("live442 wrap-5 leftover snapshot must stay 1");
    }
    if S19K_LIVE442_WRAP5_READMIT_QUEUED != 0 {
        return Err("live442 wrap-5 leftover-readmit must stay 0");
    }
    if S19K_LIVE442_WRAP_RX != 8 {
        return Err("live442 wrap_rx at MULTI death is 8");
    }
    if S19K_LIVE442_S1_LAST_RX_MS <= S19K_LIVE442_WRAP5_SNAP_MS {
        return Err("live442 last S1 MULTI must be after wrap-5 snapshot");
    }
    if crate::s19k_braiins_job::s19k_leftover_hit_admits_experimental_inactive(
        S19K_LIVE442_POST_FLUSH_LEFTOVER_HIT,
        S19K_LIVE442_POST_FLUSH_LEFTOVER_HEADER,
        0,
    ) {
        return Err("live442 leftover_hit=0 leftover_header=9 must not leftover-admit");
    }
    if crate::s19k_braiins_job::s19k_wrap5_leftover_readmit_due(
        5,
        Some(S19K_LIVE442_WRAP4_ADMIT_LEFTOVER_HIT),
        S19K_LIVE442_POST_FLUSH_LEFTOVER_HIT,
        S19K_LIVE442_POST_FLUSH_LEFTOVER_HEADER,
        0,
        false,
        false,
        true,
    ) {
        return Err("live442 leftover_header-only must not wrap-5 leftover-readmit");
    }
    if !crate::s19k_braiins_job::s19k_wrap5_leftover_snapshot_due(
        5,
        Some(S19K_LIVE442_WRAP4_ADMIT_LEFTOVER_HIT),
        false,
        false,
        true,
    ) {
        return Err("live442 wrap_rx=5 leftover_at=6 must snapshot POST-admit 21 36");
    }
    Ok(())
}

pub fn refuse_s19k_live442_as_replace_or_t600() -> Result<(), &'static str> {
    Err("live442 wrap-5 snapshot leftover_hit=0 leftover_header=9 is not replace; T+600 unmet")
}

/// live443 first alive 17:49:33.561972Z; wrap-4 leftover-admit 17:51:38.594204Z.
pub const S19K_LIVE443_WRAP4_ADMIT_LEFTOVER_HIT: u32 = 2;
pub const S19K_LIVE443_WRAP4_ADMIT_MS: u32 = 125_032;
pub const S19K_LIVE443_WRAP5_SNAP_MS: u32 = 155_032;
pub const S19K_LIVE443_S1_LAST_RX_MS: u32 = 205_574;
pub const S19K_LIVE443_S2_LAST_RX_MS: u32 = 213_094;
pub const S19K_LIVE443_FROZEN_NONCES: u32 = 1793;
pub const S19K_LIVE443_WRAP_RX: u32 = 6;
pub const S19K_LIVE443_WRAP5_SNAP_QUEUED: u32 = 1;
pub const S19K_LIVE443_WRAP5_READMIT_QUEUED: u32 = 0;
pub const S19K_LIVE443_POST_FLUSH_LEFTOVER_HIT: u32 = 0;
pub const S19K_LIVE443_POST_FLUSH_LEFTOVER_HEADER: u32 = 5;

/// live443 leftover-admit leftover_hit=2 leftover_at=2 leftover_header=0.
/// wrap-5 history+TX snapshot LIVE leftover_hit=0 leftover_header=3.
/// leftover-readmit not queued: leftover_hit stayed 0 leftover_header=5.
/// MULTI died wrap_rx=6. Parser host-silent. Not replace. T+600 unmet.
pub fn admit_s19k_live443_history_tx_snapshot_header_only_does_not_readmit(
) -> Result<(), &'static str> {
    if S19K_LIVE443_WRAP4_ADMIT_LEFTOVER_HIT != 2 {
        return Err("live443 leftover-admit leftover_hit must stay 2");
    }
    if S19K_LIVE443_WRAP5_SNAP_QUEUED != 1 {
        return Err("live443 wrap-5 leftover snapshot must stay 1");
    }
    if S19K_LIVE443_WRAP5_READMIT_QUEUED != 0 {
        return Err("live443 wrap-5 leftover-readmit must stay 0");
    }
    if S19K_LIVE443_WRAP_RX != 6 {
        return Err("live443 wrap_rx at MULTI death is 6");
    }
    if crate::s19k_braiins_job::s19k_leftover_hit_admits_experimental_inactive(
        S19K_LIVE443_POST_FLUSH_LEFTOVER_HIT,
        S19K_LIVE443_POST_FLUSH_LEFTOVER_HEADER,
        0,
    ) {
        return Err("live443 leftover_hit=0 leftover_header=5 must not leftover-admit");
    }
    if crate::s19k_braiins_job::s19k_wrap5_leftover_readmit_due(
        5,
        Some(S19K_LIVE443_WRAP4_ADMIT_LEFTOVER_HIT),
        S19K_LIVE443_POST_FLUSH_LEFTOVER_HIT,
        S19K_LIVE443_POST_FLUSH_LEFTOVER_HEADER,
        0,
        false,
        false,
        true,
    ) {
        return Err("live443 leftover_header-only must not wrap-5 leftover-readmit");
    }
    Ok(())
}

pub fn refuse_s19k_live443_as_replace_or_t600() -> Result<(), &'static str> {
    Err("live443 wrap-5 history+TX snapshot leftover_hit=0 leftover_header=5 is not replace; T+600 unmet")
}

/// live444 first alive 18:17:28.522199Z; wrap-4 leftover-admit 18:19:33.558406Z.
pub const S19K_LIVE444_WRAP4_ADMIT_LEFTOVER_HIT: u32 = 3;
pub const S19K_LIVE444_WRAP4_ADMIT_MS: u32 = 125_036;
pub const S19K_LIVE444_WRAP5_SNAP_MS: u32 = 155_037;
pub const S19K_LIVE444_S1_LAST_RX_MS: u32 = 209_386;
pub const S19K_LIVE444_S2_LAST_RX_MS: u32 = 197_291;
pub const S19K_LIVE444_FROZEN_NONCES: u32 = 1658;
pub const S19K_LIVE444_SHARES: u32 = 2;
pub const S19K_LIVE444_WRAP_RX: u32 = 6;
pub const S19K_LIVE444_WRAP5_SNAP_QUEUED: u32 = 1;
pub const S19K_LIVE444_WRAP5_READMIT_QUEUED: u32 = 0;
pub const S19K_LIVE444_POST_FLUSH_LEFTOVER_HIT: u32 = 0;
pub const S19K_LIVE444_POST_FLUSH_LEFTOVER_HEADER: u32 = 4;

/// live444 leftover-admit leftover_hit=3 leftover_at=3 leftover_header=0.
/// wrap-5 merge snapshot LIVE leftover_hit=0 leftover_header=0.
/// leftover-readmit not queued: leftover_hit stayed 0 leftover_header=4.
/// Two session-start SHARES. MULTI died wrap_rx=6. Parser host-silent.
/// Not replace. T+600 unmet. Desk merge keeps wrap-4 leftover TX; LIVE
/// leftover_hit still did not re-accumulate.
pub fn admit_s19k_live444_merge_snapshot_header_only_does_not_readmit() -> Result<(), &'static str>
{
    if S19K_LIVE444_WRAP4_ADMIT_LEFTOVER_HIT != 3 {
        return Err("live444 leftover-admit leftover_hit must stay 3");
    }
    if S19K_LIVE444_WRAP5_SNAP_QUEUED != 1 {
        return Err("live444 wrap-5 leftover snapshot must stay 1");
    }
    if S19K_LIVE444_WRAP5_READMIT_QUEUED != 0 {
        return Err("live444 wrap-5 leftover-readmit must stay 0");
    }
    if S19K_LIVE444_WRAP_RX != 6 {
        return Err("live444 wrap_rx at MULTI death is 6");
    }
    if S19K_LIVE444_SHARES != 2 {
        return Err("live444 session-start SHARE count must stay 2");
    }
    if crate::s19k_braiins_job::s19k_leftover_hit_admits_experimental_inactive(
        S19K_LIVE444_POST_FLUSH_LEFTOVER_HIT,
        S19K_LIVE444_POST_FLUSH_LEFTOVER_HEADER,
        0,
    ) {
        return Err("live444 leftover_hit=0 leftover_header=4 must not leftover-admit");
    }
    Ok(())
}

pub fn refuse_s19k_live444_as_replace_or_t600() -> Result<(), &'static str> {
    Err("live444 wrap-5 merge leftover_hit=0 leftover_header=4 is not replace; T+600 unmet")
}

/// live445 first alive 18:49:45.298055Z; wrap-4 leftover-admit 18:51:50.332507Z.
pub const S19K_LIVE445_WRAP4_ADMIT_LEFTOVER_HIT: u32 = 2;
pub const S19K_LIVE445_WRAP4_ADMIT_MS: u32 = 125_034;
pub const S19K_LIVE445_WRAP5_SNAP_MS: u32 = 155_034;
pub const S19K_LIVE445_S1_LAST_RX_MS: u32 = 211_530;
pub const S19K_LIVE445_S2_LAST_RX_MS: u32 = 201_963;
pub const S19K_LIVE445_FROZEN_NONCES: u32 = 1745;
pub const S19K_LIVE445_SHARES: u32 = 1;
pub const S19K_LIVE445_WRAP_RX: u32 = 6;
pub const S19K_LIVE445_WRAP5_SNAP_QUEUED: u32 = 1;
pub const S19K_LIVE445_WRAP5_READMIT_QUEUED: u32 = 1;
pub const S19K_LIVE445_WRAP5_READMIT_LEFTOVER_HIT: u32 = 2;
pub const S19K_LIVE445_WRAP5_READMIT_LEFTOVER_HEADER: u32 = 0;
pub const S19K_LIVE445_WRAP7_READMIT_QUEUED: u32 = 0;
pub const S19K_LIVE445_POST_READMIT_LEFTOVER_HIT: u32 = 0;
pub const S19K_LIVE445_POST_READMIT_LEFTOVER_HEADER: u32 = 1;
pub const S19K_LIVE445_POST_READMIT_MEETS: u32 = 0;

/// live445 leftover-admit leftover_hit=2 leftover_at=2 leftover_header=0.
/// wrap-5 compact-TX-meet leftover_hit re-accumulated to 2 leftover_header=0
/// and leftover-readmit queued. leftover_header-only still refuses.
/// SHARE #1. MULTI died wrap_rx=6. Not replace. T+600 unmet.
pub fn admit_s19k_live445_leftover_hit_readmits_header_only_still_refuses(
) -> Result<(), &'static str> {
    if S19K_LIVE445_WRAP4_ADMIT_LEFTOVER_HIT != 2 {
        return Err("live445 leftover-admit leftover_hit must stay 2");
    }
    if S19K_LIVE445_WRAP5_READMIT_QUEUED != 1 {
        return Err("live445 wrap-5 leftover-readmit must stay 1");
    }
    if S19K_LIVE445_WRAP5_READMIT_LEFTOVER_HIT != 2 {
        return Err("live445 leftover-readmit leftover_hit must stay 2");
    }
    if S19K_LIVE445_WRAP5_READMIT_LEFTOVER_HEADER != 0 {
        return Err("live445 leftover-readmit leftover_header must stay 0");
    }
    if crate::s19k_braiins_job::s19k_leftover_header_admits_second_cmd3(0, 3, 0) {
        return Err("live440 leftover_header-only must still refuse leftover-readmit");
    }
    if !crate::s19k_braiins_job::s19k_leftover_hit_admits_experimental_inactive(
        S19K_LIVE445_WRAP5_READMIT_LEFTOVER_HIT,
        S19K_LIVE445_WRAP5_READMIT_LEFTOVER_HEADER,
        0,
    ) {
        return Err("live445 leftover_hit=2 leftover_header=0 leftover-readmits");
    }
    if crate::s19k_braiins_job::s19k_post_inactive_replace_proven(
        Some(S19K_LIVE445_WRAP4_ADMIT_LEFTOVER_HIT),
        S19K_LIVE445_WRAP5_READMIT_LEFTOVER_HIT,
        S19K_LIVE445_WRAP5_READMIT_LEFTOVER_HEADER,
        0,
    ) {
        return Err("live445 leftover_hit=2 meets=0 is not occupied-slot replace");
    }
    if S19K_LIVE445_WRAP7_READMIT_QUEUED != 0 {
        return Err("live445 wrap-7 leftover-readmit is honest non-queue (wrap_rx=6)");
    }
    if crate::s19k_braiins_job::s19k_wrap7_leftover_readmit_due(
        6,
        Some(S19K_LIVE445_WRAP4_ADMIT_LEFTOVER_HIT),
        S19K_LIVE445_POST_READMIT_LEFTOVER_HIT,
        S19K_LIVE445_POST_READMIT_LEFTOVER_HEADER,
        S19K_LIVE445_POST_READMIT_MEETS,
        false,
        false,
        true,
    ) {
        return Err(
            "live445 wrap_rx=6 leftover_hit=0 leftover_header=1 must not wrap-7 leftover-readmit",
        );
    }
    if crate::s19k_braiins_job::s19k_wrap7_leftover_readmit_due(
        7,
        Some(S19K_LIVE445_WRAP4_ADMIT_LEFTOVER_HIT),
        0,
        3,
        0,
        false,
        false,
        true,
    ) {
        return Err("live440 leftover_header-only must not wrap-7 leftover-readmit");
    }
    if !crate::s19k_braiins_job::s19k_wrap7_leftover_readmit_due(
        7,
        Some(S19K_LIVE445_WRAP4_ADMIT_LEFTOVER_HIT),
        2,
        0,
        0,
        false,
        false,
        true,
    ) {
        return Err("wrap-7 leftover_hit=2 leftover_header=0 leftover-readmits after wrap-5 leftover-readmit");
    }
    if crate::s19k_braiins_job::s19k_post_inactive_replace_proven(
        Some(S19K_LIVE445_WRAP4_ADMIT_LEFTOVER_HIT),
        S19K_LIVE445_POST_READMIT_LEFTOVER_HIT,
        S19K_LIVE445_POST_READMIT_LEFTOVER_HEADER,
        S19K_LIVE445_POST_READMIT_MEETS,
    ) {
        return Err(
            "live445 post leftover-readmit leftover_header=1 meets=0 is not occupied-slot replace",
        );
    }
    if !crate::s19k_braiins_job::s19k_post_inactive_replace_proven(
        Some(S19K_LIVE445_WRAP4_ADMIT_LEFTOVER_HIT),
        0,
        0,
        1,
    ) {
        return Err("post-admit leftover_header=0 leftover_hit=0 meets=1 is occupied-slot replace");
    }
    Ok(())
}

pub fn refuse_s19k_live445_as_replace_or_t600() -> Result<(), &'static str> {
    Err("live445 wrap-5 leftover-readmit leftover_hit=2 meets=0 is not replace; T+600 unmet")
}

/// live446 first alive 19:34:49.231682Z; ttyS1 last MULTI 19:38:18.128025Z;
/// ttyS2 last MULTI 19:38:07.958202Z. Session-start funnel cleans=1
/// leftover_at=None leftover_hit=20 leftover_header=0 wrap_rx=6.
pub const S19K_LIVE446_S1_LAST_RX_MS: u32 = 208_896;
pub const S19K_LIVE446_S2_LAST_RX_MS: u32 = 198_727;
pub const S19K_LIVE446_FROZEN_NONCES: u32 = 1729;
pub const S19K_LIVE446_SHARES: u32 = 0;
pub const S19K_LIVE446_WRAP_RX: u32 = 6;
pub const S19K_LIVE446_LEFTOVER_HIT: u32 = 20;
pub const S19K_LIVE446_LEFTOVER_HEADER: u32 = 0;
pub const S19K_LIVE446_WRAP4_ADMIT_QUEUED: u32 = 0;
pub const S19K_LIVE446_WRAP5_READMIT_QUEUED: u32 = 0;
pub const S19K_LIVE446_WRAP7_READMIT_QUEUED: u32 = 0;
pub const S19K_LIVE446_CLEANS: u32 = 1;

/// live446 session-start funnel cleans=1 leftover_at=None leftover_hit=20
/// leftover_header=0 wrap_rx=6. wrap-4 early used to require midrun_cleans==0,
/// so leftover-admit never queued. leftover_at=None is the wrap-4 early bar.
/// wrap-5/wrap-7 leftover-readmit still require leftover_at Some. leftover_
/// header-only still refuses. Not replace. T+600 unmet.
pub fn admit_s19k_live446_session_start_clean_does_not_block_wrap4_early(
) -> Result<(), &'static str> {
    if S19K_LIVE446_WRAP4_ADMIT_QUEUED != 0 {
        return Err("live446 wrap-4 leftover-admit never queued");
    }
    if S19K_LIVE446_WRAP5_READMIT_QUEUED != 0 {
        return Err("live446 wrap-5 leftover-readmit is honest non-queue leftover_at=None");
    }
    if S19K_LIVE446_WRAP7_READMIT_QUEUED != 0 {
        return Err(
            "live446 wrap-7 leftover-readmit is honest non-queue wrap_rx=6 leftover_at=None",
        );
    }
    if S19K_LIVE446_CLEANS != 1 {
        return Err("live446 session-start funnel cleans must stay 1");
    }
    if S19K_LIVE446_LEFTOVER_HIT != 20 {
        return Err("live446 leftover_hit must stay 20");
    }
    if S19K_LIVE446_LEFTOVER_HEADER != 0 {
        return Err("live446 leftover_header must stay 0");
    }
    if crate::s19k_braiins_job::s19k_wrap5_leftover_readmit_due(
        5,
        None,
        S19K_LIVE446_LEFTOVER_HIT,
        S19K_LIVE446_LEFTOVER_HEADER,
        0,
        false,
        false,
        true,
    ) {
        return Err("live446 leftover_at=None leftover_hit=20 must not wrap-5 leftover-readmit");
    }
    if crate::s19k_braiins_job::s19k_wrap7_leftover_readmit_due(
        6,
        None,
        S19K_LIVE446_LEFTOVER_HIT,
        S19K_LIVE446_LEFTOVER_HEADER,
        0,
        false,
        false,
        true,
    ) {
        return Err("live446 wrap_rx=6 leftover_at=None must not wrap-7 leftover-readmit");
    }
    if crate::s19k_braiins_job::s19k_leftover_header_admits_second_cmd3(0, 3, 0) {
        return Err("live440 leftover_header-only must still refuse leftover-readmit");
    }
    if !crate::s19k_braiins_job::s19k_wrap4_early_leftover_safe_due(4, None, false) {
        return Err("live446 session-start leftover_at=None wrap_rx=4 must wrap-4 early");
    }
    let plan = crate::s19k_braiins_job::s19k_plan_wrap4_early_leftover_safe(
        5,
        None,
        false,
        true,
        S19K_LIVE446_LEFTOVER_HIT,
        S19K_LIVE446_LEFTOVER_HEADER,
        0,
        false,
    );
    if !plan.chain_inactive || !plan.refill {
        return Err(
            "live446 leftover_hit=20 leftover_header=0 leftover_at=None leftover-admits wrap-4 early",
        );
    }
    let after = crate::s19k_braiins_job::s19k_plan_wrap4_early_leftover_safe(
        5,
        Some(S19K_LIVE446_LEFTOVER_HIT),
        false,
        true,
        S19K_LIVE446_LEFTOVER_HIT,
        S19K_LIVE446_LEFTOVER_HEADER,
        0,
        true,
    );
    if after.chain_inactive || after.refill {
        return Err(
            "after leftover-admit leftover_at=Some wrap-4 early must not leftover-admit again",
        );
    }
    if crate::s19k_braiins_job::s19k_post_inactive_replace_proven(
        None,
        S19K_LIVE446_LEFTOVER_HIT,
        S19K_LIVE446_LEFTOVER_HEADER,
        0,
    ) {
        return Err(
            "live446 leftover_at=None leftover_hit=20 meets=0 is not occupied-slot replace",
        );
    }
    if !crate::s19k_braiins_job::s19k_leftover_hit_admits_experimental_inactive(
        S19K_LIVE446_LEFTOVER_HIT,
        S19K_LIVE446_LEFTOVER_HEADER,
        0,
    ) {
        return Err("live446 leftover_hit=20 leftover_header=0 leftover-admits");
    }
    Ok(())
}

pub fn refuse_s19k_live446_as_replace_or_t600() -> Result<(), &'static str> {
    Err("live446 session-start cleans=1 leftover_at=None leftover_hit=20 is not replace; T+600 unmet")
}

/// live447 first alive 20:13:41.538071Z; wrap-4 leftover-admit 20:15:46.544425Z.
pub const S19K_LIVE447_WRAP4_ADMIT_LEFTOVER_HIT: u32 = 9;
pub const S19K_LIVE447_WRAP4_ADMIT_MS: u32 = 125_006;
pub const S19K_LIVE447_WRAP5_READMIT_MS: u32 = 155_007;
pub const S19K_LIVE447_S1_LAST_RX_MS: u32 = 203_122;
pub const S19K_LIVE447_S2_LAST_RX_MS: u32 = 191_480;
pub const S19K_LIVE447_FROZEN_NONCES: u32 = 1487;
pub const S19K_LIVE447_SHARES: u32 = 1;
pub const S19K_LIVE447_WRAP_RX: u32 = 6;
pub const S19K_LIVE447_WRAP4_ADMIT_QUEUED: u32 = 1;
pub const S19K_LIVE447_WRAP5_READMIT_QUEUED: u32 = 1;
pub const S19K_LIVE447_WRAP5_READMIT_LEFTOVER_HIT: u32 = 1;
pub const S19K_LIVE447_WRAP5_READMIT_LEFTOVER_HEADER: u32 = 0;
pub const S19K_LIVE447_WRAP7_READMIT_QUEUED: u32 = 0;
pub const S19K_LIVE447_DEATH_LEFTOVER_HIT: u32 = 185;
pub const S19K_LIVE447_DEATH_LEFTOVER_HEADER: u32 = 2;
pub const S19K_LIVE447_LEFTOVER_AT: u32 = 9;

/// live447 wrap-4 leftover-admit leftover_hit=9 leftover_at=9 leftover_header=0.
/// wrap-5 leftover-readmit leftover_hit=1 leftover_header=0 wrap_rx=5 independent
/// of wrap-7 leftover-readmit. wrap-7 leftover-readmit honest non-queue wrap_rx=6
/// leftover_hit=185 leftover_header=2 leftover_at=9. leftover_header-only still
/// refuses. SHARE #1. Not replace. T+600 unmet.
pub fn admit_s19k_live447_wrap4_admit_wrap5_readmit_wrap7_honest_nonqueue(
) -> Result<(), &'static str> {
    if S19K_LIVE447_WRAP4_ADMIT_QUEUED != 1 {
        return Err("live447 wrap-4 leftover-admit must stay 1");
    }
    if S19K_LIVE447_WRAP4_ADMIT_LEFTOVER_HIT != 9 {
        return Err("live447 wrap-4 leftover-admit leftover_hit must stay 9");
    }
    if S19K_LIVE447_WRAP5_READMIT_QUEUED != 1 {
        return Err("live447 wrap-5 leftover-readmit must stay 1");
    }
    if S19K_LIVE447_WRAP7_READMIT_QUEUED != 0 {
        return Err("live447 wrap-7 leftover-readmit is honest non-queue wrap_rx=6");
    }
    if crate::s19k_braiins_job::s19k_leftover_header_admits_second_cmd3(0, 3, 0) {
        return Err("live440 leftover_header-only must still refuse leftover-readmit");
    }
    if crate::s19k_braiins_job::s19k_wrap7_leftover_readmit_due(
        6,
        Some(S19K_LIVE447_LEFTOVER_AT),
        S19K_LIVE447_DEATH_LEFTOVER_HIT,
        S19K_LIVE447_DEATH_LEFTOVER_HEADER,
        0,
        false,
        false,
        true,
    ) {
        return Err(
            "live447 wrap_rx=6 leftover_hit=185 leftover_header=2 must not wrap-7 leftover-readmit",
        );
    }
    if !crate::s19k_braiins_job::s19k_wrap6_leftover_readmit_due(
        6,
        Some(S19K_LIVE447_LEFTOVER_AT),
        S19K_LIVE447_DEATH_LEFTOVER_HIT,
        S19K_LIVE447_DEATH_LEFTOVER_HEADER,
        0,
        false,
        false,
        true,
    ) {
        return Err(
            "live447 wrap_rx=6 leftover_hit=185 leftover_header=2 leftover-readmits wrap-6",
        );
    }
    if crate::s19k_braiins_job::s19k_wrap6_leftover_readmit_due(
        6,
        Some(S19K_LIVE447_LEFTOVER_AT),
        0,
        3,
        0,
        false,
        false,
        true,
    ) {
        return Err("live440 leftover_header-only must not wrap-6 leftover-readmit");
    }
    if !crate::s19k_braiins_job::s19k_wrap7_leftover_readmit_due(
        7,
        Some(S19K_LIVE447_LEFTOVER_AT),
        S19K_LIVE447_DEATH_LEFTOVER_HIT,
        S19K_LIVE447_DEATH_LEFTOVER_HEADER,
        0,
        false,
        false,
        true,
    ) {
        return Err("wrap-7 leftover_hit=185 leftover_header=2 leftover-readmits if wrap_rx>=7");
    }
    if crate::s19k_braiins_job::s19k_post_inactive_replace_proven(
        Some(S19K_LIVE447_LEFTOVER_AT),
        S19K_LIVE447_DEATH_LEFTOVER_HIT,
        S19K_LIVE447_DEATH_LEFTOVER_HEADER,
        0,
    ) {
        return Err(
            "live447 leftover_hit=185 leftover_header=2 meets=0 is not occupied-slot replace",
        );
    }
    if S19K_LIVE447_SHARES != 1 {
        return Err("live447 SHARE count must stay 1");
    }
    Ok(())
}

pub fn refuse_s19k_live447_as_replace_or_t600() -> Result<(), &'static str> {
    Err("live447 wrap-5 leftover-readmit leftover_hit=1 meets=0 is not replace; T+600 unmet")
}

/// live448 first alive 20:36:14.762Z; wrap-4 leftover-admit 20:38:19.769478Z.
pub const S19K_LIVE448_WRAP4_ADMIT_LEFTOVER_HIT: u32 = 1;
pub const S19K_LIVE448_WRAP4_ADMIT_MS: u32 = 125_007;
pub const S19K_LIVE448_S1_LAST_RX_MS: u32 = 279_890;
pub const S19K_LIVE448_S2_LAST_RX_MS: u32 = 275_098;
pub const S19K_LIVE448_FROZEN_NONCES: u32 = 2321;
pub const S19K_LIVE448_SHARES: u32 = 0;
pub const S19K_LIVE448_WRAP_RX: u32 = 9;
pub const S19K_LIVE448_WRAP4_ADMIT_QUEUED: u32 = 1;
pub const S19K_LIVE448_WRAP5_READMIT_QUEUED: u32 = 0;
pub const S19K_LIVE448_WRAP6_READMIT_QUEUED: u32 = 0;
pub const S19K_LIVE448_WRAP7_READMIT_QUEUED: u32 = 0;
pub const S19K_LIVE448_DEATH_LEFTOVER_HIT: u32 = 0;
pub const S19K_LIVE448_DEATH_LEFTOVER_HEADER: u32 = 8;
pub const S19K_LIVE448_LEFTOVER_AT: u32 = 1;

/// live448 wrap-4 leftover-admit leftover_hit=1 leftover_at=1 leftover_header=0.
/// wrap_rx=9 after leftover-admit hashed. leftover_hit stayed 0 leftover_header=8.
/// wrap-5/wrap-6/wrap-7 leftover-readmit honest non-queue leftover_header-only.
/// leftover_header-only still refuses. SHARES=0. Not replace. T+600 unmet.
pub fn admit_s19k_live448_wrap7_after_leftover_admit_header_only_does_not_readmit(
) -> Result<(), &'static str> {
    if S19K_LIVE448_WRAP4_ADMIT_QUEUED != 1 {
        return Err("live448 wrap-4 leftover-admit must stay 1");
    }
    if S19K_LIVE448_WRAP_RX != 9 {
        return Err("live448 wrap_rx after leftover-admit must stay 9");
    }
    if S19K_LIVE448_WRAP6_READMIT_QUEUED != 0 {
        return Err(
            "live448 wrap-6 leftover-readmit is honest non-queue leftover_hit=0 leftover_header=8",
        );
    }
    if S19K_LIVE448_WRAP7_READMIT_QUEUED != 0 {
        return Err(
            "live448 wrap-7 leftover-readmit is honest non-queue leftover_hit=0 leftover_header=8",
        );
    }
    if crate::s19k_braiins_job::s19k_leftover_header_admits_second_cmd3(0, 8, 0) {
        return Err("live448 leftover_header=8 leftover_hit=0 must not leftover-readmit");
    }
    if crate::s19k_braiins_job::s19k_wrap6_leftover_readmit_due(
        6,
        Some(S19K_LIVE448_LEFTOVER_AT),
        S19K_LIVE448_DEATH_LEFTOVER_HIT,
        S19K_LIVE448_DEATH_LEFTOVER_HEADER,
        0,
        false,
        false,
        true,
    ) {
        return Err("live448 leftover_hit=0 leftover_header=8 must not wrap-6 leftover-readmit");
    }
    if crate::s19k_braiins_job::s19k_wrap7_leftover_readmit_due(
        9,
        Some(S19K_LIVE448_LEFTOVER_AT),
        S19K_LIVE448_DEATH_LEFTOVER_HIT,
        S19K_LIVE448_DEATH_LEFTOVER_HEADER,
        0,
        false,
        false,
        true,
    ) {
        return Err("live448 leftover_hit=0 leftover_header=8 must not wrap-7 leftover-readmit");
    }
    if crate::s19k_braiins_job::s19k_post_inactive_replace_proven(
        Some(S19K_LIVE448_LEFTOVER_AT),
        S19K_LIVE448_DEATH_LEFTOVER_HIT,
        S19K_LIVE448_DEATH_LEFTOVER_HEADER,
        0,
    ) {
        return Err(
            "live448 leftover_hit=0 leftover_header=8 meets=0 is not occupied-slot replace",
        );
    }
    if crate::s19k_braiins_job::s19k_leftover_header_admits_second_cmd3(0, 8, 0) {
        return Err("live448 leftover_header=8 leftover_hit=0 must not leftover-readmit");
    }
    if crate::s19k_braiins_job::s19k_leftover_hit_slots_after_leftover_admit(
        Some(S19K_LIVE448_LEFTOVER_AT),
        &[7],
    )
    .len()
        != 256
    {
        return Err(
            "live448 leftover_hit re-accumulation hunts wrap-4 leftover 21 36 on every job_id",
        );
    }
    if !crate::s19k_braiins_job::s19k_leftover_hit_admits_experimental_inactive(2, 8, 0) {
        return Err("leftover_hit re-accumulation leftover-readmits even if leftover_header=8");
    }
    if crate::s19k_braiins_job::s19k_wrap6_leftover_readmit_due(
        6,
        Some(S19K_LIVE448_LEFTOVER_AT),
        2,
        8,
        0,
        false,
        false,
        true,
    ) == false
    {
        return Err("after leftover-admit leftover_hit re-accumulation wrap-6 leftover-readmits");
    }
    Ok(())
}

pub fn refuse_s19k_live448_as_replace_or_t600() -> Result<(), &'static str> {
    Err("live448 wrap_rx=9 leftover_hit=0 leftover_header=8 is not replace; T+600 unmet")
}

/// Dual-port MULTI liveness. Stamp on any UART body from that tty
/// (before history-stale continue) so silence is MULTI death, not a
/// leftover classifier miss.
pub fn s19k_track1_note_port_rx(
    path: Option<&str>,
    now: std::time::Instant,
    last_s1: &mut std::time::Instant,
    last_s2: &mut std::time::Instant,
) {
    match path {
        Some(p) if p.ends_with("ttyS1") => *last_s1 = now,
        Some(p) if p.ends_with("ttyS2") => *last_s2 = now,
        _ => {}
    }
}

pub fn s19k_track1_port_silent_s(last: std::time::Instant, now: std::time::Instant) -> u64 {
    now.saturating_duration_since(last).as_secs()
}

/// Alive line must print per-port silence so wrap-4 S1-then-S2 (live428
/// +7 s, live430 same class) is visible without grepping MULTI_RX.
pub fn admit_s19k_production_alive_prints_per_port_silent(src: &str) -> Result<(), &'static str> {
    if !src.contains("s19k_track1_note_port_rx") {
        return Err("nonce path must stamp s19k_track1_note_port_rx");
    }
    if !src.contains("s1_silent_s") || !src.contains("s2_silent_s") {
        return Err("alive line must print s1_silent_s and s2_silent_s");
    }
    if !src.contains("wrap_rx") || !src.contains("s19k_track1_note_wrap_at_rx") {
        return Err(
            "alive line must print wrap_rx from last UART RX (live432 TX wrap kept climbing)",
        );
    }
    if !src.contains("s19k_track1_port_silent_s") {
        return Err("alive line must compute silence via s19k_track1_port_silent_s");
    }
    if !src.contains("S19k track1 RX death class") {
        return Err("alive tick must log classify_s19k_track1_rx_death once at silent>=90");
    }
    Ok(())
}

/// live414 Serial I/O still matched at TX=1761; S2 died before TX=1844.
pub const S19K_LIVE414_ACTOR_TX_BEFORE_WRAP7: u32 = 1_761;
pub const S19K_LIVE414_ACTOR_TX_AFTER_S2_DEATH: u32 = 1_844;

pub fn admit_s19k_live414_rx_died_while_tx_crossed_wrap7() -> Result<(), &'static str> {
    if S19K_LIVE414_ACTOR_TX_BEFORE_WRAP7 >= S19K_LIVE414_WRAP7_TX {
        return Err("live414 still matched RX/TX before wrap-7");
    }
    if S19K_LIVE414_ACTOR_TX_AFTER_S2_DEATH <= S19K_LIVE414_WRAP7_TX {
        return Err("live414 TX had crossed wrap-7 after S2 death");
    }
    Ok(())
}

pub fn admit_s19k_production_rearm_skips_tx(src: &str) -> Result<(), &'static str> {
    let start = src
        .find("live417: ticket+HCN then immediate work TX")
        .ok_or("missing live417 re-arm/TX collision comment")?;
    let win = src.get(start..start.saturating_add(220)).unwrap_or("");
    if !win.contains("skip_tx_this_loop = true") {
        return Err("mid-run re-arm must skip TX this loop (live417 wrap-6)");
    }
    Ok(())
}

/// One Braiins fill UART registry cycle (log 0 ⇒ 0x100).
pub const S19K_UART_REGISTRY_WRAP_TX: u32 = 256;

/// Trip a wrap-barrier after each full 256-slot job_id cycle (wrap-1, wrap-2, …).
pub fn s19k_track1_wrap_barrier_due(total_tx: u64) -> bool {
    total_tx > 0 && total_tx % u64::from(S19K_UART_REGISTRY_WRAP_TX) == 0
}

/// Completed registry wraps (`total_tx / 256`). live428/430 MULTI died
/// near wrap-4 with GPIO437=0. Log-only — do not skip TX (live415/416).
pub fn s19k_track1_wrap_index(total_tx: u64) -> u64 {
    total_tx / u64::from(S19K_UART_REGISTRY_WRAP_TX)
}

/// Snapshot wrap at the last UART RX. After MULTI death, TX `wrap_idx`
/// keeps climbing (live432 wrap_idx=9 with frozen nonces). wrap_rx is
/// the wrap that still had chips.
pub fn s19k_track1_note_wrap_at_rx(total_work: u64, wrap_rx: &mut u64) {
    *wrap_rx = s19k_track1_wrap_index(total_work);
}

/// TX wrap after MULTI death is not wrap-N RX survival (live432 wrap_idx=9,
/// last RX T+155). Independent of leftover_hit.
pub fn s19k_track1_tx_wrap_after_rx_death(wrap_idx: u64, wrap_rx: u64) -> bool {
    wrap_idx > wrap_rx
}

/// Why dual-port MULTI stopped. Leftover, first-clean inactive, wrap, and
/// GPIO437 are independent axes — live432 inactive at leftover_hit=0 is
/// not leftover-admitted replace, and TX wrap after death is not wrap-7.
/// live433 wrap-6 died after an identity first-clean (inactive=0,
/// leftover_hit=0): TX wrap after death must not mask WrapNoClean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kTrack1RxDeathClass {
    GpioRailOff,
    FirstCleanInactive,
    LeftoverAfterClean,
    CleanAfterRxDeath,
    WrapNoClean,
}

/// live430/434: first pool clean after both ports already silent.
/// leftover_hit=0 is unmeasured, not "no leftover".
pub const S19K_TRACK1_CLEAN_AFTER_RX_SILENT_S: u64 = 30;

pub fn s19k_track1_clean_after_rx_death_ms(clean_ms: u32, last_rx_ms: u32) -> bool {
    last_rx_ms > 0 && clean_ms > last_rx_ms
}

pub fn s19k_track1_clean_after_rx_death_silent(s1_silent_s: u64, s2_silent_s: u64) -> bool {
    s1_silent_s.min(s2_silent_s) >= S19K_TRACK1_CLEAN_AFTER_RX_SILENT_S
}

pub fn classify_s19k_track1_rx_death(
    gpio437: Option<u8>,
    wrap_idx: u64,
    wrap_rx: u64,
    midrun_cleans: u64,
    leftover_hit: u32,
    leftover_at_first_inactive: Option<u32>,
    clean_after_rx_death: bool,
) -> S19kTrack1RxDeathClass {
    let _ = (wrap_idx, wrap_rx);
    if matches!(gpio437, Some(1)) {
        return S19kTrack1RxDeathClass::GpioRailOff;
    }
    if leftover_at_first_inactive == Some(0) {
        return S19kTrack1RxDeathClass::FirstCleanInactive;
    }
    if clean_after_rx_death && leftover_hit == 0 {
        return S19kTrack1RxDeathClass::CleanAfterRxDeath;
    }
    if midrun_cleans > 0 && leftover_hit > 0 {
        return S19kTrack1RxDeathClass::LeftoverAfterClean;
    }
    S19kTrack1RxDeathClass::WrapNoClean
}

pub fn admit_s19k_live432_rx_death_is_first_clean_inactive() -> Result<(), &'static str> {
    let class = classify_s19k_track1_rx_death(Some(0), 9, 5, 1, 0, Some(0), false);
    if class != S19kTrack1RxDeathClass::FirstCleanInactive {
        return Err("live432 RX death is first-clean inactive, not leftover-admitted replace");
    }
    if !s19k_track1_tx_wrap_after_rx_death(9, 5) {
        return Err("live432 TX wrap after RX death must stay true");
    }
    Ok(())
}

pub fn refuse_s19k_wrap_tx_skip_as_survival() -> Result<(), &'static str> {
    Err("wrap-barrier is log-only; skip_tx at wrap killed MULTI (live415/416); live414 no wrap action survived wrap-7")
}

/// wrap-6 TX count (`6 * 256`). Not an ESP 16-slot or 128-mod boundary.
pub const S19K_TRACK1_WRAP6_TX: u64 = 6 * S19K_UART_REGISTRY_WRAP_TX as u64;

/// Held UART classification of wrap-6 MULTI death. protocol.md names
/// TYPE_JOB + CMD 0..3 only. ESP `+8%128` is 16 chip-visible slots
/// (`1536/128 = 12` ESP-mod wraps at wrap-6, not a new opcode).
/// Braiins wrap (`c0d4ac`) is SystemTime registry, not a UART frame.
/// live415/416 TX-skip killed MULTI; live425 survived wrap-7+ with no
/// wrap UART; live433 wrap-6 identity is WrapNoClean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kHeldUartWrap6Class {
    NoHeldAbortOpcode,
}

pub fn classify_s19k_held_uart_wrap6() -> S19kHeldUartWrap6Class {
    S19kHeldUartWrap6Class::NoHeldAbortOpcode
}

pub fn s19k_esp_mod_wraps_at_track1_wrap6() -> u64 {
    S19K_TRACK1_WRAP6_TX / u64::from(S19K_ESP_BM1366_JOB_ID_MOD)
}

/// `55 AA 21 36` is Closed11d TYPE_JOB. `55 AA 53 05` is Chain Inactive.
/// Neither is a wrap-N abort.
pub fn s19k_held_uart_prefix_is_wrap6_abort(prefix: &[u8]) -> bool {
    let _ = prefix;
    false
}

pub fn refuse_s19k_held_uart_prefix_as_wrap6_abort(prefix: &[u8]) -> Result<(), &'static str> {
    if prefix.len() >= 4
        && prefix[0] == 0x55
        && prefix[1] == 0xAA
        && prefix[2] == 0x21
        && prefix[3] == 0x36
    {
        return Err("55 AA 21 36 is Closed11d TYPE_JOB, not wrap-6 abort");
    }
    if prefix.len() >= 4
        && prefix[0] == 0x55
        && prefix[1] == 0xAA
        && prefix[2] == 0x53
        && prefix[3] == 0x05
    {
        return Err("55 AA 53 05 is Chain Inactive, not wrap-6 abort");
    }
    if s19k_held_uart_prefix_is_wrap6_abort(prefix) {
        return Err("held UART has no wrap-6 abort prefix");
    }
    Ok(())
}

pub fn admit_s19k_wrap6_death_not_held_uart_abort() -> Result<(), &'static str> {
    if classify_s19k_held_uart_wrap6() != S19kHeldUartWrap6Class::NoHeldAbortOpcode {
        return Err("held UART wrap-6 class is no abort opcode");
    }
    if S19K_TRACK1_WRAP6_TX != 1536 {
        return Err("wrap-6 is 6*256 TX");
    }
    if s19k_esp_mod_wraps_at_track1_wrap6() != 12 {
        return Err("1536/128=12 ESP-mod wraps; not a new UART opcode");
    }
    let slots =
        s19k_esp_bm1366_job_slot_count(S19K_ESP_BM1366_JOB_ID_STEP, S19K_ESP_BM1366_JOB_ID_MOD)?;
    if slots != 16 {
        return Err("ESP chip-visible slots stay 16");
    }
    if classify_s19k_track1_rx_death(Some(0), 6, 6, 1, 0, None, false)
        != S19kTrack1RxDeathClass::WrapNoClean
    {
        return Err("live433 wrap-6 identity stays WrapNoClean");
    }
    if refuse_s19k_held_uart_prefix_as_wrap6_abort(&[0x55, 0xAA, 0x21, 0x36]).is_ok() {
        return Err("55 AA 21 36 must refuse as wrap-6 abort");
    }
    if refuse_s19k_held_uart_prefix_as_wrap6_abort(&[0x55, 0xAA, 0x53, 0x05]).is_ok() {
        return Err("55 AA 53 05 must refuse as wrap-6 abort");
    }
    Ok(())
}

pub fn refuse_s19k_wrap6_as_esp16_or_bosminer_registry() -> Result<(), &'static str> {
    Err("wrap-6 MULTI death is not ESP 16-slot overflow and not bosminer c0d4ac UART abort")
}

/// ESP `BM1366_send_work`: `id = (id + 8) % 128` → 16 chip-visible slots.
/// Bible "Max Jobs 16" matches. 0xF8 is the RX extract mask, not a 32-slot
/// table. Track-1 fill stays `job_id = work_id` (live first-fill shares).
pub const S19K_ESP_BM1366_JOB_ID_STEP: u8 = 8;
pub const S19K_ESP_BM1366_JOB_ID_MOD: u8 = 128;

pub fn s19k_esp_bm1366_job_slot_count(step: u8, modulus: u8) -> Result<u8, &'static str> {
    if step == 0 || modulus % step != 0 {
        return Err("ESP job_id step must divide the modulus");
    }
    Ok(modulus / step)
}

pub fn refuse_s19k_esp_plus8_mod128_as_track1_fill() -> Result<(), &'static str> {
    Err("ESP (id+8)%128 is 16 chip-visible slots; Track-1 Closed11d fill stays job_id=work_id")
}

/// bosminer UART `worker.rs:68` / registry wrap BL `FUN_00c0d4ac` is
/// SystemTime::now + dual NANOS_PER_SEC, not a chip job abort.
pub fn refuse_s19k_bosminer_registry_wrap_as_chip_uart_abort() -> Result<(), &'static str> {
    Err("bosminer registry wrap is a SystemTime scale cell (c0d4ac), not a UART job abort")
}

pub fn refuse_s19k_slower_tx_as_wrap7_survival() -> Result<(), &'static str> {
    Err("slowing TX so wrap-7 is after T+600 is not wrap-7 survival")
}

pub fn admit_s19k_live414_wrap7_trips_barrier() -> Result<(), &'static str> {
    if S19K_LIVE414_WRAP7_TX != 7 * S19K_UART_REGISTRY_WRAP_TX {
        return Err("live414 wrap-7 must be 7×256");
    }
    if !s19k_track1_wrap_barrier_due(u64::from(S19K_LIVE414_WRAP7_TX)) {
        return Err("wrap-7 TX must trip the wrap barrier");
    }
    if s19k_track1_wrap_barrier_due(0) || s19k_track1_wrap_barrier_due(1) {
        return Err("wrap barrier must not fire before a full registry cycle");
    }
    Ok(())
}

/// Actor must skip one TX burst on wrap. live415/416 drain+rearm killed MULTI.
pub fn admit_s19k_production_wrap_barrier(src: &str) -> Result<(), &'static str> {
    if !src.contains("s19k_track1_wrap_barrier_due") {
        return Err("actor must call s19k_track1_wrap_barrier_due");
    }
    if !src.contains("S19k passthrough wrap-barrier") {
        return Err("actor must log wrap-barrier");
    }
    if !src.contains("log-only; TX continues") {
        return Err("wrap-barrier must stay log-only (live414 wrap-7)");
    }
    if !src.contains("s19k_track1_wrap_index") {
        return Err("alive line must print wrap_idx from s19k_track1_wrap_index");
    }
    if !src.contains("skip_tx_this_loop") {
        return Err("8s re-arm may skip TX; wrap itself must not");
    }
    if !src.contains("tx_before_rx && !skip_tx_this_loop") {
        return Err("wrap-barrier must gate drain_tx with skip_tx_this_loop");
    }
    let start = src
        .find("s19k_track1_wrap_barrier_due(total_tx)")
        .ok_or("missing wrap-barrier due check")?;
    let win = src.get(start..start.saturating_add(450)).unwrap_or("");
    if win.contains("s19k_passthrough_rearm_writes") {
        return Err("wrap-barrier must not ticket+HCN (live416 T+74 death)");
    }
    if win.contains("BM1366_SERIAL_TX_MIN_INTERVAL_MS") {
        return Err("wrap-barrier must not retune TX interval");
    }
    Ok(())
}

/// Production must admit Track-1 leftover Serial+BM1366 on am3-s19k.
pub fn admit_s19k_production_track1_serial_not_native(src: &str) -> Result<(), &'static str> {
    if !src.contains("Track-1 Braiins leftover") {
        return Err("main.rs must name Track-1 Braiins leftover admit");
    }
    if !src.contains("live409 parked this path") {
        return Err("main.rs must keep the live409 BoardDesc-park comment");
    }
    Ok(())
}

/// Drain-all balanced the ports (388 vs 404). live401 was 366 vs 600.
pub fn admit_s19k_live403_multi_rx_counts_balanced() -> Result<(), &'static str> {
    let lo = S19K_LIVE403_S1_MULTI_RX.min(S19K_LIVE403_S2_MULTI_RX);
    let hi = S19K_LIVE403_S1_MULTI_RX.max(S19K_LIVE403_S2_MULTI_RX);
    if lo == 0 || hi / lo >= 2 {
        return Err("live403 required-port MULTI_RX counts must stay within 2x");
    }
    let old_lo = S19K_LIVE401_S1_MULTI_RX.min(S19K_LIVE401_S2_MULTI_RX);
    let old_hi = S19K_LIVE401_S1_MULTI_RX.max(S19K_LIVE401_S2_MULTI_RX);
    if hi.saturating_mul(old_lo) >= old_hi.saturating_mul(lo) {
        return Err("live403 MULTI_RX ratio must be tighter than live401 366:600");
    }
    Ok(())
}

/// Production Multi RX must drain every ready port into `pending_rx`.
pub fn admit_s19k_production_multi_rx_drains_all(src: &str) -> Result<(), &'static str> {
    if !src.contains("pending_rx") {
        return Err("Multi RX must own a pending_rx queue for sibling frames");
    }
    if !src.contains("let mut collected") || !src.contains("collected.push") {
        return Err("Multi RX must collect every ready port before returning");
    }
    Ok(())
}

/// Half-duplex BM1366: one work TX per actor loop. Burst-3 occupies the wire.
pub fn admit_s19k_production_bm1366_tx_burst_is_one(src: &str) -> Result<(), &'static str> {
    if !src.contains("BM1366_SERIAL_TX_BURST") {
        return Err("BM1366 must name BM1366_SERIAL_TX_BURST");
    }
    let start = src
        .find("let tx_burst_per_loop = if is_bm1362")
        .ok_or("missing tx_burst_per_loop selection")?;
    let win = src.get(start..start.saturating_add(280)).unwrap_or("");
    if !win.contains("} else if is_bm1366 {") {
        return Err("BM1366 must select its own TX burst");
    }
    if !win.contains("BM1366_SERIAL_TX_BURST") {
        return Err("BM1366 tx_burst must be BM1366_SERIAL_TX_BURST");
    }
    Ok(())
}

/// : Multi RX must name the tty that produced the body.
/// Console ttyS0 is never a hash-UART hit. Discover admits S1/S2/S3.
pub fn admit_s19k_multi_rx_path(path: &str) -> Result<(), &'static str> {
    if path == "/dev/ttyS0" {
        return Err("T8: Multi RX must not tag ttyS0 (console)");
    }
    if crate::s19k_uart_trans_job::BRAIINS_TTYS_DISCOVER.contains(&path) {
        return Ok(());
    }
    Err("T8: Multi RX path must be a Track-1 hash UART (ttyS1/S2/S3)")
}

/// Path table must stay 1:1 with opened backends and include both required ports.
pub fn admit_s19k_multi_rx_tables(
    opened_backends: usize,
    tagged_paths: usize,
) -> Result<(), &'static str> {
    if opened_backends < BRAIINS_TTYS_CANDIDATES.len() {
        return Err("T8: Multi RX table opened fewer than both Track-1 ports");
    }
    if opened_backends != tagged_paths {
        return Err("T8: Multi RX path tags must match opened backends 1:1");
    }
    Ok(())
}

/// Same tty twice is not dual-UART / 2-board proof ( leftover).
pub fn refuse_same_tty_as_dual_uart_proof(a: &str, b: &str) -> Result<(), &'static str> {
    if a == b {
        return Err("same tty twice is not dual-UART / 2-board proof");
    }
    Ok(())
}

/// Required-pair dual proof is ttyS1+ttyS2. ttyS3 is discover-only.
pub fn admit_s19k_required_dual_uart_paths(a: &str, b: &str) -> Result<(), &'static str> {
    admit_s19k_multi_rx_path(a)?;
    admit_s19k_multi_rx_path(b)?;
    refuse_same_tty_as_dual_uart_proof(a, b)?;
    let pair = [a, b];
    if pair.contains(&"/dev/ttyS1") && pair.contains(&"/dev/ttyS2") {
        return Ok(());
    }
    Err("dual-UART required-pair proof is ttyS1+ttyS2; ttyS3 is discover-only")
}

/// HAL `read_nonce_response` returns a **body** (no `AA 55`). Reconstruct
/// the 11-byte wire only when the body is 9; never invent preamble on a 7-cut.
pub fn observe_s19k_tagged_rx_body(
    path: &str,
    body: Option<&[u8]>,
    window_ms: u32,
) -> Result<crate::s19k_bm1366_uart_rx::S19kUartRxObservation, &'static str> {
    admit_s19k_multi_rx_path(path)?;
    Ok(match body {
        None | Some([]) => crate::s19k_bm1366_uart_rx::S19kUartRxObservation::Silence { window_ms },
        Some(b) => observe_get_address_bodies(&[b.to_vec()], window_ms),
    })
}

/// : record ttyS1+ttyS2 WorkDispatch observations. A join is
/// diagnostic only — never drop a single-port JobNonce share.
#[derive(Debug, Default, Clone)]
pub struct S19kDualWorkRxJoin {
    s1: Option<crate::s19k_bm1366_uart_rx::S19kUartRxObservation>,
    s2: Option<crate::s19k_bm1366_uart_rx::S19kUartRxObservation>,
}

impl S19kDualWorkRxJoin {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one tagged body. Returns a join only when both required
    /// ports have been observed. ttyS3 is ignored.
    pub fn record(
        &mut self,
        path: &str,
        body: Option<&[u8]>,
    ) -> Option<crate::s19k_bm1366_uart_rx::S19kRxDiag> {
        let obs = observe_s19k_tagged_rx_body(path, body, 10).ok()?;
        if path.ends_with("ttyS1") {
            self.s1 = Some(obs);
        } else if path.ends_with("ttyS2") {
            self.s2 = Some(obs);
        } else {
            return None;
        }
        let s1 = self.s1.as_ref()?;
        let s2 = self.s2.as_ref()?;
        classify_s19k_tagged_dual_uart_rx_after(
            crate::s19k_bm1366_uart_rx::S19kRxExpectedAfter::WorkDispatch,
            "/dev/ttyS1",
            s1,
            "/dev/ttyS2",
            s2,
            Ok(()),
        )
        .ok()
    }

    /// Record Silence on a required port that has never been observed.
    /// Used on empty Multi polls so one JobNonce + one unseen twin can
    /// become `SinglePortNotDualProof` without dropping a share.
    pub fn note_empty_if_unseen(
        &mut self,
        path: &str,
    ) -> Option<crate::s19k_bm1366_uart_rx::S19kRxDiag> {
        if path.ends_with("ttyS1") && self.s1.is_some() {
            return None;
        }
        if path.ends_with("ttyS2") && self.s2.is_some() {
            return None;
        }
        self.record(path, None)
    }
}

/// Production must join required-port WorkDispatch RX without dropping a share.
pub fn admit_s19k_production_joins_dual_uart_after_fill(src: &str) -> Result<(), &'static str> {
    if !src.contains("S19kDualWorkRxJoin") {
        return Err("production must own S19kDualWorkRxJoin beside outstanding fill TX");
    }
    if !src.contains("dual_work_rx.record(") {
        return Err("production must record tagged fill RX into the dual-UART join");
    }
    if !src.contains("hunt_s19k_bm1366_fill_from_admitted_tx_path") {
        return Err("dual join must sit on the admitted-TX-path fill hunt");
    }
    if !src.contains("admit_s19k_fill_hunt_on_tx_path") {
        return Err("dual join must not qualify RX from a path that received no work");
    }
    Ok(())
}

/// : production must record empty required-port polls.
pub fn admit_s19k_production_records_empty_work_polls(src: &str) -> Result<(), &'static str> {
    if !src.contains("note_empty_if_unseen") {
        return Err("production must note empty ttyS1/ttyS2 polls into DualWorkRxJoin");
    }
    if !src.contains("classify_s19k_bm1366_rx_after") {
        return Err("production GetAddress must log typed S19kRxDiag");
    }
    Ok(())
}

/// : GetAddress TX failure is a host/UART error, not ASIC Silence.
pub fn admit_s19k_production_getaddress_tx_fail_is_framing(src: &str) -> Result<(), &'static str> {
    let tx = src
        .find("S19k GetAddress TX failed")
        .ok_or("missing GetAddress TX fail log")?;
    let end = (tx + 240).min(src.len());
    let window = &src[tx..end];
    if window.contains("S19kPortAnswer::Silence") {
        return Err("GetAddress TX fail must not be classified as Silence");
    }
    if !window.contains("S19kPortAnswer::FramingOrEcho") {
        return Err("GetAddress TX fail must be FramingOrEcho");
    }
    Ok(())
}

/// Tagged join: refuse same-path / S1+S3-as-required, then  classify.
pub fn classify_s19k_tagged_dual_uart_rx_after(
    after: crate::s19k_bm1366_uart_rx::S19kRxExpectedAfter,
    a_path: &str,
    a: &crate::s19k_bm1366_uart_rx::S19kUartRxObservation,
    b_path: &str,
    b: &crate::s19k_bm1366_uart_rx::S19kUartRxObservation,
    baud: Result<(), &'static str>,
) -> Result<crate::s19k_bm1366_uart_rx::S19kRxDiag, &'static str> {
    admit_s19k_required_dual_uart_paths(a_path, b_path)?;
    Ok(crate::s19k_bm1366_uart_rx::classify_s19k_dual_uart_rx_after(after, a, b, baud))
}

/// `a lab unit` dmesg meson UART probe (independent hash UARTs, not a mux).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kDmesgTtyProbe {
    pub tty: u8,
    pub mmio: u32,
    pub irq: u32,
}

/// `a lab unit` dmesg meson baud change (`0 → 9600`, `9600 → 115200`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kDmesgUartWake {
    pub tty: u8,
    pub from_baud: u32,
    pub to_baud: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19k78DmesgUartCensus {
    pub tty_s1_hash_wake: bool,
    pub tty_s2_hash_wake: bool,
    pub tty_s3_hash_wake: bool,
    pub tty_s0_hash_wake: bool,
}

/// Exact first-wake lines from `a lab unit` `cap_init/dmesg.before`.
pub const S19K_78_DMESG_WAKE_FIXTURE: &str = "\
[   45.501649] meson_uart ff804000.serial: ttyS3 use xtal(24M) 24000000 change 0 to 9600
[   45.506507] meson_uart ffd23000.serial: ttyS2 use xtal(24M) 24000000 change 0 to 9600
[   45.514003] meson_uart ffd24000.serial: ttyS1 use xtal(24M) 24000000 change 0 to 9600
[   46.559962] meson_uart ff804000.serial: ttyS3 use xtal(24M) 24000000 change 9600 to 115200
[   46.566236] meson_uart ffd23000.serial: ttyS2 use xtal(24M) 24000000 change 9600 to 115200
[   46.574658] meson_uart ffd24000.serial: ttyS1 use xtal(24M) 24000000 change 9600 to 115200
[   66.270975] meson_uart ff803000.serial: ttyS0 use xtal(24M) 24000000 change 115200 to 115200
";

pub const S19K_78_TTYS0_MMIO: u32 = 0xFF80_3000;
pub const S19K_78_TTYS1_MMIO: u32 = 0xFFD2_4000;
pub const S19K_78_TTYS2_MMIO: u32 = 0xFFD2_3000;
pub const S19K_78_TTYS3_MMIO: u32 = 0xFF80_4000;
pub const S19K_78_TTYS0_IRQ: u32 = 13;
pub const S19K_78_TTYS1_IRQ: u32 = 25;
pub const S19K_78_TTYS2_IRQ: u32 = 26;
pub const S19K_78_TTYS3_IRQ: u32 = 14;

/// `ff804000.serial: ttyS3 at MMIO 0xff804000 (irq = 14, …) is a meson_uart`
pub fn parse_s19k_dmesg_tty_probe(line: &str) -> Option<S19kDmesgTtyProbe> {
    let tty_idx = line.find("ttyS")?;
    let tty = line[tty_idx + 4..].chars().next()?.to_digit(10)? as u8;
    let mmio_idx = line.find("at MMIO 0x")?;
    let mmio_hex = line[mmio_idx + 10..].split_whitespace().next()?;
    let mmio = u32::from_str_radix(mmio_hex, 16).ok()?;
    let irq_idx = line.find("(irq = ")?;
    let irq_digits: String = line[irq_idx + 7..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let irq = irq_digits.parse().ok()?;
    Some(S19kDmesgTtyProbe { tty, mmio, irq })
}

/// `meson_uart ff804000.serial: ttyS3 use xtal(24M) 24000000 change 0 to 9600`
pub fn parse_s19k_dmesg_uart_wake(line: &str) -> Option<S19kDmesgUartWake> {
    let tty_idx = line.find("ttyS")?;
    let tty = line[tty_idx + 4..].chars().next()?.to_digit(10)? as u8;
    let change_idx = line.find(" change ")?;
    let after = &line[change_idx + 8..];
    let mut parts = after.split(" to ");
    let from_baud = parts.next()?.trim().parse().ok()?;
    let to_baud = parts.next()?.trim().parse().ok()?;
    Some(S19kDmesgUartWake {
        tty,
        from_baud,
        to_baud,
    })
}

/// Hash UARTs are S1+S2+S3. Console S0 must not look like a 0→9600 hash wake.
pub fn classify_s19k_78_dmesg_hash_uart_wakes(
    dmesg: &str,
) -> Result<S19k78DmesgUartCensus, &'static str> {
    let mut saw_0_9600 = [false; 4];
    let mut saw_9600_115200 = [false; 4];
    for line in dmesg.lines() {
        let Some(w) = parse_s19k_dmesg_uart_wake(line) else {
            continue;
        };
        if w.tty > 3 {
            continue;
        }
        if w.from_baud == 0 && w.to_baud == 9600 {
            saw_0_9600[w.tty as usize] = true;
        }
        if w.from_baud == 9600 && w.to_baud == 115200 {
            saw_9600_115200[w.tty as usize] = true;
        }
    }
    if !(saw_0_9600[1] && saw_0_9600[2] && saw_0_9600[3]) {
        return Err("dmesg missing 0→9600 on ttyS1+S2+S3");
    }
    if !(saw_9600_115200[1] && saw_9600_115200[2] && saw_9600_115200[3]) {
        return Err("dmesg missing 9600→115200 on ttyS1+S2+S3");
    }
    if saw_0_9600[0] {
        return Err("ttyS0 0→9600 would make console a hash UART; unexpected on .78");
    }
    Ok(S19k78DmesgUartCensus {
        tty_s1_hash_wake: true,
        tty_s2_hash_wake: true,
        tty_s3_hash_wake: true,
        tty_s0_hash_wake: false,
    })
}

/// `meson_uart ffd24000.serial: ttyS1 …`
pub fn parse_s19k_dmesg_uart_controller(line: &str) -> Option<(u8, u32)> {
    let p = line.find("meson_uart ")?;
    let rest = &line[p + 11..];
    let dot = rest.find(".serial")?;
    let mmio = u32::from_str_radix(&rest[..dot], 16).ok()?;
    let tty_idx = rest.find("ttyS")?;
    let tty = rest[tty_idx + 4..].chars().next()?.to_digit(10)? as u8;
    Some((tty, mmio))
}

/// Kernel name ↔ MMIO on `a lab unit`. Not a hashboard-slot map.
pub fn admit_s19k_78_kernel_ttys_mmio(tty: u8, mmio: u32) -> Result<(), &'static str> {
    let want = match tty {
        0 => S19K_78_TTYS0_MMIO,
        1 => S19K_78_TTYS1_MMIO,
        2 => S19K_78_TTYS2_MMIO,
        3 => S19K_78_TTYS3_MMIO,
        _ => return Err("only ttyS0-3 are pinned on .78"),
    };
    if mmio != want {
        return Err(".78 dmesg MMIO does not match pinned kernel tty");
    }
    Ok(())
}

pub fn refuse_console_mmio_as_hash_uart(mmio: u32) -> Result<(), &'static str> {
    if mmio == S19K_78_TTYS0_MMIO {
        return Err("0xFF803000 is ttyS0 console; refuse as hash UART");
    }
    Ok(())
}

/// Wake fixture must name all four controllers with the pinned MMIOs.
pub fn admit_s19k_78_dmesg_wakes_match_kernel_mmio(dmesg: &str) -> Result<(), &'static str> {
    let mut saw = [false; 4];
    for line in dmesg.lines() {
        let Some((tty, mmio)) = parse_s19k_dmesg_uart_controller(line) else {
            continue;
        };
        if tty > 3 {
            continue;
        }
        admit_s19k_78_kernel_ttys_mmio(tty, mmio)?;
        saw[tty as usize] = true;
    }
    if !(saw[0] && saw[1] && saw[2] && saw[3]) {
        return Err(".78 wake fixture must name ttyS0-3 controllers");
    }
    Ok(())
}

/// VNish DTB serial nodes match `a lab unit` dmesg MMIOs. Aliases stay unbound.
pub fn admit_s19k_dtb_serials_match_78_kernel_mmio() -> Result<(), &'static str> {
    use crate::s19k_aml_dtb::{
        VNISH_S19K_AML_AO_UART0_MMIO, VNISH_S19K_AML_AO_UART1_MMIO, VNISH_S19K_AML_EE_UART_A_MMIO,
        VNISH_S19K_AML_EE_UART_B_MMIO,
    };
    if VNISH_S19K_AML_AO_UART0_MMIO != S19K_78_TTYS0_MMIO {
        return Err("DTB serial@3000 must be ttyS0 0xFF803000");
    }
    if VNISH_S19K_AML_EE_UART_A_MMIO != S19K_78_TTYS1_MMIO {
        return Err("DTB serial@ffd24000 is ttyS1");
    }
    if VNISH_S19K_AML_EE_UART_B_MMIO != S19K_78_TTYS2_MMIO {
        return Err("DTB serial@ffd23000 is ttyS2");
    }
    if VNISH_S19K_AML_AO_UART1_MMIO != S19K_78_TTYS3_MMIO {
        return Err("DTB serial@4000 is ttyS3 0xFF804000");
    }
    Ok(())
}

///  “three boards never use ttyS3” is reversed by `a lab unit` dmesg.
pub fn refuse_wave26_two_uart_three_board_mux() -> Result<(), &'static str> {
    Err("Wave-26 2-UART/3-board mux is falsified: .78 dmesg termios-wakes ttyS1+S2+S3")
}

/// S21 AXG `/dev/ttyS4` is not the S19k third hash UART.
pub fn refuse_s19k_axg_ttys4_as_third_hash_uart() -> Result<(), &'static str> {
    Err(".78 dmesg has meson ttyS1+S2+S3; ttyS4 is S21 AXG, not the S19k third hash UART")
}

/// One `/proc/interrupts` meson_uart line: (linux irq, summed CPU counts).
pub fn parse_s19k_proc_interrupts_meson_uart(line: &str) -> Option<(u32, u64)> {
    if !line.contains("meson_uart") {
        return None;
    }
    let mut parts = line.split_whitespace();
    let irq_tok = parts.next()?;
    let irq = irq_tok.trim_end_matches(':').parse().ok()?;
    let mut sum = 0u64;
    for _ in 0..4 {
        sum = sum.saturating_add(parts.next()?.parse().ok()?);
    }
    Some((irq, sum))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19k78IrqDelta {
    pub tty_s0_delta: i64,
    pub tty_s1_delta: i64,
    pub tty_s2_delta: i64,
    pub tty_s3_delta: i64,
}

pub const S19K_78_IRQ_BEFORE_FIXTURE: &str = "\
 13:        359          0          0          0     GIC-0 225 Edge      meson_uart
 14:          0      30792          0          0     GIC-0 229 Edge      meson_uart
 25:          0          0          0          0     GIC-0  58 Edge      meson_uart
 26:          0          0          0          0     GIC-0 107 Edge      meson_uart
";

pub const S19K_78_IRQ_AFTER_FIXTURE: &str = "\
 13:        374          0          0          0     GIC-0 225 Edge      meson_uart
 14:          0      31144          0          0     GIC-0 229 Edge      meson_uart
 25:          0          0          0          0     GIC-0  58 Edge      meson_uart
 26:          0          0          0          0     GIC-0 107 Edge      meson_uart
";

fn irq_sum_map(text: &str) -> Result<std::collections::BTreeMap<u32, u64>, &'static str> {
    let mut map = std::collections::BTreeMap::new();
    for line in text.lines() {
        if let Some((irq, sum)) = parse_s19k_proc_interrupts_meson_uart(line) {
            map.insert(irq, sum);
        }
    }
    if map.is_empty() {
        return Err("no meson_uart rows");
    }
    Ok(map)
}

/// `a lab unit` cap_init interrupts: only ttyS3 (linux irq 14) takes hash RX.
pub fn classify_s19k_78_irq_delta(
    before: &str,
    after: &str,
) -> Result<S19k78IrqDelta, &'static str> {
    let b = irq_sum_map(before)?;
    let a = irq_sum_map(after)?;
    let delta = |irq: u32| -> Result<i64, &'static str> {
        let bv = *b.get(&irq).ok_or("missing before irq")?;
        let av = *a.get(&irq).ok_or("missing after irq")?;
        Ok(av as i64 - bv as i64)
    };
    let d = S19k78IrqDelta {
        tty_s0_delta: delta(S19K_78_TTYS0_IRQ)?,
        tty_s1_delta: delta(S19K_78_TTYS1_IRQ)?,
        tty_s2_delta: delta(S19K_78_TTYS2_IRQ)?,
        tty_s3_delta: delta(S19K_78_TTYS3_IRQ)?,
    };
    if d.tty_s3_delta <= 0 {
        return Err(".78 irq 14 (ttyS3) must increase across the capture window");
    }
    if d.tty_s1_delta != 0 || d.tty_s2_delta != 0 {
        return Err(".78 irq 25/26 (ttyS1/S2) stayed 0; unexpected hash RX");
    }
    Ok(d)
}

/// Rebuild full UART frames from HAL response **bodies** (no preamble)
/// so the RX hunter can classify GetAddress silence vs ChipAddress.
///
/// : an empty *window* is Silence. A present HAL body-7 (or any
/// wrong length) is **not** Silence — do not invent `AA 55` + HAL body-7,
/// and do not collapse that into an empty window.
pub fn observe_get_address_bodies(
    bodies: &[Vec<u8>],
    window_ms: u32,
) -> crate::s19k_bm1366_uart_rx::S19kUartRxObservation {
    use crate::s19k_bm1366_uart_rx::{
        observe_bm1366_uart_rx, BM1366_UART_RESP_BODY_LEN, UART_RESP_PREAMBLE,
    };
    if bodies.is_empty() {
        return observe_bm1366_uart_rx(&[], window_ms);
    }
    let mut nine = Vec::new();
    let mut first_wrong: Option<&[u8]> = None;
    for body in bodies {
        if body.len() == BM1366_UART_RESP_BODY_LEN {
            nine.extend_from_slice(&UART_RESP_PREAMBLE);
            nine.extend_from_slice(body);
        } else if first_wrong.is_none() {
            first_wrong = Some(body.as_slice());
        }
    }
    if !nine.is_empty() {
        return observe_bm1366_uart_rx(&nine, window_ms);
    }
    // Wrong-length bodies stay raw so the hunter reports NoPreamble/ShortFrame.
    observe_bm1366_uart_rx(first_wrong.unwrap_or(&[]), window_ms)
}

/// HAL default 7-byte cut is UART-config / hunter-length, not an empty window.
pub fn refuse_hal_body7_observe_as_silence(
    obs: &crate::s19k_bm1366_uart_rx::S19kUartRxObservation,
) -> Result<(), &'static str> {
    if matches!(
        obs,
        crate::s19k_bm1366_uart_rx::S19kUartRxObservation::Silence { .. }
    ) {
        return Err("HAL body-7 / wrong-length RX is framing, not Silence");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_opens_s1_s2_never_s0_s3_until_evidenced() {
        assert_eq!(
            braiins_ttys_to_open(),
            &["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"]
        );
        assert_eq!(braiins_ttys_required(), &["/dev/ttyS1", "/dev/ttyS2"]);
        assert!(s19k_port_open_is_optional("/dev/ttyS3"));
        assert!(!s19k_port_open_is_optional("/dev/ttyS1"));
        assert!(!s19k_port_open_is_optional("/dev/ttyS2"));
        assert_eq!(
            crate::s19k_uart_trans_job::BRAIINS_TTYS_FORBIDDEN,
            &["/dev/ttyS0"]
        );
        assert!(admit_discover_open_path("/dev/ttyS1").is_ok());
        assert!(admit_discover_open_path("/dev/ttyS2").is_ok());
        assert!(admit_discover_open_path("/dev/ttyS3").is_ok());
        assert!(admit_discover_open_path("/dev/ttyS0").is_err());
        assert!(refuse_hardcoded_physical_to_tty("/dev/ttyS1", 1).is_err());
        assert!(refuse_hardcoded_physical_to_tty("/dev/ttyS1", 3).is_err());
        assert!(refuse_hardcoded_physical_to_tty("/dev/ttyS3", 1).is_err());
        assert!(admit_braiins_mining_on_ports(&["/dev/ttyS1", "/dev/ttyS2"]).is_ok());
        let one_up = S19kPortRxMatrix {
            s1: S19kPortAnswer::ChipAddress {
                chip_id: 0x1366,
                count: 12,
            },
            s2: S19kPortAnswer::Silence,
            s3: S19kPortAnswer::Silence,
        };
        assert_eq!(s19k_required_ports_answered(one_up), 1);
        assert!(refuse_one_required_port_as_dual_chain_proof(one_up).is_err());
        let two_up = S19kPortRxMatrix {
            s1: S19kPortAnswer::ChipAddress {
                chip_id: 0x1366,
                count: 12,
            },
            s2: S19kPortAnswer::ChipAddress {
                chip_id: 0x1366,
                count: 12,
            },
            s3: S19kPortAnswer::Silence,
        };
        assert_eq!(s19k_required_ports_answered(two_up), 2);
        assert!(refuse_one_required_port_as_dual_chain_proof(two_up).is_ok());
        assert!(refuse_zero_required_ports_as_dual_chain_proof(two_up).is_ok());
        let s3_only = S19kPortRxMatrix {
            s1: S19kPortAnswer::Silence,
            s2: S19kPortAnswer::Silence,
            s3: S19kPortAnswer::ChipAddress {
                chip_id: 0x1366,
                count: 8,
            },
        };
        assert_eq!(s19k_required_ports_answered(s3_only), 0);
        assert!(refuse_one_required_port_as_dual_chain_proof(s3_only).is_ok());
        assert!(refuse_zero_required_ports_as_dual_chain_proof(s3_only).is_err());
        assert!(refuse_s3_only_as_required_pair_proof(s3_only).is_err());
        assert!(refuse_s3_only_as_required_pair_proof(two_up).is_ok());
        let ticket = crate::s19k_bm1366_uart_rx::bm1366_rearm_ticket_reply_uart();
        assert_eq!(
            classify_port_rx_bytes(&ticket),
            S19kPortAnswer::FramingOrEcho
        );
        let ticket_obs = crate::s19k_bm1366_uart_rx::observe_bm1366_uart_rx(&ticket, 10);
        assert_eq!(
            s19k_port_answer_from_rx(&ticket_obs),
            S19kPortAnswer::FramingOrEcho
        );
        let enum0 = crate::s19k_bm1366_uart_rx::bm1366_chip_address_uart(0);
        assert!(matches!(
            classify_port_rx_bytes(&enum0),
            S19kPortAnswer::ChipAddress {
                chip_id: 0x1366,
                count: 1
            }
        ));
        assert!(format_s19k_port_rx_matrix(one_up).contains("required_answered=1"));
        let chip_hex = "aa 55 13 66 00 00 00 00 00 00 05";
        assert!(matches!(
            classify_port_rx_hex(chip_hex),
            S19kPortAnswer::ChipAddress {
                chip_id: 0x1366,
                count: 1
            }
        ));
        assert_eq!(classify_port_rx_hex("-"), S19kPortAnswer::Silence);
        assert_eq!(classify_port_rx_hex(""), S19kPortAnswer::Silence);
        assert_eq!(
            classify_port_rx_bytes(HELD_78_CAP_SERIAL_S1),
            S19kPortAnswer::Silence
        );
        assert_eq!(
            classify_port_rx_bytes(HELD_78_CAP_SERIAL_S2),
            S19kPortAnswer::Silence
        );
        assert_eq!(
            classify_port_rx_bytes(HELD_78_CAP_SERIAL_S3),
            S19kPortAnswer::FramingOrEcho
        );
        assert!(refuse_held_78_cap_serial_as_bm1366_golden().is_err());
        assert!(matches!(
            crate::s19k_bm1366_uart_rx::observe_bm1366_uart_rx(HELD_78_CAP_SERIAL_S3, 0),
            crate::s19k_bm1366_uart_rx::S19kUartRxObservation::NoPreamble { nbytes: 3, .. }
        ));
        assert_eq!(
            classify_port_rx_hex("55 aa 40 05 00 00 1c"),
            S19kPortAnswer::FramingOrEcho
        );
        let one_hex = port_rx_matrix_from_hex(chip_hex, "-", "");
        assert_eq!(s19k_required_ports_answered(one_hex), 1);
        assert!(refuse_one_required_port_as_dual_chain_proof(one_hex).is_err());
        assert!(admit_braiins_mining_on_ports(&["/dev/ttyS1"]).is_err());
        assert!(admit_braiins_mining_on_ports(&["/dev/ttyS2"]).is_err());
        assert!(admit_braiins_mining_on_ports(&["/dev/ttyS1", "/dev/ttyS3"]).is_err());
        assert!(admit_braiins_mining_on_ports(&["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"]).is_ok());
        assert_eq!(LIVE_20260812_POPULATION.physical_present, &[2, 3]);
        assert_eq!(
            discover_plan_paths(),
            &["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"]
        );
        // serial_mining mining-on 2026-08-12 opened only ttyS1 — that is now refused.
        let source = include_str!("s19k_braiins_chain_discover.rs");
        assert!(source.contains("admit_braiins_mining_on_ports"));
        assert!(bind_physical_by_answer(
            "/dev/ttyS1",
            S19kPortAnswer::ChipAddress {
                chip_id: 0x1366,
                count: 1
            }
        )
        .unwrap()
        .is_none());
        assert_eq!(
            bind_port_after_rx(
                "/dev/ttyS1",
                S19kPortAnswer::ChipAddress {
                    chip_id: 0x1366,
                    count: 12
                }
            )
            .unwrap(),
            S19kPortBind::AnsweredGetAddress {
                chip_id: 0x1366,
                count: 12
            }
        );
        assert_eq!(
            bind_port_after_rx("/dev/ttyS2", S19kPortAnswer::Silence).unwrap(),
            S19kPortBind::Unbound
        );
        assert!(admit_ttys3_open(S19kTtys3Evidence::default()).is_err());
        assert!(
            admit_ttys3_open(S19kTtys3Evidence {
                plug439_present: true,
                ..S19kTtys3Evidence::default()
            })
            .is_err(),
            ".78 three plugs must not lift ttyS3"
        );
        assert!(admit_ttys3_open(S19kTtys3Evidence {
            getaddress_rx: true,
            ..S19kTtys3Evidence::default()
        })
        .is_ok());
        assert_eq!(LIVE_78_20251204_POPULATION.physical_present, &[1, 2, 3]);
        assert!(admit_s19k_plug_count_vs_uart_count(3, &["/dev/ttyS1", "/dev/ttyS2"]).is_err());
        assert!(admit_s19k_plug_count_vs_uart_count(
            3,
            &["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"]
        )
        .is_ok());
        assert!(refuse_wave26_two_uart_three_board_mux().is_err());
        assert!(refuse_s19k_axg_ttys4_as_third_hash_uart().is_err());
        assert!(admit_braiins_job_tx_path("/dev/ttyS4").is_err());
        // Config leftover ttyS2-only must still discover all three hash UARTs.
        assert_eq!(
            plan_s19k_braiins_mining_on_ports(Some("/dev/ttyS2")).unwrap(),
            &["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"]
        );
        assert_eq!(
            plan_s19k_braiins_mining_on_ports(Some("/dev/ttyS1")).unwrap(),
            &["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"]
        );
        assert!(plan_s19k_braiins_mining_on_ports(Some("/dev/ttyS0")).is_err());
        assert!(admit_braiins_mining_on_ports(&["/dev/ttyS1"]).is_err());
        let silence = observe_get_address_bodies(&[], 250);
        assert!(matches!(
            silence,
            crate::s19k_bm1366_uart_rx::S19kUartRxObservation::Silence { .. }
        ));
        let serial_mining = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_getaddress_tx_fail_is_framing(serial_mining).is_ok());
        assert!(admit_s19k_production_getaddress_tx_fail_is_framing(
            "S19k GetAddress TX failed\n                    S19kPortAnswer::Silence\n"
        )
        .is_err());
        assert!(
            serial_mining.contains("plan_s19k_braiins_mining_on_ports"),
            "serial_mining must call the shipped dual-port planner"
        );
        assert!(serial_mining.contains("passthrough && is_bm1366"));
        assert!(serial_mining.contains("SerialWorkTransport::Multi"));
        assert!(admit_s19k_multi_send_work(2, 2).is_ok());
        assert!(admit_s19k_multi_send_work(3, 3).is_ok());
        assert!(admit_s19k_multi_send_work(1, 2).is_err());
        assert!(admit_s19k_multi_send_work(2, 3).is_ok());
        assert!(admit_s19k_multi_send_work(1, 3).is_err());
        assert!(admit_s19k_multi_send_work(0, 2).is_err());
        assert!(admit_s19k_multi_send_work(1, 1).is_err());
        assert!(admit_s19k_multi_send_work(3, 2).is_err());
        assert!(s19k_work_tx_required_after_enum("/dev/ttyS1", false));
        assert!(s19k_work_tx_required_after_enum("/dev/ttyS2", false));
        assert!(!s19k_work_tx_required_after_enum("/dev/ttyS3", false));
        assert!(s19k_work_tx_required_after_enum("/dev/ttyS3", true));
        assert!(s19k_complete77_is_work_baud_proof(BRAIINS_TTYS_BAUD, true));
        assert!(!s19k_complete77_is_work_baud_proof(115_200, true));
        assert!(!s19k_complete77_is_work_baud_proof(
            BRAIINS_TTYS_BAUD,
            false
        ));
        assert!(serial_mining
            .contains("s19k_complete77_is_work_baud_proof(s.baud(), enum_complete_77)"));
        let retry_start = serial_mining
            .find("let retry_rx = match s.send_get_address_bm1397plus()")
            .expect("115200 diagnostic retry");
        let retry_end = serial_mining[retry_start..]
            .find("S19k EXPERIMENTAL 115200 GetAddress retry")
            .map(|offset| retry_start + offset)
            .expect("115200 retry log");
        let retry = &serial_mining[retry_start..retry_end];
        assert!(retry.contains("let retry_complete_77 = matches!"));
        assert!(!retry.contains("enum_complete_77_at_work_baud |="));
        assert!(!retry.contains("enum_complete_77_at_work_baud ="));
        assert!(admit_s19k_fill_hunt_on_tx_path(
            "/dev/ttyS3",
            &["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"]
        )
        .is_ok());
        assert!(
            admit_s19k_fill_hunt_on_tx_path("/dev/ttyS3", &["/dev/ttyS1", "/dev/ttyS2"]).is_err()
        );
        assert!(s19k_multi_send_work_tx_required("/dev/ttyS1"));
        assert!(s19k_multi_send_work_tx_required("/dev/ttyS2"));
        assert!(!s19k_multi_send_work_tx_required("/dev/ttyS3"));
        assert!(!s19k_multi_send_work_tx_required("/dev/ttyS0"));
        assert!(refuse_s3_tx_as_required_send_work("/dev/ttyS3").is_err());
        assert!(refuse_s3_tx_as_required_send_work("/dev/ttyS1").is_ok());
        assert!(refuse_s3_rx_as_fill_hunt("/dev/ttyS3").is_err());
        assert!(refuse_s3_rx_as_fill_hunt("/dev/ttyS0").is_err());
        assert!(refuse_s3_rx_as_fill_hunt("/dev/ttyS1").is_ok());
        assert!(refuse_s3_rx_as_fill_hunt("/dev/ttyS2").is_ok());
        assert!(admit_s19k_production_fill_hunt_skips_discover(serial_mining).is_ok());
        assert!(admit_s19k_production_fill_hunt_skips_discover(
            "hunt_s19k_bm1366_fill_from_tagged_slot\n"
        )
        .is_err());
        assert!(admit_s19k_production_multi_send_skips_discover(serial_mining).is_ok());
        assert!(admit_s19k_production_multi_send_skips_discover(
            "impl SerialWorkTransport\nadmit_s19k_multi_send_work\n"
        )
        .is_err());
        assert_eq!(s19k_multi_rx_start(0, 2), Some(0));
        assert_eq!(s19k_multi_rx_start(1, 2), Some(1));
        assert_eq!(s19k_multi_rx_start(2, 2), Some(0));
        assert_eq!(s19k_multi_rx_start(0, 3), Some(0));
        assert_eq!(s19k_multi_rx_start(2, 3), Some(2));
        assert_eq!(s19k_multi_rx_start(3, 3), Some(0));
        assert_eq!(s19k_multi_rx_start(0, 0), None);
        assert!(admit_s19k_multi_rx_path("/dev/ttyS1").is_ok());
        assert!(admit_s19k_multi_rx_path("/dev/ttyS2").is_ok());
        assert!(admit_s19k_multi_rx_path("/dev/ttyS3").is_ok());
        assert!(admit_s19k_multi_rx_path("/dev/ttyS0").is_err());
        assert!(admit_s19k_multi_rx_path("/dev/ttyS4").is_err());
        assert!(admit_s19k_multi_rx_tables(2, 2).is_ok());
        assert!(admit_s19k_multi_rx_tables(3, 3).is_ok());
        assert!(admit_s19k_multi_rx_tables(2, 1).is_err());
        assert!(admit_s19k_multi_rx_tables(1, 1).is_err());
        assert!(refuse_same_tty_as_dual_uart_proof("/dev/ttyS1", "/dev/ttyS1").is_err());
        assert!(refuse_same_tty_as_dual_uart_proof("/dev/ttyS1", "/dev/ttyS2").is_ok());
        assert!(admit_s19k_required_dual_uart_paths("/dev/ttyS1", "/dev/ttyS2").is_ok());
        assert!(admit_s19k_required_dual_uart_paths("/dev/ttyS2", "/dev/ttyS1").is_ok());
        assert!(admit_s19k_required_dual_uart_paths("/dev/ttyS1", "/dev/ttyS1").is_err());
        assert!(admit_s19k_required_dual_uart_paths("/dev/ttyS1", "/dev/ttyS3").is_err());
        assert!(admit_s19k_required_dual_uart_paths("/dev/ttyS0", "/dev/ttyS1").is_err());
        let job_body = crate::s19k_bm1366_uart_rx::HELD_BM1368_S21_JOB[2..].to_vec();
        let tagged_s1 = observe_s19k_tagged_rx_body("/dev/ttyS1", Some(&job_body), 10).unwrap();
        let tagged_s2 = observe_s19k_tagged_rx_body("/dev/ttyS2", Some(&job_body), 10).unwrap();
        let tagged_sil = observe_s19k_tagged_rx_body("/dev/ttyS2", None, 10).unwrap();
        assert!(observe_s19k_tagged_rx_body("/dev/ttyS0", Some(&job_body), 10).is_err());
        assert_eq!(
            classify_s19k_tagged_dual_uart_rx_after(
                crate::s19k_bm1366_uart_rx::S19kRxExpectedAfter::WorkDispatch,
                "/dev/ttyS1",
                &tagged_s1,
                "/dev/ttyS2",
                &tagged_s2,
                Ok(()),
            )
            .unwrap(),
            crate::s19k_bm1366_uart_rx::S19kRxDiag::JobNonceFillOk
        );
        assert_eq!(
            classify_s19k_tagged_dual_uart_rx_after(
                crate::s19k_bm1366_uart_rx::S19kRxExpectedAfter::WorkDispatch,
                "/dev/ttyS1",
                &tagged_s1,
                "/dev/ttyS2",
                &tagged_sil,
                Ok(()),
            )
            .unwrap(),
            crate::s19k_bm1366_uart_rx::S19kRxDiag::SinglePortNotDualProof
        );
        assert!(classify_s19k_tagged_dual_uart_rx_after(
            crate::s19k_bm1366_uart_rx::S19kRxExpectedAfter::WorkDispatch,
            "/dev/ttyS1",
            &tagged_s1,
            "/dev/ttyS1",
            &tagged_s1,
            Ok(()),
        )
        .is_err());
        assert!(classify_s19k_tagged_dual_uart_rx_after(
            crate::s19k_bm1366_uart_rx::S19kRxExpectedAfter::WorkDispatch,
            "/dev/ttyS1",
            &tagged_s1,
            "/dev/ttyS3",
            &tagged_s2,
            Ok(()),
        )
        .is_err());
        assert_eq!(
            crate::s19k_bm1366_uart_rx::classify_s19k_dual_uart_rx_after(
                crate::s19k_bm1366_uart_rx::S19kRxExpectedAfter::WorkDispatch,
                &tagged_s1,
                &tagged_s1,
                Ok(()),
            ),
            crate::s19k_bm1366_uart_rx::S19kRxDiag::JobNonceFillOk,
            "untagged join still cannot see same-tty reuse; tagged join is the refuse"
        );
        assert!(
            serial_mining.contains("admit_s19k_multi_send_work"),
            "production Multi send_work must refuse partial required-pair TX"
        );
        assert!(
            serial_mining.contains("s19k_multi_send_work_tx_required"),
            "production Multi send_work must skip discover/optional UARTs"
        );
        assert!(
            serial_mining.contains("s19k_multi_rx_start"),
            "production Multi RX must round-robin both Track-1 ports"
        );
        let mut join = S19kDualWorkRxJoin::new();
        assert!(join.record("/dev/ttyS1", Some(&job_body)).is_none());
        assert_eq!(
            join.record("/dev/ttyS2", None),
            Some(crate::s19k_bm1366_uart_rx::S19kRxDiag::SinglePortNotDualProof)
        );
        let mut both = S19kDualWorkRxJoin::new();
        both.record("/dev/ttyS1", Some(&job_body));
        assert_eq!(
            both.record("/dev/ttyS2", Some(&job_body)),
            Some(crate::s19k_bm1366_uart_rx::S19kRxDiag::JobNonceFillOk)
        );
        assert!(admit_s19k_production_joins_dual_uart_after_fill(serial_mining).is_ok());
        assert!(
            serial_mining.contains("admit_s19k_multi_rx_path"),
            "production Multi RX must tag the tty that produced the body"
        );
        assert!(
            serial_mining.contains("S19K_MULTI_RX"),
            "production Multi RX must log the tagged path"
        );
        assert!(
            serial_mining.contains("paths: opened"),
            "production Multi must keep path table 1:1 with backends"
        );
        let chip = observe_get_address_bodies(
            &[[0x13, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05].to_vec()],
            250,
        );
        assert!(matches!(
            chip,
            crate::s19k_bm1366_uart_rx::S19kUartRxObservation::Frames { .. }
        ));
        let silence_obs = observe_get_address_bodies(&[], 250);
        assert_eq!(
            s19k_port_answer_from_rx(&silence_obs),
            S19kPortAnswer::Silence
        );
        let chip_obs = observe_get_address_bodies(
            &[[0x13, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05].to_vec()],
            250,
        );
        assert!(matches!(
            s19k_port_answer_from_rx(&chip_obs),
            S19kPortAnswer::ChipAddress {
                chip_id: 0x1366,
                count: 1
            }
        ));
        let cut7 =
            observe_get_address_bodies(&[[0x13, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00].to_vec()], 250);
        assert!(matches!(
            cut7,
            crate::s19k_bm1366_uart_rx::S19kUartRxObservation::NoPreamble { nbytes: 7, .. }
        ));
        assert!(refuse_hal_body7_observe_as_silence(&cut7).is_ok());
        assert_eq!(
            s19k_port_answer_from_rx(&cut7),
            S19kPortAnswer::FramingOrEcho
        );
        assert!(refuse_hal_body7_observe_as_silence(&silence_obs).is_err());
        let mut empty_join = S19kDualWorkRxJoin::new();
        empty_join.record("/dev/ttyS1", Some(&job_body));
        assert_eq!(
            empty_join.note_empty_if_unseen("/dev/ttyS2"),
            Some(crate::s19k_bm1366_uart_rx::S19kRxDiag::SinglePortNotDualProof)
        );
        assert!(empty_join.note_empty_if_unseen("/dev/ttyS1").is_none());
        assert!(admit_s19k_production_records_empty_work_polls(serial_mining).is_ok());
        assert!(
            serial_mining.contains("observe_s19k_board_tty_discover"),
            "mining-on must call tag discover, not a hardcoded board# table"
        );
        let sm = serial_mining.replace("\r\n", "\n");
        assert!(
            sm.contains("observe_s19k_board_tty_discover(")
                && sm.contains("answers[2],")
                && sm.contains("&[]"),
            "production tag discover must pass empty evidence (no descending AML)"
        );
        assert!(
            !sm.contains("S19kBoardTtyEvidenceKind::DescendingAml"),
            "production must not inject descending AML evidence"
        );
        assert!(
            serial_mining.contains("s19k_port_open_is_optional")
                || serial_mining.contains("BRAIINS_TTYS_THIRD"),
            "mining-on must try-open ttyS3 as optional discover"
        );
        let topo = observe_s19k_dual_port_topology(
            S19kPortAnswer::ChipAddress {
                chip_id: 0x1366,
                count: 12,
            },
            S19kPortAnswer::Silence,
        );
        assert!(matches!(
            topo.tty_s1,
            S19kPortBind::AnsweredGetAddress {
                chip_id: 0x1366,
                count: 12
            }
        ));
        assert_eq!(topo.tty_s2, S19kPortBind::Unbound);
        assert_eq!(topo.tty_s3, S19kPortBind::Unbound);
        assert!(topo.tty_s3_held);
        assert_eq!(topo.physical_bound, None);
        let line = format_s19k_topology_observe(&topo);
        assert!(line.contains("S19K_TOPO"));
        assert!(line.contains("physical=unbound"));
        assert!(line.contains("ttyS3=held"));
        assert!(!line.contains("physical=1"));
        assert!(!line.contains("physical=2"));
        assert!(!line.contains("physical=3"));
        let triple = observe_s19k_triple_port_topology(
            S19kPortAnswer::ChipAddress {
                chip_id: 0x1366,
                count: 8,
            },
            S19kPortAnswer::Silence,
            S19kPortAnswer::ChipAddress {
                chip_id: 0x1366,
                count: 12,
            },
        );
        assert!(matches!(
            triple.tty_s3,
            S19kPortBind::AnsweredGetAddress {
                chip_id: 0x1366,
                count: 12
            }
        ));
        assert!(!triple.tty_s3_held);
        let census = classify_s19k_78_dmesg_hash_uart_wakes(S19K_78_DMESG_WAKE_FIXTURE).unwrap();
        assert!(census.tty_s1_hash_wake && census.tty_s2_hash_wake && census.tty_s3_hash_wake);
        assert!(!census.tty_s0_hash_wake);
        let w3 = parse_s19k_dmesg_uart_wake(
            "meson_uart ff804000.serial: ttyS3 use xtal(24M) 24000000 change 0 to 9600",
        )
        .unwrap();
        assert_eq!(w3.tty, 3);
        assert_eq!(w3.from_baud, 0);
        assert_eq!(w3.to_baud, 9600);
        let probe = parse_s19k_dmesg_tty_probe(
            "ff804000.serial: ttyS3 at MMIO 0xff804000 (irq = 14, base_baud = 1500000) is a meson_uart",
        )
        .unwrap();
        assert_eq!(probe.tty, 3);
        assert_eq!(probe.mmio, S19K_78_TTYS3_MMIO);
        assert_eq!(probe.irq, S19K_78_TTYS3_IRQ);
        assert_eq!(S19K_78_TTYS1_MMIO, 0xFFD2_4000);
        assert_eq!(S19K_78_TTYS2_IRQ, 26);
        assert_eq!(S19K_78_TTYS0_IRQ, 13);
        assert_eq!(S19K_78_TTYS0_MMIO, 0xFF80_3000);
        assert_eq!(S19K_78_TTYS1_IRQ, 25);
        assert!(admit_s19k_78_dmesg_wakes_match_kernel_mmio(S19K_78_DMESG_WAKE_FIXTURE).is_ok());
        assert_eq!(
            parse_s19k_dmesg_uart_controller(
                "meson_uart ffd24000.serial: ttyS1 use xtal(24M) 24000000 change 0 to 9600"
            ),
            Some((1, S19K_78_TTYS1_MMIO))
        );
        assert_eq!(
            parse_s19k_dmesg_uart_controller(
                "meson_uart ff804000.serial: ttyS3 use xtal(24M) 24000000 change 0 to 9600"
            ),
            Some((3, S19K_78_TTYS3_MMIO))
        );
        assert!(admit_s19k_78_kernel_ttys_mmio(1, 0xFFD2_4000).is_ok());
        assert!(admit_s19k_78_kernel_ttys_mmio(1, 0xFF80_3000).is_err());
        assert!(refuse_console_mmio_as_hash_uart(S19K_78_TTYS0_MMIO).is_err());
        assert!(refuse_console_mmio_as_hash_uart(S19K_78_TTYS1_MMIO).is_ok());
        assert!(admit_s19k_dtb_serials_match_78_kernel_mmio().is_ok());
        let irq = classify_s19k_78_irq_delta(S19K_78_IRQ_BEFORE_FIXTURE, S19K_78_IRQ_AFTER_FIXTURE)
            .unwrap();
        assert_eq!(irq.tty_s3_delta, 352);
        assert_eq!(irq.tty_s1_delta, 0);
        assert_eq!(irq.tty_s2_delta, 0);
        assert_eq!(irq.tty_s0_delta, 15);
        assert_eq!(
            parse_s19k_proc_interrupts_meson_uart(
                " 14:          0      30792          0          0     GIC-0 229 Edge      meson_uart"
            ),
            Some((14, 30792))
        );
    }

    #[test]
    fn board_tty_discover_requires_unique_serial_on_tty() {
        assert!(admit_s19k_78_chassis_rows_unique().is_ok());
        assert_eq!(
            bind_s19k_chassis_from_eeprom_serial("JYZZYR6BCJHCA0JRG"),
            Some(1)
        );
        assert_eq!(
            bind_s19k_chassis_from_eeprom_serial("JYZZYR6BCJHCA0KRG"),
            Some(2)
        );
        assert_eq!(
            bind_s19k_chassis_from_eeprom_serial("JYZZYR6BCJHCA0HNX"),
            Some(3)
        );
        assert_eq!(bind_s19k_chassis_from_eeprom_serial("UNKNOWN"), None);
        assert_eq!(bind_s19k_chassis_from_i2c(0x50), Some(1));
        assert_eq!(bind_s19k_chassis_from_i2c(0x51), Some(2));
        assert_eq!(bind_s19k_chassis_from_i2c(0x52), Some(3));
        assert_eq!(bind_s19k_chassis_from_i2c(0x53), None);
        assert!(refuse_s19k_held_corpus_as_serial_tty_map().is_err());
        assert!(refuse_s19k_106_irq_as_physical_1_ttys1().is_err());
        assert!(refuse_s19k_xilinx_s19j_as_aml_tty_map().is_err());
        assert!(refuse_hardcoded_physical_to_tty("/dev/ttyS3", 1).is_err());
        assert!(bind_s19k_board_tty(S19kBoardTtyEvidence {
            kind: S19kBoardTtyEvidenceKind::DescendingAml,
            path: "/dev/ttyS3",
            serial: None,
            physical_claim: Some(1),
        })
        .is_err());
        assert!(bind_s19k_board_tty(S19kBoardTtyEvidence {
            kind: S19kBoardTtyEvidenceKind::NaiveChainN,
            path: "/dev/ttyS1",
            serial: None,
            physical_claim: Some(1),
        })
        .is_err());
        assert!(bind_s19k_board_tty(S19kBoardTtyEvidence {
            kind: S19kBoardTtyEvidenceKind::PlugCount,
            path: "/dev/ttyS1",
            serial: None,
            physical_claim: None,
        })
        .is_err());
        assert!(bind_s19k_board_tty(S19kBoardTtyEvidence {
            kind: S19kBoardTtyEvidenceKind::RxCount,
            path: "/dev/ttyS1",
            serial: None,
            physical_claim: Some(1),
        })
        .is_err());
        assert!(bind_s19k_board_tty(S19kBoardTtyEvidence {
            kind: S19kBoardTtyEvidenceKind::AsicEepromSerialOnTty,
            path: "/dev/ttyS1",
            serial: None,
            physical_claim: None,
        })
        .is_err());
        assert!(bind_s19k_board_tty(S19kBoardTtyEvidence {
            kind: S19kBoardTtyEvidenceKind::AsicEepromSerialOnTty,
            path: "/dev/ttyS0",
            serial: Some("JYZZYR6BCJHCA0JRG"),
            physical_claim: None,
        })
        .is_err());
        let on_s2 = bind_s19k_board_tty(S19kBoardTtyEvidence {
            kind: S19kBoardTtyEvidenceKind::AsicEepromSerialOnTty,
            path: "/dev/ttyS2",
            serial: Some("JYZZYR6BCJHCA0JRG"),
            physical_claim: None,
        })
        .unwrap();
        assert_eq!(
            on_s2,
            S19kBoardTtyBind::Bound {
                physical: 1,
                path: "/dev/ttyS2",
                serial: "JYZZYR6BCJHCA0JRG",
            }
        );
        // Unique serial on ttyS3 may bind physical 1. The descending *table*
        // (physical_1→ttyS3 with no serial) stays refused.
        let on_s3 = bind_s19k_board_tty(S19kBoardTtyEvidence {
            kind: S19kBoardTtyEvidenceKind::AsicEepromSerialOnTty,
            path: "/dev/ttyS3",
            serial: Some("JYZZYR6BCJHCA0JRG"),
            physical_claim: None,
        })
        .unwrap();
        assert_eq!(
            on_s3,
            S19kBoardTtyBind::Bound {
                physical: 1,
                path: "/dev/ttyS3",
                serial: "JYZZYR6BCJHCA0JRG",
            }
        );
        assert!(bind_s19k_board_tty(S19kBoardTtyEvidence {
            kind: S19kBoardTtyEvidenceKind::AsicEepromSerialOnTty,
            path: "/dev/ttyS2",
            serial: Some("JYZZYR6BCJHCA0JRG"),
            physical_claim: Some(3),
        })
        .is_err());
        let chip = S19kPortAnswer::ChipAddress {
            chip_id: 0x1366,
            count: 12,
        };
        let empty = observe_s19k_board_tty_discover(chip, chip, chip, &[]);
        assert_eq!(empty.physical_bound, None);
        assert_eq!(empty.board_on_s1, None);
        assert_eq!(empty.board_on_s2, None);
        assert_eq!(empty.board_on_s3, None);
        assert!(refuse_s19k_host_i2c_file_as_uart_eeprom(S19K_78_I2CDETECT_FIXTURE).is_err());
        assert!(refuse_s19k_host_i2c_file_as_uart_eeprom(
            "|S/N                 |JYZZYR6BCJHCA0JRG        |"
        )
        .is_err());
        assert!(refuse_s19k_host_i2c_file_as_uart_eeprom(
            r#"{ "serial_number": "JYZZYR6BCJHCA0JRG" }"#
        )
        .is_err());
        assert!(parse_s19k_uart_eeprom_named_tty(S19K_78_I2CDETECT_FIXTURE).is_err());
        let parsed = parse_s19k_uart_eeprom_named_tty(S19K_UART_EEPROM_TTYS2_JRG_FIXTURE).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0].kind,
            S19kBoardTtyEvidenceKind::AsicEepromSerialOnTty
        );
        assert_eq!(parsed[0].path, "/dev/ttyS2");
        assert_eq!(parsed[0].serial, Some("JYZZYR6BCJHCA0JRG"));
        let spaced = parse_s19k_uart_eeprom_named_tty(
            "path=/dev/ttyS2\n4a 59 5a 5a 59 52 36 42 43 4a 48 43 41 30 4a 52 47\n",
        )
        .unwrap();
        assert_eq!(spaced[0].serial, Some("JYZZYR6BCJHCA0JRG"));
        let one_line = parse_s19k_uart_eeprom_named_tty("/dev/ttyS1 JYZZYR6BCJHCA0HNX\n").unwrap();
        assert_eq!(one_line[0].path, "/dev/ttyS1");
        assert_eq!(one_line[0].serial, Some("JYZZYR6BCJHCA0HNX"));
        assert!(
            parse_s19k_uart_eeprom_named_tty("path=/dev/ttyS0\nserial=JYZZYR6BCJHCA0JRG\n")
                .is_err()
        );
        assert!(
            parse_s19k_uart_eeprom_named_tty("path=/dev/ttyS2\nserial=NOT_A_HELD_SERIAL1\n")
                .is_err()
        );
        let from_fix = observe_s19k_board_tty_discover(
            S19kPortAnswer::Silence,
            chip,
            S19kPortAnswer::Silence,
            &parsed,
        );
        assert_eq!(from_fix.board_on_s2, Some(1));
        assert_eq!(from_fix.physical_bound, Some(1));
        assert_eq!(from_fix.board_on_s1, None);
        let one = observe_s19k_board_tty_discover(
            chip,
            S19kPortAnswer::Silence,
            S19kPortAnswer::Silence,
            &[S19kBoardTtyEvidence {
                kind: S19kBoardTtyEvidenceKind::AsicEepromSerialOnTty,
                path: "/dev/ttyS2",
                serial: Some("JYZZYR6BCJHCA0KRG"),
                physical_claim: Some(2),
            }],
        );
        assert_eq!(one.physical_bound, Some(2));
        assert_eq!(one.board_on_s2, Some(2));
        assert_eq!(one.board_on_s1, None);
        let two = observe_s19k_board_tty_discover(
            chip,
            chip,
            S19kPortAnswer::Silence,
            &[
                S19kBoardTtyEvidence {
                    kind: S19kBoardTtyEvidenceKind::AsicEepromSerialOnTty,
                    path: "/dev/ttyS1",
                    serial: Some("JYZZYR6BCJHCA0JRG"),
                    physical_claim: Some(1),
                },
                S19kBoardTtyEvidence {
                    kind: S19kBoardTtyEvidenceKind::AsicEepromSerialOnTty,
                    path: "/dev/ttyS2",
                    serial: Some("JYZZYR6BCJHCA0KRG"),
                    physical_claim: Some(2),
                },
            ],
        );
        assert_eq!(
            two.physical_bound, None,
            "two distinct chassis binds cannot collapse into one physical_bound"
        );
        assert_eq!(two.board_on_s1, Some(1));
        assert_eq!(two.board_on_s2, Some(2));
        assert_eq!(two.board_on_s3, None);
        let two_line = format_s19k_topology_observe(&two);
        assert!(two_line.contains("boards=s1:1 s2:2 s3:unbound"));
        assert!(two_line.contains("physical=unbound"));
        let descending = observe_s19k_board_tty_discover(
            chip,
            S19kPortAnswer::Silence,
            chip,
            &[S19kBoardTtyEvidence {
                kind: S19kBoardTtyEvidenceKind::DescendingAml,
                path: "/dev/ttyS3",
                serial: None,
                physical_claim: Some(1),
            }],
        );
        assert_eq!(descending.physical_bound, None);
        let serial_mining = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(serial_mining.contains("observe_s19k_board_tty_discover"));
        assert!(admit_s19k_production_uses_uart_eeprom_fixture(serial_mining).is_ok());
        assert!(
            serial_mining.contains("parse_s19k_uart_eeprom_named_tty"),
            "production must feed the bind API from DCENT_S19K_UART_EEPROM"
        );
        assert!(
            !serial_mining.contains("S19kBoardTtyEvidenceKind::DescendingAml"),
            "production must not inject descending AML evidence"
        );
    }

    #[test]
    fn host_i2c_chassis_does_not_bind_tty() {
        assert_eq!(
            parse_s19k_i2cdetect_at24(S19K_78_I2CDETECT_FIXTURE),
            [true, true, true]
        );
        let missing_mid = "\
50: 50 -- 52 -- -- -- -- -- -- -- -- -- -- -- -- -- 
";
        assert_eq!(parse_s19k_i2cdetect_at24(missing_mid), [true, false, true]);
        let table = "\
|S/N                 |JYZZYR6BCJHCA0JRG        |
|S/N                 |JYZZYR6BCJHCA0KRG        |
|S/N                 |JYZZYR6BCJHCA0HNX        |
";
        assert_eq!(
            parse_s19k_bosminer_eeprom_serials(table),
            vec![
                "JYZZYR6BCJHCA0JRG".to_string(),
                "JYZZYR6BCJHCA0KRG".to_string(),
                "JYZZYR6BCJHCA0HNX".to_string(),
            ]
        );
        let json = r#"{ "serial_number": "JYZZYR6BCJHCA0JRG" }"#;
        assert_eq!(
            parse_s19k_bosminer_eeprom_serials(json),
            vec!["JYZZYR6BCJHCA0JRG".to_string()]
        );
        let obs = observe_s19k_host_i2c_chassis(S19K_78_I2CDETECT_FIXTURE, table);
        assert_eq!(obs.at24_present, [true, true, true]);
        assert_eq!(obs.physicals, vec![1, 2, 3]);
        let line = format_s19k_host_i2c_chassis(&obs);
        assert!(line.contains("S19K_HOST_I2C"));
        assert!(line.contains("chassis=1,2,3"));
        assert!(line.contains("i2c=0x50,0x51,0x52"));
        assert!(line.contains("tty=unbound"));
        assert!(!line.contains("ttyS"));
        assert!(refuse_s19k_host_i2c_as_tty_bind().is_err());
        assert!(bind_s19k_board_tty(S19kBoardTtyEvidence {
            kind: S19kBoardTtyEvidenceKind::HostI2cChassis,
            path: "/dev/ttyS3",
            serial: Some("JYZZYR6BCJHCA0JRG"),
            physical_claim: Some(1),
        })
        .is_err());
        let host_only = observe_s19k_board_tty_discover(
            S19kPortAnswer::Silence,
            S19kPortAnswer::Silence,
            S19kPortAnswer::Silence,
            &[S19kBoardTtyEvidence {
                kind: S19kBoardTtyEvidenceKind::HostI2cChassis,
                path: "/dev/ttyS1",
                serial: Some("JYZZYR6BCJHCA0JRG"),
                physical_claim: Some(1),
            }],
        );
        assert_eq!(host_only.physical_bound, None);
        let serial_mining = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(
            serial_mining.contains("observe_s19k_host_i2c_chassis"),
            "mining-on must log host i2c chassis when detect file is set"
        );
        assert!(serial_mining.contains("DCENT_S19K_I2CDETECT"));
        assert!(serial_mining.contains("tty stays unbound"));
        let chassis_sh = include_str!("../../../scripts/s19k_host_i2c_chassis.sh");
        assert!(admit_s19k_host_i2c_chassis_script(chassis_sh).is_ok());
        assert!(chassis_sh.contains("i2cset=false"));
        assert!(chassis_sh.contains("tty=unbound"));
        assert!(!chassis_sh.contains("i2cset -y"));
        assert!(
            admit_s19k_host_i2c_chassis_script("i2cdetect -y 1\ni2cset -y 1 0x50 0 0\n").is_err()
        );
    }

    #[test]
    fn single_port_ttys0_and_uart_trans_regressions_fail() {
        assert!(admit_braiins_mining_on_ports(&["/dev/ttyS1"]).is_err());
        assert!(admit_braiins_mining_on_ports(&["/dev/ttyS2"]).is_err());
        assert!(admit_braiins_mining_on_ports(&["/dev/ttyS3"]).is_err());
        assert!(
            admit_braiins_mining_on_ports(&["/dev/ttyS0", "/dev/ttyS1", "/dev/ttyS2"]).is_err()
        );
        assert!(admit_discover_open_path("/dev/ttyS0").is_err());
        assert!(plan_s19k_braiins_mining_on_ports(Some("/dev/ttyS0,/dev/ttyS1")).is_err());
        assert!(plan_s19k_braiins_mining_on_ports(Some("/dev/ttyS1,/dev/ttyS0")).is_err());
        assert!(admit_s19k_multi_send_work(1, 2).is_err());
        assert!(admit_s19k_multi_send_work(0, 2).is_err());
        assert!(admit_s19k_multi_send_work(2, 1).is_err());
        for hint in ["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"] {
            assert_eq!(
                plan_s19k_braiins_mining_on_ports(Some(hint)).unwrap(),
                &["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"]
            );
        }
        assert!(
            admit_braiins_mining_on_ports(&["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS4"]).is_err()
        );
        let sh = include_str!("../../../scripts/s19k_braiins_wire_try.sh");
        assert!(sh.contains("legacy S19k wire-try is retired"));
        assert!(sh.contains("dcentrald_s19k_tmp_deploy.sh"));
        assert!(sh.contains("exit 64"));
        for forbidden in ["ssh", "scp", "stty", "/dev/tty", "/sys/class/gpio"] {
            assert!(!sh.contains(forbidden));
        }
    }

    #[test]
    fn s19k_multi_send_work_isolates_discover_uart() {
        assert!(s19k_multi_send_work_tx_required("/dev/ttyS1"));
        assert!(s19k_multi_send_work_tx_required("/dev/ttyS2"));
        assert!(!s19k_multi_send_work_tx_required("/dev/ttyS3"));
        assert!(admit_s19k_multi_send_work(2, 3).is_ok());
        assert!(admit_s19k_multi_send_work(1, 3).is_err());
        assert!(refuse_s3_tx_as_required_send_work("/dev/ttyS3").is_err());
        let serial_mining = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_multi_send_skips_discover(serial_mining).is_ok());
    }

    #[test]
    fn s19k_fill_hunt_isolates_discover_uart() {
        assert!(refuse_s3_rx_as_fill_hunt("/dev/ttyS3").is_err());
        assert!(refuse_s3_rx_as_fill_hunt("/dev/ttyS0").is_err());
        assert!(refuse_s3_rx_as_fill_hunt("/dev/ttyS1").is_ok());
        assert!(refuse_s3_rx_as_fill_hunt("/dev/ttyS2").is_ok());
        assert!(admit_s19k_multi_rx_path("/dev/ttyS3").is_ok());
        let serial_mining = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_fill_hunt_skips_discover(serial_mining).is_ok());
        assert!(serial_mining
            .contains("S19k UART RX is observe-only because this path did not receive work"));
    }

    #[test]
    fn s19k_live401_stall_is_first_hit_not_simultaneous() {
        let both = [true, true, false];
        assert_eq!(s19k_multi_rx_ready_indices(&both, 1, false), vec![1]);
        assert_eq!(s19k_multi_rx_ready_indices(&both, 1, true), vec![1, 0]);
        assert!(refuse_s19k_first_hit_as_dual_port_drain(&both, 1).is_err());
        assert!(refuse_s19k_first_hit_as_dual_port_drain(&[true, false, false], 0).is_ok());
        assert!(admit_s19k_live401_stall_is_sequential_s1_then_s2().is_ok());
        assert!(refuse_s19k_live401_stall_as_simultaneous_dual_death().is_err());
        assert_eq!(S19K_LIVE401_S1_LAST_RX_MS, 20_790);
        assert_eq!(S19K_LIVE401_S2_LAST_RX_MS, 60_941);
        let serial_mining = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_multi_rx_drains_all(serial_mining).is_ok());
        assert!(admit_s19k_production_bm1366_tx_burst_is_one(serial_mining).is_ok());
        assert!(admit_s19k_live403_s1_survived_past_live401_s1().is_ok());
        assert!(refuse_s19k_live403_as_stall_closed().is_err());
        assert!(admit_s19k_live403_multi_rx_counts_balanced().is_ok());
        assert!(admit_s19k_live403_actor_tx_starved_during_rx().is_ok());
        assert!(refuse_s19k_live403_as_passthrough_never_rearmed().is_err());
        assert!(admit_s19k_live404_actor_tx_kept_up_with_rx().is_ok());
        assert!(admit_s19k_live404_oneshot_rearm_then_cliff().is_ok());
        assert!(refuse_s19k_live404_as_jobid_wrap().is_err());
        assert!(refuse_s19k_live404_as_stall_closed().is_err());
        assert_eq!(S19K_LIVE403_S1_LAST_RX_MS, 40_513);
        assert_eq!(S19K_LIVE403_S2_LAST_RX_MS, 43_841);
        assert_eq!(S19K_LIVE403_ACTOR_TX_AT_LAST_RX, 25);
        assert_eq!(S19K_LIVE403_ACTOR_RX_AT_LAST_RX, 792);
        assert_eq!(S19K_LIVE403_ACTOR_TX_10S_AFTER_SILENCE, 58);
        assert_eq!(S19K_LIVE404_S1_LAST_RX_MS, 29_380);
        assert_eq!(S19K_LIVE404_S2_LAST_RX_MS, 34_788);
        assert_eq!(S19K_LIVE404_ACTOR_TX_T10, 181);
        assert!(admit_s19k_production_bm1366_skips_rx_followup_drain(serial_mining).is_ok());
        assert!(admit_s19k_production_bm1366_midrun_rearm(serial_mining).is_ok());
        assert!(admit_s19k_live405_survived_past_live404_cliff().is_ok());
        assert!(admit_s19k_live405_s1_died_at_wrap5().is_ok());
        assert!(refuse_s19k_live405_as_failed_midrun_rearm().is_err());
        assert!(refuse_s19k_live405_as_stall_closed().is_err());
        assert!(admit_s19k_production_bm1366_tx_min_interval(serial_mining).is_ok());
        assert!(admit_s19k_tx_pace_puts_wrap5_after_t90().is_ok());
        assert!(admit_s19k_fill_registry_is_256().is_ok());
        assert_eq!(S19K_LIVE405_S1_LAST_RX_MS, 71_239);
        assert_eq!(S19K_LIVE405_S2_LAST_RX_MS, 82_887);
        assert_eq!(S19K_LIVE405_WRAP5_TX, 1280);
        assert_eq!(S19K_BM1366_TX_MIN_INTERVAL_MS, 120);
        assert_eq!(S19K_LIVE407_TX_MIN_INTERVAL_MS, 80);
        assert!(admit_s19k_live406_hung_on_ttys3_9600().is_ok());
        assert!(refuse_s19k_live406_as_stall_closed().is_err());
        assert!(refuse_s19k_skip_required_port_rx_for_9600().is_ok());
        assert!(s19k_discover_skip_rx_when_leftover_baud_not_track1_3m(
            "/dev/ttyS3",
            9600
        ));
        assert!(!s19k_discover_skip_rx_when_leftover_baud_not_track1_3m(
            "/dev/ttyS3",
            3_000_000
        ));
        assert!(!s19k_discover_skip_rx_when_leftover_baud_not_track1_3m(
            "/dev/ttyS1",
            9600
        ));
        assert!(
            admit_s19k_production_skips_discover_rx_when_leftover_not_3m(serial_mining).is_ok()
        );
        assert_eq!(S19K_LIVE406_TTYS3_LEFTOVER_BAUD, 9600);
        assert!(!S19K_LIVE406_REACHED_WORK1);
        assert!(admit_s19k_live407_dual_port_past_t90().is_ok());
        assert!(admit_s19k_live407_survived_paced_wrap5().is_ok());
        assert_eq!(S19K_LIVE407_S1_LAST_RX_MS, 116_498);
        assert_eq!(S19K_LIVE407_S2_LAST_RX_MS, 107_394);
        assert_eq!(S19K_LIVE407_S1_MULTI_RX, 766);
        assert_eq!(S19K_LIVE407_S2_MULTI_RX, 680);
        assert!(admit_s19k_live407_zero_shares().is_ok());
        assert!(refuse_s19k_live407_as_share_closed().is_err());
        assert!(refuse_s19k_t90_only_as_production_ready().is_err());
        assert!(refuse_s19k_t90_only_as_customer_writable().is_err());
        assert_eq!(S19K_LIVE407_ACCEPTED_SHARES, 0);
        assert!(admit_s19k_live408_pool_accepted_one_share().is_ok());
        assert!(refuse_s19k_live408_as_t90_dual_port().is_err());
        assert!(refuse_s19k_live408_as_share_and_t90().is_err());
        assert_eq!(S19K_LIVE408_ACCEPTED_SHARES, 1);
        assert_eq!(S19K_LIVE408_SHARE_NONCE, 0x5D79_3985);
        assert_eq!(S19K_LIVE408_S1_LAST_RX_MS, 60_272);
        assert_eq!(S19K_LIVE408_S2_LAST_RX_MS, 65_238);
        assert!(admit_s19k_live408_died_at_wrap3().is_ok());
        assert!(admit_s19k_tx_pace_puts_wrap3_after_t90().is_ok());
        assert_eq!(S19K_LIVE408_WRAP3_TX, 768);
        assert_eq!(S19K_LIVE408_ACTOR_TX_AT_CLIFF, 749);
        assert!(
            crate::s19k_bm1366_share::admit_s19k_production_bm1366_holds_before_take_dispatch(
                serial_mining
            )
            .is_ok()
        );
        assert!(admit_s19k_live409_parked_boarddesc_management_only().is_ok());
        assert!(refuse_s19k_live409_as_share_and_t90().is_err());
        assert!(!S19K_LIVE409_REACHED_WORK1);
        assert_eq!(S19K_LIVE409_ACCEPTED_SHARES, 0);
        assert!(admit_s19k_live410_share_and_t90().is_ok());
        assert!(refuse_s19k_live410_as_production_ready().is_err());
        assert!(refuse_s19k_live410_as_multi_share_closed().is_err());
        assert!(refuse_s19k_live410_as_customer_writable().is_err());
        assert!(admit_s19k_live411_multi_share_and_t90().is_ok());
        assert!(refuse_s19k_live411_as_production_ready().is_err());
        assert!(refuse_s19k_live411_as_t180_soak().is_err());
        assert!(refuse_s19k_t90_multi_share_as_soak().is_err());
        assert!(refuse_s19k_live411_as_customer_writable().is_err());
        assert_eq!(S19K_LIVE411_ACCEPTED_SHARES, 5);
        assert_eq!(S19K_LIVE411_SHARE1_NONCE, 0xC15A_724A);
        assert_eq!(S19K_LIVE411_SHARE2_NONCE, 0x0033_0511);
        assert_eq!(S19K_LIVE411_S1_LAST_RX_MS, 118_283);
        assert_eq!(S19K_LIVE411_S2_LAST_RX_MS, 118_043);
        assert!(admit_s19k_live412_multi_share_and_t180().is_ok());
        assert!(admit_s19k_live412_survived_paced_wrap5().is_ok());
        assert!(refuse_s19k_live412_as_production_ready().is_err());
        assert!(refuse_s19k_t180_tmp_as_production_ready().is_err());
        assert!(refuse_s19k_live412_as_customer_writable().is_err());
        assert_eq!(S19K_LIVE412_ACCEPTED_SHARES, 8);
        assert_eq!(S19K_LIVE412_SHARE1_NONCE, 0x4E3E_900D);
        assert_eq!(S19K_LIVE412_SHARE2_NONCE, 0xE5D3_C50D);
        assert_eq!(S19K_LIVE412_S1_LAST_RX_MS, 187_186);
        assert_eq!(S19K_LIVE412_S2_LAST_RX_MS, 188_012);
        assert_eq!(S19K_LIVE412_S1_MULTI_RX, 779);
        assert_eq!(S19K_LIVE412_S2_MULTI_RX, 790);
        assert!(admit_s19k_live414_thermal_ready_and_t180().is_ok());
        assert!(admit_s19k_live414_died_at_wrap7().is_ok());
        assert!(refuse_s19k_live414_as_t600_soak().is_err());
        assert!(refuse_s19k_live414_as_production_ready().is_err());
        assert!(refuse_s19k_live414_as_customer_writable().is_err());
        assert_eq!(S19K_LIVE414_ACCEPTED_SHARES, 3);
        assert_eq!(S19K_LIVE414_SHARE1_NONCE, 0xEEAB_1C38);
        assert_eq!(S19K_LIVE414_SHARE2_NONCE, 0x97BB_F42B);
        assert_eq!(S19K_LIVE414_S1_LAST_RX_MS, 228_031);
        assert_eq!(S19K_LIVE414_S2_LAST_RX_MS, 213_744);
        assert_eq!(S19K_LIVE414_WRAP7_TX, 1_792);
        assert!(admit_s19k_live414_wrap7_trips_barrier().is_ok());
        assert!(refuse_s19k_slower_tx_as_wrap7_survival().is_err());
        assert!(admit_s19k_live415_died_before_wrap1().is_ok());
        assert!(refuse_s19k_live415_as_t600_soak().is_err());
        assert!(refuse_s19k_live415_as_production_ready().is_err());
        assert!(refuse_s19k_live415_as_customer_writable().is_err());
        assert_eq!(S19K_LIVE415_S1_LAST_RX_MS, 26_517);
        assert_eq!(S19K_LIVE415_S2_LAST_RX_MS, 26_397);
        assert!(admit_s19k_live416_died_after_wrap2_drain_rearm().is_ok());
        assert!(refuse_s19k_live416_as_t600_soak().is_err());
        assert!(refuse_s19k_live416_as_production_ready().is_err());
        assert!(refuse_s19k_live416_as_customer_writable().is_err());
        assert!(refuse_s19k_live415_416_drain_rearm_as_wrap_survival().is_err());
        assert_eq!(S19K_LIVE416_SHARE1_NONCE, 0xADFE_CA91);
        assert_eq!(S19K_LIVE416_SHARE2_NONCE, 0x61B2_1B30);
        assert_eq!(S19K_LIVE416_S1_LAST_RX_MS, 73_609);
        assert_eq!(S19K_LIVE416_S2_LAST_RX_MS, 73_729);
        assert!(admit_s19k_live417_died_at_wrap6().is_ok());
        assert!(refuse_s19k_live417_as_t600_soak().is_err());
        assert!(refuse_s19k_live417_as_production_ready().is_err());
        assert!(refuse_s19k_live417_as_customer_writable().is_err());
        assert_eq!(S19K_LIVE417_SHARE1_NONCE, 0xD081_C53B);
        assert_eq!(S19K_LIVE417_S1_LAST_RX_MS, 169_044);
        assert_eq!(S19K_LIVE417_S2_LAST_RX_MS, 175_997);
        assert_eq!(admit_s19k_production_rearm_skips_tx(serial_mining), Ok(()));
        assert!(admit_s19k_live418_died_at_wrap6().is_ok());
        assert!(refuse_s19k_live418_as_t600_soak().is_err());
        assert!(refuse_s19k_live418_as_production_ready().is_err());
        assert!(refuse_s19k_live418_as_customer_writable().is_err());
        assert_eq!(S19K_LIVE418_SHARE1_NONCE, 0xD272_543F);
        assert_eq!(S19K_LIVE418_S1_LAST_RX_MS, 184_926);
        assert_eq!(S19K_LIVE418_S2_LAST_RX_MS, 176_802);
        assert!(admit_s19k_live419_died_after_wrap1_cold_leftover().is_ok());
        assert!(refuse_s19k_live419_as_t600_soak().is_err());
        assert!(refuse_s19k_live419_as_production_ready().is_err());
        assert!(refuse_s19k_live419_as_customer_writable().is_err());
        assert_eq!(S19K_LIVE419_S1_LAST_RX_MS, 38_374);
        assert_eq!(S19K_LIVE419_S2_LAST_RX_MS, 38_254);
        assert!(admit_s19k_live420_died_after_wrap4().is_ok());
        assert!(refuse_s19k_live420_as_t600_soak().is_err());
        assert!(refuse_s19k_live420_as_production_ready().is_err());
        assert!(refuse_s19k_live420_as_customer_writable().is_err());
        assert_eq!(S19K_LIVE420_S1_LAST_RX_MS, 136_902);
        assert_eq!(S19K_LIVE420_S2_LAST_RX_MS, 126_767);
        let midrun: Vec<_> = crate::s19k_bm1366_init_seq::s19k_passthrough_rearm_writes()
            .map(|w| w.name)
            .collect();
        assert_eq!(
            crate::s19k_bm1366_init_seq::admit_s19k_midrun_rearm_includes_analog_mux(&midrun),
            Ok(())
        );
        assert!(refuse_s19k_analog_mux_rearm_as_t600_soak().is_err());
        assert!(admit_s19k_live414_shares_stopped_after_midrun_clean().is_ok());
        assert!(refuse_s19k_midrun_clean_as_chip_reload().is_err());
        assert!(refuse_s19k_fill_cursor_reset_as_t600_soak().is_err());
        assert!(admit_s19k_live414_resent_full_registry_after_clean().is_ok());
        assert!(refuse_s19k_fill_cursor_reset_as_chip_work_replace().is_err());
        assert_eq!(S19K_LIVE414_POST_CLEAN_TX_EST, 1_228);
        assert!(admit_s19k_track1_pause_rearm_one_wrap().is_ok());
        assert_eq!(
            admit_s19k_production_pauses_rearm_one_wrap_after_clean(serial_mining),
            Ok(())
        );
        assert!(refuse_s19k_hcn_pause_as_t600_soak().is_err());
        assert!(refuse_s19k_hcn_pause_as_chip_work_replace().is_err());
        assert!(refuse_s19k_getaddress_as_midrun_invalidate().is_err());
        assert!(refuse_s19k_analog_mux_as_wrap7_survival().is_err());
        assert_eq!(
            admit_s19k_production_clean_resets_fill_cursor(serial_mining),
            Ok(())
        );
        assert!(admit_s19k_live424_session_start_paused_rearm().is_ok());
        assert!(refuse_s19k_live424_as_leftover_hit_soak().is_err());
        assert!(refuse_s19k_session_start_hcn_pause().is_err());
        assert_eq!(S19K_LIVE424_SHARE1_NONCE, 0x09A9_BAAE);
        assert_eq!(S19K_LIVE424_S1_LAST_RX_MS, 102_054);
        assert_eq!(S19K_LIVE424_S2_LAST_RX_MS, 86_991);
        assert!(admit_s19k_live425_leftover_hit_and_wrap7().is_ok());
        assert!(refuse_s19k_live425_as_t600_soak().is_err());
        assert_eq!(S19K_LIVE425_SHARE1_NONCE, 0xAB96_F056);
        assert_eq!(S19K_LIVE425_LEFTOVER_HIT, 6);
        assert_eq!(S19K_LIVE414_LAST_SHARE_MS, 50_683);
        assert_eq!(S19K_LIVE414_MIDRUN_CLEAN_MS, 66_296);
        assert_eq!(S19K_LIVE412_LAST_SHARE_MS, 170_255);
        assert_eq!(S19K_LIVE412_8BD1_NOTIFY_AFTER_FIRST_WORK_MS, 7_819);
        assert_eq!(S19K_LIVE412_8BD1_TX_EST, 65);
        assert!(admit_s19k_live412_8bd1_is_first_fill().is_ok());
        assert!(refuse_s19k_live412_8bd1_as_same_slot_replace().is_err());
        assert!(refuse_s19k_session_start_shares_as_occupied_slot_replace().is_err());
        assert!(admit_s19k_live414_rx_died_while_tx_crossed_wrap7().is_ok());
        assert_eq!(S19K_LIVE414_ACTOR_TX_BEFORE_WRAP7, 1_761);
        assert_eq!(S19K_LIVE414_ACTOR_TX_AFTER_S2_DEATH, 1_844);
        assert!(s19k_track1_wrap_barrier_due(256));
        assert!(s19k_track1_wrap_barrier_due(1_792));
        assert!(!s19k_track1_wrap_barrier_due(255));
        assert_eq!(admit_s19k_production_wrap_barrier(serial_mining), Ok(()));
        assert_eq!(S19K_LIVE410_ACCEPTED_SHARES, 1);
        assert_eq!(S19K_LIVE410_SHARE_NONCE, 0x9AEA_565C);
        assert_eq!(S19K_LIVE410_S1_LAST_RX_MS, 116_990);
        assert_eq!(S19K_LIVE410_S2_LAST_RX_MS, 117_231);
        assert_eq!(S19K_LIVE410_S1_MULTI_RX, 487);
        assert_eq!(S19K_LIVE410_S2_MULTI_RX, 502);
    }

    #[test]
    fn s19k_live427_is_wrap6_not_chain_inactive() {
        assert!(admit_s19k_live427_wrap6_without_clean().is_ok());
        assert!(refuse_s19k_live427_as_chain_inactive_result().is_err());
        assert_eq!(S19K_LIVE427_S1_LAST_RX_MS, 187_676);
        assert_eq!(S19K_LIVE427_S2_LAST_RX_MS, 195_686);
        assert_eq!(S19K_TRACK1_WRAP6_MS, 6 * 256 * 120);
    }

    #[test]
    fn s19k_live428_died_before_wrap4_not_inactive() {
        let serial_mining = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_live428_rx_died_before_wrap4_gpio_on().is_ok());
        assert!(refuse_s19k_live428_as_chain_inactive_result().is_err());
        assert_eq!(S19K_LIVE428_S1_LAST_RX_MS, 106_743);
        assert_eq!(S19K_LIVE428_S2_LAST_RX_MS, 111_173);
        assert_eq!(s19k_track1_wrap_index(0), 0);
        assert_eq!(s19k_track1_wrap_index(255), 0);
        assert_eq!(s19k_track1_wrap_index(256), 1);
        assert_eq!(s19k_track1_wrap_index(1024), 4);
        assert!(s19k_track1_wrap_barrier_due(1024));
        assert!(refuse_s19k_wrap_tx_skip_as_survival().is_err());
        assert_eq!(
            s19k_esp_bm1366_job_slot_count(S19K_ESP_BM1366_JOB_ID_STEP, S19K_ESP_BM1366_JOB_ID_MOD)
                .unwrap(),
            16
        );
        assert!(s19k_esp_bm1366_job_slot_count(8, 127).is_err());
        assert!(refuse_s19k_esp_plus8_mod128_as_track1_fill().is_err());
        assert!(refuse_s19k_bosminer_registry_wrap_as_chip_uart_abort().is_err());
        assert!(admit_s19k_live430_wrap4_gpio_on_no_clean().is_ok());
        assert!(refuse_s19k_live430_as_leftover_or_sigterm().is_err());
        assert_eq!(S19K_LIVE430_FREEZE_NONCES, 1074);
        assert_eq!(S19K_LIVE430_FIRST_FILL_SHARES, 5);
        assert_eq!(S19K_LIVE430_SHARE1_NONCE, 0x0193_BE97);
        assert!(S19K_LIVE430_MIDRUN_CLEAN_AFTER_RX_DEAD);
        assert_eq!(S19K_LIVE430_FUNNEL_RXS_AFTER_CLEAN, 0);
        assert_eq!(S19K_LIVE430_S1_LAST_RX_MS, 122_605);
        assert_eq!(S19K_LIVE430_S2_LAST_RX_MS, 127_998);
        assert!(admit_s19k_live431_wrap6_after_live_clean().is_ok());
        assert!(refuse_s19k_live431_as_wrap7_t600().is_err());
        assert_eq!(S19K_LIVE431_S1_LAST_RX_MS, 200_370);
        assert_eq!(S19K_LIVE431_S2_LAST_RX_MS, 209_456);
        assert!(admit_s19k_live432_rx_died_after_first_clean_inactive().is_ok());
        assert!(refuse_s19k_live432_tx_wrap7_as_rx_survival().is_err());
        assert!(refuse_s19k_live432_first_clean_inactive_as_leftover_admit().is_err());
        assert_eq!(S19K_LIVE432_S1_LAST_RX_MS, 155_032);
        assert_eq!(S19K_LIVE432_S2_LAST_RX_MS, 160_904);
        assert!(admit_s19k_live433_wrap6_identity_death().is_ok());
        assert!(refuse_s19k_live433_as_first_clean_inactive().is_err());
        assert!(refuse_s19k_live433_leftover_hit0_as_no_leftover().is_err());
        assert_eq!(S19K_LIVE433_S1_LAST_RX_MS, 189_042);
        assert_eq!(S19K_LIVE433_S2_LAST_RX_MS, 199_601);
        assert_eq!(S19K_LIVE433_CLEAN_MS, 145_213);
        assert_eq!(
            classify_s19k_track1_rx_death(Some(0), 11, 6, 1, 0, None, false),
            S19kTrack1RxDeathClass::WrapNoClean
        );
        assert_eq!(
            classify_s19k_held_uart_wrap6(),
            S19kHeldUartWrap6Class::NoHeldAbortOpcode
        );
        assert_eq!(S19K_TRACK1_WRAP6_TX, 1536);
        assert_eq!(s19k_esp_mod_wraps_at_track1_wrap6(), 12);
        assert!(admit_s19k_wrap6_death_not_held_uart_abort().is_ok());
        assert!(refuse_s19k_wrap6_as_esp16_or_bosminer_registry().is_err());
        assert!(admit_s19k_live434_wrap4_identity_death().is_ok());
        assert!(refuse_s19k_live434_as_wrap6_or_leftover_replace().is_err());
        assert!(admit_s19k_live435_dual_port_wrap7().is_ok());
        assert!(refuse_s19k_live435_as_wrap7_t600().is_err());
        assert!(refuse_s19k_live435_leftover0_as_replace().is_err());
        assert_eq!(S19K_LIVE435_S1_LAST_RX_MS, 249_636);
        assert_eq!(S19K_LIVE435_S2_LAST_RX_MS, 242_081);
        assert_eq!(S19K_LIVE435_WRAP_RX, 8);
        assert!(admit_s19k_live436_wrap4_death_with_wrap_retire_leftover().is_ok());
        assert!(refuse_s19k_live436_as_wrap7_t600_or_replace().is_err());
        assert_eq!(S19K_LIVE436_S1_LAST_RX_MS, 146_224);
        assert_eq!(S19K_LIVE436_S2_LAST_RX_MS, 153_747);
        assert_eq!(S19K_LIVE436_WRAP_RX, 4);
        assert!(admit_s19k_live437_wrap4_snapshot_without_inactive().is_ok());
        assert!(refuse_s19k_live437_as_leftover_admit_or_t600().is_err());
        assert_eq!(S19K_LIVE437_S1_LAST_RX_MS, 179_448);
        assert_eq!(S19K_LIVE437_S2_LAST_RX_MS, 187_931);
        assert_eq!(S19K_LIVE437_WRAP_RX, 6);
        assert_eq!(S19K_LIVE437_WRAP4_SNAPSHOT_LEFTOVER_HIT, 4);
        assert!(admit_s19k_live438_wrap4_same_tick_queued_cmd3().is_ok());
        assert!(refuse_s19k_live438_admit_as_replace().is_err());
        assert_eq!(S19K_LIVE438_WRAP4_ADMIT_LEFTOVER_HIT, 6);
        assert_eq!(S19K_LIVE438_WRAP4_ADMIT_LEFTOVER_HEADER, 0);
        assert_eq!(S19K_LIVE438_INACTIVE_QUEUED, 1);
        assert_eq!(S19K_LIVE438_S1_LAST_RX_MS, 151_822);
        assert_eq!(S19K_LIVE438_S2_LAST_RX_MS, 158_264);
        assert_eq!(S19K_LIVE438_WRAP_RX, 5);
        assert!(admit_s19k_live439_wrap7_after_leftover_admit().is_ok());
        assert!(admit_s19k_live440_wrap7_header_only_does_not_readmit().is_ok());
        assert!(admit_s19k_live441_wrap6_death_before_wrap7_snapshot().is_ok());
        assert!(refuse_s19k_live441_as_replace_or_t600().is_err());
        assert_eq!(S19K_LIVE441_WRAP_RX, 6);
        assert_eq!(S19K_LIVE441_WRAP7_SNAP_QUEUED, 0);
        assert!(admit_s19k_live442_wrap5_snapshot_header_only_does_not_readmit().is_ok());
        assert!(refuse_s19k_live442_as_replace_or_t600().is_err());
        assert_eq!(S19K_LIVE442_WRAP_RX, 8);
        assert_eq!(S19K_LIVE442_WRAP5_SNAP_QUEUED, 1);
        assert_eq!(S19K_LIVE442_WRAP5_READMIT_QUEUED, 0);
        assert_eq!(S19K_LIVE442_POST_FLUSH_LEFTOVER_HEADER, 9);
        assert!(admit_s19k_live443_history_tx_snapshot_header_only_does_not_readmit().is_ok());
        assert!(refuse_s19k_live443_as_replace_or_t600().is_err());
        assert_eq!(S19K_LIVE443_WRAP_RX, 6);
        assert_eq!(S19K_LIVE443_WRAP5_SNAP_QUEUED, 1);
        assert_eq!(S19K_LIVE443_WRAP5_READMIT_QUEUED, 0);
        assert_eq!(S19K_LIVE443_POST_FLUSH_LEFTOVER_HEADER, 5);
        assert!(admit_s19k_live444_merge_snapshot_header_only_does_not_readmit().is_ok());
        assert!(refuse_s19k_live444_as_replace_or_t600().is_err());
        assert_eq!(S19K_LIVE444_WRAP_RX, 6);
        assert_eq!(S19K_LIVE444_WRAP5_SNAP_QUEUED, 1);
        assert_eq!(S19K_LIVE444_WRAP5_READMIT_QUEUED, 0);
        assert_eq!(S19K_LIVE444_SHARES, 2);
        assert_eq!(S19K_LIVE444_POST_FLUSH_LEFTOVER_HEADER, 4);
        assert!(admit_s19k_live445_leftover_hit_readmits_header_only_still_refuses().is_ok());
        assert!(refuse_s19k_live445_as_replace_or_t600().is_err());
        assert_eq!(S19K_LIVE445_WRAP5_READMIT_QUEUED, 1);
        assert_eq!(S19K_LIVE445_WRAP5_READMIT_LEFTOVER_HIT, 2);
        assert_eq!(S19K_LIVE445_WRAP5_READMIT_LEFTOVER_HEADER, 0);
        assert_eq!(S19K_LIVE445_WRAP7_READMIT_QUEUED, 0);
        assert_eq!(S19K_LIVE445_POST_READMIT_LEFTOVER_HEADER, 1);
        assert_eq!(S19K_LIVE445_SHARES, 1);
        assert!(admit_s19k_live446_session_start_clean_does_not_block_wrap4_early().is_ok());
        assert!(refuse_s19k_live446_as_replace_or_t600().is_err());
        assert_eq!(S19K_LIVE446_WRAP_RX, 6);
        assert_eq!(S19K_LIVE446_LEFTOVER_HIT, 20);
        assert_eq!(S19K_LIVE446_WRAP4_ADMIT_QUEUED, 0);
        assert_eq!(S19K_LIVE446_WRAP5_READMIT_QUEUED, 0);
        assert_eq!(S19K_LIVE446_WRAP7_READMIT_QUEUED, 0);
        assert_eq!(S19K_LIVE446_SHARES, 0);
        assert!(admit_s19k_live447_wrap4_admit_wrap5_readmit_wrap7_honest_nonqueue().is_ok());
        assert!(refuse_s19k_live447_as_replace_or_t600().is_err());
        assert_eq!(S19K_LIVE447_WRAP4_ADMIT_QUEUED, 1);
        assert_eq!(S19K_LIVE447_WRAP5_READMIT_QUEUED, 1);
        assert_eq!(S19K_LIVE447_WRAP7_READMIT_QUEUED, 0);
        assert_eq!(S19K_LIVE447_DEATH_LEFTOVER_HIT, 185);
        assert_eq!(S19K_LIVE447_SHARES, 1);
        assert!(
            admit_s19k_live448_wrap7_after_leftover_admit_header_only_does_not_readmit().is_ok()
        );
        assert!(refuse_s19k_live448_as_replace_or_t600().is_err());
        assert_eq!(S19K_LIVE448_WRAP_RX, 9);
        assert_eq!(S19K_LIVE448_WRAP4_ADMIT_QUEUED, 1);
        assert_eq!(S19K_LIVE448_WRAP6_READMIT_QUEUED, 0);
        assert_eq!(S19K_LIVE448_DEATH_LEFTOVER_HEADER, 8);
        assert_eq!(S19K_LIVE448_SHARES, 0);
        assert!(refuse_s19k_live440_as_replace_or_t600().is_err());
        assert_eq!(S19K_LIVE440_WRAP4_ADMIT_LEFTOVER_HIT, 1);
        assert_eq!(S19K_LIVE440_POST_FLUSH_LEFTOVER_HEADER, 3);
        assert_eq!(S19K_LIVE440_WRAP_RX, 7);
        assert_eq!(S19K_LIVE440_WRAP7_READMIT_QUEUED, 0);
        assert!(refuse_s19k_live439_as_replace_or_t600().is_err());
        assert_eq!(S19K_LIVE439_WRAP4_ADMIT_LEFTOVER_HIT, 2);
        assert_eq!(S19K_LIVE439_SECOND_CLEAN_LEFTOVER_HIT, 216);
        assert_eq!(S19K_LIVE439_WRAP_RX_ALIVE, 7);
        assert_eq!(S19K_LIVE434_S1_LAST_RX_MS, 138_063);
        assert_eq!(S19K_LIVE434_S2_LAST_RX_MS, 145_225);
        assert_eq!(S19K_LIVE434_WRAP_RX, 4);
        assert!(!s19k_held_uart_prefix_is_wrap6_abort(&[
            0x55, 0xAA, 0x21, 0x36
        ]));
        assert!(refuse_s19k_held_uart_prefix_as_wrap6_abort(&[0x55, 0xAA, 0x21, 0x36]).is_err());
        assert!(refuse_s19k_held_uart_prefix_as_wrap6_abort(&[0x55, 0xAA, 0x53, 0x05]).is_err());
        let mut wrap_rx = 0u64;
        s19k_track1_note_wrap_at_rx(1024, &mut wrap_rx);
        assert_eq!(wrap_rx, 4);
        assert_eq!(s19k_track1_wrap_index(2300), 8);
        assert!(s19k_track1_tx_wrap_after_rx_death(9, 5));
        assert!(!s19k_track1_tx_wrap_after_rx_death(5, 5));
        assert!(admit_s19k_live432_rx_death_is_first_clean_inactive().is_ok());
        assert_eq!(
            classify_s19k_track1_rx_death(Some(1), 4, 4, 0, 0, None, false),
            S19kTrack1RxDeathClass::GpioRailOff
        );
        assert_eq!(
            classify_s19k_track1_rx_death(Some(0), 6, 6, 0, 0, None, false),
            S19kTrack1RxDeathClass::WrapNoClean
        );
        assert_eq!(
            classify_s19k_track1_rx_death(Some(0), 6, 6, 1, 4, None, false),
            S19kTrack1RxDeathClass::LeftoverAfterClean
        );
        assert_eq!(
            classify_s19k_track1_rx_death(Some(0), 6, 4, 1, 0, None, true),
            S19kTrack1RxDeathClass::CleanAfterRxDeath
        );
        assert!(s19k_track1_clean_after_rx_death_ms(
            S19K_LIVE434_CLEAN_MS,
            S19K_LIVE434_S2_LAST_RX_MS
        ));
        assert!(!s19k_track1_clean_after_rx_death_ms(
            S19K_LIVE433_CLEAN_MS,
            S19K_LIVE433_S1_LAST_RX_MS
        ));
        assert!(s19k_track1_clean_after_rx_death_silent(62, 69));
        assert!(!s19k_track1_clean_after_rx_death_silent(0, 0));
        let t0 = std::time::Instant::now();
        let mut s1 = t0;
        let mut s2 = t0;
        s19k_track1_note_port_rx(Some("/dev/ttyS1"), t0, &mut s1, &mut s2);
        assert_eq!(s19k_track1_port_silent_s(s1, t0), 0);
        assert!(admit_s19k_production_alive_prints_per_port_silent(serial_mining).is_ok());
    }
}

// live429 first WORK 15:14:57.967Z; SIGTERM 15:15:06.895Z (9 s).
// Foreign launch.sh pidof kill — see s19k_am3_install.
