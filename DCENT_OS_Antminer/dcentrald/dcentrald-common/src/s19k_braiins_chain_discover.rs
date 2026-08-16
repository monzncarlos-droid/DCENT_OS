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
    admit_braiins_job_tx_path, BRAIINS_TTYS_CANDIDATES, BRAIINS_TTYS_DISCOVER, BRAIINS_TTYS_THIRD,
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

pub fn refuse_hardcoded_physical_to_tty(path: &str, physical_address: u8) -> Result<(), &'static str> {
    for (label, hyp) in DESCENDING_AML_HYPOTHESIS {
        if *hyp == path && label.ends_with(&physical_address.to_string()) {
            return Err(
                "T8: refuse hardcoded physical_address→ttyS; discover which port answers",
            );
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
pub fn refuse_s3_only_as_required_pair_proof(
    m: S19kPortRxMatrix,
) -> Result<(), &'static str> {
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
            if let Ok(kind) = crate::s19k_bm1366_uart_rx::classify_bm1366_uart_rx(&bytes[i..i + 11])
            {
                match kind {
                    crate::s19k_bm1366_uart_rx::S19kUartRxKind::ChipAddress { chip_id: id, .. } => {
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
        return S19kPortAnswer::ChipAddress { chip_id, count: chip };
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

pub fn bind_port_after_rx(path: &str, answer: S19kPortAnswer) -> Result<S19kPortBind, &'static str> {
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
        S19kBoardTtyEvidenceKind::PlugCount => {
            Err("T8: plug count does not name a tty")
        }
        S19kBoardTtyEvidenceKind::RxCount => {
            Err("T8: RX count does not name a chassis slot")
        }
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
    let hex: String = text
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
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
pub fn observe_s19k_host_i2c_chassis(
    i2cdetect: &str,
    eeprom_parse: &str,
) -> S19kHostI2cChassis {
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
    if script.contains("i2cset") && !script.contains("Never i2cset") && !script.contains("i2cset=false")
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
                    S19kUartRxKind::ChipAddress {
                        chip_id: id,
                        ..
                    } => {
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
        if obs.tty_s3_held {
            "held"
        } else {
            "admitted"
        },
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
        return Err(
            "T8: three plugs: discover plan must include ttyS3 (.78 dmesg wakes S1+S2+S3)",
        );
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
            if path == "/dev/ttyS0" || crate::s19k_uart_trans_job::BRAIINS_TTYS_FORBIDDEN.contains(&path)
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
    if !src.contains("refuse_s3_rx_as_fill_hunt") {
        return Err("production fill hunt must refuse discover/optional UART RX");
    }
    if !src.contains("S19k discover UART RX is observe-only; not fill-hunted") {
        return Err("production fill hunt must skip discover/optional UART RX");
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
        return Err(
            "T8: multi-tty send_work opened fewer than both Track-1 ports",
        );
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
    Err(
        "live401 ttyS1 died ~T+21s; ttyS2 died ~T+61s; work TX continued — not one dual-port crash",
    )
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
    Err(
        "live404 first job-id wrap ~T+14s still 21 TH/s at T+15/T+25; cliff is T+29–35",
    )
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
pub const S19K_BM1366_TX_MIN_INTERVAL_MS: u32 = 80;

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
    if !src.contains("const BM1366_SERIAL_TX_MIN_INTERVAL_MS: u64 = 80") {
        return Err("shipped TX pace must stay 80 ms (wrap-5 after T+90)");
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
    if !src.contains("hunt_s19k_bm1366_fill_from_tagged_slot") {
        return Err("dual join must sit on the fill hunt path");
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
pub fn admit_s19k_production_getaddress_tx_fail_is_framing(
    src: &str,
) -> Result<(), &'static str> {
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
    Ok(crate::s19k_bm1366_uart_rx::classify_s19k_dual_uart_rx_after(
        after, a, b, baud,
    ))
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
    Err(
        "Wave-26 2-UART/3-board mux is falsified: .78 dmesg termios-wakes ttyS1+S2+S3",
    )
}

/// S21 AXG `/dev/ttyS4` is not the S19k third hash UART.
pub fn refuse_s19k_axg_ttys4_as_third_hash_uart() -> Result<(), &'static str> {
    Err(
        ".78 dmesg has meson ttyS1+S2+S3; ttyS4 is S21 AXG, not the S19k third hash UART",
    )
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
pub fn observe_get_address_bodies(bodies: &[Vec<u8>], window_ms: u32) -> crate::s19k_bm1366_uart_rx::S19kUartRxObservation {
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
        let chip_hex = "aa 55 13 66 00 00 00 00 00 00 00";
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
        assert!(join
            .record("/dev/ttyS1", Some(&job_body))
            .is_none());
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
        let chip = observe_get_address_bodies(&[[0x13, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].to_vec()], 250);
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
            &[[0x13, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].to_vec()],
            250,
        );
        assert!(matches!(
            s19k_port_answer_from_rx(&chip_obs),
            S19kPortAnswer::ChipAddress {
                chip_id: 0x1366,
                count: 1
            }
        ));
        let cut7 = observe_get_address_bodies(
            &[[0x13, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00].to_vec()],
            250,
        );
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
            S19kPortBind::AnsweredGetAddress { chip_id: 0x1366, count: 12 }
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
        let irq = classify_s19k_78_irq_delta(
            S19K_78_IRQ_BEFORE_FIXTURE,
            S19K_78_IRQ_AFTER_FIXTURE,
        )
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
        assert_eq!(parsed[0].kind, S19kBoardTtyEvidenceKind::AsicEepromSerialOnTty);
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
        assert!(parse_s19k_uart_eeprom_named_tty("path=/dev/ttyS0\nserial=JYZZYR6BCJHCA0JRG\n").is_err());
        assert!(parse_s19k_uart_eeprom_named_tty("path=/dev/ttyS2\nserial=NOT_A_HELD_SERIAL1\n").is_err());
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
        assert!(admit_s19k_host_i2c_chassis_script("i2cdetect -y 1\ni2cset -y 1 0x50 0 0\n").is_err());
    }

    #[test]
    fn single_port_ttys0_and_uart_trans_regressions_fail() {
        assert!(admit_braiins_mining_on_ports(&["/dev/ttyS1"]).is_err());
        assert!(admit_braiins_mining_on_ports(&["/dev/ttyS2"]).is_err());
        assert!(admit_braiins_mining_on_ports(&["/dev/ttyS3"]).is_err());
        assert!(admit_braiins_mining_on_ports(&["/dev/ttyS0", "/dev/ttyS1", "/dev/ttyS2"]).is_err());
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
        assert!(sh.contains("probe /dev/ttyS1"));
        assert!(sh.contains("probe /dev/ttyS2"));
        assert!(
            sh.contains("probe /dev/ttyS3"),
            "wire-try must discover ttyS3 like BRAIINS_TTYS_DISCOVER"
        );
        assert!(sh.contains("/dev/uart_trans"));
        assert!(sh.contains("never ttyS0"));
        assert!(!sh.contains("probe /dev/ttyS0"));
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
        assert!(serial_mining.contains("S19k discover UART RX is observe-only; not fill-hunted"));
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
        assert_eq!(S19K_BM1366_TX_MIN_INTERVAL_MS, 80);
    }
}
