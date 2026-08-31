// SPDX-License-Identifier: GPL-3.0-or-later
//
// CGMiner port-4028 ascset command vocabulary.
//
// Wire format: pipe-delimited ASCII, single-line, terminated by newline:
//   `ascset|0,<cmd>[,<arg1>[,<arg2>...]]\n`
//
// Public commands documented at:
//    (A10 Universal API manual)
//
// Privileged commands extracted from the Avalon Family mobile app
// — not in the public docs but visible
// in the Flutter+Rust client. Documented in
//    §1.
//
// Used by both DCENT_axe Avalon (Nano 3/3S) and DCENT_OS Avalon (industrial).

use core::fmt;
use core::fmt::Write as _;

#[derive(Debug, thiserror::Error)]
pub enum AscsetError {
    #[error("encode buffer too small")]
    BufferTooSmall,
    /// `UpgradeFrame::api_ver` must fit the low 7 bits (byte0 high bit is the
    /// endian flag).
    #[error("upgrade api_ver out of range (max 127)")]
    UpgradeApiVerOutOfRange,
    /// One page's payload must fit the 2-byte `payload_len` field.
    #[error("upgrade payload too large for one page (max 65535 bytes)")]
    UpgradePayloadTooLarge,
}

// ---------------------------------------------------------------------------
// `ascset|0,upgrade,<hex>` — AvalonMiner MM3 firmware-transfer (OTA) frame.
//
// Mirrors HashSource `fmsc/cgminerapi.py::_prepare_upgrade_param` (Apache-2.0
// fms-core) and the transfer loop in `fmsc/aioupgrade.py`. The firmware is
// streamed as a sequence of pages; each page is one little-endian header
// (`UPGRADE_HEADER_SIZE` bytes) followed by up to `UPGRADE_PAGE_LEN` payload
// bytes, and the whole buffer is lowercase-hex-encoded and sent as
// `ascset|0,upgrade,<hex>`.
//
// Wire layout (all multi-byte integer fields little-endian):
//   off  size  field
//    0    1    byte0        = (endian_flag << 7) | api_ver   (endian_flag = 0)
//    1    1    header_len   = 30 (0x1e) — the DECLARED count, NOT the 32-byte size
//    2    2    cmd_id       — caller-chosen (fms-core randomises; the Canaan
//                             desktop tool increments per page)
//    4    1    sub_cmd      = 0
//    5    3    reserved1    = 0
//    8    4    uid          = session id (== int(start_time))
//   12    8    version      — target fw ver: first 8 chars, then left-'0'-padded
//                             to 8 (Python `version[:8].zfill(8)`), latin1
//   20    4    file_size    — total firmware byte length (constant per session)
//   24    4    offset       — byte offset of this page into the firmware
//   28    2    payload_len  — this page's byte count
//   30    2    reserved2    = 0
//   32   ..    payload      — this page's bytes
//
// Desk-validated byte-for-byte against the HashSource `Canaan_Peek` captures
// `Avalon-Upgrade-Wireshark.pcapng` (608 frames) and `fms_send_upgrade_file.pcapng`
// (825 frames): every real frame decoded to api_ver=2, header_len=30, sub_cmd=0,
// reserved1/2 zero, version="YYMMDDnn", with `offset` advancing by `payload_len`.
// See `tests::upgrade_frame_matches_*_pcap_header` for the pinned vectors.
// ---------------------------------------------------------------------------

/// Value of the on-wire `header_len` field (byte 1). Note this is the fms-core
/// declared value (30), which is intentionally two less than the real 32-byte
/// header that precedes the payload.
pub const UPGRADE_HEADER_LEN_FIELD: u8 = 30;
/// Actual number of header bytes emitted before the payload.
pub const UPGRADE_HEADER_SIZE: usize = 32;
/// fms-core default per-page payload length. This is a caller/transport policy
/// default, NOT a wire maximum — the Canaan desktop tool streams 1300-byte
/// pages (see the pcaps), which `UpgradeFrame::build` accepts.
pub const UPGRADE_PAGE_LEN: usize = 888;
/// Fixed on-wire length of the ASCII `version` field.
pub const UPGRADE_VERSION_LEN: usize = 8;

/// Encode the 8-byte `version` field exactly as fms-core does:
/// `version[:8].zfill(8).encode('latin1')` — take the first 8 chars, then
/// left-pad with `'0'` to 8, one byte per char (latin1). Avalon fw versions are
/// ASCII, so this is byte-identical to the reference for all real inputs.
fn encode_upgrade_version(version: &str) -> [u8; UPGRADE_VERSION_LEN] {
    let mut out: [u8; UPGRADE_VERSION_LEN] = [b'0'; UPGRADE_VERSION_LEN];
    // First up to 8 chars as latin1 (codepoint low 8 bits), matching
    // Python `version[:8].encode('latin1')`.
    let take: Vec<u8> = version
        .chars()
        .take(UPGRADE_VERSION_LEN)
        .map(|c| c as u8)
        .collect();
    // `zfill` left-pads with '0': place the taken bytes flush-right.
    let start = UPGRADE_VERSION_LEN - take.len();
    out[start..].copy_from_slice(&take);
    out
}

/// Parameters for one `ascset|0,upgrade,<hex>` firmware-transfer page.
///
/// Build the raw bytes with [`UpgradeFrame::build`] or the full ascset line with
/// [`UpgradeFrame::encode_line`]. The multi-page transfer loop, the `Err04`
/// offset resync, and the `UPAPI<2` header strip live on the toolbox side
/// (`backends/avalon.py`); this type is the single authoritative frame codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpgradeFrame<'a> {
    /// Upgrade API version (0..=127). Placed in the low 7 bits of byte0.
    pub api_ver: u8,
    /// 2-byte command id (little-endian on the wire).
    pub cmd_id: u16,
    /// 4-byte session id (== `int(start_time)`).
    pub uid: u32,
    /// Target firmware version string (truncated/zero-padded to 8, latin1).
    pub version: &'a str,
    /// Total firmware byte length (constant for the whole transfer).
    pub file_size: u32,
    /// Byte offset of this page into the firmware.
    pub offset: u32,
    /// This page's payload bytes (`<= UPGRADE_PAGE_LEN` by convention; the wire
    /// limit is 65535, the `payload_len` field width).
    pub payload: &'a [u8],
}

impl<'a> UpgradeFrame<'a> {
    /// Build the raw little-endian frame bytes (`UPGRADE_HEADER_SIZE`-byte
    /// header followed by the payload).
    pub fn build(&self) -> Result<Vec<u8>, AscsetError> {
        if self.api_ver > 0x7f {
            return Err(AscsetError::UpgradeApiVerOutOfRange);
        }
        let payload_len =
            u16::try_from(self.payload.len()).map_err(|_| AscsetError::UpgradePayloadTooLarge)?;

        let mut buf = Vec::with_capacity(UPGRADE_HEADER_SIZE + self.payload.len());
        let endian_flag: u8 = 0; // 0 = little-endian, per fms-core
        buf.push((endian_flag << 7) | self.api_ver); // byte0
        buf.push(UPGRADE_HEADER_LEN_FIELD); // header_len = 30
        buf.extend_from_slice(&self.cmd_id.to_le_bytes()); // cmd_id (2)
        buf.push(0); // sub_cmd
        buf.extend_from_slice(&[0u8; 3]); // reserved1 (3)
        buf.extend_from_slice(&self.uid.to_le_bytes()); // uid (4)
        buf.extend_from_slice(&encode_upgrade_version(self.version)); // version (8)
        buf.extend_from_slice(&self.file_size.to_le_bytes()); // file_size (4)
        buf.extend_from_slice(&self.offset.to_le_bytes()); // offset (4)
        buf.extend_from_slice(&payload_len.to_le_bytes()); // payload_len (2)
        buf.extend_from_slice(&[0u8; 2]); // reserved2 (2)
        debug_assert_eq!(buf.len(), UPGRADE_HEADER_SIZE);
        buf.extend_from_slice(self.payload); // payload
        Ok(buf)
    }

    /// Encode the full `ascset|0,upgrade,<hex>` line (no trailing newline),
    /// hex-encoding the frame lowercase, 2 digits per byte, exactly as fms-core.
    pub fn encode_line(&self) -> Result<String, AscsetError> {
        let bytes = self.build()?;
        let mut line = String::with_capacity("ascset|0,upgrade,".len() + bytes.len() * 2);
        line.push_str("ascset|0,upgrade,");
        for b in &bytes {
            // infallible write into a String
            let _ = write!(line, "{:02x}", b);
        }
        Ok(line)
    }
}

/// Public + privileged ascset command set. Add variants as we wire features.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AscsetCommand<'a> {
    /// Reboot the miner.
    Reboot,
    /// Toggle the IP-report LED. `1-1` = on, `1-0` = off (per A10 manual).
    Led { on: bool },
    /// Change operating mode (0=Normal, 1=Performance, 255=Query).
    Workmode(u8),
    /// Configure the primary pool using the five-field Canaan Universal API
    /// form: web username, web password, pool URL, worker, pool password.
    SetPool {
        username: &'a str,
        web_password: &'a str,
        url: &'a str,
        worker: &'a str,
        pool_password: &'a str,
    },
    /// Set static IP / DNS / DHCP. Free-form payload, format varies by firmware.
    Ip(&'a str),
    /// Set DNS servers, comma-separated.
    Dns(&'a str),
    /// Toggle hash-board power (0 = off, 1 = on).
    HashPower(u8),
    /// Privileged: change the web GUI password.
    Password { current: &'a str, new: &'a str },
    /// Privileged: enable QR-code-based authentication.
    QrAuth(&'a str),
    /// Privileged: per-step work level (deeper than workmode).
    WorkLevel(u8),
    /// Privileged: trigger filter cleaning indicator/timer.
    FilterClean,
    /// Privileged: night-lamp dimming.
    NightLamp { on: bool },
    /// Privileged: full software-power-off (vs. reboot).
    SoftOff,
    /// Privileged: software-power-on.
    SoftOn,
    /// Privileged: solo mining permission flag.
    SoloAllowed(bool),
    /// Privileged: LCD wallpaper choice.
    Wallpaper(&'a str),
    /// Privileged: control the LCD on Nano 3S.
    Lcd(&'a str),
    /// Privileged: RGB LED color/pattern.
    LedSet(&'a str),
    /// Privileged: audio chirp/beep.
    Audio(&'a str),
    /// Privileged: WiFi command family (`wifi|<sub>`).
    Wifi(&'a str),
    /// Privileged: time set.
    TimeSet(&'a str),
    /// Privileged: lite stats query (compact telemetry).
    LiteStats,
    /// Privileged: one MM3 firmware-transfer page (`ascset|0,upgrade,<hex>`).
    /// DESTRUCTIVE — this is the OTA flash verb. See [`UpgradeFrame`].
    Upgrade(UpgradeFrame<'a>),
}

impl<'a> AscsetCommand<'a> {
    /// Encode this command as a `ascset|0,...` line **without** trailing newline.
    pub fn encode(&self) -> String {
        match *self {
            Self::Reboot => "ascset|0,reboot,0".to_string(),
            Self::Led { on } => format!("ascset|0,led,1-{}", if on { '1' } else { '0' }),
            Self::Workmode(m) => format!("ascset|0,workmode,{}", m),
            Self::SetPool {
                username,
                web_password,
                url,
                worker,
                pool_password,
            } => format!(
                "ascset|0,setpool,{},{},{},{},{}",
                username, web_password, url, worker, pool_password
            ),
            Self::Ip(p) => format!("ascset|0,ip,{}", p),
            Self::Dns(p) => format!("ascset|0,dns,{}", p),
            Self::HashPower(v) => format!("ascset|0,hashpower,{}", v),
            Self::Password { current, new } => {
                format!("ascset|0,password,{},{}", current, new)
            }
            Self::QrAuth(p) => format!("ascset|0,qr_auth,{}", p),
            Self::WorkLevel(v) => format!("ascset|0,worklevel,{}", v),
            Self::FilterClean => "ascset|0,filter-clean".to_string(),
            Self::NightLamp { on } => {
                format!("ascset|0,nightlamp,{}", if on { 1 } else { 0 })
            }
            Self::SoftOff => "ascset|0,softoff".to_string(),
            Self::SoftOn => "ascset|0,softon".to_string(),
            Self::SoloAllowed(b) => {
                format!("ascset|0,solo-allowed,{}", if b { 1 } else { 0 })
            }
            Self::Wallpaper(p) => format!("ascset|0,wallpaper,{}", p),
            Self::Lcd(p) => format!("ascset|0,lcd,{}", p),
            Self::LedSet(p) => format!("ascset|0,ledset,{}", p),
            Self::Audio(p) => format!("ascset|0,audio,{}", p),
            Self::Wifi(p) => format!("ascset|0,wifi|{}", p),
            Self::TimeSet(p) => format!("ascset|0,time|set,{}", p),
            Self::LiteStats => "ascset|0,litestats".to_string(),
            // A malformed UpgradeFrame (api_ver > 127 / payload > 65535) can't be
            // represented on the wire; encode() is infallible by contract, so we
            // emit the empty string. Callers that need the error use
            // `UpgradeFrame::encode_line` directly.
            Self::Upgrade(frame) => frame.encode_line().unwrap_or_default(),
        }
    }

    /// True if this command requires authenticated/privileged access.
    pub fn is_privileged(&self) -> bool {
        matches!(
            self,
            Self::Password { .. }
                | Self::QrAuth(_)
                | Self::WorkLevel(_)
                | Self::FilterClean
                | Self::NightLamp { .. }
                | Self::SoftOff
                | Self::SoftOn
                | Self::SoloAllowed(_)
                | Self::Wallpaper(_)
                | Self::Lcd(_)
                | Self::LedSet(_)
                | Self::Audio(_)
                | Self::Wifi(_)
                | Self::TimeSet(_)
                | Self::LiteStats
                | Self::Upgrade(_)
        )
    }
}

impl<'a> fmt::Display for AscsetCommand<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_public_commands() {
        assert_eq!(AscsetCommand::Reboot.encode(), "ascset|0,reboot,0");
        assert_eq!(AscsetCommand::Led { on: true }.encode(), "ascset|0,led,1-1");
        assert_eq!(
            AscsetCommand::Led { on: false }.encode(),
            "ascset|0,led,1-0"
        );
        assert_eq!(AscsetCommand::Workmode(1).encode(), "ascset|0,workmode,1");
        assert_eq!(AscsetCommand::HashPower(0).encode(), "ascset|0,hashpower,0");
    }

    #[test]
    fn encodes_setpool() {
        let c = AscsetCommand::SetPool {
            username: "root",
            web_password: "root",
            url: "stratum+tcp://solo.ckpool.org:3333",
            worker: "bc1q.test",
            pool_password: "x",
        };
        assert_eq!(
            c.encode(),
            "ascset|0,setpool,root,root,stratum+tcp://solo.ckpool.org:3333,bc1q.test,x"
        );
    }

    #[test]
    fn flags_privileged() {
        assert!(AscsetCommand::Password {
            current: "a",
            new: "b"
        }
        .is_privileged());
        assert!(AscsetCommand::Wifi("scan").is_privileged());
        assert!(!AscsetCommand::Reboot.is_privileged());
        assert!(!AscsetCommand::Workmode(0).is_privileged());
    }

    #[test]
    fn privileged_encodings_are_literal_and_flagged() {
        let cases = [
            (AscsetCommand::WorkLevel(3), "ascset|0,worklevel,3"),
            (AscsetCommand::Wifi("scan"), "ascset|0,wifi|scan"),
            (
                AscsetCommand::TimeSet("2026-07-05T00:00:00Z"),
                "ascset|0,time|set,2026-07-05T00:00:00Z",
            ),
            (AscsetCommand::SoftOff, "ascset|0,softoff"),
            (AscsetCommand::SoftOn, "ascset|0,softon"),
        ];

        for (cmd, encoded) in cases {
            assert_eq!(cmd.encode(), encoded);
            assert!(cmd.is_privileged(), "{encoded} must stay privileged");
        }
    }

    #[test]
    fn public_power_and_pool_commands_are_not_privileged_by_vocab() {
        assert!(!AscsetCommand::HashPower(0).is_privileged());
        assert!(!AscsetCommand::SetPool {
            username: "root",
            web_password: "root",
            url: "stratum+tcp://pool:3333",
            worker: "worker.1",
            pool_password: "x",
        }
        .is_privileged());
    }

    // -- ascset|0,upgrade firmware-transfer frame ---------------------------

    /// Hex of the first `UPGRADE_HEADER_SIZE` bytes a frame builds to.
    fn header_hex(frame: &UpgradeFrame<'_>) -> String {
        let bytes = frame.build().unwrap();
        bytes[..UPGRADE_HEADER_SIZE]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[test]
    fn upgrade_frame_header_layout_is_32_bytes_field_30() {
        // The declared header_len field is 30 but the real header is 32 bytes.
        let frame = UpgradeFrame {
            api_ver: 2,
            cmd_id: 1,
            uid: 0,
            version: "1",
            file_size: 100,
            offset: 0,
            payload: &[0xAB, 0xCD],
        };
        let bytes = frame.build().unwrap();
        assert_eq!(bytes.len(), UPGRADE_HEADER_SIZE + 2);
        assert_eq!(bytes[1], UPGRADE_HEADER_LEN_FIELD);
        assert_eq!(bytes[1], 30);
        assert_eq!(UPGRADE_HEADER_SIZE, 32);
        // payload lands immediately after the 32-byte header
        assert_eq!(&bytes[UPGRADE_HEADER_SIZE..], &[0xAB, 0xCD]);
    }

    // The two vectors below are decoded verbatim from the HashSource `Canaan_Peek`
    // Wireshark captures (`Avalon-Upgrade-Wireshark.pcapng` frame 0/1). They pin
    // the exact 32-byte header this builder must reproduce.
    #[test]
    fn upgrade_frame_matches_avalon_pcap_header_frame0() {
        // api_ver=2 cmd_id=2 uid=1564252679 version="YYMMDDnn"
        // file_size=769096 offset=0 payload_len=1300
        let payload = vec![0u8; 1300];
        let frame = UpgradeFrame {
            api_ver: 2,
            cmd_id: 2,
            uid: 1_564_252_679,
            version: "YYMMDDnn",
            file_size: 769_096,
            offset: 0,
            payload: &payload,
        };
        assert_eq!(
            header_hex(&frame),
            "021e020000000000079a3c5d59594d4d44446e6e48bc0b000000000014050000"
        );
    }

    #[test]
    fn upgrade_frame_matches_avalon_pcap_header_frame1() {
        // Second page: cmd_id=3, offset=1300 (0x0514), still payload_len=1300.
        let payload = vec![0u8; 1300];
        let frame = UpgradeFrame {
            api_ver: 2,
            cmd_id: 3,
            uid: 1_564_252_679,
            version: "YYMMDDnn",
            file_size: 769_096,
            offset: 1300,
            payload: &payload,
        };
        assert_eq!(
            header_hex(&frame),
            "021e030000000000079a3c5d59594d4d44446e6e48bc0b001405000014050000"
        );
    }

    #[test]
    fn upgrade_frame_matches_fms_pcap_header_frame0() {
        // fms_send_upgrade_file.pcapng frame 0:
        // cmd_id=2 uid=444313857 file_size=1069965 offset=0 payload_len=1300
        let payload = vec![0u8; 1300];
        let frame = UpgradeFrame {
            api_ver: 2,
            cmd_id: 2,
            uid: 444_313_857,
            version: "YYMMDDnn",
            file_size: 1_069_965,
            offset: 0,
            payload: &payload,
        };
        assert_eq!(
            header_hex(&frame),
            "021e02000000000001b17b1a59594d4d44446e6e8d5310000000000014050000"
        );
    }

    #[test]
    fn upgrade_version_field_is_truncated_and_zero_padded() {
        // Short version → left-'0'-padded to 8 (Python zfill).
        let short = UpgradeFrame {
            api_ver: 1,
            cmd_id: 0,
            uid: 0,
            version: "abc",
            file_size: 0,
            offset: 0,
            payload: &[],
        };
        let bytes = short.build().unwrap();
        assert_eq!(&bytes[12..20], b"00000abc");

        // Over-length version → first 8 chars only.
        let long = UpgradeFrame {
            version: "0123456789",
            ..short
        };
        let bytes = long.build().unwrap();
        assert_eq!(&bytes[12..20], b"01234567");
    }

    #[test]
    fn upgrade_encode_line_is_hex_prefixed_ascset() {
        let frame = UpgradeFrame {
            api_ver: 2,
            cmd_id: 2,
            uid: 1_564_252_679,
            version: "YYMMDDnn",
            file_size: 769_096,
            offset: 0,
            payload: &[0xDE, 0xAD],
        };
        let line = frame.encode_line().unwrap();
        assert!(line.starts_with("ascset|0,upgrade,"));
        let hex = line.strip_prefix("ascset|0,upgrade,").unwrap();
        // header (32 B) + 2 payload bytes = 34 B = 68 hex chars, all lowercase.
        assert_eq!(hex.len(), (UPGRADE_HEADER_SIZE + 2) * 2);
        assert!(hex.ends_with("dead"));
        assert_eq!(hex, hex.to_ascii_lowercase());
        // The enum wrapper round-trips through the same encoder.
        assert_eq!(AscsetCommand::Upgrade(frame).encode(), line);
    }

    #[test]
    fn upgrade_command_is_privileged() {
        let frame = UpgradeFrame {
            api_ver: 2,
            cmd_id: 0,
            uid: 0,
            version: "1",
            file_size: 0,
            offset: 0,
            payload: &[],
        };
        assert!(AscsetCommand::Upgrade(frame).is_privileged());
    }

    #[test]
    fn upgrade_rejects_out_of_range_api_ver() {
        let frame = UpgradeFrame {
            api_ver: 200, // > 127, collides with the endian flag
            cmd_id: 0,
            uid: 0,
            version: "1",
            file_size: 0,
            offset: 0,
            payload: &[],
        };
        assert!(matches!(
            frame.build(),
            Err(AscsetError::UpgradeApiVerOutOfRange)
        ));
    }
}
