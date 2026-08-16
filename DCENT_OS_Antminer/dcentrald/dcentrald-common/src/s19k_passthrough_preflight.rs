//! Track-1 passthrough preflight: distinguish rail-down from UART silence.
//!
//! Live 2026-08-12 0-RX after `S99bosminer stop` is **not** a job-shape proof.
//! That stop drives GPIO437=1 (am3-s19k DISABLE). This module classifies
//! observe-only sysfs + GetAddress answers. It never writes GPIO or UART.

use crate::s19k_am3_gpio437::{
    classify_s19k_am3_gpio437, passthrough_must_keep_gpio437_engaged, s19k_am3_plug_present,
    s19k_am3_plug_present_count, S19kAm3Gpio437Rail,
};
use crate::s19k_braiins_chain_discover::{
    s19k_multi_send_work_tx_required, S19kPortAnswer,
};

/// Why GetAddress / work RX can be empty. Silence is not a parser error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kSilenceClass {
    /// GPIO437=1. `S99bosminer stop` / cooldown. Job shape is not implicated.
    RailsDisabled,
    /// GPIO437=0 but no plug GPIO reads 1. Board may be unseated.
    NoBoardPlugged,
    /// At least one required UART (ttyS1/ttyS2) answered ChipAddress 0x1366.
    ChipAnswered,
    /// ttyS3 answered ChipAddress/JobNonce; ttyS1+ttyS2 did not.
    /// Discover-only — not required-pair / dual-chain proof.
    DiscoverOnly,
    /// Host `55 AA` echo / short AA55. Transport polarity, not ASIC silence.
    FramingOrEcho,
    /// Rails engaged, at least one plug present, both ttyS silent.
    /// Baud / reset / job / address — **not** "parser ate the nonce".
    SilenceWithRailsUp,
    /// Missing GPIO or plug reads; do not invent a cause.
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kPassthroughPreflight {
    pub gpio437: Option<u8>,
    pub plugs: [Option<u8>; 3],
    pub tty_s1: S19kPortAnswer,
    pub tty_s2: S19kPortAnswer,
    pub tty_s3: S19kPortAnswer,
}

pub fn classify_s19k_passthrough_silence(p: S19kPassthroughPreflight) -> S19kSilenceClass {
    match classify_s19k_am3_gpio437(p.gpio437) {
        S19kAm3Gpio437Rail::DisabledOrCooldown => return S19kSilenceClass::RailsDisabled,
        S19kAm3Gpio437Rail::Unknown => {
            if p.gpio437.is_none() {
                return S19kSilenceClass::Inconclusive;
            }
        }
        S19kAm3Gpio437Rail::Engaged => {}
    }
    let required_chip = matches!(
        p.tty_s1,
        S19kPortAnswer::ChipAddress {
            chip_id: 0x1366,
            ..
        }
    ) || matches!(
        p.tty_s2,
        S19kPortAnswer::ChipAddress {
            chip_id: 0x1366,
            ..
        }
    );
    if required_chip {
        return S19kSilenceClass::ChipAnswered;
    }
    let discover_only = matches!(
        p.tty_s3,
        S19kPortAnswer::ChipAddress {
            chip_id: 0x1366,
            ..
        } | S19kPortAnswer::JobNonce { .. }
    );
    if discover_only {
        return S19kSilenceClass::DiscoverOnly;
    }
    let framing = matches!(p.tty_s1, S19kPortAnswer::FramingOrEcho)
        || matches!(p.tty_s2, S19kPortAnswer::FramingOrEcho)
        || matches!(p.tty_s3, S19kPortAnswer::FramingOrEcho);
    if framing {
        return S19kSilenceClass::FramingOrEcho;
    }
    let known_plugs = p.plugs.iter().filter(|v| v.is_some()).count();
    if known_plugs == 3 && s19k_am3_plug_present_count(p.plugs) == 0 {
        return S19kSilenceClass::NoBoardPlugged;
    }
    if classify_s19k_am3_gpio437(p.gpio437) == S19kAm3Gpio437Rail::Engaged
        && s19k_am3_plug_present_count(p.plugs) > 0
        && matches!(p.tty_s1, S19kPortAnswer::Silence)
        && matches!(p.tty_s2, S19kPortAnswer::Silence)
        && matches!(p.tty_s3, S19kPortAnswer::Silence)
    {
        return S19kSilenceClass::SilenceWithRailsUp;
    }
    S19kSilenceClass::Inconclusive
}

pub fn format_s19k_passthrough_preflight(
    p: S19kPassthroughPreflight,
    class: S19kSilenceClass,
) -> String {
    fn plug(v: Option<u8>) -> String {
        match s19k_am3_plug_present(v) {
            Some(true) => "1".into(),
            Some(false) => "0".into(),
            None => "?".into(),
        }
    }
    fn ans(a: S19kPortAnswer) -> &'static str {
        match a {
            S19kPortAnswer::Silence => "silence",
            S19kPortAnswer::ChipAddress { .. } => "chip",
            S19kPortAnswer::JobNonce { .. } => "nonce",
            S19kPortAnswer::FramingOrEcho => "echo",
        }
    }
    format!(
        "S19K_PREFLIGHT class={class:?} gpio437={g} plugs439/440/441={a}/{b}/{c} ttyS1={s1} ttyS2={s2} ttyS3={s3} (S99 stop => gpio437=1 RailsDisabled; not a 21 36 proof)",
        class = class,
        g = p.gpio437.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
        a = plug(p.plugs[0]),
        b = plug(p.plugs[1]),
        c = plug(p.plugs[2]),
        s1 = ans(p.tty_s1),
        s2 = ans(p.tty_s2),
        s3 = ans(p.tty_s3),
    )
}

/// Mining-on must not proceed to work TX when GPIO437 is DISABLE.
pub fn admit_s19k_passthrough_work_tx(
    class: S19kSilenceClass,
    gpio437: Option<u8>,
) -> Result<(), &'static str> {
    if class == S19kSilenceClass::RailsDisabled {
        return Err(
            "Track-1: GPIO437 DISABLE (S99 stop / cooldown). kill -9 bosminer; do not treat 0-RX as job-shape",
        );
    }
    if let Some(v) = gpio437 {
        passthrough_must_keep_gpio437_engaged(v)?;
    }
    Ok(())
}

/// Legacy observe-after-S37-export paths. Production Track-1 must resolve
/// `CH0_PLUG`/`CH1_PLUG`/`CH2_PLUG` first ().
pub fn s19k_plug_sysfs_paths() -> [&'static str; 3] {
    [
        "/sys/class/gpio/gpio439/value",
        "/sys/class/gpio/gpio440/value",
        "/sys/class/gpio/gpio441/value",
    ]
}

/// Parse a single sysfs value file (`"0\n"` / `"1\n"`).
pub fn parse_sysfs_gpio_bit(text: &str) -> Option<u8> {
    match text.trim() {
        "0" => Some(0),
        "1" => Some(1),
        _ => None,
    }
}

/// 115200 GetAddress retry outcome. Separate from 3M port answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kDualBaudRetry {
    NotRun,
    Silence,
    ChipHeardAt115200,
    /// CommandReply 0x28 at 115200. Not GetAddress ChipAddress.
    FastUartHeardAt115200,
    FramingOrEcho,
}

/// Dual-baud silence vs GPIO437. Rails-off is not chip-at-115200.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kDualBaudSilence {
    /// GPIO437=1. S99 stop / cooldown. Baud is not implicated.
    RailsDisabled,
    /// ChipAddress at 115200 while GPIO437=1. Not SafeOff proof.
    ChipHeardWhileRailsDisabled,
    /// ChipAddress at 115200 with rails engaged. Not 3M work-TX proof.
    ChipHeardAt115200,
    /// FastUART 0x28 reply at 115200 with rails engaged. Not GetAddress.
    FastUartHeardAt115200,
    /// Silence at 3M and 115200 with rails engaged. Not chip-at-115200.
    SilenceAtBothBauds,
    /// 3M already ChipAddress. Dual-baud retry is not needed.
    ChipAnsweredAt3M,
    /// Env/gate did not run the 115200 retry.
    RetryNotRun,
    /// Missing GPIO or leftover framing.
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kDualBaudObserve {
    pub gpio437: Option<u8>,
    pub answered_3m: bool,
    pub retry: S19kDualBaudRetry,
}

pub fn classify_s19k_dual_baud_silence(o: S19kDualBaudObserve) -> S19kDualBaudSilence {
    let rails = classify_s19k_am3_gpio437(o.gpio437);
    let heard = matches!(
        o.retry,
        S19kDualBaudRetry::ChipHeardAt115200 | S19kDualBaudRetry::FastUartHeardAt115200
    );
    if rails == S19kAm3Gpio437Rail::DisabledOrCooldown {
        if heard {
            return S19kDualBaudSilence::ChipHeardWhileRailsDisabled;
        }
        return S19kDualBaudSilence::RailsDisabled;
    }
    if o.answered_3m {
        return S19kDualBaudSilence::ChipAnsweredAt3M;
    }
    if rails == S19kAm3Gpio437Rail::Unknown && o.gpio437.is_none() {
        return S19kDualBaudSilence::Inconclusive;
    }
    match o.retry {
        S19kDualBaudRetry::NotRun => S19kDualBaudSilence::RetryNotRun,
        S19kDualBaudRetry::ChipHeardAt115200 => S19kDualBaudSilence::ChipHeardAt115200,
        S19kDualBaudRetry::FastUartHeardAt115200 => S19kDualBaudSilence::FastUartHeardAt115200,
        S19kDualBaudRetry::Silence => S19kDualBaudSilence::SilenceAtBothBauds,
        S19kDualBaudRetry::FramingOrEcho => S19kDualBaudSilence::Inconclusive,
    }
}

pub fn refuse_silence_at_both_bauds_as_chip_115200(
    class: S19kDualBaudSilence,
) -> Result<(), &'static str> {
    if class == S19kDualBaudSilence::SilenceAtBothBauds {
        return Err("silence at 3M and 115200 is not chip-at-115200 proof");
    }
    Ok(())
}

pub fn refuse_chip_heard_at_115200_as_rails_disabled(
    class: S19kDualBaudSilence,
) -> Result<(), &'static str> {
    if class == S19kDualBaudSilence::ChipHeardAt115200
        || class == S19kDualBaudSilence::FastUartHeardAt115200
    {
        return Err("chip UART heard at 115200 with GPIO437 engaged is not RailsDisabled");
    }
    Ok(())
}

pub fn refuse_chip_heard_while_rails_disabled_as_safeoff_proof(
    class: S19kDualBaudSilence,
) -> Result<(), &'static str> {
    if class == S19kDualBaudSilence::ChipHeardWhileRailsDisabled {
        return Err(
            "ChipAddress at 115200 while GPIO437=1; not SafeOff proof (polarity/live-gated)",
        );
    }
    Ok(())
}

/// Chip UART at 115200 is not restored-3M work-TX proof. Writing FastUART
/// 0x28 to leave 115200 is still encoding-ungrounded.
pub fn refuse_chip_heard_at_115200_as_restored_3m_work_tx(
    class: S19kDualBaudSilence,
) -> Result<(), &'static str> {
    match class {
        S19kDualBaudSilence::ChipHeardAt115200 => Err(
            "ChipHeardAt115200 is diagnostic; refuse restored-3M work TX (chip UART heard at 115200)",
        ),
        S19kDualBaudSilence::FastUartHeardAt115200 => Err(
            "FastUartHeardAt115200 is diagnostic; refuse restored-3M work TX (0x28 at 115200 is not 3M GetAddress)",
        ),
        _ => Ok(()),
    }
}

/// Work TX stays refused on GPIO DISABLE, chip-heard-while-DISABLE, and
/// 115200-only chip evidence (restored 3M is the wrong dialect).
/// `SilenceAtBothBauds` still returns Ok as a **handoff probe**, not chip-proof.
pub fn admit_s19k_dual_baud_work_tx(class: S19kDualBaudSilence) -> Result<(), &'static str> {
    match class {
        S19kDualBaudSilence::RailsDisabled => Err(
            "Track-1: GPIO437 DISABLE (S99 stop / cooldown). Dual-baud silence is not job-shape",
        ),
        S19kDualBaudSilence::ChipHeardWhileRailsDisabled => Err(
            "Track-1: chip heard at 115200 while GPIO437=1; refuse work TX (polarity unresolved)",
        ),
        S19kDualBaudSilence::ChipHeardAt115200 | S19kDualBaudSilence::FastUartHeardAt115200 => {
            refuse_chip_heard_at_115200_as_restored_3m_work_tx(class)
        }
        _ => Ok(()),
    }
}

/// Labeled work-TX kind. Only [`S19kDualBaudWorkTxKind::ChipProofAt3M`] is
/// chip-proof. Silence at both bauds is a Braiins handoff `21 36` probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kDualBaudWorkTxKind {
    /// Required port answered ChipAddress at 3M.
    ChipProofAt3M,
    /// Required port silent at 3M and 115200 with rails up. Not chip-proof.
    HandoffProbe,
    /// Retry not run / leftover framing. Not chip-proof.
    InconclusiveProbe,
    /// Discover/optional ttyS3. Not a required-pair admit.
    DiscoverSkip,
}

/// Silence at both bauds is a handoff `21 36` probe, not chip-proof 3M TX.
pub fn refuse_silence_at_both_bauds_as_chip_proof_3m_tx(
    class: S19kDualBaudSilence,
) -> Result<(), &'static str> {
    if class == S19kDualBaudSilence::SilenceAtBothBauds {
        return Err(
            "SilenceAtBothBauds is a Track-1 handoff 21 36 probe, not chip-proof 3M TX",
        );
    }
    Ok(())
}

pub fn refuse_handoff_probe_as_chip_proof_3m_tx(
    kind: S19kDualBaudWorkTxKind,
) -> Result<(), &'static str> {
    if kind == S19kDualBaudWorkTxKind::HandoffProbe {
        return Err(
            "HandoffProbe is not ChipProofAt3M; GetAddress silence is not a 3M chip admit",
        );
    }
    Ok(())
}

/// RetryNotRun / leftover framing is an inconclusive probe, not chip-proof 3M TX.
pub fn refuse_retry_not_run_or_inconclusive_as_chip_proof_3m_tx(
    class: S19kDualBaudSilence,
) -> Result<(), &'static str> {
    match class {
        S19kDualBaudSilence::RetryNotRun => Err(
            "RetryNotRun is an inconclusive Track-1 probe, not chip-proof 3M TX",
        ),
        S19kDualBaudSilence::Inconclusive => Err(
            "Inconclusive dual-baud class is leftover framing, not chip-proof 3M TX",
        ),
        _ => Ok(()),
    }
}

pub fn refuse_inconclusive_probe_as_chip_proof_3m_tx(
    kind: S19kDualBaudWorkTxKind,
) -> Result<(), &'static str> {
    if kind == S19kDualBaudWorkTxKind::InconclusiveProbe {
        return Err(
            "InconclusiveProbe is not ChipProofAt3M; RetryNotRun/framing is not a 3M chip admit",
        );
    }
    Ok(())
}

/// Classify required-port work TX. Discover paths skip. Hard-refuses stay Err.
pub fn classify_s19k_dual_baud_work_tx_kind(
    path: &str,
    class: S19kDualBaudSilence,
) -> Result<S19kDualBaudWorkTxKind, &'static str> {
    if !s19k_multi_send_work_tx_required(path) {
        return Ok(S19kDualBaudWorkTxKind::DiscoverSkip);
    }
    admit_s19k_dual_baud_work_tx(class)?;
    Ok(match class {
        S19kDualBaudSilence::ChipAnsweredAt3M => S19kDualBaudWorkTxKind::ChipProofAt3M,
        S19kDualBaudSilence::SilenceAtBothBauds => S19kDualBaudWorkTxKind::HandoffProbe,
        S19kDualBaudSilence::RetryNotRun | S19kDualBaudSilence::Inconclusive => {
            S19kDualBaudWorkTxKind::InconclusiveProbe
        }
        _ => S19kDualBaudWorkTxKind::InconclusiveProbe,
    })
}

/// Discover/optional ttyS3 is classified and logged, but must not fail the
/// required-pair work-TX admit ( TX isolation). Required Silence
/// is a labeled handoff probe, not ChipProofAt3M.
pub fn admit_s19k_dual_baud_work_tx_for_path(
    path: &str,
    class: S19kDualBaudSilence,
) -> Result<S19kDualBaudWorkTxKind, &'static str> {
    classify_s19k_dual_baud_work_tx_kind(path, class)
}

/// Production dual-baud work-TX admit must be path-gated to ttyS1+ttyS2.
pub fn admit_s19k_production_dual_baud_admit_skips_discover(
    src: &str,
) -> Result<(), &'static str> {
    if !src.contains("admit_s19k_dual_baud_work_tx_for_path")
        && !(src.contains("s19k_multi_send_work_tx_required")
            && src.contains("admit_s19k_dual_baud_work_tx"))
    {
        return Err("dual-baud work-TX admit must skip discover/optional UARTs");
    }
    Ok(())
}

/// Production must label SilenceAtBothBauds as handoff probe, not chip-proof.
pub fn admit_s19k_production_labels_silence_handoff_probe(
    src: &str,
) -> Result<(), &'static str> {
    if !src.contains("refuse_silence_at_both_bauds_as_chip_proof_3m_tx") {
        return Err("production must refuse SilenceAtBothBauds as chip-proof 3M TX");
    }
    if !src.contains("HandoffProbe is not ChipProofAt3M") {
        return Err("production must log HandoffProbe is not ChipProofAt3M");
    }
    Ok(())
}

/// Production must label RetryNotRun/Inconclusive as probe, not chip-proof.
pub fn admit_s19k_production_labels_inconclusive_probe(src: &str) -> Result<(), &'static str> {
    if !src.contains("refuse_retry_not_run_or_inconclusive_as_chip_proof_3m_tx") {
        return Err("production must refuse RetryNotRun/Inconclusive as chip-proof 3M TX");
    }
    if !src.contains("InconclusiveProbe is not ChipProofAt3M") {
        return Err("production must log InconclusiveProbe is not ChipProofAt3M");
    }
    Ok(())
}

pub fn admit_s19k_production_classifies_dual_baud(src: &str) -> Result<(), &'static str> {
    if !src.contains("classify_s19k_dual_baud_silence") {
        return Err("production must classify 115200 retry against GPIO437");
    }
    if !src.contains("admit_s19k_dual_baud_work_tx") {
        return Err("production must admit dual-baud work TX");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s99_stop_is_rails_not_job_shape() {
        let p = S19kPassthroughPreflight {
            gpio437: Some(1),
            plugs: [Some(1), Some(1), Some(0)],
            tty_s1: S19kPortAnswer::Silence,
            tty_s2: S19kPortAnswer::Silence,
            tty_s3: S19kPortAnswer::Silence,
        };
        assert_eq!(
            classify_s19k_passthrough_silence(p),
            S19kSilenceClass::RailsDisabled
        );
        assert!(admit_s19k_passthrough_work_tx(S19kSilenceClass::RailsDisabled, Some(1)).is_err());
        assert!(admit_s19k_passthrough_work_tx(S19kSilenceClass::ChipAnswered, Some(0)).is_ok());
        let line = format_s19k_passthrough_preflight(p, S19kSilenceClass::RailsDisabled);
        assert!(line.contains("S19K_PREFLIGHT"));
        assert!(line.contains("RailsDisabled"));
        assert!(line.contains("S99 stop"));
        assert_eq!(parse_sysfs_gpio_bit("0\n"), Some(0));
        assert_eq!(parse_sysfs_gpio_bit("1"), Some(1));
        assert_eq!(parse_sysfs_gpio_bit("x"), None);
        assert_eq!(crate::s19k_am3_gpio437::S19K_AM3_GPIO437_VALUE_ON, 0);
        assert_eq!(crate::s19k_am3_gpio437::S19K_AM3_PLUG_GPIOS, [439, 440, 441]);
        let silent_up = S19kPassthroughPreflight {
            gpio437: Some(0),
            plugs: [Some(0), Some(1), Some(1)],
            tty_s1: S19kPortAnswer::Silence,
            tty_s2: S19kPortAnswer::Silence,
            tty_s3: S19kPortAnswer::Silence,
        };
        assert_eq!(
            classify_s19k_passthrough_silence(silent_up),
            S19kSilenceClass::SilenceWithRailsUp
        );
        let chip = S19kPassthroughPreflight {
            gpio437: Some(0),
            plugs: [Some(0), Some(1), Some(1)],
            tty_s1: S19kPortAnswer::ChipAddress {
                chip_id: 0x1366,
                count: 12,
            },
            tty_s2: S19kPortAnswer::Silence,
            tty_s3: S19kPortAnswer::Silence,
        };
        assert_eq!(
            classify_s19k_passthrough_silence(chip),
            S19kSilenceClass::ChipAnswered
        );
        let empty = S19kPassthroughPreflight {
            gpio437: Some(0),
            plugs: [Some(0), Some(0), Some(0)],
            tty_s1: S19kPortAnswer::Silence,
            tty_s2: S19kPortAnswer::Silence,
            tty_s3: S19kPortAnswer::Silence,
        };
        assert_eq!(
            classify_s19k_passthrough_silence(empty),
            S19kSilenceClass::NoBoardPlugged
        );
        let s3_only = S19kPassthroughPreflight {
            gpio437: Some(0),
            plugs: [Some(1), Some(1), Some(1)],
            tty_s1: S19kPortAnswer::Silence,
            tty_s2: S19kPortAnswer::Silence,
            tty_s3: S19kPortAnswer::ChipAddress {
                chip_id: 0x1366,
                count: 8,
            },
        };
        assert_eq!(
            classify_s19k_passthrough_silence(s3_only),
            S19kSilenceClass::DiscoverOnly
        );
        assert!(admit_s19k_passthrough_work_tx(S19kSilenceClass::DiscoverOnly, Some(0)).is_ok());
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(
            serial.contains("classify_s19k_passthrough_silence"),
            "mining-on must classify GetAddress silence against GPIO437"
        );
        assert!(serial.contains("format_s19k_passthrough_preflight"));
        assert!(serial.contains("admit_s19k_passthrough_work_tx"));
        assert!(admit_s19k_production_classifies_dual_baud(serial).is_ok());
        let rails_off = classify_s19k_dual_baud_silence(S19kDualBaudObserve {
            gpio437: Some(1),
            answered_3m: false,
            retry: S19kDualBaudRetry::Silence,
        });
        assert_eq!(rails_off, S19kDualBaudSilence::RailsDisabled);
        assert!(refuse_silence_at_both_bauds_as_chip_115200(rails_off).is_ok());
        assert!(admit_s19k_dual_baud_work_tx(rails_off).is_err());
        let heard_off = classify_s19k_dual_baud_silence(S19kDualBaudObserve {
            gpio437: Some(1),
            answered_3m: false,
            retry: S19kDualBaudRetry::ChipHeardAt115200,
        });
        assert_eq!(
            heard_off,
            S19kDualBaudSilence::ChipHeardWhileRailsDisabled
        );
        assert!(refuse_chip_heard_while_rails_disabled_as_safeoff_proof(heard_off).is_err());
        assert!(admit_s19k_dual_baud_work_tx(heard_off).is_err());
        let heard_up = classify_s19k_dual_baud_silence(S19kDualBaudObserve {
            gpio437: Some(0),
            answered_3m: false,
            retry: S19kDualBaudRetry::ChipHeardAt115200,
        });
        assert_eq!(heard_up, S19kDualBaudSilence::ChipHeardAt115200);
        assert!(refuse_chip_heard_at_115200_as_rails_disabled(heard_up).is_err());
        assert!(refuse_chip_heard_at_115200_as_restored_3m_work_tx(heard_up).is_err());
        assert!(admit_s19k_dual_baud_work_tx(heard_up).is_err());
        let fu_heard = classify_s19k_dual_baud_silence(S19kDualBaudObserve {
            gpio437: Some(0),
            answered_3m: false,
            retry: S19kDualBaudRetry::FastUartHeardAt115200,
        });
        assert_eq!(fu_heard, S19kDualBaudSilence::FastUartHeardAt115200);
        assert_ne!(fu_heard, S19kDualBaudSilence::ChipHeardAt115200);
        assert!(refuse_chip_heard_at_115200_as_rails_disabled(fu_heard).is_err());
        assert!(refuse_chip_heard_at_115200_as_restored_3m_work_tx(fu_heard).is_err());
        assert!(admit_s19k_dual_baud_work_tx(fu_heard).is_err());
        let fu_off = classify_s19k_dual_baud_silence(S19kDualBaudObserve {
            gpio437: Some(1),
            answered_3m: false,
            retry: S19kDualBaudRetry::FastUartHeardAt115200,
        });
        assert_eq!(fu_off, S19kDualBaudSilence::ChipHeardWhileRailsDisabled);
        assert!(admit_s19k_dual_baud_work_tx(fu_off).is_err());
        let both = classify_s19k_dual_baud_silence(S19kDualBaudObserve {
            gpio437: Some(0),
            answered_3m: false,
            retry: S19kDualBaudRetry::Silence,
        });
        assert_eq!(both, S19kDualBaudSilence::SilenceAtBothBauds);
        assert!(refuse_silence_at_both_bauds_as_chip_115200(both).is_err());
        assert!(refuse_silence_at_both_bauds_as_chip_proof_3m_tx(both).is_err());
        assert!(admit_s19k_dual_baud_work_tx(both).is_ok());
        assert_eq!(
            classify_s19k_dual_baud_work_tx_kind("/dev/ttyS1", both).unwrap(),
            S19kDualBaudWorkTxKind::HandoffProbe
        );
        assert_ne!(
            classify_s19k_dual_baud_work_tx_kind("/dev/ttyS1", both).unwrap(),
            S19kDualBaudWorkTxKind::ChipProofAt3M
        );
        let at_3m = classify_s19k_dual_baud_silence(S19kDualBaudObserve {
            gpio437: Some(0),
            answered_3m: true,
            retry: S19kDualBaudRetry::NotRun,
        });
        assert_eq!(at_3m, S19kDualBaudSilence::ChipAnsweredAt3M);
        assert!(refuse_chip_heard_at_115200_as_restored_3m_work_tx(at_3m).is_ok());
        assert!(admit_s19k_dual_baud_work_tx(at_3m).is_ok());
        assert_eq!(
            classify_s19k_dual_baud_silence(S19kDualBaudObserve {
                gpio437: Some(0),
                answered_3m: false,
                retry: S19kDualBaudRetry::NotRun,
            }),
            S19kDualBaudSilence::RetryNotRun
        );
    }

    #[test]
    fn s19k_chip_heard_at_115200_refuses_restored_3m_work_tx() {
        let heard = S19kDualBaudSilence::ChipHeardAt115200;
        let fu = S19kDualBaudSilence::FastUartHeardAt115200;
        assert!(refuse_chip_heard_at_115200_as_restored_3m_work_tx(heard).is_err());
        assert!(refuse_chip_heard_at_115200_as_restored_3m_work_tx(fu).is_err());
        assert!(admit_s19k_dual_baud_work_tx(heard).is_err());
        assert!(admit_s19k_dual_baud_work_tx(fu).is_err());
        assert!(admit_s19k_dual_baud_work_tx(S19kDualBaudSilence::ChipAnsweredAt3M).is_ok());
        assert!(admit_s19k_dual_baud_work_tx(S19kDualBaudSilence::SilenceAtBothBauds).is_ok());
        assert!(refuse_silence_at_both_bauds_as_chip_proof_3m_tx(
            S19kDualBaudSilence::SilenceAtBothBauds
        )
        .is_err());
        assert!(refuse_silence_at_both_bauds_as_chip_proof_3m_tx(
            S19kDualBaudSilence::ChipAnsweredAt3M
        )
        .is_ok());
        assert!(admit_s19k_dual_baud_work_tx_for_path(
            "/dev/ttyS3",
            S19kDualBaudSilence::ChipHeardAt115200
        )
        .is_ok());
        assert!(admit_s19k_dual_baud_work_tx_for_path(
            "/dev/ttyS1",
            S19kDualBaudSilence::ChipHeardAt115200
        )
        .is_err());
        assert!(admit_s19k_dual_baud_work_tx_for_path(
            "/dev/ttyS2",
            S19kDualBaudSilence::ChipAnsweredAt3M
        )
        .is_ok());
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_dual_baud_admit_skips_discover(serial).is_ok());
    }

    #[test]
    fn s19k_dual_baud_work_tx_admit_skips_discover_s3() {
        assert!(admit_s19k_dual_baud_work_tx_for_path(
            "/dev/ttyS3",
            S19kDualBaudSilence::FastUartHeardAt115200
        )
        .is_ok());
        assert!(admit_s19k_dual_baud_work_tx_for_path(
            "/dev/ttyS3",
            S19kDualBaudSilence::RailsDisabled
        )
        .is_ok());
        assert!(admit_s19k_dual_baud_work_tx_for_path(
            "/dev/ttyS1",
            S19kDualBaudSilence::RailsDisabled
        )
        .is_err());
    }

    #[test]
    fn s19k_silence_at_both_bauds_is_handoff_probe_not_chip_proof() {
        let silence = S19kDualBaudSilence::SilenceAtBothBauds;
        let chip = S19kDualBaudSilence::ChipAnsweredAt3M;
        assert_eq!(
            classify_s19k_dual_baud_work_tx_kind("/dev/ttyS1", silence).unwrap(),
            S19kDualBaudWorkTxKind::HandoffProbe
        );
        assert_eq!(
            classify_s19k_dual_baud_work_tx_kind("/dev/ttyS2", silence).unwrap(),
            S19kDualBaudWorkTxKind::HandoffProbe
        );
        assert_eq!(
            classify_s19k_dual_baud_work_tx_kind("/dev/ttyS3", silence).unwrap(),
            S19kDualBaudWorkTxKind::DiscoverSkip
        );
        assert_eq!(
            classify_s19k_dual_baud_work_tx_kind("/dev/ttyS1", chip).unwrap(),
            S19kDualBaudWorkTxKind::ChipProofAt3M
        );
        assert!(refuse_silence_at_both_bauds_as_chip_proof_3m_tx(silence).is_err());
        assert!(refuse_silence_at_both_bauds_as_chip_proof_3m_tx(chip).is_ok());
        assert!(refuse_handoff_probe_as_chip_proof_3m_tx(
            S19kDualBaudWorkTxKind::HandoffProbe
        )
        .is_err());
        assert!(refuse_handoff_probe_as_chip_proof_3m_tx(
            S19kDualBaudWorkTxKind::ChipProofAt3M
        )
        .is_ok());
        assert!(admit_s19k_dual_baud_work_tx(silence).is_ok());
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_labels_silence_handoff_probe(serial).is_ok());
        assert!(admit_s19k_production_labels_silence_handoff_probe(
            "admit_s19k_dual_baud_work_tx_for_path\n"
        )
        .is_err());
    }

    #[test]
    fn s19k_retry_not_run_is_inconclusive_probe_not_chip_proof() {
        let retry = S19kDualBaudSilence::RetryNotRun;
        let framing = S19kDualBaudSilence::Inconclusive;
        let chip = S19kDualBaudSilence::ChipAnsweredAt3M;
        assert_eq!(
            classify_s19k_dual_baud_work_tx_kind("/dev/ttyS1", retry).unwrap(),
            S19kDualBaudWorkTxKind::InconclusiveProbe
        );
        assert_eq!(
            classify_s19k_dual_baud_work_tx_kind("/dev/ttyS2", framing).unwrap(),
            S19kDualBaudWorkTxKind::InconclusiveProbe
        );
        assert_eq!(
            classify_s19k_dual_baud_work_tx_kind("/dev/ttyS3", retry).unwrap(),
            S19kDualBaudWorkTxKind::DiscoverSkip
        );
        assert_eq!(
            classify_s19k_dual_baud_work_tx_kind("/dev/ttyS1", chip).unwrap(),
            S19kDualBaudWorkTxKind::ChipProofAt3M
        );
        assert!(refuse_retry_not_run_or_inconclusive_as_chip_proof_3m_tx(retry).is_err());
        assert!(refuse_retry_not_run_or_inconclusive_as_chip_proof_3m_tx(framing).is_err());
        assert!(refuse_retry_not_run_or_inconclusive_as_chip_proof_3m_tx(chip).is_ok());
        assert!(refuse_retry_not_run_or_inconclusive_as_chip_proof_3m_tx(
            S19kDualBaudSilence::SilenceAtBothBauds
        )
        .is_ok());
        assert!(refuse_inconclusive_probe_as_chip_proof_3m_tx(
            S19kDualBaudWorkTxKind::InconclusiveProbe
        )
        .is_err());
        assert!(refuse_inconclusive_probe_as_chip_proof_3m_tx(
            S19kDualBaudWorkTxKind::ChipProofAt3M
        )
        .is_ok());
        assert!(refuse_inconclusive_probe_as_chip_proof_3m_tx(
            S19kDualBaudWorkTxKind::HandoffProbe
        )
        .is_ok());
        assert!(admit_s19k_dual_baud_work_tx(retry).is_ok());
        assert!(admit_s19k_dual_baud_work_tx(framing).is_ok());
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_labels_inconclusive_probe(serial).is_ok());
        assert!(admit_s19k_production_labels_inconclusive_probe(
            "HandoffProbe is not ChipProofAt3M\n"
        )
        .is_err());
    }
}
