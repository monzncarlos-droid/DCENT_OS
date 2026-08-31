//! Experimental / lab-only flags for dcentrald.
//!
//! Mirror of bosminer's `bosminer-experimental.toml` concept (clean-room —
//! we observed the flag names by RE'ing the bosminer.unpacked binary at
//! offsets noted in ,
//! but we own the parser, the defaults, and the semantics).
//!
//! Loaded from `/etc/dcentrald-experimental.toml` at startup. Missing file
//! → all defaults (which are conservative — strict, no degraded modes).
//!
//! ## Why these flags exist
//!
//! Bosminer ships `bosminer-experimental.toml` empty by default and treats
//! it as the operator's escape hatch when the production safe defaults are
//! too strict for the actual hardware in front of them. Same intent here.
//!
//! ## What's NOT in here
//!
//! - **License-server flags** (none — DCENT_OS has no license server).
//! - **Telemetry-submit flags** (we never auto-submit; operator-driven).
//! - **DPS power-walk parameters** (Phase N — not yet implemented in our
//!   autotuner; will surface here once the GDTUNER state machine ports).

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Default file path. Override via `DCENTRALD_EXPERIMENTAL_TOML` env var
/// (lab/test only — production should use the file).
///
/// ## Shipped templates
///
/// Two board images ship a commented-out template at this path so the opt-in
/// is discoverable on the device instead of only in this source file:
///
/// - `br2_external_dcentos/board/amlogic/am3-s21pro/rootfs-overlay/etc/dcentrald-experimental.toml`
/// - `br2_external_dcentos/board/amlogic/am3-s21xp/rootfs-overlay/etc/dcentrald-experimental.toml`
///
/// Every key in them is commented out, so a shipped image parses to
/// [`ExperimentalConfig::default`] and grants nothing;
/// `shipped_experimental_templates_grant_nothing` pins that.
///
/// ### Why only these two boards
///
/// [`Self::load`] has exactly two callers: `SerialMiner::new` (native serial
/// arm) and the standard daemon's hardware-composition admission. The key only
/// changes an outcome for a chip the driver registry marks Experimental
/// (BM1397 / BM1398 / BM1370).
///
/// - Every Amlogic image launches with `--serial-mining` and so reaches this
///   loader, but of their stock models only `s21pro` and `s21xp` resolve to an
///   Experimental chip (BM1370); `s21` (BM1368), `s19jpro` (BM1362) and
///   `s19k` (BM1366) are Production, and BM1370 is the only Experimental chip
///   with a native dispatch site. T21 is management-only with unresolved
///   controller/PIC/PSU authority and cannot reach this loader.
/// - `am2-s19j` auto-routes to the hybrid miner and `am3-bb-s19jpro` to the
///   AM3-BB miner; neither path loads this file at all.
/// - `am2-s17p` is refused by the TD-003 board-target gate before the loader.
/// - `am2-s19pro` is the one BM1398 (Experimental) image on the standard
///   daemon, but its shipped config sets no `[mining].model`, so admission
///   bails in `pre_enumeration_topology_profile` before this loader runs. It
///   would only become reachable through an operator-edited config.
///
/// Do not add a template to a board that cannot reach this loader with an
/// Experimental chip, and never ship one with a key uncommented.
pub const DEFAULT_PATH: &str = "/etc/dcentrald-experimental.toml";

/// Operator-tunable lab flags. ALL fields default to their conservative
/// production values (no operator override required for safe-default
/// behavior).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExperimentalConfig {
    /// Exact ASIC chip IDs whose Experimental protocol drivers may execute on
    /// this boot.  Recognition remains available without this list, but no
    /// voltage/reset/PLL/address/work authority is granted.
    ///
    /// The list is deliberately chip-specific rather than a global boolean:
    /// opting into BM1398 must not silently authorize a future experimental
    /// family.  The standard daemon further requires the configured hardware
    /// composition to name the same chip ID.
    pub executable_asic_chip_ids: Vec<u16>,

    /// Maximum number of bad / missing chip responses tolerated during
    /// BM136x chain enumeration. Default 0 = strict (every chip must
    /// reply with the correct chip-id), matches dcentrald's pre-2026-04
    /// behavior.
    ///
    /// Useful for partially-faulty hashboards (e.g. live `a lab unit` chain1
    /// enumerates 8/77 chips with chip-0 reply 0xe42 instead of the
    /// expected 0x1366; setting this to 8 lets the chain proceed and
    /// mine with the working chips).
    ///
    /// Bosminer's equivalent: `rambo_mode_max_bad_responses` (we kept
    /// the exact name for ecosystem familiarity).
    pub rambo_mode_max_bad_responses: u8,

    /// On admitted NoPic miners (S21/S19K Pro NoPic / S19 XP / S19J XP) the
    /// PSU rails are always-on; bosminer refuses to disable individual
    /// hashboards because the rail can't be cut without cutting all
    /// chains together. When `true`, dcentrald will mark a single dead
    /// chain as disabled for tuner purposes while keeping the others
    /// running (the rail stays on; only the work-dispatch is gated).
    ///
    /// Default: `false` (matches bosminer safety stance).
    pub allow_disabling_hashboards_on_nopic_miners: bool,

    /// Minimum fan PWM floor (0-100). When fan tach is unreliable or
    /// the autoconfigure probe falls back, use this as the safe floor.
    /// Ignored when the active thermal profile's `fan_min_pwm` already
    /// exceeds it.
    ///
    /// Bosminer's empirical floor on .78 was 25% PWM; we default to
    /// 25 to match. Industrial profile may raise this, home profile
    /// is hard-capped at 30 by .
    pub min_fan_pwm_floor: u8,

    /// Disable bosminer's "bootstrap voltage threshold" check at boot.
    /// We don't run that check today (Phase N autotuner port territory),
    /// but the flag is reserved here so the toml schema is forward-
    /// compatible when Stage2 of the autotuner state machine ports.
    pub disable_bootstrap_check: bool,

    /// When true, send a one-time dummy telemetry packet at startup
    /// to validate the pool / dashboard pipeline. Default off.
    pub send_dummy_telemetry_on_startup: bool,

    /// Permit a board-temperature thermal lockout to be released without a
    /// powered hash-board sensor, but only after the source-aware lockout
    /// policy's conservative dwell and repeated non-warming XADC checks.
    ///
    /// This is an explicitly experimental proxy, not board-temperature
    /// equivalence. It exists for beta validation on S9-class hardware where
    /// the TMP75 domain is unavailable while hash-board voltage is disabled.
    /// Default: false (production requires same-domain evidence or operator
    /// resolution).
    pub allow_thermal_board_proxy_release_after_dwell: bool,
}

impl Default for ExperimentalConfig {
    fn default() -> Self {
        Self {
            executable_asic_chip_ids: Vec::new(),
            rambo_mode_max_bad_responses: 0,
            allow_disabling_hashboards_on_nopic_miners: false,
            min_fan_pwm_floor: 25,
            disable_bootstrap_check: false,
            send_dummy_telemetry_on_startup: false,
            allow_thermal_board_proxy_release_after_dwell: false,
        }
    }
}

impl ExperimentalConfig {
    /// Load from the canonical path, with env-var override and clean
    /// fall-through-to-defaults if the file is absent.
    pub fn load() -> Self {
        let path = std::env::var("DCENTRALD_EXPERIMENTAL_TOML")
            .unwrap_or_else(|_| DEFAULT_PATH.to_string());
        Self::load_from(Path::new(&path))
    }

    /// Load from a specific path. Test entry point.
    pub fn load_from(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(s) => match toml::from_str::<ExperimentalConfig>(&s) {
                Ok(cfg) => {
                    tracing::info!(?path, "Loaded experimental config");
                    cfg
                }
                Err(e) => {
                    tracing::warn!(?path, error = %e, "experimental toml parse failed; using defaults");
                    Self::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(
                    ?path,
                    "no experimental config (expected on production images)"
                );
                Self::default()
            }
            Err(e) => {
                tracing::warn!(?path, error = %e, "experimental config read failed; using defaults");
                Self::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "dcentrald_experimental_test_{}_{}.toml",
            name,
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("write temp toml");
        path
    }

    #[test]
    fn default_is_strict() {
        let c = ExperimentalConfig::default();
        assert_eq!(c.rambo_mode_max_bad_responses, 0);
        assert!(c.executable_asic_chip_ids.is_empty());
        assert!(!c.allow_disabling_hashboards_on_nopic_miners);
        assert_eq!(c.min_fan_pwm_floor, 25);
        assert!(!c.disable_bootstrap_check);
        assert!(!c.send_dummy_telemetry_on_startup);
        assert!(!c.allow_thermal_board_proxy_release_after_dwell);
    }

    #[test]
    fn missing_file_returns_default() {
        let c = ExperimentalConfig::load_from(Path::new("/this/path/does/not/exist/anywhere.toml"));
        assert_eq!(c.rambo_mode_max_bad_responses, 0);
    }

    #[test]
    fn rambo_mode_8_loads_for_partial_chain_use_case() {
        // .78 use case: chain1 sees 8/77 chips. Operator sets
        // rambo_mode_max_bad_responses = 8 to let init proceed.
        let path = write_temp(
            "rambo_8",
            "rambo_mode_max_bad_responses = 8\nmin_fan_pwm_floor = 30\n",
        );
        let c = ExperimentalConfig::load_from(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(c.rambo_mode_max_bad_responses, 8);
        assert_eq!(c.min_fan_pwm_floor, 30);
        // Other fields remain at defaults
        assert!(!c.allow_disabling_hashboards_on_nopic_miners);
    }

    #[test]
    fn experimental_asic_authority_is_exact_and_default_off() {
        let path = write_temp("asic_exact", "executable_asic_chip_ids = [5016]\n");
        let c = ExperimentalConfig::load_from(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(c.executable_asic_chip_ids, vec![0x1398]);
        assert!(!c.executable_asic_chip_ids.contains(&0x1387));
    }

    #[test]
    fn thermal_board_proxy_release_is_explicit_and_default_off() {
        let path = write_temp(
            "thermal_proxy",
            "allow_thermal_board_proxy_release_after_dwell = true\n",
        );
        let c = ExperimentalConfig::load_from(&path);
        let _ = std::fs::remove_file(&path);
        assert!(c.allow_thermal_board_proxy_release_after_dwell);
        assert!(!ExperimentalConfig::default().allow_thermal_board_proxy_release_after_dwell);
    }

    /// Every shipped `/etc/dcentrald-experimental.toml` template, keyed by the
    /// `/etc/dcentos/board_target` of the image that carries it.
    ///
    /// Both entries are BM1370 (`0x1370`) boards. `include_str!` binds the
    /// exact shipped bytes, so these tests fail if a template is edited into
    /// granting authority or is line-ending-corrupted. Only the S21 Pro still
    /// documents a possible operator opt-in; the evidence-only S21 XP target
    /// must explicitly document that the template cannot grant authority.
    const SHIPPED_TEMPLATES: &[(&str, &str)] = &[
        (
            "am3-s21pro",
            include_str!(
                "../../../br2_external_dcentos/board/amlogic/am3-s21pro/rootfs-overlay/etc/dcentrald-experimental.toml"
            ),
        ),
        (
            "am3-s21xp",
            include_str!(
                "../../../br2_external_dcentos/board/amlogic/am3-s21xp/rootfs-overlay/etc/dcentrald-experimental.toml"
            ),
        ),
    ];

    /// A shipped template must parse, and must parse to exactly the defaults.
    /// This is the assertion that proves the template grants nothing: a stray
    /// uncommented `executable_asic_chip_ids` would hand ASIC execution
    /// authority to a first-boot image on a profile that has never seen live
    /// silicon.
    #[test]
    fn shipped_experimental_templates_grant_nothing() {
        assert_eq!(
            SHIPPED_TEMPLATES.len(),
            2,
            "shipped templates are BM1370-only (am3-s21pro + am3-s21xp); adding one \
             for another board needs its own reachability + refusal evidence"
        );
        for (board, template) in SHIPPED_TEMPLATES {
            let parsed: ExperimentalConfig = toml::from_str(template)
                .unwrap_or_else(|e| panic!("{board} template is not valid TOML: {e}"));
            assert_eq!(
                parsed,
                ExperimentalConfig::default(),
                "{board} shipped template must parse to the conservative defaults"
            );
            assert!(
                parsed.executable_asic_chip_ids.is_empty(),
                "{board} shipped template must grant no ASIC execution authority"
            );
        }
    }

    /// Structural backstop for the parse-equality test above, plus the
    /// line-ending guard: a CRLF file in a rootfs overlay has broken boot on
    /// this project before, and a comment-only TOML would still parse to the
    /// defaults under CRLF, so parse equality alone cannot catch it.
    #[test]
    fn shipped_experimental_templates_are_fully_commented_and_lf() {
        for (board, template) in SHIPPED_TEMPLATES {
            assert!(
                !template.contains('\r'),
                "{board} template must ship LF-only line endings"
            );
            for (idx, line) in template.lines().enumerate() {
                let trimmed = line.trim();
                assert!(
                    trimmed.is_empty() || trimmed.starts_with('#'),
                    "{board} template line {} is live TOML, not a comment: {line}",
                    idx + 1
                );
            }
        }
    }

    /// The S21 Pro template documents the exact opt-in for the chip its board
    /// resolves to. `0x1370` is decimal `4976`.
    ///
    /// This pins the decimal spelling as the single canonical form so there is
    /// exactly one thing to review on an operator-facing safety document. It is
    /// NOT a claim that hex is rejected: TOML 1.0 accepts `0x1370` and the
    /// pinned `toml` crate parses it to the identical id.
    #[test]
    fn shipped_experimental_templates_document_exact_bm1370_authority_posture() {
        let opt_in = format!(
            "# executable_asic_chip_ids = [{}]",
            dcentrald_asic::drivers::bm1370::CHIP_ID
        );
        let s21pro = SHIPPED_TEMPLATES
            .iter()
            .find(|(board, _)| *board == "am3-s21pro")
            .map(|(_, template)| *template)
            .expect("shipped S21 Pro template");
        assert!(
            s21pro.contains(&opt_in),
            "am3-s21pro template must show the commented BM1370 opt-in line"
        );

        let s21xp = SHIPPED_TEMPLATES
            .iter()
            .find(|(board, _)| *board == "am3-s21xp")
            .map(|(_, template)| *template)
            .expect("shipped S21 XP template");
        assert!(!s21xp.contains(&opt_in));
        assert!(s21xp.contains("This file contains no executable ASIC opt-in"));
        assert!(s21xp.contains("Editing this file cannot override"));

        for (board, template) in SHIPPED_TEMPLATES {
            assert!(
                !template.contains("[0x1370]"),
                "{board} template must not suggest a hex literal TOML integer"
            );
        }
    }

    #[test]
    fn malformed_toml_returns_default_not_panic() {
        let path = write_temp("malformed", "this is not valid toml at all { { {");
        let c = ExperimentalConfig::load_from(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(c.rambo_mode_max_bad_responses, 0);
    }
}
