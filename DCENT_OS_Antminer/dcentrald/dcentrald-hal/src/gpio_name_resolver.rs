//! By-NAME GPIO line resolution (UB-23, 2026-08-03).
//!
//! DCENT_OS historically addresses gpiolib lines by **raw sysfs global
//! integers** (gpio437, gpio907, gpio59, ...). Those numbers are kernel-
//! version dependent: gpiochip bases are assigned at driver-probe time, so a
//! kernel bump (or even a probe-order change) silently renumbers every line
//! and the next unit's hardware identity breaks. The stable identity for a
//! line is its device-tree `gpio-line-names` entry — (chip, offset, name) —
//! not the global integer.
//!
//! Technique imported from ePIC UMC OS desk evidence (they resolve
//! per-hashboard `a0/a1/a2/nreset/board_detect` lines by DT name via libgpiod
//! so the same code serves Zynq and Amlogic; see
//!
//! §impact-U8). **Only the technique is imported.** ePIC's line numbers and
//! PL/AXI addresses come from THEIR bitstream/DT and must never be hardcoded
//! as ours.
//!
//! ## libgpiod status in this build
//!
//! No external `gpiod`/`libgpiod` crate is linked (deliberate — see
//! `Cargo.toml`). The chardev v1 ABI is already implemented in-tree by
//! [`crate::libgpiod`] (raw `ioctl(2)` against `/dev/gpiochipN`). This module
//! layers name→line resolution on top of it, with a sysfs/device-tree
//! fallback (`/sys/class/gpio/gpiochipN/device/of_node/gpio-line-names`) for
//! kernels where the chardev is absent or unreadable.
//!
//! ## Contract (fail closed)
//!
//! - A name that resolves nowhere is a **typed error**
//!   ([`GpioNameError::NameNotFound`]) — never a silent fallback to line 0 or
//!   a guessed integer.
//! - A name that resolves in more than one place is a **typed error**
//!   ([`GpioNameError::DuplicateName`]) — an ambiguous DT is a broken DT; we
//!   refuse to pick, and we refuse to mask the DT bug by falling back to the
//!   legacy integer.
//! - The **name-first, integer-fallback** resolver
//!   ([`resolve_name_or_legacy`]) accepts an explicit caller-provided legacy
//!   global integer. The integer is used ONLY when the name is genuinely
//!   absent (this kernel publishes no such name), it is surfaced as
//!   [`ResolvedGpioLine::LegacyIntegerFallback`] (structurally distinct from
//!   a name hit), and the fallback is logged via `tracing::warn!`. The
//!   integer is never the primary key.
//! - When chip base/ngpio information is available and proves the legacy
//!   integer cannot exist on this kernel, the fallback also fails closed
//!   ([`GpioNameError::FallbackUnresolvable`]) instead of handing back a
//!   number that will ENOENT (or worse, alias a renumbered line) at export
//!   time.
//!
//! ## NO polarity semantics — deliberately
//!
//! This resolver answers "WHERE is the line" and nothing else. It carries no
//! active-low/active-high notion, and the migration below must not either:
//!
//! - `gpio437` (Amlogic PSU enable): polarity is **UNRESOLVED** (ePIC writes
//!   1 to disable; we record 1 = ON; neither side has measured a rail — needs
//!   a DMM). Changing addressing must not encode a polarity opinion.
//! - `gpio907` (AM2 Zynq PWR_CONTROL): live-proven ACTIVE-LOW on both S17
//!   Pro and S19 Pro jigs, yet the shipped `ACTIVE_HIGH` constant is
//!   **deliberately kept** (removing it once made safe-off inoperative; flip
//!   is operator-gated). Do not touch it during migration.
//!
//! ## Migration plan (NOT done here — deliberately)
//!
//! This module lands the CAPABILITY only. The existing integer constants and
//! their call sites are untouched (several owning files are staged by a
//! concurrent session). The rewiring pass, to be done as ONE reviewable
//! change per platform, is:
//!
//! 1. `platform/amlogic/mod.rs` — `GPIO_PSU_ENABLE = 437`,
//!    `GPIO_PLUG_BASE = 439` (..441), `GPIO_RESET_BASE = 454` (..456),
//!    `GPIO_FAN_TACH_BASE = 447` (..450), `GPIO_PINMUX_FIX = [476, 477]`,
//!    LEDs 438/453. Replace each raw `N` with
//!    `resolve_name_or_legacy("<dt-name>", N)` where `<dt-name>` is read from
//!    OUR unit's live DT (`/proc/device-tree/.../gpio-line-names`), NOT from
//!    ePIC's.
//! 2. `board_control.rs` — `AM2_PSU_ENABLE_GPIO = 907` (PS bank e000a000)
//!    and the PL bank window 897..=901. Same recipe; polarity untouched.
//! 3. `psu_apw12_plus.rs` — `GPIO_PSU_ENABLE = 907`.
//! 4. `platform/beaglebone.rs` — `GPIO_BOARD_ENABLE_V2_0 = 59` (+ ASIC_RST
//!    set {49, 60, 27, 22}).
//! 5. `platform/cvitek.rs` — gpio412 PWR_EN + gpio427/429/431/433 ASIC_RST.
//!
//! NOT in scope for migration: `gpio.rs`'s AXI GPIO **register bit masks**
//! (0x41200000/0x41210000 via /dev/mem). Those are FPGA register bits, not
//! gpiolib lines; by-name resolution applies only where the kernel publishes
//! a gpiochip for the line.
//!
//! Each migrated call site keeps its current integer as the explicit logged
//! fallback, keeps its current polarity behaviour bit-for-bit, and must land
//! with a regression test pinning both.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::libgpiod;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// One gpiochip's name table, as gathered from the chardev v1 ABI and/or the
/// sysfs/DT fallback. Pure data so the resolution core is host-testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpioChipSnapshot {
    /// Chardev path (`/dev/gpiochipN`) when one exists; otherwise the sysfs
    /// chip directory. Identification/reporting only — no polarity meaning.
    pub chip_path: PathBuf,
    /// Legacy sysfs global base of this chip (`/sys/class/gpio/gpiochipN/base`),
    /// when known. Used to compute the legacy global number of a name hit and
    /// to range-validate integer fallbacks.
    pub base: Option<u32>,
    /// Line names by offset. `None` = unnamed line.
    pub line_names: Vec<Option<String>>,
}

/// Where a resolution came from. A fallback is structurally distinct from a
/// name hit so no caller can mistake one for the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedGpioLine {
    /// The line was found by its DT name. This is the primary, stable key.
    ByName {
        /// Chip that carries the named line.
        chip_path: PathBuf,
        /// Line offset within that chip (chardev request offset).
        offset: u32,
        /// Legacy sysfs global number (`base + offset`) when the chip base is
        /// known — lets a caller keep using its existing sysfs mechanism
        /// unchanged during migration.
        global: Option<u32>,
    },
    /// The name was absent on this kernel and the caller's EXPLICIT legacy
    /// integer was used instead. Always logged at `warn` level.
    LegacyIntegerFallback {
        /// The caller-provided legacy sysfs global number, passed through
        /// verbatim (never guessed, never adjusted).
        global: u32,
        /// Chip/offset when derivable from chip base ranges.
        chip_path: Option<PathBuf>,
        offset: Option<u32>,
        /// The exact message that was logged for this fallback.
        warning: String,
    },
}

impl ResolvedGpioLine {
    /// Legacy sysfs global number, when known.
    pub fn global(&self) -> Option<u32> {
        match self {
            Self::ByName { global, .. } => *global,
            Self::LegacyIntegerFallback { global, .. } => Some(*global),
        }
    }

    /// True when this resolution rode the legacy-integer fallback.
    pub fn is_fallback(&self) -> bool {
        matches!(self, Self::LegacyIntegerFallback { .. })
    }
}

/// Typed by-name resolution failure. Converts into `HalError::Gpio` for HAL
/// callers; tests match on the typed variants.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GpioNameError {
    /// Empty names can never be a key: DT `gpio-line-names` uses "" for
    /// unnamed lines, so matching "" would alias every unnamed line.
    #[error("GPIO line name must be non-empty (\"\" means UNNAMED in gpio-line-names)")]
    EmptyName,

    /// The name was not published by any scanned gpiochip and no legacy
    /// integer fallback was provided. Fail closed.
    #[error(
        "GPIO line name {name:?} not found on any of {chips_scanned} gpiochip(s); \
         refusing to guess a line"
    )]
    NameNotFound { name: String, chips_scanned: usize },

    /// The name is published more than once. An ambiguous DT is a broken DT;
    /// refusing (rather than picking, or silently falling back to an integer)
    /// keeps the DT bug visible.
    #[error(
        "GPIO line name {name:?} is ambiguous: {first} and {second} both publish it; \
         refusing to pick one and refusing integer fallback that would mask the DT bug"
    )]
    DuplicateName {
        name: String,
        first: String,
        second: String,
    },

    /// The name was absent AND the provided legacy integer provably cannot
    /// exist on this kernel (outside every known chip base..base+ngpio
    /// range). Fail closed rather than hand back a dead/aliased number.
    #[error(
        "GPIO line name {name:?} absent and legacy global GPIO {legacy_gpio} does not fall \
         inside any known gpiochip range: {detail}"
    )]
    FallbackUnresolvable {
        name: String,
        legacy_gpio: u32,
        detail: String,
    },
}

impl From<GpioNameError> for crate::HalError {
    fn from(e: GpioNameError) -> Self {
        crate::HalError::Gpio(e.to_string())
    }
}

fn describe_hit(chip: &Path, offset: u32) -> String {
    format!("{}:{}", chip.display(), offset)
}

// ---------------------------------------------------------------------------
// Pure resolution core (host-testable, no hardware)
// ---------------------------------------------------------------------------

/// Resolve `name` across `snapshots`, name-only. Fail closed on absent,
/// duplicate, or empty names.
pub fn resolve_by_name_in(
    snapshots: &[GpioChipSnapshot],
    name: &str,
) -> std::result::Result<ResolvedGpioLine, GpioNameError> {
    if name.is_empty() {
        return Err(GpioNameError::EmptyName);
    }

    let mut hit: Option<(&GpioChipSnapshot, u32)> = None;
    for snap in snapshots {
        for (offset, line_name) in snap.line_names.iter().enumerate() {
            if line_name.as_deref() != Some(name) {
                continue;
            }
            let offset = offset as u32;
            if let Some((prev_snap, prev_offset)) = hit {
                return Err(GpioNameError::DuplicateName {
                    name: name.to_string(),
                    first: describe_hit(&prev_snap.chip_path, prev_offset),
                    second: describe_hit(&snap.chip_path, offset),
                });
            }
            hit = Some((snap, offset));
        }
    }

    match hit {
        Some((snap, offset)) => Ok(ResolvedGpioLine::ByName {
            chip_path: snap.chip_path.clone(),
            offset,
            global: snap.base.map(|b| b + offset),
        }),
        None => Err(GpioNameError::NameNotFound {
            name: name.to_string(),
            chips_scanned: snapshots.len(),
        }),
    }
}

/// Name-first, integer-fallback resolution.
///
/// Expresses "the line called `name`, or legacy integer `legacy_global` if
/// this kernel has no names". The fallback fires ONLY on
/// [`GpioNameError::NameNotFound`]; duplicate/empty-name failures stay fail
/// closed (they indicate a broken DT, which the fallback must not mask).
/// Every taken fallback is logged via `tracing::warn!` and marked
/// [`ResolvedGpioLine::LegacyIntegerFallback`].
pub fn resolve_name_or_legacy_in(
    snapshots: &[GpioChipSnapshot],
    name: &str,
    legacy_global: u32,
) -> std::result::Result<ResolvedGpioLine, GpioNameError> {
    match resolve_by_name_in(snapshots, name) {
        Ok(hit) => Ok(hit),
        Err(GpioNameError::NameNotFound { .. }) => {
            // Derive chip/offset and range-validate when base info exists.
            let mut located: Option<(PathBuf, u32)> = None;
            let mut ranged_chips = 0usize;
            for snap in snapshots {
                if let Some(base) = snap.base {
                    ranged_chips += 1;
                    let ngpio = snap.line_names.len() as u32;
                    if legacy_global >= base && legacy_global < base + ngpio {
                        located = Some((snap.chip_path.clone(), legacy_global - base));
                        break;
                    }
                }
            }

            if located.is_none() && ranged_chips > 0 && ranged_chips == snapshots.len() {
                // Every chip published a base range and none contains the
                // legacy number: it provably does not exist on this kernel.
                return Err(GpioNameError::FallbackUnresolvable {
                    name: name.to_string(),
                    legacy_gpio: legacy_global,
                    detail: format!("{ranged_chips} gpiochip range(s) checked, none contains it"),
                });
            }

            let warning = format!(
                "GPIO line name {name:?} not published by this kernel; falling back to \
                 EXPLICIT legacy global gpio{legacy_global} (kernel-version-fragile; add \
                 gpio-line-names to the DT to make this unit's identity stable)"
            );
            tracing::warn!(
                target: "gpio_name_resolver",
                line_name = name,
                legacy_gpio = legacy_global,
                "{warning}"
            );
            let (chip_path, offset) = match located {
                Some((c, o)) => (Some(c), Some(o)),
                None => (None, None),
            };
            Ok(ResolvedGpioLine::LegacyIntegerFallback {
                global: legacy_global,
                chip_path,
                offset,
                warning,
            })
        }
        Err(other) => Err(other),
    }
}

// ---------------------------------------------------------------------------
// Snapshot gathering (chardev v1 first, sysfs/DT fallback)
// ---------------------------------------------------------------------------

/// Parse a device-tree `gpio-line-names` property blob (NUL-separated string
/// list, as exposed under `.../device/of_node/gpio-line-names`) into a
/// per-offset name table of exactly `ngpio` entries. Empty strings (DT's
/// "unnamed" marker) become `None`.
pub fn parse_dt_line_names(raw: &[u8], ngpio: usize) -> Vec<Option<String>> {
    let mut names: Vec<Option<String>> = raw
        .split(|&b| b == 0)
        .map(|chunk| {
            if chunk.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(chunk).into_owned())
            }
        })
        .collect();
    // A well-formed DT string list ends with a NUL, which yields one trailing
    // empty chunk — drop it before sizing so it isn't counted as a line.
    if raw.last() == Some(&0) {
        names.pop();
    }
    names.resize_with(ngpio, || None);
    names.truncate(ngpio);
    names
}

fn read_uint(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Enumerate gpiochips under explicit roots. Injectable roots keep this
/// testable against fixture trees; production uses [`snapshot_system_chips`].
///
/// Per chip: line names come from the chardev v1 ioctl when
/// `<dev_root>/gpiochipN` is a working chardev, else from the sysfs/DT
/// `device/of_node/gpio-line-names` blob, else all-`None` (unnamed).
pub fn snapshot_chips_from_roots(sysfs_gpio_root: &Path, dev_root: &Path) -> Vec<GpioChipSnapshot> {
    let mut snapshots = Vec::new();
    let Ok(entries) = std::fs::read_dir(sysfs_gpio_root) else {
        return snapshots;
    };

    let mut chip_dirs: Vec<(u32, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let file_name = entry.file_name();
            let name = file_name.to_str()?;
            let idx: u32 = name.strip_prefix("gpiochip")?.parse().ok()?;
            Some((idx, entry.path()))
        })
        .collect();
    chip_dirs.sort_by_key(|(idx, _)| *idx);

    for (idx, sysfs_dir) in chip_dirs {
        let base = read_uint(&sysfs_dir.join("base"));
        let ngpio = read_uint(&sysfs_dir.join("ngpio")).unwrap_or(0) as usize;

        let chardev = dev_root.join(format!("gpiochip{idx}"));
        let (chip_path, line_names) = match libgpiod::list_line_names(&chardev) {
            Ok(names) => (chardev, names),
            Err(_) => {
                // Chardev absent/unreadable (e.g. gpiolib-only kernel):
                // fall back to the DT property mirrored under sysfs.
                let dt_blob = std::fs::read(sysfs_dir.join("device/of_node/gpio-line-names"));
                let names = match dt_blob {
                    Ok(raw) => parse_dt_line_names(&raw, ngpio),
                    Err(_) => vec![None; ngpio],
                };
                (sysfs_dir, names)
            }
        };

        snapshots.push(GpioChipSnapshot {
            chip_path,
            base,
            line_names,
        });
    }
    snapshots
}

/// Enumerate the live system's gpiochips (`/sys/class/gpio` + `/dev`).
pub fn snapshot_system_chips() -> Vec<GpioChipSnapshot> {
    snapshot_chips_from_roots(Path::new("/sys/class/gpio"), Path::new("/dev"))
}

/// Resolve a line by DT name across all live gpiochips. Fail closed.
pub fn resolve_by_name(name: &str) -> crate::Result<ResolvedGpioLine> {
    let snapshots = snapshot_system_chips();
    Ok(resolve_by_name_in(&snapshots, name)?)
}

/// Name-first, integer-fallback resolution against the live system.
///
/// `legacy_global` is the call site's existing raw sysfs number, kept as an
/// explicit, logged fallback — never the primary key.
pub fn resolve_name_or_legacy(name: &str, legacy_global: u32) -> crate::Result<ResolvedGpioLine> {
    let snapshots = snapshot_system_chips();
    Ok(resolve_name_or_legacy_in(&snapshots, name, legacy_global)?)
}

impl fmt::Display for ResolvedGpioLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ByName {
                chip_path,
                offset,
                global,
            } => match global {
                Some(g) => write!(f, "{}:{} (global gpio{})", chip_path.display(), offset, g),
                None => write!(f, "{}:{}", chip_path.display(), offset),
            },
            Self::LegacyIntegerFallback { global, .. } => {
                write!(f, "gpio{global} (LEGACY INTEGER FALLBACK)")
            }
        }
    }
}
