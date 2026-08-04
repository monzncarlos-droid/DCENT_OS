//! Rank-35 (2026-08-02 hardware-enablement constitution): `PowerTopology`
//! descriptor — the single declarative dispatch input that fuses the two PSU
//! catalogs.
//!
//! # The two catalogs this module fuses
//!
//! 1. **Routing catalog** — [`crate::psus`] (`Psu` / `PsuCatalogEntry`,
//!    15 rows): I²C address, control-protocol family, enable-GPIO pin,
//!    max power, fleet usage. This is the catalog dispatch code keys on.
//! 2. **Spec catalog** — `dcentrald_api_types::psu_model` (`ApwModel` /
//!    `ApwSpec`, 18 rows): voltage/current/wattage envelopes, AC input,
//!    efficiency, voltage-feedback capability, fleet-UI labels, plus the
//!    `apw_from_fw_byte` firmware-byte classifier.
//!
//! A third, runtime-facing roster exists in
//! `dcentrald-hal::psu::PsuModel` (probe-time fw-byte classifier used by the
//! live `Apw121215a::probe()` path). It is NOT folded here — it is on the
//! live probe path and behaviour there is frozen. An additive drift-pin test
//! (`dcentrald-hal/tests/psu_fw_byte_catalog_agreement.rs`) asserts it agrees
//! with the spec catalog over the overlapping fw-byte region instead.
//!
//! # What this descriptor is
//!
//! One declarative record per [`Psu`] carrying everything a dispatch site
//! needs to *choose* a control path, so that future boards add a catalog row
//! instead of a new `match` arm:
//!
//! - the embedded routing-catalog row (byte-identical to [`Psu::catalog`] —
//!   pinned by test, so the descriptor can never drift from the catalog);
//! - the [`HalControlBinding`] naming which shipped HAL layer serves the
//!   row's control dialect (derived 1:1 from the protocol tag — a name, not
//!   a constructor: this crate has no HAL dependency and structurally cannot
//!   open a bus or energize anything);
//! - whether the **read-only** PMBus telemetry layer
//!   (`dcentrald-hal::pmbus`, landed in commit `dd2f51900`, default-OFF,
//!   opt-in `DCENT_PMBUS_TELEMETRY=1`) is applicable to the family — a
//!   description only, wired into no live path;
//! - the evidence-backed cross-catalog identity: which [`ApwModel`] spec
//!   rows describe the same physical PSU.
//!
//! # What this descriptor deliberately is NOT
//!
//! - **No polarity fields.** [`crate::psus::PsuEnableGpio`] carries a pin
//!   number and a platform tag only; this module adds nothing. In
//!   particular the Amlogic `gpio437` PSU-enable polarity is UNRESOLVED
//!   (ePIC evidence and our records disagree; nobody has measured a rail) —
//!   no field here can force that choice, and a test pins that no catalog
//!   row references pin 437 at all. `gpio907` semantics are likewise owned
//!   exclusively by `dcentrald-hal::psu_gpio_gate` and are not mirrored,
//!   summarized, or re-declared here.
//! - **No fabricated electrical values.** Every number in a descriptor is a
//!   verbatim copy of an existing catalog field. Rows the RE evidence never
//!   pinned stay exactly as partial as the catalog says they are
//!   (`verification_partial`).
//! - **No efficiency constants.** The bypass-efficiency dispatch
//!   (`dcentrald/src/runtime/efficiency.rs::psu_efficiency_for_model_name`)
//!   is a frozen daemon path; duplicating its constants here would create a
//!   second source of truth.
//! - **No wiring.** Nothing in this crate can construct a driver, open a
//!   bus, or reach `dcentrald-hal`. The descriptor is data for dispatch
//!   sites to consume in a *future* fold, once those sites are unfrozen.
//!
//! # Known cross-catalog conflicts (surfaced, NOT resolved)
//!
//! - `Psu::Apw17` (routing catalog: "APW17", S17/T17, 1700 W, proto-v2)
//!   vs `ApwModel::Apw17_1215` (spec catalog: "APW17 (1215)", S21 family,
//!   3600 W). Same name stem, contradictory hardware claims → unmapped.
//! - `Psu::Apw12Plus` ("APW12+", S21/S21 Pro/S21 XP, register protocol)
//!   vs `ApwModel::Apw17_1215` (also claims S21/S21 Pro/S21 XP). No held
//!   evidence pins them as the same unit → unmapped. Both empty mappings
//!   are pinned by tests so they cannot be "fixed" without new evidence.
//! - `ApwModel::Apw9Plus`, `Apw12_1417`, `Apw12A` and the seven `1215*`
//!   revision letters have no dedicated routing-catalog rows; the
//!   APW121215f UART-tunnel driver (`dcentrald-hal::psu_apw_uart_tunnel`)
//!   serves a unit (fw `0x76`) that has **no** routing-catalog row at all.
//!   Recorded here as a gap; adding a row needs enable-GPIO/protocol
//!   evidence this session does not hold.

use serde::Serialize;

use crate::psus::{Psu, PsuCatalogEntry, PsuProtocol, ALL_PSUS};
use dcentrald_api_types::psu_model::ApwModel;

// ---------------------------------------------------------------------------
// HAL control binding — a declarative name, never a constructor
// ---------------------------------------------------------------------------

/// Which shipped HAL layer serves a catalog row's control dialect.
///
/// This is a *name*, resolved 1:1 from [`PsuProtocol`]. This crate has no
/// HAL dependency, so the binding cannot construct, open, or energize
/// anything — it exists so dispatch sites (today: hand-written `match`es in
/// the frozen daemon paths) have a single declarative source to consume when
/// they are eventually folded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HalControlBinding {
    /// No shipped control driver; the PSU output turns on at AC apply
    /// (PMBus-class APW3++/APW7/APW9/APW10/APW11). The only applicable
    /// software layer is the read-only PMBus telemetry module
    /// (`dcentrald-hal::pmbus`), which is default-OFF and mutates nothing.
    NoneAcApply,
    /// Proprietary Bitmain proto-v1/v2 dialect with **no shipped DCENT_OS
    /// backend**. Rows with this binding cannot be driven; a dispatch site
    /// consuming this descriptor must fail closed for them.
    NoneUnimplemented,
    /// `dcentrald-hal::psu_apw12_smbus::Apw12SmbusBackend` — APW12 SMBus
    /// opcode dialect (CV1835 / AM335x BB / Amlogic S19j Pro), sealed-trait
    /// platform whitelist at construction.
    Apw12Smbus,
    /// `dcentrald-hal::psu_apw12_plus::Apw12PlusBackend` — APW12+
    /// register dialect (S21 family), sealed-trait platform whitelist at
    /// construction.
    Apw12PlusRegister,
    /// `dcentrald-hal::psu::Apw121215a` — am2 Zynq framed-I²C dsPIC-coupled
    /// dialect (fw=0x71 exact-identity adapter).
    Apw121215aFramed,
}

/// Resolve the shipped HAL binding for a protocol tag. Total and 1:1 — the
/// derivation is the protocol column of the routing catalog, nothing else.
pub const fn binding_for_protocol(protocol: PsuProtocol) -> HalControlBinding {
    match protocol {
        PsuProtocol::PmBus => HalControlBinding::NoneAcApply,
        PsuProtocol::BitmainProtoV1 | PsuProtocol::BitmainProtoV2 => {
            HalControlBinding::NoneUnimplemented
        }
        PsuProtocol::Apw12Smbus => HalControlBinding::Apw12Smbus,
        PsuProtocol::Apw12PlusRegister => HalControlBinding::Apw12PlusRegister,
        PsuProtocol::Apw121215a => HalControlBinding::Apw121215aFramed,
    }
}

/// Whether the read-only PMBus telemetry layer (`dcentrald-hal::pmbus`)
/// is applicable to this protocol family.
///
/// Descriptive only: the layer itself stays default-OFF behind
/// `DCENT_PMBUS_TELEMETRY=1` and this crate cannot enable it. Membership
/// mirrors `dcentrald-hal::pmbus::PmbusPsuFamily` (the five `PmBus` rows at
/// I²C `0x58`); the mirror is pinned by test below so the two rosters cannot
/// drift silently.
pub const fn pmbus_read_only_telemetry_applicable(protocol: PsuProtocol) -> bool {
    matches!(protocol, PsuProtocol::PmBus)
}

// ---------------------------------------------------------------------------
// Cross-catalog identity — evidence-backed rows only
// ---------------------------------------------------------------------------

/// Spec-catalog rows describing the same physical PSU as a routing-catalog
/// row. **Evidence-backed identities only**; an empty slice means "no
/// counterpart is pinned", never "no counterpart exists".
///
/// Evidence per non-empty mapping:
/// - `Apw3PlusPlus` → `Apw3`: the spec row's label is literally
///   "APW3 / APW3++".
/// - `Apw7` → `Apw7`, `Apw9` → `Apw9`: exact model-string equality.
///   (`Apw9Plus` is a distinct SKU with no routing row — not folded in.)
/// - `Apw12` → the seven `Apw12_1215a..g` revisions: both catalogs place
///   these on the S19 / S19j Pro / T19 fleet; `Apw12_1417` (L7/K7-class)
///   and `Apw12A` are different fleets and are excluded.
/// - `Apw121215a` → `Apw12_1215a`: exact model-string equality
///   ("APW121215a") plus the fw-byte tie (`apw_from_fw_byte(0x71)`), which
///   matches the routing catalog's documented fw=0x71 identity.
///
/// The same spec row may back more than one routing row (`Apw12_1215a`
/// appears under both `Apw12` and `Apw121215a`): the routing catalog keys
/// the generic SMBus dialect and the am2 dsPIC-coupled dialect separately,
/// and that split is deliberate.
pub const fn apw_models_for(psu: Psu) -> &'static [ApwModel] {
    match psu {
        Psu::Apw3PlusPlus => &[ApwModel::Apw3],
        Psu::Apw7 => &[ApwModel::Apw7],
        Psu::Apw9 => &[ApwModel::Apw9],
        Psu::Apw12 => &[
            ApwModel::Apw12_1215a,
            ApwModel::Apw12_1215b,
            ApwModel::Apw12_1215c,
            ApwModel::Apw12_1215d,
            ApwModel::Apw12_1215e,
            ApwModel::Apw12_1215f,
            ApwModel::Apw12_1215g,
        ],
        Psu::Apw121215a => &[ApwModel::Apw12_1215a],
        // No spec-catalog counterpart exists for these rows today.
        Psu::Apw10
        | Psu::Apw11
        | Psu::Apw111721b
        | Psu::Apw111721c
        | Psu::Apw11A1216_1a
        | Psu::Apw11Go
        | Psu::Nbs1902
        | Psu::Pw380X12 => &[],
        // Deliberately UNMAPPED — known cross-catalog conflicts (see module
        // docs). Do not fill these in without new hardware/RE evidence.
        Psu::Apw12Plus | Psu::Apw17 => &[],
    }
}

// ---------------------------------------------------------------------------
// The descriptor
// ---------------------------------------------------------------------------

/// The fused, declarative dispatch input for one PSU.
///
/// Additive over [`Psu::catalog`]: the embedded `catalog` field is produced
/// by the same `const` table (single source of truth — nothing is
/// re-declared), and the remaining fields are total derivations pinned by
/// the tests below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PowerTopology {
    /// Routing-catalog key.
    pub psu: Psu,
    /// The routing-catalog row, verbatim (same source as [`Psu::catalog`]).
    pub catalog: PsuCatalogEntry,
    /// Which shipped HAL layer serves this row's control dialect (a name,
    /// never a constructor).
    pub control_binding: HalControlBinding,
    /// Whether the read-only, default-OFF PMBus telemetry layer applies to
    /// this family. Descriptive only; wired into no live path.
    pub pmbus_read_only_telemetry: bool,
    /// Evidence-backed spec-catalog identities (may be empty — see
    /// [`apw_models_for`]).
    pub apw_models: &'static [ApwModel],
}

impl Psu {
    /// The fused descriptor for this PSU. `const` and total.
    pub const fn power_topology(self) -> PowerTopology {
        let catalog = self.catalog();
        PowerTopology {
            psu: self,
            catalog,
            control_binding: binding_for_protocol(catalog.protocol),
            pmbus_read_only_telemetry: pmbus_read_only_telemetry_applicable(catalog.protocol),
            apw_models: apw_models_for(self),
        }
    }
}

/// Descriptors for every routing-catalog row, in [`ALL_PSUS`] order.
pub fn all_power_topologies() -> impl Iterator<Item = PowerTopology> {
    ALL_PSUS.iter().map(|psu| psu.power_topology())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcentrald_api_types::psu_model::{apw_from_fw_byte, ALL_MODELS};

    // -- Equivalence with catalog #1 (the routing catalog) ---------------

    #[test]
    fn descriptor_embeds_the_routing_catalog_byte_identically() {
        // The load-bearing equivalence proof: for EVERY catalog entry the
        // fused descriptor's embedded row equals `Psu::catalog()` exactly.
        // A dispatch site reading `power_topology().catalog` sees the
        // identical `PsuCatalogEntry` it reads today from `catalog()`.
        for psu in ALL_PSUS {
            let topology = psu.power_topology();
            assert_eq!(topology.psu, *psu);
            assert_eq!(
                topology.catalog,
                psu.catalog(),
                "PowerTopology.catalog drifted from Psu::catalog() for {}",
                psu.model()
            );
        }
    }

    #[test]
    fn every_catalog_row_has_a_descriptor() {
        assert_eq!(all_power_topologies().count(), ALL_PSUS.len());
        assert_eq!(ALL_PSUS.len(), 15);
    }

    // -- Binding derivation is exactly the protocol column ----------------

    #[test]
    fn control_binding_is_a_pure_function_of_the_protocol_tag() {
        for psu in ALL_PSUS {
            let topology = psu.power_topology();
            let expected = match topology.catalog.protocol {
                PsuProtocol::PmBus => HalControlBinding::NoneAcApply,
                PsuProtocol::BitmainProtoV1 | PsuProtocol::BitmainProtoV2 => {
                    HalControlBinding::NoneUnimplemented
                }
                PsuProtocol::Apw12Smbus => HalControlBinding::Apw12Smbus,
                PsuProtocol::Apw12PlusRegister => HalControlBinding::Apw12PlusRegister,
                PsuProtocol::Apw121215a => HalControlBinding::Apw121215aFramed,
            };
            assert_eq!(
                topology.control_binding,
                expected,
                "binding drifted from protocol column for {}",
                psu.model()
            );
        }
    }

    #[test]
    fn shipped_driver_rows_bind_to_their_documented_backends() {
        // Mirrors the driver table documented in `crate::psus` module docs
        // and in `dcentrald-hal::psu_apw12_plus` header comments.
        assert_eq!(
            Psu::Apw12.power_topology().control_binding,
            HalControlBinding::Apw12Smbus
        );
        assert_eq!(
            Psu::Apw12Plus.power_topology().control_binding,
            HalControlBinding::Apw12PlusRegister
        );
        assert_eq!(
            Psu::Apw121215a.power_topology().control_binding,
            HalControlBinding::Apw121215aFramed
        );
        // Proto-v1/v2 rows have NO shipped backend — a consumer must fail
        // closed. If someone ships a backend for these, this pin forces the
        // descriptor update to be explicit.
        for psu in [
            Psu::Apw111721b,
            Psu::Apw111721c,
            Psu::Apw11A1216_1a,
            Psu::Apw11Go,
            Psu::Apw17,
            Psu::Nbs1902,
            Psu::Pw380X12,
        ] {
            assert_eq!(
                psu.power_topology().control_binding,
                HalControlBinding::NoneUnimplemented,
                "{} gained a binding without evidence",
                psu.model()
            );
        }
    }

    // -- PMBus read-only applicability mirrors the HAL roster --------------

    #[test]
    fn pmbus_applicability_mirrors_the_hal_pmbus_family_roster() {
        // `dcentrald-hal::pmbus::PmbusPsuFamily` covers exactly APW3++ /
        // APW7 / APW9 / APW10 / APW11 at I²C 0x58. This crate cannot import
        // the HAL, so the roster is mirrored literally; if either side
        // changes, one of these two pins breaks.
        let applicable: Vec<&'static str> = all_power_topologies()
            .filter(|t| t.pmbus_read_only_telemetry)
            .map(|t| t.catalog.model)
            .collect();
        assert_eq!(applicable, ["APW3++", "APW7", "APW9", "APW10", "APW11"]);
        for topology in all_power_topologies() {
            if topology.pmbus_read_only_telemetry {
                assert_eq!(
                    topology.catalog.i2c_address, 0x58,
                    "{} is PMBus-applicable but not at the PMBus catalog address",
                    topology.catalog.model
                );
                assert_eq!(topology.catalog.protocol, PsuProtocol::PmBus);
            } else {
                assert_ne!(topology.catalog.protocol, PsuProtocol::PmBus);
            }
        }
    }

    // -- Cross-catalog identity evidence ----------------------------------

    #[test]
    fn apw121215a_identity_is_exact_and_fw_byte_tied() {
        let topology = Psu::Apw121215a.power_topology();
        assert_eq!(topology.apw_models, &[ApwModel::Apw12_1215a]);
        // Exact model-string equality between the two catalogs.
        assert_eq!(ApwModel::Apw12_1215a.spec().label, topology.catalog.model);
        // fw=0x71 ties the spec classifier to the same revision the routing
        // catalog documents for the am2 unit.
        assert_eq!(apw_from_fw_byte(0x71), Some(ApwModel::Apw12_1215a));
    }

    #[test]
    fn apw12_maps_to_exactly_the_seven_1215_revisions() {
        let topology = Psu::Apw12.power_topology();
        assert_eq!(topology.apw_models.len(), 7);
        for model in topology.apw_models {
            let spec = model.spec();
            assert!(
                spec.label.starts_with("APW121215"),
                "{} is not a 1215 revision",
                spec.label
            );
            // Both catalogs put the 1215 revisions on the S19-class fleet.
            for used_in in topology.catalog.used_in {
                assert!(
                    spec.compatible_miners.contains(used_in),
                    "{} spec does not cover {} claimed by the routing catalog",
                    spec.label,
                    used_in
                );
            }
        }
        // The non-S19 APW12 SKUs stay excluded.
        assert!(!topology.apw_models.contains(&ApwModel::Apw12_1417));
        assert!(!topology.apw_models.contains(&ApwModel::Apw12A));
    }

    #[test]
    fn simple_name_identities_hold() {
        assert!(ApwModel::Apw3
            .spec()
            .label
            .contains(Psu::Apw3PlusPlus.model()));
        assert_eq!(ApwModel::Apw7.spec().label, Psu::Apw7.model());
        assert_eq!(ApwModel::Apw9.spec().label, Psu::Apw9.model());
    }

    #[test]
    fn conflicted_rows_stay_deliberately_unmapped() {
        // "APW17" (routing: S17/T17, 1700 W) vs "APW17 (1215)" (spec: S21
        // family, 3600 W) contradict; "APW12+" and "APW17 (1215)" both claim
        // the S21 fleet with no evidence they are the same unit. These
        // mappings stay EMPTY until real evidence lands — do not "fix" them.
        assert!(Psu::Apw17.power_topology().apw_models.is_empty());
        assert!(Psu::Apw12Plus.power_topology().apw_models.is_empty());
    }

    #[test]
    fn mapped_models_are_unique_and_belong_to_the_spec_catalog() {
        for topology in all_power_topologies() {
            let mut seen = std::collections::HashSet::new();
            for model in topology.apw_models {
                assert!(
                    seen.insert(format!("{model:?}")),
                    "duplicate mapping under {}",
                    topology.catalog.model
                );
                assert!(
                    ALL_MODELS.contains(model),
                    "{model:?} mapped under {} is not in ALL_MODELS",
                    topology.catalog.model
                );
            }
        }
    }

    // -- Safety shape: no polarity, no gpio437 -----------------------------

    #[test]
    fn descriptor_carries_no_polarity_and_never_references_gpio437() {
        for topology in all_power_topologies() {
            let json = serde_json::to_string(&topology).expect("serialize");
            for forbidden in ["polarity", "active_low", "active_high"] {
                assert!(
                    !json.contains(forbidden),
                    "descriptor for {} leaked a polarity-shaped field ({})",
                    topology.catalog.model,
                    forbidden
                );
            }
            if let Some(gpio) = topology.catalog.enable_gpio {
                assert_ne!(
                    gpio.pin, 437,
                    "{}: gpio437 polarity is UNRESOLVED; the catalog must not \
                     route through it",
                    topology.catalog.model
                );
            }
        }
    }

    // -- Wire shape --------------------------------------------------------

    #[test]
    fn descriptor_serializes_with_documented_keys() {
        let json = serde_json::to_string(&Psu::Apw12.power_topology()).expect("serialize");
        assert!(json.contains("\"psu\":\"apw12\""));
        assert!(json.contains("\"control_binding\":\"apw12_smbus\""));
        assert!(json.contains("\"pmbus_read_only_telemetry\":false"));
        assert!(json.contains("\"model\":\"APW12\""));

        let json = serde_json::to_string(&Psu::Apw9.power_topology()).expect("serialize");
        assert!(json.contains("\"control_binding\":\"none_ac_apply\""));
        assert!(json.contains("\"pmbus_read_only_telemetry\":true"));
    }
}
