//! Source-parse breadth pin for hashboard EEPROM write-denylist construction.
//!
//! The runtime guarantee is per I2C service handle: non-S9 paths that can share
//! a bus with AT24C-class hashboard EEPROMs must construct the service with the
//! 0x50..=0x57 write-denylist. This test covers every daemon/mining entry point
//! that creates such a long-running service.

const DAEMON_RS: &str = include_str!("../src/daemon.rs");
const HYBRID_RS: &str = include_str!("../src/s19j_hybrid_mining.rs");
const SERIAL_RS: &str = include_str!("../src/serial_mining.rs");
const AM3_BB_RS: &str = include_str!("../src/am3_bb_mining.rs");
const AMLOGIC_RS: &str = include_str!("../../dcentrald-hal/src/platform/amlogic/mod.rs");

struct ConstructionSite {
    label: &'static str,
    source: &'static str,
    entry_marker: &'static str,
    constructor: &'static str,
    denylist_marker: &'static str,
}

fn assert_denylisted_construction(site: &ConstructionSite) -> Result<(), String> {
    let entry = site.source.find(site.entry_marker).ok_or_else(|| {
        format!(
            "{}: missing entry marker `{}`",
            site.label, site.entry_marker
        )
    })?;
    let body = &site.source[entry..];

    let constructor_pos = body
        .find(site.constructor)
        .ok_or_else(|| format!("{}: missing denylist constructor", site.label))?;
    let denylist_pos = body.find(site.denylist_marker).ok_or_else(|| {
        format!(
            "{}: missing denylist marker `{}`",
            site.label, site.denylist_marker
        )
    })?;

    let distance = constructor_pos.abs_diff(denylist_pos);
    if distance > 512 {
        return Err(format!(
            "{}: constructor and denylist marker are too far apart ({} bytes)",
            site.label, distance
        ));
    }

    Ok(())
}

#[test]
fn non_s9_i2c_construction_sites_register_eeprom_write_denylist() {
    let sites = [
        ConstructionSite {
            label: "daemon_standard_non_s9",
            source: DAEMON_RS,
            entry_marker: "async fn init(",
            constructor: "spawn_i2c_service_no_register_touch_with_denylist",
            denylist_marker: "HASHBOARD_EEPROM_WRITE_DENYLIST.to_vec()",
        },
        ConstructionSite {
            label: "am2_hybrid_phase0",
            source: HYBRID_RS,
            entry_marker: "Phase 0: PSU bring-up",
            constructor: "spawn_i2c_service_no_register_touch_with_denylist",
            denylist_marker: "let am2_eeprom_denylist: Vec<u8> = (0x50u8..=0x57u8).collect()",
        },
        ConstructionSite {
            label: "am2_serial_pic_service",
            source: SERIAL_RS,
            entry_marker: "let bm1362_i2c_service = if",
            constructor: "spawn_i2c_service_no_register_touch_with_denylist",
            denylist_marker: "HASHBOARD_EEPROM_WRITE_DENYLIST.to_vec()",
        },
        ConstructionSite {
            label: "am3_bb_dspic_service",
            source: AM3_BB_RS,
            entry_marker: "let dspic_i2c =",
            constructor: "spawn_i2c_service_no_register_touch_with_denylist",
            denylist_marker: "AM3_BB_HASHBOARD_EEPROM_DENYLIST.to_vec()",
        },
        ConstructionSite {
            label: "am3_aml_protected_i2c0_service",
            source: AMLOGIC_RS,
            entry_marker: "pub fn spawn_amlogic_protected_i2c0_service",
            constructor: "spawn_i2c_service_no_register_touch_with_denylist",
            denylist_marker: "AMLOGIC_EEPROM_DENYLIST.to_vec()",
        },
        // The site this array was missing, and the reason it stayed missing:
        // every prior revision enumerated only the bus-0 helper above, so the
        // gate went green while the service that actually reaches the Amlogic
        // hashboard EEPROMs registered no denylist at all. The EEPROMs are on
        // bus 1 (see `shipped_amlogic_hashboard_artifact_puts_eeproms_on_the_management_bus`
        // below), which is this service.
        //
        // The entry marker resolves at the `AmlogicPowerThermalService::spawn`
        // definition, which sits well after the bus-0 helper — so the helper's
        // forward-only `find` cannot satisfy this row from the bus-0 site's
        // occurrence of the same denylist marker.
        ConstructionSite {
            label: "am3_aml_management_power_thermal_service",
            source: AMLOGIC_RS,
            entry_marker: "fn spawn(admission: &AmlogicNoPicAdmission)",
            constructor:
                "spawn_owned_i2c_service_no_register_touch_with_denylist_and_reserved_preparation",
            denylist_marker: "AMLOGIC_EEPROM_DENYLIST.to_vec()",
        },
    ];

    for site in &sites {
        assert_denylisted_construction(site)
            .unwrap_or_else(|err| panic!("EEPROM denylist construction drift: {err}"));
    }
}

/// Pin the evidence, not just the code shape.
///
/// The breadth row above asserts that the Amlogic *management* service carries
/// the EEPROM write-denylist. This asserts WHY that is the right service: the
/// hashboard EEPROMs are on I2C bus 1, per the artifact we ourselves ship into
/// the rootfs. Without this, a future reader could "simplify" the breadth array
/// back onto bus 0 and the suite would still pass.
///
/// Deliberately parsed with a plain substring scan rather than a JSON
/// dependency — this is a test-only contract over a file whose shape we own.
#[test]
fn shipped_amlogic_hashboard_artifact_puts_eeproms_on_the_management_bus() {
    const DECODED: &str = include_str!(
        "../../../br2_external_dcentos/board/amlogic/am3-s19kpro/rootfs-overlay/etc/dcentos/hashboard_decoded.json"
    );

    let declarations: Vec<&str> = DECODED
        .split("\"i2c_bus\"")
        .skip(1)
        .map(|rest| rest.trim_start_matches([':', ' ']))
        .collect();

    assert!(
        !declarations.is_empty(),
        "shipped hashboard_decoded.json declares no i2c_bus at all — the artifact \
         changed shape and this contract needs rewriting, not deleting"
    );

    for (index, decl) in declarations.iter().enumerate() {
        assert!(
            decl.starts_with('1'),
            "board {index} in the shipped Amlogic hashboard artifact declares an \
             i2c_bus that is not 1. The EEPROM write-denylist is registered on the \
             service that owns the management bus; if the boards really moved, move \
             the denylist with them rather than relaxing this assertion. \
             (Corroborated by the live .78 probe: bus 0 scans empty and every bus-0 \
             read fails, while bus 1 answers at 0x50/0x51/0x52.)"
        );
    }
}

#[test]
fn denylist_breadth_helper_rejects_plain_i2c_service_constructor() {
    let site = ConstructionSite {
        label: "negative_control",
        source: "fn run() { let _ = spawn_i2c_service_no_register_touch(0); }",
        entry_marker: "fn run()",
        constructor: "spawn_i2c_service_no_register_touch_with_denylist",
        denylist_marker: "HASHBOARD_EEPROM_WRITE_DENYLIST.to_vec()",
    };

    let err = assert_denylisted_construction(&site)
        .expect_err("negative control must reject a plain no-denylist constructor");
    assert!(
        err.contains("missing denylist constructor"),
        "unexpected negative-control error: {err}"
    );
}
