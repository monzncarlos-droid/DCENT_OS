//! Rank-35 drift pin: the HAL's probe-time fw-byte roster
//! (`dcentrald_hal::psu::PsuModel`) must stay in agreement with the spec
//! catalog (`dcentrald_api_types::psu_model`) over the fw-byte region both
//! define (`0x71..=0x77`, the APW12 1215 revisions).
//!
//! The HAL roster is on the live `Apw121215a::probe()` path and is NOT
//! folded into the `PowerTopology` descriptor
//! (`dcentrald-silicon-profiles::power_topology`); this test is the additive
//! anti-drift bound between the two instead. It changes no behaviour.
//!
//! One divergence is DELIBERATE and pinned as such below: the spec catalog
//! (RE doc) says APW121215f has a voltage-feedback ADC, while the HAL
//! conservatively reports `has_voltage_feedback() == false` for fw=0x76
//! because its telemetry has never been characterized on a live unit
//! (`is_telemetry_characterized() == false`). Do not "reconcile" either side
//! without live evidence.

use dcentrald_api_types::psu_model::apw_from_fw_byte;
use dcentrald_hal::psu::PsuModel;

/// The fw-byte region both rosters classify: 0x71..=0x77 → APW121215a..g.
const SHARED_FW_BYTES: &[u8] = &[0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77];

#[test]
fn fw_byte_classification_agrees_across_rosters() {
    for &fw in SHARED_FW_BYTES {
        let hal = PsuModel::from_fw_byte(fw);
        let spec = apw_from_fw_byte(fw).unwrap_or_else(|| {
            panic!("spec catalog lost fw byte 0x{fw:02X} that the HAL roster classifies")
        });
        let spec_label = spec.spec().label;
        // Spec labels are per-revision ("APW121215a"); HAL names may group
        // revisions ("APW121215b/c"). Agreement = same family stem AND the
        // HAL name covers the spec revision letter.
        assert!(
            spec_label.starts_with("APW121215"),
            "0x{fw:02X}: spec label {spec_label} left the 1215 family"
        );
        let hal_name = hal.name();
        assert!(
            hal_name.starts_with("APW121215"),
            "0x{fw:02X}: HAL name {hal_name} left the 1215 family"
        );
        let revision = spec_label
            .chars()
            .next_back()
            .expect("spec label is non-empty");
        assert!(
            hal_name.contains(revision),
            "0x{fw:02X}: HAL name {hal_name} does not cover spec revision {revision}"
        );
    }
}

#[test]
fn voltage_feedback_agrees_for_characterized_revisions() {
    // a/b/c (no ADC) and d/e/g (ADC) agree across both rosters.
    for (&fw, expected_feedback) in SHARED_FW_BYTES.iter().zip([
        false, // 0x71 a
        false, // 0x72 b
        false, // 0x73 c
        true,  // 0x74 d
        true,  // 0x75 e
        true,  // 0x76 f — spec says true; HAL diverges (pinned separately)
        true,  // 0x77 g
    ]) {
        let spec = apw_from_fw_byte(fw).expect("shared byte");
        assert_eq!(
            spec.spec().has_voltage_feedback,
            expected_feedback,
            "spec catalog feedback flag moved for 0x{fw:02X}"
        );
        if fw == 0x76 {
            continue; // deliberate divergence, pinned below
        }
        assert_eq!(
            PsuModel::from_fw_byte(fw).has_voltage_feedback(),
            expected_feedback,
            "HAL feedback flag disagrees with spec catalog for 0x{fw:02X}"
        );
    }
}

#[test]
fn apw121215f_conservative_divergence_is_deliberate_and_stays() {
    // Spec catalog (RE doc): 1215f HAS a voltage-feedback ADC.
    let spec = apw_from_fw_byte(0x76).expect("0x76 is APW121215f");
    assert!(spec.spec().has_voltage_feedback);
    // HAL: fw=0x76 telemetry is UNCHARACTERIZED on live hardware, so the
    // probe-path roster fails closed. Flipping this without live evidence is
    // a regression; wiring telemetry off the spec flag alone is a regression.
    let hal = PsuModel::from_fw_byte(0x76);
    assert_eq!(hal, PsuModel::Apw121215f);
    assert!(!hal.has_voltage_feedback());
    assert!(!hal.is_telemetry_characterized());
}
