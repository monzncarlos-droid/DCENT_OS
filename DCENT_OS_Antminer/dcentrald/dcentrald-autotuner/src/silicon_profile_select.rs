//! Per-chain silicon-profile table selection.
//!
//! Quality bar (gauntlet ): mixed `(model, hashboard)` preset tables
//! must not first-wins. A chain receives only the table whose hashboard key
//! matches its registered SKU. Unknown identity + multiple tables is a refuse
//! (no guess). Single-table miners keep the W15-A compat path.

use std::collections::HashMap;

use crate::SiliconPreset;

/// Pick the preset table for one chain.
///
/// * `chain_hashboard` — `Bm1362HashboardSku::hashboard_id()` when the
///   daemon registered a SKU; `None` when identity is unknown.
/// * Exact one non-empty table + no identity → that table (single-platform).
/// * Multiple tables + no match / ambiguous match → `None`.
pub fn select_silicon_preset_table<'a>(
    presets: &'a HashMap<(String, String), Vec<SiliconPreset>>,
    chain_hashboard: Option<&str>,
) -> Option<&'a Vec<SiliconPreset>> {
    let nonempty: Vec<_> = presets
        .iter()
        .filter(|(_, table)| !table.is_empty())
        .collect();
    if nonempty.is_empty() {
        return None;
    }

    if let Some(hashboard) = chain_hashboard {
        let matches: Vec<_> = nonempty
            .iter()
            .filter(|((_, key_hb), _)| key_hb.eq_ignore_ascii_case(hashboard))
            .collect();
        if matches.len() == 1 {
            return Some(matches[0].1);
        }
        return None;
    }

    if nonempty.len() == 1 {
        return Some(nonempty[0].1);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(freq_mhz: u32) -> Vec<SiliconPreset> {
        vec![SiliconPreset {
            step: 0,
            freq_mhz,
            voltage_v: 9.0,
        }]
    }

    fn key(model: &str, hb: &str) -> (String, String) {
        (model.to_string(), hb.to_string())
    }

    #[test]
    fn single_table_without_identity_keeps_w15a_compat() {
        let mut presets = HashMap::new();
        presets.insert(key("antminer_s9", "BHB-S9-generic"), table(700));
        let selected = select_silicon_preset_table(&presets, None).expect("one table");
        assert_eq!(selected[0].freq_mhz, 700);
    }

    #[test]
    fn mixed_tables_without_identity_refuse_first_wins() {
        let mut presets = HashMap::new();
        presets.insert(key("antminer_s19j_pro", "BHB42601"), table(525));
        presets.insert(key("antminer_s19j_pro", "BHB42821"), table(650));
        assert!(
            select_silicon_preset_table(&presets, None).is_none(),
            "mixed boards must not apply HashMap first-wins to every chain"
        );
    }

    #[test]
    fn mixed_tables_match_chain_sku_hashboard() {
        let mut presets = HashMap::new();
        presets.insert(key("antminer_s19j_pro", "BHB42601"), table(525));
        presets.insert(key("antminer_s19j_pro", "BHB42821"), table(650));
        let a = select_silicon_preset_table(&presets, Some("BHB42601")).expect("42601");
        let b = select_silicon_preset_table(&presets, Some("bhb42821")).expect("42821 ci");
        assert_eq!(a[0].freq_mhz, 525);
        assert_eq!(b[0].freq_mhz, 650);
    }

    #[test]
    fn unknown_sku_on_mixed_tables_is_none() {
        let mut presets = HashMap::new();
        presets.insert(key("antminer_s19j_pro", "BHB42601"), table(525));
        presets.insert(key("antminer_s19j_pro", "BHB42821"), table(650));
        assert!(select_silicon_preset_table(&presets, Some("BHB99999")).is_none());
    }

    #[test]
    fn empty_tables_are_ignored() {
        let mut presets = HashMap::new();
        presets.insert(key("antminer_s19j_pro", "BHB42601"), Vec::new());
        assert!(select_silicon_preset_table(&presets, Some("BHB42601")).is_none());
    }

    #[test]
    fn apply_active_path_uses_per_chain_selector() {
        let src = include_str!("tuner.rs");
        assert!(
            src.contains("select_silicon_preset_table("),
            "apply_active_silicon_profile_targets must select per chain, not first-wins"
        );
        assert!(
            !src.contains("Pick the first non-empty preset table"),
            "W15-A first-table-wins comment must not remain as the live policy"
        );
    }
}
