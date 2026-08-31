// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies — dcentrald (DCENT_OS Avalon, INDUSTRIAL line)
//
// THE BRIDGE BODY IS NOT WRITTEN HERE. Until 2026-08-03 this file held a
// 51-line copy of the work bridge that was a BYTE-EXACT PREFIX of the home
// line's 244-line `dcentaxe-avalon/dcentaxe-nano3s/src/bridge.rs`: the same
// `avalon_work_to_job` and `reverse_32bit_words`, and then nothing. The home
// copy's `#[cfg(test)] mod tests` — seven tests pinning a transform that feeds
// every submitted share — was absent here, so this line shipped the transform
// unguarded.
//
// The body now lives once, in `dcent-avalon-proto/shared/avalon_bridge.rs`,
// and is `include!`d verbatim by both daemons. Read that file's header for the
// full rationale, including why `include!` rather than a new Cargo dependency,
// and why a plain `diff` hid the prefix relationship (CRLF here vs LF there).
//
// Everything the pre-collapse file exported is still exported, unchanged:
// `avalon_work_to_job`.
//
// Support D-Central's open-source mining work: https://d-central.tech/fund/

include!("../../../../dcent-avalon-proto/shared/avalon_bridge.rs");

#[cfg(test)]
mod shared_source_provenance {
    /// The exact bytes this crate compiled its bridge body from. Read through
    /// the SAME relative path as the `include!` above, so the two cannot point
    /// at different files.
    const SHARED_SRC: &str = include_str!("../../../../dcent-avalon-proto/shared/avalon_bridge.rs");

    /// ANTI-REFORK GATE. If a future session copies the bridge back into this
    /// crate's `src/`, the `include!` above stops being the source of the body
    /// and this assertion is the thing that has to be deliberately falsified.
    /// That is what re-created the untested-industrial-copy situation once
    /// already.
    #[test]
    fn the_bridge_body_came_from_the_one_shared_file() {
        assert_eq!(
            super::SHARED_BRIDGE_SOURCE,
            "shared/dcent-avalon-proto/shared/avalon_bridge.rs",
            "this crate did not compile the canonical shared bridge"
        );
        assert!(
            SHARED_SRC.contains(super::SHARED_BRIDGE_SOURCE),
            "include! and include_str! resolved to different files"
        );
        assert!(SHARED_SRC.contains("pub fn avalon_work_to_job"));
        assert!(SHARED_SRC.contains("fn reverse_32bit_words"));
    }

    /// The share-affecting guards must be present in what THIS crate compiled.
    /// This is the specific regression being closed: the industrial line
    /// previously had the transform with none of these.
    #[test]
    fn the_industrial_line_now_compiles_the_share_guards() {
        for guard in [
            "fn differs_from_full_byte_reversal",
            "fn roundtrip_is_its_own_inverse",
            "fn golden_word_order_reversed_byte_in_word_preserved",
            "fn single_nonzero_word_moves_to_opposite_end",
            "fn palindromic_word_layout_is_fixed_point",
            "fn all_zero_is_fixed_point",
            "fn avalon_work_to_job_reverses_prev_and_merkle_passes_through_rest",
        ] {
            assert!(
                SHARED_SRC.contains(guard),
                "share-affecting guard `{guard}` is missing from the shared bridge"
            );
        }
    }
}
