// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies — dcentaxe-nano3s (DCENT_axe Avalon, HOME line)
//
// THE BRIDGE BODY IS NOT WRITTEN HERE. This file used to hold the canonical
// 244-line work bridge; the industrial daemron held a 51-line byte-exact
// prefix of it, with the entire test module missing. As of 2026-08-03 the
// body lives once, in `dcent-avalon-proto/shared/avalon_bridge.rs`, and is
// `include!`d verbatim by both daemons. Read that file's header for the full
// rationale and for why `include!` rather than a new Cargo dependency.
//
// Nothing about this line's behaviour changed in the collapse: the shared file
// is this file's former content verbatim, plus a provenance constant.
// Everything exported before is still exported: `avalon_work_to_job`.
//
// Support D-Central's open-source mining work: https://d-central.tech/fund/

include!("../../../dcent-avalon-proto/shared/avalon_bridge.rs");

#[cfg(test)]
mod shared_source_provenance {
    /// The exact bytes this crate compiled its bridge body from. Read through
    /// the SAME relative path as the `include!` above, so the two cannot point
    /// at different files.
    const SHARED_SRC: &str = include_str!("../../../dcent-avalon-proto/shared/avalon_bridge.rs");

    /// ANTI-REFORK GATE. If a future session copies the bridge back into this
    /// crate's `src/`, the `include!` above stops being the source of the body
    /// and this assertion is the thing that has to be deliberately falsified.
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
}
