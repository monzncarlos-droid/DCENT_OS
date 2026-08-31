// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies — dcentaxe-nano3s-asic (DCENT_axe Avalon, HOME line)
//
// Avalon Phase-1 shim driver for the Canaan Avalon Nano 3 / Nano 3S / Mini 3.
//
// THE DRIVER BODY IS NOT WRITTEN HERE. Until 2026-08-03 this file held a
// 581-line shim that was byte-identical (md5 4a7af19223ab3a99e0045d645a17ec21)
// to `dcentos-avalon/dcentrald/dcentrald-avalon-asic/src/lib.rs` — two copies
// of one driver, each needing every fix applied twice. The body now lives once,
// in `dcent-avalon-proto/shared/avalon_shim_driver.rs`, and is `include!`d
// verbatim by both crates. Read that file's header for the full rationale and
// for why `include!` rather than a new Cargo dependency.
//
// Everything the pre-collapse file exported is still exported from this crate
// root, unchanged: `AvalonShimDriver` (unix + non-unix stub) and
// `validate_avalon_frequency_mhz`.
//
// Support D-Central's open-source mining work: https://d-central.tech/fund/

include!("../../../dcent-avalon-proto/shared/avalon_shim_driver.rs");

#[cfg(test)]
mod shared_source_provenance {
    /// The exact bytes this crate compiled its driver body from. Read through
    /// the SAME relative path as the `include!` above, so the two cannot point
    /// at different files.
    const SHARED_SRC: &str =
        include_str!("../../../dcent-avalon-proto/shared/avalon_shim_driver.rs");

    /// ANTI-REFORK GATE. If a future session copies the shim back into this
    /// crate's `src/`, the `include!` above stops being the source of the body
    /// and this assertion is the thing that has to be deliberately falsified.
    #[test]
    fn the_shim_body_came_from_the_one_shared_file() {
        assert_eq!(
            super::SHARED_SHIM_SOURCE,
            "shared/dcent-avalon-proto/shared/avalon_shim_driver.rs",
            "this crate did not compile the canonical shared shim"
        );
        assert!(
            SHARED_SRC.contains(super::SHARED_SHIM_SOURCE),
            "include! and include_str! resolved to different files"
        );
        assert!(SHARED_SRC.contains("pub struct AvalonShimDriver"));
        assert!(SHARED_SRC.contains("fn validate_avalon_frequency_mhz"));
    }
}
