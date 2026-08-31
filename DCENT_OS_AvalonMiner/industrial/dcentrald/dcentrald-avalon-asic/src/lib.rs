// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies — dcentrald-avalon-asic (DCENT_OS Avalon, INDUSTRIAL line)
//
// Avalon Phase-1 shim driver for the Canaan industrial line (Avalon Q +
// A14xx / A15xx / A16xx).
//
// THE DRIVER BODY IS NOT WRITTEN HERE. Until 2026-08-03 this file held a
// 581-line shim that was byte-identical (md5 4a7af19223ab3a99e0045d645a17ec21)
// to `dcentaxe-avalon/dcentaxe-nano3s-asic/src/lib.rs` — two copies of one
// driver, each needing every fix applied twice. The body now lives once, in
// `dcent-avalon-proto/shared/avalon_shim_driver.rs`, and is `include!`d
// verbatim by both crates. Read that file's header for the full rationale and
// for why `include!` rather than a new Cargo dependency.
//
// Everything the pre-collapse file exported is still exported from this crate
// root, unchanged: `AvalonShimDriver` (unix + non-unix stub) and
// `validate_avalon_frequency_mhz`.
//
// NOTE ON SCOPE. This crate's Cargo description mentions multi-hashboard
// support via a TCA9546A I2C mux. No such code has ever existed here — the
// pre-collapse file was a verbatim copy of the single-chain home shim, mux and
// all still deferred. Collapsing the copy does not change that; when the mux
// lands it belongs in this crate, BESIDE the `include!`, not inside the shared
// body.
//
// Support D-Central's open-source mining work: https://d-central.tech/fund/

include!("../../../../dcent-avalon-proto/shared/avalon_shim_driver.rs");

// Wave 3.2 (2026-08-05): the industrial-only multi-hashboard TCA9546A I2C mux —
// the deferred item this crate's header describes — landed BESIDE the `include!`,
// not inside the shared home-shim body. Pure logic layer (open-source-cited
// constants + tests); the live I2C wiring is the K230 industrial HAL's job.
pub mod hashboard_mux;

// Wave 3.2 (2026-08-05): K230 industrial chain-reset GPIO map (RO0..RO3) + chain
// UART baud, byte-exact from open-source Avalon_mm (gpio_dev.c / uart_pro.h).
// Pure constants; the K230 HAL drives them once bench-validated.
pub mod chain_io;

// Wave 3.2 (2026-08-05): K230 industrial PSU I2C command-register map (addr 0x2C,
// version/onoff/errcode/vout/iout/pout/set-vout), byte-exact from open-source
// Avalon_mm power_i2c.h. Pure register codes; energize/set-voltage stay gated.
pub mod psu;

// Round 15 (2026-08-07), axis 9: the CONTROL-BOARD thermal axis — per-board NTC
// descriptors (A15_AC vs A15_HYDRO, which fit DIFFERENT thermistor parts), a
// fail-closed raw-ADC decode, and the evidenced trips. READ-ONLY telemetry:
// no fan actuator, no PID, no PSU write. `hashboard_mux.rs` already covers the
// per-hashboard MCU temperature registers; this covers everything else.
pub mod thermal;

#[cfg(test)]
mod shared_source_provenance {
    /// The exact bytes this crate compiled its driver body from. Read through
    /// the SAME relative path as the `include!` above, so the two cannot point
    /// at different files.
    const SHARED_SRC: &str =
        include_str!("../../../../dcent-avalon-proto/shared/avalon_shim_driver.rs");

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
