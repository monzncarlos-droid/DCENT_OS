// SPDX-License-Identifier: GPL-3.0-or-later
//
// dcentrald-avalon-hal — K230 + K210 HAL for DCENT_OS Avalon industrial.
//
// Pattern mirrors `dcentos/dcentrald/dcentrald-hal/src/platform/mod.rs`
// (170 lines — Zynq + Amlogic + BeagleBone trait dispatcher) but for the
// RISC-V Avalon platforms.
//
// Phase 1 scaffold — `Platform` trait skeleton + K230 + K210 stub
// implementations. Real impls (TCA9546A I2C mux, per-hashboard MCU access,
// Avalon-spec PSU register set, PID fan controller, V/F auto-adjust) land in
// next plan after we confirm `cargo check` passes.
//
// for the
// industrial-specific HAL bits (TCA9546A mux, custom PSU regs, separate
// A15_AC vs A15_HYDRO board variants).

pub mod platform;

#[derive(Debug, thiserror::Error)]
pub enum HalError {
    #[error("platform unsupported on this host")]
    UnsupportedPlatform,

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("not yet implemented in Phase 1 scaffold")]
    Unimplemented,
}
