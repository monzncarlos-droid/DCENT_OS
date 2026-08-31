// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies — dcent-avalon-proto
//
// Canaan Avalon protocol primitives shared between:
//   - DCENT_axe Avalon (DCENT_OS_AvalonMiner/home/) — Nano 3/3S/Mini 3 home line
//   - DCENT_OS Avalon (DCENT_OS_AvalonMiner/) — A14xx/A15xx/A16xx/Avalon Q industrial
//
// Reverse-engineered from:
//   -  (BSD-2, safe to translate)
//   - / (BUSL-1.1 — RE notes only, no verbatim copy)
//   -  (Apache-2.0 Kaitai schema)
//
//   -  §5
//   -  §1-3
//   -  §1
//
// Modules:
//   mm_pkg   - 268-byte SysV-msgq packet (Linux little <-> RT-Smart big core IPC)
//   aup      — AUP firmware container parser/builder (K210 + K230 industrial)
//   ascset   — CGMiner port-4028 ascset command vocabulary (public + privileged)
//   board    — declarative Avalon industrial board registry (8 SKUs, 3 silicon
//              families). Describes hardware; deliberately cannot energize it.
//   nano3_profile - explicit identity-only non-S Nano 3 target profile
//   nano3_uart / nano3_uart_rx - non-S Nano 3 native UART receive codec,
//              bounded stream recovery, and structural nonce admission
//   nano3_uart_tx - pure, bounded held-binary-proven TX serialization plus
//              sealed offline share reconstruction; live TX/submission refused
//   nano3_uart_transcript - pure capture/replay validator for the proven init,
//              job, poll, and nonce exchanges; grants no live authority
//   transport — SysV msgq + Unix-domain transports (cfg(unix) only)
//
// Not a module: `shared/avalon_shim_driver.rs`. That file is the single
// canonical source of the Avalon `AsicDriver` shim, `include!`d verbatim by
// dcentos-avalon's and dcentaxe-avalon's `*-asic` crates. It is never compiled
// as part of this crate — see its own header.

pub mod ascset;
pub mod aup;
pub mod board;
pub mod mm_pkg;
pub mod mm_work;
pub mod nano3_profile;
pub mod nano3_uart;
pub mod nano3_uart_rx;
#[cfg(feature = "nano3-native-tx-research")]
pub mod nano3_uart_transcript;
#[cfg(feature = "nano3-native-tx-research")]
pub mod nano3_uart_tx;

#[cfg(unix)]
pub mod transport;

/// Crate-wide error type. Per-module errors flatten into this for the public API.
#[derive(Debug, thiserror::Error)]
pub enum AvalonProtoError {
    #[error("mm_pkg: {0}")]
    MmPkg(#[from] mm_pkg::MmPkgError),

    #[error("aup: {0}")]
    Aup(#[from] aup::AupError),

    #[error("ascset: {0}")]
    Ascset(#[from] ascset::AscsetError),

    #[cfg(unix)]
    #[error("transport: {0}")]
    Transport(#[from] transport::TransportError),
}
