// SPDX-License-Identifier: GPL-3.0-or-later
//
// K210 industrial Platform stub.
//
// K210 industrial (A1346 / A1146 / A1066) runs FreeRTOS bare-metal in 8 MB
// of on-chip SRAM. Cannot host Linux. Cannot host this Rust daemon as-is.
// A real K210 port is a different firmware kernel entirely — `no_std`,
// panic-abort, bootable image with the K210 boot ROM header. The 2026-08-23
// operator decision activated that separate port under the evidence-bound
// gauntlet in `DCENT_OS_AvalonMiner/gauntlet/`; it must not be implemented
// by pretending this Linux daemon can execute on K210.
//
// This module exists to keep the Linux platform vocabulary complete and the
// dispatcher's match arms exhaustive. The active bare-metal implementation
// belongs in a separate workspace once boot/eFuse/flash evidence selects the
// exact packaging and recovery route.
//
//: all 8 K210
// industrial firmwares share the same OTP-fused AES key, so install path
// design will start from the unfused-eFuse / `aes_enable=0x00` plaintext
// AUP route.

use super::{BoardType, Platform};

#[derive(Debug)]
pub struct K210Industrial;

impl Platform for K210Industrial {
    fn board_type(&self) -> BoardType {
        BoardType::K210Industrial
    }

    fn description(&self) -> &'static str {
        "K210 RISC-V industrial Avalon — Linux-incompatible marker; active no_std port is separate"
    }
}
