// SPDX-License-Identifier: GPL-3.0-or-later
//
// K230 industrial Platform impl. Phase 1 scaffold.
//
// Industrial K230 (Avalon Q + A14xx/A15xx/A16xx) shares the K230 SoC and the
// SysV-msgq + 268-byte mm_pkg IPC with the home line (Nano 3/3S/Mini 3) —
// per `AVALON_MM_K230_INDUSTRIAL_RE.md` §3 and `AVALON_NANO3S_REPO_MAP.md` §5.
//
// Industrial-specific pieces (covered in next plan):
//   - TCA9546A 4-channel I2C mux for per-hashboard MCU access
//   - Custom Avalon PSU register set (NOT PMBus — see §11 of the industrial RE)
//   - PID fan controller with shmoo-tuned setpoint
//   - V/F auto-adjust per silicon binning
//   - A15_AC vs A15_HYDRO board variant detection

use super::{BoardType, Platform};

#[derive(Debug)]
pub struct K230Industrial {
    // No state in Phase 1.
}

impl K230Industrial {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for K230Industrial {
    fn default() -> Self {
        Self::new()
    }
}

impl Platform for K230Industrial {
    fn board_type(&self) -> BoardType {
        BoardType::K230Industrial
    }

    fn description(&self) -> &'static str {
        "K230 RISC-V industrial Avalon (Avalon Q / A14xx / A15xx / A16xx)"
    }
}
