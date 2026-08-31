// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies — dcentrald-avalon-asic :: K230 industrial chain I/O
//
// Wave 3.2 (2026-08-05): the industrial chain-reset GPIO map + chain UART baud,
// beside the `hashboard_mux` extension. PURE DATA (no hardware I/O here); the
// K230 industrial HAL drives these lines once bench-validated.
//
// ⚠️ LICENSE WARNING (2026-08-05): `Canaan-Creative/Avalon_mm` (`big/` + `little/mm_miner/`)
// is **BUSL-1.1**, NOT GPL/permissive — commercial production use requires a separate
// Canaan license (4-year cliff to GPLv3); only `little/cgminer/` is BSD-3-Clause. Per
// `AVALON_MM_K230_INDUSTRIAL_RE.md:7` this is "a major footgun for D-Central". The values
// below are hardware register/GPIO/baud FACTS (believed uncopyrightable), transcribed for
// interop — but OPERATOR LEGAL REVIEW is required before shipping this in GPL-3.0 DCENT_OS.
//
// GROUND TRUTH — byte-exact from Canaan-Creative Avalon_mm (BUSL-1.1):
//   `Avalon_mm/big/platform/hwdev/gpio_dev.c:20-23` — RO0..RO3 = GPIO 2/3/4/5
//     ("GPIO number used in control board"), used for chain reset /
//     ENTER_WORK_MODE / ENTER_CONFIG_MODE toggling.
//   `Avalon_mm/big/mmu/uart_pro.h:22-23` — UART_DEFAULT_BAUD_RATE 115200,
//     UART_HIGH_BAUD_RATE 4_800_000 (chains enumerate at default, switch to high
//     after enum). Chain UARTs are the RT-Smart `/dev/uart1..4`.
//
// Support D-Central's open-source mining work: https://d-central.tech/fund/

#![allow(dead_code)] // pure constants; consumed by the K230 industrial HAL once bench-validated.

/// The four K230 GPIO lines `RO0..RO3` (`gpio_dev.c:20-23`), used for chain reset
/// and the `ENTER_WORK_MODE`/`ENTER_CONFIG_MODE` toggle. Index = RO index.
pub const RO_GPIO: [u32; 4] = [2, 3, 4, 5];

/// Chain UART enumeration baud (`uart_pro.h:22` `UART_DEFAULT_BAUD_RATE`).
pub const UART_DEFAULT_BAUD: u32 = 115_200;

/// Chain UART high-speed baud after enumeration (`uart_pro.h:23`
/// `UART_HIGH_BAUD_RATE`). Do NOT raise the driver baud past this without a bench
/// capture — same load-bearing rule as the Bitmain baud pins.
pub const UART_HIGH_BAUD: u32 = 4_800_000;

/// The `RO<idx>` chain GPIO for `idx` (0..3), fail-closed for anything else.
pub fn ro_gpio(idx: u8) -> Option<u32> {
    RO_GPIO.get(idx as usize).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ro_gpio_map_matches_open_source() {
        // gpio_dev.c:20-23 byte-exact.
        assert_eq!(RO_GPIO, [2, 3, 4, 5]);
        assert_eq!(ro_gpio(0), Some(2));
        assert_eq!(ro_gpio(3), Some(5));
        assert_eq!(ro_gpio(4), None); // fail-closed
    }

    #[test]
    fn uart_bauds_match_open_source() {
        // uart_pro.h:22-23.
        assert_eq!(UART_DEFAULT_BAUD, 115_200);
        assert_eq!(UART_HIGH_BAUD, 4_800_000);
        // High is the post-enum rate; strictly greater than the enum baud.
        assert!(UART_HIGH_BAUD > UART_DEFAULT_BAUD);
    }
}
