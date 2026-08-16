//! CV1835 platform implementation — Sophgo CV1835 SoC, BHB42xxx S19j Pro
//! variant from the DCENT_OS dev-kit (W2 RE deliverable).
//!
//! ## Hardware ground truth
//!
//! Source files used to pin every constant in this module:
//! - `DCENT_OS_DEVELOPMENT_KIT_FROMRE1/.../SOURCE_BOARD/s19j_init.{h,c}`
//!   — 594-LOC orchestrator that owns the cold-boot phase order.
//! - `DCENT_OS_DEVELOPMENT_KIT_FROMRE1/.../ROOTFS_CV1835/CVCtrl_rootfs/etc/init.d/S37bitmainer_setup`
//!   — canonical pinmux + sysfs export script (encoded verbatim in
//!   [`super::cvitek_pinmux::CV1835_PINMUX_TABLE`]).
//! - `DCENT_OS_DEVELOPMENT_KIT_FROMRE1/.../DOCS/multi_platform_master.md`
//!   §4 (Cvitek CV1835 Control Board) — GPIO, UART, FPGA, kernel modules.
//! - `DCENT_OS_DEVELOPMENT_KIT_FROMRE1/.../DCENT_OS_
//!   §4 + §11 — CV1835 init details, rootfs config files.
//!
//! ## Architecture summary
//!
//! - **SoC**: Sophgo CV1835 (aarch64 quad Cortex-A53, 25 MHz XTAL).
//! - **Hashboards**: 4× BHB42xxx with BM1362 chips. PIC1704 voltage
//!   controller at I²C `/dev/i2c-0` 0x20 (single-controller bus, all
//!   four hashboards share the same controller — bonded).
//! - **Chain UARTs**: 4× DesignWare 16550A at MMIO 0x0500_D000 +
//!   chain×0x1000 (`/dev/ttyS1` through `/dev/ttyS4`). Selected by
//!   [`crate::serial::select_uart_table_cv1835`] from W10.3.
//! - **Fans**: PWM via `/sys/class/pwm/pwmchip8` (output) +
//!   `/sys/class/pwm/pwmchip12` (capture for tach). Period 1 KHz
//!   (1_000_000 ns), 4 fans (FAN1-4: 2 front + 2 rear).
//! - **GPIO**: sysfs `/sys/class/gpio/gpio{406,412,427,429,431,433,
//!   434,435,447,459,461}/`. Same numbering as the dev-kit
//!   `s19j_init.h` constants.
//! - **PSU**: APW121215a-class on the same `/dev/i2c-0`, gated by
//!   PWR_EN GPIO 412 (analogous to am2's PWR_CONTROL gate at gpio907).
//!
//! ## Voltage controller routing
//!
//! The retained classifier can compare the canonical `CVCtrl_BHB42XXX`
//! subtype with an I²C 0x20 probe. No admitted daemon path calls it. A future
//! runtime proposal must treat agreement as evidence for PIC1704 selection and
//! disagreement as refusal; it must not silently fall back to another mutating
//! controller path.
//!
//! ## Single-I²C-owner architecture
//!
//! The CV1835 runtime lane follows the AM2 SINGLE-I2C-OWNER rule: one process
//! owns `/dev/i2c-0`, and PIC1704, APW PSU, and LM75A traffic shares one
//! `I2cServiceHandle`. The retained service helper installs the same EEPROM
//! write denylist as Amlogic.
//!
//! ## Live verification status
//!
//! **Default = fail-closed (NOT IMPLEMENTED); Experimental opt-in = operator-only.**
//! By default no CV1835 runtime or artifact lane is admitted — the constructor
//! is a non-mutating refusal (unchanged shipped behavior). Numeric register
//! values, GPIO numbers, and sysfs paths are retained from the dev-kit
//! reverse-engineering corpus; the bring-up is R4-CONFIRMED but **bench-unproven**.
//! As of 2026-08-05, the operator explicitly authorized a **default-OFF**
//! Experimental opt-in ([`CV1835_EXPERIMENTAL_RUNTIME_ENV`]) that promotes this
//! evidence into a live runtime lane for bench bring-up. The earlier
//! "no environment override can promote this evidence" stance is superseded by
//! that authorization; the `board_desc` runtime status stays
//! `EvidenceRetainedNotImplemented` (the product-facing default is unchanged).
//!
//! ## The Antminer L9 `godminer` binary — what it does and does NOT give us
//!
//! Round 15 flagged the L9 stock miner (`usr/bin/godminer`, sha256
//! `7b088dcb…c038487`, ARM 32-bit armhf, `.symtab` stripped but **1,653 dynamic
//! symbols retained**) as carrying "a working Bitmain `cv183x_*` HAL relevant to
//! our unimplemented `CvitekPlatform`". **Round 16 B3 measured that claim and it
//! is an overclaim.** Recorded here so nobody re-chases it:
//!
//! - `readelf --dyn-syms` on `godminer` matches **zero** symbols containing
//!   `cv183`. The entire `cv183x` evidence is **10 source-file *path strings***
//!   from the Jenkins build root
//!   (`…/backend/device/hal/platform/cv183x/cv183x_{common,fan,gpio,i2c,
//!   i2c_sim,iic,lcd,pwm,uart,ui}.c`). Those functions are file-local
//!   (`static`), so they are absent from `.dynsym` and were removed with
//!   `.symtab`.
//! - So the L9 binary yields a **capability inventory** — Bitmain's CVitek HAL
//!   abstracts GPIO, I²C (two implementations plus a simulator), UART, PWM/fan,
//!   LCD/UI, and a common layer; thermal is *not* a cv183x file but the
//!   product-independent `backend/device/hal/tsensor/bitmain_tsensor.c` — and
//!   **no addresses, no register values, no function signatures.** Every
//!   numeric CVitek constant in this module still comes from our own dev-kit
//!   RE, not from `godminer`.
//! - **Trap:** `backend/device/hal/drv_pic/pic_1704.c` *is* present in the L9
//!   binary, and `pic1704_*` functions *are* in its dynsym. That does **not**
//!   mean the L9 uses a PIC1704 — its `topol.conf` says `"pic_mcu_en": false`.
//!   `godminer` is Bitmain's **unified multi-product** miner, so the presence of
//!   a driver is evidence about the *binary*, never about the *product*.
//!
//! The one genuinely load-bearing thing the L9 drop gave this module is the
//! independent corroboration of [`GPIO_PWR_EN`] — see that constant's docs.

// clippy/dead_code: CV1835 (CViTek) is an EVIDENCE-RETAINED platform port. The
// module is a complete RE'd bring-up path with no live fleet unit, so most of it
// has no production caller yet and every item reads as dead code. It is retained
// deliberately — the repo models exactly this state as
// `RuntimeStatus::EvidenceRetainedNotImplemented`. Deleting it to satisfy the
// lint would destroy real reverse-engineering work; wiring it to satisfy the lint
// would promote an unproven platform. Allowed here until a bench unit lands.
#![allow(dead_code)]
// Same rationale: the retained bring-up path imports the symbols it will use
// once wired; dropping the imports now would just have to be undone.
#![allow(unused_imports)]
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use super::config::{ChainTransport, PlatformConfig, VoltageControllerKind};
use super::subtype::{classify_with_probe, read_subtype};
use super::{BoardType, ChainAccess, FanAccess, GpioAccess, Platform};
use crate::i2c::{spawn_i2c_service_no_register_touch_with_denylist, I2cBus, I2cServiceHandle};
use crate::serial::DevmemUart;
use crate::{HalError, Result};

// Retain the reconstructed cold-boot symbols inside this crate for tests and
// future evidence comparison. The crate-private module and refused constructor
// expose no production/operator route. The inferred register phase remains
// gated behind `DCENT_CV1835_ACCEPT_INFERRED_SOC_REGS=1` (W15.A3
// rename —  Q6 confirmed CV1835 has NO FPGA; the deprecated
// `DCENT_CV1835_ACCEPT_INFERRED_FPGA` env-var name is still accepted as
// a silent backwards-compat alias).
pub use super::cvitek_cold_boot::{
    bm1362_broadcast_write_frame, bm1362_soft_reset_frame, cv1835_cold_boot as cold_boot,
    ColdBootOpts, Pic1704ColdBoot, ACCEPT_INFERRED_FPGA_ENV, ACCEPT_INFERRED_FPGA_ENV_DEPRECATED,
    ACCEPT_INFERRED_SOC_REGS_ENV, CHAIN_UART_BAUD_HZ, MISCCTRL_VALUE,
};

/// PIC1704 I²C address. Mirrored here from
/// `dcentrald_asic::pic1704::PIC1704_I2C_ADDR` to keep `dcentrald-hal`
/// free of an asic-crate dep (the asic crate already depends on hal —
/// importing the other direction creates a circular dependency).
/// The two constants are pinned to the same value (0x20) by tests in
/// `dcentrald-asic::pic1704::protocol`.
pub const CVITEK_PIC1704_I2C_ADDR: u8 = 0x20;

// ─── CV1835 hardware constants — verified against dev-kit RE ───

/// I²C bus carrying the BHB42XXX hashboard PIC1704 controllers on CV1835.
/// Single bus 0 (matches AM335x BB and Amlogic conventions).
pub const CVITEK_PIC1704_I2C_BUS: u8 = 0;

/// Number of hash chains the CV1835 S19j Pro variant exposes (BM1362 × 4).
const CV1835_CHAIN_COUNT: u8 = 4;

/// Per-chain UART device paths. Maps to the W10.3 CV1835 MMIO table at
/// 0x0500_D000 + chain×0x1000 (chain 0 → ttyS1, chain 3 → ttyS4).
const CV1835_CHAIN_UARTS: [&str; CV1835_CHAIN_COUNT as usize] = [
    "/dev/ttyS1", // chain 0 (BANK34_L9P_RXD1i)
    "/dev/ttyS2", // chain 1 (BANK34_L9P_RXD2i)
    "/dev/ttyS3", // chain 2 (BANK34_L9P_RXD3i, VI_DATA[21] mux)
    "/dev/ttyS4", // chain 3 (BANK34_L9P_RXD4i, UART1_CTS mux)
];

/// Initial chain UART baud (115200, BM1362 enumeration baud — same as
/// every other Bitmain ASIC platform).
const CV1835_CHAIN_INITIAL_BAUD: u32 = 115_200;

/// PWM period in nanoseconds — 1 KHz fan output (S37 line 93/99 program
/// `period = 1000000` for `pwmchip8/pwm0..1`). The same period applies
/// to the tach `pwmchip12` channels.
const CV1835_FAN_PWM_PERIOD_NS: u32 = 1_000_000;

/// Number of fans on the BHB42xxx S19j Pro CV variant. FAN1-FAN4 (2
/// front rotor + 2 rear rotor) per the S37 commentary.
const CV1835_FAN_COUNT: u8 = 4;

/// PWM output sysfs paths (one entry per fan rotor pair).
/// Front rotor pair (FAN1+FAN3) shares `pwmchip8/pwm1`; rear rotor pair
/// (FAN2+FAN4) shares `pwmchip8/pwm0`. The duty_cycle write maps a
/// PWM percentage 0..100 to nanoseconds 0..PERIOD.
const CV1835_FRONT_PWM_DUTY: &str = "/sys/class/pwm/pwmchip8/pwm1/duty_cycle";
const CV1835_REAR_PWM_DUTY: &str = "/sys/class/pwm/pwmchip8/pwm0/duty_cycle";

/// Per-fan tach capture sysfs paths. CV1835's PWM in capture mode
/// reports period+duty in `/sys/class/pwm/pwmchip12/pwmN/capture` as
/// two whitespace-separated nanosecond values. RPM derivation:
///
/// ```text
///   tach pulse_period_ns = first u64 in `capture`
///   pulses_per_rev = 2 (industry-standard 4-pin BLDC fan)
///   pulse_freq_hz = 1e9 / pulse_period_ns
///   rpm = pulse_freq_hz * 60 / pulses_per_rev
///       = 30 * 1e9 / pulse_period_ns
/// ```
///
/// On a 3000 RPM fan this yields ~10 ms pulse_period — well within
/// `pwmchip12`'s capture range. Per-fan layout from S37 lines 79-84:
/// FAN1 → SPEED1 (pwm13 → pwmchip12/pwm3), FAN2 → SPEED3 (pwm15 →
/// pwmchip12/pwm0)… BUT pwmchip12 actually exposes the four tach pins
/// in linear order pwm0..pwm3 mapped to FAN_INDEX 0..3 because the
/// `export` writes go 0/1/2/3 sequentially.
const CV1835_FAN_TACH_CAPTURE: [&str; CV1835_FAN_COUNT as usize] = [
    "/sys/class/pwm/pwmchip12/pwm0/capture", // FAN1 (SPEED1)
    "/sys/class/pwm/pwmchip12/pwm1/capture", // FAN2 (SPEED3)
    "/sys/class/pwm/pwmchip12/pwm2/capture", // FAN3 (SPEED2)
    "/sys/class/pwm/pwmchip12/pwm3/capture", // FAN4 (SPEED4)
];

/// Industry-standard 4-pin BLDC fan pulses-per-revolution.
const CV1835_FAN_PULSES_PER_REV: u32 = 2;

/// Fan PWM ceiling for home-mining mode.,
/// , and : the
/// HAL must clamp ANY caller's PWM request to ≤ 30. Operator override
/// to higher modes is handled at a layer above the HAL (the thermal
/// controller / FanMode policy), NOT in `set_speed`.
const CV1835_FAN_PWM_HOME_CAP: u8 = 30;

/// EEPROM I²C addresses on CV1835 hashboards. Same convention as am2
/// and am3-aml: AT24Cxx-class identity store at 0x50 base. Per
/// : writes are blocked at
/// the HAL layer, reads still work. CV1835's BHB42xxx hashboards
/// carry the same factory identity bytes (model/serial/freq profile)
/// the .74 incident proved are unreconstructable once corrupted.
pub const CV1835_EEPROM_DENYLIST: [u8; 8] = [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57];

// ─── GPIO numbering — verbatim from s19j_init.h ───

/// PSU enable GPIO on the CVitek carrier.
///
/// # Round 16 B3 — now DOUBLE-SOURCED (was single-source RE)
///
/// Originally taken only from the dev-kit RE (`s19j_init.h` +
/// `S37bitmainer_setup`). It is now independently corroborated by an
/// **authentic Bitmain stock artifact for a different product on the same
/// CV183x carrier family**: the Antminer L9's `etc/topol.conf`
/// (`FR-1.19(260302-L9).bmu` sha256 `2af05a34…05c3aa827` →
/// `00_Antminer_L9_CVCtrl_L9` → `BOOT.bin` → plaintext rootfs) states:
///
/// ```text
/// "processor": { "type": "CV183x" },
/// "power": { "type": "APW17", "i2c_addr": 16, "gpio": 412 }
/// ```
///
/// Two independent sources — our RE of the CV1835 S19j Pro carrier, and
/// Bitmain's own shipped config for the CV183x L9 — agree that the PSU-enable
/// line on this carrier family is GPIO **412**. That materially reduces the
/// chance the value is a transcription error.
///
/// ⚠ **What this does NOT establish.** The L9 (BM1491, Scrypt, 3 chains, NoPic,
/// `isl68127`/`mps2973` PMICs) is a *different board* from the CV1835 S19j Pro
/// (BM1362, SHA-256, 4 chains, PIC1704 @ 0x20). Agreement on a carrier-level
/// GPIO number is corroboration of the **numbering convention**, not proof that
/// the two boards wire PWR_EN identically. This remains bench-unproven and the
/// platform stays fail-closed by default.
///
/// Pinned by `gpio_pwr_en_is_412_double_sourced`.
const GPIO_PWR_EN: u32 = 412;
const GPIO_ASIC_RST0: u32 = 427;
const GPIO_ASIC_RST1: u32 = 429;
const GPIO_ASIC_RST2: u32 = 431;
const GPIO_ASIC_RST3: u32 = 433;
const GPIO_LED_RED: u32 = 434;
const GPIO_LED_GREEN: u32 = 435;
const GPIO_RECOVERY_BTN: u32 = 447;
const GPIO_IP_GET: u32 = 406;
const GPIO_I2C_SCL: u32 = 459;
const GPIO_I2C_SDA: u32 = 461;

/// Per-chain ASIC reset GPIO order (same indexing as `s19j_init.c`
/// `asic_rst_gpio[]`).
const GPIO_ASIC_RST: [u32; CV1835_CHAIN_COUNT as usize] = [
    GPIO_ASIC_RST0,
    GPIO_ASIC_RST1,
    GPIO_ASIC_RST2,
    GPIO_ASIC_RST3,
];

// ─── Evidence-only helpers (no admitted daemon caller) ───

/// Reconstruct the candidate voltage-controller kind for CV1835 evidence.
///
/// Reads `/etc/subtype` and runs `classify_with_probe` against
/// `/dev/i2c-{CVITEK_PIC1704_I2C_BUS}`. Returns `Pic1704` only when
/// both signals agree.
pub fn cvitek_voltage_controller() -> VoltageControllerKind {
    let subtype = read_subtype();
    let kind = classify_with_probe(subtype.as_deref(), CVITEK_PIC1704_I2C_BUS);
    tracing::info!(
        carrier = "CV1835",
        subtype = %subtype.as_deref().unwrap_or("<missing>"),
        bus = CVITEK_PIC1704_I2C_BUS,
        kind = kind.as_str(),
        "CV1835 voltage controller classification"
    );
    kind
}

/// Spawn the kernel-fd-only I²C service for `/dev/i2c-0` with the CV1835
/// hashboard EEPROM write-deny range pre-registered.
///
/// Parity helper retained for tests and a future reviewed runtime proposal.
/// No production daemon path calls it. Any future I²C owner must preserve
/// this colocated EEPROM denylist rather than opening the bus directly.
pub fn spawn_cvitek_protected_i2c0_service() -> std::io::Result<I2cServiceHandle> {
    let denylist: Vec<u8> = CV1835_EEPROM_DENYLIST.to_vec();
    let handle =
        spawn_i2c_service_no_register_touch_with_denylist(CVITEK_PIC1704_I2C_BUS, denylist)?;
    tracing::info!(
        bus = CVITEK_PIC1704_I2C_BUS,
        denylist = ?CV1835_EEPROM_DENYLIST
            .iter()
            .map(|a| format!("0x{:02X}", a))
            .collect::<Vec<_>>(),
        "CV1835 I2C service spawned with hashboard EEPROM write-deny"
    );
    Ok(handle)
}

// ─── CViTekPlatform ───

/// CV1835 control-board platform implementation.
pub struct CViTekPlatform {
    config: PlatformConfig,
}

/// Operator-authorized (2026-08-05) default-OFF opt-in that admits the
/// Experimental CV1835 runtime lane.
///
/// Unset (the shipped default) = fail-closed: `CViTekPlatform::new()` refuses,
/// exactly as before. Set to `"1"` to let an operator run the R4-CONFIRMED
/// bring-up (`cvitek_cold_boot` Phases 1-5 + [`super::cvitek_cold_boot::CV1835_STOCK_PINMUX_REPLAY`])
/// on a real — but **bench-unproven** — CV1835 unit. The fail-safe envelope
/// (mining-path watchdog, PWM-30 fan cap on the `SysfsPwm` fan, EEPROM
/// `0x50-0x57` write-denylist, and the FPGA dead-path staying gated off — CV1835
/// has no FPGA) is enforced by the daemon mining lifecycle. Rationale + review
/// scope: .
pub const CV1835_EXPERIMENTAL_RUNTIME_ENV: &str = "DCENT_CV1835_EXPERIMENTAL_RUNTIME";

/// Pure admission gate for [`CV1835_EXPERIMENTAL_RUNTIME_ENV`] — `true` only for
/// the exact opt-in value `"1"`. Extracted so the decision production passes is
/// unit-testable without mutating process env (any other value, including
/// `"0"`, `"true"`, empty, or unset, is fail-closed).
pub(crate) fn cv1835_experimental_opt_in_enabled(raw: Option<&str>) -> bool {
    raw == Some("1")
}

impl CViTekPlatform {
    /// Construct the CV1835 platform. Fail-closed by default; the
    /// operator-authorized Experimental lane is admitted only via
    /// [`CV1835_EXPERIMENTAL_RUNTIME_ENV`].
    ///
    /// **Default (env unset):** refuses, exactly as the historical fail-closed
    /// product decision (`RuntimeStatus::EvidenceRetainedNotImplemented` on the
    /// `cv1835-s19jpro` `BoardDesc` row — unchanged; the shipped default still
    /// does not run CV1835). It is NOT the Amlogic routing refusal
    /// (`RuntimeStatus::SpecialisedLifecycle`), which mines via another lane.
    ///
    /// **`DCENT_CV1835_EXPERIMENTAL_RUNTIME=1` (operator opt-in, 2026-08-05):**
    /// constructs the platform. The bring-up sequence is R4-CONFIRMED and the
    /// `Platform` trait is fully implemented, but the lane is **unproven on
    /// bench** — the operator explicitly authorized admitting it behind this
    /// default-off gate (the earlier "must not honor an environment override"
    /// stance is superseded by that authorization). Construction itself does no
    /// hardware I/O. Fail-safe envelope (defense-in-depth): the **PWM-30 fan cap**
    /// (`CViTekFan::set_speed` clamp) and the **EEPROM `0x50-0x57` write-denylist**
    /// (`open_i2c` / the protected I²C service) are enforced **in this HAL itself**,
    /// independent of the daemon; the **watchdog + PSU guard** are enforced by the
    /// daemon mining lifecycle; the FPGA dead-path stays gated off (no FPGA on
    /// CV1835). See `dcentrald-common::board_desc`,
    /// `dcent_schema::hardware::RuntimeStatus`, and the 1 evidence doc.
    pub fn new() -> Result<Self> {
        if cv1835_experimental_opt_in_enabled(
            std::env::var(CV1835_EXPERIMENTAL_RUNTIME_ENV)
                .ok()
                .as_deref(),
        ) {
            tracing::warn!(
                target: "cvitek",
                env = CV1835_EXPERIMENTAL_RUNTIME_ENV,
                "CV1835 EXPERIMENTAL runtime lane admitted (operator opt-in) — UNPROVEN on bench; fail-safe envelope enforced by the mining lifecycle"
            );
            return Ok(Self {
                config: Self::cv1835_s19j_default_config(),
            });
        }
        Err(HalError::Platform(
            "CV1835 runtime NOT IMPLEMENTED by default: reverse-engineered bring-up is retained and R4-CONFIRMED, but the runtime lane is unproven on bench. Set DCENT_CV1835_EXPERIMENTAL_RUNTIME=1 to admit the operator-authorized Experimental lane."
                .to_string(),
        ))
    }

    /// Build with explicit config (test-only). Skips signature, pinmux,
    /// and UART-table selection — call sites that use this are inside
    /// host-test cfg blocks.
    #[cfg(test)]
    fn with_config(config: PlatformConfig) -> Self {
        Self { config }
    }

    /// Construct the canonical CV1835 S19j Pro platform config. 4 BHB42xxx
    /// chains, /dev/ttyS1-4, dsPIC33EP fallback voltage controller (gets
    /// retained as Pic1704 classification evidence for a future runtime lane).
    fn cv1835_s19j_default_config() -> PlatformConfig {
        use super::config::{
            Architecture, ChainConfig, FanConfig, FanMethod, PicType, VoltageControl,
        };

        let mut chains = Vec::with_capacity(CV1835_CHAIN_COUNT as usize);
        for chain_id in 0..CV1835_CHAIN_COUNT {
            chains.push(ChainConfig {
                chain_id,
                transport: ChainTransport::Serial {
                    device: CV1835_CHAIN_UARTS[chain_id as usize].to_string(),
                    baud: CV1835_CHAIN_INITIAL_BAUD,
                },
                pic_address: Some(CVITEK_PIC1704_I2C_ADDR),
                i2c_bus: CVITEK_PIC1704_I2C_BUS,
                plug_detect_gpio: None,
                enable_gpio: Some(GPIO_ASIC_RST[chain_id as usize]),
            });
        }

        PlatformConfig {
            name: "Antminer S19j Pro (CV1835 BHB42XXX)".to_string(),
            chains,
            fan: FanConfig {
                method: FanMethod::SysfsPwm {
                    hwmon_path: "/sys/class/pwm/pwmchip8".to_string(),
                    pwm_channel: 0,
                },
                fan_count: CV1835_FAN_COUNT,
            },
            has_pic: true,
            // BHB42xxx defaults to dsPIC at the static evidence layer. A future
            // admitted runtime lane may promote it only after subtype + 0x20
            // ACK classification passes.
            pic_type: PicType::DsPic33EP16GS202,
            voltage_control: VoltageControl::DsPic,
            has_xadc: false,
            arch: Architecture::Aarch64,
            voltage_controller: VoltageControllerKind::Dspic33Ep,
        }
    }

    /// Detect a Sophgo CV1835 hardware signature without panicking on a
    /// non-Linux host.
    fn has_cv1835_signature() -> bool {
        #[cfg(target_os = "linux")]
        {
            // /proc/device-tree/model is the most reliable source — DT
            // emit "Sophgo CV1835 ..." for both stock and DCENT_OS images.
            if let Ok(model) = fs::read_to_string("/proc/device-tree/model") {
                let lower = model.to_ascii_lowercase();
                if lower.contains("cv1835") || lower.contains("sophgo") || lower.contains("cvctrl")
                {
                    return true;
                }
            }
            // Fallback: /sys/firmware/devicetree/base/compatible carries
            // the kernel's compat string list (NUL-separated).
            if let Ok(compat) = fs::read("/sys/firmware/devicetree/base/compatible") {
                for entry in compat.split(|b| *b == 0) {
                    if let Ok(s) = std::str::from_utf8(entry) {
                        let lower = s.to_ascii_lowercase();
                        if lower.contains("cv1835") || lower.contains("sophgo") {
                            return true;
                        }
                    }
                }
            }
            false
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    // ─── Public accessors for hardware-constants assertion in tests + tooling ───
    //
    // Note: `Pic1704Service` construction lives in the daemon crate
    // (`dcentrald::daemon` / hybrid mining path) rather than here.
    // `dcentrald-asic` already depends on `dcentrald-hal`, so importing
    // the asic crate from here would form a circular dependency. The
    // daemon code calls
    //
    //   use dcentrald_asic::pic1704::service::platforms::Cv1835S19jPro;
    //   use dcentrald_asic::pic1704::Pic1704Service;
    //   let pic = Pic1704Service::new(handle, CVITEK_PIC1704_I2C_ADDR,
    //                                  Cv1835S19jPro);
    //
    // when `voltage_controller() == Pic1704`. The sealed-trait gate in
    // `dcentrald-asic::pic1704::service::Pic1704Authorized` is the
    // platform-isolation guarantee.

    pub const fn chain_uarts() -> [&'static str; CV1835_CHAIN_COUNT as usize] {
        CV1835_CHAIN_UARTS
    }

    pub const fn chain_reset_gpios() -> [u32; CV1835_CHAIN_COUNT as usize] {
        GPIO_ASIC_RST
    }

    pub const fn psu_enable_gpio() -> u32 {
        GPIO_PWR_EN
    }

    pub const fn led_gpios() -> (u32, u32) {
        (GPIO_LED_GREEN, GPIO_LED_RED)
    }

    pub const fn recovery_gpio() -> u32 {
        GPIO_RECOVERY_BTN
    }

    pub const fn ip_get_gpio() -> u32 {
        GPIO_IP_GET
    }

    pub const fn i2c_pinmux_gpios() -> (u32, u32) {
        (GPIO_I2C_SCL, GPIO_I2C_SDA)
    }

    pub const fn i2c_bus_number() -> u8 {
        CVITEK_PIC1704_I2C_BUS
    }

    pub const fn fan_pwm_period_ns() -> u32 {
        CV1835_FAN_PWM_PERIOD_NS
    }

    pub const fn fan_count() -> u8 {
        CV1835_FAN_COUNT
    }

    pub const fn psu_gate_spec() -> &'static str {
        // Symbol used by `Apw121215a::with_psu_gate_spec` to identify the
        // PWR_EN line. The `gpio:` prefix matches the `PsuGpioGate::assert`
        // numeric-form parser; the daemon hands this string to the PSU
        // builder per W10.4.
        "gpio:412"
    }
}

impl Platform for CViTekPlatform {
    fn board_type(&self) -> BoardType {
        BoardType::CVitek
    }

    fn chain_count(&self) -> u8 {
        // CV1835 S19j Pro has exactly 4 chains. We pin the constant rather
        // than read from config so an accidental config drift can't change
        // the chain count out from under live mining code.
        CV1835_CHAIN_COUNT
    }

    fn open_chain(&self, chain_id: u8) -> Result<Box<dyn ChainAccess>> {
        if chain_id >= CV1835_CHAIN_COUNT {
            return Err(HalError::Platform(format!(
                "CV1835: chain {} out of range (have {})",
                chain_id, CV1835_CHAIN_COUNT
            )));
        }
        // CV1835 has no `bitmain_axi.ko` interface in the dev-kit
        // rootfs (the FPGA-less ASIC commands flow over UART), so the
        // default chain backend uses DevmemUart at the W10.3 CV1835
        // register base. The mmap-based register-shuttle adapter
        // (`crate::stock_fpga_axi_mmap::BitmainAxiUnifiedBackend`) is
        // reserved for the future stock-bitstream path. W13.B5 (2026-05-10)
        // demoted the IOCTL ABI to the `axi-ioctl-debug` Cargo feature; it
        // is not compiled into shipping firmware and the W10-era env-gate
        // `DCENT_BB_TRUST_INFERRED_AXI_IOCTL` is retired.
        let path = CV1835_CHAIN_UARTS[chain_id as usize];
        let uart = DevmemUart::open(path, CV1835_CHAIN_INITIAL_BAUD).map_err(|e| {
            HalError::Platform(format!(
                "CV1835 chain {}: DevmemUart::open({}) failed: {}",
                chain_id, path, e
            ))
        })?;
        tracing::info!(
            platform = "CV1835",
            chain_id,
            path,
            baud = CV1835_CHAIN_INITIAL_BAUD,
            "CV1835 chain UART opened"
        );
        Ok(Box::new(CViTekChainAccess {
            chain_id,
            uart: Mutex::new(uart),
        }))
    }

    fn open_i2c(&self, bus: u8) -> Result<I2cBus> {
        if bus != CVITEK_PIC1704_I2C_BUS {
            return Err(HalError::Platform(format!(
                "CV1835: only /dev/i2c-{} is supported (requested /dev/i2c-{})",
                CVITEK_PIC1704_I2C_BUS, bus
            )));
        }
        let mut handle = I2cBus::open(bus)?;
        // Defense-in-depth EEPROM write-deny — same posture as am3-aml.
        handle.set_write_denylist(&CV1835_EEPROM_DENYLIST);
        Ok(handle)
    }

    fn open_fan(&self) -> Result<Box<dyn FanAccess>> {
        Ok(Box::new(CViTekFan::new()?))
    }

    fn open_gpio(&self) -> Result<Box<dyn GpioAccess>> {
        Ok(Box::new(CViTekGpio))
    }

    fn voltage_controller(&self) -> VoltageControllerKind {
        // Test fixtures cache the evidence-only classification here. The
        // refused production constructor cannot publish it to the daemon.
        self.config.voltage_controller
    }
}

// ─── Chain access ───

/// CV1835 chain transport: DevmemUart-backed serial wrapped in a Mutex
/// so the trait-required `&self` methods can mutate the UART. Same
/// pattern Amlogic uses for `SerialChain`. CV1835 has no FPGA work
/// engine — chain commands AND mining work share the same UART.
struct CViTekChainAccess {
    chain_id: u8,
    uart: Mutex<DevmemUart>,
}

impl ChainAccess for CViTekChainAccess {
    fn send_command(&self, data: &[u8]) -> Result<()> {
        let uart = self
            .uart
            .lock()
            .map_err(|_| HalError::Platform("CV1835 chain UART mutex poisoned".into()))?;
        uart.write_bytes(data)
    }

    fn read_response(&self, buf: &mut [u8]) -> Result<usize> {
        let uart = self
            .uart
            .lock()
            .map_err(|_| HalError::Platform("CV1835 chain UART mutex poisoned".into()))?;
        Ok(uart.read_bytes(buf))
    }

    fn send_work(&self, data: &[u8]) -> Result<()> {
        let uart = self
            .uart
            .lock()
            .map_err(|_| HalError::Platform("CV1835 chain UART mutex poisoned".into()))?;
        uart.write_bytes(data)
    }

    fn read_nonce(&self, buf: &mut [u8]) -> Result<usize> {
        let uart = self
            .uart
            .lock()
            .map_err(|_| HalError::Platform("CV1835 chain UART mutex poisoned".into()))?;
        Ok(uart.read_bytes(buf))
    }

    fn set_baud(&self, baud: u32) -> Result<()> {
        let mut uart = self
            .uart
            .lock()
            .map_err(|_| HalError::Platform("CV1835 chain UART mutex poisoned".into()))?;
        let result = uart.set_baud(baud);
        tracing::info!(
            platform = "CV1835",
            chain_id = self.chain_id,
            baud,
            "CV1835 chain UART baud changed"
        );
        result
    }

    fn wait_for_nonce(&self) -> Result<()> {
        // CV1835 DevmemUart polls — yield to the scheduler so the work
        // dispatcher doesn't burn 100% CPU between reads.
        std::thread::yield_now();
        Ok(())
    }
}

// ─── Fan control (sysfs PWM + tach capture) ───

/// CV1835 fan controller backed by sysfs PWM. Both physical fan rotor
/// pairs (front FAN1+FAN3, rear FAN2+FAN4) get the same duty cycle —
/// per-rotor independent control isn't supported by the dev-kit driver.
/// Per-fan tach RPM IS available through `pwmchip12` capture.
struct CViTekFan;

impl CViTekFan {
    fn new() -> Result<Self> {
        // Best-effort sanity check: warn but don't fail if the sysfs
        // PWM duty paths aren't present yet (dev-kit's S37 init exports
        // them on first boot and they persist; any failure here is more
        // likely a kernel mismatch than a real outage). The runtime
        // sysfs writes in `set_speed` will surface the actual error.
        for path in [CV1835_FRONT_PWM_DUTY, CV1835_REAR_PWM_DUTY] {
            if !Path::new(path).exists() {
                tracing::warn!(
                    path,
                    "CV1835 fan: sysfs PWM duty path not present at construction; \
                     S37bitmainer_setup may not have run yet"
                );
            }
        }
        Ok(Self)
    }

    /// Compute duty_ns from a PWM percentage 0..100. Saturating at 100
    /// (caller already clamps to home-mining cap before calling).
    fn duty_from_pwm(pwm: u8) -> u32 {
        let pct = pwm.min(100) as u32;
        (pct * CV1835_FAN_PWM_PERIOD_NS) / 100
    }

    /// Parse the two-u64 nanosecond capture string from `pwmchip12`.
    /// Returns `Some(period_ns)` when the value is fresh and non-zero.
    fn parse_capture(raw: &str) -> Option<u64> {
        let mut parts = raw.split_whitespace();
        let period: u64 = parts.next()?.parse().ok()?;
        if period == 0 {
            None
        } else {
            Some(period)
        }
    }

    /// Convert a tach pulse_period_ns into RPM. Pulses-per-rev = 2.
    fn rpm_from_period_ns(period_ns: u64) -> u32 {
        if period_ns == 0 {
            return 0;
        }
        // pulse_freq_hz = 1e9 / period_ns
        // rpm = pulse_freq_hz * 60 / pulses_per_rev
        //     = 60 * 1e9 / period_ns / 2
        //     = 30_000_000_000 / period_ns
        let rpm_u64 = (60 * 1_000_000_000u64) / u64::from(CV1835_FAN_PULSES_PER_REV) / period_ns;
        // Saturating cast — RPM overflowing u32 means the period is
        // pathologically small (< 7 ns), which can't come from a real fan.
        if rpm_u64 > u32::MAX as u64 {
            u32::MAX
        } else {
            rpm_u64 as u32
        }
    }
}

impl FanAccess for CViTekFan {
    fn set_speed(&self, pwm: u8) {
        // Home-mining cap. Per the no-judgment philosophy + the fan-cap
        // memory rules, the HAL clamps every caller request. Operator
        // mode-policy elsewhere can pre-clamp to a lower number; the
        // HAL never goes higher than 30 unless an explicit config
        // path overrides — and that override lives outside HAL.
        let clamped = pwm.min(CV1835_FAN_PWM_HOME_CAP);
        let duty_ns = Self::duty_from_pwm(clamped);
        let duty_str = duty_ns.to_string();

        for path in [CV1835_FRONT_PWM_DUTY, CV1835_REAR_PWM_DUTY] {
            if let Err(e) = fs::write(path, &duty_str) {
                tracing::error!(
                    platform = "CV1835",
                    path,
                    requested_pwm = pwm,
                    clamped_pwm = clamped,
                    duty_ns,
                    error = %e,
                    "CV1835 fan PWM write failed"
                );
            }
        }
    }

    fn get_rpm(&self) -> u32 {
        // Average across all fans that report a fresh capture period.
        //: NEVER return RPM=0
        // when fans are spinning. We use the fan-tach derivation when
        // available and fall back to a synthesized floor otherwise.
        let per_fan = self.get_per_fan_rpm();
        let live: Vec<u32> = per_fan
            .iter()
            .filter_map(|(_, r)| (*r > 0).then_some(*r))
            .collect();
        if !live.is_empty() {
            let sum: u32 = live.iter().sum();
            return sum / live.len() as u32;
        }
        // Cold-start floor: the controller is still settling. Match the
        // Amlogic synthesized fallback to avoid false-positive
        // FanFailure during the first seconds after boot.
        let pwm = self.get_speed_pwm();
        if pwm == 0 {
            0
        } else {
            900
        }
    }

    fn get_speed_pwm(&self) -> u8 {
        // Read the front rotor's duty_cycle, convert back to PWM percent.
        // Both rotor pairs share the same duty in our driver, so reading
        // either is fine.
        let raw = match fs::read_to_string(CV1835_FRONT_PWM_DUTY) {
            Ok(s) => s,
            Err(_) => return 0,
        };
        let duty_ns: u32 = match raw.trim().parse() {
            Ok(v) => v,
            Err(_) => return 0,
        };
        if CV1835_FAN_PWM_PERIOD_NS == 0 {
            return 0;
        }
        let pct = (duty_ns.saturating_mul(100)) / CV1835_FAN_PWM_PERIOD_NS;
        pct.min(100) as u8
    }

    fn get_per_fan_rpm(&self) -> Vec<(u8, u32)> {
        let mut out = Vec::with_capacity(CV1835_FAN_COUNT as usize);
        for (i, path) in CV1835_FAN_TACH_CAPTURE.iter().enumerate() {
            let rpm = match fs::read_to_string(path) {
                Ok(raw) => Self::parse_capture(&raw)
                    .map(Self::rpm_from_period_ns)
                    .unwrap_or(0),
                Err(_) => 0,
            };
            out.push((i as u8, rpm));
        }
        out
    }

    fn fan_count(&self) -> u8 {
        CV1835_FAN_COUNT
    }

    fn tach_available(&self) -> bool {
        // Available iff at least one capture path exists. The dev-kit
        // rootfs always exports all four after S37 runs.
        CV1835_FAN_TACH_CAPTURE
            .iter()
            .any(|p| Path::new(p).exists())
    }
}

// ─── GPIO ───

struct CViTekGpio;

impl CViTekGpio {
    fn read_value(gpio: u32) -> Option<u8> {
        let path = format!("/sys/class/gpio/gpio{}/value", gpio);
        fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok())
            .map(|v| if v == 0 { 0 } else { 1 })
    }

    fn write_value(gpio: u32, value: u8) -> Result<()> {
        let path = format!("/sys/class/gpio/gpio{}/value", gpio);
        fs::write(&path, if value == 0 { "0" } else { "1" })
            .map_err(|e| HalError::Platform(format!("CV1835 GPIO {} write {}: {}", gpio, value, e)))
    }
}

impl GpioAccess for CViTekGpio {
    fn read_plug_detect(&self) -> [bool; 3] {
        // CV1835 has no per-chain plug-detect lines exposed in the dev-kit
        // pinmux (s19j_init.c does not export GPIO inputs for plug
        // detection — the BHB42xxx hashboard family probes plug presence
        // through the PIC1704 status read instead). Until live evidence
        // lands, assume 3 boards present so the higher-level enumeration
        // probes can run; a chain that doesn't ACK at PIC1704 / UART
        // gets soft-disabled by the daemon's normal failure path.
        [true, true, true]
    }

    fn set_board_reset(&self, chain: u8, assert_reset: bool) {
        let idx = chain as usize;
        if idx >= GPIO_ASIC_RST.len() {
            tracing::warn!(
                platform = "CV1835",
                chain,
                "CV1835 set_board_reset: chain id out of range"
            );
            return;
        }
        let gpio = GPIO_ASIC_RST[idx];
        // s19j_init.c convention: 1 = running, 0 = reset asserted.
        let value = if assert_reset { 0 } else { 1 };
        if let Err(e) = Self::write_value(gpio, value) {
            tracing::error!(
                platform = "CV1835",
                chain,
                gpio,
                value,
                error = %e,
                "CV1835 chain reset GPIO write failed"
            );
        }
    }
}

/// Drive the CV1835 PWR_EN line HIGH (PSU enable). Mirror of
/// `beaglebone::enable_psu` for the AM335x BB platform; same sysfs
/// write semantics.
pub fn enable_psu() -> Result<()> {
    CViTekGpio::write_value(GPIO_PWR_EN, 1)?;
    tracing::info!(
        platform = "CV1835",
        gpio = GPIO_PWR_EN,
        "CV1835 PSU PWR_EN driven HIGH"
    );
    Ok(())
}

/// Drive the CV1835 PWR_EN line LOW (PSU disable / shutdown).
pub fn disable_psu() -> Result<()> {
    CViTekGpio::write_value(GPIO_PWR_EN, 0)?;
    tracing::info!(
        platform = "CV1835",
        gpio = GPIO_PWR_EN,
        "CV1835 PSU PWR_EN driven LOW"
    );
    Ok(())
}

/// Set the CV1835 green LED.
pub fn set_led_green(on: bool) {
    let _ = CViTekGpio::write_value(GPIO_LED_GREEN, if on { 1 } else { 0 });
}

/// Set the CV1835 red LED.
pub fn set_led_red(on: bool) {
    let _ = CViTekGpio::write_value(GPIO_LED_RED, if on { 1 } else { 0 });
}

/// Read the recovery button state. Active-low, matches `s19j_init.c`'s
/// `s19j_is_recovery_mode()`.
pub fn is_recovery_mode() -> bool {
    matches!(CViTekGpio::read_value(GPIO_RECOVERY_BTN), Some(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::config::{ChainTransport, PicType, VoltageControl};
    use crate::platform::subtype::classify_voltage_controller;

    // ─── Hardware-constant pins (anti-regression) ───

    #[test]
    fn cv1835_chain_uart_paths_match_devmem_uart_table() {
        // CV1835 chain UART devices MUST line up with the W10.3 MMIO
        // table. Drift here would route ASIC commands to the wrong
        // physical UART block (catastrophic if shipped).
        assert_eq!(
            CV1835_CHAIN_UARTS,
            ["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3", "/dev/ttyS4"]
        );
    }

    #[test]
    fn cv1835_chain_count_is_four() {
        assert_eq!(CV1835_CHAIN_COUNT, 4);
        assert_eq!(CV1835_CHAIN_UARTS.len(), 4);
        assert_eq!(GPIO_ASIC_RST.len(), 4);
    }

    #[test]
    fn cv1835_gpio_constants_match_s19j_init_h() {
        // s19j_init.h verbatim — drift would mis-program the BHB42xxx
        // hashboards' reset and PWR_EN GPIOs.
        assert_eq!(GPIO_PWR_EN, 412);
        assert_eq!(GPIO_ASIC_RST, [427, 429, 431, 433]);
        assert_eq!(GPIO_LED_RED, 434);
        assert_eq!(GPIO_LED_GREEN, 435);
        assert_eq!(GPIO_RECOVERY_BTN, 447);
        assert_eq!(GPIO_IP_GET, 406);
        assert_eq!(GPIO_I2C_SCL, 459);
        assert_eq!(GPIO_I2C_SDA, 461);
    }

    /// **Round 16 B3 — `GPIO_PWR_EN` is double-sourced; keep it that way.**
    ///
    /// Source 1 (ours): dev-kit RE `s19j_init.h` / `S37bitmainer_setup`.
    /// Source 2 (Bitmain-authentic, independent product, same CV183x carrier
    /// family): the Antminer L9 stock `etc/topol.conf` states
    /// `"power": { "type": "APW17", "i2c_addr": 16, "gpio": 412 }` alongside
    /// `"processor": { "type": "CV183x" }`.
    ///
    /// This is a *safety-relevant* constant — it gates PSU energization. The
    /// test records the corroboration so a future edit has to confront both
    /// sources, and pins the EEPROM base address that the same file
    /// independently confirms (`"eeprom": { "i2c_addr": 80 }` = 0x50).
    #[test]
    fn gpio_pwr_en_is_412_double_sourced() {
        // Our RE value.
        assert_eq!(GPIO_PWR_EN, 412);
        assert_eq!(CViTekPlatform::psu_enable_gpio(), 412);
        // The L9 stock topol.conf value, transcribed verbatim as a literal so
        // the two sources are compared here rather than in prose.
        const L9_TOPOL_CONF_POWER_GPIO: u32 = 412;
        assert_eq!(
            GPIO_PWR_EN, L9_TOPOL_CONF_POWER_GPIO,
            "CV183x carrier PSU-enable GPIO disagrees between our dev-kit RE \
             and Bitmain's own L9 stock topol.conf — do not energize until \
             this is resolved on a bench unit"
        );
        // Same file states the hashboard EEPROM at decimal 80 = 0x50, which is
        // the base of our write-protection denylist.
        const L9_TOPOL_CONF_EEPROM_I2C_ADDR: u8 = 80;
        assert_eq!(
            CV1835_EEPROM_DENYLIST[0], L9_TOPOL_CONF_EEPROM_I2C_ADDR,
            "EEPROM write-deny base must stay 0x50"
        );
    }

    #[test]
    fn cv1835_eeprom_denylist_matches_am3_aml() {
        // Same range as Amlogic + am2 hybrid path. If this drifts,
        // the .74-style EEPROM corruption window reopens.
        assert_eq!(
            CV1835_EEPROM_DENYLIST,
            [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57]
        );
    }

    #[test]
    fn cv1835_fan_period_is_one_kilohertz() {
        // S37bitmainer_setup line 93/99: `period = 1000000` ns = 1 kHz.
        assert_eq!(CV1835_FAN_PWM_PERIOD_NS, 1_000_000);
        assert_eq!(CV1835_FAN_COUNT, 4);
    }

    #[test]
    fn cv1835_psu_gate_spec_targets_pwr_en_gpio_412() {
        // Apw121215a::with_psu_gate_spec(Some("gpio:412")) must hit the
        // S19j Pro PWR_EN line.
        assert_eq!(CViTekPlatform::psu_gate_spec(), "gpio:412");
        assert_eq!(CViTekPlatform::psu_enable_gpio(), 412);
    }

    #[test]
    fn cv1835_initial_chain_baud_is_115200() {
        // BM1362 enumeration baud — same across every Bitmain platform.
        assert_eq!(CV1835_CHAIN_INITIAL_BAUD, 115_200);
    }

    // ─── Voltage controller routing ───

    #[test]
    fn control_board_type_alone_never_selects_pic1704() {
        // BoardType static default for diagnostic / preflight code.
        assert_eq!(
            BoardType::CVitek.voltage_controller_default(),
            VoltageControllerKind::NoPic
        );
    }

    #[test]
    fn cv1835_subtype_classifier_picks_pic1704() {
        // `CVCtrl_BHB42XXX` is the dev-kit ground truth — must always
        // resolve to PIC1704 in the static classifier (the runtime
        // probe is the additional gate).
        let kind = classify_voltage_controller(Some("CVCtrl_BHB42XXX"));
        assert_eq!(kind, VoltageControllerKind::Pic1704);
    }

    #[test]
    fn cv1835_default_config_chains_have_pic_at_0x20() {
        let cfg = CViTekPlatform::cv1835_s19j_default_config();
        assert_eq!(cfg.chains.len(), 4);
        for chain in &cfg.chains {
            assert_eq!(chain.pic_address, Some(CVITEK_PIC1704_I2C_ADDR));
            assert_eq!(chain.i2c_bus, CVITEK_PIC1704_I2C_BUS);
            assert_eq!(
                chain.enable_gpio,
                Some(GPIO_ASIC_RST[chain.chain_id as usize])
            );
            match &chain.transport {
                ChainTransport::Serial { device, baud } => {
                    assert_eq!(*baud, CV1835_CHAIN_INITIAL_BAUD);
                    assert_eq!(device, CV1835_CHAIN_UARTS[chain.chain_id as usize]);
                }
                other => panic!("unexpected transport {:?}", other),
            }
        }
        // Static default keeps the dsPIC path so a unit whose subtype is
        // missing or 0x20 NACKs is never silently re-routed (the same
        // no-regression posture the BB platform uses).
        assert_eq!(cfg.voltage_controller, VoltageControllerKind::Dspic33Ep);
        assert!(matches!(cfg.pic_type, PicType::DsPic33EP16GS202));
        assert!(matches!(cfg.voltage_control, VoltageControl::DsPic));
    }

    #[test]
    fn cv1835_platform_with_config_reports_4_chains() {
        let plat = CViTekPlatform::with_config(CViTekPlatform::cv1835_s19j_default_config());
        assert!(matches!(plat.board_type(), BoardType::CVitek));
        assert_eq!(plat.chain_count(), 4);
        assert_eq!(plat.voltage_controller(), VoltageControllerKind::Dspic33Ep);
    }

    #[test]
    fn cv1835_platform_voltage_controller_reflects_config_override() {
        // PIC1704 routing is set on the `voltage_controller` field; the
        // platform must mirror that (mirroring the BB regression test).
        let mut cfg = CViTekPlatform::cv1835_s19j_default_config();
        cfg.voltage_controller = VoltageControllerKind::Pic1704;
        let plat = CViTekPlatform::with_config(cfg);
        assert_eq!(plat.voltage_controller(), VoltageControllerKind::Pic1704);
    }

    #[test]
    fn cv1835_open_i2c_rejects_nonzero_bus() {
        let plat = CViTekPlatform::with_config(CViTekPlatform::cv1835_s19j_default_config());
        // I2cBus doesn't implement Debug, so we can't use `expect_err`
        // — match on the variant instead. (Same pattern BB uses.)
        let msg = match plat.open_i2c(1) {
            Ok(_) => panic!("CV1835 must reject nonzero I2C bus"),
            Err(err) => err.to_string(),
        };
        assert!(
            msg.contains("only /dev/i2c-0 is supported"),
            "unexpected error: {}",
            msg
        );
    }

    // ─── Fan helpers (pure math) ───

    #[test]
    fn cv1835_duty_from_pwm_is_proportional_to_period() {
        // 0% → 0 ns, 100% → period, 50% → period / 2.
        assert_eq!(CViTekFan::duty_from_pwm(0), 0);
        assert_eq!(CViTekFan::duty_from_pwm(100), CV1835_FAN_PWM_PERIOD_NS);
        assert_eq!(CViTekFan::duty_from_pwm(50), CV1835_FAN_PWM_PERIOD_NS / 2);
        // 30% (home cap) → 30% of 1_000_000 = 300_000.
        assert_eq!(CViTekFan::duty_from_pwm(30), 300_000);
    }

    #[test]
    fn cv1835_duty_clamps_at_100_pct() {
        // PWM > 100 saturates — protects against caller-side overflow.
        assert_eq!(CViTekFan::duty_from_pwm(127), CV1835_FAN_PWM_PERIOD_NS);
        assert_eq!(CViTekFan::duty_from_pwm(255), CV1835_FAN_PWM_PERIOD_NS);
    }

    #[test]
    fn cv1835_rpm_from_period_ns_matches_2ppr_formula() {
        // 3000 RPM → period 10 ms = 10_000_000 ns.
        // RPM = 30_000_000_000 / 10_000_000 = 3000. ✓
        assert_eq!(CViTekFan::rpm_from_period_ns(10_000_000), 3000);
        // 6000 RPM (typical mining fan) → period ~5 ms.
        assert_eq!(CViTekFan::rpm_from_period_ns(5_000_000), 6000);
        // 1500 RPM (home-quiet target) → period 20 ms.
        assert_eq!(CViTekFan::rpm_from_period_ns(20_000_000), 1500);
        // Zero period (no edges captured) → 0 RPM (NOT a panic).
        assert_eq!(CViTekFan::rpm_from_period_ns(0), 0);
    }

    #[test]
    fn cv1835_parse_capture_extracts_period_ns_first_field() {
        // pwmchip12 capture format: "<period_ns> <duty_ns>".
        assert_eq!(
            CViTekFan::parse_capture("10000000 5000000\n"),
            Some(10_000_000)
        );
        assert_eq!(CViTekFan::parse_capture("0 0"), None);
        assert_eq!(CViTekFan::parse_capture(""), None);
        assert_eq!(CViTekFan::parse_capture("not-a-number"), None);
    }

    #[test]
    fn cv1835_fan_pwm_home_cap_matches_memory_rules() {
        //  and friends: home-mining cap = 30.
        assert_eq!(CV1835_FAN_PWM_HOME_CAP, 30);
    }

    // ─── Pinmux / signature host invariants ───

    #[test]
    fn cv1835_signature_returns_false_on_non_linux_host() {
        // Pure host invariant — the real check needs /proc/device-tree.
        #[cfg(not(target_os = "linux"))]
        assert!(!CViTekPlatform::has_cv1835_signature());
    }

    #[test]
    fn cv1835_runtime_constructor_is_a_non_mutating_refusal() {
        // Default path (opt-in env unset): construction refuses, unchanged.
        let error = match CViTekPlatform::new() {
            Err(error) => error,
            Ok(_) => panic!("CV1835 runtime must remain unadmitted by default"),
        };
        assert!(error.to_string().contains("runtime NOT IMPLEMENTED"));
    }

    #[test]
    fn cv1835_experimental_opt_in_gate_is_exact_and_fail_closed() {
        // Operator-authorized Experimental opt-in (2026-08-05): ONLY the exact
        // value "1" admits the lane; everything else (incl. unset) is fail-closed.
        // This is the value production actually passes new() — pinned so a wiring
        // change (e.g. accepting "true"/"yes") can't silently widen admission.
        assert!(cv1835_experimental_opt_in_enabled(Some("1")));
        assert!(!cv1835_experimental_opt_in_enabled(None));
        assert!(!cv1835_experimental_opt_in_enabled(Some("0")));
        assert!(!cv1835_experimental_opt_in_enabled(Some("true")));
        assert!(!cv1835_experimental_opt_in_enabled(Some("yes")));
        assert!(!cv1835_experimental_opt_in_enabled(Some("")));
        assert!(!cv1835_experimental_opt_in_enabled(Some(" 1")));
    }

    /// H7 G8 drift gate: the constructor refusal and the registry
    /// classification are the same fact expressed twice; if one changes, the
    /// other must be updated deliberately. CVitek is
    /// `EvidenceRetainedNotImplemented` (genuinely not implemented, evidence
    /// retained) — never the Amlogic-style `SpecialisedLifecycle` routing
    /// refusal.
    #[test]
    fn cv1835_refusal_matches_board_desc_runtime_status_classification() {
        let error = match CViTekPlatform::new() {
            Err(error) => error,
            Ok(_) => panic!("CV1835 runtime must remain unadmitted"),
        };
        assert!(error.to_string().contains("NOT IMPLEMENTED"));

        let desc = dcentrald_common::BoardDesc::lookup("cv1835-s19jpro")
            .expect("cv1835-s19jpro registry row");
        match desc.runtime_status {
            dcentrald_common::RuntimeStatus::EvidenceRetainedNotImplemented { evidence } => {
                assert!(
                    !evidence.is_empty(),
                    "retained evidence list must be non-empty"
                );
            }
            other => {
                panic!("cv1835-s19jpro must stay EvidenceRetainedNotImplemented, got {other:?}")
            }
        }
        assert!(!desc.runtime_status.permits_mining_lane());
        assert!(!desc.public_beta_install);
    }

    #[test]
    fn cv1835_voltage_controller_helper_matches_subtype_classifier() {
        // The free function `cvitek_voltage_controller` runs the same
        // classifier as the platform constructor — on a non-Linux host
        // the probe always misses, so a missing subtype still routes
        // to dsPIC. (Same posture as BB.)
        #[cfg(not(target_os = "linux"))]
        {
            let kind = cvitek_voltage_controller();
            assert_eq!(kind, VoltageControllerKind::Dspic33Ep);
        }
    }
}
