//! Zynq platform implementation.
//!
//! Supports the Xilinx Zynq 7010/7020 control boards used in Antminer S9, S17,
//! and S19 series miners. FPGA UART FIFOs are accessed via UIO devices.
//!
//! Three Zynq miner families exist. S17 and S19 share the AM2 FPGA topology,
//! so UIO enumeration alone cannot distinguish their product identity.
//!
//! **S9 (am1-s9):**
//!   - 3 hash chains (6, 7, 8) with 4 UIO devices each
//!   - 1 fan controller UIO device (uio0)
//!   - 1 glitch monitor UIO device (uio13)
//!   - I2C bus 0 for PIC controllers (0x55-0x57)
//!   - UIO names: "chain6-common", "chain7-cmd", etc.
//!
//! **AM2 S17/S19 fabric:**
//!   - 4 hash chains (1, 2, 3, 4) with 4 UIO devices each (only 3 physical boards)
//!   - 1 fan controller UIO device (uio16)
//!   - 1 board-control UIO device (uio17)
//!   - 1 glitch monitor UIO device (uio18)
//!   - I2C bus 0 for PIC controllers (0x88/0x89/0xB9/0xFE)
//!   - UIO names: "chain1-common", "chain2-cmd-rx", etc.
//!   - Additional PL UARTs at 0x41001000-0x41031000
//!
//! Auto-discovery scans `/sys/class/uio/uioN/name`. Exact `chain6..8` roles
//! identify S9 capabilities. Exact `chain1..4` roles identify the shared AM2
//! fabric, but product identity must come from `board_target` or device-tree
//! evidence because S17 and S19 cannot be separated by their UIO census.

use std::collections::HashMap;
use std::fs;

use super::{BoardType, ChainAccess, FanAccess, GpioAccess, Platform, VoltageControllerKind};
use crate::board_control::BoardControl;
use crate::fan::{Am2FanModePolicy, FanController, FanVariant};
use crate::fpga_chain::FpgaChain;
use crate::glitch_monitor::BraiinsGlitchMonitor;
use crate::gpio::{GpioController, GpioLayout};
use crate::i2c::I2cBus;
use crate::{HalError, Result};

/// am2-s17 family PSU gate GPIO.
///
/// Verified from VNish/BraiinsOS research on S17/S19 class Zynq boards:
/// `gpio907` is the shared PSU/power-control output and is active HIGH.
const AM2_S17_PSU_ENABLE_GPIO: u32 = 907;

/// Chain IDs used on S9 boards (match physical connector labels).
const S9_CHAIN_IDS: [u8; 3] = [6, 7, 8];

/// AM2 chain IDs proven by held S17 and S19-family UIO censuses. All four
/// logical groups exist even when only three physical hashboards are fitted.
const AM2_CHAIN_IDS: [u8; 4] = [1, 2, 3, 4];

/// Zynq sub-platform type (detected from UIO device names + board_target).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZynqVariant {
    /// S9 (am1-s9): 3×63 BM1387 chains numbered 6/7/8.
    /// PIC16F1704 voltage controllers at I2C 0x55-0x57. 512 MB RAM.
    S9,
    /// S17 (`board_target` token "am2-s17p"): three populated 48-chip BM1397
    /// chains in a four-slot FPGA topology numbered 1/2/3/4. 256 MB
    /// RAM — significantly less than S9, so the daemon must run with a
    /// tighter tokio worker pool and blocking-thread budget.
    /// Disambiguated through exact product identity, normally the installed
    /// `/etc/dcentos/board_target` token `am2-s17p`.
    ///
    /// SoC classification (CANONICAL — see memory rule
    /// ): the S17 control
    /// board is a **Zynq 7007S = `am2`** board, NOT `am1` (7010). The
    /// `am1-s17` `board_target` token does NOT assert an am1 SoC — it is a
    /// legacy label meaning "S9-lineage chain layout / s9io-style FPGA UIO
    /// map". Held live evidence supersedes that naming inference: S17 exposes
    /// the AM2 chain1..4 fabric. The Buildroot side of
    /// S17 belongs to the `am2-s17pro-zynq` variant family — there is
    /// deliberately NO `am1-s17` Buildroot defconfig (that would be the
    /// am1/am2 inversion the canonical rule exists to prevent). The
    /// `am1-s17` string is retained only for backward compatibility with
    /// the post-build evidence file + toolbox route keys + the unit tests
    /// below; renaming it is tracked naming debt, not a correctness bug.
    S17,
    /// S19 family on the shared AM2 fabric: 4 logical chains numbered 1/2/3/4,
    /// UIO names `chain1-*` through `chain4-*` (also the Zynq S19j Pro lane).
    S19,
}

impl ZynqVariant {
    /// Fan hardware variant associated with this Zynq sub-platform.
    pub fn fan_variant(self) -> FanVariant {
        match self {
            ZynqVariant::S9 => FanVariant::Am1S9,
            ZynqVariant::S17 => FanVariant::Am2Uio16,
            ZynqVariant::S19 => FanVariant::Am2Uio16,
        }
    }

    /// Whether opening the fan block may rewrite board-control into C52 mode.
    pub fn fan_mode_policy(self) -> Am2FanModePolicy {
        match self {
            // The C52 write is proven on bounded S19-family captures. The S17
            // capture proves the four-channel fan layout but not equivalent
            // semantics for board-control +0x04, so preserve it.
            ZynqVariant::S19 => Am2FanModePolicy::EnableC52,
            ZynqVariant::S9 | ZynqVariant::S17 => Am2FanModePolicy::Preserve,
        }
    }

    /// Whether this variant has an am2 board-control IP at 0x42810000.
    pub fn has_board_control_ip(self) -> bool {
        matches!(self, ZynqVariant::S17 | ZynqVariant::S19)
    }

    /// Whether this variant has an am2 glitch-monitor IP at 0x43D00000.
    pub fn has_glitch_monitor_ip(self) -> bool {
        matches!(self, ZynqVariant::S17 | ZynqVariant::S19)
    }

    /// Tokio worker-thread count recommended for this variant.
    ///
    /// Derived from `/proc/meminfo` evidence baked into the platform docs:
    /// S9 = 512 MB, S17 = 228 MB, S19 = 512 MB+. The S17 has less than half
    /// the RAM of S9 with the same dual-core CPU, so the daemon should run
    /// with a tighter pool to leave headroom for tmpfs + ASIC drivers +
    /// Stratum + dashboard. Returns 2 for S9/S19 (default for dual-core)
    /// and 2 for S17 (same CPU; the savings comes from the blocking pool).
    pub fn tokio_worker_threads(self) -> usize {
        match self {
            ZynqVariant::S9 | ZynqVariant::S19 => 2,
            ZynqVariant::S17 => 2,
        }
    }

    /// Tokio max-blocking-threads recommended for this variant.
    ///
    /// Tokio's default (512) is wildly out of proportion for a 228 MB device.
    /// Each blocking thread reserves a stack (~2 MB on musl by default), so
    /// the default pool can exhaust virtual memory before any actual blocking
    /// I/O is dispatched. Cap to 4 on S17, leave the default elsewhere.
    pub fn tokio_max_blocking_threads(self) -> usize {
        match self {
            ZynqVariant::S17 => 4,
            // 512 = tokio default. We don't override S9/S19 in this gate.
            ZynqVariant::S9 | ZynqVariant::S19 => 512,
        }
    }
}

/// UIO device info discovered from sysfs.
#[derive(Debug, Clone)]
pub struct UioInfo {
    /// UIO device number (e.g., 0 for /dev/uio0).
    pub number: u8,
    /// Device name from sysfs.
    pub name: String,
}

/// Zynq platform implementation.
pub struct ZynqPlatform {
    /// UIO device number for the fan controller.
    fan_uio: u8,
    /// UIO device number for the am2 board-control IP (None on S9).
    board_control_uio: Option<u8>,
    /// UIO device number for the am2 glitch-monitor IP (None on S9).
    glitch_monitor_uio: Option<u8>,
    /// UIO base numbers for each chain (chain_id -> uio_base).
    chain_uio_bases: HashMap<u8, u8>,
    /// Detected Zynq product/capability route (S9, S17, or S19 family).
    variant: ZynqVariant,
}

impl ZynqPlatform {
    /// Open exact S19/AM2 cooling custody and require the independent
    /// board-control C52 transition to be observed. Generic `Platform::open_fan`
    /// remains compatible, while hardware-owning S19 routes use this narrower
    /// fail-closed constructor before energizing hashboards.
    ///
    /// Home-profile admission is the pure [`dcentrald_common::admit_home_am2_s19_c52`]
    /// policy (P1-7); this constructor always requires the C52 receipt because
    /// it is the hardware-owning S19 path used before rail energize.
    pub fn open_am2_s19_fan_controller_checked(&self) -> Result<FanController> {
        if self.variant != ZynqVariant::S19 {
            return Err(HalError::Fan(format!(
                "checked AM2 S19 fan custody requires ZynqVariant::S19, got {:?}",
                self.variant
            )));
        }
        let fan = FanController::open_with_variant_and_mode_policy(
            self.fan_uio,
            FanVariant::Am2Uio16,
            Am2FanModePolicy::EnableC52,
        )?;
        let receipt_low = fan
            .am2_c52_fan_mode_status()
            .map(|s| (s.after & 0xff) as u8);
        // Fail-closed via the shared pure policy (home AM2-S19). Lab soft-prefer
        // is intentionally not used here: this API is the energize custody gate.
        dcentrald_common::admit_home_am2_s19_c52(receipt_low)
            .map_err(|e| HalError::Fan(format!("AM2 S19 C52 cooling custody refused: {e}")))?;
        Ok(fan)
    }

    /// Create a new Zynq platform instance.
    ///
    /// Scans UIO devices and builds the device map. Product identity is taken
    /// from the installed target or device tree before topology evidence; UIO
    /// names alone intentionally cannot choose between S17 and S19 on AM2.
    pub fn new() -> Result<Self> {
        let devices = scan_uio_devices()?;
        tracing::info!(count = devices.len(), "Discovered UIO devices");

        for dev in &devices {
            tracing::debug!(uio = dev.number, name = %dev.name, "UIO device");
        }

        // Detect the product route from exact identity first. UIO topology is
        // only a capability fallback: chain6..8 is S9-specific, while the
        // chain1..4 AM2 fabric is shared by held S17 and S19-family censuses.
        let variant = detect_zynq_variant(&devices).ok_or_else(|| {
            HalError::Platform(
                "Zynq variant detection inconclusive; refusing to default to S9".into(),
            )
        })?;
        tracing::info!(variant = ?variant, "Detected Zynq sub-platform");

        let chain_ids: &[u8] = match variant {
            ZynqVariant::S9 => &S9_CHAIN_IDS,
            ZynqVariant::S17 | ZynqVariant::S19 => &AM2_CHAIN_IDS,
        };

        // Find fan controller
        let fan_uio = find_uio_by_name(&devices, "fan-control")
            .ok_or_else(|| HalError::Platform("fan controller UIO not found".into()))?;

        // am2-only IP blocks — optional (absent on S9 am1-s9 bitstream).
        let board_control_uio = find_uio_by_name(&devices, "board-control");
        let glitch_monitor_uio = find_uio_by_name(&devices, "miner-glitch-monitor")
            .or_else(|| find_uio_by_name(&devices, "glitch-monitor"));

        if variant.has_board_control_ip() {
            if board_control_uio.is_none() {
                tracing::warn!(
                    "am2 variant detected but no 'board-control' UIO device found — \
                     reset pulses and PSU hardware-enable will be unavailable"
                );
            }
            if glitch_monitor_uio.is_none() {
                tracing::warn!(
                    "am2 variant detected but no 'miner-glitch-monitor' UIO device found — \
                     UART/I2C glitch telemetry will be unavailable"
                );
            }
        }

        let chain_uio_bases = admit_chain_uio_topology(&devices, variant, chain_ids)?;

        Ok(Self {
            fan_uio,
            board_control_uio,
            glitch_monitor_uio,
            chain_uio_bases,
            variant,
        })
    }

    /// Get the detected Zynq sub-platform variant.
    pub fn variant(&self) -> ZynqVariant {
        self.variant
    }

    /// Open the am2 board-control IP (hashboard reset, plug-detect, PSU enable).
    ///
    /// Returns `None` on am1-s9 (this IP does not exist on S9 bitstream).
    pub fn open_board_control(&self) -> Result<Option<BoardControl>> {
        match self.board_control_uio {
            Some(n) => BoardControl::open(n).map(Some),
            None => Ok(None),
        }
    }

    /// Open the am2 glitch-monitor IP (passive read-only telemetry).
    ///
    /// Returns `None` on am1-s9 (this IP does not exist on S9 bitstream).
    pub fn open_glitch_monitor(&self) -> Result<Option<BraiinsGlitchMonitor>> {
        match self.glitch_monitor_uio {
            Some(n) => BraiinsGlitchMonitor::open(n).map(Some),
            None => Ok(None),
        }
    }

    /// UIO device numbers for the am2 IP blocks, for diagnostics.
    pub fn am2_uio_numbers(&self) -> (Option<u8>, Option<u8>) {
        (self.board_control_uio, self.glitch_monitor_uio)
    }
}

fn ensure_sysfs_gpio_exported(gpio: u32) -> Result<()> {
    let gpio_dir = format!("/sys/class/gpio/gpio{}", gpio);
    if !std::path::Path::new(&gpio_dir).exists() {
        fs::write("/sys/class/gpio/export", format!("{}", gpio))
            .map_err(|e| HalError::Platform(format!("failed to export GPIO {}: {}", gpio, e)))?;
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Ok(())
}

fn set_sysfs_gpio_value(gpio: u32, high: bool) -> Result<()> {
    ensure_sysfs_gpio_exported(gpio)?;
    let dir_path = format!("/sys/class/gpio/gpio{}/direction", gpio);
    let value_path = format!("/sys/class/gpio/gpio{}/value", gpio);
    fs::write(&dir_path, "out")
        .map_err(|e| HalError::Platform(format!("GPIO {} direction: {}", gpio, e)))?;
    fs::write(&value_path, if high { "1" } else { "0" })
        .map_err(|e| HalError::Platform(format!("GPIO {} value: {}", gpio, e)))?;
    Ok(())
}

/// Enable the shared APW output gate on am2-s17 family Zynq boards.
pub fn enable_psu_output() -> Result<()> {
    set_sysfs_gpio_value(AM2_S17_PSU_ENABLE_GPIO, true)?;
    tracing::info!(
        gpio = AM2_S17_PSU_ENABLE_GPIO,
        "am2-s17 PSU output gate enabled"
    );
    Ok(())
}

/// Disable the shared APW output gate on am2-s17 family Zynq boards.
pub fn disable_psu_output() -> Result<()> {
    set_sysfs_gpio_value(AM2_S17_PSU_ENABLE_GPIO, false)?;
    tracing::info!(
        gpio = AM2_S17_PSU_ENABLE_GPIO,
        "am2-s17 PSU output gate disabled"
    );
    Ok(())
}

/// Read the current state of the shared APW output gate on am2-s17 boards.
pub fn is_psu_output_enabled() -> bool {
    let value_path = format!("/sys/class/gpio/gpio{}/value", AM2_S17_PSU_ENABLE_GPIO);
    fs::read_to_string(&value_path)
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

impl Platform for ZynqPlatform {
    fn board_type(&self) -> BoardType {
        BoardType::Zynq
    }

    fn chain_count(&self) -> u8 {
        self.chain_uio_bases.len() as u8
    }

    fn open_chain(&self, chain_id: u8) -> Result<Box<dyn ChainAccess>> {
        let uio_base = self
            .chain_uio_bases
            .get(&chain_id)
            .ok_or_else(|| HalError::Platform(format!("chain {} not found", chain_id)))?;

        let chain = FpgaChain::open(chain_id, *uio_base)?;
        Ok(Box::new(ZynqChainAccess { chain }))
    }

    fn open_i2c(&self, bus: u8) -> Result<I2cBus> {
        I2cBus::open(bus)
    }

    fn open_fan(&self) -> Result<Box<dyn FanAccess>> {
        // Route to the correct fan backend: am1-s9 uses the integrated s9io
        // 2-channel layout; am2-s17 uses the dedicated 4-channel fan-control
        // IP at 0x42800000 uio16.
        let fan_variant = self.variant.fan_variant();
        let fan_mode_policy = self.variant.fan_mode_policy();
        let fan = FanController::open_with_variant_and_mode_policy(
            self.fan_uio,
            fan_variant,
            fan_mode_policy,
        )?;
        tracing::info!(
            uio = self.fan_uio,
            variant = ?fan_variant,
            mode_policy = ?fan_mode_policy,
            "Opened fan controller with detected variant"
        );
        Ok(Box::new(fan))
    }

    fn open_gpio(&self) -> Result<Box<dyn GpioAccess>> {
        // Both families expose the same AXI-GPIO base addresses, but the bit
        // assignments differ materially. S9 uses plug 5..7/reset 9..11;
        // held S17 and S19 AM2 evidence uses plug/reset 0..2. An explicit
        // layout prevents a correct address from masking a wrong-pin write.
        let layout = match self.variant {
            ZynqVariant::S9 => GpioLayout::Am1S9,
            ZynqVariant::S17 | ZynqVariant::S19 => GpioLayout::Am2,
        };
        let controller = GpioController::new_with_layout(layout)?;
        Ok(Box::new(ZynqGpioAccess { controller }))
    }

    fn voltage_controller(&self) -> VoltageControllerKind {
        // `new()` refuses an inconclusive UIO/board-target identity, so this
        // explicit compatibility value does not rely on the fail-closed trait
        // default or on control-board family alone.
        match self.variant {
            ZynqVariant::S9 => VoltageControllerKind::Pic16f1704,
            ZynqVariant::S17 | ZynqVariant::S19 => VoltageControllerKind::Dspic33Ep,
        }
    }
}

/// `GpioAccess` adapter over the AXI-GPIO `/dev/mem` controller.
///
/// Bridges the platform-neutral [`GpioAccess`] trait to [`GpioController`]
/// (gpio.rs). The chain argument is a physical-board index 0/1/2, not the
/// FPGA's external chain label (6/7/8 on S9 or logical slot 1..4 on AM2).
struct ZynqGpioAccess {
    controller: GpioController,
}

impl GpioAccess for ZynqGpioAccess {
    fn read_plug_detect(&self) -> [bool; 3] {
        self.controller.read_plug_detect()
    }

    fn set_board_reset(&self, chain: u8, assert_reset: bool) {
        // Trait semantics: `assert_reset == true` holds the ASICs in reset.
        // GpioController::set_board_enable takes `enable` (true = release
        // reset / run), so invert: enable = !assert_reset.
        self.controller.set_board_enable(chain, !assert_reset);
    }
}

/// Wrapper to implement ChainAccess trait for FpgaChain.
struct ZynqChainAccess {
    chain: FpgaChain,
}

impl ChainAccess for ZynqChainAccess {
    fn send_command(&self, data: &[u8]) -> Result<()> {
        // Pack bytes into 32-bit words (little-endian, LSB-first)
        for chunk in data.chunks(4) {
            let mut word = 0u32;
            for (i, &byte) in chunk.iter().enumerate() {
                word |= (byte as u32) << (i * 8);
            }
            self.chain.write_cmd(word);
        }
        Ok(())
    }

    fn read_response(&self, buf: &mut [u8]) -> Result<usize> {
        let mut pos = 0;
        while pos < buf.len() {
            if let Some(word) = self.chain.read_cmd_response() {
                let bytes = word.to_le_bytes();
                let remaining = buf.len() - pos;
                let copy_len = remaining.min(4);
                buf[pos..pos + copy_len].copy_from_slice(&bytes[..copy_len]);
                pos += copy_len;
            } else {
                break; // FIFO empty
            }
        }
        Ok(pos)
    }

    fn send_work(&self, data: &[u8]) -> Result<()> {
        // Pack bytes into 32-bit words
        let mut words = Vec::with_capacity(data.len() / 4 + 1);
        for chunk in data.chunks(4) {
            let mut word = 0u32;
            for (i, &byte) in chunk.iter().enumerate() {
                word |= (byte as u32) << (i * 8);
            }
            words.push(word);
        }
        self.chain.write_work(&words);
        Ok(())
    }

    fn read_nonce(&self, buf: &mut [u8]) -> Result<usize> {
        if let Some((word0, word1)) = self.chain.read_nonce() {
            let w0_bytes = word0.to_le_bytes();
            let w1_bytes = word1.to_le_bytes();
            let copy_len = buf.len().min(8);
            if copy_len >= 4 {
                buf[0..4].copy_from_slice(&w0_bytes);
            }
            if copy_len >= 8 {
                buf[4..8].copy_from_slice(&w1_bytes);
            }
            Ok(copy_len)
        } else {
            Ok(0)
        }
    }

    fn set_baud(&self, baud: u32) -> Result<()> {
        let divisor = FpgaChain::divisor_from_baud(baud);
        self.chain.set_baud(divisor);
        tracing::debug!(
            baud,
            divisor,
            actual = FpgaChain::baud_from_divisor(divisor),
            "Set chain baud rate"
        );
        Ok(())
    }

    fn wait_for_nonce(&self) -> Result<()> {
        // Poll work RX FIFO status
        // In a production implementation, this would use IRQ via UIO
        while !self.chain.work_rx_has_data() {
            std::thread::yield_now();
        }
        Ok(())
    }
}

// NOTE: ZynqHybridChainAccess (serial commands + FPGA work) will be added
// when S19 hybrid transport support is implemented. For now, S19 uses the
// same FpgaUio transport as S9 (the BraiinsOS FPGA bitstream provides
// both cmd FIFOs and work FIFOs for all chain slots).

/// Implement FanAccess for FanController.
impl FanAccess for FanController {
    fn set_speed(&self, pwm: u8) {
        FanController::set_speed(self, pwm);
    }

    fn set_speed_checked(&self, pwm: u8) -> Result<super::FanCommandReceipt> {
        let requested = pwm.min(crate::fan::PWM_MAX);
        FanController::set_speed(self, requested);
        let (rear, front) = FanController::get_speed_pwm_channels(self);
        if rear != front {
            return Err(HalError::Fan(format!(
                "Zynq fan PWM channels disagree after command: rear={rear}, front={front}"
            )));
        }
        super::FanCommandReceipt::from_matching_readback(requested, rear)
    }

    fn get_rpm(&self) -> u32 {
        FanController::get_rpm(self)
    }

    fn get_speed_pwm(&self) -> u8 {
        FanController::get_speed_pwm(self)
    }

    fn get_per_fan_rpm(&self) -> Vec<(u8, u32)> {
        FanController::get_per_fan_rpm(self)
    }

    fn fan_count(&self) -> u8 {
        self.variant().physical_fan_count()
    }
}

/// Scan /sys/class/uio/ for all available UIO devices.
fn scan_uio_devices() -> Result<Vec<UioInfo>> {
    let uio_dir = "/sys/class/uio";
    let mut devices = Vec::new();

    let entries = fs::read_dir(uio_dir).map_err(|e| HalError::DeviceOpen {
        path: uio_dir.to_string(),
        source: e,
    })?;

    for entry in entries {
        let entry = entry.map_err(HalError::Io)?;
        let dir_name = entry.file_name().to_string_lossy().to_string();

        // Parse "uioN" to get the number
        if let Some(num_str) = dir_name.strip_prefix("uio") {
            if let Ok(number) = num_str.parse::<u8>() {
                let name_path = format!("{}/{}/name", uio_dir, dir_name);
                let name = fs::read_to_string(&name_path)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| format!("uio{}", number));

                devices.push(UioInfo { number, name });
            }
        }
    }

    devices.sort_by_key(|d| d.number);
    Ok(devices)
}

/// Find a UIO device number by its exact kernel sysfs name.
fn find_uio_by_name(devices: &[UioInfo], name: &str) -> Option<u8> {
    devices
        .iter()
        .filter(|device| device.name.trim() == name)
        .min_by_key(|device| device.number)
        .map(|d| d.number)
}

/// Return the fixed role index for an exact `chain<N>-<role>` UIO name.
fn chain_role(name: &str, chain_id: u8) -> Option<usize> {
    let prefix = format!("chain{chain_id}-");
    match name.strip_prefix(&prefix)? {
        "common" => Some(0),
        "cmd" | "cmd-rx" => Some(1),
        "work-rx" => Some(2),
        "work-tx" => Some(3),
        _ => None,
    }
}

/// Map every complete chain-UIO group present on this fabric.
///
/// **Partial population is the NORMAL live case, not an error.** Requiring all
/// `chain_ids.len()` groups contradicts our own captured evidence and would
/// take live-proven units offline at platform construction:
///
///   * `a lab unit` (XIL S19j Pro) exposes only TWO complete groups — uio4-7 =
///     `chain2-*` and uio12-15 = `chain4-*`
///.
///   * `a lab unit` unbinds `43c03000.chain1-work-tx` to free IRQ 165 for `of_serial`
///     in exactly the configuration that produced the proven standalone mining
///     run.
///
/// Exactness is still enforced PER GROUP by [`discover_chain_uio_base`] (roles
/// unique AND contiguous). Only the *count* is relaxed: an unpopulated or
/// deliberately-unbound slot is the absence of a chain, never evidence of a
/// corrupt fabric. A fabric with zero usable chains still fails closed.
///
/// Pure over a device census so the live topologies above are host-testable.
fn admit_chain_uio_topology(
    devices: &[UioInfo],
    variant: ZynqVariant,
    chain_ids: &[u8],
) -> Result<HashMap<u8, u8>> {
    // Substring counting is unsafe: `chain1` also matches `chain10`, and four
    // arbitrary matches do not prove the required
    // common/cmd-rx/work-rx/work-tx role ordering.
    let mut chain_uio_bases = HashMap::new();

    for &chain_id in chain_ids {
        if let Some(base) = discover_chain_uio_base(devices, chain_id) {
            chain_uio_bases.insert(chain_id, base);
            tracing::info!(chain_id, uio_base = base, "Mapped chain to UIO devices");
        } else if devices
            .iter()
            .any(|device| chain_role(&device.name, chain_id).is_some())
        {
            tracing::warn!(
                chain_id,
                "Incomplete, duplicated, or non-contiguous chain UIO roles"
            );
        }
    }

    // Fallback: if name-based discovery fails entirely, use positional mapping.
    if chain_uio_bases.is_empty() {
        match variant {
            ZynqVariant::S9 if devices.len() >= 12 => {
                // Bases 1/5/9, NOT 0/4/8.
                //
                // The live S9 census is uio0 `fan-control`, uio1-4 `chain6-*`,
                // uio5-8 `chain7-*`, uio9-12 `chain8-*`, uio13
                // `miner-glitch-monitor`
                // (:97-106`,
                // corroborated by `LIVE_RECON_FLEET.md`). The canonical driver
                // table agrees: `dcentrald-asic/src/drivers/mod.rs` pins
                // `uio_bases: &[1, 5, 9]` for BM1387/S9.
                //
                // The previous 0/4/8 mapping was off by one and put chain6 on
                // uio0 — the FAN-CONTROL block. Since `FpgaChain::open` maps
                // `base..base+3`, that fallback would have issued hash-chain
                // command/FIFO writes into the fan controller. Only reachable
                // when name-based discovery fails entirely, which is why it
                // survived unnoticed.
                tracing::warn!("Name-based UIO discovery failed, using S9 positional fallback");
                chain_uio_bases.insert(6, 1);
                chain_uio_bases.insert(7, 5);
                chain_uio_bases.insert(8, 9);
            }
            _ => {}
        }
    }

    if chain_uio_bases.is_empty() {
        return Err(HalError::Platform(format!(
            "no complete hash-chain UIO group found for {variant:?}: expected exact \
             common/cmd-rx/work-rx/work-tx roles for any of {chain_ids:?}"
        )));
    }

    let missing: Vec<u8> = chain_ids
        .iter()
        .copied()
        .filter(|id| !chain_uio_bases.contains_key(id))
        .collect();
    if !missing.is_empty() {
        tracing::info!(
            variant = ?variant,
            mapped = chain_uio_bases.len(),
            slots = chain_ids.len(),
            ?missing,
            "Partially populated chain-UIO topology (unpopulated or deliberately \
             unbound slots); continuing with the complete groups"
        );
    }

    Ok(chain_uio_bases)
}

/// Discover one chain only when all four named roles are unique and occupy a
/// contiguous UIO group in hardware order.
fn discover_chain_uio_base(devices: &[UioInfo], chain_id: u8) -> Option<u8> {
    let mut role_numbers = [None; 4];
    for device in devices {
        let Some(role) = chain_role(&device.name, chain_id) else {
            continue;
        };
        if role_numbers[role].replace(device.number).is_some() {
            return None;
        }
    }

    let base = role_numbers[0]?;
    for (role, number) in role_numbers.into_iter().enumerate() {
        if number != base.checked_add(role as u8) {
            return None;
        }
    }
    Some(base)
}

/// Product-independent FPGA fabric topology proven from complete, exact UIO
/// role groups. Unlike [`ZynqVariant`], this observation never consults an
/// installed target marker or device-tree product string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZynqFabricTopology {
    S9,
    Am2,
}

fn exact_zynq_fabric_topology(devices: &[UioInfo]) -> Option<ZynqFabricTopology> {
    let has_any_s9_role = S9_CHAIN_IDS.iter().any(|&chain_id| {
        devices
            .iter()
            .any(|device| chain_role(&device.name, chain_id).is_some())
    });
    let has_any_am2_role = AM2_CHAIN_IDS.iter().any(|&chain_id| {
        devices
            .iter()
            .any(|device| chain_role(&device.name, chain_id).is_some())
    });
    // At least ONE exact complete group proves the fabric — not all of them.
    //
    // This must agree with `admit_chain_uio_topology`, or the availability
    // failure is merely RELOCATED instead of fixed. This function feeds
    // `detect_exact_zynq_fabric_topology` -> `detect_control_board` ->
    // `PlatformIdentitySnapshot::observed_control_board`, which both
    // `admit_s19j_hybrid_route` and `admit_am2_bm1362_serial_route` compare
    // against `OBSERVED_CONTROL_BOARD_ZYNQ_AM2`. Requiring all four groups here
    // resolves `a lab unit`/`a lab unit` to "Zynq ambiguous" and REFUSES AM2 route admission
    // whenever mining is enabled — a harder gate than the one in
    // `ZynqPlatform::new()`.
    //
    // Exclusivity below is unchanged and still fail-closed: a census with any
    // role from BOTH families, or with roles but no complete group at all,
    // resolves to `None`.
    let complete_s9 = S9_CHAIN_IDS
        .iter()
        .any(|&chain_id| discover_chain_uio_base(devices, chain_id).is_some());
    let complete_am2 = AM2_CHAIN_IDS
        .iter()
        .any(|&chain_id| discover_chain_uio_base(devices, chain_id).is_some());

    match (complete_s9, complete_am2, has_any_s9_role, has_any_am2_role) {
        (true, false, true, false) => Some(ZynqFabricTopology::S9),
        (false, true, false, true) => Some(ZynqFabricTopology::Am2),
        _ => None,
    }
}

/// Passively prove the live FPGA fabric without opening UIO or MMIO devices.
///
/// A stale/cross-flashed board target must not authorize AM1 devmem access on
/// an AM2 fabric. The caller receives an error for incomplete, duplicated,
/// unnamed, or mixed role evidence rather than a positional/count fallback.
pub fn detect_exact_zynq_fabric_topology() -> Result<ZynqFabricTopology> {
    let devices = scan_uio_devices()?;
    exact_zynq_fabric_topology(&devices).ok_or_else(|| {
        HalError::Platform(
            "exact Zynq FPGA fabric topology is incomplete, mixed, duplicated, or unnamed"
                .to_string(),
        )
    })
}

fn normalize_model_token(model: &str) -> String {
    model
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+')
        .collect()
}

/// Detect whether this Zynq board is an S9, S17, or S19-family target.
///
/// Detection strategy (in priority order):
/// 1. `/etc/dcentos/board_target` (Buildroot post-build evidence — most
///    authoritative; `am1-s9` / `am1-s17` / `am2-s19j`).
/// 2. Device-tree model string when it contains product evidence.
/// 3. Exact UIO role names: chain6..8 can identify S9, but chain1..4 only
///    identifies the shared AM2 capability fabric and remains ambiguous
///    between S17 and S19-family products.
///
/// Returns `None` when detection is ambiguous so the constructor refuses
/// chain init instead of routing to a default fan/voltage backend.
fn detect_zynq_variant(devices: &[UioInfo]) -> Option<ZynqVariant> {
    let board_target = read_board_target_string();
    let dt_model = std::fs::read_to_string("/proc/device-tree/model").ok();
    detect_zynq_variant_from_evidence(devices, board_target.as_deref(), dt_model.as_deref())
}

fn detect_zynq_variant_from_evidence(
    devices: &[UioInfo],
    board_target: Option<&str>,
    dt_model: Option<&str>,
) -> Option<ZynqVariant> {
    if let Some(v) = detect_zynq_variant_from_board_target(board_target) {
        tracing::info!(variant = ?v, source = "board_target", "Zynq variant detected");
        return Some(v);
    }

    // Device-tree product identity is stronger than the shared AM2 chain
    // topology. A live S17 Pro and S19-family boards both expose chain1..4.
    if let Some(model) = dt_model {
        let model = model.trim().trim_end_matches('\0');
        let normalized = normalize_model_token(model);
        if let Some(v) = detect_zynq_variant_from_dt_model(&normalized) {
            tracing::info!(variant = ?v, source = "device_tree", model = %model, "Zynq variant detected");
            return Some(v);
        }
    }

    // UIO names can uniquely identify S9's chain6..8 topology, but chain1..4
    // identifies only AM2 capabilities—not whether the attached miner is S17
    // or S19. Mixed evidence is contradictory and must not be resolved by
    // preference.
    let has_chain1 = devices.iter().any(|d| chain_role(&d.name, 1).is_some());
    let has_chain6 = devices.iter().any(|d| chain_role(&d.name, 6).is_some());

    if has_chain1 && has_chain6 {
        tracing::warn!(
            source = "uio_chain_conflict",
            "mixed S9 and AM2 chain UIO evidence; refusing variant selection"
        );
        return None;
    }

    if has_chain6 {
        tracing::info!(source = "uio_chain6", "Zynq variant detected: S9");
        return Some(ZynqVariant::S9);
    }
    if has_chain1 {
        tracing::warn!(
            source = "uio_am2_ambiguous",
            "AM2 chain1..4 topology cannot distinguish S17 from S19; exact identity required"
        );
        return None;
    }
    tracing::warn!("Zynq variant detection inconclusive; refusing default route");
    None
}

/// Read `/etc/dcentos/board_target` if present. Trimmed string or None.
fn read_board_target_string() -> Option<String> {
    fs::read_to_string("/etc/dcentos/board_target")
        .ok()
        .map(|s| s.trim().to_string())
}

/// Pure helper: map a `board_target` value to a `ZynqVariant`.
///
/// Returns `None` for non-Zynq targets (am3-aml / am3-bb / am3-s19k / am3-s21
/// / etc.) so the platform constructor falls through to UIO/DT detection
/// rather than misclassifying.
///
/// SoC-mapping note (CANONICAL, ):
/// `am1` = Zynq 7010 (S9 family), `am2` = Zynq 7007S (S17/S19/S19j family).
///
/// Token contract — read before touching the match arm:
/// - `"am2-s17"` is the LIVE legacy control-board identifier for the
///   **S19-family** am2 boards (the silkscreen on this control board says
///   "S17", but the silicon is a 7007S running S19/S19 Pro/S19j Pro hash
///   boards). It is a live, tested, used token and is pinned to
///   `ZynqVariant::S19` below — never repurpose it for the S17 *miner*.
/// - `"am1-s17"` is a legacy chain-layout label (S9-lineage s9io UIO map),
///   NOT an am1 SoC assertion — S17 silicon is a 7007S = am2. Pinned to
///   `ZynqVariant::S17`.
/// - The S17 *miner* (BM1397, the actual S17/S17 Pro chassis) uses the
///   variant key `"am2-s17p"` — the Phase 2E `am2-s17pro-zynq` Buildroot
///   variant's `board_target` — never plain `"am2-s17"`. Pinned to
///   `ZynqVariant::S17` (Phase 2K / DevOps-F3).
/// Do NOT remap `am1-s17` or `am2-s17` to a new defconfig here: those
/// tokens are the contract written by the post-build overlays, consumed by
/// toolbox route keys, and pinned by the unit tests in this module.
fn detect_zynq_variant_from_board_target(target: Option<&str>) -> Option<ZynqVariant> {
    let token = target?.trim();
    match token {
        "am1-s9" => Some(ZynqVariant::S9),
        // "am1-s17" = S9-lineage chain layout label; "am2-s17p" = the S17
        // miner (BM1397) Phase 2E am2-s17pro-zynq board_target. Both map to
        // ZynqVariant::S17. NOTE: plain "am2-s17" below is the S19-family
        // legacy control-board id and stays ZynqVariant::S19.
        "am1-s17"
        | "am2-s17p"
        | "am2-s17plus"
        | "am2-t17"
        | "am2-t17plus"
        | "x17-s17e-dspic-planned"
        | "x17-t17e-pic16-planned" => Some(ZynqVariant::S17),
        // "am2-s19" = Antminer S19 BASE (S19 Standard) board_target. It is the
        // toolbox `stock-am2-s19-*` route's board_target and rides the same
        // am2/BM1398/ZynqVariant::S19 path as S19 Pro (differing only in
        // binning, which dcentrald enumerates at runtime). Made first-class
        // here 2026-07-02 so a base-S19 resolves via the authoritative
        // board_target dispatch, not only the weaker DT-model heuristic.
        // `am2-s19jpro-zynq` is the CANONICAL beta S19j Pro board_target (
        // skus.conf, the beta gate) — it MUST resolve here, not fall through to the
        // S9 fail-safe. The overlay currently stamps the shorter `am2-s19j` (also
        // matched), but a unit stamping the canonical string would otherwise be
        // mis-routed to the S9 variant (wrong chain init on a BM1362 board -> no
        // mining). Additive: cannot affect the proven `am2-s19j` path.
        "am2-s17" | "am2-s19" | "am2-s19j" | "am2-s19jpro" | "am2-s19jpro-zynq" | "am2-s19pro"
        | "am2-t19" => Some(ZynqVariant::S19),
        _ => None,
    }
}

/// Pure helper: map a normalized device-tree model token to a `ZynqVariant`.
///
/// `model` is expected to be lowercased + alnum-only (see `normalize_model_token`).
/// Exact product evidence wins over carrier naming. A bare `am2` model, or the
/// historically overloaded `am2-s17` combination, is ambiguous and cannot
/// authorize S19-only behavior when installed target identity is absent.
fn detect_zynq_variant_from_dt_model(model: &str) -> Option<ZynqVariant> {
    if model.contains("am2") {
        if model.contains("s19") || model.contains("t19") {
            return Some(ZynqVariant::S19);
        }
        return None;
    }
    if model.contains("am1s17") {
        return Some(ZynqVariant::S17);
    }
    if model.contains("am1s9") {
        return Some(ZynqVariant::S9);
    }
    // Chip-family fallbacks. The am2/am1 prefix is preferred above; these
    // run only when no platform prefix is present in the model string.
    if model.contains("s19") || model.contains("t19") {
        return Some(ZynqVariant::S19);
    }
    if model.contains("s17") || model.contains("t17") {
        return Some(ZynqVariant::S17);
    }
    if model.contains("s9") || model.contains("t9") {
        return Some(ZynqVariant::S9);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uio(number: u8, name: &str) -> UioInfo {
        UioInfo {
            number,
            name: name.to_string(),
        }
    }

    fn chain_group(chain_id: u8, base: u8) -> Vec<UioInfo> {
        vec![
            uio(base, &format!("chain{chain_id}-common")),
            uio(base + 1, &format!("chain{chain_id}-cmd-rx")),
            uio(base + 2, &format!("chain{chain_id}-work-rx")),
            uio(base + 3, &format!("chain{chain_id}-work-tx")),
        ]
    }

    #[test]
    fn exact_fabric_topology_requires_every_named_role_and_rejects_mixed_census() {
        let mut s9 = Vec::new();
        for (chain_id, base) in [(6, 1), (7, 5), (8, 9)] {
            s9.extend(chain_group(chain_id, base));
        }
        assert_eq!(
            exact_zynq_fabric_topology(&s9),
            Some(ZynqFabricTopology::S9)
        );

        let mut am2 = Vec::new();
        for (chain_id, base) in [(1, 0), (2, 4), (3, 8), (4, 12)] {
            am2.extend(chain_group(chain_id, base));
        }
        assert_eq!(
            exact_zynq_fabric_topology(&am2),
            Some(ZynqFabricTopology::Am2)
        );

        // Partial population resolves the fabric: chain8 is incomplete but
        // chain6/chain7 remain exact, which is a normal 2-populated S9. This
        // MUST match `admit_chain_uio_topology`, otherwise the availability
        // failure is relocated into route admission instead of fixed.
        let mut partially_populated = s9.clone();
        partially_populated.retain(|device| device.name != "chain8-work-tx");
        assert_eq!(
            exact_zynq_fabric_topology(&partially_populated),
            Some(ZynqFabricTopology::S9)
        );

        // Relaxing the COUNT must not relax EXACTNESS: roles present but no
        // single complete group anywhere still fails closed.
        let mut no_complete_group = Vec::new();
        for (chain_id, base) in [(6, 1), (7, 5), (8, 9)] {
            let mut group = chain_group(chain_id, base);
            group.retain(|device| !device.name.ends_with("work-tx"));
            no_complete_group.extend(group);
        }
        assert_eq!(exact_zynq_fabric_topology(&no_complete_group), None);

        let mut mixed = s9;
        mixed.extend(chain_group(1, 20));
        assert_eq!(exact_zynq_fabric_topology(&mixed), None);
    }

    /// The two live AM2 censuses must resolve to `Am2` here as well, not just
    /// in `admit_chain_uio_topology` — otherwise `detect_control_board` reports
    /// "Zynq ambiguous" and AM2 route admission refuses to mine.
    #[test]
    fn live_partial_am2_censuses_resolve_the_fabric_for_route_admission() {
        // `a lab unit`: only chain2 (uio4-7) and chain4 (uio12-15) are complete.
        let mut xil_109 = Vec::new();
        xil_109.extend(chain_group(2, 4));
        xil_109.extend(chain_group(4, 12));
        assert_eq!(
            exact_zynq_fabric_topology(&xil_109),
            Some(ZynqFabricTopology::Am2)
        );

        // `a lab unit`: chain1-work-tx unbound to free IRQ 165 for `of_serial`.
        let mut xil_25 = chain_group(1, 0);
        xil_25.retain(|d| !d.name.ends_with("work-tx"));
        xil_25.extend(chain_group(2, 4));
        assert_eq!(
            exact_zynq_fabric_topology(&xil_25),
            Some(ZynqFabricTopology::Am2)
        );
    }

    #[test]
    fn test_zynq_variant_s17_disambiguation() {
        // board_target file is the most authoritative — assert all three
        // canonical strings disambiguate cleanly.
        assert_eq!(
            detect_zynq_variant_from_board_target(Some("am1-s9")),
            Some(ZynqVariant::S9)
        );
        assert_eq!(
            detect_zynq_variant_from_board_target(Some("am1-s17")),
            Some(ZynqVariant::S17)
        );
        assert_eq!(
            detect_zynq_variant_from_board_target(Some("am2-s17")),
            Some(ZynqVariant::S19)
        );
        assert_eq!(
            detect_zynq_variant_from_board_target(Some("am2-s19j")),
            Some(ZynqVariant::S19)
        );
        // The CANONICAL beta S19j Pro board_target (skus.conf /  /
        // beta gate) MUST resolve to S19, not fall through to the S9 fail-safe.
        assert_eq!(
            detect_zynq_variant_from_board_target(Some("am2-s19jpro-zynq")),
            Some(ZynqVariant::S19)
        );
        // Phase 2D am2-s19pro-zynq variant board_target — pins to S19.
        assert_eq!(
            detect_zynq_variant_from_board_target(Some("am2-s19pro")),
            Some(ZynqVariant::S19)
        );
        // Antminer S19 BASE (S19 Standard) board_target — first-class 2026-07-02
        // (was previously None → resolved only via the DT-model heuristic).
        assert_eq!(
            detect_zynq_variant_from_board_target(Some("am2-s19")),
            Some(ZynqVariant::S19)
        );
        // Phase 2E am2-s17pro-zynq variant board_target — the S17 miner
        // (BM1397) MUST route to ZynqVariant::S17, NOT fall through to the
        // S19 DT-model branch (DevOps-F3 / Phase 2K). "am2-s17p" is the
        // literal string written by board/zynq/am2-s17pro/post-build.sh.
        assert_eq!(
            detect_zynq_variant_from_board_target(Some("am2-s17p")),
            Some(ZynqVariant::S17)
        );
        assert_eq!(
            detect_zynq_variant_from_board_target(Some("am2-s17plus")),
            Some(ZynqVariant::S17)
        );
        assert_eq!(
            detect_zynq_variant_from_board_target(Some("am2-t17")),
            Some(ZynqVariant::S17)
        );
        assert_eq!(
            detect_zynq_variant_from_board_target(Some("am2-t17plus")),
            Some(ZynqVariant::S17)
        );
        assert_eq!(
            detect_zynq_variant_from_board_target(Some("x17-s17e-dspic-planned")),
            Some(ZynqVariant::S17)
        );
        assert_eq!(
            detect_zynq_variant_from_board_target(Some("x17-t17e-pic16-planned")),
            Some(ZynqVariant::S17)
        );
        assert_eq!(
            detect_zynq_variant_from_board_target(Some("am2-t19")),
            Some(ZynqVariant::S19)
        );

        // Trim whitespace (Buildroot post-build writes a trailing newline).
        assert_eq!(
            detect_zynq_variant_from_board_target(Some("  am1-s17\n")),
            Some(ZynqVariant::S17)
        );

        // Non-Zynq platforms must return None so the platform constructor
        // can fall through to UIO/DT detection rather than misclassify.
        assert_eq!(detect_zynq_variant_from_board_target(Some("am3-bb")), None);
        assert_eq!(detect_zynq_variant_from_board_target(Some("am3-s21")), None);
        assert_eq!(
            detect_zynq_variant_from_board_target(Some("am3-s19k")),
            None
        );
        assert_eq!(detect_zynq_variant_from_board_target(Some("")), None);
        assert_eq!(detect_zynq_variant_from_board_target(None), None);
    }

    #[test]
    fn board_target_resolution_fails_closed_on_garbage() {
        // A corrupt / malformed / partial board_target read (bit-rot, a truncated
        // file, a hand-edit typo, a near-miss non-canonical token) MUST resolve to
        // None so the caller falls through to UIO/DT detection and ultimately
        // refuses if no independent evidence exists. A garbage token must never
        // be silently accepted as a known variant — accepting one
        // that mapped an S9 board to ZynqVariant::S19 would command S19's ~13.7 V
        // onto S9 (~9.1 V) silicon.
        // NOTE: `am2-s19jpro-zynq` is NOT garbage — it is the canonical beta S19j
        // Pro board_target and MUST route to S19 (asserted positively below). It was
        // wrongly listed here before; a genuine near-miss like `am2-s19jZZZ` covers
        // the fail-closed case instead.
        for bad in [
            "garbage",
            "am2-xyz",
            "am1-s99",
            "s19",
            "am2",
            "am1",
            "am2-s19jZZZ",
            "AM1-S9",
            "am1_s9",
            "am2-s19jpro-zynqXX",
            "0x1387",
            "-",
            "  \t ",
            "\0",
        ] {
            assert_eq!(
                detect_zynq_variant_from_board_target(Some(bad)),
                None,
                "garbage board_target '{bad}' must fail closed (None), not route to a variant"
            );
        }
    }

    #[test]
    fn test_zynq_variant_dt_model_disambiguation() {
        // The overloaded AM2+S17 carrier/model string is not product identity.
        assert_eq!(
            detect_zynq_variant_from_dt_model("am2s17minercontrolboard"),
            None
        );
        assert_eq!(detect_zynq_variant_from_dt_model("am2controlboard"), None);
        assert_eq!(
            detect_zynq_variant_from_dt_model("am2s19minercontrolboard"),
            Some(ZynqVariant::S19)
        );
        assert_eq!(
            detect_zynq_variant_from_dt_model("am1s17minercontrolboard"),
            Some(ZynqVariant::S17)
        );
        assert_eq!(
            detect_zynq_variant_from_dt_model("am1s9minercontrolboard"),
            Some(ZynqVariant::S9)
        );

        // Chip-family fallbacks (no am1/am2 prefix in DT).
        assert_eq!(
            detect_zynq_variant_from_dt_model("antminers17pro"),
            Some(ZynqVariant::S17)
        );
        assert_eq!(
            detect_zynq_variant_from_dt_model("antminers9"),
            Some(ZynqVariant::S9)
        );
    }

    #[test]
    fn zynq_uio_chain1_topology_alone_is_product_ambiguous() {
        let devices = [uio(1, "chain1-common"), uio(16, "fan-control")];

        let variant = detect_zynq_variant_from_evidence(&devices, None, None);

        assert_eq!(variant, None);
        assert_eq!(
            detect_zynq_variant_from_evidence(&devices, Some("am2-s19pro"), None),
            Some(ZynqVariant::S19)
        );
        assert_eq!(
            detect_zynq_variant_from_evidence(&devices, None, Some("Antminer S17 Pro")),
            Some(ZynqVariant::S17)
        );
    }

    #[test]
    fn zynq_mixed_chain_evidence_fails_closed() {
        let devices = [
            uio(1, "chain1-common"),
            uio(6, "chain6-common"),
            uio(16, "fan-control"),
        ];

        assert_eq!(
            detect_zynq_variant_from_evidence(&devices, None, None),
            None
        );
    }

    #[test]
    fn zynq_chain10_name_does_not_alias_chain1_product_evidence() {
        let devices = [uio(6, "chain6-common"), uio(10, "chain10-common")];

        assert_eq!(
            detect_zynq_variant_from_evidence(&devices, None, None),
            Some(ZynqVariant::S9)
        );
    }

    #[test]
    fn zynq_chain6_or_dt_can_still_route_s9_s17_explicitly() {
        assert_eq!(
            detect_zynq_variant_from_evidence(&[uio(6, "chain6-common")], None, None),
            Some(ZynqVariant::S9)
        );
        assert_eq!(
            detect_zynq_variant_from_evidence(
                &[uio(6, "chain6-common")],
                None,
                Some("Antminer S17 Pro")
            ),
            Some(ZynqVariant::S17)
        );
    }

    #[test]
    fn zynq_inconclusive_uio_detection_refuses_default_variant() {
        assert_eq!(detect_zynq_variant_from_evidence(&[], None, None), None);
        assert_eq!(
            detect_zynq_variant_from_evidence(&[uio(0, "fan-control")], None, None),
            None
        );
    }

    #[test]
    fn test_tokio_config_per_variant() {
        // S17's smaller RAM (228 MB vs 512 MB on S9) demands a tighter
        // blocking pool. Workers stay at 2 (dual-core CPU shared with S9/S19).
        assert_eq!(ZynqVariant::S17.tokio_worker_threads(), 2);
        assert_eq!(ZynqVariant::S17.tokio_max_blocking_threads(), 4);
        assert_eq!(ZynqVariant::S9.tokio_worker_threads(), 2);
        assert_eq!(ZynqVariant::S9.tokio_max_blocking_threads(), 512);
        assert_eq!(ZynqVariant::S19.tokio_worker_threads(), 2);
        assert_eq!(ZynqVariant::S19.tokio_max_blocking_threads(), 512);
    }

    #[test]
    fn test_fan_variant_per_zynq_variant() {
        assert_eq!(ZynqVariant::S9.fan_variant(), FanVariant::Am1S9);
        assert_eq!(ZynqVariant::S17.fan_variant(), FanVariant::Am2Uio16);
        assert_eq!(ZynqVariant::S19.fan_variant(), FanVariant::Am2Uio16);
        assert_eq!(
            ZynqVariant::S17.fan_mode_policy(),
            Am2FanModePolicy::Preserve
        );
        assert_eq!(
            ZynqVariant::S19.fan_mode_policy(),
            Am2FanModePolicy::EnableC52
        );
    }

    #[test]
    fn test_am2_specific_ips_exist_on_s17_and_s19() {
        // board-control + glitch-monitor IPs are am2 bitstream-only.
        assert!(!ZynqVariant::S9.has_board_control_ip());
        assert!(ZynqVariant::S17.has_board_control_ip());
        assert!(ZynqVariant::S19.has_board_control_ip());

        assert!(!ZynqVariant::S9.has_glitch_monitor_ip());
        assert!(ZynqVariant::S17.has_glitch_monitor_ip());
        assert!(ZynqVariant::S19.has_glitch_monitor_ip());
    }

    #[test]
    fn held_s17_uio_census_maps_all_four_logical_slots_exactly() {
        let mut devices = Vec::new();
        for (chain_id, base) in [(1, 0), (2, 4), (3, 8), (4, 12)] {
            devices.extend(chain_group(chain_id, base));
        }
        assert_eq!(discover_chain_uio_base(&devices, 1), Some(0));
        assert_eq!(discover_chain_uio_base(&devices, 2), Some(4));
        assert_eq!(discover_chain_uio_base(&devices, 3), Some(8));
        assert_eq!(discover_chain_uio_base(&devices, 4), Some(12));
        assert_eq!(discover_chain_uio_base(&devices, 6), None);
    }

    #[test]
    fn exact_chain_roles_reject_aliases_duplicates_and_noncontiguous_groups() {
        let chain10 = chain_group(10, 0);
        assert_eq!(discover_chain_uio_base(&chain10, 1), None);

        let mut duplicate = chain_group(1, 0);
        duplicate.push(uio(20, "chain1-common"));
        assert_eq!(discover_chain_uio_base(&duplicate, 1), None);

        let mut noncontiguous = chain_group(1, 0);
        noncontiguous[3].number = 9;
        assert_eq!(discover_chain_uio_base(&noncontiguous, 1), None);

        let s9 = chain_group(6, 0);
        assert_eq!(discover_chain_uio_base(&s9, 6), Some(0));
        assert_eq!(discover_chain_uio_base(&s9, 1), None);
    }

    /// LOAD-BEARING availability regression.
    ///
    /// A strict "all four groups must be present" rule takes both live-proven
    /// XIL units offline inside `ZynqPlatform::new()` — *before* power
    /// admission, so it is a hard abort rather than a degrade. Pin the two
    /// captured censuses directly.
    #[test]
    fn partially_populated_am2_censuses_from_live_units_are_admitted() {
        // `a lab unit` live census (probe-report.md): ONLY chain2 (uio4-7) and
        // chain4 (uio12-15) are complete. chain1/chain3 are absent entirely.
        let mut xil_109 = Vec::new();
        xil_109.extend(chain_group(2, 4));
        xil_109.extend(chain_group(4, 12));
        xil_109.push(uio(16, "fan-control"));
        xil_109.push(uio(17, "board-control"));
        xil_109.push(uio(18, "miner-glitch-monitor"));

        let mapped = admit_chain_uio_topology(&xil_109, ZynqVariant::S19, &AM2_CHAIN_IDS)
            .expect("`a lab unit` two-complete-group census must be admitted, not refused");
        assert_eq!(mapped.len(), 2, "only the complete groups are mapped");
        assert_eq!(mapped.get(&2), Some(&4));
        assert_eq!(mapped.get(&4), Some(&12));
        assert_eq!(mapped.get(&1), None);

        // `a lab unit` in its proven standalone-mining configuration: chain1-work-tx
        // (uio3) is deliberately unbound to free IRQ 165 for `of_serial`, so
        // chain1 is structurally incomplete while chain2 stays whole.
        let mut xil_25 = chain_group(1, 0);
        xil_25.retain(|d| !d.name.ends_with("work-tx"));
        xil_25.extend(chain_group(2, 4));
        xil_25.push(uio(16, "fan-control"));

        let mapped = admit_chain_uio_topology(&xil_25, ZynqVariant::S19, &AM2_CHAIN_IDS)
            .expect("`a lab unit` unbound work-tx census must be admitted, not refused");
        assert_eq!(
            mapped.get(&1),
            None,
            "an incomplete group must not be mapped"
        );
        assert_eq!(
            mapped.get(&2),
            Some(&4),
            "the surviving complete group must still be usable"
        );
    }

    /// The S9 positional fallback must never place a chain on uio0, which the
    /// live census shows is `fan-control`. `FpgaChain::open` maps
    /// `base..base+3`, so an off-by-one here writes hash-chain commands into
    /// the fan controller.
    #[test]
    fn s9_positional_fallback_uses_live_bases_and_never_maps_a_chain_onto_fan_control() {
        // 14 unnamed devices: name-based discovery finds nothing, so the
        // positional fallback is the only path that can populate the map.
        let unnamed: Vec<UioInfo> = (0..14).map(|n| uio(n, "unknown-ip")).collect();
        let mapped = admit_chain_uio_topology(&unnamed, ZynqVariant::S9, &S9_CHAIN_IDS)
            .expect("S9 positional fallback must still apply for a >=12 device census");

        assert_eq!(mapped.get(&6), Some(&1), "chain6 base is uio1, not uio0");
        assert_eq!(mapped.get(&7), Some(&5));
        assert_eq!(mapped.get(&8), Some(&9));
        assert!(
            !mapped.values().any(|&base| base == 0),
            "uio0 is fan-control on live S9 — no chain may be mapped onto it"
        );
    }

    #[test]
    fn a_fabric_with_no_complete_chain_group_still_fails_closed() {
        // Relaxing the count must not relax exactness: roles present but
        // non-contiguous yields zero complete groups and must refuse.
        let mut broken = chain_group(1, 0);
        broken[3].number = 9;
        broken.push(uio(16, "fan-control"));
        assert!(
            admit_chain_uio_topology(&broken, ZynqVariant::S19, &AM2_CHAIN_IDS).is_err(),
            "zero complete groups must fail closed"
        );
    }
}
