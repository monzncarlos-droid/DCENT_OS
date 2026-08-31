//! FPGA interface module for dcentrald mining daemon.
//!
//! Provides the top-level FPGA abstraction that ties together UIO device
//! management, multi-chain orchestration, interrupt-driven I/O, and the
//! complete register interface for the Braiins s9io v1.0.2 FPGA bitstream.
//!
//! Live S9 UIO census, baud helpers, and PL surface reports. Hardware
//! ownership is name-based `dcentrald_hal::platform::zynq::ZynqPlatform`
//! discovery — not positional `FAN_UIO=0` / `S9_UIO_BASES=[1,5,9]`.
//!
//! # Architecture
//!
//! The S9 FPGA has 14 UIO devices (verified from live probe):
//!
//! ```text
//! uio0:  fan-control       0x42800000  AXI Timer PWM
//! uio1:  chain6-common     0x43C00000  Common registers (VERSION, CTRL, BAUD, etc.)
//! uio2:  chain6-cmd-rx     0x43C01000  CMD RX+TX FIFOs (ASIC register access)
//! uio3:  chain6-work-rx    0x43C02000  Work RX FIFO (nonce responses)
//! uio4:  chain6-work-tx    0x43C03000  Work TX FIFO (job submission)
//! uio5:  chain7-common     0x43C10000
//! uio6:  chain7-cmd-rx     0x43C11000
//! uio7:  chain7-work-rx    0x43C12000
//! uio8:  chain7-work-tx    0x43C13000
//! uio9:  chain8-common     0x43C20000
//! uio10: chain8-cmd-rx     0x43C21000
//! uio11: chain8-work-rx    0x43C22000
//! uio12: chain8-work-tx    0x43C23000
//! uio13: miner-glitch-monitor 0x43D00000
//! ```
//!
//! # FPGA Clock
//!
//! The FPGA fabric runs at 200 MHz (100 MHz FCLK doubled by PL PLL).
//! Baud rate formula: `baud = 200_000_000 / (16 * (BAUD_REG + 1))`
//!
//! # Safety
//!
//! Accessing unmapped FPGA address space causes AXI external abort faults
//! that crash the process. All register access is bounds-checked to the 4 KB
//! UIO mapping. Stay within documented register offsets.

use std::fmt;
use std::fs;
use std::os::fd::RawFd;

use dcentrald_hal::fpga_chain::{self, FpgaChain};
use dcentrald_hal::pl_surface::{parse_uio_sysfs_hex, PlSurfaceReport};

use tracing::info;

// ---------------------------------------------------------------------------
// S9 hardware constants (verified from live probe)
// ---------------------------------------------------------------------------

/// Number of hash chains on a Zynq S9 control board.
pub const S9_CHAIN_COUNT: usize = 3;

/// Chain IDs matching physical connector labels (J6, J7, J8).
pub const S9_CHAIN_IDS: [u8; S9_CHAIN_COUNT] = [6, 7, 8];

/// Live S9 UIO census pin (uio1/5/9 = chain6/7/8). **Not a discovery
/// fallback.** Name-based `ZynqPlatform` admission is required; positional
/// mapping of unnamed devices is forbidden (DESK_NOW 2026-08-19).
pub const S9_UIO_BASES: [u8; S9_CHAIN_COUNT] = [1, 5, 9];

/// Live S9 census: uio0 is `fan-control`. **Not** a constructor argument.
/// AM2 fan-control is a different UIO (`fan-control` by name, typically 16).
pub const FAN_UIO: u8 = 0;

/// Live S9 census: uio13 is `miner-glitch-monitor`. Not a discovery fallback.
pub const GLITCH_MONITOR_UIO: u8 = 13;

/// **S9 (am1) bitstream** FPGA fabric clock frequency in Hz.
/// 100 MHz FCLK doubled by PL PLL = 200 MHz — an S9-only derivation. The
/// S19j Pro (am2) FCLK0 is 100 MHz (live probe,
/// :587,596`);
/// do NOT apply this constant's Hz math to a non-S9 carrier. Per-carrier
/// declared values: `dcentrald_hal::fpga_chain::CARRIER_FIFO_FABRIC` (W8 CLK-1).
pub const FPGA_CLK_HZ: u32 = 200_000_000;

// W8 CLK-1: this constant duplicates the HAL's S9-scoped value. Pin them
// together at compile time so the two copies can never drift apart silently.
const _: () = assert!(FPGA_CLK_HZ == dcentrald_hal::fpga_chain::FPGA_CLK_HZ);

/// PIC I2C addresses for S9 chains 6, 7, 8 (verified from live probe).
pub const S9_PIC_ADDRS: [u8; S9_CHAIN_COUNT] = [0x55, 0x56, 0x57];

// ---------------------------------------------------------------------------
// FPGA version identification
// ---------------------------------------------------------------------------

/// Decoded FPGA version info from the VERSION register.
#[derive(Debug, Clone)]
pub struct FpgaVersion {
    /// Raw register value.
    pub raw: u32,
    /// Miner model identifier (e.g., 0x09 for S9).
    pub model: u8,
    /// Major version.
    pub major: u8,
    /// Minor version.
    pub minor: u8,
    /// Patch level.
    pub patch: u8,
}

impl FpgaVersion {
    /// Decode the VERSION register (format verified from live S9: 0x00901002).
    pub fn from_raw(raw: u32) -> Self {
        Self {
            raw,
            model: ((raw >> 20) & 0xFF) as u8,
            major: ((raw >> 12) & 0x0F) as u8,
            minor: ((raw >> 8) & 0x0F) as u8,
            patch: (raw & 0xFF) as u8,
        }
    }

    /// Check if this VERSION word *looks* like an S9 bitstream.
    ///
    /// **Not a fabric-class gate.** `0x00901002` is also live AM2 CTRL at +0x00.
    /// Discriminator is BUILD_ID (`dcentrald_hal::pl_surface::admit_fabric_class`).
    pub fn is_s9(&self) -> bool {
        self.model == 0x09 || self.raw == 0x00901002
    }
}

impl fmt::Display for FpgaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Model 0x{:02X} v{}.{}.{} (raw: 0x{:08X})",
            self.model, self.major, self.minor, self.patch, self.raw
        )
    }
}

// `FpgaSubsystem` (and `FpgaSubsystem::init`) was deleted DESK_NOW 2026-08-19.
// It hardcoded FAN_UIO=0 and S9_UIO_BASES=[1,5,9] and could issue chain
// register writes into fan-control on a non-S9 UIO numbering. Use name-based
// `dcentrald_hal::platform::zynq::ZynqPlatform` discovery. Never write 0 to
// CTRL_REG after UART traffic.

// ---------------------------------------------------------------------------
// Baud rate utilities
// ---------------------------------------------------------------------------

/// Calculate baud rate from a divisor value.
///
/// Formula: `baud = FPGA_CLK_HZ / (16 * (divisor + 1))`
///
/// Common values:
///   - 0x6C (108) -> 114,679 baud (~115200, enumeration speed)
///   - 0x07 (7)   -> 1,562,500 baud (operational speed)
///   - 0x03 (3)   -> 3,125,000 baud (maximum tested)
pub fn baud_from_divisor(divisor: u32) -> u32 {
    FPGA_CLK_HZ / (16 * (divisor + 1))
}

/// Calculate divisor from a target baud rate.
///
/// Formula: `divisor = FPGA_CLK_HZ / (16 * baud) - 1`
pub fn divisor_from_baud(baud: u32) -> u32 {
    if baud == 0 {
        return 0xFFFF_FFFF; // prevent division by zero
    }
    (FPGA_CLK_HZ / (16 * baud)).saturating_sub(1)
}

// ---------------------------------------------------------------------------
// UIO IRQ support for async nonce collection
// ---------------------------------------------------------------------------

/// IRQ-capable UIO wrapper for interrupt-driven nonce collection.
///
/// The FPGA fires interrupts when:
/// - Work TX FIFO drops below threshold (ready for more work)
/// - Work RX FIFO has nonce data (nonces found by ASICs)
/// - CMD RX FIFO has command response data
///
/// Using IRQs instead of polling dramatically reduces CPU usage during
/// mining. The UIO kernel driver handles IRQ masking/unmasking via the
/// UIO file descriptor.
pub struct UioIrq {
    /// The UIO device (already mmap'd for register access).
    fd: RawFd,
}

impl UioIrq {
    /// Create an IRQ handle from a UIO device's raw file descriptor.
    ///
    /// The caller retains ownership of the UIO device. This struct
    /// only borrows the file descriptor for IRQ operations.
    pub fn from_raw_fd(fd: RawFd) -> Self {
        Self { fd }
    }

    /// Enable (re-arm) the interrupt on this UIO device.
    ///
    /// Must be called once before the first wait, and again after
    /// each interrupt fires.
    pub fn enable(&self) -> std::io::Result<()> {
        let val: u32 = 1;
        let ret = unsafe {
            libc::write(
                self.fd,
                &val as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>(),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Block until an interrupt fires on this UIO device.
    ///
    /// Returns the cumulative interrupt count since device open.
    /// This is a blocking call -- in an async context, run on a
    /// dedicated thread or use `tokio::task::spawn_blocking`.
    pub fn wait(&self) -> std::io::Result<u32> {
        let mut count: u32 = 0;
        let ret = unsafe {
            libc::read(
                self.fd,
                &mut count as *mut u32 as *mut libc::c_void,
                std::mem::size_of::<u32>(),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if ret != 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("UIO IRQ read returned {} bytes, expected 4", ret),
            ));
        }
        Ok(count)
    }

    /// Get the raw file descriptor for use with poll/epoll/select.
    ///
    /// The fd becomes readable when an interrupt fires. This allows
    /// integration with async I/O frameworks like tokio via
    /// `AsyncFd::new()`.
    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }
}

// ---------------------------------------------------------------------------
// UIO device discovery helpers
// ---------------------------------------------------------------------------

/// Information about a discovered UIO device.
#[derive(Debug, Clone)]
pub struct UioInfo {
    /// UIO device number (N in /dev/uioN).
    pub number: u8,
    /// Device name from /sys/class/uio/uioN/name.
    pub name: String,
    /// Physical address from /sys/class/uio/uioN/maps/map0/addr.
    pub phys_addr: Option<u64>,
    /// Mapping size from /sys/class/uio/uioN/maps/map0/size.
    pub map_size: Option<usize>,
}

impl UioInfo {
    /// Census report: name + kernel map0 addr/size. BUILD_ID stays `None`
    /// (sysfs cannot read common+0x04).
    pub fn to_pl_surface_report(&self) -> PlSurfaceReport {
        PlSurfaceReport::from_sysfs(
            self.name.clone(),
            self.phys_addr,
            self.map_size.map(|s| s as u64),
        )
    }
}

/// PL surface reports from the live UIO sysfs census. Missing map0 files
/// stay `None`; addresses are never invented.
pub fn pl_surface_reports() -> Vec<PlSurfaceReport> {
    scan_uio_devices()
        .iter()
        .map(UioInfo::to_pl_surface_report)
        .collect()
}

/// Scan /sys/class/uio/ for all available UIO devices.
///
/// Returns a sorted list of UIO devices with their names and addresses.
/// This is useful for diagnostics and auto-discovery of the FPGA layout.
pub fn scan_uio_devices() -> Vec<UioInfo> {
    let uio_dir = "/sys/class/uio";
    let mut devices = Vec::new();

    let entries = match fs::read_dir(uio_dir) {
        Ok(e) => e,
        Err(_) => return devices,
    };

    for entry in entries.flatten() {
        let dir_name = entry.file_name().to_string_lossy().to_string();
        if let Some(num_str) = dir_name.strip_prefix("uio") {
            if let Ok(number) = num_str.parse::<u8>() {
                let name = fs::read_to_string(format!("{}/{}/name", uio_dir, dir_name))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| format!("uio{}", number));

                let phys_addr =
                    fs::read_to_string(format!("{}/{}/maps/map0/addr", uio_dir, dir_name))
                        .ok()
                        .and_then(|s| parse_uio_sysfs_hex(&s));

                let map_size =
                    fs::read_to_string(format!("{}/{}/maps/map0/size", uio_dir, dir_name))
                        .ok()
                        .and_then(|s| parse_uio_sysfs_hex(&s).map(|n| n as usize));

                devices.push(UioInfo {
                    number,
                    name,
                    phys_addr,
                    map_size,
                });
            }
        }
    }

    devices.sort_by_key(|d| d.number);
    devices
}

/// Print a diagnostic dump of all UIO devices (for debug/hacker shell).
pub fn dump_uio_devices() {
    let devices = scan_uio_devices();
    info!("=== UIO Device Map ({} devices) ===", devices.len());
    for dev in &devices {
        let addr_str = dev
            .phys_addr
            .map(|a| format!("0x{:08X}", a))
            .unwrap_or_else(|| "???".into());
        let size_str = dev
            .map_size
            .map(|s| format!("0x{:X}", s))
            .unwrap_or_else(|| "???".into());
        info!(
            "  uio{:<3} {:24} addr={} size={}",
            dev.number, dev.name, addr_str, size_str
        );
    }
}

// ---------------------------------------------------------------------------
// FPGA register dump (diagnostics)
// ---------------------------------------------------------------------------

/// Read and log all common registers for a chain (diagnostic dump).
pub fn dump_chain_registers(chain: &FpgaChain) {
    let version = chain.common.read_reg(fpga_chain::REG_VERSION);
    let build_id = chain.common.read_reg(fpga_chain::REG_BUILD_ID);
    let ctrl = chain.common.read_reg(fpga_chain::REG_CTRL);
    let stat = chain.common.read_reg(fpga_chain::REG_STAT);
    let baud = chain.common.read_reg(fpga_chain::REG_BAUD);
    let work_time = chain.common.read_reg(fpga_chain::REG_WORK_TIME);
    let err_count = chain.common.read_reg(fpga_chain::REG_ERR_COUNTER);

    let cmd_stat = chain.cmd.read_reg(fpga_chain::REG_CMD_STAT);
    let work_rx_stat = chain.work_rx.read_reg(fpga_chain::REG_WORK_RX_STAT);
    let work_tx_stat = chain.work_tx.read_reg(fpga_chain::REG_WORK_TX_STAT);
    let work_tx_last = chain.work_tx.read_reg(fpga_chain::REG_WORK_TX_LAST);

    info!(
        chain_id = chain.chain_id,
        "Chain {} register dump:", chain.chain_id
    );
    info!(
        "  VERSION:     0x{:08X} ({})",
        version,
        FpgaVersion::from_raw(version)
    );
    info!("  BUILD_ID:    0x{:08X}", build_id);
    info!(
        "  CTRL_REG:    0x{:08X} [ENABLE={}, BM139X={}, MIDSTATE={}, ERR_CLR={}]",
        ctrl,
        (ctrl >> 3) & 1,
        (ctrl >> 4) & 1,
        (ctrl >> 1) & 3,
        ctrl & 1
    );
    info!("  STAT_REG:    0x{:08X}", stat);
    info!(
        "  BAUD_REG:    0x{:08X} ({} baud)",
        baud,
        baud_from_divisor(baud)
    );
    info!("  WORK_TIME:   0x{:08X}", work_time);
    info!("  ERR_COUNTER: {}", err_count);
    info!(
        "  CMD_STAT:    0x{:08X} [IRQ={} TX_FULL={} TX_EMPTY={} RX_FULL={} RX_EMPTY={}]",
        cmd_stat,
        (cmd_stat >> 4) & 1,
        (cmd_stat >> 3) & 1,
        (cmd_stat >> 2) & 1,
        (cmd_stat >> 1) & 1,
        cmd_stat & 1
    );
    info!(
        "  WORK_RX_STAT: 0x{:08X} [IRQ={} RX_FULL={} RX_EMPTY={}]",
        work_rx_stat,
        (work_rx_stat >> 4) & 1,
        (work_rx_stat >> 1) & 1,
        work_rx_stat & 1
    );
    info!(
        "  WORK_TX_STAT: 0x{:08X} [IRQ={} TX_FULL={} TX_EMPTY={}]",
        work_tx_stat,
        (work_tx_stat >> 4) & 1,
        (work_tx_stat >> 3) & 1,
        (work_tx_stat >> 2) & 1
    );
    info!("  WORK_TX_LAST: 0x{:08X}", work_tx_last);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baud_from_divisor() {
        // 0x6C = 108 -> 200_000_000 / (16 * 109) = 114,679
        assert_eq!(baud_from_divisor(0x6C), 114_678); // integer division
                                                      // 0x07 = 7 -> 200_000_000 / (16 * 8) = 1_562_500
        assert_eq!(baud_from_divisor(0x07), 1_562_500);
        // 0x03 = 3 -> 200_000_000 / (16 * 4) = 3_125_000
        assert_eq!(baud_from_divisor(0x03), 3_125_000);
    }

    #[test]
    fn test_divisor_from_baud() {
        assert_eq!(divisor_from_baud(115200), 107); // rounds to nearest
        assert_eq!(divisor_from_baud(1_562_500), 7);
        assert_eq!(divisor_from_baud(3_125_000), 3);
    }

    #[test]
    fn test_fpga_version_decode() {
        let v = FpgaVersion::from_raw(0x00901002);
        assert!(v.is_s9());
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 2);
    }

    #[test]
    fn test_divisor_from_baud_zero() {
        // Should not panic on zero baud
        let d = divisor_from_baud(0);
        assert_eq!(d, 0xFFFF_FFFF);
    }

    #[test]
    fn s9_uio_census_pins_are_not_a_discovery_fallback() {
        assert_eq!(S9_UIO_BASES, [1, 5, 9]);
        assert_eq!(FAN_UIO, 0);
        assert_eq!(GLITCH_MONITOR_UIO, 13);
        assert_eq!(S9_CHAIN_IDS, [6, 7, 8]);
        assert_eq!(S9_PIC_ADDRS, [0x55, 0x56, 0x57]);
    }

    #[test]
    fn s9_version_word_collides_with_am2_ctrl_build_id_is_discriminator() {
        use dcentrald_hal::pl_surface::{
            admit_fabric_class, FabricClass, BRAIINS_AM2_BITSTREAM_BUILD_ID,
            BRAIINS_S9IO_BITSTREAM_BUILD_ID, S9_VERSION_AM2_CTRL_COLLISION,
        };

        let v = FpgaVersion::from_raw(S9_VERSION_AM2_CTRL_COLLISION);
        assert!(
            v.is_s9(),
            "VERSION decode still sees 0x00901002; BUILD_ID must discriminate"
        );
        assert_eq!(
            dcentrald_hal::fpga_chain::ctrl_am2::BM1362_DEFAULT,
            S9_VERSION_AM2_CTRL_COLLISION
        );
        assert_ne!(
            BRAIINS_S9IO_BITSTREAM_BUILD_ID,
            BRAIINS_AM2_BITSTREAM_BUILD_ID
        );
        assert!(admit_fabric_class(S9_VERSION_AM2_CTRL_COLLISION, FabricClass::Am2).is_err());
        assert!(admit_fabric_class(BRAIINS_S9IO_BITSTREAM_BUILD_ID, FabricClass::Am2).is_err());
        assert!(admit_fabric_class(BRAIINS_AM2_BITSTREAM_BUILD_ID, FabricClass::Am2).is_ok());
    }

    #[test]
    fn uio_census_to_pl_surface_report_does_not_invent_addresses() {
        let named = UioInfo {
            number: 1,
            name: "chain6-common".into(),
            phys_addr: Some(0x43C0_0000),
            map_size: Some(0x1000),
        };
        let report = named.to_pl_surface_report();
        assert_eq!(report.name, "chain6-common");
        assert_eq!(report.physaddr, Some(0x43C0_0000));
        assert_eq!(report.size, Some(0x1000));
        assert_eq!(report.build_id, None);

        let missing = UioInfo {
            number: 0,
            name: "fan-control".into(),
            phys_addr: None,
            map_size: None,
        };
        let report = missing.to_pl_surface_report();
        assert_eq!(report.physaddr, None);
        assert_eq!(report.size, None);
        assert_ne!(report.physaddr, Some(0x4127_0000));
    }
}
