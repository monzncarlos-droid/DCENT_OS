//! Offline-only carrier and boot-preflight facts for the exact held L9 CVCtrl release.
//!
//! The held March-2026 component supplies an exact CV183x software tuple, an
//! ordered pinmux script, and a symbol-bearing `godminer` with a static
//! four-slot chain-routing table. Those facts are useful for clean-room replay,
//! but remain copyable software evidence. The FIT contains four generic board
//! configurations and the separately named `devicetree.dtb` is actually a PEM
//! public key. This module therefore opens no device and can never establish
//! board identity, exclusive ownership, rail safety, or mining authority.

pub const BM1491_L9_MERGE_BMU_SHA256: &str =
    "2af05a3465ae8f3bdb32a74058f8beb0c4f9246da409441e09d922f05c3aa827";
pub const BM1491_L9_MERGE_BMU_SIZE: u64 = 29_910_998;
pub const BM1491_L9_CVCTRL_COMPONENT_SHA256: &str =
    "4c997d2e20027827bda5262248d7877a34f145d7dcd700a7fc103f003b3dd1f3";
pub const BM1491_L9_CVCTRL_COMPONENT_SIZE: u64 = 13_341_654;
pub const BM1491_L9_ROOTFS_SHA256: &str =
    "e163b59d8865874d804a5091706499685ff85433c281bf368da1345979eacec3";
pub const BM1491_L9_ROOTFS_SIZE: u64 = 8_669_823;
pub const BM1491_L9_ROOTFS_IS_GZIP_CPIO: bool = true;
pub const BM1491_L9_ROOTFS_UNCOMPRESSED_SIZE: u64 = 20_039_680;
pub const BM1491_L9_ROOTFS_UNCOMPRESSED_SHA256: &str =
    "1de9301b867badf6bb3bd10db832d2ecf414355861ac29f38e518b4eb09ba667";
pub const BM1491_L9_FIT_SHA256: &str =
    "5b94c823d064306193f976bda973a3c01a494626a7cbe22c290a810425d6526a";
pub const BM1491_L9_FIT_SIZE: u64 = 4_665_826;
pub const BM1491_L9_GODMINER_SHA256: &str =
    "7b088dcb42a57f021a8448f27dcadbfef6f4c4e71652ac871393e9f73c038487";
pub const BM1491_L9_GODMINER_SIZE: u64 = 2_807_036;
pub const BM1491_L9_GODMINER_ELF_CLASS_BITS: u8 = 32;
pub const BM1491_L9_GODMINER_MACHINE: &str = "ARM EABI5 hard-float";
pub const BM1491_L9_GODMINER_BUILD_ID: &str = "ffdff776c6907282dee448f25ce3d0204abdeb26";
pub const BM1491_L9_FIT_KERNEL_ARCHITECTURE: &str = "AArch64";
pub const BM1491_L9_SETUP_SCRIPT_SHA256: &str =
    "11ed29eaefdf5a89fc5b85b65edb5fef15ef917064325fe4a591967fdf52d8bd";
pub const BM1491_L9_SETUP_SCRIPT_SIZE: u64 = 7_710;
pub const BM1491_L9_SUBTYPE_SHA256: &str =
    "5c455c46c405670417c62de9d2bb84dca3c972ca067f73698248dafb7351daf6";
pub const BM1491_L9_SUBTYPE_SIZE: u64 = 10;
pub const BM1491_L9_SUBTYPE: &str = "CVCtrl_L9";
pub const BM1491_L9_TOPOLOGY_SHA256: &str =
    "f0ea6b60c843ebf9f0ddffc74afb6e7848e8b1030006bf5561bfe5fe14af5da0";
pub const BM1491_L9_TOPOLOGY_SIZE: u64 = 2_627;
pub const BM1491_L9_MACHINE: &str = "BSL41601";
pub const BM1491_L9_PROCESSOR: &str = "CV183x";
pub const BM1491_L9_ASIC_NAME: &str = "BM1491";
pub const BM1491_L9_ASIC_ID: u16 = 0x1491;
pub const BM1491_L9_CONFIGURED_CHAIN_COUNT: usize = 3;
pub const BM1491_L9_CONFIGURED_ASICS_PER_CHAIN: u16 = 110;
pub const BM1491_L9_CONFIGURED_DOMAINS_PER_CHAIN: u8 = 22;
pub const BM1491_L9_CONFIGURED_ASICS_PER_DOMAIN: u8 = 5;
pub const BM1491_L9_CONFIGURED_ADDRESS_INTERVAL: u8 = 2;
pub const BM1491_L9_CONFIGURED_POWER_GPIO: u16 = 412;

pub const BM1491_L9_PWM_MODULE_SHA256: &str =
    "d3bc15991b53e8646cb667c26c7736e3bd785b3f6059b0eafc2e5cfb343f7136";
pub const BM1491_L9_PWM_MODULE_SIZE: u64 = 14_840;
pub const BM1491_L9_PWM_MODULE_VERMAGIC: &str =
    "4.9.38-00269-g8355fd4db SMP preempt mod_unload aarch64 ";
pub const BM1491_L9_BASE_MODULE_SHA256: &str =
    "be9bec653d3c9f6b29717d766ef82a32e346ef8d992b288fee4ece38cd1cb8ef";
pub const BM1491_L9_BASE_MODULE_SIZE: u64 = 43_728;
pub const BM1491_L9_BASE_MODULE_VERMAGIC: &str = "4.9.38-g214084e SMP preempt mod_unload aarch64 ";

/// Despite its filename, this exact component member starts with
/// `-----BEGIN PUBLIC KEY-----`, not the FDT magic `d00dfeed`.
pub const BM1491_L9_NAMED_DEVICETREE_SHA256: &str =
    "aabf3cc3da6008d90281adcc4f356920634198f2c6f104ed60547e720176653f";
pub const BM1491_L9_NAMED_DEVICETREE_SIZE: u64 = 2_933;
pub const BM1491_L9_NAMED_DEVICETREE_IS_FDT: bool = false;
/// The exact FIT `/configurations` node has four children but no `default`
/// property. `dumpimage` therefore cannot identify the resident boot choice.
pub const BM1491_L9_FIT_DEFAULT_CONFIGURATION_PRESENT: bool = false;
/// The update script copies the signed FIT verbatim to `/dev/mmcblk0p1`.
pub const BM1491_L9_UPDATE_WRITES_FIT_VERBATIM_TO_EMMC_PARTITION_ONE: bool = true;
/// The held update contains the miner rootfs and FIT, but not the resident
/// bootloader state that must select a configuration at boot.
pub const BM1491_L9_UPDATE_CONTAINS_BOOTLOADER_SELECTOR: bool = false;
pub const BM1491_L9_ACTIVE_FIT_CONFIGURATION_PROVEN: bool = false;
pub const BM1491_L9_PHYSICAL_BOARD_IDENTITY_PROVEN: bool = false;
pub const BM1491_L9_POWER_GPIO_PHYSICAL_LOAD_PROVEN: bool = false;
pub const BM1491_L9_CARRIER_AUTHORITY_AVAILABLE: bool = false;

pub const BM1491_L9_PLATFORM_INIT_ADDRESS: u32 = 0x0014_94a0;
pub const BM1491_L9_PLATFORM_UNINIT_ADDRESS: u32 = 0x0014_9a14;
pub const BM1491_L9_FPGA_INIT_ADDRESS: u32 = 0x0014_acdc;
pub const BM1491_L9_GPIO_INIT_ADDRESS: u32 = 0x0014_b0f4;
pub const BM1491_L9_UART_INIT_ADDRESS: u32 = 0x0014_e9d4;
pub const BM1491_L9_UART_SEND_ADDRESS: u32 = 0x0014_eea8;
pub const BM1491_L9_UART_RECEIVE_ADDRESS: u32 = 0x0014_f2e8;
pub const BM1491_L9_UART_SET_CONFIG_ADDRESS: u32 = 0x0014_fde0;
pub const BM1491_L9_DEV_CONFIG_ADDRESS: u32 = 0x0016_f6a4;
pub const BM1491_L9_MACHINE_RUNTIME_CTRL_ADDRESS: u32 = 0x0007_27e4;
pub const BM1491_L9_SET_BAUD_BASE_ADDRESS: u32 = 0x0007_330c;
pub const BM1491_L9_SET_BAUD_LTC_ADDRESS: u32 = 0x000f_8b40;
pub const BM1491_L9_CHIP_SETTING_BAUD_ADDRESS: u32 = 0x000f_c294;
pub const BM1491_L9_SET_CHIP_REGISTER_ADDRESS: u32 = 0x000f_adb8;
pub const BM1491_L9_HAL_CHAIN_UART_ADDRESS: u32 = 0x0015_2708;
pub const BM1491_L9_HAL_CHAIN_PLUG_ADDRESS: u32 = 0x0015_27a4;
pub const BM1491_L9_HAL_CHAIN_RESET_ADDRESS: u32 = 0x0015_2840;
pub const BM1491_L9_HAL_CHAIN_MAX_ADDRESS: u32 = 0x0015_28dc;

pub const BM1491_L9_I2C_DEVICE_ZERO: &str = "/dev/i2c-0";
pub const BM1491_L9_I2C_DEVICE_THREE: &str = "/dev/i2c-3";
pub const BM1491_L9_UART_OPEN_FLAGS: u32 = 0x0902;
pub const BM1491_L9_UART_INITIAL_TERMIOS_SPEED: u32 = 0x1002;
pub const BM1491_L9_UART_INITIAL_SPEED_BAUD: u32 = 115_200;
pub const BM1491_L9_UART_VTIME: u8 = 0;
pub const BM1491_L9_UART_VMIN: u8 = 9;
/// Requested enumeration rate stored in the exact L9 machine-runtime table.
pub const BM1491_L9_ENUMERATION_BAUD_REQUEST: u32 = 115_200;
/// Requested working rate stored immediately after the enumeration rate.
pub const BM1491_L9_WORKING_BAUD_REQUEST: u32 = 1_500_000;
/// BM1491 MISC-register selector chosen for the working-rate request.
pub const BM1491_L9_WORKING_BAUD_MISC_VALUE: u32 = 0x0000_0100;
pub const BM1491_L9_MISC_REGISTER: u8 = 0x60;
pub const BM1491_L9_WORKING_HOST_BAUD_SELECTOR: u8 = 1;
pub const BM1491_L9_WORKING_TERMIOS_SPEED: u32 = 0x100a;
/// Effective ASIC line rate implied by MISC `bt8d=1` and the 25-MHz source.
pub const BM1491_L9_WORKING_EFFECTIVE_BAUD: u32 = 1_562_500;
pub const BM1491_L9_BAUD_CHAIN_SETTLE_US: u32 = 10_000;
pub const BM1491_L9_BAUD_HOST_BATCH_SETTLE_US: u32 = 100_000;
pub const BM1491_L9_UART_WRITE_ATTEMPTS: u8 = 30;
pub const BM1491_L9_UART_PARTIAL_WRITE_DELAY_US: u32 = 100_000;
pub const BM1491_L9_FPGA_UNINIT_IS_NOOP: bool = true;
pub const BM1491_L9_UART_UNINIT_CLOSES_FILE_DESCRIPTORS: bool = false;
pub const BM1491_L9_PLATFORM_UNINIT_REQUESTS_POWER_OFF: bool = false;
pub const BM1491_L9_PLATFORM_UNINIT_PROVES_SAFE_OFF: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9UartSendTerminal {
    LazyOpenFailed,
    Complete,
    AttemptsExhausted,
    WriteError(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9UartSendReplay {
    pub terminal: Bm1491L9UartSendTerminal,
    pub requested_len: u32,
    pub bytes_written: u32,
    pub write_attempts: u8,
    pub partial_write_delays: u8,
    pub file_lock_attempted: bool,
    pub file_unlock_attempted: bool,
    pub tx_mutex_unlock_attempted: bool,
}

impl Bm1491L9UartSendReplay {
    /// A pure replay result cannot prove an OS write, lock, or carrier action.
    pub const fn admits_live_uart(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9UartSendReplayError {
    MissingWriteObservation { attempt: u8 },
    WriteReportedMoreThanRemaining { reported: u32, remaining: u32 },
}

/// Replay the exact stock `uart_send@0x0014eea8` result spine from observed
/// write returns without opening a UART.
///
/// Stock attempts `flock(LOCK_EX)` but ignores its return. A negative `write`
/// result exits after releasing only the per-chain mutex, leaving the file
/// unlock unattempted. Partial writes, including the terminal thirtieth one,
/// incur the 100-ms delay. The clean replay refuses the POSIX-impossible case
/// where `write` reports more bytes than requested.
pub fn replay_bm1491_l9_uart_send(
    requested_len: u32,
    lazy_open_succeeded: bool,
    write_results: &[i32],
) -> Result<Bm1491L9UartSendReplay, Bm1491L9UartSendReplayError> {
    if !lazy_open_succeeded {
        return Ok(Bm1491L9UartSendReplay {
            terminal: Bm1491L9UartSendTerminal::LazyOpenFailed,
            requested_len,
            bytes_written: 0,
            write_attempts: 0,
            partial_write_delays: 0,
            file_lock_attempted: false,
            file_unlock_attempted: false,
            tx_mutex_unlock_attempted: true,
        });
    }

    let mut bytes_written = 0u32;
    let mut write_attempts = 0u8;
    let mut partial_write_delays = 0u8;
    while bytes_written < requested_len && write_attempts < BM1491_L9_UART_WRITE_ATTEMPTS {
        let observed = *write_results.get(usize::from(write_attempts)).ok_or(
            Bm1491L9UartSendReplayError::MissingWriteObservation {
                attempt: write_attempts,
            },
        )?;
        write_attempts += 1;
        if observed < 0 {
            return Ok(Bm1491L9UartSendReplay {
                terminal: Bm1491L9UartSendTerminal::WriteError(observed),
                requested_len,
                bytes_written,
                write_attempts,
                partial_write_delays,
                file_lock_attempted: true,
                file_unlock_attempted: false,
                tx_mutex_unlock_attempted: true,
            });
        }
        let observed = observed as u32;
        let remaining = requested_len - bytes_written;
        if observed > remaining {
            return Err(
                Bm1491L9UartSendReplayError::WriteReportedMoreThanRemaining {
                    reported: observed,
                    remaining,
                },
            );
        }
        bytes_written += observed;
        if bytes_written < requested_len {
            partial_write_delays += 1;
        }
    }

    Ok(Bm1491L9UartSendReplay {
        terminal: if bytes_written == requested_len {
            Bm1491L9UartSendTerminal::Complete
        } else {
            Bm1491L9UartSendTerminal::AttemptsExhausted
        },
        requested_len,
        bytes_written,
        write_attempts,
        partial_write_delays,
        file_lock_attempted: true,
        file_unlock_attempted: true,
        tx_mutex_unlock_attempted: true,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9UartReceiveReplay {
    pub return_value: i32,
    pub read_attempted: bool,
    pub read_attempts: u8,
    pub timeout_parameter_used: bool,
    pub file_lock_attempted: bool,
    pub rx_mutex_unlock_attempted: bool,
}

impl Bm1491L9UartReceiveReplay {
    pub const fn admits_live_uart(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9UartReceiveReplayError {
    ReadReportedMoreThanRequested { reported: u32, requested: u32 },
}

/// Replay `uart_receive@0x0014f2e8`: lock the per-chain receive mutex, lazily
/// open, perform at most one nonblocking read, unlock, and return the raw read
/// result. The fourth timeout argument is stored but never consumed.
pub const fn replay_bm1491_l9_uart_receive(
    requested_len: u32,
    lazy_open_succeeded: bool,
    read_result: i32,
) -> Result<Bm1491L9UartReceiveReplay, Bm1491L9UartReceiveReplayError> {
    if !lazy_open_succeeded {
        return Ok(Bm1491L9UartReceiveReplay {
            return_value: -1,
            read_attempted: false,
            read_attempts: 0,
            timeout_parameter_used: false,
            file_lock_attempted: false,
            rx_mutex_unlock_attempted: true,
        });
    }
    if read_result >= 0 && read_result as u32 > requested_len {
        return Err(
            Bm1491L9UartReceiveReplayError::ReadReportedMoreThanRequested {
                reported: read_result as u32,
                requested: requested_len,
            },
        );
    }
    Ok(Bm1491L9UartReceiveReplay {
        return_value: read_result,
        read_attempted: true,
        read_attempts: 1,
        timeout_parameter_used: false,
        file_lock_attempted: false,
        rx_mutex_unlock_attempted: true,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9WorkingBaudStep {
    /// `set_baud_ltc` maps 1,500,000 to `bt8d=1` in MISC register `0x60`.
    WriteAsicMisc {
        slot: u8,
        register: u8,
        value: u32,
        result_discarded: bool,
    },
    DelayUs(u32),
    /// `dev_config_hal` maps the same request to host selector one and calls
    /// `uart_set_config(slot, 0, &selector, 4)`.
    ConfigureHostUart {
        slot: u8,
        selector: u8,
        termios_speed: u32,
        result_discarded: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1491L9WorkingBaudPlan {
    pub requested_baud: u32,
    pub effective_asic_baud: u32,
    pub steps: Vec<Bm1491L9WorkingBaudStep>,
    pub stock_returns_zero_without_acknowledgement: bool,
    _private: (),
}

impl Bm1491L9WorkingBaudPlan {
    /// A caller-supplied active-slot list and a pure operation plan cannot
    /// establish transceiver routing, clock accuracy, delivery, or ownership.
    pub const fn admits_live_baud_transition(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9WorkingBaudPlanError {
    NoActiveRuntime,
    SlotOutOfRange { slot: u8 },
    DuplicateSlot { slot: u8 },
}

/// Build the exact hardware-facing spine used for the held L9 working-baud
/// transition, without opening a UART or writing an ASIC register.
///
/// `machine_runtime_ctrl_ltc_1491@0x000727e4` stores 115,200 followed by
/// 1,500,000. `set_baud_base@0x0007330c` first invokes each runtime's
/// `set_baud_ltc` callback, waits 10 ms after each chain, then asks
/// `dev_config_hal@0x0016f6a4` to update every host UART, waits 100 ms inside
/// that callback, and waits another 10 ms after it returns. The requested
/// 1,500,000 value maps to ASIC MISC `bt8d=1`, whose effective rate is
/// 1,562,500 baud. Stock discards every ASIC and host configuration result and
/// returns zero; an executor must instead require acknowledged, measured
/// transition success before using the new rate.
pub fn plan_bm1491_l9_working_baud_transition(
    active_runtime_slots: &[u8],
) -> Result<Bm1491L9WorkingBaudPlan, Bm1491L9WorkingBaudPlanError> {
    if active_runtime_slots.is_empty() {
        return Err(Bm1491L9WorkingBaudPlanError::NoActiveRuntime);
    }

    let mut seen = [false; BM1491_L9_CHAIN_ROUTES.len()];
    for &slot in active_runtime_slots {
        let Some(seen_slot) = seen.get_mut(usize::from(slot)) else {
            return Err(Bm1491L9WorkingBaudPlanError::SlotOutOfRange { slot });
        };
        if *seen_slot {
            return Err(Bm1491L9WorkingBaudPlanError::DuplicateSlot { slot });
        }
        *seen_slot = true;
    }

    let mut steps = Vec::with_capacity(active_runtime_slots.len() * 3 + 2);
    for &slot in active_runtime_slots {
        steps.push(Bm1491L9WorkingBaudStep::WriteAsicMisc {
            slot,
            register: BM1491_L9_MISC_REGISTER,
            value: BM1491_L9_WORKING_BAUD_MISC_VALUE,
            result_discarded: true,
        });
        steps.push(Bm1491L9WorkingBaudStep::DelayUs(
            BM1491_L9_BAUD_CHAIN_SETTLE_US,
        ));
    }
    for &slot in active_runtime_slots {
        steps.push(Bm1491L9WorkingBaudStep::ConfigureHostUart {
            slot,
            selector: BM1491_L9_WORKING_HOST_BAUD_SELECTOR,
            termios_speed: BM1491_L9_WORKING_TERMIOS_SPEED,
            result_discarded: true,
        });
    }
    steps.push(Bm1491L9WorkingBaudStep::DelayUs(
        BM1491_L9_BAUD_HOST_BATCH_SETTLE_US,
    ));
    steps.push(Bm1491L9WorkingBaudStep::DelayUs(
        BM1491_L9_BAUD_CHAIN_SETTLE_US,
    ));

    Ok(Bm1491L9WorkingBaudPlan {
        requested_baud: BM1491_L9_WORKING_BAUD_REQUEST,
        effective_asic_baud: BM1491_L9_WORKING_EFFECTIVE_BAUD,
        steps,
        stock_returns_zero_without_acknowledgement: true,
        _private: (),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9FitConfiguration {
    pub configuration: &'static str,
    pub fdt_image: &'static str,
    pub fdt_size: u32,
    pub fdt_sha256: &'static str,
}

pub const BM1491_L9_FIT_KERNEL_SHA256: &str =
    "b100871820bef57b650533cc379d678afd57c6345c8425ce0d32575415cf6038";
pub const BM1491_L9_FIT_CONFIGURATIONS: [Bm1491L9FitConfiguration; 4] = [
    Bm1491L9FitConfiguration {
        configuration: "config@cv1832_wevb_0004a_spinand",
        fdt_image: "fdt@cv1832_wevb_0004a_spinand",
        fdt_size: 17_783,
        fdt_sha256: "5a111346300cf5e2b68a63136ed791f83b76288166117ca8a791e1b47fa6773c",
    },
    Bm1491L9FitConfiguration {
        configuration: "config@cv1835_miner_emmc",
        fdt_image: "fdt@cv1835_miner_emmc",
        fdt_size: 17_895,
        fdt_sha256: "5b62a37db90b81a6d6cfac00d9ae515e5024b54d82330cb5b264b54f020659d2",
    },
    Bm1491L9FitConfiguration {
        configuration: "config@cv1835_miner_spinand",
        fdt_image: "fdt@cv1835_miner_spinand",
        fdt_size: 17_891,
        fdt_sha256: "be2fcfae65e62ee2d978cd64d13d0dd4142e035f0279fc05971c432cc2f2a9ad",
    },
    Bm1491L9FitConfiguration {
        configuration: "config@cv1835_wevb_0002a_spinand",
        fdt_image: "fdt@cv1835_wevb_0002a_spinand",
        fdt_size: 17_891,
        fdt_sha256: "8af3a7783bdb566dc982f77e9d2b38be514e34c157f8a54979cabcd954fbf460",
    },
];

/// Properties shared by every one of the four embedded FIT device trees.
/// Serial zero is the console; serials one through four back `/dev/ttyS1..4`.
pub const BM1491_L9_FIT_SERIAL_CLOCK_HZ: [u32; 5] = [
    25_000_000,
    200_000_000,
    200_000_000,
    200_000_000,
    200_000_000,
];
pub const BM1491_L9_FIT_CHAIN_UART_RX_DMA_CHANNELS: [u8; 4] = [0, 2, 6, 7];
pub const BM1491_L9_FIT_UART_GPIO_PWM_SUBTREES_IDENTICAL: bool = true;
pub const BM1491_L9_FIT_I2C_PROPERTIES_IDENTICAL: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9FitCarrierVariation {
    pub configuration: &'static str,
    /// Raw DT `clock-frequency` properties for I2C0, I2C2, I2C3, and I2C4.
    /// Their physical bus timing is not admitted from these values alone.
    pub i2c_clock_frequency_properties: [u32; 4],
    pub memory_size_bytes: u32,
}

pub const BM1491_L9_FIT_CARRIER_VARIATIONS: [Bm1491L9FitCarrierVariation; 4] = [
    Bm1491L9FitCarrierVariation {
        configuration: "config@cv1832_wevb_0004a_spinand",
        i2c_clock_frequency_properties: [1_000, 100_000, 400_000, 100_000],
        memory_size_bytes: 0x2000_0000,
    },
    Bm1491L9FitCarrierVariation {
        configuration: "config@cv1835_miner_emmc",
        i2c_clock_frequency_properties: [11_000, 333, 33_000, 100_000],
        memory_size_bytes: 0x1000_0000,
    },
    Bm1491L9FitCarrierVariation {
        configuration: "config@cv1835_miner_spinand",
        i2c_clock_frequency_properties: [33_000, 333, 100_000, 100_000],
        memory_size_bytes: 0x1000_0000,
    },
    Bm1491L9FitCarrierVariation {
        configuration: "config@cv1835_wevb_0002a_spinand",
        i2c_clock_frequency_properties: [1_000, 100_000, 400_000, 100_000],
        memory_size_bytes: 0x4000_0000,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9ChainRoute {
    pub slot: u8,
    pub uart_number: u8,
    pub uart_device: &'static str,
    pub plug_gpio: u16,
    pub reset_gpio: u16,
}

/// Exact `.data` table at `0x002cc44c`; `hal_chain_max_num` scans until the
/// all-`-1` sentinel and therefore reports four carrier slots.
pub const BM1491_L9_CHAIN_ROUTES: [Bm1491L9ChainRoute; 4] = [
    Bm1491L9ChainRoute {
        slot: 0,
        uart_number: 1,
        uart_device: "/dev/ttyS1",
        plug_gpio: 426,
        reset_gpio: 427,
    },
    Bm1491L9ChainRoute {
        slot: 1,
        uart_number: 2,
        uart_device: "/dev/ttyS2",
        plug_gpio: 428,
        reset_gpio: 429,
    },
    Bm1491L9ChainRoute {
        slot: 2,
        uart_number: 3,
        uart_device: "/dev/ttyS3",
        plug_gpio: 430,
        reset_gpio: 431,
    },
    Bm1491L9ChainRoute {
        slot: 3,
        uart_number: 4,
        uart_device: "/dev/ttyS4",
        plug_gpio: 432,
        reset_gpio: 433,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9RouteError {
    SlotOutOfRange { slot: usize },
}

pub fn bm1491_l9_chain_route(slot: usize) -> Result<Bm1491L9ChainRoute, Bm1491L9RouteError> {
    BM1491_L9_CHAIN_ROUTES
        .get(slot)
        .copied()
        .ok_or(Bm1491L9RouteError::SlotOutOfRange { slot })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9PinmuxWrite {
    pub address: u32,
    pub value: u32,
}

/// Ordered `devmem` writes from the exact held `S37bitmainer_setup` script.
/// Sysfs GPIO/PWM operations that occur between writes are recorded separately.
pub const BM1491_L9_PINMUX_WRITES: [Bm1491L9PinmuxWrite; 27] = [
    Bm1491L9PinmuxWrite {
        address: 0x0300_118c,
        value: 3,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_1198,
        value: 3,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_11b0,
        value: 3,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_106c,
        value: 7,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_105c,
        value: 7,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_11b8,
        value: 0,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_119c,
        value: 0,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_11a4,
        value: 0,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_11b4,
        value: 0,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_10d8,
        value: 0,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_10ec,
        value: 0,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_10c4,
        value: 0,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_10d4,
        value: 0,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_1188,
        value: 5,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_1190,
        value: 5,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_10cc,
        value: 7,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_10dc,
        value: 7,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_10e4,
        value: 1,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_10d0,
        value: 1,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_10a8,
        value: 2,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_10ac,
        value: 2,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_10b0,
        value: 2,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_10b4,
        value: 2,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_1910,
        value: 0x320,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_1914,
        value: 0x320,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_1918,
        value: 0x320,
    },
    Bm1491L9PinmuxWrite {
        address: 0x0300_191c,
        value: 0x320,
    },
];

pub const BM1491_L9_BOOT_OUTPUT_GPIOS: [u16; 9] = [412, 427, 429, 431, 433, 435, 434, 459, 461];
pub const BM1491_L9_IIC2_BITBANG_PINS: [&str; 2] = ["IIC2_SCL/XGPIOB_11", "IIC2_SDA/XGPIOB_13"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9PwmDirection {
    Output,
    CaptureInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9PwmChannel {
    pub chip: u8,
    pub channel: u8,
    pub period_ns: u32,
    pub direction: Bm1491L9PwmDirection,
}

pub const BM1491_L9_PWM_CHANNELS: [Bm1491L9PwmChannel; 6] = [
    Bm1491L9PwmChannel {
        chip: 8,
        channel: 0,
        period_ns: 1_000_000,
        direction: Bm1491L9PwmDirection::Output,
    },
    Bm1491L9PwmChannel {
        chip: 8,
        channel: 1,
        period_ns: 1_000_000,
        direction: Bm1491L9PwmDirection::Output,
    },
    Bm1491L9PwmChannel {
        chip: 12,
        channel: 0,
        period_ns: 1_000_000,
        direction: Bm1491L9PwmDirection::CaptureInput,
    },
    Bm1491L9PwmChannel {
        chip: 12,
        channel: 1,
        period_ns: 1_000_000,
        direction: Bm1491L9PwmDirection::CaptureInput,
    },
    Bm1491L9PwmChannel {
        chip: 12,
        channel: 2,
        period_ns: 1_000_000,
        direction: Bm1491L9PwmDirection::CaptureInput,
    },
    Bm1491L9PwmChannel {
        chip: 12,
        channel: 3,
        period_ns: 1_000_000,
        direction: Bm1491L9PwmDirection::CaptureInput,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9PlatformInitStep {
    FpgaInitNoOp,
    InitializeGpioWorker,
    ClearRuntimeTable,
    ScanFourStaticCarrierSlots,
    ExportPlugInputsAndResetOutputs,
    ReadPlugAndCreateRuntimeOnlyWhenValueIsOne,
    PublishPlatformInitialized,
    StartFanThreadResultDiscarded,
    InitializeLazyUartMapResultDiscarded,
}

pub const BM1491_L9_PLATFORM_INIT_SPINE: [Bm1491L9PlatformInitStep; 9] = [
    Bm1491L9PlatformInitStep::FpgaInitNoOp,
    Bm1491L9PlatformInitStep::InitializeGpioWorker,
    Bm1491L9PlatformInitStep::ClearRuntimeTable,
    Bm1491L9PlatformInitStep::ScanFourStaticCarrierSlots,
    Bm1491L9PlatformInitStep::ExportPlugInputsAndResetOutputs,
    Bm1491L9PlatformInitStep::ReadPlugAndCreateRuntimeOnlyWhenValueIsOne,
    Bm1491L9PlatformInitStep::PublishPlatformInitialized,
    Bm1491L9PlatformInitStep::StartFanThreadResultDiscarded,
    Bm1491L9PlatformInitStep::InitializeLazyUartMapResultDiscarded,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9PlatformUninitStep {
    ReturnIfPlatformNotInitialized,
    FpgaUninitNoop,
    ScanFourStaticCarrierSlots,
    UnexportPlugGpioWhenRouteExists,
    UnexportResetGpioWhenRouteExists,
    DeleteUartMapWithoutClosingCachedDescriptors,
    ClearFanWorkerFlagAndJoin,
    UninitializeUi,
    ClearGpioWorkerFlagJoinAndDeleteMap,
    ClearPlatformInitialized,
}

pub const BM1491_L9_PLATFORM_UNINIT_SPINE: [Bm1491L9PlatformUninitStep; 10] = [
    Bm1491L9PlatformUninitStep::ReturnIfPlatformNotInitialized,
    Bm1491L9PlatformUninitStep::FpgaUninitNoop,
    Bm1491L9PlatformUninitStep::ScanFourStaticCarrierSlots,
    Bm1491L9PlatformUninitStep::UnexportPlugGpioWhenRouteExists,
    Bm1491L9PlatformUninitStep::UnexportResetGpioWhenRouteExists,
    Bm1491L9PlatformUninitStep::DeleteUartMapWithoutClosingCachedDescriptors,
    Bm1491L9PlatformUninitStep::ClearFanWorkerFlagAndJoin,
    Bm1491L9PlatformUninitStep::UninitializeUi,
    Bm1491L9PlatformUninitStep::ClearGpioWorkerFlagJoinAndDeleteMap,
    Bm1491L9PlatformUninitStep::ClearPlatformInitialized,
];

/// Exact stock presence rule. GPIO read failures are ignored by
/// `platform_init`; only the resulting byte value one creates a runtime.
pub const fn bm1491_l9_stock_present_slots(plug_values: [u8; 4]) -> [bool; 4] {
    [
        plug_values[0] == 1,
        plug_values[1] == 1,
        plug_values[2] == 1,
        plug_values[3] == 1,
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9Artifact<'a> {
    pub sha256: &'a str,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9ReleaseObservation<'a> {
    pub merge_bmu: Bm1491L9Artifact<'a>,
    pub cvctrl_component: Bm1491L9Artifact<'a>,
    pub rootfs: Bm1491L9Artifact<'a>,
    pub fit: Bm1491L9Artifact<'a>,
    pub named_devicetree: Bm1491L9Artifact<'a>,
    pub godminer: Bm1491L9Artifact<'a>,
    pub setup_script: Bm1491L9Artifact<'a>,
    pub subtype_file: Bm1491L9Artifact<'a>,
    pub subtype: &'a str,
    pub topology: Bm1491L9Artifact<'a>,
    pub machine: &'a str,
    pub processor: &'a str,
    pub asic_name: &'a str,
    pub asic_id: u16,
    pub pwm_module: Bm1491L9Artifact<'a>,
    pub pwm_vermagic: &'a str,
    pub base_module: Bm1491L9Artifact<'a>,
    pub base_vermagic: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9ReleaseMatchError {
    MergeBmuMismatch,
    ComponentMismatch,
    RootfsMismatch,
    FitMismatch,
    NamedDevicetreeMismatch,
    GodminerMismatch,
    SetupScriptMismatch,
    SubtypeMismatch,
    TopologyMismatch,
    TopologyIdentityMismatch,
    PwmModuleMismatch,
    BaseModuleMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9ExactReleaseEvidence {
    _private: (),
}

impl Bm1491L9ExactReleaseEvidence {
    pub const fn admits_board_identity(&self) -> bool {
        false
    }
    pub const fn admits_live_carrier(&self) -> bool {
        false
    }
    pub const fn admits_gpio_or_pinmux_writes(&self) -> bool {
        false
    }
    pub const fn admits_rail_mutation(&self) -> bool {
        false
    }
    pub const fn admits_mining(&self) -> bool {
        false
    }
    pub const fn admits_install(&self) -> bool {
        false
    }
}

fn artifact_matches(observed: Bm1491L9Artifact<'_>, sha256: &str, size: u64) -> bool {
    observed.size == size && observed.sha256.eq_ignore_ascii_case(sha256)
}

/// Match the complete copyable held-release tuple without authenticating a
/// publisher or the attached controller.
pub fn match_bm1491_l9_exact_release(
    observation: Bm1491L9ReleaseObservation<'_>,
) -> Result<Bm1491L9ExactReleaseEvidence, Bm1491L9ReleaseMatchError> {
    if !artifact_matches(
        observation.merge_bmu,
        BM1491_L9_MERGE_BMU_SHA256,
        BM1491_L9_MERGE_BMU_SIZE,
    ) {
        return Err(Bm1491L9ReleaseMatchError::MergeBmuMismatch);
    }
    if !artifact_matches(
        observation.cvctrl_component,
        BM1491_L9_CVCTRL_COMPONENT_SHA256,
        BM1491_L9_CVCTRL_COMPONENT_SIZE,
    ) {
        return Err(Bm1491L9ReleaseMatchError::ComponentMismatch);
    }
    if !artifact_matches(
        observation.rootfs,
        BM1491_L9_ROOTFS_SHA256,
        BM1491_L9_ROOTFS_SIZE,
    ) {
        return Err(Bm1491L9ReleaseMatchError::RootfsMismatch);
    }
    if !artifact_matches(observation.fit, BM1491_L9_FIT_SHA256, BM1491_L9_FIT_SIZE) {
        return Err(Bm1491L9ReleaseMatchError::FitMismatch);
    }
    if !artifact_matches(
        observation.named_devicetree,
        BM1491_L9_NAMED_DEVICETREE_SHA256,
        BM1491_L9_NAMED_DEVICETREE_SIZE,
    ) {
        return Err(Bm1491L9ReleaseMatchError::NamedDevicetreeMismatch);
    }
    if !artifact_matches(
        observation.godminer,
        BM1491_L9_GODMINER_SHA256,
        BM1491_L9_GODMINER_SIZE,
    ) {
        return Err(Bm1491L9ReleaseMatchError::GodminerMismatch);
    }
    if !artifact_matches(
        observation.setup_script,
        BM1491_L9_SETUP_SCRIPT_SHA256,
        BM1491_L9_SETUP_SCRIPT_SIZE,
    ) {
        return Err(Bm1491L9ReleaseMatchError::SetupScriptMismatch);
    }
    if observation.subtype != BM1491_L9_SUBTYPE
        || !artifact_matches(
            observation.subtype_file,
            BM1491_L9_SUBTYPE_SHA256,
            BM1491_L9_SUBTYPE_SIZE,
        )
    {
        return Err(Bm1491L9ReleaseMatchError::SubtypeMismatch);
    }
    if !artifact_matches(
        observation.topology,
        BM1491_L9_TOPOLOGY_SHA256,
        BM1491_L9_TOPOLOGY_SIZE,
    ) {
        return Err(Bm1491L9ReleaseMatchError::TopologyMismatch);
    }
    if observation.machine != BM1491_L9_MACHINE
        || observation.processor != BM1491_L9_PROCESSOR
        || observation.asic_name != BM1491_L9_ASIC_NAME
        || observation.asic_id != BM1491_L9_ASIC_ID
    {
        return Err(Bm1491L9ReleaseMatchError::TopologyIdentityMismatch);
    }
    if !artifact_matches(
        observation.pwm_module,
        BM1491_L9_PWM_MODULE_SHA256,
        BM1491_L9_PWM_MODULE_SIZE,
    ) || observation.pwm_vermagic != BM1491_L9_PWM_MODULE_VERMAGIC
    {
        return Err(Bm1491L9ReleaseMatchError::PwmModuleMismatch);
    }
    if !artifact_matches(
        observation.base_module,
        BM1491_L9_BASE_MODULE_SHA256,
        BM1491_L9_BASE_MODULE_SIZE,
    ) || observation.base_vermagic != BM1491_L9_BASE_MODULE_VERMAGIC
    {
        return Err(Bm1491L9ReleaseMatchError::BaseModuleMismatch);
    }
    Ok(Bm1491L9ExactReleaseEvidence { _private: () })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9SlotPreflightObservation {
    pub plug_exported: bool,
    pub plug_direction_input: bool,
    pub reset_exported: bool,
    pub reset_direction_output: bool,
    pub plug_read_succeeded: bool,
    pub plug_value: u8,
    pub uart_device_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9CarrierObservation {
    pub fpga_init_result: i32,
    pub gpio_init_result: i32,
    pub fan_init_result: i32,
    pub uart_init_result: i32,
    pub competing_owner_detected: bool,
    pub slots: [Bm1491L9SlotPreflightObservation; 4],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9CarrierPreflightError {
    FpgaInitFailed,
    GpioInitFailed,
    SlotGpioSetupFailed { slot: usize },
    SlotPlugReadFailed { slot: usize },
    MalformedPlugValue { slot: usize, value: u8 },
    PresentUartMissing { slot: usize },
    PresentChainCountMismatch { observed: usize },
    FanInitFailed,
    UartInitFailed,
    CompetingOwnerDetected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9CarrierAssessment {
    present_mask: u8,
}

impl Bm1491L9CarrierAssessment {
    pub const fn present_mask(&self) -> u8 {
        self.present_mask
    }
    /// Caller-provided operation transcripts have no freshness or ownership.
    pub const fn admits_live_carrier(&self) -> bool {
        false
    }
}

/// Fail-closed assessment layered over stock's weaker platform behavior.
///
/// Stock discards GPIO export/direction/read results and the fan/UART init
/// results. Clean code refuses those states and also requires the configured
/// three present chains, but still cannot mint a live receipt from booleans.
pub fn assess_bm1491_l9_carrier_observation(
    observation: Bm1491L9CarrierObservation,
) -> Result<Bm1491L9CarrierAssessment, Bm1491L9CarrierPreflightError> {
    if observation.fpga_init_result != 0 {
        return Err(Bm1491L9CarrierPreflightError::FpgaInitFailed);
    }
    if observation.gpio_init_result != 0 {
        return Err(Bm1491L9CarrierPreflightError::GpioInitFailed);
    }
    if observation.competing_owner_detected {
        return Err(Bm1491L9CarrierPreflightError::CompetingOwnerDetected);
    }
    let mut present_mask = 0u8;
    let mut present_count = 0usize;
    for (slot, item) in observation.slots.iter().enumerate() {
        if !item.plug_exported
            || !item.plug_direction_input
            || !item.reset_exported
            || !item.reset_direction_output
        {
            return Err(Bm1491L9CarrierPreflightError::SlotGpioSetupFailed { slot });
        }
        if !item.plug_read_succeeded {
            return Err(Bm1491L9CarrierPreflightError::SlotPlugReadFailed { slot });
        }
        if item.plug_value > 1 {
            return Err(Bm1491L9CarrierPreflightError::MalformedPlugValue {
                slot,
                value: item.plug_value,
            });
        }
        if item.plug_value == 1 {
            if !item.uart_device_present {
                return Err(Bm1491L9CarrierPreflightError::PresentUartMissing { slot });
            }
            present_count += 1;
            present_mask |= 1 << slot;
        }
    }
    if present_count != BM1491_L9_CONFIGURED_CHAIN_COUNT {
        return Err(Bm1491L9CarrierPreflightError::PresentChainCountMismatch {
            observed: present_count,
        });
    }
    if observation.fan_init_result != 0 {
        return Err(Bm1491L9CarrierPreflightError::FanInitFailed);
    }
    if observation.uart_init_result != 0 {
        return Err(Bm1491L9CarrierPreflightError::UartInitFailed);
    }
    Ok(Bm1491L9CarrierAssessment { present_mask })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(sha256: &'static str, size: u64) -> Bm1491L9Artifact<'static> {
        Bm1491L9Artifact { sha256, size }
    }

    fn exact_release() -> Bm1491L9ReleaseObservation<'static> {
        Bm1491L9ReleaseObservation {
            merge_bmu: artifact(BM1491_L9_MERGE_BMU_SHA256, BM1491_L9_MERGE_BMU_SIZE),
            cvctrl_component: artifact(
                BM1491_L9_CVCTRL_COMPONENT_SHA256,
                BM1491_L9_CVCTRL_COMPONENT_SIZE,
            ),
            rootfs: artifact(BM1491_L9_ROOTFS_SHA256, BM1491_L9_ROOTFS_SIZE),
            fit: artifact(BM1491_L9_FIT_SHA256, BM1491_L9_FIT_SIZE),
            named_devicetree: artifact(
                BM1491_L9_NAMED_DEVICETREE_SHA256,
                BM1491_L9_NAMED_DEVICETREE_SIZE,
            ),
            godminer: artifact(BM1491_L9_GODMINER_SHA256, BM1491_L9_GODMINER_SIZE),
            setup_script: artifact(BM1491_L9_SETUP_SCRIPT_SHA256, BM1491_L9_SETUP_SCRIPT_SIZE),
            subtype_file: artifact(BM1491_L9_SUBTYPE_SHA256, BM1491_L9_SUBTYPE_SIZE),
            subtype: BM1491_L9_SUBTYPE,
            topology: artifact(BM1491_L9_TOPOLOGY_SHA256, BM1491_L9_TOPOLOGY_SIZE),
            machine: BM1491_L9_MACHINE,
            processor: BM1491_L9_PROCESSOR,
            asic_name: BM1491_L9_ASIC_NAME,
            asic_id: BM1491_L9_ASIC_ID,
            pwm_module: artifact(BM1491_L9_PWM_MODULE_SHA256, BM1491_L9_PWM_MODULE_SIZE),
            pwm_vermagic: BM1491_L9_PWM_MODULE_VERMAGIC,
            base_module: artifact(BM1491_L9_BASE_MODULE_SHA256, BM1491_L9_BASE_MODULE_SIZE),
            base_vermagic: BM1491_L9_BASE_MODULE_VERMAGIC,
        }
    }

    fn slot(value: u8) -> Bm1491L9SlotPreflightObservation {
        Bm1491L9SlotPreflightObservation {
            plug_exported: true,
            plug_direction_input: true,
            reset_exported: true,
            reset_direction_output: true,
            plug_read_succeeded: true,
            plug_value: value,
            uart_device_present: value == 1,
        }
    }

    fn clean_carrier() -> Bm1491L9CarrierObservation {
        Bm1491L9CarrierObservation {
            fpga_init_result: 0,
            gpio_init_result: 0,
            fan_init_result: 0,
            uart_init_result: 0,
            competing_owner_detected: false,
            slots: [slot(1), slot(1), slot(1), slot(0)],
        }
    }

    #[test]
    fn exact_release_tuple_matches_but_never_authorizes_hardware() {
        let evidence = match_bm1491_l9_exact_release(exact_release()).unwrap();
        assert!(!evidence.admits_board_identity());
        assert!(!evidence.admits_live_carrier());
        assert!(!evidence.admits_gpio_or_pinmux_writes());
        assert!(!evidence.admits_rail_mutation());
        assert!(!evidence.admits_mining());
        assert!(!evidence.admits_install());
    }

    #[test]
    fn release_match_refuses_component_and_topology_cross_products() {
        let mut item = exact_release();
        item.cvctrl_component.sha256 = BM1491_L9_MERGE_BMU_SHA256;
        assert_eq!(
            match_bm1491_l9_exact_release(item),
            Err(Bm1491L9ReleaseMatchError::ComponentMismatch)
        );

        let mut item = exact_release();
        item.machine = "cv1835-s19jpro";
        assert_eq!(
            match_bm1491_l9_exact_release(item),
            Err(Bm1491L9ReleaseMatchError::TopologyIdentityMismatch)
        );
    }

    #[test]
    fn every_release_artifact_class_is_pinned() {
        let mutations: [fn(&mut Bm1491L9ReleaseObservation<'static>); 10] = [
            |x| x.merge_bmu.size += 1,
            |x| x.rootfs.size += 1,
            |x| x.fit.size += 1,
            |x| x.named_devicetree.size += 1,
            |x| x.godminer.size += 1,
            |x| x.setup_script.size += 1,
            |x| x.subtype_file.size += 1,
            |x| x.topology.size += 1,
            |x| x.pwm_module.size += 1,
            |x| x.base_module.size += 1,
        ];
        for mutate in mutations {
            let mut item = exact_release();
            mutate(&mut item);
            assert!(match_bm1491_l9_exact_release(item).is_err());
        }
    }

    #[test]
    fn fit_inventory_is_exact_but_active_configuration_is_unknown() {
        assert_eq!(BM1491_L9_FIT_CONFIGURATIONS.len(), 4);
        assert_eq!(
            BM1491_L9_FIT_CONFIGURATIONS[2].configuration,
            "config@cv1835_miner_spinand"
        );
        assert_eq!(BM1491_L9_FIT_CONFIGURATIONS[2].fdt_size, 17_891);
        assert!(BM1491_L9_ROOTFS_IS_GZIP_CPIO);
        assert_eq!(BM1491_L9_ROOTFS_UNCOMPRESSED_SIZE, 20_039_680);
        assert_eq!(
            BM1491_L9_ROOTFS_UNCOMPRESSED_SHA256,
            "1de9301b867badf6bb3bd10db832d2ecf414355861ac29f38e518b4eb09ba667"
        );
        assert!(!BM1491_L9_FIT_DEFAULT_CONFIGURATION_PRESENT);
        assert!(BM1491_L9_UPDATE_WRITES_FIT_VERBATIM_TO_EMMC_PARTITION_ONE);
        assert!(!BM1491_L9_UPDATE_CONTAINS_BOOTLOADER_SELECTOR);
        assert!(!BM1491_L9_ACTIVE_FIT_CONFIGURATION_PROVEN);
        assert!(!BM1491_L9_NAMED_DEVICETREE_IS_FDT);
        assert!(!BM1491_L9_PHYSICAL_BOARD_IDENTITY_PROVEN);
    }

    #[test]
    fn kernel_and_miner_architectures_are_not_conflated() {
        assert_eq!(BM1491_L9_FIT_KERNEL_ARCHITECTURE, "AArch64");
        assert_eq!(BM1491_L9_GODMINER_ELF_CLASS_BITS, 32);
        assert_eq!(BM1491_L9_GODMINER_MACHINE, "ARM EABI5 hard-float");
        assert_eq!(
            BM1491_L9_GODMINER_BUILD_ID,
            "ffdff776c6907282dee448f25ce3d0204abdeb26"
        );
    }

    #[test]
    fn fit_carrier_intersection_keeps_uart_but_not_i2c_or_memory() {
        assert!(BM1491_L9_FIT_UART_GPIO_PWM_SUBTREES_IDENTICAL);
        assert!(!BM1491_L9_FIT_I2C_PROPERTIES_IDENTICAL);
        assert_eq!(
            BM1491_L9_FIT_SERIAL_CLOCK_HZ,
            [
                25_000_000,
                200_000_000,
                200_000_000,
                200_000_000,
                200_000_000
            ]
        );
        assert_eq!(BM1491_L9_FIT_CHAIN_UART_RX_DMA_CHANNELS, [0, 2, 6, 7]);
        for (configuration, variation) in BM1491_L9_FIT_CONFIGURATIONS
            .iter()
            .zip(BM1491_L9_FIT_CARRIER_VARIATIONS)
        {
            assert_eq!(configuration.configuration, variation.configuration);
        }
        assert_eq!(
            BM1491_L9_FIT_CARRIER_VARIATIONS[0].i2c_clock_frequency_properties,
            [1_000, 100_000, 400_000, 100_000]
        );
        assert_eq!(
            BM1491_L9_FIT_CARRIER_VARIATIONS[2].i2c_clock_frequency_properties,
            [33_000, 333, 100_000, 100_000]
        );
        assert_eq!(
            BM1491_L9_FIT_CARRIER_VARIATIONS.map(|item| item.memory_size_bytes),
            [0x2000_0000, 0x1000_0000, 0x1000_0000, 0x4000_0000]
        );
    }

    #[test]
    fn four_slot_hal_table_is_distinct_from_three_chain_topology() {
        assert_eq!(BM1491_L9_CHAIN_ROUTES.len(), 4);
        assert_eq!(BM1491_L9_CONFIGURED_CHAIN_COUNT, 3);
        assert_eq!(bm1491_l9_chain_route(0).unwrap().uart_device, "/dev/ttyS1");
        assert_eq!(bm1491_l9_chain_route(3).unwrap().plug_gpio, 432);
        assert_eq!(bm1491_l9_chain_route(3).unwrap().reset_gpio, 433);
        assert_eq!(
            bm1491_l9_chain_route(4),
            Err(Bm1491L9RouteError::SlotOutOfRange { slot: 4 })
        );
    }

    #[test]
    fn stock_presence_requires_exact_byte_one() {
        assert_eq!(
            bm1491_l9_stock_present_slots([1, 0, 2, 255]),
            [true, false, false, false]
        );
    }

    #[test]
    fn pinmux_and_gpio_boundaries_are_pinned() {
        assert_eq!(BM1491_L9_PINMUX_WRITES.len(), 27);
        assert_eq!(
            BM1491_L9_PINMUX_WRITES[0],
            Bm1491L9PinmuxWrite {
                address: 0x0300_118c,
                value: 3
            }
        );
        assert_eq!(
            BM1491_L9_PINMUX_WRITES[13],
            Bm1491L9PinmuxWrite {
                address: 0x0300_1188,
                value: 5
            }
        );
        assert_eq!(
            BM1491_L9_PINMUX_WRITES[26],
            Bm1491L9PinmuxWrite {
                address: 0x0300_191c,
                value: 0x320
            }
        );
        assert_eq!(
            BM1491_L9_BOOT_OUTPUT_GPIOS,
            [412, 427, 429, 431, 433, 435, 434, 459, 461]
        );
    }

    #[test]
    fn pwm_boot_plan_has_two_outputs_and_four_capture_inputs() {
        assert_eq!(BM1491_L9_PWM_CHANNELS.len(), 6);
        assert_eq!(
            BM1491_L9_PWM_CHANNELS
                .iter()
                .filter(|x| x.direction == Bm1491L9PwmDirection::Output)
                .count(),
            2
        );
        assert_eq!(
            BM1491_L9_PWM_CHANNELS
                .iter()
                .filter(|x| x.direction == Bm1491L9PwmDirection::CaptureInput)
                .count(),
            4
        );
        assert!(BM1491_L9_PWM_CHANNELS
            .iter()
            .all(|x| x.period_ns == 1_000_000));
    }

    #[test]
    fn clean_static_carrier_assessment_is_non_authoritative() {
        let result = assess_bm1491_l9_carrier_observation(clean_carrier()).unwrap();
        assert_eq!(result.present_mask(), 0b0111);
        assert!(!result.admits_live_carrier());
    }

    #[test]
    fn clean_assessment_rejects_stock_ignored_gpio_and_thread_failures() {
        let mut item = clean_carrier();
        item.slots[1].plug_read_succeeded = false;
        assert_eq!(
            assess_bm1491_l9_carrier_observation(item),
            Err(Bm1491L9CarrierPreflightError::SlotPlugReadFailed { slot: 1 })
        );

        let mut item = clean_carrier();
        item.fan_init_result = -1;
        assert_eq!(
            assess_bm1491_l9_carrier_observation(item),
            Err(Bm1491L9CarrierPreflightError::FanInitFailed)
        );
    }

    #[test]
    fn clean_assessment_rejects_malformed_count_and_ownership() {
        let mut item = clean_carrier();
        item.slots[3] = slot(2);
        assert_eq!(
            assess_bm1491_l9_carrier_observation(item),
            Err(Bm1491L9CarrierPreflightError::MalformedPlugValue { slot: 3, value: 2 })
        );

        let mut item = clean_carrier();
        item.slots[2] = slot(0);
        assert_eq!(
            assess_bm1491_l9_carrier_observation(item),
            Err(Bm1491L9CarrierPreflightError::PresentChainCountMismatch { observed: 2 })
        );

        let mut item = clean_carrier();
        item.competing_owner_detected = true;
        assert_eq!(
            assess_bm1491_l9_carrier_observation(item),
            Err(Bm1491L9CarrierPreflightError::CompetingOwnerDetected)
        );
    }

    #[test]
    fn uart_open_and_retry_contract_is_exact() {
        assert_eq!(BM1491_L9_UART_OPEN_FLAGS, 0x902);
        assert_eq!(BM1491_L9_UART_INITIAL_TERMIOS_SPEED, 0x1002);
        assert_eq!(BM1491_L9_UART_INITIAL_SPEED_BAUD, 115_200);
        assert_eq!((BM1491_L9_UART_VTIME, BM1491_L9_UART_VMIN), (0, 9));
        assert_eq!(BM1491_L9_UART_WRITE_ATTEMPTS, 30);
        assert_eq!(BM1491_L9_UART_PARTIAL_WRITE_DELAY_US, 100_000);
        assert_eq!(BM1491_L9_UART_RECEIVE_ADDRESS, 0x0014_f2e8);
    }

    #[test]
    fn uart_send_partial_completion_delays_then_unlocks() {
        let replay = replay_bm1491_l9_uart_send(5, true, &[2, 3]).unwrap();
        assert_eq!(replay.terminal, Bm1491L9UartSendTerminal::Complete);
        assert_eq!(replay.bytes_written, 5);
        assert_eq!(replay.write_attempts, 2);
        assert_eq!(replay.partial_write_delays, 1);
        assert!(replay.file_lock_attempted);
        assert!(replay.file_unlock_attempted);
        assert!(replay.tx_mutex_unlock_attempted);
        assert!(!replay.admits_live_uart());
    }

    #[test]
    fn uart_send_terminal_partial_still_delays_and_exhausts_at_thirty() {
        let writes = [0; BM1491_L9_UART_WRITE_ATTEMPTS as usize];
        let replay = replay_bm1491_l9_uart_send(1, true, &writes).unwrap();
        assert_eq!(replay.terminal, Bm1491L9UartSendTerminal::AttemptsExhausted);
        assert_eq!(replay.bytes_written, 0);
        assert_eq!(replay.write_attempts, 30);
        assert_eq!(replay.partial_write_delays, 30);
        assert!(replay.file_unlock_attempted);
    }

    #[test]
    fn uart_send_negative_write_preserves_exact_missing_file_unlock_weakness() {
        let replay = replay_bm1491_l9_uart_send(8, true, &[3, -5]).unwrap();
        assert_eq!(replay.terminal, Bm1491L9UartSendTerminal::WriteError(-5));
        assert_eq!(replay.bytes_written, 3);
        assert_eq!(replay.write_attempts, 2);
        assert_eq!(replay.partial_write_delays, 1);
        assert!(replay.file_lock_attempted);
        assert!(!replay.file_unlock_attempted);
        assert!(replay.tx_mutex_unlock_attempted);

        assert_eq!(
            replay_bm1491_l9_uart_send(4, true, &[5]),
            Err(
                Bm1491L9UartSendReplayError::WriteReportedMoreThanRemaining {
                    reported: 5,
                    remaining: 4,
                }
            )
        );
    }

    #[test]
    fn uart_receive_is_one_nonblocking_read_and_ignores_timeout() {
        let replay = replay_bm1491_l9_uart_receive(9, true, -11).unwrap();
        assert_eq!(replay.return_value, -11);
        assert!(replay.read_attempted);
        assert_eq!(replay.read_attempts, 1);
        assert!(!replay.timeout_parameter_used);
        assert!(!replay.file_lock_attempted);
        assert!(replay.rx_mutex_unlock_attempted);
        assert!(!replay.admits_live_uart());

        let open_failure = replay_bm1491_l9_uart_receive(9, false, 9).unwrap();
        assert_eq!(open_failure.return_value, -1);
        assert!(!open_failure.read_attempted);
        assert_eq!(
            replay_bm1491_l9_uart_receive(8, true, 9),
            Err(
                Bm1491L9UartReceiveReplayError::ReadReportedMoreThanRequested {
                    reported: 9,
                    requested: 8,
                }
            )
        );
    }

    #[test]
    fn working_baud_transition_programs_all_asics_before_any_host_uart() {
        let plan = plan_bm1491_l9_working_baud_transition(&[0, 1, 2]).unwrap();
        assert_eq!(plan.requested_baud, 1_500_000);
        assert_eq!(plan.effective_asic_baud, 1_562_500);
        assert!(plan.stock_returns_zero_without_acknowledgement);
        assert!(!plan.admits_live_baud_transition());
        assert_eq!(
            plan.steps,
            vec![
                Bm1491L9WorkingBaudStep::WriteAsicMisc {
                    slot: 0,
                    register: 0x60,
                    value: 0x100,
                    result_discarded: true,
                },
                Bm1491L9WorkingBaudStep::DelayUs(10_000),
                Bm1491L9WorkingBaudStep::WriteAsicMisc {
                    slot: 1,
                    register: 0x60,
                    value: 0x100,
                    result_discarded: true,
                },
                Bm1491L9WorkingBaudStep::DelayUs(10_000),
                Bm1491L9WorkingBaudStep::WriteAsicMisc {
                    slot: 2,
                    register: 0x60,
                    value: 0x100,
                    result_discarded: true,
                },
                Bm1491L9WorkingBaudStep::DelayUs(10_000),
                Bm1491L9WorkingBaudStep::ConfigureHostUart {
                    slot: 0,
                    selector: 1,
                    termios_speed: 0x100a,
                    result_discarded: true,
                },
                Bm1491L9WorkingBaudStep::ConfigureHostUart {
                    slot: 1,
                    selector: 1,
                    termios_speed: 0x100a,
                    result_discarded: true,
                },
                Bm1491L9WorkingBaudStep::ConfigureHostUart {
                    slot: 2,
                    selector: 1,
                    termios_speed: 0x100a,
                    result_discarded: true,
                },
                Bm1491L9WorkingBaudStep::DelayUs(100_000),
                Bm1491L9WorkingBaudStep::DelayUs(10_000),
            ]
        );
    }

    #[test]
    fn working_baud_transition_preserves_active_runtime_order() {
        let plan = plan_bm1491_l9_working_baud_transition(&[2, 0]).unwrap();
        assert_eq!(
            plan.steps[0],
            Bm1491L9WorkingBaudStep::WriteAsicMisc {
                slot: 2,
                register: BM1491_L9_MISC_REGISTER,
                value: BM1491_L9_WORKING_BAUD_MISC_VALUE,
                result_discarded: true,
            }
        );
        assert_eq!(
            plan.steps[4],
            Bm1491L9WorkingBaudStep::ConfigureHostUart {
                slot: 2,
                selector: BM1491_L9_WORKING_HOST_BAUD_SELECTOR,
                termios_speed: BM1491_L9_WORKING_TERMIOS_SPEED,
                result_discarded: true,
            }
        );
    }

    #[test]
    fn working_baud_transition_refuses_empty_duplicate_or_unknown_slots() {
        assert_eq!(
            plan_bm1491_l9_working_baud_transition(&[]),
            Err(Bm1491L9WorkingBaudPlanError::NoActiveRuntime)
        );
        assert_eq!(
            plan_bm1491_l9_working_baud_transition(&[0, 0]),
            Err(Bm1491L9WorkingBaudPlanError::DuplicateSlot { slot: 0 })
        );
        assert_eq!(
            plan_bm1491_l9_working_baud_transition(&[4]),
            Err(Bm1491L9WorkingBaudPlanError::SlotOutOfRange { slot: 4 })
        );
    }

    #[test]
    fn stock_platform_uninit_is_ordered_cleanup_but_not_safe_off() {
        assert_eq!(BM1491_L9_PLATFORM_UNINIT_ADDRESS, 0x0014_9a14);
        assert_eq!(
            BM1491_L9_PLATFORM_UNINIT_SPINE,
            [
                Bm1491L9PlatformUninitStep::ReturnIfPlatformNotInitialized,
                Bm1491L9PlatformUninitStep::FpgaUninitNoop,
                Bm1491L9PlatformUninitStep::ScanFourStaticCarrierSlots,
                Bm1491L9PlatformUninitStep::UnexportPlugGpioWhenRouteExists,
                Bm1491L9PlatformUninitStep::UnexportResetGpioWhenRouteExists,
                Bm1491L9PlatformUninitStep::DeleteUartMapWithoutClosingCachedDescriptors,
                Bm1491L9PlatformUninitStep::ClearFanWorkerFlagAndJoin,
                Bm1491L9PlatformUninitStep::UninitializeUi,
                Bm1491L9PlatformUninitStep::ClearGpioWorkerFlagJoinAndDeleteMap,
                Bm1491L9PlatformUninitStep::ClearPlatformInitialized,
            ]
        );
        assert!(BM1491_L9_FPGA_UNINIT_IS_NOOP);
        assert!(!BM1491_L9_UART_UNINIT_CLOSES_FILE_DESCRIPTORS);
        assert!(!BM1491_L9_PLATFORM_UNINIT_REQUESTS_POWER_OFF);
        assert!(!BM1491_L9_PLATFORM_UNINIT_PROVES_SAFE_OFF);
    }
}
