//! Pure route selection for the exact held BM1491/L9 CVCtrl IIC descriptors.
//!
//! `iic_init@0x0014ced0` recognizes one GPIO-bit-banged descriptor and
//! otherwise opens `/dev/i2c-0` or `/dev/i2c-3`. The exact APW17, EEPROM, and
//! held control-board sensor callers construct enough of that descriptor to
//! recover their software endpoint choices. These are copyable binary facts:
//! they do not identify a physical bus, prove exclusive ownership, or
//! authorize any read or write.

pub const BM1491_L9_IIC_INIT_ADDRESS: u32 = 0x0014_ced0;
pub const BM1491_L9_IIC_UNINIT_ADDRESS: u32 = 0x0014_d4c8;
pub const BM1491_L9_I2C_SIM_INIT_ADDRESS: u32 = 0x0017_4ef4;
pub const BM1491_L9_I2C_SIM_UNINIT_ADDRESS: u32 = 0x0017_5998;
pub const BM1491_L9_I2C_SIM_ACK_ADDRESS: u32 = 0x0017_5eac;
pub const BM1491_L9_I2C_SIM_WRITE_BYTE_ADDRESS: u32 = 0x0017_603c;
pub const BM1491_L9_I2C_SIM_READ_BYTE_ADDRESS: u32 = 0x0017_61cc;
pub const BM1491_L9_I2C_SIM_SEND_CMD_ADDRESS: u32 = 0x0017_6444;
pub const BM1491_L9_BITMAIN_POWER_OPEN_ADDRESS: u32 = 0x0016_4184;
pub const BM1491_L9_BITMAIN_POWER_CLOSE_ADDRESS: u32 = 0x0016_4684;
pub const BM1491_L9_EEPROM_OPEN_ADDRESS: u32 = 0x0015_2bc0;
pub const BM1491_L9_TSENSOR_OPEN_ADDRESS: u32 = 0x0016_876c;
pub const BM1491_L9_CONTROL_SENSOR_READ_ADDRESS: u32 = 0x0016_934c;

pub const BM1491_L9_I2C_DEVICE_ZERO: &str = "/dev/i2c-0";
pub const BM1491_L9_I2C_DEVICE_THREE: &str = "/dev/i2c-3";
pub const BM1491_L9_I2C_SIM_HANDLE: i32 = 0xff;
pub const BM1491_L9_I2C_SIM_SDA_GPIO: u16 = 461;
pub const BM1491_L9_I2C_SIM_SCL_GPIO: u16 = 459;
pub const BM1491_L9_I2C_SIM_BIT_DELAY_MS: u32 = 1;
pub const BM1491_L9_I2C_SIM_ACK_READ_ERROR_ATTEMPTS: u8 = 4;
pub const BM1491_L9_I2C_SIM_NACK_POLL_IS_BOUNDED: bool = false;
pub const BM1491_L9_I2C_SIM_SYSFS_WRITE_ERRORS_STOP_TRANSACTION: bool = false;
pub const BM1491_L9_I2C_SIM_UNINIT_UNEXPORTS_GPIOS: bool = false;
pub const BM1491_L9_I2C_SIM_UNINIT_DRIVES_IDLE_LEVELS: bool = false;
pub const BM1491_L9_I2C_SIM_UNINIT_INVALIDATES_FD_GLOBALS: bool = false;
pub const BM1491_L9_I2C_SLAVE_IOCTL: u16 = 0x0703;
pub const BM1491_L9_MAX_LOGICAL_CHAIN: u8 = 15;
pub const BM1491_L9_HELD_SENSOR_ADDRESSES: [u8; 2] = [0x4c, 0x48];

/// Twelve-byte descriptor consumed by exact `iic_init`.
///
/// The stock logger calls `routing_word` a chain and formats
/// `(address_high << 3) | address_low` as the slave. The Linux ioctl receives
/// the corresponding eight-bit/write-form value
/// `(address_high << 4) | (address_low << 1)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9IicDescriptor {
    pub linux_bus_selector: u8,
    pub routing_word: u32,
    pub routing_halfword: u16,
    pub address_high: u8,
    pub address_low: u8,
}

impl Bm1491L9IicDescriptor {
    pub const fn stock_logged_slave_value(self) -> u16 {
        ((self.address_high as u16) << 3) | self.address_low as u16
    }

    pub const fn stock_ioctl_slave_value(self) -> u16 {
        ((self.address_high as u16) << 4) | ((self.address_low as u16) << 1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9IicSoftwareBackend {
    GpioBitBang {
        handle: i32,
        sda_gpio: u16,
        scl_gpio: u16,
    },
    LinuxI2c {
        device: &'static str,
        ioctl_request: u16,
        ioctl_slave_value: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9IicRoutePlan {
    pub descriptor: Bm1491L9IicDescriptor,
    pub backend: Bm1491L9IicSoftwareBackend,
    _private: (),
}

impl Bm1491L9IicRoutePlan {
    /// Software route selection cannot prove the physical device, wiring,
    /// electrical address, freshness, ownership, or safe mutation policy.
    pub const fn admits_live_iic(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9IicRouteError {
    ChainOutOfRange { chain: u8 },
    SensorAddressOverflow { chain: u8, base_address: u8 },
    BitBangAddressOutOfRange { address: u8 },
    AckReadErrorCountOutOfRange { completed_errors: u8 },
}

/// One hardware-facing step emitted by `i2c_sim_send_cmd@0x00176444`.
///
/// Every `SendByte` calls the exact byte writer, but the caller discards its
/// result. `ReadByteAndSendFinalNack` returns `0xff` on a sysfs read error,
/// which stock cannot distinguish from legitimate data `0xff` at this layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9I2cSimWireStep {
    Start,
    SendByte(u8),
    ReadByteAndSendFinalNack,
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1491L9I2cSimCommandPlan {
    steps: Vec<Bm1491L9I2cSimWireStep>,
}

impl Bm1491L9I2cSimCommandPlan {
    pub fn steps(&self) -> &[Bm1491L9I2cSimWireStep] {
        &self.steps
    }

    /// The exact software plan is copyable evidence and cannot establish
    /// physical routing, transaction completion, or mutation authority.
    pub const fn admits_live_iic(&self) -> bool {
        false
    }
}

/// Exact reaction of the byte-writer ACK path to one SDA sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9I2cSimAckSample {
    Low,
    High,
    SysfsReadError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9I2cSimAckAction {
    AcceptByte,
    /// Stock re-samples after another clock toggle and has no counter or
    /// deadline on this path. A persistently high SDA can block forever.
    PollAgainWithoutBound,
    RetryAckRead {
        completed_errors: u8,
    },
    /// After the fourth read error stock logs and lets the byte caller return;
    /// `i2c_sim_send_cmd` still does not propagate a transaction failure.
    LogAndContinueWithoutAck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9I2cSimTeardownStep {
    CloseSclValueIfFdPositive,
    CloseSdaValueIfFdPositive,
    CloseSdaDirectionIfFdPositive,
}

pub const BM1491_L9_I2C_SIM_TEARDOWN_STEPS: [Bm1491L9I2cSimTeardownStep; 3] = [
    Bm1491L9I2cSimTeardownStep::CloseSclValueIfFdPositive,
    Bm1491L9I2cSimTeardownStep::CloseSdaValueIfFdPositive,
    Bm1491L9I2cSimTeardownStep::CloseSdaDirectionIfFdPositive,
];

/// Exact top-level branch in `bitmain_power_close@0x00164684`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9PowerCloseAction {
    /// This is the branch taken by a normal successful APW17 open
    /// (`handle=0xff`, open flag set). No IIC cleanup or PSU command occurs.
    ReturnWithoutCleanup,
    /// Stock reaches its IIC-uninit/state-clear body only when the handle is
    /// zero or the open flag is clear.
    AttemptIicUninitAndClearSoftwareState,
}

pub const fn bm1491_l9_stock_power_close_action(
    handle: i32,
    open_flag: bool,
) -> Bm1491L9PowerCloseAction {
    if handle != 0 && open_flag {
        Bm1491L9PowerCloseAction::ReturnWithoutCleanup
    } else {
        Bm1491L9PowerCloseAction::AttemptIicUninitAndClearSoftwareState
    }
}

/// Replay the exact flag-dependent command shape without touching GPIOs.
///
/// The legacy APW17 writer calls this with `read=false, write_command=true`,
/// producing a fresh START/address/command/data/STOP transaction for every
/// byte. Its reader uses `read=true, write_command=false`, producing a fresh
/// START/read-address/one-byte-read/final-NACK/STOP transaction per byte.
pub fn plan_bm1491_l9_i2c_sim_command(
    address: u8,
    read: bool,
    write_command: bool,
    command: u8,
    data: u8,
) -> Result<Bm1491L9I2cSimCommandPlan, Bm1491L9IicRouteError> {
    if address > 0x7f {
        return Err(Bm1491L9IicRouteError::BitBangAddressOutOfRange { address });
    }
    let write_address = address << 1;
    let mut steps = Vec::with_capacity(7);
    if write_command {
        steps.extend([
            Bm1491L9I2cSimWireStep::Start,
            Bm1491L9I2cSimWireStep::SendByte(write_address),
            Bm1491L9I2cSimWireStep::SendByte(command),
        ]);
    }
    if read {
        steps.extend([
            Bm1491L9I2cSimWireStep::Start,
            Bm1491L9I2cSimWireStep::SendByte(write_address | 1),
            Bm1491L9I2cSimWireStep::ReadByteAndSendFinalNack,
            Bm1491L9I2cSimWireStep::Stop,
        ]);
    } else {
        if !write_command {
            steps.extend([
                Bm1491L9I2cSimWireStep::Start,
                Bm1491L9I2cSimWireStep::SendByte(write_address),
            ]);
        }
        steps.extend([
            Bm1491L9I2cSimWireStep::SendByte(data),
            Bm1491L9I2cSimWireStep::Stop,
        ]);
    }
    Ok(Bm1491L9I2cSimCommandPlan { steps })
}

/// Replay one exact ACK-path decision. `completed_read_errors` counts prior
/// sysfs read errors for this byte and is therefore limited to `0..=3`.
pub const fn bm1491_l9_i2c_sim_ack_action(
    sample: Bm1491L9I2cSimAckSample,
    completed_read_errors: u8,
) -> Result<Bm1491L9I2cSimAckAction, Bm1491L9IicRouteError> {
    if completed_read_errors >= BM1491_L9_I2C_SIM_ACK_READ_ERROR_ATTEMPTS {
        return Err(Bm1491L9IicRouteError::AckReadErrorCountOutOfRange {
            completed_errors: completed_read_errors,
        });
    }
    Ok(match sample {
        Bm1491L9I2cSimAckSample::Low => Bm1491L9I2cSimAckAction::AcceptByte,
        Bm1491L9I2cSimAckSample::High => Bm1491L9I2cSimAckAction::PollAgainWithoutBound,
        Bm1491L9I2cSimAckSample::SysfsReadError => {
            let completed_errors = completed_read_errors + 1;
            if completed_errors == BM1491_L9_I2C_SIM_ACK_READ_ERROR_ATTEMPTS {
                Bm1491L9I2cSimAckAction::LogAndContinueWithoutAck
            } else {
                Bm1491L9I2cSimAckAction::RetryAckRead { completed_errors }
            }
        }
    })
}

/// Replay the exact branch order in `iic_init` without touching a device.
pub const fn select_bm1491_l9_iic_software_route(
    descriptor: Bm1491L9IicDescriptor,
) -> Bm1491L9IicRoutePlan {
    let backend = if descriptor.routing_word == 0
        && descriptor.routing_halfword == 1
        && descriptor.address_high == 2
        && descriptor.address_low == 0
    {
        Bm1491L9IicSoftwareBackend::GpioBitBang {
            handle: BM1491_L9_I2C_SIM_HANDLE,
            sda_gpio: BM1491_L9_I2C_SIM_SDA_GPIO,
            scl_gpio: BM1491_L9_I2C_SIM_SCL_GPIO,
        }
    } else {
        Bm1491L9IicSoftwareBackend::LinuxI2c {
            device: if descriptor.linux_bus_selector == 3 {
                BM1491_L9_I2C_DEVICE_THREE
            } else {
                BM1491_L9_I2C_DEVICE_ZERO
            },
            ioctl_request: BM1491_L9_I2C_SLAVE_IOCTL,
            ioctl_slave_value: descriptor.stock_ioctl_slave_value(),
        }
    };
    Bm1491L9IicRoutePlan {
        descriptor,
        backend,
        _private: (),
    }
}

/// Exact descriptor built by `bitmain_power_open@0x00164184`.
pub const fn bm1491_l9_apw17_iic_route() -> Bm1491L9IicRoutePlan {
    select_bm1491_l9_iic_software_route(Bm1491L9IicDescriptor {
        linux_bus_selector: 0,
        routing_word: 0,
        routing_halfword: 1,
        address_high: 2,
        address_low: 0,
    })
}

/// Exact per-chain descriptor built by `eeprom_open@0x00152bc0`.
pub const fn bm1491_l9_eeprom_iic_route(
    chain: u8,
) -> Result<Bm1491L9IicRoutePlan, Bm1491L9IicRouteError> {
    if chain > BM1491_L9_MAX_LOGICAL_CHAIN {
        return Err(Bm1491L9IicRouteError::ChainOutOfRange { chain });
    }
    Ok(select_bm1491_l9_iic_software_route(Bm1491L9IicDescriptor {
        linux_bus_selector: 0,
        routing_word: chain as u32,
        routing_halfword: 0,
        address_high: 0x0a,
        address_low: chain,
    }))
}

/// Exact descriptor shape built by `tsensor_open@0x0016876c` for the held
/// control-board sensor path. The held caller supplies Linux-bus selector zero
/// and one address per call. Stock adds the runtime slot to the base address,
/// then splits it into the descriptor's high/low fields.
pub const fn bm1491_l9_control_sensor_iic_route(
    chain: u8,
    base_address: u8,
) -> Result<Bm1491L9IicRoutePlan, Bm1491L9IicRouteError> {
    if chain > BM1491_L9_MAX_LOGICAL_CHAIN {
        return Err(Bm1491L9IicRouteError::ChainOutOfRange { chain });
    }
    let Some(address) = base_address.checked_add(chain) else {
        return Err(Bm1491L9IicRouteError::SensorAddressOverflow {
            chain,
            base_address,
        });
    };
    Ok(select_bm1491_l9_iic_software_route(Bm1491L9IicDescriptor {
        linux_bus_selector: 0,
        routing_word: chain as u32,
        routing_halfword: 0,
        address_high: (address >> 3) & 0x0f,
        address_low: address & 0x07,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apw17_selects_gpio_bitbang_before_linux_bus_branch() {
        let route = bm1491_l9_apw17_iic_route();
        assert_eq!(route.descriptor.stock_logged_slave_value(), 0x10);
        assert_eq!(route.descriptor.stock_ioctl_slave_value(), 0x20);
        assert_eq!(
            route.backend,
            Bm1491L9IicSoftwareBackend::GpioBitBang {
                handle: 0xff,
                sda_gpio: 461,
                scl_gpio: 459,
            }
        );
        assert!(!route.admits_live_iic());
    }

    #[test]
    fn held_eeprom_chains_select_dev_zero_and_shifted_slave_values() {
        for (chain, expected) in [(0, 0xa0), (1, 0xa2), (2, 0xa4), (15, 0xbe)] {
            let route = bm1491_l9_eeprom_iic_route(chain).unwrap();
            assert_eq!(
                route.backend,
                Bm1491L9IicSoftwareBackend::LinuxI2c {
                    device: "/dev/i2c-0",
                    ioctl_request: 0x703,
                    ioctl_slave_value: expected,
                }
            );
        }
        assert_eq!(
            bm1491_l9_eeprom_iic_route(16),
            Err(Bm1491L9IicRouteError::ChainOutOfRange { chain: 16 })
        );
    }

    #[test]
    fn both_held_sensor_bases_route_all_three_runtimes_over_dev_zero() {
        let expected = [(0x4c, [0x98, 0x9a, 0x9c]), (0x48, [0x90, 0x92, 0x94])];
        for (base, ioctl_values) in expected {
            for (chain, ioctl_slave_value) in ioctl_values.into_iter().enumerate() {
                let route = bm1491_l9_control_sensor_iic_route(chain as u8, base).unwrap();
                assert_eq!(
                    route.descriptor.stock_logged_slave_value(),
                    u16::from(base + chain as u8)
                );
                assert_eq!(
                    route.backend,
                    Bm1491L9IicSoftwareBackend::LinuxI2c {
                        device: "/dev/i2c-0",
                        ioctl_request: 0x703,
                        ioctl_slave_value,
                    }
                );
                assert!(!route.admits_live_iic());
            }
        }
    }

    #[test]
    fn generic_selector_three_is_dev_three_but_not_selected_by_held_consumers() {
        let route = select_bm1491_l9_iic_software_route(Bm1491L9IicDescriptor {
            linux_bus_selector: 3,
            routing_word: 1,
            routing_halfword: 0,
            address_high: 9,
            address_low: 4,
        });
        assert_eq!(
            route.backend,
            Bm1491L9IicSoftwareBackend::LinuxI2c {
                device: "/dev/i2c-3",
                ioctl_request: 0x703,
                ioctl_slave_value: 0x98,
            }
        );
    }

    #[test]
    fn control_sensor_builder_refuses_invalid_chain_or_wrapping_address() {
        assert_eq!(
            bm1491_l9_control_sensor_iic_route(16, 0x4c),
            Err(Bm1491L9IicRouteError::ChainOutOfRange { chain: 16 })
        );
        assert_eq!(
            bm1491_l9_control_sensor_iic_route(15, 0xf8),
            Err(Bm1491L9IicRouteError::SensorAddressOverflow {
                chain: 15,
                base_address: 0xf8,
            })
        );
    }

    #[test]
    fn apw17_bitbang_write_restarts_and_resends_command_for_each_byte() {
        let plan = plan_bm1491_l9_i2c_sim_command(0x10, false, true, 0x11, 0x55).unwrap();
        assert_eq!(
            plan.steps(),
            [
                Bm1491L9I2cSimWireStep::Start,
                Bm1491L9I2cSimWireStep::SendByte(0x20),
                Bm1491L9I2cSimWireStep::SendByte(0x11),
                Bm1491L9I2cSimWireStep::SendByte(0x55),
                Bm1491L9I2cSimWireStep::Stop,
            ]
        );
        assert!(!plan.admits_live_iic());
    }

    #[test]
    fn apw17_bitbang_read_is_one_byte_with_final_nack() {
        let plan = plan_bm1491_l9_i2c_sim_command(0x10, true, false, 0x11, 0).unwrap();
        assert_eq!(
            plan.steps(),
            [
                Bm1491L9I2cSimWireStep::Start,
                Bm1491L9I2cSimWireStep::SendByte(0x21),
                Bm1491L9I2cSimWireStep::ReadByteAndSendFinalNack,
                Bm1491L9I2cSimWireStep::Stop,
            ]
        );
    }

    #[test]
    fn bitbang_address_is_fail_closed_before_stock_u8_shift_wrap() {
        assert_eq!(
            plan_bm1491_l9_i2c_sim_command(0x80, false, true, 0x11, 0),
            Err(Bm1491L9IicRouteError::BitBangAddressOutOfRange { address: 0x80 })
        );
    }

    #[test]
    fn ack_path_pins_unbounded_nack_and_four_read_error_limit() {
        assert_eq!(
            bm1491_l9_i2c_sim_ack_action(Bm1491L9I2cSimAckSample::Low, 0),
            Ok(Bm1491L9I2cSimAckAction::AcceptByte)
        );
        assert_eq!(
            bm1491_l9_i2c_sim_ack_action(Bm1491L9I2cSimAckSample::High, 3),
            Ok(Bm1491L9I2cSimAckAction::PollAgainWithoutBound)
        );
        assert_eq!(
            bm1491_l9_i2c_sim_ack_action(Bm1491L9I2cSimAckSample::SysfsReadError, 0),
            Ok(Bm1491L9I2cSimAckAction::RetryAckRead {
                completed_errors: 1,
            })
        );
        assert_eq!(
            bm1491_l9_i2c_sim_ack_action(Bm1491L9I2cSimAckSample::SysfsReadError, 3),
            Ok(Bm1491L9I2cSimAckAction::LogAndContinueWithoutAck)
        );
        assert_eq!(
            bm1491_l9_i2c_sim_ack_action(Bm1491L9I2cSimAckSample::Low, 4),
            Err(Bm1491L9IicRouteError::AckReadErrorCountOutOfRange {
                completed_errors: 4,
            })
        );
    }

    #[test]
    fn bitbang_uninit_only_closes_positive_fds() {
        assert_eq!(
            BM1491_L9_I2C_SIM_TEARDOWN_STEPS,
            [
                Bm1491L9I2cSimTeardownStep::CloseSclValueIfFdPositive,
                Bm1491L9I2cSimTeardownStep::CloseSdaValueIfFdPositive,
                Bm1491L9I2cSimTeardownStep::CloseSdaDirectionIfFdPositive,
            ]
        );
        assert!(!BM1491_L9_I2C_SIM_UNINIT_UNEXPORTS_GPIOS);
        assert!(!BM1491_L9_I2C_SIM_UNINIT_DRIVES_IDLE_LEVELS);
        assert!(!BM1491_L9_I2C_SIM_UNINIT_INVALIDATES_FD_GLOBALS);
        assert!(!BM1491_L9_I2C_SIM_NACK_POLL_IS_BOUNDED);
        assert!(!BM1491_L9_I2C_SIM_SYSFS_WRITE_ERRORS_STOP_TRANSACTION);
    }

    #[test]
    fn normal_power_close_state_returns_before_iic_cleanup() {
        assert_eq!(
            bm1491_l9_stock_power_close_action(0xff, true),
            Bm1491L9PowerCloseAction::ReturnWithoutCleanup
        );
        for (handle, open_flag) in [(0, true), (0xff, false), (0, false)] {
            assert_eq!(
                bm1491_l9_stock_power_close_action(handle, open_flag),
                Bm1491L9PowerCloseAction::AttemptIicUninitAndClearSoftwareState
            );
        }
    }
}
