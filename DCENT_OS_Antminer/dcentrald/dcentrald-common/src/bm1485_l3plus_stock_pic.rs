//! Exact-release BM1485/L3+ stock PIC, heartbeat, and thermal rail-off replay.
//!
//! The held 2017 stock `cgminer` selects one of four PIC endpoints on
//! `/dev/i2c-0` and writes command bytes one at a time. Runtime rail and
//! heartbeat paths never read a reply and ignore every write result. This
//! module performs no I/O and grants no carrier, rail, or shutdown authority.

use crate::bm1485_l3plus_stock::BM1485_L3PLUS_STOCK_CHAIN_COUNT;

pub const BM1485_L3PLUS_STOCK_PIC_BUS_PATH: &str = "/dev/i2c-0";
pub const BM1485_L3PLUS_STOCK_I2C_SLAVE_IOCTL: u32 = 0x703;
/// Eight-bit addresses stored by the exact binary before its `>> 1` ioctl.
pub const BM1485_L3PLUS_STOCK_PIC_STORED_ADDRESSES: [u8; 4] = [0xa0, 0xa2, 0xa4, 0xa6];
/// Seven-bit Linux I2C slave addresses actually passed to `I2C_SLAVE`.
pub const BM1485_L3PLUS_STOCK_PIC_SLAVE_ADDRESSES: [u8; 4] = [0x50, 0x51, 0x52, 0x53];

pub const BM1485_L3PLUS_STOCK_PIC_PREAMBLE: [u8; 2] = [0x55, 0xaa];
pub const BM1485_L3PLUS_STOCK_PIC_RAIL_OPCODE: u8 = 0x15;
pub const BM1485_L3PLUS_STOCK_PIC_HEARTBEAT_OPCODE: u8 = 0x16;
pub const BM1485_L3PLUS_STOCK_PIC_INTERBYTE_DELAY_US: u32 = 200;
pub const BM1485_L3PLUS_STOCK_HEARTBEAT_AFTER_CHAIN_DELAY_MS: u32 = 10;
pub const BM1485_L3PLUS_STOCK_HEARTBEAT_AFTER_SCAN_SLEEP_SECONDS: u32 = 10;
pub const BM1485_L3PLUS_STOCK_PIC_STARTUP_PHASE_DELAY_MS: u32 = 1_000;
pub const BM1485_L3PLUS_STOCK_RAIL_ENABLE_POST_PHASE_DELAY_MS: u32 = 5_000;

#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_STOCK_PIC_APPLICATION_RESET_OPCODE: u8 = 0x07;
#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_STOCK_PIC_JUMP_TO_APP_OPCODE: u8 = 0x06;
#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_STOCK_PIC_RECOVERY_COMMAND_TAIL_DELAY_US: u32 = 100_000;

/// The active-chain maximum is refreshed by `FUN_0003d0e0`, whose loop ends
/// with `sleep(10)`. `FUN_0003c7f4` then compares the retained byte strictly.
pub const BM1485_L3PLUS_STOCK_TEMP_MAX_REFRESH_SLEEP_SECONDS: u32 = 10;
pub const BM1485_L3PLUS_STOCK_THERMAL_RAIL_CUTOFF_C: u8 = 85;
pub const BM1485_L3PLUS_STOCK_THERMAL_MONITOR_TAIL_DELAY_MS: u32 = 1_000;

pub const BM1485_L3PLUS_STOCK_PIC_RUNTIME_READS_RESPONSES: bool = false;
pub const BM1485_L3PLUS_STOCK_PIC_RUNTIME_PROPAGATES_IOCTL_FAILURE: bool = false;
pub const BM1485_L3PLUS_STOCK_PIC_RUNTIME_PROPAGATES_WRITE_FAILURE: bool = false;
pub const BM1485_L3PLUS_STOCK_HEARTBEAT_DETECTS_FAILURE: bool = false;
pub const BM1485_L3PLUS_STOCK_HEARTBEAT_CUTS_RAIL_ON_FAILURE: bool = false;

/// The exact normal ARM startup/runtime call graph has no operational
/// opcode-0x10 call. The separate PIC image implements a latent DAC-byte
/// command, but neither that nor a copyable UI field establishes volts.
pub const BM1485_L3PLUS_STOCK_HAS_RECOVERED_OPERATIONAL_SET_VOLTAGE_PATH: bool = false;
pub const BM1485_L3PLUS_STOCK_UI_VOLTAGE_FIELD_AUTHORIZES_MUTATION: bool = false;
pub const BM1485_L3PLUS_STOCK_PIC_IDENTIFIES_PHYSICAL_BOARD: bool = false;
pub const BM1485_L3PLUS_STOCK_PIC_AUTHORIZES_I2C_IO: bool = false;
pub const BM1485_L3PLUS_STOCK_PIC_AUTHORIZES_RAIL_MUTATION: bool = false;
pub const BM1485_L3PLUS_STOCK_THERMAL_PLAN_PROVES_ELECTRICAL_OFF: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3PlusStockPicError {
    ChainSlotOutOfRange(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusStockPicEndpoint {
    pub chain_slot: u8,
    pub stored_eight_bit_address: u8,
    pub linux_seven_bit_slave_address: u8,
}

pub fn bm1485_l3plus_stock_pic_endpoint(
    chain_slot: usize,
) -> Result<Bm1485L3PlusStockPicEndpoint, Bm1485L3PlusStockPicError> {
    if chain_slot >= BM1485_L3PLUS_STOCK_CHAIN_COUNT {
        return Err(Bm1485L3PlusStockPicError::ChainSlotOutOfRange(chain_slot));
    }
    Ok(Bm1485L3PlusStockPicEndpoint {
        chain_slot: chain_slot as u8,
        stored_eight_bit_address: BM1485_L3PLUS_STOCK_PIC_STORED_ADDRESSES[chain_slot],
        linux_seven_bit_slave_address: BM1485_L3PLUS_STOCK_PIC_SLAVE_ADDRESSES[chain_slot],
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3PlusStockRuntimePicCommand {
    RailEnable,
    RailDisable,
    Heartbeat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusStockPicWritePlan {
    pub endpoint: Bm1485L3PlusStockPicEndpoint,
    /// Fixed-capacity command bytes; only `wire_len` bytes are emitted.
    pub wire_bytes: [u8; 4],
    wire_len: u8,
    /// Delay after each emitted byte. Unused positions are zero.
    pub delay_after_byte_us: [u32; 4],
    pub reads_response: bool,
    pub propagates_ioctl_failure: bool,
    pub propagates_write_failure: bool,
}

impl Bm1485L3PlusStockPicWritePlan {
    pub fn emitted_bytes(&self) -> &[u8] {
        &self.wire_bytes[..usize::from(self.wire_len)]
    }

    pub const fn wire_len(self) -> u8 {
        self.wire_len
    }

    pub const fn authorizes_execution(self) -> bool {
        false
    }
}

fn pic_write_plan(
    chain_slot: usize,
    wire_bytes: [u8; 4],
    wire_len: u8,
    delay_after_byte_us: [u32; 4],
) -> Result<Bm1485L3PlusStockPicWritePlan, Bm1485L3PlusStockPicError> {
    Ok(Bm1485L3PlusStockPicWritePlan {
        endpoint: bm1485_l3plus_stock_pic_endpoint(chain_slot)?,
        wire_bytes,
        wire_len,
        delay_after_byte_us,
        reads_response: BM1485_L3PLUS_STOCK_PIC_RUNTIME_READS_RESPONSES,
        propagates_ioctl_failure: BM1485_L3PLUS_STOCK_PIC_RUNTIME_PROPAGATES_IOCTL_FAILURE,
        propagates_write_failure: BM1485_L3PLUS_STOCK_PIC_RUNTIME_PROPAGATES_WRITE_FAILURE,
    })
}

pub fn bm1485_l3plus_stock_runtime_pic_command_plan(
    chain_slot: usize,
    command: Bm1485L3PlusStockRuntimePicCommand,
) -> Result<Bm1485L3PlusStockPicWritePlan, Bm1485L3PlusStockPicError> {
    let (wire_bytes, wire_len, delay_after_byte_us) = match command {
        Bm1485L3PlusStockRuntimePicCommand::RailEnable => (
            [0x55, 0xaa, BM1485_L3PLUS_STOCK_PIC_RAIL_OPCODE, 0x01],
            4,
            [BM1485_L3PLUS_STOCK_PIC_INTERBYTE_DELAY_US; 4],
        ),
        Bm1485L3PlusStockRuntimePicCommand::RailDisable => (
            [0x55, 0xaa, BM1485_L3PLUS_STOCK_PIC_RAIL_OPCODE, 0x00],
            4,
            [BM1485_L3PLUS_STOCK_PIC_INTERBYTE_DELAY_US; 4],
        ),
        Bm1485L3PlusStockRuntimePicCommand::Heartbeat => (
            [0x55, 0xaa, BM1485_L3PLUS_STOCK_PIC_HEARTBEAT_OPCODE, 0x00],
            3,
            [
                BM1485_L3PLUS_STOCK_PIC_INTERBYTE_DELAY_US,
                BM1485_L3PLUS_STOCK_PIC_INTERBYTE_DELAY_US,
                0,
                0,
            ],
        ),
    };
    pic_write_plan(chain_slot, wire_bytes, wire_len, delay_after_byte_us)
}

#[cfg(feature = "recovery-tool")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3PlusStockRecoveryPicCommand {
    ApplicationReset,
    JumpToApplication,
}

/// Feature-gated replay of the destructive startup command helpers. These
/// symbols do not link into the normal `dcentrald` build.
#[cfg(feature = "recovery-tool")]
pub fn bm1485_l3plus_stock_recovery_pic_command_plan(
    chain_slot: usize,
    command: Bm1485L3PlusStockRecoveryPicCommand,
) -> Result<Bm1485L3PlusStockPicWritePlan, Bm1485L3PlusStockPicError> {
    let opcode = match command {
        Bm1485L3PlusStockRecoveryPicCommand::ApplicationReset => {
            BM1485_L3PLUS_STOCK_PIC_APPLICATION_RESET_OPCODE
        }
        Bm1485L3PlusStockRecoveryPicCommand::JumpToApplication => {
            BM1485_L3PLUS_STOCK_PIC_JUMP_TO_APP_OPCODE
        }
    };
    pic_write_plan(
        chain_slot,
        [0x55, 0xaa, opcode, 0x00],
        3,
        [
            BM1485_L3PLUS_STOCK_PIC_INTERBYTE_DELAY_US,
            BM1485_L3PLUS_STOCK_PIC_INTERBYTE_DELAY_US,
            BM1485_L3PLUS_STOCK_PIC_RECOVERY_COMMAND_TAIL_DELAY_US,
            0,
        ],
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusStockHeartbeatSlotPlan {
    pub write: Bm1485L3PlusStockPicWritePlan,
    pub delay_after_chain_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusStockHeartbeatScanPlan {
    /// Caller supplies the exact stock combined eligibility predicate: chain
    /// active and the global heartbeat-state byte enabled.
    pub slots: [Option<Bm1485L3PlusStockHeartbeatSlotPlan>; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
    pub sleep_after_scan_seconds: u32,
    pub detects_failure: bool,
    pub cuts_rail_on_failure: bool,
}

impl Bm1485L3PlusStockHeartbeatScanPlan {
    pub const fn authorizes_execution(self) -> bool {
        false
    }
}

pub fn bm1485_l3plus_stock_heartbeat_scan_plan(
    eligible_chains: [bool; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
) -> Bm1485L3PlusStockHeartbeatScanPlan {
    let mut slots = [None; BM1485_L3PLUS_STOCK_CHAIN_COUNT];
    for (chain_slot, eligible) in eligible_chains.into_iter().enumerate() {
        if eligible {
            // Enumeration guarantees the fixed four-slot endpoint is valid.
            if let Ok(write) = bm1485_l3plus_stock_runtime_pic_command_plan(
                chain_slot,
                Bm1485L3PlusStockRuntimePicCommand::Heartbeat,
            ) {
                slots[chain_slot] = Some(Bm1485L3PlusStockHeartbeatSlotPlan {
                    write,
                    delay_after_chain_ms: BM1485_L3PLUS_STOCK_HEARTBEAT_AFTER_CHAIN_DELAY_MS,
                });
            }
        }
    }
    Bm1485L3PlusStockHeartbeatScanPlan {
        slots,
        sleep_after_scan_seconds: BM1485_L3PLUS_STOCK_HEARTBEAT_AFTER_SCAN_SLEEP_SECONDS,
        detects_failure: BM1485_L3PLUS_STOCK_HEARTBEAT_DETECTS_FAILURE,
        cuts_rail_on_failure: BM1485_L3PLUS_STOCK_HEARTBEAT_CUTS_RAIL_ON_FAILURE,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusStockThermalRailOffPlan {
    pub latest_max_temperature_sample_c: u8,
    pub over_temperature: bool,
    /// Exact action-level best-effort writes. Stock does not verify electrical
    /// de-energization and does not expose command failure to this caller.
    pub rail_disable_writes:
        [Option<Bm1485L3PlusStockPicWritePlan>; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
    pub monitor_tail_delay_ms: u32,
}

impl Bm1485L3PlusStockThermalRailOffPlan {
    pub const fn authorizes_execution(self) -> bool {
        false
    }

    pub const fn proves_electrical_off(self) -> bool {
        false
    }
}

/// Replays the command-level branch of `FUN_0003c7f4`. Equality at 85 C is
/// accepted; 86 C and above attempt opcode-0x15/payload-0 on active slots.
pub fn bm1485_l3plus_stock_thermal_rail_off_plan(
    latest_max_temperature_sample_c: u8,
    active_chains: [bool; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
) -> Bm1485L3PlusStockThermalRailOffPlan {
    let over_temperature =
        latest_max_temperature_sample_c > BM1485_L3PLUS_STOCK_THERMAL_RAIL_CUTOFF_C;
    let mut rail_disable_writes = [None; BM1485_L3PLUS_STOCK_CHAIN_COUNT];
    if over_temperature {
        for (chain_slot, active) in active_chains.into_iter().enumerate() {
            if active {
                if let Ok(write) = bm1485_l3plus_stock_runtime_pic_command_plan(
                    chain_slot,
                    Bm1485L3PlusStockRuntimePicCommand::RailDisable,
                ) {
                    rail_disable_writes[chain_slot] = Some(write);
                }
            }
        }
    }
    Bm1485L3PlusStockThermalRailOffPlan {
        latest_max_temperature_sample_c,
        over_temperature,
        rail_disable_writes,
        monitor_tail_delay_ms: BM1485_L3PLUS_STOCK_THERMAL_MONITOR_TAIL_DELAY_MS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_endpoint_table_uses_linux_seven_bit_addresses() {
        for chain_slot in 0..BM1485_L3PLUS_STOCK_CHAIN_COUNT {
            let endpoint = bm1485_l3plus_stock_pic_endpoint(chain_slot).unwrap();
            assert_eq!(endpoint.chain_slot, chain_slot as u8);
            assert_eq!(
                endpoint.stored_eight_bit_address,
                0xa0 + 2 * chain_slot as u8
            );
            assert_eq!(
                endpoint.linux_seven_bit_slave_address,
                0x50 + chain_slot as u8
            );
            assert_eq!(
                endpoint.stored_eight_bit_address >> 1,
                endpoint.linux_seven_bit_slave_address
            );
        }
        assert_eq!(
            bm1485_l3plus_stock_pic_endpoint(4),
            Err(Bm1485L3PlusStockPicError::ChainSlotOutOfRange(4))
        );
    }

    #[test]
    fn rail_commands_are_raw_unacknowledged_four_byte_writes() {
        let enable = bm1485_l3plus_stock_runtime_pic_command_plan(
            0,
            Bm1485L3PlusStockRuntimePicCommand::RailEnable,
        )
        .unwrap();
        let disable = bm1485_l3plus_stock_runtime_pic_command_plan(
            3,
            Bm1485L3PlusStockRuntimePicCommand::RailDisable,
        )
        .unwrap();
        assert_eq!(enable.emitted_bytes(), [0x55, 0xaa, 0x15, 0x01]);
        assert_eq!(disable.emitted_bytes(), [0x55, 0xaa, 0x15, 0x00]);
        assert_eq!(enable.wire_len(), 4);
        assert_eq!(enable.delay_after_byte_us, [200, 200, 200, 200]);
        assert_eq!(disable.endpoint.linux_seven_bit_slave_address, 0x53);
        assert!(!enable.reads_response);
        assert!(!enable.propagates_ioctl_failure);
        assert!(!enable.propagates_write_failure);
        assert!(!enable.authorizes_execution());
    }

    #[test]
    fn heartbeat_only_sends_and_never_detects_failure() {
        let scan = bm1485_l3plus_stock_heartbeat_scan_plan([true, false, true, false]);
        assert_eq!(scan.slots[1], None);
        assert_eq!(scan.slots[3], None);
        for slot in [0, 2] {
            let planned = scan.slots[slot].unwrap();
            assert_eq!(planned.write.emitted_bytes(), [0x55, 0xaa, 0x16]);
            assert_eq!(planned.write.delay_after_byte_us, [200, 200, 0, 0]);
            assert_eq!(planned.delay_after_chain_ms, 10);
        }
        assert_eq!(scan.sleep_after_scan_seconds, 10);
        assert!(!scan.detects_failure);
        assert!(!scan.cuts_rail_on_failure);
        assert!(!scan.authorizes_execution());
    }

    #[test]
    fn thermal_threshold_is_strict_and_disable_is_best_effort() {
        let equality = bm1485_l3plus_stock_thermal_rail_off_plan(85, [true; 4]);
        assert!(!equality.over_temperature);
        assert_eq!(equality.rail_disable_writes, [None; 4]);

        let exceeded = bm1485_l3plus_stock_thermal_rail_off_plan(86, [true, false, true, false]);
        assert!(exceeded.over_temperature);
        assert_eq!(
            exceeded.rail_disable_writes[0].unwrap().emitted_bytes(),
            [0x55, 0xaa, 0x15, 0x00]
        );
        assert_eq!(exceeded.rail_disable_writes[1], None);
        assert!(exceeded.rail_disable_writes[2].is_some());
        assert_eq!(exceeded.rail_disable_writes[3], None);
        assert_eq!(exceeded.monitor_tail_delay_ms, 1_000);
        assert!(!exceeded.proves_electrical_off());
        assert!(!exceeded.authorizes_execution());
    }

    #[test]
    fn voltage_strings_and_stock_pic_replay_never_mint_authority() {
        assert!(!BM1485_L3PLUS_STOCK_HAS_RECOVERED_OPERATIONAL_SET_VOLTAGE_PATH);
        assert!(!BM1485_L3PLUS_STOCK_UI_VOLTAGE_FIELD_AUTHORIZES_MUTATION);
        assert!(!BM1485_L3PLUS_STOCK_PIC_IDENTIFIES_PHYSICAL_BOARD);
        assert!(!BM1485_L3PLUS_STOCK_PIC_AUTHORIZES_I2C_IO);
        assert!(!BM1485_L3PLUS_STOCK_PIC_AUTHORIZES_RAIL_MUTATION);
        assert!(!BM1485_L3PLUS_STOCK_THERMAL_PLAN_PROVES_ELECTRICAL_OFF);
    }

    #[cfg(feature = "recovery-tool")]
    #[test]
    fn destructive_startup_commands_only_exist_in_recovery_builds() {
        let reset = bm1485_l3plus_stock_recovery_pic_command_plan(
            0,
            Bm1485L3PlusStockRecoveryPicCommand::ApplicationReset,
        )
        .unwrap();
        let jump = bm1485_l3plus_stock_recovery_pic_command_plan(
            1,
            Bm1485L3PlusStockRecoveryPicCommand::JumpToApplication,
        )
        .unwrap();
        assert_eq!(reset.emitted_bytes(), [0x55, 0xaa, 0x07]);
        assert_eq!(jump.emitted_bytes(), [0x55, 0xaa, 0x06]);
        assert_eq!(reset.delay_after_byte_us, [200, 200, 100_000, 0]);
        assert_eq!(jump.delay_after_byte_us, [200, 200, 100_000, 0]);
        assert_eq!(BM1485_L3PLUS_STOCK_PIC_STARTUP_PHASE_DELAY_MS, 1_000);
        assert_eq!(BM1485_L3PLUS_STOCK_RAIL_ENABLE_POST_PHASE_DELAY_MS, 5_000);
    }
}
