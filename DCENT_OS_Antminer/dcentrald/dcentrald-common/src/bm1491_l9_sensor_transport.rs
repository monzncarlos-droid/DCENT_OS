//! Pure transport-result replay for the exact held BM1491/L9 sensor backends.
//!
//! `read_sensor_temp_local_ltc` and `read_sensor_temp_remote_ltc` dispatch
//! among PIC, on-chip, and control-board sensor paths. The exact held L9
//! runtime copies two six-word sensor descriptors whose source-selector word
//! is two, so both configured sensors select the control-board backend. This
//! module models that release-bound choice and all three exact backend result
//! shapes without executing or authorizing any transport.

pub const BM1491_L9_READ_SENSOR_LOCAL_ADDRESS: u32 = 0x000f_94a0;
pub const BM1491_L9_READ_SENSOR_REMOTE_ADDRESS: u32 = 0x000f_9588;
pub const BM1491_L9_SET_SENSOR_EXTERNAL_MODE_ADDRESS: u32 = 0x000f_9460;
pub const BM1491_L9_ONCHIP_SEND_ADDRESS: u32 = 0x000f_1a84;
pub const BM1491_L9_ONCHIP_RECEIVE_ADDRESS: u32 = 0x000f_1b00;
pub const BM1491_L9_ONCHIP_QUERY_ADDRESS: u32 = 0x000f_1ce4;
pub const BM1491_L9_ONCHIP_EXTERNAL_MODE_ADDRESS: u32 = 0x000f_2b84;
pub const BM1491_L9_PIC_LOCAL_ADDRESS: u32 = 0x000f_21a8;
pub const BM1491_L9_PIC_REMOTE_ADDRESS: u32 = 0x000f_2410;
pub const BM1491_L9_CTRLBOARD_LOCAL_ADDRESS: u32 = 0x000f_2678;
pub const BM1491_L9_CTRLBOARD_REMOTE_ADDRESS: u32 = 0x000f_29e8;
pub const BM1491_L9_READ_TEMPERATURE_ADDRESS: u32 = 0x000b_0648;
pub const BM1491_L9_RUNTIME_CTRL_ADDRESS: u32 = 0x000f_a450;
pub const BM1491_L9_SENSOR_DESCRIPTORS_ADDRESS: u32 = 0x002c_b954;
pub const BM1491_L9_SENSOR_INFO_ADDRESS: u32 = 0x002c_b984;

pub const BM1491_L9_INVALID_TEMPERATURE_C: i32 = -64;
pub const BM1491_L9_SENSOR_WRAPPER_FAILURE_STATUS: u32 = 4;
pub const BM1491_L9_SENSOR_WRAPPER_SUCCESS_STATUS: u32 = 0;
pub const BM1491_L9_PIC_SENSOR_DELAY_MS: u32 = 10;
pub const BM1491_L9_ONCHIP_SENSOR_DELAY_MS: u32 = 50;
pub const BM1491_L9_ONCHIP_EXTERNAL_MODE_DELAY_MS: u32 = 100;
pub const BM1491_L9_ONCHIP_LOCAL_COMMAND: u32 = 0x0198_0000;
pub const BM1491_L9_ONCHIP_REMOTE_COMMAND: u32 = 0x0198_0100;
pub const BM1491_L9_ONCHIP_EXTERNAL_MODE_COMMAND: u32 = 0x0199_0904;
pub const BM1491_L9_ONCHIP_DESCRIPTOR_HIGH_WORD: u32 = 0xff;
pub const BM1491_L9_ONCHIP_EXTERNAL_MODE_DESCRIPTOR: u64 = 0x0000_00ff_0000_0001;
pub const BM1491_L9_ONCHIP_MAX_RECORDS: u8 = 1;
pub const BM1491_L9_PIC_REMOTE_OFFSET_C: i32 = 15;
pub const BM1491_L9_CT75_SENSOR_MODE: u32 = 3;

pub const BM1491_L9_TOPOL_PIC_MCU_ENABLED: bool = false;
pub const BM1491_L9_TOPOL_READ_CTRLBOARD_TEMPERATURE: bool = false;
pub const BM1491_L9_TOPOL_SENSOR_TYPE: &str = "onchip_sensor_unknown";
pub const BM1491_L9_SELECTED_SENSOR_SOURCE_PROVEN: bool = true;
pub const BM1491_L9_SENSOR_TRANSPORT_OWNERSHIP_PROVEN: bool = false;
pub const BM1491_L9_SENSOR_TRANSPORT_AUTHORIZES_IO: bool = false;
pub const BM1491_L9_SENSOR_TRANSPORT_AUTHORIZES_MINING: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9SensorSourceMode {
    Pic = 0,
    OnChip = 1,
    ControlBoard = 2,
}

/// Exact six-word descriptor shape consumed by `read_temperature_ini` for the
/// held L9 release. `sensor_kind` controls CT75 decoding while `source` is the
/// independent wrapper selector. The two placement fields are preserved as
/// observational enum values because their physical connector mapping is not
/// established by this binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9HeldSensorDescriptor {
    pub index: u32,
    pub sensor_kind: u32,
    pub source: Bm1491L9SensorSourceMode,
    pub airflow_position: u32,
    pub vertical_position: u32,
    pub sensor_address: u8,
}

pub const BM1491_L9_HELD_SENSOR_DESCRIPTORS: [Bm1491L9HeldSensorDescriptor; 2] = [
    Bm1491L9HeldSensorDescriptor {
        index: 0,
        sensor_kind: 1,
        source: Bm1491L9SensorSourceMode::ControlBoard,
        airflow_position: 0,
        vertical_position: 0,
        sensor_address: 0x4c,
    },
    Bm1491L9HeldSensorDescriptor {
        index: 1,
        sensor_kind: 1,
        source: Bm1491L9SensorSourceMode::ControlBoard,
        airflow_position: 1,
        vertical_position: 0,
        sensor_address: 0x48,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9HeldSensorPlanError {
    SensorIndexOutOfRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9SensorChannel {
    Local,
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9SensorTransportAction {
    PicWriteIic {
        sensor_address: u8,
    },
    DelayMilliseconds(u32),
    PicReadIic {
        sensor_address: u8,
    },
    OnChipSend {
        descriptor: u64,
        command: u64,
    },
    OnChipReceive {
        descriptor: u64,
        maximum_records: u8,
    },
    ControlBoardRead {
        sensor_address: u8,
        ct75: bool,
        expected_length: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1491L9SensorTransportPlan {
    pub source: Bm1491L9SensorSourceMode,
    pub channel: Bm1491L9SensorChannel,
    pub actions: Vec<Bm1491L9SensorTransportAction>,
    pub selected_for_held_release_proven: bool,
}

impl Bm1491L9SensorTransportPlan {
    pub const fn admits_hardware_io(&self) -> bool {
        false
    }
}

const fn bm1491_l9_onchip_descriptor(sensor_address: u8) -> u64 {
    ((BM1491_L9_ONCHIP_DESCRIPTOR_HIGH_WORD as u64) << 32) | ((sensor_address as u64) << 8)
}

/// Recover the exact external-sensor-mode setup request. The send result is
/// intentionally not interpreted here: stock always performs the 100-ms
/// delay, then its caller sets the runtime decode flag only when the send
/// helper returned zero.
pub fn bm1491_l9_plan_onchip_external_mode() -> Vec<Bm1491L9SensorTransportAction> {
    vec![
        Bm1491L9SensorTransportAction::OnChipSend {
            descriptor: BM1491_L9_ONCHIP_EXTERNAL_MODE_DESCRIPTOR,
            command: u64::from(BM1491_L9_ONCHIP_EXTERNAL_MODE_COMMAND),
        },
        Bm1491L9SensorTransportAction::DelayMilliseconds(BM1491_L9_ONCHIP_EXTERNAL_MODE_DELAY_MS),
    ]
}

/// Replay the caller's external-mode flag update. A zero send result sets the
/// flag to one; every nonzero result preserves the previous value. This flag
/// controls whether accepted on-chip samples subtract 64 C.
pub const fn bm1491_l9_replay_onchip_external_mode_flag(previous_flag: u8, send_result: i32) -> u8 {
    if send_result == 0 {
        1
    } else {
        previous_flag
    }
}

/// Build the hardware-facing action spine for one of the three recovered
/// dispatch modes. `sensor_kind` is descriptor word one and only distinguishes
/// the one-byte CT75 local control-board read from the normal two-byte read.
pub fn bm1491_l9_plan_sensor_transport(
    source: Bm1491L9SensorSourceMode,
    channel: Bm1491L9SensorChannel,
    sensor_address: u8,
    sensor_kind: u32,
) -> Bm1491L9SensorTransportPlan {
    bm1491_l9_plan_sensor_transport_with_selection(
        source,
        channel,
        sensor_address,
        sensor_kind,
        false,
    )
}

fn bm1491_l9_plan_sensor_transport_with_selection(
    source: Bm1491L9SensorSourceMode,
    channel: Bm1491L9SensorChannel,
    sensor_address: u8,
    sensor_kind: u32,
    selected_for_held_release_proven: bool,
) -> Bm1491L9SensorTransportPlan {
    let actions = match source {
        Bm1491L9SensorSourceMode::Pic => vec![
            Bm1491L9SensorTransportAction::PicWriteIic { sensor_address },
            Bm1491L9SensorTransportAction::DelayMilliseconds(BM1491_L9_PIC_SENSOR_DELAY_MS),
            Bm1491L9SensorTransportAction::PicReadIic { sensor_address },
        ],
        Bm1491L9SensorSourceMode::OnChip => {
            let descriptor = bm1491_l9_onchip_descriptor(sensor_address);
            let command = match channel {
                Bm1491L9SensorChannel::Local => BM1491_L9_ONCHIP_LOCAL_COMMAND,
                Bm1491L9SensorChannel::Remote => BM1491_L9_ONCHIP_REMOTE_COMMAND,
            };
            vec![
                Bm1491L9SensorTransportAction::OnChipSend {
                    descriptor,
                    command: u64::from(command),
                },
                Bm1491L9SensorTransportAction::DelayMilliseconds(BM1491_L9_ONCHIP_SENSOR_DELAY_MS),
                Bm1491L9SensorTransportAction::OnChipReceive {
                    descriptor,
                    maximum_records: BM1491_L9_ONCHIP_MAX_RECORDS,
                },
            ]
        }
        Bm1491L9SensorSourceMode::ControlBoard => {
            let ct75 = channel == Bm1491L9SensorChannel::Local
                && sensor_kind == BM1491_L9_CT75_SENSOR_MODE;
            vec![Bm1491L9SensorTransportAction::ControlBoardRead {
                sensor_address,
                ct75,
                expected_length: if ct75 { 1 } else { 2 },
            }]
        }
    };
    Bm1491L9SensorTransportPlan {
        source,
        channel,
        actions,
        selected_for_held_release_proven,
    }
}

/// Plan one held-release sensor read from the exact compiled descriptor. This
/// proves stock's selected backend for these bytes, but it does not establish
/// descriptor freshness, physical sensor identity, bus ownership, or I/O
/// authority.
pub fn bm1491_l9_plan_held_sensor_transport(
    sensor_index: usize,
    channel: Bm1491L9SensorChannel,
) -> Result<Bm1491L9SensorTransportPlan, Bm1491L9HeldSensorPlanError> {
    let descriptor = BM1491_L9_HELD_SENSOR_DESCRIPTORS
        .get(sensor_index)
        .ok_or(Bm1491L9HeldSensorPlanError::SensorIndexOutOfRange)?;
    Ok(bm1491_l9_plan_sensor_transport_with_selection(
        descriptor.source,
        channel,
        descriptor.sensor_address,
        descriptor.sensor_kind,
        true,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9SensorBackendResult {
    pub temperature_c: i32,
    pub valid: bool,
    pub backend_return: i32,
    pub wrapper_status: u32,
}

impl Bm1491L9SensorBackendResult {
    pub const fn admits_sensor_authority(&self) -> bool {
        false
    }
}

/// Exact outer-wrapper mapping. Only backend return `-1` becomes wrapper
/// status four; zero and every other value are reported as wrapper success.
pub const fn bm1491_l9_sensor_wrapper_status(backend_return: i32) -> u32 {
    if backend_return == -1 {
        BM1491_L9_SENSOR_WRAPPER_FAILURE_STATUS
    } else {
        BM1491_L9_SENSOR_WRAPPER_SUCCESS_STATUS
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9PicSensorReplayError {
    ReadSuppliedAfterWriteFailure,
}

/// Replay a PIC backend result. PIC write/read failure returns zero, so the
/// outer wrapper still reports success while the sample remains `-64` and
/// invalid. Successful values are signed bytes; remote adds 15 C.
pub fn bm1491_l9_replay_pic_sensor_result(
    channel: Bm1491L9SensorChannel,
    write_succeeded: bool,
    read_value: Option<u8>,
) -> Result<Bm1491L9SensorBackendResult, Bm1491L9PicSensorReplayError> {
    if !write_succeeded && read_value.is_some() {
        return Err(Bm1491L9PicSensorReplayError::ReadSuppliedAfterWriteFailure);
    }
    let (temperature_c, valid, backend_return) = if write_succeeded {
        match read_value {
            Some(raw) => {
                let offset = if channel == Bm1491L9SensorChannel::Remote {
                    BM1491_L9_PIC_REMOTE_OFFSET_C
                } else {
                    0
                };
                (i32::from(raw as i8) + offset, true, 1)
            }
            None => (BM1491_L9_INVALID_TEMPERATURE_C, false, 0),
        }
    } else {
        (BM1491_L9_INVALID_TEMPERATURE_C, false, 0)
    };
    Ok(Bm1491L9SensorBackendResult {
        temperature_c,
        valid,
        backend_return,
        wrapper_status: bm1491_l9_sensor_wrapper_status(backend_return),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9OnChipSensorReplayError {
    ResponseSuppliedAfterSendFailure,
}

/// Replay the on-chip response-count/address acceptance logic.
///
/// Send failure becomes backend return zero. After an accepted send, only one
/// returned record whose address matches is applied. Zero records, multiple
/// records, and an address mismatch all leave `-64`/invalid but still produce
/// wrapper status zero. `external_mode` subtracts 64 from the response word's
/// most-significant byte.
pub fn bm1491_l9_replay_onchip_sensor_result(
    send_succeeded: bool,
    response_count: u8,
    response_word: u32,
    response_address: u8,
    expected_address: u8,
    external_mode: bool,
) -> Result<Bm1491L9SensorBackendResult, Bm1491L9OnChipSensorReplayError> {
    if !send_succeeded && response_count != 0 {
        return Err(Bm1491L9OnChipSensorReplayError::ResponseSuppliedAfterSendFailure);
    }
    let backend_return = if send_succeeded {
        i32::from(response_count)
    } else {
        0
    };
    let accepted = send_succeeded && response_count == 1 && response_address == expected_address;
    let temperature_c = if accepted {
        let raw = i32::from((response_word >> 24) as u8);
        if external_mode {
            raw - 64
        } else {
            raw
        }
    } else {
        BM1491_L9_INVALID_TEMPERATURE_C
    };
    Ok(Bm1491L9SensorBackendResult {
        temperature_c,
        valid: accepted,
        backend_return,
        wrapper_status: bm1491_l9_sensor_wrapper_status(backend_return),
    })
}

/// Replay the control-board backend. Local CT75 mode expects one byte; every
/// other local mode and all remote reads expect two. Failure is normalized to
/// backend `-1`, so this is the only recovered route whose ordinary read
/// failure becomes wrapper status four. Remote adds its runtime offset byte.
pub fn bm1491_l9_replay_control_board_sensor_result(
    channel: Bm1491L9SensorChannel,
    sensor_kind: u32,
    read_succeeded: bool,
    raw_first_byte: u8,
    remote_offset_c: u8,
) -> Bm1491L9SensorBackendResult {
    if !read_succeeded {
        return Bm1491L9SensorBackendResult {
            temperature_c: BM1491_L9_INVALID_TEMPERATURE_C,
            valid: false,
            backend_return: -1,
            wrapper_status: BM1491_L9_SENSOR_WRAPPER_FAILURE_STATUS,
        };
    }
    let backend_return =
        if channel == Bm1491L9SensorChannel::Local && sensor_kind == BM1491_L9_CT75_SENSOR_MODE {
            1
        } else {
            2
        };
    let offset = if channel == Bm1491L9SensorChannel::Remote {
        i32::from(remote_offset_c)
    } else {
        0
    };
    Bm1491L9SensorBackendResult {
        temperature_c: i32::from(raw_first_byte as i8) + offset,
        valid: true,
        backend_return,
        wrapper_status: BM1491_L9_SENSOR_WRAPPER_SUCCESS_STATUS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_maps_only_minus_one_to_failure() {
        assert_eq!(bm1491_l9_sensor_wrapper_status(-1), 4);
        for value in [-2, 0, 1, 2] {
            assert_eq!(bm1491_l9_sensor_wrapper_status(value), 0);
        }
    }

    #[test]
    fn onchip_plans_pin_descriptor_commands_and_delay() {
        let local = bm1491_l9_plan_sensor_transport(
            Bm1491L9SensorSourceMode::OnChip,
            Bm1491L9SensorChannel::Local,
            0x4c,
            3,
        );
        let descriptor = 0x0000_00ff_0000_4c00_u64;
        assert_eq!(
            local.actions,
            vec![
                Bm1491L9SensorTransportAction::OnChipSend {
                    descriptor,
                    command: 0x0198_0000,
                },
                Bm1491L9SensorTransportAction::DelayMilliseconds(50),
                Bm1491L9SensorTransportAction::OnChipReceive {
                    descriptor,
                    maximum_records: 1,
                },
            ]
        );
        let remote = bm1491_l9_plan_sensor_transport(
            Bm1491L9SensorSourceMode::OnChip,
            Bm1491L9SensorChannel::Remote,
            0x4c,
            3,
        );
        assert!(matches!(
            remote.actions[0],
            Bm1491L9SensorTransportAction::OnChipSend {
                command: 0x0198_0100,
                ..
            }
        ));
        assert!(!local.selected_for_held_release_proven);
        assert!(!local.admits_hardware_io());
    }

    #[test]
    fn pic_plan_and_hidden_failures_are_exact() {
        let plan = bm1491_l9_plan_sensor_transport(
            Bm1491L9SensorSourceMode::Pic,
            Bm1491L9SensorChannel::Local,
            0x4c,
            0,
        );
        assert_eq!(
            plan.actions,
            vec![
                Bm1491L9SensorTransportAction::PicWriteIic {
                    sensor_address: 0x4c,
                },
                Bm1491L9SensorTransportAction::DelayMilliseconds(10),
                Bm1491L9SensorTransportAction::PicReadIic {
                    sensor_address: 0x4c,
                },
            ]
        );
        let write_failure =
            bm1491_l9_replay_pic_sensor_result(Bm1491L9SensorChannel::Local, false, None)
                .expect("consistent failure");
        assert_eq!(write_failure.temperature_c, -64);
        assert!(!write_failure.valid);
        assert_eq!(write_failure.wrapper_status, 0);
    }

    #[test]
    fn pic_signed_decode_and_remote_offset_are_exact() {
        let local =
            bm1491_l9_replay_pic_sensor_result(Bm1491L9SensorChannel::Local, true, Some(0x80))
                .expect("local read");
        let remote =
            bm1491_l9_replay_pic_sensor_result(Bm1491L9SensorChannel::Remote, true, Some(0x80))
                .expect("remote read");
        assert_eq!(local.temperature_c, -128);
        assert_eq!(remote.temperature_c, -113);
        assert!(local.valid && remote.valid);
        assert_eq!(
            bm1491_l9_replay_pic_sensor_result(Bm1491L9SensorChannel::Local, false, Some(1),),
            Err(Bm1491L9PicSensorReplayError::ReadSuppliedAfterWriteFailure)
        );
    }

    #[test]
    fn onchip_zero_multiple_and_mismatched_records_hide_behind_wrapper_success() {
        for (count, address) in [(0, 0x4c), (1, 0x4d), (2, 0x4c)] {
            let result = bm1491_l9_replay_onchip_sensor_result(
                true,
                count,
                0x5000_0000,
                address,
                0x4c,
                false,
            )
            .expect("consistent response");
            assert_eq!(result.temperature_c, -64);
            assert!(!result.valid);
            assert_eq!(result.wrapper_status, 0);
        }
    }

    #[test]
    fn onchip_applies_top_byte_and_optional_minus_sixty_four() {
        let normal = bm1491_l9_replay_onchip_sensor_result(true, 1, 0x5000_0000, 0x4c, 0x4c, false)
            .expect("matching record");
        let external =
            bm1491_l9_replay_onchip_sensor_result(true, 1, 0x5000_0000, 0x4c, 0x4c, true)
                .expect("matching external record");
        assert_eq!(normal.temperature_c, 80);
        assert_eq!(external.temperature_c, 16);
        assert!(normal.valid && external.valid);
        assert!(!normal.admits_sensor_authority());
    }

    #[test]
    fn onchip_external_mode_plan_and_flag_transition_are_exact() {
        assert_eq!(
            bm1491_l9_plan_onchip_external_mode(),
            vec![
                Bm1491L9SensorTransportAction::OnChipSend {
                    descriptor: 0x0000_00ff_0000_0001,
                    command: 0x0199_0904,
                },
                Bm1491L9SensorTransportAction::DelayMilliseconds(100),
            ]
        );
        assert_eq!(bm1491_l9_replay_onchip_external_mode_flag(0, 0), 1);
        assert_eq!(bm1491_l9_replay_onchip_external_mode_flag(0, -1), 0);
        assert_eq!(bm1491_l9_replay_onchip_external_mode_flag(7, 3), 7);
        assert!(!BM1491_L9_SENSOR_TRANSPORT_AUTHORIZES_IO);
    }

    #[test]
    fn control_board_lengths_offsets_and_failure_status_are_exact() {
        let ct75 = bm1491_l9_plan_sensor_transport(
            Bm1491L9SensorSourceMode::ControlBoard,
            Bm1491L9SensorChannel::Local,
            0x4c,
            3,
        );
        assert_eq!(
            ct75.actions,
            vec![Bm1491L9SensorTransportAction::ControlBoardRead {
                sensor_address: 0x4c,
                ct75: true,
                expected_length: 1,
            }]
        );
        let local = bm1491_l9_replay_control_board_sensor_result(
            Bm1491L9SensorChannel::Local,
            3,
            true,
            0xfe,
            99,
        );
        let remote = bm1491_l9_replay_control_board_sensor_result(
            Bm1491L9SensorChannel::Remote,
            3,
            true,
            0xfe,
            15,
        );
        let failure = bm1491_l9_replay_control_board_sensor_result(
            Bm1491L9SensorChannel::Remote,
            3,
            false,
            0,
            15,
        );
        assert_eq!((local.temperature_c, local.backend_return), (-2, 1));
        assert_eq!((remote.temperature_c, remote.backend_return), (13, 2));
        assert_eq!(failure.wrapper_status, 4);
        assert!(!failure.valid);
    }

    #[test]
    fn held_descriptors_select_control_board_without_authorizing_transport() {
        assert!(!BM1491_L9_TOPOL_PIC_MCU_ENABLED);
        assert!(!BM1491_L9_TOPOL_READ_CTRLBOARD_TEMPERATURE);
        assert_eq!(BM1491_L9_TOPOL_SENSOR_TYPE, "onchip_sensor_unknown");
        assert!(BM1491_L9_SELECTED_SENSOR_SOURCE_PROVEN);
        assert_eq!(BM1491_L9_READ_TEMPERATURE_ADDRESS, 0x000b_0648);
        assert_eq!(BM1491_L9_RUNTIME_CTRL_ADDRESS, 0x000f_a450);
        assert_eq!(BM1491_L9_SENSOR_DESCRIPTORS_ADDRESS, 0x002c_b954);
        assert_eq!(BM1491_L9_SENSOR_INFO_ADDRESS, 0x002c_b984);
        assert_eq!(
            BM1491_L9_HELD_SENSOR_DESCRIPTORS,
            [
                Bm1491L9HeldSensorDescriptor {
                    index: 0,
                    sensor_kind: 1,
                    source: Bm1491L9SensorSourceMode::ControlBoard,
                    airflow_position: 0,
                    vertical_position: 0,
                    sensor_address: 0x4c,
                },
                Bm1491L9HeldSensorDescriptor {
                    index: 1,
                    sensor_kind: 1,
                    source: Bm1491L9SensorSourceMode::ControlBoard,
                    airflow_position: 1,
                    vertical_position: 0,
                    sensor_address: 0x48,
                },
            ]
        );
        for index in 0..BM1491_L9_HELD_SENSOR_DESCRIPTORS.len() {
            let plan = bm1491_l9_plan_held_sensor_transport(index, Bm1491L9SensorChannel::Local)
                .expect("held descriptor");
            assert_eq!(plan.source, Bm1491L9SensorSourceMode::ControlBoard);
            assert!(plan.selected_for_held_release_proven);
            assert_eq!(
                plan.actions,
                vec![Bm1491L9SensorTransportAction::ControlBoardRead {
                    sensor_address: BM1491_L9_HELD_SENSOR_DESCRIPTORS[index].sensor_address,
                    ct75: false,
                    expected_length: 2,
                }]
            );
            assert!(!plan.admits_hardware_io());
        }
        assert_eq!(
            bm1491_l9_plan_held_sensor_transport(2, Bm1491L9SensorChannel::Remote),
            Err(Bm1491L9HeldSensorPlanError::SensorIndexOutOfRange)
        );
        assert!(!BM1491_L9_SENSOR_TRANSPORT_OWNERSHIP_PROVEN);
        assert!(!BM1491_L9_SENSOR_TRANSPORT_AUTHORIZES_IO);
        assert!(!BM1491_L9_SENSOR_TRANSPORT_AUTHORIZES_MINING);
    }
}
