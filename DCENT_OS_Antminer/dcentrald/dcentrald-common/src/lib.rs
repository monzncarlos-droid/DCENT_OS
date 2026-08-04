//! Shared no-HAL contract utilities for dcentrald.
//!
//! This crate is intentionally HAL-free, OS-free, and async-runtime-free, in
//! the same spirit as `dcentrald-api-types`. It is the host-safe boundary
//! for utilities that must be reachable from both the API surface
//! (`dcentrald-api`) and the protocol clients (`dcentrald-stratum`) without
//! pulling in a hardware dependency. New no-HAL helpers (config-validation,
//! ID redaction, units conversion) belong here.
//!
//! Modules:
//! - [`wallet_mask`] — Bitcoin/Litecoin wallet-address masking for log and
//!   UI emission. Provides `mask_wallet()`, `mask_in_string()`, and
//!   `is_likely_wallet()`. See module docs for the threat model and which
//!   addresses are recognized (bech32, bech32m, base58 P2PKH/P2SH, hex).
//! - [`chain_voltage`] — AT-1 measured-vs-commanded per-chain rail-voltage
//!   resolver. Reuses [`dspic_decode`]'s 0x3A `MEASURE_VOLTAGE` decode to feed
//!   the autotuner/telemetry a provenance-tagged rail voltage (read-back only).
//! - [`at3_rail`] — AT-3 process-global publish/consume slot. The am2 hybrid
//!   loop's gated, default-OFF quiet-window 0x3A read publishes a fresh measured
//!   rail here; the API per-chain telemetry projection reads it back so a
//!   plausible reading is tagged `measured`. Read-only/measure-only.
//! - [`atomic_file`] — bounded same-filesystem state replacement and durable
//!   deletion with directory fsync plus explicit publication/failure evidence.

pub mod am2_topology;
/// Canonical build target and published filename for each artifact claim.
pub mod artifact_producer;
/// Transport-neutral ASIC protocol pure admission + init program seed (ADR-0010 / P1-3).
pub mod asic_protocol;
pub mod at3_rail;
pub mod atomic_file;
/// Declarative control-board composition identity (ADR-0011). Scaffold registry.
pub mod board_desc;
/// Pure chain-transport op language + host recorder (ADR-0010 / P1-3 I/O seed).
pub mod chain_transport;
pub mod chain_voltage;
/// C52 cooling custody policy for home AM2 profiles (P1-7).
pub mod cooling_custody;
pub mod dspic_decode;
pub mod dspic_heartbeat;
/// Pure PLL frequency model + TransportOp expansion (decade P1-4 seed).
pub mod pll_model;
/// Pure stock FPGA AsicBoost / version-slot packing (G17).
pub mod stock_fpga_policy;
/// Pure ASIC ticket-mask encode (G24).
pub mod ticket_mask;
// Re-export map builder used by standard-mining heartbeat temp publication.
pub use dspic_heartbeat::{build_pic_temp_chain_map, heartbeat_extra_addrs};
/// Honest diagnostic snapshot vs active-stim labels (P2-5).
pub mod diagnostic_mode;
/// Pure hashrate-from-geometry math (P2-9).
pub mod hashrate_geometry;
/// Install/packaging matrix from BoardDesc (toolbox/CI/docs generators).
pub mod install_matrix;
/// Universal measurement provenance (P2-3).
pub mod measurement;
/// Composed multi-chain energize + dispatch admission (strangler glue).
pub mod mining_lifecycle;
/// Multi-chain power-up stagger policy (P1-5 companion).
pub mod powerup_schedule;
/// PowerCut + FanCommand policy (cut-hash-before-noise; home PWM cap).
pub mod safety_command;
/// Pure serial work-engine bookkeeping (history ring, dedup, job-id cursor).
pub mod serial_work_engine;
/// Shared serial work-history / job-id / dedup policy (mining strangler).
pub mod serial_work_policy;
/// Crash-durable source-aware thermal generation lockout.
pub mod thermal_lockout;
pub mod time;
pub mod units;
/// VoltageRail facet trait + errors (ADR-0010). Adapters live in asic/hal.
pub mod voltage_rail;
pub mod wallet_mask;
/// Work-dispatch safety admission (watchdog + heartbeat + thermal NO-SHIP).
pub mod work_dispatch_safety;

pub use asic_protocol::{
    admit_protocol_over_transport, admit_work_engine_over_transport, plan_pure_init_program,
    protocol_capabilities, InitProgram, InitStep, ProtocolCapabilities, ProtocolTransportAdmission,
    ProtocolTransportError,
};
pub use board_desc::{
    AsicProtocolAdmission, AsicProtocolIdentity, BoardDesc, BoardFamily, ChainTransportKind,
    SlotPolicy, VoltageControllerClass, WorkEngineKind,
};
pub use chain_transport::{
    admit_transport_op, am2_misc_ctrl_pre_baud_from_bosminer_cold_opt_in,
    am2_misc_ctrl_pre_baud_policy_from_bosminer_cold_opt_in, am2_misc_ctrl_pre_baud_value,
    bm1397plus_addr_interval, bm1397plus_full_population_chip_addresses,
    hot_start_dual_spray_bm1397plus_transport_ops, init_program_to_transport_ops,
    init_step_to_transport_ops, linear_chip_addresses, plan_admitted_transport_ops,
    plan_bm1387_misc_ctrl_i2c_off_chip0, plan_bm1387_misc_ctrl_triple_write_chip,
    plan_bm1397_fast_uart_pll3_then_config, plan_bm1397_fast_uart_pll3_then_config_chip,
    plan_bm1397plus_chain_inactive_burst, plan_bm1397plus_full_population_address_ladder,
    plan_bm1397plus_set_address_ladder, plan_hot_start_baud_wake_ladder,
    plan_hot_start_baud_wake_ladder_from_fast_baud, plan_hot_start_baud_wake_ops,
    plan_hot_start_dual_spray_ops, plan_hot_start_hybrid_wake_ops,
    plan_misc_ctrl_single_write_broadcast, plan_misc_ctrl_single_write_broadcast_reg,
    plan_misc_ctrl_single_write_chip, plan_misc_ctrl_single_write_chip_reg,
    plan_misc_ctrl_triple_write_broadcast, plan_misc_ctrl_triple_write_broadcast_reg,
    plan_misc_ctrl_triple_write_chip, plan_misc_ctrl_triple_write_chip_reg,
    plan_version_rolling_broadcast_writes, plan_version_rolling_quad_write_broadcast,
    plan_version_rolling_single_write_broadcast, plan_version_rolling_triple_write_broadcast,
    protocol_speaks_bm1397plus_commands, transport_backend_class, version_rolling_reg_value,
    Am2MiscCtrlPreBaudPolicy, Bm1387MiscCtrlCadenceOp, Bm1387RegWriteIntent, ChainTransport,
    HotStartBaudStage, HotStartCommandFamily, HotStartHostClass, HotStartSprayOp,
    RecordingChainTransport, TransportBackendClass, TransportOp, TransportOpError,
    AM2_MISC_CTRL_PRE_BAUD_BOSMINER_COLD, AM2_MISC_CTRL_PRE_BAUD_DEFAULT_109,
    BM1387_MISC_CTRL_I2C_OFF_MINING, BM1397_FAST_UART_CONFIG_REG, BM1397_FAST_UART_CONFIG_VALUE,
    BM1397_FAST_UART_PLL3_VALUE, BM1397_PLL3_PARAMETER_REG, HOT_START_AMLOGIC_FAST_BAUD,
    HOT_START_MISC_CTRL_BAUD_RESET, HOT_START_POST_LADDER_SETTLE_MS, HOT_START_SPRAY_DWELL_MS,
    HOT_START_TARGET_BAUD, HOT_START_ZYNQ_FAST_BAUD, HOT_START_ZYNQ_MID_BAUD, MISC_CTRL_REG_BM1387,
    MISC_CTRL_REG_BM1397PLUS, MISC_CTRL_SINGLE_WRITE_COUNT, MISC_CTRL_TRIPLE_WRITE_COUNT,
    MISC_CTRL_TRIPLE_WRITE_SPACING_MS, VERSION_ROLLING_MASK_SHIFT, VERSION_ROLLING_QUAD_COUNT,
    VERSION_ROLLING_REG_BIP320_DEFAULT, VERSION_ROLLING_REG_BM1397PLUS, VERSION_ROLLING_REG_PREFIX,
    VERSION_ROLLING_SINGLE_COUNT, VERSION_ROLLING_STRATUM_BIP320_MASK,
    VERSION_ROLLING_TRIPLE_COUNT,
};
pub use cooling_custody::{
    admit_c52_custody, admit_home_am2_s19_c52, c52_custody_decision, is_c52_mode_low_byte,
    C52AdmissionError, C52CustodyDecision, CoolingBoardClass, CoolingProfileKind,
    C49_MODE_LOW_BYTE, C52_MODE_LOW_BYTE,
};
pub use dcent_schema::hardware::{
    ArtifactKind, ArtifactMaturity, GenericConstruction, HardwareEnablementPolicy,
    ImplementationMaturity, InstallAuthorization, LifecycleLane, RecoveryMaturity, RuntimeStatus,
    StorageTopology, UpdateMechanism, HARDWARE_ENABLEMENT_SCHEMA_VERSION,
};
pub use diagnostic_mode::{
    admit_report_kind, parse_report_kind, DiagnosticModeError, DiagnosticRunMode,
};
pub use hashrate_geometry::{
    chip_hashrate_ghs, nominal_hashrate_ghs_from_geometry, total_chips_from_per_chain,
    total_chips_from_profile_geometry,
};
pub use install_matrix::{
    ab_sysupgrade_board_targets, install_matrix, install_matrix_json, install_matrix_tsv,
    public_beta_board_targets, InstallMatrixRow,
};
pub use measurement::{prefer_measured, Measurement, MeasurementProvenance};
pub use mining_lifecycle::{
    plan_multi_chain_enable, plan_production_multi_chain_enable,
    plan_production_multi_chain_energize, plan_production_multi_chain_energize_for_targets,
    MiningLifecycleError, MultiChainEnableAuthority, MultiChainEnablePlan,
    ProductionMultiChainEnergizePlan,
};
pub use pll_model::{
    admit_pll_register, bm1362_pll_frequencies, bm1362_pll_reg_and_actual,
    bm1366_pll_reg_and_actual, bm1368_pll_reg_and_actual, bm1368_pll_table_lookup,
    bm1368_vco_in_jig_range, bm1370_pll_reg_and_actual, bm1370_vco_in_jig_range,
    bm1387_pll_frequencies, bm1391_pll_fallback_200m, bm1391_pll_pack, bm1391_pll_search,
    bm1396_production_pure_pll_admitted, bm1396_production_pure_pll_status,
    bm1397_pll0_lock_bit_set, bm1397_pll0_readback_matches, bm1397_pll0_verify_rewrite_admitted,
    bm1397_pll_decode_dividers, bm1397_pll_frequencies, bm1397_pll_register_value,
    bm1398_pll_frequencies, bm1398_pll_register_value, crystal25_pll_decode_dividers,
    crystal25_pll_encode_reg, plan_all_pll_broadcast_writes, plan_bm1368_pll_ramp,
    plan_bm1391_frequency_program_ops, plan_bm1391_frequency_program_ops_chip,
    plan_bm1396_frequency_program_ops_experimental, plan_bm1397_frequency_program_ops,
    plan_bm1397_frequency_program_ops_chip, plan_bm1397_pll0_verify_read,
    plan_bm1397_pll0_verify_retry_rewrite, plan_frequency_program_ops, plan_pll0_broadcast_write,
    plan_pll_broadcast_write, pll_count, pll_family_for_protocol, pll_register_addrs,
    resolve_bm1362_pll, resolve_bm1366_pll, resolve_bm1368_pll, resolve_bm1368_pll_fallback_mhz,
    resolve_bm1368_pll_mhz, resolve_bm1368_pll_with_policy, resolve_bm1370_pll,
    resolve_bm1370_pll_mhz, resolve_bm1370_pll_with_policy, resolve_bm1387_pll, resolve_bm1391_pll,
    resolve_bm1396_pll_experimental_family_hypothesis, resolve_bm1397_pll, resolve_bm1398_pll,
    resolve_bm1398_pll_nearest_admitted, resolve_pll, resolve_pll_for_protocol, Bm1368VcoPolicy,
    Bm1370VcoPolicy, Bm1391PllSolution, Bm1396PurePllStatus, Bm1397PllDividers, Bm1398PllDividers,
    Crystal25PllDividers, PllFamily, PllPlanError, PllSolution, BM1362_PLL_FREQUENCIES,
    BM1362_PLL_TABLE, BM1368_CLKI_MHZ, BM1368_FB_DIV_MAX, BM1368_FB_DIV_MIN,
    BM1368_PLL_RAMP_MAX_X100, BM1368_PLL_TABLE, BM1368_PLL_TABLE_MAX_X100, BM1370_CLKI_MHZ,
    BM1370_FB_DIV_MAX, BM1370_FB_DIV_MIN, BM1370_JIG_VCO_MAX_MHZ, BM1370_JIG_VCO_MAX_REFDIV1_MHZ,
    BM1370_JIG_VCO_MIN_MHZ, BM1370_PLL_COUNT, BM1370_PLL_REGISTER_ADDRS, BM1387_PLL_PARAMETER_REG,
    BM1387_PLL_TABLE, BM1391_PLL0_DIVIDER_REG, BM1391_PLL0_REG, BM1391_PLL_FALLBACK_200M,
    BM1391_PLL_FALLBACK_EXTERNAL_DIV, BM1391_PLL_PROGRAM_SPACING_MS, BM1397_CLKI_MHZ,
    BM1397_FB_DIV_MAX, BM1397_FB_DIV_MIN, BM1397_FREQ_MAX_MHZ, BM1397_FREQ_MIN_MHZ,
    BM1397_PLL0_DIVIDER_PRECONFIG, BM1397_PLL0_DIVIDER_REG, BM1397_PLL0_LOCK_BIT,
    BM1397_PLL0_VERIFY_MAX_ATTEMPTS, BM1397_PLL0_VERIFY_READ_SETTLE_MS,
    BM1397_PLL0_VERIFY_REWRITE_SETTLE_MS, BM1397_PLL_PROGRAM_SPACING_MS, BM1398_CLKI_MHZ,
    BM1398_FB_DIV_MAX, BM1398_FB_DIV_MIN, BM1398_MAX_ERROR_MILLIMHZ_EXCLUSIVE,
    BM1398_REFDIV_ONE_VCO_MAX_MHZ, BM1398_VCO_MAX_MHZ, BM1398_VCO_MIN_MHZ, PLL0_PARAMETER_REG,
};
pub use powerup_schedule::{
    inter_step_delays_ms, plan_powerup, plan_production_enable_sequence, plan_production_powerup,
    require_nonempty, schedule_duration_ms, validate_production_stagger, validate_schedule_gaps,
    PowerUpPolicyError, PowerUpStep, StaggerConfig, DEFAULT_CHAIN_STAGGER_MS,
    MIN_PRODUCTION_STAGGER_MS,
};
pub use safety_command::{
    apply_safety_action, power_precedes_fan_raise, violates_home_fan_cap, FanCommand, PowerCut,
    PowerCutReason, SafetyAction, SafetyApplyReport, SafetyStep, FAN_PWM_ABSOLUTE_MAX,
    HOME_FAN_PWM_SAFETY_MAX,
};
pub use serial_work_engine::{
    admit_serial_bring_up_plugin, execute_serial_bring_up_plan, plan_serial_bring_up,
    plan_serial_bring_up_for_board, refine_bm1362_bring_up_for_board_family,
    serial_work_min_interval_ms, AsicJobIdCursor, GenerationSeenShareSet, SeenShareSet,
    SerialBringUpAdmitError, SerialBringUpPhases, SerialBringUpPlan, SerialBringUpPlanError,
    SerialBringUpPlanParams, SerialBringUpPlugin, SerialBringUpPluginKind, SerialDispatchTicket,
    SerialMiningEngineBookkeeping, SerialWorkBookkeeping, WorkHistoryEntry, WorkHistoryRing,
    SERIAL_WORK_MAX_FRAMES_PER_SEC,
}; // WorkHistoryRing is generic over entry type (P1-1)
pub use serial_work_policy::{
    generation_dedup_cutoff, generation_share_dedup_key, next_asic_job_id, serial_share_dedup_key,
    should_clear_seen_shares, should_prune_generation_seen, work_history_depth_for_chip_id,
    AM3_BB_WORK_HISTORY_PER_ID, BM1362_SERIAL_NONCE_LEN, BM1398_WORK_HISTORY_PER_ID,
    DEFAULT_SEEN_SHARES_CAP, DEFAULT_SERIAL_JOB_ID_STEP, DEFAULT_WORK_HISTORY_PER_ID,
    GENERATION_SEEN_RETAIN_WINDOW, GENERATION_SEEN_SOFT_CAP_DISPATCHER,
    GENERATION_SEEN_SOFT_CAP_SERIAL,
};
pub use stock_fpga_policy::{
    plan_stock_bc_chain_inactive_vil, plan_stock_bc_set_address_vil, plan_stock_bc_set_config,
    plan_stock_bm1387_set_freq, plan_stock_cold_boot_library_inventory,
    plan_stock_init_ticket_mask_and_hcnt_vil, plan_stock_open_core_one_chain_vil,
    plan_stock_set_asic_ticket_mask_chains_vil, plan_stock_set_asic_ticket_mask_vil,
    plan_stock_set_baud_chains_vil, plan_stock_set_baud_one_chain_vil, plan_stock_set_baud_vil,
    plan_stock_set_hcnt_chains_vil, plan_stock_set_hcnt_vil, plan_stock_software_set_address,
    stock_asicboost_admitted, stock_asicboost_slot_from_solution_idx,
    stock_asicboost_version_for_solution, stock_asicboost_version_reg,
    stock_asicboost_version_words, stock_bc_busy_wait_step, stock_bc_post_trigger_wait_budget,
    stock_bc_pre_ready_step, stock_bc_ready, stock_bc_set_config_buffer_writes,
    stock_bc_set_config_trigger_write, stock_bc_set_config_write_sequence,
    stock_bc_vil_cmd_buffer_writes, stock_bc_vil_cmd_trigger_write, stock_bc_write_command,
    stock_bc_write_merge_host_baud, stock_bc_write_requires_busy_wait, stock_bitmain_crc5,
    stock_buffer_space_ready, stock_buffer_space_wait_step, stock_calculate_core_number,
    stock_cold_boot_composition_is_phase4b_admitted, stock_cold_boot_inventory_counts,
    stock_dev_timeout_auto, stock_dhash_multi_midstate_enabled, stock_dhash_with_multi_midstate,
    stock_fan_control_full, stock_fan_control_value, stock_init_uart_bauddiv,
    stock_open_core_bc_nullwork_enable, stock_open_core_bc_nullwork_prelude,
    stock_open_core_buffer_timeout_continues_to_dhash_exit,
    stock_open_core_buffer_timeout_skips_nullwork_enable,
    stock_open_core_buffer_timeout_skips_remaining_tw, stock_open_core_dhash_entry,
    stock_open_core_dhash_exit, stock_open_core_dummy_tw_words, stock_open_core_gateblk_misc_value,
    stock_open_core_sim_write_trace, stock_sensor_calc_offset, stock_sensor_get_local,
    stock_sensor_get_remote_c, stock_set_baud_misc_value, stock_set_pwm_percent_clamped,
    stock_time_out_control_reg, StockBcBusyWaitStep, StockBcPreReadyStep, StockBcSetConfigPlan,
    StockBcVilCmdPlan, StockBufferSpaceWaitStep, StockColdBootCompositionParams,
    StockColdBootLibraryStep, StockOpenCoreOp, StockOpenCoreSimReport, StockOpenCoreSimState,
    StockSetBaudOp, StockSoftwareSetAddressOp, StockTimeOutControlScale,
    STOCK_ASICBOOST_BIP320_MASK, STOCK_ASICBOOST_SLOT_BIT_SHIFT, STOCK_ASICBOOST_SLOT_COUNT,
    STOCK_ASICBOOST_VERSION_REG_BASE, STOCK_ASICBOOST_VERSION_REG_STRIDE,
    STOCK_ASIC_TICKET_MASK_REG, STOCK_BC_BUSY_BIT, STOCK_BC_CHAIN_FIELD_CLEAR,
    STOCK_BC_POST_TRIGGER_POLL_MS, STOCK_BC_POST_TRIGGER_WAIT_MAX_ATTEMPTS,
    STOCK_BC_PRE_READY_WAIT_MAX_ATTEMPTS, STOCK_BC_SET_CONFIG_SETTLE_US, STOCK_BC_WRITE_TRIGGER_OR,
    STOCK_BM1387_MISC_CTRL_REG, STOCK_BM1387_SET_CONFIG_PLL_REG, STOCK_COLD_BOOT_INTER_STAGE_MS,
    STOCK_COLD_BOOT_OPEN_CORE_SETTLE_MS, STOCK_DHASH_MULTI_MIDSTATE_BIT, STOCK_HCNT_REG,
    STOCK_INIT_ASIC_TICKET_MASK, STOCK_INIT_UART_BAUDDIV_MAX, STOCK_INIT_UART_BAUD_NUMER_A,
    STOCK_INIT_UART_BAUD_NUMER_B, STOCK_INIT_UART_BAUD_SCALE,
    STOCK_OPEN_CORE_BC_NULLWORK_ENABLE_BIT, STOCK_OPEN_CORE_BC_NULLWORK_PRELUDE_BIT,
    STOCK_OPEN_CORE_BC_PRELUDE_AND, STOCK_OPEN_CORE_BC_PRELUDE_SETTLE_US,
    STOCK_OPEN_CORE_BUFFER_POLL_US, STOCK_OPEN_CORE_BUFFER_WAIT_MAX_ATTEMPTS,
    STOCK_OPEN_CORE_DEFAULT_BAUD_DIV_LOW5, STOCK_OPEN_CORE_DEFAULT_MULTI_VERSION,
    STOCK_OPEN_CORE_DHASH_CLEAR_MASK, STOCK_OPEN_CORE_DHASH_VIL_BIT,
    STOCK_OPEN_CORE_DUMMY_WORK_COUNT, STOCK_OPEN_CORE_FIRST_WORK_TYPE,
    STOCK_OPEN_CORE_GATEBLK_SETTLE_US, STOCK_OPEN_CORE_GATEBLK_VALUE_BASE,
    STOCK_OPEN_CORE_REST_WORK_TYPE, STOCK_REG_BC_COMMAND_BUFFER, STOCK_REG_BC_COMMAND_BUFFER_W1,
    STOCK_REG_BC_COMMAND_BUFFER_W2, STOCK_REG_BC_WRITE_COMMAND, STOCK_REG_BUFFER_SPACE,
    STOCK_REG_DHASH_ACC_CONTROL, STOCK_REG_FAN_CONTROL, STOCK_REG_HASH_COUNTING_NUMBER,
    STOCK_REG_TIME_OUT_CONTROL, STOCK_REG_TW_WRITE_COMMAND, STOCK_SENSOR_KELVIN_C,
    STOCK_SENSOR_OFFSET_COEF, STOCK_SENSOR_RAW_BIAS, STOCK_SENSOR_REMOTE_BIAS,
    STOCK_SENSOR_REMOTE_DIV, STOCK_SENSOR_REMOTE_SCALE, STOCK_SET_BAUD_MISC_FIXED,
    STOCK_SET_BAUD_POST_ALL_CHAINS_SETTLE_US, STOCK_SET_CONFIG_HDR_BCAST,
    STOCK_SET_CONFIG_HDR_UNICAST, STOCK_SET_CONFIG_LEN, STOCK_SOFTWARE_SET_ADDRESS_DWELL_MS,
    STOCK_SOFTWARE_SET_ADDRESS_INACTIVE_REPEATS, STOCK_SOFTWARE_SET_ADDRESS_INTERVAL,
    STOCK_TIMEOUT_CORE_TICKS, STOCK_TIMEOUT_MAX, STOCK_TIMEOUT_SCALE_DEN, STOCK_TIMEOUT_SCALE_NUM,
    STOCK_TIME_OUT_CONTROL_ENABLE, STOCK_TIME_OUT_CONTROL_MASK, STOCK_VIL_CHAIN_INACTIVE_HDR,
    STOCK_VIL_SET_ADDRESS_HDR, STOCK_VIL_SHORT_CMD_LEN,
};
pub use ticket_mask::{
    bit_reverse_u32_bytewise, largest_power_of_two_le, resolve_ticket_mask,
    ticket_mask_encoding_for_chip_id, ticket_mask_esp_miner_pow2_floor,
    ticket_mask_from_difficulty, TicketMaskEncoding, TICKET_MASK_REG_BM1387,
    TICKET_MASK_REG_BM1397PLUS,
};
pub use voltage_rail::{
    admit_dspic_firmware_for_energize, admit_pic1704_short_form_set_mv,
    admit_voltage_rail_mutation, admit_voltage_rail_op, chip_driver_set_voltage_admission,
    energize_voltage_rail, host_adapter_rail, is_hard_refuse, is_tas5782m_i2c_addr,
    pic16_dac_to_mv, pic16_mv_to_dac, pic1704_short_form_has_writable_voltage_setpoint,
    refuse_degraded_firmware, refuse_wrong_mode, resolve_voltage_rail_adapter,
    safe_off_voltage_rail, stock_pic16_init_dac, stock_pic16_operating_dac,
    unsupported_voltage_path, voltage_ownership_for_asic, voltage_rail_adapter_for_controller,
    voltage_rail_io_error, walk_down_and_safe_off_voltage_rail, BackendVoltageRail,
    RecordingVoltageRail, Tas5782mVoltageRail, UnsupportedExternalDacRail, VoltageOwnership,
    VoltageRail, VoltageRailAdapterKind, VoltageRailError, VoltageRailOp, VoltageRefuseReason,
    DSPIC_DEGRADED_FW, DSPIC_PROVEN_APP_FW, PIC16_MIN_SAFE_DAC, PIC16_VOLTAGE_DIVISOR,
    PIC16_VOLTAGE_OFFSET, PIC1704_REG_CONTROL, PIC1704_REG_VOLTAGE_H, PIC1704_REG_VOLTAGE_L,
    STOCK_PIC16_INIT_MV, STOCK_PIC16_OPERATING_MV, TAS5782M_I2C_ADDRS,
};
pub use work_dispatch_safety::{
    admit_work_dispatch, build_work_dispatch_inputs, map_watchdog_safety_state,
    measured_startup_thermal_state, revocation_stops_watchdog_feed, revoke_work_dispatch,
    should_revoke_work_dispatch_for_controller_health, ControllerHeartbeatObservation,
    DispatchRevocationCause, HeartbeatRequirement, ThermalSafetyState, WatchdogSafetyState,
    WorkDispatchAdmissionPublication, WorkDispatchAdmissionReceipt, WorkDispatchLifecycle,
    WorkDispatchSafetyError, WorkDispatchSafetyInputs,
};

use std::sync::atomic::{AtomicBool, Ordering};

/// Process-wide gate for the log-tail passthrough sanitizer.
///
/// W1.4: when `true` (the default), the `/api/debug/log` endpoint masks
/// any wallet-shaped substrings before serializing the response. Setting
/// this to `false` is an opt-out for operators with structured-log
/// collectors that need raw addresses.
///
/// Per-call masking on `worker=` / `username=` / `wallet=` log fields is
/// independent of this flag and cannot be disabled via the config. To see
/// raw addresses on the wire, use `RUST_LOG=trace` (TRACE-level only,
/// gated by EnvFilter, off by default in production).
static MASK_LOGS_ENABLED: AtomicBool = AtomicBool::new(true);

/// Set the process-wide log-tail mask flag. Called once at daemon startup
/// from the [logging] section of dcentrald.toml.
pub fn set_mask_logs(enabled: bool) {
    MASK_LOGS_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Read the process-wide log-tail mask flag.
pub fn mask_logs_enabled() -> bool {
    MASK_LOGS_ENABLED.load(Ordering::Relaxed)
}
