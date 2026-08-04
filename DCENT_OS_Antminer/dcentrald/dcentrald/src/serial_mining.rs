//! S19j Pro serial mining â€” full ASIC init + pure UART work dispatch.
//!
//! Bosminer on S19j Pro sends ALL work via /dev/ttyS2 serial UART, NOT FPGA FIFOs.
//! Confirmed via strace: only /dev/ttyS2, /dev/i2c-0, and fan/board UIO are used.
//!
//! Work packet (88 bytes on wire):
//!   [55 AA] preamble
//!   [21]    header (TYPE_JOB | GROUP_SINGLE | CMD_WRITE)
//!   [36]    length byte (0x36 = 54, bosminer's encoding)
//!   [82 bytes] job payload (BM1366-format: job_id, num_midstates, nonce, nbits, ntime,
//!              merkle_root, prev_block_hash, version)
//!   [2 bytes] CRC-16
//!
//! I2C addresses (AM2 S19j Pro, selected from serial slot):
//!   0x20/0x21/0x22 = dsPIC voltage controllers (fw byte detected at runtime)
//!   0x51 = EEPROM (hashboard serial/calibration data)
//!
//! PIC protocol (serialized I2C service writes to 0x21):
//!   Flush: 16x write 0x00 (clear parser state)
//!   GET_VERSION: short [55 AA 17] or framed [55 AA 04 17 00 1B]
//!   ENABLE:      [55 AA 04 15 01 1A] -> voltage on
//!   HEARTBEAT:   [55 AA 04 16 00 1A] -> keep alive
//!   RESET/JUMP bootloader-control opcodes are banned on Pic0x89 paths.
//!
//! Full ASIC init sequence (14 steps):
//!   Opens serial at 115200, enumerates 126 chips, configures registers,
//!   upgrades baud to 3.125M, ramps PLL to target frequency.

use std::collections::VecDeque;
use std::num::NonZeroU8;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use dcentrald_asic::bm1362::unassigned_address::{
    validate_unassigned_address_window, ValidatedBm1362UnassignedAddressWindow,
    UNASSIGNED_ADDRESS_BODY_BYTES as BM1362_UNASSIGNED_RESP_BODY_LEN,
};
use dcentrald_asic::drivers::{
    bm1368::{
        pll_ramp_sequence as bm1368_pll_ramp_sequence,
        FIXTURE_ADDRESS_INTERVAL as BM1368_ADDRESS_INTERVAL,
        FIXTURE_TICKET_MASK as BM1368_FIXTURE_TICKET_MASK,
        UART_RELAY_12_DOMAIN as BM1368_UART_RELAY_12_DOMAIN,
        UART_RELAY_REG as BM1368_UART_RELAY_REG,
    },
    ChipDriverAdmission, ChipRegistry, MinerProfile,
};
use dcentrald_asic::dspic::dspic_fw86_trust_degraded_override_enabled;
use dcentrald_asic::dspic::{
    dspic_runtime_protocol_is_proven, DspicFirmware, Pic0x89EndpointSession, Pic0x89Service,
};
use dcentrald_asic::serial_chip_address::{
    validate_serial_chip_address_window, SerialAddressWindowShape, ValidatedSerialChipAddressWindow,
};
use dcentrald_asic::uart_trans::{UartTransService, UartWork, DEFAULT_CHAIN_TTYS};
use dcentrald_asic::voltage_rail_adapters::Pic0x89VoltageRail;
use dcentrald_common::{
    apply_safety_action, bm1397plus_addr_interval, plan_bm1397plus_chain_inactive_burst,
    plan_bm1397plus_set_address_ladder, plan_hot_start_baud_wake_ladder_from_fast_baud,
    plan_hot_start_dual_spray_ops, plan_misc_ctrl_triple_write_broadcast,
    plan_misc_ctrl_triple_write_chip, plan_serial_bring_up, safe_off_voltage_rail,
    ChainTransportKind, ControllerHeartbeatObservation, DispatchRevocationCause,
    HeartbeatRequirement, HotStartCommandFamily, HotStartSprayOp, PowerCut, SafetyAction,
    SerialBringUpPlanParams, SerialBringUpPluginKind, SerialMiningEngineBookkeeping,
    ThermalSafetyState, TransportOp, WatchdogSafetyState, WorkDispatchAdmissionReceipt,
    WorkDispatchLifecycle, WorkDispatchSafetyError, WorkDispatchSafetyInputs, WorkHistoryRing,
    HOT_START_POST_LADDER_SETTLE_MS,
};
use dcentrald_hal::i2c::{
    spawn_i2c_service_no_register_touch_with_denylist, I2cMutationLabel, I2cServiceHandle,
    I2cTransactionStep, TerminalSafeOffTransition,
};
use dcentrald_hal::platform::{FanAccess, FanCommandReceipt, Platform};
use dcentrald_hal::psu::Apw121215a;
use dcentrald_hal::psu_gpio_gate::PsuGpioGate;
use dcentrald_hal::serial_chain::SerialChainBackend;
use dcentrald_hal::transport_op_execute::execute_transport_op_bm1397plus;
use dcentrald_thermal::controller::{
    FanTachSafety, FanTachSafetyState, DEFAULT_FAN_BELOW_MINIMUM_FAILURE_TICKS,
};

use crate::bounded_nonblocking_probe::{
    observe_nonblocking_until, BoundedProbeOutcome, NonblockingProbe,
};
use crate::config::DcentraldConfig;
use crate::execution_fence::{
    execution_fence_domain, ExecutionFenceIdentity, ExecutionFencePort, ExecutionFenceReceipt,
    ExecutionFenceTerminal, ExecutionFenceTryWait, RevokedExecutionFence,
};
use crate::hardware_mutation_fence::wait_revoked_hardware_mutation_commit_fence;
use crate::history::{self, HistoryBuffer};
use crate::model;
use crate::runtime::safety_watchdog::{
    watchdog_reset_pending_error, Am2NeverEnergized, Am2SerialThreadSlot,
    Am2SerialWatchdogShutdownManifest, NoPicSerialThreadSlot, NoPicWatchdogShutdownManifest,
    SafetyLiveness, SafetyWatchdogOwner, WatchdogCloseoutReceipt, WatchdogDisarmPermit,
    DEFAULT_WATCHDOG_STOP_TIMEOUT,
};
use crate::runtime::teardown_budget::{
    TeardownBudget, TeardownBudgetView, TeardownDisarmAuthority, TeardownStage,
};
use crate::runtime::thread_guard::{
    sleep_until_cancelled, FixedThreadRosterGuard, FixedThreadSlot, RuntimeThreadGuard,
    ThreadRosterExpectation, ThreadRosterOwner, ThreadRosterPreRuntimeCloseout,
    ThreadRosterQuiescenceReceipt, ThreadRosterRuntimeAdmission, ThreadRosterStop,
    ThreadSlotReservation, ThreadStopSummary,
};

// P1.2 fix (Audit C F-004): Bible/memory rule cap is ~50 work-frames/sec on
// serial work dispatch. The previous
// BM1362 values (1 ms Ã— 128 burst = 128,000 frames/sec) violated by 2,560Ã—
// and were the most likely root cause of the live `a lab unit` zero-nonce regime â€”
// FPGA WORK_TX FIFO saturated instantly with stale work the chips couldn't
// consume. New BM1362 values: 20 ms interval Ã— 1 burst = 50 frames/sec, at
// the documented cap.
const BM1368_DISPATCH_INTERVAL_MS: u64 = 25;
const BM1362_DISPATCH_INTERVAL_MS: u64 = 20;
const DEFAULT_DISPATCH_INTERVAL_MS: u64 = 50;

// ---------------------------------------------------------------------------
// Work-dispatch safety (shared pure policy â†’ serial adapter)
// ---------------------------------------------------------------------------

/// Map serial-engine bring-up observations into the shared matrix.
///
/// Pure and host-testable â€” serial must not invent a second admission matrix.
pub(crate) fn serial_work_dispatch_inputs(
    soc_watchdog: WatchdogSafetyState,
    heartbeat_requirement: HeartbeatRequirement,
    controller_heartbeats: &[ControllerHeartbeatObservation],
    thermal: ThermalSafetyState,
) -> WorkDispatchSafetyInputs {
    WorkDispatchSafetyInputs {
        watchdog: soc_watchdog,
        heartbeat_requirement,
        controllers: controller_heartbeats.to_vec(),
        thermal,
        previously_revoked: false,
    }
}

/// Serial SoC watchdog contribution.
///
/// - Path does not own a SafetyWatchdogOwner (legacy) â†’ DisabledByConfiguration
/// - Exact path after successful `enter_exact_serial_mining` â†’ Armed
/// - Exact path expected ownership but enter failed â†’ Unavailable
pub(crate) fn serial_watchdog_safety_state(
    owns_soc_watchdog: bool,
    mining_enter_ok: bool,
) -> WatchdogSafetyState {
    match (owns_soc_watchdog, mining_enter_ok) {
        (false, _) => WatchdogSafetyState::DisabledByConfiguration,
        (true, true) => WatchdogSafetyState::Armed,
        (true, false) => WatchdogSafetyState::Unavailable,
    }
}

/// Heartbeat pillar for serial PIC / NoPic / passthrough custody.
pub(crate) fn serial_heartbeat_inputs(
    passthrough: bool,
    nopic: bool,
    dspic_addr: Option<u8>,
    dspic_heartbeat_ok: bool,
    cycle_id: u64,
) -> (HeartbeatRequirement, Vec<ControllerHeartbeatObservation>) {
    if passthrough || nopic {
        return (HeartbeatRequirement::NoneRequired, Vec::new());
    }
    let Some(addr) = dspic_addr else {
        // Exact AM2 without a known dsPIC addr cannot honestly claim HB green.
        return (HeartbeatRequirement::AllControllersSameCycle, Vec::new());
    };
    (
        HeartbeatRequirement::AllControllersSameCycle,
        vec![ControllerHeartbeatObservation {
            controller_id: addr,
            heartbeat_ok: dspic_heartbeat_ok,
            cycle_id,
        }],
    )
}

/// Thermal pillar after pre-stratum proof (AM2) or Amlogic cooling owner.
pub(crate) fn serial_thermal_safety_state(
    thermal_proof_present: bool,
    thermal_emergency: bool,
) -> ThermalSafetyState {
    if thermal_emergency {
        ThermalSafetyState::Emergency
    } else if thermal_proof_present {
        ThermalSafetyState::Ready
    } else {
        // Paths without a thermal owner (legacy residual / passthrough) do not
        // invent Ready â€” NotReady refuses dispatch fail-closed.
        ThermalSafetyState::NotReady
    }
}

/// Admit standard UART work dispatch on the serial lifecycle latch.
pub(crate) fn serial_admit_standard_work_dispatch<'a>(
    life: &'a mut WorkDispatchLifecycle,
    inputs: &WorkDispatchSafetyInputs,
) -> Result<&'a WorkDispatchAdmissionReceipt, WorkDispatchSafetyError> {
    life.admit(inputs)
}

/// Terminal revoke for the serial lifecycle.
pub(crate) fn serial_revoke_work_dispatch(
    life: &mut WorkDispatchLifecycle,
    cause: DispatchRevocationCause,
    profile_max_pwm: u8,
) -> (SafetyAction, bool) {
    life.revoke(cause, profile_max_pwm)
}

/// Revoke work dispatch and honor `stop_feed` by terminally closing SoC WDT
/// feed ownership (exact `WatchdogFeedStopSignal` and/or legacy feed owner).
///
/// Stock parity: a mid-run revoke must stop kicks immediately, not only during
/// late SHUTDOWN teardown.
pub(crate) fn serial_revoke_and_stop_watchdog_feed(
    life: &mut WorkDispatchLifecycle,
    cause: DispatchRevocationCause,
    profile_max_pwm: u8,
    exact_feed_stop: Option<&crate::runtime::watchdog_feed_gate::WatchdogFeedStopSignal>,
    legacy_feed_owner: &mut Option<crate::daemon::LegacyWatchdogFeedOwner>,
) -> SafetyAction {
    let (action, stop_feed) = serial_revoke_work_dispatch(life, cause, profile_max_pwm);
    if stop_feed {
        if let Some(sig) = exact_feed_stop {
            sig.close_terminal_lock_free();
        }
        if let Some(owner) = legacy_feed_owner.as_mut() {
            owner.close_terminal();
        }
    }
    action
}
const BM1368_MAX_WORK_ITEMS_PER_SEC: usize = 40;
const DEFAULT_MAX_WORK_ITEMS_PER_SEC: usize = 20;
const DEFAULT_SERIAL_WORK_QUEUE_DEPTH: usize = 16;
const BM1362_SERIAL_WORK_QUEUE_DEPTH: usize = 512;
const DEFAULT_SERIAL_TX_BURST: usize = 3;
const BM1362_SERIAL_TX_BURST: usize = 1;
const WORK_HISTORY_PER_ID: usize = dcentrald_common::DEFAULT_WORK_HISTORY_PER_ID;
const BM1398_WORK_HISTORY_PER_ID: usize = dcentrald_common::BM1398_WORK_HISTORY_PER_ID;
const AMLOGIC_TEMP_STARTUP_GRACE_S: u64 = 30;
const AMLOGIC_TEMP_MISS_LIMIT: u8 = 3;
const AMLOGIC_THERMAL_RESTART_DELAY_S: u64 = 60;
const AMLOGIC_FAN_SPINUP_ATTEMPTS: u32 = 3;
const AMLOGIC_FAN_SPINUP_RETRY_DELAY: Duration = Duration::from_millis(250);
const APW12_139_ASSUMED_FW: u8 = 0x71;
// A started service-backed heartbeat has a four-second caller-side wall-clock
// bound in the HAL. Exact-route cancellation is published before terminal I/O,
// and this larger join window normally reclaims the heartbeat actor before its
// controller view can escape the route owner. Scheduler or kernel anomalies
// remain negative evidence and take the out-of-band hard-stop path.
const RUNTIME_THREAD_STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// One pre-energization decision for voltage-controller actor topology. Exact
/// watchdog routes are admitted only when resolved ASIC identity and observed
/// controller evidence agree; later service/heartbeat branches consume this
/// value instead of re-deriving exact-route behavior from `nopic`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SerialActorTopology {
    ExactNoPic,
    ExactAm2Bm1362,
    LegacyNoPic,
    LegacyPic,
}

impl SerialActorTopology {
    fn admit(
        native_nopic_power_owner: bool,
        is_bm1362: bool,
        observed_nopic: bool,
    ) -> Result<Self> {
        anyhow::ensure!(
            !(native_nopic_power_owner && is_bm1362),
            "serial ASIC identity selected mutually exclusive exact NoPic and AM2 routes"
        );
        match (native_nopic_power_owner, is_bm1362, observed_nopic) {
            (true, false, true) => Ok(Self::ExactNoPic),
            (true, false, false) => anyhow::bail!(
                "exact NoPic ASIC identity conflicts with observed PIC-controller topology"
            ),
            (false, true, false) => Ok(Self::ExactAm2Bm1362),
            (false, true, true) => anyhow::bail!(
                "exact AM2 BM1362 ASIC identity conflicts with observed NoPic topology"
            ),
            (false, false, true) => Ok(Self::LegacyNoPic),
            (false, false, false) => Ok(Self::LegacyPic),
            (true, true, _) => unreachable!("mutual-exclusion check above"),
        }
    }

    fn is_exact(self) -> bool {
        matches!(self, Self::ExactNoPic | Self::ExactAm2Bm1362)
    }

    fn is_nopic(self) -> bool {
        matches!(self, Self::ExactNoPic | Self::LegacyNoPic)
    }
}

/// Runtime-thread owner shared by legacy serial routes and the two exact
/// watchdog compositions. Exact variants can be activated only once from the
/// watchdog-issued actor owner; a pending legacy route is materialized lazily
/// before its first registration.
enum SerialRuntimeThreads {
    Pending(Option<CancellationToken>),
    Legacy(RuntimeThreadGuard),
    NoPic(FixedThreadRosterGuard<NoPicSerialThreadSlot>),
    Am2(FixedThreadRosterGuard<Am2SerialThreadSlot>),
}

enum ExactSerialRuntimeActorAdmission {
    NoPic(ThreadRosterRuntimeAdmission<NoPicSerialThreadSlot>),
    Am2 {
        roster: ThreadRosterRuntimeAdmission<Am2SerialThreadSlot>,
        apw_topology: Am2ApwActorTopology,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Am2ApwActorTopology {
    SmartPsu,
    ExplicitBypass,
}

enum ExactSerialActorCloseoutAdmission {
    NoPicPreRuntime(ThreadRosterPreRuntimeCloseout<NoPicSerialThreadSlot>),
    NoPicRuntime(ThreadRosterRuntimeAdmission<NoPicSerialThreadSlot>),
    Am2PreRuntime(ThreadRosterPreRuntimeCloseout<Am2SerialThreadSlot>),
    Am2Runtime(ThreadRosterRuntimeAdmission<Am2SerialThreadSlot>),
}

impl SerialRuntimeThreads {
    fn new() -> Self {
        Self::Pending(Some(CancellationToken::new()))
    }

    fn activate_nopic(&mut self, owner: ThreadRosterOwner<NoPicSerialThreadSlot>) -> Result<()> {
        let token = match self {
            Self::Pending(token) => token
                .take()
                .context("serial runtime cancellation owner was already consumed")?,
            _ => anyhow::bail!("NoPic serial actor roster was activated after registration began"),
        };
        *self = Self::NoPic(owner.activate(token));
        Ok(())
    }

    fn activate_am2(&mut self, owner: ThreadRosterOwner<Am2SerialThreadSlot>) -> Result<()> {
        let token = match self {
            Self::Pending(token) => token
                .take()
                .context("serial runtime cancellation owner was already consumed")?,
            _ => anyhow::bail!("AM2 serial actor roster was activated after registration began"),
        };
        *self = Self::Am2(owner.activate(token));
        Ok(())
    }

    fn ensure_legacy(&mut self) -> Result<()> {
        if let Self::Pending(token) = self {
            let token = token
                .take()
                .context("serial runtime cancellation owner was already consumed")?;
            *self = Self::Legacy(RuntimeThreadGuard::new(token));
        }
        Ok(())
    }

    fn cancellation_token(&mut self) -> Result<CancellationToken> {
        self.ensure_legacy()?;
        match self {
            Self::Legacy(guard) => Ok(guard.cancellation_token()),
            Self::NoPic(guard) => Ok(guard.cancellation_token()),
            Self::Am2(guard) => Ok(guard.cancellation_token()),
            Self::Pending(_) => unreachable!("legacy activation handled above"),
        }
    }

    fn request_stop(&self) {
        match self {
            Self::Pending(Some(token)) => token.cancel(),
            Self::Pending(None) => {}
            Self::Legacy(guard) => guard.request_stop(),
            Self::NoPic(guard) => guard.request_stop(),
            Self::Am2(guard) => guard.request_stop(),
        }
    }

    fn reserve_am2(
        &mut self,
        slot: Am2SerialThreadSlot,
    ) -> Result<ThreadSlotReservation<'_, Am2SerialThreadSlot>> {
        match self {
            Self::Am2(guard) => guard.reserve(slot),
            _ => anyhow::bail!("AM2 serial actor reservation used outside the exact AM2 roster"),
        }
    }

    fn resolve_am2_apw(&mut self, smart_psu_present: bool) -> Result<()> {
        match self {
            Self::Am2(guard) => guard.resolve_conditional(
                Am2SerialThreadSlot::ApwHeartbeat,
                smart_psu_present,
                "exact AM2 route uses an explicit non-smart PSU bypass",
            ),
            _ => anyhow::bail!("AM2 APW topology resolution used outside the exact AM2 roster"),
        }
    }

    fn reserve_serial_io(&mut self, legacy_name: &'static str) -> Result<SerialIoReservation<'_>> {
        self.ensure_legacy()?;
        match self {
            Self::Legacy(guard) => Ok(SerialIoReservation::Legacy { guard, legacy_name }),
            Self::NoPic(guard) => {
                anyhow::ensure!(
                    legacy_name == NoPicSerialThreadSlot::SerialIo.name(),
                    "NoPic exact serial roster refuses alternate I/O actor {legacy_name}"
                );
                Ok(SerialIoReservation::NoPic(
                    guard.reserve(NoPicSerialThreadSlot::SerialIo)?,
                ))
            }
            Self::Am2(guard) => {
                anyhow::ensure!(
                    legacy_name == Am2SerialThreadSlot::SerialIo.name(),
                    "AM2 exact serial roster refuses alternate I/O actor {legacy_name}"
                );
                Ok(SerialIoReservation::Am2(
                    guard.reserve(Am2SerialThreadSlot::SerialIo)?,
                ))
            }
            Self::Pending(_) => unreachable!("legacy activation handled above"),
        }
    }

    fn spawn_serial_io(
        &mut self,
        actor_name: &'static str,
        spawn: impl FnOnce() -> Result<std::thread::JoinHandle<()>>,
    ) -> Result<()> {
        let slot = self.reserve_serial_io(actor_name)?;
        let handle = spawn()?;
        slot.attach(handle);
        Ok(())
    }

    fn reserve_pic_heartbeat(&mut self) -> Result<ThreadSlotReservation<'_, Am2SerialThreadSlot>> {
        match self {
            Self::Am2(guard) => guard.reserve(Am2SerialThreadSlot::DspicHeartbeat),
            Self::Pending(_) | Self::Legacy(_) => anyhow::bail!(
                "legacy serial routes cannot register a PIC heartbeat; exact AM2 BM1362 actor authority is required"
            ),
            Self::NoPic(_) => {
                anyhow::bail!("NoPic exact serial route cannot register a dsPIC heartbeat")
            }
        }
    }

    fn spawn_pic_heartbeat(
        &mut self,
        spawn: impl FnOnce() -> Result<std::thread::JoinHandle<()>>,
    ) -> Result<()> {
        let slot = self.reserve_pic_heartbeat()?;
        let handle = spawn()?;
        slot.attach(handle);
        Ok(())
    }

    fn seal_exact_runtime(
        &mut self,
        am2_apw_topology: Option<Am2ApwActorTopology>,
    ) -> Result<ExactSerialRuntimeActorAdmission> {
        match self {
            Self::NoPic(guard) => {
                anyhow::ensure!(
                    am2_apw_topology.is_none(),
                    "NoPic actor admission cannot consume AM2 APW topology"
                );
                Ok(ExactSerialRuntimeActorAdmission::NoPic(
                    guard.seal_runtime_admission()?,
                ))
            }
            Self::Am2(guard) => {
                let apw_topology =
                    am2_apw_topology.context("AM2 actor admission requires typed APW topology")?;
                let roster = guard.seal_runtime_admission()?;
                match apw_topology {
                    Am2ApwActorTopology::SmartPsu => anyhow::ensure!(
                        roster.running(Am2SerialThreadSlot::ApwHeartbeat),
                        "smart-APW runtime requires a registered APW-heartbeat actor"
                    ),
                    Am2ApwActorTopology::ExplicitBypass => anyhow::ensure!(
                        roster.topology_not_applicable(Am2SerialThreadSlot::ApwHeartbeat),
                        "explicit APW bypass requires topology non-applicability evidence"
                    ),
                }
                Ok(ExactSerialRuntimeActorAdmission::Am2 {
                    roster,
                    apw_topology,
                })
            }
            Self::Pending(_) | Self::Legacy(_) => {
                anyhow::bail!("exact serial actor admission used outside an exact route roster")
            }
        }
    }

    async fn stop_and_join(
        &mut self,
        timeout: Duration,
        closeout_admission: Option<ExactSerialActorCloseoutAdmission>,
    ) -> SerialRuntimeThreadStop {
        if let Err(error) = self.ensure_legacy() {
            return SerialRuntimeThreadStop::InitializationFailed(error);
        }
        match self {
            Self::Legacy(guard) => {
                SerialRuntimeThreadStop::Legacy(guard.stop_and_join(timeout).await)
            }
            Self::NoPic(guard) => {
                let preparation = match closeout_admission {
                    Some(ExactSerialActorCloseoutAdmission::NoPicPreRuntime(admission)) => guard
                        .resolve_unstarted_conditionals_for_closeout(
                            admission,
                            "exact NoPic runtime actor phase was not admitted before closeout",
                        ),
                    Some(ExactSerialActorCloseoutAdmission::NoPicRuntime(admission)) => {
                        guard.validate_runtime_admitted_closeout(admission)
                    }
                    _ => {
                        guard.reject_unbound_closeout();
                        Err(anyhow::anyhow!(
                            "NoPic actor roster closeout lacks matching route-domain authority"
                        ))
                    }
                };
                if let Err(error) = preparation {
                    warn!(%error, "NoPic actor roster closeout admission failed");
                }
                SerialRuntimeThreadStop::NoPic(guard.stop_and_join(timeout).await)
            }
            Self::Am2(guard) => {
                let preparation = match closeout_admission {
                    Some(ExactSerialActorCloseoutAdmission::Am2PreRuntime(admission)) => guard
                        .resolve_unstarted_conditionals_for_closeout(
                            admission,
                            "exact AM2 runtime actor phase was not admitted before closeout",
                        ),
                    Some(ExactSerialActorCloseoutAdmission::Am2Runtime(admission)) => {
                        guard.validate_runtime_admitted_closeout(admission)
                    }
                    _ => {
                        guard.reject_unbound_closeout();
                        Err(anyhow::anyhow!(
                            "AM2 actor roster closeout lacks matching route-domain authority"
                        ))
                    }
                };
                if let Err(error) = preparation {
                    warn!(%error, "AM2 actor roster closeout admission failed");
                }
                SerialRuntimeThreadStop::Am2(guard.stop_and_join(timeout).await)
            }
            Self::Pending(_) => unreachable!("legacy activation handled above"),
        }
    }
}

enum SerialIoReservation<'a> {
    Legacy {
        guard: &'a mut RuntimeThreadGuard,
        legacy_name: &'static str,
    },
    NoPic(ThreadSlotReservation<'a, NoPicSerialThreadSlot>),
    Am2(ThreadSlotReservation<'a, Am2SerialThreadSlot>),
}

impl SerialIoReservation<'_> {
    fn attach(self, handle: std::thread::JoinHandle<()>) {
        match self {
            Self::Legacy { guard, legacy_name } => guard.push(legacy_name, handle),
            Self::NoPic(slot) => slot.attach(handle),
            Self::Am2(slot) => slot.attach(handle),
        }
    }
}

enum SerialRuntimeThreadStop {
    InitializationFailed(anyhow::Error),
    Legacy(ThreadStopSummary),
    NoPic(ThreadRosterStop<NoPicSerialThreadSlot>),
    Am2(ThreadRosterStop<Am2SerialThreadSlot>),
}

impl SerialRuntimeThreadStop {
    fn any_timed_out(&self) -> bool {
        match self {
            Self::InitializationFailed(_) => true,
            Self::Legacy(stop) => stop.any_timed_out(),
            Self::NoPic(stop) => stop.any_timed_out(),
            Self::Am2(stop) => stop.any_timed_out(),
        }
    }

    fn panicked_worker_names(&self) -> Vec<&'static str> {
        match self {
            Self::InitializationFailed(_) => Vec::new(),
            Self::Legacy(stop) => stop.panicked_worker_names(),
            Self::NoPic(stop) => stop.panicked_worker_names(),
            Self::Am2(stop) => stop.panicked_worker_names(),
        }
    }

    fn into_nopic_receipt(self) -> Result<ThreadRosterQuiescenceReceipt<NoPicSerialThreadSlot>> {
        match self {
            Self::NoPic(stop) => stop
                .into_receipt()
                .context("NoPic exact serial actor roster did not close cleanly"),
            Self::InitializationFailed(error) => Err(error),
            Self::Legacy(_) | Self::Am2(_) => {
                anyhow::bail!("NoPic watchdog closeout received the wrong serial actor roster")
            }
        }
    }

    fn into_am2_receipt(self) -> Result<ThreadRosterQuiescenceReceipt<Am2SerialThreadSlot>> {
        match self {
            Self::Am2(stop) => stop
                .into_receipt()
                .context("AM2 exact serial actor roster did not close cleanly"),
            Self::InitializationFailed(error) => Err(error),
            Self::Legacy(_) | Self::NoPic(_) => {
                anyhow::bail!("AM2 watchdog closeout received the wrong serial actor roster")
            }
        }
    }
}
const AM2_BM1362_SERIAL_FENCE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const NOPIC_WATCHDOG_BRINGUP_GRACE: Duration = Duration::from_secs(120);
const NOPIC_SAFETY_LIVENESS_INTERVAL: Duration = Duration::from_secs(2);
const AM2_BM1362_WATCHDOG_BRINGUP_GRACE: Duration = Duration::from_secs(180);
const AM2_BM1362_SAFETY_LIVENESS_INTERVAL: Duration = Duration::from_secs(2);
const AM2_BM1362_REQUIRED_AIRFLOW_MIN_RPM: u32 = 1800;
/// Match the established hybrid-runtime rule: twenty consecutive 1 Hz
/// selected-dsPIC heartbeat failures revoke voltage-maintenance authority.
const AM2_BM1362_PIC_HEARTBEAT_MAX_FAILURES: u32 = 20;
const AM2_BM1362_PIC_HEARTBEAT_ATTEMPT_BUDGET_S: u32 = 3;
const AM2_BM1362_EMERGENCY_CUT_MARGIN_S: u32 = 2;
const AM2_BM1362_MIN_WATCHDOG_TIMEOUT_S: u32 =
    2 * (AM2_BM1362_PIC_HEARTBEAT_ATTEMPT_BUDGET_S + AM2_BM1362_EMERGENCY_CUT_MARGIN_S);
/// Ordinary APW wire loss is allowed three consecutive 1 Hz attempts before
/// explicit cutoff. Typed ownership, safety-generation, policy, and protocol
/// failures bypass this budget and terminate immediately.
const AM2_BM1362_APW_HEARTBEAT_MAX_FAILURES: u32 = 3;
const AM2_BM1362_THERMAL_POLL_TIMEOUT: Duration = Duration::from_secs(3);
const AM2_BM1362_TERMINAL_SAFE_OFF_ATTEMPTS: usize = 2;
const HASHBOARD_EEPROM_WRITE_DENYLIST: [u8; 8] = [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57];

#[derive(Debug)]
struct FanTachSnapshot {
    available: bool,
    expected_channels: usize,
    readings: Vec<(u8, u32)>,
}

impl FanTachSnapshot {
    fn rpms(&self) -> Vec<u32> {
        self.readings.iter().map(|(_, rpm)| *rpm).collect()
    }
}

async fn sample_fan_tach(fan: Arc<dyn FanAccess>) -> Result<FanTachSnapshot> {
    tokio::task::spawn_blocking(move || {
        let readings = fan.get_per_fan_rpm();
        FanTachSnapshot {
            // Read availability after sampling so a sampler error that revokes
            // the owner's evidence is part of this snapshot.
            available: fan.tach_available(),
            expected_channels: fan.fan_count() as usize,
            readings,
        }
    })
    .await
    .context("fan tach sampling worker did not complete")
}

#[derive(Debug, Clone, Copy)]
struct Am2ThermalObservation {
    temp_c: f32,
    source: crate::s19j_hybrid_mining::Am2ThermalSource,
}

impl Am2ThermalObservation {
    fn chain_temp_source(self) -> &'static str {
        match self.source {
            crate::s19j_hybrid_mining::Am2ThermalSource::DspicBoardSensor => {
                dcentrald_api::ChainTempSource::BOARD_SENSOR
            }
            crate::s19j_hybrid_mining::Am2ThermalSource::XadcSocDie => {
                dcentrald_api::ChainTempSource::SOC_DIE_FALLBACK
            }
        }
    }
}

/// Keep synchronous dsPIC/XADC reads off the Tokio safety loop and put a hard
/// deadline around loss of thermal observability. A timed-out blocking worker
/// may finish its read in the background, but its supervisor ownership is
/// permanently revoked and the caller immediately enters terminal safe-off.
async fn poll_am2_thermal_bounded(
    mut supervisor: crate::s19j_hybrid_mining::Am2ThermalSupervisor,
    stage: crate::s19j_hybrid_mining::Am2ThermalPollStage,
    capture_cold_baseline: bool,
) -> Result<(
    crate::s19j_hybrid_mining::Am2ThermalSupervisor,
    Am2ThermalObservation,
)> {
    let worker = tokio::task::spawn_blocking(move || {
        if capture_cold_baseline {
            supervisor.maybe_capture_die_baseline();
        }
        let result = supervisor.poll_and_check(stage);
        (supervisor, result)
    });
    let (supervisor, result) = tokio::time::timeout(AM2_BM1362_THERMAL_POLL_TIMEOUT, worker)
        .await
        .context("AM2 BM1362 thermal poll exceeded its 3-second safety deadline")?
        .context("AM2 BM1362 thermal polling worker failed")?;
    let temp_c = result?;
    let source = supervisor
        .effective_source()
        .context("AM2 BM1362 thermal poll returned a value without source provenance")?;
    Ok((supervisor, Am2ThermalObservation { temp_c, source }))
}

fn require_am2_bringup_active(shutdown: &CancellationToken, stage: &'static str) -> Result<()> {
    if shutdown.is_cancelled() {
        anyhow::bail!("shutdown requested during AM2 BM1362 bring-up at {stage}");
    }
    Ok(())
}

async fn wait_am2_bringup_active(
    shutdown: &CancellationToken,
    duration: Duration,
    stage: &'static str,
) -> Result<()> {
    tokio::select! {
        _ = shutdown.cancelled() => {
            anyhow::bail!("shutdown requested during AM2 BM1362 bring-up wait at {stage}")
        }
        _ = tokio::time::sleep(duration) => Ok(()),
    }
}

async fn wait_am2_apw_heartbeat_stable(
    shutdown: &CancellationToken,
    terminal_exit: &mut mpsc::UnboundedReceiver<String>,
    progress: &AtomicU64,
    duration: Duration,
    stage: &'static str,
) -> Result<()> {
    wait_am2_apw_heartbeat_stable_with_post_wait(
        shutdown,
        terminal_exit,
        progress,
        duration,
        stage,
        || {},
    )
    .await
}

async fn wait_am2_apw_heartbeat_stable_with_post_wait<F>(
    shutdown: &CancellationToken,
    terminal_exit: &mut mpsc::UnboundedReceiver<String>,
    progress: &AtomicU64,
    duration: Duration,
    stage: &'static str,
    post_wait: F,
) -> Result<()>
where
    F: FnOnce(),
{
    let initial_progress = progress.load(Ordering::Acquire);
    tokio::select! {
        biased;
        exit = terminal_exit.recv() => match exit {
            Some(reason) => anyhow::bail!(
                "AM2 BM1362 APW heartbeat failed during {stage}: {reason}"
            ),
            None if shutdown.is_cancelled() => anyhow::bail!(
                "shutdown requested during AM2 BM1362 bring-up wait at {stage}"
            ),
            None => anyhow::bail!(
                "AM2 BM1362 APW heartbeat actor exited without a terminal receipt during {stage}"
            ),
        },
        _ = shutdown.cancelled() => {
            anyhow::bail!("shutdown requested during AM2 BM1362 bring-up wait at {stage}")
        }
        _ = tokio::time::sleep(duration) => {}
    }

    post_wait();
    match terminal_exit.try_recv() {
        Ok(reason) => anyhow::bail!("AM2 BM1362 APW heartbeat failed during {stage}: {reason}"),
        Err(mpsc::error::TryRecvError::Disconnected) if shutdown.is_cancelled() => {
            anyhow::bail!("shutdown requested during AM2 BM1362 bring-up wait at {stage}")
        }
        Err(mpsc::error::TryRecvError::Disconnected) => anyhow::bail!(
            "AM2 BM1362 APW heartbeat actor exited without a terminal receipt during {stage}"
        ),
        Err(mpsc::error::TryRecvError::Empty) => {}
    }
    if shutdown.is_cancelled() {
        anyhow::bail!("shutdown requested during AM2 BM1362 bring-up wait at {stage}");
    }
    let observed_progress = progress.load(Ordering::Acquire);
    if observed_progress <= initial_progress {
        anyhow::bail!("AM2 BM1362 APW heartbeat made no successful progress during {stage}");
    }
    Ok(())
}

async fn admit_fan_motion_at_pwm(
    fan: Arc<dyn FanAccess>,
    safety: &mut FanTachSafety,
    pwm: u8,
    stage: &'static str,
) -> Result<FanCommandReceipt> {
    let receipt = set_fan_speed_checked_blocking(
        Arc::clone(&fan),
        pwm,
        "Amlogic pre-energize fan command/readback",
    )
    .await
    .with_context(|| format!("Amlogic {stage} fan command/readback failed"))?;
    for attempt in 1..=AMLOGIC_FAN_SPINUP_ATTEMPTS {
        let snapshot = sample_fan_tach(fan.clone()).await?;
        let rpms = snapshot.rpms();
        let state = safety.observe_required_airflow(
            snapshot.available,
            receipt.observed_pwm(),
            snapshot.expected_channels,
            &rpms,
        );
        match state {
            FanTachSafetyState::Healthy => {
                info!(
                    stage,
                    attempt,
                    pwm = receipt.observed_pwm(),
                    readings = ?snapshot.readings,
                    "Amlogic pre-energize fan-motion admission accepted"
                );
                return Ok(receipt);
            }
            FanTachSafetyState::AirflowNotCommanded
            | FanTachSafetyState::EvidenceUnavailable { .. } => {
                anyhow::bail!("Amlogic {stage} pre-energize tach evidence unavailable: {state:?}");
            }
            FanTachSafetyState::Debouncing { .. } | FanTachSafetyState::Failed { .. }
                if attempt < AMLOGIC_FAN_SPINUP_ATTEMPTS =>
            {
                warn!(stage, attempt, ?state, readings = ?snapshot.readings, "Amlogic fans have not established motion; retrying before power admission");
                tokio::time::sleep(AMLOGIC_FAN_SPINUP_RETRY_DELAY).await;
            }
            _ => {
                anyhow::bail!(
                    "Amlogic {stage} pre-energize fan-motion admission refused after {} attempts: state={state:?}, readings={:?}",
                    AMLOGIC_FAN_SPINUP_ATTEMPTS,
                    snapshot.readings
                );
            }
        }
    }
    anyhow::bail!("Amlogic {stage} pre-energize fan-motion admission did not complete")
}

async fn admit_fan_airflow_envelope(
    fan: Arc<dyn FanAccess>,
    safety: &mut FanTachSafety,
    minimum_pwm: u8,
    maximum_pwm: u8,
) -> Result<FanCommandReceipt> {
    admit_fan_motion_at_pwm(fan.clone(), safety, maximum_pwm, "spin-up").await?;
    if minimum_pwm != maximum_pwm {
        if let Err(minimum_error) =
            admit_fan_motion_at_pwm(fan.clone(), safety, minimum_pwm, "energized minimum").await
        {
            match set_fan_speed_checked_blocking(
                Arc::clone(&fan),
                maximum_pwm,
                "Amlogic pre-energize fan ceiling restoration",
            )
            .await
            {
                Ok(_) => {
                    anyhow::bail!(
                        "Amlogic energized-minimum motion proof failed; restored startup ceiling before refusing power: {minimum_error:#}"
                    );
                }
                Err(restore_error) => {
                    anyhow::bail!(
                        "Amlogic energized-minimum motion proof failed and startup ceiling restoration also failed: motion={minimum_error:#}; restore={restore_error}"
                    );
                }
            }
        }
    }
    // Leave startup at the retained ceiling. The low-point observation above
    // proves the later proportional controller may safely return to its floor.
    set_fan_speed_checked_blocking(
        fan,
        maximum_pwm,
        "Amlogic final pre-energize fan command/readback",
    )
    .await
    .context("Amlogic final pre-energize fan command/readback failed")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoPicFanLoopDisposition {
    Continue,
    SafeOffAndStop,
}

fn nopic_fan_loop_disposition(state: &FanTachSafetyState) -> NoPicFanLoopDisposition {
    match state {
        FanTachSafetyState::Healthy | FanTachSafetyState::Debouncing { .. } => {
            NoPicFanLoopDisposition::Continue
        }
        FanTachSafetyState::AirflowNotCommanded
        | FanTachSafetyState::Failed { .. }
        | FanTachSafetyState::EvidenceUnavailable { .. } => NoPicFanLoopDisposition::SafeOffAndStop,
    }
}

fn observed_dspic_firmware(version: Option<u8>) -> Result<DspicFirmware> {
    let version = version.context(
        "dsPIC firmware was not observed; refusing protocol-dependent heartbeat startup",
    )?;
    let firmware = DspicFirmware::from_version(version);
    if !dspic_runtime_protocol_is_proven(firmware) {
        anyhow::bail!(
            "unsupported observed dsPIC firmware 0x{version:02X}; refusing protocol-dependent heartbeat startup"
        );
    }
    Ok(firmware)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoPicPowerState {
    NeverOwned,
    MayBeEnergized,
    EnabledByDaemon,
}

struct NoPicPsuGuard {
    state: NoPicPowerState,
    lifecycle_owner: Option<dcentrald_hal::platform::amlogic::AmlogicPowerThermalLifecycleOwner>,
}

pub(crate) struct NoPicSafeOffReceipt {
    power: dcentrald_hal::platform::amlogic::PsuSafeOffReceipt,
    management_fabric: dcentrald_hal::i2c::I2cServiceCloseReceipt,
    teardown_budget: Option<TeardownBudgetView>,
}

/// Move-only timing progress for one exact-serial cutoff. The checked hardware
/// receipt remains route-specific; this capability proves only that the
/// load-bearing cut ran inside the watchdog-issued absolute schedule.
struct ExactSerialTeardownProgress {
    teardown_budget: TeardownBudgetView,
    cutoff_started_at: Instant,
    cutoff_completed_at: Instant,
}

impl ExactSerialTeardownProgress {
    fn after_worker_timed_cut(
        teardown_budget: TeardownBudgetView,
        cutoff_started_at: Instant,
        cutoff_completed_at: Instant,
    ) -> Result<Self> {
        teardown_budget.require_not_before_start(cutoff_started_at)?;
        teardown_budget.require_completed_at(TeardownStage::CutoffStart, cutoff_started_at)?;
        teardown_budget.require_completed_at(TeardownStage::CutoffComplete, cutoff_completed_at)?;
        Ok(Self {
            teardown_budget,
            cutoff_started_at,
            cutoff_completed_at,
        })
    }

    fn after_nopic_checked_cut(
        teardown_budget: TeardownBudgetView,
        timed_cut: TimedTerminalOwnerOperation<NoPicEmergencyCutReceipt>,
    ) -> Result<Self> {
        let TimedTerminalOwnerOperation {
            value: _checked_cut,
            started_at,
            completed_at,
        } = timed_cut;
        Self::after_worker_timed_cut(teardown_budget, started_at, completed_at)
    }

    fn after_am2_checked_cut(
        teardown_budget: Option<TeardownBudgetView>,
        timed_cut: TimedTerminalOwnerOperation<Am2FirstStageCutAttempt>,
    ) -> (Am2FirstStageCutAttempt, Result<Self>) {
        let TimedTerminalOwnerOperation {
            value: first_stage_cut,
            started_at,
            completed_at,
        } = timed_cut;
        let timing = match &first_stage_cut.result {
            Ok(_) => match teardown_budget {
                Some(budget) => Self::after_worker_timed_cut(budget, started_at, completed_at),
                None => Err(anyhow::anyhow!(
                    "AM2 teardown budget was unavailable at first-stage cutoff"
                )),
            },
            Err(error) => Err(anyhow::anyhow!(
                "AM2 checked first-stage cutoff failed: {error:#}"
            )),
        };
        (first_stage_cut, timing)
    }

    fn complete(self, completed_at: Instant) -> Result<ExactSerialTeardownReceipt> {
        self.teardown_budget
            .require_completed_at(TeardownStage::CutoffStart, self.cutoff_started_at)?;
        self.teardown_budget
            .require_completed_at(TeardownStage::CutoffComplete, self.cutoff_completed_at)?;
        self.teardown_budget
            .require_completed_at(TeardownStage::CleanupComplete, completed_at)?;
        Ok(ExactSerialTeardownReceipt {
            teardown_budget: self.teardown_budget,
        })
    }
}

/// Run/issuer-bound proof that exact-serial cutoff and cleanup completed within
/// their shared schedule. Only the exact watchdog manifests can consume it.
pub(crate) struct ExactSerialTeardownReceipt {
    teardown_budget: TeardownBudgetView,
}

impl ExactSerialTeardownReceipt {
    pub(crate) fn same_teardown_budget(&self, authority: &TeardownDisarmAuthority) -> bool {
        self.teardown_budget.same_budget(authority)
    }
}

fn remaining_exact_serial_cleanup(
    teardown_budget: Option<&TeardownBudgetView>,
    requested: Duration,
) -> Duration {
    match teardown_budget {
        Some(budget) => budget
            .remaining_capped_at(TeardownStage::CleanupComplete, requested, Instant::now())
            .unwrap_or(Duration::ZERO),
        None => requested,
    }
}

/// Checked evidence that an urgent GPIO cutoff was issued before bounded
/// closeout. This deliberately cannot satisfy the watchdog shutdown manifest:
/// only [`NoPicSafeOffReceipt`], minted by a repeated checked readback after all
/// mutation domains and runtime actors are fenced, has terminal authority.
struct NoPicEmergencyCutReceipt {
    _power: dcentrald_hal::platform::amlogic::PsuSafeOffReceipt,
}

impl NoPicSafeOffReceipt {
    pub(crate) fn power(&self) -> &dcentrald_hal::platform::amlogic::PsuSafeOffReceipt {
        &self.power
    }

    pub(crate) fn management_fabric(&self) -> &dcentrald_hal::i2c::I2cServiceCloseReceipt {
        &self.management_fabric
    }

    pub(crate) fn same_teardown_budget(&self, authority: &TeardownDisarmAuthority) -> bool {
        self.teardown_budget
            .as_ref()
            .is_some_and(|budget| budget.same_budget(authority))
    }
}

impl NoPicPsuGuard {
    fn new() -> Self {
        crate::terminal_io_owner::prepare();
        Self {
            state: NoPicPowerState::NeverOwned,
            lifecycle_owner: None,
        }
    }

    fn prepare_enable(
        &mut self,
        fan_max_pwm: u8,
        lifecycle_owner: dcentrald_hal::platform::amlogic::AmlogicPowerThermalLifecycleOwner,
    ) {
        self.state = NoPicPowerState::MayBeEnergized;
        self.lifecycle_owner = Some(lifecycle_owner);
        arm_nopic_teardown(fan_max_pwm);
    }

    fn mark_enabled(&mut self) {
        debug_assert_eq!(self.state, NoPicPowerState::MayBeEnergized);
        self.state = NoPicPowerState::EnabledByDaemon;
    }

    fn owns_power(&self) -> bool {
        self.state != NoPicPowerState::NeverOwned
    }

    /// Issue an early independent GPIO cutoff without consuming the owner.
    /// Terminal closeout repeats checked safe-off after every mutation domain
    /// is fenced, so this is latency reduction rather than final evidence.
    fn first_stage_safe_off(&self) -> Result<NoPicEmergencyCutReceipt> {
        if !self.owns_power() {
            anyhow::bail!("NoPic first-stage safe-off requested without an owned power lease");
        }
        let owner = self
            .lifecycle_owner
            .as_ref()
            .context("NoPic first-stage management-fabric lifecycle owner was unavailable")?;
        let (_, power) = owner
            .latch_terminal_and_disable_psu_checked()
            .context("checked NoPic first-stage GPIO437 safe-off failed")?;
        Ok(NoPicEmergencyCutReceipt { _power: power })
    }

    fn safe_off(
        &mut self,
        teardown_budget: Option<TeardownBudgetView>,
        management_fabric_deadline: Instant,
    ) -> Result<NoPicSafeOffReceipt> {
        if !self.owns_power() {
            anyhow::bail!("NoPic software safe-off requested without an owned power lease");
        }
        let fabric_close = self
            .lifecycle_owner
            .as_mut()
            .context("NoPic management-fabric lifecycle owner was unavailable")
            .and_then(|owner| {
                let _ = owner.latch_terminal_safe_off();
                owner
                    .close_and_join_until(management_fabric_deadline)
                    .map_err(anyhow::Error::from)
            });
        // Repeat the checked load-bearing cutoff after the bus fd and worker
        // are gone. A close failure cannot suppress this physical-safe-
        // direction attempt, but it withholds the typed watchdog receipt.
        let power = self
            .lifecycle_owner
            .as_ref()
            .context("NoPic terminal GPIO owner was unavailable")
            .and_then(|owner| {
                owner
                    .latch_terminal_and_disable_psu_checked()
                    .map(|(_, receipt)| receipt)
                    .map_err(anyhow::Error::from)
            })
            .context("checked NoPic GPIO437 safe-off failed");
        let (management_fabric, receipt) = match (fabric_close, power) {
            (Ok(fabric), Ok(power)) => (fabric, power),
            (Err(fabric_error), Ok(_)) => {
                return Err(fabric_error.context(
                    "NoPic GPIO437 is checked low, but management I2C did not close cleanly",
                ));
            }
            (Ok(_), Err(power_error)) => return Err(power_error),
            (Err(fabric_error), Err(power_error)) => {
                return Err(anyhow::anyhow!(
                    "NoPic management I2C close failed ({fabric_error:#}); checked GPIO437 safe-off also failed ({power_error:#})"
                ));
            }
        };
        self.state = NoPicPowerState::NeverOwned;
        Ok(NoPicSafeOffReceipt {
            power: receipt,
            management_fabric,
            teardown_budget,
        })
    }
}

impl Drop for NoPicPsuGuard {
    fn drop(&mut self) {
        if !self.owns_power() {
            return;
        }
        self.state = NoPicPowerState::NeverOwned;
        let lifecycle_owner = self.lifecycle_owner.take();
        crate::terminal_io_owner::dispatch("nopic-drop-safe-off", move || {
            let mut lifecycle_owner = lifecycle_owner;
            let owner_cut_attempted = if let Some(owner) = lifecycle_owner.as_ref() {
                let transition = owner.latch_terminal_safe_off();
                if !transition.no_controller_mutation_stage_in_flight() {
                    error!(
                        generation = transition.generation(),
                        "NoPic drop fenced management I2C with a controller mutation still in flight"
                    );
                }
                if let Err(e) = owner.latch_terminal_and_disable_psu_checked() {
                    warn!(error = %e, "Failed to disable NoPic PSU during shutdown");
                }
                true
            } else {
                false
            };
            // Safety (cut-hash-before-noise + PWM-30 home cap, per
            // ): CUT PSU POWER FIRST so the heat
            // source (the hashboards) is removed, THEN hold fans at the quiet
            // home cap for coast-down. NEVER blast a home-unit's fans to 100%:
            // once the chips are de-energized there is no active thermal load
            // that justifies a jet, and these are home/space-heater units the
            // operator works beside.
            //
            // (Was: 100% fan-blast for 2 s applied BEFORE the PSU cut â€” a direct
            // inversion of cut-hash-before-noise and a violation of the absolute
            // PWM-30 home cap. Audit wf_4a84d55e ABSENT finding, 2026-05-29.)
            if !owner_cut_attempted {
                if let Err(e) = dcentrald_hal::platform::amlogic::disable_psu_checked() {
                    warn!(error = %e, "Failed to disable NoPic PSU without lifecycle owner during shutdown");
                }
            }
            if let Some(owner) = lifecycle_owner.as_mut() {
                if let Err(error) =
                    owner.close_and_join_until(Instant::now() + Duration::from_secs(2))
                {
                    warn!(%error, "NoPic drop-safe-off could not join the management I2C worker");
                }
            }
            // Quiet coast-down at PWM 30 (home cap). The Amlogic PWM period is
            // 100_000 ns (AMLOGIC_PWM_PERIOD_NS), so PWM 30 = 30_000 ns duty â€”
            // NOT 100_000 (100% jet). Best-effort; fans run off the control-board
            // rail and stay powered after the hashboard PSU is disabled.
            let _ = std::fs::write("/sys/class/pwm/pwmchip0/pwm0/duty_cycle", "30000");
            let _ = std::fs::write("/sys/class/pwm/pwmchip0/pwm1/duty_cycle", "30000");
        });
    }
}

fn checked_nopic_emergency_safe_off(guard: &mut NoPicPsuGuard) -> Result<NoPicEmergencyCutReceipt> {
    if guard.owns_power() {
        guard.first_stage_safe_off()
    } else {
        anyhow::bail!("checked NoPic emergency safe-off requested without an owned power lease")
    }
}

/// Process-global flag, armed the moment a NoPic (am3-aml) run energizes the PSU.
/// Release builds use `panic = "abort"`, which BYPASSES `NoPicPsuGuard::Drop`, and
/// NoPic (TAS5782M DAC voltage) has NO PIC heartbeat watchdog â€” so without this a
/// panic leaves the hashboards energized indefinitely (fire risk). The `main()`
/// crash panic hook reads this to cut PSU power. Mirrors the am2 `AM2_TEARDOWN_PARAMS`
/// pattern (W24-CRASH-1). Stores the home fan cap, already clamped to PWM_SAFETY_MAX.
static NOPIC_TEARDOWN_ARMED: std::sync::OnceLock<u8> = std::sync::OnceLock::new();

/// Arm the NoPic (am3-aml) panic-hook teardown â€” call at the instant the NoPic PSU
/// is energized. Idempotent (OnceLock::set). `fan_max_pwm` is clamped to the home
/// PWM_SAFETY_MAX so the coast-down can never blast.
pub fn arm_nopic_teardown(fan_max_pwm: u8) {
    let _ = NOPIC_TEARDOWN_ARMED.set(fan_max_pwm.min(dcentrald_hal::fan::PWM_SAFETY_MAX));
}

/// Best-effort cut-hash-before-noise teardown for the `main()` crash panic hook on
/// the am3-aml NoPic path. No-op (and no allocation) unless a NoPic run armed it.
/// Cuts PSU power FIRST (remove the heat source), then quiet-coasts fans at the home
/// cap. Swallows all errors (must never re-panic from inside the panic hook).
pub fn nopic_panic_hook_best_effort_teardown() {
    if let Some(&cap_pwm) = NOPIC_TEARDOWN_ARMED.get() {
        let _ = dcentrald_hal::platform::amlogic::disable_psu();
        // Amlogic PWM period = 100_000 ns, so PWM N => N * 1000 ns duty (PWM 30 = 30000).
        let duty = (cap_pwm.min(dcentrald_hal::fan::PWM_SAFETY_MAX) as u32) * 1_000;
        let duty_s = duty.to_string();
        let _ = std::fs::write("/sys/class/pwm/pwmchip0/pwm0/duty_cycle", &duty_s);
        let _ = std::fs::write("/sys/class/pwm/pwmchip0/pwm1/duty_cycle", &duty_s);
    }
}

trait Am2FirstStagePowerCut {
    fn attempt_first_stage_power_cut(&mut self, reason: &'static str) -> Result<()>;
}

/// Advance one owned safe-off leg without ever losing the live owner on
/// failure or replaying a leg that already produced evidence.
fn attempt_retained_safe_off_leg<O, R>(
    owner: &mut Option<O>,
    receipt: &mut Option<R>,
    missing_owner: &'static str,
    attempt: impl FnOnce(&mut O) -> Result<R>,
) -> Result<()> {
    if receipt.is_some() {
        return Ok(());
    }
    let result = attempt(owner.as_mut().context(missing_owner)?)?;
    *receipt = Some(result);
    owner.take();
    Ok(())
}

/// Do not begin any final safe-off leg until the shared controller fabric has
/// produced a positive terminal barrier. A failed barrier attempt must leave
/// every leg owner and receipt untouched so a later observation can establish
/// the barrier before the complete D/APW/GPIO sequence is executed.
fn attempt_after_terminal_barrier<S, R>(
    state: &mut S,
    establish_barrier: impl FnOnce(&mut S) -> Result<()>,
    attempt_safe_off: impl FnOnce(&mut S) -> Result<R>,
) -> Result<R> {
    establish_barrier(state)?;
    attempt_safe_off(state)
}

fn install_unique_owner<O, R>(
    owner: &mut Option<O>,
    completed_receipt: &Option<R>,
    new_owner: O,
    duplicate_error: &'static str,
) -> Result<()> {
    if owner.is_some() || completed_receipt.is_some() {
        anyhow::bail!(duplicate_error);
    }
    *owner = Some(new_owner);
    Ok(())
}

fn record_joined_actor_panic(
    terminal_error: &mut Option<anyhow::Error>,
    panicked_worker_names: &[&'static str],
) {
    if panicked_worker_names.is_empty() {
        return;
    }
    let panic_error = anyhow::anyhow!(
        "hardware runtime actors panicked before joined shutdown completion: {}",
        panicked_worker_names.join(", ")
    );
    *terminal_error = Some(match terminal_error.take() {
        Some(primary) => anyhow::anyhow!("{primary:#}; {panic_error:#}"),
        None => panic_error,
    });
}

fn record_terminal_closeout_result(
    terminal_error: &mut Option<anyhow::Error>,
    terminal_closeout: &mut Option<WatchdogCloseoutReceipt>,
    subsystem: &'static str,
    closeout_result: Result<WatchdogCloseoutReceipt>,
) {
    match closeout_result {
        Ok(receipt) => {
            if terminal_closeout.replace(receipt).is_some() {
                *terminal_error = Some(match terminal_error.take() {
                    Some(primary) => anyhow::anyhow!(
                        "{primary:#}; {subsystem} produced duplicate watchdog closeout evidence"
                    ),
                    None => {
                        anyhow::anyhow!("{subsystem} produced duplicate watchdog closeout evidence")
                    }
                });
            }
        }
        Err(closeout_error) => {
            *terminal_error = Some(match terminal_error.take() {
                Some(primary) => anyhow::anyhow!(
                    "{primary:#}; {subsystem} terminal closeout also failed: {closeout_error:#}"
                ),
                None => closeout_error,
            });
        }
    }
}

/// Move a retained hardware owner to Tokio's blocking pool for one synchronous
/// operation, then return the same owner to its lifecycle slot.
/// A worker panic drops the owner on the blocking thread, invoking its
/// fail-safe `Drop`; the join error remains negative watchdog-disarm evidence.
/// Callers that need deadline evidence must timestamp inside the blocking
/// closure: queuing this future is not proof that physical I/O has started.
async fn run_terminal_owner_operation_blocking<G, T, F>(
    owner: &mut G,
    empty_owner: G,
    operation_name: &'static str,
    operation: F,
) -> Result<T>
where
    G: Send + 'static,
    T: Send + 'static,
    F: FnOnce(&mut G) -> Result<T> + Send + 'static,
{
    let retained_owner = std::mem::replace(owner, empty_owner);
    match tokio::task::spawn_blocking(move || {
        let mut retained_owner = retained_owner;
        let result = operation(&mut retained_owner);
        (retained_owner, result)
    })
    .await
    {
        Ok((returned_owner, result)) => {
            *owner = returned_owner;
            result
        }
        Err(error) => Err(anyhow::anyhow!(
            "{operation_name} blocking worker did not return retained hardware ownership: {error}"
        )),
    }
}

struct TimedTerminalOwnerOperation<T> {
    value: T,
    started_at: Instant,
    completed_at: Instant,
}

/// Timestamp a terminal operation at its actual blocking-worker execution
/// boundary. This prevents blocking-pool queue delay from masquerading as a
/// timely physical cutoff.
async fn run_timed_terminal_owner_operation_blocking<G, T, F>(
    owner: &mut G,
    empty_owner: G,
    operation_name: &'static str,
    operation: F,
) -> Result<TimedTerminalOwnerOperation<T>>
where
    G: Send + 'static,
    T: Send + 'static,
    F: FnOnce(&mut G) -> Result<T> + Send + 'static,
{
    run_terminal_owner_operation_blocking(
        owner,
        empty_owner,
        operation_name,
        move |retained_owner| {
            let started_at = Instant::now();
            let result = operation(retained_owner);
            let completed_at = Instant::now();
            result.map(|value| TimedTerminalOwnerOperation {
                value,
                started_at,
                completed_at,
            })
        },
    )
    .await
}

async fn checked_nopic_emergency_safe_off_blocking(
    guard: &mut NoPicPsuGuard,
    operation_name: &'static str,
) -> Result<NoPicEmergencyCutReceipt> {
    run_terminal_owner_operation_blocking(
        guard,
        NoPicPsuGuard::new(),
        operation_name,
        checked_nopic_emergency_safe_off,
    )
    .await
}

async fn set_fan_speed_checked_blocking(
    fan: Arc<dyn FanAccess>,
    pwm: u8,
    operation_name: &'static str,
) -> Result<FanCommandReceipt> {
    tokio::task::spawn_blocking(move || fan.set_speed_checked(pwm))
        .await
        .map_err(|error| {
            anyhow::anyhow!("{operation_name} blocking worker did not complete: {error}")
        })?
        .map_err(anyhow::Error::from)
}

struct Am2PsuRuntimeGuard {
    apw: Am2ApwRuntimeState,
    gate: Option<PsuGpioGate>,
    management_fabric: Option<I2cServiceHandle>,
    management_fabric_transition: Option<TerminalSafeOffTransition>,
    /// Exact BM1362 dsPIC chip-rail disable leg, installed BEFORE
    /// `cold_boot_init` can energize the selected per-chain rail. `None` until
    /// the exact endpoint owner is installed; unsupported BM1398/BM1366 native
    /// identities are refused before this guard or any hardware observer exists.
    ///
    /// Why this exists: dropping PWR_CONTROL alone does NOT cut the per-chain
    /// dsPIC DC-DC rail â€” that is exactly the load-bearing finding the am2
    /// hybrid path encoded as `Am2HomeHardStopGuard::arm_dspic_teardown`
    /// (without it "every standalone attempt needs a fresh AC-cycle" and the
    /// chain stays energized behind PWR_CONTROL). The serial BM1398 / BM1362
    /// direct paths energize the same dsPIC chip rail but had no equivalent
    /// disable leg, so a bare `?` early-return after `cold_boot_init` (e.g.
    /// `init_asic_chain` / `init_bm1398` failure, stratum handshake error) left
    /// the chain rail ENABLED. Disabling the dsPIC voltage FIRST on teardown is
    /// cut-hash-before-noise; it is the same op the clean-stop path issues, so
    /// a redundant disable on clean exit is benign + idempotent.
    /// The only native serial owner is the exact BM1362 Pic0x89 endpoint
    /// session. No legacy BHB56/dsPIC session can inhabit this guard.
    dspic: Option<Pic0x89EndpointSession>,
    /// Monotonic record that this guard accepted a live PWR_CONTROL owner after
    /// the exact never-energized boundary was consumed. Once true, absence of
    /// daemon-owned dsPIC custody says nothing about an inherited per-chain rail
    /// and can never be upgraded to `NeverArmed` safe-off evidence.
    power_boundary_crossed: bool,
    /// Monotonic distinction between an endpoint owner that was never admitted
    /// and one whose owner/evidence later disappeared. `NeverArmed` is truthful
    /// only while the separate PWR_CONTROL boundary also remains uncrossed.
    dspic_ever_armed: bool,
    /// Completed-leg evidence is retained across a failed composite teardown.
    /// This lets a second explicit attempt retry only failed owners without
    /// losing proof from legs that already reached their safe state.
    dspic_safe_off_receipt: Option<Am2DspicSafeOffDisposition>,
    gate_safe_off_receipt: Option<dcentrald_hal::psu_gpio_gate::PsuGpioSafeOffReceipt>,
}

#[derive(Debug)]
struct Am2ApwBypassAdmission {
    _model: String,
    _rail_v: f64,
}

#[derive(Debug)]
enum Am2ApwSafeOffReceipt {
    SmartApw,
    ExplicitBypass(Am2ApwBypassAdmission),
}

enum Am2ApwRuntimeState {
    Unclassified,
    Bypassed(Am2ApwBypassAdmission),
    Pending(Arc<Mutex<Apw121215a>>),
    SafeOff(Am2ApwSafeOffReceipt),
}

fn attempt_am2_apw_safe_off(
    state: &mut Am2ApwRuntimeState,
    attempt_pending: impl FnOnce(&Arc<Mutex<Apw121215a>>) -> Result<()>,
) -> Result<()> {
    let owned = std::mem::replace(state, Am2ApwRuntimeState::Unclassified);
    match owned {
        Am2ApwRuntimeState::Pending(owner) => match attempt_pending(&owner) {
            Ok(()) => {
                *state = Am2ApwRuntimeState::SafeOff(Am2ApwSafeOffReceipt::SmartApw);
                Ok(())
            }
            Err(error) => {
                *state = Am2ApwRuntimeState::Pending(owner);
                Err(error)
            }
        },
        Am2ApwRuntimeState::Bypassed(admission) => {
            *state = Am2ApwRuntimeState::SafeOff(Am2ApwSafeOffReceipt::ExplicitBypass(admission));
            Ok(())
        }
        Am2ApwRuntimeState::SafeOff(receipt) => {
            *state = Am2ApwRuntimeState::SafeOff(receipt);
            Ok(())
        }
        Am2ApwRuntimeState::Unclassified => {
            *state = Am2ApwRuntimeState::Unclassified;
            anyhow::bail!(
                "checked AM2 terminal safe-off lacks smart-APW ownership or explicit bypass admission"
            )
        }
    }
}

#[derive(Debug)]
enum Am2DspicSafeOffDisposition {
    NeverArmed,
    Disabled { count: usize },
}

/// Checked AM2 direct-serial terminal safe-off evidence. Construction is
/// private to the guard and requires every owned dsPIC/APW leg plus verified
/// electrical PWR_CONTROL OFF readback to complete.
#[derive(Debug)]
pub(crate) struct Am2SerialSafeOffReceipt {
    gate: dcentrald_hal::psu_gpio_gate::PsuGpioSafeOffReceipt,
    dspic: Am2DspicSafeOffDisposition,
    apw: Am2ApwSafeOffReceipt,
    management_fabric: TerminalSafeOffTransition,
    teardown_budget: Option<TeardownBudgetView>,
}

impl Am2SerialSafeOffReceipt {
    fn gate(&self) -> &dcentrald_hal::psu_gpio_gate::PsuGpioSafeOffReceipt {
        &self.gate
    }

    fn disabled_dspic_count(&self) -> usize {
        match &self.dspic {
            Am2DspicSafeOffDisposition::NeverArmed => 0,
            Am2DspicSafeOffDisposition::Disabled { count } => *count,
        }
    }

    fn dspic_was_never_armed(&self) -> bool {
        matches!(&self.dspic, Am2DspicSafeOffDisposition::NeverArmed)
    }

    pub(crate) fn management_fabric(&self) -> &TerminalSafeOffTransition {
        &self.management_fabric
    }

    pub(crate) fn same_teardown_budget(&self, authority: &TeardownDisarmAuthority) -> bool {
        self.teardown_budget
            .as_ref()
            .is_some_and(|budget| budget.same_budget(authority))
    }

    pub(crate) fn software_safe_off_completed(&self) -> bool {
        matches!(
            &self.dspic,
            Am2DspicSafeOffDisposition::NeverArmed
                | Am2DspicSafeOffDisposition::Disabled { count: 1.. }
        ) && matches!(
            &self.apw,
            Am2ApwSafeOffReceipt::SmartApw
                | Am2ApwSafeOffReceipt::ExplicitBypass(Am2ApwBypassAdmission { .. })
        )
    }

    pub(crate) fn smart_psu_present(&self) -> bool {
        matches!(&self.apw, Am2ApwSafeOffReceipt::SmartApw)
    }
}

impl Am2PsuRuntimeGuard {
    fn new() -> Self {
        crate::terminal_io_owner::prepare();
        Self::empty()
    }

    fn empty() -> Self {
        Self {
            apw: Am2ApwRuntimeState::Unclassified,
            gate: None,
            management_fabric: None,
            management_fabric_transition: None,
            dspic: None,
            power_boundary_crossed: false,
            dspic_ever_armed: false,
            dspic_safe_off_receipt: None,
            gate_safe_off_receipt: None,
        }
    }

    fn has_terminal_ownership(&self) -> bool {
        !matches!(self.apw, Am2ApwRuntimeState::Unclassified)
            || self.gate.is_some()
            || self.management_fabric.is_some()
            || self.management_fabric_transition.is_some()
            || self.dspic.is_some()
            || self.power_boundary_crossed
            || self.dspic_ever_armed
            || self.dspic_safe_off_receipt.is_some()
            || self.gate_safe_off_receipt.is_some()
    }

    fn set_psu(&mut self, psu: Arc<Mutex<Apw121215a>>) -> Result<()> {
        if !matches!(self.apw, Am2ApwRuntimeState::Unclassified) {
            anyhow::bail!("AM2 APW applicability was already classified");
        }
        self.apw = Am2ApwRuntimeState::Pending(psu);
        Ok(())
    }

    fn admit_apw_bypass(&mut self, model: &str, rail_v: f64) -> Result<()> {
        if !matches!(self.apw, Am2ApwRuntimeState::Unclassified) {
            anyhow::bail!("AM2 APW applicability was already classified");
        }
        if model.trim().is_empty() || !rail_v.is_finite() || rail_v <= 0.0 {
            anyhow::bail!("AM2 APW bypass admission requires a named positive-voltage PSU");
        }
        self.apw = Am2ApwRuntimeState::Bypassed(Am2ApwBypassAdmission {
            _model: model.to_string(),
            _rail_v: rail_v,
        });
        Ok(())
    }

    fn apw_actor_topology(&self) -> Result<Am2ApwActorTopology> {
        match &self.apw {
            Am2ApwRuntimeState::Pending(_) => Ok(Am2ApwActorTopology::SmartPsu),
            Am2ApwRuntimeState::Bypassed(_) => Ok(Am2ApwActorTopology::ExplicitBypass),
            Am2ApwRuntimeState::Unclassified => {
                anyhow::bail!("AM2 runtime actor admission lacks classified APW topology")
            }
            Am2ApwRuntimeState::SafeOff(_) => {
                anyhow::bail!("AM2 runtime actor admission occurred after APW safe-off")
            }
        }
    }

    fn set_gate(&mut self, gate: PsuGpioGate) -> Result<()> {
        anyhow::ensure!(
            self.power_boundary_crossed,
            "AM2 PWR_CONTROL owner cannot be installed before the energizing boundary"
        );
        install_unique_owner(
            &mut self.gate,
            &self.gate_safe_off_receipt,
            gate,
            "AM2 PWR_CONTROL ownership was already established",
        )
    }

    fn enter_power_boundary(&mut self) -> Result<()> {
        anyhow::ensure!(
            !self.power_boundary_crossed,
            "AM2 PWR_CONTROL energizing boundary was already crossed"
        );
        anyhow::ensure!(
            self.gate.is_none() && self.gate_safe_off_receipt.is_none(),
            "AM2 PWR_CONTROL energizing boundary has conflicting retained state"
        );
        self.power_boundary_crossed = true;
        Ok(())
    }

    fn set_management_fabric(&mut self, service: I2cServiceHandle) -> Result<()> {
        install_unique_owner(
            &mut self.management_fabric,
            &self.management_fabric_transition,
            service,
            "AM2 management I2C fabric ownership was already established",
        )
    }

    fn latch_management_fabric_terminally(&mut self) -> Result<()> {
        if self.management_fabric_transition.is_some() {
            return Ok(());
        }
        let service = self
            .management_fabric
            .as_ref()
            .context("required AM2 management I2C fabric owner was absent")?;
        let transition = service.latch_terminal_safe_off();
        if !transition.no_controller_mutation_stage_in_flight() {
            anyhow::bail!(
                "AM2 management I2C terminal barrier observed an in-flight controller mutation"
            );
        }
        self.management_fabric_transition = Some(transition);
        Ok(())
    }

    fn set_exact_dspic(&mut self, session: Pic0x89EndpointSession) -> Result<()> {
        if self.dspic.is_some() {
            anyhow::bail!("AM2 dsPIC ownership was already established");
        }
        self.dspic_ever_armed = true;
        self.dspic_safe_off_receipt = None;
        self.dspic = Some(session);
        Ok(())
    }

    fn exact_dspic_controller_mut(&mut self) -> Result<&mut Pic0x89Service> {
        match self.dspic.as_mut() {
            Some(session) => Ok(session.controller_mut()),
            _ => anyhow::bail!("exact AM2 dsPIC endpoint custody is unavailable"),
        }
    }

    fn exact_dspic_controller(&self) -> Result<Pic0x89Service> {
        match self.dspic.as_ref() {
            Some(session) => Ok(session.controller()),
            _ => anyhow::bail!("exact AM2 dsPIC endpoint custody is unavailable"),
        }
    }

    fn classify_never_armed_dspic_for_safe_off(&mut self) -> bool {
        if self.power_boundary_crossed
            || self.dspic_ever_armed
            || self.dspic.is_some()
            || self.dspic_safe_off_receipt.is_some()
        {
            return false;
        }
        self.dspic_safe_off_receipt = Some(Am2DspicSafeOffDisposition::NeverArmed);
        true
    }

    fn teardown_checked(
        &mut self,
        reason: &'static str,
        require_dspic: bool,
        teardown_budget: Option<&TeardownBudgetView>,
    ) -> Result<Am2SerialSafeOffReceipt> {
        attempt_after_terminal_barrier(
            self,
            Am2PsuRuntimeGuard::latch_management_fabric_terminally,
            |guard| {
                guard.teardown_after_terminal_barrier_checked(
                    reason,
                    require_dspic,
                    teardown_budget,
                )
            },
        )
    }

    fn teardown_after_terminal_barrier_checked(
        &mut self,
        reason: &'static str,
        require_dspic: bool,
        teardown_budget: Option<&TeardownBudgetView>,
    ) -> Result<Am2SerialSafeOffReceipt> {
        debug_assert!(self.management_fabric_transition.is_some());
        let mut errors = Vec::new();
        // Cut hash/power FIRST (cut-hash-before-noise): disable voltage on every
        // armed dsPIC BEFORE touching the APW/PWR_CONTROL, so the per-chain
        // DC-DC rail is brought down instead of left energized behind a dropped
        // PWR_CONTROL. No-op when unarmed â†’ teardown stays byte-for-byte
        // identical to the historical PSU-only behaviour on paths that never
        // energized a dsPIC (NoPic / passthrough).
        if self.classify_never_armed_dspic_for_safe_off() {
            info!(
                reason,
                require_dspic, "AM2 dsPIC safe-off classified as NeverArmed"
            );
        } else if let Err(error) = attempt_retained_safe_off_leg(
            &mut self.dspic,
            &mut self.dspic_safe_off_receipt,
            "required dsPIC safe-direction owner was absent",
            |session| {
                // P1-2: VoltageRail safe_off on Pic0x89 production controller.
                let disable_result = {
                    let pic = session.controller_mut();
                    if let Err(error) = pic.send_heartbeat() {
                        warn!(reason, %error, "exact AM2 dsPIC heartbeat before disable failed");
                    }
                    let mut rail =
                        Pic0x89VoltageRail::new(pic, dspic_fw86_trust_degraded_override_enabled());
                    safe_off_voltage_rail(&mut rail)
                };
                disable_result
                    .map_err(|e| {
                        anyhow::anyhow!("exact AM2 dsPIC VoltageRail safe_off failed: {e}")
                    })
                    .context("exact AM2 dsPIC disable failed")?;
                info!(
                    reason,
                    "exact AM2 dsPIC voltage disabled during teardown (VoltageRail)"
                );
                Ok(Am2DspicSafeOffDisposition::Disabled { count: 1 })
            },
        ) {
            errors.push(error.to_string());
        }
        if self.dspic_safe_off_receipt.is_none() && errors.is_empty() {
            errors.push(
                "AM2 dsPIC was previously armed but neither its owner nor safe-off evidence remains"
                    .to_string(),
            );
        }

        if let Err(error) = attempt_am2_apw_safe_off(&mut self.apw, |psu_owner| {
            // Poison-tolerant lock: this is the cut-hash-before-noise teardown
            // path (called from Drop too). If a PSU heartbeat-thread panic
            // poisoned this mutex, `.unwrap()` would panic HERE and skip the
            // watchdog-off + voltage-min â€” leaving the rail pinned at the mining
            // setpoint behind only the ~30s hardware watchdog (and a panic inside
            // Drop during unwind aborts). Recover the guard instead so the
            // safety teardown actually runs. Matches the proven i2c.rs idiom.
            let mut psu = psu_owner.lock().unwrap_or_else(|e| e.into_inner());
            Ok(psu.safe_shutdown_to_min()?)
        }) {
            warn!(reason, %error, "BM1362 direct path PSU safe-direction shutdown failed");
            errors.push(format!("APW safe-direction shutdown failed: {error}"));
        }

        if let Err(error) = attempt_retained_safe_off_leg(
            &mut self.gate,
            &mut self.gate_safe_off_receipt,
            "required PWR_CONTROL safe-off owner was absent",
            |gate| {
                let gpio = gate.gpio();
                match gate.force_safe_off_verified() {
                    Ok(receipt) => Ok(receipt),
                    Err(e) => {
                        warn!(reason, gpio, error = %e, "BM1362 direct path PWR_CONTROL terminal safe-off failed");
                        Err(anyhow::anyhow!(
                            "PWR_CONTROL gpio{gpio} terminal safe-off failed: {e}"
                        ))
                    }
                }
            },
        ) {
            errors.push(error.to_string());
        }

        if !errors.is_empty() {
            anyhow::bail!(
                "AM2 direct-serial checked safe-off incomplete during {reason}: {}",
                errors.join("; ")
            );
        }
        let apw = match std::mem::replace(&mut self.apw, Am2ApwRuntimeState::Unclassified) {
            Am2ApwRuntimeState::SafeOff(receipt) => receipt,
            state => {
                self.apw = state;
                anyhow::bail!("AM2 APW safe-off evidence disappeared before receipt minting")
            }
        };
        self.management_fabric.take();
        let dspic = self
            .dspic_safe_off_receipt
            .take()
            .expect("absence recorded above");
        self.dspic_ever_armed = false;
        Ok(Am2SerialSafeOffReceipt {
            gate: self
                .gate_safe_off_receipt
                .take()
                .expect("absence recorded above"),
            dspic,
            apw,
            management_fabric: self
                .management_fabric_transition
                .take()
                .expect("absence recorded above"),
            teardown_budget: teardown_budget.cloned(),
        })
    }

    fn teardown_checked_retrying(
        &mut self,
        reason: &'static str,
        require_dspic: bool,
        teardown_budget: Option<TeardownBudgetView>,
    ) -> Result<Am2SerialSafeOffReceipt> {
        let mut failures = Vec::new();
        for attempt in 1..=AM2_BM1362_TERMINAL_SAFE_OFF_ATTEMPTS {
            match self.teardown_checked(reason, require_dspic, teardown_budget.as_ref()) {
                Ok(receipt) => return Ok(receipt),
                Err(error) => {
                    warn!(
                        reason,
                        attempt,
                        max_attempts = AM2_BM1362_TERMINAL_SAFE_OFF_ATTEMPTS,
                        %error,
                        "AM2 checked terminal safe-off attempt incomplete; retained failed owners will be retried"
                    );
                    failures.push(format!("attempt {attempt}: {error:#}"));
                }
            }
        }
        anyhow::bail!(
            "AM2 checked terminal safe-off exhausted {} attempts during {reason}: {}",
            AM2_BM1362_TERMINAL_SAFE_OFF_ATTEMPTS,
            failures.join("; ")
        )
    }

    fn teardown(&mut self, reason: &'static str) {
        if let Err(error) = self.teardown_checked(reason, false, None) {
            warn!(reason, %error, "serial AM2 best-effort teardown was incomplete");
        }
    }

    /// Immediate first-stage emergency cutoff. This borrows rather than
    /// consumes the retained GPIO owner so ordered teardown can later stop
    /// actors, close every mutation domain, disable dsPIC/APW, and repeat the
    /// checked OFF transition as final stable evidence.
    fn emergency_cut_gpio_verified(&mut self, reason: &'static str) -> Result<()> {
        let gate = self
            .gate
            .as_mut()
            .context("AM2 emergency cutoff lost retained PWR_CONTROL ownership")?;
        let receipt = gate
            .force_safe_off_verified()
            .context("AM2 emergency PWR_CONTROL cutoff failed")?;
        warn!(
            reason,
            gpio = receipt.gpio(),
            off_level = receipt.off_level(),
            "AM2 emergency first-stage GPIO cutoff completed before teardown fences"
        );
        Ok(())
    }

    /// Reuse the checked dsPIC leg without touching an APW mutex or the GPIO
    /// owner that a detached feeder may still reference. Temporarily removing
    /// those two owners forces aggregate receipt construction to fail, while
    /// the already-terminal management fabric still permits the load-bearing
    /// dsPIC disable and retains its positive evidence.
    fn hard_stop_dspic_after_terminal_barrier(&mut self, reason: &'static str) {
        debug_assert!(self.management_fabric_transition.is_some());
        let dspic_cut_required = self.dspic_ever_armed || self.dspic.is_some();
        if !dspic_cut_required || self.dspic_safe_off_receipt.is_some() {
            return;
        }

        for attempt in 1..=AM2_BM1362_TERMINAL_SAFE_OFF_ATTEMPTS {
            let retained_apw = std::mem::replace(&mut self.apw, Am2ApwRuntimeState::Unclassified);
            let retained_gate = self.gate.take();
            let retained_gate_receipt = self.gate_safe_off_receipt.take();

            // Failure is expected because APW and GPIO classification are
            // deliberately hidden. Only the retained dsPIC leg's state change
            // is consumed by this narrow abnormal-closeout operation.
            let _ = self.teardown_after_terminal_barrier_checked(reason, true, None);

            self.apw = retained_apw;
            self.gate = retained_gate;
            self.gate_safe_off_receipt = retained_gate_receipt;
            if matches!(
                self.dspic_safe_off_receipt.as_ref(),
                Some(Am2DspicSafeOffDisposition::Disabled { .. })
            ) {
                warn!(
                    reason,
                    attempt,
                    "serial AM2 out-of-band dsPIC hard stop completed after terminal fabric latch"
                );
                return;
            }
        }

        warn!(
            reason,
            attempts = AM2_BM1362_TERMINAL_SAFE_OFF_ATTEMPTS,
            "serial AM2 out-of-band dsPIC hard stop exhausted retries; PWR_CONTROL fallback will still be asserted"
        );
    }

    /// Immediate transport-independent fallback for a feeder that cannot be
    /// proven quiescent. The I2C fabric is terminally latched first, draining
    /// in-flight controller mutation and rejecting later ordinary heartbeats;
    /// the retained dsPIC owner can then attempt its load-bearing disable. The
    /// potentially feeder-owned PSU mutex is never entered. PWR_CONTROL remains
    /// an independent transport-level fallback.
    fn hard_stop_out_of_band(&mut self, reason: &'static str) {
        // Remove terminal ownership from `self` before any fallible operation.
        // The temporary is ManuallyDrop so an unexpected panic cannot run this
        // guard's Drop and recursively enqueue the same hard stop forever.
        let mut owned = std::mem::ManuallyDrop::new(std::mem::replace(self, Self::empty()));
        Self::execute_manually_retained_hard_stop(&mut owned, reason);
    }

    /// Execute one terminal hard-stop attempt without ever exposing a live
    /// guard to implicit Drop. If the operation panics, the ManuallyDrop owner
    /// intentionally leaks: fail-closed resource leakage is preferable to
    /// recursively redispatching an incomplete electrical shutdown forever.
    fn execute_manually_retained_hard_stop(
        owned: &mut std::mem::ManuallyDrop<Self>,
        reason: &'static str,
    ) {
        owned.hard_stop_out_of_band_owned(reason);
        debug_assert!(!owned.has_terminal_ownership());
        // SAFETY: `hard_stop_out_of_band_owned` retires every field recognized
        // by `has_terminal_ownership` on all normal paths. Its destructor can
        // therefore run exactly once without redispatching another hard stop.
        unsafe { std::mem::ManuallyDrop::drop(owned) };
    }

    fn hard_stop_out_of_band_owned(&mut self, reason: &'static str) {
        if let Some(service) = self.management_fabric.as_ref() {
            let transition = service.latch_terminal_safe_off();
            if !transition.no_controller_mutation_stage_in_flight() {
                warn!(
                    reason,
                    generation = transition.generation(),
                    "serial AM2 out-of-band hard stop terminally latched I2C with a controller mutation still in flight"
                );
            }
            self.management_fabric_transition = Some(transition);
        }
        if self.management_fabric_transition.is_some() {
            self.hard_stop_dspic_after_terminal_barrier(reason);
        }
        if let Some(mut gate) = self.gate.take() {
            let gpio = gate.gpio();
            if let Err(e) = gate.force_safe_off_verified() {
                warn!(
                    reason,
                    gpio,
                    error = %e,
                    "serial AM2 out-of-band PWR_CONTROL hard stop failed"
                );
            } else {
                warn!(
                    reason,
                    gpio, "serial AM2 PWR_CONTROL hard stop asserted without entering PSU mutex"
                );
            }
        } else if let Some(receipt) = self.gate_safe_off_receipt.as_ref() {
            warn!(
                reason,
                gpio = receipt.gpio(),
                "serial AM2 out-of-band hard stop retained prior verified PWR_CONTROL OFF evidence"
            );
        } else {
            warn!(
                reason,
                "serial AM2 out-of-band hard stop had no owned PWR_CONTROL gate; relying on cancelled heartbeat watchdogs"
            );
        }

        // Dropping these owners is non-blocking. A detached feeder retains its
        // own Arc until it returns; no destructor here attempts to reclaim it.
        self.apw = Am2ApwRuntimeState::Unclassified;
        self.dspic.take();
        self.dspic_safe_off_receipt.take();
        self.gate_safe_off_receipt.take();
        self.management_fabric.take();
        self.management_fabric_transition.take();
        self.power_boundary_crossed = false;
        self.dspic_ever_armed = false;
    }
}

impl Drop for Am2PsuRuntimeGuard {
    fn drop(&mut self) {
        if !self.has_terminal_ownership() {
            return;
        }
        // Drop can run on an async `?` path while a feeder is wedged. Transfer
        // every move-only owner to the process-wide blocking lane: the Tokio
        // worker neither performs sysfs/controller I/O nor waits for it.
        // Explicit graceful teardown is still awaited separately after
        // `RuntimeThreadGuard::stop_and_join` proves every feeder quiescent.
        // Wrap the transferred guard before dispatch. If both the process-wide
        // lane and its fallback thread reject this closure, dropping the job
        // drops only ManuallyDrop and cannot synchronously re-enter this Drop.
        let mut owned = std::mem::ManuallyDrop::new(std::mem::replace(self, Self::empty()));
        crate::terminal_io_owner::dispatch("am2-serial-drop-hard-stop", move || {
            Self::execute_manually_retained_hard_stop(&mut owned, "drop");
        });
    }
}

impl Am2FirstStagePowerCut for Am2PsuRuntimeGuard {
    fn attempt_first_stage_power_cut(&mut self, reason: &'static str) -> Result<()> {
        self.emergency_cut_gpio_verified(reason)
    }
}

/// Select the fast baud rate based on platform.
/// Zynq NS16550A: 3,125,000 (custom BOTHER divisor from 200 MHz clock)
/// Amlogic meson_uart: 3,000,000 (standard B3000000 from 24 MHz crystal)
/// Fast baud rate for BM136x ASIC communication.
/// BM1368 FAST_UART register configures the ASIC's UART baud from 25 MHz crystal.
/// Zynq NS16550A: exact 3,125,000 via BOTHER (200 MHz PL clock / 64).
/// Amlogic meson_uart: CANNOT do 3,125,000 (rounds to 4M!). Must use B3000000.
/// Bosminer logs "3125000" but the kernel rounds it to the nearest standard rate.
/// The ASIC's FAST_UART value 0x00003001 = 3,125,000 from crystal, but the 4%
/// mismatch to host 3M is within UART tolerance for short bursts.
fn fast_baud() -> u32 {
    if std::path::Path::new("/dev/uio0").exists() {
        dcentrald_hal::serial::BAUD_3125000 // Zynq: exact 3,125,000 via BOTHER
    } else {
        dcentrald_hal::serial::BAUD_3000000 // Amlogic: B3000000 (closest to 3.125M)
    }
}

/// Non-destructive post-ENABLE chain UART rail-engagement probe (BM1362 path).
///
/// APW121215a (FW `0x71`) has NO voltage/current/power feedback (`psu.rs:493`
/// `has_voltage_feedback() == false`), and dsPIC fw=0x86 in bare protocol
/// returns only the FW echo byte for any read â€” including GET_VOLTAGE
/// (0x3B). The ENABLE_VOLTAGE bare ACK only confirms protocol-level
/// acceptance, NOT actual rail engagement. The only software signal that
/// the chain DC-DC has actually engaged 13.7 V is whether the BM1362 ASICs
/// drive any byte onto the chain UART RX line.
///
/// This probe opens the chain UART via `DevmemUart`, sleeps 200 ms for the
/// DC-DC to ramp, drains RX for up to 500 ms, and logs the byte count +
/// first-up-to-16-byte preview.
///
/// - `rx_bytes_pre_init == 0`: chain rail is likely 0 V â€” dsPIC ENABLE
///   didn't actually engage the DC-DC even though the IÂ²C ACK landed.
/// - `rx_bytes_pre_init > 0`:  chain is electrically alive â€” BM1362 init
///   may need adjustment but the rail is up.
///
/// Best-effort at the transport level: ordinary open/read failure is logged.
/// The only production caller is the restricted AM2 observation facade, so
/// this preserve-state mapping and the later formal backend remain inside one
/// logical execution fence even though the HAL intentionally uses two opens.
fn post_enable_chain_uart_probe(serial_device: &str, pic_addr: u8) {
    use dcentrald_hal::serial::DevmemUart;

    // Sleep 200 ms after ENABLE so the DC-DC has time to ramp.
    std::thread::sleep(Duration::from_millis(200));

    let uart = match DevmemUart::open_preserve_state(serial_device, 115_200) {
        Ok(u) => u,
        Err(e) => {
            warn!(
                error = %e,
                serial_device,
                "Post-ENABLE chain UART probe: DevmemUart::open failed â€” \
                 skipping rail-engagement diagnostic (Phase 2 init will retry)"
            );
            return;
        }
    };

    let mut buf = [0u8; 256];
    let total = uart.read_bytes_timeout(&mut buf, 500);

    let preview_len = total.min(16);
    let preview = &buf[..preview_len];

    tracing::info!(
        serial_device,
        pic_addr = format_args!("0x{:02X}", pic_addr),
        rx_bytes_pre_init = total,
        rx_preview = format!("{:02X?}", preview),
        "Post-ENABLE chain UART rail-engagement probe (rx_bytes>0 implies rail is electrically alive)"
    );

    if total == 0 {
        warn!(
            serial_device,
            "Post-ENABLE chain UART probe: 0 bytes in 500 ms â€” chain rail is \
             likely 0 V (dsPIC ENABLE didn't actually engage DC-DC). Hardware \
             multimeter on the chain rail is the next step."
        );
    } else {
        info!(
            serial_device,
            rx_bytes_pre_init = total,
            "Post-ENABLE chain UART probe: chain is electrically alive â€” \
             BM1362 init may still need adjustment but the rail is up."
        );
    }

    // `uart` drops here, releasing the preserve-state mmap. The restricted
    // session later opens its formal backend without leaving the same fence.
}

/// Legacy count-inference policy retained only as a regression reference.
/// Production uses `resolve_native_serial_identity_and_geometry`.
#[cfg(test)]
fn serial_chip_id(model_hint: Option<&str>, chip_count: u8) -> u16 {
    if let Some(chip_id) = model_hint.and_then(model::model_chip_id) {
        return chip_id;
    }

    match chip_count {
        114 => 0x1398,
        110 | 77 => 0x1366,
        65 => 0x1370,
        108 => 0x1368,
        _ => 0x1362,
    }
}

/// True when `chip_id` belongs to a NoPic (TAS5782M / LDO) voltage-control
/// family â€” the S21-class chips that have ONLY ever shipped without a PIC /
/// dsPIC voltage controller. BM1368 (S21/T21) and BM1370 (S21 Pro / S21+ /
/// S21 XP) are the two production NoPic SHA-256 dies; BM1373 (S23) is the
/// pre-hardware NoPic continuation. Everything else (BM1387/BM1397/BM1398/
/// BM1362/BM1366) drives voltage through a PIC16 or dsPIC.
///
/// Source: `dcentrald-asic::drivers::PicType` profile table + `model.rs`
/// `pic_type_hint` (S21/T21/S21 Pro/+/XP all `ModelPicTypeHint::NoPic`).
#[cfg(test)]
fn serial_chip_id_is_nopic_family(chip_id: u16) -> bool {
    matches!(chip_id, 0x1368 | 0x1370 | 0x1373)
}

/// Legacy count-inference discriminator retained only to pin historical
/// regression behavior. It is not production authority; native serial mining
/// requires catalog identity through `resolve_native_serial_identity_and_geometry`.
///
/// Carry-forward **F-E3** (Preparedness-Sweep-v2 HIGH SAFETY): BM1370 SKUs
/// (S21 Pro / S21+ / S21 XP) must NOT silently route through the BM1368 (S21)
/// driver â€” and must NEVER fall through to the BM1362 catch-all (a PIC-family
/// driver that would try dsPIC I2C voltage control on a NoPic chain). A wrong
/// driver on a live chain is worse than a clean stop, so an undisambiguable
/// NoPic S21-family unit is **refused**, not guessed.
///
/// Discriminator evidence (corpus, not assumption): stock firmware reads the
/// CHIP_ID from register `0x00` â€” BM1370 returns `0x13700000`, BM1368 returns
/// `0x13680000` (ESP-Miner `bm1370.c` / `bm1368.c`,
///
/// Â§8.1/Â§9.1; :26`). When
/// the operator pins the model string (`s21pro`/`s21xp`/`s21+`/`s21plus` â†’
/// family `bm1370`) that register-truth is honoured directly. The hazard this
/// guard closes is the **count-only** inference when no model string is set:
/// a BM1370 chassis enumerating any count other than the canonical 65 would
/// otherwise be silently downgraded to BM1368 (108) or BM1362 (any other
/// count).
///
/// Rules:
/// - Explicit model chip-id is always trusted (operator-pinned ground truth).
/// - A `nopic`-declared unit must resolve to a NoPic family; if the count-only
///   inference produces a PIC family (BM1362/BM1398/BM1366) the resolution is
///   ambiguous â†’ refuse with an actionable error (operator pins
///   `mining.model`).
/// - Proven count anchors are preserved exactly (114â†’1398, 110/77â†’1366,
///   65â†’1370, 108â†’1368, and the am2/XIL BM1362 default for PIC units).
#[cfg(test)]
fn resolve_serial_chip_id(model_hint: Option<&str>, chip_count: u8, nopic: bool) -> Result<u16> {
    let chip_id = serial_chip_id(model_hint, chip_count);
    let model_pinned = model_hint.and_then(model::model_chip_id).is_some();

    // F-E3 fail-safe: a NoPic chassis (S21 family) that the count-only
    // heuristic would map onto a PIC-family driver is genuinely ambiguous â€”
    // most dangerously a BM1370 SKU at a non-65 count falling through to the
    // BM1362 (PIC/dsPIC) catch-all. Refuse rather than drive a NoPic chain
    // with a PIC-family driver. Operator resolves by pinning `mining.model`.
    if nopic && !model_pinned && !serial_chip_id_is_nopic_family(chip_id) {
        anyhow::bail!(
            "Refusing to dispatch a NoPic S21-class chain to the PIC-family \
             driver inferred from chip_count={chip_count} (chip_id=0x{chip_id:04X}). \
             A BM1370 (S21 Pro / S21+ / S21 XP) or BM1368 (S21/T21) unit cannot \
             be safely disambiguated by chip count alone here â€” set \
             `mining.model` (e.g. s21pro / s21 / s21xp) so the BM1370-vs-BM1368 \
             driver split is explicit. A wrong driver on a live chain is worse \
             than a clean stop (carry-forward F-E3)."
        );
    }

    Ok(chip_id)
}

fn hardware_difficulty_for_serial_family(chip_id: u16) -> Result<u64> {
    MinerProfile::for_chip(chip_id)
        .map(|profile| profile.hardware_difficulty as u64)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "native serial chip 0x{chip_id:04X} has no MinerProfile difficulty policy"
            )
        })
}

fn validate_serial_model_voltage_identity(
    model_name: &str,
    chip_id: u16,
    pic_hint: Option<model::ModelPicTypeHint>,
) -> Result<()> {
    let definitively_nopic_family = matches!(chip_id, 0x1368 | 0x1370 | 0x1373);
    let controller_only_family =
        matches!(chip_id, 0x1362 | 0x1387 | 0x1391 | 0x1396 | 0x1397 | 0x1398);
    match pic_hint {
        Some(model::ModelPicTypeHint::NoPic) if controller_only_family => anyhow::bail!(
            "native serial model `{model_name}` declares NoPic but chip 0x{chip_id:04X} is a controller-only family"
        ),
        Some(model::ModelPicTypeHint::Pic16 | model::ModelPicTypeHint::DsPic)
            if definitively_nopic_family =>
        {
            anyhow::bail!(
                "native serial model `{model_name}` declares a PIC/dsPIC but chip 0x{chip_id:04X} is a definitive NoPic family"
            )
        }
        None if definitively_nopic_family => anyhow::bail!(
            "native serial model `{model_name}` has definitive NoPic chip 0x{chip_id:04X} but no voltage-architecture declaration"
        ),
        _ => Ok(()),
    }
}

fn resolve_native_serial_identity_and_geometry(
    model_hint: Option<&str>,
    configured_chip_count: Option<u8>,
) -> Result<(u16, u8)> {
    let model_name = model_hint
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .context(
            "native serial mining requires an explicit recognized mining.model; chip count is geometry, not ASIC identity",
        )?;
    let chip_id = model::model_chip_id(model_name).ok_or_else(|| {
        anyhow::anyhow!(
            "native serial mining model `{model_name}` is unknown or has no authoritative chip identity"
        )
    })?;
    if !matches!(chip_id, 0x1362 | 0x1366 | 0x1368 | 0x1370 | 0x1398) {
        anyhow::bail!(
            "native serial mining model `{model_name}` resolves to unsupported chip 0x{chip_id:04X}; no serial dispatcher exists for this family"
        );
    }
    validate_serial_model_voltage_identity(
        model_name,
        chip_id,
        model::model_pic_type_hint(model_name),
    )?;
    let chip_count = configured_chip_count
        .or_else(|| model::model_chip_count_hint(model_name))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "native serial mining model `{model_name}` has no authoritative per-chain geometry; set mining.serial_chip_count explicitly"
            )
        })?;
    if chip_count == 0 {
        anyhow::bail!("native serial mining chip count must be at least 1");
    }
    Ok((chip_id, chip_count))
}

/// Check if we're on a NoPic miner (no PIC voltage controller â€” voltage is
/// either kernel-managed via TAS5782M DTB or pre-set by hardware).
///
/// ## Declarative signals (always consulted, in order)
/// 1. `model.pic_type_hint == NoPic` â€” per the static catalog
///    ([`crate::model::model_pic_type_hint`]). Covers S21/T21/S21 Pro/+/XP,
///    S19K Pro NoPic, S19 XP, S19J XP â€” every model whose BraiinsOS+
///    catalog only ships NoPic variants.
/// 2. Fallback chip-id whitelist for chassis where the model string isn't
///    set: `0x1368` (BM1368, S21 family) and `0x1370` (BM1370, S21 Pro
///    family) â€” these chips have only ever shipped NoPic. Note that
///    `0x1366` (BM1366) is deliberately NOT in this list: the corpus only
///    proves S19k Pro NoPic, not all BM1366 boards, so a hardcoded chip-id
///    whitelist would mis-classify PIC-bearing BM1366 variants. EEPROM
///    authority (below) is the correct mechanism for that case.
///
/// ## EEPROM authority (gated, default-OFF â€”  Phase 2B)
/// When `DCENT_AM2_EEPROM_PIC_DETECT=1` the declarative result above is an
/// INPUT to the EEPROM-authoritative resolver
/// ([`crate::runtime::hardware_info::resolve_is_nopic_from_eeprom`], built
/// on the single pure decision [`crate::runtime::hardware_info::resolve_pic_type`]):
/// a chain whose EEPROM preamble classifies to a clear NoPic SKU
/// (BHB56902 / `0x05 0x11`) forces `true` regardless of carrier/chip-id; a
/// clear PIC/dsPIC preamble forces `false`; any weak/absent signal
/// (malformed/timeout/unpopulated/read-error/ambiguous) falls back to the
/// declarative result. The authority NEVER moves the answer toward "PIC"
/// on a weak signal â€” it fails toward the existing behavior. This is the
/// real runtime detection the old doc-comment falsely promised.
///
/// **No-regression guarantee:** with the gate OFF (the default) the EEPROM
/// is never read here and the result is the declarative value, byte-identical
/// to today. EEPROM reads (0x50-0x57) are READ-allowed by the HAL denylist;
/// this path never issues a write, and never SET_VOLTAGE on a NoPic board.
fn is_nopic(config: &DcentraldConfig) -> bool {
    let declarative_nopic = if let Some(model) = config.mining.model.as_deref() {
        matches!(
            model::model_pic_type_hint(model),
            Some(model::ModelPicTypeHint::NoPic)
        ) || matches!(config.mining.model_chip_id(), Some(0x1368 | 0x1370))
    } else {
        matches!(config.mining.model_chip_id(), Some(0x1368 | 0x1370))
    };

    // Chain-slot count for the gated EEPROM probe: the profile's chain
    // count when the chip-id is known, else the universal 3-chain default.
    let chain_slots = config
        .mining
        .model_chip_id()
        .and_then(MinerProfile::for_chip)
        .map(|p| p.chain_count as usize)
        .unwrap_or(3);

    crate::runtime::hardware_info::resolve_is_nopic_from_eeprom(declarative_nopic, chain_slots)
}

/// Legacy S19j Pro PIC I2C address fallback (7-bit).
///
/// Native BM1362 mode resolves the active PIC from the serial slot instead of
/// using this globally, because am2 boards expose one voltage controller per
/// hashboard at 0x20/0x21/0x22.
const S19J_PIC_ADDR_7BIT: u8 = 0x21;

/// S19 Pro dsPIC I2C addresses (7-bit).
const S19_DSPIC_ADDRS: [u8; 3] = [0x20, 0x21, 0x22];

/// PIC heartbeat interval â€” 1 s.
///
/// See [`dcentrald_silicon_profiles::pic_heartbeat::pic_heartbeat_config`]
/// for the canonical per-`(Platform, PicFw)` matrix. Serial-mining is
/// am2-s17 / am3-aml depending on detected SoC â€” both rows pin 1 s
/// (am3-aml is no-op via `cfg.nopic`).
const PIC_HEARTBEAT_INTERVAL_MS: u64 = 1000;
const BM13XX_CMD_RESP_BODY_LEN: usize = 9;

/// BM1362: job_id increments by 24, 9-byte response body.
const BM1362_JOB_ID_INC: u8 = 24;
/// BM1366: job_id increments by 8, 9-byte response body.
const BM1366_JOB_ID_INC: u8 = 8;
/// BM1398: job_id increments by 4 (lower 2 bits = midstate index), 7-byte response body.
const BM1398_JOB_ID_INC: u8 = 4;
const JOB_ID_MASK: u8 = 0x7F;

const BM1362_RESP_BODY_LEN: usize = 9;
const BM1398_RESP_BODY_LEN: usize = 7;
const SERIAL_VERSION_ROLLING_FIELD_MASK: u32 = 0x1FFF_E000;

// ---------------------------------------------------------------------------
// CRC-5 for PIC I2C commands (same as ASIC protocol CRC5)
// ---------------------------------------------------------------------------

/// Build a 6-byte PIC command: [55 AA 04 cmd arg checksum]
///
/// S19j Pro PIC (v0x86 stock Bitmain) uses a simple byte-sum checksum,
/// NOT the CRC5 used by ASIC commands. Confirmed by matching bosminer strace:
///   [55 AA 04 17 00 1B] -> checksum = 0x04 + 0x17 + 0x00 = 0x1B
///   [55 AA 04 15 01 1A] -> checksum = 0x04 + 0x15 + 0x01 = 0x1A
///   [55 AA 04 16 00 1A] -> checksum = 0x04 + 0x16 + 0x00 = 0x1A
fn pic_cmd(cmd: u8, arg: u8) -> [u8; 6] {
    let checksum = 0x04u8.wrapping_add(cmd).wrapping_add(arg);
    [0x55, 0xAA, 0x04, cmd, arg, checksum]
}

/// Build a 7-byte PIC ENABLE/DISABLE_VOLTAGE command in the VNish-RE'd form:
///   `[55 AA 05 15 ARG 0x00 SUM]`
///
/// Source: VNish/bosminer cgminer disasm (RE corpus 2026-04-25, 22 firmwares
/// cross-validated). For fw=0x86 (S19j stock Bitmain) and fw=0x89 (S19j Pro am2)
/// the ENABLE/DISABLE frames have a 2-byte payload `[ARG, 0x00]`, NOT the
/// 1-byte `[ARG]` form previously used.
///
/// Verified frames:
///   ENABLE  : [55 AA 05 15 01 00 1B]  SUM = (0x05+0x15+0x01+0x00)&0xFF = 0x1B
///   DISABLE : [55 AA 05 15 00 00 1A]  SUM = (0x05+0x15+0x00+0x00)&0xFF = 0x1A
///
/// Mirrors `dcentrald_asic::dspic::dspic_enable_voltage_frame` /
/// `dspic_disable_voltage_frame` with `EnableFrameEncoding::VnishPadded`.
#[allow(dead_code)]
fn pic_enable_cmd_vnish(arg: u8) -> [u8; 7] {
    let checksum = 0x05u8
        .wrapping_add(0x15)
        .wrapping_add(arg)
        .wrapping_add(0x00);
    [0x55, 0xAA, 0x05, 0x15, arg, 0x00, checksum]
}

// ---------------------------------------------------------------------------
// BM1362 ASIC init constants (from bm1362.rs + Mujina PROTOCOL.md)
// ---------------------------------------------------------------------------

const VERSION_MASK_VALUE: u32 = 0x9000_FFFF;
const INIT_CONTROL_BCAST: u32 = 0x0000_0000;
const MISC_CONTROL_INIT: u32 = 0x00C1_00B0;
const INIT_CONTROL_PER_CHIP: u32 = 0x0200_0000;
const CORE_REG_HASH_CLK: u32 = 0x8000_8540;
const CORE_REG_CLK_DELAY: u32 = 0x8000_8008; // BM1362-specific
const CORE_REG_UNKNOWN: u32 = 0x8000_82AA;
const IO_DRIVER_NORMAL: u32 = 0x0001_1111;
const ANALOG_MUX_VALUE: u32 = 0x0000_0003;
const FAST_UART_VALUE: u32 = 0x0000_3011;
// R6-7 keeps BM1362 UART_RELAY writes lab-gated until exact 0x2C/0x34
// control semantics are live-captured.
const BM1362_UART_RELAY_REG: u8 = 0x2C;
const BM1362_UART_RELAY_ENABLE: u32 = 0x007C_0003;
const BM1362_UART_RELAY_REG_ALT: u8 = 0x34;
const BM1362_UART_RELAY_ENABLE_ALT: u32 = 0x000F_0003;
const TICKET_MASK_256: u32 = 0x0000_00FF;
const NONCE_RANGE_126: u32 = 0x0000_1381; // BM1362: 126 chips (S19j Pro)
const NONCE_RANGE_108: u32 = 0x0000_15A4; // BM1368: 108 chips (S21 stock default)
const BM1362_PLL0_DIVIDER_REG: u8 = 0x70;
const BM1362_TRACE_PLL0_DIVIDER: u32 = 0x0000_0000;
const BM1362_TRACE_PLL_PARAM_525: u32 = 0x40A8_0265;

/// Serial dispatch pacing during init â€” mirrors the traced/order-sensitive am2 path.
const SERIAL_PACE_MIN_MS: u64 = 20;

// ---------------------------------------------------------------------------
// BM1368 ASIC init constants (from bm1368.rs + ESP-Miner, verified on S21)
// Register values differ from BM1362 â€” using BM1362 values = 0 nonces.
// ---------------------------------------------------------------------------
const BM1368_REG_A8_BCAST: u32 = 0x0007_0000;
const BM1368_MISC_CTRL_BCAST: u32 = 0xFF0F_C100;
const BM1368_CORE_REG_1: u32 = 0x8000_8B00;
const BM1368_CORE_REG_2: u32 = 0x8000_8018;
const BM1368_CORE_REG_3: u32 = 0x8000_82AA;
const BM1368_TICKET_MASK: u32 = BM1368_FIXTURE_TICKET_MASK;
const BM1368_IO_DRIVER: u32 = 0x0211_1111;
const BM1368_REG_A8_PER_CHIP: u32 = 0x0007_01F0;
const BM1368_MISC_CTRL_PER_CHIP: u32 = 0xF000_C100;
const BM1368_FAST_UART: u32 = 0x0000_3001; // 3.125M (BM1366+ value). Host B3000000 within tolerance.
                                           // ---------------------------------------------------------------------------
                                           // BM1366 ASIC init constants (from bm1366.rs + ESP-Miner)
                                           // ---------------------------------------------------------------------------
const BM1366_VERSION_MASK_VALUE: u32 = 0x9000_FFFF;
const BM1366_REG_A8_BCAST: u32 = 0x0007_0000;
const BM1366_REG_A8_PER_CHIP: u32 = 0x0007_01F0;
const BM1366_MISC_CTRL_BCAST: u32 = 0xFF0F_C100;
const BM1366_MISC_CTRL_PER_CHIP: u32 = 0xF000_C100;
const BM1366_CORE_REG_HASH_CLOCK: u32 = 0x8000_8540;
const BM1366_CORE_REG_CLOCK_DELAY: u32 = 0x8000_8020;
const BM1366_CORE_REG_UNKNOWN: u32 = 0x8000_82AA;
const BM1366_ANALOG_MUX: u32 = 0x0000_0003;
const BM1366_IO_DRIVER: u32 = 0x0211_1111;
const BM1366_UART_RELAY: u32 = 0x007C_0003;
const BM1366_HASH_COUNTING_S19XP: u32 = 0x0000_151C;
const BM1366_HASH_COUNTING_S19K: u32 = 0x0000_115A;
const BM1366_TICKET_MASK: u32 = 0x0000_00FF;

// ---------------------------------------------------------------------------
// BM1370 ASIC init constants (from bm1370.rs + ESP-Miner)
// ---------------------------------------------------------------------------
const BM1370_VERSION_MASK_VALUE: u32 = 0x9000_FFFF;
const BM1370_REG_A8_BCAST: u32 = 0x0007_0000;
const BM1370_REG_A8_PER_CHIP: u32 = 0x0007_01F0;
const BM1370_MISC_CTRL_BCAST: u32 = 0xF000_C100;
const BM1370_MISC_CTRL_PER_CHIP: u32 = 0xF000_C100;
const BM1370_CORE_REG_1: u32 = 0x8000_8B00;
const BM1370_CORE_REG_2: u32 = 0x8000_800C;
const BM1370_CORE_REG_3: u32 = 0x8000_82AA;
const BM1370_CORE_REG_EXTRA: u32 = 0x8000_8DEE;
const BM1370_MISC_SETTINGS_B9: u32 = 0x0000_4480;
const BM1370_ANALOG_MUX: u32 = 0x0000_0002;
const BM1370_IO_DRIVER: u32 = 0x0001_1111;
const BM1370_HASH_COUNTING: u32 = 0x0000_1EB5;
const BM1370_TICKET_MASK: u32 = 0x0000_00FF;

// ---------------------------------------------------------------------------
// BM1398 ASIC init constants (from bm1398.rs)
// ---------------------------------------------------------------------------

const BM1398_MISC_CTRL_INIT: u32 = 0x0000_7A31; // BT8D=26 â†’ 115200 baud
const BM1398_MISC_CTRL_FAST: u32 = 0x0000_6031; // BT8D=0 â†’ 3.125 MHz baud
const BM1398_TICKET_MASK: u32 = 0x0000_00FF; // Difficulty 256
const BM1398_ORDERED_CLK_EN: u32 = 0x0000_0001;
const BM1398_CLK_ORDER_CTRL: u32 = 0x0000_0000;

fn bm1398_pll_lookup(target_mhz: u16) -> (u32, u16) {
    let target_mhz = target_mhz.clamp(400, 700);
    let solution = dcentrald_api_types::bm1398_protocol::resolve_bm1398_pll(target_mhz)
        .expect("built-in BM1398 PLL search envelope must resolve mining frequencies");
    let actual_millimhz = solution
        .dividers
        .output_millimhz(dcentrald_api_types::bm1398_protocol::BM1398_PLL_SEARCH_SPEC.reference_mhz)
        .expect("resolved BM1398 dividers are non-zero");
    (
        solution.register_value,
        ((actual_millimhz + 500) / 1_000) as u16,
    )
}

// P1-4 pure PLL SSOT (dcentrald-common::pll_model) — thin engine wrappers.
fn bm1362_pll_lookup(target_mhz: u16) -> (u32, u16) {
    let s = dcentrald_common::resolve_pll(dcentrald_common::PllFamily::Bm1362, target_mhz);
    (s.register_value, s.actual_freq_mhz)
}

fn bm1368_pll_search(target_mhz: u16) -> (u32, u16) {
    let s = dcentrald_common::resolve_pll(dcentrald_common::PllFamily::Bm1368, target_mhz);
    (s.register_value, s.actual_freq_mhz)
}

fn bm1366_pll_search(target_mhz: u16) -> (u32, u16) {
    let s = dcentrald_common::resolve_pll(dcentrald_common::PllFamily::Bm1366, target_mhz);
    (s.register_value, s.actual_freq_mhz)
}

fn bm1370_pll_search(target_mhz: u16) -> (u32, u16) {
    let s = dcentrald_common::resolve_pll(dcentrald_common::PllFamily::Bm1370, target_mhz);
    (s.register_value, s.actual_freq_mhz)
}

/// Exact experimental authority for one AM2/BM1362 direct-serial diagnostic.
///
/// This is captured before any EEPROM, controller, PSU, UART, or ASIC access.
/// It binds the BoardDesc/config protocol proof to the live image marker and
/// the closed AM2 UART/slot/dsPIC topology. Direct BM1362 serial mining is not
/// a generic fallback for BeagleBone, Amlogic, or preserve-state adoption.
#[must_use = "AM2 BM1362 route admission must be consumed by serial execution"]
#[derive(Debug)]
struct Am2Bm1362DirectSerialAdmission {
    issuer: Arc<()>,
    _composition: crate::am2_bm1362_serial_admission::Am2Bm1362SerialRouteAdmission,
    dispatch: crate::SerialRuntimeDispatchAdmission,
    controller_plan: dcentrald_hal::platform::Am2ControllerPlan,
    serial_device: String,
    active_slot: u8,
    pic_address: u8,
}

fn require_monitored_am2_bm1362_serial_actor(serial_device: &str) -> Result<()> {
    if SerialMiner::am3_bb_uart_trans_chains_from_serial_device(serial_device).is_some() {
        anyhow::bail!(
            "validated AM2 BM1362 direct serial refuses /dev/ttyO* uart_trans routing until that actor implements the same exit, progress, commit-fence, and shutdown evidence contract"
        );
    }
    Ok(())
}

impl Am2Bm1362DirectSerialAdmission {
    fn capture(
        composition: crate::am2_bm1362_serial_admission::Am2Bm1362SerialRouteAdmission,
        dispatch: crate::SerialRuntimeDispatchAdmission,
        serial_device: &str,
    ) -> Result<Self> {
        if dispatch.board_target() != "am2-s19j"
            || dispatch.identity() != dcentrald_common::AsicProtocolIdentity::Bm1362
        {
            anyhow::bail!(
                "BM1362 direct serial requires exact am2-s19j/Bm1362 dispatch admission, got {}/{:?}",
                dispatch.board_target(),
                dispatch.identity()
            );
        }
        if !crate::env_flag("DCENT_ALLOW_AM2_BM1362_SERIAL_WORK") {
            anyhow::bail!(
                "AM2 BM1362 direct serial is Experimental and requires DCENT_ALLOW_AM2_BM1362_SERIAL_WORK=1 before hardware construction"
            );
        }
        if crate::env_flag("DCENT_BM1362_SKIP_POST_POWER_RESET") {
            anyhow::bail!(
                "validated AM2 BM1362 direct serial refuses the hot-start multi-baud reset spray; a fresh reset-to-115200 baseline is mandatory"
            );
        }
        require_monitored_am2_bm1362_serial_actor(serial_device)?;
        let controller_plan = dcentrald_hal::platform::discover_system_am2_controller_plan(&[
            serial_device.to_owned(),
        ])?;
        if controller_plan.board_target() != dispatch.board_target() {
            anyhow::bail!(
                "AM2 controller plan target {:?} does not match dispatch target {:?}",
                controller_plan.board_target(),
                dispatch.board_target()
            );
        }
        let context = controller_plan
            .contexts()
            .first()
            .context("AM2 BM1362 controller plan has no serial context")?;
        if controller_plan.contexts().len() != 1 || context.serial_device() != serial_device {
            anyhow::bail!(
                "AM2 BM1362 direct serial requires one exact controller context for {serial_device:?}"
            );
        }
        if context.slot() >= 3 || !S19_DSPIC_ADDRS.contains(&context.address()) {
            anyhow::bail!(
                "AM2 BM1362 direct serial refuses unsupported slot {} / dsPIC 0x{:02X}; retained EEPROM and controller authority cover slots 0..=2 only",
                context.slot(),
                context.address()
            );
        }
        let active_slot = context.slot();
        let pic_address = context.address();
        Ok(Self {
            issuer: Arc::new(()),
            _composition: composition,
            dispatch,
            controller_plan,
            serial_device: serial_device.to_owned(),
            active_slot,
            pic_address,
        })
    }

    fn controller_plan(&self) -> &dcentrald_hal::platform::Am2ControllerPlan {
        &self.controller_plan
    }

    fn same_issuer(&self, issuer: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.issuer, issuer)
    }

    fn serial_device(&self) -> &str {
        &self.serial_device
    }

    fn active_slot(&self) -> u8 {
        self.active_slot
    }

    fn pic_address(&self) -> u8 {
        self.pic_address
    }

    fn into_dispatch(self) -> crate::SerialRuntimeDispatchAdmission {
        self.dispatch
    }
}

pub struct SerialMiner {
    config: DcentraldConfig,
    shutdown: CancellationToken,
    runtime_dispatch_admission: Option<crate::SerialRuntimeDispatchAdmission>,
    am2_bm1362_route_admission: Option<Am2Bm1362DirectSerialAdmission>,
    /// Exact driver-maturity authority captured before any serial runtime can
    /// open hardware. In particular, BM1370 remains recognizable without
    /// being executable unless the boot policy names chip ID 0x1370 exactly.
    _asic_driver_admission: ChipDriverAdmission,
}

/// Exact-family serial response evidence bound to one configured physical
/// Amlogic route. This is deliberately not a measured-enumeration token:
/// repeated CRC-clean GetAddress frames establish protocol-family presence,
/// while `configured_chip_count` remains declarative chain geometry.
#[must_use = "validated serial admission must be consumed by one execution generation"]
#[derive(Debug, PartialEq, Eq)]
struct ValidatedSerialChainAdmission {
    board_target: &'static str,
    identity: dcentrald_common::AsicProtocolIdentity,
    active_slot: u8,
    serial_device: String,
    configured_baud: u32,
    observed_frames: NonZeroU8,
    response_shape: SerialAddressWindowShape,
    configured_chip_count: u8,
}

/// Exact post-assignment address coverage observed through the already-bound
/// serial execution session. Unlike the startup family window, this token may
/// publish a chip count because every configured address appears exactly once
/// after this runtime's SetAddress sequence.
#[must_use = "validated assigned geometry must feed runtime publication"]
#[derive(Debug, PartialEq, Eq)]
struct ValidatedSerialAssignedGeometry {
    identity: dcentrald_common::AsicProtocolIdentity,
    observed_chip_count: NonZeroU8,
    addresses: Vec<u8>,
}

impl ValidatedSerialAssignedGeometry {
    fn from_window(
        window: ValidatedSerialChipAddressWindow,
        expected_identity: dcentrald_common::AsicProtocolIdentity,
        configured_chip_count: u8,
        address_interval: u8,
    ) -> Result<Self> {
        let configured_chip_count = NonZeroU8::new(configured_chip_count)
            .context("assigned serial geometry requires nonzero configured geometry")?;
        let expected_addresses = (0..configured_chip_count.get())
            .map(|index| (u16::from(index) * u16::from(address_interval)) as u8)
            .collect::<Vec<_>>();
        if window.identity() != expected_identity {
            anyhow::bail!(
                "post-assignment serial family {:?} does not match expected {:?}",
                window.identity(),
                expected_identity
            );
        }
        if window.shape() != SerialAddressWindowShape::UniqueAssignedAddresses
            || window.observed_frames() != configured_chip_count
            || window.responder_addresses() != expected_addresses
        {
            anyhow::bail!(
                "post-assignment serial coverage is not the exact configured address plan: frames={}, configured={}, shape={:?}, observed={:02X?}, expected={:02X?}",
                window.observed_frames(),
                configured_chip_count,
                window.shape(),
                window.responder_addresses(),
                expected_addresses
            );
        }
        Ok(Self {
            identity: expected_identity,
            observed_chip_count: configured_chip_count,
            addresses: expected_addresses,
        })
    }

    fn observed_chip_count(&self) -> u8 {
        self.observed_chip_count.get()
    }
}

impl ValidatedSerialChainAdmission {
    fn bind_am2_bm1362(
        route: Am2Bm1362DirectSerialAdmission,
        configured_baud: u32,
        configured_chip_count: u8,
        window: ValidatedBm1362UnassignedAddressWindow,
    ) -> Result<Self> {
        if configured_baud != 115_200 {
            anyhow::bail!(
                "AM2 BM1362 reset-baseline admission requires 115200 baud, got {configured_baud}"
            );
        }
        if configured_chip_count == 0 {
            anyhow::bail!("AM2 BM1362 serial admission requires nonzero configured geometry");
        }
        if usize::from(window.observed_frames().get()) > usize::from(configured_chip_count) {
            anyhow::bail!(
                "AM2 BM1362 reset-baseline window contains {} frames, exceeding configured {}-chip geometry",
                window.observed_frames(),
                configured_chip_count
            );
        }
        let active_slot = route.active_slot();
        let serial_device = route.serial_device().to_owned();
        let dispatch = route.into_dispatch();
        Ok(Self {
            board_target: dispatch.board_target(),
            identity: dispatch.identity(),
            active_slot,
            serial_device,
            configured_baud,
            observed_frames: window.observed_frames(),
            response_shape: SerialAddressWindowShape::RepeatedUnassignedZero,
            configured_chip_count,
        })
    }

    fn bind(
        dispatch: crate::SerialRuntimeDispatchAdmission,
        platform: &dcentrald_hal::platform::amlogic::AmlogicNoPicAdmission,
        serial_device: &str,
        configured_baud: u32,
        configured_chip_count: u8,
        window: ValidatedSerialChipAddressWindow,
    ) -> Result<Self> {
        if platform.board_target() != dispatch.board_target() {
            anyhow::bail!(
                "serial BoardDesc target {:?} does not match exact Amlogic platform admission {:?}",
                dispatch.board_target(),
                platform.board_target()
            );
        }
        if platform.serial_device() != serial_device {
            anyhow::bail!(
                "serial response endpoint {serial_device:?} does not match Amlogic platform admission {:?}",
                platform.serial_device()
            );
        }
        Self::bind_route(
            dispatch,
            platform.active_slot(),
            serial_device,
            configured_baud,
            configured_chip_count,
            window,
        )
    }

    fn bind_route(
        dispatch: crate::SerialRuntimeDispatchAdmission,
        active_slot: u8,
        serial_device: &str,
        configured_baud: u32,
        configured_chip_count: u8,
        window: ValidatedSerialChipAddressWindow,
    ) -> Result<Self> {
        if !matches!(
            dispatch.identity(),
            dcentrald_common::AsicProtocolIdentity::Bm1362
                | dcentrald_common::AsicProtocolIdentity::Bm1368
                | dcentrald_common::AsicProtocolIdentity::Bm1370
        ) {
            anyhow::bail!(
                "validated direct-serial admission is not implemented for {:?}",
                dispatch.identity()
            );
        }
        if window.identity() != dispatch.identity() {
            anyhow::bail!(
                "serial response identity {:?} does not match BoardDesc/config admission {:?}",
                window.identity(),
                dispatch.identity()
            );
        }
        if configured_chip_count == 0 {
            anyhow::bail!("validated serial admission requires nonzero configured geometry");
        }
        if usize::from(window.observed_frames().get()) > usize::from(configured_chip_count) {
            anyhow::bail!(
                "serial response window contains {} frames, exceeding configured {}-chip geometry; refusing potentially duplicated/stale traffic",
                window.observed_frames(),
                configured_chip_count
            );
        }
        Ok(Self {
            board_target: dispatch.board_target(),
            identity: dispatch.identity(),
            active_slot,
            serial_device: serial_device.to_owned(),
            configured_baud,
            observed_frames: window.observed_frames(),
            response_shape: window.shape(),
            configured_chip_count,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactSerialRoute {
    NoPic,
    Am2Bm1362,
}

/// Move-only proof that the watchdog-issued exact actor roster was fully
/// resolved and issuer-validated before a serial route requests Mining phase.
pub(crate) struct ExactSerialRuntimeAdmissionPermit {
    run_scope: crate::runtime::safety_watchdog::WatchdogRunScope,
    route: ExactSerialRoute,
}

impl ExactSerialRuntimeAdmissionPermit {
    pub(crate) fn run_scope(&self) -> &crate::runtime::safety_watchdog::WatchdogRunScope {
        &self.run_scope
    }

    pub(crate) fn is_nopic(&self) -> bool {
        self.route == ExactSerialRoute::NoPic
    }

    pub(crate) fn is_am2_bm1362(&self) -> bool {
        self.route == ExactSerialRoute::Am2Bm1362
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SerialSessionDescriptor {
    board_target: &'static str,
    identity: dcentrald_common::AsicProtocolIdentity,
    active_slot: u8,
    serial_device: String,
    configured_chip_count: u8,
}

impl SerialSessionDescriptor {
    fn from_validated(admission: &ValidatedSerialChainAdmission) -> Self {
        Self {
            board_target: admission.board_target,
            identity: admission.identity,
            active_slot: admission.active_slot,
            serial_device: admission.serial_device.clone(),
            configured_chip_count: admission.configured_chip_count,
        }
    }

    fn validate_promotion(&self, admission: &ValidatedSerialChainAdmission) -> Result<()> {
        anyhow::ensure!(
            *self == Self::from_validated(admission),
            "validated serial admission does not match the observing session descriptor"
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct SerialSessionToken {
    _run_scope: crate::runtime::safety_watchdog::WatchdogRunScope,
    route: ExactSerialRoute,
    descriptor: SerialSessionDescriptor,
}

impl SerialSessionToken {
    #[cfg(test)]
    fn from_validated_for_test(admission: &ValidatedSerialChainAdmission) -> Self {
        let descriptor = SerialSessionDescriptor::from_validated(admission);
        let route = if descriptor.identity == dcentrald_common::AsicProtocolIdentity::Bm1362 {
            ExactSerialRoute::Am2Bm1362
        } else {
            ExactSerialRoute::NoPic
        };
        Self {
            _run_scope: crate::runtime::safety_watchdog::WatchdogRunScope::new(),
            route,
            descriptor,
        }
    }
}

impl ExecutionFenceIdentity for SerialSessionToken {
    fn execution_identity(&self) -> String {
        format!(
            "{:?}/{}/{:?}/slot{}/{}",
            self.route,
            self.descriptor.board_target,
            self.descriptor.identity,
            self.descriptor.active_slot,
            self.descriptor.serial_device,
        )
    }
}

type SerialExecutionCommitPort = ExecutionFencePort<SerialSessionToken>;
type SerialExecutionTerminal = ExecutionFenceTerminal<SerialSessionToken>;
type RevokedSerialExecutionFence = RevokedExecutionFence<SerialSessionToken>;

#[derive(Debug)]
pub(crate) struct SerialExecutionBarrierReceipt {
    _receipt: ExecutionFenceReceipt<SerialSessionToken>,
}

impl SerialExecutionBarrierReceipt {
    fn from_receipt(receipt: ExecutionFenceReceipt<SerialSessionToken>) -> Self {
        Self { _receipt: receipt }
    }
}

struct SerialObservationPort {
    issuer: Arc<()>,
    execution: SerialExecutionCommitPort,
    descriptor: SerialSessionDescriptor,
}

struct NoPicSerialObservation {
    inner: SerialObservationPort,
}

struct Am2SerialObservation {
    inner: SerialObservationPort,
}

struct NoPicAdmittedSerial {
    backend: SerialChainBackend,
    configured_baud: u32,
    window: ValidatedSerialChipAddressWindow,
    issuer: Arc<()>,
    descriptor: SerialSessionDescriptor,
}

struct Am2ObservedResetBaseline {
    backend: SerialChainBackend,
    window: ValidatedBm1362UnassignedAddressWindow,
    issuer: Arc<()>,
    descriptor: SerialSessionDescriptor,
}

impl NoPicSerialObservation {
    fn observe_candidate(&self, probe_baud: u32) -> Result<Option<NoPicAdmittedSerial>> {
        self.inner
            .execution
            .commit("NoPic serial admission observation", || -> Result<_> {
                let probe = match SerialChainBackend::open(
                    0,
                    &self.inner.descriptor.serial_device,
                    probe_baud,
                ) {
                    Ok(probe) => probe,
                    Err(error) => {
                        warn!(probe_baud, %error, "Serial admission UART open failed");
                        return Ok(None);
                    }
                };
                probe.set_response_len(BM13XX_CMD_RESP_BODY_LEN);
                if let Err(error) = probe.flush_io() {
                    warn!(probe_baud, %error, "Unable to clear stale UART responses before serial admission probe");
                    return Ok(None);
                }
                if let Err(error) = probe.send_get_address_bm1397plus() {
                    warn!(probe_baud, %error, "Serial admission GetAddress query failed");
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(200));
                let responses = match probe.read_all_responses(500) {
                    Ok(responses) => responses,
                    Err(error) => {
                        warn!(probe_baud, %error, "Serial admission probe read failed");
                        return Ok(None);
                    }
                };
                match validate_serial_chip_address_window(responses.iter().map(Vec::as_slice)) {
                    Ok(window)
                        if window.identity() == self.inner.descriptor.identity
                            && usize::from(window.observed_frames().get())
                                <= usize::from(self.inner.descriptor.configured_chip_count) =>
                    {
                        info!(
                            probe_baud,
                            identity = ?window.identity(),
                            observed_frames = window.observed_frames().get(),
                            response_shape = ?window.shape(),
                            configured_chip_count = self.inner.descriptor.configured_chip_count,
                            "CRC-verified serial protocol-family admission window accepted"
                        );
                        Ok(Some(NoPicAdmittedSerial {
                            backend: probe,
                            configured_baud: probe_baud,
                            window,
                            issuer: Arc::clone(&self.inner.issuer),
                            descriptor: self.inner.descriptor.clone(),
                        }))
                    }
                    Ok(window) => {
                        warn!(
                            probe_baud,
                            identity = ?window.identity(),
                            expected_identity = ?self.inner.descriptor.identity,
                            observed_frames = window.observed_frames().get(),
                            configured_chip_count = self.inner.descriptor.configured_chip_count,
                            "Serial response window does not match the admitted family/geometry envelope"
                        );
                        Ok(None)
                    }
                    Err(error) => {
                        warn!(
                            probe_baud,
                            ?error,
                            "Serial response window failed exact ChipAddress validation"
                        );
                        Ok(None)
                    }
                }
            })
            .map_err(anyhow::Error::from)
    }
}

impl Am2SerialObservation {
    fn observe_preserve_state(&self, pic_addr: u8) -> Result<()> {
        self.inner
            .execution
            .commit("AM2 preserve-state serial observation", || -> Result<()> {
                post_enable_chain_uart_probe(&self.inner.descriptor.serial_device, pic_addr);
                Ok(())
            })
            .map_err(anyhow::Error::from)
    }

    fn observe_reset_baseline(&self) -> Result<Am2ObservedResetBaseline> {
        self.inner
            .execution
            .commit("AM2 reset-baseline serial observation", || -> Result<_> {
                let serial = SerialChainBackend::open(
                    0,
                    &self.inner.descriptor.serial_device,
                    115_200,
                )
                .context("failed to open AM2 BM1362 reset-baseline UART at 115200")?;
                serial.set_response_len(BM1362_UNASSIGNED_RESP_BODY_LEN);
                serial
                    .flush_io()
                    .context("failed to flush AM2 BM1362 reset-baseline UART")?;
                serial
                    .send_get_address_bm1397plus()
                    .context("failed to send AM2 BM1362 reset-baseline GetAddress")?;
                std::thread::sleep(Duration::from_millis(200));
                let responses = serial
                    .read_all_responses(500)
                    .context("failed to read AM2 BM1362 reset-baseline responses")?;
                let window = validate_unassigned_address_window(responses.iter().map(Vec::as_slice))
                .map_err(|error| {
                    anyhow::anyhow!("AM2 BM1362 reset-baseline validation failed: {error:?}")
                })?;
                info!(
                    serial_device = %self.inner.descriptor.serial_device,
                    frames = window.observed_frames().get(),
                    "CRC-verified BM1362 reset-baseline response window admitted (frame count is not population)"
                );
                Ok(Am2ObservedResetBaseline {
                    backend: serial,
                    window,
                    issuer: Arc::clone(&self.inner.issuer),
                    descriptor: self.inner.descriptor.clone(),
                })
            })
            .map_err(anyhow::Error::from)
    }
}

/// Exact direct-serial route domains are deliberately hidden behind one
/// lifecycle owner. The outer module can drive the transitions, but it cannot
/// construct either opaque closeout state or combine loose HAL receipts.
mod serial_route_domains {
    use super::*;

    /// Opaque coupling of the physical backend retained by an observation,
    /// the admission derived from that observation, and the exact session
    /// that issued both. Keeping this type private to the route domain makes
    /// it impossible for outer production code to substitute a loose backend
    /// between evidence collection and execution promotion.
    pub(super) struct BoundObservedSerial {
        backend: SerialChainBackend,
        admission: ValidatedSerialChainAdmission,
        issuer: Arc<()>,
        descriptor: SerialSessionDescriptor,
    }

    enum SerialExecutionLifecycle {
        Pending,
        Observing {
            terminal: Option<SerialExecutionTerminal>,
            issuer: Arc<()>,
            descriptor: SerialSessionDescriptor,
        },
        Executing {
            terminal: Option<SerialExecutionTerminal>,
            issuer: Arc<()>,
            descriptor: SerialSessionDescriptor,
        },
        Closed,
    }

    enum ApiMutationLifecycle {
        Pending(Option<dcentrald_hal::platform::HardwareMutationGateOwner>),
        Opened(Option<dcentrald_hal::platform::HardwareMutationGateOwner>),
        Closed,
    }

    enum Am2ResetLifecycle {
        NotApplicable,
        Pending,
        Attempting {
            slot: u8,
        },
        FailedBeforeMutation {
            slot: u8,
        },
        ReleaseRegisterVerified {
            slot: u8,
            route_issuer: Arc<()>,
            receipt: dcentrald_hal::board_control::ExactAm2ResetRegisterReceipt,
        },
        PulseUnverifiedReleaseRegisterVerified {
            slot: u8,
            route_issuer: Arc<()>,
            receipt: dcentrald_hal::board_control::ExactAm2ResetReleaseRegisterReceipt,
        },
        OutcomeUnknown {
            slot: u8,
        },
        Closed,
    }

    enum SerialActorLifecycle {
        NoPic {
            owner: Option<ThreadRosterOwner<NoPicSerialThreadSlot>>,
            expectation: Option<ThreadRosterExpectation<NoPicSerialThreadSlot>>,
            runtime_admission: Option<ThreadRosterRuntimeAdmission<NoPicSerialThreadSlot>>,
        },
        Am2Bm1362 {
            owner: Option<ThreadRosterOwner<Am2SerialThreadSlot>>,
            expectation: Option<ThreadRosterExpectation<Am2SerialThreadSlot>>,
            runtime_admission: Option<ThreadRosterRuntimeAdmission<Am2SerialThreadSlot>>,
        },
    }

    enum SerialActorExpectation {
        NoPic {
            owner_activated: bool,
            expectation: ThreadRosterExpectation<NoPicSerialThreadSlot>,
            runtime_was_admitted: bool,
        },
        Am2Bm1362 {
            owner_activated: bool,
            expectation: ThreadRosterExpectation<Am2SerialThreadSlot>,
            runtime_was_admitted: bool,
        },
    }

    /// Sole owner of the exact route's serial-execution and external API
    /// mutation domains. It is claimed once from the armed watchdog owner.
    pub(super) struct SerialRouteDomains {
        scope: Option<crate::runtime::safety_watchdog::WatchdogRunScope>,
        route: ExactSerialRoute,
        am2_reset_issuer: Option<Arc<()>>,
        serial: SerialExecutionLifecycle,
        api: ApiMutationLifecycle,
        reset: Am2ResetLifecycle,
        actors: SerialActorLifecycle,
    }

    pub(super) struct RevokedRouteDomains {
        serial: RevokedSerialExecutionDomain,
        api: RevokedApiMutationDomain,
    }

    enum RevokedSerialExecutionState {
        NeverObserved,
        ObservationRevoked(RevokedSerialExecutionFence),
        ExecutionRevoked(RevokedSerialExecutionFence),
    }

    pub(super) struct RevokedSerialExecutionDomain {
        scope: crate::runtime::safety_watchdog::WatchdogRunScope,
        route: ExactSerialRoute,
        state: RevokedSerialExecutionState,
        actors: SerialActorExpectation,
        actor_closeout_admission: Option<ExactSerialActorCloseoutAdmission>,
        am2_reset_closeout: Option<Am2ResetDomainCloseout>,
    }

    enum RevokedApiMutationState {
        NeverOpened,
        Revoked {
            gate: dcentrald_hal::platform::HardwareMutationGate,
            final_commit: dcentrald_hal::platform::RevokedHardwareMutationCommitFence,
        },
    }

    pub(super) struct RevokedApiMutationDomain {
        scope: crate::runtime::safety_watchdog::WatchdogRunScope,
        route: ExactSerialRoute,
        state: RevokedApiMutationState,
    }

    enum SerialExecutionCloseoutState {
        NeverObserved,
        ObservationClosed(SerialExecutionBarrierReceipt),
        ExecutionClosed(SerialExecutionBarrierReceipt),
    }

    /// Opaque move-only proof that the exact serial execution domain either
    /// never admitted UART commits or was revoked and observed quiescent.
    pub(crate) struct SerialExecutionDomainCloseout {
        scope: crate::runtime::safety_watchdog::WatchdogRunScope,
        route: ExactSerialRoute,
        _state: SerialExecutionCloseoutState,
        actors: SerialActorExpectation,
        actor_closeout_admission: Option<ExactSerialActorCloseoutAdmission>,
        am2_reset_closeout: Option<Am2ResetDomainCloseout>,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Am2ResetCloseoutOutcome {
        NeverAttempted,
        FailedBeforeMutation,
        ReleaseRegisterVerified(dcentrald_hal::board_control::ExactAm2ResetRegisterReceipt),
        PulseUnverifiedReleaseRegisterVerified(
            dcentrald_hal::board_control::ExactAm2ResetReleaseRegisterReceipt,
        ),
        OutcomeUnknown,
    }

    /// Watchdog-run-bound exact-reset closeout. Register verification is kept
    /// separate from the serial barrier because reset is an independent MMIO
    /// mutation domain that precedes UART observation.
    pub(crate) struct Am2ResetDomainCloseout {
        scope: crate::runtime::safety_watchdog::WatchdogRunScope,
        slot: Option<u8>,
        outcome: Am2ResetCloseoutOutcome,
    }

    enum ApiMutationCloseoutState {
        NeverOpened,
        Closed {
            _drain: dcentrald_hal::platform::HardwareMutationBarrierReceipt,
            _final_commit: dcentrald_hal::platform::HardwareMutationCommitFenceReceipt,
        },
    }

    /// Opaque move-only proof issued by one API lifecycle owner. Callers can
    /// never mix a drain receipt from one gate with a final-commit receipt from
    /// another gate or assert `NeverOpened` themselves.
    pub(crate) struct ApiMutationDomainCloseout {
        scope: crate::runtime::safety_watchdog::WatchdogRunScope,
        route: ExactSerialRoute,
        _state: ApiMutationCloseoutState,
    }

    impl SerialRouteDomains {
        fn claim_inner(
            watchdog: &mut SafetyWatchdogOwner,
            route: ExactSerialRoute,
            am2_reset_issuer: Option<Arc<()>>,
        ) -> Result<Self> {
            anyhow::ensure!(
                (route == ExactSerialRoute::Am2Bm1362) == am2_reset_issuer.is_some(),
                "exact serial route/reset-issuer composition mismatch"
            );
            let watchdog_route = match route {
                ExactSerialRoute::NoPic => {
                    crate::runtime::safety_watchdog::SerialWatchdogComposition::NoPic
                }
                ExactSerialRoute::Am2Bm1362 => {
                    crate::runtime::safety_watchdog::SerialWatchdogComposition::Am2Bm1362
                }
            };
            let admission = watchdog.claim_serial_route_scope(watchdog_route)?;
            let (scope, actors) = match route {
                ExactSerialRoute::NoPic => {
                    let (scope, owner, expectation) = admission.into_nopic_parts()?;
                    (
                        scope,
                        SerialActorLifecycle::NoPic {
                            owner: Some(owner),
                            expectation: Some(expectation),
                            runtime_admission: None,
                        },
                    )
                }
                ExactSerialRoute::Am2Bm1362 => {
                    let (scope, owner, expectation) = admission.into_am2_parts()?;
                    (
                        scope,
                        SerialActorLifecycle::Am2Bm1362 {
                            owner: Some(owner),
                            expectation: Some(expectation),
                            runtime_admission: None,
                        },
                    )
                }
            };
            Ok(Self {
                scope: Some(scope),
                route,
                am2_reset_issuer,
                serial: SerialExecutionLifecycle::Pending,
                api: ApiMutationLifecycle::Pending(Some(
                    dcentrald_hal::platform::HardwareMutationGateOwner::new_pending(),
                )),
                reset: match route {
                    ExactSerialRoute::NoPic => Am2ResetLifecycle::NotApplicable,
                    ExactSerialRoute::Am2Bm1362 => Am2ResetLifecycle::Pending,
                },
                actors,
            })
        }

        pub(super) fn claim_nopic(watchdog: &mut SafetyWatchdogOwner) -> Result<Self> {
            Self::claim_inner(watchdog, ExactSerialRoute::NoPic, None)
        }

        pub(super) fn claim_am2(
            watchdog: &mut SafetyWatchdogOwner,
            route: &Am2Bm1362DirectSerialAdmission,
        ) -> Result<Self> {
            Self::claim_inner(
                watchdog,
                ExactSerialRoute::Am2Bm1362,
                Some(Arc::clone(&route.issuer)),
            )
        }

        #[cfg(test)]
        pub(super) fn claim(
            watchdog: &mut SafetyWatchdogOwner,
            route: ExactSerialRoute,
        ) -> Result<Self> {
            match route {
                ExactSerialRoute::NoPic => Self::claim_nopic(watchdog),
                ExactSerialRoute::Am2Bm1362 => {
                    Self::claim_inner(watchdog, ExactSerialRoute::Am2Bm1362, Some(Arc::new(())))
                }
            }
        }

        pub(super) fn take_nopic_actor_owner(
            &mut self,
        ) -> Result<ThreadRosterOwner<NoPicSerialThreadSlot>> {
            match &mut self.actors {
                SerialActorLifecycle::NoPic { owner, .. } => owner
                    .take()
                    .context("NoPic serial watchdog actor owner was already consumed"),
                SerialActorLifecycle::Am2Bm1362 { .. } => {
                    anyhow::bail!("AM2 serial route cannot issue a NoPic actor owner")
                }
            }
        }

        pub(super) fn take_am2_actor_owner(
            &mut self,
        ) -> Result<ThreadRosterOwner<Am2SerialThreadSlot>> {
            match &mut self.actors {
                SerialActorLifecycle::Am2Bm1362 { owner, .. } => owner
                    .take()
                    .context("AM2 serial watchdog actor owner was already consumed"),
                SerialActorLifecycle::NoPic { .. } => {
                    anyhow::bail!("NoPic serial route cannot issue an AM2 actor owner")
                }
            }
        }

        fn begin_observation(
            &mut self,
            descriptor: SerialSessionDescriptor,
        ) -> Result<SerialObservationPort> {
            if !matches!(self.serial, SerialExecutionLifecycle::Pending) {
                anyhow::bail!("exact direct-serial observation session was already opened")
            }
            let scope = self
                .scope
                .as_ref()
                .context("exact serial route scope disappeared before observation")?
                .clone();
            let issuer = Arc::new(());
            let (execution, terminal) = execution_fence_domain(SerialSessionToken {
                _run_scope: scope,
                route: self.route,
                descriptor: descriptor.clone(),
            });
            self.serial = SerialExecutionLifecycle::Observing {
                terminal: Some(terminal),
                issuer: Arc::clone(&issuer),
                descriptor: descriptor.clone(),
            };
            Ok(SerialObservationPort {
                issuer,
                execution,
                descriptor,
            })
        }

        pub(super) fn begin_nopic_observation(
            &mut self,
            dispatch: &crate::SerialRuntimeDispatchAdmission,
            platform: &dcentrald_hal::platform::amlogic::AmlogicNoPicAdmission,
            serial_device: &str,
            configured_chip_count: u8,
        ) -> Result<NoPicSerialObservation> {
            anyhow::ensure!(
                self.route == ExactSerialRoute::NoPic,
                "AM2 serial route cannot issue a NoPic observation facade"
            );
            anyhow::ensure!(
                platform.board_target() == dispatch.board_target(),
                "NoPic observation BoardDesc/platform target mismatch"
            );
            anyhow::ensure!(
                platform.serial_device() == serial_device,
                "NoPic observation endpoint does not match platform admission"
            );
            anyhow::ensure!(
                matches!(
                    dispatch.identity(),
                    dcentrald_common::AsicProtocolIdentity::Bm1368
                        | dcentrald_common::AsicProtocolIdentity::Bm1370
                ),
                "NoPic observation requires BM1368/BM1370 identity"
            );
            anyhow::ensure!(
                configured_chip_count > 0,
                "NoPic observation requires nonzero configured geometry"
            );
            Ok(NoPicSerialObservation {
                inner: self.begin_observation(SerialSessionDescriptor {
                    board_target: dispatch.board_target(),
                    identity: dispatch.identity(),
                    active_slot: platform.active_slot(),
                    serial_device: serial_device.to_owned(),
                    configured_chip_count,
                })?,
            })
        }

        pub(super) fn begin_am2_observation(
            &mut self,
            route: &Am2Bm1362DirectSerialAdmission,
            configured_chip_count: u8,
        ) -> Result<Am2SerialObservation> {
            anyhow::ensure!(
                self.route == ExactSerialRoute::Am2Bm1362,
                "NoPic serial route cannot issue an AM2 observation facade"
            );
            anyhow::ensure!(
                matches!(
                    &self.reset,
                    Am2ResetLifecycle::ReleaseRegisterVerified {
                        slot,
                        route_issuer,
                        receipt,
                    }
                        if *slot == route.active_slot()
                            && receipt.slot() == route.active_slot()
                            && route.same_issuer(route_issuer)
                ),
                "AM2 serial observation requires same-route, same-slot reset assertion/release register verification"
            );
            anyhow::ensure!(
                configured_chip_count > 0,
                "AM2 observation requires nonzero configured geometry"
            );
            Ok(Am2SerialObservation {
                inner: self.begin_observation(SerialSessionDescriptor {
                    board_target: route.dispatch.board_target(),
                    identity: route.dispatch.identity(),
                    active_slot: route.active_slot(),
                    serial_device: route.serial_device().to_owned(),
                    configured_chip_count,
                })?,
            })
        }

        /// Perform the exact AM2 reset transaction once under the retained
        /// watchdog route owner. The lifecycle is pessimistically moved to
        /// `Attempting` immediately before the first HAL method that can write
        /// MMIO, so unwinding or an ambiguous readback can never look pending.
        pub(super) fn pulse_am2_hashboard_reset(
            &mut self,
            route: &Am2Bm1362DirectSerialAdmission,
        ) -> Result<()> {
            anyhow::ensure!(
                self.route == ExactSerialRoute::Am2Bm1362,
                "NoPic serial route cannot issue AM2 reset authority"
            );
            let expected_issuer = self
                .am2_reset_issuer
                .as_ref()
                .context("AM2 reset route issuer was not bound when the domain was claimed")?;
            anyhow::ensure!(
                route.same_issuer(expected_issuer),
                "AM2 reset authority was supplied by another route admission"
            );
            let slot = route.active_slot();
            anyhow::ensure!(
                matches!(self.reset, Am2ResetLifecycle::Pending),
                "exact AM2 reset authority was already consumed"
            );

            let platform = match dcentrald_hal::platform::zynq::ZynqPlatform::new()
                .context("failed to bind the admitted Zynq platform for AM2 reset")
            {
                Ok(platform) => platform,
                Err(error) => {
                    self.reset = Am2ResetLifecycle::FailedBeforeMutation { slot };
                    return Err(error);
                }
            };
            let board_control = match platform
                .open_board_control()
                .context("failed to open admitted AM2 board-control reset owner")
                .and_then(|owner| {
                    owner.context("admitted AM2 board-control IP is unavailable for reset")
                }) {
                Ok(owner) => owner,
                Err(error) => {
                    self.reset = Am2ResetLifecycle::FailedBeforeMutation { slot };
                    return Err(error);
                }
            };

            self.reset = Am2ResetLifecycle::Attempting { slot };
            match board_control.pulse_reset_exact(slot) {
                Ok(receipt) if receipt.slot() == slot => {
                    self.reset = Am2ResetLifecycle::ReleaseRegisterVerified {
                        slot,
                        route_issuer: Arc::clone(&route.issuer),
                        receipt,
                    };
                    info!(
                        slot,
                        gpio = receipt.gpio(),
                        reset_bit = format!("0x{:08X}", receipt.reset_bit()),
                        asserted_data = format!("0x{:08X}", receipt.asserted_data()),
                        released_data = format!("0x{:08X}", receipt.released_data()),
                        path = route.serial_device(),
                        "AM2 reset assertion/release register receipt retained by route domain"
                    );
                    Ok(())
                }
                Ok(receipt) => {
                    self.reset = Am2ResetLifecycle::OutcomeUnknown { slot };
                    anyhow::bail!(
                        "AM2 reset receipt slot {} does not match admitted slot {slot}",
                        receipt.slot()
                    )
                }
                Err(
                    dcentrald_hal::board_control::ExactAm2ResetFailure::AssertionUnverifiedButReleaseRegisterVerified {
                        release,
                        detail,
                        ..
                    },
                ) => {
                    self.reset = Am2ResetLifecycle::PulseUnverifiedReleaseRegisterVerified {
                        slot,
                        route_issuer: Arc::clone(&route.issuer),
                        receipt: release,
                    };
                    Err(anyhow::anyhow!(
                        "AM2 slot {slot} hashboard reset assertion was unverified; UART observation remains forbidden: {detail}"
                    ))
                }
                Err(error) => {
                    self.reset = if error.mutation_entered() {
                        Am2ResetLifecycle::OutcomeUnknown { slot }
                    } else {
                        Am2ResetLifecycle::FailedBeforeMutation { slot }
                    };
                    Err(anyhow::Error::from(error)
                        .context(format!("AM2 slot {slot} hashboard reset pulse failed")))
                }
            }
        }

        fn validate_observed_session(
            &self,
            issuer: &Arc<()>,
            descriptor: &SerialSessionDescriptor,
        ) -> Result<()> {
            match &self.serial {
                SerialExecutionLifecycle::Observing {
                    issuer: active_issuer,
                    descriptor: active_descriptor,
                    ..
                } => {
                    anyhow::ensure!(
                        Arc::ptr_eq(active_issuer, issuer),
                        "observed serial backend was issued by another session"
                    );
                    anyhow::ensure!(
                        active_descriptor == descriptor,
                        "observed serial backend descriptor drifted before binding"
                    );
                    Ok(())
                }
                _ => anyhow::bail!("observed serial backend binding requires an observing session"),
            }
        }

        pub(super) fn bind_nopic_observed_serial(
            &self,
            observed: NoPicAdmittedSerial,
            route_admission: crate::SerialRuntimeDispatchAdmission,
            platform: &dcentrald_hal::platform::amlogic::AmlogicNoPicAdmission,
            serial_device: &str,
            configured_chip_count: u8,
        ) -> Result<(u32, BoundObservedSerial)> {
            anyhow::ensure!(
                self.route == ExactSerialRoute::NoPic,
                "AM2 serial route cannot bind a NoPic observed backend"
            );
            let NoPicAdmittedSerial {
                backend,
                configured_baud,
                window,
                issuer,
                descriptor,
            } = observed;
            self.validate_observed_session(&issuer, &descriptor)?;
            let admission = ValidatedSerialChainAdmission::bind(
                route_admission,
                platform,
                serial_device,
                configured_baud,
                configured_chip_count,
                window,
            )?;
            descriptor.validate_promotion(&admission)?;
            Ok((
                configured_baud,
                BoundObservedSerial {
                    backend,
                    admission,
                    issuer,
                    descriptor,
                },
            ))
        }

        pub(super) fn bind_am2_observed_serial(
            &self,
            observed: Am2ObservedResetBaseline,
            route: Am2Bm1362DirectSerialAdmission,
            configured_chip_count: u8,
        ) -> Result<BoundObservedSerial> {
            anyhow::ensure!(
                self.route == ExactSerialRoute::Am2Bm1362,
                "NoPic serial route cannot bind an AM2 observed backend"
            );
            anyhow::ensure!(
                matches!(
                    &self.reset,
                    Am2ResetLifecycle::ReleaseRegisterVerified { route_issuer, .. }
                        if route.same_issuer(route_issuer)
                ),
                "AM2 observed backend binding requires the reset-admitted route issuer"
            );
            let Am2ObservedResetBaseline {
                backend,
                window,
                issuer,
                descriptor,
            } = observed;
            self.validate_observed_session(&issuer, &descriptor)?;
            let admission = ValidatedSerialChainAdmission::bind_am2_bm1362(
                route,
                115_200,
                configured_chip_count,
                window,
            )?;
            descriptor.validate_promotion(&admission)?;
            Ok(BoundObservedSerial {
                backend,
                admission,
                issuer,
                descriptor,
            })
        }

        fn promote_execution(
            &mut self,
            observation: SerialObservationPort,
            admission: ValidatedSerialChainAdmission,
        ) -> Result<SerialExecutionCommitPort> {
            let previous = std::mem::replace(&mut self.serial, SerialExecutionLifecycle::Closed);
            let (terminal, issuer, descriptor) = match previous {
                SerialExecutionLifecycle::Observing {
                    terminal,
                    issuer,
                    descriptor,
                } => (terminal, issuer, descriptor),
                other => {
                    self.serial = other;
                    anyhow::bail!("serial execution promotion requires an observing session")
                }
            };
            let promotion = (|| -> Result<()> {
                anyhow::ensure!(
                    Arc::ptr_eq(&issuer, &observation.issuer),
                    "serial observation facade was issued by another session"
                );
                anyhow::ensure!(
                    descriptor == observation.descriptor,
                    "serial observation facade descriptor drifted before promotion"
                );
                descriptor.validate_promotion(&admission)
            })();
            if let Err(error) = promotion {
                self.serial = SerialExecutionLifecycle::Observing {
                    terminal,
                    issuer,
                    descriptor,
                };
                return Err(error);
            }
            self.serial = SerialExecutionLifecycle::Executing {
                terminal,
                issuer,
                descriptor,
            };
            Ok(observation.execution)
        }

        pub(super) fn promote_nopic_execution(
            &mut self,
            observation: NoPicSerialObservation,
            bound: BoundObservedSerial,
        ) -> Result<ValidatedSerialBackend> {
            anyhow::ensure!(
                self.route == ExactSerialRoute::NoPic,
                "AM2 serial route cannot promote a NoPic observation"
            );
            anyhow::ensure!(
                Arc::ptr_eq(&bound.issuer, &observation.inner.issuer),
                "NoPic observed backend and observation facade have different issuers"
            );
            anyhow::ensure!(
                bound.descriptor == observation.inner.descriptor,
                "NoPic observed backend and observation facade descriptors differ"
            );
            let execution = self.promote_execution(observation.inner, bound.admission)?;
            Ok(ValidatedSerialBackend::new(bound.backend, execution))
        }

        pub(super) fn promote_am2_execution(
            &mut self,
            observation: Am2SerialObservation,
            bound: BoundObservedSerial,
        ) -> Result<ValidatedSerialBackend> {
            anyhow::ensure!(
                self.route == ExactSerialRoute::Am2Bm1362,
                "NoPic serial route cannot promote an AM2 observation"
            );
            anyhow::ensure!(
                Arc::ptr_eq(&bound.issuer, &observation.inner.issuer),
                "AM2 observed backend and observation facade have different issuers"
            );
            anyhow::ensure!(
                bound.descriptor == observation.inner.descriptor,
                "AM2 observed backend and observation facade descriptors differ"
            );
            let execution = self.promote_execution(observation.inner, bound.admission)?;
            Ok(ValidatedSerialBackend::new(bound.backend, execution))
        }

        pub(super) fn admit_runtime_actors(
            &mut self,
            admission: ExactSerialRuntimeActorAdmission,
        ) -> Result<ExactSerialRuntimeAdmissionPermit> {
            anyhow::ensure!(
                matches!(self.serial, SerialExecutionLifecycle::Executing { .. }),
                "exact serial runtime actors cannot be admitted before serial execution promotion"
            );
            match (&mut self.actors, admission) {
                (
                    SerialActorLifecycle::NoPic {
                        owner,
                        expectation,
                        runtime_admission,
                    },
                    ExactSerialRuntimeActorAdmission::NoPic(admission),
                ) => {
                    anyhow::ensure!(
                        owner.is_none(),
                        "NoPic serial actor owner was not activated before runtime admission"
                    );
                    anyhow::ensure!(
                        runtime_admission.is_none(),
                        "NoPic serial runtime actors were already admitted"
                    );
                    let expectation = expectation
                        .as_ref()
                        .context("NoPic serial actor expectation disappeared before admission")?;
                    anyhow::ensure!(
                        admission.authorizes(expectation),
                        "NoPic runtime actor admission was issued by another roster"
                    );
                    anyhow::ensure!(
                        admission.running(NoPicSerialThreadSlot::SerialIo),
                        "NoPic normal runtime requires a registered serial-I/O actor"
                    );
                    *runtime_admission = Some(admission);
                    Ok(ExactSerialRuntimeAdmissionPermit {
                        run_scope: self
                            .scope
                            .as_ref()
                            .context("NoPic route scope disappeared before runtime admission")?
                            .clone(),
                        route: self.route,
                    })
                }
                (
                    SerialActorLifecycle::Am2Bm1362 {
                        owner,
                        expectation,
                        runtime_admission,
                    },
                    ExactSerialRuntimeActorAdmission::Am2 {
                        roster: admission,
                        apw_topology,
                    },
                ) => {
                    anyhow::ensure!(
                        owner.is_none(),
                        "AM2 serial actor owner was not activated before runtime admission"
                    );
                    anyhow::ensure!(
                        runtime_admission.is_none(),
                        "AM2 serial runtime actors were already admitted"
                    );
                    let expectation = expectation
                        .as_ref()
                        .context("AM2 serial actor expectation disappeared before admission")?;
                    anyhow::ensure!(
                        admission.authorizes(expectation),
                        "AM2 runtime actor admission was issued by another roster"
                    );
                    anyhow::ensure!(
                        admission.running(Am2SerialThreadSlot::DspicHeartbeat),
                        "AM2 normal runtime requires a registered dsPIC-heartbeat actor"
                    );
                    anyhow::ensure!(
                        admission.running(Am2SerialThreadSlot::SerialIo),
                        "AM2 normal runtime requires a registered serial-I/O actor"
                    );
                    anyhow::ensure!(
                        match apw_topology {
                            Am2ApwActorTopology::SmartPsu => {
                                admission.running(Am2SerialThreadSlot::ApwHeartbeat)
                            }
                            Am2ApwActorTopology::ExplicitBypass =>
                                admission.topology_not_applicable(Am2SerialThreadSlot::ApwHeartbeat),
                        },
                        "AM2 normal runtime actor roster contradicts typed APW topology"
                    );
                    *runtime_admission = Some(admission);
                    Ok(ExactSerialRuntimeAdmissionPermit {
                        run_scope: self
                            .scope
                            .as_ref()
                            .context("AM2 route scope disappeared before runtime admission")?
                            .clone(),
                        route: self.route,
                    })
                }
                (
                    SerialActorLifecycle::NoPic { .. },
                    ExactSerialRuntimeActorAdmission::Am2 { .. },
                ) => {
                    anyhow::bail!("NoPic serial route cannot admit an AM2 runtime actor roster")
                }
                (
                    SerialActorLifecycle::Am2Bm1362 { .. },
                    ExactSerialRuntimeActorAdmission::NoPic(_),
                ) => anyhow::bail!("AM2 serial route cannot admit a NoPic runtime actor roster"),
            }
        }

        #[cfg(test)]
        pub(super) fn open_serial_execution(
            &mut self,
            admission: ValidatedSerialChainAdmission,
        ) -> Result<SerialExecutionCommitPort> {
            let descriptor = SerialSessionDescriptor::from_validated(&admission);
            let observation = self.begin_observation(descriptor)?;
            self.promote_execution(observation, admission)
        }

        #[cfg(test)]
        pub(super) fn begin_serial_observation_for_test(
            &mut self,
            admission: &ValidatedSerialChainAdmission,
        ) -> Result<SerialObservationPort> {
            self.begin_observation(SerialSessionDescriptor::from_validated(admission))
        }

        #[cfg(test)]
        pub(super) fn promote_serial_observation_for_test(
            &mut self,
            observation: SerialObservationPort,
            admission: ValidatedSerialChainAdmission,
        ) -> Result<SerialExecutionCommitPort> {
            self.promote_execution(observation, admission)
        }

        /// Return the gate exposed to management surfaces. NoPic opens the
        /// owner-held pending gate exactly once. Exact AM2 exposes the same
        /// pending gate read-only: no caller owns the capability required to
        /// open it, so shutdown can truthfully report `NeverOpened`.
        pub(super) fn management_api_gate(
            &mut self,
        ) -> Result<dcentrald_hal::platform::HardwareMutationGate> {
            match self.route {
                ExactSerialRoute::NoPic => {
                    let owner = match &mut self.api {
                        ApiMutationLifecycle::Pending(owner) => owner
                            .take()
                            .context("NoPic API pending owner was already consumed")?,
                        ApiMutationLifecycle::Opened(_) => {
                            anyhow::bail!("NoPic API mutation domain was already opened")
                        }
                        ApiMutationLifecycle::Closed => {
                            anyhow::bail!("NoPic API mutation domain is closed")
                        }
                    };
                    if let Err(error) = owner.open() {
                        self.api = ApiMutationLifecycle::Pending(Some(owner));
                        return Err(anyhow::Error::from(error));
                    }
                    let gate = owner.gate();
                    self.api = ApiMutationLifecycle::Opened(Some(owner));
                    Ok(gate)
                }
                ExactSerialRoute::Am2Bm1362 => match &self.api {
                    ApiMutationLifecycle::Pending(Some(owner)) => Ok(owner.gate()),
                    ApiMutationLifecycle::Pending(None) => {
                        anyhow::bail!("exact AM2 API pending owner was already consumed")
                    }
                    ApiMutationLifecycle::Opened(_) => {
                        anyhow::bail!("exact AM2 API mutation domain unexpectedly opened")
                    }
                    ApiMutationLifecycle::Closed => {
                        anyhow::bail!("exact AM2 API mutation domain is closed")
                    }
                },
            }
        }

        /// Synchronously revoke every exact route mutation domain before any
        /// watchdog RPC or potentially blocking physical safe-off operation.
        pub(super) fn begin_closeout(mut self) -> Result<RevokedRouteDomains> {
            let scope = self
                .scope
                .take()
                .context("exact serial route-domain scope was already consumed")?;
            let (actors, actor_closeout_admission) = match &mut self.actors {
                SerialActorLifecycle::NoPic {
                    owner,
                    expectation,
                    runtime_admission,
                } => {
                    let runtime_was_admitted = runtime_admission.is_some();
                    let closeout_admission = match runtime_admission.take() {
                        Some(admission) => {
                            ExactSerialActorCloseoutAdmission::NoPicRuntime(admission)
                        }
                        None => ExactSerialActorCloseoutAdmission::NoPicPreRuntime(
                            expectation
                                .as_ref()
                                .context(
                                    "NoPic serial actor expectation disappeared before pre-runtime closeout",
                                )?
                                .issue_pre_runtime_closeout(),
                        ),
                    };
                    (
                        SerialActorExpectation::NoPic {
                            owner_activated: owner.is_none(),
                            expectation: expectation
                                .take()
                                .context("NoPic serial actor expectation was already consumed")?,
                            runtime_was_admitted,
                        },
                        closeout_admission,
                    )
                }
                SerialActorLifecycle::Am2Bm1362 {
                    owner,
                    expectation,
                    runtime_admission,
                } => {
                    let runtime_was_admitted = runtime_admission.is_some();
                    let closeout_admission = match runtime_admission.take() {
                        Some(admission) => {
                            ExactSerialActorCloseoutAdmission::Am2Runtime(admission)
                        }
                        None => ExactSerialActorCloseoutAdmission::Am2PreRuntime(
                            expectation
                                .as_ref()
                                .context(
                                    "AM2 serial actor expectation disappeared before pre-runtime closeout",
                                )?
                                .issue_pre_runtime_closeout(),
                        ),
                    };
                    (
                        SerialActorExpectation::Am2Bm1362 {
                            owner_activated: owner.is_none(),
                            expectation: expectation
                                .take()
                                .context("AM2 serial actor expectation was already consumed")?,
                            runtime_was_admitted,
                        },
                        closeout_admission,
                    )
                }
            };
            let am2_reset_closeout =
                match std::mem::replace(&mut self.reset, Am2ResetLifecycle::Closed) {
                    Am2ResetLifecycle::NotApplicable => None,
                    Am2ResetLifecycle::Pending => Some(Am2ResetDomainCloseout {
                        scope: scope.clone(),
                        slot: None,
                        outcome: Am2ResetCloseoutOutcome::NeverAttempted,
                    }),
                    Am2ResetLifecycle::FailedBeforeMutation { slot } => {
                        Some(Am2ResetDomainCloseout {
                            scope: scope.clone(),
                            slot: Some(slot),
                            outcome: Am2ResetCloseoutOutcome::FailedBeforeMutation,
                        })
                    }
                    Am2ResetLifecycle::ReleaseRegisterVerified { slot, receipt, .. } => {
                        Some(Am2ResetDomainCloseout {
                            scope: scope.clone(),
                            slot: Some(slot),
                            outcome: Am2ResetCloseoutOutcome::ReleaseRegisterVerified(receipt),
                        })
                    }
                    Am2ResetLifecycle::PulseUnverifiedReleaseRegisterVerified {
                        slot,
                        receipt,
                        ..
                    } => Some(Am2ResetDomainCloseout {
                        scope: scope.clone(),
                        slot: Some(slot),
                        outcome: Am2ResetCloseoutOutcome::PulseUnverifiedReleaseRegisterVerified(
                            receipt,
                        ),
                    }),
                    Am2ResetLifecycle::Attempting { slot }
                    | Am2ResetLifecycle::OutcomeUnknown { slot } => Some(Am2ResetDomainCloseout {
                        scope: scope.clone(),
                        slot: Some(slot),
                        outcome: Am2ResetCloseoutOutcome::OutcomeUnknown,
                    }),
                    Am2ResetLifecycle::Closed => {
                        anyhow::bail!("exact AM2 reset domain was already closed")
                    }
                };
            let serial = RevokedSerialExecutionDomain {
                scope: scope.clone(),
                route: self.route,
                state: match std::mem::replace(&mut self.serial, SerialExecutionLifecycle::Closed) {
                    SerialExecutionLifecycle::Pending => RevokedSerialExecutionState::NeverObserved,
                    SerialExecutionLifecycle::Observing {
                        mut terminal,
                        issuer: _,
                        descriptor: _,
                    } => RevokedSerialExecutionState::ObservationRevoked(
                        terminal
                            .take()
                            .context("serial observation terminal was already consumed")?
                            .revoke(),
                    ),
                    SerialExecutionLifecycle::Executing {
                        mut terminal,
                        issuer: _,
                        descriptor: _,
                    } => RevokedSerialExecutionState::ExecutionRevoked(
                        terminal
                            .take()
                            .context("serial execution terminal was already consumed")?
                            .revoke(),
                    ),
                    SerialExecutionLifecycle::Closed => {
                        anyhow::bail!("exact serial execution domain was already closed")
                    }
                },
                actors,
                actor_closeout_admission: Some(actor_closeout_admission),
                am2_reset_closeout,
            };
            let api = RevokedApiMutationDomain {
                scope,
                route: self.route,
                state: match std::mem::replace(&mut self.api, ApiMutationLifecycle::Closed) {
                    ApiMutationLifecycle::Pending(mut owner) => {
                        // Dropping the sole opener terminally closes the pending
                        // gate. It never admitted a lease or entered a commit.
                        let owner = owner
                            .take()
                            .context("exact API pending owner was already consumed")?;
                        drop(owner);
                        RevokedApiMutationState::NeverOpened
                    }
                    ApiMutationLifecycle::Opened(mut owner) => {
                        let owner = owner
                            .take()
                            .context("exact API opened owner was already consumed")?;
                        let final_commit = owner.revoke_commit_fence();
                        let gate = owner.gate();
                        drop(owner);
                        RevokedApiMutationState::Revoked { gate, final_commit }
                    }
                    ApiMutationLifecycle::Closed => {
                        anyhow::bail!("exact API mutation domain was already closed")
                    }
                },
            };
            Ok(RevokedRouteDomains { serial, api })
        }
    }

    impl Drop for SerialRouteDomains {
        fn drop(&mut self) {
            let terminal = match &mut self.serial {
                SerialExecutionLifecycle::Observing { terminal, .. }
                | SerialExecutionLifecycle::Executing { terminal, .. } => terminal.take(),
                SerialExecutionLifecycle::Pending | SerialExecutionLifecycle::Closed => None,
            };
            if let Some(terminal) = terminal {
                // Revocation itself is synchronous and fail-closed. Drop
                // cannot mint quiescence evidence, so the revoked waiter is
                // discarded only after closing fresh UART admission.
                drop(terminal.revoke());
            }
            match &mut self.api {
                ApiMutationLifecycle::Pending(owner) => {
                    drop(owner.take());
                }
                ApiMutationLifecycle::Opened(owner) => {
                    if let Some(owner) = owner.take() {
                        drop(owner.revoke_commit_fence());
                        drop(owner);
                    }
                }
                ApiMutationLifecycle::Closed => {}
            }
        }
    }

    impl RevokedRouteDomains {
        pub(super) fn split_for_closeout(
            self,
        ) -> (RevokedSerialExecutionDomain, RevokedApiMutationDomain) {
            (self.serial, self.api)
        }
    }

    impl RevokedSerialExecutionDomain {
        pub(super) async fn complete(
            self,
            timeout: Duration,
            lifecycle_scope: &'static str,
        ) -> Result<SerialExecutionDomainCloseout> {
            let state = match self.state {
                RevokedSerialExecutionState::NeverObserved => {
                    SerialExecutionCloseoutState::NeverObserved
                }
                RevokedSerialExecutionState::ObservationRevoked(fence) => {
                    SerialExecutionCloseoutState::ObservationClosed(
                        wait_revoked_serial_execution_fence(fence, timeout, lifecycle_scope)
                            .await?,
                    )
                }
                RevokedSerialExecutionState::ExecutionRevoked(fence) => {
                    SerialExecutionCloseoutState::ExecutionClosed(
                        wait_revoked_serial_execution_fence(fence, timeout, lifecycle_scope)
                            .await?,
                    )
                }
            };
            Ok(SerialExecutionDomainCloseout {
                scope: self.scope,
                route: self.route,
                _state: state,
                actors: self.actors,
                actor_closeout_admission: self.actor_closeout_admission,
                am2_reset_closeout: self.am2_reset_closeout,
            })
        }
    }

    impl RevokedApiMutationDomain {
        pub(super) async fn complete(
            self,
            timeout: Duration,
            lifecycle_scope: &'static str,
        ) -> Result<ApiMutationDomainCloseout> {
            let state = match self.state {
                RevokedApiMutationState::NeverOpened => ApiMutationCloseoutState::NeverOpened,
                RevokedApiMutationState::Revoked { gate, final_commit } => {
                    let closeout_started_at = Instant::now();
                    let closeout_deadline = closeout_started_at
                        .checked_add(timeout)
                        .context("API mutation closeout deadline overflowed Instant")?;
                    let drain: Result<_> =
                        match tokio::task::spawn_blocking(move || gate.close_and_drain(timeout))
                            .await
                        {
                            Ok(result) => result.map_err(anyhow::Error::from).and_then(|receipt| {
                                anyhow::ensure!(
                                    receipt.closed_and_drained_at() < closeout_deadline,
                                    "{lifecycle_scope} API mutation drain completed at or after its shared closeout deadline"
                                );
                                Ok(receipt)
                            }),
                            Err(error) => Err(anyhow::anyhow!(
                                "{lifecycle_scope} API mutation drain worker failed: {error}"
                            )),
                        };
                    let final_commit = wait_revoked_hardware_mutation_commit_fence(
                        final_commit,
                        tokio::time::Instant::from_std(closeout_started_at),
                        tokio::time::Instant::from_std(closeout_deadline),
                        lifecycle_scope,
                    )
                    .await;
                    match (drain, final_commit) {
                        (Ok(drain), Ok(final_commit)) => ApiMutationCloseoutState::Closed {
                            _drain: drain,
                            _final_commit: final_commit,
                        },
                        (Err(drain), Err(final_commit)) => anyhow::bail!(
                            "{lifecycle_scope} API mutation closeout failed: drain: {drain:#}; final commit: {final_commit:#}"
                        ),
                        (Err(error), Ok(_)) => return Err(error),
                        (Ok(_), Err(error)) => return Err(error),
                    }
                }
            };
            Ok(ApiMutationDomainCloseout {
                scope: self.scope,
                route: self.route,
                _state: state,
            })
        }
    }

    impl SerialExecutionDomainCloseout {
        pub(crate) fn run_scope(&self) -> &crate::runtime::safety_watchdog::WatchdogRunScope {
            &self.scope
        }

        pub(crate) fn is_nopic(&self) -> bool {
            self.route == ExactSerialRoute::NoPic
        }

        pub(crate) fn is_am2_bm1362(&self) -> bool {
            self.route == ExactSerialRoute::Am2Bm1362
        }

        pub(crate) fn is_complete(&self) -> bool {
            self.actor_closeout_admission.is_none()
                && self.am2_reset_closeout.is_none()
                && match &self._state {
                    SerialExecutionCloseoutState::NeverObserved => true,
                    SerialExecutionCloseoutState::ObservationClosed(_receipt)
                    | SerialExecutionCloseoutState::ExecutionClosed(_receipt) => true,
                }
        }

        pub(crate) fn authorizes_nopic_actors(
            &self,
            receipt: &ThreadRosterQuiescenceReceipt<NoPicSerialThreadSlot>,
        ) -> bool {
            matches!(
                &self.actors,
                SerialActorExpectation::NoPic {
                    owner_activated: true,
                    expectation,
                    ..
                } if receipt.authorizes(expectation)
            )
        }

        pub(crate) fn authorizes_am2_actors(
            &self,
            receipt: &ThreadRosterQuiescenceReceipt<Am2SerialThreadSlot>,
        ) -> bool {
            matches!(
                &self.actors,
                SerialActorExpectation::Am2Bm1362 {
                    owner_activated: true,
                    expectation,
                    ..
                } if receipt.authorizes(expectation)
            )
        }

        pub(crate) fn nopic_runtime_actors_were_admitted(&self) -> bool {
            matches!(
                &self.actors,
                SerialActorExpectation::NoPic {
                    runtime_was_admitted: true,
                    ..
                }
            )
        }

        pub(crate) fn am2_runtime_actors_were_admitted(&self) -> bool {
            matches!(
                &self.actors,
                SerialActorExpectation::Am2Bm1362 {
                    runtime_was_admitted: true,
                    ..
                }
            )
        }

        pub(super) fn take_actor_closeout_admission(
            &mut self,
        ) -> Result<ExactSerialActorCloseoutAdmission> {
            self.actor_closeout_admission
                .take()
                .context("exact serial actor closeout admission was already consumed")
        }

        pub(super) fn take_am2_reset_closeout(&mut self) -> Result<Am2ResetDomainCloseout> {
            anyhow::ensure!(
                self.route == ExactSerialRoute::Am2Bm1362,
                "NoPic serial closeout cannot issue an AM2 reset closeout"
            );
            self.am2_reset_closeout
                .take()
                .context("exact AM2 reset closeout was already consumed")
        }

        pub(crate) fn serial_was_observed(&self) -> bool {
            !matches!(self._state, SerialExecutionCloseoutState::NeverObserved)
        }

        #[cfg(test)]
        pub(super) fn was_never_opened(&self) -> bool {
            matches!(self._state, SerialExecutionCloseoutState::NeverObserved)
        }

        #[cfg(test)]
        pub(super) fn was_observation_only(&self) -> bool {
            matches!(
                self._state,
                SerialExecutionCloseoutState::ObservationClosed(_)
            )
        }

        #[cfg(test)]
        pub(super) fn was_promoted_to_execution(&self) -> bool {
            matches!(
                self._state,
                SerialExecutionCloseoutState::ExecutionClosed(_)
            )
        }
    }

    impl Am2ResetDomainCloseout {
        pub(crate) fn run_scope(&self) -> &crate::runtime::safety_watchdog::WatchdogRunScope {
            &self.scope
        }

        pub(crate) fn pulse_register_verified(&self) -> bool {
            matches!(
                &self.outcome,
                Am2ResetCloseoutOutcome::ReleaseRegisterVerified(_)
            )
        }

        pub(crate) fn terminal_release_register_verified(&self) -> bool {
            matches!(
                &self.outcome,
                Am2ResetCloseoutOutcome::ReleaseRegisterVerified(_)
                    | Am2ResetCloseoutOutcome::PulseUnverifiedReleaseRegisterVerified(_)
            )
        }

        pub(crate) fn safe_without_reset_mutation(&self) -> bool {
            matches!(
                &self.outcome,
                Am2ResetCloseoutOutcome::NeverAttempted
                    | Am2ResetCloseoutOutcome::FailedBeforeMutation
            )
        }

        pub(crate) fn outcome_unknown(&self) -> bool {
            matches!(&self.outcome, Am2ResetCloseoutOutcome::OutcomeUnknown)
        }

        pub(crate) fn slot(&self) -> Option<u8> {
            self.slot
        }

        #[cfg(test)]
        pub(super) fn was_never_attempted(&self) -> bool {
            matches!(&self.outcome, Am2ResetCloseoutOutcome::NeverAttempted)
        }

        #[cfg(test)]
        pub(super) fn pulse_was_unverified_but_release_register_verified(&self) -> bool {
            matches!(
                &self.outcome,
                Am2ResetCloseoutOutcome::PulseUnverifiedReleaseRegisterVerified(_)
            )
        }
    }

    impl ApiMutationDomainCloseout {
        pub(crate) fn run_scope(&self) -> &crate::runtime::safety_watchdog::WatchdogRunScope {
            &self.scope
        }

        pub(crate) fn is_nopic(&self) -> bool {
            self.route == ExactSerialRoute::NoPic
        }

        pub(crate) fn is_am2_bm1362(&self) -> bool {
            self.route == ExactSerialRoute::Am2Bm1362
        }

        pub(crate) fn is_complete(&self) -> bool {
            match &self._state {
                ApiMutationCloseoutState::NeverOpened => true,
                ApiMutationCloseoutState::Closed {
                    _drain,
                    _final_commit,
                } => true,
            }
        }

        #[cfg(test)]
        pub(super) fn was_never_opened(&self) -> bool {
            matches!(self._state, ApiMutationCloseoutState::NeverOpened)
        }
    }
}

use serial_route_domains::SerialRouteDomains;
pub(crate) use serial_route_domains::{
    Am2ResetDomainCloseout, ApiMutationDomainCloseout, SerialExecutionDomainCloseout,
};

/// Move-only evidence that the immediate physical cutoff was attempted before
/// the exact AM2 serial execution domain can be closed. The result remains
/// attached to the attempt: a failed GPIO transition still MUST be followed
/// by serial revocation, but it can never authorize watchdog disarm.
struct Am2FirstStageCutAttempt {
    result: Result<()>,
}

/// Clean failure dispositions are deliberately split at the physical
/// energizing boundary. Both permit management-only operation after a positive
/// watchdog closeout, but `NeverEnergizedClosed` must never be presented as
/// evidence that terminal safe-off I/O ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SerialFailureDisposition {
    NeverEnergizedClosed,
    TerminalSafeOffClosed,
}

/// Move-only proof that the exact AM2 route closed while its watchdog-issued
/// `Am2NeverEnergized` authority was still intact.
#[derive(Debug)]
struct Am2NeverEnergizedCloseout {
    _watchdog: WatchdogCloseoutReceipt,
}

#[derive(Debug)]
struct SerialNeverEnergizedError {
    source: anyhow::Error,
    _closeout: Am2NeverEnergizedCloseout,
}

impl std::fmt::Display for SerialNeverEnergizedError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:#}", self.source)
    }
}

impl std::error::Error for SerialNeverEnergizedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Marker returned only when an energized exact serial failure path completed
/// checked safe-off, closed every mutation/actor domain, and positively
/// observed the watchdog magic-close plus worker exit.
#[derive(Debug)]
pub(crate) struct SerialTerminalSafeOffError {
    source: anyhow::Error,
    _closeout: WatchdogCloseoutReceipt,
}

impl std::fmt::Display for SerialTerminalSafeOffError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:#}", self.source)
    }
}

impl std::error::Error for SerialTerminalSafeOffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub(crate) fn is_terminal_safe_off_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<SerialTerminalSafeOffError>().is_some())
}

/// Recover the exact clean-close disposition without allowing a
/// never-energized close to masquerade as terminal-safe-off evidence.
pub(crate) fn failure_disposition(error: &anyhow::Error) -> Option<SerialFailureDisposition> {
    error.chain().find_map(|cause| {
        if cause.downcast_ref::<SerialNeverEnergizedError>().is_some() {
            Some(SerialFailureDisposition::NeverEnergizedClosed)
        } else if cause.downcast_ref::<SerialTerminalSafeOffError>().is_some() {
            Some(SerialFailureDisposition::TerminalSafeOffClosed)
        } else {
            None
        }
    })
}

fn never_energized_error(
    source: anyhow::Error,
    closeout: Am2NeverEnergizedCloseout,
) -> anyhow::Error {
    anyhow::Error::new(SerialNeverEnergizedError {
        source,
        _closeout: closeout,
    })
}

fn terminal_safe_off_error(
    source: anyhow::Error,
    closeout: WatchdogCloseoutReceipt,
) -> anyhow::Error {
    anyhow::Error::new(SerialTerminalSafeOffError {
        source,
        _closeout: closeout,
    })
}

/// Consume and destroy clean-close authority immediately before the first
/// outcome-unknown PWR_CONTROL assertion. Callers must complete every
/// fallible configuration/applicability check before moving the token here.
fn assert_am2_psu_gpio_after_energizing_boundary(
    power: &mut Am2PsuRuntimeGuard,
    never_energized: Am2NeverEnergized,
    gpio: Option<&str>,
) -> Result<u32> {
    assert_am2_psu_gpio_after_energizing_boundary_with(power, never_energized, gpio, |gpio| {
        PsuGpioGate::assert(gpio).map_err(anyhow::Error::from)
    })
}

fn assert_am2_psu_gpio_after_energizing_boundary_with<F>(
    power: &mut Am2PsuRuntimeGuard,
    never_energized: Am2NeverEnergized,
    gpio: Option<&str>,
    assert: F,
) -> Result<u32>
where
    F: FnOnce(Option<&str>) -> Result<PsuGpioGate>,
{
    // This fact becomes true before entering the outcome-unknown HAL call and
    // remains true even when assertion returns an error without an owner.
    power.enter_power_boundary()?;
    drop(never_energized);
    let gate = assert(gpio)?;
    let asserted_gpio = gate.gpio();
    power.set_gate(gate)?;
    Ok(asserted_gpio)
}

async fn close_am2_watchdog_never_energized(
    watchdog_owner: &mut Option<SafetyWatchdogOwner>,
    never_energized: &mut Option<Am2NeverEnergized>,
    route_domains: &mut Option<SerialRouteDomains>,
    runtime_threads: &mut SerialRuntimeThreads,
) -> Result<Am2NeverEnergizedCloseout> {
    // Pre-energization is a physical-power classification, not permission to
    // abandon the watchdog-issued mutation/actor domains. Revoke and close
    // those domains first so clean watchdog close remains composition-wide.
    let route_closeout = route_domains
        .take()
        .context("AM2 pre-energization closeout lost route-domain ownership")
        .and_then(SerialRouteDomains::begin_closeout);
    let (mut serial_result, api_result) = match route_closeout {
        Ok(revoked) => {
            let (serial, api) = revoked.split_for_closeout();
            (
                serial
                    .complete(RUNTIME_THREAD_STOP_TIMEOUT, "AM2 pre-energization")
                    .await,
                api.complete(RUNTIME_THREAD_STOP_TIMEOUT, "AM2 pre-energization API")
                    .await,
            )
        }
        Err(error) => {
            let detail = format!("AM2 pre-energization route revocation failed: {error:#}");
            (
                Err(anyhow::anyhow!(detail.clone())),
                Err(anyhow::anyhow!(detail)),
            )
        }
    };
    let actor_closeout_admission = serial_result
        .as_mut()
        .ok()
        .and_then(|closeout| closeout.take_actor_closeout_admission().ok());
    let reset_result = serial_result
        .as_mut()
        .map_err(|error| {
            anyhow::anyhow!("serial closeout unavailable for reset evidence: {error:#}")
        })
        .and_then(SerialExecutionDomainCloseout::take_am2_reset_closeout);
    let actor_result = runtime_threads
        .stop_and_join(RUNTIME_THREAD_STOP_TIMEOUT, actor_closeout_admission)
        .await
        .into_am2_receipt();

    let composition_result = match (&serial_result, &api_result, &reset_result, &actor_result) {
        (Ok(serial), Ok(api), Ok(reset), Ok(actors)) => {
            anyhow::ensure!(
                serial.is_complete() && api.is_complete(),
                "AM2 pre-energization mutation domains did not close completely"
            );
            anyhow::ensure!(
                reset.run_scope().same_run(serial.run_scope())
                    && reset.safe_without_reset_mutation(),
                "AM2 pre-energization reset domain does not prove no reset mutation"
            );
            anyhow::ensure!(
                serial.authorizes_am2_actors(actors),
                "AM2 pre-energization actor receipt belongs to another route roster"
            );
            anyhow::ensure!(
                !serial.am2_runtime_actors_were_admitted(),
                "AM2 pre-energization closeout observed an impossible admitted runtime"
            );
            for slot in [
                Am2SerialThreadSlot::ApwHeartbeat,
                Am2SerialThreadSlot::DspicHeartbeat,
                Am2SerialThreadSlot::SerialIo,
            ] {
                anyhow::ensure!(
                    actors.not_started_before_runtime_admission(slot),
                    "AM2 pre-energization closeout lacks not-reached evidence for {slot:?}"
                );
            }
            Ok(())
        }
        _ => Err(anyhow::anyhow!(
            "AM2 pre-energization composition closeout lacks complete mutation/actor evidence"
        )),
    };

    let mut prerequisite_errors = Vec::new();
    if let Err(error) = &serial_result {
        prerequisite_errors.push(format!("serial execution closeout failed: {error:#}"));
    }
    if let Err(error) = &api_result {
        prerequisite_errors.push(format!("API mutation closeout failed: {error:#}"));
    }
    if let Err(error) = &actor_result {
        prerequisite_errors.push(format!("actor roster closeout failed: {error:#}"));
    }
    if let Err(error) = &reset_result {
        prerequisite_errors.push(format!("reset-domain closeout failed: {error:#}"));
    }
    if let Err(error) = &composition_result {
        prerequisite_errors.push(format!("composition validation failed: {error:#}"));
    }
    if !prerequisite_errors.is_empty() {
        return Err(anyhow::anyhow!(
            "AM2 pre-energization closeout incomplete: {}",
            prerequisite_errors.join("; ")
        ));
    }

    let watchdog = watchdog_owner
        .take()
        .context("AM2 pre-energization closeout lost watchdog ownership")?;
    let evidence = never_energized
        .take()
        .context("AM2 pre-energization closeout lost never-energized evidence")?;
    watchdog
        .disarm_never_energized(evidence, DEFAULT_WATCHDOG_STOP_TIMEOUT)
        .await
        .map(|watchdog| Am2NeverEnergizedCloseout {
            _watchdog: watchdog,
        })
}

fn attempt_am2_first_stage_cut(
    power: &mut impl Am2FirstStagePowerCut,
    reason: &'static str,
) -> Am2FirstStageCutAttempt {
    let mut failures = Vec::new();
    for attempt in 1..=AM2_BM1362_TERMINAL_SAFE_OFF_ATTEMPTS {
        match power.attempt_first_stage_power_cut(reason) {
            Ok(()) => {
                return Am2FirstStageCutAttempt { result: Ok(()) };
            }
            Err(error) => failures.push(format!("attempt {attempt}: {error:#}")),
        }
    }
    Am2FirstStageCutAttempt {
        result: Err(anyhow::anyhow!(
            "AM2 BM1362 first-stage cutoff failed during {reason} after {} attempts: {}",
            AM2_BM1362_TERMINAL_SAFE_OFF_ATTEMPTS,
            failures.join("; ")
        )),
    }
}

struct Am2SerialCloseoutAfterFirstStageCut {
    first_stage_cut: Result<()>,
    serial_barrier: Result<SerialExecutionDomainCloseout>,
}

/// Move-only proof that exact AM2 serial admission was revoked synchronously
/// before the first potentially blocking physical cutoff attempt, watchdog
/// RPC, or bounded commit-fence wait could yield.
struct Am2RevokedSerialDomainAfterFirstStageCut {
    first_stage_cut: Result<()>,
    serial: serial_route_domains::RevokedSerialExecutionDomain,
}

impl Am2RevokedSerialDomainAfterFirstStageCut {
    fn first_stage_cut_failure_detail(&self) -> Option<String> {
        self.first_stage_cut
            .as_ref()
            .err()
            .map(|error| format!("{error:#}"))
    }
}

/// Attach the result of the first physical cutoff only after serial admission
/// has already been closed. The watchdog must also have entered its bounded
/// Teardown phase before callers perform the cutoff.
fn record_am2_first_stage_cut_after_revocation(
    serial: serial_route_domains::RevokedSerialExecutionDomain,
    first_stage_cut: Am2FirstStageCutAttempt,
) -> Am2RevokedSerialDomainAfterFirstStageCut {
    Am2RevokedSerialDomainAfterFirstStageCut {
        first_stage_cut: first_stage_cut.result,
        serial,
    }
}

/// Wait only after the caller has synchronously revoked the serial generation.
/// This is deliberately separate from revocation so watchdog phase commands
/// can never leave UART commit admission open while they await a response.
async fn wait_revoked_am2_serial_execution_fence(
    fence: RevokedSerialExecutionFence,
    timeout: Duration,
) -> Result<SerialExecutionBarrierReceipt> {
    wait_revoked_serial_execution_fence(fence, timeout, "AM2 BM1362").await
}

async fn wait_revoked_serial_execution_fence(
    fence: RevokedSerialExecutionFence,
    timeout: Duration,
    lifecycle_scope: &'static str,
) -> Result<SerialExecutionBarrierReceipt> {
    wait_revoked_serial_execution_fence_with_post_pending_probe(
        fence,
        timeout,
        lifecycle_scope,
        || {},
    )
    .await
}

fn serial_execution_fence_timeout_error(
    lifecycle_scope: &str,
    execution_identity: &str,
    started: tokio::time::Instant,
    timeout: Duration,
    quiescence_observed_after_deadline: bool,
) -> anyhow::Error {
    let commit_fence_state = if quiescence_observed_after_deadline {
        "quiescent_after_deadline"
    } else {
        "no_timely_quiescence_observation"
    };
    error!(
        serial_execution_identity = execution_identity,
        deadline_ms = timeout.as_millis(),
        elapsed_ms = started.elapsed().as_millis(),
        serial_admission_revoked = true,
        commit_fence_state,
        entered_commit_state = "unknown",
        detached_waiter = false,
        "serial commit fence exceeded its bounded nonblocking wait"
    );
    if quiescence_observed_after_deadline {
        anyhow::anyhow!(
            "{lifecycle_scope} serial generation {execution_identity} was revoked, but commit-fence quiescence was first observed after its {} ms deadline; no blocking waiter was detached",
            timeout.as_millis()
        )
    } else {
        anyhow::anyhow!(
            "{lifecycle_scope} serial generation {execution_identity} was revoked, but its commit fence produced no timely quiescence evidence within {} ms; no blocking waiter was detached",
            timeout.as_millis()
        )
    }
}

fn serial_execution_fence_poisoned_error(
    lifecycle_scope: &str,
    execution_identity: &str,
    started: tokio::time::Instant,
) -> anyhow::Error {
    error!(
        serial_execution_identity = execution_identity,
        elapsed_ms = started.elapsed().as_millis(),
        serial_admission_revoked = true,
        commit_fence_state = "quiescent_but_poisoned",
        entered_commit_state = "unwound_with_possible_partial_side_effect",
        fence_poisoned = true,
        detached_waiter = false,
        "serial commit fence is quiescent but cannot support clean shutdown"
    );
    anyhow::anyhow!(
        "{lifecycle_scope} serial generation {execution_identity} became quiescent after a commit panic; terminal safe-off remains mandatory and clean watchdog disarm is forbidden"
    )
}

async fn wait_revoked_serial_execution_fence_with_post_pending_probe<F>(
    mut fence: RevokedSerialExecutionFence,
    timeout: Duration,
    lifecycle_scope: &'static str,
    mut post_pending_probe: F,
) -> Result<SerialExecutionBarrierReceipt>
where
    F: FnMut(),
{
    let execution_identity = fence.execution_identity();
    let started = tokio::time::Instant::now();
    let deadline = started + timeout;
    let outcome = observe_nonblocking_until(
        fence,
        deadline,
        AM2_BM1362_SERIAL_FENCE_POLL_INTERVAL,
        |fence| match fence.try_wait_for_commit_fence() {
            ExecutionFenceTryWait::Fenced(receipt) => NonblockingProbe::Ready {
                completed_at: receipt.fenced_at(),
                value: receipt,
            },
            ExecutionFenceTryWait::Pending(fence) => {
                post_pending_probe();
                NonblockingProbe::Pending(fence)
            }
        },
    )
    .await;
    match outcome {
        BoundedProbeOutcome::Timely(receipt) => {
            if receipt.fence_poisoned() {
                Err(serial_execution_fence_poisoned_error(
                    lifecycle_scope,
                    &execution_identity,
                    started,
                ))
            } else {
                Ok(SerialExecutionBarrierReceipt::from_receipt(receipt))
            }
        }
        BoundedProbeOutcome::DeadlineExceeded { .. } => Err(serial_execution_fence_timeout_error(
            lifecycle_scope,
            &execution_identity,
            started,
            timeout,
            false,
        )),
        BoundedProbeOutcome::CompletedAfterDeadline(_) => {
            Err(serial_execution_fence_timeout_error(
                lifecycle_scope,
                &execution_identity,
                started,
                timeout,
                true,
            ))
        }
    }
}

#[cfg(test)]
async fn wait_revoked_am2_serial_execution_fence_with_post_pending_probe<F>(
    fence: RevokedSerialExecutionFence,
    timeout: Duration,
    post_pending_probe: F,
) -> Result<SerialExecutionBarrierReceipt>
where
    F: FnMut(),
{
    wait_revoked_serial_execution_fence_with_post_pending_probe(
        fence,
        timeout,
        "AM2 BM1362",
        post_pending_probe,
    )
    .await
}

async fn wait_am2_serial_domain_after_revocation(
    revoked_domain: Am2RevokedSerialDomainAfterFirstStageCut,
    timeout: Duration,
) -> Am2SerialCloseoutAfterFirstStageCut {
    let Am2RevokedSerialDomainAfterFirstStageCut {
        first_stage_cut,
        serial,
    } = revoked_domain;
    let serial_barrier = serial.complete(timeout, "AM2 BM1362").await;

    Am2SerialCloseoutAfterFirstStageCut {
        first_stage_cut,
        serial_barrier,
    }
}

async fn closeout_native_nopic_failure(
    watchdog_owner: &mut Option<SafetyWatchdogOwner>,
    route_domains: &mut Option<SerialRouteDomains>,
    psu_guard: &mut NoPicPsuGuard,
    runtime_threads: &mut SerialRuntimeThreads,
    prior_emergency_cut: Option<NoPicEmergencyCutReceipt>,
) -> Result<WatchdogCloseoutReceipt> {
    // Close both route mutation domains before the first watchdog RPC. The
    // consuming lifecycle owner also retains their exact watchdog-run scope.
    let route_closeout = route_domains
        .take()
        .context("NoPic route-domain owner disappeared during failure closeout")
        .and_then(SerialRouteDomains::begin_closeout);
    // Actor cancellation is monotonic-safe and must not wait behind GPIO,
    // serial-domain, or API closeout. This gives bounded blocking workers the
    // whole terminal schedule in which to relinquish their retained views.
    runtime_threads.request_stop();
    let mut watchdog = watchdog_owner.take();
    let mut teardown_budget: Option<TeardownBudget> = None;
    let mut teardown_view: Option<TeardownBudgetView> = None;
    let mut teardown_admission = None;
    let teardown_request_result = match watchdog.as_mut() {
        Some(watchdog) => match watchdog.request_teardown_budget() {
            Ok(request) => {
                let (budget, admission) = request.into_parts();
                teardown_view = Some(budget.view());
                teardown_budget = Some(budget);
                teardown_admission = Some(admission);
                Ok(())
            }
            Err(error) => Err(error),
        },
        None => Err(anyhow::anyhow!(
            "NoPic watchdog owner disappeared during failure closeout"
        )),
    };

    // A pre-existing emergency receipt is diagnostic only. Repeat the checked
    // load-bearing cut after this watchdog published its absolute schedule.
    let _prior_emergency_cut = prior_emergency_cut;
    let first_stage_result = run_timed_terminal_owner_operation_blocking(
        psu_guard,
        NoPicPsuGuard::new(),
        "NoPic failure first-stage safe-off",
        |guard| guard.first_stage_safe_off(),
    )
    .await;
    if let Err(error) = &first_stage_result {
        warn!(
            %error,
            "NoPic first-stage GPIO cutoff failed; bounded closeout and terminal checked safe-off continue with the watchdog armed"
        );
    }
    let cutoff_timing_result = first_stage_result.and_then(|timed| {
        ExactSerialTeardownProgress::after_nopic_checked_cut(
            teardown_view
                .as_ref()
                .context("NoPic teardown budget was unavailable at first-stage cutoff")?
                .clone(),
            timed,
        )
    });
    let teardown_result = match teardown_request_result {
        Err(error) => Err(error),
        Ok(()) => match (
            watchdog.as_mut(),
            teardown_admission.take(),
            teardown_view.as_ref(),
        ) {
            (Some(watchdog), Some(admission), Some(view)) => watchdog
                .observe_teardown_admission(admission, view)
                .await
                .map_err(anyhow::Error::msg),
            (None, _, _) => Err(anyhow::anyhow!(
                "NoPic watchdog owner disappeared before Teardown acknowledgement"
            )),
            (_, None, _) => Err(anyhow::anyhow!(
                "NoPic watchdog Teardown acknowledgement authority was unavailable"
            )),
            (_, _, None) => Err(anyhow::anyhow!(
                "NoPic watchdog teardown budget view was unavailable"
            )),
        },
    };

    let (mut serial_barrier_result, api_closeout_result) = match route_closeout {
        Ok(revoked) => {
            let (revoked_serial, revoked_api) = revoked.split_for_closeout();
            let serial_timeout =
                remaining_exact_serial_cleanup(teardown_view.as_ref(), RUNTIME_THREAD_STOP_TIMEOUT);
            let serial = revoked_serial
                .complete(serial_timeout, "native NoPic failure")
                .await;
            let api_timeout =
                remaining_exact_serial_cleanup(teardown_view.as_ref(), RUNTIME_THREAD_STOP_TIMEOUT);
            let api = revoked_api
                .complete(api_timeout, "native NoPic failure API")
                .await;
            (serial, api)
        }
        Err(error) => {
            let detail = format!("NoPic route revocation failed: {error:#}");
            (
                Err(anyhow::anyhow!(detail.clone())),
                Err(anyhow::anyhow!(detail)),
            )
        }
    };
    let actor_closeout_admission = serial_barrier_result
        .as_mut()
        .ok()
        .and_then(|closeout| closeout.take_actor_closeout_admission().ok());
    let thread_stop = runtime_threads
        .stop_and_join(
            remaining_exact_serial_cleanup(teardown_view.as_ref(), RUNTIME_THREAD_STOP_TIMEOUT),
            actor_closeout_admission,
        )
        .await;
    let actor_receipt_result = thread_stop.into_nopic_receipt();
    // An emergency receipt proves only that power was cut promptly. Repeat the
    // checked GPIO-low readback now, after serial/API fencing and actor join, so
    // stale pre-fence evidence can never authorize watchdog Disarm.
    let safe_off_budget = teardown_view.clone();
    let management_fabric_deadline = Instant::now()
        + remaining_exact_serial_cleanup(teardown_view.as_ref(), RUNTIME_THREAD_STOP_TIMEOUT);
    let power_receipt_result = run_terminal_owner_operation_blocking(
        psu_guard,
        NoPicPsuGuard::new(),
        "NoPic failure checked safe-off",
        move |guard| guard.safe_off(safe_off_budget, management_fabric_deadline),
    )
    .await
    .context("NoPic failure checked safe-off failed");

    let mut prerequisite_errors = Vec::new();
    if let Err(error) = &teardown_result {
        prerequisite_errors.push(format!("watchdog Teardown admission failed: {error:#}"));
    }
    if let Err(error) = &serial_barrier_result {
        prerequisite_errors.push(format!("serial execution barrier failed: {error:#}"));
    }
    if let Err(error) = &api_closeout_result {
        prerequisite_errors.push(format!("API mutation closeout failed: {error:#}"));
    }
    if let Err(error) = &actor_receipt_result {
        prerequisite_errors.push(format!("NoPic actor roster closeout failed: {error:#}"));
    }
    if let Err(error) = &power_receipt_result {
        prerequisite_errors.push(format!("checked safe-off failed: {error:#}"));
    }
    if let Err(error) = &cutoff_timing_result {
        prerequisite_errors.push(format!("absolute cutoff timing failed: {error:#}"));
    }
    if !prerequisite_errors.is_empty() {
        // Do not write the watchdog magic-close value without complete typed
        // evidence. Dropping an armed owner deliberately leaves the external
        // watchdog as the final backstop, but only after serial/API fencing,
        // actor cancellation, and checked safe-off have all been attempted.
        return Err(anyhow::anyhow!(
            "native NoPic failure closeout incomplete: {}",
            prerequisite_errors.join("; ")
        ));
    }

    teardown_result?;
    let serial_barrier = serial_barrier_result?;
    let api_closeout = api_closeout_result?;
    let actor_receipt = actor_receipt_result?;
    let power_receipt = power_receipt_result?;
    let teardown_receipt = cutoff_timing_result?.complete(Instant::now())?;
    let teardown_disarm = teardown_budget
        .context("NoPic teardown budget was unavailable after completed safety legs")?
        .begin_disarm_at(Instant::now())?;
    let watchdog = watchdog.context("NoPic watchdog owner missing after completed safety legs")?;
    let manifest = NoPicWatchdogShutdownManifest::new(
        serial_barrier,
        api_closeout,
        actor_receipt,
        power_receipt,
        teardown_receipt,
        teardown_disarm,
    );
    let permit = WatchdogDisarmPermit::from_nopic_manifest(manifest)?;
    watchdog
        .disarm_and_join(permit, DEFAULT_WATCHDOG_STOP_TIMEOUT)
        .await
}

fn failure_with_closeout(
    primary: anyhow::Error,
    closeout: Result<WatchdogCloseoutReceipt>,
) -> anyhow::Error {
    match closeout {
        Ok(receipt) => terminal_safe_off_error(primary, receipt),
        Err(closeout_error) => watchdog_reset_pending_error(
            "native serial NoPic",
            format!("{primary:#}; terminal failure closeout also failed: {closeout_error:#}"),
        ),
    }
}

async fn closeout_am2_bm1362_failure(
    watchdog_owner: &mut Option<SafetyWatchdogOwner>,
    route_domains: &mut Option<SerialRouteDomains>,
    power_guard: &mut Am2PsuRuntimeGuard,
    runtime_threads: &mut SerialRuntimeThreads,
) -> Result<WatchdogCloseoutReceipt> {
    let mut watchdog = watchdog_owner.take();
    let route_closeout = route_domains
        .take()
        .context("AM2 BM1362 route-domain owner disappeared during failure closeout")
        .and_then(SerialRouteDomains::begin_closeout);
    // Stop keep-alive authority as soon as mutation domains are synchronously
    // revoked. The later join repeats cancellation and produces the receipt.
    runtime_threads.request_stop();
    // Publish a finite watchdog-feed deadline before any GPIO operation. A
    // wedged sysfs/MMIO cutoff can then delay software evidence, but it cannot
    // keep the watchdog in unbounded Bringup/Mining feed behavior.
    let mut teardown_budget: Option<TeardownBudget> = None;
    let mut teardown_view: Option<TeardownBudgetView> = None;
    let mut teardown_admission = None;
    let teardown_request_result = match watchdog.as_mut() {
        Some(watchdog) => match watchdog.request_teardown_budget() {
            Ok(request) => {
                let (budget, admission) = request.into_parts();
                teardown_view = Some(budget.view());
                teardown_budget = Some(budget);
                teardown_admission = Some(admission);
                Ok(())
            }
            Err(error) => Err(error),
        },
        None => Err(anyhow::anyhow!(
            "AM2 BM1362 watchdog owner disappeared during terminal closeout"
        )),
    };
    let first_stage_worker = run_timed_terminal_owner_operation_blocking(
        power_guard,
        Am2PsuRuntimeGuard::new(),
        "AM2 BM1362 failure first-stage safe-off",
        |guard| {
            Ok(attempt_am2_first_stage_cut(
                guard,
                "bm1362-failure-closeout",
            ))
        },
    )
    .await;
    let (first_stage_cut, cutoff_timing_result) = match first_stage_worker {
        Ok(timed) => {
            ExactSerialTeardownProgress::after_am2_checked_cut(teardown_view.clone(), timed)
        }
        Err(error) => {
            let detail = format!("{error:#}");
            (
                Am2FirstStageCutAttempt { result: Err(error) },
                Err(anyhow::anyhow!(
                    "AM2 first-stage cutoff worker produced no timing evidence: {detail}"
                )),
            )
        }
    };
    let teardown_result = match teardown_request_result {
        Err(error) => Err(error),
        Ok(()) => match (
            watchdog.as_mut(),
            teardown_admission.take(),
            teardown_view.as_ref(),
        ) {
            (Some(watchdog), Some(admission), Some(view)) => watchdog
                .observe_teardown_admission(admission, view)
                .await
                .map_err(anyhow::Error::msg),
            (None, _, _) => Err(anyhow::anyhow!(
                "AM2 BM1362 watchdog owner disappeared before Teardown acknowledgement"
            )),
            (_, None, _) => Err(anyhow::anyhow!(
                "AM2 BM1362 watchdog Teardown acknowledgement authority was unavailable"
            )),
            (_, _, None) => Err(anyhow::anyhow!(
                "AM2 BM1362 watchdog teardown budget view was unavailable"
            )),
        },
    };
    let cut_failure = first_stage_cut
        .result
        .as_ref()
        .err()
        .map(|error| format!("{error:#}"));
    let feed_suppression_result = if let Some(detail) = cut_failure.as_ref() {
        match watchdog.as_mut() {
            Some(watchdog) => {
                watchdog
                    .suppress_feeds_terminally(format!(
                        "AM2 first-stage GPIO cutoff remained unverified: {detail}"
                    ))
                    .await
            }
            None => Err(anyhow::anyhow!(
                "AM2 BM1362 watchdog owner disappeared before terminal feed suppression"
            )),
        }
    } else {
        Ok(())
    };
    let (emergency_cut_result, mut serial_barrier_result, api_closeout_result) =
        match route_closeout {
            Ok(revoked) => {
                let (revoked_serial, revoked_api) = revoked.split_for_closeout();
                let revoked_serial =
                    record_am2_first_stage_cut_after_revocation(revoked_serial, first_stage_cut);
                let serial_closeout = wait_am2_serial_domain_after_revocation(
                    revoked_serial,
                    remaining_exact_serial_cleanup(
                        teardown_view.as_ref(),
                        RUNTIME_THREAD_STOP_TIMEOUT,
                    ),
                )
                .await;
                let api_closeout = revoked_api
                    .complete(
                        remaining_exact_serial_cleanup(
                            teardown_view.as_ref(),
                            RUNTIME_THREAD_STOP_TIMEOUT,
                        ),
                        "AM2 BM1362 failure API",
                    )
                    .await;
                (
                    serial_closeout.first_stage_cut,
                    serial_closeout.serial_barrier,
                    api_closeout,
                )
            }
            Err(error) => {
                let detail = format!("AM2 route revocation failed: {error:#}");
                (
                    first_stage_cut.result,
                    Err(anyhow::anyhow!(detail.clone())),
                    Err(anyhow::anyhow!(detail)),
                )
            }
        };

    let actor_closeout_admission = serial_barrier_result
        .as_mut()
        .ok()
        .and_then(|closeout| closeout.take_actor_closeout_admission().ok());
    let reset_closeout_result = serial_barrier_result
        .as_mut()
        .map_err(|error| {
            anyhow::anyhow!("serial closeout unavailable for reset evidence: {error:#}")
        })
        .and_then(SerialExecutionDomainCloseout::take_am2_reset_closeout);
    let thread_stop = runtime_threads
        .stop_and_join(
            remaining_exact_serial_cleanup(teardown_view.as_ref(), RUNTIME_THREAD_STOP_TIMEOUT),
            actor_closeout_admission,
        )
        .await;
    let safe_off_result = if thread_stop.any_timed_out() {
        let hard_stop_result = run_terminal_owner_operation_blocking(
            power_guard,
            Am2PsuRuntimeGuard::new(),
            "AM2 BM1362 out-of-band terminal hard stop",
            |guard| {
                guard.hard_stop_out_of_band("bm1362-terminal-thread-timeout");
                Ok(())
            },
        )
        .await;
        Err(anyhow::anyhow!(
            "AM2 BM1362 actor timeout required out-of-band safe-off without a checked receipt{}",
            hard_stop_result
                .err()
                .map(|error| format!("; hard-stop worker failed: {error:#}"))
                .unwrap_or_default()
        ))
    } else {
        let safe_off_budget = teardown_view.clone();
        run_terminal_owner_operation_blocking(
            power_guard,
            Am2PsuRuntimeGuard::new(),
            "AM2 BM1362 checked terminal safe-off",
            move |guard| {
                guard.teardown_checked_retrying("bm1362-terminal-closeout", true, safe_off_budget)
            },
        )
        .await
        .context("AM2 BM1362 checked terminal safe-off failed")
    };
    let actor_receipt_result = thread_stop.into_am2_receipt();

    let mut prerequisite_errors = Vec::new();
    if let Err(error) = &emergency_cut_result {
        prerequisite_errors.push(format!("first-stage emergency cutoff failed: {error:#}"));
    }
    if let Err(error) = &feed_suppression_result {
        prerequisite_errors.push(format!("watchdog feed suppression failed: {error:#}"));
    }
    if let Err(error) = &teardown_result {
        prerequisite_errors.push(format!("watchdog Teardown admission failed: {error:#}"));
    }
    if let Err(error) = &serial_barrier_result {
        prerequisite_errors.push(format!("serial execution barrier failed: {error:#}"));
    }
    if let Err(error) = &api_closeout_result {
        prerequisite_errors.push(format!("API mutation closeout failed: {error:#}"));
    }
    if let Err(error) = &safe_off_result {
        prerequisite_errors.push(format!("checked safe-off failed: {error:#}"));
    }
    if let Err(error) = &actor_receipt_result {
        prerequisite_errors.push(format!("AM2 actor roster closeout failed: {error:#}"));
    }
    if let Err(error) = &reset_closeout_result {
        prerequisite_errors.push(format!("AM2 reset-domain closeout failed: {error:#}"));
    }
    if let Err(error) = &cutoff_timing_result {
        prerequisite_errors.push(format!("absolute cutoff timing failed: {error:#}"));
    }
    if !prerequisite_errors.is_empty() {
        return Err(anyhow::anyhow!(
            "AM2 BM1362 terminal closeout incomplete; watchdog left armed: {}",
            prerequisite_errors.join("; ")
        ));
    }

    teardown_result?;
    let serial_barrier = serial_barrier_result?;
    let api_closeout = api_closeout_result?;
    let reset_closeout = reset_closeout_result?;
    let actor_receipt = actor_receipt_result?;
    let safe_off = safe_off_result?;
    let safe_off_gpio = safe_off.gate().gpio();
    let disabled_dspics = safe_off.disabled_dspic_count();
    let dspic_never_armed = safe_off.dspic_was_never_armed();
    let teardown_receipt = cutoff_timing_result?.complete(Instant::now())?;
    let teardown_disarm = teardown_budget
        .context("AM2 teardown budget was unavailable after completed safety legs")?
        .begin_disarm_at(Instant::now())?;
    let watchdog = watchdog.context("AM2 watchdog owner missing after completed safety legs")?;
    let manifest = Am2SerialWatchdogShutdownManifest::new(
        serial_barrier,
        api_closeout,
        reset_closeout,
        actor_receipt,
        safe_off,
        teardown_receipt,
        teardown_disarm,
    );
    let permit = WatchdogDisarmPermit::from_am2_serial_manifest(manifest)?;
    let closeout = watchdog
        .disarm_and_join(permit, DEFAULT_WATCHDOG_STOP_TIMEOUT)
        .await?;
    info!(
        gpio = safe_off_gpio,
        disabled_dspics,
        dspic_never_armed,
        "AM2 BM1362 watchdog close observed after fenced actors and checked terminal safe-off"
    );
    Ok(closeout)
}

fn failure_with_am2_closeout(
    primary: anyhow::Error,
    closeout: Result<WatchdogCloseoutReceipt>,
) -> anyhow::Error {
    match closeout {
        Ok(receipt) => terminal_safe_off_error(primary, receipt),
        Err(closeout_error) => watchdog_reset_pending_error(
            "AM2 BM1362 direct serial",
            format!("{primary:#}; terminal closeout also failed: {closeout_error:#}"),
        ),
    }
}

fn failure_with_am2_never_energized_closeout(
    primary: anyhow::Error,
    closeout: Result<Am2NeverEnergizedCloseout>,
) -> anyhow::Error {
    match closeout {
        Ok(receipt) => never_energized_error(primary, receipt),
        Err(closeout_error) => watchdog_reset_pending_error(
            "AM2 BM1362 direct serial",
            format!("{primary:#}; never-energized closeout also failed: {closeout_error:#}"),
        ),
    }
}

fn classify_serial_terminal_result(
    topology: SerialActorTopology,
    terminal_error: Option<anyhow::Error>,
    terminal_closeout: Option<WatchdogCloseoutReceipt>,
) -> Result<()> {
    match (topology.is_exact(), terminal_error, terminal_closeout) {
        (true, Some(error), Some(closeout)) => Err(terminal_safe_off_error(error, closeout)),
        (true, Some(error), None) => Err(watchdog_reset_pending_error(
            "exact serial terminal closeout",
            format!("{error:#}; positive watchdog closeout receipt unavailable"),
        )),
        (true, None, Some(_closeout)) => Ok(()),
        (true, None, None) => Err(watchdog_reset_pending_error(
            "exact serial terminal closeout",
            "positive watchdog closeout receipt unavailable",
        )),
        (false, Some(error), _) => Err(error),
        (false, None, _) => Ok(()),
    }
}

async fn failure_with_exact_serial_closeout(
    primary: anyhow::Error,
    topology: SerialActorTopology,
    nopic_watchdog: &mut Option<SafetyWatchdogOwner>,
    am2_watchdog: &mut Option<SafetyWatchdogOwner>,
    route_domains: &mut Option<SerialRouteDomains>,
    nopic_power: &mut NoPicPsuGuard,
    am2_power: &mut Am2PsuRuntimeGuard,
    runtime_threads: &mut SerialRuntimeThreads,
) -> anyhow::Error {
    match topology {
        SerialActorTopology::ExactNoPic => {
            let closeout = closeout_native_nopic_failure(
                nopic_watchdog,
                route_domains,
                nopic_power,
                runtime_threads,
                None,
            )
            .await;
            failure_with_closeout(primary, closeout)
        }
        SerialActorTopology::ExactAm2Bm1362 => {
            let closeout = closeout_am2_bm1362_failure(
                am2_watchdog,
                route_domains,
                am2_power,
                runtime_threads,
            )
            .await;
            failure_with_am2_closeout(primary, closeout)
        }
        SerialActorTopology::LegacyNoPic | SerialActorTopology::LegacyPic => primary,
    }
}

/// Raw UART ownership plus the exact response/route execution fence. The raw
/// backend never leaves this wrapper while family-specific Amlogic init runs.
#[derive(Clone)]
struct Am2EnergizedSerialCancellation {
    shutdown: CancellationToken,
}

impl Am2EnergizedSerialCancellation {
    fn require_active(&self, operation: &'static str) -> Result<()> {
        if self.shutdown.is_cancelled() {
            anyhow::bail!(
                "AM2 BM1362 shutdown was requested; refusing subsequent {operation} commit"
            );
        }
        Ok(())
    }
}

struct ValidatedSerialBackend {
    backend: SerialChainBackend,
    execution: SerialExecutionCommitPort,
    am2_energized_cancellation: Option<Am2EnergizedSerialCancellation>,
}

impl ValidatedSerialBackend {
    fn new(backend: SerialChainBackend, execution: SerialExecutionCommitPort) -> Self {
        Self {
            backend,
            execution,
            am2_energized_cancellation: None,
        }
    }

    fn with_am2_energized_cancellation(mut self, shutdown: CancellationToken) -> Self {
        self.am2_energized_cancellation = Some(Am2EnergizedSerialCancellation { shutdown });
        self
    }

    /// Enter the validated execution fence and re-check exact AM2
    /// cancellation while the commit fence is held, immediately before the
    /// indivisible backend mutation. Every serial write/baud transition uses
    /// this one path, so cancellation during a diagnostic sleep or long init
    /// sequence prevents every later physical commit.
    fn commit<R>(
        &self,
        operation: &'static str,
        mutation: impl FnOnce() -> Result<R>,
    ) -> Result<R> {
        self.execution
            .commit(operation, || {
                if let Some(cancellation) = self.am2_energized_cancellation.as_ref() {
                    cancellation.require_active(operation)?;
                }
                mutation()
            })
            .map_err(anyhow::Error::from)
    }

    fn set_response_len(&self, body_len: usize) {
        self.backend.set_response_len(body_len);
    }

    fn set_baud(&self, baud: u32) -> Result<()> {
        self.commit("serial host baud transition", || {
            self.backend.set_baud(baud).map_err(anyhow::Error::from)
        })
    }

    fn flush_io(&self) -> Result<()> {
        self.commit("serial response flush", || {
            self.backend.flush_io().map_err(anyhow::Error::from)
        })
    }

    fn read_all_responses(&self, max_wait_ms: u64) -> Result<Vec<Vec<u8>>> {
        self.commit("serial response window read", || {
            self.backend
                .read_all_responses(max_wait_ms)
                .map_err(anyhow::Error::from)
        })
    }

    /// Issue a fresh, execution-fenced GetAddress transaction and turn only
    /// its complete CRC-clean exact-family response window into evidence.
    /// BM13xx has no request nonce, so flushing immediately before the
    /// required query is the strongest transport-local anti-staleness bound.
    fn query_chip_address_window(
        &self,
        expected_identity: dcentrald_common::AsicProtocolIdentity,
        phase: &str,
    ) -> Result<ValidatedSerialChipAddressWindow> {
        self.set_response_len(BM13XX_CMD_RESP_BODY_LEN);
        self.flush_io()
            .with_context(|| format!("{phase}: failed to clear stale serial responses"))?;
        self.send_get_address_bm1397plus()
            .with_context(|| format!("{phase}: GetAddress query did not commit"))?;
        std::thread::sleep(Duration::from_millis(200));
        let responses = self
            .read_all_responses(500)
            .with_context(|| format!("{phase}: GetAddress response read failed"))?;
        let window = validate_serial_chip_address_window(responses.iter().map(Vec::as_slice))
            .map_err(|error| {
                anyhow::anyhow!("{phase}: ChipAddress validation failed: {error:?}")
            })?;
        if window.identity() != expected_identity {
            anyhow::bail!(
                "{phase}: response family {:?} does not match expected {:?}",
                window.identity(),
                expected_identity
            );
        }
        Ok(window)
    }

    /// P1-3: pure `TransportOp` → HAL `execute_transport_op_bm1397plus` →
    /// inherent serial I/O. All serial-mining BM1397+ command traffic shares
    /// this surface (not a second open-coded matrix).
    fn execute_bm1397plus_op(&self, operation: &'static str, op: TransportOp) -> Result<()> {
        self.commit(operation, || {
            execute_transport_op_bm1397plus(&self.backend, &op)
                .map_err(|e| anyhow::anyhow!("serial transport op execute: {e}"))
        })
    }

    fn send_get_address_bm1397plus(&self) -> Result<()> {
        self.execute_bm1397plus_op(
            "serial GetAddress query",
            TransportOp::SendGetAddressBm1397Plus,
        )
    }

    fn send_chain_inactive_bm1397plus(&self) -> Result<()> {
        self.execute_bm1397plus_op(
            "serial ChainInactive",
            TransportOp::SendChainInactiveBm1397Plus,
        )
    }

    fn send_set_address_bm1397plus(&self, address: u8) -> Result<()> {
        self.execute_bm1397plus_op(
            "serial SetAddress",
            TransportOp::SendSetAddressBm1397Plus { addr: address },
        )
    }

    fn send_write_reg_broadcast_bm1397plus(&self, register: u8, value: u32) -> Result<()> {
        self.execute_bm1397plus_op(
            "serial broadcast register write",
            TransportOp::SendWriteRegBroadcastBm1397Plus {
                reg: register,
                value,
            },
        )
    }

    fn send_write_reg_bm1397plus(&self, chip_address: u8, register: u8, value: u32) -> Result<()> {
        self.execute_bm1397plus_op(
            "serial addressed register write",
            TransportOp::SendWriteRegBm1397Plus {
                chip_addr: chip_address,
                reg: register,
                value,
            },
        )
    }

    fn send_work(&self, frame: &[u8]) -> Result<()> {
        self.commit("serial mining work send", || {
            self.backend.send_work(frame).map_err(anyhow::Error::from)
        })
    }

    fn read_nonce_response(&self) -> Result<Option<Vec<u8>>> {
        self.commit("serial nonce response read", || {
            self.backend
                .read_nonce_response()
                .map_err(anyhow::Error::from)
        })
    }
}

enum SerialWorkTransport {
    Legacy(SerialChainBackend),
    Validated(ValidatedSerialBackend),
}

#[derive(Debug)]
enum SerialActorExit {
    Cancelled,
    Failed(String),
}

#[derive(Debug)]
enum Am2PicHeartbeatExit {
    Failed(String),
}

fn require_actor_fresh_before_mining<T: std::fmt::Debug>(
    actor: &'static str,
    exit_rx: &mut mpsc::UnboundedReceiver<T>,
) -> Result<()> {
    match exit_rx.try_recv() {
        Err(mpsc::error::TryRecvError::Empty) => Ok(()),
        Ok(exit) => anyhow::bail!(
            "{actor} exited before exact watchdog Mining admission: {exit:?}"
        ),
        Err(mpsc::error::TryRecvError::Disconnected) => anyhow::bail!(
            "{actor} exit channel closed before exact watchdog Mining admission (panic or sender loss)"
        ),
    }
}

fn require_exact_serial_actor_freshness(
    topology: SerialActorTopology,
    monitor_serial_actor: bool,
    am2_apw_topology: Option<Am2ApwActorTopology>,
    am2_apw_heartbeat_required: bool,
    serial_actor_exit_rx: &mut mpsc::UnboundedReceiver<SerialActorExit>,
    am2_pic_heartbeat_exit_rx: &mut mpsc::UnboundedReceiver<Am2PicHeartbeatExit>,
    am2_apw_heartbeat_exit_rx: &mut mpsc::UnboundedReceiver<String>,
) -> Result<()> {
    anyhow::ensure!(
        monitor_serial_actor,
        "exact direct-serial Mining admission requires an observable serial-I/O actor"
    );
    require_actor_fresh_before_mining("serial-I/O actor", serial_actor_exit_rx)?;
    match topology {
        SerialActorTopology::ExactNoPic => {
            anyhow::ensure!(
                am2_apw_topology.is_none() && !am2_apw_heartbeat_required,
                "exact NoPic Mining admission retained AM2 APW topology"
            );
        }
        SerialActorTopology::ExactAm2Bm1362 => {
            let apw_topology = am2_apw_topology
                .context("exact AM2 actor freshness requires typed APW topology")?;
            anyhow::ensure!(
                am2_apw_heartbeat_required == matches!(apw_topology, Am2ApwActorTopology::SmartPsu),
                "exact AM2 APW heartbeat requirement disagrees with typed topology"
            );
            require_actor_fresh_before_mining(
                "AM2 dsPIC-heartbeat actor",
                am2_pic_heartbeat_exit_rx,
            )?;
            if matches!(apw_topology, Am2ApwActorTopology::SmartPsu) {
                require_actor_fresh_before_mining(
                    "AM2 APW-heartbeat actor",
                    am2_apw_heartbeat_exit_rx,
                )?;
            }
        }
        SerialActorTopology::LegacyNoPic | SerialActorTopology::LegacyPic => {
            anyhow::bail!("legacy serial topology cannot request exact actor freshness")
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Am2HeartbeatDisposition {
    Healthy { recovered_failures: u32 },
    Retrying { consecutive_failures: u32 },
    Terminal { consecutive_failures: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Am2NonceSafetyTrip {
    StartupNoNonce,
    MidRunNonceStall,
}

/// Pool-state text alone is not physical hashing evidence: startup emits
/// Connecting/Authorized and donation mode can be announced before its TCP
/// connection exists.  Terminal disconnect handling therefore requires both
/// a previously observed pool-hashing state and at least one UART work commit.
#[derive(Debug, Default)]
struct Am2PoolDisconnectSafety {
    pool_hashing_was_allowed: bool,
    terminal: bool,
}

impl Am2PoolDisconnectSafety {
    fn observe(
        &mut self,
        pool_hashing_allowed: bool,
        pool_hashing_ever_allowed: bool,
        committed_work_epoch: u64,
        hash_on_disconnect_enabled: bool,
    ) -> bool {
        self.pool_hashing_was_allowed |= pool_hashing_allowed || pool_hashing_ever_allowed;
        if self.terminal || hash_on_disconnect_enabled {
            return false;
        }
        if !pool_hashing_allowed && self.pool_hashing_was_allowed && committed_work_epoch != 0 {
            self.terminal = true;
            return true;
        }
        false
    }
}

#[derive(Debug)]
struct Am2NonceSafetyGuard {
    startup_timeout: Option<Duration>,
    mid_run_timeout: Option<Duration>,
    first_dispatch_at: Option<Duration>,
    last_valid_nonce_at: Option<Duration>,
    terminal: bool,
}

impl Am2NonceSafetyGuard {
    fn new(timeout_s: u64, mid_run_timeout: Option<Duration>) -> Self {
        let startup_timeout = (timeout_s != 0).then(|| Duration::from_secs(timeout_s));
        Self {
            startup_timeout,
            mid_run_timeout,
            first_dispatch_at: None,
            last_valid_nonce_at: None,
            terminal: false,
        }
    }

    fn observe_dispatch(&mut self, now: Duration) {
        self.first_dispatch_at.get_or_insert(now);
    }

    fn observe_valid_nonce(&mut self, now: Duration) {
        self.last_valid_nonce_at = Some(now);
    }

    fn pause_for_missing_pool_authority(&mut self) {
        self.first_dispatch_at = None;
        self.last_valid_nonce_at = None;
    }

    fn evaluate(&mut self, now: Duration) -> Option<Am2NonceSafetyTrip> {
        if self.terminal {
            return None;
        }
        let trip = if let Some(last_nonce) = self.last_valid_nonce_at {
            self.mid_run_timeout
                .filter(|timeout| now.saturating_sub(last_nonce) >= *timeout)
                .map(|_| Am2NonceSafetyTrip::MidRunNonceStall)
        } else {
            self.first_dispatch_at.and_then(|first_dispatch| {
                self.startup_timeout
                    .filter(|timeout| now.saturating_sub(first_dispatch) >= *timeout)
                    .map(|_| Am2NonceSafetyTrip::StartupNoNonce)
            })
        };
        if trip.is_some() {
            self.terminal = true;
        }
        trip
    }
}

fn observe_am2_heartbeat_result(
    consecutive_failures: &mut u32,
    succeeded: bool,
    terminal_failure_limit: u32,
) -> Am2HeartbeatDisposition {
    if succeeded {
        let recovered_failures = *consecutive_failures;
        *consecutive_failures = 0;
        return Am2HeartbeatDisposition::Healthy { recovered_failures };
    }
    *consecutive_failures = consecutive_failures.saturating_add(1);
    if *consecutive_failures >= terminal_failure_limit.max(1) {
        Am2HeartbeatDisposition::Terminal {
            consecutive_failures: *consecutive_failures,
        }
    } else {
        Am2HeartbeatDisposition::Retrying {
            consecutive_failures: *consecutive_failures,
        }
    }
}

fn am2_apw_heartbeat_wire_retryable(error: &dcentrald_hal::HalError) -> bool {
    matches!(
        error,
        dcentrald_hal::HalError::I2c { .. } | dcentrald_hal::HalError::PsuHeartbeatExhausted { .. }
    )
}

fn publish_am2_apw_heartbeat_terminal(
    lifecycle_shutdown: &CancellationToken,
    terminal_exit: &mpsc::UnboundedSender<String>,
    reason: String,
) -> bool {
    // Cancellation that was already visible linearizes an ordinary operator
    // shutdown before this in-flight heartbeat result. Do not relabel it as a
    // terminal hardware failure. If cancellation begins after this check, the
    // heartbeat failure has already won the publication election below.
    if lifecycle_shutdown.is_cancelled() {
        return false;
    }
    // Publish the diagnostic first. A biased receiver can then preserve the
    // exact cause even though cancellation and the channel become ready in
    // the same scheduler turn.
    let _ = terminal_exit.send(reason);
    lifecycle_shutdown.cancel();
    true
}

struct Am2ApwHeartbeatActorExitGuard {
    runtime_shutdown: CancellationToken,
    lifecycle_shutdown: CancellationToken,
    terminal_exit: mpsc::UnboundedSender<String>,
}

impl Drop for Am2ApwHeartbeatActorExitGuard {
    fn drop(&mut self) {
        if !self.runtime_shutdown.is_cancelled() && !self.lifecycle_shutdown.is_cancelled() {
            let _ = publish_am2_apw_heartbeat_terminal(
                &self.lifecycle_shutdown,
                &self.terminal_exit,
                "APW heartbeat actor exited unexpectedly without a terminal receipt".to_string(),
            );
        }
    }
}

fn am2_pic_heartbeat_failure_limit(effective_watchdog_timeout_s: u32) -> Option<u32> {
    // The watchdog's mining stall policy is bounded by roughly half its
    // effective timeout. Leave a full second of margin so the heartbeat actor
    // requests an explicit GPIO cutoff before even the shortest admitted
    // watchdog can reset the SoC. Long windows retain the evidence-backed
    // hybrid-runtime ceiling of twenty consecutive 1 Hz failures.
    if effective_watchdog_timeout_s < AM2_BM1362_MIN_WATCHDOG_TIMEOUT_S {
        return None;
    }
    let explicit_cut_budget_s =
        (effective_watchdog_timeout_s / 2).saturating_sub(AM2_BM1362_EMERGENCY_CUT_MARGIN_S);
    Some(
        (explicit_cut_budget_s / AM2_BM1362_PIC_HEARTBEAT_ATTEMPT_BUDGET_S)
            .clamp(1, AM2_BM1362_PIC_HEARTBEAT_MAX_FAILURES),
    )
}

impl SerialWorkTransport {
    fn send_work(&self, frame: &[u8]) -> Result<()> {
        match self {
            Self::Legacy(backend) => Ok(backend.send_work(frame)?),
            Self::Validated(backend) => backend.send_work(frame),
        }
    }

    fn read_nonce_response(&self) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Legacy(backend) => Ok(backend.read_nonce_response()?),
            Self::Validated(backend) => backend.read_nonce_response(),
        }
    }
}

trait SerialActorBackend {
    fn actor_send_work(&self, frame: &[u8]) -> Result<()>;
    fn actor_read_nonce_response(&self) -> Result<Option<Vec<u8>>>;
}

impl SerialActorBackend for SerialWorkTransport {
    fn actor_send_work(&self, frame: &[u8]) -> Result<()> {
        self.send_work(frame)
    }

    fn actor_read_nonce_response(&self) -> Result<Option<Vec<u8>>> {
        self.read_nonce_response()
    }
}

#[allow(clippy::too_many_arguments)]
fn run_serial_io_actor<B: SerialActorBackend>(
    serial: B,
    work_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    nonce_tx: mpsc::Sender<Vec<u8>>,
    shutdown: CancellationToken,
    progress: Arc<AtomicU64>,
    committed_work_epoch: Arc<AtomicU64>,
    exact_am2_bm1362: bool,
    tx_burst_per_loop: usize,
    tx_before_rx: bool,
) -> SerialActorExit {
    info!(
        tx_burst_per_loop,
        tx_before_rx,
        "Serial I/O thread started (VTIME=1, bounded queue, family-specific TX scheduler)"
    );
    let mut total_frames: u64 = 0;
    let mut total_tx: u64 = 0;
    let mut last_diag = Instant::now();
    let mut terminal_error: Option<String> = None;
    let mut consecutive_read_errors = 0u8;

    let mut drain_tx = |limit: usize, total_tx: &mut u64| -> Result<()> {
        for _ in 0..limit {
            let frame = work_queue
                .lock()
                .unwrap_or_else(|error| {
                    warn!("work_queue mutex poisoned, recovering");
                    error.into_inner()
                })
                .pop_front();
            let Some(frame) = frame else { break };
            serial
                .actor_send_work(&frame)
                .context("serial work send failed")?;
            *total_tx = total_tx.saturating_add(1);
            progress.fetch_add(1, Ordering::Release);
            if exact_am2_bm1362 {
                committed_work_epoch.fetch_add(1, Ordering::Release);
            }
        }
        Ok(())
    };

    'serial_io: loop {
        if shutdown.is_cancelled() {
            break;
        }

        if tx_before_rx {
            if let Err(error) = drain_tx(tx_burst_per_loop, &mut total_tx) {
                terminal_error = Some(format!("{error:#}"));
                break;
            }
        }

        match serial.actor_read_nonce_response() {
            Ok(Some(data)) => {
                consecutive_read_errors = 0;
                progress.fetch_add(1, Ordering::Release);
                total_frames = total_frames.saturating_add(1);
                if nonce_tx.blocking_send(data).is_err() {
                    terminal_error = Some(
                        "serial nonce receiver closed while actor remained active".to_string(),
                    );
                    break;
                }
                // Once one response arrives, drain a bounded window without
                // blocking. Receiver loss here is terminal for the outer actor,
                // not merely the inner drain loop.
                for _ in 0..31 {
                    match serial.actor_read_nonce_response() {
                        Ok(Some(data)) => {
                            progress.fetch_add(1, Ordering::Release);
                            total_frames = total_frames.saturating_add(1);
                            if nonce_tx.blocking_send(data).is_err() {
                                terminal_error =
                                    Some("serial nonce receiver closed during drain".to_string());
                                break 'serial_io;
                            }
                        }
                        _ => break,
                    }
                }
            }
            Ok(None) => {
                consecutive_read_errors = 0;
                // An empty bounded VTIME poll proves the serial actor itself
                // is schedulable, but does not feed the separate nonce guard.
                progress.fetch_add(1, Ordering::Release);
            }
            Err(error) => {
                consecutive_read_errors = consecutive_read_errors.saturating_add(1);
                warn!(%error, consecutive_read_errors, "Serial nonce read failed");
                if consecutive_read_errors >= 3 {
                    terminal_error = Some(format!(
                        "serial nonce read failed {consecutive_read_errors} consecutive times: {error}"
                    ));
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        if !tx_before_rx {
            if let Err(error) = drain_tx(tx_burst_per_loop, &mut total_tx) {
                terminal_error = Some(format!("{error:#}"));
                break;
            }
        }

        if last_diag.elapsed() > Duration::from_secs(10) {
            info!(
                total_frames,
                total_tx, "Serial I/O: {} RX nonces, {} TX work sent", total_frames, total_tx,
            );
            last_diag = Instant::now();
        }
    }

    if shutdown.is_cancelled() {
        SerialActorExit::Cancelled
    } else {
        SerialActorExit::Failed(terminal_error.unwrap_or_else(|| {
            "serial I/O actor exited without cancellation or an explicit error".to_string()
        }))
    }
}

/// Immutable startup authority for degraded BM1366 enumeration.
///
/// `rambo_mode_max_bad_responses` decides whether a partial GetAddress result
/// may proceed into ChainInactive, address, and PLL writes. It must therefore
/// be captured before any rail is energized and reused for every fallback UART
/// attempt in this mining generation. Deliberately do not implement `Clone` or
/// `Copy`: this policy belongs to one serial-miner lifecycle.
#[must_use = "BM1366 enumeration admission must remain bound to its startup generation"]
#[derive(Debug, PartialEq, Eq)]
struct Bm1366EnumerationAdmission {
    expected_chip_count: u8,
    configured_max_bad_responses: u8,
    minimum_required_responses: usize,
}

impl Bm1366EnumerationAdmission {
    fn from_startup_policy(
        expected_chip_count: u8,
        configured_max_bad_responses: u8,
    ) -> Result<Self> {
        if expected_chip_count == 0 {
            anyhow::bail!("BM1366 enumeration admission requires at least one expected chip");
        }
        let minimum_required_responses = usize::from(
            expected_chip_count
                .saturating_sub(configured_max_bad_responses)
                .max(1),
        );
        Ok(Self {
            expected_chip_count,
            configured_max_bad_responses,
            minimum_required_responses,
        })
    }

    fn admits_response_count(&self, observed_responses: usize) -> bool {
        observed_responses >= self.minimum_required_responses
    }
}

fn admit_serial_driver_execution(
    chip_id: u16,
    executable_experimental_chip_ids: &[u16],
) -> Result<ChipDriverAdmission> {
    let registry = if executable_experimental_chip_ids.contains(&chip_id) {
        ChipRegistry::with_experimental_driver(chip_id)
    } else {
        ChipRegistry::production()
    };
    registry.admit(chip_id).with_context(|| {
        format!(
            "serial ASIC driver 0x{chip_id:04X} is not executable under the immutable boot policy; Experimental drivers require executable_asic_chip_ids to contain this exact chip ID"
        )
    })
}

/// Acquire a blocking runtime owner's mutex without allowing lock contention
/// to hide cancellation. Poison preserves access to the retained owner for
/// fail-safe handling; ordinary contention is polled in short cancellable
/// intervals.
fn lock_runtime_owner_until_cancelled<'a, T>(
    owner: &'a Mutex<T>,
    shutdown: &CancellationToken,
    owner_name: &'static str,
) -> Option<std::sync::MutexGuard<'a, T>> {
    loop {
        match owner.try_lock() {
            Ok(guard) => return Some(guard),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                warn!(
                    owner = owner_name,
                    "runtime owner mutex was poisoned; recovering"
                );
                return Some(poisoned.into_inner());
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                if sleep_until_cancelled(shutdown, Duration::from_millis(20)) {
                    return None;
                }
            }
        }
    }
}

impl SerialMiner {
    pub fn new(
        config: DcentraldConfig,
        shutdown: CancellationToken,
        runtime_dispatch_admission: crate::RuntimeDispatchAdmission,
        am2_bm1362_serial_route_admission: Option<
            crate::am2_bm1362_serial_admission::Am2Bm1362SerialRouteAdmission,
        >,
    ) -> Result<Self> {
        let (resolved_chip_id, _) = resolve_native_serial_identity_and_geometry(
            config.mining.model.as_deref(),
            config.mining.serial_chip_count,
        )?;
        let identity = dcentrald_common::AsicProtocolIdentity::from_chip_id(resolved_chip_id)
            .context("native serial identity has no protocol-admission representation")?;
        let runtime_dispatch_admission = runtime_dispatch_admission
            .require_serial_asic_protocol(identity)
            .map_err(anyhow::Error::msg)?;
        let serial_device = config
            .mining
            .serial_device
            .as_deref()
            .unwrap_or("/dev/ttyS2");
        let (runtime_dispatch_admission, am2_bm1362_route_admission) = if resolved_chip_id == 0x1362
        {
            if config.mining.passthrough {
                anyhow::bail!(
                        "BM1362 preserve-state passthrough has no typed external-owner initialization handoff; refusing direct work dispatch"
                    );
            }
            let composition = am2_bm1362_serial_route_admission.context(
                "BM1362 direct serial lacks exact startup AM2/Zynq composition admission",
            )?;
            (
                None,
                Some(Am2Bm1362DirectSerialAdmission::capture(
                    composition,
                    runtime_dispatch_admission,
                    serial_device,
                )?),
            )
        } else {
            if am2_bm1362_serial_route_admission.is_some() {
                anyhow::bail!(
                    "AM2 BM1362 composition authority contradicts the resolved serial ASIC family"
                );
            }
            (Some(runtime_dispatch_admission), None)
        };
        let experimental = crate::experimental::ExperimentalConfig::load();
        let asic_driver_admission = admit_serial_driver_execution(
            resolved_chip_id,
            &experimental.executable_asic_chip_ids,
        )?;
        Ok(Self {
            config,
            shutdown,
            runtime_dispatch_admission,
            am2_bm1362_route_admission,
            _asic_driver_admission: asic_driver_admission,
        })
    }

    fn drain_serial_passthrough_backlog(serial: &SerialChainBackend, window_ms: u64) {
        let deadline = Instant::now() + Duration::from_millis(window_ms);
        let mut drained_frames = 0usize;

        while Instant::now() < deadline {
            match serial.read_all_responses(50) {
                Ok(batch) if !batch.is_empty() => drained_frames += batch.len(),
                Ok(_) => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => {
                    warn!(error = %e, "Passthrough backlog drain read failed");
                    break;
                }
            }
        }

        let _ = serial.flush_io();
        info!(
            window_ms,
            drained_frames, "Passthrough serial backlog drained before own work dispatch"
        );
    }

    fn am2_slot_from_serial_device(serial_device: &str) -> Option<u8> {
        match serial_device {
            "/dev/ttyS1" => Some(0),
            "/dev/ttyS2" => Some(1),
            "/dev/ttyS3" => Some(2),
            "/dev/ttyS4" => Some(3),
            _ => None,
        }
    }

    fn am3_bb_uart_trans_chain_from_serial_device(serial_device: &str) -> Option<usize> {
        DEFAULT_CHAIN_TTYS
            .iter()
            .position(|path| *path == serial_device)
    }

    fn am3_bb_uart_trans_chains_from_serial_device(serial_device: &str) -> Option<Vec<usize>> {
        let mut chains = Vec::new();
        for raw in serial_device.split(',') {
            let path = raw.trim();
            if path.is_empty() {
                return None;
            }
            let chain = Self::am3_bb_uart_trans_chain_from_serial_device(path)?;
            if !chains.contains(&chain) {
                chains.push(chain);
            }
        }
        if chains.is_empty() {
            None
        } else {
            Some(chains)
        }
    }

    fn am3_bb_uart_trans_chain_bits(chains: &[usize]) -> u32 {
        chains.iter().fold(0u32, |bits, chain| {
            if *chain < DEFAULT_CHAIN_TTYS.len() {
                bits | (1u32 << chain)
            } else {
                bits
            }
        })
    }

    fn spawn_am3_bb_uart_trans_io_thread(
        serial_device: String,
        selected_chains: Vec<usize>,
        work_queue_io: Arc<Mutex<VecDeque<Vec<u8>>>>,
        nonce_tx: mpsc::Sender<Vec<u8>>,
        reader_shutdown: CancellationToken,
        work_queue_depth: usize,
        tx_burst_per_loop: usize,
    ) -> Result<std::thread::JoinHandle<()>> {
        let mut service = UartTransService::open_paths_with_baud(DEFAULT_CHAIN_TTYS, fast_baud())
            .context("am3-bb uart_trans failed to open ttyO chains")?;
        let selected_chain_bits = Self::am3_bb_uart_trans_chain_bits(&selected_chains);
        service.set_chain_exist_bits(selected_chain_bits);
        service
            .set_work_queue_count(work_queue_depth)
            .context("am3-bb uart_trans rejected queue depth")?;
        service
            .set_send_interval(Duration::from_millis(BM1362_DISPATCH_INTERVAL_MS))
            .context("am3-bb uart_trans rejected send interval")?;
        service.start_send_work_timer();

        std::thread::Builder::new()
            .name("am3-bb-uart-trans-io".to_string())
            .spawn(move || {
                info!(
                    serial_device,
                    ?selected_chains,
                    selected_chain_bits,
                    work_queue_depth,
                    tx_burst_per_loop,
                    "am3-bb uart_trans I/O thread starting"
                );

                let mut total_tx: u64 = 0;
                let mut total_nonces: u64 = 0;
                let mut last_diag = Instant::now();

                loop {
                    if reader_shutdown.is_cancelled() {
                        break;
                    }

                    for _ in 0..tx_burst_per_loop {
                        let frame = work_queue_io
                            .lock()
                            .unwrap_or_else(|e| {
                                tracing::warn!("work_queue mutex poisoned, recovering");
                                e.into_inner()
                            })
                            .pop_front();
                        let Some(frame) = frame else {
                            break;
                        };

                        let work = match UartWork::from_command_frame(&frame) {
                            Ok(work) => work,
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    frame_len = frame.len(),
                                    "am3-bb uart_trans dropped malformed BM1362 work frame"
                                );
                                continue;
                            }
                        };

                        for chain in &selected_chains {
                            if let Err(e) = service.enqueue_work(*chain, work.clone()) {
                                warn!(error = %e, chain, "am3-bb uart_trans queue failed");
                                break;
                            }
                        }
                    }

                    match service.send_due_work_once() {
                        Ok(sent) => total_tx = total_tx.saturating_add(sent as u64),
                        Err(e) => {
                            warn!(error = %e, "am3-bb uart_trans work send failed");
                            break;
                        }
                    }

                    match service.poll_nonces_once() {
                        Ok(nonces) => {
                            for (chain, nonce) in nonces {
                                if !selected_chains.contains(&chain) {
                                    debug!(
                                        chain,
                                        ?selected_chains,
                                        "am3-bb uart_trans ignored nonce from unselected chain"
                                    );
                                    continue;
                                }
                                total_nonces = total_nonces.saturating_add(1);
                                if nonce_tx
                                    .blocking_send(nonce.to_bm1362_body().to_vec())
                                    .is_err()
                                {
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "am3-bb uart_trans nonce poll failed");
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    }

                    if last_diag.elapsed() > Duration::from_secs(10) {
                        info!(
                            total_nonces,
                            total_tx,
                            "am3-bb uart_trans I/O: {} RX nonces, {} TX work sent",
                            total_nonces,
                            total_tx,
                        );
                        last_diag = Instant::now();
                    }

                    std::thread::sleep(service.send_interval());
                }

                info!("am3-bb uart_trans I/O thread exited");
            })
            .context("Failed to spawn am3-bb uart_trans I/O thread")
    }

    fn bm1362_stop_after_pre_pll_probe_enabled() -> bool {
        std::env::var_os("DCENT_BM1362_STOP_AFTER_PRE_PLL_PROBE").is_some()
    }

    fn bm1362_early_115200_probe_enabled() -> bool {
        std::env::var_os("DCENT_BM1362_EARLY_115200_PROBE").is_some()
    }

    fn bm1362_allow_stale_enable_reply_enabled() -> bool {
        std::env::var_os("DCENT_BM1362_ALLOW_STALE_ENABLE_REPLY").is_some()
    }

    fn bm1362_uart_relay_lab_enabled() -> bool {
        std::env::var_os("DCENT_BM1362_ENABLE_UART_RELAY_LAB").is_some()
    }

    fn am3_bb_uart_trans_lab_enabled() -> bool {
        std::env::var_os("DCENT_AM3_BB_ENABLE_UART_TRANS_LAB").is_some()
    }

    fn maybe_write_bm1362_uart_relay(
        serial: &ValidatedSerialBackend,
        stage: &'static str,
    ) -> Result<()> {
        if !Self::bm1362_uart_relay_lab_enabled() {
            warn!(
                stage,
                "BM1362 UART_RELAY reg 0x2C/0x34 writes skipped by default; set DCENT_BM1362_ENABLE_UART_RELAY_LAB=1 only for R6-7 capture work"
            );
            return Ok(());
        }

        serial
            .send_write_reg_broadcast_bm1397plus(BM1362_UART_RELAY_REG, BM1362_UART_RELAY_ENABLE)?;
        std::thread::sleep(Duration::from_millis(10));
        serial.send_write_reg_broadcast_bm1397plus(
            BM1362_UART_RELAY_REG_ALT,
            BM1362_UART_RELAY_ENABLE_ALT,
        )?;
        std::thread::sleep(Duration::from_millis(10));
        info!(stage, "BM1362 UART_RELAY lab-gated broadcast sent");
        Ok(())
    }

    fn is_known_pic_fw(version: u8) -> bool {
        matches!(version, 0x82 | 0x86 | 0x89 | 0x8A | 0xB9 | 0xFE)
    }

    fn is_shift_left_pic_artifact(buf: &[u8]) -> bool {
        buf.len() >= 2 && buf.windows(2).all(|w| w[1] == w[0].wrapping_shl(1))
    }

    fn classify_pic_reply(buf: &[u8]) -> &'static str {
        if buf.is_empty() {
            "empty"
        } else if buf.iter().all(|&b| b == 0x00) {
            "all-zero"
        } else if buf.iter().all(|&b| b == 0xFF) {
            "all-ff"
        } else if Self::is_shift_left_pic_artifact(buf) {
            "shift-left-bus-noise"
        } else if Self::parse_pic_fw_reply(buf, buf.len()).is_some() {
            "valid-fw"
        } else {
            "unknown"
        }
    }

    fn format_pic_probe_samples(samples: &[String]) -> String {
        samples
            .iter()
            .rev()
            .take(6)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(" | ")
    }

    fn parse_pic_fw_reply(buf: &[u8], read_len: usize) -> Option<u8> {
        let buf = &buf[..read_len.min(buf.len())];
        if buf.is_empty()
            || buf.iter().all(|&b| b == 0x00)
            || buf.iter().all(|&b| b == 0xFF)
            || Self::is_shift_left_pic_artifact(buf)
        {
            return None;
        }

        if buf.len() >= 3 && buf[0] == 0x05 && buf[1] == 0x17 && Self::is_known_pic_fw(buf[2]) {
            return Some(buf[2]);
        }
        if buf.len() >= 3 && buf[0] == 0x17 && Self::is_known_pic_fw(buf[2]) {
            return Some(buf[2]);
        }
        if Self::is_known_pic_fw(buf[0]) {
            return Some(buf[0]);
        }
        None
    }

    fn format_probe_samples(responses: &[Vec<u8>]) -> String {
        responses
            .iter()
            .take(4)
            .map(|resp| {
                resp.iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>()
            .join(" | ")
    }

    fn psu_heartbeat_loop(
        psu: Arc<Mutex<Apw121215a>>,
        shutdown: CancellationToken,
        lifecycle_shutdown: CancellationToken,
        interval: Duration,
        progress: Arc<AtomicU64>,
        terminal_exit: mpsc::UnboundedSender<String>,
    ) {
        let _exit_guard = Am2ApwHeartbeatActorExitGuard {
            runtime_shutdown: shutdown.clone(),
            lifecycle_shutdown: lifecycle_shutdown.clone(),
            terminal_exit: terminal_exit.clone(),
        };
        let mut consecutive_fails = 0u32;
        loop {
            if shutdown.is_cancelled() {
                info!("PSU heartbeat thread shutting down");
                return;
            }
            if sleep_until_cancelled(&shutdown, interval) {
                info!("PSU heartbeat thread shutting down after sleep");
                return;
            }
            let Some(mut psu) =
                lock_runtime_owner_until_cancelled(psu.as_ref(), &shutdown, "AM2 APW heartbeat")
            else {
                info!("PSU heartbeat thread shutting down while waiting for PSU ownership");
                return;
            };
            if shutdown.is_cancelled() {
                info!("PSU heartbeat thread shutting down after acquiring PSU lock");
                return;
            }
            let result = psu.heartbeat_cancellable(|| shutdown.is_cancelled());
            match result {
                Ok(()) => {
                    progress.fetch_add(1, Ordering::Release);
                    if consecutive_fails > 0 {
                        info!(
                            fails = consecutive_fails,
                            "PSU heartbeat recovered after {} fails", consecutive_fails
                        );
                        consecutive_fails = 0;
                    }
                }
                Err(e) if am2_apw_heartbeat_wire_retryable(&e) => {
                    match observe_am2_heartbeat_result(
                        &mut consecutive_fails,
                        false,
                        AM2_BM1362_APW_HEARTBEAT_MAX_FAILURES,
                    ) {
                        Am2HeartbeatDisposition::Terminal {
                            consecutive_failures,
                        } => {
                            let published = publish_am2_apw_heartbeat_terminal(
                                &lifecycle_shutdown,
                                &terminal_exit,
                                format!(
                                    "APW heartbeat wire operation failed {consecutive_failures} consecutive times: {e}"
                                ),
                            );
                            if published {
                                error!(
                                    fails = consecutive_failures,
                                    "PSU heartbeat wire failures exhausted their bounded retry budget; requesting explicit GPIO cutoff before APW watchdog expiry"
                                );
                            } else {
                                info!(
                                    fails = consecutive_failures,
                                    "PSU heartbeat wire retry budget completed during ordinary lifecycle shutdown; suppressing terminal failure publication"
                                );
                            }
                            return;
                        }
                        Am2HeartbeatDisposition::Retrying {
                            consecutive_failures,
                        } => {
                            warn!(fails = consecutive_failures, "PSU heartbeat fail: {}", e);
                        }
                        Am2HeartbeatDisposition::Healthy { .. } => {
                            unreachable!("failed APW heartbeat cannot be healthy")
                        }
                    }
                }
                Err(e) => {
                    let published = publish_am2_apw_heartbeat_terminal(
                        &lifecycle_shutdown,
                        &terminal_exit,
                        format!("APW heartbeat lost typed controller/safety authority: {e}"),
                    );
                    if published {
                        error!(
                            error = %e,
                            "PSU heartbeat lost typed controller/safety authority; requesting immediate explicit GPIO cutoff"
                        );
                    } else {
                        info!(
                            error = %e,
                            "PSU heartbeat operation completed during ordinary lifecycle shutdown; suppressing terminal failure publication"
                        );
                    }
                    return;
                }
            }
        }
    }

    fn pic_read_fw_version_service(i2c: &I2cServiceHandle, addr: u8) -> Result<(u8, Vec<u8>)> {
        // Service-only three-phase probing: flush -> write -> quiet window -> read.
        // Do not use I2C_RDWR here; it can turn a parser wedge into persistent bus noise.
        //
        // DELIBERATE DIVERGENCE from the am2-Zynq hybrid path's pic_read_fw_version_service
        // in s19j_hybrid_mining.rs (which dropped the 16-zero flush + 5-byte read in favour
        // of a bosminer-faithful no-flush, 1-byte clean read + retry, 2026-05-21). This
        // BM1362 *direct-serial* path is the am3-bb `a lab unit` / Amlogic accepted-share-proven
        // route, where the 16-zero flush is REQUIRED to clear a healthy fw=0x89 dsPIC MSSP
        // parser (see init_pic doc-comment below: "v0x89 needs 16, not 8"). The all-FF wedge
        // the hybrid fix targets is a `a lab unit`/`a lab unit` am2 phenomenon, NOT observed here. Do NOT
        // "unify" these two readers until the `a lab unit` clean-read A/B proves the flush is the
        // actual am2 FF-generator â€” unifying now would regress the proven `a lab unit` path.
        const GET_VERSION_FRAMED: [u8; 6] = [0x55, 0xAA, 0x04, 0x17, 0x00, 0x1B];
        const GET_VERSION_SHORT: [u8; 3] = [0x55, 0xAA, 0x17];
        let probes: [(&str, &[u8], usize); 2] = [
            ("framed-55aa0417001b", &GET_VERSION_FRAMED, 5),
            ("short-55aa17", &GET_VERSION_SHORT, 1),
        ];
        let mut samples = Vec::new();

        for attempt in 1..=3 {
            for (variant, frame, read_len) in probes.iter().copied() {
                let buf = match i2c.transaction_mutating(
                    I2cMutationLabel::Recovery,
                    addr,
                    vec![
                        I2cTransactionStep::SetTimeout(10),
                        I2cTransactionStep::WriteByteByByte(vec![0u8; 16]),
                        I2cTransactionStep::SleepMs(10),
                        I2cTransactionStep::Write(frame.to_vec()),
                        I2cTransactionStep::SleepMs(100),
                        I2cTransactionStep::Read(read_len),
                    ],
                ) {
                    Ok(mut reads) => match reads.pop() {
                        Some(buf) => buf,
                        None => {
                            warn!(
                                addr = format_args!("0x{:02X}", addr),
                                attempt,
                                variant,
                                "BM1362 direct PIC GET_VERSION transaction returned no read"
                            );
                            std::thread::sleep(Duration::from_millis(50));
                            continue;
                        }
                    },
                    Err(e) => {
                        samples.push(format!("{}#{}:transaction-error:{}", variant, attempt, e));
                        warn!(
                            addr = format_args!("0x{:02X}", addr),
                            attempt,
                            variant,
                            error = %e,
                            "BM1362 direct PIC GET_VERSION transaction failed"
                        );
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                };
                let class = Self::classify_pic_reply(&buf);
                samples.push(format!("{}#{}:{}:{:02X?}", variant, attempt, class, buf));
                info!(
                    addr = format_args!("0x{:02X}", addr),
                    attempt,
                    variant,
                    class,
                    read_len = buf.len(),
                    raw = format_args!("{:02X?}", buf),
                    "BM1362 direct PIC GET_VERSION service reply",
                );

                if let Some(fw) = Self::parse_pic_fw_reply(&buf, buf.len()) {
                    return Ok((fw, buf));
                }

                warn!(
                    addr = format_args!("0x{:02X}", addr),
                    attempt,
                    variant,
                    class,
                    raw = format_args!("{:02X?}", buf),
                    "BM1362 direct PIC service GET_VERSION did not return a valid firmware reply",
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        Err(anyhow::anyhow!(
            "BM1362 direct PIC service GET_VERSION failed at 0x{:02X}: no valid framed/short 0x17 response after 3 attempts; recent samples: {}",
            addr,
            Self::format_pic_probe_samples(&samples),
        ))
    }

    fn log_bm1362_probe_stage(
        serial: &ValidatedSerialBackend,
        stage: &str,
        wait_ms: u64,
    ) -> Result<()> {
        serial.set_response_len(BM13XX_CMD_RESP_BODY_LEN);
        serial
            .send_get_address_bm1397plus()
            .with_context(|| format!("BM1362 {stage} diagnostic GetAddress did not commit"))?;
        std::thread::sleep(Duration::from_millis(wait_ms));
        let responses = serial.read_all_responses(500)?;
        info!(
            stage,
            responses = responses.len(),
            samples = %Self::format_probe_samples(&responses),
            "BM1362 probe ladder"
        );
        Ok(())
    }

    /// Reset ASICs to 115200 baud from any previous baud rate (hot-start recovery).
    ///
    /// After power cycle, ASICs default to 115200 so this is a no-op.
    /// After killing previous firmware, ASICs may be at 1.5625M or 3.125M.
    /// Pure ladder + dual-spray from `plan_hot_start_*` (P1-1 dual-spray residual
    /// closed): BM1387-form then BM1397+ at each open baud. Host open/close remains
    /// engine policy.
    fn reset_asic_baud(serial_device: &str) {
        let fb = fast_baud();
        let stages = plan_hot_start_baud_wake_ladder_from_fast_baud(fb);
        let spray_ops = plan_hot_start_dual_spray_ops();
        info!(
            "Hot-start baud reset: pure ladder stages={} dual-spray ops={} fast={}",
            stages.len(),
            spray_ops.len(),
            fb
        );

        for stage in stages {
            if let Ok(serial) = SerialChainBackend::open(0, serial_device, stage.baud) {
                info!(
                    baud = stage.baud,
                    label = stage.label,
                    "Hot-start baud-wake stage (pure dual-spray: BM1387-form + BM1397+)"
                );
                // Pure dual-spray SSOT — family-dispatched (not open-coded halves).
                for op in &spray_ops {
                    match op {
                        HotStartSprayOp::ChainInactive {
                            family: HotStartCommandFamily::Bm1387Form,
                        } => {
                            let _ = serial.send_chain_inactive();
                        }
                        HotStartSprayOp::WriteRegBroadcast {
                            family: HotStartCommandFamily::Bm1387Form,
                            reg,
                            value,
                        } => {
                            let _ = serial.send_write_reg_broadcast(*reg, *value);
                        }
                        HotStartSprayOp::ChainInactive {
                            family: HotStartCommandFamily::Bm1397Plus,
                        } => {
                            let _ = serial.send_chain_inactive_bm1397plus();
                        }
                        HotStartSprayOp::WriteRegBroadcast {
                            family: HotStartCommandFamily::Bm1397Plus,
                            reg,
                            value,
                        } => {
                            let _ = serial.send_write_reg_broadcast_bm1397plus(*reg, *value);
                        }
                        HotStartSprayOp::DelayMs { ms } => {
                            std::thread::sleep(Duration::from_millis(u64::from(*ms)));
                        }
                    }
                }
                drop(serial);
            }
        }

        std::thread::sleep(Duration::from_millis(u64::from(
            HOT_START_POST_LADDER_SETTLE_MS,
        )));
        info!("Baud reset complete — ASICs should be at 115200");
    }

    /// P1-1: MiscCtrl cadence is pure SSOT (`plan_misc_ctrl_triple_write_*`).
    /// Value selection remains engine policy (init / post-fast / hot-start).
    fn bm1362_misc_ctrl_triple_write_serial(
        serial: &ValidatedSerialBackend,
        value: u32,
    ) -> Result<()> {
        for (i, op) in plan_misc_ctrl_triple_write_broadcast(value)
            .into_iter()
            .enumerate()
        {
            serial
                .execute_bm1397plus_op("BM1362 MiscCtrl triple-write", op)
                .with_context(|| {
                    format!(
                        "BM1362 MiscCtrl triple-write op {}/{}",
                        i + 1,
                        // 3 writes + 3 delays
                        6
                    )
                })?;
        }
        Ok(())
    }

    fn bm1362_misc_ctrl_triple_write_chip_serial(
        serial: &ValidatedSerialBackend,
        chip_addr: u8,
        value: u32,
    ) -> Result<()> {
        for (i, op) in plan_misc_ctrl_triple_write_chip(chip_addr, value)
            .into_iter()
            .enumerate()
        {
            serial
                .execute_bm1397plus_op("BM1362 MiscCtrl chip triple-write", op)
                .with_context(|| {
                    format!(
                        "BM1362 MiscCtrl chip 0x{:02X} triple-write op {}/{}",
                        chip_addr,
                        i + 1,
                        6
                    )
                })?;
        }
        Ok(())
    }

    /// The 108-chip case stays pinned to the jig-attested fixture interval; the
    /// general case delegates to the shared ladder so it cannot truncate to
    /// zero at one chip. (The two agree at 108 â€” `256 / 108 == 2 ==
    /// BM1368_ADDRESS_INTERVAL` â€” so the pin is documentation of provenance,
    /// not a behavioural exception, and is left alone rather than churned on a
    /// live-proven S21 path.)
    fn bm1368_addr_interval(chip_count: u8) -> Result<u8> {
        if chip_count == 108 {
            Ok(BM1368_ADDRESS_INTERVAL)
        } else {
            Self::serial_address_interval(chip_count)
        }
    }

    fn bm1368_chain_inactive(serial: &ValidatedSerialBackend) -> Result<()> {
        // P1-1 pure SerialBringUpPlugin soft_reset phase (×3); 10 ms dwell is engine policy.
        let bring_up = plan_serial_bring_up(
            SerialBringUpPluginKind::AmlogicBm1368,
            ChainTransportKind::Serial,
            &SerialBringUpPlanParams {
                chip_count: 0,
                frequency_mhz: 0,
                chain_inactive_count: 3,
                inactive_dwell_ms: 0,
                post_enum_delay_ms: 0,
            },
        )
        .map_err(|e| anyhow::anyhow!("BM1368 bring-up soft_reset plan refused: {e}"))?;
        for (i, op) in bring_up.phases().soft_reset.into_iter().enumerate() {
            serial.execute_bm1397plus_op("serial ChainInactive", op)?;
            std::thread::sleep(Duration::from_millis(10));
            debug!("BM1368 chain inactive {}/{}", i + 1, 3);
        }
        Ok(())
    }

    fn bm1368_write_fixture_registers(serial: &ValidatedSerialBackend) -> Result<()> {
        serial.send_write_reg_broadcast_bm1397plus(0x54, ANALOG_MUX_VALUE)?;
        serial.send_write_reg_broadcast_bm1397plus(0xA8, BM1368_REG_A8_BCAST)?;
        serial.send_write_reg_broadcast_bm1397plus(0x18, BM1368_MISC_CTRL_BCAST)?;
        serial.send_write_reg_broadcast_bm1397plus(0x3C, BM1368_CORE_REG_1)?;
        serial.send_write_reg_broadcast_bm1397plus(0x3C, BM1368_CORE_REG_2)?;
        serial.send_write_reg_broadcast_bm1397plus(0x14, BM1368_TICKET_MASK)?;
        serial.send_write_reg_broadcast_bm1397plus(0x58, BM1368_IO_DRIVER)?;
        serial.send_write_reg_bm1397plus(
            0x00,
            BM1368_UART_RELAY_REG,
            BM1368_UART_RELAY_12_DOMAIN,
        )?;
        Ok(())
    }

    fn bm1368_core_reset(serial: &ValidatedSerialBackend, chip_count: u8) -> Result<()> {
        let addr_interval = Self::bm1368_addr_interval(chip_count)?;
        // P1-1 residual: pure linear_chip_addresses SSOT (no open-coded i*interval).
        for chip_addr in dcentrald_common::linear_chip_addresses(chip_count, addr_interval) {
            serial.send_write_reg_bm1397plus(chip_addr, 0xA8, BM1368_REG_A8_PER_CHIP)?;
            serial.send_write_reg_bm1397plus(chip_addr, 0x18, BM1368_MISC_CTRL_PER_CHIP)?;
            serial.send_write_reg_bm1397plus(chip_addr, 0x3C, BM1368_CORE_REG_1)?;
            serial.send_write_reg_bm1397plus(chip_addr, 0x3C, BM1368_CORE_REG_2)?;
            serial.send_write_reg_bm1397plus(chip_addr, 0x3C, BM1368_CORE_REG_3)?;
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    /// Full BM1362 ASIC chain initialization over one parser-admitted UART
    /// generation. The raw backend never reopens or escapes this fence.
    fn init_bm1362_chain(
        serial: ValidatedSerialBackend,
        serial_device: &str,
        configured_baud: u32,
        chip_count: u8,
        target_freq_mhz: u16,
    ) -> Result<(ValidatedSerialBackend, ValidatedSerialAssignedGeometry)> {
        info!(
            "=== BM1362 ASIC INIT ({} chips, {} MHz target, admitted {} baud) ===",
            chip_count, target_freq_mhz, configured_baud
        );
        if configured_baud != 115_200 {
            anyhow::bail!(
                "BM1362 init requires the checked reset-baseline 115200 route, got {configured_baud}"
            );
        }
        if chip_count == 0 {
            anyhow::bail!("BM1362 init requires nonzero configured geometry");
        }

        // Flush any stale data
        serial
            .flush_io()
            .context("BM1362 init failed to flush the admitted UART generation")?;
        std::thread::sleep(Duration::from_millis(50));

        // am2 Braiins glitch monitor mirror diagnostics (Braiins-am2 bitstream only).
        // W13.B1 (2026-05-10): the `0x43D00000` window is reclassified as a
        // diagnostic-only Braiins-am2 status mirror. R6-7 keeps the BM1362
        // 0x2C/0x34 candidate relay broadcasts lab-gated.
        if let Some(slot) = Self::am2_slot_from_serial_device(serial_device) {
            let phys_idx = slot + 1;
            if dcentrald_hal::glitch_monitor::chain_glitch_status_offset(phys_idx).is_some() {
                let braiins_glitch_uio: u8 = std::env::var("DCENT_BRAIINS_GLITCH_UIO")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(18);
                match dcentrald_hal::glitch_monitor::BraiinsGlitchMonitor::open(braiins_glitch_uio)
                {
                    Ok(monitor) => match monitor.read_chain_uart_relay_mirror(phys_idx) {
                        Ok(value) => info!(
                            phys_idx,
                            serial_device,
                            value = format_args!("0x{:08X}", value),
                            "am2 Braiins glitch mirror observed for direct BM1362 path (diagnostic only)"
                        ),
                        Err(e) => warn!(
                            phys_idx,
                            serial_device,
                            error = %e,
                            "am2 Braiins glitch mirror read failed â€” continuing (non-fatal)"
                        ),
                    },
                    Err(e) => warn!(
                        error = %e,
                        "am2 Braiins glitch mirror open failed (Braiins-am2 only) â€” continuing (non-fatal)"
                    ),
                }
            } else {
                warn!(
                    slot,
                    serial_device,
                    "am2 Braiins glitch mirror: slot {} has no known mirror offset (populated slots: 1=chain1, 2=chain4)",
                    slot
                );
            }
        }

        if Self::bm1362_early_115200_probe_enabled() {
            Self::log_bm1362_probe_stage(&serial, "after_open_115200", 150)?;
        }

        // === Phase A: Healthy traced 115200-baud init ===

        // Step 1: First healthy chain writes use BM1397+/BM1362 headers.
        serial.send_write_reg_broadcast_bm1397plus(0xA8, INIT_CONTROL_BCAST)?;
        std::thread::sleep(Duration::from_millis(10));
        Self::bm1362_misc_ctrl_triple_write_serial(&serial, MISC_CONTROL_INIT)?;
        std::thread::sleep(Duration::from_millis(10));
        serial.send_write_reg_broadcast_bm1397plus(0xA4, VERSION_MASK_VALUE)?;
        std::thread::sleep(Duration::from_millis(10));
        info!("Step 1: Healthy traced 115200 broadcast preamble applied");
        if Self::bm1362_early_115200_probe_enabled() {
            Self::log_bm1362_probe_stage(&serial, "after_115200_preamble", 150)?;
        }

        // Step 2–3: pure SerialBringUpPlugin plan phases (P1-1). Dwells/probes
        // stay engine policy; GetAddress is intentionally not inserted here
        // (historical serial path addresses without a mid-sequence GetAddress).
        let bring_up = plan_serial_bring_up(
            SerialBringUpPluginKind::Am2ZynqBm1362,
            ChainTransportKind::Serial,
            &SerialBringUpPlanParams {
                chip_count,
                frequency_mhz: 0,
                chain_inactive_count: 3,
                inactive_dwell_ms: 0, // engine owns 300 ms sleep + optional probe
                post_enum_delay_ms: 0,
            },
        )
        .map_err(|e| anyhow::anyhow!("serial BM1362 bring-up plan refused: {e}"))?;
        let phases = bring_up.phases();
        let addr_interval = bm1397plus_addr_interval(chip_count);

        info!("Step 2: Chain Inactive x3 (SerialBringUpPlugin soft_reset phase)");
        for (i, op) in phases.soft_reset.into_iter().enumerate() {
            serial.execute_bm1397plus_op("serial ChainInactive", op)?;
            std::thread::sleep(Duration::from_millis(300));
            if Self::bm1362_early_115200_probe_enabled() {
                let stage = format!("after_chain_inactive_{}", i + 1);
                Self::log_bm1362_probe_stage(&serial, &stage, 150)?;
            }
        }

        info!(
            "Step 3: Assigning addresses to {} chips (SerialBringUpPlugin ladder phase)",
            chip_count
        );
        for (i, op) in phases.address_ladder.into_iter().enumerate() {
            serial.execute_bm1397plus_op("serial SetAddress", op)?;
            if Self::bm1362_early_115200_probe_enabled()
                && (i == 0 || i % 16 == 15 || i + 1 == chip_count as usize)
            {
                std::thread::sleep(Duration::from_millis(20));
                let stage = format!("after_setaddr_{:03}", i + 1);
                Self::log_bm1362_probe_stage(&serial, &stage, 150)?;
            }
            if i % 16 == 15 {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        std::thread::sleep(Duration::from_millis(10));
        info!(
            "Enumeration complete: {} chips addressed (interval={})",
            chip_count, addr_interval
        );

        // Step 4: Remaining traced 115200-baud broadcast block before the fast-baud switch.
        serial.send_write_reg_broadcast_bm1397plus(0x3C, CORE_REG_HASH_CLK)?;
        std::thread::sleep(Duration::from_millis(10));
        if Self::bm1362_early_115200_probe_enabled() {
            Self::log_bm1362_probe_stage(&serial, "after_reg_3c_hash_clk", 150)?;
        }
        serial.send_write_reg_broadcast_bm1397plus(0x3C, CORE_REG_CLK_DELAY)?;
        std::thread::sleep(Duration::from_millis(10));
        if Self::bm1362_early_115200_probe_enabled() {
            Self::log_bm1362_probe_stage(&serial, "after_reg_3c_clk_delay", 150)?;
        }
        serial.send_write_reg_broadcast_bm1397plus(0x54, ANALOG_MUX_VALUE)?;
        std::thread::sleep(Duration::from_millis(10));
        if Self::bm1362_early_115200_probe_enabled() {
            Self::log_bm1362_probe_stage(&serial, "after_reg_54_analog_mux", 150)?;
        }
        serial.send_write_reg_broadcast_bm1397plus(0x58, IO_DRIVER_NORMAL)?;
        std::thread::sleep(Duration::from_millis(10));
        serial.send_write_reg_broadcast_bm1397plus(0x14, TICKET_MASK_256)?;
        std::thread::sleep(Duration::from_millis(10));
        serial.send_write_reg_broadcast_bm1397plus(0x10, NONCE_RANGE_126)?;
        std::thread::sleep(Duration::from_millis(10));
        Self::maybe_write_bm1362_uart_relay(&serial, "bm1362_step4_115200")?;
        info!("Step 4: Healthy traced 115200 broadcast block complete");
        if Self::bm1362_early_115200_probe_enabled() {
            Self::log_bm1362_probe_stage(&serial, "after_reg_58_stock_0x52_probe", 150)?;
        }

        // Step 5: Healthy chain4 trace shows the PLL divider / param pair twice
        // before the FastUART register write.
        Self::log_bm1362_probe_stage(&serial, "pre_pll_preamble", 150)?;
        if Self::bm1362_stop_after_pre_pll_probe_enabled() {
            return Err(anyhow::anyhow!(
                "DCENT_BM1362_STOP_AFTER_PRE_PLL_PROBE requested; stopping before PLL and fast-baud writes",
            ));
        }
        let (traced_pll_param, final_freq_mhz) = if target_freq_mhz == 525 {
            (BM1362_TRACE_PLL_PARAM_525, 525)
        } else {
            let (pll_reg, actual_freq) = bm1362_pll_lookup(target_freq_mhz.clamp(400, 597));
            warn!(
                requested_mhz = target_freq_mhz,
                traced_only_mhz = 525,
                fallback_pll = format_args!("0x{:08X}", pll_reg),
                fallback_actual_mhz = actual_freq,
                "BM1362 traced init only has a live PLL param for 525 MHz; falling back to lookup-derived PLL value"
            );
            (pll_reg, actual_freq)
        };
        serial.send_write_reg_broadcast_bm1397plus(
            BM1362_PLL0_DIVIDER_REG,
            BM1362_TRACE_PLL0_DIVIDER,
        )?;
        std::thread::sleep(Duration::from_millis(10));
        serial.send_write_reg_broadcast_bm1397plus(0x08, traced_pll_param)?;
        std::thread::sleep(Duration::from_millis(10));
        Self::log_bm1362_probe_stage(&serial, "post_pll_pair_1", 150)?;
        serial.send_write_reg_broadcast_bm1397plus(
            BM1362_PLL0_DIVIDER_REG,
            BM1362_TRACE_PLL0_DIVIDER,
        )?;
        std::thread::sleep(Duration::from_millis(10));
        serial.send_write_reg_broadcast_bm1397plus(0x08, traced_pll_param)?;
        std::thread::sleep(Duration::from_millis(10));
        Self::log_bm1362_probe_stage(&serial, "post_pll_pair_2", 150)?;
        info!(
            pll = format_args!("0x{:08X}", traced_pll_param),
            "Step 5: traced PLL preamble applied"
        );

        // Step 6: ASIC and host fast-baud switch.
        serial.send_write_reg_broadcast_bm1397plus(0x28, FAST_UART_VALUE)?;
        std::thread::sleep(Duration::from_millis(10));
        Self::bm1362_misc_ctrl_triple_write_serial(&serial, MISC_CONTROL_INIT)?;
        std::thread::sleep(Duration::from_millis(10));
        Self::log_bm1362_probe_stage(&serial, "post_fast_uart_reg_pre_host_switch", 150)?;
        serial.set_baud(fast_baud())?;
        std::thread::sleep(Duration::from_millis(1000));
        info!(
            pll = format_args!("0x{:08X}", traced_pll_param),
            fast_uart = format_args!("0x{:08X}", FAST_UART_VALUE),
            misc_ctrl = format_args!("0x{:08X}", MISC_CONTROL_INIT),
            "Step 6: Host baud upgraded to 3.125 Mbaud"
        );

        Self::maybe_write_bm1362_uart_relay(&serial, "bm1362_step6_fast_baud")?;

        // === DIAGNOSTIC: Verify small-command RX still works immediately after
        // the fast-baud transition. If this probe dies, the remaining blocker is
        // likely baud/transport or mining-ready state, not the full work frame.
        // BM13xx register-read responses are 11 bytes total on wire, i.e. 9
        // bytes after the 0xAA 0x55 preamble. `read_all_responses()` expects
        // the body length, not the total frame length.
        let post_baud_window = serial.query_chip_address_window(
            dcentrald_common::AsicProtocolIdentity::Bm1362,
            "BM1362 post-baud command-path probe",
        )?;
        info!(
            "POST-BAUD PROBE: {} responses (after step 6 fast-baud switch)",
            post_baud_window.observed_frames()
        );

        // === Phase B: High-baud mining-ready configuration ===

        // Step 7: Healthy stock init runs the full per-chip A8 / 18 / 3C x3 loop
        // only after the fast-baud transition.
        info!(
            "Step 7: Per-chip init loop after fast-baud switch ({} chips, 5 regs each)",
            chip_count
        );
        for (i, chip_addr) in dcentrald_common::linear_chip_addresses(chip_count, addr_interval)
            .into_iter()
            .enumerate()
        {
            serial.send_write_reg_bm1397plus(chip_addr, 0xA8, INIT_CONTROL_PER_CHIP)?;
            Self::bm1362_misc_ctrl_triple_write_chip_serial(&serial, chip_addr, MISC_CONTROL_INIT)?;
            serial.send_write_reg_bm1397plus(chip_addr, 0x3C, CORE_REG_HASH_CLK)?;
            serial.send_write_reg_bm1397plus(chip_addr, 0x3C, CORE_REG_CLK_DELAY)?;
            serial.send_write_reg_bm1397plus(chip_addr, 0x3C, CORE_REG_UNKNOWN)?;

            if i % 16 == 15 {
                std::thread::sleep(Duration::from_millis(SERIAL_PACE_MIN_MS));
            }
        }
        std::thread::sleep(Duration::from_millis(100));
        info!("Step 7: Per-chip init complete");

        // Healthy stock chain4 tracing has a clear post-baud per-chip loop, but
        // did not show an additional trailing broadcast block for BM1362 here.
        // On `a lab unit`, the command path stays alive immediately after the baud
        // switch and then goes dead again later in our synthetic tail. Keep the
        // direct path as close to stock as possible and defer any extra mining-
        // ready broadcasts until they are proven necessary by live parity.
        info!("Step 8: Skipping synthetic post-baud nonce-range/version-mask tail on BM1362 direct path");

        // === DIAGNOSTIC: Verify small-command RX still works after the full
        // high-baud mining-ready register block.
        let post_final_window = serial.query_chip_address_window(
            dcentrald_common::AsicProtocolIdentity::Bm1362,
            "BM1362 post-init population probe",
        )?;
        let post_final_frames = post_final_window.observed_frames();
        let assigned_geometry = ValidatedSerialAssignedGeometry::from_window(
            post_final_window,
            dcentrald_common::AsicProtocolIdentity::Bm1362,
            chip_count,
            addr_interval,
        )?;
        info!(
            "POST-FINAL PROBE: {} responses (after post-baud BM1362 direct config)",
            post_final_frames
        );

        info!(
            "=== BM1362 INIT COMPLETE â€” {} chips at {} MHz ===",
            chip_count, final_freq_mhz
        );

        // Flush any stale register responses from init commands before nonce collection
        serial
            .flush_io()
            .context("BM1362 init final serial flush failed")?;
        std::thread::sleep(Duration::from_millis(50));
        serial
            .flush_io()
            .context("BM1362 init second final serial flush failed")?;
        info!("Serial RX flushed after init");

        Ok((serial, assigned_geometry))
    }

    /// Address-assignment interval for a linear `256 / chip_count` ladder.
    ///
    /// Every serial init route computed this inline as
    /// `(256u16 / chip_count.max(1) as u16) as u8`, which is correct for every
    /// population we ship and silently wrong for exactly one: at
    /// `chip_count == 1` the mathematical interval is 256, which is not
    /// representable on the 8-bit address bus and truncates to **0** â€” so a
    /// one-chip repair fixture would assign address 0 to every chip and then
    /// validate itself against the same wrong stride.
    ///
    /// `LinearAddressPlan::from_truncated_byte_space` already encodes the right
    /// rule (one chip has only address 0, so use the smallest canonical
    /// non-zero stride). Routing through it makes that rule single-sourced
    /// instead of re-derived per chip family.
    ///
    /// This is wire-identical for every shipped population: for any
    /// `chip_count >= 2` the value is the same `256 / chip_count`, and the
    /// last address `(n - 1) * (256 / n)` is always `< 256`, so the shared
    /// constructor's byte-space check never rejects a real geometry. Only the
    /// one-chip case changes, and only from a broken value to a valid one.
    ///
    /// Deliberately does NOT touch how many frames are sent or their pacing â€”
    /// those differ per family by design and are live-proven.
    fn serial_address_interval(chip_count: u8) -> Result<u8> {
        let plan = dcentrald_api_types::asic_command::LinearAddressPlan::from_truncated_byte_space(
            u16::from(chip_count.max(1)),
        )
        .map_err(|err| {
            anyhow::anyhow!(
                "serial address ladder rejected chip_count={}: {:?}",
                chip_count,
                err
            )
        })?;
        Ok(plan.address_interval())
    }

    /// BM1368 ASIC init via serial (S21, T21).
    /// Uses BM1368-specific register values from ESP-Miner + bm1368.rs.
    /// Key differences from BM1362: different MISC_CTRL, CORE_REG, IO_DRIVER,
    /// and per-chip register values. This route retains the configured UART
    /// rate whose response window supplied admission; it does not claim a
    /// hardware baud readback or issue an unproven rate transition.
    fn init_bm1368_chain(
        serial: ValidatedSerialBackend,
        serial_device: &str,
        configured_baud: u32,
        chip_count: u8,
        target_freq_mhz: u16,
    ) -> Result<(ValidatedSerialBackend, ValidatedSerialAssignedGeometry)> {
        info!(
            "=== BM1368 ASIC INIT ({} chips, {} MHz target, admitted {} baud) ===",
            chip_count, target_freq_mhz, configured_baud
        );

        // Retain the backend and baud that supplied exact CRC-verified family
        // evidence. Reopening or spraying multi-family reset commands here
        // would discard the admitted route generation.
        info!(
            serial_device,
            configured_baud, "Using admitted configured UART rate for BM1368 init"
        );
        let _ = serial.flush_io();
        std::thread::sleep(Duration::from_millis(50));

        // === Phase A: Enumeration at the admitted configured UART rate ===

        // === ALL COMMANDS USE BM1397+ HEADERS (0x51/0x41/0x53/0x40) ===
        // BM1387 uses 0x58/0x48/0x55/0x41 which are CMD_SETCONFIG â€” incompatible!

        // Step 1: Version mask x4 (BM1368 needs 4, not 3 like BM1362)
        for i in 0..4 {
            serial.send_write_reg_broadcast_bm1397plus(0xA4, VERSION_MASK_VALUE)?;
            std::thread::sleep(Duration::from_millis(5));
            info!("Step 1: Version mask write {}/4", i + 1);
        }

        // Step 2–3: SerialBringUpPlugin phases (P1-1). Soft_reset via helper
        // (×3 + 10 ms engine dwells); address ladder from the same pure plan.
        // GetAddress is intentionally deferred to the PRE-INIT probe below.
        info!("Step 2: Chain Inactive x3");
        Self::bm1368_chain_inactive(&serial)?;

        info!("Step 3: Assigning addresses to {} chips", chip_count);
        let addr_interval = u16::from(Self::bm1368_addr_interval(chip_count)?);
        let bring_up = plan_serial_bring_up(
            SerialBringUpPluginKind::AmlogicBm1368,
            ChainTransportKind::Serial,
            &SerialBringUpPlanParams {
                chip_count,
                frequency_mhz: 0,
                chain_inactive_count: 3,
                inactive_dwell_ms: 0,
                post_enum_delay_ms: 0,
            },
        )
        .map_err(|e| anyhow::anyhow!("BM1368 bring-up address plan refused: {e}"))?;
        // Multi-chip: fixture/serial interval must match 256/N full-pop SSOT.
        // Single-chip: LinearAddressPlan uses interval 1 while bm1397plus uses 255;
        // both ladders emit only SetAddress{0} so ops stay identical.
        if chip_count > 1 {
            debug_assert_eq!(
                addr_interval as u8,
                bm1397plus_addr_interval(chip_count),
                "BM1368 addr_interval must match full-population SSOT for multi-chip"
            );
        }
        for (i, op) in bring_up.phases().address_ladder.into_iter().enumerate() {
            serial.execute_bm1397plus_op("serial SetAddress", op)?;
            if i % 16 == 15 {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        std::thread::sleep(Duration::from_millis(10));
        info!(
            "Issued {} configured BM1368 SetAddress commands (interval={}); population remains unpublished until exact post-assignment coverage",
            chip_count, addr_interval
        );

        // === DIAGNOSTIC: Probe chips after enumeration, before any register writes ===
        serial.set_response_len(BM13XX_CMD_RESP_BODY_LEN);
        let _ = serial.send_get_address_bm1397plus();
        std::thread::sleep(Duration::from_millis(200));
        let pre_responses = serial.read_all_responses(500)?;
        info!(
            "PRE-INIT PROBE: {} chip responses (before register writes)",
            pre_responses.len()
        );

        // === Phase B: Register Configuration (BM1368-specific, BM1397+ headers) ===

        // Step 4a-4h: Fixture broadcast register block
        Self::bm1368_write_fixture_registers(&serial)?;
        std::thread::sleep(Duration::from_millis(10));
        info!("Step 4: Fixture broadcast registers applied");
        info!("Step 4a: AnalogMux = 0x{:08X}", ANALOG_MUX_VALUE);
        info!("Step 4b: REG_A8 = 0x{:08X}", BM1368_REG_A8_BCAST);

        // Step 4b: Misc Control broadcast
        serial.send_write_reg_broadcast_bm1397plus(0x18, BM1368_MISC_CTRL_BCAST)?;
        std::thread::sleep(Duration::from_millis(10));
        info!("Step 4b: MiscCtrl = 0x{:08X}", BM1368_MISC_CTRL_BCAST);

        // Step 4c: Core register control â€” first write
        serial.send_write_reg_broadcast_bm1397plus(0x3C, BM1368_CORE_REG_1)?;
        info!("Step 4c: CoreReg[1] = 0x{:08X}", BM1368_CORE_REG_1);

        // Step 4d: Core register control â€” second write
        serial.send_write_reg_broadcast_bm1397plus(0x3C, BM1368_CORE_REG_2)?;
        info!("Step 4d: CoreReg[2] = 0x{:08X}", BM1368_CORE_REG_2);

        // Step 4e: Ticket mask init (BM1368 extra)
        serial.send_write_reg_broadcast_bm1397plus(0x14, BM1368_TICKET_MASK)?;
        info!("Step 4e: TicketMask init = 0x{:08X}", BM1368_TICKET_MASK);

        // Step 4f: Analog mux (temp diode)
        serial.send_write_reg_broadcast_bm1397plus(0x54, ANALOG_MUX_VALUE)?;
        info!("Step 4f: AnalogMux = 0x{:08X}", ANALOG_MUX_VALUE);

        // Step 4g: IO driver strength
        serial.send_write_reg_broadcast_bm1397plus(0x58, BM1368_IO_DRIVER)?;
        info!("Step 4g: IODriver = 0x{:08X}", BM1368_IO_DRIVER);

        std::thread::sleep(Duration::from_millis(10));

        // === DIAGNOSTIC: Probe after broadcast registers ===
        let _ = serial.send_get_address_bm1397plus();
        std::thread::sleep(Duration::from_millis(200));
        let post_bcast = serial.read_all_responses(500)?;
        info!(
            "POST-BROADCAST PROBE: {} responses (after 4a-4g)",
            post_bcast.len()
        );

        // Step 5: Per-chip register init (5 writes per chip, BM1397+ single-chip header 0x41)
        info!("Step 5: Per-chip init loop ({} chips)", chip_count);
        for chip_addr in dcentrald_common::linear_chip_addresses(chip_count, addr_interval as u8) {
            serial.send_write_reg_bm1397plus(chip_addr, 0xA8, BM1368_REG_A8_PER_CHIP)?;
            serial.send_write_reg_bm1397plus(chip_addr, 0x18, BM1368_MISC_CTRL_PER_CHIP)?;
            serial.send_write_reg_bm1397plus(chip_addr, 0x3C, BM1368_CORE_REG_1)?;
            serial.send_write_reg_bm1397plus(chip_addr, 0x3C, BM1368_CORE_REG_2)?;
            serial.send_write_reg_bm1397plus(chip_addr, 0x3C, BM1368_CORE_REG_3)?;
            // 20ms per chip (ESP-Miner uses 500ms; 20ms is a compromise for Linux serial)
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(50));
        info!("Step 5: Per-chip init complete");

        // Step 6: Difficulty mask
        serial.send_write_reg_broadcast_bm1397plus(0x14, BM1368_TICKET_MASK)?;
        info!("Step 6: TicketMask = 0x{:08X}", BM1368_TICKET_MASK);

        // === DIAGNOSTIC: Probe after per-chip config ===
        let _ = serial.send_get_address_bm1397plus();
        std::thread::sleep(Duration::from_millis(200));
        let post_perchip = serial.read_all_responses(500)?;
        info!(
            "POST-PERCHIP PROBE: {} responses (after step 5-6)",
            post_perchip.len()
        );

        // Step 7: PLL frequency ramp at the admitted configured UART rate.
        let target_freq = target_freq_mhz.clamp(50, 800);
        info!(
            "Step 7: PLL ramp to {} MHz (configured UART rate {})",
            target_freq, configured_baud
        );
        let mut current_freq: u16 = 200;
        while current_freq < target_freq {
            let (pll_reg, actual_freq) = bm1368_pll_search(current_freq);
            serial.send_write_reg_broadcast_bm1397plus(0x08, pll_reg)?;
            std::thread::sleep(Duration::from_millis(100));
            debug!("PLL ramp: {} MHz (0x{:08X})", actual_freq, pll_reg);
            current_freq = current_freq.saturating_add(25);
        }
        let (final_pll, final_freq) = bm1368_pll_search(target_freq);
        serial.send_write_reg_broadcast_bm1397plus(0x08, final_pll)?;
        std::thread::sleep(Duration::from_millis(100));
        info!(
            "Step 7: PLL final = {} MHz (0x{:08X})",
            final_freq, final_pll
        );

        // Step 8: Hash counting / nonce range.
        serial.send_write_reg_broadcast_bm1397plus(0x10, NONCE_RANGE_108)?;
        std::thread::sleep(Duration::from_millis(10));
        info!(
            "Step 8: HashCounting = 0x{:08X} (108 chips)",
            NONCE_RANGE_108
        );

        // Step 9: Final version mask.
        serial.send_write_reg_broadcast_bm1397plus(0xA4, VERSION_MASK_VALUE)?;
        std::thread::sleep(Duration::from_millis(10));
        info!("Step 9: Final version mask = 0x{:08X}", VERSION_MASK_VALUE);

        // === Phase C: retain the same route/rate that supplied admission ===
        // Reopening the UART or changing the ASIC rate would invalidate the
        // route generation. Rate readback is unavailable, so logs describe
        // the configured value and never promote it to observed evidence.
        info!(
            "Step 10: Retaining admitted configured UART rate {}",
            configured_baud
        );

        // === POST-INIT: Verify chips still respond at the retained rate ===
        let post_window = serial.query_chip_address_window(
            dcentrald_common::AsicProtocolIdentity::Bm1368,
            "BM1368 post-init population probe",
        )?;
        let post_observed_frames = post_window.observed_frames().get();
        let assigned_geometry = ValidatedSerialAssignedGeometry::from_window(
            post_window,
            dcentrald_common::AsicProtocolIdentity::Bm1368,
            chip_count,
            Self::bm1368_addr_interval(chip_count)?,
        )?;
        info!(
            "Post-init probe: {} chip responses at {} baud",
            post_observed_frames, configured_baud
        );

        info!(
            "=== BM1368 INIT COMPLETE â€” configured {} chips at {} MHz, {} baud ===",
            chip_count, final_freq, configured_baud
        );

        let _ = serial.flush_io();
        std::thread::sleep(Duration::from_millis(50));
        let _ = serial.flush_io();
        info!("Serial RX flushed after init");

        Ok((serial, assigned_geometry))
    }

    fn init_bm1366_chain(
        serial_device: &str,
        target_freq_mhz: u16,
        enumeration_admission: &Bm1366EnumerationAdmission,
    ) -> Result<SerialChainBackend> {
        // Phase H.13: apply the startup-captured operator-tunable
        // rambo_mode_max_bad_responses policy (default 0 = strict).
        // Bosminer's "Rambo mode" â€” proceed with chain enumeration even
        // when some chips fail to respond. Useful for partially-faulty
        // hashboards (e.g. .78 chain1 sees 8/77 chips: with rambo=8 the
        // chain still mines on the 8 working chips; without it dcentrald
        // refuses to start).
        // The degraded-enumeration decision was captured before hardware
        // construction. This post-energize retry path must never reload it.
        let chip_count = enumeration_admission.expected_chip_count;
        let rambo_max = enumeration_admission.configured_max_bad_responses;

        info!(
            "=== BM1366 ASIC INIT (experimental, {} chips, {} MHz target, rambo_max={}) ===",
            chip_count, target_freq_mhz, rambo_max
        );

        Self::reset_asic_baud(serial_device);

        let mut serial = SerialChainBackend::open(0, serial_device, 115_200)
            .context("Failed to open serial port at 115200")?;
        let _ = serial.flush_io();
        std::thread::sleep(Duration::from_millis(50));
        serial.set_response_len(BM13XX_CMD_RESP_BODY_LEN);

        for _ in 0..3 {
            serial.send_write_reg_broadcast_bm1397plus(0xA4, BM1366_VERSION_MASK_VALUE)?;
            std::thread::sleep(Duration::from_millis(5));
        }

        let _ = serial.send_get_address_bm1397plus();
        std::thread::sleep(Duration::from_millis(200));
        let pre_responses = serial.read_all_responses(500)?;
        // Rambo gate: tolerate only the startup-admitted number of missing
        // chips. A later file replacement cannot change this decision.
        let min_required = enumeration_admission.minimum_required_responses;
        if !enumeration_admission.admits_response_count(pre_responses.len()) {
            anyhow::bail!(
                "Only {} of {} BM1366 ASICs responded to GetAddress on {} (rambo_max={} â†’ min_required={}); chain looks dead",
                pre_responses.len(),
                chip_count,
                serial_device,
                rambo_max,
                min_required,
            );
        }
        if pre_responses.len() < chip_count as usize {
            tracing::warn!(
                got = pre_responses.len(),
                expected = chip_count,
                rambo_max,
                "BM1366 partial chain enumeration â€” proceeding under rambo_mode tolerance",
            );
        }

        serial.send_write_reg_broadcast_bm1397plus(0xA8, BM1366_REG_A8_BCAST)?;
        std::thread::sleep(Duration::from_millis(5));
        serial.send_write_reg_broadcast_bm1397plus(0x18, BM1366_MISC_CTRL_BCAST)?;
        std::thread::sleep(Duration::from_millis(5));
        // Pure SerialBringUpPlugin phases (P1-1); single inactive + full ladder.
        // Dwells stay engine policy; enum phase not forced into this sequence.
        let addr_interval = Self::serial_address_interval(chip_count)?;
        let bring_up = plan_serial_bring_up(
            SerialBringUpPluginKind::AmlogicBm1366,
            ChainTransportKind::Serial,
            &SerialBringUpPlanParams {
                chip_count,
                frequency_mhz: 0,
                chain_inactive_count: 1,
                inactive_dwell_ms: 0,
                post_enum_delay_ms: 0,
            },
        )
        .map_err(|e| anyhow::anyhow!("serial BM1366 bring-up plan refused: {e}"))?;
        let phases = bring_up.phases();
        // P1-3: this pre-admission BM1366 path holds a raw `SerialChainBackend`
        // (no `ValidatedSerialBackend` execution fence exists yet at this
        // phase), so planned ops execute through the same shared HAL adapter
        // the fenced façade delegates to.
        for op in phases.soft_reset {
            execute_transport_op_bm1397plus(&serial, &op)
                .map_err(|e| anyhow::anyhow!("serial ChainInactive: {e}"))?;
        }
        std::thread::sleep(Duration::from_millis(10));

        for (i, op) in phases.address_ladder.into_iter().enumerate() {
            execute_transport_op_bm1397plus(&serial, &op)
                .map_err(|e| anyhow::anyhow!("serial SetAddress: {e}"))?;
            if i % 16 == 15 {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        std::thread::sleep(Duration::from_millis(10));
        info!(
            "Issued {} configured BM1366 SetAddress commands (interval={}); population remains unpublished until exact post-assignment coverage",
            chip_count, addr_interval
        );

        serial.send_write_reg_broadcast_bm1397plus(0x3C, BM1366_CORE_REG_HASH_CLOCK)?;
        std::thread::sleep(Duration::from_millis(5));
        serial.send_write_reg_broadcast_bm1397plus(0x3C, BM1366_CORE_REG_CLOCK_DELAY)?;
        std::thread::sleep(Duration::from_millis(5));
        serial.send_write_reg_broadcast_bm1397plus(0x14, BM1366_TICKET_MASK)?;
        std::thread::sleep(Duration::from_millis(5));
        serial.send_write_reg_broadcast_bm1397plus(0x54, BM1366_ANALOG_MUX)?;
        std::thread::sleep(Duration::from_millis(5));
        serial.send_write_reg_broadcast_bm1397plus(0x58, BM1366_IO_DRIVER)?;
        std::thread::sleep(Duration::from_millis(5));
        serial.send_write_reg_bm1397plus(0x00, 0x2C, BM1366_UART_RELAY)?;
        std::thread::sleep(Duration::from_millis(5));

        for i in 0..chip_count {
            let addr = (i as u16 * addr_interval as u16) as u8;
            serial.send_write_reg_bm1397plus(addr, 0xA8, BM1366_REG_A8_PER_CHIP)?;
            serial.send_write_reg_bm1397plus(addr, 0x18, BM1366_MISC_CTRL_PER_CHIP)?;
            serial.send_write_reg_bm1397plus(addr, 0x3C, BM1366_CORE_REG_HASH_CLOCK)?;
            serial.send_write_reg_bm1397plus(addr, 0x3C, BM1366_CORE_REG_CLOCK_DELAY)?;
            serial.send_write_reg_bm1397plus(addr, 0x3C, BM1366_CORE_REG_UNKNOWN)?;
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(50));

        let (pll_reg, actual_freq) = bm1366_pll_search(target_freq_mhz);
        serial.send_write_reg_broadcast_bm1397plus(0x08, pll_reg)?;
        std::thread::sleep(Duration::from_millis(100));

        let hash_counting = if chip_count >= 100 {
            BM1366_HASH_COUNTING_S19XP
        } else {
            BM1366_HASH_COUNTING_S19K
        };
        serial.send_write_reg_broadcast_bm1397plus(0x10, hash_counting)?;
        std::thread::sleep(Duration::from_millis(10));
        serial.send_write_reg_broadcast_bm1397plus(0xA4, BM1366_VERSION_MASK_VALUE)?;
        std::thread::sleep(Duration::from_millis(10));

        let _ = serial.send_get_address_bm1397plus();
        std::thread::sleep(Duration::from_millis(200));
        let post_responses = serial.read_all_responses(500)?;
        if post_responses.is_empty() {
            anyhow::bail!(
                "BM1366 init completed but no ASICs responded to post-init GetAddress on {}",
                serial_device
            );
        }

        info!(
            "=== BM1366 INIT COMPLETE â€” {} chips at {} MHz, 115200 baud ===",
            chip_count, actual_freq
        );
        let _ = serial.flush_io();
        std::thread::sleep(Duration::from_millis(50));
        let _ = serial.flush_io();
        Ok(serial)
    }

    fn init_bm1370_chain(
        serial: ValidatedSerialBackend,
        serial_device: &str,
        configured_baud: u32,
        chip_count: u8,
        target_freq_mhz: u16,
    ) -> Result<(ValidatedSerialBackend, ValidatedSerialAssignedGeometry)> {
        info!(
            "=== BM1370 ASIC INIT (experimental, {} chips, {} MHz target, admitted {} baud) ===",
            chip_count, target_freq_mhz, configured_baud
        );

        info!(
            serial_device,
            configured_baud, "Using admitted configured UART rate for BM1370 init"
        );
        let _ = serial.flush_io();
        std::thread::sleep(Duration::from_millis(50));
        serial.set_response_len(BM13XX_CMD_RESP_BODY_LEN);

        for _ in 0..4 {
            serial.send_write_reg_broadcast_bm1397plus(0xA4, BM1370_VERSION_MASK_VALUE)?;
            std::thread::sleep(Duration::from_millis(5));
        }

        let _ = serial.send_get_address_bm1397plus();
        std::thread::sleep(Duration::from_millis(200));
        let pre_responses = serial.read_all_responses(500)?;
        if pre_responses.is_empty() {
            anyhow::bail!(
                "No BM1370 ASICs responded to GetAddress on {} before init",
                serial_device
            );
        }

        serial.send_write_reg_broadcast_bm1397plus(0xA8, BM1370_REG_A8_BCAST)?;
        std::thread::sleep(Duration::from_millis(10));
        serial.send_write_reg_broadcast_bm1397plus(0x18, BM1370_MISC_CTRL_BCAST)?;
        std::thread::sleep(Duration::from_millis(10));

        // P1-1 pure SerialBringUpPlugin phases: single ChainInactive + full-pop ladder.
        // Historical path used one inactive (not ×3); preserve count=1. Dwells engine-owned.
        // Pre-init GetAddress above stays outside the pure plan (probe, not soft_reset).
        let addr_interval = Self::serial_address_interval(chip_count)?;
        let bring_up = plan_serial_bring_up(
            SerialBringUpPluginKind::AmlogicBm1370,
            ChainTransportKind::Serial,
            &SerialBringUpPlanParams {
                chip_count,
                frequency_mhz: 0,
                chain_inactive_count: 1,
                inactive_dwell_ms: 0,
                post_enum_delay_ms: 0,
            },
        )
        .map_err(|e| anyhow::anyhow!("BM1370 bring-up plan refused: {e}"))?;
        let phases = bring_up.phases();
        for op in phases.soft_reset {
            serial.execute_bm1397plus_op("serial ChainInactive", op)?;
        }
        std::thread::sleep(Duration::from_millis(10));

        for (i, op) in phases.address_ladder.into_iter().enumerate() {
            serial.execute_bm1397plus_op("serial SetAddress", op)?;
            if i % 16 == 15 {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        std::thread::sleep(Duration::from_millis(10));

        serial.send_write_reg_broadcast_bm1397plus(0x3C, BM1370_CORE_REG_1)?;
        std::thread::sleep(Duration::from_millis(10));
        serial.send_write_reg_broadcast_bm1397plus(0x3C, BM1370_CORE_REG_2)?;
        std::thread::sleep(Duration::from_millis(10));
        serial.send_write_reg_broadcast_bm1397plus(0x14, BM1370_TICKET_MASK)?;
        std::thread::sleep(Duration::from_millis(10));
        serial.send_write_reg_broadcast_bm1397plus(0x58, BM1370_IO_DRIVER)?;
        std::thread::sleep(Duration::from_millis(10));

        for addr in dcentrald_common::linear_chip_addresses(chip_count, addr_interval) {
            serial.send_write_reg_bm1397plus(addr, 0xA8, BM1370_REG_A8_PER_CHIP)?;
            serial.send_write_reg_bm1397plus(addr, 0x18, BM1370_MISC_CTRL_PER_CHIP)?;
            serial.send_write_reg_bm1397plus(addr, 0x3C, BM1370_CORE_REG_1)?;
            serial.send_write_reg_bm1397plus(addr, 0x3C, BM1370_CORE_REG_2)?;
            serial.send_write_reg_bm1397plus(addr, 0x3C, BM1370_CORE_REG_3)?;
            std::thread::sleep(Duration::from_millis(5));
        }

        serial.send_write_reg_broadcast_bm1397plus(0xB9, BM1370_MISC_SETTINGS_B9)?;
        std::thread::sleep(Duration::from_millis(10));
        serial.send_write_reg_broadcast_bm1397plus(0x54, BM1370_ANALOG_MUX)?;
        std::thread::sleep(Duration::from_millis(10));
        serial.send_write_reg_broadcast_bm1397plus(0xB9, BM1370_MISC_SETTINGS_B9)?;
        std::thread::sleep(Duration::from_millis(10));
        serial.send_write_reg_broadcast_bm1397plus(0x3C, BM1370_CORE_REG_EXTRA)?;
        std::thread::sleep(Duration::from_millis(10));

        // P1-4 pure PLL solution → TransportOp PLL0 broadcast (execute via existing write).
        let (pll_reg, actual_freq) = bm1370_pll_search(target_freq_mhz);
        serial.execute_bm1397plus_op(
            "serial PLL0",
            dcentrald_common::plan_pll0_broadcast_write(dcentrald_common::PllSolution {
                register_value: pll_reg,
                actual_freq_mhz: actual_freq,
                family: dcentrald_common::PllFamily::Bm1370,
            }),
        )?;
        std::thread::sleep(Duration::from_millis(100));
        serial.send_write_reg_broadcast_bm1397plus(0x10, BM1370_HASH_COUNTING)?;
        std::thread::sleep(Duration::from_millis(10));
        serial.send_write_reg_broadcast_bm1397plus(0xA4, BM1370_VERSION_MASK_VALUE)?;
        std::thread::sleep(Duration::from_millis(10));

        let post_window = serial.query_chip_address_window(
            dcentrald_common::AsicProtocolIdentity::Bm1370,
            "BM1370 post-init population probe",
        )?;
        let assigned_geometry = ValidatedSerialAssignedGeometry::from_window(
            post_window,
            dcentrald_common::AsicProtocolIdentity::Bm1370,
            chip_count,
            Self::serial_address_interval(chip_count)?,
        )?;

        info!(
            "=== BM1370 INIT COMPLETE â€” configured {} chips at {} MHz, {} baud ===",
            chip_count, actual_freq, configured_baud
        );
        let _ = serial.flush_io();
        std::thread::sleep(Duration::from_millis(50));
        let _ = serial.flush_io();
        Ok((serial, assigned_geometry))
    }

    /// BM1398 ASIC init via serial (S19 Pro).
    /// Simplified init: enumerate at 115200, configure registers, upgrade to 3.125M.
    /// No PLL3/FastUART â€” uses default 25 MHz CLKI for baud clock.
    fn init_bm1398_chain(
        serial_device: &str,
        chip_count: u8,
        target_freq_mhz: u16,
    ) -> Result<SerialChainBackend> {
        info!(
            "=== BM1398 ASIC INIT ({} chips, {} MHz target) ===",
            chip_count, target_freq_mhz
        );

        // Open serial at 115200 for init commands
        let serial = SerialChainBackend::open(0, serial_device, 115_200)
            .context("Failed to open serial port at 115200")?;
        let _ = serial.flush_io();
        std::thread::sleep(Duration::from_millis(50));

        // Step 1–2: pure SerialBringUpPlugin soft_reset + full-pop address ladder
        // (P1-1/P1-3 SSOT — no open-coded 256/chip_count).
        info!("Step 1: Chain Inactive (BM1397+)");
        let bring_up = plan_serial_bring_up(
            SerialBringUpPluginKind::SerialBm1398,
            ChainTransportKind::Serial,
            &SerialBringUpPlanParams {
                chip_count,
                frequency_mhz: 0,
                chain_inactive_count: 1,
                inactive_dwell_ms: 0,
                post_enum_delay_ms: 0,
            },
        )
        .map_err(|e| anyhow::anyhow!("BM1398 bring-up plan refused: {e}"))?;
        let phases = bring_up.phases();
        for op in phases.soft_reset {
            match op {
                TransportOp::SendChainInactiveBm1397Plus => {
                    serial.send_chain_inactive_bm1397plus()?;
                }
                TransportOp::DelayMs { ms } => {
                    std::thread::sleep(Duration::from_millis(u64::from(ms)));
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(10));

        info!("Step 2: Assigning addresses to {} chips", chip_count);
        let addr_interval = u16::from(bm1397plus_addr_interval(chip_count));
        for op in phases.address_ladder {
            if let TransportOp::SendSetAddressBm1397Plus { addr } = op {
                serial.send_set_address_bm1397plus(addr)?;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
        info!(
            "Addresses assigned: {} chips, spacing {}",
            chip_count, addr_interval
        );

        // Step 2b: GetAddress scan â€” verify ASICs respond
        info!("Step 2b: GetAddress scan â€” verifying ASICs respond");
        let _ = serial.flush_io();
        serial.send_get_address_bm1397plus()?;
        std::thread::sleep(Duration::from_millis(500));
        let responses = serial.read_all_responses(500)?;
        if responses.is_empty() {
            anyhow::bail!("NO chips responded to GetAddress on {} â€” hash board may not be connected or powered", serial_device);
        } else {
            info!(
                "GetAddress: {} response(s) â€” ASICs are alive!",
                responses.len()
            );
        }

        // Step 3: Clock Order Control 0/1 = 0
        serial.send_write_reg_broadcast(0x80, BM1398_CLK_ORDER_CTRL)?;
        serial.send_write_reg_broadcast(0x84, BM1398_CLK_ORDER_CTRL)?;
        std::thread::sleep(Duration::from_millis(5));

        // Step 4: Ordered Clock Enable = 1
        serial.send_write_reg_broadcast(0x20, BM1398_ORDERED_CLK_EN)?;
        std::thread::sleep(Duration::from_millis(5));

        // Step 5: staged core-register control recovered independently from
        // the stock NBP1901 miner and repair jig.
        for write in dcentrald_api_types::bm1398_protocol::BM1398_PROVEN_CORE_WRITES {
            serial.send_write_reg_broadcast(write.register, write.value)?;
            std::thread::sleep(Duration::from_millis(5));
        }

        // Step 6: TicketMask (difficulty 256)
        serial.send_write_reg_broadcast(0x14, BM1398_TICKET_MASK)?;
        info!("TicketMask = 0x{:08X} (difficulty 256)", BM1398_TICKET_MASK);
        std::thread::sleep(Duration::from_millis(5));

        // Step 7: MiscCtrl at 115200 (BT8D=26)
        serial.send_write_reg_broadcast(0x18, BM1398_MISC_CTRL_INIT)?;
        std::thread::sleep(Duration::from_millis(10));

        // Step 8: PLL0 (frequency)
        let (pll_reg, actual_freq) = bm1398_pll_lookup(target_freq_mhz);
        for _ in 0..2 {
            serial.send_write_reg_broadcast(0x70, 0x0F0F_0F00)?; // PLL0 Divider preconfig
            std::thread::sleep(Duration::from_millis(10));
        }
        for _ in 0..2 {
            serial.send_write_reg_broadcast(0x08, pll_reg)?; // PLL0 Parameter
            std::thread::sleep(Duration::from_millis(10));
        }
        info!("PLL0 = 0x{:08X} ({} MHz)", pll_reg, actual_freq);
        std::thread::sleep(Duration::from_millis(20)); // PLL lock time

        // Step 9: Baud upgrade to 3.125 MHz
        // MiscCtrl BT8D=0 â†’ ASIC baud = 25MHz/(1*8) = 3.125 MHz (default CLKI, no PLL3)
        serial.send_write_reg_broadcast(0x18, BM1398_MISC_CTRL_FAST)?;
        std::thread::sleep(Duration::from_millis(200));
        info!("MiscCtrl = 0x6031 (BT8D=0 â†’ 3.125 MHz). Upgrading serial baud...");

        // Switch serial port to 3.125 Mbaud
        serial.set_baud(fast_baud())?;
        std::thread::sleep(Duration::from_millis(100));
        info!("Serial baud = 3.125 Mbaud");

        // Re-send MiscCtrl at new baud (CE expert: S9 Step 5b pattern)
        serial.send_write_reg_broadcast(0x18, BM1398_MISC_CTRL_FAST)?;
        std::thread::sleep(Duration::from_millis(10));
        info!("MiscCtrl re-sent at 3.125M baud");

        info!(
            "=== BM1398 INIT COMPLETE â€” {} chips at {} MHz, 3.125M baud ===",
            chip_count, actual_freq
        );

        let _ = serial.flush_io();
        std::thread::sleep(Duration::from_millis(50));
        let _ = serial.flush_io();

        Ok(serial)
    }

    /// The unchanged native BM1366 refusal text, reused as the baseline that
    /// the experimental admission decorates on every fail-closed path. When the
    /// opt-in is unset the engine never reaches this constant at all â€” it bails
    /// with the identical literal at the identity boundary â€” so the default
    /// refusal a normal image emits is byte-for-byte what it always was.
    const BM1366_NATIVE_BASELINE_REFUSAL: &'static str = "NOT IMPLEMENTED: native BM1366 catalog identities are live-evidence-backed NoPic hashboards; the former AMLCtrl_BHB56 dsPIC route contradicts BHB56902 EEPROM evidence [05,11] and must not authorize controller, voltage, or ASIC mutation";

    /// Exact, default-OFF operator opt-in for Experimental native BM1366.
    ///
    /// Extracted as its own function so the choice PRODUCTION makes is
    /// testable. A test that calls the admission helper with a hand-written
    /// `true` proves only that the helper works; it can never see what the
    /// engine actually passes, which is how a capability once went
    /// test-only-reachable here with the suite green.
    ///
    /// Only the exact string `"1"` opts in. An unset, empty, malformed, or
    /// merely truthy-looking value ("true", "yes", "0") stays refused, because
    /// the failure direction of a mis-parsed gate is granting an experimental
    /// hardware path nobody asked for.
    fn experimental_native_bm1366_opt_in() -> bool {
        Self::experimental_native_bm1366_opt_in_from(
            std::env::var(dcentrald_api_types::hashboard_eeprom::EXPERIMENTAL_NATIVE_BM1366_ENV)
                .ok()
                .as_deref(),
        )
    }

    /// Pure parse half of the opt-in, split from the environment read so it can
    /// be pinned exhaustively without mutating process-global state from a test
    /// (which races every other test in the binary).
    fn experimental_native_bm1366_opt_in_from(raw: Option<&str>) -> bool {
        matches!(raw, Some("1"))
    }

    pub async fn run(&mut self) -> Result<()> {
        let serial_device = self
            .config
            .mining
            .serial_device
            .clone()
            .unwrap_or_else(|| "/dev/ttyS2".to_string());
        let model_hint = self.config.mining.model.as_deref();
        let (resolved_chip_id, chip_count) = resolve_native_serial_identity_and_geometry(
            model_hint,
            self.config.mining.serial_chip_count,
        )?;
        let target_freq = self.config.mining.frequency_mhz;
        let passthrough = self.config.mining.passthrough;

        // `resolve_native_serial_identity_and_geometry` is the production
        // identity boundary. Per-family dispatch is derived only from its
        // catalog chip ID; chip count is geometry and never selects a driver.
        let is_bm1398 = resolved_chip_id == 0x1398;
        let is_bm1368 = resolved_chip_id == 0x1368;
        let is_bm1366 = resolved_chip_id == 0x1366;
        let is_bm1370 = resolved_chip_id == 0x1370;
        let is_bm1362 = resolved_chip_id == 0x1362;
        if is_bm1398 && !passthrough {
            anyhow::bail!(
                "NOT IMPLEMENTED: native BM1398 mining lacks an exact physical hashboard/controller identity; BHB42 EEPROM preamble [04,11] identifies BM1362 and must not authorize BM1398 voltage or ASIC mutation"
            );
        }
        // Experimental native BM1366 is an operator-set, default-OFF opt-in.
        // With the environment variable unset this reads exactly as it always
        // has: same condition, same position, same message, and no observation
        // of any kind. Setting the opt-in does NOT grant anything â€” it only
        // defers the refusal to the two-source admission further down, which
        // additionally requires an independently decoded hashboard identity
        // that exactly equals BM1366. Both refusals are terminal.
        let bm1366_experimental_opt_in = Self::experimental_native_bm1366_opt_in();
        if is_bm1366 && !passthrough && !bm1366_experimental_opt_in {
            anyhow::bail!(
                "NOT IMPLEMENTED: native BM1366 catalog identities are live-evidence-backed NoPic hashboards; the former AMLCtrl_BHB56 dsPIC route contradicts BHB56902 EEPROM evidence [05,11] and must not authorize controller, voltage, or ASIC mutation"
            );
        }
        // Optional EEPROM-backed PIC detection may perform bounded read-only
        // sysfs I/O. Unsupported native identities must be refused before even
        // that observation so rejection is side-effect-free and deterministic.
        let nopic = is_nopic(&self.config);
        let mut runtime_dispatch_admission = self.runtime_dispatch_admission.take();
        let mut am2_bm1362_route_admission = self.am2_bm1362_route_admission.take();
        if is_bm1362 != am2_bm1362_route_admission.is_some() {
            anyhow::bail!(
                "BM1362 direct-serial route authority does not match the resolved ASIC identity"
            );
        }
        if !is_bm1362 && runtime_dispatch_admission.is_none() {
            anyhow::bail!("serial runtime dispatch admission was already consumed");
        }
        let mut am2_never_energized = None;
        let mut validated_serial_geometry: Option<ValidatedSerialAssignedGeometry> = None;
        if passthrough && (is_bm1368 || is_bm1370) {
            anyhow::bail!(
                "BM1368/BM1370 preserve-state passthrough has no native route-admission contract; refusing to bless external initialization as validated serial execution"
            );
        }
        let native_nopic_power_owner = !passthrough && (is_bm1368 || is_bm1370);
        let serial_actor_topology =
            SerialActorTopology::admit(native_nopic_power_owner, is_bm1362, nopic)?;
        let validated_serial_route = serial_actor_topology.is_exact();
        if validated_serial_route
            && Self::am3_bb_uart_trans_lab_enabled()
            && Self::am3_bb_uart_trans_chains_from_serial_device(&serial_device).is_some()
        {
            anyhow::bail!(
                "exact direct-serial routes refuse the experimental uart_trans actor before hardware admission"
            );
        }
        let nopic_watchdog_liveness = SafetyLiveness::default();
        // Declared before the PSU guard so ordinary unwinding cuts GPIO437
        // before dropping the watchdog command owner. The retained bus-1
        // owner is declared first so the PSU guard drops (and cuts power)
        // before the final management-fabric handle can disappear.
        let mut amlogic_admission: Option<dcentrald_hal::platform::amlogic::AmlogicNoPicAdmission> =
            None;
        let mut amlogic_power_thermal: Option<
            dcentrald_hal::platform::amlogic::AmlogicPowerThermalService,
        > = None;
        let mut amlogic_fan: Option<Arc<dyn FanAccess>> = None;
        let mut am2_fan: Option<Arc<dyn FanAccess>> = None;
        let mut nopic_fan_safety = FanTachSafety::with_minimum_credible_rpm(
            DEFAULT_FAN_BELOW_MINIMUM_FAILURE_TICKS,
            dcentrald_hal::platform::amlogic::REQUIRED_AIRFLOW_MIN_RPM,
        );
        let mut am2_fan_safety = FanTachSafety::with_minimum_credible_rpm(
            DEFAULT_FAN_BELOW_MINIMUM_FAILURE_TICKS,
            AM2_BM1362_REQUIRED_AIRFLOW_MIN_RPM,
        );
        let mut nopic_watchdog: Option<SafetyWatchdogOwner> = None;
        let mut am2_watchdog: Option<SafetyWatchdogOwner> = None;
        let mut serial_route_domains: Option<SerialRouteDomains> = None;
        let am2_watchdog_liveness = SafetyLiveness::default();
        let mut am2_pic_heartbeat_terminal_limit = AM2_BM1362_PIC_HEARTBEAT_MAX_FAILURES;
        let (am2_apw_heartbeat_exit_tx, mut am2_apw_heartbeat_exit_rx) =
            mpsc::unbounded_channel::<String>();
        let mut am2_apw_heartbeat_exit_tx = Some(am2_apw_heartbeat_exit_tx);
        let am2_apw_heartbeat_progress = Arc::new(AtomicU64::new(0));
        let mut am2_apw_heartbeat_required = false;
        let mut nopic_psu_guard = NoPicPsuGuard::new();
        let mut nopic_energized_at: Option<Instant> = None;
        let mut am2_power = Am2PsuRuntimeGuard::new();
        // Hardware-worker cancellation is independent from the process token.
        // The main loop observes process shutdown, admits watchdog Teardown,
        // and only then asks this owner to stop its actors.
        let mut runtime_threads = SerialRuntimeThreads::new();
        let mut bm1362_detected_pic_fw: Option<u8> = None;
        let mut am2_thermal_supervisor: Option<crate::s19j_hybrid_mining::Am2ThermalSupervisor> =
            None;
        let mut am2_startup_temp_c: Option<f32> = None;
        let mut am2_startup_temp_source: Option<String> = None;
        let hw_difficulty = hardware_difficulty_for_serial_family(resolved_chip_id)?;
        // Exact AM2 BM1362 route/slot/controller authority was captured by the
        // constructor before any hardware access. Other BM1362 direct routes
        // and preserve-state adoption are refused there instead of falling
        // through to a caller-selected raw dsPIC address.
        let bm1362_pic_addr = am2_bm1362_route_admission
            .as_ref()
            .map(Am2Bm1362DirectSerialAdmission::pic_address);
        if let Some(addr) = bm1362_pic_addr {
            info!(
                serial_device = %serial_device,
                pic_addr = format_args!("0x{:02X}", addr),
                "BM1362 direct PIC address selected from serial slot",
            );
        }

        if is_bm1366 {
            warn!("BM1366 serial mining path is experimental â€” bring-up and live validation still pending");
        }

        if is_bm1370 {
            warn!("BM1370 serial mining path is experimental â€” job-id behavior and live validation still pending");
        }

        let job_id_increment: u8 = if is_bm1398 {
            BM1398_JOB_ID_INC
        } else if is_bm1366 {
            BM1366_JOB_ID_INC
        } else {
            BM1362_JOB_ID_INC
        };
        let resp_body_len: usize = if is_bm1398 {
            BM1398_RESP_BODY_LEN
        } else {
            BM1362_RESP_BODY_LEN
        };

        if is_bm1398 {
            info!(
                "=== S19 PRO SERIAL MINING (BM1398, {} chips) ===",
                chip_count
            );
        } else if is_bm1366 {
            info!(
                "=== BM1366 SERIAL MINING (experimental, {} chips) ===",
                chip_count
            );
        } else if is_bm1370 {
            info!(
                "=== BM1370 SERIAL MINING (experimental, {} chips, NoPic) ===",
                chip_count
            );
        } else if is_bm1368 {
            info!(
                "=== S21 SERIAL MINING (BM1368, {} chips, NoPic) ===",
                chip_count
            );
        } else {
            info!(
                "=== S19J PRO SERIAL MINING (BM1362, {} chips) ===",
                chip_count
            );
        }

        let mut published_voltage_mv = self.config.mining.voltage_mv;

        // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Hashboard-SKU energize-refusal gate ( B2, 2026-05-22).
        //
        // Drive-half of matrix Â§7 #15. Probes per-chain EEPROM preambles
        // BEFORE any dsPIC/NoPic voltage write. Refuses on malformed
        // header / timeout / mixed-SKU / profile-bind failure. Skipped on
        // `passthrough` (bosminer or other-OS owns voltage). Env-gated
        // strictness (`DCENT_AM2_STRICT_SKU_REFUSE`, default OFF);
        // `DCENT_AM2_ACCEPT_DEGRADED_HARDWARE=1` is the lab override.
        //
        // The serial path is multi-chip-family: BM1398 (am2 S19 Pro,
        // PIC-class), BM1362 (am2 S19j Pro, PIC-class), BM1366 (am3 S19k
        // Pro, NoPic-class), BM1368 (am3 S21, NoPic-class), BM1370 (am3
        // S21 Pro/XP, NoPic-class). All routes through the gate the same
        // way â€” the gate only inspects EEPROM preambles, not chip ID, so
        // it's family-agnostic. BHB-S9 / BHB-S11 / BHB-S17 hashboards
        // have `eeprom_preamble = None` in the catalog and so their
        // (typically all-zero / vendor-proprietary) headers will surface
        // as Unpopulated/ReadError/MalformedPreamble depending on what's
        // in the EEPROM. For those platforms the gate is informational
        // until the catalog is filled in â€” strict-mode operators should
        // confirm classification first.
        // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        let mut retained_eeprom_bytes: [Option<Vec<u8>>; 3] = [None, None, None];
        if !passthrough {
            use crate::runtime::hardware_info::{
                read_hashboard_eeprom_for_energize_gate, EepromReadinessError,
                DEFAULT_EEPROM_READINESS_BUDGET_MS,
            };
            use dcentrald_silicon_profiles::energize_gate::{
                accept_degraded_hardware_enabled, classify_chain, gate_chains_for_energize,
                strict_sku_refuse_enabled, ChainProbe,
            };
            let strict = strict_sku_refuse_enabled();
            let accept_degraded = accept_degraded_hardware_enabled();
            let deadline = std::time::Instant::now()
                + std::time::Duration::from_millis(DEFAULT_EEPROM_READINESS_BUDGET_MS);
            let mut probes: Vec<ChainProbe> = Vec::with_capacity(3);
            for slot in 0u8..=2u8 {
                match read_hashboard_eeprom_for_energize_gate(slot as usize, deadline) {
                    Ok(bytes) => {
                        retained_eeprom_bytes[slot as usize] = Some(bytes.clone());
                        probes.push(classify_chain(slot, Some(&bytes)));
                    }
                    Err(EepromReadinessError::Timeout { .. }) => {
                        probes.push(ChainProbe::Timeout { chain_id: slot });
                    }
                    Err(EepromReadinessError::InvalidSlot { .. }) => {
                        probes.push(ChainProbe::ReadError { chain_id: slot });
                    }
                }
            }
            info!(
                strict,
                accept_degraded,
                probes = ?probes,
                "serial-mining: hashboard-SKU energize-gate probes"
            );
            match gate_chains_for_energize(&probes, strict) {
                Ok((bindings, telemetry)) => {
                    info!(
                        chains = bindings.len(),
                        bindings = ?bindings,
                        "serial-mining: energize gate ACCEPTED"
                    );
                    if !telemetry.is_empty() {
                        warn!(
                            reasons = %telemetry.summary(),
                            "serial-mining: [ENERGIZE-REFUSED telemetry-only â€” would refuse if DCENT_AM2_STRICT_SKU_REFUSE=1] {}",
                            telemetry.summary()
                        );
                    }
                }
                Err(refusal) => {
                    if accept_degraded {
                        warn!(
                            reasons = %refusal.summary(),
                            "serial-mining: [ENERGIZE-REFUSED but proceeding â€” DCENT_AM2_ACCEPT_DEGRADED_HARDWARE=1 lab override] {}",
                            refusal.summary()
                        );
                    } else {
                        tracing::error!(
                            reasons = %refusal.summary(),
                            "serial-mining: [ENERGIZE-REFUSED] {}",
                            refusal.summary()
                        );
                        anyhow::bail!(
                            "serial-mining hashboard-SKU energize gate refused: {}",
                            refusal.summary()
                        );
                    }
                }
            }
        }

        // â”€â”€ Native BM1366: two-source Experimental admission â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // The energize gate above already read and retained every populated
        // hashboard page, so this consumes bytes that are already in hand and
        // performs no new observation of any kind. Admission requires BOTH the
        // operator's explicit opt-in AND an independently decoded identity that
        // exactly equals the required protocol; absent, weak, contradicted, or
        // mismatched evidence all return the original refusal.
        //
        // Admission here does NOT enable mining, and is not a step toward
        // enabling it by accident. The transport chain below still refuses
        // BM1366 unconditionally, and no transport, controller, voltage, or
        // ASIC mutation exists for this family. What this closes is narrower
        // and real: the decision layer had no production caller at all, so it
        // was reachable only from its own tests.
        if is_bm1366 && !passthrough {
            use crate::runtime::hardware_info::fold_observed_identity_from_retained_pages;
            use dcentrald_api_types::hashboard_eeprom::{
                admit_native_experimental, NativeExperimentalAdmission,
                EXPERIMENTAL_NATIVE_BM1366_ENV,
            };

            let observed = fold_observed_identity_from_retained_pages(&retained_eeprom_bytes)
                .map_err(|mixed| {
                    anyhow::anyhow!(
                        "{} [experimental opt-in set, but the hashboards disagree on ASIC \
                         identity: {mixed}; fail-closed]",
                        Self::BM1366_NATIVE_BASELINE_REFUSAL
                    )
                })?;
            match admit_native_experimental(
                bm1366_experimental_opt_in,
                observed,
                dcentrald_common::board_desc::AsicProtocolIdentity::Bm1366,
                Self::BM1366_NATIVE_BASELINE_REFUSAL,
            ) {
                NativeExperimentalAdmission::Refused(reason) => anyhow::bail!(reason),
                NativeExperimentalAdmission::AdmittedExperimental { identity } => {
                    warn!(
                        ?identity,
                        opt_in_env = EXPERIMENTAL_NATIVE_BM1366_ENV,
                        "EXPERIMENTAL: native BM1366 admitted by operator opt-in plus a decoded \
                         hashboard EEPROM identity. No mining transport exists for this family, \
                         so this run still refuses below and nothing is energized."
                    );
                }
            }
        }

        // Bootstrap sysfs EEPROM reads above must finish before the sole
        // runtime service reserves /dev/i2c-0. A kernel AT24 read is an I2C
        // transfer even though it appears as a read-only sysfs file; allowing
        // it after this boundary would create an invisible second bus owner.
        let bm1362_i2c_service = if is_bm1362 && !serial_actor_topology.is_nopic() && !passthrough {
            Some(
                spawn_i2c_service_no_register_touch_with_denylist(
                    0,
                    HASHBOARD_EEPROM_WRITE_DENYLIST.to_vec(),
                )
                .context("Failed to spawn AM2 serial /dev/i2c-0 service")?,
            )
        } else {
            None
        };
        if let Some(service) = bm1362_i2c_service.as_ref() {
            // Retain the exact serialized management fabric before any route
            // can energize. Checked teardown terminally latches every clone of
            // this service and includes that transition in watchdog-disarm
            // evidence, preventing a stale handle from mutating after OFF.
            am2_power.set_management_fabric(service.clone())?;
        }
        if native_nopic_power_owner {
            amlogic_admission = Some(
                dcentrald_hal::platform::amlogic::AmlogicNoPicAdmission::detect(
                    dcentrald_hal::platform::amlogic::AmlogicNoPicProfile::S21,
                    &serial_device,
                )
                .context("Amlogic control-board identity did not admit native NoPic ownership")?,
            );
            let admission = amlogic_admission
                .as_ref()
                .context("Amlogic NoPic admission disappeared before owner construction")?;
            amlogic_power_thermal = Some(
                admission
                    .spawn_power_thermal_service()
                    .context("Failed to establish retained Amlogic /dev/i2c-1 ownership")?,
            );
        }

        // Cooling ownership and a checked startup command are prerequisites
        // for native NoPic power. This narrow constructor performs no platform
        // re-detection or raw I2C probe after the serialized services exist.
        let (effective_fan_min_pwm, effective_fan_max_pwm): (u8, u8) = if native_nopic_power_owner {
            let accept_degraded_tach = std::env::var("DCENT_AM3_AML_ACCEPT_DEGRADED_TACH")
                .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let mut profile = dcentrald_thermal::profiles::ThermalProfile {
                fan_max_pwm: self.config.thermal.fan_max_pwm,
                fan_min_pwm: self.config.thermal.fan_min_pwm,
                ..Default::default()
            };
            let _ = dcentrald_thermal::profiles::enforce_amlogic_tach_safety_policy(
                &mut profile,
                true,
                accept_degraded_tach,
            );
            dcentrald_thermal::profiles::enforce_required_airflow_pwm(
                &mut profile,
                dcentrald_hal::platform::amlogic::REQUIRED_AIRFLOW_MIN_PWM,
            )
            .context("Amlogic air-cooled fan profile cannot satisfy required airflow")?;
            (profile.fan_min_pwm, profile.fan_max_pwm)
        } else {
            (
                self.config.thermal.fan_min_pwm,
                self.config.thermal.fan_max_pwm,
            )
        };
        amlogic_fan = if native_nopic_power_owner {
            let fan = amlogic_admission
                .as_ref()
                .context("Amlogic cooling construction lacks NoPic admission")?
                .open_fan_controller()
                .context("Failed to open Amlogic fan control before power admission")?;
            if effective_fan_max_pwm < self.config.thermal.fan_max_pwm {
                warn!(
                    requested_cap = self.config.thermal.fan_max_pwm,
                    applied_cap = effective_fan_max_pwm,
                    "am3-aml fan cap exceeds degraded-tach safety policy; applying retained startup ceiling"
                );
            }
            let receipt = admit_fan_airflow_envelope(
                fan.clone(),
                &mut nopic_fan_safety,
                effective_fan_min_pwm,
                effective_fan_max_pwm,
            )
            .await?;
            debug!(
                requested_pwm = receipt.requested_pwm(),
                observed_pwm = receipt.observed_pwm(),
                minimum_pwm = effective_fan_min_pwm,
                "Amlogic cooling owner admitted before NoPic power after min/max motion proof"
            );
            Some(fan)
        } else {
            None
        };
        if matches!(serial_actor_topology, SerialActorTopology::ExactAm2Bm1362) {
            let route = am2_bm1362_route_admission
                .as_ref()
                .context("AM2 BM1362 route admission disappeared before cooling ownership")?;
            let platform = dcentrald_hal::platform::zynq::ZynqPlatform::new()
                .context("failed to bind admitted AM2 Zynq fan owner")?;
            let fan: Arc<dyn FanAccess> = Arc::new(
                platform
                    .open_am2_s19_fan_controller_checked()
                    .context(
                        "failed to open AM2 fan controller with checked C52 custody before power admission",
                    )?,
            );
            let startup_pwm = self
                .config
                .thermal
                .fan_max_pwm
                .min(dcentrald_hal::fan::PWM_MAX)
                .min(dcentrald_hal::fan::PWM_SAFETY_MAX);
            let fan_receipt = admit_fan_motion_at_pwm(
                fan.clone(),
                &mut am2_fan_safety,
                startup_pwm,
                "AM2 BM1362 startup",
            )
            .await
            .with_context(|| {
                format!(
                    "AM2 BM1362 slot {} cooling admission failed before PWR_CONTROL",
                    route.active_slot()
                )
            })?;
            info!(
                slot = route.active_slot(),
                requested_pwm = fan_receipt.requested_pwm(),
                observed_pwm = fan_receipt.observed_pwm(),
                "AM2 BM1362 fan custody and all-channel tach motion admitted before power"
            );
            am2_fan = Some(fan);

            if self.config.watchdog.timeout_s < AM2_BM1362_MIN_WATCHDOG_TIMEOUT_S {
                anyhow::bail!(
                    "AM2 BM1362 direct serial requires watchdog.timeout_s >= {} so a worst-case dsPIC heartbeat request plus emergency GPIO cutoff completes before reset; configured {}",
                    AM2_BM1362_MIN_WATCHDOG_TIMEOUT_S,
                    self.config.watchdog.timeout_s
                );
            }
            let (mut watchdog, watchdog_admission) = SafetyWatchdogOwner::start_before_energizing(
                &self.config.watchdog,
                AM2_BM1362_WATCHDOG_BRINGUP_GRACE,
                AM2_BM1362_SAFETY_LIVENESS_INTERVAL,
                am2_watchdog_liveness.clone(),
            )
            .await?;
            let arm_receipt = watchdog_admission.require_armed("AM2 BM1362 direct serial")?;
            let mut domains =
                SerialRouteDomains::claim_am2(&mut watchdog, route).map_err(|error| {
                    watchdog_reset_pending_error(
                        "AM2 BM1362 direct serial",
                        format!("post-arm route-domain claim failed: {error:#}"),
                    )
                })?;
            let never_energized = watchdog.issue_am2_never_energized().map_err(|error| {
                watchdog_reset_pending_error(
                    "AM2 BM1362 direct serial",
                    format!("post-arm never-energized token issuance failed: {error:#}"),
                )
            })?;
            serial_route_domains = Some(domains);
            am2_never_energized = Some(never_energized);
            am2_watchdog = Some(watchdog);
            let actor_activation = serial_route_domains
                .as_mut()
                .context("AM2 route-domain owner disappeared before actor activation")
                .and_then(SerialRouteDomains::take_am2_actor_owner)
                .and_then(|owner| runtime_threads.activate_am2(owner));
            if let Err(error) = actor_activation {
                let closeout = close_am2_watchdog_never_energized(
                    &mut am2_watchdog,
                    &mut am2_never_energized,
                    &mut serial_route_domains,
                    &mut runtime_threads,
                )
                .await;
                return Err(failure_with_am2_never_energized_closeout(error, closeout));
            }
            am2_pic_heartbeat_terminal_limit = match am2_pic_heartbeat_failure_limit(
                arm_receipt.effective_timeout_s,
            ) {
                Some(limit) => limit,
                None => {
                    let closeout = close_am2_watchdog_never_energized(
                        &mut am2_watchdog,
                        &mut am2_never_energized,
                        &mut serial_route_domains,
                        &mut runtime_threads,
                    )
                    .await;
                    return Err(failure_with_am2_never_energized_closeout(
                        anyhow::anyhow!(
                            "AM2 BM1362 effective watchdog timeout {}s is below explicit heartbeat-cut minimum {}s",
                            arm_receipt.effective_timeout_s,
                            AM2_BM1362_MIN_WATCHDOG_TIMEOUT_S
                        ),
                        closeout,
                    ));
                }
            };
            info!(
                requested_timeout_s = arm_receipt.requested_timeout_s,
                effective_timeout_s = arm_receipt.effective_timeout_s,
                kick_interval_s = arm_receipt.kick_interval_s,
                bringup_grace_s = AM2_BM1362_WATCHDOG_BRINGUP_GRACE.as_secs(),
                pic_heartbeat_terminal_failures = am2_pic_heartbeat_terminal_limit,
                "AM2 BM1362 SoC watchdog ownership admitted before energizing"
            );
            if self.shutdown.is_cancelled() {
                let closeout = close_am2_watchdog_never_energized(
                    &mut am2_watchdog,
                    &mut am2_never_energized,
                    &mut serial_route_domains,
                    &mut runtime_threads,
                )
                .await;
                return Err(failure_with_am2_never_energized_closeout(
                    anyhow::anyhow!(
                        "shutdown raced AM2 BM1362 fan/watchdog admission; refusing energization"
                    ),
                    closeout,
                ));
            }
        }
        let serial = if passthrough {
            info!("PASSTHROUGH MODE â€” skipping PIC/ASIC init");
            info!(
                "Opening {} in preserve-state passthrough mode",
                serial_device
            );
            let mut s = SerialChainBackend::open_passthrough(0, &serial_device)
                .context("Failed to open passthrough serial backend")?;
            s.set_response_len(resp_body_len);
            Self::drain_serial_passthrough_backlog(&s, 5000);
            SerialWorkTransport::Legacy(s)
        } else if is_bm1398 {
            // Refusal backstop, not a driver arm: the authoritative refusal is
            // the identity bail at the top of run(). This arm is reachable
            // only if that bail is ever bypassed (e.g. via a config/model
            // string defect). The rail is still cold here â€” this arm only
            // selects a transport, and no energizing call has run on this
            // path. (Some energizing calls appear EARLIER in the function,
            // at the AM2 fan-admission and watchdog-arm steps; they are
            // simply unreachable on this path, which resolves a Legacy
            // topology. Do not restate this as "every energizing call sits
            // in later arms" â€” that is false.)
            //
            // Bailing rather than panicking does NOT keep the session alive.
            // The crate ships panic = "abort", and an untyped bail is just as
            // terminal: failure_disposition() returns Some only for
            // SerialNeverEnergizedError / SerialTerminalSafeOffError, so an
            // untyped error yields None, and main.rs refuses stable
            // management-only operation on None and returns Err. Both paths
            // end the process and arm the session crash latch.
            //
            // What the bail actually buys: a typed, logged, attributable
            // error instead of an opaque abort, destructors run on the way
            // out, and refusal semantics uniform with the identity bails.
            anyhow::bail!("non-passthrough BM1398 is refused before hardware construction");
        } else if is_bm1366 {
            // Same refusal backstop as the BM1398 arm above, with the same
            // caveat: this is terminal for the session too. It buys
            // diagnosability and destructor execution, not survival of the
            // update path. No hardware has been observed or energized here.
            anyhow::bail!("non-passthrough BM1366 is refused before hardware observation");
        } else if is_bm1368 || is_bm1370 {
            // ---- BM1368 (S21/T21): NoPic + BM1368-specific init ----
            // Voltage architecture (verified 2026-04-12 via ftrace + fixture RE + live probe):
            //   - TAS5782M DACs (bus 0, addr 0x49/0x4A/0x4B) are kernel-managed from DTB
            //   - APW PSU enabled via GPIO 437 plus APW I2C/PMBus preboot sequence at 0x1f
            //   - Bosminer never writes to TAS5782M â€” voltage DACs stay kernel-managed
            //   - No PMBus device at 0x58 on either I2C bus (confirmed 2026-04-12);
            //     the native cold-boot APW path is bus 1 addr 0x1f
            info!("Phase 1: PSU enable (NoPic model, TAS5782M kernel-managed)");

            // Wave J Lane A: NoPic PSU enable is GPIO-437-only (the voltage is
            // kernel-managed TAS5782M; there is NO smart-PSU probe to skip), so a
            // 120V non-smart PSU already works here. When [power.psu_override] is
            // set we honor it for telemetry: record the declared model + its
            // efficiency, and log the disposition so the override is never silently
            // ignored (fail-loud honesty). The GPIO 437 enable below is correct for
            // any PSU and is unchanged.
            if crate::s19j_hybrid_mining::psu_override_active(
                self.config.power.psu_override.as_ref(),
            ) {
                let ovr = self
                    .config
                    .power
                    .psu_override
                    .as_ref()
                    .expect("psu_override_active implies Some");
                info!(
                    model = %ovr.model,
                    rail_v = ovr.voltage_v,
                    efficiency =
                        ?crate::runtime::efficiency::psu_efficiency_for_model_name(&ovr.model),
                    "NoPic (am3-aml): PSU OVERRIDE honored as INFORMATIONAL â€” PSU enable is \
                     GPIO-437-only + kernel-managed TAS5782M voltage, so there is no smart-PSU \
                     probe to bypass; declared model + efficiency recorded for telemetry"
                );
            }

            if !native_nopic_power_owner {
                anyhow::bail!(
                    "internal NoPic ownership mismatch: energizing path lacks an explicit power lease"
                );
            }
            if self.shutdown.is_cancelled() {
                anyhow::bail!("shutdown was already requested before NoPic watchdog admission");
            }
            let power_thermal = amlogic_power_thermal
                .as_mut()
                .context("NoPic power route lacks retained Amlogic bus-1 ownership")?;
            // Retain terminal management-fabric authority before watchdog
            // admission. This performs no energizing I/O, but makes every
            // later watchdog/shutdown race capable of producing checked-low
            // power and fabric-fence evidence.
            let management_lifecycle = power_thermal
                .take_lifecycle_owner()
                .context("NoPic power route could not transfer bus-1 lifecycle ownership")?;
            nopic_psu_guard.prepare_enable(effective_fan_max_pwm, management_lifecycle);
            let psu_enable_operation = power_thermal
                .take_psu_enable_operation()
                .context("NoPic power route could not mint its one-shot PSU enable operation")?;
            let (mut watchdog_owner, watchdog_admission) =
                SafetyWatchdogOwner::start_before_energizing(
                    &self.config.watchdog,
                    NOPIC_WATCHDOG_BRINGUP_GRACE,
                    NOPIC_SAFETY_LIVENESS_INTERVAL,
                    nopic_watchdog_liveness.clone(),
                )
                .await?;
            let arm_receipt = watchdog_admission.require_armed("native serial NoPic")?;
            let mut domains =
                SerialRouteDomains::claim_nopic(&mut watchdog_owner).map_err(|error| {
                    watchdog_reset_pending_error(
                        "native serial NoPic",
                        format!("post-arm route-domain claim failed: {error:#}"),
                    )
                })?;
            serial_route_domains = Some(domains);
            nopic_watchdog = Some(watchdog_owner);
            let actor_activation = serial_route_domains
                .as_mut()
                .context("NoPic route-domain owner disappeared before actor activation")
                .and_then(SerialRouteDomains::take_nopic_actor_owner)
                .and_then(|owner| runtime_threads.activate_nopic(owner));
            if let Err(error) = actor_activation {
                let closeout = closeout_native_nopic_failure(
                    &mut nopic_watchdog,
                    &mut serial_route_domains,
                    &mut nopic_psu_guard,
                    &mut runtime_threads,
                    None,
                )
                .await;
                return Err(failure_with_closeout(error, closeout));
            }
            info!(
                requested_timeout_s = arm_receipt.requested_timeout_s,
                effective_timeout_s = arm_receipt.effective_timeout_s,
                kick_interval_s = arm_receipt.kick_interval_s,
                bringup_grace_s = NOPIC_WATCHDOG_BRINGUP_GRACE.as_secs(),
                "NoPic watchdog arm admission observed before GPIO437 mutation"
            );
            if self.shutdown.is_cancelled() {
                let error =
                    anyhow::anyhow!("shutdown raced NoPic watchdog admission; refusing PSU enable");
                let closeout = closeout_native_nopic_failure(
                    &mut nopic_watchdog,
                    &mut serial_route_domains,
                    &mut nopic_psu_guard,
                    &mut runtime_threads,
                    None,
                )
                .await;
                return Err(failure_with_closeout(error, closeout));
            }

            // Enable PSU via GPIO 437 (PWR_EN, active HIGH: 1=ON, 0=OFF â€”
            // Q10, polarity CORRECTED 2026-05-21; see amlogic/mod.rs enable_psu_gpio
            // + the psu_enable_is_active_high_437 test). Do NOT re-read this as the
            // old "PSU_nEN active LOW" â€” that inverted reading was the original
            // polarity bug. (prod-readiness hunt-2 #H2.) Arm the shutdown guard
            // immediately so a failed init does not leave boards powered.
            let enable_result =
                tokio::task::spawn_blocking(move || psu_enable_operation.enable_psu()).await;
            let enable_receipt = match enable_result {
                Ok(Ok(receipt)) => receipt,
                Ok(Err(error)) => {
                    let error = anyhow::anyhow!("Failed to enable NoPic PSU: {error}");
                    let closeout = closeout_native_nopic_failure(
                        &mut nopic_watchdog,
                        &mut serial_route_domains,
                        &mut nopic_psu_guard,
                        &mut runtime_threads,
                        None,
                    )
                    .await;
                    return Err(failure_with_closeout(error, closeout));
                }
                Err(join_error) => {
                    let error =
                        anyhow::anyhow!("NoPic PSU enable worker did not complete: {join_error}");
                    let closeout = closeout_native_nopic_failure(
                        &mut nopic_watchdog,
                        &mut serial_route_domains,
                        &mut nopic_psu_guard,
                        &mut runtime_threads,
                        None,
                    )
                    .await;
                    return Err(failure_with_closeout(error, closeout));
                }
            };
            debug!(
                writes_completed_at = ?enable_receipt.writes_completed_at(),
                status_word = ?enable_receipt.status_word(),
                "NoPic APW enable receipt retained"
            );
            nopic_psu_guard.mark_enabled();
            let energized_at = Instant::now();
            nopic_energized_at = Some(energized_at);

            let startup_thermal_owner = power_thermal.thermal_port();
            let startup_thermal_result = tokio::task::spawn_blocking(move || {
                startup_thermal_owner
                    .read_board_temperatures(Instant::now() + Duration::from_millis(750))
            })
            .await;
            let mut startup_board_temps = match startup_thermal_result {
                Ok(temperatures) => temperatures,
                Err(join_error) => {
                    let error = anyhow::anyhow!(
                        "NoPic startup thermal worker did not complete: {join_error}"
                    );
                    let closeout = closeout_native_nopic_failure(
                        &mut nopic_watchdog,
                        &mut serial_route_domains,
                        &mut nopic_psu_guard,
                        &mut runtime_threads,
                        None,
                    )
                    .await;
                    return Err(failure_with_closeout(error, closeout));
                }
            };
            let startup_deadline = energized_at + Duration::from_secs(AMLOGIC_TEMP_STARTUP_GRACE_S);
            loop {
                if let Some(hottest_temp) = startup_board_temps.hottest_celsius() {
                    if hottest_temp >= self.config.thermal.dangerous_temp_c as f32 {
                        let error = anyhow::anyhow!(
                            "Amlogic startup observed dangerous temperature {hottest_temp:.1} C before ASIC initialization"
                        );
                        let first_safe_off = run_terminal_owner_operation_blocking(
                            &mut nopic_psu_guard,
                            NoPicPsuGuard::new(),
                            "NoPic dangerous-startup-temperature safe-off",
                            |guard| guard.first_stage_safe_off(),
                        )
                        .await;
                        let closeout = closeout_native_nopic_failure(
                            &mut nopic_watchdog,
                            &mut serial_route_domains,
                            &mut nopic_psu_guard,
                            &mut runtime_threads,
                            first_safe_off.ok(),
                        )
                        .await;
                        return Err(failure_with_closeout(error, closeout));
                    }
                }
                let startup_coverage = startup_board_temps.required_coverage();
                if startup_coverage.is_complete() {
                    break;
                }
                warn!(
                    required_slots = ?startup_coverage.required_slots(),
                    missing_slots = ?startup_coverage.missing_slots(),
                    deadline_ms = startup_deadline.saturating_duration_since(Instant::now()).as_millis(),
                    "Required board-temperature coverage is incomplete after PSU enable; ASIC initialization remains blocked"
                );
                if self.shutdown.is_cancelled() || Instant::now() >= startup_deadline {
                    let error = anyhow::anyhow!(
                        "required Amlogic board-temperature coverage did not become complete before the powered-startup deadline"
                    );
                    let first_safe_off = run_terminal_owner_operation_blocking(
                        &mut nopic_psu_guard,
                        NoPicPsuGuard::new(),
                        "NoPic incomplete-startup-thermal-coverage safe-off",
                        |guard| guard.first_stage_safe_off(),
                    )
                    .await;
                    let closeout = closeout_native_nopic_failure(
                        &mut nopic_watchdog,
                        &mut serial_route_domains,
                        &mut nopic_psu_guard,
                        &mut runtime_threads,
                        first_safe_off.ok(),
                    )
                    .await;
                    return Err(failure_with_closeout(error, closeout));
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                let retry_owner = power_thermal.thermal_port();
                let retry_result = tokio::task::spawn_blocking(move || {
                    retry_owner.read_board_temperatures(Instant::now() + Duration::from_millis(750))
                })
                .await;
                startup_board_temps = match retry_result {
                    Ok(temperatures) => temperatures,
                    Err(join_error) => {
                        let error = anyhow::anyhow!(
                            "NoPic startup thermal retry worker did not complete: {join_error}"
                        );
                        let closeout = closeout_native_nopic_failure(
                            &mut nopic_watchdog,
                            &mut serial_route_domains,
                            &mut nopic_psu_guard,
                            &mut runtime_threads,
                            None,
                        )
                        .await;
                        return Err(failure_with_closeout(error, closeout));
                    }
                };
            }
            if let Some(hottest_temp) = startup_board_temps.hottest_celsius() {
                info!(
                    sensors = startup_board_temps.readings().len(),
                    unavailable = startup_board_temps.unavailable().len(),
                    hottest_c = format_args!("{:.1}", hottest_temp),
                    "Board temperature sensors responded after PSU enable"
                );
            }

            // Phase 1b: NO GPIO board reset on S21 NoPic!
            // GPIO 454-456 reset kills TAS5782M DAC voltage â†’ ASICs lose power.
            // Instead: skip reset, send GetAddress to verify chips are alive.
            info!("Phase 1b: Skipping GPIO board reset (NoPic â€” reset kills voltage)");

            // Diagnostic: probe chips at multiple bauds to find if they're alive.
            // Try the common live-state fast baud first, then back down.
            let observation_result = (|| -> Result<NoPicSerialObservation> {
                let dispatch = runtime_dispatch_admission
                    .as_ref()
                    .context("NoPic serial observation lost dispatch admission")?;
                let platform = amlogic_admission
                    .as_ref()
                    .context("NoPic serial observation lost platform admission")?;
                serial_route_domains
                    .as_mut()
                    .context("NoPic serial observation lost route-domain ownership")?
                    .begin_nopic_observation(dispatch, platform, &serial_device, chip_count)
            })();
            let nopic_observation = match observation_result {
                Ok(observation) => observation,
                Err(error) => {
                    let closeout = closeout_native_nopic_failure(
                        &mut nopic_watchdog,
                        &mut serial_route_domains,
                        &mut nopic_psu_guard,
                        &mut runtime_threads,
                        None,
                    )
                    .await;
                    return Err(failure_with_closeout(error, closeout));
                }
            };
            let mut admitted_serial: Option<NoPicAdmittedSerial> = None;
            for probe_baud in [3_000_000u32, 1_000_000, 115_200] {
                info!("Phase 1c: Probing chips at {} baud...", probe_baud);
                match nopic_observation.observe_candidate(probe_baud) {
                    Ok(Some(admitted)) => {
                        admitted_serial = Some(admitted);
                        break;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let closeout = closeout_native_nopic_failure(
                            &mut nopic_watchdog,
                            &mut serial_route_domains,
                            &mut nopic_psu_guard,
                            &mut runtime_threads,
                            None,
                        )
                        .await;
                        return Err(failure_with_closeout(error, closeout));
                    }
                }
            }

            if admitted_serial.is_none() {
                let startup_error = anyhow::anyhow!(
                    "No CRC-verified BM1368/BM1370 ChipAddress response window was observed at an admitted baud; refusing family-specific writes"
                );
                let closeout = closeout_native_nopic_failure(
                    &mut nopic_watchdog,
                    &mut serial_route_domains,
                    &mut nopic_psu_guard,
                    &mut runtime_threads,
                    None,
                )
                .await;
                return Err(failure_with_closeout(startup_error, closeout));
            }
            let observed = admitted_serial.expect("admitted serial window checked above");
            let route_admission = match runtime_dispatch_admission.take() {
                Some(admission) => admission,
                None => {
                    let error = anyhow::anyhow!(
                        "serial BoardDesc/config admission disappeared before response binding"
                    );
                    let closeout = closeout_native_nopic_failure(
                        &mut nopic_watchdog,
                        &mut serial_route_domains,
                        &mut nopic_psu_guard,
                        &mut runtime_threads,
                        None,
                    )
                    .await;
                    return Err(failure_with_closeout(error, closeout));
                }
            };
            let platform_admission = match amlogic_admission.as_ref() {
                Some(admission) => admission,
                None => {
                    let error = anyhow::anyhow!(
                        "Amlogic platform admission disappeared before serial response binding"
                    );
                    let closeout = closeout_native_nopic_failure(
                        &mut nopic_watchdog,
                        &mut serial_route_domains,
                        &mut nopic_psu_guard,
                        &mut runtime_threads,
                        None,
                    )
                    .await;
                    return Err(failure_with_closeout(error, closeout));
                }
            };
            let bound_observed_result = serial_route_domains
                .as_ref()
                .context("NoPic observed serial binding lost its route-domain owner")
                .and_then(|domains| {
                    domains.bind_nopic_observed_serial(
                        observed,
                        route_admission,
                        platform_admission,
                        &serial_device,
                        chip_count,
                    )
                });
            let (configured_baud, bound_observed) = match bound_observed_result {
                Ok(bound) => bound,
                Err(error) => {
                    let closeout = closeout_native_nopic_failure(
                        &mut nopic_watchdog,
                        &mut serial_route_domains,
                        &mut nopic_psu_guard,
                        &mut runtime_threads,
                        None,
                    )
                    .await;
                    return Err(failure_with_closeout(error, closeout));
                }
            };
            let validated_backend_result = serial_route_domains
                .as_mut()
                .context("NoPic serial execution lost its route-domain owner")
                .and_then(|domains| {
                    domains.promote_nopic_execution(nopic_observation, bound_observed)
                });
            let validated_backend = match validated_backend_result {
                Ok(backend) => backend,
                Err(error) => {
                    let error = failure_with_exact_serial_closeout(
                        error,
                        serial_actor_topology,
                        &mut nopic_watchdog,
                        &mut am2_watchdog,
                        &mut serial_route_domains,
                        &mut nopic_psu_guard,
                        &mut am2_power,
                        &mut runtime_threads,
                    )
                    .await;
                    return Err(error);
                }
            };
            let init_result = if is_bm1370 {
                info!(
                    "Phase 2: Full BM1370 ASIC init ({} configured chips)",
                    chip_count
                );
                Self::init_bm1370_chain(
                    validated_backend,
                    &serial_device,
                    configured_baud,
                    chip_count,
                    target_freq,
                )
            } else {
                info!(
                    "Phase 2: Full BM1368 ASIC init ({} configured chips)",
                    chip_count
                );
                Self::init_bm1368_chain(
                    validated_backend,
                    &serial_device,
                    configured_baud,
                    chip_count,
                    target_freq,
                )
            };
            let (validated_backend, assigned_geometry) = match init_result {
                Ok(result) => result,
                Err(error) => {
                    let closeout = closeout_native_nopic_failure(
                        &mut nopic_watchdog,
                        &mut serial_route_domains,
                        &mut nopic_psu_guard,
                        &mut runtime_threads,
                        None,
                    )
                    .await;
                    return Err(failure_with_closeout(error, closeout));
                }
            };
            validated_backend.set_response_len(resp_body_len);
            validated_serial_geometry = Some(assigned_geometry);
            SerialWorkTransport::Validated(validated_backend)
        } else {
            // ---- BM1362 (S19j Pro): PIC init + BM1362-specific init ----
            let bm1362_bringup_result: Result<SerialWorkTransport> = async {
            let mut am2_serial_observation: Option<Am2SerialObservation> = None;
            if serial_actor_topology.is_nopic() {
                info!("Phase 1: SKIPPED â€” NoPic model, voltage via TAS5782M DAC");
            } else {
                // W24-CRASH-1 (panic-hook coverage for the BM1362 direct serial
                // path): this branch is about to assert PWR_CONTROL + bring up the
                // APW rail + set the chain rail to 13.7 V via the dsPIC. On a
                // `panic = "abort"` build NONE of `Am2PsuRuntimeGuard::Drop` /
                // `PsuGpioGate::Drop` run, and â€” unlike the NoPic branch (which
                // arms `arm_nopic_teardown`) â€” this path previously armed NO
                // panic-hook teardown at all, so a panic during enum / init /
                // stratum handshake left PWR_CONTROL asserted with NO software
                // backstop (APW fw=0x71 + dsPIC fw=0x86 have no telemetry; the
                // only hardware backstop is the dsPIC heartbeat watchdog). Arm
                // the SAME process-global the am2 hybrid run-scope uses so the
                // already-installed `main()` panic hook drives this unit's
                // `pwr_control_gpio` low FIRST, then caps fans at PWM_SAFETY_MAX
                // (30). Idempotent (OnceLock); stores config only â€” no hardware
                // I/O on the happy path; only fires on a panic. (Audit
                // panic-hook-coverage gap, 2026-05-29.)
                crate::s19j_hybrid_mining::arm_am2_teardown_params(&self.config)
                    .context("BM1362 direct serial panic-teardown authority unavailable")?;

                // Quiet-state `a lab unit` direct tests were still leaning on whatever
                // shared PSU state BraiinsOS left behind. Own the APW rail in the
                // pure serial BM1362 path too so direct tests no longer depend on
                // stock fee-session runtime state.
                let psu_transport = self.config.psu.transport.as_str();
                let psu_address = self.config.psu.i2c_address;
                let psu_target_rail_v = self.config.psu.voltage_mv as f64 / 1000.0;
                let psu_heartbeat_hz = u64::from(self.config.psu.heartbeat_hz.max(1));
                let psu_heartbeat_interval =
                    Duration::from_millis((1000 / psu_heartbeat_hz).max(1));

                info!(
                    transport = psu_transport,
                    addr = format_args!("0x{:02X}", psu_address),
                    "Phase -1: APW bring-up for BM1362 direct path"
                );
                // Wave J Lane A: 120V "Loki bypass" â€” when the operator declares a
                // non-smart PSU via [power.psu_override], there is no APW121215a at
                // 0x10 to probe / cold-boot / heartbeat (it would BLOCK on a dumb
                // PSU). Assert PWR_CONTROL via PsuGpioGate (the APW output enable is
                // wired through it) and proceed â€” the BM1362 chip-rail voltage path
                // below is UNCHANGED (psu_override.voltage_v is the PSU OUTPUT rail,
                // never the chip setpoint). Mirrors the proven s19j_hybrid Phase-0
                // branch (b)..
                require_am2_bringup_active(
                    &self.shutdown,
                    "before PWR_CONTROL assertion",
                )?;
                if crate::s19j_hybrid_mining::psu_override_active(
                    self.config.power.psu_override.as_ref(),
                ) {
                    let ovr = self
                        .config
                        .power
                        .psu_override
                        .as_ref()
                        .expect("psu_override_active implies Some");
                    am2_power.admit_apw_bypass(&ovr.model, ovr.voltage_v)?;
                    runtime_threads.resolve_am2_apw(false)?;
                    let boundary = am2_never_energized.take().context(
                        "AM2 BM1362 lost never-energized authority before bypass PWR_CONTROL",
                    )?;
                    let asserted_gpio = assert_am2_psu_gpio_after_energizing_boundary(
                        &mut am2_power,
                        boundary,
                        self.config.psu.pwr_control_gpio.as_deref(),
                    )
                    .context("PSU bypass: PWR_CONTROL assert failed (BM1362 direct)")?;
                    info!(
                        model = %ovr.model,
                        rail_v = ovr.voltage_v,
                        gpio = asserted_gpio,
                        efficiency =
                            ?crate::runtime::efficiency::psu_efficiency_for_model_name(&ovr.model),
                        "BM1362 direct: PSU OVERRIDE (Loki bypass) â€” skipping Apw121215a \
                         probe/cold-boot/heartbeat; PWR_CONTROL asserted; rail voltage recorded \
                         (NOT the chip voltage)"
                    );
                    require_am2_bringup_active(
                        &self.shutdown,
                        "after bypass PWR_CONTROL assertion",
                    )?;
                } else if psu_transport == "gpio_bitbang" {
                    let boundary = am2_never_energized.take().context(
                        "AM2 BM1362 lost never-energized authority before bitbang PWR_CONTROL",
                    )?;
                    let asserted_gpio = assert_am2_psu_gpio_after_energizing_boundary(
                        &mut am2_power,
                        boundary,
                        self.config.psu.pwr_control_gpio.as_deref(),
                    )
                    .context("Failed to assert PWR_CONTROL for BM1362 direct path")?;
                    info!(
                        gpio = asserted_gpio,
                        "BM1362 direct path: PWR_CONTROL asserted"
                    );
                    require_am2_bringup_active(
                        &self.shutdown,
                        "after bitbang PWR_CONTROL assertion",
                    )?;

                    let psu = Apw121215a::open_gpio_bitbang_at(psu_address).context(
                        "Failed to open APW121215a via gpio bit-bang for BM1362 direct path",
                    )?;
                    let psu = Arc::new(Mutex::new(psu));
                    am2_power.set_psu(psu.clone())?;
                    require_am2_bringup_active(
                        &self.shutdown,
                        "before bitbang APW cold boot",
                    )?;
                    let apw_bringup_shutdown = self.shutdown.clone();
                    psu.lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .cold_boot_sequence_write_only_cancellable(
                            psu_target_rail_v,
                            APW12_139_ASSUMED_FW,
                            || apw_bringup_shutdown.is_cancelled(),
                        )
                        .context("BM1362 direct path PSU write-only cold_boot_sequence failed")?;
                    require_am2_bringup_active(
                        &self.shutdown,
                        "after bitbang APW cold boot",
                    )?;
                    let psu_hb = psu.clone();
                    let shutdown_hb = runtime_threads.cancellation_token()?;
                    let heartbeat_lifecycle_shutdown = self.shutdown.clone();
                    let heartbeat_progress = am2_apw_heartbeat_progress.clone();
                    let heartbeat_exit = am2_apw_heartbeat_exit_tx
                        .as_ref()
                        .context("AM2 BM1362 APW heartbeat exit owner was already retired")?
                        .clone();
                    am2_apw_heartbeat_required = true;
                    let heartbeat_slot = runtime_threads
                        .reserve_am2(Am2SerialThreadSlot::ApwHeartbeat)?;
                    let handle_result = std::thread::Builder::new()
                        .name("s19j-serial-psu-hb".into())
                        .spawn(move || {
                            Self::psu_heartbeat_loop(
                                psu_hb,
                                shutdown_hb,
                                heartbeat_lifecycle_shutdown,
                                psu_heartbeat_interval,
                                heartbeat_progress,
                                heartbeat_exit,
                            )
                        })
                        .context("Failed to spawn BM1362 direct PSU heartbeat thread");
                    let handle = match handle_result {
                        Ok(handle) => handle,
                        Err(error) => {
                            drop(heartbeat_slot);
                            return Err(error);
                        }
                    };
                    heartbeat_slot.attach(handle);
                    runtime_threads.resolve_am2_apw(true)?;
                    drop(am2_apw_heartbeat_exit_tx.take());
                    info!(
                        hz = psu_heartbeat_hz,
                        "BM1362 direct PSU heartbeat thread spawned"
                    );
                    wait_am2_apw_heartbeat_stable(
                        &self.shutdown,
                        &mut am2_apw_heartbeat_exit_rx,
                        &am2_apw_heartbeat_progress,
                        Duration::from_secs(5),
                        "bitbang APW heartbeat stabilization",
                    )
                    .await?;
                } else if let Some(i2c_service) = bm1362_i2c_service.as_ref() {
                    let boundary = am2_never_energized.take().context(
                        "AM2 BM1362 lost never-energized authority before service PWR_CONTROL",
                    )?;
                    let asserted_gpio = assert_am2_psu_gpio_after_energizing_boundary(
                        &mut am2_power,
                        boundary,
                        self.config.psu.pwr_control_gpio.as_deref(),
                    )
                    .context("Failed to assert PWR_CONTROL for BM1362 direct service path")?;
                    info!(
                        gpio = asserted_gpio,
                        "BM1362 direct service path: PWR_CONTROL asserted"
                    );
                    require_am2_bringup_active(
                        &self.shutdown,
                        "after service PWR_CONTROL assertion",
                    )?;

                    let psu = Apw121215a::open_service_at(i2c_service.clone(), 0, psu_address)
                        .context("Failed to open APW121215a through BM1362 direct I2C service")?;
                    let psu = Arc::new(Mutex::new(psu));
                    am2_power.set_psu(psu.clone())?;
                    require_am2_bringup_active(
                        &self.shutdown,
                        "before service APW cold boot",
                    )?;
                    let apw_bringup_shutdown = self.shutdown.clone();
                    psu.lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .cold_boot_sequence_write_only_cancellable(
                            psu_target_rail_v,
                            APW12_139_ASSUMED_FW,
                            || apw_bringup_shutdown.is_cancelled(),
                        )
                        .context("BM1362 direct path APW service cold_boot_sequence failed")?;
                    require_am2_bringup_active(
                        &self.shutdown,
                        "after service APW cold boot",
                    )?;
                    let psu_hb = psu.clone();
                    let shutdown_hb = runtime_threads.cancellation_token()?;
                    let heartbeat_lifecycle_shutdown = self.shutdown.clone();
                    let heartbeat_progress = am2_apw_heartbeat_progress.clone();
                    let heartbeat_exit = am2_apw_heartbeat_exit_tx
                        .as_ref()
                        .context("AM2 BM1362 APW heartbeat exit owner was already retired")?
                        .clone();
                    am2_apw_heartbeat_required = true;
                    let heartbeat_slot = runtime_threads
                        .reserve_am2(Am2SerialThreadSlot::ApwHeartbeat)?;
                    let handle_result = std::thread::Builder::new()
                        .name("s19j-serial-psu-hb".into())
                        .spawn(move || {
                            Self::psu_heartbeat_loop(
                                psu_hb,
                                shutdown_hb,
                                heartbeat_lifecycle_shutdown,
                                psu_heartbeat_interval,
                                heartbeat_progress,
                                heartbeat_exit,
                            )
                        })
                        .context("Failed to spawn BM1362 direct PSU service heartbeat thread");
                    let handle = match handle_result {
                        Ok(handle) => handle,
                        Err(error) => {
                            drop(heartbeat_slot);
                            return Err(error);
                        }
                    };
                    heartbeat_slot.attach(handle);
                    runtime_threads.resolve_am2_apw(true)?;
                    drop(am2_apw_heartbeat_exit_tx.take());
                    info!(
                        hz = psu_heartbeat_hz,
                        "BM1362 direct PSU service heartbeat thread spawned"
                    );
                    wait_am2_apw_heartbeat_stable(
                        &self.shutdown,
                        &mut am2_apw_heartbeat_exit_rx,
                        &am2_apw_heartbeat_progress,
                        Duration::from_secs(5),
                        "service APW heartbeat stabilization",
                    )
                    .await?;
                } else {
                    anyhow::bail!(
                        "BM1362 direct path has unsupported PSU transport {psu_transport:?} and no explicit bypass; refusing to energize without owned APW/PWR_CONTROL custody"
                    );
                }

                let pic_addr =
                    bm1362_pic_addr.context("BM1362 direct PIC address was not resolved")?;
                info!("Phase 1: PIC init at I2C 0x{:02X} (Pic0x89 flow)", pic_addr);
                require_am2_bringup_active(
                    &self.shutdown,
                    "before PIC firmware preflight",
                )?;
                let (detected_fw, detected_fw_reply) =
                    if let Some(i2c_service) = bm1362_i2c_service.as_ref() {
                        Self::pic_read_fw_version_service(i2c_service, pic_addr)
                            .context("BM1362 direct PIC service GET_VERSION preflight failed")?
                    } else {
                        anyhow::bail!(
                            "BM1362 direct PIC service missing; refusing second /dev/i2c-0 owner"
                        )
                    };
                require_am2_bringup_active(
                    &self.shutdown,
                    "after PIC firmware preflight",
                )?;
                info!(
                    fw = format_args!("0x{:02X}", detected_fw),
                    "BM1362 direct PIC FW version"
                );
                bm1362_detected_pic_fw = Some(detected_fw);

                let i2c_service = bm1362_i2c_service
                    .as_ref()
                    .context("BM1362 direct PIC service missing before endpoint binding")?;
                let route = am2_bm1362_route_admission.as_ref().context(
                    "exact AM2 BM1362 route admission disappeared before controller binding",
                )?;
                let plan = route.controller_plan();
                let context = plan.context_for_address(pic_addr).ok_or_else(|| {
                    anyhow::anyhow!(
                        "exact am2-s19j plan has no context for observed PIC address 0x{pic_addr:02X}; refusing raw-address fallback"
                    )
                })?;
                if context.serial_device() != route.serial_device()
                    || context.slot() != route.active_slot()
                {
                    anyhow::bail!(
                        "AM2 BM1362 controller context drifted from the constructor-captured UART/slot route"
                    );
                }
                let eeprom_bytes = retained_eeprom_bytes
                    .get(usize::from(context.slot()))
                    .and_then(|bytes| bytes.clone())
                    .with_context(|| {
                        format!(
                            "exact am2-s19j slot {} lacks its retained pre-energize EEPROM observation",
                            context.slot()
                        )
                    })?;
                let presence = dcentrald_hal::platform::bind_am2_hashboard_presence(
                    plan,
                    context,
                    eeprom_bytes,
                )?;
                let endpoint =
                    dcentrald_hal::platform::bind_am2_controller_endpoint_from_observation(
                        &presence,
                        &detected_fw_reply,
                    )?;
                info!(
                    serial_device = %serial_device,
                    pic_addr = format_args!("0x{:02X}", endpoint.address()),
                    firmware = ?endpoint.observed_firmware(),
                    "BM1362 direct PIC owner bound to exact AM2 endpoint capability from retained observations"
                );
                let pic_session = Pic0x89EndpointSession::new(i2c_service.clone(), endpoint)
                    .context("failed to bind AM2 Pic0x89 endpoint to I2C service")?;
                // Retain the safe-direction owner before reset. PWR_CONTROL has
                // already crossed the energization boundary, so a reset failure
                // cannot assume an inherited per-chain rail was off merely
                // because this run had not yet issued ENABLE_VOLTAGE.
                am2_power.set_exact_dspic(pic_session)?;

                // Bosminer's am2 cold-boot order resets the hashboard after the
                // APW rail is owned but before per-chain dsPIC voltage enable.
                // A post-enable reset can drop ASICs immediately after the
                // DC-DC ramp, so keep the reset-before-enable ordering aligned
                // with the hybrid path.
                info!("Phase 1b: Pulsing am2 hashboard reset before PIC voltage enable");
                require_am2_bringup_active(&self.shutdown, "before hashboard reset")?;
                serial_route_domains
                    .as_mut()
                    .context("AM2 reset lost its watchdog-bound route-domain owner")?
                    .pulse_am2_hashboard_reset(route)?;
                require_am2_bringup_active(&self.shutdown, "after hashboard reset")?;
                info!("Phase 1c: Waiting 2s after HB reset for fan/autoconfig gate ('Fans OK' window)");
                wait_am2_bringup_active(
                    &self.shutdown,
                    Duration::from_secs(2),
                    "post-reset fan/autoconfig window",
                )
                .await?;

                // Pic0x89Service handles fw0x86 bare ENABLE as a one-byte
                // firmware ACK and uses frame-shape-aware RESET/JUMP guards;
                //.
                require_am2_bringup_active(&self.shutdown, "before dsPIC voltage cold boot")?;
                let dspic_bringup_shutdown = self.shutdown.clone();
                am2_power
                    .exact_dspic_controller_mut()?
                    .cold_boot_init_cancellable(13_700, || {
                        dspic_bringup_shutdown.is_cancelled()
                    })
                    .context("BM1362 direct PIC service cold_boot_init failed")?;
                require_am2_bringup_active(&self.shutdown, "after dsPIC voltage cold boot")?;
                info!("BM1362 direct PIC cold_boot_init returned OK (SetVoltage 13.7V applied + ENABLE_VOLTAGE accepted at protocol level â€” ACK/echo only); rail engagement UNVERIFIED until the post-enable chain-UART probe / chain enumeration below");

                // Post-ENABLE chain UART rail-engagement probe. APW121215a
                // has no voltage feedback (`psu.rs:493`) and dsPIC fw=0x86
                // bare GET_VOLTAGE only echoes the FW byte, so chain UART
                // byte-count is the only software signal of actual rail
                // engagement. and
                // .
                let observation = serial_route_domains
                    .as_mut()
                    .context("AM2 serial observation lost route-domain ownership")?
                    .begin_am2_observation(
                        am2_bm1362_route_admission.as_ref().context(
                            "AM2 route admission disappeared before preserve-state observation",
                        )?,
                        chip_count,
                    )?;
                observation.observe_preserve_state(pic_addr)?;
                am2_serial_observation = Some(observation);

                wait_am2_bringup_active(
                    &self.shutdown,
                    Duration::from_millis(1200),
                    "post-voltage chain stabilization",
                )
                .await?;
            }

            info!(
                "Phase 2: Full BM1362 ASIC init ({} configured chips)",
                chip_count
            );
            let route = am2_bm1362_route_admission
                .take()
                .context("AM2 BM1362 route admission disappeared before serial binding")?;
            require_am2_bringup_active(&self.shutdown, "before reset-baseline observation")?;
            let observation = am2_serial_observation
                .take()
                .context("AM2 serial observation facade disappeared before reset baseline")?;
            let observed = observation.observe_reset_baseline()?;
            require_am2_bringup_active(&self.shutdown, "after reset-baseline observation")?;
            let bound_observed = serial_route_domains
                .as_ref()
                .context("AM2 BM1362 observed serial binding lost its route-domain owner")?
                .bind_am2_observed_serial(observed, route, chip_count)?;
            let validated_backend = serial_route_domains
                .as_mut()
                .context("AM2 BM1362 serial execution lost its route-domain owner")?
                .promote_am2_execution(observation, bound_observed)?
                .with_am2_energized_cancellation(self.shutdown.clone());
            require_am2_bringup_active(&self.shutdown, "before fenced ASIC initialization")?;
            let (validated_backend, assigned_geometry) = Self::init_bm1362_chain(
                validated_backend,
                &serial_device,
                115_200,
                chip_count,
                target_freq,
            )
            .context("AM2 BM1362 fenced initialization failed")?;
            require_am2_bringup_active(&self.shutdown, "after fenced ASIC initialization")?;
            validated_backend.set_response_len(resp_body_len);
            validated_serial_geometry = Some(assigned_geometry);
            Ok(SerialWorkTransport::Validated(validated_backend))
            }
            .await;
            match bm1362_bringup_result {
                Ok(serial) => serial,
                Err(error) => {
                    let error = if am2_apw_heartbeat_required {
                        match am2_apw_heartbeat_exit_rx.try_recv() {
                            Ok(reason) => error.context(format!(
                                "AM2 BM1362 APW heartbeat failed during hardware bring-up: {reason}"
                            )),
                            Err(mpsc::error::TryRecvError::Disconnected)
                            | Err(mpsc::error::TryRecvError::Empty) => error,
                        }
                    } else {
                        error
                    };
                    if am2_never_energized.is_some() {
                        let closeout = close_am2_watchdog_never_energized(
                            &mut am2_watchdog,
                            &mut am2_never_energized,
                            &mut serial_route_domains,
                            &mut runtime_threads,
                        )
                        .await;
                        return Err(failure_with_am2_never_energized_closeout(error, closeout));
                    }
                    let closeout = closeout_am2_bm1362_failure(
                        &mut am2_watchdog,
                        &mut serial_route_domains,
                        &mut am2_power,
                        &mut runtime_threads,
                    )
                    .await;
                    return Err(failure_with_am2_closeout(error, closeout));
                }
            }
        };
        // Retire the unused root sender on bypass/non-APW compositions. On an
        // exact APW route it was retired before stabilization, making the
        // worker the sole sender so panic/early loss is observable immediately.
        drop(am2_apw_heartbeat_exit_tx.take());

        let published_chip_count = match (validated_serial_route, validated_serial_geometry.take())
        {
            (true, Some(geometry)) => geometry.observed_chip_count(),
            (true, None) => {
                let error = anyhow::anyhow!(
                    "validated direct-serial runtime reached publication without exact post-assignment address coverage"
                );
                if native_nopic_power_owner {
                    let closeout = closeout_native_nopic_failure(
                        &mut nopic_watchdog,
                        &mut serial_route_domains,
                        &mut nopic_psu_guard,
                        &mut runtime_threads,
                        None,
                    )
                    .await;
                    return Err(failure_with_closeout(error, closeout));
                }
                let closeout = closeout_am2_bm1362_failure(
                    &mut am2_watchdog,
                    &mut serial_route_domains,
                    &mut am2_power,
                    &mut runtime_threads,
                )
                .await;
                return Err(failure_with_am2_closeout(error, closeout));
            }
            (false, Some(_)) => {
                anyhow::bail!("validated serial geometry escaped into a legacy route")
            }
            (false, None) => chip_count,
        };
        match (validated_serial_route, &serial) {
            (true, SerialWorkTransport::Validated(_)) | (false, SerialWorkTransport::Legacy(_)) => {
            }
            (true, SerialWorkTransport::Legacy(_)) => {
                let error = anyhow::anyhow!(
                    "validated direct-serial runtime reached work transport without execution authority"
                );
                if native_nopic_power_owner {
                    let closeout = closeout_native_nopic_failure(
                        &mut nopic_watchdog,
                        &mut serial_route_domains,
                        &mut nopic_psu_guard,
                        &mut runtime_threads,
                        None,
                    )
                    .await;
                    return Err(failure_with_closeout(error, closeout));
                }
                let closeout = closeout_am2_bm1362_failure(
                    &mut am2_watchdog,
                    &mut serial_route_domains,
                    &mut am2_power,
                    &mut runtime_threads,
                )
                .await;
                return Err(failure_with_am2_closeout(error, closeout));
            }
            (false, SerialWorkTransport::Validated(_)) => {
                anyhow::bail!("validated serial execution authority escaped into a legacy route")
            }
        }

        if matches!(serial_actor_topology, SerialActorTopology::ExactAm2Bm1362) {
            let thermal_pic = match am2_power
                .exact_dspic_controller()
                .context("AM2 BM1362 thermal proof lost exact endpoint custody")
            {
                Ok(thermal_pic) => thermal_pic,
                Err(error) => {
                    let closeout = closeout_am2_bm1362_failure(
                        &mut am2_watchdog,
                        &mut serial_route_domains,
                        &mut am2_power,
                        &mut runtime_threads,
                    )
                    .await;
                    return Err(failure_with_am2_closeout(error, closeout));
                }
            };
            let supervisor = crate::s19j_hybrid_mining::Am2ThermalSupervisor::new(
                Some(thermal_pic),
                self.config.thermal.hot_temp_c,
                self.config.thermal.dangerous_temp_c,
                self.config.thermal.die_temp_calibration.clone(),
            );
            let (supervisor, startup_thermal) = match poll_am2_thermal_bounded(
                supervisor,
                crate::s19j_hybrid_mining::Am2ThermalPollStage::PreStratum(
                    "direct-serial-pre-stratum",
                ),
                true,
            )
            .await
            {
                Ok(result) => result,
                Err(error) => {
                    let primary =
                        error.context("AM2 BM1362 thermal proof failed before pool connection");
                    let closeout = closeout_am2_bm1362_failure(
                        &mut am2_watchdog,
                        &mut serial_route_domains,
                        &mut am2_power,
                        &mut runtime_threads,
                    )
                    .await;
                    return Err(failure_with_am2_closeout(primary, closeout));
                }
            };
            info!(
                temp_c = startup_thermal.temp_c,
                source = ?startup_thermal.source,
                "AM2 BM1362 board/XADC thermal visibility admitted before sustained mining"
            );
            am2_startup_temp_c = Some(startup_thermal.temp_c);
            am2_startup_temp_source = Some(startup_thermal.chain_temp_source().to_string());
            am2_thermal_supervisor = Some(supervisor);
        }

        let (am2_pic_heartbeat_exit_tx, mut am2_pic_heartbeat_exit_rx) =
            mpsc::unbounded_channel::<Am2PicHeartbeatExit>();
        let am2_pic_heartbeat_progress = Arc::new(AtomicU64::new(0));
        let monitor_dspic_heartbeat_actor =
            is_bm1362 && !passthrough && !serial_actor_topology.is_nopic();

        // ---- Phase 3: PIC heartbeat thread (kernel I2C) ----
        // S21/T21 NoPic: no PIC â†’ no heartbeat needed (voltage stays from kernel DAC)
        if passthrough {
            info!("Phase 3: SKIPPED - passthrough mode does not own PIC voltage state");
        } else if serial_actor_topology.is_nopic() {
            info!("Phase 3: SKIPPED â€” NoPic model, no PIC heartbeat needed");
        } else {
            info!("Phase 3: Starting PIC heartbeat thread");
            let hb_shutdown = match runtime_threads.cancellation_token() {
                Ok(token) => token,
                Err(error) => {
                    let error = failure_with_exact_serial_closeout(
                        error,
                        serial_actor_topology,
                        &mut nopic_watchdog,
                        &mut am2_watchdog,
                        &mut serial_route_domains,
                        &mut nopic_psu_guard,
                        &mut am2_power,
                        &mut runtime_threads,
                    )
                    .await;
                    return Err(error);
                }
            };
            let heartbeat_exact_pic = match am2_power
                .exact_dspic_controller()
                .context("BM1362 heartbeat lost exact endpoint custody")
            {
                Ok(pic) => pic,
                Err(error) => {
                    let closeout = closeout_am2_bm1362_failure(
                        &mut am2_watchdog,
                        &mut serial_route_domains,
                        &mut am2_power,
                        &mut runtime_threads,
                    )
                    .await;
                    return Err(failure_with_am2_closeout(error, closeout));
                }
            };
            let am2_heartbeat_exit = am2_pic_heartbeat_exit_tx.clone();
            let am2_heartbeat_progress = am2_pic_heartbeat_progress.clone();
            let heartbeat_start_result = runtime_threads.spawn_pic_heartbeat(|| {
                std::thread::Builder::new()
                    .name("s19j-pic-hb".to_string())
                    .spawn(move || {
                        let mut pic = heartbeat_exact_pic;
                        let mut fails = 0u32;
                        loop {
                            if hb_shutdown.is_cancelled() {
                                break;
                            }
                            let result = pic.send_heartbeat();
                            match observe_am2_heartbeat_result(
                                &mut fails,
                                result.is_ok(),
                                am2_pic_heartbeat_terminal_limit,
                            ) {
                                Am2HeartbeatDisposition::Healthy {
                                    recovered_failures,
                                } => {
                                    if recovered_failures > 0 {
                                        info!(
                                            recovered_failures,
                                            "exact AM2 dsPIC heartbeat recovered"
                                        );
                                    }
                                    am2_heartbeat_progress.fetch_add(1, Ordering::Release);
                                }
                                Am2HeartbeatDisposition::Retrying {
                                    consecutive_failures,
                                } => {
                                    let error = result.expect_err("retrying requires an error");
                                    warn!(
                                        fails = consecutive_failures,
                                        %error,
                                        "exact AM2 dsPIC heartbeat failed; withholding combined watchdog liveness"
                                    );
                                }
                                Am2HeartbeatDisposition::Terminal {
                                    consecutive_failures,
                                } => {
                                    let error = result.expect_err("terminal failure requires an error");
                                    let reason = format!(
                                        "exact AM2 dsPIC heartbeat failed {consecutive_failures} consecutive times: {error}"
                                    );
                                    error!(
                                        fails = consecutive_failures,
                                        %error,
                                        "exact AM2 dsPIC heartbeat authority revoked; requesting terminal safe-off"
                                    );
                                    let _ = am2_heartbeat_exit
                                        .send(Am2PicHeartbeatExit::Failed(reason));
                                    break;
                                }
                            }
                            if crate::runtime::thread_guard::sleep_until_cancelled(
                                &hb_shutdown,
                                Duration::from_millis(PIC_HEARTBEAT_INTERVAL_MS),
                            ) {
                                break;
                            }
                        }
                    })
                    .context("Failed to spawn heartbeat thread")
            });
            match heartbeat_start_result {
                Ok(()) => {}
                Err(error)
                    if matches!(serial_actor_topology, SerialActorTopology::ExactAm2Bm1362) =>
                {
                    let closeout = closeout_am2_bm1362_failure(
                        &mut am2_watchdog,
                        &mut serial_route_domains,
                        &mut am2_power,
                        &mut runtime_threads,
                    )
                    .await;
                    return Err(failure_with_am2_closeout(error, closeout));
                }
                Err(error) => {
                    return Err(error);
                }
            }
        } // end NoPic check
          // The exact actor is now the sole sender. Closure without a failure
          // receipt proves panic or unexpected actor loss.
        drop(am2_pic_heartbeat_exit_tx);

        // ---- Arm the hardware watchdog (AFTER chain bring-up completes) ----
        // `--serial-mining` (PIC and NoPic) bypasses `Daemon::run()`, so this path
        // historically armed NO `/dev/watchdog` â€” a CPU/runtime hang here left the
        // boards energized & unsupervised. Arm it now (chain init + heartbeat
        // complete, before pool connect) via the shared, config-gated helper â€”
        // NOT earlier, so the DTB-10s window can never trip during cold-boot.
        // SAF-5: gate kicks on this path's mining/event-loop heartbeat so a
        // live-locked serial miner stops feeding `/dev/watchdog` after the
        // counter has started advancing. The Amlogic thermal arm still owns
        // actual temperature fail-closed behavior.
        let watchdog_liveness = Arc::new(AtomicU64::new(0));
        let mut legacy_watchdog_feed_owner = if nopic_watchdog.is_none() && am2_watchdog.is_none() {
            crate::daemon::spawn_watchdog_kicker(
                &self.config.watchdog,
                Some(watchdog_liveness.clone()),
            )
        } else {
            None
        };

        // ---- Phase 4: Pool connection ----
        info!("Phase 4: Connecting to pool");
        let (job_tx, mut job_rx) = mpsc::channel::<dcentrald_stratum::types::JobTemplate>(32);
        let (share_tx, share_rx) = mpsc::channel::<dcentrald_stratum::types::ValidShare>(256);
        let (status_tx, mut status_rx) =
            mpsc::channel::<dcentrald_stratum::types::StratumStatus>(64);
        let (mining_sync_tx, _) = tokio::sync::broadcast::channel(256);
        let (jd_status_tx, jd_status_rx) = tokio::sync::watch::channel(
            crate::daemon::initial_job_declaration_status(&self.config.job_declaration),
        );
        crate::daemon::spawn_job_declaration_supervisor(
            self.config.job_declaration.clone(),
            jd_status_tx,
            self.shutdown.clone(),
        );

        let serial_version_rolling = self.config.mining.version_rolling;
        if is_bm1398 && self.config.mining.version_rolling {
            info!("BM1398 serial path reconstructs rolled versions from nonce midstate index");
        }

        // P2-9: use observed/published chip count when validated geometry exists.
        let stratum_config = crate::config::build_stratum_config_with_enumerated_chips(
            &self.config,
            crate::config::stratum_donation_config(&self.config.donation),
            serial_version_rolling,
            false,
            (published_chip_count > 0).then_some(u32::from(published_chip_count)),
        );
        let stratum_router = dcentrald_stratum::StratumRouter::new(stratum_config)
            .with_job_declaration_status_rx(jd_status_rx.clone());
        let recent_share_history = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(async move {
            stratum_router.run(job_tx, share_rx, status_tx).await;
        });

        let (state_tx, state_rx) = tokio::sync::watch::channel(dcentrald_api::MinerState {
            hashrate_ghs: 0.0,
            hashrate_5s_ghs: 0.0,
            accepted: 0,
            rejected: 0,
            chains: vec![dcentrald_api::ChainState {
                id: 0,
                chips: published_chip_count,
                frequency_mhz: target_freq,
                voltage_mv: published_voltage_mv,
                temp_c: 0.0,
                temp_source: None,
                hashrate_ghs: 0.0,
                errors: 0,
                // FWT-4: this is the pre-mining initial snapshot (hashrate 0) â€”
                // report the honest "active" (chain present, not yet producing),
                // not a fabricated "mining".
                status: "active".to_string(),
            }],
            fans: dcentrald_api::FanState {
                // Placeholder snapshot (rpm/temp/hashrate all 0 here): report the
                // quiet idle floor, not a max-blast number. The old NoPic value
                // (127) was both alarming and off-scale for the Amlogic 0-100 fan
                // range; this is display-only telemetry, never a fan command.
                pwm: 10,
                rpm: 0,
                per_fan: vec![],
            },
            pool: dcentrald_api::PoolState {
                url: self.config.pool.url.clone(),
                worker: self.config.pool.worker.clone(),
                status: "connecting".to_string(),
                difficulty: 0.0,
                last_share_at: 0,
                protocol: "sv1".to_string(),
                encrypted: false,
                encrypted_source: dcentrald_api::pool_quality_honest_default_source(),
                sv2_session: None,
                sv2_session_source: dcentrald_api::pool_quality_honest_default_source(),
                donating: false,
                donating_source: dcentrald_api::pool_quality_honest_default_source(),
                donation_active_url: String::new(),
                donation_active_worker: String::new(),
                donation_pool_index: 0,
                share_efficiency: None,
                auto_fallback_active: false,
                auto_fallback_source: dcentrald_api::pool_quality_honest_default_source(),
                auto_retry_sv2_after_s: None,
                sv2_custom_job: None,
                auto_fallback_reason: None,
                failover: dcentrald_stratum::types::PoolFailoverStatus::default(),
                failover_source: dcentrald_api::pool_quality_honest_default_source(),
                hashrate_split: dcentrald_stratum::types::HashrateSplitStatus::default(),
                hashrate_split_source: dcentrald_api::pool_quality_honest_default_source(),
                latency_ms: 0,
                latency_ms_source: dcentrald_api::pool_quality_honest_default_source(),
                reject_reason_counts: [0; 6],
                reject_reason_counts_source: dcentrald_api::pool_quality_honest_default_source(),
                rolling_acceptance_pct_30min: 100.0,
                rolling_acceptance_count_30min: (0, 0),
                rolling_acceptance_source: dcentrald_api::pool_quality_honest_default_source(),
                worst_chip_hw_err_rate: None,
            },
            uptime_s: 0,
            firmware_version: "0.4.0".to_string(),
            mode: dcentrald_api::OperatingMode::Standard,
        });

        // Status logger
        let ss = self.shutdown.clone();
        let recent_share_history_status = recent_share_history.clone();
        let mining_sync_status_tx = mining_sync_tx.clone();
        let status_state_tx = state_tx.clone();
        let (pool_hashing_allowed_tx, mut pool_hashing_allowed_rx) =
            tokio::sync::watch::channel(false);
        // A watch receiver may coalesce Mining -> Connecting before the main
        // loop observes the intermediate value. Preserve the monotonic fact
        // that pool hashing authority was once announced; terminal action
        // still additionally requires a successful UART work commit.
        let pool_hashing_ever_allowed = Arc::new(AtomicBool::new(false));
        let pool_hashing_ever_allowed_status = Arc::clone(&pool_hashing_ever_allowed);
        tokio::spawn(async move {
            let mut current_pool_difficulty = 1.0f64;
            let mut pool_quality = dcentrald_stratum::pool_quality::PoolQualitySnapshot::default();
            loop {
                tokio::select! {
                    _ = ss.cancelled() => break,
                    Some(st) = status_rx.recv() => {
                        dcentrald_stratum::pool_quality::apply_stratum_status(
                            &mut pool_quality,
                            &st,
                        );
                        let quality_snapshot = pool_quality.clone();
                        status_state_tx.send_modify(|state| {
                            state.pool.apply_quality_snapshot(&quality_snapshot);
                        });
                        match st {
                        dcentrald_stratum::types::StratumStatus::ShareAccepted { job_id, pool_target_difficulty, achieved_difficulty, meta } => {
                            let timestamp_ms = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64;
                            let target_difficulty = if pool_target_difficulty > 0.0 {
                                pool_target_difficulty
                            } else {
                                current_pool_difficulty
                            }
                            .max(1.0);
                            let achieved_difficulty = achieved_difficulty
                                .filter(|value| value.is_finite() && *value > 0.0);
                            let lucky_share = achieved_difficulty
                                .map(|difficulty| difficulty >= target_difficulty * 10.0)
                                .unwrap_or(false);
                            let _ = mining_sync_status_tx.send(
                                dcentrald_api::websocket::build_mining_sync_message(
                                    &dcentrald_api::websocket::WsMiningSyncMessage {
                                        msg_type: "mining_sync".to_string(),
                                        timestamp_ms,
                                        event: if lucky_share {
                                            dcentrald_api::websocket::WsMiningSyncEventKind::LuckyShare
                                        } else {
                                            dcentrald_api::websocket::WsMiningSyncEventKind::ShareAccepted
                                        },
                                        chain_id: None,
                                        count: Some(1),
                                        job_id: Some(job_id.clone()),
                                        difficulty: achieved_difficulty,
                                        target_difficulty: Some(target_difficulty),
                                        intensity: Some(0.75),
                                        error_code: None,
                                        error_msg: None,
                                    },
                                ),
                            );
                            dcentrald_api::push_recent_share_event(
                                &recent_share_history_status,
                                dcentrald_api::RecentShareEvent {
                                    timestamp_ms,
                                    result: "accepted".to_string(),
                                    job_id: job_id.clone(),
                                    difficulty: achieved_difficulty,
                                    target_difficulty: Some(target_difficulty),
                                    error_code: None,
                                    error_msg: None,
                                    worker_name: meta.as_ref().map(|meta| meta.share.worker_name.clone()),
                                    nonce: meta.as_ref().map(|meta| meta.share.nonce.clone()),
                                    ntime: meta.as_ref().map(|meta| meta.share.ntime.clone()),
                                    extranonce2: meta.as_ref().map(|meta| meta.share.extranonce2.clone()),
                                    version_bits: meta.as_ref().and_then(|meta| meta.share.version_bits.clone()),
                                    version: meta.as_ref().map(|meta| meta.share.version),
                                    protocol_meta_present: meta.is_some(),
                                },
                            );
                            status_state_tx.send_modify(|state| {
                                state.accepted += 1;
                                state.pool.difficulty = target_difficulty;
                                state.pool.last_share_at = timestamp_ms / 1000;
                            });
                            info!(job_id = %job_id, pool_target_difficulty = target_difficulty, achieved_difficulty, "SHARE ACCEPTED");
                        }
                        dcentrald_stratum::types::StratumStatus::ShareRejected { job_id, error_code, error_msg, meta } => {
                            let timestamp_ms = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64;
                            let _ = mining_sync_status_tx.send(
                                dcentrald_api::websocket::build_mining_sync_message(
                                    &dcentrald_api::websocket::WsMiningSyncMessage {
                                        msg_type: "mining_sync".to_string(),
                                        timestamp_ms,
                                        event: dcentrald_api::websocket::WsMiningSyncEventKind::ShareRejected,
                                        chain_id: None,
                                        count: Some(1),
                                        job_id: Some(job_id.clone()),
                                        difficulty: None,
                                        target_difficulty: Some(current_pool_difficulty.max(1.0)),
                                        intensity: Some(0.75),
                                        error_code: Some(error_code),
                                        error_msg: Some(error_msg.clone()),
                                    },
                                ),
                            );
                            dcentrald_api::push_recent_share_event(
                                &recent_share_history_status,
                                dcentrald_api::RecentShareEvent {
                                    timestamp_ms,
                                    result: "rejected".to_string(),
                                    job_id: job_id.clone(),
                                    difficulty: None,
                                    target_difficulty: Some(current_pool_difficulty.max(1.0)),
                                    error_code: Some(error_code),
                                    error_msg: Some(error_msg.clone()),
                                    worker_name: meta.as_ref().map(|meta| meta.share.worker_name.clone()),
                                    nonce: meta.as_ref().map(|meta| meta.share.nonce.clone()),
                                    ntime: meta.as_ref().map(|meta| meta.share.ntime.clone()),
                                    extranonce2: meta.as_ref().map(|meta| meta.share.extranonce2.clone()),
                                    version_bits: meta.as_ref().and_then(|meta| meta.share.version_bits.clone()),
                                    version: meta.as_ref().map(|meta| meta.share.version),
                                    protocol_meta_present: meta.is_some(),
                                },
                            );
                            status_state_tx.send_modify(|state| {
                                state.rejected += 1;
                                state.pool.difficulty = current_pool_difficulty.max(1.0);
                            });
                            warn!(job_id = %job_id, error = %error_msg, "SHARE REJECTED");
                        }
                        dcentrald_stratum::types::StratumStatus::DifficultyChanged(d) => {
                            current_pool_difficulty = d;
                            status_state_tx.send_modify(|state| {
                                state.pool.difficulty = d;
                            });
                            info!("Pool difficulty: {}", d);
                        }
                        dcentrald_stratum::types::StratumStatus::StateChanged(state) => {
                            let pool_hashing_allowed = matches!(
                                state,
                                dcentrald_stratum::types::StratumState::Mining
                                    | dcentrald_stratum::types::StratumState::Donating
                            );
                            if pool_hashing_allowed {
                                pool_hashing_ever_allowed_status.store(true, Ordering::Release);
                            }
                            let _ = pool_hashing_allowed_tx.send(pool_hashing_allowed);
                            let status_str = match state {
                                dcentrald_stratum::types::StratumState::Disconnected => "Disconnected",
                                dcentrald_stratum::types::StratumState::Connecting => "Connecting",
                                dcentrald_stratum::types::StratumState::Authorized => "Authorized",
                                dcentrald_stratum::types::StratumState::Mining => "Alive",
                                dcentrald_stratum::types::StratumState::Donating => "Donating",
                                dcentrald_stratum::types::StratumState::AuthFailed => "AuthFailed",
                            };
                            status_state_tx.send_modify(|miner_state| {
                                miner_state.pool.status = status_str.to_string();
                            });
                            let pool_authorized = matches!(status_str, "Authorized" | "Alive" | "Donating");
                            let authorize_state = match status_str {
                                "Alive" => "mining",
                                other => other,
                            }
                            .to_ascii_lowercase();
                            let timestamp_ms = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64;
                            let _ = mining_sync_status_tx.send(
                                dcentrald_api::websocket::build_mining_sync_message_with_fields(
                                    &dcentrald_api::websocket::WsMiningSyncMessage {
                                        msg_type: "mining_sync".to_string(),
                                        timestamp_ms,
                                        event: dcentrald_api::websocket::WsMiningSyncEventKind::AuthorizeState,
                                        chain_id: None,
                                        count: Some(1),
                                        job_id: None,
                                        difficulty: None,
                                        target_difficulty: None,
                                        intensity: None,
                                        error_code: None,
                                        error_msg: None,
                                    },
                                    vec![
                                        ("pool_authorized", serde_json::json!(pool_authorized)),
                                        ("authorize_state", serde_json::json!(authorize_state)),
                                    ],
                                ),
                            );
                            info!("Pool: {:?}", state)
                        }
                        dcentrald_stratum::types::StratumStatus::Sv2CustomJobDeclared { channel_id, request_id, template_id } => {
                            let updated_at_s = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            status_state_tx.send_modify(|state| {
                                state.pool.sv2_custom_job = Some(dcentrald_api::Sv2CustomJobInfo {
                                    status: "declared".to_string(),
                                    channel_id: Some(channel_id),
                                    request_id: Some(request_id),
                                    template_id: Some(template_id),
                                    job_id: None,
                                    last_error: None,
                                    updated_at_s,
                                });
                            });
                        }
                        dcentrald_stratum::types::StratumStatus::Sv2CustomJobAccepted { channel_id, request_id, template_id, job_id } => {
                            let updated_at_s = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            status_state_tx.send_modify(|state| {
                                state.pool.sv2_custom_job = Some(dcentrald_api::Sv2CustomJobInfo {
                                    status: "accepted".to_string(),
                                    channel_id: Some(channel_id),
                                    request_id: Some(request_id),
                                    template_id: Some(template_id),
                                    job_id: Some(job_id),
                                    last_error: None,
                                    updated_at_s,
                                });
                            });
                        }
                        dcentrald_stratum::types::StratumStatus::Sv2CustomJobRejected { channel_id, request_id, template_id, reason } => {
                            let updated_at_s = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            status_state_tx.send_modify(|state| {
                                state.pool.sv2_custom_job = Some(dcentrald_api::Sv2CustomJobInfo {
                                    status: "rejected".to_string(),
                                    channel_id: Some(channel_id),
                                    request_id: Some(request_id),
                                    template_id,
                                    job_id: None,
                                    last_error: Some(reason.clone()),
                                    updated_at_s,
                                });
                            });
                        }
                        _ => {}
                        }
                    }
                }
            }
        });

        // ---- Phase 4.5: Serial I/O thread ----
        // Blocking serial reads (VTIME=100ms) cannot run in async context â€”
        // they block the tokio executor and starve job_rx/dispatch_timer.
        // Solution: dedicated thread owns serial port, handles both reads and writes.
        let (nonce_tx, mut nonce_rx) = mpsc::channel::<Vec<u8>>(256);
        let (serial_actor_exit_tx, mut serial_actor_exit_rx) =
            mpsc::unbounded_channel::<SerialActorExit>();
        let serial_actor_progress = Arc::new(AtomicU64::new(0));
        // Incremented only after the execution-fenced backend has completed a
        // physical UART work commit. Queue admission is not sufficient proof:
        // disconnect handling must distinguish stale software work from a job
        // that an ASIC may continue hashing autonomously.
        let am2_committed_work_epoch = Arc::new(AtomicU64::new(0));
        let work_queue_depth = if is_bm1362 {
            BM1362_SERIAL_WORK_QUEUE_DEPTH
        } else {
            DEFAULT_SERIAL_WORK_QUEUE_DEPTH
        };
        let tx_burst_per_loop = if is_bm1362 {
            BM1362_SERIAL_TX_BURST
        } else {
            DEFAULT_SERIAL_TX_BURST
        };
        let tx_before_rx = is_bm1362;
        let work_queue: Arc<Mutex<VecDeque<Vec<u8>>>> =
            Arc::new(Mutex::new(VecDeque::with_capacity(work_queue_depth)));
        let work_queue_io = Arc::clone(&work_queue);

        // Keep VTIME=1 (100ms) â€” proven to work. Bounded queue provides pipeline depth.

        let reader_shutdown = match runtime_threads.cancellation_token() {
            Ok(token) => token,
            Err(error) => {
                let error = failure_with_exact_serial_closeout(
                    error,
                    serial_actor_topology,
                    &mut nopic_watchdog,
                    &mut am2_watchdog,
                    &mut serial_route_domains,
                    &mut nopic_psu_guard,
                    &mut am2_power,
                    &mut runtime_threads,
                )
                .await;
                return Err(error);
            }
        };
        let parsed_uart_trans_chains = if is_bm1362 {
            Self::am3_bb_uart_trans_chains_from_serial_device(&serial_device)
        } else {
            None
        };
        if parsed_uart_trans_chains.is_some() && !Self::am3_bb_uart_trans_lab_enabled() {
            warn!(
                serial_device = %serial_device,
                "BM1362 /dev/ttyO* uart_trans routing skipped by default; set DCENT_AM3_BB_ENABLE_UART_TRANS_LAB=1 only for R6-9 capture work"
            );
        }
        let am3_bb_uart_trans_chains = if Self::am3_bb_uart_trans_lab_enabled() {
            parsed_uart_trans_chains
        } else {
            None
        };
        let thread_name = if am3_bb_uart_trans_chains.is_some() {
            "am3-bb-uart-trans-io"
        } else {
            "s19j-serial-io"
        };
        let monitor_serial_actor = am3_bb_uart_trans_chains.is_none();
        let serial_io_result = runtime_threads.spawn_serial_io(thread_name, || {
            if let Some(selected_chains) = am3_bb_uart_trans_chains {
                info!(
                    serial_device = %serial_device,
                    ?selected_chains,
                    "Routing BM1362 /dev/ttyO* work through userspace uart_trans"
                );
                drop(serial);
                Self::spawn_am3_bb_uart_trans_io_thread(
                    serial_device.clone(),
                    selected_chains,
                    work_queue_io,
                    nonce_tx,
                    reader_shutdown,
                    work_queue_depth,
                    tx_burst_per_loop,
                )
            } else {
                let actor_exit_tx = serial_actor_exit_tx.clone();
                let actor_progress = serial_actor_progress.clone();
                let committed_work_epoch = Arc::clone(&am2_committed_work_epoch);
                std::thread::Builder::new()
                    .name("s19j-serial-io".to_string())
                    .spawn(move || {
                        let exit = run_serial_io_actor(
                            serial,
                            work_queue_io,
                            nonce_tx,
                            reader_shutdown,
                            actor_progress,
                            committed_work_epoch,
                            is_bm1362,
                            tx_burst_per_loop,
                            tx_before_rx,
                        );
                        let _ = actor_exit_tx.send(exit);
                        info!("Serial I/O thread exited");
                    })
                    .context("Failed to spawn serial I/O thread")
            }
        });
        match serial_io_result {
            Ok(()) => {}
            Err(error) if native_nopic_power_owner => {
                let closeout = closeout_native_nopic_failure(
                    &mut nopic_watchdog,
                    &mut serial_route_domains,
                    &mut nopic_psu_guard,
                    &mut runtime_threads,
                    None,
                )
                .await;
                return Err(failure_with_closeout(error, closeout));
            }
            Err(error) if is_bm1362 => {
                let closeout = closeout_am2_bm1362_failure(
                    &mut am2_watchdog,
                    &mut serial_route_domains,
                    &mut am2_power,
                    &mut runtime_threads,
                )
                .await;
                return Err(failure_with_am2_closeout(error, closeout));
            }
            Err(error) => return Err(error),
        }
        // The actor clone is now the sole exit sender. Channel closure without
        // an explicit event therefore proves a panic or unexpected sender loss.
        drop(serial_actor_exit_tx);

        // ---- Phase 4b: Start API servers (dashboard, REST, CGMiner, WebSocket) ----
        let (mode_tx, mode_rx) =
            tokio::sync::watch::channel(dcentrald_api::OperatingMode::Standard);
        let (stats_tx, _) = tokio::sync::broadcast::channel(64);
        let (diag_tx, _) = tokio::sync::broadcast::channel(16);
        let (auto_tx, _) = tokio::sync::broadcast::channel(16);
        let (power_tx, power_rx) =
            tokio::sync::watch::channel(dcentrald_autotuner::LivePowerEstimate::default());
        let (auto_status_tx, auto_status_rx) =
            tokio::sync::watch::channel(dcentrald_autotuner::AutotunerRuntimeStatus::default());
        let (auto_eff_tx, auto_eff_rx) =
            tokio::sync::watch::channel(None::<dcentrald_autotuner::EfficiencySnapshot>);
        let (auto_health_tx, auto_health_rx) =
            tokio::sync::watch::channel(None::<dcentrald_autotuner::LiveChipHealthState>);
        let (auto_telem_tx, auto_telem_rx) =
            tokio::sync::watch::channel(dcentrald_autotuner::TelemetryExportState::default());

        let api_config = dcentrald_api::ApiConfig {
            cgminer_port: self.config.api.cgminer_port,
            http_port: self.config.api.http_port,
            http_bind: self.config.api.http_bind.clone(),
            websocket_enabled: self.config.api.websocket,
            websocket_tickets: self.config.api.websocket_tickets,
            cgminer_bind_lan: self.config.api.cgminer_bind_lan,
            cgminer_lan_writes: self.config.api.cgminer_lan_writes,
            metrics_require_auth: self.config.api.metrics_require_auth,
            // W13.D1: dev-mode boot-timeline gate. See ApiConfig docs.
            expose_boot_timeline: self.config.api.expose_boot_timeline,
            observer_only: crate::runtime_policy::ephemeral_runtime_enabled(),
        };
        let power_calibration = std::sync::Arc::new(std::sync::RwLock::new(
            self.config.power.calibration.clone().unwrap_or_default(),
        ));
        let psu_lock = std::sync::Arc::new(std::sync::Mutex::new(()));
        // The exact route-domain owner exposes this gate. Native NoPic opens it
        // once at AppState publication; exact AM2 retains the sole opener and
        // exposes a permanently pending denial gate because no API adapter can
        // borrow its polarity-aware GPIO907/dsPIC owners. Legacy routes retain
        // their existing open gate outside the exact watchdog composition.
        let hardware_mutation_gate_result = match serial_actor_topology {
            SerialActorTopology::ExactNoPic | SerialActorTopology::ExactAm2Bm1362 => {
                serial_route_domains
                    .as_mut()
                    .context("exact serial API publication lost its route-domain owner")
                    .and_then(SerialRouteDomains::management_api_gate)
            }
            SerialActorTopology::LegacyNoPic | SerialActorTopology::LegacyPic => {
                if serial_route_domains.is_some() {
                    Err(anyhow::anyhow!(
                        "legacy serial route unexpectedly retained exact API authority"
                    ))
                } else {
                    Ok(dcentrald_hal::platform::HardwareMutationGate::new_open())
                }
            }
        };
        let hardware_mutation_gate = match hardware_mutation_gate_result {
            Ok(gate) => gate,
            Err(error) => {
                let error = failure_with_exact_serial_closeout(
                    error,
                    serial_actor_topology,
                    &mut nopic_watchdog,
                    &mut am2_watchdog,
                    &mut serial_route_domains,
                    &mut nopic_psu_guard,
                    &mut am2_power,
                    &mut runtime_threads,
                )
                .await;
                return Err(error);
            }
        };

        let history_path = history::storage_path();
        let history_buffer = HistoryBuffer::load(&history_path);
        let history_data = Arc::new(Mutex::new(history::serialize_for_api(
            &history_buffer.samples(),
        )));
        let solar_history = Arc::new(Mutex::new(Vec::new()));
        let history_state_rx = state_rx.clone();
        let history_power_rx = power_rx.clone();
        let mining_pipeline_snapshot_rx = if self.config.mining.pipeline_snapshot.enabled {
            Some(
                dcentrald_api::mining_pipeline_snapshot::spawn_mining_pipeline_snapshot_publisher(
                    &mining_sync_tx,
                    self.config.mining.pipeline_snapshot.stale_after_ms,
                ),
            )
        } else {
            None
        };

        let app_state = std::sync::Arc::new(dcentrald_api::AppState {
            state_rx: state_rx.clone(),
            mode_rx: mode_rx.clone(),
            stats_tx: stats_tx.clone(),
            mining_sync_tx: mining_sync_tx.clone(),
            mining_pipeline_snapshot_rx,
            mining_pipeline_snapshot_stale_after_ms: self
                .config
                .mining
                .pipeline_snapshot
                .stale_after_ms
                .max(1),
            diagnostic_progress_tx: diag_tx.clone(),
            diagnostic_service: Arc::new(tokio::sync::Mutex::new(
                dcentrald_diagnostics::DiagnosticService::new(diag_tx),
            )),
            autotuner_tx: auto_tx,
            config: api_config,
            network_block: self.config.network_block.clone(),
            jd_status_rx,
            profile_path: "/tmp/profiles".to_string(),
            led_tx: None,
            led_status_rx: None,
            curtailment: std::sync::Arc::new(tokio::sync::Mutex::new(
                dcentrald_thermal::curtailment::CurtailmentController::new(),
            )),
            power_rx: power_rx.clone(),
            power_calibration,
            psu_lock,
            hardware_mutation_gate: hardware_mutation_gate.clone(),
            autotuner_status_rx: auto_status_rx,
            autotuner_efficiency_rx: auto_eff_rx,
            autotuner_chip_health_rx: auto_health_rx,
            autotuner_telemetry_rx: auto_telem_rx,
            autotuner_command_tx: None,
            history_data: history_data.clone(),
            recent_share_history: recent_share_history.clone(),
            local_reject_ring: std::sync::Arc::new(std::sync::Mutex::new(
                dcentrald_api_types::share_validation::LocalRejectRing::with_default_capacity(),
            )),
            boot_progress: std::sync::Arc::new(dcentrald_api::BootProgressSnapshot::new()),
            audit_ring: std::sync::Arc::new(std::sync::Mutex::new(
                dcentrald_api_types::audit_log::AuditRing::with_default_capacity(),
            )),
            room_temp_c10: std::sync::atomic::AtomicU32::new(0),
            hardware_info: std::sync::Arc::new(std::sync::Mutex::new(
                dcentrald_api::HardwareInfo::default(),
            )),
            // W13.D1 boot phase tracker â€” default Generic(Booting), live
            // wiring deferred to W14+.
            boot_phase_tracker: std::sync::Arc::new(
                dcentrald_api::boot_phase_tracker::BootPhaseTracker::new(),
            ),
            offgrid_rx: None,
            pid_state_rx: None,
            pid_command_tx: None,
            solar_rx: None,
            solar_history,
            // P3-2: read-only status handlers read this in-memory mirror of
            // dcentrald.toml instead of re-parsing the file every request.
            config_cache: std::sync::Arc::new(dcentrald_api::ConfigTableCache::new()),
        });

        match dcentrald_api::start_api_servers(app_state).await {
            Ok(_) => info!(
                http_port = self.config.api.http_port,
                cgminer_port = self.config.api.cgminer_port,
                "API servers online â€” dashboard + CGMiner + WebSocket"
            ),
            Err(e) => {
                warn!(error = %e, "Failed to start API servers â€” mining without monitoring")
            }
        }

        let _metrics_csv_handle = crate::metrics_export::spawn_metrics_csv_task(
            self.shutdown.clone(),
            state_rx.clone(),
            power_rx.clone(),
        );

        let history_shutdown = self.shutdown.clone();
        let history_buffer_task = history_buffer.clone();
        let history_data_task = history_data.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(history::HISTORY_INTERVAL_S));
            loop {
                tokio::select! {
                    _ = history_shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        let timestamp_s = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let state = history_state_rx.borrow().clone();
                        let power = history_power_rx.borrow().clone();
                        let sample = history::sample_from_runtime(timestamp_s, &state, &power);
                        history_buffer_task.push(sample);

                        if let Ok(mut guard) = history_data_task.lock() {
                            *guard = history::serialize_for_api(&history_buffer_task.samples());
                        }
                    }
                }
            }
        });

        // ---- Phase 5: Mining loop ----
        info!(
            "=== MINING ACTIVE â€” {} {} chips on {} at {} MHz ===",
            chip_count,
            if is_bm1398 {
                "BM1398"
            } else if is_bm1366 {
                "BM1366"
            } else if is_bm1370 {
                "BM1370"
            } else if is_bm1368 {
                "BM1368"
            } else {
                "BM1362"
            },
            serial_device,
            target_freq
        );

        let mut work_builder = dcentrald_stratum::share_pipeline::WorkBuilder::new();
        let mut current_job: Option<dcentrald_stratum::types::JobTemplate> = None;
        // P1-1 pure history + SerialMiningEngineBookkeeping façade (job-id +
        // generation-keyed dedup retain-prune SSOT).
        let history_per_id = if is_bm1398 {
            BM1398_WORK_HISTORY_PER_ID
        } else {
            WORK_HISTORY_PER_ID
        };
        let mut work_history: WorkHistoryRing<WorkEntry> = WorkHistoryRing::new(history_per_id);
        let mut bookkeeping = SerialMiningEngineBookkeeping::serial_mining(job_id_increment);

        let mut total_work: u64 = 0;
        let mut total_nonces: u64 = 0;
        let mut shares_submitted: u64 = 0;
        let start_time = Instant::now();
        let mut last_hr_time = Instant::now();
        let mut hr_nonces: u64 = 0;

        let dispatch_ms = if is_bm1362 {
            BM1362_DISPATCH_INTERVAL_MS
        } else if is_bm1366 {
            (2000u64 / chip_count.max(1) as u64).max(10)
        } else if is_bm1368 || is_bm1370 {
            BM1368_DISPATCH_INTERVAL_MS
        } else {
            50
        };
        let mut dispatch_timer = tokio::time::interval(Duration::from_millis(dispatch_ms));
        let mut hashrate_timer = tokio::time::interval(Duration::from_secs(5));
        let mut mining_sync_timer = tokio::time::interval(Duration::from_millis(250));
        let mut pending_dispatches = 0u32;
        let mut pending_nonces = 0u32;
        let am2_nonce_timeout_s = if is_bm1362 {
            self.config.mining.am2_no_nonce_timeout_s
        } else {
            0
        };
        let mut am2_nonce_safety = Am2NonceSafetyGuard::new(
            am2_nonce_timeout_s,
            crate::s19j_hybrid_mining::am2_mid_run_nonce_stall_timeout(am2_nonce_timeout_s),
        );
        let mut am2_nonce_safety_timer = tokio::time::interval(Duration::from_secs(1));
        let hash_on_disconnect_enabled = self.config.hash_on_disconnect.enabled;
        let mut am2_pool_disconnect_safety = Am2PoolDisconnectSafety::default();

        // Thermal management for NoPic/Amlogic platforms
        let mut thermal_timer = tokio::time::interval(Duration::from_secs(2));
        let mut am2_thermal_timer = tokio::time::interval(Duration::from_secs(2));
        // The pre-energize cooling owner computed this retained ceiling once;
        // every steady-state command below uses the same value.
        let mut latest_temp_c: f32 = am2_startup_temp_c.unwrap_or(0.0);
        let mut latest_temp_source = am2_startup_temp_source;
        let mut latest_fan_pwm: u8 = if amlogic_fan.is_some() {
            // THERMAL-2: seed with the degraded-tach-clamped ceiling, matching the
            // startup `fan.set_speed(effective_fan_max_pwm)` above.
            effective_fan_max_pwm
        } else if am2_fan.is_some() {
            self.config
                .thermal
                .fan_max_pwm
                .min(dcentrald_hal::fan::PWM_MAX)
                .min(dcentrald_hal::fan::PWM_SAFETY_MAX)
        } else {
            10
        };
        let mut latest_fan_rpm: u32 = 0;
        let mut latest_per_fan: Vec<(u8, u32)> = Vec::new();
        let thermal_started_at = nopic_energized_at.unwrap_or_else(Instant::now);
        let mut consecutive_missing_temp_ticks: u8 = 0;
        let mut early_safe_off_receipt: Option<NoPicEmergencyCutReceipt> = None;
        let mut terminal_safety_error: Option<anyhow::Error> = None;
        let mut terminal_watchdog_closeout: Option<WatchdogCloseoutReceipt> = None;

        let watchdog_enter_result: Result<()> = async {
            let mut exact_watchdog_mining_admission = if serial_actor_topology.is_exact() {
                let am2_apw_topology = match serial_actor_topology {
                    SerialActorTopology::ExactNoPic => None,
                    SerialActorTopology::ExactAm2Bm1362 => Some(am2_power.apw_actor_topology()?),
                    SerialActorTopology::LegacyNoPic | SerialActorTopology::LegacyPic => {
                        unreachable!("legacy topology excluded by exact admission guard")
                    }
                };
                require_exact_serial_actor_freshness(
                    serial_actor_topology,
                    monitor_serial_actor,
                    am2_apw_topology,
                    am2_apw_heartbeat_required,
                    &mut serial_actor_exit_rx,
                    &mut am2_pic_heartbeat_exit_rx,
                    &mut am2_apw_heartbeat_exit_rx,
                )?;
                let actor_admission = runtime_threads.seal_exact_runtime(am2_apw_topology)?;
                Some(
                    serial_route_domains
                        .as_mut()
                        .context("exact serial actor admission lost its route-domain owner")?
                        .admit_runtime_actors(actor_admission)?,
                )
            } else {
                None
            };
            match serial_actor_topology {
                SerialActorTopology::ExactNoPic => {
                    anyhow::ensure!(
                        am2_watchdog.is_none(),
                        "exact NoPic topology retained a competing AM2 watchdog"
                    );
                    let admission = exact_watchdog_mining_admission
                        .take()
                        .context("NoPic watchdog Mining transition lacks exact actor admission")?;
                    let watchdog = nopic_watchdog
                        .as_mut()
                        .context("exact NoPic topology lost its retained watchdog owner")?;
                    // The serial actor, fan owner, and thermal branch now
                    // exist. The next completed liveness tick must advance the
                    // worker snapshot; zero is never an unlimited grace.
                    watchdog.enter_exact_serial_mining(admission).await
                }
                SerialActorTopology::ExactAm2Bm1362 => {
                    anyhow::ensure!(
                        nopic_watchdog.is_none(),
                        "exact AM2 topology retained a competing NoPic watchdog"
                    );
                    let admission = exact_watchdog_mining_admission
                        .take()
                        .context("AM2 watchdog Mining transition lacks exact actor admission")?;
                    let watchdog = am2_watchdog
                        .as_mut()
                        .context("exact AM2 topology lost its retained watchdog owner")?;
                    watchdog.enter_exact_serial_mining(admission).await
                }
                SerialActorTopology::LegacyNoPic | SerialActorTopology::LegacyPic => {
                    anyhow::ensure!(
                        exact_watchdog_mining_admission.is_none()
                            && nopic_watchdog.is_none()
                            && am2_watchdog.is_none(),
                        "legacy serial topology retained exact watchdog runtime authority"
                    );
                    Ok(())
                }
            }
        }
        .await;
        if let Err(error) = watchdog_enter_result {
            if native_nopic_power_owner {
                let closeout = closeout_native_nopic_failure(
                    &mut nopic_watchdog,
                    &mut serial_route_domains,
                    &mut nopic_psu_guard,
                    &mut runtime_threads,
                    None,
                )
                .await;
                return Err(failure_with_closeout(error, closeout));
            }
            let closeout = closeout_am2_bm1362_failure(
                &mut am2_watchdog,
                &mut serial_route_domains,
                &mut am2_power,
                &mut runtime_threads,
            )
            .await;
            return Err(failure_with_am2_closeout(error, closeout));
        }

        // ---- Shared work-dispatch safety admission (pure latch) ----
        let mut dispatch_life = WorkDispatchLifecycle::new();
        let owns_soc_watchdog = matches!(
            serial_actor_topology,
            SerialActorTopology::ExactNoPic | SerialActorTopology::ExactAm2Bm1362
        );
        let wd_state = serial_watchdog_safety_state(owns_soc_watchdog, true);
        let (hb_req, hb_obs) = serial_heartbeat_inputs(
            passthrough,
            serial_actor_topology.is_nopic(),
            if monitor_dspic_heartbeat_actor {
                am2_power.exact_dspic_controller().ok().map(|c| c.address())
            } else {
                None
            },
            // Heartbeat actor started (or not required); terminal failure
            // arrives via am2_pic_heartbeat_exit_rx mid-run.
            true,
            1,
        );
        // Fail-closed thermal pillar: only Ready when this run retained a real
        // thermal proof/owner. Do NOT invent Ready for legacy/passthrough paths
        // that never observed board/die temps or cooling custody.
        let thermal_proof_present =
            am2_thermal_supervisor.is_some() || amlogic_fan.is_some() || am2_fan.is_some();
        let thermal_state = serial_thermal_safety_state(thermal_proof_present, false);
        let dispatch_inputs = serial_work_dispatch_inputs(wd_state, hb_req, &hb_obs, thermal_state);
        match serial_admit_standard_work_dispatch(&mut dispatch_life, &dispatch_inputs) {
            Ok(receipt) => {
                info!(
                    watchdog = ?receipt.watchdog,
                    thermal = ?receipt.thermal,
                    controller_count = receipt.controller_count,
                    heartbeat_cycle_id = ?receipt.heartbeat_cycle_id,
                    "serial work-dispatch admission OK â€” UART work allowed"
                );
            }
            Err(err) => {
                error!(error = %err, "serial work-dispatch admission REFUSED â€” no UART work");
                if native_nopic_power_owner {
                    let closeout = closeout_native_nopic_failure(
                        &mut nopic_watchdog,
                        &mut serial_route_domains,
                        &mut nopic_psu_guard,
                        &mut runtime_threads,
                        None,
                    )
                    .await;
                    return Err(failure_with_closeout(
                        anyhow::anyhow!("serial work-dispatch admission refused: {err}"),
                        closeout,
                    ));
                }
                if matches!(serial_actor_topology, SerialActorTopology::ExactAm2Bm1362) {
                    let closeout = closeout_am2_bm1362_failure(
                        &mut am2_watchdog,
                        &mut serial_route_domains,
                        &mut am2_power,
                        &mut runtime_threads,
                    )
                    .await;
                    return Err(failure_with_am2_closeout(
                        anyhow::anyhow!("serial work-dispatch admission refused: {err}"),
                        closeout,
                    ));
                }
                return Err(anyhow::anyhow!(
                    "serial work-dispatch admission refused: {err}"
                ));
            }
        }
        let home_profile_pwm = self
            .config
            .thermal
            .fan_max_pwm
            .min(dcentrald_hal::fan::PWM_SAFETY_MAX);

        let mut last_serial_actor_progress = serial_actor_progress.load(Ordering::Acquire);
        let mut last_am2_pic_heartbeat_progress =
            am2_pic_heartbeat_progress.load(Ordering::Acquire);
        let mut last_am2_apw_heartbeat_progress =
            am2_apw_heartbeat_progress.load(Ordering::Acquire);
        // Mid-run revoke with stop_feed must suppress further SoC WDT kicks
        // immediately (stock parity) — not only during late SHUTDOWN.
        let exact_watchdog_feed_stop = am2_watchdog
            .as_ref()
            .map(|w| w.feed_stop_signal())
            .or_else(|| nopic_watchdog.as_ref().map(|w| w.feed_stop_signal()));
        loop {
            tokio::select! {
                biased;

                exit = am2_apw_heartbeat_exit_rx.recv(), if am2_apw_heartbeat_required => {
                    match exit {
                        Some(reason) => {
                            if dispatch_life.is_admitted() {
                                let _ = serial_revoke_and_stop_watchdog_feed(
                                    &mut dispatch_life,
                                    DispatchRevocationCause::HeartbeatFailure,
                                    home_profile_pwm,
                                    exact_watchdog_feed_stop.as_ref(),
                                    &mut legacy_watchdog_feed_owner,
                                );
                            }
                            terminal_safety_error = Some(anyhow::anyhow!(
                                "AM2 BM1362 APW heartbeat actor failed terminally: {reason}"
                            ));
                        }
                        None if self.shutdown.is_cancelled() => {
                            info!("AM2 BM1362 APW heartbeat actor observed runtime shutdown");
                        }
                        None => {
                            if dispatch_life.is_admitted() {
                                let _ = serial_revoke_and_stop_watchdog_feed(
                                    &mut dispatch_life,
                                    DispatchRevocationCause::HeartbeatFailure,
                                    home_profile_pwm,
                                    exact_watchdog_feed_stop.as_ref(),
                                    &mut legacy_watchdog_feed_owner,
                                );
                            }
                            terminal_safety_error = Some(anyhow::anyhow!(
                                "AM2 BM1362 APW heartbeat exit channel closed without a terminal receipt (panic or sender loss)"
                            ));
                        }
                    }
                    break;
                }

                _ = self.shutdown.cancelled() => {
                    info!("Shutdown");
                    if dispatch_life.is_admitted() {
                        let _ = serial_revoke_and_stop_watchdog_feed(
                            &mut dispatch_life,
                            DispatchRevocationCause::OperatorSafeOff,
                            home_profile_pwm,
                            exact_watchdog_feed_stop.as_ref(),
                            &mut legacy_watchdog_feed_owner,
                        );
                    }
                    break;
                }

                pool_state = pool_hashing_allowed_rx.changed() => {
                    if pool_state.is_err() {
                        if self.shutdown.is_cancelled() {
                            info!("Stratum status reducer closed during requested shutdown");
                            break;
                        }
                        terminal_safety_error = Some(anyhow::anyhow!(
                            "Stratum status reducer disappeared; hashing authority can no longer be observed"
                        ));
                        break;
                    }
                    let pool_hashing_allowed = *pool_hashing_allowed_rx.borrow();
                    let committed_work_epoch =
                        am2_committed_work_epoch.load(Ordering::Acquire);
                    let terminal_revocation = am2_pool_disconnect_safety.observe(
                        pool_hashing_allowed,
                        pool_hashing_ever_allowed.load(Ordering::Acquire),
                        committed_work_epoch,
                        hash_on_disconnect_enabled,
                    );
                    if !pool_hashing_allowed && !hash_on_disconnect_enabled {
                        current_job = None;
                        work_history.clear_all();
                        work_queue
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clear();
                        am2_nonce_safety.pause_for_missing_pool_authority();
                        info!(
                            "Pool hashing authority revoked; current job, serial queue, and work history cleared because hash_on_disconnect=false"
                        );
                        if is_bm1362 && terminal_revocation {
                            terminal_safety_error = Some(anyhow::anyhow!(
                                "AM2 BM1362 pool hashing authority was revoked after UART work commit epoch {committed_work_epoch} while hash_on_disconnect=false; terminal power cutoff required because a committed ASIC job cannot be synchronously withdrawn"
                            ));
                            break;
                        }
                    }
                }

                _ = am2_nonce_safety_timer.tick(), if is_bm1362 => {
                    let pool_hashing_allowed = *pool_hashing_allowed_rx.borrow();
                    let committed_work_epoch =
                        am2_committed_work_epoch.load(Ordering::Acquire);
                    if am2_pool_disconnect_safety.observe(
                        pool_hashing_allowed,
                        pool_hashing_ever_allowed.load(Ordering::Acquire),
                        committed_work_epoch,
                        hash_on_disconnect_enabled,
                    ) {
                        current_job = None;
                        work_history.clear_all();
                        work_queue
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clear();
                        am2_nonce_safety.pause_for_missing_pool_authority();
                        terminal_safety_error = Some(anyhow::anyhow!(
                            "AM2 BM1362 observed UART work commit epoch {committed_work_epoch} after pool hashing authority was revoked; terminal power cutoff required because committed ASIC work cannot be synchronously withdrawn"
                        ));
                        break;
                    }
                    if let Some(trip) = am2_nonce_safety.evaluate(start_time.elapsed()) {
                        terminal_safety_error = Some(anyhow::anyhow!(
                            "AM2 BM1362 nonce-safety deadline expired: {trip:?}; configured startup timeout={}s",
                            self.config.mining.am2_no_nonce_timeout_s
                        ));
                        break;
                    }
                }

                exit = am2_pic_heartbeat_exit_rx.recv(), if monitor_dspic_heartbeat_actor => {
                    match exit {
                        Some(Am2PicHeartbeatExit::Failed(reason)) => {
                            if dispatch_life.is_admitted() {
                                let _ = serial_revoke_and_stop_watchdog_feed(
                                    &mut dispatch_life,
                                    DispatchRevocationCause::HeartbeatFailure,
                                    home_profile_pwm,
                                    exact_watchdog_feed_stop.as_ref(),
                                    &mut legacy_watchdog_feed_owner,
                                );
                            }
                            terminal_safety_error = Some(anyhow::anyhow!(
                                "AM2 dsPIC heartbeat actor failed terminally: {reason}"
                            ));
                        }
                        None if self.shutdown.is_cancelled() => {
                            info!("AM2 dsPIC heartbeat actor observed runtime shutdown");
                        }
                        None => {
                            if dispatch_life.is_admitted() {
                                let _ = serial_revoke_and_stop_watchdog_feed(
                                    &mut dispatch_life,
                                    DispatchRevocationCause::HeartbeatFailure,
                                    home_profile_pwm,
                                    exact_watchdog_feed_stop.as_ref(),
                                    &mut legacy_watchdog_feed_owner,
                                );
                            }
                            terminal_safety_error = Some(anyhow::anyhow!(
                                "AM2 dsPIC heartbeat exit channel closed without a terminal receipt (panic or sender loss)"
                            ));
                        }
                    }
                    break;
                }

                exit = serial_actor_exit_rx.recv(), if monitor_serial_actor => {
                    match exit {
                        Some(SerialActorExit::Cancelled) if self.shutdown.is_cancelled() => {
                            info!("Serial I/O actor observed shutdown cancellation");
                        }
                        Some(SerialActorExit::Cancelled) => {
                            terminal_safety_error = Some(anyhow::anyhow!(
                                "serial I/O actor stopped before runtime shutdown"
                            ));
                        }
                        Some(SerialActorExit::Failed(reason)) => {
                            terminal_safety_error = Some(anyhow::anyhow!(
                                "serial I/O actor failed terminally: {reason}"
                            ));
                        }
                        None => {
                            terminal_safety_error = Some(anyhow::anyhow!(
                                "serial I/O actor exit channel closed without a terminal receipt (panic or sender loss)"
                            ));
                        }
                    }
                    break;
                }

                // Thermal control loop (every 2 seconds)
                _ = thermal_timer.tick(), if amlogic_fan.is_some() => {
                    let Some(thermal_owner) = amlogic_power_thermal
                        .as_ref()
                        .map(|service| service.thermal_port())
                    else {
                        terminal_safety_error = Some(anyhow::anyhow!(
                            "Amlogic cooling owner exists without retained power/thermal ownership"
                        ));
                        break;
                    };
                    let Some(fan_sampler) = amlogic_fan.clone() else {
                        terminal_safety_error = Some(anyhow::anyhow!(
                            "Amlogic thermal tick lost its retained cooling owner"
                        ));
                        break;
                    };
                    // Both operations are synchronous kernel/sysfs work. Run them
                    // concurrently on the blocking pool so the Tokio worker can
                    // continue processing shutdown and network tasks.
                    let temperature_worker = tokio::task::spawn_blocking(move || {
                        thermal_owner.read_board_temperatures(
                            Instant::now() + Duration::from_millis(750),
                        )
                    });
                    let fan_worker = sample_fan_tach(fan_sampler);
                    let (temperature_result, fan_result) = tokio::join!(temperature_worker, fan_worker);
                    let temperature_snapshot = match temperature_result {
                        Ok(snapshot) => snapshot,
                        Err(join_error) => {
                            error!(%join_error, "Amlogic thermal polling worker failed; cutting hash power");
                            match checked_nopic_emergency_safe_off_blocking(
                                &mut nopic_psu_guard,
                                "Amlogic thermal-worker emergency safe-off",
                            )
                            .await
                            {
                                Ok(receipt) => early_safe_off_receipt = Some(receipt),
                                Err(safe_off_error) => error!(%safe_off_error, "Amlogic thermal-worker safe-off did not complete"),
                            }
                            terminal_safety_error = Some(anyhow::anyhow!(
                                "Amlogic thermal polling worker failed: {join_error}"
                            ));
                            break;
                        }
                    };
                    let fan_snapshot = match fan_result {
                        Ok(snapshot) => snapshot,
                        Err(sample_error) => {
                            error!(%sample_error, "Amlogic fan polling worker failed; cutting hash power");
                            match checked_nopic_emergency_safe_off_blocking(
                                &mut nopic_psu_guard,
                                "Amlogic fan-worker emergency safe-off",
                            )
                            .await
                            {
                                Ok(receipt) => early_safe_off_receipt = Some(receipt),
                                Err(safe_off_error) => error!(%safe_off_error, "Amlogic fan-worker safe-off did not complete"),
                            }
                            terminal_safety_error = Some(anyhow::anyhow!(
                                "Amlogic fan polling worker failed: {sample_error}"
                            ));
                            break;
                        }
                    };
                    let FanTachSnapshot {
                        available: fan_tach_available,
                        expected_channels: expected_fan_channels,
                        readings,
                    } = fan_snapshot;
                    latest_per_fan = readings;
                    latest_fan_rpm = latest_per_fan
                        .iter()
                        .map(|(_, rpm)| *rpm)
                        .min()
                        .unwrap_or(0);
                    let fan_rpms = latest_per_fan
                        .iter()
                        .map(|(_, rpm)| *rpm)
                        .collect::<Vec<_>>();
                    let fan_safety_state = nopic_fan_safety.observe_required_airflow(
                        fan_tach_available,
                        latest_fan_pwm,
                        expected_fan_channels,
                        &fan_rpms,
                    );
                    if let FanTachSafetyState::Debouncing {
                        consecutive_below_minimum,
                        failure_ticks,
                        minimum_credible_rpm,
                    } = fan_safety_state
                    {
                        warn!(
                            consecutive_below_minimum,
                            failure_ticks,
                            minimum_credible_rpm,
                            readings = ?latest_per_fan,
                            "Amlogic below-threshold RPM observation is inside the bounded fan-failure debounce"
                        );
                    }
                    if nopic_fan_loop_disposition(&fan_safety_state)
                        == NoPicFanLoopDisposition::SafeOffAndStop
                    {
                        error!(
                            ?fan_safety_state,
                            readings = ?latest_per_fan,
                            "Amlogic fan safety admission revoked; cutting hash power"
                        );
                        match checked_nopic_emergency_safe_off_blocking(
                            &mut nopic_psu_guard,
                            "Amlogic fan-safety emergency safe-off",
                        )
                        .await
                        {
                            Ok(receipt) => early_safe_off_receipt = Some(receipt),
                            Err(safe_off_error) => error!(%safe_off_error, "Amlogic fan-safety checked safe-off did not complete"),
                        }
                        let _ = crate::restart::schedule_daemon_restart(
                            "amlogic_fan_safety_restart",
                            Duration::from_secs(AMLOGIC_THERMAL_RESTART_DELAY_S),
                        );
                        terminal_safety_error = Some(anyhow::anyhow!(
                            "Amlogic fan safety admission revoked: {fan_safety_state:?}"
                        ));
                        break;
                    }
                    let required_coverage = temperature_snapshot.required_coverage();
                    let dangerous_observation = temperature_snapshot
                        .hottest_celsius()
                        .is_some_and(|temp| temp >= self.config.thermal.dangerous_temp_c as f32);
                    if let Some(ref fan) = amlogic_fan {
                        if !required_coverage.is_complete() && !dangerous_observation {
                            latest_temp_c = 0.0;
                            latest_temp_source = None;
                            // stale-temp / no thermal proof: cap fans at the PWM-30 home cap.
                            // NoPic (am3-aml) has no die-temp fallback, and disable_psu fires
                            // after the startup grace â€” so blasting fans here is never justified.
                            // ("stale-temp ... ALL must cap at
                            // PWM 30"). swarm wf_e0647147 GAP #2 (emergency/stale arm).
                            // THERMAL-2: use the degraded-tach-clamped ceiling (then the
                            // PWM-30 stale-temp safety cap). Both only lower the value.
                            let stale_pwm = effective_fan_max_pwm
                                .min(dcentrald_hal::fan::PWM_SAFETY_MAX);
                            match set_fan_speed_checked_blocking(
                                Arc::clone(fan),
                                stale_pwm,
                                "Amlogic stale-temperature fan command/readback",
                            )
                            .await
                            {
                                Ok(receipt) => latest_fan_pwm = receipt.observed_pwm(),
                                Err(fan_error) => {
                                    error!(%fan_error, "Amlogic stale-temperature fan command/readback failed; cutting hash power");
                                    match checked_nopic_emergency_safe_off_blocking(
                                        &mut nopic_psu_guard,
                                        "Amlogic stale-temperature fan-failure safe-off",
                                    )
                                    .await
                                    {
                                        Ok(receipt) => early_safe_off_receipt = Some(receipt),
                                        Err(safe_off_error) => error!(%safe_off_error, "Amlogic fan failure emergency safe-off did not complete"),
                                    }
                                    terminal_safety_error = Some(anyhow::anyhow!(
                                        "Amlogic stale-temperature fan command/readback failed: {fan_error}"
                                    ));
                                    break;
                                }
                            }
                            consecutive_missing_temp_ticks = consecutive_missing_temp_ticks.saturating_add(1);

                            if thermal_started_at.elapsed() >= Duration::from_secs(AMLOGIC_TEMP_STARTUP_GRACE_S)
                                && consecutive_missing_temp_ticks >= AMLOGIC_TEMP_MISS_LIMIT
                            {
                                error!(
                                    required_slots = ?required_coverage.required_slots(),
                                    missing_slots = ?required_coverage.missing_slots(),
                                    missing_ticks = consecutive_missing_temp_ticks,
                                    grace_s = AMLOGIC_TEMP_STARTUP_GRACE_S,
                                    "Required Amlogic board-temperature coverage remained incomplete after startup grace â€” shutting down NoPic mining for safety"
                                );
                                match checked_nopic_emergency_safe_off_blocking(
                                    &mut nopic_psu_guard,
                                    "Amlogic missing-temperature emergency safe-off",
                                )
                                .await
                                {
                                    Ok(receipt) => early_safe_off_receipt = Some(receipt),
                                    Err(safe_off_error) => error!(%safe_off_error, "Amlogic missing-temperature checked safe-off did not complete"),
                                }
                                let _ = crate::restart::schedule_daemon_restart(
                                    "amlogic_missing_temps_restart",
                                    Duration::from_secs(AMLOGIC_THERMAL_RESTART_DELAY_S),
                                );
                                terminal_safety_error = Some(anyhow::anyhow!(
                                    "Required Amlogic board-temperature coverage remained incomplete after the startup grace"
                                ));
                                break;
                            }
                        } else {
                            consecutive_missing_temp_ticks = 0;
                            let max_temp = temperature_snapshot
                                .hottest_celsius()
                                .unwrap_or(0.0);
                            latest_temp_c = max_temp;
                            latest_temp_source = (max_temp > 0.0).then(|| {
                                dcentrald_api::ChainTempSource::BOARD_SENSOR.to_string()
                            });
                            if max_temp >= self.config.thermal.dangerous_temp_c as f32 {
                                error!(temp = max_temp, "DANGEROUS TEMP — emergency PSU disable!");
                                // P1-6: cut-hash-before-noise via pure SafetyAction, then adapters.
                                // Fan cap first is inverted vs policy — policy cuts power then fans.
                                // Order: revoke dispatch → PSU safe-off (cut) → home-capped fan.
                                let thermal_action =
                                    PowerCut::home_thermal_hard_stop_action(home_profile_pwm);
                                let emergency_pwm = effective_fan_max_pwm
                                    .min(dcentrald_hal::fan::PWM_SAFETY_MAX);
                                if dispatch_life.is_admitted() {
                                    let _ = serial_revoke_and_stop_watchdog_feed(
                                        &mut dispatch_life,
                                        DispatchRevocationCause::ThermalCutoff,
                                        home_profile_pwm,
                                        exact_watchdog_feed_stop.as_ref(),
                                        &mut legacy_watchdog_feed_owner,
                                    );
                                }
                                // Execute SafetyAction: CutPower → CommandFans (P1-6).
                                // Cut = NoPic PSU safe-off; Fan = home-capped emergency PWM.
                                let mut cut_ok = false;
                                let mut fan_err: Option<String> = None;
                                let apply_report = apply_safety_action(
                                    thermal_action,
                                    |_cut| {
                                        // Blocking safe-off is async; mark intent — real I/O below.
                                        cut_ok = true;
                                        Ok::<(), ()>(())
                                    },
                                    |_pwm| Ok(()),
                                );
                                let _ = apply_report;
                                if cut_ok {
                                    match checked_nopic_emergency_safe_off_blocking(
                                        &mut nopic_psu_guard,
                                        "Amlogic dangerous-temperature emergency safe-off",
                                    )
                                    .await
                                    {
                                        Ok(receipt) => early_safe_off_receipt = Some(receipt),
                                        Err(safe_off_error) => error!(%safe_off_error, "Amlogic dangerous-temperature checked safe-off did not complete"),
                                    }
                                }
                                match set_fan_speed_checked_blocking(
                                    Arc::clone(fan),
                                    emergency_pwm,
                                    "Amlogic emergency fan command/readback",
                                )
                                .await
                                {
                                    Ok(receipt) => latest_fan_pwm = receipt.observed_pwm(),
                                    Err(fan_error) => {
                                        fan_err = Some(fan_error.to_string());
                                        error!(%fan_error, "Amlogic emergency fan command/readback failed after power cut");
                                        if early_safe_off_receipt.is_none() {
                                            match checked_nopic_emergency_safe_off_blocking(
                                                &mut nopic_psu_guard,
                                                "Amlogic emergency-fan-failure safe-off",
                                            )
                                            .await
                                            {
                                                Ok(receipt) => {
                                                    early_safe_off_receipt = Some(receipt)
                                                }
                                                Err(safe_off_error) => error!(%safe_off_error, "Amlogic emergency fan failure safe-off did not complete"),
                                            }
                                        }
                                        terminal_safety_error = Some(anyhow::anyhow!(
                                            "Amlogic emergency fan command/readback failed: {fan_error}"
                                        ));
                                        break;
                                    }
                                }
                                let _ = fan_err;
                                let _ = crate::restart::schedule_daemon_restart(
                                    "amlogic_thermal_restart",
                                    Duration::from_secs(AMLOGIC_THERMAL_RESTART_DELAY_S),
                                );
                                terminal_safety_error = Some(anyhow::anyhow!(
                                    "Amlogic dangerous temperature {max_temp:.1} C triggered emergency shutdown"
                                ));
                                break; // exit mining loop â€” NoPicPsuGuard::Drop handles cleanup
                            } else if max_temp >= self.config.thermal.hot_temp_c as f32 {
                                warn!(temp = max_temp, "HOT â€” fans to profile max");
                                // THERMAL-2: degraded-tach-clamped ceiling.
                                // F-02: also clamp to PWM_SAFETY_MAX for symmetry with
                                // the DANGEROUS/emergency arm above. effective_fan_max_pwm
                                // is already â‰¤ the home cap on a correctly-configured unit
                                // (home cap â‰¤ 30), so this is strictly-safer defense
                                // against a misconfig where the profile ceiling exceeds the
                                // hard fan cap â€” a HOT event must never blast past it.
                                let hot_pwm =
                                    effective_fan_max_pwm.min(dcentrald_hal::fan::PWM_SAFETY_MAX);
                                match set_fan_speed_checked_blocking(
                                    Arc::clone(fan),
                                    hot_pwm,
                                    "Amlogic hot-state fan command/readback",
                                )
                                .await
                                {
                                    Ok(receipt) => latest_fan_pwm = receipt.observed_pwm(),
                                    Err(fan_error) => {
                                        error!(%fan_error, "Amlogic hot-state fan command/readback failed; cutting hash power");
                                        match checked_nopic_emergency_safe_off_blocking(
                                            &mut nopic_psu_guard,
                                            "Amlogic hot-state fan-failure safe-off",
                                        )
                                        .await
                                        {
                                            Ok(receipt) => early_safe_off_receipt = Some(receipt),
                                            Err(safe_off_error) => error!(%safe_off_error, "Amlogic hot-state fan failure safe-off did not complete"),
                                        }
                                        terminal_safety_error = Some(anyhow::anyhow!(
                                            "Amlogic hot-state fan command/readback failed: {fan_error}"
                                        ));
                                        break;
                                    }
                                }
                            } else {
                                // Proportional fan control: scale between min and the
                                // THERMAL-2 degraded-tach-clamped max PWM.
                                let target = self.config.thermal.target_temp_c as f32;
                                // Guard the denominator: a target_temp_c of 30 makes it 0,
                                // and 0/0 (max_temp==30) yields NaN â†’ `NaN as u8 == 0`, which
                                // would command fan PWM 0 in the cool branch instead of
                                // min_pwm. `.max(1.0)` keeps the ratio finite and fail-safe.
                                let ratio =
                                    ((max_temp - 30.0) / (target - 30.0).max(1.0)).clamp(0.0, 1.0);
                                let min_pwm = effective_fan_min_pwm as f32;
                                let max_pwm = effective_fan_max_pwm as f32;
                                let pwm = (min_pwm + ratio * (max_pwm - min_pwm)) as u8;
                                match set_fan_speed_checked_blocking(
                                    Arc::clone(fan),
                                    pwm,
                                    "Amlogic proportional fan command/readback",
                                )
                                .await
                                {
                                    Ok(receipt) => latest_fan_pwm = receipt.observed_pwm(),
                                    Err(fan_error) => {
                                        error!(%fan_error, "Amlogic thermal fan command/readback failed; cutting hash power");
                                        match checked_nopic_emergency_safe_off_blocking(
                                            &mut nopic_psu_guard,
                                            "Amlogic thermal-fan-failure safe-off",
                                        )
                                        .await
                                        {
                                            Ok(receipt) => early_safe_off_receipt = Some(receipt),
                                            Err(safe_off_error) => error!(%safe_off_error, "Amlogic thermal fan failure safe-off did not complete"),
                                        }
                                        terminal_safety_error = Some(anyhow::anyhow!(
                                            "Amlogic thermal fan command/readback failed: {fan_error}"
                                        ));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    nopic_watchdog_liveness.mark_progress();
                }

                _ = am2_thermal_timer.tick(), if am2_fan.is_some() => {
                    let Some(supervisor) = am2_thermal_supervisor.take() else {
                        terminal_safety_error = Some(anyhow::anyhow!(
                            "AM2 BM1362 fan owner exists without retained thermal supervision"
                        ));
                        break;
                    };
                    let Some(fan) = am2_fan.clone() else {
                        terminal_safety_error = Some(anyhow::anyhow!(
                            "AM2 BM1362 safety tick lost retained fan custody"
                        ));
                        break;
                    };
                    let (supervisor, thermal_observation) = match poll_am2_thermal_bounded(
                        supervisor,
                        crate::s19j_hybrid_mining::Am2ThermalPollStage::Runtime(
                            "direct-serial-runtime",
                        ),
                        false,
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(error) => {
                            if dispatch_life.is_admitted() {
                                let _ = serial_revoke_and_stop_watchdog_feed(
                                    &mut dispatch_life,
                                    DispatchRevocationCause::ThermalCutoff,
                                    home_profile_pwm,
                                    exact_watchdog_feed_stop.as_ref(),
                                    &mut legacy_watchdog_feed_owner,
                                );
                            }
                            terminal_safety_error = Some(error.context(
                                "AM2 BM1362 runtime thermal evidence was revoked"
                            ));
                            break;
                        }
                    };
                    am2_thermal_supervisor = Some(supervisor);
                    latest_temp_c = thermal_observation.temp_c;
                    latest_temp_source =
                        Some(thermal_observation.chain_temp_source().to_string());
                    let fan_receipt = match set_fan_speed_checked_blocking(
                        Arc::clone(&fan),
                        latest_fan_pwm,
                        "AM2 BM1362 runtime fan command/readback",
                    )
                    .await
                    {
                        Ok(receipt) => receipt,
                        Err(error) => {
                            terminal_safety_error = Some(anyhow::anyhow!(
                                "AM2 BM1362 checked fan command failed: {error}"
                            ));
                            break;
                        }
                    };
                    latest_fan_pwm = fan_receipt.observed_pwm();
                    let fan_snapshot = match sample_fan_tach(fan).await {
                        Ok(snapshot) => snapshot,
                        Err(error) => {
                            terminal_safety_error = Some(error.context(
                                "AM2 BM1362 all-channel tach sampling failed"
                            ));
                            break;
                        }
                    };
                    latest_per_fan = fan_snapshot.readings;
                    latest_fan_rpm = latest_per_fan
                        .iter()
                        .map(|(_, rpm)| *rpm)
                        .min()
                        .unwrap_or(0);
                    let rpms = latest_per_fan
                        .iter()
                        .map(|(_, rpm)| *rpm)
                        .collect::<Vec<_>>();
                    let fan_state = am2_fan_safety.observe_required_airflow(
                        fan_snapshot.available,
                        latest_fan_pwm,
                        fan_snapshot.expected_channels,
                        &rpms,
                    );
                    if nopic_fan_loop_disposition(&fan_state)
                        == NoPicFanLoopDisposition::SafeOffAndStop
                    {
                        terminal_safety_error = Some(anyhow::anyhow!(
                            "AM2 BM1362 required-airflow evidence was revoked: {fan_state:?}"
                        ));
                        break;
                    }
                    if matches!(fan_state, FanTachSafetyState::Debouncing { .. }) {
                        warn!(
                            ?fan_state,
                            readings = ?latest_per_fan,
                            "AM2 BM1362 fan evidence is debouncing; withholding watchdog liveness"
                        );
                        continue;
                    }
                    let actor_progress = serial_actor_progress.load(Ordering::Acquire);
                    if actor_progress == last_serial_actor_progress {
                        warn!(
                            actor_progress,
                            "AM2 BM1362 serial actor made no bounded I/O progress; withholding watchdog liveness"
                        );
                        continue;
                    }
                    let heartbeat_progress =
                        am2_pic_heartbeat_progress.load(Ordering::Acquire);
                    if heartbeat_progress == last_am2_pic_heartbeat_progress {
                        warn!(
                            heartbeat_progress,
                            "AM2 BM1362 dsPIC heartbeat made no fresh progress; withholding combined watchdog liveness"
                        );
                        continue;
                    }
                    if am2_apw_heartbeat_required {
                        let apw_progress = am2_apw_heartbeat_progress.load(Ordering::Acquire);
                        if apw_progress == last_am2_apw_heartbeat_progress {
                            warn!(
                                apw_progress,
                                "AM2 BM1362 APW heartbeat made no fresh progress; withholding combined watchdog liveness"
                            );
                            continue;
                        }
                        last_am2_apw_heartbeat_progress = apw_progress;
                    }
                    last_serial_actor_progress = actor_progress;
                    last_am2_pic_heartbeat_progress = heartbeat_progress;
                    am2_watchdog_liveness.mark_progress();
                }

                Some(job) = job_rx.recv() => {
                    let sync_job_id = job.job_id.clone();
                    if job.clean_jobs {
                        info!(job_id = %job.job_id, "NEW BLOCK");
                        work_history.clear_all();
                        bookkeeping.on_clean_jobs();
                        work_builder.reset_extranonce2();
                        work_queue.lock().unwrap_or_else(|e| { tracing::warn!("work_queue mutex poisoned"); e.into_inner() }).clear(); // flush stale work
                    }
                    work_builder.set_version_mask(job.version_mask);
                    let _ = mining_sync_tx.send(
                        dcentrald_api::websocket::build_mining_sync_message(
                            &dcentrald_api::websocket::WsMiningSyncMessage {
                                msg_type: "mining_sync".to_string(),
                                timestamp_ms: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis() as u64,
                                event: if job.clean_jobs {
                                    dcentrald_api::websocket::WsMiningSyncEventKind::CleanJob
                                } else {
                                    dcentrald_api::websocket::WsMiningSyncEventKind::JobReceived
                                },
                                chain_id: None,
                                count: Some(1),
                                job_id: Some(sync_job_id),
                                difficulty: None,
                                target_difficulty: None,
                                intensity: Some(if job.clean_jobs { 1.0 } else { 0.45 }),
                                error_code: None,
                                error_msg: None,
                            },
                        ),
                    );
                    if job.is_flush_only() {
                        info!(
                            job_id = %job.job_id,
                            "Pool switch flush complete; serial dispatch paused until the next pool notify"
                        );
                        current_job = None;
                        continue;
                    }
                    current_job = Some(job);
                }

                _ = dispatch_timer.tick() => {
                    // Fail-closed: never push UART work without live admission.
                    if !dispatch_life.is_admitted() {
                        continue;
                    }
                    if let Some(ref job) = current_job {
                        let work = match work_builder.next_work(job) {
                            Ok(work) => work,
                            Err(error) => {
                                warn!(%error, "V1 work domain unavailable; pausing serial dispatch until a fresh generation arrives");
                                current_job = None;
                                continue;
                            }
                        };
                        // P1-1: pure SerialMiningEngineBookkeeping assigns job_id + generation.
                        let ticket = bookkeeping.take_dispatch();
                        let asic_job_id = ticket.job_id;
                        let dispatch_generation = ticket.generation;

                        // BM1362/BM1366 Full Header serial work format (ESP-Miner struct):
                        //   [0]     = job_id (full byte, 0-127)
                        //   [1]     = num_midstates (0x01)
                        //   [2..5]  = starting_nonce (0x00000000)
                        //   [6..9]  = nbits (LE)
                        //   [10..13] = ntime (LE)
                        //   [14..45] = merkle_root (32 bytes, word-reversed)
                        //   [46..77] = prev_block_hash (32 bytes, word-reversed)
                        //   [78..81] = version (LE)
                        // Total payload: 82 bytes
                        // Length byte: 0x56 = 86 = cmd(1) + len(1) + payload(82) + CRC16(2)
                        let work_frame = if is_bm1398 {
                            // BM1398 midstate work format (4 midstates)
                            // Payload: job_id(1) + num_ms(1) + nonce(4) + nbits(4) + ntime(4) + merkle4(4) + 4*midstate(128) = 146
                            let mut payload = vec![0u8; 146];
                            payload[0] = asic_job_id;
                            payload[1] = 0x04; // num_midstates = 4
                            // payload[2..5] = starting_nonce = 0 (already zero)
                            payload[6..10].copy_from_slice(&work.nbits.to_le_bytes());
                            payload[10..14].copy_from_slice(&work.ntime.to_le_bytes());
                            payload[14..18].copy_from_slice(&work.merkle4);
                            // Midstates: 32 bytes each, reversed 32-bit word order
                            for (slot, ms) in work.midstates.iter().enumerate().take(4) {
                                let base = 18 + slot * 32;
                                for i in 0..8 {
                                    let word_idx = 7 - i;
                                    payload[base + i*4..base + i*4 + 4].copy_from_slice(&[
                                        ms[word_idx*4], ms[word_idx*4+1], ms[word_idx*4+2], ms[word_idx*4+3]
                                    ]);
                                }
                            }
                            // Duplicate midstate 0 if fewer than 4 provided
                            if work.midstates.len() < 4 {
                                for slot in work.midstates.len()..4 {
                                    let dst = 18 + slot * 32;
                                    let src_data: Vec<u8> = payload[18..50].to_vec();
                                    payload[dst..dst+32].copy_from_slice(&src_data);
                                }
                            }
                            let mut frame = Vec::with_capacity(148);
                            frame.push(0x21); // header: TYPE_JOB | CMD_WRITE
                            frame.push(0x96); // length: 150 = 2(hdr+len) + 146(payload) + 2(CRC16)
                            frame.extend_from_slice(&payload);
                            frame
                        } else {
                            // BM1362 full-header work format (existing)
                            let mut payload = [0u8; 82];
                            payload[0] = asic_job_id;
                            payload[1] = 0x01; // num_midstates
                            payload[6..10].copy_from_slice(&work.nbits.to_le_bytes());
                            payload[10..14].copy_from_slice(&work.ntime.to_le_bytes());
                            let mr = reverse_32bit_words(&work.merkle_root);
                            payload[14..46].copy_from_slice(&mr);
                            let pbh = reverse_32bit_words(&work.prev_block_hash);
                            payload[46..78].copy_from_slice(&pbh);
                            payload[78..82].copy_from_slice(&work.version.to_le_bytes());
                            let mut frame = Vec::with_capacity(84);
                            frame.push(0x21);
                            frame.push(0x56); // length: 86
                            frame.extend_from_slice(&payload);
                            frame
                        };

                        work_history.push(
                            asic_job_id,
                            WorkEntry {
                                generation: dispatch_generation,
                                work_generation: work.work_generation,
                                job_id: work.job_id.clone(),
                                extranonce2: work.extranonce2.clone(),
                                ntime: work.ntime,
                                nbits: work.nbits,
                                version: work.version,
                                version_mask: work.version_mask,
                                share_target: work.share_target,
                                prev_block_hash: work.prev_block_hash,
                                merkle_root: work.merkle_root,
                            },
                        );

                        let logged_job_id = asic_job_id;
                        total_work += 1;
                        pending_dispatches = pending_dispatches.saturating_add(1);
                        if is_bm1362 {
                            am2_nonce_safety.observe_dispatch(start_time.elapsed());
                        }

                        if total_work <= 1 {
                            // Log FULL frame including preamble + CRC (88 bytes on wire)
                            let full_hex: String = {
                                // Reconstruct what send_work() produces
                                let crc = dcentrald_hal::serial_chain::crc16_public(&work_frame);
                                let mut full = vec![0x55u8, 0xAA];
                                full.extend_from_slice(&work_frame);
                                full.push((crc >> 8) as u8);
                                full.push((crc & 0xFF) as u8);
                                full.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
                            };
                            info!("FULL FRAME ON WIRE ({} bytes): {}", work_frame.len() + 4, full_hex);
                        }
                        if total_work <= 3 {
                            let hex: String = work_frame.iter().take(20)
                                .map(|b| format!("{:02X}", b))
                                .collect::<Vec<_>>().join(" ");
                            info!(
                                job_id = logged_job_id,
                                pool_job = %work.job_id,
                                hex = %hex,
                                "WORK #{} sent: {}", total_work, hex,
                            );
                        }

                        {
                            let mut q = work_queue.lock().unwrap_or_else(|e| { tracing::warn!("work_queue mutex poisoned"); e.into_inner() });
                            if q.len() >= work_queue_depth { q.pop_front(); } // drop oldest if full
                            q.push_back(work_frame);
                        }
                    }
                }

                _ = mining_sync_timer.tick() => {
                    watchdog_liveness.fetch_add(1, Ordering::Relaxed);
                    if pending_dispatches > 0 {
                        let _ = mining_sync_tx.send(
                            dcentrald_api::websocket::build_mining_sync_message(
                                &dcentrald_api::websocket::WsMiningSyncMessage {
                                    msg_type: "mining_sync".to_string(),
                                    timestamp_ms: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_millis() as u64,
                                    event: dcentrald_api::websocket::WsMiningSyncEventKind::DispatchBurst,
                                    chain_id: None,
                                    count: Some(pending_dispatches),
                                    job_id: current_job.as_ref().map(|job| job.job_id.clone()),
                                    difficulty: None,
                                    target_difficulty: None,
                                    intensity: Some((pending_dispatches.min(24) as f32) / 24.0),
                                    error_code: None,
                                    error_msg: None,
                                },
                            ),
                        );
                        pending_dispatches = 0;
                    }

                    if pending_nonces > 0 {
                        let _ = mining_sync_tx.send(
                            dcentrald_api::websocket::build_mining_sync_message(
                                &dcentrald_api::websocket::WsMiningSyncMessage {
                                    msg_type: "mining_sync".to_string(),
                                    timestamp_ms: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_millis() as u64,
                                    event: dcentrald_api::websocket::WsMiningSyncEventKind::NonceBurst,
                                    chain_id: None,
                                    count: Some(pending_nonces),
                                    job_id: current_job.as_ref().map(|job| job.job_id.clone()),
                                    difficulty: None,
                                    target_difficulty: None,
                                    intensity: Some((pending_nonces.min(64) as f32) / 64.0),
                                    error_code: None,
                                    error_msg: None,
                                },
                            ),
                        );
                        pending_nonces = 0;
                    }
                }

                Some(resp) = nonce_rx.recv() => {
                    if resp.len() < resp_body_len { continue; }

                    total_nonces += 1;
                    hr_nonces += 1;
                    pending_nonces = pending_nonces.saturating_add(1);

                    // BM1362 serial response (9 body bytes after 0xAA 0x55 preamble strip):
                    //   [0..3] = nonce (4 raw bytes from ASIC, big-endian on wire)
                    //   [4]    = midstate_num (always 0 for BM1362)
                    //   [5]    = RESULT: job_id = (byte & 0xF0) >> 1, small_core = byte & 0x0F
                    //   [6..7] = version bits (VH VL, big-endian, shifted << 13)
                    //   [8]    = FLAGS (bit7=1 = job response, bits 4:0 = CRC5)
                    //
                    // NONCE BYTE ORDER (critical for share validation + pool submission):
                    // The ASIC sends nonce bytes in big-endian order on the wire.
                    // ESP-Miner reads them into a packed struct where the u32 field
                    // gets the LE interpretation of those bytes (memcpy on LE ESP32).
                    // For share submission, ESP-Miner formats this u32 as "%08lx".
                    // The pool parses that hex value, does to_le_bytes(), and gets
                    // back the original wire bytes for header hashing.
                    //
                    // We mimic ESP-Miner: interpret the wire bytes as LE u32.
                    // from_le_bytes([resp[0], resp[1], resp[2], resp[3]]) makes
                    // resp[0] = LSB, resp[3] = MSB â€” same as C packed struct on LE.
                    let nonce = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
                    let id_byte = resp[5];
                    // BM1362 serial response ID byte: job_id encoded as (job_id << 1),
                    // small_core in lower 4 bits (BM1362 has 16 small cores like BM1370).
                    //
                    // BM1362 uses +24 job_id increment (BM1368/BM1370 family), so the
                    // extraction must match ESP-Miner BM1368/BM1370:
                    //   job_id = (id_byte & 0xF0) >> 1
                    //
                    // Example: sent job_id=24 (0x18), ASIC encodes 0x18<<1=0x30,
                    //   response byte 0x36 = 0x30 | small_core=6
                    //   (0x36 & 0xF0) >> 1 = 0x30 >> 1 = 0x18 = 24  CORRECT
                    //
                    // BM1368/BM1370/BM1362: job_id = (id_byte & 0xF0) >> 1, small_core = id_byte & 0x0F
                    let (resp_job_id, midstate_idx, version_bits_raw, flags) = if is_bm1398 {
                        // BM1398: 7-byte body [nonce(4), midstate(1), job_id(1), crc5(1)]
                        // No resp[7] or resp[8] â€” only 7 bytes after preamble strip
                        let jid = id_byte & 0xFC; // upper 6 bits = job_id
                        (jid, resp[4], 0u16, resp[6])
                    } else if is_bm1366 {
                        (
                            id_byte & 0xF8,
                            resp[4],
                            u16::from_be_bytes([resp[6], resp[7]]),
                            resp[8],
                        )
                    } else {
                        (
                            (id_byte & 0xF0) >> 1,
                            resp[4],
                            u16::from_be_bytes([resp[6], resp[7]]),
                            resp[8],
                        )
                    };

                    if flags & 0x80 == 0 { continue; }

                    if total_nonces <= 10 {
                        if is_bm1398 {
                            info!(
                                nonce = format_args!("0x{:08X}", nonce),
                                job_id = resp_job_id,
                                midstate_idx,
                                raw = format_args!("{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
                                    resp[0], resp[1], resp[2], resp[3], resp[4], resp[5], resp[6]),
                                "Nonce #{} (BM1398)", total_nonces,
                            );
                        } else {
                            info!(
                                nonce = format_args!("0x{:08X}", nonce),
                                job_id = resp_job_id,
                                midstate_idx,
                                vbits = format_args!("0x{:04X}", version_bits_raw),
                                raw = format_args!("{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
                                    resp[0], resp[1], resp[2], resp[3], resp[4], resp[5], resp[6], resp[7], resp[8]),
                                "Nonce #{}", total_nonces,
                            );
                        }
                    }

                    // resp_job_id is a raw hardware RX byte. Pure WorkHistoryRing
                    // indexes all 256 u8 slots, so out-of-range panics cannot occur;
                    // empty-slot still means stale/unmatched work.
                    if work_history.is_empty_slot(resp_job_id) {
                        debug!(resp_job_id, "Stale (no work history entry)");
                        continue;
                    }

                    let latest_entry = match work_history.latest(resp_job_id) {
                        Some(e) => e.clone(),
                        None => { warn!("History empty after non-empty check â€” skipping nonce"); continue; }
                    };
                    let latest_rolled_version = match serial_rolled_version(
                        &latest_entry,
                        version_bits_raw,
                        is_bm1398,
                        midstate_idx,
                    ) {
                        Some(version) => version,
                        None => {
                            debug!(
                                midstate_idx,
                                resp_job_id,
                                version_bits_raw = format_args!("0x{:04X}", version_bits_raw),
                                "Serial nonce referenced unsupported version metadata"
                            );
                            continue;
                        }
                    };
                    if is_bm1362 {
                        // A CRC/flag-valid response tied to retained work and
                        // supported version metadata proves live silicon even
                        // when it does not meet the pool share target.
                        am2_nonce_safety.observe_valid_nonce(start_time.elapsed());
                    }

                    // Full 80-byte header validation.
                    //
                    // NONCE BYTE ORDER FIX (root cause of share validation failure):
                    // The nonce u32 is now parsed via from_le_bytes() (matching ESP-Miner's
                    // packed struct on LE hardware). to_le_bytes() reconstructs the original
                    // wire bytes. format!("{:08x}", nonce) produces the correct pool
                    // submission hex string. Both validation and submission are consistent.
                    //
                    // prev_block_hash: internal header format (reverse_endianness_per_word
                    // already applied by WorkBuilder). merkle_root: raw SHA-256d output.
                    let latest_meets_target = dcentrald_stratum::share_pipeline::validate_full_header(
                        &serial_build_header(&latest_entry, latest_rolled_version, nonce),
                        &latest_entry.share_target,
                    );

                    if total_nonces <= 5 || latest_meets_target {
                        info!(
                            nonce = format_args!("0x{:08X}", nonce),
                            rolled_ver = format_args!("0x{:08X}", latest_rolled_version),
                            vbits = format_args!("0x{:04X}", version_bits_raw),
                            midstate_idx,
                            meets = latest_meets_target,
                            "VALIDATION: meets={}",
                            latest_meets_target,
                        );
                    }

                    if let Some((entry, rolled_version, header)) =
                        work_history.iter_newest_first(resp_job_id).find_map(|candidate| {
                        let rolled_version = serial_rolled_version(
                            candidate,
                            version_bits_raw,
                            is_bm1398,
                            midstate_idx,
                        )?;
                        let header = serial_build_header(candidate, rolled_version, nonce);
                        if dcentrald_stratum::share_pipeline::validate_full_header(&header, &candidate.share_target) {
                            Some((candidate.clone(), rolled_version, header))
                        } else {
                            None
                        }
                    }) {
                        let distinct_midstates = if is_bm1398 {
                            entry.version_mask != 0
                        } else {
                            version_bits_raw != 0
                        };
                        let dedup_midstate_idx = if distinct_midstates { midstate_idx } else { 0 };
                        // P1-1 pure SerialMiningEngineBookkeeping: generation-keyed
                        // admit + retain-prune over soft-cap.
                        if !bookkeeping.admit_share(
                            entry.generation,
                            nonce,
                            dedup_midstate_idx,
                        ) {
                            debug!(
                                generation = entry.generation,
                                nonce = format_args!("0x{:08X}", nonce),
                                midstate_idx = dedup_midstate_idx,
                                "Duplicate serial share candidate ignored"
                            );
                            continue;
                        }

                        let vdelta = rolled_version ^ entry.version;
                        let achieved_difficulty = serial_achieved_difficulty_from_header(&header);
                        let share = dcentrald_stratum::types::ValidShare {
                            work_generation: entry.work_generation,
                            worker_name: self.config.pool.worker.clone(),
                            job_id: entry.job_id.clone(),
                            extranonce2: entry.extranonce2.clone(),
                            ntime: format!("{:08x}", entry.ntime),
                            nonce: format!("{:08x}", nonce),
                            version_bits: if vdelta != 0 { Some(format!("{:08x}", vdelta)) } else { None },
                            version: rolled_version,
                            achieved_difficulty,
                        };
                        // BUG FIX (2026-04-11): try_send â†’ send().await to prevent
                        // silently dropping valid shares under backpressure.
                        match share_tx.send(share).await {
                            Ok(()) => {
                                shares_submitted += 1;
                                info!(nonce = format_args!("0x{:08X}", nonce), "SHARE #{}", shares_submitted);
                            }
                            Err(e) => {
                                error!(error = %e, "Share channel closed");
                                break;
                            }
                        }
                    }
                }

                _ = hashrate_timer.tick() => {
                    let elapsed = last_hr_time.elapsed().as_secs_f64();
                    if elapsed > 0.0 && hr_nonces > 0 {
                        let ths = hr_nonces as f64 * hw_difficulty as f64 * 4_294_967_296.0 / elapsed / 1e12;
                        info!("{:.2} TH/s â€” {} nonces, {} shares, {}s uptime",
                            ths, total_nonces, shares_submitted, start_time.elapsed().as_secs());
                        hr_nonces = 0;
                        last_hr_time = Instant::now();
                    } else {
                        info!(total_work, total_nonces, shares_submitted,
                            uptime = start_time.elapsed().as_secs(),
                            "Mining loop alive â€” {} work, {} nonces, {}s",
                            total_work, total_nonces, start_time.elapsed().as_secs());
                    }

                    // Publish loop-owned telemetry via send_modify. Each field has
                    // one writer: this loop owns hashrate/chains/fans/uptime and the
                    // status/reducer task owns accepted/rejected plus all live
                    // pool-quality fields. Leaving pool.* untouched here avoids
                    // clobbering failover, donation, SV2, latency, and reject
                    // evidence between status events.
                    let current_ths = if elapsed > 0.0 { total_nonces as f64 * hw_difficulty as f64 * 4_294_967_296.0 / start_time.elapsed().as_secs_f64() / 1e12 } else { 0.0 };
                    let per_fan = latest_per_fan
                        .iter()
                        .copied()
                        .map(|(id, rpm)| dcentrald_api::PerFanReading {
                            id,
                            rpm,
                            // Amlogic/Braiins fan PWM is already a 0-100 duty
                            // value on the serial path; do not rescale it as a
                            // legacy 0-127 S9 FPGA register.
                            pwm_percent: latest_fan_pwm.min(100),
                        })
                        .collect::<Vec<_>>();
                    state_tx.send_modify(|s| {
                        s.hashrate_ghs = current_ths * 1000.0; // TH/s â†’ GH/s
                        s.hashrate_5s_ghs = current_ths * 1000.0;
                        s.chains = vec![dcentrald_api::ChainState {
                            id: 0,
                            chips: published_chip_count,
                            frequency_mhz: target_freq,
                            voltage_mv: published_voltage_mv,
                            temp_c: latest_temp_c,
                            // Preserve the retained thermal owner's provenance:
                            // Amlogic NoPic reports board sensors, while exact AM2
                            // may honestly report the XADC SoC-die fallback.
                            temp_source: latest_temp_source.clone(),
                            hashrate_ghs: current_ths * 1000.0,
                            errors: 0,
                            // FWT-4: derive the per-chain status from the REAL
                            // measured hashrate instead of a hardcoded "mining".
                            // A chain whose rolling hashrate has collapsed to 0
                            // (stalled/dead) must read "active" (enumerated, not
                            // producing), never a falsely-alive "mining". Mirrors
                            // the hybrid path (unique_nonces>0 ? mining : active).
                            status: if current_ths > 0.0 { "mining" } else { "active" }
                                .to_string(),
                        }];
                        s.fans = dcentrald_api::FanState {
                            pwm: latest_fan_pwm,
                            rpm: latest_fan_rpm,
                            per_fan,
                        };
                        s.uptime_s = start_time.elapsed().as_secs();
                        s.firmware_version = "0.4.0".to_string();
                        s.mode = dcentrald_api::OperatingMode::Standard;
                    });
                }
            }
        }

        // A committed BM1362 job can continue autonomously during both safety
        // failure and operator cancellation. Revoke fresh UART admission
        // synchronously, then publish a bounded watchdog-feed deadline before
        // entering potentially blocking GPIO I/O. Ordered closeout below
        // repeats safe-off after every mutation domain is fenced so it can mint
        // terminal evidence.
        let (mut exact_revoked_serial, exact_revoked_api) = match serial_route_domains.take() {
            Some(domains) => match domains.begin_closeout() {
                Ok(revoked) => {
                    let (serial, api) = revoked.split_for_closeout();
                    (Some(serial), Some(api))
                }
                Err(error) => {
                    terminal_safety_error =
                        Some(error.context(
                            "exact serial route domains could not begin terminal closeout",
                        ));
                    (None, None)
                }
            },
            None => (None, None),
        };
        // Publish actor cancellation before watchdog/GPIO/control-plane work.
        // A service-backed heartbeat call is caller-bounded; the later join
        // observes completion or forces the existing hard-stop fallback.
        runtime_threads.request_stop();
        let legacy_revoked_api_commit_fence = exact_revoked_api
            .is_none()
            .then(|| hardware_mutation_gate.revoke_commit_fence());

        info!("=== SHUTDOWN ===");
        if let Some(owner) = legacy_watchdog_feed_owner.as_mut() {
            owner.close_terminal();
        }
        let mut exact_teardown_budget: Option<TeardownBudget> = None;
        let mut exact_teardown_view: Option<TeardownBudgetView> = None;
        let mut exact_teardown_admission = None;
        let watchdog_teardown_request_result = if let Some(watchdog) = nopic_watchdog.as_mut() {
            match watchdog.request_teardown_budget() {
                Ok(request) => {
                    let (budget, admission) = request.into_parts();
                    exact_teardown_view = Some(budget.view());
                    exact_teardown_budget = Some(budget);
                    exact_teardown_admission = Some(admission);
                    Ok(())
                }
                Err(error) => Err(error),
            }
        } else if let Some(watchdog) = am2_watchdog.as_mut() {
            match watchdog.request_teardown_budget() {
                Ok(request) => {
                    let (budget, admission) = request.into_parts();
                    exact_teardown_view = Some(budget.view());
                    exact_teardown_budget = Some(budget);
                    exact_teardown_admission = Some(admission);
                    Ok(())
                }
                Err(error) => Err(error),
            }
        } else {
            Ok(())
        };
        let mut exact_cutoff_timing_result: Option<Result<ExactSerialTeardownProgress>> = None;
        if !is_bm1362 && nopic_psu_guard.owns_power() {
            let _prior_emergency_cut = early_safe_off_receipt.take();
            let first_stage_result = run_timed_terminal_owner_operation_blocking(
                &mut nopic_psu_guard,
                NoPicPsuGuard::new(),
                "NoPic operator-stop first-stage safe-off",
                |guard| guard.first_stage_safe_off(),
            )
            .await;
            if let Err(error) = &first_stage_result {
                warn!(
                    %error,
                    "NoPic operator-stop first-stage GPIO cutoff failed; bounded closeout and terminal checked safe-off continue with the watchdog armed"
                );
            }
            exact_cutoff_timing_result = Some(first_stage_result.and_then(|timed| {
                ExactSerialTeardownProgress::after_nopic_checked_cut(
                    exact_teardown_view
                        .as_ref()
                        .context("NoPic teardown budget was unavailable at first-stage cutoff")?
                        .clone(),
                    timed,
                )
            }));
        }
        let mut am2_unbound_first_stage_cut = None;
        let am2_revoked_serial = if is_bm1362 {
            let first_stage_worker = run_timed_terminal_owner_operation_blocking(
                &mut am2_power,
                Am2PsuRuntimeGuard::new(),
                "AM2 BM1362 operator-stop first-stage safe-off",
                |guard| {
                    Ok(attempt_am2_first_stage_cut(
                        guard,
                        "bm1362-runtime-or-operator-stop",
                    ))
                },
            )
            .await;
            let first_stage_cut = match first_stage_worker {
                Ok(timed) => {
                    let (first_stage_cut, timing) =
                        ExactSerialTeardownProgress::after_am2_checked_cut(
                            exact_teardown_view.clone(),
                            timed,
                        );
                    exact_cutoff_timing_result = Some(timing);
                    first_stage_cut
                }
                Err(error) => {
                    let detail = format!("{error:#}");
                    exact_cutoff_timing_result = Some(Err(anyhow::anyhow!(
                        "AM2 first-stage cutoff worker produced no timing evidence: {detail}"
                    )));
                    Am2FirstStageCutAttempt { result: Err(error) }
                }
            };
            match exact_revoked_serial.take() {
                Some(revoked_serial) => Some(record_am2_first_stage_cut_after_revocation(
                    revoked_serial,
                    first_stage_cut,
                )),
                None => {
                    am2_unbound_first_stage_cut = Some(first_stage_cut.result);
                    terminal_safety_error = Some(match terminal_safety_error.take() {
                        Some(primary) => anyhow::anyhow!(
                            "{primary:#}; AM2 serial domain was unavailable after synchronous closeout attempt"
                        ),
                        None => anyhow::anyhow!(
                            "AM2 serial domain was unavailable after synchronous closeout attempt"
                        ),
                    });
                    None
                }
            }
        } else {
            None
        };
        let mut watchdog_teardown_result = match watchdog_teardown_request_result {
            Err(error) => Err(error),
            Ok(()) => match exact_teardown_admission.take() {
                Some(admission) => match exact_teardown_view.as_ref() {
                    Some(view) => {
                        if let Some(watchdog) = nopic_watchdog.as_mut() {
                            watchdog
                                .observe_teardown_admission(admission, view)
                                .await
                                .map_err(anyhow::Error::msg)
                        } else if let Some(watchdog) = am2_watchdog.as_mut() {
                            watchdog
                                .observe_teardown_admission(admission, view)
                                .await
                                .map_err(anyhow::Error::msg)
                        } else {
                            Err(anyhow::anyhow!(
                                "exact serial watchdog owner disappeared before Teardown acknowledgement"
                            ))
                        }
                    }
                    None => Err(anyhow::anyhow!(
                        "exact serial watchdog teardown budget view was unavailable"
                    )),
                },
                None if serial_actor_topology.is_exact() => Err(anyhow::anyhow!(
                    "exact serial watchdog Teardown acknowledgement authority was unavailable"
                )),
                None => Ok(()),
            },
        };
        let am2_first_stage_cut_failure = am2_revoked_serial
            .as_ref()
            .and_then(Am2RevokedSerialDomainAfterFirstStageCut::first_stage_cut_failure_detail)
            .or_else(|| {
                am2_unbound_first_stage_cut
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| format!("{error:#}"))
            });
        if let Some(detail) = am2_first_stage_cut_failure.as_ref() {
            if let Some(watchdog) = am2_watchdog.as_mut() {
                let suppression = watchdog
                    .suppress_feeds_terminally(format!(
                        "AM2 first-stage GPIO cutoff remained unverified: {detail}"
                    ))
                    .await;
                if let Err(error) = suppression {
                    terminal_safety_error = Some(match terminal_safety_error.take() {
                        Some(primary) => anyhow::anyhow!(
                            "{primary:#}; watchdog feed suppression also failed: {error:#}"
                        ),
                        None => anyhow::anyhow!(
                            "AM2 watchdog feed suppression failed after unverified cutoff: {error:#}"
                        ),
                    });
                }
            }
            watchdog_teardown_result = Err(anyhow::anyhow!(
                "watchdog feed suppression is terminal after unverified first-stage cutoff; Disarm is forbidden"
            ));
        }
        // Await the exact serial commit fence only after synchronous revocation
        // above and watchdog phase transition. No work queued during a watchdog
        // RPC can enter a revoked UART generation.
        let mut serial_execution_closeout_result = if is_bm1362 {
            match am2_revoked_serial {
                Some(revoked_serial) => {
                    let closeout = wait_am2_serial_domain_after_revocation(
                        revoked_serial,
                        remaining_exact_serial_cleanup(
                            exact_teardown_view.as_ref(),
                            RUNTIME_THREAD_STOP_TIMEOUT,
                        ),
                    )
                    .await;
                    if let Err(cut_error) = closeout.first_stage_cut {
                        terminal_safety_error = Some(match terminal_safety_error.take() {
                            Some(primary) => anyhow::anyhow!(
                                "{primary:#}; AM2 first-stage GPIO cutoff also failed: {cut_error:#}"
                            ),
                            None => anyhow::anyhow!(
                                "AM2 operator-stop first-stage GPIO cutoff failed: {cut_error:#}"
                            ),
                        });
                    }
                    closeout.serial_barrier
                }
                None => {
                    if let Some(Err(cut_error)) = am2_unbound_first_stage_cut.take() {
                        terminal_safety_error = Some(match terminal_safety_error.take() {
                            Some(primary) => anyhow::anyhow!(
                                "{primary:#}; AM2 first-stage GPIO cutoff also failed: {cut_error:#}"
                            ),
                            None => anyhow::anyhow!(
                                "AM2 operator-stop first-stage GPIO cutoff failed: {cut_error:#}"
                            ),
                        });
                    }
                    Err(anyhow::anyhow!(
                        "AM2 serial revocation evidence is unavailable during shutdown"
                    ))
                }
            }
        } else if native_nopic_power_owner {
            match exact_revoked_serial.take() {
                Some(serial) => {
                    serial
                        .complete(
                            remaining_exact_serial_cleanup(
                                exact_teardown_view.as_ref(),
                                RUNTIME_THREAD_STOP_TIMEOUT,
                            ),
                            "validated NoPic serial runtime shutdown",
                        )
                        .await
                }
                None => Err(anyhow::anyhow!(
                    "validated NoPic serial route-domain owner is unavailable during shutdown"
                )),
            }
        } else {
            Err(anyhow::anyhow!(
                "serial execution closeout is not applicable to this legacy route"
            ))
        };
        // Actor cancellation was published immediately after route revocation.
        // Now close every control-plane hardware mutation and wait for admitted
        // calls to finish. A timeout remains negative evidence: teardown still
        // cuts power, but watchdog Disarm is then unreachable.
        let exact_api_closeout_result = match exact_revoked_api {
            Some(api) => Some(
                api.complete(
                    remaining_exact_serial_cleanup(
                        exact_teardown_view.as_ref(),
                        RUNTIME_THREAD_STOP_TIMEOUT,
                    ),
                    "serial runtime API",
                )
                .await,
            ),
            None => {
                // Legacy routes are outside the exact watchdog composition.
                // Their actor cancellation is already published; close and
                // drain the public mutation gate before best-effort safe-off.
                let mutation_gate_for_drain = hardware_mutation_gate.clone();
                let drain = match tokio::task::spawn_blocking(move || {
                    mutation_gate_for_drain.close_and_drain(RUNTIME_THREAD_STOP_TIMEOUT)
                })
                .await
                {
                    Ok(result) => result.map_err(anyhow::Error::from),
                    Err(join_error) => Err(anyhow::anyhow!(
                        "hardware mutation barrier worker failed: {join_error}"
                    )),
                };
                let final_commit = match legacy_revoked_api_commit_fence {
                    Some(fence) => {
                        let started = tokio::time::Instant::now();
                        wait_revoked_hardware_mutation_commit_fence(
                            fence,
                            started,
                            started + RUNTIME_THREAD_STOP_TIMEOUT,
                            "legacy serial runtime API",
                        )
                        .await
                    }
                    None => Err(anyhow::anyhow!(
                        "legacy serial API final-commit authority was unavailable"
                    )),
                };
                if let Err(error) = drain {
                    error!(%error, "Legacy serial API mutation drain failed");
                }
                if let Err(error) = final_commit {
                    error!(%error, "Legacy serial API final-commit fence failed");
                }
                None
            }
        };
        // Cancellation is already published. Clear queued work before joining
        // the serial actor so no retained frame can outlive terminal closeout.
        work_queue
            .lock()
            .unwrap_or_else(|poisoned| {
                warn!("work queue mutex poisoned during shutdown; recovering for terminal clear");
                poisoned.into_inner()
            })
            .clear();
        let actor_closeout_admission = serial_execution_closeout_result
            .as_mut()
            .ok()
            .and_then(|closeout| closeout.take_actor_closeout_admission().ok());
        let am2_reset_closeout_result = if is_bm1362 {
            Some(
                serial_execution_closeout_result
                    .as_mut()
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "serial closeout unavailable for AM2 reset evidence: {error:#}"
                        )
                    })
                    .and_then(SerialExecutionDomainCloseout::take_am2_reset_closeout),
            )
        } else {
            None
        };
        let thread_stop = runtime_threads
            .stop_and_join(
                remaining_exact_serial_cleanup(
                    exact_teardown_view.as_ref(),
                    RUNTIME_THREAD_STOP_TIMEOUT,
                ),
                actor_closeout_admission,
            )
            .await;
        let panicked_worker_names = thread_stop.panicked_worker_names();
        let am2_safe_off_result = if thread_stop.any_timed_out() {
            warn!(
                timeout_ms = RUNTIME_THREAD_STOP_TIMEOUT.as_millis(),
                "one or more serial runtime threads were detached at the shutdown deadline; using out-of-band hard stop"
            );
            let hard_stop_result = run_terminal_owner_operation_blocking(
                &mut am2_power,
                Am2PsuRuntimeGuard::new(),
                "serial runtime out-of-band hard stop",
                |guard| {
                    guard.hard_stop_out_of_band("runtime-thread-timeout");
                    Ok(())
                },
            )
            .await;
            if is_bm1362 {
                Some(Err(anyhow::anyhow!(
                    "AM2 BM1362 runtime actor timeout prevented checked terminal safe-off evidence{}",
                    hard_stop_result
                        .err()
                        .map(|error| format!("; hard-stop worker failed: {error:#}"))
                        .unwrap_or_default()
                )))
            } else {
                if let Err(error) = hard_stop_result {
                    terminal_safety_error = Some(match terminal_safety_error.take() {
                        Some(primary) => anyhow::anyhow!(
                            "{primary:#}; serial runtime hard-stop worker also failed: {error:#}"
                        ),
                        None => error,
                    });
                }
                None
            }
        } else if is_bm1362 {
            let safe_off_budget = exact_teardown_view.clone();
            Some(
                run_terminal_owner_operation_blocking(
                    &mut am2_power,
                    Am2PsuRuntimeGuard::new(),
                    "AM2 BM1362 checked shutdown safe-off",
                    move |guard| guard.teardown_checked_retrying("shutdown", true, safe_off_budget),
                )
                .await
                .context("AM2 BM1362 checked shutdown safe-off failed"),
            )
        } else {
            if let Err(error) = run_terminal_owner_operation_blocking(
                &mut am2_power,
                Am2PsuRuntimeGuard::new(),
                "serial AM2 best-effort shutdown",
                |guard| {
                    guard.teardown("shutdown");
                    Ok(())
                },
            )
            .await
            {
                terminal_safety_error = Some(match terminal_safety_error.take() {
                    Some(primary) => anyhow::anyhow!(
                        "{primary:#}; serial AM2 shutdown worker also failed: {error:#}"
                    ),
                    None => error,
                });
            }
            None
        };

        if let Some(watchdog_owner) = nopic_watchdog.take() {
            let nopic_closeout_result: Result<WatchdogCloseoutReceipt> = async {
                // Cut hash power before acoustic coast-down. A fan readback failure
                // is degraded shutdown evidence, but must not force a reboot that
                // could re-energize a GPIO already proven low.
                // Early thermal/fan failure paths may already have proven an
                // urgent GPIO cutoff. That evidence is intentionally not
                // terminal: repeat checked safe-off only after route mutation
                // domains and runtime actors have reached their closeout fence.
                let safe_off_budget = exact_teardown_view.clone();
                let management_fabric_deadline = Instant::now()
                    + remaining_exact_serial_cleanup(
                        exact_teardown_view.as_ref(),
                        RUNTIME_THREAD_STOP_TIMEOUT,
                    );
                let power_receipt = run_terminal_owner_operation_blocking(
                    &mut nopic_psu_guard,
                    NoPicPsuGuard::new(),
                    "NoPic checked operator-stop safe-off",
                    move |guard| {
                        guard.safe_off(safe_off_budget, management_fabric_deadline)
                    },
                )
                .await?;
                if let Some(fan) = amlogic_fan.as_ref() {
                    let fan = Arc::clone(fan);
                    match tokio::task::spawn_blocking(move || {
                        fan.set_speed_checked(dcentrald_hal::fan::PWM_SAFETY_MAX)
                    })
                    .await
                    {
                        Ok(Ok(receipt)) => info!(
                            requested_pwm = receipt.requested_pwm(),
                            observed_pwm = receipt.observed_pwm(),
                            "NoPic quiet fan coast-down completed on both PWM channels"
                        ),
                        Ok(Err(error)) => warn!(
                            %error,
                            "NoPic power is checked low, but quiet fan coast-down readback failed"
                        ),
                        Err(error) => warn!(
                            %error,
                            "NoPic quiet fan coast-down worker failed after checked power-off"
                        ),
                    }
                }
                watchdog_teardown_result?;
                let serial_execution_closeout = serial_execution_closeout_result?;
                let api_mutation_closeout = exact_api_closeout_result
                    .context("NoPic API closeout result was not produced")??;
                let actor_receipt = thread_stop.into_nopic_receipt()?;
                let power_gpio = power_receipt.power().gpio();
                let teardown_receipt = exact_cutoff_timing_result
                    .take()
                    .context("NoPic exact cutoff timing result was not produced")??
                    .complete(Instant::now())?;
                let teardown_disarm = exact_teardown_budget
                    .take()
                    .context("NoPic teardown budget was not retained through closeout")?
                    .begin_disarm_at(Instant::now())?;
                let manifest = NoPicWatchdogShutdownManifest::new(
                    serial_execution_closeout,
                    api_mutation_closeout,
                    actor_receipt,
                    power_receipt,
                    teardown_receipt,
                    teardown_disarm,
                );
                let permit = WatchdogDisarmPermit::from_nopic_manifest(manifest)?;
                let closeout = watchdog_owner
                    .disarm_and_join(permit, DEFAULT_WATCHDOG_STOP_TIMEOUT)
                    .await?;
                info!(
                    gpio = power_gpio,
                    "NoPic watchdog close and worker exit observed after actor quiescence and checked GPIO-low safe-off"
                );
                Ok(closeout)
            }
            .await;
            record_terminal_closeout_result(
                &mut terminal_safety_error,
                &mut terminal_watchdog_closeout,
                "NoPic",
                nopic_closeout_result,
            );
        } else if let Some(watchdog_owner) = am2_watchdog.take() {
            let am2_closeout_result: Result<WatchdogCloseoutReceipt> = async {
                watchdog_teardown_result?;
                let serial_execution_closeout = serial_execution_closeout_result?;
                let api_mutation_closeout = exact_api_closeout_result
                    .context("AM2 BM1362 API closeout result was not produced")??;
                let reset_closeout = am2_reset_closeout_result
                    .context("AM2 BM1362 reset closeout result was not produced")??;
                let actor_receipt = thread_stop.into_am2_receipt()?;
                let safe_off =
                    am2_safe_off_result.context("AM2 BM1362 safe-off result was not produced")??;
                let safe_off_gpio = safe_off.gate().gpio();
                let disabled_dspics = safe_off.disabled_dspic_count();
                let dspic_never_armed = safe_off.dspic_was_never_armed();
                let teardown_receipt = exact_cutoff_timing_result
                    .take()
                    .context("AM2 exact cutoff timing result was not produced")??
                    .complete(Instant::now())?;
                let teardown_disarm = exact_teardown_budget
                    .take()
                    .context("AM2 teardown budget was not retained through closeout")?
                    .begin_disarm_at(Instant::now())?;
                let manifest = Am2SerialWatchdogShutdownManifest::new(
                    serial_execution_closeout,
                    api_mutation_closeout,
                    reset_closeout,
                    actor_receipt,
                    safe_off,
                    teardown_receipt,
                    teardown_disarm,
                );
                let permit = WatchdogDisarmPermit::from_am2_serial_manifest(manifest)?;
                let closeout = watchdog_owner
                    .disarm_and_join(permit, DEFAULT_WATCHDOG_STOP_TIMEOUT)
                    .await?;
                info!(
                    gpio = safe_off_gpio,
                    disabled_dspics,
                    dspic_never_armed,
                    "AM2 BM1362 watchdog close and worker exit observed after checked terminal safe-off"
                );
                Ok(closeout)
            }
            .await;
            record_terminal_closeout_result(
                &mut terminal_safety_error,
                &mut terminal_watchdog_closeout,
                "AM2 BM1362",
                am2_closeout_result,
            );
        } else if serial_actor_topology.is_exact() {
            record_terminal_closeout_result(
                &mut terminal_safety_error,
                &mut terminal_watchdog_closeout,
                "exact serial watchdog",
                Err(anyhow::anyhow!(
                    "exact serial route reached terminal shutdown without retained watchdog ownership"
                )),
            );
        }
        // A joined panic proves physical quiescence, so checked safe-off still
        // runs. The fixed roster withholds clean Disarm authority because a
        // panic cannot prove the actor-owned child graph completed normally.
        record_joined_actor_panic(&mut terminal_safety_error, &panicked_worker_names);
        if let Err(e) = history_buffer.save(&history_path) {
            warn!(error = %e, path = %history_path.display(), "Failed to persist history to disk");
        }
        classify_serial_terminal_result(
            serial_actor_topology,
            terminal_safety_error,
            terminal_watchdog_closeout,
        )
    }
}

fn reverse_32bit_words(data: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..(i + 1) * 4].copy_from_slice(&data[(7 - i) * 4..(7 - i + 1) * 4]);
    }
    out
}

#[derive(Clone)]
struct WorkEntry {
    generation: u64,
    work_generation: dcentrald_stratum::WorkGeneration,
    job_id: String,
    extranonce2: String,
    ntime: u32,
    nbits: u32,
    version: u32,
    version_mask: u32,
    share_target: [u8; 32],
    prev_block_hash: [u8; 32],
    merkle_root: [u8; 32],
}

fn serial_rolled_version(
    entry: &WorkEntry,
    version_bits_raw: u16,
    is_bm1398: bool,
    midstate_idx: u8,
) -> Option<u32> {
    if is_bm1398 {
        if midstate_idx >= 4 {
            return None;
        }
        if entry.version_mask == 0 {
            return Some(entry.version);
        }

        let mut rolled_version = entry.version;
        for _ in 0..midstate_idx {
            rolled_version =
                dcentrald_stratum::work::increment_bitmask_pub(rolled_version, entry.version_mask);
        }
        return Some(rolled_version);
    }

    // BIP320 reconstruction is unconditional for BM1362-family chips â€”
    // they roll the BIP320 16-bit field regardless of whether the pool
    // negotiated `mining.configure`. The .135 Amlogic S21 pre-fix run
    // (2026-04-11, 0.023% accept rate) was THIS branch silently dropping
    // ~99.9% of valid hashing work whenever the pool didn't negotiate the
    // mask. The 2026-05-15 .109 XIL milestone confirmed the chip-side
    // behavior. See:
    //
    //
    //   -  F1.
    let (rolled_version, vbits_delta) =
        dcentrald_asic::bm1362::bip320_reconstruct_rolled_version(entry.version, version_bits_raw);

    if entry.version_mask == 0 {
        // Pool didn't negotiate version-rolling. The chip rolled anyway â€”
        // submit the rolled-version share. validate_full_header upstream is
        // the SOLE gate; pools that understand BIP320 will accept (Public
        // Pool does), pools that don't will reject post-submit.
        return Some(rolled_version);
    }

    if vbits_delta & !entry.version_mask != 0 {
        // Chip rolled bits OUTSIDE the pool's negotiated mask â€” the share
        // would be rejected post-submit. Drop it locally to avoid spamming
        // the pool with unsanctioned rolls.
        return None;
    }

    Some(rolled_version)
}

/// G22: thin-wrap stratum pure SSOT (engines keep distinct WorkEntry types).
fn serial_build_header(entry: &WorkEntry, rolled_version: u32, nonce: u32) -> [u8; 80] {
    dcentrald_stratum::v1::job::build_block_header(
        rolled_version,
        &entry.prev_block_hash,
        &entry.merkle_root,
        entry.ntime,
        entry.nbits,
        nonce,
    )
}

fn serial_full_header_hash_be(header: &[u8; 80]) -> [u8; 32] {
    let hash = dcentrald_stratum::work::double_sha256(header);
    let mut hash_be = [0u8; 32];
    for i in 0..32 {
        hash_be[i] = hash[31 - i];
    }
    hash_be
}

fn serial_achieved_difficulty_from_header(header: &[u8; 80]) -> Option<f64> {
    let hash_be = serial_full_header_hash_be(header);
    let difficulty = dcentrald_stratum::v1::difficulty::hash_to_difficulty(&hash_be);
    if difficulty.is_finite() && difficulty > 0.0 {
        Some(difficulty)
    } else {
        None
    }
}

fn serial_next_asic_job_id(asic_job_id: u8, job_id_increment: u8) -> u8 {
    asic_job_id.wrapping_add(job_id_increment) & JOB_ID_MASK
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The address ladder must be unchanged on every population we actually
    /// ship, and must stop truncating to zero on the one that we do not.
    ///
    /// The shipped geometries all divide into the 8-bit space with an interval
    /// of at least 1, so routing them through the shared `LinearAddressPlan`
    /// changes no byte on any wire. The single behavioural change is at one
    /// chip, where `256` is not representable in a `u8` and the old inline
    /// `(256 / n) as u8` produced `0` â€” which would have assigned address 0 to
    /// every chip and then validated the geometry against the same zero stride.
    #[test]
    fn serial_address_ladder_is_unchanged_for_shipped_populations_and_safe_at_one_chip() {
        // (chip_count, expected interval) â€” the populations in the model catalog.
        for (chips, expected) in [
            (63_u8, 4_u8), // S9      BM1387  3x63
            (48, 5),       // S17     BM1397  3x48
            (30, 8),       // T17     BM1397  3x30
            (114, 2),      // S19 Pro BM1398  3x114
            (126, 2),      // S19j Pro BM1362 3x126
            (110, 2),      // S19 XP  BM1366  3x110
            (77, 3),       // S19k Pro BM1366 3x77
            (108, 2),      // S21     BM1368  3x108
            (65, 3),       // S21 Pro BM1370  3x65
        ] {
            let actual = SerialMiner::serial_address_interval(chips)
                .expect("shipped population must produce a valid ladder");
            assert_eq!(
                actual, expected,
                "address interval drifted for a shipped {chips}-chip population"
            );
            // What the inline expression used to compute, byte for byte.
            assert_eq!(
                actual,
                (256u16 / u16::from(chips)) as u8,
                "shipped populations must be wire-identical to the previous inline form"
            );

            // The last address must stay inside the byte space, which is what
            // makes the shared constructor accept every one of these.
            let last = u16::from(chips - 1) * u16::from(actual);
            assert!(
                last < 256,
                "{chips} chips would address past the byte space"
            );
        }

        // The case the old form got wrong: 256 truncates to 0 in a u8.
        assert_eq!(
            (256u16 / 1u16) as u8,
            0,
            "sanity: the old inline form really did truncate to zero at one chip"
        );
        assert_eq!(
            SerialMiner::serial_address_interval(1).expect("one chip is a valid fixture"),
            1,
            "a one-chip fixture must get a non-zero stride"
        );

        // `.max(1)` still absorbs a zero count rather than erroring.
        assert_eq!(
            SerialMiner::serial_address_interval(0).expect("zero is clamped, not rejected"),
            1
        );
    }

    /// The BM1368 helper keeps its jig-attested 108 pin, and that pin must not
    /// silently disagree with the general ladder â€” if it ever does, one of the
    /// two is wrong and the difference would only show up on hardware.
    #[test]
    fn bm1368_fixture_interval_agrees_with_the_general_ladder() {
        assert_eq!(
            SerialMiner::bm1368_addr_interval(108).expect("S21 population"),
            SerialMiner::serial_address_interval(108).expect("general ladder"),
            "the BM1368 fixture pin and the general ladder disagree at 108 chips"
        );
        assert_eq!(
            SerialMiner::bm1368_addr_interval(1).expect("one-chip fixture"),
            1,
            "the BM1368 helper must not truncate to zero at one chip either"
        );
    }

    struct FakeSerialActorBackend {
        reads: Mutex<VecDeque<Result<Option<Vec<u8>>>>>,
        read_count: AtomicU64,
        fail_send: bool,
        cancel_after_reads: Option<u64>,
        cancel_after_send: bool,
        shutdown: CancellationToken,
    }

    impl FakeSerialActorBackend {
        fn new(reads: Vec<Result<Option<Vec<u8>>>>, shutdown: CancellationToken) -> Self {
            Self {
                reads: Mutex::new(reads.into()),
                read_count: AtomicU64::new(0),
                fail_send: false,
                cancel_after_reads: None,
                cancel_after_send: false,
                shutdown,
            }
        }
    }

    impl SerialActorBackend for FakeSerialActorBackend {
        fn actor_send_work(&self, _frame: &[u8]) -> Result<()> {
            if self.fail_send {
                anyhow::bail!("injected serial TX failure");
            }
            if self.cancel_after_send {
                self.shutdown.cancel();
            }
            Ok(())
        }

        fn actor_read_nonce_response(&self) -> Result<Option<Vec<u8>>> {
            let read_count = self.read_count.fetch_add(1, Ordering::AcqRel) + 1;
            let result = self.reads.lock().unwrap().pop_front().unwrap_or(Ok(None));
            if self
                .cancel_after_reads
                .is_some_and(|limit| read_count >= limit)
            {
                self.shutdown.cancel();
            }
            result
        }
    }

    fn serial_route_admission(
        board_target: &'static str,
        identity: dcentrald_common::AsicProtocolIdentity,
    ) -> crate::SerialRuntimeDispatchAdmission {
        crate::admit_board_desc_runtime_dispatch(
            dcentrald_common::BoardDesc::lookup(board_target),
            crate::RuntimeDispatchKind::Serial,
            true,
            Some(identity),
        )
        .unwrap()
        .require_serial_asic_protocol(identity)
        .unwrap()
    }

    fn chip_address_body(chip_id: u16, address: u8) -> [u8; BM13XX_CMD_RESP_BODY_LEN] {
        let [high, low] = chip_id.to_be_bytes();
        let mut body = [high, low, 0, address, address, 0, 0, 0, 0];
        body[8] = dcentrald_asic::protocol::bm13xx_command_response_crc5(&body[..8]);
        body
    }

    fn serial_window(chip_id: u16, addresses: &[u8]) -> ValidatedSerialChipAddressWindow {
        let bodies = addresses
            .iter()
            .copied()
            .map(|address| chip_address_body(chip_id, address))
            .collect::<Vec<_>>();
        validate_serial_chip_address_window(bodies.iter().map(|body| &body[..])).unwrap()
    }

    #[test]
    fn validated_serial_admission_binds_exact_route_family_and_separate_geometry() {
        let admission = ValidatedSerialChainAdmission::bind_route(
            serial_route_admission("am3-s21", dcentrald_common::AsicProtocolIdentity::Bm1368),
            1,
            "/dev/ttyS2",
            3_000_000,
            108,
            serial_window(0x1368, &[0, 0, 0]),
        )
        .unwrap();

        assert_eq!(admission.board_target, "am3-s21");
        assert_eq!(
            admission.identity,
            dcentrald_common::AsicProtocolIdentity::Bm1368
        );
        assert_eq!(admission.active_slot, 1);
        assert_eq!(admission.observed_frames.get(), 3);
        assert_eq!(admission.configured_chip_count, 108);
        assert_eq!(
            admission.response_shape,
            SerialAddressWindowShape::RepeatedUnassignedZero
        );
    }

    #[test]
    fn validated_serial_admission_rejects_family_cross_use_and_impossible_frame_envelope() {
        let family_error = ValidatedSerialChainAdmission::bind_route(
            serial_route_admission("am3-s21", dcentrald_common::AsicProtocolIdentity::Bm1368),
            0,
            "/dev/ttyS1",
            115_200,
            108,
            serial_window(0x1370, &[0]),
        )
        .unwrap_err();
        assert!(family_error.to_string().contains("does not match"));

        let geometry_error = ValidatedSerialChainAdmission::bind_route(
            serial_route_admission("am3-s21pro", dcentrald_common::AsicProtocolIdentity::Bm1370),
            0,
            "/dev/ttyS1",
            1_000_000,
            2,
            serial_window(0x1370, &[0, 4, 8]),
        )
        .unwrap_err();
        assert!(geometry_error.to_string().contains("exceeding configured"));
    }

    #[test]
    fn assigned_serial_geometry_requires_exact_unique_configured_address_coverage() {
        let geometry = ValidatedSerialAssignedGeometry::from_window(
            serial_window(0x1368, &[0, 85, 170]),
            dcentrald_common::AsicProtocolIdentity::Bm1368,
            3,
            85,
        )
        .unwrap();
        assert_eq!(geometry.observed_chip_count(), 3);
        assert_eq!(
            geometry.identity,
            dcentrald_common::AsicProtocolIdentity::Bm1368
        );
        assert_eq!(geometry.addresses, vec![0, 85, 170]);

        for window in [
            serial_window(0x1368, &[0, 85]),
            serial_window(0x1368, &[0, 85, 85]),
            serial_window(0x1368, &[0, 84, 170]),
        ] {
            let error = ValidatedSerialAssignedGeometry::from_window(
                window,
                dcentrald_common::AsicProtocolIdentity::Bm1368,
                3,
                85,
            )
            .unwrap_err();
            assert!(error.to_string().contains("exact configured address plan"));
        }
    }

    #[test]
    fn serial_execution_terminal_rejects_late_physical_commit() {
        let admission = ValidatedSerialChainAdmission::bind_route(
            serial_route_admission("am3-s21", dcentrald_common::AsicProtocolIdentity::Bm1368),
            2,
            "/dev/ttyS3",
            115_200,
            108,
            serial_window(0x1368, &[0]),
        )
        .unwrap();
        let (port, terminal) =
            execution_fence_domain(SerialSessionToken::from_validated_for_test(&admission));
        let receipt = match terminal.revoke().try_wait_for_commit_fence() {
            ExecutionFenceTryWait::Fenced(receipt) => receipt,
            ExecutionFenceTryWait::Pending(_) => {
                panic!("idle serial execution fence remained busy")
            }
        };
        let executed = std::sync::atomic::AtomicBool::new(false);
        let error = port
            .commit(
                "late serial work",
                || -> std::result::Result<(), &'static str> {
                    executed.store(true, Ordering::SeqCst);
                    Ok(())
                },
            )
            .unwrap_err();

        assert_eq!(receipt.token().descriptor.serial_device, "/dev/ttyS3");
        assert!(!executed.load(Ordering::SeqCst));
        assert!(error.to_string().contains("is closed"));
    }

    #[tokio::test]
    async fn serial_execution_fence_rejects_panicked_commit_as_clean_shutdown_evidence() {
        let admission = ValidatedSerialChainAdmission::bind_route(
            serial_route_admission("am3-s21", dcentrald_common::AsicProtocolIdentity::Bm1368),
            2,
            "/dev/ttyS3",
            115_200,
            108,
            serial_window(0x1368, &[0]),
        )
        .unwrap();
        let (port, terminal) =
            execution_fence_domain(SerialSessionToken::from_validated_for_test(&admission));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = port.commit(
                "panicking serial commit",
                || -> std::result::Result<(), &'static str> {
                    panic!("fixture serial commit panic")
                },
            );
        }));
        assert!(panic.is_err());

        let error = wait_revoked_serial_execution_fence(
            terminal.revoke(),
            Duration::from_secs(1),
            "serial poison fixture",
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("clean watchdog disarm is forbidden"));
    }

    struct RecordingAm2FirstStageCut {
        observed: std::sync::mpsc::Sender<&'static str>,
    }

    impl Am2FirstStagePowerCut for RecordingAm2FirstStageCut {
        fn attempt_first_stage_power_cut(&mut self, reason: &'static str) -> Result<()> {
            self.observed.send(reason).unwrap();
            Ok(())
        }
    }

    struct FailingAm2FirstStageCut {
        observed: std::sync::mpsc::Sender<&'static str>,
    }

    impl Am2FirstStagePowerCut for FailingAm2FirstStageCut {
        fn attempt_first_stage_power_cut(&mut self, reason: &'static str) -> Result<()> {
            self.observed.send(reason).unwrap();
            anyhow::bail!("injected GPIO OFF readback failure")
        }
    }

    #[test]
    fn exact_am2_closeouts_revoke_serial_and_bound_watchdog_before_gpio_cut() {
        let source = include_str!("serial_mining.rs");
        let failure = source
            .split_once("async fn closeout_am2_bm1362_failure(")
            .expect("AM2 failure closeout")
            .1
            .split_once("fn failure_with_am2_closeout(")
            .expect("AM2 failure closeout boundary")
            .0;
        let failure_revoke = failure
            .find(".and_then(SerialRouteDomains::begin_closeout)")
            .expect("failure closeout route-domain revocation");
        let failure_request = failure
            .find(".request_teardown_budget()")
            .expect("failure closeout bounded watchdog request");
        let failure_cut = failure
            .find("\"AM2 BM1362 failure first-stage safe-off\"")
            .expect("failure closeout first-stage cutoff");
        let failure_observe = failure
            .find(".observe_teardown_admission(admission, view)")
            .expect("failure closeout watchdog acknowledgement wait");
        let failure_ack_gate = failure
            .find("teardown_result?;")
            .expect("failure closeout negative acknowledgement gate");
        let failure_manifest = failure
            .find("Am2SerialWatchdogShutdownManifest::new(")
            .expect("failure closeout typed watchdog manifest");
        assert!(
            failure_revoke < failure_request
                && failure_request < failure_cut
                && failure_cut < failure_observe
                && failure_observe < failure_ack_gate
                && failure_ack_gate < failure_manifest
        );

        let shutdown = source
            .split_once("let (mut exact_revoked_serial, exact_revoked_api)")
            .expect("AM2 operator closeout")
            .1
            .split_once("// Await the exact serial commit fence")
            .expect("AM2 operator closeout boundary")
            .0;
        let shutdown_revoke = shutdown
            .find("Some(domains) => match domains.begin_closeout()")
            .expect("operator closeout route-domain revocation");
        let am2_watchdog_branch = shutdown
            .find("} else if let Some(watchdog) = am2_watchdog.as_mut() {")
            .expect("operator closeout exact AM2 watchdog branch");
        let shutdown_request = shutdown[am2_watchdog_branch..]
            .find(".request_teardown_budget()")
            .map(|offset| am2_watchdog_branch + offset)
            .expect("operator closeout exact AM2 bounded watchdog request");
        let shutdown_cut = shutdown
            .find("\"AM2 BM1362 operator-stop first-stage safe-off\"")
            .expect("operator closeout first-stage cutoff");
        let shutdown_observe = shutdown
            .find(".observe_teardown_admission(admission, view)")
            .expect("operator closeout watchdog acknowledgement wait");
        assert!(
            shutdown_revoke < shutdown_request
                && shutdown_request < shutdown_cut
                && shutdown_cut < shutdown_observe
        );

        let serial_wait = source
            .split_once("impl RevokedSerialExecutionDomain {")
            .expect("revoked exact serial lifecycle")
            .1
            .split_once("impl RevokedApiMutationDomain {")
            .expect("revoked exact serial lifecycle boundary")
            .0;
        assert!(serial_wait.contains("wait_revoked_serial_execution_fence("));
        assert!(!serial_wait.contains("spawn_blocking"));
        assert!(!serial_wait.contains(".wait_for_commit_fence()"));

        let serial_closeout = source
            .split_once("async fn wait_am2_serial_domain_after_revocation(")
            .expect("AM2 serial-domain closeout")
            .1
            .split_once("async fn closeout_native_nopic_failure(")
            .expect("AM2 serial-domain closeout boundary")
            .0;
        assert!(serial_closeout.contains(".complete(timeout, \"AM2 BM1362\")"));
        assert!(!serial_closeout.contains("spawn_blocking"));
        assert!(!serial_closeout.contains(".wait_for_commit_fence()"));
    }

    #[test]
    fn nopic_and_legacy_shutdown_revoke_before_watchdog_and_cut_before_uart_wait() {
        let source = include_str!("serial_mining.rs");
        let production_end = source
            .find("\n#[cfg(test)]\nmod tests {")
            .expect("production/test module boundary");
        let production = &source[..production_end];

        let nopic = production
            .split_once("async fn closeout_native_nopic_failure(")
            .expect("NoPic failure closeout")
            .1
            .split_once("fn failure_with_closeout(")
            .expect("NoPic failure closeout boundary")
            .0;
        let nopic_route_revoke = nopic
            .find(".and_then(SerialRouteDomains::begin_closeout)")
            .unwrap();
        let nopic_watchdog_request = nopic.find(".request_teardown_budget()").unwrap();
        let nopic_first_cut = nopic
            .find("\"NoPic failure first-stage safe-off\"")
            .unwrap();
        let nopic_watchdog_observe = nopic
            .find(".observe_teardown_admission(admission, view)")
            .unwrap();
        let nopic_serial_wait = nopic.find("let serial_timeout =").unwrap();
        let nopic_api_wait = nopic.find("let api_timeout =").unwrap();
        let nopic_actor_stop = nopic.find("let thread_stop = runtime_threads").unwrap();
        let nopic_final_cut = nopic.find("\"NoPic failure checked safe-off\"").unwrap();
        let nopic_ack_gate = nopic.find("teardown_result?;").unwrap();
        let nopic_manifest = nopic.find("NoPicWatchdogShutdownManifest::new(").unwrap();
        assert!(
            nopic_route_revoke < nopic_watchdog_request
                && nopic_watchdog_request < nopic_first_cut
                && nopic_first_cut < nopic_watchdog_observe
                && nopic_watchdog_observe < nopic_serial_wait
                && nopic_serial_wait < nopic_api_wait
                && nopic_api_wait < nopic_actor_stop
                && nopic_actor_stop < nopic_final_cut
                && nopic_final_cut < nopic_ack_gate
                && nopic_ack_gate < nopic_manifest
        );

        let run = production
            .split_once("pub async fn run(&mut self)")
            .expect("serial run body")
            .1;
        let shutdown = run
            .split_once("let (mut exact_revoked_serial, exact_revoked_api)")
            .expect("serial shutdown revocation boundary")
            .1;
        let exact_route_revoke = shutdown
            .find("Some(domains) => match domains.begin_closeout()")
            .unwrap();
        let legacy_api_revoke = shutdown
            .find("hardware_mutation_gate.revoke_commit_fence()")
            .unwrap();
        let shutdown_marker = shutdown.find("info!(\"=== SHUTDOWN ===\");").unwrap();
        let watchdog_request = shutdown[shutdown_marker..]
            .find(".request_teardown_budget()")
            .map(|offset| shutdown_marker + offset)
            .unwrap();
        let first_cut = shutdown
            .find("\"NoPic operator-stop first-stage safe-off\"")
            .unwrap();
        let watchdog_observe = shutdown
            .find(".observe_teardown_admission(admission, view)")
            .unwrap();
        let serial_wait = shutdown
            .find("validated NoPic serial runtime shutdown")
            .unwrap();
        let api_wait = shutdown.find("\"serial runtime API\"").unwrap();
        let actor_stop = shutdown.find("let thread_stop = runtime_threads").unwrap();
        let final_cut = shutdown
            .find("\"NoPic checked operator-stop safe-off\"")
            .unwrap();
        let shutdown_ack_gate = shutdown.find("watchdog_teardown_result?;").unwrap();
        let shutdown_manifest = shutdown
            .find("NoPicWatchdogShutdownManifest::new(")
            .unwrap();
        assert!(
            exact_route_revoke < shutdown_marker
                && legacy_api_revoke < shutdown_marker
                && shutdown_marker < watchdog_request
                && watchdog_request < first_cut
                && first_cut < watchdog_observe
                && watchdog_observe < serial_wait
                && serial_wait < api_wait
                && api_wait < actor_stop
                && actor_stop < final_cut
                && final_cut < shutdown_ack_gate
                && shutdown_ack_gate < shutdown_manifest
        );

        assert!(!production.contains("spawn_blocking(move || commit_gate"));
        assert!(!production.contains("mutation_gate_for_commit.close_and_wait"));
        assert!(!production.contains("close_and_wait_for_commit_fence()"));
        let api_closeout = production
            .split_once("impl RevokedApiMutationDomain {")
            .expect("revoked API domain implementation")
            .1
            .split_once("impl SerialExecutionDomainCloseout {")
            .expect("revoked API closeout boundary")
            .0;
        assert!(api_closeout.contains("let closeout_deadline = closeout_started_at"));
        assert!(api_closeout.contains("receipt.closed_and_drained_at() < closeout_deadline"));
        assert!(api_closeout.contains("tokio::time::Instant::from_std(closeout_deadline)"));
        assert!(!api_closeout.contains("started + timeout"));
    }

    #[test]
    fn nopic_emergency_cut_cannot_be_reused_as_terminal_safeoff_evidence() {
        let source = include_str!("serial_mining.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production source");

        assert!(production
            .contains("fn first_stage_safe_off(&self) -> Result<NoPicEmergencyCutReceipt>"));
        assert!(production.contains("fn safe_off("));
        assert!(production.contains("teardown_budget: Option<TeardownBudgetView>"));
        assert!(
            production.contains("management_fabric: dcentrald_hal::i2c::I2cServiceCloseReceipt")
        );
        assert!(production
            .contains("let mut early_safe_off_receipt: Option<NoPicEmergencyCutReceipt> = None;"));

        let failure = production
            .split_once("async fn closeout_native_nopic_failure(")
            .expect("NoPic failure closeout")
            .1
            .split_once("fn failure_with_closeout(")
            .expect("NoPic failure closeout boundary")
            .0;
        assert!(failure.contains("prior_emergency_cut: Option<NoPicEmergencyCutReceipt>"));
        assert!(
            failure.contains("let power_receipt_result = run_terminal_owner_operation_blocking(")
        );
        assert!(!failure.contains("Some(receipt) => Ok(receipt)"));

        let shutdown = production
            .split_once("info!(\"=== SHUTDOWN ===\");")
            .expect("NoPic terminal closeout")
            .1;
        let discard_early = shutdown
            .find("let _prior_emergency_cut = early_safe_off_receipt.take();")
            .expect("pre-fence emergency evidence must be discarded");
        let repeat_first_stage = shutdown
            .find("\"NoPic operator-stop first-stage safe-off\"")
            .expect("post-budget first-stage safe-off must be repeated");
        let repeat_checked = shutdown
            .find("\"NoPic checked operator-stop safe-off\"")
            .expect("post-fence checked safe-off must be repeated");
        let manifest = shutdown
            .find("NoPicWatchdogShutdownManifest::new")
            .expect("NoPic watchdog manifest");
        assert!(
            discard_early < repeat_first_stage
                && repeat_first_stage < repeat_checked
                && repeat_checked < manifest
        );
        assert!(!shutdown.contains("Some(receipt) => receipt"));

        let final_safe_off = production
            .split_once("fn safe_off(")
            .expect("NoPic final safe-off")
            .1
            .split_once("impl Drop for NoPicPsuGuard")
            .expect("NoPic final safe-off boundary")
            .0;
        let worker_join = final_safe_off
            .find(".close_and_join_until(management_fabric_deadline)")
            .expect("NoPic management-fabric join");
        let final_gpio = final_safe_off
            .find(".latch_terminal_and_disable_psu_checked()")
            .expect("NoPic final owner-mediated checked GPIO-low observation");
        assert!(worker_join < final_gpio);

        let drop_safe_off = production
            .split_once("impl Drop for NoPicPsuGuard")
            .expect("NoPic drop safe-off")
            .1
            .split_once("fn checked_nopic_emergency_safe_off")
            .expect("NoPic drop safe-off boundary")
            .0;
        let urgent_gpio = drop_safe_off
            .find(".latch_terminal_and_disable_psu_checked()")
            .expect("NoPic drop urgent owner-mediated GPIO cut");
        let bounded_join = drop_safe_off
            .find("owner.close_and_join_until(")
            .expect("NoPic drop bounded bus join");
        assert!(urgent_gpio < bounded_join);
    }

    #[test]
    fn serial_terminal_physical_io_uses_blocking_workers() {
        let source = include_str!("serial_mining.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production source");
        let owner_worker = production
            .split("async fn run_terminal_owner_operation_blocking")
            .nth(1)
            .expect("terminal owner blocking helper")
            .split("async fn checked_nopic_emergency_safe_off_blocking")
            .next()
            .expect("bounded terminal owner helper");
        assert!(owner_worker.contains("tokio::task::spawn_blocking(move ||"));
        assert!(owner_worker.contains("(retained_owner, result)"));
        assert!(owner_worker.contains("*owner = returned_owner"));
        assert!(production.contains("async fn run_timed_terminal_owner_operation_blocking"));
        assert_eq!(
            production
                .match_indices("run_timed_terminal_owner_operation_blocking(")
                .count(),
            4,
            "every exact first-stage cutoff must timestamp actual blocking-worker execution"
        );
        assert!(production.contains("ExactSerialTeardownProgress::after_nopic_checked_cut("));
        assert!(production.contains("ExactSerialTeardownProgress::after_am2_checked_cut("));
        assert!(!production.contains("ExactSerialTeardownProgress::after_checked_cut("));

        for operation in [
            "NoPic failure first-stage safe-off",
            "NoPic failure checked safe-off",
            "AM2 BM1362 failure first-stage safe-off",
            "AM2 BM1362 checked terminal safe-off",
            "NoPic operator-stop first-stage safe-off",
            "AM2 BM1362 operator-stop first-stage safe-off",
            "AM2 BM1362 checked shutdown safe-off",
            "NoPic checked operator-stop safe-off",
        ] {
            assert!(
                production.contains(operation),
                "terminal blocking-owner contract missing {operation}"
            );
        }
        assert!(production.contains("set_fan_speed_checked_blocking("));
        assert!(production.contains("NoPic quiet fan coast-down worker failed"));
    }

    #[test]
    fn serial_guard_destructors_transfer_terminal_io_to_the_blocking_owner() {
        let source = include_str!("serial_mining.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production source");

        let nopic_drop = production
            .split("impl Drop for NoPicPsuGuard")
            .nth(1)
            .expect("NoPic guard drop")
            .split("fn checked_nopic_emergency_safe_off")
            .next()
            .expect("bounded NoPic drop body");
        let nopic_dispatch = nopic_drop
            .find("crate::terminal_io_owner::dispatch(")
            .expect("NoPic drop must transfer cleanup");
        assert!(
            nopic_dispatch
                < nopic_drop
                    .find(".latch_terminal_and_disable_psu_checked()")
                    .expect("NoPic queued cleanup must use the terminal GPIO owner")
        );
        assert!(
            nopic_dispatch
                < nopic_drop
                    .find("std::fs::write(")
                    .expect("NoPic queued cleanup must quiet fans")
        );

        let am2_drop = production
            .split("impl Drop for Am2PsuRuntimeGuard")
            .nth(1)
            .expect("AM2 serial guard drop")
            .split("impl Am2FirstStagePowerCut")
            .next()
            .expect("bounded AM2 serial drop body");
        let am2_dispatch = am2_drop
            .find("crate::terminal_io_owner::dispatch(")
            .expect("AM2 serial drop must transfer cleanup");
        assert!(
            am2_dispatch
                < am2_drop
                    .find("Self::execute_manually_retained_hard_stop(&mut owned, \"drop\")")
                    .expect("AM2 serial queued cleanup must execute hard stop")
        );
        let retained_before_dispatch = am2_drop
            .find("std::mem::ManuallyDrop::new(std::mem::replace(self, Self::empty()))")
            .expect("AM2 live owner must be ManuallyDrop-retained before dispatch");
        assert!(retained_before_dispatch < am2_dispatch);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn am2_failure_and_operator_stop_verify_power_off_before_waiting_on_serial_commit_fence()
    {
        for reason in ["bm1362-failure-closeout", "bm1362-runtime-or-operator-stop"] {
            let admission = ValidatedSerialChainAdmission::bind_route(
                serial_route_admission("am3-s21", dcentrald_common::AsicProtocolIdentity::Bm1368),
                2,
                "/dev/ttyS3",
                115_200,
                108,
                serial_window(0x1368, &[0]),
            )
            .unwrap();
            let mut watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
            let mut domains =
                SerialRouteDomains::claim(&mut watchdog, ExactSerialRoute::Am2Bm1362).unwrap();
            let port = domains.open_serial_execution(admission).unwrap();
            let late_port = port.clone();
            let (commit_entered_tx, commit_entered_rx) = std::sync::mpsc::channel();
            let (release_commit_tx, release_commit_rx) = std::sync::mpsc::channel();
            let commit_thread = std::thread::spawn(move || {
                port.commit(
                    "held UART work commit",
                    || -> std::result::Result<(), &'static str> {
                        commit_entered_tx.send(()).unwrap();
                        release_commit_rx.recv().unwrap();
                        Ok(())
                    },
                )
                .unwrap();
            });
            commit_entered_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("UART commit entered before closeout");

            let (cut_tx, cut_rx) = std::sync::mpsc::channel();
            let (revoked_tx, revoked_rx) = std::sync::mpsc::channel();
            let (closeout_tx, closeout_rx) = std::sync::mpsc::channel();
            let closeout_task = tokio::spawn(async move {
                let mut power = RecordingAm2FirstStageCut { observed: cut_tx };
                let (revoked_state, _revoked_api) =
                    domains.begin_closeout().unwrap().split_for_closeout();
                revoked_tx.send(()).unwrap();
                let cut = attempt_am2_first_stage_cut(&mut power, reason);
                let revoked = record_am2_first_stage_cut_after_revocation(revoked_state, cut);
                let closeout =
                    wait_am2_serial_domain_after_revocation(revoked, RUNTIME_THREAD_STOP_TIMEOUT)
                        .await;
                closeout_tx
                    .send((
                        closeout.first_stage_cut.is_ok(),
                        closeout.serial_barrier.is_ok(),
                    ))
                    .unwrap();
            });

            revoked_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("serial admission revoked synchronously before GPIO cutoff");
            assert!(late_port
                .commit("late UART work", || -> Result<()> { Ok(()) })
                .is_err());
            assert_eq!(
                cut_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
                reason,
                "first-stage cut must follow synchronous serial revocation while the entered commit remains held"
            );
            assert!(
                matches!(
                    closeout_rx.try_recv(),
                    Err(std::sync::mpsc::TryRecvError::Empty)
                ),
                "serial fence unexpectedly completed before held UART commit returned"
            );

            release_commit_tx.send(()).unwrap();
            assert_eq!(
                closeout_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
                (true, true)
            );
            commit_thread.join().unwrap();
            closeout_task.await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn am2_persistent_cut_failure_revokes_serial_before_immediate_retries_and_fence_wait() {
        let admission = ValidatedSerialChainAdmission::bind_route(
            serial_route_admission("am3-s21", dcentrald_common::AsicProtocolIdentity::Bm1368),
            2,
            "/dev/ttyS3",
            115_200,
            108,
            serial_window(0x1368, &[0]),
        )
        .unwrap();
        let mut watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut domains =
            SerialRouteDomains::claim(&mut watchdog, ExactSerialRoute::Am2Bm1362).unwrap();
        let port = domains.open_serial_execution(admission).unwrap();
        let late_port = port.clone();
        let (commit_entered_tx, commit_entered_rx) = std::sync::mpsc::channel();
        let (release_commit_tx, release_commit_rx) = std::sync::mpsc::channel();
        let commit_thread = std::thread::spawn(move || {
            port.commit(
                "held UART work commit",
                || -> std::result::Result<(), &'static str> {
                    commit_entered_tx.send(()).unwrap();
                    release_commit_rx.recv().unwrap();
                    Ok(())
                },
            )
            .unwrap();
        });
        commit_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        let (cut_tx, cut_rx) = std::sync::mpsc::channel();
        let (revoked_tx, revoked_rx) = std::sync::mpsc::channel();
        let closeout_task = tokio::spawn(async move {
            let mut power = FailingAm2FirstStageCut { observed: cut_tx };
            let (revoked_state, _revoked_api) =
                domains.begin_closeout().unwrap().split_for_closeout();
            revoked_tx.send(()).unwrap();
            let cut = attempt_am2_first_stage_cut(&mut power, "persistent-cut-failure");
            let revoked = record_am2_first_stage_cut_after_revocation(revoked_state, cut);
            wait_am2_serial_domain_after_revocation(revoked, RUNTIME_THREAD_STOP_TIMEOUT).await
        });

        revoked_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("serial admission revoked before the first fallible GPIO cutoff attempt");
        assert!(late_port
            .commit("late UART work", || -> Result<()> { Ok(()) })
            .is_err());
        for _ in 0..AM2_BM1362_TERMINAL_SAFE_OFF_ATTEMPTS {
            assert_eq!(
                cut_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
                "persistent-cut-failure"
            );
        }
        assert!(matches!(
            cut_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert!(!closeout_task.is_finished());

        release_commit_tx.send(()).unwrap();
        let closeout = closeout_task.await.unwrap();
        assert!(closeout.first_stage_cut.is_err());
        assert!(closeout.serial_barrier.is_ok());
        commit_thread.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn am2_serial_fence_timeout_drops_revoked_owner_without_blocking_waiter() {
        let admission = ValidatedSerialChainAdmission::bind_route(
            serial_route_admission("am3-s21", dcentrald_common::AsicProtocolIdentity::Bm1368),
            2,
            "/dev/ttyS3",
            115_200,
            108,
            serial_window(0x1368, &[0]),
        )
        .unwrap();
        let (port, terminal) =
            execution_fence_domain(SerialSessionToken::from_validated_for_test(&admission));
        let observer = port.clone();
        let (commit_entered_tx, commit_entered_rx) = std::sync::mpsc::channel();
        let (release_commit_tx, release_commit_rx) = std::sync::mpsc::channel();
        let commit_thread = std::thread::spawn(move || {
            port.commit(
                "never-returning UART work commit fixture",
                || -> std::result::Result<(), &'static str> {
                    commit_entered_tx.send(()).unwrap();
                    release_commit_rx.recv().unwrap();
                    Ok(())
                },
            )
            .unwrap();
        });
        commit_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("UART commit entered before revocation");

        let revoked = terminal.revoke();
        assert_eq!(observer.owner_count_for_test(), 3);
        let error =
            match wait_revoked_am2_serial_execution_fence(revoked, Duration::from_millis(25)).await
            {
                Ok(_) => panic!("held UART commit unexpectedly produced a fence receipt"),
                Err(error) => error,
            };

        assert!(error
            .to_string()
            .contains("no timely quiescence evidence within 25 ms"));
        assert_eq!(
            observer.owner_count_for_test(),
            2,
            "timed-out polling must drop revoked authority instead of retaining it in a detached blocking worker"
        );
        assert!(observer
            .commit("late UART work", || -> Result<()> { Ok(()) })
            .is_err());

        release_commit_tx.send(()).unwrap();
        commit_thread.join().unwrap();
        assert_eq!(observer.owner_count_for_test(), 1);
    }

    #[test]
    fn am2_serial_fence_timeout_allows_runtime_drop_before_commit_release() {
        let admission = ValidatedSerialChainAdmission::bind_route(
            serial_route_admission("am3-s21", dcentrald_common::AsicProtocolIdentity::Bm1368),
            2,
            "/dev/ttyS3",
            115_200,
            108,
            serial_window(0x1368, &[0]),
        )
        .unwrap();
        let (port, terminal) =
            execution_fence_domain(SerialSessionToken::from_validated_for_test(&admission));
        let observer = port.clone();
        let (commit_entered_tx, commit_entered_rx) = std::sync::mpsc::channel();
        let (release_commit_tx, release_commit_rx) = std::sync::mpsc::channel();
        let commit_thread = std::thread::spawn(move || {
            port.commit(
                "runtime-drop UART work commit fixture",
                || -> std::result::Result<(), &'static str> {
                    commit_entered_tx.send(()).unwrap();
                    release_commit_rx.recv().unwrap();
                    Ok(())
                },
            )
            .unwrap();
        });
        commit_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("UART commit entered before revocation");
        let (release_after_runtime_tx, release_after_runtime_rx) = std::sync::mpsc::channel();
        let safety_releaser = std::thread::spawn(move || {
            let released_after_runtime_drop = release_after_runtime_rx
                .recv_timeout(Duration::from_secs(5))
                .is_ok();
            release_commit_tx.send(()).unwrap();
            released_after_runtime_drop
        });

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_time()
            .build()
            .unwrap();
        let result = runtime.block_on(wait_revoked_am2_serial_execution_fence(
            terminal.revoke(),
            Duration::from_millis(25),
        ));
        assert!(result.is_err());
        drop(runtime);
        assert_eq!(observer.owner_count_for_test(), 2);
        let _ = release_after_runtime_tx.send(());

        assert!(
            safety_releaser.join().unwrap(),
            "runtime drop waited for the still-held UART commit until the five-second safety fallback released it"
        );
        commit_thread.join().unwrap();
        assert_eq!(observer.owner_count_for_test(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn am2_serial_fence_never_probes_after_absolute_deadline() {
        let admission = ValidatedSerialChainAdmission::bind_route(
            serial_route_admission("am3-s21", dcentrald_common::AsicProtocolIdentity::Bm1368),
            2,
            "/dev/ttyS3",
            115_200,
            108,
            serial_window(0x1368, &[0]),
        )
        .unwrap();
        let (port, terminal) =
            execution_fence_domain(SerialSessionToken::from_validated_for_test(&admission));
        let (commit_entered_tx, commit_entered_rx) = std::sync::mpsc::channel();
        let (release_commit_tx, release_commit_rx) = std::sync::mpsc::channel();
        let (commit_returned_tx, commit_returned_rx) = std::sync::mpsc::channel();
        let commit_thread = std::thread::spawn(move || {
            port.commit(
                "post-deadline UART work commit fixture",
                || -> std::result::Result<(), &'static str> {
                    commit_entered_tx.send(()).unwrap();
                    release_commit_rx.recv().unwrap();
                    Ok(())
                },
            )
            .unwrap();
            commit_returned_tx.send(()).unwrap();
        });
        commit_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("UART commit entered before revocation");
        let mut release_commit_tx = Some(release_commit_tx);

        let result = wait_revoked_am2_serial_execution_fence_with_post_pending_probe(
            terminal.revoke(),
            Duration::from_millis(25),
            || {
                release_commit_tx
                    .take()
                    .expect("post-poll hook runs only once")
                    .send(())
                    .unwrap();
                commit_returned_rx
                    .recv_timeout(Duration::from_secs(1))
                    .expect("released UART commit returned before the deadline attribution check");
                std::thread::sleep(Duration::from_millis(30));
            },
        )
        .await;

        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("no timely quiescence evidence within 25 ms"));
        commit_thread.join().unwrap();
    }

    #[test]
    fn terminal_barrier_failure_consumes_no_safe_off_leg_before_retry() {
        struct Script {
            barrier_observations: Vec<bool>,
            barrier_receipt: bool,
            leg_receipts: [bool; 3],
            trace: Vec<&'static str>,
        }

        fn composite_attempt(script: &mut Script) -> Result<()> {
            attempt_after_terminal_barrier(
                script,
                |script| {
                    if script.barrier_receipt {
                        return Ok(());
                    }
                    script.trace.push("B");
                    if script.barrier_observations.remove(0) {
                        script.barrier_receipt = true;
                        Ok(())
                    } else {
                        anyhow::bail!("controller mutation remained in flight")
                    }
                },
                |script| {
                    for (index, leg) in ["D", "A", "G"].into_iter().enumerate() {
                        script.trace.push(leg);
                        script.leg_receipts[index] = true;
                    }
                    Ok(())
                },
            )
        }

        let mut script = Script {
            barrier_observations: vec![false, true],
            barrier_receipt: false,
            leg_receipts: [false; 3],
            trace: Vec::new(),
        };

        assert!(composite_attempt(&mut script).is_err());
        assert_eq!(script.trace, vec!["B"]);
        assert!(!script.barrier_receipt);
        assert_eq!(script.leg_receipts, [false; 3]);

        // Model the pre-authorized mutation completing after the negative
        // observation. No final receipt existed for it to invalidate.
        script.trace.push("E");
        composite_attempt(&mut script).unwrap();
        assert_eq!(script.trace, vec!["B", "E", "B", "D", "A", "G"]);
        assert!(script.barrier_receipt);
        assert_eq!(script.leg_receipts, [true; 3]);
    }

    #[test]
    fn joined_actor_panic_is_reported_after_safe_shutdown_without_hiding_primary_error() {
        let mut clean = None;
        record_joined_actor_panic(&mut clean, &[]);
        assert!(clean.is_none());

        record_joined_actor_panic(&mut clean, &["serial-hash-worker", "serial-thermal-worker"]);
        let rendered = clean.take().unwrap().to_string();
        assert!(rendered.contains("hardware runtime actors panicked"));
        assert!(rendered.contains("serial-hash-worker, serial-thermal-worker"));

        let mut primary = Some(anyhow::anyhow!("primary lifecycle failure"));
        record_joined_actor_panic(&mut primary, &["serial-share-worker"]);
        let rendered = primary.unwrap().to_string();
        assert!(rendered.contains("primary lifecycle failure"));
        assert!(rendered.contains("hardware runtime actors panicked"));
        assert!(rendered.contains("serial-share-worker"));

        let mut production_closeout = Some(anyhow::anyhow!("primary lifecycle failure"));
        let mut production_receipt = None;
        record_terminal_closeout_result(
            &mut production_closeout,
            &mut production_receipt,
            "NoPic",
            Err(anyhow::anyhow!("watchdog disarm evidence rejected")),
        );
        assert!(production_receipt.is_none());
        record_joined_actor_panic(&mut production_closeout, &["serial-reader"]);
        let rendered = production_closeout.unwrap().to_string();
        assert!(rendered.contains("primary lifecycle failure"));
        assert!(rendered.contains("NoPic terminal closeout also failed"));
        assert!(rendered.contains("watchdog disarm evidence rejected"));
        assert!(rendered.contains("hardware runtime actors panicked"));
        assert!(rendered.contains("serial-reader"));

        let source = include_str!("serial_mining.rs");
        let nopic_start = source
            .find("let nopic_closeout_result: Result<WatchdogCloseoutReceipt> = async")
            .expect("NoPic closeout containment boundary");
        let panic_merge = source[nopic_start..]
            .find("record_joined_actor_panic(&mut terminal_safety_error")
            .map(|offset| nopic_start + offset)
            .expect("joined-panic terminal merge");
        let nopic_closeout = &source[nopic_start..panic_merge];
        assert!(nopic_closeout.contains("record_terminal_closeout_result("));
        assert!(nopic_closeout.contains("nopic_closeout_result,"));
        let am2_start = nopic_closeout
            .find("let am2_closeout_result: Result<WatchdogCloseoutReceipt> = async")
            .expect("AM2 closeout containment boundary");
        let am2_closeout = &nopic_closeout[am2_start..];
        assert!(am2_closeout.contains("record_terminal_closeout_result("));
        assert!(am2_closeout.contains("am2_closeout_result,"));
        assert!(source[panic_merge..].contains("thread_stop.panicked_worker_names()"));
    }

    #[test]
    fn retained_single_owner_safe_off_legs_execute_all_pending_work_and_never_replay_success() {
        struct ScriptedOwner {
            name: &'static str,
            failures_remaining: usize,
            trace: Arc<Mutex<Vec<&'static str>>>,
            drops: Arc<AtomicU64>,
        }

        impl ScriptedOwner {
            fn attempt(&mut self) -> Result<&'static str> {
                self.trace.lock().unwrap().push(self.name);
                if self.failures_remaining > 0 {
                    self.failures_remaining -= 1;
                    anyhow::bail!("{} scripted safe-off failure", self.name);
                }
                Ok(self.name)
            }
        }

        impl Drop for ScriptedOwner {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn owner(
            name: &'static str,
            failures_remaining: usize,
            trace: &Arc<Mutex<Vec<&'static str>>>,
        ) -> (Option<ScriptedOwner>, Arc<AtomicU64>) {
            let drops = Arc::new(AtomicU64::new(0));
            (
                Some(ScriptedOwner {
                    name,
                    failures_remaining,
                    trace: Arc::clone(trace),
                    drops: Arc::clone(&drops),
                }),
                drops,
            )
        }

        fn composite_attempt(
            dspic: &mut Option<ScriptedOwner>,
            dspic_receipt: &mut Option<&'static str>,
            apw: &mut Option<ScriptedOwner>,
            apw_receipt: &mut Option<&'static str>,
            gate: &mut Option<ScriptedOwner>,
            gate_receipt: &mut Option<&'static str>,
        ) -> Result<()> {
            let mut errors = Vec::new();
            for (owner, receipt, missing) in [
                (dspic, dspic_receipt, "missing scripted dsPIC"),
                (apw, apw_receipt, "missing scripted APW"),
                (gate, gate_receipt, "missing scripted GPIO"),
            ] {
                if let Err(error) =
                    attempt_retained_safe_off_leg(owner, receipt, missing, ScriptedOwner::attempt)
                {
                    errors.push(error.to_string());
                }
            }
            if errors.is_empty() {
                Ok(())
            } else {
                anyhow::bail!(errors.join("; "))
            }
        }

        for failures in [(1, 0, 0), (0, 1, 0), (0, 0, 1), (1, 1, 1)] {
            let trace = Arc::new(Mutex::new(Vec::new()));
            let (mut dspic, dspic_drops) = owner("D", failures.0, &trace);
            let (mut apw, apw_drops) = owner("A", failures.1, &trace);
            let (mut gate, gate_drops) = owner("G", failures.2, &trace);
            let mut dspic_receipt = None;
            let mut apw_receipt = None;
            let mut gate_receipt = None;

            assert!(composite_attempt(
                &mut dspic,
                &mut dspic_receipt,
                &mut apw,
                &mut apw_receipt,
                &mut gate,
                &mut gate_receipt,
            )
            .is_err());
            assert_eq!(*trace.lock().unwrap(), vec!["D", "A", "G"]);
            for (failed, owner, receipt, drops) in [
                (failures.0 > 0, &dspic, &dspic_receipt, &dspic_drops),
                (failures.1 > 0, &apw, &apw_receipt, &apw_drops),
                (failures.2 > 0, &gate, &gate_receipt, &gate_drops),
            ] {
                assert_eq!(owner.is_some(), failed);
                assert_eq!(receipt.is_none(), failed);
                assert_eq!(drops.load(Ordering::SeqCst), u64::from(!failed));
            }
            assert!(
                dspic_receipt.is_none() || apw_receipt.is_none() || gate_receipt.is_none(),
                "partial completion must not mint composite evidence"
            );

            composite_attempt(
                &mut dspic,
                &mut dspic_receipt,
                &mut apw,
                &mut apw_receipt,
                &mut gate,
                &mut gate_receipt,
            )
            .unwrap();
            let trace_after_retry = trace.lock().unwrap().clone();
            for (name, failed_once) in [
                ("D", failures.0 > 0),
                ("A", failures.1 > 0),
                ("G", failures.2 > 0),
            ] {
                assert_eq!(
                    trace_after_retry
                        .iter()
                        .filter(|observed| **observed == name)
                        .count(),
                    if failed_once { 2 } else { 1 }
                );
            }
            assert_eq!(
                (dspic_receipt, apw_receipt, gate_receipt),
                (Some("D"), Some("A"), Some("G"))
            );
            assert_eq!(dspic_drops.load(Ordering::SeqCst), 1);
            assert_eq!(apw_drops.load(Ordering::SeqCst), 1);
            assert_eq!(gate_drops.load(Ordering::SeqCst), 1);

            composite_attempt(
                &mut dspic,
                &mut dspic_receipt,
                &mut apw,
                &mut apw_receipt,
                &mut gate,
                &mut gate_receipt,
            )
            .unwrap();
            assert_eq!(*trace.lock().unwrap(), trace_after_retry);
        }

        let trace = Arc::new(Mutex::new(Vec::new()));
        let (mut dspic, dspic_drops) = owner("D", 3, &trace);
        let (mut apw, apw_drops) = owner("A", 0, &trace);
        let (mut gate, gate_drops) = owner("G", 0, &trace);
        let mut dspic_receipt = None;
        let mut apw_receipt = None;
        let mut gate_receipt = None;
        for _ in 0..AM2_BM1362_TERMINAL_SAFE_OFF_ATTEMPTS {
            assert!(composite_attempt(
                &mut dspic,
                &mut dspic_receipt,
                &mut apw,
                &mut apw_receipt,
                &mut gate,
                &mut gate_receipt,
            )
            .is_err());
        }
        assert_eq!(*trace.lock().unwrap(), vec!["D", "A", "G", "D"]);
        assert!(dspic.is_some());
        assert!(dspic_receipt.is_none());
        assert_eq!(dspic_drops.load(Ordering::SeqCst), 0);
        assert_eq!(apw_drops.load(Ordering::SeqCst), 1);
        assert_eq!(gate_drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn am2_out_of_band_hard_stop_clears_every_terminal_ownership_flag() {
        let mut guard = Am2PsuRuntimeGuard::empty();
        guard.power_boundary_crossed = true;
        guard.dspic_ever_armed = true;
        guard.dspic_safe_off_receipt = Some(Am2DspicSafeOffDisposition::NeverArmed);

        guard.hard_stop_out_of_band("unit-test");

        assert!(!guard.has_terminal_ownership());
        assert!(!guard.power_boundary_crossed);
        assert!(!guard.dspic_ever_armed);
        assert!(guard.dspic_safe_off_receipt.is_none());
    }

    #[test]
    fn am2_out_of_band_hard_stop_cannot_drop_assign_or_early_return_live_ownership() {
        let source = include_str!("serial_mining.rs");
        let start = source
            .find("    fn hard_stop_out_of_band(&mut self")
            .expect("AM2 hard-stop entry");
        let end = source[start..]
            .find("impl Drop for Am2PsuRuntimeGuard")
            .map(|offset| start + offset)
            .expect("AM2 hard-stop boundary");
        let hard_stop = &source[start..end];
        assert!(!hard_stop.contains("*owned ="));
        assert!(!hard_stop.contains("ManuallyDrop::into_inner"));

        let owned_start = hard_stop
            .find("fn hard_stop_out_of_band_owned")
            .expect("owned AM2 hard stop");
        let owned = &hard_stop[owned_start..];
        assert!(!owned.contains("return;"));
        for retirement in [
            "self.apw = Am2ApwRuntimeState::Unclassified;",
            "self.dspic.take();",
            "self.dspic_safe_off_receipt.take();",
            "self.gate_safe_off_receipt.take();",
            "self.management_fabric.take();",
            "self.management_fabric_transition.take();",
            "self.power_boundary_crossed = false;",
            "self.dspic_ever_armed = false;",
        ] {
            assert!(
                owned.contains(retirement),
                "missing retirement: {retirement}"
            );
        }
    }

    #[test]
    fn apw_bypass_and_unclassified_state_transitions_are_explicit() {
        let mut bypass = Am2ApwRuntimeState::Bypassed(Am2ApwBypassAdmission {
            _model: "Loki".to_string(),
            _rail_v: 12.0,
        });
        attempt_am2_apw_safe_off(&mut bypass, |_| panic!("bypass must not call an APW owner"))
            .unwrap();
        assert!(matches!(
            bypass,
            Am2ApwRuntimeState::SafeOff(Am2ApwSafeOffReceipt::ExplicitBypass(_))
        ));

        let mut unclassified = Am2ApwRuntimeState::Unclassified;
        assert!(attempt_am2_apw_safe_off(&mut unclassified, |_| Ok(())).is_err());
        assert!(matches!(unclassified, Am2ApwRuntimeState::Unclassified));
    }

    #[cfg(feature = "sim-hal")]
    #[test]
    fn production_apw_state_machine_retains_failed_owner_and_never_replays_receipt() {
        use dcentrald_hal::platform::sim::{SimModel, SimPlatform};

        let platform = SimPlatform::new(SimModel::S19Pro);
        let service = platform.open_i2c_service(0).unwrap();
        let psu =
            Apw121215a::open_service_at(service, 0, dcentrald_hal::psu::APW12_FRAMED_ADDR).unwrap();
        let mut state = Am2ApwRuntimeState::Pending(Arc::new(Mutex::new(psu)));
        let mut attempts = 0;

        let error = attempt_am2_apw_safe_off(&mut state, |_| {
            attempts += 1;
            anyhow::bail!("scripted APW shutdown failure")
        })
        .unwrap_err();
        assert!(error.to_string().contains("scripted APW shutdown failure"));
        assert!(matches!(state, Am2ApwRuntimeState::Pending(_)));

        attempt_am2_apw_safe_off(&mut state, |_| {
            attempts += 1;
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            state,
            Am2ApwRuntimeState::SafeOff(Am2ApwSafeOffReceipt::SmartApw)
        ));

        attempt_am2_apw_safe_off(&mut state, |_| {
            attempts += 1;
            anyhow::bail!("completed APW receipt was replayed")
        })
        .unwrap();
        assert_eq!(attempts, 2);
    }

    #[test]
    fn am2_checked_teardown_retains_failed_leg_owners_and_retries_composite_evidence() {
        let source = include_str!("serial_mining.rs");
        let checked_start = source
            .find("    fn teardown_checked(\n")
            .expect("checked AM2 teardown");
        let after_barrier_start = source[checked_start..]
            .find("    fn teardown_after_terminal_barrier_checked(\n")
            .map(|offset| checked_start + offset)
            .expect("post-barrier checked AM2 teardown");
        let retry_start = source[after_barrier_start..]
            .find("    fn teardown_checked_retrying(\n")
            .map(|offset| after_barrier_start + offset)
            .expect("retrying AM2 teardown");
        let teardown_start = source[retry_start..]
            .find("    fn teardown(&mut self")
            .map(|offset| retry_start + offset)
            .expect("best-effort teardown boundary");
        let checked = &source[checked_start..after_barrier_start];
        let after_barrier = &source[after_barrier_start..retry_start];
        let retrying = &source[retry_start..teardown_start];

        assert!(checked.contains("attempt_after_terminal_barrier("));
        assert!(checked.contains("Am2PsuRuntimeGuard::latch_management_fabric_terminally"));
        assert!(checked.contains("teardown_after_terminal_barrier_checked"));
        assert!(!checked.contains("require_apw_classification"));
        assert!(
            after_barrier
                .matches("attempt_retained_safe_off_leg(")
                .count()
                >= 2
        );
        assert!(after_barrier.contains("|session|"));
        assert!(after_barrier.contains("session.controller_mut()"));
        assert!(!after_barrier.contains("Am2DspicRuntimeOwner::Legacy"));
        assert!(after_barrier.contains("attempt_am2_apw_safe_off(&mut self.apw"));
        assert!(after_barrier.contains("self.dspic_safe_off_receipt"));
        assert!(after_barrier.contains("self.gate_safe_off_receipt"));
        assert!(retrying.contains("AM2_BM1362_TERMINAL_SAFE_OFF_ATTEMPTS"));
        assert!(retrying
            .contains("self.teardown_checked(reason, require_dspic, teardown_budget.as_ref())"));

        let hard_stop_helper = source
            .split("    fn hard_stop_dspic_after_terminal_barrier(")
            .nth(1)
            .and_then(|tail| {
                tail.split("    /// Immediate transport-independent fallback")
                    .next()
            })
            .expect("bounded AM2 abnormal dsPIC closeout helper");
        assert!(hard_stop_helper.contains("teardown_after_terminal_barrier_checked"));
        assert!(hard_stop_helper.contains("std::mem::replace(&mut self.apw"));
        assert!(hard_stop_helper.contains("let retained_gate = self.gate.take()"));

        let hard_stop = source
            .split("    fn hard_stop_out_of_band(")
            .nth(1)
            .and_then(|tail| tail.split("impl Drop for Am2PsuRuntimeGuard").next())
            .expect("bounded AM2 out-of-band hard stop");
        let terminal_latch = hard_stop
            .find("service.latch_terminal_safe_off()")
            .expect("terminal I2C latch");
        let dspic_cut = hard_stop
            .find("self.hard_stop_dspic_after_terminal_barrier(reason)")
            .expect("out-of-band dsPIC cutoff");
        let gpio_cut = hard_stop
            .find("gate.force_safe_off_verified()")
            .expect("out-of-band PWR_CONTROL cutoff");
        assert!(terminal_latch < dspic_cut && dspic_cut < gpio_cut);
    }

    #[test]
    fn unique_owner_installation_never_replaces_live_or_completed_custody() {
        let mut owner = None;
        let mut receipt: Option<&'static str> = None;
        install_unique_owner(&mut owner, &receipt, "first", "duplicate").unwrap();
        assert!(install_unique_owner(&mut owner, &receipt, "second", "duplicate").is_err());
        assert_eq!(owner, Some("first"));

        owner.take();
        receipt = Some("completed");
        assert!(install_unique_owner(&mut owner, &receipt, "third", "duplicate").is_err());
        assert!(owner.is_none());
        assert_eq!(receipt, Some("completed"));
    }

    #[test]
    fn exact_am2_apw_applicability_is_explicit_and_unclassified_state_cannot_close() {
        let mut unclassified = Am2PsuRuntimeGuard::new();
        let error = unclassified
            .teardown_checked("unclassified-test", true, None)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("required AM2 management I2C fabric owner was absent"));

        let mut bypass = Am2PsuRuntimeGuard::new();
        assert!(bypass.admit_apw_bypass("", 12.0).is_err());
        assert!(bypass.admit_apw_bypass("Loki", f64::NAN).is_err());
        bypass.admit_apw_bypass("Loki", 12.0).unwrap();
        assert!(matches!(bypass.apw, Am2ApwRuntimeState::Bypassed(_)));
        assert!(bypass.admit_apw_bypass("second", 12.0).is_err());

        let mut missing_fabric = Am2PsuRuntimeGuard::new();
        missing_fabric.admit_apw_bypass("Loki", 12.0).unwrap();
        let error = missing_fabric
            .teardown_checked("missing-management-fabric-test", true, None)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("required AM2 management I2C fabric owner was absent"));
    }

    #[test]
    fn exact_am2_dspic_safeoff_distinguishes_never_armed_from_lost_armed_owner() {
        let mut never_armed = Am2PsuRuntimeGuard::empty();
        assert!(never_armed.classify_never_armed_dspic_for_safe_off());
        assert!(!never_armed.classify_never_armed_dspic_for_safe_off());
        assert!(matches!(
            never_armed.dspic_safe_off_receipt,
            Some(Am2DspicSafeOffDisposition::NeverArmed)
        ));
        never_armed.dspic_safe_off_receipt.take();

        let mut inherited_state_unknown = Am2PsuRuntimeGuard::empty();
        inherited_state_unknown.power_boundary_crossed = true;
        assert!(!inherited_state_unknown.classify_never_armed_dspic_for_safe_off());
        assert!(inherited_state_unknown.dspic_safe_off_receipt.is_none());

        let mut lost_armed_owner = Am2PsuRuntimeGuard::empty();
        lost_armed_owner.dspic_ever_armed = true;
        assert!(!lost_armed_owner.classify_never_armed_dspic_for_safe_off());
        assert!(lost_armed_owner.dspic_safe_off_receipt.is_none());
        lost_armed_owner.dspic_ever_armed = false;
    }

    #[cfg(feature = "sim-hal")]
    #[test]
    fn exact_am2_management_fabric_latch_is_unique_and_rejects_stale_clones() {
        use dcentrald_hal::platform::sim::{SimModel, SimPlatform};

        let platform = SimPlatform::new(SimModel::S19Pro);
        let service = platform.open_i2c_service(0).unwrap();
        let stale_clone = service.clone();
        let mut guard = Am2PsuRuntimeGuard::new();

        guard.set_management_fabric(service).unwrap();
        assert!(guard.set_management_fabric(stale_clone.clone()).is_err());
        guard.latch_management_fabric_terminally().unwrap();
        let transition = guard
            .management_fabric_transition
            .as_ref()
            .expect("positive terminal transition retained by the AM2 guard");
        assert!(transition.no_controller_mutation_stage_in_flight());
        let _service_startup_trace = platform.drain_i2c_trace().unwrap();

        let error = stale_clone
            .write_bytes(0x10, &[0x55, 0xAA, 0x04, 0x81, 0x01, 0x86])
            .expect_err("a stale service clone must reject post-safe-off mutation admission");
        assert!(error.to_string().contains("terminal safe-off is latched"));
        assert!(
            platform.drain_i2c_trace().unwrap().is_empty(),
            "post-latch mutation must fail before reaching the simulated I2C worker"
        );
    }

    #[cfg(feature = "sim-hal")]
    #[test]
    fn exact_am2_guard_retries_real_negative_i2c_barrier_before_any_safe_off_leg() {
        use dcentrald_hal::platform::sim::{SimModel, SimPlatform};

        let platform = SimPlatform::new(SimModel::S19Pro);
        let service = platform.open_i2c_service(0).unwrap();
        let stale_clone = service.clone();
        let mut guard = Am2PsuRuntimeGuard::new();
        guard.set_management_fabric(service).unwrap();
        guard
            .admit_apw_bypass("simulated fixed rail", 12.0)
            .unwrap();

        platform.arm_next_i2c_transfer_stall().unwrap();
        let mutation = std::thread::spawn(move || {
            stale_clone.write_bytes(0x10, &[0x55, 0xAA, 0x04, 0x81, 0x01, 0x86])
        });
        assert!(platform
            .wait_for_i2c_transfer_stall(Duration::from_secs(1))
            .unwrap());

        let first = guard
            .teardown_checked("real-negative-barrier", false, None)
            .expect_err("an in-flight controller stage must deny the first terminal barrier");
        assert!(first.to_string().contains("in-flight controller mutation"));
        assert!(guard.management_fabric_transition.is_none());
        assert!(matches!(guard.apw, Am2ApwRuntimeState::Bypassed(_)));
        assert!(guard.dspic_safe_off_receipt.is_none());
        assert!(guard.gate_safe_off_receipt.is_none());

        let retained_service = guard
            .management_fabric
            .as_ref()
            .expect("negative observation must retain the management-fabric owner")
            .clone();
        let stale_error = retained_service
            .write_bytes(0x10, &[0x55, 0xAA, 0x04, 0x81, 0x01, 0x86])
            .expect_err("the terminal latch must fence every later clone admission");
        assert!(stale_error
            .to_string()
            .contains("terminal safe-off is latched"));

        platform.release_i2c_transfer_stall().unwrap();
        let _admitted_mutation_result = mutation.join().unwrap();

        let second = guard
            .teardown_checked("real-positive-barrier", false, None)
            .expect_err("the intentionally incomplete fixture has no GPIO owner");
        let rendered = second.to_string();
        assert!(!rendered.contains("required dsPIC safe-direction owner was absent"));
        assert!(
            rendered.contains("required PWR_CONTROL safe-off owner was absent"),
            "{rendered}"
        );
        assert!(guard
            .management_fabric_transition
            .as_ref()
            .is_some_and(TerminalSafeOffTransition::no_controller_mutation_stage_in_flight));
        assert!(matches!(guard.apw, Am2ApwRuntimeState::SafeOff(_)));
        assert!(matches!(
            guard.dspic_safe_off_receipt,
            Some(Am2DspicSafeOffDisposition::NeverArmed)
        ));
    }

    #[test]
    fn exact_am2_power_boundary_remains_crossed_when_gpio_assertion_is_unknown() {
        let mut guard = Am2PsuRuntimeGuard::new();
        let mut watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        watchdog
            .claim_serial_route_scope(
                crate::runtime::safety_watchdog::SerialWatchdogComposition::Am2Bm1362,
            )
            .unwrap();
        let never_energized = watchdog.issue_am2_never_energized().unwrap();
        let error = assert_am2_psu_gpio_after_energizing_boundary_with(
            &mut guard,
            never_energized,
            Some("scripted-pwr-control"),
            |_| anyhow::bail!("scripted outcome-unknown GPIO assertion"),
        )
        .unwrap_err();

        assert!(error.to_string().contains("outcome-unknown"));
        assert!(guard.power_boundary_crossed);
        assert!(!guard.classify_never_armed_dspic_for_safe_off());
        assert!(guard.dspic_safe_off_receipt.is_none());
    }

    #[test]
    fn native_amlogic_serial_source_has_one_validated_write_and_shutdown_path() {
        let source = include_str!("serial_mining.rs");
        let production_end = source
            .find("\n#[cfg(test)]\nmod tests {")
            .expect("production/test module boundary");
        let production = &source[..production_end];
        let bm1368_start = production.find("fn init_bm1368_chain(").unwrap();
        let bm1368_end = production[bm1368_start..]
            .find("fn init_bm1366_chain(")
            .map(|offset| bm1368_start + offset)
            .unwrap();
        let bm1370_start = production.find("fn init_bm1370_chain(").unwrap();
        let bm1370_end = production[bm1370_start..]
            .find("fn init_bm1398_chain(")
            .map(|offset| bm1370_start + offset)
            .unwrap();
        for init in [
            &production[bm1368_start..bm1368_end],
            &production[bm1370_start..bm1370_end],
        ] {
            assert!(!init.contains("reset_asic_baud("));
            assert!(!init.contains("SerialChainBackend::open("));
            assert!(init.contains("ValidatedSerialBackend"));
            assert!(init.contains("query_chip_address_window("));
        }

        let run_start = production.find("pub async fn run(&mut self)").unwrap();
        let run = &production[run_start..];
        let observation = run.find(".begin_nopic_observation(").unwrap();
        let probe = run
            .find("nopic_observation.observe_candidate(probe_baud)")
            .unwrap();
        let bind = run.find(".bind_nopic_observed_serial(").unwrap();
        let promotion = run.find(".promote_nopic_execution(").unwrap();
        let init = run.find("Self::init_bm1370_chain(").unwrap();
        let shutdown_marker = run.find("info!(\"=== SHUTDOWN ===\");").unwrap();
        let route_revoke = run
            .find("Some(domains) => match domains.begin_closeout()")
            .unwrap();
        let shutdown = &run[shutdown_marker..];
        let shutdown_fence = shutdown
            .find("validated NoPic serial runtime shutdown")
            .unwrap();
        let api_closeout = shutdown.find("\"serial runtime API\"").unwrap();
        let queue_clear = shutdown.find(".clear();").unwrap();
        assert!(observation < probe && probe < bind && bind < promotion && promotion < init);
        assert!(route_revoke < shutdown_marker);
        assert!(shutdown_fence < api_closeout && api_closeout < queue_clear);
        assert!(!production.contains("terminal.close_and_wait_for_commit_fence()"));
        let admission_impl = production
            .find("impl ValidatedSerialChainAdmission {")
            .expect("validated serial admission implementation");
        let bind_start = production[admission_impl..]
            .find("    fn bind(\n")
            .map(|offset| admission_impl + offset)
            .expect("Amlogic platform bind method");
        let bind_end = production[bind_start..]
            .find("    fn bind_route(\n")
            .map(|offset| bind_start + offset)
            .expect("generic route bind boundary");
        let bind = &production[bind_start..bind_end];
        assert!(bind.contains("platform.board_target() != dispatch.board_target()"));
        assert!(bind.contains("platform.serial_device() != serial_device"));
        assert!(run.contains(".bind_nopic_observed_serial("));
        assert!(run.contains("chips: published_chip_count"));
        let raw_escape_marker = ["fn into_", "parts("].concat();
        assert!(!production.contains(&raw_escape_marker));
        let native_start = run.find("} else if is_bm1368 || is_bm1370 {").unwrap();
        let native_end = run[native_start..]
            .find("// ---- BM1362 (S19j Pro): PIC init + BM1362-specific init ----")
            .map(|offset| native_start + offset)
            .unwrap();
        let native = &run[native_start..native_end];
        assert!(!native.contains("if !found_chips"));
        assert!(!native.contains("continuing with cold NoPic init"));
    }

    #[test]
    fn exact_serial_raw_observation_is_restricted_and_promoted_without_reopen() {
        let source = include_str!("serial_mining.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production source");

        let nopic_facade = production
            .split_once("impl NoPicSerialObservation {")
            .expect("NoPic observation facade")
            .1
            .split_once("impl Am2SerialObservation {")
            .expect("NoPic observation boundary")
            .0;
        assert!(nopic_facade.contains("SerialChainBackend::open("));
        assert!(nopic_facade.contains("validate_serial_chip_address_window("));

        let am2_facade = production
            .split_once("impl Am2SerialObservation {")
            .expect("AM2 observation facade")
            .1
            .split_once("mod serial_route_domains {")
            .expect("AM2 observation boundary")
            .0;
        assert!(am2_facade.contains("post_enable_chain_uart_probe("));
        assert!(am2_facade.contains("SerialChainBackend::open("));
        assert!(am2_facade.contains("validate_unassigned_address_window("));

        let run = production
            .split_once("pub async fn run(&mut self)")
            .expect("serial runtime")
            .1;
        let nopic_start = run
            .find(".begin_nopic_observation(")
            .expect("NoPic observation begins");
        let nopic_promote = run[nopic_start..]
            .find(".promote_nopic_execution(")
            .map(|offset| nopic_start + offset)
            .expect("NoPic observation promotes");
        let nopic_segment = &run[nopic_start..nopic_promote];
        assert!(nopic_segment.contains("observe_candidate(probe_baud)"));
        assert!(nopic_segment.contains(".bind_nopic_observed_serial("));
        assert!(!nopic_segment.contains("SerialChainBackend::open("));

        let am2_start = run
            .find(".begin_am2_observation(")
            .expect("AM2 observation begins");
        let am2_promote = run[am2_start..]
            .find(".promote_am2_execution(")
            .map(|offset| am2_start + offset)
            .expect("AM2 observation promotes");
        let am2_segment = &run[am2_start..am2_promote];
        assert!(am2_segment.contains("observation.observe_preserve_state(pic_addr)?"));
        assert!(am2_segment.contains("observation.observe_reset_baseline()?"));
        assert!(am2_segment.contains(".bind_am2_observed_serial("));
        assert!(!am2_segment.contains("SerialChainBackend::open("));

        let domains = production
            .split_once("mod serial_route_domains {")
            .expect("opaque serial route domain")
            .1;
        assert!(domains.contains("struct BoundObservedSerial {"));
        assert!(domains.contains("Arc::ptr_eq(active_issuer, issuer)"));
        assert!(domains.contains("active_descriptor == descriptor"));
        assert!(domains.contains("Arc::ptr_eq(&bound.issuer, &observation.inner.issuer)"));
        assert!(domains.contains("bound.descriptor == observation.inner.descriptor"));
        assert!(!run.contains("ValidatedSerialChainAdmission::bind("));
        assert!(!run.contains("ValidatedSerialChainAdmission::bind_am2_bm1362("));
        assert!(!run.contains(".open_serial_execution("));
        assert!(!production.contains("observe_bm1362_reset_baseline"));
    }

    #[test]
    fn bm1366_enumeration_admission_is_strict_or_explicitly_degraded() {
        let strict = Bm1366EnumerationAdmission::from_startup_policy(77, 0).unwrap();
        assert_eq!(strict.minimum_required_responses, 77);
        assert!(!strict.admits_response_count(76));
        assert!(strict.admits_response_count(77));

        let degraded = Bm1366EnumerationAdmission::from_startup_policy(77, 8).unwrap();
        assert_eq!(degraded.minimum_required_responses, 69);
        assert!(!degraded.admits_response_count(68));
        assert!(degraded.admits_response_count(69));

        let one_chip_floor = Bm1366EnumerationAdmission::from_startup_policy(77, u8::MAX).unwrap();
        assert_eq!(one_chip_floor.minimum_required_responses, 1);
        assert!(!one_chip_floor.admits_response_count(0));
        assert!(one_chip_floor.admits_response_count(1));
        assert!(Bm1366EnumerationAdmission::from_startup_policy(0, 0).is_err());
    }

    #[test]
    fn bm1366_degraded_enumeration_component_cannot_bypass_runtime_refusal() {
        let source = include_str!("serial_mining.rs");
        let init_start = source.find("fn init_bm1366_chain(").unwrap();
        let init_end = source[init_start..]
            .find("fn init_bm1370_chain(")
            .map(|offset| init_start + offset)
            .unwrap();
        let init = &source[init_start..init_end];
        assert!(!init.contains("ExperimentalConfig::load()"));
        assert!(init.contains("enumeration_admission: &Bm1366EnumerationAdmission"));

        let run_start = source.find("pub async fn run(&mut self)").unwrap();
        let test_start = source.find("\n#[cfg(test)]\nmod tests {").unwrap();
        let run = &source[run_start..test_start];
        assert!(run.contains("if is_bm1366 && !passthrough"));
        // The transport-chain refusal backstop must refuse with a typed error
        // (bail), never panic. Both outcomes are terminal for the session --
        // an untyped bail yields a None disposition and main.rs refuses
        // stable management-only operation on None -- so what this pins is
        // diagnosability and destructor execution, NOT survival of the
        // firmware-update path. The bail literal below is split so this
        // contract cannot be satisfied by its own source text.
        let backstop_bail = [
            "anyhow::bail!(\"non-passthrough BM1366 ",
            "is refused before hardware observation\");",
        ]
        .concat();
        assert!(run.contains(&backstop_bail));
        let backstop_panic = ["unreachable!(\"non-", "passthrough"].concat();
        assert!(!run.contains(&backstop_panic));
        assert!(!run.contains("Bm1366EnumerationAdmission::from_startup_policy"));
        assert!(!run.contains("Self::init_bm1366_chain("));
        assert!(!run.contains("Waiting 21s for BM1366 ASIC boot"));
        assert!(!run.contains("ExperimentalConfig::load()"));
    }

    #[derive(Default)]
    struct MotionFanMock {
        pwm: std::sync::atomic::AtomicU8,
        minimum_motion_pwm: std::sync::atomic::AtomicU8,
        fail_on_command: std::sync::atomic::AtomicUsize,
        commands: Mutex<Vec<u8>>,
    }

    impl FanAccess for MotionFanMock {
        fn set_speed(&self, pwm: u8) {
            self.pwm.store(pwm, Ordering::Release);
            self.commands.lock().unwrap().push(pwm);
        }

        fn set_speed_checked(&self, pwm: u8) -> dcentrald_hal::Result<FanCommandReceipt> {
            self.set_speed(pwm);
            let command_count = self.commands.lock().unwrap().len();
            if self.fail_on_command.load(Ordering::Acquire) == command_count {
                return Err(dcentrald_hal::HalError::Fan(format!(
                    "injected checked fan-command failure at command {command_count}"
                )));
            }
            FanCommandReceipt::from_matching_readback(pwm, self.get_speed_pwm())
        }

        fn get_rpm(&self) -> u32 {
            self.get_per_fan_rpm()
                .into_iter()
                .map(|(_, rpm)| rpm)
                .min()
                .unwrap_or(0)
        }

        fn get_speed_pwm(&self) -> u8 {
            self.pwm.load(Ordering::Acquire)
        }

        fn get_per_fan_rpm(&self) -> Vec<(u8, u32)> {
            let pwm = self.get_speed_pwm();
            let minimum_motion_pwm = self.minimum_motion_pwm.load(Ordering::Acquire).max(1);
            let rpm = if pwm == 0 {
                0
            } else if pwm >= minimum_motion_pwm {
                1200
            } else {
                // Model one stray edge per second. A positive reading this low
                // must not satisfy the Amlogic credible-motion admission floor.
                30
            };
            (0..4).map(|id| (id, rpm)).collect()
        }

        fn fan_count(&self) -> u8 {
            4
        }
    }

    #[tokio::test]
    async fn preenergize_airflow_envelope_proves_max_then_min_then_restores_max() {
        let concrete = Arc::new(MotionFanMock::default());
        let fan: Arc<dyn FanAccess> = concrete.clone();
        let mut safety = FanTachSafety::with_minimum_credible_rpm(
            DEFAULT_FAN_BELOW_MINIMUM_FAILURE_TICKS,
            dcentrald_hal::platform::amlogic::REQUIRED_AIRFLOW_MIN_RPM,
        );

        let receipt = admit_fan_airflow_envelope(fan, &mut safety, 10, 30)
            .await
            .unwrap();

        assert_eq!(receipt.observed_pwm(), 30);
        assert_eq!(*concrete.commands.lock().unwrap(), [30, 10, 30]);
    }

    #[tokio::test]
    async fn preenergize_airflow_envelope_refuses_low_point_and_restores_maximum() {
        let concrete = Arc::new(MotionFanMock::default());
        concrete.minimum_motion_pwm.store(20, Ordering::Release);
        let fan: Arc<dyn FanAccess> = concrete.clone();
        let mut safety = FanTachSafety::with_minimum_credible_rpm(
            DEFAULT_FAN_BELOW_MINIMUM_FAILURE_TICKS,
            dcentrald_hal::platform::amlogic::REQUIRED_AIRFLOW_MIN_RPM,
        );

        let error = admit_fan_airflow_envelope(fan, &mut safety, 10, 30)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("restored startup ceiling"));
        assert_eq!(concrete.pwm.load(Ordering::Acquire), 30);
        assert_eq!(*concrete.commands.lock().unwrap(), [30, 10, 30]);
    }

    #[tokio::test]
    async fn preenergize_airflow_envelope_reports_low_point_and_restore_failures_together() {
        let concrete = Arc::new(MotionFanMock::default());
        concrete.minimum_motion_pwm.store(20, Ordering::Release);
        concrete.fail_on_command.store(3, Ordering::Release);
        let fan: Arc<dyn FanAccess> = concrete.clone();
        let mut safety = FanTachSafety::with_minimum_credible_rpm(
            DEFAULT_FAN_BELOW_MINIMUM_FAILURE_TICKS,
            dcentrald_hal::platform::amlogic::REQUIRED_AIRFLOW_MIN_RPM,
        );

        let error = admit_fan_airflow_envelope(fan, &mut safety, 10, 30)
            .await
            .unwrap_err();
        let message = error.to_string();

        assert!(message.contains("motion proof failed"));
        assert!(message.contains("restoration also failed"));
        assert!(message.contains("injected checked fan-command failure"));
        assert_eq!(*concrete.commands.lock().unwrap(), [30, 10, 30]);
    }

    #[test]
    fn nopic_fan_loop_disposition_is_terminal_for_every_revoked_state() {
        let continuing = [
            FanTachSafetyState::Healthy,
            FanTachSafetyState::Debouncing {
                consecutive_below_minimum: 1,
                failure_ticks: 3,
                minimum_credible_rpm: 300,
            },
        ];
        for state in continuing {
            assert_eq!(
                nopic_fan_loop_disposition(&state),
                NoPicFanLoopDisposition::Continue
            );
        }

        let terminal = [
            FanTachSafetyState::AirflowNotCommanded,
            FanTachSafetyState::Failed {
                consecutive_below_minimum: 3,
                failure_ticks: 3,
                minimum_credible_rpm: 300,
            },
            FanTachSafetyState::EvidenceUnavailable {
                expected_channels: 4,
                observed_channels: 3,
            },
        ];
        for state in terminal {
            assert_eq!(
                nopic_fan_loop_disposition(&state),
                NoPicFanLoopDisposition::SafeOffAndStop
            );
        }
    }

    #[test]
    fn bm1362_heartbeat_requires_supported_observed_dspic_firmware() {
        assert!(observed_dspic_firmware(None).is_err());
        assert!(observed_dspic_firmware(Some(0x00)).is_err());
        assert!(observed_dspic_firmware(Some(0xff)).is_err());
        assert!(observed_dspic_firmware(Some(0x88)).is_err());
        assert!(matches!(
            observed_dspic_firmware(Some(0x89)).unwrap(),
            DspicFirmware::Fw89
        ));
    }

    #[test]
    fn bm1362_heartbeat_failure_budget_is_bounded_and_success_resets_it() {
        let mut failures = 0;
        for expected in 1..AM2_BM1362_PIC_HEARTBEAT_MAX_FAILURES {
            assert_eq!(
                observe_am2_heartbeat_result(
                    &mut failures,
                    false,
                    AM2_BM1362_PIC_HEARTBEAT_MAX_FAILURES,
                ),
                Am2HeartbeatDisposition::Retrying {
                    consecutive_failures: expected,
                }
            );
        }
        assert_eq!(
            observe_am2_heartbeat_result(
                &mut failures,
                false,
                AM2_BM1362_PIC_HEARTBEAT_MAX_FAILURES,
            ),
            Am2HeartbeatDisposition::Terminal {
                consecutive_failures: AM2_BM1362_PIC_HEARTBEAT_MAX_FAILURES,
            }
        );
        assert_eq!(
            observe_am2_heartbeat_result(
                &mut failures,
                true,
                AM2_BM1362_PIC_HEARTBEAT_MAX_FAILURES,
            ),
            Am2HeartbeatDisposition::Healthy {
                recovered_failures: AM2_BM1362_PIC_HEARTBEAT_MAX_FAILURES,
            }
        );
        assert_eq!(failures, 0);
    }

    #[test]
    fn exact_dspic_heartbeat_is_bounded_observable_and_terminally_consumed() {
        let source = include_str!("serial_mining.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production serial mining source");
        let actor = production
            .split("let heartbeat_start_result = runtime_threads.spawn_pic_heartbeat")
            .nth(1)
            .and_then(|tail| tail.split("match heartbeat_start_result").next())
            .expect("exact dsPIC heartbeat actor");
        assert!(actor.contains("observe_am2_heartbeat_result("));
        assert!(actor.contains("am2_pic_heartbeat_terminal_limit"));
        assert!(actor.contains("am2_heartbeat_progress.fetch_add(1, Ordering::Release)"));
        assert!(actor.contains("Am2PicHeartbeatExit::Failed(reason)"));
        assert!(actor.contains("sleep_until_cancelled("));
        assert!(!production.contains("heartbeat_legacy_dspics"));
        assert!(!production.contains("legacy dsPIC heartbeat"));
        assert_eq!(
            production.matches("runtime_threads.request_stop();").count(),
            3,
            "NoPic failure, AM2 failure, and ordinary shutdown must all publish early actor cancellation"
        );

        let nopic_failure = production
            .split("async fn closeout_native_nopic_failure(")
            .nth(1)
            .and_then(|tail| tail.split("fn failure_with_closeout(").next())
            .expect("NoPic failure closeout");
        let nopic_revoke = nopic_failure
            .find(".and_then(SerialRouteDomains::begin_closeout)")
            .expect("NoPic failure route revocation");
        let nopic_cancel = nopic_failure
            .find("runtime_threads.request_stop();")
            .expect("NoPic failure actor cancellation");
        let nopic_watchdog_request = nopic_failure
            .find("watchdog.request_teardown_budget()")
            .expect("NoPic failure watchdog teardown request");
        let nopic_gpio = nopic_failure
            .find("NoPic failure first-stage safe-off")
            .expect("NoPic failure first-stage GPIO operation");
        let nopic_watchdog_observe = nopic_failure
            .find(".observe_teardown_admission(admission, view)")
            .expect("NoPic failure watchdog acknowledgement wait");
        let nopic_serial_wait = nopic_failure
            .find(".complete(serial_timeout, \"native NoPic failure\")")
            .expect("NoPic failure serial-domain completion wait");
        let nopic_api_wait = nopic_failure
            .find(".complete(api_timeout, \"native NoPic failure API\")")
            .expect("NoPic failure API-domain completion wait");
        assert!(nopic_revoke < nopic_cancel);
        assert!(nopic_cancel < nopic_watchdog_request);
        assert!(nopic_watchdog_request < nopic_gpio);
        assert!(nopic_gpio < nopic_watchdog_observe);
        assert!(nopic_watchdog_observe < nopic_serial_wait);
        assert!(nopic_watchdog_observe < nopic_api_wait);

        let am2_failure = production
            .split("async fn closeout_am2_bm1362_failure(")
            .nth(1)
            .and_then(|tail| tail.split("fn failure_with_am2_closeout(").next())
            .expect("AM2 failure closeout");
        let failure_revoke = am2_failure
            .find(".and_then(SerialRouteDomains::begin_closeout)")
            .expect("AM2 failure route revocation");
        let failure_cancel = am2_failure
            .find("runtime_threads.request_stop();")
            .expect("AM2 failure actor cancellation");
        let failure_watchdog_request = am2_failure
            .find("watchdog.request_teardown_budget()")
            .expect("AM2 failure watchdog teardown request");
        let failure_gpio = am2_failure
            .find("let first_stage_worker = run_timed_terminal_owner_operation_blocking(")
            .expect("AM2 failure first-stage GPIO operation");
        let failure_watchdog_observe = am2_failure
            .find(".observe_teardown_admission(admission, view)")
            .expect("AM2 failure watchdog acknowledgement wait");
        assert!(failure_revoke < failure_cancel);
        assert!(failure_cancel < failure_watchdog_request);
        assert!(failure_watchdog_request < failure_gpio);
        assert!(failure_gpio < failure_watchdog_observe);

        let shutdown = production
            .split("// A committed BM1362 job can continue autonomously")
            .nth(1)
            .expect("ordinary serial shutdown");
        let shutdown_revoke = shutdown
            .find("domains.begin_closeout()")
            .expect("ordinary shutdown route revocation");
        let shutdown_cancel = shutdown
            .find("runtime_threads.request_stop();")
            .expect("ordinary shutdown actor cancellation");
        let shutdown_watchdog_request = shutdown
            .find("watchdog.request_teardown_budget()")
            .expect("ordinary shutdown watchdog teardown request");
        let shutdown_gpio = shutdown
            .find("AM2 BM1362 operator-stop first-stage safe-off")
            .expect("ordinary shutdown first-stage GPIO operation");
        let shutdown_watchdog_observe = shutdown
            .find(".observe_teardown_admission(admission, view)")
            .expect("ordinary shutdown watchdog acknowledgement wait");
        let shutdown_ack_gates = shutdown
            .match_indices("watchdog_teardown_result?;")
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(
            shutdown_ack_gates.len(),
            2,
            "NoPic and AM2 closeout branches must both reject negative acknowledgement before Disarm"
        );
        let shutdown_nopic_manifest = shutdown
            .find("NoPicWatchdogShutdownManifest::new(")
            .expect("ordinary NoPic watchdog manifest");
        let shutdown_am2_manifest = shutdown
            .find("Am2SerialWatchdogShutdownManifest::new(")
            .expect("ordinary AM2 watchdog manifest");
        assert!(shutdown_revoke < shutdown_cancel);
        assert!(shutdown_cancel < shutdown_watchdog_request);
        assert!(shutdown_watchdog_request < shutdown_gpio);
        assert!(shutdown_gpio < shutdown_watchdog_observe);
        assert!(shutdown_watchdog_observe < shutdown_ack_gates[0]);
        assert!(shutdown_ack_gates[0] < shutdown_nopic_manifest);
        assert!(shutdown_nopic_manifest < shutdown_ack_gates[1]);
        assert!(shutdown_ack_gates[1] < shutdown_am2_manifest);

        let consumer = production
            .split("exit = am2_pic_heartbeat_exit_rx.recv()")
            .nth(1)
            .and_then(|tail| tail.split("exit = serial_actor_exit_rx.recv()").next())
            .expect("dsPIC heartbeat terminal consumer");
        assert!(consumer.contains("if monitor_dspic_heartbeat_actor"));
        assert!(consumer.contains("terminal_safety_error = Some"));
        assert!(consumer.contains("AM2 dsPIC heartbeat actor failed terminally"));
    }

    #[test]
    fn bm1362_heartbeat_terminal_limit_precedes_short_watchdog_reset_windows() {
        assert_eq!(am2_pic_heartbeat_failure_limit(3), None);
        assert_eq!(am2_pic_heartbeat_failure_limit(9), None);
        assert_eq!(am2_pic_heartbeat_failure_limit(10), Some(1));
        assert_eq!(am2_pic_heartbeat_failure_limit(20), Some(2));
        assert_eq!(am2_pic_heartbeat_failure_limit(60), Some(9));
        assert_eq!(am2_pic_heartbeat_failure_limit(180), Some(20));
    }

    #[test]
    fn bm1362_apw_heartbeat_threshold_retries_terminates_and_recovers() {
        assert_eq!(AM2_BM1362_APW_HEARTBEAT_MAX_FAILURES, 3);
        let mut failures = 0;
        assert_eq!(
            observe_am2_heartbeat_result(
                &mut failures,
                false,
                AM2_BM1362_APW_HEARTBEAT_MAX_FAILURES,
            ),
            Am2HeartbeatDisposition::Retrying {
                consecutive_failures: 1,
            }
        );
        assert_eq!(
            observe_am2_heartbeat_result(
                &mut failures,
                false,
                AM2_BM1362_APW_HEARTBEAT_MAX_FAILURES,
            ),
            Am2HeartbeatDisposition::Retrying {
                consecutive_failures: 2,
            }
        );
        assert_eq!(
            observe_am2_heartbeat_result(
                &mut failures,
                false,
                AM2_BM1362_APW_HEARTBEAT_MAX_FAILURES,
            ),
            Am2HeartbeatDisposition::Terminal {
                consecutive_failures: 3,
            }
        );
        assert_eq!(
            observe_am2_heartbeat_result(
                &mut failures,
                true,
                AM2_BM1362_APW_HEARTBEAT_MAX_FAILURES,
            ),
            Am2HeartbeatDisposition::Healthy {
                recovered_failures: 3,
            }
        );
        assert_eq!(failures, 0);
    }

    #[test]
    fn bm1362_apw_heartbeat_retries_only_wire_exhaustion_and_fails_typed_authority() {
        assert!(am2_apw_heartbeat_wire_retryable(
            &dcentrald_hal::HalError::I2c {
                bus: 0,
                addr: 0x10,
                detail: "transient data NAK".to_string(),
            }
        ));
        assert!(am2_apw_heartbeat_wire_retryable(
            &dcentrald_hal::HalError::PsuHeartbeatExhausted {
                primary: "0x84 transient wire failure".to_string(),
                fallback: "0x81/[0x02] transient wire failure".to_string(),
            }
        ));
        for error in [
            dcentrald_hal::HalError::I2cSafetySuperseded {
                bus: 0,
                addr: 0x10,
                detail: "terminal safe-off generation".to_string(),
            },
            dcentrald_hal::HalError::I2cSafeOffOutcomeUnknown {
                bus: 0,
                addr: 0x10,
                detail: "accepted safe-off completion was not observed".to_string(),
            },
            dcentrald_hal::HalError::PsuProtocolOwned(
                "unrelated runtime protocol failure".to_string(),
            ),
        ] {
            assert!(
                !am2_apw_heartbeat_wire_retryable(&error),
                "typed authority/protocol failure was incorrectly retryable: {error}"
            );
        }
    }

    #[test]
    fn bm1362_pool_disconnect_requires_announced_authority_and_uart_commit() {
        let mut startup = Am2PoolDisconnectSafety::default();
        assert!(!startup.observe(false, false, 0, false)); // initial
        assert!(!startup.observe(false, false, 0, false)); // Connecting
        assert!(!startup.observe(false, false, 0, false)); // Authorized
        assert!(!startup.observe(true, true, 0, false)); // Mining, no work yet
        assert!(!startup.observe(false, true, 0, false)); // loss before commit

        let mut committed = Am2PoolDisconnectSafety::default();
        assert!(!committed.observe(true, true, 0, false));
        assert!(!committed.observe(true, true, 1, false));
        assert!(committed.observe(false, true, 1, false));
        assert!(!committed.observe(false, true, 2, false)); // one terminal receipt

        let mut donating_without_job = Am2PoolDisconnectSafety::default();
        assert!(!donating_without_job.observe(true, true, 0, false));
        assert!(!donating_without_job.observe(false, true, 0, false));

        // Status and UART events are produced on different threads. If the
        // loss arrives first, observing the later physical commit while the
        // current state remains false must still trip.
        let mut reordered = Am2PoolDisconnectSafety::default();
        assert!(!reordered.observe(true, true, 0, false));
        assert!(!reordered.observe(false, true, 0, false));
        assert!(reordered.observe(false, true, 1, false));

        let mut explicitly_allowed = Am2PoolDisconnectSafety::default();
        assert!(!explicitly_allowed.observe(true, true, 1, true));
        assert!(!explicitly_allowed.observe(false, true, 1, true));
    }

    #[tokio::test]
    async fn exact_route_api_lifecycle_distinguishes_never_opened_from_opened_and_closed() {
        let mut am2_watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut am2 =
            SerialRouteDomains::claim(&mut am2_watchdog, ExactSerialRoute::Am2Bm1362).unwrap();
        let denied_gate = am2.management_api_gate().unwrap();
        assert!(denied_gate.try_acquire().is_err());
        let (_serial, api) = am2.begin_closeout().unwrap().split_for_closeout();
        let closeout = api
            .complete(Duration::from_millis(10), "AM2 API test")
            .await
            .unwrap();
        assert!(closeout.was_never_opened());

        let mut nopic_watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut nopic =
            SerialRouteDomains::claim(&mut nopic_watchdog, ExactSerialRoute::NoPic).unwrap();
        let open_gate = nopic.management_api_gate().unwrap();
        let lease = open_gate
            .try_acquire()
            .expect("NoPic API gate opens only through its lifecycle owner");
        drop(lease);
        let (_serial, api) = nopic.begin_closeout().unwrap().split_for_closeout();
        let closeout = api
            .complete(Duration::from_millis(10), "NoPic API test")
            .await
            .unwrap();
        assert!(!closeout.was_never_opened());
        assert!(open_gate.try_acquire().is_err());
    }

    #[tokio::test]
    async fn exact_am2_reset_closeout_distinguishes_never_attempted_from_serial_barrier() {
        let mut watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut domains =
            SerialRouteDomains::claim(&mut watchdog, ExactSerialRoute::Am2Bm1362).unwrap();
        let actor_owner = domains.take_am2_actor_owner().unwrap();
        let mut threads = SerialRuntimeThreads::new();
        threads.activate_am2(actor_owner).unwrap();

        let (serial, api) = domains.begin_closeout().unwrap().split_for_closeout();
        let mut serial = serial
            .complete(Duration::from_millis(100), "AM2 reset NeverAttempted test")
            .await
            .unwrap();
        api.complete(Duration::from_millis(100), "AM2 reset API closeout test")
            .await
            .unwrap();
        assert!(!serial.is_complete());
        let actor_admission = serial.take_actor_closeout_admission().unwrap();
        let reset = serial.take_am2_reset_closeout().unwrap();
        let actors = threads
            .stop_and_join(Duration::ZERO, Some(actor_admission))
            .await
            .into_am2_receipt()
            .unwrap();

        assert!(serial.is_complete());
        assert!(serial.authorizes_am2_actors(&actors));
        assert!(reset.run_scope().same_run(serial.run_scope()));
        assert!(reset.was_never_attempted());
        assert!(reset.safe_without_reset_mutation());
        assert!(!reset.pulse_register_verified());
        assert!(!reset.terminal_release_register_verified());
        assert!(!reset.outcome_unknown());
        assert_eq!(reset.slot(), None);
    }

    #[test]
    fn exact_am2_reset_mutation_is_route_bound_read_back_and_manifested() {
        let source = include_str!("serial_mining.rs");
        let hal = include_str!("../../dcentrald-hal/src/board_control.rs");
        let watchdog = include_str!("runtime/safety_watchdog.rs");
        let production = source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("serial production source");

        let domain_start = production
            .find("pub(super) fn pulse_am2_hashboard_reset(")
            .expect("watchdog-bound AM2 reset domain method");
        let domain_end = production[domain_start..]
            .find("pub(super) fn promote_nopic_execution(")
            .map(|offset| domain_start + offset)
            .expect("AM2 reset domain method boundary");
        let domain = &production[domain_start..domain_end];
        let issuer_check = domain
            .find("route.same_issuer(expected_issuer)")
            .expect("route issuer validation before reset ownership acquisition");
        let platform_open = domain
            .find("dcentrald_hal::platform::zynq::ZynqPlatform::new()")
            .expect("Zynq reset owner acquisition");
        let attempting = domain
            .find("self.reset = Am2ResetLifecycle::Attempting { slot };")
            .expect("pessimistic reset attempt transition");
        let pulse = domain
            .find("board_control.pulse_reset_exact(slot)")
            .expect("exact HAL reset call");
        let verified = domain
            .find("Am2ResetLifecycle::ReleaseRegisterVerified")
            .expect("register-verified reset transition");
        assert!(issuer_check < platform_open);
        assert!(platform_open < attempting && attempting < pulse && pulse < verified);

        let run = production
            .split("pub async fn run(&mut self)")
            .nth(1)
            .expect("serial runtime");
        let reset = run
            .find(".pulse_am2_hashboard_reset(route)?")
            .expect("route-domain reset transaction");
        let dspic_custody = run
            .find("am2_power.set_exact_dspic(pic_session)?")
            .expect("retained exact dsPIC safe-direction custody");
        let dspic_enable = run
            .find(".cold_boot_init_cancellable(13_700")
            .expect("exact dsPIC voltage enable");
        let observation = run
            .find(".begin_am2_observation(")
            .expect("AM2 observation admission");
        assert!(dspic_custody < reset && reset < dspic_enable && dspic_enable < observation);
        assert!(production.contains(
            "AM2 serial observation requires same-route, same-slot reset assertion/release register verification"
        ));
        assert!(domain.contains("route_issuer: Arc::clone(&route.issuer)"));
        assert!(production.contains("route.same_issuer(route_issuer)"));
        assert!(production.contains("SerialRouteDomains::claim_am2(&mut watchdog, route)"));
        assert!(domain.contains("PulseUnverifiedReleaseRegisterVerified"));
        assert!(watchdog.contains("self.reset.pulse_register_verified()"));
        assert!(watchdog.contains("self.reset.terminal_release_register_verified()"));
        assert_eq!(
            production
                .matches("DCENT_BM1362_SKIP_POST_POWER_RESET")
                .count(),
            1,
            "the forbidden reset-skip policy must be evaluated once at exact route admission, never re-read during runtime"
        );

        let write_low = hal
            .find("std::ptr::write_volatile(reg, low);")
            .expect("reset LOW write");
        let read_low = hal[write_low..]
            .find("let asserted_data = std::ptr::read_volatile(reg);")
            .map(|offset| write_low + offset)
            .expect("reset LOW readback");
        let write_high = hal
            .find("std::ptr::write_volatile(reg, high);")
            .expect("reset HIGH write");
        let read_high = hal[write_high..]
            .find("let released_data = std::ptr::read_volatile(reg);")
            .map(|offset| write_high + offset)
            .expect("reset HIGH readback");
        assert!(write_low < read_low && read_low < write_high && write_high < read_high);
        assert!(watchdog.contains("reset: crate::serial_mining::Am2ResetDomainCloseout"));
        assert!(
            watchdog.contains("AM2 reset MMIO outcome is unknown; watchdog Disarm is forbidden")
        );
    }

    fn exact_route_test_admission_at(
        serial_device: &str,
        configured_chip_count: u8,
    ) -> ValidatedSerialChainAdmission {
        ValidatedSerialChainAdmission::bind_route(
            serial_route_admission("am3-s21", dcentrald_common::AsicProtocolIdentity::Bm1368),
            2,
            serial_device,
            115_200,
            configured_chip_count,
            serial_window(0x1368, &[0]),
        )
        .unwrap()
    }

    fn exact_route_test_admission() -> ValidatedSerialChainAdmission {
        exact_route_test_admission_at("/dev/ttyS3", 108)
    }

    async fn close_test_route_domains(
        mut domains: SerialRouteDomains,
        open_serial: bool,
        open_api: bool,
    ) -> (SerialExecutionDomainCloseout, ApiMutationDomainCloseout) {
        if open_serial {
            let port = domains
                .open_serial_execution(exact_route_test_admission())
                .unwrap();
            drop(port);
        }
        if open_api {
            let gate = domains.management_api_gate().unwrap();
            let lease = gate.try_acquire().unwrap();
            drop(lease);
        }
        let (serial, api) = domains.begin_closeout().unwrap().split_for_closeout();
        (
            serial
                .complete(Duration::from_millis(100), "serial phase-matrix test")
                .await
                .unwrap(),
            api.complete(Duration::from_millis(100), "API phase-matrix test")
                .await
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn exact_route_domain_phase_matrix_is_owner_issued() {
        for (open_serial, open_api, serial_never_opened, api_never_opened) in [
            (false, false, true, true),
            (true, false, false, true),
            (true, true, false, false),
        ] {
            let mut watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
            let domains =
                SerialRouteDomains::claim(&mut watchdog, ExactSerialRoute::NoPic).unwrap();
            let (serial, api) = close_test_route_domains(domains, open_serial, open_api).await;
            assert_eq!(serial.was_never_opened(), serial_never_opened);
            assert_eq!(api.was_never_opened(), api_never_opened);
        }
    }

    #[tokio::test]
    async fn exact_serial_session_closeout_distinguishes_pending_observing_and_executing() {
        let mut pending_watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let pending =
            SerialRouteDomains::claim(&mut pending_watchdog, ExactSerialRoute::NoPic).unwrap();
        let (pending_serial, pending_api) = pending.begin_closeout().unwrap().split_for_closeout();
        let pending_closeout = pending_serial
            .complete(Duration::from_millis(100), "pending serial session test")
            .await
            .unwrap();
        pending_api
            .complete(Duration::from_millis(100), "pending API session test")
            .await
            .unwrap();
        assert!(pending_closeout.was_never_opened());
        assert!(!pending_closeout.was_observation_only());
        assert!(!pending_closeout.was_promoted_to_execution());

        let admission = exact_route_test_admission();
        let mut observing_watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut observing =
            SerialRouteDomains::claim(&mut observing_watchdog, ExactSerialRoute::NoPic).unwrap();
        let observation = observing
            .begin_serial_observation_for_test(&admission)
            .unwrap();
        let late_observation = observation.execution.clone();
        let (observing_serial, observing_api) =
            observing.begin_closeout().unwrap().split_for_closeout();
        assert!(late_observation
            .commit("late observation after revocation", || -> Result<()> {
                Ok(())
            })
            .is_err());
        drop(observation);
        drop(late_observation);
        let observing_closeout = observing_serial
            .complete(Duration::from_millis(100), "observing serial session test")
            .await
            .unwrap();
        observing_api
            .complete(Duration::from_millis(100), "observing API session test")
            .await
            .unwrap();
        assert!(!observing_closeout.was_never_opened());
        assert!(observing_closeout.was_observation_only());
        assert!(!observing_closeout.was_promoted_to_execution());

        let admission = exact_route_test_admission();
        let mut executing_watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut executing =
            SerialRouteDomains::claim(&mut executing_watchdog, ExactSerialRoute::NoPic).unwrap();
        let observation = executing
            .begin_serial_observation_for_test(&admission)
            .unwrap();
        let execution = executing
            .promote_serial_observation_for_test(observation, admission)
            .unwrap();
        let late_execution = execution.clone();
        let (executing_serial, executing_api) =
            executing.begin_closeout().unwrap().split_for_closeout();
        assert!(late_execution
            .commit("late execution after revocation", || -> Result<()> {
                Ok(())
            })
            .is_err());
        drop(execution);
        drop(late_execution);
        let executing_closeout = executing_serial
            .complete(Duration::from_millis(100), "executing serial session test")
            .await
            .unwrap();
        executing_api
            .complete(Duration::from_millis(100), "executing API session test")
            .await
            .unwrap();
        assert!(!executing_closeout.was_never_opened());
        assert!(!executing_closeout.was_observation_only());
        assert!(executing_closeout.was_promoted_to_execution());
    }

    #[tokio::test]
    async fn exact_serial_session_promotion_mismatch_restores_observation_and_revokes_late_work() {
        let admission = exact_route_test_admission_at("/dev/ttyS3", 108);
        let mismatched_admission = exact_route_test_admission_at("/dev/ttyS4", 108);
        let mut watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut domains =
            SerialRouteDomains::claim(&mut watchdog, ExactSerialRoute::NoPic).unwrap();
        let observation = domains
            .begin_serial_observation_for_test(&admission)
            .unwrap();
        let late_observation = observation.execution.clone();
        let error = domains
            .promote_serial_observation_for_test(observation, mismatched_admission)
            .unwrap_err();
        assert!(error.to_string().contains("does not match"));

        let (serial, api) = domains.begin_closeout().unwrap().split_for_closeout();
        assert!(late_observation
            .commit("late mismatched observation", || -> Result<()> { Ok(()) })
            .is_err());
        drop(late_observation);
        let closeout = serial
            .complete(Duration::from_millis(100), "mismatched serial session test")
            .await
            .unwrap();
        api.complete(Duration::from_millis(100), "mismatched API session test")
            .await
            .unwrap();
        assert!(closeout.was_observation_only());
    }

    #[tokio::test]
    async fn exact_serial_session_rejects_cross_session_observation_facade() {
        let admission_a = exact_route_test_admission();
        let admission_b = exact_route_test_admission();
        let mut watchdog_a = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut watchdog_b = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut domains_a =
            SerialRouteDomains::claim(&mut watchdog_a, ExactSerialRoute::NoPic).unwrap();
        let mut domains_b =
            SerialRouteDomains::claim(&mut watchdog_b, ExactSerialRoute::NoPic).unwrap();
        let observation_a = domains_a
            .begin_serial_observation_for_test(&admission_a)
            .unwrap();
        let late_a = observation_a.execution.clone();
        let observation_b = domains_b
            .begin_serial_observation_for_test(&admission_b)
            .unwrap();

        let error = domains_b
            .promote_serial_observation_for_test(observation_a, admission_a)
            .unwrap_err();
        assert!(error.to_string().contains("another session"));

        let (serial_a, api_a) = domains_a.begin_closeout().unwrap().split_for_closeout();
        let (serial_b, api_b) = domains_b.begin_closeout().unwrap().split_for_closeout();
        assert!(late_a
            .commit("late cross-session observation", || -> Result<()> {
                Ok(())
            })
            .is_err());
        drop(late_a);
        drop(observation_b);
        let closeout_a = serial_a
            .complete(Duration::from_millis(100), "cross-session A test")
            .await
            .unwrap();
        let closeout_b = serial_b
            .complete(Duration::from_millis(100), "cross-session B test")
            .await
            .unwrap();
        api_a
            .complete(Duration::from_millis(100), "cross-session API A test")
            .await
            .unwrap();
        api_b
            .complete(Duration::from_millis(100), "cross-session API B test")
            .await
            .unwrap();
        assert!(closeout_a.was_observation_only());
        assert!(closeout_b.was_observation_only());
    }

    #[test]
    fn dropping_opened_route_domains_revokes_uart_and_api_admission() {
        let mut watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut domains =
            SerialRouteDomains::claim(&mut watchdog, ExactSerialRoute::NoPic).unwrap();
        let serial = domains
            .open_serial_execution(exact_route_test_admission())
            .unwrap();
        let api = domains.management_api_gate().unwrap();
        drop(domains);

        assert!(serial
            .commit("late commit after route-owner drop", || -> Result<()> {
                Ok(())
            })
            .is_err());
        assert!(api.try_acquire().is_err());
    }

    #[tokio::test]
    async fn exact_route_domain_closeouts_reject_cross_run_pairing_and_duplicate_claims() {
        let mut watchdog_a = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let domains_a =
            SerialRouteDomains::claim(&mut watchdog_a, ExactSerialRoute::NoPic).unwrap();
        assert!(SerialRouteDomains::claim(&mut watchdog_a, ExactSerialRoute::NoPic).is_err());
        let (serial_a, _api_a) = close_test_route_domains(domains_a, false, false).await;

        let mut watchdog_b = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let domains_b =
            SerialRouteDomains::claim(&mut watchdog_b, ExactSerialRoute::NoPic).unwrap();
        let (_serial_b, api_b) = close_test_route_domains(domains_b, false, false).await;
        assert!(
            crate::runtime::safety_watchdog::validate_exact_serial_domain_pair_for_test(
                false, &serial_a, &api_b,
            )
            .is_err()
        );

        let mut watchdog_c = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let domains_c =
            SerialRouteDomains::claim(&mut watchdog_c, ExactSerialRoute::NoPic).unwrap();
        let (serial_c, api_c) = close_test_route_domains(domains_c, false, false).await;
        crate::runtime::safety_watchdog::validate_exact_serial_domain_pair_for_test(
            false, &serial_c, &api_c,
        )
        .unwrap();

        let mut watchdog_am2 = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let domains_am2 =
            SerialRouteDomains::claim(&mut watchdog_am2, ExactSerialRoute::Am2Bm1362).unwrap();
        let (serial_am2, api_am2) = close_test_route_domains(domains_am2, false, false).await;
        assert!(
            crate::runtime::safety_watchdog::validate_exact_serial_domain_pair_for_test(
                false,
                &serial_am2,
                &api_am2,
            )
            .is_err()
        );
    }

    fn run_fake_serial_actor(
        backend: FakeSerialActorBackend,
        work: Vec<Vec<u8>>,
        nonce_tx: mpsc::Sender<Vec<u8>>,
        shutdown: CancellationToken,
        exact_am2_bm1362: bool,
    ) -> (SerialActorExit, u64, u64) {
        let progress = Arc::new(AtomicU64::new(0));
        let committed = Arc::new(AtomicU64::new(0));
        let exit = run_serial_io_actor(
            backend,
            Arc::new(Mutex::new(work.into())),
            nonce_tx,
            shutdown,
            Arc::clone(&progress),
            Arc::clone(&committed),
            exact_am2_bm1362,
            1,
            true,
        );
        (
            exit,
            progress.load(Ordering::Acquire),
            committed.load(Ordering::Acquire),
        )
    }

    #[test]
    fn serial_actor_distinguishes_empty_poll_liveness_from_committed_work() {
        let shutdown = CancellationToken::new();
        let mut backend = FakeSerialActorBackend::new(Vec::new(), shutdown.clone());
        backend.cancel_after_reads = Some(3);
        let (nonce_tx, _nonce_rx) = mpsc::channel(4);
        let (exit, progress, committed) =
            run_fake_serial_actor(backend, Vec::new(), nonce_tx, shutdown, true);
        assert!(matches!(exit, SerialActorExit::Cancelled));
        assert_eq!(progress, 3);
        assert_eq!(committed, 0);
    }

    #[test]
    fn serial_actor_mints_commit_evidence_only_after_successful_tx() {
        let shutdown = CancellationToken::new();
        let mut backend = FakeSerialActorBackend::new(Vec::new(), shutdown.clone());
        backend.cancel_after_send = true;
        let (nonce_tx, _nonce_rx) = mpsc::channel(4);
        let (exit, progress, committed) =
            run_fake_serial_actor(backend, vec![vec![0x21, 0x56]], nonce_tx, shutdown, true);
        assert!(matches!(exit, SerialActorExit::Cancelled));
        assert!(progress >= 1);
        assert_eq!(committed, 1);

        let shutdown = CancellationToken::new();
        let mut failed = FakeSerialActorBackend::new(Vec::new(), shutdown.clone());
        failed.fail_send = true;
        let (nonce_tx, _nonce_rx) = mpsc::channel(4);
        let (exit, _, committed) =
            run_fake_serial_actor(failed, vec![vec![0x21, 0x56]], nonce_tx, shutdown, true);
        let SerialActorExit::Failed(reason) = exit else {
            panic!("failed TX must terminate the serial actor");
        };
        assert!(reason.contains("serial work send failed"));
        assert!(reason.contains("injected serial TX failure"));
        assert_eq!(committed, 0);
    }

    #[test]
    fn serial_actor_receiver_loss_and_three_read_errors_are_terminal() {
        let shutdown = CancellationToken::new();
        let backend =
            FakeSerialActorBackend::new(vec![Ok(Some(vec![0xAA, 0x55]))], shutdown.clone());
        let (nonce_tx, nonce_rx) = mpsc::channel(1);
        drop(nonce_rx);
        let (exit, _, _) = run_fake_serial_actor(backend, Vec::new(), nonce_tx, shutdown, true);
        assert!(matches!(
            exit,
            SerialActorExit::Failed(reason) if reason.contains("nonce receiver closed")
        ));

        let shutdown = CancellationToken::new();
        let backend = FakeSerialActorBackend::new(
            vec![
                Err(anyhow::anyhow!("read one")),
                Err(anyhow::anyhow!("read two")),
                Err(anyhow::anyhow!("read three")),
            ],
            shutdown.clone(),
        );
        let (nonce_tx, _nonce_rx) = mpsc::channel(1);
        let (exit, _, _) = run_fake_serial_actor(backend, Vec::new(), nonce_tx, shutdown, true);
        assert!(matches!(
            exit,
            SerialActorExit::Failed(reason) if reason.contains("3 consecutive times")
        ));
    }

    #[test]
    fn bm1362_nonce_safety_distinguishes_startup_midrun_and_disabled() {
        let mut guard = Am2NonceSafetyGuard::new(10, Some(Duration::from_secs(300)));
        assert_eq!(guard.evaluate(Duration::from_secs(100)), None);
        guard.observe_dispatch(Duration::from_secs(100));
        assert_eq!(guard.evaluate(Duration::from_secs(109)), None);
        assert_eq!(
            guard.evaluate(Duration::from_secs(110)),
            Some(Am2NonceSafetyTrip::StartupNoNonce)
        );
        assert_eq!(guard.evaluate(Duration::from_secs(999)), None);

        let mut midrun = Am2NonceSafetyGuard::new(10, Some(Duration::from_secs(300)));
        midrun.observe_dispatch(Duration::from_secs(5));
        midrun.observe_valid_nonce(Duration::from_secs(12));
        assert_eq!(midrun.evaluate(Duration::from_secs(311)), None);
        assert_eq!(
            midrun.evaluate(Duration::from_secs(312)),
            Some(Am2NonceSafetyTrip::MidRunNonceStall)
        );

        let mut paused = Am2NonceSafetyGuard::new(10, Some(Duration::from_secs(300)));
        paused.observe_dispatch(Duration::ZERO);
        paused.pause_for_missing_pool_authority();
        assert_eq!(paused.evaluate(Duration::from_secs(10_000)), None);

        let mut disabled = Am2NonceSafetyGuard::new(0, None);
        disabled.observe_dispatch(Duration::ZERO);
        disabled.observe_valid_nonce(Duration::from_secs(1));
        assert_eq!(
            disabled.evaluate(Duration::from_secs(u32::MAX as u64)),
            None
        );
    }

    #[test]
    fn exact_am2_source_clears_stale_work_when_hash_on_disconnect_is_false() {
        let source = include_str!("serial_mining.rs");
        let disconnect = source
            .find("if !pool_hashing_allowed && !hash_on_disconnect_enabled")
            .expect("disconnect authority gate");
        let branch = &source[disconnect..disconnect + 900];
        assert!(branch.contains("current_job = None"));
        // P1-1: the consolidated WorkHistoryRing clears every slot at once.
        assert!(branch.contains("work_history.clear_all();"));
        assert!(branch.contains(".clear();"));
        assert!(!branch.contains("send_work"));
    }

    #[test]
    fn serial_runtime_has_no_unbrokered_kernel_i2c_fd_or_ioctl_path() {
        let source = include_str!("serial_mining.rs");
        let raw_open = ["std::fs::", "OpenOptions"].concat();
        let raw_ioctl = ["libc::", "ioctl"].concat();
        let raw_bus_type = ["I2c", "Bus::"].concat();
        let platform_raw_open = [".open_i2c", "("].concat();
        let direct_device_open = [".open(\"/dev/", "i2c-"].concat();
        assert!(!source.contains(&raw_open));
        assert!(!source.contains(&raw_ioctl));
        assert!(!source.contains(&raw_bus_type));
        assert!(!source.contains(&platform_raw_open));
        assert!(!source.contains(&direct_device_open));
        assert!(source.contains("refusing an unbrokered /dev/i2c-0 owner"));
    }

    fn sample_entry(version: u32, version_mask: u32) -> WorkEntry {
        WorkEntry {
            generation: 1,
            work_generation: dcentrald_stratum::WorkGeneration::UNTRACKED,
            job_id: "job".to_string(),
            extranonce2: "00000000".to_string(),
            ntime: 0x65a0_b1c2,
            nbits: 0x1703_4219,
            version,
            version_mask,
            share_target: [0xff; 32],
            prev_block_hash: [0x11; 32],
            merkle_root: [0x22; 32],
        }
    }

    #[test]
    fn serial_rolled_version_reconstructs_when_pool_did_not_negotiate_mask() {
        // Updated 2026-05-15 (cross-platform Protocol fix sweep):
        // BM1362-family chips roll BIP320 unconditionally regardless of
        // pool `mining.configure` negotiation. The previous test asserted
        // a "drop on version_bits_raw != 0 when version_mask == 0" early
        // return, which was the silent-drop bug responsible for the .135
        // Amlogic 0.023% accept rate (per
        //  F1).
        // Now we reconstruct the rolled version unconditionally;
        // validate_full_header is the SOLE gate.
        let entry = sample_entry(0x2000_0000, 0);

        // vbits=0 â†’ base_version (no rolling, identity).
        assert_eq!(
            serial_rolled_version(&entry, 0, false, 0),
            Some(0x2000_0000)
        );
        // vbits=1, mask=0 â†’ reconstruct rolled version: (1 << 13) & 0x1FFFE000 = 0x2000;
        // rolled = (0x2000_0000 & !0x1FFFE000) | 0x2000 = 0x2000_2000.
        assert_eq!(
            serial_rolled_version(&entry, 1, false, 0),
            Some(0x2000_2000)
        );
        // vbits with the BIP320 field maximally set (vbits=0xFFFF) â†’
        // delta = 0x1FFFE000 (full mask); rolled = 0x2000_0000 | 0x1FFFE000.
        assert_eq!(
            serial_rolled_version(&entry, 0xFFFF, false, 0),
            Some(0x2000_0000 | 0x1FFF_E000)
        );
    }

    #[test]
    fn serial_rolled_version_accepts_only_negotiated_mask_bits() {
        let entry = sample_entry(0x2000_0000, 0x0000_6000);

        assert_eq!(
            serial_rolled_version(&entry, 1, false, 0),
            Some(0x2000_2000)
        );
        assert_eq!(serial_rolled_version(&entry, 4, false, 0), None);
    }

    #[test]
    fn bm1398_rejects_out_of_range_midstate_even_without_rolling() {
        let entry = sample_entry(0x2000_0000, 0);

        assert_eq!(serial_rolled_version(&entry, 0, true, 3), Some(0x2000_0000));
        assert_eq!(serial_rolled_version(&entry, 0, true, 4), None);
    }

    #[test]
    fn serial_share_fixture_keeps_target_and_achieved_difficulty_separate() {
        let entry = sample_entry(0x2000_0000, 0);
        let nonce = 0x2a00_0000;
        let header = serial_build_header(&entry, entry.version, nonce);
        // G22: engine builder is byte-identical to stratum pure SSOT.
        assert_eq!(
            header,
            dcentrald_stratum::v1::job::build_block_header(
                entry.version,
                &entry.prev_block_hash,
                &entry.merkle_root,
                entry.ntime,
                entry.nbits,
                nonce,
            )
        );

        assert!(dcentrald_stratum::share_pipeline::validate_full_header(
            &header,
            &entry.share_target
        ));

        let achieved = serial_achieved_difficulty_from_header(&header)
            .expect("fixture header should produce a finite achieved difficulty");
        let pool_target_difficulty = 8_192.0;
        let share = dcentrald_stratum::types::ValidShare {
            work_generation: entry.work_generation,
            worker_name: "worker.1".to_string(),
            job_id: entry.job_id.clone(),
            extranonce2: entry.extranonce2.clone(),
            ntime: format!("{:08x}", entry.ntime),
            nonce: format!("{:08x}", nonce),
            version_bits: None,
            version: entry.version,
            achieved_difficulty: Some(achieved),
        };

        assert_eq!(share.achieved_difficulty, Some(achieved));
        assert_ne!(share.achieved_difficulty, Some(pool_target_difficulty));
    }

    #[test]
    fn bm1398_fixture_validates_full_header_with_rolled_midstate() {
        let entry = sample_entry(0x2000_0000, 0x0000_6000);
        let rolled_version =
            serial_rolled_version(&entry, 0, true, 3).expect("BM1398 midstate 3 is valid");
        let header = serial_build_header(&entry, rolled_version, 0x1b2c_3d4e);

        assert_eq!(rolled_version, 0x2000_6000);
        assert!(dcentrald_stratum::share_pipeline::validate_full_header(
            &header,
            &entry.share_target
        ));
        assert!(serial_achieved_difficulty_from_header(&header).is_some());
    }

    #[test]
    fn bm1398_work_id_wraps_on_seven_bit_job_ring() {
        assert_eq!(serial_next_asic_job_id(0, BM1398_JOB_ID_INC), 4);
        assert_eq!(serial_next_asic_job_id(124, BM1398_JOB_ID_INC), 0);
        assert_eq!(serial_next_asic_job_id(120, BM1398_JOB_ID_INC), 124);
    }

    #[test]
    fn am3_bb_uart_trans_chain_parser_accepts_single_ttyo_path() {
        assert_eq!(
            SerialMiner::am3_bb_uart_trans_chains_from_serial_device("/dev/ttyO4"),
            Some(vec![2])
        );
        assert_eq!(SerialMiner::am3_bb_uart_trans_chain_bits(&[2]), 0b0100);
    }

    #[test]
    fn am3_bb_uart_trans_chain_parser_accepts_deduped_ttyo_list() {
        assert_eq!(
            SerialMiner::am3_bb_uart_trans_chains_from_serial_device(
                "/dev/ttyO1, /dev/ttyO2,/dev/ttyO4,/dev/ttyO2"
            ),
            Some(vec![0, 1, 2])
        );
        assert_eq!(
            SerialMiner::am3_bb_uart_trans_chain_bits(&[0, 1, 2]),
            0b0111
        );
    }

    #[test]
    fn am3_bb_uart_trans_chain_parser_rejects_unknown_or_empty_paths() {
        assert_eq!(
            SerialMiner::am3_bb_uart_trans_chains_from_serial_device("/dev/ttyS2"),
            None
        );
        assert_eq!(
            SerialMiner::am3_bb_uart_trans_chains_from_serial_device("/dev/ttyO1,"),
            None
        );
    }

    #[test]
    fn exact_am2_bm1362_refuses_unmonitored_uart_trans_routes() {
        for device in ["/dev/ttyO1", "/dev/ttyO1,/dev/ttyO2", "/dev/ttyO4"] {
            let error = require_monitored_am2_bm1362_serial_actor(device).unwrap_err();
            assert!(error.to_string().contains("refuses /dev/ttyO* uart_trans"));
        }
        for device in ["/dev/ttyS0", "/dev/ttyS2", "/dev/ttyAML0"] {
            require_monitored_am2_bm1362_serial_actor(device).unwrap();
        }
    }

    // -----------------------------------------------------------------------
    // F-E3 â€” BM1370 vs BM1368 driver-dispatch safety
    //
    // Discriminator: stock firmware reads CHIP_ID from register 0x00 â€”
    // BM1370 returns 0x13700000, BM1368 returns 0x13680000 (ESP-Miner
    // bm1370.c / bm1368.c). When the model string is pinned that ground
    // truth is honoured; the fail-safe closes the count-only inference path
    // so a BM1370 SKU can never silently land on the BM1368 path or the
    // BM1362 PIC-family catch-all.
    // -----------------------------------------------------------------------

    #[test]
    fn s21pro_family_models_resolve_to_bm1370_not_bm1368() {
        // Every BM1370 SKU model string must resolve to 0x1370 (NoPic), never
        // the BM1368 (0x1368) S21 path. nopic=true (S21 family is always NoPic).
        for model in ["s21pro", "s21xp", "s21+", "s21plus"] {
            let chip_id = resolve_serial_chip_id(Some(model), 65, true)
                .unwrap_or_else(|e| panic!("model {model} must resolve, got: {e}"));
            assert_eq!(
                chip_id, 0x1370,
                "{model} must dispatch to BM1370, not BM1368/BM1362"
            );
            assert!(serial_chip_id_is_nopic_family(chip_id));
        }
        // The proven S21/T21 path stays BM1368.
        for model in ["s21", "t21"] {
            assert_eq!(
                resolve_serial_chip_id(Some(model), 108, true).unwrap(),
                0x1368
            );
        }
    }

    #[test]
    fn bm1370_serial_execution_requires_exact_experimental_chip_authority() {
        assert!(admit_serial_driver_execution(0x1368, &[]).is_ok());
        assert!(admit_serial_driver_execution(0x1370, &[]).is_err());
        assert!(admit_serial_driver_execution(0x1370, &[0x1398]).is_err());
        let admission = admit_serial_driver_execution(0x1370, &[0x1370]).unwrap();
        assert_eq!(admission.chip_id(), 0x1370);
    }

    #[test]
    fn pinned_bm1370_model_wins_over_misleading_chip_count() {
        // A BM1370 chassis that mis-enumerates to 108 chips (the S21/BM1368
        // count) must STILL resolve to BM1370 when the model is pinned â€” the
        // operator-pinned register truth beats the count heuristic.
        assert_eq!(
            resolve_serial_chip_id(Some("s21pro"), 108, true).unwrap(),
            0x1370
        );
        // ...and a count of 65 with no model still infers BM1370 (anchor).
        assert_eq!(resolve_serial_chip_id(None, 65, true).unwrap(), 0x1370);
    }

    #[test]
    fn ambiguous_nopic_count_refuses_instead_of_guessing_a_pic_driver() {
        // The core F-E3 hazard: a NoPic S21-class chain with no model string
        // enumerating a non-anchor count would, under the old logic, fall
        // through to the BM1362 (PIC/dsPIC) catch-all â€” a wrong-family driver
        // on a NoPic chain. The fail-safe must REFUSE, not guess.
        for count in [60u8, 120, 130, 195, 0] {
            let result = resolve_serial_chip_id(None, count, true);
            assert!(
                result.is_err(),
                "NoPic chain at chip_count={count} with no model must refuse, \
                 got Ok({:?})",
                result.ok()
            );
        }
    }

    #[test]
    fn pic_family_default_path_is_unchanged_for_non_nopic_units() {
        // BM1362 am2/XIL units (PIC family, nopic=false) keep the proven
        // catch-all default at non-anchor counts (e.g. 28/126) â€” no regression.
        assert_eq!(resolve_serial_chip_id(None, 126, false).unwrap(), 0x1362);
        assert_eq!(resolve_serial_chip_id(None, 28, false).unwrap(), 0x1362);
        // Proven count anchors for the other PIC families are preserved.
        assert_eq!(resolve_serial_chip_id(None, 114, false).unwrap(), 0x1398);
        assert_eq!(resolve_serial_chip_id(None, 110, false).unwrap(), 0x1366);
        assert_eq!(resolve_serial_chip_id(None, 77, false).unwrap(), 0x1366);
    }

    #[test]
    fn native_serial_identity_never_comes_from_default_or_explicit_geometry() {
        assert!(resolve_native_serial_identity_and_geometry(None, None).is_err());
        assert!(resolve_native_serial_identity_and_geometry(None, Some(126)).is_err());
        assert!(
            resolve_native_serial_identity_and_geometry(Some("future-miner"), Some(126)).is_err()
        );
        assert!(
            resolve_native_serial_identity_and_geometry(Some("s9"), Some(63)).is_err(),
            "a recognized model outside the native serial dispatcher must fail closed"
        );
    }

    #[test]
    fn native_serial_geometry_requires_catalog_evidence_or_explicit_override() {
        assert_eq!(
            resolve_native_serial_identity_and_geometry(Some("s19jpro"), None).unwrap(),
            (0x1362, 126)
        );
        assert!(resolve_native_serial_identity_and_geometry(Some("t19"), None).is_err());
        assert_eq!(
            resolve_native_serial_identity_and_geometry(Some("t19"), Some(76)).unwrap(),
            (0x1398, 76)
        );
        assert!(resolve_native_serial_identity_and_geometry(Some("t19"), Some(0)).is_err());
    }

    #[test]
    fn native_serial_voltage_identity_rejects_impossible_model_chip_pairs() {
        assert!(validate_serial_model_voltage_identity(
            "bad-pic-s21",
            0x1368,
            Some(model::ModelPicTypeHint::DsPic),
        )
        .is_err());
        assert!(validate_serial_model_voltage_identity(
            "bad-nopic-s19j",
            0x1362,
            Some(model::ModelPicTypeHint::NoPic),
        )
        .is_err());
        assert!(
            validate_serial_model_voltage_identity("missing-s21-declaration", 0x1370, None,)
                .is_err()
        );
        assert!(validate_serial_model_voltage_identity(
            "s19kpro",
            0x1366,
            Some(model::ModelPicTypeHint::NoPic),
        )
        .is_ok());
    }

    #[test]
    fn native_serial_difficulty_requires_a_registered_profile() {
        assert!(hardware_difficulty_for_serial_family(0xFFFF).is_err());
        let expected = MinerProfile::for_chip(0x1362)
            .expect("BM1362 profile")
            .hardware_difficulty as u64;
        assert_eq!(
            hardware_difficulty_for_serial_family(0x1362).unwrap(),
            expected
        );
    }

    #[test]
    fn retired_bhb56_dspic_route_has_no_runtime_capability_surface() {
        let production = include_str!("serial_mining.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production serial mining source");
        assert!(!production.contains("subtype_requires_bhb56_endpoint_capability"));
        assert!(!production.contains("pending_bhb56_endpoints"));
        assert!(!production.contains("set_legacy_dspics"));
        assert!(!production.contains("legacy_dspic_controllers"));
        assert!(!production.contains("AMLCtrl_BHB56-family system identity"));
        assert!(!production.contains("PicHeartbeatReservation::Legacy"));
        assert!(!production.contains("guard.push(\"s19j-pic-hb\""));
    }

    #[test]
    fn legacy_serial_topology_refuses_pic_heartbeat_before_spawn() {
        let mut threads = SerialRuntimeThreads::new();
        let spawned = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&spawned);

        let error = threads
            .spawn_pic_heartbeat(move || {
                observed.store(true, Ordering::SeqCst);
                Ok(std::thread::spawn(|| {}))
            })
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("exact AM2 BM1362 actor authority is required"));
        assert!(!spawned.load(Ordering::SeqCst));
    }

    #[test]
    fn runtime_thread_join_budget_exceeds_service_heartbeat_call_bound() {
        assert!(
            RUNTIME_THREAD_STOP_TIMEOUT > dcentrald_hal::i2c::I2C_HEARTBEAT_CALL_WALL_CLOCK_BUDGET
        );
        let production = include_str!("serial_mining.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .unwrap();
        assert!(production.contains("lock_runtime_owner_until_cancelled("));
        assert!(production.contains("psu.heartbeat_cancellable(|| shutdown.is_cancelled())"));
        assert!(!production.contains("let result = psu.heartbeat();"));
    }

    #[test]
    fn cancellation_interrupts_wait_for_runtime_owner_lock() {
        let owner = Arc::new(Mutex::new(()));
        let held = owner.lock().unwrap();
        let shutdown = CancellationToken::new();
        let worker_owner = Arc::clone(&owner);
        let worker_shutdown = shutdown.clone();
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let cancelled = lock_runtime_owner_until_cancelled(
                worker_owner.as_ref(),
                &worker_shutdown,
                "test owner",
            )
            .is_none();
            result_tx.send(cancelled).unwrap();
        });

        std::thread::sleep(Duration::from_millis(40));
        shutdown.cancel();
        let cancelled = result_rx.recv_timeout(Duration::from_secs(1));
        drop(held);
        worker.join().unwrap();
        assert_eq!(cancelled.unwrap(), true);
    }

    #[test]
    fn exact_serial_actor_topology_rejects_controller_conflicts_before_route_use() {
        assert_eq!(
            SerialActorTopology::admit(true, false, true).unwrap(),
            SerialActorTopology::ExactNoPic
        );
        assert_eq!(
            SerialActorTopology::admit(false, true, false).unwrap(),
            SerialActorTopology::ExactAm2Bm1362
        );
        assert!(SerialActorTopology::admit(true, false, false).is_err());
        assert!(SerialActorTopology::admit(false, true, true).is_err());
        assert!(SerialActorTopology::admit(true, true, true).is_err());
    }

    #[tokio::test]
    async fn exact_serial_io_rejects_alternate_actor_before_spawn_closure() {
        let mut watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let admission = watchdog
            .claim_serial_route_scope(
                crate::runtime::safety_watchdog::SerialWatchdogComposition::NoPic,
            )
            .unwrap();
        let (_scope, actor_owner, _expectation) = admission.into_nopic_parts().unwrap();
        let mut threads = SerialRuntimeThreads::new();
        threads.activate_nopic(actor_owner).unwrap();

        let spawn_called = Arc::new(AtomicBool::new(false));
        let closure_called = Arc::clone(&spawn_called);
        let result = threads.spawn_serial_io("am3-bb-uart-trans-io", move || {
            closure_called.store(true, Ordering::SeqCst);
            Ok(std::thread::spawn(|| {}))
        });
        assert!(result.is_err());
        assert!(!spawn_called.load(Ordering::SeqCst));
        assert!(threads
            .stop_and_join(Duration::from_secs(1), None)
            .await
            .into_nopic_receipt()
            .is_err());
    }

    #[tokio::test]
    async fn exact_serial_pre_runtime_closeout_classifies_only_untouched_actor_slots() {
        let mut nopic_watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut nopic_domains =
            SerialRouteDomains::claim(&mut nopic_watchdog, ExactSerialRoute::NoPic).unwrap();
        let actor_owner = nopic_domains.take_nopic_actor_owner().unwrap();
        let mut nopic_threads = SerialRuntimeThreads::new();
        nopic_threads.activate_nopic(actor_owner).unwrap();

        let (serial, api) = nopic_domains.begin_closeout().unwrap().split_for_closeout();
        let mut serial = serial
            .complete(
                Duration::from_millis(100),
                "NoPic pre-runtime actor closeout test",
            )
            .await
            .unwrap();
        api.complete(
            Duration::from_millis(100),
            "NoPic pre-runtime API closeout test",
        )
        .await
        .unwrap();
        assert!(!serial.is_complete());
        let admission = serial.take_actor_closeout_admission().unwrap();
        let actors = nopic_threads
            .stop_and_join(Duration::from_secs(1), Some(admission))
            .await
            .into_nopic_receipt()
            .unwrap();
        assert!(serial.is_complete());
        assert!(serial.authorizes_nopic_actors(&actors));
        assert!(actors.not_started_before_runtime_admission(NoPicSerialThreadSlot::SerialIo));
        assert!(!actors.topology_not_applicable(NoPicSerialThreadSlot::SerialIo));

        let mut am2_watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut am2_domains =
            SerialRouteDomains::claim(&mut am2_watchdog, ExactSerialRoute::Am2Bm1362).unwrap();
        let actor_owner = am2_domains.take_am2_actor_owner().unwrap();
        let mut am2_threads = SerialRuntimeThreads::new();
        am2_threads.activate_am2(actor_owner).unwrap();
        am2_threads
            .reserve_am2(Am2SerialThreadSlot::ApwHeartbeat)
            .unwrap()
            .attach(std::thread::spawn(|| {}));
        am2_threads
            .spawn_pic_heartbeat(|| Ok(std::thread::spawn(|| {})))
            .unwrap();

        let (serial, api) = am2_domains.begin_closeout().unwrap().split_for_closeout();
        let mut serial = serial
            .complete(
                Duration::from_millis(100),
                "AM2 partial actor closeout test",
            )
            .await
            .unwrap();
        api.complete(Duration::from_millis(100), "AM2 partial API closeout test")
            .await
            .unwrap();
        let admission = serial.take_actor_closeout_admission().unwrap();
        let actors = am2_threads
            .stop_and_join(Duration::from_secs(1), Some(admission))
            .await
            .into_am2_receipt()
            .unwrap();
        assert!(serial.authorizes_am2_actors(&actors));
        assert!(actors.joined(Am2SerialThreadSlot::ApwHeartbeat));
        assert!(actors.joined(Am2SerialThreadSlot::DspicHeartbeat));
        assert!(actors.not_started_before_runtime_admission(Am2SerialThreadSlot::SerialIo));
    }

    #[tokio::test]
    async fn exact_serial_actor_closeout_requires_matching_route_domain_authority() {
        let mut watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut domains =
            SerialRouteDomains::claim(&mut watchdog, ExactSerialRoute::NoPic).unwrap();
        let actor_owner = domains.take_nopic_actor_owner().unwrap();
        let mut threads = SerialRuntimeThreads::new();
        threads.activate_nopic(actor_owner).unwrap();
        assert!(threads
            .stop_and_join(Duration::ZERO, None)
            .await
            .into_nopic_receipt()
            .is_err());
        drop(domains);

        let mut nopic_watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut nopic_domains =
            SerialRouteDomains::claim(&mut nopic_watchdog, ExactSerialRoute::NoPic).unwrap();
        let actor_owner = nopic_domains.take_nopic_actor_owner().unwrap();
        let mut nopic_threads = SerialRuntimeThreads::new();
        nopic_threads.activate_nopic(actor_owner).unwrap();

        let mut am2_watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let am2_domains =
            SerialRouteDomains::claim(&mut am2_watchdog, ExactSerialRoute::Am2Bm1362).unwrap();
        let (am2_serial, _am2_api) = am2_domains.begin_closeout().unwrap().split_for_closeout();
        let mut am2_serial = am2_serial
            .complete(
                Duration::from_millis(100),
                "foreign AM2 actor closeout test",
            )
            .await
            .unwrap();
        let wrong_route = am2_serial.take_actor_closeout_admission().unwrap();
        assert!(nopic_threads
            .stop_and_join(Duration::ZERO, Some(wrong_route))
            .await
            .into_nopic_receipt()
            .is_err());
        drop(nopic_domains);
    }

    #[tokio::test]
    async fn exact_serial_runtime_actor_admission_requires_promoted_execution_and_same_roster() {
        let mut early_watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut early_domains =
            SerialRouteDomains::claim(&mut early_watchdog, ExactSerialRoute::NoPic).unwrap();
        let actor_owner = early_domains.take_nopic_actor_owner().unwrap();
        let mut early_threads = SerialRuntimeThreads::new();
        early_threads.activate_nopic(actor_owner).unwrap();
        early_threads
            .spawn_serial_io(NoPicSerialThreadSlot::SerialIo.name(), || {
                Ok(std::thread::spawn(|| {}))
            })
            .unwrap();
        let admission = early_threads.seal_exact_runtime(None).unwrap();
        let error = early_domains
            .admit_runtime_actors(admission)
            .err()
            .expect("pre-execution actor admission must fail");
        assert!(error
            .to_string()
            .contains("before serial execution promotion"));
        drop(early_domains);

        let mut route_watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut route_domains =
            SerialRouteDomains::claim(&mut route_watchdog, ExactSerialRoute::NoPic).unwrap();
        let route_actor_owner = route_domains.take_nopic_actor_owner().unwrap();
        let mut route_threads = SerialRuntimeThreads::new();
        route_threads.activate_nopic(route_actor_owner).unwrap();
        let execution = route_domains
            .open_serial_execution(exact_route_test_admission())
            .unwrap();
        drop(execution);

        let mut foreign_watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut foreign_domains =
            SerialRouteDomains::claim(&mut foreign_watchdog, ExactSerialRoute::NoPic).unwrap();
        let foreign_actor_owner = foreign_domains.take_nopic_actor_owner().unwrap();
        let mut foreign_threads = SerialRuntimeThreads::new();
        foreign_threads.activate_nopic(foreign_actor_owner).unwrap();
        foreign_threads
            .spawn_serial_io(NoPicSerialThreadSlot::SerialIo.name(), || {
                Ok(std::thread::spawn(|| {}))
            })
            .unwrap();
        let foreign_admission = foreign_threads.seal_exact_runtime(None).unwrap();
        let error = route_domains
            .admit_runtime_actors(foreign_admission)
            .err()
            .expect("cross-roster actor admission must fail");
        assert!(error.to_string().contains("another roster"));
        drop(route_domains);
        drop(foreign_domains);
    }

    #[tokio::test]
    async fn exact_serial_runtime_actor_admission_closes_as_joined_after_typed_mining_permit() {
        let mut watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut domains =
            SerialRouteDomains::claim(&mut watchdog, ExactSerialRoute::NoPic).unwrap();
        let actor_owner = domains.take_nopic_actor_owner().unwrap();
        let mut threads = SerialRuntimeThreads::new();
        threads.activate_nopic(actor_owner).unwrap();
        let execution = domains
            .open_serial_execution(exact_route_test_admission())
            .unwrap();
        drop(execution);
        threads
            .spawn_serial_io(NoPicSerialThreadSlot::SerialIo.name(), || {
                Ok(std::thread::spawn(|| {}))
            })
            .unwrap();
        let admission = threads.seal_exact_runtime(None).unwrap();
        let permit = domains.admit_runtime_actors(admission).unwrap();
        assert!(permit.is_nopic());
        drop(permit);

        let (serial, api) = domains.begin_closeout().unwrap().split_for_closeout();
        let mut serial = serial
            .complete(
                Duration::from_millis(100),
                "NoPic admitted actor closeout test",
            )
            .await
            .unwrap();
        api.complete(
            Duration::from_millis(100),
            "NoPic admitted API closeout test",
        )
        .await
        .unwrap();
        let closeout_admission = serial.take_actor_closeout_admission().unwrap();
        let actors = threads
            .stop_and_join(Duration::from_secs(1), Some(closeout_admission))
            .await
            .into_nopic_receipt()
            .unwrap();
        assert!(serial.nopic_runtime_actors_were_admitted());
        assert!(serial.authorizes_nopic_actors(&actors));
        assert!(actors.joined(NoPicSerialThreadSlot::SerialIo));
        assert!(!actors.not_started_before_runtime_admission(NoPicSerialThreadSlot::SerialIo));
    }

    #[tokio::test]
    async fn exact_am2_actor_topology_is_power_bound_and_failed_start_stays_negative() {
        let mut power = Am2PsuRuntimeGuard::empty();
        assert!(power.apw_actor_topology().is_err());
        power.admit_apw_bypass("test fixed rail", 12.0).unwrap();
        assert_eq!(
            power.apw_actor_topology().unwrap(),
            Am2ApwActorTopology::ExplicitBypass
        );

        let mut watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut domains =
            SerialRouteDomains::claim(&mut watchdog, ExactSerialRoute::Am2Bm1362).unwrap();
        let actor_owner = domains.take_am2_actor_owner().unwrap();
        let mut threads = SerialRuntimeThreads::new();
        threads.activate_am2(actor_owner).unwrap();
        drop(
            threads
                .reserve_serial_io(Am2SerialThreadSlot::SerialIo.name())
                .unwrap(),
        );
        let (serial, _api) = domains.begin_closeout().unwrap().split_for_closeout();
        let mut serial = serial
            .complete(
                Duration::from_millis(100),
                "AM2 failed-start actor closeout test",
            )
            .await
            .unwrap();
        let closeout_admission = serial.take_actor_closeout_admission().unwrap();
        assert!(threads
            .stop_and_join(Duration::ZERO, Some(closeout_admission))
            .await
            .into_am2_receipt()
            .is_err());
    }

    #[test]
    fn exact_serial_actor_rosters_reserve_before_spawn_and_feed_typed_manifests() {
        let source = include_str!("serial_mining.rs");
        let watchdog = include_str!("runtime/safety_watchdog.rs");

        assert!(source.contains("let mut runtime_threads = SerialRuntimeThreads::new();"));
        assert!(source.contains(".and_then(|owner| runtime_threads.activate_nopic(owner));"));
        assert!(source.contains(".and_then(|owner| runtime_threads.activate_am2(owner));"));
        let production = source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("serial production source");
        let retained_domains = production
            .match_indices("serial_route_domains = Some(domains);")
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(retained_domains.len(), 2);
        let am2_watchdog_retain = production
            .find("am2_watchdog = Some(watchdog);")
            .expect("retained AM2 watchdog before actor activation");
        let am2_actor_activation = production
            .find(".and_then(|owner| runtime_threads.activate_am2(owner));")
            .expect("AM2 actor activation");
        assert!(retained_domains[0] < am2_watchdog_retain);
        assert!(am2_watchdog_retain < am2_actor_activation);
        let nopic_watchdog_retain = production
            .find("nopic_watchdog = Some(watchdog_owner);")
            .expect("retained NoPic watchdog before actor activation");
        let nopic_actor_activation = production
            .find(".and_then(|owner| runtime_threads.activate_nopic(owner));")
            .expect("NoPic actor activation");
        assert!(retained_domains[1] < nopic_watchdog_retain);
        assert!(nopic_watchdog_retain < nopic_actor_activation);
        let untyped_registration = ["runtime_threads.", "push("].concat();
        assert!(!source.contains(&untyped_registration));

        let helper_start = source
            .find("fn spawn_serial_io(")
            .expect("serial actor reserve/spawn helper");
        let helper_end = source[helper_start..]
            .find("fn reserve_pic_heartbeat(")
            .map(|offset| helper_start + offset)
            .expect("serial actor helper boundary");
        let helper = &source[helper_start..helper_end];
        let serial_reserve = helper
            .find("let slot = self.reserve_serial_io(actor_name)?;")
            .expect("serial I/O slot reservation");
        let serial_spawn = helper
            .find("let handle = spawn()?;")
            .expect("serial I/O spawn");
        let serial_attach = helper
            .find("slot.attach(handle);")
            .expect("serial I/O slot attachment");
        assert!(serial_reserve < serial_spawn && serial_spawn < serial_attach);

        let pic_helper_start = source
            .find("fn spawn_pic_heartbeat(")
            .expect("dsPIC actor reserve/spawn helper");
        let pic_helper_end = source[pic_helper_start..]
            .find("async fn stop_and_join(")
            .map(|offset| pic_helper_start + offset)
            .expect("dsPIC actor helper boundary");
        let pic_helper = &source[pic_helper_start..pic_helper_end];
        let pic_reserve = pic_helper
            .find("let slot = self.reserve_pic_heartbeat()?;")
            .expect("dsPIC heartbeat slot reservation");
        let pic_spawn = pic_helper
            .find("let handle = spawn()?;")
            .expect("dsPIC heartbeat spawn");
        let pic_attach = pic_helper
            .find("slot.attach(handle);")
            .expect("dsPIC heartbeat slot attachment");
        assert!(pic_reserve < pic_spawn && pic_spawn < pic_attach);

        let run = source
            .split("pub async fn run(&mut self)")
            .nth(1)
            .expect("serial runtime");
        let topology_admission = run
            .find("SerialActorTopology::admit(")
            .expect("pre-hardware actor topology admission");
        let hardware_owner = run
            .find("let bm1362_i2c_service")
            .expect("first retained exact hardware owner");
        assert!(topology_admission < hardware_owner);
        assert!(run.contains(
            "exact direct-serial routes refuse the experimental uart_trans actor before hardware admission"
        ));

        let apw_reservation_pattern =
            [".reserve_am2(", "Am2SerialThreadSlot::ApwHeartbeat)?"].concat();
        let apw_reservations = source
            .match_indices(&apw_reservation_pattern)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(apw_reservations.len(), 2);
        for reservation in apw_reservations {
            let spawn = source[reservation..]
                .find(".name(\"s19j-serial-psu-hb\".into())")
                .map(|offset| reservation + offset)
                .expect("APW heartbeat spawn after reservation");
            let attach = source[spawn..]
                .find("heartbeat_slot.attach(handle);")
                .map(|offset| spawn + offset)
                .expect("APW heartbeat attachment");
            assert!(reservation < spawn && spawn < attach);
        }

        assert!(watchdog.contains("actors: ThreadRosterQuiescenceReceipt<NoPicSerialThreadSlot>"));
        assert!(watchdog.contains("actors: ThreadRosterQuiescenceReceipt<Am2SerialThreadSlot>"));
        let watchdog_compact = watchdog.split_whitespace().collect::<String>();
        assert!(watchdog_compact
            .contains("ThreadSlotDeclaration::conditional(NoPicSerialThreadSlot::SerialIo,)"));
        assert!(watchdog_compact
            .contains("ThreadSlotDeclaration::conditional(Am2SerialThreadSlot::DspicHeartbeat)"));
        assert!(source.contains("runtime_threads.seal_exact_runtime(am2_apw_topology)"));
        assert!(source.contains(".admit_runtime_actors(actor_admission)"));
        assert!(source.contains("closeout.take_actor_closeout_admission().ok()"));
        assert!(source.contains("watchdog.enter_exact_serial_mining(admission).await"));
        let seal = run
            .find("runtime_threads.seal_exact_runtime(am2_apw_topology)")
            .expect("exact roster seal");
        let serial_root_retired = run
            .find("drop(serial_actor_exit_tx);")
            .expect("serial actor root exit sender retirement");
        let freshness = run
            .find("require_exact_serial_actor_freshness(")
            .expect("pre-Mining actor freshness check");
        let route_admission = run
            .find(".admit_runtime_actors(actor_admission)")
            .expect("route-bound actor admission");
        let mining = run
            .find("watchdog.enter_exact_serial_mining(admission).await")
            .expect("watchdog Mining admission");
        assert!(
            serial_root_retired < freshness
                && freshness < seal
                && seal < route_admission
                && route_admission < mining
        );
        assert!(watchdog.contains(
            "exact serial watchdog Mining admission requires typed runtime-actor authority"
        ));
    }

    #[test]
    fn exact_serial_actor_freshness_rejects_queued_or_disconnected_required_exits() {
        let (serial_tx, mut serial_rx) = mpsc::unbounded_channel();
        let serial_actor_tx = serial_tx.clone();
        drop(serial_tx);
        let (pic_tx, mut pic_rx) = mpsc::unbounded_channel();
        let pic_actor_tx = pic_tx.clone();
        drop(pic_tx);
        let (apw_tx, mut apw_rx) = mpsc::unbounded_channel();
        drop(apw_tx);

        require_exact_serial_actor_freshness(
            SerialActorTopology::ExactAm2Bm1362,
            true,
            Some(Am2ApwActorTopology::ExplicitBypass),
            false,
            &mut serial_rx,
            &mut pic_rx,
            &mut apw_rx,
        )
        .expect("explicit APW bypass must not require a nonexistent APW actor");

        serial_actor_tx.send(SerialActorExit::Cancelled).unwrap();
        let queued = require_exact_serial_actor_freshness(
            SerialActorTopology::ExactAm2Bm1362,
            true,
            Some(Am2ApwActorTopology::ExplicitBypass),
            false,
            &mut serial_rx,
            &mut pic_rx,
            &mut apw_rx,
        )
        .unwrap_err();
        assert!(queued
            .to_string()
            .contains("serial-I/O actor exited before"));
        drop(serial_actor_tx);
        drop(pic_actor_tx);

        let (serial_tx, mut serial_rx) = mpsc::unbounded_channel::<SerialActorExit>();
        drop(serial_tx);
        let (_pic_tx, mut pic_rx) = mpsc::unbounded_channel::<Am2PicHeartbeatExit>();
        let (_apw_tx, mut apw_rx) = mpsc::unbounded_channel::<String>();
        let disconnected = require_exact_serial_actor_freshness(
            SerialActorTopology::ExactNoPic,
            true,
            None,
            false,
            &mut serial_rx,
            &mut pic_rx,
            &mut apw_rx,
        )
        .unwrap_err();
        assert!(disconnected
            .to_string()
            .contains("serial-I/O actor exit channel closed"));

        let (_serial_tx, mut serial_rx) = mpsc::unbounded_channel::<SerialActorExit>();
        let (_pic_tx, mut pic_rx) = mpsc::unbounded_channel::<Am2PicHeartbeatExit>();
        let (apw_tx, mut apw_rx) = mpsc::unbounded_channel::<String>();
        drop(apw_tx);
        let missing_apw = require_exact_serial_actor_freshness(
            SerialActorTopology::ExactAm2Bm1362,
            true,
            Some(Am2ApwActorTopology::SmartPsu),
            true,
            &mut serial_rx,
            &mut pic_rx,
            &mut apw_rx,
        )
        .unwrap_err();
        assert!(missing_apw
            .to_string()
            .contains("AM2 APW-heartbeat actor exit channel closed"));

        let (_serial_tx, mut serial_rx) = mpsc::unbounded_channel::<SerialActorExit>();
        let (_pic_tx, mut pic_rx) = mpsc::unbounded_channel::<Am2PicHeartbeatExit>();
        let (_apw_tx, mut apw_rx) = mpsc::unbounded_channel::<String>();
        let unobservable = require_exact_serial_actor_freshness(
            SerialActorTopology::ExactNoPic,
            false,
            None,
            false,
            &mut serial_rx,
            &mut pic_rx,
            &mut apw_rx,
        )
        .unwrap_err();
        assert!(unobservable
            .to_string()
            .contains("observable serial-I/O actor"));

        let legacy = require_exact_serial_actor_freshness(
            SerialActorTopology::LegacyNoPic,
            true,
            None,
            false,
            &mut serial_rx,
            &mut pic_rx,
            &mut apw_rx,
        )
        .unwrap_err();
        assert!(legacy
            .to_string()
            .contains("legacy serial topology cannot request exact actor freshness"));
    }

    #[test]
    fn exact_serial_invariant_failures_preserve_ordered_safety_legs() {
        let source = include_str!("serial_mining.rs");
        let routed_failure = ["failure_with_exact_", "serial_closeout("].concat();
        assert!(source.match_indices(&routed_failure).count() >= 5);

        let nopic_start = source
            .find("async fn closeout_native_nopic_failure(")
            .expect("NoPic failure closeout");
        let nopic_end = source[nopic_start..]
            .find("fn failure_with_closeout(")
            .map(|offset| nopic_start + offset)
            .expect("NoPic failure closeout boundary");
        let nopic = &source[nopic_start..nopic_end];
        let nopic_revoke = nopic
            .find(".and_then(SerialRouteDomains::begin_closeout)")
            .expect("NoPic synchronous route closeout attempt");
        let nopic_cut = nopic
            .find("NoPic failure first-stage safe-off")
            .expect("NoPic first-stage cutoff");
        let nopic_join = nopic
            .find("let thread_stop = runtime_threads")
            .expect("NoPic actor stop");
        let nopic_checked = nopic
            .find("NoPic failure checked safe-off")
            .expect("NoPic checked safe-off");
        assert!(nopic_revoke < nopic_cut && nopic_cut < nopic_join && nopic_join < nopic_checked);

        let am2_start = source
            .find("async fn closeout_am2_bm1362_failure(")
            .expect("AM2 failure closeout");
        let am2_end = source[am2_start..]
            .find("fn failure_with_am2_closeout(")
            .map(|offset| am2_start + offset)
            .expect("AM2 failure closeout boundary");
        let am2 = &source[am2_start..am2_end];
        let am2_revoke = am2
            .find(".and_then(SerialRouteDomains::begin_closeout)")
            .expect("AM2 synchronous route closeout attempt");
        let am2_cut = am2
            .find("AM2 BM1362 failure first-stage safe-off")
            .expect("AM2 first-stage cutoff");
        let am2_join = am2
            .find("let thread_stop = runtime_threads")
            .expect("AM2 actor stop");
        let am2_checked = am2
            .find("AM2 BM1362 checked terminal safe-off")
            .expect("AM2 checked safe-off");
        assert!(am2_revoke < am2_cut && am2_cut < am2_join && am2_join < am2_checked);

        let first_expect = [
            "expect(\"BM1362 serial domain was revoked",
            " before first-stage cutoff\")",
        ]
        .concat();
        let second_expect = [
            "expect(\"BM1362 route creates serial",
            " revocation evidence\")",
        ]
        .concat();
        assert!(!source.contains(&first_expect));
        assert!(!source.contains(&second_expect));
        let bringup_start = source
            .find("let bm1362_bringup_result: Result<SerialWorkTransport>")
            .expect("AM2 bring-up transaction");
        let bringup_end = source[bringup_start..]
            .find("match bm1362_bringup_result")
            .map(|offset| bringup_start + offset)
            .expect("single AM2 bring-up failure boundary");
        assert!(!source[bringup_start..bringup_end].contains("closeout_am2_bm1362_failure("));
        assert!(source.contains(
            "exact serial route reached terminal shutdown without retained watchdog ownership"
        ));
    }

    #[test]
    fn exact_serial_failure_disposition_requires_positive_watchdog_closeout() {
        let nopic_pending =
            failure_with_closeout(anyhow::anyhow!("primary"), Err(anyhow::anyhow!("closeout")));
        assert!(!is_terminal_safe_off_error(&nopic_pending));
        assert!(crate::runtime::safety_watchdog::is_watchdog_reset_pending(
            &nopic_pending
        ));

        let am2_pending =
            failure_with_am2_closeout(anyhow::anyhow!("primary"), Err(anyhow::anyhow!("closeout")));
        assert!(!is_terminal_safe_off_error(&am2_pending));
        assert!(crate::runtime::safety_watchdog::is_watchdog_reset_pending(
            &am2_pending
        ));

        let never_energized_pending = failure_with_am2_never_energized_closeout(
            anyhow::anyhow!("primary"),
            Err(anyhow::anyhow!("closeout")),
        );
        assert_eq!(failure_disposition(&never_energized_pending), None);
        assert!(crate::runtime::safety_watchdog::is_watchdog_reset_pending(
            &never_energized_pending
        ));

        let missing_receipt = classify_serial_terminal_result(
            SerialActorTopology::ExactAm2Bm1362,
            Some(anyhow::anyhow!("operator loop failed")),
            None,
        )
        .expect_err("missing closeout evidence must remain reset pending");
        assert!(!is_terminal_safe_off_error(&missing_receipt));
        assert!(crate::runtime::safety_watchdog::is_watchdog_reset_pending(
            &missing_receipt
        ));

        let source = include_str!("serial_mining.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production serial mining source");
        for receipt_move in [
            "Ok(receipt) => terminal_safe_off_error(primary, receipt)",
            "(true, Some(error), Some(closeout)) => Err(terminal_safe_off_error(error, closeout))",
            "Ok(receipt) => never_energized_error(primary, receipt)",
        ] {
            assert!(
                source.contains(receipt_move),
                "positive owner closeout must be moved into the terminal marker: {receipt_move}"
            );
        }
        assert!(source.contains("_closeout: closeout"));
        assert!(!source.contains(concat!("WatchdogCloseoutReceipt", "::")));
    }

    #[test]
    fn am2_never_energized_closeout_is_not_terminal_safe_off_evidence() {
        assert_ne!(
            SerialFailureDisposition::NeverEnergizedClosed,
            SerialFailureDisposition::TerminalSafeOffClosed
        );

        let source = include_str!("serial_mining.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production serial mining source");
        let closeout = source
            .split("async fn close_am2_watchdog_never_energized(")
            .nth(1)
            .and_then(|tail| tail.split("fn attempt_am2_first_stage_cut(").next())
            .expect("never-energized closeout body");
        assert!(closeout.contains("Result<Am2NeverEnergizedCloseout>"));
        assert!(closeout.contains(".disarm_never_energized(evidence"));
        assert!(closeout.contains("Am2NeverEnergizedCloseout"));
        assert!(!closeout.contains("terminal_safe_off_error"));

        assert_eq!(
            source
                .matches("close_am2_watchdog_never_energized(")
                .count(),
            source
                .matches("failure_with_am2_never_energized_closeout(")
                .count(),
            "every never-energized closeout path must use the distinct failure constructor"
        );
    }

    #[test]
    fn nopic_watchdog_and_safeoff_order_is_fail_closed() {
        let source = include_str!("serial_mining.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production serial mining source");
        let management_owner = source
            .find("let mut amlogic_power_thermal")
            .expect("retained Amlogic management owner declaration");
        let cooling_owner = source
            .find("let mut amlogic_fan")
            .expect("retained Amlogic cooling owner declaration");
        let watchdog_owner = source
            .find("let mut nopic_watchdog")
            .expect("retained NoPic watchdog owner declaration");
        let psu_guard = source
            .find("let mut nopic_psu_guard")
            .expect("NoPic PSU guard declaration");
        let service_spawn = source
            .find(".spawn_power_thermal_service()")
            .expect("retained bus-1 service spawn");
        let admission = source
            .find("AmlogicNoPicAdmission::detect(")
            .expect("typed Amlogic NoPic admission");
        let bm1366_refusal = source
            .find("NOT IMPLEMENTED: native BM1366 catalog identities")
            .expect("BM1366 native fail-closed boundary");
        let fan_open = source
            .find(".open_fan_controller()")
            .expect("pre-energize cooling admission");
        let fan_motion = source
            .find("let receipt = admit_fan_airflow_envelope(")
            .expect("pre-energize fan-motion evidence gate");
        let power_start = source
            .find("if !native_nopic_power_owner")
            .expect("NoPic power-ownership boundary");
        let power_end = source[power_start..]
            .find("let mut startup_board_temps")
            .map(|offset| power_start + offset)
            .expect("NoPic post-enable temperature boundary");
        let power = &source[power_start..power_end];
        let watchdog_arm = power
            .find("SafetyWatchdogOwner::start_before_energizing")
            .expect("pre-energize watchdog admission");
        let lifecycle_owner = power
            .find(".take_lifecycle_owner()")
            .expect("move-only bus-1 lifecycle transfer");
        let may_be_energized = power
            .find("nopic_psu_guard.prepare_enable")
            .expect("pre-mutation NoPic guard arm");
        let enable_operation = power
            .find(".take_psu_enable_operation()")
            .expect("one-shot GPIO437/APW enable authority");
        let psu_enable = power
            .find("tokio::task::spawn_blocking(move || psu_enable_operation.enable_psu())")
            .expect("retained-service GPIO437/APW enable call");
        let enabled_receipt = power
            .find("nopic_psu_guard.mark_enabled()")
            .expect("NoPic enable ownership receipt");
        let startup_coverage_gate = source[power_end..]
            .find("if startup_coverage.is_complete()")
            .map(|offset| power_end + offset)
            .expect("complete startup thermal-coverage gate");
        let first_asic_probe = source[power_end..]
            .find("Phase 1c: Probing chips")
            .map(|offset| power_end + offset)
            .expect("first NoPic ASIC probe");
        assert!(lifecycle_owner < may_be_energized);
        assert!(may_be_energized < enable_operation);
        assert!(enable_operation < watchdog_arm);
        assert!(watchdog_arm < psu_enable);
        assert!(psu_enable < enabled_receipt);
        assert!(enabled_receipt + power_start < startup_coverage_gate);
        assert!(startup_coverage_gate < first_asic_probe);
        assert!(management_owner < cooling_owner);
        assert!(cooling_owner < watchdog_owner);
        assert!(watchdog_owner < psu_guard);
        assert!(service_spawn < fan_open);
        assert!(fan_open < fan_motion);
        assert!(fan_motion < power_start);
        assert!(bm1366_refusal < admission);

        assert!(source.contains("let mut runtime_threads = SerialRuntimeThreads::new();"));
        assert!(source.contains(".and_then(|owner| runtime_threads.activate_nopic(owner));"));
        assert!(source.contains(".and_then(|owner| runtime_threads.activate_am2(owner));"));
        assert!(source.contains("let reader_shutdown = match runtime_threads.cancellation_token()"));
        assert!(source.contains("runtime_threads.spawn_pic_heartbeat(||"));
        assert!(source.contains("runtime_threads.spawn_serial_io(thread_name"));
        let apw_reservation = [".reserve_am2(", "Am2SerialThreadSlot::ApwHeartbeat)?"].concat();
        assert!(source.contains(&apw_reservation));
        assert!(source.contains("AmlogicNoPicAdmission::detect("));
        assert!(source.contains(".spawn_power_thermal_service()"));
        assert!(source.contains(".read_board_temperatures("));
        let raw_temperature_helper = ["amlogic::read_board_", "temps("].concat();
        let generic_platform_open = ["amlogic::AmlogicPlatform::", "new()"].concat();
        assert!(!source.contains(&raw_temperature_helper));
        assert!(!source.contains(&generic_platform_open));
        assert!(source.contains("owner.latch_terminal_safe_off();"));
        assert!(source.contains(".close_and_join_until(management_fabric_deadline)"));
        assert!(source.contains("management_fabric: dcentrald_hal::i2c::I2cServiceCloseReceipt"));

        let runtime_fan_safety = source
            .find("let fan_safety_state = nopic_fan_safety.observe_required_airflow")
            .expect("runtime fan-safety observation");
        let runtime_safe_off = source[runtime_fan_safety..]
            .find("checked_nopic_emergency_safe_off_blocking(")
            .map(|offset| runtime_fan_safety + offset)
            .expect("runtime fan-safety checked safe-off");
        let watchdog_progress = source[runtime_fan_safety..]
            .find("nopic_watchdog_liveness.mark_progress()")
            .map(|offset| runtime_fan_safety + offset)
            .expect("NoPic watchdog liveness marker");
        assert!(runtime_fan_safety < runtime_safe_off);
        assert!(runtime_safe_off < watchdog_progress);

        let shutdown = source
            .split("info!(\"=== SHUTDOWN ===\");")
            .nth(1)
            .expect("serial shutdown section");
        let teardown_request = shutdown
            .find(".request_teardown_budget()")
            .expect("watchdog Teardown request");
        let first_stage_cut = shutdown
            .find("\"NoPic operator-stop first-stage safe-off\"")
            .expect("post-budget checked first-stage cutoff");
        let teardown_observe = shutdown
            .find(".observe_teardown_admission(admission, view)")
            .expect("post-cut watchdog Teardown acknowledgement wait");
        let serial_barrier = shutdown
            .find("validated NoPic serial runtime shutdown")
            .expect("NoPic serial execution barrier");
        let mutation_barrier = shutdown
            .find("\"serial runtime API\"")
            .expect("exact control-plane hardware mutation barrier");
        let actor_join = shutdown
            .find("let thread_stop = runtime_threads")
            .expect("serial actor join");
        let power_off = shutdown
            .find("\"NoPic checked operator-stop safe-off\"")
            .expect("checked NoPic safe-off");
        let quiet_fan = shutdown
            .find("fan.set_speed_checked")
            .expect("checked quiet fan command");
        let teardown_receipt = shutdown
            .find("let teardown_receipt = exact_cutoff_timing_result")
            .expect("same-budget exact teardown receipt");
        let teardown_disarm = shutdown
            .find(".begin_disarm_at(Instant::now())?")
            .expect("same-budget disarm authority");
        let manifest = shutdown
            .find("NoPicWatchdogShutdownManifest::new")
            .expect("exact NoPic shutdown manifest");
        let permit = shutdown
            .find("WatchdogDisarmPermit::from_nopic_manifest")
            .expect("typed watchdog disarm permit");
        let disarm = shutdown
            .find(".disarm_and_join")
            .expect("watchdog close and join");
        let persistence = shutdown
            .find("history_buffer.save")
            .expect("noncritical history persistence");
        assert!(teardown_request < first_stage_cut);
        assert!(first_stage_cut < teardown_observe);
        assert!(teardown_observe < serial_barrier);
        assert!(serial_barrier < mutation_barrier);
        assert!(mutation_barrier < actor_join);
        assert!(actor_join < power_off);
        assert!(power_off < quiet_fan);
        assert!(quiet_fan < teardown_receipt);
        assert!(teardown_receipt < teardown_disarm);
        assert!(teardown_disarm < manifest);
        assert!(manifest < permit);
        assert!(permit < disarm);
        assert!(disarm < persistence);
    }

    #[test]
    fn bm1366_experimental_opt_in_admits_only_the_exact_env_value() {
        assert!(SerialMiner::experimental_native_bm1366_opt_in_from(Some(
            "1"
        )));
        // Everything else stays refused. The failure direction of a loose parse
        // is granting an experimental hardware path nobody asked for, so even
        // clearly-truthy spellings must not opt in.
        for refused in [
            None,
            Some(""),
            Some("0"),
            Some("true"),
            Some("TRUE"),
            Some("yes"),
            Some("on"),
            Some(" 1"),
            Some("1 "),
            Some("01"),
        ] {
            assert!(
                !SerialMiner::experimental_native_bm1366_opt_in_from(refused),
                "{refused:?} must not opt in to experimental native BM1366"
            );
        }
    }

    #[test]
    fn bm1366_experimental_admission_consumes_the_real_opt_in_and_observed_identity() {
        let source = include_str!("serial_mining.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production serial-mining source");

        // The environment half must read the shared api-types const rather than
        // a private re-spelling that could silently drift from it.
        assert!(source.contains("EXPERIMENTAL_NATIVE_BM1366_ENV"));

        let admission = source
            .find("match admit_native_experimental(")
            .expect("BM1366 experimental admission call site");
        let call_end = source[admission..]
            .find(") {")
            .map(|offset| admission + offset)
            .expect("end of the admission argument list");
        let args = &source[admission..call_end];

        // The load-bearing argument. A hardcoded `true` here would make the
        // operator opt-in decorative and admit on decoded evidence alone â€” and
        // no test that called `admit_native_experimental` directly with its own
        // literal could ever observe that, which is exactly how a capability
        // went test-only-reachable in this file before.
        assert!(
            args.contains("bm1366_experimental_opt_in"),
            "admission must consume the real opt-in: {args}"
        );
        assert!(
            !args.contains("true"),
            "the experimental opt-in must never be hardcoded: {args}"
        );
        assert!(
            args.contains("observed"),
            "admission must consume an independently observed identity: {args}"
        );
        assert!(
            args.contains("AsicProtocolIdentity::Bm1366"),
            "the required protocol must stay exact: {args}"
        );

        // Admission is a decision layer, not an enablement. It must consume
        // pages the energize gate already retained rather than opening
        // anything, and the transport backstop below must still refuse, so
        // this stays observable-but-inert.
        assert!(
            source.contains("fold_observed_identity_from_retained_pages(&retained_eeprom_bytes)")
        );
        assert!(source.contains("non-passthrough BM1366 is refused before"));
    }

    #[test]
    fn bm1366_native_route_fails_closed_before_optional_hardware_observation() {
        let source = include_str!("serial_mining.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production serial-mining source");
        let identity = source
            .find("let is_bm1366 = resolved_chip_id == 0x1366;")
            .expect("BM1366 catalog identity boundary");
        let refusal = source[identity..]
            .find("if is_bm1366 && !passthrough")
            .map(|offset| identity + offset)
            .expect("BM1366 native refusal");
        let optional_observation = source[identity..]
            .find("let nopic = is_nopic(&self.config);")
            .map(|offset| identity + offset)
            .expect("optional EEPROM-backed NoPic observation");
        assert!(refusal < optional_observation);
        let gate = &source[refusal..optional_observation];
        assert!(gate.contains("NOT IMPLEMENTED"));
        assert!(gate.contains("BHB56902 EEPROM evidence [05,11]"));
        assert!(gate.contains("must not authorize controller, voltage, or ASIC mutation"));

        // Refusal-before-observation, enforced not just ordered: nothing
        // between run() entry and the optional NoPic observation may touch
        // EEPROM, the filesystem, or I2C. `source` is already sliced to the
        // production region, so these tokens cannot be satisfied or tripped
        // by this contract's own text.
        let run_prefix = source
            .find("pub async fn run(&mut self)")
            .expect("serial run entrypoint");
        assert!(run_prefix < identity);
        let pre_refusal = &source[run_prefix..optional_observation];
        for forbidden in [
            "read_hashboard_eeprom",
            "std::fs::read",
            "i2c",
            "I2cServiceHandle",
        ] {
            assert!(
                !pre_refusal.contains(forbidden),
                "pre-refusal window gained a hardware observation: {forbidden}"
            );
        }

        let transport_chain = source
            .find("let serial = if passthrough {")
            .expect("serial transport branch chain");
        assert_eq!(
            source.matches("let serial = if passthrough {").count(),
            1,
            "serial transport chain anchor is no longer unique; re-anchor this contract"
        );
        let branch_end = source[transport_chain..]
            .find("} else if is_bm1368 || is_bm1370 {")
            .map(|offset| transport_chain + offset)
            .expect("end of BM1366 transport branch");
        assert_eq!(
            source[transport_chain..branch_end]
                .matches("} else if is_bm1366 {")
                .count(),
            1,
            "BM1366 transport-arm anchor must appear exactly once inside the transport chain"
        );
        let branch_start = source[transport_chain..branch_end]
            .find("} else if is_bm1366 {")
            .map(|offset| transport_chain + offset)
            .expect("BM1366 transport branch inside the serial transport chain");
        let branch = &source[branch_start..branch_end];
        assert_eq!(
            branch.matches("} else if ").count(),
            1,
            "BM1366 transport-arm window re-anchored; it must span exactly one arm"
        );
        assert!(branch.contains("anyhow::bail!"));
        assert!(branch.contains("non-passthrough BM1366 is refused before hardware observation"));
        assert!(!branch.contains("unreachable!"));
        assert!(!branch.contains("cold_boot_init"));
        assert!(!branch.contains("init_bm1366_chain"));
        // The refusal arm itself must stay side-effect-free.
        for forbidden in [
            "read_hashboard_eeprom",
            "std::fs::read",
            "i2c",
            "I2cServiceHandle",
        ] {
            assert!(
                !branch.contains(forbidden),
                "BM1366 refusal arm gained a hardware observation: {forbidden}"
            );
        }
        assert!(!source.contains("pending_bhb56_endpoints"));
        assert!(!source.contains("legacy_dspic_sessions"));
    }

    #[test]
    fn bm1398_native_route_fails_closed_before_optional_hardware_observation() {
        let source = include_str!("serial_mining.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production serial mining source");
        let identity = production
            .find("let is_bm1398 = resolved_chip_id == 0x1398;")
            .expect("BM1398 catalog identity boundary");
        let refusal = production[identity..]
            .find("if is_bm1398 && !passthrough")
            .map(|offset| identity + offset)
            .expect("BM1398 native refusal");
        let optional_observation = production[identity..]
            .find("let nopic = is_nopic(&self.config);")
            .map(|offset| identity + offset)
            .expect("optional EEPROM-backed NoPic observation");
        assert!(refusal < optional_observation);
        let first_construction = production[refusal..]
            .find("let mut runtime_dispatch_admission")
            .map(|offset| refusal + offset)
            .expect("first post-identity runtime construction");
        let gate = &production[refusal..first_construction];
        assert!(gate.contains("NOT IMPLEMENTED"));
        assert!(gate.contains("BHB42 EEPROM preamble [04,11] identifies BM1362"));
        assert!(gate.contains("must not authorize BM1398 voltage or ASIC mutation"));

        // Refusal-before-observation, enforced not just ordered: nothing
        // between run() entry and the optional NoPic observation may touch
        // EEPROM, the filesystem, or I2C. `production` excludes this test
        // module, so these tokens cannot be satisfied or tripped by this
        // contract's own text.
        let run_prefix = production
            .find("pub async fn run(&mut self)")
            .expect("serial run entrypoint");
        assert!(run_prefix < identity);
        let pre_refusal = &production[run_prefix..optional_observation];
        for forbidden in [
            "read_hashboard_eeprom",
            "std::fs::read",
            "i2c",
            "I2cServiceHandle",
        ] {
            assert!(
                !pre_refusal.contains(forbidden),
                "pre-refusal window gained a hardware observation: {forbidden}"
            );
        }

        assert_eq!(
            production.matches("} else if is_bm1398 {").count(),
            1,
            "BM1398 transport-arm anchor is no longer unique; re-anchor this contract"
        );
        let branch_start = production
            .find("} else if is_bm1398 {")
            .expect("BM1398 transport branch");
        let branch_end = production[branch_start..]
            .find("} else if is_bm1366 {")
            .map(|offset| branch_start + offset)
            .expect("BM1398 transport branch boundary");
        let branch = &production[branch_start..branch_end];
        assert_eq!(
            branch.matches("} else if ").count(),
            1,
            "BM1398 transport-arm window re-anchored; it must span exactly one arm"
        );
        assert!(branch.contains("anyhow::bail!"));
        assert!(branch.contains("non-passthrough BM1398 is refused before hardware construction"));
        assert!(!branch.contains("unreachable!"));
        assert!(!branch.contains("cold_boot_init"));
        assert!(!branch.contains("init_bm1398_chain"));
        assert!(!branch.contains("/dev/ttyS4"));
        // The refusal arm itself must stay side-effect-free.
        for forbidden in [
            "read_hashboard_eeprom",
            "std::fs::read",
            "i2c",
            "I2cServiceHandle",
        ] {
            assert!(
                !branch.contains(forbidden),
                "BM1398 refusal arm gained a hardware observation: {forbidden}"
            );
        }
        assert!(!production.contains("pending_bm1398_presences"));
    }

    #[test]
    fn exact_am2_bm1362_init_uses_constructor_plan_and_retained_observations() {
        let source = include_str!("serial_mining.rs");
        let capture_start = source
            .find("impl Am2Bm1362DirectSerialAdmission")
            .expect("exact route constructor");
        let capture_end = source[capture_start..]
            .find("pub struct SerialMiner")
            .map(|offset| capture_start + offset)
            .expect("exact route constructor boundary");
        let capture = &source[capture_start..capture_end];
        let discover = ["discover_system_am2_", "controller_plan"].concat();
        assert!(capture.contains(&discover));

        let get_version_call = [
            "Self::pic_read_fw_version_service",
            "(i2c_service, pic_addr)",
        ]
        .concat();
        assert_eq!(
            source.matches(&get_version_call).count(),
            1,
            "AM2 endpoint binding must not add a second GET_VERSION transaction"
        );

        let branch_start = source
            .find("let (detected_fw, detected_fw_reply)")
            .expect("existing BM1362 firmware observation");
        let branch_end = source[branch_start..]
            .find("observation.observe_preserve_state(pic_addr)?;")
            .map(|offset| branch_start + offset)
            .expect("BM1362 post-enable proof boundary");
        let branch = &source[branch_start..branch_end];
        assert_eq!(
            branch.matches(&discover).count(),
            0,
            "the exact BM1362 branch must consume the constructor-captured plan, never rediscover controller identity"
        );
        assert!(branch.contains("route.controller_plan()"));
        assert!(branch.contains("retained_eeprom_bytes"));
        assert!(branch.contains("bind_am2_hashboard_presence("));
        assert!(branch.contains("bind_am2_controller_endpoint_from_observation("));
        assert!(branch.contains("&detected_fw_reply"));
        assert!(branch.contains("Pic0x89EndpointSession::new"));
        assert!(branch.contains("refusing raw-address fallback"));
        assert!(!branch.contains("Pic0x89Service::new_with_fw"));
        assert!(!branch.contains("DspicService::new("));
    }

    #[tokio::test]
    async fn am2_bringup_wait_is_immediately_cancellation_aware() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let started = Instant::now();
        let error =
            wait_am2_bringup_active(&shutdown, Duration::from_secs(30), "scripted stabilization")
                .await
                .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(error.to_string().contains("scripted stabilization"));
    }

    #[tokio::test]
    async fn am2_apw_stabilization_observes_terminal_exit_before_hardware_bringup_continues() {
        let shutdown = CancellationToken::new();
        let (terminal_tx, mut terminal_rx) = mpsc::unbounded_channel();
        let progress = AtomicU64::new(0);
        assert!(publish_am2_apw_heartbeat_terminal(
            &shutdown,
            &terminal_tx,
            "typed controller authority was superseded".to_string(),
        ));
        drop(terminal_tx);

        let started = Instant::now();
        let error = wait_am2_apw_heartbeat_stable(
            &shutdown,
            &mut terminal_rx,
            &progress,
            Duration::from_secs(30),
            "scripted APW stabilization",
        )
        .await
        .unwrap_err();

        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(shutdown.is_cancelled());
        assert!(error.to_string().contains("typed controller authority"));
        assert!(error.to_string().contains("scripted APW stabilization"));
    }

    #[tokio::test]
    async fn am2_apw_stabilization_closed_channel_preserves_ordinary_shutdown() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let (terminal_tx, mut terminal_rx) = mpsc::unbounded_channel::<String>();
        drop(terminal_tx);
        let progress = AtomicU64::new(0);

        let started = Instant::now();
        let error = wait_am2_apw_heartbeat_stable(
            &shutdown,
            &mut terminal_rx,
            &progress,
            Duration::from_secs(30),
            "scripted ordinary shutdown",
        )
        .await
        .unwrap_err();

        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(error.to_string().contains("shutdown requested"));
        assert!(error.to_string().contains("scripted ordinary shutdown"));
        assert!(!error.to_string().contains("actor exited"));
    }

    #[tokio::test]
    async fn am2_apw_stabilization_timer_boundary_preserves_shutdown_attribution() {
        let shutdown = CancellationToken::new();
        let (_terminal_tx, mut terminal_rx) = mpsc::unbounded_channel::<String>();
        let progress = AtomicU64::new(0);

        let error = wait_am2_apw_heartbeat_stable_with_post_wait(
            &shutdown,
            &mut terminal_rx,
            &progress,
            Duration::ZERO,
            "scripted timer-boundary shutdown",
            || shutdown.cancel(),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("shutdown requested"));
        assert!(error
            .to_string()
            .contains("scripted timer-boundary shutdown"));
        assert!(!error.to_string().contains("no successful progress"));
    }

    #[test]
    fn am2_apw_terminal_publication_does_not_relabel_ordinary_shutdown() {
        let lifecycle_shutdown = CancellationToken::new();
        lifecycle_shutdown.cancel();
        let (terminal_tx, mut terminal_rx) = mpsc::unbounded_channel();

        assert!(!publish_am2_apw_heartbeat_terminal(
            &lifecycle_shutdown,
            &terminal_tx,
            "in-flight heartbeat completed after operator shutdown".to_string(),
        ));
        assert!(matches!(
            terminal_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn am2_apw_actor_unexpected_exit_cancels_lifecycle_and_publishes_reason() {
        let runtime_shutdown = CancellationToken::new();
        let lifecycle_shutdown = CancellationToken::new();
        let (terminal_tx, mut terminal_rx) = mpsc::unbounded_channel();
        {
            let _guard = Am2ApwHeartbeatActorExitGuard {
                runtime_shutdown,
                lifecycle_shutdown: lifecycle_shutdown.clone(),
                terminal_exit: terminal_tx,
            };
        }

        assert!(lifecycle_shutdown.is_cancelled());
        assert!(terminal_rx
            .try_recv()
            .unwrap()
            .contains("exited unexpectedly"));
    }

    #[tokio::test]
    async fn am2_apw_stabilization_requires_live_actor_and_successful_progress() {
        let shutdown = CancellationToken::new();
        let (terminal_tx, mut terminal_rx) = mpsc::unbounded_channel::<String>();
        let progress = Arc::new(AtomicU64::new(0));
        let progress_worker = progress.clone();
        let updater = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            progress_worker.fetch_add(1, Ordering::Release);
        });

        wait_am2_apw_heartbeat_stable(
            &shutdown,
            &mut terminal_rx,
            &progress,
            Duration::from_millis(50),
            "scripted successful APW stabilization",
        )
        .await
        .unwrap();
        updater.await.unwrap();

        drop(terminal_tx);
        let (closed_tx, mut closed_rx) = mpsc::unbounded_channel::<String>();
        drop(closed_tx);
        let error = wait_am2_apw_heartbeat_stable(
            &shutdown,
            &mut closed_rx,
            &AtomicU64::new(0),
            Duration::from_secs(30),
            "scripted closed APW actor",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("without a terminal receipt"));
    }

    #[test]
    fn exact_am2_bringup_validates_before_consuming_power_boundary_authority() {
        let source = include_str!("serial_mining.rs");
        let start = source
            .find("let bm1362_bringup_result: Result<SerialWorkTransport> = async")
            .expect("scoped exact BM1362 bring-up transaction");
        let end = source[start..]
            .find("match bm1362_bringup_result")
            .map(|offset| start + offset)
            .expect("scoped bring-up closeout boundary");
        let bringup = &source[start..end];

        assert!(!bringup.contains("std::thread::sleep"));
        assert!(bringup.matches("wait_am2_bringup_active(").count() >= 2);
        assert_eq!(
            bringup.matches("wait_am2_apw_heartbeat_stable(").count(),
            2,
            "both exact APW transports must observe actor exit and successful progress during stabilization"
        );
        assert_eq!(
            bringup
                .matches("drop(am2_apw_heartbeat_exit_tx.take())")
                .count(),
            2,
            "the heartbeat worker must be the sole exit sender before either stabilization wait"
        );
        assert!(bringup.matches("require_am2_bringup_active(").count() >= 12);
        let cancellation_fence = bringup
            .find("before PWR_CONTROL assertion")
            .expect("pre-energization cancellation fence");
        let bypass_classification = bringup
            .find("am2_power.admit_apw_bypass")
            .expect("fallible bypass applicability classification");
        let authority_consumption = bringup
            .find("let boundary = am2_never_energized.take()")
            .expect("never-energized authority consumption");
        let first_gpio_assertion = bringup
            .find("assert_am2_psu_gpio_after_energizing_boundary")
            .expect("first token-consuming PWR_CONTROL mutation");
        assert!(cancellation_fence < authority_consumption);
        assert!(bypass_classification < authority_consumption);
        assert!(authority_consumption < first_gpio_assertion);
        assert!(!bringup.contains("PsuGpioGate::assert"));
    }

    #[test]
    fn am2_cancellation_refuses_every_subsequent_validated_serial_commit() {
        let shutdown = CancellationToken::new();
        let cancellation = Am2EnergizedSerialCancellation {
            shutdown: shutdown.clone(),
        };
        let committed = AtomicU64::new(0);

        cancellation.require_active("first scripted write").unwrap();
        committed.fetch_add(1, Ordering::SeqCst);
        shutdown.cancel();
        let error = cancellation
            .require_active("second scripted write")
            .unwrap_err();
        if cancellation.require_active("third scripted write").is_ok() {
            committed.fetch_add(1, Ordering::SeqCst);
        }

        assert_eq!(committed.load(Ordering::SeqCst), 1);
        assert!(error.to_string().contains("refusing subsequent"));

        let source = include_str!("serial_mining.rs");
        let backend_start = source.find("impl ValidatedSerialBackend {").unwrap();
        let backend_end = source[backend_start..]
            .find("enum SerialWorkTransport")
            .map(|offset| backend_start + offset)
            .unwrap();
        let backend = &source[backend_start..backend_end];
        assert_eq!(backend.matches("self.execution").count(), 1);
        // Directly commit-fenced operations keep their literal labels at the
        // fence call.
        for operation in [
            "serial response flush",
            "serial response window read",
            "serial host baud transition",
            "serial mining work send",
            "serial nonce response read",
        ] {
            assert!(backend.contains(&format!("self.commit(\"{operation}\"")));
        }
        // P1-3: BM1397+ command labels funnel through the shared
        // `execute_bm1397plus_op(operation, op)` façade, whose body is the
        // single `self.commit(operation, …)` fence entry. Every label must
        // still appear in the backend impl so cancellation refuses each one.
        assert!(backend.contains("fn execute_bm1397plus_op"));
        assert!(backend.contains("self.commit(operation"));
        for operation in [
            "serial GetAddress query",
            "serial ChainInactive",
            "serial SetAddress",
            "serial broadcast register write",
            "serial addressed register write",
        ] {
            assert!(backend.contains(&format!("\"{operation}\"")));
        }
    }

    #[test]
    fn nopic_family_classifier_matches_profile_table() {
        // BM1368 / BM1370 / BM1373 are the NoPic families; the PIC families
        // are not. Mirrors dcentrald-asic PicType + model.rs pic_type_hint.
        assert!(serial_chip_id_is_nopic_family(0x1368));
        assert!(serial_chip_id_is_nopic_family(0x1370));
        assert!(serial_chip_id_is_nopic_family(0x1373));
        assert!(!serial_chip_id_is_nopic_family(0x1362));
        assert!(!serial_chip_id_is_nopic_family(0x1366));
        assert!(!serial_chip_id_is_nopic_family(0x1398));
        assert!(!serial_chip_id_is_nopic_family(0x1387));
    }

    #[test]
    fn bm1370_and_bm1368_chip_ids_are_distinct_in_discriminator() {
        // Regression pin: the two NoPic S21-class dies must never collapse to
        // the same chip-id in the serial discriminator (the register-0x00
        // CHIP_ID truth 0x13700000 vs 0x13680000).
        let bm1370 = resolve_serial_chip_id(Some("s21pro"), 65, true).unwrap();
        let bm1368 = resolve_serial_chip_id(Some("s21"), 108, true).unwrap();
        assert_ne!(bm1370, bm1368);
        assert_eq!(bm1370, 0x1370);
        assert_eq!(bm1368, 0x1368);
    }

    /// VNish-RE'd 7-byte ENABLE/DISABLE_VOLTAGE form for fw=0x86/0x89 PICs.
    /// Source: .
    /// Mirrors the byte-exact assertion in `dcentrald-asic/src/dspic.rs`.
    #[test]
    fn pic_enable_cmd_vnish_byte_exact() {
        // ENABLE: [55 AA 05 15 01 00 1B] â€” SUM = (0x05+0x15+0x01+0x00) = 0x1B
        assert_eq!(
            pic_enable_cmd_vnish(0x01),
            [0x55, 0xAA, 0x05, 0x15, 0x01, 0x00, 0x1B]
        );
        // DISABLE: [55 AA 05 15 00 00 1A] â€” SUM = (0x05+0x15+0x00+0x00) = 0x1A
        assert_eq!(
            pic_enable_cmd_vnish(0x00),
            [0x55, 0xAA, 0x05, 0x15, 0x00, 0x00, 0x1A]
        );
    }
}

#[cfg(test)]
mod work_dispatch_admission_tests {
    //! Drive the shipped serial admission adapters through the real
    //! `WorkDispatchLifecycle` path - not a reimplementation.

    use super::*;
    use dcentrald_common::{power_precedes_fan_raise, SafetyStep, HOME_FAN_PWM_SAFETY_MAX};

    #[test]
    fn serial_watchdog_state_maps_ownership() {
        assert_eq!(
            serial_watchdog_safety_state(false, false),
            WatchdogSafetyState::DisabledByConfiguration
        );
        assert_eq!(
            serial_watchdog_safety_state(true, true),
            WatchdogSafetyState::Armed
        );
        assert_eq!(
            serial_watchdog_safety_state(true, false),
            WatchdogSafetyState::Unavailable
        );
    }

    #[test]
    fn serial_heartbeat_nopic_and_passthrough_require_none() {
        let (req, obs) = serial_heartbeat_inputs(true, false, Some(0x20), true, 1);
        assert_eq!(req, HeartbeatRequirement::NoneRequired);
        assert!(obs.is_empty());
        let (req, obs) = serial_heartbeat_inputs(false, true, None, true, 1);
        assert_eq!(req, HeartbeatRequirement::NoneRequired);
        assert!(obs.is_empty());
    }

    #[test]
    fn serial_admit_green_succeeds() {
        let mut life = WorkDispatchLifecycle::new();
        let (req, obs) = serial_heartbeat_inputs(false, false, Some(0x20), true, 3);
        let inputs = serial_work_dispatch_inputs(
            serial_watchdog_safety_state(true, true),
            req,
            &obs,
            ThermalSafetyState::Ready,
        );
        let receipt = serial_admit_standard_work_dispatch(&mut life, &inputs).expect("admit");
        assert_eq!(receipt.controller_count, 1);
        assert_eq!(receipt.heartbeat_cycle_id, Some(3));
        assert!(life.is_admitted());
    }

    #[test]
    fn serial_admit_refuses_failed_dspic_heartbeat() {
        let mut life = WorkDispatchLifecycle::new();
        let (req, obs) = serial_heartbeat_inputs(false, false, Some(0x22), false, 1);
        let inputs = serial_work_dispatch_inputs(
            WatchdogSafetyState::Armed,
            req,
            &obs,
            ThermalSafetyState::Ready,
        );
        let err = serial_admit_standard_work_dispatch(&mut life, &inputs).unwrap_err();
        assert!(matches!(
            err,
            WorkDispatchSafetyError::HeartbeatFailed {
                controller_id: 0x22,
                ..
            }
        ));
        assert!(!life.is_admitted());
    }

    #[test]
    fn serial_admit_refuses_watchdog_unavailable() {
        let mut life = WorkDispatchLifecycle::new();
        let (req, obs) = serial_heartbeat_inputs(false, true, None, true, 1);
        let inputs = serial_work_dispatch_inputs(
            serial_watchdog_safety_state(true, false),
            req,
            &obs,
            ThermalSafetyState::Ready,
        );
        let err = serial_admit_standard_work_dispatch(&mut life, &inputs).unwrap_err();
        assert!(matches!(
            err,
            WorkDispatchSafetyError::WatchdogNotAdmitted {
                state: WatchdogSafetyState::Unavailable
            }
        ));
    }

    #[test]
    fn serial_terminal_revoke_blocks_re_admit_until_teardown() {
        let mut life = WorkDispatchLifecycle::new();
        let (req, obs) = serial_heartbeat_inputs(false, false, Some(0x20), true, 1);
        let inputs = serial_work_dispatch_inputs(
            WatchdogSafetyState::Armed,
            req,
            &obs,
            ThermalSafetyState::Ready,
        );
        serial_admit_standard_work_dispatch(&mut life, &inputs).expect("admit");
        let (action, stop_feed) =
            serial_revoke_work_dispatch(&mut life, DispatchRevocationCause::HeartbeatFailure, 100);
        assert!(stop_feed);
        assert!(power_precedes_fan_raise(&action.steps()));
        match &action.steps()[1] {
            SafetyStep::CommandFans(fan) => {
                assert!(fan.effective_pwm() <= HOME_FAN_PWM_SAFETY_MAX);
            }
            other => panic!("expected fan park second, got {other:?}"),
        }
        let err = serial_admit_standard_work_dispatch(&mut life, &inputs).unwrap_err();
        assert_eq!(err, WorkDispatchSafetyError::TerminallyRevoked);
        life.reset_after_full_teardown();
        serial_admit_standard_work_dispatch(&mut life, &inputs).expect("re-admit after teardown");
    }

    #[test]
    fn serial_run_owns_lifecycle_and_calls_shipped_adapters() {
        let src = include_str!("serial_mining.rs");
        assert!(
            src.contains("WorkDispatchLifecycle::new()"),
            "serial run must own a WorkDispatchLifecycle"
        );
        assert!(
            src.contains("serial_admit_standard_work_dispatch"),
            "run must call the shipped serial admit adapter"
        );
        assert!(
            src.contains("serial_revoke_and_stop_watchdog_feed"),
            "run must call the shipped serial revoke+stop_feed adapter"
        );
        assert!(
            src.contains("close_terminal_lock_free()"),
            "serial mid-run revoke must stop SoC WDT feed"
        );
        assert!(
            src.contains("thermal_proof_present"),
            "serial admit must not invent thermal Ready"
        );
        assert!(
            src.contains("DispatchRevocationCause::HeartbeatFailure"),
            "PIC/APW HB failure must terminal-revoke via HeartbeatFailure"
        );
        assert!(
            src.contains("DispatchRevocationCause::ThermalCutoff"),
            "thermal trip must revoke via ThermalCutoff"
        );
        assert!(
            src.contains("DispatchRevocationCause::OperatorSafeOff"),
            "operator shutdown must revoke via OperatorSafeOff"
        );
        assert!(
            src.contains("if !dispatch_life.is_admitted()"),
            "dispatch must gate UART work on live admission"
        );
    }
}
