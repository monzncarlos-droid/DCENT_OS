// SPDX-License-Identifier: GPL-3.0-or-later
//
// Nano 3 hardware-custody admission state machine.
//
// This module is deliberately pure: it opens no device, stops no process and
// commands no actuator.  The runtime must obtain each observation from the
// appropriate process/device/safety owner and submit it here in order.  Keeping
// admission separate from I/O makes the dangerous property easy to test:
// DCENT never claims the Nano 3 merely because btcminer stopped or work
// dispatch ceased.

use std::fmt;

use crate::nano3_safety::Nano3SafetySnapshot;

// One source of truth with the explicit identity-only profile. Re-export the
// historical ownership names so the custody machine and its callers retain a
// stable API while profile resolution remains non-authorizing.
pub use dcent_avalon_proto::nano3_profile::{
    NANO3_CHAIN_UART, NANO3_REQUIRED_ASIC_COUNT as NANO3_ASIC_COUNT,
};

/// Monotonic ownership/admission stages.
///
/// `FaultAwaitingHashCut` and `FaultContained` are terminal for this machine.
/// Recovery must construct a fresh machine only after the outer supervisor has
/// re-established the initial stock-owned condition.  This prevents a fault
/// acknowledgement from silently regaining mining authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipState {
    StockOwned,
    StockQuiesced,
    StockFileDescriptorsReleased,
    CoolingHeld,
    SensorsHeld,
    WatchdogHeld,
    HashPowerOffProven,
    UartExclusive,
    Nano3Detected,
    DcentOwnedSafeIdle,
    Mining,
    FaultAwaitingHashCut,
    FaultContained,
}

impl OwnershipState {
    /// Whether the state authorizes sending mining work.
    pub const fn may_dispatch_work(self) -> bool {
        matches!(self, Self::Mining)
    }

    /// Whether DCENT has completed the custody proof.
    ///
    /// A contained fault intentionally returns false even though some resources
    /// may still be held: containment is not operating authority.
    pub const fn has_dcent_custody(self) -> bool {
        matches!(self, Self::DcentOwnedSafeIdle | Self::Mining)
    }

    /// Whether the supervisor must independently confirm that hash power is
    /// off before it may call the fault contained.
    pub const fn requires_hash_cut_confirmation(self) -> bool {
        matches!(self, Self::FaultAwaitingHashCut)
    }
}

/// Positive observations consumed by the custody machine.
///
/// Boolean fields are intentionally explicit.  A caller cannot accidentally
/// turn "we attempted the operation" into "the required result was observed".
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CustodyEvent<'a> {
    StockQuiesced {
        process_absent: bool,
        automatic_restart_inhibited: bool,
    },
    StockFileDescriptorsReleased {
        all_hardware_fds_released: bool,
    },
    CoolingHeld {
        actuator_exclusive: bool,
        feedback_valid: bool,
    },
    SensorsHeld {
        temperature_fresh: bool,
        sensor_loss_trip_armed: bool,
    },
    WatchdogHeld {
        owner_exclusive: bool,
        expiry_path_verified: bool,
    },
    HashPowerOffProven {
        independently_observed: bool,
    },
    UartExclusive {
        device: &'a str,
        exclusive_claim: bool,
    },
    AsicsDetected {
        count: u8,
        nano3_identity_confirmed: bool,
    },
    AdmitSafeIdle,
    StartMining {
        /// Complete same-iteration Nano 3 observation.  This is evaluated at
        /// the transition; earlier boolean custody claims cannot substitute
        /// for fresh fan, thermal, heartbeat, watchdog, and cut evidence.
        safety_snapshot: &'a Nano3SafetySnapshot,
        fresh_work_available: bool,
    },
    /// Stopping work is not a hash-power cut.  From `Mining`, this enters the
    /// fault path and still requires independent cut confirmation.
    WorkDispatchStopped,
    HashCutConfirmedAfterFault {
        independently_observed: bool,
    },
}

impl CustodyEvent<'_> {
    const fn name(self) -> &'static str {
        match self {
            Self::StockQuiesced { .. } => "stock-quiesced",
            Self::StockFileDescriptorsReleased { .. } => "stock-fds-released",
            Self::CoolingHeld { .. } => "cooling-held",
            Self::SensorsHeld { .. } => "sensors-held",
            Self::WatchdogHeld { .. } => "watchdog-held",
            Self::HashPowerOffProven { .. } => "hash-power-off-proven",
            Self::UartExclusive { .. } => "uart-exclusive",
            Self::AsicsDetected { .. } => "asics-detected",
            Self::AdmitSafeIdle => "admit-safe-idle",
            Self::StartMining { .. } => "start-mining",
            Self::WorkDispatchStopped => "work-dispatch-stopped",
            Self::HashCutConfirmedAfterFault { .. } => "fault-hash-cut-confirmed",
        }
    }
}

/// Fault causes retained for diagnostics.  A cause never grants a recovery
/// transition by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyFault {
    UartLost,
    SensorLost,
    FanFeedbackLost,
    WatchdogCustodyLost,
    SafetySupervisorLost,
    HardwareIdentityChanged,
    WorkDispatchStoppedWithoutHashCut,
    Other(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyError {
    OutOfOrder {
        state: OwnershipState,
        event: &'static str,
    },
    MissingEvidence(&'static str),
    WrongUartDevice {
        observed: String,
    },
    WrongAsicCount {
        observed: u8,
        required: u8,
    },
    FaultAlreadyLatched,
}

impl fmt::Display for CustodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfOrder { state, event } => {
                write!(f, "event {event} is not admitted from {state:?}")
            }
            Self::MissingEvidence(evidence) => write!(f, "missing evidence: {evidence}"),
            Self::WrongUartDevice { observed } => write!(
                f,
                "Nano 3 chain UART must be {NANO3_CHAIN_UART}, observed {observed}"
            ),
            Self::WrongAsicCount { observed, required } => write!(
                f,
                "Nano 3 detect must report exactly {required} ASICs, observed {observed}"
            ),
            Self::FaultAlreadyLatched => write!(f, "hardware-custody fault is already latched"),
        }
    }
}

impl std::error::Error for CustodyError {}

/// Pure admission ledger for one uninterrupted ownership attempt.
#[derive(Debug, Clone)]
pub struct Nano3HardwareCustody {
    state: OwnershipState,
    fault: Option<CustodyFault>,
}

impl Default for Nano3HardwareCustody {
    fn default() -> Self {
        Self::new()
    }
}

impl Nano3HardwareCustody {
    pub const fn new() -> Self {
        Self {
            state: OwnershipState::StockOwned,
            fault: None,
        }
    }

    pub const fn state(&self) -> OwnershipState {
        self.state
    }

    pub const fn fault(&self) -> Option<CustodyFault> {
        self.fault
    }

    /// Latch a runtime fault from any non-fault state.
    ///
    /// Even a fault from `DcentOwnedSafeIdle` requires a new, independent hash
    /// cut observation.  Historical evidence from the normal admission path is
    /// not reused after a fault because the fault may itself invalidate it.
    pub fn latch_fault(&mut self, fault: CustodyFault) -> Result<OwnershipState, CustodyError> {
        if matches!(
            self.state,
            OwnershipState::FaultAwaitingHashCut | OwnershipState::FaultContained
        ) {
            return Err(CustodyError::FaultAlreadyLatched);
        }
        self.fault = Some(fault);
        self.state = OwnershipState::FaultAwaitingHashCut;
        Ok(self.state)
    }

    /// Apply one positive custody observation.
    ///
    /// Failed validation leaves the state unchanged.  There are no transition
    /// shortcuts: every stage in the custody proof must occur exactly once and
    /// in order.
    pub fn apply(&mut self, event: CustodyEvent<'_>) -> Result<OwnershipState, CustodyError> {
        let next = match (self.state, event) {
            (
                OwnershipState::StockOwned,
                CustodyEvent::StockQuiesced {
                    process_absent,
                    automatic_restart_inhibited,
                },
            ) => {
                require(process_absent, "stock btcminer process is absent")?;
                require(
                    automatic_restart_inhibited,
                    "stock btcminer automatic restart is inhibited",
                )?;
                OwnershipState::StockQuiesced
            }
            (
                OwnershipState::StockQuiesced,
                CustodyEvent::StockFileDescriptorsReleased {
                    all_hardware_fds_released,
                },
            ) => {
                require(
                    all_hardware_fds_released,
                    "stock hardware file descriptors are released",
                )?;
                OwnershipState::StockFileDescriptorsReleased
            }
            (
                OwnershipState::StockFileDescriptorsReleased,
                CustodyEvent::CoolingHeld {
                    actuator_exclusive,
                    feedback_valid,
                },
            ) => {
                require(actuator_exclusive, "cooling actuator is exclusively held")?;
                require(feedback_valid, "cooling feedback is valid")?;
                OwnershipState::CoolingHeld
            }
            (
                OwnershipState::CoolingHeld,
                CustodyEvent::SensorsHeld {
                    temperature_fresh,
                    sensor_loss_trip_armed,
                },
            ) => {
                require(temperature_fresh, "temperature telemetry is fresh")?;
                require(sensor_loss_trip_armed, "sensor-loss hash cut is armed")?;
                OwnershipState::SensorsHeld
            }
            (
                OwnershipState::SensorsHeld,
                CustodyEvent::WatchdogHeld {
                    owner_exclusive,
                    expiry_path_verified,
                },
            ) => {
                require(owner_exclusive, "watchdog ownership is exclusive")?;
                require(
                    expiry_path_verified,
                    "watchdog expiry reaches the verified fail-safe path",
                )?;
                OwnershipState::WatchdogHeld
            }
            (
                OwnershipState::WatchdogHeld,
                CustodyEvent::HashPowerOffProven {
                    independently_observed,
                },
            ) => {
                require(
                    independently_observed,
                    "hash power off is independently observed",
                )?;
                OwnershipState::HashPowerOffProven
            }
            (
                OwnershipState::HashPowerOffProven,
                CustodyEvent::UartExclusive {
                    device,
                    exclusive_claim,
                },
            ) => {
                if device != NANO3_CHAIN_UART {
                    return Err(CustodyError::WrongUartDevice {
                        observed: device.to_owned(),
                    });
                }
                require(exclusive_claim, "Nano 3 UART is exclusively claimed")?;
                OwnershipState::UartExclusive
            }
            (
                OwnershipState::UartExclusive,
                CustodyEvent::AsicsDetected {
                    count,
                    nano3_identity_confirmed,
                },
            ) => {
                require(
                    nano3_identity_confirmed,
                    "Nano 3 hardware identity is confirmed",
                )?;
                if count != NANO3_ASIC_COUNT {
                    return Err(CustodyError::WrongAsicCount {
                        observed: count,
                        required: NANO3_ASIC_COUNT,
                    });
                }
                OwnershipState::Nano3Detected
            }
            (OwnershipState::Nano3Detected, CustodyEvent::AdmitSafeIdle) => {
                OwnershipState::DcentOwnedSafeIdle
            }
            (
                OwnershipState::DcentOwnedSafeIdle,
                CustodyEvent::StartMining {
                    safety_snapshot,
                    fresh_work_available,
                },
            ) => {
                if let Some(blocker) = safety_snapshot.first_blocker() {
                    return Err(CustodyError::MissingEvidence(blocker.description()));
                }
                require(fresh_work_available, "fresh mining work is available")?;
                OwnershipState::Mining
            }
            (OwnershipState::Mining, CustodyEvent::WorkDispatchStopped) => {
                self.fault = Some(CustodyFault::WorkDispatchStoppedWithoutHashCut);
                OwnershipState::FaultAwaitingHashCut
            }
            (
                OwnershipState::FaultAwaitingHashCut,
                CustodyEvent::HashCutConfirmedAfterFault {
                    independently_observed,
                },
            ) => {
                require(
                    independently_observed,
                    "post-fault hash power off is independently observed",
                )?;
                OwnershipState::FaultContained
            }
            (state, event) => {
                return Err(CustodyError::OutOfOrder {
                    state,
                    event: event.name(),
                });
            }
        };

        self.state = next;
        Ok(next)
    }
}

fn require(observed: bool, evidence: &'static str) -> Result<(), CustodyError> {
    if observed {
        Ok(())
    } else {
        Err(CustodyError::MissingEvidence(evidence))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nano3_safety::{
        BoardTemperatures, FanSafetyEvidence, FanTach, IndependentCutEvidence,
        IndependentCutTopology, PhysicalHeartbeatEvidence, ThermalSafetyEvidence, Timed,
        WatchdogPath, WatchdogSafetyEvidence,
    };

    fn complete_unreleased_safety_snapshot() -> Nano3SafetySnapshot {
        let decode_tach = |count: u64, observed_at_ms, sequence| {
            Timed::new(
                FanTach::decode(&count.to_le_bytes()).expect("valid timer fixture"),
                observed_at_ms,
                sequence,
            )
        };
        Nano3SafetySnapshot {
            now_ms: 10_000,
            custody_iteration: 70,
            fan: FanSafetyEvidence {
                custody_iteration: 70,
                previous: decode_tach(58, 8_000, 40),
                current: decode_tach(59, 9_900, 41),
                actuator_exclusive: true,
                pwm_path_live_verified: true,
                intended_pwm_period_ns: 40_000,
                intended_pwm_duty_ns: 10_000,
                observed_pwm_period_ns: Some(40_000),
                observed_pwm_duty_ns: Some(10_000),
                observed_pwm_enabled: Some(true),
                qualified_minimum_rpm: Some(1_500),
            },
            thermal: ThermalSafetyEvidence {
                custody_iteration: 70,
                board: Timed::new(
                    BoardTemperatures::decode(b"2150\n", b"2250\n").unwrap(),
                    9_900,
                    50,
                ),
                qualified_inlet_max_c: Some(150.0),
                qualified_outlet_max_c: Some(150.0),
                independent_hard_temperature_channels_healthy: true,
                controller_asic_response_live_qualified: true,
                sensor_loss_cut_live_qualified: true,
            },
            heartbeat: PhysicalHeartbeatEvidence {
                custody_iteration: 70,
                rising_edges: 6,
                falling_edges: 6,
                valid_cycles: 6,
                duty_percent: 50,
                last_edge_at_ms: 9_900,
                production_timeout_ms: 1_000,
                coupled_to_complete_custody_iteration: true,
            },
            watchdog: WatchdogSafetyEvidence {
                custody_iteration: 70,
                observed_at_ms: 9_900,
                path: WatchdogPath::IndependentInterlock,
                owner_exclusive: true,
                independent_supervisor_watchdog_healthy: true,
            },
            cut: IndependentCutEvidence {
                custody_iteration: 70,
                observed_at_ms: 9_900,
                topology: IndependentCutTopology::WholeDevice,
                qualification_record: None,
                cutoff_armed: true,
                manual_rearm_only: true,
            },
            controller_fault_absent: true,
        }
    }

    fn advance_to_safe_idle(custody: &mut Nano3HardwareCustody) {
        custody
            .apply(CustodyEvent::StockQuiesced {
                process_absent: true,
                automatic_restart_inhibited: true,
            })
            .unwrap();
        custody
            .apply(CustodyEvent::StockFileDescriptorsReleased {
                all_hardware_fds_released: true,
            })
            .unwrap();
        custody
            .apply(CustodyEvent::CoolingHeld {
                actuator_exclusive: true,
                feedback_valid: true,
            })
            .unwrap();
        custody
            .apply(CustodyEvent::SensorsHeld {
                temperature_fresh: true,
                sensor_loss_trip_armed: true,
            })
            .unwrap();
        custody
            .apply(CustodyEvent::WatchdogHeld {
                owner_exclusive: true,
                expiry_path_verified: true,
            })
            .unwrap();
        custody
            .apply(CustodyEvent::HashPowerOffProven {
                independently_observed: true,
            })
            .unwrap();
        custody
            .apply(CustodyEvent::UartExclusive {
                device: NANO3_CHAIN_UART,
                exclusive_claim: true,
            })
            .unwrap();
        custody
            .apply(CustodyEvent::AsicsDetected {
                count: NANO3_ASIC_COUNT,
                nano3_identity_confirmed: true,
            })
            .unwrap();
        custody.apply(CustodyEvent::AdmitSafeIdle).unwrap();
    }

    /// Synthetic test-only state used to exercise post-mining fault behavior.
    /// The production transition is deliberately unreachable while the native
    /// Nano 3 energization release latch remains open.
    fn set_synthetic_mining_state_for_fault_tests(custody: &mut Nano3HardwareCustody) {
        advance_to_safe_idle(custody);
        custody.state = OwnershipState::Mining;
    }

    #[test]
    fn full_proof_reaches_safe_idle_but_release_latch_still_refuses_mining() {
        let mut custody = Nano3HardwareCustody::new();
        assert_eq!(custody.state(), OwnershipState::StockOwned);
        assert!(!custody.state().has_dcent_custody());
        assert!(!custody.state().may_dispatch_work());

        advance_to_safe_idle(&mut custody);
        assert_eq!(custody.state(), OwnershipState::DcentOwnedSafeIdle);
        assert!(custody.state().has_dcent_custody());
        assert!(!custody.state().may_dispatch_work());

        let safety_snapshot = complete_unreleased_safety_snapshot();
        let error = custody
            .apply(CustodyEvent::StartMining {
                safety_snapshot: &safety_snapshot,
                fresh_work_available: true,
            })
            .unwrap_err();
        assert_eq!(
            error,
            CustodyError::MissingEvidence(
                "native Nano 3 energization compile-time release latch has not been released"
            )
        );
        assert_eq!(custody.state(), OwnershipState::DcentOwnedSafeIdle);
        assert!(!custody.state().may_dispatch_work());
    }

    #[test]
    fn out_of_order_evidence_is_refused_without_advancing() {
        let mut custody = Nano3HardwareCustody::new();
        let err = custody
            .apply(CustodyEvent::HashPowerOffProven {
                independently_observed: true,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            CustodyError::OutOfOrder {
                state: OwnershipState::StockOwned,
                event: "hash-power-off-proven"
            }
        ));
        assert_eq!(custody.state(), OwnershipState::StockOwned);
    }

    #[test]
    fn attempted_quiesce_is_not_observed_quiescence() {
        let mut custody = Nano3HardwareCustody::new();
        let err = custody
            .apply(CustodyEvent::StockQuiesced {
                process_absent: false,
                automatic_restart_inhibited: true,
            })
            .unwrap_err();
        assert_eq!(
            err,
            CustodyError::MissingEvidence("stock btcminer process is absent")
        );
        assert_eq!(custody.state(), OwnershipState::StockOwned);
    }

    #[test]
    fn all_three_safety_owners_are_individually_required() {
        let mut custody = Nano3HardwareCustody::new();
        custody
            .apply(CustodyEvent::StockQuiesced {
                process_absent: true,
                automatic_restart_inhibited: true,
            })
            .unwrap();
        custody
            .apply(CustodyEvent::StockFileDescriptorsReleased {
                all_hardware_fds_released: true,
            })
            .unwrap();

        let err = custody
            .apply(CustodyEvent::CoolingHeld {
                actuator_exclusive: true,
                feedback_valid: false,
            })
            .unwrap_err();
        assert_eq!(
            err,
            CustodyError::MissingEvidence("cooling feedback is valid")
        );
        assert_eq!(
            custody.state(),
            OwnershipState::StockFileDescriptorsReleased
        );

        custody
            .apply(CustodyEvent::CoolingHeld {
                actuator_exclusive: true,
                feedback_valid: true,
            })
            .unwrap();
        assert!(custody
            .apply(CustodyEvent::SensorsHeld {
                temperature_fresh: true,
                sensor_loss_trip_armed: false,
            })
            .is_err());
        assert_eq!(custody.state(), OwnershipState::CoolingHeld);

        custody
            .apply(CustodyEvent::SensorsHeld {
                temperature_fresh: true,
                sensor_loss_trip_armed: true,
            })
            .unwrap();
        assert!(custody
            .apply(CustodyEvent::WatchdogHeld {
                owner_exclusive: true,
                expiry_path_verified: false,
            })
            .is_err());
        assert_eq!(custody.state(), OwnershipState::SensorsHeld);
    }

    #[test]
    fn uart_and_identity_are_exact_profile_gates() {
        let mut custody = Nano3HardwareCustody::new();
        custody
            .apply(CustodyEvent::StockQuiesced {
                process_absent: true,
                automatic_restart_inhibited: true,
            })
            .unwrap();
        custody
            .apply(CustodyEvent::StockFileDescriptorsReleased {
                all_hardware_fds_released: true,
            })
            .unwrap();
        custody
            .apply(CustodyEvent::CoolingHeld {
                actuator_exclusive: true,
                feedback_valid: true,
            })
            .unwrap();
        custody
            .apply(CustodyEvent::SensorsHeld {
                temperature_fresh: true,
                sensor_loss_trip_armed: true,
            })
            .unwrap();
        custody
            .apply(CustodyEvent::WatchdogHeld {
                owner_exclusive: true,
                expiry_path_verified: true,
            })
            .unwrap();
        custody
            .apply(CustodyEvent::HashPowerOffProven {
                independently_observed: true,
            })
            .unwrap();

        assert_eq!(
            custody
                .apply(CustodyEvent::UartExclusive {
                    device: "/dev/ttyS0",
                    exclusive_claim: true,
                })
                .unwrap_err(),
            CustodyError::WrongUartDevice {
                observed: "/dev/ttyS0".to_owned()
            }
        );
        assert_eq!(custody.state(), OwnershipState::HashPowerOffProven);

        custody
            .apply(CustodyEvent::UartExclusive {
                device: NANO3_CHAIN_UART,
                exclusive_claim: true,
            })
            .unwrap();
        assert_eq!(
            custody
                .apply(CustodyEvent::AsicsDetected {
                    count: 12,
                    nano3_identity_confirmed: true,
                })
                .unwrap_err(),
            CustodyError::WrongAsicCount {
                observed: 12,
                required: NANO3_ASIC_COUNT
            }
        );
        assert_eq!(custody.state(), OwnershipState::UartExclusive);
    }

    #[test]
    fn mining_requires_live_safety_cut_and_fresh_work() {
        let mut heartbeat_not_coupled = complete_unreleased_safety_snapshot();
        heartbeat_not_coupled
            .heartbeat
            .coupled_to_complete_custody_iteration = false;
        let mut cut_not_armed = complete_unreleased_safety_snapshot();
        cut_not_armed.cut.cutoff_armed = false;

        for (snapshot, fresh_work_available) in [
            (heartbeat_not_coupled, true),
            (cut_not_armed, true),
            (complete_unreleased_safety_snapshot(), false),
        ] {
            let mut custody = Nano3HardwareCustody::new();
            advance_to_safe_idle(&mut custody);
            assert!(custody
                .apply(CustodyEvent::StartMining {
                    safety_snapshot: &snapshot,
                    fresh_work_available,
                })
                .is_err());
            assert_eq!(custody.state(), OwnershipState::DcentOwnedSafeIdle);
            assert!(!custody.state().may_dispatch_work());
        }
    }

    #[test]
    fn every_injected_runtime_fault_requires_a_new_hash_cut_confirmation() {
        for fault in [
            CustodyFault::UartLost,
            CustodyFault::SensorLost,
            CustodyFault::FanFeedbackLost,
            CustodyFault::WatchdogCustodyLost,
            CustodyFault::SafetySupervisorLost,
            CustodyFault::HardwareIdentityChanged,
        ] {
            let mut custody = Nano3HardwareCustody::new();
            set_synthetic_mining_state_for_fault_tests(&mut custody);

            assert_eq!(
                custody.latch_fault(fault).unwrap(),
                OwnershipState::FaultAwaitingHashCut
            );
            assert_eq!(custody.fault(), Some(fault));
            assert!(custody.state().requires_hash_cut_confirmation());
            assert!(!custody.state().has_dcent_custody());
            assert!(!custody.state().may_dispatch_work());

            let err = custody
                .apply(CustodyEvent::HashCutConfirmedAfterFault {
                    independently_observed: false,
                })
                .unwrap_err();
            assert!(matches!(err, CustodyError::MissingEvidence(_)));
            assert_eq!(custody.state(), OwnershipState::FaultAwaitingHashCut);

            assert_eq!(
                custody
                    .apply(CustodyEvent::HashCutConfirmedAfterFault {
                        independently_observed: true,
                    })
                    .unwrap(),
                OwnershipState::FaultContained
            );
            assert!(!custody.state().has_dcent_custody());
            assert!(!custody.state().may_dispatch_work());
        }
    }

    #[test]
    fn faults_from_every_admission_stage_discard_operating_authority() {
        for state in [
            OwnershipState::StockOwned,
            OwnershipState::StockQuiesced,
            OwnershipState::StockFileDescriptorsReleased,
            OwnershipState::CoolingHeld,
            OwnershipState::SensorsHeld,
            OwnershipState::WatchdogHeld,
            OwnershipState::HashPowerOffProven,
            OwnershipState::UartExclusive,
            OwnershipState::Nano3Detected,
            OwnershipState::DcentOwnedSafeIdle,
            OwnershipState::Mining,
        ] {
            let mut custody = Nano3HardwareCustody { state, fault: None };
            custody
                .latch_fault(CustodyFault::SafetySupervisorLost)
                .unwrap();
            assert_eq!(custody.state(), OwnershipState::FaultAwaitingHashCut);
            assert!(custody.state().requires_hash_cut_confirmation());
            assert!(!custody.state().has_dcent_custody());
            assert!(!custody.state().may_dispatch_work());
        }
    }

    #[test]
    fn stopping_work_never_claims_hash_power_is_off() {
        let mut custody = Nano3HardwareCustody::new();
        set_synthetic_mining_state_for_fault_tests(&mut custody);

        assert_eq!(
            custody.apply(CustodyEvent::WorkDispatchStopped).unwrap(),
            OwnershipState::FaultAwaitingHashCut
        );
        assert_eq!(
            custody.fault(),
            Some(CustodyFault::WorkDispatchStoppedWithoutHashCut)
        );
        assert!(custody.state().requires_hash_cut_confirmation());
        assert!(!custody.state().has_dcent_custody());
    }

    #[test]
    fn a_contained_fault_is_terminal_and_cannot_resume_mining() {
        let mut custody = Nano3HardwareCustody::new();
        set_synthetic_mining_state_for_fault_tests(&mut custody);
        custody.latch_fault(CustodyFault::UartLost).unwrap();
        custody
            .apply(CustodyEvent::HashCutConfirmedAfterFault {
                independently_observed: true,
            })
            .unwrap();

        assert!(matches!(
            custody
                .apply(CustodyEvent::StartMining {
                    safety_snapshot: &complete_unreleased_safety_snapshot(),
                    fresh_work_available: true,
                })
                .unwrap_err(),
            CustodyError::OutOfOrder {
                state: OwnershipState::FaultContained,
                ..
            }
        ));
        assert_eq!(custody.state(), OwnershipState::FaultContained);
    }

    #[test]
    fn fault_in_safe_idle_does_not_reuse_the_earlier_hash_off_proof() {
        let mut custody = Nano3HardwareCustody::new();
        advance_to_safe_idle(&mut custody);
        custody.latch_fault(CustodyFault::SensorLost).unwrap();

        assert_eq!(custody.state(), OwnershipState::FaultAwaitingHashCut);
        assert!(custody.state().requires_hash_cut_confirmation());
        assert!(!custody.state().has_dcent_custody());
    }
}
