use dcent_schema::capability::{
    AsicCapability, AsicFamily, BoardCapability, CapabilityReferences, ControlBoardCapability,
    DeviceCapabilityDescriptor, DeviceFamily, FailSafePolicy, FanControlMode, FanDescriptor,
    FanEnvelope, FanTopology, FrequencyEnvelope, HardwareIdentity, HashboardDescriptor,
    IdentityConfidence, InstallCapability, InstallCapabilityPlan, OperatingEnvelopes,
    PlannerOutcome, PowerCapability, ProofScope, PsuMode, RuntimeCapability, SafeDefaults,
    SupportTier, TempSensorClass, TempSensorDescriptor, ThermalCapability, TopologyCapability,
    VoltageEnvelope, CAPABILITY_SCHEMA_VERSION, READ_ONLY_RUNTIME_CAPABILITIES,
};
use dcentaxe_hal::board::{FanControllerKind, PowerControllerKind, TempSensorKind};

use crate::config::DcentAxeConfig;

/// Build-bound deployment policy from the canonical `esp-targets.json` row.
///
/// The firmware build script emits these values as compile-time environment
/// constants. Keeping them explicit here prevents the shared DCENT_OS
/// capability surface from treating an identity-only diagnostic image like a
/// public mining image merely because both run on an ESP32-S3.
#[derive(Debug, Clone, Copy)]
pub struct DeploymentPolicy<'a> {
    pub hardware_family: &'a str,
    pub support_tier: &'a str,
    pub runtime_mode: &'a str,
    pub install_policy: &'a str,
}

/// One policy predicate for every operator-facing mutation surface.
///
/// Unknown values deny by default. The profile input is the runtime board
/// resolver's fail-closed result, not merely the presence of ASIC topology.
pub fn deployment_allows_operational_mutations(
    runtime_mode: &str,
    install_policy: &str,
    profile_allows_mining: bool,
) -> bool {
    runtime_mode == "mining"
        && matches!(install_policy, "production" | "public-beta" | "lab-only")
        && profile_allows_mining
}

pub fn build_esp_capability_descriptor(
    config: &DcentAxeConfig,
    mining_enabled: bool,
    min_frequency_mhz: f32,
    max_frequency_mhz: f32,
    min_voltage_mv: u16,
    max_voltage_mv: u16,
    deployment: DeploymentPolicy<'_>,
) -> DeviceCapabilityDescriptor {
    let board = config.board_config();
    let profile_resolution = config.board_profile_resolution();
    let recognized = profile_resolution.identity_recognized && profile_resolution.family_consistent;

    if !recognized {
        return DeviceCapabilityDescriptor::unknown(
            DeviceFamily::Esp,
            "ESP board identity is unknown or inconsistent; runtime is read-only until board evidence is fixed",
        );
    }

    // `BoardConfig::mining_capable()` describes physical mining topology only
    // (ASICs plus an operating envelope). The profile resolution is the real
    // fail-closed runtime gate: it also covers trusted thermal sensing, board
    // identity consistency, accessory pin conflicts, and custom-board rules.
    let profile_allows_mining = profile_resolution.mining_allowed_without_lab_bypass;
    let read_only = !deployment_allows_operational_mutations(
        deployment.runtime_mode,
        deployment.install_policy,
        profile_allows_mining,
    );

    let mut runtime_caps = READ_ONLY_RUNTIME_CAPABILITIES.to_vec();
    if !read_only {
        runtime_caps.extend_from_slice(&[
            RuntimeCapability::PoolsRw,
            RuntimeCapability::ConfigRw,
            RuntimeCapability::Reboot,
            RuntimeCapability::Backup,
            RuntimeCapability::FlashOta,
            RuntimeCapability::FlashOtaWww,
            RuntimeCapability::SettingsPatch,
            RuntimeCapability::AsicOptions,
            RuntimeCapability::Identify,
            RuntimeCapability::WifiScan,
        ]);
        if board.model.has_voltage_control() {
            runtime_caps.push(RuntimeCapability::PowerControl);
        }
    }

    let support = match deployment.support_tier {
        "stable" | "production" => SupportTier::Stable,
        "beta" => SupportTier::Beta,
        "experimental" => SupportTier::Experimental,
        "unsupported" => SupportTier::Unsupported,
        _ => SupportTier::Unknown,
    };
    let asic_family = asic_family(&board.asic_model);
    let install = install_capability_plan(deployment.install_policy);
    let fail_safe_reason = if read_only {
        format!(
            "build policy is runtime_mode={} install_policy={}; expose identity and monitoring only",
            deployment.runtime_mode, deployment.install_policy
        )
    } else {
        format!(
            "recognized {} ESP board; mutating routes remain owner-authenticated and safety-clamped",
            deployment.install_policy
        )
    };

    DeviceCapabilityDescriptor {
        schema_version: CAPABILITY_SCHEMA_VERSION,
        family: DeviceFamily::Esp,
        identity: HardwareIdentity {
            confidence: if !config.board_version.trim().is_empty() {
                IdentityConfidence::Exact
            } else {
                IdentityConfidence::High
            },
            sources: identity_sources(config),
            note: Some(format!(
                "ESP board registry reports '{}' with runtime_mode={} install_policy={} tier={:?}",
                config.support_status(),
                deployment.runtime_mode,
                deployment.install_policy,
                support
            )),
            device_model: Some(board.device_model.clone()),
            board_target: Some(board.model.board_target().to_string()),
            board_version: Some(board.board_version.clone()),
            platform: Some("esp32-s3".to_string()),
        },
        support,
        board: BoardCapability {
            board_target: Some(board.model.board_target().to_string()),
            family: Some(deployment.hardware_family.to_string()),
            control_board: Some(board.model.name().to_string()),
            fixture_refs: vec![
                "DCENT_OS_ESP/dcentaxe-hal/src/board.rs".to_string(),
                "DCENT_OS_ESP/dcentaxe/src/config.rs".to_string(),
            ],
        },
        control_board: ControlBoardCapability {
            soc: Some("esp32-s3".to_string()),
            control_board_id: Some(board.board_version.clone()),
            uio_model: None,
        },
        asic: AsicCapability {
            chip_model: Some(board.asic_model.clone()),
            asic_family,
            chip_id: Some(board.model.expected_chip_id()),
            baud: Some(esp_runtime_baud(&board.asic_model)),
            cores_per_chip: Some(cores_per_chip(&board.asic_model)),
            nonce_attribution_cores: Some(nonce_attribution_cores(&board.asic_model)),
        },
        topology: TopologyCapability {
            chain_count: Some(1),
            chips_per_chain: Some(board.asic_count as u16),
            fan_count: Some(fan_count(board.fan_controller)),
            temp_sensors: temp_sensors(board.temp_sensor, board.power_controller),
            hashboards: vec![HashboardDescriptor {
                index: Some(0),
                chain_index: Some(0),
                chip_model: Some(board.asic_model.clone()),
                asic_family,
                chip_id: Some(board.model.expected_chip_id()),
                chips_per_chain: Some(board.asic_count as u16),
                present: Some(board.mining_capable()),
                serial: None,
            }],
        },
        fan_topology: esp_fan_topology(board.fan_controller),
        temp_sensors: esp_temp_sensor_descriptors(board.temp_sensor, board.power_controller),
        thermal: ThermalCapability {
            runtime_caps: vec![RuntimeCapability::Monitoring],
            fail_closed_on_sensor_loss: board.temp_sensor != TempSensorKind::None,
        },
        power: PowerCapability {
            runtime_caps: if board.model.has_voltage_control() && !read_only {
                vec![RuntimeCapability::PowerControl]
            } else {
                Vec::new()
            },
            voltage_control: Some(power_controller_label(board.power_controller).to_string()),
            psu_protocol: Some("board-regulator".to_string()),
            psu_mode: PsuMode::AutoDetect,
            psu_model: Some(power_controller_label(board.power_controller).to_string()),
            writes_enabled: board.model.has_voltage_control() && !read_only,
        },
        controllers: Vec::new(),
        operating_envelopes: OperatingEnvelopes {
            frequency: Some(FrequencyEnvelope {
                min_mhz: Some(clamp_f32_to_u16(
                    min_frequency_mhz,
                    min_frequency_mhz,
                    max_frequency_mhz,
                )),
                max_mhz: Some(clamp_f32_to_u16(
                    max_frequency_mhz,
                    min_frequency_mhz,
                    max_frequency_mhz,
                )),
                step_mhz: None,
            }),
            voltage: Some(VoltageEnvelope {
                min_mv: Some(min_voltage_mv),
                max_mv: Some(max_voltage_mv),
                step_mv: None,
            }),
            fan: Some(FanEnvelope {
                min_pwm: Some(0),
                max_pwm: Some(100),
            }),
        },
        references: CapabilityReferences {
            fixture_refs: vec![
                "DCENT_OS_ESP/dcentaxe-hal/src/board.rs".to_string(),
                "DCENT_OS_ESP/"
                    .to_string(),
            ],
            sim_profile_ref: None,
            bench_checklist_ref: Some("BP-ESP-BOARD-SOAK".to_string()),
        },
        runtime_caps,
        install,
        safe_defaults: SafeDefaults {
            mining_enabled: mining_enabled && !read_only && profile_allows_mining,
            fan_pwm_cap: if read_only { 30 } else { 100 },
            frequency_mhz: Some(clamp_f32_to_u16(
                board.default_frequency,
                min_frequency_mhz,
                max_frequency_mhz,
            )),
            voltage_mv: Some(
                board
                    .default_voltage_mv
                    .clamp(min_voltage_mv, max_voltage_mv),
            ),
        },
        fail_safe: FailSafePolicy {
            read_only,
            mining_start_allowed: !read_only && profile_allows_mining,
            mutating_routes_allowed: !read_only,
            reason: fail_safe_reason,
        },
    }
}

fn install_capability_plan(install_policy: &str) -> InstallCapabilityPlan {
    match install_policy {
        "public-beta" => InstallCapabilityPlan {
            planner_outcome: PlannerOutcome::OtaSupported,
            proof_scope: Some(ProofScope::UploadOnlyBootPending),
            required_capabilities: vec![
                InstallCapability::HttpOtaOrUsbSerial,
                InstallCapability::ManifestBoardMatch,
            ],
            missing_capabilities: vec![InstallCapability::RestoreVerified],
            recovery_route_id: Some("esp-ota-or-usb-serial".to_string()),
            note: Some(
                "Public-beta signed OTA/upload is supported; boot, rollback, and mining proof remain pending"
                    .to_string(),
            ),
        },
        "lab-only" => InstallCapabilityPlan {
            planner_outcome: PlannerOutcome::EvidenceGap,
            proof_scope: Some(ProofScope::ExactTargetLabOnly),
            required_capabilities: vec![
                InstallCapability::HttpOtaOrUsbSerial,
                InstallCapability::ManifestBoardMatch,
            ],
            missing_capabilities: vec![InstallCapability::RestoreVerified],
            recovery_route_id: Some("esp-exact-target-lab".to_string()),
            note: Some(
                "Exact-target lab installation only; field promotion requires retained boot, safety, share, rollback, and soak evidence"
                    .to_string(),
            ),
        },
        _ => InstallCapabilityPlan {
            planner_outcome: PlannerOutcome::EvidenceGap,
            proof_scope: Some(ProofScope::LocalArtifactOnly),
            required_capabilities: Vec::new(),
            missing_capabilities: vec![
                InstallCapability::HttpOtaOrUsbSerial,
                InstallCapability::RestoreVerified,
            ],
            recovery_route_id: None,
            note: Some(
                "Installation is blocked; this artifact is limited to offline package proof and identity diagnostics"
                    .to_string(),
            ),
        },
    }
}

fn asic_family(chip_model: &str) -> AsicFamily {
    match chip_model.trim() {
        "BM1397" | "BM1366" | "BM1368" | "BM1370" | "BM1373" => AsicFamily::BitmainBm13xx,
        // MSBT0501/LT0051 is a Hammer Scrypt ASIC, not a Bitmain BM13xx.
        // The shared schema does not yet have a dedicated family, so Unknown
        // is the honest value rather than fabricating a Bitmain lineage.
        _ => AsicFamily::Unknown,
    }
}

fn identity_sources(config: &DcentAxeConfig) -> Vec<String> {
    let mut sources = Vec::new();
    if !config.board_version.trim().is_empty() {
        sources.push(format!(
            "config.board_version:{}",
            config.board_version.trim()
        ));
    }
    if !config.board_model.trim().is_empty() {
        sources.push(format!("config.board_model:{}", config.board_model.trim()));
    }
    if !config.asic_model.trim().is_empty() {
        sources.push(format!("config.asic_model:{}", config.asic_model.trim()));
    }
    sources
}

fn esp_runtime_baud(chip_model: &str) -> u32 {
    match chip_model.trim() {
        "BM1397" => 3_125_000,
        "BM1366" | "BM1368" | "BM1370" => 1_000_000,
        _ => 115_200,
    }
}

fn cores_per_chip(chip_model: &str) -> u32 {
    match chip_model.trim() {
        "BM1397" => 168,
        "BM1366" => 112,
        "BM1368" => 80,
        // BM1373 grouped with BM1370 — PROJECTED (matches api.rs:1014).
        "BM1370" | "BM1373" => 128,
        _ => 0,
    }
}

fn nonce_attribution_cores(chip_model: &str) -> u32 {
    match chip_model.trim() {
        "BM1397" => 672,
        "BM1366" => 894,
        "BM1368" => 1276,
        // BM1373 grouped with BM1370 — PROJECTED (matches main.rs:460).
        "BM1370" | "BM1373" => 2040,
        _ => 0,
    }
}

fn fan_count(kind: FanControllerKind) -> u8 {
    match kind {
        FanControllerKind::None => 0,
        FanControllerKind::Emc2101 | FanControllerKind::Emc2103 => 1,
        FanControllerKind::Emc2302 => 2,
    }
}

fn esp_fan_topology(kind: FanControllerKind) -> FanTopology {
    let count = fan_count(kind);
    let per_fan: Vec<FanDescriptor> = (0..count)
        .map(|index| FanDescriptor {
            index: Some(index),
            tach_channel: Some(index),
            pwm_channel: Some(index),
            label: Some(format!("fan{index}")),
        })
        .collect();

    FanTopology {
        control_mode: match kind {
            FanControllerKind::None => FanControlMode::None,
            FanControllerKind::Emc2101 => FanControlMode::Emc2101,
            FanControllerKind::Emc2103 => FanControlMode::Emc2103,
            FanControllerKind::Emc2302 => FanControlMode::Emc2302,
        },
        fan_count: Some(count),
        tach_channels: per_fan.iter().filter_map(|fan| fan.tach_channel).collect(),
        pwm_channels: per_fan.iter().filter_map(|fan| fan.pwm_channel).collect(),
        per_fan,
    }
}

fn temp_sensors(temp: TempSensorKind, power: PowerControllerKind) -> Vec<String> {
    let mut sensors = Vec::new();
    match temp {
        TempSensorKind::None => {}
        TempSensorKind::Emc2101 => sensors.push("emc2101".to_string()),
        TempSensorKind::Tmp1075 => sensors.push("tmp1075".to_string()),
        TempSensorKind::Emc2103 => sensors.push("emc2103".to_string()),
        // Deliberately generic: the muxed Nerd boards fit a TMP451 or an
        // ADT7461-family equivalent, and the capability string must not assert
        // a specific part we have never read a device ID from.
        TempSensorKind::Tmp451 => sensors.push("tmp451".to_string()),
    }
    if power == PowerControllerKind::Tps546 {
        sensors.push("tps546-vr".to_string());
    }
    sensors
}

fn esp_temp_sensor_descriptors(
    temp: TempSensorKind,
    power: PowerControllerKind,
) -> Vec<TempSensorDescriptor> {
    temp_sensors(temp, power)
        .into_iter()
        .enumerate()
        .map(|(index, name)| TempSensorDescriptor {
            class: match name.as_str() {
                "tps546-vr" => TempSensorClass::VrController,
                _ => TempSensorClass::BoardI2c,
            },
            name: Some(name),
            bus: Some("i2c".to_string()),
            address: None,
            index: u8::try_from(index).ok(),
            fallback_order: u8::try_from(index).ok(),
        })
        .collect()
}

fn power_controller_label(kind: PowerControllerKind) -> &'static str {
    match kind {
        PowerControllerKind::None => "fixed-or-none",
        PowerControllerKind::Tps546 => "tps546",
        PowerControllerKind::Ds4432u => "ds4432u",
        // Deliberately generic: which of TPS53647/TPS53667 is fitted is only
        // known after the runtime device-code read, and the NerdOCTAXE-γ ships
        // both across revisions. Naming one part here would be a claim the
        // board row cannot back.
        PowerControllerKind::Tps5364x => "tps5364x",
    }
}

fn clamp_f32_to_u16(value: f32, min: f32, max: f32) -> u16 {
    value.clamp(min, max).round() as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_beta_policy() -> DeploymentPolicy<'static> {
        DeploymentPolicy {
            hardware_family: "bitaxe",
            support_tier: "beta",
            runtime_mode: "mining",
            install_policy: "public-beta",
        }
    }

    #[test]
    fn known_gamma_descriptor_uses_the_registry_public_beta_policy() {
        let cfg = DcentAxeConfig::default();
        let desc = build_esp_capability_descriptor(
            &cfg,
            true,
            50.0,
            650.0,
            850,
            1350,
            public_beta_policy(),
        );

        assert_eq!(desc.family, DeviceFamily::Esp);
        assert_eq!(desc.support, SupportTier::Beta);
        assert_eq!(desc.identity.confidence, IdentityConfidence::Exact);
        assert_eq!(desc.board.board_target.as_deref(), Some("bitaxe-gamma"));
        assert_eq!(desc.board.family.as_deref(), Some("bitaxe"));
        assert_eq!(desc.asic.chip_model.as_deref(), Some("BM1370"));
        assert_eq!(desc.asic.baud, Some(1_000_000));
        assert!(desc.runtime_caps.contains(&RuntimeCapability::FlashOta));
        assert_eq!(desc.install.planner_outcome, PlannerOutcome::OtaSupported);
        assert_eq!(desc.safe_defaults.fan_pwm_cap, 100);
        assert!(desc.fail_safe.mutating_routes_allowed);
    }

    #[test]
    fn unknown_board_identity_fails_read_only() {
        let mut cfg = DcentAxeConfig::default();
        cfg.board_version = "unknown-board-version".to_string();

        let desc = build_esp_capability_descriptor(
            &cfg,
            true,
            50.0,
            650.0,
            850,
            1350,
            public_beta_policy(),
        );

        assert_eq!(desc.support, SupportTier::Unknown);
        assert_eq!(desc.identity.confidence, IdentityConfidence::Unknown);
        assert_eq!(desc.runtime_caps, READ_ONLY_RUNTIME_CAPABILITIES);
        assert!(desc.fail_safe.read_only);
        assert!(!desc.fail_safe.mining_start_allowed);
        assert!(!desc.fail_safe.mutating_routes_allowed);
        assert!(!desc.safe_defaults.mining_enabled);
    }

    #[test]
    fn hammer_identity_only_policy_is_read_only_and_not_installable() {
        let mut cfg = DcentAxeConfig::default();
        cfg.board_version = "3004".to_string();
        cfg.board_model = "hammer_bc04".to_string();
        cfg.asic_model = "BM1370".to_string();
        cfg.asic_count = 4;

        let desc = build_esp_capability_descriptor(
            &cfg,
            true,
            50.0,
            650.0,
            1000,
            1250,
            DeploymentPolicy {
                hardware_family: "hammer-bc",
                support_tier: "experimental",
                runtime_mode: "identity-only",
                install_policy: "blocked",
            },
        );

        assert_eq!(desc.board.family.as_deref(), Some("hammer-bc"));
        assert_eq!(desc.support, SupportTier::Experimental);
        assert_eq!(desc.runtime_caps, READ_ONLY_RUNTIME_CAPABILITIES);
        assert_eq!(desc.install.planner_outcome, PlannerOutcome::EvidenceGap);
        assert_eq!(
            desc.install.proof_scope,
            Some(ProofScope::LocalArtifactOnly)
        );
        assert!(desc.fail_safe.read_only);
        assert!(!desc.fail_safe.mining_start_allowed);
        assert!(!desc.fail_safe.mutating_routes_allowed);
        assert!(!desc.safe_defaults.mining_enabled);
        assert!(!desc.power.writes_enabled);
    }

    #[test]
    fn hammer_scrypt_asic_is_not_misreported_as_bitmain_bm13xx() {
        assert_eq!(asic_family("MSBT0501"), AsicFamily::Unknown);
        assert_eq!(asic_family("LT0051"), AsicFamily::Unknown);
        assert_eq!(asic_family("BM1370"), AsicFamily::BitmainBm13xx);
    }

    #[test]
    fn deployment_mutation_policy_is_closed_by_default() {
        assert!(deployment_allows_operational_mutations(
            "mining",
            "public-beta",
            true
        ));
        assert!(deployment_allows_operational_mutations(
            "mining",
            "production",
            true
        ));
        assert!(deployment_allows_operational_mutations(
            "mining", "lab-only", true
        ));
        assert!(!deployment_allows_operational_mutations(
            "identity-only",
            "blocked",
            true
        ));
        assert!(!deployment_allows_operational_mutations(
            "mining", "blocked", true
        ));
        assert!(!deployment_allows_operational_mutations(
            "mining",
            "public-beta",
            false
        ));
        assert!(!deployment_allows_operational_mutations(
            "future-mode",
            "future-policy",
            true
        ));
    }

    #[test]
    fn esp_baud_pins_keep_bm136x_bm1370_at_one_mbaud() {
        assert_eq!(esp_runtime_baud("BM1366"), 1_000_000);
        assert_eq!(esp_runtime_baud("BM1368"), 1_000_000);
        assert_eq!(esp_runtime_baud("BM1370"), 1_000_000);
        assert_eq!(esp_runtime_baud("BM1397"), 3_125_000);
    }
}
