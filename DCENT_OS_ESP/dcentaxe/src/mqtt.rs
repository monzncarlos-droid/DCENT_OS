// DCENT_axe — MQTT publisher (esp-idf transport)
// Copyright (C) 2026 D-Central Technologies
// License: GPL-3.0
//
//! Thin, fail-soft, default-OFF MQTT integration for Home Assistant.
//!
//! All the testable logic (HA discovery topics/payloads + the state payload)
//! lives in the host-pure [`crate::mqtt_ha`] module. This file is ONLY the
//! esp-idf transport: it owns the broker connection, publish cadence, and the
//! bounded command handoff from the MQTT callback to this worker thread.
//!
//! ## Invariants (do not regress)
//! - **Default-OFF.** Nothing runs unless `config.mqtt.enabled` is true AND a
//!   broker host is configured.
//! - **Fail-soft.** Every broker/network error is logged + retried with backoff.
//!   MQTT runs on its own thread; the broker callback never blocks or takes a
//!   device-state lock. Optional controls only update shared autotuner intent;
//!   the normal board/thermal safety path remains authoritative.
//! - **No HTTP handler.** MQTT is outbound, so `MAX_URI_HANDLERS` is unchanged.
//! - **panic=abort safe.** We snapshot-then-drop every `SharedState` lock (never
//!   hold one across a publish) and use `unwrap_or_else(|e| e.into_inner())`, so
//!   a fault on this thread can never poison a `Mutex` another thread unwraps.
//! - **Controls are doubly opt-in.** Command topics are advertised/subscribed
//!   only when `mqtt.commands_enabled` is true AND the compiled/runtime
//!   deployment policy permits operational mutations. Policy is rechecked on
//!   every command, and stale retained discovery controls are tombstoned.
//!
//! Field-delivery status: implemented + host-unit-tested (the payload builder)
//! and xtensa-built; live broker delivery is not yet field-proven. See README /
//!  for the honest claim wording.

use crate::mqtt_ha::{
    autotune_update_for_command, build_publish_plan, command_discovery_tombstones,
    command_state_echo, command_subscribe_topics, command_surface_enabled, device_id_from_mac,
    lwt_spec, parse_command, state_topic, CommandTopics, EnergyAccumulator, HaDevice, HaState,
    MqttPublishOp, MqttQos, PublishPhase,
};
use crate::shared::{AutotuneMode, SharedState};
use esp_idf_svc::mqtt::client::{
    Details, EspMqttClient, EventPayload, LwtConfiguration, MqttClientConfiguration, QoS,
};
use esp_idf_svc::sys;
use log::{info, warn};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, TrySendError};
use std::time::{Duration, Instant};

/// Map the host-pure [`MqttQos`] (used by the publish plan) onto the esp-idf
/// `QoS` enum. Keeps `mqtt_ha` free of any esp-idf dependency so it host-tests.
fn esp_qos(q: MqttQos) -> QoS {
    match q {
        MqttQos::AtMostOnce => QoS::AtMostOnce,
        MqttQos::AtLeastOnce => QoS::AtLeastOnce,
    }
}

/// Worker thread stack. The publish loop serializes a small JSON state object
/// (heap-allocated by serde_json), so this is comfortable headroom.
const MQTT_TASK_STACK: usize = 8 * 1024;
/// esp-mqtt client RX/TX buffers — kept small for the ~300 KB RAM budget. The
/// discovery configs + state payloads are well under 1 KiB each.
const MQTT_BUFFER_SIZE: usize = 1024;
/// Reconnect backoff ceiling.
const RECONNECT_BACKOFF_MAX_S: u64 = 60;
/// Never publish faster than this (avoids a busy loop on a bad config value).
const MIN_PUBLISH_INTERVAL_S: u16 = 5;
/// The MQTT callback cannot block the esp-mqtt task. A small bounded channel
/// absorbs a brief burst; excess commands are dropped and can be retried by HA.
const MQTT_COMMAND_QUEUE_CAPACITY: usize = 8;
/// Command payloads are scalar numbers/mode tokens. Reject larger input before
/// allocating/copying it out of the esp-mqtt callback.
const MAX_COMMAND_PAYLOAD_BYTES: usize = 64;
/// We subscribe to three exact short topics; reject any unexpected large topic.
const MAX_COMMAND_TOPIC_BYTES: usize = 128;
/// Wake periodically even when telemetry is slow so config/policy revocation is
/// reflected promptly and forces a reconnect/tombstone pass.
const MQTT_POLICY_POLL: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct InboundMqttCommand {
    topic: String,
    payload: Vec<u8>,
}

/// Read the device MAC (last 3 octets feed the stable HA device id).
fn device_mac_string() -> String {
    let mut mac = [0u8; 6];
    // SAFETY: esp_efuse_mac_get_default fills exactly 6 bytes into our buffer.
    let err = unsafe { sys::esp_efuse_mac_get_default(mac.as_mut_ptr()) };
    if err == sys::ESP_OK {
        mac.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    } else {
        String::new()
    }
}

/// Spawn the MQTT publisher thread IFF `config.mqtt.enabled` and a broker host is
/// configured. Safe to call unconditionally at boot — it returns immediately when
/// MQTT is off (the default).
pub fn spawn_publisher(state: SharedState) {
    let cfg = state
        .config
        .lock()
        .map(|c| c.mqtt.clone())
        .unwrap_or_else(|e| e.into_inner().mqtt.clone());

    if !cfg.enabled {
        info!("MQTT publisher disabled (mqtt.enabled=false)");
        return;
    }
    if cfg.broker_host.trim().is_empty() {
        warn!("MQTT enabled but broker host is empty — not starting publisher");
        return;
    }

    let device_id = device_id_from_mac(&device_mac_string());
    info!(
        "MQTT publisher starting: broker {}:{} (tls={}) device_id={}",
        cfg.broker_host.trim(),
        cfg.broker_port,
        cfg.tls,
        device_id
    );

    let _ = std::thread::Builder::new()
        .name("mqtt".into())
        .stack_size(MQTT_TASK_STACK)
        .spawn(move || run_loop(state, device_id))
        .map_err(|e| warn!("failed to spawn MQTT thread: {e}"));
}

/// Reconnecting publish loop. Each session is a fresh connect + retained
/// discovery publish + periodic state publishes; on any error we back off and
/// reconnect. This loop never exits while MQTT stays enabled.
fn run_loop(state: SharedState, device_id: String) {
    let mut backoff = 2u64;
    // ONE energy accumulator for the whole boot: it lives HERE (not inside
    // `run_session`) so the lifetime kWh total is monotonic ACROSS reconnects and
    // only resets on reboot — exactly the HA `total_increasing` energy contract.
    let mut energy = EnergyAccumulator::new();
    loop {
        match run_session(&state, &device_id, &mut energy) {
            Ok(()) => {
                // A clean return means MQTT was disabled mid-run — stop quietly.
                info!("MQTT publisher stopping (disabled at runtime)");
                return;
            }
            Err(e) => warn!("MQTT session ended: {e} — reconnecting in {backoff}s"),
        }
        std::thread::sleep(Duration::from_secs(backoff));
        backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX_S);
    }
}

/// One broker session: connect, publish retained discovery, then publish state on
/// the configured cadence until an error or MQTT is disabled. Returns `Ok(())`
/// only when MQTT was disabled at runtime (clean stop); any transport problem is
/// `Err` so `run_loop` reconnects.
fn run_session(
    state: &SharedState,
    device_id: &str,
    energy: &mut EnergyAccumulator,
) -> Result<(), String> {
    // Re-read config each session so edits (broker move, disable) take effect on
    // the next reconnect without a reboot.
    let cfg = state
        .config
        .lock()
        .map(|c| c.mqtt.clone())
        .unwrap_or_else(|e| e.into_inner().mqtt.clone());
    if !cfg.enabled {
        return Ok(());
    }

    let host = cfg.broker_host.trim();
    if host.is_empty() {
        return Err("broker host empty".to_string());
    }
    let scheme = if cfg.tls { "mqtts" } else { "mqtt" };
    let url = format!("{scheme}://{host}:{}", cfg.broker_port);

    let device = build_device(state, device_id);
    let state_t = state_topic(device_id);

    // The publish SEQUENCE + the LWT now come from the host-pure, host-tested
    // plan in `mqtt_ha` (`build_publish_plan` / `lwt_spec`). This transport only
    // owns the connection + the loop cadence; the wire output (topics/payloads/
    // retain/QoS) is exactly what this fn used to inline. The plan is proven
    // host-side against an in-process mock broker — that is NOT live-broker proof
    // (live delivery stays operator/broker-gated).
    let lwt_spec = lwt_spec(device_id);

    // Borrows below must outlive the new_cb() call (the C client copies them
    // synchronously at construction). They all live for the rest of this fn.
    let client_id = device_id.to_string();
    let username = cfg.username.clone();
    let password = cfg.password.clone();
    let lwt = LwtConfiguration {
        topic: &lwt_spec.topic,
        payload: lwt_spec.payload.as_bytes(),
        qos: esp_qos(lwt_spec.qos),
        retain: lwt_spec.retain,
    };
    let conf = MqttClientConfiguration {
        client_id: Some(&client_id),
        username: (!username.is_empty()).then_some(username.as_str()),
        password: (!password.is_empty()).then_some(password.as_str()),
        keep_alive_interval: Some(Duration::from_secs(30)),
        buffer_size: MQTT_BUFFER_SIZE,
        out_buffer_size: MQTT_BUFFER_SIZE,
        lwt: Some(lwt),
        ..Default::default()
    };

    // The effective command surface is stricter than the persisted opt-in: an
    // identity-only/blocked build or an unsafe runtime board profile always
    // wins and leaves MQTT read-only.
    let commands_enabled = command_surface_enabled(
        cfg.commands_enabled,
        crate::auth::deployment_mutations_allowed(state),
    );
    if cfg.commands_enabled && !commands_enabled {
        warn!("MQTT commands requested but denied by deployment/board policy; telemetry remains read-only");
    }

    // new_cb pumps the connection internally. Copy only complete, tiny command
    // messages into a bounded channel: the esp-mqtt task never blocks, never
    // locks SharedState, and never applies a command inside the C callback.
    let (command_tx, command_rx) = sync_channel(MQTT_COMMAND_QUEUE_CAPACITY);
    let mut client = EspMqttClient::new_cb(&url, &conf, move |event| {
        let EventPayload::Received {
            topic: Some(topic),
            data,
            details,
            ..
        } = event.payload()
        else {
            return;
        };
        if details != Details::Complete {
            warn!("MQTT command chunk rejected (fragmented payloads are not accepted)");
            return;
        }
        if topic.len() > MAX_COMMAND_TOPIC_BYTES || data.len() > MAX_COMMAND_PAYLOAD_BYTES {
            warn!(
                "MQTT command rejected: topic/payload exceeds bounded input ({} / {} bytes)",
                topic.len(),
                data.len()
            );
            return;
        }
        let inbound = InboundMqttCommand {
            topic: topic.to_string(),
            payload: data.to_vec(),
        };
        if let Err(error) = command_tx.try_send(inbound) {
            match error {
                TrySendError::Full(_) => warn!("MQTT command queue full; dropping command"),
                TrySendError::Disconnected(_) => {
                    warn!("MQTT command worker unavailable; dropping command")
                }
            }
        }
    })
    .map_err(|e| format!("connect: {e}"))?;

    if commands_enabled {
        for topic in command_subscribe_topics(device_id) {
            client
                .subscribe(&topic, QoS::AtLeastOnce)
                .map_err(|e| format!("command subscribe to {topic}: {e}"))?;
        }
        info!("MQTT/HA command surface enabled (3 bounded command topics)");
    } else {
        // Retained discovery survives broker reconnects. Explicit empty retained
        // payloads remove controls advertised by an older/permitted session.
        for op in command_discovery_tombstones(device_id) {
            client
                .enqueue(&op.topic, esp_qos(op.qos), op.retain, op.payload.as_bytes())
                .map_err(|e| format!("command discovery tombstone {}: {e}", op.topic))?;
        }
    }

    // On-connect plan: retained discovery configs (so a freshly started HA still
    // auto-creates the entities) -> availability `online` -> the first state
    // payload (so entities show a value immediately). All ops are load-bearing
    // on connect, so any enqueue failure ends the session and reconnects.
    let connect_plan = build_publish_plan(
        &device,
        &snapshot_state(state, energy.energy_kwh()),
        PublishPhase::OnConnect,
        commands_enabled,
    );
    let discovery_count = connect_plan
        .iter()
        .filter(|op| op.topic.starts_with("homeassistant/"))
        .count();
    for op in &connect_plan {
        client
            .enqueue(&op.topic, esp_qos(op.qos), op.retain, op.payload.as_bytes())
            .map_err(|e| format!("on-connect publish to {}: {e}", op.topic))?;
    }
    info!(
        "MQTT/HA discovery published ({discovery_count} entities) — miner will appear in Home Assistant"
    );

    let interval_s = cfg.publish_interval_s.max(MIN_PUBLISH_INTERVAL_S) as u64;
    let interval = Duration::from_secs(interval_s);

    // The on-connect plan already shipped the first state, so the first periodic
    // tick must NOT re-publish it — it only refreshes availability. From the
    // second tick on, the full periodic plan runs. This keeps the publish stream
    // byte-identical to the prior inline loop (which published state, then the
    // availability heartbeat, then slept).
    let mut first_tick = true;
    let mut next_publish = Instant::now();
    let command_topics = CommandTopics::new(device_id);
    loop {
        // Stop cleanly if MQTT was disabled at runtime. A change to the
        // effective command surface forces a fresh session so subscriptions and
        // retained discovery/tombstones converge with current policy.
        let (still_enabled, commands_requested_now) = state
            .config
            .lock()
            .map(|c| (c.mqtt.enabled, c.mqtt.commands_enabled))
            .unwrap_or_else(|e| {
                let c = e.into_inner();
                (c.mqtt.enabled, c.mqtt.commands_enabled)
            });
        if !still_enabled {
            return Ok(());
        }
        let commands_enabled_now = command_surface_enabled(
            commands_requested_now,
            crate::auth::deployment_mutations_allowed(state),
        );
        if commands_enabled_now != commands_enabled {
            return Err("effective MQTT command policy changed".to_string());
        }

        if Instant::now() >= next_publish {
            // Snapshot once per tick: the state payload carries the cumulative
            // energy integrated so far, and we reuse its `power_w` to advance
            // the accumulator for the next interval.
            let snap = snapshot_state(state, energy.energy_kwh());

            // Periodic plan: the state payload (load-bearing — reconnect on
            // failure) then a retained availability heartbeat (best-effort).
            let tick_plan =
                build_publish_plan(&device, &snap, PublishPhase::Periodic, commands_enabled);
            for op in &tick_plan {
                // The on-connect plan already published the first state; only
                // refresh availability on this immediate first tick.
                if first_tick && op.topic == state_t {
                    continue;
                }
                let r =
                    client.enqueue(&op.topic, esp_qos(op.qos), op.retain, op.payload.as_bytes());
                if op.topic == state_t {
                    r.map_err(|e| format!("state publish: {e}"))?;
                } else {
                    let _ = r;
                }
            }
            first_tick = false;

            // `add_sample` is fail-benign for non-finite/negative readings.
            energy.add_sample(snap.power_w, interval_s as f64);
            next_publish = Instant::now() + interval;
        }

        let wait = next_publish
            .saturating_duration_since(Instant::now())
            .min(MQTT_POLICY_POLL);
        match command_rx.recv_timeout(wait) {
            Ok(inbound) => {
                if let Some(echo) = apply_inbound_command(state, &command_topics, inbound) {
                    client
                        .enqueue(
                            &echo.topic,
                            esp_qos(echo.qos),
                            echo.retain,
                            echo.payload.as_bytes(),
                        )
                        .map_err(|e| format!("command state echo to {}: {e}", echo.topic))?;
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err("MQTT command callback disconnected".to_string());
            }
        }
    }
}

/// Parse, policy-check, validate, and atomically apply one queued HA command.
/// Rejected input never publishes a success echo.
fn apply_inbound_command(
    state: &SharedState,
    topics: &CommandTopics,
    inbound: InboundMqttCommand,
) -> Option<MqttPublishOp> {
    let Some(command) = parse_command(topics, &inbound.topic, &inbound.payload) else {
        warn!("MQTT command rejected: unknown topic or invalid payload");
        return None;
    };

    // Lock order is config -> autotuner, matching the rest of the runtime. Hold
    // both only for the small atomic state update; no broker call occurs here.
    let config = state.config.lock().unwrap_or_else(|e| e.into_inner());
    let profile_allows_mining = config
        .board_profile_resolution()
        .mining_allowed_without_lab_bypass;
    let deployment_allowed = crate::capabilities::deployment_allows_operational_mutations(
        env!("DCENTAXE_RUNTIME_MODE"),
        env!("DCENTAXE_INSTALL_POLICY"),
        profile_allows_mining,
    );
    if !command_surface_enabled(config.mqtt.commands_enabled, deployment_allowed) {
        warn!("MQTT command rejected: command surface is disabled by config/deployment policy");
        return None;
    }

    let mut autotuner = state.autotuner.lock().unwrap_or_else(|e| e.into_inner());
    let update = autotune_update_for_command(&command, autotuner.target_value);
    let mode = match AutotuneMode::from_api_str(update.mode) {
        Some(mode) => mode,
        None => {
            warn!("MQTT command rejected: unsupported autotuner mode");
            return None;
        }
    };
    let pure_mode = match mode {
        AutotuneMode::MaxHashrate => crate::chip_profiles_bitaxe::BestPointMode::MaxHashrate,
        AutotuneMode::TargetWatts => crate::chip_profiles_bitaxe::BestPointMode::TargetWatts,
        AutotuneMode::BestEfficiency => crate::chip_profiles_bitaxe::BestPointMode::BestEfficiency,
        AutotuneMode::TargetTemp => crate::chip_profiles_bitaxe::BestPointMode::TargetTemp,
    };
    let validated_target = match update.target_value {
        Some(target) => {
            match crate::chip_profiles_bitaxe::validate_autotune_target(pure_mode, target) {
                Ok(target) => Some(target),
                Err(message) => {
                    warn!("MQTT command rejected by autotuner target validator: {message}");
                    return None;
                }
            }
        }
        None => None,
    };

    autotuner.enabled = true;
    autotuner.mode = mode;
    if let Some(target) = validated_target {
        autotuner.target_value = target;
    }
    autotuner.status = format!("MQTT command accepted: {}", update.mode);
    drop(autotuner);
    drop(config);

    let (topic, payload) = command_state_echo(topics, &command);
    Some(MqttPublishOp {
        topic,
        payload,
        retain: true,
        qos: MqttQos::AtLeastOnce,
    })
}

/// Build the stable HA device identity from the current config (name/model/url
/// from board config + hostname/IP). `device_id` is MAC-derived and stable.
fn build_device(state: &SharedState, device_id: &str) -> HaDevice {
    let (name, model, hostname) = {
        let cfg = state.config.lock().unwrap_or_else(|e| e.into_inner());
        let board = cfg.board_config();
        let model_name = board.model.name();
        (
            format!("DCENT_axe {model_name}"),
            format!("{model_name} / {}", board.asic_model),
            cfg.hostname.clone(),
        )
    };

    // Prefer the live IP; fall back to <hostname>.local; else omit.
    let configuration_url = {
        let ip = state
            .telemetry
            .lock()
            .map(|t| t.device_ip.clone())
            .unwrap_or_else(|e| e.into_inner().device_ip.clone());
        if !ip.is_empty() {
            Some(format!("http://{ip}"))
        } else if !hostname.is_empty() {
            Some(format!("http://{hostname}.local"))
        } else {
            None
        }
    };

    HaDevice {
        device_id: device_id.to_string(),
        name,
        model,
        sw_version: env!("CARGO_PKG_VERSION").to_string(),
        configuration_url,
    }
}

/// Snapshot the live telemetry into the host-pure [`HaState`]. Snapshot-then-drop
/// each lock so we never hold one across a publish (panic=abort lock-safety).
/// `energy_kwh` is the cumulative lifetime energy from the caller-owned
/// [`EnergyAccumulator`] (integrated across ticks in `run_session`), so the meter
/// stays monotonic — it is NOT re-derived here per tick.
fn snapshot_state(state: &SharedState, energy_kwh: f64) -> HaState {
    let (hashrate_ghs, accepted, rejected) = {
        let stats = state.stats.lock().unwrap_or_else(|e| e.into_inner());
        let snap = stats.snapshot();
        (
            snap.hashrate_1m_ghs as f32,
            snap.accepted_shares,
            snap.rejected_shares,
        )
    };
    let (chip_temp_c, power_w, fan_rpm, uptime_s) = {
        let t = state.telemetry.lock().unwrap_or_else(|e| e.into_inner());
        (t.chip_temp_c, t.power_w, t.fan_rpm, t.uptime_secs)
    };
    let (board_version_recognized, support_status) = {
        let cfg = state.config.lock().unwrap_or_else(|e| e.into_inner());
        (
            cfg.board_version_recognized(),
            cfg.support_status().to_string(),
        )
    };

    HaState {
        hashrate_ghs,
        chip_temp_c,
        power_w,
        fan_rpm,
        accepted,
        rejected,
        uptime_s,
        energy_kwh,
        board_version_recognized,
        support_status,
    }
}
