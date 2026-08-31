//! Pure MQTT TLS-scheme + RELEASE command-admission helpers.
//!
//! Host-testable without HAL / rumqttc. `mqtt.rs` owns the transport wiring.

/// MQTT-TLS-DOWNGRADE-1: true when the broker URL scheme requests encrypted
/// transport. `mqtt.rs::parse_broker_url` strips the scheme, so connect sites
/// check this separately and fail closed rather than silently downgrade.
pub fn broker_url_requires_tls(url: &str) -> bool {
    let t = url.trim();
    t.starts_with("mqtts://") || t.starts_with("ssl://") || t.starts_with("tls://")
}

/// Token files that admit MQTT *command* writes on a RELEASE image.
/// Minted by `mcp_server.py --mint-token` (same secret as MCP/gRPC).
pub const MQTT_COMMAND_TOKEN_PATHS: &[&str] = &[
    "/data/dcent/mqtt_token",
    "/data/dcent/mcp_token",
    "/run/dcentos/mcp_token",
];

/// Command subscriber admission.
///
/// DEV/lab (`is_release == false`): sink present is enough (MQTT still
/// default-OFF in config). RELEASE: refuse commands unless a minted token
/// file exists — the broker is not an authenticated operator.
pub fn mqtt_commands_admitted(sink_present: bool, is_release: bool, token_present: bool) -> bool {
    sink_present && (!is_release || token_present)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_requesting_schemes_are_detected() {
        for url in [
            "mqtts://broker.example:8883",
            "ssl://broker.example:8883",
            "tls://broker.example:8883",
            "  mqtts://broker.example:8883  ",
        ] {
            assert!(
                broker_url_requires_tls(url),
                "{url} must be detected as TLS-requesting"
            );
        }
    }

    #[test]
    fn plaintext_schemes_do_not_trip_the_tls_guard() {
        for url in [
            "mqtt://broker.example:1883",
            "tcp://broker.example:1883",
            "broker.example:1883",
            "broker.example",
        ] {
            assert!(
                !broker_url_requires_tls(url),
                "{url} is plaintext and must not trip the TLS guard"
            );
        }
    }

    #[test]
    fn release_mqtt_commands_refuse_without_token() {
        assert!(!mqtt_commands_admitted(true, true, false));
        assert!(mqtt_commands_admitted(true, true, true));
        assert!(mqtt_commands_admitted(true, false, false));
        assert!(!mqtt_commands_admitted(false, false, true));
        assert!(!mqtt_commands_admitted(false, true, true));
    }
}
