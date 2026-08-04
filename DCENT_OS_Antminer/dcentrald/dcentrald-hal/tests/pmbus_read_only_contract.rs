//! Source contract: `dcentrald-hal::pmbus` must stay a **read-only** layer.
//!
//! This file deliberately lives outside `src/pmbus.rs` and inspects that file
//! as data. A source contract that `include_str!`s its own file self-matches:
//! negative assertions fail against their own text and positive ones keep
//! passing after the invariant is deleted. Reading a *different* file avoids
//! both traps, so the forbidden mnemonics below may be spelled out here and
//! nowhere in the module under test.
//!
//! Companion in-module proofs (`src/pmbus.rs` `mod tests`) pin the numeric
//! side: every emitted command code sits in the PMBus read/status/identity
//! region, and no state-changing code is reachable from `PmbusReadCommand`.
//! This file pins the textual side: no encoder, no write-shaped bus call, no
//! state-changing mnemonic anywhere in the module.

use dcentrald_hal::pmbus::{
    PmbusPsuFamily, PmbusReadCommand, PmbusTelemetryGate,
    CANDIDATE_PROTO_V1_MEASURE_CURRENT_UNPROBED, PMBUS_PSU_I2C_ADDRESS,
};

const PMBUS_SOURCE: &str = include_str!("../src/pmbus.rs");

/// Slice off the `#[cfg(test)]` module so the contract applies to the shipped
/// production region only, and so test fixtures can name whatever they need.
fn production_region() -> &'static str {
    match PMBUS_SOURCE.find("#[cfg(test)]") {
        Some(index) => &PMBUS_SOURCE[..index],
        None => PMBUS_SOURCE,
    }
}

#[test]
fn the_module_names_no_state_changing_pmbus_command() {
    // Every PMBus command that changes device state, latches configuration,
    // clears fault history, or commits to non-volatile memory. None of these
    // may appear anywhere in the module — not as a constant, not as an enum
    // variant, not even as a commented-out "future work" note, because a
    // named opcode is one careless edit away from being dispatched.
    const FORBIDDEN_MNEMONICS: &[&str] = &[
        "OPERATION",
        "ON_OFF_CONFIG",
        "CLEAR_FAULTS",
        "VOUT_COMMAND",
        "VOUT_TRIM",
        "VOUT_CAL_OFFSET",
        "VOUT_MAX",
        "VOUT_MARGIN_HIGH",
        "VOUT_MARGIN_LOW",
        "VOUT_TRANSITION_RATE",
        "VOUT_DROOP",
        "VOUT_SCALE_LOOP",
        "VOUT_SCALE_MONITOR",
        "STORE_DEFAULT_ALL",
        "RESTORE_DEFAULT_ALL",
        "STORE_USER_ALL",
        "RESTORE_USER_ALL",
        "STORE_DEFAULT_CODE",
        "RESTORE_DEFAULT_CODE",
        "WRITE_PROTECT",
        "FREQUENCY_SWITCH",
        "IOUT_OC_FAULT_LIMIT",
        "OT_FAULT_LIMIT",
        "VIN_ON",
        "VIN_OFF",
        "TON_DELAY",
        "TOFF_DELAY",
        "FAN_COMMAND_1",
        "FAN_CONFIG_1_2",
    ];
    let source = production_region();
    for mnemonic in FORBIDDEN_MNEMONICS {
        assert!(
            !source.contains(mnemonic),
            "src/pmbus.rs names the state-changing PMBus command {mnemonic}; \
             this layer is read-only and must not define, document, or \
             dispatch it"
        );
    }
}

#[test]
fn the_module_makes_no_write_shaped_bus_call() {
    // A PMBus read is an SMBus Read Byte/Word/Block: the command code goes out
    // as a register pointer, then a repeated START reads the payload. That is
    // exactly one bus API — `write_read_mutating`, labelled `QueryPrelude`.
    // Any other write-shaped call would be a payload-bearing command.
    const FORBIDDEN_CALLS: &[&str] = &[
        ".write_bytes(",
        ".write_byte_by_byte(",
        ".write_bytes_mutating(",
        ".write_byte_by_byte_mutating(",
        ".transaction(",
        ".transaction_with_intent(",
        "write_bytes_with_intent",
        "I2cBus::open",
        "open_for_recovery",
        "/dev/mem",
        "set_write_denylist",
    ];
    let source = production_region();
    for call in FORBIDDEN_CALLS {
        assert!(
            !source.contains(call),
            "src/pmbus.rs contains `{call}`; the PMBus layer must reach the \
             bus only through the shared I2C service's read path and must \
             never open, bypass, or reconfigure it"
        );
    }
    assert_eq!(
        source.matches("write_read_mutating").count(),
        1,
        "src/pmbus.rs must contain exactly one bus call site — the SMBus \
         command-pointer read"
    );
}

#[test]
fn the_module_defines_no_encoder() {
    // Decoding turns device bytes into numbers. Encoding turns numbers into
    // device bytes, which is only ever useful for writing. There must be no
    // encoder here at all.
    const FORBIDDEN_ENCODERS: &[&str] = &[
        "fn from_f64",
        "fn from_f32",
        "fn encode",
        "fn to_slinear11",
        "fn to_ulinear16",
        "fn to_linear11",
        "fn to_linear16",
    ];
    let source = production_region();
    for encoder in FORBIDDEN_ENCODERS {
        assert!(
            !source.contains(encoder),
            "src/pmbus.rs defines `{encoder}`; a value-to-wire encoder has no \
             read-only purpose and is the seed of a write path"
        );
    }
}

#[test]
fn the_read_transport_trait_exposes_exactly_one_method() {
    let source = production_region();
    let trait_start = source
        .find("pub trait PmbusReadTransport")
        .expect("PmbusReadTransport trait must exist");
    let trait_body = &source[trait_start..];
    let trait_end = trait_body
        .find("\n}")
        .expect("PmbusReadTransport trait must be closed");
    let trait_body = &trait_body[..trait_end];
    assert_eq!(
        trait_body.matches("fn ").count(),
        1,
        "PmbusReadTransport must expose exactly one method so no write \
         capability can hide behind the abstraction: {trait_body}"
    );
    assert!(
        trait_body.contains("fn read_command_payload"),
        "the sole PmbusReadTransport method must be the read"
    );
}

#[test]
fn the_module_never_substitutes_a_zero_for_a_failed_read() {
    // `unwrap_or`-family calls on a `Measured` are exactly how a bus error
    // becomes a plausible-looking `0 V`. None may exist.
    const FORBIDDEN_DEFAULTS: &[&str] = &[
        "unwrap_or(0",
        "unwrap_or_default()",
        "unwrap_or_else(|| 0",
        ".unwrap_or(0.0)",
    ];
    let source = production_region();
    for pattern in FORBIDDEN_DEFAULTS {
        assert!(
            !source.contains(pattern),
            "src/pmbus.rs contains `{pattern}`; an absent measurement must \
             stay typed-unknown and must never become a number"
        );
    }
}

#[test]
fn the_module_carries_its_experimental_marking() {
    let source = production_region();
    assert!(
        source.contains("EXPERIMENTAL"),
        "the PMBus layer must stay marked experimental until live-verified"
    );
    assert!(
        source.contains("DESK-EVIDENCE"),
        "the PMBus layer must stay marked DESK-EVIDENCE until live-verified"
    );
}

#[test]
fn the_gate_is_default_off_from_the_public_api() {
    assert_eq!(PmbusTelemetryGate::default(), PmbusTelemetryGate::Disabled);
    assert!(!PmbusTelemetryGate::default().is_enabled());
    assert!(!PmbusTelemetryGate::from_raw(None).is_enabled());
    assert!(PmbusTelemetryGate::from_raw(Some("1")).is_enabled());
}

#[test]
fn the_public_command_surface_is_read_only_by_code() {
    // Re-asserted across the crate boundary: a downstream crate can only ever
    // reach these codes, all of which are PMBus reads.
    for command in PmbusReadCommand::ALL {
        let code = command.code();
        let is_read_region = code == 0x20 || (0x79..=0x7F).contains(&code) || code >= 0x88;
        assert!(
            is_read_region,
            "{} (0x{code:02X}) escapes the read/status/identity region",
            command.mnemonic()
        );
        assert_ne!(code, CANDIDATE_PROTO_V1_MEASURE_CURRENT_UNPROBED);
    }
}

#[test]
fn every_covered_family_is_pinned_to_the_catalog_address() {
    assert_eq!(PMBUS_PSU_I2C_ADDRESS, 0x58);
    let models: Vec<&str> = PmbusPsuFamily::ALL.iter().map(|f| f.model()).collect();
    assert_eq!(models, vec!["APW3++", "APW7", "APW9", "APW10", "APW11"]);
    for family in PmbusPsuFamily::ALL {
        assert_eq!(family.i2c_address(), PMBUS_PSU_I2C_ADDRESS);
    }
}
