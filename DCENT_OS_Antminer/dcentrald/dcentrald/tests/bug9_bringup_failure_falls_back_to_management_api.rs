//! BUG-9 (2026-06-05) — standard-daemon mining bring-up must be bounded and
//! fail closed without overstating management-plane availability.
//!
//! ## Live symptom that motivated this
//!
//! On a live S9 (am1, BM1387) freshly installed with DCENT_OS, the daemon
//! boots MANAGEMENT-ONLY (mining disabled by design — `mining_start_enabled()
//! == false`). After the operator completed the setup wizard (pool set, mining
//! enabled), restarting the daemon to ENGAGE mining made the `:8080` API go
//! DOWN and stay down 4+ minutes with no recovery — the S9 cold-boot
//! (PSU/PIC-enumerate/open-core, all blocking I²C/UART I/O) wedged the whole
//! daemon, INCLUDING the API server.
//!
//! ## Root cause (the structure this test pins)
//!
//! In `Daemon::run_lifecycle()` the API server (`start_api_servers`) is spawned
//! DEEP inside the function, AFTER the 7-phase hardware bring-up `init()`.
//! Unlike the hybrid / serial / stratum-proxy / am3-bb arms (which spawn the
//! API BEFORE the mining loop), the standard BraiinsOS-FPGA daemon arm (S9/am1
//! + am2-s17) has no API until `init()` returns. So a `init()` that HANGS
//! (documented S9 failure modes: "AXI IIC Controller Stuck State (SR=0xC0)",
//! "dead PICs burn the entire heartbeat budget", a stuck chain-UART RX) means
//! `start_api_servers` is NEVER reached → no dashboard, no recovery.
//!
//! ## The fix (two guards, both pinned below)
//!
//! (A) BOUND THE HANG: `init()` is raced against `resolve_init_timeout()`
//!     (`DEFAULT_INIT_TIMEOUT_SECS`, env-overridable via
//!     `DCENT_INIT_TIMEOUT_SECS`). An infinite wedge becomes a clean error in
//!     bounded time.
//!
//! (B) ATTEMPT TERMINAL SAFE-OFF: management-only is conditional on a positive
//!     terminal closeout. Current production init marks partial hardware state
//!     unknown, so an init failure normally remains ResetPending and exits for
//!     the external safety path. The coordinator's simulated management-only
//!     branch is retained for a future evidence-backed partial-bringup ledger.
//!
//! The hardware-independent coordinator in `daemon_lifecycle.rs` now owns and
//! runtime-tests the deadline and recovery ordering. This integration test only
//! pins the concrete daemon's delegation, the closed-gate API adapter, and the
//! honest production ResetPending boundary.

const DAEMON_RS: &str = include_str!("../src/daemon.rs");
const DAEMON_LIFECYCLE_RS: &str = include_str!("../src/daemon_lifecycle.rs");

/// (A) The `init()` await must be BOUNDED by a timeout — never a bare
/// `self.init().await?` that can hang forever. Pin that the bring-up is raced
/// against `resolve_init_timeout()` via `tokio::time::timeout`.
#[test]
fn bug9_standard_daemon_delegates_init_to_bounded_lifecycle_coordinator() {
    assert!(
        DAEMON_RS.contains("fn resolve_init_timeout()"),
        "BUG-9 (A): resolve_init_timeout() helper is missing — the hardware \
         bring-up timeout bound was removed"
    );
    assert!(
        DAEMON_RS.contains("const DEFAULT_INIT_TIMEOUT_SECS"),
        "BUG-9 (A): DEFAULT_INIT_TIMEOUT_SECS constant is missing"
    );
    assert!(DAEMON_RS.contains("crate::daemon_lifecycle::initialize_or_recover("));
    assert!(DAEMON_RS.contains("&crate::daemon_lifecycle::TokioLifecycleClock"));
    assert!(DAEMON_RS.contains("init_timeout,"));
    assert!(DAEMON_LIFECYCLE_RS
        .contains(".within(init_timeout, platform.initialize_platform(identity))"));
    assert!(DAEMON_LIFECYCLE_RS.contains("tokio::time::timeout(duration, future)"));

    // The OLD unbounded shape `self.init().await?` (a `?` directly on the await)
    // must NOT come back. We allow `self.init()` to appear (it is the argument to
    // timeout), but never the `?`-on-await form.
    assert!(
        !DAEMON_RS.contains("self.init().await?"),
        "BUG-9 (A) REGRESSION: the unbounded `self.init().await?` shape is back — \
         bring-up can hang forever and lock out the management plane"
    );
}

/// (A) The env override `DCENT_INIT_TIMEOUT_SECS` exists and is FLOORED so an
/// operator cannot accidentally set it to 0 (or a too-small value) and re-break
/// the no-hang guarantee. The override is for RAISING the bound on a slow lab
/// unit, not disabling it.
#[test]
fn bug9_init_timeout_env_override_is_floored() {
    assert!(
        DAEMON_RS.contains("DCENT_INIT_TIMEOUT_SECS"),
        "BUG-9 (A): the DCENT_INIT_TIMEOUT_SECS env override is missing"
    );
    let helper_start = DAEMON_RS
        .find("fn resolve_init_timeout()")
        .expect("resolve_init_timeout missing");
    // Bound the inspection to the helper body (next `\nfn ` or `\nconst ` after it).
    let rest = &DAEMON_RS[helper_start..];
    let helper_end = rest[3..].find("\nfn ").map(|i| i + 3).unwrap_or(rest.len());
    let body = &rest[..helper_end];
    assert!(
        body.contains(".filter(|&s| s > 0)") || body.contains("s > 0"),
        "BUG-9 (A): resolve_init_timeout must reject 0 (a 0-second timeout would \
         instantly false-trip and re-break bring-up)"
    );
    assert!(
        body.contains(".max(10)"),
        "BUG-9 (A): resolve_init_timeout must floor the env override (e.g. .max(10)) \
         so a too-small value can't false-trip on a healthy unit"
    );
}

/// The fall-back uses the existing `run_api_only()` wrapper, which delegates to
/// a closed hardware-mutation-gate helper that owns `start_api_servers`. Pin the
/// management-plane liveness and fail-closed mutation posture together.
#[test]
fn bug9_run_api_only_spawns_the_api_server() {
    let api_only = DAEMON_RS
        .find("async fn run_api_only(")
        .expect("run_api_only definition missing");
    // Bound to the function body up to the next `\n    async fn ` / `\n    fn `.
    let rest = &DAEMON_RS[api_only..];
    let end = rest[10..]
        .find("\n    async fn ")
        .or_else(|| rest[10..].find("\n    fn "))
        .map(|i| i + 10)
        .unwrap_or(rest.len());
    let body = &rest[..end];
    assert!(
        body.contains("run_api_only_with_hardware_mutation_gate")
            && body.contains("HardwareMutationGate::new_closed()"),
        "BUG-9 (B): run_api_only() must delegate to the closed-gate management API helper"
    );

    let helper = DAEMON_RS
        .find("async fn run_api_only_with_hardware_mutation_gate(")
        .expect("closed-gate API helper missing");
    let helper_rest = &DAEMON_RS[helper..];
    let helper_end = helper_rest[10..]
        .find("\n    async fn ")
        .or_else(|| helper_rest[10..].find("\n    fn "))
        .map(|i| i + 10)
        .unwrap_or(helper_rest.len());
    assert!(
        helper_rest[..helper_end].contains("start_api_servers"),
        "BUG-9 (B): the closed-gate helper must spawn the management API"
    );
}

/// Do not regress the current honest boundary into an unsupported claim that
/// arbitrary partial initialization can safely park in management-only mode.
#[test]
fn bug9_production_partial_init_remains_reset_pending_without_a_safety_ledger() {
    assert!(DAEMON_RS.contains("self.preflight_hardware_state_unknown = true;"));
    assert!(DAEMON_RS
        .contains("let mut software_disable_failed = self.preflight_hardware_state_unknown"));
    assert!(
        DAEMON_RS.contains("shutdown safety evidence is incomplete; terminal closeout is unproven")
    );
    assert!(DAEMON_LIFECYCLE_RS.contains("management-only is forbidden"));
}
