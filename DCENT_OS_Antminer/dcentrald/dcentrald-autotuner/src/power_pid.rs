//! Closed-loop watt-anchored power-target controller (PID).
//!
//! Reference behavior studied (NOT yet matched): **LuxOS power-targeting PID** /
//! **BraiinsOS power-target mode**. Both actuate frequency *and* per-domain
//! voltage along silicon characterization curves with PSU-measured feedback; this
//! module is a **closed-loop building block** toward that goal, not parity with
//! it. Given a watt setpoint it reads `error = target − measured`, drives a PID
//! whose output is a commanded power budget, and converges within a bounded error
//! band *without* violating the operating-point / PVT envelope — but it trims
//! **frequency only at a fixed voltage**. `AutoTuner::apply_target_mode`
//! (`TuneTarget::Power`) now drives [`allocate_power_target_step`]: estimate-only
//! samples HOLD to the derated feed-forward; a PMBus/ADC sample closes the PID.
//! Voltage actuation along silicon curves remains a follow-on (gauntlet #2).
//!
//! # What was missing before this module
//!
//! The `TunerMode::PowerTarget { watts }` path in
//! [`crate::tuner::AutoTuner::apply_target_mode`] is pure **feed-forward**: it
//! runs [`PowerModel::allocate_budget_safe`](crate::power_budget::PowerModel::allocate_budget_safe)
//! exactly once from the CMOS `C_eff·V²·f` model and applies the result. The
//! model carries a documented ±10 % error (and, on an uncalibrated miner, a
//! family safety derate), so the *actual* measured draw can sit well off the
//! setpoint with no term that ever closes the gap. There is no closed loop that
//! reads `error = target − measured` and drives a correction back toward the
//! target.
//!
//! This module adds exactly that closed loop. It reads the error, drives a PID
//! whose output is a **commanded power budget** (watts), clamps that budget to
//! the achievable [`PowerEnvelope`], and feeds it back through the existing
//! [`PowerModel::allocate_budget`](crate::power_budget::PowerModel::allocate_budget)
//! so the per-chip frequencies converge until measured ≈ target — even when the
//! feed-forward model is biased.
//!
//! # Design invariants
//!
//! - **Pure + host-testable.** No clock, no HAL, no randomness. Time is an
//!   injected `dt` (a tick count), so a deterministic simulation can run the
//!   loop for N steps and assert convergence. The controller consumes an
//!   *injected* power measurement each tick — it never reads hardware.
//! - **Measurement-provenance gate.** The loop refuses to close on a sample it
//!   cannot trust. [`WattTargetController::step`] takes a
//!   [`PowerAuthoritySample`](crate::power_budget::PowerAuthoritySample); unless
//!   the sample is measured (PMBus/ADC) or a wall-meter-anchored estimate
//!   ([`PowerAuthorityKind::is_control_authoritative`](crate::power_budget::PowerAuthorityKind::is_control_authoritative)),
//!   the loop **HOLDs** — it freezes the integral and re-issues its last
//!   command. Rationale: where no real measurement exists, the "measured" input
//!   is the model's *own* feed-forward, so the loop would be a tautology chasing
//!   itself; and the normal path uses `allocate_budget` (NOT `_safe`), so an
//!   unmeasured source would also silently drop the uncalibrated safety derate.
//! - **The envelope is a hard clamp, never a suggestion.** The commanded budget
//!   is clamped to `[floor_watts, ceiling_watts]` from the operating-point / PVT
//!   envelope. A physically impossible watt target saturates at the ceiling —
//!   the loop reports `saturated_high` and runs every chip at its envelope
//!   ceiling; it never overclocks past the envelope to chase an unreachable
//!   number.
//! - **Anti-windup on the integral term.** Two independent guards: (1)
//!   *conditional integration* — the integral is frozen whenever the command is
//!   limited (by the envelope or the slew limiter) in the same direction as the
//!   error, so it cannot charge into a saturated rail; and (2) an absolute
//!   integral clamp. Together they stop the classic post-saturation overshoot.
//! - **Bounded, gradual actuation (finite by default).** A per-tick slew-rate
//!   limit bounds how fast the commanded power may move. The constructor
//!   defaults to a **finite** limit (a fraction of the envelope span per tick),
//!   matching the project's "gradual ramp / cut hash before noise" philosophy
//!   and keeping overshoot small under telemetry delay. (The old default of
//!   `INFINITY` measured 17.9 % overshoot — 31 % with a 2-tick telemetry delay —
//!   a footgun for the circuit-cap use case.) A no-slew mode stays available for
//!   tests that intentionally exercise the raw PID law.
//! - **Divergence watchdog.** A saturating oscillation that never converges (the
//!   probe saw a permanent limit cycle at 3× gain with no detection) is caught:
//!   after `N` consecutive out-of-band ticks with sustained-amplitude sign
//!   flips, the controller falls back to the derated `allocate_budget_safe`
//!   feed-forward. The fallback can never overclock past the envelope.
//! - **Default-inert.** Nothing here is wired into the live tuner runtime; it is
//!   opt-in and changes no existing default. Daemon wiring is a later round.
//!
//! # Composition with the DPS walker (design note — NOT wired here)
//!
//! Two ramp authorities exist in this crate over the *same* actuator (a power
//! target that resolves to per-chip frequency): this PID's per-tick **slew
//! limit**, and the DPS walker's discrete **`power_step_w`** move
//! ([`crate::dps::DpsWalkerConfig`], driven by
//! [`crate::dps_governor::DpsGovernor`]). If both actuated frequency on the same
//! tick they would fight — each would see the other's move as plant disturbance,
//! and the two ramp rates would beat against each other.
//!
//! The composition rule when this controller is eventually daemon-wired is
//! **mutual exclusion of slew ownership, chosen at the mode layer — never
//! simultaneous frequency writes:**
//!
//! - In **power-target mode**, *this* watt-PID owns the ramp: its slew limit is
//!   the sole per-tick rate authority, and the DPS governor is suspended (it
//!   must not also walk `power_target`). The PID's commanded budget already
//!   respects `min_power`/`max_power` via the envelope clamp.
//! - In **DPS mode** (thermal/curtailment-driven scaling), the
//!   [`DpsGovernor`](crate::dps_governor::DpsGovernor) owns the ramp via its
//!   `power_step_w` walk, and this watt-PID does not run.
//! - The two never co-actuate. If a future design wants DPS to *bound* the
//!   watt-PID (e.g. a thermal cap lowering the ceiling), it does so by lowering
//!   the PID's **envelope** (`pvt_ceiling_mhz` / a reduced ceiling), not by
//!   independently writing frequency — so there remains exactly one slew source.
//!
//! This is a design note only; no DPS wiring is added by this module.

use crate::power_budget::{PowerAuthorityKind, PowerAuthoritySample, PowerEnvelope, PowerModel};
use crate::profile::ChipProfile;
use std::collections::VecDeque;

/// PID gains for the watt-target loop.
///
/// The proportional term multiplies a *watt error* to produce a *watt budget*
/// correction, so `kp` is roughly dimensionless (≈ how hard to push per watt of
/// miss). `ki` and `kd` are scaled by the injected `dt`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PidGains {
    /// Proportional gain (watt-budget correction per watt of error).
    pub kp: f64,
    /// Integral gain (per injected `dt` tick).
    pub ki: f64,
    /// Derivative gain (per injected `dt` tick). Applied to the *measurement*
    /// derivative (not the error derivative) so a setpoint step does not kick
    /// the output.
    pub kd: f64,
}

impl PidGains {
    /// Conservative gains tuned for the near-unity plant gain of the watt loop.
    ///
    /// The plant gain (commanded budget → measured power) is ≈ ×1 because both
    /// scale ~linearly with the allocated dynamic budget. Feed-forward carries
    /// the bulk of the command (= the setpoint); P + I trim the residual model
    /// bias; a small D damps the approach. Chosen for a well-damped step
    /// response that settles with no meaningful overshoot when paired with the
    /// default slew limiter.
    pub const fn default_watt_loop() -> Self {
        Self {
            kp: 0.10,
            ki: 0.20,
            kd: 0.05,
        }
    }

    /// Scale all three gains by a common factor (test/diagnostic helper — a
    /// factor `> 1` deliberately de-tunes the loop toward oscillation).
    pub fn scaled(self, factor: f64) -> Self {
        Self {
            kp: self.kp * factor,
            ki: self.ki * factor,
            kd: self.kd * factor,
        }
    }
}

impl Default for PidGains {
    fn default() -> Self {
        Self::default_watt_loop()
    }
}

/// One command produced by [`WattTargetPid::update`].
#[derive(Debug, Clone, Copy)]
pub struct WattCommand {
    /// Commanded board-power budget (watts), after envelope + slew clamping.
    /// Feed this to `allocate_budget`.
    pub commanded_watts: f64,
    /// Error term this tick (`target − measured`).
    pub error_watts: f64,
    /// The PID's desired command *before* the envelope / slew clamp (diagnostic).
    pub desired_watts: f64,
    /// Proportional contribution.
    pub p_term: f64,
    /// Integral contribution.
    pub i_term: f64,
    /// Derivative contribution.
    pub d_term: f64,
    /// `true` when the command is pinned at the envelope ceiling with unmet
    /// upward demand — i.e. the target is unreachable-high for this envelope.
    pub saturated_high: bool,
    /// `true` when the command is pinned at the envelope floor with unmet
    /// downward demand.
    pub saturated_low: bool,
}

impl WattCommand {
    /// A synthesized command for the controller's HOLD / watchdog-fallback paths
    /// (where the PID law did NOT run this tick). The P/I/D terms are zero and
    /// no saturation is reported because no closed-loop step was taken.
    fn synthesized(commanded_watts: f64, error_watts: f64, desired_watts: f64) -> Self {
        Self {
            commanded_watts,
            error_watts,
            desired_watts,
            p_term: 0.0,
            i_term: 0.0,
            d_term: 0.0,
            saturated_high: false,
            saturated_low: false,
        }
    }
}

/// Pure discrete PID controller for the watt-target loop.
///
/// Positional form with feed-forward = setpoint, derivative-on-measurement,
/// conditional-integration + clamp anti-windup, an envelope output clamp, and a
/// per-tick slew-rate limit (finite by default). Deterministic: no clock, no
/// randomness.
#[derive(Debug, Clone)]
pub struct WattTargetPid {
    gains: PidGains,
    dt: f64,
    /// Absolute clamp on the integral accumulator (watt·ticks). `INFINITY` =
    /// rely solely on conditional integration.
    integral_limit: f64,
    /// Absolute max change in commanded watts per tick. `INFINITY` = no absolute
    /// override → defer to `slew_frac`.
    slew_limit: f64,
    /// Default per-tick slew cap expressed as a fraction of the envelope span,
    /// used whenever `slew_limit` is not a finite absolute override. `None` =
    /// no slew limit at all (pure PID). Constructed as
    /// `Some(DEFAULT_SLEW_FRAC)` so a fresh controller is finite-slew by
    /// default without needing to know the absolute watt scale up front.
    slew_frac: Option<f64>,
    integral: f64,
    prev_measured: Option<f64>,
    prev_command: Option<f64>,
    initialized: bool,
}

impl WattTargetPid {
    /// Default injected time step (one tick).
    pub const DEFAULT_DT: f64 = 1.0;
    /// Default per-tick slew cap as a fraction of the envelope span. A fresh
    /// controller may move at most 10 % of `[floor, ceiling]` per tick, which
    /// tames overshoot under telemetry delay while still ramping in ~10 ticks.
    pub const DEFAULT_SLEW_FRAC: f64 = 0.10;
    const SAT_EPS: f64 = 1e-9;

    /// New controller with the default watt-loop gains, a **finite** default
    /// slew (10 % of the envelope span per tick), and no integral clamp (pure
    /// conditional-integration anti-windup).
    pub fn new() -> Self {
        Self::with_gains(PidGains::default_watt_loop())
    }

    /// New controller with explicit gains (finite default slew, as [`Self::new`]).
    pub fn with_gains(gains: PidGains) -> Self {
        Self {
            gains,
            dt: Self::DEFAULT_DT,
            integral_limit: f64::INFINITY,
            slew_limit: f64::INFINITY,
            slew_frac: Some(Self::DEFAULT_SLEW_FRAC),
            integral: 0.0,
            prev_measured: None,
            prev_command: None,
            initialized: false,
        }
    }

    /// Override the injected time step (a tick count; must be finite and `> 0`).
    /// Non-positive / non-finite values are ignored (keeps [`Self::DEFAULT_DT`]).
    pub fn with_dt(mut self, dt: f64) -> Self {
        if dt.is_finite() && dt > 0.0 {
            self.dt = dt;
        }
        self
    }

    /// Set an absolute anti-windup clamp on the integral accumulator, in
    /// integral-of-error units (watt·ticks). Non-finite / negative ignored.
    pub fn with_integral_limit(mut self, limit: f64) -> Self {
        if limit.is_finite() && limit >= 0.0 {
            self.integral_limit = limit;
        }
        self
    }

    /// Set an **absolute** per-tick slew-rate limit on the commanded watts (must
    /// be finite and `> 0`; non-positive / non-finite ignored). A finite
    /// absolute value takes precedence over the fractional default and bounds
    /// how fast the command may move.
    pub fn with_slew_limit(mut self, watts_per_tick: f64) -> Self {
        if watts_per_tick.is_finite() && watts_per_tick > 0.0 {
            self.slew_limit = watts_per_tick;
        }
        self
    }

    /// Set the **fractional** per-tick slew cap (fraction of the envelope span,
    /// applied when no absolute `with_slew_limit` override is set). Must be
    /// finite and `> 0`; otherwise ignored.
    pub fn with_slew_frac(mut self, frac: f64) -> Self {
        if frac.is_finite() && frac > 0.0 {
            self.slew_frac = Some(frac);
        }
        self
    }

    /// Disable slew limiting entirely (pure PID — the command jumps straight to
    /// the envelope-clamped desired value each tick). This is the explicit
    /// opt-out of the finite default; use it only where the raw PID law is the
    /// thing under test.
    pub fn with_no_slew(mut self) -> Self {
        self.slew_limit = f64::INFINITY;
        self.slew_frac = None;
        self
    }

    /// Reset all loop state (integral, history). Gains / limits are retained.
    pub fn reset(&mut self) {
        self.integral = 0.0;
        self.prev_measured = None;
        self.prev_command = None;
        self.initialized = false;
    }

    /// Reset only the integral accumulator (used by the divergence-watchdog
    /// fallback so a wound-up integral cannot relaunch a swing on recovery).
    fn reset_integral(&mut self) {
        self.integral = 0.0;
    }

    /// Overwrite the "last command" the slew limiter ramps from. Used by the
    /// controller's fallback path so a resumed PID ramps from where the safe
    /// feed-forward actually left the hardware.
    fn set_prev_command(&mut self, watts: f64) {
        if watts.is_finite() {
            self.prev_command = Some(watts);
        }
    }

    /// Current integral accumulator (watt·ticks).
    pub fn integral(&self) -> f64 {
        self.integral
    }

    /// The last commanded budget (watts), or `None` before the first actuation.
    /// The provenance HOLD path re-issues this verbatim.
    pub fn last_command(&self) -> Option<f64> {
        self.prev_command
    }

    /// Configured gains.
    pub fn gains(&self) -> PidGains {
        self.gains
    }

    /// The effective per-tick slew cap (watts) for a given envelope: the
    /// absolute override if finite, else the fractional default × span, else
    /// `INFINITY`. A degenerate (zero-span) envelope collapses to `INFINITY` so
    /// the envelope clamp alone governs.
    fn effective_slew(&self, envelope: PowerEnvelope) -> f64 {
        if self.slew_limit.is_finite() {
            self.slew_limit
        } else if let Some(frac) = self.slew_frac {
            let s = envelope.span_watts() * frac;
            if s > 0.0 {
                s
            } else {
                f64::INFINITY
            }
        } else {
            f64::INFINITY
        }
    }

    /// Run one control tick.
    ///
    /// `target_watts` — the setpoint. `measured_watts` — the latest measured or
    /// estimated board power (injected; the controller never reads hardware).
    /// `envelope` — the achievable-power clamp for the current chip set.
    ///
    /// Returns the [`WattCommand`] whose `commanded_watts` should be fed to
    /// `allocate_budget`.
    pub fn update(
        &mut self,
        target_watts: f64,
        measured_watts: f64,
        envelope: PowerEnvelope,
    ) -> WattCommand {
        // Sanitize inputs. A non-finite target is treated as 0 (no drive). A
        // non-finite measurement is treated as "no new information": use the
        // target as the measurement (error 0) so a transient bad reading can
        // neither wind up the integral nor kick the derivative.
        let target = if target_watts.is_finite() {
            target_watts
        } else {
            0.0
        };
        let measured = if measured_watts.is_finite() {
            measured_watts
        } else {
            // No new information: hold the last finite measurement (or the
            // target on the very first tick) so a transient bad reading neither
            // kicks the derivative (measured == prev ⇒ d = 0) nor winds the
            // integral when we were already settled (error == 0).
            self.prev_measured.unwrap_or(target)
        };

        let error = target - measured;

        // Derivative on measurement (negated): with a constant target,
        // d(error)/dt = −d(measured)/dt. Using the measurement derivative avoids
        // a derivative "kick" when the target steps.
        let d_measured = match self.prev_measured {
            Some(prev) if self.initialized => (measured - prev) / self.dt,
            _ => 0.0,
        };
        let d_term = -self.gains.kd * d_measured;

        // Tentative integral (committed below only if anti-windup allows).
        let integral_candidate =
            (self.integral + error * self.dt).clamp(-self.integral_limit, self.integral_limit);

        let p_term = self.gains.kp * error;
        let i_term = self.gains.ki * integral_candidate;

        // Feed-forward = target: an unbiased model would draw the target when
        // commanded the target budget; P/I/D trim the residual bias.
        let desired = target + p_term + i_term + d_term;

        // 1) Clamp to the achievable envelope (hard operating-point limit).
        let env_clamped = envelope.clamp(desired);

        // 2) Slew-limit relative to the previous command. On the first tick,
        // start the ramp from where we already are (the measured power, clamped
        // into the envelope) so a large initial gap does not slam the command.
        let prev_command = self
            .prev_command
            .unwrap_or_else(|| envelope.clamp(measured));
        let slew = self.effective_slew(envelope);
        let slewed = if slew.is_finite() {
            let delta = (env_clamped - prev_command).clamp(-slew, slew);
            prev_command + delta
        } else {
            env_clamped
        };
        // Belt-and-suspenders: the slewed value must still be inside the envelope.
        let commanded = envelope.clamp(slewed);

        // Was the command limited below / above what the PID actually wanted?
        // (Covers BOTH the envelope clamp and the slew limiter.)
        let limited_high = commanded < desired - Self::SAT_EPS;
        let limited_low = commanded > desired + Self::SAT_EPS;

        // Envelope-specific saturation (for callers / the impossible-target
        // path): pinned at a rail with unmet demand in that direction.
        let saturated_high = commanded >= envelope.ceiling_watts - Self::SAT_EPS
            && desired > commanded + Self::SAT_EPS;
        let saturated_low = commanded <= envelope.floor_watts + Self::SAT_EPS
            && desired < commanded - Self::SAT_EPS;

        // Anti-windup (conditional integration): commit the new integral only
        // when the command is NOT limited, OR when the error would drive the
        // command back OUT of the limit (error sign opposes the limited
        // direction). Otherwise freeze it so it cannot charge further into the
        // rail — which is what would cause post-saturation overshoot.
        let drives_out_of_high = limited_high && error < 0.0;
        let drives_out_of_low = limited_low && error > 0.0;
        if (!limited_high && !limited_low) || drives_out_of_high || drives_out_of_low {
            self.integral = integral_candidate;
        }

        self.prev_measured = Some(measured);
        self.prev_command = Some(commanded);
        self.initialized = true;

        WattCommand {
            commanded_watts: commanded,
            error_watts: error,
            desired_watts: desired,
            p_term,
            i_term,
            d_term,
            saturated_high,
            saturated_low,
        }
    }
}

impl Default for WattTargetPid {
    fn default() -> Self {
        Self::new()
    }
}

/// Sustained-non-convergence detector for the closed watt loop.
///
/// A healthy loop converges into a band and stays there. A mistuned loop (the
/// probe drove it to a permanent limit cycle at 3× gain) sits *outside* the band
/// forever, oscillating with roughly constant amplitude. This watchdog trips
/// when it sees that pattern — `window` consecutive out-of-band ticks, at least
/// `min_sign_flips` error sign changes across the window, and an amplitude that
/// is **not shrinking** (a converging/ringing loop shrinks its amplitude each
/// swing and is deliberately NOT flagged). When it trips, the controller falls
/// back to the derated `allocate_budget_safe` feed-forward, which can never
/// overclock past the envelope.
#[derive(Debug, Clone)]
pub struct DivergenceWatchdog {
    /// Convergence band as a fraction of `|target|`.
    band_frac: f64,
    /// Consecutive out-of-band ticks required before a trip can be declared.
    window: usize,
    /// Minimum error sign flips within the window to count as oscillation.
    min_sign_flips: usize,
    /// Recent errors while continuously outside the band (cleared on any in-band
    /// tick). Length is bounded by `window`.
    recent: VecDeque<f64>,
    tripped: bool,
}

impl DivergenceWatchdog {
    /// Default convergence band (5 % of target).
    pub const DEFAULT_BAND_FRAC: f64 = 0.05;
    /// Default patience: consecutive out-of-band ticks before a trip.
    pub const DEFAULT_WINDOW: usize = 12;
    /// Default oscillation threshold: sign flips within the window.
    pub const DEFAULT_MIN_SIGN_FLIPS: usize = 4;
    /// The recent-half peak error must stay at least this fraction of the
    /// older-half peak for the amplitude to count as "not shrinking".
    const AMPLITUDE_SHRINK_FLOOR: f64 = 0.9;

    pub fn new() -> Self {
        Self::with_params(
            Self::DEFAULT_BAND_FRAC,
            Self::DEFAULT_WINDOW,
            Self::DEFAULT_MIN_SIGN_FLIPS,
        )
    }

    /// Construct with explicit parameters (sanitized: band `> 0`, window `>= 2`,
    /// flips `>= 1`).
    pub fn with_params(band_frac: f64, window: usize, min_sign_flips: usize) -> Self {
        Self {
            band_frac: if band_frac.is_finite() && band_frac > 0.0 {
                band_frac
            } else {
                Self::DEFAULT_BAND_FRAC
            },
            window: window.max(2),
            min_sign_flips: min_sign_flips.max(1),
            recent: VecDeque::new(),
            tripped: false,
        }
    }

    /// Whether the watchdog is currently latched into the diverged state.
    pub fn tripped(&self) -> bool {
        self.tripped
    }

    /// Clear all state (used on a deliberate reset / setpoint change).
    pub fn reset(&mut self) {
        self.recent.clear();
        self.tripped = false;
    }

    /// Fold one authoritative `error = target − measured` tick in and return the
    /// current tripped state. Non-finite / zero-target ticks are neutral (they
    /// neither advance toward a trip nor clear an existing latch).
    pub fn observe(&mut self, error: f64, target: f64) -> bool {
        if !(target.is_finite() && target.abs() > 0.0) || !error.is_finite() {
            return self.tripped;
        }
        let band = self.band_frac * target.abs();
        if error.abs() <= band {
            // Converged this tick → clear the latch and the evidence window.
            self.recent.clear();
            self.tripped = false;
            return false;
        }
        // Outside the band → accumulate evidence.
        self.recent.push_back(error);
        while self.recent.len() > self.window {
            self.recent.pop_front();
        }
        if self.recent.len() >= self.window && self.is_saturating_oscillation(band) {
            self.tripped = true;
        }
        self.tripped
    }

    fn is_saturating_oscillation(&self, band: f64) -> bool {
        // Every sample in the window must be outside the band (guaranteed by the
        // clear-on-in-band rule, but re-checked for safety).
        if self.recent.iter().any(|e| e.abs() <= band) {
            return false;
        }
        // Count error sign flips across the window (oscillation vs monotonic).
        let mut flips = 0usize;
        let mut prev_sign = 0i8;
        for &e in &self.recent {
            let sign: i8 = if e > 0.0 { 1 } else { -1 };
            if prev_sign != 0 && sign != prev_sign {
                flips += 1;
            }
            prev_sign = sign;
        }
        if flips < self.min_sign_flips {
            return false;
        }
        // Amplitude not shrinking: the recent half's peak |error| is at least
        // AMPLITUDE_SHRINK_FLOOR of the older half's peak. A converging ringing
        // loop shrinks each swing and is NOT flagged as diverging.
        let mid = self.recent.len() / 2;
        let older_peak = self
            .recent
            .iter()
            .take(mid)
            .fold(0.0_f64, |m, &e| m.max(e.abs()));
        let recent_peak = self
            .recent
            .iter()
            .skip(mid)
            .fold(0.0_f64, |m, &e| m.max(e.abs()));
        recent_peak >= older_peak * Self::AMPLITUDE_SHRINK_FLOOR
    }
}

impl Default for DivergenceWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of one [`WattTargetController::step`].
#[derive(Debug, Clone)]
pub struct WattControlStep {
    /// The command produced by the PID (clamped budget + diagnostics), or a
    /// synthesized command on the HOLD / watchdog-fallback paths.
    pub command: WattCommand,
    /// Per-chip target frequencies fed to the hardware this tick.
    pub freqs: Vec<u16>,
    /// The power model's own feed-forward estimate of the board power the
    /// `freqs` will draw. The loop's *feedback* comes from the injected
    /// measurement on the next step, not from this estimate.
    pub modeled_watts: f64,
    /// The achievable envelope used to clamp this step.
    pub envelope: PowerEnvelope,
    /// The provenance class of the sample that drove this step.
    pub authority_kind: PowerAuthorityKind,
    /// `true` when the sample was not control-authoritative and the loop HELD
    /// (froze the integral, re-issued its last command) instead of actuating.
    pub held_for_provenance: bool,
    /// `true` when the divergence watchdog tripped and the step used the derated
    /// `allocate_budget_safe` feed-forward instead of the PID command.
    pub watchdog_fallback: bool,
}

/// Closed-loop watt-anchored controller: a [`WattTargetPid`] driving the
/// existing [`PowerModel`] allocation, gated by measurement provenance and a
/// divergence watchdog.
///
/// Each [`step`](Self::step) is one measure → allocate cycle: it derives the
/// achievable envelope for the current chips, checks the sample's provenance,
/// runs the PID (or HOLDs), watches for divergence, and turns the resulting
/// budget into per-chip frequencies. The caller applies the frequencies, then
/// feeds the next measured power back into the following `step`.
///
/// Note: the healthy path deliberately calls `allocate_budget` (not
/// `allocate_budget_safe`). The uncalibrated family derate in the `_safe`
/// variant is a *one-shot* feed-forward guard against overshoot; here the closed
/// loop itself corrects model error tick-by-tick, so the derate would only fight
/// the integral and bias the converged setpoint low. The derate is re-applied
/// exactly on the two untrusted paths — a non-measured sample (HOLD, first tick)
/// and a tripped divergence watchdog — where there is no trustworthy feedback to
/// correct with.
#[derive(Debug, Clone)]
pub struct WattTargetController {
    model: PowerModel,
    pid: WattTargetPid,
    watchdog: Option<DivergenceWatchdog>,
}

impl WattTargetController {
    /// New controller wrapping a power model, with the default watt-loop PID and
    /// the default divergence watchdog enabled.
    pub fn new(model: PowerModel) -> Self {
        Self {
            model,
            pid: WattTargetPid::new(),
            watchdog: Some(DivergenceWatchdog::new()),
        }
    }

    /// New controller with an explicit PID (gains / slew / integral limits) and
    /// the default divergence watchdog enabled.
    pub fn with_pid(model: PowerModel, pid: WattTargetPid) -> Self {
        Self {
            model,
            pid,
            watchdog: Some(DivergenceWatchdog::new()),
        }
    }

    /// Replace the divergence watchdog.
    pub fn with_watchdog(mut self, watchdog: DivergenceWatchdog) -> Self {
        self.watchdog = Some(watchdog);
        self
    }

    /// Disable divergence detection (e.g. to test the raw PID law in isolation).
    pub fn without_divergence_watchdog(mut self) -> Self {
        self.watchdog = None;
        self
    }

    /// Shared reference to the inner PID.
    pub fn pid(&self) -> &WattTargetPid {
        &self.pid
    }

    /// Mutable reference to the inner PID (e.g. to `reset` or retune).
    pub fn pid_mut(&mut self) -> &mut WattTargetPid {
        &mut self.pid
    }

    /// Shared reference to the divergence watchdog, if enabled.
    pub fn watchdog(&self) -> Option<&DivergenceWatchdog> {
        self.watchdog.as_ref()
    }

    /// Shared reference to the power model.
    pub fn model(&self) -> &PowerModel {
        &self.model
    }

    /// Reset the loop state (integral + history + watchdog).
    pub fn reset(&mut self) {
        self.pid.reset();
        if let Some(wd) = self.watchdog.as_mut() {
            wd.reset();
        }
    }

    /// One measure → allocate control tick.
    ///
    /// * `target_watts` — the watt setpoint.
    /// * `sample` — the latest power reading with its provenance. The loop only
    ///   closes on a control-authoritative sample (measured PSU/board telemetry
    ///   or a wall-calibrated estimate); otherwise it HOLDs.
    /// * `voltage_v` — the chain rail voltage used for the CMOS power solve.
    /// * `chip_profiles` — the chips to allocate across.
    /// * `min_freq_mhz` — the frequency floor.
    /// * `num_chains` — active chains (for static-overhead accounting).
    /// * `pvt_ceiling_mhz` — optional PVT-envelope frequency cap (see
    ///   [`PowerModel::achievable_power_envelope`](crate::power_budget::PowerModel::achievable_power_envelope)).
    #[allow(clippy::too_many_arguments)]
    pub fn step(
        &mut self,
        target_watts: f64,
        sample: &PowerAuthoritySample,
        voltage_v: f64,
        chip_profiles: &[ChipProfile],
        min_freq_mhz: u16,
        num_chains: u8,
        pvt_ceiling_mhz: Option<u16>,
    ) -> WattControlStep {
        let envelope = self.model.achievable_power_envelope(
            voltage_v,
            chip_profiles,
            min_freq_mhz,
            num_chains,
            pvt_ceiling_mhz,
        );
        let measured = sample.board_watts;

        // (a) Measurement-provenance gate. Without a control-authoritative
        // sample the "measured" input is the model's own feed-forward; closing
        // the loop on it is a tautology, and it would drop the safety derate the
        // untrusted paths rely on. HOLD instead.
        if !sample.kind.is_control_authoritative() {
            return self.hold_for_provenance(
                target_watts,
                measured,
                envelope,
                voltage_v,
                chip_profiles,
                min_freq_mhz,
                num_chains,
                sample.kind,
            );
        }

        // Trusted feedback → run the PID law.
        let command = self.pid.update(target_watts, measured, envelope);

        // (c) Divergence watchdog: observe the trusted error and, if a
        // sustained saturating oscillation is detected, fall back to the derated
        // safe feed-forward (which can never overclock past the envelope).
        let diverged = match self.watchdog.as_mut() {
            Some(wd) => wd.observe(command.error_watts, target_watts),
            None => false,
        };
        if diverged {
            return self.watchdog_fallback(
                target_watts,
                command.error_watts,
                envelope,
                voltage_v,
                chip_profiles,
                min_freq_mhz,
                num_chains,
                sample.kind,
            );
        }

        // Healthy closed-loop path.
        let freqs = self.model.allocate_budget(
            command.commanded_watts,
            voltage_v,
            chip_profiles,
            min_freq_mhz,
            num_chains,
        );
        let modeled_watts = self.modeled_power(voltage_v, &freqs, num_chains);
        WattControlStep {
            command,
            freqs,
            modeled_watts,
            envelope,
            authority_kind: sample.kind,
            held_for_provenance: false,
            watchdog_fallback: false,
        }
    }

    /// Provenance HOLD: freeze the integral (do not touch PID state) and
    /// re-issue the last validated command. If no trusted command has ever been
    /// established, fall back to the derated `allocate_budget_safe` feed-forward
    /// on the target (a conservative cold start), never `allocate_budget`.
    #[allow(clippy::too_many_arguments)]
    fn hold_for_provenance(
        &mut self,
        target_watts: f64,
        measured: f64,
        envelope: PowerEnvelope,
        voltage_v: f64,
        chip_profiles: &[ChipProfile],
        min_freq_mhz: u16,
        num_chains: u8,
        kind: PowerAuthorityKind,
    ) -> WattControlStep {
        let error = if target_watts.is_finite() && measured.is_finite() {
            target_watts - measured
        } else {
            0.0
        };
        let (commanded, freqs) = match self.pid.last_command() {
            Some(held) => {
                // Re-issue the last validated command verbatim (already
                // envelope-clamped and derived from trusted feedback).
                let f = self.model.allocate_budget(
                    held,
                    voltage_v,
                    chip_profiles,
                    min_freq_mhz,
                    num_chains,
                );
                (held, f)
            }
            None => {
                // No trusted command yet → derated safe feed-forward on target.
                let f = self.model.allocate_budget_safe(
                    target_watts,
                    voltage_v,
                    chip_profiles,
                    min_freq_mhz,
                    num_chains,
                    None,
                );
                (envelope.clamp(target_watts), f)
            }
        };
        let modeled_watts = self.modeled_power(voltage_v, &freqs, num_chains);
        WattControlStep {
            command: WattCommand::synthesized(commanded, error, commanded),
            freqs,
            modeled_watts,
            envelope,
            authority_kind: kind,
            held_for_provenance: true,
            watchdog_fallback: false,
        }
    }

    /// Divergence fallback: abandon the PID command, reset the integral so a
    /// stale wind-up cannot relaunch the swing, and use the derated
    /// `allocate_budget_safe` feed-forward on the target. Fails safe: no chip is
    /// allocated past its `max_stable_mhz`, so nothing overclocks past the
    /// envelope.
    #[allow(clippy::too_many_arguments)]
    fn watchdog_fallback(
        &mut self,
        target_watts: f64,
        error_watts: f64,
        envelope: PowerEnvelope,
        voltage_v: f64,
        chip_profiles: &[ChipProfile],
        min_freq_mhz: u16,
        num_chains: u8,
        kind: PowerAuthorityKind,
    ) -> WattControlStep {
        self.pid.reset_integral();
        let freqs = self.model.allocate_budget_safe(
            target_watts,
            voltage_v,
            chip_profiles,
            min_freq_mhz,
            num_chains,
            None,
        );
        let modeled_watts = self.modeled_power(voltage_v, &freqs, num_chains);
        // Resume the PID's slew ramp from where the safe feed-forward actually
        // left the hardware, so a recovery does not jump.
        self.pid.set_prev_command(modeled_watts);
        let commanded = envelope.clamp(target_watts);
        WattControlStep {
            command: WattCommand::synthesized(commanded, error_watts, commanded),
            freqs,
            modeled_watts,
            envelope,
            authority_kind: kind,
            held_for_provenance: false,
            watchdog_fallback: true,
        }
    }

    /// The model's board-power estimate for an explicit frequency set, using the
    /// SAME accounting as `allocate_budget` (dynamic + static overhead scaled to
    /// `num_chains`).
    fn modeled_power(&self, voltage_v: f64, freqs: &[u16], num_chains: u8) -> f64 {
        let static_overhead =
            self.model.static_per_chain_w() * num_chains as f64 + self.model.control_board_w();
        let dynamic: f64 = freqs
            .iter()
            .map(|&f| self.model.chip_power_w(voltage_v, f))
            .sum();
        dynamic + static_overhead
    }
}

/// PMBus-shaped sample used by the tuner when `ChipStatsSnapshot.psu_power_w`
/// is present. Control-authoritative.
pub fn pmbus_power_sample(board_watts: f64) -> PowerAuthoritySample {
    PowerAuthoritySample {
        kind: PowerAuthorityKind::Pmbus,
        board_watts,
        wall_watts: board_watts,
        confidence: 0.95,
        age_ms: None,
        source: "pmbus".to_string(),
    }
}

/// Estimate-only sample. The watt loop HOLDs and uses `allocate_budget_safe`.
pub fn estimated_power_sample(board_watts: f64) -> PowerAuthoritySample {
    PowerAuthoritySample {
        kind: PowerAuthorityKind::Estimated,
        board_watts,
        wall_watts: board_watts,
        confidence: 0.45,
        age_ms: None,
        source: "estimated".to_string(),
    }
}

/// Immersion C_eff correction applied after the night cut.
const IMMERSION_POWER_SCALE: f64 = 0.955;

/// Resolve the Power-mode watt setpoint `apply_target_mode` actually allocates.
///
/// Order: night cut (home `power_reduction_pct` while in the night window),
/// then the existing immersion 4.5 % C_eff derate. `local_hour` is injected
/// so host tests do not depend on wall-clock.
pub fn resolve_power_mode_target_watts(
    raw_target_watts: u32,
    night: &crate::config::NightPowerPolicy,
    local_hour: u8,
    immersion_mode: bool,
) -> u32 {
    let in_night = night.enabled
        && dcentrald_common::night_power::night_hours_active(
            local_hour,
            night.start_hour,
            night.end_hour,
        );
    let after_night = dcentrald_common::night_power::night_adjusted_watts(
        raw_target_watts,
        in_night,
        night.power_reduction_pct,
    );
    if !immersion_mode {
        return after_night;
    }
    let adjusted = (after_night as f64 * IMMERSION_POWER_SCALE) as u32;
    if adjusted < after_night {
        adjusted
    } else {
        after_night
    }
}

/// Shipped Power-mode allocation used by `AutoTuner::apply_target_mode`.
///
/// Estimate-only / missing samples HOLD to the derated feed-forward (first
/// tick is byte-identical to the old `allocate_budget_safe` one-shot). A
/// measured PMBus/ADC sample closes the PID.
pub fn allocate_power_target_step(
    controller: &mut WattTargetController,
    target_watts: f64,
    sample: Option<&PowerAuthoritySample>,
    voltage_v: f64,
    chip_profiles: &[ChipProfile],
    min_freq_mhz: u16,
    num_chains: u8,
    pvt_ceiling_mhz: Option<u16>,
) -> WattControlStep {
    let fallback = estimated_power_sample(0.0);
    let sample = sample.unwrap_or(&fallback);
    controller.step(
        target_watts,
        sample,
        voltage_v,
        chip_profiles,
        min_freq_mhz,
        num_chains,
        pvt_ceiling_mhz,
    )
}

/// Whether the background monitor should run another watt-PID step.
///
/// DPS schedule owns the ramp when enabled (mutual exclusion). Estimate-only
/// samples HOLD; only a control-authoritative sample closes the loop.
pub fn watt_pid_should_step(
    power_mode: bool,
    dps_schedule_idle: bool,
    sample: Option<&PowerAuthoritySample>,
) -> bool {
    power_mode
        && dps_schedule_idle
        && sample
            .map(|s| s.kind.is_control_authoritative())
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{ChipGrade, ChipProfile};

    // ---- Test-only sample builders -----------------------------------------

    /// A control-authoritative (PMBus-measured) sample carrying `board_watts`.
    fn measured_sample(board_watts: f64) -> PowerAuthoritySample {
        PowerAuthoritySample {
            kind: PowerAuthorityKind::Pmbus,
            board_watts,
            wall_watts: board_watts / 0.93,
            confidence: 0.95,
            age_ms: None,
            source: "pmbus".to_string(),
        }
    }

    /// A sample of an arbitrary provenance class carrying `board_watts`.
    fn sample_of(kind: PowerAuthorityKind, board_watts: f64) -> PowerAuthoritySample {
        PowerAuthoritySample {
            kind,
            board_watts,
            wall_watts: board_watts / 0.93,
            confidence: 0.5,
            age_ms: None,
            source: "test".to_string(),
        }
    }

    // ---- Deterministic simulation harness -----------------------------------
    //
    // The "plant" is reality: a power model whose dynamic coefficient differs
    // from the controller's nominal model by a fixed BIAS. This is exactly the
    // documented ±10 % model error the feed-forward-only path cannot correct.
    // The controller only ever sees `measured = plant(freqs)`; it never sees the
    // bias. A real closed loop must still converge.

    fn grade_b_chips(n: usize, max_stable_mhz: u16) -> Vec<ChipProfile> {
        (0..n)
            .map(|i| ChipProfile {
                chip_index: i as u8,
                max_stable_mhz,
                operating_mhz: max_stable_mhz,
                grade: ChipGrade::B,
                error_rate: 0.001,
                nonces_counted: 100,
                vf_curve: None,
                thermal_max_stable_mhz: None,
            })
            .collect()
    }

    /// Board power reality would draw for a given frequency set, using the
    /// biased `plant` dynamic coefficient but the SAME static overhead as the
    /// nominal model (we are isolating the dynamic model error).
    fn plant_board_watts(
        plant: &PowerModel,
        nominal: &PowerModel,
        voltage_v: f64,
        freqs: &[u16],
        num_chains: u8,
    ) -> f64 {
        let static_overhead =
            nominal.static_per_chain_w() * num_chains as f64 + nominal.control_board_w();
        let dynamic: f64 = freqs
            .iter()
            .map(|&f| plant.chip_power_w(voltage_v, f))
            .sum();
        dynamic + static_overhead
    }

    /// Deterministic pseudo-random value in `[-1, 1]` for a step index. No RNG,
    /// no clock — a fixed SplitMix-style hash of the tick counter so the whole
    /// sim stays reproducible.
    fn det_noise(step: usize) -> f64 {
        let mut z = (step as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(0x1234_5678_9ABC_DEF0);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z ^= z >> 27;
        // Top 24 bits → [0, 1) → [-1, 1).
        let u = ((z >> 40) as f64) / ((1u64 << 24) as f64);
        (u * 2.0) - 1.0
    }

    /// Which slew mode the simulated controller runs with.
    #[derive(Clone, Copy)]
    enum SlewMode {
        /// Use the constructor's finite fractional default.
        Default,
        /// No slew limiting (pure PID).
        None,
        /// Absolute watts/tick.
        Abs(f64),
    }

    struct SimConfig<'a> {
        target: f64,
        /// Multiplicative dynamic-power bias (reality vs nominal model).
        bias: f64,
        /// Constant ADDITIVE plant error in watts (static-overhead-style bias).
        additive_bias_w: f64,
        /// Symmetric measurement noise as a fraction of the reading (± this).
        noise_frac: f64,
        /// Extra feedback (actuator/telemetry) delay in ticks, on top of the
        /// harness's inherent 1-tick loop delay.
        extra_delay: usize,
        initial_measured: f64,
        voltage_v: f64,
        chips: &'a [ChipProfile],
        min_freq: u16,
        num_chains: u8,
        slew: SlewMode,
        gain_mult: f64,
        watchdog: bool,
        max_steps: usize,
        band_frac: f64,
    }

    impl<'a> SimConfig<'a> {
        fn base(target: f64, chips: &'a [ChipProfile], num_chains: u8, initial: f64) -> Self {
            Self {
                target,
                bias: 1.0,
                additive_bias_w: 0.0,
                noise_frac: 0.0,
                extra_delay: 0,
                initial_measured: initial,
                voltage_v: 9.1,
                chips,
                min_freq: 300,
                num_chains,
                slew: SlewMode::Default,
                gain_mult: 1.0,
                watchdog: true,
                max_steps: 200,
                band_frac: 0.02,
            }
        }
    }

    #[derive(Debug)]
    struct SimResult {
        final_measured: f64,
        final_error_frac: f64,
        settled_error_frac: f64,
        steps_to_converge: Option<usize>,
        max_overshoot_frac: f64,
        peak_freq: u16,
        max_ceiling: u16,
        watchdog_tripped: bool,
    }

    /// Run the full closed loop under `cfg` and report convergence stats. The
    /// "true measured" the plant produces is fed back with the configured delay
    /// and measurement noise; the controller only ever sees the (delayed, noisy)
    /// sample.
    fn run_sim_cfg(cfg: SimConfig) -> SimResult {
        let nominal = PowerModel::new_bm1387();
        let plant = PowerModel::new_bm1387().with_c_eff(nominal.c_eff() * cfg.bias);

        let mut pid =
            WattTargetPid::with_gains(PidGains::default_watt_loop().scaled(cfg.gain_mult));
        pid = match cfg.slew {
            SlewMode::Default => pid,
            SlewMode::None => pid.with_no_slew(),
            SlewMode::Abs(s) => pid.with_slew_limit(s),
        };
        let mut ctrl = WattTargetController::with_pid(nominal.clone(), pid);
        if !cfg.watchdog {
            ctrl = ctrl.without_divergence_watchdog();
        }

        let max_ceiling = cfg
            .chips
            .iter()
            .map(|c| c.max_stable_mhz)
            .max()
            .unwrap_or(0);

        // `history[t]` = the TRUE plant board power after step `t-1` (index 0 is
        // the seed). The sample fed at step `t` reads `history[t - extra_delay]`.
        let mut history: Vec<f64> = vec![cfg.initial_measured];
        let mut steps_to_converge = None;
        let mut max_overshoot_frac = 0.0_f64;
        let mut settled_error_frac = 0.0_f64;
        let mut peak_freq = 0u16;
        let mut watchdog_tripped = false;
        let mut last_true = cfg.initial_measured;

        for step in 0..cfg.max_steps {
            let idx = step.saturating_sub(cfg.extra_delay);
            let delayed_true = *history.get(idx).unwrap_or(&cfg.initial_measured);
            // Apply measurement noise to what the sensor reports (deterministic).
            let reported = if cfg.noise_frac > 0.0 {
                delayed_true * (1.0 + cfg.noise_frac * det_noise(step))
            } else {
                delayed_true
            };

            let s = ctrl.step(
                cfg.target,
                &measured_sample(reported),
                cfg.voltage_v,
                cfg.chips,
                cfg.min_freq,
                cfg.num_chains,
                None,
            );
            if s.watchdog_fallback {
                watchdog_tripped = true;
            }

            // Reality responds to the commanded frequencies, plus any constant
            // additive plant error the model does not know about.
            let true_response =
                plant_board_watts(&plant, &nominal, cfg.voltage_v, &s.freqs, cfg.num_chains)
                    + cfg.additive_bias_w;
            last_true = true_response;
            history.push(true_response);

            if let Some(&f) = s.freqs.iter().max() {
                peak_freq = peak_freq.max(f);
            }
            // True overshoot = how far the TRUE measured blows PAST the target,
            // in the direction of approach. The initial approach gap is NOT
            // overshoot.
            let past_target = if cfg.target >= cfg.initial_measured {
                (true_response - cfg.target).max(0.0)
            } else {
                (cfg.target - true_response).max(0.0)
            };
            max_overshoot_frac = max_overshoot_frac.max(past_target / cfg.target);

            let err_frac = (true_response - cfg.target).abs() / cfg.target;
            if steps_to_converge.is_none() && err_frac <= cfg.band_frac {
                steps_to_converge = Some(step + 1);
            }
            // Track the worst error over the LAST quarter of the run (settled
            // band-wander), which is what the additive/noise cases care about.
            if step >= cfg.max_steps * 3 / 4 {
                settled_error_frac = settled_error_frac.max(err_frac);
            }
        }

        SimResult {
            final_measured: last_true,
            final_error_frac: (last_true - cfg.target).abs() / cfg.target,
            settled_error_frac,
            steps_to_converge,
            max_overshoot_frac,
            peak_freq,
            max_ceiling,
            watchdog_tripped,
        }
    }

    /// Back-compat thin wrapper matching the original convergence-test harness:
    /// single multiplicative bias, no additive error / noise / delay, watchdog
    /// DISABLED (these tests exercise the raw PID convergence law). `slew`
    /// `Some(s)` = absolute watts/tick; `None` = explicit no-slew.
    #[allow(clippy::too_many_arguments)]
    fn run_sim(
        target: f64,
        bias: f64,
        initial_measured: f64,
        voltage_v: f64,
        chips: &[ChipProfile],
        min_freq: u16,
        num_chains: u8,
        slew: Option<f64>,
        max_steps: usize,
        band_frac: f64,
    ) -> SimResult {
        let mut cfg = SimConfig::base(target, chips, num_chains, initial_measured);
        cfg.bias = bias;
        cfg.voltage_v = voltage_v;
        cfg.min_freq = min_freq;
        cfg.slew = match slew {
            Some(s) => SlewMode::Abs(s),
            None => SlewMode::None,
        };
        cfg.watchdog = false;
        cfg.max_steps = max_steps;
        cfg.band_frac = band_frac;
        run_sim_cfg(cfg)
    }

    // ---- Pure PID unit tests ------------------------------------------------

    #[test]
    fn pid_drives_command_up_when_below_target_and_down_when_above() {
        let env = PowerEnvelope {
            floor_watts: 100.0,
            ceiling_watts: 2000.0,
        };
        // Raw PID law under test → explicit no-slew so the command reflects the
        // desired value in one tick (the finite default would ramp gradually).
        let mut pid = WattTargetPid::new().with_no_slew();
        // Measured far below target → positive error → command should exceed
        // the feed-forward target.
        let up = pid.update(1000.0, 600.0, env);
        assert!(up.error_watts > 0.0);
        assert!(
            up.commanded_watts >= 1000.0,
            "below-target should push the command up, got {}",
            up.commanded_watts
        );

        let mut pid2 = WattTargetPid::new().with_no_slew();
        // Measured above target → negative error → command below feed-forward.
        let down = pid2.update(1000.0, 1400.0, env);
        assert!(down.error_watts < 0.0);
        assert!(
            down.commanded_watts <= 1000.0,
            "above-target should push the command down, got {}",
            down.commanded_watts
        );
    }

    #[test]
    fn pid_command_is_clamped_to_envelope_ceiling_for_impossible_target() {
        let env = PowerEnvelope {
            floor_watts: 200.0,
            ceiling_watts: 900.0,
        };
        // Explicit no-slew → clamps to the ceiling immediately in one tick.
        let mut pid = WattTargetPid::new().with_no_slew();
        // Ask for 5x the envelope ceiling.
        let cmd = pid.update(5000.0, 300.0, env);
        assert!(
            (cmd.commanded_watts - 900.0).abs() < 1e-6,
            "impossible target must clamp to ceiling 900, got {}",
            cmd.commanded_watts
        );
        assert!(cmd.saturated_high, "should report ceiling saturation");
        assert!(!cmd.saturated_low);
    }

    #[test]
    fn pid_command_is_clamped_to_envelope_floor_for_sub_floor_target() {
        let env = PowerEnvelope {
            floor_watts: 300.0,
            ceiling_watts: 900.0,
        };
        // Explicit no-slew → clamps to the floor immediately.
        let mut pid = WattTargetPid::new().with_no_slew();
        // Ask for far below the floor (e.g. curtailment beyond what freq can do).
        let cmd = pid.update(50.0, 400.0, env);
        assert!(
            (cmd.commanded_watts - 300.0).abs() < 1e-6,
            "sub-floor target must clamp to floor 300, got {}",
            cmd.commanded_watts
        );
        assert!(cmd.saturated_low);
        assert!(!cmd.saturated_high);
    }

    #[test]
    fn default_constructor_has_a_finite_slew_limit() {
        // (b) The constructor MUST default to a finite per-tick slew. Prove it
        // by showing a large upward demand does NOT jump straight to the
        // envelope-clamped desired value in one tick — it ramps by ~10% of the
        // span. (The old INFINITY default jumped immediately and measured 17.9%
        // overshoot.)
        let env = PowerEnvelope {
            floor_watts: 200.0,
            ceiling_watts: 1200.0, // span 1000 → default slew 100 W/tick
        };
        let mut pid = WattTargetPid::new();
        // Huge target; measured at the floor. A no-slew loop would clamp to the
        // ceiling (1200) immediately; the finite default must move only ~100 W.
        let cmd = pid.update(5000.0, 200.0, env);
        let moved = cmd.commanded_watts - 200.0;
        assert!(
            moved > 0.0 && moved <= 100.0 + 1e-6,
            "finite default slew must cap the first move at ~10% of span (100 W), moved {} W",
            moved
        );
        assert!(
            cmd.commanded_watts < env.ceiling_watts - 1.0,
            "finite default must NOT reach the ceiling in one tick, got {}",
            cmd.commanded_watts
        );

        // And an explicit no-slew controller DOES reach the ceiling in one tick,
        // proving the difference is the finite default (not the envelope clamp).
        let mut raw = WattTargetPid::new().with_no_slew();
        let raw_cmd = raw.update(5000.0, 200.0, env);
        assert!(
            (raw_cmd.commanded_watts - env.ceiling_watts).abs() < 1e-6,
            "no-slew must clamp straight to the ceiling, got {}",
            raw_cmd.commanded_watts
        );
    }

    #[test]
    fn anti_windup_conditional_integration_freezes_integral_while_saturated() {
        // Impossible-high target with the command pinned at the ceiling and a
        // permanent positive error. Conditional integration must FREEZE the
        // integral (never charge it into the rail), so it stays at ~0.
        let env = PowerEnvelope {
            floor_watts: 200.0,
            ceiling_watts: 900.0,
        };
        let mut pid = WattTargetPid::new();
        for _ in 0..200 {
            // measured always below target and below ceiling → error stays +.
            let _ = pid.update(5000.0, 850.0, env);
        }
        assert!(
            pid.integral().abs() < 1e-6,
            "integral must stay frozen (~0) while saturated high with + error, got {}",
            pid.integral()
        );
    }

    #[test]
    fn anti_windup_integral_clamp_bounds_the_accumulator() {
        // Wide envelope (never envelope-saturated) + a constant unresolved
        // positive error would wind the integral up unbounded. The absolute
        // integral clamp must cap it.
        let env = PowerEnvelope {
            floor_watts: 0.0,
            ceiling_watts: 1e9,
        };
        let limit = 500.0;
        let mut pid = WattTargetPid::new().with_integral_limit(limit);
        for _ in 0..1000 {
            // Constant 100 W error, never resolved (open-loop drive).
            let _ = pid.update(1000.0, 900.0, env);
        }
        assert!(
            pid.integral() <= limit + 1e-6 && pid.integral() >= -limit - 1e-6,
            "integral must be clamped to +/-{limit}, got {}",
            pid.integral()
        );
        // And it should have actually reached the clamp (proving the bound bites).
        assert!(
            (pid.integral() - limit).abs() < 1e-6,
            "integral should have wound up to the clamp {limit}, got {}",
            pid.integral()
        );
    }

    #[test]
    fn derivative_on_measurement_has_no_setpoint_kick() {
        // At steady state (measured == target, no prior motion) a pure setpoint
        // step must not produce a derivative spike: the D term stays 0 because
        // the derivative is taken on the (unchanged) measurement, not the error.
        let env = PowerEnvelope {
            floor_watts: 0.0,
            ceiling_watts: 5000.0,
        };
        let mut pid = WattTargetPid::new();
        // Prime at steady state.
        let _ = pid.update(1000.0, 1000.0, env);
        // Step the target up; measurement hasn't moved yet.
        let cmd = pid.update(1500.0, 1000.0, env);
        assert!(
            cmd.d_term.abs() < 1e-9,
            "derivative-on-measurement must not kick on a setpoint step, got d_term={}",
            cmd.d_term
        );
    }

    #[test]
    fn non_finite_measurement_does_not_wind_up_or_kick() {
        let env = PowerEnvelope {
            floor_watts: 0.0,
            ceiling_watts: 5000.0,
        };
        let mut pid = WattTargetPid::new();
        // Prime at steady state so "hold last measurement" yields error 0.
        let _ = pid.update(1000.0, 1000.0, env);
        let before = pid.integral();
        let cmd = pid.update(1000.0, f64::NAN, env);
        // Held last (finite) measurement 1000 == target → error 0, no kick.
        assert_eq!(cmd.error_watts, 0.0);
        assert!(cmd.d_term.abs() < 1e-9);
        assert!((pid.integral() - before).abs() < 1e-9);
    }

    // ---- Envelope helper ----------------------------------------------------

    #[test]
    fn envelope_floor_below_ceiling_and_target_containment() {
        let model = PowerModel::new_bm1387();
        let chips = grade_b_chips(63, 700);
        let env = model.achievable_power_envelope(9.1, &chips, 300, 1, None);
        assert!(
            env.floor_watts < env.ceiling_watts,
            "floor {} must be below ceiling {}",
            env.floor_watts,
            env.ceiling_watts
        );
        // A mid-range target is inside; an absurd one is not.
        let mid = (env.floor_watts + env.ceiling_watts) / 2.0;
        assert!(env.contains(mid));
        assert!(!env.contains(env.ceiling_watts + 1000.0));
        assert!(!env.contains(f64::NAN));
    }

    #[test]
    fn allocate_power_target_step_holds_estimate_and_closes_on_pmbus() {
        let model = PowerModel::new_bm1387();
        let chips = grade_b_chips(63, 700);
        let mut ctrl = WattTargetController::new(model.clone());
        let held = allocate_power_target_step(
            &mut ctrl,
            1100.0,
            Some(&estimated_power_sample(1100.0)),
            9.1,
            &chips,
            300,
            3,
            None,
        );
        assert!(held.held_for_provenance);
        let safe = model.allocate_budget_safe(1100.0, 9.1, &chips, 300, 3, None);
        assert_eq!(held.freqs, safe);

        let mut closed = WattTargetController::new(model);
        let step = allocate_power_target_step(
            &mut closed,
            1100.0,
            Some(&pmbus_power_sample(1300.0)),
            9.1,
            &chips,
            300,
            3,
            None,
        );
        assert!(!step.held_for_provenance);
        assert_ne!(
            step.freqs, safe,
            "measured 1300 W vs 1100 W target must move frequencies off the one-shot feed-forward"
        );
        assert!(
            step.freqs.iter().zip(safe.iter()).all(|(a, b)| *a <= *b),
            "closing a high-power miss must decrease-only vs the safe one-shot"
        );
    }

    #[test]
    fn tuner_power_mode_calls_allocate_power_target_step() {
        let tuner = include_str!("tuner.rs");
        assert!(
            tuner.contains("allocate_power_target_step("),
            "apply_target_mode Power must drive the shipped watt-PID helper"
        );
        assert!(
            tuner.contains("last_power_sample"),
            "tuner must cache the latest power sample for the PID"
        );
        assert!(
            tuner.contains("WattTargetController::new"),
            "tuner must own a WattTargetController across Power-mode ticks"
        );
        assert!(
            tuner.contains("watt_pid_should_step("),
            "background monitor must step the watt PID on authoritative samples"
        );
    }

    #[test]
    fn resolve_power_mode_target_applies_night_then_immersion() {
        let night = crate::config::NightPowerPolicy {
            enabled: true,
            start_hour: 22,
            end_hour: 7,
            power_reduction_pct: 40,
            timezone_offset_hours: 0,
        };
        assert_eq!(
            resolve_power_mode_target_watts(1000, &night, 23, false),
            600,
            "22-07 window at 23:00 must apply the persisted 40% home cut"
        );
        assert_eq!(
            resolve_power_mode_target_watts(1000, &night, 12, false),
            1000,
            "daytime must keep the raw Power setpoint"
        );
        assert_eq!(
            resolve_power_mode_target_watts(1000, &night, 23, true),
            573,
            "night cut is first; immersion 4.5% applies to the reduced setpoint"
        );
        let off = crate::config::NightPowerPolicy::default();
        assert_eq!(resolve_power_mode_target_watts(1000, &off, 23, false), 1000);
    }

    #[test]
    fn apply_target_mode_calls_resolve_power_mode_target_watts() {
        let tuner = include_str!("tuner.rs");
        assert!(
            tuner.contains("crate::resolve_power_mode_target_watts("),
            "apply_target_mode must allocate the night-adjusted Power setpoint"
        );
        let daemon = include_str!("../../dcentrald/src/daemon.rs");
        assert!(
            daemon.contains("NightPowerPolicy::from_home_night_mode("),
            "daemon must seed night_power from mode.home.night_mode"
        );
        let hybrid = include_str!("../../dcentrald/src/s19j_hybrid_mining.rs");
        assert!(
            hybrid.contains("NightPowerPolicy::from_home_night_mode("),
            "am2 hybrid tuner spawn must seed night_power from mode.home.night_mode"
        );
        let rest = include_str!("../../dcentrald-api/src/rest/late.rs");
        assert!(
            rest.contains("AutoTunerCommand::ApplyNightPowerPolicy"),
            "POST /api/home/night-mode must send ApplyNightPowerPolicy to the live tuner"
        );
        assert!(
            rest.contains("\"runtimeAdopted\": serial_truth.runtime_adopted"),
            "POST night-mode must report tuner adoption via the honesty helper, never invent true"
        );
        assert!(
            rest.contains("serial_night_power_read_truth("),
            "POST must not claim tuner runtimeAdopted on serial"
        );
    }

    #[test]
    fn watt_pid_should_step_only_on_authoritative_power_mode() {
        assert!(!watt_pid_should_step(
            false,
            true,
            Some(&pmbus_power_sample(1000.0))
        ));
        assert!(!watt_pid_should_step(
            true,
            false,
            Some(&pmbus_power_sample(1000.0))
        ));
        assert!(!watt_pid_should_step(
            true,
            true,
            Some(&estimated_power_sample(1000.0))
        ));
        assert!(!watt_pid_should_step(true, true, None));
        assert!(watt_pid_should_step(
            true,
            true,
            Some(&pmbus_power_sample(1000.0))
        ));
    }

    #[test]
    fn envelope_respects_pvt_ceiling_frequency_cap() {
        let model = PowerModel::new_bm1387();
        let chips = grade_b_chips(63, 700);
        let uncapped = model.achievable_power_envelope(9.1, &chips, 300, 1, None);
        // Cap the per-chip ceiling frequency well below max_stable.
        let capped = model.achievable_power_envelope(9.1, &chips, 300, 1, Some(500));
        assert!(
            capped.ceiling_watts < uncapped.ceiling_watts,
            "PVT ceiling cap must lower the achievable ceiling ({} !< {})",
            capped.ceiling_watts,
            uncapped.ceiling_watts
        );
    }

    // ---- Measurement-provenance gate (a) ------------------------------------

    #[test]
    fn provenance_gate_holds_on_non_measured_sample() {
        // Establish a trusted command + a non-zero integral over a few measured
        // ticks, then feed an ESTIMATED (non-authoritative) sample. The loop
        // must HOLD: integral frozen, command re-issued verbatim, and the step
        // flagged held_for_provenance.
        let chips: Vec<ChipProfile> = (0..3).flat_map(|_| grade_b_chips(63, 700)).collect();
        let nominal = PowerModel::new_bm1387();
        let plant = PowerModel::new_bm1387().with_c_eff(nominal.c_eff() * 1.08);
        let mut ctrl = WattTargetController::with_pid(
            nominal.clone(),
            WattTargetPid::new().with_slew_limit(50.0),
        );

        let mut measured = ctrl
            .model()
            .achievable_power_envelope(9.1, &chips, 300, 3, None)
            .floor_watts;
        for _ in 0..12 {
            let s = ctrl.step(
                1100.0,
                &measured_sample(measured),
                9.1,
                &chips,
                300,
                3,
                None,
            );
            measured = plant_board_watts(&plant, &nominal, 9.1, &s.freqs, 3);
        }
        // Capture the trusted baseline right before the untrusted tick.
        let integral_before = ctrl.pid().integral();
        let command_before = ctrl.pid().last_command().expect("a trusted command exists");
        assert!(
            integral_before.abs() > 1e-9,
            "the 8% bias should have driven a non-zero integral by now, got {integral_before}"
        );

        // Now a garbage, wildly-off ESTIMATED sample arrives.
        let held = ctrl.step(
            1100.0,
            &sample_of(PowerAuthorityKind::Estimated, 100_000.0),
            9.1,
            &chips,
            300,
            3,
            None,
        );
        assert!(
            held.held_for_provenance,
            "must HOLD on a non-measured sample"
        );
        assert!(!held.watchdog_fallback);
        assert_eq!(held.authority_kind, PowerAuthorityKind::Estimated);
        // Integral frozen: exactly unchanged by the held tick.
        assert_eq!(
            ctrl.pid().integral(),
            integral_before,
            "integral must be frozen on a HOLD tick"
        );
        // Command re-issued verbatim (the last trusted command).
        assert!(
            (held.command.commanded_watts - command_before).abs() < 1e-9,
            "HOLD must re-issue the last command {command_before}, got {}",
            held.command.commanded_watts
        );
        // And a second consecutive HOLD re-issues the SAME command (it does not
        // drift): the loop never actuates on the untrusted feed.
        let held2 = ctrl.step(
            1100.0,
            &sample_of(PowerAuthorityKind::Unknown, 0.0),
            9.1,
            &chips,
            300,
            3,
            None,
        );
        assert!(held2.held_for_provenance);
        assert!((held2.command.commanded_watts - command_before).abs() < 1e-9);
    }

    #[test]
    fn provenance_gate_first_tick_uses_safe_feed_forward_not_raw_allocate() {
        // With NO prior trusted command, a non-measured sample must fall back to
        // the DERATED allocate_budget_safe feed-forward (never the underated
        // allocate_budget). Prove it: the held freqs must draw strictly LESS
        // than the un-derated allocate_budget for the same target.
        let chips = grade_b_chips(63, 700);
        let nominal = PowerModel::new_bm1387();
        let mut ctrl = WattTargetController::new(nominal.clone());
        // An INTERIOR target (single-chain envelope is ~[251, 493] W). A target
        // above the ceiling would saturate both paths to max_stable and hide the
        // derate; 400 W leaves room for the derate to lower the allocation.
        let target = 400.0;

        let held = ctrl.step(
            target,
            &sample_of(PowerAuthorityKind::Estimated, 400.0),
            9.1,
            &chips,
            300,
            1,
            None,
        );
        assert!(held.held_for_provenance);
        // The un-derated path for the same target:
        let raw_freqs = nominal.allocate_budget(target, 9.1, &chips, 300, 1);
        let raw_modeled: f64 = raw_freqs
            .iter()
            .map(|&f| nominal.chip_power_w(9.1, f))
            .sum::<f64>()
            + nominal.static_per_chain_w()
            + nominal.control_board_w();
        assert!(
            held.modeled_watts < raw_modeled - 1.0,
            "first-tick HOLD must use the DERATED safe feed-forward ({} !< {})",
            held.modeled_watts,
            raw_modeled
        );
        // Fail-safe: nothing overclocked past max_stable.
        assert!(held.freqs.iter().all(|&f| f <= 700));
    }

    #[test]
    fn provenance_gate_admits_wall_calibrated_estimate() {
        // A wall-meter-anchored estimate IS control-authoritative → the loop
        // actuates (does not HOLD).
        let chips = grade_b_chips(63, 700);
        let nominal = PowerModel::new_bm1387();
        let mut ctrl = WattTargetController::new(nominal.clone());
        let s = ctrl.step(
            900.0,
            &sample_of(PowerAuthorityKind::WallCalibratedEstimate, 700.0),
            9.1,
            &chips,
            300,
            1,
            None,
        );
        assert!(
            !s.held_for_provenance,
            "a wall-calibrated estimate must actuate, not HOLD"
        );
    }

    // ---- Closed-loop convergence (the headline proof) -----------------------

    #[test]
    fn closed_loop_converges_within_band_despite_model_bias() {
        // Full-S9-scale: 3 chains x 63 chips. Reality draws 8 % more dynamic
        // power than the controller's model (uncalibrated-class error). The
        // feed-forward-only path would settle ~8 % high forever; the closed loop
        // must pull measured back to within 2 % of the 1100 W target.
        let chips: Vec<ChipProfile> = (0..3).flat_map(|_| grade_b_chips(63, 700)).collect();
        let env_model = PowerModel::new_bm1387();
        let env = env_model.achievable_power_envelope(9.1, &chips, 300, 3, None);
        // Sanity: 1100 W is genuinely inside the achievable envelope.
        assert!(
            env.contains(1100.0),
            "test target 1100 W must be inside envelope [{:.0}, {:.0}]",
            env.floor_watts,
            env.ceiling_watts
        );

        let slew = Some(env.span_watts() * 0.10); // gentle 10%-of-span ramp
        let res = run_sim(
            1100.0,
            1.08,            // target, bias
            env.floor_watts, // start cold (all chips near floor)
            9.1,
            &chips,
            300,
            3,
            slew,
            120,
            0.02,
        );

        assert!(
            res.final_error_frac <= 0.02,
            "final error {:.3} must be within the 2% band (measured {:.1} W)",
            res.final_error_frac,
            res.final_measured
        );
        assert!(
            res.steps_to_converge.is_some(),
            "loop must reach the 2% band within the tick budget"
        );
        // Overshoot bound. Feed-forward = target with reality drawing 8 % more
        // than the model means the terminal bump is inherently ~ (bias-1)·
        // (target-static)/target ≈ 7 %; assert it stays inside a physically
        // honest 8 % (a tighter/calibrated model gives a tighter bump — see
        // `closed_loop_low_bias_overshoot_is_tight`).
        assert!(
            res.max_overshoot_frac <= 0.08,
            "overshoot {:.3} must stay <= 8%",
            res.max_overshoot_frac
        );
        // Stability: the loop must never overclock past the chip ceiling.
        assert!(
            res.peak_freq <= res.max_ceiling,
            "peak freq {} must never exceed max_stable {}",
            res.peak_freq,
            res.max_ceiling
        );
    }

    #[test]
    fn closed_loop_low_bias_overshoot_is_tight() {
        // A well-calibrated model (reality within 3 % of the model) must give a
        // tight terminal overshoot (<= 4 %) and converge to within 2 %. Proves
        // the overshoot scales with model error, not with a controller defect.
        let chips: Vec<ChipProfile> = (0..3).flat_map(|_| grade_b_chips(63, 700)).collect();
        let env = PowerModel::new_bm1387().achievable_power_envelope(9.1, &chips, 300, 3, None);
        let slew = Some(env.span_watts() * 0.10);
        let res = run_sim(
            1100.0,
            1.03,
            env.floor_watts,
            9.1,
            &chips,
            300,
            3,
            slew,
            120,
            0.02,
        );
        assert!(
            res.final_error_frac <= 0.02,
            "final error {:.3} must be within 2% (measured {:.1} W)",
            res.final_error_frac,
            res.final_measured
        );
        assert!(
            res.max_overshoot_frac <= 0.04,
            "low-bias overshoot {:.3} must be tight (<= 4%)",
            res.max_overshoot_frac
        );
    }

    #[test]
    fn closed_loop_converges_from_multiple_starting_points() {
        // Same plant, three very different initial feedback samples: cold
        // (floor), already-at-target, and hot (ceiling). All must land in-band.
        let chips: Vec<ChipProfile> = (0..3).flat_map(|_| grade_b_chips(63, 700)).collect();
        let env = PowerModel::new_bm1387().achievable_power_envelope(9.1, &chips, 300, 3, None);
        let slew = Some(env.span_watts() * 0.10);
        let starts = [env.floor_watts, 1100.0, env.ceiling_watts];
        for &start in &starts {
            let res = run_sim(1100.0, 1.08, start, 9.1, &chips, 300, 3, slew, 140, 0.02);
            assert!(
                res.final_error_frac <= 0.02,
                "start={:.0} W: final error {:.3} must be within 2% (measured {:.1} W)",
                start,
                res.final_error_frac,
                res.final_measured
            );
            assert!(
                res.peak_freq <= res.max_ceiling,
                "start={:.0} W: peak freq {} exceeded ceiling {}",
                start,
                res.peak_freq,
                res.max_ceiling
            );
        }
    }

    #[test]
    fn closed_loop_pure_pid_no_slew_still_converges() {
        // Without the slew limiter (pure PID) the loop is more aggressive; it
        // must still converge in-band (looser overshoot tolerance). Watchdog is
        // off in run_sim so this exercises the raw PID law.
        let chips: Vec<ChipProfile> = (0..3).flat_map(|_| grade_b_chips(63, 700)).collect();
        let env = PowerModel::new_bm1387().achievable_power_envelope(9.1, &chips, 300, 3, None);
        let res = run_sim(
            1100.0,
            1.08,
            env.floor_watts,
            9.1,
            &chips,
            300,
            3,
            None, // explicit no slew
            120,
            0.02,
        );
        assert!(
            res.final_error_frac <= 0.02,
            "pure-PID final error {:.3} must be within 2% (measured {:.1} W)",
            res.final_error_frac,
            res.final_measured
        );
        assert!(
            res.peak_freq <= res.max_ceiling,
            "pure-PID peak freq {} exceeded ceiling {}",
            res.peak_freq,
            res.max_ceiling
        );
    }

    #[test]
    fn closed_loop_recovers_from_a_step_change_in_target() {
        // Converge at 900 W, then step the target to 1300 W and prove the loop
        // re-converges to the new setpoint. Exercises setpoint-step recovery
        // (the derivative-on-measurement design point).
        let chips: Vec<ChipProfile> = (0..3).flat_map(|_| grade_b_chips(63, 700)).collect();
        let nominal = PowerModel::new_bm1387();
        let plant = PowerModel::new_bm1387().with_c_eff(nominal.c_eff() * 1.08);
        let env = nominal.achievable_power_envelope(9.1, &chips, 300, 3, None);
        assert!(env.contains(900.0) && env.contains(1300.0));

        let mut ctrl = WattTargetController::with_pid(
            nominal.clone(),
            WattTargetPid::new().with_slew_limit(env.span_watts() * 0.10),
        );

        let mut measured = env.floor_watts;
        // Phase 1: settle at 900 W.
        for _ in 0..120 {
            let s = ctrl.step(900.0, &measured_sample(measured), 9.1, &chips, 300, 3, None);
            measured = plant_board_watts(&plant, &nominal, 9.1, &s.freqs, 3);
        }
        let err1 = (measured - 900.0).abs() / 900.0;
        assert!(
            err1 <= 0.02,
            "phase 1 must settle at 900 W, err {:.3}",
            err1
        );

        // Phase 2: step target to 1300 W and re-converge.
        let mut peak_after_step = 0u16;
        for _ in 0..120 {
            let s = ctrl.step(
                1300.0,
                &measured_sample(measured),
                9.1,
                &chips,
                300,
                3,
                None,
            );
            if let Some(&f) = s.freqs.iter().max() {
                peak_after_step = peak_after_step.max(f);
            }
            measured = plant_board_watts(&plant, &nominal, 9.1, &s.freqs, 3);
        }
        let err2 = (measured - 1300.0).abs() / 1300.0;
        assert!(
            err2 <= 0.02,
            "phase 2 must re-converge to 1300 W, err {:.3} (measured {:.1} W)",
            err2,
            measured
        );
        assert!(
            peak_after_step <= 700,
            "step recovery must never overclock past max_stable 700, got {}",
            peak_after_step
        );
    }

    #[test]
    fn impossible_target_is_clamped_not_obeyed_past_the_envelope() {
        // The load-bearing safety property: a request for an impossible watt
        // target must be CLAMPED to the envelope, never obeyed past it. Every
        // chip pins at its max_stable ceiling; nothing overclocks; the loop
        // reports saturation and the integral never winds up.
        let chips: Vec<ChipProfile> = (0..3).flat_map(|_| grade_b_chips(63, 700)).collect();
        let nominal = PowerModel::new_bm1387();
        let plant = PowerModel::new_bm1387().with_c_eff(nominal.c_eff() * 1.08);
        let env = nominal.achievable_power_envelope(9.1, &chips, 300, 3, None);

        // No slew limit → the command reaches the ceiling immediately; watchdog
        // off so we isolate the envelope-clamp safety property.
        let mut ctrl =
            WattTargetController::with_pid(nominal.clone(), WattTargetPid::new().with_no_slew())
                .without_divergence_watchdog();
        let mut measured = env.floor_watts;
        let mut last: Option<WattControlStep> = None;
        for _ in 0..40 {
            let s = ctrl.step(
                9999.0,
                &measured_sample(measured),
                9.1,
                &chips,
                300,
                3,
                None,
            );
            measured = plant_board_watts(&plant, &nominal, 9.1, &s.freqs, 3);
            last = Some(s);
        }
        let s = last.expect("ran at least one step");
        // Command clamped to the ceiling, not the 9999 W request.
        assert!(
            (s.command.commanded_watts - env.ceiling_watts).abs() <= env.ceiling_watts * 0.001,
            "command {:.1} W must clamp to ceiling {:.1} W, not the 9999 W request",
            s.command.commanded_watts,
            env.ceiling_watts
        );
        assert!(s.command.saturated_high, "must report ceiling saturation");
        // Every chip is at (or below) its max_stable ceiling — never overclocked.
        assert!(
            s.freqs.iter().all(|&f| f <= 700),
            "no chip may exceed max_stable 700 chasing an impossible target: {:?}",
            &s.freqs[..4.min(s.freqs.len())]
        );
        // The best we can do (max_stable everywhere) is what the model realises.
        assert!(
            s.modeled_watts <= env.ceiling_watts + 1e-6,
            "modeled power {:.1} must not exceed envelope ceiling {:.1}",
            s.modeled_watts,
            env.ceiling_watts
        );
        // Measured is below the impossible target forever → integral frozen.
        assert!(
            ctrl.pid().integral().abs() < 1e-6,
            "integral must not wind up against an unreachable target, got {}",
            ctrl.pid().integral()
        );
    }

    #[test]
    fn allocate_budget_output_stays_inside_envelope_across_the_sweep() {
        // Independent of convergence: for ANY commanded budget, allocate_budget
        // never produces a frequency set drawing (modeled) more than the
        // envelope ceiling, and clamped budgets never exceed max_stable.
        let chips = grade_b_chips(63, 700);
        let model = PowerModel::new_bm1387();
        let env = model.achievable_power_envelope(9.1, &chips, 300, 1, None);
        for pct in 0..=20 {
            let budget = env.floor_watts + env.span_watts() * (pct as f64 / 20.0) * 2.0; // sweep past ceiling
            let commanded = env.clamp(budget);
            let freqs = model.allocate_budget(commanded, 9.1, &chips, 300, 1);
            assert!(
                freqs.iter().all(|&f| f <= 700),
                "budget {:.0} W (clamped {:.0}) overclocked past max_stable: {:?}",
                budget,
                commanded,
                &freqs[..4]
            );
        }
    }

    // ---- Divergence watchdog (c) --------------------------------------------

    #[test]
    fn divergence_watchdog_does_not_false_trip_on_healthy_convergence() {
        // A healthy, slew-limited loop that converges cleanly must NEVER trip
        // the watchdog (the amplitude-shrink guard rejects converging ringing).
        let chips: Vec<ChipProfile> = (0..3).flat_map(|_| grade_b_chips(63, 700)).collect();
        let env = PowerModel::new_bm1387().achievable_power_envelope(9.1, &chips, 300, 3, None);
        let mut cfg = SimConfig::base(1100.0, &chips, 3, env.floor_watts);
        cfg.bias = 1.08;
        cfg.slew = SlewMode::Abs(env.span_watts() * 0.10);
        cfg.watchdog = true;
        cfg.max_steps = 160;
        let res = run_sim_cfg(cfg);
        assert!(
            !res.watchdog_tripped,
            "watchdog must not fire on a healthy converging loop"
        );
        assert!(res.final_error_frac <= 0.02);
    }

    #[test]
    fn divergence_watchdog_unit_trips_on_sustained_oscillation_only() {
        // Direct unit test of the detector. A sustained fixed-amplitude limit
        // cycle far outside the band must trip; a converging (shrinking) ring
        // must not; a slow monotonic approach must not.
        let target = 1000.0;

        // (1) Sustained oscillation: ±200 W (20% >> 5% band), constant amplitude.
        let mut wd = DivergenceWatchdog::new();
        let mut tripped = false;
        for i in 0..40 {
            let err = if i % 2 == 0 { 200.0 } else { -200.0 };
            tripped |= wd.observe(err, target);
        }
        assert!(tripped, "constant-amplitude limit cycle must trip");
        assert!(wd.tripped());

        // (2) Converging ring: oscillates but amplitude decays into the band.
        let mut wd2 = DivergenceWatchdog::new();
        let mut amp = 300.0;
        let mut tripped2 = false;
        for i in 0..60 {
            let err = if i % 2 == 0 { amp } else { -amp };
            tripped2 |= wd2.observe(err, target);
            amp *= 0.85; // shrink each swing → converges
        }
        assert!(
            !tripped2,
            "a converging (amplitude-decaying) ring must NOT trip the watchdog"
        );

        // (3) Slow monotonic approach: outside band a long time, no sign flips.
        let mut wd3 = DivergenceWatchdog::new();
        let mut tripped3 = false;
        for i in 0..60 {
            let err = 400.0 - (i as f64) * 5.0; // 400 → decreasing, same sign
            tripped3 |= wd3.observe(err.max(1.0), target);
        }
        assert!(
            !tripped3,
            "a slow monotonic (non-oscillating) approach must NOT trip"
        );
    }

    #[test]
    fn divergence_watchdog_tames_a_3x_gain_limit_cycle() {
        // (c) The probe saw a permanent oscillation at 3x gain with NO
        // detection. With the watchdog ON it must trip and fall back to the
        // derated safe feed-forward, bounding the overshoot and NEVER
        // overclocking past the envelope. Compare against the watchdog OFF arm.
        let chips: Vec<ChipProfile> = (0..3).flat_map(|_| grade_b_chips(63, 700)).collect();
        let env = PowerModel::new_bm1387().achievable_power_envelope(9.1, &chips, 300, 3, None);

        // No slew + 3x gain → a genuine limit cycle.
        let mk = |watchdog: bool| {
            let mut cfg = SimConfig::base(1100.0, &chips, 3, env.floor_watts);
            cfg.bias = 1.08;
            cfg.slew = SlewMode::None;
            cfg.gain_mult = 3.0;
            cfg.watchdog = watchdog;
            cfg.max_steps = 200;
            cfg.band_frac = 0.05;
            run_sim_cfg(cfg)
        };

        let off = mk(false);
        let on = mk(true);
        eprintln!(
            "[watchdog 3x-gain] OFF: overshoot={:.3} settled_err={:.3} converged={:?} | \
             ON: overshoot={:.3} settled_err={:.3} tripped={} converged={:?}",
            off.max_overshoot_frac,
            off.settled_error_frac,
            off.steps_to_converge,
            on.max_overshoot_frac,
            on.settled_error_frac,
            on.watchdog_tripped,
            on.steps_to_converge,
        );

        // Detection: the watchdog MUST fire on the limit cycle.
        assert!(
            on.watchdog_tripped,
            "watchdog must detect the 3x-gain limit cycle (probe saw no detection)"
        );
        // The OFF arm oscillates without ever settling into the 5% band.
        assert!(
            off.steps_to_converge.is_none() || off.settled_error_frac > 0.05,
            "no-watchdog arm should keep oscillating (settled_err {:.3})",
            off.settled_error_frac
        );
        // With the watchdog, the settled band-wander is meaningfully tamer than
        // the free-running oscillation.
        assert!(
            on.settled_error_frac < off.settled_error_frac,
            "watchdog must tame the oscillation: on {:.3} !< off {:.3}",
            on.settled_error_frac,
            off.settled_error_frac
        );
        // Fail-safe in BOTH arms: never overclock past the chip ceiling.
        assert!(on.peak_freq <= on.max_ceiling, "watchdog arm overclocked");
        assert!(
            off.peak_freq <= off.max_ceiling,
            "no-watchdog arm overclocked"
        );
    }

    // ---- Harder deterministic sims (d): additive bias / noise / delay -------

    #[test]
    fn hard_case_static_overhead_additive_bias_is_absorbed() {
        // (d)(i) A constant ADDITIVE plant error (unknown static overhead) that
        // the multiplicative model cannot represent. The integral term must
        // absorb it; the settled band-wander must stay tight. Prove finite slew
        // helps vs no-slew.
        let chips: Vec<ChipProfile> = (0..3).flat_map(|_| grade_b_chips(63, 700)).collect();
        let env = PowerModel::new_bm1387().achievable_power_envelope(9.1, &chips, 300, 3, None);

        let mk = |slew: SlewMode| {
            let mut cfg = SimConfig::base(1100.0, &chips, 3, env.floor_watts);
            cfg.bias = 1.04;
            cfg.additive_bias_w = 60.0; // constant +60 W the model never sees
            cfg.slew = slew;
            cfg.watchdog = true;
            cfg.max_steps = 220;
            cfg.band_frac = 0.02;
            run_sim_cfg(cfg)
        };
        let no_slew = mk(SlewMode::None);
        let finite = mk(SlewMode::Default);
        eprintln!(
            "[additive +60W] no_slew: overshoot={:.3} settled_err={:.3} final_err={:.3} | \
             finite: overshoot={:.3} settled_err={:.3} final_err={:.3}",
            no_slew.max_overshoot_frac,
            no_slew.settled_error_frac,
            no_slew.final_error_frac,
            finite.max_overshoot_frac,
            finite.settled_error_frac,
            finite.final_error_frac,
        );
        // The integral absorbs the additive bias → settled within 2%.
        assert!(
            finite.settled_error_frac <= 0.02,
            "additive bias must be absorbed to <=2% band-wander, got {:.3}",
            finite.settled_error_frac
        );
        assert!(finite.final_error_frac <= 0.02);
        // Finite slew never overshoots more than the aggressive no-slew arm.
        assert!(
            finite.max_overshoot_frac <= no_slew.max_overshoot_frac + 1e-9,
            "finite slew must not overshoot more than no-slew ({:.3} vs {:.3})",
            finite.max_overshoot_frac,
            no_slew.max_overshoot_frac
        );
        assert!(finite.peak_freq <= finite.max_ceiling);
    }

    #[test]
    fn hard_case_measurement_noise_stays_bounded() {
        // (d)(ii) ±3% measurement noise. D-on-measurement would amplify it into
        // the command; the loop must stay bounded and settle near the target
        // (the residual band can't beat the noise floor). Finite slew must not
        // make the peak command overshoot worse than no-slew.
        let chips: Vec<ChipProfile> = (0..3).flat_map(|_| grade_b_chips(63, 700)).collect();
        let env = PowerModel::new_bm1387().achievable_power_envelope(9.1, &chips, 300, 3, None);

        let mk = |slew: SlewMode| {
            let mut cfg = SimConfig::base(1100.0, &chips, 3, env.floor_watts);
            cfg.bias = 1.06;
            cfg.noise_frac = 0.03;
            cfg.slew = slew;
            cfg.watchdog = true;
            cfg.max_steps = 240;
            cfg.band_frac = 0.05;
            run_sim_cfg(cfg)
        };
        let no_slew = mk(SlewMode::None);
        let finite = mk(SlewMode::Default);
        eprintln!(
            "[noise ±3%] no_slew: overshoot={:.3} settled_err={:.3} tripped={} | \
             finite: overshoot={:.3} settled_err={:.3} tripped={}",
            no_slew.max_overshoot_frac,
            no_slew.settled_error_frac,
            no_slew.watchdog_tripped,
            finite.max_overshoot_frac,
            finite.settled_error_frac,
            finite.watchdog_tripped,
        );
        // Settled within ~2x the noise floor (noise itself is ±3% on the TRUE
        // signal, so the true measured can wander up to ~the noise amplitude).
        assert!(
            finite.settled_error_frac <= 0.06,
            "noisy loop settled band-wander {:.3} must stay bounded (<=6%)",
            finite.settled_error_frac
        );
        // Command stability: finite slew does not overshoot more than no-slew.
        assert!(
            finite.max_overshoot_frac <= no_slew.max_overshoot_frac + 1e-9,
            "finite slew overshoot {:.3} must not exceed no-slew {:.3} under noise",
            finite.max_overshoot_frac,
            no_slew.max_overshoot_frac
        );
        // Fail-safe under noise.
        assert!(finite.peak_freq <= finite.max_ceiling);
    }

    #[test]
    fn hard_case_actuator_delay_overshoot_tamed_by_finite_slew() {
        // (d)(iii) A 2-tick actuator/telemetry delay — the classic overshoot
        // driver (the probe saw 31% overshoot WITHOUT finite slew). Prove the
        // finite default slew slashes the overshoot vs no-slew.
        let chips: Vec<ChipProfile> = (0..3).flat_map(|_| grade_b_chips(63, 700)).collect();
        let env = PowerModel::new_bm1387().achievable_power_envelope(9.1, &chips, 300, 3, None);

        let mk = |slew: SlewMode| {
            let mut cfg = SimConfig::base(1100.0, &chips, 3, env.floor_watts);
            cfg.bias = 1.05;
            cfg.extra_delay = 2; // ~2 extra ticks of loop delay
            cfg.slew = slew;
            cfg.watchdog = true;
            cfg.max_steps = 240;
            // 3% band: the extra phase lag leaves a small residual ripple, so the
            // delay test scores "converged" at 3% (this test is about overshoot
            // taming, not the tight-2% convergence proven elsewhere).
            cfg.band_frac = 0.03;
            run_sim_cfg(cfg)
        };
        let no_slew = mk(SlewMode::None);
        let finite = mk(SlewMode::Default);
        eprintln!(
            "[delay 2-tick] no_slew: overshoot={:.3} final_err={:.3} converged={:?} | \
             finite: overshoot={:.3} final_err={:.3} converged={:?}",
            no_slew.max_overshoot_frac,
            no_slew.final_error_frac,
            no_slew.steps_to_converge,
            finite.max_overshoot_frac,
            finite.final_error_frac,
            finite.steps_to_converge,
        );
        // The naive no-slew arm overshoots hard under delay.
        assert!(
            no_slew.max_overshoot_frac >= 0.12,
            "no-slew under delay should overshoot badly (got {:.3})",
            no_slew.max_overshoot_frac
        );
        // The finite default slew tames it to a small overshoot.
        assert!(
            finite.max_overshoot_frac <= 0.08,
            "finite slew must tame delay overshoot to <=8% (got {:.3})",
            finite.max_overshoot_frac
        );
        // And it is strictly better than the no-slew arm.
        assert!(
            finite.max_overshoot_frac < no_slew.max_overshoot_frac,
            "finite slew {:.3} must beat no-slew {:.3} under delay",
            finite.max_overshoot_frac,
            no_slew.max_overshoot_frac
        );
        // Still converges into the 2% band despite the delay.
        assert!(
            finite.steps_to_converge.is_some(),
            "finite-slew loop must still converge under a 2-tick delay"
        );
        assert!(finite.peak_freq <= finite.max_ceiling);
    }
}
