import React, { useState, useEffect } from 'react';
import { useMinerStore } from '../../store/miner';
import { api } from '../../api/client';
import type { NightModeRequest } from '../../api/types';
import { glossaryText } from '../../utils/glossary';

/** Same home PWM-30 cap as `dcentrald_hal::fan::PWM_SAFETY_MAX`. */
export const NIGHT_FAN_PWM_SAFETY_CAP = 30;
export const NIGHT_FREQUENCY_MIN_MHZ = 200;
export const NIGHT_FREQUENCY_DEFAULT_MHZ = 400;
export const NIGHT_FREQUENCY_MAX_MHZ = 650;

export function clampNightFanPwm(pwm: number): number {
  if (!Number.isFinite(pwm)) return NIGHT_FAN_PWM_SAFETY_CAP;
  return Math.max(0, Math.min(NIGHT_FAN_PWM_SAFETY_CAP, Math.round(pwm)));
}

export function clampNightFrequencyMhz(mhz: number): number {
  if (!Number.isFinite(mhz) || mhz <= 0) return NIGHT_FREQUENCY_DEFAULT_MHZ;
  return Math.max(
    NIGHT_FREQUENCY_MIN_MHZ,
    Math.min(NIGHT_FREQUENCY_MAX_MHZ, Math.round(mhz)),
  );
}

/** Shipped NightMode POST body. Tests drive this, not a parallel oracle. */
export function buildNightModeCommitRequest(input: {
  enabled: boolean;
  startHour: number;
  endHour: number;
  reductionPct: number;
  maxFanPwm: number;
  maxFrequencyMhz: number;
}): NightModeRequest {
  return {
    enabled: input.enabled,
    start_hour: input.startHour,
    end_hour: input.endHour,
    max_fan_pwm: clampNightFanPwm(input.maxFanPwm),
    max_frequency_mhz: clampNightFrequencyMhz(input.maxFrequencyMhz),
    power_reduction_pct: input.reductionPct,
  };
}

export function NightMode() {
  const nightMode = useMinerStore(s => s.nightMode);
  const setNightMode = useMinerStore(s => s.setNightMode);
  const addToast = useMinerStore(s => s.addToast);

  const [enabled, setEnabled] = useState(nightMode?.enabled ?? false);
  const [startHour, setStartHour] = useState(nightMode?.start_hour ?? 22);
  const [endHour, setEndHour] = useState(nightMode?.end_hour ?? 7);
  const [reductionPct, setReductionPct] = useState(nightMode?.power_reduction_pct ?? 50);
  const [maxFanPwm, setMaxFanPwm] = useState(
    clampNightFanPwm(nightMode?.max_fan_pwm ?? NIGHT_FAN_PWM_SAFETY_CAP),
  );
  const [maxFrequencyMhz, setMaxFrequencyMhz] = useState(
    clampNightFrequencyMhz(nightMode?.max_frequency_mhz ?? NIGHT_FREQUENCY_DEFAULT_MHZ),
  );

  // Sync from store when API data arrives
  useEffect(() => {
    if (nightMode) {
      setEnabled(nightMode.enabled);
      setStartHour(nightMode.start_hour);
      setEndHour(nightMode.end_hour);
      setReductionPct(nightMode.power_reduction_pct);
      setMaxFanPwm(clampNightFanPwm(nightMode.max_fan_pwm));
      setMaxFrequencyMhz(
        clampNightFrequencyMhz(nightMode.max_frequency_mhz ?? NIGHT_FREQUENCY_DEFAULT_MHZ),
      );
    }
  }, [nightMode]);

  const commit = async (nextEnabled: boolean) => {
    const body = buildNightModeCommitRequest({
      enabled: nextEnabled,
      startHour,
      endHour,
      reductionPct,
      maxFanPwm,
      maxFrequencyMhz,
    });
    try {
      await api.setNightMode(body);
      setNightMode({
        enabled: nextEnabled,
        start_hour: startHour,
        end_hour: endHour,
        max_fan_pwm: body.max_fan_pwm ?? NIGHT_FAN_PWM_SAFETY_CAP,
        max_frequency_mhz: body.max_frequency_mhz,
        power_reduction_pct: reductionPct,
        active: nightMode?.active ?? false,
      });
    } catch {
      addToast('Failed to save night mode settings', 'error');
      throw new Error('night-mode commit failed');
    }
  };

  const handleSave = async () => {
    await commit(enabled).catch(() => {});
  };

  // HEATER-4: the toggle must be BIDIRECTIONAL. Previously it only flipped
  // local state, and the "Save" button (which commits to the daemon) lives
  // inside the `enabled &&` body — so toggling OFF hid the only control that
  // could persist the change and night mode could be ENABLED but never
  // DISABLED. Now every toggle commits to the server immediately (optimistic,
  // reverted on failure) and reflects the committed state from the store.
  const handleToggle = async () => {
    const next = !enabled;
    setEnabled(next);
    try {
      await commit(next);
    } catch {
      setEnabled(!next);
    }
  };

  const hourOptions = Array.from({ length: 24 }, (_, i) => i);
  const formatHour = (h: number) => `${h.toString().padStart(2, '0')}:00`;

  return (
    <div className="night-mode-card">
      <div className="night-mode-head">
        <div>
          <div
            className="night-mode-title"
            data-tooltip={glossaryText('cut_hash_before_noise')}
          >
            Night Mode
          </div>
          <div className="night-mode-subtitle">Reduce power during sleeping hours</div>
        </div>
        <div className="night-mode-head-actions">
          {nightMode?.active && (
            <span
              className="night-mode-active-pill"
              data-tooltip={glossaryText('night_mode_behaviour')}
            >
              Active
            </span>
          )}
          <button
            type="button"
            role="switch"
            aria-checked={enabled ? 'true' : 'false'}
            aria-label="Night mode"
            tabIndex={0}
            className={`toggle-switch night-mode-toggle${enabled ? ' on' : ''}`}
            onClick={() => { void handleToggle(); }}
            onKeyDown={(e) => {
              if (e.key === ' ' || e.key === 'Enter') {
                e.preventDefault();
                void handleToggle();
              }
            }}
          >
            <div className="thumb" aria-hidden="true" />
          </button>
        </div>
      </div>

      {enabled && (
        <div className="night-mode-body">
          <div className="night-mode-hours">
            <label className="night-mode-field">
              <div className="night-mode-field-label">Start</div>
              <select
                className="night-mode-select"
                value={startHour}
                onChange={e => setStartHour(Number(e.target.value))}
              >
                {hourOptions.map(h => <option key={h} value={h}>{formatHour(h)}</option>)}
              </select>
            </label>
            <label className="night-mode-field">
              <div className="night-mode-field-label">End</div>
              <select
                className="night-mode-select"
                value={endHour}
                onChange={e => setEndHour(Number(e.target.value))}
              >
                {hourOptions.map(h => <option key={h} value={h}>{formatHour(h)}</option>)}
              </select>
            </label>
          </div>

          <div>
            <div className="night-mode-slider-head">
              <label
                htmlFor="night-mode-reduction"
                data-tooltip={glossaryText('night_mode_behaviour')}
              >
                Power Reduction
              </label>
              <span aria-hidden="true" className="night-mode-slider-value">{reductionPct}%</span>
            </div>
            <input
              id="night-mode-reduction"
              className="night-mode-range"
              type="range"
              min={10}
              max={90}
              step={5}
              value={reductionPct}
              onChange={e => setReductionPct(Number(e.target.value))}
              aria-label={`Power reduction: ${reductionPct}%`}
              aria-valuemin={10}
              aria-valuemax={90}
              aria-valuenow={reductionPct}
              aria-valuetext={`${reductionPct}%`}
            />
            <div className="night-mode-range-scale">
              <span>10%</span>
              <span>90%</span>
            </div>
          </div>

          <div>
            <div className="night-mode-slider-head">
              <label
                htmlFor="night-mode-fan"
                data-tooltip={glossaryText('cut_hash_before_noise')}
              >
                Night fan PWM
              </label>
              <span aria-hidden="true" className="night-mode-slider-value">{maxFanPwm}</span>
            </div>
            <input
              id="night-mode-fan"
              className="night-mode-range"
              type="range"
              min={0}
              max={NIGHT_FAN_PWM_SAFETY_CAP}
              step={1}
              value={maxFanPwm}
              onChange={e => setMaxFanPwm(clampNightFanPwm(Number(e.target.value)))}
              aria-label={`Night fan PWM: ${maxFanPwm}`}
              aria-valuemin={0}
              aria-valuemax={NIGHT_FAN_PWM_SAFETY_CAP}
              aria-valuenow={maxFanPwm}
              aria-valuetext={`PWM ${maxFanPwm}`}
            />
            <div className="night-mode-range-scale">
              <span>0</span>
              <span>{NIGHT_FAN_PWM_SAFETY_CAP}</span>
            </div>
          </div>

          <div>
            <div className="night-mode-slider-head">
              <label
                htmlFor="night-mode-frequency"
                data-tooltip={glossaryText('night_mode_behaviour')}
              >
                Night frequency
              </label>
              <span aria-hidden="true" className="night-mode-slider-value">{maxFrequencyMhz} MHz</span>
            </div>
            <input
              id="night-mode-frequency"
              className="night-mode-range"
              type="range"
              min={NIGHT_FREQUENCY_MIN_MHZ}
              max={NIGHT_FREQUENCY_MAX_MHZ}
              step={10}
              value={maxFrequencyMhz}
              onChange={e => setMaxFrequencyMhz(clampNightFrequencyMhz(Number(e.target.value)))}
              aria-label={`Night frequency: ${maxFrequencyMhz} megahertz`}
              aria-valuemin={NIGHT_FREQUENCY_MIN_MHZ}
              aria-valuemax={NIGHT_FREQUENCY_MAX_MHZ}
              aria-valuenow={maxFrequencyMhz}
              aria-valuetext={`${maxFrequencyMhz} megahertz`}
            />
            <div className="night-mode-range-scale">
              <span>{NIGHT_FREQUENCY_MIN_MHZ} MHz</span>
              <span>{NIGHT_FREQUENCY_MAX_MHZ} MHz</span>
            </div>
          </div>

          <button
            type="button"
            className="settings-save-btn night-mode-save"
            onClick={handleSave}
          >
            Save Night Mode
          </button>
        </div>
      )}
    </div>
  );
}
