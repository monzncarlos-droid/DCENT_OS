// @vitest-environment jsdom
//
// NightMode PWM / frequency sliders must ride the shipped
// `buildNightModeCommitRequest` → `api.setNightMode` path.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

import { api } from '../../api/client';
import { useMinerStore } from '../../store/miner';
import type { NightModeResponse } from '../../api/types';
import {
  NIGHT_FAN_PWM_SAFETY_CAP,
  NIGHT_FREQUENCY_DEFAULT_MHZ,
  NIGHT_FREQUENCY_MAX_MHZ,
  NIGHT_FREQUENCY_MIN_MHZ,
  NightMode,
  buildNightModeCommitRequest,
  clampNightFanPwm,
  clampNightFrequencyMhz,
} from './NightMode';

vi.mock('../../api/client', () => ({
  api: {
    setNightMode: vi.fn().mockResolvedValue({ status: 'ok' }),
  },
}));

const liveNight: NightModeResponse = {
  enabled: true,
  start_hour: 22,
  end_hour: 7,
  max_fan_pwm: 20,
  power_reduction_pct: 40,
  max_frequency_mhz: 350,
  active: false,
};

describe('buildNightModeCommitRequest', () => {
  it('sends clamped PWM and frequency on the live POST body', () => {
    expect(clampNightFanPwm(80)).toBe(NIGHT_FAN_PWM_SAFETY_CAP);
    expect(clampNightFanPwm(20)).toBe(20);
    expect(clampNightFrequencyMhz(100)).toBe(NIGHT_FREQUENCY_MIN_MHZ);
    expect(clampNightFrequencyMhz(900)).toBe(NIGHT_FREQUENCY_MAX_MHZ);
    expect(clampNightFrequencyMhz(0)).toBe(NIGHT_FREQUENCY_DEFAULT_MHZ);

    const body = buildNightModeCommitRequest({
      enabled: true,
      startHour: 22,
      endHour: 7,
      reductionPct: 40,
      maxFanPwm: 80,
      maxFrequencyMhz: 350,
    });
    expect(body.max_fan_pwm).toBe(30);
    expect(body.max_frequency_mhz).toBe(350);
    expect(body.power_reduction_pct).toBe(40);
    expect(body.enabled).toBe(true);
  });
});

describe('NightMode sliders commit PWM and frequency', () => {
  beforeEach(() => {
    vi.mocked(api.setNightMode).mockClear().mockResolvedValue({ status: 'ok' } as never);
    useMinerStore.setState({ nightMode: liveNight });
  });

  afterEach(() => {
    cleanup();
    useMinerStore.setState({ nightMode: null });
  });

  it('renders the PWM and frequency sliders and saves their values', async () => {
    render(<NightMode />);

    const fan = document.getElementById('night-mode-fan') as HTMLInputElement;
    const freq = document.getElementById('night-mode-frequency') as HTMLInputElement;
    expect(fan).toBeTruthy();
    expect(freq).toBeTruthy();
    expect(fan.max).toBe(String(NIGHT_FAN_PWM_SAFETY_CAP));
    expect(fan.value).toBe('20');
    expect(freq.value).toBe('350');

    fireEvent.change(fan, { target: { value: '15' } });
    fireEvent.change(freq, { target: { value: '320' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save Night Mode' }));

    await vi.waitFor(() => {
      expect(api.setNightMode).toHaveBeenCalled();
    });
    expect(api.setNightMode).toHaveBeenCalledWith(
      buildNightModeCommitRequest({
        enabled: true,
        startHour: 22,
        endHour: 7,
        reductionPct: 40,
        maxFanPwm: 15,
        maxFrequencyMhz: 320,
      }),
    );
  });
});
