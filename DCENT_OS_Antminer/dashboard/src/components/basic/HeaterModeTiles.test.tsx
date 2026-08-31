// @vitest-environment jsdom
//
// Quiet tile must commit PWM/MHz through buildNightModeCommitRequest.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

import { api } from '../../api/client';
import { useMinerStore } from '../../store/miner';
import type { NightModeResponse } from '../../api/types';
import { buildNightModeCommitRequest } from './NightMode';
import { HeaterModeTiles } from './HeaterModeTiles';

vi.mock('../../api/client', () => ({
  api: {
    setNightMode: vi.fn().mockResolvedValue({ status: 'ok' }),
    setHeaterTarget: vi.fn().mockResolvedValue({ status: 'ok' }),
  },
}));

const liveNight: NightModeResponse = {
  enabled: false,
  start_hour: 22,
  end_hour: 7,
  max_fan_pwm: 20,
  power_reduction_pct: 40,
  max_frequency_mhz: 350,
  active: false,
};

describe('HeaterModeTiles Quiet night ceilings', () => {
  beforeEach(() => {
    vi.mocked(api.setNightMode).mockClear().mockResolvedValue({ status: 'ok' } as never);
    useMinerStore.setState({ nightMode: liveNight, heaterPresets: [] });
  });

  afterEach(() => {
    cleanup();
    useMinerStore.setState({ nightMode: null });
  });

  it('toggles Quiet with the shipped PWM/frequency commit body', async () => {
    render(<HeaterModeTiles />);
    fireEvent.click(screen.getByRole('button', { name: /Quiet/i }));
    await vi.waitFor(() => {
      expect(api.setNightMode).toHaveBeenCalled();
    });
    expect(api.setNightMode).toHaveBeenCalledWith(
      buildNightModeCommitRequest({
        enabled: true,
        startHour: 22,
        endHour: 7,
        reductionPct: 40,
        maxFanPwm: 20,
        maxFrequencyMhz: 350,
      }),
    );
  });

  it('commits slider PWM while Quiet is on', async () => {
    useMinerStore.setState({
      nightMode: { ...liveNight, enabled: true },
    });
    render(<HeaterModeTiles />);
    const fan = document.getElementById('quiet-night-fan') as HTMLInputElement;
    expect(fan).toBeTruthy();
    expect(fan.value).toBe('20');
    fireEvent.change(fan, { target: { value: '15' } });
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
        maxFrequencyMhz: 350,
      }),
    );
  });
});
