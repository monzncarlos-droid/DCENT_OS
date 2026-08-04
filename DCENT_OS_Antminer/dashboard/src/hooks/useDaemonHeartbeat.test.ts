// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, cleanup } from '@testing-library/react';

const h = vi.hoisted(() => ({ store: { lastWsFrameAt: 0 } }));

vi.mock('../store/miner', () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const useMinerStore: any = (sel?: (s: unknown) => unknown) => (sel ? sel(h.store) : h.store);
  useMinerStore.getState = () => h.store;
  return { useMinerStore };
});
vi.mock('../api/client', () => ({
  DAEMON_DISCONNECTED_EVENT: 'daemon:disconnected',
  DAEMON_RECONNECTED_EVENT: 'daemon:reconnected',
}));

import { useDaemonHeartbeat } from './useDaemonHeartbeat';

function healthResponse(alive: boolean) {
  return vi.fn(async () => new Response(JSON.stringify({ alive, pid: 123 }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  }));
}

beforeEach(() => {
  vi.useFakeTimers();
  h.store.lastWsFrameAt = 0;
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('useDaemonHeartbeat (finding 3: a fresh WebSocket frame is daemon-liveness evidence)', () => {
  it('does NOT report the daemon dead when REST never re-proves but WS frames stay fresh', async () => {
    (globalThis as { fetch: typeof fetch }).fetch = healthResponse(true) as unknown as typeof fetch;

    const { result } = renderHook(() => useDaemonHeartbeat());
    // No DAEMON_RECONNECTED_EVENT ever fires (REST stats 404 on a heater / bring-up
    // unit), so REST liveness never refreshes. Keep WS frames fresh while advancing
    // well past the 30s starting grace — pre-fix this flipped to a false 'dead'.
    for (let i = 0; i < 14; i++) {
      h.store.lastWsFrameAt = Date.now();
      await vi.advanceTimersByTimeAsync(3000);
    }
    expect(result.current.state).toBe('alive');
  });

  it('still reports dead past the grace window when neither REST nor WS frames are fresh', async () => {
    (globalThis as { fetch: typeof fetch }).fetch = healthResponse(true) as unknown as typeof fetch;
    h.store.lastWsFrameAt = 0; // no WS frame ever

    const { result } = renderHook(() => useDaemonHeartbeat());
    // Advance in interval-sized steps so each async probe fully drains (a single
    // large advance can leave an async interval callback un-drained in vitest).
    for (let i = 0; i < 14; i++) {
      await vi.advanceTimersByTimeAsync(3000); // ~42s total, past 30s STARTING_GRACE_MS
    }
    expect(result.current.state).toBe('dead');
  });
});
