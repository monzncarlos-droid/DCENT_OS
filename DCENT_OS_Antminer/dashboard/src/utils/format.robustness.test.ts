import { describe, it, expect } from 'vitest';
import {
  formatHashrate,
  formatHashrateShort,
  formatWatts,
  formatSats,
  formatTemp,
} from './format';

// Finding 9: formatters must render an honest placeholder for non-finite input
// rather than the literal "NaN W" / "NaN°C" / "NaN MH/s" (matches formatEfficiency's
// truth contract). Also: raw floats are rounded, not printed as "743.2800001 W".
describe('formatter robustness (non-finite -> honest placeholder)', () => {
  it('formatHashrate', () => {
    expect(formatHashrate(NaN)).toBe('—');
    expect(formatHashrate(Infinity)).toBe('—');
    expect(formatHashrate(1200)).toBe('1.20 TH/s'); // valid input unchanged
  });

  it('formatHashrateShort', () => {
    expect(formatHashrateShort(NaN)).toEqual({ value: '—', unit: '' });
    expect(formatHashrateShort(1200)).toEqual({ value: '1.20', unit: 'TH/s' });
  });

  it('formatWatts', () => {
    expect(formatWatts(NaN)).toBe('—');
    expect(formatWatts(743.2800001)).toBe('743 W'); // rounded, not a raw float
    expect(formatWatts(1500)).toBe('1.50 kW');
  });

  it('formatSats', () => {
    expect(formatSats(NaN)).toBe('—');
    expect(formatSats(500.7)).toBe('501 sats'); // rounded
    expect(formatSats(2_500_000)).toBe('2.50M sats');
  });

  it('formatTemp', () => {
    expect(formatTemp(NaN)).toBe('—');
    expect(formatTemp(62.34)).toBe('62.3°C');
  });
});
