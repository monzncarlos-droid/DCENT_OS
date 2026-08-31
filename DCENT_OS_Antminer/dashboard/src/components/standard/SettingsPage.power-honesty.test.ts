import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

const source = readFileSync('src/components/standard/settings/GeneralTab.tsx', 'utf8');

describe('Settings profitability power honesty', () => {
  it('does not label standby fallback watts as live power', () => {
    expect(source).toContain('getLiveWallWatts');
    expect(source).toContain('Based on live wall power');
    expect(source).toContain('Power unavailable; cost uses');
    expect(source).toContain('standby assumption');
    expect(source).not.toContain('Based on live power: {watts}W');
  });

  it('passes donation and pool-fee take-rates into profitability math', () => {
    expect(source).toContain('donationTakePercent');
    expect(source).toContain('DEFAULT_DONATION_PERCENT');
    expect(source).toContain('loadPoolFeePercent');
    expect(source).toContain('getDonationConfig');
    expect(source).toContain('donationPercent');
    expect(source).toContain('poolFeePercent');
    expect(source).toMatch(
      /estimateDailyProfit\([\s\S]*donationPercent[\s\S]*poolFeePercent/,
    );
    // Omitting takeRates makes estimateDailyProfit treat donation as 0%.
    expect(source).not.toMatch(
      /estimateDailyProfit\(\s*hashrate\s*,\s*watts\s*,\s*settings\.btcPrice\s*,\s*settings\.electricityRate\s*,\s*networkDifficulty\s*\)/,
    );
  });
});
