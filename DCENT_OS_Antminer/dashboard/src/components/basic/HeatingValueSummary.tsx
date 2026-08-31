import React, { useEffect, useState } from 'react';
import { useMinerStore } from '../../store/miner';
import { getLiveDisplayWallWatts } from '../../utils/power';
import { glossaryText } from '../../utils/glossary';
import { api } from '../../api/client';
import {
  applyTakeRates,
  donationTakePercent,
  DEFAULT_DONATION_PERCENT,
  loadPoolFeePercent,
  seasonalHeatCredit,
  monthsToFraction,
  findHeatingZone,
} from '../../utils/thermal';

export function HeatingValueSummary() {
  const heater = useMinerStore(s => s.heaterStatus);
  const status = useMinerStore(s => s.status);
  const settings = useMinerStore(s => s.settings);

  const [showHeatCredit, setShowHeatCredit] = useState(false);
  const [donationPercent, setDonationPercent] = useState(DEFAULT_DONATION_PERCENT);
  const [poolFeePercent] = useState(() => loadPoolFeePercent());

  useEffect(() => {
    let cancelled = false;
    api.getDonationConfig()
      .then(cfg => {
        if (!cancelled) setDonationPercent(donationTakePercent(cfg));
      })
      .catch(() => {
        if (!cancelled) setDonationPercent(DEFAULT_DONATION_PERCENT);
      });
    return () => { cancelled = true; };
  }, []);

  const stats = useMinerStore(s => s.stats);
  const hashrateGhs = status?.hashrate_ghs ?? heater?.hashrate_ghs ?? 0;
  // Economic cost must be live wall-power backed; display/model fallback watts
  // are fine for warmth estimates elsewhere, but not for billing math.
  const powerWatts = getLiveDisplayWallWatts(heater, stats?.power);
  const uptimeS = status?.uptime_s ?? 0;
  const hoursRunning = uptimeS / 3600;

  // Sats earned today in USD — net after donation + pool fee. Heat-credit is
  // a separate optional USD estimate and is never added to this Bitcoin figure.
  const satsToday = heater?.sats_today ?? 0;
  const taken = applyTakeRates(satsToday, donationPercent, poolFeePercent);
  const satsUsd = (taken.netSats / 100_000_000) * settings.btcPrice;
  const grossSatsUsd = (satsToday / 100_000_000) * settings.btcPrice;

  // Electricity cost: (watts / 1000) * hoursRunning * electricityRate
  const electricityCost = powerWatts > 0
    ? (powerWatts / 1000) * hoursRunning * settings.electricityRate
    : null;

  // BTC net never includes heat-credit. Missing wall power → net excludes electricity cost.
  const netValue = electricityCost == null ? satsUsd : satsUsd - electricityCost;

  const heatZone = findHeatingZone('quebec-hydro');
  const dailyHeatCreditUsd = showHeatCredit && powerWatts > 0
    ? seasonalHeatCredit({
        wall_watts: powerWatts,
        displaced_fraction: heatZone?.default_displaced_fraction ?? 0.85,
        heating_season_active: monthsToFraction(heatZone?.season_months_default ?? 7),
        kwh_rate: settings.electricityRate,
      })
    : 0;

  // HEATER-5: when the operator hasn't confirmed an electricity rate, the rate
  // is the daemon default guess — label any cost/net figure as an uncalibrated
  // estimate instead of presenting it as a confident dollar amount.
  const rateUncalibrated = settings.electricityRateCalibrated === false;

  // If not mining, show zero state
  const isMining = hashrateGhs > 0;

  return (
    <div className="heating-value-summary">
      <div className="heating-value-amount">
        ${isMining ? netValue.toFixed(2) : '0.00'}
      </div>
      <div
        className="heating-value-label"
        data-tooltip={glossaryText('net_value_offset')}
      >
        Today's net Bitcoin value
      </div>
      {isMining && (satsUsd > 0 || electricityCost != null) && (
        <div className="hv-breakdown">
          <div className="hv-row">
            <span>Bitcoin earned (net)</span>
            <span className="hv-amount hv-amount--earn">+${satsUsd.toFixed(2)}</span>
          </div>
          {(donationPercent > 0 || poolFeePercent > 0) && (
            <div className="hv-row">
              <span>
                Gross before donation {donationPercent.toFixed(1)}%
                {poolFeePercent > 0 ? ` + pool fee ${poolFeePercent.toFixed(1)}%` : ''}
              </span>
              <span className="hv-amount">+${grossSatsUsd.toFixed(2)}</span>
            </div>
          )}
          <div className="hv-row">
            <span>Electricity cost{rateUncalibrated ? ' (uncalibrated estimate)' : ''}</span>
            <span className="hv-amount hv-amount--cost">
              {electricityCost != null ? `-$${electricityCost.toFixed(2)}` : 'Unavailable'}
            </span>
          </div>
          {electricityCost == null && (
            <div id="heating-value-offset-note" className="hv-offset-note">
              Live wall-power unavailable; net excludes electricity cost.
            </div>
          )}
          <div className={`hv-row hv-row--total${netValue >= 0 ? ' is-positive' : ' is-negative'}`}>
            <span>Net BTC</span>
            <span data-testid="heating-net-btc">${netValue >= 0 ? '+' : '-'}${Math.abs(netValue).toFixed(2)}</span>
          </div>
          {showHeatCredit && (
            <div className="hv-row" data-testid="seasonal-heat-credit">
              <span>Optional seasonal heat-credit (not Bitcoin)</span>
              <span className="hv-amount hv-amount--earn">${dailyHeatCreditUsd.toFixed(2)}/day est.</span>
            </div>
          )}
        </div>
      )}

      {isMining && (
        <div
          className="hv-mode-toggle"
          data-tooltip="Optional kWh × seasonal factor × $/kWh estimate. Never added to sats."
        >
          <span>Show seasonal heat-credit estimate?</span>
          <button
            type="button"
            className={`hv-switch${showHeatCredit ? ' is-on' : ''}`}
            onClick={() => setShowHeatCredit(!showHeatCredit)}
            role="switch"
            aria-checked={showHeatCredit}
            aria-label="Include optional seasonal heat-credit estimate"
          >
            <span className="hv-switch__thumb" aria-hidden="true" />
          </button>
          <span className={`hv-mode-state${showHeatCredit ? ' is-yes' : ''}`}>
            {showHeatCredit ? 'Optional on' : 'Off'}
          </span>
        </div>
      )}
    </div>
  );
}
