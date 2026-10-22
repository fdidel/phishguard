/**
 * Risk score meter.
 *
 * The meter uses a numeric readout and a textual band, so the information is
 * not conveyed by the bar colour alone.
 */

interface RiskScoreProps {
  score: number | null;
  probability: number | null;
}

function bandFor(score: number): { label: string; tone: string } {
  if (score >= 70) return { label: 'High', tone: 'dangerous' };
  if (score >= 35) return { label: 'Elevated', tone: 'suspicious' };
  return { label: 'Low', tone: 'safe' };
}

export default function RiskScore({ score, probability }: RiskScoreProps) {
  if (score === null) {
    return (
      <div className="risk risk--unknown">
        <p className="risk__label">Risk score</p>
        <p className="risk__value">Not available</p>
        <p className="risk__hint">
          No score could be produced for this scan, so no risk level can be shown.
        </p>
      </div>
    );
  }

  const clamped = Math.max(0, Math.min(100, score));
  const band = bandFor(clamped);
  const percentText =
    probability === null ? '' : ` (model probability ${(probability * 100).toFixed(1)}%)`;

  return (
    <div className={`risk risk--${band.tone}`}>
      <p className="risk__label">
        Risk score <span className="risk__band">- {band.label} risk</span>
      </p>
      <p className="risk__value">
        {clamped}
        <span className="risk__scale"> / 100</span>
      </p>
      <div
        className="risk__track"
        role="meter"
        aria-valuenow={clamped}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Risk score ${clamped} out of 100, ${band.label} risk`}
      >
        <div className="risk__fill" style={{ width: `${clamped}%` }} />
      </div>
      <p className="risk__hint">
        Relative risk indicator derived from the calibrated model probability
        {percentText}. It is not a probability of harm and not a guarantee.
      </p>
    </div>
  );
}
