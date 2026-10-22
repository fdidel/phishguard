/**
 * Evidence panel: the per-prediction reasons behind a verdict.
 *
 * The list clearly separates
 *   - *evidence* observed for THIS URL, and
 *   - *global* feature importance, which is a property of the trained model
 *     and not a statement about this particular URL.
 */

import type { Explanation, Indicator } from '../types';

interface EvidenceListProps {
  explanation: Explanation | null;
  indicators: Indicator[];
}

function formatValue(value: number): string {
  if (!Number.isFinite(value)) return '-';
  if (Number.isInteger(value)) return String(value);
  return value.toFixed(3);
}

export default function EvidenceList({ explanation, indicators }: EvidenceListProps) {
  const evidence = explanation?.evidence?.length ? explanation.evidence : indicators;
  const contributions = explanation?.top_contributing_features ?? [];

  return (
    <section className="panel" aria-labelledby="evidence-heading">
      <h3 id="evidence-heading" className="panel__title">
        Why this verdict
      </h3>

      {evidence.length === 0 ? (
        <p className="panel__empty">
          No individual indicator stood out for this address. The verdict is based on the
          overall pattern of the {contributions.length > 0 ? 'features listed below' : 'URL'}.
        </p>
      ) : (
        <ul className="evidence">
          {evidence.map((item, index) => (
            <li className="evidence__item" key={`${item.category}-${index}`}>
              <span className="evidence__category">{item.category.replace(/_/g, ' ')}</span>
              <span className="evidence__description">{item.description}</span>
              {Number.isFinite(item.value) && item.value !== 0 ? (
                <span className="evidence__value">value: {formatValue(item.value)}</span>
              ) : null}
            </li>
          ))}
        </ul>
      )}

      {explanation?.note ? (
        <p className="panel__note" data-testid="explanation-note">
          {explanation.note}
        </p>
      ) : null}

      {contributions.length > 0 ? (
        <>
          <h4 className="panel__subtitle">Top contributing features for this prediction</h4>
          <table className="table table--compact">
            <caption className="visually-hidden">
              Feature contributions for this single prediction
            </caption>
            <thead>
              <tr>
                <th scope="col">Feature</th>
                <th scope="col">Value</th>
                <th scope="col">Contribution</th>
                <th scope="col">Global importance</th>
              </tr>
            </thead>
            <tbody>
              {contributions.map((contribution) => (
                <tr key={contribution.feature}>
                  <th scope="row">{contribution.feature.replace(/_/g, ' ')}</th>
                  <td>{formatValue(contribution.value)}</td>
                  <td>{formatValue(contribution.contribution)}</td>
                  <td>{formatValue(contribution.global_importance)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="panel__note">
            <strong>Contribution</strong> is this feature&rsquo;s effect on this single
            prediction. <strong>Global importance</strong> is a property of the trained model
            across the whole dataset - a high global importance does not by itself mean the
            feature triggered this particular verdict.
          </p>
        </>
      ) : null}
    </section>
  );
}
