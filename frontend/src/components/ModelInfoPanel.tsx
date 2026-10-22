/**
 * Model provenance panel.
 *
 * Shows the real metrics recorded by the training run.  Nothing here is
 * invented in the browser - every number comes from
 * `GET /api/v1/model/metrics`.
 */

import { useEffect, useState } from 'react';
import { fetchModelInfo, fetchModelMetrics } from '../services/api';
import type { ModelInfoResponse, ModelMetricsResponse } from '../types';

function formatNumber(value: unknown, digits = 4): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—';
  return value.toFixed(digits);
}

export default function ModelInfoPanel() {
  const [info, setInfo] = useState<ModelInfoResponse | null>(null);
  const [metrics, setMetrics] = useState<ModelMetricsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    Promise.all([fetchModelInfo(), fetchModelMetrics()])
      .then(([infoResult, metricsResult]) => {
        if (cancelled) return;
        if (infoResult.ok) {
          setInfo(infoResult.data);
        } else {
          setError(infoResult.message);
        }
        if (metricsResult.ok) {
          setMetrics(metricsResult.data);
        } else if (!error) {
          setError(metricsResult.message);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return (
      <section className="panel" aria-busy="true">
        <p className="panel__meta">Loading model information…</p>
      </section>
    );
  }

  if (error && !info) {
    return (
      <section className="panel">
        <p className="panel__error" role="alert">
          {error}
        </p>
      </section>
    );
  }

  const testSet = (metrics?.test_set ?? {}) as Record<string, unknown>;
  const metricsBlock = (testSet.metrics ?? {}) as Record<string, unknown>;
  const errorRates = (testSet.error_rates ?? {}) as Record<string, unknown>;
  const dataset = (metrics?.dataset ?? {}) as Record<string, unknown>;

  return (
    <section className="panel" aria-labelledby="model-heading">
      <h2 id="model-heading" className="panel__title">
        Model provenance
      </h2>

      {error ? <p className="panel__error">{error}</p> : null}

      <dl className="definition-list">
        <div>
          <dt>Model version</dt>
          <dd data-testid="model-version">{info?.model_version ?? 'unavailable'}</dd>
        </div>
        <div>
          <dt>Algorithm</dt>
          <dd>{info?.algorithm ?? 'unavailable'}</dd>
        </div>
        <div>
          <dt>Trained at</dt>
          <dd>{info?.trained_at ? new Date(info.trained_at).toLocaleString() : 'unavailable'}</dd>
        </div>
        <div>
          <dt>Random seed</dt>
          <dd>{info?.random_seed ?? 'unavailable'}</dd>
        </div>
        <div>
          <dt>Feature schema</dt>
          <dd>{info?.feature_schema_version ?? 'unavailable'}</dd>
        </div>
        <div>
          <dt>Features used</dt>
          <dd>{info?.feature_count ?? 0}</dd>
        </div>
        <div>
          <dt>Dataset</dt>
          <dd>{String(dataset.name ?? 'unavailable')}</dd>
        </div>
        <div>
          <dt>Test samples</dt>
          <dd>{String(testSet.n_samples ?? testSet.total ?? 'unavailable')}</dd>
        </div>
      </dl>

      <h3 className="panel__subtitle">Held-out test performance</h3>
      <p className="panel__note">
        These numbers come from the real training run and were measured on a test partition
        that was never used for fitting or threshold selection.
      </p>
      <div className="table-wrapper">
        <table className="table table--compact">
          <caption className="visually-hidden">Held-out test metrics</caption>
          <thead>
            <tr>
              <th scope="col">Metric</th>
              <th scope="col">Value</th>
            </tr>
          </thead>
          <tbody>
            {[
              ['Accuracy', metricsBlock.accuracy],
              ['Precision', metricsBlock.precision],
              ['Recall', metricsBlock.recall],
              ['F1 score', metricsBlock.f1],
              ['False positive rate', errorRates.false_positive_rate],
              ['False negative rate', errorRates.false_negative_rate],
            ].map(([label, value]) => (
              <tr key={String(label)}>
                <th scope="row">{String(label)}</th>
                <td>{formatNumber(value)}</td>
              </tr>
            ))}
            <tr>
              <th scope="row">ROC-AUC</th>
              <td>
                {formatNumber(
                  (testSet.roc as Record<string, unknown> | undefined)?.roc_auc ??
                    (metrics?.thresholds ? undefined : undefined),
                )}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      {metrics?.model_comparison && metrics.model_comparison.length > 0 ? (
        <>
          <h3 className="panel__subtitle">Model comparison</h3>
          <div className="table-wrapper">
            <table className="table table--compact">
              <caption className="visually-hidden">Comparison of the trained candidates</caption>
              <thead>
                <tr>
                  <th scope="col">Model</th>
                  <th scope="col">Accuracy</th>
                  <th scope="col">F1</th>
                  <th scope="col">ROC-AUC</th>
                </tr>
              </thead>
              <tbody>
                {metrics.model_comparison.map((row, index) => (
                  <tr key={`${String(row.name ?? index)}`}>
                    <th scope="row">{String(row.name ?? `model ${index + 1}`)}</th>
                    <td>{formatNumber(row.test_accuracy ?? row.accuracy)}</td>
                    <td>{formatNumber(row.test_f1 ?? row.f1)}</td>
                    <td>{formatNumber(row.test_roc_auc ?? row.roc_auc)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : null}

      <h3 className="panel__subtitle">Decision thresholds</h3>
      <div className="table-wrapper">
        <table className="table table--compact">
          <caption className="visually-hidden">Thresholds used to map probabilities to verdicts</caption>
          <thead>
            <tr>
              <th scope="col">Threshold</th>
              <th scope="col">Value</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(info?.thresholds ?? {}).map(([key, value]) => (
              <tr key={key}>
                <th scope="row">{key.replace(/_/g, ' ')}</th>
                <td>{formatNumber(value, 4)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
