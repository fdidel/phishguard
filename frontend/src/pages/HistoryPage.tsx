/**
 * The "Scan history" page: recorded scans plus an aggregate summary.
 */

import { useEffect, useState } from 'react';
import ScanHistoryTable from '../components/ScanHistoryTable';
import { fetchReportSummary } from '../services/api';
import type { ReportSummaryResponse } from '../types';

interface HistoryPageProps {
  refreshToken?: number;
}

export default function HistoryPage({ refreshToken = 0 }: HistoryPageProps) {
  const [summary, setSummary] = useState<ReportSummaryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchReportSummary()
      .then((result) => {
        if (cancelled) return;
        if (result.ok) {
          setSummary(result.data);
        } else {
          setError(result.message);
        }
      })
      .catch(() => {
        if (!cancelled) setError('The summary could not be loaded.');
      });
    return () => {
      cancelled = true;
    };
  }, [refreshToken]);

  return (
    <div className="page">
      {error ? (
        <p className="panel__error" role="alert">
          {error}
        </p>
      ) : null}

      {summary ? (
        <section className="panel" aria-labelledby="summary-heading">
          <h2 id="summary-heading" className="panel__title">
            Summary of recorded scans
          </h2>
          <div className="stat-grid">
            <div className="stat">
              <span className="stat__value">{summary.total_scans}</span>
              <span className="stat__label">Total scans</span>
            </div>
            <div className="stat stat--dangerous">
              <span className="stat__value">{summary.dangerous_scans}</span>
              <span className="stat__label">Dangerous</span>
            </div>
            <div className="stat stat--suspicious">
              <span className="stat__value">{summary.suspicious_scans}</span>
              <span className="stat__label">Suspicious</span>
            </div>
            <div className="stat stat--safe">
              <span className="stat__value">{summary.safe_scans}</span>
              <span className="stat__label">No indicators found</span>
            </div>
            <div className="stat stat--failed">
              <span className="stat__value">{summary.failed_scans}</span>
              <span className="stat__label">Failed analyses</span>
            </div>
            <div className="stat">
              <span className="stat__value">{summary.unique_domains}</span>
              <span className="stat__label">Unique domains</span>
            </div>
            <div className="stat">
              <span className="stat__value">
                {summary.average_risk_score === null ? '—' : summary.average_risk_score}
              </span>
              <span className="stat__label">Average risk score</span>
            </div>
          </div>
        </section>
      ) : null}

      <ScanHistoryTable refreshToken={refreshToken} />
    </div>
  );
}
