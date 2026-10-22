/**
 * Scan history table with filtering, pagination and a CSV export link.
 *
 * The CSV link points at the backend export endpoint.  It is a normal
 * download link - the dashboard never navigates to a scanned address.
 */

import { useEffect, useState } from 'react';
import {
  fetchScans,
  reportExportUrl,
  type ScanListQuery,
} from '../services/api';
import type { ScanSummary } from '../types';
import { describeVerdict } from './VerdictBadge';

interface ScanHistoryTableProps {
  /** Bumped by the parent to force a refresh after a new scan. */
  refreshToken?: number;
  onSelect?: (scan: ScanSummary) => void;
}

const CLASSIFICATIONS = ['', 'safe', 'suspicious', 'dangerous', 'inconclusive', 'unknown'];
const STATUSES = ['', 'completed', 'inconclusive', 'failed'];

export default function ScanHistoryTable({ refreshToken = 0, onSelect }: ScanHistoryTableProps) {
  const [items, setItems] = useState<ScanSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [classification, setClassification] = useState('');
  const [status, setStatus] = useState('');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    const query: ScanListQuery = { page, page_size: 20 };
    if (classification) query.classification = classification;
    if (status) query.status = status;
    if (search.trim()) query.search = search.trim();

    fetchScans(query)
      .then((result) => {
        if (cancelled) return;
        if (result.ok) {
          setItems(result.data.items);
          setTotal(result.data.total);
          setPages(Math.max(1, result.data.pages));
        } else {
          setError(result.message);
          setItems([]);
          setTotal(0);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [page, classification, status, search, refreshToken]);

  return (
    <section className="panel" aria-labelledby="history-heading">
      <div className="panel__header">
        <h2 id="history-heading" className="panel__title">
          Scan history
        </h2>
        <a className="button button--ghost" href={reportExportUrl()} download>
          Export CSV
        </a>
      </div>

      <div className="filters">
        <div className="filters__field">
          <label htmlFor="filter-classification">Verdict</label>
          <select
            id="filter-classification"
            value={classification}
            onChange={(event) => {
              setPage(1);
              setClassification(event.target.value);
            }}
          >
            {CLASSIFICATIONS.map((value) => (
              <option key={value} value={value}>
                {value === '' ? 'All verdicts' : value}
              </option>
            ))}
          </select>
        </div>

        <div className="filters__field">
          <label htmlFor="filter-status">Status</label>
          <select
            id="filter-status"
            value={status}
            onChange={(event) => {
              setPage(1);
              setStatus(event.target.value);
            }}
          >
            {STATUSES.map((value) => (
              <option key={value} value={value}>
                {value === '' ? 'All statuses' : value}
              </option>
            ))}
          </select>
        </div>

        <div className="filters__field filters__field--grow">
          <label htmlFor="filter-search">Search address</label>
          <input
            id="filter-search"
            type="search"
            value={search}
            placeholder="example.com"
            onChange={(event) => {
              setPage(1);
              setSearch(event.target.value);
            }}
          />
        </div>
      </div>

      {error ? (
        <p className="panel__error" role="alert">
          {error}
        </p>
      ) : null}

      <p className="panel__meta" aria-live="polite">
        {loading ? 'Loading…' : `${total} scan${total === 1 ? '' : 's'} recorded`}
      </p>

      <div className="table-wrapper">
        <table className="table">
          <caption className="visually-hidden">Recorded scans</caption>
          <thead>
            <tr>
              <th scope="col">Verdict</th>
              <th scope="col">Address</th>
              <th scope="col">Risk</th>
              <th scope="col">Status</th>
              <th scope="col">Scanned at</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 && !loading ? (
              <tr>
                <td colSpan={5} className="table__empty">
                  No scans recorded yet.
                </td>
              </tr>
            ) : null}
            {items.map((item) => {
              const descriptor = describeVerdict(item.classification, item.status);
              return (
                <tr
                  key={item.scan_id}
                  className="table__row"
                  onClick={() => onSelect?.(item)}
                  tabIndex={onSelect ? 0 : undefined}
                  onKeyDown={(event) => {
                    if (onSelect && (event.key === 'Enter' || event.key === ' ')) {
                      event.preventDefault();
                      onSelect(item);
                    }
                  }}
                >
                  <td>
                    <span className={`chip chip--${descriptor.tone}`}>
                      <span aria-hidden="true">{descriptor.symbol}</span> {descriptor.label}
                    </span>
                  </td>
                  <td className="table__url">{item.submitted_url}</td>
                  <td>{item.risk_score === null ? '—' : item.risk_score}</td>
                  <td>
                    <code>{item.status}</code>
                  </td>
                  <td>{new Date(item.scanned_at).toLocaleString()}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {pages > 1 ? (
        <nav className="pagination" aria-label="Scan history pages">
          <button
            type="button"
            className="button button--ghost"
            disabled={page <= 1}
            onClick={() => setPage((current) => Math.max(1, current - 1))}
          >
            Previous
          </button>
          <span>
            Page {page} of {pages}
          </span>
          <button
            type="button"
            className="button button--ghost"
            disabled={page >= pages}
            onClick={() => setPage((current) => Math.min(pages, current + 1))}
          >
            Next
          </button>
        </nav>
      ) : null}
    </section>
  );
}
