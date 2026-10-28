/**
 * PhishGuard dashboard.
 *
 * A single-page application with three views:
 *   - Scan   : the URL verification form and the result panel
 *   - History: the recorded scans with filters and CSV export
 *   - Model  : the provenance and measured performance of the trained model
 *
 * The dashboard never navigates to a scanned address.
 */

import { useCallback, useEffect, useState } from 'react';
import ScanPage from './pages/ScanPage';
import HistoryPage from './pages/HistoryPage';
import ModelPage from './pages/ModelPage';
import { fetchHealth } from './services/api';
import type { HealthResponse } from './types';

type Tab = 'scan' | 'history' | 'model';

const TABS: Array<{ id: Tab; label: string }> = [
  { id: 'scan', label: 'Verify a website' },
  { id: 'history', label: 'Scan history' },
  { id: 'model', label: 'Model & performance' },
];

export default function App() {
  const [tab, setTab] = useState<Tab>('scan');
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [historyToken, setHistoryToken] = useState(0);

  useEffect(() => {
    let cancelled = false;
    fetchHealth()
      .then((result) => {
        if (cancelled) return;
        if (result.ok) {
          setHealth(result.data);
        } else {
          setHealthError(result.message);
        }
      })
      .catch(() => {
        if (!cancelled) setHealthError('The PhishGuard service could not be reached.');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleScanned = useCallback(() => {
    setHistoryToken((token) => token + 1);
  }, []);

  return (
    <div className="app">
      <a className="skip-link" href="#main">
        Skip to main content
      </a>

      <header className="app__header">
        <div className="app__brand">
          <span className="app__logo" aria-hidden="true">
            🛡
          </span>
          <div>
            <h1 className="app__title">PhishGuard</h1>
            <p className="app__subtitle">
              AI-powered phishing detection and website safety verification
            </p>
          </div>
        </div>

        <div className="app__status" role="status">
          {healthError ? (
            <span className="status status--error">
              <span aria-hidden="true">✖</span> Service unavailable
            </span>
          ) : health ? (
            <span
              className={`status status--${health.model_loaded ? 'ok' : 'warn'}`}
              data-testid="service-status"
            >
              <span aria-hidden="true">{health.model_loaded ? '✔' : '⚠'}</span>{' '}
              {health.model_loaded
                ? `Model ${health.model_version ?? 'loaded'}`
                : 'Model not loaded'}
            </span>
          ) : (
            <span className="status">Checking service…</span>
          )}
        </div>
      </header>

      <nav className="app__nav" aria-label="Sections">
        <ul>
          {TABS.map((item) => (
            <li key={item.id}>
              <button
                type="button"
                className={`tab${tab === item.id ? ' tab--active' : ''}`}
                aria-current={tab === item.id ? 'page' : undefined}
                onClick={() => setTab(item.id)}
              >
                {item.label}
              </button>
            </li>
          ))}
        </ul>
      </nav>

      <main className="app__main" id="main">
        {tab === 'scan' ? (
          <ScanPage onScanned={handleScanned} />
        ) : null}
        {tab === 'history' ? <HistoryPage refreshToken={historyToken} /> : null}
        {tab === 'model' ? <ModelPage /> : null}
      </main>

      <footer className="app__footer">
        <div className="footer__content">
          <img
            className="footer__logo"
            src="/assets/nasarawa-state-university-logo.png"
            alt="Nasarawa State University, Keffi"
          />
          <div className="footer__text">
            <p>
              PhishGuard produces a risk <em>indicator</em> based on the structure of an address. It
              is not a guarantee that a website is safe, and it does not replace your own judgement.
            </p>
            <p className="footer__attribution">
              Developed by <strong>Didel Oluwafemi</strong> &nbsp;|&nbsp;
              BSc Computer Science Project &mdash; Nasarawa State University, Keffi
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
