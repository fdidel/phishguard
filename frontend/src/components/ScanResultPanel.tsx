/**
 * The full result panel for one scan.
 *
 * Layout follows the seven-part structure required by the specification:
 *   1. submitted address        5. model / version provenance
 *   2. verdict                  6. limitations
 *   3. risk score               7. warnings
 *   4. explanation / evidence
 *
 * The panel never opens the submitted address in a new browser tab.  The
 * address is rendered as plain text so that a user cannot be navigated to a
 * malicious site by clicking on the result of their own scan.
 */

import type { ScanResult } from '../types';
import VerdictBadge from './VerdictBadge';
import RiskScore from './RiskScore';
import EvidenceList from './EvidenceList';

interface ScanResultPanelProps {
  result: ScanResult;
}

function coverageLabel(coverage: string): string {
  switch (coverage) {
    case 'url_and_page':
      return 'URL structure and page content were analysed';
    case 'url_only':
      return 'Only the URL structure was analysed - the site was never contacted';
    case 'none':
      return 'Nothing could be analysed';
    default:
      return coverage;
  }
}

export default function ScanResultPanel({ result }: ScanResultPanelProps) {
  const isDangerous = result.classification === 'dangerous' && result.status !== 'failed';
  const isFailed = result.status === 'failed';

  return (
    <section className="result" aria-labelledby="result-heading">
      <h2 id="result-heading" className="result__heading">
        Result
      </h2>

      {/* 1. Submitted address - plain text, never a link. */}
      <div className="result__row">
        <h3 className="result__label">Address you submitted</h3>
        <p className="result__url" data-testid="submitted-url">
          {result.submitted_url || '(empty)'}
        </p>
        {result.normalized_url && result.normalized_url !== result.submitted_url ? (
          <p className="result__sub">
            Analysed as <code>{result.normalized_url}</code>
          </p>
        ) : null}
        {result.hostname ? (
          <p className="result__sub">
            Host: <code>{result.hostname}</code>
            {result.registrable_domain ? (
              <>
                {' '}
                &middot; Domain: <code>{result.registrable_domain}</code>
              </>
            ) : null}
          </p>
        ) : null}
        <p className="result__hint">
          PhishGuard never opens the address for you. It is shown as text on purpose.
        </p>
      </div>

      {/* 2. Verdict */}
      <div className="result__row">
        <h3 className="result__label">Verdict</h3>
        <VerdictBadge
          classification={result.classification}
          status={result.status}
          label={result.classification_label}
        />
        {result.guidance ? (
          <p className="result__guidance" data-testid="guidance">
            {result.guidance}
          </p>
        ) : null}
        {isDangerous ? (
          <div className="result__alert" role="alert" data-testid="danger-advice">
            <p className="result__alert-title">Do not enter any personal information on this site.</p>
            <ul>
              <li>Do not type in a username, password or one-time code.</li>
              <li>Do not enter card details, bank details or PINs.</li>
              <li>Do not download files or install anything from it.</li>
              <li>
                If you already entered credentials, change the password and contact the
                provider from a site you reached by typing its address yourself.
              </li>
            </ul>
          </div>
        ) : null}
        {isFailed ? (
          <div className="result__alert result__alert--failed" role="alert" data-testid="failed-advice">
            <p className="result__alert-title">This analysis failed.</p>
            <p>
              No verdict was reached. A failed analysis is <strong>not</strong> a safe result -
              treat the address as unverified and do not rely on this page to judge it.
            </p>
          </div>
        ) : null}
        {isFailed && result.error_code ? (
          <div className="result__meta" data-testid="failure-reason">
            <h3 className="result__label">Why it failed</h3>
            <p className="result__sub">
              Reason: <code>{result.error_code}</code>
            </p>
            {result.error_message ? (
              <p className="result__sub" data-testid="failure-detail">
                {result.error_message}
              </p>
            ) : null}
          </div>
        ) : null}
      </div>

      {/* 3. Risk score */}
      <div className="result__row">
        <h3 className="result__label">Risk</h3>
        <RiskScore score={result.risk_score} probability={result.phishing_probability} />
      </div>

      {/* 4. Explanation */}
      <div className="result__row">
        <EvidenceList explanation={result.explanation} indicators={result.indicators} />
      </div>

      {/* 5. Coverage + provenance */}
      <div className="result__row result__row--split">
        <div>
          <h3 className="result__label">What was checked</h3>
          <p className="result__meta" data-testid="analysis-coverage">
            {coverageLabel(result.analysis_coverage)}
          </p>
          <p className="result__meta">
            Scan status: <code>{result.status}</code>
            {result.duration_ms !== null ? ` &middot; ${result.duration_ms} ms` : ''}
          </p>
        </div>
        <div>
          <h3 className="result__label">Model</h3>
          <p className="result__meta">
            Version: <code data-testid="model-version">{result.model_version ?? 'unavailable'}</code>
          </p>
          <p className="result__meta">
            Algorithm: <code>{result.model_algorithm ?? 'unavailable'}</code>
          </p>
          <p className="result__meta">
            Feature schema: <code>{result.feature_schema_version ?? 'unavailable'}</code>
          </p>
        </div>
      </div>

      {/* 6. Limitations */}
      <div className="result__row">
        <h3 className="result__label">Limitations</h3>
        {result.limitations.length > 0 ? (
          <ul className="limitations" data-testid="limitations">
            {result.limitations.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        ) : (
          <p className="result__meta">No limitations were reported for this scan.</p>
        )}
      </div>

      {/* 7. Warnings */}
      {result.warnings.length > 0 ? (
        <div className="result__row">
          <h3 className="result__label">Warnings</h3>
          <ul className="warnings" data-testid="warnings">
            {result.warnings.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}
