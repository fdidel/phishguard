/**
 * Shared fixtures for the dashboard tests.
 *
 * The shapes mirror `backend/app/schemas/scan.py` exactly so a change in the
 * API contract that is not mirrored here fails the TypeScript build.
 */

import type { ScanResult, ScanSummary } from '../src/types';

export const DANGEROUS_URL = 'http://paypa1-secure-login.example/account/verify?id=99';

export function dangerousResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    scan_id: 'scan-dangerous-1',
    submitted_url: DANGEROUS_URL,
    normalized_url: DANGEROUS_URL,
    hostname: 'paypa1-secure-login.example',
    registrable_domain: 'paypa1-secure-login.example',

    status: 'completed',
    analysis_coverage: 'url_only',
    classification: 'dangerous',
    classification_label: 'Dangerous',
    guidance: 'Do not enter credentials or payment details on this site.',

    risk_score: 91,
    phishing_probability: 0.97,

    indicators: [
      {
        category: 'url_keyword',
        value: 1,
        description: 'The address contains the keyword "login".',
      },
    ],
    explanation: {
      evidence: [
        {
          category: 'url_keyword',
          value: 1,
          description: 'The address contains the keyword "login".',
        },
      ],
      top_contributing_features: [
        {
          feature: 'url_keyword_count',
          value: 3,
          global_importance: 0.21,
          contribution: 0.12,
        },
      ],
      note: 'Contributions are estimated for this single prediction.',
    },
    warnings: [],

    model_version: '2026.10.22-0001',
    feature_schema_version: '1.0.0',
    model_algorithm: 'XGBoost',

    threat_intelligence: null,
    page_analysis: null,

    scanned_at: '2026-10-22T09:00:00Z',
    duration_ms: 12,
    limitations: ['The model only sees the structure of the address.'],
    ...overrides,
  };
}

/** A scan whose analysis failed - it must never be presented as safe. */
export function failedResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return dangerousResult({
    scan_id: 'scan-failed-1',
    submitted_url: 'http://localhost:8080/admin',
    normalized_url: 'http://localhost:8080/admin',
    hostname: 'localhost',
    registrable_domain: 'localhost',
    status: 'failed',
    analysis_coverage: 'none',
    classification: 'unknown',
    classification_label: 'Analysis failed',
    guidance: 'No verdict was produced for this address.',
    risk_score: null,
    phishing_probability: null,
    indicators: [],
    explanation: null,
    model_version: null,
    feature_schema_version: null,
    model_algorithm: null,
    duration_ms: 3,
    limitations: ['The address could not be analysed.'],
    ...overrides,
  });
}

export function summaryItem(overrides: Partial<ScanSummary> = {}): ScanSummary {
  return {
    scan_id: 'scan-1',
    submitted_url: DANGEROUS_URL,
    normalized_url: DANGEROUS_URL,
    hostname: 'paypa1-secure-login.example',
    status: 'completed',
    classification: 'dangerous',
    risk_score: 91,
    phishing_probability: 0.97,
    model_version: '2026.10.22-0001',
    scanned_at: '2026-10-22T09:00:00Z',
    duration_ms: 12,
    ...overrides,
  };
}
