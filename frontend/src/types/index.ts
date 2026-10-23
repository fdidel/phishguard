/**
 * TypeScript mirrors of the PhishGuard API contract.
 *
 * Every type here corresponds 1:1 to a Pydantic schema in
 * `backend/app/schemas/scan.py`.  The field names are intentionally identical
 * so that the dashboard can never silently disagree with the backend.
 */

/** Verdict produced by the classifier. */
export type Classification =
  | 'safe'
  | 'suspicious'
  | 'dangerous'
  | 'inconclusive'
  | 'unknown';

/** Lifecycle status of a scan. */
export type ScanStatus = 'completed' | 'inconclusive' | 'failed';

/** A single piece of evidence supporting a verdict. */
export interface Indicator {
  category: string;
  value: number;
  description: string;
}

/** Contribution estimate for one feature in one prediction. */
export interface FeatureContribution {
  feature: string;
  value: number;
  global_importance: number;
  contribution: number;
}

/** The explanation attached to a scan result. */
export interface Explanation {
  evidence: Indicator[];
  top_contributing_features: FeatureContribution[];
  note: string;
}

/** Full result of `POST /api/v1/scan`. */
export interface ScanResult {
  scan_id: string;
  submitted_url: string;
  normalized_url: string;
  hostname: string;
  registrable_domain: string;

  status: ScanStatus;
  analysis_coverage: string;
  classification: Classification;
  classification_label: string;
  guidance: string;

  risk_score: number | null;
  phishing_probability: number | null;

  indicators: Indicator[];
  explanation: Explanation | null;
  warnings: string[];

  model_version: string | null;
  feature_schema_version: string | null;
  model_algorithm: string | null;

  threat_intelligence: Record<string, unknown> | null;
  page_analysis: Record<string, unknown> | null;

  /** Machine-readable failure reason; null unless the scan failed. */
  error_code: string | null | undefined;
  /** Human-readable failure reason; null unless the scan failed. */
  error_message: string | null | undefined;

  scanned_at: string;
  duration_ms: number | null;
  limitations: string[];
}

/** Compact record used by the history list. */
export interface ScanSummary {
  scan_id: string;
  submitted_url: string;
  normalized_url: string;
  hostname: string;
  status: ScanStatus;
  classification: Classification;
  risk_score: number | null;
  phishing_probability: number | null;
  model_version: string | null;
  scanned_at: string;
  duration_ms: number | null;
}

/** Full detail of a single scan. */
export interface ScanDetail extends ScanSummary {
  registrable_domain: string;
  analysis_coverage: string;
  classification_label: string;
  guidance: string;
  indicators: Indicator[];
  explanation: Explanation | null;
  warnings: string[];
  feature_schema_version: string | null;
  features: Record<string, number> | null;
  threat_intelligence: Record<string, unknown> | null;
  page_analysis: Record<string, unknown> | null;
  error_code: string | null;
  error_message: string | null;
}

/** A page of scan history. */
export interface PaginatedScans {
  items: ScanSummary[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

/** Service health. */
export interface HealthResponse {
  status: string;
  version: string;
  environment: string;
  model_loaded: boolean;
  model_version: string | null;
  database: string;
  page_analysis_enabled: boolean;
  threat_intel_enabled: boolean;
  timestamp: string;
}

/** Metadata about the loaded model. */
export interface ModelInfoResponse {
  available: boolean;
  model_version: string | null;
  feature_schema_version: string;
  algorithm: string | null;
  trained_at: string | null;
  random_seed: number | null;
  thresholds: Record<string, number>;
  feature_count: number;
  supported_features: string[];
  error: string | null;
}

/** Saved evaluation metrics from the real training run. */
export interface ModelMetricsResponse {
  model_version: string | null;
  feature_schema_version: string | null;
  selected_model: string | null;
  trained_at: string | null;
  random_seed: number | null;
  dataset: Record<string, unknown>;
  split: Record<string, unknown>;
  thresholds: Record<string, number>;
  test_set: Record<string, unknown>;
  model_comparison: Array<Record<string, unknown>>;
  feature_importance: Array<Record<string, unknown>>;
  inference_latency: Record<string, unknown>;
  environment: Record<string, unknown>;
}

/** Aggregate statistics across the scan history. */
export interface ReportSummaryResponse {
  total_scans: number;
  by_status: Record<string, number>;
  by_classification: Record<string, number>;
  average_risk_score: number | null;
  dangerous_scans: number;
  suspicious_scans: number;
  safe_scans: number;
  failed_scans: number;
  unique_domains: number;
  generated_at: string;
}

/** Uniform error body returned by the API. */
export interface ApiErrorBody {
  error: string;
  message: string;
  detail?: unknown;
}

/** Body of `POST /api/v1/feedback`. */
export interface FeedbackRequest {
  scan_id: string;
  is_correct: boolean;
  correct_classification?: string | null;
  comment?: string | null;
}
