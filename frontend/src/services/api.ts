/**
 * Thin client for the PhishGuard REST API.
 *
 * The client is deliberately defensive: it never throws a raw network error at
 * the UI, it always returns a discriminated union so a component can render a
 * helpful message instead of crashing, and it never redirects the browser to
 * the submitted URL (the dashboard must not auto-open a scanned site).
 */

import type {
  ApiErrorBody,
  FeedbackRequest,
  HealthResponse,
  ModelInfoResponse,
  ModelMetricsResponse,
  PaginatedScans,
  ReportSummaryResponse,
  ScanDetail,
  ScanResult,
  ScanSummary,
} from '../types';

/** Base URL of the API.  Empty means "same origin" (Vite proxies in dev). */
export const API_BASE = (import.meta.env?.VITE_API_BASE_URL as string | undefined) ?? '';

export type ApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string; message: string; status: number };

/** Query parameters accepted by `GET /api/v1/scans`. */
export interface ScanListQuery {
  page?: number;
  page_size?: number;
  status?: string;
  classification?: string;
  domain?: string;
  search?: string;
}

function buildQuery(params: Record<string, unknown>): string {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return;
    search.append(key, String(value));
  });
  const query = search.toString();
  return query ? `?${query}` : '';
}

async function request<T>(
  path: string,
  init: RequestInit = {},
): Promise<ApiResult<T>> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      headers: { 'Content-Type': 'application/json', ...(init.headers ?? {}) },
      ...init,
    });
  } catch (cause) {
    return {
      ok: false,
      error: 'network_error',
      message:
        'Could not reach the PhishGuard service. Check that the backend is running and try again.',
      status: 0,
    };
  }

  const text = await response.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }

  if (!response.ok) {
    const body = payload as ApiErrorBody | null;
    return {
      ok: false,
      error: body?.error ?? `http_${response.status}`,
      message:
        body?.message ??
        `The request failed with HTTP status ${response.status}.`,
      status: response.status,
    };
  }

  return { ok: true, data: payload as T };
}

/** `GET /health` */
export function fetchHealth(): Promise<ApiResult<HealthResponse>> {
  return request<HealthResponse>('/health');
}

/** `GET /api/v1/model/info` */
export function fetchModelInfo(): Promise<ApiResult<ModelInfoResponse>> {
  return request<ModelInfoResponse>('/api/v1/model/info');
}

/** `GET /api/v1/model/metrics` */
export function fetchModelMetrics(): Promise<ApiResult<ModelMetricsResponse>> {
  return request<ModelMetricsResponse>('/api/v1/model/metrics');
}

/** `POST /api/v1/scan` */
export function submitScan(
  url: string,
  includePageAnalysis = false,
): Promise<ApiResult<ScanResult>> {
  return request<ScanResult>('/api/v1/scan', {
    method: 'POST',
    body: JSON.stringify({ url, include_page_analysis: includePageAnalysis }),
  });
}

/** `GET /api/v1/scans` */
export function fetchScans(
  query: ScanListQuery = {},
): Promise<ApiResult<PaginatedScans>> {
  return request<PaginatedScans>(
    `/api/v1/scans${buildQuery(query as Record<string, unknown>)}`,
  );
}

/** `GET /api/v1/scans/{scan_id}` */
export function fetchScanDetail(scanId: string): Promise<ApiResult<ScanDetail>> {
  return request<ScanDetail>(
    `/api/v1/scans/${encodeURIComponent(scanId)}`,
  );
}

/** `POST /api/v1/feedback` */
export function submitFeedback(
  body: FeedbackRequest,
): Promise<ApiResult<{ feedback_id: string; scan_id: string; recorded_at: string }>> {
  return request('/api/v1/feedback', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

/** `GET /api/v1/reports/summary` */
export function fetchReportSummary(): Promise<ApiResult<ReportSummaryResponse>> {
  return request<ReportSummaryResponse>('/api/v1/reports/summary');
}

/** URL of the CSV export (used as a download link, never auto-navigated). */
export function reportExportUrl(limit = 5000): string {
  return `${API_BASE}/api/v1/reports/export.csv?limit=${limit}`;
}

/**
 * Client-side pre-validation.
 *
 * The backend performs the authoritative validation; this only avoids a
 * pointless round trip and gives the user immediate feedback.  It mirrors the
 * rules in `phishguard/url_validation.py` without replacing them.
 */
export function validateUrlInput(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return 'Enter the address of the website you want to check.';
  if (trimmed.length > 2048) return 'The address is too long (maximum 2048 characters).';
  if (/\s/.test(trimmed)) return 'The address must not contain spaces.';
  if (!/^https?:\/\//i.test(trimmed)) {
    return 'The address must start with http:// or https://';
  }
  try {
    const parsed = new URL(trimmed);
    if (!parsed.hostname) return 'The address does not contain a valid hostname.';
  } catch {
    return 'That does not look like a valid web address.';
  }
  return null;
}

export type { ScanSummary };
