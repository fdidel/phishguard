/**
 * The API client must never throw a raw network error at the UI and must never
 * resolve a failed request with `ok: true`.  The URL pre-validation mirrors
 * the backend rules in `phishguard/url_validation.py`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  fetchHealth,
  reportExportUrl,
  submitScan,
  validateUrlInput,
} from '../src/services/api';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('validateUrlInput', () => {
  it('accepts a well formed https address', () => {
    expect(validateUrlInput('https://example.com/login')).toBeNull();
  });

  it('accepts a well formed http address', () => {
    expect(validateUrlInput('http://example.com')).toBeNull();
  });

  it('rejects an empty value', () => {
    expect(validateUrlInput('')).toMatch(/enter the address/i);
    expect(validateUrlInput('   ')).toMatch(/enter the address/i);
  });

  it('rejects an address without an http(s) scheme', () => {
    expect(validateUrlInput('example.com')).toMatch(/http:\/\/ or https:\/\//i);
    expect(validateUrlInput('javascript:alert(1)')).toMatch(/http:\/\/ or https:\/\//i);
    expect(validateUrlInput('ftp://example.com')).toMatch(/http:\/\/ or https:\/\//i);
    expect(validateUrlInput('file:///etc/passwd')).toMatch(/http:\/\/ or https:\/\//i);
  });

  it('rejects an address containing whitespace', () => {
    expect(validateUrlInput('https://exa mple.com')).toMatch(/must not contain spaces/i);
  });

  it('rejects an address that is longer than the backend limit', () => {
    const long = `https://example.com/${'a'.repeat(2048)}`;
    expect(validateUrlInput(long)).toMatch(/too long/i);
  });

  it('rejects an address without a hostname', () => {
    // "https://" has an empty authority, which the URL parser rejects outright.
    expect(validateUrlInput('https://')).toMatch(/valid (web address|hostname)/i);
    expect(validateUrlInput('https://?x=1')).toMatch(/valid (web address|hostname)/i);
  });

  it('accepts an address whose extra slashes make the first path segment the host', () => {
    // The WHATWG URL parser treats "https:///path" as the host "path", which is
    // the same interpretation the backend normalisation uses.
    expect(validateUrlInput('https:///path')).toBeNull();
  });

  it('trims surrounding whitespace before validating', () => {
    expect(validateUrlInput('  https://example.com  ')).toBeNull();
  });
});

describe('request handling', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('returns the parsed body on success', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      jsonResponse({ status: 'ok', model_loaded: true }),
    ) as unknown as typeof fetch;

    const result = await fetchHealth();
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.model_loaded).toBe(true);
    }
  });

  it('turns a network failure into a structured error instead of throwing', async () => {
    globalThis.fetch = vi
      .fn()
      .mockRejectedValue(new TypeError('Failed to fetch')) as unknown as typeof fetch;

    const result = await fetchHealth();
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe('network_error');
      expect(result.status).toBe(0);
      expect(result.message).toMatch(/could not reach/i);
    }
  });

  it('surfaces the API error body for a non-2xx response', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      jsonResponse({ error: 'invalid_url', message: 'The address is not valid.' }, 400),
    ) as unknown as typeof fetch;

    const result = await fetchHealth();
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe('invalid_url');
      expect(result.message).toBe('The address is not valid.');
      expect(result.status).toBe(400);
    }
  });

  it('falls back to a generic message when the error body is not JSON', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response('<html>502 Bad Gateway</html>', { status: 502 }),
    ) as unknown as typeof fetch;

    const result = await fetchHealth();
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe('http_502');
      expect(result.message).toMatch(/HTTP status 502/);
    }
  });

  it('posts the address as JSON to the scan endpoint', async () => {
    const spy = vi.fn().mockResolvedValue(jsonResponse({ scan_id: 'abc' }));
    globalThis.fetch = spy as unknown as typeof fetch;

    await submitScan('https://example.com');

    expect(spy).toHaveBeenCalledTimes(1);
    const [url, init] = spy.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/v1/scan');
    expect(init.method).toBe('POST');
    expect(JSON.parse(String(init.body))).toEqual({
      url: 'https://example.com',
      include_page_analysis: false,
    });
  });
});

describe('reportExportUrl', () => {
  it('points at the CSV export endpoint', () => {
    expect(reportExportUrl(100)).toContain('/api/v1/reports/export.csv?limit=100');
  });
});
