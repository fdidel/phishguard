# Security

## Threat Model

The primary threat vector is **SSRF (Server-Side Request Forgery)** if page analysis is enabled. The scan endpoint must never make untrusted outbound requests.

## SSRF Protection

When `PAGE_ANALYSIS_ENABLED=true`:

1. **DNS re-resolution:** `socket.getaddrinfo` resolves the hostname before connecting, preventing DNS rebinding attacks.
2. **Private/reserved blocklist:** IPs in `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0/8`, `::1/128`, `fc00::/7` are blocked.
3. **Port allowlist:** Only ports 80 and 443 are allowed.
4. **Redirect loop detection:** Max 3 redirects, loop detection prevents infinite redirects.
5. **Byte budget:** Max 512 KB response body.
6. **Time budget:** Max 5 seconds per request.
7. **No redirect following by default:** `_NoRedirectHandler` prevents redirect-based SSRF unless explicitly configured.

## Input Validation

| Check | Rule |
|-------|------|
| URL scheme | Only `http` and `https` allowed |
| URL length | 64–8192 characters |
| Hostname | Must match hostname grammar regex |
| IDNA conversion | Unicode host converted to punycode |
| Userinfo | Stripped before persistence (no credential logging) |

## Rate Limiting

- Per-IP sliding window: 30 requests/minute (configurable via `RATE_LIMIT_PER_MINUTE`)
- Disabled only in test mode
- Health probe and interactive docs exempt
- Returns `429 Too Many Requests` with `Retry-After` header

## Security Headers

Every response includes:

| Header | Value |
|--------|-------|
| X-Content-Type-Options | nosniff |
| X-Frame-Options | DENY |
| Referrer-Policy | no-referrer |
| Permissions-Policy | geolocation=(), microphone=(), camera=() |
| Content-Security-Policy | default-src 'none'; frame-ancestors 'none'; base-uri 'none' |
| Cross-Origin-Opener-Policy | same-origin |
| Cross-Origin-Resource-Policy | same-origin |
| Cache-Control | no-store |

In production, also adds:

| Header | Value |
|--------|-------|
| Strict-Transport-Security | max-age=31536000; includeSubDomains |

## Error Handling

- Unexpected exceptions are caught and returned as uniform JSON error bodies — **never** stack traces in production.
- `RequestValidationError` → 422 with structured detail.
- `StarletteHTTPException` → appropriate HTTP status.
- `Exception` handler → 500 with generic message.

## Credential Safety

- Userinfo (`username:password@`) is stripped from URLs before persistence.
- No credentials are ever logged.
- No secrets are committed to the repository.
- Environment variables drive all configuration; no hardcoded secrets.

## Data Safety

- Scan history is retained for 90 days (configurable via `SCAN_RETENTION_DAYS`).
- A retention job (`scripts/purge_expired_scans.py`) removes expired records.
- The database is SQLite by default; production deployments should use PostgreSQL.
