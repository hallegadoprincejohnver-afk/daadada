# Secure URL Resolver API

A small Node.js API that follows ordinary HTTPS redirects for explicitly supported shortener domains. It does not emulate browser JavaScript, solve captchas, skip advertising checkpoints, or bypass access controls.

## Endpoints

- `GET /healthz`: public health check.
- `POST /v1/resolve`: authenticated URL resolution.

Example request:

```bash
curl -X POST "https://YOUR-SERVICE.onrender.com/v1/resolve" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://bit.ly/example"}'
```

Successful response:

```json
{
  "success": true,
  "original_url": "https://bit.ly/example",
  "resolved_url": "https://example.org/destination",
  "redirects_followed": 1,
  "http_status": 200
}
```

The sample destination above is illustrative; actual results depend on the submitted URL.

## Required environment variables

- `API_KEY`: a random secret of at least 32 characters. Send it only using the `Authorization: Bearer ...` header.
- `ALLOWED_HOSTS`: comma-separated exact hostnames allowed as the **initial** URL. The default list is `bit.ly,tinyurl.com,is.gd,rb.gy,t.co,ow.ly,buff.ly,shorturl.at`.

## Safeguards

- HTTPS only; rejects URLs with credentials, IP-literal hostnames, and nonstandard ports.
- Resolves every hop and pins the HTTPS connection to validated public DNS addresses.
- Rejects private, loopback, link-local, reserved and documentation IP ranges, including IPv4-mapped IPv6.
- Validates every redirect before following it; maximum of 8 redirects; detects redirect loops.
- Short request/DNS timeouts; limits request body/header size and does not forward cookies or caller credentials.
- API-key authentication uses a timing-safe comparison.
- Per-IP and per-API-key rate limits, security headers, and no-store response caching.

## Known limitations

This version resolves ordinary server-side HTTPS redirects only. It will not resolve JavaScript/meta-refresh redirects, links requiring browser interactions, or services whose destinations are not exposed through normal HTTP redirects. The allowlist applies to the starting URL; each subsequent hop must resolve only to public IP addresses and use HTTPS.

Rate-limit counters are kept in memory, so use a shared rate-limit store before scaling to multiple instances. The service has no database and does not persist user submissions or API keys.

## Local development

```bash
npm install
API_KEY="replace-with-a-long-random-secret" ALLOWED_HOSTS="bit.ly,tinyurl.com,is.gd,rb.gy,t.co,ow.ly,buff.ly,shorturl.at" npm start
npm test
```
