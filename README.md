# Smart Proxy

A universal, self-hosted, response-aware forward proxy with sticky upstream exit routing and automatic rotation on HTTP 403/429/503 and anti-bot challenges.

## Architecture

- **Engine**: mitmproxy core (`mitmdump`) in regular forward-proxy mode.
- **TLS Interception**: Dynamically generates origin certificates signed by a persistent private CA (`/ca/mitmproxy-ca-cert.pem`).
- **Sticky Pool**: Dynamically synchronizes healthy concrete exits from `worldpool-adapter` and keeps the active exit sticky for all sessions until an upstream error occurs.
- **Inline Replay**: On HTTP 403, 429, 503, or WAF challenge signatures, automatically quarantines the failed exit, rotates to the next healthy node, and replays the request seamlessly.
- **Zero Client Overhead**: No client-side fallback logic needed. Standard `HTTP_PROXY` / `HTTPS_PROXY` interface.

## Client Configuration

### Node.js (Rule 34 API / OmniRoute)
```bash
export HTTP_PROXY="http://proxyuser:password@100.101.155.30:8080"
export HTTPS_PROXY="http://proxyuser:password@100.101.155.30:8080"
export NODE_EXTRA_CA_CERTS="/path/to/smart-proxy-ca.crt"
```

### Python (Requests / httpx)
```bash
export HTTP_PROXY="http://proxyuser:password@100.101.155.30:8080"
export HTTPS_PROXY="http://proxyuser:password@100.101.155.30:8080"
export REQUESTS_CA_BUNDLE="/path/to/smart-proxy-ca.crt"
```

### curl
```bash
curl -x http://proxyuser:password@100.101.155.30:8080 --cacert /path/to/smart-proxy-ca.crt https://example.com
```
