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

## Testing & Quality Assurance

All changes to `smart_proxy.py` or proxy routing MUST pass the test suite before any commit or deployment:

```bash
# Core Acceptance Suite
python3 test_smart_proxy_suite.py

# Advanced 5-Retry & Concurrency E2E Suite
python3 test_smart_proxy_e2e.py
```

## Operational Guidelines (Web Unlocker Architecture)

- **Minimum 5 Retries (`MAX_RETRIES=5`)**: Always fail over across at least 5 distinct healthy proxy nodes on status 403/429/500/502/503/504 or anti-bot challenge HTML.
- **Non-Blocking Async Execution**: Replay loops run asynchronously (`asyncio.to_thread`) to prevent blocking the mitmproxy event loop.
- **Sticky Affinity with Domain Scoping**: Pin traffic to healthy exits per destination domain until an upstream failure occurs.
- **Mutation Safety**: Safe methods (`GET`, `HEAD`, `OPTIONS`, `PUT`, `DELETE`) replay automatically; mutations (`POST`) require header `X-Allow-Mutation-Replay: 1`.
