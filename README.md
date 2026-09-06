# Smart Proxy

A universal, high-performance, self-hosted forward proxy with TLS MITM interception, per-destination sticky exit pools, dynamic latency ranking, and automatic fail-fast rotation across upstream proxies.

---

## Key Features

- **Universal RFC 9110 Forward Proxy**: Standard `HTTP_PROXY` / `HTTPS_PROXY` interface compatible with any HTTP client (Node.js, Python, curl, Playwright, Go, Rust).
- **TLS MITM Interception**: Dynamically generates origin certificates signed by a persistent private CA (`/ca/mitmproxy-ca-cert.pem`).
- **Per-Destination Sticky Pools**: Preserves sticky exit node affinity per root domain (`e621.net`, `danbooru.donmai.us`, `gelbooru.com`) so errors on one target never evict healthy sessions on another.
- **Domain-Scoped Cooldowns**: HTTP 403, 429, 503, and WAF challenges trigger host-specific cooldowns; socket drops trigger global cooldowns.
- **Dynamic Upstream Aggregation**: Ingests and latency-sorts concrete proxy feeds from `worldpool-adapter` (180s refresh cycle) with real HTTPS CONNECT pre-flight probing.
- **In-Flight Replay Engine**: Automatically replays failed safe requests (`GET`, `HEAD`) across alternative healthy exits in milliseconds before returning to the client.
- **Zero Destination-Specific Logic**: Remains pure, generic network infrastructure with no hardcoded destination headers or custom API routing.

---

## Architecture & Learnings

For the complete architectural design records, protocol implementation details, booru upstream quirks, and fleet operations guidelines, see:

📖 **[KNOWLEDGE_BASE.md](./KNOWLEDGE_BASE.md)**

---

## Client Configuration

### Node.js (Rule 34 API, OmniRoute)
```bash
export HTTP_PROXY="http://user:password@100.101.155.30:8088"
export HTTPS_PROXY="http://user:password@100.101.155.30:8088"
export NODE_EXTRA_CA_CERTS="/path/to/smart-proxy-ca.crt"
```

### Python (Requests, httpx, ChangeDetection)
```bash
export HTTP_PROXY="http://user:password@100.101.155.30:8088"
export HTTPS_PROXY="http://user:password@100.101.155.30:8088"
export REQUESTS_CA_BUNDLE="/path/to/smart-proxy-ca.crt"
export SSL_CERT_FILE="/path/to/smart-proxy-ca.crt"
```

### cURL
```bash
curl --cacert /path/to/smart-proxy-ca.crt \
     -x "http://user:password@smart-proxy.akbal.dev:24000" \
     "https://example.com"
```

---

## Testing & Quality Assurance

All changes to `smart_proxy.py` or proxy routing must pass the automated test suites:

```bash
# Core Acceptance Suite
python3 test_smart_proxy_suite.py

# Stress & Concurrency Suite
python3 test_smart_proxy_stress_fuzz.py
```

---

## Operational Parameters

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `PROXY_AUTH` | `""` | `username:password` for forward proxy basic auth |
| `ADAPTER_URL` | `""` | Base URL to `worldpool-adapter` feeds |
| `ADAPTER_REFRESH_INTERVAL`| `300` | Background adapter refresh interval (seconds) |
| `COOLDOWN_SECONDS` | `60` | Duration to quarantine an exit on 429/403/503 |
| `MAX_RETRIES` | `3` | Maximum in-flight replay attempts per request |
| `REPLAY_TIMEOUT` | `20.0` | Upstream socket timeout for in-flight replay (seconds) |
| `UPSTREAM_CONNECT_TIMEOUT`| `10.0` | Upstream TCP/CONNECT handshake timeout (seconds) |
