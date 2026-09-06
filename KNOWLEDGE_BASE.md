# Smart Proxy — Architectural Knowledge Base & Operational Learnings

This document preserves the comprehensive design decisions, protocol quirks, upstream peculiarities, and operational lessons discovered while building, tuning, and running Smart Proxy across production fleet infrastructure.

---

## 1. Core Philosophy & Design Principles

### 1.1 "Stupid Client, Very Smart Server"
- Downstream applications (Rule-34 API, OmniRoute, ChangeDetection, scraper scripts) should remain simple, standard clients using standard `HTTP_PROXY` / `HTTPS_PROXY` environment variables or proxy options.
- The proxy server owns all complex resilience logic: TLS interception, sticky session maintenance, upstream health checking, error classification, rapid rotation, and automatic in-flight request replay.

### 1.2 Universal & Standalone
- **Zero Destination-Specific Logic**: The proxy remains generic forward-proxy infrastructure. It never injects destination-specific headers (like booru-specific User-Agents) or custom application routing rules.
- **No Bespoke Reverse Proxies**: Avoid one-off reverse proxies or gateway services for specific destinations; use a single universal forward proxy with TLS MITM.

### 1.3 Validation Standard: Uncached Correlated Testing
- Never validate proxy health using cached HTTP requests or HTTP status alone (which may return 200 from Cloudflare edge caches).
- Always validate using **uncached, cache-busted requests** (e.g., negative random tags `-bust_<hex>`) and correlate responses against live container logs, exit IP changes, and rotation metrics.

---

## 2. Upstream Architecture & Pool Management

### 2.1 Dynamic Aggregation & Fast Refresh
- Proxies are dynamically aggregated from upstream feeds (Worldpool, Proxifly, Monosans, etc.) via `worldpool-adapter`.
- The refresh interval is tuned to **180 seconds** to ensure stale dead exits are evicted quickly and newly discovered low-latency nodes enter rotation immediately.

### 2.2 Real HTTPS CONNECT Pre-Flight Probing
- **Pitfall**: Probing candidate proxies with plain HTTP requests (e.g., `http://cp.cloudflare.com/generate_204`) gives false positives. Many public proxies allow plain HTTP tunneling but fail or block HTTPS `CONNECT` tunnels on port 443.
- **Solution**: Pre-flight health checks probe real HTTPS CONNECT tunnels via `https://1.1.1.1/cdn-cgi/trace`. Only proxies that successfully complete the TLS handshake over the tunnel are added to the active pool.

### 2.3 Per-Destination Sticky Tracking & Domain-Scoped Cooldowns
- **Problem**: In a shared global pool, if domain A (e.g., `e621.net`) rate-limits an exit IP (HTTP 429), rotating the global proxy would prematurely evict healthy sessions for domain B (e.g., `gelbooru.com` or `danbooru.donmai.us`).
- **Solution**:
  1. **Root Domain Grouping**: Subdomains are extracted to root domains (e.g., `static1.e621.net` → `e621.net`) so all related assets share sticky affinity.
  2. **Scoped Cooldowns**:
     - **Host Failures (HTTP 403, 429, 503, WAF challenges)**: Trigger `record_host_failure()`, placing that exit on cooldown *only* for the affected root domain (default 60s).
     - **Global Socket Failures (Connection refused, reset, timeout)**: Trigger `record_global_failure()`, placing that exit on cooldown across all destinations.
  3. **Starvation Prevention**: If all nodes in the pool are temporarily on cooldown for a given domain, the pool falls back to the earliest-expiring node rather than failing or stalling.

---

## 3. Mitmproxy 12 Internals & Flow Lifecycle

### 3.1 Via Binding Lifecycle (`requestheaders` vs `request`)
- In mitmproxy 12+, `make_server_connection` executes during the `requestheaders` phase before `request`.
- Setting `flow.server_conn.via` during `request` is too late because the connection layer has already resolved the upstream route.
- Upstream routing must assign `flow.server_conn.via = parse(node.key, "http")` in `requestheaders` and `http_connect_upstream`.
- **Do not replace the `Server` object**: Re-instantiating `flow.server_conn = Server(...)` breaks internal connection state. Only mutate `flow.server_conn.via`.

### 3.2 Upstream Proxy CONNECT Authentication
- When routing through authenticated upstream proxies, the `Proxy-Authorization: Basic <base64>` header must be injected into the upstream CONNECT handshake in `http_connect_upstream`.

### 3.3 Avoiding `ClientPlayback` Deadlocks
- **Pitfall**: Using mitmproxy's `replay.client` (`ClientPlayback`) on live in-flight flows fails with `Can't replay live flow`. Polling `flow.response` inside a sleep loop causes a 30s+ dead wait per retry.
- **Solution**: In-flight replay is handled via synchronous worker execution (`_fetch_upstream_sync`) using `urllib.request` running in a dedicated `ThreadPoolExecutor`.

### 3.4 Event Loop Safety & Executor Shutdown
- Mitmproxy event loops may recycle. Using `asyncio.to_thread()` can trigger `RuntimeError: Executor shutdown has been called`.
- Always use a dedicated, persistent `concurrent.futures.ThreadPoolExecutor(max_workers=32, thread_name_prefix="smartproxy-worker")`.

### 3.5 Removal of `@concurrent` Decorators
- Applying `@concurrent` across `request`, `http_connect`, `response`, and `error` hooks causes race conditions where metadata is lost or flow order is scrambled. All flow handlers operate sequentially per flow.

---

## 4. Booru & Upstream Target Quirks (e621, Danbooru, Rule34)

### 4.1 Two-Layer Bot Detection (Cloudflare WAF vs. Rails Application)
```
Request ────► [ Layer 1: Cloudflare WAF ] ────► [ Layer 2: e621 Backend ]
              Checks: Browser signature         Checks: Non-generic project
              Passes: `Mozilla/5.0...`          Passes: `Grabber/7.14.0`
```
1. **Layer 1 (Edge / Cloudflare)**: Pure custom User-Agents (e.g. `MyProject/1.0`) receive higher bot scores and are challenged during query spikes. Starting the UA with a standard browser signature (`Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0`) allows smooth passage through edge heuristics.
2. **Layer 2 (Application / Rails)**: e621 blocks known scrapers (`curl`, `python-requests`, `urllib`, `Universal-Booru-Wrapper/*`) with `429 Too Many Requests`. Appending a recognized, widely distributed client signature (`Grabber/7.14.0 User/<uuid>`) satisfies application checks.

### 4.2 Dynamic Client UUIDs
- Bionus Grabber generates a unique UUID on first run and persists it as `User/<uuid>`.
- Client wrappers should dynamically generate RFC 4122 v4 UUIDs per client instance to prevent monolithic clustering on shared proxy IPs.

### 4.3 Database Heavy Query Latency Dynamics
- **Latency Reality**: On booru backends (e621 PostgreSQL), searches combining **broad negative exclusions** (e.g., `-pokemon_(species)`) and **score filters** (`score:>=50`) trigger intensive database operations that take **8 to 15 seconds** to compute.
- **Timeout Requirements**:
  - `socket.setdefaulttimeout(20.0)`
  - `REPLAY_TIMEOUT = 20.0`
  - `UPSTREAM_CONNECT_TIMEOUT = 10.0`
  - `tcp_timeout = 35` (mitmproxy command-line argument)
  - Setting timeouts below 8 seconds causes premature socket aborts and false-positive proxy rotations.

---

## 5. System, Kernel & Fleet Operations

### 5.1 File Descriptor & Socket Scaling
- **Netdata Alert**: Long-lived MITM proxy processes encounter file descriptor exhaustion if bounded by default soft limits (`1024`).
- **Solution**: Configure Docker daemon defaults globally via `/etc/docker/daemon.json`:
  ```json
  {
    "default-ulimits": {
      "nofile": {
        "Name": "nofile",
        "Soft": 65535,
        "Hard": 524288
      }
    }
  }
  ```
- **Kernel TCP Tuning**:
  - `net.ipv4.tcp_tw_reuse = 2`
  - `net.ipv4.tcp_fin_timeout = 60`

### 5.2 Fleet Certificate Synchronization
- The persistent MITM CA certificate (`smart-proxy-ca.crt` / `smart-proxy-ca.pem`) must be synchronized across all downstream consumer runtimes:
  - **Node.js (Rule-34 API, OmniRoute)**: `NODE_EXTRA_CA_CERTS=/app/ca/smart-proxy-ca.pem`
  - **Python (ChangeDetection)**: `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` / system trust store
  - **Bitwarden Vault**: Stored in item `Hosting EU — Smart Proxy Root CA & Credentials`
- When regenerating the Smart Proxy volume, always check the SHA-256 fingerprint of `/ca/mitmproxy-ca.pem` and push the updated certificate to all consumers.

### 5.3 Network Topology & Firewalling
- **Private Endpoint**: Bound internally to Tailscale (`100.101.155.30:8088` / `http://hosting-eu:8088`).
- **Public Endpoint**: Exposed on port `24000` with basic authentication (`smart-proxy.akbal.dev:24000`), requiring `--set block_global=false` in mitmdump to permit public clients.
