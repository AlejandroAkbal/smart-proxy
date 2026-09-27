# Smart Proxy Adaptive Rate Limiting & Retry-After Implementation Plan (v2)

> **Goal:** Prevent fast proxy nodes from being overly penalized or sidelined for long periods upon receiving HTTP 429 responses, by parsing RFC 9110 `Retry-After` headers, applying adaptive backoff for rate limits without `Retry-After`, and decoupling rate-limiting cooldowns from network latency EMA degradation.

---

## 1. Problem Statement & Root Cause Analysis

### Current Invariant Breaches:
1. **Rigid 60s Sidelining on 429:** When any proxy node receives a 429 (Too Many Requests), `smart_proxy.py` treats it identically to a WAF block (403) or gateway crash (502/504), assigning a hardcoded `COOLDOWN_SECONDS = 60` lock for that domain.
2. **Ignored `Retry-After` Header:** Servers often state exact wait periods via `Retry-After: 3` (burst throttling) or `Retry-After: 120`. `smart_proxy.py` never inspects this header, causing either unnecessary 60s lockouts or premature retries on longer bans.
3. **Artificial Latency Inflation (`ema_latency_ms += 500.0`):** `record_host_failure()` penalizes node latency by +500ms on all failures. A 429 is an origin rate-limit, not a slow network transport. Inflating EMA latency keeps the fastest nodes sorted behind slower nodes long after the rate-limit window has expired.
4. **Cooldown Bypass on Empty Pool:** `select_best_for()` currently falls back to selecting `min(self.nodes, key=lambda n: n.get_effective_cooldown(domain))` if `healthy` is empty, which can immediately re-dispatch requests to a node that was just placed on cooldown.

---

## 2. Component Contracts & Edge Case Remediations

### Component 1: `parse_retry_after(raw_header: Optional[str], now: Optional[Union[float, datetime.datetime]] = None, min_seconds: float = 2.0, max_seconds: float = 300.0) -> Optional[float]`
- **RFC 9110 §10.2.3 & §5.6.7 Compliance:**
  1. **Input Normalization:**
     - Return `None` if `raw_header` is empty or None.
     - Strip whitespace and outer quotes: `raw_clean = raw_header.strip().strip("\"'")`.
  2. **Delta-Seconds:**
     - Validate strictly using `raw_clean.isdigit()`. Reject `nan`, `inf`, negative numbers, signs (`+`/`-`), and scientific notation (`1e2`).
     - Clamp valid integer values: `return min(max(float(raw_clean), min_seconds), max_seconds)`.
  3. **HTTP-Date (IMF-fixdate, RFC 850, ANSI C asctime):**
     - Normalize leap seconds: RFC 9110 mandates accepting `:60`. Normalize `:60` to `:59` before parsing: `re.sub(r":60(?=[^\d]|$)", ":59", raw_clean)`.
     - Parse using `email.utils.parsedate_to_datetime(raw_clean)`.
     - **Timezone Invariant:** If `dt.tzinfo is None` (as returned for ANSI C `asctime`), explicitly assign UTC: `dt = dt.replace(tzinfo=datetime.timezone.utc)`. Otherwise convert to UTC: `dt = dt.astimezone(datetime.timezone.utc)`.
     - Compute delta relative to UTC `now`: `delta = (dt - now_utc).total_seconds()`.
     - If `delta < -60.0` (stale/past header), treat as invalid and return `None` (falling back to adaptive backoff).
     - Otherwise clamp: `return min(max(delta, min_seconds), max_seconds)`.
  4. **Exception Safety:** Catch `(ValueError, TypeError, IndexError, OverflowError)` and return `None`.

### Component 2: `ProxyNode` Rate-Limit Tracking
- **State Fields:**
  - `consecutive_rate_limits: dict[str, int] = field(default_factory=dict)` mapping domain to failure count.
- **`record_host_rate_limit(domain: str, retry_after_s: Optional[float] = None)`:**
  - Increments `consecutive_rate_limits[domain]`.
  - Memory Bounding: If `len(self.consecutive_rate_limits) > 500`, prune the 100 least recently accessed domains (matching `host_cooldowns` eviction).
  - Cooldown computation:
    - If `retry_after_s` is provided: `cooldown = retry_after_s`.
    - If `retry_after_s is None`: Adaptive exponential backoff:
      `count = self.consecutive_rate_limits[domain]`
      `cooldown = min(10.0 * (2 ** min(count - 1, 5)), 300.0)`
      (Yields 10s, 20s, 40s, 80s, 160s, capped at 300s, preventing integer/float overflow).
  - Sets `self.host_cooldowns[domain] = time.time() + cooldown`.
  - **Zero EMA Latency Penalty:** Does NOT modify `self.ema_latency_ms`.
  - **Zero Global Failure Penalty:** Does NOT increment `self.failure_count` (preserving unbiased multi-domain tie-breaking).
- **`record_host_failure(domain: str)`:**
  - Standard failure (403, 502, 504, Cloudflare WAF challenge): applies flat 60s cooldown and `self.ema_latency_ms += 500.0`.
  - Resets `self.consecutive_rate_limits.pop(domain, None)`.
- **`record_success(duration_ms: float, domain: Optional[str] = None)`:**
  - Standard EMA latency update.
  - If `domain` is provided: `self.consecutive_rate_limits.pop(domain, None)`.

### Component 3: `StickyLatencyPool` Thread-Safe Management
- **`mark_host_rate_limit(node: ProxyNode, domain: str, retry_after_s: Optional[float] = None)`:**
  - Thread-safe: Wrapped in `with self.lock:`.
  - Calls `node.record_host_rate_limit(domain, retry_after_s)`.
  - Evicts sticky assignment if `self.current_nodes.get(domain) and self.current_nodes[domain].key == node.key: self.current_nodes.pop(domain, None)`.
- **`record_latency(node: ProxyNode, duration_ms: float, domain: Optional[str] = None)`:**
  - Thread-safe: Wrapped in `with self.lock:`.
  - Calls `node.record_success(duration_ms, domain)`.
- **`select_best_for(domain: str, check_rate_limit: bool = True) -> Optional[ProxyNode]`:**
  - When `healthy` is empty, return `None` instead of bypassing cooldown to pick `min(self.nodes, key=...)`.

### Component 4: Unified Request Quarantine in `SmartProxyAddon`
- Extract quarantine classification into a shared helper:
  ```python
  def _record_blocked_status(node: ProxyNode, domain: str, resp: mitm_http.Response, resp_sample: bytes):
      is_challenge = bool(CHALLENGE_RE.search(resp_sample))
      retry_after_raw = resp.headers.get("retry-after") if resp.headers else None
      if not is_challenge and (resp.status_code == 429 or (resp.status_code == 503 and retry_after_raw)):
          retry_after_s = parse_retry_after(retry_after_raw)
          pool.mark_host_rate_limit(node, domain, retry_after_s)
      else:
          pool.mark_host_failed(node, domain)
  ```
- **Apply to both branches:**
  - Terminal branch (line 939): `_record_blocked_status(node, domain, resp, resp_sample)`.
  - Retry/Failover branch (line 945): `_record_blocked_status(node, domain, resp, resp_sample)`.
- Success branch (line 937): `pool.record_latency(node, (time.monotonic() - start_time) * 1000.0, domain=domain)`.

---

## 3. Step-by-Step Implementation Steps

1. **Step 1: Implement `parse_retry_after` in `smart_proxy.py`**
   - Add regex import and RFC 9110 parsing logic with `re.sub` for `:60`, `isdigit()`, and timezone-aware datetime arithmetic.
2. **Step 2: Update `ProxyNode` in `smart_proxy.py`**
   - Add `consecutive_rate_limits` dictionary with 500-domain LRU bounding.
   - Add `record_host_rate_limit(domain, retry_after_s=None)`.
   - Update `record_success(duration_ms, domain=None)` to pop consecutive rate limits.
   - Update `record_host_failure(domain)` to pop consecutive rate limits.
3. **Step 3: Update `StickyLatencyPool` in `smart_proxy.py`**
   - Add `mark_host_rate_limit` with `with self.lock:`.
   - Update `record_latency` signature with `domain: Optional[str] = None`.
   - Update `select_best_for` to return `None` when all nodes are in cooldown.
4. **Step 4: Update `SmartProxyAddon.request` in `smart_proxy.py`**
   - Implement `_record_blocked_status`.
   - Replace lines 939 and 945 with `_record_blocked_status`.
   - Pass `domain` to `pool.record_latency` on success.
5. **Step 5: Write Comprehensive Test Suite**
   - In `test_smart_proxy_resilience_v2.py`:
     - Test `parse_retry_after` with integer seconds, quoted strings, `nan`, `inf`, negative values, scientific notation.
     - Test `parse_retry_after` with RFC 1123, RFC 850, ANSI C asctime, leap seconds `:60`, past dates.
     - Test `ProxyNode.record_host_rate_limit` adaptive backoff (10s, 20s, 40s, capped at 300s) and verify `ema_latency_ms` and `failure_count` remain unchanged.
     - Test `record_success` resets `consecutive_rate_limits`.
     - Test WAF challenge on 429 triggers `mark_host_failed` (500ms penalty), not rate-limit.
     - Test terminal 429 response invokes `mark_host_rate_limit`.
     - Test `select_best_for` returns `None` when all nodes on cooldown.
6. **Step 6: Adversarial QA Code Review, PR, and Deployment**
   - Run tests.
   - Dispatch adversarial QA code critic.
   - Open PR, merge into `main`.
   - Deploy Coolify service `hp2ewpogk3oxhqvf6wkb46iz`.
