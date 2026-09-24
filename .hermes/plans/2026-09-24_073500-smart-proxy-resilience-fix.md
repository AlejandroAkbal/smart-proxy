# Smart Proxy Resilience & Root Cause Fix Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Eliminate Smart Proxy 30s+ timeout cascades, in-flight replay hangs on HEAD requests, decompression corruption, and sticky lock-in on mediocre proxies while preserving legitimate slow booru queries and avoiding Cloudflare session thrashing.

**Architecture:** Bounded end-to-end request budget (25s hard ceiling, 7s connect/first-byte budget) with active socket cancellation on client disconnect; RFC 9110 compliant HEAD/204/304 response framing; bounded decompression (20 MB cap) with origin error separation; soft latency re-ranking (rotate lazily only if active sticky node EMA exceeds 1.5× fleet top); and preserving learned production EMA and domain cooldowns across pool refreshes.

**Tech Stack:** Python 3.11+, mitmproxy addon (`mitmproxy.http`), HTTP/1.1 & HTTP/2, Docker Compose, Coolify.

---

### Task 1: Fix `worldpool-adapter` Coolify Healthcheck Syntax

**Objective:** Repair the unquoted URL syntax error in Coolify's Docker Compose definition for `worldpool-adapter` that caused 139 failing healthchecks.

**Files:**
- Modify via Coolify API/Tinker on `hetzner-de-1`: Service `qwsm8umlxplwpg8cnndchwrq` (`mihomo`)
- Local reference: `compose-mihomo-historical.yaml:55-60`

**Step 1: Inspect current healthcheck command in Coolify DB**
Run:
```bash
ssh hetzner-de-1 "docker exec coolify php artisan tinker --execute '\$s = App\Models\Service::find(149); echo \$s->docker_compose_raw;'"
```
Observe unquoted URL: `urlopen(http://127.0.0.1:3000/health, timeout=3)` causing `SyntaxError: invalid syntax`.

**Step 2: Update service compose in Coolify with quoted URL**
Run:
```bash
ssh hetzner-de-1 "docker exec coolify php artisan tinker --execute '
\$service = App\Models\Service::find(149);
\$raw = \$service->docker_compose_raw;
\$raw = str_replace(\"http://127.0.0.1:3000/health\", \"\\x27http://127.0.0.1:3000/health\\x27\", \$raw);
\$service->docker_compose_raw = \$raw;
\$service->save();
\$service->saveComposeConfigs();
echo \"Updated healthcheck syntax!\n\";
'"
```

**Step 3: Redeploy `worldpool-adapter` in Coolify**
Run:
```bash
ssh hetzner-de-1 "cd /data/coolify/services/qwsm8umlxplwpg8cnndchwrq && docker compose up -d"
```

**Step 4: Verify container transitions to healthy**
Run:
```bash
ssh hetzner-de-1 "sleep 15 && docker ps --filter name=worldpool-adapter --format 'table {{.Names}}\t{{.Status}}'"
```
Expected: `worldpool-adapter-qwsm8umlxplwpg8cnndchwrq   Up ... (healthy)` with 0 exit code.

---

### Task 2: RFC 9110 Compliant HEAD / Framing & Body Truncation Validation

**Objective:** Prevent `_read_with_deadline` from hanging on HEAD requests while ensuring GET bodies match `Content-Length` without false-positive failures on 204/304.

**Files:**
- Modify: `smart_proxy.py:475-535`
- Test: `test_smart_proxy_adversarial.py`

**Step 1: Write failing test in `test_smart_proxy_adversarial.py`**
Add test case `test_head_request_no_hang_and_no_body`:
```python
def test_head_request_no_hang_and_no_body(self):
    class HeadHandler(http.server.BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200)
            self.send_header("Content-Length", "557")
            self.send_header("Content-Type", "application/xml")
            self.end_headers()
    # verify _read_with_deadline returns b"" in < 0.1s instead of timing out at 2.0s
```

**Step 2: Run test to verify failure**
Run: `python3 -m unittest test_smart_proxy_adversarial.py -k test_head_request_no_hang_and_no_body`
Expected: FAIL — `TimeoutError: Upstream response read deadline exceeded`

**Step 3: Implement minimal fix in `smart_proxy.py`**
In `_read_with_deadline(resp, method="GET", status_code=200, timeout=..., sock=...)`:
```python
# RFC 9110 §6.4.1 & §8.6: 1xx, 204, 304, and responses to HEAD MUST NOT include a message body.
if method.upper() == "HEAD" or status_code in (204, 304) or (100 <= status_code < 200):
    return b""
```
And for responses with `Content-Length`:
```python
cl_header = resp.headers.get("Content-Length")
if cl_header and cl_header.isdigit():
    expected_len = int(cl_header)
    if total_len < expected_len:
        raise IncompleteReadError(f"Premature EOF: received {total_len}/{expected_len} bytes")
```

**Step 4: Run test to verify pass**
Run: `python3 -m unittest test_smart_proxy_adversarial.py -k test_head_request_no_hang_and_no_body`
Expected: PASS in < 0.05s.

**Step 5: Commit**
```bash
git add smart_proxy.py test_smart_proxy_adversarial.py
git commit -m "fix(framing): handle HEAD/204/304 without body and validate Content-Length on GET"
```

---

### Task 3: Bounded Decompression with Origin Error Discrimination

**Objective:** Prevent raw compressed bytes from leaking downstream when decompression fails, prevent gzip bomb OOM crashes, and avoid quarantining healthy proxies on origin payload corruption.

**Files:**
- Modify: `smart_proxy.py:410-445`
- Test: `test_smart_proxy_adversarial.py`

**Step 1: Write failing test in `test_smart_proxy_adversarial.py`**
Add test case `test_decompress_failure_does_not_strip_header_or_quarantine`:
```python
def test_decompress_failure_does_not_strip_header_or_quarantine(self):
    corrupted_gzip = b"\x1f\x8b\x08" + b"random_corrupted_data_not_valid_gzip"
    decompressed, success = _decompress_body_safe(corrupted_gzip, "gzip", max_bytes=20*1024*1024)
    self.assertFalse(success)
```

**Step 2: Run test to verify failure**
Run: `python3 -m unittest test_smart_proxy_adversarial.py -k test_decompress_failure_does_not_strip_header_or_quarantine`
Expected: FAIL — function `_decompress_body_safe` does not exist.

**Step 3: Implement bounded decompression with status return**
In `smart_proxy.py`:
```python
MAX_DECOMPRESSED_BYTES = 20 * 1024 * 1024  # 20 MB safety ceiling against gzip bombs

def _decompress_body_safe(content: bytes, encoding: Optional[str], max_bytes: int = MAX_DECOMPRESSED_BYTES) -> tuple[bytes, bool]:
    if not encoding or not content:
        return content, True
    enc = encoding.lower().strip()
    try:
        if enc == "gzip":
            # Decompress with size limit to prevent gzip bomb
            d = gzip.decompress(content)
            if len(d) > max_bytes:
                raise ValueError("Decompressed payload exceeds safety ceiling")
            return d, True
        elif enc == "deflate":
            d = zlib.decompress(content)
            if len(d) > max_bytes:
                raise ValueError("Decompressed payload exceeds safety ceiling")
            return d, True
    except Exception as e:
        logger.warning(f"[SmartProxy] Upstream payload decompression failed ({enc}): {e}")
        return content, False
    return content, True
```
In `_fetch_upstream_sync`:
- If `success` is False, do **not** strip `Content-Encoding` (preserve original framing) and mark response as origin-error rather than proxy connection failure so the proxy is not falsely quarantined.

**Step 4: Run test to verify pass**
Run: `python3 -m unittest test_smart_proxy_adversarial.py -k test_decompress_failure_does_not_strip_header_or_quarantine`
Expected: PASS.

**Step 5: Commit**
```bash
git add smart_proxy.py test_smart_proxy_adversarial.py
git commit -m "fix(decompression): add 20MB decompression ceiling and preserve headers on origin decode error"
```

---

### Task 4: Global Request Deadline Budget & Active Socket Cancellation

**Objective:** Cap end-to-end request latency at 25s (well below UptimeRobot's 30s timeout) while allocating 7s for initial connect/first-byte to allow slow booru searches to complete, and actively close upstream sockets when the client disconnects.

**Files:**
- Modify: `smart_proxy.py:20-40`, `smart_proxy.py:650-780`
- Test: `test_smart_proxy_stress_fuzz.py`

**Step 1: Write failing test in `test_smart_proxy_stress_fuzz.py`**
Add test case `test_overall_deadline_budget_prevents_cascades`:
```python
def test_overall_deadline_budget_prevents_cascades(self):
    # Simulate two slow upstream proxies that hang for 15s each
    # Ensure entire flow terminates with 504 Gateway Timeout in <= 25.5s
```

**Step 2: Run test to verify failure**
Run: `python3 -m unittest test_smart_proxy_stress_fuzz.py -k test_overall_deadline_budget_prevents_cascades`
Expected: FAIL — request took 40.04s.

**Step 3: Implement overall request budget and active socket tracking**
In `smart_proxy.py`:
```python
GLOBAL_REQUEST_TIMEOUT = 25.0  # Strict ceiling below UptimeRobot 30s
CONNECT_FIRST_BYTE_TIMEOUT = 7.0  # Fast-fail dead proxy connects while giving booru DB time

def http_connect(self, flow: mitm_http.HTTPFlow) -> None:
    flow.metadata["request_start_time"] = time.time()
    flow.metadata["active_sockets"] = []
```
In `client_disconnected(self, client: mitm_http.Client)`:
```python
# Actively abort any in-flight upstream sockets associated with this client flow
for flow in self.active_flows_for_client(client.id):
    for sock in flow.metadata.get("active_sockets", []):
        try:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        except Exception:
            pass
```
In `response()` and `error()` replay loops:
```python
elapsed = time.time() - flow.metadata.get("request_start_time", time.time())
remaining_budget = GLOBAL_REQUEST_TIMEOUT - elapsed
if remaining_budget < 2.0:
    logger.warning(f"[SmartProxy] Overall request budget exhausted ({elapsed:.1f}s), aborting retries.")
    break
attempt_timeout = min(REPLAY_TIMEOUT, remaining_budget, CONNECT_FIRST_BYTE_TIMEOUT)
```

**Step 4: Run test to verify pass**
Run: `python3 -m unittest test_smart_proxy_stress_fuzz.py -k test_overall_deadline_budget_prevents_cascades`
Expected: PASS — request completes with 504 in < 25.1s, sockets closed.

**Step 5: Commit**
```bash
git add smart_proxy.py test_smart_proxy_stress_fuzz.py
git commit -m "fix(budget): enforce 25s global request budget and cancel active sockets on client disconnect"
```

---

### Task 5: Probe Validation & Learned EMA / Domain Cooldown Preservation

**Objective:** Prevent `_probe_node` from treating 403/429 as healthy, and stop `update_nodes` from overwriting real production EMA and resetting domain quarantine cooldowns.

**Files:**
- Modify: `smart_proxy.py:160-200`, `smart_proxy.py:315-330`
- Test: `test_smart_proxy_adversarial.py`

**Step 1: Write failing test in `test_smart_proxy_adversarial.py`**
Add test case `test_probe_rejects_403_and_pool_update_preserves_production_ema`:
```python
def test_probe_rejects_403_and_pool_update_preserves_production_ema(self):
    node = ProxyNode(scheme="http", host="1.2.3.4", port=8080, ema_latency_ms=950.0)
    node.domain_cooldowns["e621.net"] = time.time() + 600
    # Simulate update_nodes with fresh probe node showing 20ms
    # Verify ema_latency_ms is NOT overwritten to 20ms and domain_cooldowns is preserved
```

**Step 2: Run test to verify failure**
Run: `python3 -m unittest test_smart_proxy_adversarial.py -k test_probe_rejects_403_and_pool_update_preserves_production_ema`
Expected: FAIL — `ema_latency_ms` was overwritten to 20ms and cooldown was reset.

**Step 3: Implement fix in `smart_proxy.py`**
In `_probe_node`:
```python
# Only true success (200, 204) proves Cloudflare edge ingress; 403/429 indicate IP reputation blocks
if resp.status in (200, 204):
    node.ema_latency_ms = duration_ms
    return node
return None
```
In `StickyLatencyPool.update_nodes`:
```python
for key, n in unique_new.items():
    if key in existing:
        old = existing[key]
        # Preserve real production learned latency; do NOT overwrite with synthetic 204 probe
        if old.ema_latency_ms <= 0:
            old.ema_latency_ms = n.ema_latency_ms
        # Preserve domain-specific cooldowns and failure counts
        merged.append(old)
    else:
        merged.append(n)
```

**Step 4: Run test to verify pass**
Run: `python3 -m unittest test_smart_proxy_adversarial.py -k test_probe_rejects_403_and_pool_update_preserves_production_ema`
Expected: PASS.

**Step 5: Commit**
```bash
git add smart_proxy.py test_smart_proxy_adversarial.py
git commit -m "fix(pool): reject 403/429 in probe and preserve production EMA and cooldowns across refreshes"
```

---

### Task 6: Soft Latency Re-Ranking Without Cloudflare Session Thrashing

**Objective:** Prevent 98% of traffic from locking onto mediocre public proxies by lazily re-evaluating the sticky node only when its latency exceeds 1.5× the fleet's top node, avoiding arbitrary mid-session IP thrashing.

**Files:**
- Modify: `smart_proxy.py:200-240`
- Test: `test_smart_proxy_stress_fuzz.py`

**Step 1: Write failing test in `test_smart_proxy_stress_fuzz.py`**
Add test case `test_soft_latency_reranking_switches_slow_sticky_node`:
```python
def test_soft_latency_reranking_switches_slow_sticky_node(self):
    pool = StickyLatencyPool()
    fast_node = ProxyNode(scheme="http", host="100.101.155.30", port=1080, ema_latency_ms=50.0)
    slow_node = ProxyNode(scheme="http", host="43.153.80.169", port=80, ema_latency_ms=650.0)
    pool.update_nodes([fast_node, slow_node])
    pool.current_nodes["paheal.net"] = slow_node  # initially stuck on slow
    # On get_current_or_best, since slow_node (650ms) > 1.5 * fast_node (50ms), it should switch to fast_node
    selected = pool.get_current_or_best("paheal.net")
    self.assertEqual(selected.host, "100.101.155.30")
```

**Step 2: Run test to verify failure**
Run: `python3 -m unittest test_smart_proxy_stress_fuzz.py -k test_soft_latency_reranking_switches_slow_sticky_node`
Expected: FAIL — returned `slow_node` due to blind stickiness.

**Step 3: Implement soft latency re-ranking**
In `StickyLatencyPool.get_current_or_best(domain: str)`:
```python
with self.lock:
    now = time.time()
    current = self.current_nodes.get(domain)
    if current and current.is_available_for(domain, now):
        # Find the best available candidate
        best_candidate = self._peek_best_for(domain, now)
        if best_candidate and best_candidate.key != current.key:
            # Only migrate if current node is significantly worse (> 1.5x slower)
            # This prevents session thrashing between equally fast nodes
            if current.ema_latency_ms > (best_candidate.ema_latency_ms * 1.5):
                logger.info(f"[SmartProxy] Soft re-ranking {domain}: switching from {current.key} ({current.ema_latency_ms:.1f}ms) to {best_candidate.key} ({best_candidate.ema_latency_ms:.1f}ms)")
                if best_candidate.try_consume_token():
                    self.current_nodes[domain] = best_candidate
                    return best_candidate
        if current.try_consume_token():
            return current
    return self.select_best_for(domain, check_rate_limit=True)
```

**Step 4: Run test to verify pass**
Run: `python3 -m unittest test_smart_proxy_stress_fuzz.py -k test_soft_latency_reranking_switches_slow_sticky_node`
Expected: PASS.

**Step 5: Commit**
```bash
git add smart_proxy.py test_smart_proxy_stress_fuzz.py
git commit -m "feat(routing): soft re-rank sticky exit when EMA latency exceeds 1.5x fleet top"
```

---

### Task 7: Full QA Battery & Adversarial Verification

**Objective:** Run the full combined adversarial, stress, fuzz, and contract test suites locally to ensure zero regressions across all 7 protocol probes.

**Files:**
- Test runners: `test_smart_proxy_adversarial.py`, `test_smart_proxy_stress_fuzz.py`, `test_contract.py`

**Step 1: Run complete adversarial test suite**
Run: `python3 -m unittest test_smart_proxy_adversarial.py -v`
Expected: ALL tests pass (0 failures, 0 errors).

**Step 2: Run complete stress & fuzz test suite**
Run: `python3 -m unittest test_smart_proxy_stress_fuzz.py -v`
Expected: ALL tests pass (0 failures, 0 errors).

**Step 3: Run full live contract test**
Run: `python3 -m unittest test_contract.py -v`
Expected: ALL tests pass.

---

### Task 8: Production Deployment via Coolify & Multi-Probe Verification

**Objective:** Deploy patched `smart_proxy.py` and updated Coolify configuration to `hetzner-de-1`, verify healthy container status, and run 30 paced real requests across Paheal and e621.

**Files:**
- Remote host: `hetzner-de-1`
- Container: `smart-proxy-hp2ewpogk3oxhqvf6wkb46iz`

**Step 1: Copy patched `smart_proxy.py` to `hetzner-de-1` and update container**
```bash
scp smart_proxy.py hetzner-de-1:/tmp/smart_proxy.py
ssh hetzner-de-1 "docker cp /tmp/smart_proxy.py smart-proxy-hp2ewpogk3oxhqvf6wkb46iz:/app/smart_proxy.py && docker restart smart-proxy-hp2ewpogk3oxhqvf6wkb46iz"
```

**Step 2: Verify `worldpool-adapter` and `smart-proxy` container health**
```bash
ssh hetzner-de-1 "docker ps --filter 'name=hp2ewpogk3oxhqvf6wkb46iz' --filter 'name=qwsm8umlxplwpg8cnndchwrq'"
```
Expected: Both containers show `healthy` status.

**Step 3: Run 30 paced real queries across booru targets from `hetzner-de-2`**
Verify:
1. `paheal.net` queries achieve > 90% routing to fleet nodes (`100.101.155.30` / `100.78.142.119`) with average latency < 100ms.
2. `e621.net` queries fail over cleanly to `vsys-nl-1`, `oracle-es`, or `raspberry-pi` without exceeding 12s.
3. 0 requests exceed 25s; zero 503 or 504 errors returned.
4. UptimeRobot monitor `803068245` continues reporting `UP`.
