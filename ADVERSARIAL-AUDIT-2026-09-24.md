# Adversarial audit — Smart Proxy "Paheal downtime fix"

Date: 2026-09-24 (UTC). Auditor: independent subagent. Mandate: prove or falsify the four
claims made to Alejandro, using reproducible evidence only.

## 0. Scope / artefact identity (verified first)

| Item | Value | Proof |
|---|---|---|
| Live container | `smart-proxy-hp2ewpogk3oxhqvf6wkb46iz` on `hetzner-de-1`, `Up`, `RestartCount=0` | `docker inspect` |
| Started | `2026-09-24T04:06:34Z` (image built from `github.com/AlejandroAkbal/smart-proxy.git#main`) | `docker inspect .State.StartedAt` |
| Deployed code | `sha256(/app/smart_proxy.py) = 7b1982972f9375374a136d6918d448b8a85b8e3d1371c4f5a064bdef8f0207fe`, 804 lines | `docker exec … sha256sum` |
| Local working copy | identical hash (same 804 lines) | `shasum -a 256 smart_proxy.py` |
| GitHub `main` | identical hash (`raw.githubusercontent.com/…/main/smart_proxy.py`) | `curl … && shasum` |

=> Every line quoted below is the code that is actually serving traffic.

## 1. Verdict on the four claims

### Claim 1 — "Fleet sing-boxes in UPSTREAM_PROXIES fixed Paheal downtime because Hetzner DE
### nodes are fastest (52–80 ms) and win EMA selection." — **FALSE as stated**

* Live routing, 60 min window:
  `docker logs --since 60m … | grep 'next_layer set server.via' | grep paheal | awk '{print $NF}'`
  → **32 / 9846 paheal connections (0.33 %) went to a fleet node**; 75 min window: **142 / 9423 (1.51 %)**.
  Everything else goes to worldpool public proxies (`43.173.120.13:8899`, `193.104.179.115:3128`,
  `192.210.140.253:3128`, `31.31.74.185:9898`, …). The fleet does **not** win EMA selection for
  paheal; it is not the primary path at all.
* The latency premise is roughly true but self-defeating: `_probe_node` measures
  `https://cp.cloudflare.com/generate_204` (lines 295, 308, 314). Measured per node in the container:
  hetzner-de-1 **204 in 22 ms**, hetzner-de-2 **31 ms**, oracle-es 50/54 ms, vsys-nl 22 ms.
  The two "fastest" nodes are **403-blocked on e621.net** (proven below) — i.e. "fastest wins"
  systematically selects a blocked node first.
* What the fleet actually contributes: the majority of *recovery retries* for paheal
  (`Error-recovery success … from http://100.x` = 70 vs 60 from public nodes, 60 min).
  So the honest statement is "fleet nodes act as the failover net", not "they fixed the outage".
* Monitoring causality is unsupported: UptimeRobot daily/hourly uptime for monitor `803068245`
  is **100 % for the 7 h before the deploy and 100 % for the 3 h after**; the only incident in 12 h
  is 440 s at **02:49–02:57Z**, i.e. **1 h 17 m before this container existed**.

### Claim 2 — "In-flight retry logic and replay via `_fetch_upstream_sync` is robust and handles
### failures seamlessly." — **OVERSTATED / FALSE under load**

* `_fetch_upstream_sync` failures in the live log (75 min): 1109 successes, **355 replay
  timeouts**, 355 connection failures, 536 global quarantines, **2771 rotation events**.
* Reconstructed per-request replay cost (rotation timestamp → outcome timestamp, 2097 requests
  that consumed both retries): median 6.0 s, p90 **33.4 s**, max **77.4 s** — **151 requests in
  75 min exceeded UptimeRobot's 30 s timeout** in the replay stack alone (initial attempt excluded).
* Structurally unbounded budget: per attempt the deadline is 20 s *connect* + 20 s *read*
  (`http.client.HTTPConnection(..., timeout=timeout)` line 541 + `_read_with_deadline` deadline
  line 480), × `MAX_RETRIES=2`, plus mitmproxy's own `connect_timeout=10 s`; there is **no overall
  deadline, no `asyncio.wait_for`, no future cancellation** anywhere in the file:
  `grep -nE 'wait_for|\.cancel\(|asyncio\.timeout|Semaphore' smart_proxy.py` → no matches.
* Reproduced: against a black-hole upstream with `REPLAY_TIMEOUT=20.0`, `MAX_RETRIES=2` →
  `replay attempt 1: 20.02 s`, `replay attempt 2: 20.02 s`, **TOTAL 40.04 s > 30 s**
  (`adversarial-probes/corruption_and_timeout_probe.py`, run inside the live container).
* Reproduced end-to-end on the exact monitored URL: paced replica of the monitor (one HEAD every
  8 s to `http://<api-container>:3000/booru/rule34.paheal.net/posts?baseEndpoint=rule34.paheal.net&limit=1`,
  same method/URL the monitor uses) → **1 of 12 checks returned HTTP 503 after 34.4 s**
  (07:18:25Z). Proxy log for that request: attempt 1 failed → `Rotating -> http://154.201.126.44:8080
  (attempt 2/2)` → connection error → client gave up. 503 is outside the monitor's
  `successHttpResponseCodes: ["2xx","3xx"]` and 34.4 s > `timeout: 30`.
* Also reproduced: 40 concurrent HEADs to e621 through the proxy → **40/40 × 403**, plus two
  >30 s (`33.87 s`, `35.04 s`) responses on the API's e621 endpoint. Rotation cannot fix a
  User-Agent/policy block; it only burns up to 2 × 20 s and returns the same block.

### Claim 3 — "Aborting replay loops on `if not flow.client_conn.connected: break` prevents
### resource leaks." — **PARTIALLY TRUE, materially overstated**

* The guard exists twice (lines **704** and **763**) and does fire in production:
  `grep -c 'aborting error recovery'` = **476 events in 75 min** — clients (the API) abandon
  in-flight replays constantly.
* It only prevents *subsequent* iterations. The in-flight `await loop.run_in_executor(...)`
  (lines 716, 775) is never cancelled and there is no cancellation primitive in the file, so a
  disconnected client's replay keeps a `_WORKER_EXECUTOR` thread busy for up to 20 s
  (32 workers max). Observed thread count stayed flat at 35, so no unbounded thread leak — but
  "prevents resource leaks" should read "stops the *next* retry".

### Claim 4 — "Response decompression in `_fetch_upstream_sync` prevents JSON corruption."
### — **FALSE / inverted**

* `_decompress_body` (lines 412–442) **swallows the error and returns the raw compressed bytes**:
  `except Exception: return content`. `_fetch_upstream_sync` then strips `content-encoding`
  (line 569) and returns `mitm_http.Response.make(resp.status, content, resp_headers)` (line 573).
  Result: **HTTP 200 carrying gzip binary with no encoding header**.
  Proof inside the live container: `returned body: 23B first 8 bytes: b'\x1f\x8b\x08\x00\x00\x00\x00\x00'`,
  `content-encoding header sent to client: None`, `json.loads(body)` → `UnicodeDecodeError`.
* `_read_with_deadline` (478–505) reads until EOF and **never validates `Content-Length`** despite
  `Content-Length: 23` being present, so a body truncated by an early close is accepted as complete
  and then mis-decompressed as above.
* The happy path is fine: real replays return decodable JSON.

## 2. The six investigation items

1. **HEAD handling.** The mechanism is real and reproduced: with an upstream that answers HEAD and
   keeps the connection open, `resp.fp.read1(65536)` (line 496) blocks until the full deadline —
   `HEAD + keep-alive -> result=None (REPLAY FAILED) elapsed=5.01 s` vs
   `HEAD + close -> result=200 elapsed=0.00 s`. The same probe shows a *complete* GET body is also
   discarded when the peer keeps the connection open (`GET + keep-alive -> REPLAY FAILED 5.01 s`),
   because the reader waits for EOF, not for `Content-Length`.
   **It does not, however, break the UptimeRobot monitor for api.r34.app**: the API converts
   HEAD→GET (`grep -cE '128\.140\.76\.73:[0-9]+: HEAD'` over 30 min = **0** while 25 HEADs were sent
   to the API), and both real targets honour `Connection: close` (per-node live replay: paheal HTTP
   HEAD 308 in 0.04 s, HTTPS 200, e621 403 — all fast). The hazard remains live for anything that
   sends HEAD straight at the proxy (e.g. the `smart-proxy.akbal.dev:24000` monitors) and for any
   target/proxy that stops closing: a real instance of this failure mode appeared in the same test —
   oracle-es-1 hung on `https://e621.net/posts.json` (`TimeoutError: The read operation timed out`,
   8.17 s) although the same node returned 200 moments later, and 355 replay timeouts occurred in
   75 min.
2. **If Hetzner DE gets blocked on Paheal.** The probe cannot see it: it only tests
   `cp.cloudflare.com/generate_204` and **accepts 403/429 as healthy** (line 318:
   `if resp.status in (200, 204, 301, 302, 304, 403, 429)`), and it never inspects the body — so a
   node that is blocked on the real targets stays "verified healthy" and keeps the best EMA.
   `update_nodes` (line 145-174) then **resets `global_cooldown_until = 0` and overwrites the
   learned EMA with the fresh probe latency** on every 300 s refresh. Deterministic proof
   (`pool_reset_probe.py`): after a 403 the node is quarantined (`global_cd_until>0`,
   `is_available_for(paheal)=False`); after the next refresh `ema=25.0`, `global_cd_until=0.0`,
   "global quarantine forgotten: True", "re-ranked as fastest: True". The per-domain cooldown does
   survive (600 s), so the practical recovery is: the first paheal request after each cooldown
   expiry pays a failed attempt (0.5 s for a clean 403, up to 20 s if it hangs) and then rotates to
   another node — no operator action, but the blocked node is silently re-promoted, for every
   domain, every 5 minutes. Empirically the fleet nodes are re-used in bursts right after each
   refresh: 24.6 % of all fleet paheal routings land in the first 30 s after a refresh vs 10.8 %
   of all routings (n=142, suggestive not conclusive).
3. **SOCKS5.** Not reachable today, by accident: `_refresh_from_sources` line 361 filters
   `n.scheme in ("http", "https")`, and the feeds really do emit socks5
   (`monosans 5 socks5/5 http`, `iplocate 1`, `hookzof 4`, `databay 8` → 18 of 35 parsed nodes
   dropped). `http.client` cannot speak SOCKS5 — proven with a local SOCKS5 listener that received
   the raw bytes `b'CONNECT example.com:'` and answered garbage → `RemoteDisconnected`. Latent hole:
   an `https://` proxy URL *passes* the filter, and line 541 builds a plaintext
   `http.client.HTTPConnection` for it (and `mitmproxy.net.server_spec.parse(key, "http")` is told
   "http"), so an HTTPS-to-proxy entry would fail/leak in cleartext rather than error cleanly.
4. **Probe quality.** Yes — a node can pass the probe and be dead on the target. Per-node truth
   test from inside the container:
   `hetzner-de-1 204 in 22 ms | e621.net 403 | paheal 200`,
   `hetzner-de-2 204 in 31 ms | e621.net 403 | paheal 200`,
   `oracle-es-1/2 and vsys-nl 204 | e621.net 200 | paheal 200`.
   Additionally the probe accepts 403/429 as healthy and doesn't check the body, and its measured
   latency *replaces* the learned EMA at every refresh (line 163), so "health" is a 1.2 s
   status-line check against a third domain.
5. **30 s timeout edge cases.** Yes, several, all reproduced: (a) two sequential 20 s replays
   = 40.04 s (synthetic, inside the container); (b) 151 production requests in 75 min ≥ 30 s, max
   77.4 s; (c) monitor replica on the real monitored URL: 503 after 34.4 s (1 in 12 paced checks);
   (d) 40 concurrent HEADs → tail 11.4 s from queueing on a 32-thread executor, and the API's own
   e621 HEAD endpoint returned 33.87 s / 35.04 s. The 30 s monitor timeout is reachable and has been
   reached.
6. **Live container state.** `UPSTREAM_PROXIES` **is** present in the container env, with 6 fleet
   sing-boxes (`docker inspect … .Config.Env`), and the sing-boxes **are** handling live traffic:
   replay target selection to `http://100.x` = **969 in 60 min**, `Replay success … from http://100.x`
   = 292, `Error-recovery success … from http://100.x` = 379 (of which paheal 70). They are just not
   the primary path (§Claim 1).

## 3. Incidental defects found (not in the brief)

* `worldpool-adapter` container is **unhealthy, 139 consecutive failed healthchecks** — its
  healthcheck has a shell-syntax bug (`urlopen(http://127.0.0.1:3000/health, …)` unquoted →
  `SyntaxError`, exit 1). It still serves data, but 6 of its 12 feeds return HTTP 503
  (`worldpool, proxifly, proxyscrape, vakhov, speedx, zaeem`) which is why the pool is only
  14–31 raw nodes per refresh.
* `RATE_LIMIT_RPS` is unset (0.0) and `try_consume_token` returns `True` unconditionally in that
  case (line 84) → **no rate limiting at all** in this deployment.
* Replay responses are fully buffered and then decompressed with no size cap on the decompressed
  side (`_decompress_body`) → gzip-bomb memory exposure (raw read is capped at 100 MB).
* Rotation is attempted for *any* 403/429, including UA/policy blocks it can never fix, as
  demonstrated by 40/40 × 403 on e621 with a `curl` UA.

## 4. Reproduce everything

```bash
# 0. code identity
shasum -a 256 /Users/alejandro/Developer/Personal/smart-proxy-work/smart_proxy.py
ssh hetzner-de-1 'docker exec smart-proxy-hp2ewpogk3oxhqvf6wkb46iz sha256sum /app/smart_proxy.py'

# 1. fleet share of live traffic
ssh hetzner-de-1 "docker logs --since 60m smart-proxy-hp2ewpogk3oxhqvf6wkb46iz 2>&1 \
  | grep 'next_layer set server.via' | grep paheal | awk '{print \$NF}' | grep -c '^http://100\.'"

# 2. probe-healthy-but-blocked
ssh hetzner-de-1 "docker exec -i smart-proxy-hp2ewpogk3oxhqvf6wkb46iz python3 -" < adversarial-probes/per_node_truth.py

# 3. HEAD/framing hazard
ssh hetzner-de-1 "docker exec -i smart-proxy-hp2ewpogk3oxhqvf6wkb46iz python3 -" < adversarial-probes/framing_probe.py

# 4. corruption + 40 s replay tail
ssh hetzner-de-1 "docker exec -i smart-proxy-hp2ewpogk3oxhqvf6wkb46iz python3 -" < adversarial-probes/corruption_and_timeout_probe.py

# 5. cooldown/EMA reset every refresh
ssh hetzner-de-1 "docker exec -i smart-proxy-hp2ewpogk3oxhqvf6wkb46iz python3 -" < adversarial-probes/pool_reset_probe.py

# 6. monitor-faithful paced test (503 after 34.4 s)
ssh hetzner-de-2 'bash -s' < adversarial-probes/paced_monitor.sh

# 7. UptimeRobot truth
python3 - <<'EOF'   # key from ~/.config/uptimerobot/credentials.json
# GET /v2/getMonitors?api_key=…&monitors=803068245&custom_uptime_ranges=<a>_<b>: 100% for 7h before
# the 04:06Z deploy; the only 12h incident is 440s at 02:49-02:57Z
EOF
```
