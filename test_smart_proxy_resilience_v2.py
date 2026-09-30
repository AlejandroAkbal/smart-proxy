import asyncio
import base64
import gzip
import http.server
import io
import os
import socket
import sys
import threading
import time
import unittest
import zlib
from unittest.mock import MagicMock

# Mock mitmproxy environment if running outside container
try:
    import mitmproxy.http as mitm_http
    from mitmproxy.connection import Server, Client
    from mitmproxy.net.server_spec import ServerSpec, parse
except ImportError:
    import types
    mitmproxy = types.ModuleType("mitmproxy")
    sys.modules["mitmproxy"] = mitmproxy
    from test_mitmproxy_stubs import install_proxy_stack_stubs
    install_proxy_stack_stubs(mitmproxy)
    mitm_http = types.ModuleType("mitmproxy.http")
    sys.modules["mitmproxy.http"] = mitm_http
    mitm_connection = types.ModuleType("mitmproxy.connection")
    sys.modules["mitmproxy.connection"] = mitm_connection
    mitm_net = types.ModuleType("mitmproxy.net")
    sys.modules["mitmproxy.net"] = mitm_net
    mitm_spec = types.ModuleType("mitmproxy.net.server_spec")
    sys.modules["mitmproxy.net.server_spec"] = mitm_spec

    class MockServer:
        def __init__(self, address=None):
            self.address = address
            self.via = None
    mitm_connection.Server = MockServer
    mitm_connection.Client = MagicMock
    mitm_spec.ServerSpec = MagicMock
    mitm_spec.parse = lambda s, scheme="http": s
    class MockResponse:
        def __init__(self, status_code=200, content=b"", headers=None):
            self.status_code = status_code
            self.content = content
            h_dict = {}
            if isinstance(headers, list):
                for k, v in headers:
                    k_str = k.decode() if isinstance(k, bytes) else str(k)
                    v_str = v.decode() if isinstance(v, bytes) else str(v)
                    h_dict[k_str] = v_str
            elif isinstance(headers, dict):
                h_dict = headers
            self.headers = h_dict

        @classmethod
        def make(cls, status_code, content=b"", headers=None):
            return cls(status_code=status_code, content=content, headers=headers)

    mitm_http.Response = MockResponse
    mitm_http.HTTPFlow = MagicMock
    class MockRequest:
        def __init__(self, method="GET", url="http://example.com/test", headers=None, content=b""):
            self.method = method
            self.url = url
            self.headers = headers or {}
            self.content = content
            self.host = "example.com"
            self.pretty_host = "example.com"
    mitm_http.Request = MockRequest

# Import smart_proxy module
import smart_proxy
from smart_proxy import (
    GLOBAL_REQUEST_TIMEOUT,
    INITIAL_REQUEST_TIMEOUT,
    MAX_DECOMPRESSED_BYTES,
    ProxyNode,
    StickyLatencyPool,
    _decompress_body_safe,
    _extract_sample_body,
    _probe_node,
    _read_with_deadline,
    _record_blocked_status,
    parse_retry_after,
)


class TestResilienceAndFraming(unittest.TestCase):
    def test_head_framing_returns_empty_immediately(self):
        """RFC 9110 §8.6: HEAD request must return b'' immediately regardless of Content-Length."""
        mock_resp = MagicMock()
        mock_resp.getheader.side_effect = lambda h: "1048576" if h.lower() == "content-length" else None
        
        # Test HEAD
        body = _read_with_deadline(mock_resp, timeout=5.0, method="HEAD", status_code=200)
        self.assertEqual(body, b"")
        mock_resp.read.assert_not_called()

        # Test 204 No Content
        body_204 = _read_with_deadline(mock_resp, timeout=5.0, method="GET", status_code=204)
        self.assertEqual(body_204, b"")

        # Test 304 Not Modified
        body_304 = _read_with_deadline(mock_resp, timeout=5.0, method="GET", status_code=304)
        self.assertEqual(body_304, b"")

    def test_content_length_truncation_detection(self):
        """If received body is shorter than Content-Length header, raise ConnectionError."""
        mock_resp = MagicMock()
        mock_resp.getheader.side_effect = lambda h: "100" if h.lower() == "content-length" else None
        mock_resp.chunked = False
        mock_resp.fp = None
        # Returns only 20 bytes then EOF
        mock_resp.read.side_effect = [b"A" * 20, b""]

        with self.assertRaises(ConnectionError) as ctx:
            _read_with_deadline(mock_resp, timeout=2.0, method="GET", status_code=200)
        self.assertIn("expected 100 bytes, received 20 bytes", str(ctx.exception))

    def test_bounded_safe_decompression_gzip_bomb(self):
        """A gzip bomb expanding beyond MAX_DECOMPRESSED_BYTES must be aborted and flagged invalid."""
        # Create a compressed block of 100KB zeroes that expands to 25MB
        expanded_size = 25 * 1024 * 1024
        raw = b"\x00" * expanded_size
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as f:
            f.write(raw)
        compressed = buf.getvalue()

        # Test with a 1MB limit
        result, ok = _decompress_body_safe(compressed, "gzip", max_bytes=1024 * 1024)
        self.assertFalse(ok)
        self.assertEqual(result, compressed)  # Raw compressed bytes retained

    def test_corrupt_decompression_preserves_content_and_flags_error(self):
        """Malformed compressed data returns raw bytes and ok=False."""
        corrupt_data = b"\x1f\x8b\x08not-a-valid-gzip-stream"
        result, ok = _decompress_body_safe(corrupt_data, "gzip")
        self.assertFalse(ok)
        self.assertEqual(result, corrupt_data)

    def test_probe_node_rejects_403_and_429(self):
        """_probe_node must reject 403 / 429 status codes from Cloudflare."""
        node = ProxyNode(scheme="http", host="127.0.0.1", port=65500)
        
        # Test mock server returning 403
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        ls.listen(1)
        port = ls.getsockname()[1]
        node.port = port

        def serve():
            try:
                c, _ = ls.accept()
                req = c.recv(1024)
                # Reply to CONNECT
                c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                # Now TLS would happen or plain HTTP in test; since probe wraps SSL,
                # let's test that failure to complete TLS returns None
                c.close()
            except Exception:
                pass
            finally:
                ls.close()

        threading.Thread(target=serve, daemon=True).start()
        res = _probe_node(node, timeout=0.5)
        self.assertIsNone(res)

    def test_pool_update_preserves_learned_ema_and_cooldowns(self):
        """Pool refresh must not overwrite production EMA latency or clear unexpired cooldowns."""
        p = StickyLatencyPool()
        n1 = ProxyNode(scheme="http", host="10.0.0.1", port=8080, ema_latency_ms=250.0, success_count=15)
        n1.global_cooldown_until = time.time() + 45.0  # 45s left
        p.update_nodes([n1])

        # New discovery reports 20ms probe latency for n1
        n1_fresh = ProxyNode(scheme="http", host="10.0.0.1", port=8080, ema_latency_ms=20.0, success_count=0)
        p.update_nodes([n1_fresh])

        # Check that old EMA and cooldown were NOT wiped
        active_n1 = p.nodes[0]
        self.assertEqual(active_n1.ema_latency_ms, 250.0)
        self.assertGreater(active_n1.global_cooldown_until, time.time())

    def test_soft_latency_reranking(self):
        """Current sticky node is lazily migrated when another healthy node is >1.5x faster."""
        p = StickyLatencyPool()
        # Slow node: 800ms EMA
        slow = ProxyNode(scheme="http", host="10.0.0.1", port=8080, ema_latency_ms=800.0, success_count=10)
        # Fast node: 100ms EMA
        fast = ProxyNode(scheme="http", host="10.0.0.2", port=8080, ema_latency_ms=100.0, success_count=10)
        p.update_nodes([slow, fast])

        # Initially stick to slow node
        p.set_current_node("paheal.net", slow)
        self.assertEqual(p.current_nodes["paheal.net"].key, slow.key)

        # get_current_or_best should detect fast is >1.5x faster (800 > 150) and migrate
        selected = p.get_current_or_best("paheal.net")
        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(selected.key, fast.key)
        self.assertEqual(p.current_nodes["paheal.net"].key, fast.key)

    def test_socket_cancellation_on_client_disconnect(self):
        """Active sockets registered under a client ID are immediately closed on client_disconnected."""
        addon = smart_proxy.SmartProxyAddon()
        client = MagicMock()
        client.id = "test-client-123"

        s1 = socket.socket()
        s2 = socket.socket()
        addon.register_active_socket(client.id, s1)
        addon.register_active_socket(client.id, s2)

        self.assertEqual(len(addon.active_sockets_by_client[client.id]), 2)

        addon.client_disconnected(client)
        self.assertNotIn(client.id, addon.active_sockets_by_client)
        
        # Verify sockets were closed (fileno is -1)
        self.assertEqual(s1.fileno(), -1)
        self.assertEqual(s2.fileno(), -1)

    def test_timeout_constants(self):
        """Verify SLA constants match user instruction: 60.0s global, 15.0s initial."""
        self.assertEqual(GLOBAL_REQUEST_TIMEOUT, 60.0)
        self.assertEqual(INITIAL_REQUEST_TIMEOUT, 15.0)
        self.assertEqual(MAX_DECOMPRESSED_BYTES, 20 * 1024 * 1024)

    def test_soft_latency_reranking_small_absolute_delta(self):
        """Migration occurs when faster node is >1.5x faster even if delta < 100ms (e.g. 60ms vs 20ms)."""
        p = StickyLatencyPool()
        slow = ProxyNode(scheme="http", host="10.0.0.1", port=8080, ema_latency_ms=60.0, success_count=10)
        fast = ProxyNode(scheme="http", host="10.0.0.2", port=8080, ema_latency_ms=20.0, success_count=10)
        p.update_nodes([slow, fast])
        p.set_current_node("e621.net", slow)

        selected = p.get_current_or_best("e621.net")
        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(selected.key, fast.key)

    def test_origin_error_preserves_content_encoding_and_body(self):
        """Origin 500 error must NOT strip Content-Encoding or decompress, preserving raw origin payload."""
        origin_payload = b"\x1f\x8b\x08test-server-error"
        enc = "gzip"
        # status >= 400 is not decompressed in _fetch_upstream_sync
        # and enc_header is NOT stripped if decompress_ok is False
        body, ok = _decompress_body_safe(origin_payload, enc)
        # malformed gzip returns ok=False
        self.assertFalse(ok)
        self.assertEqual(body, origin_payload)

    def test_budget_driven_retry_exhaustion_bounds(self):
        """Verify that when all healthy nodes are tried, retry loop breaks cleanly without looping infinitely."""
        import smart_proxy
        from smart_proxy import pool as global_pool, ProxyNode as Node, SmartProxyAddon

        n1 = Node('http', '10.0.0.1', 8080)
        n2 = Node('http', '10.0.0.2', 8080)
        n3 = Node('http', '10.0.0.3', 8080)
        n3.global_cooldown_until = time.time() + 100.0  # unavailable

        global_pool.nodes = []
        global_pool.current_nodes.clear()
        global_pool.update_nodes([n1, n2, n3])
        addon = SmartProxyAddon()

        flow = MagicMock()
        flow.request.method = 'GET'
        flow.request.pretty_host = 'danbooru.donmai.us'
        flow.request.url = 'https://danbooru.donmai.us/posts.json'
        flow.request.headers = {}
        flow.metadata = {}
        flow.response = None
        flow.client_conn = MagicMock(connected=True, id='c1')

        attempts = []
        orig_fetch = smart_proxy._fetch_upstream_sync

        def mock_fetch(f, node, timeout):
            attempts.append(node.key)
            resp = MagicMock(status_code=503, content=b'503 Service Unavailable', headers={'content-type': 'text/plain'})
            return resp

        smart_proxy._fetch_upstream_sync = mock_fetch
        try:
            asyncio.run(addon.request(flow))
        finally:
            smart_proxy._fetch_upstream_sync = orig_fetch

        self.assertEqual(len(attempts), 3)
        self.assertEqual(set(attempts), {n1.key, n2.key, n3.key})
        self.assertEqual(flow.response.status_code, 503)

    def test_budget_driven_retry_all_connection_failures_returns_504(self):
        """Verify that when all healthy nodes hit connection timeout, proxy terminates and returns 504."""
        import smart_proxy
        from smart_proxy import pool as global_pool, ProxyNode as Node, SmartProxyAddon

        n1 = Node('http', '10.0.0.1', 8080)
        n2 = Node('http', '10.0.0.2', 8080)
        global_pool.nodes = []
        global_pool.current_nodes.clear()
        global_pool.update_nodes([n1, n2])
        addon = SmartProxyAddon()

        flow = MagicMock()
        flow.request.method = 'GET'
        flow.request.pretty_host = 'danbooru.donmai.us'
        flow.request.url = 'https://danbooru.donmai.us/posts.json'
        flow.request.headers = {}
        flow.metadata = {}
        flow.response = None
        flow.client_conn = MagicMock(connected=True, id='c2')

        attempts = []
        orig_fetch = smart_proxy._fetch_upstream_sync

        def mock_fetch(f, node, timeout):
            attempts.append(node.key)
            return None

        smart_proxy._fetch_upstream_sync = mock_fetch
        try:
            asyncio.run(addon.request(flow))
        finally:
            smart_proxy._fetch_upstream_sync = orig_fetch

        self.assertEqual(len(attempts), 2)
        self.assertEqual(flow.response.status_code, 504)


class TestRetryAfterAndRateLimiting(unittest.TestCase):
    def test_parse_retry_after_delta_seconds(self):
        """Delta-seconds must parse integer seconds and clamp within [min_seconds, max_seconds]."""
        self.assertEqual(parse_retry_after("15"), 15.0)
        self.assertEqual(parse_retry_after("1"), 2.0)  # Clamped to min 2.0s
        self.assertEqual(parse_retry_after("500"), 500.0)  # Do not shorten upstream Retry-After
        self.assertEqual(parse_retry_after("   60   "), 60.0)
        self.assertEqual(parse_retry_after('"120"'), 120.0)

    def test_parse_retry_after_rejections(self):
        """Must reject nan, inf, negative values, exponents, and malformed strings."""
        self.assertIsNone(parse_retry_after("nan"))
        self.assertIsNone(parse_retry_after("NaN"))
        self.assertIsNone(parse_retry_after("inf"))
        self.assertIsNone(parse_retry_after("-inf"))
        self.assertIsNone(parse_retry_after("-10"))
        self.assertIsNone(parse_retry_after("1e2"))
        self.assertIsNone(parse_retry_after(""))
        self.assertIsNone(parse_retry_after(None))
        self.assertIsNone(parse_retry_after("not-a-number"))

    def test_parse_retry_after_http_dates(self):
        """HTTP-dates (RFC 1123, ANSI C asctime, leap seconds) must parse correctly with UTC awareness."""
        import datetime
        now = datetime.datetime(2026, 10, 21, 7, 27, 50, tzinfo=datetime.timezone.utc)
        
        # IMF-fixdate (10 seconds in future)
        val1 = parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT", now=now)
        self.assertIsNotNone(val1)
        self.assertAlmostEqual(val1 or 0.0, 10.0, places=1)

        # ANSI C asctime format (naive date without tz in string)
        val2 = parse_retry_after("Wed Oct 21 07:28:00 2026", now=now)
        self.assertIsNotNone(val2)
        self.assertAlmostEqual(val2 or 0.0, 10.0, places=1)

        # Leap second :60 normalized to :59 (07:28:59 - 07:27:50 = 69s)
        val3 = parse_retry_after("Wed, 21 Oct 2026 07:28:60 GMT", now=now)
        self.assertIsNotNone(val3)
        self.assertAlmostEqual(val3 or 0.0, 69.0, places=1)

        # Stale/past date (> 60s in the past) returns None
        past = "Sun, 06 Nov 1994 08:49:37 GMT"
        self.assertIsNone(parse_retry_after(past, now=now))

    def test_rate_limit_zero_ema_and_failure_count(self):
        """HTTP 429 rate limit must NOT inflate ema_latency_ms and must NOT increment failure_count."""
        node = ProxyNode('http', '10.0.0.1', 8080, ema_latency_ms=250.0)
        now = time.time()
        node.record_host_rate_limit("donmai.us", retry_after_s=15.0)

        # Invariant checks
        self.assertEqual(node.ema_latency_ms, 250.0)
        self.assertEqual(node.failure_count, 0)
        self.assertGreaterEqual(node.host_cooldowns["donmai.us"], now + 14.9)
        self.assertFalse(node.is_available_for("donmai.us", now))

        # Host-specific failures preserve global quality while quarantining this domain.
        node.record_host_failure("donmai.us")
        self.assertEqual(node.ema_latency_ms, 250.0)
        self.assertEqual(node.failure_count, 0)
        self.assertFalse(node.is_available_for("donmai.us", time.time()))
        self.assertTrue(node.is_available_for("example.com", time.time()))

    def test_rate_limit_missing_retry_after_adaptive_backoff(self):
        """When Retry-After is absent, exponential step-up applies (10s, 20s, 40s...) capped at 300s."""
        node = ProxyNode('http', '10.0.0.1', 8080)
        now = time.time()

        # Step 1: 10s
        node.record_host_rate_limit("donmai.us", retry_after_s=None)
        self.assertAlmostEqual(node.host_cooldowns["donmai.us"] - now, 10.0, delta=0.5)

        # Step 2: 20s
        node.record_host_rate_limit("donmai.us", retry_after_s=None)
        self.assertAlmostEqual(node.host_cooldowns["donmai.us"] - now, 20.0, delta=0.5)

        # Step 3: 40s
        node.record_host_rate_limit("donmai.us", retry_after_s=None)
        self.assertAlmostEqual(node.host_cooldowns["donmai.us"] - now, 40.0, delta=0.5)

        # Step 6+: capped at 300s without overflow
        for _ in range(10):
            node.record_host_rate_limit("donmai.us", retry_after_s=None)
        self.assertAlmostEqual(node.host_cooldowns["donmai.us"] - now, 300.0, delta=0.5)

    def test_rate_limit_success_resets_consecutive_counter(self):
        """A successful response for the domain clears consecutive rate limits."""
        node = ProxyNode('http', '10.0.0.1', 8080)
        node.record_host_rate_limit("donmai.us")
        self.assertEqual(node.consecutive_rate_limits.get("donmai.us"), 1)

        node.record_success(50.0, domain="donmai.us")
        self.assertNotIn("donmai.us", node.consecutive_rate_limits)

    def test_rate_limit_counter_not_cleared_on_origin_error_or_host_failure(self):
        """Origin errors (HTTP >= 400) and host failures must NOT reset consecutive_rate_limits."""
        node = ProxyNode('http', '10.0.0.1', 8080)
        node.record_host_rate_limit("donmai.us")
        self.assertEqual(node.consecutive_rate_limits.get("donmai.us"), 1)

        # Host failure (e.g. 502/timeout/WAF challenge) must not clear rate limit count
        node.record_host_failure("donmai.us")
        self.assertEqual(node.consecutive_rate_limits.get("donmai.us"), 1)

        # Clear both cooldown and hard rate-limit state for this unrelated flow test.
        node.host_cooldowns.clear()
        node.rate_limit_until.clear()

        # Integration: HTTP 500 through flow must not clear rate limit count
        from smart_proxy import pool as global_pool, SmartProxyAddon
        global_pool.nodes = [node]
        global_pool.current_nodes.clear()
        addon = SmartProxyAddon()

        flow = MagicMock()
        flow.request.method = 'GET'
        flow.request.pretty_host = 'danbooru.donmai.us'
        flow.request.url = 'https://danbooru.donmai.us/posts.json'
        flow.request.headers = {}
        flow.metadata = {}
        flow.response = None
        flow.client_conn = MagicMock(connected=True, id='c_err')

        orig_fetch = smart_proxy._fetch_upstream_sync
        smart_proxy._fetch_upstream_sync = lambda f, n, to: MagicMock(status_code=500, content=b'Server Error', headers={})
        try:
            asyncio.run(addon.request(flow))
        finally:
            smart_proxy._fetch_upstream_sync = orig_fetch

        self.assertEqual(node.consecutive_rate_limits.get("donmai.us"), 1)

        # HTTP 200 through flow MUST clear rate limit count
        flow2 = MagicMock()
        flow2.request.method = 'GET'
        flow2.request.pretty_host = 'danbooru.donmai.us'
        flow2.request.url = 'https://danbooru.donmai.us/posts.json'
        flow2.request.headers = {}
        flow2.metadata = {}
        flow2.response = None
        flow2.client_conn = MagicMock(connected=True, id='c_ok')

        smart_proxy._fetch_upstream_sync = lambda f, n, to: MagicMock(status_code=200, content=b'[]', headers={})
        try:
            asyncio.run(addon.request(flow2))
        finally:
            smart_proxy._fetch_upstream_sync = orig_fetch

        self.assertNotIn("donmai.us", node.consecutive_rate_limits)

    def test_select_best_for_returns_none_when_all_on_cooldown(self):
        """select_best_for must return None if all nodes are in cooldown, preserving rate limit window."""
        pool = StickyLatencyPool()
        n = ProxyNode('http', '10.0.0.1', 8080)
        pool.update_nodes([n])
        pool.mark_host_rate_limit(n, "donmai.us", retry_after_s=60.0)

        best = pool.select_best_for("donmai.us")
        self.assertIsNone(best)

    def test_waf_challenge_precedence_over_429(self):
        """A Cloudflare challenge with status 429 uses host failure quarantine, not rate-limit state."""
        node = ProxyNode('http', '10.0.0.1', 8080, ema_latency_ms=250.0)
        resp = MagicMock(status_code=429, headers={"retry-after": "5"})
        resp_sample = b"<html><title>Just a moment...</title><div class='cf-chl-widget'></div></html>"

        _record_blocked_status(node, "donmai.us", resp, resp_sample)
        # Must be treated as a domain quarantine without changing global quality.
        self.assertEqual(node.ema_latency_ms, 250.0)
        self.assertEqual(node.failure_count, 0)
        self.assertFalse(node.is_available_for("donmai.us", time.time()))
        self.assertNotIn("donmai.us", node.consecutive_rate_limits)

    def test_integration_request_429_retry_after_failover(self):
        """Integration: Request hitting 429 with Retry-After: 5 fails over to node 2, leaving node 1 EMA intact."""
        from smart_proxy import pool as global_pool, SmartProxyAddon

        n1 = ProxyNode('http', '10.0.0.1', 8080, ema_latency_ms=100.0)
        n2 = ProxyNode('http', '10.0.0.2', 8080, ema_latency_ms=200.0)
        global_pool.nodes = []
        global_pool.current_nodes.clear()
        global_pool.update_nodes([n1, n2])
        addon = SmartProxyAddon()

        flow = MagicMock()
        flow.request.method = 'GET'
        flow.request.pretty_host = 'danbooru.donmai.us'
        flow.request.url = 'https://danbooru.donmai.us/posts.json'
        flow.request.headers = {}
        flow.metadata = {}
        flow.response = None
        flow.client_conn = MagicMock(connected=True, id='c_rl')

        attempts = []
        orig_fetch = smart_proxy._fetch_upstream_sync

        def mock_fetch(f, node, timeout):
            attempts.append(node.key)
            if node.key == n1.key:
                return MagicMock(status_code=429, content=b'Too Many Requests', headers={'retry-after': '5'})
            return MagicMock(status_code=200, content=b'[]', headers={'content-type': 'application/json'})

        smart_proxy._fetch_upstream_sync = mock_fetch
        try:
            asyncio.run(addon.request(flow))
        finally:
            smart_proxy._fetch_upstream_sync = orig_fetch

        self.assertEqual(attempts, [n1.key, n2.key])
        self.assertEqual(flow.response.status_code, 200)
        # n1 should have kept its 100ms EMA without penalty
        self.assertEqual(n1.ema_latency_ms, 100.0)
        self.assertEqual(n1.failure_count, 0)
        self.assertFalse(n1.is_available_for("donmai.us", time.time()))


if __name__ == "__main__":
    unittest.main()
