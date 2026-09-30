import asyncio
import http.server
import io
import socket
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

import test_smart_proxy_resilience_v2  # noqa: F401 - installs local mitmproxy stubs

import smart_proxy


class LocalProxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.requests.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        self.do_GET()

    def log_message(self, *_args):
        pass


class TestPoolCapacity(unittest.TestCase):
    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), LocalProxy)
        self.server.requests = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.pool = smart_proxy.StickyLatencyPool()
        self.pool_patch = patch.object(smart_proxy, "pool", self.pool)
        self.pool_patch.start()
        self.addCleanup(self.pool_patch.stop)

    def node(self, **kwargs):
        return smart_proxy.ProxyNode("http", "127.0.0.1", self.server.server_port, **kwargs)

    def flow(self, method="GET", domain="destination.test"):
        flow = MagicMock()
        flow.request.method = method
        flow.request.pretty_host = domain
        flow.request.url = f"http://{domain}/resource"
        flow.request.headers = {}
        flow.request.content = b""
        flow.metadata = {}
        flow.response = None
        flow.client_conn = MagicMock(connected=True, id="capacity-client")
        return flow

    def test_fifteen_nodes_cooled_for_600_seconds_can_use_one_last_resort(self):
        node = self.node(ema_latency_ms=10.0)
        other_nodes = [
            smart_proxy.ProxyNode("http", "127.0.0.1", 40000 + index, ema_latency_ms=100.0 + index)
            for index in range(14)
        ]
        self.pool.update_nodes([node, *other_nodes])
        with patch.object(smart_proxy, "COOLDOWN_SECONDS", 600):
            for candidate in self.pool.nodes:
                self.pool.mark_global_failed(candidate)
            flow = self.flow()
            start = time.monotonic()
            asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 200)
        self.assertLess(time.monotonic() - start, 2.0)
        self.assertEqual(self.server.requests, ["http://destination.test/resource"])
        self.assertIs(flow.metadata["upstream_proxy"], node)

    def test_empty_tokens_do_not_bypass_bucket_and_request_waits_for_refill(self):
        node = self.node(rate_limit_rps=25.0, tokens=0.0, bucket_capacity=1.0)
        self.pool.update_nodes([node])
        self.pool.set_current_node("destination.test", node)
        self.assertIsNone(self.pool.get_current_or_best("destination.test"))
        self.assertIsNone(self.pool.select_candidate_for("destination.test"))

        flow = self.flow()
        start = time.monotonic()
        asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 200)
        self.assertGreaterEqual(time.monotonic() - start, 0.01)
        self.assertEqual(len(self.server.requests), 1)

    def test_rate_limit_and_retention_saturation_are_not_degraded_candidates(self):
        node = self.node()
        self.pool.update_nodes([node])
        self.pool.mark_host_rate_limit(node, "destination.test", retry_after_s=300)
        node.global_cooldown_until = time.time() + 600
        self.assertIsNone(self.pool.select_degraded_for("destination.test"))
        flow = self.flow()
        asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 504)
        self.assertEqual(self.server.requests, [])

        other = self.node()
        other.port += 1
        other.global_cooldown_until = time.time() + 600
        self.pool.update_nodes([other])
        self.pool.retention_saturated_until = time.time() + 300
        self.assertIsNone(self.pool.select_degraded_for("unrelated.test"))

    def test_rate_limit_is_not_shortened_by_later_failure_or_shorter_limit(self):
        node = self.node()
        self.pool.update_nodes([node])
        self.pool.mark_host_rate_limit(node, "destination.test", retry_after_s=300)
        original = node.host_cooldowns["destination.test"]
        self.pool.mark_host_failed(node, "destination.test")
        self.pool.mark_host_rate_limit(node, "destination.test", retry_after_s=2)
        self.assertGreaterEqual(node.host_cooldowns["destination.test"], original)
        self.assertIsNone(self.pool.select_degraded_for("destination.test"))

    def test_challenge_with_retry_after_is_hard_blocked_past_host_cooldown(self):
        node = self.node()
        self.pool.update_nodes([node])
        response = MagicMock(status_code=429, headers={"retry-after": "300"})
        smart_proxy._record_blocked_status(node, "destination.test", response, b"cf-chl")
        later = time.time() + 100
        self.assertEqual(node.consecutive_rate_limits, {})
        self.assertFalse(node.can_try_degraded("destination.test", later))
        self.assertIsNone(self.pool.select_degraded_for("destination.test"))

    def test_long_retry_after_is_never_clamped_to_shorter_deadline(self):
        self.assertEqual(smart_proxy.parse_retry_after("900"), 900.0)
        node = self.node()
        self.pool.update_nodes([node])
        self.pool.mark_host_rate_limit(node, "destination.test", retry_after_s=900)
        self.assertGreater(node.rate_limit_until["destination.test"], time.time() + 899)

    def test_day_long_retry_after_is_last_resort_without_changing_deadline(self):
        node = self.node()
        self.pool.update_nodes([node])
        self.pool.mark_host_rate_limit(node, "destination.test", retry_after_s=86400)
        deadline = node.rate_limit_until["destination.test"]
        host_deadline = node.host_cooldowns["destination.test"]
        self.assertFalse(node.is_available_for("destination.test", time.time()))
        self.assertIsNone(self.pool.select_candidate_for("destination.test"))

        flow = self.flow()
        asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 200)
        self.assertEqual(self.server.requests, ["http://destination.test/resource"])
        self.assertEqual(node.rate_limit_until["destination.test"], deadline)
        self.assertEqual(node.host_cooldowns["destination.test"], host_deadline)

    def test_short_retry_after_and_configured_escape_threshold_are_respected(self):
        node = self.node()
        self.pool.update_nodes([node])
        self.pool.mark_host_rate_limit(node, "destination.test", retry_after_s=299)
        flow = self.flow()
        asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 504)
        self.assertEqual(self.server.requests, [])

        self.pool.mark_host_rate_limit(node, "destination.test", retry_after_s=86400)
        with patch.object(smart_proxy, "RATE_LIMIT_ESCAPE_THRESHOLD_SECONDS", 90000):
            flow = self.flow()
            asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 504)
        self.assertEqual(self.server.requests, [])

    def test_escape_chooses_soonest_expiring_long_retry_after(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            refused_port = reserved.getsockname()[1]
        longer = smart_proxy.ProxyNode("http", "127.0.0.1", refused_port, ema_latency_ms=1.0)
        shorter = self.node(ema_latency_ms=500.0)
        self.pool.update_nodes([longer, shorter])
        self.pool.mark_host_rate_limit(longer, "destination.test", retry_after_s=86400)
        self.pool.mark_host_rate_limit(shorter, "destination.test", retry_after_s=3600)
        flow = self.flow()
        asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 200)
        self.assertIs(flow.metadata["upstream_proxy"], shorter)
        self.assertEqual(longer.failure_count, 0)
        self.assertEqual(self.server.requests, ["http://destination.test/resource"])

    def test_retry_chain_can_reach_untried_long_backoff_escape(self):
        class RateLimitResponse(LocalProxy):
            def do_GET(self):
                self.send_response(429)
                self.send_header("Retry-After", "86400")
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()

        first_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RateLimitResponse)
        first_server.requests = []
        first_thread = threading.Thread(target=first_server.serve_forever, daemon=True)
        first_thread.start()
        self.addCleanup(first_thread.join, 2)
        self.addCleanup(first_server.server_close)
        self.addCleanup(first_server.shutdown)
        first = smart_proxy.ProxyNode("http", "127.0.0.1", first_server.server_port, ema_latency_ms=1.0)
        escaped = self.node(ema_latency_ms=500.0)
        self.pool.update_nodes([first, escaped])
        self.pool.mark_host_rate_limit(escaped, "destination.test", retry_after_s=86400)
        deadline = escaped.rate_limit_until["destination.test"]

        flow = self.flow()
        asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 200)
        self.assertIs(flow.metadata["upstream_proxy"], escaped)
        self.assertEqual(self.server.requests, ["http://destination.test/resource"])
        self.assertEqual(escaped.rate_limit_until["destination.test"], deadline)

    def test_non_rate_limited_cooled_node_precedes_long_backoff_escape(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            refused_port = reserved.getsockname()[1]
        limited = smart_proxy.ProxyNode("http", "127.0.0.1", refused_port, ema_latency_ms=1.0)
        cooled = self.node(ema_latency_ms=500.0)
        self.pool.update_nodes([limited, cooled])
        self.pool.mark_host_rate_limit(limited, "destination.test", retry_after_s=86400)
        self.pool.mark_host_failed(cooled, "destination.test")
        flow = self.flow()
        asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 200)
        self.assertIs(flow.metadata["upstream_proxy"], cooled)
        self.assertEqual(limited.failure_count, 0)

    def test_global_quarantine_and_retention_saturation_exclude_escape(self):
        node = self.node()
        self.pool.update_nodes([node])
        self.pool.mark_host_rate_limit(node, "destination.test", retry_after_s=86400)
        deadline = node.rate_limit_until["destination.test"]
        self.pool.retention_saturated_until = time.time() + 600
        flow = self.flow()
        asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 504)

        self.pool.retention_saturated_until = 0.0
        node.global_cooldown_until = time.time() + 600
        flow = self.flow()
        asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 504)
        self.assertEqual(self.server.requests, [])
        self.assertEqual(node.rate_limit_until["destination.test"], deadline)

    def test_long_backoff_escape_still_waits_for_its_token(self):
        node = self.node(rate_limit_rps=25.0, tokens=0.0, bucket_capacity=1.0)
        self.pool.update_nodes([node])
        self.pool.mark_host_rate_limit(node, "destination.test", retry_after_s=86400)
        flow = self.flow()
        start = time.monotonic()
        asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 200)
        self.assertGreaterEqual(time.monotonic() - start, 0.01)
        self.assertEqual(len(self.server.requests), 1)

    def test_long_backoff_escape_does_not_preempt_healthy_token_wait(self):
        healthy = self.node(rate_limit_rps=0.05, tokens=0.0, bucket_capacity=1.0)
        long_backoff = smart_proxy.ProxyNode("http", "127.0.0.1", self.server.server_port + 1)
        self.pool.update_nodes([healthy, long_backoff])
        self.pool.mark_host_rate_limit(long_backoff, "destination.test", retry_after_s=86400)
        flow = self.flow()
        start = time.monotonic()
        with patch.object(smart_proxy, "GLOBAL_REQUEST_TIMEOUT", 1.2):
            asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 504)
        self.assertLess(time.monotonic() - start, 1.5)
        self.assertEqual(self.server.requests, [])
        self.assertEqual(long_backoff.failure_count, 0)

    def test_unsafe_post_never_replays_to_long_backoff_escape(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            refused_port = reserved.getsockname()[1]
        refused = smart_proxy.ProxyNode("http", "127.0.0.1", refused_port, ema_latency_ms=1.0)
        escaped = self.node(ema_latency_ms=500.0)
        self.pool.update_nodes([refused, escaped])
        self.pool.mark_host_rate_limit(escaped, "destination.test", retry_after_s=86400)
        flow = self.flow(method="POST")
        asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 504)
        self.assertEqual(refused.failure_count, 1)
        self.assertEqual(self.server.requests, [])

    def test_tried_node_is_not_replayed_during_degraded_fallback(self):
        node = self.node()
        self.pool.update_nodes([node])
        self.pool.mark_global_failed(node)
        self.assertIsNone(self.pool.select_degraded_for("destination.test", exclude_keys={node.key}))

    def test_failed_proxy_falls_back_to_untried_cooled_live_proxy(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            refused_port = reserved.getsockname()[1]
        refused = smart_proxy.ProxyNode("http", "127.0.0.1", refused_port, ema_latency_ms=10.0)
        cooled = self.node(ema_latency_ms=100.0)
        self.pool.update_nodes([refused, cooled])
        with patch.object(smart_proxy, "COOLDOWN_SECONDS", 600):
            self.pool.mark_global_failed(cooled)
            flow = self.flow()
            asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 200)
        self.assertEqual(refused.failure_count, 1)
        self.assertEqual(self.server.requests, ["http://destination.test/resource"])

    def test_unsafe_post_does_not_replay_to_cooled_live_proxy(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            refused_port = reserved.getsockname()[1]
        refused = smart_proxy.ProxyNode("http", "127.0.0.1", refused_port, ema_latency_ms=10.0)
        cooled = self.node(ema_latency_ms=100.0)
        self.pool.update_nodes([refused, cooled])
        self.pool.mark_global_failed(cooled)
        flow = self.flow(method="POST")
        asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 504)
        self.assertEqual(refused.failure_count, 1)
        self.assertEqual(self.server.requests, [])

    def test_token_wait_stops_at_global_deadline(self):
        node = self.node(rate_limit_rps=0.05, tokens=0.0, bucket_capacity=1.0)
        self.pool.update_nodes([node])
        flow = self.flow()
        start = time.monotonic()
        with patch.object(smart_proxy, "GLOBAL_REQUEST_TIMEOUT", 1.2):
            asyncio.run(smart_proxy.SmartProxyAddon().request(flow))
        self.assertEqual(flow.response.status_code, 504)
        self.assertLess(time.monotonic() - start, 1.5)
        self.assertEqual(self.server.requests, [])

    def test_bounded_rate_limit_history_preserves_evicted_deadlines(self):
        node = self.node()
        self.pool.update_nodes([node])
        for index in range(501):
            self.pool.mark_host_rate_limit(node, f"domain-{index}.test", retry_after_s=300)
        self.assertLessEqual(len(node.rate_limit_until), 500)
        self.assertGreater(node.rate_limit_saturated_until, time.time())
        self.assertIsNone(self.pool.select_degraded_for("domain-0.test"))

    def test_refresh_does_not_admit_unverified_node_as_normal(self):
        previous = self.node()
        self.pool.update_nodes([previous])
        verified = smart_proxy.ProxyNode("http", "127.0.0.1", self.server.server_port + 1)
        self.pool.update_nodes([verified])
        self.assertEqual([node.key for node in self.pool.nodes], [verified.key])
        self.assertIn(previous.key, self.pool.retained_nodes)

    def test_partial_probe_result_controls_active_supply_not_retention(self):
        previously_verified = self.node()
        passing = smart_proxy.ProxyNode("http", "127.0.0.1", self.server.server_port + 1)
        self.pool.update_nodes([previously_verified, passing])
        proxy_urls = f"{previously_verified.key},{passing.key}"
        with patch.object(smart_proxy, "UPSTREAM_PROXIES_ENV", proxy_urls), patch.object(
            smart_proxy, "ADAPTER_URL", "http://local-fixture.invalid"
        ), patch.object(smart_proxy.urllib.request, "urlopen", side_effect=lambda *_args, **_kwargs: io.BytesIO(b"")), patch.object(
            smart_proxy, "_probe_node", side_effect=lambda node: node if node.key == passing.key else None
        ):
            smart_proxy._refresh_from_sources()
        self.assertEqual([node.key for node in self.pool.nodes], [passing.key])
        self.assertIn(previously_verified.key, self.pool.retained_nodes)


if __name__ == "__main__":
    unittest.main()
