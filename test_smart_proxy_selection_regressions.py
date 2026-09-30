import asyncio
import sys
import threading
import time
import types
import unittest
from unittest.mock import MagicMock, patch


try:
    import mitmproxy.http as mitm_http
except ImportError:
    mitmproxy = types.ModuleType("mitmproxy")
    sys.modules["mitmproxy"] = mitmproxy
    from test_mitmproxy_stubs import install_proxy_stack_stubs

    install_proxy_stack_stubs(mitmproxy)
    mitm_http = types.ModuleType("mitmproxy.http")
    sys.modules["mitmproxy.http"] = mitm_http

    class MockResponse:
        def __init__(self, status_code=200, content=b"", headers=None):
            self.status_code = status_code
            self.content = content
            self.headers = headers or {}

        @classmethod
        def make(cls, status_code, content=b"", headers=None):
            return cls(status_code, content, headers)

    mitm_http.Response = MockResponse
    mitm_http.HTTPFlow = MagicMock
    mitm_connection = types.ModuleType("mitmproxy.connection")
    mitm_connection.Client = MagicMock
    mitm_connection.Server = MagicMock
    sys.modules["mitmproxy.connection"] = mitm_connection
    mitm_net = types.ModuleType("mitmproxy.net")
    mitm_spec = types.ModuleType("mitmproxy.net.server_spec")
    mitm_spec.ServerSpec = MagicMock
    mitm_spec.parse = lambda value, scheme="http": value
    sys.modules["mitmproxy.net"] = mitm_net
    sys.modules["mitmproxy.net.server_spec"] = mitm_spec


import smart_proxy
from smart_proxy import ProxyNode, SmartProxyAddon, StickyLatencyPool


class TestSelectionRegressions(unittest.TestCase):
    class ControlledClock:
        def __init__(self, value=0.0):
            self.value = value
            self.lock = threading.Lock()

        def __call__(self):
            with self.lock:
                self.value += 0.0001
                return self.value

        def advance(self, seconds):
            with self.lock:
                self.value += seconds

    def make_flow(self, host="api.domain-a.test"):
        flow = MagicMock()
        flow.request.method = "GET"
        flow.request.pretty_host = host
        flow.request.url = f"https://{host}/resource"
        flow.request.headers = {}
        flow.metadata = {}
        flow.response = None
        flow.client_conn = MagicMock(connected=True, id="selection-regression")
        return flow

    def test_successful_fallback_records_only_full_attempt_latency(self):
        first = ProxyNode("http", "10.0.0.1", 8080, ema_latency_ms=100.0)
        second = ProxyNode("http", "10.0.0.2", 8080, ema_latency_ms=100.0)
        old_nodes = smart_proxy.pool.nodes
        old_current = smart_proxy.pool.current_nodes
        smart_proxy.pool.nodes = [first, second]
        smart_proxy.pool.current_nodes = {}
        flow = self.make_flow()
        observed = []
        clock = self.ControlledClock(100.0)

        def fetch(_flow, node, _timeout):
            if node.key == first.key:
                clock.advance(0.060)
                return MagicMock(status_code=503, content=b"unavailable", headers={})
            clock.advance(0.005)
            return MagicMock(status_code=200, content=b"ok", headers={})

        original_record_latency = smart_proxy.pool.record_latency

        def record_latency(node, duration_ms, domain=None):
            observed.append((node.key, duration_ms, domain))
            original_record_latency(node, duration_ms, domain)

        try:
            with patch.object(smart_proxy.time, "monotonic", side_effect=clock), patch.object(
                smart_proxy, "_fetch_upstream_sync", side_effect=fetch
            ), patch.object(smart_proxy.pool, "record_latency", side_effect=record_latency):
                asyncio.run(SmartProxyAddon().request(flow))
        finally:
            smart_proxy.pool.nodes = old_nodes
            smart_proxy.pool.current_nodes = old_current

        self.assertEqual(flow.response.status_code, 200)
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0][0], second.key)
        self.assertAlmostEqual(observed[0][1], 5.1, delta=1.0)

    def test_domain_failure_does_not_change_global_quality(self):
        node = ProxyNode("http", "10.0.0.1", 8080, ema_latency_ms=125.0, failure_count=4)
        node.record_host_failure("domain-a.test")

        self.assertEqual(node.ema_latency_ms, 125.0)
        self.assertEqual(node.failure_count, 4)
        self.assertFalse(node.is_available_for("domain-a.test", time.time()))
        self.assertTrue(node.is_available_for("domain-b.test", time.time()))

    def test_readmission_preserves_quality_and_active_global_quarantine(self):
        pool = StickyLatencyPool(history_retention_seconds=60.0, history_capacity=8)
        node = ProxyNode("http", "10.0.0.1", 8080, ema_latency_ms=77.0, success_count=9, failure_count=2)
        node.global_cooldown_until = time.time() + 30.0
        pool.update_nodes([node])
        pool.update_nodes([ProxyNode("http", "10.0.0.2", 8080)])
        pool.update_nodes([ProxyNode("http", "10.0.0.1", 8080, ema_latency_ms=5.0)])

        restored = pool.nodes[0]
        self.assertEqual(restored.ema_latency_ms, 77.0)
        self.assertEqual(restored.success_count, 9)
        self.assertEqual(restored.failure_count, 2)
        self.assertGreater(restored.global_cooldown_until, time.time())
        self.assertIsNone(pool.select_best_for("domain-b.test"))

    def test_readmission_does_not_bypass_active_retry_after(self):
        pool = StickyLatencyPool(history_retention_seconds=60.0, history_capacity=8)
        node = ProxyNode("http", "10.0.0.1", 8080, ema_latency_ms=88.0, success_count=5)
        pool.update_nodes([node])
        pool.mark_host_rate_limit(node, "domain-a.test", retry_after_s=30.0)
        pool.update_nodes([ProxyNode("http", "10.0.0.2", 8080)])
        pool.update_nodes([ProxyNode("http", "10.0.0.1", 8080, ema_latency_ms=5.0)])

        restored = pool.nodes[0]
        self.assertFalse(restored.is_available_for("domain-a.test", time.time()))
        self.assertTrue(restored.is_available_for("domain-b.test", time.time()))
        self.assertEqual(restored.ema_latency_ms, 88.0)

    def test_expired_quarantine_does_not_block_readmitted_node(self):
        pool = StickyLatencyPool(history_retention_seconds=60.0, history_capacity=8)
        node = ProxyNode("http", "10.0.0.1", 8080, ema_latency_ms=91.0, success_count=3)
        node.host_cooldowns["domain-a.test"] = time.time() - 1.0
        pool.update_nodes([node])
        pool.update_nodes([ProxyNode("http", "10.0.0.2", 8080)])
        pool.update_nodes([ProxyNode("http", "10.0.0.1", 8080)])

        restored = pool.nodes[0]
        self.assertTrue(restored.is_available_for("domain-a.test", time.time()))
        self.assertEqual(restored.ema_latency_ms, 91.0)

    def test_expired_retention_releases_history(self):
        clock = self.ControlledClock(100.0)
        pool = StickyLatencyPool(history_retention_seconds=5.0, history_capacity=8)
        node = ProxyNode("http", "10.0.0.1", 8080, ema_latency_ms=42.0, success_count=7)
        with patch.object(smart_proxy.time, "monotonic", side_effect=clock):
            pool.update_nodes([node])
            pool.update_nodes([ProxyNode("http", "10.0.0.2", 8080)])
            clock.advance(6.0)
            fresh = ProxyNode("http", "10.0.0.1", 8080, ema_latency_ms=333.0)
            pool.update_nodes([fresh])

        self.assertIs(pool.nodes[0], fresh)
        self.assertEqual(pool.nodes[0].ema_latency_ms, 333.0)
        self.assertEqual(pool.nodes[0].success_count, 0)

    def test_expired_retention_preserves_active_quarantine_deadline(self):
        monotonic = self.ControlledClock(100.0)
        wall = self.ControlledClock(1000.0)
        pool = StickyLatencyPool(history_retention_seconds=5.0, history_capacity=8)
        node = ProxyNode("http", "10.0.0.1", 8080)
        node.host_cooldowns["domain-a.test"] = 1030.0

        with patch.object(smart_proxy.time, "monotonic", side_effect=monotonic), patch.object(
            smart_proxy.time, "time", side_effect=wall
        ):
            pool.update_nodes([node])
            pool.update_nodes([ProxyNode("http", "10.0.0.2", 8080)])
            monotonic.advance(6.0)
            readmitted = ProxyNode("http", "10.0.0.1", 8080)
            pool.update_nodes([readmitted])

        self.assertGreaterEqual(readmitted.global_cooldown_until, 1030.0)

    def test_zero_capacity_preserves_active_quarantine_deadline(self):
        wall = self.ControlledClock(2000.0)
        pool = StickyLatencyPool(history_retention_seconds=60.0, history_capacity=0)
        node = ProxyNode("http", "10.0.0.1", 8080)
        node.global_cooldown_until = 2030.0

        with patch.object(smart_proxy.time, "time", side_effect=wall):
            pool.update_nodes([node])
            pool.update_nodes([ProxyNode("http", "10.0.0.2", 8080)])
            readmitted = ProxyNode("http", "10.0.0.1", 8080)
            pool.update_nodes([readmitted])

        self.assertGreaterEqual(readmitted.global_cooldown_until, 2030.0)

    def test_retained_history_is_bounded_under_churn(self):
        pool = StickyLatencyPool(history_retention_seconds=60.0, history_capacity=3)
        for index in range(10):
            pool.update_nodes([ProxyNode("http", f"10.0.0.{index}", 8080, success_count=1)])

        self.assertLessEqual(len(pool.retained_nodes), 3)
        self.assertNotIn("http://10.0.0.0:8080", pool.retained_nodes)
        self.assertIn("http://10.0.0.8:8080", pool.retained_nodes)

        evicted = ProxyNode("http", "10.0.0.0", 8080, ema_latency_ms=321.0)
        pool.update_nodes([evicted])
        self.assertIs(pool.nodes[0], evicted)
        self.assertEqual(pool.nodes[0].success_count, 0)

    def test_capacity_eviction_cannot_bypass_active_retry_after(self):
        pool = StickyLatencyPool(history_retention_seconds=60.0, history_capacity=1)
        first = ProxyNode("http", "10.0.0.1", 8080)
        second = ProxyNode("http", "10.0.0.2", 8080)
        pool.update_nodes([first])
        pool.mark_host_rate_limit(first, "domain-a.test", retry_after_s=30.0)
        pool.update_nodes([second])
        pool.mark_host_rate_limit(second, "domain-a.test", retry_after_s=30.0)
        pool.update_nodes([ProxyNode("http", "10.0.0.3", 8080)])

        readmitted = ProxyNode("http", "10.0.0.1", 8080)
        pool.update_nodes([readmitted])
        self.assertLessEqual(len(pool.retained_nodes), 1)
        self.assertIsNone(pool.select_best_for("domain-a.test"))
        self.assertGreater(readmitted.global_cooldown_until, time.time())


if __name__ == "__main__":
    unittest.main()
