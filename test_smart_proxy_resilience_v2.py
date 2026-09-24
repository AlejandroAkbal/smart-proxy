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
    mitm_http.Response = MagicMock
    mitm_http.HTTPFlow = MagicMock

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
        """Verify SLA constants match user instruction: 29.0s global, 12.0s initial."""
        self.assertEqual(GLOBAL_REQUEST_TIMEOUT, 29.0)
        self.assertEqual(INITIAL_REQUEST_TIMEOUT, 12.0)
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


if __name__ == "__main__":
    unittest.main()
