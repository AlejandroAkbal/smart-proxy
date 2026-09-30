import asyncio
import socket
import threading
import time
import unittest
from unittest.mock import MagicMock

# Reuse the repository's mitmproxy compatibility bootstrap before importing smart_proxy.
import test_smart_proxy_resilience_v2  # noqa: F401

import smart_proxy


class ConnectServer:
    def __init__(self, after_connect):
        self.after_connect = after_connect
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.accepted = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            client, _ = self.sock.accept()
            self.accepted.set()
            with client:
                request = b""
                while b"\r\n\r\n" not in request:
                    chunk = client.recv(4096)
                    if not chunk:
                        return
                    request += chunk
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self.after_connect(client)
        finally:
            self.sock.close()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=2)


def make_flow(client_id="reliability-client"):
    flow = MagicMock()
    flow.request.method = "GET"
    flow.request.pretty_host = "destination.test"
    flow.request.url = "https://destination.test/resource"
    flow.request.headers = {}
    flow.request.content = b""
    flow.metadata = {}
    flow.response = None
    flow.client_conn = MagicMock(connected=True, id=client_id)
    return flow


class TestUpstreamFailureAttribution(unittest.TestCase):
    def setUp(self):
        self.old_nodes = smart_proxy.pool.nodes
        self.old_current = smart_proxy.pool.current_nodes
        smart_proxy.pool.nodes = []
        smart_proxy.pool.current_nodes = {}

    def tearDown(self):
        smart_proxy.pool.nodes = self.old_nodes
        smart_proxy.pool.current_nodes = self.old_current

    def test_real_connect_then_tls_failure_is_domain_scoped(self):
        server = ConnectServer(lambda client: None)
        try:
            node = smart_proxy.ProxyNode("http", "127.0.0.1", server.port)
            smart_proxy.pool.nodes = [node]
            flow = make_flow()

            asyncio.run(smart_proxy.SmartProxyAddon().request(flow))

            self.assertEqual(flow.response.status_code, 504)
            self.assertEqual(node.failure_count, 0)
            self.assertEqual(node.global_cooldown_until, 0.0)
            self.assertGreater(node.host_cooldowns["destination.test"], time.time())
        finally:
            server.close()

    def test_real_proxy_tcp_refusal_is_global(self):
        reserved = socket.socket()
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
        reserved.close()
        node = smart_proxy.ProxyNode("http", "127.0.0.1", port)
        smart_proxy.pool.nodes = [node]

        asyncio.run(smart_proxy.SmartProxyAddon().request(make_flow()))

        self.assertEqual(node.failure_count, 1)
        self.assertGreater(node.global_cooldown_until, time.time())

    def test_disconnect_closes_real_tunnel_without_penalizing_node(self):
        release = threading.Event()

        def hold(client):
            release.wait(2)

        server = ConnectServer(hold)
        addon = smart_proxy.SmartProxyAddon()
        node = smart_proxy.ProxyNode("http", "127.0.0.1", server.port)
        smart_proxy.pool.nodes = [node]
        flow = make_flow("disconnect-client")

        def disconnect():
            self.assertTrue(server.accepted.wait(1))
            flow.client_conn.connected = False
            addon.client_disconnected(flow.client_conn)
            release.set()

        thread = threading.Thread(target=disconnect)
        thread.start()
        try:
            asyncio.run(addon.request(flow))
        finally:
            release.set()
            thread.join(timeout=2)
            server.close()

        self.assertEqual(node.failure_count, 0)
        self.assertEqual(node.global_cooldown_until, 0.0)
        self.assertNotIn("destination.test", node.host_cooldowns)

    def test_failure_started_before_newer_success_cannot_requarantine(self):
        node = smart_proxy.ProxyNode("http", "127.0.0.1", 8080)
        attempt_generation = node.health_generation
        node.record_success(10.0, "destination.test")

        applied = smart_proxy.pool.mark_global_failed(
            node, expected_generation=attempt_generation
        )

        self.assertFalse(applied)
        self.assertEqual(node.failure_count, 0)
        self.assertEqual(node.global_cooldown_until, 0.0)

    def test_destination_failure_started_before_newer_success_cannot_requarantine(self):
        node = smart_proxy.ProxyNode("http", "127.0.0.1", 8080)
        attempt_generation = node.host_health_generations.get("destination.test", 0)
        node.record_success(10.0, "destination.test")

        applied = smart_proxy.pool.mark_host_failed(
            node, "destination.test", expected_generation=attempt_generation
        )

        self.assertFalse(applied)
        self.assertNotIn("destination.test", node.host_cooldowns)

    def test_unrelated_destination_success_does_not_hide_target_failure(self):
        node = smart_proxy.ProxyNode("http", "127.0.0.1", 8080)
        attempt_generation = node.host_health_generations.get("destination.test", 0)
        node.record_success(10.0, "other.test")

        applied = smart_proxy.pool.mark_host_failed(
            node, "destination.test", expected_generation=attempt_generation
        )

        self.assertTrue(applied)
        self.assertGreater(node.host_cooldowns["destination.test"], time.time())


if __name__ == "__main__":
    unittest.main()
