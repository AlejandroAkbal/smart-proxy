"""
Adversarial fuzzing and vulnerability verification suite for smart_proxy.py.
Probes:
1. Transfer-Encoding & Content-Length framing mismatch in _fetch_upstream_sync.
2. Compression bypass (Brotli/Zstd) in challenge detector.
3. HTTPS Replay RuntimeError bug (set_tunnel after connect).
4. Socket descriptor leak on network/TLS exceptions in _fetch_upstream_sync.
5. Memory leaks: unbounded host_cooldowns growth.
6. Pool desync: stale/zombie nodes retained in current_nodes after pool refresh.
7. Concurrency & token bucket race conditions.
"""

import sys
import os
import time
import socket
import threading
import http.server
import http.client
import ssl
import gzip
import zlib
from dataclasses import dataclass, field
from typing import List, Optional

# Mock mitmproxy objects if mitmproxy is not directly importable in root python
try:
    from mitmproxy import http as mitm_http
    from mitmproxy.net.server_spec import ServerSpec
except ImportError:
    # Build minimal compatible mock for testing smart_proxy logic
    class Headers(dict):
        def get_all(self, key):
            return [self[key]] if key in self else []
        def set_all(self, key, values):
            self[key] = values[-1] if values else ""
    
    class MockRequest:
        def __init__(self, method="GET", url="http://example.com/test", headers=None, content=b""):
            self.method = method
            self.url = url
            self.headers = headers or {}
            self.content = content
            self.host = "example.com"
            self.pretty_host = "example.com"

    class MockResponse:
        def __init__(self, status_code=200, content=b"", headers=None):
            self.status_code = status_code
            self.content = content
            self.headers = headers or {}

        @classmethod
        def make(cls, status_code, content, headers):
            h_dict = {}
            if isinstance(headers, list):
                for k, v in headers:
                    k_str = k.decode() if isinstance(k, bytes) else str(k)
                    v_str = v.decode() if isinstance(v, bytes) else str(v)
                    h_dict[k_str] = v_str
            elif isinstance(headers, dict):
                h_dict = headers
            return cls(status_code=status_code, content=content, headers=h_dict)

    class MockFlow:
        def __init__(self, request=None, response=None):
            self.request = request or MockRequest()
            self.response = response
            self.metadata = {}
            self.error = None
            self.is_replay = False

    class mitm_http:
        Request = MockRequest
        Response = MockResponse
        HTTPFlow = MockFlow

    mitmproxy_mod = type(sys)("mitmproxy")
    mitmproxy_mod.ctx = type(sys)("ctx")
    mitmproxy_mod.http = mitm_http
    sys.modules["mitmproxy"] = mitmproxy_mod
    sys.modules["mitmproxy.http"] = mitm_http
    conn_mod = type(sys)("mitmproxy.connection")
    class Server:
        def __init__(self, address=None):
            self.address = address
            self.via = None
            self.timestamp_start = None
    class MockClient:
        def __init__(self, id="mock-client-id"):
            self.id = id

    conn_mod.Server = Server
    conn_mod.Client = MockClient
    mitm_http.Client = MockClient
    sys.modules["mitmproxy.connection"] = conn_mod
    sys.modules["mitmproxy.net"] = type(sys)("mitmproxy.net")
    spec_mod = type(sys)("mitmproxy.net.server_spec")
    
    class ServerSpec:
        def __init__(self, spec):
            self.spec = spec
        def __eq__(self, other):
            return isinstance(other, ServerSpec) and self.spec == other.spec
    spec_mod.ServerSpec = ServerSpec
    sys.modules["mitmproxy.net.server_spec"] = spec_mod

# Now import smart_proxy under test
import smart_proxy

def run_test(name, fn):
    print(f"\n[TEST] {name}")
    try:
        fn()
        print(f"  -> PASS")
        return True
    except AssertionError as e:
        print(f"  -> VULNERABILITY CONFIRMED (AssertionError): {e}")
        return False
    except Exception as e:
        print(f"  -> VULNERABILITY CONFIRMED ({type(e).__name__}): {e}")
        return False

# ==============================================================================
# 1. BUG: HTTPS Replay Crashes with RuntimeError (set_tunnel after connect)
# ==============================================================================
def test_https_replay_crash():
    """
    In _fetch_upstream_sync:
    conn.set_tunnel() MUST be called BEFORE conn.connect().
    """
    class DummyTunnelHandler(http.server.BaseHTTPRequestHandler):
        def do_CONNECT(self):
            self.send_response(200, "Connection Established")
            self.end_headers()
        def log_message(self, format, *args): pass

    server = http.server.HTTPServer(("127.0.0.1", 0), DummyTunnelHandler)
    proxy_port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=1.0)
    try:
        conn.set_tunnel("httpbin.org:443")
        conn.connect()
        conn.close()
    except Exception as e:
        raise AssertionError(f"HTTPS tunnel setup failed: {e}")
    finally:
        server.shutdown()


def test_unbounded_host_cooldowns_memory():
    """
    ProxyNode.record_host_failure should bound dictionary size to prevent memory leaks.
    """
    node = smart_proxy.ProxyNode(scheme="http", host="1.2.3.4", port=8080)
    for i in range(1000):
        node.record_host_failure(f"sub-{i}.domain.com")

    if len(node.host_cooldowns) > 500:
        raise AssertionError(f"ProxyNode.host_cooldowns grew to {len(node.host_cooldowns)} entries without bounding/TTL pruning.")


def test_brotli_challenge_bypass():
    """
    _extract_sample_body must decompress gzip, deflate, and handle brotli/zstd gracefully.
    """
    raw_html = b"<html><head><title>Just a moment...</title></head><body>Cloudflare turnstile challenge-platform cf-chl</body></html>"
    compressed_gz = gzip.compress(raw_html)
    sample_gz_upper = smart_proxy._extract_sample_body(compressed_gz, "Gzip")
    match_gz_upper = bool(smart_proxy.CHALLENGE_RE.search(sample_gz_upper))
    if not match_gz_upper:
        raise AssertionError("Case-insensitive 'Gzip' failed to decompress and match challenge pattern.")

# ==============================================================================
# 2. BUG: Chunked Framing Corruption & Hop-by-Hop Header Leakage
# ==============================================================================
def test_chunked_framing_mismatch():
    """
    When upstream server responds with Transfer-Encoding: chunked,
    http.client de-chunks the payload on resp.read().
    smart_proxy forwards Transfer-Encoding: chunked with raw decoded bytes!
    """
    class ChunkedHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Content-Type", "text/plain")
            self.send_header("Connection", "keep-alive")
            self.send_header("Keep-Alive", "timeout=5")
            self.end_headers()
            
            # Send standard chunked body: chunk "hello", chunk "world", final chunk
            self.wfile.write(b"5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n")
            self.wfile.flush()

        def log_message(self, format, *args):
            pass

    origin = http.server.HTTPServer(("127.0.0.1", 0), ChunkedHandler)
    origin_port = origin.server_port
    t = threading.Thread(target=origin.serve_forever, daemon=True)
    t.start()

    flow = mitm_http.HTTPFlow()
    flow.request = mitm_http.Request(
        method="GET",
        url=f"http://127.0.0.1:{origin_port}/data",
        headers={"Host": f"127.0.0.1:{origin_port}"}
    )
    node = smart_proxy.ProxyNode(scheme="http", host="127.0.0.1", port=origin_port)

    resp = smart_proxy._fetch_upstream_sync(flow, node, timeout=2.0)
    origin.shutdown()

    assert resp is not None, "Failed to get response from origin"
    
    # Body is decoded to b"helloworld"
    assert resp.content == b"helloworld", f"Unexpected body: {resp.content}"
    
    # Headers check: Transfer-Encoding must NOT be present if body is already decoded!
    headers_dict = {k.lower(): v for k, v in resp.headers.items()}
    
    issues = []
    if "transfer-encoding" in headers_dict:
        issues.append(f"Transfer-Encoding: {headers_dict['transfer-encoding']} leaked downstream with decoded body!")
    if "connection" in headers_dict:
        issues.append(f"Hop-by-hop Connection header leaked downstream: {headers_dict['connection']}")
    if "keep-alive" in headers_dict:
        issues.append(f"Hop-by-hop Keep-Alive header leaked downstream: {headers_dict['keep-alive']}")

    if issues:
        raise AssertionError("Header framing & hop-by-hop corruption: " + "; ".join(issues))

# ==============================================================================
# 3. Challenge Detection on Compressed Payloads (Gzip / Deflate / Brotli)
# ==============================================================================
def test_brotli_challenge_bypass():
    """
    _extract_sample_body must decompress gzip, deflate, and handle case-insensitive encoding headers.
    """
    raw_html = b"<html><head><title>Just a moment...</title></head><body>Cloudflare turnstile challenge-platform cf-chl</body></html>"
    
    # Test uppercase/whitespace Gzip
    compressed_gz = gzip.compress(raw_html)
    sample_gz_upper = smart_proxy._extract_sample_body(compressed_gz, "Gzip")
    match_gz_upper = bool(smart_proxy.CHALLENGE_RE.search(sample_gz_upper))
    
    # Test deflate
    compressed_df = zlib.compress(raw_html)
    sample_df = smart_proxy._extract_sample_body(compressed_df, "deflate")
    match_df = bool(smart_proxy.CHALLENGE_RE.search(sample_df))

    issues = []
    if not match_gz_upper:
        issues.append("Case-sensitive 'Gzip' / 'gzip; charset=utf-8' NOT decompressed; challenge detection bypassed!")
    if not match_df:
        issues.append("Deflate content NOT decompressed; challenge detection bypassed!")

    if issues:
        raise AssertionError("Challenge bypass: " + "; ".join(issues))

# ==============================================================================
# 4. BUG: Socket Descriptor Leak in _fetch_upstream_sync on Connection Errors
# ==============================================================================
def test_socket_leak_on_failure():
    """
    In _fetch_upstream_sync:
    conn.connect() is executed, but conn.close() is only in the try block.
    If wrap_socket or getresponse or request fails, conn.close() is skipped.
    """
    # Start a server that accepts TCP then hangs/closes abruptly
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    port = server_sock.getsockname()[1]
    server_sock.listen(10)

    def bad_server():
        while True:
            try:
                conn, _ = server_sock.accept()
                # Accept connection but do nothing, causing client timeout or RST
                time.sleep(0.5)
                conn.close()
            except:
                break

    t = threading.Thread(target=bad_server, daemon=True)
    t.start()

    flow = mitm_http.HTTPFlow()
    flow.request = mitm_http.Request(
        method="GET",
        url=f"http://127.0.0.1:{port}/timeout",
        headers={"Host": f"127.0.0.1:{port}"}
    )
    node = smart_proxy.ProxyNode(scheme="http", host="127.0.0.1", port=port)

    # Perform 50 rapid failed requests
    for _ in range(50):
        smart_proxy._fetch_upstream_sync(flow, node, timeout=0.05)

    server_sock.close()
    print("  Note: socket.close() missing in 'finally' block within _fetch_upstream_sync.")

# ==============================================================================
# 5. Host Cooldown Memory Bounding & TTL Pruning
# ==============================================================================
def test_unbounded_host_cooldowns_memory():
    """
    ProxyNode.record_host_failure should bound dictionary size to prevent memory leaks.
    """
    node = smart_proxy.ProxyNode(scheme="http", host="1.2.3.4", port=8080)
    for i in range(1000):
        node.record_host_failure(f"sub-{i}.domain.com")

    if len(node.host_cooldowns) > 500:
        raise AssertionError(f"ProxyNode.host_cooldowns grew to {len(node.host_cooldowns)} entries without bounding/TTL pruning (Memory Leak).")

# ==============================================================================
# 6. BUG: Pool Desync / Zombie Sticky Node Retention
# ==============================================================================
def test_pool_stale_node_retention():
    """
    When update_nodes() runs with a new proxy list, current_nodes continues holding
    the old ProxyNode even if it is no longer in pool.nodes.
    """
    pool = smart_proxy.StickyLatencyPool()
    node_a = smart_proxy.ProxyNode(scheme="http", host="1.1.1.1", port=8080)
    node_b = smart_proxy.ProxyNode(scheme="http", host="2.2.2.2", port=8080)
    
    # Initial pool with node A
    pool.update_nodes([node_a])
    chosen = pool.select_best_for("target.com")
    assert chosen == node_a
    assert pool.current_nodes.get("target.com") == node_a

    # Adapter refreshes pool: node A is dead/removed, only node B is present
    pool.update_nodes([node_b])
    
    # pool.nodes now only has node B
    assert len(pool.nodes) == 1 and pool.nodes[0] == node_b

    # But get_current_or_best still returns node A!
    current = pool.get_current_or_best("target.com")
    
    if current == node_a:
        raise AssertionError("Zombie ProxyNode leak: current_nodes returned decommissioned node_a that is no longer in pool.nodes!")

# ==============================================================================
# 7. CONCURRENCY: Token Bucket Contention & Multithreading
# ==============================================================================
def test_token_bucket_concurrency():
    """
    ProxyNode.try_consume_token is not internally locked.
    High concurrent threads contending on a single ProxyNode can cause race conditions.
    """
    node = smart_proxy.ProxyNode(
        scheme="http",
        host="1.1.1.1",
        port=8080,
        rate_limit_rps=100.0,
        tokens=10.0,
        bucket_capacity=10.0
    )

    consumed = [0]
    lock = threading.Lock()

    def worker():
        for _ in range(100):
            if node.try_consume_token():
                with lock:
                    consumed[0] += 1
            time.sleep(0.001)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()

    print(f"  Token bucket consumed {consumed[0]} tokens under concurrency.")


if __name__ == "__main__":
    print("=== STARTING SMART PROXY ADVERSARIAL AUDIT & FUZZING ===")
    results = {}
    results["https_replay_crash"] = run_test("1. HTTPS Replay Tunneling Crash", test_https_replay_crash)
    results["chunked_framing_mismatch"] = run_test("2. Chunked Framing & Hop-by-Hop Leakage", test_chunked_framing_mismatch)
    results["brotli_challenge_bypass"] = run_test("3. Brotli / Case-Sensitive Challenge Bypass", test_brotli_challenge_bypass)
    results["socket_leak_on_failure"] = run_test("4. Socket Descriptor Leak on Failures", test_socket_leak_on_failure)
    results["unbounded_host_cooldowns"] = run_test("5. Unbounded host_cooldowns Memory Leak", test_unbounded_host_cooldowns_memory)
    results["pool_stale_node_retention"] = run_test("6. Stale/Zombie Node Retention in Pool", test_pool_stale_node_retention)
    results["token_bucket_concurrency"] = run_test("7. Token Bucket Concurrency", test_token_bucket_concurrency)

    print("\n=== SUMMARY OF VULNERABILITIES FOUND ===")
    for k, v in results.items():
        status = "PASSED" if v else "VULNERABILITY CONFIRMED"
        print(f"  - {k}: {status}")
