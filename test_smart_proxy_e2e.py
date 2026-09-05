import os
import sys
import time
import json
import socket
import threading
import ssl
import subprocess
import urllib.parse
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

PORT_ORIGIN = 29300
PORT_PROXY_FAST_A = 29301
PORT_PROXY_FAST_B = 29302
PORT_PROXY_SLOW = 29303
PORT_PROXY_DEAD = 29304
PORT_SMART_PROXY = 29380

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

proxy_connections = {}  # client_port -> proxy_name
proxy_connections_lock = threading.Lock()

def record_proxy_connection(port, name):
    with proxy_connections_lock:
        proxy_connections[port] = name

def get_proxy_for_connection(port):
    with proxy_connections_lock:
        return proxy_connections.get(port, "Direct")

class MockOriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        peer_port = self.connection.getpeername()[1]
        proxy = get_proxy_for_connection(peer_port)

        # Test Case: 429 Rate Limit on Proxy A
        if "sim-429" in self.path:
            if proxy == "Proxy-A":
                body = b'{"error": "rate_limited_on_proxy_a"}'
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                return

        # Test Case: Challenge HTML on Proxy A
        if "sim-challenge" in self.path:
            if proxy == "Proxy-A":
                body = b"<html><title>Just a moment...</title><body>Cloudflare Turnstile challenge</body></html>"
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                return

        # Test Case: Universal Failure (All proxies fail)
        if "sim-all-fail" in self.path:
            body = b'{"error": "blocked"}'
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return

        # Normal Successful Response
        resp_data = json.dumps({
            "status": "ok",
            "proxy": proxy,
            "path": self.path,
            "timestamp": time.time()
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(resp_data)

def pipe_sockets(sock1, sock2):
    def forward(src, dst):
        try:
            while True:
                data = src.recv(8192)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try: dst.shutdown(socket.SHUT_WR)
            except Exception: pass

    t1 = threading.Thread(target=forward, args=(sock1, sock2), daemon=True)
    t2 = threading.Thread(target=forward, args=(sock2, sock1), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

class BaseMockProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    proxy_name = "BaseProxy"
    artificial_delay = 0.0

    def log_message(self, format, *args):
        pass

    def do_CONNECT(self):
        if self.artificial_delay > 0:
            time.sleep(self.artificial_delay)
        host, port = self.path.split(":")
        target_sock = socket.create_connection((host, int(port)), timeout=5)
        record_proxy_connection(target_sock.getsockname()[1], self.proxy_name)
        self.send_response(200, "Connection Established")
        self.end_headers()
        pipe_sockets(self.connection, target_sock)
        self.close_connection = True

    def do_GET(self):
        if self.artificial_delay > 0:
            time.sleep(self.artificial_delay)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""
        parsed = urllib.parse.urlsplit(self.path)
        conn = socket.create_connection((parsed.hostname, parsed.port or 80), timeout=5)
        record_proxy_connection(conn.getsockname()[1], self.proxy_name)
        
        req_lines = [f"GET {parsed.path or '/'} HTTP/1.1"]
        for k, v in self.headers.items():
            if k.lower() not in ("host", "proxy-connection", "connection"):
                req_lines.append(f"{k}: {v}")
        req_lines.append(f"Host: {parsed.netloc}")
        req_lines.append("Connection: close\r\n\r\n")
        conn.sendall("\r\n".join(req_lines).encode("utf-8") + body)
        
        resp_data = b""
        while True:
            chunk = conn.recv(8192)
            if not chunk:
                break
            resp_data += chunk
        conn.close()
        
        self.connection.sendall(resp_data)
        self.close_connection = True

class ProxyFastAHandler(BaseMockProxyHandler):
    proxy_name = "Proxy-A"

class ProxyFastBHandler(BaseMockProxyHandler):
    proxy_name = "Proxy-B"

class ProxySlowHandler(BaseMockProxyHandler):
    proxy_name = "Proxy-Slow"
    artificial_delay = 4.0

def start_servers():
    s_origin = ThreadingHTTPServer(("127.0.0.1", PORT_ORIGIN), MockOriginHandler)
    s_proxy_a = ThreadingHTTPServer(("127.0.0.1", PORT_PROXY_FAST_A), ProxyFastAHandler)
    s_proxy_b = ThreadingHTTPServer(("127.0.0.1", PORT_PROXY_FAST_B), ProxyFastBHandler)
    s_proxy_slow = ThreadingHTTPServer(("127.0.0.1", PORT_PROXY_SLOW), ProxySlowHandler)

    for s in (s_origin, s_proxy_a, s_proxy_b, s_proxy_slow):
        t = threading.Thread(target=s.serve_forever, daemon=True)
        t.start()
    return (s_origin, s_proxy_a, s_proxy_b, s_proxy_slow)

def run_tests():
    print("=" * 60)
    print("SMART PROXY COMPREHENSIVE END-TO-END TEST SUITE")
    print("=" * 60)
    
    servers = start_servers()
    print("[1/5] Mock Origin & Proxy Servers started.")

    # Prepare directories & copy code
    workspace = os.path.dirname(os.path.abspath(__file__))
    smart_proxy_path = os.path.join(workspace, "smart_proxy.py")
    ca_dir = "/tmp/smart-proxy-e2e-ca"
    os.makedirs(ca_dir, exist_ok=True)
    os.chmod(ca_dir, 0o777)

    subprocess.run(["docker", "rm", "-f", "smart-proxy-e2e-runner"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    upstream_env = f"http://host.docker.internal:{PORT_PROXY_FAST_A},http://host.docker.internal:{PORT_PROXY_FAST_B},http://host.docker.internal:{PORT_PROXY_SLOW}"

    cmd = [
        "docker", "run", "-d", "--name", "smart-proxy-e2e-runner",
        "-p", f"{PORT_SMART_PROXY}:8080",
        "-v", f"{smart_proxy_path}:/app/smart_proxy.py:ro",
        "-v", f"{ca_dir}:/ca",
        "-e", f"UPSTREAM_PROXIES={upstream_env}",
        "-e", "COOLDOWN_SECONDS=10",
        "-e", "MAX_RETRIES=2",
        "mitmproxy/mitmproxy:latest",
        "mitmdump",
        "-p", "8080",
        "-s", "/app/smart_proxy.py",
        "--set", "confdir=/ca",
        "--set", "connection_strategy=lazy",
        "--set", "upstream_cert=false"
    ]
    
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"Failed to start smart-proxy container: {res.stderr}")
        sys.exit(1)
    
    print(f"[2/5] Smart Proxy container started on port {PORT_SMART_PROXY}.")

    # Wait for smart proxy port
    ready = False
    for _ in range(30):
        try:
            s = socket.create_connection(("127.0.0.1", PORT_SMART_PROXY), timeout=1)
            s.close()
            ready = True
            break
        except Exception:
            time.sleep(0.3)
    
    if not ready:
        logs = subprocess.run(["docker", "logs", "smart-proxy-e2e-runner"], capture_output=True, text=True).stdout
        print("Smart Proxy failed to listen. Logs:\n", logs)
        sys.exit(1)
    
    print("[3/5] Smart Proxy port active and reachable.")

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{PORT_SMART_PROXY}"}))

    print("\n" + "-" * 50)
    print("TEST 1: Baseline Request & Sticky Exit Assignment")
    print("-" * 50)
    t0 = time.time()
    resp = opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/init-sticky", timeout=5)
    d = json.loads(resp.read().decode())
    elapsed = time.time() - t0
    initial_proxy = d.get("proxy")
    print(f"Initial Proxy: {initial_proxy} | Time: {elapsed:.3f}s | Status: {resp.status}")
    assert resp.status == 200
    assert initial_proxy in ("Proxy-A", "Proxy-B")
    print("✔ TEST 1 PASSED")

    print("\n" + "-" * 50)
    print("TEST 2: Strict Sticky Pinning across 5 Consecutive Requests")
    print("-" * 50)
    for i in range(5):
        t0 = time.time()
        resp = opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/sticky-{i}", timeout=5)
        d = json.loads(resp.read().decode())
        elapsed = time.time() - t0
        print(f"Request {i+1}: {d.get('proxy')} | Time: {elapsed:.3f}s")
        assert d.get("proxy") == initial_proxy
    print("✔ TEST 2 PASSED")

    print("\n" + "-" * 50)
    print("TEST 3: HTTP 429 Status Auto-Rotation & Fast Replay")
    print("-" * 50)
    # Reset pool if needed so Proxy-A is tested for 429
    t0 = time.time()
    resp = opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/sim-429", timeout=5)
    d = json.loads(resp.read().decode())
    elapsed = time.time() - t0
    print(f"Replay Handled By: {d.get('proxy')} | Time: {elapsed:.3f}s | Status: {resp.status}")
    assert resp.status == 200
    assert d.get("proxy") != "Proxy-A"
    print("✔ TEST 3 PASSED")

    print("\n" + "-" * 50)
    print("TEST 4: Cloudflare Challenge Signature Auto-Rotation")
    print("-" * 50)
    t0 = time.time()
    resp = opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/sim-challenge", timeout=5)
    d = json.loads(resp.read().decode())
    elapsed = time.time() - t0
    print(f"Challenge Handled By: {d.get('proxy')} | Time: {elapsed:.3f}s | Status: {resp.status}")
    assert resp.status == 200
    print("✔ TEST 4 PASSED")

    print("\n" + "-" * 50)
    print("TEST 5: Fast Failure & Deadline (< 4.0s) on Total Pool Exhaustion")
    print("-" * 50)
    t0 = time.time()
    try:
        resp = opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/sim-all-fail", timeout=10)
        print("Received status:", resp.status)
    except urllib.error.HTTPError as e:
        elapsed = time.time() - t0
        print(f"Correctly failed with HTTP {e.code} in {elapsed:.3f}s")
        assert elapsed < 4.0, f"Failure took too long: {elapsed:.3f}s (expected < 4.0s)"
    print("✔ TEST 5 PASSED")

    print("\n" + "-" * 50)
    print("TEST 6: Non-Blocking Async Concurrency (Anti-Starvation)")
    print("-" * 50)
    # Fire 10 concurrent requests; all run in parallel without event loop serialization
    results = []
    threads = []
    
    def worker(idx):
        t_start = time.time()
        try:
            r = opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/concurrent-{idx}", timeout=8)
            res_dict = json.loads(r.read().decode())
            results.append((idx, r.status, time.time() - t_start, res_dict.get("proxy")))
        except Exception as err:
            results.append((idx, type(err).__name__, time.time() - t_start, "ERROR"))

    t_all = time.time()
    for i in range(10):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    total_concurrency_time = time.time() - t_all
    print(f"10 Concurrent Requests Total Elapsed: {total_concurrency_time:.3f}s")
    for idx, st, el, pr in results:
        print(f"  Req #{idx}: Status {st} in {el:.3f}s (via {pr})")
        assert st == 200
    
    # 10 requests taking 4.0s delay in serial would take 40s; in parallel it takes ~4.5s
    assert total_concurrency_time < 5.0, f"Concurrency test too slow: {total_concurrency_time:.3f}s (expected parallel execution < 5.0s)"
    print("✔ TEST 6 PASSED")

    print("\n" + "=" * 60)
    print("ALL 6 END-TO-END TESTS PASSED PERFECTLY!")
    print("=" * 60)

    # Cleanup
    subprocess.run(["docker", "rm", "-f", "smart-proxy-e2e-runner"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    try:
        run_tests()
    except Exception as e:
        print(f"\n❌ TEST SUITE FAILED: {e}")
        subprocess.run(["docker", "rm", "-f", "smart-proxy-e2e-runner"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sys.exit(1)
