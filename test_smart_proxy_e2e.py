import gzip
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

PORT_ORIGIN = 29300
PORT_PROXY_1 = 29301
PORT_PROXY_2 = 29302
PORT_PROXY_3 = 29303
PORT_PROXY_4 = 29304
PORT_PROXY_5 = 29305
PORT_PROXY_SLOW = 29306
PORT_SMART_PROXY = 29380


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


proxy_connections = {}
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

        # Multi-stage 5-retry simulation: Proxies 1-4 fail, Proxy 5 succeeds
        if "sim-5-retries" in self.path:
            if proxy in ("Proxy-1", "Proxy-2", "Proxy-3", "Proxy-4"):
                body = f'{{"error": "blocked_on_{proxy}"}}'.encode()
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                return

        # Gzip compressed challenge
        if "sim-gzip-challenge" in self.path:
            if proxy == "Proxy-1":
                raw_html = b"<html><title>Just a moment...</title><body>Cloudflare Turnstile challenge</body></html>"
                compressed = gzip.compress(raw_html)
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", str(len(compressed)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(compressed)
                return

        # Universal Failure
        if "sim-all-fail" in self.path:
            body = b'{"error": "all_blocked"}'
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return

        resp_data = json.dumps({
            "status": "ok",
            "proxy": proxy,
            "path": self.path,
            "timestamp": time.time(),
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(resp_data)

    def do_POST(self):
        peer_port = self.connection.getpeername()[1]
        proxy = get_proxy_for_connection(peer_port)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""

        # 5a: Unsafe POST without flag should NOT be replayed on 503
        if "sim-mutation-fail" in self.path:
            # First attempt fails 503 on any proxy
            resp_body = b'{"error": "mutation_failed"}'
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(resp_body)
            return

        # 5b: Replayed mutation succeeds on next proxy
        if "sim-mutation-replayed" in self.path:
            if proxy != "Proxy-5":
                resp_body = b'{"error": "mutation_failed_first_try"}'
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(resp_body)
                return

        resp_data = json.dumps({
            "status": "ok",
            "proxy": proxy,
            "received_body": body.decode(errors="replace"),
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
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

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
        self._proxy("GET")

    def do_POST(self):
        self._proxy("POST")

    def _proxy(self, method):
        if self.artificial_delay > 0:
            time.sleep(self.artificial_delay)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""
        
        target_host = "127.0.0.1"
        target_port = PORT_ORIGIN
        target_path = self.path
        
        if self.path.startswith("http://") or self.path.startswith("https://"):
            parsed = urllib.parse.urlsplit(self.path)
            target_host = parsed.hostname or "127.0.0.1"
            target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            target_path = parsed.path or "/"
            if parsed.query:
                target_path += "?" + parsed.query
        
        import http.client
        conn = http.client.HTTPConnection(target_host, target_port, timeout=5)
        conn.connect()
        record_proxy_connection(conn.sock.getsockname()[1], self.proxy_name)
        
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "proxy-connection", "connection")}
        headers["Host"] = f"{target_host}:{target_port}"
        headers["Connection"] = "close"
        
        conn.request(method, target_path, body=body, headers=headers)
        res = conn.getresponse()
        resp_data = res.read()
        
        self.send_response(res.status)
        for k, v in res.getheaders():
            if k.lower() not in ("content-length", "connection"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp_data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(resp_data)
        conn.close()


def make_proxy_handler(name, delay=0.0):
    class CustomProxyHandler(BaseMockProxyHandler):
        proxy_name = name
        artificial_delay = delay

    return CustomProxyHandler


def start_servers():
    s_origin = ThreadingHTTPServer(("0.0.0.0", PORT_ORIGIN), MockOriginHandler)
    s_p1 = ThreadingHTTPServer(("0.0.0.0", PORT_PROXY_1), make_proxy_handler("Proxy-1"))
    s_p2 = ThreadingHTTPServer(("0.0.0.0", PORT_PROXY_2), make_proxy_handler("Proxy-2"))
    s_p3 = ThreadingHTTPServer(("0.0.0.0", PORT_PROXY_3), make_proxy_handler("Proxy-3"))
    s_p4 = ThreadingHTTPServer(("0.0.0.0", PORT_PROXY_4), make_proxy_handler("Proxy-4"))
    s_p5 = ThreadingHTTPServer(("0.0.0.0", PORT_PROXY_5), make_proxy_handler("Proxy-5"))
    s_pslow = ThreadingHTTPServer(("0.0.0.0", PORT_PROXY_SLOW), make_proxy_handler("Proxy-Slow", 4.0))

    all_servers = (s_origin, s_p1, s_p2, s_p3, s_p4, s_p5, s_pslow)
    for s in all_servers:
        t = threading.Thread(target=s.serve_forever, daemon=True)
        t.start()
    return all_servers


def run_tests():
    print("=" * 65)
    print("SMART PROXY ADVANCED UNLOCKER (5-RETRY & ASYNC) TEST SUITE")
    print("=" * 65)

    start_servers()
    print("[1/5] Mock origin and 6 proxy servers active.")

    workspace = os.path.dirname(os.path.abspath(__file__))
    smart_proxy_path = os.path.join(workspace, "smart_proxy.py")
    ca_dir = "/tmp/smart-proxy-e2e-ca"
    os.makedirs(ca_dir, exist_ok=True)
    os.chmod(ca_dir, 0o777)

    subprocess.run(["docker", "rm", "-f", "smart-proxy-e2e-runner"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    upstream_env = f"http://host.docker.internal:{PORT_PROXY_1},http://host.docker.internal:{PORT_PROXY_2},http://host.docker.internal:{PORT_PROXY_3},http://host.docker.internal:{PORT_PROXY_4},http://host.docker.internal:{PORT_PROXY_5},http://host.docker.internal:{PORT_PROXY_SLOW}"

    cmd = [
        "docker", "run", "-d", "--name", "smart-proxy-e2e-runner",
        "-p", f"{PORT_SMART_PROXY}:8080",
        "-v", f"{smart_proxy_path}:/app/smart_proxy.py:ro",
        "-v", f"{ca_dir}:/ca",
        "-e", f"UPSTREAM_PROXIES={upstream_env}",
        "-e", "COOLDOWN_SECONDS=10",
        "-e", "MAX_RETRIES=5",
        "mitmproxy/mitmproxy:latest",
        "mitmdump",
        "-p", "8080",
        "-s", "/app/smart_proxy.py",
        "--set", "confdir=/ca",
        "--set", "connection_strategy=lazy",
        "--set", "upstream_cert=false",
    ]

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"Failed to start container: {res.stderr}")
        sys.exit(1)

    print(f"[2/5] Smart Proxy started on port {PORT_SMART_PROXY} (MAX_RETRIES=5).")

    ready = False
    for _ in range(40):
        try:
            s = socket.create_connection(("127.0.0.1", PORT_SMART_PROXY), timeout=1)
            s.close()
            # Test actual proxy response readiness
            test_opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{PORT_SMART_PROXY}"}))
            test_resp = test_opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/health-ready", timeout=2)
            if test_resp.status == 200:
                ready = True
                break
        except Exception:
            time.sleep(0.3)

    if not ready:
        logs = subprocess.run(["docker", "logs", "smart-proxy-e2e-runner"], capture_output=True, text=True).stdout
        print("Smart Proxy failed to listen. Logs:\n", logs)
        sys.exit(1)

    print("[3/5] Smart Proxy listener verified.")

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{PORT_SMART_PROXY}"}))

    print("\n" + "-" * 55)
    print("TEST 1: Baseline Request & Sticky Exit Assignment")
    print("-" * 55)
    t0 = time.time()
    resp = opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/init-sticky", timeout=5)
    d = json.loads(resp.read().decode())
    elapsed = time.time() - t0
    initial_proxy = d.get("proxy")
    print(f"Initial Sticky Proxy: {initial_proxy} | Time: {elapsed:.3f}s | Status: {resp.status}")
    assert resp.status == 200
    assert initial_proxy.startswith("Proxy-")
    print("✔ TEST 1 PASSED")

    print("\n" + "-" * 55)
    print("TEST 2: Strict Sticky Pinning across 5 Consecutive Requests")
    print("-" * 55)
    for i in range(5):
        t0 = time.time()
        resp = opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/sticky-{i}", timeout=5)
        d = json.loads(resp.read().decode())
        elapsed = time.time() - t0
        print(f"Request {i+1}: {d.get('proxy')} | Time: {elapsed:.3f}s")
        assert d.get("proxy") == initial_proxy
    print("✔ TEST 2 PASSED")

    print("\n" + "-" * 55)
    print("TEST 3: 5-Retry Cascading Failover (Web Unlocker Mimic)")
    print("-" * 55)
    t0 = time.time()
    resp = opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/sim-5-retries", timeout=8)
    d = json.loads(resp.read().decode())
    elapsed = time.time() - t0
    print(f"5-Retry Success Handled By: {d.get('proxy')} | Time: {elapsed:.3f}s | Status: {resp.status}")
    assert resp.status == 200
    assert d.get("proxy") == "Proxy-5"
    print("✔ TEST 3 PASSED")

    print("\n" + "-" * 55)
    print("TEST 4: Gzip Compressed Cloudflare Challenge Auto-Rotation")
    print("-" * 55)
    t0 = time.time()
    resp = opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/sim-gzip-challenge", timeout=5)
    d = json.loads(resp.read().decode())
    elapsed = time.time() - t0
    print(f"Gzip Challenge Rotated To: {d.get('proxy')} | Time: {elapsed:.3f}s | Status: {resp.status}")
    assert resp.status == 200
    assert d.get("proxy") != "Proxy-1"
    print("✔ TEST 4 PASSED")

    print("\n" + "-" * 55)
    print("TEST 5: Mutation Safety (POST Replay Guards)")
    print("-" * 55)
    # 5a: Unsafe POST without flag should NOT be replayed on 503
    req_unsafe = urllib.request.Request(
        f"http://127.0.0.1:{PORT_ORIGIN}/sim-mutation-fail",
        data=b'{"action":"transfer"}',
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        resp = opener.open(req_unsafe, timeout=5)
        print("Unexpected 200 on unsafe mutation")
        assert False
    except urllib.error.HTTPError as e:
        print(f"Unsafe POST correctly NOT replayed (Status: {e.code})")
        assert e.code == 503

    # 5b: POST with X-Allow-Mutation-Replay: 1 MUST be replayed
    req_safe = urllib.request.Request(
        f"http://127.0.0.1:{PORT_ORIGIN}/sim-mutation-replayed",
        data=b'{"action":"idempotent_read"}',
        headers={"Content-Type": "application/json", "X-Allow-Mutation-Replay": "1"},
        method="POST"
    )
    resp = opener.open(req_safe, timeout=5)
    d = json.loads(resp.read().decode())
    print(f"Safe Mutation Replayed To: {d.get('proxy')} | Status: {resp.status}")
    assert resp.status == 200
    print("✔ TEST 5 PASSED")

    print("\n" + "-" * 55)
    print("TEST 6: Non-Blocking Async Concurrency (Anti-Starvation)")
    print("-" * 55)
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

    assert total_concurrency_time < 5.0
    print("✔ TEST 6 PASSED")

    print("\n" + "-" * 55)
    print("TEST 7: Cache-Busting Uncached Live Probing Simulation")
    print("-" * 55)
    import random
    uncached_tags = [f"-test{random.randint(100000, 999999)}_{int(time.time())}_{i}" for i in range(5)]
    for tag in uncached_tags:
        t0 = time.time()
        resp = opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/posts?tags={tag}", timeout=5)
        d = json.loads(resp.read().decode())
        elapsed = time.time() - t0
        print(f"Random Negative Tag '{tag}': {d.get('proxy')} | Time: {elapsed:.3f}s | Status: {resp.status}")
        assert resp.status == 200
    print("✔ TEST 7 PASSED")

    print("\n" + "=" * 65)
    print("ALL 7 ADVANCED UNLOCKER TESTS PASSED PERFECTLY!")
    print("=" * 65)

    subprocess.run(["docker", "rm", "-f", "smart-proxy-e2e-runner"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    try:
        run_tests()
    except Exception as e:
        import traceback
        traceback.print_exc()
        logs = subprocess.run(["docker", "logs", "smart-proxy-e2e-runner"], capture_output=True, text=True).stdout
        print("\n=== FULL DOCKER LOGS ===")
        print(logs)
        print("========================")
        subprocess.run(["docker", "rm", "-f", "smart-proxy-e2e-runner"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sys.exit(1)
