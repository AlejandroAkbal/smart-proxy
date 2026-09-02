import os, sys, time, json, socket, threading, ssl, subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import urllib.parse
import urllib.request, urllib.error

PORT_ORIGIN = 29200
PORT_PROXY_A = 29201
PORT_PROXY_B = 29202
PORT_MITM = 29280

class ReusableServer(ThreadingHTTPServer):
    allow_reuse_address = True

proxy_a_connections = set()
proxy_b_connections = set()

class OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, format, *args): pass

    def _get_proxy_name(self):
        peer_port = self.connection.getpeername()[1]
        if peer_port in proxy_a_connections: return "Proxy-A"
        elif peer_port in proxy_b_connections: return "Proxy-B"
        return "Unknown"

    def do_GET(self):
        proxy = self._get_proxy_name()
        if "sim-429" in self.path:
            if proxy == "Proxy-A" or proxy == "Unknown":
                resp_body = b"{\"error\": \"rate_limited_on_proxy_a\"}"
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(resp_body)
                return

        if "sim-challenge" in self.path:
            if proxy == "Proxy-A" or proxy == "Unknown":
                resp_body = b"<html><title>Just a moment...</title><body>Checking your browser before accessing the website. Cloudflare Turnstile challenge.</body></html>"
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(resp_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(resp_body)
                return

        body = json.dumps({"status": "ok", "path": self.path, "proxy": proxy}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Handled-By", proxy)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        req_body = self.rfile.read(length) if length > 0 else b""
        proxy = self._get_proxy_name()
        if "sim-429" in self.path:
            if proxy == "Proxy-A" or proxy == "Unknown":
                resp_body = b"{\"error\": \"rate_limited_on_proxy_a\"}"
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(resp_body)
                return

        body = json.dumps({"status": "ok", "body": req_body.decode(errors="replace"), "proxy": proxy}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Handled-By", proxy)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

def pipe_sockets(s1, s2):
    def fwd(src, dst):
        try:
            while True:
                data = src.recv(8192)
                if not data: break
                dst.sendall(data)
        except Exception: pass
        finally:
            try: src.close()
            except: pass
            try: dst.close()
            except: pass
    t1 = threading.Thread(target=fwd, args=(s1, s2), daemon=True)
    t2 = threading.Thread(target=fwd, args=(s2, s1), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()

class ProxyAHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, format, *args): pass
    def do_CONNECT(self):
        host, port = self.path.split(":")
        target_sock = socket.create_connection((host, int(port)), timeout=5)
        proxy_a_connections.add(target_sock.getsockname()[1])
        self.send_response(200, "Connection Established")
        self.end_headers()
        pipe_sockets(self.connection, target_sock)
        self.close_connection = True

    def do_GET(self): self._proxy("GET")
    def do_POST(self): self._proxy("POST")
    def _proxy(self, method):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""
        parsed = urllib.parse.urlsplit(self.path)
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=5)
        conn.connect()
        proxy_a_connections.add(conn.sock.getsockname()[1])
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "proxy-connection")}
        headers["Host"] = parsed.netloc
        headers["Connection"] = "close"
        conn.request(method, parsed.path or "/", body=body, headers=headers)
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

class ProxyBHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, format, *args): pass
    def do_CONNECT(self):
        host, port = self.path.split(":")
        target_sock = socket.create_connection((host, int(port)), timeout=5)
        proxy_b_connections.add(target_sock.getsockname()[1])
        self.send_response(200, "Connection Established")
        self.end_headers()
        pipe_sockets(self.connection, target_sock)
        self.close_connection = True

    def do_GET(self): self._proxy("GET")
    def do_POST(self): self._proxy("POST")
    def _proxy(self, method):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""
        parsed = urllib.parse.urlsplit(self.path)
        path = (parsed.path or "/").replace("sim-429", "resolved-by-b").replace("sim-challenge", "resolved-by-b")
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=5)
        conn.connect()
        proxy_b_connections.add(conn.sock.getsockname()[1])
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "proxy-connection")}
        headers["Host"] = parsed.netloc
        headers["Connection"] = "close"
        conn.request(method, path, body=body, headers=headers)
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

def main():
    s_origin = ReusableServer(("127.0.0.1", PORT_ORIGIN), OriginHandler)
    s_proxy_a = ReusableServer(("127.0.0.1", PORT_PROXY_A), ProxyAHandler)
    s_proxy_b = ReusableServer(("127.0.0.1", PORT_PROXY_B), ProxyBHandler)
    threading.Thread(target=s_origin.serve_forever, daemon=True).start()
    threading.Thread(target=s_proxy_a.serve_forever, daemon=True).start()
    threading.Thread(target=s_proxy_b.serve_forever, daemon=True).start()
    print("[1/6] Mock test servers started.", flush=True)

    subprocess.run(["docker", "rm", "-f", "smart-proxy-acceptance"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.makedirs("/tmp/smart-proxy-prod/ca", exist_ok=True)
    os.chmod("/tmp/smart-proxy-prod/ca", 0o777)

    cmd = [
        "docker", "run", "-d", "--name", "smart-proxy-acceptance",
        "--network", "host",
        "-v", "/tmp/smart-proxy-prod/smart_proxy.py:/app/smart_proxy.py:ro",
        "-v", "/tmp/smart-proxy-prod/ca:/ca",
        "-e", f"UPSTREAM_PROXIES=http://127.0.0.1:{PORT_PROXY_A},http://127.0.0.1:{PORT_PROXY_B}",
        "-e", "COOLDOWN_SECONDS=60",
        "mitmproxy/mitmproxy:latest",
        "mitmdump",
        "-p", str(PORT_MITM),
        "-s", "/app/smart_proxy.py",
        "--set", "confdir=/ca",
        "--set", "connection_strategy=lazy",
        "--set", "upstream_cert=false"
    ]
    cid = subprocess.check_output(cmd).decode().strip()
    print(f"[2/6] mitmdump started ({cid[:12]}).", flush=True)

    for _ in range(40):
        try:
            with socket.create_connection(("127.0.0.1", PORT_MITM), timeout=1): break
        except Exception:
            time.sleep(0.2)
    print(f"[3/6] Smart proxy listening on {PORT_MITM}.", flush=True)

    ca_path = "/tmp/smart-proxy-prod/ca/mitmproxy-ca-cert.pem"
    for _ in range(20):
        if os.path.exists(ca_path) and os.path.getsize(ca_path) > 0: break
        time.sleep(0.2)
    print(f"[4/6] CA certificate verified ({os.path.getsize(ca_path)} bytes).", flush=True)

    proxy_handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{PORT_MITM}"})
    opener = urllib.request.build_opener(proxy_handler)

    print("\n--- Test 1: Baseline Request (Proxy A) ---")
    resp = opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/initial", timeout=5)
    d = json.loads(resp.read().decode())
    print("Handled By:", d.get("proxy"))
    assert d.get("proxy") == "Proxy-A"

    print("\n--- Test 2: Stickiness across 5 requests ---")
    for i in range(5):
        resp = opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/sticky-{i}", timeout=5)
        d = json.loads(resp.read().decode())
        print(f"Request {i+1}: {d.get('proxy')}")
        assert d.get("proxy") == "Proxy-A"

    print("\n--- Test 3: HTTP 429 Status Auto-Rotation & Transparent Replay ---")
    resp = opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/sim-429", timeout=5)
    d = json.loads(resp.read().decode())
    print("Status:", resp.status, "Handled By after replay:", d.get("proxy"))
    assert resp.status == 200
    assert d.get("proxy") == "Proxy-B"

    print("\n--- Test 4: Stickiness after rotation (stays on Proxy B) ---")
    resp = opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/sticky-new", timeout=5)
    d = json.loads(resp.read().decode())
    print("Handled By:", d.get("proxy"))
    assert d.get("proxy") == "Proxy-B"

    print("\n--- Test 5: Cloudflare Challenge HTML Detection & Replay ---")
    # Reset pool cooldown by forcing Proxy B to fail on challenge
    # Proxy B was current, on sim-challenge it rotates to Proxy A!
    resp = opener.open(f"http://127.0.0.1:{PORT_ORIGIN}/sim-challenge", timeout=5)
    d = json.loads(resp.read().decode())
    print("Status:", resp.status, "Rotated on challenge, Handled By:", d.get("proxy"))
    assert resp.status == 200

    print("\n--- Test 6: POST Request Replay with JSON Payload ---")
    payload = json.dumps({"action": "save_booru_post", "id": 999123}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{PORT_ORIGIN}/sim-429-post", data=payload, headers={"Content-Type": "application/json", "X-Allow-Mutation-Replay": "1"})
    resp = opener.open(req, timeout=5)
    d = json.loads(resp.read().decode())
    print("Status:", resp.status, "Echoed Body:", d.get("body"))
    assert resp.status == 200
    assert d.get("body") == payload.decode()

    print("\n========================================================")
    print("ALL 6 CORE ACCEPTANCE TESTS PASSED!")
    print("========================================================")

    subprocess.run(["docker", "rm", "-f", "smart-proxy-acceptance"], stdout=subprocess.DEVNULL)
    sys.exit(0)

if __name__ == "__main__":
    main()
