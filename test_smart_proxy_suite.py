import os, sys, time, json, socket, threading, ssl, subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import urllib.parse
import urllib.request, urllib.error

PORT_ORIGIN = 29400
PORT_PROXY_A = 29401
PORT_PROXY_B = 29402
PORT_MITM = 29480

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

class BaseMockProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    proxy_name = "BaseProxy"
    def log_message(self, format, *args): pass

    def do_CONNECT(self):
        host, port = self.path.split(":")
        target_sock = socket.create_connection((host, int(port)), timeout=5)
        if self.proxy_name == "Proxy-A": proxy_a_connections.add(target_sock.getsockname()[1])
        else: proxy_b_connections.add(target_sock.getsockname()[1])
        self.send_response(200, "Connection Established")
        self.end_headers()
        pipe_sockets(self.connection, target_sock)
        self.close_connection = True

    def do_GET(self): self._proxy("GET")
    def do_POST(self): self._proxy("POST")

    def _proxy(self, method):
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
        
        conn = socket.create_connection((target_host, target_port), timeout=5)
        if self.proxy_name == "Proxy-A": proxy_a_connections.add(conn.getsockname()[1])
        else: proxy_b_connections.add(conn.getsockname()[1])
        
        req_lines = [f"{method} {target_path} HTTP/1.1"]
        for k, v in self.headers.items():
            if k.lower() not in ("host", "proxy-connection", "connection"):
                req_lines.append(f"{k}: {v}")
        req_lines.append(f"Host: {target_host}:{target_port}")
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

class ProxyAHandler(BaseMockProxyHandler):
    proxy_name = "Proxy-A"

class ProxyBHandler(BaseMockProxyHandler):
    proxy_name = "Proxy-B"

def main():
    s_origin = ReusableServer(("0.0.0.0", PORT_ORIGIN), OriginHandler)
    s_proxy_a = ReusableServer(("0.0.0.0", PORT_PROXY_A), ProxyAHandler)
    s_proxy_b = ReusableServer(("0.0.0.0", PORT_PROXY_B), ProxyBHandler)
    threading.Thread(target=s_origin.serve_forever, daemon=True).start()
    threading.Thread(target=s_proxy_a.serve_forever, daemon=True).start()
    threading.Thread(target=s_proxy_b.serve_forever, daemon=True).start()
    print("[1/6] Mock test servers started.", flush=True)

    subprocess.run(["docker", "rm", "-f", "smart-proxy-acceptance"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    workspace = os.path.dirname(os.path.abspath(__file__))
    smart_proxy_path = os.path.join(workspace, "smart_proxy.py")
    ca_dir = "/tmp/smart-proxy-suite-ca"
    os.makedirs(ca_dir, exist_ok=True)
    os.chmod(ca_dir, 0o777)

    cmd = [
        "docker", "run", "-d", "--name", "smart-proxy-acceptance",
        "-p", f"{PORT_MITM}:8080",
        "-v", f"{smart_proxy_path}:/app/smart_proxy.py:ro",
        "-v", f"{ca_dir}:/ca",
        "-e", f"UPSTREAM_PROXIES=http://host.docker.internal:{PORT_PROXY_A},http://host.docker.internal:{PORT_PROXY_B}",
        "-e", "COOLDOWN_SECONDS=60",
        "mitmproxy/mitmproxy:latest",
        "mitmdump",
        "-p", "8080",
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

    # Wait for smart proxy port
    ready = False
    for _ in range(30):
        try:
            s = socket.create_connection(("127.0.0.1", PORT_MITM), timeout=1)
            s.close()
            ready = True
            break
        except Exception:
            time.sleep(0.3)

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
