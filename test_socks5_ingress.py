import base64
import contextlib
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


AUTH = "test-user:test-password"
IMAGE = "smart-proxy-socks5-test"
CONTAINER = "smart-proxy-socks5-test"
HTTP_PORT = 29480
SOCKS_PORT = 29481
ORIGIN_HTTP_PORT = 29400
ORIGIN_HTTPS_PORT = 29443
UPSTREAM_PORT = 29401
RAW_PORT = 29402


def recv_exact(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return data


def recv_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def recv_all(sock):
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk


def socks_connect(username=None, password=None, host="test.local", port=ORIGIN_HTTP_PORT):
    sock = socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=5)
    sock.settimeout(5)
    methods = b"\x02" if username is not None else b"\x00"
    sock.sendall(b"\x05\x01" + methods)
    method_reply = recv_exact(sock, 2)
    if username is None or method_reply != b"\x05\x02":
        return sock, method_reply
    user = username.encode()
    secret = (password or "").encode()
    sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(secret)]) + secret)
    auth_reply = recv_exact(sock, 2)
    if auth_reply != b"\x01\x00":
        return sock, auth_reply
    encoded_host = host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(encoded_host)]) + encoded_host + port.to_bytes(2, "big"))
    return sock, recv_exact(sock, 10)


def fragmented_tls_request(sock, context, split_after, path):
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname="test.local")

    with contextlib.suppress(ssl.SSLWantReadError):
        tls.do_handshake()
    client_hello = outgoing.read()
    if len(client_hello) <= split_after:
        raise AssertionError("OpenSSL did not produce a complete ClientHello")

    sock.sendall(client_hello[:split_after])
    time.sleep(0.2)
    sock.sendall(client_hello[split_after:])

    while True:
        try:
            tls.do_handshake()
            break
        except ssl.SSLWantReadError:
            pending = outgoing.read()
            if pending:
                sock.sendall(pending)
            encrypted = sock.recv(65536)
            if not encrypted:
                raise ConnectionError("SOCKS connection closed during fragmented TLS handshake")
            incoming.write(encrypted)

    pending = outgoing.read()
    if pending:
        sock.sendall(pending)

    request = f"GET {path} HTTP/1.1\r\nHost: test.local:{ORIGIN_HTTPS_PORT}\r\nConnection: close\r\n\r\n".encode()
    tls.write(request)
    sock.sendall(outgoing.read())

    response = b""
    while True:
        try:
            response += tls.read(65536)
        except ssl.SSLWantReadError:
            encrypted = sock.recv(65536)
            if not encrypted:
                break
            incoming.write(encrypted)
        except ssl.SSLZeroReturnError:
            break
    return response


class OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        body = json.dumps({"path": self.path, "host": self.headers.get("Host")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def pipe(left, right):
    def copy(source, destination):
        try:
            while data := source.recv(65536):
                destination.sendall(data)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                destination.shutdown(socket.SHUT_WR)

    threads = [
        threading.Thread(target=copy, args=(left, right), daemon=True),
        threading.Thread(target=copy, args=(right, left), daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


class UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    @staticmethod
    def destination(host, port):
        return ("127.0.0.1" if host == "test.local" else host, port)

    def do_CONNECT(self):
        host, raw_port = self.path.rsplit(":", 1)
        target = socket.create_connection(self.destination(host, int(raw_port)), timeout=5)
        self.send_response(200, "Connection Established")
        self.end_headers()
        try:
            pipe(self.connection, target)
        finally:
            target.close()
        self.close_connection = True

    def do_GET(self):
        parsed = __import__("urllib.parse").parse.urlsplit(self.path)
        host = parsed.hostname or "test.local"
        port = parsed.port or 80
        conn = http.client.HTTPConnection(*self.destination(host, port), timeout=5)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        conn.request("GET", path, headers={"Host": self.headers.get("Host", host), "Connection": "close"})
        response = conn.getresponse()
        body = response.read()
        self.send_response(response.status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        conn.close()


class RawServer:
    def __init__(self):
        self.accepted = threading.Event()
        self.received = b""
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", RAW_PORT))
        self.sock.listen()

    def start(self):
        def run():
            self.sock.settimeout(8)
            try:
                conn, _ = self.sock.accept()
                self.accepted.set()
                conn.settimeout(1)
                with contextlib.suppress(OSError):
                    self.received = conn.recv(4096)
                conn.close()
            except OSError:
                pass

        threading.Thread(target=run, daemon=True).start()

    def close(self):
        self.sock.close()


class Socks5IngressWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("docker") or not shutil.which("openssl"):
            raise unittest.SkipTest("docker and openssl are required")
        cls.tempdir = tempfile.mkdtemp(prefix="smart-proxy-socks5-")
        cert = os.path.join(cls.tempdir, "origin.crt")
        key = os.path.join(cls.tempdir, "origin.key")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=test.local", "-addext", "subjectAltName=DNS:test.local", "-keyout", key, "-out", cert],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cls.http_origin = ThreadingHTTPServer(("0.0.0.0", ORIGIN_HTTP_PORT), OriginHandler)
        cls.https_origin = ThreadingHTTPServer(("0.0.0.0", ORIGIN_HTTPS_PORT), OriginHandler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        cls.https_origin.socket = tls.wrap_socket(cls.https_origin.socket, server_side=True)
        cls.upstream = ThreadingHTTPServer(("0.0.0.0", UPSTREAM_PORT), UpstreamHandler)
        for server in (cls.http_origin, cls.https_origin, cls.upstream):
            threading.Thread(target=server.serve_forever, daemon=True).start()

        subprocess.run(["docker", "build", "-t", IMAGE, "."], check=True)
        subprocess.run(["docker", "rm", "-f", CONTAINER], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(
            [
                "docker", "run", "-d", "--name", CONTAINER,
                "-p", f"{HTTP_PORT}:8080", "-p", f"{SOCKS_PORT}:1080",
                "-v", f"{cls.tempdir}:/ca",
                "-e", f"PROXY_AUTH={AUTH}",
                "-e", f"UPSTREAM_PROXIES=http://host.docker.internal:{UPSTREAM_PORT}",
                IMAGE,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=1) as ready_sock:
                    ready_sock.sendall(b"\x05\x01\x00")
                    if recv_exact(ready_sock, 2) == b"\x05\xff":
                        break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError("SOCKS listener did not start")
        ca_file = os.path.join(cls.tempdir, "mitmproxy-ca-cert.pem")
        deadline = time.time() + 10
        while time.time() < deadline and not os.path.exists(ca_file):
            time.sleep(0.1)
        if not os.path.exists(ca_file):
            raise RuntimeError("mitmproxy CA was not generated")

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["docker", "rm", "-f", CONTAINER], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for server in (cls.http_origin, cls.https_origin, cls.upstream):
            server.shutdown()
            server.server_close()
        shutil.rmtree(cls.tempdir)

    def test_missing_credentials_are_rejected(self):
        sock, reply = socks_connect()
        self.addCleanup(sock.close)
        self.assertEqual(reply, b"\x05\xff")

    def test_wrong_credentials_are_rejected(self):
        sock, reply = socks_connect("test-user", "wrong")
        self.addCleanup(sock.close)
        self.assertEqual(reply, b"\x01\x01")

    def test_correct_credentials_allow_http(self):
        sock, reply = socks_connect("test-user", "test-password")
        self.addCleanup(sock.close)
        self.assertEqual(reply[:2], b"\x05\x00")
        sock.sendall(b"GET /socks-http HTTP/1.1\r\nHost: test.local:%d\r\nConnection: close\r\n\r\n" % ORIGIN_HTTP_PORT)
        response = recv_all(sock)
        self.assertIn(b"200 OK", response)
        self.assertIn(b"/socks-http", response)

    def test_socks5h_https_uses_interception_ca(self):
        sock, reply = socks_connect("test-user", "test-password", port=ORIGIN_HTTPS_PORT)
        self.assertEqual(reply[:2], b"\x05\x00")
        context = ssl.create_default_context(cafile=os.path.join(self.tempdir, "mitmproxy-ca-cert.pem"))
        tls_sock = context.wrap_socket(sock, server_hostname="test.local")
        self.addCleanup(tls_sock.close)
        tls_sock.sendall(b"GET /socks-https HTTP/1.1\r\nHost: test.local:%d\r\nConnection: close\r\n\r\n" % ORIGIN_HTTPS_PORT)
        response = recv_all(tls_sock)
        self.assertIn(b"200 OK", response)
        self.assertIn(b"/socks-https", response)

    def test_fragmented_tls_client_hello_is_buffered(self):
        context = ssl.create_default_context(cafile=os.path.join(self.tempdir, "mitmproxy-ca-cert.pem"))
        for split_after in (1, 2):
            with self.subTest(split_after=split_after):
                sock, reply = socks_connect("test-user", "test-password", port=ORIGIN_HTTPS_PORT)
                self.assertEqual(reply[:2], b"\x05\x00")
                try:
                    response = fragmented_tls_request(sock, context, split_after, f"/fragmented-tls-{split_after}")
                finally:
                    sock.close()
                self.assertIn(b"200 OK", response)
                self.assertIn(f"/fragmented-tls-{split_after}".encode(), response)

    def test_existing_authenticated_http_ingress(self):
        conn = http.client.HTTPConnection("127.0.0.1", HTTP_PORT, timeout=5)
        token = base64.b64encode(AUTH.encode()).decode()
        conn.request("GET", f"http://test.local:{ORIGIN_HTTP_PORT}/regular-http", headers={"Proxy-Authorization": f"Basic {token}"})
        response = conn.getresponse()
        body = response.read()
        conn.close()
        self.assertEqual(response.status, 200)
        self.assertIn(b"/regular-http", body)

    def test_non_http_socks_payload_is_not_forwarded(self):
        raw = RawServer()
        raw.start()
        self.addCleanup(raw.close)
        sock, reply = socks_connect("test-user", "test-password", host="host.docker.internal", port=RAW_PORT)
        self.addCleanup(sock.close)
        self.assertEqual(reply[:2], b"\x05\x00")
        sock.sendall(b"SSH-2.0-test\r\n")
        self.assertEqual(sock.recv(1), b"")
        raw.accepted.wait(0.5)
        time.sleep(0.1)
        self.assertEqual(raw.received, b"")


if __name__ == "__main__":
    unittest.main(verbosity=2)
