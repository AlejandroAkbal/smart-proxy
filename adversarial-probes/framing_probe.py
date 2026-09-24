"""Adversarial probe of _read_with_deadline / _fetch_upstream_sync framing behaviour.

Four upstream behaviours, using the REAL smart_proxy code in the live container:

  A) HEAD  + keep-alive open  (server ignores our `Connection: close`)
  B) HEAD  + server closes
  C) GET   + exact Content-Length body, keep-alive open
  D) GET   + exact Content-Length body, server closes
"""
import socket
import threading
import time

from unittest.mock import MagicMock

from smart_proxy import _fetch_upstream_sync, ProxyNode

BODY = b'{"posts":[]}' + b" " * 20  # 32 bytes, exactly Content-Length below
CLEN = str(len(BODY)).encode()


def make_server(close_after: bool):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", 0))
    ls.listen(8)
    port = ls.getsockname()[1]

    def handle(conn):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            method = data.split(b"\r\n", 1)[0].split()[0].decode()
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: " + CLEN + b"\r\n\r\n"
            )
            if method != "HEAD":
                conn.sendall(BODY)
            if close_after:
                conn.close()
            else:
                time.sleep(25)  # ignore Connection: close, hold the socket open
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def serve():
        while True:
            try:
                c, _ = ls.accept()
            except Exception:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return port


for label, method, close_after in (
    ("A HEAD + keep-alive", "HEAD", False),
    ("B HEAD + close     ", "HEAD", True),
    ("C GET  + keep-alive", "GET", False),
    ("D GET  + close     ", "GET", True),
):
    port = make_server(close_after)
    time.sleep(0.2)
    node = ProxyNode(scheme="http", host="127.0.0.1", port=port)
    flow = MagicMock()
    flow.request.url = "http://example.com/posts.json"
    flow.request.method = method
    flow.request.headers = {}
    flow.request.content = None
    t0 = time.time()
    r = _fetch_upstream_sync(flow, node, timeout=5.0)
    el = time.time() - t0
    print(
        f"{label}  ->  result={'None (REPLAY FAILED)' if r is None else r.status_code}"
        f"  body={len(r.content) if r else 0}B  elapsed={el:.2f}s"
    )
