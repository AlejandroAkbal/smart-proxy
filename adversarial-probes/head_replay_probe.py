"""Adversarial probe: does _fetch_upstream_sync hang on HEAD replays?

Emulates an upstream proxy/endpoint that answers HEAD with Content-Length: 100
but keeps the connection open (ignores our `Connection: close`). Uses the real
smart_proxy code from inside the live container.
"""
import socket
import threading
import time

from unittest.mock import MagicMock

from smart_proxy import _fetch_upstream_sync, ProxyNode

PORT = 18080
LISTEN = socket.socket()
LISTEN.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
LISTEN.bind(("127.0.0.1", PORT))
LISTEN.listen(8)


def serve():
    while True:
        try:
            c, _ = LISTEN.accept()
        except Exception:
            return

        def handle(conn):
            try:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                method = data.split(b"\r\n", 1)[0].split()[0].decode()
                # Declares a body length, then sends NO body (legal for HEAD) and
                # deliberately keeps the connection open.
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    b"Content-Length: 100\r\n\r\n"
                )
                if method != "HEAD":
                    conn.sendall(b'{"ok":true}' + b" " * 87)
                time.sleep(30)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        threading.Thread(target=handle, args=(c,), daemon=True).start()


threading.Thread(target=serve, daemon=True).start()
time.sleep(0.3)

node = ProxyNode(scheme="http", host="127.0.0.1", port=PORT)

for method in ("HEAD", "GET"):
    flow = MagicMock()
    flow.request.url = "http://example.com/posts.json"
    flow.request.method = method
    flow.request.headers = {}
    flow.request.content = None
    t0 = time.time()
    r = _fetch_upstream_sync(flow, node, timeout=6.0)
    el = time.time() - t0
    print(
        f"method={method:5s} timeout=6.0s  ->  "
        f"result={'None(REPLAY FAILED)' if r is None else r.status_code} "
        f"body={len(r.content) if r else 0}B  elapsed={el:.2f}s"
    )
