"""Adversarial probe #2: silent JSON corruption + sequential-retry deadline blowout.

Uses the REAL smart_proxy code inside the live container.

Case 1 (claim 4 falsifier): upstream declares `Content-Encoding: gzip` with
Content-Length: N, then closes the connection after only part of the gzip body.
_read_with_deadline stops at EOF (it never validates Content-Length), so a
TRUNCATED body is treated as a complete response.  _decompress_body then fails
to gunzip, swallows the exception and returns the raw compressed bytes, while
_fetch_upstream_sync strips the content-encoding header.  Result: the client
gets a 200 with undecodable binary garbage instead of an error.

Case 2 (30s-timeout falsifier): two SEQUENTIAL replays against an upstream that
accepts the connection and never answers.  There is no overall request budget,
so the two timeouts add up.
"""
import gzip
import http.client
import socket
import ssl
import threading
import time
from unittest.mock import MagicMock

from smart_proxy import REPLAY_TIMEOUT, MAX_RETRIES, _fetch_upstream_sync, ProxyNode

LISTEN = socket.socket()
LISTEN.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
LISTEN.bind(("127.0.0.1", 0))
PORT = LISTEN.getsockname()[1]
LISTEN.listen(16)


def serve():
    while True:
        try:
            c, _ = LISTEN.accept()
        except OSError:
            return
        threading.Thread(target=_handle, args=(c,), daemon=True).start()


def _handle(c):
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = c.recv(4096)
            if not chunk:
                return
            data += chunk
        first = data.split(b"\r\n", 1)[0].decode(errors="replace")
        if "/blackhole" in first:
            # accept, never answer -> socket read/write timeout on the caller side
            time.sleep(40)
            return
        # Case 1: declare gzip + a length, send a TRUNCATED gzip stream, close.
        full = gzip.compress(b'{"posts":[' + b'{"id":1},' * 500 + b'{"id":2}]}')
        partial = full[: len(full) // 3]
        c.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Encoding: gzip\r\nContent-Length: %d\r\n\r\n" % len(full)
            + partial
        )
        c.close()
    except Exception:
        pass


threading.Thread(target=serve, daemon=True).start()
time.sleep(0.3)


def mkflow(url, method="GET"):
    f = MagicMock()
    f.request.url = url
    f.request.method = method
    f.request.headers = {}
    f.request.content = None
    return f


node = ProxyNode(scheme="http", host="127.0.0.1", port=PORT)

print("### Case 1: truncated Content-Encoding: gzip body")
t0 = time.time()
r = _fetch_upstream_sync(mkflow(f"http://example.com/hangless/posts.json"), node, timeout=8)
print(f"  elapsed={time.time()-t0:.2f}s  status={r.status_code if r else None}")
if r:
    body = r.content or b""
    print(f"  returned body: {len(body)}B  first 8 bytes: {body[:8]!r}")
    print(f"  content-encoding header sent to client: {r.headers.get('content-encoding')!r}")
    try:
        import json as _j
        _j.loads(body)
        print("  json.loads(body): OK (no corruption)")
    except Exception as e:
        print(f"  json.loads(body): FAILED -> {type(e).__name__}: {e}")
    print("  => client receives HTTP 200 with a body it cannot decode" if body[:2] == b"\x1f\x8b" else "  => body decoded")

print()
print(f"### Case 2: sequential replay timeouts (REPLAY_TIMEOUT={REPLAY_TIMEOUT}, MAX_RETRIES={MAX_RETRIES})")
total = 0.0
for i in range(1, MAX_RETRIES + 1):
    t0 = time.time()
    r = _fetch_upstream_sync(mkflow("http://example.com/blackhole"), node, timeout=REPLAY_TIMEOUT)
    el = time.time() - t0
    total += el
    print(f"  replay attempt {i}: elapsed={el:.2f}s result={'None (failed)' if r is None else r.status_code}")
print(f"  TOTAL replay tail = {total:.2f}s  (UptimeRobot monitor timeout = 30s)")
print(f"  >>> worst case exceeds monitor timeout: {total > 30}")
