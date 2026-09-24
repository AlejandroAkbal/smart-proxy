"""Does the LIVE replay path terminate on the real targets, and how fast?
Plain-HTTP rule34.paheal.net is what api.r34.app actually requests."""
import time
from unittest.mock import MagicMock
from smart_proxy import _fetch_upstream_sync, ProxyNode

NODES = [
    ("hetzner-de-1", "100.101.155.30", "router_user:SecurePassword123"),
    ("hetzner-de-2", "100.78.142.119", "router_user:SecurePassword123"),
    ("oracle-es-1",  "100.108.164.100", "router_user:SecurePassword123"),
    ("oracle-es-2",  "100.86.19.121", "router_user:SecurePassword123"),
    ("vsys-nl-1",    "100.106.178.1", "router_user:8BNoqKMOjf9UwekwURdhcsUC6YNuUYAg"),
    ("home-es",      "100.90.223.5", "router_user:SecurePassword123"),
]

def mkflow(url, method="GET"):
    f = MagicMock()
    f.request.url = url
    f.request.method = method
    f.request.headers = {"User-Agent": "R34/1.0"}
    f.request.content = None
    return f

TARGETS = [
    ("http  paheal api", "http://rule34.paheal.net/api/danbooru/find_posts?limit=1", "GET"),
    ("http  paheal api", "http://rule34.paheal.net/api/danbooru/find_posts?limit=1", "HEAD"),
    ("https paheal api", "https://rule34.paheal.net/api/danbooru/find_posts?limit=1", "GET"),
    ("https e621  api", "https://e621.net/posts.json?limit=1", "GET"),
]

for name, host, auth in NODES:
    node = ProxyNode(scheme="http", host=host, port=1080, auth=auth)
    print(f"== {name} ({host})")
    for label, url, method in TARGETS:
        t0 = time.time()
        r = _fetch_upstream_sync(mkflow(url, method), node, timeout=8.0)
        el = time.time() - t0
        if r is None:
            print(f"   {label:18s} {method:4s} -> NO RESPONSE (replay failed) in {el:.2f}s")
        else:
            print(f"   {label:18s} {method:4s} -> {r.status_code} len={len(r.content or b'')}B conn_hdr={r.headers.get('connection')} in {el:.2f}s")
