#!/usr/bin/env python3
"""Per-node truth test: does each fleet sing-box actually work for the TARGET domains?"""
import base64
import http.client
import ssl
import time

NODES = [
    ("100.101.155.30", "router_user:SecurePassword123", "hetzner-de-1"),
    ("100.78.142.119", "router_user:SecurePassword123", "hetzner-de-2"),
    ("100.108.164.100", "router_user:SecurePassword123", "oracle-es-?"),
    ("100.86.19.121", "router_user:SecurePassword123", "oracle-es-?"),
    ("100.106.178.1", "router_user:8BNoqKMOjf9UwekwURdhcsUC6YNuUYAg", "vsys-nl-1"),
    ("100.90.223.5", "router_user:SecurePassword123", "home-es (Telefonica)"),
]

TARGETS = [
    ("probe cp.cloudflare.com/generate_204", "cp.cloudflare.com", "/generate_204"),
    ("e621.net", "e621.net", "/posts.json?limit=1"),
    ("rule34.paheal.net (https)", "rule34.paheal.net", "/api/danbooru/find_posts?limit=1"),
]

UA = "Mozilla/5.0 (compatible; SmartProxyProbe/1.0)"


def check(host, port, auth, tgt_host, path, timeout=12, scheme="https"):
    enc = base64.b64encode(auth.encode()).decode()
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn.set_tunnel(f"{tgt_host}:443" if scheme == "https" else f"{tgt_host}:80",
                    headers={"Proxy-Authorization": f"Basic {enc}"})
    try:
        conn.connect()
    except Exception as e:
        return f"TUNNEL-FAIL {type(e).__name__}: {e}"
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            conn.sock = ctx.wrap_socket(conn.sock, server_hostname=tgt_host)
        except Exception as e:
            return f"TLS-FAIL {type(e).__name__}: {e}"
    t0 = time.time()
    try:
        conn.request("GET", path, headers={"Host": tgt_host, "Connection": "close", "User-Agent": UA})
        r = conn.getresponse()
        body = r.read(400)
        return f"{r.status} in {(time.time()-t0)*1000:.0f}ms | {body[:80]!r}"
    except Exception as e:
        return f"REQ-FAIL {type(e).__name__}: {e}"
    finally:
        try:
            conn.close()
        except Exception:
            pass


for ip, auth, label in NODES:
    print(f"== {label} ({ip})")
    for tname, thost, tpath in TARGETS:
        print(f"   {tname:38s} -> {check(ip, 1080, auth, thost, tpath, scheme='http' if tname.startswith('probe') else 'https')}")
