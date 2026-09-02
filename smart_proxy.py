import re
import os
import time
import socket
import logging
import threading
import urllib.request
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional, Tuple, Any, cast

from mitmproxy import http, ctx
from mitmproxy.connection import Server
from mitmproxy.net.server_spec import ServerSpec
from mitmproxy.script import concurrent

CHALLENGE_RE = re.compile(
    rb"captcha|cf-chl|challenge-platform|unusual traffic|temporarily blocked|just a moment|security check|cloudflare-static",
    re.I
)
RETRY_STATUSES = {403, 429, 503}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}
COOLDOWN_SECONDS = int(os.environ.get("COOLDOWN_SECONDS", "600"))
MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "2"))
ADAPTER_URL = os.environ.get("ADAPTER_URL", "").rstrip("/")
ADAPTER_REFRESH_INTERVAL = int(os.environ.get("ADAPTER_REFRESH_INTERVAL", "300"))

@dataclass
class ProxyNode:
    scheme: str # "http" or "socks5"
    host: str
    port: int
    auth: Optional[str] = None
    cooldown_until: float = 0.0

    @property
    def key(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

class StickyPool:
    def __init__(self):
        self.lock = threading.Lock()
        self.nodes: List[ProxyNode] = []
        self.current_idx: int = 0

    def update_nodes(self, new_nodes: List[ProxyNode]):
        if not new_nodes:
            return
        with self.lock:
            existing = {n.key: n for n in self.nodes}
            merged = []
            for n in new_nodes:
                if n.key in existing:
                    n.cooldown_until = existing[n.key].cooldown_until
                merged.append(n)
            self.nodes = merged
            if self.nodes:
                self.current_idx = self.current_idx % len(self.nodes)

    def current(self) -> Optional[ProxyNode]:
        with self.lock:
            if not self.nodes:
                return None
            now = time.time()
            for i in range(len(self.nodes)):
                idx = (self.current_idx + i) % len(self.nodes)
                if self.nodes[idx].cooldown_until <= now:
                    self.current_idx = idx
                    return self.nodes[idx]
            # If all in cooldown, pick the one expiring earliest
            earliest = min(self.nodes, key=lambda n: n.cooldown_until)
            self.current_idx = self.nodes.index(earliest)
            return earliest

    def mark_failed(self, node: ProxyNode):
        with self.lock:
            node.cooldown_until = time.time() + COOLDOWN_SECONDS
            if self.nodes:
                self.current_idx = (self.current_idx + 1) % len(self.nodes)

    def count(self) -> int:
        with self.lock:
            return len(self.nodes)

pool = StickyPool()

def _parse_yaml_proxies(raw_text: str) -> List[ProxyNode]:
    nodes = []
    cur_type = "http"
    cur_server = ""
    cur_port = 0
    cur_user = None
    cur_pass = None

    for line in raw_text.splitlines():
        line = line.strip()
        if line.startswith("- name:") or line.startswith("name:"):
            if cur_server and cur_port:
                auth = f"{cur_user}:{cur_pass}" if cur_user else None
                nodes.append(ProxyNode(scheme=cur_type, host=cur_server, port=cur_port, auth=auth))
            cur_type = "http"
            cur_server = ""
            cur_port = 0
            cur_user = None
            cur_pass = None
        elif line.startswith("type:"):
            cur_type = line.split(":", 1)[1].strip().strip("\"'").lower()
        elif line.startswith("server:"):
            cur_server = line.split(":", 1)[1].strip().strip("\"'")
        elif line.startswith("port:"):
            try: cur_port = int(line.split(":", 1)[1].strip().strip("\"'"))
            except ValueError: pass
        elif line.startswith("username:"):
            cur_user = line.split(":", 1)[1].strip().strip("\"'")
        elif line.startswith("password:"):
            cur_pass = line.split(":", 1)[1].strip().strip("\"'")

    if cur_server and cur_port:
        auth = f"{cur_user}:{cur_pass}" if cur_user else None
        nodes.append(ProxyNode(scheme=cur_type, host=cur_server, port=cur_port, auth=auth))
    return nodes

def _refresh_from_adapter():
    if not ADAPTER_URL:
        return
    feeds = ["worldpool.yaml", "proxifly.yaml", "monosans.yaml"]
    all_nodes = []
    for f in feeds:
        try:
            url = f"{ADAPTER_URL}/{f}"
            req = urllib.request.Request(url, headers={"User-Agent": "SmartProxy"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                text = resp.read().decode("utf-8", errors="replace")
                all_nodes.extend(_parse_yaml_proxies(text))
        except Exception:
            pass

    if all_nodes:
        valid = [n for n in all_nodes if n.scheme == "http"]
        if valid:
            pool.update_nodes(valid)
            ctx.log.info(f"[SmartProxy] Refreshed pool from adapter: {len(valid)} healthy HTTP nodes.")

def _background_updater():
    while True:
        try:
            _refresh_from_adapter()
        except Exception as e:
            ctx.log.warn(f"[SmartProxy] Pool refresh error: {e}")
        time.sleep(ADAPTER_REFRESH_INTERVAL)

PROXY_AUTH = os.environ.get("PROXY_AUTH", "")

def _check_auth(flow: http.HTTPFlow) -> bool:
    if not PROXY_AUTH:
        return True
    auth_header = flow.request.headers.get("Proxy-Authorization", "")
    if not auth_header.startswith("Basic "):
        return False
    try:
        import base64
        decoded = base64.b64decode(auth_header[6:].strip()).decode("utf-8")
        return decoded == PROXY_AUTH
    except Exception:
        return False

class SmartProxyAddon:
    def __init__(self):
        self.authenticated_conns = set()
        if PROXY_AUTH:
            ctx.log.info(f"[SmartProxy] Authentication enabled for user: {PROXY_AUTH.split(':', 1)[0]}")
        raw_env = os.environ.get("UPSTREAM_PROXIES", "")
        if raw_env:
            nodes = []
            for raw in raw_env.split(","):
                raw = raw.strip()
                if not raw: continue
                if not raw.startswith("http://") and not raw.startswith("socks5://"):
                    raw = "http://" + raw
                p = urllib.parse.urlsplit(raw)
                auth = f"{p.username}:{p.password}" if p.username else None
                nodes.append(ProxyNode(scheme=p.scheme, host=p.hostname, port=p.port or 80, auth=auth))
            if nodes:
                pool.update_nodes(nodes)

        if ADAPTER_URL:
            # Immediate initial fetch
            threading.Thread(target=_refresh_from_adapter, daemon=True).start()
            threading.Thread(target=_background_updater, daemon=True).start()

    def http_connect(self, flow: http.HTTPFlow) -> None:
        if not _check_auth(flow):
            flow.response = http.Response.make(
                407,
                b"Proxy Authentication Required\n",
                {"Proxy-Authenticate": 'Basic realm="Smart Proxy"'}
            )
        else:
            self.authenticated_conns.add(flow.client_conn.id)

    def client_disconnected(self, client: Any) -> None:
        self.authenticated_conns.discard(getattr(client, "id", None))

    def request(self, flow: http.HTTPFlow) -> None:
        is_authenticated = (flow.client_conn.id in self.authenticated_conns) or _check_auth(flow)
        if not is_authenticated:
            flow.response = http.Response.make(
                407,
                b"Proxy Authentication Required\n",
                {"Proxy-Authenticate": 'Basic realm="Smart Proxy"'}
            )
            return

        # Strip Proxy-Authorization header before forwarding upstream
        flow.request.headers.pop("Proxy-Authorization", None)

        node = flow.metadata.pop("force_proxy", None) or pool.current()
        if not node:
            return

        flow.metadata["upstream_proxy"] = node
        spec = ServerSpec((node.scheme, (node.host, node.port)))

        is_proxy_change = (flow.server_conn.via != spec)
        server_open = flow.server_conn.timestamp_start is not None
        if is_proxy_change and server_open:
            flow.server_conn = Server(address=flow.server_conn.address)
        flow.server_conn.via = spec

    @concurrent
    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None or flow.is_replay:
            return

        status = flow.response.status_code
        body = flow.response.content or b""
        is_blocked = (status in RETRY_STATUSES) or bool(CHALLENGE_RE.search(body[:16384]))

        if not is_blocked:
            return

        method = flow.request.method.upper()
        allow_replay = (method in SAFE_METHODS) or (flow.request.headers.get("X-Allow-Mutation-Replay") == "1")
        if not allow_replay:
            ctx.log.warn(f"[SmartProxy] Detected status {status} on unsafe method {method} - not replaying to prevent duplicate mutations.")
            return

        retries = flow.metadata.get("retry_count", 0)
        if retries >= MAX_RETRIES:
            return

        current_node = flow.metadata.get("upstream_proxy")
        if current_node:
            pool.mark_failed(current_node)

        next_node = pool.current()
        if not next_node or (next_node == current_node and pool.count() > 1):
            return

        flow.metadata["retry_count"] = retries + 1
        ctx.log.info(f"[SmartProxy] Detected status {status}/challenge on {method} {flow.request.host}. Rotating {current_node.key} -> {next_node.key} (attempt {retries+1})")

        new_flow = flow.copy()
        new_flow.metadata["force_proxy"] = next_node
        new_flow.metadata["retry_count"] = retries + 1

        cast(Any, ctx.master).commands.call("replay.client", [new_flow])

        for _ in range(200):
            if new_flow.response is not None or new_flow.error is not None:
                break
            time.sleep(0.05)

        if new_flow.response is not None:
            ctx.log.info(f"[SmartProxy] Replay success: received status {new_flow.response.status_code} from {next_node.key}")
            flow.response = new_flow.response
            flow.metadata["upstream_proxy"] = next_node
        else:
            ctx.log.error(f"[SmartProxy] Replay failed or timed out on {next_node.key}: error={new_flow.error}")

addons = [SmartProxyAddon()]
