import re
import os
import time
import socket
import logging
import threading
import urllib.request
import urllib.parse
import gzip
import zlib
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Any, cast

# Reasonable timeout on upstream socket connections to prune completely dead proxies without cutting off slow boorus
socket.setdefaulttimeout(10.0)

from mitmproxy import http, ctx
from mitmproxy.connection import Server
from mitmproxy.net.server_spec import ServerSpec

logger = logging.getLogger("smart_proxy")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

CHALLENGE_RE = re.compile(
    rb"captcha|cf-chl|challenge-platform|unusual traffic|temporarily blocked|just a moment|security check|cloudflare-static",
    re.I
)
RETRY_STATUSES = {403, 429, 503}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}
COOLDOWN_SECONDS = int(os.environ.get("COOLDOWN_SECONDS", "900"))
MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "5"))
ADAPTER_URL = os.environ.get("ADAPTER_URL", "").rstrip("/")
ADAPTER_REFRESH_INTERVAL = int(os.environ.get("ADAPTER_REFRESH_INTERVAL", "300"))
PROXY_AUTH = os.environ.get("PROXY_AUTH", "")

@dataclass
class ProxyNode:
    scheme: str # "http"
    host: str
    port: int
    auth: Optional[str] = None
    global_cooldown_until: float = 0.0
    host_cooldowns: dict[str, float] = field(default_factory=dict)
    ema_latency_ms: float = 500.0 # Initial default latency
    success_count: int = 0
    failure_count: int = 0

    @property
    def key(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def is_available_for(self, domain: str, now: float) -> bool:
        if self.global_cooldown_until > now:
            return False
        return self.host_cooldowns.get(domain, 0.0) <= now

    def get_effective_cooldown(self, domain: str) -> float:
        return max(self.global_cooldown_until, self.host_cooldowns.get(domain, 0.0))

    def record_success(self, duration_ms: float):
        self.success_count += 1
        # Exponential moving average with alpha=0.25
        self.ema_latency_ms = (0.25 * duration_ms) + (0.75 * self.ema_latency_ms)

    def record_host_failure(self, domain: str):
        self.failure_count += 1
        self.host_cooldowns[domain] = time.time() + COOLDOWN_SECONDS
        self.ema_latency_ms += 500.0

    def record_global_failure(self):
        self.failure_count += 1
        self.global_cooldown_until = time.time() + COOLDOWN_SECONDS
        self.ema_latency_ms += 1500.0

def _extract_root_domain(host: str) -> str:
    """Extract root domain to group subdomains (e.g. api.e621.net -> e621.net)."""
    if not host:
        return "default"
    host = host.split(":")[0].lower().strip(".")
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return host
    if len(parts) <= 2:
        return host
    if len(parts) >= 3 and parts[-2] in {"co", "com", "net", "org", "edu", "gov"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

class StickyLatencyPool:
    def __init__(self):
        self.lock = threading.Lock()
        self.nodes: List[ProxyNode] = []
        self.current_nodes: dict[str, ProxyNode] = {} # domain -> sticky ProxyNode

    def update_nodes(self, new_nodes: List[ProxyNode]):
        if not new_nodes:
            return
        with self.lock:
            existing = {n.key: n for n in self.nodes}
            merged = []
            for n in new_nodes:
                if n.key in existing:
                    old = existing[n.key]
                    n.global_cooldown_until = old.global_cooldown_until
                    n.host_cooldowns = old.host_cooldowns
                    n.ema_latency_ms = old.ema_latency_ms
                    n.success_count = old.success_count
                    n.failure_count = old.failure_count
                merged.append(n)
            self.nodes = merged
            for domain, node in list(self.current_nodes.items()):
                if node.key in existing:
                    self.current_nodes[domain] = existing[node.key]

    def select_best_for(self, domain: str) -> Optional[ProxyNode]:
        """Picks the lowest latency node available for domain."""
        with self.lock:
            if not self.nodes:
                return None
            now = time.time()
            healthy = [n for n in self.nodes if n.is_available_for(domain, now)]
            if healthy:
                healthy.sort(key=lambda n: (n.ema_latency_ms, n.failure_count))
                self.current_nodes[domain] = healthy[0]
                return healthy[0]
            # Fallback: if all on cooldown for this domain, pick earliest expiring
            earliest = min(self.nodes, key=lambda n: n.get_effective_cooldown(domain))
            self.current_nodes[domain] = earliest
            return earliest

    def get_current_or_best(self, domain: str) -> Optional[ProxyNode]:
        """Keeps active sticky node for domain if healthy; otherwise picks best."""
        with self.lock:
            now = time.time()
            current = self.current_nodes.get(domain)
            if current and current.is_available_for(domain, now):
                return current
        return self.select_best_for(domain)

    def mark_host_failed(self, node: ProxyNode, domain: str):
        with self.lock:
            node.record_host_failure(domain)
            if self.current_nodes.get(domain) and self.current_nodes[domain].key == node.key:
                self.current_nodes.pop(domain, None)

    def mark_global_failed(self, node: ProxyNode):
        with self.lock:
            node.record_global_failure()
            for domain, cur in list(self.current_nodes.items()):
                if cur.key == node.key:
                    self.current_nodes.pop(domain, None)

    def record_latency(self, node: ProxyNode, duration_ms: float):
        with self.lock:
            node.record_success(duration_ms)

    def count(self) -> int:
        with self.lock:
            return len(self.nodes)

pool = StickyLatencyPool()

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
            logger.info(f"[SmartProxy] Refreshed pool from adapter: {len(valid)} healthy HTTP nodes.")

def _background_updater():
    while True:
        try:
            _refresh_from_adapter()
        except Exception as e:
            logger.warn(f"[SmartProxy] Pool refresh error: {e}")
        time.sleep(ADAPTER_REFRESH_INTERVAL)

# Initial load on import
try:
    _refresh_from_adapter()
except Exception:
    pass

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

def _extract_sample_body(content: bytes, encoding: Optional[str]) -> bytes:
    if not content:
        return b""
    if encoding == "gzip":
        try:
            return gzip.decompress(content)[:16384]
        except Exception:
            pass
    elif encoding == "deflate":
        try:
            return zlib.decompress(content)[:16384]
        except Exception:
            pass
    return content[:16384]


def _fetch_upstream(flow: http.HTTPFlow, node: ProxyNode, timeout: float = 6.0) -> Optional[http.Response]:
    proxy_url = f"{node.scheme}://{node.host}:{node.port}"
    handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = urllib.request.build_opener(handler)

    headers = dict(flow.request.headers)
    for h in ["proxy-authorization", "proxy-connection", "connection", "keep-alive", "host", "Host"]:
        headers.pop(h, None)

    body = flow.request.content if flow.request.content else None
    req = urllib.request.Request(
        flow.request.url,
        data=body,
        headers=headers,
        method=flow.request.method
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            content = resp.read()
            resp_headers = [
                (k.encode("utf-8"), v.encode("utf-8"))
                for k, v in resp.headers.items()
            ]
            return http.Response.make(resp.status, content, resp_headers)
    except urllib.error.HTTPError as e:
        content = e.read()
        resp_headers = [
            (k.encode("utf-8"), v.encode("utf-8"))
            for k, v in e.headers.items()
        ]
        return http.Response.make(e.code, content, resp_headers)
    except Exception:
        return None


class SmartProxyAddon:
    def __init__(self):
        self.authenticated_conns = set()

    def running(self) -> None:
        _refresh_from_adapter()
        t = threading.Thread(target=_background_updater, daemon=True)
        t.start()
        logger.info("[SmartProxy] Background proxy pool updater started.")

    def client_disconnected(self, client: http.Client) -> None:
        self.authenticated_conns.discard(client.id)

    def http_connect(self, flow: http.HTTPFlow) -> None:
        if not PROXY_AUTH:
            return

        if _check_auth(flow):
            self.authenticated_conns.add(flow.client_conn.id)
            flow.response = http.Response.make(200, b"")
        else:
            flow.response = http.Response.make(
                407,
                b"Proxy Authentication Required\n",
                {"Proxy-Authenticate": 'Basic realm="Smart Proxy"'}
            )

    def server_connect(self, data) -> None:
        if not data.server.address:
            return
        host = data.server.address[0]
        domain = _extract_root_domain(host)
        node = pool.get_current_or_best(domain)
        if node:
            spec = ServerSpec((node.scheme, (node.host, node.port)))
            data.server.via = spec
            ctx.log.info(f"[SmartProxy] Routing server connection for {host} ({domain}) via {node.key}")

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        is_authenticated = (flow.client_conn.id in self.authenticated_conns) or _check_auth(flow)
        if not is_authenticated:
            flow.response = http.Response.make(
                407,
                b"Proxy Authentication Required\n",
                {"Proxy-Authenticate": 'Basic realm="Smart Proxy"'}
            )
            return

        flow.request.headers.pop("Proxy-Authorization", None)
        domain = _extract_root_domain(flow.request.pretty_host)
        flow.metadata["target_domain"] = domain
        node = flow.metadata.pop("force_proxy", None) or pool.get_current_or_best(domain)
        if not node:
            return

        flow.metadata["upstream_proxy"] = node
        flow.metadata["start_time"] = time.time()
        spec = ServerSpec((node.scheme, (node.host, node.port)))
        flow.server_conn.via = spec

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.response is not None:
            return
        domain = flow.metadata.get("target_domain") or _extract_root_domain(flow.request.pretty_host)
        node = flow.metadata.get("upstream_proxy") or pool.get_current_or_best(domain)
        if node:
            spec = ServerSpec((node.scheme, (node.host, node.port)))
            flow.server_conn.via = spec

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None or flow.is_replay:
            return

        current_node: Optional[ProxyNode] = flow.metadata.get("upstream_proxy")
        start_time: float = flow.metadata.get("start_time", time.time())
        duration_ms = (time.time() - start_time) * 1000.0
        domain = flow.metadata.get("target_domain") or _extract_root_domain(flow.request.pretty_host)

        status = flow.response.status_code
        body = flow.response.content or b""
        sample = _extract_sample_body(body, flow.response.headers.get("content-encoding"))
        is_blocked = (status in RETRY_STATUSES) or bool(CHALLENGE_RE.search(sample))

        if not is_blocked:
            # Record successful response latency
            if current_node:
                pool.record_latency(current_node, duration_ms)
            return

        method = flow.request.method.upper()
        allow_replay = (method in SAFE_METHODS) or (flow.request.headers.get("X-Allow-Mutation-Replay") == "1")
        if not allow_replay:
            ctx.log.warn(f"[SmartProxy] Detected status {status} on unsafe method {method} - not replaying to prevent duplicate mutations.")
            return

        last_failed = current_node
        if last_failed:
            pool.mark_host_failed(last_failed, domain)

        for retry_num in range(1, MAX_RETRIES + 1):
            next_node = pool.select_best_for(domain)
            if not next_node or (next_node == last_failed and pool.count() > 1):
                break

            ctx.log.info(f"[SmartProxy] Detected status {status}/challenge on {method} {flow.request.host} ({domain}). Rotating {last_failed.key if last_failed else 'none'} -> {next_node.key} (attempt {retry_num}/{MAX_RETRIES})")
            resp = _fetch_upstream(flow, next_node, timeout=6.0)
            if resp is not None:
                resp_status = resp.status_code
                resp_body = resp.content or b""
                resp_sample = _extract_sample_body(resp_body, resp.headers.get("content-encoding"))
                resp_blocked = (resp_status in RETRY_STATUSES) or bool(CHALLENGE_RE.search(resp_sample))
                if not resp_blocked:
                    ctx.log.info(f"[SmartProxy] Replay success: received status {resp_status} from {next_node.key} for {domain}")
                    flow.response = resp
                    flow.error = None
                    flow.metadata["upstream_proxy"] = next_node
                    pool.record_latency(next_node, (time.time() - start_time) * 1000.0)
                    return
                else:
                    ctx.log.warn(f"[SmartProxy] Replay attempt {retry_num} on {next_node.key} returned status {resp_status}/challenge. Quarantining for {domain}...")
            else:
                ctx.log.warn(f"[SmartProxy] Replay attempt {retry_num} on {next_node.key} timed out or connection failed. Quarantining for {domain}...")

            pool.mark_host_failed(next_node, domain)
            last_failed = next_node

    def error(self, flow: http.HTTPFlow) -> None:
        if flow.is_replay:
            return

        current_node: Optional[ProxyNode] = flow.metadata.get("upstream_proxy")
        start_time: float = flow.metadata.get("start_time", time.time())
        domain = flow.metadata.get("target_domain") or _extract_root_domain(flow.request.pretty_host)

        method = flow.request.method.upper()
        allow_replay = (method in SAFE_METHODS) or (flow.request.headers.get("X-Allow-Mutation-Replay") == "1")
        if not allow_replay:
            return

        last_failed = current_node
        if last_failed:
            pool.mark_global_failed(last_failed)

        for retry_num in range(1, MAX_RETRIES + 1):
            next_node = pool.select_best_for(domain)
            if not next_node or (next_node == last_failed and pool.count() > 1):
                break

            ctx.log.info(f"[SmartProxy] Detected connection error ({flow.error}) on {method} {flow.request.host}. Rotating globally {last_failed.key if last_failed else 'none'} -> {next_node.key} (attempt {retry_num}/{MAX_RETRIES})")
            resp = _fetch_upstream(flow, next_node, timeout=6.0)
            if resp is not None:
                resp_status = resp.status_code
                resp_body = resp.content or b""
                resp_sample = _extract_sample_body(resp_body, resp.headers.get("content-encoding"))
                resp_blocked = (resp_status in RETRY_STATUSES) or bool(CHALLENGE_RE.search(resp_sample))
                if not resp_blocked:
                    ctx.log.info(f"[SmartProxy] Error-recovery success: received status {resp_status} from {next_node.key} for {domain}")
                    flow.response = resp
                    flow.error = None
                    flow.metadata["upstream_proxy"] = next_node
                    pool.record_latency(next_node, (time.time() - start_time) * 1000.0)
                    return
                else:
                    ctx.log.warn(f"[SmartProxy] Error-recovery attempt {retry_num} on {next_node.key} returned status {resp_status}/challenge. Quarantining for {domain}...")
                    pool.mark_host_failed(next_node, domain)
            else:
                ctx.log.warn(f"[SmartProxy] Error-recovery attempt {retry_num} on {next_node.key} timed out or connection failed. Quarantining globally...")
                pool.mark_global_failed(next_node)

            last_failed = next_node

addons = [SmartProxyAddon()]
