import asyncio
import base64
import gzip
import logging
import os
import re
import socket
import threading
import time
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field
from typing import Any, List, Optional, Set, Tuple

# Reasonable default timeout on socket operations
socket.setdefaulttimeout(3.0)

from mitmproxy import ctx, http
from mitmproxy.connection import Server
from mitmproxy.net.server_spec import ServerSpec

logger = logging.getLogger("smart_proxy")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

CHALLENGE_RE = re.compile(
    rb"captcha|cf-chl|challenge-platform|unusual traffic|temporarily blocked|just a moment|security check|cloudflare-static|turnstile",
    re.I,
)
RETRY_STATUSES = {403, 429, 502, 503, 504}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}

COOLDOWN_SECONDS = int(os.environ.get("COOLDOWN_SECONDS", "300"))
MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "2"))
REPLAY_TIMEOUT = float(os.environ.get("REPLAY_TIMEOUT", "2.0"))
UPSTREAM_CONNECT_TIMEOUT = float(os.environ.get("UPSTREAM_CONNECT_TIMEOUT", "2.0"))
ADAPTER_URL = os.environ.get("ADAPTER_URL", "").rstrip("/")
ADAPTER_REFRESH_INTERVAL = int(os.environ.get("ADAPTER_REFRESH_INTERVAL", "300"))
PROXY_AUTH = os.environ.get("PROXY_AUTH", "")
UPSTREAM_PROXIES_ENV = os.environ.get("UPSTREAM_PROXIES", "")


RATE_LIMIT_RPS = float(os.environ.get("RATE_LIMIT_RPS", "0"))


@dataclass
class ProxyNode:
    scheme: str  # "http" | "socks5"
    host: str
    port: int
    auth: Optional[str] = None
    global_cooldown_until: float = 0.0
    host_cooldowns: dict[str, float] = field(default_factory=dict)
    ema_latency_ms: float = 500.0
    success_count: int = 0
    failure_count: int = 0

    # Rate limiting: token bucket
    tokens: float = 5.0
    last_token_update: float = field(default_factory=time.time)
    rate_limit_rps: float = RATE_LIMIT_RPS
    bucket_capacity: float = 5.0

    @property
    def key(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def url_with_auth(self) -> str:
        if self.auth:
            return f"{self.scheme}://{self.auth}@{self.host}:{self.port}"
        return f"{self.scheme}://{self.host}:{self.port}"

    def is_available_for(self, domain: str, now: float) -> bool:
        if self.global_cooldown_until > now:
            return False
        return self.host_cooldowns.get(domain, 0.0) <= now

    def get_effective_cooldown(self, domain: str) -> float:
        return max(self.global_cooldown_until, self.host_cooldowns.get(domain, 0.0))

    def try_consume_token(self) -> bool:
        if self.rate_limit_rps <= 0:
            return True
        now = time.time()
        elapsed = now - self.last_token_update
        self.last_token_update = now
        self.tokens = min(self.bucket_capacity, self.tokens + (elapsed * self.rate_limit_rps))
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    def record_success(self, duration_ms: float):
        self.success_count += 1
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
        self.current_nodes: dict[str, ProxyNode] = {}  # domain -> sticky ProxyNode

    def update_nodes(self, new_nodes: List[ProxyNode]):
        if not new_nodes:
            return
        with self.lock:
            existing = {n.key: n for n in self.nodes}
            unique_new: dict[str, ProxyNode] = {}
            for n in new_nodes:
                if n.key not in unique_new:
                    unique_new[n.key] = n

            merged = []
            for key, n in unique_new.items():
                if key in existing:
                    old = existing[key]
                    old.scheme = n.scheme
                    old.host = n.host
                    old.port = n.port
                    old.auth = n.auth
                    merged.append(old)
                else:
                    merged.append(n)
            self.nodes = merged
            for domain, node in list(self.current_nodes.items()):
                if node.key in existing:
                    self.current_nodes[domain] = existing[node.key]

    def select_best_for(self, domain: str, check_rate_limit: bool = True) -> Optional[ProxyNode]:
        """Picks the lowest latency available node for domain and makes it sticky."""
        with self.lock:
            if not self.nodes:
                return None
            now = time.time()
            healthy = [n for n in self.nodes if n.is_available_for(domain, now)]
            if healthy:
                healthy.sort(key=lambda n: (n.ema_latency_ms, n.failure_count))
                if check_rate_limit:
                    # Pick lowest latency node that has token available
                    for candidate in healthy:
                        if candidate.try_consume_token():
                            self.current_nodes[domain] = candidate
                            return candidate
                # If all rate limited or rate check disabled, pick top healthy
                best = healthy[0]
                self.current_nodes[domain] = best
                return best
            
            # Fallback: if all on cooldown for this domain, pick earliest expiring
            earliest = min(self.nodes, key=lambda n: n.get_effective_cooldown(domain))
            self.current_nodes[domain] = earliest
            return earliest

    def get_current_or_best(self, domain: str) -> Optional[ProxyNode]:
        """Keeps active sticky node for domain if healthy and has token; otherwise selects best."""
        with self.lock:
            now = time.time()
            current = self.current_nodes.get(domain)
            if current and current.is_available_for(domain, now):
                if current.try_consume_token():
                    return current
        return self.select_best_for(domain, check_rate_limit=True)

    def set_current_node(self, domain: str, node: ProxyNode):
        with self.lock:
            self.current_nodes[domain] = node

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


def _parse_proxy_url(url_str: str) -> Optional[ProxyNode]:
    try:
        parsed = urllib.parse.urlsplit(url_str.strip())
        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        if scheme not in ("http", "https", "socks5", "socks5h"):
            scheme = "http"
        host = parsed.hostname
        port = parsed.port or (8080 if scheme.startswith("http") else 1080)
        auth = None
        if parsed.username or parsed.password:
            auth = f"{parsed.username or ''}:{parsed.password or ''}"
        if host and port:
            return ProxyNode(scheme=scheme, host=host, port=port, auth=auth)
    except Exception:
        pass
    return None


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
            try:
                cur_port = int(line.split(":", 1)[1].strip().strip("\"'"))
            except ValueError:
                pass
        elif line.startswith("username:"):
            cur_user = line.split(":", 1)[1].strip().strip("\"'")
        elif line.startswith("password:"):
            cur_pass = line.split(":", 1)[1].strip().strip("\"'")

    if cur_server and cur_port:
        auth = f"{cur_user}:{cur_pass}" if cur_user else None
        nodes.append(ProxyNode(scheme=cur_type, host=cur_server, port=cur_port, auth=auth))
    return nodes


def _refresh_from_sources():
    all_nodes = []

    # 1. Direct environment proxy list
    if UPSTREAM_PROXIES_ENV:
        for entry in UPSTREAM_PROXIES_ENV.split(","):
            node = _parse_proxy_url(entry)
            if node:
                all_nodes.append(node)

    # 2. Adapter feeds
    if ADAPTER_URL:
        feeds = [
            "worldpool.yaml", "proxifly.yaml", "monosans.yaml",
            "proxyscrape.yaml", "vakhov.yaml", "iplocate.yaml",
            "speedx.yaml", "aliilapro.yaml", "hookzof-socks5.yaml",
            "databay-socks5.yaml", "zaeem-https.yaml", "relayglass-https.yaml"
        ]
        for f in feeds:
            try:
                url = f"{ADAPTER_URL}/{f}"
                req = urllib.request.Request(url, headers={"User-Agent": "SmartProxy"})
                with urllib.request.urlopen(req, timeout=4) as resp:
                    text = resp.read().decode("utf-8", errors="replace")
                    all_nodes.extend(_parse_yaml_proxies(text))
            except Exception:
                pass

    if all_nodes:
        valid = [n for n in all_nodes if n.scheme in ("http", "socks5", "socks5h")]
        if valid:
            pool.update_nodes(valid)
            logger.info(f"[SmartProxy] Refreshed pool from sources: {len(valid)} nodes active.")


def _background_updater():
    while True:
        try:
            _refresh_from_sources()
        except Exception as e:
            logger.warning(f"[SmartProxy] Pool refresh error: {e}")
        time.sleep(ADAPTER_REFRESH_INTERVAL)


# Initial load on import
try:
    _refresh_from_sources()
except Exception:
    pass


def _check_auth(flow: http.HTTPFlow) -> bool:
    if not PROXY_AUTH:
        return True
    auth_header = flow.request.headers.get("Proxy-Authorization", "")
    if not auth_header.startswith("Basic "):
        return False
    try:
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


def _fetch_upstream_sync(flow: http.HTTPFlow, node: ProxyNode, timeout: float = REPLAY_TIMEOUT) -> Optional[http.Response]:
    """Synchronous worker function run in background executor thread."""
    proxy_url = node.url_with_auth
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
        method=flow.request.method,
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
        self.authenticated_conns: Set[str] = set()

    def load(self, loader):
        loader.add_option(
            "connection_strategy", str, "lazy", "Mitmproxy connection strategy"
        )
        loader.add_option(
            "connect_timeout", float, UPSTREAM_CONNECT_TIMEOUT, "Upstream connect timeout"
        )

    def running(self) -> None:
        _refresh_from_sources()
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
            return
        else:
            flow.response = http.Response.make(
                407,
                b"Proxy Authentication Required\n",
                {"Proxy-Authenticate": 'Basic realm="Smart Proxy"'},
            )

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        is_authenticated = (flow.client_conn.id in self.authenticated_conns) or _check_auth(flow)
        if not is_authenticated:
            flow.response = http.Response.make(
                407,
                b"Proxy Authentication Required\n",
                {"Proxy-Authenticate": 'Basic realm="Smart Proxy"'},
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
        if flow.server_conn.via != spec or flow.server_conn.timestamp_start is not None:
            flow.server_conn = Server(address=flow.server_conn.address)
        flow.server_conn.via = spec

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.response is not None:
            return
        domain = flow.metadata.get("target_domain") or _extract_root_domain(flow.request.pretty_host)
        node = flow.metadata.get("upstream_proxy") or pool.get_current_or_best(domain)
        if node:
            spec = ServerSpec((node.scheme, (node.host, node.port)))
            flow.server_conn.via = spec

    async def response(self, flow: http.HTTPFlow) -> None:
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
            if current_node:
                pool.record_latency(current_node, duration_ms)
            return

        method = flow.request.method.upper()
        allow_replay = (method in SAFE_METHODS) or (flow.request.headers.get("X-Allow-Mutation-Replay") == "1")
        if not allow_replay:
            ctx.log.warning(
                f"[SmartProxy] Detected status {status} on unsafe method {method} - not replaying."
            )
            return

        last_failed = current_node
        if last_failed:
            pool.mark_host_failed(last_failed, domain)

        # Async non-blocking replay loop
        for retry_num in range(1, MAX_RETRIES + 1):
            next_node = pool.select_best_for(domain, check_rate_limit=True)
            if not next_node or (next_node == last_failed and pool.count() > 1):
                break

            ctx.log.info(
                f"[SmartProxy] Detected status {status}/challenge on {method} {flow.request.host} ({domain}). Rotating -> {next_node.key} (attempt {retry_num}/{MAX_RETRIES})"
            )
            resp = await asyncio.to_thread(_fetch_upstream_sync, flow, next_node, timeout=REPLAY_TIMEOUT)
            if resp is not None:
                resp_status = resp.status_code
                resp_body = resp.content or b""
                resp_sample = _extract_sample_body(resp_body, resp.headers.get("content-encoding"))
                resp_blocked = (resp_status in RETRY_STATUSES) or bool(CHALLENGE_RE.search(resp_sample))
                if not resp_blocked:
                    ctx.log.info(
                        f"[SmartProxy] Replay success: received status {resp_status} from {next_node.key} for {domain}"
                    )
                    flow.response = resp
                    flow.error = None
                    flow.metadata["upstream_proxy"] = next_node
                    pool.set_current_node(domain, next_node)
                    pool.record_latency(next_node, (time.time() - start_time) * 1000.0)
                    return
                else:
                    ctx.log.warning(
                        f"[SmartProxy] Replay attempt {retry_num} on {next_node.key} returned status {resp_status}/challenge. Quarantining for {domain}..."
                    )
            else:
                ctx.log.warning(
                    f"[SmartProxy] Replay attempt {retry_num} on {next_node.key} timed out. Quarantining for {domain}..."
                )

            pool.mark_host_failed(next_node, domain)
            last_failed = next_node

    async def error(self, flow: http.HTTPFlow) -> None:
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

        # Async non-blocking error recovery loop
        for retry_num in range(1, MAX_RETRIES + 1):
            next_node = pool.select_best_for(domain, check_rate_limit=True)
            if not next_node or (next_node == last_failed and pool.count() > 1):
                break

            ctx.log.info(
                f"[SmartProxy] Connection error on {method} {flow.request.host}. Rotating -> {next_node.key} (attempt {retry_num}/{MAX_RETRIES})"
            )
            resp = await asyncio.to_thread(_fetch_upstream_sync, flow, next_node, timeout=REPLAY_TIMEOUT)
            if resp is not None:
                resp_status = resp.status_code
                resp_body = resp.content or b""
                resp_sample = _extract_sample_body(resp_body, resp.headers.get("content-encoding"))
                resp_blocked = (resp_status in RETRY_STATUSES) or bool(CHALLENGE_RE.search(resp_sample))
                if not resp_blocked:
                    ctx.log.info(
                        f"[SmartProxy] Error-recovery success: status {resp_status} from {next_node.key} for {domain}"
                    )
                    flow.response = resp
                    flow.error = None
                    flow.metadata["upstream_proxy"] = next_node
                    pool.set_current_node(domain, next_node)
                    pool.record_latency(next_node, (time.time() - start_time) * 1000.0)
                    return
                else:
                    ctx.log.warning(
                        f"[SmartProxy] Error-recovery attempt {retry_num} on {next_node.key} returned status {resp_status}. Quarantining globally..."
                    )
            else:
                ctx.log.warning(
                    f"[SmartProxy] Error-recovery attempt {retry_num} on {next_node.key} timed out. Quarantining globally..."
                )

            pool.mark_global_failed(next_node)
            last_failed = next_node


addons = [SmartProxyAddon()]
