import asyncio
import base64
import concurrent.futures
import gzip
import io
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
from typing import Any, List, Optional, Set

# Reasonable default timeout on socket operations for slow booru backends
socket.setdefaulttimeout(15.0)

from mitmproxy import http as mitm_http
from mitmproxy.connection import Client, Server
from mitmproxy.net.server_spec import parse

logger = logging.getLogger("smart_proxy")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

CHALLENGE_RE = re.compile(
    rb"captcha|cf-chl|challenge-platform|unusual traffic|temporarily blocked|just a moment|security check|cloudflare-static|turnstile",
    re.I,
)
RETRY_STATUSES = {403, 429, 502, 503, 504}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

COOLDOWN_SECONDS = int(os.environ.get("COOLDOWN_SECONDS", "60"))
# Legacy parameter kept for backward-compatibility; retry loop is purely budget-driven
MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "10"))

# Strict end-to-end deadline budget and timeouts (user SLA: 60s global budget, 15s initial attempt)
GLOBAL_REQUEST_TIMEOUT = float(os.environ.get("GLOBAL_REQUEST_TIMEOUT", "60.0"))
INITIAL_REQUEST_TIMEOUT = float(os.environ.get("INITIAL_REQUEST_TIMEOUT", "15.0"))
REPLAY_TIMEOUT = float(os.environ.get("REPLAY_TIMEOUT", "15.0"))
UPSTREAM_CONNECT_TIMEOUT = float(os.environ.get("UPSTREAM_CONNECT_TIMEOUT", "10.0"))
MAX_DECOMPRESSED_BYTES = int(os.environ.get("MAX_DECOMPRESSED_BYTES", str(20 * 1024 * 1024)))
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
        now = time.time()
        self.failure_count += 1
        if len(self.host_cooldowns) >= 500:
            active = {k: v for k, v in self.host_cooldowns.items() if v > now}
            if len(active) >= 500:
                # Evict oldest 100 entries
                sorted_keys = sorted(active.keys(), key=lambda k: active[k])
                for k in sorted_keys[:100]:
                    active.pop(k, None)
            self.host_cooldowns = active
        self.host_cooldowns[domain] = now + COOLDOWN_SECONDS
        self.ema_latency_ms += 500.0

    def record_global_failure(self):
        self.failure_count += 1
        self.global_cooldown_until = time.time() + COOLDOWN_SECONDS
        self.ema_latency_ms += 1500.0


def _extract_root_domain(host: str) -> str:
    """Extract root domain to group subdomains (e.g. api.example.com -> example.com)."""
    if not host:
        return "default"
    host = host.lower().strip(".")
    if host.startswith("["):
        end = host.find("]")
        if end != -1:
            return host[:end+1]
    host = host.split(":")[0]
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
                    # Preserve learned production EMA latency if node has live history
                    if old.success_count == 0:
                        old.ema_latency_ms = n.ema_latency_ms
                    # Only clear global cooldown if it has already expired
                    if old.global_cooldown_until <= time.time():
                        old.global_cooldown_until = 0.0
                    merged.append(old)
                else:
                    merged.append(n)
            self.nodes = merged
            valid_keys = {n.key for n in self.nodes}
            self.current_nodes = {
                d: existing[n.key] if n.key in existing else n
                for d, n in self.current_nodes.items()
                if n.key in valid_keys
            }

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
            return min(self.nodes, key=lambda n: n.get_effective_cooldown(domain))

    def get_current_or_best(self, domain: str) -> Optional[ProxyNode]:
        """Keeps active sticky node for domain if healthy and has token.
        Performs soft latency re-ranking: if current node latency has degraded
        significantly (> 1.5x) compared to the best available alternative,
        it lazily migrates stickiness to the faster node.
        """
        with self.lock:
            now = time.time()
            current = self.current_nodes.get(domain)
            if current and current.is_available_for(domain, now):
                # Check for soft re-ranking against other healthy candidates
                healthy_alts = [
                    n for n in self.nodes
                    if n.key != current.key and n.is_available_for(domain, now)
                ]
                if healthy_alts:
                    healthy_alts.sort(key=lambda n: (n.ema_latency_ms, n.failure_count))
                    for alt in healthy_alts:
                        if current.ema_latency_ms > (alt.ema_latency_ms * 1.5):
                            if alt.try_consume_token():
                                self.current_nodes[domain] = alt
                                return alt
                        else:
                            break

                if current.try_consume_token():
                    return current
        return self.select_best_for(domain, check_rate_limit=True)

    def has_untried_healthy(self, domain: str, tried_keys: Set[str]) -> bool:
        """Returns True if there is at least one healthy, untried candidate for domain."""
        with self.lock:
            now = time.time()
            return any(
                n.key not in tried_keys and n.is_available_for(domain, now)
                for n in self.nodes
            )

    def select_candidate_for(
        self, domain: str, exclude_keys: Optional[Set[str]] = None, check_rate_limit: bool = True
    ) -> Optional[ProxyNode]:
        """Picks the best untried candidate node for domain during a request attempt chain."""
        with self.lock:
            if not self.nodes:
                return None
            exclude = exclude_keys or set()
            now = time.time()
            healthy = [
                n for n in self.nodes
                if n.key not in exclude and n.is_available_for(domain, now)
            ]
            if healthy:
                healthy.sort(key=lambda n: (n.ema_latency_ms, n.failure_count))
                if check_rate_limit:
                    for candidate in healthy:
                        if candidate.try_consume_token():
                            return candidate
                return healthy[0]
            return None

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


def _probe_node(node: ProxyNode, target_url: str = "https://cp.cloudflare.com/generate_204", timeout: float = 1.2) -> Optional[ProxyNode]:
    """Fast pre-flight probe testing real HTTPS CONNECT tunnel within 1.2s."""
    t0 = time.time()
    conn = None
    try:
        import http.client
        import ssl

        conn = http.client.HTTPConnection(node.host, node.port, timeout=timeout)
        tunnel_headers = {}
        if node.auth:
            encoded_auth = base64.b64encode(node.auth.encode()).decode()
            tunnel_headers["Proxy-Authorization"] = f"Basic {encoded_auth}"
        conn.set_tunnel("cp.cloudflare.com:443", headers=tunnel_headers)
        conn.connect()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        conn.sock = context.wrap_socket(conn.sock, server_hostname="cp.cloudflare.com")
        conn.request("GET", "/generate_204", headers={"Host": "cp.cloudflare.com", "Connection": "close"})
        resp = conn.getresponse()
        resp.read(512)
        duration_ms = (time.time() - t0) * 1000.0
        if resp.status in (200, 204):
            node.ema_latency_ms = duration_ms
            return node
    except Exception:
        pass
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
    return None


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
        valid_raw = [n for n in all_nodes if n.scheme in ("http", "https")]
        if valid_raw:
            if UPSTREAM_PROXIES_ENV and not ADAPTER_URL:
                pool.update_nodes(valid_raw)
                logger.info(f"[SmartProxy] Test pool loaded: {len(valid_raw)} HTTP nodes active.")
            else:
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                    probed = list(executor.map(_probe_node, valid_raw))
                verified = [n for n in probed if n is not None]
                if verified:
                    pool.update_nodes(verified)
                    logger.info(f"[SmartProxy] Verified pool: {len(verified)}/{len(valid_raw)} healthy nodes active.")
                else:
                    pool.update_nodes(valid_raw)
                    logger.info(f"[SmartProxy] Fallback: {len(valid_raw)} unverified nodes loaded.")


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


def _check_auth(flow: mitm_http.HTTPFlow) -> bool:
    if not PROXY_AUTH:
        return True
    auth_header = flow.request.headers.get("Proxy-Authorization", "").strip()
    if not auth_header:
        return False
    parts = auth_header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "basic":
        return False
    try:
        decoded = base64.b64decode(parts[1]).decode("utf-8")
        import hmac
        return hmac.compare_digest(decoded, PROXY_AUTH)
    except Exception:
        return False


def _decompress_body_safe(
    content: bytes,
    encoding: Optional[str],
    max_bytes: int = MAX_DECOMPRESSED_BYTES,
) -> tuple[bytes, bool]:
    """Safely decompresses body with maximum streaming expansion cap against compression bombs.
    Returns (decompressed_content, True) on successful decompression or uncompressed pass-through.
    Returns (raw_content, False) if decompression failed, truncated, or exceeded max_bytes.
    """
    if not content:
        return b"", True
    enc = (encoding or "").lower().strip()
    if not enc or enc == "identity":
        return content, True

    try:
        if enc in ("gzip", "x-gzip"):
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            decomp = d.decompress(content, max_bytes + 1)
            if len(decomp) > max_bytes or len(d.unconsumed_tail) > 0:
                logger.warning(f"[SmartProxy] Gzip bomb protection triggered (> {max_bytes} bytes)")
                return content, False
            if not d.eof:
                logger.warning("[SmartProxy] Gzip stream truncated / missing EOF")
                return content, False
            return decomp, True

        elif enc in ("deflate", "raw-deflate"):
            for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                try:
                    d = zlib.decompressobj(wbits)
                    decomp = d.decompress(content, max_bytes + 1)
                    if len(decomp) > max_bytes or len(d.unconsumed_tail) > 0:
                        logger.warning(f"[SmartProxy] Deflate bomb protection triggered (> {max_bytes} bytes)")
                        return content, False
                    if d.eof:
                        return decomp, True
                except Exception:
                    continue
            return content, False

        elif enc in ("br", "brotli"):
            import brotli
            d = brotli.Decompressor()
            chunks = []
            total = 0
            for i in range(0, len(content), 16384):
                out = d.process(content[i : i + 16384])
                if out:
                    chunks.append(out)
                    total += len(out)
                    if total > max_bytes:
                        logger.warning(f"[SmartProxy] Brotli bomb protection triggered (> {max_bytes} bytes)")
                        return content, False
            if not d.is_finished():
                return content, False
            return b"".join(chunks), True

        elif enc in ("zstd", "zstandard"):
            import zstandard
            dctx = zstandard.ZstdDecompressor()
            reader = dctx.read_to_iter(io.BytesIO(content), read_size=16384)
            chunks = []
            total = 0
            for chunk in reader:
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    logger.warning(f"[SmartProxy] Zstd bomb protection triggered (> {max_bytes} bytes)")
                    return content, False
            return b"".join(chunks), True
    except Exception as e:
        logger.warning(f"[SmartProxy] Decompression failed for encoding '{enc}': {e}")
        return content, False

    return content, True


def _extract_sample_body(content: bytes, encoding: Optional[str]) -> bytes:
    if not content:
        return b""
    enc = (encoding or "").lower().strip()
    if not enc or enc == "identity":
        return content[:16384]
    sample, _ = _decompress_body_safe(content, enc, max_bytes=16384)
    return sample[:16384]


def _read_with_deadline(
    resp: Any,
    timeout: float,
    sock: Optional[socket.socket] = None,
    method: str = "GET",
    status_code: int = 200,
    max_bytes: int = 100 * 1024 * 1024,
) -> bytes:
    """Reads response with strict total deadline to prevent Slowloris resource leaks.
    RFC 9110 compliant: HEAD and empty statuses (204, 304, 1xx) return b'' immediately.
    Enforces Content-Length completeness to prevent silent truncation.
    """
    if method.upper() == "HEAD" or status_code in (204, 304) or (100 <= status_code < 200):
        return b""

    expected_len: Optional[int] = None
    if hasattr(resp, "getheader"):
        cl_hdr = resp.getheader("content-length")
        if cl_hdr and cl_hdr.strip().isdigit():
            expected_len = int(cl_hdr.strip())

    deadline = time.monotonic() + timeout
    chunks = []
    total_len = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Upstream response read deadline exceeded")
        if sock:
            sock.settimeout(max(0.01, remaining))
        elif hasattr(resp, "fp") and resp.fp:
            raw_sock = getattr(resp.fp, "raw", None)
            if raw_sock and hasattr(raw_sock, "_sock") and raw_sock._sock:
                raw_sock._sock.settimeout(max(0.01, remaining))
        if getattr(resp, "chunked", False):
            chunk = resp.read(65536)
        elif hasattr(resp, "fp") and resp.fp and hasattr(resp.fp, "read1"):
            chunk = resp.fp.read1(65536)
        else:
            chunk = resp.read(65536)
        if not chunk:
            break
        chunks.append(chunk)
        total_len += len(chunk)
        if expected_len is not None and total_len >= expected_len:
            break
        if total_len > max_bytes:
            raise ValueError("Response payload exceeds maximum allowed size")

    if expected_len is not None and total_len < expected_len:
        raise ConnectionError(f"Incomplete response read: expected {expected_len} bytes, received {total_len} bytes")

    return b"".join(chunks)


# Dedicated persistent executor for async worker offloading
_WORKER_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=32, thread_name_prefix="smartproxy-worker")
_active_addon: Optional["SmartProxyAddon"] = None


def _fetch_upstream_sync(flow: mitm_http.HTTPFlow, node: ProxyNode, timeout: float = REPLAY_TIMEOUT) -> Optional[mitm_http.Response]:
    """Synchronous worker function run in background executor thread with strict absolute deadline."""
    global _active_addon
    start_mono = time.monotonic()
    deadline = start_mono + timeout

    def check_deadline() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0.05:
            raise TimeoutError(f"Replay deadline exceeded ({timeout:.1f}s)")
        return remaining

    parsed = urllib.parse.urlsplit(flow.request.url)
    is_https = parsed.scheme == "https"
    target_host = parsed.hostname
    target_port = parsed.port or (443 if is_https else 80)

    headers = dict(flow.request.headers)
    for h in ["proxy-authorization", "proxy-connection", "connection", "keep-alive", "host", "Host"]:
        headers.pop(h, None)
    headers["Host"] = target_host
    headers["Connection"] = "close"

    encoded_auth = None
    if node.auth:
        encoded_auth = base64.b64encode(node.auth.encode()).decode()
        if not is_https:
            headers["Proxy-Authorization"] = f"Basic {encoded_auth}"

    body = flow.request.content if flow.request.content else None

    conn = None
    registered_socks: list[socket.socket] = []
    client_conn = getattr(flow, "client_conn", None)
    client_id = getattr(client_conn, "id", None) if client_conn else None

    try:
        import http.client
        import ssl

        # Allow upstream servers/proxies with extensive header sets
        http.client._MAXHEADERS = 1000

        conn = http.client.HTTPConnection(node.host, node.port, timeout=check_deadline())

        if is_https:
            tunnel_headers = {}
            if encoded_auth:
                tunnel_headers["Proxy-Authorization"] = f"Basic {encoded_auth}"
            conn.set_tunnel(f"{target_host}:{target_port}", headers=tunnel_headers)
            conn.connect()
            if client_id and _active_addon and conn.sock:
                _active_addon.register_active_socket(client_id, conn.sock)
                registered_socks.append(conn.sock)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn.sock.settimeout(check_deadline())
            conn.sock = context.wrap_socket(conn.sock, server_hostname=target_host)
            if client_id and _active_addon and conn.sock:
                _active_addon.register_active_socket(client_id, conn.sock)
                registered_socks.append(conn.sock)
        else:
            conn.connect()
            if client_id and _active_addon and conn.sock:
                _active_addon.register_active_socket(client_id, conn.sock)
                registered_socks.append(conn.sock)

        req_path = flow.request.url if not is_https else (parsed.path or "/")
        if parsed.query and is_https:
            req_path += "?" + parsed.query

        if conn.sock:
            conn.sock.settimeout(check_deadline())
        conn.request(flow.request.method, req_path, body=body, headers=headers)
        if conn.sock:
            conn.sock.settimeout(check_deadline())
        resp = conn.getresponse()
        raw_content = _read_with_deadline(
            resp,
            timeout=check_deadline(),
            sock=conn.sock,
            method=flow.request.method,
            status_code=resp.status,
        )

        is_head = flow.request.method.upper() == "HEAD"
        is_empty_status = resp.status in (204, 304) or (100 <= resp.status < 200)
        orig_clen = resp.getheader("content-length")
        enc_header = resp.getheader("content-encoding")

        # RFC 9110 Representation headers:
        # Only decompress 2xx representation responses.
        # Preserve original Content-Encoding and raw bytes on origin errors (status >= 400).
        if resp.status < 400 and not is_head and not is_empty_status:
            content, decompress_ok = _decompress_body_safe(raw_content, enc_header)
        else:
            content = raw_content
            decompress_ok = False

        drop_headers = {
            "transfer-encoding", "connection", "keep-alive", "proxy-authenticate"
        }
        if not is_head and not is_empty_status:
            drop_headers.add("content-length")

        # Only strip Content-Encoding if 2xx body was successfully decompressed
        if decompress_ok and enc_header:
            drop_headers.add("content-encoding")

        resp_headers = [
            (str(k).encode("utf-8", errors="replace"), str(v).encode("utf-8", errors="replace"))
            for k, v in resp.getheaders()
            if k.lower() not in drop_headers
        ]
        res = mitm_http.Response.make(resp.status, content, resp_headers)
        # RFC 9110 §9.3.2: preserve original representation Content-Length for HEAD and empty statuses
        if (is_head or is_empty_status) and orig_clen is not None:
            res.headers["content-length"] = orig_clen
        return res
    except Exception as e:
        logger.warning(f"[SmartProxy] Replay upstream connection failed to {node.key}: {type(e).__name__}: {e}")
        return None
    finally:
        for s in registered_socks:
            if client_id and _active_addon:
                _active_addon.unregister_active_socket(client_id, s)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


class SmartProxyAddon:
    def __init__(self):
        global _active_addon
        _active_addon = self
        self.authenticated_conns: Set[str] = set()
        self.active_sockets_by_client: dict[str, set[socket.socket]] = {}
        self.socket_lock = threading.Lock()

    def register_active_socket(self, client_id: str, sock: socket.socket) -> None:
        with self.socket_lock:
            if client_id not in self.active_sockets_by_client:
                self.active_sockets_by_client[client_id] = set()
            self.active_sockets_by_client[client_id].add(sock)

    def unregister_active_socket(self, client_id: str, sock: socket.socket) -> None:
        with self.socket_lock:
            if client_id in self.active_sockets_by_client:
                self.active_sockets_by_client[client_id].discard(sock)

    def load(self, loader):
        loader.add_option(
            "connection_strategy", str, "lazy", "Mitmproxy connection strategy"
        )
        loader.add_option(
            "connect_timeout", float, min(INITIAL_REQUEST_TIMEOUT, UPSTREAM_CONNECT_TIMEOUT), "Upstream connect timeout"
        )

    def running(self) -> None:
        _refresh_from_sources()
        t = threading.Thread(target=_background_updater, daemon=True)
        t.start()
        logger.info("[SmartProxy] Background proxy pool updater started.")

    def client_disconnected(self, client: Client) -> None:
        self.authenticated_conns.discard(client.id)
        with self.socket_lock:
            socks = self.active_sockets_by_client.pop(client.id, set())
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass

    def http_connect(self, flow: mitm_http.HTTPFlow) -> None:
        domain = _extract_root_domain(flow.request.pretty_host)
        flow.metadata["target_domain"] = domain
        flow.metadata["start_time"] = time.monotonic()

        if not PROXY_AUTH:
            return

        if _check_auth(flow):
            self.authenticated_conns.add(flow.client_conn.id)
            return
        else:
            flow.response = mitm_http.Response.make(
                407,
                b"Proxy Authentication Required\n",
                {"Proxy-Authenticate": 'Basic realm="Smart Proxy"'},
            )

    def next_layer(self, nextlayer) -> None:
        pass

    def requestheaders(self, flow: mitm_http.HTTPFlow) -> None:
        client_conn = getattr(flow, "client_conn", None)
        client_id = getattr(client_conn, "id", None) if client_conn else None
        is_authenticated = (client_id in self.authenticated_conns) or _check_auth(flow)
        if not is_authenticated:
            flow.response = mitm_http.Response.make(
                407,
                b"Proxy Authentication Required\n",
                {"Proxy-Authenticate": 'Basic realm="Smart Proxy"'},
            )
            return

        if client_id:
            self.authenticated_conns.add(client_id)
        flow.request.headers.pop("Proxy-Authorization", None)

    async def request(self, flow: mitm_http.HTTPFlow) -> None:
        if flow.response is not None:
            return

        client_conn = getattr(flow, "client_conn", None)
        client_id = getattr(client_conn, "id", None) if client_conn else None
        is_authenticated = (client_id in self.authenticated_conns) or _check_auth(flow)
        if not is_authenticated:
            flow.response = mitm_http.Response.make(
                407,
                b"Proxy Authentication Required\n",
                {"Proxy-Authenticate": 'Basic realm="Smart Proxy"'},
            )
            return

        if client_id:
            self.authenticated_conns.add(client_id)
        flow.request.headers.pop("Proxy-Authorization", None)

        target_host = flow.request.pretty_host
        domain = _extract_root_domain(target_host)
        flow.metadata["target_domain"] = domain

        method = flow.request.method.upper()
        start_time = flow.metadata.get("start_time") or time.monotonic()
        flow.metadata["start_time"] = start_time

        last_failed: Optional[ProxyNode] = None
        attempt = 0
        tried_keys: Set[str] = set()

        while True:
            attempt += 1
            now = time.monotonic()
            remaining_budget = GLOBAL_REQUEST_TIMEOUT - (now - start_time)
            if remaining_budget < 1.0:
                logger.warning(
                    f"[SmartProxy] Request on {domain} exceeded global budget (remaining {remaining_budget:.2f}s < 1.0s). Aborting."
                )
                break

            if client_conn and not getattr(client_conn, "connected", True):
                logger.info(f"[SmartProxy] Client disconnected on {domain}, aborting attempt loop.")
                break

            if attempt == 1:
                node = pool.get_current_or_best(domain)
                if not node or node.key in tried_keys:
                    node = pool.select_candidate_for(domain, exclude_keys=tried_keys)
            else:
                node = pool.select_candidate_for(domain, exclude_keys=tried_keys)

            if not node:
                logger.warning(
                    f"[SmartProxy] All available proxy nodes exhausted for {domain} on attempt {attempt}."
                )
                break

            tried_keys.add(node.key)

            if attempt == 1:
                attempt_timeout = min(INITIAL_REQUEST_TIMEOUT, remaining_budget)
            else:
                attempt_timeout = min(REPLAY_TIMEOUT, remaining_budget)

            logger.info(
                f"[SmartProxy] Attempt {attempt} for {method} {flow.request.url} via {node.key} "
                f"(timeout {attempt_timeout:.1f}s, budget left {remaining_budget:.1f}s)"
            )

            loop = asyncio.get_running_loop()
            try:
                resp = await asyncio.wait_for(
                    loop.run_in_executor(_WORKER_EXECUTOR, _fetch_upstream_sync, flow, node, attempt_timeout),
                    timeout=attempt_timeout + 0.2,
                )
            except asyncio.TimeoutError:
                logger.warning(f"[SmartProxy] Attempt {attempt} on {node.key} hit asyncio timeout ({attempt_timeout:.1f}s)")
                resp = None
            except Exception as e:
                logger.warning(f"[SmartProxy] Attempt {attempt} on {node.key} failed: {e}")
                resp = None

            if resp is not None:
                resp_status = resp.status_code
                resp_body = resp.content or b""
                resp_sample = _extract_sample_body(resp_body, resp.headers.get("content-encoding"))
                resp_blocked = (resp_status in RETRY_STATUSES) or bool(CHALLENGE_RE.search(resp_sample))

                allow_replay = (method in SAFE_METHODS) or (flow.request.headers.get("X-Allow-Mutation-Replay") == "1")

                remaining_after = GLOBAL_REQUEST_TIMEOUT - (time.monotonic() - start_time)
                has_untried = pool.has_untried_healthy(domain, tried_keys)
                if not resp_blocked or not allow_replay or remaining_after < 1.0 or not has_untried:
                    flow.response = resp
                    flow.metadata["upstream_proxy"] = node
                    if not resp_blocked:
                        pool.set_current_node(domain, node)
                        pool.record_latency(node, (time.monotonic() - start_time) * 1000.0)
                    else:
                        pool.mark_host_failed(node, domain)
                    return
                else:
                    logger.warning(
                        f"[SmartProxy] Attempt {attempt} on {node.key} returned status {resp_status}/challenge. Quarantining for {domain}..."
                    )
                    pool.mark_host_failed(node, domain)
            else:
                logger.warning(
                    f"[SmartProxy] Attempt {attempt} on {node.key} timed out or connection failed. Quarantining globally..."
                )
                pool.mark_global_failed(node)
                allow_replay = (method in SAFE_METHODS) or (flow.request.headers.get("X-Allow-Mutation-Replay") == "1")
                if not allow_replay:
                    logger.warning(
                        f"[SmartProxy] Attempt {attempt} failed on unsafe method {method} - aborting further attempts."
                    )
                    break

            last_failed = node

        if flow.response is None:
            flow.response = mitm_http.Response.make(
                504,
                b"504 Gateway Timeout - Smart Proxy: all upstream attempts failed or SLA budget exceeded\n",
                [(b"Content-Type", b"text/plain"), (b"Connection", b"close")],
            )

    async def response(self, flow: mitm_http.HTTPFlow) -> None:
        pass

    async def error(self, flow: mitm_http.HTTPFlow) -> None:
        pass


addons = [SmartProxyAddon()]
