#!/usr/bin/env python3
"""
Deterministic Adversarial SLA Verification Probe:
Tests the SLA contract:
  - Initial attempt budget = 12.0s maximum.
  - Downstream timeouts (30s UptimeRobot boundary) must be eliminated.
  - Transparent forward proxy must failover to healthy standby nodes when initial attempt hangs.

Expected behavior under SLA contract:
  When the initial chosen upstream node hangs (blackholes), smart-proxy must abort the initial
  attempt within the 12.0s budget, failover to a healthy standby node, and return HTTP 200 to the client
  within the global request budget (< 29.0s).

Actual behavior under updated smart_proxy.py:
  1. smart_proxy.py line 750 sets mitmproxy option `tcp_timeout` to 12s (INITIAL_REQUEST_TIMEOUT).
     In mitmproxy, `tcp_timeout` governs downstream client inactivity.
  2. smart_proxy.py lines 806-820 implements `_initial_attempt_watchdog`, which only executes:
       flow.server_conn.error = f"Initial attempt timeout exceeded ({timeout}s)"
     In mitmproxy, `server_conn.error` is informational metadata for connection reuse; setting it on
     an active flow is a no-op that neither closes the upstream socket nor triggers replay.
  3. At 12.0s, mitmproxy's TimeoutWatchdog forcibly disconnects the downstream client socket.
  4. smart_proxy.py lines 1002-1005 detects `not client_conn.connected` and aborts error recovery.
  5. The downstream client receives an unhandled socket drop (RemoteDisconnected) at ~13s;
     no failover occurs, and downstream SLA is violated.

Exit code:
  0 if compliant (failover succeeds and returns HTTP 200).
  1 if rejected (contract violated).
"""

import http.client
import socket
import sys
import threading
import time

PROXY_PORT = 29480
BLACKHOLE_PORT = 29401
HEALTHY_PORT = 29402

def run_probe():
    # 1. Start blackhole proxy on 29401 (accepts connection, never replies)
    ls_blackhole = socket.socket()
    ls_blackhole.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls_blackhole.bind(("0.0.0.0", BLACKHOLE_PORT))
    ls_blackhole.listen(5)

    # 2. Start healthy proxy on 29402 (returns HTTP 200)
    ls_healthy = socket.socket()
    ls_healthy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls_healthy.bind(("0.0.0.0", HEALTHY_PORT))
    ls_healthy.listen(5)

    stop_event = threading.Event()

    def blackhole_worker():
        while not stop_event.is_set():
            try:
                ls_blackhole.settimeout(0.5)
                conn, _ = ls_blackhole.accept()
                def hold(c):
                    try:
                        time.sleep(40)
                    finally:
                        try:
                            c.close()
                        except Exception:
                            pass
                threading.Thread(target=hold, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def healthy_worker():
        while not stop_event.is_set():
            try:
                ls_healthy.settimeout(0.5)
                conn, _ = ls_healthy.accept()
                def handle(c):
                    try:
                        data = b""
                        while b"\r\n\r\n" not in data:
                            chunk = c.recv(1024)
                            if not chunk:
                                return
                            data += chunk
                        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\nhealthy-payload")
                    finally:
                        try:
                            c.close()
                        except Exception:
                            pass
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    t1 = threading.Thread(target=blackhole_worker, daemon=True)
    t2 = threading.Thread(target=healthy_worker, daemon=True)
    t1.start()
    t2.start()

    time.sleep(0.5)
    t0 = time.time()
    result_status = None
    exception_caught = None

    try:
        conn = http.client.HTTPConnection("127.0.0.1", PROXY_PORT, timeout=30.0)
        conn.request("GET", "http://rule34.xxx/sla-test", headers={"Host": "rule34.xxx"})
        resp = conn.getresponse()
        result_status = resp.status
    except Exception as e:
        exception_caught = e
    finally:
        elapsed = time.time() - t0
        stop_event.set()
        ls_blackhole.close()
        ls_healthy.close()

    print(f"Elapsed: {elapsed:.2f}s")
    if result_status == 200:
        print("PASS: Smart proxy successfully failed over to healthy standby within SLA budget.")
        sys.exit(0)
    else:
        print("FAIL (CONTRACT VIOLATION):")
        print(f"  Expected: HTTP 200 via failover within SLA (<= 29.0s)")
        print(f"  Actual: result_status={result_status}, exception={type(exception_caught).__name__}: {exception_caught}")
        print("  smart_proxy.py failed to failover when initial attempt hung; downstream client socket was terminated.")
        sys.exit(1)

if __name__ == "__main__":
    run_probe()
