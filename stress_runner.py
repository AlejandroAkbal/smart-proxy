import time
import random
import threading
import subprocess
import urllib.request
import urllib.error
import ssl
import json
import sys

# Target live endpoints and booru hosts
ENDPOINTS = [
    "https://r34.app/posts/e621.net?tags=-test{tag}",
    "https://r34.app/posts/e621.net?tags=solo",
    "https://r34.app/posts/e621.net?tags=pokemon",
    "https://r34.app/posts/e621.net?tags=animated",
    "https://r34.app/posts/e621.net?tags=cat",
    "https://r34.app/posts/e621.net?tags=dragon",
]

def run_burst(burst_id, count=10):
    threads = []
    results = []
    
    def fetch(url):
        t0 = time.time()
        try:
            res = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}:%{time_total}", url],
                capture_output=True,
                text=True,
                timeout=30
            )
            dt = time.time() - t0
            out = res.stdout.strip()
            status, el = out.split(":") if ":" in out else ("ERR", f"{dt:.3f}")
            results.append((url, status, float(el)))
        except Exception as e:
            results.append((url, "TIMEOUT", 30.0))

    t_start = time.time()
    for i in range(count):
        tag_val = f"{random.randint(100000, 999999)}_{int(time.time())}_{i}"
        template = random.choice(ENDPOINTS)
        target_url = template.format(tag=tag_val)
        t = threading.Thread(target=fetch, args=(target_url,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    total_el = time.time() - t_start
    p200 = sum(1 for _, s, _ in results if s == "200")
    latencies = [l for _, _, l in results]
    avg_l = sum(latencies) / len(latencies) if latencies else 0.0
    max_l = max(latencies) if latencies else 0.0
    min_l = min(latencies) if latencies else 0.0
    
    print(f"[{time.strftime('%H:%M:%S')}] Burst #{burst_id:03d}: {p200}/{count} OK (200) | Min: {min_l:.2f}s | Avg: {avg_l:.2f}s | Max: {max_l:.2f}s | Total Burst Time: {total_el:.2f}s", flush=True)
    return p200 == count

if __name__ == "__main__":
    print(f"Starting continuous stress & reliability loop at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    burst_idx = 1
    failures = 0
    total_bursts = 15
    for i in range(total_bursts):
        ok = run_burst(burst_idx, count=8)
        if not ok:
            failures += 1
        burst_idx += 1
        time.sleep(1.0)
    print(f"\nStress run complete: {total_bursts - failures}/{total_bursts} bursts passed 100% OK.")
