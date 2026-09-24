"""Deterministic proof: every pool refresh un-quarantines failed nodes and
overwrites their learned latency with the fresh (probe-target) latency."""
import time
from smart_proxy import pool, ProxyNode, COOLDOWN_SECONDS, ADAPTER_REFRESH_INTERVAL

print("ADAPTER_REFRESH_INTERVAL =", ADAPTER_REFRESH_INTERVAL, "s   COOLDOWN_SECONDS =", COOLDOWN_SECONDS)

n = ProxyNode(scheme="http", host="10.0.0.9", port=1080)
pool.update_nodes([n])
print("t0  node ema=%.1f global_cd=%.1f host_cd=%s" % (n.ema_latency_ms, n.global_cooldown_until, n.host_cooldowns))

# simulate: the node answers 403 on the target domain -> quarantined globally + host cooldown
n.record_global_failure()
n.record_host_failure("rule34.paheal.net")
print("after 403  ema=%.1f global_cd_until=%.1f host_cd(paheal)=%.1f" % (
    n.ema_latency_ms, n.global_cooldown_until, n.host_cooldowns.get("rule34.paheal.net", 0)))
print("  is_available_for(paheal) ->", n.is_available_for("rule34.paheal.net", time.time()))
print("  is_available_for(e621)   ->", n.is_available_for("e621.net", time.time()))

# simulate the next scheduled refresh: the probe only tests cp.cloudflare.com/generate_204,
# which still answers 204 -> node comes back "healthy" with a low probe latency
probe_result = ProxyNode(scheme="http", host="10.0.0.9", port=1080)
probe_result.ema_latency_ms = 25.0          # what _probe_node would set
pool.update_nodes([probe_result])
after = pool.nodes[0]
print("after refresh  ema=%.1f global_cd_until=%.1f host_cd(paheal)=%.1f" % (
    after.ema_latency_ms, after.global_cooldown_until, after.host_cooldowns.get("rule34.paheal.net", 0)))
print("  global quarantine forgotten:", after.global_cooldown_until == 0.0)
print("  re-ranked as fastest (ema reset to probe value):", after.ema_latency_ms == 25.0)
print("  still host-cooled for paheal:", not after.is_available_for("rule34.paheal.net", time.time()))
