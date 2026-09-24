#!/bin/bash
# Adversarial probe: thread/executor behaviour of the LIVE smart-proxy under parallel replay load
C=smart-proxy-hp2ewpogk3oxhqvf6wkb46iz
P='http://OypeiLQmtcJe6aM0:XJPIf2n2yjtgZZVWgOMHiqVEWQmWn3RL@127.0.0.1:24000'
U='https://e621.net/posts.json?limit=1'

threads() { docker exec $C sh -c 'grep Threads /proc/1/status'; }

echo "### baseline threads (idle):"; threads

echo "### launching 40 parallel replays (e621 HEAD, a domain that 403s on some nodes)"
rm -f /tmp/burst_*.out
for i in $(seq 1 40); do
  ( curl -ksS -I -x "$P" "$U" -o /dev/null -w "%{http_code} %{time_total}\n" --max-time 120 > /tmp/burst_$i.out 2>&1 ) &
done
for t in $(seq 1 20); do
  sleep 2
  echo "t=+$((t*2))s $(threads)"
done
wait
echo "### after burst:"; threads
echo "### per-request results (code time):"
cat /tmp/burst_*.out | sort | uniq -c | sort -rn
echo "### slowest 10:"
cat /tmp/burst_*.out | sort -k2 -rn | head -10
rm -f /tmp/burst_*.out
