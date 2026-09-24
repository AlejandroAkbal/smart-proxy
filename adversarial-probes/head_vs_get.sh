#!/bin/bash
# Adversarial load probe: HEAD vs GET through the live smart proxy
P='http://OypeiLQmtcJe6aM0:XJPIf2n2yjtgZZVWgOMHiqVEWQmWn3RL@91.107.213.51:24000'
N=${1:-10}
echo "### HEAD x$N (e621.net, a domain that 403s on some nodes)"
for i in $(seq 1 $N); do
  curl -ksS --http1.1 -I -x "$P" https://e621.net/posts.json?limit=1 -o /dev/null \
    -w "HEAD http=%{http_code} time=%{time_total}\n" --max-time 120 || echo "HEAD curl error $?"
done
echo "### GET x$N (e621.net)"
for i in $(seq 1 $N); do
  curl -ksS --http1.1 -x "$P" https://e621.net/posts.json?limit=1 -o /dev/null \
    -w "GET  http=%{http_code} time=%{time_total}\n" --max-time 120 || echo "GET curl error $?"
done
