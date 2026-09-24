#!/bin/bash
IP=$(docker inspect osgkkckcgsko404w48ws0ocw-061909066721 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
URL="http://$IP:3000/booru/rule34.paheal.net/posts?baseEndpoint=rule34.paheal.net&limit=1"
echo "container IP: $IP"
echo "--- HEAD ---"
curl -sS -I -o /tmp/head.out -w 'HEAD http=%{http_code} time=%{time_total}\n' --max-time 90 "$URL"
echo "--- HEAD body/headers size: $(wc -c < /tmp/head.out)"
echo "--- GET ---"
curl -sS -o /dev/null -w 'GET  http=%{http_code} time=%{time_total}\n' --max-time 90 "$URL"
echo "--- GET e621 ---"
curl -sS -o /dev/null -w 'GET e621 http=%{http_code} time=%{time_total}\n' --max-time 90 "http://$IP:3000/booru/e621.net/posts?baseEndpoint=e621.net&limit=1"
