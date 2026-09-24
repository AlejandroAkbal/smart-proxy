#!/bin/bash
IP=$(docker inspect osgkkckcgsko404w48ws0ocw-061909066721 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
URL="http://$IP:3000/booru/rule34.paheal.net/posts?baseEndpoint=rule34.paheal.net&limit=1"
echo "### paced monitor replica: 12 HEADs, 8s apart (~96s), exact monitor URL"
for i in $(seq 1 12); do
  curl -sS -I -o /dev/null -w "$(date -u +%H:%M:%S) HEAD http=%{http_code} time=%{time_total}\n" --max-time 40 "$URL"
  [ $i -lt 12 ] && sleep 8
done
