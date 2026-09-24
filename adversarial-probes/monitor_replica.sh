#!/bin/bash
IP=$(docker inspect osgkkckcgsko404w48ws0ocw-061909066721 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
API="http://$IP:3000/booru/rule34.paheal.net/posts?baseEndpoint=rule34.paheal.net&limit=1"
API621="http://$IP:3000/booru/e621.net/posts?baseEndpoint=e621.net&limit=1"
echo "### monitor replica: HEAD api/booru/rule34.paheal.net x15"
for i in $(seq 1 15); do
  curl -sS -I -o /dev/null -x "" -w "HEAD-paheal http=%{http_code} total=%{time_total}\n" --max-time 120 "$API"
done
echo "### monitor replica: HEAD api/booru/e621.net x10"
for i in $(seq 1 10); do
  curl -sS -I -o /dev/null -w "HEAD-e621   http=%{http_code} total=%{time_total}\n" --max-time 120 "$API621"
done
