#!/usr/bin/env bash
# Disposable lab only: never changes the host firewall or an existing network.
set -euo pipefail
prefix="aisecure-lab-${RANDOM}-$$"
image="$prefix"
cleanup() {
  docker rm -f "$prefix-app" "$prefix-gateway" "$prefix-receiver" >/dev/null 2>&1 || true
  docker network rm "$prefix-isolated" "$prefix-receiver-net" >/dev/null 2>&1 || true
  docker image rm "$image" >/dev/null 2>&1 || true
}
trap cleanup EXIT
root="$(cd "$(dirname "$0")/.." && pwd)"
docker build -q -t "$image" -f "$root/deployment/Dockerfile" "$root"
docker network create --internal "$prefix-isolated" >/dev/null
docker network create --internal "$prefix-receiver-net" >/dev/null
runopts=(--read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=32m --memory 192m --cpus 1)
docker run -d --name "$prefix-receiver" --network "$prefix-receiver-net" --network-alias receiver "${runopts[@]}" "$image" receiver >/dev/null
docker create --name "$prefix-gateway" --network "$prefix-isolated" --network-alias gateway "${runopts[@]}" "$image" gateway >/dev/null
docker network connect "$prefix-receiver-net" "$prefix-gateway"
docker start "$prefix-gateway" >/dev/null
sink_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$prefix-receiver")
# Readiness is local to the isolated gateway container.
for attempt in {1..30}; do
  if docker exec "$prefix-gateway" python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8080/",timeout=1)' >/dev/null 2>&1; then break; fi
  sleep 1
done
docker run --rm --name "$prefix-app" --network "$prefix-isolated" "${runopts[@]}" -e "SINK_IP=$sink_ip" "$image" client
# Check independently at the receiver, not just the gateway's success response.
docker exec "$prefix-receiver" python -c 'import json,urllib.request; x=json.load(urllib.request.urlopen("http://127.0.0.1:8080/")); assert x["received_count"]==1; assert x["received"][0]["input"]=="SYNTHETIC PUBLIC ACCEPTANCE MESSAGE"; print("PASS: independent receiver confirms exactly one expected payload")'
docker stop "$prefix-gateway" >/dev/null
docker run --rm --name "$prefix-app" --network "$prefix-isolated" "${runopts[@]}" -e "SINK_IP=$sink_ip" "$image" client stopped
