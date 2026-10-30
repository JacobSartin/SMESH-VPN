#!/bin/sh
# End-to-end check on one Linux machine: a discovery server and two clients,
# each client in its own network namespace (standing in for separate hosts),
# then ping across the overlay in both directions.
#
# Usage: sudo scripts/netns-demo.sh [bin-dir]
#   bin-dir holds smesh-server_linux_amd64 and smesh-client_linux_amd64 (default: bin).
set -eu

BIN=$(cd "${1:-bin}" && pwd)
SERVER="$BIN/smesh-server_linux_amd64"
CLIENT="$BIN/smesh-client_linux_amd64"
WORK=$(mktemp -d)
BRIDGE=smesh-br
SERVER_IP=192.168.77.1
PIDS=""

cleanup() {
	status=$?
	for pid in $PIDS; do kill "$pid" 2>/dev/null || true; done
	wait 2>/dev/null || true
	if [ "$status" -ne 0 ]; then
		for log in "$WORK"/*.log; do echo "==> $log"; cat "$log"; done
	fi
	ip netns del smesh-a 2>/dev/null || true
	ip netns del smesh-b 2>/dev/null || true
	ip link del "$BRIDGE" 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

echo "--- provisioning identities"
"$SERVER" init-ca -dir "$WORK/ca"
"$SERVER" issue-client -ca-dir "$WORK/ca" -out "$WORK/a"
"$SERVER" issue-client -ca-dir "$WORK/ca" -out "$WORK/b"

echo "--- building the underlay network"
ip link add "$BRIDGE" type bridge
ip addr add "$SERVER_IP/24" dev "$BRIDGE"
ip link set "$BRIDGE" up
for peer in a b; do
	case $peer in a) addr=192.168.77.2 ;; b) addr=192.168.77.3 ;; esac
	ip netns add "smesh-$peer"
	ip link add "veth-$peer" type veth peer name eth0 netns "smesh-$peer"
	ip link set "veth-$peer" master "$BRIDGE" up
	ip -n "smesh-$peer" addr add "$addr/24" dev eth0
	ip -n "smesh-$peer" link set eth0 up
	ip -n "smesh-$peer" link set lo up
done

echo "--- starting discovery server"
"$SERVER" serve -ca-dir "$WORK/ca" -listen "$SERVER_IP:8081" -ip "$SERVER_IP" >"$WORK/server.log" 2>&1 &
PIDS="$PIDS $!"
sleep 1

echo "--- starting clients"
ip netns exec smesh-a "$CLIENT" -discovery "https://$SERVER_IP:8081" -dir "$WORK/a" -vpn-ip 10.77.0.2/24 >"$WORK/a.log" 2>&1 &
PIDS="$PIDS $!"
ip netns exec smesh-b "$CLIENT" -discovery "https://$SERVER_IP:8081" -dir "$WORK/b" -vpn-ip 10.77.0.3/24 >"$WORK/b.log" 2>&1 &
PIDS="$PIDS $!"

wait_for_ping() {
	ns=$1 target=$2
	for _ in $(seq 1 20); do
		if ip netns exec "$ns" ping -c 1 -W 1 "$target" >/dev/null 2>&1; then
			ip netns exec "$ns" ping -c 3 "$target"
			return 0
		fi
		sleep 1
	done
	echo "ping from $ns to $target failed" >&2
	return 1
}

echo "--- ping a -> b"
wait_for_ping smesh-a 10.77.0.3
echo "--- ping b -> a"
wait_for_ping smesh-b 10.77.0.2

echo "--- full-MTU packet a -> b (1400-byte IP packet, do not fragment)"
ip netns exec smesh-a ping -c 2 -s 1372 -M do 10.77.0.3

echo "--- client a log"
cat "$WORK/a.log"
echo "PASS"
