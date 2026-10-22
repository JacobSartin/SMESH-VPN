#!/bin/sh
# Bring up the test environment, ping every pair of clients over the overlay,
# and tear it down again.
#
# Usage: docker/test.sh [--keep] [override.yaml ...]
#   --keep          leave the environment running afterwards
#   override.yaml   extra compose files layered on docker/compose.yaml
#
# Every service named client-* is tested; its overlay address is read from VPN_IP.
set -eu

DIR=$(cd "$(dirname "$0")" && pwd)
FILES="-f $DIR/compose.yaml"
KEEP=0
for arg in "$@"; do
	case "$arg" in
	--keep) KEEP=1 ;;
	*) FILES="$FILES -f $arg" ;;
	esac
done

# shellcheck disable=SC2086 # FILES is a list of -f flags
compose() { docker compose $FILES "$@"; }

cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		echo "--- logs"
		compose logs --no-color --tail 40 || true
	fi
	if [ "$KEEP" -eq 1 ]; then
		echo "--- environment left running; stop it with: docker compose $FILES down -v"
	else
		compose down -v --remove-orphans >/dev/null 2>&1 || true
	fi
	exit "$status"
}
trap cleanup EXIT INT TERM

echo "--- starting"
compose up -d --build

CLIENTS=$(compose config --services | grep '^client-' || true)
[ -n "$CLIENTS" ] || { echo "no client-* services found" >&2; exit 1; }

vpn_ip() { compose exec -T "$1" printenv VPN_IP | cut -d/ -f1; }

ping_peer() {
	src=$1 dst=$2 ip=$3
	i=0
	while [ "$i" -lt 30 ]; do
		if compose exec -T "$src" ping -c 1 -W 1 "$ip" >/dev/null 2>&1; then
			compose exec -T "$src" ping -c 3 -q "$ip" | tail -n 2
			return 0
		fi
		i=$((i + 1))
		sleep 1
	done
	echo "FAIL: $src cannot reach $dst ($ip)" >&2
	return 1
}

failed=0
for src in $CLIENTS; do
	for dst in $CLIENTS; do
		[ "$src" = "$dst" ] && continue
		ip=$(vpn_ip "$dst")
		echo "--- $src -> $dst ($ip)"
		ping_peer "$src" "$dst" "$ip" || failed=1
	done
done

[ "$failed" -eq 0 ] || exit 1
echo "PASS: all $(echo "$CLIENTS" | wc -w | tr -d ' ') clients reach each other"
