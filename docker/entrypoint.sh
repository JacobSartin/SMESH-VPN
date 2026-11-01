#!/bin/sh
# Entrypoint for the SMESH-VPN test environment. The first argument selects the role.
#
#   pki        create the CA (once) and issue an identity for each name in $CLIENTS
#   discovery  run the discovery server (TLS cert valid for $DISCOVERY_IP)
#   client     run a VPN client with the identity /pki/$CLIENT_NAME
#   router     forward packets between the attached networks
#
# Any other command is executed as is. $ROUTES ("CIDR via GATEWAY", comma
# separated) is applied before discovery and client start.
set -eu

apply_routes() {
	[ -n "${ROUTES:-}" ] || return 0
	echo "$ROUTES" | tr ',' '\n' | while read -r route; do
		[ -n "$route" ] || continue
		# shellcheck disable=SC2086 # route is "CIDR via GATEWAY"
		ip route replace $route
		echo "route: $route"
	done
}

role=${1:-}
[ $# -gt 0 ] && shift

case "$role" in
pki)
	if [ ! -f /pki/ca/ca.crt ]; then
		smesh-server init-ca -dir /pki/ca
	fi
	for name in ${CLIENTS:?CLIENTS must list the client names}; do
		if [ ! -f "/pki/$name/client.crt" ]; then
			smesh-server issue-client -ca-dir /pki/ca -out "/pki/$name"
		fi
	done
	;;
discovery)
	apply_routes
	exec smesh-server serve -ca-dir /pki/ca \
		-listen ":${DISCOVERY_PORT:-8081}" \
		-ip "${DISCOVERY_IP:?}" -hostname discovery \
		-ttl "${DISCOVERY_TTL:-2m}" "$@"
	;;
client)
	apply_routes
	exec smesh-client \
		-discovery "${DISCOVERY_URL:?}" \
		-dir "/pki/${CLIENT_NAME:?}" \
		-vpn-ip "${VPN_IP:?}" \
		-listen ":${LISTEN_PORT:-7777}" \
		-mtu "${MTU:-1400}" "$@"
	;;
router)
	echo "forwarding between: $(ip -4 -o addr show scope global | awk '{print $4}' | tr '\n' ' ')"
	exec sleep infinity
	;;
*)
	exec "$role" "$@"
	;;
esac
