# Docker test environment

Two VPN clients on separate networks, a discovery server, and a router that joins the networks. All of it runs in Docker.

```text
  site-a 172.30.1.0/24          core 172.30.0.0/24          site-b 172.30.2.0/24
  client-a .10 ──────────── router .254 ───────────────── client-b .10
                                  │
                            discovery .10
```

The router forwards packets without NAT, so the clients can dial each other and the discovery server directly. That matches what the MVP supports. Each client's overlay traffic runs over its `smesh0` TUN interface: `10.77.0.2` for client-a, `10.77.0.3` for client-b.

Docker with Compose v2 is required. Clients need `/dev/net/tun`, which Docker Desktop (WSL2) and Linux hosts both provide.

## Run the test

```bash
docker/test.sh
```

The script builds the image and starts everything. It then pings every pair of `client-*` services over the overlay, prints `PASS` or the failing pair along with the recent logs, and tears the environment down. Add `--keep` to leave it running.

## Poke at it by hand

```bash
docker compose -f docker/compose.yaml up -d --build
docker compose -f docker/compose.yaml exec client-a ping 10.77.0.3
docker compose -f docker/compose.yaml logs -f client-a client-b
docker compose -f docker/compose.yaml exec router tcpdump -ni any tcp port 7777   # the encrypted tunnel
docker compose -f docker/compose.yaml down -v
```

`down -v` also deletes the `pki` volume, so the next `up` issues fresh identities. Leave out `-v` to keep them.

## Change the configuration

**Settings:** `docker/.env` holds the defaults. Override them in the shell for a single run:

```bash
NET_PREFIX=172.31 CLIENT_B_VPN_IP=10.77.0.9/24 MTU=1280 docker/test.sh
```

| Variable                             | Default                        | Meaning                                                                                 |
| ------------------------------------ | ------------------------------ | --------------------------------------------------------------------------------------- |
| `NET_PREFIX`                         | `172.30`                       | First two octets of the underlay subnets. Change it if it clashes with a local network. |
| `CLIENT_A_VPN_IP`, `CLIENT_B_VPN_IP` | `10.77.0.2/24`, `10.77.0.3/24` | Overlay address and prefix of each client                                               |
| `MTU`                                | `1400`                         | TUN MTU on the clients                                                                  |
| `LISTEN_PORT`                        | `7777`                         | Peer session port                                                                       |
| `DISCOVERY_PORT`                     | `8081`                         | Discovery server port                                                                   |
| `DISCOVERY_TTL`                      | `2m`                           | How long a registration lives without a heartbeat                                       |

**Topologies:** put each topology in an override file layered on `compose.yaml`. [compose.three-clients.yaml](compose.three-clients.yaml) adds a third client on its own site, and is a template for others:

```bash
docker/test.sh docker/compose.three-clients.yaml
```

To add a client in an override:

1. Add its name to `pki`'s `CLIENTS`.
2. Attach the router to its network if it's a new one.
3. Define the service with `extends: { file: compose.yaml, service: client-a }`.
4. Give it its own `CLIENT_NAME`, `VPN_IP`, `ROUTES` and network.

`test.sh` picks up every `client-*` service on its own.

**Roles:** the image's entrypoint ([entrypoint.sh](entrypoint.sh)) takes a role: `pki`, `discovery`, `client` or `router`.

- Extra arguments after `client` or `discovery` go to the binary, for example `command: [client, -advertise, 172.30.1.10:7777]`.
- `ROUTES` (`"CIDR via GATEWAY"`, comma separated) is installed before the discovery server or client starts.
- Any other command runs as given, for example `docker compose ... run --rm client-a sh`.
