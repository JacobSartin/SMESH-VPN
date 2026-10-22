```text
███████╗███╗   ███╗███████╗███████╗██╗  ██╗    ██╗   ██╗██████╗ ███╗   ██╗
██╔════╝████╗ ████║██╔════╝██╔════╝██║  ██║    ██║   ██║██╔══██╗████╗  ██║
███████╗██╔████╔██║█████╗  ███████╗███████║    ██║   ██║██████╔╝██╔██╗ ██║
╚════██║██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║    ╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║
███████║██║ ╚═╝ ██║███████╗███████║██║  ██║     ╚████╔╝ ██║     ██║ ╚████║
╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝      ╚═══╝  ╚═╝     ╚═╝  ╚═══╝
```

# Post-Quantum Mesh VPN

A mesh VPN whose peer sessions are established with a hybrid classical/post-quantum key exchange and authenticated with post-quantum certificates.

## Status

This is an MVP. Two or more Linux peers that can reach each other directly (no NAT or firewall between them) can join an overlay network coordinated by a discovery server. See [docs/MVP_PLAN.md](docs/MVP_PLAN.md) for what's in scope and what's deliberately deferred.

## How it works

- **Identity:** an offline CA issues each peer an ML-DSA-44 certificate. The peer's ID is the UUID in that certificate.
- **Discovery:** peers register their endpoint and overlay IP with the discovery server over mutual TLS (ML-DSA certificates on both sides). Registrations expire unless refreshed.
- **Sessions:** peers connect directly over TCP. The handshake is X25519 + ML-KEM-768 (PQXDH-style), signed with each peer's ML-DSA key. Traffic is encrypted with AES-256-GCM. For each pair, the peer with the lower ID dials, so there is one session per pair.
- **Data plane:** each peer has a TUN interface. IPv4 packets for another peer's overlay IP go through that peer's session. Packets whose source address doesn't belong to the sending peer are dropped.

## Requirements

- Go 1.27+
- Clients: Linux, root or `CAP_NET_ADMIN`, and the `ip` command
- The discovery server runs on any OS

## Build

```bash
make            # Linux and Windows binaries into bin/
make test       # go vet + go test
```

Or build directly, for example `go build -o bin/smesh-client ./cmd/Client`.

## Quick start

### 1. Create the CA and issue client identities

Do this on a trusted machine and keep `ca/ca.key` private.

```bash
smesh-server init-ca -dir ca
smesh-server issue-client -ca-dir ca -out alice
smesh-server issue-client -ca-dir ca -out bob
```

Each output directory holds `client.crt`, `client.key`, and `ca.crt`. Copy it to the matching peer. Client certificates are valid for 30 days.

### 2. Run the discovery server

`-hostname` / `-ip` must match the name or address clients use in their `-discovery` URL; they go into the server's TLS certificate.

```bash
smesh-server serve -ca-dir ca -listen :8081 -ip 203.0.113.10
```

### 3. Run a client on each peer

```bash
sudo smesh-client -discovery https://203.0.113.10:8081 -dir alice -vpn-ip 10.77.0.2/24
sudo smesh-client -discovery https://203.0.113.10:8081 -dir bob   -vpn-ip 10.77.0.3/24
```

Then `ping 10.77.0.3` from alice.

Useful client flags:

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `:7777` | TCP address for incoming peer sessions |
| `-advertise` | discovery server's view of this host, at the `-listen` port | endpoint other peers should dial |
| `-tun` | `smesh0` | TUN interface name |
| `-mtu` | `1400` | TUN MTU |

### Try it on one machine

With Docker: two clients on separate networks, a discovery server, and a router between them. The test pings every pair of clients. Settings and topologies are easy to change; see [docker/README.md](docker/README.md).

```bash
docker/test.sh          # or: make docker-test
```

Without Docker, on Linux: `scripts/netns-demo.sh` does the same with network namespaces.

```bash
make
sudo scripts/netns-demo.sh bin
```

## Testing

```bash
go test ./...
go test -race ./...    # needs cgo
```

The `pkg/Mesh` tests run a discovery server and two peers in process with in-memory TUN devices.

## Current limitations

- Linux clients only; no Windows TUN yet
- No NAT traversal or relaying: peers must be able to dial each other directly
- Tunnel over TCP (performance degrades under packet loss)
- IPv4 overlay only; overlay IPs are chosen by each client and must be unique
- Revocation (CRL) is implemented in the CA but not distributed to peers
- Data frames have no replay protection beyond what TCP provides

## License

This project is licensed under the MIT License - see the LICENSE file for details.
