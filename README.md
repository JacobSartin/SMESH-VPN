```text
███████╗███╗   ███╗███████╗███████╗██╗  ██╗    ██╗   ██╗██████╗ ███╗   ██╗
██╔════╝████╗ ████║██╔════╝██╔════╝██║  ██║    ██║   ██║██╔══██╗████╗  ██║
███████╗██╔████╔██║█████╗  ███████╗███████║    ██║   ██║██████╔╝██╔██╗ ██║
╚════██║██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║    ╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║
███████║██║ ╚═╝ ██║███████╗███████║██║  ██║     ╚████╔╝ ██║     ██║ ╚████║
╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝      ╚═══╝  ╚═╝     ╚═╝  ╚═══╝
```

# SMESH-VPN

A mesh VPN prototype in Go built around a hybrid post-quantum handshake:
X25519 + ML-KEM-768 key agreement, ML-DSA-44 certificates for identity, and
AES-256-GCM for session traffic. It uses only the Go standard library.

## Status

The control-plane pieces are implemented and tested. The data plane is not
built yet, so SMESH-VPN does not carry IP traffic today.

Working:

- Hybrid PQXDH key exchange (X25519 + ML-KEM-768); see [pkg/PQXDH](pkg/PQXDH/README.md)
- ML-DSA-44 certificate authority: client and server certificate issuance,
  verification, and revocation lists
- Certificate-authenticated handshake, plus a temporary unauthenticated mode
  used while connection setup is being built out
- Session manager with AES-256-GCM sessions, idle cleanup, and lifecycle events
- Discovery server with an HTTP API over mutual TLS for registering, listing,
  looking up, and removing peers

In progress:

- TUN interface and packet forwarding (the data plane)
- Wiring the client to the discovery API for automatic peer connections
- Rekeying, configuration flags, and reconnect handling

[STATUS.md](STATUS.md) has the detailed list of gaps and known weaknesses.

## Layout

| Path | Contents |
| --- | --- |
| `cmd/Server` | Session listener (`:8080`) and discovery API (`:8081`, mutual TLS) |
| `cmd/Client` | Test client that opens a session to a local server |
| `pkg/PQXDH` | Hybrid key exchange |
| `pkg/Auth` | Authenticated handshake messages and signatures |
| `pkg/Certs` | Certificate authority, client verification, CRLs |
| `pkg/Session` | Sessions, session manager, node identity |
| `pkg/AES` | AES-256-GCM wrapper |
| `pkg/Network` | Length-prefixed message framing |

## Building

Requires Go 1.27 or newer (the code uses the standard library's `crypto/mldsa`
and `uuid` packages).

```bash
make
```

This builds Linux and Windows binaries for the client and server into `bin/`.

## Running

Start the server, then the client in another terminal:

```bash
./bin/smesh-server_linux_amd64
./bin/smesh-client_linux_amd64
```

On Windows, use the `.exe` binaries in `bin\`. The client connects to
`localhost:8080` and establishes a session using the unauthenticated handshake.

## Testing

```bash
go vet ./...
go test ./...
```

CI runs both on every push and pull request.

## License

MIT. See [LICENSE](LICENSE).
