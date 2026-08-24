# SMESH-VPN Codebase Status

## Current Status

SMESH-VPN is currently a promising crypto/session prototype, not yet a functional VPN. The repository has working pieces for AES-GCM encryption, hybrid PQXDH-style key exchange, certificate issuance/verification, CRL handling, authenticated handshakes, unauthenticated no-certificate session setup, basic session management, and a minimal in-memory discovery registry.

The existing validation baseline is mostly healthy:

- `go test ./...` passes with Go `1.26.3`.
- `go vet ./...` passes with Go `1.26.3`.

The client and server can now establish sessions without certificate material by using the unauthenticated PQXDH path. The server also exposes a simple HTTP discovery API for peer registration, lookup, listing, and removal. The pieces are still scaffolding rather than a complete VPN workflow.

## Biggest Weak Points

- The discovery server has a minimal peer registry, but clients are not yet integrated with it for automatic peer discovery or connection brokering.
- The TUN/TAP data plane is missing. The `tunnel interface{}` field is only a placeholder, and there is no packet loop, route setup, MTU handling, or OS integration.
- The unauthenticated handshake path is intentionally temporary and does not authenticate peers. The certificate-authenticated path still exists, but certificate runtime provisioning is deferred while connection coordination is built incrementally.
- Replay protection for the authenticated handshake is timestamp-only. Old messages are rejected, but there is no nonce/session cache and future timestamps are not explicitly rejected.
- Rekeying is a stub. `RekeyIfNeeded` changes status and timestamps, but does not run a fresh key exchange or replace the active cipher key.

## Missing

- Configuration through CLI flags or config files for server address, listen address, certificate paths, key paths, CA roots, CRLs, timeouts, and peer settings.
- Client integration with the discovery API for register/list/connect workflows.
- Connection brokering behavior for peers that cannot directly dial each other.
- TUN/TAP implementation and packet forwarding loop.
- Reconnect, retry, shutdown, and cancellation behavior using `context.Context`.
- More session and network tests, especially for listener-driven connection setup, close behavior, failed handshakes, and network framing edge cases.
- Certificate/key lifecycle once authentication is reintroduced: persisted identity loading, CA trust setup, CRL refresh flow, and enrollment command path.
- Race-test coverage once CGO/race tooling is available.
- Coverage reporting once the local Go toolchain issue is fixed.
- Docker files referenced by the README.
- A license file referenced by the README.

## Verification Notes

The following commands passed:

```text
go test ./...
go vet ./...
```

The following checks were blocked by local toolchain or environment configuration:

- `go test -race ./...` failed because race testing requires CGO support, and `CGO_ENABLED` was disabled by default. Enabling CGO still failed in this environment due Go race runtime package resolution errors.
