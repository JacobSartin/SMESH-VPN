# SMESH-VPN MVP Plan

_Reviewed 2026-10-07 against `main` @ `7707ccd` (Go 1.27.0). `go build`, `go vet`, and `go test ./...` all pass._

## Progress (2026-10-07)

All phases below are implemented. The four open decisions at the end were confirmed as written. Bugs 1–9 are fixed. Of the minor items in 10, the `LoadCertificate` doc and the rekey stub are fixed (aged sessions are now closed and reconnect with a fresh key exchange); dropped events are still silent.

| Phase | Where | Notes |
|---|---|---|
| 0 Housekeeping | `Makefile`, `cmd/Server` | The session listener was removed from the server. |
| 1 Identity | `pkg/Certs/storage.go`, `pkg/Session/identity.go`, `cmd/Server` (`init-ca`, `issue-client`) | Serials are now random 128-bit, so separate offline runs never collide. |
| 2 Discovery server | `pkg/Discovery/server.go`, `tls.go` | Moved out of `cmd/Server` so the client can share its types. `GET /peers` excludes the caller. A successful registration returns 200. |
| 3 Discovery client | `pkg/Discovery/client.go` | |
| 4 Peer sessions | `pkg/Auth`, `pkg/Session`, `pkg/Mesh` | Peers with the same ID: the newest session wins, so a restarted peer replaces its stale session. |
| 5 TUN | `pkg/Tun` | Raw fd, `TUNSETIFF`, then `os.NewFile` (opening via `os.OpenFile` left reads stuck). |
| 6 Client CLI | `cmd/Client` | |
| 7 Verification | `pkg/Mesh/node_test.go`, `scripts/netns-demo.sh`, `README.md` | The netns script replaces the docker-compose idea. Real-Linux end to end passes. `-race` is clean. |

**Found by the Docker environment (`docker/`):** handshake signatures covered `time.Time.MarshalBinary`, whose bytes depend on the time zone. A sender whose `Local` zone is UTC (any container without tzdata) produced signatures that failed after the JSON round trip. Fixed by signing Unix nanoseconds, with a regression test.

**LICENSE:** added on `main` (MIT).

## MVP definition

Two clients, each with a publicly reachable IP and port (no NAT, no firewall), can:

1. Authenticate to the discovery server and register their endpoint and overlay IP.
2. Learn about each other from the discovery server.
3. Open one authenticated, encrypted peer-to-peer session.
4. Route IP traffic between their overlay addresses through a TUN interface. For example, `ping 10.77.0.3` from peer A reaches peer B.

**Out of scope for the MVP:** NAT traversal and relaying, Windows TUN, real rekeying, CRL distribution, an online enrollment API, UDP transport, an IPv6 overlay, config files, and more than a handful of peers.

## Where the code stands

| Area | State | MVP-relevant? |
|---|---|---|
| `pkg/AES` (AES-256-GCM) | Done, tested | Yes, as is |
| `pkg/PQXDH` (X25519 + ML-KEM-768 → HKDF) | Done, tested | Yes, as is |
| `pkg/Auth` (ML-DSA-signed PQXDH handshake) | Done, tested; identity-binding gaps (below) | Yes: this is the peer handshake |
| `pkg/Certs` (CA, issuance, verifier, CRL) | Works in memory; **no persistence** | Yes: needs save/load |
| `pkg/Network` (u16 length-prefixed frames) | Done | Yes, as is |
| `pkg/Session` (session, manager, events) | Handshake and messaging work; no keepalive, reconnect, or deadlines | Yes: needs completion |
| `cmd/Server` discovery registry | mTLS-identity registry works; **unreachable in practice** (below) | Yes: needs flags and provisioning |
| `cmd/Client` | Placeholder: dials the server's `:8080` as if it were a peer | Rewrite |
| TUN / data plane | Missing entirely | Yes: biggest new piece |
| CRL, fingerprint cache, `Lock/Unlock`, rekey | Scaffolding | No: leave alone |

**Verified during review:** a real ML-DSA-44 mutual-TLS handshake with Go 1.27's `crypto/tls` works end to end (scratch test, since deleted). The existing discovery tests only fake `r.TLS`, so this had not been proven before. `x509.MarshalPKCS8PrivateKey` supports `*mldsa.PrivateKey`, so the CA and client keys can be persisted as standard PEM.

### The `unvetted` branch

It is **already merged** into `main` (merge `54aef36`). Its only unique commit, `055f6f5` "?", added `STATUS.md` and the first discovery registry. `7707ccd` "Update discovery server" then superseded that registry: it derives identity from the mTLS certificate, uses `netip.AddrPort`, expires peers on `Get` and `Remove`, and replaced `google/uuid` with the stdlib `uuid`. Nothing on the branch remains to salvage, so it can be archived.

### `STATUS.md` accuracy

It is mostly accurate on what's missing. It is stale on the toolchain (it says 1.26.3; `go.mod` now requires 1.27). It also understates one gap: clients don't just lack integration with discovery. **They cannot obtain a certificate at all**, so they cannot talk to discovery. Replace it with this plan, or update it once Phase 1 lands.

## Bugs and gaps found (fix as part of the MVP)

1. **Peer identity is not bound to the certificate.** [session.go:150](../pkg/Session/session.go) uses the self-declared `hello.ID` as the peer ID and never checks it against `certs.ClientIDFromCertificate`. `ID` is also only covered by the signature when it is non-nil ([authenticated_handshake_hello.go:37](../pkg/Auth/authenticated_handshake_hello.go)).
2. **The peer verifier accepts any certificate signed by the CA**, including the discovery server's own TLS certificate. `VerifyPeerCertificate` sets no `KeyUsages`, so Go defaults to ServerAuth ([client_verifier.go:52](../pkg/Certs/client_verifier.go)). Requiring ClientAuth and a valid client ID fixes this and item 1 together.
3. **The handshake response is not bound to the hello.** The response signature covers no hash of the client hello ([authenticated_handshake_response.go:32](../pkg/Auth/authenticated_handshake_response.go)). ML-KEM limits the practical impact, but adding a transcript hash is cheap.
4. **No I/O deadlines during the handshake.** A peer that connects and sends nothing pins a goroutine forever in `RecvWithLen`.
5. **Idle cleanup is silent.** `CleanupIdleSessions` closes sessions without emitting `SessionEventDisconnected` ([manager.go:178](../pkg/Session/manager.go)), so nothing above it can reconnect. There is also no keepalive, so a quiet tunnel dies after `maxIdleTime`.
6. **The handshake mode is implicit.** Each side picks authenticated or unauthenticated based on its own identity, with no version or mode byte, so mismatched configs fail with JSON decode errors.
7. **Discovery cannot be used.** The CA is regenerated on every start. The server TLS certificate's SANs are hard-coded to `localhost`/`127.0.0.1`/`::1`. There is no way to issue a client certificate outside tests.
8. **Wrong topology in `cmd/`.** The server also runs a session listener on `:8080` that the client dials as if it were a peer. `DiscoveryServer.manager` is unused.
9. **`Makefile` breaks on Linux and WSL.** It builds `./cmd/server`, but the directory is `cmd/Server`, so the build fails on case-sensitive filesystems. `-tags server` does nothing, and the Linux server binary gets an `.exe` suffix.
10. **Minor issues:**
    - `LoadCertificate`'s doc says PEM, but the code parses DER.
    - `RekeyIfNeeded` reports success without rekeying.
    - Dropped events are silent.

**Known and accepted for the MVP (document, don't fix):**
- Data frames use random-nonce GCM with one key for both directions and no sequence numbers, so there is no replay or reorder detection beyond TCP's.
- The tunnel runs over TCP (TCP-over-TCP meltdown under loss).

## Work plan

Phases are ordered by dependency. Sizes are rough: S is under half a day, M is about a day, L is several days.

### Phase 0: Housekeeping (S)
- Fix the `Makefile`: use `./cmd/Server`, drop the meaningless tag, remove the `.exe` from the Linux server binary name.
- Remove the `:8080` session listener and the `SessionManager` from `cmd/Server`. Discovery is coordination only. Drop the `manager` field from `DiscoveryServer`.
- Replace `STATUS.md` with a pointer to this plan.

### Phase 1: Persistent identity and offline provisioning (M)
_Decision: offline issuance via CLI, no enrollment API. This is the most conservative path and reuses the existing CA code unchanged._
- `pkg/Certs`: `SaveCA(dir)` and `LoadCA(dir)` (PEM certificate plus PKCS#8 key, key file mode `0600`). Add PEM helpers for certificates and keys.
- `cmd/Server` subcommands:
  - `init-ca --dir`
  - `issue-client --ca-dir --out <dir> [--id <uuid>]`: writes `client.crt`, `client.key`, `ca.crt`
  - `serve`
- The server TLS certificate is issued at `serve` time from `--hostname` / `--ip` flags (repeatable), not hard-coded SANs.
- `pkg/Session`: `LoadClientIdentity(certPath, keyPath, caPath)` returns a `ClientIdentity` with `ID` taken from the certificate and a configured `Verifier`.
- Tests: CA round trip through disk; a loaded identity completes the authenticated session handshake.

### Phase 2: Discovery server, runnable (S–M)
- `serve` flags: `--listen :8081`, `--ca-dir`, `--hostname`, `--ip`, `--ttl 2m`.
- Extend registration with `vpn_ip` (`netip.Addr`, declared by the client). Reject a registration whose `vpn_ip` belongs to another live peer (409). Return it in `PeerRecord`.
- If the declared endpoint host is unspecified (`0.0.0.0:port`), fill it in from the TLS connection's source IP. This is cheap and makes the no-NAT case work without hand-typing public IPs.
- Shut down gracefully on SIGINT/SIGTERM.
- Tests: a **real** mTLS `httptest` server test (replacing the faked `r.TLS` for at least one path), VPN IP conflict handling, and endpoint fill-in.

### Phase 3: Discovery client library (S)
- New `pkg/Discovery`: an mTLS `http.Client` built from the `ClientIdentity`, plus `Register`, `ListPeers`, `GetPeer`, and `Deregister`.
- A heartbeat loop that re-registers every `ttl/3`, driven by `context.Context`.
- Tests run against the real handler over `httptest.NewTLSServer`.

### Phase 4: Peer sessions (M–L)
- **Handshake hardening:** fix bugs 1–4 and 6.
  - Derive the peer ID from the certificate and reject a mismatched `hello.ID`.
  - Verify with ClientAuth EKU.
  - Add a hello hash to the response signature.
  - Set a 10 s handshake deadline on the connection.
  - Prepend a 1-byte protocol and mode tag.
- **Unauthenticated path:** the MVP always uses the authenticated path, because every peer has a certificate. Keep the unauthenticated code for tests, but the client should refuse to start without an identity.
- **Frame types:** add a 1-byte type inside the plaintext (`data`, `keepalive`). Send a keepalive every 10 s. Emit `Disconnected` from idle cleanup.
- **Peer manager** (new, in `pkg/Session` or `pkg/Mesh`):
  - Listen on `--listen`.
  - For each discovered peer, the side with the **lower UUID dials** and the other waits. This prevents duplicate sessions.
  - Keep one session per peer ID, enforced on both inbound and outbound.
  - Reconnect with backoff when a session drops.
  - Map overlay IP to session using `vpn_ip` from discovery.
- Tests: two in-process peers find each other through an in-process discovery server and exchange frames; a dropped connection reconnects.

### Phase 5: TUN data plane, Linux only (M–L)
_Decision: Linux only for the MVP. Windows needs Wintun (a driver DLL plus a non-stdlib binding), which goes against the stdlib-only direction of `dffd026`/`43faf64`._
- `pkg/Tun`: open `/dev/net/tun` with `TUNSETIFF` (`IFF_TUN|IFF_NO_PI`) using `syscall`. Configure the address, MTU (1400), and link-up by shelling out to `ip`. This stays stdlib-only and is easy to read. Hide it behind a small `Device` interface (`Read`, `Write`, `Close`) so tests can use an in-memory fake.
- Packet loop:
  - TUN → parse the IPv4 destination → look up the session by overlay IP → `Send`.
  - Session `Read` → TUN `Write`.
  - Drop packets with no matching peer, and IPv6 packets.
- `//go:build linux` for the real device, and a stub that returns an error elsewhere.
- Requires root or `CAP_NET_ADMIN`. Document this.

### Phase 6: Client CLI (S)
- Flags:
  - `--discovery https://host:8081`
  - `--cert`, `--key`, `--ca`
  - `--listen :7777`
  - `--advertise <ip:port>` (optional, given the Phase 2 fill-in)
  - `--vpn-ip 10.77.0.2/24`
  - `--tun smesh0`
- Startup: load identity → bring up TUN → register and heartbeat → peer manager → packet loop. On SIGINT: deregister, close sessions, remove the TUN.

### Phase 7: Verification and docs (S–M)
- An in-process end-to-end test: discovery plus two peers with fake TUN devices, where an IPv4 packet injected at A comes out at B.
- A manual acceptance test: two Linux hosts or containers, then `ping` across the overlay in both directions. A minimal `docker-compose.yml` with `NET_ADMIN` is the cheapest way to make this repeatable, and the README already promises one.
- Rewrite the README run instructions (provisioning, server, client). Remove the claims that aren't true yet (Docker until added, CRL-based revocation, Windows client). Add the LICENSE file the README references.

## Deferred (post-MVP)
NAT traversal and relaying, Windows (Wintun), UDP transport, real rekeying, per-direction keys with counter nonces and replay windows, CRL distribution through discovery, an online enrollment API, server-assigned overlay IPs, config files, IPv6 overlay, race-detector CI.

## Open decisions (defaults assumed above)
1. **Linux-only data plane for the MVP:** assumed yes.
2. **Offline certificate issuance** rather than an enrollment endpoint: assumed yes.
3. **Overlay IPs set by a client flag** and conflict-checked by the server, rather than server-assigned: assumed yes.
4. **TCP transport** for the MVP: assumed yes, since it reuses the existing framing and session code.
