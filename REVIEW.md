# SMESH-VPN Code Review

Reviewed at commit `7707ccd` (branch `claude/smesh-vpn-review-03ce6a`). Baseline: `go build`, `go vet`, and `go test ./...` all pass on Go 1.27.0.

The project is a crypto and session prototype, not yet a VPN, and this review treats it that way. Missing features that STATUS.md already lists (TUN, config, discovery integration, rekey) are not repeated here. What follows are defects in the code that exists.

Each finding that has a test points at a `review_test.go` file. Those tests are written to fail while the bug is present, so they are red right now. Fix the bug and they go green.

| # | Severity | Area | Finding | Test |
|---|----------|------|---------|------|
| 1 | High | Auth / Session | Peer ID is self-asserted and never checked against the certificate | `pkg/Auth/review_test.go` TestHelloIDMustMatchCertificateIdentity |
| 2 | High | Auth | Server response not bound to the hello; identity misbinding (UKS) | `pkg/Auth/review_test.go` TestResponseIsBoundToTheHelloItAnswers |
| 3 | High | Session | Data channel has no replay protection and no direction binding | `pkg/Session/review_test.go` TestDataChannelRejectsReplayAndReflection |
| 4 | High | cmd/Server | Mesh listener on :8080 runs unauthenticated while discovery API requires mTLS | none (by design for now, see note) |
| 5 | Medium | Certs | Peer verifier accepts any CA-signed cert, including the TLS server cert | `pkg/Auth/review_test.go` TestPeerVerifierRejectsNonClientCertificates |
| 6 | Medium | Certs | Re-revoking a re-issued client ID un-revokes the earlier serial | `pkg/Certs/review_test.go` TestReissuedClientKeepsEarlierSerialRevoked |
| 7 | Medium | Session | Handshake has no deadline; silent peers pin goroutines forever | `pkg/Session/review_test.go` TestHandshakeArmsReadDeadline |
| 8 | Medium | Session | Duplicate peer IDs corrupt `sessionsByPeerID` on removal | `pkg/Session/review_test.go` TestPeerLookupStaysConsistentWhenPeerIDsCollide |
| 9 | Medium | Session | Idle cleanup never emits a Disconnected event | `pkg/Session/review_test.go` TestIdleCleanupEmitsDisconnectedEvent |
| 10 | Medium | Discovery | Registered address is self-asserted and unvalidated | none |
| 11 | Low | Auth | Signed transcript concatenates variable-length fields without framing | none |
| 12 | Low | Auth | Timestamp-only replay window (already in STATUS.md) | existing test covers the window |
| 13 | Low | AES | Random GCM nonces with no rekey; "secure wipe" is cosmetic | none |
| 14 | Low | Session / Certs | Several unlocked field accesses (data races) | race detector, see below |
| 15 | Low | Build | Makefile breaks on case-sensitive filesystems; `-tags server` is unused | none |

---

## 1. Peer ID is self-asserted and never checked against the certificate (High)

`AuthenticatedHandshakeHello.ID` is set by the sender from `identity.ID`. The server verifies the certificate chain and the signature, but nothing compares `hello.ID` to the UUID embedded in the certificate's CommonName (`certs.ClientIDFromCertificate`). In `NewSessionFromConn` ([session.go:150](pkg/Session/session.go:150)) the session's `peer.ID` is taken straight from the hello, and the manager indexes it in `sessionsByPeerID`.

Any peer holding a valid certificate can therefore claim any ID. Combined with finding 8, a malicious insider can claim a victim's ID, get a session indexed under it, and have the victim's slot in the lookup table deleted or overwritten. Once `sessionsByPeerID` drives packet routing, this is traffic hijacking.

The unauthenticated path has the same shape ([session.go:567](pkg/Session/session.go:567)) but that path makes no identity claims at all, so it is only noted.

**Fix.** In `ProcessClientHello`, extract the ID from the verified certificate and either reject a mismatch or drop the `ID` field from the hello entirely and derive the peer ID from the cert. Return the verified certificate and ID from `ProcessClientHello` so the session layer does not re-parse `hello.Certificate` itself.

## 2. Server response is not bound to the client hello (High)

The response signature covers `ECPublicKey || Certificate || Ciphertext || Timestamp` ([authenticated_handshake_response.go:32](pkg/Auth/authenticated_handshake_response.go:32)). It does not cover anything from the hello, and `KeyGen` ([key_gen.go:9](pkg/PQXDH/key_gen.go:9)) derives the key from the two shared secrets alone with a fixed info string. Neither side's identity enters the transcript.

This permits the classic unknown-key-share attack. Insider Mallory takes Alice's ephemeral public keys from her hello, wraps them in a fresh hello signed with Mallory's own certificate, and sends that to Bob. Bob encapsulates to Alice's keys and signs a response. Mallory forwards the response to Alice unchanged. Alice verifies Bob's signature and derives key K. Bob derives the same K but records the peer as Mallory. Mallory cannot read the traffic, but Bob now attributes everything Alice sends to Mallory. In a mesh where identity decides overlay IP, ACLs, or logging, that matters.

The test demonstrates both halves: Bob accepts Mallory's hello and Alice accepts Bob's response, and the two keys are byte-equal.

**Fix.** Two changes, both standard:

- Include a hash of the full client hello (all fields including certificate and signature) in the response's signed data.
- Feed a transcript hash into HKDF, either as salt or in the info string: both certificates, both EC public keys, the PQ public key, and the ciphertext. Something like `info = "SMESH-VPN-v1" || SHA3(hello || response-without-signature)`. This also gives key confirmation for free once either side sends an authenticated frame.

While here: the `ID` field is only included in the signed data when non-nil ([authenticated_handshake_hello.go:37](pkg/Auth/authenticated_handshake_hello.go:37)). That is safe but odd; once the ID comes from the cert (finding 1) the field can go.

## 3. Data channel has no replay protection and no direction binding (High)

`Session.Receive` decrypts any frame that authenticates under the session key. There is no sequence number, so an on-path attacker can replay any captured frame. Both directions use the same key and the same `AES256` instance with random nonces, so an attacker can also reflect a peer's own frames back to it and they decrypt cleanly.

For a VPN carrying IP packets this means replayed UDP datagrams, duplicated TCP segments, and reflected packets all reach the TUN device.

**Fix.** Derive two keys from the handshake (initiator-to-responder and responder-to-initiator) with distinct HKDF labels, and use a 64-bit counter nonce per direction with a sliding anti-replay window on receive (WireGuard's design is the reference). This also removes the random-nonce birthday limit in finding 13.

## 4. Mesh listener is unauthenticated while discovery requires mTLS (High, known)

`cmd/Server/main.go` builds a CA and runs the discovery HTTP API behind mutual TLS, then starts the session listener on :8080 with an identity that has no certificate, so every connection takes the unauthenticated PQXDH path. Anyone who can reach :8080 gets an encrypted session with no credentials. STATUS.md says this is temporary. The point here is that the server already has everything it needs: it owns the CA, so it could issue itself a client cert and populate `identity.Certificate`, `PrivateKey`, and `Verifier` before listening. Until then, README claims like "only authorized clients with valid certificates can connect" are false for the shipped binaries.

A related design gap: the wire format has no message type or version byte. Authenticated and unauthenticated hellos are distinguished only by which JSON fields happen to be present. The combinations fail closed today (an unauthenticated hello sent to an authenticated server fails at certificate parse), but that is an accident of field naming, not a protocol decision. Add a one-byte message type and a protocol version to every frame before adding more message kinds.

## 5. Peer verifier accepts any CA-signed certificate (Medium)

`ClientCertificateVerifier.VerifyPeerCertificate` ([client_verifier.go:52](pkg/Certs/client_verifier.go:52)) calls `x509.Verify` with no `KeyUsages`, which Go defaults to `ExtKeyUsageServerAuth`. It also does not check that the subject carries a client identity. So the discovery TLS certificate (ServerAuth only, CommonName "SMESH-VPN-Discovery-...") passes as a mesh peer. `CertificateAuthority.ValidateClientCertificate` by contrast does require ClientAuth, so the two verifiers disagree.

**Fix.** Set `KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}` in the verifier and require `ClientIDFromCertificate` to succeed. Consider dropping `ExtKeyUsageServerAuth` from issued client certs, since mesh peers authenticate with the handshake signature, not TLS.

## 6. Re-revoking a re-issued client ID un-revokes the earlier serial (Medium)

`CRLManager.revokedCertificates` is keyed by client ID ([crl.go:50](pkg/Certs/crl.go:50)). `RevokeCertificate` deletes the cert from `ca.Certificates`, which allows `IssueClientCertificate` for the same ID again. Revoking that second cert overwrites the map entry, and the next `UpdateCRL` emits a CRL containing only the second serial. The first certificate, still within its 30-day validity, passes `ValidateClientCertificate` again.

**Fix.** Key the revocation map by serial number (string form of the `big.Int`). Serial numbers are already unique via the monotonic counter.

## 7. Handshake has no deadline (Medium)

`ListenForNewConnections` spawns a goroutine per accepted connection and `NewSessionFromConn` blocks in `RecvWithLen` with no deadline. A peer that connects and sends nothing, or sends a 2-byte length prefix and stops, holds a goroutine and a socket forever. There is also no cap on concurrent handshakes. On the client side, `EstablishKeyExchange` holds `s.mu` across the entire network round trip, so `Status()` and `Close()` on that session block too.

**Fix.** `conn.SetDeadline(time.Now().Add(handshakeTimeout))` before the handshake and clear it after. Add a semaphore or counter for in-flight handshakes. Do not hold the session mutex across I/O; do the exchange on locals and take the lock only to install the cipher and status.

## 8. Duplicate peer IDs corrupt the lookup table (Medium)

`CreateSession` and `CreateSessionFromConnection` write `sessionsByPeerID[peer.ID] = session` unconditionally. If a session for that peer already exists it is silently shadowed but stays in `sessions`. `RemoveSession(old)` then does `delete(sessionsByPeerID, session.peer.ID)`, which removes the entry for the *new* session. The same happens in `CleanupIdleSessions`.

This is a plain logic bug on its own (reconnects will trigger it) and the amplifier for finding 1.

**Fix.** On insert, if a session for the peer already exists, decide the policy explicitly: close and replace the old one, or reject the new one. On delete, only remove the peer index entry if it still points at the session being removed.

## 9. Idle cleanup never emits Disconnected (Medium)

`CleanupIdleSessions` ([manager.go:178](pkg/Session/manager.go:178)) removes sessions from the maps and calls `session.Close()` directly, bypassing `notifyEvent`. Consumers watching the event channel will never learn that an idle session went away. `CloseAll` has the same gap.

**Fix.** Route through the same removal path as `RemoveSession`, or emit the event after closing.

## 10. Discovery registration address is self-asserted (Medium)

`POST /peers` records whatever `address` the client sends ([discovery_server.go:219](cmd/Server/discovery_server.go:219)). Identity comes from the TLS cert, which is right, but the address is not checked against anything. A peer can register `0.0.0.0`, a loopback, a multicast address, or another peer's real address. Since connections are authenticated end to end, pointing peers at an attacker only yields failed handshakes, but pointing many peers at a third-party host is a reflection nuisance, and after finding 2 is fixed this is the next thing an insider would poke at.

**Fix.** At minimum reject unspecified, loopback, multicast, and link-local addresses. Consider defaulting the IP to the TLS connection's remote address and only allowing the client to pick the port, with an explicit override for NAT cases once brokering exists.

Smaller discovery notes: `GetPeer` takes a write lock for a read, which is fine but means every lookup serializes. The HTTP server sets `ReadHeaderTimeout` but no `ReadTimeout`, `WriteTimeout`, or `IdleTimeout`. The discovery tests inject `r.TLS` directly, so no test exercises a real ML-DSA mTLS handshake; one `httptest.NewUnstartedServer` with `TLS` set would close that gap and is worth adding since the TLS ML-DSA support is new in Go.

## 11. Signed transcript has no field framing (Low)

Both `signatureData` functions concatenate fields with `slices.Concat`. The certificate is variable length and is followed by the timestamp. DER is self-delimiting and Go's parser rejects trailing bytes, so I could not construct a practical ambiguity, but this is the kind of thing that becomes exploitable when a field is added later. Length-prefix each field, or sign a hash of a canonical encoding.

## 12. Timestamp-only replay protection (Low, known)

Already in STATUS.md. One correction to that document: `validHandshakeTime` does reject future timestamps beyond the skew window. What is missing is a cache of recently seen hellos, so a captured hello can be replayed for five minutes. The cost to the server is one ML-KEM encapsulation and one ML-DSA signature per replay, which is a cheap DoS lever. A fix for finding 2 (transcript binding) plus a small LRU of hello hashes closes this.

## 13. AES-GCM nonce management and key wiping (Low)

Random 96-bit nonces are fine for a prototype, but NIST SP 800-38D caps random-nonce use at 2^32 messages per key, and `RekeyIfNeeded` is a stub that just resets the timestamp. The counter-nonce design from finding 3 resolves this. Separately, `AES256.Close` zeroes a copy of the key but the expanded key schedule inside `cipher.AEAD` is untouched, so the "secure wipe" guarantee in the comments is not real. Either drop the claim or drop the key copy (the TODO on [aes.go:52](pkg/AES/aes.go:52) already suggests this).

## 14. Data races (Low)

The race detector could not be run in this environment. Found by reading:

- `rekeyAgingSessions` reads `session.established` without the session lock ([manager.go:203](pkg/Session/manager.go:203)) while `RekeyIfNeeded` writes it under the lock.
- `ClientCertificateVerifier.LoadCRL` and `EnableCRLChecking` write `cv.crl` and `cv.enableCRLChecking` with no lock while `checkCertificateRevocation` reads them under `RLock`.
- `SessionManager.Shutdown` closes `stopCleanup` unconditionally; a second call panics.
- `Session.Close` returns early if `connection.Close()` errors, leaving `closed=false` with a nil cipher, so the next `Send` reports "encryption not initialized" instead of "closed".

Once `-race` works, `go test -race ./...` will catch the first two.

## 15. Build (Low)

- Makefile builds `./cmd/server` but the directory is `cmd/Server`. Works on Windows and WSL over NTFS, fails on Linux.
- `-tags server` is passed but no file has a `//go:build` constraint, so it is dead.
- The Linux server binary is named `.exe`.
- README references Docker Compose and a LICENSE file that do not exist (STATUS.md notes this).

---

## Architecture notes

These are not bugs but will shape the next steps.

**Naming.** The `PQXDH` package is not PQXDH. PQXDH (Signal) has identity keys, signed prekeys, and one-time prekeys with a specific multi-DH construction. What is here is an ephemeral hybrid KEM: X25519 plus ML-KEM-768, combined through HKDF. That is a perfectly good building block, and close to what TLS and X-Wing do, but the name will mislead anyone evaluating the protocol. Call it what it is (`hybridkem` or similar) and describe the authenticated version as "signed ephemeral hybrid KEM" or a SIGMA-style handshake once the transcript binding is in.

**One-shot handshake objects.** `AuthenticatedPQXDHServer` is created per connection in `NewSessionFromConn`, so the server's X25519 key is fresh per session. Good. But `ServerKeyExchange` and `ClientKeyExchange` take the key-holder struct *by value*, which copies private key material around on the stack for no reason. Make them methods on the pointer.

**Session owns too much and too little.** `Session` does dialing, the handshake, framing, and crypto. Meanwhile the manager reaches into `session.peer.ID` and `session.established` directly. The handshake should produce a small `Keys` value (two directional keys plus the verified peer identity) and the session should be constructed from that. That separation is what makes the handshake testable without sockets, makes rekey a real operation (swap the `Keys`), and keeps the manager from needing unexported fields.

**`PeerInfo.Certificate` by value.** Copying an `x509.Certificate` struct around is wasteful and makes `PeerInfo{}` surprising. Use a pointer, or store just the verified ID and fingerprint.

**Identity in the server binary.** `cmd/Server/main.go` creates the CA in memory on every start, which invalidates every client certificate on restart. STATUS.md lists persistence as missing. Until it exists, every "restart the server" test case will also be a "re-enroll every client" test case.

**Error path hygiene.** `NewSessionFromConn` closes the connection on some error paths but not on JSON or certificate parse failures. `CreateSessionFromConnection` covers it, but any direct caller leaks. Pick one owner for the connection on failure and make it consistent, or `defer` a close that is disarmed on success.

---

## Verification

```text
go build ./...          ok
go vet ./...            ok
go test ./...           ok before review tests were added
go test -race ./...     blocked: gcc not in PATH (same as STATUS.md)
```

New review tests, all currently failing by design:

```text
pkg/Auth     TestHelloIDMustMatchCertificateIdentity
pkg/Auth     TestResponseIsBoundToTheHelloItAnswers
pkg/Auth     TestPeerVerifierRejectsNonClientCertificates
pkg/Session  TestDataChannelRejectsReplayAndReflection
pkg/Session  TestIdleCleanupEmitsDisconnectedEvent
pkg/Session  TestPeerLookupStaysConsistentWhenPeerIDsCollide
pkg/Session  TestHandshakeArmsReadDeadline
pkg/Certs    TestReissuedClientKeepsEarlierSerialRevoked
```

Suggested order of fixes: 1 and 2 together (they share the transcript change), then 5, then 3, then 8 and 9, then the rest.
