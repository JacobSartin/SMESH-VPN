# SMESH-VPN Status

**MVP implemented (2026-10-07).** Two Linux peers that can reach each other directly can join an overlay network through the discovery server and exchange IP traffic over post-quantum authenticated, encrypted sessions. This has been verified end to end with `scripts/netns-demo.sh` (ping both ways, including full-MTU packets).

- Scope, design decisions, and the deferred list: [docs/MVP_PLAN.md](docs/MVP_PLAN.md)
- How to run it: [README.md](README.md)

Validation: `go vet ./...`, `go test ./...`, and `go test -race ./...` (on Linux) pass with Go 1.27.0.
