# Repository Guidelines

## Project Structure & Module Organization

This is a Go 1.25 tunnel/proxy project (module `x-tunnel`).

- `cmd/main.go` — CLI entrypoint.
- `internal/app/` — application wiring: engine, client/server, front proxy, SOCKS5/HTTP local listeners, control plane, keepalive, pacing, TLS ECH/DNS.
- `internal/transport/` — transport backends (QUIC, TCP, datagram, rotation/selection).
- `internal/wire/` — wire protocol (v2/v3 framing, cipher stream, TAI64N timestamps, KDF/nonces).
- `internal/netaddr/` — address handling helpers.
- `tests/` colocated: `*_test.go` files live next to the code they cover (e.g. `protocol_v3_test.go`, `quic_dualstack_test.go`, `integration_test.go` in `internal/app`).
- `scripts/` — `build.sh`, `release.sh`, `install`.
- `docs/` — design and protocol specs; `examples/` — sample client/server JSON configs.

## Build, Test, and Development Commands

- `go build ./...` — compile all packages.
- `go test ./...` — run the full test suite.
- `go test -race ./internal/app/` — race-detector run for a package (integration tests live here).
- `go test -bench . ./internal/wire/` — run protocol benchmarks (`*_bench_test.go`).
- `bash scripts/build.sh` / `bash scripts/release.sh` — cross-compile build / release packaging.
- `go run ./cmd --config examples/local-client.json` — run locally against the example configs.

## Coding Style & Naming Conventions

- Standard Go: `gofmt`-formatted, tabs, exported symbols in PascalCase, unexported in camelCase.
- Run `go vet ./...` and `gofmt -l .` before committing; both must be clean.
- Mirror existing file layout: one concern per file (e.g. `front_proxy.go`, `tls_ech_dns.go`), tests in the same package with `_test.go` suffix.
- Keep new code inside `internal/` unless it is part of the CLI surface.

## Testing Guidelines

- Framework: Go's standard `testing` package; no external test framework.
- Name unit tests `TestXxx`, benchmarks `BenchmarkXxx` (see `protocol_v3_bench_test.go`).
- Integration tests (`internal/app/integration_test.go`) spin up real client/server pairs — keep them deterministic and free of fixed ports/sleeps where possible.
- Every protocol or transport change must include tests, and protocol changes must stay compatible with `docs/protocol.md` and the versioned `internal/wire` implementations.

## Commit & Pull Request Guidelines

- Follow the existing history: short, imperative, prefixed subjects (e.g. `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `perf:`); check `git log --oneline` for current examples.
- PRs should include: a clear description of the behavior change, linked issues, test commands run and their results, and updated `docs/` / `examples/` when behavior or configuration changes.
- Do not commit secrets, keys, or live endpoint credentials; config examples must use placeholders.

## Security & Configuration Tips

- Crypto and KDF logic lives in `internal/wire` — changes there require extra scrutiny and benchmark evidence.
- Never log credentials or PSKs; the project uses ring-buffer logging (`logring.go`) — keep it secret-free.
