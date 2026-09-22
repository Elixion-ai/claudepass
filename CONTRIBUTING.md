# Contributing to ClaudePass

ClaudePass is MIT-licensed and open to contributions. The goal is to be the standard way AI coding agents use Secrets without ever seeing them, so the bar is: every change keeps that guarantee provable.

## Before you start

- Read [`CONTEXT.md`](CONTEXT.md) for the vocabulary (Secret, Handle, Agent, Broker, Context, Redaction, Command Policy, Vault, Binding, Manifest, Capture, Intercept, Exposed) and use those terms, not the alternatives it lists under "avoid".
- Read the [ADRs](docs/adr/) touching the area you are changing. Do not reverse a decision without writing a superseding ADR; [ADR-0011](docs/adr/0011-free-and-open-source.md) is a recent example.
- The product spec is [`docs/PRD.md`](docs/PRD.md). What each component does and touches is in [`docs/SECURITY.md`](docs/SECURITY.md); the threat model is [`docs/THREATS.md`](docs/THREATS.md).

## Build and test

```bash
go build ./cmd/cpass
gofmt -l .
go vet -tags e2e ./...
golangci-lint run
go test -race -count=1 ./...
```

Those are the checks CI runs on macOS and Linux (CI also builds every package and runs a `cpass run` smoke test in CI mode). End-to-end tests build the `cpass` binary and drive it as a subprocess with `CPASS_HOME` and `CPASS_KEY` set, the same way an Agent uses it.

The leak test suite in `internal/e2e` tries every known reveal path and asserts nothing reaches stdout. It must stay green: a change that turns one of those tests red is a security regression, not a flaky test to skip.

### Real coverage, including the e2e subprocess (CLA-88)

`go test -coverprofile` alone reads misleadingly low for `internal/broker`, `internal/run`, `internal/cli` and `internal/mcp`: almost everything in those packages is exercised by driving the built `cpass`/`helper` binaries as `os/exec` subprocesses in `internal/e2e`, which self-instrumentation can't see into at all — see `internal/e2e/harness_test.go`'s `e2eCoverDir` doc comment for exactly why. This is a separate, opt-in recipe from the one above; an ordinary `go test ./...` is unaffected by it and no faster or slower for it existing.

```bash
covdir="$(mktemp -d)"
E2E_COVERDIR="$covdir" go test -cover ./... -args -test.gocoverdir="$covdir"
go tool covdata percent -i="$covdir" \
  -pkg=github.com/Elixion-ai/claudepass/internal/broker,github.com/Elixion-ai/claudepass/internal/run,github.com/Elixion-ai/claudepass/internal/cli,github.com/Elixion-ai/claudepass/internal/mcp
```

`E2E_COVERDIR` makes `internal/e2e`'s `TestMain` build `cpass`/`helper` with `-cover` and point their `GOCOVERDIR` at `$covdir`; `-args -test.gocoverdir="$covdir"` makes `go test -cover`'s own unit-test coverage (every package's direct tests, `internal/e2e`'s own included) land in the same directory in the same binary format, so one `go tool covdata` read covers both without a separate merge step. `go tool covdata textfmt -i="$covdir" -o=coverage.out` instead produces a classic profile for `go tool cover -html`/`-func`. `.github/workflows/ci.yml`'s `coverage` job runs this same recipe on every push, as a separate, advisory (`continue-on-error`) job from the one that actually gates merges.

## Submitting a change

- Keep commits and pull requests small and focused, and explain the why.
- If you change behaviour documented in `docs/SECURITY.md`, update the doc in the same change. The tests in `internal/e2e/docs_test.go` fail when the `CPASS_*` environment variable table or the on-disk path table drifts from what the source does, and they execute the README quickstart against the built binary.
- Never commit a real Secret, not even in a test. Fixtures use obviously fake values; the Intercept detector's own test data shows the pattern.

## Reporting a vulnerability

Do not open a public issue. See [`.github/SECURITY.md`](.github/SECURITY.md).
