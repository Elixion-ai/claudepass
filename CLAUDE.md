# ClaudePass

Secret manager for AI coding agents. Read `CONTEXT.md` for vocabulary and `docs/adr/` for decisions before changing anything. The PRD is `docs/PRD.md`.

## Agent skills

### Issue tracker

Elixion, project key `CLA`, via the elixion MCP tools. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-label vocabulary. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` and `docs/adr/` at the root. See `docs/agents/domain.md`.

## Build and test

Go, single binary `cpass`. `go build ./cmd/cpass && go test ./...`. End-to-end tests drive the built binary with `CPASS_HOME` and `CPASS_KEY` set; leak tests live in `internal/e2e` and must stay green.
