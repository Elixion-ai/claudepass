# ClaudePass

A secret manager for AI coding agents. `cpass` lets an Agent use a Secret at
the point a command runs without the value ever entering the Agent's
Context. See [`CONTEXT.md`](CONTEXT.md) for vocabulary, [`docs/adr/`](docs/adr/)
for design decisions, and [`docs/PRD.md`](docs/PRD.md) for the product spec.

## Install

`gumruyanzh/claudepass` is a private repository (closed source, see
[ADR-0006](docs/adr/0006-closed-source-paid.md)); both install paths below
need read access to it.

**curl:**

```bash
export GITHUB_TOKEN=$(gh auth token)   # or any token with read access to the repo
curl -fsSL https://raw.githubusercontent.com/gumruyanzh/claudepass/main/install.sh | sh
```

**Homebrew** (from the owner's tap):

```bash
export HOMEBREW_GITHUB_API_TOKEN=$(gh auth token)
brew tap softorize/tap
brew install cpass
```

Both installers, and the release pipeline that feeds them, are covered by
`.goreleaser.yaml`, `.github/workflows/release.yml`, and `install.sh` at the
repo root — see CLA-16.

## Build from source

```bash
go build -o cpass ./cmd/cpass
go test -race -count=1 ./...
```
