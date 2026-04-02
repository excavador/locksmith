# locksmith

## CRITICAL: Shell environment (devbox + direnv)

This project uses devbox + direnv. You MUST follow this pattern for ALL bash commands:

1. First bash call: `cd` to the project root (ONLY cd, nothing else)
2. Second bash call: your actual command (e.g., `go build ./...`)

NEVER combine cd with other commands: `cd /path && go build` WILL FAIL.
NEVER manually set PATH or run `eval "$(devbox shellenv)"` in the main session.
The direnv CwdChanged hook loads the environment automatically AFTER the cd call completes.

This pattern works for both the main session and subagents.

---

GPG key lifecycle manager with YubiKey support and encrypted vault storage.

## Commands

Prefer Justfile recipes over raw commands for build, test, lint:
- `just build` — build binary to bin/gpgsmith
- `just test` — run all tests
- `just lint` — run golangci-lint
- `just check` — lint + test
- `just fmt` — format code

## Stack

- Go 1.26+, urfave/cli/v3
- filippo.io/age for encryption
- Shells out to `gpg` binary for GPG operations
- log/slog to stderr, minimal stdout for piping

## Conventions

- `cmd/gpgsmith/main.go` — minimal entrypoint with ldflags
- `pkg/gpgsmith/` — Main() with signal handling, slog, CLI wiring
- `pkg/vault/` — encrypted snapshot storage (age + tar)
- `pkg/gpg/` — GPG operations, inventory, audit
- Config: YAML files (vault config + GPG config inside GNUPGHOME)
- Use `.yaml` extension for all config files

