default:
    @just --list

build:
    go build -ldflags "-X main.Version=dev -X main.Commit=$(git rev-parse --short HEAD) -X main.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o bin/gpgsmith ./cmd/gpgsmith

test:
    go test ./...

lint:
    golangci-lint run

fmt:
    gofmt -w .

deps:
    go mod tidy
    go mod verify

check: lint test

# Regenerate ConnectRPC client/server code from proto/gpgsmith/v1/*.proto.
# Only schema editors need this; the generated code is committed to git so
# `go install` and CI work without buf installed.
generate:
    go generate ./pkg/gen

# Lint the .proto files. Separate from `just lint` (which runs golangci-lint
# on Go) so a misformatted .proto cannot break the Go developer feedback loop.
lint-proto:
    cd proto && buf lint

# Verify that running generate and lint-proto leaves the working tree clean.
# Used by CI to catch missing regeneration after a .proto edit.
generate-check:
    #!/usr/bin/env bash
    set -euo pipefail
    just generate
    if [ -n "$(git status --porcelain pkg/gen)" ]; then
        echo "ERROR: pkg/gen is dirty after 'just generate':"
        git diff --stat pkg/gen
        exit 1
    fi

all: deps fmt lint test build

tidy-check:
    #!/usr/bin/env bash
    set -euo pipefail
    just deps
    just fmt
    if [ -n "$(git status --porcelain)" ]; then
        echo "ERROR: working tree is dirty after 'just deps' and 'just fmt':"
        git diff --stat
        exit 1
    fi

release-snapshot:
    goreleaser release --snapshot --clean
