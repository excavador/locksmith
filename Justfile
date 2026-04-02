default:
    @just --list

build:
    go build -ldflags "-X main.Version=dev -X main.Commit=$(git rev-parse --short HEAD) -X main.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.GoVersion=$(go version | cut -d' ' -f3)" -o bin/gpgsmith ./cmd/gpgsmith

test:
    go test ./...

lint:
    golangci-lint run

fmt:
    gofmt -w .

deps:
    go mod tidy
    go mod verify

check: deps fmt lint test build

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
