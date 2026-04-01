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

check: lint test

release-snapshot:
    goreleaser release --snapshot --clean
