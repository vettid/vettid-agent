BINARY_NAME := vettid-agent
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)"

.PHONY: build test lint clean release

build:
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/vettid-agent

test:
	go test -race -v ./...

lint:
	go vet ./...
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./...; fi

clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/

release: clean
	mkdir -p dist
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64   ./cmd/vettid-agent
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64   ./cmd/vettid-agent
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64  ./cmd/vettid-agent
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64  ./cmd/vettid-agent
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe ./cmd/vettid-agent
	@echo "Release binaries in dist/"
	@cd dist && for f in $(BINARY_NAME)-*; do sha256sum "$$f" >> checksums.txt; done
