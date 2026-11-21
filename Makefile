MODULE     := github.com/PedroMartinezag/dock-prune-daemon
BINARY     := dock-prune-daemon
CMD_PKG    := ./cmd/dock-prune-daemon
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X $(MODULE)/internal/buildinfo.Version=$(VERSION) \
	-X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(MODULE)/internal/buildinfo.BuildDate=$(BUILD_DATE)

.PHONY: all verify-zero-dep vet test test-race fuzz-smoke lint build clean

all: verify-zero-dep vet test-race build

verify-zero-dep:
	@if grep -Eq '^[[:space:]]*require[[:space:]]' go.mod; then \
		echo "FATAL: external dependencies detected in go.mod (zero-dep contract violated)"; \
		exit 1; \
	fi
	@if [ -f go.sum ]; then \
		echo "FATAL: go.sum must not exist in a zero-dependency repository"; \
		exit 1; \
	fi
	@echo "OK: zero external dependencies verified."

vet:
	go vet ./...

test:
	go test -v -count=1 ./...

test-race:
	go test -race -count=1 -coverprofile=coverage.out ./...

fuzz-smoke:
	go test ./internal/config -run=^$$ -fuzz=FuzzParseByteSize -fuzztime=5s
	go test ./internal/config -run=^$$ -fuzz=FuzzLoadJSON -fuzztime=5s
	go test ./internal/config -run=^$$ -fuzz=FuzzEnvOverrides -fuzztime=5s

lint:
	golangci-lint run ./...

build: verify-zero-dep
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(CMD_PKG)

clean:
	rm -rf bin/ dist/ coverage.out coverage.html
