.PHONY: build clean test

GO = $(shell which go)
BIN = ./bin

GO_FLAGS=-ldflags "-X 'github.com/Layr-Labs/eigenx-kms-go/internal/version.Version=$(shell cat VERSION)' -X 'github.com/Layr-Labs/eigenx-kms-go/internal/version.Commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo 'unknown')'"


all: deps/go build/cmd/poc

# -----------------------------------------------------------------------------
# Dependencies
# -----------------------------------------------------------------------------
deps: deps/go
	./scripts/installDeps.sh
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0
	cd protos && buf dep update


.PHONY: deps/go
deps/go:
	${GO} mod tidy
	$(GO) install github.com/vektra/mockery/v3@v3.5.5


# -----------------------------------------------------------------------------
# Build binaries
# -----------------------------------------------------------------------------
.PHONY: cmd/poc
build/cmd/poc:
	go build $(GO_FLAGS) -o ${BIN}/poc ./cmd/poc

.PHONY: cmd/kmsServer
build/cmd/kmsServer:
	go build $(GO_FLAGS) -o ${BIN}/kms-server ./cmd/kmsServer


# -----------------------------------------------------------------------------
# Tests and linting
# -----------------------------------------------------------------------------
.PHONY: test
test:
	GOFLAGS="-count=1" go test -v -p 1 -parallel 1 ./...

.PHONY: lint
lint:
	golangci-lint run --timeout "5m"

.PHONY: fmt
fmt:
	gofmt -w .

.PHONY: fmtcheck
fmtcheck:
	@unformatted_files=$$(gofmt -l .); \
	if [ -n "$$unformatted_files" ]; then \
		echo "The following files are not properly formatted:"; \
		echo "$$unformatted_files"; \
		echo "Please run 'gofmt -w .' to format them."; \
		exit 1; \
	fi

.PHONY: mocks
mocks:
	@echo "Generating mocks..."
	mockery

# -----------------------------------------------------------------------------
# Contract targets
# -----------------------------------------------------------------------------

.PHONY: build/contracts
build/contracts:
	@echo "Building smart contract artifacts..."
	forge build

test/contracts:
	@echo "Running smart contract tests..."
	forge test
