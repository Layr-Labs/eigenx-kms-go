.PHONY: build clean test

GO = $(shell which go)
BIN = ./bin

GO_FLAGS=-ldflags "-X 'github.com/Layr-Labs/eigenx-kms-go/internal/version.Version=$(shell cat VERSION)' -X 'github.com/Layr-Labs/eigenx-kms-go/internal/version.Commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo 'unknown')'"


all: deps/go build/cmd

# -----------------------------------------------------------------------------
# Dependencies
# -----------------------------------------------------------------------------
deps: deps/go


.PHONY: deps/go
deps/go:
	${GO} mod tidy
	$(GO) install github.com/vektra/mockery/v3@v3.5.5
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.5.0


# -----------------------------------------------------------------------------
# Build binaries
# -----------------------------------------------------------------------------

.PHONY: cmd/kmsServer
build/cmd/kmsServer:
	go build $(GO_FLAGS) -o ${BIN}/kms-server ./cmd/kmsServer

.PHONY: cmd/registerOperator
build/cmd/registerOperator:
	go build $(GO_FLAGS) -o ${BIN}/register-operator ./cmd/registerOperator

.PHONY: cmd/kmsClient
build/cmd/kmsClient:
	go build $(GO_FLAGS) -o ${BIN}/kms-client ./cmd/kmsClient

.PHONY: build/cmd
build/cmd: build/cmd/kmsServer build/cmd/registerOperator build/cmd/kmsClient

# -----------------------------------------------------------------------------
# Tests and linting
# -----------------------------------------------------------------------------
.PHONY: forge-test
forge-test:
	forge test

.PHONY: test
test: forge-test
	GOFLAGS="-count=1" ./scripts/goTest.sh -v -p 1 -parallel 1 ./...

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

.PHONY: anvil/start/l1
anvil/start/l1:
	anvil \
		--fork-url https://practical-serene-mound.ethereum-sepolia.quiknode.pro/3aaa48bd95f3d6aed60e89a1a466ed1e2a440b61/ \
		--load-state ./internal/testData/anvil-l1-state.json \
		--chain-id 31337 \
		--fork-block-number 9778678 \
		--block-time 2 \
		--port 8545

.PHONY: anvil/start/l1-live
anvil/start/l1-live:
	anvil \
		--fork-url https://practical-serene-mound.ethereum-sepolia.quiknode.pro/3aaa48bd95f3d6aed60e89a1a466ed1e2a440b61/ \
		--block-time 2 \
		--port 8545

.PHONY: anvil/start/l2
anvil/start/l2:
	anvil \
		--fork-url https://soft-alpha-grass.base-sepolia.quiknode.pro/fd5e4bf346247d9b6e586008a9f13df72ce6f5b2/ \
		--load-state ./internal/testData/anvil-l2-state.json \
		--chain-id 31338 \
		--fork-block-number 34610863 \
		--block-time 2 \
		--port 9545
