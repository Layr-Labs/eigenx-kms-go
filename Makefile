.PHONY: build clean test

GO = $(shell which go)
BIN = ./bin

# Version/commit embedded into every build. Kept as a bare ldflags fragment (no
# -ldflags prefix) so it can be composed into a SINGLE -ldflags arg below: go
# build only honors the LAST -ldflags it sees, so two separate -ldflags would
# silently drop one set. See GO_FLAGS_STATIC.
VERSION_LDFLAGS=-X 'github.com/Layr-Labs/eigenx-kms-go/internal/version.Version=$(shell cat VERSION)' -X 'github.com/Layr-Labs/eigenx-kms-go/internal/version.Commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo 'unknown')'

GO_FLAGS=-ldflags "$(VERSION_LDFLAGS)"

# Static build folds the version flags into the same -ldflags as -s -w -extldflags;
# a previous `$(GO_FLAGS) -ldflags=...` form emitted two -ldflags and lost the
# version embedding (the whole point of provenance for the in-TEE helper).
GO_FLAGS_STATIC=-ldflags "-s -w -extldflags '-static' $(VERSION_LDFLAGS)"

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

.PHONY: build/cmd/kmsClient
build/cmd/kmsClient:
	go build $(GO_FLAGS) -o ${BIN}/kms-client ./cmd/kmsClient

.PHONY: build/cmd/kmsClient/static
build/cmd/kmsClient/static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		$(GO_FLAGS_STATIC) \
		-trimpath -buildvcs=false \
		-o ${BIN}/kms-client ./cmd/kmsClient

.PHONY: build/cmd/kmsCDHHelper
build/cmd/kmsCDHHelper:
	go build $(GO_FLAGS) -o ${BIN}/eigenx-cdh-helper ./cmd/kmsCDHHelper

# Static linux/amd64 eigenx-cdh-helper for the podVM AMI build (it bakes this
# binary into the SEV-SNP guest image — see ecloud-platform-infra
# podvm-build.sh). Built reproducibly (CGO off, -trimpath) and published as a
# release asset so the in-TEE binary traces to a git tag/commit instead of a
# hand-uploaded S3 blob.
.PHONY: build/cmd/kmsCDHHelper/static
build/cmd/kmsCDHHelper/static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		$(GO_FLAGS_STATIC) \
		-trimpath -buildvcs=false \
		-o ${BIN}/eigenx-cdh-helper ./cmd/kmsCDHHelper

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

.PHONY: anvil/start/l2-live
anvil/start/l2-live:
	anvil \
		--fork-url https://soft-alpha-grass.base-sepolia.quiknode.pro/fd5e4bf346247d9b6e586008a9f13df72ce6f5b2/ \
		--block-time 2 \
		--port 9545
