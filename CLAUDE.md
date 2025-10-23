# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

EigenX KMS AVS is a distributed key management system running as an EigenLayer AVS that provides threshold cryptography-based secret management. It uses BLS12-381 threshold signatures combined with Identity-Based Encryption (IBE) to ensure secure application secret access.

## Architecture

The system implements:
- **Distributed Key Generation (DKG)** with authenticated acknowledgements
- **Threshold signing** (⌈2n/3⌉ threshold) using BLS12-381 curves
- **Automatic key resharing** every 10 minutes for security rotation
- **Application signing** with threshold partial signatures
- **Authenticated P2P messaging** using BN254 signatures
- **Identity-Based Encryption (IBE)** for secure secret management

## Development Commands

### Build
```bash
# Build the POC binary
make build/cmd/poc

# Build with custom version and commit
make all
```

### Testing
```bash
# Run all tests
make test

# Run tests for specific package
go test ./pkg/node -v

# Run specific test
go test ./pkg/dkg -run TestGenerateShares -v

# Run integration tests only
go test ./internal/tests/integration -v
```

### Code Quality
```bash
# Run linter (requires golangci-lint)
make lint

# Format code
make fmt

# Check formatting
make fmtcheck
```

### Dependencies
```bash
# Install all dependencies including golangci-lint
make deps

# Update Go dependencies only
make deps/go
```

## Project Structure

```
eigenx-kms-go/
├── cmd/                    # Command-line applications
│   ├── kmsServer/         # Main KMS server binary
│   ├── registerOperator/  # Operator registration utility
│   └── debugAvsOperators/ # AVS debugging tool
├── pkg/                   # Core packages
│   ├── node/             # KMS node implementation
│   ├── dkg/              # Distributed Key Generation
│   ├── reshare/          # Key resharing protocol
│   ├── transport/        # Authenticated P2P communication
│   ├── peering/          # Operator discovery and validation
│   ├── crypto/           # BLS12-381 cryptographic operations
│   ├── keystore/         # Versioned key management
│   └── types/            # Core data structures
├── internal/             # Internal utilities
│   ├── tests/           # Test infrastructure and data
│   └── testData/        # ChainConfig and test accounts
├── contracts/           # Smart contracts (EigenLayer integration)
├── scripts/             # Build and setup scripts
└── docs/                # Technical documentation
```

## Core Architecture Components

### Node Infrastructure (`pkg/node/`)
- **`Node`**: Main KMS node with BN254 private key for P2P authentication
- **`Server`**: HTTP server handling authenticated inter-node communication
- **Address-based Identity**: Operators identified by Ethereum addresses, node IDs derived via `addressToNodeID()`

### Authenticated Messaging (`pkg/transport/`, `pkg/types/`)
- **`AuthenticatedMessage`**: All P2P messages wrapped with `Payload`, `Hash`, `Signature`
- **Message Security**: BN254 signatures over keccak256(payload), verified using crypto-libs
- **Address Validation**: Both sender and recipient addresses included in signed payload
- **Transport Layer**: Automatic message signing/verification with peer lookup

### Cryptographic Protocols (`pkg/dkg/`, `pkg/reshare/`)
- **DKG Protocol**: Complete implementation with authenticated acknowledgements to prevent equivocation
- **Share Verification**: Polynomial commitment verification in G2 group
- **Key Resharing**: Lagrange interpolation-based share redistribution
- **Threshold Calculation**: ⌈2n/3⌉ Byzantine fault tolerance

### Peering and Discovery (`pkg/peering/`)
- **`OperatorSetPeer`**: Core operator representation with BN254 public keys
- **`localPeeringDataFetcher`**: Test implementation using ChainConfig data
- **Dynamic Operator Sets**: Fetched from peering system, not hardcoded

### Key Management (`pkg/keystore/`)
- **`KeyShareVersion`**: Versioned key shares with epoch tracking
- **Time-based Keys**: Supports historical key versions for attestation time validation
- **Active Share Management**: Current vs pending key versions

## Testing Infrastructure

### Test Data (`internal/tests/`)
- **`ChainConfig`**: Real operator addresses and BN254 private keys from chain state
- **`utils.go`**: Helper functions for accessing test configuration
- Use `GetProjectRootPath()` + `ReadChainConfig()` for authentic test data

### Test Patterns
- **Unit Tests**: Use `createTestOperators()` with ChainConfig data
- **Integration Tests**: Use `testutil.NewTestCluster()` for multi-node scenarios  
- **Authentication Testing**: All tests validate BN254 signature flows
- **Peering Simulation**: Use `localPeeringDataFetcher` for realistic operator discovery

## Security Model

### Message Authentication
- Every inter-node message cryptographically signed with BN254 private keys
- Payload integrity protected via keccak256 hash verification
- Sender authentication via public key lookup from peering data
- Recipient verification ensures messages are intended for target operator

### Acknowledgement System
- Prevents dealer equivocation during DKG/reshare phases
- Players sign commitments to create non-repudiable acknowledgements
- Dealers must receive threshold acknowledgements before proceeding
- Uses same BN254 signing scheme as transport layer