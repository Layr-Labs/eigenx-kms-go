# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

EigenX KMS AVS is a distributed key management system running as an EigenLayer AVS that provides threshold cryptography-based secret management. It uses BLS12-381 threshold signatures combined with Identity-Based Encryption (IBE) to ensure secure application secret access.

## Architecture

The system implements:
- Distributed Key Generation (DKG) protocol
- Threshold signing (⌈2n/3⌉ threshold)
- Automatic key resharing every 10 minutes
- Application signing with partial signatures that can be combined
- BLS12-381 elliptic curve cryptography

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
# Run tests
make test

# Note: goTest.sh script is referenced but not present, tests run with:
GOFLAGS="-count=1" ./scripts/goTest.sh -v -p 1 -parallel 1 ./...
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
├── cmd/poc/         # Proof of concept implementation
│   └── main.go      # Main DKG/reshare simulation
├── internal/        # Internal packages
│   └── version/     # Version information
├── scripts/         # Build and install scripts
├── docs/            # Technical documentation
└── Makefile         # Build automation
```

## Key Implementation Details

The POC (`cmd/poc/main.go`) implements:
- Complete DKG protocol with commitment verification
- Resharing protocol for operator set changes
- HTTP-based P2P communication between nodes
- Application signing with threshold signatures
- Acknowledgement system to prevent equivocation

### Core Types
- `Participant`: Self-contained KMS node with key shares and network handling
- `KeyShareVersion`: Versioned key shares with epoch tracking
- `OperatorInfo`: On-chain operator registration data

### Cryptographic Operations
- Uses `gnark-crypto` library for BLS12-381 operations
- Polynomial evaluation for secret sharing
- Lagrange interpolation for key/signature recovery
- Commitment verification in G2 group

## Testing the System

The POC includes a distributed simulation that:
1. Starts multiple KMS nodes on different ports
2. Runs initial DKG to establish shared secret
3. Tests application signing with threshold signatures
4. Demonstrates resharing protocol