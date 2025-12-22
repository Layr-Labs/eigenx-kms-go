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
# Build all binaries
make all

# Build specific components
make build/cmd/poc          # DKG proof of concept
make build/cmd/kmsServer    # KMS node server
make build/cmd/kmsClient    # KMS client CLI
make build/cmd/registerOperator  # Operator registration utility
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
│   ├── kmsClient/         # Client CLI for encrypt/decrypt operations
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
- **Address-based Identity**: Operators identified by Ethereum addresses, node IDs derived via `util.AddressToNodeID()`

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

## Attestation Methods

The KMS server supports multiple attestation methods for verifying application identity and integrity:

### Google Confidential Space (GCP) / Intel Trust Authority
- **Method Name**: `"gcp"` or `"intel"`
- **Use Case**: Production environments requiring hardware TEE attestation
- **Provides**: Proof of TEE execution environment, software image integrity
- **Format**: JWT token from Confidential Space or Trust Authority
- **Security**: Highest - cryptographically proves code running in secure enclave
- **Configuration**: Requires `--gcp-project-id` and `--attestation-provider`
- **Default**: Enabled by default (`--enable-gcp-attestation=true`)

### ECDSA Signature-Based
- **Method Name**: `"ecdsa"`
- **Use Case**: Development, testing, non-TEE environments
- **Provides**: Proof of ECDSA private key ownership
- **Format**: Challenge-response with ECDSA signature
- **Security**: Basic - only proves key ownership, not execution environment
- **Configuration**: Enable with `--enable-ecdsa-attestation=true`
- **Default**: Disabled by default

### Attestation Method Selection

Configure at server startup:
```bash
# GCP only (default)
./bin/kms-server --gcp-project-id my-project ...

# ECDSA only (development)
./bin/kms-server --enable-gcp-attestation=false --enable-ecdsa-attestation=true ...

# Both methods enabled
./bin/kms-server --gcp-project-id my-project --enable-ecdsa-attestation=true ...
```

Client specifies method in `/secrets` request:
```json
{
  "app_id": "my-app",
  "attestation_method": "ecdsa",
  "attestation": "<signature>",
  "challenge": "<timestamp>-<nonce>",
  "public_key": "<ecdsa-pubkey>"
}
```

### ECDSA Attestation Protocol

Challenge format: `<timestamp>-<nonce_hex>` (e.g., `1702857600-a1b2c3d4...`)
- `timestamp`: Unix seconds (prevents replay attacks)
- `nonce`: 32 bytes hex (prevents replay within time window)

Signed message: `keccak256(appID || "-" || challenge || "-" || publicKey_hex)`

Time window: 5 minutes (default, configurable)

See `examples/ecdsa_attestation.go` for complete implementation example.

## KMS Client Usage

The `kmsClient` CLI provides application developers with tools to encrypt/decrypt data using the distributed KMS:

```bash
# Get master public key for an application
./bin/kms-client --avs-address "0x..." --operator-set-id 0 \
  get-pubkey --app-id "my-app"

# Encrypt data for an application  
./bin/kms-client --avs-address "0x..." --operator-set-id 0 \
  encrypt --app-id "my-app" --data "secret-config-data" --output encrypted.hex

# Decrypt data by collecting threshold signatures
./bin/kms-client --avs-address "0x..." --operator-set-id 0 \
  decrypt --app-id "my-app" --encrypted-data encrypted.hex

# Use custom RPC URL
./bin/kms-client --rpc-url "https://eth-sepolia.g.alchemy.com/v2/..." \
  --avs-address "0x..." --operator-set-id 1 \
  encrypt --app-id "my-app" --data "secret-data"
```

### Client Flow
1. **Operator Discovery**: Queries blockchain via `contractCaller.GetOperatorSetMembersWithPeering()` 
2. **Master Public Key**: Collects commitments from operators via `/pubkey` endpoint
3. **Encryption**: Uses IBE encryption with computed master public key
4. **Decryption**: Collects partial signatures via `/app/sign` endpoint and recovers app private key
5. **Threshold Security**: Requires ⌈2n/3⌉ operator signatures for decryption
- dont create useless test results files