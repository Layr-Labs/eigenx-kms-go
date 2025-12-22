# EigenX KMS AVS

A distributed key management system running as an EigenLayer AVS that provides threshold cryptography-based secret management using Identity-Based Encryption (IBE).

## Overview

EigenX KMS enables applications to securely encrypt and decrypt data using a distributed network of operators. The system uses:

- **BLS12-381 threshold signatures** for distributed key generation and signing
- **Identity-Based Encryption (IBE)** where application IDs serve as public keys
- **Automatic key resharing** at regular intervals for security rotation
- **Byzantine fault tolerance** with ceiling(2n/3) threshold for partial signature recovery
- **100% operator participation** required for DKG to ensure complete key distribution

## Quick Start

### Prerequisites

- Go 1.21+
- Access to Ethereum RPC endpoint
- Registered operator with EigenLayer AVS

### Build

```bash
# Build all binaries
make all

# Or build specific components
make build/cmd/kmsServer    # KMS node server
make build/cmd/kmsClient    # KMS client CLI
```

### Run a KMS Operator

```bash
./bin/kms-server \
  --operator-address "0x..." \
  --bn254-private-key "0x..." \
  --avs-address "0x..." \
  --operator-set-id 0 \
  --chain-id 1 \
  --rpc-url "https://eth-mainnet.g.alchemy.com/v2/..." \
  --port 8080
```

The node will automatically:
1. Wait for the first interval boundary (10 minutes for mainnet)
2. Detect if genesis DKG is needed (query other operators)
3. Execute DKG if no master key exists, or join via reshare
4. Automatically reshare keys every interval

### Use the KMS Client

```bash
# Encrypt data for an application
./bin/kms-client --avs-address "0x..." --operator-set-id 0 \
  encrypt --app-id "my-app" --data "secret-config" --output encrypted.hex

# Decrypt data
./bin/kms-client --avs-address "0x..." --operator-set-id 0 \
  decrypt --app-id "my-app" --encrypted-data encrypted.hex
```

## How It Works

### Automatic Protocol Execution

Every node runs a 500ms scheduler that:

1. **Calculates interval boundary** (rounded to chain-specific interval)
2. **Checks if boundary already processed** (prevents duplicates)
3. **Determines operator state**:
   - Has shares?  Run reshare as existing operator
   - No shares?  Query peers to detect genesis vs existing cluster
4. **Executes appropriate protocol** with synchronized session timestamp

### Distributed Key Generation (DKG)

**Trigger**: First interval boundary when no master key exists

**Process**:
1. Each operator generates random polynomial `f_i(z)`
2. Operators broadcast commitments and send shares to all peers
3. Each operator verifies received shares and sends acknowledgements
4. All operators finalize: `master_secret = sum(f_i(0))` across all operators

**Requirement**: ALL operators must participate (100% acknowledgements)

### Automatic Resharing

**Trigger**: Every interval boundary (10min/2min/30s depending on chain)

**Process**:
1. Existing operators use current share as `f'_i(0) = current_share_i`
2. Generate new shares and distribute to ALL operators (including new ones)
3. Each operator computes new share via Lagrange interpolation
4. Master secret preserved: `sum(f'_i(0)) = sum(current_share_i) = original_master_secret`

**New Operator Joining**:
- Waits for next interval boundary
- Detects existing cluster (peers have commitments)
- Receives shares from existing operators
- Computes share via Lagrange interpolation

### Identity-Based Encryption (IBE)

**Encryption**: `ciphertext = Encrypt(H_1(app_id), master_public_key, plaintext)`

**Decryption**:
1. Client collects ceiling(2n/3) partial signatures from operators
2. Recovers `app_private_key = sum(lambda_i * partial_sig_i)` (Lagrange interpolation)
3. Decrypts: `plaintext = Decrypt(app_private_key, ciphertext)`

## Architecture

### Components

- **`cmd/kmsServer`**: KMS node server with automatic scheduler
- **`cmd/kmsClient`**: CLI for encrypting/decrypting data
- **`pkg/node`**: Core node logic, DKG, and reshare protocols
- **`pkg/transport`**: Authenticated P2P communication with BN254 signatures
- **`pkg/client`**: KMSClient library for applications
- **`pkg/crypto`**: BLS12-381 cryptographic operations

### Chain-Specific Configuration

| Chain | Reshare Interval | Use Case |
|-------|-----------------|----------|
| Mainnet | 10 minutes | Production |
| Sepolia | 2 minutes | Testnet |
| Anvil | 30 seconds | Local testing |

## Security Model

### Message Authentication

All inter-node messages include:
- `FromOperatorAddress` and `ToOperatorAddress` in signed payload
- `SessionTimestamp` for protocol coordination
- BN254 signature over `keccak256(payload)`

Recipients verify:
1. Payload hash matches
2. Signature valid using sender's BN254 public key
3. Message intended for this operator
4. Session exists and is valid

### Threshold Properties

- **DKG**: Requires 100% operator participation (all must send shares + acknowledgements)
- **Partial Signatures**: Requires ceiling(2n/3) operators for app key recovery
- **Byzantine Fault Tolerance**: System secure with up to floor(n/3) malicious operators

## Development

### Testing

```bash
# Run all tests
make test

# Run specific test
go test ./pkg/node -v

# Run integration tests
go test ./internal/tests/integration -v
```

### Linting

```bash
make lint
```

## Documentation

- **[CLAUDE.md](./CLAUDE.md)**: Architecture and development guide
- **[Execution Plan](./docs/001_cleanupExecutionPlan.md)**: Implementation milestones
- **[Server README](./cmd/kmsServer/README.md)**: Server configuration and API
- **[Client README](./cmd/kmsClient/README.md)**: Client usage examples

## License

See LICENSE file for details.

## ⚠️ Warning: This is Alpha, non-audited code ⚠️
eigenx-kms-go is in active development and is not yet audited. Use at your own risk.
