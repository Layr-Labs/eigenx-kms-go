# EigenX KMS Go Packages

This directory contains the modular packages for the EigenX KMS AVS implementation, following Go best practices and SOLID principles.

## Package Structure

### `/pkg/types`
Core type definitions and data structures shared across all packages:
- `OperatorInfo`: On-chain operator registration data
- `KeyShareVersion`: Versioned key share management
- `G1Point`, `G2Point`: BLS12-381 curve points
- Message types for network communication

### `/pkg/crypto`
Cryptographic operations and utilities:
- BLS12-381 curve operations (scalar multiplication, point addition)
- Polynomial evaluation for secret sharing
- Lagrange interpolation for secret recovery
- Hash functions for commitments and points

### `/pkg/keystore`
Thread-safe key management:
- Key version storage and retrieval
- Active/pending version management
- Time-based key version lookup
- Concurrent access protection

### `/pkg/dkg`
Distributed Key Generation protocol:
- Polynomial generation and secret sharing
- Commitment creation and verification
- Share verification using polynomial commitments
- Threshold calculation

### `/pkg/reshare`
Key resharing protocol:
- Dynamic threshold changes
- Operator set updates
- Share regeneration with preserved secret
- Completion signature management

### `/pkg/transport`
Network communication layer:
- HTTP client with retry logic
- Share and commitment broadcasting
- Acknowledgement handling
- Configurable retry policies

### `/pkg/node`
Main node implementation:
- Dependency injection for all components
- Protocol orchestration (DKG, resharing)
- HTTP server for peer communication
- State management and synchronization

## Design Principles

1. **Single Responsibility**: Each package has a focused, well-defined purpose
2. **Dependency Injection**: Components receive dependencies through constructors
3. **Interface Segregation**: Clean interfaces define package contracts
4. **Separation of Concerns**: Network, crypto, and protocol logic are isolated
5. **Thread Safety**: Concurrent access is properly synchronized
6. **Error Handling**: Explicit error returns and proper propagation

## Usage Example

```go
// Create node configuration
cfg := node.Config{
    ID:         1,
    Port:       8001,
    P2PPrivKey: privateKey,
    P2PPubKey:  publicKey,
    Operators:  operators,
}

// Create and start node
n := node.NewNode(cfg)
err := n.Start()

// Run DKG protocol
err = n.RunDKG()

// Sign application data
signature := n.SignAppID("app-id", timestamp)
```

## Testing

Each package can be tested independently:

```bash
go test ./pkg/crypto
go test ./pkg/dkg
go test ./pkg/node
```

## Future Improvements

- Add comprehensive unit tests for each package
- Implement real ed25519 signature verification
- Add metrics and monitoring interfaces
- Create mock implementations for testing
- Add configuration management
- Implement proper logging with structured logs