# KMS Server Command

This command starts a KMS node server that participates in the distributed key management system using authenticated messaging and address-based operator identification.

## Usage

### Basic Usage
```bash
make build/cmd/kmsServer
./bin/kms-server \
  --operator-address "0x..." \
  --bn254-private-key "0x..." \
  --avs-address "0x..." \
  --operator-set-id 0 \
  --chain-id 31337 \
  --port 8001
```

### From Source
```bash
go run cmd/kmsServer/main.go \
  --operator-address "0x..." \
  --bn254-private-key "0x..." \
  --avs-address "0x..." \
  --operator-set-id 0 \
  --chain-id 31337 \
  --port 8001
```

### Configuration

Required flags:
- **`--operator-address`**: Ethereum address identifying this operator
- **`--bn254-private-key`**: BN254 private key for P2P authentication and threshold crypto
- **`--avs-address`**: AVS contract address for operator discovery
- **`--chain-id`**: Ethereum chain ID (1=mainnet, 11155111=sepolia, 31337=anvil)

Optional flags:
- **`--rpc-url`**: Ethereum RPC endpoint (default: http://localhost:8545)
- **`--operator-set-id`**: Operator set ID (default: 0)
- **`--port`**: HTTP server port (default: 8000)
- **`--dkg-at`**: Unix timestamp for coordinated DKG (0=immediate)
- **`--verbose`**: Enable debug logging

## Key Architecture Changes

### Address-Based Identity
- Operators identified by Ethereum addresses (not sequential node IDs)
- Node IDs derived from addresses using `addressToNodeID(keccak256(address))`
- Consistent identity across DKG, reshare, and client operations

### Authenticated Messaging
- All inter-node messages signed with BN254 private keys
- Message format: `{payload: []byte, hash: [32]byte, signature: []byte}`
- Recipients verify sender identity using on-chain public keys

### Dynamic Operator Discovery
- Operators fetched from peering system (not hardcoded)
- Uses `peering.IPeeringDataFetcher` interface for operator set retrieval
- Supports both on-chain and local/test configurations

## Protocol Operations

### DKG (Distributed Key Generation)
- Nodes execute DKG protocol to establish shared secret
- Uses authenticated acknowledgements to prevent equivocation  
- Threshold: ⌈2n/3⌉ signatures required for completion
- Node IDs derived from operator addresses for consistency

### Key Resharing  
- Automatic resharing every 10 minutes for security
- Supports dynamic operator set changes
- Maintains key share versions with epoch tracking

### Application Signing
- Provides partial signatures for application private key recovery
- Uses BLS12-381 threshold signatures
- Time-based key version selection for historical requests

## API Endpoints

Once running, the server exposes these endpoints:

### Application Endpoints
- `POST /secrets` - TEE applications request encrypted secrets and partial signatures
- `POST /app/sign` - Direct application partial signature requests
- `GET /pubkey` - Public key commitments for master key computation

### Protocol Endpoints (Authenticated)
All protocol endpoints require `AuthenticatedMessage` wrapper with BN254 signatures:

- `POST /dkg/share` - DKG share distribution with authentication
- `POST /dkg/commitment` - DKG commitment broadcasting
- `POST /dkg/ack` - DKG acknowledgements (prevents equivocation)
- `POST /reshare/share` - Reshare share distribution
- `POST /reshare/commitment` - Reshare commitment broadcasting  
- `POST /reshare/ack` - Reshare acknowledgements
- `POST /reshare/complete` - Reshare completion signals

## Client Integration

### Using KMS Client CLI

The recommended way to interact with the KMS is via the `kmsClient` CLI:

```bash
# Build the client
make build/cmd/kmsClient

# Encrypt data (discovers operators from chain)
./bin/kms-client --avs-address "0x..." --operator-set-id 0 \
  encrypt --app-id "my-app" --data "secret-config" --output encrypted.hex

# Decrypt data (collects threshold signatures)
./bin/kms-client --avs-address "0x..." --operator-set-id 0 \
  decrypt --app-id "my-app" --encrypted-data encrypted.hex
```

### Direct HTTP Testing

Test individual endpoints:

```bash
# Get operator's public key commitments
curl -X GET http://localhost:8001/pubkey

# Request partial signature
curl -X POST http://localhost:8001/app/sign \
  -H "Content-Type: application/json" \
  -d '{
    "appID": "test-app", 
    "attestationTime": 0
  }'

# Request secrets (TEE applications)
curl -X POST http://localhost:8001/secrets \
  -H "Content-Type: application/json" \
  -d '{
    "app_id": "test-app",
    "attestation": "eyJ0ZXN0IjoiYXR0ZXN0YXRpb24ifQ==",
    "rsa_pubkey_tmp": "LS0tLS1CRUdJTi...",
    "attest_time": 1640995200
  }'
```

## Security Model

### Message Authentication
- Every inter-node message includes sender's Ethereum address
- Messages signed with operator's BN254 private key  
- Recipients verify signatures using public keys from peering data
- Prevents message forgery and ensures operator authenticity

### Acknowledgement System
- DKG phase includes authenticated acknowledgements
- Prevents dealer equivocation during share distribution
- Players must acknowledge valid shares before DKG completion
- Uses same BN254 signing scheme as transport layer

### Threshold Properties
- Requires ⌈2n/3⌉ operators for key operations
- Byzantine fault tolerance against malicious operators
- No single point of failure in key management
- Automatic key resharing maintains security over time

## Testing

### Unit Tests
```bash
# Run server tests
go test ./pkg/node -v

# Test authenticated messaging
go test ./pkg/transport ./pkg/types -v
```

### Integration Testing
```bash
# Test full protocol with multiple nodes
go test ./internal/tests/integration -v

# Test with real operator data
go test ./pkg/testutil -v
```

## Implementation Status

### Current Features
- ✅ Authenticated inter-node messaging with BN254 signatures
- ✅ Complete DKG protocol with acknowledgement system  
- ✅ Address-based operator identification
- ✅ `/pubkey` endpoint for client master key computation
- ✅ `/app/sign` endpoint for partial signature collection

### Configuration Requirements
The server requires proper `peering.IPeeringDataFetcher` implementation:
- For production: Use on-chain peering data fetcher
- For testing: Use `localPeeringDataFetcher` with ChainConfig data
- The `fetchCurrentOperators` method uses the injected `peeringDataFetcher`

### Local Development
For testing, use the ChainConfig test data:
- 5 preconfigured operator addresses and BN254 keys
- Located in `internal/testData/chain-config.json`
- Accessed via `tests.GetProjectRootPath()` and `tests.ReadChainConfig()`
- Use `localPeeringDataFetcher.NewLocalPeeringDataFetcher()` for testing