# KMS Server Command

This command starts a KMS node server that participates in the distributed key management system.

## Usage

### Basic Usage
```bash
go run cmd/kms-server/main.go --node-id 1 --port 8001 --chain-id 31337
```

### With Environment Variables
```bash
export KMS_NODE_ID=1
export KMS_PORT=8001
export KMS_CHAIN_ID=11155111  # Sepolia testnet
export KMS_P2P_PRIVATE_KEY="your-base64-private-key"
export KMS_P2P_PUBLIC_KEY="your-base64-public-key"
export KMS_AUTO_DKG=true

go run cmd/kms-server/main.go
```

### Production Example (3-node cluster on anvil)

**Terminal 1 (Node 1):**
```bash
go run cmd/kms-server/main.go \
  --node-id 1 \
  --port 8001 \
  --chain-id 31337 \
  --verbose
```

**Terminal 2 (Node 2):**
```bash
go run cmd/kms-server/main.go \
  --node-id 2 \
  --port 8002 \
  --chain-id 31337 \
  --verbose
```

**Terminal 3 (Node 3):**
```bash
go run cmd/kms-server/main.go \
  --node-id 3 \
  --port 8003 \
  --chain-id 31337 \
  --auto-dkg \
  --verbose
```

## Configuration

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `--node-id` | `KMS_NODE_ID` | 1 | Unique node identifier |
| `--port` | `KMS_PORT` | 8000 | HTTP server port |
| `--chain-id` | `KMS_CHAIN_ID` | *required* | Ethereum chain ID (1=mainnet, 11155111=sepolia, 31337=anvil) |
| `--p2p-private-key` | `KMS_P2P_PRIVATE_KEY` | test key | ed25519 private key (base64) |
| `--p2p-public-key` | `KMS_P2P_PUBLIC_KEY` | test key | ed25519 public key (base64) |
| `--auto-dkg` | `KMS_AUTO_DKG` | false | Run DKG automatically on startup |
| `--verbose` | `KMS_VERBOSE` | false | Enable verbose logging |

## Chain Integration

The server automatically retrieves the operator set from the on-chain AVS registry based on the chain ID:

- **Mainnet (1)**: Queries production KMS AVS registry
- **Sepolia (11155111)**: Queries testnet KMS AVS registry  
- **Anvil (31337)**: Uses local development operator set

In production, this calls `IKmsAvsRegistry.getNodeInfos()` to get the current operator set.

## API Endpoints

Once running, the server exposes these endpoints:

### Application Endpoints
- `POST /secrets` - Applications request encrypted secrets and partial signatures
- `POST /app/sign` - Direct application signing (legacy)

### Protocol Endpoints  
- `POST /dkg/share` - DKG share distribution
- `POST /dkg/commitment` - DKG commitment broadcasting
- `POST /dkg/ack` - DKG acknowledgements
- `POST /reshare/share` - Reshare share distribution
- `POST /reshare/commitment` - Reshare commitment broadcasting
- `POST /reshare/ack` - Reshare acknowledgements
- `POST /reshare/complete` - Reshare completion signals

## Example Client Usage

After starting the servers, test with a client:

```go
// Use the KMS client
import "github.com/Layr-Labs/eigenx-kms-go/pkg/client"

client := client.NewKMSClient([]string{
    "http://localhost:8001",
    "http://localhost:8002", 
    "http://localhost:8003",
})

result, err := client.RetrieveSecrets("your-app-id", "sha256:your-image-digest")
if err != nil {
    log.Fatalf("Failed to retrieve secrets: %v", err)
}

fmt.Printf("Retrieved app private key: %x...\n", result.AppPrivateKey.X.Bytes()[:8])
fmt.Printf("Environment data: %s\n", result.EncryptedEnv)
```

Or test with a simple HTTP request:

```bash
curl -X POST http://localhost:8001/secrets \
  -H "Content-Type: application/json" \
  -d '{
    "app_id": "test-app",
    "attestation": "eyJ0ZXN0IjoiYXR0ZXN0YXRpb24ifQ==",
    "rsa_pubkey_tmp": "LS0tLS1CRUdJTi...",
    "attest_time": 1640995200
  }'
```