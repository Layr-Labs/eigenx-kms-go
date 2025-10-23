# Register Operator Command

This command registers an operator with the EigenKMS AVS registry contract.

## Usage

### Basic Registration
```bash
go run cmd/registerOperator/main.go \
  --avs-address 0x1234567890123456789012345678901234567890 \
  --operator-address 0xabcdefabcdefabcdefabcdefabcdefabcdefabcd \
  --operator-private-key ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --avs-private-key 47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a \
  --bn254-private-key 59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
  --socket http://operator.example.com:8001 \
  --operator-set-id 1 \
  --chain-id 31337
```

### With Environment Variables
```bash
export EIGENKMS_AVS_ADDRESS=0x1234567890123456789012345678901234567890
export EIGENKMS_OPERATOR_ADDRESS=0xabcdefabcdefabcdefabcdefabcdefabcdefabcd
export EIGENKMS_OPERATOR_PRIVATE_KEY=ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
export EIGENKMS_AVS_PRIVATE_KEY=47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a
export EIGENKMS_BN254_PRIVATE_KEY=59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
export EIGENKMS_SOCKET=http://operator.example.com:8001
export EIGENKMS_OPERATOR_SET_ID=1
export EIGENKMS_CHAIN_ID=31337

go run cmd/registerOperator/main.go
```

### Dry Run (Validation Only)
```bash
go run cmd/registerOperator/main.go \
  --avs-address 0x1234567890123456789012345678901234567890 \
  --operator-address 0xabcdefabcdefabcdefabcdefabcdefabcdefabcd \
  --operator-private-key ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --bn254-private-key 59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
  --socket http://operator.example.com:8001 \
  --operator-set-id 1 \
  --dry-run \
  --verbose
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--avs-address` | string | Yes | EigenKMS AVS registry contract address |
| `--operator-address` | string | Yes | Ethereum address of the operator |
| `--operator-private-key` | string | Yes | ECDSA private key for signing transactions (hex) |
| `--avs-private-key` | string | Yes | AVS ECDSA private key for AVS operations (hex) |
| `--bn254-private-key` | string | Yes | BN254 private key for threshold crypto (hex) |
| `--socket` | string | Yes | P2P socket address (http/https URL) |
| `--operator-set-id` | uint32 | Yes | Operator set ID to join (must be > 0) |
| `--chain-id` | uint64 | No | Ethereum chain ID (default: 31337 for anvil) |
| `--verbose` | bool | No | Enable verbose logging |
| `--dry-run` | bool | No | Validate only, don't execute |

## Parameter Details

### AVS Address
The deployed EigenKMS AVS registry contract address on the target chain.

### Operator Address
Your operator's Ethereum address that will be registered with the AVS.

### Operator Private Key
ECDSA private key (32 bytes as hex string) used to sign transactions. This key corresponds to the operator address.

**⚠️ Security**: Keep this key secure! It's used to sign on-chain transactions.

### AVS Private Key
AVS ECDSA private key (32 bytes as hex string) used for AVS-specific operations and signatures.

**⚠️ Security**: Keep this key secure! It's used for AVS protocol operations.

### BN254 Private Key
BN254 private key (32 bytes as hex string) used for threshold cryptography operations in the KMS protocol.

**⚠️ Security**: Keep this key secure! It's used for cryptographic operations.

### Socket Address
The HTTP/HTTPS endpoint where your KMS node server is running. Other operators will use this to communicate with your node.

### Operator Set ID
The operator set you want to join. Each operator set has its own threshold and participant list.

## Chain Support

| Chain | ID | Description |
|-------|----|-----------| 
| **Mainnet** | `1` | Production Ethereum |
| **Sepolia** | `11155111` | Ethereum testnet |
| **Anvil** | `31337` | Local development |

## Example Workflows

### 1. Local Testing (Anvil)
```bash
# Start local anvil chain
anvil

# Register operator
go run cmd/registerOperator/main.go \
  --avs-address 0x5FbDB2315678afecb367f032d93F642f64180aa3 \
  --operator-address 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
  --operator-private-key ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --bn254-private-key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --socket http://localhost:8001 \
  --operator-set-id 1 \
  --verbose
```

### 2. Testnet Registration (Sepolia)
```bash
go run cmd/registerOperator/main.go \
  --avs-address 0x... \
  --operator-address 0x... \
  --operator-private-key $OPERATOR_PRIVATE_KEY \
  --bn254-private-key $BN254_PRIVATE_KEY \
  --socket https://operator.mycompany.com:8001 \
  --operator-set-id 1 \
  --chain-id 11155111 \
  --verbose
```

### 3. Production Registration (Mainnet)
```bash
go run cmd/registerOperator/main.go \
  --avs-address 0x... \
  --operator-address 0x... \
  --operator-private-key $OPERATOR_PRIVATE_KEY \
  --bn254-private-key $BN254_PRIVATE_KEY \
  --socket https://kms-operator.mycompany.com:8001 \
  --operator-set-id 1 \
  --chain-id 1
```

## Security Considerations

1. **Private Key Management**: 
   - Store private keys securely (environment variables, vault systems)
   - Never commit private keys to version control
   - Use different keys for different environments

2. **Network Security**:
   - Use HTTPS for production socket addresses
   - Ensure firewall allows P2P communication on socket port
   - Monitor for unauthorized access attempts

3. **Validation**:
   - Always run with `--dry-run` first to validate parameters
   - Verify AVS contract address is correct for your target chain
   - Double-check operator set ID before registration

## Troubleshooting

### Common Errors

**Invalid private key format:**
```
Error: ECDSA private key must be 32 bytes (64 hex chars), got 62 chars
```
Solution: Ensure private key is exactly 64 hex characters (32 bytes)

**Invalid socket address:**
```
Error: socket address must start with http:// or https://
```
Solution: Include protocol prefix in socket address

**Unsupported chain:**
```
Error: unsupported chain ID 999. Supported: 1 (mainnet), 11155111 (sepolia), 31337 (anvil)
```
Solution: Use one of the supported chain IDs