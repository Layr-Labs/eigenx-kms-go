# KMS Client

A CLI tool for interacting with EigenX KMS operators to encrypt and decrypt application data using threshold cryptography.

## Usage

### Prerequisites

1. Have running KMS operators with completed DKG
2. Know the AVS contract address and operator set ID
3. Access to Ethereum RPC endpoint
4. Know your application ID

### Commands

#### Get Master Public Key

```bash
./bin/kms-client --avs-address "0x1234..." --operator-set-id 0 \
  get-pubkey --app-id "my-application"
```

#### Encrypt Data

```bash
# Encrypt to stdout
./bin/kms-client --avs-address "0x1234..." --operator-set-id 0 \
  encrypt --app-id "my-application" --data "my secret configuration data"

# Encrypt to file
./bin/kms-client --avs-address "0x1234..." --operator-set-id 0 \
  encrypt --app-id "my-application" --data "my secret configuration data" \
  --output encrypted-data.hex
```

#### Decrypt Data

```bash
# Decrypt from hex string
./bin/kms-client --avs-address "0x1234..." --operator-set-id 0 \
  decrypt --app-id "my-application" --encrypted-data "deadbeef..."

# Decrypt from file  
./bin/kms-client --avs-address "0x1234..." --operator-set-id 0 \
  decrypt --app-id "my-application" --encrypted-data encrypted-data.hex \
  --output decrypted-data.txt

# Custom threshold and RPC
./bin/kms-client --rpc-url "https://eth-sepolia.g.alchemy.com/v2/..." \
  --avs-address "0x1234..." --operator-set-id 1 \
  decrypt --app-id "my-application" --encrypted-data encrypted-data.hex \
  --threshold 2
```

## How It Works

### CLI Tool (This Binary)

1. **Operator Discovery**: Queries the blockchain using AVS address and operator set ID to get operators
2. **Master Public Key**: Queries `/pubkey` endpoint from all operators and computes master public key
3. **Encryption**: Uses IBE where app public key = `H_1(app_id)`
4. **Decryption**: Collects partial signatures from `/app/sign` endpoint (no attestation required)
5. **Fault Tolerance**: Handles operator failures automatically

**Note**: The CLI decrypt command uses `/app/sign` which does NOT require attestation.

### Library (pkg/clients/kmsClient)

The `KMSClient` Go library supports two modes:

#### Mode 1: Basic IBE (No Attestation)
- Use `CollectPartialSignatures()` + `DecryptForApp()`
- Endpoint: `/app/sign`
- No attestation required
- Used by this CLI tool

#### Mode 2: Secrets Retrieval (With Attestation)
- Use `RetrieveSecretsWithOptions()`
- Endpoint: `/secrets`
- Requires attestation (GCP/Intel/ECDSA)
- For TEE applications needing environment variables + attestation proof

**Example with ECDSA attestation:**
```go
client := kmsClient.NewKMSClient(operatorURLs, logger)
result, err := client.RetrieveSecretsWithOptions("my-app", &kmsClient.SecretsOptions{
    AttestationMethod: "ecdsa",
    ECDSAPrivateKey:   myPrivateKey, // or nil to generate
})
// Returns: app private key + encrypted environment variables
```

**Example with GCP attestation:**
```go
result, err := client.RetrieveSecretsWithOptions("my-app", &kmsClient.SecretsOptions{
    AttestationMethod: "gcp",
    ImageDigest:       "sha256:...",
})
```

See `examples/ecdsa_attestation.go` for complete implementation.

## Security

- Operator information fetched directly from blockchain (no manual URL management)
- Threshold cryptography ensures no single operator can decrypt data
- Application ID serves as the identity in the IBE scheme
- Client validates operator responses and handles failures gracefully
- Uses existing authenticated operator endpoints for security

## Global Options

- `--rpc-url`: Ethereum RPC endpoint (default: http://localhost:8545)
- `--avs-address`: AVS contract address (required)
- `--operator-set-id`: Operator set ID to use (default: 0)

All commands automatically discover and interact with the current operator set from the blockchain.