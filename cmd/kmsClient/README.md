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

1. **Operator Discovery**: The client queries the blockchain using the AVS address and operator set ID to get the current list of operators and their socket addresses

2. **Master Public Key Retrieval**: Queries all active operators for their current commitments via the `/pubkey` endpoint and computes the master public key using `crypto.ComputeMasterPublicKey()`

3. **Encryption**: Uses Identity-Based Encryption (IBE) where the application's public key is derived from `H_1(app_id)` and encryption is performed with the master public key

4. **Decryption**: Collects threshold partial signatures from operators via the `/app/sign` endpoint, recovers the application's private key using Lagrange interpolation, and decrypts the data

5. **Fault Tolerance**: Automatically handles operator failures and collects signatures until the threshold is met

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