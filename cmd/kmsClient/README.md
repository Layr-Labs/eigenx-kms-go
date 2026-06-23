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

#### Decrypt Data with ECDSA Attestation

Some operator deployments require attestation before serving an application's
key material. The `decrypt` command can authenticate with an ECDSA
challenge-response attestation against the operators' `/secrets` endpoint:

```bash
# ECDSA key passed directly (hex, 0x prefix optional)
./bin/kms-client --avs-address "0x1234..." --operator-set-id 0 \
  decrypt --app-id "my-application" --encrypted-data encrypted-data.hex \
  --attestation ecdsa --ecdsa-private-key 0xabc123...

# ECDSA key read from a file
./bin/kms-client --avs-address "0x1234..." --operator-set-id 0 \
  decrypt --app-id "my-application" --encrypted-data encrypted-data.hex \
  --attestation ecdsa --ecdsa-private-key-file ./app-key.hex
```

Decrypt flags:

- `--attestation`: attestation method. Empty (default) uses the
  unauthenticated `/app/sign` endpoint; `ecdsa` uses ECDSA challenge-response
  attestation against `/secrets`.
- `--ecdsa-private-key`: hex-encoded secp256k1 private key (an optional `0x`
  prefix is accepted). Takes priority over `--ecdsa-private-key-file`.
- `--ecdsa-private-key-file`: path to a file containing the hex-encoded key.
  Used when `--ecdsa-private-key` is not set.

When `--attestation ecdsa` is set, at least one of `--ecdsa-private-key` or
`--ecdsa-private-key-file` is required.

**Prerequisites for the attested path** (stricter than the default
`/app/sign` flow):

- Operators must run with ECDSA attestation enabled
  (`--enable-ecdsa-attestation=true`).
- The app must exist on-chain so the operator can look up its creator. For ECDSA
  specifically, a published release is **not** required (env is returned only if
  a release exists); the signing key must belong to the app's creator.

**Security caveat:** ECDSA attestation proves only ownership of the ECDSA
private key and the freshness of the challenge. It does **not** prove a TEE
execution environment. The operator binds the ECDSA signer to the app's on-chain
**creator**: the `--ecdsa-private-key` / `--ecdsa-private-key-file` you supply
MUST be the key of the EOA that deployed/created the app, or the request is
rejected with `ecdsa signer is not the app creator`. The attested ECDSA path
does not require an on-chain release; it returns the app's environment only if a
release exists, and otherwise returns empty env alongside the recovered key.
Use ECDSA attestation for development and for operators configured to require
it — not as a production confidentiality guarantee. For production, use a TEE
attestation method (GCP Confidential Space / Intel Trust Authority).

## How It Works

### CLI Tool (This Binary)

1. **Operator Discovery**: Queries the blockchain using AVS address and operator set ID to get operators
2. **Master Public Key**: Queries `/pubkey` endpoint from all operators and computes master public key
3. **Encryption**: Uses IBE where app public key = `H_1(app_id)`
4. **Decryption**: Collects partial signatures from the `/app/sign` endpoint (no attestation) by default, or from the attested `/secrets` endpoint when `--attestation ecdsa` is set
5. **Fault Tolerance**: Handles operator failures automatically

**Note**: By default the CLI decrypt command uses `/app/sign`, which does NOT require attestation. Pass `--attestation ecdsa` to use the attested `/secrets` endpoint instead.

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

- `--environment`, `-e`: named connection preset that fills `--avs-address` and `--operator-set-id` (e.g. `sepolia`). Explicit flags override the preset. The RPC URL is never part of a preset.
- `--rpc-url`: Ethereum RPC endpoint (default: http://localhost:8545)
- `--avs-address`: AVS contract address (required unless provided by `--environment`)
- `--operator-set-id`: Operator set ID to use (default: 0)

All commands automatically discover and interact with the current operator set from the blockchain.

### Environments

`--environment` (alias `-e`) selects a named connection preset so you don't have
to pass `--avs-address`/`--operator-set-id` on every call:

| Environment | avs-address | operator-set-id |
|-------------|-------------|-----------------|
| `sepolia`   | `0x47c9806e7DC4e6fE9a0a2399831F32d06DaE5730` | `0` |

The preset supplies only `--avs-address` and `--operator-set-id`. It does **not**
set `--rpc-url` — production RPC URLs embed API-key credentials, so you must
still pass your own `--rpc-url`. Any flag you pass explicitly overrides the
preset value.

```bash
# Use the sepolia preset; supply your own RPC URL
./bin/kms-client --environment sepolia \
  --rpc-url "https://eth-sepolia.example/v2/<key>" \
  get-pubkey --app-id "my-application"

# Override the preset's operator-set-id
./bin/kms-client -e sepolia --operator-set-id 1 \
  --rpc-url "https://eth-sepolia.example/v2/<key>" \
  get-pubkey --app-id "my-application"
```