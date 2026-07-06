#!/usr/bin/env bash

set -e          # Exit on any error
set -u          # Exit on undefined variables
set -o pipefail # Exit if any command in a pipe fails

# testEcdsaEncryptDecrypt.sh
#
# End-to-end check of the KMS ECDSA-attestation path against a live cluster:
# encrypt a plaintext for an app, then decrypt it back through the attested
# /secrets endpoint using an ECDSA private key, and assert the round-trip
# matches.
#
# The ECDSA key MUST belong to the app's on-chain creator (the EOA that
# deployed the app) — operators bind the ECDSA signer to the creator and
# reject anyone else with "ecdsa signer is not the app creator". Operators
# must also run with --enable-ecdsa-attestation=true.
#
# Usage:
#   ECDSA_PRIVATE_KEY=0x... APP_ID=my-app ETH_RPC_URL=https://... \
#     ./scripts/testEcdsaEncryptDecrypt.sh
#
# Environment variables:
#   ECDSA_PRIVATE_KEY  (required) hex secp256k1 key of the app creator EOA (0x optional)
#   APP_ID             (required) application ID to encrypt/decrypt for
#   ETH_RPC_URL        (required) Ethereum (Sepolia L1) RPC URL — used for operator discovery
#   ENVIRONMENT        (optional) client preset for avs-address/operator-set-id (default: sepolia)
#   PLAINTEXT          (optional) value to round-trip (default: an auto-generated marker)
#   AVS_ADDRESS        (optional) overrides the preset's AVS address
#   OPERATOR_SET_ID    (optional) overrides the preset's operator set ID

ECDSA_PRIVATE_KEY=${ECDSA_PRIVATE_KEY:-}
APP_ID=${APP_ID:-}
ETH_RPC_URL=${ETH_RPC_URL:-}
ENVIRONMENT=${ENVIRONMENT:-sepolia}
PLAINTEXT=${PLAINTEXT:-"ecdsa-roundtrip-check"}
AVS_ADDRESS=${AVS_ADDRESS:-}
OPERATOR_SET_ID=${OPERATOR_SET_ID:-}

if [[ -z "$ECDSA_PRIVATE_KEY" ]]; then
  echo "Error: ECDSA_PRIVATE_KEY environment variable is not set (hex secp256k1 key of the app creator)." >&2
  exit 1
fi

if [[ -z "$APP_ID" ]]; then
  echo "Error: APP_ID environment variable is not set." >&2
  exit 1
fi

if [[ -z "$ETH_RPC_URL" ]]; then
  echo "Error: ETH_RPC_URL environment variable is not set (Sepolia L1 RPC URL for operator discovery)." >&2
  exit 1
fi

# Resolve repo root from this script's location so it runs from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

CLIENT_BIN="${REPO_ROOT}/bin/kms-client"

# Build the client if it isn't already present.
if [[ ! -x "$CLIENT_BIN" ]]; then
  echo "==> Building kms-client..."
  make build/cmd/kmsClient
fi

# Assemble the connection flags shared by every invocation. The preset fills
# avs-address/operator-set-id; explicit overrides win (matching the CLI's own
# precedence). The RPC URL is never part of a preset, so we always pass it.
CONN_FLAGS=(--environment "$ENVIRONMENT" --rpc-url "$ETH_RPC_URL")
[[ -n "$AVS_ADDRESS" ]] && CONN_FLAGS+=(--avs-address "$AVS_ADDRESS")
[[ -n "$OPERATOR_SET_ID" ]] && CONN_FLAGS+=(--operator-set-id "$OPERATOR_SET_ID")

# Keep the ciphertext and the recovered plaintext in a private temp dir that is
# cleaned up on exit — the encrypted blob is written 0600 by the client, and we
# never want the recovered secret lingering in the repo tree.
WORK_DIR="$(mktemp -d)"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

ENCRYPTED_FILE="${WORK_DIR}/encrypted.hex"
DECRYPTED_FILE="${WORK_DIR}/decrypted.txt"

echo "==> Encrypting test value for app '${APP_ID}'..."
"$CLIENT_BIN" "${CONN_FLAGS[@]}" \
  encrypt \
  --app-id "$APP_ID" \
  --data "$PLAINTEXT" \
  --output "$ENCRYPTED_FILE"

echo "==> Decrypting via ECDSA attestation..."
"$CLIENT_BIN" "${CONN_FLAGS[@]}" \
  decrypt \
  --app-id "$APP_ID" \
  --encrypted-data "$ENCRYPTED_FILE" \
  --attestation ecdsa \
  --ecdsa-private-key "$ECDSA_PRIVATE_KEY" \
  --output "$DECRYPTED_FILE"

RECOVERED="$(cat "$DECRYPTED_FILE")"

echo
if [[ "$RECOVERED" == "$PLAINTEXT" ]]; then
  echo "✅ SUCCESS: round-trip matched for app '${APP_ID}'."
  exit 0
else
  echo "❌ FAILURE: decrypted value does not match the original." >&2
  echo "   expected: ${PLAINTEXT}" >&2
  echo "   got:      ${RECOVERED}" >&2
  exit 1
fi
