#!/usr/bin/env bash
set -euo pipefail

PRIVATE_KEY_DEPLOYER=${PRIVATE_KEY_DEPLOYER:-}
PRIVATE_KEY_AVS=${PRIVATE_KEY_AVS:-}
ETH_RPC_URL=${ETH_RPC_URL:-"http://localhost:8545"}
BASE_RPC_URL=${BASE_RPC_URL:-"http://localhost:9545"}

# Registrar upgrade (L1)
REGISTRAR_PROXY=${REGISTRAR_PROXY:-"0xfe0c3C2DB3b767f768F9000d48193F0EE0BfC07D"}
REGISTRAR_PROXY_ADMIN=${REGISTRAR_PROXY_ADMIN:-"0x396453d3f233da7771f292a5aa9dcfb59c87241e"}

# Commitment Registry upgrade (L2)
COMMITMENT_REGISTRY_PROXY=${COMMITMENT_REGISTRY_PROXY:-"0xfe0c3C2DB3b767f768F9000d48193F0EE0BfC07D"}
COMMITMENT_REGISTRY_PROXY_ADMIN=${COMMITMENT_REGISTRY_PROXY_ADMIN:-"0x396453d3f233da7771f292a5aa9dcfb59c87241e"}

if [[ -z "$PRIVATE_KEY_DEPLOYER" ]]; then
  echo "Error: PRIVATE_KEY_DEPLOYER environment variable is not set."
  exit 1
fi

if [[ -z "$PRIVATE_KEY_AVS" ]]; then
  echo "Error: PRIVATE_KEY_AVS environment variable is not set."
  exit 1
fi

upgrade_registrar=false
upgrade_commitment_registry=false

if [[ -n "$REGISTRAR_PROXY" && -n "$REGISTRAR_PROXY_ADMIN" ]]; then
  upgrade_registrar=true
fi

if [[ -n "$COMMITMENT_REGISTRY_PROXY" && -n "$COMMITMENT_REGISTRY_PROXY_ADMIN" ]]; then
  upgrade_commitment_registry=true
fi

if [[ "$upgrade_registrar" == "false" && "$upgrade_commitment_registry" == "false" ]]; then
  echo "Error: No upgrade targets specified."
  echo ""
  echo "To upgrade the Registrar (L1), set:"
  echo "  REGISTRAR_PROXY=<proxy-address>"
  echo "  REGISTRAR_PROXY_ADMIN=<proxy-admin-address>"
  echo ""
  echo "To upgrade the Commitment Registry (L2), set:"
  echo "  COMMITMENT_REGISTRY_PROXY=<proxy-address>"
  echo "  COMMITMENT_REGISTRY_PROXY_ADMIN=<proxy-admin-address>"
  exit 1
fi

cd contracts

if [[ "$upgrade_registrar" == "true" ]]; then
  echo "=== Upgrading EigenKMSRegistrar on L1 ==="
  echo "Proxy: $REGISTRAR_PROXY"
  echo "ProxyAdmin: $REGISTRAR_PROXY_ADMIN"
  echo ""

  forge script script/preprod/UpgradeEigenKMSRegistrar.s.sol --slow --rpc-url $ETH_RPC_URL --broadcast \
      --sig "run(address,address)" \
      "${REGISTRAR_PROXY}" \
      "${REGISTRAR_PROXY_ADMIN}"

  echo ""
  echo "EigenKMSRegistrar upgrade complete."
  echo ""
fi

if [[ "$upgrade_commitment_registry" == "true" ]]; then
  echo "=== Upgrading EigenKMSCommitmentRegistry on L2 ==="
  echo "Proxy: $COMMITMENT_REGISTRY_PROXY"
  echo "ProxyAdmin: $COMMITMENT_REGISTRY_PROXY_ADMIN"
  echo ""

  forge script script/preprod/UpgradeEigenKMSCommitmentRegistry.s.sol --slow --rpc-url $BASE_RPC_URL --broadcast \
      --sig "run(address,address)" \
      "${COMMITMENT_REGISTRY_PROXY}" \
      "${COMMITMENT_REGISTRY_PROXY_ADMIN}"

  echo ""
  echo "EigenKMSCommitmentRegistry upgrade complete."
  echo ""
fi
