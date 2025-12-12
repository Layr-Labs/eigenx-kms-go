#!/usr/bin/env bash

PRIVATE_KEY_DEPLOYER=${PRIVATE_KEY_DEPLOYER:-}
PRIVATE_KEY_AVS=${PRIVATE_KEY_AVS:-}
AVS_ACCOUNT_ADDRESS=${AVS_ACCOUNT_ADDRESS:-}
ETH_RPC_URL=${ETH_RPC_URL:-"http://localhost:8545"}
BASE_RPC_URL=${BASE_RPC_URL:-"http://localhost:9545"}

if [[ -z "$PRIVATE_KEY_DEPLOYER" ]]; then
  echo "Error: PRIVATE_KEY_DEPLOYER environment variable is not set."
  exit 1
fi

if [[ -z "$PRIVATE_KEY_AVS" ]]; then
  echo "Error: PRIVATE_KEY_AVS environment variable is not set."
  exit 1
fi

if [[ -z "$AVS_ACCOUNT_ADDRESS" ]]; then
  echo "Error: AVS_ACCOUNT_ADDRESS environment variable is not set."
  exit 1
fi

if [[ -z "$ETH_RPC_URL" ]]; then
  echo "Error: ETH_RPC_URL environment variable is not set."
  exit 1
fi

ethereumChainId=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' $ETH_RPC_URL | jq -r '.result' | xargs printf "%d\n")
baseChainId=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' $BASE_RPC_URL | jq -r '.result' | xargs printf "%d\n")


# if [[ -z "$BASE_RPC_URL" ]]; then
#   echo "Error: BASE_RPC_URL environment variable is not set."
#   exit 1
# fi

operator1Address="0x144c70563952f6f60E3ee94608d70352D7b8b99c"
operator2Address="0x0351aD97FA3045567D4EaA0004cfFB3DE4Fd95aE"
operator3Address="0x04f68cc4dAd8E916DFBF680200f2e281860E801D"

cd contracts

echo "Deploying L1 AVS contract..."
operatorSetId="0"
forge script script/preprod/DeployEigenKMSRegistrar.s.sol --slow --rpc-url $ETH_RPC_URL --broadcast \
    --sig "run(address,uint32,address,address,address)" \
    "${AVS_ACCOUNT_ADDRESS}" \
    "${operatorSetId}" \
    "${operator1Address}" \
    "${operator2Address}" \
    "${operator3Address}"

# we need to get index 2 since thats where the actual proxy lives
eigenKMSRegistrarAddress=$(cat ./broadcast/DeployEigenKMSRegistrar.s.sol/$ethereumChainId/run-latest.json | jq -r '.transactions[2].contractAddress')

echo "Setting up EigenKMS Registrar..."
forge script script/preprod/SetupEigenKMSRegistrar.s.sol --slow --rpc-url $ETH_RPC_URL --broadcast --sig "run(address)" $eigenKMSRegistrarAddress


echo "Deploying L2 AVS contract..."
operatorSetId="0"
ecdsaCertificateVerifier="0xb3Cd1A457dEa9A9A6F6406c6419B1c326670A96F" # base sepolia
bn254CertificateVerifier="0xff58A373c18268F483C1F5cA03Cf885c0C43373a" # base sepolia
curveType="1"

forge script script/preprod/DeployEigenKMSCommitmentRegistry.s.sol --slow --rpc-url $BASE_RPC_URL --broadcast \
    --sig "run(address,uint32,address,address,uint8)" \
    "${AVS_ACCOUNT_ADDRESS}" "${operatorSetId}" "${ecdsaCertificateVerifier}" "${bn254CertificateVerifier}" "${curveType}"

eigenKMSCommitmentRegistryAddress=$(cat ./broadcast/DeployEigenKMSCommitmentRegistry.s.sol/$baseChainId/run-latest.json | jq -r '.transactions[2].contractAddress')

# ----- final output -----
echo "Registrar contract address: $eigenKMSRegistrarAddress"
echo "Commitment registry contract address: $eigenKMSCommitmentRegistryAddress"
