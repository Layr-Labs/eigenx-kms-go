#!/usr/bin/env bash

anvilL1Pid=""
anvilL2Pid=""

function cleanup() {
    kill $anvilL1Pid || true
    kill $anvilL2Pid || true

    exit $?
}
trap cleanup ERR
set -euo pipefail


# ethereum holesky
L1_FORK_RPC_URL=https://practical-serene-mound.ethereum-sepolia.quiknode.pro/3aaa48bd95f3d6aed60e89a1a466ed1e2a440b61/

anvilL1ChainId=31337
anvilL1StartBlock=9775400
anvilL1DumpStatePath=./anvil-l1.json
anvilL1ConfigPath=./anvil-l1-config.json
anvilL1RpcPort=8545
anvilL1RpcUrl="http://localhost:${anvilL1RpcPort}"

# base mainnet
L2_FORK_RPC_URL=https://soft-alpha-grass.base-sepolia.quiknode.pro/fd5e4bf346247d9b6e586008a9f13df72ce6f5b2/

anvilL2ChainId=8453
anvilL2StartBlock=34590518
anvilL2DumpStatePath=./anvil-l2.json
anvilL2ConfigPath=./anvil-l2-config.json
anvilL2RpcPort=9545
anvilL2RpcUrl="http://localhost:${anvilL2RpcPort}"


seedAccounts=$(cat ./anvilConfig/accounts.json)

# -----------------------------------------------------------------------------
# Start Ethereum L1
# -----------------------------------------------------------------------------
anvil \
    --fork-url $L1_FORK_RPC_URL \
    --dump-state $anvilL1DumpStatePath \
    --config-out $anvilL1ConfigPath \
    --chain-id $anvilL1ChainId \
    --port $anvilL1RpcPort \
    --block-time 2 \
    --fork-block-number $anvilL1StartBlock &

anvilL1Pid=$!
sleep 3

# -----------------------------------------------------------------------------
# Start Base L2
# -----------------------------------------------------------------------------
anvil \
    --fork-url $L2_FORK_RPC_URL \
    --dump-state $anvilL2DumpStatePath \
    --config-out $anvilL2ConfigPath \
    --chain-id $anvilL2ChainId \
    --port $anvilL2RpcPort \
    --fork-block-number $anvilL2StartBlock &
anvilL2Pid=$!
sleep 3

function fundAccount() {
    address=$1
    echo "Funding address $address on L1"
    cast rpc --rpc-url $anvilL1RpcUrl anvil_setBalance $address '0x21E19E0C9BAB2400000' # 10,000 ETH

    echo "Funding address $address on L2"
    cast rpc --rpc-url $anvilL2RpcUrl anvil_setBalance $address '0x21E19E0C9BAB2400000' # 10,000 ETH
}

# loop over the seed accounts (json array) and fund the accounts
numAccounts=$(echo $seedAccounts | jq '. | length - 1')
for i in $(seq 0 $numAccounts); do
    account=$(echo $seedAccounts | jq -r ".[$i]")
    address=$(echo $account | jq -r '.address')

    fundAccount $address
done

export GLOBAL_ROOT_CONFIRMER_ACCOUNT="0xDA29BB71669f46F2a779b4b62f03644A84eE3479"
export CROSS_CHAIN_REGISTRY_OWNER_ACCOUNT="0xb094Ba769b4976Dc37fC689A76675f31bc4923b0"

# fund the account used for table transport
fundAccount "0x8736311E6b706AfF3D8132Adf351387092802bA6"

# cross chain registry owner
fundAccount $CROSS_CHAIN_REGISTRY_OWNER_ACCOUNT


# avs deployer account
deployAccountAddress=$(echo $seedAccounts | jq -r '.[0].address')
deployAccountPk=$(echo $seedAccounts | jq -r '.[0].private_key')
export PRIVATE_KEY_DEPLOYER=$deployAccountPk
echo "Deploy account: $deployAccountAddress"
echo "Deploy account private key: $deployAccountPk"

# actual AVS account
avsAccountAddress=$(echo $seedAccounts | jq -r '.[1].address')
avsAccountPk=$(echo $seedAccounts | jq -r '.[1].private_key')
export PRIVATE_KEY_AVS=$avsAccountPk
echo "AVS account: $avsAccountAddress"
echo "AVS account private key: $avsAccountPk"

# operator accounts
operatorAccountAddress_1=$(echo $seedAccounts | jq -r '.[2].address')
operatorAccountPk_1=$(echo $seedAccounts | jq -r '.[2].private_key')
export PRIVATE_KEY_OPERATOR_1=$operatorAccountPk_1
echo "EC Operator account 1: $operatorAccountAddress_1"
echo "EC Operator account 1 private key: $operatorAccountPk_1"

operatorAccountAddress_2=$(echo $seedAccounts | jq -r '.[3].address')
operatorAccountPk_2=$(echo $seedAccounts | jq -r '.[3].private_key')
export PRIVATE_KEY_OPERATOR_2=$operatorAccountPk_2
echo "EC Operator account 2: $operatorAccountAddress_2"
echo "EC Operator account 2 private key: $operatorAccountPk_2"

operatorAccountAddress_3=$(echo $seedAccounts | jq -r '.[4].address')
operatorAccountPk_3=$(echo $seedAccounts | jq -r '.[4].private_key')
export PRIVATE_KEY_OPERATOR_3=$operatorAccountPk_3
echo "EC Operator account 3: $operatorAccountAddress_3"
echo "EC Operator account 3 private key: $operatorAccountPk_3"

operatorAccountAddress_4=$(echo $seedAccounts | jq -r '.[5].address')
operatorAccountPk_4=$(echo $seedAccounts | jq -r '.[5].private_key')
export PRIVATE_KEY_OPERATOR_4=$operatorAccountPk_4
echo "EC Operator account 4: $operatorAccountAddress_4"
echo "EC Operator account 4 private key: $operatorAccountPk_4"

operatorAccountAddress_5=$(echo $seedAccounts | jq -r '.[6].address')
operatorAccountPk_5=$(echo $seedAccounts | jq -r '.[6].private_key')
export PRIVATE_KEY_OPERATOR_5=$operatorAccountPk_5
echo "EC Operator account 5: $operatorAccountAddress_5"
echo "EC Operator account 5 private key: $operatorAccountPk_5"

cd contracts

export L1_RPC_URL="http://localhost:${anvilL1RpcPort}"

# -----------------------------------------------------------------------------
# Create operators
# -----------------------------------------------------------------------------
function registerOperator() {
    operatorPk=$1
    operatorAddress=$2
    echo "Registering operator $operatorAddress"

    export OPERATOR_PRIVATE_KEY=$operatorPk
    export AVS_ADDRESS=$avsAccountAddress
    export OPERATOR_ADDRESS=$operatorAddress

    forge script script/RegisterOperator.s.sol --slow --rpc-url $L1_RPC_URL --broadcast --sig "run()"

    echo "Acquiring testnet EIGEN"
    # impersonate the 0xDa account
    cast rpc anvil_impersonateAccount $GLOBAL_ROOT_CONFIRMER_ACCOUNT --rpc-url $L1_RPC_URL
    forge script script/AcquireEigen.s.sol --slow --rpc-url $L1_RPC_URL --sender $GLOBAL_ROOT_CONFIRMER_ACCOUNT --unlocked --broadcast --sig "run(address)" "${operatorAddress}"

    # echo "Staking eigen"
    # forge script script/StakeAndDelegate.s.sol --slow --rpc-url $L1_RPC_URL --broadcast --sig "run()" -vvvv
}
echo "-------------------------------------------------------------"
echo "Registering operators"
echo "-------------------------------------------------------------"
registerOperator $operatorAccountPk_1 $operatorAccountAddress_1
registerOperator $operatorAccountPk_2 $operatorAccountAddress_2
registerOperator $operatorAccountPk_3 $operatorAccountAddress_3
registerOperator $operatorAccountPk_4 $operatorAccountAddress_4
registerOperator $operatorAccountPk_5 $operatorAccountAddress_5

# -----------------------------------------------------------------------------
# Deploy L1 avs contract
# -----------------------------------------------------------------------------
echo "Deploying L1 AVS contract..."
forge script script/local/DeployEigenKMSRegistrar.s.sol --slow --rpc-url $L1_RPC_URL --broadcast --sig "run(address)" "${avsAccountAddress}"

# we need to get index 2 since thats where the actual proxy lives
eigenKMSRegistrarAddress=$(cat ./broadcast/DeployEigenKMSRegistrar.s.sol/$anvilL1ChainId/run-latest.json | jq -r '.transactions[2].contractAddress')
echo "Registrar contract address: $eigenKMSRegistrarAddress"

# ------------------------------------------------`-----------------------------
# Setup L1 AVS
# -----------------------------------------------------------------------------
echo "Setting up EigenKMS Registrar..."
forge script script/local/SetupEigenKMSRegistrar.s.sol --slow --rpc-url $L1_RPC_URL --broadcast --sig "run(address)" $eigenKMSRegistrarAddress

# -----------------------------------------------------------------------------
# Deploy L2 avs contract
# -----------------------------------------------------------------------------
echo "Deploying L1 AVS contract..."
avsAddress=$()
operatorSetId="0"
ecdsaCertificateVerifier="0xb3Cd1A457dEa9A9A6F6406c6419B1c326670A96F" # base sepolia
bn254CertificateVerifier="0xff58A373c18268F483C1F5cA03Cf885c0C43373a" # base sepolia
curveType="1"

forge script script/local/DeployEigenKMSCommitmentRegistry.s.sol --slow --rpc-url $L1_RPC_URL --broadcast \
    --sig "run(address,uint32,address,address,uint8)" \
    "${avsAccountAddress}" "${operatorSetId}" "${ecdsaCertificateVerifier}" "${bn254CertificateVerifier}" "${curveType}"


# -----------------------------------------------------------------------------
# Setup L1 multichain
# -----------------------------------------------------------------------------
# echo "Setting up L1 AVS..."
# TODO(seanmcgary): probably dont need multichain
# export L1_CHAIN_ID=$anvilL1ChainId
# cast rpc anvil_impersonateAccount $CROSS_CHAIN_REGISTRY_OWNER_ACCOUNT --rpc-url $L1_RPC_URL
# forge script script/local/WhitelistDevnet.s.sol --slow --rpc-url $L1_RPC_URL --sender $CROSS_CHAIN_REGISTRY_OWNER_ACCOUNT --unlocked --broadcast --sig "run()"
# forge script script/local/SetupAVSMultichain.s.sol --slow --rpc-url $L1_RPC_URL --broadcast --sig "run()"



# Move back up into the project root
cd ../

function registerOperatorToAvs() {
    operatorPk=$1
    operatorAddress=$2
    operatorIndex=$3
    echo "Registering operator $operatorAddress to AVS"

    socket="http://localhost:750${operatorIndex}"

    set -e

    go run cmd/registerOperator/main.go \
        --avs-address $avsAccountAddress \
        --operator-address $operatorAddress \
        --operator-private-key $operatorPk \
        --avs-private-key $avsAccountPk \
        --bn254-private-key $operatorPk \
        --socket $socket \
        --operator-set-id 0 \
        --rpc-url $L1_RPC_URL \
        --chain-id $anvilL1ChainId \
        --verbose
}
echo "-------------------------------------------------------------"
echo "Registering operators to AVS"
echo "-------------------------------------------------------------"

registerOperatorToAvs $operatorAccountPk_1 $operatorAccountAddress_1 1
registerOperatorToAvs $operatorAccountPk_2 $operatorAccountAddress_2 2
registerOperatorToAvs $operatorAccountPk_3 $operatorAccountAddress_3 3
registerOperatorToAvs $operatorAccountPk_4 $operatorAccountAddress_4 4
registerOperatorToAvs $operatorAccountPk_5 $operatorAccountAddress_5 5

echo "Ended at block number: "
cast block-number

kill $anvilL1Pid || true
sleep 3

rm -rf ./internal/testData/anvil*.json

cp -R $anvilL1DumpStatePath internal/testData/anvil-l1-state.json
cp -R $anvilL1ConfigPath internal/testData/anvil-l1-config.json

# make the files read-only since anvil likes to overwrite things
chmod 444 internal/testData/anvil*

rm $anvilL1DumpStatePath
rm $anvilL1ConfigPath

function lowercaseAddress() {
    echo "$1" | tr '[:upper:]' '[:lower:]'
}

avsAccountPublicKey=$(cast wallet public-key --private-key $avsAccountPk)

operatorAccountPublicKey_1=$(cast wallet public-key --private-key "$operatorAccountPk_1")
operatorAccountPublicKey_2=$(cast wallet public-key --private-key "$operatorAccountPk_2")
operatorAccountPublicKey_3=$(cast wallet public-key --private-key "$operatorAccountPk_3")
operatorAccountPublicKey_4=$(cast wallet public-key --private-key "$operatorAccountPk_4")
operatorAccountPublicKey_5=$(cast wallet public-key --private-key "$operatorAccountPk_5")

# create a heredoc json file and dump it to internal/testData/chain-config.json
cat <<EOF > internal/testData/chain-config.json
{
      "avsAccountAddress": "$avsAccountAddress",
      "avsAccountPk": "$avsAccountPk",
      "avsAccountPublicKey": "$avsAccountPublicKey",
      "operatorAccountAddress_1": "$operatorAccountAddress_1",
      "operatorAccountPk_1": "$operatorAccountPk_1",
      "operatorAccountPublicKey_1": "$operatorAccountPublicKey_1",
      "operatorAccountAddress_2": "$operatorAccountAddress_2",
      "operatorAccountPk_2": "$operatorAccountPk_2",
      "operatorAccountPublicKey_2": "$operatorAccountPublicKey_2",
      "operatorAccountAddress_3": "$operatorAccountAddress_3",
      "operatorAccountPk_3": "$operatorAccountPk_3",
      "operatorAccountPublicKey_3": "$operatorAccountPublicKey_3",
      "operatorAccountAddress_4": "$operatorAccountAddress_4",
      "operatorAccountPk_4": "$operatorAccountPk_4",
      "operatorAccountPublicKey_4": "$operatorAccountPublicKey_4",
      "operatorAccountAddress_5": "$operatorAccountAddress_5",
      "operatorAccountPk_5": "$operatorAccountPk_5",
      "operatorAccountPublicKey_5": "$operatorAccountPublicKey_5",
      "forkL1Block": "$anvilL1StartBlock"
}
EOF

