#!/usr/bin/env bash

set -e  # Exit on any error
set -u  # Exit on undefined variables
set -o pipefail  # Exit if any command in a pipe fails

# spin up a new web3signer docker container for L1
web3signerL1Name="web3signer-l1"
web3signerL1Port=9100
web3signerL1HttpPort=9101
web3signerL1ChainId=1

cleanup_containers() {
    echo "Cleaning up containers..."
    # Avoid noisy "No such container" messages during cleanup.
    docker rm -f "$web3signerL1Name" >/dev/null 2>&1 || true
}

trap cleanup_containers ERR EXIT SIGINT SIGTERM

function runWeb3SignerContainer() {
    local name=$1
    local port=$2
    local chainId=$3

    docker run \
        --rm \
        --name $name \
        -v ./internal/testData/web3signer:/web3signer \
        -i \
        -p "${port}:${port}" \
         consensys/web3signer:develop \
            --key-store-path=/web3signer/keys \
            --http-listen-port=$port \
            eth1 \
            --chain-id $chainId \
            --keystores-path=/web3signer/keystores \
            --keystores-passwords-path=/web3signer/passwords
}

runWeb3SignerContainer $web3signerL1Name $web3signerL1Port $web3signerL1ChainId

echo "Sleeping to let web3signer containers start..."
sleep 3
