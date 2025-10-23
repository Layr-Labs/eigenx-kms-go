#!/usr/bin/env bash

OPERATOR_INDEX=$1
RUN_DKG_AT=$2

_usage="usage: $0 <operator_index>"

if [[ -z "$OPERATOR_INDEX" ]]; then
  echo $_usage
  exit 1
fi

if [[ -z "$RUN_DKG_AT" ]]; then
  RUN_DKG_AT=$(($(date +%s) + 15))
fi

chainConfig=$(cat ./internal/testData/chain-config.json)

privateKey=$(echo $chainConfig | jq -r ".operatorAccountPk_$OPERATOR_INDEX")
accountAddress=$(echo $chainConfig | jq -r ".operatorAccountAddress_$OPERATOR_INDEX")
avsAddress=$(echo $chainConfig | jq -r ".avsAccountAddress")
rpcUrl="http://localhost:8545"

serverPort="750${OPERATOR_INDEX}"

go run cmd/kmsServer/main.go \
    --chain-id 31337 \
    --port $serverPort \
    --operator-address $accountAddress \
    --bn254-private-key $privateKey \
    --avs-address $avsAddress \
    --rpc-url $rpcUrl \
    --dkg-at $RUN_DKG_AT \
    --verbose

