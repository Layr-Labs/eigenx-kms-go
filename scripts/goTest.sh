#!/usr/bin/env bash

set -e  # Exit on any error
set -u  # Exit on undefined variables
set -o pipefail  # Exit if any command in a pipe fails

# spin up a new web3signer docker container for L1
web3signerL1Name="web3signer-l1"
web3signerL1Port=9100
web3signerL1HttpPort=9101
web3signerL1ChainId=1

web3signerL2Name="web3signer-l2"
web3signerL2Port=9200
web3signerL2HttpPort=9201
web3signerL2ChainId=31338

# Redis container settings (only used if no Redis is already reachable on
# localhost:6379, e.g. when running locally outside CI). In CI, the workflow
# starts Redis as a service container and exports REDIS_TEST_ADDRESS, so this
# script's probe will short-circuit before launching anything.
redisContainerName="eigenx-kms-go-test-redis-$$"
redisHost="localhost"
redisPort=6379
redisStartedByScript="false"

cleanup_containers() {
    echo "Cleaning up containers..."
    # Avoid noisy "No such container" messages during cleanup (e.g. if the
    # container never started or already exited due to --rm).
    docker rm -f "$web3signerL1Name" >/dev/null 2>&1 || true
    docker rm -f "$web3signerL2Name" >/dev/null 2>&1 || true
    if [ "$redisStartedByScript" = "true" ]; then
        docker rm -f "$redisContainerName" >/dev/null 2>&1 || true
    fi
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
        --detach \
         consensys/web3signer:develop \
            --key-store-path=/web3signer/keys \
            --http-listen-port=$port \
            eth1 \
            --chain-id $chainId \
            --keystores-path=/web3signer/keystores \
            --keystores-passwords-path=/web3signer/passwords
}

# isRedisReachable returns 0 if a Redis server responds to PING on the
# configured host:port, 1 otherwise. Uses a one-shot redis:7-alpine container
# so we don't require redis-cli on the host.
function isRedisReachable() {
    docker run --rm --network host redis:7-alpine \
        redis-cli -h "$redisHost" -p "$redisPort" ping 2>/dev/null \
        | grep -q "PONG"
}

function ensureRedisRunning() {
    if [ -n "${REDIS_TEST_ADDRESS:-}" ]; then
        echo "REDIS_TEST_ADDRESS is set to '${REDIS_TEST_ADDRESS}', skipping Redis container startup."
        return
    fi

    if isRedisReachable; then
        echo "Redis already reachable on ${redisHost}:${redisPort}, reusing it."
        export REDIS_TEST_ADDRESS="${redisHost}:${redisPort}"
        return
    fi

    echo "Starting Redis container '${redisContainerName}' on ${redisHost}:${redisPort}..."
    docker run \
        --rm \
        --name "$redisContainerName" \
        -p "${redisPort}:${redisPort}" \
        --detach \
        redis:7-alpine >/dev/null
    redisStartedByScript="true"

    # Poll for readiness up to ~30s.
    local i
    for i in $(seq 1 30); do
        if isRedisReachable; then
            echo "Redis container is ready."
            export REDIS_TEST_ADDRESS="${redisHost}:${redisPort}"
            return
        fi
        sleep 1
    done

    echo "Redis container failed to become ready within 30s." >&2
    exit 1
}

runWeb3SignerContainer $web3signerL1Name $web3signerL1Port $web3signerL1ChainId
runWeb3SignerContainer $web3signerL2Name $web3signerL2Port $web3signerL2ChainId

echo "Sleeping to let web3signer containers start..."
sleep 3

ensureRedisRunning


# run the tests
# GOFLAGS="-count=1" $(GO) test -v -p 1 -parallel 1 ./...
# Set a longer timeout for integration tests (default is 10m)
GOFLAGS="-count=1" go test -timeout 10m $@
