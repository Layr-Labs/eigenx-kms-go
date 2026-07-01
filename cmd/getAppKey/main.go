// getAppKey recovers and prints the raw app_private_key (hex) for an appID from a
// healthy KMS — the same material agent-key-service uses as the signing root
// (result.AppPrivateKey). Threshold-recovers from partial sigs and verifies
// against the master public key before printing, so a poisoned KMS fails loudly
// instead of emitting a bad key. TEST/OPS tool — prints key material to stdout.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

func main() {
	rpc := flag.String("rpc-url", "", "L1 RPC URL")
	avs := flag.String("avs-address", "", "KMS AVS address")
	opSet := flag.Uint("operator-set-id", 0, "operator set id")
	appID := flag.String("app-id", "", "app id")
	threshold := flag.Int("threshold", 2, "recovery threshold")
	flag.Parse()
	if *rpc == "" || *avs == "" || *appID == "" {
		fmt.Fprintln(os.Stderr, "need --rpc-url --avs-address --app-id")
		os.Exit(2)
	}

	zl, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	eth := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{BaseUrl: *rpc, BlockType: ethereum.BlockType_Latest}, zl)
	l1, err := eth.GetEthereumContractCaller()
	if err != nil { fmt.Fprintln(os.Stderr, "eth:", err); os.Exit(1) }
	cc, err := caller.NewContractCaller(l1, nil, zl)
	if err != nil { fmt.Fprintln(os.Stderr, "cc:", err); os.Exit(1) }
	client, err := kmsClient.NewClient(&kmsClient.ClientConfig{AVSAddress: *avs, OperatorSetID: uint32(*opSet), Logger: zl, ContractCaller: cc})
	if err != nil { fmt.Fprintln(os.Stderr, "client:", err); os.Exit(1) }

	ops, err := client.GetOperators()
	if err != nil { fmt.Fprintln(os.Stderr, "operators:", err); os.Exit(1) }

	sigs, err := client.CollectPartialSignatures(*appID, ops, *threshold)
	if err != nil { fmt.Fprintln(os.Stderr, "partial sigs:", err); os.Exit(1) }

	// verify against MPK during recovery (fails loud if KMS poisoned)
	mpk, mpkErr := client.GetMasterPublicKey(ops)
	var key *types.G1Point
	if mpkErr == nil {
		k, err := crypto.RecoverAppPrivateKeyWithRetry(*appID, sigs, *threshold, func(cand *types.G1Point) bool {
			ok, verr := crypto.VerifyAppPrivateKey(*appID, *cand, *mpk)
			return verr == nil && ok
		})
		if err != nil { fmt.Fprintln(os.Stderr, "recover (KMS may be poisoned):", err); os.Exit(1) }
		key = k
	} else {
		fmt.Fprintln(os.Stderr, "WARN no MPK, unverified recover:", mpkErr)
		k, err := crypto.RecoverAppPrivateKey(*appID, sigs, *threshold)
		if err != nil { fmt.Fprintln(os.Stderr, "recover:", err); os.Exit(1) }
		key = k
	}
	// print the app_private_key compressed bytes as hex (this is signerd's root)
	fmt.Println(hex.EncodeToString(key.CompressedBytes))
}
