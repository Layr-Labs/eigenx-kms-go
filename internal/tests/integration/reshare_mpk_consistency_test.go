package integration

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/testutil"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// Test_Reshare_ServedMPK_MatchesCommitments guards the production bug where the
// served MasterPublicKey drifted from the operators' actual key shares after
// reshares, making every app's secrets undecryptable ("all combinations
// exhausted"). It drives real nodes through reshares and asserts, each round,
// that the served MPK equals Σ(served commitments[0]) — the value clients
// reconstruct — and that a threshold recovery verifies against the served MPK.
//
// Without the reshare-finalize fix (which recomputes MPK from the dealers'
// commitments instead of blindly carrying it forward), the served MPK and the
// commitments diverge and this fails.
func Test_Reshare_ServedMPK_MatchesCommitments(t *testing.T) {
	cluster := testutil.NewTestCluster(t, 3)
	defer cluster.Close()

	appID := "reshare-mpk-consistency"
	qID, err := crypto.HashToG1(appID)
	require.NoError(t, err)

	assertConsistent := func(round int) {
		// served MPK + commitments per node (all from the active version /pubkey serves)
		var allCommitments [][]types.G2Point
		var servedMPK *types.G2Point
		partials := map[common.Address]types.G1Point{}
		for _, n := range cluster.Nodes {
			av := n.GetKeyStore().GetActiveVersion()
			require.NotNilf(t, av, "round %d: node has no active version", round)
			require.NotNilf(t, av.MasterPublicKey, "round %d: node has nil MasterPublicKey", round)
			allCommitments = append(allCommitments, av.Commitments)
			servedMPK = av.MasterPublicKey // all nodes serve the same MPK

			sig, err := crypto.ScalarMulG1(*qID, av.PrivateShare)
			require.NoError(t, err)
			partials[n.GetOperatorAddress()] = *sig
		}

		// 1) served MPK == Σ(commitments[0])  (what the client computes)
		computed, err := crypto.ComputeMasterPublicKey(allCommitments)
		require.NoError(t, err)
		require.Equalf(t, servedMPK.CompressedBytes, computed.CompressedBytes,
			"round %d: served MasterPublicKey != Σ(commitments[0]) — served MPK is stale", round)

		// 2) threshold recovery of partial sigs verifies against the served MPK
		key, err := crypto.RecoverAppPrivateKey(appID, partials, 2)
		require.NoErrorf(t, err, "round %d: recover", round)
		ok, err := crypto.VerifyAppPrivateKey(appID, *key, *servedMPK)
		require.NoError(t, err)
		require.Truef(t, ok, "round %d: recovered key does not verify against served MPK", round)
		t.Logf("round %d: served MPK consistent with commitments + shares ✓", round)
	}

	assertConsistent(0) // genesis

	for round := 1; round <= 2; round++ {
		versions := make(map[int]int64, len(cluster.Nodes))
		for i, n := range cluster.Nodes {
			versions[i] = n.GetKeyStore().GetActiveVersion().Version
		}
		require.Truef(t, testutil.WaitForReshare(cluster, versions, 45*time.Second),
			"reshare round %d did not occur", round)
		assertConsistent(round)
	}
}
