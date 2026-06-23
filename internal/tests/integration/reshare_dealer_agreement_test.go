package integration

import (
	"testing"
	"time"

	eigenxcrypto "github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/testutil"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// assertClusterConsistent verifies the post-reshare correctness invariant that the
// dealer-set-agreement fix must preserve, and that the bug violated:
//
//  1. Every threshold-sized subset of the operators' current shares recovers the SAME
//     master secret (shares are mutually consistent — lie on one polynomial).
//  2. That recovered secret's public key (S·G2) equals the master public key the cluster
//     would serve (Σ commitments[0]) — i.e. served MPK matches the shares.
//
// If either fails, decryption would fail for every app ("all combinations exhausted").
func assertClusterConsistent(t *testing.T, cluster *testutil.TestCluster, label string) {
	t.Helper()

	n := len(cluster.Nodes)
	threshold := dkg.CalculateThreshold(n)

	// Collect each node's current private share + served MasterPublicKey.
	shares := make(map[common.Address]*fr.Element, n)
	addrs := make([]common.Address, 0, n)
	var servedMPK *types.G2Point
	for _, node := range cluster.Nodes {
		v := node.GetKeyStore().GetActiveVersion()
		require.NotNilf(t, v, "[%s] node %s has no active version", label, node.GetOperatorAddress().Hex())
		require.NotNilf(t, v.PrivateShare, "[%s] node %s has nil private share", label, node.GetOperatorAddress().Hex())
		require.NotNilf(t, v.MasterPublicKey, "[%s] node %s has nil served MasterPublicKey", label, node.GetOperatorAddress().Hex())
		addr := node.GetOperatorAddress()
		shares[addr] = v.PrivateShare
		addrs = append(addrs, addr)
		// All nodes must serve the SAME master public key (clients rely on threshold
		// agreement over this value).
		if servedMPK == nil {
			mpk := *v.MasterPublicKey
			servedMPK = &mpk
		} else {
			require.Truef(t, servedMPK.IsEqual(v.MasterPublicKey),
				"[%s] nodes disagree on served MasterPublicKey", label)
		}
	}

	// (1) All threshold-sized subsets must recover the SAME secret — shares are mutually
	// consistent (lie on one polynomial). This is the property the mixed-dealer-set bug
	// destroyed.
	var recoveredSecret *fr.Element
	subsets := chooseSubsets(addrs, threshold)
	require.NotEmpty(t, subsets, "[%s] expected at least one threshold subset", label)
	for _, sub := range subsets {
		rec := make(map[common.Address]*fr.Element, threshold)
		for _, a := range sub {
			rec[a] = shares[a]
		}
		got, err := eigenxcrypto.RecoverSecret(rec)
		require.NoErrorf(t, err, "[%s] recover failed for subset %v", label, sub)
		if recoveredSecret == nil {
			recoveredSecret = got
		} else {
			require.Truef(t, got.Equal(recoveredSecret),
				"[%s] INCONSISTENT SHARES: subset %v recovered a different key — cluster is poisoned", label, sub)
		}
	}

	// (2) The SERVED master public key (what /pubkey returns and clients encrypt to) must
	// equal S·G2 for the secret the shares recover. This is the exact decrypt invariant:
	// recovery yields S·H(appID), which verifies against served MPK = S·G2. If these
	// diverge, every decryption fails ("all combinations exhausted"). Note we check the
	// served MasterPublicKey field, NOT Σcommitments[0]: under a (uniform) subset dealer
	// set the per-node commitments are lambda-scaled, so Σcommitments[0] != S·G2 even
	// though the cluster is perfectly healthy — the served carried-forward MPK is the
	// authoritative value decryption actually uses.
	wantMPK, err := eigenxcrypto.ScalarMulG2(eigenxcrypto.G2Generator, recoveredSecret)
	require.NoErrorf(t, err, "[%s] failed to compute S·G2", label)
	require.Truef(t, servedMPK.IsEqual(wantMPK),
		"[%s] served MasterPublicKey does not match the shares' secret — decrypt would fail", label)
}

// chooseSubsets returns all k-sized subsets of addrs (n is tiny in tests).
func chooseSubsets(addrs []common.Address, k int) [][]common.Address {
	var out [][]common.Address
	var rec func(start int, cur []common.Address)
	rec = func(start int, cur []common.Address) {
		if len(cur) == k {
			cp := make([]common.Address, k)
			copy(cp, cur)
			out = append(out, cp)
			return
		}
		for i := start; i < len(addrs); i++ {
			rec(i+1, append(cur, addrs[i]))
		}
	}
	rec(0, nil)
	return out
}

func currentVersions(cluster *testutil.TestCluster) map[int]int64 {
	m := make(map[int]int64, len(cluster.Nodes))
	for i, n := range cluster.Nodes {
		if v := n.GetKeyStore().GetActiveVersion(); v != nil {
			m[i] = v.Version
		}
	}
	return m
}

// Test_ReshareDealerAgreement_HealthyRoundsStayConsistent runs several automatic
// reshares with no partition and asserts the cluster stays consistent each round —
// the baseline the fix must not regress.
func Test_ReshareDealerAgreement_HealthyRoundsStayConsistent(t *testing.T) {
	cluster := testutil.NewTestCluster(t, 3)
	defer cluster.Close()

	assertClusterConsistent(t, cluster, "post-DKG")

	for round := 0; round < 3; round++ {
		versions := currentVersions(cluster)
		require.Truef(t, testutil.WaitForReshare(cluster, versions, 45*time.Second),
			"reshare round %d did not occur", round)
		assertClusterConsistent(t, cluster, "healthy-round")
	}
}

// Test_ReshareDealerAgreement_PartitionedRoundDoesNotPoison is the core regression for
// the bug: it injects a partition (one operator's on-chain commitment is suppressed for
// a round, modeling the live "0/2 acks" blackout) and asserts the cluster does NOT get
// poisoned — i.e. shares remain mutually consistent and served MPK still matches.
//
// Before the dealer-set-agreement fix, a mixed-dealer-set round like this corrupted the
// master secret (no subset recovered a consistent key). With the fix, all nodes derive
// the same dealer set from the registry, so they either finalize on the same set or all
// abort-and-retry — never poison.
func Test_ReshareDealerAgreement_PartitionedRoundDoesNotPoison(t *testing.T) {
	cluster := testutil.NewTestCluster(t, 3)
	defer cluster.Close()

	assertClusterConsistent(t, cluster, "post-DKG")

	// Pick one operator to "partition" for the next reshare epoch: suppress its on-chain
	// commitment submission. The session epoch == the trigger block timestamp; suppress
	// across a window of upcoming epochs so the next round is affected regardless of the
	// exact boundary timestamp.
	victim := cluster.Nodes[2].GetOperatorAddress()
	base := time.Now().Unix()
	for ts := base - 5; ts <= base+120; ts++ {
		cluster.CommitmentRegistry.SuppressSubmission(ts, victim)
	}

	// Drive reshare rounds across the partition. Either every node finalizes on the same
	// (smaller) agreed set, or they abort and retry — in all cases the cluster must
	// remain consistent (never poisoned).
	for round := 0; round < 3; round++ {
		versions := currentVersions(cluster)
		// Reshare may or may not advance every node's version during the partition; we do
		// not require advancement, only that whatever state results stays consistent.
		_ = testutil.WaitForReshare(cluster, versions, 45*time.Second)
		assertClusterConsistent(t, cluster, "partitioned-round")
	}

	// Heal the partition: the suppressed operator can submit again. After healing,
	// reshares must continue to produce a consistent cluster.
	cluster.CommitmentRegistry = testutil.NewMockCommitmentRegistry()
	for round := 0; round < 2; round++ {
		versions := currentVersions(cluster)
		_ = testutil.WaitForReshare(cluster, versions, 45*time.Second)
		assertClusterConsistent(t, cluster, "post-heal")
	}
}
