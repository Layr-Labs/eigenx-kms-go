package node

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func createMPKServer(t *testing.T, mpk *types.G2Point) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pubkey" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		resp := map[string]interface{}{
			"masterPublicKey": mpk,
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
}

func newTestNode(t *testing.T, addr string) *Node {
	t.Helper()
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)
	return &Node{
		OperatorAddress: common.HexToAddress(addr),
		logger:          logger,
	}
}

func TestFetchMPKFromPeers_AllHonest(t *testing.T) {
	honestMPK := crypto.G2Generator

	peers := make([]*peering.OperatorSetPeer, 4)
	for i := 0; i < 4; i++ {
		srv := createMPKServer(t, &honestMPK)
		defer srv.Close()
		peers[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress("0x" + string(rune('1'+i)) + "000000000000000000000000000000000000000"),
			SocketAddress:   srv.URL,
		}
	}

	node := newTestNode(t, "0x5000000000000000000000000000000000000000")
	mpk, err := node.fetchMPKFromPeers(context.Background(), peers)
	require.NoError(t, err)
	require.NotNil(t, mpk)
	assert.True(t, mpk.IsEqual(&honestMPK))
}

func TestFetchMPKFromPeers_OneCorrupted(t *testing.T) {
	honestMPK := crypto.G2Generator
	corruptedMPK := *types.ZeroG2Point()

	// 4 operators: 3 honest, 1 corrupted. Threshold = ceil(2*4/3) = 3.
	peers := make([]*peering.OperatorSetPeer, 4)
	for i := 0; i < 3; i++ {
		srv := createMPKServer(t, &honestMPK)
		defer srv.Close()
		peers[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress("0x" + string(rune('1'+i)) + "000000000000000000000000000000000000000"),
			SocketAddress:   srv.URL,
		}
	}
	corruptedSrv := createMPKServer(t, &corruptedMPK)
	defer corruptedSrv.Close()
	peers[3] = &peering.OperatorSetPeer{
		OperatorAddress: common.HexToAddress("0x4000000000000000000000000000000000000000"),
		SocketAddress:   corruptedSrv.URL,
	}

	node := newTestNode(t, "0x5000000000000000000000000000000000000000")
	mpk, err := node.fetchMPKFromPeers(context.Background(), peers)
	require.NoError(t, err)
	require.NotNil(t, mpk)
	assert.True(t, mpk.IsEqual(&honestMPK))
}

func TestFetchMPKFromPeers_TooManyCorrupted(t *testing.T) {
	honestMPK := crypto.G2Generator
	corruptedMPK := *types.ZeroG2Point()

	// 4 operators: 2 honest, 2 corrupted. Neither meets threshold of 3.
	peers := make([]*peering.OperatorSetPeer, 4)
	for i := 0; i < 2; i++ {
		srv := createMPKServer(t, &honestMPK)
		defer srv.Close()
		peers[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress("0x" + string(rune('1'+i)) + "000000000000000000000000000000000000000"),
			SocketAddress:   srv.URL,
		}
	}
	for i := 2; i < 4; i++ {
		srv := createMPKServer(t, &corruptedMPK)
		defer srv.Close()
		peers[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress("0x" + string(rune('1'+i)) + "000000000000000000000000000000000000000"),
			SocketAddress:   srv.URL,
		}
	}

	node := newTestNode(t, "0x5000000000000000000000000000000000000000")
	mpk, err := node.fetchMPKFromPeers(context.Background(), peers)
	require.Error(t, err)
	assert.Nil(t, mpk)
	assert.Contains(t, err.Error(), "failed to reach threshold agreement")
}

func TestFetchMPKFromPeers_ExcludesSelf(t *testing.T) {
	honestMPK := crypto.G2Generator
	selfAddr := "0x1000000000000000000000000000000000000000"

	// 4 peers + self = 5 total operators. Threshold = ceil(2*5/3) = 4.
	// Self excluded → 4 peers respond → meets threshold.
	peers := make([]*peering.OperatorSetPeer, 5)

	// Self - this server should never be called
	selfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("self node should not be contacted")
	}))
	defer selfSrv.Close()
	peers[0] = &peering.OperatorSetPeer{
		OperatorAddress: common.HexToAddress(selfAddr),
		SocketAddress:   selfSrv.URL,
	}

	for i := 1; i < 5; i++ {
		srv := createMPKServer(t, &honestMPK)
		defer srv.Close()
		peers[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress("0x" + string(rune('a'+i)) + "000000000000000000000000000000000000000"),
			SocketAddress:   srv.URL,
		}
	}

	node := newTestNode(t, selfAddr)
	mpk, err := node.fetchMPKFromPeers(context.Background(), peers)
	require.NoError(t, err)
	require.NotNil(t, mpk)
	assert.True(t, mpk.IsEqual(&honestMPK))
}

func TestFetchMPKFromPeers_ContextCancellation(t *testing.T) {
	// Create a server that will block until the test is done
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	peers := []*peering.OperatorSetPeer{
		{
			OperatorAddress: common.HexToAddress("0x1000000000000000000000000000000000000000"),
			SocketAddress:   srv.URL,
		},
	}

	node := newTestNode(t, "0x2000000000000000000000000000000000000000")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	mpk, err := node.fetchMPKFromPeers(ctx, peers)
	require.Error(t, err)
	assert.Nil(t, mpk)
}

func TestFetchMPKFromPeers_UnreachablePeer(t *testing.T) {
	honestMPK := crypto.G2Generator

	// 4 operators: 3 honest + 1 unreachable. Threshold = 3.
	peers := make([]*peering.OperatorSetPeer, 4)
	for i := 0; i < 3; i++ {
		srv := createMPKServer(t, &honestMPK)
		defer srv.Close()
		peers[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress("0x" + string(rune('1'+i)) + "000000000000000000000000000000000000000"),
			SocketAddress:   srv.URL,
		}
	}
	// Unreachable peer
	peers[3] = &peering.OperatorSetPeer{
		OperatorAddress: common.HexToAddress("0x4000000000000000000000000000000000000000"),
		SocketAddress:   "http://127.0.0.1:1", // nothing listening
	}

	node := newTestNode(t, "0x5000000000000000000000000000000000000000")
	mpk, err := node.fetchMPKFromPeers(context.Background(), peers)
	require.NoError(t, err)
	require.NotNil(t, mpk)
	assert.True(t, mpk.IsEqual(&honestMPK))
}
