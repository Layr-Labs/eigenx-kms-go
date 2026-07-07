package testutil

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/blockHandler"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/node"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering/localPeeringDataFetcher"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence/memory"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner/inMemoryTransportSigner"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// TestCluster represents a cluster of KMS nodes for testing
type TestCluster struct {
	Nodes        []*node.Node
	Servers      []*httptest.Server
	ServerURLs   []string
	NumNodes     int
	MasterPubKey types.G2Point
	MockPoller   *MockChainPoller // Exposed for test control

	// CommitmentRegistry simulates the on-chain commitment registry that the reshare
	// dealer-set-agreement path reads. By default every operator is reported as having
	// submitted for every epoch (healthy cluster). Tests can call SuppressSubmission to
	// model an operator that failed to submit (partition), exercising the agreement +
	// abort-retry behavior. See docs/011_reshareDealerSetAgreement.md.
	CommitmentRegistry *MockCommitmentRegistry
}

// MockCommitmentRegistry is a thread-safe in-memory stand-in for the on-chain
// EigenKMSCommitmentRegistry, used to drive the reshare dealer-set-agreement logic in
// tests. By default every operator reads as "submitted". A test can install a
// suppression predicate to model an operator that did NOT submit (e.g. partitioned) for
// ALL epochs — robust to test timing, unlike pre-seeding specific epoch timestamps.
type MockCommitmentRegistry struct {
	mu       sync.RWMutex
	suppress func(epoch int64, op common.Address) bool // returns true => treat as NOT submitted
	// submissions stores the REAL commitment hash each operator submitted per epoch, so
	// GetCommitmentAt serves authentic hashes. docs/013 Change 2 verifies each dealer's P2P
	// commitments+sourceVersion against this on-chain hash, so a sentinel would fail every
	// reshare. Keyed by epoch then operator.
	submissions map[int64]map[common.Address][32]byte
}

// NewMockCommitmentRegistry returns a registry where everything reads as submitted.
func NewMockCommitmentRegistry() *MockCommitmentRegistry {
	return &MockCommitmentRegistry{
		submissions: make(map[int64]map[common.Address][32]byte),
	}
}

// recordSubmission stores an operator's real commitment hash for an epoch (called from the
// per-node mock caller's SubmitCommitment).
func (r *MockCommitmentRegistry) recordSubmission(epoch int64, op common.Address, commitmentHash [32]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.submissions[epoch] == nil {
		r.submissions[epoch] = make(map[common.Address][32]byte)
	}
	r.submissions[epoch][op] = commitmentHash
}

// commitmentHashFor returns the real submitted hash for (epoch, op), or the zero hash if
// the operator has not submitted (or is suppressed).
func (r *MockCommitmentRegistry) commitmentHashFor(epoch int64, op common.Address) [32]byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.suppress != nil && r.suppress(epoch, op) {
		return [32]byte{}
	}
	if byOp, ok := r.submissions[epoch]; ok {
		if h, ok := byOp[op]; ok {
			return h
		}
	}
	return [32]byte{}
}

// SuppressOperator models an operator that never submits a commitment (partitioned) for
// every epoch, until cleared with Clear. Robust across test timing (no epoch window).
func (r *MockCommitmentRegistry) SuppressOperator(victim common.Address) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.suppress = func(_ int64, op common.Address) bool { return op == victim }
}

// SetSuppressPredicate installs a custom suppression predicate for fine-grained control.
func (r *MockCommitmentRegistry) SetSuppressPredicate(fn func(epoch int64, op common.Address) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.suppress = fn
}

// Clear removes any suppression — all operators read as submitted again (heal).
func (r *MockCommitmentRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.suppress = nil
}

// NewTestCluster creates a test cluster of KMS nodes with completed DKG
func NewTestCluster(t *testing.T, numNodes int) *TestCluster {
	if numNodes > 5 {
		t.Fatalf("Cannot create more than 5 nodes (limited by ChainConfig)")
	}

	// Get test data from ChainConfig
	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	if err != nil {
		t.Fatalf("Failed to read chain config: %v", err)
	}

	addresses := []string{
		chainConfig.OperatorAccountAddress1,
		chainConfig.OperatorAccountAddress2,
		chainConfig.OperatorAccountAddress3,
		chainConfig.OperatorAccountAddress4,
		chainConfig.OperatorAccountAddress5,
	}
	privateKeys := []string{
		chainConfig.OperatorAccountPrivateKey1,
		chainConfig.OperatorAccountPrivateKey2,
		chainConfig.OperatorAccountPrivateKey3,
		chainConfig.OperatorAccountPrivateKey4,
		chainConfig.OperatorAccountPrivateKey5,
	}

	// Create test cluster
	cluster := &TestCluster{
		Nodes:              make([]*node.Node, numNodes),
		Servers:            make([]*httptest.Server, numNodes),
		ServerURLs:         make([]string, numNodes),
		NumNodes:           numNodes,
		CommitmentRegistry: NewMockCommitmentRegistry(),
	}

	// Create nodes with real addresses and keys
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	// First, create test servers to get URLs before creating peering data
	cluster.Servers = make([]*httptest.Server, numNodes)
	cluster.ServerURLs = make([]string, numNodes)

	for i := 0; i < numNodes; i++ {
		// Create placeholder server to get URL
		cluster.Servers[i] = httptest.NewServer(nil)
		cluster.ServerURLs[i] = cluster.Servers[i].URL
	}

	// Now create peering data fetcher with actual server URLs
	peeringDataFetcher := createTestPeeringDataFetcherWithURLs(t, addresses, privateKeys, cluster.ServerURLs, numNodes)

	// Create one block handler per node
	nodeBlockHandlers := make([]blockHandler.IBlockHandler, numNodes)
	for i := 0; i < numNodes; i++ {
		nodeBlockHandlers[i] = blockHandler.NewBlockHandler(testLogger)
	}

	// Create mock poller that broadcasts to all node handlers
	// Use 10 blocks for Anvil (20 seconds with 2s block time, more realistic)
	cluster.MockPoller = NewMockChainPoller(nodeBlockHandlers, 10, testLogger)

	// Create nodes with proper configuration
	for i := 0; i < numNodes; i++ {
		portNumber, _ := strconv.Atoi(fmt.Sprintf("750%d", i))
		cfg := node.Config{
			OperatorAddress: addresses[i],
			Port:            portNumber,
			ChainID:         config.ChainId_EthereumAnvil, // Use anvil for tests (10 block interval)
			AVSAddress:      "0x1234567890123456789012345678901234567890",
			OperatorSetId:   1,
		}

		pkBytes, err := hexutil.Decode(privateKeys[i])
		if err != nil {
			t.Fatalf("Failed to decode BN254 private key: %v", err)
		}
		imts, err := inMemoryTransportSigner.NewBn254InMemoryTransportSigner(pkBytes, testLogger)
		if err != nil {
			t.Fatalf("Failed to create in-memory transport signer: %v", err)
		}

		// Use mock attestation verifier for tests
		mockManager := attestation.NewStubManager()

		// Create mock base contract caller backed by the cluster's shared commitment
		// registry simulation, so the reshare dealer-set-agreement path reads a
		// consistent (and test-controllable) set of submitters across all nodes.
		//
		// SubmitCommitment records this operator's REAL commitment hash into the shared
		// registry; GetCommitmentAt serves it back. This authenticity matters because
		// docs/013 Change 2 verifies each dealer's P2P (commitments, sourceVersion) against
		// its on-chain commitment hash — a sentinel value would fail every reshare.
		mockBaseContractCaller := &contractCaller.MockContractCallerStub{
			OperatorAddress: common.HexToAddress(addresses[i]),
			SubmitCommitmentFunc: func(epoch int64, operator common.Address, commitmentHash [32]byte, _ [32]byte) {
				cluster.CommitmentRegistry.recordSubmission(epoch, operator, commitmentHash)
			},
			GetCommitmentAtFunc: func(_ context.Context, _ common.Address, epoch int64, operator common.Address, blockNumber uint64) ([32]byte, [32]byte, uint64, error) {
				// Regression guard for the L1-block-as-L2-height bug: the registry is on
				// Base (L2) but the reshare trigger block is an Ethereum (L1) block, so the
				// finalize path MUST read at head (blockNumber == 0). If a non-zero block is
				// ever threaded in again, fail loudly here rather than silently returning
				// stale/empty results. See docs/011_reshareDealerSetAgreement.md.
				if blockNumber != 0 {
					t.Fatalf("GetCommitmentAt called with non-zero block %d; reshare must read the Base registry at head (the trigger block is an L1 height)", blockNumber)
				}
				// Serve the operator's REAL submitted hash (zero if not submitted/suppressed).
				h := cluster.CommitmentRegistry.commitmentHashFor(epoch, operator)
				if h == ([32]byte{}) {
					return [32]byte{}, [32]byte{}, 0, nil
				}
				return h, h, 1, nil
			},
		}

		mockRegistryAddress := common.HexToAddress("0x1111111111111111111111111111111111111111")

		// Create in-memory persistence for each test node
		persistence := memory.NewMemoryPersistence()

		n, err := node.NewNode(cfg, peeringDataFetcher, nodeBlockHandlers[i], cluster.MockPoller, imts, mockManager, mockBaseContractCaller, nil, mockRegistryAddress, persistence, testLogger)
		if err != nil {
			t.Fatalf("Failed to create node %d: %v", i+1, err)
		}
		cluster.Nodes[i] = n

		// Replace placeholder server with actual server
		server := node.NewServer(cluster.Nodes[i], 0)
		cluster.Servers[i].Config.Handler = server.GetHandler()

		// Start the node (starts scheduler and server)
		if err := cluster.Nodes[i].Start(); err != nil {
			t.Fatalf("Failed to start node %d: %v", i+1, err)
		}

		// Small stagger between node starts to prevent thundering herd
		// This simulates realistic deployment where nodes don't start simultaneously
		time.Sleep(50 * time.Millisecond)
	}

	// Give all nodes additional time to fully initialize
	time.Sleep(300 * time.Millisecond)

	// Emit initial block to initialize the scheduler (block 10)
	t.Logf("Emitting block 10 to initialize scheduler...")
	if err := cluster.MockPoller.EmitBlockAtNumber(10); err != nil {
		t.Fatalf("Failed to emit initial block: %v", err)
	}

	// Give nodes time to initialize
	time.Sleep(100 * time.Millisecond)

	// Now emit block 20 to trigger DKG (next interval boundary)
	t.Logf("Emitting block 20 to trigger DKG...")
	if err := cluster.MockPoller.EmitBlockAtNumber(20); err != nil {
		t.Fatalf("Failed to emit trigger block: %v", err)
	}

	// Wait for automatic DKG to complete
	// The protocol timeout for Anvil is 30s; use 60s here to give ample headroom
	// for slow CI runners (GitHub Actions) where HTTP round trips between nodes
	// and crypto operations can be sluggish.
	t.Logf("Waiting for automatic DKG to complete...")
	if !WaitForDKGCompletion(cluster, 60*time.Second) {
		t.Fatalf("DKG did not complete within timeout")
	}

	// Compute master public key from commitments
	cluster.MasterPubKey = ComputeMasterPublicKey(cluster)

	t.Logf("✓ Test cluster ready with DKG complete")
	t.Logf("  - Nodes: %d", numNodes)
	t.Logf("  - Block interval: 10 blocks")
	t.Logf("  - Current block: %d", cluster.MockPoller.GetCurrentBlock())
	t.Logf("  - Master Public Key: %s", hex.EncodeToString(cluster.MasterPubKey.CompressedBytes[:20])+"...")

	return cluster
}

// createTestPeeringDataFetcherWithURLs creates a peering data fetcher with actual test server URLs
func createTestPeeringDataFetcherWithURLs(t *testing.T, addresses, privateKeys, serverURLs []string, numNodes int) peering.IPeeringDataFetcher {
	peers := make([]*peering.OperatorSetPeer, numNodes)

	for i := 0; i < numNodes; i++ {
		privKey, err := bn254.NewPrivateKeyFromHexString(privateKeys[i])
		if err != nil {
			t.Fatalf("Failed to create BN254 private key: %v", err)
		}

		peers[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress(addresses[i]),
			SocketAddress:   serverURLs[i], // Use actual test server URL
			WrappedPublicKey: peering.WrappedPublicKey{
				PublicKey:    privKey.Public(),
				ECDSAAddress: common.HexToAddress(addresses[i]),
			},
			CurveType: config.CurveTypeBN254,
		}
	}

	operatorSet := &peering.OperatorSetPeers{
		OperatorSetId: 1,
		AVSAddress:    common.HexToAddress("0x1234567890123456789012345678901234567890"),
		Peers:         peers,
	}

	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	return localPeeringDataFetcher.NewLocalPeeringDataFetcher([]*peering.OperatorSetPeers{operatorSet}, testLogger)
}

// WaitForDKGCompletion polls nodes until all have completed DKG
func WaitForDKGCompletion(cluster *TestCluster, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	checkInterval := 500 * time.Millisecond
	lastLogTime := time.Now()

	for time.Now().Before(deadline) {
		allComplete := true
		completedCount := 0

		for _, n := range cluster.Nodes {
			if n.GetKeyStore().GetActiveVersion() != nil {
				completedCount++
			} else {
				allComplete = false
			}
		}

		// Log progress every 5 seconds
		if time.Since(lastLogTime) > 5*time.Second {
			cluster.Nodes[0].GetKeyStore() // Trigger any logging
			lastLogTime = time.Now()
		}

		if allComplete {
			return true
		}

		time.Sleep(checkInterval)
	}

	// Log which nodes failed to complete
	for i, n := range cluster.Nodes {
		if n.GetKeyStore().GetActiveVersion() == nil {
			fmt.Printf("Node %d (%s) did not complete DKG\n", i, n.GetOperatorAddress().Hex())
		}
	}

	return false
}

// WaitForReshare waits for nodes to complete a reshare (key version change)
// It automatically emits a block to trigger the reshare
func WaitForReshare(cluster *TestCluster, initialVersions map[int]int64, timeout time.Duration) bool {
	// Emit next block to trigger reshare (next interval boundary)
	if err := cluster.MockPoller.EmitBlock(); err != nil {
		return false
	}

	deadline := time.Now().Add(timeout)
	checkInterval := 500 * time.Millisecond

	for time.Now().Before(deadline) {
		reshareOccurred := false
		for i, n := range cluster.Nodes {
			activeVersion := n.GetKeyStore().GetActiveVersion()
			if activeVersion != nil && activeVersion.Version != initialVersions[i] {
				reshareOccurred = true
				break
			}
		}

		if reshareOccurred {
			return true
		}

		time.Sleep(checkInterval)
	}

	return false
}

// ComputeMasterPublicKey computes the master public key from all node commitments
func ComputeMasterPublicKey(cluster *TestCluster) types.G2Point {
	var allCommitments [][]types.G2Point

	for _, n := range cluster.Nodes {
		activeVersion := n.GetKeyStore().GetActiveVersion()
		if activeVersion != nil && len(activeVersion.Commitments) > 0 {
			allCommitments = append(allCommitments, activeVersion.Commitments)
		}
	}

	if len(allCommitments) == 0 {
		return types.G2Point{}
	}

	masterPubKey, err := crypto.ComputeMasterPublicKey(allCommitments)
	if err != nil {
		return types.G2Point{}
	}
	return *masterPubKey
}

// GetMasterPublicKey returns the master public key
func (c *TestCluster) GetMasterPublicKey() types.G2Point {
	return c.MasterPubKey
}

// GetServerURLs returns the list of server URLs
func (c *TestCluster) GetServerURLs() []string {
	return c.ServerURLs
}

// Close shuts down all nodes in the cluster
func (c *TestCluster) Close() {
	if c == nil {
		return
	}

	// Stop all nodes
	for i := range c.Nodes {
		if c.Nodes[i] != nil {
			_ = c.Nodes[i].Stop()
		}
	}

	// Stop httptest servers
	for _, server := range c.Servers {
		if server != nil {
			server.Close()
		}
	}

	// Give OS time to release ports (prevents "address already in use" in next test)
	time.Sleep(100 * time.Millisecond)
}
