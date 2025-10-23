package node

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	eigenxcrypto "github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/keystore"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/registry"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/reshare"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transport"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// addressToNodeID converts an Ethereum address to a node ID using keccak256 hash
// Equivalent to: uint64(uint256(keccak256(abi.encodePacked(address))))
func addressToNodeID(address common.Address) int {
	hash := crypto.Keccak256(address.Bytes())
	// Take first 8 bytes of hash as uint64, then convert to int
	nodeID := int(common.BytesToHash(hash).Big().Uint64())
	return nodeID
}

const (
	// ReshareFrequency is the frequency of resharing in seconds
	ReshareFrequency = 10 * 60 // 10 minutes
	// ReshareTimeout is the timeout for reshare operations
	ReshareTimeout = 2 * 60 // 2 minutes
)

// Node represents a KMS node
type Node struct {
	// Identity
	OperatorAddress common.Address // Ethereum address of this operator
	Port            int
	BN254PrivateKey *bn254.PrivateKey // BN254 private key for threshold crypto and P2P
	Threshold       int
	TotalNodes      int

	// Dependencies
	keyStore            *keystore.KeyStore
	transport           *transport.Client
	server              *Server
	attestationVerifier attestation.Verifier
	releaseRegistry     registry.Client
	rsaEncryption       *encryption.RSAEncryption
	peeringDataFetcher  peering.IPeeringDataFetcher
	logger              *zap.Logger

	// Dynamic components (created when needed)
	dkg      *dkg.DKG
	resharer *reshare.Reshare

	// State management
	receivedShares      map[int]*fr.Element
	receivedCommitments map[int][]types.G2Point
	receivedAcks        map[int]map[int]*types.Acknowledgement
	reshareComplete     map[int]*types.CompletionSignature

	mu sync.RWMutex
}

// Config holds node configuration
type Config struct {
	OperatorAddress string // Ethereum address of the operator (hex string)
	Port            int
	BN254PrivateKey string      // BN254 private key (hex string)
	Logger          *zap.Logger // Optional logger, will create default if nil
}

// NewNode creates a new node instance with dependency injection
func NewNode(cfg Config, pdf peering.IPeeringDataFetcher) *Node {
	// Create logger if not provided
	nodeLogger := cfg.Logger
	if nodeLogger == nil {
		nodeLogger, _ = logger.NewLogger(&logger.LoggerConfig{Debug: false})
	}

	// Parse operator address
	operatorAddress := common.HexToAddress(cfg.OperatorAddress)

	// Parse BN254 private key
	bn254PrivKey, err := bn254.NewPrivateKeyFromHexString(cfg.BN254PrivateKey)
	if err != nil {
		nodeLogger.Sugar().Fatalw("Invalid BN254 private key", "error", err)
	}

	// Use operator address hash as transport client ID (for consistency)
	transportClientID := addressToNodeID(operatorAddress)

	n := &Node{
		OperatorAddress:     operatorAddress,
		Port:                cfg.Port,
		BN254PrivateKey:     bn254PrivKey,
		keyStore:            keystore.NewKeyStore(),
		transport:           transport.NewClient(transportClientID),
		server:              NewServer(nil, cfg.Port), // Will set node reference later
		attestationVerifier: attestation.NewStubVerifier(),
		releaseRegistry:     registry.NewStubClient(),
		rsaEncryption:       encryption.NewRSAEncryption(),
		peeringDataFetcher:  pdf,
		logger:              nodeLogger,
		receivedShares:      make(map[int]*fr.Element),
		receivedCommitments: make(map[int][]types.G2Point),
		receivedAcks:        make(map[int]map[int]*types.Acknowledgement),
		reshareComplete:     make(map[int]*types.CompletionSignature),
	}

	// Set node reference in server
	n.server.node = n

	return n
}

// Start starts the node's HTTP server
func (n *Node) Start() error {
	return n.server.Start()
}

// Stop stops the node
func (n *Node) Stop() error {
	return n.server.Stop()
}

// fetchCurrentOperators fetches the current operator set from the peering system
func (n *Node) fetchCurrentOperators(ctx context.Context) ([]types.OperatorInfo, error) {
	// TODO: Use actual AVS address and operator set ID from chain
	// For now, using placeholder values
	avsAddress := "0x1234567890123456789012345678901234567890"
	operatorSetId := uint32(1)

	operatorSetPeers, err := n.peeringDataFetcher.ListKMSOperators(ctx, avsAddress, operatorSetId)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch operators from peering system: %w", err)
	}

	// Sort peers by address for consistent ordering
	sortedPeers := make([]*peering.OperatorSetPeer, len(operatorSetPeers.Peers))
	copy(sortedPeers, operatorSetPeers.Peers)
	sort.Slice(sortedPeers, func(i, j int) bool {
		return sortedPeers[i].OperatorAddress.Hex() < sortedPeers[j].OperatorAddress.Hex()
	})

	// Convert to OperatorInfo with address-based ID assignment
	operators := make([]types.OperatorInfo, len(sortedPeers))

	for i, peer := range sortedPeers {
		// Use keccak256 hash of address as node ID for better distribution
		nodeID := addressToNodeID(peer.OperatorAddress)
		operators[i] = types.OperatorInfo{
			ID:           nodeID,
			P2PPubKey:    []byte(peer.OperatorAddress.Hex()), // TODO: Use actual BN254 public key
			P2PNodeURL:   peer.SocketAddress,
			KMSServerURL: peer.SocketAddress,
		}
	}

	n.logger.Sugar().Infow("Fetched operators from chain", "operator_address", n.OperatorAddress.Hex(), "count", len(operators))
	return operators, nil
}

// RunDKG executes the DKG protocol
func (n *Node) RunDKG() error {
	ctx := context.Background()
	n.logger.Sugar().Infow("Starting DKG", "operator_address", n.OperatorAddress.Hex())

	// Fetch current operators from peering system
	operators, err := n.fetchCurrentOperators(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch operators: %w", err)
	}

	// Use keccak256 hash of operator address as node ID
	thisNodeID := addressToNodeID(n.OperatorAddress)

	// Verify this operator is in the fetched operator set
	operatorFound := false
	for _, op := range operators {
		if op.ID == thisNodeID {
			operatorFound = true
			break
		}
	}
	if !operatorFound {
		return fmt.Errorf("this operator %s (ID: %d) not found in operator set", n.OperatorAddress.Hex(), thisNodeID)
	}

	// Create DKG instance using address-derived ID
	threshold := dkg.CalculateThreshold(len(operators))
	n.dkg = dkg.NewDKG(thisNodeID, threshold, operators)
	n.Threshold = threshold
	n.TotalNodes = len(operators)

	n.logger.Sugar().Infow("Starting DKG Phase 1", "operator_address", n.OperatorAddress.Hex(), "node_id", thisNodeID, "threshold", threshold, "total_operators", len(operators))

	// Phase 1: Generate shares and commitments
	shares, commitments, err := n.dkg.GenerateShares()
	if err != nil {
		return err
	}

	// Broadcast commitments
	_ = n.transport.BroadcastCommitments(operators, commitments, "/dkg/commitment")

	// Send shares to each participant
	for _, op := range operators {
		if op.ID == thisNodeID {
			n.mu.Lock()
			n.receivedShares[thisNodeID] = shares[thisNodeID]
			n.receivedCommitments[thisNodeID] = commitments
			n.mu.Unlock()
			continue
		}
		_ = n.transport.SendShareWithRetry(op, shares[op.ID], "/dkg/share")
	}

	// Wait for all shares and commitments
	if err := n.waitForSharesWithRetry(n.TotalNodes, 30*time.Second); err != nil {
		return err
	}
	if err := n.waitForCommitmentsWithRetry(n.TotalNodes, 30*time.Second); err != nil {
		return err
	}

	// Phase 2: Verify and send acknowledgements
	n.logger.Sugar().Infow("Starting DKG Phase 2", "operator_address", n.OperatorAddress.Hex(), "node_id", thisNodeID, "phase", "verify_and_ack")

	n.mu.RLock()
	receivedShares := make(map[int]*fr.Element)
	for k, v := range n.receivedShares {
		receivedShares[k] = v
	}
	receivedCommitments := make(map[int][]types.G2Point)
	for k, v := range n.receivedCommitments {
		receivedCommitments[k] = v
	}
	n.mu.RUnlock()

	validShares := make(map[int]*fr.Element)
	for dealerID, share := range receivedShares {
		commitments := receivedCommitments[dealerID]
		if n.dkg.VerifyShare(dealerID, share, commitments) {
			validShares[dealerID] = share

			// TODO: Create and send acknowledgement (need operator info for transport)
			// ack := dkg.CreateAcknowledgement(thisNodeID, dealerID, commitments, n.signAcknowledgement)
			// TODO: Send acknowledgement using transport

			n.logger.Sugar().Infow("Verified and acked share", "operator_address", n.OperatorAddress.Hex(), "node_id", thisNodeID, "dealer_id", dealerID)
		} else {
			n.logger.Sugar().Warnw("Invalid share received", "operator_address", n.OperatorAddress.Hex(), "node_id", thisNodeID, "dealer_id", dealerID)
		}
	}

	n.mu.Lock()
	n.receivedShares = validShares
	n.mu.Unlock()

	// Wait for acknowledgements (as a dealer)
	if err := n.waitForAcknowledgements(n.Threshold, 30*time.Second); err != nil {
		return fmt.Errorf("insufficient acknowledgements: %v", err)
	}

	// Phase 3: Finalize
	n.logger.Sugar().Infow("Starting DKG Phase 3", "operator_address", n.OperatorAddress.Hex(), "node_id", thisNodeID, "phase", "finalization")

	allCommitments := make([][]types.G2Point, 0, len(receivedCommitments))
	participantIDs := make([]int, 0, len(receivedCommitments))

	for _, op := range operators {
		if comm, ok := receivedCommitments[op.ID]; ok {
			allCommitments = append(allCommitments, comm)
			participantIDs = append(participantIDs, op.ID)
		}
	}

	keyVersion := n.dkg.FinalizeKeyShare(n.receivedShares, allCommitments, participantIDs)
	n.keyStore.AddVersion(keyVersion)

	n.logger.Sugar().Infow("DKG complete", "operator_address", n.OperatorAddress.Hex(), "node_id", thisNodeID)
	return nil
}

// RunReshareWithTimeout runs reshare with a timeout
func (n *Node) RunReshareWithTimeout() error {
	ctx, cancel := context.WithTimeout(context.Background(), ReshareTimeout*time.Second)
	defer cancel()

	done := make(chan error, 1)

	go func() {
		done <- n.RunReshare()
	}()

	select {
	case err := <-done:
		if err != nil {
			n.logger.Sugar().Errorw("Reshare failed", "node_id", n.OperatorAddress.Hex(), "error", err)
			n.abandonReshare()
			return err
		}
		return nil
	case <-ctx.Done():
		n.logger.Sugar().Warnw("Reshare timeout, abandoning", "node_id", n.OperatorAddress.Hex())
		n.abandonReshare()
		return fmt.Errorf("reshare timeout")
	}
}

// RunReshare executes the reshare protocol
func (n *Node) RunReshare() error {
	ctx := context.Background()

	// Fetch current operators from peering system
	operators, err := n.fetchCurrentOperators(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch operators for reshare: %w", err)
	}

	// Use keccak256 hash of operator address as node ID (same as DKG)
	thisNodeID := addressToNodeID(n.OperatorAddress)

	// Verify this operator is in the fetched operator set
	operatorFound := false
	for _, op := range operators {
		if op.ID == thisNodeID {
			operatorFound = true
			break
		}
	}
	if !operatorFound {
		return fmt.Errorf("this operator %s (ID: %d) not found in reshare operator set", n.OperatorAddress.Hex(), thisNodeID)
	}

	// Calculate new threshold
	newThreshold := dkg.CalculateThreshold(len(operators))
	n.logger.Sugar().Infow("Starting reshare", "operator_address", n.OperatorAddress.Hex(), "node_id", thisNodeID, "threshold", newThreshold, "operators", len(operators))

	// Create reshare instance with current operators
	n.resharer = reshare.NewReshare(thisNodeID, operators)
	n.Threshold = newThreshold
	n.TotalNodes = len(operators)

	// Get current share
	currentShare, err := n.keyStore.GetActivePrivateShare()
	if err != nil {
		return err
	}

	// Phase 1: Generate new shares
	shares, commitments, err := n.resharer.GenerateNewShares(currentShare, newThreshold)
	if err != nil {
		return err
	}

	// Broadcast commitments
	_ = n.transport.BroadcastCommitments(operators, commitments, "/reshare/commitment")

	// Send shares to all operators
	for _, op := range operators {
		if op.ID == thisNodeID {
			n.mu.Lock()
			n.receivedShares[thisNodeID] = shares[op.ID]
			n.receivedCommitments[thisNodeID] = commitments
			n.mu.Unlock()
			continue
		}
		_ = n.transport.SendShareWithRetry(op, shares[op.ID], "/reshare/share")
	}

	// Wait for shares and commitments
	if err := n.waitForSharesWithRetry(len(operators), 60*time.Second); err != nil {
		return err
	}
	if err := n.waitForCommitmentsWithRetry(len(operators), 60*time.Second); err != nil {
		return err
	}

	// TODO: Complete reshare implementation
	n.logger.Sugar().Infow("Reshare protocol initiated", "operator_address", n.OperatorAddress.Hex(), "node_id", thisNodeID)

	return nil
}

// SignAppID signs an application ID
func (n *Node) SignAppID(appID string, attestationTime int64) types.G1Point {
	keyVersion := n.keyStore.GetKeyVersionAtTime(attestationTime, ReshareFrequency)
	if keyVersion == nil {
		keyVersion = n.keyStore.GetActiveVersion()
	}

	if keyVersion == nil || keyVersion.PrivateShare == nil {
		return types.G1Point{}
	}

	privateShare := new(fr.Element).Set(keyVersion.PrivateShare)
	qID := eigenxcrypto.HashToG1(appID)
	partialSig := eigenxcrypto.ScalarMulG1(qID, privateShare)
	return partialSig
}

func (n *Node) abandonReshare() {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.keyStore.ClearPendingVersion()
	n.receivedShares = make(map[int]*fr.Element)
	n.receivedCommitments = make(map[int][]types.G2Point)
	n.receivedAcks = make(map[int]map[int]*types.Acknowledgement)
	n.reshareComplete = make(map[int]*types.CompletionSignature)

	n.logger.Sugar().Warnw("Reshare abandoned, keeping active version", "node_id", n.OperatorAddress.Hex())
}

func (n *Node) signAcknowledgement(dealerID int, commitmentHash [32]byte) []byte {
	// STUB: In production, sign with ed25519 private key
	return []byte(fmt.Sprintf("ack_sig_%s_%d", n.OperatorAddress.Hex(), dealerID))
}

// Wait functions

func (n *Node) waitForSharesWithRetry(expectedCount int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	checkInterval := 200 * time.Millisecond

	for time.Now().Before(deadline) {
		n.mu.RLock()
		received := len(n.receivedShares)
		n.mu.RUnlock()

		if received >= expectedCount {
			return nil
		}

		time.Sleep(checkInterval)
	}

	n.mu.RLock()
	received := len(n.receivedShares)
	n.mu.RUnlock()

	return fmt.Errorf("timeout: got %d shares, expected %d", received, expectedCount)
}

func (n *Node) waitForCommitmentsWithRetry(expectedCount int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	checkInterval := 200 * time.Millisecond

	for time.Now().Before(deadline) {
		n.mu.RLock()
		received := len(n.receivedCommitments)
		n.mu.RUnlock()

		if received >= expectedCount {
			return nil
		}

		time.Sleep(checkInterval)
	}

	n.mu.RLock()
	received := len(n.receivedCommitments)
	n.mu.RUnlock()

	return fmt.Errorf("timeout: got %d commitments, expected %d", received, expectedCount)
}

func (n *Node) waitForAcknowledgements(threshold int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	checkInterval := 200 * time.Millisecond

	for time.Now().Before(deadline) {
		n.mu.RLock()
		// Note: receivedAcks is keyed by dealer ID (int), not operator address
		// This needs to be updated to work with the new system
		acks := n.receivedAcks[1] // TODO: Fix acknowledgement system
		count := 0
		if acks != nil {
			count = len(acks)
		}
		n.mu.RUnlock()

		if count >= threshold {
			return nil
		}

		time.Sleep(checkInterval)
	}

	n.mu.RLock()
	acks := n.receivedAcks[1] // TODO: Fix acknowledgement system
	count := 0
	if acks != nil {
		count = len(acks)
	}
	n.mu.RUnlock()

	return fmt.Errorf("timeout: got %d acks, expected %d", count, threshold)
}

// Helper methods for testing

// GetOperatorAddress returns the operator's address
func (n *Node) GetOperatorAddress() common.Address {
	return n.OperatorAddress
}

// GetReleaseRegistry returns the release registry client (for testing)
func (n *Node) GetReleaseRegistry() registry.Client {
	return n.releaseRegistry
}

// GetKeyStore returns the keystore (for testing)
func (n *Node) GetKeyStore() *keystore.KeyStore {
	return n.keyStore
}

// RunDKGPhase1 runs only phase 1 of DKG (for testing)
func (n *Node) RunDKGPhase1() (map[int]*fr.Element, []types.G2Point, error) {
	return n.dkg.GenerateShares()
}

// ReceiveShare receives a share from another node (for testing)
func (n *Node) ReceiveShare(fromID int, share *fr.Element, commitments []types.G2Point) error {
	n.mu.Lock()
	n.receivedShares[fromID] = share
	n.receivedCommitments[fromID] = commitments
	n.mu.Unlock()

	// Verify the share
	if n.dkg.VerifyShare(fromID, share, commitments) {
		n.logger.Sugar().Infow("Verified share", "node_id", n.OperatorAddress.Hex(), "from_id", fromID)
		return nil
	} else {
		return fmt.Errorf("node %s: invalid share from node %d", n.OperatorAddress.Hex(), fromID)
	}
}

// UpdateOperatorSet is no longer needed - operators are fetched dynamically from peering system

// FinalizeDKG finalizes the DKG process and creates active key version (for testing)
func (n *Node) FinalizeDKG(allCommitments [][]types.G2Point, participantIDs []int) error {
	n.mu.RLock()
	receivedShares := make(map[int]*fr.Element)
	for k, v := range n.receivedShares {
		receivedShares[k] = v
	}
	n.mu.RUnlock()

	keyVersion := n.dkg.FinalizeKeyShare(receivedShares, allCommitments, participantIDs)
	n.keyStore.AddVersion(keyVersion)

	n.logger.Sugar().Infow("DKG finalized", "node_id", n.OperatorAddress.Hex(), "version", keyVersion.Version)
	return nil
}
