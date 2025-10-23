package node

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
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

const (
	// ReshareFrequency is the frequency of resharing in seconds
	ReshareFrequency = 10 * 60 // 10 minutes
	// ReshareTimeout is the timeout for reshare operations
	ReshareTimeout = 2 * 60 // 2 minutes
)

// Node represents a KMS node
type Node struct {
	// Identity
	ID         int
	Port       int
	P2PPrivKey []byte // ed25519 private key
	P2PPubKey  []byte // ed25519 public key
	Threshold  int
	TotalNodes int

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
	ID         int
	Port       int
	P2PPrivKey []byte
	P2PPubKey  []byte
	Logger     *zap.Logger // Optional logger, will create default if nil
}

// NewNode creates a new node instance with dependency injection
func NewNode(cfg Config, pdf peering.IPeeringDataFetcher) *Node {
	// Create logger if not provided
	nodeLogger := cfg.Logger
	if nodeLogger == nil {
		nodeLogger, _ = logger.NewLogger(&logger.LoggerConfig{Debug: false})
	}

	n := &Node{
		ID:                  cfg.ID,
		Port:                cfg.Port,
		P2PPrivKey:          cfg.P2PPrivKey,
		P2PPubKey:           cfg.P2PPubKey,
		keyStore:            keystore.NewKeyStore(),
		transport:           transport.NewClient(cfg.ID),
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
	
	// Convert OperatorSetPeers to our OperatorInfo format
	operators := make([]types.OperatorInfo, len(operatorSetPeers.Peers))
	for i, peer := range operatorSetPeers.Peers {
		operators[i] = types.OperatorInfo{
			ID:           i + 1, // TODO: Use actual operator ID from on-chain data
			P2PPubKey:    []byte(peer.OperatorAddress.Hex()), // TODO: Use actual P2P public key
			P2PNodeURL:   peer.SocketAddress,
			KMSServerURL: peer.SocketAddress,
		}
	}
	
	n.logger.Sugar().Infow("Fetched operators from chain", "node_id", n.ID, "count", len(operators))
	return operators, nil
}

// RunDKG executes the DKG protocol
func (n *Node) RunDKG() error {
	return n.RunDKGWithOperators(context.Background(), nil)
}

// RunDKGWithOperators executes DKG with a specific operator set (for testing)
func (n *Node) RunDKGWithOperators(ctx context.Context, testOperators []types.OperatorInfo) error {
	n.logger.Sugar().Infow("Starting DKG Phase 1", "node_id", n.ID, "phase", "generate_shares")

	// Fetch current operators from peering system (unless test operators provided)
	var operators []types.OperatorInfo
	var err error
	
	if testOperators != nil {
		operators = testOperators
		n.logger.Sugar().Debugw("Using test operators for DKG", "node_id", n.ID, "count", len(operators))
	} else {
		operators, err = n.fetchCurrentOperators(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch operators: %w", err)
		}
	}

	// Create DKG instance with current operators
	threshold := dkg.CalculateThreshold(len(operators))
	n.dkg = dkg.NewDKG(n.ID, threshold, operators)
	n.Threshold = threshold
	n.TotalNodes = len(operators)

	// Phase 1: Generate shares and commitments
	shares, commitments, err := n.dkg.GenerateShares()
	if err != nil {
		return err
	}

	// Broadcast commitments
	_ = n.transport.BroadcastCommitments(operators, commitments, "/dkg/commitment")

	// Send shares to each participant
	for _, op := range operators {
		if op.ID == n.ID {
			n.mu.Lock()
			n.receivedShares[n.ID] = shares[n.ID]
			n.receivedCommitments[n.ID] = commitments
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
	n.logger.Sugar().Infow("Starting DKG Phase 2", "node_id", n.ID, "phase", "verify_and_ack")

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
			// ack := dkg.CreateAcknowledgement(n.ID, dealerID, commitments, n.signAcknowledgement)
			// TODO: Send acknowledgement using transport

			n.logger.Sugar().Infow("Verified and acked share", "node_id", n.ID, "dealer_id", dealerID)
		} else {
			n.logger.Sugar().Warnw("Invalid share received", "node_id", n.ID, "dealer_id", dealerID)
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
	n.logger.Sugar().Infow("Starting DKG Phase 3", "node_id", n.ID, "phase", "finalization")

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

	n.logger.Sugar().Infow("DKG complete", "node_id", n.ID)
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
			n.logger.Sugar().Errorw("Reshare failed", "node_id", n.ID, "error", err)
			n.abandonReshare()
			return err
		}
		return nil
	case <-ctx.Done():
		n.logger.Sugar().Warnw("Reshare timeout, abandoning", "node_id", n.ID)
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

	// Calculate new threshold
	newThreshold := dkg.CalculateThreshold(len(operators))
	n.logger.Sugar().Infow("Starting reshare", "node_id", n.ID, "threshold", newThreshold, "operators", len(operators))

	// Create reshare instance with current operators
	n.resharer = reshare.NewReshare(n.ID, operators)
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
		if op.ID == n.ID {
			n.mu.Lock()
			n.receivedShares[n.ID] = shares[op.ID]
			n.receivedCommitments[n.ID] = commitments
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
	n.logger.Sugar().Infow("Reshare protocol initiated", "node_id", n.ID)

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
	qID := crypto.HashToG1(appID)
	partialSig := crypto.ScalarMulG1(qID, privateShare)
	return partialSig
}

// Helper methods

// getOperatorByID is no longer needed - operators are fetched dynamically when needed

// refreshOperatorSet is no longer needed - operators fetched dynamically during operations

func (n *Node) abandonReshare() {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.keyStore.ClearPendingVersion()
	n.receivedShares = make(map[int]*fr.Element)
	n.receivedCommitments = make(map[int][]types.G2Point)
	n.receivedAcks = make(map[int]map[int]*types.Acknowledgement)
	n.reshareComplete = make(map[int]*types.CompletionSignature)

	n.logger.Sugar().Warnw("Reshare abandoned, keeping active version", "node_id", n.ID)
}

func (n *Node) signAcknowledgement(dealerID int, commitmentHash [32]byte) []byte {
	// STUB: In production, sign with ed25519 private key
	return []byte(fmt.Sprintf("ack_sig_%d_%d", n.ID, dealerID))
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
		acks := n.receivedAcks[n.ID]
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
	acks := n.receivedAcks[n.ID]
	count := 0
	if acks != nil {
		count = len(acks)
	}
	n.mu.RUnlock()

	return fmt.Errorf("timeout: got %d acks, expected %d", count, threshold)
}

// Helper methods for testing

// GetID returns the node's ID
func (n *Node) GetID() int {
	return n.ID
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
		n.logger.Sugar().Infow("Verified share", "node_id", n.ID, "from_id", fromID)
		return nil
	} else {
		return fmt.Errorf("node %d: invalid share from node %d", n.ID, fromID)
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

	n.logger.Sugar().Infow("DKG finalized", "node_id", n.ID, "version", keyVersion.Version)
	return nil
}
