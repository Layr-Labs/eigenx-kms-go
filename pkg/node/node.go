package node

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/keystore"
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
	dkg                 *dkg.DKG
	resharer            *reshare.Reshare
	server              *Server
	attestationVerifier attestation.Verifier
	releaseRegistry     registry.Client
	rsaEncryption       *encryption.RSAEncryption

	// Operators
	Operators []types.OperatorInfo

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
	Operators  []types.OperatorInfo
}

// NewNode creates a new node instance with dependency injection
func NewNode(cfg Config) *Node {
	threshold := dkg.CalculateThreshold(len(cfg.Operators))

	n := &Node{
		ID:                  cfg.ID,
		Port:                cfg.Port,
		P2PPrivKey:          cfg.P2PPrivKey,
		P2PPubKey:           cfg.P2PPubKey,
		Threshold:           threshold,
		TotalNodes:          len(cfg.Operators),
		Operators:           cfg.Operators,
		keyStore:            keystore.NewKeyStore(),
		transport:           transport.NewClient(cfg.ID),
		attestationVerifier: attestation.NewStubVerifier(),
		releaseRegistry:     registry.NewStubClient(),
		rsaEncryption:       encryption.NewRSAEncryption(),
		receivedShares:      make(map[int]*fr.Element),
		receivedCommitments: make(map[int][]types.G2Point),
		receivedAcks:        make(map[int]map[int]*types.Acknowledgement),
		reshareComplete:     make(map[int]*types.CompletionSignature),
	}

	n.dkg = dkg.NewDKG(cfg.ID, threshold, cfg.Operators)
	n.resharer = reshare.NewReshare(cfg.ID, cfg.Operators)
	n.server = NewServer(n, cfg.Port)

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

// RunDKG executes the DKG protocol
func (n *Node) RunDKG() error {
	fmt.Printf("Node %d: Starting DKG Phase 1 (generate shares)\n", n.ID)

	// Phase 1: Generate shares and commitments
	shares, commitments, err := n.dkg.GenerateShares()
	if err != nil {
		return err
	}

	// Broadcast commitments
	_ = n.transport.BroadcastCommitments(n.Operators, commitments, "/dkg/commitment")

	// Send shares to each participant
	for _, op := range n.Operators {
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
	fmt.Printf("Node %d: Starting DKG Phase 2 (verify and ack)\n", n.ID)

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

			// Create and send acknowledgement
			ack := dkg.CreateAcknowledgement(n.ID, dealerID, commitments, n.signAcknowledgement)
			dealer := n.getOperatorByID(dealerID)
			if dealer != nil {
				_ = n.transport.SendAcknowledgement(ack, *dealer, "/dkg/ack")
			}

			fmt.Printf("Node %d: ✓ Verified and acked share from Node %d\n", n.ID, dealerID)
		} else {
			fmt.Printf("Node %d: ✗ Invalid share from Node %d\n", n.ID, dealerID)
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
	fmt.Printf("Node %d: Starting DKG Phase 3 (finalization)\n", n.ID)

	allCommitments := make([][]types.G2Point, 0, len(receivedCommitments))
	participantIDs := make([]int, 0, len(receivedCommitments))

	for _, op := range n.Operators {
		if comm, ok := receivedCommitments[op.ID]; ok {
			allCommitments = append(allCommitments, comm)
			participantIDs = append(participantIDs, op.ID)
		}
	}

	keyVersion := n.dkg.FinalizeKeyShare(n.receivedShares, allCommitments, participantIDs)
	n.keyStore.AddVersion(keyVersion)

	fmt.Printf("Node %d: ✓ DKG complete\n", n.ID)
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
			fmt.Printf("Node %d: Reshare failed: %v\n", n.ID, err)
			n.abandonReshare()
			return err
		}
		return nil
	case <-ctx.Done():
		fmt.Printf("Node %d: Reshare timeout, abandoning\n", n.ID)
		n.abandonReshare()
		return fmt.Errorf("reshare timeout")
	}
}

// RunReshare executes the reshare protocol
func (n *Node) RunReshare() error {
	// Update operator set from chain
	n.refreshOperatorSet()

	// Recalculate threshold
	newThreshold := dkg.CalculateThreshold(len(n.Operators))

	fmt.Printf("Node %d: Starting reshare (threshold: %d, operators: %d)\n",
		n.ID, newThreshold, len(n.Operators))

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
	_ = n.transport.BroadcastCommitments(n.Operators, commitments, "/reshare/commitment")

	// Send shares to all operators
	for _, op := range n.Operators {
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
	if err := n.waitForSharesWithRetry(len(n.Operators), 60*time.Second); err != nil {
		return err
	}
	if err := n.waitForCommitmentsWithRetry(len(n.Operators), 60*time.Second); err != nil {
		return err
	}

	// TODO: Complete reshare implementation
	fmt.Printf("Node %d: Reshare protocol initiated\n", n.ID)

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

func (n *Node) getOperatorByID(id int) *types.OperatorInfo {
	for _, op := range n.Operators {
		if op.ID == id {
			return &op
		}
	}
	return nil
}

func (n *Node) refreshOperatorSet() {
	// STUB: In production, query IKmsAvsRegistry.getNodeInfos() from chain
	fmt.Printf("Node %d: Refreshed operator set from chain (%d operators)\n",
		n.ID, len(n.Operators))
}

func (n *Node) abandonReshare() {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.keyStore.ClearPendingVersion()
	n.receivedShares = make(map[int]*fr.Element)
	n.receivedCommitments = make(map[int][]types.G2Point)
	n.receivedAcks = make(map[int]map[int]*types.Acknowledgement)
	n.reshareComplete = make(map[int]*types.CompletionSignature)

	fmt.Printf("Node %d: Reshare abandoned, keeping active version\n", n.ID)
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