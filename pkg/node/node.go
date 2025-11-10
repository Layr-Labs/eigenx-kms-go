package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"
	"time"

	chainPoller "github.com/Layr-Labs/chain-indexer/pkg/chainPollers"
	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/Layr-Labs/crypto-libs/pkg/ecdsa"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/blockHandler"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	eigenxcrypto "github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/keystore"
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
	// ReshareFrequency is the frequency of resharing in seconds (deprecated)
	// Deprecated: Use block-based intervals via config.GetReshareBlockIntervalForChain
	ReshareFrequency = 10 * 60 // 10 minutes
)

// Node represents a KMS node
type Node struct {
	// Identity
	OperatorAddress common.Address // Ethereum address of this operator
	Port            int
	BN254PrivateKey *bn254.PrivateKey // BN254 private key for threshold crypto and P2P
	ChainID         config.ChainId    // Ethereum chain ID
	AVSAddress      string            // AVS contract address
	OperatorSetId   uint32            // Operator set ID

	// Dependencies
	keyStore            *keystore.KeyStore
	transport           *transport.Client
	server              *Server
	attestationVerifier attestation.Verifier
	releaseRegistry     registry.Client
	rsaEncryption       *encryption.RSAEncryption
	peeringDataFetcher  peering.IPeeringDataFetcher
	logger              *zap.Logger
	transportSigner     transportSigner.ITransportSigner

	// Dynamic components (created when needed)
	dkg      *dkg.DKG
	resharer *reshare.Reshare

	// State management
	receivedShares      map[int]*fr.Element
	receivedCommitments map[int][]types.G2Point
	receivedAcks        map[int]map[int]*types.Acknowledgement
	reshareComplete     map[int]*types.CompletionSignature

	// Session management
	activeSessions    map[int64]*ProtocolSession
	sessionMutex      sync.RWMutex
	sessionNotify     map[int64]chan struct{} // Notifies when session is created
	sessionNotifyLock sync.Mutex

	// Scheduling
	enableAutoReshare     bool
	lastProcessedBoundary int64
	cancelFunc            context.CancelFunc

	blockHandler blockHandler.IBlockHandler
	poller       chainPoller.IChainPoller

	mu sync.RWMutex
}

// ProtocolSession tracks state for a DKG or reshare session
type ProtocolSession struct {
	SessionTimestamp int64
	Type             string // "dkg" or "reshare"
	Phase            int    // 1, 2, 3
	StartTime        time.Time
	Operators        []*peering.OperatorSetPeer

	// Session-specific state
	shares      map[int]*fr.Element
	commitments map[int][]types.G2Point
	acks        map[int]map[int]*types.Acknowledgement

	mu sync.RWMutex
}

// Config holds node configuration
type Config struct {
	OperatorAddress string // Ethereum address of the operator (hex string)
	Port            int
	BN254PrivateKey string         // BN254 private key (hex string)
	ChainID         config.ChainId // Ethereum chain ID
	AVSAddress      string         // AVS contract address (hex string)
	OperatorSetId   uint32         // Operator set ID
}

// NewNode creates a new node instance with dependency injection
func NewNode(
	cfg Config,
	pdf peering.IPeeringDataFetcher,
	bh blockHandler.IBlockHandler,
	cp chainPoller.IChainPoller,
	tps transportSigner.ITransportSigner,
	l *zap.Logger,
) *Node {
	// Parse operator address
	operatorAddress := common.HexToAddress(cfg.OperatorAddress)

	// Parse BN254 private key
	bn254PrivKey, err := bn254.NewPrivateKeyFromHexString(cfg.BN254PrivateKey)
	if err != nil {
		l.Sugar().Fatalw("Invalid BN254 private key", "error", err)
	}

	// Use operator address hash as transport client ID (for consistency)
	transportClientID := addressToNodeID(operatorAddress)

	n := &Node{
		OperatorAddress:       operatorAddress,
		Port:                  cfg.Port,
		BN254PrivateKey:       bn254PrivKey,
		ChainID:               cfg.ChainID,
		AVSAddress:            cfg.AVSAddress,
		OperatorSetId:         cfg.OperatorSetId,
		keyStore:              keystore.NewKeyStore(),
		server:                NewServer(nil, cfg.Port), // Will set node reference later
		attestationVerifier:   attestation.NewStubVerifier(),
		releaseRegistry:       registry.NewStubClient(),
		rsaEncryption:         encryption.NewRSAEncryption(),
		peeringDataFetcher:    pdf,
		logger:                l,
		receivedShares:        make(map[int]*fr.Element),
		receivedCommitments:   make(map[int][]types.G2Point),
		receivedAcks:          make(map[int]map[int]*types.Acknowledgement),
		reshareComplete:       make(map[int]*types.CompletionSignature),
		activeSessions:        make(map[int64]*ProtocolSession),
		sessionNotify:         make(map[int64]chan struct{}),
		enableAutoReshare:     true, // Always enabled
		blockHandler:          bh,
		poller:                cp,
		lastProcessedBoundary: 0,
		transportSigner:       tps,
	}

	// Set node reference in server
	n.server.node = n

	// Initialize transport with authenticated messaging
	// TODO(seanmcgary): this should be injected, not created here
	n.transport = transport.NewClient(transportClientID, operatorAddress, tps)

	return n
}

// startScheduler starts the automatic protocol scheduler with context
func (n *Node) startScheduler(ctx context.Context) {
	go n.blockHandler.ListenToChannel(ctx, n.checkScheduledOperations)
}

// checkScheduledOperations checks for block interval boundaries and executes appropriate protocol
func (n *Node) checkScheduledOperations(block *ethereum.EthereumBlock) {
	blockNumber := int64(block.Number.Value())

	// Step 1: Get block interval for this chain
	blockInterval := config.GetReshareBlockIntervalForChain(n.ChainID)

	// Step 2: Check if this block is an interval boundary
	if blockNumber%blockInterval != 0 {
		// Not an interval boundary, skip
		return
	}

	// Step 3: Initialize on first run (check BEFORE duplicate check to avoid block 0 issue)
	if n.lastProcessedBoundary == 0 {
		n.lastProcessedBoundary = blockNumber
		n.logger.Sugar().Infow("Initialized block boundary tracking",
			"operator_address", n.OperatorAddress.Hex(),
			"block_number", blockNumber)
		return // Don't trigger on first block
	}

	// Step 4: Check if we've already processed this block number
	if blockNumber == n.lastProcessedBoundary {
		return // Already handled this block
	}

	// Step 5: Update last processed boundary
	n.lastProcessedBoundary = blockNumber

	n.logger.Sugar().Infow("Block interval boundary reached",
		"operator_address", n.OperatorAddress.Hex(),
		"block_number", blockNumber,
		"block_interval", blockInterval)

	// Step 6: Fetch current operators
	ctx := context.Background()
	operators, err := n.fetchCurrentOperators(ctx, n.AVSAddress, n.OperatorSetId)
	if err != nil {
		n.logger.Sugar().Errorw("Failed to fetch operators for interval check",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
		return
	}

	// Step 7: Determine if I'm a new or existing operator
	if !n.hasExistingShares() {
		// I'm a new operator - need to determine cluster state
		clusterState := n.detectClusterState(operators)

		if clusterState == "genesis" {
			// No master key exists - run genesis DKG
			n.logger.Sugar().Infow("Triggering genesis DKG at block boundary",
				"operator_address", n.OperatorAddress.Hex(),
				"block_number", blockNumber)

			go func() {
				if err := n.RunDKG(blockNumber); err != nil {
					n.logger.Sugar().Errorw("Genesis DKG failed",
						"operator_address", n.OperatorAddress.Hex(),
						"error", err)
				}
			}()
		} else {
			// Existing cluster - join via reshare
			n.logger.Sugar().Infow("Joining existing cluster via reshare",
				"operator_address", n.OperatorAddress.Hex(),
				"block_number", blockNumber)

			go func() {
				if err := n.RunReshareAsNewOperator(blockNumber); err != nil {
					n.logger.Sugar().Errorw("Failed to join cluster via reshare",
						"operator_address", n.OperatorAddress.Hex(),
						"error", err)
				}
			}()
		}
	} else {
		// I'm an existing operator - run normal reshare
		n.logger.Sugar().Infow("Triggering automatic reshare",
			"operator_address", n.OperatorAddress.Hex(),
			"block_number", blockNumber,
			"block_interval", blockInterval)

		go func() {
			if err := n.RunReshareAsExistingOperator(blockNumber); err != nil {
				n.logger.Sugar().Errorw("Automatic reshare failed",
					"operator_address", n.OperatorAddress.Hex(),
					"error", err)
			}
		}()
	}
}

// Start starts the node's HTTP server and scheduler
func (n *Node) Start() error {
	// Create context for managing server and scheduler lifecycle
	ctx, cancel := context.WithCancel(context.Background())
	n.cancelFunc = cancel

	// start the poller
	if err := n.poller.Start(ctx); err != nil {
		return fmt.Errorf("failed to start chain poller: %w", err)
	}

	// Start scheduler in goroutine
	go n.startScheduler(ctx)

	// Start HTTP server in goroutine
	go func() {
		if err := n.server.Start(); err != nil {
			n.logger.Sugar().Errorw("HTTP server error", "operator_address", n.OperatorAddress.Hex(), "error", err)
		}
	}()

	n.logger.Sugar().Infow("Node started", "operator_address", n.OperatorAddress.Hex(), "port", n.Port)
	return nil
}

// Stop stops the node's HTTP server and scheduler
func (n *Node) Stop() error {
	// Cancel context to stop scheduler and any ongoing operations
	if n.cancelFunc != nil {
		n.cancelFunc()
	}

	// Stop HTTP server
	return n.server.Stop()
}

// fetchCurrentOperators fetches the current operator set from the peering system
func (n *Node) fetchCurrentOperators(ctx context.Context, avsAddress string, operatorSetId uint32) ([]*peering.OperatorSetPeer, error) {
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

	n.logger.Sugar().Infow("Fetched operators from chain", "operator_address", n.OperatorAddress.Hex(), "count", len(sortedPeers))
	return sortedPeers, nil
}

// hasExistingShares returns true if this node has active key shares
func (n *Node) hasExistingShares() bool {
	return n.keyStore.GetActiveVersion() != nil
}

// detectClusterState queries operators to determine if genesis DKG or existing cluster
func (n *Node) detectClusterState(operators []*peering.OperatorSetPeer) string {
	// Query /pubkey from all operators to see if anyone has commitments
	for _, op := range operators {
		commitments, err := n.transport.QueryOperatorPubkey(op)
		if err != nil {
			// Operator might be down - continue checking others
			n.logger.Sugar().Debugw("Failed to query operator pubkey",
				"operator_address", n.OperatorAddress.Hex(),
				"peer", op.OperatorAddress.Hex(),
				"error", err)
			continue
		}

		if len(commitments) > 0 {
			n.logger.Sugar().Infow("Detected existing cluster",
				"operator_address", n.OperatorAddress.Hex(),
				"peer_with_key", op.OperatorAddress.Hex())
			return "existing"
		}
	}

	n.logger.Sugar().Infow("No existing master key detected - genesis DKG needed",
		"operator_address", n.OperatorAddress.Hex())
	return "genesis"
}

// createSession creates a new protocol session with the provided timestamp
func (n *Node) createSession(sessionType string, operators []*peering.OperatorSetPeer, sessionTimestamp int64) *ProtocolSession {
	session := &ProtocolSession{
		SessionTimestamp: sessionTimestamp, // Use provided timestamp for coordination
		Type:             sessionType,
		Phase:            1,
		StartTime:        time.Now(),
		Operators:        operators,
		shares:           make(map[int]*fr.Element),
		commitments:      make(map[int][]types.G2Point),
		acks:             make(map[int]map[int]*types.Acknowledgement),
	}

	n.sessionMutex.Lock()
	n.activeSessions[sessionTimestamp] = session
	n.sessionMutex.Unlock()

	// Notify any waiters that this session is now available
	n.sessionNotifyLock.Lock()
	if ch, exists := n.sessionNotify[sessionTimestamp]; exists {
		close(ch) // Broadcast to all waiters
		delete(n.sessionNotify, sessionTimestamp)
	}
	n.sessionNotifyLock.Unlock()

	n.logger.Sugar().Infow("Created protocol session",
		"operator_address", n.OperatorAddress.Hex(),
		"session_timestamp", sessionTimestamp,
		"type", sessionType)

	return session
}

// getSession retrieves a session by timestamp
func (n *Node) getSession(sessionTimestamp int64) *ProtocolSession {
	n.sessionMutex.RLock()
	defer n.sessionMutex.RUnlock()
	return n.activeSessions[sessionTimestamp]
}

// waitForSession waits for a session to be created, with timeout
// This handles the race condition where a node receives protocol messages
// before it has created the session (e.g., slower node in block processing)
func (n *Node) waitForSession(sessionTimestamp int64, timeout time.Duration) *ProtocolSession {
	// Check if session already exists
	session := n.getSession(sessionTimestamp)
	if session != nil {
		return session
	}

	// Session doesn't exist yet, get or create notification channel
	n.sessionNotifyLock.Lock()
	notifyCh, exists := n.sessionNotify[sessionTimestamp]
	if !exists {
		notifyCh = make(chan struct{})
		n.sessionNotify[sessionTimestamp] = notifyCh
	}
	n.sessionNotifyLock.Unlock()

	// Wait for session to be created or timeout
	select {
	case <-notifyCh:
		// Session was created, retrieve it
		return n.getSession(sessionTimestamp)
	case <-time.After(timeout):
		// Timeout - clean up notify channel
		n.sessionNotifyLock.Lock()
		if ch, exists := n.sessionNotify[sessionTimestamp]; exists && ch == notifyCh {
			delete(n.sessionNotify, sessionTimestamp)
		}
		n.sessionNotifyLock.Unlock()
		return nil
	}
}

// cleanupSession removes a completed or failed session
func (n *Node) cleanupSession(sessionTimestamp int64) {
	n.sessionMutex.Lock()
	delete(n.activeSessions, sessionTimestamp)
	n.sessionMutex.Unlock()

	n.logger.Sugar().Debugw("Cleaned up session",
		"operator_address", n.OperatorAddress.Hex(),
		"session_timestamp", sessionTimestamp)
}

// cleanupOldSessions removes sessions older than the specified duration
// This will be called by the automatic scheduler in Milestone 3
func (n *Node) cleanupOldSessions(maxAge time.Duration) { //nolint:unused // Will be used by scheduler in Milestone 3
	n.sessionMutex.Lock()
	defer n.sessionMutex.Unlock()

	now := time.Now()
	for timestamp, session := range n.activeSessions {
		if now.Sub(session.StartTime) > maxAge {
			delete(n.activeSessions, timestamp)
			n.logger.Sugar().Warnw("Cleaned up expired session",
				"operator_address", n.OperatorAddress.Hex(),
				"session_timestamp", timestamp,
				"type", session.Type,
				"age", now.Sub(session.StartTime))
		}
	}
}

// RunDKG executes the DKG protocol with the provided session timestamp
func (n *Node) RunDKG(sessionTimestamp int64) error {
	ctx := context.Background()
	n.logger.Sugar().Infow("Starting DKG",
		"operator_address", n.OperatorAddress.Hex(),
		"session_timestamp", sessionTimestamp)

	// Fetch current operators from peering system
	operators, err := n.fetchCurrentOperators(ctx, n.AVSAddress, n.OperatorSetId)
	if err != nil {
		return fmt.Errorf("failed to fetch operators: %w", err)
	}

	// Create session for this DKG run with provided timestamp
	session := n.createSession("dkg", operators, sessionTimestamp)
	defer n.cleanupSession(session.SessionTimestamp)

	// Use keccak256 hash of operator address as node ID
	thisNodeID := addressToNodeID(n.OperatorAddress)

	// Verify this operator is in the fetched operator set
	operatorFound := false
	for _, op := range operators {
		if op.OperatorAddress == n.OperatorAddress {
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

	n.logger.Sugar().Infow("Starting DKG Phase 1", "operator_address", n.OperatorAddress.Hex(), "node_id", thisNodeID, "threshold", threshold, "total_operators", len(operators))

	// Phase 1: Generate shares and commitments
	shares, commitments, err := n.dkg.GenerateShares()
	if err != nil {
		return err
	}

	// Broadcast commitments
	if err := n.transport.BroadcastDKGCommitments(operators, commitments, session.SessionTimestamp); err != nil {
		n.logger.Sugar().Errorw("Failed to broadcast commitments", "operator_address", n.OperatorAddress.Hex(), "error", err)
		// Continue anyway - other nodes may have received
	}

	// Send shares to each participant
	for _, op := range operators {
		opNodeID := addressToNodeID(op.OperatorAddress)
		if opNodeID == thisNodeID {
			n.mu.Lock()
			n.receivedShares[thisNodeID] = shares[thisNodeID]
			n.receivedCommitments[thisNodeID] = commitments
			n.mu.Unlock()
			continue
		}
		if err := n.transport.SendDKGShare(op, shares[opNodeID], session.SessionTimestamp); err != nil {
			n.logger.Sugar().Warnw("Failed to send share to operator",
				"operator_address", n.OperatorAddress.Hex(),
				"target", op.OperatorAddress.Hex(),
				"error", err)
			// Continue with other operators
		}
	}

	// Wait for all shares and commitments (timeout must be less than block interval)
	protocolTimeout := config.GetProtocolTimeoutForChain(n.ChainID)
	if err := n.waitForSharesWithRetry(len(operators), protocolTimeout); err != nil {
		return err
	}
	if err := n.waitForCommitmentsWithRetry(len(operators), protocolTimeout); err != nil {
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

			// Create acknowledgement for verified share
			ack := dkg.CreateAcknowledgement(thisNodeID, dealerID, commitments, n.signAcknowledgement)

			// Find dealer's peer info for transport
			var dealerPeer *peering.OperatorSetPeer
			for _, op := range operators {
				if addressToNodeID(op.OperatorAddress) == dealerID {
					dealerPeer = op
					break
				}
			}

			if dealerPeer != nil {
				// Send acknowledgement to dealer
				err := n.transport.SendDKGAcknowledgement(ack, dealerPeer, session.SessionTimestamp)
				if err != nil {
					n.logger.Sugar().Warnw("Failed to send acknowledgement",
						"operator_address", n.OperatorAddress.Hex(),
						"dealer_address", dealerPeer.OperatorAddress.Hex(),
						"error", err)
				} else {
					n.logger.Sugar().Debugw("Sent acknowledgement",
						"operator_address", n.OperatorAddress.Hex(),
						"dealer_address", dealerPeer.OperatorAddress.Hex(),
						"dealer_id", dealerID)
				}
			}

			n.logger.Sugar().Infow("Verified and acked share", "operator_address", n.OperatorAddress.Hex(), "node_id", thisNodeID, "dealer_id", dealerID)
		} else {
			n.logger.Sugar().Warnw("Invalid share received", "operator_address", n.OperatorAddress.Hex(), "node_id", thisNodeID, "dealer_id", dealerID)
		}
	}

	n.mu.Lock()
	n.receivedShares = validShares
	n.mu.Unlock()

	// Wait for acknowledgements (as a dealer) - need ALL operators for DKG
	if err := n.waitForAcknowledgements(len(operators), protocolTimeout); err != nil {
		return fmt.Errorf("insufficient acknowledgements: %v", err)
	}

	// Phase 3: Finalize
	n.logger.Sugar().Infow("Starting DKG Phase 3", "operator_address", n.OperatorAddress.Hex(), "node_id", thisNodeID, "phase", "finalization")

	allCommitments := make([][]types.G2Point, 0, len(receivedCommitments))
	participantIDs := make([]int, 0, len(receivedCommitments))

	for _, op := range operators {
		opNodeID := addressToNodeID(op.OperatorAddress)
		if comm, ok := receivedCommitments[opNodeID]; ok {
			allCommitments = append(allCommitments, comm)
			participantIDs = append(participantIDs, opNodeID)
		}
	}

	keyVersion := n.dkg.FinalizeKeyShare(n.receivedShares, allCommitments, participantIDs)
	keyVersion.Version = session.SessionTimestamp // Use session timestamp as version
	n.keyStore.AddVersion(keyVersion)

	n.logger.Sugar().Infow("DKG complete",
		"operator_address", n.OperatorAddress.Hex(),
		"node_id", thisNodeID,
		"version", keyVersion.Version)
	return nil
}

// RunReshareAsExistingOperator executes the reshare protocol as an existing operator with shares
func (n *Node) RunReshareAsExistingOperator(sessionTimestamp int64) error {
	ctx := context.Background()
	n.logger.Sugar().Infow("Starting reshare as existing operator",
		"operator_address", n.OperatorAddress.Hex(),
		"session_timestamp", sessionTimestamp)

	// Fetch current operators from peering system
	operators, err := n.fetchCurrentOperators(ctx, n.AVSAddress, n.OperatorSetId)
	if err != nil {
		return fmt.Errorf("failed to fetch operators for reshare: %w", err)
	}

	// Use keccak256 hash of operator address as node ID (same as DKG)
	thisNodeID := addressToNodeID(n.OperatorAddress)

	// Verify this operator is in the fetched operator set
	operatorFound := false
	for _, op := range operators {
		if op.OperatorAddress == n.OperatorAddress {
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

	// Create session for this reshare run with provided timestamp
	session := n.createSession("reshare", operators, sessionTimestamp)
	defer n.cleanupSession(session.SessionTimestamp)

	// Broadcast commitments
	if err := n.transport.BroadcastReshareCommitments(operators, commitments, session.SessionTimestamp); err != nil {
		n.logger.Sugar().Errorw("Failed to broadcast reshare commitments", "operator_address", n.OperatorAddress.Hex(), "error", err)
		// Continue anyway - other nodes may have received
	}

	// Send shares to all operators
	for _, op := range operators {
		opNodeID := addressToNodeID(op.OperatorAddress)
		if opNodeID == thisNodeID {
			n.mu.Lock()
			n.receivedShares[thisNodeID] = shares[opNodeID]
			n.receivedCommitments[thisNodeID] = commitments
			n.mu.Unlock()
			continue
		}
		if err := n.transport.SendReshareShare(op, shares[opNodeID], session.SessionTimestamp); err != nil {
			n.logger.Sugar().Warnw("Failed to send reshare share to operator",
				"operator_address", n.OperatorAddress.Hex(),
				"target", op.OperatorAddress.Hex(),
				"error", err)
			// Continue with other operators
		}
	}

	// Wait for shares and commitments (timeout must be less than block interval)
	protocolTimeout := config.GetProtocolTimeoutForChain(n.ChainID)
	if err := n.waitForSharesWithRetry(len(operators), protocolTimeout); err != nil {
		return err
	}
	if err := n.waitForCommitmentsWithRetry(len(operators), protocolTimeout); err != nil {
		return err
	}

	// Phase 2: Finalize reshare
	n.logger.Sugar().Infow("Starting Reshare Finalization", "operator_address", n.OperatorAddress.Hex(), "node_id", thisNodeID)

	// Collect all commitments and participant IDs
	n.mu.RLock()
	allCommitments := make([][]types.G2Point, 0, len(n.receivedCommitments))
	participantIDs := make([]int, 0, len(n.receivedCommitments))

	for _, op := range operators {
		opNodeID := addressToNodeID(op.OperatorAddress)
		if comm, ok := n.receivedCommitments[opNodeID]; ok {
			allCommitments = append(allCommitments, comm)
			participantIDs = append(participantIDs, opNodeID)
		}
	}

	receivedShares := make(map[int]*fr.Element)
	for k, v := range n.receivedShares {
		receivedShares[k] = v
	}
	n.mu.RUnlock()

	// Compute new key share using Lagrange interpolation
	newKeyVersion := n.resharer.ComputeNewKeyShare(participantIDs, receivedShares, allCommitments)
	newKeyVersion.Version = sessionTimestamp // Use session timestamp as version
	newKeyVersion.IsActive = true            // Activate immediately (all operators must participate)

	// Add new version to keystore
	n.keyStore.AddVersion(newKeyVersion)

	n.logger.Sugar().Infow("Reshare completed", "operator_address", n.OperatorAddress.Hex(), "node_id", thisNodeID, "new_version", newKeyVersion.Version)

	return nil
}

// RunReshareAsNewOperator executes reshare protocol as a new operator (no existing shares)
func (n *Node) RunReshareAsNewOperator(sessionTimestamp int64) error {
	ctx := context.Background()
	n.logger.Sugar().Infow("Starting reshare as new operator (joining existing cluster)",
		"operator_address", n.OperatorAddress.Hex(),
		"session_timestamp", sessionTimestamp)

	// Fetch current operators from peering system
	operators, err := n.fetchCurrentOperators(ctx, n.AVSAddress, n.OperatorSetId)
	if err != nil {
		return fmt.Errorf("failed to fetch operators: %w", err)
	}

	thisNodeID := addressToNodeID(n.OperatorAddress)

	// Create reshare instance
	n.resharer = reshare.NewReshare(thisNodeID, operators)

	// Create session for this reshare (as recipient only)
	session := n.createSession("reshare", operators, sessionTimestamp)
	defer n.cleanupSession(session.SessionTimestamp)

	// New operators DON'T generate shares - only receive from existing operators
	n.logger.Sugar().Infow("Waiting for shares from existing operators",
		"operator_address", n.OperatorAddress.Hex(),
		"expected_operators", len(operators))

	// Wait for shares and commitments from existing operators
	protocolTimeout := config.GetProtocolTimeoutForChain(n.ChainID)
	if err := n.waitForSharesWithRetry(len(operators), protocolTimeout); err != nil {
		return fmt.Errorf("failed to receive shares: %w", err)
	}
	if err := n.waitForCommitmentsWithRetry(len(operators), protocolTimeout); err != nil {
		return fmt.Errorf("failed to receive commitments: %w", err)
	}

	// Collect all commitments and participant IDs
	n.mu.RLock()
	allCommitments := make([][]types.G2Point, 0, len(n.receivedCommitments))
	participantIDs := make([]int, 0, len(n.receivedCommitments))

	for _, op := range operators {
		opNodeID := addressToNodeID(op.OperatorAddress)
		if comm, ok := n.receivedCommitments[opNodeID]; ok {
			allCommitments = append(allCommitments, comm)
			participantIDs = append(participantIDs, opNodeID)
		}
	}

	receivedShares := make(map[int]*fr.Element)
	for k, v := range n.receivedShares {
		receivedShares[k] = v
	}
	n.mu.RUnlock()

	// Compute new key share using Lagrange interpolation
	newKeyVersion := n.resharer.ComputeNewKeyShare(participantIDs, receivedShares, allCommitments)
	newKeyVersion.Version = sessionTimestamp // Use session timestamp as version
	newKeyVersion.IsActive = true            // First key version becomes active immediately

	// Add new version to keystore
	n.keyStore.AddVersion(newKeyVersion)

	n.logger.Sugar().Infow("Successfully joined cluster via reshare",
		"operator_address", n.OperatorAddress.Hex(),
		"node_id", thisNodeID,
		"version", newKeyVersion.Version)

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
	qID, err := eigenxcrypto.HashToG1(appID)
	if err != nil {
		return types.G1Point{}
	}
	partialSig, err := eigenxcrypto.ScalarMulG1(*qID, privateShare)
	if err != nil {
		return types.G1Point{}
	}
	return *partialSig
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
	thisNodeID := addressToNodeID(n.OperatorAddress)

	for time.Now().Before(deadline) {
		n.mu.RLock()
		// receivedAcks is keyed by dealer ID, we are the dealer waiting for acks
		acks := n.receivedAcks[thisNodeID]
		count := 0
		if acks != nil {
			count = len(acks)
		}
		n.mu.RUnlock()

		if count >= threshold {
			n.logger.Sugar().Infow("Received sufficient acknowledgements",
				"operator_address", n.OperatorAddress.Hex(),
				"received", count,
				"threshold", threshold)
			return nil
		}

		time.Sleep(checkInterval)
	}

	n.mu.RLock()
	acks := n.receivedAcks[thisNodeID]
	count := 0
	if acks != nil {
		count = len(acks)
	}
	n.mu.RUnlock()

	return fmt.Errorf("timeout waiting for acknowledgements: got %d acks, expected %d", count, threshold)
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

// signMessage signs a message payload using the node's BN254 private key
func (n *Node) signMessage(payloadBytes []byte) ([]byte, error) {
	payloadHash := crypto.Keccak256(payloadBytes)
	var hash32 [32]byte
	copy(hash32[:], payloadHash)
	signature, err := n.BN254PrivateKey.SignSolidityCompatible(hash32)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}
	return signature.Bytes(), nil
}

// verifyMessage verifies an authenticated message using the sender's BN254 public key
func (n *Node) verifyMessage(authMsg *types.AuthenticatedMessage, senderPeer *peering.OperatorSetPeer) error {
	// Verify payload hash
	actualHash := crypto.Keccak256(authMsg.Payload)
	if !bytes.Equal(actualHash, authMsg.Hash[:]) {
		return fmt.Errorf("payload digest mismatch")
	}

	//nolint:staticcheck
	if senderPeer.CurveType == config.CurveTypeBN254 {
		// Verify signature using BN254 (must use VerifySolidityCompatible to match SignSolidityCompatible)
		sig, err := bn254.NewSignatureFromBytes(authMsg.Signature)
		if err != nil {
			return fmt.Errorf("invalid signature format: %w", err)
		}

		// Type assert to BN254 public key
		bn254PubKey, ok := senderPeer.WrappedPublicKey.PublicKey.(*bn254.PublicKey)
		if !ok {
			return fmt.Errorf("sender public key is not BN254 type")
		}

		isValid, err := sig.VerifySolidityCompatible(bn254PubKey, authMsg.Hash)
		if err != nil {
			return fmt.Errorf("signature verification error: %w", err)
		}
		if !isValid {
			return fmt.Errorf("signature verification failed")
		}
	} else if senderPeer.CurveType == config.CurveTypeECDSA {
		sig, err := ecdsa.NewSignatureFromBytes(authMsg.Signature)
		if err != nil {
			return fmt.Errorf("invalid ECDSA signature format: %w", err)
		}
		verified, err := sig.VerifyWithAddress(actualHash, senderPeer.WrappedPublicKey.ECDSAAddress)
		if err != nil {
			return fmt.Errorf("ECDSA signature verification error: %w", err)
		}
		if !verified {
			return fmt.Errorf("ECDSA signature verification failed")
		}

	} else {
		return fmt.Errorf("unsupported curve type for sender: %v", senderPeer.CurveType)
	}
	return nil
}

// findPeerByAddress finds a peer by their operator address
func (n *Node) findPeerByAddress(address common.Address, peers []*peering.OperatorSetPeer) *peering.OperatorSetPeer {
	for _, peer := range peers {
		if peer.OperatorAddress == address {
			return peer
		}
	}
	return nil
}

// signAcknowledgement signs an acknowledgement using BN254 private key
func (n *Node) signAcknowledgement(dealerID int, commitmentHash [32]byte) []byte {
	// Create message: dealerID || commitmentHash
	dealerBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(dealerBytes, uint32(dealerID))
	message := append(dealerBytes, commitmentHash[:]...)
	messageHash := crypto.Keccak256(message)

	var hash32 [32]byte
	copy(hash32[:], messageHash)
	signature, err := n.BN254PrivateKey.SignSolidityCompatible(hash32)
	if err != nil {
		n.logger.Sugar().Errorw("Failed to sign acknowledgement", "error", err)
		return nil
	}
	return signature.Bytes()
}
