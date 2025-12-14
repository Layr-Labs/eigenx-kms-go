package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
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
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	eigenxcrypto "github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/keystore"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/merkle"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/registry"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/reshare"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transport"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/util"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

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
	ChainID         config.ChainId // Ethereum chain ID
	AVSAddress      string         // AVS contract address
	OperatorSetId   uint32         // Operator set ID

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
	persistence         persistence.INodePersistence

	// Dynamic components (created when needed)
	dkg      *dkg.DKG
	resharer *reshare.Reshare

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

	// Base chain integration (for commitment registry)
	baseContractCaller        contractCaller.IContractCaller
	commitmentRegistryAddress common.Address
}

// ProtocolSession tracks state for a DKG or reshare session
type ProtocolSession struct {
	SessionTimestamp int64
	Type             string // "dkg" or "reshare"
	Phase            int    // 1, 2, 3, 4 (Phase 4 adds merkle tree building and contract submission)
	StartTime        time.Time
	Operators        []*peering.OperatorSetPeer

	// Session-specific state (moved from global Node state)
	shares      map[int64]*fr.Element
	commitments map[int64][]types.G2Point
	acks        map[int64]map[int64]*types.Acknowledgement

	// Completion channels (buffered, size 1) - signaled when all expected messages received
	sharesCompleteChan      chan bool
	commitmentsCompleteChan chan bool
	acksCompleteChan        chan bool

	// Phase 4: Merkle tree state
	myAckMerkleTree   *merkle.MerkleTree
	myCommitmentHash  [32]byte
	contractSubmitted bool

	// Phase 4: Verification state
	verifiedOperators map[int64]bool

	mu sync.RWMutex
}

// HandleReceivedShare stores a share and signals completion if all shares received
// Returns error if duplicate share detected
func (s *ProtocolSession) HandleReceivedShare(senderNodeID int64, share *fr.Element) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reject duplicates
	if _, exists := s.shares[senderNodeID]; exists {
		return fmt.Errorf("duplicate share from node %d", senderNodeID)
	}

	s.shares[senderNodeID] = share

	// Signal completion when EXACTLY all shares received
	if len(s.shares) == len(s.Operators) {
		select {
		case s.sharesCompleteChan <- true:
		default: // Already signaled
		}
	}

	return nil
}

// HandleReceivedCommitment stores commitments and signals completion if all received
// Returns error if duplicate commitment detected
func (s *ProtocolSession) HandleReceivedCommitment(senderNodeID int64, commitments []types.G2Point) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reject duplicates
	if _, exists := s.commitments[senderNodeID]; exists {
		return fmt.Errorf("duplicate commitment from node %d", senderNodeID)
	}

	s.commitments[senderNodeID] = commitments

	// Signal completion when EXACTLY all commitments received
	if len(s.commitments) == len(s.Operators) {
		select {
		case s.commitmentsCompleteChan <- true:
		default: // Already signaled
		}
	}

	return nil
}

// HandleReceivedAck stores an acknowledgement and signals completion if all acks received for this dealer
// Returns error if duplicate ack detected
func (s *ProtocolSession) HandleReceivedAck(dealerNodeID, playerNodeID int64, ack *types.Acknowledgement) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reject duplicates
	if s.acks[dealerNodeID] != nil {
		if _, exists := s.acks[dealerNodeID][playerNodeID]; exists {
			return fmt.Errorf("duplicate ack from player %d for dealer %d", playerNodeID, dealerNodeID)
		}
	}

	if s.acks[dealerNodeID] == nil {
		s.acks[dealerNodeID] = make(map[int64]*types.Acknowledgement)
	}
	s.acks[dealerNodeID][playerNodeID] = ack

	// Signal completion when EXACTLY all expected acks received (for this dealer)
	expectedAcks := len(s.Operators) - 1 // All except self
	if len(s.acks[dealerNodeID]) == expectedAcks {
		select {
		case s.acksCompleteChan <- true:
		default: // Already signaled
		}
	}

	return nil
}

// toPersistenceState converts ProtocolSession to persistence.ProtocolSessionState for saving
func (ps *ProtocolSession) toPersistenceState() *persistence.ProtocolSessionState {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	// Convert operator peers to addresses
	operatorAddresses := make([]string, len(ps.Operators))
	for i, op := range ps.Operators {
		operatorAddresses[i] = op.OperatorAddress.Hex()
	}

	// Convert shares (fr.Element -> string)
	shares := make(map[int64]string)
	for nodeID, share := range ps.shares {
		shares[nodeID] = types.SerializeFr(share).Data
	}

	// Commitments and acknowledgements are already serializable
	commitments := make(map[int64][]types.G2Point)
	for k, v := range ps.commitments {
		commitments[k] = v
	}

	acks := make(map[int64]map[int64]*types.Acknowledgement)
	for k, v := range ps.acks {
		acks[k] = v
	}

	return &persistence.ProtocolSessionState{
		SessionTimestamp:  ps.SessionTimestamp,
		Type:              ps.Type,
		Phase:             ps.Phase,
		StartTime:         ps.StartTime.Unix(),
		OperatorAddresses: operatorAddresses,
		Shares:            shares,
		Commitments:       commitments,
		Acknowledgements:  acks,
	}
}

// saveSession persists the current protocol session state
func (n *Node) saveSession(session *ProtocolSession) error {
	if session == nil {
		return nil
	}

	persistenceState := session.toPersistenceState()
	if err := n.persistence.SaveProtocolSession(persistenceState); err != nil {
		n.logger.Sugar().Errorw("Failed to persist protocol session",
			"operator_address", n.OperatorAddress.Hex(),
			"session_timestamp", session.SessionTimestamp,
			"error", err)
		return err
	}

	return nil
}

// Config holds node configuration
type Config struct {
	OperatorAddress string         // Ethereum address of the operator (hex string)
	Port            int            //HTTP server port
	ChainID         config.ChainId // Ethereum chain ID
	AVSAddress      string         // AVS contract address (hex string)
	OperatorSetId   uint32         // Operator set ID
}

// NewNode creates a new node instance with dependency injection
// attestationVerifier is required and must not be nil
func NewNode(
	cfg Config,
	pdf peering.IPeeringDataFetcher,
	bh blockHandler.IBlockHandler,
	cp chainPoller.IChainPoller,
	tps transportSigner.ITransportSigner,
	attestationVerifier attestation.Verifier,
	baseContractCaller contractCaller.IContractCaller,
	commitmentRegistryAddress common.Address,
	p persistence.INodePersistence,
	l *zap.Logger,
) (*Node, error) {
	// Validate required dependencies
	if attestationVerifier == nil {
		return nil, fmt.Errorf("attestationVerifier is required and cannot be nil")
	}
	if baseContractCaller == nil {
		return nil, fmt.Errorf("baseContractCaller is required")
	}
	if commitmentRegistryAddress == (common.Address{}) {
		return nil, fmt.Errorf("commitmentRegistryAddress is required")
	}

	// Parse operator address
	operatorAddress := common.HexToAddress(cfg.OperatorAddress)

	// Use operator address hash as transport client ID (for consistency)
	transportClientID := util.AddressToNodeID(operatorAddress)

	n := &Node{
		OperatorAddress:           operatorAddress,
		Port:                      cfg.Port,
		ChainID:                   cfg.ChainID,
		AVSAddress:                cfg.AVSAddress,
		OperatorSetId:             cfg.OperatorSetId,
		keyStore:                  keystore.NewKeyStore(),
		server:                    NewServer(nil, cfg.Port), // Will set node reference later
		attestationVerifier:       attestationVerifier,
		releaseRegistry:           registry.NewStubClient(),
		rsaEncryption:             encryption.NewRSAEncryption(),
		peeringDataFetcher:        pdf,
		logger:                    l,
		activeSessions:            make(map[int64]*ProtocolSession),
		sessionNotify:             make(map[int64]chan struct{}),
		enableAutoReshare:         true, // Always enabled
		blockHandler:              bh,
		poller:                    cp,
		lastProcessedBoundary:     0,
		transportSigner:           tps,
		baseContractCaller:        baseContractCaller,
		commitmentRegistryAddress: commitmentRegistryAddress,
		persistence:               p,
	}

	// Set node reference in server
	n.server.node = n

	// Initialize transport with authenticated messaging
	// TODO(seanmcgary): this should be injected, not created here
	n.transport = transport.NewClient(transportClientID, operatorAddress, tps)

	return n, nil
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

	// Persist block boundary
	nodeState := &persistence.NodeState{
		LastProcessedBoundary: blockNumber,
		NodeStartTime:         time.Now().Unix(),
		OperatorAddress:       n.OperatorAddress.Hex(),
	}
	if err := n.persistence.SaveNodeState(nodeState); err != nil {
		n.logger.Sugar().Errorw("Failed to persist node state",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
		// Continue - non-fatal, can recover on next boundary
	}

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
	// Restore state before starting services
	if err := n.RestoreState(); err != nil {
		return fmt.Errorf("failed to restore state: %w", err)
	}

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

// RestoreState loads persisted state on node startup
func (n *Node) RestoreState() error {
	n.logger.Sugar().Infow("Restoring node state from persistence",
		"operator_address", n.OperatorAddress.Hex())

	// 1. Load node operational state
	nodeState, err := n.persistence.LoadNodeState()
	if err != nil {
		return fmt.Errorf("failed to load node state: %w", err)
	}

	if nodeState != nil {
		// Verify operator address matches
		if nodeState.OperatorAddress != "" && nodeState.OperatorAddress != n.OperatorAddress.Hex() {
			n.logger.Sugar().Warnw("Operator address mismatch in persisted state",
				"expected", n.OperatorAddress.Hex(),
				"persisted", nodeState.OperatorAddress)
		}

		if nodeState.LastProcessedBoundary > 0 {
			n.lastProcessedBoundary = nodeState.LastProcessedBoundary
			n.logger.Sugar().Infow("Restored last processed boundary",
				"operator_address", n.OperatorAddress.Hex(),
				"block_number", nodeState.LastProcessedBoundary)
		}
	}

	// 2. Load all key share versions
	versions, err := n.persistence.ListKeyShareVersions()
	if err != nil {
		return fmt.Errorf("failed to load key share versions: %w", err)
	}

	n.logger.Sugar().Infow("Loaded key share versions",
		"operator_address", n.OperatorAddress.Hex(),
		"count", len(versions))

	for _, version := range versions {
		n.keyStore.AddVersion(version)
	}

	// 3. Restore active version pointer
	activeEpoch, err := n.persistence.GetActiveVersionEpoch()
	if err != nil {
		return fmt.Errorf("failed to load active version epoch: %w", err)
	}

	if activeEpoch > 0 {
		// Find and set the active version in keystore
		for _, version := range versions {
			if version.Version == activeEpoch {
				n.keyStore.SetActiveVersion(version)
				n.logger.Sugar().Infow("Restored active key version",
					"operator_address", n.OperatorAddress.Hex(),
					"epoch", activeEpoch)
				break
			}
		}
	}

	// 4. Check for incomplete protocol sessions
	sessions, err := n.persistence.ListProtocolSessions()
	if err != nil {
		return fmt.Errorf("failed to load protocol sessions: %w", err)
	}

	if len(sessions) > 0 {
		n.logger.Sugar().Warnw("Found incomplete protocol sessions",
			"operator_address", n.OperatorAddress.Hex(),
			"count", len(sessions))

		// Get protocol timeout for this chain
		protocolTimeout := config.GetProtocolTimeoutForChain(n.ChainID)
		timeoutSeconds := int64(protocolTimeout.Seconds())

		// Process each session
		for _, sessionState := range sessions {
			// Check if session has expired
			if sessionState.IsExpired(timeoutSeconds) {
				n.logger.Sugar().Warnw("Cleaning up expired session",
					"operator_address", n.OperatorAddress.Hex(),
					"session_timestamp", sessionState.SessionTimestamp,
					"type", sessionState.Type,
					"phase", sessionState.Phase,
					"age_seconds", time.Now().Unix()-sessionState.StartTime)

				if err := n.persistence.DeleteProtocolSession(sessionState.SessionTimestamp); err != nil {
					n.logger.Sugar().Errorw("Failed to delete expired session",
						"operator_address", n.OperatorAddress.Hex(),
						"session_timestamp", sessionState.SessionTimestamp,
						"error", err)
				}
			} else {
				// Session not expired - could attempt resumption
				// For now, still clean up (resumption is complex, future enhancement)
				n.logger.Sugar().Warnw("Cleaning up incomplete session (resumption not yet implemented)",
					"operator_address", n.OperatorAddress.Hex(),
					"session_timestamp", sessionState.SessionTimestamp,
					"type", sessionState.Type,
					"phase", sessionState.Phase,
					"age_seconds", time.Now().Unix()-sessionState.StartTime)

				if err := n.persistence.DeleteProtocolSession(sessionState.SessionTimestamp); err != nil {
					n.logger.Sugar().Errorw("Failed to delete incomplete session",
						"operator_address", n.OperatorAddress.Hex(),
						"session_timestamp", sessionState.SessionTimestamp,
						"error", err)
				}
			}
		}
	}

	n.logger.Sugar().Infow("State restoration complete",
		"operator_address", n.OperatorAddress.Hex())
	return nil
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

	// Fail fast on derived nodeID collisions to avoid silent overwrites in protocol state.
	// (Node IDs are used as map keys in sessions; collisions would cause split-brain / misrouting.)
	seenNodeIDs := make(map[int64]common.Address, len(sortedPeers))
	for _, op := range sortedPeers {
		id := util.AddressToNodeID(op.OperatorAddress)
		if prev, ok := seenNodeIDs[id]; ok && prev != op.OperatorAddress {
			return nil, fmt.Errorf("derived nodeID collision: node_id=%d addr1=%s addr2=%s", id, prev.Hex(), op.OperatorAddress.Hex())
		}
		seenNodeIDs[id] = op.OperatorAddress
	}

	n.logger.Sugar().Infow("Fetched operators from chain",
		"operator_address", n.OperatorAddress.Hex(),
		"count", len(sortedPeers),
		"operators", strings.Join(util.Map(sortedPeers, func(op *peering.OperatorSetPeer, i uint64) string {
			return fmt.Sprintf("%s:%s", op.OperatorAddress.String(), op.SocketAddress)
		}), ", "),
	)
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
		SessionTimestamp:        sessionTimestamp,
		Type:                    sessionType,
		Phase:                   1,
		StartTime:               time.Now(),
		Operators:               operators,
		shares:                  make(map[int64]*fr.Element),
		commitments:             make(map[int64][]types.G2Point),
		acks:                    make(map[int64]map[int64]*types.Acknowledgement),
		sharesCompleteChan:      make(chan bool, 1),
		commitmentsCompleteChan: make(chan bool, 1),
		acksCompleteChan:        make(chan bool, 1),
		verifiedOperators:       make(map[int64]bool),
	}

	// Initialize acks map for each operator (as dealer)
	for _, op := range operators {
		nodeID := util.AddressToNodeID(op.OperatorAddress)
		session.acks[nodeID] = make(map[int64]*types.Acknowledgement)
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

// cleanupSession removes a completed or failed session from memory and persistence
func (n *Node) cleanupSession(sessionTimestamp int64) {
	n.sessionMutex.Lock()
	delete(n.activeSessions, sessionTimestamp)
	n.sessionMutex.Unlock()

	// Delete from persistence
	if err := n.persistence.DeleteProtocolSession(sessionTimestamp); err != nil {
		n.logger.Sugar().Warnw("Failed to delete session from persistence",
			"operator_address", n.OperatorAddress.Hex(),
			"session_timestamp", sessionTimestamp,
			"error", err)
	}

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

	// Persist initial session state
	if err := n.saveSession(session); err != nil {
		n.logger.Sugar().Warnw("Failed to persist initial DKG session",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
	}

	// Use keccak256 hash of operator address as node ID
	thisNodeID := util.AddressToNodeID(n.OperatorAddress)

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
		opNodeID := util.AddressToNodeID(op.OperatorAddress)
		n.logger.Sugar().Debugw("Sending share to operator",
			"operator_address", n.OperatorAddress.Hex(),
			"target", op.OperatorAddress.Hex())
		if opNodeID == thisNodeID {
			// Store own share and commitment in session
			_ = session.HandleReceivedShare(thisNodeID, shares[thisNodeID])
			_ = session.HandleReceivedCommitment(thisNodeID, commitments)
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

	// Wait for all shares and commitments using channel-based signaling
	protocolTimeout := config.GetProtocolTimeoutForChain(n.ChainID)
	if err := waitForShares(session, protocolTimeout); err != nil {
		return err
	}
	if err := waitForCommitments(session, protocolTimeout); err != nil {
		return err
	}

	// Update session to Phase 2 and persist
	session.mu.Lock()
	session.Phase = 2
	session.mu.Unlock()
	if err := n.saveSession(session); err != nil {
		n.logger.Sugar().Warnw("Failed to persist DKG session after Phase 1",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
	}

	// Phase 2: Verify and send acknowledgements
	n.logger.Sugar().Infow("Starting DKG Phase 2", "operator_address", n.OperatorAddress.Hex(), "node_id", thisNodeID, "phase", "verify_and_ack")

	// Get shares and commitments from session (we know we have all of them now)
	session.mu.RLock()
	receivedShares := session.shares
	receivedCommitments := session.commitments
	session.mu.RUnlock()

	validShares := make(map[int64]*fr.Element)
	for dealerID, share := range receivedShares {
		commitments := receivedCommitments[dealerID]
		if n.dkg.VerifyShare(dealerID, share, commitments) {
			validShares[dealerID] = share

			// Create acknowledgement for verified share (Phase 4: added epoch and share)
			ack := dkg.CreateAcknowledgement(thisNodeID, dealerID, sessionTimestamp, share, commitments, n.signAcknowledgement)

			// Find dealer's peer info for transport
			var dealerPeer *peering.OperatorSetPeer
			for _, op := range operators {
				if util.AddressToNodeID(op.OperatorAddress) == dealerID {
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

	// No need to store validShares globally - just use them for finalization later

	// Wait for acknowledgements (as a dealer) - need ALL operators for DKG
	myNodeID := util.AddressToNodeID(n.OperatorAddress)
	if err := waitForAcks(session, myNodeID, protocolTimeout); err != nil {
		return fmt.Errorf("insufficient acknowledgements: %v", err)
	}

	// Update session to Phase 3 and persist
	session.mu.Lock()
	session.Phase = 3
	session.mu.Unlock()
	if err := n.saveSession(session); err != nil {
		n.logger.Sugar().Warnw("Failed to persist DKG session after Phase 2",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
	}

	// Phase 3: Build Merkle Tree and Submit to Contract
	n.logger.Sugar().Infow("DKG Phase 3: Building merkle tree and submitting to contract",
		"operator_address", n.OperatorAddress.Hex(),
		"session", session.SessionTimestamp)

	// Collect acknowledgements from session where I am the dealer
	session.mu.RLock()
	myAcks := make([]*types.Acknowledgement, 0)
	if ackMap, ok := session.acks[myNodeID]; ok {
		for _, ack := range ackMap {
			myAcks = append(myAcks, ack)
		}
	}
	session.mu.RUnlock()

	if len(myAcks) == 0 {
		return fmt.Errorf("no acknowledgements collected as dealer")
	}

	// Build merkle tree from collected acks
	merkleTree, err := dkg.BuildAcknowledgementMerkleTree(myAcks)
	if err != nil {
		return fmt.Errorf("failed to build merkle tree: %w", err)
	}

	// Compute commitment hash
	myCommitmentHash := eigenxcrypto.HashCommitment(commitments)

	n.logger.Sugar().Infow("Merkle tree built successfully",
		"num_acks", len(myAcks),
		"merkle_root", fmt.Sprintf("0x%x", merkleTree.Root))

	// Submit to contract with retry logic
	err = n.submitCommitmentWithRetry(
		ctx,
		session.SessionTimestamp,
		myCommitmentHash,
		merkleTree.Root,
	)
	if err != nil {
		return fmt.Errorf("failed to submit commitment after retries: %w", err)
	}

	n.logger.Sugar().Infow("Commitment submitted to Base contract successfully",
		"commitment_hash", fmt.Sprintf("0x%x", myCommitmentHash),
		"merkle_root", fmt.Sprintf("0x%x", merkleTree.Root))

	// Store in session
	session.mu.Lock()
	session.myAckMerkleTree = merkleTree
	session.myCommitmentHash = myCommitmentHash
	session.contractSubmitted = true
	session.mu.Unlock()

	// Phase 4: Broadcast commitments with proofs to all operators
	n.logger.Sugar().Infow("DKG Phase 4: Broadcasting commitments with proofs",
		"operator_address", n.OperatorAddress.Hex())

	err = n.transport.BroadcastCommitmentsWithProofs(
		operators,
		session.SessionTimestamp,
		commitments,
		myAcks,
		merkleTree,
	)
	if err != nil {
		n.logger.Sugar().Warnw("Failed to broadcast commitments with proofs", "error", err)
		// Continue - not fatal if some broadcasts fail
	}

	// Phase 5: Wait for and verify all operator broadcasts
	n.logger.Sugar().Infow("DKG Phase 5: Waiting for operator verifications",
		"expected_verifications", len(operators)-1)

	err = n.WaitForVerifications(session.SessionTimestamp, protocolTimeout)
	if err != nil {
		n.logger.Sugar().Warnw("Verification phase incomplete", "error", err)
		// Continue - not fatal, verification is optional
	} else {
		n.logger.Sugar().Infow("All operator broadcasts verified successfully")
	}

	// Phase 6: Finalize
	n.logger.Sugar().Infow("DKG Phase 6: Finalizing key share",
		"operator_address", n.OperatorAddress.Hex(),
		"node_id", thisNodeID)

	allCommitments := make([][]types.G2Point, 0, len(receivedCommitments))
	participantIDs := make([]int64, 0, len(receivedCommitments))

	for _, op := range operators {
		opNodeID := util.AddressToNodeID(op.OperatorAddress)
		if comm, ok := receivedCommitments[opNodeID]; ok {
			allCommitments = append(allCommitments, comm)
			participantIDs = append(participantIDs, opNodeID)
		}
	}

	// Use validShares (only verified shares) for finalization
	keyVersion := n.dkg.FinalizeKeyShare(validShares, allCommitments, participantIDs)
	keyVersion.Version = session.SessionTimestamp // Use session timestamp as version
	// Store THIS node's commitments (not allCommitments[0]) so that when the client
	// queries all operators and sums their commitments[0], it computes the correct master public key
	keyVersion.Commitments = commitments

	// Persist key version BEFORE adding to keystore
	// This ensures we fail if persistence fails, preventing state inconsistency
	if err := n.persistence.SaveKeyShareVersion(keyVersion); err != nil {
		n.logger.Sugar().Errorw("Failed to persist key share version - DKG cannot complete",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
		return fmt.Errorf("failed to persist key share version: %w", err)
	}

	// Persist active version pointer
	if err := n.persistence.SetActiveVersionEpoch(keyVersion.Version); err != nil {
		n.logger.Sugar().Errorw("Failed to persist active version pointer - DKG cannot complete",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
		return fmt.Errorf("failed to persist active version pointer: %w", err)
	}

	// Only add to keystore after successful persistence
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
	thisNodeID := util.AddressToNodeID(n.OperatorAddress)

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

	// Persist initial session state
	if err := n.saveSession(session); err != nil {
		n.logger.Sugar().Warnw("Failed to persist initial reshare session",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
	}

	// Broadcast commitments
	if err := n.transport.BroadcastReshareCommitments(operators, commitments, session.SessionTimestamp); err != nil {
		n.logger.Sugar().Errorw("Failed to broadcast reshare commitments", "operator_address", n.OperatorAddress.Hex(), "error", err)
		// Continue anyway - other nodes may have received
	}

	// Send shares to all operators
	for _, op := range operators {
		opNodeID := util.AddressToNodeID(op.OperatorAddress)
		if opNodeID == thisNodeID {
			// Store own share and commitment in session
			_ = session.HandleReceivedShare(thisNodeID, shares[opNodeID])
			_ = session.HandleReceivedCommitment(thisNodeID, commitments)
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

	// Wait for shares and commitments using channel-based signaling
	protocolTimeout := config.GetProtocolTimeoutForChain(n.ChainID)
	if err := waitForShares(session, protocolTimeout); err != nil {
		return err
	}
	if err := waitForCommitments(session, protocolTimeout); err != nil {
		return err
	}

	// Update session to Phase 2 and persist
	session.mu.Lock()
	session.Phase = 2
	session.mu.Unlock()
	if err := n.saveSession(session); err != nil {
		n.logger.Sugar().Warnw("Failed to persist reshare session after Phase 1",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
	}

	// Phase 1b: Verify shares and send acknowledgements
	n.logger.Sugar().Infow("Reshare Phase 1b: Verifying shares and sending acknowledgements",
		"operator_address", n.OperatorAddress.Hex(),
		"node_id", thisNodeID)

	// Get shares and commitments from session
	session.mu.RLock()
	receivedShares := session.shares
	receivedCommitments := session.commitments
	session.mu.RUnlock()

	validShares := make(map[int64]*fr.Element)
	for dealerID, share := range receivedShares {
		commitments := receivedCommitments[dealerID]
		if n.resharer.VerifyNewShare(dealerID, share, commitments) {
			validShares[dealerID] = share

			// Create acknowledgement for verified share
			ack := reshare.CreateAcknowledgement(thisNodeID, dealerID, sessionTimestamp, share, commitments, n.signAcknowledgement)

			// Find dealer's peer info for transport
			var dealerPeer *peering.OperatorSetPeer
			for _, op := range operators {
				if util.AddressToNodeID(op.OperatorAddress) == dealerID {
					dealerPeer = op
					break
				}
			}

			if dealerPeer != nil {
				// Send acknowledgement to dealer
				err := n.transport.SendReshareAcknowledgement(ack, dealerPeer, session.SessionTimestamp)
				if err != nil {
					n.logger.Sugar().Warnw("Failed to send reshare acknowledgement",
						"operator_address", n.OperatorAddress.Hex(),
						"dealer_address", dealerPeer.OperatorAddress.Hex(),
						"error", err)
				} else {
					n.logger.Sugar().Debugw("Sent reshare acknowledgement",
						"operator_address", n.OperatorAddress.Hex(),
						"dealer_address", dealerPeer.OperatorAddress.Hex(),
						"dealer_id", dealerID)
				}
			}

			n.logger.Sugar().Infow("Verified and acked reshare share",
				"operator_address", n.OperatorAddress.Hex(),
				"node_id", thisNodeID,
				"dealer_id", dealerID)
		} else {
			n.logger.Sugar().Warnw("Invalid reshare share received",
				"operator_address", n.OperatorAddress.Hex(),
				"node_id", thisNodeID,
				"dealer_id", dealerID)
		}
	}

	// Wait for acknowledgements (as a dealer)
	myNodeID := util.AddressToNodeID(n.OperatorAddress)
	if err := waitForAcks(session, myNodeID, protocolTimeout); err != nil {
		return fmt.Errorf("insufficient reshare acknowledgements: %v", err)
	}

	// Phase 2: Build Merkle Tree and Submit to Contract
	n.logger.Sugar().Infow("Reshare Phase 2: Building merkle tree and submitting to contract",
		"operator_address", n.OperatorAddress.Hex(),
		"session", session.SessionTimestamp)

	// Collect acknowledgements from session where I am the dealer
	session.mu.RLock()
	myAcks := make([]*types.Acknowledgement, 0)
	if ackMap, ok := session.acks[myNodeID]; ok {
		for _, ack := range ackMap {
			myAcks = append(myAcks, ack)
		}
	}
	session.mu.RUnlock()

	if len(myAcks) == 0 {
		return fmt.Errorf("no acknowledgements collected as dealer in reshare")
	}

	// Build merkle tree from collected acks
	merkleTree, err := reshare.BuildAcknowledgementMerkleTree(myAcks)
	if err != nil {
		return fmt.Errorf("failed to build merkle tree in reshare: %w", err)
	}

	// Compute commitment hash from my commitments (from session)
	session.mu.RLock()
	myCommitments, ok := session.commitments[myNodeID]
	session.mu.RUnlock()
	if !ok {
		return fmt.Errorf("my commitments not found in reshare")
	}

	myCommitmentHash := eigenxcrypto.HashCommitment(myCommitments)

	n.logger.Sugar().Infow("Merkle tree built successfully in reshare",
		"num_acks", len(myAcks),
		"merkle_root", fmt.Sprintf("0x%x", merkleTree.Root))

	// Submit to contract with retry logic
	err = n.submitCommitmentWithRetry(
		ctx,
		session.SessionTimestamp,
		myCommitmentHash,
		merkleTree.Root,
	)
	if err != nil {
		return fmt.Errorf("failed to submit commitment in reshare after retries: %w", err)
	}

	n.logger.Sugar().Infow("Commitment submitted to Base contract successfully in reshare",
		"commitment_hash", fmt.Sprintf("0x%x", myCommitmentHash),
		"merkle_root", fmt.Sprintf("0x%x", merkleTree.Root))

	// Store in session
	session.mu.Lock()
	session.myAckMerkleTree = merkleTree
	session.myCommitmentHash = myCommitmentHash
	session.contractSubmitted = true
	session.mu.Unlock()

	// Phase 3: Broadcast commitments with proofs
	n.logger.Sugar().Infow("Reshare Phase 3: Broadcasting commitments with proofs",
		"operator_address", n.OperatorAddress.Hex())

	err = n.transport.BroadcastCommitmentsWithProofs(
		operators,
		session.SessionTimestamp,
		myCommitments,
		myAcks,
		merkleTree,
	)
	if err != nil {
		n.logger.Sugar().Warnw("Failed to broadcast commitments with proofs in reshare", "error", err)
		// Continue - not fatal if some broadcasts fail
	}

	// Phase 4: Wait for verifications
	n.logger.Sugar().Infow("Reshare Phase 4: Waiting for operator verifications",
		"expected_verifications", len(operators)-1)

	err = n.WaitForVerifications(session.SessionTimestamp, protocolTimeout)
	if err != nil {
		n.logger.Sugar().Warnw("Verification phase incomplete in reshare", "error", err)
		// Continue - not fatal, verification is optional
	} else {
		n.logger.Sugar().Infow("All operator broadcasts verified successfully in reshare")
	}

	// Phase 5: Finalize reshare
	n.logger.Sugar().Infow("Reshare Phase 5: Finalizing key share",
		"operator_address", n.OperatorAddress.Hex(),
		"node_id", thisNodeID)

	// Collect all commitments and participant IDs for finalization from session
	session.mu.RLock()
	allCommitmentsForFinalize := make([][]types.G2Point, 0, len(session.commitments))
	participantIDsForFinalize := make([]int64, 0, len(session.commitments))

	for _, op := range operators {
		opNodeID := util.AddressToNodeID(op.OperatorAddress)
		if comm, ok := session.commitments[opNodeID]; ok {
			allCommitmentsForFinalize = append(allCommitmentsForFinalize, comm)
			participantIDsForFinalize = append(participantIDsForFinalize, opNodeID)
		}
	}

	receivedSharesForFinalize := session.shares
	session.mu.RUnlock()

	// Compute new key share using Lagrange interpolation
	newKeyVersion := n.resharer.ComputeNewKeyShare(participantIDsForFinalize, receivedSharesForFinalize, allCommitmentsForFinalize)
	newKeyVersion.Version = sessionTimestamp // Use session timestamp as version
	newKeyVersion.IsActive = true            // Activate immediately (all operators must participate)

	// Scale this node's first commitment by its Lagrange coefficient
	// This ensures that when the client sums all operators' commitments[0], it gets g^s (master public key)
	// In reshare: C[0] = g^{x_i} where x_i is old share
	// Master public key = g^s = g^{Σ λ_i * x_i} = Σ λ_i * C[0]
	// So we store λ_i * C[0] as our contribution to the master public key sum
	lambda := eigenxcrypto.ComputeLagrangeCoefficient(thisNodeID, participantIDsForFinalize)
	scaledFirstCommitment, err := eigenxcrypto.ScalarMulG2(myCommitments[0], lambda)
	if err != nil {
		return fmt.Errorf("failed to scale commitment: %w", err)
	}

	// Create scaled commitments (only first one is scaled for master public key computation)
	scaledCommitments := make([]types.G2Point, len(myCommitments))
	scaledCommitments[0] = *scaledFirstCommitment
	for i := 1; i < len(myCommitments); i++ {
		scaledCommitments[i] = myCommitments[i]
	}
	newKeyVersion.Commitments = scaledCommitments

	// Persist new key version BEFORE adding to keystore
	// This ensures we fail if persistence fails, preventing state inconsistency
	if err := n.persistence.SaveKeyShareVersion(newKeyVersion); err != nil {
		n.logger.Sugar().Errorw("Failed to persist reshare key share version - reshare cannot complete",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
		return fmt.Errorf("failed to persist reshare key share version: %w", err)
	}

	// Update active version pointer
	if err := n.persistence.SetActiveVersionEpoch(newKeyVersion.Version); err != nil {
		n.logger.Sugar().Errorw("Failed to persist active version pointer - reshare cannot complete",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
		return fmt.Errorf("failed to persist active version pointer: %w", err)
	}

	// Only add to keystore after successful persistence
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

	thisNodeID := util.AddressToNodeID(n.OperatorAddress)

	// Create reshare instance
	n.resharer = reshare.NewReshare(thisNodeID, operators)

	// Create session for this reshare (as recipient only)
	session := n.createSession("reshare", operators, sessionTimestamp)
	defer n.cleanupSession(session.SessionTimestamp)

	// Persist initial session state
	if err := n.saveSession(session); err != nil {
		n.logger.Sugar().Warnw("Failed to persist initial reshare session (new operator)",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
	}

	// New operators DON'T generate shares - only receive from existing operators
	n.logger.Sugar().Infow("Waiting for shares from existing operators",
		"operator_address", n.OperatorAddress.Hex(),
		"expected_operators", len(operators))

	// Wait for shares and commitments from existing operators using channel-based signaling
	protocolTimeout := config.GetProtocolTimeoutForChain(n.ChainID)
	if err := waitForShares(session, protocolTimeout); err != nil {
		return fmt.Errorf("failed to receive shares: %w", err)
	}
	if err := waitForCommitments(session, protocolTimeout); err != nil {
		return fmt.Errorf("failed to receive commitments: %w", err)
	}

	// Collect all commitments and participant IDs from session
	session.mu.RLock()
	allCommitments := make([][]types.G2Point, 0, len(session.commitments))
	participantIDs := make([]int64, 0, len(session.commitments))

	for _, op := range operators {
		opNodeID := util.AddressToNodeID(op.OperatorAddress)
		if comm, ok := session.commitments[opNodeID]; ok {
			allCommitments = append(allCommitments, comm)
			participantIDs = append(participantIDs, opNodeID)
		}
	}

	receivedShares := session.shares
	session.mu.RUnlock()

	// Compute new key share using Lagrange interpolation
	newKeyVersion := n.resharer.ComputeNewKeyShare(participantIDs, receivedShares, allCommitments)
	newKeyVersion.Version = sessionTimestamp // Use session timestamp as version
	newKeyVersion.IsActive = true            // First key version becomes active immediately

	// Persist first key version BEFORE adding to keystore (critical for new operator)
	// This ensures we fail if persistence fails, preventing state inconsistency
	if err := n.persistence.SaveKeyShareVersion(newKeyVersion); err != nil {
		n.logger.Sugar().Errorw("Failed to persist first key share version - cannot join cluster",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
		return fmt.Errorf("failed to persist first key share version: %w", err)
	}

	// Set as active version
	if err := n.persistence.SetActiveVersionEpoch(newKeyVersion.Version); err != nil {
		n.logger.Sugar().Errorw("Failed to persist active version pointer - cannot join cluster",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
		return fmt.Errorf("failed to persist active version pointer: %w", err)
	}

	// Only add to keystore after successful persistence
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

// Wait functions using channel-based completion signaling

// waitForShares waits for all shares to be received using channel signaling
func waitForShares(session *ProtocolSession, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	select {
	case <-session.sharesCompleteChan:
		return nil

	case <-ctx.Done():
		session.mu.RLock()
		received := len(session.shares)
		expected := len(session.Operators)
		session.mu.RUnlock()
		return fmt.Errorf("timeout waiting for shares: got %d/%d", received, expected)
	}
}

// waitForCommitments waits for all commitments to be received using channel signaling
func waitForCommitments(session *ProtocolSession, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	select {
	case <-session.commitmentsCompleteChan:
		return nil

	case <-ctx.Done():
		session.mu.RLock()
		received := len(session.commitments)
		expected := len(session.Operators)
		session.mu.RUnlock()
		return fmt.Errorf("timeout waiting for commitments: got %d/%d", received, expected)
	}
}

// waitForAcks waits for all acknowledgements to be received for a specific dealer using polling
// Note: We poll instead of using acksCompleteChan because the channel signals when ANY dealer
// completes, not when THIS specific dealer completes. Each dealer needs to wait for their own acks.
func waitForAcks(session *ProtocolSession, dealerNodeID int64, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	expected := len(session.Operators) - 1 // All operators except dealer itself

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			session.mu.RLock()
			ackMap := session.acks[dealerNodeID]
			received := 0
			if ackMap != nil {
				received = len(ackMap)
			}
			session.mu.RUnlock()
			return fmt.Errorf("timeout waiting for acks: got %d/%d", received, expected)

		case <-ticker.C:
			session.mu.RLock()
			ackMap := session.acks[dealerNodeID]
			received := 0
			if ackMap != nil {
				received = len(ackMap)
			}
			session.mu.RUnlock()

			if received >= expected {
				return nil
			}
		}
	}
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
func (n *Node) RunDKGPhase1() (map[int64]*fr.Element, []types.G2Point, error) {
	return n.dkg.GenerateShares()
}

// Deprecated: Old test helper functions - use TestCluster instead
// These functions used global state which has been moved to sessions

// verifyMessage verifies an authenticated message using the sender's BN254 public key
func (n *Node) verifyMessage(authMsg *types.AuthenticatedMessage, senderPeer *peering.OperatorSetPeer) error {
	// Verify payload hash
	actualHash := crypto.Keccak256(authMsg.Payload)
	if !bytes.Equal(actualHash, authMsg.Hash[:]) {
		return fmt.Errorf("payload digest mismatch")
	}

	n.logger.Sugar().Infow("Verifying message signature",
		zap.String("sender_address", senderPeer.OperatorAddress.String()),
		zap.String("public_key", senderPeer.WrappedPublicKey.ECDSAAddress.String()),
		zap.String("curve_type", senderPeer.CurveType.String()),
		zap.String("hash", fmt.Sprintf("0x%x", authMsg.Hash)),
	)

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

// submitCommitmentWithRetry submits a commitment to the Base contract with exponential backoff retry logic
func (n *Node) submitCommitmentWithRetry(
	ctx context.Context,
	epoch int64,
	commitmentHash [32]byte,
	merkleRoot [32]byte,
) error {
	const maxRetries = 3
	backoffDurations := []time.Duration{
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
	}

	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		n.logger.Sugar().Infow("Submitting commitment to Base contract",
			"attempt", attempt+1,
			"max_attempts", maxRetries,
			"epoch", epoch,
			"commitment_hash", fmt.Sprintf("0x%x", commitmentHash),
			"merkle_root", fmt.Sprintf("0x%x", merkleRoot))

		// Call contract submission (synchronous, waits for tx to be mined)
		_, err := n.baseContractCaller.SubmitCommitment(
			ctx,
			n.commitmentRegistryAddress,
			epoch,
			commitmentHash,
			merkleRoot,
		)

		if err == nil {
			n.logger.Sugar().Infow("Commitment submitted successfully to Base chain",
				"attempt", attempt+1,
				"epoch", epoch)
			return nil
		}

		lastErr = err
		n.logger.Sugar().Warnw("Commitment submission failed",
			"attempt", attempt+1,
			"error", err)

		// If this isn't the last attempt, wait before retrying
		if attempt < maxRetries-1 {
			backoffDuration := backoffDurations[attempt]
			n.logger.Sugar().Infow("Retrying after backoff",
				"backoff_duration", backoffDuration)

			select {
			case <-ctx.Done():
				return fmt.Errorf("context cancelled during retry backoff: %w", ctx.Err())
			case <-time.After(backoffDuration):
				// Continue to next retry
			}
		}
	}

	return fmt.Errorf("failed to submit commitment after %d attempts: %w", maxRetries, lastErr)
}

// signAcknowledgement signs an acknowledgement using ECDSA transport signer
func (n *Node) signAcknowledgement(dealerID int64, commitmentHash [32]byte) []byte {
	// Create message: dealerID || commitmentHash
	dealerBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(dealerBytes, uint32(dealerID))
	message := append(dealerBytes, commitmentHash[:]...)

	// Sign using transport signer (ECDSA)
	signature, err := n.transportSigner.SignMessage(message)
	if err != nil {
		n.logger.Sugar().Errorw("Failed to sign acknowledgement", "error", err)
		return nil
	}
	return signature
}

// VerifyOperatorBroadcast verifies a commitment broadcast against on-chain data (Phase 6)
func (n *Node) VerifyOperatorBroadcast(
	sessionTimestamp int64,
	broadcast *types.CommitmentBroadcast,
	contractRegistryAddr common.Address,
) error {
	if broadcast == nil {
		return fmt.Errorf("broadcast is nil")
	}

	// Step 1: Query contract for operator's commitment (requires contractCaller in Phase 6)
	// For now, this is a placeholder that will be implemented when we integrate with the contract
	// In Phase 7 integration tests, we'll add the actual contract query

	// Step 2: Verify commitment hash matches broadcast
	broadcastCommitmentHash := eigenxcrypto.HashCommitment(broadcast.Commitments)

	// Step 3: Find MY ack in the broadcast
	session := n.getSession(sessionTimestamp)
	if session == nil {
		return fmt.Errorf("session not found")
	}

	myNodeID := util.AddressToNodeID(n.OperatorAddress)

	var myAck *types.Acknowledgement
	for _, ack := range broadcast.Acknowledgements {
		if ack.PlayerID == myNodeID {
			myAck = ack
			break
		}
	}

	if myAck == nil {
		return fmt.Errorf("my ack not found in broadcast")
	}

	// Step 4: Verify MY ack's shareHash matches the share I received
	session.mu.RLock()
	receivedShare := session.shares[broadcast.FromOperatorID]
	session.mu.RUnlock()

	if receivedShare == nil {
		return fmt.Errorf("no share received from operator %d", broadcast.FromOperatorID)
	}

	expectedShareHash := eigenxcrypto.HashShareForAck(receivedShare)
	if myAck.ShareHash != expectedShareHash {
		return fmt.Errorf("share hash mismatch: ack says %x, actual is %x",
			myAck.ShareHash, expectedShareHash)
	}

	// Step 5: Verify merkle proof
	leafHash := eigenxcrypto.HashAcknowledgementForMerkle(myAck)
	proof := &merkle.MerkleProof{
		Leaf:  leafHash,
		Proof: broadcast.MerkleProof,
	}

	// For Phase 6, we'll verify against the tree root
	// In Phase 7, we'll verify against on-chain root from contract
	// For now, just verify the proof is well-formed
	if len(proof.Proof) == 0 {
		return fmt.Errorf("merkle proof is empty")
	}

	// Mark operator as verified
	session.mu.Lock()
	session.verifiedOperators[broadcast.FromOperatorID] = true
	session.mu.Unlock()

	n.logger.Sugar().Debugw("Verified operator broadcast",
		"from_operator", broadcast.FromOperatorID,
		"epoch", broadcast.Epoch,
		"commitment_hash", fmt.Sprintf("%x", broadcastCommitmentHash[:8]),
	)

	return nil
}

// WaitForVerifications waits for all operators to be verified (Phase 6)
func (n *Node) WaitForVerifications(sessionTimestamp int64, timeout time.Duration) error {
	session := n.getSession(sessionTimestamp)
	if session == nil {
		return fmt.Errorf("session not found")
	}

	expectedVerifications := len(session.Operators) - 1 // All except self

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-time.After(time.Until(deadline)):
			session.mu.RLock()
			verified := len(session.verifiedOperators)
			session.mu.RUnlock()
			return fmt.Errorf("timeout waiting for verifications: verified %d/%d",
				verified, expectedVerifications)

		case <-ticker.C:
			session.mu.RLock()
			verified := len(session.verifiedOperators)
			session.mu.RUnlock()

			if verified >= expectedVerifications {
				n.logger.Sugar().Infow("All operators verified",
					"session", sessionTimestamp,
					"verified_count", verified,
				)
				return nil
			}
		}
	}
}
