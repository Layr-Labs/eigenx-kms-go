package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	"github.com/Layr-Labs/eigenx-kms-go/pkg/bls"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	eigenxcrypto "github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/keystore"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/merkle"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/reshare"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transport"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/util"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
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
	keyStore           *keystore.KeyStore
	transport          *transport.Client
	server             *Server
	attestationManager *attestation.AttestationManager // Multi-method attestation manager
	rsaEncryption      *encryption.RSAEncryption
	peeringDataFetcher peering.IPeeringDataFetcher
	logger             *zap.Logger
	transportSigner    transportSigner.ITransportSigner
	persistence        persistence.INodePersistence

	// Dynamic components (created when needed)
	dkg      *dkg.DKG
	resharer *reshare.Reshare

	// Session management
	activeSessions    map[int64]*ProtocolSession
	sessionMutex      sync.RWMutex
	sessionNotify     map[int64]chan struct{} // Notifies when session is created
	sessionNotifyLock sync.Mutex

	// retainedGeneratedShares holds the per-recipient reshare shares this node dealt,
	// keyed by session timestamp, kept PAST session teardown so a lagging peer can still
	// fetch the share it missed (docs/012 Layer 3a). Without this, a dealer that finished
	// a round and cleaned up its session would 503 the fetch, the peer would abort and
	// fall a version behind, and the next round would corrupt the master secret. Bounded
	// to the last retainedShareRounds sessions to cap memory (in-memory only — a restart
	// drops it, which degrades to the pre-existing abort-and-retry, never to corruption).
	retainedGeneratedShares     map[int64]map[common.Address]*fr.Element
	retainedGeneratedShareOrder []int64
	retainedSharesMutex         sync.RWMutex

	// Scheduling
	enableAutoReshare     bool
	lastProcessedBoundary int64
	cancelFunc            context.CancelFunc

	blockHandler blockHandler.IBlockHandler
	poller       chainPoller.IChainPoller

	// Base chain integration (for commitment registry)
	baseContractCaller        contractCaller.IContractCaller
	commitmentRegistryAddress common.Address

	// Access control
	appAllowlist map[string]bool // nil means all apps allowed
}

// ProtocolSession tracks state for a DKG or reshare session
type ProtocolSession struct {
	SessionTimestamp int64
	Type             string // "dkg" or "reshare"
	Phase            int    // 1, 2, 3, 4 (Phase 4 adds merkle tree building and contract submission)
	StartTime        time.Time
	Operators        []*peering.OperatorSetPeer

	// TriggerBlockNumber is the interval-boundary block that triggered this session.
	// It is identical across all operators (they all trigger on the same boundary) and
	// is the anchor for the pinned-height registry read used to derive the agreed
	// reshare dealer set. See docs/011_reshareDealerSetAgreement.md.
	TriggerBlockNumber int64

	// Session-specific state (moved from global Node state)
	shares      map[common.Address]*fr.Element
	commitments map[common.Address][]types.G2Point
	acks        map[common.Address]map[common.Address]*types.Acknowledgement

	// sourceVersions records, per reshare dealer, the key version it dealt FROM (carried
	// in its commitment broadcast). Used at finalize to drop dealers on a stale source
	// version so the refreshed shares all descend from one polynomial (docs/012 Layer 2).
	// Empty for DKG (no source version).
	sourceVersions map[common.Address]int64

	// myGeneratedShares retains the per-recipient shares THIS node generated as a
	// dealer (recipient address -> share). Unlike `shares` (which holds shares this
	// node RECEIVED from others), this is what we DEALT, kept so we can answer an
	// on-demand share-fetch request from a peer that missed our original send during
	// the dealer-set-agreement finalize phase. Populated once after GenerateNewShares.
	myGeneratedShares map[common.Address]*fr.Element

	// Completion channels (buffered, size 1) - signaled when all expected messages received
	sharesCompleteChan      chan bool
	commitmentsCompleteChan chan bool
	acksCompleteChan        chan bool

	// Phase 4: Merkle tree state.
	// myAckCommitmentHash is the PLAIN HashCommitment of this node's commitments (the
	// ack/merkle-domain hash). It is NOT necessarily the value submitted on-chain: for
	// reshare the on-chain submission binds the source version (HashReshareCommitment), so
	// this field and the on-chain hash intentionally differ. It is retained for diagnostics
	// only and is not consensus-read; do not treat it as the on-chain commitment hash.
	myAckMerkleTree     *merkle.MerkleTree
	myAckCommitmentHash [32]byte
	contractSubmitted   bool

	// Phase 4: Verification state
	verifiedOperators map[common.Address]bool

	mu sync.RWMutex
}

// SetMyGeneratedShares records the per-recipient shares this node dealt, so they can
// be re-served on demand to a peer that missed the original send.
func (s *ProtocolSession) SetMyGeneratedShares(shares map[common.Address]*fr.Element) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.myGeneratedShares = make(map[common.Address]*fr.Element, len(shares))
	for addr, sh := range shares {
		// Deep-copy the field element: the caller retains the source map (it's the
		// return value of GenerateNewShares), so storing the pointer would alias
		// cryptographic material — a later mutation of the source would silently
		// corrupt what we later serve on demand.
		s.myGeneratedShares[addr] = new(fr.Element).Set(sh)
	}
}

// GetMyGeneratedShareFor returns the share this node (as dealer) generated for the
// given recipient, or nil if not present. Used to answer an on-demand share fetch.
func (s *ProtocolSession) GetMyGeneratedShareFor(recipient common.Address) *fr.Element {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.myGeneratedShares == nil {
		return nil
	}
	sh := s.myGeneratedShares[recipient]
	if sh == nil {
		return nil
	}
	// Return a copy so a caller cannot mutate the retained share.
	return new(fr.Element).Set(sh)
}

// retainedShareRounds bounds how many recent reshare rounds' generated shares are kept
// for on-demand fetch after session teardown (docs/012 Layer 3a). At the ~2-minute
// reshare cadence this covers several minutes of catch-up window, ample for the
// second-scale receipt skew that triggered the live incident, while capping memory.
const retainedShareRounds = 4

// retainGeneratedShares stores (a copy of) the per-recipient shares this node dealt for
// the given session so they can be served after the session is torn down. Bounded to the
// most recent retainedShareRounds sessions; the oldest is evicted first.
func (n *Node) retainGeneratedShares(sessionTimestamp int64, shares map[common.Address]*fr.Element) {
	n.retainedSharesMutex.Lock()
	defer n.retainedSharesMutex.Unlock()

	if n.retainedGeneratedShares == nil {
		n.retainedGeneratedShares = make(map[int64]map[common.Address]*fr.Element)
	}

	if _, exists := n.retainedGeneratedShares[sessionTimestamp]; !exists {
		n.retainedGeneratedShareOrder = append(n.retainedGeneratedShareOrder, sessionTimestamp)
	}

	cp := make(map[common.Address]*fr.Element, len(shares))
	for addr, sh := range shares {
		// Deep-copy: the caller retains the source map (GenerateNewShares' return value),
		// so storing the pointer would alias cryptographic material.
		cp[addr] = new(fr.Element).Set(sh)
	}
	n.retainedGeneratedShares[sessionTimestamp] = cp

	// Evict oldest beyond the bound.
	for len(n.retainedGeneratedShareOrder) > retainedShareRounds {
		oldest := n.retainedGeneratedShareOrder[0]
		n.retainedGeneratedShareOrder = n.retainedGeneratedShareOrder[1:]
		delete(n.retainedGeneratedShares, oldest)
	}
}

// getRetainedGeneratedShare returns a copy of the share this node dealt to recipient for
// the given session, or nil if not retained (unknown session or recipient).
func (n *Node) getRetainedGeneratedShare(sessionTimestamp int64, recipient common.Address) *fr.Element {
	n.retainedSharesMutex.RLock()
	defer n.retainedSharesMutex.RUnlock()

	byRecipient, ok := n.retainedGeneratedShares[sessionTimestamp]
	if !ok {
		return nil
	}
	sh, ok := byRecipient[recipient]
	if !ok || sh == nil {
		return nil
	}
	return new(fr.Element).Set(sh)
}

// GetSourceVersions returns a copy of the per-dealer source versions recorded this session.
func (s *ProtocolSession) GetSourceVersions() map[common.Address]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[common.Address]int64, len(s.sourceVersions))
	for k, v := range s.sourceVersions {
		out[k] = v
	}
	return out
}

// GetCommitmentsFor returns a copy of the polynomial commitments this session received
// from the given dealer, or nil if none. Used by the post-reshare MPK validation to
// recompute the group public key from the agreed dealers' commitments (docs/012 Layer 1).
func (s *ProtocolSession) GetCommitmentsFor(dealer common.Address) []types.G2Point {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.commitments[dealer]
	if !ok {
		return nil
	}
	// Deep copy: a shallow copy(out, c) would share each G2Point's CompressedBytes backing
	// array with session state, so an in-place byte mutation by a caller could corrupt the
	// stored commitment that Layer 1's MPK check relies on. Copy the bytes too.
	out := make([]types.G2Point, len(c))
	for i, pt := range c {
		cb := make([]byte, len(pt.CompressedBytes))
		copy(cb, pt.CompressedBytes)
		out[i] = types.G2Point{CompressedBytes: cb}
	}
	return out
}

// HandleReceivedShare stores a share and signals completion if all shares received
// Returns error if duplicate share detected
func (s *ProtocolSession) HandleReceivedShare(sender common.Address, share *fr.Element) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reject duplicates
	if _, exists := s.shares[sender]; exists {
		return fmt.Errorf("duplicate share from %s", sender.Hex())
	}

	s.shares[sender] = share

	// Signal completion when ALL shares received (not threshold).
	// The threshold fallback is handled by waitForNShares, which polls
	// the map length until the required count is reached or timeout.
	// Note: self-share is stored before waitForShares is called, so len(s.shares)
	// starts at 1 (self) when waiting begins.
	if len(s.shares) == len(s.Operators) {
		select {
		case s.sharesCompleteChan <- true:
		default: // Already signaled
		}
	}

	return nil
}

// HandleReceivedCommitment stores commitments (and, for reshare, the dealer's source
// version) and signals completion if all received. Returns error if duplicate commitment
// detected.
//
// sourceVersion is the key version the dealer reshared FROM (docs/012 Layer 2); pass 0 for
// DKG, which has no source version. It is recorded under the SAME lock and BEFORE the
// completion channel is signaled — atomicity matters: the reshare goroutine unblocked by
// the signal reads GetSourceVersions() at finalize, so recording it separately (after the
// signal) would race and could drop the last dealer as "unknown", aborting the round.
func (s *ProtocolSession) HandleReceivedCommitment(sender common.Address, commitments []types.G2Point, sourceVersion int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reject empty commitments
	if len(commitments) == 0 {
		return fmt.Errorf("empty commitments from %s", sender.Hex())
	}

	// Reject duplicates
	if _, exists := s.commitments[sender]; exists {
		return fmt.Errorf("duplicate commitment from %s", sender.Hex())
	}

	s.commitments[sender] = commitments
	if s.sourceVersions == nil {
		s.sourceVersions = make(map[common.Address]int64)
	}
	s.sourceVersions[sender] = sourceVersion

	// Signal completion when ALL commitments received (not threshold).
	// The threshold fallback is handled by waitForCommitmentsWithThreshold.
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
func (s *ProtocolSession) HandleReceivedAck(dealer, player common.Address, ack *types.Acknowledgement) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reject duplicates
	if s.acks[dealer] != nil {
		if _, exists := s.acks[dealer][player]; exists {
			return fmt.Errorf("duplicate ack from player %s for dealer %s", player.Hex(), dealer.Hex())
		}
	}

	if s.acks[dealer] == nil {
		s.acks[dealer] = make(map[common.Address]*types.Acknowledgement)
	}
	s.acks[dealer][player] = ack

	// Signal completion when EXACTLY all expected acks received (for this dealer)
	expectedAcks := len(s.Operators) - 1 // All except self
	if len(s.acks[dealer]) == expectedAcks {
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

	// Convert shares (fr.Element -> string, key = address hex)
	shares := make(map[string]string)
	for addr, share := range ps.shares {
		shares[addr.Hex()] = types.SerializeFr(share).Data
	}

	// Commitments (key = address hex)
	commitments := make(map[string][]types.G2Point)
	for addr, v := range ps.commitments {
		commitments[addr.Hex()] = v
	}

	// Acknowledgements (key = address hex)
	acks := make(map[string]map[string]*types.Acknowledgement)
	for dealer, ackMap := range ps.acks {
		innerMap := make(map[string]*types.Acknowledgement)
		for player, ack := range ackMap {
			innerMap[player.Hex()] = ack
		}
		acks[dealer.Hex()] = innerMap
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
	Port            int            // HTTP server port
	ChainID         config.ChainId // Ethereum chain ID
	AVSAddress      string         // AVS contract address (hex string)
	OperatorSetId   uint32         // Operator set ID
	AppAllowlist    []string       // Optional: restrict /app/sign and /secrets to these app IDs (empty = allow all)
}

// NewNode creates a new node instance with dependency injection
func NewNode(
	cfg Config,
	pdf peering.IPeeringDataFetcher,
	bh blockHandler.IBlockHandler,
	cp chainPoller.IChainPoller,
	tps transportSigner.ITransportSigner,
	attestationManager *attestation.AttestationManager,
	baseContractCaller contractCaller.IContractCaller,
	commitmentRegistryAddress common.Address,
	p persistence.INodePersistence,
	l *zap.Logger,
) (*Node, error) {
	// Validate required dependencies
	if attestationManager == nil {
		return nil, fmt.Errorf("attestationManager is required and cannot be nil")
	}
	if baseContractCaller == nil {
		return nil, fmt.Errorf("baseContractCaller is required")
	}
	if commitmentRegistryAddress == (common.Address{}) {
		return nil, fmt.Errorf("commitmentRegistryAddress is required")
	}

	// Parse operator address
	operatorAddress := common.HexToAddress(cfg.OperatorAddress)

	n := &Node{
		OperatorAddress:           operatorAddress,
		Port:                      cfg.Port,
		ChainID:                   cfg.ChainID,
		AVSAddress:                cfg.AVSAddress,
		OperatorSetId:             cfg.OperatorSetId,
		keyStore:                  keystore.NewKeyStore(),
		server:                    NewServer(nil, cfg.Port), // Will set node reference later
		attestationManager:        attestationManager,
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

	// Build app allowlist if configured
	if len(cfg.AppAllowlist) > 0 {
		n.appAllowlist = make(map[string]bool, len(cfg.AppAllowlist))
		for _, appID := range cfg.AppAllowlist {
			n.appAllowlist[strings.TrimSpace(appID)] = true
		}
	}

	// Set node reference in server
	n.server.node = n

	// Initialize transport with authenticated messaging
	// TODO(seanmcgary): this should be injected, not created here
	n.transport = transport.NewClient(operatorAddress, tps)

	return n, nil
}

// startScheduler starts the automatic protocol scheduler with context
func (n *Node) startScheduler(ctx context.Context) {
	go n.blockHandler.ListenToChannel(ctx, n.checkScheduledOperations)
}

// checkScheduledOperations checks for block interval boundaries and executes appropriate protocol
func (n *Node) checkScheduledOperations(block *ethereum.EthereumBlock) {
	blockNumber := int64(block.Number.Value())
	blockTimestamp := int64(block.Timestamp.Value())

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
		"block_timestamp", blockTimestamp,
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

	// Step 7: Skip if a protocol session is already in progress
	n.sessionMutex.RLock()
	activeCount := len(n.activeSessions)
	n.sessionMutex.RUnlock()
	if activeCount > 0 {
		n.logger.Sugar().Infow("Skipping boundary: protocol session already in progress",
			"operator_address", n.OperatorAddress.Hex(),
			"block_number", blockNumber,
			"block_timestamp", blockTimestamp,
			"active_sessions", activeCount)
		return
	}

	// Step 8: Determine if I'm a new or existing operator
	if !n.hasExistingShares() {
		// I'm a new operator - need to determine cluster state
		clusterState := n.detectClusterState(operators)

		if clusterState == "genesis" {
			// No master key exists - run genesis DKG
			n.logger.Sugar().Infow("Triggering genesis DKG at block boundary",
				"operator_address", n.OperatorAddress.Hex(),
				"block_number", blockNumber,
				"block_timestamp", blockTimestamp)

			go func() {
				if err := n.RunDKG(blockTimestamp); err != nil {
					n.logger.Sugar().Errorw("Genesis DKG failed",
						"operator_address", n.OperatorAddress.Hex(),
						"error", err)
				}
			}()
		} else {
			// Existing cluster - join via reshare.
			n.logger.Sugar().Infow("Joining existing cluster via reshare",
				"operator_address", n.OperatorAddress.Hex(),
				"block_number", blockNumber,
				"block_timestamp", blockTimestamp)

			go func() {
				if err := n.RunReshareAsNewOperator(blockTimestamp); err != nil {
					n.logger.Sugar().Errorw("Failed to join cluster via reshare",
						"operator_address", n.OperatorAddress.Hex(),
						"error", err)
				}
			}()
		}
	} else {
		// I'm an existing operator - run normal reshare.
		n.logger.Sugar().Infow("Triggering automatic reshare",
			"operator_address", n.OperatorAddress.Hex(),
			"block_number", blockNumber,
			"block_timestamp", blockTimestamp,
			"block_interval", blockInterval)

		go func() {
			if err := n.RunReshareAsExistingOperator(blockTimestamp, blockNumber); err != nil {
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
		// Warn if a persisted version looks like a block number rather than a Unix timestamp.
		// Unix timestamps are >= 1_000_000_000 (Sep 2001); block numbers are well below that.
		// This can happen when upgrading from a pre-fix deployment that stored block numbers.
		if version.Version < 1_000_000_000 {
			n.logger.Sugar().Warnw("Persisted key version looks like a block number, not a Unix timestamp — key lookup by attestation time may fail",
				"operator_address", n.OperatorAddress.Hex(),
				"version", version.Version)
		}
		n.keyStore.AddVersion(version)
	}

	// 3. Restore active version pointer
	activeTimestamp, err := n.persistence.GetActiveVersionTimestamp()
	if err != nil {
		return fmt.Errorf("failed to load active version timestamp: %w", err)
	}

	if activeTimestamp > 0 {
		// Find and set the active version in keystore
		for _, version := range versions {
			if version.Version == activeTimestamp {
				n.keyStore.SetActiveVersion(version)
				n.logger.Sugar().Infow("Restored active key version",
					"operator_address", n.OperatorAddress.Hex(),
					"version", activeTimestamp)
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
		return bytes.Compare(sortedPeers[i].OperatorAddress.Bytes(), sortedPeers[j].OperatorAddress.Bytes()) < 0
	})

	n.logger.Sugar().Infow("Fetched operators from chain",
		"operator_address", n.OperatorAddress.Hex(),
		"count", len(sortedPeers),
		"operators", strings.Join(util.Map(sortedPeers, func(op *peering.OperatorSetPeer, i uint64) string {
			return fmt.Sprintf("%s:%s", op.OperatorAddress.String(), op.SocketAddress)
		}), ", "),
	)

	if err := validateOperatorSetNoDuplicates(sortedPeers); err != nil {
		return nil, fmt.Errorf("operator set validation failed: %w", err)
	}

	return sortedPeers, nil
}

// validateOperatorSetNoDuplicates fails fast if the operator list contains duplicate addresses.
func validateOperatorSetNoDuplicates(operators []*peering.OperatorSetPeer) error {
	seenAddrs := make(map[common.Address]struct{}, len(operators))

	for _, op := range operators {
		if op == nil {
			return fmt.Errorf("operator is nil")
		}

		addr := op.OperatorAddress
		if _, ok := seenAddrs[addr]; ok {
			return fmt.Errorf("duplicate operator address in operator set: %s", addr.Hex())
		}
		seenAddrs[addr] = struct{}{}
	}

	return nil
}

// validateReshareOperatorOverlap ensures that enough operators from the previous key version
// remain in the new operator set to satisfy the old threshold. If fewer than ⌈2n/3⌉ of the
// original n participants are still present, the reshare cannot reconstruct the master secret.
func validateReshareOperatorOverlap(oldParticipants []common.Address, newOperators []*peering.OperatorSetPeer) error {
	if len(oldParticipants) == 0 {
		return nil
	}

	oldThreshold := dkg.CalculateThreshold(len(oldParticipants))

	newOperatorAddrs := make(map[common.Address]struct{}, len(newOperators))
	for _, op := range newOperators {
		newOperatorAddrs[op.OperatorAddress] = struct{}{}
	}

	overlap := 0
	for _, addr := range oldParticipants {
		if _, ok := newOperatorAddrs[addr]; ok {
			overlap++
		}
	}

	if overlap < oldThreshold {
		return fmt.Errorf(
			"insufficient operator overlap for reshare: %d of %d previous participants remain in the new operator set, need at least %d",
			overlap, len(oldParticipants), oldThreshold,
		)
	}

	return nil
}

// sessionParticipantIDs returns the set of operators that HOLD a refreshed share after a
// reshare finalizes — the full session operator set, in on-chain order.
//
// This is deliberately NOT the dealer subset. ComputeNewKeyShare gives every recipient
// (every session operator) a valid share of the same secret S, whether or not it dealt
// this round. Persisting the dealer subset as a version's ParticipantIDs is the "ratchet"
// bug (docs/013 Change 1): expectedReshareDealers intersects the next round's dealers with
// the prior version's ParticipantIDs, so a subset round shrinks the expected set — and
// does so per-node — which froze a version split on preprod. The holder set is the full
// on-chain operators slice, identical across nodes.
func sessionParticipantIDs(operators []*peering.OperatorSetPeer) []common.Address {
	ids := make([]common.Address, 0, len(operators))
	for _, op := range operators {
		ids = append(ids, op.OperatorAddress)
	}
	return ids
}

// expectedReshareDealers returns the canonical set of dealers every operator must use
// when finalizing a reshare round, in deterministic order. It is the intersection of
// the current on-chain operator set with the previous key version's participants:
// only previous participants hold a share to deal, and only currently-registered
// operators are legitimate.
//
// This set is computed purely from chain/persisted state — NOT from any per-node
// runtime view of who happened to respond — so it is identical on every honest node.
// Finalizing on this exact set on all nodes is what guarantees their refreshed shares
// stay mutually consistent (see the invariant comment at the reshare finalize site).
//
// Ordering follows the `operators` slice (the on-chain order, identical across nodes),
// so the dealer set is order-stable as well as membership-stable.
//
// If there is no active version (this node has never completed DKG), there are no
// prior participants to scope against; the caller should not be finalizing an
// existing-operator reshare in that state, so we return all current operators.
func (n *Node) expectedReshareDealers(operators []*peering.OperatorSetPeer) []common.Address {
	activeVersion := n.keyStore.GetActiveVersion()
	if activeVersion == nil || len(activeVersion.ParticipantIDs) == 0 {
		dealers := make([]common.Address, 0, len(operators))
		for _, op := range operators {
			dealers = append(dealers, op.OperatorAddress)
		}
		return dealers
	}

	prevParticipants := make(map[common.Address]struct{}, len(activeVersion.ParticipantIDs))
	for _, addr := range activeVersion.ParticipantIDs {
		prevParticipants[addr] = struct{}{}
	}

	dealers := make([]common.Address, 0, len(operators))
	for _, op := range operators {
		if _, ok := prevParticipants[op.OperatorAddress]; ok {
			dealers = append(dealers, op.OperatorAddress)
		}
	}
	return dealers
}

// deriveAgreedDealerSet returns the dealer set all operators agree to finalize on,
// derived from SHARED on-chain state (the commitment registry) rather than any node's
// local receipt timing. A dealer is in the set iff it submitted a commitment for this
// epoch in the registry.
//
// Because reads happen at chain head (the registry is on Base/L2 while the reshare is
// triggered by an Ethereum/L1 block, so the L1 trigger block cannot pin the L2 read —
// see docs/011_reshareDealerSetAgreement.md), we converge by polling until every
// EXPECTED dealer (on-chain ∩ prior participants) has submitted, or a bounded deadline
// passes. `commitments[epoch]` is append-only and epoch-keyed, so the observed set only
// grows and never changes a past entry — polling converges all honest nodes to the same
// "all dealers that submitted for this epoch" set. A genuinely-offline operator never
// submits, so it is uniformly absent on every node (preserving liveness).
//
// pinnedBlock, when > 0, is used as the L2 read height (reserved for when an L2 block
// feed is available); 0 means read at head.
// Returns the agreed dealer set AND each submitter's on-chain commitment hash, so the
// caller can verify each dealer's P2P-advertised (commitments, sourceVersion) against the
// shared registry state (docs/013 Change 2).
func (n *Node) deriveAgreedDealerSet(
	ctx context.Context,
	operators []*peering.OperatorSetPeer,
	epoch int64,
	pinnedBlock int64,
) ([]common.Address, map[common.Address][32]byte, error) {
	expected := n.expectedReshareDealers(operators)
	if len(expected) == 0 {
		return nil, nil, fmt.Errorf("no expected dealers for reshare")
	}

	deadline := time.Now().Add(config.GetProtocolTimeoutForChain(n.ChainID))
	pollInterval := 1 * time.Second

	var submitted []common.Address
	onChainHashes := make(map[common.Address][32]byte, len(expected))
	for {
		submitted = submitted[:0]
		for k := range onChainHashes {
			delete(onChainHashes, k)
		}
		for _, dealer := range expected {
			commitmentHash, _, _, err := n.baseContractCaller.GetCommitmentAt(
				ctx, n.commitmentRegistryAddress, epoch, dealer, uint64(max(pinnedBlock, 0)),
			)
			if err != nil {
				n.logger.Sugar().Debugw("registry read failed while deriving dealer set",
					"operator_address", n.OperatorAddress.Hex(),
					"dealer", dealer.Hex(), "error", err)
				continue
			}
			if commitmentHash != ([32]byte{}) {
				submitted = append(submitted, dealer)
				onChainHashes[dealer] = commitmentHash
			}
		}

		// Converged: every expected dealer has submitted on-chain.
		if len(submitted) == len(expected) {
			return submitted, onChainHashes, nil
		}
		if time.Now().After(deadline) {
			// Deadline reached: finalize on whoever submitted (uniform across nodes,
			// since it's derived from the same registry). Caller enforces |D| >= threshold.
			n.logger.Sugar().Infow("Dealer-set convergence deadline reached",
				"operator_address", n.OperatorAddress.Hex(),
				"submitted", len(submitted), "expected", len(expected))
			return submitted, onChainHashes, nil
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// fetchAndVerifyReshareShare obtains the share `dealer` generated for THIS node via the
// on-demand fetch RPC, then verifies it against the dealer's broadcast commitments using
// the same polynomial-commitment check as the push path. Returns the verified share or
// an error if it cannot be obtained/verified.
func (n *Node) fetchAndVerifyReshareShare(session *ProtocolSession, dealer common.Address) (*fr.Element, error) {
	// Locate the dealer's peer info.
	var dealerPeer *peering.OperatorSetPeer
	for _, op := range session.Operators {
		if op.OperatorAddress == dealer {
			dealerPeer = op
			break
		}
	}
	if dealerPeer == nil {
		return nil, fmt.Errorf("dealer %s not in session operator set", dealer.Hex())
	}

	// Retry the fetch a few times: a transient connection failure (dealer briefly
	// restarting, TCP RST) should not abort the whole reshare round (a ~interval-long
	// wait). Verification failures below are NOT retried — a bad share is permanently bad.
	var authResp *types.AuthenticatedMessage
	var err error
	backoff := 1 * time.Second
	for attempt := 0; attempt < 3; attempt++ {
		authResp, err = n.transport.RequestReshareShare(dealerPeer, session.SessionTimestamp)
		if err == nil {
			break
		}
		if attempt < 2 {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
	if err != nil {
		return nil, fmt.Errorf("fetch share from %s after retries: %w", dealer.Hex(), err)
	}

	// Authenticate the response: it must be BN254-signed by the dealer we asked. This
	// matches the push path's security model and prevents a spoofed From/To.
	if err := n.verifyMessage(authResp, dealerPeer); err != nil {
		return nil, fmt.Errorf("fetched share response from %s failed authentication: %w", dealer.Hex(), err)
	}
	var shareMsg types.ShareMessage
	if err := json.Unmarshal(authResp.Payload, &shareMsg); err != nil {
		return nil, fmt.Errorf("failed to parse fetched share from %s: %w", dealer.Hex(), err)
	}
	// The response must come FROM the dealer and be addressed TO this node.
	if shareMsg.FromOperatorAddress != dealer {
		return nil, fmt.Errorf("fetched share sender %s != requested dealer %s", shareMsg.FromOperatorAddress.Hex(), dealer.Hex())
	}
	if shareMsg.ToOperatorAddress != n.OperatorAddress {
		return nil, fmt.Errorf("fetched share addressed to %s, not this node %s", shareMsg.ToOperatorAddress.Hex(), n.OperatorAddress.Hex())
	}
	if shareMsg.Share == nil {
		return nil, fmt.Errorf("dealer %s returned empty share", dealer.Hex())
	}
	share := types.DeserializeFr(shareMsg.Share)

	// Verify against the dealer's commitments (must have been broadcast/received).
	session.mu.RLock()
	commitments := session.commitments[dealer]
	session.mu.RUnlock()
	if len(commitments) == 0 {
		return nil, fmt.Errorf("no commitments for dealer %s to verify fetched share", dealer.Hex())
	}
	if !n.resharer.VerifyNewShare(share, commitments) {
		return nil, fmt.Errorf("fetched share from %s failed polynomial verification", dealer.Hex())
	}
	return share, nil
}

// hasExistingShares returns true if this node has active key shares
func (n *Node) hasExistingShares() bool {
	return n.keyStore.GetActiveVersion() != nil
}

// countNewOperatorsInSet returns the number of operators in the current set that
// were not participants in the previous key version (i.e., are joining fresh).
//
// For existing operators (who have an active key version), this is computed by
// comparing the current set's node IDs against the stored ParticipantIDs.
//
// For new operators (no active key version), this is computed by querying each
// peer's /pubkey endpoint: an empty response indicates no existing key share,
// and therefore a new operator. Query failures are logged as warnings and
// counted conservatively as "new" to avoid underestimating the new-operator
// count. A nil transport is treated the same way (all operators counted as new).
func (n *Node) countNewOperatorsInSet(operators []*peering.OperatorSetPeer) int {
	activeVersion := n.keyStore.GetActiveVersion()
	if activeVersion != nil {
		prevAddrs := make(map[common.Address]struct{}, len(activeVersion.ParticipantIDs))
		for _, addr := range activeVersion.ParticipantIDs {
			prevAddrs[addr] = struct{}{}
		}
		newCount := 0
		for _, op := range operators {
			if _, found := prevAddrs[op.OperatorAddress]; !found {
				newCount++
			}
		}
		return newCount
	}

	// No active version: this node is itself new. Query peers to count operators
	// without an existing master key (empty commitments = new operator).
	if n.transport == nil {
		n.logger.Sugar().Warnw("No transport available; treating all operators as new",
			"operator_address", n.OperatorAddress.Hex(),
			"count", len(operators))
		return len(operators)
	}
	newCount := 0
	for _, op := range operators {
		commitments, err := n.transport.QueryOperatorPubkey(op)
		if err != nil {
			n.logger.Sugar().Warnw("Could not query operator pubkey; treating as new operator",
				"operator_address", n.OperatorAddress.Hex(),
				"peer", op.OperatorAddress.Hex(),
				"error", err)
			newCount++
		} else if len(commitments) == 0 {
			newCount++
		}
	}
	return newCount
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
func (n *Node) createSession(sessionType string, operators []*peering.OperatorSetPeer, sessionTimestamp int64) (*ProtocolSession, error) {
	if err := validateOperatorSetNoDuplicates(operators); err != nil {
		return nil, err
	}

	session := &ProtocolSession{
		SessionTimestamp:        sessionTimestamp,
		Type:                    sessionType,
		Phase:                   1,
		StartTime:               time.Now(),
		Operators:               operators,
		shares:                  make(map[common.Address]*fr.Element),
		commitments:             make(map[common.Address][]types.G2Point),
		acks:                    make(map[common.Address]map[common.Address]*types.Acknowledgement),
		sourceVersions:          make(map[common.Address]int64),
		sharesCompleteChan:      make(chan bool, 1),
		commitmentsCompleteChan: make(chan bool, 1),
		acksCompleteChan:        make(chan bool, 1),
		verifiedOperators:       make(map[common.Address]bool),
	}

	// Initialize acks map for each operator (as dealer)
	for _, op := range operators {
		session.acks[op.OperatorAddress] = make(map[common.Address]*types.Acknowledgement)
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

	return session, nil
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
	session, err := n.createSession("dkg", operators, sessionTimestamp)
	if err != nil {
		return fmt.Errorf("failed to create DKG session: %w", err)
	}
	defer n.cleanupSession(session.SessionTimestamp)

	// Persist initial session state
	if err := n.saveSession(session); err != nil {
		n.logger.Sugar().Warnw("Failed to persist initial DKG session",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
	}

	// Verify this operator is in the fetched operator set
	operatorFound := false
	for _, op := range operators {
		if op.OperatorAddress == n.OperatorAddress {
			operatorFound = true
			break
		}
	}
	if !operatorFound {
		return fmt.Errorf("this operator %s not found in operator set", n.OperatorAddress.Hex())
	}

	// Create DKG instance using operator address
	threshold := dkg.CalculateThreshold(len(operators))
	n.dkg = dkg.NewDKG(n.OperatorAddress, threshold, operators)

	n.logger.Sugar().Infow("Starting DKG Phase 1", "operator_address", n.OperatorAddress.Hex(), "threshold", threshold, "total_operators", len(operators))

	// Phase 1: Generate shares and commitments
	shares, commitments, err := n.dkg.GenerateShares()
	if err != nil {
		return err
	}

	// Store own share and commitment BEFORE broadcasting to other nodes.
	// This prevents a race where a fast peer receives our commitment, verifies,
	// and sends an ack back before we've stored our own commitment in the
	// session — causing verifyAcknowledgement to reject the ack with
	// "dealer commitments unavailable".
	_ = session.HandleReceivedShare(n.OperatorAddress, shares[n.OperatorAddress])
	_ = session.HandleReceivedCommitment(n.OperatorAddress, commitments, 0) // DKG has no source version

	// Broadcast commitments
	if err := n.transport.BroadcastDKGCommitments(operators, commitments, session.SessionTimestamp); err != nil {
		n.logger.Sugar().Errorw("Failed to broadcast commitments", "operator_address", n.OperatorAddress.Hex(), "error", err)
		// Continue anyway - other nodes may have received
	}

	// Send shares to each participant
	for _, op := range operators {

		if op.OperatorAddress == n.OperatorAddress {
			continue // Already stored above
		}
		n.logger.Sugar().Debugw("Sending share to operator",
			"operator_address", n.OperatorAddress.Hex(),
			"target", op.OperatorAddress.Hex())
		if err := n.transport.SendDKGShare(op, shares[op.OperatorAddress], session.SessionTimestamp); err != nil {
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
	n.logger.Sugar().Infow("Starting DKG Phase 2", "operator_address", n.OperatorAddress.Hex(), "phase", "verify_and_ack")

	// Get shares and commitments from session (we know we have all of them now)
	session.mu.RLock()
	receivedShares := session.shares
	receivedCommitments := session.commitments
	session.mu.RUnlock()

	validShares := make(map[common.Address]*fr.Element)
	for dealerAddr, share := range receivedShares {
		commitments := receivedCommitments[dealerAddr]
		if n.dkg.VerifyShare(share, commitments) {
			validShares[dealerAddr] = share

			// Skip sending ack to self — a dealer does not need to ack its own share.
			if dealerAddr == n.OperatorAddress {
				n.logger.Sugar().Debugw("Skipping self-ack", "operator_address", n.OperatorAddress.Hex(), "dealer_address", dealerAddr.Hex())
				continue
			}

			// Find dealer's peer info for transport
			var dealerPeer *peering.OperatorSetPeer
			for _, op := range operators {
				if op.OperatorAddress == dealerAddr {
					dealerPeer = op
					break
				}
			}

			if dealerPeer == nil {
				continue
			}

			// Create acknowledgement for verified share using operator addresses
			ack := eigenxcrypto.CreateAcknowledgement(n.OperatorAddress, dealerPeer.OperatorAddress, sessionTimestamp, share, commitments, n.signAcknowledgement)

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
					"dealer_address", dealerAddr.Hex())
			}

			n.logger.Sugar().Infow("Verified and acked share", "operator_address", n.OperatorAddress.Hex(), "dealer_address", dealerAddr.Hex())
		} else {
			n.logInvalidShareComplaint("dkg", sessionTimestamp, n.OperatorAddress, dealerAddr, share, commitments)
		}
	}

	// No need to store validShares globally - just use them for finalization later

	// Wait for acknowledgements (as a dealer).
	// We require a threshold (t) of *other* operators to ack, so that there exist t non-dealer holders
	// of this dealer's contribution (robust even if the dealer goes offline later).

	requiredAcks := threshold
	if requiredAcks < 0 {
		requiredAcks = 0
	}
	if err := waitForAcks(session, n.OperatorAddress, requiredAcks, protocolTimeout); err != nil {
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
	if ackMap, ok := session.acks[n.OperatorAddress]; ok {
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
	err = n.submitCommitmentWithRetry(ctx, session.SessionTimestamp, myCommitmentHash, merkleTree.Root)
	if err != nil {
		return fmt.Errorf("failed to submit commitment after retries: %w", err)
	}

	n.logger.Sugar().Infow("Commitment submitted to Base contract successfully",
		"commitment_hash", fmt.Sprintf("0x%x", myCommitmentHash),
		"merkle_root", fmt.Sprintf("0x%x", merkleTree.Root))

	// Store in session
	session.mu.Lock()
	session.myAckMerkleTree = merkleTree
	session.myAckCommitmentHash = myCommitmentHash
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
		"operator_address", n.OperatorAddress.Hex())

	// Build trusted dealer set: intersection of polynomial-verified shares and merkle-verified operators.
	// Self is always trusted (a node doesn't verify its own broadcast).
	session.mu.RLock()
	verifiedOps := make(map[common.Address]bool, len(session.verifiedOperators))
	for k, v := range session.verifiedOperators {
		verifiedOps[k] = v
	}
	session.mu.RUnlock()
	verifiedOps[n.OperatorAddress] = true

	trustedShares := trustedDealerIDs(validShares, verifiedOps)

	n.logger.Sugar().Infow("Dealer filtering for DKG finalization",
		"total_received", len(receivedShares),
		"polynomial_verified", len(validShares),
		"merkle_verified", len(verifiedOps),
		"trusted_dealers", len(trustedShares))

	allCommitments := make([][]types.G2Point, 0, len(trustedShares))
	participantIDs := make([]common.Address, 0, len(trustedShares))
	finalShares := make(map[common.Address]*fr.Element, len(trustedShares))

	for _, op := range operators {

		if share, ok := trustedShares[op.OperatorAddress]; ok {
			if comm, ok := receivedCommitments[op.OperatorAddress]; ok {
				allCommitments = append(allCommitments, comm)
				participantIDs = append(participantIDs, op.OperatorAddress)
				finalShares[op.OperatorAddress] = share
			}
		}
	}

	if len(participantIDs) < threshold {
		return fmt.Errorf("insufficient trusted dealers for DKG finalize: got %d, need %d", len(participantIDs), threshold)
	}

	// Use finalShares (polynomial-verified AND merkle-verified, with matching commitments) for finalization
	keyVersion := n.dkg.FinalizeKeyShare(finalShares, allCommitments, participantIDs)
	keyVersion.Version = session.SessionTimestamp // Use session timestamp as version
	// Commitments[0] is the constant term of the combined commitment polynomial,
	// which equals the master public key: MPK = sum_i(C_i[0]) where C_i is dealer i's commitment.
	// Cache it before overwriting Commitments so operators can serve it for client threshold agreement.
	if len(keyVersion.Commitments) > 0 {
		mpk := keyVersion.Commitments[0]
		keyVersion.MasterPublicKey = &mpk
	} else {
		n.logger.Sugar().Errorw("DKG produced key version with empty commitments - MasterPublicKey will be nil",
			"operator_address", n.OperatorAddress.Hex(),
			"session_timestamp", session.SessionTimestamp)
	}
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
	if err := n.persistence.SetActiveVersionTimestamp(keyVersion.Version); err != nil {
		n.logger.Sugar().Errorw("Failed to persist active version pointer - DKG cannot complete",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
		return fmt.Errorf("failed to persist active version pointer: %w", err)
	}

	// Only add to keystore after successful persistence
	n.keyStore.AddVersion(keyVersion)

	n.logger.Sugar().Infow("DKG complete",
		"operator_address", n.OperatorAddress.Hex(),
		"version", keyVersion.Version)
	return nil
}

// RunReshareAsExistingOperator executes the reshare protocol as an existing operator with shares.
//
// triggerBlock is the interval-boundary block number that triggered this reshare; it is
// identical across all operators and anchors the pinned-height registry read used to
// derive the agreed dealer set at finalize (docs/011_reshareDealerSetAgreement.md).
// Pass 0 to disable pinned-height agreement and fall back to head reads (used by unit
// tests that don't run a real chain).
func (n *Node) RunReshareAsExistingOperator(sessionTimestamp int64, triggerBlock int64) error {
	ctx := context.Background()
	n.logger.Sugar().Infow("Starting reshare as existing operator",
		"operator_address", n.OperatorAddress.Hex(),
		"session_timestamp", sessionTimestamp,
		"trigger_block", triggerBlock)

	// Fetch current operators from peering system
	operators, err := n.fetchCurrentOperators(ctx, n.AVSAddress, n.OperatorSetId)
	if err != nil {
		return fmt.Errorf("failed to fetch operators for reshare: %w", err)
	}

	// Compute numNewOperators from the same operators snapshot to avoid TOCTOU.
	numNewOperators := n.countNewOperatorsInSet(operators)
	if numNewOperators < 0 || numNewOperators >= len(operators) {
		return fmt.Errorf("numNewOperators %d out of range [0, %d)", numNewOperators, len(operators))
	}

	// Verify this operator is in the fetched operator set
	operatorFound := false
	for _, op := range operators {
		if op.OperatorAddress == n.OperatorAddress {
			operatorFound = true
			break
		}
	}
	if !operatorFound {
		return fmt.Errorf("this operator %s not found in reshare operator set", n.OperatorAddress.Hex())
	}

	// Validate that enough old participants remain in the new operator set to reconstruct the secret.
	// If too many operators were replaced since the last DKG/reshare, the master secret cannot be
	// maintained and reshare must not proceed.
	if activeVersion := n.keyStore.GetActiveVersion(); activeVersion != nil {
		if err := validateReshareOperatorOverlap(activeVersion.ParticipantIDs, operators); err != nil {
			return fmt.Errorf("reshare operator set validation failed: %w", err)
		}
	}

	// Calculate new threshold
	newThreshold := dkg.CalculateThreshold(len(operators))
	n.logger.Sugar().Infow("Starting reshare", "operator_address", n.OperatorAddress.Hex(), "threshold", newThreshold, "operators", len(operators))

	// Create reshare instance with current operators
	n.resharer = reshare.NewReshare(n.OperatorAddress, operators)

	// Get current share and the version we are dealing FROM. All finalized dealers must
	// deal from the same source version or the refreshed shares won't descend from one
	// polynomial (docs/012 Layer 2); we advertise this version in our commitment broadcast.
	//
	// We deal from our LOCAL active share (GetActivePrivateShare) and TELL everyone which
	// version that is (sourceVersion). We deliberately do NOT fetch a specific version via
	// keystore.GetPrivateShareForVersion here: a node always deals its own current share and
	// lets the cluster reconcile at finalize. If this node is a laggard, SelectMajoritySource-
	// Version drops it from the dealer set (its stale-version commitment loses the majority),
	// and it re-derives its refreshed share purely as a RECIPIENT of the kept dealers — it
	// never needs to look up a historical share to deal. GetPrivateShareForVersion exists as
	// a guarded accessor for that potential future dealing path and for debugging; the
	// current design closes the laggard case via recipient-side reconciliation instead.
	currentShare, err := n.keyStore.GetActivePrivateShare()
	if err != nil {
		return err
	}
	// sourceVersion is always set here: GetActivePrivateShare above already errored out if
	// there were no active version, so GetActiveVersion is non-nil.
	sourceVersion := n.keyStore.GetActiveVersion().Version

	// Phase 1: Generate dealer polynomials anchored at each dealer's current share.
	// Each dealer i samples f_i with f_i(0)=x_i and broadcasts commitments + per-recipient shares.
	// Recipients then combine received shares via Lagrange to derive a refreshed share of the same
	// master secret. This works for both existing and newly joining operators.
	shares, commitments, err := n.resharer.GenerateNewShares(currentShare, newThreshold)
	if err != nil {
		return err
	}

	session, err := n.createSession("reshare", operators, sessionTimestamp)
	if err != nil {
		return fmt.Errorf("failed to create reshare session: %w", err)
	}
	session.TriggerBlockNumber = triggerBlock
	defer n.cleanupSession(session.SessionTimestamp)

	// Persist initial session state
	if err := n.saveSession(session); err != nil {
		n.logger.Sugar().Warnw("Failed to persist initial reshare session",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
	}

	// Store own share and commitment BEFORE broadcasting to other nodes.
	// This prevents a race where a fast peer receives our commitment, verifies,
	// and sends an ack back before we've stored our own commitment in the
	// session — causing verifyAcknowledgement to reject the ack with
	// "dealer commitments unavailable".
	_ = session.HandleReceivedShare(n.OperatorAddress, shares[n.OperatorAddress])
	_ = session.HandleReceivedCommitment(n.OperatorAddress, commitments, sourceVersion)

	// Broadcast commitments (advertising the source version we dealt from)
	if err := n.transport.BroadcastReshareCommitments(operators, commitments, session.SessionTimestamp, sourceVersion); err != nil {
		n.logger.Sugar().Errorw("Failed to broadcast reshare commitments", "operator_address", n.OperatorAddress.Hex(), "error", err)
		// Continue anyway - other nodes may have received
	}

	// Retain the shares we generated as a dealer so we can re-serve any of them to a
	// peer that missed our original send (see on-demand share fetch during finalize).
	session.SetMyGeneratedShares(shares)
	// Also retain at the node level, keyed by session, so we can still serve an on-demand
	// fetch AFTER this session is torn down on completion (docs/012 Layer 3a). This is the
	// fix for the live incident's 503 trigger: a lagging peer fetching our share after we
	// finished the round must succeed, not abort.
	n.retainGeneratedShares(session.SessionTimestamp, shares)

	// Send shares to all operators
	for _, op := range operators {

		if op.OperatorAddress == n.OperatorAddress {
			continue // Already stored above
		}
		if err := n.transport.SendReshareShare(op, shares[op.OperatorAddress], session.SessionTimestamp); err != nil {
			n.logger.Sugar().Warnw("Failed to send reshare share to operator",
				"operator_address", n.OperatorAddress.Hex(),
				"target", op.OperatorAddress.Hex(),
				"error", err)
			// Continue with other operators
		}
	}

	// Build set of operator IDs from the on-chain operator set.
	// All operators registered on-chain are legitimate dealers; polynomial
	// commitment verification (below) guards against invalid shares.
	// Using ParticipantIDs from activeVersion would exclude operators that
	// missed a previous reshare, permanently orphaning them from the quorum.
	onChainOpIDs := make(map[common.Address]bool, len(operators))
	for _, op := range operators {
		onChainOpIDs[op.OperatorAddress] = true
	}

	// Wait for shares and commitments. New operators (running RunReshareAsNewOperator) do not
	// contribute shares, so only existing operators can contribute. We require a threshold of
	// those existing operators rather than all of them, so resharing can proceed even if some
	// existing operators are offline (per KMS-010 recommendation).
	// Count functions filter to on-chain operators so that shares/commitments from new
	// operators do not inflate the count toward the threshold.
	protocolTimeout := config.GetProtocolTimeoutForChain(n.ChainID)
	existingOperators := len(operators) - numNewOperators
	requiredContributions := dkg.CalculateThreshold(existingOperators)
	countOnChainShares := func() int {
		count := 0
		for addr := range session.shares {
			if onChainOpIDs[addr] {
				count++
			}
		}
		return count
	}
	countOnChainCommitments := func() int {
		count := 0
		for addr := range session.commitments {
			if onChainOpIDs[addr] {
				count++
			}
		}
		return count
	}
	if err := waitForN(session, requiredContributions, protocolTimeout, countOnChainShares, "shares"); err != nil {
		return err
	}
	if err := waitForN(session, requiredContributions, protocolTimeout, countOnChainCommitments, "commitments"); err != nil {
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
		"operator_address", n.OperatorAddress.Hex())

	// Copy shares and commitments from session under lock, filtering to on-chain operators only.
	// After threshold fallback, late-arriving shares may still be written concurrently.
	session.mu.RLock()
	receivedShares := make(map[common.Address]*fr.Element)
	for addr, s := range session.shares {
		if onChainOpIDs[addr] {
			receivedShares[addr] = s
		}
	}
	receivedCommitments := make(map[common.Address][]types.G2Point)
	for addr, c := range session.commitments {
		if onChainOpIDs[addr] {
			receivedCommitments[addr] = c
		}
	}
	session.mu.RUnlock()

	validShares := make(map[common.Address]*fr.Element)
	invalidDealers := make([]common.Address, 0)
	for dealerAddr, share := range receivedShares {
		commitments := receivedCommitments[dealerAddr]
		if n.resharer.VerifyNewShare(share, commitments) {
			validShares[dealerAddr] = share

			// Skip sending ack to self — a dealer does not need to ack its own share.
			if dealerAddr == n.OperatorAddress {
				n.logger.Sugar().Debugw("Skipping self-ack for reshare", "operator_address", n.OperatorAddress.Hex(), "dealer_address", dealerAddr.Hex())
				continue
			}

			// Find dealer's peer info for transport
			var dealerPeer *peering.OperatorSetPeer
			for _, op := range operators {
				if op.OperatorAddress == dealerAddr {
					dealerPeer = op
					break
				}
			}

			if dealerPeer == nil {
				continue
			}

			// Create acknowledgement for verified share using operator addresses
			ack := eigenxcrypto.CreateAcknowledgement(n.OperatorAddress, dealerPeer.OperatorAddress, sessionTimestamp, share, commitments, n.signAcknowledgement)

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
					"dealer_address", dealerAddr.Hex())
			}

			n.logger.Sugar().Infow("Verified and acked reshare share",
				"operator_address", n.OperatorAddress.Hex(),
				"dealer_address", dealerAddr.Hex())
		} else {
			n.logInvalidShareComplaint("reshare", sessionTimestamp, n.OperatorAddress, dealerAddr, share, commitments)
			invalidDealers = append(invalidDealers, dealerAddr)
		}
	}

	// Remove invalid shares from session so they are excluded from participant
	// selection and delta computation. Without this, an operator sending an
	// invalid share would still be included in session.shares and corrupt the
	// new key share.
	if len(invalidDealers) > 0 {
		session.mu.Lock()
		for _, id := range invalidDealers {
			delete(session.shares, id)
		}
		session.mu.Unlock()
	}

	// Wait for acknowledgements (as a dealer).
	// We require newThreshold acks so that at least t operators in the new committee have
	// confirmed receipt of this dealer's contribution. Both existing and new operators send
	// acks, so the reachable ack count is len(operators)-1 (everyone except this dealer).

	requiredAcks := newThreshold
	if requiredAcks < 0 {
		requiredAcks = 0
	}
	if err := waitForAcks(session, n.OperatorAddress, requiredAcks, protocolTimeout); err != nil {
		// Threshold fallback: check if we have at least threshold-1 acks
		session.mu.RLock()
		ackMap := session.acks[n.OperatorAddress]
		received := 0
		if ackMap != nil {
			received = len(ackMap)
		}
		session.mu.RUnlock()
		fallbackRequired := requiredAcks - 1
		if fallbackRequired < 1 {
			fallbackRequired = 1
		}
		if received >= fallbackRequired {
			n.logger.Sugar().Warnw("Not all acks received but fallback threshold met, proceeding",
				"received", received, "required", requiredAcks, "fallback", fallbackRequired,
				"total_operators", len(operators))
		} else {
			return fmt.Errorf("insufficient reshare acknowledgements: %v", err)
		}
	}

	// Phase 2: Build Merkle Tree and Submit to Contract
	n.logger.Sugar().Infow("Reshare Phase 2: Building merkle tree and submitting to contract",
		"operator_address", n.OperatorAddress.Hex(),
		"session", session.SessionTimestamp)

	// Collect acknowledgements from session where I am the dealer
	session.mu.RLock()
	myAcks := make([]*types.Acknowledgement, 0)
	if ackMap, ok := session.acks[n.OperatorAddress]; ok {
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
	myCommitments, ok := session.commitments[n.OperatorAddress]
	session.mu.RUnlock()
	if !ok {
		return fmt.Errorf("my commitments not found in reshare")
	}

	// The ON-CHAIN submitted hash for reshare binds the source version (docs/013 Change 2),
	// so every node can verify each dealer's P2P-advertised SourceVersion against shared
	// registry state at finalize. This is intentionally NOT the ack/merkle hash: the ack
	// subsystem (merkle tree + ack signatures) keeps using the plain HashCommitment, and
	// nothing compares the two, so they are free to diverge.
	onChainCommitmentHash := eigenxcrypto.HashReshareCommitment(myCommitments, sourceVersion)

	n.logger.Sugar().Infow("Merkle tree built successfully in reshare",
		"num_acks", len(myAcks),
		"merkle_root", fmt.Sprintf("0x%x", merkleTree.Root))

	// Submit to contract with retry logic
	err = n.submitCommitmentWithRetry(ctx, session.SessionTimestamp, onChainCommitmentHash, merkleTree.Root)
	if err != nil {
		return fmt.Errorf("failed to submit commitment in reshare after retries: %w", err)
	}

	n.logger.Sugar().Infow("Commitment submitted to Base contract successfully in reshare",
		"commitment_hash", fmt.Sprintf("0x%x", onChainCommitmentHash),
		"source_version", sourceVersion,
		"merkle_root", fmt.Sprintf("0x%x", merkleTree.Root))

	// Store in session. myAckCommitmentHash holds the PLAIN hash (ack/merkle domain); the
	// on-chain submission above used HashReshareCommitment (source-version-bound), so the two
	// intentionally differ for reshare — see the field doc.
	session.mu.Lock()
	session.myAckMerkleTree = merkleTree
	session.myAckCommitmentHash = eigenxcrypto.HashCommitment(myCommitments)
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
		"operator_address", n.OperatorAddress.Hex())

	err = n.WaitForVerifications(session.SessionTimestamp, protocolTimeout)
	if err != nil {
		n.logger.Sugar().Warnw("Verification phase incomplete in reshare", "error", err)
		// Continue - not fatal, verification is optional
	} else {
		n.logger.Sugar().Infow("All operator broadcasts verified successfully in reshare")
	}

	// Phase 5: Finalize reshare
	n.logger.Sugar().Infow("Reshare Phase 5: Finalizing key share",
		"operator_address", n.OperatorAddress.Hex())

	// Build trusted dealer set: intersection of polynomial-verified shares and merkle-verified operators.
	// Self is always trusted (a node doesn't verify its own broadcast).
	session.mu.RLock()
	verifiedOps := make(map[common.Address]bool, len(session.verifiedOperators))
	for k, v := range session.verifiedOperators {
		verifiedOps[k] = v
	}
	session.mu.RUnlock()
	verifiedOps[n.OperatorAddress] = true

	trustedShares := trustedDealerIDs(validShares, verifiedOps)

	n.logger.Sugar().Infow("Dealer filtering for reshare finalization",
		"total_received", len(receivedShares),
		"polynomial_verified", len(validShares),
		"merkle_verified", len(verifiedOps),
		"trusted_dealers", len(trustedShares))

	// CRITICAL CORRECTNESS INVARIANT: every operator MUST finalize on the IDENTICAL
	// dealer set. ComputeNewKeyShare reconstructs each refreshed share via Lagrange
	// interpolation over the dealer set, and the coefficients depend on WHICH dealers
	// are in it. If operators finalize on different sets (e.g. one is briefly partitioned
	// and misses a dealer before its peers do) they land on different polynomials, their
	// refreshed shares become mutually inconsistent, no threshold subset recovers a
	// consistent app key (every decrypt fails "all combinations exhausted"), and
	// Σcommitments[0] diverges from the served MasterPublicKey. A single mixed-set round
	// permanently poisons the cluster (verified empirically + by real-code simulation).
	//
	// To force agreement, we derive the dealer set from SHARED on-chain state rather than
	// each node's local receipt timing: D = operators that submitted a commitment for
	// this epoch in the registry. See docs/011_reshareDealerSetAgreement.md.
	//
	// We read at L2 HEAD (pinnedBlock = 0), NOT session.TriggerBlockNumber. The trigger
	// block is an Ethereum L1 block number, but the commitment registry lives on Base
	// (L2) — the two block-number spaces are unrelated, so pinning the L2 read to an L1
	// height would query Base at a wildly wrong (years-old) height and return empty,
	// aborting every reshare. Head reads + the convergence/abort-retry below give
	// agreement without a pinned height. session.TriggerBlockNumber is retained for when
	// a real L2 block feed is plumbed; until then it must NOT be used as the read height.
	agreedDealers, onChainHashes, err := n.deriveAgreedDealerSet(ctx, operators, session.SessionTimestamp, 0)
	if err != nil {
		return fmt.Errorf("failed to derive agreed dealer set: %w", err)
	}
	if len(agreedDealers) < newThreshold {
		return fmt.Errorf("agreed dealer set too small: got %d on-chain submitters, need %d; will retry next interval",
			len(agreedDealers), newThreshold)
	}

	// SOURCE-VERSION VERIFICATION (docs/013 Change 2). For each on-chain-agreed dealer,
	// recompute HashReshareCommitment(its P2P commitments, its P2P-advertised SourceVersion)
	// and require it to equal the dealer's ON-CHAIN commitment hash. This binds the source
	// version to shared, append-only registry state: a dealer cannot advertise a version
	// over P2P that differs from the one it committed on-chain (equivocation is rejected),
	// and a dealer whose commitments/version we haven't received yet is dropped from the
	// tally universe — but only after this verification, so the version we DO tally on is
	// cryptographically bound, not an unauthenticated P2P value. Dealers that fail
	// verification are excluded here; the source-version selection below runs over the
	// VERIFIED subset, so all honest nodes compute over identical shared data.
	observedSourceVersions := session.GetSourceVersions()
	commitmentsByDealer := make(map[common.Address][]types.G2Point, len(agreedDealers))
	for _, dealer := range agreedDealers {
		commitmentsByDealer[dealer] = session.GetCommitmentsFor(dealer)
	}
	verifiedDealers, verifiedSourceVersions := reshare.VerifyDealerSourceVersions(
		agreedDealers, onChainHashes, commitmentsByDealer, observedSourceVersions)
	if len(verifiedDealers) < newThreshold {
		return fmt.Errorf("verified reshare dealer set too small: %d of %d on-chain submitters verified, need %d; will retry next interval",
			len(verifiedDealers), len(agreedDealers), newThreshold)
	}

	// SOURCE-VERSION AGREEMENT (docs/013 Change 3). Keep only dealers on the winning source
	// version (highest version with >= threshold verified submitters). Because the tally
	// runs over the on-chain-VERIFIED versions above, every honest node computes it over
	// identical shared data and selects the identical kept set (restoring the docs/011
	// identical-D invariant). An excluded laggard still recomputes its own refreshed share
	// as a recipient of the kept dealers, resyncing implicitly.
	agreedDealers, srcVersion, err := reshare.SelectMajoritySourceVersion(
		verifiedDealers, verifiedSourceVersions, newThreshold)
	if err != nil {
		n.logger.Sugar().Warnw("Aborting reshare finalize: no source-version-agreed dealer set",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
		return fmt.Errorf("reshare aborted: %w; will retry next interval", err)
	}
	// Observability: SelectMajoritySourceVersion picks the highest version with >= threshold
	// support, not necessarily the newest present. If the winning version is behind the
	// newest verified one (e.g. 2 of 3 nodes both missed the last round), the cluster
	// correctly finalizes on that older version — surface it so operators don't misread a
	// "regression" to a lower version as a fault.
	var maxObserved int64
	for _, v := range verifiedSourceVersions {
		if v > maxObserved {
			maxObserved = v
		}
	}
	if srcVersion < maxObserved {
		n.logger.Sugar().Infow("Reshare source-version majority is behind the newest observed version (expected under a shared lag; not a fault)",
			"operator_address", n.OperatorAddress.Hex(),
			"chosen_source_version", srcVersion,
			"max_observed_version", maxObserved)
	}

	// Ensure we hold a verified share from every dealer in D. For any we are missing
	// (we were lagging / dropped that send), fetch it on demand from the dealer and
	// verify it with the same polynomial-commitment check as the push path. If we still
	// cannot obtain+verify a dealer in D, ABORT and retry — we must not finalize on a set
	// different from D.
	participantIDsForFinalize := make([]common.Address, 0, len(agreedDealers))
	finalShares := make(map[common.Address]*fr.Element, len(agreedDealers))
	for _, dealer := range agreedDealers {
		if share, ok := trustedShares[dealer]; ok {
			participantIDsForFinalize = append(participantIDsForFinalize, dealer)
			finalShares[dealer] = share
			continue
		}
		// Missing locally — fetch on demand.
		share, ferr := n.fetchAndVerifyReshareShare(session, dealer)
		if ferr != nil {
			n.logger.Sugar().Warnw("Aborting reshare finalize: could not obtain a dealer in the agreed set",
				"operator_address", n.OperatorAddress.Hex(),
				"missing_dealer", dealer.Hex(),
				"agreed_dealers", len(agreedDealers),
				"error", ferr)
			return fmt.Errorf("reshare aborted: missing verified share for agreed dealer %s: %w; will retry next interval",
				dealer.Hex(), ferr)
		}
		participantIDsForFinalize = append(participantIDsForFinalize, dealer)
		finalShares[dealer] = share
	}

	// srcVersion is logged for observability only; the refreshed share is computed from each
	// dealer's already-received share below, not re-fetched by version. srcVersion's role is
	// upstream — SelectMajoritySourceVersion used it to pick participantIDsForFinalize.
	n.logger.Sugar().Infow("Finalizing reshare on agreed dealer set",
		"operator_address", n.OperatorAddress.Hex(),
		"agreed_dealers", len(participantIDsForFinalize),
		"source_version", srcVersion,
		"pinned_block", session.TriggerBlockNumber)

	// Compute refreshed share using the same Lagrange reconstruction as the new-operator path.
	newKeyVersion, err := n.resharer.ComputeNewKeyShare(participantIDsForFinalize, finalShares, nil)
	if err != nil {
		return fmt.Errorf("failed to compute refreshed key share: %w", err)
	}
	if newKeyVersion == nil {
		return fmt.Errorf("failed to compute refreshed key share: resharer returned nil key version")
	}
	newKeyVersion.Version = sessionTimestamp
	newKeyVersion.IsActive = true
	// ParticipantIDs is the set of share HOLDERS (full session operator set), NOT the dealer
	// subset that reconstructed this round. Every operator recomputes its own share, so all
	// hold a share of S; storing the dealer subset here shrinks the next round's expected
	// dealer set per-node and freezes a version split (docs/013 Change 1).
	newKeyVersion.ParticipantIDs = sessionParticipantIDs(operators)

	// Carry forward MPK from the current active version (MPK doesn't change during reshare).
	// A non-nil active version with a nil MPK must NOT silently skip Layer 1: that would both
	// leave a source-version split undetected AND carry a nil MPK forward, making the nil
	// sticky so every subsequent reshare also skips validation. Abort loudly instead. (The
	// activeVersion == nil case is genesis with no MPK to validate against — handled below by
	// leaving newKeyVersion.MasterPublicKey nil and skipping validation.)
	if currentVersion := n.keyStore.GetActiveVersion(); currentVersion != nil {
		if currentVersion.MasterPublicKey == nil {
			return fmt.Errorf("reshare aborted: active version %d has nil MasterPublicKey; cannot validate reshare (check DKG log for a commitments error); will retry next interval",
				currentVersion.Version)
		}
		mpkCopy := *currentVersion.MasterPublicKey
		newKeyVersion.MasterPublicKey = &mpkCopy

		// VALIDATE BEFORE COMMIT (docs/011 § step 5, docs/012 Layer 1). Recompute the
		// group public key implied by the agreed dealers' commitments and require it to
		// equal the carried-forward MPK. If any dealer dealt from a mismatched source
		// share (a cross-round version split) or the dealer sets diverged, the refreshed
		// shares would not reconstruct the served MPK — decrypt would fail cluster-wide
		// with "all combinations exhausted" and the corruption would be permanent. Abort
		// loudly and retry next interval instead of persisting a poisoned share.
		mpkCommitmentsByDealer := make(map[common.Address][]types.G2Point, len(participantIDsForFinalize))
		for _, dealer := range participantIDsForFinalize {
			mpkCommitmentsByDealer[dealer] = session.GetCommitmentsFor(dealer)
		}
		if verr := reshare.ValidateReshareMasterPublicKey(participantIDsForFinalize, mpkCommitmentsByDealer, &mpkCopy); verr != nil {
			n.logger.Sugar().Errorw("ABORTING reshare finalize: post-reshare MPK validation failed",
				"operator_address", n.OperatorAddress.Hex(),
				"agreed_dealers", len(participantIDsForFinalize),
				"new_version", newKeyVersion.Version,
				"error", verr)
			return fmt.Errorf("reshare aborted: post-reshare MPK validation failed: %w; will retry next interval", verr)
		}
	}

	// Persist new key version BEFORE adding to keystore
	// This ensures we fail if persistence fails, preventing state inconsistency
	if err := n.persistence.SaveKeyShareVersion(newKeyVersion); err != nil {
		n.logger.Sugar().Errorw("Failed to persist reshare key share version - reshare cannot complete",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
		return fmt.Errorf("failed to persist reshare key share version: %w", err)
	}

	// Update active version pointer
	if err := n.persistence.SetActiveVersionTimestamp(newKeyVersion.Version); err != nil {
		n.logger.Sugar().Errorw("Failed to persist active version pointer - reshare cannot complete",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
		return fmt.Errorf("failed to persist active version pointer: %w", err)
	}

	// Only add to keystore after successful persistence
	n.keyStore.AddVersion(newKeyVersion)

	n.logger.Sugar().Infow("Reshare completed", "operator_address", n.OperatorAddress.Hex(), "new_version", newKeyVersion.Version)

	return nil
}

// RunReshareAsNewOperator executes reshare protocol as a new operator (no existing shares).
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

	// Build set of existing operator IDs by querying /pubkey endpoints.
	// Only existing operators hold valid key shares to redistribute;
	// new operators could maliciously send shares and commitments.
	existingOpIDs := make(map[common.Address]bool)
	if n.transport != nil {
		for _, op := range operators {
			commitments, err := n.transport.QueryOperatorPubkey(op)
			if err != nil {
				n.logger.Sugar().Warnw("Could not query operator pubkey; treating as new operator",
					"operator_address", n.OperatorAddress.Hex(),
					"peer", op.OperatorAddress.Hex(),
					"error", err)
			} else if len(commitments) > 0 {
				existingOpIDs[op.OperatorAddress] = true
			}
		}
	} else {
		n.logger.Sugar().Warnw("No transport available; treating all operators as new",
			"operator_address", n.OperatorAddress.Hex(),
			"count", len(operators))
	}

	// The caller (self) is always one of the new operators, so the minimum valid
	// value is 1; 0 would require all N operators to contribute which deadlocks
	// since this node never sends shares.
	numNewOperators := len(operators) - len(existingOpIDs)
	if numNewOperators < 1 || numNewOperators >= len(operators) {
		return fmt.Errorf("numNewOperators %d out of range [1, %d)", numNewOperators, len(operators))
	}

	// Create reshare instance
	n.resharer = reshare.NewReshare(n.OperatorAddress, operators)

	// Create session for this reshare (as recipient only)
	session, err := n.createSession("reshare", operators, sessionTimestamp)
	if err != nil {
		return fmt.Errorf("failed to create reshare session: %w", err)
	}
	defer n.cleanupSession(session.SessionTimestamp)

	// Persist initial session state
	if err := n.saveSession(session); err != nil {
		n.logger.Sugar().Warnw("Failed to persist initial reshare session (new operator)",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
	}

	// New operators DON'T generate shares - only receive from existing operators.
	// We require a threshold of existing operators rather than all of them, so resharing
	// can proceed even if some existing operators are offline (per KMS-010 recommendation).
	existingOperators := len(operators) - numNewOperators
	requiredContributions := dkg.CalculateThreshold(existingOperators)
	n.logger.Sugar().Infow("Waiting for shares from existing operators",
		"operator_address", n.OperatorAddress.Hex(),
		"existing_operators", existingOperators,
		"expected_shares", requiredContributions)

	// Count functions filter to existing operators only so that shares/commitments from new
	// operators do not inflate the count toward the threshold.
	protocolTimeout := config.GetProtocolTimeoutForChain(n.ChainID)
	countExistingShares := func() int {
		count := 0
		for addr := range session.shares {
			if existingOpIDs[addr] {
				count++
			}
		}
		return count
	}
	countExistingCommitments := func() int {
		count := 0
		for addr := range session.commitments {
			if existingOpIDs[addr] {
				count++
			}
		}
		return count
	}
	if err := waitForN(session, requiredContributions, protocolTimeout, countExistingShares, "shares"); err != nil {
		return fmt.Errorf("failed to receive shares: %w", err)
	}
	if err := waitForN(session, requiredContributions, protocolTimeout, countExistingCommitments, "commitments"); err != nil {
		return fmt.Errorf("failed to receive commitments: %w", err)
	}

	// Copy shares and commitments from session under lock, filtering to existing operators only.
	// After threshold fallback, late-arriving shares may still be written concurrently.
	session.mu.RLock()
	receivedShares := make(map[common.Address]*fr.Element)
	for addr, s := range session.shares {
		if existingOpIDs[addr] {
			receivedShares[addr] = s
		}
	}
	receivedCommitments := make(map[common.Address][]types.G2Point)
	for addr, c := range session.commitments {
		if existingOpIDs[addr] {
			receivedCommitments[addr] = c
		}
	}
	session.mu.RUnlock()

	// Verify all dealer shares and send acknowledgements to prevent dealer equivocation.
	validShares := make(map[common.Address]*fr.Element)
	for _, op := range operators {
		dealerAddr := op.OperatorAddress
		share, hasShare := receivedShares[dealerAddr]
		commitments, hasCommitments := receivedCommitments[dealerAddr]
		if !hasShare || share == nil || !hasCommitments || len(commitments) == 0 {
			continue
		}
		if n.resharer.VerifyNewShare(share, commitments) {
			validShares[dealerAddr] = share

			// Create acknowledgement for verified share using operator addresses
			ack := eigenxcrypto.CreateAcknowledgement(n.OperatorAddress, op.OperatorAddress, sessionTimestamp, share, commitments, n.signAcknowledgement)

			// Send acknowledgement to dealer
			err := n.transport.SendReshareAcknowledgement(ack, op, session.SessionTimestamp)
			if err != nil {
				n.logger.Sugar().Warnw("Failed to send reshare acknowledgement (new operator)",
					"operator_address", n.OperatorAddress.Hex(),
					"dealer_address", op.OperatorAddress.Hex(),
					"error", err)
			} else {
				n.logger.Sugar().Debugw("Sent reshare acknowledgement (new operator)",
					"operator_address", n.OperatorAddress.Hex(),
					"dealer_address", dealerAddr.Hex())
			}

			n.logger.Sugar().Infow("Verified and acked reshare share (new operator)",
				"operator_address", n.OperatorAddress.Hex(),
				"dealer_address", dealerAddr.Hex())
		} else {
			n.logInvalidShareComplaint("reshare-new-operator", sessionTimestamp, n.OperatorAddress, dealerAddr, share, commitments)
		}
	}

	// Wait for dealer commitment broadcasts (merkle tree verification)
	n.logger.Sugar().Infow("Reshare (new operator): Waiting for operator commitment broadcasts",
		"operator_address", n.OperatorAddress.Hex(),
		"expected_verifications", len(operators)-1)

	err = n.WaitForVerifications(session.SessionTimestamp, protocolTimeout)
	if err != nil {
		n.logger.Sugar().Warnw("Verification phase incomplete in reshare (new operator)", "error", err)
	} else {
		n.logger.Sugar().Infow("All operator broadcasts verified successfully in reshare (new operator)")
	}

	// Build trusted dealer set: intersection of polynomial-verified shares and merkle-verified operators.
	session.mu.RLock()
	verifiedOps := make(map[common.Address]bool, len(session.verifiedOperators))
	for k, v := range session.verifiedOperators {
		verifiedOps[k] = v
	}
	session.mu.RUnlock()

	trustedShares := trustedDealerIDs(validShares, verifiedOps)

	n.logger.Sugar().Infow("Dealer filtering for new operator reshare finalization",
		"total_received", len(receivedShares),
		"polynomial_verified", len(validShares),
		"merkle_verified", len(verifiedOps),
		"trusted_dealers", len(trustedShares))

	// AGREE on the dealer set from shared on-chain state, exactly as the existing-operator
	// path does (docs/013). A new operator MUST finalize on the IDENTICAL dealer set D as
	// everyone else, or its ComputeNewKeyShare interpolates over a different D and produces a
	// share inconsistent with the cluster (Bug 2 on the join path). We derive D from the
	// registry, verify each dealer's source version against its on-chain commitment hash, and
	// select the agreed source-version subset — then finalize on exactly that set.
	requiredShares := dkg.CalculateThreshold(len(operators))
	agreedDealers, onChainHashes, err := n.deriveAgreedDealerSet(ctx, operators, session.SessionTimestamp, 0)
	if err != nil {
		return fmt.Errorf("failed to derive agreed dealer set (new operator): %w", err)
	}
	observedSourceVersions := session.GetSourceVersions()
	commitmentsByDealer := make(map[common.Address][]types.G2Point, len(agreedDealers))
	for _, dealer := range agreedDealers {
		commitmentsByDealer[dealer] = session.GetCommitmentsFor(dealer)
	}
	verifiedDealers, verifiedSourceVersions := reshare.VerifyDealerSourceVersions(
		agreedDealers, onChainHashes, commitmentsByDealer, observedSourceVersions)
	// Explicit pre-check symmetric with the existing-operator path (surfaces verified-vs-agreed
	// counts for ops triage of join failures) before SelectMajoritySourceVersion's own guard.
	if len(verifiedDealers) < requiredShares {
		return fmt.Errorf("verified reshare dealer set too small (new operator): %d of %d on-chain submitters verified, need %d; will retry next interval",
			len(verifiedDealers), len(agreedDealers), requiredShares)
	}
	agreedDealers, agreedSrcVersion, err := reshare.SelectMajoritySourceVersion(verifiedDealers, verifiedSourceVersions, requiredShares)
	if err != nil {
		n.logger.Sugar().Warnw("Aborting new-operator reshare finalize: no source-version-agreed dealer set",
			"operator_address", n.OperatorAddress.Hex(), "error", err)
		return fmt.Errorf("new-operator reshare aborted: %w; will retry next interval", err)
	}

	// Assemble finalize shares from the agreed dealer set. Every agreed dealer must have a
	// share; if one is missing locally (a joining node is especially likely to have missed
	// the initial push window), fetch it on demand and verify it — mirroring the
	// existing-operator path — before aborting. Only abort if it still can't be obtained.
	participantIDs := make([]common.Address, 0, len(agreedDealers))
	finalShares := make(map[common.Address]*fr.Element, len(agreedDealers))
	for _, dealer := range agreedDealers {
		if share, ok := trustedShares[dealer]; ok {
			participantIDs = append(participantIDs, dealer)
			finalShares[dealer] = share
			continue
		}
		share, ferr := n.fetchAndVerifyReshareShare(session, dealer)
		if ferr != nil {
			n.logger.Sugar().Warnw("Aborting new-operator reshare finalize: could not obtain a dealer in the agreed set",
				"operator_address", n.OperatorAddress.Hex(), "missing_dealer", dealer.Hex(), "error", ferr)
			return fmt.Errorf("new-operator reshare aborted: missing verified share for agreed dealer %s: %w; will retry next interval", dealer.Hex(), ferr)
		}
		participantIDs = append(participantIDs, dealer)
		finalShares[dealer] = share
	}

	n.logger.Sugar().Infow("Finalizing new-operator reshare on agreed dealer set",
		"operator_address", n.OperatorAddress.Hex(),
		"agreed_dealers", len(participantIDs),
		"source_version", agreedSrcVersion)

	if len(participantIDs) < requiredShares {
		return fmt.Errorf("insufficient verified shares for new-operator finalize: got %d, need %d", len(participantIDs), requiredShares)
	}

	// Compute new key share using verified dealer shares only.
	newKeyVersion, err := n.resharer.ComputeNewKeyShare(participantIDs, finalShares, nil)
	if err != nil {
		return fmt.Errorf("failed to compute new operator key share: %w", err)
	}
	if newKeyVersion == nil {
		return fmt.Errorf("failed to compute new operator key share: resharer returned nil key version")
	}
	newKeyVersion.Version = sessionTimestamp // Use session timestamp as version
	newKeyVersion.IsActive = true            // First key version becomes active immediately
	// Record the full session operator set as share holders, not the dealer subset that
	// ComputeNewKeyShare defaulted to (docs/013 Change 1) — keeps the next round's expected
	// dealer set stable across nodes.
	newKeyVersion.ParticipantIDs = sessionParticipantIDs(operators)

	// Fetch MPK from existing operators using threshold agreement
	// New operators cannot derive the MPK from reshare protocol data alone
	mpk, err := n.fetchMPKFromPeers(ctx, operators)
	if err != nil {
		n.logger.Sugar().Warnw("Failed to fetch MPK from peers during new operator join - this operator will not contribute to client MPK threshold agreement until next reshare or restart",
			"error", err)
	} else {
		newKeyVersion.MasterPublicKey = mpk
	}

	// Persist first key version BEFORE adding to keystore (critical for new operator)
	// This ensures we fail if persistence fails, preventing state inconsistency
	if err := n.persistence.SaveKeyShareVersion(newKeyVersion); err != nil {
		n.logger.Sugar().Errorw("Failed to persist first key share version - cannot join cluster",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
		return fmt.Errorf("failed to persist first key share version: %w", err)
	}

	// Set as active version
	if err := n.persistence.SetActiveVersionTimestamp(newKeyVersion.Version); err != nil {
		n.logger.Sugar().Errorw("Failed to persist active version pointer - cannot join cluster",
			"operator_address", n.OperatorAddress.Hex(),
			"error", err)
		return fmt.Errorf("failed to persist active version pointer: %w", err)
	}

	// Only add to keystore after successful persistence
	n.keyStore.AddVersion(newKeyVersion)

	n.logger.Sugar().Infow("Successfully joined cluster via reshare",
		"operator_address", n.OperatorAddress.Hex(),
		"version", newKeyVersion.Version)

	return nil
}

// signAppIDWithVersion computes a partial BLS signature for appID using a pre-resolved key version.
func (n *Node) signAppIDWithVersion(appID string, keyVersion *types.KeyShareVersion) (types.G1Point, error) {
	if keyVersion == nil || keyVersion.PrivateShare == nil {
		return types.G1Point{}, fmt.Errorf("no private share available")
	}

	privateShare := new(fr.Element).Set(keyVersion.PrivateShare)
	qID, err := eigenxcrypto.HashToG1(appID)
	if err != nil {
		return types.G1Point{}, fmt.Errorf("HashToG1 failed: %w", err)
	}
	partialSig, err := eigenxcrypto.ScalarMulG1(*qID, privateShare)
	if err != nil {
		return types.G1Point{}, fmt.Errorf("ScalarMulG1 failed: %w", err)
	}
	return *partialSig, nil
}

// SignAppID signs an application ID using the key version active at attestationTime.
// attestationTime == 0 means "use the currently active version".
func (n *Node) SignAppID(appID string, attestationTime int64) (types.G1Point, error) {
	var keyVersion *types.KeyShareVersion
	if attestationTime > 0 {
		keyVersion = n.keyStore.GetKeyVersionAtTime(attestationTime)
		if keyVersion == nil {
			return types.G1Point{}, fmt.Errorf("no key version found for attestation time %d", attestationTime)
		}
	} else {
		keyVersion = n.keyStore.GetActiveVersion()
	}
	return n.signAppIDWithVersion(appID, keyVersion)
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

// waitForN polls until getCount() returns at least required, or the timeout elapses.
// getCount is called while session.mu.RLock is held.
func waitForN(session *ProtocolSession, required int, timeout time.Duration, getCount func() int, label string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	maxPossible := len(session.Operators)
	if required < 0 {
		required = 0
	}
	if required > maxPossible {
		required = maxPossible
	}

	if required == 0 {
		return nil
	}

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			session.mu.RLock()
			received := getCount()
			session.mu.RUnlock()
			return fmt.Errorf("timeout waiting for %s: got %d/%d", label, received, required)

		case <-ticker.C:
			session.mu.RLock()
			received := getCount()
			session.mu.RUnlock()

			if received >= required {
				return nil
			}
		}
	}
}

// waitForNShares waits for at least required shares using polling.
// Use this instead of waitForShares when fewer than all operators are expected to contribute
// (e.g., new operators joining don't send shares, so existing operators wait for N-numNew shares).
func waitForNShares(session *ProtocolSession, required int, timeout time.Duration) error {
	return waitForN(session, required, timeout, func() int { return len(session.shares) }, "shares")
}

// waitForNCommitments waits for at least required commitments using polling.
// Use this instead of waitForCommitments when fewer than all operators are expected to contribute
// (e.g., new operators joining don't broadcast commitments).
func waitForNCommitments(session *ProtocolSession, required int, timeout time.Duration) error {
	return waitForN(session, required, timeout, func() int { return len(session.commitments) }, "commitments")
}

// waitForAcks waits for at least required acknowledgements to be received for a specific dealer using polling.
// Note: We poll instead of using acksCompleteChan because the channel signals when ANY dealer
// completes, not when THIS specific dealer completes. Each dealer needs to wait for their own acks.
func waitForAcks(session *ProtocolSession, dealer common.Address, required int, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Clamp required to a sensible range.
	maxPossible := len(session.Operators) - 1 // All operators except dealer itself
	if required < 0 {
		required = 0
	}
	if required > maxPossible {
		required = maxPossible
	}

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			session.mu.RLock()
			ackMap := session.acks[dealer]
			received := 0
			if ackMap != nil {
				received = len(ackMap)
			}
			session.mu.RUnlock()
			return fmt.Errorf("timeout waiting for acks: got %d/%d", received, required)

		case <-ticker.C:
			session.mu.RLock()
			ackMap := session.acks[dealer]
			received := 0
			if ackMap != nil {
				received = len(ackMap)
			}
			session.mu.RUnlock()

			if received >= required {
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

// GetKeyStore returns the keystore (for testing)
func (n *Node) GetKeyStore() *keystore.KeyStore {
	return n.keyStore
}

// RunDKGPhase1 runs only phase 1 of DKG (for testing)
func (n *Node) RunDKGPhase1() (map[common.Address]*fr.Element, []types.G2Point, error) {
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

// trustedDealerIDs returns the subset of validShares whose dealers also passed
// merkle proof verification (present in verifiedOperators).
func trustedDealerIDs(validShares map[common.Address]*fr.Element, verifiedOperators map[common.Address]bool) map[common.Address]*fr.Element {
	trusted := make(map[common.Address]*fr.Element, len(validShares))
	for addr, share := range validShares {
		if verifiedOperators[addr] {
			trusted[addr] = share
		}
	}
	return trusted
}

func (n *Node) logInvalidShareComplaint(protocol string, sessionTimestamp int64, receiverAddr common.Address, dealerAddr common.Address, share *fr.Element, commitments []types.G2Point) {
	// We intentionally log a compact "complaint record" that is sufficient to correlate
	// off-chain alerts and (future) on-chain fraud proofs without dumping huge payloads.
	//
	// Evidence included:
	// - share hash (keccak256) and share value (field element string)
	// - commitment hash (sha256) and commitment count
	var shareHash [32]byte
	shareStr := ""
	if share != nil {
		shareHash = eigenxcrypto.HashShareForAck(share)
		shareStr = types.SerializeFr(share).Data
	}

	commitmentHash := eigenxcrypto.HashCommitment(commitments)

	n.logger.Sugar().Warnw("ComplaintRecord: invalid share",
		"protocol", protocol,
		"operator_address", n.OperatorAddress.Hex(),
		"receiver_address", receiverAddr.Hex(),
		"session_timestamp", sessionTimestamp,
		"dealer_address", dealerAddr.Hex(),
		"share_hash", fmt.Sprintf("0x%x", shareHash[:]),
		"share", shareStr,
		"commitment_hash", fmt.Sprintf("0x%x", commitmentHash[:]),
		"commitment_count", len(commitments),
	)
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
			"session_timestamp", epoch,
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
				"session_timestamp", epoch)
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

func buildAcknowledgementSigningMessage(dealerAddress, playerAddress common.Address, epoch int64, shareHash, commitmentHash [32]byte) []byte {
	// message = dealerAddress || playerAddress || epoch || shareHash || commitmentHash
	msg := make([]byte, 0, 20+20+8+32+32)
	epochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(epochBytes, uint64(epoch))
	msg = append(msg, dealerAddress.Bytes()...)
	msg = append(msg, playerAddress.Bytes()...)
	msg = append(msg, epochBytes...)
	msg = append(msg, shareHash[:]...)
	msg = append(msg, commitmentHash[:]...)
	return msg
}

// signAcknowledgement signs acknowledgement fields using the transport signer.
func (n *Node) signAcknowledgement(dealerAddress, playerAddress common.Address, epoch int64, shareHash, commitmentHash [32]byte) []byte {
	message := buildAcknowledgementSigningMessage(dealerAddress, playerAddress, epoch, shareHash, commitmentHash)

	// Sign using transport signer (ECDSA)
	signature, err := n.transportSigner.SignMessage(message)
	if err != nil {
		n.logger.Sugar().Errorw("Failed to sign acknowledgement", "error", err)
		return nil
	}
	return signature
}

func (n *Node) verifyAcknowledgement(
	session *ProtocolSession,
	senderPeer *peering.OperatorSetPeer,
	expectedDealer common.Address,
	sessionTimestamp int64,
	ack *types.Acknowledgement,
) error {
	if ack == nil {
		return fmt.Errorf("ack is nil")
	}
	expectedPlayerAddr := senderPeer.OperatorAddress
	if ack.PlayerAddress != expectedPlayerAddr {
		return fmt.Errorf("ack player mismatch: got %s expected %s", ack.PlayerAddress.Hex(), expectedPlayerAddr.Hex())
	}
	expectedDealerAddr := n.OperatorAddress
	if ack.DealerAddress != expectedDealerAddr {
		return fmt.Errorf("ack dealer mismatch: got %s expected %s", ack.DealerAddress.Hex(), expectedDealerAddr.Hex())
	}
	if ack.SessionTimestamp != sessionTimestamp {
		return fmt.Errorf("ack session timestamp mismatch: got %d expected %d", ack.SessionTimestamp, sessionTimestamp)
	}
	if len(ack.Signature) == 0 {
		return fmt.Errorf("ack signature is empty")
	}

	session.mu.RLock()
	dealerCommitments, ok := session.commitments[expectedDealer]
	session.mu.RUnlock()
	if !ok || len(dealerCommitments) == 0 {
		return fmt.Errorf("dealer commitments unavailable for dealer %s", expectedDealer.Hex())
	}
	expectedCommitmentHash := eigenxcrypto.HashCommitment(dealerCommitments)
	if ack.CommitmentHash != expectedCommitmentHash {
		return fmt.Errorf("ack commitment hash mismatch")
	}

	msg := buildAcknowledgementSigningMessage(ack.DealerAddress, ack.PlayerAddress, ack.SessionTimestamp, ack.ShareHash, ack.CommitmentHash)
	msgHash := crypto.Keccak256Hash(msg)

	switch senderPeer.CurveType {
	case config.CurveTypeBN254:
		sig, err := bn254.NewSignatureFromBytes(ack.Signature)
		if err != nil {
			return fmt.Errorf("invalid BN254 ack signature format: %w", err)
		}
		bn254PubKey, ok := senderPeer.WrappedPublicKey.PublicKey.(*bn254.PublicKey)
		if !ok {
			return fmt.Errorf("sender public key is not BN254 type")
		}
		valid, err := sig.VerifySolidityCompatible(bn254PubKey, msgHash)
		if err != nil {
			return fmt.Errorf("BN254 ack signature verification error: %w", err)
		}
		if !valid {
			return fmt.Errorf("BN254 ack signature verification failed")
		}
	case config.CurveTypeECDSA:
		sig, err := ecdsa.NewSignatureFromBytes(ack.Signature)
		if err != nil {
			return fmt.Errorf("invalid ECDSA ack signature format: %w", err)
		}
		valid, err := sig.VerifyWithAddress(msgHash[:], senderPeer.WrappedPublicKey.ECDSAAddress)
		if err != nil {
			return fmt.Errorf("ECDSA ack signature verification error: %w", err)
		}
		if !valid {
			return fmt.Errorf("ECDSA ack signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported curve type for ack verification: %s", senderPeer.CurveType)
	}

	return nil
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

	// Step 2: Compute commitment hash (will be verified against on-chain data in Phase 7)
	// TODO: Compare broadcastCommitmentHash against contract-stored value once contract integration is complete
	broadcastCommitmentHash := eigenxcrypto.HashCommitment(broadcast.Commitments)

	// Step 3: Find MY ack in the broadcast
	session := n.getSession(sessionTimestamp)
	if session == nil {
		return fmt.Errorf("session not found")
	}

	var myAck *types.Acknowledgement
	for _, ack := range broadcast.Acknowledgements {
		if ack.PlayerAddress == n.OperatorAddress {
			myAck = ack
			break
		}
	}

	if myAck == nil {
		return fmt.Errorf("my ack not found in broadcast")
	}

	// Step 4: Verify MY ack's shareHash matches the share I received
	session.mu.RLock()
	receivedShare := session.shares[broadcast.FromOperatorAddress]
	session.mu.RUnlock()

	if receivedShare == nil {
		return fmt.Errorf("no share received from operator %s", broadcast.FromOperatorAddress.Hex())
	}

	expectedShareHash := eigenxcrypto.HashShareForAck(receivedShare)
	if myAck.ShareHash != expectedShareHash {
		return fmt.Errorf("share hash mismatch: ack says %x, actual is %x",
			myAck.ShareHash, expectedShareHash)
	}

	// Step 5: Verify merkle proof is present
	// NOTE: Full proof verification requires the leaf index, which is not currently
	// transmitted in CommitmentBroadcast. The broadcast only carries the sibling hashes
	// ([][32]byte) but not the leaf's position in the tree. Full verification will be
	// implemented in Phase 7 when we verify against on-chain root from contract, which
	// will also supply the leaf index. For now, verify the proof is non-empty.
	if len(broadcast.MerkleProof) == 0 {
		return fmt.Errorf("merkle proof is empty")
	}

	// Mark operator as verified
	session.mu.Lock()
	session.verifiedOperators[broadcast.FromOperatorAddress] = true
	session.mu.Unlock()

	n.logger.Sugar().Debugw("Verified operator broadcast",
		"from_operator", broadcast.FromOperatorAddress.Hex(),
		"session_timestamp", broadcast.SessionTimestamp,
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

	// For reshare, only expect threshold-1 verifications (matching the threshold
	// semantics used for shares). For DKG, expect all n-1.
	// Cap at receivedShareCount-1 since we can only verify operators we received
	// shares from, and some may go offline before broadcasting.
	expectedVerifications := len(session.Operators) - 1
	if session.Type == "reshare" {
		session.mu.RLock()
		receivedShareCount := len(session.shares)
		session.mu.RUnlock()
		thresholdMinus1 := dkg.CalculateThreshold(len(session.Operators)) - 1
		expectedVerifications = min(thresholdMinus1, receivedShareCount-1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
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

// fetchMPKFromPeers fetches the master public key from peer operators using threshold agreement.
// Used by new operators joining via reshare who cannot derive the MPK from protocol data alone.
func (n *Node) fetchMPKFromPeers(ctx context.Context, operators []*peering.OperatorSetPeer) (*types.G2Point, error) {
	// Build peer list excluding self, then compute threshold from full operator set
	peers := make([]*peering.OperatorSetPeer, 0, len(operators))
	for _, op := range operators {
		if op.OperatorAddress != n.OperatorAddress {
			peers = append(peers, op)
		}
	}

	type mpkResult struct {
		mpk *types.G2Point
	}

	resultChan := make(chan mpkResult, len(peers))
	var wg sync.WaitGroup

	httpClient := &http.Client{Timeout: 10 * time.Second}

	for _, op := range peers {
		wg.Add(1)
		go func(peer *peering.OperatorSetPeer) {
			defer wg.Done()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, peer.SocketAddress+"/pubkey", nil)
			if err != nil {
				n.logger.Sugar().Warnw("Failed to create MPK request", "peer", peer.SocketAddress, "error", err)
				return
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				n.logger.Sugar().Warnw("Failed to fetch MPK from peer", "peer", peer.SocketAddress, "error", err)
				return
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				n.logger.Sugar().Warnw("Peer returned error for MPK", "peer", peer.SocketAddress, "status", resp.StatusCode, "body", string(body))
				return
			}

			var response struct {
				MasterPublicKey *types.G2Point `json:"masterPublicKey"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				n.logger.Sugar().Warnw("Failed to decode MPK response", "peer", peer.SocketAddress, "error", err)
				return
			}

			if response.MasterPublicKey == nil || len(response.MasterPublicKey.CompressedBytes) == 0 {
				return
			}

			// Validate the bytes decode to a valid G2 curve point
			if _, err := bls.G2PointFromCompressedBytes(response.MasterPublicKey.CompressedBytes); err != nil {
				n.logger.Sugar().Warnw("Peer returned invalid G2 point for MPK", "peer", peer.SocketAddress, "error", err)
				return
			}

			resultChan <- mpkResult{mpk: response.MasterPublicKey}
		}(op)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Threshold agreement: group by compressed bytes, pick the one with enough votes
	mpkVotes := make(map[string][]*types.G2Point)
	for res := range resultChan {
		key := hex.EncodeToString(res.mpk.CompressedBytes)
		mpkVotes[key] = append(mpkVotes[key], res.mpk)
	}

	// Use threshold based on the full operator set size (including self)
	threshold := dkg.CalculateThreshold(len(operators))
	for _, votes := range mpkVotes {
		if len(votes) >= threshold {
			return votes[0], nil
		}
	}

	return nil, fmt.Errorf("failed to reach threshold agreement on MPK: needed %d, best had %d votes", threshold, maxVotes(mpkVotes))
}

func maxVotes(votes map[string][]*types.G2Point) int {
	m := 0
	for _, v := range votes {
		if len(v) > m {
			m = len(v)
		}
	}
	return m
}
