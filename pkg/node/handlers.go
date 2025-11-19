package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/common"
)

// validateAuthenticatedMessage validates an incoming authenticated message
func (s *Server) validateAuthenticatedMessage(r *http.Request, expectedRecipient common.Address) (*types.AuthenticatedMessage, *peering.OperatorSetPeer, interface{}, error) {
	// Parse authenticated message wrapper
	var authMsg types.AuthenticatedMessage
	if err := json.NewDecoder(r.Body).Decode(&authMsg); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse authenticated message: %w", err)
	}

	// First decode payload to get sender address and session timestamp
	var baseMsg struct {
		FromOperatorAddress common.Address `json:"fromOperatorAddress"`
		ToOperatorAddress   common.Address `json:"toOperatorAddress"`
		SessionTimestamp    int64          `json:"sessionTimestamp"`
	}
	if err := json.Unmarshal(authMsg.Payload, &baseMsg); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse message addresses: %w", err)
	}

	// Verify message is intended for this node (unless broadcast)
	if baseMsg.ToOperatorAddress != (common.Address{}) && baseMsg.ToOperatorAddress != expectedRecipient {
		return nil, nil, nil, fmt.Errorf("message not intended for this operator")
	}

	// Get session - it contains the operators for this protocol run
	session := s.node.getSession(baseMsg.SessionTimestamp)
	var operators []*peering.OperatorSetPeer

	if session != nil {
		// Use operators from session (already fetched when protocol started)
		session.mu.RLock()
		operators = session.Operators
		session.mu.RUnlock()
	} else {
		// No session yet - fetch operators (this happens for first message of a session)
		// This is normal - receiving node might not have started protocol yet
		ctx := context.Background()
		var err error
		operators, err = s.node.fetchCurrentOperators(ctx, s.node.AVSAddress, s.node.OperatorSetId)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to fetch operators for validation: %w", err)
		}
	}

	// Find sender peer
	senderPeer := s.node.findPeerByAddress(baseMsg.FromOperatorAddress, operators)
	if senderPeer == nil {
		return nil, nil, nil, fmt.Errorf("unknown sender: %s", baseMsg.FromOperatorAddress.Hex())
	}

	// Verify authentication
	if err := s.node.verifyMessage(&authMsg, senderPeer); err != nil {
		return nil, nil, nil, fmt.Errorf("authentication failed: %w", err)
	}

	return &authMsg, senderPeer, nil, nil
}

// handleSecretsRequest handles the /secrets endpoint for application secret retrieval
func (s *Server) handleSecretsRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request
	var req types.SecretsRequestV1
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.AppID == "" {
		http.Error(w, "app_id is required", http.StatusBadRequest)
		return
	}
	if len(req.RSAPubKeyTmp) == 0 {
		http.Error(w, "rsa_pubkey_tmp is required", http.StatusBadRequest)
		return
	}

	s.node.logger.Sugar().Infow("Processing secrets request", "node_id", s.node.OperatorAddress.Hex(), "app_id", req.AppID)

	// Step 1: Verify attestation
	claims, err := s.node.attestationVerifier.VerifyAttestation(req.Attestation)
	if err != nil {
		s.node.logger.Sugar().Warnw("Attestation verification failed", "node_id", s.node.OperatorAddress.Hex(), "error", err)
		http.Error(w, "Invalid attestation", http.StatusUnauthorized)
		return
	}

	// Step 2: Query latest release from on-chain registry
	release, err := s.node.releaseRegistry.GetLatestRelease(req.AppID)
	if err != nil {
		s.node.logger.Sugar().Warnw("Failed to get release", "node_id", s.node.OperatorAddress.Hex(), "app_id", req.AppID, "error", err)
		http.Error(w, "Release not found", http.StatusNotFound)
		return
	}

	// Step 3: Verify image digest matches
	if claims.ImageDigest != release.ImageDigest {
		s.node.logger.Sugar().Warnw("Image digest mismatch", "node_id", s.node.OperatorAddress.Hex(), "app_id", req.AppID, "expected", release.ImageDigest, "got", claims.ImageDigest)
		http.Error(w, "Image digest mismatch - unauthorized image", http.StatusForbidden)
		return
	}

	// Step 4: Get appropriate key share based on attestation time
	var keyVersion *types.KeyShareVersion
	if req.AttestTime > 0 {
		// Use key version from the specified time
		keyVersion = s.node.keyStore.GetKeyVersionAtTime(req.AttestTime, ReshareFrequency)
	}
	if keyVersion == nil {
		// Fallback to active version
		keyVersion = s.node.keyStore.GetActiveVersion()
	}

	if keyVersion == nil || keyVersion.PrivateShare == nil {
		s.node.logger.Sugar().Errorw("No valid key share available", "node_id", s.node.OperatorAddress.Hex())
		http.Error(w, "No valid key share", http.StatusServiceUnavailable)
		return
	}

	// Step 5: Generate partial signature for this app
	// partial_sig = H(app_id)^{key_share}
	partialSig := s.node.SignAppID(req.AppID, req.AttestTime)

	s.node.logger.Sugar().Infow("Generated partial signature", "node_id", s.node.OperatorAddress.Hex(), "app_id", req.AppID)

	// Step 6: Serialize partial signature for encryption
	partialSigBytes, err := json.Marshal(partialSig)
	if err != nil {
		s.node.logger.Sugar().Errorw("Failed to serialize partial signature", "node_id", s.node.OperatorAddress.Hex(), "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Step 7: Encrypt partial signature with ephemeral RSA public key
	encryptedPartialSig, err := s.node.rsaEncryption.Encrypt(partialSigBytes, req.RSAPubKeyTmp)
	if err != nil {
		s.node.logger.Sugar().Errorw("Failed to encrypt partial signature", "node_id", s.node.OperatorAddress.Hex(), "error", err)
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	// Step 8: Create response
	response := types.SecretsResponseV1{
		EncryptedEnv:        release.EncryptedEnv,
		PublicEnv:           release.PublicEnv,
		EncryptedPartialSig: encryptedPartialSig,
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.node.logger.Sugar().Errorw("Failed to encode response", "node_id", s.node.OperatorAddress.Hex(), "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	s.node.logger.Sugar().Infow("Successfully served secrets", "node_id", s.node.OperatorAddress.Hex(), "app_id", req.AppID)
}

// handleDKGCommitment handles DKG commitment messages
func (s *Server) handleDKGCommitment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate authenticated message (accepts broadcast messages)
	authMsg, senderPeer, _, err := s.validateAuthenticatedMessage(r, s.node.OperatorAddress)
	if err != nil {
		s.node.logger.Sugar().Warnw("DKG commitment authentication failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Decode commitment message
	var commitMsg types.CommitmentMessage
	if err := json.Unmarshal(authMsg.Payload, &commitMsg); err != nil {
		http.Error(w, "Failed to parse commitment message", http.StatusBadRequest)
		return
	}

	// Get session for this message, wait if not ready yet
	session := s.node.waitForSession(commitMsg.SessionTimestamp, 5*time.Second)
	if session == nil {
		s.node.logger.Sugar().Warnw("Session not created within timeout",
			"session_timestamp", commitMsg.SessionTimestamp,
			"from", senderPeer.OperatorAddress.Hex())
		http.Error(w, "Session timeout", http.StatusServiceUnavailable)
		return
	}

	// Convert sender address to node ID and store commitments
	senderNodeID := addressToNodeID(senderPeer.OperatorAddress)

	// Store in session
	session.mu.Lock()
	session.commitments[senderNodeID] = commitMsg.Commitments
	session.mu.Unlock()

	// Also store in global state for backward compatibility
	s.node.mu.Lock()
	s.node.receivedCommitments[senderNodeID] = commitMsg.Commitments
	s.node.mu.Unlock()

	s.node.logger.Sugar().Debugw("Received authenticated DKG commitments",
		"node_id", s.node.OperatorAddress.Hex(),
		"from_address", senderPeer.OperatorAddress.Hex(),
		"sender_node_id", senderNodeID,
		"session_timestamp", commitMsg.SessionTimestamp,
		"count", len(commitMsg.Commitments))

	w.WriteHeader(http.StatusOK)
}

// handleDKGShare handles DKG share messages
func (s *Server) handleDKGShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate authenticated message
	authMsg, senderPeer, _, err := s.validateAuthenticatedMessage(r, s.node.OperatorAddress)
	if err != nil {
		s.node.logger.Sugar().Warnw("DKG share authentication failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Decode share message
	var shareMsg types.ShareMessage
	if err := json.Unmarshal(authMsg.Payload, &shareMsg); err != nil {
		http.Error(w, "Failed to parse share message", http.StatusBadRequest)
		return
	}

	// Get session for this message, wait if not ready yet
	session := s.node.waitForSession(shareMsg.SessionTimestamp, 5*time.Second)
	if session == nil {
		s.node.logger.Sugar().Warnw("Session not created within timeout",
			"session_timestamp", shareMsg.SessionTimestamp,
			"from", senderPeer.OperatorAddress.Hex())
		http.Error(w, "Session timeout", http.StatusServiceUnavailable)
		return
	}

	// Convert addresses to node IDs
	senderNodeID := addressToNodeID(senderPeer.OperatorAddress)
	share := types.DeserializeFr(shareMsg.Share)

	// Store received share in session
	session.mu.Lock()
	session.shares[senderNodeID] = share
	session.mu.Unlock()

	// Also store in global state for backward compatibility
	s.node.mu.Lock()
	s.node.receivedShares[senderNodeID] = share
	s.node.mu.Unlock()

	s.node.logger.Sugar().Debugw("Received authenticated DKG share",
		"node_id", s.node.OperatorAddress.Hex(),
		"from_address", senderPeer.OperatorAddress.Hex(),
		"sender_node_id", senderNodeID,
		"session_timestamp", shareMsg.SessionTimestamp)

	w.WriteHeader(http.StatusOK)
}

// handleDKGAck handles DKG acknowledgement messages
func (s *Server) handleDKGAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate authenticated message
	authMsg, senderPeer, _, err := s.validateAuthenticatedMessage(r, s.node.OperatorAddress)
	if err != nil {
		s.node.logger.Sugar().Warnw("DKG acknowledgement authentication failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Decode acknowledgement message
	var ackMsg types.AcknowledgementMessage
	if err := json.Unmarshal(authMsg.Payload, &ackMsg); err != nil {
		http.Error(w, "Failed to parse acknowledgement message", http.StatusBadRequest)
		return
	}

	// Get session for this message, wait if not ready yet
	session := s.node.waitForSession(ackMsg.SessionTimestamp, 5*time.Second)
	if session == nil {
		s.node.logger.Sugar().Warnw("Session not created within timeout",
			"session_timestamp", ackMsg.SessionTimestamp,
			"from", senderPeer.OperatorAddress.Hex())
		http.Error(w, "Unknown session", http.StatusBadRequest)
		return
	}

	// Convert sender address to node ID and store acknowledgement
	senderNodeID := addressToNodeID(senderPeer.OperatorAddress)
	thisNodeID := addressToNodeID(s.node.OperatorAddress)

	// Store in session
	session.mu.Lock()
	if session.acks[thisNodeID] == nil {
		session.acks[thisNodeID] = make(map[int]*types.Acknowledgement)
	}
	session.acks[thisNodeID][senderNodeID] = ackMsg.Ack
	session.mu.Unlock()

	// Also store in global state for backward compatibility
	s.node.mu.Lock()
	if s.node.receivedAcks[thisNodeID] == nil {
		s.node.receivedAcks[thisNodeID] = make(map[int]*types.Acknowledgement)
	}
	s.node.receivedAcks[thisNodeID][senderNodeID] = ackMsg.Ack
	s.node.mu.Unlock()

	s.node.logger.Sugar().Debugw("Received authenticated acknowledgement",
		"node_id", s.node.OperatorAddress.Hex(),
		"from_address", senderPeer.OperatorAddress.Hex(),
		"from_player", senderNodeID,
		"for_dealer", thisNodeID,
		"session_timestamp", ackMsg.SessionTimestamp)

	w.WriteHeader(http.StatusOK)
}

// handleReshareCommitment handles reshare commitment messages
func (s *Server) handleReshareCommitment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse commitment message
	var commitments []types.G2Point
	if err := json.NewDecoder(r.Body).Decode(&commitments); err != nil {
		http.Error(w, "Failed to parse commitments", http.StatusBadRequest)
		return
	}

	// TODO: Store received commitments
	s.node.logger.Sugar().Debugw("Received reshare commitments", "node_id", s.node.OperatorAddress.Hex(), "count", len(commitments))

	w.WriteHeader(http.StatusOK)
}

// handleReshareShare handles reshare share messages
func (s *Server) handleReshareShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: Parse and store received share
	s.node.logger.Sugar().Debugw("Received reshare share", "node_id", s.node.OperatorAddress.Hex())

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleReshareAck(w http.ResponseWriter, r *http.Request) {
	var msg types.AcknowledgementMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.node.mu.Lock()
	if s.node.receivedAcks[msg.Ack.DealerID] == nil {
		s.node.receivedAcks[msg.Ack.DealerID] = make(map[int]*types.Acknowledgement)
	}
	s.node.receivedAcks[msg.Ack.DealerID][msg.Ack.PlayerID] = msg.Ack
	s.node.mu.Unlock()

	s.node.logger.Sugar().Debugw("Received reshare ack", "node_id", s.node.OperatorAddress.Hex(), "from_player", msg.Ack.PlayerID)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleReshareComplete(w http.ResponseWriter, r *http.Request) {
	var msg types.CompletionMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.node.logger.Sugar().Infow("Received reshare completion", "node_id", s.node.OperatorAddress.Hex(), "from_node", msg.Completion.NodeID)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAppSign(w http.ResponseWriter, r *http.Request) {
	var req types.AppSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	partialSig := s.node.SignAppID(req.AppID, req.AttestationTime)

	resp := types.AppSignResponse{
		OperatorAddress:  s.node.OperatorAddress.Hex(),
		PartialSignature: partialSig,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleGetCommitments handles requests for public key commitments
func (s *Server) handleGetCommitments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get active key version
	activeVersion := s.node.keyStore.GetActiveVersion()
	if activeVersion == nil {
		http.Error(w, "No active key version", http.StatusServiceUnavailable)
		return
	}

	// Return commitments and operator address
	response := map[string]interface{}{
		"operatorAddress": s.node.OperatorAddress.Hex(),
		"commitments":     activeVersion.Commitments,
		"version":         activeVersion.Version,
		"isActive":        activeVersion.IsActive,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.node.logger.Sugar().Errorw("Failed to encode commitments response", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	s.node.logger.Sugar().Debugw("Served public key commitments", "operator_address", s.node.OperatorAddress.Hex())
}

// handleCommitmentBroadcast handles commitment broadcasts with merkle proofs (Phase 5)
func (s *Server) handleCommitmentBroadcast(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var msg types.CommitmentBroadcastMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	// Get session (should already exist from DKG/Reshare flow)
	session := s.node.getSession(msg.SessionID)
	if session == nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	s.node.logger.Sugar().Debugw("Received commitment broadcast",
		"from", msg.FromOperatorID,
		"epoch", msg.Broadcast.Epoch,
		"num_acks", len(msg.Broadcast.Acknowledgements),
		"num_commitments", len(msg.Broadcast.Commitments),
		"proof_length", len(msg.Broadcast.MerkleProof),
	)

	// Phase 6: Verify the broadcast
	// Note: Contract registry address should come from node config in production
	// For now, using zero address as placeholder
	contractRegistryAddr := common.Address{}
	if err := s.node.VerifyOperatorBroadcast(msg.SessionID, msg.Broadcast, contractRegistryAddr); err != nil {
		s.node.logger.Sugar().Warnw("Failed to verify operator broadcast",
			"from", msg.FromOperatorID,
			"error", err,
		)
		http.Error(w, fmt.Sprintf("Verification failed: %v", err), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}
