package node

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

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

	fmt.Printf("Node %d: Processing secrets request for app_id: %s\n", s.node.ID, req.AppID)

	// Step 1: Verify attestation
	claims, err := s.node.attestationVerifier.VerifyAttestation(req.Attestation)
	if err != nil {
		fmt.Printf("Node %d: Attestation verification failed: %v\n", s.node.ID, err)
		http.Error(w, "Invalid attestation", http.StatusUnauthorized)
		return
	}

	// Step 2: Query latest release from on-chain registry
	release, err := s.node.releaseRegistry.GetLatestRelease(req.AppID)
	if err != nil {
		fmt.Printf("Node %d: Failed to get release for %s: %v\n", s.node.ID, req.AppID, err)
		http.Error(w, "Release not found", http.StatusNotFound)
		return
	}

	// Step 3: Verify image digest matches
	if claims.ImageDigest != release.ImageDigest {
		fmt.Printf("Node %d: Image digest mismatch for %s. Expected: %s, Got: %s\n",
			s.node.ID, req.AppID, release.ImageDigest, claims.ImageDigest)
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
		fmt.Printf("Node %d: No valid key share available\n", s.node.ID)
		http.Error(w, "No valid key share", http.StatusServiceUnavailable)
		return
	}

	// Step 5: Generate partial signature for this app
	// partial_sig = H(app_id)^{key_share}
	partialSig := s.node.SignAppID(req.AppID, req.AttestTime)

	fmt.Printf("Node %d: Generated partial signature for %s\n", s.node.ID, req.AppID)

	// Step 6: Serialize partial signature for encryption
	partialSigBytes, err := json.Marshal(partialSig)
	if err != nil {
		fmt.Printf("Node %d: Failed to serialize partial signature: %v\n", s.node.ID, err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Step 7: Encrypt partial signature with ephemeral RSA public key
	encryptedPartialSig, err := s.node.rsaEncryption.Encrypt(partialSigBytes, req.RSAPubKeyTmp)
	if err != nil {
		fmt.Printf("Node %d: Failed to encrypt partial signature: %v\n", s.node.ID, err)
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
		fmt.Printf("Node %d: Failed to encode response: %v\n", s.node.ID, err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	fmt.Printf("Node %d: Successfully served secrets for app_id: %s\n", s.node.ID, req.AppID)
}

// handleDKGCommitment handles DKG commitment messages
func (s *Server) handleDKGCommitment(w http.ResponseWriter, r *http.Request) {
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
	fmt.Printf("Node %d: Received DKG commitments (count: %d)\n", s.node.ID, len(commitments))
	
	w.WriteHeader(http.StatusOK)
}

// handleDKGShare handles DKG share messages
func (s *Server) handleDKGShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: Parse and store received share
	fmt.Printf("Node %d: Received DKG share\n", s.node.ID)
	
	w.WriteHeader(http.StatusOK)
}

// handleDKGAck handles DKG acknowledgement messages
func (s *Server) handleDKGAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse acknowledgement
	var ack types.Acknowledgement
	if err := json.NewDecoder(r.Body).Decode(&ack); err != nil {
		http.Error(w, "Failed to parse acknowledgement", http.StatusBadRequest)
		return
	}

	// TODO: Store received acknowledgement
	fmt.Printf("Node %d: Received acknowledgement from node %d for dealer %d\n", 
		s.node.ID, ack.PlayerID, ack.DealerID)
	
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
	fmt.Printf("Node %d: Received reshare commitments (count: %d)\n", s.node.ID, len(commitments))
	
	w.WriteHeader(http.StatusOK)
}

// handleReshareShare handles reshare share messages
func (s *Server) handleReshareShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: Parse and store received share
	fmt.Printf("Node %d: Received reshare share\n", s.node.ID)
	
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

	fmt.Printf("Node %d: Received reshare ack from Node %d\n", s.node.ID, msg.Ack.PlayerID)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleReshareComplete(w http.ResponseWriter, r *http.Request) {
	var msg types.CompletionMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Printf("Node %d: Received reshare completion from Node %d\n", s.node.ID, msg.Completion.NodeID)
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
		NodeID:           s.node.ID,
		PartialSignature: partialSig,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}