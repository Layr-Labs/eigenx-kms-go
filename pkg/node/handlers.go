package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// validateAuthenticatedMessage validates an incoming authenticated message
func (s *Server) validateAuthenticatedMessage(r *http.Request, expectedRecipient common.Address) (*types.AuthenticatedMessage, *peering.OperatorSetPeer, interface{}, error) {
	// Parse authenticated message wrapper
	var authMsg types.AuthenticatedMessage
	if err := json.NewDecoder(r.Body).Decode(&authMsg); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse authenticated message: %w", err)
	}
	s.node.logger.Sugar().Infow("Received authenticated message wrapper", "msg", string(authMsg.Payload))
	// First decode payload to get sender address and session timestamp
	var baseMsg struct {
		FromOperatorAddress common.Address `json:"fromOperatorAddress"`
		ToOperatorAddress   common.Address `json:"toOperatorAddress"`
		SessionTimestamp    int64          `json:"sessionTimestamp"`
	}
	if err := json.Unmarshal(authMsg.Payload, &baseMsg); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse message addresses: %w", err)
	}
	// s.node.logger.Sugar().Infow("received authenticated message", "msg", baseMsg)

	// Verify message is intended for this node
	if baseMsg.ToOperatorAddress != expectedRecipient {
		return nil, nil, nil, fmt.Errorf("message not intended for this operator - to: '%s' expected: '%s'", baseMsg.ToOperatorAddress, expectedRecipient)
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

// verifyECDSAOwnership confirms the ECDSA attestation signer controls the app's
// on-chain creator key. The appID for ECDSA must be an app contract address;
// the signer is derived from the already-verified attestation public key and
// compared to GetAppCreator(appID). Returns (httpStatus, error); (0, nil) on
// success.
func (s *Server) verifyECDSAOwnership(appID string, publicKey []byte) (int, error) {
	if !common.IsHexAddress(appID) {
		return http.StatusBadRequest, fmt.Errorf("app_id must be a contract address for ecdsa attestation")
	}
	pub, err := ethcrypto.UnmarshalPubkey(publicKey)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid ecdsa public key: %w", err)
	}
	signer := ethcrypto.PubkeyToAddress(*pub)

	creator, err := s.node.baseContractCaller.GetAppCreator(common.HexToAddress(appID), nil)
	if err != nil {
		return http.StatusBadGateway, fmt.Errorf("failed to look up app creator: %w", err)
	}
	if signer != creator {
		return http.StatusForbidden, fmt.Errorf("ecdsa signer is not the app creator")
	}
	return 0, nil
}

// handleSecretsRequest handles the /secrets endpoint for application secret retrieval
func (s *Server) handleSecretsRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Cap the request body before decoding. The per-field guards below
	// (RSAPubKeyTmp, ExtraData, CCInitData, Attestation) only fire after
	// json.Decode has already fully allocated the body, so an oversized
	// POST would balloon memory before any check runs. Bound it up front
	// at the sum of the field caps plus JSON/base64 overhead slack.
	// MaxBytesReader makes Decode return an error past the limit.
	const maxSecretsBodyBytes = 2*types.MaxAttestationSize + 2*types.MaxExtraDataSize + 64*1024
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxSecretsBodyBytes))

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
	if s.node.appAllowlist != nil && !s.node.appAllowlist[req.AppID] {
		s.node.logger.Sugar().Warnw("Secrets request rejected: app not in allowlist",
			"operator_address", s.node.OperatorAddress.Hex(),
			"app_id", req.AppID)
		http.Error(w, "app not allowed", http.StatusForbidden)
		return
	}
	if len(req.RSAPubKeyTmp) == 0 {
		http.Error(w, "rsa_pubkey_tmp is required", http.StatusBadRequest)
		return
	}
	if len(req.RSAPubKeyTmp) > 8192 {
		http.Error(w, "rsa_pubkey_tmp too large", http.StatusBadRequest)
		return
	}
	if len(req.ExtraData) > types.MaxExtraDataSize {
		http.Error(w, fmt.Sprintf("extra_data exceeds 1MB limit (%d bytes)", len(req.ExtraData)), http.StatusBadRequest)
		return
	}
	if len(req.CCInitData) > types.MaxExtraDataSize {
		http.Error(w, fmt.Sprintf("cc_init_data exceeds 1MB limit (%d bytes)", len(req.CCInitData)), http.StatusBadRequest)
		return
	}
	if len(req.Attestation) > types.MaxAttestationSize {
		http.Error(w, fmt.Sprintf("attestation exceeds %d byte limit (%d bytes)", types.MaxAttestationSize, len(req.Attestation)), http.StatusBadRequest)
		return
	}

	s.node.logger.Sugar().Infow("Processing secrets request", "operator_address", s.node.OperatorAddress.Hex(), "app_id", req.AppID, "attestation_method", req.AttestationMethod)

	// Step 1: Validate attestation method is provided
	if req.AttestationMethod == "" {
		s.node.logger.Sugar().Warnw("Attestation method is required", "operator_address", s.node.OperatorAddress.Hex(), "app_id", req.AppID)
		http.Error(w, "Attestation method is required", http.StatusBadRequest)
		return
	}

	// Step 2: Verify attestation using AttestationManager
	attestReq := &attestation.AttestationRequest{
		Method:       req.AttestationMethod,
		AppID:        req.AppID,
		Attestation:  req.Attestation,
		Challenge:    req.Challenge,
		PublicKey:    req.PublicKey,
		RSAPubKeyTmp: req.RSAPubKeyTmp,
		ExtraData:    req.ExtraData,
		CCInitData:   req.CCInitData,
	}
	// TPM attestation needs the RSA key to compute the hardware-bound challenge
	if req.AttestationMethod == "tpm" {
		if attestReq.Metadata == nil {
			attestReq.Metadata = make(map[string]interface{})
		}
		attestReq.Metadata["rsa_pubkey"] = req.RSAPubKeyTmp
	}

	claims, err := s.node.attestationManager.VerifyWithMethod(req.AttestationMethod, attestReq)
	if err != nil {
		s.node.logger.Sugar().Warnw("Attestation verification failed",
			"operator_address", s.node.OperatorAddress.Hex(),
			"method", req.AttestationMethod,
			"error", err)
		http.Error(w, fmt.Sprintf("Invalid attestation: %v", err), http.StatusUnauthorized)
		return
	}

	// Step 2b: Ensure attested application identity matches requested app.
	if claims.AppID != req.AppID {
		s.node.logger.Sugar().Warnw("App ID mismatch in attestation claims",
			"operator_address", s.node.OperatorAddress.Hex(),
			"requested_app_id", req.AppID,
			"attested_app_id", claims.AppID)
		http.Error(w, "App ID mismatch - unauthorized app", http.StatusForbidden)
		return
	}

	// Reject replayed attestation tokens by tracking JTI claim.
	// Any method that sets JTI (GCP, Intel, future providers) gets replay protection automatically.
	if claims.JTI != "" {
		if !s.checkAndStoreJTI(claims.JTI, claims.ExpiresAt) {
			s.node.logger.Sugar().Warnw("Replayed attestation token rejected",
				"operator_address", s.node.OperatorAddress.Hex(),
				"app_id", req.AppID,
				"jti", claims.JTI)
			http.Error(w, "attestation token already used", http.StatusUnauthorized)
			return
		}
	}

	// Step 3: Resolve the release and run method-specific authorization.
	//
	// ECDSA is a lightweight ownership-proof method for testing: it binds to the
	// app's on-chain creator and does NOT depend on a release (best-effort env,
	// no digest/registry/container-policy checks). All other methods keep the
	// full release + image-digest + registry + container-policy enforcement.
	var release *types.Release
	if req.AttestationMethod == "ecdsa" {
		if status, ownErr := s.verifyECDSAOwnership(req.AppID, claims.PublicKey); ownErr != nil {
			s.node.logger.Sugar().Warnw("ECDSA ownership check failed",
				"operator_address", s.node.OperatorAddress.Hex(),
				"app_id", req.AppID,
				"error", ownErr)
			http.Error(w, ownErr.Error(), status)
			return
		}

		// Best-effort env: a missing release is fine for ECDSA — serve the share
		// with empty env. A present release contributes its env.
		release, err = s.node.baseContractCaller.GetLatestReleaseAsRelease(r.Context(), req.AppID)
		if err != nil {
			s.node.logger.Sugar().Infow("No release for ecdsa app; serving share with empty env",
				"operator_address", s.node.OperatorAddress.Hex(),
				"app_id", req.AppID)
			release = &types.Release{}
		}
	} else {
		// Query latest release from on-chain AppController
		release, err = s.node.baseContractCaller.GetLatestReleaseAsRelease(r.Context(), req.AppID)
		if err != nil {
			s.node.logger.Sugar().Warnw("Failed to get release", "operator_address", s.node.OperatorAddress.Hex(), "app_id", req.AppID, "error", err)
			http.Error(w, "Release not found", http.StatusNotFound)
			return
		}

		// Step 4: Verify image digest matches.
		if claims.ImageDigest != release.ImageDigest {
			s.node.logger.Sugar().Warnw("Image digest mismatch", "operator_address", s.node.OperatorAddress.Hex(), "app_id", req.AppID, "expected", release.ImageDigest, "got", claims.ImageDigest)
			http.Error(w, "Image digest mismatch - unauthorized image", http.StatusForbidden)
			return
		}

		// Step 4b: Verify registry matches when claims surface one.
		//
		// eigenx-snp populates claims.Registry from cc_init_data's policy.rego
		// (e.g. "ghcr.io/example/app"); the on-chain Release.Registry is the
		// same shape — what AgentKit publishes via extractRegistryNameNoDocker
		// (registry + repo path, sans tag/digest). Other attestation methods
		// (kbs-ear, gcp/intel) leave claims.Registry empty; in that case we
		// don't enforce — those methods either don't surface the registry yet
		// or cover environments where the on-chain Registry is absent. When
		// release.Registry is empty (older releases pre-Registry-field) we
		// also skip — fail-open here is safe because the digest check above
		// already pinned identity.
		if claims.Registry != "" && release.Registry != "" && claims.Registry != release.Registry {
			s.node.logger.Sugar().Warnw("Registry mismatch",
				"operator_address", s.node.OperatorAddress.Hex(),
				"app_id", req.AppID,
				"expected", release.Registry, "got", claims.Registry)
			http.Error(w, "Registry mismatch - unauthorized image source", http.StatusForbidden)
			return
		}

		// Step 5: Verify container execution policy matches on-chain values.
		//
		// eigenx-snp does not surface ContainerPolicy in claims (the policy lives
		// in cc_init_data's aa.toml / cdh.toml, which we don't parse yet). If a
		// release pins a non-empty ContainerPolicy and the request authenticates
		// via eigenx-snp, validateContainerPolicy would silently succeed against
		// claims.ContainerPolicy's zero value — the policy would not be enforced.
		// Fail closed instead: workloads that don't pin a ContainerPolicy still
		// work over eigenx-snp; workloads that do pin one cannot use eigenx-snp
		// until the SEV-SNP path surfaces the running container's policy claims.
		// TODO(eigenx): surface the running container's launch spec into
		// claims.ContainerPolicy so this gap closes and this branch can drop.
		// Design + recommended approach: docs/009_eigenxSnpAttestation.md
		// ("Follow-up 1: ContainerPolicy enforcement").
		if req.AttestationMethod == "eigenx-snp" && hasContainerPolicy(release.ContainerPolicy) {
			s.node.logger.Sugar().Warnw(
				"refusing eigenx-snp request: release pins ContainerPolicy that this method does not yet surface in claims",
				"operator_address", s.node.OperatorAddress.Hex(),
				"app_id", req.AppID,
			)
			http.Error(w, "eigenx-snp attestation does not yet enforce ContainerPolicy; release requires it", http.StatusForbidden)
			return
		}
		if err := validateContainerPolicy(claims.ContainerPolicy, release.ContainerPolicy); err != nil {
			s.node.logger.Sugar().Warnw("Container policy mismatch", "operator_address", s.node.OperatorAddress.Hex(), "app_id", req.AppID, "error", err)
			http.Error(w, "Container policy mismatch", http.StatusForbidden)
			return
		}
	}

	// Step 6: Get appropriate key share based on attestation time
	var keyVersion *types.KeyShareVersion
	if req.AttestationTime > 0 {
		// Use key version from the specified time
		keyVersion = s.node.keyStore.GetKeyVersionAtTime(req.AttestationTime)
		if keyVersion == nil {
			s.node.logger.Sugar().Warnw("No key version found for attestation time",
				"operator_address", s.node.OperatorAddress.Hex(),
				"attestation_time", req.AttestationTime)
			http.Error(w, "No key version found for the specified attestation time", http.StatusNotFound)
			return
		}
	} else {
		keyVersion = s.node.keyStore.GetActiveVersion()
	}

	if keyVersion == nil || keyVersion.PrivateShare == nil {
		s.node.logger.Sugar().Errorw("No valid key share available", "operator_address", s.node.OperatorAddress.Hex())
		http.Error(w, "No valid key share", http.StatusServiceUnavailable)
		return
	}

	// Step 7: Generate partial signature for this app using the already-resolved key version
	// partial_sig = H(app_id)^{key_share}
	partialSig, err := s.node.signAppIDWithVersion(req.AppID, keyVersion)
	if err != nil {
		s.node.logger.Sugar().Errorw("Failed to compute partial signature", "operator_address", s.node.OperatorAddress.Hex(), "app_id", req.AppID, "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	s.node.logger.Sugar().Infow("Generated partial signature", "operator_address", s.node.OperatorAddress.Hex(), "app_id", req.AppID)

	// Step 8: Serialize partial signature for encryption
	partialSigBytes, err := json.Marshal(partialSig)
	if err != nil {
		s.node.logger.Sugar().Errorw("Failed to serialize partial signature", "operator_address", s.node.OperatorAddress.Hex(), "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Step 9: Encrypt partial signature with ephemeral RSA public key
	encryptedPartialSig, err := s.node.rsaEncryption.Encrypt(partialSigBytes, req.RSAPubKeyTmp)
	if err != nil {
		s.node.logger.Sugar().Errorw("Failed to encrypt partial signature", "operator_address", s.node.OperatorAddress.Hex(), "error", err)
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	// Step 10: Create response
	response := types.SecretsResponseV1{
		EncryptedEnv:        release.EncryptedEnv,
		PublicEnv:           release.PublicEnv,
		EncryptedPartialSig: encryptedPartialSig,
		ExtraData:           req.ExtraData,
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.node.logger.Sugar().Errorw("Failed to encode response", "operator_address", s.node.OperatorAddress.Hex(), "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	s.node.logger.Sugar().Infow("Successfully served secrets", "operator_address", s.node.OperatorAddress.Hex(), "app_id", req.AppID)
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

	senderAddr := senderPeer.OperatorAddress

	// Store commitment in session (handles duplicate detection and completion signaling)
	if err := session.HandleReceivedCommitment(senderAddr, commitMsg.Commitments); err != nil {
		s.node.logger.Sugar().Warnw("Failed to store commitment",
			"from", senderPeer.OperatorAddress.Hex(),
			"error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.node.logger.Sugar().Debugw("Received authenticated DKG commitments",
		"operator_address", s.node.OperatorAddress.Hex(),
		"from_address", senderPeer.OperatorAddress.Hex(),
		"sender_address", senderAddr.Hex(),
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

	// Validate share is present
	if shareMsg.Share == nil {
		http.Error(w, "share is required", http.StatusBadRequest)
		return
	}

	senderAddr := senderPeer.OperatorAddress
	share := types.DeserializeFr(shareMsg.Share)

	// Store share in session (handles duplicate detection and completion signaling)
	if err := session.HandleReceivedShare(senderAddr, share); err != nil {
		s.node.logger.Sugar().Warnw("Failed to store share",
			"from", senderPeer.OperatorAddress.Hex(),
			"error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.node.logger.Sugar().Debugw("Received authenticated DKG share",
		"operator_address", s.node.OperatorAddress.Hex(),
		"from_address", senderPeer.OperatorAddress.Hex(),
		"sender_address", senderAddr.Hex(),
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

	senderAddr := senderPeer.OperatorAddress
	thisAddr := s.node.OperatorAddress

	if err := s.node.verifyAcknowledgement(session, senderPeer, thisAddr, ackMsg.SessionTimestamp, ackMsg.Ack); err != nil {
		s.node.logger.Sugar().Warnw("Invalid DKG acknowledgement",
			"from", senderPeer.OperatorAddress.Hex(),
			"error", err)
		http.Error(w, "Invalid acknowledgement", http.StatusBadRequest)
		return
	}

	// Store ack in session (handles duplicate detection and completion signaling)
	if err := session.HandleReceivedAck(thisAddr, senderAddr, ackMsg.Ack); err != nil {
		s.node.logger.Sugar().Warnw("Failed to store ack",
			"from", senderPeer.OperatorAddress.Hex(),
			"error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.node.logger.Sugar().Debugw("Received authenticated acknowledgement",
		"operator_address", s.node.OperatorAddress.Hex(),
		"from_address", senderPeer.OperatorAddress.Hex(),
		"from_player", senderAddr.Hex(),
		"for_dealer", thisAddr.Hex(),
		"session_timestamp", ackMsg.SessionTimestamp)

	w.WriteHeader(http.StatusOK)
}

// handleReshareCommitment handles reshare commitment messages
func (s *Server) handleReshareCommitment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate authenticated message
	authMsg, senderPeer, _, err := s.validateAuthenticatedMessage(r, s.node.OperatorAddress)
	if err != nil {
		s.node.logger.Sugar().Warnw("Reshare commitment authentication failed", "error", err)
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

	senderAddr := senderPeer.OperatorAddress

	// Store commitment in session
	if err := session.HandleReceivedCommitment(senderAddr, commitMsg.Commitments); err != nil {
		s.node.logger.Sugar().Warnw("Failed to store reshare commitment",
			"from", senderPeer.OperatorAddress.Hex(),
			"error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Record the source version this dealer dealt from, so finalize can drop dealers on a
	// stale source version (docs/012 Layer 2).
	session.SetSourceVersion(senderAddr, commitMsg.SourceVersion)

	s.node.logger.Sugar().Debugw("Received reshare commitments",
		"operator_address", s.node.OperatorAddress.Hex(),
		"from", senderPeer.OperatorAddress.Hex(),
		"count", len(commitMsg.Commitments))

	w.WriteHeader(http.StatusOK)
}

// handleReshareShare handles reshare share messages
func (s *Server) handleReshareShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate authenticated message
	authMsg, senderPeer, _, err := s.validateAuthenticatedMessage(r, s.node.OperatorAddress)
	if err != nil {
		s.node.logger.Sugar().Warnw("Reshare share authentication failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Decode share message
	var shareMsg types.ShareMessage
	if err := json.Unmarshal(authMsg.Payload, &shareMsg); err != nil {
		http.Error(w, "Failed to parse share message", http.StatusBadRequest)
		return
	}

	// Get session for this message
	session := s.node.waitForSession(shareMsg.SessionTimestamp, 5*time.Second)
	if session == nil {
		s.node.logger.Sugar().Warnw("Session not created within timeout",
			"session_timestamp", shareMsg.SessionTimestamp,
			"from", senderPeer.OperatorAddress.Hex())
		http.Error(w, "Session timeout", http.StatusServiceUnavailable)
		return
	}

	// Validate share is present
	if shareMsg.Share == nil {
		http.Error(w, "share is required", http.StatusBadRequest)
		return
	}

	senderAddr := senderPeer.OperatorAddress
	share := types.DeserializeFr(shareMsg.Share)

	// Store share in session
	if err := session.HandleReceivedShare(senderAddr, share); err != nil {
		s.node.logger.Sugar().Warnw("Failed to store reshare share",
			"from", senderPeer.OperatorAddress.Hex(),
			"error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.node.logger.Sugar().Debugw("Received reshare share",
		"operator_address", s.node.OperatorAddress.Hex(),
		"from", senderPeer.OperatorAddress.Hex())

	w.WriteHeader(http.StatusOK)
}

// handleReshareShareRequest answers an on-demand share fetch: a peer asks for the
// reshare share THIS node (as dealer) generated for it during dealer-set-agreement
// finalization. We serve ONLY the share destined for the authenticated requester —
// never any other operator's share. See docs/011_reshareDealerSetAgreement.md.
func (s *Server) handleReshareShareRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authMsg, senderPeer, _, err := s.validateAuthenticatedMessage(r, s.node.OperatorAddress)
	if err != nil {
		s.node.logger.Sugar().Warnw("Reshare share-request authentication failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	var reqMsg types.ShareRequestMessage
	if err := json.Unmarshal(authMsg.Payload, &reqMsg); err != nil {
		http.Error(w, "Failed to parse share request", http.StatusBadRequest)
		return
	}

	// Serve only the requester's own share (the authenticated sender), never another
	// operator's. The requester address is the authenticated identity, not a field the
	// caller can spoof.
	requester := senderPeer.OperatorAddress

	// Resolve the share the requester is missing. Prefer a live session (tolerating slight
	// delivery-ordering skew, in case the request arrives before this node created the
	// session), but fall back to the node-level retained store: the common case in the
	// live incident is a peer that lagged and asks for our share AFTER we already finished
	// the round and tore down our session. Retained shares (docs/012 Layer 3a) let that
	// fetch succeed instead of 503-ing the peer into a corrupting version split.
	var share *fr.Element
	if session := s.node.waitForSession(reqMsg.SessionTimestamp, 5*time.Second); session != nil {
		share = session.GetMyGeneratedShareFor(requester)
	}
	if share == nil {
		share = s.node.getRetainedGeneratedShare(reqMsg.SessionTimestamp, requester)
	}
	if share == nil {
		s.node.logger.Sugar().Warnw("No generated share to serve for requester",
			"operator_address", s.node.OperatorAddress.Hex(),
			"requester", requester.Hex(),
			"session_timestamp", reqMsg.SessionTimestamp)
		http.Error(w, "No share available for requester", http.StatusNotFound)
		return
	}

	respMsg := types.ShareMessage{
		FromOperatorAddress: s.node.OperatorAddress,
		ToOperatorAddress:   requester,
		SessionTimestamp:    reqMsg.SessionTimestamp,
		Share:               types.SerializeFr(share),
	}
	respBytes, err := json.Marshal(respMsg)
	if err != nil {
		http.Error(w, "Failed to marshal share response", http.StatusInternalServerError)
		return
	}
	// Authenticate the response (BN254-signed), matching the push path's security model.
	// The requester verifies this against the dealer's peer key before trusting the share,
	// so the response's From/To fields can't be spoofed and the share is bound to this
	// dealer as the sender.
	authResp, err := s.node.transportSigner.CreateAuthenticatedMessage(respBytes)
	if err != nil {
		s.node.logger.Sugar().Warnw("Failed to sign share response", "error", err)
		http.Error(w, "Failed to sign share response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(authResp); err != nil {
		s.node.logger.Sugar().Warnw("Failed to encode share response", "error", err)
	}
}

func (s *Server) handleReshareAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate authenticated message
	authMsg, senderPeer, _, err := s.validateAuthenticatedMessage(r, s.node.OperatorAddress)
	if err != nil {
		s.node.logger.Sugar().Warnw("Reshare ack authentication failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Decode acknowledgement message
	var ackMsg types.AcknowledgementMessage
	if err := json.Unmarshal(authMsg.Payload, &ackMsg); err != nil {
		http.Error(w, "Failed to parse ack message", http.StatusBadRequest)
		return
	}

	// Get session for this message
	session := s.node.waitForSession(ackMsg.SessionTimestamp, 5*time.Second)
	if session == nil {
		s.node.logger.Sugar().Warnw("Session not created within timeout",
			"session_timestamp", ackMsg.SessionTimestamp,
			"from", senderPeer.OperatorAddress.Hex())
		http.Error(w, "Unknown session", http.StatusBadRequest)
		return
	}

	senderAddr := senderPeer.OperatorAddress
	thisAddr := s.node.OperatorAddress

	if err := s.node.verifyAcknowledgement(session, senderPeer, thisAddr, ackMsg.SessionTimestamp, ackMsg.Ack); err != nil {
		s.node.logger.Sugar().Warnw("Invalid reshare acknowledgement",
			"from", senderPeer.OperatorAddress.Hex(),
			"error", err)
		http.Error(w, "Invalid acknowledgement", http.StatusBadRequest)
		return
	}

	// Store ack in session
	if err := session.HandleReceivedAck(thisAddr, senderAddr, ackMsg.Ack); err != nil {
		s.node.logger.Sugar().Warnw("Failed to store reshare ack",
			"from", senderPeer.OperatorAddress.Hex(),
			"error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.node.logger.Sugar().Debugw("Received reshare ack",
		"operator_address", s.node.OperatorAddress.Hex(),
		"from_player", senderAddr.Hex(),
		"for_dealer", thisAddr.Hex())

	w.WriteHeader(http.StatusOK)
}

// hasContainerPolicy reports whether the on-chain ContainerPolicy pins any
// non-empty field. Used to detect releases that rely on policy enforcement
// when the request authenticates via a method (e.g. eigenx-snp) that does not
// surface ContainerPolicy in its claims.
func hasContainerPolicy(p types.ContainerPolicy) bool {
	return len(p.Args) > 0 || len(p.CmdOverride) > 0 || len(p.Env) > 0 || len(p.EnvOverride) > 0 || p.RestartPolicy != ""
}

// validateContainerPolicy checks that the container execution fields in the JWT claims
// match the on-chain policy registered by the app developer. Fields with zero/empty
// values in the policy are not enforced, allowing developers to restrict only the
// fields they care about.
func validateContainerPolicy(claims types.ContainerPolicy, policy types.ContainerPolicy) error {
	if len(policy.Args) > 0 && !slices.Equal(claims.Args, policy.Args) {
		return fmt.Errorf("args mismatch: expected %v, got %v", policy.Args, claims.Args)
	}

	if len(policy.CmdOverride) > 0 && !slices.Equal(claims.CmdOverride, policy.CmdOverride) {
		return fmt.Errorf("cmd_override mismatch: expected %v, got %v", policy.CmdOverride, claims.CmdOverride)
	}

	for key, expectedVal := range policy.Env {
		if actualVal, ok := claims.Env[key]; !ok || actualVal != expectedVal {
			return fmt.Errorf("env mismatch for key %q: expected %q, got %q", key, expectedVal, actualVal)
		}
	}

	for key, expectedVal := range policy.EnvOverride {
		if actualVal, ok := claims.EnvOverride[key]; !ok || actualVal != expectedVal {
			return fmt.Errorf("env_override mismatch for key %q: expected %q, got %q", key, expectedVal, actualVal)
		}
	}

	if policy.RestartPolicy != "" && claims.RestartPolicy != policy.RestartPolicy {
		return fmt.Errorf("restart_policy mismatch: expected %q, got %q", policy.RestartPolicy, claims.RestartPolicy)
	}

	return nil
}

// handleAppSign handles partial signature requests from KMS clients.
// NOTE: This endpoint is intentionally client-facing (not node-to-node) and does not
// use validateAuthenticatedMessage. It is called by the kmsClient CLI to collect partial
// BLS signatures for IBE decryption. Callers do not hold BN254 operator keys.
func (s *Server) handleAppSign(w http.ResponseWriter, r *http.Request) {
	// SECURITY/TRUST NOTE:
	// Deployment is expected to
	// enforce caller identity/authorization at the edge (e.g. WAF/ingress with HTTPS +
	// mTLS and app-level policy). If that external control is not present, this endpoint
	// should be treated as unsafe for public exposure.
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req types.AppSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Failed to parse request", http.StatusBadRequest)
		return
	}

	if req.AppID == "" {
		http.Error(w, "app_id is required", http.StatusBadRequest)
		return
	}
	if s.node.appAllowlist != nil && !s.node.appAllowlist[req.AppID] {
		s.node.logger.Sugar().Warnw("App sign request rejected: app not in allowlist",
			"operator_address", s.node.OperatorAddress.Hex(),
			"app_id", req.AppID)
		http.Error(w, "app not allowed", http.StatusForbidden)
		return
	}

	partialSig, err := s.node.SignAppID(req.AppID, req.AttestationTime)
	if err != nil {
		s.node.logger.Sugar().Errorw("Failed to compute partial signature for app",
			"operator_address", s.node.OperatorAddress.Hex(),
			"app_id", req.AppID,
			"error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	s.node.logger.Sugar().Infow("Served partial signature",
		"operator_address", s.node.OperatorAddress.Hex(),
		"app_id", req.AppID)

	resp := types.AppSignResponse{
		OperatorAddress:  s.node.OperatorAddress.Hex(),
		PartialSignature: partialSig,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.node.logger.Sugar().Errorw("Failed to encode app sign response", "error", err)
	}
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

	// Return commitments, operator address, and pre-computed master public key
	response := map[string]interface{}{
		"operatorAddress": s.node.OperatorAddress.Hex(),
		"commitments":     activeVersion.Commitments,
		"masterPublicKey": activeVersion.MasterPublicKey,
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

// handleCommitmentBroadcast handles authenticated commitment broadcasts with merkle proofs (Phase 5)
func (s *Server) handleCommitmentBroadcast(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate authentication
	authMsg, senderPeer, _, err := s.validateAuthenticatedMessage(r, s.node.OperatorAddress)
	if err != nil {
		s.node.logger.Sugar().Warnw("Authentication failed for commitment broadcast", "error", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	var msg types.CommitmentBroadcastMessage
	if err := json.Unmarshal(authMsg.Payload, &msg); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if msg.Broadcast == nil {
		http.Error(w, "broadcast is required", http.StatusBadRequest)
		return
	}

	// Get session (should already exist from DKG/Reshare flow)
	session := s.node.getSession(msg.SessionTimestamp)
	if session == nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	s.node.logger.Sugar().Debugw("Received authenticated commitment broadcast",
		"from", senderPeer.OperatorAddress.Hex(),
		"session_timestamp", msg.Broadcast.SessionTimestamp,
		"num_acks", len(msg.Broadcast.Acknowledgements),
		"num_commitments", len(msg.Broadcast.Commitments),
		"proof_length", len(msg.Broadcast.MerkleProof),
	)

	// Phase 6: Verify the broadcast against on-chain commitment
	contractRegistryAddr := s.node.commitmentRegistryAddress
	if err := s.node.VerifyOperatorBroadcast(msg.SessionTimestamp, msg.Broadcast, contractRegistryAddr); err != nil {
		s.node.logger.Sugar().Errorw("Failed to verify operator broadcast",
			"from_operator", senderPeer.OperatorAddress.Hex(),
			"session", msg.SessionTimestamp,
			"error", err,
		)
		http.Error(w, fmt.Sprintf("verification failed: %v", err), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}
