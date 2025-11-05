package node

import (
	"fmt"
	"net/http"
)

/*
Server handles HTTP requests for inter-node protocol communication and client requests.

DKG Protocol Flow (Genesis - All operators participate):
  Phase 1: Share Distribution
    - Each node generates random polynomial f_i(z) and commitments
    - POST /dkg/commitment: Broadcast commitments to all operators
    - POST /dkg/share: Send encrypted shares to each operator
    - Each node waits for shares + commitments from ALL operators

  Phase 2: Verification & Acknowledgement
    - Each node verifies received shares against commitments
    - POST /dkg/ack: Send acknowledgement to each operator whose share was valid
    - Each node waits for acknowledgements from ALL operators (100% required)

  Phase 3: Finalization
    - Compute final key share: sum of all received shares
    - Store KeyShareVersion with IsActive=true
    - Master secret = Σ f_i(0) across all operators

Reshare Protocol Flow (Existing Operators):
  Phase 1: Share Redistribution
    - Each node uses current share as f'_i(0) = current_share_i
    - Generates new polynomial and shares
    - POST /reshare/commitment: Broadcast new commitments
    - POST /reshare/share: Send new shares to ALL operators (including new ones)
    - Wait for shares + commitments from all operators

  Phase 2: Finalization
    - Compute new share via Lagrange: x'_j = Σ λ_i * s'_ij
    - Store new KeyShareVersion with IsActive=true
    - Master secret preserved: Σ f'_i(0) = Σ current_share_i = original_master_secret

Reshare Protocol Flow (New Operators):
  - New operator has no current share → does NOT generate shares
  - Only receives shares from existing operators
  - Computes share via Lagrange interpolation
  - Stores first KeyShareVersion with IsActive=true

Client Request Flow:
  GET /pubkey:
    - Returns operator's current commitments and key version
    - Used by clients to compute master public key

  POST /app/sign:
    - Request: { appID, attestationTime }
    - Computes partial signature: Sign(H_1(appID))
    - Response: { partialSignature, operatorAddress }
    - Client collects ⌈2n/3⌉ signatures to recover app private key

  POST /secrets:
    - Request: { appID, attestation, rsaPubKey, attestTime }
    - Validates attestation and image digest
    - Returns encrypted environment + RSA-encrypted partial signature
    - Used by TEE applications for secret retrieval

Session Management:
  - All protocol messages include SessionTimestamp (rounded to interval boundary)
  - Messages routed to correct session
  - Session stores operators (fetched once per protocol)
  - Prevents message confusion between concurrent protocols

Authentication:
  - All inter-node messages wrapped in AuthenticatedMessage:
    { payload: []byte, hash: [32]byte, signature: []byte }
  - Signature verified using sender's BN254 public key from peering data
  - Payload contains fromOperatorAddress, toOperatorAddress, sessionTimestamp
*/

// Server handles HTTP requests for the node
type Server struct {
	node       *Node
	httpServer *http.Server
}

// NewServer creates a new server instance
func NewServer(node *Node, port int) *Server {
	s := &Server{
		node: node,
	}

	mux := http.NewServeMux()

	// DKG endpoints
	mux.HandleFunc("/dkg/share", s.handleDKGShare)
	mux.HandleFunc("/dkg/commitment", s.handleDKGCommitment)
	mux.HandleFunc("/dkg/ack", s.handleDKGAck)

	// Reshare endpoints
	mux.HandleFunc("/reshare/share", s.handleReshareShare)
	mux.HandleFunc("/reshare/commitment", s.handleReshareCommitment)
	mux.HandleFunc("/reshare/ack", s.handleReshareAck)
	mux.HandleFunc("/reshare/complete", s.handleReshareComplete)

	// App signing endpoint
	mux.HandleFunc("/app/sign", s.handleAppSign)

	// Secrets endpoint for TEE applications
	mux.HandleFunc("/secrets", s.handleSecretsRequest)

	// Public key endpoint for clients
	mux.HandleFunc("/pubkey", s.handleGetCommitments)

	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	return s
}

// Start starts the HTTP server
func (s *Server) Start() error {
	go func() {
		s.node.logger.Sugar().Infow("Starting HTTP server", "operator_address", s.node.OperatorAddress.Hex(), "port", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
			s.node.logger.Sugar().Errorw("HTTP server error", "operator_address", s.node.OperatorAddress.Hex(), "error", err)
		}
	}()
	return nil
}

// Stop stops the HTTP server
func (s *Server) Stop() error {
	return s.httpServer.Close()
}

// GetHandler returns the HTTP handler (for testing)
func (s *Server) GetHandler() http.Handler {
	return s.httpServer.Handler
}

// Note: Handler implementations moved to handlers.go
