package node

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
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
    - Request: { appID, attestationMethod, attestation, rsaPubKey, attestTime, challenge?, publicKey? }
    - attestationMethod: "gcp" (default), "intel", or "ecdsa"
    - For GCP/Intel: attestation contains JWT token
    - For ECDSA: attestation contains signature, challenge and publicKey required
    - Validates attestation and image digest
    - Returns encrypted environment + RSA-encrypted partial signature
    - Used by TEE applications for secret retrieval

    Examples:
      GCP attestation:
        { "app_id": "my-app", "attestation_method": "gcp",
          "attestation": "<jwt-token>", "rsa_pubkey_tmp": "<pubkey>" }

      ECDSA attestation:
        { "app_id": "my-app", "attestation_method": "ecdsa",
          "attestation": "<signature>", "challenge": "<timestamp>-<nonce>",
          "public_key": "<ecdsa-pubkey>", "rsa_pubkey_tmp": "<rsa-pubkey>" }

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

	// jtiMu guards jtiCache to prevent concurrent replay attacks.
	jtiMu    sync.Mutex
	jtiCache map[string]int64 // jti -> expiry unix timestamp

	// stopJTICleanup signals the background JTI cleanup goroutine to exit.
	stopJTICleanup chan struct{}
	stopOnce       sync.Once
}

// maxBodySize wraps a handler with http.MaxBytesReader to limit request body size.
func maxBodySize(maxBytes int64, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next(w, r)
	}
}

// concurrencyLimit wraps a handler with a buffered channel semaphore.
// Returns 503 Service Unavailable when the concurrency limit is reached.
func concurrencyLimit(maxConcurrent int, next http.HandlerFunc) http.HandlerFunc {
	sem := make(chan struct{}, maxConcurrent)
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			next(w, r)
		default:
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		}
	}
}

// rateLimited wraps a handler with a token bucket rate limiter.
// Returns 429 Too Many Requests when the rate limit is exceeded.
func rateLimited(rps float64, burst int, next http.HandlerFunc) http.HandlerFunc {
	limiter := rate.NewLimiter(rate.Limit(rps), burst)
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// NewServer creates a new server instance
func NewServer(node *Node, port int) *Server {
	s := &Server{
		node:           node,
		jtiCache:       make(map[string]int64),
		stopJTICleanup: make(chan struct{}),
	}

	mux := http.NewServeMux()

	// DKG endpoints
	mux.HandleFunc("/dkg/share", maxBodySize(64<<10, s.handleDKGShare))
	mux.HandleFunc("/dkg/commitment", maxBodySize(256<<10, s.handleDKGCommitment))
	mux.HandleFunc("/dkg/ack", maxBodySize(64<<10, s.handleDKGAck))
	mux.HandleFunc("/dkg/broadcast", maxBodySize(1<<20, s.handleCommitmentBroadcast))

	// Reshare endpoints
	mux.HandleFunc("/reshare/share", maxBodySize(64<<10, s.handleReshareShare))
	mux.HandleFunc("/reshare/commitment", maxBodySize(256<<10, s.handleReshareCommitment))
	mux.HandleFunc("/reshare/ack", maxBodySize(64<<10, s.handleReshareAck))

	// App signing endpoint
	mux.HandleFunc("/app/sign", rateLimited(50, 100, concurrencyLimit(20, maxBodySize(16<<10, s.handleAppSign))))

	// Secrets endpoint for TEE applications
	mux.HandleFunc("/secrets", rateLimited(10, 20, concurrencyLimit(10, maxBodySize(64<<10, s.handleSecretsRequest))))

	// Public key endpoint for clients
	mux.HandleFunc("/pubkey", s.handleGetCommitments)

	s.httpServer = &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	return s
}

// Start starts the HTTP server and the background JTI cleanup goroutine.
func (s *Server) Start() error {
	go s.runJTICleanup()
	go func() {
		s.node.logger.Sugar().Infow("Starting HTTP server", "operator_address", s.node.OperatorAddress.Hex(), "port", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
			s.node.logger.Sugar().Errorw("HTTP server error", "operator_address", s.node.OperatorAddress.Hex(), "error", err)
		}
	}()
	return nil
}

// Stop stops the HTTP server and the background JTI cleanup goroutine.
// Safe to call multiple times.
func (s *Server) Stop() error {
	s.stopOnce.Do(func() { close(s.stopJTICleanup) })
	return s.httpServer.Close()
}

// GetHandler returns the HTTP handler (for testing)
func (s *Server) GetHandler() http.Handler {
	return s.httpServer.Handler
}

// maxJTICacheSize is the upper bound on tracked JTIs. If the cache is full,
// new tokens are rejected to prevent memory exhaustion from DDoS.
const maxJTICacheSize = 100_000

// checkAndStoreJTI checks whether jti has been used before and, if not, records it
// until expiresAt. Returns true if the jti is new (allowed), false if it is a replay
// or the cache is at capacity.
// Expired entries are purged by a background goroutine (see runJTICleanup).
func (s *Server) checkAndStoreJTI(jti string, expiresAt int64) bool {
	s.jtiMu.Lock()
	defer s.jtiMu.Unlock()

	if _, seen := s.jtiCache[jti]; seen {
		return false
	}

	if len(s.jtiCache) >= maxJTICacheSize {
		return false
	}

	s.jtiCache[jti] = expiresAt
	return true
}

// jtiCleanupInterval controls how often the background goroutine purges expired JTIs.
const jtiCleanupInterval = 1 * time.Minute

// runJTICleanup periodically removes expired entries from the JTI cache.
// It runs until stopJTICleanup is closed.
func (s *Server) runJTICleanup() {
	ticker := time.NewTicker(jtiCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopJTICleanup:
			return
		case <-ticker.C:
			now := time.Now().Unix()
			s.jtiMu.Lock()
			for k, exp := range s.jtiCache {
				if now >= exp {
					delete(s.jtiCache, k)
				}
			}
			s.jtiMu.Unlock()
		}
	}
}

// Note: Handler implementations moved to handlers.go
