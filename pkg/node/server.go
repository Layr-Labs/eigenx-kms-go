package node

import (
	"fmt"
	"net/http"
)

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

	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	return s
}

// Start starts the HTTP server
func (s *Server) Start() error {
	go func() {
		fmt.Printf("Node %d: Starting HTTP server on port %s\n", s.node.ID, s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("Node %d: HTTP server error: %v\n", s.node.ID, err)
		}
	}()
	return nil
}

// Stop stops the HTTP server
func (s *Server) Stop() error {
	return s.httpServer.Close()
}

// Note: Handler implementations moved to handlers.go