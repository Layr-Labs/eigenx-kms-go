package peering

import (
	"context"
)

// StubPeeringDataFetcher is a simple stub implementation for testing
type StubPeeringDataFetcher struct {
	operators *OperatorSetPeers
}

// NewStubPeeringDataFetcher creates a new stub peering data fetcher
func NewStubPeeringDataFetcher(operators *OperatorSetPeers) *StubPeeringDataFetcher {
	return &StubPeeringDataFetcher{
		operators: operators,
	}
}

// ListKMSOperators returns the stub operator set
func (s *StubPeeringDataFetcher) ListKMSOperators(ctx context.Context, avsAddress string, operatorSetId uint32) (*OperatorSetPeers, error) {
	// Return the stub operators for any query
	if s.operators != nil {
		return s.operators, nil
	}

	// Return empty operator set if none provided
	return &OperatorSetPeers{
		OperatorSetId: operatorSetId,
		Peers:         []*OperatorSetPeer{},
	}, nil
}
