package integration

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/testutil"
	"github.com/stretchr/testify/require"
)

func Test_Reshare_SucceedsWithExactlyThresholdAcks(t *testing.T) {
	const n = 5
	cluster := testutil.NewTestCluster(t, n)
	defer cluster.Close()

	// Choose a dealer (node 0). We will drop exactly one /reshare/ack request to this dealer.
	dealerURL := cluster.ServerURLs[0]
	var droppedReshare atomic.Bool
	originalTransport := http.DefaultTransport
	http.DefaultTransport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		url := req.URL.String()
		if strings.HasPrefix(url, dealerURL) &&
			strings.Contains(url, "/reshare/ack") &&
			droppedReshare.CompareAndSwap(false, true) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       http.NoBody,
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
		return originalTransport.RoundTrip(req)
	})
	defer func() { http.DefaultTransport = originalTransport }()

	// Run reshare manually (existing operators) at a new session timestamp.
	reshareTS := time.Now().Unix()
	require.NoError(t, runOnAllNodes(cluster, func(ctx context.Context, idx int) error {
		return cluster.Nodes[idx].RunReshareAsExistingOperator(reshareTS)
	}, 120*time.Second))

	require.True(t, droppedReshare.Load(), "expected exactly one dropped /reshare/ack to dealer")
}

func runOnAllNodes(cluster *testutil.TestCluster, fn func(ctx context.Context, idx int) error, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, len(cluster.Nodes))

	for i := range cluster.Nodes {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errCh <- fn(ctx, idx)
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}


