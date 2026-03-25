package node

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestMaxBodySize(t *testing.T) {
	handler := maxBodySize(16, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("within limit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("small"))
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("exceeds limit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 100)))
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected 413, got %d", rec.Code)
		}
	})
}

func TestConcurrencyLimit(t *testing.T) {
	var active atomic.Int32
	blocker := make(chan struct{})

	handler := concurrencyLimit(2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Add(-1)
		<-blocker
		w.WriteHeader(http.StatusOK)
	}))

	var wg sync.WaitGroup
	results := make([]int, 3)

	// Launch 3 concurrent requests with limit of 2
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			rec := httptest.NewRecorder()
			handler(rec, req)
			results[idx] = rec.Code
		}(i)
	}

	// Wait for 2 requests to be active, then the 3rd should get 503
	// Give a brief moment for goroutines to start
	for active.Load() < 2 {
	}

	// Unblock all
	close(blocker)
	wg.Wait()

	got503 := 0
	got200 := 0
	for _, code := range results {
		switch code {
		case http.StatusOK:
			got200++
		case http.StatusServiceUnavailable:
			got503++
		}
	}

	if got200 != 2 || got503 != 1 {
		t.Fatalf("expected 2x200 and 1x503, got 200s=%d 503s=%d", got200, got503)
	}
}

func TestRateLimited(t *testing.T) {
	handler := rateLimited(1, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request should succeed (uses the burst token)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", rec.Code)
	}

	// Second request immediately should be rate limited
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: expected 429, got %d", rec.Code)
	}
}
