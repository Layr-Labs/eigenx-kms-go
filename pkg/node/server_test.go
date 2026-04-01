package node

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
	blocker := make(chan struct{})
	// entered signals that a handler goroutine is inside the handler.
	entered := make(chan struct{}, 3)

	handler := concurrencyLimit(2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-blocker
		w.WriteHeader(http.StatusOK)
	}))

	// Launch 2 requests that will block inside the handler.
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			rec := httptest.NewRecorder()
			handler(rec, req)
		}()
	}

	// Wait until both are inside the handler (semaphore full).
	<-entered
	<-entered

	// Third request should be rejected immediately with 503.
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}

	// Unblock the two held requests.
	close(blocker)
	wg.Wait()
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
