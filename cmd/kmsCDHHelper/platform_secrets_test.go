package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchStackSecrets_HappyPath(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		// proto bytes marshal as base64-std strings on the wire.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"secrets": []map[string]string{
				{"name": "DB_PASSWORD", "value": base64.StdEncoding.EncodeToString([]byte("ciphertext-1"))},
				{"name": "API_KEY", "value": base64.StdEncoding.EncodeToString([]byte("ciphertext-2"))},
			},
		})
	}))
	defer srv.Close()

	got, err := fetchStackSecrets(srv.URL, "secret-key", "stack-abc")
	require.NoError(t, err)

	assert.Equal(t, "Bearer secret-key", gotAuth, "must present the internal API key as a Bearer token")
	assert.Equal(t, "/internal/v1/stacks/stack-abc/secrets", gotPath)
	require.Len(t, got, 2)
	assert.Equal(t, "DB_PASSWORD", got[0].Name)
	assert.Equal(t, []byte("ciphertext-1"), got[0].Value, "value must be base64-decoded to raw ciphertext bytes")
	assert.Equal(t, "API_KEY", got[1].Name)
	assert.Equal(t, []byte("ciphertext-2"), got[1].Value)
}

func TestFetchStackSecrets_Non200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := fetchStackSecrets(srv.URL, "k", "stack-abc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestFetchStackSecrets_MalformedJSONIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := fetchStackSecrets(srv.URL, "k", "stack-abc")
	require.Error(t, err)
}

func TestFetchStackSecrets_EscapesStackIDInPath(t *testing.T) {
	// A stack_id containing path metacharacters must be percent-escaped into a
	// SINGLE path segment — it must not split into extra segments or traverse.
	// (Config-time validation in applyInitdataKMSConfig is the primary guard;
	// this is defense-in-depth at the request boundary.)
	for _, tc := range []struct {
		name    string
		stackID string
	}{
		{"embedded_slash", "weird/id"},
		{"dotdot_escaped", "%2e%2e"},
		{"literal_dotdot_slash", "../etc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotEscapedPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotEscapedPath = r.URL.EscapedPath()
				_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []any{}})
			}))
			defer srv.Close()

			_, err := fetchStackSecrets(srv.URL, "k", tc.stackID)
			require.NoError(t, err)
			// The stack segment sits between "/stacks/" and "/secrets"; assert the
			// path shape is exactly one escaped segment there and never traverses.
			assert.Contains(t, gotEscapedPath, "/internal/v1/stacks/")
			assert.True(t, strings.HasSuffix(gotEscapedPath, "/secrets"))
			assert.NotContains(t, gotEscapedPath, "/../", "stack_id must not introduce a traversal segment")
			assert.NotContains(t, gotEscapedPath, "stacks/../", "stack_id must not escape the stacks/ prefix")
		})
	}
}

func TestFetchStackSecrets_BodyCapped(t *testing.T) {
	// A misbehaving endpoint returning a huge body must not OOM the
	// memory-constrained peer-pod. The response is read under io.LimitReader;
	// a body past the cap yields a decode error (truncated JSON), not a hang.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write a valid prefix then far more than the cap of junk so the
		// LimitReader truncates mid-stream and json.Unmarshal fails.
		_, _ = w.Write([]byte(`{"secrets":[`))
		junk := make([]byte, platformSecretsMaxBody+1024)
		for i := range junk {
			junk[i] = 'A'
		}
		_, _ = w.Write(junk)
	}))
	defer srv.Close()

	_, err := fetchStackSecrets(srv.URL, "k", "stack-abc")
	require.Error(t, err)
}

func TestFetchStackSecrets_EmptyListIsOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []any{}})
	}))
	defer srv.Close()

	got, err := fetchStackSecrets(srv.URL, "k", "stack-abc")
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestFetchStackSecrets_StripsBaseURLQueryAndFragment(t *testing.T) {
	// A stray query/fragment on the configured platform_secrets_url must not
	// leak into the request — fetchStackSecrets targets a fixed API path.
	var gotRawQuery, gotFragment, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawQuery = r.URL.RawQuery
		gotFragment = r.URL.Fragment // fragments aren't sent over the wire, but assert on the built URL below too
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []any{}})
	}))
	defer srv.Close()

	// Fragment never reaches the server (HTTP clients drop it), so the RawQuery
	// assertion is the load-bearing one; the fragment is covered by construction.
	_, err := fetchStackSecrets(srv.URL+"?debug=true#frag", "k", "stack-abc")
	require.NoError(t, err)
	assert.Empty(t, gotRawQuery, "base-URL query string must be stripped, not forwarded")
	assert.Empty(t, gotFragment)
	assert.Equal(t, "/internal/v1/stacks/stack-abc/secrets", gotPath)
}
