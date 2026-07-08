package main

// Client for ecloud-platform's InternalSecretsService HTTP gateway. On the
// stack model the KMS returns only the recovered app-private-key; the actual
// secret ciphertexts live in the platform and are fetched here, then
// IBE-decrypted inside the TEE with that key (see retrieveAndDecrypt).
//
// The endpoint + bearer key are SNP-bound via cc_init_data (applyInitdataKMSConfig),
// and the route is only reachable by the helper over the trusted internal network.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// platformSecretsTimeout bounds the whole ListSecrets round trip.
	platformSecretsTimeout = 30 * time.Second
	// platformSecretsMaxBody caps the response body. Stack secret sets are
	// small (kilobytes of ciphertext); 8 MiB is generous headroom that still
	// protects the memory-constrained peer-pod from a misbehaving endpoint.
	platformSecretsMaxBody = 8 << 20
	// platformSecretsErrBodyMax bounds how much of a non-200 response body is
	// echoed into an error (which reaches stderr/journal via main's log.Printf).
	// Enough to surface a real error message without dumping a large
	// remote-controlled body into operator logs.
	platformSecretsErrBodyMax = 4 << 10
)

// stackSecret is one platform secret: a name and its opaque IBE ciphertext.
// Its field layout is intentionally identical to internalSecret so the
// conversion stackSecret(internalSecret{...}) is legal and cheap — keep the two
// in sync if either gains a field, or the conversion in fetchStackSecrets breaks.
type stackSecret struct {
	Name  string
	Value []byte
}

// internalSecret mirrors the protojson wire shape of InternalSecret. The proto
// `bytes value` field marshals as a base64-std string; a Go []byte field
// unmarshals it back to raw bytes automatically.
type internalSecret struct {
	Name  string `json:"name"`
	Value []byte `json:"value"`
}

type listSecretsResponse struct {
	Secrets []internalSecret `json:"secrets"`
}

// fetchStackSecrets GETs a stack's sealed secrets from the platform's
// InternalSecretsService HTTP gateway and returns each {name, ciphertext}.
// baseURL is the gateway root; the stack path is appended here. apiKey is the
// static internal API key, presented as a Bearer token.
func fetchStackSecrets(baseURL, apiKey, stackID string) ([]stackSecret, error) {
	// baseURL was already scheme-validated by validateHTTPURL in
	// applyInitdataKMSConfig; re-parsing here is defense-in-depth so this
	// function is safe to call independently (and in tests) without assuming a
	// prior validation pass.
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse platform secrets URL: %w", err)
	}
	// Percent-escape stackID into a SINGLE path segment. NOTE: url.JoinPath is
	// NOT safe here — it does not percent-escape "." / ".." or embedded "/", it
	// path-CLEANS them (silently dropping/rewriting segments), which is a
	// traversal footgun. Build the path explicitly with url.PathEscape so a
	// hostile stack_id can never reshape the request path. (stackID is also
	// content-validated at config time in applyInitdataKMSConfig — this is
	// defense-in-depth at the request boundary.)
	base := strings.TrimRight(u.Path, "/")
	u.Path = base + "/internal/v1/stacks/" + url.PathEscape(stackID) + "/secrets"
	// Drop any query/fragment carried on the configured base URL: this is a
	// fixed internal API path and stray params (e.g. a "?debug=true" left on
	// platform_secrets_url) must not leak into the request.
	u.RawQuery = ""
	u.Fragment = ""

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build ListSecrets request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: platformSecretsTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u.String(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, platformSecretsMaxBody))
	if err != nil {
		return nil, fmt.Errorf("read ListSecrets response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Truncate the surfaced body: it is remote-controlled and reaches
		// stderr/journal via main's log.Printf.
		snippet := body
		if len(snippet) > platformSecretsErrBodyMax {
			snippet = snippet[:platformSecretsErrBodyMax]
		}
		return nil, fmt.Errorf("platform ListSecrets returned status %d: %s", resp.StatusCode, string(snippet))
	}

	var parsed listSecretsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode ListSecrets response: %w", err)
	}

	out := make([]stackSecret, 0, len(parsed.Secrets))
	for _, s := range parsed.Secrets {
		out = append(out, stackSecret(s))
	}
	return out, nil
}
