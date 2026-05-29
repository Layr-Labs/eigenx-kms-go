package util

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// HTTP response-body limits. Callers may pass any int64 cap; these are
// repository-wide defaults for the common cases.
const (
	// DefaultMaxJSONResponseBytes bounds JSON responses on the operator-to-
	// operator and operator-to-client paths. 64 KiB is large enough for the
	// G2-commitment lists / IBE ciphertexts we exchange and small enough to
	// stop a malicious peer from forcing OOM via a multi-GB stream.
	DefaultMaxJSONResponseBytes int64 = 64 * 1024

	// DefaultMaxErrorBodyBytes bounds bytes read from a non-2xx response for
	// inclusion in an error message. Best-effort log decoration; the outer
	// HTTP status is what callers should branch on.
	DefaultMaxErrorBodyBytes int64 = 4 * 1024
)

// ReadResponseBody reads up to maxBytes from resp.Body and returns the bytes.
// Always closes resp.Body. Returns an error if the body read fails or if the
// body exceeds maxBytes — over-limit is treated as a hard failure rather than
// a silent truncation, so callers cannot accidentally trust a partial payload.
//
// Use this for non-JSON responses (raw text, pre-decoded binary, hex
// signatures). For JSON responses prefer DecodeJSONResponse, which composes
// this read with json.Unmarshal in one call.
func ReadResponseBody(resp *http.Response, maxBytes int64) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()

	// Read maxBytes+1 so we can distinguish "exactly at the cap" from
	// "exceeded the cap" — io.LimitReader truncates silently, which on its
	// own would make the over-limit case indistinguishable from a payload
	// that happens to be exactly maxBytes long.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("response body exceeded %d bytes", maxBytes)
	}
	return body, nil
}

// DecodeJSONResponse reads up to maxBytes from resp.Body, decodes it as JSON
// into a value of type T, and always closes resp.Body. The generic parameter
// commits the caller to a concrete type at the call site rather than handing
// out a (*any, error) pair.
//
// Returns an error if (a) the body read fails, (b) the body exceeds maxBytes,
// or (c) JSON decoding fails. The body is always drained and closed.
//
// Usage:
//
//	resp, err := http.Get(url)
//	if err != nil { ... }
//	parsed, err := util.DecodeJSONResponse[MyType](resp, util.DefaultMaxJSONResponseBytes)
func DecodeJSONResponse[T any](resp *http.Response, maxBytes int64) (T, error) {
	var zero T
	body, err := ReadResponseBody(resp, maxBytes)
	if err != nil {
		return zero, err
	}

	var out T
	if err := json.Unmarshal(body, &out); err != nil {
		return zero, fmt.Errorf("decode JSON response: %w", err)
	}
	return out, nil
}

// ReadErrorBody reads up to maxBytes of resp.Body for inclusion in an error
// message. Always closes resp.Body. Returns the bytes that were successfully
// read (possibly truncated by the LimitReader) and any read error. Truncation
// is silent — io.ReadAll on an io.LimitReader returns nil err on truncation;
// a non-nil err here means the underlying body read genuinely failed.
//
// Callers commonly use this as best-effort log decoration:
//
//	body, _ := util.ReadErrorBody(resp, util.DefaultMaxErrorBodyBytes)
//	return fmt.Errorf("operator returned status %d: %s", resp.StatusCode, body)
//
// The error return is provided so callers who care about read failures can
// surface them; the underscore form above is acceptable when the outer HTTP
// status is the actionable signal.
func ReadErrorBody(resp *http.Response, maxBytes int64) (string, error) {
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return string(body), fmt.Errorf("read error body: %w", err)
	}
	return string(body), nil
}
