package util

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type sample struct {
	Name string `json:"name"`
	N    int    `json:"n"`
}

// errReader is an io.ReadCloser that returns a hard error after returning
// some leading bytes. Lets us assert that read failures surface even when
// the body partially streams.
type errReader struct {
	prefix []byte
	err    error
	i      int
}

func (e *errReader) Read(p []byte) (int, error) {
	if e.i < len(e.prefix) {
		n := copy(p, e.prefix[e.i:])
		e.i += n
		return n, nil
	}
	return 0, e.err
}

func (e *errReader) Close() error { return nil }

func newJSONResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func Test_DecodeJSONResponse(t *testing.T) {
	t.Run("decodes well-formed body under cap", func(t *testing.T) {
		resp := newJSONResponse(`{"name":"alice","n":7}`)

		out, err := DecodeJSONResponse[sample](resp, 1024)
		require.NoError(t, err)
		require.Equal(t, sample{Name: "alice", N: 7}, out)
	})

	t.Run("decodes payload of exactly maxBytes", func(t *testing.T) {
		// Pad the JSON so its length lands exactly on a target cap.
		body := `{"name":"alice","n":7}` // 22 bytes
		require.Equal(t, 22, len(body))

		out, err := DecodeJSONResponse[sample](newJSONResponse(body), int64(len(body)))
		require.NoError(t, err)
		require.Equal(t, sample{Name: "alice", N: 7}, out)
	})

	t.Run("rejects payload one byte over the cap", func(t *testing.T) {
		body := `{"name":"alice","n":7}` // 22 bytes

		_, err := DecodeJSONResponse[sample](newJSONResponse(body), int64(len(body)-1))
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeded")
	})

	t.Run("rejects multi-megabyte attacker body without OOM", func(t *testing.T) {
		// A 4 MiB body should never be fully buffered when the cap is 64 KiB.
		// io.LimitReader prevents io.ReadAll from drinking it all.
		big := strings.Repeat("a", 4*1024*1024)

		_, err := DecodeJSONResponse[sample](newJSONResponse(big), 64*1024)
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeded")
	})

	t.Run("returns decode error on malformed JSON", func(t *testing.T) {
		_, err := DecodeJSONResponse[sample](newJSONResponse(`{not-json`), 1024)
		require.Error(t, err)
		require.Contains(t, err.Error(), "decode JSON response")
	})

	t.Run("surfaces read errors", func(t *testing.T) {
		boom := errors.New("network broke")
		resp := &http.Response{
			StatusCode: 200,
			Body:       &errReader{prefix: []byte(`{"name":`), err: boom},
		}

		_, err := DecodeJSONResponse[sample](resp, 1024)
		require.Error(t, err)
		require.ErrorIs(t, err, boom)
	})
}

func Test_ReadResponseBody(t *testing.T) {
	t.Run("returns full body when under cap", func(t *testing.T) {
		got, err := ReadResponseBody(newJSONResponse("0xdeadbeef"), 1024)
		require.NoError(t, err)
		require.Equal(t, []byte("0xdeadbeef"), got)
	})

	t.Run("returns body of exactly maxBytes", func(t *testing.T) {
		body := "0xdeadbeef" // 10 bytes
		got, err := ReadResponseBody(newJSONResponse(body), int64(len(body)))
		require.NoError(t, err)
		require.Equal(t, []byte(body), got)
	})

	t.Run("rejects body one byte over the cap", func(t *testing.T) {
		body := "0xdeadbeef" // 10 bytes
		_, err := ReadResponseBody(newJSONResponse(body), int64(len(body)-1))
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeded")
	})

	t.Run("rejects multi-megabyte attacker body without OOM", func(t *testing.T) {
		big := strings.Repeat("a", 4*1024*1024)
		_, err := ReadResponseBody(newJSONResponse(big), 64*1024)
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeded")
	})

	t.Run("surfaces read errors", func(t *testing.T) {
		boom := errors.New("network broke")
		resp := &http.Response{
			StatusCode: 200,
			Body:       &errReader{prefix: []byte("partial"), err: boom},
		}
		_, err := ReadResponseBody(resp, 1024)
		require.Error(t, err)
		require.ErrorIs(t, err, boom)
	})
}

func Test_ReadErrorBody(t *testing.T) {
	t.Run("returns full body when under cap", func(t *testing.T) {
		got, err := ReadErrorBody(newJSONResponse("upstream broke"), 1024)
		require.NoError(t, err)
		require.Equal(t, "upstream broke", got)
	})

	t.Run("silently truncates body over cap", func(t *testing.T) {
		// io.ReadAll on an io.LimitReader returns the truncated prefix with
		// nil error. ReadErrorBody is best-effort log decoration, so this
		// truncation is by design.
		got, err := ReadErrorBody(newJSONResponse("aaaaaaaaaa"), 4)
		require.NoError(t, err)
		require.Equal(t, "aaaa", got)
	})

	t.Run("surfaces read errors with whatever was read so far", func(t *testing.T) {
		boom := errors.New("network broke")
		resp := &http.Response{
			StatusCode: 500,
			Body:       &errReader{prefix: []byte("partial"), err: boom},
		}

		got, err := ReadErrorBody(resp, 1024)
		require.Error(t, err)
		require.ErrorIs(t, err, boom)
		require.Equal(t, "partial", got)
	})
}
