package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadRequest_HappyPath(t *testing.T) {
	in := Request{
		KMSURL:        "https://kms.example/secrets",
		AVSAddress:    "0xabc",
		OperatorSetID: 0,
		RPCURL:        "https://eth.example/v2/key",
		AppID:         "app-id",
		CiphertextHex: "deadbeef",
	}
	body, err := json.Marshal(in)
	require.NoError(t, err)

	got, err := readRequest(bytes.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, in.KMSURL, got.KMSURL)
	assert.Equal(t, in.AVSAddress, got.AVSAddress)
	assert.Equal(t, in.OperatorSetID, got.OperatorSetID)
	assert.Equal(t, in.RPCURL, got.RPCURL)
	assert.Equal(t, in.AppID, got.AppID)
	assert.Equal(t, in.CiphertextHex, got.CiphertextHex)
}

func TestReadRequest_MissingFields(t *testing.T) {
	tests := []struct {
		name        string
		req         Request
		expectedErr string
	}{
		{
			name: "missing avs_address",
			req: Request{
				RPCURL:        "https://eth.example",
				AppID:         "x",
				CiphertextHex: "00",
			},
			expectedErr: "avs_address is required",
		},
		{
			name: "missing rpc_url",
			req: Request{
				AVSAddress:    "0xabc",
				AppID:         "x",
				CiphertextHex: "00",
			},
			expectedErr: "rpc_url is required",
		},
		{
			name: "missing app_id",
			req: Request{
				AVSAddress:    "0xabc",
				RPCURL:        "https://eth.example",
				CiphertextHex: "00",
			},
			expectedErr: "app_id is required",
		},
		{
			name: "missing ciphertext_hex",
			req: Request{
				AVSAddress: "0xabc",
				RPCURL:     "https://eth.example",
				AppID:      "x",
			},
			expectedErr: "ciphertext_hex is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.req)
			require.NoError(t, err)
			_, err = readRequest(bytes.NewReader(body))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

func TestReadRequest_InvalidJSON(t *testing.T) {
	_, err := readRequest(strings.NewReader("not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode JSON")
}

func TestBuildReportData_Composition(t *testing.T) {
	rsaPub := []byte("-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----")
	extraData := []byte("extra")
	initData := []byte("initdata-document-bytes")

	got := buildReportData(rsaPub, extraData, initData)

	// must be exactly 64 bytes (the SEV-SNP REPORT_DATA field width)
	assert.Equal(t, 64, len(got))

	// lower 32 = SHA-256(rsaPub || extraData)
	want := sha256.Sum256(append(append([]byte{}, rsaPub...), extraData...))
	assert.Equal(t, want[:], got[:32])

	// upper 32 = SHA-384(initData)[:32]
	full := sha512.Sum384(initData)
	assert.Equal(t, full[:32], got[32:])
}

func TestBuildReportData_EmptyExtraData(t *testing.T) {
	rsaPub := []byte("pub")
	initData := []byte("init")

	got := buildReportData(rsaPub, nil, initData)
	want := sha256.Sum256(rsaPub)
	assert.Equal(t, want[:], got[:32])
}

func TestReportData_Base64URLRoundTrip(t *testing.T) {
	rsaPub := []byte("pub")
	extraData := []byte("ed")
	initData := []byte("init")

	rd := buildReportData(rsaPub, extraData, initData)
	encoded := base64.RawURLEncoding.EncodeToString(rd[:])
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.Equal(t, rd[:], decoded)
}
