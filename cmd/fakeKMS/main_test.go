package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"log/slog"
	"os"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper: build a server wired to a known scalar.
func newTestServer(t *testing.T, scalarHex string) (*server, types.G2Point) {
	t.Helper()
	masterBytes, err := hex.DecodeString(strings.TrimPrefix(scalarHex, "0x"))
	require.NoError(t, err)
	require.Equal(t, 32, len(masterBytes))
	var s fr.Element
	s.SetBytes(masterBytes)
	require.False(t, s.IsZero())

	mpk, err := crypto.ScalarMulG2(crypto.G2Generator, &s)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	mgr := attestation.NewAttestationManager(logger)
	method := attestation.NewEigenXSNPAttestationMethod(nil, logger)
	require.NoError(t, mgr.RegisterMethod(method))

	srv := &server{
		logger:             logger,
		masterScalar:       &s,
		masterPubKey:       *mpk,
		operatorAddress:    common.HexToAddress("0x000000000000000000000000000000000000beef"),
		attestationManager: mgr,
		appsCfg:            &appsConfig{index: map[string]*appEntry{}},
		rsa:                encryption.NewRSAEncryption(),
	}
	return srv, *mpk
}

func TestPubkey(t *testing.T) {
	srv, mpk := newTestServer(t, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")

	r := httptest.NewRequest(http.MethodGet, "/pubkey", nil)
	w := httptest.NewRecorder()
	srv.handlePubkey(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		OperatorAddress string          `json:"operatorAddress"`
		Commitments     []types.G2Point `json:"commitments"`
		MasterPublicKey *types.G2Point  `json:"masterPublicKey"`
		IsActive        bool            `json:"isActive"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.IsActive)
	require.NotNil(t, resp.MasterPublicKey)
	assert.Equal(t, mpk.CompressedBytes, resp.MasterPublicKey.CompressedBytes)
	require.Len(t, resp.Commitments, 1)
	assert.Equal(t, mpk.CompressedBytes, resp.Commitments[0].CompressedBytes)
}

// TestEndToEndIBE proves the fakeKMS partial signature is the real app
// private key by encrypting a message under the master public key and
// decrypting it with the recovered app private key.
func TestEndToEndIBE(t *testing.T) {
	srv, mpk := newTestServer(t, "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")

	appID := "app-ee:e2e"
	plaintext := []byte("the secret is the cake")

	// Encrypt plaintext under master pubkey for this app.
	ciphertext, err := crypto.EncryptForApp(appID, mpk, plaintext)
	require.NoError(t, err)

	// Hit /app/sign with the same appID.
	body, _ := json.Marshal(types.AppSignRequest{AppID: appID})
	r := httptest.NewRequest(http.MethodPost, "/app/sign", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleAppSign(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var signResp types.AppSignResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&signResp))

	// With threshold = 1 and one operator, the partial signature IS the app
	// private key; no Lagrange interpolation needed. Decrypt.
	recovered, err := crypto.DecryptForApp(appID, signResp.PartialSignature, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered)
}
