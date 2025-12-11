package crypto

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/bls"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
	"github.com/stretchr/testify/require"
)

// deriveScalar deterministically maps arbitrary bytes into an Fr element.
func deriveScalar(b []byte) *fr.Element {
	h := sha256.Sum256(b)
	s := new(fr.Element)
	if err := s.SetBytes(h[:]); err != nil {
		// Fall back to zero on decode error to keep the fuzzer moving.
		s.SetZero()
	}
	// Avoid the zero scalar so we don't get identity results in group operations.
	if s.IsZero() {
		s.SetUint64(1)
	}
	return s
}

func FuzzAddG1MatchesLibrary(f *testing.F) {
	f.Add([]byte("a"), []byte("b"))
	f.Add([]byte("same"), []byte("same")) // identical scalars
	f.Add([]byte{}, []byte("b"))          // empty seed

	f.Fuzz(func(t *testing.T, seedA, seedB []byte) {
		scalarA := deriveScalar(seedA)
		scalarB := deriveScalar(seedB)

		pA, err := ScalarMulG1(G1Generator, scalarA)
		require.NoError(t, err)
		pB, err := ScalarMulG1(G1Generator, scalarB)
		require.NoError(t, err)

		result, err := AddG1(*pA, *pB)
		require.NoError(t, err)

		// Compute expected using the underlying library for cross-check.
		libPA, err := bls.ScalarMulG1(bls.G1Generator, scalarA)
		require.NoError(t, err)
		libPB, err := bls.ScalarMulG1(bls.G1Generator, scalarB)
		require.NoError(t, err)
		libSum, err := bls.AddG1(libPA, libPB)
		require.NoError(t, err)

		expected := &types.G1Point{CompressedBytes: libSum.Marshal()}
		require.True(t, expected.IsEqual(result), "AddG1 diverged from library addition")
	})
}

func FuzzAddG2MatchesLibrary(f *testing.F) {
	f.Add([]byte("a"), []byte("b"))
	f.Add([]byte("same"), []byte("same")) // identical scalars
	f.Add([]byte{}, []byte("b"))          // empty seed

	f.Fuzz(func(t *testing.T, seedA, seedB []byte) {
		scalarA := deriveScalar(seedA)
		scalarB := deriveScalar(seedB)

		pA, err := ScalarMulG2(G2Generator, scalarA)
		require.NoError(t, err)
		pB, err := ScalarMulG2(G2Generator, scalarB)
		require.NoError(t, err)

		result, err := AddG2(*pA, *pB)
		require.NoError(t, err)

		libPA, err := bls.ScalarMulG2(bls.G2Generator, scalarA)
		require.NoError(t, err)
		libPB, err := bls.ScalarMulG2(bls.G2Generator, scalarB)
		require.NoError(t, err)
		libSum, err := bls.AddG2(libPA, libPB)
		require.NoError(t, err)

		expected := &types.G2Point{CompressedBytes: libSum.Marshal()}
		require.True(t, expected.IsEqual(result), "AddG2 diverged from library addition")
	})
}

func FuzzRecoverAppPrivateKeyRoundTrip(f *testing.F) {
	f.Add("app-1", []byte("seed"), 3)
	f.Add("app-2", []byte("another"), 4)
	f.Add("app-3", []byte("edge"), 5)

	f.Fuzz(func(t *testing.T, appID string, seed []byte, n int) {
		if appID == "" {
			appID = "default-app"
		}
		if n < 3 {
			n = 3
		}
		if n > 7 {
			n = 7
		}

		threshold := (2*n + 2) / 3 // ⌈2n/3⌉

		// Generate a proper polynomial with threshold-1 degree.
		// The secret is the constant term.
		secret := deriveScalar(seed)
		poly := make(polynomial.Polynomial, threshold)
		poly[0].Set(secret)
		for i := 1; i < threshold; i++ {
			// Deterministically derive higher coefficients from seed + index.
			// Use a copy so we never mutate the fuzzer-provided seed (libFuzzer marks input const).
			coeffSeed := append(append([]byte{}, seed...), byte(i))
			poly[i].Set(deriveScalar(coeffSeed))
		}

		// Generate shares by evaluating at participant IDs.
		participants := make([]int, n)
		for i := 0; i < n; i++ {
			participants[i] = i + 1
		}

		appHash, err := HashToG1(appID)
		require.NoError(t, err)

		// Create partial signatures: partialSig_i = share_i * H(appID)
		allPartialSigs := make(map[int]types.G1Point, n)
		for _, id := range participants {
			share := EvaluatePolynomial(poly, int64(id))
			partial, err := ScalarMulG1(*appHash, share)
			require.NoError(t, err)
			allPartialSigs[id] = *partial
		}

		// Test 1: Recovery with exactly threshold shares should succeed.
		thresholdSigs := make(map[int]types.G1Point, threshold)
		for i := 0; i < threshold; i++ {
			id := participants[i]
			thresholdSigs[id] = allPartialSigs[id]
		}

		recovered, err := RecoverAppPrivateKey(appID, thresholdSigs, threshold)
		require.NoError(t, err)
		isRecoveredZero, err := recovered.IsZero()
		require.NoError(t, err)
		require.False(t, isRecoveredZero, "recovered key should not be zero")

		// Test 2: Recovery with all shares should produce the same result.
		recoveredAll, err := RecoverAppPrivateKey(appID, allPartialSigs, threshold)
		require.NoError(t, err)

		// Both recoveries should yield the same app private key: secret * H(appID).
		expectedAppPriv, err := ScalarMulG1(*appHash, secret)
		require.NoError(t, err)

		require.True(t, expectedAppPriv.IsEqual(recovered), "threshold recovery mismatch")
		require.True(t, expectedAppPriv.IsEqual(recoveredAll), "full recovery mismatch")
	})
}

func FuzzRecoverAppPrivateKeyInsufficientShares(f *testing.F) {
	f.Add("app-1", []byte("seed"))

	f.Fuzz(func(t *testing.T, appID string, seed []byte) {
		if appID == "" {
			appID = "default-app"
		}

		n := 5
		threshold := (2*n + 2) / 3 // threshold = 4 for n=5

		secret := deriveScalar(seed)
		poly := make(polynomial.Polynomial, threshold)
		poly[0].Set(secret)
		for i := 1; i < threshold; i++ {
			coeffSeed := append(append([]byte{}, seed...), byte(i))
			poly[i].Set(deriveScalar(coeffSeed))
		}

		appHash, err := HashToG1(appID)
		require.NoError(t, err)

		// Create only threshold-1 shares (insufficient).
		insufficientSigs := make(map[int]types.G1Point, threshold-1)
		for i := 1; i < threshold; i++ {
			share := EvaluatePolynomial(poly, int64(i))
			partial, err := ScalarMulG1(*appHash, share)
			require.NoError(t, err)
			insufficientSigs[i] = *partial
		}

		// RecoverAppPrivateKey should reject insufficient shares.
		_, err = RecoverAppPrivateKey(appID, insufficientSigs, threshold)
		require.Error(t, err, "should reject insufficient shares")
		require.Contains(t, err.Error(), "insufficient partial signatures")
	})
}

func FuzzEncryptDecryptRoundTrip(f *testing.F) {
	// NOTE: This tests the simplified XOR stub, not real IBE.
	// When real IBE is implemented, this test will need updates.
	f.Add("app-1", []byte("hello world"))
	f.Add("app-2", []byte{})       // empty plaintext
	f.Add("app-3", []byte{0, 255}) // binary data

	f.Fuzz(func(t *testing.T, appID string, plaintext []byte) {
		// Keep sizes manageable for fuzz runs.
		if len(appID) > 64 {
			appID = appID[:64]
		}
		if len(appID) < 5 {
			appID = appID + strings.Repeat("a", 5-len(appID))
		}
		if len(plaintext) > 512 {
			plaintext = plaintext[:512]
		}
		if appID == "" {
			appID = "default-app"
		}

		// Derive a deterministic but valid master public key and matching app private key: s*H(appID).
		scalar := deriveScalar([]byte(appID))
		appHash, err := HashToG1(appID)
		require.NoError(t, err)
		masterPK, err := ScalarMulG2(G2Generator, scalar)
		require.NoError(t, err)

		ciphertext, err := EncryptForApp(appID, *masterPK, plaintext)
		require.NoError(t, err)

		// Use matching app private key: s * H(appID).
		appPriv, err := ScalarMulG1(*appHash, scalar)
		require.NoError(t, err)

		decrypted, err := DecryptForApp(appID, *appPriv, ciphertext)
		require.NoError(t, err)
		require.True(t, bytes.Equal(plaintext, decrypted), "decrypted plaintext mismatch")
	})
}

func FuzzEncryptDecryptWrongAppID(f *testing.F) {
	// Test that decryption with wrong appID fails (for XOR stub, produces wrong plaintext).
	f.Add("app-correct", "app-wrong", []byte("secret data"))

	f.Fuzz(func(t *testing.T, correctAppID, wrongAppID string, plaintext []byte) {
		if correctAppID == "" {
			correctAppID = "correct-app"
		}
		if len(correctAppID) < 5 {
			correctAppID = correctAppID + strings.Repeat("a", 5-len(correctAppID))
		}
		if wrongAppID == "" || wrongAppID == correctAppID {
			wrongAppID = correctAppID + "-wrong"
		}
		if len(wrongAppID) < 5 {
			wrongAppID = wrongAppID + strings.Repeat("b", 5-len(wrongAppID))
		}
		if len(plaintext) > 256 {
			plaintext = plaintext[:256]
		}
		if len(plaintext) == 0 {
			plaintext = []byte("default")
		}

		scalar := deriveScalar([]byte(correctAppID))
		masterPK, err := ScalarMulG2(G2Generator, scalar)
		require.NoError(t, err)

		ciphertext, err := EncryptForApp(correctAppID, *masterPK, plaintext)
		require.NoError(t, err)

		// Decrypt with wrong appID.
		wrongScalar := deriveScalar([]byte(wrongAppID))
		wrongHash, err := HashToG1(wrongAppID)
		require.NoError(t, err)
		wrongAppPriv, err := ScalarMulG1(*wrongHash, wrongScalar)
		require.NoError(t, err)

		decrypted, err := DecryptForApp(wrongAppID, *wrongAppPriv, ciphertext)
		// For XOR stub: decryption succeeds but produces wrong plaintext.
		// For real IBE: would produce garbage or fail pairing check.
		if err == nil {
			require.NotEqual(t, plaintext, decrypted, "wrong appID should produce wrong plaintext")
		}
	})
}
