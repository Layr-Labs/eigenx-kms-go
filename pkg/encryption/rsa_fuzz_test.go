package encryption

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	fuzzPrivKeyPEM []byte
	fuzzPubKeyPEM  []byte
)

func init() {
	// Generate once to avoid expensive keygen in each fuzz iteration.
	// Uses 1024-bit keys for speed in fuzzing only - production code enforces 2048+.
	priv, pub, err := GenerateKeyPairForTesting(1024)
	if err == nil {
		fuzzPrivKeyPEM = priv
		fuzzPubKeyPEM = pub
	}
}

func FuzzRSAEncryptDecrypt(f *testing.F) {
	if fuzzPrivKeyPEM == nil || fuzzPubKeyPEM == nil {
		f.Skip("failed to generate RSA keypair for fuzzing")
	}

	const maxOAEPMsgLen = 60 // conservatively below 1024-bit OAEP(SHA-256) limit (~62 bytes)
	f.Add([]byte("hello"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		// Keep message within OAEP limit for 1024-bit keys (~86 bytes with SHA-256).
		if len(plaintext) > maxOAEPMsgLen {
			plaintext = plaintext[:maxOAEPMsgLen]
		}

		r := NewRSAEncryption()

		// Use testing variants that skip key size validation.
		ciphertext, err := r.EncryptForTesting(plaintext, fuzzPubKeyPEM)
		require.NoError(t, err)

		decrypted, err := r.DecryptForTesting(ciphertext, fuzzPrivKeyPEM)
		require.NoError(t, err)
		require.Equal(t, plaintext, decrypted)
	})
}

func FuzzRSARejectsWeakKeys(f *testing.F) {
	// Test that production functions reject weak keys.
	f.Add([]byte("test data"))

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		const maxOAEPMsgLen = 60
		if len(plaintext) > maxOAEPMsgLen {
			plaintext = plaintext[:maxOAEPMsgLen]
		}

		r := NewRSAEncryption()

		// Production Encrypt should reject 1024-bit keys.
		_, err := r.Encrypt(plaintext, fuzzPubKeyPEM)
		require.Error(t, err, "Encrypt should reject weak 1024-bit key")
		require.Contains(t, err.Error(), "RSA key too weak")
	})
}
