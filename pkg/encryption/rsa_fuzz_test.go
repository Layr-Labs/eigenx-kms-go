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
	priv, pub, err := GenerateKeyPair(1024)
	if err == nil {
		fuzzPrivKeyPEM = priv
		fuzzPubKeyPEM = pub
	}
}

func FuzzRSAEncryptDecrypt(f *testing.F) {
	if fuzzPrivKeyPEM == nil || fuzzPubKeyPEM == nil {
		f.Skip("failed to generate RSA keypair for fuzzing")
	}

	f.Add([]byte("hello"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		// Keep message within OAEP limit for 1024-bit keys (~86 bytes with SHA-256).
		if len(plaintext) > 80 {
			plaintext = plaintext[:80]
		}

		r := NewRSAEncryption()

		ciphertext, err := r.Encrypt(plaintext, fuzzPubKeyPEM)
		require.NoError(t, err)

		decrypted, err := r.Decrypt(ciphertext, fuzzPrivKeyPEM)
		require.NoError(t, err)
		require.Equal(t, plaintext, decrypted)
	})
}
