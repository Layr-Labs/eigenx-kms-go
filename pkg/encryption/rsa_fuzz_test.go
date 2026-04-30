package encryption

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// generateWeakKeyPair generates an RSA key pair without the MinRSAKeyBits check.
// Only for fuzz testing — production code must use GenerateKeyPair.
func generateWeakKeyPair(bits int) (privateKeyPEM, publicKeyPEM []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return privKeyPEM, pubKeyPEM, nil
}

// encryptNoMinKeySize encrypts without the MinRSAKeyBits check.
// Only for fuzz testing — production code must use RSAEncryption.Encrypt.
func encryptNoMinKeySize(plaintext, publicKeyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	pubkey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	rsaPubKey, ok := pubkey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, plaintext, nil)
}

// decryptNoMinKeySize decrypts without the MinRSAKeyBits check.
// Only for fuzz testing — production code must use RSAEncryption.Decrypt.
func decryptNoMinKeySize(ciphertext, privateKeyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	privkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		privkeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		privkey, ok = privkeyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privkey, ciphertext, nil)
}

var (
	fuzzPrivKeyPEM []byte
	fuzzPubKeyPEM  []byte
)

func init() {
	// Generate once to avoid expensive keygen in each fuzz iteration.
	// Uses 1024-bit keys for speed in fuzzing only - production code enforces 2048+.
	priv, pub, err := generateWeakKeyPair(1024)
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
	f.Add([]byte{})                       // empty plaintext
	f.Add(bytes.Repeat([]byte{0xFF}, 60)) // max bytes near OAEP limit
	f.Add([]byte{0x00, 0x01, 0x02})       // low bytes
	f.Add([]byte("a very long message that tests boundary conditions"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		// Keep message within OAEP limit for 1024-bit keys (~86 bytes with SHA-256).
		if len(plaintext) > maxOAEPMsgLen {
			plaintext = plaintext[:maxOAEPMsgLen]
		}

		ciphertext, err := encryptNoMinKeySize(plaintext, fuzzPubKeyPEM)
		require.NoError(t, err)

		decrypted, err := decryptNoMinKeySize(ciphertext, fuzzPrivKeyPEM)
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
