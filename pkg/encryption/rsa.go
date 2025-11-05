package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// RSAEncryption provides RSA encryption/decryption functionality
type RSAEncryption struct{}

// NewRSAEncryption creates a new RSA encryption instance
func NewRSAEncryption() *RSAEncryption {
	return &RSAEncryption{}
}

// Encrypt encrypts data with RSA public key using OAEP padding
func (e *RSAEncryption) Encrypt(plaintext, publicKeyPEM []byte) ([]byte, error) {
	// Parse PEM-encoded public key
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parse the public key
	pubkey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPubKey, ok := pubkey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	// Encrypt using OAEP with SHA-256
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	return ciphertext, nil
}

// Decrypt decrypts data with RSA private key using OAEP padding
func (e *RSAEncryption) Decrypt(ciphertext, privateKeyPEM []byte) ([]byte, error) {
	// Parse PEM-encoded private key
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parse the private key
	privkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
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

	// Decrypt using OAEP with SHA-256
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privkey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// GenerateKeyPair generates a new RSA key pair for testing
func GenerateKeyPair(bits int) (privateKeyPEM, publicKeyPEM []byte, err error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Encode private key to PEM
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	// Encode public key to PEM
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
