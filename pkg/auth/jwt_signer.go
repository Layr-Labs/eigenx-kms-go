package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const jwtIssuer = "eigenx-kms"

type JWTSigner struct {
	privateKey *rsa.PrivateKey
	expiration time.Duration
}

func NewJWTSigner(privateKeyPEM string, expiration time.Duration) (*JWTSigner, error) {
	key, err := parseRSAPrivateKey([]byte(privateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}
	return &JWTSigner{
		privateKey: key,
		expiration: expiration,
	}, nil
}

func (s *JWTSigner) SignAttestationJWT(appID string, verified *attestation.VerifiedAttestation, audience, extraDataB64 string) (string, error) {
	now := time.Now()
	claims := NewAttestationJWTClaims(appID, verified)
	claims.ExtraData = extraDataB64

	token := jwt.New()
	if err := token.Set(jwt.IssuerKey, jwtIssuer); err != nil {
		return "", fmt.Errorf("failed to set issuer: %w", err)
	}
	if err := token.Set(jwt.SubjectKey, appID); err != nil {
		return "", fmt.Errorf("failed to set subject: %w", err)
	}
	if err := token.Set(jwt.IssuedAtKey, now); err != nil {
		return "", fmt.Errorf("failed to set issued at: %w", err)
	}
	if err := token.Set(jwt.ExpirationKey, now.Add(s.expiration)); err != nil {
		return "", fmt.Errorf("failed to set expiration: %w", err)
	}
	if audience != "" {
		if err := token.Set(jwt.AudienceKey, audience); err != nil {
			return "", fmt.Errorf("failed to set audience: %w", err)
		}
	}

	// Set rich attestation claims
	if err := token.Set("app_id", claims.AppID); err != nil {
		return "", fmt.Errorf("failed to set app_id: %w", err)
	}
	if err := token.Set("secboot", claims.SecBoot); err != nil {
		return "", fmt.Errorf("failed to set secboot: %w", err)
	}
	if err := token.Set("hwmodel", claims.HWModel); err != nil {
		return "", fmt.Errorf("failed to set hwmodel: %w", err)
	}
	if err := token.Set("hardened", claims.Hardened); err != nil {
		return "", fmt.Errorf("failed to set hardened: %w", err)
	}
	if err := token.Set("submods", claims.SubMods); err != nil {
		return "", fmt.Errorf("failed to set submods: %w", err)
	}
	if claims.TDX != nil {
		if err := token.Set("tdx", claims.TDX); err != nil {
			return "", fmt.Errorf("failed to set tdx: %w", err)
		}
	}
	if claims.SevSnp != nil {
		if err := token.Set("sevsnp", claims.SevSnp); err != nil {
			return "", fmt.Errorf("failed to set sevsnp: %w", err)
		}
	}
	if claims.ExtraData != "" {
		if err := token.Set("extra_data", claims.ExtraData); err != nil {
			return "", fmt.Errorf("failed to set extra_data: %w", err)
		}
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), s.privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return string(signed), nil
}

// PublicKey returns the public key corresponding to the signing private key.
func (s *JWTSigner) PublicKey() *rsa.PublicKey {
	return &s.privateKey.PublicKey
}

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	// Try PKCS8 first
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not an RSA private key")
		}
		return rsaKey, nil
	}

	// Fall back to PKCS1
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse as PKCS8 or PKCS1: %w", err)
	}
	return rsaKey, nil
}
