package bls

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddressToFr(t *testing.T) {
	t.Run("Non-zero address gives non-zero result", func(t *testing.T) {
		addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
		elem := AddressToFr(addr)
		assert.False(t, elem.IsZero(), "non-zero address should produce non-zero field element")
	})

	t.Run("Deterministic", func(t *testing.T) {
		addr := common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
		elem1 := AddressToFr(addr)
		elem2 := AddressToFr(addr)
		assert.True(t, elem1.Equal(elem2), "same address should produce same field element")
	})

	t.Run("Different addresses differ", func(t *testing.T) {
		addr1 := common.HexToAddress("0x0000000000000000000000000000000000000001")
		addr2 := common.HexToAddress("0x0000000000000000000000000000000000000002")
		elem1 := AddressToFr(addr1)
		elem2 := AddressToFr(addr2)
		assert.False(t, elem1.Equal(elem2), "different addresses should produce different field elements")
	})
}

func TestAddressToFr_ZeroAddress(t *testing.T) {
	addr := common.Address{}
	elem := AddressToFr(addr)
	assert.True(t, elem.IsZero(), "zero address should produce zero field element")
}

func TestEvaluatePolynomialAddr(t *testing.T) {
	t.Run("Address 0x...0001 maps to 1", func(t *testing.T) {
		// Address 0x0000...0001 should map to fr.Element(1)
		addr := common.HexToAddress("0x0000000000000000000000000000000000000001")

		// P(x) = 3 + 2x => P(1) = 5
		var coeff0, coeff1 fr.Element
		coeff0.SetInt64(3)
		coeff1.SetInt64(2)
		poly := polynomial.Polynomial{coeff0, coeff1}

		result := EvaluatePolynomialAddr(poly, addr)
		expected := new(fr.Element).SetInt64(5)
		assert.True(t, result.Equal(expected), "P(1) should equal 5")
	})

	t.Run("Matches int64 evaluation for small addresses", func(t *testing.T) {
		// Address 0x...0005 should give same result as evaluating at x=5
		addr := common.HexToAddress("0x0000000000000000000000000000000000000005")

		var coeff0, coeff1, coeff2 fr.Element
		coeff0.SetInt64(1)
		coeff1.SetInt64(2)
		coeff2.SetInt64(3)
		poly := polynomial.Polynomial{coeff0, coeff1, coeff2}

		addrResult := EvaluatePolynomialAddr(poly, addr)
		int64Result := EvaluatePolynomial(poly, 5)
		assert.True(t, addrResult.Equal(int64Result), "should match int64 evaluation for equivalent value")
	})
}

func TestComputeLagrangeCoefficientAddr(t *testing.T) {
	t.Run("Produces non-zero coefficient", func(t *testing.T) {
		participants := []common.Address{
			common.HexToAddress("0x0000000000000000000000000000000000000001"),
			common.HexToAddress("0x0000000000000000000000000000000000000002"),
			common.HexToAddress("0x0000000000000000000000000000000000000003"),
		}

		coeff := ComputeLagrangeCoefficientAddr(participants[0], participants)
		assert.False(t, coeff.IsZero(), "Lagrange coefficient should be non-zero")
	})

	t.Run("Matches int64 version for small addresses", func(t *testing.T) {
		participants := []common.Address{
			common.HexToAddress("0x0000000000000000000000000000000000000001"),
			common.HexToAddress("0x0000000000000000000000000000000000000002"),
			common.HexToAddress("0x0000000000000000000000000000000000000003"),
		}
		participantsInt := []int64{1, 2, 3}

		addrCoeff := ComputeLagrangeCoefficientAddr(participants[0], participants)
		intCoeff := ComputeLagrangeCoefficient(1, participantsInt)
		assert.True(t, addrCoeff.Equal(intCoeff), "should match int64 version for equivalent small values")
	})
}

func TestRecoverSecretAddr(t *testing.T) {
	t.Run("Recovers original secret from threshold shares", func(t *testing.T) {
		secret := new(fr.Element).SetInt64(42)
		degree := 2 // threshold = degree + 1 = 3

		poly, err := GeneratePolynomial(secret, degree)
		require.NoError(t, err)

		// Generate shares for 5 participants
		participants := []common.Address{
			common.HexToAddress("0x0000000000000000000000000000000000000001"),
			common.HexToAddress("0x0000000000000000000000000000000000000002"),
			common.HexToAddress("0x0000000000000000000000000000000000000003"),
			common.HexToAddress("0x0000000000000000000000000000000000000004"),
			common.HexToAddress("0x0000000000000000000000000000000000000005"),
		}

		allShares := GenerateSharesAddr(poly, participants)

		// Use threshold number of shares (degree + 1 = 3)
		thresholdShares := make(map[common.Address]*fr.Element)
		for i := 0; i < degree+1; i++ {
			thresholdShares[participants[i]] = allShares[participants[i]]
		}

		recovered, err := RecoverSecretAddr(thresholdShares)
		require.NoError(t, err)
		assert.True(t, recovered.Equal(secret), "recovered secret should match original")
	})

	t.Run("Different subsets recover same secret", func(t *testing.T) {
		secret := new(fr.Element).SetInt64(9999)
		degree := 2

		poly, err := GeneratePolynomial(secret, degree)
		require.NoError(t, err)

		participants := []common.Address{
			common.HexToAddress("0x0000000000000000000000000000000000000001"),
			common.HexToAddress("0x0000000000000000000000000000000000000002"),
			common.HexToAddress("0x0000000000000000000000000000000000000003"),
			common.HexToAddress("0x0000000000000000000000000000000000000004"),
			common.HexToAddress("0x0000000000000000000000000000000000000005"),
		}

		allShares := GenerateSharesAddr(poly, participants)

		// Subset 1: participants 0, 1, 2
		subset1 := make(map[common.Address]*fr.Element)
		subset1[participants[0]] = allShares[participants[0]]
		subset1[participants[1]] = allShares[participants[1]]
		subset1[participants[2]] = allShares[participants[2]]

		// Subset 2: participants 2, 3, 4
		subset2 := make(map[common.Address]*fr.Element)
		subset2[participants[2]] = allShares[participants[2]]
		subset2[participants[3]] = allShares[participants[3]]
		subset2[participants[4]] = allShares[participants[4]]

		recovered1, err := RecoverSecretAddr(subset1)
		require.NoError(t, err)

		recovered2, err := RecoverSecretAddr(subset2)
		require.NoError(t, err)

		assert.True(t, recovered1.Equal(recovered2), "different subsets should recover same secret")
		assert.True(t, recovered1.Equal(secret), "recovered secret should match original")
	})
}

func TestGenerateSharesAddr(t *testing.T) {
	t.Run("Generates correct number of shares", func(t *testing.T) {
		secret := new(fr.Element).SetInt64(100)
		poly, err := GeneratePolynomial(secret, 3)
		require.NoError(t, err)

		participants := []common.Address{
			common.HexToAddress("0x0000000000000000000000000000000000000001"),
			common.HexToAddress("0x0000000000000000000000000000000000000002"),
			common.HexToAddress("0x0000000000000000000000000000000000000003"),
			common.HexToAddress("0x0000000000000000000000000000000000000004"),
			common.HexToAddress("0x0000000000000000000000000000000000000005"),
		}

		shares := GenerateSharesAddr(poly, participants)
		assert.Equal(t, len(participants), len(shares), "should generate one share per participant")

		// Verify each participant has a share
		for _, addr := range participants {
			_, ok := shares[addr]
			assert.True(t, ok, "share should exist for participant %s", addr.Hex())
		}
	})

	t.Run("All shares are different", func(t *testing.T) {
		secret := new(fr.Element).SetInt64(777)
		poly, err := GeneratePolynomial(secret, 2)
		require.NoError(t, err)

		participants := []common.Address{
			common.HexToAddress("0x1111111111111111111111111111111111111111"),
			common.HexToAddress("0x2222222222222222222222222222222222222222"),
			common.HexToAddress("0x3333333333333333333333333333333333333333"),
		}

		shares := GenerateSharesAddr(poly, participants)

		// All shares should be distinct
		for i := 0; i < len(participants); i++ {
			for j := i + 1; j < len(participants); j++ {
				assert.False(t, shares[participants[i]].Equal(shares[participants[j]]),
					"shares for different participants should differ")
			}
		}
	})
}

func TestVerifyShareAddr(t *testing.T) {
	t.Run("Valid share passes verification", func(t *testing.T) {
		secret := new(fr.Element).SetInt64(12345)
		degree := 2

		poly, err := GeneratePolynomial(secret, degree)
		require.NoError(t, err)

		commitments, err := CreateCommitments(poly)
		require.NoError(t, err)

		addr := common.HexToAddress("0x0000000000000000000000000000000000000001")
		share := EvaluatePolynomialAddr(poly, addr)

		valid, err := VerifyShareAddr(addr, share, commitments)
		require.NoError(t, err)
		assert.True(t, valid, "valid share should pass verification")
	})

	t.Run("Invalid share fails verification", func(t *testing.T) {
		secret := new(fr.Element).SetInt64(12345)
		degree := 2

		poly, err := GeneratePolynomial(secret, degree)
		require.NoError(t, err)

		commitments, err := CreateCommitments(poly)
		require.NoError(t, err)

		addr := common.HexToAddress("0x0000000000000000000000000000000000000001")
		// Use a wrong share value
		wrongShare := new(fr.Element).SetInt64(99999)

		valid, err := VerifyShareAddr(addr, wrongShare, commitments)
		require.NoError(t, err)
		assert.False(t, valid, "invalid share should fail verification")
	})

	t.Run("Nil share returns error", func(t *testing.T) {
		addr := common.HexToAddress("0x0000000000000000000000000000000000000001")
		commitments := []*G2Point{{point: nil}}

		_, err := VerifyShareAddr(addr, nil, commitments)
		assert.Error(t, err)
	})

	t.Run("Empty commitments returns error", func(t *testing.T) {
		addr := common.HexToAddress("0x0000000000000000000000000000000000000001")
		share := new(fr.Element).SetInt64(1)

		_, err := VerifyShareAddr(addr, share, []*G2Point{})
		assert.Error(t, err)
	})
}
