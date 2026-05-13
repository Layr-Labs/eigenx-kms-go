# Refactor NodeID from int64 to common.Address

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace opaque int64 nodeIDs (keccak hash of address) with `common.Address` throughout the codebase so logs are human-readable and the unnecessary hashing indirection is eliminated.

**Architecture:** The refactor proceeds bottom-up: first change the crypto/polynomial layer to accept `common.Address` and convert internally to `fr.Element` (using `new(fr.Element).SetBytes(address.Bytes())` — 20 bytes fits within BLS12-381's 32-byte scalar field). Then update the DKG/reshare layer, then the node/session/transport layer, then the client. Persisted `ParticipantIDs` changes from `[]int64` to `[]common.Address`. The `addressToNodeID` function and `util.AddressToNodeID` are deleted entirely.

**Tech Stack:** Go, gnark-crypto (BLS12-381 fr.Element), go-ethereum (common.Address), testify

---

## File Map

| Layer | Files | Change |
|-------|-------|--------|
| Crypto primitives | `pkg/bls/polynomial.go` | `int64` → `common.Address` in all public APIs; internal `addressToFr()` helper |
| Crypto wrapper | `pkg/crypto/bls.go` | Update signatures to match `pkg/bls` |
| DKG protocol | `pkg/dkg/dkg.go`, `pkg/dkg/mock_Protocol.go` | `int64` → `common.Address` in Protocol interface and DKG struct |
| Reshare protocol | `pkg/reshare/reshare.go` | `int64` → `common.Address` in Reshare struct |
| Types | `pkg/types/types.go` | `ParticipantIDs []common.Address`, `FromOperatorID`/`ToOperatorID`/`NodeID` → addresses |
| Persistence | `pkg/persistence/types.go`, `pkg/persistence/memory/memory.go` | Session shares/commitments/acks maps keyed by address string |
| Node core | `pkg/node/node.go` | Session maps, all `addressToNodeID` calls removed |
| Node handlers | `pkg/node/handlers.go` | `senderNodeID` replaced by `senderAddress` |
| Transport | `pkg/transport/client.go` | Remove `nodeID int64` field, use address directly |
| KMS Client | `pkg/clients/kmsClient/client.go` | `map[int64]types.G1Point` → `map[common.Address]types.G1Point` |
| Util (DELETE) | `pkg/util/util.go` | Remove `AddressToNodeID` function |
| All `*_test.go` in above packages | Update to use addresses instead of int64 IDs |

---

### Task 1: Add `AddressToFr` helper in `pkg/bls/polynomial.go`

**Files:**
- Modify: `pkg/bls/polynomial.go`
- Create: `pkg/bls/polynomial_address_test.go`

This is the foundation — a function that converts `common.Address` (20 bytes) to an `fr.Element` for polynomial math. This replaces the `SetInt64(nodeID)` pattern.

- [ ] **Step 1: Write the failing test**

Create `pkg/bls/polynomial_address_test.go`:

```go
package bls

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestAddressToFr(t *testing.T) {
	addr := common.HexToAddress("0x144c70563952f6f60E3ee94608d70352D7b8b99c")

	result := AddressToFr(addr)
	require.NotNil(t, result)
	require.False(t, result.IsZero(), "non-zero address should produce non-zero field element")

	// Deterministic: same address always gives same result
	result2 := AddressToFr(addr)
	require.True(t, result.Equal(result2))

	// Different address gives different result
	addr2 := common.HexToAddress("0x0351aD97FA3045567D4EaA0004cfFB3DE4Fd95aE")
	result3 := AddressToFr(addr2)
	require.False(t, result.Equal(result3))
}

func TestAddressToFr_ZeroAddress(t *testing.T) {
	addr := common.Address{}
	result := AddressToFr(addr)
	require.NotNil(t, result)
	require.True(t, result.IsZero(), "zero address should produce zero field element")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/bls/ -run TestAddressToFr -v -count=1`
Expected: FAIL — `AddressToFr` undefined

- [ ] **Step 3: Implement `AddressToFr`**

Add to `pkg/bls/polynomial.go`:

```go
import "github.com/ethereum/go-ethereum/common"

// AddressToFr converts an Ethereum address to a BLS12-381 scalar field element.
// The 20-byte address is right-padded to 32 bytes and interpreted as a big-endian integer.
// This is used as the evaluation point in polynomial secret sharing (Shamir).
func AddressToFr(addr common.Address) *fr.Element {
	var buf [32]byte
	copy(buf[12:], addr.Bytes()) // right-align 20 bytes in 32-byte buffer (big-endian)
	var elem fr.Element
	elem.SetBytes(buf[:])
	return &elem
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/bls/ -run TestAddressToFr -v -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/bls/polynomial.go pkg/bls/polynomial_address_test.go
git commit -m "feat: add AddressToFr helper for address-based polynomial evaluation"
```

---

### Task 2: Add address-based polynomial functions in `pkg/bls/polynomial.go`

**Files:**
- Modify: `pkg/bls/polynomial.go`
- Create: `pkg/bls/polynomial_address_test.go` (append tests)

Add new function signatures that accept `common.Address` alongside the existing int64 ones. The old ones will be removed in a later task once all callers are migrated.

- [ ] **Step 1: Write failing tests**

Append to `pkg/bls/polynomial_address_test.go`:

```go
func TestEvaluatePolynomialAddr(t *testing.T) {
	// Create a simple polynomial: f(x) = 3 + 2x
	poly := make(polynomial.Polynomial, 2)
	poly[0].SetInt64(3)
	poly[1].SetInt64(2)

	addr := common.HexToAddress("0x0000000000000000000000000000000000000001")
	result := EvaluatePolynomialAddr(poly, addr)
	require.NotNil(t, result)

	// f(1) = 3 + 2*1 = 5
	expected := new(fr.Element).SetInt64(5)
	require.True(t, result.Equal(expected), "EvaluatePolynomialAddr(poly, addr(1)) should equal 5")
}

func TestComputeLagrangeCoefficientAddr(t *testing.T) {
	// Simple 2-of-3 scenario: participants at addresses 1, 2, 3
	addr1 := common.HexToAddress("0x0000000000000000000000000000000000000001")
	addr2 := common.HexToAddress("0x0000000000000000000000000000000000000002")
	addr3 := common.HexToAddress("0x0000000000000000000000000000000000000003")

	participants := []common.Address{addr1, addr2, addr3}
	lambda := ComputeLagrangeCoefficientAddr(addr1, participants)
	require.NotNil(t, lambda)
	require.False(t, lambda.IsZero())
}

func TestRecoverSecretAddr(t *testing.T) {
	// Create polynomial f(x) = 42 + 7x (secret = 42, degree 1, threshold 2)
	secret := new(fr.Element).SetInt64(42)
	poly := make(polynomial.Polynomial, 2)
	poly[0].Set(secret)
	poly[1].SetInt64(7)

	addr1 := common.HexToAddress("0x0000000000000000000000000000000000000001")
	addr2 := common.HexToAddress("0x0000000000000000000000000000000000000002")
	addr3 := common.HexToAddress("0x0000000000000000000000000000000000000003")

	shares := map[common.Address]*fr.Element{
		addr1: EvaluatePolynomialAddr(poly, addr1),
		addr2: EvaluatePolynomialAddr(poly, addr2),
		addr3: EvaluatePolynomialAddr(poly, addr3),
	}

	recovered, err := RecoverSecretAddr(shares)
	require.NoError(t, err)
	require.True(t, recovered.Equal(secret), "recovered secret should equal 42")
}

func TestGenerateSharesAddr(t *testing.T) {
	secret := new(fr.Element).SetInt64(100)
	poly := make(polynomial.Polynomial, 2)
	poly[0].Set(secret)
	poly[1].SetInt64(5)

	addrs := []common.Address{
		common.HexToAddress("0x0000000000000000000000000000000000000001"),
		common.HexToAddress("0x0000000000000000000000000000000000000002"),
	}

	shares := GenerateSharesAddr(poly, addrs)
	require.Len(t, shares, 2)
	for _, addr := range addrs {
		require.NotNil(t, shares[addr])
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/bls/ -run "TestEvaluatePolynomialAddr|TestComputeLagrangeCoefficientAddr|TestRecoverSecretAddr|TestGenerateSharesAddr" -v -count=1`
Expected: FAIL — functions undefined

- [ ] **Step 3: Implement the address-based functions**

Add to `pkg/bls/polynomial.go`:

```go
// EvaluatePolynomialAddr evaluates a polynomial at the point derived from an Ethereum address.
func EvaluatePolynomialAddr(poly polynomial.Polynomial, addr common.Address) *fr.Element {
	xFr := AddressToFr(addr)
	result := poly.Eval(xFr)
	return &result
}

// ComputeLagrangeCoefficientAddr computes the Lagrange coefficient for a participant
// identified by address, at evaluation point x=0.
func ComputeLagrangeCoefficientAddr(i common.Address, participants []common.Address) *fr.Element {
	numerator := new(fr.Element).SetOne()
	denominator := new(fr.Element).SetOne()

	iFr := AddressToFr(i)

	for _, j := range participants {
		if i != j {
			jFr := AddressToFr(j)

			negJ := new(fr.Element).Neg(jFr)
			numerator.Mul(numerator, negJ)

			diff := new(fr.Element).Sub(iFr, jFr)
			denominator.Mul(denominator, diff)
		}
	}

	lambda := new(fr.Element).Inverse(denominator)
	lambda.Mul(lambda, numerator)
	return lambda
}

// RecoverSecretAddr recovers the secret from shares keyed by address using Lagrange interpolation.
func RecoverSecretAddr(shares map[common.Address]*fr.Element) (*fr.Element, error) {
	participants := make([]common.Address, 0, len(shares))
	for addr := range shares {
		participants = append(participants, addr)
	}

	secret := new(fr.Element).SetZero()

	for addr, share := range shares {
		lambda := ComputeLagrangeCoefficientAddr(addr, participants)
		term := new(fr.Element).Mul(lambda, share)
		secret.Add(secret, term)
	}

	if secret.IsZero() {
		return nil, errors.New("secret cannot be zero, this should not happen")
	}
	return secret, nil
}

// GenerateSharesAddr generates shares for participants identified by addresses.
func GenerateSharesAddr(poly polynomial.Polynomial, participants []common.Address) map[common.Address]*fr.Element {
	shares := make(map[common.Address]*fr.Element)
	for _, addr := range participants {
		shares[addr] = EvaluatePolynomialAddr(poly, addr)
	}
	return shares
}

// VerifyShareAddr verifies a share against polynomial commitments for a participant address.
func VerifyShareAddr(addr common.Address, share *fr.Element, commitments []*G2Point) (bool, error) {
	if len(commitments) == 0 {
		return false, errors.New("no commitments provided")
	}
	if share == nil {
		return false, errors.New("share is nil")
	}

	shareCommitment, err := ScalarMulG2(G2Generator, share)
	if err != nil {
		return false, fmt.Errorf("failed to compute share commitment: %w", err)
	}

	nodeFr := AddressToFr(addr)
	powers := make([]fr.Element, len(commitments))
	powers[0].SetOne()
	for i := 1; i < len(commitments); i++ {
		powers[i].Mul(&powers[i-1], nodeFr)
	}

	commitmentPoints := make([]bls12381.G2Affine, len(commitments))
	for i, c := range commitments {
		if c == nil || c.point == nil {
			return false, fmt.Errorf("nil commitment at index %d", i)
		}
		commitmentPoints[i] = *c.point
	}

	var expectedCommitment bls12381.G2Affine
	if _, err := expectedCommitment.MultiExp(commitmentPoints, powers, ecc.MultiExpConfig{}); err != nil {
		return false, fmt.Errorf("failed to compute expected commitment: %w", err)
	}

	return shareCommitment.point.Equal(&expectedCommitment), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/bls/ -run "TestEvaluatePolynomialAddr|TestComputeLagrangeCoefficientAddr|TestRecoverSecretAddr|TestGenerateSharesAddr" -v -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/bls/polynomial.go pkg/bls/polynomial_address_test.go
git commit -m "feat: add address-based polynomial, Lagrange, and share functions"
```

---

### Task 3: Add address-based wrappers in `pkg/crypto/bls.go`

**Files:**
- Modify: `pkg/crypto/bls.go`

- [ ] **Step 1: Add wrapper functions that delegate to `pkg/bls`**

```go
// AddressToFr converts an Ethereum address to a BLS12-381 scalar field element.
func AddressToFr(addr common.Address) *fr.Element {
	return bls.AddressToFr(addr)
}

// EvaluatePolynomialAddr evaluates a polynomial at the point derived from an address.
func EvaluatePolynomialAddr(poly polynomial.Polynomial, addr common.Address) *fr.Element {
	return bls.EvaluatePolynomialAddr(poly, addr)
}

// ComputeLagrangeCoefficientAddr computes Lagrange coefficient for an address-identified participant.
func ComputeLagrangeCoefficientAddr(i common.Address, participants []common.Address) *fr.Element {
	return bls.ComputeLagrangeCoefficientAddr(i, participants)
}

// RecoverSecretAddr recovers secret from address-keyed shares using Lagrange interpolation.
func RecoverSecretAddr(shares map[common.Address]*fr.Element) (*fr.Element, error) {
	return bls.RecoverSecretAddr(shares)
}

// RecoverAppPrivateKeyAddr recovers app private key from address-keyed partial signatures.
func RecoverAppPrivateKeyAddr(appID string, partialSigs map[common.Address]types.G1Point, threshold int) (*types.G1Point, error) {
	if len(partialSigs) < threshold {
		return nil, fmt.Errorf("insufficient partial signatures: got %d, need %d", len(partialSigs), threshold)
	}

	participants := make([]common.Address, 0, len(partialSigs))
	for addr := range partialSigs {
		participants = append(participants, addr)
	}
	sort.Slice(participants, func(i, j int) bool {
		return bytes.Compare(participants[i].Bytes(), participants[j].Bytes()) < 0
	})
	if len(participants) > threshold {
		participants = participants[:threshold]
	}

	result := types.ZeroG1Point()
	for _, addr := range participants {
		lambda := ComputeLagrangeCoefficientAddr(addr, participants)
		scaledSig, err := ScalarMulG1(partialSigs[addr], lambda)
		if err != nil {
			return nil, err
		}
		summed, err := AddG1Points(*result, *scaledSig)
		if err != nil {
			return nil, err
		}
		result = summed
	}

	isZero, err := result.IsZero()
	if err != nil {
		return nil, fmt.Errorf("failed to check if recovered key is zero: %w", err)
	}
	if isZero {
		return nil, fmt.Errorf("recovered app private key is the zero point (identity)")
	}
	return result, nil
}

// RecoverAppPrivateKeyWithRetryAddr is the address-keyed version of RecoverAppPrivateKeyWithRetry.
func RecoverAppPrivateKeyWithRetryAddr(
	appID string,
	partialSigs map[common.Address]types.G1Point,
	threshold int,
	validate func(*types.G1Point) bool,
) (*types.G1Point, error) {
	return recoverAppPrivateKeyWithRetryAddr(appID, partialSigs, threshold, validate, DefaultMaxRecoveryAttempts)
}

func recoverAppPrivateKeyWithRetryAddr(
	appID string,
	partialSigs map[common.Address]types.G1Point,
	threshold int,
	validate func(*types.G1Point) bool,
	maxAttempts int,
) (*types.G1Point, error) {
	if len(partialSigs) < threshold {
		return nil, fmt.Errorf("insufficient partial signatures: got %d, need %d", len(partialSigs), threshold)
	}

	allParticipants := make([]common.Address, 0, len(partialSigs))
	for addr := range partialSigs {
		allParticipants = append(allParticipants, addr)
	}
	sort.Slice(allParticipants, func(i, j int) bool {
		return bytes.Compare(allParticipants[i].Bytes(), allParticipants[j].Bytes()) < 0
	})

	trySubset := func(subset []common.Address) (*types.G1Point, bool) {
		subsetSigs := make(map[common.Address]types.G1Point, len(subset))
		for _, addr := range subset {
			subsetSigs[addr] = partialSigs[addr]
		}
		recovered, err := RecoverAppPrivateKeyAddr(appID, subsetSigs, threshold)
		if err != nil {
			return nil, false
		}
		if validate(recovered) {
			return recovered, true
		}
		return nil, false
	}

	n := len(allParticipants)
	indices := make([]int, threshold)
	for i := range indices {
		indices[i] = i
	}

	attempts := 0
	for {
		if attempts >= maxAttempts {
			return nil, fmt.Errorf("exhausted %d recovery attempts without finding valid key", maxAttempts)
		}
		subset := make([]common.Address, threshold)
		for i, idx := range indices {
			subset[i] = allParticipants[idx]
		}
		if result, ok := trySubset(subset); ok {
			return result, nil
		}
		attempts++

		// Advance to next combination
		i := threshold - 1
		for i >= 0 && indices[i] == n-threshold+i {
			i--
		}
		if i < 0 {
			return nil, fmt.Errorf("all %d combinations exhausted without finding valid key", attempts)
		}
		indices[i]++
		for j := i + 1; j < threshold; j++ {
			indices[j] = indices[j-1] + 1
		}
	}
}
```

- [ ] **Step 2: Run existing tests to verify nothing broke**

Run: `go test ./pkg/crypto/ -v -count=1`
Expected: PASS (existing tests still use int64 versions)

- [ ] **Step 3: Commit**

```bash
git add pkg/crypto/bls.go
git commit -m "feat: add address-based crypto functions alongside int64 versions"
```

---

### Task 4: Update `pkg/types/types.go`

**Files:**
- Modify: `pkg/types/types.go`

- [ ] **Step 1: Change `ParticipantIDs` and operator ID fields to `common.Address`**

```go
// In KeyShareVersion:
ParticipantIDs  []common.Address // Which participants were in the operator set for this version

// In CompletionSignature:
NodeAddress      common.Address  // (was NodeID int64)

// In CommitmentBroadcast:
FromOperatorAddress common.Address // (was FromOperatorID int64)

// In CommitmentBroadcastMessage:
// Remove FromOperatorID and ToOperatorID int64 fields (redundant with FromOperatorAddress/ToOperatorAddress)
```

Changes to `CommitmentBroadcastMessage`:
```go
type CommitmentBroadcastMessage struct {
	FromOperatorAddress common.Address       `json:"fromOperatorAddress"`
	ToOperatorAddress   common.Address       `json:"toOperatorAddress"`
	SessionTimestamp    int64                `json:"sessionTimestamp"`
	Broadcast           *CommitmentBroadcast `json:"broadcast"`
}
```

Changes to `CommitmentBroadcast`:
```go
type CommitmentBroadcast struct {
	FromOperatorAddress common.Address     // Operator sending the broadcast
	SessionTimestamp    int64              // Block timestamp of the protocol session
	Commitments         []G2Point          // Dealer's polynomial commitments
	Acknowledgements    []*Acknowledgement // All n-1 acks collected as dealer
	MerkleProof         [][32]byte         // Merkle proof for specific recipient
}
```

- [ ] **Step 2: This will break compilation in many packages — that's expected at this stage**

The remaining tasks fix callers layer by layer. Do NOT attempt to compile yet.

- [ ] **Step 3: Commit**

```bash
git add pkg/types/types.go
git commit -m "refactor: change nodeID fields in types to common.Address"
```

---

### Task 5: Update `pkg/dkg/dkg.go` and `pkg/reshare/reshare.go`

**Files:**
- Modify: `pkg/dkg/dkg.go`
- Modify: `pkg/reshare/reshare.go`

- [ ] **Step 1: Change DKG struct and interface**

In `pkg/dkg/dkg.go`, change:
- `nodeID int64` → `nodeAddress common.Address`
- `NewDKG(nodeID int64, ...)` → `NewDKG(nodeAddress common.Address, ...)`
- `GenerateShares() (map[int64]*fr.Element, ...)` → `GenerateShares() (map[common.Address]*fr.Element, ...)`
- `FinalizeKeyShare(shares map[int64]*fr.Element, ..., participantIDs []int64)` → `FinalizeKeyShare(shares map[common.Address]*fr.Element, ..., participantIDs []common.Address)`
- All internal `int64` nodeID usages → `common.Address`
- Replace `util.AddressToNodeID(op.OperatorAddress)` with `op.OperatorAddress` directly
- Replace `crypto.EvaluatePolynomial(d.poly, int64(opNodeID))` with `crypto.EvaluatePolynomialAddr(d.poly, op.OperatorAddress)`
- Replace `new(fr.Element).SetInt64(int64(d.nodeID))` with `bls.AddressToFr(d.nodeAddress)`

- [ ] **Step 2: Change Reshare struct**

In `pkg/reshare/reshare.go`, same pattern:
- `nodeID int64` → `nodeAddress common.Address`
- `NewReshare(nodeID int64, ...)` → `NewReshare(nodeAddress common.Address, ...)`
- `GenerateNewShares(...)` returns `map[common.Address]*fr.Element`
- `ComputeNewKeyShare(dealerIDs []int64, shares map[int64]*fr.Element, ...)` → `ComputeNewKeyShare(dealers []common.Address, shares map[common.Address]*fr.Element, ...)`
- Replace `crypto.EvaluatePolynomial(r.poly, int64(opNodeID))` with `crypto.EvaluatePolynomialAddr(r.poly, op.OperatorAddress)`
- Replace `new(fr.Element).SetInt64(r.nodeID)` with `bls.AddressToFr(r.nodeAddress)`

- [ ] **Step 3: Regenerate or update `pkg/dkg/mock_Protocol.go`**

Update the mock to match new interface signatures.

- [ ] **Step 4: Commit**

```bash
git add pkg/dkg/ pkg/reshare/
git commit -m "refactor: DKG and reshare use common.Address instead of int64 nodeID"
```

---

### Task 6: Update `pkg/node/node.go` — ProtocolSession and maps

**Files:**
- Modify: `pkg/node/node.go`

- [ ] **Step 1: Change ProtocolSession maps from int64 keys to common.Address keys**

```go
type ProtocolSession struct {
    // ...
    shares      map[common.Address]*fr.Element
    commitments map[common.Address][]types.G2Point
    acks        map[common.Address]map[common.Address]*types.Acknowledgement
    // ...
    verifiedOperators map[common.Address]bool
}
```

- [ ] **Step 2: Remove `addressToNodeID` variable and all calls**

Delete:
```go
var addressToNodeID = util.AddressToNodeID
```

Replace all `addressToNodeID(op.OperatorAddress)` → `op.OperatorAddress` throughout.
Replace all `thisNodeID := addressToNodeID(n.OperatorAddress)` → `thisAddr := n.OperatorAddress`.

- [ ] **Step 3: Update all session method signatures**

- `HandleReceivedShare(senderNodeID int64, ...)` → `HandleReceivedShare(sender common.Address, ...)`
- `HandleReceivedCommitment(senderNodeID int64, ...)` → `HandleReceivedCommitment(sender common.Address, ...)`
- `HandleReceivedAck(dealerNodeID, playerNodeID int64, ...)` → `HandleReceivedAck(dealer, player common.Address, ...)`

- [ ] **Step 4: Update `waitForAcks` and threshold logic**

All references to `myNodeID` become `n.OperatorAddress`. The `waitForAcks` function signature changes from `waitForAcks(session, myNodeID int64, ...)` to `waitForAcks(session, myAddr common.Address, ...)`.

- [ ] **Step 5: Update `NewDKG` and `NewReshare` calls**

Replace:
```go
n.dkgProtocol = dkg.NewDKG(addressToNodeID(n.OperatorAddress), threshold, operators)
```
With:
```go
n.dkgProtocol = dkg.NewDKG(n.OperatorAddress, threshold, operators)
```

Same for `reshare.NewReshare`.

- [ ] **Step 6: Commit**

```bash
git add pkg/node/node.go
git commit -m "refactor: node.go uses common.Address instead of int64 nodeID"
```

---

### Task 7: Update `pkg/node/handlers.go`

**Files:**
- Modify: `pkg/node/handlers.go`

- [ ] **Step 1: Replace all `util.AddressToNodeID` calls with direct address usage**

Every handler that does:
```go
senderNodeID := util.AddressToNodeID(senderPeer.OperatorAddress)
```
Becomes:
```go
senderAddr := senderPeer.OperatorAddress
```

And uses `senderAddr` in session method calls.

- [ ] **Step 2: Commit**

```bash
git add pkg/node/handlers.go
git commit -m "refactor: handlers use common.Address directly"
```

---

### Task 8: Update `pkg/transport/client.go`

**Files:**
- Modify: `pkg/transport/client.go`

- [ ] **Step 1: Remove `nodeID int64` field from Client struct**

```go
type Client struct {
    operatorAddr common.Address
    signer       transportSigner.ITransportSigner
}
```

Update `NewClient` signature — remove `nodeID int64` parameter.
Update `CommitmentBroadcastMessage` construction to remove `FromOperatorID`/`ToOperatorID`.

- [ ] **Step 2: Commit**

```bash
git add pkg/transport/client.go
git commit -m "refactor: transport client uses address, removes int64 nodeID"
```

---

### Task 9: Update `pkg/clients/kmsClient/client.go`

**Files:**
- Modify: `pkg/clients/kmsClient/client.go`

- [ ] **Step 1: Change `map[int64]types.G1Point` to `map[common.Address]types.G1Point`**

All functions that collect/return partial signatures switch from int64-keyed maps to address-keyed maps:
- `CollectPartialSignatures` returns `map[common.Address]types.G1Point`
- `decryptWithRetry` accepts `map[common.Address]types.G1Point`
- `collectPartialSignaturesForDecrypt` returns `map[common.Address]types.G1Point`
- Internal result structs: `nodeID int64` → `operatorAddr common.Address`

Replace `util.AddressToNodeID(op.OperatorAddress)` with `op.OperatorAddress`.

- [ ] **Step 2: Commit**

```bash
git add pkg/clients/kmsClient/client.go
git commit -m "refactor: kmsClient uses address-keyed partial signature maps"
```

---

### Task 10: Update persistence layer

**Files:**
- Modify: `pkg/persistence/types.go`
- Modify: `pkg/persistence/memory/memory.go`
- Modify: any other persistence implementations (badger, redis if present)

- [ ] **Step 1: Change `ProtocolSessionState.Shares` map key from `int64` to address string**

```go
type ProtocolSessionState struct {
    // ...
    Shares           map[string]string                      `json:"shares"`           // key: address hex
    Commitments      map[string][]types.G2Point             `json:"commitments"`      // key: address hex
    Acknowledgements map[string]map[string]*types.Acknowledgement `json:"acknowledgements"` // key: address hex
}
```

Note: JSON map keys must be strings, so `common.Address` is serialized as hex string (`addr.Hex()`).

- [ ] **Step 2: Update memory persistence to handle the new key format**

- [ ] **Step 3: Commit**

```bash
git add pkg/persistence/
git commit -m "refactor: persistence uses address strings for session map keys"
```

---

### Task 11: Delete `util.AddressToNodeID` and remove `addressToNodeID` seam

**Files:**
- Modify: `pkg/util/util.go` (remove function)
- Modify: `pkg/node/node.go` (remove `var addressToNodeID` line)

- [ ] **Step 1: Delete `AddressToNodeID` from `pkg/util/util.go`**

Remove lines 161-169.

- [ ] **Step 2: Delete `addressToNodeID` variable from `pkg/node/node.go`**

Remove lines 120-122.

- [ ] **Step 3: Remove `validateOperatorSetNoNodeIDCollisions` function**

This is no longer needed — `common.Address` uniqueness is guaranteed by the operator set (no hash collisions possible).

- [ ] **Step 4: Commit**

```bash
git add pkg/util/util.go pkg/node/node.go
git commit -m "refactor: remove AddressToNodeID and nodeID collision validation"
```

---

### Task 12: Update all tests

**Files:**
- Modify: All `*_test.go` files in `pkg/node/`, `pkg/dkg/`, `pkg/reshare/`, `pkg/crypto/`, `pkg/bls/`, `pkg/clients/kmsClient/`
- Modify: `internal/tests/integration/`

- [ ] **Step 1: Update node tests**

Tests that use `patchAddressToNodeID` or `int64` node IDs switch to using `common.Address` directly. The `patchAddressToNodeID` helper and related tests are deleted since there's no more indirection to patch.

Key changes:
- `operator_set_validation_test.go`: Remove nodeID collision tests (no longer possible)
- `reshare_validation_test.go`: `makeNodeWithKeyVersion` accepts `[]common.Address` for participantIDs
- `share_filtering_test.go`: `trustedDealerIDs` uses `common.Address` keys
- `reshare_returning_operator_test.go`: Uses addresses directly

- [ ] **Step 2: Update DKG/reshare tests**

Tests call `NewDKG(addr, ...)` instead of `NewDKG(int64, ...)`.

- [ ] **Step 3: Update crypto tests**

The `bls_test.go` existing tests that use `int64` remain (old API still exists temporarily or is removed). New tests use address-based functions.

- [ ] **Step 4: Run full test suite**

Run: `./scripts/goTest.sh ./...`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add .
git commit -m "refactor: update all tests to use common.Address instead of int64 nodeID"
```

---

### Task 13: Remove old int64-based functions (cleanup)

**Files:**
- Modify: `pkg/bls/polynomial.go` (remove old `EvaluatePolynomial`, `ComputeLagrangeCoefficient`, `RecoverSecret`, `GenerateShares`, `VerifyShare`)
- Modify: `pkg/crypto/bls.go` (remove old int64 wrappers)

- [ ] **Step 1: Remove deprecated int64 functions from `pkg/bls/polynomial.go`**

Remove: `EvaluatePolynomial`, `ComputeLagrangeCoefficient`, `RecoverSecret`, `GenerateShares`, `VerifyShare` (the int64 versions).

Rename the `*Addr` variants to drop the `Addr` suffix (they become the canonical versions):
- `EvaluatePolynomialAddr` → `EvaluatePolynomial`
- `ComputeLagrangeCoefficientAddr` → `ComputeLagrangeCoefficient`
- `RecoverSecretAddr` → `RecoverSecret`
- `GenerateSharesAddr` → `GenerateShares`
- `VerifyShareAddr` → `VerifyShare`

- [ ] **Step 2: Same rename in `pkg/crypto/bls.go`**

- [ ] **Step 3: Run full test suite**

Run: `./scripts/goTest.sh ./...`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add pkg/bls/ pkg/crypto/
git commit -m "refactor: remove deprecated int64 polynomial functions, rename Addr variants"
```

---

### Task 14: Final verification and cleanup

- [ ] **Step 1: Grep for any remaining int64 nodeID references**

Run: `grep -rn "AddressToNodeID\|addressToNodeID\|nodeID.*int64\|int64.*nodeID" pkg/ --include="*.go" | grep -v "_test.go"`
Expected: No matches (only timestamp-related int64 remain)

- [ ] **Step 2: Grep for stale comments referencing nodeID**

Run: `grep -rn "nodeID\|node_id\|node ID" pkg/ --include="*.go" | grep -v "nodeAddress\|node_address"`
Expected: Only log fields named "node_id" that now log addresses

- [ ] **Step 3: Run full test suite one final time**

Run: `./scripts/goTest.sh ./...`
Expected: All pass

- [ ] **Step 4: Commit any cleanup**

```bash
git add .
git commit -m "chore: final cleanup of stale nodeID references"
```
