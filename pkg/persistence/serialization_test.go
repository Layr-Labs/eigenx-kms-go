package persistence

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMarshalUnmarshalKeyShareVersion_RoundTrip tests JSON marshaling/unmarshaling
func TestMarshalUnmarshalKeyShareVersion_RoundTrip(t *testing.T) {
	// Create a sample KeyShareVersion
	privateShare := fr.NewElement(uint64(98765))

	original := &types.KeyShareVersion{
		Version:      9876543210,
		PrivateShare: &privateShare,
		Commitments: []types.G2Point{
			{CompressedBytes: []byte{10, 20, 30}},
		},
		IsActive:       false,
		ParticipantIDs: []int64{10, 20, 30},
	}
	data, err := json.Marshal(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)
	var restored *types.KeyShareVersion
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)
	require.NotNil(t, restored)

	// Verify all fields match
	assert.Equal(t, original.Version, restored.Version)
	assert.Equal(t, original.IsActive, restored.IsActive)
	assert.Equal(t, original.ParticipantIDs, restored.ParticipantIDs)
	assert.Equal(t, len(original.Commitments), len(restored.Commitments))

	// Verify private share equality (fr.Element supports Cmp)
	assert.True(t, original.PrivateShare.Equal(restored.PrivateShare))
}

// TestMarshalUnmarshalKeyShareVersion_WithMasterPublicKey tests round-trip with MasterPublicKey
func TestMarshalUnmarshalKeyShareVersion_WithMasterPublicKey(t *testing.T) {
	privateShare := fr.NewElement(uint64(12345))
	mpk := &types.G2Point{CompressedBytes: []byte{99, 88, 77, 66}}

	original := &types.KeyShareVersion{
		Version:         1234567890,
		PrivateShare:    &privateShare,
		Commitments:     []types.G2Point{{CompressedBytes: []byte{10, 20, 30}}},
		MasterPublicKey: mpk,
		IsActive:        true,
		ParticipantIDs:  []int64{1, 2, 3},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var restored *types.KeyShareVersion
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)
	require.NotNil(t, restored)

	require.NotNil(t, restored.MasterPublicKey)
	assert.Equal(t, original.MasterPublicKey.CompressedBytes, restored.MasterPublicKey.CompressedBytes)
}

// TestUnmarshalKeyShareVersion_BackwardCompat tests that old data without MasterPublicKey deserializes correctly
func TestUnmarshalKeyShareVersion_BackwardCompat(t *testing.T) {
	// JSON without MasterPublicKey field (simulating data from old version)
	oldJSON := []byte(`{"Version":1234567890,"PrivateShare":null,"Commitments":[{"CompressedBytes":"CgoeHg=="}],"IsActive":true,"ParticipantIDs":[1,2,3]}`)

	var restored *types.KeyShareVersion
	err := json.Unmarshal(oldJSON, &restored)
	require.NoError(t, err)
	require.NotNil(t, restored)
	assert.Nil(t, restored.MasterPublicKey, "MasterPublicKey should be nil for old data without the field")
	assert.Equal(t, int64(1234567890), restored.Version)
	assert.True(t, restored.IsActive)
}

// TestMarshalKeyShareVersion_NilInput documents that json.Marshal of a nil
// pointer returns the literal "null" without error and without invoking
// MarshalJSON on the nil receiver.
func TestMarshalKeyShareVersion_NilInput(t *testing.T) {
	var nilVersion *types.KeyShareVersion
	result, err := json.Marshal(nilVersion)
	require.NoError(t, err)
	assert.Equal(t, []byte("null"), result)
}

// TestUnmarshalKeyShareVersion_TypeMismatch verifies that syntactically
// valid JSON with a mismatched field type produces an error.
func TestUnmarshalKeyShareVersion_TypeMismatch(t *testing.T) {
	invalidJSON := []byte(`{"version": "not a number"}`)

	var restored *types.KeyShareVersion
	err := json.Unmarshal(invalidJSON, &restored)
	require.Error(t, err)
}

// TestUnmarshalKeyShareVersion_EmptyData tests error handling for empty data
func TestUnmarshalKeyShareVersion_EmptyData(t *testing.T) {
	var restored *types.KeyShareVersion
	err := json.Unmarshal([]byte{}, &restored)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected end of JSON input")
}

// TestMarshalUnmarshalNodeState_RoundTrip tests NodeState serialization
func TestMarshalUnmarshalNodeState_RoundTrip(t *testing.T) {
	original := &NodeState{
		LastProcessedBoundary: 12345,
		NodeStartTime:         9876543210,
		OperatorAddress:       "0x1234567890abcdef",
	}
	data, err := json.Marshal(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)
	var restored *NodeState
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)
	require.NotNil(t, restored)
	assert.Equal(t, original.LastProcessedBoundary, restored.LastProcessedBoundary)
	assert.Equal(t, original.NodeStartTime, restored.NodeStartTime)
	assert.Equal(t, original.OperatorAddress, restored.OperatorAddress)
}

// TestMarshalUnmarshalProtocolSessionState_RoundTrip tests ProtocolSessionState serialization
func TestMarshalUnmarshalProtocolSessionState_RoundTrip(t *testing.T) {
	original := &ProtocolSessionState{
		SessionTimestamp:  1234567890,
		Type:              "dkg",
		Phase:             2,
		StartTime:         1234567800,
		OperatorAddresses: []string{"0x1234", "0x5678"},
		Shares: map[int64]string{
			1: "share1",
			2: "share2",
		},
		Commitments: map[int64][]types.G2Point{
			1: {{CompressedBytes: []byte{1, 2, 3}}},
			2: {{CompressedBytes: []byte{4, 5, 6}}},
		},
		Acknowledgements: map[int64]map[int64]*types.Acknowledgement{
			1: {
				2: {PlayerAddress: common.BigToAddress(big.NewInt(2)), DealerAddress: common.BigToAddress(big.NewInt(1)), SessionTimestamp: 1234567890},
			},
		},
	}
	data, err := json.Marshal(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)
	var restored *ProtocolSessionState
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)
	require.NotNil(t, restored)
	assert.Equal(t, original.SessionTimestamp, restored.SessionTimestamp)
	assert.Equal(t, original.Type, restored.Type)
	assert.Equal(t, original.Phase, restored.Phase)
	assert.Equal(t, original.StartTime, restored.StartTime)
	assert.Equal(t, original.OperatorAddresses, restored.OperatorAddresses)
	assert.Equal(t, original.Shares, restored.Shares)
	assert.Equal(t, len(original.Commitments), len(restored.Commitments))
	assert.Equal(t, len(original.Acknowledgements), len(restored.Acknowledgements))
}
