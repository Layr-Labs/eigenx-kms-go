package persistence

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
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

	// Marshal to JSON
	data, err := MarshalKeyShareVersion(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from JSON
	restored, err := UnmarshalKeyShareVersion(data)
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

// TestMarshalKeyShareVersion_NilInput tests error handling for nil input
func TestMarshalKeyShareVersion_NilInput(t *testing.T) {
	_, err := MarshalKeyShareVersion(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil KeyShareVersion")
}

// TestUnmarshalKeyShareVersion_InvalidJSON tests error handling for invalid JSON
func TestUnmarshalKeyShareVersion_InvalidJSON(t *testing.T) {
	invalidJSON := []byte(`{"version": "not a number"}`)

	_, err := UnmarshalKeyShareVersion(invalidJSON)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal")
}

// TestUnmarshalKeyShareVersion_EmptyData tests error handling for empty data
func TestUnmarshalKeyShareVersion_EmptyData(t *testing.T) {
	_, err := UnmarshalKeyShareVersion([]byte{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty data")
}

// TestMarshalUnmarshalNodeState_RoundTrip tests NodeState serialization
func TestMarshalUnmarshalNodeState_RoundTrip(t *testing.T) {
	original := &NodeState{
		LastProcessedBoundary: 12345,
		NodeStartTime:         9876543210,
		OperatorAddress:       "0x1234567890abcdef",
	}

	// Marshal
	data, err := MarshalNodeState(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	restored, err := UnmarshalNodeState(data)
	require.NoError(t, err)
	require.NotNil(t, restored)

	// Verify
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
				2: {PlayerID: 2, DealerID: 1, Epoch: 1234567890},
			},
		},
	}

	// Marshal
	data, err := MarshalProtocolSessionState(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	restored, err := UnmarshalProtocolSessionState(data)
	require.NoError(t, err)
	require.NotNil(t, restored)

	// Verify
	assert.Equal(t, original.SessionTimestamp, restored.SessionTimestamp)
	assert.Equal(t, original.Type, restored.Type)
	assert.Equal(t, original.Phase, restored.Phase)
	assert.Equal(t, original.StartTime, restored.StartTime)
	assert.Equal(t, original.OperatorAddresses, restored.OperatorAddresses)
	assert.Equal(t, original.Shares, restored.Shares)
	assert.Equal(t, len(original.Commitments), len(restored.Commitments))
	assert.Equal(t, len(original.Acknowledgements), len(restored.Acknowledgements))
}
