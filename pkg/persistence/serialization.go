package persistence

import (
	"encoding/json"
	"fmt"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// MarshalKeyShareVersion serializes a KeyShareVersion to JSON bytes.
// Uses standard JSON marshaling - fr.Element has built-in JSON support.
func MarshalKeyShareVersion(ksv *types.KeyShareVersion) ([]byte, error) {
	if ksv == nil {
		return nil, fmt.Errorf("cannot marshal nil KeyShareVersion")
	}

	data, err := json.Marshal(ksv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal KeyShareVersion to JSON: %w", err)
	}

	return data, nil
}

// UnmarshalKeyShareVersion deserializes a KeyShareVersion from JSON bytes.
// Uses standard JSON unmarshaling - fr.Element has built-in JSON support.
func UnmarshalKeyShareVersion(data []byte) (*types.KeyShareVersion, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot unmarshal empty data")
	}

	var ksv types.KeyShareVersion
	if err := json.Unmarshal(data, &ksv); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to KeyShareVersion: %w", err)
	}

	return &ksv, nil
}

// MarshalNodeState serializes NodeState to JSON bytes.
func MarshalNodeState(ns *NodeState) ([]byte, error) {
	if ns == nil {
		return nil, fmt.Errorf("cannot marshal nil NodeState")
	}

	return json.Marshal(ns)
}

// UnmarshalNodeState deserializes NodeState from JSON bytes.
func UnmarshalNodeState(data []byte) (*NodeState, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot unmarshal empty data")
	}

	var ns NodeState
	if err := json.Unmarshal(data, &ns); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to NodeState: %w", err)
	}

	return &ns, nil
}

// MarshalProtocolSessionState serializes ProtocolSessionState to JSON bytes.
func MarshalProtocolSessionState(pss *ProtocolSessionState) ([]byte, error) {
	if pss == nil {
		return nil, fmt.Errorf("cannot marshal nil ProtocolSessionState")
	}

	return json.Marshal(pss)
}

// UnmarshalProtocolSessionState deserializes ProtocolSessionState from JSON bytes.
func UnmarshalProtocolSessionState(data []byte) (*ProtocolSessionState, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot unmarshal empty data")
	}

	var pss ProtocolSessionState
	if err := json.Unmarshal(data, &pss); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to ProtocolSessionState: %w", err)
	}

	return &pss, nil
}
