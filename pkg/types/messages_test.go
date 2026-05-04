package types

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestDeserializeFr(t *testing.T) {
	tests := []struct {
		name    string
		input   *SerializedFrElement
		wantErr bool
	}{
		{
			name:    "nil input returns error",
			input:   nil,
			wantErr: true,
		},
		{
			name:    "empty string returns error",
			input:   &SerializedFrElement{Data: ""},
			wantErr: true,
		},
		{
			name:    "non-numeric string returns error",
			input:   &SerializedFrElement{Data: "not-a-number"},
			wantErr: true,
		},
		{
			name:    "valid element round-trips",
			input:   SerializeFr(new(fr.Element).SetInt64(42)),
			wantErr: false,
		},
		{
			name:    "zero element round-trips",
			input:   SerializeFr(new(fr.Element).SetInt64(0)),
			wantErr: false,
		},
		{
			name:    "large valid element round-trips",
			input:   SerializeFr(new(fr.Element).SetInt64(1<<62 - 1)),
			wantErr: false,
		},
		{
			name:    "value at field order is rejected",
			input:   &SerializedFrElement{Data: "52435875175126190479447740508185965837690552500527637822603658699938581184513"},
			wantErr: true,
		},
		{
			name:    "value above field order is rejected",
			input:   &SerializedFrElement{Data: "52435875175126190479447740508185965837690552500527637822603658699938581184514"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DeserializeFr(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("DeserializeFr() expected error, got nil (result=%v)", result)
				}
				return
			}
			if err != nil {
				t.Fatalf("DeserializeFr() unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("DeserializeFr() returned nil element for valid input")
			}
		})
	}
}
