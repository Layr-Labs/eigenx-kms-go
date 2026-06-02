package util

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateAppID(t *testing.T) {
	require.Error(t, ValidateAppID(""))
	require.Error(t, ValidateAppID("abcd"))
	require.NoError(t, ValidateAppID("abcde"))
	require.NoError(t, ValidateAppID("valid-app-id"))
}

func TestValidateAppID_Boundaries(t *testing.T) {
	tests := []struct {
		name    string
		appID   string
		wantErr bool
	}{
		{name: "empty", appID: "", wantErr: true},
		{name: "1 char (minimum valid)", appID: "a", wantErr: false},
		{name: "short valid ID", appID: "kms", wantErr: false},
		{name: "255 chars (max valid)", appID: strings.Repeat("a", 255), wantErr: false},
		{name: "256 chars (too long)", appID: strings.Repeat("a", 256), wantErr: true},
		{name: "contains space", appID: "hello world", wantErr: true},
		{name: "contains newline", appID: "hello\nworld", wantErr: true},
		{name: "contains slash", appID: "app/id", wantErr: true},
		{name: "contains unicode", appID: "app\u4e2d", wantErr: true},
		{name: "all valid chars", appID: "My-App_1.0", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAppID(tt.appID)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
