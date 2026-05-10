package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateAppID(t *testing.T) {
	require.Error(t, ValidateAppID(""))
	require.Error(t, ValidateAppID("abcd"))
	require.NoError(t, ValidateAppID("abcde"))
	require.NoError(t, ValidateAppID("valid-app-id"))
}
