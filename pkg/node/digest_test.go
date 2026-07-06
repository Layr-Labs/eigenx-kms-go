package node

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDigestFromImageRef(t *testing.T) {
	validHex := strings.Repeat("a", 64)

	cases := []struct {
		name string
		ref  string
		want string
	}{
		{
			name: "valid full digest",
			ref:  "ghcr.io/example/app@sha256:" + validHex,
			want: "sha256:" + validHex,
		},
		{
			name: "no @sha256: segment",
			ref:  "ghcr.io/example/app:latest",
			want: "",
		},
		{
			name: "empty tail is rejected",
			ref:  "app@sha256:",
			want: "",
		},
		{
			name: "short tail is rejected",
			ref:  "app@sha256:abcd",
			want: "",
		},
		{
			name: "over-long tail is rejected",
			ref:  "app@sha256:" + strings.Repeat("a", 65),
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, digestFromImageRef(tc.ref))
		})
	}
}
