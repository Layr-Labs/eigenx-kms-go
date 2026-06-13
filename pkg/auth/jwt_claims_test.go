package auth

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/go-tpm-tools/sdk/attest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHwModelFromPlatform(t *testing.T) {
	tests := []struct {
		platform attest.Platform
		expected string
	}{
		{attest.PlatformIntelTDX, "GCP_INTEL_TDX"},
		{attest.PlatformAMDSevSnp, "GCP_AMD_SEV_SNP"},
		{attest.PlatformGCPShieldedVM, "GCP_SHIELDED_VM"},
		{attest.Platform(99), "UNKNOWN"},
	}

	for _, tc := range tests {
		assert.Equal(t, tc.expected, hwModelFromPlatform(tc.platform))
	}
}

func TestNewAttestationJWTClaims_TDX(t *testing.T) {
	verified := &attestation.VerifiedAttestation{
		TPMClaims: &attest.TPMClaims{
			Platform: attest.PlatformIntelTDX,
			Hardened: true,
			GCE: &attest.GCEInfo{
				ProjectID:     "my-project",
				ProjectNumber: 12345,
				Zone:          "us-central1-a",
				InstanceName:  "tee-0xabc123",
				InstanceID:    67890,
			},
		},
		Container: &attest.ContainerInfo{
			ImageReference: "gcr.io/my-project/my-image:latest",
			ImageDigest:    "sha256:deadbeef",
			ImageID:        "sha256:imageID",
			RestartPolicy:  "Never",
			Args:           []string{"--flag"},
			EnvVars:        map[string]string{"KEY": "VALUE"},
		},
		TEEClaims: &attest.TEEClaims{
			TDX: &attest.TDXClaims{
				MRTD:      [48]byte{0x01, 0x02},
				RTMR0:     [48]byte{0x03},
				RTMR1:     [48]byte{0x04},
				RTMR2:     [48]byte{0x05},
				RTMR3:     [48]byte{0x06},
				TeeTcbSvn: [16]byte{0x07},
			},
		},
		Platform: attest.PlatformIntelTDX,
	}

	claims := NewAttestationJWTClaims("0xabc123", verified)

	require.NotNil(t, claims)
	assert.Equal(t, "0xabc123", claims.AppID)
	assert.Equal(t, "GCP_INTEL_TDX", claims.HWModel)
	assert.True(t, claims.SecBoot)
	assert.True(t, claims.Hardened)

	// GCE claims
	require.NotNil(t, claims.SubMods.GCE)
	assert.Equal(t, "my-project", claims.SubMods.GCE.ProjectID)
	assert.Equal(t, "12345", claims.SubMods.GCE.ProjectNumber)
	assert.Equal(t, "us-central1-a", claims.SubMods.GCE.Zone)
	assert.Equal(t, "tee-0xabc123", claims.SubMods.GCE.InstanceName)
	assert.Equal(t, "67890", claims.SubMods.GCE.InstanceID)

	// Container claims
	require.NotNil(t, claims.SubMods.Container)
	assert.Equal(t, "sha256:deadbeef", claims.SubMods.Container.ImageDigest)
	assert.Equal(t, "gcr.io/my-project/my-image:latest", claims.SubMods.Container.ImageReference)
	assert.Equal(t, "Never", claims.SubMods.Container.RestartPolicy)
	assert.Equal(t, []string{"--flag"}, claims.SubMods.Container.Args)
	assert.Equal(t, map[string]string{"KEY": "VALUE"}, claims.SubMods.Container.EnvVars)

	// TDX claims
	require.NotNil(t, claims.TDX)
	assert.NotEmpty(t, claims.TDX.MRTD)
	assert.Nil(t, claims.SevSnp)
}

func TestNewAttestationJWTClaims_SevSnp(t *testing.T) {
	verified := &attestation.VerifiedAttestation{
		TPMClaims: &attest.TPMClaims{
			Platform: attest.PlatformAMDSevSnp,
			Hardened: false,
			GCE: &attest.GCEInfo{
				ProjectID:    "proj",
				InstanceName: "tee-0xdef",
			},
		},
		Container: &attest.ContainerInfo{
			ImageDigest: "sha256:aabb",
		},
		TEEClaims: &attest.TEEClaims{
			SevSnp: &attest.SevSnpClaims{
				Measurement:  [48]byte{0xAA},
				HostData:     [32]byte{0xBB},
				CurrentTcb:   100,
				ReportedTcb:  200,
				CommittedTcb: 300,
				GuestSvn:     1,
			},
		},
		Platform: attest.PlatformAMDSevSnp,
	}

	claims := NewAttestationJWTClaims("0xdef", verified)

	assert.Equal(t, "GCP_AMD_SEV_SNP", claims.HWModel)
	assert.Nil(t, claims.TDX)
	require.NotNil(t, claims.SevSnp)
	assert.Equal(t, uint64(100), claims.SevSnp.CurrentTcb)
	assert.Equal(t, uint64(200), claims.SevSnp.ReportedTcb)
	assert.Equal(t, uint64(300), claims.SevSnp.CommittedTcb)
	assert.Equal(t, uint32(1), claims.SevSnp.GuestSvn)
}

func TestNewAttestationJWTClaims_ShieldedVM(t *testing.T) {
	verified := &attestation.VerifiedAttestation{
		TPMClaims: &attest.TPMClaims{
			Platform: attest.PlatformGCPShieldedVM,
			Hardened: true,
			GCE: &attest.GCEInfo{
				ProjectID:    "proj",
				InstanceName: "tee-0xghi",
			},
		},
		Container: &attest.ContainerInfo{
			ImageDigest: "sha256:ccdd",
		},
		// No TEE claims for Shielded VM
		Platform: attest.PlatformGCPShieldedVM,
	}

	claims := NewAttestationJWTClaims("0xghi", verified)

	assert.Equal(t, "GCP_SHIELDED_VM", claims.HWModel)
	assert.Nil(t, claims.TDX)
	assert.Nil(t, claims.SevSnp)
}
