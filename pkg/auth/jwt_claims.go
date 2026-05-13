package auth

import (
	"encoding/hex"
	"strconv"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/go-tpm-tools/sdk/attest"
)

// AttestationJWTClaims mirrors the CS token structure, populated from VerifiedAttestation.
// Standard JWT fields (iss, sub, iat, exp, aud) are handled separately by the jwt library.
type AttestationJWTClaims struct {
	AppID     string  `json:"app_id"`
	SecBoot   bool    `json:"secboot"`
	HWModel   string  `json:"hwmodel"`
	Hardened  bool    `json:"hardened"`
	SubMods   SubMods `json:"submods"`
	ExtraData string  `json:"extra_data,omitempty"` // base64-encoded extra_data bytes; present only when extra_data was provided

	TDX    *TDXJWTClaims    `json:"tdx,omitempty"`
	SevSnp *SevSnpJWTClaims `json:"sevsnp,omitempty"`
}

// SubMods contains nested attestation submods (container and GCE info).
type SubMods struct {
	Container *ContainerClaims `json:"container,omitempty"`
	GCE       *GCEClaims       `json:"gce,omitempty"`
}

// ContainerClaims describes the attested container workload.
type ContainerClaims struct {
	ImageReference string            `json:"image_reference"`
	ImageDigest    string            `json:"image_digest"`
	ImageID        string            `json:"image_id"`
	RestartPolicy  string            `json:"restart_policy"`
	Args           []string          `json:"args,omitempty"`
	EnvVars        map[string]string `json:"env,omitempty"`
}

// GCEClaims describes the GCP Compute Engine instance.
type GCEClaims struct {
	ProjectID     string `json:"project_id"`
	ProjectNumber string `json:"project_number"`
	Zone          string `json:"zone"`
	InstanceName  string `json:"instance_name"`
	InstanceID    string `json:"instance_id"`
}

// TDXJWTClaims holds Intel TDX hardware measurements.
type TDXJWTClaims struct {
	MRTD      string `json:"mrtd"`
	RTMR0     string `json:"rtmr0"`
	RTMR1     string `json:"rtmr1"`
	RTMR2     string `json:"rtmr2"`
	RTMR3     string `json:"rtmr3"`
	TeeTcbSvn string `json:"tee_tcb_svn"`
}

// SevSnpJWTClaims holds AMD SEV-SNP hardware measurements.
type SevSnpJWTClaims struct {
	Measurement  string `json:"measurement"`
	HostData     string `json:"host_data"`
	CurrentTcb   uint64 `json:"current_tcb"`
	ReportedTcb  uint64 `json:"reported_tcb"`
	CommittedTcb uint64 `json:"committed_tcb"`
	GuestSvn     uint32 `json:"guest_svn"`
}

// hwModelFromPlatform maps an attest.Platform to the HWModel string used in the JWT.
func hwModelFromPlatform(p attest.Platform) string {
	switch p {
	case attest.PlatformIntelTDX:
		return "GCP_INTEL_TDX"
	case attest.PlatformAMDSevSnp:
		return "GCP_AMD_SEV_SNP"
	case attest.PlatformGCPShieldedVM:
		return "GCP_SHIELDED_VM"
	default:
		return "UNKNOWN"
	}
}

// NewAttestationJWTClaims converts verified attestation data into JWT claims.
func NewAttestationJWTClaims(appID string, v *attestation.VerifiedAttestation) *AttestationJWTClaims {
	claims := &AttestationJWTClaims{
		AppID:   appID,
		HWModel: hwModelFromPlatform(v.Platform),
	}

	if v.TPMClaims != nil {
		claims.Hardened = v.TPMClaims.Hardened
		// Secure Boot is always enabled on Confidential Space VMs per Google's spec.
		claims.SecBoot = true

		if v.TPMClaims.GCE != nil {
			claims.SubMods.GCE = &GCEClaims{
				ProjectID:     v.TPMClaims.GCE.ProjectID,
				ProjectNumber: strconv.FormatUint(v.TPMClaims.GCE.ProjectNumber, 10),
				Zone:          v.TPMClaims.GCE.Zone,
				InstanceName:  v.TPMClaims.GCE.InstanceName,
				InstanceID:    strconv.FormatUint(v.TPMClaims.GCE.InstanceID, 10),
			}
		}
	}

	if v.Container != nil {
		claims.SubMods.Container = &ContainerClaims{
			ImageReference: v.Container.ImageReference,
			ImageDigest:    v.Container.ImageDigest,
			ImageID:        v.Container.ImageID,
			RestartPolicy:  v.Container.RestartPolicy,
			Args:           v.Container.Args,
			EnvVars:        v.Container.EnvVars,
		}
	}

	if v.TEEClaims != nil {
		if v.TEEClaims.TDX != nil {
			claims.TDX = &TDXJWTClaims{
				MRTD:      hex.EncodeToString(v.TEEClaims.TDX.MRTD[:]),
				RTMR0:     hex.EncodeToString(v.TEEClaims.TDX.RTMR0[:]),
				RTMR1:     hex.EncodeToString(v.TEEClaims.TDX.RTMR1[:]),
				RTMR2:     hex.EncodeToString(v.TEEClaims.TDX.RTMR2[:]),
				RTMR3:     hex.EncodeToString(v.TEEClaims.TDX.RTMR3[:]),
				TeeTcbSvn: hex.EncodeToString(v.TEEClaims.TDX.TeeTcbSvn[:]),
			}
		}
		if v.TEEClaims.SevSnp != nil {
			claims.SevSnp = &SevSnpJWTClaims{
				Measurement:  hex.EncodeToString(v.TEEClaims.SevSnp.Measurement[:]),
				HostData:     hex.EncodeToString(v.TEEClaims.SevSnp.HostData[:]),
				CurrentTcb:   v.TEEClaims.SevSnp.CurrentTcb,
				ReportedTcb:  v.TEEClaims.SevSnp.ReportedTcb,
				CommittedTcb: v.TEEClaims.SevSnp.CommittedTcb,
				GuestSvn:     v.TEEClaims.SevSnp.GuestSvn,
			}
		}
	}

	return claims
}
