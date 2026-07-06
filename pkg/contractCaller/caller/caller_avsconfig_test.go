package caller

import (
	"testing"

	IEigenKMSRegistrar "github.com/Layr-Labs/eigenx-kms-go/pkg/middleware-bindings/IEigenKMSRegistrar"
	"github.com/stretchr/testify/require"
)

// mapAvsConfig converts the generated binding struct to the caller's AvsConfig.
// This is the pure mapping used by ContractCaller.GetAvsConfig; tested directly
// because the live read requires a chain connection (integration-only).
func Test_mapAvsConfig(t *testing.T) {
	in := IEigenKMSRegistrar.IEigenKMSRegistrarTypesAvsConfig{
		OperatorSetId:  7,
		PlatformRpcUrl: "platform.example:9002",
	}
	got := mapAvsConfig(in)
	require.Equal(t, &AvsConfig{OperatorSetId: 7, PlatformRpcUrl: "platform.example:9002"}, got)
}
