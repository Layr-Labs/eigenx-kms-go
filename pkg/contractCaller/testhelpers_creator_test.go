package contractCaller

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestTestableStubGetAppCreator(t *testing.T) {
	stub := NewTestableContractCallerStub()
	app := common.HexToAddress("0xD36193599084B7d905fD40A436A0588d945e8299")
	creator := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Unset → zero address, no error.
	got, err := stub.GetAppCreator(app, nil)
	require.NoError(t, err)
	require.Equal(t, common.Address{}, got)

	// After SetAppCreator → returns it (case-insensitive key).
	stub.SetAppCreator(app, creator)
	got, err = stub.GetAppCreator(app, nil)
	require.NoError(t, err)
	require.Equal(t, creator, got)
}
