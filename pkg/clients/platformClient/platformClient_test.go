package platformClient

import (
	"context"
	"encoding/json"
	"testing"

	libecdsa "github.com/Layr-Labs/crypto-libs/pkg/ecdsa"
	kmsv1 "github.com/Layr-Labs/eigenx-kms-go/gen/protos/eigenlayer/platform/v1/kms"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner/inMemoryTransportSigner"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func TestBuildAuthenticatedMessage_VerifiesUnderPlatformPath(t *testing.T) {
	// Generate a throwaway ECDSA key and derive its address (the operator identity).
	priv, err := gethcrypto.GenerateKey()
	require.NoError(t, err)
	pkBytes := gethcrypto.FromECDSA(priv)
	signer, err := inMemoryTransportSigner.NewECDSAInMemoryTransportSigner(pkBytes, zap.NewNop())
	require.NoError(t, err)

	opAddr := gethcrypto.PubkeyToAddress(priv.PublicKey)

	payload, hash, sig, err := buildAuthenticatedMessage(signer, opAddr, "stack-123", 1_700_000_000)
	require.NoError(t, err)

	// 1. hash must equal keccak256(payload) (server recomputes and requires this).
	require.Equal(t, gethcrypto.Keccak256(payload), hash)

	// 2. payload must be the JSON of ReleasePayload with the exact tags.
	var rp ReleasePayload
	require.NoError(t, json.Unmarshal(payload, &rp))
	require.Equal(t, opAddr, rp.FromOperatorAddress)
	require.Equal(t, "stack-123", rp.StackID)
	require.Equal(t, int64(1_700_000_000), rp.Timestamp)

	// 3. signature must recover to the operator address via the platform's verify path.
	s, err := libecdsa.NewSignatureFromBytes(sig)
	require.NoError(t, err)
	ok, err := s.VerifyWithAddress(hash, opAddr)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestGetLatestDeployedRelease_UnconfiguredURL(t *testing.T) {
	c := &client{urlProvider: func() string { return "" }, nowUnix: func() int64 { return 1 }}
	_, err := c.GetLatestDeployedRelease(context.Background(), "s")
	require.ErrorIs(t, err, ErrPlatformURLNotConfigured)
}

// fakeConn implements grpc.ClientConnInterface; Invoke fills the reply with a fixed
// GetLatestDeployedReleaseResponse so we can assert the client's response mapping.
type fakeConn struct{ resp *kmsv1.GetLatestDeployedReleaseResponse }

func (f *fakeConn) Invoke(_ context.Context, _ string, _, reply any, _ ...grpc.CallOption) error {
	out := reply.(*kmsv1.GetLatestDeployedReleaseResponse)
	proto.Merge(out, f.resp)
	return nil
}
func (f *fakeConn) NewStream(_ context.Context, _ *grpc.StreamDesc, _ string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, nil
}

func TestGetLatestDeployedRelease_MapsResponse(t *testing.T) {
	priv, err := gethcrypto.GenerateKey()
	require.NoError(t, err)
	signer, err := inMemoryTransportSigner.NewECDSAInMemoryTransportSigner(gethcrypto.FromECDSA(priv), zap.NewNop())
	require.NoError(t, err)

	resp := &kmsv1.GetLatestDeployedReleaseResponse{
		StackId:        "stack-123",
		Version:        4,
		ManifestDigest: "sha256:manifestdigest",
		Apps: []*kmsv1.DeployedApp{
			{Name: "web", Image: "registry/web@sha256:aaa"},
			{Name: "worker", Image: "registry/worker@sha256:bbb"},
		},
	}
	c := &client{
		urlProvider:     func() string { return "platform.example:9002" },
		operatorAddress: gethcrypto.PubkeyToAddress(priv.PublicKey),
		signer:          signer,
		logger:          zap.NewNop(),
		nowUnix:         func() int64 { return 1_700_000_000 },
		dial: func(string) (grpc.ClientConnInterface, func() error, error) {
			return &fakeConn{resp: resp}, func() error { return nil }, nil
		},
	}
	got, err := c.GetLatestDeployedRelease(context.Background(), "stack-123")
	require.NoError(t, err)
	require.Equal(t, "stack-123", got.StackID)
	require.Equal(t, int32(4), got.Version)
	require.Equal(t, "sha256:manifestdigest", got.ManifestDigest)
	require.Equal(t, []App{
		{Name: "web", Image: "registry/web@sha256:aaa"},
		{Name: "worker", Image: "registry/worker@sha256:bbb"},
	}, got.Apps)
}
