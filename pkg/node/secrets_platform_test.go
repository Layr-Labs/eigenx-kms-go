package node

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/blockHandler"
	platformClient "github.com/Layr-Labs/eigenx-kms-go/pkg/clients/platformClient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering/localPeeringDataFetcher"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence/memory"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner/inMemoryTransportSigner"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// platformTestChainPoller is a no-op chain poller for testing.
type platformTestChainPoller struct{}

func (m *platformTestChainPoller) Start(ctx context.Context) error { return nil }

// fakePlatformClient is an in-package stub for platformClient.Client. Because this
// test lives in package node, it can be assigned directly to n.platformClient.
type fakePlatformClient struct {
	rel   *platformClient.Release
	err   error
	calls int
}

func (f *fakePlatformClient) GetLatestDeployedRelease(ctx context.Context, stackID string) (*platformClient.Release, error) {
	f.calls++
	return f.rel, f.err
}

// fakeAttestationMethod returns caller-chosen claims (AppID == request.AppID and a
// configurable ImageDigest) so tests can drive the platform authorization branch.
type fakeAttestationMethod struct {
	name        string
	imageDigest string
}

func (f *fakeAttestationMethod) Name() string { return f.name }

func (f *fakeAttestationMethod) Verify(request *attestation.AttestationRequest) (*types.AttestationClaims, error) {
	return &types.AttestationClaims{
		AppID:       request.AppID,
		ImageDigest: f.imageDigest,
		IssuedAt:    time.Now().Unix(),
	}, nil
}

// newPlatformTestNode builds a node in-package (so the unexported platformClient
// field can be set directly), mirroring the integration harness setup.
func newPlatformTestNode(t *testing.T, manager *attestation.AttestationManager) *Node {
	t.Helper()

	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	require.NoError(t, err)

	testLogger, err := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	require.NoError(t, err)

	cfg := Config{
		OperatorAddress: chainConfig.OperatorAccountAddress1,
		Port:            0,
		ChainID:         config.ChainId_EthereumAnvil,
		AVSAddress:      "0x1234567890123456789012345678901234567890",
		OperatorSetId:   1,
	}

	privKey, err := bn254.NewPrivateKeyFromHexString(chainConfig.OperatorAccountPrivateKey1)
	require.NoError(t, err)

	peer := &peering.OperatorSetPeer{
		OperatorAddress: common.HexToAddress(chainConfig.OperatorAccountAddress1),
		SocketAddress:   "http://localhost:8080",
		WrappedPublicKey: peering.WrappedPublicKey{
			PublicKey:    privKey.Public(),
			ECDSAAddress: common.HexToAddress(chainConfig.OperatorAccountAddress1),
		},
		CurveType: config.CurveTypeBN254,
	}

	operatorSet := &peering.OperatorSetPeers{
		OperatorSetId: 1,
		AVSAddress:    common.HexToAddress("0x1234567890123456789012345678901234567890"),
		Peers:         []*peering.OperatorSetPeer{peer},
	}

	peeringDataFetcher := localPeeringDataFetcher.NewLocalPeeringDataFetcher([]*peering.OperatorSetPeers{operatorSet}, nil)

	bh := blockHandler.NewBlockHandler(testLogger)
	mockPoller := &platformTestChainPoller{}

	pkBytes, err := hexutil.Decode(chainConfig.OperatorAccountPrivateKey1)
	require.NoError(t, err)

	imts, err := inMemoryTransportSigner.NewBn254InMemoryTransportSigner(pkBytes, testLogger)
	require.NoError(t, err)

	mockBaseContractCaller := contractCaller.NewTestableContractCallerStub()
	mockRegistryAddress := common.HexToAddress("0x1111111111111111111111111111111111111111")

	persistence := memory.NewMemoryPersistence()
	t.Cleanup(func() { _ = persistence.Close() })

	n, err := NewNode(cfg, peeringDataFetcher, bh, mockPoller, imts, manager, mockBaseContractCaller, mockRegistryAddress, persistence, testLogger)
	require.NoError(t, err)

	// Seed an active key share so partial signing succeeds.
	testShare := new(fr.Element).SetInt64(42)
	keyVersion := &types.KeyShareVersion{
		Version:        time.Now().Unix(),
		PrivateShare:   testShare,
		Commitments:    []types.G2Point{},
		IsActive:       true,
		ParticipantIDs: []common.Address{common.HexToAddress(chainConfig.OperatorAccountAddress1)},
	}
	n.GetKeyStore().AddVersion(keyVersion)

	return n
}

// buildPlatformSecretsRequest builds a /secrets request for the platform path.
func buildPlatformSecretsRequest(t *testing.T, appID, method, stackID string) types.SecretsRequestV1 {
	t.Helper()
	_, pubKeyPEM, err := encryption.GenerateKeyPair(2048)
	require.NoError(t, err)
	return types.SecretsRequestV1{
		AppID:             appID,
		AttestationMethod: method,
		Attestation:       []byte("dummy-attestation"),
		RSAPubKeyTmp:      pubKeyPEM,
		StackID:           stackID,
	}
}

func servePlatformSecrets(t *testing.T, n *Node, req types.SecretsRequestV1) *httptest.ResponseRecorder {
	t.Helper()
	reqBody, err := json.Marshal(req)
	require.NoError(t, err)
	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server := NewServer(n, 0)
	server.GetHandler().ServeHTTP(w, httpReq)
	return w
}

const (
	platformTestAppID   = "my-app"
	platformTestStackID = "stack-123"
	platformTestHex     = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"
	platformTestDigest  = "sha256:" + platformTestHex
)

func newPlatformManager(t *testing.T, imageDigest string) *attestation.AttestationManager {
	t.Helper()
	slogger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := attestation.NewAttestationManager(slogger)
	require.NoError(t, manager.RegisterMethod(&fakeAttestationMethod{name: "gcp", imageDigest: imageDigest}))
	// ecdsa registered so the ecdsa+stack_id guard test reaches the handler (verification passes).
	require.NoError(t, manager.RegisterMethod(&fakeAttestationMethod{name: "ecdsa", imageDigest: imageDigest}))
	return manager
}

func TestSecretsPlatform_DigestMatch(t *testing.T) {
	n := newPlatformTestNode(t, newPlatformManager(t, platformTestDigest))
	fake := &fakePlatformClient{rel: &platformClient.Release{
		StackID: platformTestStackID,
		Apps: []platformClient.App{
			{Name: "app", Image: "registry/app@" + platformTestDigest},
		},
	}}
	n.platformClient = fake

	req := buildPlatformSecretsRequest(t, platformTestAppID, "gcp", platformTestStackID)
	w := servePlatformSecrets(t, n, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp types.SecretsResponseV1
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.NotNil(t, resp.EncryptedPartialSig)
	assert.NotEmpty(t, resp.EncryptedPartialSig)
	assert.Equal(t, "", resp.EncryptedEnv, "platform path returns no env")
	assert.Equal(t, "", resp.PublicEnv, "platform path returns no env")
	assert.Equal(t, 1, fake.calls)
}

func TestSecretsPlatform_DigestNoMatch(t *testing.T) {
	n := newPlatformTestNode(t, newPlatformManager(t, platformTestDigest))
	fake := &fakePlatformClient{rel: &platformClient.Release{
		StackID: platformTestStackID,
		Apps: []platformClient.App{
			{Name: "app", Image: "registry/app@sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		},
	}}
	n.platformClient = fake

	req := buildPlatformSecretsRequest(t, platformTestAppID, "gcp", platformTestStackID)
	w := servePlatformSecrets(t, n, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
}

func TestSecretsPlatform_URLNotConfigured(t *testing.T) {
	n := newPlatformTestNode(t, newPlatformManager(t, platformTestDigest))
	fake := &fakePlatformClient{err: platformClient.ErrPlatformURLNotConfigured}
	n.platformClient = fake

	req := buildPlatformSecretsRequest(t, platformTestAppID, "gcp", platformTestStackID)
	w := servePlatformSecrets(t, n, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "platform RPC URL not configured")
}

func TestSecretsPlatform_GRPCPermissionDenied(t *testing.T) {
	n := newPlatformTestNode(t, newPlatformManager(t, platformTestDigest))
	fake := &fakePlatformClient{err: status.Error(codes.PermissionDenied, "denied")}
	n.platformClient = fake

	req := buildPlatformSecretsRequest(t, platformTestAppID, "gcp", platformTestStackID)
	w := servePlatformSecrets(t, n, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
}

func TestSecretsPlatform_GRPCUnavailable(t *testing.T) {
	n := newPlatformTestNode(t, newPlatformManager(t, platformTestDigest))
	fake := &fakePlatformClient{err: status.Error(codes.Unavailable, "down")}
	n.platformClient = fake

	req := buildPlatformSecretsRequest(t, platformTestAppID, "gcp", platformTestStackID)
	w := servePlatformSecrets(t, n, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "body: %s", w.Body.String())
}

func TestSecretsPlatform_GRPCUnauthenticated(t *testing.T) {
	n := newPlatformTestNode(t, newPlatformManager(t, platformTestDigest))
	fake := &fakePlatformClient{err: status.Error(codes.Unauthenticated, "bad sig")}
	n.platformClient = fake

	req := buildPlatformSecretsRequest(t, platformTestAppID, "gcp", platformTestStackID)
	w := servePlatformSecrets(t, n, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code, "body: %s", w.Body.String())
}

func TestSecretsPlatform_ECDSARejected(t *testing.T) {
	n := newPlatformTestNode(t, newPlatformManager(t, platformTestDigest))
	fake := &fakePlatformClient{rel: &platformClient.Release{
		StackID: platformTestStackID,
		Apps:    []platformClient.App{{Name: "app", Image: "registry/app@" + platformTestDigest}},
	}}
	n.platformClient = fake

	req := buildPlatformSecretsRequest(t, platformTestAppID, "ecdsa", platformTestStackID)
	w := servePlatformSecrets(t, n, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "ecdsa attestation is not permitted for stack_id requests")
	assert.Equal(t, 0, fake.calls, "guard must fire before any platform call")
}

func TestSecretsPlatform_NonSha256Digest(t *testing.T) {
	// Non-sha256-prefixed digest via a non-ecdsa method must be rejected (defense-in-depth).
	n := newPlatformTestNode(t, newPlatformManager(t, "ecdsa:unverified"))
	fake := &fakePlatformClient{rel: &platformClient.Release{
		StackID: platformTestStackID,
		Apps:    []platformClient.App{{Name: "app", Image: "registry/app@" + platformTestDigest}},
	}}
	n.platformClient = fake

	req := buildPlatformSecretsRequest(t, platformTestAppID, "gcp", platformTestStackID)
	w := servePlatformSecrets(t, n, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
}
