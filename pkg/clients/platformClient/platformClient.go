package platformClient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	kmsv1 "github.com/Layr-Labs/eigenx-kms-go/gen/protos/eigenlayer/platform/v1/kms"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner"
	"github.com/ethereum/go-ethereum/common"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var ErrPlatformURLNotConfigured = errors.New("platform RPC URL not configured")

type App struct {
	Name  string
	Image string
}

type Release struct {
	StackID        string
	Version        int32
	ManifestDigest string
	Apps           []App
}

// ReleasePayload is the inner signed message. Its JSON tags match the platform
// wire contract; it is redefined here (NOT imported from ecloud-platform) to
// avoid a module cycle.
type ReleasePayload struct {
	FromOperatorAddress common.Address `json:"fromOperatorAddress"`
	StackID             string         `json:"stackId"`
	Timestamp           int64          `json:"timestamp"`
}

type Client interface {
	GetLatestDeployedRelease(ctx context.Context, stackID string) (*Release, error)
}

type client struct {
	urlProvider     func() string
	operatorAddress common.Address
	signer          transportSigner.ITransportSigner
	logger          *zap.Logger
	nowUnix         func() int64
	// dial is injected in tests; defaults to a real insecure gRPC dial.
	dial func(url string) (grpc.ClientConnInterface, func() error, error)
}

func NewClient(urlProvider func() string, operatorAddress common.Address, signer transportSigner.ITransportSigner, l *zap.Logger) Client {
	return &client{
		urlProvider:     urlProvider,
		operatorAddress: operatorAddress,
		signer:          signer,
		logger:          l,
		nowUnix:         func() int64 { return timeNowUnix() },
		dial:            defaultDial,
	}
}

// buildAuthenticatedMessage marshals the inner ReleasePayload, signs it with the
// node's ECDSA transport signer, and returns (payload, hash, signature) — the three
// fields of the platform's AuthenticatedMessage.
func buildAuthenticatedMessage(
	signer transportSigner.ITransportSigner,
	operatorAddress common.Address,
	stackID string,
	nowUnix int64,
) (payload []byte, hash []byte, signature []byte, err error) {
	rp := ReleasePayload{FromOperatorAddress: operatorAddress, StackID: stackID, Timestamp: nowUnix}
	payload, err = json.Marshal(rp)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal release payload: %w", err)
	}
	signed, err := signer.CreateAuthenticatedMessage(payload)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign release payload: %w", err)
	}
	h := make([]byte, len(signed.Hash))
	copy(h, signed.Hash[:])
	return signed.Payload, h, signed.Signature, nil
}

func (c *client) GetLatestDeployedRelease(ctx context.Context, stackID string) (*Release, error) {
	url := strings.TrimSpace(c.urlProvider())
	if url == "" {
		return nil, ErrPlatformURLNotConfigured
	}
	payload, hash, sig, err := buildAuthenticatedMessage(c.signer, c.operatorAddress, stackID, c.nowUnix())
	if err != nil {
		return nil, err
	}
	conn, closeFn, err := c.dial(url)
	if err != nil {
		return nil, fmt.Errorf("dial platform: %w", err)
	}
	defer func() { _ = closeFn() }()

	resp, err := kmsv1.NewKMSServiceClient(conn).GetLatestDeployedRelease(ctx, &kmsv1.GetLatestDeployedReleaseRequest{
		Auth: &kmsv1.AuthenticatedMessage{Payload: payload, Hash: hash, Signature: sig},
	})
	if err != nil {
		return nil, err // gRPC status error; caller maps codes
	}
	apps := make([]App, 0, len(resp.GetApps()))
	for _, a := range resp.GetApps() {
		apps = append(apps, App{Name: a.GetName(), Image: a.GetImage()})
	}
	return &Release{
		StackID:        resp.GetStackId(),
		Version:        resp.GetVersion(),
		ManifestDigest: resp.GetManifestDigest(),
		Apps:           apps,
	}, nil
}

func defaultDial(url string) (grpc.ClientConnInterface, func() error, error) {
	conn, err := grpc.NewClient(url, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	return conn, conn.Close, nil
}
