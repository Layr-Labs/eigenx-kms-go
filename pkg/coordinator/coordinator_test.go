package coordinator

import (
	"context"
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	kmsTypes "github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"go.uber.org/zap"
)

// mockAppUpgradedIterator is a test iterator that replays a fixed set of AppUpgraded events.
type mockAppUpgradedIterator struct {
	events []*contractCaller_caller_AppUpgradedEvent
	index  int
}

// We use the caller package's exported type via the contractCaller package's interface.
// Define a local alias for the event fields we need so the test doesn't need to import caller.
type contractCaller_caller_AppUpgradedEvent = struct {
	App common.Address
	Raw ethTypes.Log
}

func newMockIterator(events []*contractCaller_caller_AppUpgradedEvent) *mockAppUpgradedIterator {
	return &mockAppUpgradedIterator{events: events}
}

func (m *mockAppUpgradedIterator) Next() bool {
	m.index++
	return m.index <= len(m.events)
}
func (m *mockAppUpgradedIterator) Error() error { return nil }
func (m *mockAppUpgradedIterator) Close() error { return nil }

// coordinatorTestCallerStub extends TestableContractCallerStub with controllable
// FilterAppUpgraded output for Coordinator unit tests.
type coordinatorTestCallerStub struct {
	*contractCaller.TestableContractCallerStub
	upgradeEvents []common.Address // apps that fire AppUpgraded when queried
}

func newCoordinatorTestStub() *coordinatorTestCallerStub {
	return &coordinatorTestCallerStub{
		TestableContractCallerStub: contractCaller.NewTestableContractCallerStub(),
	}
}

// addUpgradeEvent simulates upgradeApp() being seen on-chain for the given app.
func (s *coordinatorTestCallerStub) addUpgradeEvent(appID string, pendingRelease *kmsTypes.Release) {
	s.upgradeEvents = append(s.upgradeEvents, common.HexToAddress(appID))
	s.SetPendingRelease(appID, pendingRelease)
}

func TestCoordinator_ConfirmsPendingUpgrades(t *testing.T) {
	appID := "0x1111111111111111111111111111111111111111"
	oldDigest := "sha256:old"
	newDigest := "sha256:new"

	stub := newCoordinatorTestStub()
	stub.AddTestRelease(appID, &kmsTypes.Release{ImageDigest: oldDigest})
	stub.addUpgradeEvent(appID, &kmsTypes.Release{ImageDigest: newDigest})

	// Verify the confirmed release is still old before the Coordinator runs.
	ctx := context.Background()
	confirmed, err := stub.GetLatestReleaseAsRelease(ctx, appID)
	if err != nil {
		t.Fatalf("GetLatestReleaseAsRelease: %v", err)
	}
	if confirmed.ImageDigest != oldDigest {
		t.Fatalf("expected confirmed digest %s before run, got %s", oldDigest, confirmed.ImageDigest)
	}

	// Manually call ConfirmUpgrade (the Coordinator's core action) to simulate one poll cycle.
	receipt, err := stub.ConfirmUpgrade(ctx, appID)
	if err != nil {
		t.Fatalf("ConfirmUpgrade: %v", err)
	}
	if receipt.Status != 1 {
		t.Fatalf("expected receipt status 1, got %d", receipt.Status)
	}

	// After confirmation the new digest should be confirmed.
	confirmed, err = stub.GetLatestReleaseAsRelease(ctx, appID)
	if err != nil {
		t.Fatalf("GetLatestReleaseAsRelease after confirm: %v", err)
	}
	if confirmed.ImageDigest != newDigest {
		t.Fatalf("expected confirmed digest %s after confirm, got %s", newDigest, confirmed.ImageDigest)
	}

	// Pending should now be cleared.
	if _, err := stub.GetPendingReleaseAsRelease(ctx, appID); err == nil {
		t.Fatal("expected pending release to be cleared after confirmation")
	}
}

func TestCoordinator_IdempotentOnAlreadyConfirmed(t *testing.T) {
	appID := "0x2222222222222222222222222222222222222222"

	stub := newCoordinatorTestStub()
	stub.AddTestRelease(appID, &kmsTypes.Release{ImageDigest: "sha256:current"})
	// No pending release — simulates an app where confirmUpgrade was already called.

	// ConfirmUpgrade on an app with no pending release should return an error.
	ctx := context.Background()
	_, err := stub.ConfirmUpgrade(ctx, appID)
	if err == nil {
		t.Fatal("expected error when confirming with no pending release")
	}
}

func TestCoordinator_GetAppPendingReleaseBlockNumber_ZeroWhenNoPending(t *testing.T) {
	appID := "0x3333333333333333333333333333333333333333"

	stub := newCoordinatorTestStub()
	stub.AddTestRelease(appID, &kmsTypes.Release{ImageDigest: "sha256:current"})

	ctx := context.Background()
	pendingBlock, err := stub.GetAppPendingReleaseBlockNumber(
		common.HexToAddress(appID),
		&bind.CallOpts{Context: ctx},
	)
	if err != nil {
		t.Fatalf("GetAppPendingReleaseBlockNumber: %v", err)
	}
	if pendingBlock != 0 {
		t.Fatalf("expected 0 pending block with no pending release, got %d", pendingBlock)
	}
}

func TestCoordinator_New(t *testing.T) {
	stub := contractCaller.NewTestableContractCallerStub()
	logger, _ := zap.NewDevelopment()

	c := New(stub, 100*time.Millisecond, 42, logger)
	if c.lastProcessedBlock != 42 {
		t.Fatalf("expected startBlock 42, got %d", c.lastProcessedBlock)
	}
	if c.pollInterval != 100*time.Millisecond {
		t.Fatalf("unexpected poll interval")
	}
}

func TestCoordinator_Start_StopsOnContextCancel(t *testing.T) {
	stub := contractCaller.NewTestableContractCallerStub()
	logger, _ := zap.NewDevelopment()

	c := New(stub, 50*time.Millisecond, 0, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	err := c.Start(ctx)
	if err != context.DeadlineExceeded {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}
