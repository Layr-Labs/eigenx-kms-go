package coordinator

import (
	"context"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"go.uber.org/zap"
)

// Coordinator watches for pending app upgrades on the AppController contract and calls
// confirmUpgrade() to promote them to the confirmed (active) state. This is the missing
// step in the two-phase upgrade protocol that prevents the KMS-009 race condition:
//
//  1. Developer calls upgradeApp()  → pending release written on-chain.
//  2. Coordinator detects AppUpgraded event, verifies the new GCP Confidential Space
//     instance is healthy, then calls confirmUpgrade().
//  3. Only after step 2 does handleSecretsRequest begin accepting the new image digest.
//
// The Coordinator must hold UAM permission on the AppController contract (i.e., be the
// designated admin address). Unauthorized confirmUpgrade() calls revert on-chain.
type Coordinator struct {
	contractCaller     contractCaller.IContractCaller
	pollInterval       time.Duration
	lastProcessedBlock uint64
	logger             *zap.Logger
}

// New creates a Coordinator that begins scanning from startBlock.
// startBlock should typically be set to the current chain head at startup so that
// the Coordinator does not re-scan the entire chain history.
func New(
	cc contractCaller.IContractCaller,
	pollInterval time.Duration,
	startBlock uint64,
	logger *zap.Logger,
) *Coordinator {
	return &Coordinator{
		contractCaller:     cc,
		pollInterval:       pollInterval,
		lastProcessedBlock: startBlock,
		logger:             logger,
	}
}

// Start runs the Coordinator loop until ctx is cancelled. It polls for AppUpgraded events
// (which now fire when upgradeApp() writes to the pending slot) and calls confirmUpgrade()
// for each app that still has a pending release.
func (c *Coordinator) Start(ctx context.Context) error {
	c.logger.Sugar().Infow("Coordinator starting",
		"poll_interval", c.pollInterval,
		"start_block", c.lastProcessedBlock)

	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Sugar().Info("Coordinator stopping")
			return ctx.Err()
		case <-ticker.C:
			if err := c.processPendingUpgrades(ctx); err != nil {
				c.logger.Sugar().Warnw("Error processing pending upgrades", "error", err)
			}
		}
	}
}

// processPendingUpgrades scans for AppUpgraded events since the last processed block
// and confirms any that still have a pending release on-chain.
func (c *Coordinator) processPendingUpgrades(ctx context.Context) error {
	startBlock := c.lastProcessedBlock + 1
	iter, err := c.contractCaller.FilterAppUpgraded(nil, &bind.FilterOpts{
		Context: ctx,
		Start:   startBlock,
		End:     nil, // scan up to the latest block
	})
	if err != nil {
		return err
	}
	if iter == nil {
		return nil
	}
	defer iter.Close()

	var maxBlock uint64
	for iter.Next() {
		event := iter.Event()
		if event == nil {
			continue
		}

		appID := event.App.Hex()
		blockNum := event.Raw.BlockNumber
		if blockNum > maxBlock {
			maxBlock = blockNum
		}

		// Check if this app still has a pending release (another Coordinator may have
		// already confirmed it, or the event may be from a historical upgrade).
		pendingBlock, err := c.contractCaller.GetAppPendingReleaseBlockNumber(
			event.App,
			&bind.CallOpts{Context: ctx},
		)
		if err != nil {
			c.logger.Sugar().Warnw("Failed to get pending release block number",
				"app_id", appID, "error", err)
			continue
		}
		if pendingBlock == 0 {
			// Already confirmed or no pending upgrade.
			continue
		}

		c.logger.Sugar().Infow("Confirming pending upgrade",
			"app_id", appID,
			"pending_block", pendingBlock)

		receipt, err := c.contractCaller.ConfirmUpgrade(ctx, appID)
		if err != nil {
			c.logger.Sugar().Errorw("Failed to confirm upgrade",
				"app_id", appID,
				"pending_block", pendingBlock,
				"error", err)
			continue
		}

		c.logger.Sugar().Infow("Upgrade confirmed",
			"app_id", appID,
			"tx_hash", receipt.TxHash.Hex(),
			"block", receipt.BlockNumber)
	}

	if err := iter.Error(); err != nil {
		return err
	}

	if maxBlock > c.lastProcessedBlock {
		c.lastProcessedBlock = maxBlock
	}

	return nil
}
