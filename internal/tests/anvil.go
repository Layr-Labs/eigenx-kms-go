package tests

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
)

type AnvilConfig struct {
	ForkUrl         string `json:"forkUrl"`
	ForkBlockNumber string `json:"forkBlockNumber"`
	BlockTime       string `json:"blockTime"`
	PortNumber      string `json:"portNumber"`
	StateFilePath   string `json:"stateFilePath"`
	ChainId         string `json:"chainId"`
}

func StartAnvil(projectRoot string, ctx context.Context, cfg *AnvilConfig) (*exec.Cmd, error) {
	// exec anvil command to start the anvil node
	args := []string{
		"--fork-url", cfg.ForkUrl,
		"--load-state", cfg.StateFilePath,
		"--chain-id", cfg.ChainId,
		"--port", cfg.PortNumber,
		"--block-time", cfg.BlockTime,
		"--fork-block-number", cfg.ForkBlockNumber,
		"-vvv",
	}
	fmt.Printf("Starting anvil with args: %v\n", args)
	cmd := exec.CommandContext(ctx, "anvil", args...)
	cmd.Stderr = os.Stderr

	joinOutput := os.Getenv("JOIN_ANVIL_OUTPUT")
	if joinOutput == "true" {
		cmd.Stdout = os.Stdout
	}

	err := cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start anvil: %w", err)
	}

	rpcUrl := fmt.Sprintf("http://localhost:%s", cfg.PortNumber)

	for i := 1; i < 10; i++ {
		res, err := http.Post(rpcUrl, "application/json", nil)
		if err == nil && res.StatusCode == 200 {
			fmt.Println("Anvil is up and running")
			return cmd, nil
		}
		fmt.Printf("Anvil not ready yet, retrying... %d\n", i)
		time.Sleep(time.Second * time.Duration(i))
	}

	return nil, fmt.Errorf("failed to start anvil")
}

func WaitForAnvil(
	anvilWg *sync.WaitGroup,
	ctx context.Context,
	t *testing.T,
	ethereumClient ethereum.Client,
	errorsChan chan error,
) {
	defer anvilWg.Done()
	time.Sleep(2 * time.Second) // give anvil some time to start

	for {
		select {
		case <-ctx.Done():
			t.Logf("Failed to start anvil: %v", ctx.Err())
			errorsChan <- fmt.Errorf("failed to start anvil: %w", ctx.Err())
			return
		case <-time.After(2 * time.Second):
			t.Logf("Checking if anvil is up and running...")
			block, err := ethereumClient.GetLatestBlock(ctx)
			if err != nil {
				t.Logf("Failed to get latest block, will retry: %v", err)
				continue
			}
			t.Logf("Anvil is up and running, latest block: %v", block)
			return
		}
	}
}

func KillallAnvils() error {
	cmd := exec.Command("pkill", "-f", "anvil")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to kill all anvils: %w", err)
	}
	fmt.Println("All anvil processes killed successfully")
	return nil
}

func KillAnvil(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return fmt.Errorf("anvil command is not running")
	}

	if err := cmd.Process.Kill(); err != nil {
		return fmt.Errorf("failed to kill anvil process: %w", err)
	}
	_ = cmd.Wait()

	fmt.Println("Anvil process killed successfully")
	return nil
}

func StartL1Anvil(projectRoot string, ctx context.Context) (*exec.Cmd, error) {
	chainConfig, err := ReadChainConfig(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to read chain config: %w", err)
	}
	forkUrl := "https://practical-serene-mound.ethereum-sepolia.quiknode.pro/3aaa48bd95f3d6aed60e89a1a466ed1e2a440b61/"
	portNumber := "8545"
	blockTime := "2"
	forkBlockNumber := chainConfig.ForkL1Block
	chainId := "31337"

	fullPath, err := filepath.Abs(fmt.Sprintf("%s/internal/testData/anvil-l1-state.json", projectRoot))
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	stat, err := os.Stat(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}
	if stat.IsDir() {
		return nil, fmt.Errorf("path is a directory: %s", fullPath)
	}

	return StartAnvil(projectRoot, ctx, &AnvilConfig{
		ForkUrl:         forkUrl,
		ForkBlockNumber: forkBlockNumber,
		BlockTime:       blockTime,
		PortNumber:      portNumber,
		StateFilePath:   fullPath,
		ChainId:         chainId,
	})
}

func StartL2Anvil(projectRoot string, ctx context.Context) (*exec.Cmd, error) {
	chainConfig, err := ReadChainConfig(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to read chain config: %w", err)
	}
	forkUrl := "https://soft-alpha-grass.base-sepolia.quiknode.pro/fd5e4bf346247d9b6e586008a9f13df72ce6f5b2/"
	portNumber := "9545"
	blockTime := "2"
	forkBlockNumber := chainConfig.ForkL2Block
	chainId := "31338"

	fullPath, err := filepath.Abs(fmt.Sprintf("%s/internal/testData/anvil-l2-state.json", projectRoot))
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	stat, err := os.Stat(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}
	if stat.IsDir() {
		return nil, fmt.Errorf("path is a directory: %s", fullPath)
	}

	return StartAnvil(projectRoot, ctx, &AnvilConfig{
		ForkUrl:         forkUrl,
		ForkBlockNumber: forkBlockNumber,
		BlockTime:       blockTime,
		PortNumber:      portNumber,
		StateFilePath:   fullPath,
		ChainId:         chainId,
	})
}
