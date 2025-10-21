package registry

import (
	"fmt"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// Client defines the interface for release registry operations
type Client interface {
	GetLatestRelease(appID string) (*types.Release, error)
}

// StubClient is a stub implementation for testing
type StubClient struct {
	// Mock releases for testing
	releases map[string]*types.Release
}

// NewStubClient creates a new stub release registry client
func NewStubClient() *StubClient {
	// Pre-populate with some test releases
	releases := map[string]*types.Release{
		"test-app": {
			ImageDigest:  "sha256:test123",
			EncryptedEnv: "encrypted-env-data-for-test-app",
			PublicEnv:    "PUBLIC_VAR=test-value",
			Timestamp:    time.Now().Unix(),
		},
		"demo-app": {
			ImageDigest:  "sha256:demo456", 
			EncryptedEnv: "encrypted-env-data-for-demo-app",
			PublicEnv:    "DEMO_MODE=true",
			Timestamp:    time.Now().Unix(),
		},
	}
	
	return &StubClient{releases: releases}
}

// GetLatestRelease retrieves the latest release for an application (stub implementation)
func (c *StubClient) GetLatestRelease(appID string) (*types.Release, error) {
	// STUB: In production, this would:
	// 1. Query the on-chain release registry contract
	// 2. Call IReleaseRegistry.getLatestRelease(appId)
	// 3. Parse the returned Release struct
	// 4. Verify the release data integrity
	
	release, exists := c.releases[appID]
	if !exists {
		return nil, fmt.Errorf("no release found for app_id: %s", appID)
	}
	
	fmt.Printf("Found release for app_id: %s, image: %s\n", appID, release.ImageDigest)
	return release, nil
}

// AddTestRelease adds a test release (for testing only)
func (c *StubClient) AddTestRelease(appID string, release *types.Release) {
	c.releases[appID] = release
}

// ProductionClient would implement the real on-chain client
type ProductionClient struct {
	chainClient interface{} // Would be an Ethereum client
	contractAddr string     // Release registry contract address
}

// NewProductionClient creates a production release registry client
func NewProductionClient(chainClient interface{}, contractAddr string) *ProductionClient {
	return &ProductionClient{
		chainClient: chainClient,
		contractAddr: contractAddr,
	}
}

// GetLatestRelease retrieves release from on-chain contract (production implementation)
func (c *ProductionClient) GetLatestRelease(appID string) (*types.Release, error) {
	// TODO: Implement actual contract call
	// Example:
	// 1. Call contract.GetLatestRelease(appID)
	// 2. Parse the returned data
	// 3. Return typed Release struct
	return nil, fmt.Errorf("production client not implemented yet")
}