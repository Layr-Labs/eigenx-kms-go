package persistence_test

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence/memory"
	"github.com/stretchr/testify/require"
)

func TestPoisonedVersions_Memory(t *testing.T) {
	var p persistence.INodePersistence = memory.NewMemoryPersistence()
	require.NoError(t, p.AddPoisonedVersion(1783944564))
	require.NoError(t, p.AddPoisonedVersion(1783944564)) // idempotent
	require.NoError(t, p.AddPoisonedVersion(1783944800))
	got, err := p.ListPoisonedVersions()
	require.NoError(t, err)
	require.ElementsMatch(t, []int64{1783944564, 1783944800}, got)

	// Empty case: a fresh store returns an empty (non-nil) slice, not an error.
	fresh := memory.NewMemoryPersistence()
	empty, err := fresh.ListPoisonedVersions()
	require.NoError(t, err)
	require.NotNil(t, empty)
	require.Empty(t, empty)
}
