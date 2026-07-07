package registrarabi

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// TestEmbeddedABIHasAvsConfigSet guards against the embedded ABI drifting away
// from the concrete EigenKMSRegistrar contract. It ensures the AvsConfigSet
// event exists with exactly the two non-indexed inputs the node relies on to
// pick up platform config changes.
func TestEmbeddedABIHasAvsConfigSet(t *testing.T) {
	parsedABI, err := abi.JSON(strings.NewReader(EigenKMSRegistrarABI))
	if err != nil {
		t.Fatalf("failed to parse embedded EigenKMSRegistrar ABI: %v", err)
	}

	event, ok := parsedABI.Events[AvsConfigSetEventName]
	if !ok {
		t.Fatalf("embedded ABI is missing the %q event", AvsConfigSetEventName)
	}

	if len(event.Inputs) != 2 {
		t.Fatalf("expected %q to have 2 inputs, got %d", AvsConfigSetEventName, len(event.Inputs))
	}

	expected := []struct {
		name    string
		typeStr string
	}{
		{"operatorSetId", "uint32"},
		{"platformRpcUrl", "string"},
	}

	for i, exp := range expected {
		input := event.Inputs[i]
		if input.Name != exp.name {
			t.Errorf("input %d: expected name %q, got %q", i, exp.name, input.Name)
		}
		if input.Type.String() != exp.typeStr {
			t.Errorf("input %d (%s): expected type %q, got %q", i, exp.name, exp.typeStr, input.Type.String())
		}
		if input.Indexed {
			t.Errorf("input %d (%s): expected non-indexed, but it is indexed", i, exp.name)
		}
	}
}
