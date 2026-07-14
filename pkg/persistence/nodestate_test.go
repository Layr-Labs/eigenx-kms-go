package persistence

import (
	"encoding/json"
	"testing"
)

func TestNodeState_AutoHealFieldsRoundTrip(t *testing.T) {
	in := &NodeState{
		LastProcessedBoundary:      100,
		OperatorAddress:            "0xabc",
		TrackedSourceVersion:       1783944564,
		ConsecutiveMPKAborts:       3,
		LastKnownGoodSourceVersion: 1783944444,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out NodeState
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.TrackedSourceVersion != 1783944564 || out.ConsecutiveMPKAborts != 3 || out.LastKnownGoodSourceVersion != 1783944444 {
		t.Fatalf("auto-heal fields did not round-trip: %+v", out)
	}
}
