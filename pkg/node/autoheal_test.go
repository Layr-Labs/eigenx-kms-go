package node

import "testing"

func TestAbortTracker_MajorityGatedIncrement(t *testing.T) {
	tr := &abortTracker{}

	// Majority attempting our active version V=100 -> increments.
	for i := 1; i <= 2; i++ {
		if demote := tr.recordMPKAbort(100, 100, 2); demote {
			t.Fatalf("premature demote at count %d", i)
		}
	}
	// Third consecutive on same version -> demote.
	if demote := tr.recordMPKAbort(100, 100, 2); !demote {
		t.Fatal("expected demote at 3 consecutive aborts")
	}
}

func TestAbortTracker_DoesNotCountWhenMajorityOnDifferentVersion(t *testing.T) {
	tr := &abortTracker{}
	// We rolled back to 90, but the majority is still attempting 100.
	// Our active (90) != majority (100) -> do NOT count (don't blame good 90).
	for i := 0; i < 10; i++ {
		if demote := tr.recordMPKAbort(90, 100, 2); demote {
			t.Fatal("must not demote our version when majority is on a different version")
		}
	}
	if tr.ConsecutiveAborts != 0 {
		t.Fatalf("expected 0 aborts counted, got %d", tr.ConsecutiveAborts)
	}
}

func TestAbortTracker_ResetsOnActiveVersionChange(t *testing.T) {
	tr := &abortTracker{}
	tr.recordMPKAbort(100, 100, 2) // count=1 on v100
	tr.recordMPKAbort(90, 90, 2)   // active changed -> reset, count=1 on v90
	if tr.TrackedSourceVersion != 90 || tr.ConsecutiveAborts != 1 {
		t.Fatalf("expected tracked=90 count=1, got tracked=%d count=%d", tr.TrackedSourceVersion, tr.ConsecutiveAborts)
	}
}

func TestAbortTracker_ResetOnSuccess(t *testing.T) {
	tr := &abortTracker{}
	tr.recordMPKAbort(100, 100, 2)
	tr.recordSuccess()
	if tr.ConsecutiveAborts != 0 {
		t.Fatalf("expected reset, got %d", tr.ConsecutiveAborts)
	}
}

func TestRollbackTarget(t *testing.T) {
	never := func(int64) bool { return false }
	// Prefer LKG when usable.
	if got, ok := rollbackTarget(90, 100, []int64{80, 90, 100}, never); !ok || got != 90 {
		t.Fatalf("expected LKG 90, got %d ok=%v", got, ok)
	}
	// No LKG -> highest persisted below poison.
	if got, ok := rollbackTarget(0, 100, []int64{70, 80, 100}, never); !ok || got != 80 {
		t.Fatalf("expected walk-back 80, got %d ok=%v", got, ok)
	}
	// Skip a poisoned candidate.
	poisoned := map[int64]bool{80: true}
	if got, ok := rollbackTarget(0, 100, []int64{70, 80, 100}, func(v int64) bool { return poisoned[v] }); !ok || got != 70 {
		t.Fatalf("expected 70 (skip poisoned 80), got %d ok=%v", got, ok)
	}
	// Floor: nothing below poison.
	if _, ok := rollbackTarget(0, 100, []int64{100, 110}, never); ok {
		t.Fatal("expected floor (no target)")
	}
}
