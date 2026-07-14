package node

import "sort"

// demotionThreshold is the number of consecutive MPK-validation aborts on the
// same active source version after which that version is declared poisoned.
const demotionThreshold = 3

// abortTracker counts consecutive Layer-1 MPK-validation aborts on the same
// active source version, majority-gated so an early roller does not over-walk.
type abortTracker struct {
	TrackedSourceVersion int64
	ConsecutiveAborts    int
}

// recordMPKAbort applies the majority-gated increment. It returns demote=true
// when the counter reaches demotionThreshold on the active source version.
//
//   - If the active source version changed since we last tracked, reset and
//     start counting the new version (preserves "resets on active-version change").
//   - Only increment when the round's agreed majority source version equals our
//     active source version — i.e. the cluster is actually attempting OUR version.
//     A node that has already rolled back to a lower version does not count aborts
//     that the majority incurs on the still-poisoned higher version.
func (t *abortTracker) recordMPKAbort(activeSourceVersion, majoritySrcVersion int64, threshold int) bool {
	if t.TrackedSourceVersion != activeSourceVersion {
		t.TrackedSourceVersion = activeSourceVersion
		t.ConsecutiveAborts = 0
	}
	if majoritySrcVersion != activeSourceVersion {
		return false
	}
	t.ConsecutiveAborts++
	return t.ConsecutiveAborts >= demotionThreshold
}

// recordSuccess resets the counter after a round that passed MPK validation.
func (t *abortTracker) recordSuccess() {
	t.ConsecutiveAborts = 0
}

// rollbackTarget picks the demotion rollback target. Prefers the last-known-good
// source version when it is usable (present, below the poisoned version, not
// itself poisoned); otherwise the highest persisted version strictly below the
// poisoned one that is not poisoned. Returns ok=false when none exists (floor).
func rollbackTarget(lkg int64, poisonedVersion int64, persistedVersions []int64, isPoisoned func(int64) bool) (int64, bool) {
	if lkg > 0 && lkg < poisonedVersion && !isPoisoned(lkg) {
		return lkg, true
	}
	sorted := append([]int64(nil), persistedVersions...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] > sorted[j] }) // descending
	for _, v := range sorted {
		if v < poisonedVersion && !isPoisoned(v) {
			return v, true
		}
	}
	return 0, false
}
