package node

import (
	"sort"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
)

// demotionThreshold is the number of consecutive MPK-validation aborts on the
// same active source version after which that version is declared poisoned.
const demotionThreshold = 3

// abortTracker counts consecutive Layer-1 MPK-validation aborts on the same
// active source version, majority-gated so an early roller does not over-walk.
//
// Thread-safety: these fields are read/written without a mutex. This is safe
// ONLY because checkScheduledOperations (node.go ~735) guarantees at most one
// reshare goroutine runs at a time — it skips the boundary if any protocol
// session is already active, so recordMPKAbort / recordSuccess never race. A
// future change that permits overlapping reshare sessions MUST add
// synchronization (or route mutations through a single owner) here.
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
func (t *abortTracker) recordMPKAbort(activeSourceVersion, majoritySrcVersion int64) bool {
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

// onMPKValidationAbort records a Layer-1 MPK-validation abort against the active
// source version (majority-gated) and, on reaching the demotion threshold,
// demotes the active version and rolls back. Persists the counter each call.
func (n *Node) onMPKValidationAbort(activeSourceVersion, majoritySrcVersion int64) {
	demote := n.abortTracker.recordMPKAbort(activeSourceVersion, majoritySrcVersion)
	n.persistAbortTracker()
	if !demote {
		return
	}
	n.logger.Sugar().Warnw("Auto-heal: demoting poisoned source version after consecutive MPK aborts",
		"operator_address", n.OperatorAddress.Hex(),
		"poisoned_version", activeSourceVersion, "consecutive_aborts", n.abortTracker.ConsecutiveAborts)
	n.performRollback(activeSourceVersion)
}

// performRollback marks poisonedVersion poisoned (keystore + persistence) and
// re-points the active version to the rollback target (LKG or walk-back). If no
// target exists, halts rotation with a loud alert (never auto-re-DKG).
func (n *Node) performRollback(poisonedVersion int64) {
	n.keyStore.MarkPoisoned(poisonedVersion)
	if err := n.persistence.AddPoisonedVersion(poisonedVersion); err != nil {
		n.logger.Sugar().Errorw("Auto-heal: failed to persist poisoned version", "version", poisonedVersion, "error", err)
	}

	lkg := int64(0)
	if st, err := n.persistence.LoadNodeState(); err == nil && st != nil {
		lkg = st.LastKnownGoodSourceVersion
	}
	versions, verr := n.persistence.ListKeyShareVersions()
	if verr != nil {
		// Cannot enumerate the persisted versions, so we cannot safely choose a
		// rollback target. Floor loudly and RETURN here rather than continuing with
		// an empty slice — otherwise rollbackTarget might return the LKG, the
		// apply-loop would find no match, and we'd emit the misleading "target not
		// present" floor log that blames a missing target instead of the real
		// storage error. Leave the tracker untouched (as the other floor branches
		// do) so it stays loud on every re-trigger.
		n.logger.Sugar().Errorw("AUTO-HEAL FLOOR: could not list persisted versions to choose a rollback target; rotation halted, decrypt still served. MANUAL INTERVENTION REQUIRED (no auto re-DKG).",
			"operator_address", n.OperatorAddress.Hex(), "poisoned_version", poisonedVersion, "error", verr)
		return
	}
	nums := make([]int64, 0, len(versions))
	for _, v := range versions {
		nums = append(nums, v.Version)
	}
	target, ok := rollbackTarget(lkg, poisonedVersion, nums, n.keyStore.IsPoisoned)
	if !ok {
		n.logger.Sugar().Errorw("AUTO-HEAL FLOOR: no non-poisoned version below the poisoned one; rotation halted, decrypt still served. MANUAL INTERVENTION REQUIRED (no auto re-DKG).",
			"operator_address", n.OperatorAddress.Hex(), "poisoned_version", poisonedVersion)
		return
	}
	for _, v := range versions {
		if v.Version == target {
			n.keyStore.SetActiveVersion(v)
			if err := n.persistence.SetActiveVersionTimestamp(target); err != nil {
				n.logger.Sugar().Errorw("Auto-heal: failed to persist rolled-back active version", "target", target, "error", err)
			}
			// Reset the tracker to the new active version.
			n.abortTracker.TrackedSourceVersion = target
			n.abortTracker.ConsecutiveAborts = 0
			n.persistAbortTracker()
			n.logger.Sugar().Infow("Auto-heal: rolled active version back to recover rotation",
				"operator_address", n.OperatorAddress.Hex(), "from", poisonedVersion, "to", target)
			return
		}
	}
	// rollbackTarget chose a version that is not present in the persisted set
	// (defense-in-depth: e.g. a future change prunes versions below the LKG
	// marker, or LKG points outside the persisted set). Treat this exactly like
	// the floor: loudly halt rotation, never auto-re-DKG, never change the MPK,
	// and — mirroring the floor branch — leave the tracker untouched so it stays
	// loud on every re-trigger rather than silently stalling.
	n.logger.Sugar().Errorw("AUTO-HEAL FLOOR: chosen rollback target not present in persisted versions; rotation halted, decrypt still served. MANUAL INTERVENTION REQUIRED (no auto re-DKG).",
		"operator_address", n.OperatorAddress.Hex(), "poisoned_version", poisonedVersion, "target", target)
}

// persistAbortTracker writes the current tracker into NodeState (merging with
// the existing persisted state so other fields are preserved).
func (n *Node) persistAbortTracker() {
	st, err := n.persistence.LoadNodeState()
	if err != nil || st == nil {
		st = &persistence.NodeState{OperatorAddress: n.OperatorAddress.Hex()}
	}
	st.TrackedSourceVersion = n.abortTracker.TrackedSourceVersion
	st.ConsecutiveMPKAborts = n.abortTracker.ConsecutiveAborts
	if err := n.persistence.SaveNodeState(st); err != nil {
		n.logger.Sugar().Errorw("Auto-heal: failed to persist abort tracker", "error", err)
	}
}

// recordSuccessfulReshare resets the abort counter and records the agreed source
// version as last-known-good after a round that passed MPK validation.
func (n *Node) recordSuccessfulReshare(agreedSrcVersion int64) {
	n.abortTracker.recordSuccess()
	st, err := n.persistence.LoadNodeState()
	if err != nil || st == nil {
		st = &persistence.NodeState{OperatorAddress: n.OperatorAddress.Hex()}
	}
	// If the prior persisted state was mid-abort, this validated reshare confirms
	// the cluster has healed: emit a distinct info log so the recovery is greppable.
	if st.ConsecutiveMPKAborts > 0 {
		n.logger.Sugar().Infow("Auto-heal: rotation resumed (reshare validated after prior aborts)",
			"operator_address", n.OperatorAddress.Hex(),
			"prior_consecutive_aborts", st.ConsecutiveMPKAborts,
			"agreed_source_version", agreedSrcVersion)
	}
	st.ConsecutiveMPKAborts = 0
	if agreedSrcVersion > 0 {
		st.LastKnownGoodSourceVersion = agreedSrcVersion
	}
	if err := n.persistence.SaveNodeState(st); err != nil {
		n.logger.Sugar().Errorw("Auto-heal: failed to persist LKG marker", "error", err)
	}
}
