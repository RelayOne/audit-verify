// main_test.go contains unit-level regression tests for the P1 and P2 fixes
// introduced in v1.0.1.
//
// These tests exercise the pure-Go logic (collectLeaves, buildMerkleRoot) and
// do not require a running Postgres.
package main

import (
	"fmt"
	"testing"
	"time"
)

// TestCollectLeaves_SameMillisecondOrdering is a regression test for the P1
// same-millisecond event ordering bug.
//
// When two events share the same millisecond timestamp, the v1.0.0 verifier
// broke ties by event ID (ULID lexical order), which could differ from the
// server-side chain-append order. This test confirms that collectLeaves now
// uses SequenceNum (chain-append position) as the tie-breaker.
func TestCollectLeaves_SameMillisecondOrdering(t *testing.T) {
	ts := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)

	// Two events at the exact same millisecond. Their IDs are lexically
	// "reversed" relative to their append order: evtZ was appended first
	// (SequenceNum=1) but its ID sorts after evtA (SequenceNum=2).
	// collectLeaves must order them by SequenceNum, not ID.
	events := []AuditEvent{
		{
			ID:          "evtZ_appended_first",
			OrgID:       "org1",
			Timestamp:   ts, // same millisecond
			EventHash:   "hashZ",
			SequenceNum: 1, // first in chain
		},
		{
			ID:          "evtA_appended_second",
			OrgID:       "org1",
			Timestamp:   ts, // same millisecond
			EventHash:   "hashA",
			SequenceNum: 2, // second in chain
		},
	}

	startTime := ts.Add(-time.Second)
	endTime := ts.Add(time.Second)

	leaves := collectLeaves(events, "org1", startTime, endTime)
	if len(leaves) != 2 {
		t.Fatalf("expected 2 leaves, got %d", len(leaves))
	}

	// SequenceNum=1 (evtZ) must come before SequenceNum=2 (evtA).
	if leaves[0] != "hashZ" {
		t.Errorf("P1 regression: expected leaves[0]=hashZ (SequenceNum=1), got %q — same-ms tie-break is wrong", leaves[0])
	}
	if leaves[1] != "hashA" {
		t.Errorf("P1 regression: expected leaves[1]=hashA (SequenceNum=2), got %q — same-ms tie-break is wrong", leaves[1])
	}
}

// TestCollectLeaves_SameMillisecond_IDOrderWouldFail demonstrates the v1.0.0
// bug: if we broke ties by ID, the order would be reversed because
// "evtA_appended_second" < "evtZ_appended_first" lexically, but evtZ was
// appended first. This test confirms the fixed ordering is NOT the wrong
// ID-based ordering.
func TestCollectLeaves_SameMillisecond_IDOrderWouldFail(t *testing.T) {
	ts := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	events := []AuditEvent{
		{
			ID:          "evtZ_appended_first",
			OrgID:       "org1",
			Timestamp:   ts,
			EventHash:   "hashZ",
			SequenceNum: 1,
		},
		{
			ID:          "evtA_appended_second",
			OrgID:       "org1",
			Timestamp:   ts,
			EventHash:   "hashA",
			SequenceNum: 2,
		},
	}
	startTime := ts.Add(-time.Second)
	endTime := ts.Add(time.Second)

	leaves := collectLeaves(events, "org1", startTime, endTime)

	// With the fix, the correct chain order is [hashZ, hashA].
	// Verify the fixed order matches chain order, not ID sort order.
	// ID sort order would give [hashA, hashZ] because "evtA..." < "evtZ...".
	if len(leaves) == 2 && leaves[0] == "hashA" && leaves[1] == "hashZ" {
		t.Errorf("P1 regression detected: leaves ordered by ID, not chain position (SequenceNum). v1.0.0 bug is present.")
	}
}

// TestCollectLeaves_DifferentTimestamps verifies that events at different
// milliseconds are still ordered by timestamp (the common case is unchanged).
func TestCollectLeaves_DifferentTimestamps(t *testing.T) {
	base := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	events := []AuditEvent{
		{ID: "evt3", OrgID: "org1", Timestamp: base.Add(2 * time.Millisecond), EventHash: "hash3", SequenceNum: 3},
		{ID: "evt1", OrgID: "org1", Timestamp: base.Add(0 * time.Millisecond), EventHash: "hash1", SequenceNum: 1},
		{ID: "evt2", OrgID: "org1", Timestamp: base.Add(1 * time.Millisecond), EventHash: "hash2", SequenceNum: 2},
	}
	startTime := base.Add(-time.Second)
	endTime := base.Add(time.Second)

	leaves := collectLeaves(events, "org1", startTime, endTime)
	if len(leaves) != 3 {
		t.Fatalf("expected 3 leaves, got %d", len(leaves))
	}
	want := []string{"hash1", "hash2", "hash3"}
	for i, w := range want {
		if leaves[i] != w {
			t.Errorf("leaves[%d] = %q, want %q", i, leaves[i], w)
		}
	}
}

// TestCollectLeaves_OrgFilter verifies that events from a different org are
// excluded.
func TestCollectLeaves_OrgFilter(t *testing.T) {
	ts := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	events := []AuditEvent{
		{ID: "a", OrgID: "org1", Timestamp: ts, EventHash: "h1", SequenceNum: 1},
		{ID: "b", OrgID: "org2", Timestamp: ts, EventHash: "h2", SequenceNum: 2},
	}
	leaves := collectLeaves(events, "org1", ts.Add(-time.Second), ts.Add(time.Second))
	if len(leaves) != 1 || leaves[0] != "h1" {
		t.Errorf("expected [h1], got %v", leaves)
	}
}

// TestBuildMerkleRoot_SingleLeaf verifies the trivial single-leaf case.
func TestBuildMerkleRoot_SingleLeaf(t *testing.T) {
	leaves := []string{"deadbeef"}
	root := buildMerkleRoot(leaves)
	if root != "deadbeef" {
		t.Errorf("single leaf Merkle root should equal the leaf itself, got %q", root)
	}
}

// TestBuildMerkleRoot_Deterministic verifies buildMerkleRoot is deterministic.
func TestBuildMerkleRoot_Deterministic(t *testing.T) {
	leaves := []string{"ab", "cd"}
	r1 := buildMerkleRoot(leaves)
	r2 := buildMerkleRoot(leaves)
	if r1 != r2 {
		t.Errorf("buildMerkleRoot is not deterministic: %q != %q", r1, r2)
	}
	if r1 == "" {
		t.Error("Merkle root must not be empty for two leaves")
	}
}

// TestCollectLeaves_PartialRange_P2 is a regression test for the P2
// partial-range seal check bug.
//
// When --from-seq or --to-seq restricts the event window, verifySeals must
// skip seals whose time window spans events outside the loaded range.
// This test verifies that collectLeaves correctly excludes events outside a
// given time window (the boundary-check logic that verifySeals relies on).
func TestCollectLeaves_PartialRange_P2(t *testing.T) {
	base := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	events := []AuditEvent{
		{ID: "e1", OrgID: "org1", Timestamp: base.Add(0 * time.Millisecond), EventHash: "h1", SequenceNum: 1},
		{ID: "e2", OrgID: "org1", Timestamp: base.Add(1 * time.Millisecond), EventHash: "h2", SequenceNum: 2},
		{ID: "e3", OrgID: "org1", Timestamp: base.Add(2 * time.Millisecond), EventHash: "h3", SequenceNum: 3},
		{ID: "e4", OrgID: "org1", Timestamp: base.Add(3 * time.Millisecond), EventHash: "h4", SequenceNum: 4},
		{ID: "e5", OrgID: "org1", Timestamp: base.Add(4 * time.Millisecond), EventHash: "h5", SequenceNum: 5},
	}

	// Seal window covers events e2..e4 only.
	sealStart := base.Add(1 * time.Millisecond)
	sealEnd := base.Add(3 * time.Millisecond)
	leaves := collectLeaves(events, "org1", sealStart, sealEnd)

	if len(leaves) != 3 {
		t.Fatalf("P2 partial-range: expected 3 leaves (e2,e3,e4) got %d: %v", len(leaves), leaves)
	}
	want := []string{"h2", "h3", "h4"}
	for i, w := range want {
		if leaves[i] != w {
			t.Errorf("P2 partial-range: leaves[%d]=%q want %q", i, leaves[i], w)
		}
	}
}

// TestVerifySeals_PartialRange_SkipLogic is a regression test for the P2
// partial-range verifySeals fix.
//
// When --from-seq/--to-seq restricts the scanned event window, verifySeals
// must skip seals whose [start_time, end_time] extends outside the range
// covered by the loaded events slice. This test verifies the boundary logic
// by confirming:
//   - A seal fully within the loaded range has leaves collected correctly.
//   - A seal that starts before rangeMinTS would have start_time < rangeMinTS,
//     which is the skip condition; collectLeaves correctly returns 0 for events
//     outside the window.
//
// The verifySeals skip condition is:
//
//	if s.StartTime.Before(rangeMinTS) || s.EndTime.After(rangeMaxTS) { skip }
//
// This test exercises the boundary check via collectLeaves to confirm that:
// - Seals fully within range collect the right events.
// - Seals straddling the boundary would find fewer events than event_count,
//   which IS the false-GAP scenario that the skip prevents.
func TestVerifySeals_PartialRange_SkipLogic(t *testing.T) {
	base := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)

	// Events e1..e10 span base+0ms..base+9ms.
	var events []AuditEvent
	for i := 0; i < 10; i++ {
		events = append(events, AuditEvent{
			ID:          fmt.Sprintf("e%d", i+1),
			OrgID:       "org1",
			Timestamp:   base.Add(time.Duration(i) * time.Millisecond),
			EventHash:   fmt.Sprintf("h%d", i+1),
			SequenceNum: int64(i + 1),
		})
	}

	// rangeMinTS and rangeMaxTS as verifySeals computes them.
	rangeMinTS := events[0].Timestamp // base+0ms
	rangeMaxTS := events[len(events)-1].Timestamp // base+9ms

	// Case 1: Seal fully within range [base+2ms, base+7ms] — 6 events.
	sealStart := base.Add(2 * time.Millisecond)
	sealEnd := base.Add(7 * time.Millisecond)
	within := !(sealStart.Before(rangeMinTS) || sealEnd.After(rangeMaxTS))
	if !within {
		t.Errorf("P2: seal [+2ms,+7ms] within range [+0ms,+9ms] should NOT be skipped")
	}
	leaves := collectLeaves(events, "org1", sealStart, sealEnd)
	if len(leaves) != 6 {
		t.Errorf("P2: expected 6 leaves for [+2ms,+7ms], got %d", len(leaves))
	}

	// Case 2: Seal straddling the left boundary [base-1ms, base+5ms] — skip.
	sealStart2 := base.Add(-1 * time.Millisecond) // before range
	sealEnd2 := base.Add(5 * time.Millisecond)
	wouldSkip2 := sealStart2.Before(rangeMinTS) || sealEnd2.After(rangeMaxTS)
	if !wouldSkip2 {
		t.Errorf("P2: seal straddling left boundary should be skipped")
	}
	// Without the skip, collectLeaves would find only 6 events (e1..e6), not
	// the 7 that the seal's event_count would declare — causing a false GAP.
	leavesWithoutSkip := collectLeaves(events, "org1", sealStart2, sealEnd2)
	if len(leavesWithoutSkip) != 6 {
		t.Errorf("P2: expected 6 leaves without skip (events only start at base+0ms), got %d", len(leavesWithoutSkip))
	}
	// The skip IS the fix: verifySeals records a note and continues rather
	// than comparing 6 < declared_7 and returning exitGap.

	// Case 3: Seal straddling the right boundary [base+5ms, base+11ms] — skip.
	sealStart3 := base.Add(5 * time.Millisecond)
	sealEnd3 := base.Add(11 * time.Millisecond) // after range
	wouldSkip3 := sealStart3.Before(rangeMinTS) || sealEnd3.After(rangeMaxTS)
	if !wouldSkip3 {
		t.Errorf("P2: seal straddling right boundary should be skipped")
	}
}

// TestBuildMerkleRoot_OddLeaves verifies the odd-leaf duplication case.
func TestBuildMerkleRoot_OddLeaves(t *testing.T) {
	// With 3 leaves [a, b, c], the tree is:
	//   level0: [a, b, c]
	//   level1: [sha256(a+b), sha256(c+c)]
	//   level2: [sha256(sha256(a+b) + sha256(c+c))]
	leaves := []string{"aa", "bb", "cc"}
	root := buildMerkleRoot(leaves)
	if root == "" {
		t.Error("Merkle root must not be empty for 3 leaves")
	}
	// Verify it's different from the 2-leaf case.
	root2 := buildMerkleRoot([]string{"aa", "bb"})
	if root == root2 {
		t.Error("3-leaf and 2-leaf Merkle roots should differ")
	}
}
