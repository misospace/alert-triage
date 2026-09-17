package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHistoryRetentionCutoff(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	retain := 2 * time.Hour

	now := time.Now()
	old := now.Add(-3 * time.Hour)
	recent := now.Add(-1 * time.Hour)

	// Write JSONL entries with varying ages.
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	enc.Encode(sighting{Signature: "old_sig", Title: "old_title", At: old})
	enc.Encode(sighting{Signature: "recent_sig", Title: "recent_title", At: recent})
	f.Close()

	h, err := NewHistory(path, retain)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(h.entries); got != 1 {
		t.Errorf("expected 1 entry after retention cutoff, got %d", got)
	}
	if len(h.entries) > 0 && h.entries[0].Signature != "recent_sig" {
		t.Errorf("expected recent_sig, got %s", h.entries[0].Signature)
	}
}

func TestHistoryTruncatedFinalLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	retain := 24 * time.Hour

	now := time.Now()
	valid := sighting{Signature: "valid_sig", Title: "valid_title", At: now}

	// Write a valid JSON line followed by truncated garbage.
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	json.NewEncoder(f).Encode(valid)
	f.WriteString(`{"sig":"partial`) // truncated, no newline
	f.Close()

	h, err := NewHistory(path, retain)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(h.entries); got != 1 {
		t.Errorf("expected 1 entry (truncated line skipped), got %d", got)
	}
	if len(h.entries) > 0 && h.entries[0].Signature != "valid_sig" {
		t.Errorf("expected valid_sig, got %s", h.entries[0].Signature)
	}
}

func TestHistoryRecordPriorCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	retain := 24 * time.Hour

	h, err := NewHistory(path, retain)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	count1 := h.Record("sig_a", "title_a", now)
	if count1 != 0 {
		t.Errorf("first Record expected prior count 0, got %d", count1)
	}
	count2 := h.Record("sig_a", "title_a", now.Add(time.Minute))
	if count2 != 1 {
		t.Errorf("second Record for same sig expected prior count 1, got %d", count2)
	}
	count3 := h.Record("sig_b", "title_b", now)
	if count3 != 0 {
		t.Errorf("Record for different sig expected prior count 0, got %d", count3)
	}
}

func TestHistoryCompactExpiry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	retain := 1 * time.Second

	h, err := NewHistory(path, retain)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	oldTime := now.Add(-2 * time.Second)
	h.Record("old_sig", "old_title", oldTime)
	h.Record("new_sig", "new_title", now)

	if err := h.Compact(); err != nil {
		t.Fatal(err)
	}

	// Reload to verify only recent entries persisted.
	h2, err := NewHistory(path, retain)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(h2.entries); got != 1 {
		t.Errorf("expected 1 entry after Compact expiry, got %d", got)
	}
	if len(h2.entries) > 0 && h2.entries[0].Signature != "new_sig" {
		t.Errorf("expected new_sig, got %s", h2.entries[0].Signature)
	}
}

func TestHistoryCompactAtomicRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	retain := 24 * time.Hour

	h, err := NewHistory(path, retain)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	h.Record("sig_x", "title_x", now)

	if err := h.Compact(); err != nil {
		t.Fatal(err)
	}

	// Verify the temp file was cleaned up and original exists.
	tmpPath := path + ".tmp"
	if _, err := os.Stat(tmpPath); err == nil {
		t.Error("expected temp file to be removed after Compact")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected history file to exist after Compact: %v", err)
	}
}

func TestHistoryPriorSeenCountsOnlyMatchingSigs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	retain := 24 * time.Hour

	h, err := NewHistory(path, retain)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	// Seed entries directly so we can pin the timestamps.
	h.entries = append(h.entries,
		sighting{Signature: "alpha", Title: "alpha-title", At: now.Add(-3 * time.Hour)},
		sighting{Signature: "alpha", Title: "alpha-title", At: now.Add(-1 * time.Hour)},
		sighting{Signature: "beta", Title: "beta-title", At: now.Add(-30 * time.Minute)},
	)

	if got := h.PriorSeen("alpha", "alpha-title"); got != 2 {
		t.Errorf("PriorSeen(alpha) = %d, want 2", got)
	}
	if got := h.PriorSeen("beta", "beta-title"); got != 1 {
		t.Errorf("PriorSeen(beta) = %d, want 1", got)
	}
	if got := h.PriorSeen("missing", "missing-title"); got != 0 {
		t.Errorf("PriorSeen(missing) = %d, want 0", got)
	}

	// PriorSeen must not record a sighting; Record still returns prior==2 next time.
	if got := h.Record("alpha", "alpha-title", now); got != 2 {
		t.Errorf("Record(alpha) prior = %d, want 2 (PriorSeen must not have mutated state)", got)
	}
}

func TestHistoryPriorSeenExcludesExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	retain := 1 * time.Hour

	h, err := NewHistory(path, retain)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	h.entries = append(h.entries,
		sighting{Signature: "old", Title: "old", At: now.Add(-3 * time.Hour)},
		sighting{Signature: "fresh", Title: "fresh", At: now.Add(-10 * time.Minute)},
	)

	if got := h.PriorSeen("old", "old"); got != 0 {
		t.Errorf("PriorSeen should drop expired entry, got %d", got)
	}
	if got := h.PriorSeen("fresh", "fresh"); got != 1 {
		t.Errorf("PriorSeen should keep in-window entry, got %d", got)
	}
}

func TestHistoryNewHistorySurvivesUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	retain := 1 * time.Hour

	// Point the history at a path that cannot be opened (a directory
	// stands in for a permission-denied / corrupted-mount case: os.Open
	// on a directory fails on every supported platform).
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}

	h, err := NewHistory(path, retain)
	if err != nil {
		t.Fatalf("NewHistory should not return an error for an unreadable file, got %v", err)
	}
	if h == nil {
		t.Fatal("NewHistory returned a nil history")
	}
	if len(h.entries) != 0 {
		t.Errorf("expected empty history when load cannot read the file, got %d entries", len(h.entries))
	}
}

// TestHistoryPriorSeenDoesNotRecord asserts that PriorSeen is a pure
// read: calling it must not append a sighting to history.jsonl. This
// is the contract process() relies on to avoid "seen N time(s) recently"
// claims for fires the operator never received (see issue #102).
func TestHistoryPriorSeenDoesNotRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	retain := 24 * time.Hour

	h, err := NewHistory(path, retain)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if got := h.PriorSeen("sig_a", "title_a"); got != 0 {
			t.Errorf("PriorSeen iter %d = %d, want 0 (must not mutate state)", i, got)
		}
	}

	// The on-disk file must not exist; PriorSeen never opens it for write.
	if _, err := os.Stat(path); err == nil {
		t.Errorf("PriorSeen should not create %s, but it exists", path)
	}
}

// TestProcessHistoryRollbackOnDeliveryFailure is the acceptance test for
// issue #102. It reproduces the process() flow without HTTP: the first
// pass reads PriorSeen (no record), the third pass only calls Record if
// the simulated Deliver succeeded.
//
// Scenario from the issue:
//  1. Fire 1: Deliver fails -> no history.jsonl entry, PriorSeen=0.
//  2. Fire 2: Deliver succeeds -> PriorSeen=0 (fire 1 must not count),
//     and the on-disk file gets exactly one entry. Fire 2's footer
//     reads "first time seen".
//  3. Fire 3 (after reload): PriorSeen must be 1 (only the successful
//     fire counts), so the footer reads "seen 1 time(s) recently".
//
// And separately, if the *third* fire's Deliver fails, history.jsonl
// must remain at exactly one entry — no stray sighting for the failed
// fire 3.
func TestProcessHistoryRollbackOnDeliveryFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	retain := 24 * time.Hour

	h, err := NewHistory(path, retain)
	if err != nil {
		t.Fatal(err)
	}

	const sig = "node_not_ready"
	const title = "node-not-ready"

	deliver := func() bool { return false } // every Deliver() returns an error

	fire := func(label string, ok bool, wantPrior int) {
		deliver = func() bool { return ok }

		// Pass 1: count only, do not record.
		prior := h.PriorSeen(sig, title)
		if prior != wantPrior {
			t.Errorf("%s: prior before record = %d, want %d", label, prior, wantPrior)
		}

		// Pass 3: only record if Deliver succeeded.
		if deliver() {
			h.Record(sig, title, time.Now())
		}
	}

	// Fire 1: fails. The operator never saw anything; PriorSeen must be 0
	// and no line may be appended to history.jsonl.
	fire("fire-1 fails", false, 0)

	// Fire 2: succeeds. PriorSeen must still be 0 (failed fire 1 is not
	// counted) so the footer reads "first time seen", and exactly one
	// line lands on disk after this fire.
	fire("fire-2 succeeds", true, 0)

	// Fire 3: fails. Now prior is 1 (the successful fire 2), and no
	// additional line may be appended because this delivery failed.
	fire("fire-3 fails", false, 1)

	// Reload from disk to confirm only the successful fire was persisted.
	reloaded, err := NewHistory(path, retain)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(reloaded.entries); got != 1 {
		t.Fatalf("after fail/succeed/fail sequence, history.jsonl should hold 1 sighting, got %d", got)
	}
	if got := reloaded.PriorSeen(sig, title); got != 1 {
		t.Errorf("after the three fires, PriorSeen = %d, want 1 (only the successful fire counts)", got)
	}
}

// TestProcessHistoryNoLeakOnFirstFire verifies that an entirely failing
// alert (Deliver returns an error on every fire) never leaves a sighting
// behind, so a later successful fire claims "first time seen" rather
// than "seen N time(s) recently" with N from failed deliveries.
func TestProcessHistoryNoLeakOnFirstFire(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	retain := 24 * time.Hour

	h, err := NewHistory(path, retain)
	if err != nil {
		t.Fatal(err)
	}

	const sig = "disk_pressure"
	const title = "disk-pressure"

	// Fire 1: Deliver fails.
	if got := h.PriorSeen(sig, title); got != 0 {
		t.Fatalf("fire 1 prior = %d, want 0", got)
	}
	// Deliver fails -> no Record call.

	// Reload and confirm the file is still empty / non-existent.
	reloaded, err := NewHistory(path, retain)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(reloaded.entries); got != 0 {
		t.Fatalf("fire 1 (failed) should leave no sightings, found %d", got)
	}

	// Fire 2: Deliver succeeds.
	if got := h.PriorSeen(sig, title); got != 0 {
		t.Fatalf("fire 2 prior = %d, want 0 (failed fire 1 must not count)", got)
	}
	h.Record(sig, title, time.Now())

	// Re-read after the successful fire: this fire saw "first time".
	reloaded, err = NewHistory(path, retain)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.PriorSeen(sig, title); got != 1 {
		t.Errorf("after 1 fail + 1 success, PriorSeen = %d, want 1", got)
	}
}

// TestHistoryCompactDoesNotBlockPriorSeenDuringRewrite is the regression
// test for issue #147: Compact's temp-file write and rename used to run
// under h.mu, so a slow filesystem stalled every PriorSeen and Record
// caller until the rename returned. The fix releases the lock around
// the on-disk work and only re-acquires it to swap the in-memory slice.
//
// The test installs a hook that blocks Compact between the temp-file
// write and the rename, simulating a slow filesystem, and asserts that
// a concurrent PriorSeen returns well before the hook fires — i.e. the
// read waited only on the swap window, not the rewrite window.
func TestHistoryCompactDoesNotBlockPriorSeenDuringRewrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	retain := 24 * time.Hour

	h, err := NewHistory(path, retain)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	if got := h.Record("sig_a", "title_a", now); got != 0 {
		t.Fatalf("seed Record prior = %d, want 0", got)
	}

	// Install a hook that blocks Compact between the temp-file write
	// and the rename. The signal channel lets the test wait until
	// Compact has actually reached the rewrite before launching
	// PriorSeen, so the assertion is about the lock-not-held window.
	entered := make(chan struct{})
	release := make(chan struct{})
	oldHook := compactRewriteDelay
	compactRewriteDelay = func() {
		close(entered)
		<-release
	}
	t.Cleanup(func() { compactRewriteDelay = oldHook })

	compactDone := make(chan error, 1)
	go func() { compactDone <- h.Compact() }()

	// Wait for Compact to enter the rewrite window before timing
	// PriorSeen, so we measure the lock-free window, not the snapshot
	// or swap.
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		<-compactDone
		t.Fatal("Compact did not reach the rewrite hook within 2s")
	}

	start := time.Now()
	got := h.PriorSeen("sig_a", "title_a")
	elapsed := time.Since(start)

	if got != 1 {
		t.Errorf("PriorSeen = %d, want 1", got)
	}
	// The rewrite hook blocks for ~100ms (set below). If Compact still
	// held h.mu across the rewrite, PriorSeen would block here too.
	// Allow generous slack for scheduler jitter but still well under
	// the rewrite window.
	if elapsed > 50*time.Millisecond {
		t.Errorf("PriorSeen blocked for %v during Compact rewrite; expected sub-millisecond (lock must be released during the rewrite)", elapsed)
	}

	// Release the hook and let Compact finish; surface any error.
	close(release)
	if err := <-compactDone; err != nil {
		t.Fatalf("Compact returned %v after the rewrite delay", err)
	}
}

// TestHistoryCompactReleasesLockDuringRewrite pairs with the prior-seen
// test to cover the writer side of issue #147: a Record running while
// Compact is mid-rewrite must not block on the rewrite either. It also
// verifies the post-rewrite ordering invariant from the issue: the
// appended line lands in either the pre-rename file (lost on rename,
// but the call itself does not error) or the post-rename file (kept).
func TestHistoryCompactReleasesLockDuringRewrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	retain := 24 * time.Hour

	h, err := NewHistory(path, retain)
	if err != nil {
		t.Fatal(err)
	}

	// Block Compact mid-rewrite so Record runs concurrently with it.
	entered := make(chan struct{})
	release := make(chan struct{})
	oldHook := compactRewriteDelay
	compactRewriteDelay = func() {
		close(entered)
		<-release
	}
	t.Cleanup(func() { compactRewriteDelay = oldHook })

	compactDone := make(chan error, 1)
	go func() { compactDone <- h.Compact() }()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		<-compactDone
		t.Fatal("Compact did not reach the rewrite hook within 2s")
	}

	// Record runs while Compact is mid-rewrite. It must return quickly
	// (no half-temp error) and not deadlock on h.mu.
	start := time.Now()
	prior := h.Record("sig_b", "title_b", time.Now())
	elapsed := time.Since(start)

	if elapsed > 50*time.Millisecond {
		t.Errorf("Record blocked for %v during Compact rewrite; expected sub-millisecond", elapsed)
	}
	if prior != 0 {
		t.Errorf("Record prior = %d, want 0", prior)
	}

	close(release)
	if err := <-compactDone; err != nil {
		t.Fatalf("Compact returned %v after the rewrite delay", err)
	}

	// Reload the on-disk file. Whether the appended line landed
	// pre-rename (lost) or post-rename (kept), the file must be valid
	// JSONL and must not show a half-written temp artifact.
	reloaded, err := NewHistory(path, retain)
	if err != nil {
		t.Fatalf("reload after Compact: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Error(".tmp file leaked after Compact")
	}
	for i, e := range reloaded.entries {
		if e.Signature == "" || e.Title == "" {
			t.Errorf("entry %d is malformed: %+v", i, e)
		}
	}
}
