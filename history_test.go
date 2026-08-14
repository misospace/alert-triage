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
