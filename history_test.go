package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewHistory_NoFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.jsonl")

	h, err := NewHistory(path, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewHistory unexpected error: %v", err)
	}
	if len(h.entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(h.entries))
	}
}

func TestNewHistory_LoadsRecentEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	now := time.Now()
	entries := []sighting{
		{Signature: "sig-a", Title: "A", At: now.Add(-1 * time.Hour)},
		{Signature: "sig-b", Title: "B", At: now.Add(-48 * time.Hour)}, // expired
		{Signature: "sig-c", Title: "C", At: now.Add(-30 * time.Minute)},
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	h, err := NewHistory(path, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewHistory error: %v", err)
	}
	// Only the two recent entries should survive retention cutoff.
	if len(h.entries) != 2 {
		t.Fatalf("expected 2 entries after retention cutoff, got %d", len(h.entries))
	}
}

func TestNewHistory_ToleratesTruncatedFinalLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	now := time.Now()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Write a valid line.
	json.NewEncoder(f).Encode(sighting{Signature: "good", Title: "Good", At: now})
	// Write a truncated JSON line (simulates killed mid-write).
	f.WriteString(`{"sig":"bad","title":"Bad","at":"2024-`)
	f.Close()

	h, err := NewHistory(path, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewHistory should tolerate truncated line: %v", err)
	}
	if len(h.entries) != 1 {
		t.Fatalf("expected 1 entry (truncated line skipped), got %d", len(h.entries))
	}
	if h.entries[0].Signature != "good" {
		t.Fatalf("expected signature 'good', got %q", h.entries[0].Signature)
	}
}

func TestNewHistory_SkipsEmptyLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	now := time.Now()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("\n")
	json.NewEncoder(f).Encode(sighting{Signature: "sig", Title: "T", At: now})
	f.WriteString("\n\n")
	f.Close()

	h, err := NewHistory(path, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewHistory error: %v", err)
	}
	if len(h.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(h.entries))
	}
}

func TestRecord_PriorCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	h, err := NewHistory(path, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()

	// First record: prior = 0
	prior := h.Record("sig-a", "Alert A", now)
	if prior != 0 {
		t.Fatalf("first record expected prior=0, got %d", prior)
	}

	// Second record same sig: prior = 1
	prior = h.Record("sig-a", "Alert A again", now.Add(1*time.Minute))
	if prior != 1 {
		t.Fatalf("second record expected prior=1, got %d", prior)
	}

	// Third record different sig: prior = 0
	prior = h.Record("sig-b", "Alert B", now.Add(2*time.Minute))
	if prior != 0 {
		t.Fatalf("different sig expected prior=0, got %d", prior)
	}

	// Fourth record same sig-a: prior = 2 (both previous sig-a entries)
	prior = h.Record("sig-a", "Alert A third time", now.Add(3*time.Minute))
	if prior != 2 {
		t.Fatalf("expected prior=2, got %d", prior)
	}
}

func TestRecord_ExpiresOldEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	h, err := NewHistory(path, 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()

	// Record an entry.
	h.Record("sig-a", "A", now.Add(-2*time.Hour))

	// Record a new entry; the old one is outside the 1h retention window.
	prior := h.Record("sig-a", "A again", now)
	if prior != 0 {
		t.Fatalf("expected prior=0 (old entry expired), got %d", prior)
	}
}

func TestRecord_PersistsToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	h, err := NewHistory(path, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	h.Record("sig-x", "X", now)

	// Read the file directly.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("file not written: %v", err)
	}
	if !strings.Contains(string(data), "sig-x") {
		t.Fatalf("expected file to contain 'sig-x', got: %s", string(data))
	}
}

func TestRecord_NoPath(t *testing.T) {
	h, err := NewHistory("", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Should not panic with empty path.
	h.Record("sig", "T", time.Now())
}

func TestCompact_RewritesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	now := time.Now()
	h, err := NewHistory(path, 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Add entries: one recent, one old.
	h.entries = []sighting{
		{Signature: "old", Title: "Old", At: now.Add(-2 * time.Hour)},
		{Signature: "new", Title: "New", At: now.Add(-30 * time.Minute)},
	}

	if err := h.Compact(); err != nil {
		t.Fatalf("Compact error: %v", err)
	}

	// Only the recent entry should remain.
	if len(h.entries) != 1 {
		t.Fatalf("expected 1 entry after compact, got %d", len(h.entries))
	}
	if h.entries[0].Signature != "new" {
		t.Fatalf("expected 'new', got %q", h.entries[0].Signature)
	}

	// Verify the file was rewritten.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("file not found after compact: %v", err)
	}
	if strings.Contains(string(data), "old") {
		t.Fatalf("compact should have removed old entry; got: %s", string(data))
	}
	if !strings.Contains(string(data), "new") {
		t.Fatalf("compact should keep new entry; got: %s", string(data))
	}
}

func TestCompact_NoPath(t *testing.T) {
	h, err := NewHistory("", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Should not error with empty path.
	if err := h.Compact(); err != nil {
		t.Fatalf("Compact with no path should return nil, got: %v", err)
	}
}

func TestCompact_EmptyHistory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	h, err := NewHistory(path, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if err := h.Compact(); err != nil {
		t.Fatalf("Compact on empty history error: %v", err)
	}
}

func TestCompact_AtomicRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	h, err := NewHistory(path, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	h.Record("sig", "T", now)

	if err := h.Compact(); err != nil {
		t.Fatalf("Compact error: %v", err)
	}

	// The .tmp file should not exist after successful compact.
	tmpPath := path + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("expected .tmp file to be cleaned up, but it exists")
	}
}
