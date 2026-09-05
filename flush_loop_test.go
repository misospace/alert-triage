package main

// Tests for runFlushLoop / drainBuffer / runCompactLoop.
//
// Issue #83 named main_test.go as the expected home for the shutdown-drain
// test, but drainBuffer is package-private state on the same goroutine-shape
// as runFlushLoop itself — exercising the drain path here keeps the flush
// tests grouped with their buffer mechanism rather than mixed into TestMain
// shape tests in main_test.go. The earlier delta extracted drainBuffer from
// inline closure to a method for this exact reason.

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// bufferLen returns the buffer's length with its mutex held. The package
// does not expose a Len method.
func bufferLen(b *buffer) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.alerts)
}

// stubKube builds a kube whose HTTP client talks to a test server that
// answers /api/v1/nodes with an empty list. Every call increments the
// counter so tests can assert the path was hit.
func stubKube(t *testing.T) (*kube, *int64) {
	t.Helper()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		// empty result list — covers the not-found branches cheaply.
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	t.Cleanup(srv.Close)
	return &kube{hc: srv.Client(), base: srv.URL}, &hits
}

// TestRunFlushLoopTick exercises the tick-driven path of runFlushLoop: an
// alert pushed into the buffer must be drained by the next tick, and the
// real process path must run end-to-end without panicking.
func TestRunFlushLoopTick(t *testing.T) {
	cfg := &Config{FlushDelay: 20 * time.Millisecond, MaxWindow: time.Second}
	buf := &buffer{}
	old := time.Now().Add(-time.Hour)
	buf.add([]Alert{{StartsAt: old}})
	if got := bufferLen(buf); got != 1 {
		t.Fatalf("setup: buffer should hold 1 alert, got %d", got)
	}

	k, hits := stubKube(t)
	hist, err := NewHistory(filepath.Join(t.TempDir(), "h.json"), time.Hour)
	if err != nil {
		t.Fatalf("NewHistory: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runFlushLoop(ctx, cfg, buf, k, hist, &recent{}, nil)
		close(done)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if bufferLen(buf) == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := bufferLen(buf); got != 0 {
		t.Fatalf("expected buffer drained after flush tick, got %d", got)
	}
	// Snapshot hits after the buffer is drained. The interval is
	// clamped to a second, so wait long enough that a second tick
	// would have fired and assert the loop did not flush an empty
	// buffer. An over-eager loop that drains a buffer, then drains
	// again on an empty buffer, would grow the counter here.
	drainedHits := atomic.LoadInt64(hits)
	time.Sleep(2500 * time.Millisecond)
	cancel()
	<-done
	if got := atomic.LoadInt64(hits); got != drainedHits {
		t.Fatalf("loop flushed an empty buffer: hits %d -> %d (expected no growth after drain)", drainedHits, got)
	}
}

// TestDrainBufferShutdownPath exercises the SIGTERM "flush before exit"
// path: drainBuffer must call process on every buffered batch and leave
// the buffer empty on return. This is the path that lives next to
// runFlushLoop in main.go (the issue calls out main.go:262–294
// specifically) and was previously only reachable via the signal
// goroutine.
func TestDrainBufferShutdownPath(t *testing.T) {
	cfg := &Config{MaxWindow: time.Second}
	buf := &buffer{}
	old := time.Now().Add(-time.Hour)
	buf.add([]Alert{
		{Fingerprint: "fp-a", StartsAt: old},
		{Fingerprint: "fp-b", StartsAt: old},
	})

	k, hits := stubKube(t)
	hist, err := NewHistory(filepath.Join(t.TempDir(), "h.json"), time.Hour)
	if err != nil {
		t.Fatalf("NewHistory: %v", err)
	}
	before := atomic.LoadInt64(hits)
	drained := drainBuffer(context.Background(), cfg, buf, k, hist, &recent{}, nil)
	if drained != 2 {
		t.Fatalf("expected drainBuffer to drain 2 alerts, got %d", drained)
	}
	if got := bufferLen(buf); got != 0 {
		t.Fatalf("drainBuffer must leave the buffer empty; got len=%d", got)
	}
	if atomic.LoadInt64(hits) <= before {
		t.Fatalf("drainBuffer must drive process to the kube at least once; hits=%d before=%d", atomic.LoadInt64(hits), before)
	}
}

// TestDrainBufferShutdownEmpty asserts the empty-buffer branch of
// drainBuffer: a process restart that finds no buffered alerts must
// return drained=0 and not panic.
func TestDrainBufferShutdownEmpty(t *testing.T) {
	buf := &buffer{}
	k, _ := stubKube(t)
	hist, err := NewHistory(filepath.Join(t.TempDir(), "h.json"), time.Hour)
	if err != nil {
		t.Fatalf("NewHistory: %v", err)
	}
	got := drainBuffer(context.Background(), &Config{}, buf, k, hist, &recent{}, nil)
	if got != 0 {
		t.Fatalf("expected drained=0 on empty buffer, got %d", got)
	}
	if l := bufferLen(buf); l != 0 {
		t.Fatalf("buffer should still be empty, got len=%d", l)
	}
}

// TestRunCompactLoopCompactsOnTick exercises the tick-firing branch of
// runCompactLoop: a History holding both a stale and a live entry must
// compact on a tick, dropping the stale entry from the on-disk file while
// the live one survives.
//
// The assertion reads the file, not PriorSeen: with a short retain window
// PriorSeen filters out stale entries by its own cutoff, so it would report
// the stale entry as gone even if Compact never ran — the vacuous pass this
// test used to make. The file is the only thing Compact rewrites.
func TestRunCompactLoopCompactsOnTick(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "h.json")
	hist, err := NewHistory(path, time.Hour)
	if err != nil {
		t.Fatalf("NewHistory: %v", err)
	}
	// Seed one stale entry (outside the 1h retain) and one live entry
	// (inside it). Compact must drop the former and keep the latter.
	hist.Record("stale-sig", "stale-title", time.Now().Add(-2*time.Hour))
	hist.Record("live-sig", "live-title", time.Now().Add(-time.Minute))

	// Shorten the ticker so a tick fires within the test's deadline.
	oldInterval := compactInterval
	compactInterval = 10 * time.Millisecond
	t.Cleanup(func() { compactInterval = oldInterval })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runCompactLoop(ctx, hist)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading history file: %v", err)
		}
		if !bytes.Contains(data, []byte("stale-sig")) && bytes.Contains(data, []byte("live-sig")) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading history file: %v", err)
	}
	if bytes.Contains(data, []byte("stale-sig")) {
		t.Fatalf("stale entry survived a compaction tick: %s", data)
	}
	if !bytes.Contains(data, []byte("live-sig")) {
		t.Fatalf("live entry was dropped by compaction: %s", data)
	}

	// The loop must exit on cancel so the goroutine does not leak past
	// the test.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("runCompactLoop did not return within 2s of context cancel")
	}
}

// TestRunFlushLoopExitsOnContextCancelMidTick asserts that cancelling the
// loop's context while a tick is in flight causes runFlushLoop to return
// within the cancel propagation budget (100ms) without running a stale
// process. This is the acceptance test for issue #100: the flush loop must
// honour a shutdown-aware context so an in-flight tick at SIGTERM exits
// promptly instead of running for the full NarrateTimeout.
func TestRunFlushLoopExitsOnContextCancelMidTick(t *testing.T) {
	cfg := &Config{FlushDelay: 10 * time.Millisecond, MaxWindow: time.Second}
	buf := &buffer{}
	old := time.Now().Add(-time.Hour)
	buf.add([]Alert{{Fingerprint: "fp-cancel", StartsAt: old}})

	k, hits := stubKube(t)
	hist, err := NewHistory(filepath.Join(t.TempDir(), "h.json"), time.Hour)
	if err != nil {
		t.Fatalf("NewHistory: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runFlushLoop(ctx, cfg, buf, k, hist, &recent{}, nil)
		close(done)
	}()

	// Wait for the first tick to drain the buffer.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if bufferLen(buf) == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if bufferLen(buf) != 0 {
		t.Fatalf("expected buffer drained before cancel, got %d", bufferLen(buf))
	}
	// Give process a moment to finish its kube call and return to the select.
	time.Sleep(50 * time.Millisecond)
	before := atomic.LoadInt64(hits)

	// Cancel the context while the loop is in its select (between ticks).
	cancel()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("runFlushLoop did not return within 100ms of context cancel")
	}

	// No stale process should have run after cancel.
	if got := atomic.LoadInt64(hits); got != before {
		t.Fatalf("stale process ran after cancel: hits %d -> %d", before, got)
	}
}

// TestRunCompactLoopExitsOnContextCancel exercises the SIGTERM shutdown
// path of runCompactLoop: cancelling the context must cause the loop to
// return within the next tick window rather than keep its 6-hour timer
// running. This guards the issue #95 fix that added a <-ctx.Done() arm
// to the select, so a leaked goroutine on shutdown is caught in CI.
func TestRunCompactLoopExitsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	hist, err := NewHistory(filepath.Join(dir, "h.json"), 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewHistory: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runCompactLoop(ctx, hist)
		close(done)
	}()
	// Give the loop a moment to enter its select on the first tick.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("runCompactLoop did not return within 2s of context cancel")
	}
}
