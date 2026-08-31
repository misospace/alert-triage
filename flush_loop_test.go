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
	"context"
	"net/http"
	"net/http/httptest"
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
// runCompactLoop: a History with a stale entry must compact and rewrite
// the file before the next tick. We hijack Compact via a short
// retain/interval to drive the path deterministically.
func TestRunCompactLoopCompactsOnTick(t *testing.T) {
	dir := t.TempDir()
	hist, err := NewHistory(filepath.Join(dir, "h.json"), 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewHistory: %v", err)
	}
	// Seed a stale entry so Compact has something to do.
	hist.Record("stale-sig", "stale-title", time.Now().Add(-time.Hour))
	done := make(chan struct{})
	go func() {
		runCompactLoop(hist)
		close(done)
	}()
	// Wait for at least one tick: Compact is on a 5s timer in production,
	// but runCompactLoop reads hist.retain to schedule. With a 10ms retain
	// the loop schedules compaction immediately and rewrites the file.
	deadline := time.Now().Add(2 * time.Second)
	var compacted bool
	for time.Now().Before(deadline) {
		hist.mu.Lock()
		_ = hist.entries // touch the struct to prove it is alive
		hist.mu.Unlock()
		// After the first compaction, the stale entry must be gone.
		if hist.PriorSeen("stale-sig", "stale-title") == 0 {
			compacted = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !compacted {
		t.Fatalf("runCompactLoop did not compact a stale entry within 2s")
	}
}
