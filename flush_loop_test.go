package main

import (
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
	cancel()
	<-done
	if got := bufferLen(buf); got != 0 {
		t.Fatalf("expected buffer drained after flush tick, got %d", got)
	}
	if atomic.LoadInt64(hits) == 0 {
		t.Fatalf("expected process to reach the kube at least once; got zero hits")
	}
}

// TestRunFlushLoopShutdownDrain exercises the drain path on shutdown: the
// loop must return promptly when its context is cancelled, even if the
// ticker has not fired. We use a long FlushDelay so no tick fires.
func TestRunFlushLoopShutdownDrain(t *testing.T) {
	cfg := &Config{FlushDelay: 10 * time.Second, MaxWindow: time.Second}
	buf := &buffer{}
	old := time.Now().Add(-time.Hour)
	buf.add([]Alert{{StartsAt: old}})

	k, _ := stubKube(t)
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
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("runFlushLoop did not return within 2s of ctx cancel")
	}
	// The alert we pushed must still be in the buffer — we cancelled
	// before the tick, so the drain-on-exit path should not have
	// processed it.
	if got := bufferLen(buf); got != 1 {
		t.Fatalf("expected buffer to retain alert when ctx cancels before tick; got len=%d", got)
	}
}

// TestRunCompactLoopStartup verifies the loop spins up without panicking.
// runCompactLoop has no public stop signal in this version; we just
// confirm it does not crash on a fresh History and exit if it ever
// returns. We allocate it in a goroutine and ignore the leak — it is
// terminated by process exit in production.
func TestRunCompactLoopStartup(t *testing.T) {
	hist, err := NewHistory(filepath.Join(t.TempDir(), "h.json"), time.Hour)
	if err != nil {
		t.Fatalf("NewHistory: %v", err)
	}
	defer os.Remove(hist.path)
	done := make(chan struct{})
	go func() {
		runCompactLoop(hist)
		close(done)
	}()
	// Give the loop a beat to schedule.
	time.Sleep(50 * time.Millisecond)
	select {
	case <-done:
		// returned already, fine
	default:
		// still running, which is the expected steady state. Nothing to
		// assert beyond "did not panic".
	}
}
