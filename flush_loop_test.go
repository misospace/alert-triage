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

// waitForDigest fatals unless the recent store holds at least n digests
// within the timeout.
//
// The flush loop empties the buffer when take() pops the batch, but
// process keeps issuing kube reads after the pop — a namespace-less
// group takes the cluster-wide Flux path — so a hit-counter snapshot
// taken the moment the drain is observed counts those in-flight reads
// as extra flushes on a slow or race-instrumented host (issue #314).
// Waiting for the flush's digest record is the end-of-flush signal:
// process appends it synchronously after its last kube read, so the
// counter snapshot taken afterwards is the flush's complete cost.
// A quiet window on the counter cannot serve: it absorbs a one-shot
// duplicate flush and folds its reads into the baseline. A second
// record cannot hide that way.
func waitForDigest(t *testing.T, seen *recent, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if got := len(seen.snapshot()); got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("flush published %d digests within %v, want at least %d",
				len(seen.snapshot()), timeout, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
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
	// The zero-value recent{} discards every record, so the digest
	// count below would assert on an empty slice forever.
	seen := &recent{max: 10}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runFlushLoop(ctx, cfg, buf, k, hist, seen, nil)
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
	// Snapshot the counter only once the flush itself is over (see
	// waitForDigest), then hold for a second clamped interval: the
	// original guard survives — a loop that flushes again grows the
	// counter afterwards, and whichever tick it fires on, a completed
	// second process also shows up as a second digest record below,
	// even if its reads had already landed when the counter was
	// snapshotted.
	waitForDigest(t, seen, 1, 3*time.Second)
	drainedHits := atomic.LoadInt64(hits)
	if drainedHits == 0 {
		t.Fatalf("flush drove no kube reads; the counter guard would pass vacuously")
	}
	time.Sleep(2500 * time.Millisecond)
	cancel()
	<-done
	if got := atomic.LoadInt64(hits); got != drainedHits {
		t.Fatalf("loop flushed an empty buffer: hits %d -> %d (expected no growth after drain)", drainedHits, got)
	}
	if got := len(seen.snapshot()); got != 1 {
		t.Fatalf("loop flushed the buffer more than once: %d digests published, want 1", got)
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
// loop's context while a tick's process is still inside its kube reads
// causes runFlushLoop to return within the cancel propagation budget
// (100ms). This is the acceptance test for issue #100: the flush loop must
// honour a shutdown-aware context so an in-flight tick at SIGTERM exits
// promptly instead of running for the full NarrateTimeout. The stub kube
// holds its first read open until cleanup releases it, so the cancel is
// verifiably mid-tick instead of racing the flush (issue #315); the read
// itself ends because the client honours the context, and a process that
// ignored the context would hold the loop open and fail here.
func TestRunFlushLoopExitsOnContextCancelMidTick(t *testing.T) {
	cfg := &Config{FlushDelay: 10 * time.Millisecond, MaxWindow: time.Second}
	buf := &buffer{}
	old := time.Now().Add(-time.Hour)
	buf.add([]Alert{{Fingerprint: "fp-cancel", StartsAt: old}})

	// The first read signals arrival and then blocks, so process cannot
	// leave its kube call until the client's cancel tears the read down.
	// release is unblocked only by cleanup, which runs LIFO: before
	// srv.Close waits on outstanding handlers.
	readStarted := make(chan struct{})
	release := make(chan struct{})
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt64(&hits, 1) == 1 {
			close(readStarted)
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	k := &kube{hc: srv.Client(), base: srv.URL}

	hist, err := NewHistory(filepath.Join(t.TempDir(), "h.json"), time.Hour)
	if err != nil {
		t.Fatalf("NewHistory: %v", err)
	}
	seen := &recent{max: 10}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runFlushLoop(ctx, cfg, buf, k, hist, seen, nil)
		close(done)
	}()

	select {
	case <-readStarted:
	case <-time.After(2 * time.Second):
		t.Fatalf("no kube read reached the stub server; the tick never started a process")
	}

	// process is blocked inside its first kube read: cancel mid-tick.
	cancel()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("runFlushLoop did not return within 100ms of cancel while process was in flight")
	}

	// Reads attempted after the cancel must fail client-side without
	// reaching the server, and no second process may have run. The
	// canceled flush itself may still publish its digest while winding
	// down, so the record bound is one, not zero.
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Fatalf("reads reached the kube after cancel: hits 1 -> %d", got)
	}
	if got := len(seen.snapshot()); got > 1 {
		t.Fatalf("stale process ran after cancel: %d digests published, want at most 1", got)
	}
}

// TestRunFlushLoopExitsOnContextCancelIdle covers the other arm the
// mid-tick test used to hit only by accident: a cancel that arrives
// between ticks, with the loop parked in its select and an empty buffer,
// must return within the same 100ms budget. Shutdown lands on whichever
// arm it finds, so both need a deterministic guard (issue #315).
func TestRunFlushLoopExitsOnContextCancelIdle(t *testing.T) {
	cfg := &Config{FlushDelay: 10 * time.Millisecond, MaxWindow: time.Second}
	buf := &buffer{}
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
	// Let the loop goroutine start. The interval is clamped to a
	// second, so no tick has fired yet and the loop sits in its select.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("runFlushLoop did not return within 100ms of context cancel while idle")
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
