package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFetchPodLogs_empty(t *testing.T) {
	k := &kube{}
	got, _ := k.fetchPodLogs(context.Background(), nil, DefaultPodLogConcurrency)
	if got != nil {
		t.Errorf("expected nil for empty pods, got %v", got)
	}
	got, _ = k.fetchPodLogs(context.Background(), []podLogSpec{}, DefaultPodLogConcurrency)
	if got != nil {
		t.Errorf("expected nil for empty slice, got %v", got)
	}
}

// TestNormalizePodLogConcurrency pins the three branches of the normaliser:
// unset or non-positive falls back to the default, a positive value passes
// through unchanged, and anything over the 8-pod cap is clamped. The cap is
// the file-level invariant that a misconfiguration can never open more
// concurrent log reads than a group can name (issue #146), so it must hold
// at the function boundary and not just inside Enrich's path.
func TestNormalizePodLogConcurrency(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want int
	}{
		{"negative falls back to default", -3, DefaultPodLogConcurrency},
		{"zero falls back to default", 0, DefaultPodLogConcurrency},
		{"positive one passes through", 1, 1},
		{"positive default passes through", DefaultPodLogConcurrency, DefaultPodLogConcurrency},
		{"positive seven passes through", 7, 7},
		{"eight is the upper bound, passes through", 8, 8},
		{"nine clamps to eight", 9, 8},
		{"large value clamps to eight", 1000, 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizePodLogConcurrency(tt.in); got != tt.want {
				t.Errorf("normalizePodLogConcurrency(%d) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestFetchPodLogs_badKey(t *testing.T) {
	// podLogSpec has no string key to be malformed: only the namespace/name
	// pair can fail. A nil Name still produces a key, so test the empty-spec
	// path here too.
	k := &kube{}
	got, _ := k.fetchPodLogs(context.Background(), []podLogSpec{{Namespace: "ns"}}, DefaultPodLogConcurrency)
	if len(got) != 0 {
		t.Errorf("expected empty map for empty Name, got %v", got)
	}
}

func TestFetchPodLogs_noServer(t *testing.T) {
	k := &kube{base: "http://127.0.0.1:1"}
	got, _ := k.fetchPodLogs(context.Background(), []podLogSpec{{Namespace: "ns", Name: "pod"}}, DefaultPodLogConcurrency)
	if len(got) != 0 {
		t.Errorf("expected empty map when server unreachable, got %v", got)
	}
}

func TestFetchPodLogs_success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/log") {
			http.Error(w, "not found", 404)
			return
		}
		q := r.URL.Query()
		if q.Get("previous") != "true" {
			http.Error(w, "expected previous=true", 400)
			return
		}
		w.Write([]byte("line1\nline2\nline3\n"))
	}))
	defer srv.Close()

	k := &kube{base: srv.URL + "/", token: "tok", hc: http.DefaultClient}
	got, prov := k.fetchPodLogs(context.Background(), []podLogSpec{{Namespace: "ns", Name: "pod", Previous: true}}, DefaultPodLogConcurrency)
	if len(got) != 1 {
		t.Fatalf("expected 1 log, got %d", len(got))
	}
	if !strings.Contains(got["ns/pod"], "line1") {
		t.Errorf("log missing expected content: %q", got["ns/pod"])
	}
	if p := prov["ns/pod"]; p.Stream != "previous" {
		t.Errorf("provenance stream = %q, want previous", p.Stream)
	}
}

func TestFetchPodLogs_stripsSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("api_key=supersecret\nok line\n"))
	}))
	defer srv.Close()

	k := &kube{base: srv.URL + "/", token: "tok", hc: http.DefaultClient}
	got, _ := k.fetchPodLogs(context.Background(), []podLogSpec{{Namespace: "ns", Name: "pod"}}, DefaultPodLogConcurrency)
	if len(got) != 1 {
		t.Fatalf("expected 1 log, got %d", len(got))
	}
	if strings.Contains(got["ns/pod"], "supersecret") {
		t.Errorf("secret not stripped: %q", got["ns/pod"])
	}
}

func TestFetchPodLogs_capped(t *testing.T) {
	big := strings.Repeat("x\n", 100)
	var gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.RawQuery
		w.Write([]byte(big))
	}))
	defer srv.Close()

	k := &kube{base: srv.URL + "/", token: "tok", hc: http.DefaultClient}
	got, _ := k.fetchPodLogs(context.Background(), []podLogSpec{{Namespace: "ns", Name: "pod"}}, DefaultPodLogConcurrency)
	if len(got) != 1 {
		t.Fatalf("expected 1 log, got %d", len(got))
	}
	if !strings.Contains(gotURL, "tailLines=20") {
		t.Errorf("expected tailLines=20 in request, got: %s", gotURL)
	}
}

// Regression for #146: fetchPodLogs used to walk the capped pods strictly in
// series, so one stalled read on pod 1 held the whole flush behind 8 × the
// per-pod timeout. With the bounded per-pod semaphore the remaining reads
// overlap the stall, so the function returns in ≈ 1 round-trip + the per-pod
// timeout floor — well under 8 ×. The timing gap is what the regression
// asserts (bounded ≈ 3 batches vs serial 3 + 7); the in-flight count asserts
// the bound is in force as an upper limit.
//
// The threshold is a generous ceiling on the bounded path so a slow CI host
// under load does not flake the test. The shape — never 8 × the per-pod
// timeout — is what the regression is meant to lock in.
func TestFetchPodLogsStalledPodDoesNotSerialise(t *testing.T) {
	const (
		cost = 200 * time.Millisecond // each healthy per-pod read's cost
		// Bounded dispatch: the stall (cost * 3 = the http.Client
		// timeout) overlaps with the other reads, so the total is ≈
		// one timeout + three batches of cost ≈ 4 × cost in practice.
		// Serial dispatch: the stall (one per-pod timeout) plus every
		// read behind it ≈ (3 + 7) × cost. The threshold sits at
		// 8 × cost, comfortably above the bounded shape and well
		// below the serial one.
		threshold = 8 * cost
	)

	var inFlight, maxInFlight atomic.Int32
	stall := make(chan struct{})

	// Track the peak number of concurrently in-flight log reads, including
	// the stalled one.
	updateMax := func() {
		n := inFlight.Add(1)
		for {
			m := maxInFlight.Load()
			if n <= m || maxInFlight.CompareAndSwap(m, n) {
				break
			}
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/log") {
			http.NotFound(w, r)
			return
		}
		defer inFlight.Add(-1)
		updateMax()
		if strings.Contains(r.URL.Path, "/pods/p1/log") {
			// The stalled read: blocks until the test closes the channel
			// on the way out.
			<-stall
			return
		}
		// A healthy read costs one round-trip, so the serial walk pays it
		// per pod.
		time.Sleep(cost)
		w.Write([]byte("ok\n"))
	}))
	defer srv.Close()

	k := &kube{base: srv.URL, token: "tok", hc: &http.Client{Timeout: cost * 3}}
	pods := []podLogSpec{
		{Namespace: "ns", Name: "p1"},
		{Namespace: "ns", Name: "p2"},
		{Namespace: "ns", Name: "p3"},
		{Namespace: "ns", Name: "p4"},
		{Namespace: "ns", Name: "p5"},
		{Namespace: "ns", Name: "p6"},
		{Namespace: "ns", Name: "p7"},
		{Namespace: "ns", Name: "p8"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer close(stall) // wake the stalled handler before the server tears down

	start := time.Now()
	done := make(chan map[string]string, 1)
	go func() {
		got, _ := k.fetchPodLogs(ctx, pods, DefaultPodLogConcurrency)
		done <- got
	}()

	select {
	case got := <-done:
		elapsed := time.Since(start)
		if elapsed > threshold {
			t.Fatalf("fetchPodLogs took %v, past the bounded threshold %v; the stalled pod serialised the remaining reads",
				elapsed, threshold)
		}
		// The stalled pod is absent; every other pod is present.
		if len(got) != 7 {
			t.Fatalf("expected logs for 7 healthy pods, got %d: %v", len(got), got)
		}
		if _, ok := got["ns/p1"]; ok {
			t.Errorf("stalled pod p1 must not appear in the results")
		}
	case <-time.After(threshold + 3*cost):
		t.Fatal("fetchPodLogs did not return within the bounded threshold; the stalled pod serialised the remaining reads")
	}

	// The bound must be in force: never more than 4 reads in flight at once.
	if max := maxInFlight.Load(); max > DefaultPodLogConcurrency {
		t.Errorf("more than %d reads in flight (observed %d); the per-pod bound is not in force",
			DefaultPodLogConcurrency, max)
	}
}

// TestFetchPodLogsContextCancelled verifies that fetchPodLogs also honours
// context cancellation.
func TestFetchPodLogsContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	k := &kube{
		base: srv.URL,
		hc:   &http.Client{Timeout: 15 * time.Second},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan map[string]string, 1)
	go func() {
		got, _ := k.fetchPodLogs(ctx, []podLogSpec{{Namespace: "ns", Name: "pod"}}, DefaultPodLogConcurrency)
		done <- got
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case got := <-done:
		if len(got) != 0 {
			t.Errorf("expected empty map after cancellation, got %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fetchPodLogs did not return promptly after context cancellation")
	}
}

// Regression for #146: fetchPodLogs used to derive its per-pod concurrency
// from a field on the shared *kube that Enrich rewrote on every call
// (k.logConcurrency = normalizePodLogConcurrency(cfg.PodLogConcurrency)).
// Under the SIGTERM shutdown path runFlushLoop's canceled process and
// drainBuffer's new process both reach Enrich on the same *kube; the
// goroutines spawned by an in-flight fetchPodLogs read k.logConcurrency
// while the other caller's goroutine writes it, racing. Concurrency is
// now passed in by value so *kube carries no writeable per-call state:
// driving fetchPodLogs from many goroutines on a single *kube must
// never produce a -race report, regardless of what concurrency value
// each caller passes.
func TestFetchPodLogsConcurrentCallersDoNotRace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/log") {
			http.NotFound(w, r)
			return
		}
		// Hold the read open long enough that every caller has launched
		// its goroutines and is reading the same *kube simultaneously;
		// any write to kube state from a caller would race with the
		// reads other callers' goroutines are doing here.
		time.Sleep(50 * time.Millisecond)
		w.Write([]byte("ok\n"))
	}))
	defer srv.Close()

	k := &kube{base: srv.URL, token: "tok", hc: http.DefaultClient}

	// Many concurrent callers, each with a different per-call
	// concurrency. The buggy code stored the value on *kube, so all
	// callers would race on the same field; the fix passes it on the
	// stack so there is nothing on *kube to race on.
	const callers = 8
	pods := []podLogSpec{
		{Namespace: "ns", Name: "p1"},
		{Namespace: "ns", Name: "p2"},
		{Namespace: "ns", Name: "p3"},
		{Namespace: "ns", Name: "p4"},
		{Namespace: "ns", Name: "p5"},
		{Namespace: "ns", Name: "p6"},
		{Namespace: "ns", Name: "p7"},
		{Namespace: "ns", Name: "p8"},
	}
	done := make(chan struct{}, callers)
	for i := 0; i < callers; i++ {
		concurrency := i%DefaultPodLogConcurrency + 1
		go func(c int) {
			defer func() { done <- struct{}{} }()
			got, _ := k.fetchPodLogs(context.Background(), pods, c)
			if len(got) != len(pods) {
				t.Errorf("caller concurrency=%d: expected %d logs, got %d", c, len(pods), len(got))
			}
		}(concurrency)
	}
	deadline := time.After(5 * time.Second)
	for i := 0; i < callers; i++ {
		select {
		case <-done:
		case <-deadline:
			t.Fatalf("fetchPodLogs did not return from caller %d within deadline", i)
		}
	}
}
