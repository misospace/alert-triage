package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseVictoriaLogsSuccess(t *testing.T) {
	body := []byte("{\"_msg\":\"first line\"}\n{\"_msg\":\"second line\"}\n")
	records, err := parseVictoriaLogs(body)
	if err != nil {
		t.Fatalf("parseVictoriaLogs: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d: %#v", len(records), records)
	}
	if records[0].message != "first line" || records[1].message != "second line" {
		t.Fatalf("unexpected messages: %#v", records)
	}
	if records[0].stream != "" || records[1].stream != "" {
		t.Fatalf("victorialogs records should have no stream, got %#v", records)
	}
}

func TestParseVictoriaLogsMalformed(t *testing.T) {
	body := []byte("this is not json\nand neither is this")
	if _, err := parseVictoriaLogs(body); err == nil {
		t.Fatalf("expected error for malformed JSONL")
	}
}

func TestParseVictoriaLogsEmpty(t *testing.T) {
	records, err := parseVictoriaLogs([]byte(""))
	if err != nil {
		t.Fatalf("empty input should not error: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("empty input should produce no records, got %#v", records)
	}
}

func TestParseVictoriaLogsSkipsBlankMessages(t *testing.T) {
	body := []byte("{}\n{\"_msg\":\"   \"}\n{\"_msg\":\"real\"}\n")
	records, err := parseVictoriaLogs(body)
	if err != nil {
		t.Fatalf("parseVictoriaLogs: %v", err)
	}
	if len(records) != 1 || records[0].message != "real" {
		t.Fatalf("expected only non-blank message, got %#v", records)
	}
}

func TestParseLokiSuccess(t *testing.T) {
	body := []byte(`{"status":"success","data":{"result":[
		{"stream":{"pod":"p1","namespace":"ns"},"values":[["1","line A"],["2","line B"]]}
	]}}`)
	records, err := parseLoki(body)
	if err != nil {
		t.Fatalf("parseLoki: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d: %#v", len(records), records)
	}
	if records[0].stream != "namespace=ns pod=p1" || records[1].stream != "namespace=ns pod=p1" {
		t.Fatalf("unexpected streams: %#v", records)
	}
	if records[0].message != "line A" || records[1].message != "line B" {
		t.Fatalf("unexpected messages: %#v", records)
	}
}

func TestParseLokiStatusError(t *testing.T) {
	body := []byte(`{"status":"error","data":{"resultType":"","result":[]}}`)
	if _, err := parseLoki(body); err == nil {
		t.Fatalf("expected error for non-success status")
	}
}

func TestParseLokiMalformed(t *testing.T) {
	body := []byte(`not json at all`)
	if _, err := parseLoki(body); err == nil {
		t.Fatalf("expected error for malformed JSON")
	}
}

func TestParseLokiEmptyResult(t *testing.T) {
	body := []byte(`{"status":"success","data":{"result":[]}}`)
	records, err := parseLoki(body)
	if err != nil {
		t.Fatalf("empty result should not error: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected 0 records, got %#v", records)
	}
}

func TestParseLokiSkipsBlankMessages(t *testing.T) {
	body := []byte(`{"status":"success","data":{"result":[
		{"stream":{"pod":"p1"},"values":[["1","   "],["2","real"]]}
	]}}`)
	records, err := parseLoki(body)
	if err != nil {
		t.Fatalf("parseLoki: %v", err)
	}
	if len(records) != 1 || records[0].message != "real" {
		t.Fatalf("expected only the non-blank message, got %#v", records)
	}
}

func TestStreamLabelsSorted(t *testing.T) {
	got := streamLabels(map[string]string{"zebra": "z", "alpha": "a", "beta": "b"})
	want := []string{"alpha=a", "beta=b", "zebra=z"}
	if len(got) != len(want) {
		t.Fatalf("streamLabels = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("streamLabels[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestStreamLabelsNil(t *testing.T) {
	if got := streamLabels(nil); got != nil {
		t.Fatalf("streamLabels(nil) = %#v, want nil", got)
	}
}

func TestStreamLabelsEmpty(t *testing.T) {
	if got := streamLabels(map[string]string{}); got != nil {
		t.Fatalf("streamLabels(empty) = %#v, want nil", got)
	}
}

func TestStreamLabelsKeepsBlankValues(t *testing.T) {
	got := streamLabels(map[string]string{"k": "v", "blank": "", "blank2": "   "})
	want := []string{"blank=", "blank2=   ", "k=v"}
	if len(got) != len(want) {
		t.Fatalf("streamLabels = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("streamLabels[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCollapseAndCapDistinct(t *testing.T) {
	order := []*backendLog{
		{message: "alpha", count: 1},
		{message: "beta", count: 1},
		{message: "gamma", count: 1},
	}
	got := collapseAndCap(nil, order, 5)
	if len(got) != 3 {
		t.Fatalf("expected 3 lines, got %d: %#v", len(got), got)
	}
	if got[0] != "alpha" || got[1] != "beta" || got[2] != "gamma" {
		t.Fatalf("distinct lines should pass through unchanged: %#v", got)
	}
}

func TestCollapseAndCapRepeats(t *testing.T) {
	order := []*backendLog{
		{message: "foo", count: 3},
		{message: "bar", count: 1},
	}
	got := collapseAndCap(nil, order, 10)
	if len(got) != 2 {
		t.Fatalf("expected 2 collapsed entries, got %d: %#v", len(got), got)
	}
	if got[0] != "[x3] foo" {
		t.Fatalf("expected '[x3] foo', got %q", got[0])
	}
	if got[1] != "bar" {
		t.Fatalf("expected 'bar' second, got %q", got[1])
	}
}

func TestCollapseAndCapStreamPrefix(t *testing.T) {
	order := []*backendLog{
		{stream: "ns-a pod-p", message: "boom", count: 2},
		{stream: "ns-a pod-p", message: "restart", count: 1},
	}
	got := collapseAndCap(nil, order, 10)
	if len(got) != 2 {
		t.Fatalf("expected 2 lines, got %d: %#v", len(got), got)
	}
	if got[0] != "[x2] [ns-a pod-p] boom" {
		t.Fatalf("expected count-then-stream prefix, got %q", got[0])
	}
	if got[1] != "[ns-a pod-p] restart" {
		t.Fatalf("expected stream prefix on single, got %q", got[1])
	}
}

func TestCollapseAndCapOverflow(t *testing.T) {
	order := []*backendLog{
		{message: "a", count: 1}, {message: "b", count: 1}, {message: "c", count: 1},
		{message: "d", count: 1}, {message: "e", count: 1}, {message: "f", count: 1},
		{message: "g", count: 1},
	}
	got := collapseAndCap(nil, order, 5)
	if len(got) != 6 {
		t.Fatalf("expected 6 entries (5 + overflow), got %d: %#v", len(got), got)
	}
	if got[5] != "...and 2 more distinct lines" {
		t.Fatalf("expected overflow marker, got %q", got[5])
	}
	for i := 0; i < 5; i++ {
		if got[i] != string(rune('a'+i)) {
			t.Fatalf("line %d = %q", i, got[i])
		}
	}
}

func TestCollapseAndCapZeroFallback(t *testing.T) {
	order := []*backendLog{
		{message: "alpha", count: 1},
		{message: "beta", count: 1},
		{message: "gamma", count: 1},
	}
	got := collapseAndCap(nil, order, 0)
	if len(got) != 3 {
		t.Fatalf("cap=0 should fall back to default limit, got %d: %#v", len(got), got)
	}
}

func TestQueryVictoriaLogsOverHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/select/logsql/query") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if q := r.URL.Query().Get("query"); q == "" || !strings.Contains(q, "namespace:") {
			t.Errorf("query param missing namespace filter: %q", q)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"_msg\":\"hello\"}\n{\"_msg\":\"world\"}\n"))
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		base:   srv.URL,
		flavor: "victorialogs",
		limit:  50,
		hc:     srv.Client(),
	}
	start := time.Now().Add(-time.Minute)
	end := time.Now()
	records, err := b.query(context.Background(), "ns-a", "pod-1", start, end)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d: %#v", len(records), records)
	}
	if records[0].message != "hello" || records[1].message != "world" {
		t.Fatalf("unexpected messages: %#v", records)
	}
}

func TestQueryLokiStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/loki/api/v1/query_range") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"error","data":{"result":[]}}`))
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		base:   srv.URL,
		flavor: "loki",
		limit:  50,
		hc:     srv.Client(),
	}
	if _, err := b.query(context.Background(), "ns-a", "", time.Now().Add(-time.Minute), time.Now()); err == nil {
		t.Fatalf("expected error for non-success loki status")
	}
}

// TestFetchBackendLogsDedup verifies the per-(namespace,pod) query dedup:
// N alerts sharing the same pod in the same namespace must result in exactly
// one pod-scoped query, not N. (The unconditional namespace-only query is
// dropped when subjects are resolved.)
func TestFetchBackendLogsDedup(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"result":[]}}`)
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		base:   srv.URL,
		flavor: "loki",
		limit:  50,
		hc:     srv.Client(),
	}
	g := Group{
		Namespaces: []string{"ns-a"},
		Alerts: []Alert{
			{Labels: map[string]string{"pod": "p1", "namespace": "ns-a", "alertname": "x"}},
			{Labels: map[string]string{"pod": "p1", "namespace": "ns-a", "alertname": "y"}},
			{Labels: map[string]string{"pod": "p1", "namespace": "ns-a", "alertname": "z"}},
		},
	}
	if _, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, targetPodsFromAlerts(g.Alerts)); err != nil {
		t.Fatalf("fetchBackendLogsResult: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected exactly 1 pod-scoped query after dedup, got %d", got)
	}
}

// TestFetchBackendLogsTargetPodsIsPrimary verifies that when a concrete
// subject is known (via the enrichment's resolved target-pod set), the
// namespace-only query is not issued at all and no namespace-wide lines leak
// into the primary evidence.
func TestFetchBackendLogsTargetPodsIsPrimary(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		queries = append(queries, q)
		w.Header().Set("Content-Type", "application/json")
		if q == `namespace:"ns-a" AND pod:"p1"` {
			_, _ = io.WriteString(w, `{"status":"success","data":{"result":[{"stream":{"pod":"p1","namespace":"ns-a"},"values":[["1","target pod failure line"]]}]}}`)
			return
		}
		// Namespace-wide query: unrelated controller chatter must never appear.
		_, _ = io.WriteString(w, `{"status":"success","data":{"result":[{"stream":{"pod":"flux-controller","namespace":"ns-a"},"values":[["1","unrelated flux chatter"]]}]}}`)
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		base:   srv.URL,
		flavor: "loki",
		limit:  50,
		hc:     srv.Client(),
	}
	// The alert carries no pod label; the resolved target set does.
	g := Group{
		Namespaces: []string{"ns-a"},
		Alerts:     []Alert{{Labels: map[string]string{"alertname": "KubeJobFailed"}}},
	}
	targetPods := map[string]bool{"ns-a/p1": true}
	res, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, targetPods)
	if err != nil {
		t.Fatalf("fetchBackendLogsResult: %v", err)
	}
	if len(res.Primary) == 0 || !strings.Contains(res.Primary[0], "target pod failure line") {
		t.Fatalf("expected the target pod's line as primary evidence, got %#v", res.Primary)
	}
	for _, line := range res.Primary {
		if strings.Contains(line, "unrelated flux chatter") {
			t.Fatalf("namespace-wide line entered primary evidence: %#v", res.Primary)
		}
	}
	if len(res.Ambient) != 0 {
		t.Fatalf("no ambient context expected when a subject is resolved, got %#v", res.Ambient)
	}
	if len(queries) != 1 {
		t.Fatalf("expected exactly one (pod-scoped) query, got %d: %v", len(queries), queries)
	}
	if !strings.Contains(queries[0], "pod:") {
		t.Fatalf("the only query must be pod-scoped, got %q", queries[0])
	}
}

// TestFetchBackendLogsTargetDedup verifies multiple alerts resolving to
// different target pods issue one query per distinct (namespace,pod), and
// never a namespace-only query.
func TestFetchBackendLogsTargetDedup(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Query().Get("query"), "pod:") {
			t.Errorf("unexpected non-pod-scoped query %q", r.URL.RawQuery)
		}
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"result":[]}}`)
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		base:   srv.URL,
		flavor: "loki",
		limit:  50,
		hc:     srv.Client(),
	}
	g := Group{
		Namespaces: []string{"ns-a"},
		Alerts: []Alert{
			{Labels: map[string]string{"pod": "p1", "namespace": "ns-a", "alertname": "x"}},
			{Labels: map[string]string{"pod": "p1", "namespace": "ns-a", "alertname": "y"}},
			{Labels: map[string]string{"pod": "p2", "namespace": "ns-a", "alertname": "z"}},
		},
	}
	if _, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, targetPodsFromAlerts(g.Alerts)); err != nil {
		t.Fatalf("fetchBackendLogsResult: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected exactly 2 pod-scoped queries (one per distinct pod), got %d", got)
	}
}

// TestFetchBackendLogsNoSubjectIsAmbient verifies the fallback: with no
// concrete subject the namespace-wide lookup still runs, but its result is
// explicitly marked ambient and never placed in the primary evidence.
func TestFetchBackendLogsNoSubjectIsAmbient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if strings.Contains(q, "pod:") {
			t.Errorf("no pod-scoped query expected, got %q", q)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"result":[{"stream":{"pod":"other","namespace":"ns-a"},"values":[["1","namespace chatter"]]}]}}`)
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		base:   srv.URL,
		flavor: "loki",
		limit:  50,
		hc:     srv.Client(),
	}
	g := Group{
		Namespaces: []string{"ns-a"},
		Alerts:     []Alert{{Labels: map[string]string{"alertname": "SomeAlert"}}},
	}
	res, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, map[string]bool{})
	if err != nil {
		t.Fatalf("fetchBackendLogsResult: %v", err)
	}
	if len(res.Primary) != 0 {
		t.Fatalf("expected no primary evidence without a subject, got %#v", res.Primary)
	}
	if len(res.Ambient) != 1 || !strings.Contains(res.Ambient[0], "(ambient, namespace-wide)") {
		t.Fatalf("expected exactly one explicitly-ambient line, got %#v", res.Ambient)
	}
}

// TestTargetPodsByNamespace verifies the namespace/pod key split. The first
// "/" separates namespace from pod, so extra slashes belong to the pod name;
// keys missing either half are dropped rather than turned into bogus queries.
func TestTargetPodsByNamespace(t *testing.T) {
	got := targetPodsByNamespace(map[string]bool{
		"ns-a/p1": true,
		"ns-a/p2": true,
		"ns-b/p1": true,
		"/p":      true, // no namespace
		"ns/":     true, // no pod
		"noSlash": true, // not a key
		"ns/p/od": true, // extra slash is part of the pod name
	})
	if len(got) != 3 {
		t.Fatalf("expected 3 namespaces, got %#v", got)
	}
	if len(got["ns-a"]) != 2 || got["ns-a"][0] != "p1" || got["ns-a"][1] != "p2" {
		t.Fatalf("ns-a = %#v, want [p1 p2] sorted", got["ns-a"])
	}
	if len(got["ns-b"]) != 1 || got["ns-b"][0] != "p1" {
		t.Fatalf("ns-b = %#v", got["ns-b"])
	}
	if len(got["ns"]) != 1 || got["ns"][0] != "p/od" {
		t.Fatalf("extra slashes belong to the pod name, got %#v", got["ns"])
	}
	if _, ok := got[""]; ok {
		t.Fatalf("blank namespace key must be dropped, got %#v", got)
	}
}

// TestFetchBackendLogsEmptyNamespace verifies the short-circuit when the
// group has no namespaces — the backend should not be hit at all.
func TestFetchBackendLogsEmptyNamespace(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"result":[]}}`)
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		base:   srv.URL,
		flavor: "loki",
		limit:  50,
		hc:     srv.Client(),
	}
	g := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "x"}}}}
	lines, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, targetPodsFromAlerts(g.Alerts))
	if err != nil {
		t.Fatalf("fetchBackendLogsResult: %v", err)
	}
	if lines.Primary != nil {
		t.Fatalf("expected nil primary for empty namespace, got %v", lines.Primary)
	}
	if lines.Ambient != nil {
		t.Fatalf("expected no ambient for empty namespace, got %v", lines.Ambient)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("expected zero backend hits for empty-namespace short-circuit, got %d", got)
	}
}

// TestFetchBackendLogsNilReceiver ensures the nil-receiver guard works.
func TestFetchBackendLogsNilReceiver(t *testing.T) {
	var b *logsBackend
	res, err := b.fetchBackendLogsResult(context.Background(), Group{}, time.Minute, nil)
	if err != nil {
		t.Fatalf("nil receiver should be a no-op, got err=%v", err)
	}
	if res.Primary != nil || res.Ambient != nil {
		t.Fatalf("nil receiver should return empty results, got %#v", res)
	}
}

// TestFetchBackendLogsConvenienceWrapper verifies the wrapper logs the
// error and returns whatever lines the result variant produced.
func TestFetchBackendLogsConvenienceWrapper(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not json`))
	}))
	t.Cleanup(srv.Close)
	b := &logsBackend{
		url:    srv.URL,
		base:   srv.URL,
		flavor: "loki",
		limit:  50,
		hc:     srv.Client(),
	}
	g := Group{Namespaces: []string{"ns"}}
	lines := b.fetchBackendLogs(context.Background(), g, time.Minute)
	if lines != nil {
		t.Fatalf("expected nil lines on backend JSON error, got %v", lines)
	}
}
