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
// N alerts sharing the same pod in the same namespace must result in only
// two backend hits (one namespace-only + one pod-specific), not N+1.
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
			{Labels: map[string]string{"pod": "p1", "alertname": "x"}},
			{Labels: map[string]string{"pod": "p1", "alertname": "y"}},
			{Labels: map[string]string{"pod": "p1", "alertname": "z"}},
		},
	}
	if _, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute); err != nil {
		t.Fatalf("fetchBackendLogsResult: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected exactly 2 queries (namespace + pod) after dedup, got %d", got)
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
	lines, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute)
	if err != nil {
		t.Fatalf("fetchBackendLogsResult: %v", err)
	}
	if lines != nil {
		t.Fatalf("expected nil lines for empty namespace, got %v", lines)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("expected zero backend hits for empty-namespace short-circuit, got %d", got)
	}
}

// TestFetchBackendLogsNilReceiver ensures the nil-receiver guard works.
func TestFetchBackendLogsNilReceiver(t *testing.T) {
	var b *logsBackend
	lines, err := b.fetchBackendLogsResult(context.Background(), Group{}, time.Minute)
	if err != nil {
		t.Fatalf("nil receiver should be a no-op, got err=%v", err)
	}
	if lines != nil {
		t.Fatalf("nil receiver should return nil lines, got %v", lines)
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
