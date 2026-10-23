package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrometheusIsConfigured(t *testing.T) {
	if (&Prometheus{}).isConfigured() {
		t.Error("nil Prometheus should not be configured")
	}
	p := &Prometheus{url: "http://localhost:9090"}
	if !p.isConfigured() {
		t.Error("Prometheus with URL should be configured")
	}
}

func TestSummarizeSeries(t *testing.T) {
	tests := []struct {
		name     string
		values   [][]interface{}
		wantNil  bool
		wantMin  float64
		wantMax  float64
		wantLast float64
		wantDir  string
	}{
		{
			name:    "empty values",
			values:  nil,
			wantNil: true,
		},
		{
			name: "single point",
			values: [][]interface{}{
				{float64(1000), "42.5"},
			},
			wantMin:  42.5,
			wantMax:  42.5,
			wantLast: 42.5,
			wantDir:  "stable",
		},
		{
			name: "rising trend",
			values: [][]interface{}{
				{float64(1000), "10"},
				{float64(1010), "20"},
				{float64(1020), "30"},
			},
			wantMin:  10,
			wantMax:  30,
			wantLast: 30,
			wantDir:  "rising",
		},
		{
			name: "falling trend",
			values: [][]interface{}{
				{float64(1000), "90"},
				{float64(1010), "50"},
				{float64(1020), "10"},
			},
			wantMin:  10,
			wantMax:  90,
			wantLast: 10,
			wantDir:  "falling",
		},
		{
			name: "stable with noise",
			values: [][]interface{}{
				{float64(1000), "50"},
				{float64(1010), "50.0001"},
				{float64(1020), "50"},
			},
			wantMin:  50,
			wantMax:  50.0001,
			wantLast: 50,
			wantDir:  "stable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := summarizeSeries(nil, tt.values)
			if tt.wantNil {
				if s != nil {
					t.Errorf("expected nil, got %+v", s)
				}
				return
			}
			if s == nil {
				t.Fatal("expected non-nil summary")
			}
			if s.min != tt.wantMin {
				t.Errorf("min = %f, want %f", s.min, tt.wantMin)
			}
			if s.max != tt.wantMax {
				t.Errorf("max = %f, want %f", s.max, tt.wantMax)
			}
			if s.last != tt.wantLast {
				t.Errorf("last = %f, want %f", s.last, tt.wantLast)
			}
			if s.direction != tt.wantDir {
				t.Errorf("direction = %q, want %q", s.direction, tt.wantDir)
			}
		})
	}
}

func TestMetricSummaryRender(t *testing.T) {
	s := &metricSummary{
		labels: map[string]string{
			"namespace": "kube-system",
			"pod":       "coredns-abc123",
		},
		min:       0.85,
		max:       0.97,
		last:      0.96,
		direction: "rising",
	}
	got := s.render()
	if got == "" {
		t.Fatal("render returned empty string")
	}
	// Check it contains expected parts.
	for _, want := range []string{"min=0.85", "max=0.97", "last=0.96", "rising", "namespace=kube-system", "pod=coredns-abc123"} {
		if !strings.Contains(got, want) {
			t.Errorf("render = %q, missing %q", got, want)
		}
	}
}

func TestMetricSummaryRenderNoLabels(t *testing.T) {
	s := &metricSummary{
		labels:    map[string]string{},
		min:       1.0,
		max:       2.0,
		last:      1.5,
		direction: "falling",
	}
	got := s.render()
	if got == "" {
		t.Fatal("render returned empty string")
	}
	if strings.Contains(got, "{") {
		t.Errorf("expected no label context, got %q", got)
	}
}

func TestPrometheusFetchRules(t *testing.T) {
	rulesResp := rulesResponse{
		Status: "success",
		Data: rulesData{
			Groups: []ruleGroup{{
				Rules: []ruleEntry{
					{Name: "HighMemory", Type: "alert", Query: "container_memory_working_set_bytes / container_memory_limit_bytes > 0.9"},
					{Name: "NodeDown", Type: "alert", Query: "up == 0"},
					{Name: "recorded_metric", Type: "recording", Query: "sum(rate(...))"},
				},
			}},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/rules" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(rulesResp)
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	rules, err := p.fetchRules(context.Background())
	if err != nil {
		t.Fatalf("fetchRules error: %v", err)
	}

	if got := rules["HighMemory"]; got != "container_memory_working_set_bytes / container_memory_limit_bytes > 0.9" {
		t.Errorf("HighMemory = %q, want expression", got)
	}
	if _, ok := rules["NodeDown"]; !ok {
		t.Error("missing NodeDown rule")
	}
	if _, ok := rules["recorded_metric"]; ok {
		t.Error("recording rule should not be included")
	}
}

func TestPrometheusQueryRange(t *testing.T) {
	resp := queryRangeResponse{
		Status: "success",
		Data: queryRangeData{
			ResultType: "matrix",
			Result: []queryResult{{
				Metric: map[string]string{"namespace": "default", "pod": "test-pod"},
				Values: [][]interface{}{
					{float64(1000), "10"},
					{float64(1010), "20"},
					{float64(1020), "30"},
				},
			}},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query_range" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("query") == "" {
			t.Error("missing query parameter")
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	summaries, err := p.queryRange(context.Background(), "up", time.Unix(1000, 0), time.Unix(1020, 0), 10*time.Second)
	if err != nil {
		t.Fatalf("queryRange error: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	s := summaries[0]
	if s.min != 10 || s.max != 30 || s.last != 30 {
		t.Errorf("unexpected stats: min=%f max=%f last=%f", s.min, s.max, s.last)
	}
	if s.labels["pod"] != "test-pod" {
		t.Errorf("pod label = %q, want test-pod", s.labels["pod"])
	}
}

func TestEnrichMetricsWithRulesSharesRulesAcrossGroups(t *testing.T) {
	rulesResp := rulesResponse{
		Status: "success",
		Data: rulesData{
			Groups: []ruleGroup{{
				Rules: []ruleEntry{
					{Name: "HighMemory", Type: "alert", Query: "container_memory_working_set_bytes > 1000"},
					{Name: "HighCPU", Type: "alert", Query: "rate(container_cpu_usage_seconds_total[5m]) > 0.9"},
				},
			}},
		},
	}

	queryResp := queryRangeResponse{
		Status: "success",
		Data: queryRangeData{
			ResultType: "matrix",
			Result: []queryResult{{
				Metric: map[string]string{"namespace": "default", "pod": "web-1"},
				Values: [][]interface{}{
					{float64(1000), "900"},
					{float64(1010), "1200"},
				},
			}},
		},
	}

	rulesCalls := 0
	queryCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/rules":
			rulesCalls++
			json.NewEncoder(w).Encode(rulesResp)
		case "/api/v1/query_range":
			queryCalls++
			json.NewEncoder(w).Encode(queryResp)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}

	// Fetch rules once, as the flush loop does.
	rules, err := p.FetchRules(context.Background())
	if err != nil {
		t.Fatalf("FetchRules: %v", err)
	}
	if rulesCalls != 1 {
		t.Fatalf("expected 1 rules call after FetchRules, got %d", rulesCalls)
	}

	// Enrich two groups sharing the same rules map.
	g1 := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "HighMemory"}}}}
	g2 := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "HighCPU"}}}}
	ev1 := p.EnrichMetricsWithRules(context.Background(), g1, 1*time.Hour, rules, nil)
	ev2 := p.EnrichMetricsWithRules(context.Background(), g2, 1*time.Hour, rules, nil)

	// The rules endpoint must not have been hit again.
	if rulesCalls != 1 {
		t.Errorf("expected rules fetched exactly once across groups, got %d calls", rulesCalls)
	}
	// Per-alert-name queries still run for each group.
	if queryCalls != 2 {
		t.Errorf("expected 2 query_range calls (one per group), got %d", queryCalls)
	}
	if len(ev1.Context) == 0 || len(ev2.Context) == 0 {
		t.Errorf("expected rule metric lines for both groups, got %v / %v", ev1, ev2)
	}
}

func TestEnrichMetricsWithRulesBackendError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	rules, err := p.FetchRules(context.Background())
	if err == nil {
		t.Fatal("expected FetchRules to fail against a 500 backend")
	}

	g := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "TestAlert"}}}}
	ev := p.EnrichMetricsWithRules(context.Background(), g, 1*time.Hour, rules, err)

	if len(ev.Context) != 1 {
		t.Fatalf("expected 1 error line, got %d: %v", len(ev.Context), ev.Context)
	}
	if !strings.Contains(ev.Context[0], "metrics backend error") {
		t.Errorf("expected 'metrics backend error' line, got %q", ev.Context[0])
	}
}

// TestMetricsRuleResultStaysContextDespitePodLabel pins the issue #136 review
// finding: a common pod label bounds only the fixed context metrics, not the
// alert-rule expression. That expression is replayed as written and may
// aggregate a namespace, workload or cluster, so its result must stay Context
// even when the group carries a pod label and the fixed metrics are Subject.
func TestMetricsRuleResultStaysContextDespitePodLabel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query_range" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			return
		}
		json.NewEncoder(w).Encode(queryRangeResponse{
			Status: "success",
			Data: queryRangeData{
				ResultType: "matrix",
				Result: []queryResult{{
					Metric: map[string]string{"namespace": "default"},
					Values: [][]interface{}{{float64(1000), "1"}},
				}},
			},
		})
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	rules := map[string]string{"HighMemory": "container_memory_working_set_bytes > 1000"}
	g := Group{Alerts: []Alert{{Labels: map[string]string{
		"alertname": "HighMemory", "namespace": "default", "pod": "web-1",
	}}}}
	ev := p.EnrichMetricsWithRules(context.Background(), g, 1*time.Hour, rules, nil)

	for _, line := range ev.Subject {
		if strings.Contains(line, "HighMemory") {
			t.Errorf("alert-rule result classified as subject-scoped: %q", line)
		}
	}
	ruleInContext := false
	for _, line := range ev.Context {
		if strings.Contains(line, "HighMemory") {
			ruleInContext = true
		}
	}
	if !ruleInContext {
		t.Errorf("alert-rule result missing from context: %v", ev.Context)
	}
	podBoundedInSubject := false
	for _, line := range ev.Subject {
		if strings.Contains(line, "container_restarts") {
			podBoundedInSubject = true
		}
	}
	if !podBoundedInSubject {
		t.Errorf("pod-bounded fixed metrics missing from subject: %v", ev.Subject)
	}
}

func TestGroupLabel(t *testing.T) {
	tests := []struct {
		name string
		g    Group
		key  string
		want string
	}{
		{
			name: "common namespace",
			g: Group{Alerts: []Alert{
				{Labels: map[string]string{"namespace": "default"}},
				{Labels: map[string]string{"namespace": "default"}},
			}},
			key:  "namespace",
			want: "default",
		},
		{
			name: "conflicting namespace",
			g: Group{Alerts: []Alert{
				{Labels: map[string]string{"namespace": "default"}},
				{Labels: map[string]string{"namespace": "kube-system"}},
			}},
			key:  "namespace",
			want: "",
		},
		{
			name: "missing label",
			g: Group{Alerts: []Alert{
				{Labels: map[string]string{"alertname": "Test"}},
			}},
			key:  "pod",
			want: "",
		},
		{
			name: "empty group",
			g:    Group{},
			key:  "namespace",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.g.Label(tt.key); got != tt.want {
				t.Errorf("Label(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestEscapeLabelValue(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"simple", "simple"},
		{`has"quote`, `has\"quote`},
		{`multi"ple"quotes`, `multi\"ple\"quotes`},
		{`foo\bar`, `foo\\bar`},
		{`foo\\bar`, `foo\\\\bar`},
		{"a\nb", `a\nb`},
		{"a\rb", `a\rb`},
		{"a\r\nb", `a\r\nb`},
		// Issue #203: all four hazardous bytes in one value. The input is
		// a, ", \, newline, CR, z; the want is the literal text
		// a\"\\\n\rz with backslash-n and backslash-r as two characters each.
		{"a\"\\\n\rz", `a\"\\\n\rz`},
	}
	for _, tt := range tests {
		if got := escapeLabelValue(tt.in); got != tt.want {
			t.Errorf("escapeLabelValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestContextMetricQueriesEscapesLabelValues guards the issue #161 regression:
// a namespace (or pod) containing a backslash must not produce a PromQL string
// literal the backend cannot parse. The expression is asserted verbatim;
// the label values carry both a backslash and a double quote so any missing
// escaping pass shows up in the filter.
func TestContextMetricQueriesEscapesLabelValues(t *testing.T) {
	queries := contextMetricQueries(`ns\with\backslash`, `pod\with\back`)
	if len(queries) != 3 {
		t.Fatalf("expected 3 context metric queries, got %d", len(queries))
	}
	wantFilter := `namespace="ns\\with\\backslash",pod="pod\\with\\back"`
	for _, q := range queries {
		if !strings.Contains(q.expr, wantFilter) {
			t.Errorf("%s: expr = %q, want filter %q", q.name, q.expr, wantFilter)
		}
	}

	// A value with both a backslash and a quote must be fully escaped in the
	// right order: `a\`b` -> `a\\\"b` -> `a\\\\\"b`.
	queries = contextMetricQueries(`a\"b`, "")
	if len(queries) != 3 {
		t.Fatalf("expected 3 context metric queries, got %d", len(queries))
	}
	wantQuoted := `namespace="a\\\"b"`
	for _, q := range queries {
		if !strings.Contains(q.expr, wantQuoted) {
			t.Errorf("%s: expr = %q, want %q", q.name, q.expr, wantQuoted)
		}
	}

	// A plain value must pass through untouched.
	queries = contextMetricQueries("plain", "pod-plain")
	wantPlain := `namespace="plain",pod="pod-plain"`
	for _, q := range queries {
		if !strings.Contains(q.expr, wantPlain) {
			t.Errorf("%s: expr = %q, want %q", q.name, q.expr, wantPlain)
		}
	}
}

func TestQueryRangeNoData(t *testing.T) {
	resp := queryRangeResponse{
		Status: "success",
		Data: queryRangeData{
			ResultType: "matrix",
			Result:     []queryResult{},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	summaries, err := p.queryRange(context.Background(), "up", time.Unix(1000, 0), time.Unix(1020, 0), 10*time.Second)
	if err != nil {
		t.Fatalf("queryRange error: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected 0 summaries for empty result, got %d", len(summaries))
	}
}

func TestQueryRangeHandlesNaNInf(t *testing.T) {
	resp := queryRangeResponse{
		Status: "success",
		Data: queryRangeData{
			ResultType: "matrix",
			Result: []queryResult{{
				Metric: map[string]string{},
				Values: [][]interface{}{
					{float64(1000), "NaN"},
					{float64(1010), "+Inf"},
					{float64(1020), "-Inf"},
					{float64(1030), "42"},
				},
			}},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	summaries, err := p.queryRange(context.Background(), "test", time.Unix(1000, 0), time.Unix(1030, 0), 10*time.Second)
	if err != nil {
		t.Fatalf("queryRange error: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	// Only the valid numeric value (42) should be included.
	s := summaries[0]
	if s.min != 42 || s.max != 42 || s.last != 42 {
		t.Errorf("expected only valid values, got min=%f max=%f last=%f", s.min, s.max, s.last)
	}
}

func TestRenderEvidenceWithMetrics(t *testing.T) {
	r := Report{
		Group: Group{
			Key:        "test-group",
			Reason:     "OOMKilled",
			Node:       "node-1",
			Alerts:     []Alert{{Labels: map[string]string{"alertname": "HighMemory"}}},
			Namespaces: []string{"default"},
		},
		ContextMetrics: []string{
			"HighMemory min=0.85 max=0.97 last=0.96 rising {namespace=default,pod=web-1}",
		},
	}

	evidence := renderEvidence(r)
	if !strings.Contains(evidence, "METRICS") {
		t.Error("expected METRICS section in evidence")
	}
	if !strings.Contains(evidence, "HighMemory") {
		t.Error("expected alert name in metrics evidence")
	}
	if !strings.Contains(evidence, "rising") {
		t.Error("expected direction in metrics evidence")
	}
}

func TestRenderEvidenceWithoutMetrics(t *testing.T) {
	r := Report{
		Group: Group{
			Key:        "test-group",
			Reason:     "OOMKilled",
			Node:       "node-1",
			Alerts:     []Alert{{Labels: map[string]string{"alertname": "HighMemory"}}},
			Namespaces: []string{"default"},
		},
	}

	evidence := renderEvidence(r)
	if strings.Contains(evidence, "METRICS") {
		t.Error("should not have METRICS section when no metrics")
	}
}

func TestPrometheusGetHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	_, err := p.get(context.Background(), "/api/v1/rules")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	expectedMsg := "HTTP 404"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("error = %q, want substring %q", err.Error(), expectedMsg)
	}
}

func TestPrometheusParseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	_, err := p.fetchRules(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestQueryRangeParseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	_, err := p.queryRange(context.Background(), "up", time.Unix(1000, 0), time.Unix(1020, 0), 10*time.Second)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestQueryRangeNonSuccessStatus(t *testing.T) {
	resp := queryRangeResponse{Status: "error"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	_, err := p.queryRange(context.Background(), "up", time.Unix(1000, 0), time.Unix(1020, 0), 10*time.Second)
	if err == nil {
		t.Fatal("expected error for non-success status")
	}
}

func TestRulesNonSuccessStatus(t *testing.T) {
	resp := rulesResponse{Status: "error"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	_, err := p.fetchRules(context.Background())
	if err == nil {
		t.Fatal("expected error for non-success status")
	}
}

// TestPrometheusGetCapsOverSizeResponse guards against the unbounded-body
// regression tracked in #65: the flush-loop goroutine must not buffer a
// Prometheus response larger than the configured cap.
func TestPrometheusGetCapsOverSizeResponse(t *testing.T) {
	// Server streams a body larger than metricsBodyCap. get must fail rather
	// than buffering the whole thing, matching the logs backend's behaviour.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "")
		w.WriteHeader(http.StatusOK)
		chunk := bytes.Repeat([]byte("a"), 64<<10)
		for i := 0; i < 256; i++ { // 16 MiB total, well over the 4 MiB cap
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	body, err := p.get(context.Background(), "/api/v1/rules")
	if err == nil {
		t.Fatal("expected error for over-cap response, got nil")
	}
	if body != nil {
		t.Errorf("expected nil body on over-cap error, got %d bytes", len(body))
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("error = %q, want substring %q", err.Error(), "exceeded")
	}
}

func TestPrometheusGetReadsNormalResponse(t *testing.T) {
	// Sanity-check that a sub-cap body still decodes as before the cap landed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"success","data":{"groups":[]}}`)
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	body, err := p.get(context.Background(), "/api/v1/rules")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(body), `"status":"success"`) {
		t.Errorf("body = %q, want JSON success envelope", string(body))
	}
}

// TestMemoryWorkingSetMatchingByContainerIdentity guards issue #190: the
// memory ratio must match working set and limit by container (in addition to
// namespace and pod) so a multi-container pod yields one ratio per container
// rather than one cross-container ratio or an invalid one-to-one match.
func TestMemoryWorkingSetMatchingByContainerIdentity(t *testing.T) {
	queries := contextMetricQueries("ns", "pod")
	var mem struct {
		name string
		expr string
	}
	for _, q := range queries {
		if q.name == "memory_working_set" {
			mem = q
			break
		}
	}
	if mem.name == "" {
		t.Fatal("memory_working_set query missing from contextMetricQueries")
	}

	if strings.Contains(mem.expr, "ignoring(") {
		t.Errorf("memory_working_set expr must not use ignoring(...); got %q", mem.expr)
	}
	if !strings.Contains(mem.expr, "on(namespace, pod, container)") {
		t.Errorf("memory_working_set expr must match on(namespace, pod, container); got %q", mem.expr)
	}
	wantHead := "container_memory_working_set_bytes{"
	if !strings.HasPrefix(mem.expr, wantHead) {
		t.Errorf("memory_working_set expr must start with %q; got %q", wantHead, mem.expr)
	}
	if !strings.Contains(mem.expr, "/ on(namespace, pod, container) container_memory_limit_bytes{") {
		t.Errorf("memory_working_set expr must divide working set by limit on(namespace, pod, container); got %q", mem.expr)
	}
}

// TestMemoryWorkingSetPrometheusFixture runs the issue #190 acceptance fixture
// against the actual memory_working_set expressions via `promtool test rules`.
// The tool is gated on $PROMTOOL so this test is skipped in environments
// without it; the structural assertion in
// TestMemoryWorkingSetMatchingByContainerIdentity still runs everywhere.
// The fixture mirrors the issue: working sets api=64, sidecar=16 paired with
// their own limits 128 and 64, and requires api=0.5 and sidecar=0.25. The
// second recording rule exercises the namespace-only selector that the app
// produces when no pod label is present on the alert.
func TestMemoryWorkingSetPrometheusFixture(t *testing.T) {
	promtoolPath := os.Getenv("PROMTOOL")
	if promtoolPath == "" {
		t.Skip("PROMTOOL env var not set; skipping external Prometheus fixture")
	}
	if _, err := os.Stat(promtoolPath); err != nil {
		t.Skipf("PROMTOOL=%s not found: %v", promtoolPath, err)
	}

	podScopedExpr := ""
	nsOnlyExpr := ""
	for _, q := range contextMetricQueries("sample", "web") {
		if q.name == "memory_working_set" {
			podScopedExpr = q.expr
		}
	}
	for _, q := range contextMetricQueries("sample", "") {
		if q.name == "memory_working_set" {
			nsOnlyExpr = q.expr
		}
	}
	if podScopedExpr == "" || nsOnlyExpr == "" {
		t.Fatal("memory_working_set expression missing for one or both selector forms")
	}

	dir := t.TempDir()
	rulesYAML := fmt.Sprintf(`groups:
  - name: fixture
    rules:
      - record: memory_ratio_podscoped
        expr: %q
      - record: memory_ratio_ns_only
        expr: %q
`, podScopedExpr, nsOnlyExpr)
	if err := os.WriteFile(filepath.Join(dir, "rules.yml"), []byte(rulesYAML), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	testYAML := `rule_files:
  - rules.yml
evaluation_interval: 1m
tests:
  # Pod-scoped: two-container pod. api working set 64 / api limit 128 = 0.5,
  # sidecar working set 16 / sidecar limit 64 = 0.25, no cross match.
  - interval: 1m
    input_series:
      - series: 'container_memory_working_set_bytes{namespace="sample",pod="web",container="api"}'
        values: '64 64 64'
      - series: 'container_memory_working_set_bytes{namespace="sample",pod="web",container="sidecar"}'
        values: '16 16 16'
      - series: 'container_memory_limit_bytes{namespace="sample",pod="web",container="api"}'
        values: '128 128 128'
      - series: 'container_memory_limit_bytes{namespace="sample",pod="web",container="sidecar"}'
        values: '64 64 64'
    promql_expr_test:
      - expr: memory_ratio_podscoped
        eval_time: 1m
        exp_samples:
          - labels: 'memory_ratio_podscoped{container="api",namespace="sample",pod="web"}'
            value: 0.5
          - labels: 'memory_ratio_podscoped{container="sidecar",namespace="sample",pod="web"}'
            value: 0.25
  # Pod-scoped: mismatched container identities. working_set=api has no
  # matching limit because only sidecar's limit exists; the expression must
  # NOT invent a cross-container ratio.
  - interval: 1m
    input_series:
      - series: 'container_memory_working_set_bytes{namespace="sample",pod="web",container="api"}'
        values: '64 64 64'
      - series: 'container_memory_limit_bytes{namespace="sample",pod="web",container="sidecar"}'
        values: '128 128 128'
    promql_expr_test:
      - expr: memory_ratio_podscoped
        eval_time: 1m
  # Namespace-only query spanning two pods. The selector omits pod; the
  # on(...) clause still requires a pod match, so each pod produces its own
  # per-container ratio without merging across pods.
  - interval: 1m
    input_series:
      - series: 'container_memory_working_set_bytes{namespace="sample",pod="webA",container="api"}'
        values: '64 64 64'
      - series: 'container_memory_working_set_bytes{namespace="sample",pod="webB",container="api"}'
        values: '32 32 32'
      - series: 'container_memory_limit_bytes{namespace="sample",pod="webA",container="api"}'
        values: '128 128 128'
      - series: 'container_memory_limit_bytes{namespace="sample",pod="webB",container="api"}'
        values: '64 64 64'
    promql_expr_test:
      - expr: memory_ratio_ns_only
        eval_time: 1m
        exp_samples:
          - labels: 'memory_ratio_ns_only{container="api",namespace="sample",pod="webA"}'
            value: 0.5
          - labels: 'memory_ratio_ns_only{container="api",namespace="sample",pod="webB"}'
            value: 0.5
`
	if err := os.WriteFile(filepath.Join(dir, "tests.yml"), []byte(testYAML), 0o644); err != nil {
		t.Fatalf("write tests: %v", err)
	}

	cmd := exec.Command(promtoolPath, "test", "rules", "tests.yml")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("promtool test rules failed:\n%s\n--- output end ---", out)
	}
	if !strings.Contains(string(out), "SUCCESS") {
		t.Fatalf("promtool output missing SUCCESS marker:\n%s", out)
	}
}

// TestEnrichMemoryRatioSubjectScoped covers the pipeline that fixed context
// metrics expose: a two-container pod with a common pod label classifies the
// memory_working_set lines as subject evidence; the renderer carries the
// container label through to make per-container ratios distinguishable.
func TestEnrichMemoryRatioSubjectScoped(t *testing.T) {
	queries := make([]string, 0, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query_range" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			return
		}
		expr := r.URL.Query().Get("query")
		queries = append(queries, expr)
		if !strings.Contains(expr, "memory_working_set") {
			// Other fixed metrics produce empty result, which renders as
			// "no data"; the parser is irrelevant for this test.
			json.NewEncoder(w).Encode(queryRangeResponse{
				Status: "success",
				Data:   queryRangeData{ResultType: "matrix", Result: []queryResult{}},
			})
			return
		}
		json.NewEncoder(w).Encode(queryRangeResponse{
			Status: "success",
			Data: queryRangeData{
				ResultType: "matrix",
				Result: []queryResult{
					{Metric: map[string]string{
						"namespace": "sample", "pod": "web", "container": "api",
					}, Values: [][]interface{}{
						{float64(1000), "0.5"}, {float64(1010), "0.5"},
					}},
					{Metric: map[string]string{
						"namespace": "sample", "pod": "web", "container": "sidecar",
					}, Values: [][]interface{}{
						{float64(1000), "0.25"}, {float64(1010), "0.25"},
					}},
				},
			},
		})
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	g := Group{Alerts: []Alert{{Labels: map[string]string{
		"alertname": "HighMemory", "namespace": "sample", "pod": "web",
	}}}}
	ev := p.EnrichMetricsWithRules(context.Background(), g, 1*time.Hour, nil, nil)

	var mem []string
	for _, line := range ev.Subject {
		if strings.Contains(line, "memory_working_set") {
			mem = append(mem, line)
		}
	}
	if len(mem) != 2 {
		t.Fatalf("expected 2 memory_working_set subject lines (one per container), got %d: %v", len(mem), mem)
	}
	// Each rendered line must carry the container label so the model can
	// tell api from sidecar. This is the visible fallout from the ignoring()
	// bug: container stripped from the metric series was stripped from the
	// rendered evidence too.
	containers := map[string]bool{}
	for _, line := range mem {
		for _, c := range []string{"container=api", "container=sidecar"} {
			if strings.Contains(line, c) {
				containers[c] = true
			}
		}
	}
	if len(containers) != 2 {
		t.Errorf("expected each container label in the subject evidence; got lines: %v", mem)
	}

	// Verify the expression sent to the backend matches by container.
	var memQuery string
	for _, q := range queries {
		if strings.Contains(q, "memory_working_set") {
			memQuery = q
		}
	}
	if memQuery == "" {
		t.Fatal("memory_working_set query not issued")
	}
	if strings.Contains(memQuery, "ignoring(container)") {
		t.Errorf("memory_working_set query regressed to ignoring(container): %s", memQuery)
	}
	if !strings.Contains(memQuery, "on(namespace, pod, container)") {
		t.Errorf("memory_working_set query missing on(namespace, pod, container): %s", memQuery)
	}
}

// TestEnrichMemoryRatioMismatchedContainers proves the expression yields no
// ratio when containers do not pair. The pipeline surfaces Prometheus's
// empty result as a "no data" line for the metric name; the test asserts
// that surface form is preserved (no synthetic cross-container ratio is
// fabricated to fill a line) when the only working_set and only limit
// belong to different containers.
func TestEnrichMemoryRatioMismatchedContainers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		if !strings.Contains(query, "memory_working_set") {
			json.NewEncoder(w).Encode(queryRangeResponse{
				Status: "success",
				Data:   queryRangeData{ResultType: "matrix", Result: []queryResult{}},
			})
			return
		}
		if !strings.Contains(query, "on(namespace, pod, container)") {
			t.Errorf("memory_working_set query regressed to ignoring(container): %s", query)
		}
		// Prometheus returns an empty result when the on() clause pairs no
		// series; that empty result surfaces as "memory_working_set: no data".
		json.NewEncoder(w).Encode(queryRangeResponse{
			Status: "success",
			Data:   queryRangeData{ResultType: "matrix", Result: []queryResult{}},
		})
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	g := Group{Alerts: []Alert{{Labels: map[string]string{
		"alertname": "HighMemory", "namespace": "sample", "pod": "web",
	}}}}
	ev := p.EnrichMetricsWithRules(context.Background(), g, 1*time.Hour, nil, nil)

	var memLines []string
	memLines = append(memLines, ev.Subject...)
	memLines = append(memLines, ev.Context...)
	var sawNoData bool
	for _, line := range memLines {
		if !strings.Contains(line, "memory_working_set") {
			continue
		}
		// A ratio line would carry min=/max=/last= stats; no_data must
		// NOT carry them, and the line is the truthful surface for the
		// "no matching pairs" condition.
		if strings.Contains(line, "min=") {
			t.Errorf("memory_working_set must not invent a ratio when containers do not pair; got %q", line)
		}
		if strings.Contains(line, "no data") {
			sawNoData = true
		}
	}
	if !sawNoData {
		t.Errorf("expected a memory_working_set 'no data' line; got subject=%v context=%v", ev.Subject, ev.Context)
	}
}
