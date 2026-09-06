package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	lines1 := p.EnrichMetricsWithRules(context.Background(), g1, 1*time.Hour, rules, nil)
	lines2 := p.EnrichMetricsWithRules(context.Background(), g2, 1*time.Hour, rules, nil)

	// The rules endpoint must not have been hit again.
	if rulesCalls != 1 {
		t.Errorf("expected rules fetched exactly once across groups, got %d calls", rulesCalls)
	}
	// Per-alert-name queries still run for each group.
	if queryCalls != 2 {
		t.Errorf("expected 2 query_range calls (one per group), got %d", queryCalls)
	}
	if len(lines1) == 0 || len(lines2) == 0 {
		t.Errorf("expected metric lines for both groups, got %v / %v", lines1, lines2)
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
	lines := p.EnrichMetricsWithRules(context.Background(), g, 1*time.Hour, rules, err)

	if len(lines) != 1 {
		t.Fatalf("expected 1 error line, got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "metrics backend error") {
		t.Errorf("expected 'metrics backend error' line, got %q", lines[0])
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
	}
	for _, tt := range tests {
		if got := escapeLabelValue(tt.in); got != tt.want {
			t.Errorf("escapeLabelValue(%q) = %q, want %q", tt.in, got, tt.want)
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
		Metrics: []string{
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
