package main

import (
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
		name      string
		values    [][]interface{}
		wantNil   bool
		wantMin   float64
		wantMax   float64
		wantLast  float64
		wantDir   string
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
	rules, err := p.fetchRules()
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
	summaries, err := p.queryRange("up", time.Unix(1000, 0), time.Unix(1020, 0), 10*time.Second)
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

func TestPrometheusEnrichMetricsNoConfig(t *testing.T) {
	var p *Prometheus
	g := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "TestAlert"}}}}
	result := p.EnrichMetrics(g, 1*time.Hour)
	if result != nil {
		t.Errorf("expected nil for unconfigured Prometheus, got %v", result)
	}
}

func TestPrometheusEnrichMetricsWithBackend(t *testing.T) {
	rulesResp := rulesResponse{
		Status: "success",
		Data: rulesData{
			Groups: []ruleGroup{{
				Rules: []ruleEntry{
					{Name: "HighMemory", Type: "alert", Query: "container_memory_working_set_bytes > 1000"},
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
					{float64(1020), "1500"},
				},
			}},
		},
	}

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch r.URL.Path {
		case "/api/v1/rules":
			json.NewEncoder(w).Encode(rulesResp)
		case "/api/v1/query_range":
			json.NewEncoder(w).Encode(queryResp)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	g := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "HighMemory"}}}}
	lines := p.EnrichMetrics(g, 1*time.Hour)

	if len(lines) == 0 {
		t.Fatal("expected at least one metric line")
	}
	for _, line := range lines {
		t.Logf("metric line: %s", line)
	}

	// Should have queried rules and then query_range.
	if callCount < 2 {
		t.Errorf("expected at least 2 API calls, got %d", callCount)
	}
}

func TestPrometheusEnrichMetricsNoRuleMatch(t *testing.T) {
	rulesResp := rulesResponse{
		Status: "success",
		Data:   rulesData{Groups: []ruleGroup{}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(rulesResp)
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	g := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "UnknownAlert"}}}}
	lines := p.EnrichMetrics(g, 1*time.Hour)

	if len(lines) != 1 {
		t.Fatalf("expected 1 line for missing rule, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "no rule expression found") {
		t.Errorf("expected 'no rule expression found', got %q", lines[0])
	}
}

func TestPrometheusEnrichMetricsBackendError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	g := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "TestAlert"}}}}
	lines := p.EnrichMetrics(g, 1*time.Hour)

	if len(lines) == 0 {
		t.Fatal("expected error line for backend failure")
	}
	if !strings.Contains(lines[0], "error") && !strings.Contains(lines[0], "Error") {
		t.Errorf("expected error message, got %q", lines[0])
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
	summaries, err := p.queryRange("up", time.Unix(1000, 0), time.Unix(1020, 0), 10*time.Second)
	if err != nil {
		t.Fatalf("queryRange error: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected 0 summaries for empty result, got %d", len(summaries))
	}
}

func TestEnrichMetricsWithNamespaceContext(t *testing.T) {
	rulesResp := rulesResponse{
		Status: "success",
		Data: rulesData{Groups: []ruleGroup{}},
	}

	queryResp := queryRangeResponse{
		Status: "success",
		Data: queryRangeData{
			ResultType: "matrix",
			Result: []queryResult{{
				Metric: map[string]string{"namespace": "default"},
				Values: [][]interface{}{
					{float64(1000), "5"},
					{float64(1010), "7"},
				},
			}},
		},
	}

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch r.URL.Path {
		case "/api/v1/rules":
			json.NewEncoder(w).Encode(rulesResp)
		case "/api/v1/query_range":
			json.NewEncoder(w).Encode(queryResp)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	g := Group{Alerts: []Alert{
		{Labels: map[string]string{"alertname": "HighMemory", "namespace": "default", "pod": "web-1"}},
	}}
	lines := p.EnrichMetrics(g, 1*time.Hour)

	// Should have queried rules + context metrics (3 queries).
	if callCount < 4 {
		t.Errorf("expected at least 4 API calls (rules + 3 context), got %d", callCount)
	}

	// Check that context metric names appear.
	found := make(map[string]bool)
	for _, line := range lines {
		for _, name := range []string{"container_restarts", "memory_working_set", "cpu_throttle_ratio"} {
			if strings.Contains(line, name) {
				found[name] = true
			}
		}
	}
	for name := range found {
		t.Logf("found context metric: %s", name)
	}
}

func TestEnrichMetricsDistinguishesNoConfigFromNoData(t *testing.T) {
	// Unconfigured returns nil.
	var p *Prometheus
	g := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "Test"}}}}
	if got := p.EnrichMetrics(g, 1*time.Hour); got != nil {
		t.Errorf("unconfigured Prometheus should return nil, got %v", got)
	}

	// Configured but no data returns non-nil with "no data" message.
	rulesResp := rulesResponse{
		Status: "success",
		Data:   rulesData{Groups: []ruleGroup{}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(rulesResp)
	}))
	defer srv.Close()

	p = &Prometheus{url: srv.URL, hc: http.DefaultClient}
	lines := p.EnrichMetrics(g, 1*time.Hour)
	if lines == nil {
		t.Fatal("configured Prometheus with no data should return non-nil")
	}
	if !strings.Contains(lines[0], "no rule expression found") {
		t.Errorf("expected 'no rule expression found', got %q", lines[0])
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
	summaries, err := p.queryRange("test", time.Unix(1000, 0), time.Unix(1030, 0), 10*time.Second)
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

func TestEnrichMetricsMultipleAlertNames(t *testing.T) {
	rulesResp := rulesResponse{
		Status: "success",
		Data: rulesData{
			Groups: []ruleGroup{{
				Rules: []ruleEntry{
					{Name: "HighMemory", Type: "alert", Query: "mem > 90"},
					{Name: "HighCPU", Type: "alert", Query: "cpu > 80"},
				},
			}},
		},
	}

	queryResp := queryRangeResponse{
		Status: "success",
		Data: queryRangeData{
			ResultType: "matrix",
			Result: []queryResult{{
				Metric: map[string]string{},
				Values: [][]interface{}{{float64(1000), "95"}},
			}},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/rules":
			json.NewEncoder(w).Encode(rulesResp)
		case "/api/v1/query_range":
			json.NewEncoder(w).Encode(queryResp)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	g := Group{Alerts: []Alert{
		{Labels: map[string]string{"alertname": "HighMemory"}},
		{Labels: map[string]string{"alertname": "HighCPU"}},
	}}
	lines := p.EnrichMetrics(g, 1*time.Hour)

	if len(lines) < 2 {
		t.Errorf("expected at least 2 lines for 2 alert names, got %d: %v", len(lines), lines)
	}
}

func TestEnrichMetricsStepCalculation(t *testing.T) {
	rulesResp := rulesResponse{
		Status: "success",
		Data: rulesData{
			Groups: []ruleGroup{{
				Rules: []ruleEntry{
					{Name: "TestAlert", Type: "alert", Query: "up"},
				},
			}},
		},
	}

	var capturedStep string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/rules":
			json.NewEncoder(w).Encode(rulesResp)
		case "/api/v1/query_range":
			capturedStep = r.URL.Query().Get("step")
			json.NewEncoder(w).Encode(queryRangeResponse{Status: "success"})
		}
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	g := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "TestAlert"}}}}

	// Very small window should clamp step to 15s.
	p.EnrichMetrics(g, 30*time.Second)
	if capturedStep != "15s" {
		t.Errorf("step for 30s window = %q, want 15s", capturedStep)
	}

	// Very large window should clamp step to 300s (5 min cap).
	p.EnrichMetrics(g, 24*time.Hour)
	if capturedStep != "300s" {
		t.Errorf("step for 24h window = %q, want 300s", capturedStep)
	}

	// 1h window: step = 360s, which exceeds 5min cap → clamped to 300s.
	p.EnrichMetrics(g, 1*time.Hour)
	if capturedStep != "300s" {
		t.Errorf("step for 1h window = %q, want 300s", capturedStep)
	}

	// 2min window: step = 12s, clamped to 15s.
	p.EnrichMetrics(g, 2*time.Minute)
	if capturedStep != "15s" {
		t.Errorf("step for 2m window = %q, want 15s", capturedStep)
	}

	// 10min window: step = 60s, within bounds.
	p.EnrichMetrics(g, 10*time.Minute)
	if capturedStep != "60s" {
		t.Errorf("step for 10m window = %q, want 60s", capturedStep)
	}

	// 6min window: step = 36s, within bounds.
	p.EnrichMetrics(g, 6*time.Minute)
	if capturedStep != "36s" {
		t.Errorf("step for 6m window = %q, want 36s", capturedStep)
	}

	// 3min window: step = 18s, within bounds.
	p.EnrichMetrics(g, 3*time.Minute)
	if capturedStep != "18s" {
		t.Errorf("step for 3m window = %q, want 18s", capturedStep)
	}
}

func TestEnrichMetricsFailOpen(t *testing.T) {
	// When the backend is unreachable, EnrichMetrics returns error lines
	// rather than panicking or blocking.
	p := &Prometheus{url: "http://localhost:59999", hc: &http.Client{Timeout: 100 * time.Millisecond}}
	g := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "TestAlert"}}}}

	lines := p.EnrichMetrics(g, 1*time.Hour)
	if len(lines) == 0 {
		t.Fatal("expected error lines for unreachable backend")
	}
	// The first line should be an error about the rules query.
	if !strings.Contains(lines[0], "error") && !strings.Contains(lines[0], "Error") {
		t.Errorf("expected error message, got %q", lines[0])
	}
}

func TestEnrichMetricsDeduplicatesAlertNames(t *testing.T) {
	rulesResp := rulesResponse{
		Status: "success",
		Data: rulesData{
			Groups: []ruleGroup{{
				Rules: []ruleEntry{
					{Name: "HighMemory", Type: "alert", Query: "mem > 90"},
				},
			}},
		},
	}

	queryCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/rules":
			json.NewEncoder(w).Encode(rulesResp)
		case "/api/v1/query_range":
			queryCount++
			json.NewEncoder(w).Encode(queryRangeResponse{Status: "success"})
		}
	}))
	defer srv.Close()

	p := &Prometheus{url: srv.URL, hc: http.DefaultClient}
	// Multiple alerts with the same name should only trigger one query_range.
	g := Group{Alerts: []Alert{
		{Labels: map[string]string{"alertname": "HighMemory", "instance": "a"}},
		{Labels: map[string]string{"alertname": "HighMemory", "instance": "b"}},
		{Labels: map[string]string{"alertname": "HighMemory", "instance": "c"}},
	}}
	p.EnrichMetrics(g, 1*time.Hour)

	if queryCount != 1 {
		t.Errorf("expected 1 query_range for deduplicated alert name, got %d", queryCount)
	}
}

func TestRenderEvidenceWithMetrics(t *testing.T) {
	r := Report{
		Group: Group{
			Key:      "test-group",
			Reason:   "OOMKilled",
			Node:     "node-1",
			Alerts:   []Alert{{Labels: map[string]string{"alertname": "HighMemory"}}},
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
			Key:      "test-group",
			Reason:   "OOMKilled",
			Node:     "node-1",
			Alerts:   []Alert{{Labels: map[string]string{"alertname": "HighMemory"}}},
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
	_, err := p.get("/api/v1/rules")
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
	_, err := p.fetchRules()
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
	_, err := p.queryRange("up", time.Unix(1000, 0), time.Unix(1020, 0), 10*time.Second)
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
	_, err := p.queryRange("up", time.Unix(1000, 0), time.Unix(1020, 0), 10*time.Second)
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
	_, err := p.fetchRules()
	if err == nil {
		t.Fatal("expected error for non-success status")
	}
}
