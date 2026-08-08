package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewPrometheus(t *testing.T) {
	t.Run("empty URL returns nil", func(t *testing.T) {
		p := newPrometheus("")
		if p != nil {
			t.Fatal("expected nil for empty URL")
		}
	})

	t.Run("non-empty URL returns client with trailing slash stripped", func(t *testing.T) {
		p := newPrometheus("http://prom:9090/")
		if p == nil {
			t.Fatal("expected non-nil for valid URL")
		}
		if p.url != "http://prom:9090" {
			t.Fatalf("unexpected url %q", p.url)
		}
	})
}

func TestFetchRuleExpression(t *testing.T) {
	t.Run("nil client returns error", func(t *testing.T) {
		_, err := (*Prometheus)(nil).FetchRuleExpression("OOMKilled")
		if err == nil {
			t.Fatal("expected error for nil client")
		}
	})

	t.Run("finds rule by name", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := rulesResponse{
				Status: "success",
				Data: rulesData{
					Groups: []ruleGroup{{
						Name: "kube-system",
						Rules: []ruleEntry{{
							Name:  "OOMKilled",
							Type:  "alerting",
							Query: "kube_pod_container_status_last_terminated_reason{reason=\"OOMKilled\"} > 0",
						}},
					}},
				},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer srv.Close()

		p := newPrometheus(srv.URL)
		expr, err := p.FetchRuleExpression("OOMKilled")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if expr != `kube_pod_container_status_last_terminated_reason{reason="OOMKilled"} > 0` {
			t.Fatalf("unexpected expression: %q", expr)
		}
	})

	t.Run("returns error when rule not found", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := rulesResponse{Status: "success", Data: rulesData{Groups: []ruleGroup{{}}}}
			json.NewEncoder(w).Encode(resp)
		}))
		defer srv.Close()

		p := newPrometheus(srv.URL)
		_, err := p.FetchRuleExpression("NonExistent")
		if err == nil {
			t.Fatal("expected error for missing rule")
		}
	})
}

func TestQueryRange(t *testing.T) {
	t.Run("nil client returns error", func(t *testing.T) {
		_, err := (*Prometheus)(nil).QueryRange("up", time.Time{}, time.Time{})
		if err == nil {
			t.Fatal("expected error for nil client")
		}
	})

	t.Run("returns values from response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := queryRangeResponse{
				Status: "success",
				Data: queryRangeData{
					ResultType: "matrix",
					Result: []queryResult{{
						Metric: map[string]string{"__name__": "up"},
						Values: [][]any{
							{float64(1000), "1"},
							{float64(2000), "0.5"},
							{float64(3000), "1"},
						},
					}},
				},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer srv.Close()

		p := newPrometheus(srv.URL)
		values, err := p.QueryRange("up", time.Unix(1000, 0), time.Unix(3000, 0))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(values) != 3 {
			t.Fatalf("expected 3 values, got %d", len(values))
		}
		if values[0] != 1 || values[1] != 0.5 || values[2] != 1 {
			t.Fatalf("unexpected values: %v", values)
		}
	})

	t.Run("skips NaN and Inf values", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := queryRangeResponse{
				Status: "success",
				Data: queryRangeData{
					ResultType: "matrix",
					Result: []queryResult{{
						Metric: map[string]string{"__name__": "test"},
						Values: [][]any{
							{float64(1000), "1"},
							{float64(2000), "NaN"},
							{float64(3000), "+Inf"},
							{float64(4000), "2"},
						},
					}},
				},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer srv.Close()

		p := newPrometheus(srv.URL)
		values, err := p.QueryRange("test", time.Unix(1000, 0), time.Unix(4000, 0))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(values) != 2 {
			t.Fatalf("expected 2 values (NaN and Inf skipped), got %d: %v", len(values), values)
		}
	})

	t.Run("returns empty slice when no results", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := queryRangeResponse{
				Status: "success",
				Data:   queryRangeData{ResultType: "matrix", Result: []queryResult{}},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer srv.Close()

		p := newPrometheus(srv.URL)
		values, err := p.QueryRange("nonexistent_metric", time.Unix(1000, 0), time.Unix(2000, 0))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(values) != 0 {
			t.Fatalf("expected 0 values, got %d", len(values))
		}
	})
}

func TestSummarize(t *testing.T) {
	tests := []struct {
		name     string
		values   []float64
		wantData bool
		wantMin  float64
		wantMax  float64
		wantLast float64
		wantDir  string
	}{
		{
			name:     "empty values",
			values:   nil,
			wantData: false,
		},
		{
			name:     "single value",
			values:   []float64{42},
			wantData: true,
			wantMin:  42, wantMax: 42, wantLast: 42,
			wantDir: "stable",
		},
		{
			name:     "rising trend",
			values:   []float64{1, 2, 3, 4, 5, 6, 7, 8},
			wantData: true,
			wantMin:  1, wantMax: 8, wantLast: 8,
			wantDir: "rising",
		},
		{
			name:     "falling trend",
			values:   []float64{8, 7, 6, 5, 4, 3, 2, 1},
			wantData: true,
			wantMin:  1, wantMax: 8, wantLast: 1,
			wantDir: "falling",
		},
		{
			name:     "stable values",
			values:   []float64{5, 5, 5, 5, 5, 5, 5, 5},
			wantData: true,
			wantMin:  5, wantMax: 5, wantLast: 5,
			wantDir: "stable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Summarize(tt.name, tt.values)
			if s.HasData != tt.wantData {
				t.Errorf("HasData = %v, want %v", s.HasData, tt.wantData)
			}
			if !tt.wantData {
				return
			}
			if s.Min != tt.wantMin {
				t.Errorf("Min = %v, want %v", s.Min, tt.wantMin)
			}
			if s.Max != tt.wantMax {
				t.Errorf("Max = %v, want %v", s.Max, tt.wantMax)
			}
			if s.Last != tt.wantLast {
				t.Errorf("Last = %v, want %v", s.Last, tt.wantLast)
			}
			if s.Direction != tt.wantDir {
				t.Errorf("Direction = %q, want %q", s.Direction, tt.wantDir)
			}
		})
	}
}

func TestComputeDirection(t *testing.T) {
	tests := []struct {
		name   string
		values []float64
		want   string
	}{
		{"less than 3 values", []float64{1, 2}, "stable"},
		{"rising", []float64{1, 2, 3, 4, 5, 6, 7, 8}, "rising"},
		{"falling", []float64{8, 7, 6, 5, 4, 3, 2, 1}, "falling"},
		{"stable", []float64{5, 5, 5, 5, 5, 5, 5, 5}, "stable"},
		{"near zero stable", []float64{0.001, 0.001, 0.001, 0.001}, "stable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeDirection(tt.values)
			if got != tt.want {
				t.Errorf("computeDirection(%v) = %q, want %q", tt.values, got, tt.want)
			}
		})
	}
}

func TestExtractPodNamespaces(t *testing.T) {
	g := Group{
		Alerts: []Alert{
			{Labels: map[string]string{"pod": "web-1", "namespace": "prod"}},
			{Labels: map[string]string{"pod": "web-1", "namespace": "prod"}}, // duplicate
			{Labels: map[string]string{"pod": "api-1", "namespace": "prod"}},
			{Labels: map[string]string{"pod": "", "namespace": "prod"}}, // no pod, skipped
		},
	}

	pods := extractPodNamespaces(g)
	if len(pods) != 2 {
		t.Fatalf("expected 2 unique pods, got %d", len(pods))
	}
	if pods[0].Pod != "web-1" || pods[0].NS != "prod" {
		t.Errorf("unexpected first pod: %+v", pods[0])
	}
	if pods[1].Pod != "api-1" || pods[1].NS != "prod" {
		t.Errorf("unexpected second pod: %+v", pods[1])
	}
}

func TestFetchGroupMetricsNilClient(t *testing.T) {
	var p *Prometheus
	g := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "OOMKilled"}}}}
	result := p.FetchGroupMetrics(g, 5*time.Minute)
	if result != nil {
		t.Fatal("expected nil for nil client")
	}
}

func TestFetchGroupMetricsIntegration(t *testing.T) {
	ruleCallCount := 0
	queryCallCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/rules":
			ruleCallCount++
			resp := rulesResponse{
				Status: "success",
				Data: rulesData{
					Groups: []ruleGroup{{
						Name: "alerts",
						Rules: []ruleEntry{{
							Name:  "OOMKilled",
							Type:  "alerting",
							Query: "kube_pod_container_status_last_terminated_reason{reason=\"OOMKilled\"} > 0",
						}},
					}},
				},
			}
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/api/v1/query_range":
			queryCallCount++
			resp := queryRangeResponse{
				Status: "success",
				Data: queryRangeData{
					ResultType: "matrix",
					Result: []queryResult{{
						Metric: map[string]string{"__name__": "test"},
						Values: [][]any{
							{float64(1000), "1"},
							{float64(2000), "2"},
							{float64(3000), "3"},
						},
					}},
				},
			}
			json.NewEncoder(w).Encode(resp)

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := newPrometheus(srv.URL)
	g := Group{Alerts: []Alert{{
		Labels: map[string]string{
			"alertname": "OOMKilled",
			"pod":       "web-1",
			"namespace": "prod",
		},
	}}}

	metrics := p.FetchGroupMetrics(g, 5*time.Minute)

	if len(metrics) == 0 {
		t.Fatal("expected at least one metric summary")
	}

	// First metric should be the rule expression
	if !metrics[0].HasData {
		t.Error("expected rule metric to have data")
	}

	// Should have called rules endpoint once
	if ruleCallCount != 1 {
		t.Errorf("expected 1 rules call, got %d", ruleCallCount)
	}

	// Should have called query_range: 1 (rule) + 3 (restarts, memory, cpu for one pod) = 4
	if queryCallCount != 4 {
		t.Errorf("expected 4 query_range calls, got %d", queryCallCount)
	}
}

func TestFormatMetricValue(t *testing.T) {
	tests := []struct {
		name string
		val  float64
		want string
	}{
		{"memory bytes", 1024 * 1024 * 512, "512.0Mi"},
		{"memory small", 1024, "1.0Ki"},
		{"throttle", 0.15, "15.0%"},
		{"restarts", 3, "3"},
		{"generic large", 123.456, "123.46"},
		{"generic small", 0.00123, "0.00123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatMetricValue(tt.name, tt.val)
			if got != tt.want {
				t.Errorf("formatMetricValue(%q, %v) = %q, want %q", tt.name, tt.val, got, tt.want)
			}
		})
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		val  float64
		want string
	}{
		{0, "0B"},
		{512, "512B"},
		{1024, "1.0Ki"},
		{1024 * 1024, "1.0Mi"},
		{1024 * 1024 * 1024, "1.0Gi"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v", tt.val), func(t *testing.T) {
			got := formatBytes(tt.val)
			if got != tt.want {
				t.Errorf("formatBytes(%v) = %q, want %q", tt.val, got, tt.want)
			}
		})
	}
}
