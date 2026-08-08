package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLogBackendVictoriaLogs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/select/logsql/query" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("query") == "" {
			t.Error("expected query parameter")
		}

		w.Header().Set("Content-Type", "application/x-ndjson")
		data := `{"_msg":"error: connection refused","_time":"1700000000","_stream":"default/app"}
{"_msg":"error: connection refused","_time":"1700000001","_stream":"default/app"}
{"_msg":"info: retrying","_time":"1700000002","_stream":"default/app"}`
		_, _ = w.Write([]byte(data))
	}))
	defer srv.Close()

	lb := newLogBackend(srv.URL, "victorialogs", 10)
	lines, err := lb.Query([]string{"default"}, []string{"app-abc"}, time.Time{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if lines[0] != "error: connection refused" {
		t.Errorf("unexpected first line: %q", lines[0])
	}
}

func TestLogBackendLoki(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/loki/api/v1/query_range" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"result": []map[string]interface{}{
					{
						"values": [][]string{
							{"1700000000000000000", "error: connection refused"},
							{"1700000001000000000", "info: retrying"},
						},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	lb := newLogBackend(srv.URL, "loki", 10)
	lines, err := lb.Query([]string{"default"}, []string{"app-abc"}, time.Time{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	if lines[0] != "error: connection refused" {
		t.Errorf("unexpected first line: %q", lines[0])
	}
}

func TestLogBackendNil(t *testing.T) {
	lines, err := (*LogBackend)(nil).Query([]string{"default"}, nil, time.Time{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 0 {
		t.Fatalf("expected 0 lines from nil backend, got %d", len(lines))
	}
}

func TestLogBackendUnknownFlavor(t *testing.T) {
	lb := newLogBackend("http://example.com", "unknown", 10)
	_, err := lb.Query([]string{"default"}, nil, time.Time{}, time.Now())
	if err == nil {
		t.Fatal("expected error for unknown flavor")
	}
}

func TestBuildLogQuery(t *testing.T) {
	q := buildLogQuery([]string{"kube-system", "monitoring"}, []string{"app-abc"})
	if !strings.Contains(q, `namespace=~"kube-system|monitoring"`) {
		t.Errorf("query missing namespace: %s", q)
	}
	if !strings.Contains(q, `pod=~"app-abc"`) {
		t.Errorf("query missing pod: %s", q)
	}

	q2 := buildLogQuery([]string{"default"}, nil)
	if strings.Contains(q2, "pod") {
		t.Errorf("query should not contain pod filter: %s", q2)
	}
}

func TestCollapseLogLines(t *testing.T) {
	lines := []string{
		"error: connection refused",
		"error: connection refused",
		"error: connection refused",
		"info: retrying",
		"info: retrying",
	}
	collapsed := collapseLogLines(lines)
	if !strings.Contains(collapsed, "[3 × error: connection refused]") {
		t.Errorf("expected collapsed repeat, got: %s", collapsed)
	}
	if !strings.Contains(collapsed, "[2 × info: retrying]") {
		t.Errorf("expected collapsed repeat, got: %s", collapsed)
	}
}

func TestCollapseLogLinesCap(t *testing.T) {
	lines := make([]string, 100)
	for i := range lines {
		lines[i] = "line"
	}
	collapsed := collapseLogLines(lines)
	if strings.Count(collapsed, "\n") >= 40 {
		t.Errorf("expected at most 40 lines after collapse, got more newlines than expected: %d", strings.Count(collapsed, "\n"))
	}
}

func TestFetchBackendLogsNoBackend(t *testing.T) {
	logs, status := fetchBackendLogs(nil, Group{Namespaces: []string{"default"}}, 5*time.Minute)
	if logs != "" {
		t.Errorf("expected empty logs, got: %q", logs)
	}
	if status != "no log backend configured" {
		t.Errorf("expected 'no log backend configured', got: %q", status)
	}
}
