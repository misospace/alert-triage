package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchBackendLogsVictoriaLogs(t *testing.T) {
	var requestPath, requestQuery, requestStart, requestEnd string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		requestQuery = r.URL.Query().Get("query")
		requestStart = r.URL.Query().Get("start")
		requestEnd = r.URL.Query().Get("end")
		w.Header().Set("Content-Type", "application/x-ndjson")
		fmt.Fprintln(w, `{"_stream":"pod-a","_msg":"password=hunter2"}`)
		fmt.Fprintln(w, `{"_stream":"pod-b","_msg":"ready"}`)
	}))
	defer server.Close()

	t.Setenv("LOGS_URL", server.URL)
	t.Setenv("LOGS_FLAVOR", "victorialogs")
	t.Setenv("LOGS_LIMIT", "2")

	start := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	end := start.Add(3 * time.Minute)
	group := Group{
		Namespaces: []string{"default"},
		Alerts: []Alert{{
			StartsAt: start,
			EndsAt:   end,
			Labels:   map[string]string{"namespace": "default", "pod": "api-0"},
		}},
	}
	state, lines, detail := fetchBackendLogs(group, 3*time.Minute)
	if state != "ok" || detail != "" {
		t.Fatalf("state=%q lines=%q detail=%q", state, lines, detail)
	}
	if requestPath != "/select/logsql/query" {
		t.Fatalf("path=%q", requestPath)
	}
	if !strings.Contains(requestQuery, `namespace:"default"`) || !strings.Contains(requestQuery, `pod:"api-0"`) {
		t.Fatalf("query=%q", requestQuery)
	}
	parsedStart, err := time.Parse(time.RFC3339Nano, requestStart)
	if err != nil || !parsedStart.Equal(start) {
		t.Fatalf("start=%q (%v)", requestStart, err)
	}
	parsedEnd, err := time.Parse(time.RFC3339Nano, requestEnd)
	if err != nil || !parsedEnd.Equal(end) {
		t.Fatalf("end=%q (%v)", requestEnd, err)
	}
	if len(lines) != 2 || !strings.Contains(lines[0], "[REDACTED]") {
		t.Fatalf("lines=%q", lines)
	}
}

func TestFetchBackendLogsLoki(t *testing.T) {
	var gotQuery, gotStart, gotEnd, gotLimit string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		gotStart = r.URL.Query().Get("start")
		gotEnd = r.URL.Query().Get("end")
		gotLimit = r.URL.Query().Get("limit")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"success","data":{"result":[{"stream":{"pod":"api-0"},"values":[["1","token=secret"]]}]}}`)
	}))
	defer server.Close()

	t.Setenv("LOGS_URL", server.URL)
	t.Setenv("LOGS_FLAVOR", "loki")
	t.Setenv("LOGS_LIMIT", "7")
	b, err := newLogsBackend()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	q := logQuery{
		query: logQueryString(b.flavor, "default", "api-0"),
		start: formatLogTime(start, b.flavor),
		end:   formatLogTime(start.Add(time.Minute), b.flavor),
	}
	lines, err := b.query(q)
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != `{namespace="default",pod="api-0"}` || gotLimit != "7" {
		t.Fatalf("query=%q limit=%q", gotQuery, gotLimit)
	}
	if gotStart != fmt.Sprint(start.UnixNano()) || gotEnd != fmt.Sprint(start.Add(time.Minute).UnixNano()) {
		t.Fatalf("start=%q end=%q", gotStart, gotEnd)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "[REDACTED]") {
		t.Fatalf("lines=%q", lines)
	}
}

func TestCollapseBackendLinesCapsAndCountsRepeats(t *testing.T) {
	lines := []string{"same", "same", "one", "two", "three", "four", "password=secret"}
	got := collapseBackendLines(lines, 2)
	if len(got) != 3 {
		t.Fatalf("got %d lines, want a cap marker: %q", len(got), got)
	}
	if got[0] != "same (repeated 2 times)" {
		t.Fatalf("repeated line=%q", got[0])
	}
	if !strings.Contains(got[2], "omitted after cap") {
		t.Fatalf("cap marker=%q", got[2])
	}
}

func TestBackendUnconfiguredIsDistinctFromNoResults(t *testing.T) {
	t.Setenv("LOGS_URL", "")
	t.Setenv("LOGS_FLAVOR", "victorialogs")
	state, lines, detail := fetchBackendLogs(Group{Namespaces: []string{"default"}}, time.Minute)
	if state != backendUnconfigured || len(lines) != 0 || detail != "" {
		t.Fatalf("unconfigured state=%q lines=%q detail=%q", state, lines, detail)
	}

	t.Setenv("LOGS_URL", "http://127.0.0.1:1")
	serverState, serverLines, serverDetail := fetchBackendLogs(Group{Namespaces: []string{"default"}}, time.Minute)
	if serverState != backendError || len(serverLines) != 0 || serverDetail == "" {
		t.Fatalf("error state=%q lines=%q detail=%q", serverState, serverLines, serverDetail)
	}
}
