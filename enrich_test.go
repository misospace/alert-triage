package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPodList(t *testing.T) {
	data := []byte(`{"items":[{"metadata":{"name":"p1","namespace":"ns1"},"status":{"phase":"Failed"}}]}`)
	var got podList
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Metadata.Name != "p1" {
		t.Errorf("unexpected result: %v", got)
	}
}

func TestPodListEmpty(t *testing.T) {
	var got podList
	if err := json.Unmarshal([]byte(`{"items":[]}`), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestNodeList(t *testing.T) {
	data := []byte(`{"items":[{"metadata":{"name":"n1"},"status":{"conditions":[{"type":"Ready","status":"False"}]}}]}`)
	var got nodeList
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Metadata.Name != "n1" {
		t.Errorf("unexpected result: %v", got)
	}
}

func TestEventList(t *testing.T) {
	data := []byte(`{"items":[{"reason":"NodeNotReady","message":"node n1 not ready"}]}`)
	var got eventList
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Reason != "NodeNotReady" {
		t.Errorf("unexpected result: %v", got)
	}
}

func TestFluxList(t *testing.T) {
	data := []byte(`{"items":[{"metadata":{"name":"f1","namespace":"flux"},"status":{"conditions":[{"type":"Ready","status":"False"}]}}]}`)
	var got fluxList
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Metadata.Name != "f1" {
		t.Errorf("unexpected result: %v", got)
	}
}

func TestFluxListEmpty(t *testing.T) {
	var got fluxList
	if err := json.Unmarshal([]byte(`{"items":[]}`), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestStripSecrets(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"api_key=abc123", "api_key=[REDACTED]"},
		{"password: mysecret", "password: [REDACTED]"},
		{"token = xyz789", "token = [REDACTED]"},
		{"no secrets here", "no secrets here"},
		{"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY_ID=[REDACTED]"},
	}
	for _, tt := range tests {
		got := stripSecrets(tt.in)
		if strings.Contains(got, "abc123") || strings.Contains(got, "mysecret") || strings.Contains(got, "xyz789") || strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("stripSecrets(%q) = %q; secret not redacted", tt.in, got)
		}
	}
}

func TestFetchPodLogs_empty(t *testing.T) {
	k := &kube{}
	got := k.fetchPodLogs(nil)
	if got != nil {
		t.Errorf("expected nil for empty pods, got %v", got)
	}
	got = k.fetchPodLogs([]string{})
	if got != nil {
		t.Errorf("expected nil for empty slice, got %v", got)
	}
}

func TestFetchPodLogs_badKey(t *testing.T) {
	k := &kube{}
	got := k.fetchPodLogs([]string{"no-slash"})
	if len(got) != 0 {
		t.Errorf("expected empty map for bad key, got %v", got)
	}
}

func TestFetchPodLogs_noServer(t *testing.T) {
	k := &kube{base: "http://127.0.0.1:1"}
	got := k.fetchPodLogs([]string{"ns/pod"})
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
	got := k.fetchPodLogs([]string{"ns/pod"})
	if len(got) != 1 {
		t.Fatalf("expected 1 log, got %d", len(got))
	}
	if !strings.Contains(got["ns/pod"], "line1") {
		t.Errorf("log missing expected content: %q", got["ns/pod"])
	}
}

func TestFetchPodLogs_stripsSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("api_key=supersecret\nok line\n"))
	}))
	defer srv.Close()

	k := &kube{base: srv.URL + "/", token: "tok", hc: http.DefaultClient}
	got := k.fetchPodLogs([]string{"ns/pod"})
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
	got := k.fetchPodLogs([]string{"ns/pod"})
	if len(got) != 1 {
		t.Fatalf("expected 1 log, got %d", len(got))
	}
	if !strings.Contains(gotURL, "tailLines=20") {
		t.Errorf("expected tailLines=20 in request, got: %s", gotURL)
	}
}

// Regression: 0.1.8 compared the group's cluster against a client cluster that
// was never assigned, so every group looked foreign and enrichment was skipped
// on every instance. 77 digests shipped narrating alert text alone while
// claiming the cluster was healthy. An unknown client cluster must enrich, not
// refuse.
func TestEnrichSkipsOnlyWhenBothClustersAreKnownAndDiffer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()

	tests := []struct {
		name          string
		clientCluster string
		groupCluster  string
		wantSkipped   bool
	}{
		{"client cluster unknown enriches", "", "main", false},
		{"alert carries no cluster label enriches", "main", "", false},
		{"neither known enriches", "", "", false},
		{"same cluster enriches", "main", "main", false},
		{"known and different is skipped", "main", "utility", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &kube{cluster: tt.clientCluster, base: srv.URL, token: "tok", hc: srv.Client()}
			g := Group{Key: "single/A", Cluster: tt.groupCluster, Alerts: []Alert{
				{Labels: map[string]string{"alertname": "A", "namespace": "llm"}},
			}}
			got := k.Enrich(context.Background(), g, time.Minute, &Config{})

			skipped := strings.Contains(got.Scope, "cluster state unavailable")
			if skipped != tt.wantSkipped {
				t.Errorf("skipped = %v, want %v (scope: %q)", skipped, tt.wantSkipped, got.Scope)
			}
		})
	}
}

func TestEnrichment_empty(t *testing.T) {
	got := Enrichment{}.empty()
	if !got {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestEnrich_skipsSucceededPodsAndSortsByScore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.Contains(r.URL.Path, "/pods") || strings.Contains(r.URL.Path, "/log") {
			_, _ = io.WriteString(w, `{}`)
			return
		}
		_, _ = io.WriteString(w, `{"items":[
			{"metadata":{"name":"job-finished","namespace":"ns1"},
			 "status":{"phase":"Succeeded",
			   "containerStatuses":[{"ready":false,"restartCount":0,
			     "state":{"terminated":{"reason":"Completed"}}}]}},
			{"metadata":{"name":"flaky-restart","namespace":"ns1"},
			 "status":{"phase":"Running",
			   "containerStatuses":[{"ready":false,"restartCount":1,
			     "state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}},
			{"metadata":{"name":"pending-pod","namespace":"ns1"},
			 "status":{"phase":"Pending",
			   "containerStatuses":[{"ready":false,"restartCount":0,
			     "state":{"waiting":{"reason":"ImagePullBackOff"}}}]}},
			{"metadata":{"name":"job-finished-2","namespace":"ns1"},
			 "status":{"phase":"Succeeded",
			   "containerStatuses":[{"ready":false,"restartCount":0,
			     "state":{"terminated":{"reason":"Completed"}}}]}}
		]}`)
	}))
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "KubePodNotReady", "namespace": "ns1"}}},
		Namespaces: []string{"ns1"},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{})

	for _, p := range en.UnhealthyPods {
		if strings.Contains(p, "job-finished") {
			t.Errorf("Succeeded pod should be skipped, got %q", p)
		}
	}
	if len(en.UnhealthyPods) != 2 {
		t.Fatalf("expected 2 unhealthy pods (CrashLoopBackOff + Pending), got %d: %v", len(en.UnhealthyPods), en.UnhealthyPods)
	}
	if !strings.Contains(en.UnhealthyPods[0], "flaky-restart") {
		t.Errorf("expected worst pod (CrashLoopBackOff) first, got %v", en.UnhealthyPods)
	}
	if !strings.Contains(en.UnhealthyPods[1], "pending-pod") {
		t.Errorf("expected Pending pod second, got %v", en.UnhealthyPods)
	}
}
