package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func sampleAlerts(severity string) []Alert {
	return []Alert{{
		Labels:   map[string]string{"alertname": "KubeJobFailed", "severity": severity, "namespace": "ns-app"},
		StartsAt: time.Now().Add(-3 * time.Minute),
	}}
}

func TestNewGitHubUnset(t *testing.T) {
	cfg := &Config{}
	if got := newGitHub(cfg); got != nil {
		t.Fatalf("newGitHub with no env should return nil, got %#v", got)
	}
	cfg.GitHubRepo = "owner/repo"
	if got := newGitHub(cfg); got != nil {
		t.Fatalf("newGitHub with token unset should return nil, got %#v", got)
	}
	cfg.GitHubToken = "tok"
	got := newGitHub(cfg)
	if got == nil {
		t.Fatalf("newGitHub with both fields set should return a client")
	}
	if got.repo != "owner/repo" || got.token != "tok" {
		t.Fatalf("client misconfigured: %#v", got)
	}
}

func TestShouldCommentInterval(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name   string
		iss    *ghIssue
		labels []ghLabel
		sev    string
		want   bool
	}{
		{
			name: "fresh open no recent comment",
			iss:  &ghIssue{CreatedAt: now.Add(-5 * time.Minute), UpdatedAt: now.Add(-5 * time.Minute)},
			want: true,
		},
		{
			name: "comment 1 minute ago is suppressed",
			iss:  &ghIssue{CreatedAt: now.Add(-1 * time.Hour), UpdatedAt: now.Add(-1 * time.Minute), Comments: 1},
			want: false,
		},
		{
			name: "comment 13h ago passes",
			iss:  &ghIssue{CreatedAt: now.Add(-2 * 24 * time.Hour), UpdatedAt: now.Add(-13 * time.Hour), Comments: 2},
			want: true,
		},
		{
			name:   "unchanged severity within interval is suppressed",
			iss:    &ghIssue{CreatedAt: now.Add(-1 * time.Hour), UpdatedAt: now.Add(-1 * time.Minute), Comments: 1},
			labels: []ghLabel{{Name: "alert-triage"}, {Name: "warning"}},
			sev:    "warning",
			want:   false,
		},
		{
			name:   "unchanged severity after interval passes",
			iss:    &ghIssue{CreatedAt: now.Add(-2 * 24 * time.Hour), UpdatedAt: now.Add(-13 * time.Hour), Comments: 2},
			labels: []ghLabel{{Name: "alert-triage"}, {Name: "warning"}},
			sev:    "warning",
			want:   true,
		},
		{
			name:   "escalated severity within interval passes",
			iss:    &ghIssue{CreatedAt: now.Add(-1 * time.Hour), UpdatedAt: now.Add(-1 * time.Minute), Comments: 1},
			labels: []ghLabel{{Name: "alert-triage"}, {Name: "warning"}},
			sev:    "critical",
			want:   true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.iss.Labels = c.labels
			r := Report{Group: Group{Key: "KubeJobFailed", Alerts: sampleAlerts(c.sev)}}
			if got := shouldComment(c.iss, r, 12*time.Hour); got != c.want {
				t.Fatalf("want %v got %v", c.want, got)
			}
		})
	}
}

func TestSeverityLabel(t *testing.T) {
	cases := map[string]string{
		"critical": "critical",
		"Warning":  "warning",
		"info":     "info",
		"":         "",
		"  ":       "",
		"strange":  "strange",
	}
	for in, want := range cases {
		if got := severityLabel(in); got != want {
			t.Fatalf("severityLabel(%q) = %q want %q", in, got, want)
		}
	}
}

func TestSignatureMarker(t *testing.T) {
	sig := "KubeJobFailed|abc"
	marker := fmt.Sprintf(signatureMarker, sig)
	if !strings.HasPrefix(marker, "<!-- alert-triage:") {
		t.Fatalf("marker %q missing prefix", marker)
	}
	if !strings.HasSuffix(marker, " -->") {
		t.Fatalf("marker %q missing suffix", marker)
	}
	if !strings.Contains(marker, `"sig":"`+sig+`"`) {
		t.Fatalf("marker %q missing sig payload", marker)
	}
}

// splitFirstLine returns the first line (without trailing newline) and the rest.
func splitFirstLine(s string) (string, string) {
	s = strings.TrimPrefix(s, "\n")
	idx := strings.IndexByte(s, '\n')
	if idx < 0 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

// stubGitHub is an httptest server that simulates GitHub's REST API enough for
// the tests below: it pages through issues, accepts issue creation, and accepts
// issue comments.
type stubGitHub struct {
	server *httptest.Server
	calls  atomic.Int32
}

func (s *stubGitHub) issuesHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/issues", func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			page := r.URL.Query().Get("page")
			switch page {
			case "", "1":
				rel := fmt.Sprintf(`<%s%s?page=2>; rel="next"`, s.server.URL, r.URL.Path)
				w.Header().Set("Link", rel)
				_, _ = w.Write([]byte(`[{"number":1,"title":"first","body":"one"}]`))
			case "2":
				rel := fmt.Sprintf(`<%s%s?page=3>; rel="next"`, s.server.URL, r.URL.Path)
				w.Header().Set("Link", rel)
				_, _ = w.Write([]byte(`[{"number":2,"title":"second","body":"two"}]`))
			case "3":
				_, _ = w.Write([]byte(`[]`))
			default:
				_, _ = w.Write([]byte(`[]`))
			}
			return
		}
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"number":42,"title":"new","body":"new body","html_url":"https://example.com/42"}`))
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("/repos/owner/repo/issues/42/comments", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":7}`))
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	return mux
}

func newStubGitHub(t *testing.T) *stubGitHub {
	t.Helper()
	stub := &stubGitHub{}
	stub.server = httptest.NewServer(stub.issuesHandler())
	t.Cleanup(stub.server.Close)
	return stub
}

func TestSetHeaders(t *testing.T) {
	cfg := &Config{GitHubRepo: "owner/repo", GitHubToken: "secret-token"}
	g := newGitHub(cfg)
	if g == nil {
		t.Fatalf("client should be non-nil")
	}
	req, err := http.NewRequest(http.MethodGet, "http://example.invalid", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	g.setHeaders(req)
	if got := req.Header.Get("Authorization"); got != "Bearer secret-token" {
		t.Fatalf("Authorization = %q", got)
	}
	if got := req.Header.Get("Accept"); got != "application/vnd.github+json" {
		t.Fatalf("Accept = %q", got)
	}
	if got := req.Header.Get("User-Agent"); got == "" {
		t.Fatalf("User-Agent should be set")
	}
}

func TestParseNextPage(t *testing.T) {
	if got := parseNextPage(""); got != 0 {
		t.Fatalf("empty header should give 0, got %d", got)
	}
	if got := parseNextPage(`<https://api.example.invalid/repos/owner/repo/issues?page=2>; rel="last"`); got != 0 {
		t.Fatalf("no rel=next should give 0, got %d", got)
	}
	if got := parseNextPage(`garbage data without brackets`); got != 0 {
		t.Fatalf("malformed should give 0, got %d", got)
	}
	if got := parseNextPage(`<https://api.example.invalid/p?page=3>; rel="next"`); got != 3 {
		t.Fatalf("with rel=next should give 3, got %d", got)
	}
	if got := parseNextPage(`<https://api.example.invalid/p?page=2>; rel="prev", <https://api.example.invalid/p?page=4>; rel="next"`); got != 4 {
		t.Fatalf("first match wins, got %d", got)
	}
}

func TestRenderIssueBodyMarkerFirstLine(t *testing.T) {
	cfg := &Config{GrafanaURL: "https://grafana.example.com"}
	r := Report{Cfg: cfg, Group: Group{Key: "KubeJobFailed", Alerts: sampleAlerts("warning")}}
	sig := r.Group.Signature()
	body := renderIssueBody(r, sig)
	first, rest := splitFirstLine(body)
	if !strings.HasPrefix(first, "<!-- alert-triage:") {
		t.Fatalf("first line should be the signature marker, got %q", first)
	}
	if !strings.Contains(rest, first) {
		t.Fatalf("marker should appear in body once")
	}
	if !strings.Contains(body, "KubeJobFailed") {
		t.Fatalf("body missing group key")
	}
}

func TestRenderIssueBodyLowConfidence(t *testing.T) {
	cfg := &Config{}
	r := Report{
		Cfg:    cfg,
		Group:  Group{Key: "LowConf", Alerts: sampleAlerts("info")},
		Triage: Triage{FixLocation: "git", Confidence: "low"},
	}
	body := renderIssueBody(r, r.Group.Signature())
	if !strings.Contains(body, "LowConf") {
		t.Fatalf("body missing group key")
	}
	if !strings.Contains(body, "low confidence") {
		t.Fatalf("body missing low-confidence marker")
	}
}

func TestRenderIssueBodyGrafanaLinkPresent(t *testing.T) {
	cfg := &Config{GrafanaURL: "https://grafana.example.com"}
	r := Report{Cfg: cfg, Group: Group{Key: "KubeJobFailed", Alerts: sampleAlerts("warning")}}
	body := renderIssueBody(r, r.Group.Signature())
	if !strings.Contains(body, "grafana.example.com") {
		t.Fatalf("body should include grafana host: %s", body)
	}
}

func TestRenderIssueBodyGrafanaLinkAbsent(t *testing.T) {
	cfg := &Config{}
	r := Report{Cfg: cfg, Group: Group{Key: "KubeJobFailed", Alerts: sampleAlerts("warning")}}
	body := renderIssueBody(r, r.Group.Signature())
	if strings.Contains(body, "grafana.example.com") || strings.Contains(body, "Grafana") {
		t.Fatalf("body should not mention Grafana when GrafanaURL unset: %s", body)
	}
}

func TestRenderIssueBodyPayloadDetails(t *testing.T) {
	cfg := &Config{}
	r := Report{
		Cfg:    cfg,
		Group:  Group{Key: "KubeJobFailed", Alerts: sampleAlerts("warning")},
		Raw:    `{"alerts":[]}`,
	}
	body := renderIssueBody(r, r.Group.Signature())
	if !strings.Contains(body, "<details>") {
		t.Fatalf("body should contain details block when payload present, got:\n%s", body)
	}
}

func TestRenderCommentBody(t *testing.T) {
	r := Report{Group: Group{Key: "KubeJobFailed", Alerts: sampleAlerts("warning")}, PriorSeen: 3}
	body := renderCommentBody(r)
	if !strings.Contains(body, "3") {
		t.Fatalf("comment should reference prior count: %s", body)
	}
	if !strings.Contains(body, "warning") {
		t.Fatalf("comment should mention severity: %s", body)
	}
	if !strings.Contains(body, fmt.Sprintf(signatureMarker, r.Group.Signature())) {
		t.Fatalf("comment should carry signature marker: %s", body)
	}
}

func TestDeliverGitHubCreatePath(t *testing.T) {
	stub := newStubGitHub(t)
	cfg := &Config{
		GitHubRepo:  "owner/repo",
		GitHubToken: "tok",
	}
	g := newGitHub(cfg)
	if g == nil {
		t.Fatalf("client should be non-nil")
	}
	g.apiURL = stub.server.URL
	r := Report{Group: Group{Key: "KubeJobFailed", Alerts: sampleAlerts("warning")}, Triage: Triage{FixLocation: "git"}}
	action, err := deliverGitHub(context.Background(), g, cfg, r)
	if err != nil {
		t.Fatalf("deliverGitHub: %v", err)
	}
	if action.Outcome == "" {
		t.Fatalf("expected non-empty outcome")
	}
	if stub.calls.Load() == 0 {
		t.Fatalf("expected at least one HTTP call to stub")
	}
}

func TestDeliverGitHubCommentPath(t *testing.T) {
	stub := newStubGitHub(t)
	cfg := &Config{
		GitHubRepo:  "owner/repo",
		GitHubToken: "tok",
	}
	g := newGitHub(cfg)
	g.apiURL = stub.server.URL
	r := Report{Group: Group{Key: "KubeJobFailed", Alerts: sampleAlerts("warning")}, Triage: Triage{FixLocation: "git"}}
	if _, err := deliverGitHub(context.Background(), g, cfg, r); err != nil {
		t.Fatalf("deliverGitHub: %v", err)
	}
}

func TestDeliverGitHubSuppressedByInterval(t *testing.T) {
	cfg := &Config{
		GitHubRepo:           "owner/repo",
		GitHubToken:          "tok",
		IssueCommentInterval: 24 * time.Hour,
	}
	now := time.Now()
	r := Report{Group: Group{Key: "KubeJobFailed", Alerts: sampleAlerts("warning")}, Triage: Triage{FixLocation: "git"}}
	open := &ghIssue{Number: 7, UpdatedAt: now, Comments: 1, Labels: []ghLabel{{Name: "warning"}}}
	if got := shouldComment(open, r, cfg.IssueCommentInterval); got {
		t.Fatalf("interval gate should suppress a 1m-old comment")
	}
}

func TestDeliverGitHubNonActionable(t *testing.T) {
	stub := newStubGitHub(t)
	cfg := &Config{
		GitHubRepo:  "owner/repo",
		GitHubToken: "tok",
	}
	g := newGitHub(cfg)
	g.apiURL = stub.server.URL
	r := Report{Group: Group{Key: "KubeJobFailed", Alerts: sampleAlerts("info")}, Triage: Triage{FixLocation: "none"}}
	action, err := deliverGitHub(context.Background(), g, cfg, r)
	if err != nil {
		t.Fatalf("non-actionable should not error: %v", err)
	}
	if action.Outcome != "none" {
		t.Fatalf("expected outcome=none, got %q", action.Outcome)
	}
}

func TestDeliverGitHubNilClient(t *testing.T) {
	cfg := &Config{}
	r := Report{Group: Group{Key: "X"}, Triage: Triage{FixLocation: "git"}}
	action, err := deliverGitHub(context.Background(), nil, cfg, r)
	if err != nil {
		t.Fatalf("nil client should be a no-op, got %v", err)
	}
	if action.Outcome != "none" {
		t.Fatalf("expected outcome=none for nil client, got %q", action.Outcome)
	}
}

func TestFindOpenIssueStub(t *testing.T) {
	stub := newStubGitHub(t)
	cfg := &Config{GitHubRepo: "owner/repo", GitHubToken: "tok"}
	g := newGitHub(cfg)
	g.apiURL = stub.server.URL
	_, err := g.findOpenIssue(context.Background(), "sig-x")
	if err != nil {
		t.Fatalf("findOpenIssue: %v", err)
	}
}

func TestCreateIssueBodyShape(t *testing.T) {
	var captured io.Reader
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/owner/repo/issues" && r.Method == http.MethodPost {
			captured = r.Body
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"number":1,"title":"x","body":"y","html_url":"http://e/x"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)
	cfg := &Config{GitHubRepo: "owner/repo", GitHubToken: "tok"}
	g := newGitHub(cfg)
	g.apiURL = srv.URL
	if _, _, err := g.createIssue(context.Background(), "title-x", "body-y", nil); err != nil {
		t.Fatalf("createIssue: %v", err)
	}
	if captured == nil {
		t.Fatalf("createIssue did not POST")
	}
	var payload map[string]any
	if err := json.NewDecoder(captured).Decode(&payload); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if payload["title"] != "title-x" || payload["body"] != "body-y" {
		t.Fatalf("payload mismatch: %#v", payload)
	}
}
