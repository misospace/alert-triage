package main

import (
	"context"
	"encoding/json"
	"errors"
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
		{
			name:   "escalated severity after interval passes",
			iss:    &ghIssue{CreatedAt: now.Add(-2 * 24 * time.Hour), UpdatedAt: now.Add(-13 * time.Hour), Comments: 2},
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
	if strings.Contains(rest, first) {
		t.Fatalf("marker should appear only on the first line, but appears more than once")
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
	cfg := &Config{GrafanaURL: "https://grafana.example.com", GrafanaLogsDS: "loki"}
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
		Cfg:   cfg,
		Group: Group{Key: "KubeJobFailed", Alerts: sampleAlerts("warning")},
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
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/owner/repo/issues" && r.Method == http.MethodPost {
			captured, _ = io.ReadAll(r.Body)
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
	if len(captured) == 0 {
		t.Fatalf("createIssue did not POST")
	}
	var payload map[string]any
	if err := json.Unmarshal(captured, &payload); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if payload["title"] != "title-x" || payload["body"] != "body-y" {
		t.Fatalf("payload mismatch: %#v", payload)
	}
}

// A stalled GitHub API must not hold the delivery loop for the full 30s
// budget: cancelling the caller's context — as a SIGTERM drain does — must
// abort the in-flight request promptly. The GitHub client Deliver builds is
// fixed to api.github.com, so this drives the arm directly against a blocked
// server with the same 100ms-cancel / <200ms shape as the Discord arm's
// TestDeliverContextCancelledInFlight (issue #145).
func TestDeliverGitHubContextCancelledInFlight(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hold the connection open without responding so the request is
		// in flight; releasing it lets the handler finish and srv.Close()
		// does not wait on the connection.
		<-release
	}))
	defer srv.Close()
	defer close(release)

	cfg := &Config{GitHubRepo: "owner/repo", GitHubToken: "tok"}
	g := newGitHub(cfg)
	g.apiURL = srv.URL
	r := Report{Group: Group{Key: "KubeJobFailed", Alerts: sampleAlerts("warning")}, Triage: Triage{FixLocation: "git"}}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := deliverGitHub(ctx, g, cfg, r)
	elapsed := time.Since(start)

	if elapsed > 200*time.Millisecond {
		t.Fatalf("deliverGitHub took %v after context cancellation, want < 200ms", elapsed)
	}
	if err == nil {
		t.Fatal("expected error on context cancellation")
	}
	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context cancellation error, got %v", err)
	}
}

// --- Commit-relevance helpers (issue #135) ---

func TestParseGitHubRepoURL(t *testing.T) {
	cases := []struct {
		raw   string
		owner string
		repo  string
		ok    bool
	}{
		{"https://github.com/owner/name", "owner", "name", true},
		{"https://github.com/owner/name.git", "owner", "name", true},
		{"http://github.com/owner/name", "owner", "name", true},
		{"git@github.com:owner/name.git", "owner", "name", true},
		{"ssh://git@github.com/owner/name.git", "owner", "name", true},
		{"https://github.com/owner/name/", "owner", "name", true},
		{"https://gitlab.com/owner/name", "", "", false},
		{"https://example.com/owner/name", "", "", false},
		{"git@gitlab.com:owner/name.git", "", "", false},
		{"https://github.com/only", "", "", false},
		{"", "", "", false},
		{"  ", "", "", false},
		{"https://github.com//repo", "", "", false},
	}
	for _, c := range cases {
		owner, name, ok := parseGitHubRepoURL(c.raw)
		if owner != c.owner || name != c.repo || ok != c.ok {
			t.Errorf("parseGitHubRepoURL(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.raw, owner, name, ok, c.owner, c.repo, c.ok)
		}
	}
}

func TestParseFluxRevisionSHA(t *testing.T) {
	const validSHA = "0123456789abcdef0123456789abcdef01234567"
	const upperSHA = "0123456789ABCDEF0123456789ABCDEF01234567"
	cases := []struct {
		rev  string
		want string
		ok   bool
	}{
		{"refs/heads/main@sha1:" + validSHA, validSHA, true},
		{"refs/heads/main@sha1:" + upperSHA, validSHA, true},
		{"refs/tags/v1.0.0@sha1:" + validSHA, validSHA, true},
		{"main@sha1:" + validSHA, validSHA, true},
		{"sha1:" + validSHA, validSHA, true},
		{validSHA, validSHA, true},
		{"refs/heads/main", "", false},
		{"main", "", false},
		{"refs/heads/main@sha1:tooshort", "", false},
		{"refs/heads/main@sha1:" + validSHA + "extra", "", false},
		{"refs/heads/main@sha256:" + strings.Repeat("a", 64), "", false}, // sha256 not yet Flux-stamped
		// SHA-1 hash with the wrong algorithm label is also rejected: the
		// parser must match what Flux actually stamps, not silently accept
		// whatever algorithm string the object happens to carry.
		{"refs/heads/main@sha99:" + validSHA, "", false},
		{"", "", false},
		{"refs/heads/main@sha1:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "", false},
	}
	for _, c := range cases {
		got, ok := parseFluxRevisionSHA(c.rev)
		if got != c.want || ok != c.ok {
			t.Errorf("parseFluxRevisionSHA(%q) = (%q,%v), want (%q,%v)", c.rev, got, ok, c.want, c.ok)
		}
	}
}

func TestPathIntersects(t *testing.T) {
	cases := []struct {
		name           string
		workload       string
		components     []string
		changed        []string
		wantContains   []string
		wantNotContain string
	}{
		{
			name:         "touches workload path",
			workload:     "apps/payments",
			changed:      []string{"apps/payments/kustomization.yaml", "apps/payments/deployment.yaml"},
			wantContains: []string{"apps/payments/kustomization.yaml", "apps/payments/deployment.yaml"},
		},
		{
			name:           "unrelated path does not touch",
			workload:       "apps/payments",
			changed:        []string{"apps/orders/kustomization.yaml", "README.md"},
			wantNotContain: "apps/orders/kustomization.yaml",
		},
		{
			name:         "component path match",
			workload:     "apps/payments",
			components:   []string{"components/backup"},
			changed:      []string{"components/backup/kustomization.yaml"},
			wantContains: []string{"components/backup/kustomization.yaml"},
		},
		{
			name:           "prefix that is not a segment boundary does not match",
			workload:       "app",
			changed:        []string{"application/x.yaml"},
			wantNotContain: "application/x.yaml",
		},
		{
			name:           "no workload path is a no-op",
			changed:        []string{"anything.yaml"},
			wantNotContain: "anything.yaml",
		},
		{
			name:           "traversal in workload path drops .. segments so they cannot escape",
			workload:       "../../etc",
			changed:        []string{"secrets/x.yaml"},
			wantNotContain: "secrets/x.yaml",
		},
		{
			name:         "leading slash in changed file is stripped",
			workload:     "apps/payments",
			changed:      []string{"/apps/payments/deployment.yaml"},
			wantContains: []string{"/apps/payments/deployment.yaml"},
		},
		{
			name:         "component resolved against the workload path (../shared)",
			workload:     "apps/payments/prod",
			components:   []string{"apps/payments/shared"},
			changed:      []string{"apps/payments/shared/x.yaml"},
			wantContains: []string{"apps/payments/shared/x.yaml"},
		},
		{
			name:           "component that stays inside the workload path matches a nested file",
			workload:       "apps/payments",
			components:     []string{"deploy/prod"},
			changed:        []string{"apps/payments/deploy/prod/x.yaml"},
			wantContains:   []string{"apps/payments/deploy/prod/x.yaml"},
			wantNotContain: "apps/payments/deploy/staging/x.yaml",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pathIntersects(c.workload, c.components, c.changed)
			for _, want := range c.wantContains {
				found := false
				for _, g := range got {
					if g == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected match for %q, got %v", want, got)
				}
			}
			if c.wantNotContain != "" {
				for _, g := range got {
					if g == c.wantNotContain {
						t.Errorf("unexpected match for %q, got %v", c.wantNotContain, got)
					}
				}
			}
		})
	}
}

// fakeCommitServer is an httptest server shaped like GitHub's
// GET /repos/{owner}/{repo}/commits/{sha}. It serves one canned payload per
// configured SHA so the tests can drive multiple commits through a single
// client without re-wiring the mux.
type fakeCommitServer struct {
	srv      *httptest.Server
	calls    atomic.Int32
	payloads map[string]commitPayload
	status   map[string]int
	// pageOverrides keys a specific page of a paginated commit. The key is
	// "<owner>/<repo>/<sha>/<page>" (or "<sha>/<page>" for the default
	// single-repo key) and, when present, takes precedence over the base
	// payload so a test can serve page 1 with one file set and page 2 with
	// another.
	pageOverrides map[string]commitPayload
}

type commitPayload struct {
	files   []map[string]string
	message string
	// links, when non-empty, is set as the response Link header so the
	// test can drive pagination (fetchCommitFiles follows rel="next").
	links string
}

func newFakeCommitServer(t *testing.T) *fakeCommitServer {
	f := &fakeCommitServer{
		payloads:      map[string]commitPayload{},
		status:        map[string]int{},
		pageOverrides: map[string]commitPayload{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		// Path is /repos/owner/repo/commits/<sha>
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 5 || parts[0] != "repos" || parts[3] != "commits" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
			return
		}
		sha := parts[4]
		// Key the payload on repo + sha so one server can stand in for
		// multiple repositories (the cross-repo lookup test) while the
		// default single-repo tests keep using plain SHA keys.
		repoKey := parts[1] + "/" + parts[2] + "/" + sha
		key := sha
		if _, ok := f.payloads[repoKey]; ok {
			key = repoKey
		}
		// A page override (driven by the page query param) wins over the
		// base payload so a paginated test can serve distinct file sets per
		// page.
		page := r.URL.Query().Get("page")
		if page == "" {
			page = "1"
		}
		if s, ok := f.status[sha]; ok {
			w.WriteHeader(s)
			_, _ = w.Write([]byte(`{"message":"forced status"}`))
			return
		}
		var (
			p  commitPayload
			ok bool
		)
		if ov, o := f.pageOverrides[key+"/"+page]; o {
			p, ok = ov, true
		} else {
			p, ok = f.payloads[key]
		}
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"unknown sha"}`))
			return
		}
		files := make([]map[string]string, 0, len(p.files))
		for _, fl := range p.files {
			files = append(files, map[string]string{"filename": fl["filename"]})
		}
		resp := map[string]any{
			"sha":    sha,
			"commit": map[string]any{"message": p.message},
			"files":  files,
		}
		w.Header().Set("Content-Type", "application/json")
		if p.links != "" {
			w.Header().Set("Link", p.links)
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCommitServer) client() *gitHubClient {
	return &gitHubClient{
		token:  "t",
		repo:   "owner/repo",
		hc:     &http.Client{Timeout: 5 * time.Second},
		apiURL: f.srv.URL,
	}
}

// TestClassifyCommitTouches drives classifyCommit end-to-end against the
// fake commit server: a commit whose changed files include the workload
// path produces State == "touches" with the matching file listed.
func TestClassifyCommitTouches(t *testing.T) {
	srv := newFakeCommitServer(t)
	srv.payloads["0123456789abcdef0123456789abcdef01234567"] = commitPayload{
		files: []map[string]string{
			{"filename": "apps/payments/kustomization.yaml"},
			{"filename": "README.md"},
		},
		message: "bump image tag",
	}
	g := srv.client()
	rel := classifyCommit(context.Background(), g, "https://github.com/owner/repo",
		"refs/heads/main@sha1:0123456789abcdef0123456789abcdef01234567",
		"apps/payments", nil)
	if rel.State != commitRelevanceTouches {
		t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceTouches, rel.Reason)
	}
	if len(rel.MatchingPaths) != 1 || rel.MatchingPaths[0] != "apps/payments/kustomization.yaml" {
		t.Fatalf("matching paths = %v, want [apps/payments/kustomization.yaml]", rel.MatchingPaths)
	}
	if rel.CommitMessage != "bump image tag" {
		t.Fatalf("commit message = %q", rel.CommitMessage)
	}
}

// TestClassifyCommitDoesNotTouch covers the motivating case: a commit that
// only touches an unrelated workload is explicitly rendered as not touching
// the affected one.
func TestClassifyCommitDoesNotTouch(t *testing.T) {
	srv := newFakeCommitServer(t)
	srv.payloads["0123456789abcdef0123456789abcdef01234567"] = commitPayload{
		files: []map[string]string{
			{"filename": "apps/orders/kustomization.yaml"},
		},
		message: "bump image tag for orders",
	}
	g := srv.client()
	rel := classifyCommit(context.Background(), g, "https://github.com/owner/repo",
		"refs/heads/main@sha1:0123456789abcdef0123456789abcdef01234567",
		"apps/payments", nil)
	if rel.State != commitRelevanceDoesNotTouch {
		t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceDoesNotTouch, rel.Reason)
	}
	if len(rel.MatchingPaths) != 0 {
		t.Fatalf("expected no matching paths, got %v", rel.MatchingPaths)
	}
	if rel.CommitMessage != "bump image tag for orders" {
		t.Fatalf("commit message = %q", rel.CommitMessage)
	}
}

// TestClassifyCommitComponentPathMatch exercises the issue #134 dependency:
// the workload path is "apps/payments" but the commit only touches one of
// the declared component paths, so the result must still be "touches".
func TestClassifyCommitComponentPathMatch(t *testing.T) {
	srv := newFakeCommitServer(t)
	srv.payloads["0123456789abcdef0123456789abcdef01234567"] = commitPayload{
		files: []map[string]string{
			{"filename": "components/backup/job.yaml"},
		},
		message: "tune backup retention",
	}
	g := srv.client()
	rel := classifyCommit(context.Background(), g, "https://github.com/owner/repo",
		"refs/heads/main@sha1:0123456789abcdef0123456789abcdef01234567",
		"apps/payments", []string{"components/backup"})
	if rel.State != commitRelevanceTouches {
		t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceTouches, rel.Reason)
	}
	if len(rel.MatchingPaths) != 1 || rel.MatchingPaths[0] != "components/backup/job.yaml" {
		t.Fatalf("matching paths = %v, want [components/backup/job.yaml]", rel.MatchingPaths)
	}
}

// TestClassifyCommitUnsupportedHost verifies a non-github.com repo URL
// degrades to "unknown" without making an HTTP call.
func TestClassifyCommitUnsupportedHost(t *testing.T) {
	g := &gitHubClient{token: "t", repo: "owner/repo", hc: &http.Client{}, apiURL: "http://unused.invalid"}
	rel := classifyCommit(context.Background(), g, "https://gitlab.com/owner/repo",
		"refs/heads/main@sha1:0123456789abcdef0123456789abcdef01234567",
		"apps/payments", nil)
	if rel.State != commitRelevanceUnknown {
		t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceUnknown, rel.Reason)
	}
	if rel.Reason == "" {
		t.Fatalf("unknown state must carry a reason")
	}
}

// TestClassifyCommitMalformedRevision exercises a revision that does not
// carry a SHA: the lookup degrades to "unknown" without making an HTTP call.
func TestClassifyCommitMalformedRevision(t *testing.T) {
	srv := newFakeCommitServer(t)
	g := srv.client()
	rel := classifyCommit(context.Background(), g, "https://github.com/owner/repo",
		"refs/heads/main", "apps/payments", nil)
	if rel.State != commitRelevanceUnknown {
		t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceUnknown, rel.Reason)
	}
	if srv.calls.Load() != 0 {
		t.Fatalf("expected no API calls for malformed revision, got %d", srv.calls.Load())
	}
}

// TestClassifyCommitCrossRepo is the regression test for the re-grooming
// finding: the workload's GitRepository points at a DIFFERENT GitHub repo
// than the configured GITHUB_REPO the client was built against. The commit
// must be fetched from the parsed source repo (reusing the client's token)
// and classified normally — not degraded to "unknown" because it is not
// the issue-tracking repo. The fake server keys the payload on the
// source repo, so a client that still queries the configured repo gets a
// 404 and the test fails.
func TestClassifyCommitCrossRepo(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	srv := newFakeCommitServer(t)
	// The commit lives in other-owner/other-repo, not in the configured
	// owner/repo the client was built against.
	srv.payloads["other-owner/other-repo/"+sha] = commitPayload{
		files: []map[string]string{
			{"filename": "apps/payments/deployment.yaml"},
		},
		message: "bump image",
	}
	g := srv.client()
	rel := classifyCommit(context.Background(), g, "https://github.com/other-owner/other-repo",
		"refs/heads/main@sha1:"+sha,
		"apps/payments", nil)
	if rel.State != commitRelevanceTouches {
		t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceTouches, rel.Reason)
	}
	if len(rel.MatchingPaths) != 1 || rel.MatchingPaths[0] != "apps/payments/deployment.yaml" {
		t.Fatalf("matching paths = %v, want [apps/payments/deployment.yaml]", rel.MatchingPaths)
	}
	if srv.calls.Load() == 0 {
		t.Fatalf("expected at least one API call against the source repo")
	}
}

// TestClassifyCommitPaginatedFiles is the pagination regression: GitHub's
// commit endpoint is paginated (300 files/page) and a workload match can
// sit on a later page. Page 1 must be unrelated; the workload file lives
// on page 2. Following the Link rel="next" header is what turns this from
// a false "does not touch" into a correct "touches".
func TestClassifyCommitPaginatedFiles(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	srv := newFakeCommitServer(t)
	nextURL := srv.srv.URL + "/repos/owner/repo/commits/" + sha + "?per_page=300&page=2"
	srv.payloads[sha] = commitPayload{
		// Page 1: only an unrelated file, and a Link header pointing at
		// page 2. If the client reads a single page, the workload match is
		// never seen and the state would wrongly be "does not touch".
		files: []map[string]string{
			{"filename": "unrelated/one.yaml"},
		},
		message: "mass rename",
		links:   `<` + nextURL + `>; rel="next", <` + nextURL + `>; rel="last"`,
	}
	// Page 2: the workload file, and no next link so pagination stops.
	srv.pageOverrides[sha+"/2"] = commitPayload{
		files:   []map[string]string{{"filename": "apps/payments/kustomization.yaml"}},
		message: "mass rename",
	}
	g := srv.client()
	rel := classifyCommit(context.Background(), g, "https://github.com/owner/repo",
		"refs/heads/main@sha1:"+sha,
		"apps/payments", nil)
	if rel.State != commitRelevanceTouches {
		t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceTouches, rel.Reason)
	}
	if len(rel.MatchingPaths) != 1 || rel.MatchingPaths[0] != "apps/payments/kustomization.yaml" {
		t.Fatalf("matching paths = %v, want the page-2 workload file", rel.MatchingPaths)
	}
	if srv.calls.Load() < 2 {
		t.Fatalf("expected the client to follow pagination (>=2 API calls), got %d", srv.calls.Load())
	}
}

// TestClassifyCommitAPIFailure covers the GitHub API failure mode: a 500
// or 404 response degrades to "unknown" without panicking. The error is
// surfaced in the Reason so an operator inspecting the digest can see we
// tried.
func TestClassifyCommitAPIFailure(t *testing.T) {
	srv := newFakeCommitServer(t)
	srv.status["0123456789abcdef0123456789abcdef01234567"] = http.StatusInternalServerError
	g := srv.client()
	rel := classifyCommit(context.Background(), g, "https://github.com/owner/repo",
		"refs/heads/main@sha1:0123456789abcdef0123456789abcdef01234567",
		"apps/payments", nil)
	if rel.State != commitRelevanceUnknown {
		t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceUnknown, rel.Reason)
	}
	if rel.Reason == "" {
		t.Fatalf("unknown state must carry a reason")
	}
	if srv.calls.Load() == 0 {
		t.Fatalf("expected at least one API call before degrading")
	}
}

// TestClassifyCommitPrivateRepo exercises the private-repo / 404 path: a
// 404 from the API must not be confused with a clean "does not touch".
func TestClassifyCommitPrivateRepo(t *testing.T) {
	srv := newFakeCommitServer(t)
	// 404 with no payload registered; the fake server already returns 404
	// for unknown SHAs.
	g := srv.client()
	rel := classifyCommit(context.Background(), g, "https://github.com/owner/repo",
		"refs/heads/main@sha1:0123456789abcdef0123456789abcdef01234567",
		"apps/payments", nil)
	if rel.State != commitRelevanceUnknown {
		t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceUnknown, rel.Reason)
	}
	if rel.Reason == "" {
		t.Fatalf("unknown state must carry a reason")
	}
}

// TestClassifyCommitNoGitHubClient verifies that classifyCommit is a clean
// no-op when GITHUB_REPO / GITHUB_TOKEN are unset: no panic, no error,
// just a degraded result.
func TestClassifyCommitNoGitHubClient(t *testing.T) {
	rel := classifyCommit(context.Background(), nil, "https://github.com/owner/repo",
		"refs/heads/main@sha1:0123456789abcdef0123456789abcdef01234567",
		"apps/payments", nil)
	if rel.State != commitRelevanceUnknown {
		t.Fatalf("state = %q, want %q", rel.State, commitRelevanceUnknown)
	}
	if rel.Reason == "" {
		t.Fatalf("unknown state must carry a reason")
	}
}

// TestClassifyCommitNoWorkloadPath verifies a missing workload path
// degrades to "unknown" (we never know what to compare against).
func TestClassifyCommitNoWorkloadPath(t *testing.T) {
	srv := newFakeCommitServer(t)
	g := srv.client()
	rel := classifyCommit(context.Background(), g, "https://github.com/owner/repo",
		"refs/heads/main@sha1:0123456789abcdef0123456789abcdef01234567",
		"", nil)
	if rel.State != commitRelevanceUnknown {
		t.Fatalf("state = %q, want %q", rel.State, commitRelevanceUnknown)
	}
	if srv.calls.Load() != 0 {
		t.Fatalf("expected no API calls when workload path is empty, got %d", srv.calls.Load())
	}
}

// TestCleanRepoPathTraversal drops leading "../" segments so a forged
// Kustomization spec cannot smuggle a path escape through the workload field.
func TestCleanRepoPathTraversal(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"apps/payments", "apps/payments"},
		{"/apps/payments", "apps/payments"},
		{"apps/payments/", "apps/payments"},
		{"../etc/secrets", "etc/secrets"},
		{"./apps/./payments", "apps/payments"},
		{"", ""},
		// A null byte is not a path segment marker: it survives inside the
		// segment it is embedded in and the ".." is dropped as usual. The
		// result simply never matches a real changed file, and no traversal
		// is possible; this documents that behaviour.
		{"../\x00apps/payments", "\x00apps/payments"},
	}
	for _, c := range cases {
		if got := cleanRepoPath(c.in); got != c.want {
			t.Errorf("cleanRepoPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestResolveWorkloadPaths is the unit test for the component-path
// resolution the review required: each declared component is relative to the
// Kustomization's spec.path (the workload path), not to the repo root. A
// component like "../shared" under workload "apps/payments/prod" must
// resolve to "apps/payments/shared", and a component that escapes the repo
// root after resolution must be rejected (ok == false) so it cannot match
// changed files outside the workload's Git surface.
func TestResolveWorkloadPaths(t *testing.T) {
	cases := []struct {
		name       string
		workload   string
		components []string
		want       []string
		ok         bool
	}{
		{
			name:       "no components",
			workload:   "apps/payments/prod",
			components: nil,
			want:       []string{},
			ok:         true,
		},
		{
			name:       "sibling component via ../",
			workload:   "apps/payments/prod",
			components: []string{"../shared"},
			want:       []string{"apps/payments/shared"},
			ok:         true,
		},
		{
			name:       "multi-level ../ component",
			workload:   "apps/payments/prod",
			components: []string{"../../shared"},
			want:       []string{"apps/shared"},
			ok:         true,
		},
		{
			name:       "component at the workload path itself",
			workload:   "apps/payments",
			components: []string{".."},
			want:       []string{"apps"},
			ok:         true,
		},
		{
			name:       "nested relative component",
			workload:   "apps/payments",
			components: []string{"deploy/prod"},
			want:       []string{"deploy/prod"},
			ok:         true,
		},
		{
			name:     "escaping component is rejected",
			workload: "apps/payments/prod",
			// Four ".." from a three-level-deep workload pops above the repo
			// root; three would land exactly on it ("secrets"), which is a
			// legitimate in-repo path, not an escape.
			components: []string{"../../../../secrets"},
			want:       nil,
			ok:         false,
		},
		{
			name:       "empty workload is rejected",
			workload:   "",
			components: []string{".."},
			want:       nil,
			ok:         false,
		},
		{
			name: "null byte in component does not traverse",
			// The ".." segment is a real traversal (it is exactly ".."); the
			// null byte sits in the FOLLOWING segment, so it rides along
			// verbatim when the component is resolved against the workload
			// path. The embedded null byte can neither pop an extra level nor
			// hide a segment, so it stays inert and the result cannot match a
			// real changed file.
			workload:   "apps/payments/prod",
			components: []string{"../\x00shared"},
			want:       []string{"apps/payments/\x00shared"},
			ok:         true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := resolveWorkloadPaths(c.workload, c.components)
			if ok != c.ok {
				t.Fatalf("resolveWorkloadPaths(%q, %v) ok = %v, want %v", c.workload, c.components, ok, c.ok)
			}
			if !ok {
				return
			}
			if len(got) != len(c.want) {
				t.Fatalf("resolveWorkloadPaths(%q, %v) = %v, want %v", c.workload, c.components, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("resolveWorkloadPaths(%q, %v)[%d] = %q, want %q", c.workload, c.components, i, got[i], c.want[i])
				}
			}
		})
	}
}
