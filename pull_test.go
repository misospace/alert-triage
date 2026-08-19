package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- path / branch helpers ---

func TestPathAllowedDirectAndNested(t *testing.T) {
	allow := []string{"deploy/", "apps/myapp/values.yaml"}
	cases := []struct {
		path string
		want bool
	}{
		{"deploy/foo.yaml", true},
		{"deploy/nested/bar.yaml", true},
		{"apps/myapp/values.yaml", true},
		{"apps/myapp/values.yaml.bak", false},
		{"deploy-other/x.yaml", false},
		{"README.md", false},
		{"../escape.yaml", false},
		{"/abs/path.yaml", false},
	}
	for _, c := range cases {
		if got := pathAllowed(c.path, allow); got != c.want {
			t.Errorf("pathAllowed(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestPathAllowedWildcardIsNotWritable(t *testing.T) {
	// A '.' root must not authorise arbitrary paths: the allowlist bounds the
	// writable set, it does not widen it to the whole repo (or outside of it).
	if pathAllowed("deploy/web.yaml", []string{"."}) {
		t.Errorf("'.' root must not authorise an arbitrary path")
	}
	if pathAllowed("anything/else.yaml", []string{"deploy/", "."}) {
		t.Errorf("'.' must not authorise a path outside the named roots")
	}
	if allowlistIsWildcard([]string{"deploy/"}) {
		t.Errorf("a plain allowlist must not be flagged as a wildcard")
	}
	for _, allow := range [][]string{{"."}, {"deploy/", "."}, {"deploy/", "a/.."}, {"."}} {
		if !allowlistIsWildcard(allow) {
			t.Errorf("allowlist %v should be flagged as a wildcard", allow)
		}
	}
}

func TestExtractPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"raise memory limit in clusters/prod/apps/myapp.yaml", "clusters/prod/apps/myapp.yaml"},
		{"fix `apps/foo/values.yaml`", "apps/foo/values.yaml"},
		{"no file mentioned", ""},
		{"see https://example.com/path/to/file.yaml", ""},
		{"see http://example.com/a.yaml", ""},
		{"../escape.yaml is bad", ""},
		{"/etc/passwd style", ""},
	}
	for _, c := range cases {
		if got := extractPath(c.in); got != c.want {
			t.Errorf("extractPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBranchSlug(t *testing.T) {
	got := branchSlug("KubePodNotReady:default:myapp")
	if !strings.HasPrefix(got, "KubePodNotReady") {
		t.Errorf("unexpected slug: %q", got)
	}
	if strings.Contains(got, ":") {
		t.Errorf("slug should not contain ':' (ref-format forbids): %q", got)
	}
	if got := branchSlug(""); got == "" {
		t.Errorf("branch slug should never be empty")
	}
	if got := branchSlug("alert-triage/../.."); strings.Contains(got, "/") {
		t.Errorf("slug must not contain slashes: %q", got)
	}
}

// --- applyDiff ---

const patchableManifest = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: api
          image: ghcr.io/example/api:1.2.3
          resources:
            limits:
              cpu: 250m
              memory: 64Mi
            requests:
              cpu: 100m
              memory: 64Mi
`

func TestApplyDiffRoundTrip(t *testing.T) {
	triage := Triage{FixLocation: "git", Confidence: "high"}
	diff := Propose(triage, "deploy/web.yaml", patchableManifest)
	if diff == "" {
		t.Fatalf("expected a diff from Propose")
	}

	patched, ok := applyDiff(patchableManifest, diff)
	if !ok {
		t.Fatalf("applyDiff failed on a valid Propose diff:\n%s", diff)
	}
	if !strings.Contains(patched, "memory: 128Mi") {
		t.Errorf("patched content did not raise the memory limit:\n%s", patched)
	}
	if strings.Contains(patched, "memory: 64Mi\n") {
		// The api container's limit was the only 64Mi target; its requests
		// block also holds 64Mi and must not be touched by this diff.
		if strings.Contains(patched, "cpu: 250m\n              memory: 128Mi") {
			t.Log("ok: api limit raised, requests block unchanged")
		} else {
			t.Errorf("patched content unexpectedly still holds a 64Mi memory limit:\n%s", patched)
		}
	}
}

func TestApplyDiffRejectsGarbage(t *testing.T) {
	if _, ok := applyDiff("x", "not a patch"); ok {
		t.Errorf("garbage patch should fail closed")
	}
	if _, ok := applyDiff("x", "--- a/y\n+++ b/y\n"); ok {
		t.Errorf("missing hunk should fail closed")
	}
	if _, ok := applyDiff("x", "--- a/y\n+++ b/y\n@@ -1,1 +1,1 @@\n-nope\n+yes"); ok {
		t.Errorf("patch with a bogus removal line should fail closed")
	}
	if _, ok := applyDiff("x", "--- a/y\n+++ b/y\n@@ -1,1 +1 @@\n-x\n+y"); ok {
		t.Errorf("malformed hunk counts should fail closed")
	}
}

func TestApplyDiffRejectsStalePatch(t *testing.T) {
	// The removal lines describe a file state that no longer matches the
	// authoritative content: applying it must fail closed rather than corrupt.
	diff := "--- a/deploy/web.yaml\n+++ b/deploy/web.yaml\n@@ -6,3 +6,3 @@\n-          image: ghcr.io/example/OLD:1.0\n+          image: ghcr.io/example/NEW:2.0\n          cpu: 250m\n          memory: 64Mi\n"
	if _, ok := applyDiff(patchableManifest, diff); ok {
		t.Errorf("stale diff whose removal lines don't match should be rejected")
	}
}

func TestPRMarkerMatchesIssueMarker(t *testing.T) {
	if prMarker != signatureMarker {
		t.Fatalf("PR and issue dedup markers diverged: %q vs %q", prMarker, signatureMarker)
	}
}

// --- loadPRConfig ---

func TestLoadPRConfigRequiresOptIn(t *testing.T) {
	t.Setenv("GITHUB_PR_OPT_IN", "")
	t.Setenv("GITHUB_TOKEN", "t")
	t.Setenv("GITHUB_REPO", "o/r")
	t.Setenv("GITHUB_PR_PATH_ALLOWLIST", "deploy/")
	if cfg := loadPRConfig(); cfg != nil {
		t.Errorf("expected nil when opt-in unset, got %+v", cfg)
	}
}

func TestLoadPRConfigRequiresTokenAndRepo(t *testing.T) {
	t.Setenv("GITHUB_PR_OPT_IN", "true")
	t.Setenv("GITHUB_PR_PATH_ALLOWLIST", "deploy/")

	t.Setenv("GITHUB_TOKEN", "t")
	t.Setenv("GITHUB_REPO", "")
	if cfg := loadPRConfig(); cfg != nil {
		t.Errorf("expected nil when repo missing, got %+v", cfg)
	}

	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GITHUB_REPO", "o/r")
	if cfg := loadPRConfig(); cfg != nil {
		t.Errorf("expected nil when token missing, got %+v", cfg)
	}
}

func TestLoadPRConfigEmptyAllowlistReturnsNil(t *testing.T) {
	t.Setenv("GITHUB_PR_OPT_IN", "true")
	t.Setenv("GITHUB_TOKEN", "t")
	t.Setenv("GITHUB_REPO", "o/r")
	t.Setenv("GITHUB_PR_PATH_ALLOWLIST", "")
	if cfg := loadPRConfig(); cfg != nil {
		t.Errorf("expected nil when allowlist empty, got %+v", cfg)
	}
}

func TestLoadPRConfigParsesAllowlistAndCap(t *testing.T) {
	t.Setenv("GITHUB_PR_OPT_IN", "true")
	t.Setenv("GITHUB_TOKEN", "t")
	t.Setenv("GITHUB_REPO", "o/r")
	t.Setenv("GITHUB_PR_PATH_ALLOWLIST", "deploy/,   apps/foo/ ")
	t.Setenv("GITHUB_PR_DAILY_CAP", "3")
	cfg := loadPRConfig()
	if cfg == nil {
		t.Fatalf("expected config")
	}
	if cfg.DailyCap != 3 {
		t.Errorf("expected daily cap 3, got %d", cfg.DailyCap)
	}
	if len(cfg.Allowlist) != 2 || cfg.Allowlist[0] != "deploy/" || cfg.Allowlist[1] != "apps/foo/" {
		t.Errorf("unexpected allowlist: %#v", cfg.Allowlist)
	}
}

func TestLoadPRConfigRejectsWildcardAllowlist(t *testing.T) {
	t.Setenv("GITHUB_PR_OPT_IN", "true")
	t.Setenv("GITHUB_TOKEN", "t")
	t.Setenv("GITHUB_REPO", "o/r")
	// A '.' (bare or cleaning to it) would make every repo path writable; the
	// write arm must stay off rather than silently widen to the whole repo.
	for _, allow := range []string{".", "deploy/,. ", "deploy/,a/..", " . "} {
		t.Setenv("GITHUB_PR_PATH_ALLOWLIST", allow)
		if cfg := loadPRConfig(); cfg != nil {
			t.Errorf("allowlist %q must be rejected, got %+v", allow, cfg)
		}
	}
	// A normal allowlist still loads.
	t.Setenv("GITHUB_PR_PATH_ALLOWLIST", "deploy/")
	if cfg := loadPRConfig(); cfg == nil {
		t.Errorf("a plain allowlist must still load")
	}
}

func TestLoadPRConfigMalformedCapUsesDefault(t *testing.T) {
	t.Setenv("GITHUB_PR_OPT_IN", "true")
	t.Setenv("GITHUB_TOKEN", "t")
	t.Setenv("GITHUB_REPO", "o/r")
	t.Setenv("GITHUB_PR_PATH_ALLOWLIST", "deploy/")
	// Anything that is not a clean positive integer falls back to the
	// documented default rather than silently picking up a partial parse.
	for _, v := range []string{"abc", "3abc", "0", "-2", "1.5", ""} {
		t.Setenv("GITHUB_PR_DAILY_CAP", v)
		cfg := loadPRConfig()
		if cfg == nil {
			t.Fatalf("cap %q should still load a config", v)
		}
		if cfg.DailyCap != defaultPRDailyCap {
			t.Errorf("malformed cap %q: expected default %d, got %d", v, defaultPRDailyCap, cfg.DailyCap)
		}
	}
}

func TestSplitCSV(t *testing.T) {
	if got := splitCSV(""); got != nil {
		t.Errorf("splitCSV(\"\") = %v, want nil", got)
	}
	if got := splitCSV("a, b ,"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("splitCSV: %v", got)
	}
}

func TestPREligible(t *testing.T) {
	if !prEligible(Triage{FixLocation: "git", Confidence: "high"}) {
		t.Errorf("git+high should be PR-eligible")
	}
	if prEligible(Triage{FixLocation: "partial", Confidence: "high"}) {
		t.Errorf("partial must not be PR-eligible (proposal-only)")
	}
	if prEligible(Triage{FixLocation: "git", Confidence: "low"}) {
		t.Errorf("low confidence must not be PR-eligible")
	}
}

// --- daily cap ---

func TestReserveAllowanceCapsAndRollsDay(t *testing.T) {
	c := &PRConfig{DailyCap: 2}
	day := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	if !c.reserveAllowance(day) {
		t.Fatalf("first slot should be granted")
	}
	if !c.reserveAllowance(day) {
		t.Fatalf("second slot should be granted")
	}
	if c.reserveAllowance(day) {
		t.Fatalf("third slot must be denied")
	}
	// Next calendar day rolls the budget over.
	next := day.Add(24 * time.Hour)
	if !c.reserveAllowance(next) {
		t.Fatalf("budget should roll over on a new day")
	}
}

func TestRefundAllowanceFreesASlot(t *testing.T) {
	c := &PRConfig{DailyCap: 1}
	day := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	if !c.reserveAllowance(day) {
		t.Fatalf("first slot should be granted")
	}
	if c.reserveAllowance(day) {
		t.Fatalf("second slot must be denied while the first is reserved")
	}
	// The reserved write failed: refund, and the slot is reservable again.
	c.refundAllowance(day)
	if !c.reserveAllowance(day) {
		t.Fatalf("refunded slot should be reservable again")
	}
}

func TestRefundAllowanceDoesNotLeakAcrossDay(t *testing.T) {
	c := &PRConfig{DailyCap: 1}
	day := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	if !c.reserveAllowance(day) {
		t.Fatalf("first slot should be granted")
	}
	// Another call rolls the window forward; the old day's slot is reset away.
	if !c.reserveAllowance(day.Add(24 * time.Hour)) {
		t.Fatalf("new day should grant a slot")
	}
	// A refund timestamped in the old day must not free today's budget.
	c.refundAllowance(day)
	if c.reserveAllowance(day.Add(24 * time.Hour)) {
		t.Fatalf("an old-day refund must not free a new-day slot")
	}
}

// --- GitHub PR API against a fake server ---

type fakeGH struct {
	t          *testing.T
	srv        *httptest.Server
	existing   *ghPR
	failStatus int // when > 0, respond with this status to mutating/list calls

	mu       sync.Mutex
	prBody   string
	putBody  map[string]string
	puts     int
	prCalls  int
	comments int
	putFile  string
}

func newFakeGH(t *testing.T, existing *ghPR, failStatus int) *fakeGH {
	f := &fakeGH{t: t, existing: existing, failStatus: failStatus}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGH) handle(w http.ResponseWriter, r *http.Request) {
	if f.failStatus > 0 {
		w.WriteHeader(f.failStatus)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r":
		_ = json.NewEncoder(w).Encode(map[string]string{"default_branch": "main"})
	case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/git/ref/heads/main":
		_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "headsha123"}})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/"):
		_ = json.NewEncoder(w).Encode(map[string]string{
			"content":  base64.StdEncoding.EncodeToString([]byte(patchableManifest)),
			"sha":      "blobsha123",
			"encoding": "base64",
		})
	case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/pulls":
		if f.existing != nil {
			_ = json.NewEncoder(w).Encode([]ghPR{*f.existing})
			return
		}
		_ = json.NewEncoder(w).Encode([]ghPR{})
	case r.Method == http.MethodPost && r.URL.Path == "/repos/o/r/pulls":
		f.mu.Lock()
		f.prCalls++
		var payload map[string]string
		_ = json.NewDecoder(r.Body).Decode(&payload)
		f.prBody = payload["body"]
		_ = payload
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(ghPR{Number: 7, HTMLURL: "https://pr/7", State: "open"})
	case r.Method == http.MethodPost && r.URL.Path == "/repos/o/r/git/refs":
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/"):
		f.mu.Lock()
		f.puts++
		f.putFile = strings.TrimPrefix(r.URL.Path, "/repos/o/r/contents/")
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.putBody = payload
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/comments"):
		f.mu.Lock()
		f.comments++
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	default:
		f.t.Logf("fakeGH: unhandled %s %s", r.Method, r.URL.String())
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeGH) client() *gitHubClient {
	return &gitHubClient{token: "t", repo: "o/r", hc: &http.Client{}, apiURL: f.srv.URL}
}

func triageReport() Report {
	return Report{
		Group: Group{
			Cluster: "default",
			Alerts:  []Alert{{Labels: map[string]string{"alertname": "XPodCrash", "severity": "warning"}}},
		},
		Triage:     Triage{FixLocation: "git", Confidence: "high", WhatToChange: "raise memory limit in deploy/web.yaml", Narrative: "The api container is being OOM-killed."},
		Narrative:  "The api container is being OOM-killed.",
		PriorSeen:  2,
		Enrichment: Enrichment{Nodes: []string{"node1 Ready"}, Scope: "deploy/web.yaml"},
	}
}

func prCfg() *PRConfig {
	return &PRConfig{OptIn: true, Allowlist: []string{"deploy/"}, DailyCap: 10}
}

func TestDeliverPullCreatesNewPR(t *testing.T) {
	f := newFakeGH(t, nil, 0)
	cfg := prCfg()
	cfg.PublicURL = "https://triage.example.com"

	r := triageReport()
	act, err := deliverPull(context.Background(), f.client(), cfg, r)
	if err != nil {
		t.Fatalf("deliverPull: %v", err)
	}
	if act.Outcome != "created" {
		t.Fatalf("expected created, got %s", act.Outcome)
	}
	if !strings.HasPrefix(act.Branch, "alert-triage/") {
		t.Errorf("branch should be namespaced, got %q", act.Branch)
	}
	if f.prCalls != 1 {
		t.Errorf("expected 1 PR create, got %d", f.prCalls)
	}
	if f.puts != 1 {
		t.Fatalf("expected 1 file PUT, got %d", f.puts)
	}

	// The committed content must be the patched full file (memory raised),
	// with a blob-SHA precondition — not a slice of model text.
	f.mu.Lock()
	put := f.putBody["content"]
	sha := f.putBody["sha"]
	putFile := f.putFile
	prBody := f.prBody
	f.mu.Unlock()

	raw, err := base64.StdEncoding.DecodeString(put)
	if err != nil {
		t.Fatalf("committed content was not valid base64: %v", err)
	}
	if !strings.Contains(string(raw), "memory: 128Mi") {
		t.Errorf("committed content did not raise the memory limit:\n%s", raw)
	}
	if sha != "blobsha123" {
		t.Errorf("PUT must carry the blob SHA precondition, got %q", sha)
	}
	if putFile != "deploy/web.yaml" {
		t.Errorf("PUT wrote to wrong path %q", putFile)
	}

	// Body fields: narrative, evidence, proposed diff, digest link.
	for _, want := range []string{
		fmt.Sprintf(prMarker, r.Group.Signature()),
		"The api container is being OOM-killed.",
		"**What to change**",
		"**Proposed diff**",
		"```diff",
		"<summary>Evidence</summary>",
		"Cluster: default",
		"**Digest:** https://triage.example.com/recent",
	} {
		if !strings.Contains(prBody, want) {
			t.Errorf("PR body missing %q:\n%s", want, prBody)
		}
	}
}

func TestDeliverPullRecurrenceUpdatesNotDuplicates(t *testing.T) {
	existing := &ghPR{
		Number:  11,
		State:   "open",
		HTMLURL: "https://pr/11",
		Body:    "some body " + fmt.Sprintf(prMarker, triageReport().Group.Signature()),
	}
	existing.Head.Ref = "alert-triage/abc"
	f := newFakeGH(t, existing, 0)

	r := triageReport()
	act, err := deliverPull(context.Background(), f.client(), prCfg(), r)
	if err != nil {
		t.Fatalf("deliverPull: %v", err)
	}
	if act.Outcome != "updated" {
		t.Fatalf("expected updated, got %s", act.Outcome)
	}
	if f.prCalls != 0 {
		t.Errorf("recurrence must not open a new PR, got %d create calls", f.prCalls)
	}
	if f.puts != 0 {
		t.Errorf("recurrence must not commit a file, got %d PUTs", f.puts)
	}
	if f.comments != 1 {
		t.Errorf("expected 1 re-fire comment, got %d", f.comments)
	}
}

func TestDeliverPullHonoursDailyCap(t *testing.T) {
	f := newFakeGH(t, nil, 0)
	cfg := prCfg()
	cfg.DailyCap = 1
	// Exhaust today's budget.
	cfg.reserveAllowance(time.Now())

	act, err := deliverPull(context.Background(), f.client(), cfg, triageReport())
	if err != nil {
		t.Fatalf("deliverPull: %v", err)
	}
	if act.Outcome != "capped" {
		t.Fatalf("expected capped, got %s", act.Outcome)
	}
	if f.prCalls != 0 {
		t.Errorf("capped must not open a PR, got %d", f.prCalls)
	}
	if f.puts != 0 {
		t.Errorf("capped must not commit, got %d PUTs", f.puts)
	}
}

func TestDeliverPullRevokedTokenDegrades(t *testing.T) {
	// 401 behaves exactly like a revoked/removed token: an error surfaces for
	// the caller to log, and no write happened. The digest path swallows it.
	f := newFakeGH(t, nil, http.StatusUnauthorized)
	act, err := deliverPull(context.Background(), f.client(), prCfg(), triageReport())
	if err == nil {
		t.Fatalf("expected an error on 401, got outcome %s", act.Outcome)
	}
	if f.puts != 0 || f.prCalls != 0 {
		t.Errorf("a 401 must not write anything: puts=%d prs=%d", f.puts, f.prCalls)
	}
}

func TestDeliverPullServerFailureDegrades(t *testing.T) {
	f := newFakeGH(t, nil, http.StatusInternalServerError)
	if _, err := deliverPull(context.Background(), f.client(), prCfg(), triageReport()); err == nil {
		t.Fatalf("expected an error on 500")
	}
}

func TestDeliverPullOffWhenConfigNil(t *testing.T) {
	gh := newFakeGH(t, nil, 0).client()
	act, err := deliverPull(context.Background(), gh, nil, triageReport())
	if err != nil {
		t.Fatalf("deliverPull: %v", err)
	}
	if act.Outcome != "off" {
		t.Errorf("expected off when cfg nil, got %s", act.Outcome)
	}
}

func TestDeliverPullSkipsOnGates(t *testing.T) {
	cases := []struct {
		name string
		cfg  *PRConfig
		r    Report
	}{
		{"low confidence", prCfg(), func() Report { r := triageReport(); r.Triage.Confidence = "low"; return r }()},
		{"partial location", prCfg(), func() Report { r := triageReport(); r.Triage.FixLocation = "partial"; return r }()},
		{"no path", prCfg(), func() Report { r := triageReport(); r.Triage.WhatToChange = "no file path here"; return r }()},
		{"path not allowlisted", prCfg(), func() Report { r := triageReport(); r.Triage.WhatToChange = "fix apps/other.yaml"; return r }()},
		{"path escapes allowlist", &PRConfig{OptIn: true, Allowlist: []string{"deploy/"}, DailyCap: 10}, func() Report { r := triageReport(); r.Triage.WhatToChange = "fix ../deploy/web.yaml"; return r }()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeGH(t, nil, 0)
			act, err := deliverPull(context.Background(), f.client(), c.cfg, c.r)
			if err != nil {
				t.Fatalf("deliverPull: %v", err)
			}
			if act.Outcome != "skipped" {
				t.Errorf("expected skipped, got %s", act.Outcome)
			}
			if f.prCalls != 0 || f.puts != 0 {
				t.Errorf("gate skip must not write: prs=%d puts=%d", f.prCalls, f.puts)
			}
		})
	}
}

func TestDeliverPullSkipsWhenProposeRefuses(t *testing.T) {
	// Serve a manifest Propose cannot patch (no memory field); the PR arm
	// must skip rather than write a bogus diff.
	f := newFakeGH(t, nil, 0)
	r := triageReport()
	r.Triage.WhatToChange = "deploy/empty.yaml"

	origHandler := f.srv.Config.Handler
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, "/repos/o/r/contents/") {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"content":  base64.StdEncoding.EncodeToString([]byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n")),
				"sha":      "blobsha1",
				"encoding": "base64",
			})
			return
		}
		origHandler.ServeHTTP(w, req)
	})

	act, err := deliverPull(context.Background(), f.client(), prCfg(), r)
	if err != nil {
		t.Fatalf("deliverPull: %v", err)
	}
	if act.Outcome != "skipped" {
		t.Errorf("expected skipped when Propose refuses, got %s", act.Outcome)
	}
	if f.prCalls != 0 || f.puts != 0 {
		t.Errorf("Propose refusal must not write: prs=%d puts=%d", f.prCalls, f.puts)
	}
}

func TestDeliverPullRefundsAllowanceOnOpenFailure(t *testing.T) {
	// Only the final create-PR call fails; list/read and the earlier branch/
	// file writes succeed. The reserved daily slot must be refunded so a retry
	// is not left capped by an attempt that opened nothing.
	f := newFakeGH(t, nil, 0)
	origHandler := f.srv.Config.Handler
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost && req.URL.Path == "/repos/o/r/pulls" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		origHandler.ServeHTTP(w, req)
	})
	cfg := prCfg()
	cfg.DailyCap = 1

	if _, err := deliverPull(context.Background(), f.client(), cfg, triageReport()); err == nil {
		t.Fatalf("expected an error when create-PR fails")
	}
	// Restore the healthy handler: a retry must be allowed, not capped.
	f.srv.Config.Handler = origHandler
	act, err := deliverPull(context.Background(), f.client(), cfg, triageReport())
	if err != nil {
		t.Fatalf("retry deliverPull: %v", err)
	}
	if act.Outcome != "created" {
		t.Fatalf("expected created after a refund, got %s", act.Outcome)
	}
}

func TestDeliverPullCapRolloverUsesInjectedClock(t *testing.T) {
	// Drive the daily window end-to-end through the injected clock, so the
	// timeNow seam is proven to be consulted by the create path (not just the
	// unit-level reserve/refund helpers).
	f := newFakeGH(t, nil, 0)
	cfg := prCfg()
	cfg.DailyCap = 1

	orig := timeNow
	defer func() { timeNow = orig }()
	dayA := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	timeNow = func() time.Time { return dayA }

	if act, err := deliverPull(context.Background(), f.client(), cfg, triageReport()); err != nil || act.Outcome != "created" {
		t.Fatalf("expected created on day A, got %s (%v)", act.Outcome, err)
	}
	if act, err := deliverPull(context.Background(), f.client(), cfg, triageReport()); err != nil || act.Outcome != "capped" {
		t.Fatalf("expected capped on day A, got %s (%v)", act.Outcome, err)
	}
	timeNow = func() time.Time { return dayA.Add(24 * time.Hour) }
	if act, err := deliverPull(context.Background(), f.client(), cfg, triageReport()); err != nil || act.Outcome != "created" {
		t.Fatalf("expected created after day rollover, got %s (%v)", act.Outcome, err)
	}
}

func TestFindOpenPRPaginatesPastFirstPage(t *testing.T) {
	// A recurrence must be found even past page 1, or a re-fire would open a
	// duplicate once the repo outgrows 100 open PRs.
	sig := triageReport().Group.Signature()
	marker := fmt.Sprintf(prMarker, sig)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/repos/o/r/pulls" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.URL.Query().Get("page") {
		case "1":
			w.Header().Set("Link", `<https://api.github.com/repos/o/r/pulls?per_page=100&page=2&state=open>; rel="next"`)
			_ = json.NewEncoder(w).Encode([]ghPR{{Number: 1, State: "open", Body: "unrelated PR"}})
		case "2":
			_ = json.NewEncoder(w).Encode([]ghPR{{Number: 2, State: "open", Body: "hit " + marker}})
		default:
			_ = json.NewEncoder(w).Encode([]ghPR{})
		}
	}))
	t.Cleanup(srv.Close)
	gh := &gitHubClient{token: "t", repo: "o/r", hc: &http.Client{}, apiURL: srv.URL}

	got, err := gh.findOpenPR(context.Background(), sig)
	if err != nil {
		t.Fatalf("findOpenPR: %v", err)
	}
	if got == nil || got.Number != 2 {
		t.Fatalf("expected the marker PR on page 2, got %+v", got)
	}
}

// --- idempotent recovery against partial writes ---

// fakeRepoServer is a stateful fake of the few GitHub endpoints the PR arm
// uses. Unlike the stateless fakeGH above (whose contents GET always serves
// the manifest), it tracks real per-branch file state and ref existence so the
// recovery tests can simulate partial writes — a branch created but no PR — and
// verify a retry adopts the branch without corrupting it.
type branchState struct {
	content string
	sha     string
}

type fakeRepoServer struct {
	srv           *httptest.Server
	defaultHead   string
	defaultFile   string
	defaultSha    string
	defaultBranch string
	branches      map[string]branchState // topic branch name → file state
	failCreatePR  bool
	nextBlob      int

	mu         sync.Mutex
	prCount    int
	putCount   int
	lastPutSha string
}

func newFakeRepo(t *testing.T, defaultFile string) *fakeRepoServer {
	f := &fakeRepoServer{
		defaultHead:   "headsha123",
		defaultFile:   defaultFile,
		defaultSha:    "defaultblob123",
		defaultBranch: "main",
		branches:      map[string]branchState{},
		nextBlob:      1,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRepoServer) client() *gitHubClient {
	return &gitHubClient{token: "t", repo: "o/r", hc: &http.Client{}, apiURL: f.srv.URL}
}

func (f *fakeRepoServer) branchContent(branch string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.branches[branch].content
}

func (f *fakeRepoServer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r":
		_ = json.NewEncoder(w).Encode(map[string]string{"default_branch": f.defaultBranch})
	case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/git/ref/heads/"+f.defaultBranch:
		_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": f.defaultHead}})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/o/r/git/ref/heads/"):
		branch := strings.TrimPrefix(r.URL.Path, "/repos/o/r/git/ref/heads/")
		if _, ok := f.branches[branch]; ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "somecommitsha"}})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/"):
		ref := r.URL.Query().Get("ref")
		var content, sha string
		switch {
		case ref == f.defaultBranch || ref == f.defaultHead:
			content, sha = f.defaultFile, f.defaultSha
		default:
			b, ok := f.branches[ref]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			content, sha = b.content, b.sha
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"content":  base64.StdEncoding.EncodeToString([]byte(content)),
			"sha":      sha,
			"encoding": "base64",
		})
	case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/pulls":
		_ = json.NewEncoder(w).Encode([]ghPR{})
	case r.Method == http.MethodPost && r.URL.Path == "/repos/o/r/git/refs":
		var payload map[string]string
		_ = json.NewDecoder(r.Body).Decode(&payload)
		branch := strings.TrimPrefix(payload["ref"], "refs/heads/")
		if _, ok := f.branches[branch]; ok {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		// A new branch is cut at the default HEAD, so it carries the default
		// file and blob SHA — exactly what GitHub returns for a fresh ref.
		f.branches[branch] = branchState{content: f.defaultFile, sha: f.defaultSha}
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/"):
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		b, ok := f.branches[payload["branch"]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if payload["sha"] != b.sha {
			w.WriteHeader(http.StatusConflict)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(payload["content"])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		newSHA := fmt.Sprintf("blob%d", f.nextBlob)
		f.nextBlob++
		f.branches[payload["branch"]] = branchState{content: string(raw), sha: newSHA}
		f.putCount++
		f.lastPutSha = payload["sha"]
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodPost && r.URL.Path == "/repos/o/r/pulls":
		if f.failCreatePR {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		f.prCount++
		w.WriteHeader(http.StatusCreated)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// patchedManifest is what a clean run would commit for patchableManifest: the
// validated Propose diff applied to the authoritative original.
func patchedManifest(t *testing.T) string {
	t.Helper()
	diff := Propose(triageReport().Triage, "deploy/web.yaml", patchableManifest)
	if diff == "" {
		t.Fatalf("expected Propose to yield a diff for patchableManifest")
	}
	patched, ok := applyDiff(patchableManifest, diff)
	if !ok {
		t.Fatalf("expected applyDiff to succeed:\n%s", diff)
	}
	return patched
}

func TestDeliverPullRecoversFromPRCreateFailure(t *testing.T) {
	// First run: the branch is created and the file committed, but the final
	// create-PR call fails — an orphan branch with our validated content is
	// left behind. A retry must adopt that branch (422 create → confirm → skip
	// the already-exact PUT) and open the PR, without corrupting it or opening
	// a second branch.
	f := newFakeRepo(t, patchableManifest)
	f.failCreatePR = true
	cfg := prCfg()
	gh := f.client()
	r := triageReport()

	if _, err := deliverPull(context.Background(), gh, cfg, r); err == nil {
		t.Fatalf("expected an error when create-PR fails")
	}
	branch := "alert-triage/" + branchSlug(r.Group.Signature())
	if got := f.branchContent(branch); got != patchedManifest(t) {
		t.Fatalf("run 1 should have committed the patched content, got:\n%s", got)
	}

	// Second run: the write arm heals and the PR ships.
	f.failCreatePR = false
	act, err := deliverPull(context.Background(), gh, cfg, r)
	if err != nil {
		t.Fatalf("retry deliverPull: %v", err)
	}
	if act.Outcome != "created" {
		t.Fatalf("expected created on retry, got %s", act.Outcome)
	}
	if f.prCount != 1 {
		t.Errorf("expected exactly one PR after two runs, got %d", f.prCount)
	}
	// The retry must not have re-committed: run 1 did the single PUT, run 2
	// recognised the content as already exact and skipped it.
	if f.putCount != 1 {
		t.Errorf("expected 1 PUT total (first run only), got %d", f.putCount)
	}
	if got := f.branchContent(branch); got != patchedManifest(t) {
		t.Errorf("retry corrupted the branch content:\n%s", got)
	}
}

func TestDeliverPullAdoptsBranchMissingOnlyPR(t *testing.T) {
	// Branch creation 422 recovery with a branch that still carries the
	// *original* content (a previous run created the branch but failed before
	// the file PUT). The branch is adopted and the validated patched content
	// committed using the branch's own current blob SHA, then the PR opens.
	f := newFakeRepo(t, patchableManifest)
	gh := f.client()
	r := triageReport()
	branch := "alert-triage/" + branchSlug(r.Group.Signature())
	f.mu.Lock()
	f.branches[branch] = branchState{content: patchableManifest, sha: "defaultblob123"}
	f.mu.Unlock()

	act, err := deliverPull(context.Background(), gh, prCfg(), r)
	if err != nil {
		t.Fatalf("deliverPull: %v", err)
	}
	if act.Outcome != "created" {
		t.Fatalf("expected created, got %s", act.Outcome)
	}
	if f.prCount != 1 {
		t.Errorf("expected one PR, got %d", f.prCount)
	}
	if f.branchContent(branch) != patchedManifest(t) {
		t.Errorf("branch was not advanced to the patched content:\n%s", f.branchContent(branch))
	}
	if f.putCount != 1 {
		t.Errorf("expected a single commit PUT on adoption, got %d", f.putCount)
	}
	// The commit must have used the branch's current blob SHA as the
	// precondition, not a stale/default one.
	if f.lastPutSha != "defaultblob123" {
		t.Errorf("expected the branch's current blob SHA as the PUT precondition, got %q", f.lastPutSha)
	}
}

func TestDeliverPullFailsClosedOnUnexpectedBranchContent(t *testing.T) {
	// The deterministic branch exists but carries content that is neither the
	// authoritative original nor our validated patch (e.g. someone edited it,
	// or a stale run wrote different content). The write arm must fail closed:
	// never overwrite, never open a PR on top of it.
	f := newFakeRepo(t, patchableManifest)
	gh := f.client()
	r := triageReport()
	branch := "alert-triage/" + branchSlug(r.Group.Signature())
	unexpected := "kind: Deployment\nmetadata:\n  name: someone-else\n"
	f.mu.Lock()
	f.branches[branch] = branchState{content: unexpected, sha: "weirdsha"}
	f.mu.Unlock()

	if _, err := deliverPull(context.Background(), gh, prCfg(), r); err == nil {
		t.Fatalf("expected a fail-closed error on unexpected branch content")
	} else if !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Errorf("expected a 'refusing to overwrite' error, got: %v", err)
	}
	if f.prCount != 0 {
		t.Errorf("unexpected branch content must not open a PR, got %d", f.prCount)
	}
	if f.putCount != 0 {
		t.Errorf("unexpected branch content must never be overwritten, got %d PUTs", f.putCount)
	}
	if f.branchContent(branch) != unexpected {
		t.Errorf("unexpected branch content was modified:\n%s", f.branchContent(branch))
	}
}
