package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
		{"deploy/web\x00.yaml", false},
		{"deploy/\x00web.yaml", false},
		{"\x00deploy/web.yaml", false},
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
	if pathAllowed("deploy/web.yaml", []string{"deploy/\x00"}) {
		t.Errorf("a NUL-bearing allowlist root must not authorise a path")
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
		{"fix deploy/web\x00.yaml", ""},
		{"fix \x00deploy/web.yaml", ""},
		{"fix deploy/\x00web.yaml", ""},
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
	diff := Propose(oomAlerts(), triage, "deploy/web.yaml", patchableManifest)
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

func TestApplyDiffPreservesTrailingNewlines(t *testing.T) {
	// splitLines trims every trailing break, so re-appending a single one
	// used to normalise a manifest ending in blank lines (#281). Every
	// trailing break of the original must survive the patch byte-for-byte,
	// and content without a final break must stay without one.
	if got, ok := applyDiff("x\n\n\n", "--- a/y\n+++ b/y\n@@ -1,1 +1,1 @@\n-x\n+y"); !ok || got != "y\n\n\n" {
		t.Errorf("trailing blank lines were not carried over: ok=%v got=%q", ok, got)
	}
	if got, ok := applyDiff("x", "--- a/y\n+++ b/y\n@@ -1,1 +1,1 @@\n-x\n+y"); !ok || got != "y" {
		t.Errorf("content without a final break gained one: ok=%v got=%q", ok, got)
	}
}

func TestProposeAppliesThroughTrailingBlankLines(t *testing.T) {
	// A manifest identical to the accepted fixture except for two blank
	// lines at the end must still ship a proposal whose applied content
	// raises exactly the memory scalar (#281).
	triage := Triage{FixLocation: "git", Confidence: "high"}
	manifest := patchableManifest + "\n\n"
	diff := Propose(oomAlerts(), triage, "deploy/web.yaml", manifest)
	if diff == "" {
		t.Fatalf("expected a diff from Propose for a manifest ending in blank lines")
	}
	patched, ok := applyDiff(manifest, diff)
	if !ok {
		t.Fatalf("applyDiff failed on a valid Propose diff:\n%s", diff)
	}
	want := strings.Replace(patchableManifest,
		"cpu: 250m\n              memory: 64Mi",
		"cpu: 250m\n              memory: 128Mi", 1) + "\n\n"
	if patched != want {
		t.Errorf("patched content mismatch:\nwant:\n%q\ngot:\n%q", want, patched)
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
			"type":     "file",
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
			// The group names an OOMKilled alert: the alert-type gate in
			// Propose requires a memory-pressure alert for the write arm.
			Alerts: []Alert{{Labels: map[string]string{"alertname": "OOMKilled", "severity": "warning"}}},
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

	// Updates never consume the daily budget, so they must never reconcile
	// the cap counter either.
	var allGets atomic.Int32
	origHandler := f.srv.Config.Handler
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet && req.URL.Path == "/repos/o/r/pulls" && req.URL.Query().Get("state") == "all" {
			allGets.Add(1)
		}
		origHandler.ServeHTTP(w, req)
	})

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
	if allGets.Load() != 0 {
		t.Errorf("an update must not reconcile the daily cap, got %d seed calls", allGets.Load())
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
				"type":     "file",
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

func TestDeliverPullSkipsNonMemoryPressureAlert(t *testing.T) {
	// A high-confidence git triage over a patchable manifest is not enough:
	// the group fired for a node fault, not a memory kill, so the PR arm
	// stays silent.
	f := newFakeGH(t, nil, 0)
	r := triageReport()
	r.Group.Alerts = []Alert{{Labels: map[string]string{"alertname": "KubeNodeNotReady", "severity": "critical"}}}

	act, err := deliverPull(context.Background(), f.client(), prCfg(), r)
	if err != nil {
		t.Fatalf("deliverPull: %v", err)
	}
	if act.Outcome != "skipped" {
		t.Errorf("expected skipped for a non-memory-pressure alert, got %s", act.Outcome)
	}
	if f.prCalls != 0 || f.puts != 0 {
		t.Errorf("non-memory-pressure alert must not write: prs=%d puts=%d", f.prCalls, f.puts)
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

func TestGetFileRejectsNonFileTypes(t *testing.T) {
	// The Contents API reports "symlink" for symlinks (with content holding
	// the target *path*, not the target's file), "dir" and "submodule" for
	// other non-regular entries. Only type "file" is a patch target; anything
	// else — including a missing type — must fail closed at the read.
	cases := []struct {
		name   string
		typ    string
		wantOK bool
	}{
		{"file", "file", true},
		{"symlink", "symlink", false},
		{"dir", "dir", false},
		{"submodule", "submodule", false},
		{"missing", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"content":  base64.StdEncoding.EncodeToString([]byte("hello\n")),
					"sha":      "sha1",
					"encoding": "base64",
					"type":     c.typ,
				})
			}))
			t.Cleanup(srv.Close)
			gh := &gitHubClient{token: "t", repo: "o/r", hc: &http.Client{}, apiURL: srv.URL}
			got, _, err := gh.getFile(context.Background(), "main", "deploy/web.yaml")
			if c.wantOK {
				if err != nil || got != "hello\n" {
					t.Fatalf("type %q: got (%q, %v), want (hello, nil)", c.typ, got, err)
				}
			} else if err == nil {
				t.Fatalf("type %q must fail closed, got content %q", c.typ, got)
			}
		})
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
	typ     string // Contents API type; "file" unless a test says otherwise
}

type fakeRepoServer struct {
	srv           *httptest.Server
	defaultHead   string
	defaultFile   string
	defaultSha    string
	defaultTyp    string
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
		defaultTyp:    "file",
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
		var content, sha, typ string
		switch {
		case ref == f.defaultBranch || ref == f.defaultHead:
			content, sha, typ = f.defaultFile, f.defaultSha, f.defaultTyp
		default:
			b, ok := f.branches[ref]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			content, sha, typ = b.content, b.sha, b.typ
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"content":  base64.StdEncoding.EncodeToString([]byte(content)),
			"sha":      sha,
			"encoding": "base64",
			"type":     typ,
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
		// file, blob SHA and type — exactly what GitHub returns for a fresh
		// ref.
		f.branches[branch] = branchState{content: f.defaultFile, sha: f.defaultSha, typ: f.defaultTyp}
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
		f.branches[payload["branch"]] = branchState{content: string(raw), sha: newSHA, typ: b.typ}
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
	r := triageReport()
	diff := Propose(r.Group.Alerts, r.Triage, "deploy/web.yaml", patchableManifest)
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
	f.branches[branch] = branchState{content: patchableManifest, sha: "defaultblob123", typ: "file"}
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
	f.branches[branch] = branchState{content: unexpected, sha: "weirdsha", typ: "file"}
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

func TestDeliverPullRefusesSymlinkTarget(t *testing.T) {
	// The allowlisted path on the default branch is a symlink: the Contents
	// API reports type "symlink" with content = the target path, not the
	// target's file. Treating that as a regular file would patch the wrong
	// thing. The write arm must fail closed on the read — before any branch
	// creation, file PUT, or PR.
	f := newFakeRepo(t, patchableManifest)
	f.mu.Lock()
	f.defaultTyp = "symlink"
	f.mu.Unlock()
	gh := f.client()

	if _, err := deliverPull(context.Background(), gh, prCfg(), triageReport()); err == nil {
		t.Fatalf("expected an error when the target path is a symlink")
	}
	if f.putCount != 0 {
		t.Errorf("a symlink target must not be written, got %d PUTs", f.putCount)
	}
	if f.prCount != 0 {
		t.Errorf("a symlink target must not open a PR, got %d", f.prCount)
	}
	f.mu.Lock()
	n := len(f.branches)
	f.mu.Unlock()
	if n != 0 {
		t.Errorf("a symlink target must not create a branch, got %d", n)
	}
}

// A stalled GitHub PR API must not hold the delivery loop for the full 30s
// budget: cancelling the caller's context — as a SIGTERM drain does — must
// abort the in-flight request promptly. This mirrors the issue arm's
// TestDeliverGitHubContextCancelledInFlight and the Discord arm's
// TestDeliverContextCancelledInFlight (issue #145); the PR arm's first call
// is the /pulls list, so a blocked server there is enough to hold it.
func TestDeliverPullContextCancelledInFlight(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hold the connection open without responding so the /pulls list
		// request is in flight; releasing it lets srv.Close() not wait.
		<-release
	}))
	defer srv.Close()
	defer close(release)

	g := &gitHubClient{token: "t", repo: "o/r", hc: &http.Client{}, apiURL: srv.URL}

	r := triageReport()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := deliverPull(ctx, g, prCfg(), r)
	elapsed := time.Since(start)

	if elapsed > 200*time.Millisecond {
		t.Fatalf("deliverPull took %v after context cancellation, want < 200ms", elapsed)
	}
	if err == nil {
		t.Fatal("expected error on context cancellation")
	}
	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context cancellation error, got %v", err)
	}
}

// TestListPRsCapsOverSizeResponse guards against the unbounded-body
// regression tracked in #210: a paginated PR list must fail rather than
// buffer a body larger than ghListBodyCap.
func TestListPRsCapsOverSizeResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		chunk := strings.Repeat("a", 64<<10)
		for i := 0; i < 96; i++ { // 6 MiB total, well over the 4 MiB cap
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	g := &gitHubClient{token: "t", repo: "o/r", hc: http.DefaultClient, apiURL: srv.URL}
	_, _, err := g.listPRs(context.Background(), 1, 50)
	if err == nil {
		t.Fatal("expected error for over-cap response, got nil")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("error = %q, want substring %q", err.Error(), "exceeded")
	}
}

// TestDefaultBranchCapsOverSizeResponse guards the ref half of the
// default-branch lookup (#210): the repo record is known-small, so an
// over-cap body must fail rather than buffer.
func TestDefaultBranchCapsOverSizeResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/repos/o/r") {
			w.Write([]byte(`{"default_branch":"main"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, strings.Repeat("a", ghSmallBodyCap+1))
	}))
	defer srv.Close()

	g := &gitHubClient{token: "t", repo: "o/r", hc: http.DefaultClient, apiURL: srv.URL}
	_, _, err := g.defaultBranch(context.Background())
	if err == nil {
		t.Fatal("expected error for over-cap response, got nil")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("error = %q, want substring %q", err.Error(), "exceeded")
	}
}

// TestGetFileCapsOverSizeResponse guards against the unbounded-body
// regression tracked in #210: a Contents API read must fail rather than
// buffer a body larger than ghFileBodyCap.
func TestGetFileCapsOverSizeResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		chunk := strings.Repeat("a", 64<<10)
		for i := 0; i < 96; i++ { // 6 MiB total, well over the 4 MiB cap
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	g := &gitHubClient{token: "t", repo: "o/r", hc: http.DefaultClient, apiURL: srv.URL}
	if _, _, err := g.getFile(context.Background(), "main", "deploy/x.yaml"); err == nil {
		t.Fatal("expected error for over-cap response, got nil")
	} else if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("error = %q, want substring %q", err.Error(), "exceeded")
	}
}

func TestPRMarkerPrefixPinned(t *testing.T) {
	if !strings.HasPrefix(fmt.Sprintf(prMarker, "abc"), prMarkerPrefix) || strings.Contains(prMarkerPrefix, "%") {
		t.Fatalf("marker prefix %q does not safely match the marker", prMarkerPrefix)
	}
}

func TestUTCDayStart(t *testing.T) {
	zone := time.FixedZone("UTC+2", 2*60*60)
	cases := []struct {
		in   time.Time
		want time.Time
	}{
		{time.Date(2026, 8, 19, 15, 30, 0, 0, time.UTC), time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)},
		{time.Date(2026, 8, 19, 1, 30, 0, 0, zone), time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		if got := utcDayStart(tc.in); !got.Equal(tc.want) {
			t.Errorf("utcDayStart(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestCountMarkerPRsCreatedSince(t *testing.T) {
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets.Add(1)
		if r.URL.Query().Get("state") != "all" || r.URL.Query().Get("sort") != "created" || r.URL.Query().Get("direction") != "desc" {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		switch r.URL.Query().Get("page") {
		case "1":
			w.Header().Set("Link", `<https://api.example/pulls?page=2>; rel="next"`)
			// A closed PR created today still spent the budget; a PR with no
			// parseable created_at is neither counted nor allowed to end the
			// scan; a PR created exactly at the day boundary counts.
			_ = json.NewEncoder(w).Encode([]ghPR{
				{State: "closed", Body: fmt.Sprintf(prMarker, "merged"), CreatedAt: time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)},
				{Body: "other", CreatedAt: time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC)},
				{Body: fmt.Sprintf(prMarker, "unknown-age")},
				{Body: fmt.Sprintf(prMarker, "boundary"), CreatedAt: time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)},
			})
		case "2":
			// Sorted newest-first, so this older PR ends the scan: page 3
			// must never be requested.
			_ = json.NewEncoder(w).Encode([]ghPR{{Body: fmt.Sprintf(prMarker, "yesterday"), CreatedAt: time.Date(2026, 8, 18, 23, 0, 0, 0, time.UTC)}})
		default:
			t.Errorf("unexpected page request: %s", r.URL.Query().Get("page"))
		}
	}))
	defer srv.Close()
	gh := &gitHubClient{token: "t", repo: "o/r", hc: http.DefaultClient, apiURL: srv.URL}
	got, err := gh.countMarkerPRsCreatedSince(context.Background(), time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC))
	if err != nil || got != 2 || gets.Load() != 2 {
		t.Fatalf("count=%d gets=%d err=%v; want 2, 2, nil", got, gets.Load(), err)
	}
}

func TestCountMarkerPRsFailsLoudAtSafetyCap(t *testing.T) {
	// A scan that runs out of bound with pages left cannot know the true
	// count, and a silently low count would reset the cap. It must error so
	// the caller degrades to the process-local count instead of seeding.
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := gets.Add(1)
		page := r.URL.Query().Get("page")
		if page != fmt.Sprint(n) || r.URL.Query().Get("per_page") != "100" {
			t.Errorf("unexpected page/per_page: %s/%s", page, r.URL.Query().Get("per_page"))
		}
		w.Header().Set("Link", fmt.Sprintf(`<https://api.example/pulls?page=%d>; rel="next"`, n+1))
		_ = json.NewEncoder(w).Encode([]ghPR{{Body: fmt.Sprintf(prMarker, "today"), CreatedAt: time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)}})
	}))
	defer srv.Close()
	gh := &gitHubClient{token: "t", repo: "o/r", hc: http.DefaultClient, apiURL: srv.URL}
	_, err := gh.countMarkerPRsCreatedSince(context.Background(), time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "20-page") {
		t.Fatalf("want a truncation error after the 20-page bound, got %v", err)
	}
	if gets.Load() != 20 {
		t.Fatalf("expected exactly 20 page requests, got %d", gets.Load())
	}
}

func TestCountMarkerPRsRejectsNonAdvancingPagination(t *testing.T) {
	// A Link header that advertises the page just fetched — or one already
	// visited — would pin the scan in a loop: the 20-page bound only catches
	// increasing page numbers. The scan must fail loud after the first
	// non-advancing page instead of looping until the caller's context
	// expires.
	tests := []struct {
		name    string
		next    func(page int) string
		wantReq int32
	}{
		{
			// The finding's exact shape: every page advertises page 1.
			name:    "pinned at page 1",
			next:    func(int) string { return `<https://api.example/pulls?page=1>; rel="next"` },
			wantReq: 1,
		},
		{
			// Page 2 advertising an already-visited page must also stop the
			// scan, not walk it backwards.
			name: "page 2 advertises page 1",
			next: func(page int) string {
				if page == 1 {
					return `<https://api.example/pulls?page=2>; rel="next"`
				}
				return `<https://api.example/pulls?page=1>; rel="next"`
			},
			wantReq: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gets atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gets.Add(1)
				page, _ := strconv.Atoi(r.URL.Query().Get("page"))
				w.Header().Set("Link", tt.next(page))
				_ = json.NewEncoder(w).Encode([]ghPR{{Body: fmt.Sprintf(prMarker, "today"), CreatedAt: time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)}})
			}))
			defer srv.Close()
			gh := &gitHubClient{token: "t", repo: "o/r", hc: http.DefaultClient, apiURL: srv.URL}
			// Bounded so a regression that loops on a non-advancing page
			// fails the test instead of hanging it until the package timeout.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := gh.countMarkerPRsCreatedSince(ctx, time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC))
			if err == nil || !strings.Contains(err.Error(), "did not advance") {
				t.Fatalf("want a non-advancing pagination error, got %v", err)
			}
			if gets.Load() != tt.wantReq {
				t.Fatalf("expected %d requests, got %d", tt.wantReq, gets.Load())
			}
		})
	}
}

func TestReconcileAllowanceSeedsCounterAndKeepsInFlight(t *testing.T) {
	now := time.Date(2026, 8, 19, 11, 0, 0, 0, time.UTC)
	cfg := &PRConfig{DailyCap: 3}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		// Simulate a caller concurrent to the fold: its reservation is not on
		// GitHub yet, so the seed must not discard it.
		if !cfg.reserveAllowance(now) {
			t.Error("concurrent in-flight reservation denied")
		}
		_ = json.NewEncoder(w).Encode([]ghPR{{Body: fmt.Sprintf(prMarker, "a"), CreatedAt: now}, {Body: fmt.Sprintf(prMarker, "b"), CreatedAt: now}})
	}))
	defer srv.Close()
	gh := &gitHubClient{token: "t", repo: "o/r", hc: http.DefaultClient, apiURL: srv.URL}
	if err := cfg.reconcileAllowance(context.Background(), gh, now); err != nil {
		t.Fatal(err)
	}
	if !cfg.reserveAllowance(now) || cfg.reserveAllowance(now) {
		t.Fatal("the seed must adopt the GitHub count without discarding the in-flight reservation, leaving exactly one slot")
	}
	if err := cfg.reconcileAllowance(context.Background(), gh, now.Add(time.Hour)); err != nil || calls.Load() != 1 {
		t.Fatalf("second reconciliation calls=%d err=%v", calls.Load(), err)
	}
}

func TestReconcileAllowanceConcurrentCallersCoalesce(t *testing.T) {
	// The day check and the reconciledDay write are not atomic on their own:
	// callers arriving while a seed scan is in flight must wait on it instead
	// of each issuing the same day's scan, or a burst would reconcile one day
	// several times over.
	now := time.Date(2026, 8, 19, 11, 0, 0, 0, time.UTC)
	cfg := &PRConfig{DailyCap: 2}
	var scans atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scans.Add(1)
		<-release // hold the scan open so later callers must find it in flight
		_ = json.NewEncoder(w).Encode([]ghPR{{Body: fmt.Sprintf(prMarker, "a"), CreatedAt: now}})
	}))
	defer srv.Close()
	gh := &gitHubClient{token: "t", repo: "o/r", hc: http.DefaultClient, apiURL: srv.URL}

	const callers = 8
	errs := make([]error, callers)
	var wg sync.WaitGroup
	// Bounded so a regression that wedges the in-flight marker fails the
	// test instead of hanging it until the package timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = cfg.reconcileAllowance(ctx, gh, now)
		}(i)
	}
	// Let every caller pile onto the in-flight scan before it finishes. The
	// scans==1 assertion is structural, so this sleep only buys discrimination
	// against a regression to un-coalesced callers.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if scans.Load() != 1 {
		t.Fatalf("scans=%d; concurrent callers must coalesce onto exactly one seed scan", scans.Load())
	}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	// The seed counted one marker PR, so of the cap of two exactly one slot
	// remains.
	if !cfg.reserveAllowance(now) || cfg.reserveAllowance(now) {
		t.Fatal("seed must adopt the GitHub count, leaving exactly one slot of two")
	}
}

func TestReconcileAllowanceDayRollsReseeds(t *testing.T) {
	dayA := time.Date(2026, 8, 19, 11, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		count := 2
		created := dayA
		if n > 1 {
			count = 0
			created = dayA.Add(24 * time.Hour)
		}
		prs := make([]ghPR, count)
		for i := range prs {
			prs[i] = ghPR{Body: fmt.Sprintf(prMarker, fmt.Sprint(i)), CreatedAt: created}
		}
		_ = json.NewEncoder(w).Encode(prs)
	}))
	defer srv.Close()
	gh := &gitHubClient{token: "t", repo: "o/r", hc: http.DefaultClient, apiURL: srv.URL}
	cfg := &PRConfig{DailyCap: 1}
	if err := cfg.reconcileAllowance(context.Background(), gh, dayA); err != nil {
		t.Fatal(err)
	}
	dayB := dayA.Add(24 * time.Hour)
	if err := cfg.reconcileAllowance(context.Background(), gh, dayB); err != nil {
		t.Fatal(err)
	}
	if !cfg.reserveAllowance(dayB) || cfg.reserveAllowance(dayB) {
		t.Fatal("day B must have an independent one-slot budget")
	}
}

func TestReconcileAllowanceScanBudgetBoundsSeedScan(t *testing.T) {
	// The seed scan and the write it precedes share the caller's context, so
	// a scan that hangs must fail at a budget of its own: run on the caller's
	// deadline alone, it would pin reconciliation until that deadline and
	// leave the write the allowance is computed for no context to run in.
	now := time.Date(2026, 8, 19, 11, 0, 0, 0, time.UTC)
	cfg := &PRConfig{DailyCap: 2}
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets.Add(1)
		<-r.Context().Done() // upstream never answers; cut when the request's context does
	}))
	defer srv.Close()
	gh := &gitHubClient{token: "t", repo: "o/r", hc: http.DefaultClient, apiURL: srv.URL}

	orig := prSeedScanBudget
	defer func() { prSeedScanBudget = orig }()
	prSeedScanBudget = 50 * time.Millisecond

	// The parent context is generous: a regression that runs the scan on the
	// caller's deadline blocks for all of it and trips the elapsed bound.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	err := cfg.reconcileAllowance(ctx, gh, now)
	elapsed := time.Since(start)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want the scan budget to fail the seed, got %v", err)
	}
	if !strings.Contains(err.Error(), "budget") {
		t.Fatalf("want the budget named in the error for the operator log, got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("reconcile blocked %v; the scan must fail at its own budget, not the caller's deadline", elapsed)
	}
	if cfg.reconciledDay != "" {
		t.Fatal("a budget-failed seed must not be cached")
	}
	if gets.Load() != 1 {
		t.Fatalf("expected exactly one scan request, got %d", gets.Load())
	}

	// A budget failure is an ordinary failed seed: nothing is cached, and the
	// next attempt retries it against a healthy upstream.
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]ghPR{{Body: fmt.Sprintf(prMarker, "a"), CreatedAt: now}})
	}))
	defer healthy.Close()
	retry := &gitHubClient{token: "t", repo: "o/r", hc: http.DefaultClient, apiURL: healthy.URL}
	if err := cfg.reconcileAllowance(context.Background(), retry, now); err != nil {
		t.Fatal(err)
	}
	if cfg.reconciledDay == "" || cfg.opened != 1 {
		t.Fatalf("retry must seed normally; day=%q opened=%d", cfg.reconciledDay, cfg.opened)
	}
}

func TestDeliverPullReconcilesCapFromGitHub(t *testing.T) {
	now := time.Date(2026, 8, 19, 11, 0, 0, 0, time.UTC)
	orig := timeNow
	defer func() { timeNow = orig }()
	timeNow = func() time.Time { return now }
	var creates, puts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/pulls":
			if r.URL.Query().Get("state") == "open" {
				_ = json.NewEncoder(w).Encode([]ghPR{})
				return
			}
			_ = json.NewEncoder(w).Encode([]ghPR{{Body: fmt.Sprintf(prMarker, "othersig-1"), CreatedAt: now}, {Body: fmt.Sprintf(prMarker, "othersig-2"), CreatedAt: now}})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r":
			_ = json.NewEncoder(w).Encode(map[string]string{"default_branch": "main"})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/git/ref/heads/main":
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "headsha123"}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/"):
			_ = json.NewEncoder(w).Encode(map[string]string{"content": base64.StdEncoding.EncodeToString([]byte(patchableManifest)), "sha": "blobsha123", "encoding": "base64", "type": "file"})
		case r.Method == http.MethodPut:
			puts.Add(1)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/o/r/pulls":
			creates.Add(1)
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer srv.Close()
	cfg := prCfg()
	cfg.DailyCap = 2
	act, err := deliverPull(context.Background(), &gitHubClient{token: "t", repo: "o/r", hc: http.DefaultClient, apiURL: srv.URL}, cfg, triageReport())
	if err != nil || act.Outcome != "capped" || creates.Load() != 0 || puts.Load() != 0 {
		t.Fatalf("action=%+v creates=%d puts=%d err=%v; want capped without writes", act, creates.Load(), puts.Load(), err)
	}
}

func TestDeliverPullReconcilesOncePerDay(t *testing.T) {
	now := time.Date(2026, 8, 19, 11, 0, 0, 0, time.UTC)
	orig := timeNow
	defer func() { timeNow = orig }()
	timeNow = func() time.Time { return now }
	var allGets, openGets, creates atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/pulls":
			if r.URL.Query().Get("state") == "all" {
				allGets.Add(1)
				_ = json.NewEncoder(w).Encode([]ghPR{{Body: fmt.Sprintf(prMarker, "seed"), CreatedAt: now}})
			} else {
				openGets.Add(1)
				_ = json.NewEncoder(w).Encode([]ghPR{})
			}
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r":
			_ = json.NewEncoder(w).Encode(map[string]string{"default_branch": "main"})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/git/ref/heads/main":
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "headsha123"}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/"):
			_ = json.NewEncoder(w).Encode(map[string]string{"content": base64.StdEncoding.EncodeToString([]byte(patchableManifest)), "sha": "blobsha123", "encoding": "base64", "type": "file"})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/o/r/pulls":
			creates.Add(1)
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer srv.Close()
	gh := &gitHubClient{token: "t", repo: "o/r", hc: http.DefaultClient, apiURL: srv.URL}
	cfg := prCfg()
	cfg.DailyCap = 5
	for i := 0; i < 2; i++ {
		r := triageReport()
		if i == 1 {
			r.Group.Alerts[0].Labels["alertname"] = "ContainerOOMKilled"
		}
		act, err := deliverPull(context.Background(), gh, cfg, r)
		if err != nil || act.Outcome != "created" {
			t.Fatalf("attempt %d: action=%+v err=%v", i+1, act, err)
		}
	}
	if allGets.Load() != 1 || openGets.Load() != 2 || creates.Load() != 2 {
		t.Fatalf("all=%d open=%d creates=%d; want 1, 2, 2", allGets.Load(), openGets.Load(), creates.Load())
	}
}

func TestDeliverPullRetriesFailedReconcile(t *testing.T) {
	// A failed seed must not be cached: the next attempt retries, and when it
	// succeeds the day's budget reflects PRs the process never saw. Otherwise
	// one transient 5xx would quietly reinstate the per-process cap (#383).
	// The retry seed includes the PR this process itself opened, so the fold
	// must adopt the GitHub count (max): adding it to the local count would
	// double-count that PR and cap the second attempt instead of opening.
	now := time.Date(2026, 8, 19, 11, 0, 0, 0, time.UTC)
	orig := timeNow
	defer func() { timeNow = orig }()
	timeNow = func() time.Time { return now }
	var allGets, creates, puts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/pulls":
			if r.URL.Query().Get("state") == "open" {
				_ = json.NewEncoder(w).Encode([]ghPR{})
				return
			}
			// First seed fails; the retry sees the PR this process opened
			// plus one it never saw, spending two of the cap of three.
			if allGets.Add(1) == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			own := fmt.Sprintf(prMarker, triageReport().Group.Signature())
			_ = json.NewEncoder(w).Encode([]ghPR{{Body: own, CreatedAt: now}, {Body: fmt.Sprintf(prMarker, "pre-restart"), CreatedAt: now}})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r":
			_ = json.NewEncoder(w).Encode(map[string]string{"default_branch": "main"})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/git/ref/heads/main":
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "headsha123"}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/"):
			_ = json.NewEncoder(w).Encode(map[string]string{"content": base64.StdEncoding.EncodeToString([]byte(patchableManifest)), "sha": "blobsha123", "encoding": "base64", "type": "file"})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/o/r/pulls":
			creates.Add(1)
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut:
			puts.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer srv.Close()
	gh := &gitHubClient{token: "t", repo: "o/r", hc: http.DefaultClient, apiURL: srv.URL}
	cfg := prCfg()
	cfg.DailyCap = 3

	act, err := deliverPull(context.Background(), gh, cfg, triageReport())
	if err != nil || act.Outcome != "created" {
		t.Fatalf("attempt 1 with a failed seed: action=%+v err=%v", act, err)
	}
	r2 := triageReport()
	r2.Group.Alerts[0].Labels["alertname"] = "ContainerOOMKilled"
	act, err = deliverPull(context.Background(), gh, cfg, r2)
	if err != nil || act.Outcome != "created" {
		t.Fatalf("attempt 2 must open (max fold, not addition): action=%+v err=%v", act, err)
	}
	r3 := triageReport()
	r3.Group.Alerts[0].Labels["alertname"] = "OOMKilled"
	act, err = deliverPull(context.Background(), gh, cfg, r3)
	if err != nil || act.Outcome != "capped" {
		t.Fatalf("attempt 3 must hit the cap the seed counted: action=%+v err=%v", act, err)
	}
	if allGets.Load() != 2 || creates.Load() != 2 || puts.Load() != 2 {
		t.Fatalf("all=%d creates=%d puts=%d; want the seed retried once and exactly two writes", allGets.Load(), creates.Load(), puts.Load())
	}
}

func TestDeliverPullReconcileFailureDegrades(t *testing.T) {
	f := newFakeGH(t, nil, 0)
	orig := f.srv.Config.Handler
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/pulls" && r.URL.Query().Get("state") == "all" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		orig.ServeHTTP(w, r)
	})
	act, err := deliverPull(context.Background(), f.client(), prCfg(), triageReport())
	if err != nil || act.Outcome != "created" {
		t.Fatalf("action=%+v err=%v; reconciliation failure should degrade", act, err)
	}
}
