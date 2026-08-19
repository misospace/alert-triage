package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	}
	for _, c := range cases {
		if got := pathAllowed(c.path, allow); got != c.want {
			t.Errorf("pathAllowed(%q) = %v, want %v", c.path, got, c.want)
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
		{"../escape.yaml", ""},
	}
	for _, c := range cases {
		if got := extractPath(c.in); got != c.want {
			t.Errorf("extractPath(%q) = %v, want %q", c.in, got, c.want)
		}
	}
}

func TestBranchSlug(t *testing.T) {
	got := branchSlug("KubePodNotReady::default::myapp")
	if !strings.HasPrefix(got, "KubePodNotReady") {
		t.Errorf("unexpected slug: %q", got)
	}
	if strings.Contains(got, "::") {
		t.Errorf("slug should not contain : (ref-format forbids): %q", got)
	}
	if got := branchSlug(""); got == "" {
		t.Errorf("branch slug should never be empty")
	}
}

// --- applyPatch ---

func TestApplyPatchRoundTrip(t *testing.T) {
	original := "line1\nline2\nline3\nline4\n"
	patch := "--- a/x\n+++ b/x\n@@ -1,3 +1,3 @@\n line1\n-line2\n+line2b\n line3"
	got, ok := applyPatch(original, patch)
	if !ok {
		t.Fatalf("applyPatch failed")
	}
	if got != "line1\nline2b\nline3\nline4\n" {
		t.Errorf("patch produced unexpected output: %q", got)
	}
}

func TestApplyPatchRejectsGarbage(t *testing.T) {
	if _, ok := applyPatch("x", "not a patch"); ok {
		t.Errorf("garbage patch should fail closed")
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

func TestLoadPRConfigRespectsAllowlist(t *testing.T) {
	t.Setenv("GITHUB_PR_OPT_IN", "true")
	t.Setenv("GITHUB_TOKEN", "t")
	t.Setenv("GITHUB_REPO", "o/r")
	t.Setenv("GITHUB_PR_PATH_ALLOWLIST", "deploy/, apps/foo/")
	cfg := loadPRConfig()
	if cfg == nil {
		t.Fatalf("expected config")
	}
	if cfg.DailyCap < 1 {
		t.Errorf("default daily cap should be >= 1")
	}
	if len(cfg.Allowlist) != 2 {
		t.Errorf("expected 2 allowlist entries, got %d", len(cfg.Allowlist))
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

func TestLoadPRConfigTokenWithoutRepoReturnsNil(t *testing.T) {
	t.Setenv("GITHUB_PR_OPT_IN", "true")
	t.Setenv("GITHUB_TOKEN", "t")
	t.Setenv("GITHUB_REPO", "")
	t.Setenv("GITHUB_PR_PATH_ALLOWLIST", "deploy/")
	if cfg := loadPRConfig(); cfg != nil {
		t.Errorf("expected nil when repo missing, got %+v", cfg)
	}
}

// --- proposalEligible ---

func TestProposalEligible(t *testing.T) {
	if prEligible(Triage{FixLocation: "git", Confidence: "high"}) != true {
		t.Errorf("git+high should be eligible")
	}
	if prEligible(Triage{FixLocation: "partial", Confidence: "high"}) != false {
		t.Errorf("partial must not be eligible")
	}
	if prEligible(Triage{FixLocation: "git", Confidence: "low"}) != false {
		t.Errorf("low confidence must not be eligible")
	}
}

// --- deliverPull behaviour, using a fake GitHub server ---

func newFakeGH(t *testing.T, existing *ghPR) (*gitHubClient, *httptest.Server, *int) {
	t.Helper()
	var prCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r":
			_ = json.NewEncoder(w).Encode(map[string]string{"default_branch": "main"})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"content":  base64.StdEncoding.EncodeToString([]byte("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        resources:\n          limits:\n            memory: 256Mi\n")),
				"sha":      "abc",
				"encoding": "base64",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/pulls":
			if existing != nil {
				_ = json.NewEncoder(w).Encode([]ghPR{*existing})
				return
			}
			_ = json.NewEncoder(w).Encode([]ghPR{})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/o/r/pulls":
			prCalls++
			_ = json.NewEncoder(w).Encode(ghPR{Number: 7, HTMLURL: "https://pr/7", State: "open"})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/o/r/git/refs":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/comments"):
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	gh := &gitHubClient{
		token:  "t",
		repo:   "o/r",
		hc:     &http.Client{},
		apiURL: srv.URL,
	}
	return gh, srv, &prCalls
}

func TestDeliverPullCreatesOnePRPerSignature(t *testing.T) {
	gh, srv, prCalls := newFakeGH(t, nil)
	t.Cleanup(srv.Close)
	cfg := &PRConfig{OptIn: true, Allowlist: []string{"deploy/"}, DailyCap: 5}

	r := Report{
		Group:  Group{Key: "XPodCrash::default::app", Cluster: "default", Alerts: []Alert{{Labels: map[string]string{"alertname": "XPodCrash"}}}},
		Triage: Triage{FixLocation: "git", Confidence: "high", WhatToChange: "raise memory limit in deploy/app.yaml", Narrative: "memory"},
	}

	const origYAML = "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        resources:\n          limits:\n            memory: 256Mi\n"

	a, err := deliverPull(context.Background(), gh, cfg, r, origYAML, "https://digest/1", 0)
	if err != nil {
		t.Fatalf("deliverPull: %v", err)
	}
	if a.Outcome != "created" {
		t.Errorf("first call should create, got %s", a.Outcome)
	}
	if !strings.HasPrefix(a.Branch, "alert-triage/") {
		t.Errorf("branch should be namespaced, got %s", a.Branch)
	}
	if *prCalls != 1 {
		t.Errorf("expected 1 PR creation call, got %d", *prCalls)
	}
}

func TestDeliverPullRecurrenceUpdates(t *testing.T) {
	recurrenceGroup := Group{Cluster: "default", Alerts: []Alert{{Labels: map[string]string{"alertname": "XPodCrash"}}}}
	existing := &ghPR{
		Number:  11,
		State:   "open",
		HTMLURL: "https://pr/11",
		Body:    fmt.Sprintf(prMarker, recurrenceGroup.Signature()),
	}
	gh, srv, prCalls := newFakeGH(t, existing)
	t.Cleanup(srv.Close)
	cfg := &PRConfig{OptIn: true, Allowlist: []string{"deploy/"}, DailyCap: 5}

	r := Report{
		Group:    Group{Key: "XPodCrash::default::app", Cluster: "default", Alerts: []Alert{{Labels: map[string]string{"alertname": "XPodCrash"}}}},
		Triage:   Triage{FixLocation: "git", Confidence: "high", WhatToChange: "raise memory limit in deploy/app.yaml", Narrative: "memory"},
		PriorSeen: 3,
	}
	const origYAML = "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        resources:\n          limits:\n            memory: 256Mi\n"
	a, err := deliverPull(context.Background(), gh, cfg, r, origYAML, "https://digest/2", 1)
	if err != nil {
		t.Fatalf("deliverPull: %v", err)
	}
	if a.Outcome != "updated" {
		t.Errorf("recurrence should update, got %s", a.Outcome)
	}
	if *prCalls != 0 {
		t.Errorf("recurrence must not call PR create, got %d", *prCalls)
	}
}

func TestDeliverPullHonoursDailyCap(t *testing.T) {
	gh, srv, _ := newFakeGH(t, nil)
	t.Cleanup(srv.Close)
	cfg := &PRConfig{Allowlist: []string{"deploy/"}, DailyCap: 1}

	r := Report{
		Group:  Group{Key: "s1"},
		Triage: Triage{FixLocation: "git", Confidence: "high", WhatToChange: "deploy/x.yaml"},
	}
	const origYAML = "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        resources:\n          limits:\n            memory: 256Mi\n"
	a, err := deliverPull(context.Background(), gh, cfg, r, origYAML, "", 1)
	if err != nil {
		t.Fatalf("deliverPull: %v", err)
	}
	if a.Outcome != "capped" {
		t.Errorf("expected capped when openedToday >= DailyCap, got %s", a.Outcome)
	}
}

func TestDeliverPullOffWhenConfigNil(t *testing.T) {
	a, err := deliverPull(context.Background(), &gitHubClient{}, nil, Report{}, "", "", 0)
	if err != nil {
		t.Fatalf("deliverPull: %v", err)
	}
	if a.Outcome != "off" {
		t.Errorf("expected off when cfg nil, got %s", a.Outcome)
	}
}

func TestDeliverPullMissingPathSkips(t *testing.T) {
	cfg := &PRConfig{Allowlist: []string{"deploy/"}, DailyCap: 5}
	r := Report{
		Group:  Group{Key: "s1"},
		Triage: Triage{FixLocation: "git", Confidence: "high", WhatToChange: "no path here"},
	}
	a, err := deliverPull(context.Background(), &gitHubClient{}, cfg, r, "", "", 0)
	if err != nil {
		t.Fatalf("deliverPull: %v", err)
	}
	if a.Outcome != "skipped" {
		t.Errorf("expected skipped when no path, got %s", a.Outcome)
	}
}

func TestDeliverPullPathNotUnderAllowlistSkips(t *testing.T) {
	cfg := &PRConfig{Allowlist: []string{"deploy/"}, DailyCap: 5}
	r := Report{
		Group:  Group{Key: "s1"},
		Triage: Triage{FixLocation: "git", Confidence: "high", WhatToChange: "fix apps/foo.yaml"},
	}
	a, err := deliverPull(context.Background(), &gitHubClient{}, cfg, r, "", "", 0)
	if err != nil {
		t.Fatalf("deliverPull: %v", err)
	}
	if a.Outcome != "skipped" {
		t.Errorf("expected skipped when path not under allowlist, got %s", a.Outcome)
	}
}

func TestDeliverPullLowConfidenceSkips(t *testing.T) {
	cfg := &PRConfig{Allowlist: []string{"deploy/"}, DailyCap: 5}
	r := Report{
		Group:  Group{Key: "s1"},
		Triage: Triage{FixLocation: "git", Confidence: "low", WhatToChange: "deploy/x.yaml"},
	}
	a, err := deliverPull(context.Background(), &gitHubClient{}, cfg, r, "", "", 0)
	if err != nil {
		t.Fatalf("deliverPull: %v", err)
	}
	if a.Outcome != "skipped" {
		t.Errorf("expected skipped when confidence low, got %s", a.Outcome)
	}
}

func TestDeliverPullPartialSkips(t *testing.T) {
	cfg := &PRConfig{Allowlist: []string{"deploy/"}, DailyCap: 5}
	r := Report{
		Group:  Group{Key: "s1"},
		Triage: Triage{FixLocation: "partial", Confidence: "high", WhatToChange: "deploy/x.yaml"},
	}
	a, err := deliverPull(context.Background(), &gitHubClient{}, cfg, r, "", "", 0)
	if err != nil {
		t.Fatalf("deliverPull: %v", err)
	}
	if a.Outcome != "skipped" {
		t.Errorf("partial fix_location must not open PR, got %s", a.Outcome)
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
