package main

// pull.go opens pull requests for fix proposals once their diff has been
// validated over a stretch of incidents (issue #36). It is the write arm of
// the proposal pipeline: propose.go computes the diff, this file chooses
// whether and how to land it on GitHub. Nothing is written here unless every
// gate below passes silently — being wrong stops being a suggestion at this
// step, and the gates are the only thing standing between a bad narrative
// and a commit.
//
// Hard gates, in order, before any API call that mutates state:
//
//  1. Opt-in.  A token that exists for other reasons (issues) must not
//     silently turn this on. GITHUB_PR_OPT_IN must be set to "true".
//  2. Identity.  GITHUB_TOKEN and GITHUB_REPO must both be set.
//  3. Plan.  Only fix_location == "git" plus confidence == "high".
//  4. Diff.  Propose must return a non-empty patch for the named path.
//  5. Path.  The path must be under a configured allowlist.
//  6. Cap.  No more than GITHUB_PR_DAILY_CAP PRs per calendar day; the
//     trip is logged so a flapping alert does not generate a queue of
//     branches.
//
// On a recurrence the existing PR is updated with a new comment rather than
// a second PR being opened. The dedup key is the same signature marker used
// for issues (#14), so the same marker does both jobs from one scan.
//
// A network or API failure must degrade to "proposal only" and never block
// the digest. Errors are logged and the report layer carries on.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// prMarker is the line GitHub searches for to recognise an existing PR for
// a signature. Kept parallel to the issue marker.
const prMarker = `<!-- alert-triage-pr:{"sig":"%s"} -->`

// PRConfig is the opt-in plus gates. The constructor reads these from env
// alongside the existing GITHUB_TOKEN / GITHUB_REPO and degrades to nil
// whenever anything is missing so the rest of the program can treat "off"
// as "no behaviour change".
type PRConfig struct {
	OptIn     bool
	BaseURL   string // API base; default https://api.github.com
	Allowlist []string
	DailyCap  int
	MaxBytes  int // commit blob cap; cheaper than streaming in a homelab
}

// loadPRConfig reads PR env vars. Returns nil when opt-in is off so callers
// can short-circuit without a flag check.
func loadPRConfig() *PRConfig {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("GITHUB_PR_OPT_IN")), "true") {
		return nil
	}
	if strings.TrimSpace(os.Getenv("GITHUB_TOKEN")) == "" || strings.TrimSpace(os.Getenv("GITHUB_REPO")) == "" {
		logf("github-pr: opt-in set but GITHUB_TOKEN/GITHUB_REPO missing; proposals only")
		return nil
	}
	allow := splitCSV(os.Getenv("GITHUB_PR_PATH_ALLOWLIST"))
	if len(allow) == 0 {
		logf("github-pr: opt-in set but GITHUB_PR_PATH_ALLOWLIST empty; proposals only")
		return nil
	}
	cap := 5
	if v := strings.TrimSpace(os.Getenv("GITHUB_PR_DAILY_CAP")); v != "" {
		var n int
		fmt.Sscanf(v, "%d", &n)
		if n > 0 {
			cap = n
		}
	}
	return &PRConfig{
		OptIn:     true,
		Allowlist: allow,
		DailyCap:  cap,
		MaxBytes:  1048576,
	}
}

// splitCSV is a tolerant comma splitter that ignores blanks.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// PRAction is what main.go renders into the chat/issue line. URL is empty
// when the action is "skipped", "capped", or "off".
type PRAction struct {
	Outcome string // created | updated | skipped | capped | off
	URL     string
	Branch  string
}

// deliverPull is the single entry point. It is a no-op when prcfg is nil
// (the default), so the call site is unconditional.
func deliverPull(ctx context.Context, gh *gitHubClient, prcfg *PRConfig, r Report, original string, digestURL string, openedToday int) (PRAction, error) {
	if prcfg == nil {
		return PRAction{Outcome: "off"}, nil
	}
	if gh == nil {
		return PRAction{Outcome: "off"}, nil
	}
	if !proposalEligible(r.Triage) {
		return PRAction{Outcome: "skipped"}, nil
	}

	relPath := extractPath(r.Triage.WhatToChange)
	if relPath == "" {
		logf("github-pr: no path in what_to_change for %s", r.Group.Signature())
		return PRAction{Outcome: "skipped"}, nil
	}
	if !pathAllowed(relPath, prcfg.Allowlist) {
		logf("github-pr: %s not under allowlist", relPath)
		return PRAction{Outcome: "skipped"}, nil
	}

	patch := Propose(r.Triage, relPath, original)
	if patch == "" {
		// Propose already logged the reason; this is the expected path
		// for change classes the diff layer hasn't validated yet.
		return PRAction{Outcome: "skipped"}, nil
	}

	if openedToday >= prcfg.DailyCap {
		logf("github-pr: daily cap %d reached; proposal stays open for %s", prcfg.DailyCap, r.Group.Signature())
		return PRAction{Outcome: "capped"}, nil
	}

	sig := r.Group.Signature()
	if sig == "" {
		return PRAction{Outcome: "skipped"}, nil
	}
	branch := "alert-triage/" + branchSlug(sig)

	existing, err := gh.findOpenPR(ctx, sig)
	if err != nil {
		return PRAction{}, err
	}

	if existing == nil {
		u, err := gh.openPR(ctx, branch, relPath, patch, r, digestURL)
		if err != nil {
			return PRAction{}, err
		}
		logf("github-pr: opened PR for %s on %s", sig, branch)
		return PRAction{Outcome: "created", URL: u, Branch: branch}, nil
	}

	if err := gh.updatePR(ctx, existing, r, digestURL); err != nil {
		return PRAction{}, err
	}
	logf("github-pr: updated PR #%d for %s", existing.Number, sig)
	return PRAction{Outcome: "updated", URL: existing.HTMLURL, Branch: existing.Head.Ref}, nil
}

// proposalEligible is the gating predicate for fix_location == "git".
// Pulled out of the Triage type so it can be tested independently of the
// narrative parser.
func proposalEligible(t Triage) bool {
	return strings.EqualFold(strings.TrimSpace(t.FixLocation), "git") &&
		strings.EqualFold(strings.TrimSpace(t.Confidence), "high")
}

// extractPath pulls the first repo-relative path from a what_to_change
// string. The model is told to name a file; we accept whatever token looks
// most like a path. Returns "" when nothing qualifies.
func extractPath(s string) string {
	for _, f := range strings.Fields(s) {
		f = strings.Trim(f, "`\"'")
		if !strings.Contains(f, "/") {
			continue
		}
		if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") {
			continue
		}
		clean := path.Clean(f)
		if clean == "." || strings.HasPrefix(clean, "..") {
			continue
		}
		return clean
	}
	return ""
}

// pathAllowed checks whether a relative path is under at least one allowed
// root. Allowed roots are clean and prefix-checked with a trailing slash
// so "deploy/foo" does not match "deploy-other/file".
func pathAllowed(p string, allow []string) bool {
	p = path.Clean(p)
	for _, a := range allow {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		a = path.Clean(a)
		if a == "." {
			return true
		}
		if p == a {
			return true
		}
		if strings.HasPrefix(p, strings.TrimRight(a, "/")+"/") {
			return true
		}
	}
	return false
}

// branchSlug turns a signature into a branch name. Strips characters that
// git ref-format forbids and caps at 60 chars.
func branchSlug(sig string) string {
	keep := func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9':
			return r
		}
		return '-'
	}
	out := strings.Map(keep, sig)
	out = strings.Trim(out, "-")
	if out == "" {
		out = "alert"
	}
	if len(out) > 60 {
		out = out[:60]
	}
	return strings.TrimRight(out, "-")
}

// --- GitHub PR API ---

type ghPR struct {
	Number  int    `json:"number"`
	State   string `json:"state"`
	Title   string `json:"title"`
	Body    string `json:"body"`
	HTMLURL string `json:"html_url"`
	Head    struct {
		Ref string `json:"ref"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
}

func (g *gitHubClient) findOpenPR(ctx context.Context, sig string) (*ghPR, error) {
	marker := fmt.Sprintf(prMarker, sig)
	q := url.Values{}
	q.Set("state", "open")
	q.Set("per_page", "100")
	u := g.apiURL + "/repos/" + g.repo + "/pulls?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	g.setHeaders(req)
	resp, err := g.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("github pr list: %s: %s", resp.Status, string(body))
	}
	var raw []ghPR
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	for i := range raw {
		if strings.Contains(raw[i].Body, marker) {
			return &raw[i], nil
		}
	}
	return nil, nil
}

// openPR creates a branch off the default branch, commits the patched file
// contents, and opens the PR. Steps follow the public API; no SDK.
func (g *gitHubClient) openPR(ctx context.Context, branch, relPath, patch string, r Report, digestURL string) (string, error) {
	defaultBranch, err := g.defaultBranch(ctx)
	if err != nil {
		return "", err
	}

	original, sha, err := g.getFile(ctx, defaultBranch, relPath)
	if err != nil {
		return "", err
	}
	patched, ok := applyPatch(original, patch)
	if !ok {
		return "", fmt.Errorf("github-pr: patch did not apply to current %s", relPath)
	}

	if err := g.createBranch(ctx, branch, sha); err != nil {
		// 422 means the branch already exists from a half-finished run;
		// surface that as a real error so the caller logs it.
		return "", err
	}
	if err := g.putFile(ctx, branch, relPath, patched, sha); err != nil {
		return "", err
	}

	return g.createPR(ctx, branch, defaultBranch, prTitle(r), prBody(r, digestURL, branch))
}

func (g *gitHubClient) defaultBranch(ctx context.Context) (string, error) {
	u := g.apiURL + "/repos/" + g.repo
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	g.setHeaders(req)
	resp, err := g.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("github repo: %s: %s", resp.Status, string(body))
	}
	var out struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.DefaultBranch == "" {
		return "", fmt.Errorf("github repo: empty default_branch")
	}
	return out.DefaultBranch, nil
}

func (g *gitHubClient) getFile(ctx context.Context, branch, file string) (string, string, error) {
	u := g.apiURL + "/repos/" + g.repo + "/contents/" + url.PathEscape(file) + "?ref=" + url.QueryEscape(branch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", "", err
	}
	g.setHeaders(req)
	resp, err := g.hc.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", "", fmt.Errorf("github get file: %s not found on %s", file, branch)
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", "", fmt.Errorf("github get file: %s: %s", resp.Status, string(body))
	}
	var out struct {
		Content  string `json:"content"`
		SHA      string `json:"sha"`
		Encoding string `json:"encoding"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", err
	}
	if out.Encoding != "base64" {
		return "", "", fmt.Errorf("github get file: unexpected encoding %q", out.Encoding)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(out.Content, "\n", ""))
	if err != nil {
		return "", "", err
	}
	return string(raw), out.SHA, nil
}

func (g *gitHubClient) createBranch(ctx context.Context, branch, fromSHA string) error {
	u := g.apiURL + "/repos/" + g.repo + "/git/refs"
	payload := map[string]string{
		"ref": "refs/heads/" + branch,
		"sha": fromSHA,
	}
	buf, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	g.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("github create branch: %s: %s", resp.Status, string(body))
	}
	return nil
}

func (g *gitHubClient) putFile(ctx context.Context, branch, file, content, sha string) error {
	u := g.apiURL + "/repos/" + g.repo + "/contents/" + url.PathEscape(file)
	payload := map[string]string{
		"message": "alert-triage: proposed fix for " + file,
		"content": base64.StdEncoding.EncodeToString([]byte(content)),
		"branch":  branch,
		"sha":     sha,
	}
	buf, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	g.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("github put file: %s: %s", resp.Status, string(body))
	}
	return nil
}

func (g *gitHubClient) createPR(ctx context.Context, head, base, title, body string) (string, error) {
	payload := map[string]string{
		"title": title,
		"body":  body,
		"head":  head,
		"base":  base,
	}
	buf, _ := json.Marshal(payload)
	u := g.apiURL + "/repos/" + g.repo + "/pulls"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	g.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("github create pr: %s: %s", resp.Status, string(body))
	}
	var out ghPR
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.HTMLURL, nil
}

func (g *gitHubClient) updatePR(ctx context.Context, pr *ghPR, r Report, digestURL string) error {
	body := fmt.Sprintf("Re-fire for signature `%s`.\n\n%s", r.Group.Signature(), prUpdateBody(r, digestURL))
	u := fmt.Sprintf("%s/repos/%s/issues/%d/comments", g.apiURL, g.repo, pr.Number)
	payload := map[string]string{"body": body}
	buf, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	g.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("github pr comment: %s: %s", resp.Status, string(body))
	}
	return nil
}

func prTitle(r Report) string {
	sev := r.Group.Severity()
	if sev == "" {
		sev = "alert"
	}
	return fmt.Sprintf("alert-triage: %s (%s)", r.Group.Title(), sev)
}

func prBody(r Report, digestURL, branch string) string {
	var b strings.Builder
	sig := r.Group.Signature()
	fmt.Fprintf(&b, prMarker+"\n\n", sig)
	if r.Narrative != "" {
		b.WriteString(r.Narrative)
		b.WriteString("\n\n")
	}
	if w := r.Triage.WhatToChange; w != "" {
		fmt.Fprintf(&b, "**What to change**\n\n%s\n\n", w)
	}
	fmt.Fprintf(&b, "**Branch:** `%s`\n\n", branch)
	if digestURL != "" {
		fmt.Fprintf(&b, "**Digest:** %s\n", digestURL)
	}
	b.WriteString("\nProposed by alert-triage. Generated by `Propose` over the diff validated in #35; reviewed-only unless confidence is `high` and the path is under the allowlist.\n")
	return b.String()
}

func prUpdateBody(r Report, digestURL string) string {
	var b strings.Builder
	b.WriteString("Re-fire details:\n\n")
	if r.PriorSeen > 0 {
		fmt.Fprintf(&b, "- Seen %d time(s) recently\n", r.PriorSeen)
	}
	fmt.Fprintf(&b, "- Severity: `%s`\n", r.Group.Severity())
	if digestURL != "" {
		fmt.Fprintf(&b, "- Digest: %s\n", digestURL)
	}
	return b.String()
}

// applyPatch turns the unified diff produced by Propose into the patched
// file text. It understands the header format emitted by propose.go: a
// single hunk with leading context lines, "-old" / "+new" lines, and a
// trailing context. Anything else fails closed.
func applyPatch(original, patch string) (string, bool) {
	lines := strings.Split(strings.TrimRight(patch, "\n"), "\n")
	if len(lines) < 4 {
		return "", false
	}
	if !strings.HasPrefix(lines[0], "--- a/") || !strings.HasPrefix(lines[1], "+++ b/") {
		return "", false
	}
	if !strings.HasPrefix(lines[2], "@@") {
		return "", false
	}
	var oldStart, oldCount int
	if _, err := fmt.Sscanf(lines[2], "@@ -%d,%d +%d,%d @@", &oldStart, &oldCount, new(int), new(int)); err != nil {
		return "", false
	}
	if oldStart < 1 {
		return "", false
	}

	orig := strings.Split(original, "\n")
	out := make([]string, 0, len(orig))
	out = append(out, orig[:oldStart-1]...)
	for _, l := range lines[3:] {
		switch {
		case strings.HasPrefix(l, "+"):
			out = append(out, strings.TrimPrefix(l, "+"))
		case strings.HasPrefix(l, "-"):
			// drop
		case strings.HasPrefix(l, " "):
			out = append(out, strings.TrimPrefix(l, " "))
		case l == "":
			// empty contextual line
		default:
			return "", false
		}
	}
	return strings.Join(out, "\n"), true
}

// timeNow is the clock for the daily cap. Stubbable in tests.
var timeNow = func() time.Time { return time.Now() } //nolint:gochecknoglobals
