package main

// pull.go opens pull requests for validated fix proposals (issue #36). It is
// the write arm of the proposal pipeline: propose.go computes the diff, this
// file decides whether and how to land it on GitHub. Nothing mutates upstream
// state unless every gate passes silently, because this is the point where
// being wrong stops being a suggestion.
//
// Design notes / invariants:
//
//   - Strictly opt-in.  GITHUB_PR_OPT_IN must be "true" on top of
//     GITHUB_TOKEN and GITHUB_REPO. A token that exists for issue mirroring
//     must not silently turn this on.
//   - fix_location=git AND confidence=high only — strictly tighter than the
//     proposal gate (proposalEligible also admits "partial").
//   - A non-empty Propose diff that applies cleanly is a hard prerequisite for
//     any write. The committed content is the patched full file, derived by
//     applying the validated diff to the authoritative repo content, never a
//     slice of model text.
//   - One deterministic branch per group signature. A re-fire finds the open
//     PR carrying the marker and comments on it instead of opening a second.
//   - Branches always fork off the default branch HEAD; the default branch
//     itself is never written.
//   - New PRs are capped per calendar day; the trip is logged.
//   - Any API failure (revoked token, timeout, 4xx/5xx) is logged and degrades
//     to "proposal only". It never blocks the digest.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PRs and issues share the same signature marker so a recurrence has one
// durable identity regardless of which GitHub surface it first reaches.
const prMarker = signatureMarker

// defaultPRDailyCap is the per-day budget for NEW PRs when
// GITHUB_PR_DAILY_CAP is unset or malformed. Deliberately small: a PR is a
// proposed code change, not a log line, so the arm stays quiet unless a human
// has raised the cap to match the incident volume.
const defaultPRDailyCap = 5

// PRConfig is the opt-in plus gates for the PR write arm. It is nil unless
// every hard prerequisite is configured so the rest of the program can treat
// "off" as "no behaviour change".
type PRConfig struct {
	OptIn     bool
	Allowlist []string
	DailyCap  int
	PublicURL string // optional public base URL; digest link is only emitted when set

	mu     sync.Mutex
	day    string // calendar day ("2006-01-02") for the current cap window
	opened int    // PRs created within that window
}

// loadPRConfig reads the PR env vars. It returns nil when opt-in is off or a
// load-bearing prerequisite is missing, so callers short-circuit without a
// per-field check.
func loadPRConfig() *PRConfig {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("GITHUB_PR_OPT_IN")), "true") {
		return nil
	}
	if strings.TrimSpace(os.Getenv("GITHUB_TOKEN")) == "" ||
		strings.TrimSpace(os.Getenv("GITHUB_REPO")) == "" {
		logf("github-pr: opt-in set but GITHUB_TOKEN/GITHUB_REPO missing; proposals only")
		return nil
	}
	allow := splitCSV(os.Getenv("GITHUB_PR_PATH_ALLOWLIST"))
	if len(allow) == 0 {
		logf("github-pr: opt-in set but GITHUB_PR_PATH_ALLOWLIST empty; proposals only")
		return nil
	}
	// A '.' wildcard would authorise every repository path — the exact failure
	// the allowlist exists to prevent. Refuse to enable the write arm rather
	// than silently making the whole repo writable.
	if allowlistIsWildcard(allow) {
		logf("github-pr: GITHUB_PR_PATH_ALLOWLIST uses a '.' wildcard; refusing to make every repo path writable; proposals only")
		return nil
	}
	cap := defaultPRDailyCap
	if v := strings.TrimSpace(os.Getenv("GITHUB_PR_DAILY_CAP")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			logf("github-pr: malformed GITHUB_PR_DAILY_CAP %q; using default %d", v, defaultPRDailyCap)
		} else {
			cap = n
		}
	}
	return &PRConfig{
		OptIn:     true,
		Allowlist: allow,
		DailyCap:  cap,
		PublicURL: strings.TrimRight(strings.TrimSpace(os.Getenv("GITHUB_PR_PUBLIC_URL")), "/"),
	}
}

// digestLink returns the public link to the recent digests, or "" when no
// public base URL is configured. Nothing is invented here: an unset URL means
// the PR body carries no link rather than a fabricated one.
func (c *PRConfig) digestLink() string {
	if c == nil || c.PublicURL == "" {
		return ""
	}
	return c.PublicURL + "/recent"
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

// reserveAllowance takes one slot from the per-day budget for a NEW PR,
// rolling the window forward when the calendar day changes. It returns false
// when the cap is already spent. The slot is *reserved*, not yet spent: the
// caller must call refundAllowance if the write it reserved for ultimately
// fails, so a branch/file/PR creation error does not burn the day's budget.
// Updates to existing PRs never call this. Safe for concurrent callers: at
// most DailyCap slots can be reserved at once, and every reservation that ends
// in a successful open is exactly one real PR.
func (c *PRConfig) reserveAllowance(now time.Time) bool {
	day := now.UTC().Format("2006-01-02")
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.day != day {
		c.day = day
		c.opened = 0
	}
	if c.DailyCap > 0 && c.opened >= c.DailyCap {
		return false
	}
	c.opened++
	return true
}

// refundAllowance gives a reserved slot back after the write it was reserved
// for failed. It uses the same `now` the reservation took: if the window has
// since rolled to a new calendar day (reset by another call's reservation)
// there is nothing to hand back, so it is left alone.
func (c *PRConfig) refundAllowance(now time.Time) {
	day := now.UTC().Format("2006-01-02")
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.day != day {
		return
	}
	if c.opened > 0 {
		c.opened--
	}
}

// PRAction is the outcome of the PR arm, rendered into nothing by the digest
// itself (the digest carries on regardless). The fields exist so a future
// surface can link to the PR.
type PRAction struct {
	Outcome string // off | skipped | capped | created | updated
	URL     string
	Branch  string
}

// deliverPull is the single entry point for the PR write arm. It is a no-op
// when prcfg is nil, so the call site is unconditional. Any error here is an
// API failure and must be surfaced to the caller only for logging — the digest
// path must never depend on it.
func deliverPull(ctx context.Context, gh *gitHubClient, prcfg *PRConfig, r Report) (PRAction, error) {
	if prcfg == nil || !prcfg.OptIn {
		return PRAction{Outcome: "off"}, nil
	}
	if gh == nil {
		return PRAction{Outcome: "off"}, nil
	}
	if !prEligible(r.Triage) {
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

	sig := r.Group.Signature()
	if sig == "" {
		return PRAction{Outcome: "skipped"}, nil
	}

	// Recurrence wins: an existing open PR carrying the marker is updated, and
	// updating never consumes the daily budget for new PRs.
	existing, err := gh.findOpenPR(ctx, sig)
	if err != nil {
		return PRAction{}, err
	}
	if existing != nil {
		if err := gh.updatePR(ctx, existing, r, prcfg.digestLink()); err != nil {
			return PRAction{}, err
		}
		logf("github-pr: updated PR #%d for %s", existing.Number, sig)
		return PRAction{Outcome: "updated", URL: existing.HTMLURL, Branch: existing.Head.Ref}, nil
	}

	// Prepare the commit against the authoritative default-branch content:
	// fetch, run the validated Propose diff, and apply it to the full file.
	patch, err := preparePatch(ctx, gh, relPath, r)
	if err != nil {
		if err == errNoPatch || err == errPatchStale {
			logf("github-pr: %v for %s", err, relPath)
			return PRAction{Outcome: "skipped"}, nil
		}
		return PRAction{}, err
	}

	// One clock reading for reserve and the matching refund, so the two are
	// guaranteed to agree on which calendar window the slot belongs to.
	now := timeNow()
	if !prcfg.reserveAllowance(now) {
		logf("github-pr: daily cap %d reached; proposal stays open for %s", prcfg.DailyCap, sig)
		return PRAction{Outcome: "capped"}, nil
	}

	if err := gh.openPR(ctx, patch, r, prcfg.digestLink()); err != nil {
		// The write failed, so it must not count against the day's budget:
		// hand the reservation back and degrade to proposal-only.
		prcfg.refundAllowance(now)
		return PRAction{}, err
	}
	logf("github-pr: opened PR for %s on %s", sig, patch.branch)
	return PRAction{Outcome: "created", Branch: patch.branch}, nil
}

// prEligible is the gating predicate for the PR write arm: fix_location=git
// AND confidence=high. Stricter than proposalEligible, which also admits
// "partial" locations for showing a diff without writing anything.
func prEligible(t Triage) bool {
	return strings.EqualFold(strings.TrimSpace(t.FixLocation), "git") &&
		strings.EqualFold(strings.TrimSpace(t.Confidence), "high")
}

// extractPath pulls the first repo-relative path token out of what_to_change.
// The model is told to name a file; we accept the token that looks most like a
// path and reject anything that could escape the repository root (traversal
// or an absolute path). Returns "" when nothing qualifies.
func extractPath(s string) string {
	for _, f := range strings.Fields(s) {
		f = strings.Trim(f, "`\"'")
		if !strings.Contains(f, "/") {
			continue
		}
		if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") ||
			strings.HasPrefix(f, "//") {
			continue
		}
		clean := path.Clean(f)
		if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." {
			continue
		}
		if strings.HasPrefix(clean, "/") {
			continue
		}
		return clean
	}
	return ""
}

// pathAllowed decides whether a repository-relative path is under at least one
// allowed root. Both sides are cleaned and the prefix test carries a trailing
// slash so "deploy/foo" never slips past an allowlist entry that names a
// different root like "deploy-other/". A wildcard ('.'), an escape, or an
// absolute root never authorises a write: that would make the whole repo (or
// outside of it) writable, which is exactly what the allowlist is for.
func pathAllowed(p string, allow []string) bool {
	p = path.Clean(p)
	if p == "." || strings.HasPrefix(p, "../") || p == ".." || strings.HasPrefix(p, "/") {
		return false
	}
	for _, a := range allow {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		a = path.Clean(a)
		if a == "." || a == ".." || strings.HasPrefix(a, "/") {
			continue
		}
		if a == p {
			return true
		}
		if strings.HasPrefix(p, a+"/") {
			return true
		}
	}
	return false
}

// allowlistIsWildcard reports whether the allowlist contains a '.' (or any
// entry that cleans to it), which would authorise every repository path.
// Config load uses this to fail closed instead of turning the whole repo
// writable.
func allowlistIsWildcard(allow []string) bool {
	for _, a := range allow {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if path.Clean(a) == "." {
			return true
		}
	}
	return false
}

// branchSlug turns a signature hash into a branch-safe name. Signatures are
// already hex, but sanitising keeps ref-format rules (no ':', no leading '-',
// bounded length) even if a caller passes something else.
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

// filePatch is the validated material for one new PR: the deterministic
// branch, the authoritative default-branch content/commit/blob SHAs for
// preconditions and recovery comparison, the patched full content to commit,
// and the diff for the PR body. original is kept so a retry can tell, by
// comparing a pre-existing branch's file against it, whether the branch is
// still untouched (adopt and commit) or already carries our patch (skip).
type filePatch struct {
	branch        string
	relPath       string
	diff          string
	original      string
	patched       string
	blobSHA       string
	headSHA       string
	defaultBranch string
}

// preparePatch fetches the authoritative file from the default branch, runs
// the validated Propose diff, and applies it to the full content. errNoPatch
// means Propose declined (change class not validated); errPatchStale means the
// diff would not apply to the current content (e.g. the file drifted). Neither
// is an API failure.
func preparePatch(ctx context.Context, gh *gitHubClient, relPath string, r Report) (*filePatch, error) {
	defaultBranch, defaultHeadSHA, err := gh.defaultBranch(ctx)
	if err != nil {
		return nil, err
	}
	// Fetch the authoritative file by the exact default HEAD SHA, not the
	// moving branch name, so the blob-SHA precondition and the commit the
	// branch is cut from are guaranteed to be the same snapshot. Fetching by
	// name could read a blob that is not actually at the SHA we branch from if
	// the default branch moves between the two calls.
	current, blobSHA, err := gh.getFile(ctx, defaultHeadSHA, relPath)
	if err != nil {
		return nil, err
	}
	diff := Propose(r.Triage, relPath, current)
	if diff == "" {
		return nil, errNoPatch
	}
	patched, ok := applyDiff(current, diff)
	if !ok {
		return nil, errPatchStale
	}
	return &filePatch{
		branch:        "alert-triage/" + branchSlug(r.Group.Signature()),
		relPath:       relPath,
		diff:          diff,
		original:      current,
		patched:       patched,
		blobSHA:       blobSHA,
		headSHA:       defaultHeadSHA,
		defaultBranch: defaultBranch,
	}, nil
}

var (
	errNoPatch      = fmt.Errorf("github-pr: Propose produced no patch")
	errPatchStale   = fmt.Errorf("github-pr: validated diff did not apply to current content")
	errBranchExists = fmt.Errorf("github-pr: branch already exists")
)

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

// findOpenPR lists open PRs and returns the one whose body carries the
// signature marker, paginating via the Link header. A recurrence must still be
// found past page 1: stopping at the first page is what would let a re-fire
// open a duplicate once the repo outgrows 100 open PRs.
func (g *gitHubClient) findOpenPR(ctx context.Context, sig string) (*ghPR, error) {
	marker := fmt.Sprintf(prMarker, sig)
	page := 1
	for {
		prs, next, err := g.listPRs(ctx, page, 100)
		if err != nil {
			return nil, err
		}
		for i := range prs {
			if strings.Contains(prs[i].Body, marker) {
				return &prs[i], nil
			}
		}
		if next == 0 {
			return nil, nil
		}
		page = next
		if page > 20 { // safety: 2000 open PRs is enough
			return nil, nil
		}
	}
}

// listPRs returns one page of open PRs and the next page number (0 when the
// Link header carries no rel="next"), mirroring the issue lister so both dedup
// scans paginate identically.
func (g *gitHubClient) listPRs(ctx context.Context, page, perPage int) ([]ghPR, int, error) {
	u, _ := url.Parse(g.apiURL + "/repos/" + g.repo + "/pulls")
	q := u.Query()
	q.Set("state", "open")
	q.Set("per_page", fmt.Sprintf("%d", perPage))
	q.Set("page", fmt.Sprintf("%d", page))
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	g.setHeaders(req)
	resp, err := g.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, 0, fmt.Errorf("github pr list: %s: %s", resp.Status, string(body))
	}
	var raw []ghPR
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, 0, err
	}
	next := 0
	if link := resp.Header.Get("Link"); link != "" {
		next = parseNextPage(link)
	}
	return raw, next, nil
}

// openPR lands the patched full file on the deterministic branch and opens the
// PR. It is idempotent across partial writes: if a previous run created the
// branch but failed before the PR shipped, a retry adopts the existing branch
// instead of stalling on a 422 or cutting a second branch, preserving the "one
// PR per signature" invariant. The default branch itself is never written.
func (g *gitHubClient) openPR(ctx context.Context, patch *filePatch, r Report, digestURL string) error {
	// Ensure the deterministic branch exists. A 422 means it already exists (an
	// orphan from a failed write, or already created): confirm the ref and adopt
	// it. Any other failure is a real API error and aborts.
	if err := g.createBranch(ctx, patch.branch, patch.headSHA); err != nil {
		if err != errBranchExists {
			return err
		}
		if err := g.confirmBranch(ctx, patch.branch); err != nil {
			return err
		}
	}
	if err := g.adoptBranch(ctx, patch); err != nil {
		return err
	}
	return g.createPR(ctx, patch.branch, patch.defaultBranch, prTitle(r), prBody(r, patch, digestURL))
}

// adoptBranch reconciles the deterministic branch to the validated patched
// content, failing closed on anything ambiguous. It fetches the branch's
// current file and only acts when the content is exactly one of the two known
// states:
//
//   - unchanged from the authoritative original — commit the validated patched
//     content using the branch's current blob SHA as the precondition;
//   - already exactly the validated patched content — the write from an earlier
//     run already landed; skip the file PUT and let the caller open the PR.
//
// If the branch carries anything else — someone edited it, a stale earlier run
// wrote different content, or the default moved — we refuse to overwrite and
// return an error. An orphan branch is only ever adopted into the state our
// signature, diff and allowlist already proved correct, never clobbered.
func (g *gitHubClient) adoptBranch(ctx context.Context, patch *filePatch) error {
	branchContent, branchBlobSHA, err := g.getFile(ctx, patch.branch, patch.relPath)
	if err != nil {
		return err
	}
	switch {
	case branchContent == patch.original:
		// The branch is an untouched fork of the default: commit the patched
		// content against the branch's own current blob SHA so the PUT never
		// has a stale precondition.
		return g.putFile(ctx, patch.branch, patch.relPath, patch.patched, branchBlobSHA)
	case branchContent == patch.patched:
		// Already exact: an earlier run's PUT landed but the PR never opened.
		// Skip the re-PUT and let the caller open the PR.
		return nil
	default:
		return fmt.Errorf("github-pr: branch %s carries unexpected content for %s; refusing to overwrite", patch.branch, patch.relPath)
	}
}

// confirmBranch verifies that a deterministic branch ref actually exists after
// a 422 create, so we adopt a branch we can prove is there rather than trusting
// the status code alone.
func (g *gitHubClient) confirmBranch(ctx context.Context, branch string) error {
	u := g.apiURL + "/repos/" + g.repo + "/git/ref/heads/" + url.PathEscape(branch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	g.setHeaders(req)
	resp, err := g.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("github branch %s not found after 422 create: %s", branch, string(body))
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("github confirm branch %s: %s: %s", branch, resp.Status, string(body))
	}
	return nil
}

// defaultBranch returns the repository's default branch name and the commit
// SHA of its HEAD, used as the base for new PR branches.
func (g *gitHubClient) defaultBranch(ctx context.Context) (name, headSHA string, err error) {
	u := g.apiURL + "/repos/" + g.repo
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
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", "", fmt.Errorf("github repo: %s: %s", resp.Status, string(body))
	}
	var out struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", err
	}
	if out.DefaultBranch == "" {
		return "", "", fmt.Errorf("github repo: empty default_branch")
	}

	u2 := g.apiURL + "/repos/" + g.repo + "/git/ref/heads/" + url.PathEscape(out.DefaultBranch)
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, u2, nil)
	if err != nil {
		return "", "", err
	}
	g.setHeaders(req2)
	resp2, err := g.hc.Do(req2)
	if err != nil {
		return "", "", err
	}
	defer resp2.Body.Close()
	if resp2.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp2.Body, 4096))
		return "", "", fmt.Errorf("github default ref: %s: %s", resp2.Status, string(body))
	}
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&ref); err != nil {
		return "", "", err
	}
	if ref.Object.SHA == "" {
		return "", "", fmt.Errorf("github default ref: empty object sha")
	}
	return out.DefaultBranch, ref.Object.SHA, nil
}

// getFile returns the decoded contents and the blob SHA of a file on a branch.
// The blob SHA is the precondition for the subsequent Contents PUT.
func (g *gitHubClient) getFile(ctx context.Context, branch, file string) (content, sha string, err error) {
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
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
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
	// 422 is GitHub's "already exists" for a ref create; it is not a failure
	// but a signal the deterministic branch is already there (e.g. orphaned by
	// a failed run) and should be adopted rather than re-created.
	if resp.StatusCode == http.StatusUnprocessableEntity {
		return errBranchExists
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("github create branch: %s: %s", resp.Status, string(body))
	}
	return nil
}

// putFile commits the patched full content to a branch using the blob SHA of
// the file as a precondition: if the file changed underneath us (the branch no
// longer carries that blob), the PUT fails atomically rather than corrupting
// the tree. This is the guard against committing to stale content.
func (g *gitHubClient) putFile(ctx context.Context, branch, file, content, sha string) error {
	u := g.apiURL + "/repos/" + g.repo + "/contents/" + url.PathEscape(file)
	payload := map[string]string{
		"message": "alert-triage: proposed fix for " + file,
		"content": base64.StdEncoding.EncodeToString([]byte(content)),
		"branch":  branch,
		"sha":     sha,
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
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

func (g *gitHubClient) createPR(ctx context.Context, head, base, title, body string) error {
	payload := map[string]string{
		"title": title,
		"body":  body,
		"head":  head,
		"base":  base,
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	u := g.apiURL + "/repos/" + g.repo + "/pulls"
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
		return fmt.Errorf("github create pr: %s: %s", resp.Status, string(body))
	}
	return nil
}

// updatePR comments on an existing PR for a re-fire. Updating never opens a
// second PR and never consumes the daily budget.
func (g *gitHubClient) updatePR(ctx context.Context, pr *ghPR, r Report, digestURL string) error {
	body := fmt.Sprintf("Re-fire for signature `%s`.\n\n%s", r.Group.Signature(), prUpdateBody(r, digestURL))
	u := fmt.Sprintf("%s/repos/%s/issues/%d/comments", g.apiURL, g.repo, pr.Number)
	payload := map[string]string{"body": body}
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
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

// prBody builds the PR description. It always carries the narrative, the
// proposed diff, and the evidence the model was given; the digest link is only
// added when a public URL is configured.
func prBody(r Report, patch *filePatch, digestURL string) string {
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

	b.WriteString("**Proposed diff**\n\n```diff\n")
	b.WriteString(strings.TrimRight(patch.diff, "\n"))
	b.WriteString("\n```\n\n")

	if evid := renderEvidence(r); evid != "" {
		fmt.Fprintf(&b, "<details><summary>Evidence</summary>\n\n%s\n\n</details>\n\n", evid)
	}

	fmt.Fprintf(&b, "**Branch:** `%s`\n", patch.branch)
	if digestURL != "" {
		fmt.Fprintf(&b, "**Digest:** %s\n", digestURL)
	}

	b.WriteString("\nGenerated by alert-triage from a high-confidence `fix_location=git` proposal whose diff passed the validated change classes; the path is under the configured allowlist. Review before merge.\n")
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
	return strings.TrimRight(b.String(), "\n")
}

// applyDiff applies a Propose unified diff to the authoritative file content.
//
// Propose emits a full-region replacement: a single hunk whose old lines are
// all prefixed '-' and whose new lines are all prefixed '+', with no context
// lines. Applying it deletes oldCount lines at oldStart and inserts the new
// lines there. To keep this from blindly trusting diff text, the removal lines
// are verified byte-for-byte against the current content — if the file has
// drifted and the old lines no longer match, the patch is rejected as stale.
func applyDiff(original, diff string) (string, bool) {
	orig := splitLines(original)
	lines := strings.Split(strings.TrimRight(diff, "\n"), "\n")
	if len(lines) < 4 {
		return "", false
	}
	if !strings.HasPrefix(lines[0], "--- a/") || !strings.HasPrefix(lines[1], "+++ b/") {
		return "", false
	}
	var oldStart, oldCount, newCount int
	if n, err := fmt.Sscanf(lines[2], "@@ -%d,%d +%d,%d @@", &oldStart, &oldCount, new(int), &newCount); err != nil || n != 4 {
		return "", false
	}
	if oldStart < 1 || oldCount < 0 || newCount < 0 {
		return "", false
	}
	body := lines[3:]
	if len(body) < oldCount+newCount {
		return "", false
	}
	if oldStart-1+oldCount > len(orig) {
		return "", false
	}

	removed := make([]string, 0, oldCount)
	for _, l := range body[:oldCount] {
		if !strings.HasPrefix(l, "-") {
			return "", false
		}
		removed = append(removed, strings.TrimPrefix(l, "-"))
	}
	added := make([]string, 0, newCount)
	for _, l := range body[oldCount : oldCount+newCount] {
		if !strings.HasPrefix(l, "+") {
			return "", false
		}
		added = append(added, strings.TrimPrefix(l, "+"))
	}
	if len(body) != oldCount+newCount {
		return "", false
	}

	// Stale-patch guard: the removal lines must match the authoritative
	// content at the claimed offset. A diff generated against different
	// content fails closed instead of corrupting the file.
	for i, want := range removed {
		if orig[oldStart-1+i] != want {
			return "", false
		}
	}

	out := make([]string, 0, len(orig)-oldCount+newCount)
	out = append(out, orig[:oldStart-1]...)
	out = append(out, added...)
	out = append(out, orig[oldStart-1+oldCount:]...)
	res := strings.Join(out, "\n")
	if strings.HasSuffix(original, "\n") {
		res += "\n"
	}
	return res, true
}

// timeNow is the clock for the daily cap; stubbable in tests.
var timeNow = func() time.Time { return time.Now() } //nolint:gochecknoglobals
