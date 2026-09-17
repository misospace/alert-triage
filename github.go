package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GitHub delivery: when GITHUB_REPO and GITHUB_TOKEN are set, actionable
// incidents are mirrored to a GitHub issue keyed on the group signature so
// repeated firings update one durable record instead of producing a new chat
// message each time. Unset env means today's chat-only behaviour.
//
// The dedup key is an HTML comment in the body: <!-- alert-triage:{"sig":"..."} -->.
// On re-fire we list open issues, fetch the body of the one carrying the marker,
// and either comment (with flap control) or create the issue. Flap control uses
// the issue's most recent comment timestamp so a re-fire a week later gets a
// comment, but one four minutes later is suppressed.
//
// Issue #14 / Scope: this is the durable record an operator needed. Chat
// delivery stays so a fresh firing still pings the room; the chat line points
// at the issue when one exists.

const signatureMarker = `<!-- alert-triage:{"sig":"%s"} -->`

type gitHubClient struct {
	token  string
	repo   string // "owner/name"
	hc     *http.Client
	apiURL string // defaults to https://api.github.com
}

func newGitHub(cfg *Config) *gitHubClient {
	if cfg.GitHubToken == "" || cfg.GitHubRepo == "" {
		return nil
	}
	return &gitHubClient{
		token:  cfg.GitHubToken,
		repo:   cfg.GitHubRepo,
		hc:     &http.Client{Timeout: 30 * time.Second},
		apiURL: "https://api.github.com",
	}
}

type ghIssue struct {
	Number    int       `json:"number"`
	Title     string    `json:"title"`
	State     string    `json:"state"`
	HTMLURL   string    `json:"html_url"`
	Body      string    `json:"body"`
	Labels    []ghLabel `json:"labels"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Comments  int       `json:"comments"`
}

type ghLabel struct {
	Name string `json:"name"`
}

// issueAction tells main.go what happened: "created", "commented" or "none"
// (no env, not actionable, or no change worth posting). The URL is set when an
// issue now exists so chat can link to it.
type issueAction struct {
	Outcome string // created | commented | none
	URL     string
}

// deliverGitHub routes the incident to GitHub. It is a no-op when the env is
// unset or the triage verdict is non-actionable; chat-only groups never touch
// the API. Returns (action, err): action.Outcome=="none" with err==nil is the
// expected path for the majority of groups.
func deliverGitHub(ctx context.Context, gh *gitHubClient, cfg *Config, r Report) (issueAction, error) {
	if gh == nil {
		return issueAction{Outcome: "none"}, nil
	}
	if !r.Triage.Actionable() {
		return issueAction{Outcome: "none"}, nil
	}
	sig := r.Group.Signature()
	if sig == "" {
		return issueAction{Outcome: "none"}, nil
	}

	existing, err := gh.findOpenIssue(ctx, sig)
	if err != nil {
		return issueAction{}, err
	}

	body := renderIssueBody(r, sig)

	if existing == nil {
		title := issueTitle(r)
		num, url, err := gh.createIssue(ctx, title, body, labelsFor(r))
		if err != nil {
			return issueAction{}, err
		}
		logf("github: created issue #%d for %s", num, sig)
		return issueAction{Outcome: "created", URL: url}, nil
	}

	// Already open. Comment only when the state changed or enough time has
	// passed since the last comment; otherwise we are exactly the flapping
	// alert the issue warned about.
	if shouldComment(existing, r, cfg.IssueCommentInterval) {
		body := renderCommentBody(r)
		if err := gh.comment(ctx, existing.Number, body); err != nil {
			return issueAction{}, err
		}
		logf("github: commented on #%d for %s", existing.Number, sig)
		return issueAction{Outcome: "commented", URL: existing.HTMLURL}, nil
	}
	return issueAction{Outcome: "none", URL: existing.HTMLURL}, nil
}

// shouldComment gates re-fire comments. Two reasons to post: the severity
// moved (so the issue reflects the current state) or the last comment is older
// than the flap interval. PriorSeen contributes a "fired N times recently"
// line which is what makes the comment worthwhile.
func shouldComment(existing *ghIssue, r Report, interval time.Duration) bool {
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	// Severity change always warrants a note. Only judge a change when the
	// issue actually carries labels: labelsFor stamps one severity label on
	// creation, so a missing current-severity label means the severity moved.
	if want := severityLabel(r.Group.Severity()); want != "" && len(existing.Labels) > 0 {
		changed := true
		for _, l := range existing.Labels {
			if l.Name == want {
				// The issue already carries the current severity: no change,
				// so fall through to the interval gate below.
				changed = false
				break
			}
		}
		if changed {
			return true
		}
	}
	// If we've never commented on this issue yet, the first re-fire is
	// always worth a note — the initial body captured the first firing, but
	// operators want to see "still happening" written down somewhere.
	if existing.Comments == 0 {
		return true
	}
	return time.Since(existing.UpdatedAt) >= interval
}

func issueTitle(r Report) string {
	// "KubePodNotReady (warning)" — short, sorts in the issue list, and the
	// signature marker inside the body still does the dedup work.
	sev := r.Group.Severity()
	if sev == "" {
		sev = "alert"
	}
	return fmt.Sprintf("%s (%s)", r.Group.Title(), sev)
}

func labelsFor(r Report) []string {
	out := []string{"alert-triage"}
	if s := severityLabel(r.Group.Severity()); s != "" {
		out = append(out, s)
	}
	return out
}

func severityLabel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "critical", "warning", "info":
		return s
	}
	if s == "" {
		return ""
	}
	return s
}

// renderIssueBody is the full GitHub-flavoured Markdown body. Chat delivery
// loses evidence when it's verbose; a folded <details> block solves that.
// The signature marker is required for dedup and must be the first line so a
// quick text search picks it up before any quoting.
func renderIssueBody(r Report, sig string) string {
	var b strings.Builder
	fmt.Fprintf(&b, signatureMarker+"\n\n", sig)

	if r.Narrative != "" {
		b.WriteString(r.Narrative)
		b.WriteString("\n\n")
	}

	if loc := r.Triage.FixLocation; loc != "" && loc != "unknown" {
		fmt.Fprintf(&b, "**Fix belongs in:** `%s`", loc)
		if r.Triage.Confidence == "low" {
			b.WriteString(" _(low confidence)_")
		}
		b.WriteString("\n\n")
	}
	if w := r.Triage.WhatToChange; w != "" {
		fmt.Fprintf(&b, "**What to change**\n\n%s\n\n", w)
	}

	// Grafana Explore links: same construction as the Discord embed, so the
	// issue body and the chat digest agree on where the evidence lives. Links
	// are emitted only when GRAFANA_URL and the relevant datasource UID are
	// set; otherwise the body reads exactly as it did before.
	if metricsLink, logsLink := grafanaLinks(r.Cfg, firstExpression(r.Group.Alerts), firstNamespace(r.Group.Alerts), groupWindow(r.Group)); metricsLink != "" || logsLink != "" {
		b.WriteString("**Grafana**\n\n")
		if metricsLink != "" {
			fmt.Fprintf(&b, "• [Metrics explore](%s)\n", metricsLink)
		}
		if logsLink != "" {
			fmt.Fprintf(&b, "• [Logs explore](%s)\n", logsLink)
		}
		b.WriteString("\n")
	}

	b.WriteString("**Alerts**\n\n")
	b.WriteString("| Severity | Alert | Namespace | Since |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, a := range r.Group.Alerts {
		ns := a.namespace()
		if ns == "" {
			ns = "—"
		}
		since := "—"
		if !a.StartsAt.IsZero() {
			since = a.StartsAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s |\n", a.severity(), a.name(), ns, since)
	}
	b.WriteString("\n")

	if evid := renderEvidence(r); evid != "" {
		fmt.Fprintf(&b, "<details><summary>Evidence</summary>\n\n%s\n\n</details>\n\n", evid)
	}

	payloadJSON := renderPayload(r)
	if payloadJSON != "" {
		fmt.Fprintf(&b, "<details><summary>Raw Alertmanager payload</summary>\n\n```json\n%s\n```\n\n</details>\n",
			clamp(payloadJSON, 60000))
	}

	return b.String()
}

// renderCommentBody is the briefer form used on re-fire. It records the new
// firing count and any severity shift; full body rebuild is unnecessary and
// noisy.
func renderCommentBody(r Report) string {
	var b strings.Builder
	b.WriteString("**Re-fire**\n\n")
	if r.PriorSeen > 0 {
		fmt.Fprintf(&b, "Seen %d time(s) recently.\n\n", r.PriorSeen)
	}
	if r.Narrative != "" {
		b.WriteString(clamp(r.Narrative, 1500))
		b.WriteString("\n\n")
	}
	fmt.Fprintf(&b, "Severity: `%s`\n", r.Group.Severity())
	return b.String()
}

func renderPayload(r Report) string {
	type payloadView struct {
		Group  string  `json:"group"`
		Status string  `json:"status"`
		Alerts []Alert `json:"alerts"`
	}
	pv := payloadView{
		Group:  r.Group.Key,
		Status: "firing",
		Alerts: r.Group.Alerts,
	}
	b, err := json.MarshalIndent(pv, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

// findOpenIssue lists open issues labelled alert-triage and returns the one
// whose body contains the signature marker. Pagination stops at the first
// match; the API caps results at 100 per page which is fine for the
// steady-state of an alert-triage queue.
func (g *gitHubClient) findOpenIssue(ctx context.Context, sig string) (*ghIssue, error) {
	marker := fmt.Sprintf(signatureMarker, sig)
	page := 1
	for {
		issues, next, err := g.listIssues(ctx, page, 100, "open")
		if err != nil {
			return nil, err
		}
		for i := range issues {
			if strings.Contains(issues[i].Body, marker) {
				return &issues[i], nil
			}
		}
		if next == 0 {
			return nil, nil
		}
		page = next
		if page > 20 { // safety: 2000 open issues is enough
			return nil, nil
		}
	}
}

// listIssues returns one page of issues. The custom media type asks for the
// issues' labels inline so we don't have to fan out a second request per row
// just to compute the severity-change check.
func (g *gitHubClient) listIssues(ctx context.Context, page, perPage int, state string) ([]ghIssue, int, error) {
	u, _ := url.Parse(g.apiURL + "/repos/" + g.repo + "/issues")
	q := u.Query()
	q.Set("state", state)
	q.Set("labels", "alert-triage")
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
	if resp.StatusCode == http.StatusNotFound {
		return nil, 0, fmt.Errorf("github: repo %q not found or token lacks access", g.repo)
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, 0, fmt.Errorf("github list: %s: %s", resp.Status, string(body))
	}

	var raw []ghIssue
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, 0, err
	}
	// The /issues endpoint also returns PRs; drop anything that doesn't look
	// like an issue we created. The signature marker search below will also
	// reject PRs since their bodies never carry the marker.
	issues := make([]ghIssue, 0, len(raw))
	for _, i := range raw {
		issues = append(issues, i)
	}
	next := 0
	if link := resp.Header.Get("Link"); link != "" {
		next = parseNextPage(link)
	}
	return issues, next, nil
}

func parseNextPage(link string) int {
	for _, part := range strings.Split(link, ",") {
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		href := part
		if i := strings.Index(href, "<"); i >= 0 {
			href = href[i+1:]
		}
		if j := strings.Index(href, ">"); j >= 0 {
			href = href[:j]
		}
		u, err := url.Parse(href)
		if err != nil {
			return 0
		}
		page := u.Query().Get("page")
		if page == "" {
			return 0
		}
		var n int
		fmt.Sscanf(page, "%d", &n)
		return n
	}
	return 0
}

func (g *gitHubClient) createIssue(ctx context.Context, title, body string, labels []string) (int, string, error) {
	payload := map[string]any{
		"title":  title,
		"body":   body,
		"labels": labels,
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.apiURL+"/repos/"+g.repo+"/issues", bytes.NewReader(buf))
	if err != nil {
		return 0, "", err
	}
	g.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.hc.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return 0, "", fmt.Errorf("github create: %s: %s", resp.Status, string(body))
	}
	var out ghIssue
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, "", err
	}
	return out.Number, out.HTMLURL, nil
}

func (g *gitHubClient) comment(ctx context.Context, number int, body string) error {
	payload := map[string]string{"body": body}
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	u := fmt.Sprintf("%s/repos/%s/issues/%d/comments", g.apiURL, g.repo, number)
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
		return fmt.Errorf("github comment: %s: %s", resp.Status, string(body))
	}
	return nil
}

func (g *gitHubClient) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "alert-triage")
}

// Commit relevance for a Flux reconcile. A healthy Flux reconcile is neutral
// (see fluxActivity), but when the source is GitHub we can fetch the commit
// that the revision references and check whether its changed files intersect
// the workload's GitOps path or declared component paths. The evidence is
// deliberately best-effort: a non-GitHub source, a private-repo 404, an
// unparseable revision, or any API failure degrades to Unknown so the digest
// keeps shipping instead of being blocked on an external lookup.
//
// The State values are the three the issue asks for:
//   - "touches"          - the commit changed at least one file under the
//     workload path or one of the declared component
//     paths.
//   - "does_not_touch"   - the commit was fetched successfully and no changed
//     file intersects the workload/component paths.
//   - "unknown"          - any other reason: unsupported host, unparseable
//     revision, API failure, private-repo auth failure,
//     or empty workload path.
const (
	commitRelevanceTouches      = "touches"
	commitRelevanceDoesNotTouch = "does_not_touch"
	commitRelevanceUnknown      = "unknown"
)

// CommitRelevance is the result of classifying a reconciled GitHub commit
// against the workload's Git surface. Fields are populated as far as the
// lookup could get; Reason is always human-readable and is the single thing
// the rendering layer shows when State is "unknown" so the operator can see
// why the check degraded. CommitMessage is the raw commit message body and
// is treated as untrusted external text by the renderer; the page also
// never carries the full message — only a short, flattened summary line.
type CommitRelevance struct {
	State          string   // touches | does_not_touch | unknown
	RepoURL        string   // e.g. https://github.com/owner/repo
	Revision       string   // the full Flux revision string the lookup tried
	SHA            string   // the bare SHA the API was queried with
	WorkloadPath   string   // repository-relative workload path that was checked
	ComponentPaths []string // repository-relative component paths (issue #134)
	MatchingPaths  []string // subset of changed files that matched
	CommitMessage  string   // short, flattened message; treated as untrusted
	Reason         string   // short explanation; shown only when State == "unknown"
}

// parseGitHubRepoURL extracts the owner/name from a GitHub repository URL.
// Accepted forms:
//   - https://github.com/<owner>/<repo>[.git]
//   - http://github.com/<owner>/<repo>[.git]
//   - git@github.com:<owner>/<repo>[.git]
//   - ssh://git@github.com/<owner>/<repo>[.git]
//
// Non-github.com hosts (a self-hosted Enterprise host, a GitLab URL) return
// ("", "", false) so the lookup degrades to "unknown" rather than guessing.
// Trailing ".git", trailing slashes, and the auth segment are stripped before
// the owner/repo pair is extracted. This is a string parser, not a URL parser:
// the GitHub Enterprise case has too many forms to be worth a full parse.
func parseGitHubRepoURL(raw string) (owner, name string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}
	// Normalise the scp-style ssh form ("git@github.com:owner/repo")
	// to "ssh://git@github.com/owner/repo" so the url.Parse below can
	// extract the host: the standard library treats the scp form as a
	// single opaque path.
	if i := strings.Index(raw, "@"); i >= 0 && !strings.Contains(raw[i:], "://") {
		// Find the first ':' after the '@', which separates the
		// host from the path in scp syntax.
		rest := raw[i+1:]
		if j := strings.Index(rest, ":"); j >= 0 {
			host := rest[:j]
			path := rest[j+1:]
			raw = "ssh://" + raw[:i] + "@" + host + "/" + path
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// Maybe the input was just "github.com/owner/repo"; split on '/'.
		parts := strings.Split(strings.TrimLeft(raw, "/"), "/")
		return matchGitHubHost(parts)
	}
	host := strings.ToLower(u.Host)
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	if host != "github.com" {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	// parts is [owner, repo]; reject anything longer so a stray
	// fragment does not produce a malformed lookup.
	return splitOwnerRepo(parts)
}

// matchGitHubHost turns ["github.com", owner, repo(.git?)] into (owner, repo)
// for the case where the input lacked a scheme and the host ended up in
// the path. Anything other than exactly three path elements is rejected.
func matchGitHubHost(parts []string) (owner, name string, ok bool) {
	if len(parts) == 3 && strings.EqualFold(parts[0], "github.com") {
		return splitOwnerRepo(parts[1:])
	}
	return "", "", false
}

// splitOwnerRepo turns [owner, repo] into (owner, repo-without-.git).
// Rejects empty entries so a stray fragment or double slash cannot
// produce a malformed repo lookup.
func splitOwnerRepo(parts []string) (owner, name string, ok bool) {
	if len(parts) != 2 {
		return "", "", false
	}
	o, r := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if o == "" || r == "" {
		return "", "", false
	}
	return o, strings.TrimSuffix(r, ".git"), true
}

// parseFluxRevisionSHA extracts a usable SHA from a Flux revision string.
// Flux v2 stamps revisions in the form:
//
//	refs/heads/<branch>@sha1:<40-char-hex>
//	refs/tags/<tag>@sha1:<40-char-hex>
//	<branch>@sha1:<40-char-hex>
//	sha1:<40-char-hex>
//	<40-char-hex>
//
// Any revision string that does not carry a 40-character lowercase or
// uppercase hex SHA returns ("", false) so the GitHub lookup degrades to
// "unknown" rather than firing an API request that the server will reject.
// The algorithm prefix is hard-coded to "sha1" because that is what Flux
// stamps today; a future "sha256:" prefix would be a separate change so
// it is rejected rather than silently coerced.
func parseFluxRevisionSHA(rev string) (sha string, ok bool) {
	rev = strings.TrimSpace(rev)
	if rev == "" {
		return "", false
	}
	// Accept either "<algo>:<hex>" (when the part before ":" looks like
	// a Flux ref) or a bare 40-char hex. The two arms are kept separate
	// so a future algorithm prefix is a single-line change rather than
	// a rewrite of this branch.
	if i := strings.Index(rev, ":"); i >= 0 {
		head := rev[:i]
		algo := head
		if j := strings.LastIndex(head, "@"); j >= 0 {
			algo = head[j+1:]
		}
		if algo != "sha1" {
			return "", false
		}
		rev = rev[i+1:]
	}
	if !isHex40(rev) {
		return "", false
	}
	return strings.ToLower(rev), true
}

// isHex40 is true for a 40-character string of [0-9a-fA-F]. SHA-1 is the
// algorithm Flux stamps today; a 64-character SHA-256 revision is not
// currently produced by Flux but the helper is kept strict so the parser
// does not silently accept a truncated value.
func isHex40(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// pathIntersects reports whether any changed file lives under one of the
// declared workload paths. The matching paths are returned so the renderer
// can list exactly which files were the trigger; the workload path and any
// declared component paths are all considered equivalent (a component is
// part of the workload's effective Git surface per #134).
//
// All comparisons are done on cleaned, repository-relative paths: leading
// and trailing slashes are stripped, ".." segments are collapsed, and the
// match is a path-prefix check so a workload at "apps/payments" matches a
// changed file at "apps/payments/deployment.yaml". The comparison is also
// anchored at the path boundary, so a workload at "app" does NOT match a
// changed file at "application/x" — the prefix has to land on a segment
// boundary, otherwise unrelated directories fuse.
func pathIntersects(workloadPath string, componentPaths, changedFiles []string) []string {
	var matches []string
	roots := make([]string, 0, 1+len(componentPaths))
	if w := cleanRepoPath(workloadPath); w != "" {
		roots = append(roots, w)
	}
	for _, c := range componentPaths {
		if cp := cleanRepoPath(c); cp != "" && cp != cleanRepoPath(workloadPath) {
			roots = append(roots, cp)
		}
	}
	if len(roots) == 0 {
		return nil
	}
	for _, f := range changedFiles {
		cf := cleanRepoPath(f)
		if cf == "" {
			continue
		}
		for _, root := range roots {
			if cf == root || strings.HasPrefix(cf, root+"/") {
				matches = append(matches, f)
				break
			}
		}
	}
	return matches
}

// resolveWorkloadPaths normalizes the workload path and each declared
// component path to repository-relative form. A component is relative to
// the Kustomization's spec.path, not to the repo root, so each is resolved
// against the workload path: a component "../shared" under workload
// "apps/payments/prod" resolves to "apps/payments/shared". After
// normalization, any path that still sits above the repo root (a
// malformed spec whose components reference the parent of the repo root)
// is reported as not-ok; a component that resolves to a path outside the
// repo root would match changed files that are not part of this
// workload's Git surface, so the caller degrades to "unknown".
func resolveWorkloadPaths(workloadPath string, componentPaths []string) ([]string, bool) {
	base := cleanRepoPath(workloadPath)
	if base == "" {
		return nil, false
	}
	resolved := make([]string, 0, len(componentPaths))
	for _, c := range componentPaths {
		// cleanRepoPath strips ".." segments, so decide first from the raw
		// value whether the component needs to be resolved against the
		// workload path (it contains a traversal) or is already a
		// repo-relative path that can be used as-is.
		if hasTraversal(c) {
			if rel := joinRepoPaths(base, c); rel == "" {
				// Escapes the repo root: reject the whole lookup.
				return nil, false
			} else {
				resolved = append(resolved, rel)
			}
			continue
		}
		if rel := cleanRepoPath(c); rel != "" {
			resolved = append(resolved, rel)
		}
	}
	return resolved, true
}

// hasTraversal reports whether a raw component path contains a ".." path
// segment, i.e. whether it is relative to the workload path and must be
// resolved against it.
func hasTraversal(p string) bool {
	for _, seg := range strings.Split(strings.TrimLeft(p, "/"), "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// joinRepoPaths resolves a possibly-traversal component path against a
// base repo-relative path, returning "" when the result escapes the repo
// root. Uses repository (Unix) path semantics. The component is split on
// its raw form: ".." segments are the very thing being resolved, so they
// must survive (cleanRepoPath would have dropped them).
func joinRepoPaths(base, comp string) string {
	parts := strings.Split(cleanRepoPath(base), "/")
	for _, seg := range strings.Split(strings.TrimLeft(comp, "/"), "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(parts) == 0 {
				// Escapes the repo root.
				return ""
			}
			parts = parts[:len(parts)-1]
		default:
			parts = append(parts, seg)
		}
	}
	return strings.Join(parts, "/")
}

// cleanRepoPath trims leading/trailing slashes and collapses redundant
// separators without using filepath.Clean (which is OS-dependent — this is
// always a Unix-style Git path). A leading ".." or "." collapses to "" so
// the caller can drop it; the digest never renders traversal attempts.
func cleanRepoPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimLeft(p, "/")
	p = strings.TrimRight(p, "/")
	if p == "" {
		return ""
	}
	// Replace any run of '/' with a single one, then split on '/' so
	// ".." segments can be removed the same way path.Clean would for a
	// repository-relative path.
	parts := strings.Split(strings.ReplaceAll(p, "\\", "/"), "/")
	out := parts[:0]
	for _, seg := range parts {
		switch seg {
		case "", ".":
			continue
		case "..":
			// Reaching a parent of the repo root is meaningless here;
			// drop the segment so we never emit a path that escapes.
			continue
		default:
			out = append(out, seg)
		}
	}
	return strings.Join(out, "/")
}

// fetchCommitFiles retrieves the list of files changed in a single commit.
// The endpoint returns a Commit object whose "files" array carries one entry
// per changed path; we read just the "filename" of each, the minimum needed
// to answer "did this commit touch the workload?". A 404 (the most common
// non-success — private-repo auth failure, fork the token cannot see,
// never-existed SHA) is folded into the err return so the caller can label
// the relevance as "unknown". Network errors, timeouts, and 5xx all bubble
// up untouched so the caller can decide whether to log them.
//
// The body is capped at 1 MiB before decoding: the API can return arbitrarily
// large files arrays for mass-rename commits, and the cap is large enough
// to handle a thousand changed files with long paths but small enough to
// fail fast on a misconfigured proxy returning a verbose error body.
// fetchCommitFiles retrieves the full list of files changed in a single
// commit, following the endpoint's pagination. ownerRepo is the
// "owner/name" the commit belongs to — derived from the workload's
// GitRepository URL, not necessarily the configured GITHUB_REPO the client
// was built against (the token and HTTP client are reused across repos; only
// the /repos/ path changes).
//
// The commit endpoint is paginated: a large commit (a mass rename) can
// spread its files across multiple pages of up to 300. We follow the Link
// rel="next" header until there is no next page so an incomplete file list
// never turns into a confident "does not touch" — the whole point of the
// lookup (issue #135) is a positive negative, and that only holds when the
// file set is complete. A hard page cap bounds a misbehaving proxy that
// repeats rel="next"; hitting it is an error so the caller degrades to
// "unknown".
//
// A 404 (the most common non-success — private-repo auth failure, a fork the
// token cannot see, a never-existed SHA) is folded into the err return so the
// caller can label the relevance "unknown". Network errors, timeouts, and
// 5xx all bubble up untouched so the caller can decide whether to log them.
func (g *gitHubClient) fetchCommitFiles(ctx context.Context, ownerRepo, sha string) ([]string, error) {
	if g == nil {
		return nil, fmt.Errorf("github: no client")
	}
	if ownerRepo == "" {
		return nil, fmt.Errorf("github: empty repo")
	}
	if sha == "" {
		return nil, fmt.Errorf("github: empty sha")
	}

	// 300 is the documented per-page maximum for this endpoint; per_page is
	// fixed on the first page and carried forward in each rel="next" URL.
	url := g.apiURL + "/repos/" + ownerRepo + "/commits/" + sha + "?per_page=300"
	// 300 files/page * 100 pages = 30k files, far beyond any real commit.
	const maxPages = 100
	var out []string
	for i := 0; ; i++ {
		if i >= maxPages {
			return nil, fmt.Errorf("github: commit %s file list incomplete (reached %d pages)", sha, maxPages)
		}
		files, next, err := g.fetchCommitPage(ctx, url)
		if err != nil {
			return nil, err
		}
		out = append(out, files...)
		if next == "" {
			break
		}
		url = next
	}
	return out, nil
}

// fetchCommitPage fetches one page of the commit endpoint and returns the
// file names on that page plus the URL of the next page (from the Link
// rel="next" header) or "" when there is no next page.
func (g *gitHubClient) fetchCommitPage(ctx context.Context, url string) ([]string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	g.setHeaders(req)

	resp, err := g.hc.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, "", fmt.Errorf("github: commit not found or token lacks access")
	}
	if resp.StatusCode == http.StatusForbidden {
		// Rate-limited or private-repo permission denied; the message
		// is not actionable for the operator, so collapse to one shape.
		return nil, "", fmt.Errorf("github: commit forbidden (rate limit or permissions)")
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, "", fmt.Errorf("github commit: %s: %s", resp.Status, string(body))
	}
	var payload struct {
		Files []struct {
			Filename string `json:"filename"`
		} `json:"files"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return nil, "", fmt.Errorf("github commit decode: %w", err)
	}
	out := make([]string, 0, len(payload.Files))
	for _, f := range payload.Files {
		if f.Filename != "" {
			out = append(out, f.Filename)
		}
	}
	next := ""
	if link := resp.Header.Get("Link"); link != "" {
		next = parseLinkNext(link)
	}
	return out, next, nil
}

// parseLinkNext extracts the next-page URL from a GitHub Link header
// ("<url>; rel=\"next\", <url>; rel=\"last\"") or "" when the header has no
// rel="next" part. The URL is the part wrapped in <...>; we take the whole
// thing so its per_page/page query params are preserved verbatim.
func parseLinkNext(link string) string {
	for _, part := range strings.Split(link, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		i := strings.IndexByte(part, '<')
		j := strings.LastIndexByte(part, '>')
		if i >= 0 && j > i {
			return part[i+1 : j]
		}
		return part
	}
	return ""
}

// fetchCommitMessage returns the first line of the commit message, capped
// to a safe length and flattened so a single newline cannot smuggle a
// second line into the evidence. ownerRepo carries the parsed source
// "owner/name" (see fetchCommitFiles); the client's token and transport are
// reused. Returns "" on any failure; the caller is responsible for the
// untrusted fence and never has to gate on a missing message.
func (g *gitHubClient) fetchCommitMessage(ctx context.Context, ownerRepo, sha string) string {
	if g == nil || ownerRepo == "" || sha == "" {
		return ""
	}
	u := g.apiURL + "/repos/" + ownerRepo + "/commits/" + sha
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	g.setHeaders(req)
	resp, err := g.hc.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return ""
	}
	var payload struct {
		Commit struct {
			Message string `json:"message"`
		} `json:"commit"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&payload); err != nil {
		return ""
	}
	msg := payload.Commit.Message
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	return strings.TrimSpace(msg)
}

// classifyCommit is the convenience entry point the enrichment layer uses.
// It parses the repo URL and revision, fetches the commit's files if both
// parsed and the workload path is non-empty, and classifies the result as
// touches/does_not_touch/unknown. Failures at any step degrade to a single
// CommitRelevance with State == "unknown" so the renderer can present a
// neutral note ("could not determine") rather than pretending the lookup
// did not happen.
//
// componentPaths may be nil; they are accepted separately so callers that
// do not yet have #134's KustomizationTopology in their hands can still
// classify against the workload path alone. The shape stays the same once
// #134 lands — only the slice gets populated from there.
func classifyCommit(ctx context.Context, gh *gitHubClient, repoURL, revision, workloadPath string, componentPaths []string) CommitRelevance {
	out := CommitRelevance{
		RepoURL:        repoURL,
		Revision:       revision,
		WorkloadPath:   workloadPath,
		ComponentPaths: append([]string(nil), componentPaths...),
		State:          commitRelevanceUnknown,
	}
	if gh == nil {
		out.Reason = "GitHub client not configured (GITHUB_REPO/GITHUB_TOKEN unset)"
		return out
	}
	if repoURL == "" {
		out.Reason = "no GitOps repository URL resolved for the workload"
		return out
	}
	owner, name, ok := parseGitHubRepoURL(repoURL)
	if !ok {
		out.Reason = "GitOps repository host is not github.com"
		return out
	}
	// The commit is fetched from the repo the workload's GitRepository
	// resolved to — owner/name above — not from the configured GITHUB_REPO
	// the client was built against. The client's token and HTTP transport
	// are reused across repos; only the /repos/ path changes. A workload
	// whose source lives in a different (GitHub) repo than the
	// issue-tracking one is a perfectly valid lookup, and treating it as
	// "unknown" would turn a working cross-repo deployment into a silent
	// negative.
	ownerRepo := owner + "/" + name
	sha, ok := parseFluxRevisionSHA(revision)
	if !ok {
		out.Reason = "Flux revision is not SHA-bearing: " + truncate(revision, 80)
		return out
	}
	if workloadPath == "" {
		out.Reason = "no workload path resolved (resolveRepoPaths returned nothing)"
		return out
	}
	// A Kustomization's declared components are relative to its spec.path,
	// not to the repo root, so they are resolved against the workload path
	// before the path intersection is computed. A component that escapes
	// the repo root after resolution (a malformed spec) is dropped: it
	// would match things that are not part of this workload's Git surface.
	resolved, ok := resolveWorkloadPaths(workloadPath, componentPaths)
	if !ok {
		out.Reason = "workload path is not a valid repo-relative path"
		return out
	}
	out.WorkloadPath = cleanRepoPath(workloadPath)
	out.ComponentPaths = append([]string(nil), resolved...)
	out.SHA = sha
	files, err := gh.fetchCommitFiles(ctx, ownerRepo, sha)
	if err != nil {
		out.Reason = truncate(err.Error(), 200)
		return out
	}
	matches := pathIntersects(out.WorkloadPath, out.ComponentPaths, files)
	out.MatchingPaths = matches
	if len(matches) > 0 {
		out.State = commitRelevanceTouches
		out.CommitMessage = gh.fetchCommitMessage(ctx, ownerRepo, sha)
		return out
	}
	out.State = commitRelevanceDoesNotTouch
	out.CommitMessage = gh.fetchCommitMessage(ctx, ownerRepo, sha)
	return out
}

// clamp lives in enrich.go; the GitHub body builder reuses it.

// renderEvidence assembles the cluster evidence collected during enrichment
// into one Markdown section. Returns "" if there is nothing to show so the
// <details> block is omitted entirely.
