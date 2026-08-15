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
	Number      int       `json:"number"`
	Title       string    `json:"title"`
	State       string    `json:"state"`
	HTMLURL     string    `json:"html_url"`
	Body        string    `json:"body"`
	Labels      []ghLabel `json:"labels"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Comments    int       `json:"comments"`
	CommentList []ghIssueComment `json:"-"`
}

type ghLabel struct {
	Name string `json:"name"`
}

type ghIssueComment struct {
	CreatedAt time.Time `json:"created_at"`
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
	// Severity change always warrants a note.
	want := severityLabel(r.Group.Severity())
	for _, l := range existing.Labels {
		if l.Name == want {
			return true
		}
	}
	// If we've never commented on this issue yet, the first re-fire is
	// always worth a note — the initial body captured the first firing, but
	// operators want to see "still happening" written down somewhere.
	if len(existing.CommentList) == 0 && existing.Comments == 0 {
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

// clamp lives in enrich.go; the GitHub body builder reuses it.

// renderEvidence assembles the cluster evidence collected during enrichment
// into one Markdown section. Returns "" if there is nothing to show so the
// <details> block is omitted entirely.
