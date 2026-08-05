package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Report is one correlated incident, ready to deliver.
type Report struct {
	Group      Group
	Enrichment Enrichment
	PriorSeen  int
	Narrative  string
}

const narratePrompt = `You are triaging Kubernetes alerts for a homelab cluster.
Write 2-4 sentences for the operator: what is broken, the most likely cause, and
what to check first.

The cluster has ALREADY been inspected on your behalf. Everything under EVIDENCE
was read live from the Kubernetes API moments ago. Treat it as first-hand fact.

Rules:
- Never comment on your own limitations. Do not say you did not check the
  cluster, cannot access it, or lack information. The evidence below IS the
  check. If it is thin, reason from the alert itself instead.
- "No unhealthy nodes" and "no recent warning events" are findings, not gaps.
  Use them to rule causes out.
- Some alerts are self-describing. Restate what it means operationally and stop;
  do not pad.
- Name a cause only where the evidence or the alert supports one. If several are
  plausible, give the likeliest and say what would distinguish them.
- If a Flux resource reconciled or went NotReady near the alert, say so - a
  recent deploy is the first thing worth ruling out.
- No preamble, no bullet points, no markdown headers. Plain prose only.`

type chatReq struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
	Stream   bool      `json:"stream"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResp struct {
	Choices []struct {
		Message struct {
			Content          string `json:"content"`
			ReasoningContent string `json:"reasoning_content"`
		} `json:"message"`
	} `json:"choices"`
}

// Narrate asks the model for a plain-language story. A failure here is not
// fatal: the digest still ships with its evidence, just without the summary.
func Narrate(cfg Config, r Report) string {
	if cfg.LiteLLMURL == "" {
		return ""
	}
	body, err := json.Marshal(chatReq{
		Model: cfg.Model,
		Messages: []message{
			{Role: "system", Content: narratePrompt},
			{Role: "user", Content: renderEvidence(r)},
		},
	})
	if err != nil {
		logf("narrate: marshal: %v", err)
		return ""
	}

	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.LiteLLMURL, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		logf("narrate: request: %v", err)
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.LiteLLMKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.LiteLLMKey)
	}

	hc := &http.Client{Timeout: cfg.NarrateTimeout}
	resp, err := hc.Do(req)
	if err != nil {
		logf("narrate: %v", err)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logf("narrate: %s", resp.Status)
		return ""
	}
	var out chatResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		logf("narrate: decode: %v", err)
		return ""
	}
	if len(out.Choices) == 0 {
		return ""
	}
	// Some reasoning models put the answer in content and thinking in
	// reasoning_content; others invert it when content comes back empty.
	if c := strings.TrimSpace(out.Choices[0].Message.Content); c != "" {
		return c
	}
	return strings.TrimSpace(out.Choices[0].Message.ReasoningContent)
}

func renderEvidence(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Grouping: %s (%s)\n", r.Group.Key, r.Group.Reason)
	if r.Group.Node != "" {
		fmt.Fprintf(&b, "Node: %s\n", r.Group.Node)
	}
	if len(r.Group.Namespaces) > 0 {
		fmt.Fprintf(&b, "Namespaces: %s\n", strings.Join(r.Group.Namespaces, ", "))
	}
	if r.PriorSeen > 0 {
		fmt.Fprintf(&b, "History: this shape has fired %d time(s) recently.\n", r.PriorSeen)
	} else {
		b.WriteString("History: not seen recently.\n")
	}

	b.WriteString("\nAlerts:\n")
	for _, a := range r.Group.Alerts {
		fmt.Fprintf(&b, "- [%s] %s", a.severity(), a.name())
		if s := firstAnnotation(a); s != "" {
			fmt.Fprintf(&b, ": %s", s)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "\nEVIDENCE (read live from the Kubernetes API; scope: %s)\n", orUnknown(r.Enrichment.Scope))
	writeFinding(&b, "Unhealthy nodes", r.Enrichment.Nodes, "all nodes Ready, none under pressure or cordoned")
	writeFinding(&b, "Unhealthy pods", r.Enrichment.UnhealthyPods, "no unhealthy pods in scope")
	writeFinding(&b, "Recent warning events", r.Enrichment.Events, "no warning events in the window")
	writeFinding(&b, "Recent Flux activity", r.Enrichment.RecentChanges, "no reconciles or failures in the window, so a recent deploy is unlikely")
	return b.String()
}

// writeFinding renders a section, stating the negative explicitly when empty so
// the model can rule causes out instead of treating silence as missing data.
func writeFinding(b *strings.Builder, title string, items []string, whenEmpty string) {
	if len(items) == 0 {
		fmt.Fprintf(b, "\n%s: %s\n", title, whenEmpty)
		return
	}
	fmt.Fprintf(b, "\n%s:\n", title)
	for _, s := range items {
		fmt.Fprintf(b, "- %s\n", s)
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func firstAnnotation(a Alert) string {
	for _, k := range []string{"summary", "message", "description"} {
		if v := strings.TrimSpace(a.Annotations[k]); v != "" {
			return truncate(v, 200)
		}
	}
	return ""
}

type discordEmbed struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Color       int    `json:"color"`
	Fields      []struct {
		Name   string `json:"name"`
		Value  string `json:"value"`
		Inline bool   `json:"inline"`
	} `json:"fields,omitempty"`
	Footer struct {
		Text string `json:"text"`
	} `json:"footer"`
}

func severityColor(s string) int {
	switch s {
	case "critical":
		return 0xD32F2F
	case "warning":
		return 0xF9A825
	default:
		return 0x1E88E5
	}
}

// Deliver posts one incident to the digest webhook.
func Deliver(cfg Config, r Report) error {
	if cfg.DiscordURL == "" {
		return fmt.Errorf("no discord webhook configured")
	}

	var desc strings.Builder
	if r.Narrative != "" {
		desc.WriteString(r.Narrative)
		desc.WriteString("\n\n")
	}
	desc.WriteString("**Alerts**\n")
	for _, a := range r.Group.Alerts {
		fmt.Fprintf(&desc, "• `%s` %s", a.severity(), a.name())
		if ns := a.namespace(); ns != "" {
			fmt.Fprintf(&desc, " — %s", ns)
		}
		desc.WriteString("\n")
	}
	writeDiscordSection(&desc, "Unhealthy nodes", r.Enrichment.Nodes)
	writeDiscordSection(&desc, "Unhealthy pods", r.Enrichment.UnhealthyPods)
	writeDiscordSection(&desc, "Recent events", r.Enrichment.Events)
	writeDiscordSection(&desc, "Recent changes", r.Enrichment.RecentChanges)

	embed := discordEmbed{
		Title:       r.Group.Title(),
		Description: clamp(desc.String(), 3900),
		Color:       severityColor(r.Group.Severity()),
	}
	seen := "first time seen"
	if r.PriorSeen > 0 {
		seen = fmt.Sprintf("seen %d time(s) recently", r.PriorSeen)
	}
	embed.Footer.Text = fmt.Sprintf("%s · %s · %s", r.Group.Key, r.Group.Severity(), seen)

	body, err := json.Marshal(map[string]any{"embeds": []discordEmbed{embed}})
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Post(cfg.DiscordURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("discord: %s", resp.Status)
	}
	return nil
}

func writeDiscordSection(b *strings.Builder, title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "\n**%s**\n", title)
	for _, s := range items {
		fmt.Fprintf(b, "• %s\n", s)
	}
}
