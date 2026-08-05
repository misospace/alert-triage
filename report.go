package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
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
- An alert name uses the vocabulary of whatever emitted it, which is often not
  Kubernetes. Read the labels and annotation before assuming a word means the
  Kubernetes object of the same name: "deployment" may mean an upstream routing
  target, "node" a database member, "cluster" an application's own cluster. The
  labels say which subject is meant - trust them over the name.
- Alerts from an application concern that application's internal state, not the
  health of the pods running it. Do not infer that a workload is down because it
  reported a fault in something it manages.
- "No unhealthy nodes" and "no recent warning events" are findings, not gaps.
  Use them to rule causes out.
- Some alerts are self-describing. Restate what it means operationally and stop;
  do not pad.
- Refer to a subject by the name its label gives it and say nothing about what
  it is. You do not know whether it is local or remote, a pod or a proxy, one
  machine or a pool. Never generalise from one member's name to the rest: if
  three things are listed and one is called "self-hosted", that says nothing
  about the other two. Write "three targets (a, b, c)", not "three <adjective>
  targets".
- Name a cause only where the evidence or the alert supports one. If several are
  plausible, give the likeliest and say what would distinguish them.
- Anything under BACKGROUND is unrelated noise until proven otherwise. Never
  speculate that it might be connected, and never write a sentence of the form
  "if X also runs there, it may be worth checking". Mention it only when it
  names the same resource, node or namespace as the alert - and then say plainly
  that it does. Otherwise leave it out entirely.
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
		if l := contextLabels(a); l != "" {
			fmt.Fprintf(&b, "  labels: %s\n", l)
		}
	}

	fmt.Fprintf(&b, "\nEVIDENCE (read live from the Kubernetes API; scope: %s)\n", orUnknown(r.Enrichment.Scope))
	writeFinding(&b, "Unhealthy nodes", r.Enrichment.Nodes, "all nodes Ready, none under pressure or cordoned")
	writeFinding(&b, "Unhealthy pods", r.Enrichment.UnhealthyPods, "no unhealthy pods in scope")
	writeFinding(&b, "Recent warning events", r.Enrichment.Events, "no warning events in the window")
	writeFinding(&b, "Recent Flux activity", r.Enrichment.RecentChanges, "no reconciles or failures in the window, so a recent deploy is unlikely")

	if len(r.Enrichment.Ambient) > 0 {
		b.WriteString("\nBACKGROUND - everything else happening in the cluster right now.\n")
		b.WriteString("This is NOT known to involve the alert above. A homelab always has\n")
		b.WriteString("unrelated noise in flight; do not offer any of it as a cause unless it\n")
		b.WriteString("names the same resource, node or namespace as the alert.\n")
		for _, s := range r.Enrichment.Ambient {
			fmt.Fprintf(&b, "- %s\n", s)
		}
	}
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

// boilerplateLabels carry no meaning for a reader; everything else is shown,
// because the label that disambiguates an alert is often domain-specific
// (litellm_model_name, device, mountpoint) and cannot be enumerated up front.
var boilerplateLabels = map[string]bool{
	"alertname": true, "severity": true, "prometheus": true, "__name__": true,
	"endpoint": true, "container": true, "pod_template_hash": true,
	"prometheus_replica": true, "service": true,
}

// contextLabels renders the labels that help interpret an alert. Without these
// the model sees only the alert name, and alert names use the vocabulary of
// whatever emitted them rather than Kubernetes'.
func contextLabels(a Alert) string {
	keys := make([]string, 0, len(a.Labels))
	for k, v := range a.Labels {
		if v == "" || boilerplateLabels[k] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+a.Labels[k])
	}
	return strings.Join(parts, " ")
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
