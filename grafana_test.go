package main

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGrafanaExploreURLShape(t *testing.T) {
	base := "https://grafana.example.com"
	from := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	to := from.Add(10 * time.Minute)

	got := grafanaExplore(base, "prom", `up{job="api"}`, from, to, "prometheus")
	if !strings.HasPrefix(got, base+"/explore?left=") {
		t.Fatalf("expected /explore?left= prefix, got %q", got)
	}
	if !strings.Contains(got, "prom") {
		t.Fatalf("expected datasource uid in URL, got %q", got)
	}
	if !strings.Contains(got, "up%7Bjob%3D%22api%22%7D") && !strings.Contains(got, "up") {
		t.Fatalf("expected PromQL expression in URL, got %q", got)
	}
	// RFC3339 with colons URL-encoded as %3A
	if !strings.Contains(got, "2026-01-02T03%3A04%3A05Z") {
		t.Fatalf("expected from timestamp in URL, got %q", got)
	}
}

func TestGrafanaExploreZeroWindowSuppressed(t *testing.T) {
	if got := grafanaExplore("https://g", "ds", "up", time.Time{}, time.Time{}, "prometheus"); got != "" {
		t.Fatalf("expected zero window to produce no URL, got %q", got)
	}
}

func TestGrafanaLinksZeroWindowGroupSuppressed(t *testing.T) {
	cfg := &Config{
		GrafanaURL:       "https://grafana.example.com",
		GrafanaMetricsDS: "prom",
		GrafanaLogsDS:    "loki",
	}
	g := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "TestAlert"}}}} // StartsAt and EndsAt both zero
	m, l := grafanaLinks(cfg, "up", "kube-system", groupWindow(g))
	if m != "" || l != "" {
		t.Fatalf("expected no links for zero-window group, got metrics=%q logs=%q", m, l)
	}
}

func TestGroupWindowActiveAlertFallsBackToStartsAt(t *testing.T) {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	g := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "Up"}, StartsAt: start}}} // EndsAt zero: still active
	w := groupWindow(g)
	if !w[0].Equal(start) || !w[1].Equal(start) {
		t.Fatalf("expected [start, start] for active alert, got [%s, %s]", w[0], w[1])
	}
}

func TestGrafanaLinksOmittedWhenConfigMissing(t *testing.T) {
	cfg := &Config{} // GRAFANA_URL unset
	m, l := grafanaLinks(cfg, "up", "kube-system", [2]time.Time{time.Now(), time.Now()})
	if m != "" || l != "" {
		t.Fatalf("expected empty links, got metrics=%q logs=%q", m, l)
	}
}

func TestGrafanaLinksMetricsOnlyWithoutLogsDS(t *testing.T) {
	cfg := &Config{
		GrafanaURL:       "https://grafana.example.com",
		GrafanaMetricsDS: "prom",
	}
	m, l := grafanaLinks(cfg, "up", "kube-system", [2]time.Time{time.Now(), time.Now().Add(time.Minute)})
	if m == "" {
		t.Fatalf("expected metrics link, got empty")
	}
	if l != "" {
		t.Fatalf("expected logs link to be omitted, got %q", l)
	}
}

func TestGrafanaLinksLogsOnlyWithoutMetricsDS(t *testing.T) {
	cfg := &Config{
		GrafanaURL:    "https://grafana.example.com",
		GrafanaLogsDS: "loki",
	}
	m, l := grafanaLinks(cfg, "up", "kube-system", [2]time.Time{time.Now(), time.Now().Add(time.Minute)})
	if m != "" {
		t.Fatalf("expected metrics link to be omitted, got %q", m)
	}
	if l == "" {
		t.Fatalf("expected logs link, got empty")
	}
}

func TestEnvGrafanaURLDropsRelative(t *testing.T) {
	t.Setenv("GRAFANA_URL", "/grafana")
	if got := envGrafanaURL("GRAFANA_URL"); got != "" {
		t.Fatalf("expected relative URL to be dropped, got %q", got)
	}
}

func TestEnvGrafanaURLAcceptsAbsolute(t *testing.T) {
	t.Setenv("GRAFANA_URL", "https://grafana.example.com/")
	if got := envGrafanaURL("GRAFANA_URL"); got != "https://grafana.example.com" {
		t.Fatalf("expected trailing slash stripped, got %q", got)
	}
}

func TestNamespaceLabelEmptySuppressed(t *testing.T) {
	if got := namespaceLabel(""); got != "" {
		t.Fatalf("expected empty namespace to produce empty label, got %q", got)
	}
	if got := namespaceLabel("kube-system"); got != `{namespace="kube-system"}` {
		t.Fatalf("unexpected label: %q", got)
	}
}

// TestNamespaceLabelEscapesValues verifies the LogQL literal in the
// Explore link is built through quoteLogValue so a `"` or `\` in the
// namespace cannot break out of the quoted literal and inject selector
// syntax. The envelope selector shape is the one Grafana decodes and
// parses, so URL-encoding at the outer JSON marshaler is not enough.
// TestGrafanaLinksRedactCredentialBearingExpression (#278): scrape-target
// URLs and hard-coded bearer params do occur in rule expressions, and the
// Explore links embedded in the issue body and chat digest are durable and
// URL-quoted, not redacted. The values feeding both links come through
// firstExpression/firstNamespace, so the credential must be gone before
// embedding — while the link stays a valid URL whose left= envelope is
// still decodable JSON with the benign query text intact.
func TestGrafanaLinksRedactCredentialBearingExpression(t *testing.T) {
	cfg := &Config{
		GrafanaURL:       "https://grafana.example.com",
		GrafanaMetricsDS: "prom",
		GrafanaLogsDS:    "loki",
	}
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	alerts := []Alert{{
		Labels: map[string]string{"alertname": "ApiDown", "namespace": "prod token=synthetic-ns-secret"},
		Annotations: map[string]string{
			"expr": `up{job="api"} > 0 or probe{scrape_url="http://svc/metrics?password=synthetic-expr-password"} or http_headers{authorization="Bearer abcdef0123456789"}`,
		},
		StartsAt: start,
		EndsAt:   start.Add(10 * time.Minute),
	}}
	g := Group{Alerts: alerts}
	metrics, logs := grafanaLinks(cfg, firstExpression(alerts), firstNamespace(alerts), groupWindow(g))
	if metrics == "" || logs == "" {
		t.Fatalf("expected both links, got metrics=%q logs=%q", metrics, logs)
	}
	for _, secret := range []string{"synthetic-expr-password", "abcdef0123456789", "synthetic-ns-secret"} {
		if strings.Contains(metrics, secret) || strings.Contains(logs, secret) {
			t.Fatalf("secret %q leaked into Grafana links:\nmetrics=%q\nlogs=%q", secret, metrics, logs)
		}
	}
	// Link validity: query escaping intact, envelope still JSON, and the
	// benign query shapes survive so the operator lands on a real query.
	decoded := map[string]string{}
	for kind, link := range map[string]string{"metrics": metrics, "logs": logs} {
		u, err := url.Parse(link)
		if err != nil {
			t.Fatalf("%s link is not a valid URL: %v\n%s", kind, err, link)
		}
		var doc struct {
			Queries []struct {
				Expr string `json:"expr"`
			} `json:"queries"`
		}
		left := u.Query().Get("left")
		if err := json.Unmarshal([]byte(left), &doc); err != nil {
			t.Fatalf("%s link left= envelope is not valid JSON: %v\n%s", kind, err, left)
		}
		if len(doc.Queries) != 1 || !strings.Contains(doc.Queries[0].Expr, "[REDACTED]") {
			t.Fatalf("%s link query lost the redaction marker: %+v", kind, doc.Queries)
		}
		decoded[kind] = doc.Queries[0].Expr
	}
	if !strings.Contains(decoded["metrics"], `up{job="api"}`) {
		t.Errorf("benign PromQL must survive: %q", decoded["metrics"])
	}
	if !strings.Contains(decoded["logs"], `{namespace="prod`) {
		t.Errorf("benign LogQL selector must survive: %q", decoded["logs"])
	}
}

func TestNamespaceLabelEscapesValues(t *testing.T) {
	ns := `ns"a\b`
	want := `{namespace="ns\"a\\b"}`
	if got := namespaceLabel(ns); got != want {
		t.Fatalf("namespaceLabel(%q) = %q, want %q", ns, got, want)
	}
}
