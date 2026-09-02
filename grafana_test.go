package main

import (
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
