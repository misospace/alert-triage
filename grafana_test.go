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

// TestGroupWindowMalformedAlertNeverInverted covers the window the Explore
// links are built from. Alertmanager never sends an alert whose EndsAt
// precedes its StartsAt, but a malformed webhook payload can, and the
// inverted pair used to reach the operator as a link with an empty range
// (#364). Alerts whose timestamps do not line up must not invert the pair
// either, and the window must keep covering the alerts it covers today.
func TestGroupWindowMalformedAlertNeverInverted(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		name   string
		alerts []Alert
		want   [2]time.Time
	}{
		{"malformed alert alone", []Alert{
			{StartsAt: base.Add(time.Hour), EndsAt: base},
		}, [2]time.Time{base.Add(time.Hour), base.Add(time.Hour)}},
		{"malformed alert beside a resolved one", []Alert{
			{StartsAt: base.Add(time.Hour), EndsAt: base},
			{StartsAt: base, EndsAt: base.Add(10 * time.Minute)},
		}, [2]time.Time{base, base.Add(time.Hour)}},
		{"malformed alert beside an active one", []Alert{
			{StartsAt: base.Add(time.Hour), EndsAt: base},
			{StartsAt: base.Add(2 * time.Hour)},
		}, [2]time.Time{base.Add(time.Hour), base.Add(2 * time.Hour)}},
		{"resolved alert ended before a later alert started", []Alert{
			{EndsAt: base},
			{StartsAt: base.Add(time.Hour)},
		}, [2]time.Time{base, base.Add(time.Hour)}},
		{"malformed alert beside one without a start", []Alert{
			{StartsAt: base.Add(time.Hour), EndsAt: base.Add(-time.Hour)},
			{EndsAt: base},
		}, [2]time.Time{base, base.Add(time.Hour)}},
		{"malformed alert beside one that ended earlier", []Alert{
			{StartsAt: base.Add(time.Hour), EndsAt: base},
			{StartsAt: base.Add(-2 * time.Hour), EndsAt: base.Add(-time.Hour)},
		}, [2]time.Time{base.Add(-2 * time.Hour), base.Add(time.Hour)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := groupWindow(Group{Alerts: tc.alerts})
			if !w[0].Equal(tc.want[0]) || !w[1].Equal(tc.want[1]) {
				t.Fatalf("window = [%s, %s], want [%s, %s]", w[0], w[1], tc.want[0], tc.want[1])
			}
			if w[1].Before(w[0]) {
				t.Fatalf("window from %s is after to %s", w[0], w[1])
			}
			// every alert that carries both timestamps must stay inside the
			// window
			for _, a := range tc.alerts {
				start, end := alertWindow(a)
				if start.IsZero() || end.IsZero() {
					continue
				}
				if w[0].After(start) || w[1].Before(end) {
					t.Fatalf("window [%s, %s] does not cover the alert [%s, %s]", w[0], w[1], start, end)
				}
			}
		})
	}
}

// TestGroupWindowNeverInvertedForAnyTimestamps walks every combination of
// alert timestamps over a group of two alerts and over a group of three.
// The window must not come back inverted for any of them, and the order of
// the alerts must not change it.
func TestGroupWindowNeverInvertedForAnyTimestamps(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	stamps := []time.Time{{}, base, base.Add(time.Hour)}
	var alerts []Alert
	for _, s := range stamps {
		for _, e := range stamps {
			alerts = append(alerts, Alert{StartsAt: s, EndsAt: e})
		}
	}
	for i := range alerts {
		for j := range alerts {
			w := groupWindow(Group{Alerts: []Alert{alerts[i], alerts[j]}})
			if w[1].Before(w[0]) {
				t.Fatalf("window inverted for %+v and %+v: [%s, %s]", alerts[i], alerts[j], w[0], w[1])
			}
			reversed := groupWindow(Group{Alerts: []Alert{alerts[j], alerts[i]}})
			if !reversed[0].Equal(w[0]) || !reversed[1].Equal(w[1]) {
				t.Fatalf("window changed with the alert order: [%s, %s] and [%s, %s]", w[0], w[1], reversed[0], reversed[1])
			}
		}
	}
	for i := range alerts {
		for j := range alerts {
			for k := range alerts {
				group := []Alert{alerts[i], alerts[j], alerts[k]}
				w := groupWindow(Group{Alerts: group})
				if w[1].Before(w[0]) {
					t.Fatalf("window inverted for %+v: [%s, %s]", group, w[0], w[1])
				}
			}
		}
	}
}

// TestGroupWindowMalformedAlertKeepsItsStart pins the clamp direction. The
// alert's own start stays in the window, and the end moves up to meet it:
// the alert began at that moment, so the window covers it.
func TestGroupWindowMalformedAlertKeepsItsStart(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	start := base.Add(time.Hour)
	w := groupWindow(Group{Alerts: []Alert{{StartsAt: start, EndsAt: base}}})
	if !w[0].Equal(start) {
		t.Fatalf("expected from %s, got %s", start, w[0])
	}
	if !w[1].Equal(start) {
		t.Fatalf("expected the end clamped up to %s, got %s", start, w[1])
	}
}

// TestGroupWindowTimestampLessGroupStaysZeroPair keeps the zero pair alive.
// A group whose alerts carry no timestamps must still return the zero pair,
// and grafanaExplore suppresses it rather than linking the unix epoch.
func TestGroupWindowTimestampLessGroupStaysZeroPair(t *testing.T) {
	g := Group{Alerts: []Alert{
		{Labels: map[string]string{"alertname": "TestAlert"}},
		{Labels: map[string]string{"alertname": "OtherAlert"}},
	}}
	w := groupWindow(g)
	if !w[0].IsZero() || !w[1].IsZero() {
		t.Fatalf("expected the zero pair, got [%s, %s]", w[0], w[1])
	}
}

// TestGrafanaLinksRangeOrderedForMalformedAlert is the end-to-end check. The
// link the operator clicks must carry a range that starts before it ends,
// whether the alert behind it was malformed or not.
func TestGrafanaLinksRangeOrderedForMalformedAlert(t *testing.T) {
	cfg := &Config{
		GrafanaURL:       "https://grafana.example.com",
		GrafanaMetricsDS: "prom",
		GrafanaLogsDS:    "loki",
	}
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	alerts := []Alert{{
		Labels:      map[string]string{"alertname": "ApiDown", "namespace": "prod"},
		Annotations: map[string]string{"expr": `up{job="api"}`},
		StartsAt:    base.Add(time.Hour),
		EndsAt:      base,
	}}
	metrics, logs := grafanaLinks(cfg, firstExpression(alerts), firstNamespace(alerts), groupWindow(Group{Alerts: alerts}))
	if metrics == "" || logs == "" {
		t.Fatalf("expected both links, got metrics=%q logs=%q", metrics, logs)
	}
	for kind, link := range map[string]string{"metrics": metrics, "logs": logs} {
		u, err := url.Parse(link)
		if err != nil {
			t.Fatalf("%s link is not a valid URL: %v\n%s", kind, err, link)
		}
		var doc struct {
			Range struct {
				From string `json:"from"`
				To   string `json:"to"`
			} `json:"range"`
		}
		left := u.Query().Get("left")
		if err := json.Unmarshal([]byte(left), &doc); err != nil {
			t.Fatalf("%s link left= envelope is not valid JSON: %v\n%s", kind, err, left)
		}
		from, err := time.Parse(time.RFC3339, doc.Range.From)
		if err != nil {
			t.Fatalf("%s link range.from is not RFC3339: %v\n%s", kind, err, doc.Range.From)
		}
		to, err := time.Parse(time.RFC3339, doc.Range.To)
		if err != nil {
			t.Fatalf("%s link range.to is not RFC3339: %v\n%s", kind, err, doc.Range.To)
		}
		if to.Before(from) {
			t.Fatalf("%s link range starts %s after it ends %s", kind, from, to)
		}
	}
}

func TestGroupWindowZeroStartFallsBackToEndsAt(t *testing.T) {
	end := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	g := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "Up"}, EndsAt: end}}} // StartsAt zero: timestamp dropped
	w := groupWindow(g)
	if !w[0].Equal(end) || !w[1].Equal(end) {
		t.Fatalf("expected [end, end] for zero-start alert, got [%s, %s]", w[0], w[1])
	}
}

func TestGroupWindowSingleResolvedAlert(t *testing.T) {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	end := start.Add(10 * time.Minute)
	g := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "Up"}, StartsAt: start, EndsAt: end}}}
	w := groupWindow(g)
	if !w[0].Equal(start) || !w[1].Equal(end) {
		t.Fatalf("expected [start, end] for resolved alert, got [%s, %s]", w[0], w[1])
	}
}

func TestGroupWindowAllZeroStaysZero(t *testing.T) {
	g := Group{Alerts: []Alert{
		{Labels: map[string]string{"alertname": "A"}},
		{Labels: map[string]string{"alertname": "B"}},
	}}
	w := groupWindow(g)
	if !w[0].IsZero() || !w[1].IsZero() {
		t.Fatalf("expected zero pair for timestamp-less group, got [%s, %s]", w[0], w[1])
	}
}

// TestGroupWindowMixedResolvedAndActive guards #363: the window's end must
// consider every alert's effective end, where an active alert's effective
// end is its StartsAt. A group-wide fallback let a resolved alert that
// ended before a later active alert began produce end < that alert's
// start, so the Explore link excluded the incident it linked. The order of
// the alerts in the group must not matter.
func TestGroupWindowMixedResolvedAndActive(t *testing.T) {
	resolvedStart := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	resolvedEnd := resolvedStart.Add(time.Minute)
	activeStart := resolvedEnd.Add(time.Minute)
	resolved := Alert{Labels: map[string]string{"alertname": "DiskFull"}, StartsAt: resolvedStart, EndsAt: resolvedEnd}
	active := Alert{Labels: map[string]string{"alertname": "PodCrashloop"}, StartsAt: activeStart}
	timestampless := Alert{Labels: map[string]string{"alertname": "Dropped"}}

	for name, alerts := range map[string][]Alert{
		"resolved first":     {resolved, active},
		"active first":       {active, resolved},
		"with timestampless": {resolved, timestampless, active},
	} {
		w := groupWindow(Group{Alerts: alerts})
		if !w[0].Equal(resolvedStart) || !w[1].Equal(activeStart) {
			t.Errorf("%s: expected [%s, %s], got [%s, %s]", name, resolvedStart, activeStart, w[0], w[1])
		}
	}
}

// TestGroupWindowStartOnlyEndOnlyMix pins the property that each alert's
// effective timestamps bound the window no matter which single timestamp
// it carries. Pre-fix, both orders of a start-only active alert and an
// end-only alert produced the inverted window [t3, t1]: the window's
// `from` was seeded from the first alert with no per-alert fallback.
func TestGroupWindowStartOnlyEndOnlyMix(t *testing.T) {
	t1 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	t3 := t1.Add(3 * time.Minute)
	startOnly := Alert{Labels: map[string]string{"alertname": "Active"}, StartsAt: t3}
	endOnly := Alert{Labels: map[string]string{"alertname": "Dropped"}, EndsAt: t1}
	for name, alerts := range map[string][]Alert{
		"start-only first": {startOnly, endOnly},
		"end-only first":   {endOnly, startOnly},
	} {
		w := groupWindow(Group{Alerts: alerts})
		if !w[0].Equal(t1) || !w[1].Equal(t3) {
			t.Errorf("%s: expected [%s, %s], got [%s, %s]", name, t1, t3, w[0], w[1])
		}
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
// Explore link is escaped through quoteLogValue.
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
