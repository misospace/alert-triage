package main

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"time"
)

// envGrafanaURL returns GRAFANA_URL only when it is an absolute http(s) URL.
// A relative or scheme-less value is dropped: a link that 404s during an
// incident is worse than no link, and the same reasoning already governs
// what_to_change never naming a path it was not shown.
func envGrafanaURL(key string) string {
	raw := strings.TrimSpace(strings.TrimRight(strings.TrimSpace(os.Getenv(key)), "/"))
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return raw
}

// groupWindow returns [from, to] covering every alert in the group. An
// empty group returns the zero pair, which makes grafanaExplore emit "" -
// so a malformed group never produces a half-open URL either. A zero
// EndsAt is the normal shape of an active alert (it has not resolved), so
// it falls back to the alert's StartsAt; the reverse holds for a zero
// StartsAt. Only when no alert in the group carries any usable timestamp
// does the zero pair survive, and grafanaExplore suppresses it rather than
// emitting a URL whose range is the unix epoch.
func groupWindow(g Group) [2]time.Time {
	if len(g.Alerts) == 0 {
		return [2]time.Time{}
	}
	from, to := g.Alerts[0].StartsAt, g.Alerts[0].EndsAt
	for _, a := range g.Alerts[1:] {
		if !a.StartsAt.IsZero() && (from.IsZero() || a.StartsAt.Before(from)) {
			from = a.StartsAt
		}
		if a.EndsAt.After(to) {
			to = a.EndsAt
		}
	}
	if to.IsZero() {
		to = from
	}
	if from.IsZero() {
		from = to
	}
	return [2]time.Time{from, to}
}

// grafanaExplore builds a /explore URL whose left pane carries one query
// against ds and the [from, to] range. expr is the PromQL/LogQL string the
// alert itself fires on; from/to are the alert's own window so the operator
// lands already scoped. Returns "" when base or ds is empty - the digest
// must remain complete without links, so a half-configured Grafana is
// simply silent on the missing side rather than emitting a broken URL.
// It also returns "" when from or to is the zero time: a group whose alerts
// carry no StartsAt/EndsAt at all (the timestamp dropped at webhook-emission
// time) would otherwise format as 0001-01-01T00:00:00Z, a valid RFC3339
// string that sends the operator to the unix epoch instead of the incident.
func grafanaExplore(base, ds, expr string, from, to time.Time, datasourceType string) string {
	if base == "" || ds == "" || expr == "" || from.IsZero() || to.IsZero() {
		return ""
	}
	left := map[string]any{
		"datasource": map[string]string{"uid": ds, "type": datasourceType},
		"queries": []map[string]any{
			{
				"refId": "A",
				"datasource": map[string]string{
					"uid":  ds,
					"type": datasourceType,
				},
				"expr":    expr,
				"range":   true,
				"instant": false,
			},
		},
		"range": map[string]string{
			"from": from.UTC().Format(time.RFC3339),
			"to":   to.UTC().Format(time.RFC3339),
		},
	}
	raw, err := json.Marshal(left)
	if err != nil {
		return ""
	}
	return base + "/explore?left=" + url.QueryEscape(string(raw))
}

// grafanaLinks assembles the Explore links attached to a digest. Each link
// is omitted independently when its config is missing; the function never
// invents a dashboard URL. expression is whatever PromQL/LogQL the alert
// was built around (best effort - empty just means no metrics link).
func grafanaLinks(cfg *Config, expression, namespace string, window [2]time.Time) (metrics, logs string) {
	if cfg == nil || cfg.GrafanaURL == "" {
		return "", ""
	}
	from, to := window[0], window[1]
	metrics = grafanaExplore(cfg.GrafanaURL, cfg.GrafanaMetricsDS, expression, from, to, "prometheus")
	logs = grafanaExplore(cfg.GrafanaURL, cfg.GrafanaLogsDS, namespaceLabel(namespace), from, to, "loki")
	return metrics, logs
}

// namespaceLabel turns "kube-system" into the LogQL convention `{namespace="kube-system"}`.
// An empty namespace yields an empty string, which suppresses the logs link
// rather than emitting a `{namespace=""}` that would search every namespace.
func namespaceLabel(ns string) string {
	if ns == "" {
		return ""
	}
	return `{namespace="` + ns + `"}`
}
