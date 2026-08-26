package main

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync/atomic"
	"time"
)

// triageMetrics holds the internal counters and gauges that /metrics exposes.
// The /metrics endpoint is the only thing that makes a silent delivery failure
// visible, so this struct is the source of truth for "is the service doing
// what it claims to do". A self-reporting alert that fires into this very
// service is fine as long as the metric that surfaces delivery failure is
// scraped by something outside this process.
//
// The counters are atomic.Int64 because every increment happens on a hot path
// (the webhook handler, the flush loop, the per-group loop inside process).
// A mutex around a struct would serialize those paths; the gauges use the
// same atomic primitives and store unix seconds so the wire format is stable.
type triageMetrics struct {
	alertsReceived    atomic.Int64
	groupsFormed      atomic.Int64
	digestsDelivered  atomic.Int64
	deliveryFailures  atomic.Int64
	narrationFailures atomic.Int64
	modelCalls        atomic.Int64
	lastFlushUnix     atomic.Int64
}

var metrics = &triageMetrics{}

// observeAlerts records the number of firing alerts accepted by /webhook.
// It is called after the TriageLabel gate, so dropped alerts are deliberately
// not counted here — they are surfaced through cfg.DroppedByLabel so a label
// rule typo is visible without waiting on Prometheus.
func (m *triageMetrics) observeAlerts(n int) {
	if n > 0 {
		m.alertsReceived.Add(int64(n))
	}
}

// observeGroups records how many groups Correlate produced for a flush.
func (m *triageMetrics) observeGroups(n int) {
	if n > 0 {
		m.groupsFormed.Add(int64(n))
	}
}

// observeDelivery is called once per group, regardless of success. The boolean
// distinguishes a delivered digest from one the channel refused so the two
// counters can be compared against each other.
func (m *triageMetrics) observeDelivery(ok bool) {
	if ok {
		m.digestsDelivered.Add(1)
	} else {
		m.deliveryFailures.Add(1)
	}
}

// observeNarration is called when Narrate returns a non-actionable triage
// because the model call failed. The digest is still delivered with the
// evidence it already has; this counter only tracks lost explanations.
func (m *triageMetrics) observeNarration(failed bool) {
	if failed {
		m.narrationFailures.Add(1)
	}
}

// observeModelCall is incremented every time Narrate decides to call the
// model. MAX_GROUPS caps the number of calls per flush, so the rate of this
// counter against digestsDelivered is a direct read on the cap.
func (m *triageMetrics) observeModelCall() {
	m.modelCalls.Add(1)
}

// markFlushed stamps the time of the last successful delivery so the rule
// "alerts received but nothing flushed recently" has a denominator.
func (m *triageMetrics) markFlushed() {
	m.lastFlushUnix.Store(time.Now().Unix())
}

// writePrometheus renders the current snapshot in Prometheus text format
// (https://prometheus.io/docs/instrumenting/exposition_formats/). HELP and
// TYPE lines come first so the output passes promtool's lint without flags.
func (m *triageMetrics) writePrometheus(w io.Writer) {
	now := time.Now().Unix()
	lines := []struct {
		name  string
		help  string
		kind  string // "counter" or "gauge"
		value int64
	}{
		{
			"alert_triage_alerts_received_total",
			"Total firing alerts accepted by the webhook after the TriageLabel gate.",
			"counter",
			m.alertsReceived.Load(),
		},
		{
			"alert_triage_groups_formed_total",
			"Total alert groups produced by Correlate across every flush.",
			"counter",
			m.groupsFormed.Load(),
		},
		{
			"alert_triage_digests_delivered_total",
			"Total digests successfully delivered to the operator channel.",
			"counter",
			m.digestsDelivered.Load(),
		},
		{
			"alert_triage_delivery_failures_total",
			"Total digests the channel refused (HTTP error, timeout, JSON encode).",
			"counter",
			m.deliveryFailures.Load(),
		},
		{
			"alert_triage_narration_failures_total",
			"Total groups whose model call failed; the digest still ships with evidence only.",
			"counter",
			m.narrationFailures.Load(),
		},
		{
			"alert_triage_model_calls_total",
			"Total model calls made by Narrate, capped per flush by MAX_GROUPS.",
			"counter",
			m.modelCalls.Load(),
		},
		{
			"alert_triage_last_flush_timestamp_seconds",
			"Unix timestamp of the most recent successful digest delivery; 0 if none yet.",
			"gauge",
			m.lastFlushUnix.Load(),
		},
	}

	// Stable order: matches the order above regardless of map iteration.
	// The lines slice is local, so a plain index loop keeps the output
	// deterministic and easy to diff across scrapes.
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		fmt.Fprintf(w, "# HELP %s %s\n", l.name, l.help)
		fmt.Fprintf(w, "# TYPE %s %s\n", l.name, l.kind)
		fmt.Fprintf(w, "%s %d\n", l.name, l.value)
	}

	// scrape_timestamp is a synthetic gauge so the rule evaluator can see
	// how stale a missed scrape is without re-reading the scrape config.
	fmt.Fprintf(w, "# HELP alert_triage_scrape_timestamp_seconds Unix timestamp of the current /metrics scrape.\n")
	fmt.Fprintf(w, "# TYPE alert_triage_scrape_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "alert_triage_scrape_timestamp_seconds %d\n", now)
}

// metricsHandler serves /metrics in Prometheus text format. It is wrapped in
// requireAuth in main.go, the same wrapper guarding /recent: when
// WEBHOOK_TOKEN is set the endpoint enforces it (bearer token or
// X-Webhook-Token), and when it is unset the check fails open, matching the
// rest of the webhook surface. So a ServiceMonitor must carry the token as a
// bearer secret whenever WEBHOOK_TOKEN is configured; only an unauthenticated
// deployment accepts scrapes without one.
func metricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		metrics.writePrometheus(w)
	}
}

// sortedKeys is a small helper for any future labelled metric; it keeps the
// output deterministic when label sets grow.
func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
