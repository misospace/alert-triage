package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMetricsEndpointShape exercises the scrape format directly: every counter
// and gauge from the issue scope must appear with the right Prometheus
// metadata so a freshly installed ServiceMonitor does not have to wait for
// the first real failure to learn the metric names.
func TestMetricsEndpointShape(t *testing.T) {
	// Reset the package-global so the test is independent of any earlier
	// observation. The struct is exposed only to tests; production code goes
	// through the helpers above.
	metrics.alertsReceived.Store(0)
	metrics.groupsFormed.Store(0)
	metrics.digestsDelivered.Store(0)
	metrics.deliveryFailures.Store(0)
	metrics.narrationFailures.Store(0)
	metrics.modelCalls.Store(0)
	metrics.lastFlushUnix.Store(0)

	metrics.observeAlerts(3)
	metrics.observeGroups(2)
	metrics.observeDelivery(true)
	metrics.observeDelivery(false)
	metrics.observeNarration(true)
	metrics.observeModelCall()
	metrics.markFlushed()

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	metricsHandler()(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}
	body := rec.Body.String()

	want := []string{
		"# TYPE alert_triage_alerts_received_total counter",
		"alert_triage_alerts_received_total 3",
		"# TYPE alert_triage_groups_formed_total counter",
		"alert_triage_groups_formed_total 2",
		"# TYPE alert_triage_digests_delivered_total counter",
		"alert_triage_digests_delivered_total 1",
		"# TYPE alert_triage_delivery_failures_total counter",
		"alert_triage_delivery_failures_total 1",
		"# TYPE alert_triage_narration_failures_total counter",
		"alert_triage_narration_failures_total 1",
		"# TYPE alert_triage_model_calls_total counter",
		"alert_triage_model_calls_total 1",
		"# TYPE alert_triage_last_flush_timestamp_seconds gauge",
	}
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("missing line %q in:\n%s", w, body)
		}
	}

	// Content-Type must follow the Prometheus exposition spec or scrapers
	// fall back to a stricter parser and drop the response.
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type: %q", ct)
	}
}
