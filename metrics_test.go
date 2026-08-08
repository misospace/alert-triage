package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsCounters(t *testing.T) {
	m := NewMetrics()

	m.RecordAlert(5)
	if got := m.alertsReceived.Load(); got != 5 {
		t.Errorf("alertsReceived = %d; want 5", got)
	}

	m.RecordGroup(2)
	if got := m.groupsFormed.Load(); got != 2 {
		t.Errorf("groupsFormed = %d; want 2", got)
	}

	m.RecordDelivery()
	if got := m.digestsDelivered.Load(); got != 1 {
		t.Errorf("digestsDelivered = %d; want 1", got)
	}

	m.RecordDeliveryFailure()
	if got := m.deliveryFailures.Load(); got != 1 {
		t.Errorf("deliveryFailures = %d; want 1", got)
	}

	m.RecordNarrationFailure()
	if got := m.narrationFailures.Load(); got != 1 {
		t.Errorf("narrationFailures = %d; want 1", got)
	}

	m.RecordModelCall()
	if got := m.modelCalls.Load(); got != 1 {
		t.Errorf("modelCalls = %d; want 1", got)
	}

	m.RecordFlush()
	if got := m.lastSuccessfulFlush.Load(); got == 0 {
		t.Error("lastSuccessfulFlush should be non-zero after RecordFlush")
	}
}

func TestMetricsHandler(t *testing.T) {
	m := NewMetrics()
	m.RecordAlert(3)
	m.RecordGroup(1)
	m.RecordDelivery()
	m.RecordDeliveryFailure()
	m.RecordNarrationFailure()
	m.RecordModelCall()
	m.RecordFlush()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Code)
	}

	body := rec.Body.String()
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4" {
		t.Errorf("content-type = %q; want text/plain; version=0.0.4", ct)
	}

	wantLines := []string{
		"# TYPE alert_triage_alerts_received_total counter",
		"alert_triage_alerts_received_total 3",
		"# TYPE alert_triage_groups_formed_total counter",
		"alert_triage_groups_formed_total 1",
		"# TYPE alert_triage_digests_delivered_total counter",
		"alert_triage_digests_delivered_total 1",
		"# TYPE alert_triage_delivery_failures_total counter",
		"alert_triage_delivery_failures_total 1",
		"# TYPE alert_triage_narration_failures_total counter",
		"alert_triage_narration_failures_total 1",
		"# TYPE alert_triage_model_calls_total counter",
		"alert_triage_model_calls_total 1",
		"# TYPE alert_triage_last_successful_flush_timestamp gauge",
	}

	for _, want := range wantLines {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q\n\nbody:\n%s", want, body)
		}
	}
}

func TestMetricsHandlerEmpty(t *testing.T) {
	m := NewMetrics()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "alert_triage_alerts_received_total 0") {
		t.Error("expected zero counter for alerts_received")
	}
}
