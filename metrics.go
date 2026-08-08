package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Metrics holds all Prometheus-style counters and gauges for the alert-triage service.
// All fields are atomic so they can be read/written from multiple goroutines safely.
type Metrics struct {
	alertsReceived        atomic.Int64
	groupsFormed          atomic.Int64
	digestsDelivered      atomic.Int64
	deliveryFailures      atomic.Int64
	narrationFailures     atomic.Int64
	modelCalls            atomic.Int64
	lastSuccessfulFlush   atomic.Int64 // unix epoch seconds
}

// NewMetrics returns a zero-initialized Metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{}
}

// RecordAlert increments the alerts received counter.
func (m *Metrics) RecordAlert(n int) {
	m.alertsReceived.Add(int64(n))
}

// RecordGroup increments the groups formed counter.
func (m *Metrics) RecordGroup(n int) {
	m.groupsFormed.Add(int64(n))
}

// RecordDelivery increments the digests delivered counter and updates last flush time.
func (m *Metrics) RecordDelivery() {
	m.digestsDelivered.Add(1)
	m.lastSuccessfulFlush.Store(time.Now().Unix())
}

// RecordDeliveryFailure increments the delivery failures counter.
func (m *Metrics) RecordDeliveryFailure() {
	m.deliveryFailures.Add(1)
}

// RecordNarrationFailure increments the narration failures counter.
func (m *Metrics) RecordNarrationFailure() {
	m.narrationFailures.Add(1)
}

// RecordModelCall increments the model calls counter.
func (m *Metrics) RecordModelCall() {
	m.modelCalls.Add(1)
}

// RecordFlush updates the last successful flush timestamp to now.
func (m *Metrics) RecordFlush() {
	m.lastSuccessfulFlush.Store(time.Now().Unix())
}

// Handler returns an http.HandlerFunc that writes metrics in Prometheus text format.
func (m *Metrics) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		var sb strings.Builder
		writeCounter(&sb, "alert_triage_alerts_received_total",
			m.alertsReceived.Load(), "Total alerts received by the service.")
		writeCounter(&sb, "alert_triage_groups_formed_total",
			m.groupsFormed.Load(), "Total alert groups formed after correlation.")
		writeCounter(&sb, "alert_triage_digests_delivered_total",
			m.digestsDelivered.Load(), "Total digests successfully delivered.")
		writeCounter(&sb, "alert_triage_delivery_failures_total",
			m.deliveryFailures.Load(), "Total delivery failures.")
		writeCounter(&sb, "alert_triage_narration_failures_total",
			m.narrationFailures.Load(), "Total narration failures.")
		writeCounter(&sb, "alert_triage_model_calls_total",
			m.modelCalls.Load(), "Total LLM model calls made.")
		writeGauge(&sb, "alert_triage_last_successful_flush_timestamp",
			float64(m.lastSuccessfulFlush.Load()),
			"Unix timestamp of the last successful flush cycle.")
		fmt.Fprint(w, sb.String())
	}
}

func writeCounter(sb *strings.Builder, name string, value int64, help string) {
	fmt.Fprintf(sb, "# HELP %s %s\n", name, help)
	fmt.Fprintf(sb, "# TYPE %s counter\n", name)
	fmt.Fprintf(sb, "%s %d\n\n", name, value)
}

func writeGauge(sb *strings.Builder, name string, value float64, help string) {
	fmt.Fprintf(sb, "# HELP %s %s\n", name, help)
	fmt.Fprintf(sb, "# TYPE %s gauge\n", name)
	fmt.Fprintf(sb, "%s %.0f\n\n", name, value)
}
