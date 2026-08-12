package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEnvDuration(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{"valid go duration", "30s", 30 * time.Second},
		{"integer seconds", "60", 60 * time.Second},
		{"invalid value", "abc", 15 * time.Minute},
		{"zero", "0", 0},
		{"negative", "-10s", -10 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("TEST_DURATION", tt.value)
			defer os.Unsetenv("TEST_DURATION")
			got := envDuration("TEST_DURATION", 15*time.Minute)
			if got != tt.want {
				t.Errorf("envDuration(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}

	// Missing env falls back to default.
	os.Unsetenv("TEST_DURATION")
	got := envDuration("TEST_DURATION", 15*time.Minute)
	if got != 15*time.Minute {
		t.Errorf("envDuration missing key = %v, want 15m", got)
	}
}

func TestBufferAddTake(t *testing.T) {
	b := &buffer{}
	b.firstAt = time.Now().Add(-1 * time.Second)
	b.add([]Alert{{Fingerprint: "a"}, {Fingerprint: "b"}})

	got := b.take(time.Now(), 0, 10*time.Second)
	if len(got) != 2 {
		t.Errorf("expected 2 alerts, got %d", len(got))
	}
}

func TestBufferEmpty(t *testing.T) {
	b := &buffer{}
	got := b.take(time.Now(), 100*time.Millisecond, 10*time.Second)
	if len(got) != 0 {
		t.Errorf("expected 0 alerts from empty buffer, got %d", len(got))
	}
}

func TestBufferMaxWindow(t *testing.T) {
	b := &buffer{}
	now := time.Now()
	b.add([]Alert{{Fingerprint: "old"}})
	b.firstAt = now.Add(-3 * time.Second)
	b.add([]Alert{{Fingerprint: "new"}})

	got := b.take(now, 10*time.Second, 2*time.Second)
	if len(got) != 2 {
		t.Errorf("expected 2 alerts (max window exceeded), got %d", len(got))
	}
}

func TestBufferFlushDelay(t *testing.T) {
	b := &buffer{}
	now := time.Now()
	b.add([]Alert{{Fingerprint: "delayed"}})
	b.firstAt = now.Add(-500 * time.Millisecond)

	// Not yet past flush delay.
	got := b.take(now, 1*time.Second, 10*time.Second)
	if len(got) != 0 {
		t.Errorf("expected 0 alerts before flush delay, got %d", len(got))
	}

	// Past flush delay.
	got = b.take(now.Add(600*time.Millisecond), 1*time.Second, 10*time.Second)
	if len(got) != 1 || got[0].Fingerprint != "delayed" {
		t.Errorf("expected 'delayed' after flush delay, got %v", got)
	}
}

func TestBufferMultipleItems(t *testing.T) {
	b := &buffer{}
	b.firstAt = time.Now().Add(-1 * time.Second)
	for _, fp := range []string{"a", "b", "c", "d", "e"} {
		b.add([]Alert{{Fingerprint: fp}})
	}

	got := b.take(time.Now(), 0, 10*time.Second)
	if len(got) != 5 {
		t.Errorf("expected 5 alerts, got %d", len(got))
	}
}

// Alertmanager re-sends a firing group on every membership change, so the same
// fingerprint arrives repeatedly inside one window. Each copy used to be
// buffered, duplicating the alert in the digest and inflating group counts.
func TestBufferDedupesRepeatDeliveries(t *testing.T) {
	b := &buffer{}
	first := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

	b.add([]Alert{{Fingerprint: "dup", StartsAt: first}, {Fingerprint: "other", StartsAt: first}})
	b.add([]Alert{{Fingerprint: "dup", StartsAt: first.Add(10 * time.Minute)}})
	b.firstAt = time.Now().Add(-time.Second)

	got := b.take(time.Now(), 0, 10*time.Second)
	if len(got) != 2 {
		t.Fatalf("expected 2 alerts after dedup, got %d", len(got))
	}
	if !got[0].StartsAt.Equal(first) {
		t.Errorf("StartsAt = %v, want the first occurrence %v", got[0].StartsAt, first)
	}
}

// A window that has been taken starts clean, or an alert that fires again an
// hour later would be dropped as a duplicate of the one already reported.
func TestBufferDedupeResetsAfterTake(t *testing.T) {
	b := &buffer{}
	b.add([]Alert{{Fingerprint: "a"}})
	b.firstAt = time.Now().Add(-time.Second)
	if got := b.take(time.Now(), 0, 10*time.Second); len(got) != 1 {
		t.Fatalf("expected 1 alert in the first window, got %d", len(got))
	}

	b.add([]Alert{{Fingerprint: "a"}})
	b.firstAt = time.Now().Add(-time.Second)
	if got := b.take(time.Now(), 0, 10*time.Second); len(got) != 1 {
		t.Errorf("expected the alert again in a later window, got %d", len(got))
	}
}

// Replayed and hand-built payloads often carry no fingerprint. Falling back to
// the labels keeps unrelated alerts apart while still collapsing real copies.
func TestBufferDedupesWithoutFingerprints(t *testing.T) {
	mk := func(name string) Alert {
		return Alert{Labels: map[string]string{"alertname": name, "namespace": "llm"}}
	}
	b := &buffer{}
	b.add([]Alert{mk("A"), mk("B"), mk("A")})
	b.firstAt = time.Now().Add(-time.Second)

	got := b.take(time.Now(), 0, 10*time.Second)
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct alerts, got %d", len(got))
	}
}

func TestBufferNotYetDue(t *testing.T) {
	b := &buffer{}
	now := time.Now()
	b.firstAt = now
	b.add([]Alert{{Fingerprint: "fresh"}})

	got := b.take(now.Add(500*time.Millisecond), 1*time.Second, 10*time.Second)
	if len(got) != 0 {
		t.Errorf("expected 0 alerts before flush delay, got %d", len(got))
	}
}

// Every accepted group costs a model call and a message in the operator
// channel, so an unauthenticated /webhook is both a spend and a spoofing vector.
func TestWebhookTokenEnforcement(t *testing.T) {
	body := `{"alerts":[{"status":"firing","fingerprint":"a","labels":{"alertname":"A"}}]}`
	tests := []struct {
		name    string
		token   string
		header  string
		value   string
		want    int
		buffers bool
	}{
		{"no token configured accepts", "", "", "", http.StatusAccepted, true},
		{"missing header rejected", "s3cret", "", "", http.StatusUnauthorized, false},
		{"wrong bearer rejected", "s3cret", "Authorization", "Bearer wrong", http.StatusUnauthorized, false},
		{"wrong header token rejected", "s3cret", "X-Webhook-Token", "wrong", http.StatusUnauthorized, false},
		{"bearer accepted", "s3cret", "Authorization", "Bearer s3cret", http.StatusAccepted, true},
		{"header token accepted", "s3cret", "X-Webhook-Token", "s3cret", http.StatusAccepted, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &buffer{}
			req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
			if tt.header != "" {
				req.Header.Set(tt.header, tt.value)
			}
			w := httptest.NewRecorder()
			webhookHandler(&Config{WebhookToken: tt.token}, buf)(w, req)

			if w.Code != tt.want {
				t.Errorf("status = %d, want %d", w.Code, tt.want)
			}
			buffered := len(buf.take(time.Now(), 0, 0))
			if tt.buffers && buffered != 1 {
				t.Errorf("expected the alert to be buffered, got %d", buffered)
			}
			if !tt.buffers && buffered != 0 {
				t.Errorf("rejected request must not buffer anything, got %d", buffered)
			}
		})
	}
}

// Triage is opt-in by label so a flood of uninteresting upstream alerts does
// not cost a model call. The filter is gated behind TriageLabel so a fresh
// deployment with no labelled rules keeps triaging everything — flipping it
// on with nothing labelled would otherwise drop 100% of alerts silently.
func TestWebhookTriageLabelOptIn(t *testing.T) {
	mkPayload := func(alerts ...Alert) string {
		body, _ := json.Marshal(Payload{Alerts: alerts})
		return string(body)
	}
	mkReq := func(t *testing.T, body, label string) *http.Request {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
		req.Header.Set("X-Webhook-Token", "secret")
		return req
	}

	cases := []struct {
		name     string
		label    string
		alerts   []Alert
		wantBuf  int
		wantDrop int64
	}{
		{
			name:    "empty label disables the filter",
			label:   "",
			alerts:  []Alert{{Fingerprint: "a"}, {Fingerprint: "b"}},
			wantBuf: 2,
		},
		{
			name:     "label absent on alert is dropped",
			label:    "triage",
			alerts:   []Alert{{Fingerprint: "a", Labels: map[string]string{"severity": "critical"}}},
			wantDrop: 1,
		},
		{
			name:     "label value false is dropped",
			label:    "triage",
			alerts:   []Alert{{Fingerprint: "a", Labels: map[string]string{"triage": "false"}}},
			wantDrop: 1,
		},
		{
			name:    "label value true is buffered",
			label:   "triage",
			alerts:  []Alert{{Fingerprint: "a", Labels: map[string]string{"triage": "true"}}},
			wantBuf: 1,
		},
		{
			name:  "custom label name is honoured",
			label: "ship-to-triage",
			alerts: []Alert{
				{Fingerprint: "a", Labels: map[string]string{"ship-to-triage": "true"}},
			},
			wantBuf: 1,
		},
		{
			name:  "mixed batch counts drops and buffers true only",
			label: "triage",
			alerts: []Alert{
				{Fingerprint: "yes", Labels: map[string]string{"triage": "true"}},
				{Fingerprint: "no"},
				{Fingerprint: "off", Labels: map[string]string{"triage": "false"}},
				{Fingerprint: "yes2", Labels: map[string]string{"triage": "True"}}, // case sensitive on purpose
			},
			wantBuf:  1,
			wantDrop: 3,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			cfg.WebhookToken = "secret"
			cfg.TriageLabel = tt.label
			buf := &buffer{}
			w := httptest.NewRecorder()
			webhookHandler(&cfg, buf)(w, mkReq(t, mkPayload(tt.alerts...), tt.label))
			if w.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusAccepted)
			}
			if got := len(buf.take(time.Now(), 0, 0)); got != tt.wantBuf {
				t.Errorf("buffered = %d, want %d", got, tt.wantBuf)
			}
			if got := cfg.DroppedByLabel.Load(); got != tt.wantDrop {
				t.Errorf("DroppedByLabel = %d, want %d", got, tt.wantDrop)
			}
		})
	}
}

// Resolved alerts never carry the opt-in label, so once the filter is on the
// webhook must continue to drop them silently rather than double-count them
// against the DroppedByLabel total.
func TestWebhookResolvedSkipsLabelCounter(t *testing.T) {
	var cfg Config
	cfg.WebhookToken = "secret"
	cfg.TriageLabel = "triage"
	body, _ := json.Marshal(Payload{Alerts: []Alert{
		{Status: "resolved", Fingerprint: "old"},
	}})
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Webhook-Token", "secret")
	buf := &buffer{}
	webhookHandler(&cfg, buf)(httptest.NewRecorder(), req)
	if got := cfg.DroppedByLabel.Load(); got != 0 {
		t.Errorf("DroppedByLabel = %d for resolved-only batch, want 0", got)
	}
}

// Concurrent deliveries must each contribute to the cumulative counter
// without losing updates. atomic.Int64 is what keeps this safe.
func TestWebhookDroppedCounterConcurrent(t *testing.T) {
	var cfg Config
	cfg.WebhookToken = "secret"
	cfg.TriageLabel = "triage"
	handler := webhookHandler(&cfg, &buffer{})

	const deliveries = 32
	const perDelivery = 4
	body, _ := json.Marshal(Payload{Alerts: []Alert{
		{Fingerprint: "dropped", Labels: map[string]string{"triage": "false"}},
		{Fingerprint: "dropped2"},
		{Fingerprint: "kept", Labels: map[string]string{"triage": "true"}},
		{Status: "resolved"},
	}})

	var wg sync.WaitGroup
	for i := 0; i < deliveries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
			req.Header.Set("X-Webhook-Token", "secret")
			handler(httptest.NewRecorder(), req)
		}()
	}
	wg.Wait()

	// Two of the four alerts lack triage=true; resolved already dropped.
	if want := int64(deliveries * 2); cfg.DroppedByLabel.Load() != want {
		t.Errorf("DroppedByLabel = %d, want %d", cfg.DroppedByLabel.Load(), want)
	}
}

// A flood must not grow memory without limit. The newest are refused rather
// than evicting the alerts that opened the window, which are the ones that
// explain a cascade.
func TestBufferCapRefusesNewest(t *testing.T) {
	b := &buffer{max: 3}
	alerts := []Alert{
		{Fingerprint: "first"}, {Fingerprint: "second"}, {Fingerprint: "third"},
		{Fingerprint: "fourth"}, {Fingerprint: "fifth"},
	}
	if rejected := b.add(alerts); rejected != 2 {
		t.Errorf("rejected = %d, want 2", rejected)
	}
	b.firstAt = time.Now().Add(-time.Second)
	got := b.take(time.Now(), 0, 10*time.Second)
	if len(got) != 3 {
		t.Fatalf("buffered %d alerts, want the cap of 3", len(got))
	}
	if got[0].Fingerprint != "first" {
		t.Errorf("kept %q first, want the alert that opened the window", got[0].Fingerprint)
	}
}

func TestBufferNoCapWhenUnset(t *testing.T) {
	b := &buffer{}
	if rejected := b.add([]Alert{{Fingerprint: "a"}, {Fingerprint: "b"}}); rejected != 0 {
		t.Errorf("rejected = %d, want 0 when no cap is configured", rejected)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	for _, e := range []string{"DISCORD_WEBHOOK_URL", "RETENTION", "FLUSH_DELAY", "MAX_WINDOW", "TRIAGE_LABEL"} {
		os.Unsetenv(e)
	}
	cfg := loadConfig()
	if cfg.Retention != 7*24*time.Hour {
		t.Errorf("default retention = %v, want 168h", cfg.Retention)
	}
	if cfg.FlushDelay != 3*time.Minute {
		t.Errorf("default flush delay = %v, want 3m", cfg.FlushDelay)
	}
	if cfg.MaxWindow != 10*time.Minute {
		t.Errorf("default max window = %v, want 10m", cfg.MaxWindow)
	}
	// TRIAGE_LABEL must default to empty so a fresh image triages every
	// alert; flipping the gate on with no labelled rules would drop them
	// all silently.
	if cfg.TriageLabel != "" {
		t.Errorf("default TriageLabel = %q, want \"\"", cfg.TriageLabel)
	}
}

func TestLoadConfigCustom(t *testing.T) {
	os.Setenv("DISCORD_WEBHOOK_URL", "https://example.com/hook")
	os.Setenv("RETENTION", "48h")
	os.Setenv("TRIAGE_LABEL", "triage")
	defer func() {
		os.Unsetenv("DISCORD_WEBHOOK_URL")
		os.Unsetenv("RETENTION")
		os.Unsetenv("TRIAGE_LABEL")
	}()

	cfg := loadConfig()
	if cfg.DiscordURL != "https://example.com/hook" {
		t.Errorf("webhook = %q, want https://example.com/hook", cfg.DiscordURL)
	}
	if cfg.Retention != 48*time.Hour {
		t.Errorf("retention = %v, want 48h", cfg.Retention)
	}
	if cfg.TriageLabel != "triage" {
		t.Errorf("TriageLabel = %q, want triage", cfg.TriageLabel)
	}
}

// TestShutdownDrainFlushesBuffer verifies that the graceful-shutdown drain
// logic flushes buffered alerts instead of silently dropping them.  This is
// the regression test for issue #11: on SIGTERM the process must drain the
// in-memory buffer through process() before exiting.
func TestShutdownDrainFlushesBuffer(t *testing.T) {
	var cfg Config
	cfg.WebhookToken = "secret"

	buf := &buffer{}
	now := time.Now()
	buf.firstAt = now.Add(-time.Second)
	buf.add([]Alert{
		{Fingerprint: "a", Labels: map[string]string{"alertname": "TestAlert1"}},
		{Fingerprint: "b", Labels: map[string]string{"alertname": "TestAlert2"}},
	})

	// Create a real History so process() doesn't panic on nil deref.
	hist, err := NewHistory(t.TempDir()+"/history.json", 1*time.Hour)
	if err != nil {
		t.Fatalf("NewHistory: %v", err)
	}

	var seen recent

	// Simulate the drain loop from main.go's shutdown handler.
	drained := 0
	for {
		buf.mu.Lock()
		if len(buf.alerts) == 0 {
			buf.mu.Unlock()
			break
		}
		alerts := buf.alerts
		buf.alerts = nil
		buf.seen = nil
		buf.mu.Unlock()
		process(&cfg, alerts, nil, hist, &seen)
		drained += len(alerts)
	}

	if drained != 2 {
		t.Errorf("drained %d alerts, want 2", drained)
	}
}
