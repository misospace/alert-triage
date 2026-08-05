package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
			webhookHandler(Config{WebhookToken: tt.token}, buf)(w, req)

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
	for _, e := range []string{"DISCORD_WEBHOOK_URL", "RETENTION", "FLUSH_DELAY", "MAX_WINDOW"} {
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
}

func TestLoadConfigCustom(t *testing.T) {
	os.Setenv("DISCORD_WEBHOOK_URL", "https://example.com/hook")
	os.Setenv("RETENTION", "48h")
	defer func() {
		os.Unsetenv("DISCORD_WEBHOOK_URL")
		os.Unsetenv("RETENTION")
	}()

	cfg := loadConfig()
	if cfg.DiscordURL != "https://example.com/hook" {
		t.Errorf("webhook = %q, want https://example.com/hook", cfg.DiscordURL)
	}
	if cfg.Retention != 48*time.Hour {
		t.Errorf("retention = %v, want 48h", cfg.Retention)
	}
}
