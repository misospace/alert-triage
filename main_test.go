package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- webhook auth tests ---

func TestWebhookNoTokenConfigured(t *testing.T) {
	cfg := Config{WebhookToken: ""}
	buf := &buffer{}
	h := handleWebhook(cfg, buf)

	req := httptest.NewRequest(http.MethodPost, "/webhook",
		bytes.NewReader(validPayload()))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", rec.Code)
	}
	if len(buf.alerts) != 1 {
		t.Errorf("expected 1 alert buffered, got %d", len(buf.alerts))
	}
}

func TestWebhookMissingToken(t *testing.T) {
	cfg := Config{WebhookToken: "secret"}
	buf := &buffer{}
	h := handleWebhook(cfg, buf)

	req := httptest.NewRequest(http.MethodPost, "/webhook",
		bytes.NewReader(validPayload()))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
	if len(buf.alerts) != 0 {
		t.Error("expected no alerts buffered")
	}
}

func TestWebhookWrongToken(t *testing.T) {
	cfg := Config{WebhookToken: "secret"}
	buf := &buffer{}
	h := handleWebhook(cfg, buf)

	req := httptest.NewRequest(http.MethodPost, "/webhook",
		bytes.NewReader(validPayload()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Token", "wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
	if len(buf.alerts) != 0 {
		t.Error("expected no alerts buffered")
	}
}

func TestWebhookValidToken(t *testing.T) {
	cfg := Config{WebhookToken: "secret"}
	buf := &buffer{}
	h := handleWebhook(cfg, buf)

	req := httptest.NewRequest(http.MethodPost, "/webhook",
		bytes.NewReader(validPayload()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Token", "secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", rec.Code)
	}
	if len(buf.alerts) != 1 {
		t.Errorf("expected 1 alert buffered, got %d", len(buf.alerts))
	}
}

func TestWebhookMethodNotAllowed(t *testing.T) {
	cfg := Config{WebhookToken: "secret"}
	buf := &buffer{}
	h := handleWebhook(cfg, buf)

	req := httptest.NewRequest(http.MethodGet, "/webhook", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestWebhookBadPayload(t *testing.T) {
	cfg := Config{WebhookToken: "secret"}
	buf := &buffer{}
	h := handleWebhook(cfg, buf)

	req := httptest.NewRequest(http.MethodPost, "/webhook",
		bytes.NewReader([]byte("not json")))
	req.Header.Set("X-Webhook-Token", "secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestWebhookFiltersResolved(t *testing.T) {
	cfg := Config{WebhookToken: "secret"}
	buf := &buffer{}
	h := handleWebhook(cfg, buf)

	p := Payload{
		Alerts: []Alert{
			{Status: "resolved", Labels: map[string]string{"alertname": "Old"}},
			{Status: "firing", Labels: map[string]string{"alertname": "New"}},
		},
	}
	body, _ := json.Marshal(p)

	req := httptest.NewRequest(http.MethodPost, "/webhook",
		bytes.NewReader(body))
	req.Header.Set("X-Webhook-Token", "secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", rec.Code)
	}
	if len(buf.alerts) != 1 {
		t.Errorf("expected 1 alert (resolved filtered), got %d", len(buf.alerts))
	}
	if buf.alerts[0].Labels["alertname"] != "New" {
		t.Errorf("expected 'New', got %q", buf.alerts[0].Labels["alertname"])
	}
}

func validPayload() []byte {
	p := Payload{
		Alerts: []Alert{
			{Status: "firing", Labels: map[string]string{"alertname": "HighCPU"}},
		},
	}
	b, _ := json.Marshal(p)
	return b
}

// --- buffer cap tests ---

func TestBufferCapEnforced(t *testing.T) {
	buf := &buffer{cap: 3}
	for i := 0; i < 5; i++ {
		buf.add([]Alert{{Labels: map[string]string{"idx": string(rune('0'+i))}}})
	}
	if len(buf.alerts) != 3 {
		t.Errorf("expected 3 alerts (cap), got %d", len(buf.alerts))
	}
	// Oldest should have been dropped; remaining are the last 3.
	if buf.alerts[0].Labels["idx"] != "2" {
		t.Errorf("expected oldest to be '2', got %q", buf.alerts[0].Labels["idx"])
	}
}

func TestBufferCapZeroUnlimited(t *testing.T) {
	buf := &buffer{cap: 0}
	for i := 0; i < 100; i++ {
		buf.add([]Alert{{Labels: map[string]string{"idx": string(rune('0' + i%10))}}})
	}
	if len(buf.alerts) != 100 {
		t.Errorf("expected 100 alerts (unlimited), got %d", len(buf.alerts))
	}
}

func TestBufferTake(t *testing.T) {
	buf := &buffer{cap: 100}
	buf.add([]Alert{{Labels: map[string]string{"alertname": "A"}}})
	buf.firstAt = time.Now().Add(-5 * time.Minute)

	// flushDelay=3m, maxWindow=10m → age exceeds both
	got := buf.take(time.Now(), 3*time.Minute, 10*time.Minute)
	if len(got) != 1 {
		t.Errorf("expected 1 alert from take, got %d", len(got))
	}
	if len(buf.alerts) != 0 {
		t.Error("expected buffer cleared after take")
	}
}

func TestBufferTakeNotDue(t *testing.T) {
	buf := &buffer{cap: 100}
	buf.add([]Alert{{Labels: map[string]string{"alertname": "A"}}})
	buf.firstAt = time.Now().Add(-30 * time.Second)

	got := buf.take(time.Now(), 3*time.Minute, 10*time.Minute)
	if len(got) != 0 {
		t.Errorf("expected no alerts (not due), got %d", len(got))
	}
}

// --- config loading tests ---

func TestEnvDefault(t *testing.T) {
	if got := envDefault("NONEXISTENT_VAR_XYZ", "fallback"); got != "fallback" {
		t.Errorf("expected 'fallback', got %q", got)
	}
}

func TestEnvDuration(t *testing.T) {
	if got := envDuration("NONEXISTENT_VAR_XYZ", 5*time.Second); got != 5*time.Second {
		t.Errorf("expected 5s, got %v", got)
	}
}
