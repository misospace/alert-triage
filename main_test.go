package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookAuth_NoTokenRequired(t *testing.T) {
	cfg := Config{WebhookToken: ""}
	buf := &buffer{cap: 100}

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cfg.WebhookToken != "" && r.Header.Get("X-Webhook-Token") != cfg.WebhookToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		defer r.Body.Close()
		var p Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		firing := p.Alerts[:0]
		for _, a := range p.Alerts {
			if a.Status != "resolved" {
				firing = append(firing, a)
			}
		}
		if len(firing) > 0 {
			buf.add(firing)
		}
		w.WriteHeader(http.StatusAccepted)
	})

	payload := Payload{Alerts: []Alert{{Status: "firing", Labels: map[string]string{"alertname": "test"}}}}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}
}

func TestWebhookAuth_RejectsMissingToken(t *testing.T) {
	cfg := Config{WebhookToken: "secret"}
	buf := &buffer{cap: 100}

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cfg.WebhookToken != "" && r.Header.Get("X-Webhook-Token") != cfg.WebhookToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		defer r.Body.Close()
		var p Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		firing := p.Alerts[:0]
		for _, a := range p.Alerts {
			if a.Status != "resolved" {
				firing = append(firing, a)
			}
		}
		if len(firing) > 0 {
			buf.add(firing)
		}
		w.WriteHeader(http.StatusAccepted)
	})

	payload := Payload{Alerts: []Alert{{Status: "firing", Labels: map[string]string{"alertname": "test"}}}}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestWebhookAuth_RejectsWrongToken(t *testing.T) {
	cfg := Config{WebhookToken: "secret"}
	buf := &buffer{cap: 100}

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cfg.WebhookToken != "" && r.Header.Get("X-Webhook-Token") != cfg.WebhookToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		defer r.Body.Close()
		var p Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		firing := p.Alerts[:0]
		for _, a := range p.Alerts {
			if a.Status != "resolved" {
				firing = append(firing, a)
			}
		}
		if len(firing) > 0 {
			buf.add(firing)
		}
		w.WriteHeader(http.StatusAccepted)
	})

	payload := Payload{Alerts: []Alert{{Status: "firing", Labels: map[string]string{"alertname": "test"}}}}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Webhook-Token", "wrong")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestWebhookAuth_AcceptsValidToken(t *testing.T) {
	cfg := Config{WebhookToken: "secret"}
	buf := &buffer{cap: 100}

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cfg.WebhookToken != "" && r.Header.Get("X-Webhook-Token") != cfg.WebhookToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		defer r.Body.Close()
		var p Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		firing := p.Alerts[:0]
		for _, a := range p.Alerts {
			if a.Status != "resolved" {
				firing = append(firing, a)
			}
		}
		if len(firing) > 0 {
			buf.add(firing)
		}
		w.WriteHeader(http.StatusAccepted)
	})

	payload := Payload{Alerts: []Alert{{Status: "firing", Labels: map[string]string{"alertname": "test"}}}}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Webhook-Token", "secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}
}

func TestBufferCap_DropOldest(t *testing.T) {
	buf := &buffer{cap: 3}

	for i := 0; i < 5; i++ {
		buf.add([]Alert{{Labels: map[string]string{"idx": string(rune('A'+i))}}})
	}

	buf.mu.Lock()
	if len(buf.alerts) != 3 {
		t.Fatalf("expected 3 alerts, got %d", len(buf.alerts))
	}
	// Oldest two (A, B) should have been dropped; remaining are C, D, E.
	if buf.alerts[0].Labels["idx"] != "C" {
		t.Fatalf("expected first alert idx=C, got %s", buf.alerts[0].Labels["idx"])
	}
	if buf.alerts[1].Labels["idx"] != "D" {
		t.Fatalf("expected second alert idx=D, got %s", buf.alerts[1].Labels["idx"])
	}
	if buf.alerts[2].Labels["idx"] != "E" {
		t.Fatalf("expected third alert idx=E, got %s", buf.alerts[2].Labels["idx"])
	}
	buf.mu.Unlock()
}
