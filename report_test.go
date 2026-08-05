package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSeverityColor(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{"critical", 0xD32F2F},
		{"warning", 0xF9A825},
		{"info", 0x1E88E5},
		{"", 0x1E88E5},
		{"unknown", 0x1E88E5},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := severityColor(tt.severity)
			if got != tt.want {
				t.Errorf("severityColor(%q) = 0x%06X, want 0x%06X", tt.severity, got, tt.want)
			}
		})
	}
}

func TestRenderEvidence_Basic(t *testing.T) {
	r := Report{
		Group: Group{
			Key:        "test-key",
			Reason:     "same-node",
			Node:       "node-1",
			Namespaces: []string{"default", "kube-system"},
			Alerts: []Alert{
				{Labels: map[string]string{"alertname": "HighCPU", "severity": "warning"}, Annotations: map[string]string{"summary": "CPU is high"}},
			},
		},
		PriorSeen: 3,
		Enrichment: Enrichment{
			Scope:           "node/node-1",
			Nodes:           []string{"node-1: MemoryPressure"},
			UnhealthyPods:   []string{"pod-x: CrashLoopBackOff"},
			Events:          []string{"Warning Evicted pod-x"},
			RecentChanges:   []string{"HelmRelease app reconciled"},
		},
	}

	evidence := renderEvidence(r)

	if !strings.Contains(evidence, "test-key") {
		t.Error("expected evidence to contain group key")
	}
	if !strings.Contains(evidence, "node-1") {
		t.Error("expected evidence to contain node name")
	}
	if !strings.Contains(evidence, "default") {
		t.Error("expected evidence to contain namespace")
	}
	if !strings.Contains(evidence, "3 time(s)") {
		t.Error("expected evidence to contain prior seen count")
	}
	if !strings.Contains(evidence, "HighCPU") {
		t.Error("expected evidence to contain alert name")
	}
	if !strings.Contains(evidence, "MemoryPressure") {
		t.Error("expected evidence to contain unhealthy node finding")
	}
	if !strings.Contains(evidence, "CrashLoopBackOff") {
		t.Error("expected evidence to contain unhealthy pod finding")
	}
	if !strings.Contains(evidence, "Evicted") {
		t.Error("expected evidence to contain event finding")
	}
	if !strings.Contains(evidence, "HelmRelease") {
		t.Error("expected evidence to contain recent change finding")
	}
}

func TestRenderEvidence_EmptyEnrichment(t *testing.T) {
	r := Report{
		Group: Group{
			Key:    "empty-group",
			Reason: "same-namespace",
			Alerts: []Alert{
				{Labels: map[string]string{"alertname": "TestAlert"}, Annotations: map[string]string{}},
			},
		},
		PriorSeen:  0,
		Enrichment: Enrichment{},
	}

	evidence := renderEvidence(r)

	if !strings.Contains(evidence, "not seen recently") {
		t.Error("expected 'not seen recently' for PriorSeen=0")
	}
	if !strings.Contains(evidence, "all nodes Ready") {
		t.Error("expected empty enrichment to show 'all nodes Ready'")
	}
	if !strings.Contains(evidence, "no unhealthy pods in scope") {
		t.Error("expected empty enrichment to show 'no unhealthy pods'")
	}
	if !strings.Contains(evidence, "no warning events in the window") {
		t.Error("expected empty enrichment to show 'no warning events'")
	}
	if !strings.Contains(evidence, "no reconciles or failures") {
		t.Error("expected empty enrichment to show 'no reconciles'")
	}
	if !strings.Contains(evidence, "unknown") {
		t.Error("expected scope to be 'unknown' when empty")
	}
}

func TestRenderEvidence_NoNode(t *testing.T) {
	r := Report{
		Group: Group{
			Key:    "no-node",
			Reason: "same-namespace",
			Alerts: []Alert{
				{Labels: map[string]string{"alertname": "TestAlert"}, Annotations: map[string]string{}},
			},
		},
	}

	evidence := renderEvidence(r)
	if strings.Contains(evidence, "Node:") {
		t.Error("expected no Node line when Group.Node is empty")
	}
}

func TestRenderEvidence_NoNamespaces(t *testing.T) {
	r := Report{
		Group: Group{
			Key:    "no-ns",
			Reason: "same-node",
			Node:   "node-1",
			Alerts: []Alert{
				{Labels: map[string]string{"alertname": "TestAlert"}, Annotations: map[string]string{}},
			},
		},
	}

	evidence := renderEvidence(r)
	if strings.Contains(evidence, "Namespaces:") {
		t.Error("expected no Namespaces line when empty")
	}
}

func TestRenderEvidence_AnnotationFallback(t *testing.T) {
	r := Report{
		Group: Group{
			Key:    "annot-test",
			Reason: "same-node",
			Alerts: []Alert{
				{Labels: map[string]string{"alertname": "NoSummary"}, Annotations: map[string]string{"message": "fallback message"}},
			},
		},
	}

	evidence := renderEvidence(r)
	if !strings.Contains(evidence, "fallback message") {
		t.Error("expected annotation fallback to 'message' field")
	}
}

func TestDeliver_Success(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := json.Marshal(map[string]any{"id": "123"})
		receivedBody = body
		w.WriteHeader(http.StatusOK)
		w.Write(receivedBody)
	}))
	defer srv.Close()

	cfg := Config{DiscordURL: srv.URL}
	r := Report{
		Group: Group{
			Key:     "deliver-test",
			Reason:  "same-node",
			Alerts:  []Alert{{Labels: map[string]string{"alertname": "TestAlert", "severity": "critical"}, Annotations: map[string]string{"summary": "test"}}},
		},
		Narrative: "This is a test narrative.",
		PriorSeen: 2,
	}

	if err := Deliver(cfg, r); err != nil {
		t.Fatalf("Deliver error: %v", err)
	}

	payload := strings.TrimSpace(string(receivedBody))
	if payload == "" {
		t.Fatal("expected non-empty response body")
	}
}

func TestDeliver_NoWebhook(t *testing.T) {
	cfg := Config{DiscordURL: ""}
	r := Report{}

	err := Deliver(cfg, r)
	if err == nil {
		t.Fatal("expected error when DiscordURL is empty")
	}
	if !strings.Contains(err.Error(), "no discord webhook configured") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDeliver_HttpError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := Config{DiscordURL: srv.URL}
	r := Report{
		Group: Group{
			Key:    "error-test",
			Reason: "same-node",
			Alerts: []Alert{{Labels: map[string]string{"alertname": "A"}, Annotations: map[string]string{}}},
		},
	}

	err := Deliver(cfg, r)
	if err == nil {
		t.Fatal("expected error on 404 response")
	}
	if !strings.Contains(err.Error(), "discord:") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDeliver_EmptyEnrichment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{DiscordURL: srv.URL}
	r := Report{
		Group: Group{
			Key:    "empty-enrich",
			Reason: "same-namespace",
			Alerts: []Alert{{Labels: map[string]string{"alertname": "A"}, Annotations: map[string]string{}}},
		},
		Enrichment: Enrichment{},
	}

	if err := Deliver(cfg, r); err != nil {
		t.Fatalf("Deliver with empty enrichment error: %v", err)
	}
}

func TestDeliver_ClampsDescription(t *testing.T) {
	var receivedJSON map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedJSON)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{DiscordURL: srv.URL}

	// Build a very long narrative to exceed 3900 chars.
	longNarrative := strings.Repeat("x", 5000)
	r := Report{
		Group: Group{
			Key:    "clamp-test",
			Reason: "same-node",
			Alerts: []Alert{{Labels: map[string]string{"alertname": "A"}, Annotations: map[string]string{}}},
		},
		Narrative: longNarrative,
	}

	if err := Deliver(cfg, r); err != nil {
		t.Fatalf("Deliver error: %v", err)
	}

	embeds, ok := receivedJSON["embeds"].([]any)
	if !ok || len(embeds) == 0 {
		t.Fatal("expected embeds in payload")
	}
	embed := embeds[0].(map[string]any)
	desc, ok := embed["description"].(string)
	if !ok {
		t.Fatal("expected description as string")
	}
	// The narrative is clamped to 3900 chars + "..." = 3903, then evidence is appended.
	// Verify the narrative portion ends with "...".
	parts := strings.SplitN(desc, "\n\n", 2)
	narrativePart := parts[0]
	if !strings.HasSuffix(narrativePart, "...") {
		t.Error("expected clamped narrative to end with '...'")
	}
	// The narrative portion should be exactly 3903 (3900 + "...").
	if len(narrativePart) != 3903 {
		t.Errorf("narrative portion length %d, expected 3903", len(narrativePart))
	}
}

func TestDeliver_FooterPriorSeen(t *testing.T) {
	var receivedJSON map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedJSON)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{DiscordURL: srv.URL}
	r := Report{
		Group: Group{
			Key:    "footer-test",
			Reason: "same-node",
			Alerts: []Alert{{Labels: map[string]string{"alertname": "A"}, Annotations: map[string]string{}}},
		},
		PriorSeen: 5,
	}

	if err := Deliver(cfg, r); err != nil {
		t.Fatalf("Deliver error: %v", err)
	}

	embeds := receivedJSON["embeds"].([]any)
	embed := embeds[0].(map[string]any)
	footer := embed["footer"].(map[string]any)
	text := footer["text"].(string)

	if !strings.Contains(text, "seen 5 time(s) recently") {
		t.Errorf("expected footer to contain prior seen count, got: %s", text)
	}
}

func TestDeliver_FooterFirstSeen(t *testing.T) {
	var receivedJSON map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedJSON)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{DiscordURL: srv.URL}
	r := Report{
		Group: Group{
			Key:    "first-seen",
			Reason: "same-node",
			Alerts: []Alert{{Labels: map[string]string{"alertname": "A"}, Annotations: map[string]string{}}},
		},
		PriorSeen: 0,
	}

	if err := Deliver(cfg, r); err != nil {
		t.Fatalf("Deliver error: %v", err)
	}

	embeds := receivedJSON["embeds"].([]any)
	embed := embeds[0].(map[string]any)
	footer := embed["footer"].(map[string]any)
	text := footer["text"].(string)

	if !strings.Contains(text, "first time seen") {
		t.Errorf("expected footer to contain 'first time seen', got: %s", text)
	}
}

func TestNarrate_NoURL(t *testing.T) {
	cfg := Config{LiteLLMURL: ""}
	r := Report{}

	result := Narrate(cfg, r)
	if result != "" {
		t.Errorf("expected empty narrative when LiteLLMURL is empty, got %q", result)
	}
}

func TestNarrate_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := `{
			"choices": [{
				"message": {
					"content": "The node is experiencing memory pressure."
				}
			}]
		}`
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(resp))
	}))
	defer srv.Close()

	cfg := Config{LiteLLMURL: srv.URL, Model: "test-model", NarrateTimeout: 5 * time.Second}
	r := Report{
		Group: Group{
			Key:    "narrate-test",
			Reason: "same-node",
			Alerts: []Alert{{Labels: map[string]string{"alertname": "A"}, Annotations: map[string]string{}}},
		},
	}

	result := Narrate(cfg, r)
	if result != "The node is experiencing memory pressure." {
		t.Errorf("unexpected narrative: %q", result)
	}
}

func TestNarrate_HttpError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := Config{LiteLLMURL: srv.URL, Model: "test-model", NarrateTimeout: 5 * time.Second}
	r := Report{}

	result := Narrate(cfg, r)
	if result != "" {
		t.Errorf("expected empty narrative on HTTP error, got %q", result)
	}
}

func TestNarrate_UsesReasoningContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := `{
			"choices": [{
				"message": {
					"content": "",
					"reasoning_content": "Reasoning-based answer."
				}
			}]
		}`
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(resp))
	}))
	defer srv.Close()

	cfg := Config{LiteLLMURL: srv.URL, Model: "test-model", NarrateTimeout: 5 * time.Second}
	r := Report{}

	result := Narrate(cfg, r)
	if result != "Reasoning-based answer." {
		t.Errorf("expected reasoning content fallback, got %q", result)
	}
}

func TestNarrate_AuthorizationHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer srv.Close()

	cfg := Config{LiteLLMURL: srv.URL, LiteLLMKey: "test-key-123", Model: "test-model", NarrateTimeout: 5 * time.Second}
	r := Report{}

	Narrate(cfg, r)
	if gotAuth != "Bearer test-key-123" {
		t.Errorf("expected Authorization header 'Bearer test-key-123', got %q", gotAuth)
	}
}

func TestNarrate_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	cfg := Config{LiteLLMURL: srv.URL, Model: "test-model", NarrateTimeout: 5 * time.Second}
	r := Report{}

	result := Narrate(cfg, r)
	if result != "" {
		t.Errorf("expected empty narrative on invalid JSON, got %q", result)
	}
}

func TestNarrate_NoChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[]}`))
	}))
	defer srv.Close()

	cfg := Config{LiteLLMURL: srv.URL, Model: "test-model", NarrateTimeout: 5 * time.Second}
	r := Report{}

	result := Narrate(cfg, r)
	if result != "" {
		t.Errorf("expected empty narrative on no choices, got %q", result)
	}
}

func TestNarrate_UsesModel(t *testing.T) {
	var receivedModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		receivedModel = body["model"].(string)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer srv.Close()

	cfg := Config{LiteLLMURL: srv.URL, Model: "custom-model", NarrateTimeout: 5 * time.Second}
	r := Report{}

	Narrate(cfg, r)
	if receivedModel != "custom-model" {
		t.Errorf("expected model 'custom-model', got %q", receivedModel)
	}
}

func TestWriteFinding_Empty(t *testing.T) {
	var b strings.Builder
	writeFinding(&b, "Test Section", nil, "nothing found")
	s := b.String()
	if !strings.Contains(s, "Test Section: nothing found") {
		t.Errorf("unexpected output for empty items: %q", s)
	}
}

func TestWriteFinding_WithItems(t *testing.T) {
	var b strings.Builder
	writeFinding(&b, "Items", []string{"a", "b"}, "none")
	s := b.String()
	if !strings.Contains(s, "- a") || !strings.Contains(s, "- b") {
		t.Errorf("expected items in output: %q", s)
	}
}

func TestOrUnknown(t *testing.T) {
	if got := orUnknown(""); got != "unknown" {
		t.Errorf("orUnknown(\"\") = %q, want \"unknown\"", got)
	}
	if got := orUnknown("node-1"); got != "node-1" {
		t.Errorf("orUnknown(\"node-1\") = %q, want \"node-1\"", got)
	}
}

func TestFirstAnnotation(t *testing.T) {
	a := Alert{Annotations: map[string]string{"summary": "sum", "message": "msg"}}
	if got := firstAnnotation(a); got != "sum" {
		t.Errorf("firstAnnotation = %q, want \"sum\"", got)
	}

	a2 := Alert{Annotations: map[string]string{"message": "msg"}}
	if got := firstAnnotation(a2); got != "msg" {
		t.Errorf("firstAnnotation fallback = %q, want \"msg\"", got)
	}

	a3 := Alert{Annotations: map[string]string{}}
	if got := firstAnnotation(a3); got != "" {
		t.Errorf("firstAnnotation empty = %q, want \"\"", got)
	}
}

func TestFirstAnnotation_Truncates(t *testing.T) {
	long := strings.Repeat("x", 300)
	a := Alert{Annotations: map[string]string{"summary": long}}
	got := firstAnnotation(a)
	if len(got) > 203 { // 200 chars + "..."
		t.Errorf("firstAnnotation did not truncate, length = %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Error("truncated annotation should end with '...'")
	}
}
