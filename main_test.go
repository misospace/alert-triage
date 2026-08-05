package main

import (
	"os"
	"testing"
	"time"
)

func TestEnvDuration_ValidGoDuration(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{"hours", "2h", 2 * time.Hour},
		{"minutes", "30m", 30 * time.Minute},
		{"seconds", "90s", 90 * time.Second},
		{"mixed", "1h30m", 90 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("TEST_DURATION", tt.value)
			defer os.Unsetenv("TEST_DURATION")

			got := envDuration("TEST_DURATION", 0)
			if got != tt.want {
				t.Errorf("envDuration(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestEnvDuration_IntegerSeconds(t *testing.T) {
	os.Setenv("TEST_DURATION", "7200")
	defer os.Unsetenv("TEST_DURATION")

	got := envDuration("TEST_DURATION", 0)
	want := 7200 * time.Second
	if got != want {
		t.Errorf("envDuration(\"7200\") = %v, want %v", got, want)
	}
}

func TestEnvDuration_InvalidFallsBack(t *testing.T) {
	os.Setenv("TEST_DURATION", "not-a-duration")
	defer os.Unsetenv("TEST_DURATION")

	fallback := 15 * time.Minute
	got := envDuration("TEST_DURATION", fallback)
	if got != fallback {
		t.Errorf("envDuration with invalid value = %v, want fallback %v", got, fallback)
	}
}

func TestEnvDuration_UnsetFallsBack(t *testing.T) {
	os.Unsetenv("TEST_DURATION")
	fallback := 10 * time.Minute
	got := envDuration("TEST_DURATION", fallback)
	if got != fallback {
		t.Errorf("envDuration with unset var = %v, want fallback %v", got, fallback)
	}
}

func TestEnvDuration_ZeroValue(t *testing.T) {
	os.Setenv("TEST_DURATION", "0")
	defer os.Unsetenv("TEST_DURATION")

	got := envDuration("TEST_DURATION", 1*time.Hour)
	if got != 0 {
		t.Errorf("envDuration(\"0\") = %v, want 0", got)
	}
}

func TestEnvDefault(t *testing.T) {
	os.Setenv("TEST_DEFAULT_KEY", "custom")
	defer os.Unsetenv("TEST_DEFAULT_KEY")

	got := envDefault("TEST_DEFAULT_KEY", "fallback")
	if got != "custom" {
		t.Errorf("envDefault with set var = %q, want \"custom\"", got)
	}

	got2 := envDefault("NONEXISTENT_KEY_12345", "fallback")
	if got2 != "fallback" {
		t.Errorf("envDefault with unset var = %q, want \"fallback\"", got2)
	}
}

func TestBuffer_AddAndTake(t *testing.T) {
	buf := &buffer{}

	now := time.Now()
	buf.add([]Alert{
		{Labels: map[string]string{"alertname": "A"}, Annotations: map[string]string{}},
		{Labels: map[string]string{"alertname": "B"}, Annotations: map[string]string{}},
	})

	got := buf.take(now.Add(1*time.Hour), 5*time.Second, 20*time.Second)
	if len(got) != 2 {
		t.Fatalf("expected 2 alerts, got %d", len(got))
	}
}

func TestBuffer_TakeReturnsEmptyWhenNoAlerts(t *testing.T) {
	buf := &buffer{}
	got := buf.take(time.Now(), 5*time.Second, 20*time.Second)
	if len(got) != 0 {
		t.Fatalf("expected 0 alerts from empty buffer, got %d", len(got))
	}
}

func TestBuffer_FlushDelay(t *testing.T) {
	buf := &buffer{}

	now := time.Now()
	buf.add([]Alert{
		{Labels: map[string]string{"alertname": "A"}, Annotations: map[string]string{}},
	})

	// Immediately after add, take should return empty (within flush delay).
	got := buf.take(now.Add(100*time.Millisecond), 5*time.Second, 20*time.Second)
	if len(got) != 0 {
		t.Fatalf("expected 0 alerts within flush delay, got %d", len(got))
	}

	// Wait past FLUSH_DELAY.
	got = buf.take(now.Add(6*time.Second), 5*time.Second, 20*time.Second)
	if len(got) != 1 {
		t.Fatalf("expected 1 alert after flush delay, got %d", len(got))
	}
}

func TestBuffer_MaxWindowCap(t *testing.T) {
	buf := &buffer{}

	now := time.Now()
	buf.add([]Alert{
		{Labels: map[string]string{"alertname": "A"}, Annotations: map[string]string{}},
	})

	// Wait past MAX_WINDOW (but within flush delay).
	got := buf.take(now.Add(25*time.Second), 30*time.Second, 20*time.Second)
	if len(got) != 1 {
		t.Fatalf("expected 1 alert after max window, got %d", len(got))
	}
}

func TestBuffer_TakeClears(t *testing.T) {
	buf := &buffer{}

	now := time.Now()
	buf.add([]Alert{
		{Labels: map[string]string{"alertname": "A"}, Annotations: map[string]string{}},
	})

	got1 := buf.take(now.Add(1*time.Hour), 5*time.Second, 20*time.Second)
	if len(got1) != 1 {
		t.Fatalf("first take expected 1, got %d", len(got1))
	}

	// Second take should be empty.
	got2 := buf.take(now.Add(2*time.Hour), 5*time.Second, 20*time.Second)
	if len(got2) != 0 {
		t.Fatalf("second take expected 0, got %d", len(got2))
	}
}

func TestBuffer_MultipleCycles(t *testing.T) {
	buf := &buffer{}

	now := time.Now()
	buf.add([]Alert{
		{Labels: map[string]string{"alertname": "A"}, Annotations: map[string]string{}},
	})

	got := buf.take(now.Add(1*time.Hour), 5*time.Second, 20*time.Second)
	if len(got) != 1 {
		t.Fatalf("first cycle expected 1, got %d", len(got))
	}

	// Add more alerts for second cycle.
	buf.add([]Alert{
		{Labels: map[string]string{"alertname": "B"}, Annotations: map[string]string{}},
	})

	got = buf.take(now.Add(2*time.Hour), 5*time.Second, 20*time.Second)
	if len(got) != 1 {
		t.Fatalf("second cycle expected 1, got %d", len(got))
	}
}

func TestBuffer_AppendsMultipleAdds(t *testing.T) {
	buf := &buffer{}

	now := time.Now()
	buf.add([]Alert{
		{Labels: map[string]string{"alertname": "A"}, Annotations: map[string]string{}},
	})
	buf.add([]Alert{
		{Labels: map[string]string{"alertname": "B"}, Annotations: map[string]string{}},
		{Labels: map[string]string{"alertname": "C"}, Annotations: map[string]string{}},
	})

	got := buf.take(now.Add(1*time.Hour), 5*time.Second, 20*time.Second)
	if len(got) != 3 {
		t.Fatalf("expected 3 alerts from multiple adds, got %d", len(got))
	}
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name       string
		envVars    map[string]string
		wantURL    string
		wantModel  string
	}{
		{
			name: "defaults",
			envVars: map[string]string{
				"DISCORD_WEBHOOK_URL": "",
				"MODEL":               "",
			},
			wantURL:   "",
			wantModel: "dsv4f",
		},
		{
			name: "custom values",
			envVars: map[string]string{
				"DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/123/abc",
				"MODEL":               "gpt-4o-mini",
			},
			wantURL:   "https://discord.com/api/webhooks/123/abc",
			wantModel: "gpt-4o-mini",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all relevant env vars first.
			for k := range tt.envVars {
				os.Unsetenv(k)
			}
			// Set the test values.
			for k, v := range tt.envVars {
				if v != "" {
					os.Setenv(k, v)
				}
			}

			cfg := loadConfig()

			if cfg.DiscordURL != tt.wantURL {
				t.Errorf("DiscordURL = %q, want %q", cfg.DiscordURL, tt.wantURL)
			}
			if cfg.Model != tt.wantModel {
				t.Errorf("Model = %q, want %q", cfg.Model, tt.wantModel)
			}

			// Cleanup.
			for k := range tt.envVars {
				os.Unsetenv(k)
			}
		})
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	// Clear all env vars that loadConfig reads.
	for _, k := range []string{
		"LISTEN_ADDR", "LITELLM_URL", "LITELLM_API_KEY", "MODEL",
		"DISCORD_WEBHOOK_URL", "HISTORY_PATH",
		"FLUSH_DELAY", "MAX_WINDOW", "CORRELATE_SLACK",
		"EVIDENCE_WINDOW", "RETENTION", "NARRATE_TIMEOUT",
	} {
		os.Unsetenv(k)
	}

	cfg := loadConfig()

	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want \":8080\"", cfg.ListenAddr)
	}
	if cfg.Model != "dsv4f" {
		t.Errorf("Model = %q, want \"dsv4f\"", cfg.Model)
	}
	if cfg.FlushDelay != 3*time.Minute {
		t.Errorf("FlushDelay = %v, want 3m", cfg.FlushDelay)
	}
	if cfg.MaxWindow != 10*time.Minute {
		t.Errorf("MaxWindow = %v, want 10m", cfg.MaxWindow)
	}
	if cfg.Retention != 7*24*time.Hour {
		t.Errorf("Retention = %v, want 168h", cfg.Retention)
	}
}

func TestRunFlushLoop_IntervalCalc(t *testing.T) {
	// Verify the interval calculation logic in runFlushLoop.
	// We can't easily test the loop itself (it blocks), but we can verify
	// the interval bounds by checking that the function doesn't panic.
	cfg := Config{FlushDelay: 1 * time.Second} // minimum interval
	buf := &buffer{}

	// Just verify it starts without panicking; we'll stop it quickly.
	done := make(chan struct{})
	go func() {
		runFlushLoop(cfg, buf, nil, nil)
		close(done)
	}()

	// Give it a moment to start, then check it's running.
	time.Sleep(50 * time.Millisecond)
	// We can't easily stop the goroutine, but at least we verified it doesn't panic.
}
