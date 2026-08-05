package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

var version = "dev"

type Config struct {
	ListenAddr     string
	LiteLLMURL     string
	LiteLLMKey     string
	Model          string
	DiscordURL     string
	HistoryPath    string
	FlushDelay     time.Duration
	MaxWindow      time.Duration
	CorrelateSlack time.Duration
	EvidenceWindow time.Duration
	Retention      time.Duration
	NarrateTimeout time.Duration
	WebhookToken   string
	MaxBuffered    int
}

func loadConfig() Config {
	return Config{
		ListenAddr:     envDefault("LISTEN_ADDR", ":8080"),
		LiteLLMURL:     envDefault("LITELLM_URL", ""),
		LiteLLMKey:     os.Getenv("LITELLM_API_KEY"),
		Model:          envDefault("MODEL", "dsv4f"),
		DiscordURL:     os.Getenv("DISCORD_WEBHOOK_URL"),
		HistoryPath:    envDefault("HISTORY_PATH", "/data/history.jsonl"),
		FlushDelay:     envDuration("FLUSH_DELAY", 3*time.Minute),
		MaxWindow:      envDuration("MAX_WINDOW", 10*time.Minute),
		CorrelateSlack: envDuration("CORRELATE_SLACK", 5*time.Minute),
		EvidenceWindow: envDuration("EVIDENCE_WINDOW", 30*time.Minute),
		Retention:      envDuration("RETENTION", 7*24*time.Hour),
		NarrateTimeout: envDuration("NARRATE_TIMEOUT", 120*time.Second),
		WebhookToken:   os.Getenv("WEBHOOK_TOKEN"),
		MaxBuffered:    envInt("MAX_BUFFERED", 10000),
	}
}

// buffer accumulates alerts so that a cascade is reported as one incident
// rather than a burst of unrelated-looking messages.
type buffer struct {
	mu      sync.Mutex
	alerts  []Alert
	firstAt time.Time
	cap     int
}

func (b *buffer) add(alerts []Alert) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.alerts) == 0 {
		b.firstAt = time.Now()
	}
	for _, a := range alerts {
		if b.cap > 0 && len(b.alerts) >= b.cap {
			// drop-oldest: shift the slice left by one to make room
			b.alerts = append(b.alerts[:0], b.alerts[1:]...)
		}
		if b.cap == 0 || len(b.alerts) < b.cap {
			b.alerts = append(b.alerts, a)
		}
	}
}

// take returns the buffered alerts if the window is due, clearing the buffer.
func (b *buffer) take(now time.Time, flushDelay, maxWindow time.Duration) []Alert {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.alerts) == 0 {
		return nil
	}
	age := now.Sub(b.firstAt)
	if age < flushDelay && age < maxWindow {
		return nil
	}
	out := b.alerts
	b.alerts = nil
	return out
}

func main() {
	cfg := loadConfig()
	log.Printf("alert-triage %s listening on %s (model=%s flush=%s)", version, cfg.ListenAddr, cfg.Model, cfg.FlushDelay)

	hist, err := NewHistory(cfg.HistoryPath, cfg.Retention)
	if err != nil {
		log.Fatalf("history: %v", err)
	}
	k, err := newKube()
	if err != nil {
		// Enrichment is optional; without it the digest still correlates and
		// narrates, so this must not be fatal for local runs or a broken SA.
		logf("kubernetes unavailable, enrichment disabled: %v", err)
	}

	buf := &buffer{cap: cfg.MaxBuffered}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
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
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&p); err != nil {
			logf("webhook: decode: %v", err)
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
		// Ack immediately; Alertmanager should never block on triage work.
		w.WriteHeader(http.StatusAccepted)
	})

	go runFlushLoop(cfg, buf, k, hist)
	go runCompactLoop(hist)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func runFlushLoop(cfg Config, buf *buffer, k *kube, hist *History) {
	// Poll well inside the flush delay so the window is honoured rather than
	// rounded up to the tick.
	interval := cfg.FlushDelay / 4
	if interval > 15*time.Second {
		interval = 15 * time.Second
	}
	if interval < time.Second {
		interval = time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for range tick.C {
		alerts := buf.take(time.Now(), cfg.FlushDelay, cfg.MaxWindow)
		if len(alerts) == 0 {
			continue
		}
		process(cfg, alerts, k, hist)
	}
}

func runCompactLoop(hist *History) {
	tick := time.NewTicker(6 * time.Hour)
	defer tick.Stop()
	for range tick.C {
		if err := hist.Compact(); err != nil {
			logf("history: compact: %v", err)
		}
	}
}

func process(cfg Config, alerts []Alert, k *kube, hist *History) {
	nodeOf := k.ResolveNodes(alerts)
	groups := Correlate(alerts, nodeOf, DefaultSignatures(), cfg.CorrelateSlack)
	log.Printf("processing %d alerts into %d group(s)", len(alerts), len(groups))

	for _, g := range groups {
		r := Report{Group: g, Enrichment: k.Enrich(g, cfg.EvidenceWindow)}
		r.PriorSeen = hist.Record(g.Signature(), g.Title(), time.Now())
		r.Narrative = Narrate(cfg, r)
		if err := Deliver(cfg, r); err != nil {
			logf("deliver %s: %v", g.Key, err)
		}
	}
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second
	}
	logf("bad duration for %s=%q, using %s", key, v, fallback)
	return fallback
}

func logf(format string, args ...any) {
	log.Printf(format, args...)
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	logf("bad int for %s=%q, using %d", key, v, fallback)
	return fallback
}
