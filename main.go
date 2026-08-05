package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
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
	}
}

// recent keeps the last few delivered digests in memory so they can be read
// back over HTTP. Reviewing what the model actually wrote is the only way to
// judge triage quality, and requiring a human to relay it out of a chat client
// makes that loop slow and lossy.
type recent struct {
	mu    sync.Mutex
	max   int
	items []DigestRecord
}

// DigestRecord is one delivered digest, as served by /recent.
type DigestRecord struct {
	At           time.Time `json:"at"`
	Key          string    `json:"key"`
	Title        string    `json:"title"`
	Severity     string    `json:"severity"`
	Alerts       []string  `json:"alerts"`
	PriorSeen    int       `json:"prior_seen"`
	Narrative    string    `json:"narrative"`
	Evidence     string    `json:"evidence"`
	FixLocation  string    `json:"fix_location"`
	WhatToChange string    `json:"what_to_change,omitempty"`
	Confidence   string    `json:"confidence,omitempty"`
	Actionable   bool      `json:"actionable"`
	Delivered    bool      `json:"delivered"`
	DeliverErr   string    `json:"deliver_error,omitempty"`
}

func (r *recent) add(d DigestRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, d)
	if len(r.items) > r.max {
		r.items = r.items[len(r.items)-r.max:]
	}
}

// snapshot returns the records newest first, since the reason to open this
// endpoint is nearly always the digest that just arrived.
func (r *recent) snapshot() []DigestRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]DigestRecord, 0, len(r.items))
	for i := len(r.items) - 1; i >= 0; i-- {
		out = append(out, r.items[i])
	}
	return out
}

// buffer accumulates alerts so that a cascade is reported as one incident
// rather than a burst of unrelated-looking messages.
type buffer struct {
	mu      sync.Mutex
	alerts  []Alert
	seen    map[string]bool
	firstAt time.Time
}

// add buffers alerts that are not already in the window. Alertmanager re-sends
// a firing group whenever its membership changes, and retries on failure, so
// the same alert can arrive several times before the window closes. Ingesting
// each copy duplicates its bullet in the digest and inflates every count the
// operator reads, including "processing N alerts into M groups". The first
// copy is kept, so StartsAt stays the one correlation windowing expects.
func (b *buffer) add(alerts []Alert) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.alerts) == 0 {
		b.firstAt = time.Now()
	}
	if b.seen == nil {
		b.seen = make(map[string]bool, len(alerts))
	}
	for _, a := range alerts {
		id := a.identity()
		if b.seen[id] {
			continue
		}
		b.seen[id] = true
		b.alerts = append(b.alerts, a)
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
	b.alerts, b.seen = nil, nil
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

	buf := &buffer{}
	seen := &recent{max: 20}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/recent", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(seen.snapshot()); err != nil {
			logf("recent: encode: %v", err)
		}
	})
	mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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

	go runFlushLoop(cfg, buf, k, hist, seen)
	go runCompactLoop(hist)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func runFlushLoop(cfg Config, buf *buffer, k *kube, hist *History, seen *recent) {
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
		process(cfg, alerts, k, hist, seen)
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

func process(cfg Config, alerts []Alert, k *kube, hist *History, seen *recent) {
	nodeOf := k.ResolveNodes(alerts)
	groups := Correlate(alerts, nodeOf, DefaultSignatures(), cfg.CorrelateSlack)
	log.Printf("processing %d alerts into %d group(s)", len(alerts), len(groups))

	for _, g := range groups {
		r := Report{Group: g, Enrichment: k.Enrich(g, cfg.EvidenceWindow)}
		r.PriorSeen = hist.Record(g.Signature(), g.Title(), time.Now())
		r.Triage = Narrate(cfg, r)
		r.Narrative = r.Triage.Narrative

		rec := DigestRecord{
			At: time.Now(), Key: g.Key, Title: g.Title(), Severity: g.Severity(),
			PriorSeen: r.PriorSeen, Narrative: r.Narrative, Evidence: renderEvidence(r),
			FixLocation: r.Triage.FixLocation, WhatToChange: r.Triage.WhatToChange,
			Confidence: r.Triage.Confidence, Actionable: r.Triage.Actionable(),
		}
		for _, a := range g.Alerts {
			rec.Alerts = append(rec.Alerts, a.name())
		}
		if err := Deliver(cfg, r); err != nil {
			rec.DeliverErr = err.Error()
			logf("deliver %s: %v", g.Key, err)
		} else {
			rec.Delivered = true
		}
		seen.add(rec)
		log.Printf("digest %s [%s] fix=%s %s | %s", g.Key, g.Severity(),
			orUnknown(r.Triage.FixLocation), g.Title(), oneLine(r.Narrative))
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

// oneLine flattens a narrative for the log, where it doubles as the record of
// what was actually said when the pod is later restarted.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 400 {
		return s[:400] + "..."
	}
	if s == "" {
		return "(no narrative)"
	}
	return s
}

func logf(format string, args ...any) {
	log.Printf(format, args...)
}
