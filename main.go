package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var version = "dev"

type Config struct {
	ListenAddr     string
	WebhookToken   string
	MaxAlerts      int
	MaxGroups      int
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

	// TriageLabel, when set, makes the webhook drop any alert whose
	// labels[TriageLabel] is not "true". It defaults to empty so a fresh
	// deployment triages everything (fail-open, matching WEBHOOK_TOKEN):
	// nothing in either cluster labels its rules today, and dropping them
	// silently would look identical to a quiet week. Flip this on after
	// the PrometheusRules in home-ops carry the label.
	TriageLabel string

	// DroppedByLabel counts alerts the webhook dropped because they
	// lacked the TriageLabel. Surfaced in the delivery log so a
	// label-rule typo is visible without waiting on Prometheus metrics.
	DroppedByLabel atomic.Int64
}

func loadConfig() Config {
	return Config{
		ListenAddr:     envDefault("LISTEN_ADDR", ":8080"),
		WebhookToken:   os.Getenv("WEBHOOK_TOKEN"),
		MaxAlerts:      envInt("MAX_ALERTS", 500),
		MaxGroups:      envInt("MAX_GROUPS", 12),
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
		TriageLabel:    os.Getenv("TRIAGE_LABEL"),
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
	max     int
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
// It returns how many alerts were refused because the window is full. Refusing
// the newest is deliberate: the alerts that opened the window are the ones that
// explain a cascade, so evicting them to make room for the tail would discard
// the trigger and keep the collateral.
func (b *buffer) add(alerts []Alert) (rejected int) {
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
		if b.max > 0 && len(b.alerts) >= b.max {
			rejected++
			continue
		}
		b.seen[id] = true
		b.alerts = append(b.alerts, a)
	}
	return rejected
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

	// Log backend (optional)
	lb := newLogBackend(
		os.Getenv("LOGS_URL"),
		os.Getenv("LOGS_FLAVOR"),
		envInt("LOGS_LIMIT", 200),
	)

	buf := &buffer{max: cfg.MaxAlerts}
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
	mux.HandleFunc("/webhook", webhookHandler(&cfg, buf))

	go runFlushLoop(&cfg, buf, k, lb, hist, seen)
	go runCompactLoop(hist)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func webhookHandler(cfg *Config, buf *buffer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !authorized(cfg.WebhookToken, r) {
			logf("webhook: rejected request without a valid token")
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
		// Opt-in triage: when TriageLabel is set, only alerts whose label is
		// exactly "true" are buffered. An empty TriageLabel fails open so a
		// fresh image keeps triaging everything; gates are flipped on after
		// the rules in home-ops carry the label.
		var dropped int
		if cfg.TriageLabel != "" {
			optIn := firing[:0]
			for _, a := range firing {
				if a.Labels[cfg.TriageLabel] == "true" {
					optIn = append(optIn, a)
				} else {
					dropped++
				}
			}
			firing = optIn
			if dropped > 0 {
				cfg.DroppedByLabel.Add(int64(dropped))
				logf("webhook: dropped %d alert(s) without %s=true (cumulative %d)",
					dropped, cfg.TriageLabel, cfg.DroppedByLabel.Load())
			}
		}
		if len(firing) > 0 {
			if rejected := buf.add(firing); rejected > 0 {
				logf("webhook: window full at %d alerts, refused %d", cfg.MaxAlerts, rejected)
			}
		}
		// Ack immediately; Alertmanager should never block on triage work.
		w.WriteHeader(http.StatusAccepted)
	}
}

// authorized checks the shared secret guarding /webhook. Every accepted group
// costs a model call and a message in the operator channel, so an open endpoint
// is both a spend and a spoofing vector.
//
// The token arrives as a bearer token because AlertmanagerConfig cannot set
// arbitrary headers on a webhook receiver — httpConfig offers authorization,
// basicAuth and bearerTokenSecret and nothing else. X-Webhook-Token is accepted
// as well, since it is far easier to send by hand when replaying alerts.
//
// An unset token accepts everything and says so once. Enforcing unconditionally
// would mean a new image silently rejects every alert until the receiver has
// been given the secret, and silent triage failure is indistinguishable from a
// quiet week.
func authorized(token string, r *http.Request) bool {
	if token == "" {
		warnUnauthenticated.Do(func() {
			log.Print("WEBHOOK_TOKEN is unset: /webhook accepts unauthenticated requests")
		})
		return true
	}
	if h := r.Header.Get("X-Webhook-Token"); h != "" {
		return subtle.ConstantTimeCompare([]byte(h), []byte(token)) == 1
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(bearer), []byte(token)) == 1
}

var warnUnauthenticated sync.Once

func runFlushLoop(cfg *Config, buf *buffer, k *kube, lb *LogBackend, hist *History, seen *recent) {
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
		process(cfg, alerts, k, lb, hist, seen)
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

func process(cfg *Config, alerts []Alert, k *kube, lb *LogBackend, hist *History, seen *recent) {
	nodeOf := k.ResolveNodes(alerts)
	groups := Correlate(alerts, nodeOf, DefaultSignatures(), cfg.CorrelateSlack)
	log.Printf("processing %d alerts into %d group(s)", len(alerts), len(groups))

	// One model call per group means a burst of unique alerts sets the spend. Past
	// the cap the digest still ships with its evidence; only the narrative is
	// skipped, most urgent groups first, so what is lost is the explanation of the
	// least urgent thing rather than the report of it.
	sort.SliceStable(groups, func(i, j int) bool {
		return severityRank(groups[i].Severity()) > severityRank(groups[j].Severity())
	})
	if cfg.MaxGroups > 0 && len(groups) > cfg.MaxGroups {
		log.Printf("narrating the %d most urgent of %d groups; the rest ship without one (MAX_GROUPS=%d)",
			cfg.MaxGroups, len(groups), cfg.MaxGroups)
	}

	for i, g := range groups {
		r := Report{Group: g, Enrichment: k.Enrich(g, cfg.EvidenceWindow, lb)}
		r.PriorSeen = hist.Record(g.Signature(), g.Title(), time.Now())
		if cfg.MaxGroups <= 0 || i < cfg.MaxGroups {
			r.Triage = Narrate(cfg, r)
		}
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

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	logf("bad integer for %s=%q, using %d", key, v, fallback)
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
