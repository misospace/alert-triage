package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
	APIFormat      string
	DiscordURL     string
	HistoryPath    string
	FlushDelay     time.Duration
	MaxWindow      time.Duration
	CorrelateSlack time.Duration
	EvidenceWindow time.Duration
	Retention      time.Duration
	NarrateTimeout time.Duration

	// NarrateConcurrency caps how many model calls run at once for a
	// single flush. The host is parallel-capable, but LiteLLM's
	// `self-hosted` profile tops out at max_parallel_requests: 2, so
	// exceeding it only queues upstream. Default 2; raise only with
	// a model backend that can absorb it.
	NarrateConcurrency int

	// TriageLabel, when set, makes the webhook drop any alert whose
	// labels[TriageLabel] is not "true". It defaults to empty so a fresh
	// deployment triages everything (fail-open, matching WEBHOOK_TOKEN):
	// nothing in either cluster labels its rules today, and dropping them
	// silently would look identical to a quiet week. Flip this on after
	// the PrometheusRules in home-ops carry the label.
	TriageLabel string

	// Cluster names the cluster this instance serves, matching the `cluster`
	// label the local Prometheus stamps on alerts. Alerts without that label
	// inherit this value; it also gates enrichment when the two disagree.
	Cluster string

	// MetricsURL is the base URL of a Prometheus-compatible backend
	// (Prometheus, VictoriaMetrics, Thanos, Mimir, promxy). When set, the
	// digest queries /api/v1/rules and /api/v1/query_range to attach metric
	// evidence to each alert group. Unset keeps today's behaviour.
	MetricsURL string

	// GitOpsRepo and GitOpsPath are the fallback repo URL and directory
	// used when a workload carries no Flux or Argo annotations. They are
	// never concatenated into a result on their own; an unset pair is a
	// no-op rather than a fabricated location.
	GitOpsRepo string
	GitOpsPath string

	// GitHubRepo / GitHubToken mirror actionable incidents as GitHub issues,
	// keyed on the group signature so re-fires update one durable record.
	// Both unset keeps the original chat-only behaviour; see issue #14.
	GitHubRepo  string
	GitHubToken string

	// GitHubPR holds the opt-in gate for the PR write arm (issue #36). It is
	// nil unless GITHUB_PR_OPT_IN is set with a token, repo and path
	// allowlist; see loadPRConfig. A nil value keeps the pre-#36 behaviour.
	GitHubPR *PRConfig

	// GrafanaURL is the base URL of a Grafana instance. When set, digests
	// gain an Explore link for the alerting expression and (if GrafanaLogsDS
	// is also set) a logs Explore link scoped to the same window. Unset keeps
	// the linkless behaviour; a malformed value is worse than none, so a
	// relative or scheme-less URL is dropped at config time.
	GrafanaURL       string
	GrafanaMetricsDS string
	GrafanaLogsDS    string

	// IssueCommentInterval sets the floor between comments on a re-firing
	// issue. Default 12h; severity changes bypass the gate so an alert that
	// escalates to critical is always noted.
	IssueCommentInterval time.Duration

	// DroppedByLabel counts alerts the webhook dropped because they
	// lacked the TriageLabel. Surfaced in the delivery log so a
	// label-rule typo is visible without waiting on Prometheus metrics.
	DroppedByLabel atomic.Int64
}

func loadConfig() Config {
	return Config{
		ListenAddr:           envDefault("LISTEN_ADDR", ":8080"),
		WebhookToken:         os.Getenv("WEBHOOK_TOKEN"),
		MaxAlerts:            envInt("MAX_ALERTS", 500),
		MaxGroups:            envInt("MAX_GROUPS", 12),
		NarrateConcurrency:   envInt("NARRATE_CONCURRENCY", 2),
		LiteLLMURL:           envDefault("LITELLM_URL", ""),
		LiteLLMKey:           os.Getenv("LITELLM_API_KEY"),
		Model:                envDefault("MODEL", "dsv4f"),
		APIFormat:            envDefault("API_FORMAT", "openai"),
		DiscordURL:           os.Getenv("DISCORD_WEBHOOK_URL"),
		HistoryPath:          envDefault("HISTORY_PATH", "/data/history.jsonl"),
		FlushDelay:           envDuration("FLUSH_DELAY", 3*time.Minute),
		MaxWindow:            envDuration("MAX_WINDOW", 10*time.Minute),
		CorrelateSlack:       envDuration("CORRELATE_SLACK", 5*time.Minute),
		EvidenceWindow:       envDuration("EVIDENCE_WINDOW", 30*time.Minute),
		Retention:            envDuration("RETENTION", 7*24*time.Hour),
		NarrateTimeout:       envDuration("NARRATE_TIMEOUT", 120*time.Second),
		TriageLabel:          os.Getenv("TRIAGE_LABEL"),
		Cluster:              os.Getenv("CLUSTER"),
		MetricsURL:           os.Getenv("METRICS_URL"),
		GitOpsRepo:           os.Getenv("GITOPS_REPO"),
		GitOpsPath:           os.Getenv("GITOPS_PATH"),
		GitHubRepo:           os.Getenv("GITHUB_REPO"),
		GitHubToken:          os.Getenv("GITHUB_TOKEN"),
		GitHubPR:             loadPRConfig(),
		IssueCommentInterval: envDuration("ISSUE_COMMENT_INTERVAL", 12*time.Hour),
		GrafanaURL:           envGrafanaURL("GRAFANA_URL"),
		GrafanaMetricsDS:     os.Getenv("GRAFANA_METRICS_DS"),
		GrafanaLogsDS:        os.Getenv("GRAFANA_LOGS_DS"),
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
		logf("history: %v", err)
	}
	k, err := newKube(cfg.Cluster)
	if err != nil {
		// Enrichment is optional; without it the digest still correlates and
		// narrates, so this must not be fatal for local runs or a broken SA.
		logf("kubernetes unavailable, enrichment disabled: %v", err)
	} else if cfg.Cluster == "" {
		log.Print("CLUSTER is unset: every group is enriched against this API server. " +
			"Set it if this instance receives alerts from more than one cluster.")
	}

	var prom *Prometheus
	if cfg.MetricsURL != "" {
		prom = &Prometheus{
			url: cfg.MetricsURL,
			hc:  &http.Client{Timeout: 15 * time.Second},
		}
		log.Printf("metrics backend configured at %s", cfg.MetricsURL)
	}

	buf := &buffer{max: cfg.MaxAlerts}
	seen := &recent{max: 20}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/recent", requireAuth(cfg.WebhookToken, "recent", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(seen.snapshot()); err != nil {
			logf("recent: encode: %v", err)
		}
	}))
	mux.HandleFunc("/webhook", webhookHandler(&cfg, buf))
	mux.HandleFunc("/metrics", requireAuth(cfg.WebhookToken, "metrics", metricsHandler()))

	go runFlushLoop(context.Background(), &cfg, buf, k, hist, seen, prom)
	go runCompactLoop(context.Background(), hist)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Graceful shutdown: catch SIGTERM/SIGINT so buffered alerts are flushed
	// rather than silently dropped on pod eviction or node drain.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		log.Print("shutdown signal received; draining buffer before exit")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			logf("server shutdown: %v", err)
		}
		// Drain any alerts still sitting in the buffer. The flush loop is no
		// longer running (the process is about to exit), so we call process
		// directly for every remaining batch.
		drained := drainBuffer(ctx, &cfg, buf, k, hist, seen, prom)
		log.Printf("shutdown: flushed %d buffered alert(s)", drained)
		os.Exit(0)
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
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
			// Count alerts that survived the label gate and made it into the
			// buffer, not the raw payload: a deluge of already-resolved
			// alerts must not look like a busy day on the dashboard.
			metrics.observeAlerts(len(firing))
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

// requireAuth guards a read endpoint (e.g. /recent, /metrics) with the same
// token check as /webhook. When the token is unset it fails open, matching the
// webhook's documented behaviour, so a fresh deployment does not break.
func requireAuth(token, name string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorized(token, r) {
			logf("%s: rejected request without a valid token", name)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

var warnUnauthenticated sync.Once

func runFlushLoop(ctx context.Context, cfg *Config, buf *buffer, k *kube, hist *History, seen *recent, prom *Prometheus) {
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
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		alerts := buf.take(time.Now(), cfg.FlushDelay, cfg.MaxWindow)
		if len(alerts) == 0 {
			continue
		}
		process(ctx, cfg, alerts, k, hist, seen, prom)
	}
}

func runCompactLoop(ctx context.Context, hist *History) {
	tick := time.NewTicker(6 * time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if err := hist.Compact(); err != nil {
			logf("history: compact: %v", err)
		}
	}
}

// drainBuffer empties the buffer synchronously by calling process on
// every remaining batch. It is the SIGTERM "flush before exit" path,
// extracted into a helper so a test can assert process runs and the
// buffer is empty on return without driving the full signal goroutine.
func drainBuffer(ctx context.Context, cfg *Config, buf *buffer, k *kube, hist *History, seen *recent, prom *Prometheus) (drained int) {
	for {
		buf.mu.Lock()
		if len(buf.alerts) == 0 {
			buf.mu.Unlock()
			return drained
		}
		alerts := buf.alerts
		buf.alerts = nil
		buf.seen = nil
		buf.mu.Unlock()
		process(ctx, cfg, alerts, k, hist, seen, prom)
		drained += len(alerts)
	}
}

func process(ctx context.Context, cfg *Config, alerts []Alert, k *kube, hist *History, seen *recent, prom *Prometheus) {
	nodeOf := k.ResolveNodes(ctx, alerts)
	groups := Correlate(alerts, nodeOf, DefaultSignatures(), cfg.CorrelateSlack, cfg.Cluster)
	// Count groups once per flush; if the count stays at zero while alerts
	// arrive, the correlation rules are misbehaving, not the network.
	metrics.observeGroups(len(groups))
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

	// First pass: gather enrichment, metrics, and history. These are fast
	// API reads; running them serially avoids putting extra pressure on the
	// API server. Narration is the only step slow enough to be worth
	// parallelising.
	//
	// The rules payload is identical for every group in a flush, so fetch it
	// once here and share it across the per-group metric enrichment instead
	// of re-downloading /api/v1/rules for each group (issue #66).
	var rules map[string]string
	var rulesErr error
	if prom != nil && len(groups) > 0 {
		rules, rulesErr = prom.FetchRules(ctx)
	}
	reports := make([]Report, len(groups))
	narrateIdx := make([]int, 0, len(groups))
	for i, g := range groups {
		r := Report{Cfg: cfg, Group: g, Enrichment: k.Enrich(ctx, g, cfg.EvidenceWindow, cfg)}
		if prom != nil {
			r.Metrics = prom.EnrichMetricsWithRules(ctx, g, cfg.EvidenceWindow, rules, rulesErr)
		}
		r.PriorSeen = hist.Record(g.Signature(), g.Title(), time.Now())
		reports[i] = r
		if cfg.MaxGroups <= 0 || i < cfg.MaxGroups {
			narrateIdx = append(narrateIdx, i)
		}
	}

	// Second pass: narration. Each call is independent — a slow or failed
	// model call for one group must not cancel or delay the others. Bounded
	// by NarrateConcurrency so the host isn't flooded past what the model
	// backend can absorb. Order of completion is irrelevant: results are
	// written back into the per-group slot, and delivery walks the slots
	// in the original severity order.
	concurrency := cfg.NarrateConcurrency
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, i := range narrateIdx {
		i := i
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			// During shutdown the drain context carries the pod's termination
			// deadline. Once it is spent, stop issuing narrate calls: the
			// digest still ships with its evidence, but a model call would only
			// push the drain past the grace period and get cut off by SIGKILL.
			// The skip is logged and counted so silent narration loss stays
			// visible.
			if err := ctx.Err(); err != nil {
				logf("narrate %s: skipped, shutdown deadline reached: %v", reports[i].Group.Key, err)
				metrics.observeNarration(true)
				return
			}
			metrics.observeModelCall()
			reports[i].Triage = Narrate(ctx, cfg, reports[i])
			// A non-actionable triage without a narrative means the model
			// call failed: the digest still ships with evidence, but the
			// explanation was lost. This counter is the only signal that
			// a silent narration regression has happened.
			metrics.observeNarration(reports[i].Triage.Narrative == "" && reports[i].Triage.Confidence == "")
			reports[i].Narrative = reports[i].Triage.Narrative
		}()
	}
	wg.Wait()

	// Third pass: deliver in the original severity order. Reordering would
	// invert the most-urgent-first contract that the sort above established.
	for i, g := range groups {
		r := reports[i]
		rec := DigestRecord{
			At: time.Now(), Key: g.Key, Title: g.Title(), Severity: g.Severity(),
			PriorSeen: r.PriorSeen, Narrative: r.Narrative, Evidence: renderEvidence(r),
			FixLocation: r.Triage.FixLocation, WhatToChange: r.Triage.WhatToChange,
			Confidence: r.Triage.Confidence, Actionable: r.Triage.Actionable(),
		}
		for _, a := range g.Alerts {
			rec.Alerts = append(rec.Alerts, a.name())
		}
		if err := Deliver(ctx, cfg, r); err != nil {
			rec.DeliverErr = err.Error()
			metrics.observeDelivery(false)
			logf("deliver %s: %v", g.Key, err)
		} else {
			rec.Delivered = true
			metrics.observeDelivery(true)
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
