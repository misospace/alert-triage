package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Prometheus queries a Prometheus-compatible metrics backend.
// The HTTP API is a de-facto standard shared by Prometheus, VictoriaMetrics,
// Thanos, Mimir and promxy — a single METRICS_URL covers all of them.
//
// The HTTP client is supplied by the caller and must carry a Timeout: a stalled
// backend that accepts the TCP connection but never responds must not be
// allowed to block the flush loop or the shutdown drain. All request methods
// take a context so cancellation propagates from the flush loop, from the
// SIGTERM drain, and from the client's own timeout.
type Prometheus struct {
	url string
	hc  *http.Client
}

func (p *Prometheus) isConfigured() bool {
	return p != nil && p.url != ""
}

// --- Prometheus API response types ---

type rulesResponse struct {
	Status string    `json:"status"`
	Data   rulesData `json:"data"`
}

type rulesData struct {
	Groups []ruleGroup `json:"groups"`
}

type ruleGroup struct {
	Rules []ruleEntry `json:"rules"`
}

type ruleEntry struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Query string `json:"query"`
}

type queryRangeResponse struct {
	Status string         `json:"status"`
	Data   queryRangeData `json:"data"`
}

type queryRangeData struct {
	ResultType string        `json:"resultType"`
	Result     []queryResult `json:"result"`
}

type queryResult struct {
	Metric map[string]string `json:"metric"`
	Values [][]interface{}   `json:"values"` // [timestamp, "value_string"]
}

// fetchRules retrieves alerting rules and returns a map of alert name to
// PromQL expression. Only rules of type "alert" are included. A flush that
// enriches several groups should call this once and share the result via
// EnrichMetricsWithRules, rather than re-downloading /api/v1/rules for every
// group (issue #66).
func (p *Prometheus) fetchRules(ctx context.Context) (map[string]string, error) {
	data, err := p.get(ctx, "/api/v1/rules")
	if err != nil {
		return nil, err
	}

	var resp rulesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse rules response: %w", err)
	}

	if resp.Status != "success" {
		return nil, fmt.Errorf("rules API returned status: %s", resp.Status)
	}

	rules := make(map[string]string)
	for _, group := range resp.Data.Groups {
		for _, rule := range group.Rules {
			if rule.Type == "alert" {
				rules[rule.Name] = rule.Query
			}
		}
	}
	return rules, nil
}

// queryRange evaluates a PromQL expression over a time range and returns
// compact summaries for each series in the result.
func (p *Prometheus) queryRange(ctx context.Context, expr string, start, end time.Time, step time.Duration) ([]metricSummary, error) {
	values := url.Values{}
	values.Set("query", expr)
	values.Set("start", strconv.FormatFloat(float64(start.Unix()), 'f', -1, 64))
	values.Set("end", strconv.FormatFloat(float64(end.Unix()), 'f', -1, 64))
	values.Set("step", fmt.Sprintf("%ds", int(step.Seconds())))

	data, err := p.get(ctx, "/api/v1/query_range?"+values.Encode())
	if err != nil {
		return nil, err
	}

	var resp queryRangeResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse query_range response: %w", err)
	}

	if resp.Status != "success" {
		return nil, fmt.Errorf("query_range API returned status: %s", resp.Status)
	}

	var summaries []metricSummary
	for _, result := range resp.Data.Result {
		s := summarizeSeries(result.Metric, result.Values)
		if s != nil {
			summaries = append(summaries, *s)
		}
	}
	return summaries, nil
}

// metricSummary holds compact statistics for a single time series.
type metricSummary struct {
	labels    map[string]string
	min       float64
	max       float64
	last      float64
	direction string
}

// summarizeSeries computes min, max, last and direction from raw Prometheus
// values. Returns nil when there are no valid numeric points.
func summarizeSeries(labels map[string]string, values [][]interface{}) *metricSummary {
	if len(values) == 0 {
		return nil
	}

	var nums []float64
	for _, v := range values {
		if len(v) < 2 {
			continue
		}
		if s, ok := v[1].(string); ok {
			if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				nums = append(nums, f)
			}
		}
	}
	if len(nums) == 0 {
		return nil
	}

	minVal, maxVal := nums[0], nums[0]
	for _, n := range nums[1:] {
		if n < minVal {
			minVal = n
		}
		if n > maxVal {
			maxVal = n
		}
	}

	first := nums[0]
	last := nums[len(nums)-1]

	direction := "stable"
	diff := last - first
	if diff > 1e-9 {
		direction = "rising"
	} else if diff < -1e-9 {
		direction = "falling"
	}

	return &metricSummary{
		labels:    labels,
		min:       minVal,
		max:       maxVal,
		last:      last,
		direction: direction,
	}
}

// render formats the summary as a compact one-liner. Label values are
// workload-authored and belong inside the untrusted fence when rendered.
func (s *metricSummary) render() string {
	var labelParts []string
	for _, k := range []string{"namespace", "pod", "container"} {
		if v, ok := s.labels[k]; ok && v != "" {
			labelParts = append(labelParts, fmt.Sprintf("%s=%s", k, v))
		}
	}

	labelCtx := ""
	if len(labelParts) > 0 {
		sort.Strings(labelParts)
		labelCtx = " {" + strings.Join(labelParts, ",") + "}"
	}

	return fmt.Sprintf("min=%.2f max=%.2f last=%.2f %s%s", s.min, s.max, s.last, s.direction, labelCtx)
}

// MetricEvidence separates metric summaries by scope so the renderer can keep
// DIRECT SUBJECT EVIDENCE truthful. Subject holds summaries whose query was
// explicitly bounded to the resolved subject pod: only the fixed context
// metrics narrow on pod, and only when a common pod label was available.
// Context holds everything else. An alert-rule expression is replayed exactly
// as written and may aggregate a namespace, workload, service or cluster, so
// its result is never assumed subject-scoped; a fixed context metric without a
// pod label is namespace-wide too.
type MetricEvidence struct {
	Subject []string
	Context []string
}

// Per-group line budgets for metric evidence (issue #344). The fixed context
// queries filter on namespace at best and an alert-rule expression is replayed
// exactly as written, so one source can return hundreds of series. A single
// head-keep on the assembled list puts that flood in front — rule series are
// appended first and the fixed context queries last — so the flooding source
// keeps the whole head and the operational lines and the per-alert
// diagnostics appended between simply vanish. The budget is therefore split
// per source where the sources are still known: every source gets a bounded
// share, diagnostics are kept unless diagnostics alone exceed the cap, and
// each dropped tail is counted with the kind of line it is (series vs notes).
const (
	maxSubjectMetricLines    = 12
	maxContextMetricLines    = 24
	maxMetricSeriesPerSource = 6
)

// metricSeriesSource is the series one metric source (one alert-rule
// expression, or one fixed context query) contributes before budgeting.
// lines are rendered and self-labeled, so the budgeter may interleave
// sources without losing which query a line came from.
type metricSeriesSource struct {
	name  string
	lines []string
}

// budgetMetricLines assembles one evidence list under a hard cap from the
// sources' diagnostics (notes) and their series lines. Notes are paid first
// and kept in source order: each is a single line explaining why a source is
// silent, and a flood in another source must not squeeze it out. The rest of
// the budget is dealt to the sources round-robin, one line at a time, so no
// source is represented twice before every other source is represented once,
// and no source exceeds maxMetricSeriesPerSource. A truncated source keeps
// one counted tail line in place of its dropped series; series left over
// when even that line no longer fits are folded into one trailing count.
// Every count line names what it counted: a dropped tail of notes is never
// reported as series and vice versa.
func budgetMetricLines(notes []string, sources []metricSeriesSource, max int) []string {
	if len(notes) > max-1 {
		unshownSeries := countUnshownSeries(sources, nil)
		// Both count lines must fit inside max, so the notes keep one slot
		// each: a dropped series tail is never allowed to push the list past
		// the cap the writer-side guard was sized against.
		keep := max - 1
		if unshownSeries > 0 {
			keep = max - 2
		}
		out := append([]string{}, notes[:keep]...)
		out = append(out, fmt.Sprintf("...and %d more notes", len(notes)-keep))
		if unshownSeries > 0 {
			out = append(out, fmt.Sprintf("...and %d more series", unshownSeries))
		}
		return out
	}

	out := append([]string{}, notes...)
	// One slot stays reserved so the trailing count line below always fits;
	// without it the list could exceed max.
	budget := max - len(notes) - 1
	taken := make([]int, len(sources))
	for budget > 0 {
		progressed := false
		for i := range sources {
			if budget == 0 {
				break
			}
			stream := seriesStreamLen(sources[i])
			if taken[i] >= stream {
				continue
			}
			budget--
			progressed = true
			// Items are the capped series lines in order, then, for a source
			// whose series exceeded the cap, one tail line as the last item.
			if cap := min(len(sources[i].lines), maxMetricSeriesPerSource); taken[i] >= cap {
				out = append(out, fmt.Sprintf("...and %d more series for %s",
					len(sources[i].lines)-cap, sources[i].name))
			} else {
				out = append(out, sources[i].lines[taken[i]])
			}
			taken[i]++
		}
		if !progressed {
			break
		}
	}
	if n := countUnshownSeries(sources, taken); n > 0 {
		out = append(out, fmt.Sprintf("...and %d more series", n))
	}
	return out
}

// seriesStreamLen is how many budget slots a source can consume: its capped
// series lines plus one tail line when its series exceeded the cap.
func seriesStreamLen(s metricSeriesSource) int {
	n := min(len(s.lines), maxMetricSeriesPerSource)
	if len(s.lines) > maxMetricSeriesPerSource {
		n++
	}
	return n
}

// countUnshownSeries counts series lines a source holds that are neither in
// the output nor covered by that source's own tail line. A source whose tail
// line was spent has its whole dropped remainder reported there, so it
// contributes nothing here; a source that never got its tail line contributes
// everything not taken. taken[i] > maxMetricSeriesPerSource is the signal
// that the tail line was spent (series slots are exhausted first).
func countUnshownSeries(sources []metricSeriesSource, taken []int) int {
	n := 0
	for i, s := range sources {
		t := 0
		if i < len(taken) {
			t = taken[i]
		}
		shown := min(t, maxMetricSeriesPerSource)
		if t > maxMetricSeriesPerSource {
			continue
		}
		n += len(s.lines) - shown
	}
	return n
}

// sortMetricSummaries puts one source's series in a deterministic order.
// The budget keeps a bounded head and the backend returns series in an
// arbitrary order, so without a sort the surviving lines — and therefore
// what /recent shows for the same fire — change between runs (issue #344).
func sortMetricSummaries(summaries []metricSummary) {
	sort.Slice(summaries, func(i, j int) bool {
		li, lj := summaries[i].labels, summaries[j].labels
		for _, k := range []string{"namespace", "pod", "container"} {
			if li[k] != lj[k] {
				return li[k] < lj[k]
			}
		}
		return summaries[i].render() < summaries[j].render()
	})
}

// EnrichMetricsWithRules queries the Prometheus backend for evidence about the
// group's alerts using a caller-supplied rules map, so a flush that enriches
// several groups fetches /api/v1/rules once and reuses it. Returns compact
// one-liner summaries split by scope (see MetricEvidence). Nil slices are
// returned when no metrics backend is configured; a non-nil Context line
// distinguishes an unreachable backend from "not configured". A non-nil
// rulesErr (from a failed FetchRules) yields the single "metrics backend error"
// line. Each source's contribution is budgeted per group (issue #344, see
// maxContextMetricLines) so a flooding rule-expression result cannot evict
// the fixed context queries or the per-alert diagnostics.
func (p *Prometheus) EnrichMetricsWithRules(ctx context.Context, g Group, window time.Duration, rules map[string]string, rulesErr error) MetricEvidence {
	var out MetricEvidence
	if !p.isConfigured() {
		return out
	}

	// Collect unique alert names from the group.
	alertNames := make(map[string]bool)
	for _, a := range g.Alerts {
		if name := a.Labels["alertname"]; name != "" {
			alertNames[name] = true
		}
	}

	if rulesErr != nil {
		out.Context = append(out.Context, fmt.Sprintf("metrics backend error: %v", rulesErr))
		return out
	}

	now := time.Now()
	start := now.Add(-window)
	step := window / 10
	if step < 15*time.Second {
		step = 15 * time.Second
	}
	if step > 5*time.Minute {
		step = 5 * time.Minute
	}

	// Query the expression for each alert name we found in rules. The
	// expression is replayed as written, so its result may span more than the
	// resolved subject; it stays context rather than being promoted to DIRECT.
	// Series and diagnostics are kept apart because the budget protects the
	// diagnostics from another source's flood (issue #344).
	sortedNames := sortedKeys(alertNames)
	var notes []string
	var sources []metricSeriesSource

	for _, name := range sortedNames {
		expr, ok := rules[name]
		if !ok {
			notes = append(notes, fmt.Sprintf("no rule expression found for alert %s", name))
			continue
		}

		summaries, err := p.queryRange(ctx, expr, start, now, step)
		if err != nil {
			notes = append(notes, fmt.Sprintf("query error for %s: %v", name, err))
			continue
		}
		if len(summaries) == 0 {
			notes = append(notes, fmt.Sprintf("%s: no data in range", name))
			continue
		}

		sources = append(sources, metricSeriesSource{name: name, lines: renderSummaries(name, summaries)})
	}

	// Query fixed context metrics if a namespace label exists on any alert.
	// These are the only queries that can be bounded to the resolved subject:
	// with a pod label they render as direct evidence, without one they are
	// namespace-wide and belong in context.
	ns := g.Label("namespace")
	pod := g.Label("pod")
	if ns != "" {
		fixedNotes, fixedSources := p.queryContextMetrics(ctx, ns, pod, start, now, step)
		if pod != "" {
			out.Subject = budgetMetricLines(fixedNotes, fixedSources, maxSubjectMetricLines)
		} else {
			notes = append(notes, fixedNotes...)
			sources = append(sources, fixedSources...)
		}
	}
	out.Context = budgetMetricLines(notes, sources, maxContextMetricLines)

	return out
}

// renderSummaries formats one source's series as self-labeled lines, sorted
// so the bounded head is the same head every run sees.
func renderSummaries(name string, summaries []metricSummary) []string {
	sortMetricSummaries(summaries)
	lines := make([]string, 0, len(summaries))
	for _, s := range summaries {
		lines = append(lines, fmt.Sprintf("%s %s", name, s.render()))
	}
	return lines
}

// queryContextMetrics queries a fixed set of operational metrics for the given
// namespace and optional pod: container restarts, memory working set vs limit,
// CPU throttling ratio. Like the per-rule loop, it keeps diagnostics apart from
// series so the per-source budget can protect them (issue #344).
func (p *Prometheus) queryContextMetrics(ctx context.Context, ns, pod string, start, end time.Time, step time.Duration) ([]string, []metricSeriesSource) {
	var notes []string
	var sources []metricSeriesSource

	for _, q := range contextMetricQueries(ns, pod) {
		summaries, err := p.queryRange(ctx, q.expr, start, end, step)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: query error: %v", q.name, err))
			continue
		}
		if len(summaries) == 0 {
			notes = append(notes, fmt.Sprintf("%s: no data", q.name))
			continue
		}
		sources = append(sources, metricSeriesSource{name: q.name, lines: renderSummaries(q.name, summaries)})
	}

	return notes, sources
}

// contextMetricQueries builds the fixed context-metric expressions for the
// given namespace and optional pod, escaping label values for PromQL string
// literals. Kept pure (no I/O) so the escaping can be asserted without a
// live backend.
//
// The memory_working_set ratio matches on (namespace, pod, container) so a
// multi-container pod divides each container's working set by its own limit
// (issue #190). `ignoring(container)` would either invalidate one-to-one
// matching on two series with otherwise identical labels or, with only one
// series per side, divide one container's usage by another container's limit
// and strip the container label from the output, hiding where the pressure
// came from.
func contextMetricQueries(ns, pod string) []struct {
	name string
	expr string
} {
	labelFilter := fmt.Sprintf(`namespace="%s"`, escapeLabelValue(ns))
	if pod != "" {
		labelFilter += fmt.Sprintf(`,pod="%s"`, escapeLabelValue(pod))
	}

	return []struct {
		name string
		expr string
	}{
		{"container_restarts", fmt.Sprintf(`kube_pod_container_status_restarts_total{%s}`, labelFilter)},
		{"memory_working_set", fmt.Sprintf(`container_memory_working_set_bytes{%s} / on(namespace, pod, container) container_memory_limit_bytes{%s}`, labelFilter, labelFilter)},
		{"cpu_throttle_ratio", fmt.Sprintf(`rate(container_cpu_throttled_seconds_total{%s}[5m])`, labelFilter)},
	}
}

// escapeLabelValue escapes backslashes, double quotes, newlines and carriage
// returns in a label value for safe embedding in PromQL string literals.
// The backslash pass runs first: escaping quotes first would let its pass
// double the backslashes it inserted, and an unescaped backslash is read by
// the backend as the start of an escape sequence, breaking the query. The
// newline and carriage-return passes must also run after it, and PromQL
// string literals cannot contain a raw line break at all, so a label value
// carrying one (label values are arbitrary UTF-8; the alert source, not
// Kubernetes name validation, decides what arrives) yields a selector the
// parser rejects and the group loses all metric context (issue #203, same
// failure mode as the backslash case in issue #161).
func escapeLabelValue(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return strings.ReplaceAll(v, "\r", `\r`)
}

// metricsBodyCap bounds how much of a Prometheus response we'll buffer before
// failing the request. It mirrors the limit the logs backend applies (4 MiB)
// so the two enrichment paths are consistent. A misconfigured backend that
// streams a runaway /api/v1/rules or /api/v1/query_range reply otherwise
// forces the whole body into memory on the flush-loop goroutine.
const metricsBodyCap = 4 << 20

func (p *Prometheus) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.url+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, path)
	}
	// Read cap+1 bytes so an over-cap response is unambiguously detectable:
	// io.LimitReader silently truncates, but a body whose payload exceeds
	// metricsBodyCap will yield cap+1 bytes here and we surface that as an
	// error instead of allocating unboundedly or returning a truncated reply.
	body, err := io.ReadAll(io.LimitReader(resp.Body, metricsBodyCap+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > metricsBodyCap {
		return nil, fmt.Errorf("metrics: response from %s exceeded %d bytes", path, metricsBodyCap)
	}
	return body, nil
}
