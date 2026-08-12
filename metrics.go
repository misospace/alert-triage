package main

import (
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
// PromQL expression. Only rules of type "alert" are included.
func (p *Prometheus) fetchRules() (map[string]string, error) {
	data, err := p.get("/api/v1/rules")
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
func (p *Prometheus) queryRange(expr string, start, end time.Time, step time.Duration) ([]metricSummary, error) {
	values := url.Values{}
	values.Set("query", expr)
	values.Set("start", strconv.FormatFloat(float64(start.Unix()), 'f', -1, 64))
	values.Set("end", strconv.FormatFloat(float64(end.Unix()), 'f', -1, 64))
	values.Set("step", fmt.Sprintf("%ds", int(step.Seconds())))

	data, err := p.get("/api/v1/query_range?" + values.Encode())
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

// EnrichMetrics queries the Prometheus backend for evidence about the group's
// alerts. Returns compact one-liner summaries. Nil is returned when no metrics
// backend is configured; a non-nil slice with error lines distinguishes an
// unreachable backend from "not configured".
func (p *Prometheus) EnrichMetrics(g Group, window time.Duration) []string {
	if !p.isConfigured() {
		return nil
	}

	var lines []string

	// Collect unique alert names from the group.
	alertNames := make(map[string]bool)
	for _, a := range g.Alerts {
		if name := a.Labels["alertname"]; name != "" {
			alertNames[name] = true
		}
	}

	// Fetch rules to find expressions for our alerts.
	rules, err := p.fetchRules()
	if err != nil {
		lines = append(lines, fmt.Sprintf("metrics backend error: %v", err))
		return lines
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

	// Query the expression for each alert name we found in rules.
	sortedNames := make([]string, 0, len(alertNames))
	for name := range alertNames {
		sortedNames = append(sortedNames, name)
	}
	sort.Strings(sortedNames)

	for _, name := range sortedNames {
		expr, ok := rules[name]
		if !ok {
			lines = append(lines, fmt.Sprintf("no rule expression found for alert %s", name))
			continue
		}

		summaries, err := p.queryRange(expr, start, now, step)
		if err != nil {
			lines = append(lines, fmt.Sprintf("query error for %s: %v", name, err))
			continue
		}
		if len(summaries) == 0 {
			lines = append(lines, fmt.Sprintf("%s: no data in range", name))
			continue
		}

		for _, s := range summaries {
			line := fmt.Sprintf("%s %s", name, s.render())
			lines = append(lines, line)
		}
	}

	// Query fixed context metrics if namespace label exists on any alert.
	ns := g.Label("namespace")
	pod := g.Label("pod")
	if ns != "" {
		contextMetrics := p.queryContextMetrics(ns, pod, start, now, step)
		lines = append(lines, contextMetrics...)
	}

	return lines
}

// queryContextMetrics queries a fixed set of operational metrics for the given
// namespace and optional pod: container restarts, memory working set vs limit,
// CPU throttling ratio.
func (p *Prometheus) queryContextMetrics(ns, pod string, start, end time.Time, step time.Duration) []string {
	var lines []string

	labelFilter := fmt.Sprintf(`namespace="%s"`, escapeLabelValue(ns))
	if pod != "" {
		labelFilter += fmt.Sprintf(`,pod="%s"`, escapeLabelValue(pod))
	}

	type metricQuery struct {
		name string
		expr string
	}

	queries := []metricQuery{
		{"container_restarts", fmt.Sprintf(`kube_pod_container_status_restarts_total{%s}`, labelFilter)},
		{"memory_working_set", fmt.Sprintf(`container_memory_working_set_bytes{%s} / ignoring(container) container_memory_limit_bytes{%s}`, labelFilter, labelFilter)},
		{"cpu_throttle_ratio", fmt.Sprintf(`rate(container_cpu_throttled_seconds_total{%s}[5m])`, labelFilter)},
	}

	for _, q := range queries {
		summaries, err := p.queryRange(q.expr, start, end, step)
		if err != nil {
			lines = append(lines, fmt.Sprintf("%s: query error: %v", q.name, err))
			continue
		}
		if len(summaries) == 0 {
			lines = append(lines, fmt.Sprintf("%s: no data", q.name))
			continue
		}
		for _, s := range summaries {
			lines = append(lines, fmt.Sprintf("%s %s", q.name, s.render()))
		}
	}

	return lines
}

// escapeLabelValue escapes double quotes in a label value for safe embedding
// in PromQL string literals.
func escapeLabelValue(v string) string {
	return strings.ReplaceAll(v, `"`, `\"`)
}

func (p *Prometheus) get(path string) ([]byte, error) {
	req, err := http.NewRequest("GET", p.url+path, nil)
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
	return io.ReadAll(resp.Body)
}
