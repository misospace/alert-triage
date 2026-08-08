package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Prometheus wraps a Prometheus-compatible HTTP API client.
type Prometheus struct {
	url string
	hc  *http.Client
}

// newPrometheus creates a Prometheus client. Returns nil if urlStr is empty,
// which signals "no metrics backend configured" downstream.
func newPrometheus(urlStr string) *Prometheus {
	if urlStr == "" {
		return nil
	}
	urlStr = strings.TrimRight(urlStr, "/")
	return &Prometheus{
		url: urlStr,
		hc:  &http.Client{Timeout: 10 * time.Second},
	}
}

// MetricSummary is a compact rendering of a single metric's trajectory.
type MetricSummary struct {
	Name      string
	Min       float64
	Max       float64
	Last      float64
	Direction string // "rising", "falling", "stable"
	HasData   bool
}

// ---------- Prometheus API response types ----------

type rulesResponse struct {
	Status string    `json:"status"`
	Data   rulesData `json:"data"`
}

type rulesData struct {
	Groups []ruleGroup `json:"groups"`
}

type ruleGroup struct {
	Name  string      `json:"name"`
	Rules []ruleEntry `json:"rules"`
}

type ruleEntry struct {
	Name   string            `json:"name"`
	Type   string            `json:"type"` // "alerting" or "recording"
	Query  string            `json:"query"`
	Labels map[string]string `json:"labels"`
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
	Values [][]any           `json:"values"` // [timestamp, value_string]
}

// ---------- Public methods ----------

// FetchRuleExpression finds the PromQL expression for an alerting rule by name.
func (p *Prometheus) FetchRuleExpression(alertName string) (string, error) {
	if p == nil {
		return "", fmt.Errorf("no metrics backend configured")
	}

	resp, err := p.hc.Get(p.url + "/api/v1/rules?type=alert")
	if err != nil {
		return "", fmt.Errorf("fetch rules: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("rules endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var rules rulesResponse
	if err := json.NewDecoder(resp.Body).Decode(&rules); err != nil {
		return "", fmt.Errorf("decode rules: %w", err)
	}
	if rules.Status != "success" {
		return "", fmt.Errorf("rules API returned status=%s", rules.Status)
	}

	for _, group := range rules.Data.Groups {
		for _, rule := range group.Rules {
			if rule.Type == "alerting" && rule.Name == alertName {
				return rule.Query, nil
			}
		}
	}

	return "", fmt.Errorf("no alerting rule named %q found", alertName)
}

// QueryRange executes a range query and returns all numeric values across all series.
func (p *Prometheus) QueryRange(expr string, start, end time.Time) ([]float64, error) {
	if p == nil {
		return nil, fmt.Errorf("no metrics backend configured")
	}

	q := url.Values{}
	q.Set("query", expr)
	q.Set("start", strconv.FormatFloat(float64(start.Unix())+float64(start.Nanosecond())/1e9, 'f', -1, 64))
	q.Set("end", strconv.FormatFloat(float64(end.Unix())+float64(end.Nanosecond())/1e9, 'f', -1, 64))
	q.Set("step", "15s")

	reqURL := p.url + "/api/v1/query_range?" + q.Encode()

	resp, err := p.hc.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("query_range: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("query_range returned %d: %s", resp.StatusCode, string(body))
	}

	var qr queryRangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&qr); err != nil {
		return nil, fmt.Errorf("decode query_range: %w", err)
	}
	if qr.Status != "success" {
		return nil, fmt.Errorf("query_range API returned status=%s", qr.Status)
	}

	var values []float64
	for _, result := range qr.Data.Result {
		for _, v := range result.Values {
			if len(v) < 2 {
				continue
			}
			if s, ok := v[1].(string); ok {
				if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
					values = append(values, f)
				}
			}
		}
	}

	return values, nil
}

// Summarize computes a MetricSummary from a slice of float values.
func Summarize(name string, values []float64) MetricSummary {
	if len(values) == 0 {
		return MetricSummary{Name: name, HasData: false}
	}

	minVal, maxVal := values[0], values[0]
	for _, v := range values {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
	}

	last := values[len(values)-1]
	direction := computeDirection(values)

	return MetricSummary{
		Name:      name,
		Min:       minVal,
		Max:       maxVal,
		Last:      last,
		Direction: direction,
		HasData:   true,
	}
}

func computeDirection(values []float64) string {
	if len(values) < 3 {
		return "stable"
	}
	mid := len(values) / 2
	var firstSum, secondSum float64
	for i := 0; i < mid; i++ {
		firstSum += values[i]
	}
	for i := mid; i < len(values); i++ {
		secondSum += values[i]
	}
	firstAvg := firstSum / float64(mid)
	secondAvg := secondSum / float64(len(values)-mid)

	// Handle near-zero averages
	if math.Abs(firstAvg) < 1e-9 && math.Abs(secondAvg) < 1e-9 {
		return "stable"
	}

	// When first half is near zero, direction follows the sign of second half
	if math.Abs(firstAvg) < 1e-9 {
		if secondAvg > 0 {
			return "rising"
		}
		if secondAvg < 0 {
			return "falling"
		}
		return "stable"
	}

	ratio := secondAvg / firstAvg
	if ratio > 1.05 {
		return "rising"
	}
	if ratio < 0.95 {
		return "falling"
	}
	return "stable"
}

// podNS pairs a pod name with its namespace for metric queries.
type podNS struct {
	Pod string
	NS  string
}

// extractPodNamespaces returns unique namespace/pod pairs from the group's alerts.
func extractPodNamespaces(g Group) []podNS {
	seen := map[string]bool{}
	var pods []podNS
	for _, a := range g.Alerts {
		pod := a.Labels["pod"]
		ns := a.Labels["namespace"]
		if pod == "" {
			continue
		}
		key := ns + "/" + pod
		if !seen[key] {
			seen[key] = true
			pods = append(pods, podNS{Pod: pod, NS: ns})
		}
	}
	return pods
}

// FetchGroupMetrics queries the firing rule's expression and a fixed set of
// contextual metrics for each pod in the group. Returns nil when p is nil
// (no backend configured), or an empty slice when queries return no data.
func (p *Prometheus) FetchGroupMetrics(g Group, window time.Duration) []MetricSummary {
	if p == nil {
		return nil
	}

	var summaries []MetricSummary
	now := time.Now()
	start := now.Add(-window)

	// 1. Query the firing rule's expression trajectory
	alertName := g.Alerts[0].Labels["alertname"]
	if expr, err := p.FetchRuleExpression(alertName); err == nil {
		values, qErr := p.QueryRange(expr, start, now)
		if qErr != nil {
			log.Printf("prometheus: query_range for %q: %v", alertName, qErr)
		} else {
			summaries = append(summaries, Summarize(alertName+" (rule)", values))
		}
	} else {
		log.Printf("prometheus: %v", err)
	}

	// 2. Contextual metrics for each pod in the group (cap at 5 to bound queries)
	pods := extractPodNamespaces(g)
	if len(pods) > 5 {
		log.Printf("prometheus: capping pod metrics to 5 (group has %d pods)", len(pods))
		pods = pods[:5]
	}

	for _, pn := range pods {
		// Container restarts
		restartExpr := fmt.Sprintf("kube_pod_container_status_restarts_total{namespace=%q,pod=%q}", pn.NS, pn.Pod)
		values, err := p.QueryRange(restartExpr, start, now)
		if err != nil {
			log.Printf("prometheus: restarts for %s/%s: %v", pn.NS, pn.Pod, err)
		} else {
			summaries = append(summaries, Summarize("restarts "+pn.Pod, values))
		}

		// Memory working set
		memExpr := fmt.Sprintf("container_memory_working_set_bytes{namespace=%q,pod=%q}", pn.NS, pn.Pod)
		values, err = p.QueryRange(memExpr, start, now)
		if err != nil {
			log.Printf("prometheus: memory for %s/%s: %v", pn.NS, pn.Pod, err)
		} else {
			summaries = append(summaries, Summarize("memory "+pn.Pod, values))
		}

		// CPU throttling ratio
		cpuExpr := fmt.Sprintf("rate(container_cpu_cfs_throttled_seconds_total{namespace=%q,pod=%q}[5m])", pn.NS, pn.Pod)
		values, err = p.QueryRange(cpuExpr, start, now)
		if err != nil {
			log.Printf("prometheus: cpu throttle for %s/%s: %v", pn.NS, pn.Pod, err)
		} else {
			summaries = append(summaries, Summarize("cpu_throttle "+pn.Pod, values))
		}
	}

	return summaries
}

// ---------- Formatting helpers ----------

func formatMetricValue(name string, v float64) string {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "memory") || strings.Contains(lower, "working_set") {
		return formatBytes(v)
	}
	if strings.Contains(lower, "throttle") {
		return fmt.Sprintf("%.1f%%", v*100)
	}
	if strings.Contains(lower, "restart") {
		return fmt.Sprintf("%.0f", v)
	}
	// Default: reasonable precision
	if v >= 1.0 {
		return fmt.Sprintf("%.2f", v)
	}
	return fmt.Sprintf("%.4g", v)
}

func formatBytes(v float64) string {
	const unit = 1024.0
	if v < unit {
		return fmt.Sprintf("%.0fB", v)
	}
	v /= unit
	if v < unit {
		return fmt.Sprintf("%.1fKi", v)
	}
	v /= unit
	if v < unit {
		return fmt.Sprintf("%.1fMi", v)
	}
	v /= unit
	return fmt.Sprintf("%.1fGi", v)
}
