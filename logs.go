package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultLogLimit = 50
	logHTTPTimeout  = 10 * time.Second

	backendUnconfigured = "unconfigured"
	backendNoResults    = "no-results"
	backendNoQuery      = "no-query"
	backendError        = "error"
)

var errNoLogsBackend = errors.New("no log backend configured")

type logQuery struct {
	query string
	start string
	end   string
}

type logQueryRange struct {
	start time.Time
	end   time.Time
}

type logsBackend struct {
	base   *url.URL
	flavor string
	limit  int
	client *http.Client
}

func newLogsBackend() (*logsBackend, error) {
	rawURL := strings.TrimSpace(os.Getenv("LOGS_URL"))
	if rawURL == "" {
		return nil, errNoLogsBackend
	}
	base, err := url.Parse(rawURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("invalid LOGS_URL")
	}

	flavor := strings.ToLower(strings.TrimSpace(os.Getenv("LOGS_FLAVOR")))
	if flavor != "victorialogs" && flavor != "loki" {
		return nil, fmt.Errorf("LOGS_FLAVOR must be victorialogs or loki")
	}

	limit := defaultLogLimit
	if rawLimit := strings.TrimSpace(os.Getenv("LOGS_LIMIT")); rawLimit != "" {
		limit, err = strconv.Atoi(rawLimit)
		if err != nil || limit <= 0 {
			return nil, fmt.Errorf("LOGS_LIMIT must be a positive integer")
		}
	}

	return &logsBackend{
		base:   base,
		flavor: flavor,
		limit:  limit,
		client: &http.Client{Timeout: logHTTPTimeout},
	}, nil
}

func (b *logsBackend) query(q logQuery) ([]string, error) {
	if b == nil || b.base == nil {
		return nil, fmt.Errorf("log backend is not initialized")
	}
	if b.client == nil {
		b.client = &http.Client{Timeout: logHTTPTimeout}
	}

	endpoint := "/select/logsql/query"
	if b.flavor == "loki" {
		endpoint = "/loki/api/v1/query_range"
	}
	u := *b.base
	u.Path = strings.TrimRight(u.Path, "/") + endpoint
	params := u.Query()
	params.Set("query", q.query)
	params.Set("start", q.start)
	params.Set("end", q.end)
	if b.flavor == "loki" {
		params.Set("limit", strconv.Itoa(b.limit))
	}
	u.RawQuery = params.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), logHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create log backend request: %w", err)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query log backend: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("log backend returned HTTP %d", resp.StatusCode)
	}

	if b.flavor == "loki" {
		return parseLokiLogs(resp.Body)
	}
	return parseVictoriaLogs(resp.Body)
}

func parseVictoriaLogs(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	var lines []string
	for scanner.Scan() {
		if strings.TrimSpace(string(scanner.Bytes())) == "" {
			continue
		}
		var record struct {
			Msg    string `json:"_msg"`
			Stream string `json:"_stream"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, fmt.Errorf("decode VictoriaLogs response: %w", err)
		}
		line := record.Msg
		if record.Stream != "" {
			line = "[" + record.Stream + "] " + line
		}
		line = stripSecrets(line)
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read VictoriaLogs response: %w", err)
	}
	return lines, nil
}

func parseLokiLogs(r io.Reader) ([]string, error) {
	var response struct {
		Data struct {
			Result []struct {
				Values [][]string `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(r, 32*1024*1024)).Decode(&response); err != nil {
		return nil, fmt.Errorf("decode Loki response: %w", err)
	}
	var lines []string
	for _, result := range response.Data.Result {
		for _, value := range result.Values {
			if len(value) < 2 {
				continue
			}
			line := stripSecrets(value[1])
			if line == "" {
				continue
			}
			lines = append(lines, line)
		}
	}
	return lines, nil
}

func fetchBackendLogs(g Group, window time.Duration) (string, []string, string) {
	b, err := newLogsBackend()
	return fetchBackendLogsWithBackend(g, window, b, err)
}

func fetchBackendLogsWithBackend(g Group, window time.Duration, b *logsBackend, err error) (string, []string, string) {
	if err != nil {
		if errors.Is(err, errNoLogsBackend) {
			return backendUnconfigured, nil, ""
		}
		return backendError, nil, stripSecrets(err.Error())
	}
	if b == nil {
		return backendUnconfigured, nil, ""
	}

	queries := backendLogQueries(g, window, b.flavor)
	if len(queries) == 0 {
		return backendNoQuery, nil, ""
	}

	var all []string
	for _, q := range queries {
		lines, queryErr := b.query(q)
		if queryErr != nil {
			// Keep evidence already gathered from successful requests. The error
			// is reported separately so the model can distinguish partial data
			// from a backend that simply returned no records.
			return backendError, collapseBackendLines(all, b.limit), stripSecrets(queryErr.Error())
		}
		all = append(all, lines...)
	}
	if len(all) == 0 {
		return backendNoResults, nil, ""
	}
	return "ok", collapseBackendLines(all, b.limit), ""
}

func backendLogQueries(g Group, window time.Duration, flavor string) []logQuery {
	type key struct {
		namespace string
		pod       string
	}
	seenAlert := false
	seenQuery := make(map[key]logQueryRange)
	queryOrder := make([]key, 0)
	addQuery := func(namespace, pod string, a Alert) {
		namespace = strings.TrimSpace(stripSecrets(namespace))
		pod = strings.TrimSpace(stripSecrets(pod))
		if namespace == "" {
			return
		}
		k := key{namespace: namespace, pod: pod}
		rng, exists := seenQuery[k]
		start, end := alertWindow(a, window)
		if !exists {
			seenQuery[k] = logQueryRange{start: start, end: end}
			queryOrder = append(queryOrder, k)
			return
		}
		if start.Before(rng.start) || rng.start.IsZero() {
			rng.start = start
		}
		if end.After(rng.end) || rng.end.IsZero() {
			rng.end = end
		}
		seenQuery[k] = rng
	}

	for _, alert := range g.Alerts {
		seenAlert = true
		namespace := strings.TrimSpace(alert.Labels["namespace"])
		pod := strings.TrimSpace(alert.Labels["pod"])
		if namespace == "" {
			for _, fallback := range g.Namespaces {
				addQuery(fallback, pod, alert)
			}
			continue
		}
		addQuery(namespace, pod, alert)
	}
	if !seenAlert {
		for _, namespace := range g.Namespaces {
			alert := Alert{}
			addQuery(namespace, "", alert)
		}
	}

	queries := make([]logQuery, 0, len(queryOrder))
	for _, k := range queryOrder {
		rng := seenQuery[k]
		queries = append(queries, logQuery{
			query: logQueryString(flavor, k.namespace, k.pod),
			start: formatLogTime(rng.start, flavor),
			end:   formatLogTime(rng.end, flavor),
		})
	}
	return queries
}

func logQueryString(flavor, namespace, pod string) string {
	namespace = strings.TrimSpace(stripSecrets(namespace))
	pod = strings.TrimSpace(stripSecrets(pod))
	if flavor == "loki" {
		labels := []string{"namespace=" + strconv.Quote(namespace)}
		if pod != "" {
			labels = append(labels, "pod="+strconv.Quote(pod))
		}
		return "{" + strings.Join(labels, ",") + "}"
	}
	query := "namespace:" + strconv.Quote(namespace)
	if pod != "" {
		query += " AND pod:" + strconv.Quote(pod)
	}
	return query
}

func formatLogTime(t time.Time, flavor string) string {
	if flavor == "loki" {
		return strconv.FormatInt(t.UnixNano(), 10)
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func alertWindow(a Alert, fallback time.Duration) (time.Time, time.Time) {
	start, end := a.StartsAt, a.EndsAt
	if start.IsZero() && end.IsZero() {
		end = time.Now()
		start = end.Add(-fallback)
	}
	if start.IsZero() {
		start = end
	}
	if end.IsZero() {
		if fallback > 0 {
			end = start.Add(fallback)
		} else {
			end = start
		}
	}
	if end.Before(start) {
		start, end = end, start
	}
	return start, end
}

func collapseBackendLines(lines []string, limit int) []string {
	if limit <= 0 {
		limit = defaultLogLimit
	}
	counts := make(map[string]int)
	order := make([]string, 0)
	for _, raw := range lines {
		line := strings.TrimSpace(stripSecrets(raw))
		if line == "" {
			continue
		}
		if _, exists := counts[line]; !exists {
			order = append(order, line)
		}
		counts[line]++
	}
	if len(order) == 0 {
		return nil
	}

	out := make([]string, 0, min(len(order), limit)+1)
	for i, line := range order {
		if i >= limit {
			break
		}
		count := counts[line]
		if count > 1 {
			out = append(out, line+" (repeated "+strconv.Itoa(count)+" times)")
		} else {
			out = append(out, line)
		}
	}
	dropped := 0
	for _, line := range order[min(len(order), limit):] {
		dropped += counts[line]
	}
	if dropped > 0 {
		out = append(out, fmt.Sprintf("[%d additional log line(s) omitted after cap; repeated lines were collapsed]", dropped))
	}
	return out
}

// Keep the local minimum helper here so this file also builds on Go versions
// where the stdlib has not yet exposed min for integer types.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
