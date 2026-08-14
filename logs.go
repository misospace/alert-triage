package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultLogLimit = 50

// logsBackend is an optional, stdlib-only client for a VictoriaLogs or Loki
// HTTP endpoint. The URL is the base URL; the backend-specific query path is
// appended by endpoint.
type logsBackend struct {
	url    string
	base   string
	flavor string
	limit  int
	hc     *http.Client
	now    func() time.Time
}

func newLogsBackend() *logsBackend {
	rawURL := strings.TrimSpace(os.Getenv("LOGS_URL"))
	if rawURL == "" {
		return nil
	}

	flavor := strings.ToLower(strings.TrimSpace(os.Getenv("LOGS_FLAVOR")))
	if flavor != "victorialogs" && flavor != "loki" {
		logf("enrich: unsupported LOGS_FLAVOR %q", flavor)
		return nil
	}

	limit := defaultLogLimit
	if rawLimit := strings.TrimSpace(os.Getenv("LOGS_LIMIT")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			logf("enrich: invalid LOGS_LIMIT %q", rawLimit)
			return nil
		}
		limit = parsed
	}

	base := strings.TrimRight(rawURL, "/")
	backend := &logsBackend{
		url:    base,
		base:   base,
		flavor: flavor,
		limit:  limit,
	}
	if _, err := backend.endpoint(); err != nil {
		logf("enrich: invalid LOGS_URL: %v", err)
		return nil
	}
	return backend
}

func (b *logsBackend) endpoint() (string, error) {
	if b == nil {
		return "", fmt.Errorf("log backend is nil")
	}
	base := strings.TrimRight(b.url, "/")
	if base == "" {
		return "", fmt.Errorf("empty URL")
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid URL %q", b.url)
	}
	switch b.flavor {
	case "victorialogs":
		return base + "/select/logsql/query", nil
	case "loki":
		return base + "/loki/api/v1/query_range", nil
	default:
		return "", fmt.Errorf("unsupported flavor %q", b.flavor)
	}
}

// fetchBackendLogs keeps the original, convenient method for callers while
// recording backend errors in the service log. Enrich uses the result variant
// below so a configured-but-empty backend is distinguishable from an outage.
func (b *logsBackend) fetchBackendLogs(g Group, window time.Duration) []string {
	lines, err := b.fetchBackendLogsResult(g, window)
	if err != nil {
		logf("enrich: backend logs: %v", err)
		return lines
	}
	return lines
}

type backendLog struct {
	stream  string
	message string
	count   int
}

func (b *logsBackend) fetchBackendLogsResult(g Group, window time.Duration) ([]string, error) {
	if b == nil {
		return nil, nil
	}
	if len(g.Namespaces) == 0 {
		return nil, nil
	}
	if window <= 0 {
		window = 5 * time.Minute
	}

	now := time.Now().UTC()
	if b.now != nil {
		now = b.now().UTC()
	}
	start := now.Add(-window)
	seen := make(map[string]*backendLog)
	var order []*backendLog
	seenQueries := make(map[string]struct{})

	// Deduplicate pod-specific requests while retaining a namespace-only
	// request for groups which contain alerts without a pod label.
	for _, namespace := range g.Namespaces {
		namespace = strings.TrimSpace(namespace)
		if namespace == "" {
			continue
		}
		queries := map[string]string{"": ""}
		for _, alert := range g.Alerts {
			pod := strings.TrimSpace(alert.Labels["pod"])
			if pod != "" {
				queries[pod] = pod
			}
		}
		pods := make([]string, 0, len(queries))
		for pod := range queries {
			pods = append(pods, pod)
		}
		sort.Strings(pods)
		for _, pod := range pods {
			queryKey := namespace + "\x00" + pod
			if _, ok := seenQueries[queryKey]; ok {
				continue
			}
			seenQueries[queryKey] = struct{}{}
			records, err := b.query(namespace, pod, start, now)
			if err != nil {
				return nil, err
			}
			for _, record := range records {
				message := strings.Join(strings.Fields(stripSecrets(record.message)), " ")
				if message == "" {
					continue
				}
				stream := strings.Join(strings.Fields(stripSecrets(record.stream)), " ")
				key := stream + "\x00" + message
				entry := seen[key]
				if entry == nil {
					entry = &backendLog{stream: stream, message: message, count: 1}
					seen[key] = entry
					order = append(order, entry)
				} else {
					entry.count++
				}
			}
		}
	}

	return collapseAndCap(seen, order, b.limit), nil
}

func (b *logsBackend) query(namespace, pod string, start, end time.Time) ([]backendLog, error) {
	endpoint, err := b.endpoint()
	if err != nil {
		return nil, err
	}
	query := fmt.Sprintf("namespace:%q", namespace)
	if pod != "" {
		query += " AND pod:" + fmt.Sprintf("%q", pod)
	}
	params := url.Values{}
	params.Set("query", query)
	params.Set("start", strconv.FormatInt(start.UTC().UnixNano(), 10))
	params.Set("end", strconv.FormatInt(end.UTC().UnixNano(), 10))
	if b.limit > 0 {
		params.Set("limit", strconv.Itoa(b.limit))
	}
	req, err := http.NewRequest(http.MethodGet, endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	client := b.hc
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%s returned HTTP %d", b.flavor, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if b.flavor == "loki" {
		return parseLoki(body)
	}
	return parseVictoriaLogs(body)
}

func parseVictoriaLogs(body []byte) ([]backendLog, error) {
	var out []backendLog
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record struct {
			Message string `json:"_msg"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, err
		}
		if strings.TrimSpace(record.Message) != "" {
			out = append(out, backendLog{message: record.Message})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseLoki(body []byte) ([]backendLog, error) {
	var response struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Stream map[string]string `json:"stream"`
				Values [][]string        `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	if response.Status != "" && response.Status != "success" {
		return nil, fmt.Errorf("loki returned status %q", response.Status)
	}
	var out []backendLog
	for _, result := range response.Data.Result {
		stream := streamLabels(result.Stream)
		for _, value := range result.Values {
			if len(value) < 2 || strings.TrimSpace(value[1]) == "" {
				continue
			}
			out = append(out, backendLog{stream: strings.Join(stream, " "), message: value[1]})
		}
	}
	return out, nil
}

func streamLabels(s map[string]string) []string {
	if len(s) == 0 {
		return nil
	}
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+s[key])
	}
	return out
}

func collapseAndCap(seen map[string]*backendLog, order []*backendLog, cap int) []string {
	if cap <= 0 {
		cap = defaultLogLimit
	}
	out := make([]string, 0, len(order))
	for i, entry := range order {
		if len(out) >= cap {
			out = append(out, fmt.Sprintf("...and %d more distinct lines", len(order)-i))
			break
		}
		line := entry.message
		if entry.stream != "" {
			line = "[" + entry.stream + "] " + line
		}
		if entry.count > 1 {
			line = fmt.Sprintf("[x%d] %s", entry.count, line)
		}
		out = append(out, line)
	}
	return out
}
