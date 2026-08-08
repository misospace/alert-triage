package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// LogBackend queries a log backend (VictoriaLogs or Loki) for context.
type LogBackend struct {
	URL    string
	Flavor string // "victorialogs" or "loki"
	Limit  int
	hc     *http.Client
}

func newLogBackend(urlStr, flavor string, limit int) *LogBackend {
	if urlStr == "" {
		return nil
	}
	urlStr = strings.TrimRight(urlStr, "/")
	return &LogBackend{
		URL:    urlStr,
		Flavor: flavor,
		Limit:  limit,
		hc: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Query fetches log lines matching the given namespaces and optional pod filter,
// within the specified time range. Returns raw log lines (caller should apply
// stripSecrets and collapseLogLines).
func (lb *LogBackend) Query(namespaces []string, pods []string, start, end time.Time) ([]string, error) {
	if lb == nil || lb.URL == "" {
		return nil, nil
	}

	query := buildLogQuery(namespaces, pods)

	switch lb.Flavor {
	case "victorialogs":
		return lb.queryVictoriaLogs(query, start, end)
	case "loki":
		return lb.queryLoki(query, start, end)
	default:
		return nil, fmt.Errorf("unknown log flavor: %s", lb.Flavor)
	}
}

// buildLogQuery constructs a stream selector for VictoriaLogs LogSQL or Loki LogQL.
func buildLogQuery(namespaces []string, pods []string) string {
	var parts []string

	if len(namespaces) > 0 {
		escaped := make([]string, len(namespaces))
		for i, ns := range namespaces {
			escaped[i] = regexp.QuoteMeta(ns)
		}
		parts = append(parts, fmt.Sprintf("namespace=~%q", strings.Join(escaped, "|")))
	}

	if len(pods) > 0 {
		escaped := make([]string, len(pods))
		for i, p := range pods {
			escaped[i] = regexp.QuoteMeta(p)
		}
		parts = append(parts, fmt.Sprintf("pod=~%q", strings.Join(escaped, "|")))
	}

	return "{" + strings.Join(parts, ", ") + "}"
}

// queryVictoriaLogs queries VictoriaLogs via its LogSQL endpoint.
// Response is JSONL with _msg, _time, _stream fields.
func (lb *LogBackend) queryVictoriaLogs(query string, start, end time.Time) ([]string, error) {
	u := lb.URL + "/select/logsql/query"
	params := url.Values{}
	params.Set("query", query)
	params.Set("start", fmt.Sprintf("%d", start.Unix()))
	params.Set("end", fmt.Sprintf("%d", end.Unix()))
	if lb.Limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", lb.Limit))
	}
	u += "?" + params.Encode()

	resp, err := lb.hc.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("victorialogs: %s", resp.Status)
	}

	var lines []string
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20)) // 1MB cap
	for scanner.Scan() {
		var entry struct {
			Msg string `json:"_msg"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.Msg != "" {
			lines = append(lines, entry.Msg)
		}
	}

	return lines, scanner.Err()
}

// queryLoki queries Loki via its query_range endpoint.
// Response is JSON with data.result[].values[][1] containing log lines.
func (lb *LogBackend) queryLoki(query string, start, end time.Time) ([]string, error) {
	u := lb.URL + "/loki/api/v1/query_range"
	params := url.Values{}
	params.Set("query", query)
	params.Set("start", fmt.Sprintf("%d", start.UnixNano()))
	params.Set("end", fmt.Sprintf("%d", end.UnixNano()))
	if lb.Limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", lb.Limit))
	}
	u += "?" + params.Encode()

	resp, err := lb.hc.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("loki: %s", resp.Status)
	}

	var body struct {
		Data struct {
			Result []struct {
				Values [][]string `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, err
	}

	var lines []string
	for _, r := range body.Data.Result {
		for _, v := range r.Values {
			if len(v) >= 2 {
				lines = append(lines, v[1])
			}
		}
	}

	return lines, nil
}
