package main

import (
	"bufio"
	"context"
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
//
// The HTTP client is supplied by the caller and must carry a Timeout: a stalled
// backend that accepts the TCP connection but never responds must not be
// allowed to block the flush loop or the shutdown drain. All request methods
// take a context so cancellation propagates from the flush loop, from the
// SIGTERM drain, and from the client's own timeout.
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
	logs := &logsBackend{
		url:    base,
		base:   base,
		flavor: flavor,
		limit:  limit,
	}
	// The constructor owns the HTTP client: a 15s timeout so a stalled backend
	// can never block the flush loop or the shutdown drain.
	logs.hc = &http.Client{Timeout: 15 * time.Second}
	if _, err := logs.endpoint(); err != nil {
		logf("enrich: invalid LOGS_URL: %v", err)
		return nil
	}
	return logs
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
// recording backend errors in the service log. It returns only the primary
// (subject-scoped) lines; Enrich uses the result variant below so it can also
// receive the ambient namespace-wide context and keep the two apart.
func (b *logsBackend) fetchBackendLogs(ctx context.Context, g Group, window time.Duration) []string {
	res, err := b.fetchBackendLogsResult(ctx, g, window, targetPodsFromAlerts(g.Alerts))
	if err != nil {
		logf("enrich: backend logs: %v", err)
		return res.Primary
	}
	return res.Primary
}

type backendLog struct {
	stream  string
	message string
	count   int
}

// backendLogResult separates primary evidence (lines scoped to a resolved
// concrete subject) from ambient context (namespace-wide lines gathered because
// no subject could be resolved). Enrich keeps the two apart so a coincidence is
// never read as a cause: Primary goes to BackendLogs, Ambient to
// Enrichment.Ambient (rendered under BACKGROUND), and neither is presented as
// the failing resource's own logs when it is not.
type backendLogResult struct {
	Primary []string
	Ambient []string
}

// ambientLogMarker prefixes namespace-wide backend-log lines returned when no
// concrete subject could be resolved. It is what makes them explicitly
// ambient/background: Enrich routes them to Enrichment.Ambient so they render
// under BACKGROUND, never into the primary BackendLogs.
const ambientLogMarker = "(ambient, namespace-wide) "

// targetPodsFromAlerts builds the concrete-subject set from raw alert pod
// labels, the same way Enrich does, so the convenience wrapper stays usable on
// its own. Enrich passes its own set, which also includes Job-resolved pods
// once subject resolution lands.
func targetPodsFromAlerts(alerts []Alert) map[string]bool {
	out := make(map[string]bool)
	for _, a := range alerts {
		if a.Labels["pod"] != "" && a.namespace() != "" {
			out[a.namespace()+"/"+a.Labels["pod"]] = true
		}
	}
	return out
}

// targetPodsByNamespace groups a set of "namespace/pod" subject keys by their
// namespace so each resolved pod can be queried once per namespace. Pod and
// namespace names are DNS-1123 (no "/"), so the first slash unambiguously
// separates the two; invalid keys are dropped rather than queried.
func targetPodsByNamespace(targetPods map[string]bool) map[string][]string {
	out := make(map[string][]string)
	for key := range targetPods {
		i := strings.IndexByte(key, '/')
		if i <= 0 || i == len(key)-1 {
			continue
		}
		ns := strings.TrimSpace(key[:i])
		pod := strings.TrimSpace(key[i+1:])
		if ns == "" || pod == "" {
			continue
		}
		out[ns] = append(out[ns], pod)
	}
	for ns := range out {
		sort.Strings(out[ns])
	}
	return out
}

func (b *logsBackend) fetchBackendLogsResult(ctx context.Context, g Group, window time.Duration, targetPods map[string]bool) (backendLogResult, error) {
	if b == nil {
		return backendLogResult{}, nil
	}
	if len(g.Namespaces) == 0 {
		return backendLogResult{}, nil
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

	// Concrete subjects resolved by enrichment, grouped by namespace. When
	// non-empty we query only those pods: a namespace-only query would return a
	// slice of whatever else runs in the namespace (Flux reconciles, other
	// controllers) and drown the primary evidence in plausible but causally
	// irrelevant text. It is issued only when no subject could be resolved.
	byNS := targetPodsByNamespace(targetPods)

	for _, namespace := range g.Namespaces {
		namespace = strings.TrimSpace(namespace)
		if namespace == "" {
			continue
		}
		var pods []string
		if len(byNS) > 0 {
			pods = byNS[namespace]
		} else {
			pods = []string{""}
		}
		for _, pod := range pods {
			queryKey := namespace + "\x00" + pod
			if _, ok := seenQueries[queryKey]; ok {
				continue
			}
			seenQueries[queryKey] = struct{}{}
			records, err := b.query(ctx, namespace, pod, start, now)
			if err != nil {
				return backendLogResult{}, err
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

	collapsed := collapseAndCap(seen, order, b.limit)
	if len(byNS) == 0 {
		// No concrete subject: everything returned is namespace-wide, so mark it
		// ambient and keep it out of the primary evidence.
		marked := make([]string, len(collapsed))
		for i, line := range collapsed {
			marked[i] = ambientLogMarker + line
		}
		return backendLogResult{Ambient: marked}, nil
	}
	return backendLogResult{Primary: collapsed}, nil
}

func (b *logsBackend) query(ctx context.Context, namespace, pod string, start, end time.Time) ([]backendLog, error) {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	client := b.hc
	if client == nil {
		// Defensive default: never reach the network through http.DefaultClient,
		// which has no timeout. newLogsBackend always sets hc; this fallback
		// only fires for backends built directly in unit tests.
		client = &http.Client{Timeout: 15 * time.Second}
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
