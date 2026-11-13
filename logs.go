package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	// SkippedRefused records that at least one namespace the group names was
	// refused as not one path segment and was never queried. The caller must
	// not render an empty result as "the backend has no lines for the
	// namespace": a refused scope is uninspected, not empty (issue #311
	// review, #331).
	SkippedRefused bool
	// NoRecords records that at least one queried scope's reply carried no
	// log record at all: the backend answered with something that was not a
	// set of log lines. Nothing is known about the window in that case, so
	// no "there were no lines" claim is supported for the read.
	NoRecords bool
	// SkippedUnresolved lists the valid namespaces (one path segment) that
	// received no query at all: the group resolved a subject pod in another
	// namespace, and a resolved-subject group queries only those pods, so a
	// namespace without one is silently uninspected. An uninspected scope
	// must not render as "returned no lines" any more than a refused one may
	// (#311 review, #331), so it is surfaced here instead — but the cause is
	// different (no subject, not a refused name), so it keeps its own marker
	// (issue #339). The names are alert-supplied: callers that render them
	// must apply the same redaction and untrusted treatment they apply to
	// every other namespace render.
	SkippedUnresolved []string
}

// ambientLogMarker prefixes namespace-wide backend-log lines returned when no
// concrete subject could be resolved. It is what makes them explicitly
// ambient/background: Enrich routes them to Enrichment.Ambient so they render
// under BACKGROUND, never into the primary BackendLogs.
const ambientLogMarker = "(ambient, namespace-wide) "

// targetPodsFromAlerts builds the concrete-subject set from raw alert pod
// labels, the same shape Enrich passes for its resolved subjects.
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
	skippedRefused := false
	// Set, not slice: a hand-built Group can repeat a namespace, and the
	// gap must be named once. Sorted at return for a stable render.
	skippedUnresolved := map[string]bool{}
	// A reply that carried no log record is a fact about the reply, not a
	// failed read: the group read continues and the fact travels with the
	// result so the renderer can state the gap instead of a negative.
	noRecords := false

	for _, namespace := range g.Namespaces {
		// The namespace is alert-supplied text. The query quotes it, so the
		// blast radius here is a lookup under a wrong key rather than an
		// apiserver path traversal, but #311's rule covers this read too: a
		// namespace that is not one path segment sends no request for its
		// scope, including the namespace-wide fallback (#331). The check is
		// the same one that gates the apiserver reads (Enrich's refusedNS),
		// so no surface can call a refused scope empty while another calls
		// it uninspected. A value that passes is a DNS-1123 label: the old
		// TrimSpace was a no-op for everything still queried.
		if !fluxPathSegment(namespace) {
			skippedRefused = true
			continue
		}
		var pods []string
		if len(byNS) > 0 {
			// With a resolved subject anywhere in the group only resolved
			// pods are queried, so a valid namespace with none of them sends
			// no request, not even the namespace-wide fallback. Name the gap
			// instead of leaving it to render as an empty scope (#339).
			pods = byNS[namespace]
			if len(pods) == 0 {
				skippedUnresolved[namespace] = true
				continue
			}
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
				if errors.Is(err, errNoLogRecords) {
					// The reply parsed and carried no log record, so the
					// scope is unknown rather than empty. The read does not
					// fail and the next scope is still queried.
					noRecords = true
					continue
				}
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

	if noRecords {
		// One line per read, not per scope: the condition is about the
		// reply, and neither the reply body nor the alert-supplied scope
		// names belong in the log.
		logf("enrich: backend logs: a backend reply carried no log record, so the scope is unknown rather than empty")
	}

	collapsed := collapseAndCap(order, b.limit)
	if len(byNS) == 0 {
		// No concrete subject: everything returned is namespace-wide, so mark it
		// ambient and keep it out of the primary evidence. The fallback ran for
		// every valid namespace here, so skippedUnresolved is necessarily empty.
		marked := make([]string, len(collapsed))
		for i, line := range collapsed {
			marked[i] = ambientLogMarker + line
		}
		return backendLogResult{Ambient: marked, SkippedRefused: skippedRefused, NoRecords: noRecords}, nil
	}
	var unresolved []string
	for ns := range skippedUnresolved {
		unresolved = append(unresolved, ns)
	}
	sort.Strings(unresolved)
	return backendLogResult{Primary: collapsed, SkippedRefused: skippedRefused, SkippedUnresolved: unresolved, NoRecords: noRecords}, nil
}

// quoteLogValue renders a label value as a double-quoted literal with `"` and
// `\` escaped, using strconv.Quote so a value containing either cannot break
// out of the literal and inject query syntax. Both backends use double-quoted
// string literals in their query languages, so one helper serves both.
func quoteLogValue(v string) string {
	return strconv.Quote(v)
}

// buildQuery spells the (namespace, pod) filter in the backend's query
// language. LogsQL and LogQL do not share one: VictoriaLogs takes
// `field:"value"` filters joined by AND, Loki takes a `{label="value"}`
// stream selector, so the query is built per flavor.
func (b *logsBackend) buildQuery(namespace, pod string) string {
	switch b.flavor {
	case "loki":
		if pod != "" {
			return "{namespace=" + quoteLogValue(namespace) + ",pod=" + quoteLogValue(pod) + "}"
		}
		return "{namespace=" + quoteLogValue(namespace) + "}"
	case "victorialogs":
		query := "namespace:" + quoteLogValue(namespace)
		if pod != "" {
			query += " AND pod:" + quoteLogValue(pod)
		}
		return query
	default:
		// Unreachable: endpoint() rejects unknown flavors before query()
		// builds a request, so the flavor whitelist stays in one mental
		// place without dead code.
		query := "namespace:" + quoteLogValue(namespace)
		if pod != "" {
			query += " AND pod:" + quoteLogValue(pod)
		}
		return query
	}
}

// query reads the backend for one scope. The error it returns is either a
// failed read or the errNoLogRecords condition: the reply parsed and carried
// no log record, so the scope is unknown rather than empty. An empty
// VictoriaLogs reply is not an error here — it is the backend's own "no
// lines" answer.
func (b *logsBackend) query(ctx context.Context, namespace, pod string, start, end time.Time) ([]backendLog, error) {
	endpoint, err := b.endpoint()
	if err != nil {
		return nil, err
	}
	query := b.buildQuery(namespace, pod)
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
	records, err := parseVictoriaLogs(body)
	if errors.Is(err, errEmptyVictoriaLogsReply) {
		// VictoriaLogs answers a query that matched nothing with an empty
		// 200 body. The parser refuses an empty body (issue #342, criterion
		// 2) because only the caller can tell an empty reply from a lost
		// one, but this read did not fail: the backend answered, with no
		// lines. Rendering it as a failed query would claim a failure that
		// did not happen.
		return nil, nil
	}
	return records, err
}

// errEmptyVictoriaLogsReply reports a VictoriaLogs reply that carried no
// NDJSON line at all. The parser refuses it rather than reporting an empty
// scope, because "the body was empty" and "the body held no log records" are
// different facts and only the caller knows which one the backend meant:
// VictoriaLogs answers a query that matched nothing with an empty 200 body.
// b.query maps this error back to "no lines"; a reply that held no log
// record is named separately (errNoLogRecords), and every other unreadable
// reply stays a failed query (issue #342, criterion 2).
var errEmptyVictoriaLogsReply = errors.New("victorialogs response was empty")

// errNoLogRecords reports a reply that parsed but carried no log record at
// all — a 200 body holding {"error":"unauthorized"}, for instance. The reply
// is not a set of log lines, so the read cannot say the scope had no lines;
// it established only that it could not find any, and not why. It is not a
// failed read either: the backend answered. Only the VictoriaLogs parser
// raises it — a Loki reply with an empty result set is Loki's own "no lines"
// answer and stays an empty scope.
var errNoLogRecords = errors.New("victorialogs reply carried no log record")

// logMessage is the _msg field of a log record. It remembers whether the
// field was there at all, because "the record carried a blank message" and
// "the line carried no message field" are different facts: the first is a
// log record with nothing to show, the second is not a log record at all
// (#349). A plain string field cannot tell them apart — an absent field and
// a null field both decode to the empty string — so the presence is
// recorded here.
type logMessage struct {
	present bool
	text    string
}

// UnmarshalJSON records that the field was present and reads the text. A
// null message is a record with no text, not a missing record. A non-string
// message is not a message: the line stays unreadable, as it was before this
// type existed, rather than becoming a record with no text.
func (m *logMessage) UnmarshalJSON(data []byte) error {
	m.present = true
	if string(data) == "null" {
		return nil
	}
	return json.Unmarshal(data, &m.text)
}

func parseVictoriaLogs(body []byte) ([]backendLog, error) {
	var out []backendLog
	// The line reader is readHistoryLines' (issue #162), reused for the
	// oversized-record case (issue #347): a record over oversizedLineCap is
	// skipped with only a tail sample retained, and the read continues on the
	// following line. A bufio.Scanner cannot hold this stance — it returns
	// bufio.ErrTooLong at its 1 MiB token cap, and the whole read failed
	// there, which issue #342 criterion 2 reserves for an empty or wholly
	// unparseable body.
	r := bufio.NewReaderSize(bytes.NewReader(body), 64*1024)
	lineNo := 0
	lines := 0
	parsed := 0
	records := 0
	unreadable := 0
	var firstSkipLine int
	var firstSkipErr error
	for {
		// readHistoryLine returns the whole record when it fits the cap and
		// only a tail sample when it does not, along with the bytes consumed
		// from the stream. io.EOF means the line ended the body, with or
		// without a trailing newline; an in-memory reader fails no other way,
		// so the loop breaks after processing the reported line.
		line, _, consumed, err := readHistoryLine(r, 0)
		if len(line) > 0 {
			lineNo++
		}
		if int64(consumed) > oversizedLineCap {
			// The line is there; this reader just refuses to buffer a record
			// that large, so it counts as a line seen and not read, and it
			// never reaches json.Unmarshal. It is not blank, so it keeps the
			// body out of the empty-reply case below.
			lines++
			unreadable++
			if firstSkipErr == nil {
				firstSkipLine, firstSkipErr = lineNo, fmt.Errorf(
					"oversized record, %d bytes over the %d cap",
					consumed-oversizedLineCap, oversizedLineCap)
			}
		} else if text := strings.TrimSpace(string(line)); text != "" {
			lines++
			var record struct {
				Message logMessage `json:"_msg"`
			}
			// One malformed record — a broken plugin output, a proxy-injected
			// line, a truncated write — must not discard the valid lines around
			// it. This is the same skip-and-log stance readHistoryLines takes for
			// the history JSONL: a transient parse failure must not become data
			// loss for the whole response. The skips are logged once, aggregated,
			// because the body is untrusted input and a hostile or garbage reply
			// must not be able to flood the log line by line.
			if err := json.Unmarshal([]byte(text), &record); err != nil {
				unreadable++
				if firstSkipErr == nil {
					firstSkipLine, firstSkipErr = lineNo, err
				}
			} else {
				parsed++
				// A line that carried an _msg field is a log record, even
				// when the message is blank or null: a blank message is
				// noise to drop, not a missing record. A parsed line
				// without the field (an error object, say) is not a record
				// at all, which is what the no-record condition below
				// names.
				if record.Message.present {
					records++
					if strings.TrimSpace(record.Message.text) != "" {
						out = append(out, backendLog{message: record.Message.text})
					}
				}
			}
		}
		if err != nil {
			break
		}
	}
	if unreadable > 0 {
		logf("enrich: skipped %d unreadable VictoriaLogs line(s) (first at line %d: %v)", unreadable, firstSkipLine, firstSkipErr)
	}
	// The guard's boundary (issue #342, criterion 2). A reply whose every line
	// failed to parse is not an empty answer: the reply was not the NDJSON we
	// asked for, and rendering it as "no logs in the window" would be an
	// explicit negative no read can support. A reply with no line in it is
	// refused for the same reason, but b.query maps that one back to an empty
	// scope, because VictoriaLogs answers a query that matched nothing with
	// an empty 200 body. A body that holds at least one line which parsed is
	// not wholly unparseable, so it degrades to the records it yielded; when
	// none of them carried an _msg field, the reply carried no log record at
	// all and the empty scope is not stated either (#349). An oversized line is
	// a line seen and not read: it neither fails the read (issue #347) nor lets
	// a body holding only oversized records slip into the empty-reply case.
	if lines == 0 {
		return nil, errEmptyVictoriaLogsReply
	}
	if parsed == 0 {
		return nil, fmt.Errorf("victorialogs response had no parseable lines (%d unreadable lines)", unreadable)
	}
	// A reply whose lines parsed but carried no log record (e.g. an error
	// object with no _msg) is not a set of log lines: it says nothing about
	// the window, so the read cannot state that the scope had no lines. It is
	// not a failed read either — the backend answered — so it is named, and
	// the caller decides what to say about the scope (#349). A record whose
	// message was blank is still a record, so a reply holding only those
	// keeps the empty scope it earned.
	if records == 0 {
		return nil, errNoLogRecords
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
	keys := sortedKeys(s)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+s[key])
	}
	return out
}

func collapseAndCap(order []*backendLog, cap int) []string {
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
