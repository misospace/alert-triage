package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseVictoriaLogsSuccess(t *testing.T) {
	body := []byte("{\"_msg\":\"first line\"}\n{\"_msg\":\"second line\"}\n")
	records, err := parseVictoriaLogs(body)
	if err != nil {
		t.Fatalf("parseVictoriaLogs: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d: %#v", len(records), records)
	}
	if records[0].message != "first line" || records[1].message != "second line" {
		t.Fatalf("unexpected messages: %#v", records)
	}
	if records[0].stream != "" || records[1].stream != "" {
		t.Fatalf("victorialogs records should have no stream, got %#v", records)
	}
}

func TestParseVictoriaLogsMalformed(t *testing.T) {
	body := []byte("this is not json\nand neither is this")
	_, err := parseVictoriaLogs(body)
	if err == nil {
		t.Fatalf("expected error for wholly unparseable JSONL")
	}
	if !strings.Contains(err.Error(), "2 unreadable lines") {
		t.Fatalf("error should report the skipped-line count, got %q", err.Error())
	}
	// A wholly unparseable body is unreadable, not empty: it must not be
	// reported as the empty reply, which the caller maps to an empty scope.
	if errors.Is(err, errEmptyVictoriaLogsReply) {
		t.Fatalf("a wholly unparseable body must not be reported as an empty reply: %v", err)
	}
}

// TestParseVictoriaLogsLogsSkippedLine pins that a skipped malformed line is
// surfaced, not just tolerated (issue #342 criterion 1): the skip is logged
// once, in aggregate, with the number of lines skipped and where the first
// one was.
func TestParseVictoriaLogsLogsSkippedLine(t *testing.T) {
	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(prev) })

	body := []byte("{\"_msg\":\"first line\"}\nnot json at all\n{\"_msg\":\"second line\"}\n")
	if _, err := parseVictoriaLogs(body); err != nil {
		t.Fatalf("parseVictoriaLogs: %v", err)
	}

	out := logBuf.String()
	if !strings.Contains(out, "skipped 1 unreadable VictoriaLogs line") {
		t.Fatalf("expected the skipped line to be logged, got %q", out)
	}
	if strings.Count(out, "unreadable VictoriaLogs line") != 1 {
		t.Fatalf("expected one aggregated skip log entry, got %q", out)
	}
	if !strings.Contains(out, "first at line 2") {
		t.Fatalf("expected the log to name the first skipped line, got %q", out)
	}
}

// TestParseVictoriaLogsOversizedMiddleLine pins the #347 case: a record over
// the size cap must not end the read. The old bufio.Scanner failed the whole
// reply with bufio.ErrTooLong at such a line; now it is skipped like a
// malformed one and the records on both sides survive. The oversized record
// here is valid JSON, so this pins the size skip itself and not a parse
// failure: a record that big is never handed to json.Unmarshal.
func TestParseVictoriaLogsOversizedMiddleLine(t *testing.T) {
	body := []byte("{\"_msg\":\"first line\"}\n" +
		"{\"_msg\":\"" + strings.Repeat("y", oversizedLineCap+1) + "\"}\n" +
		"{\"_msg\":\"second line\"}\n")
	records, err := parseVictoriaLogs(body)
	if err != nil {
		t.Fatalf("oversized middle record must not fail the whole read: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected the 2 records around the oversized one, got %d: %#v", len(records), records)
	}
	if records[0].message != "first line" || records[1].message != "second line" {
		t.Fatalf("records around the oversized line must survive: %#v", records)
	}
}

// TestParseVictoriaLogsOversizedOnlyLine pins the other side of the #347
// case against criterion 2: a body holding nothing but an oversized record is
// wholly unparseable, not an empty reply. It must not be mapped back to "no
// lines in the window" — the reply carried a line, we just refuse to buffer
// a record that large.
func TestParseVictoriaLogsOversizedOnlyLine(t *testing.T) {
	body := []byte("{\"_msg\":\"" + strings.Repeat("y", oversizedLineCap+1) + "\"}")
	_, err := parseVictoriaLogs(body)
	if err == nil {
		t.Fatalf("an oversized-only body must be refused")
	}
	if errors.Is(err, errEmptyVictoriaLogsReply) {
		t.Fatalf("an oversized-only body is unreadable, not empty: %v", err)
	}
	if !strings.Contains(err.Error(), "1 unreadable lines") {
		t.Fatalf("error should report the skipped-line count, got %q", err.Error())
	}
}

// TestParseVictoriaLogsLogsOversizedLine pins that a skipped oversized
// record is surfaced in the same aggregated skip log, with the size gap as
// its reason.
func TestParseVictoriaLogsLogsOversizedLine(t *testing.T) {
	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(prev) })

	body := []byte("{\"_msg\":\"first line\"}\n" +
		"{\"_msg\":\"" + strings.Repeat("y", oversizedLineCap+1) + "\"}\n" +
		"{\"_msg\":\"second line\"}\n")
	if _, err := parseVictoriaLogs(body); err != nil {
		t.Fatalf("parseVictoriaLogs: %v", err)
	}

	out := logBuf.String()
	if !strings.Contains(out, "skipped 1 unreadable VictoriaLogs line") {
		t.Fatalf("expected the oversized line to be logged, got %q", out)
	}
	if strings.Count(out, "unreadable VictoriaLogs line") != 1 {
		t.Fatalf("expected one aggregated skip log entry, got %q", out)
	}
	if !strings.Contains(out, "first at line 2") {
		t.Fatalf("expected the log to name the first skipped line, got %q", out)
	}
	if !strings.Contains(out, "oversized record,") || !strings.Contains(out, "bytes over the") {
		t.Fatalf("expected the log to give the size gap as the reason, got %q", out)
	}
}

// TestParseVictoriaLogsMalformedMiddleLine pins the degrade-not-fail stance:
// one malformed record between two valid ones must not discard the valid
// lines around it — the malformed line is skipped and logged, and the parse
// error must not escalate into BackendState="error" for the whole read.
func TestParseVictoriaLogsMalformedMiddleLine(t *testing.T) {
	body := []byte("{\"_msg\":\"first line\"}\nnot json at all\n{\"_msg\":\"second line\"}\n")
	records, err := parseVictoriaLogs(body)
	if err != nil {
		t.Fatalf("malformed middle line must not fail the whole read: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 valid records, got %d: %#v", len(records), records)
	}
	if records[0].message != "first line" || records[1].message != "second line" {
		t.Fatalf("valid records around the malformed line must survive: %#v", records)
	}
}

// TestParseVictoriaLogsMalformedTrailingLine pins that a malformed line after
// the valid records (a truncated write mid-line) is skipped, not fatal.
func TestParseVictoriaLogsMalformedTrailingLine(t *testing.T) {
	body := []byte("{\"_msg\":\"first line\"}\n{\"_msg\":\"second line\"}\n{\"_msg\":\"trunca")
	records, err := parseVictoriaLogs(body)
	if err != nil {
		t.Fatalf("malformed trailing line must not fail the whole read: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 valid records, got %d: %#v", len(records), records)
	}
}

// TestParseVictoriaLogsEmpty pins the empty-body half of the guard's
// boundary (issue #342, criterion 2): a reply with no line in it is not the
// NDJSON the query asked for, so the parser refuses it. Only the caller can
// tell an empty reply from a lost one — VictoriaLogs answers "nothing
// matched" with an empty 200 body — so the refusal names the condition
// instead of reporting a failed read.
func TestParseVictoriaLogsEmpty(t *testing.T) {
	if _, err := parseVictoriaLogs([]byte("")); !errors.Is(err, errEmptyVictoriaLogsReply) {
		t.Fatalf("empty body must be refused by the parser, got %v", err)
	}
}

// TestParseVictoriaLogsBlankOnlyBody pins the same boundary for a body that
// holds only blank lines: there is no line in it to read, so it is refused
// like an empty body rather than reported as an empty answer.
func TestParseVictoriaLogsBlankOnlyBody(t *testing.T) {
	if _, err := parseVictoriaLogs([]byte("\n \n\n")); !errors.Is(err, errEmptyVictoriaLogsReply) {
		t.Fatalf("blank-only body must be refused by the parser, got %v", err)
	}
}

// TestParseVictoriaLogsNonRecordJSON pins that valid JSON which is not a log
// record (e.g. an error object with no _msg) is named as what it is: the
// reply parsed and carried no log record, so the read cannot state that the
// scope had no lines. It is not the empty reply either — that one means
// "nothing matched" — and it is not a failed read, which is pinned at the
// fetch level.
func TestParseVictoriaLogsNonRecordJSON(t *testing.T) {
	records, err := parseVictoriaLogs([]byte("{\"error\":\"unauthorized\"}\n"))
	if !errors.Is(err, errNoLogRecords) {
		t.Fatalf("a non-record body must be named as carrying no log record, got %v", err)
	}
	if errors.Is(err, errEmptyVictoriaLogsReply) {
		t.Fatalf("a non-record body is not an empty reply: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected no records from a non-record body, got %#v", records)
	}
}

// TestParseVictoriaLogsNonRecordWithMalformedLine pins the other half of the
// guard's boundary (issue #342, criterion 2): a body holding a line that
// parsed is not wholly unparseable, even when the parsed line carried no log
// record and another line was malformed. It names the no-record condition
// instead of failing the read.
func TestParseVictoriaLogsNonRecordWithMalformedLine(t *testing.T) {
	records, err := parseVictoriaLogs([]byte("{\"error\":\"unauthorized\"}\nnot json at all\n"))
	if !errors.Is(err, errNoLogRecords) {
		t.Fatalf("a body with a parseable line but no log record must be named as such, got %v", err)
	}
	if errors.Is(err, errEmptyVictoriaLogsReply) {
		t.Fatalf("a body with a parseable line is not an empty reply: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected no records from a non-record body, got %#v", records)
	}
}

// TestParseVictoriaLogsBlankMessageIsARecord pins the other side of #349's
// record test: a record whose message is blank is still a record, so the
// reply is a set of log lines that happened to be empty of content — the
// empty scope it earned — and not the no-record gap. Only a reply whose
// lines carried no _msg field at all is the gap.
func TestParseVictoriaLogsBlankMessageIsARecord(t *testing.T) {
	records, err := parseVictoriaLogs([]byte("{\"_msg\":\"\"}\n"))
	if err != nil {
		t.Fatalf("a blank message is noise, not a failed read: %v", err)
	}
	if errors.Is(err, errNoLogRecords) {
		t.Fatalf("a blank message is still a record, so the empty scope stands: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected the blank message to be dropped, got %#v", records)
	}
}

// TestParseVictoriaLogsRealisticReplyShape exercises the field set a real
// VictoriaLogs /select/logsql/query reply carries — _time, _stream, _msg and
// the kubernetes.* labels — with a malformed line between two records. The
// records around the malformed line must survive with their messages intact,
// and the extra fields must not affect the parse.
func TestParseVictoriaLogsRealisticReplyShape(t *testing.T) {
	body := []byte(`{"_msg":"failed to pull image","_time":"2026-11-10T10:00:00Z","_stream":"stdout","kubernetes_namespace":"ns-a","kubernetes_pod_name":"p1"}
{"_msg":"trunca
{"_msg":"container restarted","_time":"2026-11-10T10:00:05Z","_stream":"stdout","kubernetes_namespace":"ns-a","kubernetes_pod_name":"p1"}
`)
	records, err := parseVictoriaLogs(body)
	if err != nil {
		t.Fatalf("a malformed line in a realistic reply must not fail the read: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 valid records, got %d: %#v", len(records), records)
	}
	if records[0].message != "failed to pull image" || records[1].message != "container restarted" {
		t.Fatalf("records around the malformed line must survive: %#v", records)
	}
}

// TestParseVictoriaLogsSkipsBlankMessages pins that blank _msg values are
// dropped as noise while real messages survive.
func TestParseVictoriaLogsSkipsBlankMessages(t *testing.T) {
	body := []byte("{}\n{\"_msg\":\"   \"}\n{\"_msg\":\"real\"}\n")
	records, err := parseVictoriaLogs(body)
	if err != nil {
		t.Fatalf("parseVictoriaLogs: %v", err)
	}
	if len(records) != 1 || records[0].message != "real" {
		t.Fatalf("expected only non-blank message, got %#v", records)
	}
}

func TestParseLokiSuccess(t *testing.T) {
	body := []byte(`{"status":"success","data":{"result":[
		{"stream":{"pod":"p1","namespace":"ns"},"values":[["1","line A"],["2","line B"]]}
	]}}`)
	records, err := parseLoki(body)
	if err != nil {
		t.Fatalf("parseLoki: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d: %#v", len(records), records)
	}
	if records[0].stream != "namespace=ns pod=p1" || records[1].stream != "namespace=ns pod=p1" {
		t.Fatalf("unexpected streams: %#v", records)
	}
	if records[0].message != "line A" || records[1].message != "line B" {
		t.Fatalf("unexpected messages: %#v", records)
	}
}

func TestParseLokiStatusError(t *testing.T) {
	body := []byte(`{"status":"error","data":{"resultType":"","result":[]}}`)
	if _, err := parseLoki(body); err == nil {
		t.Fatalf("expected error for non-success status")
	}
}

func TestParseLokiMalformed(t *testing.T) {
	body := []byte(`not json at all`)
	if _, err := parseLoki(body); err == nil {
		t.Fatalf("expected error for malformed JSON")
	}
}

// TestParseLokiEmptyBody pins that the Loki parser is left alone: its reply
// is a single JSON document, so an empty body is unreadable and errors. The
// VictoriaLogs parser may degrade a reply; Loki's has no line to degrade.
func TestParseLokiEmptyBody(t *testing.T) {
	if _, err := parseLoki([]byte("")); err == nil {
		t.Fatalf("expected an error for an empty Loki body")
	}
}

func TestParseLokiEmptyResult(t *testing.T) {
	body := []byte(`{"status":"success","data":{"result":[]}}`)
	records, err := parseLoki(body)
	if err != nil {
		t.Fatalf("empty result should not error: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected 0 records, got %#v", records)
	}
}

func TestParseLokiSkipsBlankMessages(t *testing.T) {
	body := []byte(`{"status":"success","data":{"result":[
		{"stream":{"pod":"p1"},"values":[["1","   "],["2","real"]]}
	]}}`)
	records, err := parseLoki(body)
	if err != nil {
		t.Fatalf("parseLoki: %v", err)
	}
	if len(records) != 1 || records[0].message != "real" {
		t.Fatalf("expected only the non-blank message, got %#v", records)
	}
}

func TestStreamLabelsSorted(t *testing.T) {
	got := streamLabels(map[string]string{"zebra": "z", "alpha": "a", "beta": "b"})
	want := []string{"alpha=a", "beta=b", "zebra=z"}
	if len(got) != len(want) {
		t.Fatalf("streamLabels = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("streamLabels[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestStreamLabelsNil(t *testing.T) {
	if got := streamLabels(nil); got != nil {
		t.Fatalf("streamLabels(nil) = %#v, want nil", got)
	}
}

func TestStreamLabelsEmpty(t *testing.T) {
	if got := streamLabels(map[string]string{}); got != nil {
		t.Fatalf("streamLabels(empty) = %#v, want nil", got)
	}
}

func TestStreamLabelsKeepsBlankValues(t *testing.T) {
	got := streamLabels(map[string]string{"k": "v", "blank": "", "blank2": "   "})
	want := []string{"blank=", "blank2=   ", "k=v"}
	if len(got) != len(want) {
		t.Fatalf("streamLabels = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("streamLabels[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCollapseAndCapDistinct(t *testing.T) {
	order := []*backendLog{
		{message: "alpha", count: 1},
		{message: "beta", count: 1},
		{message: "gamma", count: 1},
	}
	got := collapseAndCap(order, 5)
	if len(got) != 3 {
		t.Fatalf("expected 3 lines, got %d: %#v", len(got), got)
	}
	if got[0] != "alpha" || got[1] != "beta" || got[2] != "gamma" {
		t.Fatalf("distinct lines should pass through unchanged: %#v", got)
	}
}

func TestCollapseAndCapRepeats(t *testing.T) {
	order := []*backendLog{
		{message: "foo", count: 3},
		{message: "bar", count: 1},
	}
	got := collapseAndCap(order, 10)
	if len(got) != 2 {
		t.Fatalf("expected 2 collapsed entries, got %d: %#v", len(got), got)
	}
	if got[0] != "[x3] foo" {
		t.Fatalf("expected '[x3] foo', got %q", got[0])
	}
	if got[1] != "bar" {
		t.Fatalf("expected 'bar' second, got %q", got[1])
	}
}

func TestCollapseAndCapStreamPrefix(t *testing.T) {
	order := []*backendLog{
		{stream: "ns-a pod-p", message: "boom", count: 2},
		{stream: "ns-a pod-p", message: "restart", count: 1},
	}
	got := collapseAndCap(order, 10)
	if len(got) != 2 {
		t.Fatalf("expected 2 lines, got %d: %#v", len(got), got)
	}
	if got[0] != "[x2] [ns-a pod-p] boom" {
		t.Fatalf("expected count-then-stream prefix, got %q", got[0])
	}
	if got[1] != "[ns-a pod-p] restart" {
		t.Fatalf("expected stream prefix on single, got %q", got[1])
	}
}

func TestCollapseAndCapOverflow(t *testing.T) {
	order := []*backendLog{
		{message: "a", count: 1}, {message: "b", count: 1}, {message: "c", count: 1},
		{message: "d", count: 1}, {message: "e", count: 1}, {message: "f", count: 1},
		{message: "g", count: 1},
	}
	got := collapseAndCap(order, 5)
	if len(got) != 6 {
		t.Fatalf("expected 6 entries (5 + overflow), got %d: %#v", len(got), got)
	}
	if got[5] != "...and 2 more distinct lines" {
		t.Fatalf("expected overflow marker, got %q", got[5])
	}
	for i := 0; i < 5; i++ {
		if got[i] != string(rune('a'+i)) {
			t.Fatalf("line %d = %q", i, got[i])
		}
	}
}

func TestCollapseAndCapZeroFallback(t *testing.T) {
	order := []*backendLog{
		{message: "alpha", count: 1},
		{message: "beta", count: 1},
		{message: "gamma", count: 1},
	}
	got := collapseAndCap(order, 0)
	if len(got) != 3 {
		t.Fatalf("cap=0 should fall back to default limit, got %d: %#v", len(got), got)
	}
}

func TestQueryVictoriaLogsOverHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/select/logsql/query") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if q := r.URL.Query().Get("query"); q == "" || !strings.Contains(q, "namespace:") {
			t.Errorf("query param missing namespace filter: %q", q)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"_msg\":\"hello\"}\n{\"_msg\":\"world\"}\n"))
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		flavor: "victorialogs",
		limit:  50,
		hc:     srv.Client(),
	}
	start := time.Now().Add(-time.Minute)
	end := time.Now()
	records, err := b.query(context.Background(), "ns-a", "pod-1", start, end)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d: %#v", len(records), records)
	}
	if records[0].message != "hello" || records[1].message != "world" {
		t.Fatalf("unexpected messages: %#v", records)
	}
}

// TestQueryVictoriaLogsEmptyReplyIsEmptyScope pins the boundary between an
// empty reply and a failed read: VictoriaLogs answers a query that matched
// nothing with an empty 200 body, so the read succeeds with no lines and the
// digest can state an empty scope. Reporting it as a failed query would
// claim a failure the backend never reported.
func TestQueryVictoriaLogsEmptyReplyIsEmptyScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		flavor: "victorialogs",
		limit:  50,
		hc:     srv.Client(),
	}
	records, err := b.query(context.Background(), "ns-a", "pod-1", time.Now().Add(-time.Minute), time.Now())
	if err != nil {
		t.Fatalf("an empty reply must not fail the read: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected no records from an empty reply, got %#v", records)
	}
}

// TestFetchBackendLogsEmptyReplyIsEmptyScope pins that a namespace whose
// reply is empty does not abort the read for the whole group: the group ends
// with no lines and no error, which is what lets the digest state an empty
// scope instead of a failed query.
func TestFetchBackendLogsEmptyReplyIsEmptyScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		flavor: "victorialogs",
		limit:  50,
		hc:     srv.Client(),
	}
	g := Group{
		Namespaces: []string{"ns-a"},
		Alerts: []Alert{
			{Labels: map[string]string{"pod": "p1", "namespace": "ns-a", "alertname": "KubePodNotReady"}},
		},
	}
	res, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, targetPodsFromAlerts(g.Alerts))
	if err != nil {
		t.Fatalf("an empty reply must not fail the group read: %v", err)
	}
	if len(res.Primary) != 0 || len(res.Ambient) != 0 {
		t.Fatalf("expected no lines from an empty reply, got %#v", res)
	}
	if res.SkippedRefused {
		t.Fatalf("an empty reply is an empty scope, not a refused one")
	}
}

// TestFetchBackendLogsDegradedReplyKeepsRecords pins the degrade-not-fail
// stance end to end: a reply with one malformed line still yields the records
// around it, as primary evidence for the group.
func TestFetchBackendLogsDegradedReplyKeepsRecords(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = io.WriteString(w, "{\"_msg\":\"first line\"}\nnot json at all\n{\"_msg\":\"second line\"}\n")
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		flavor: "victorialogs",
		limit:  50,
		hc:     srv.Client(),
	}
	g := Group{
		Namespaces: []string{"ns-a"},
		Alerts: []Alert{
			{Labels: map[string]string{"pod": "p1", "namespace": "ns-a", "alertname": "KubePodNotReady"}},
		},
	}
	res, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, targetPodsFromAlerts(g.Alerts))
	if err != nil {
		t.Fatalf("a degraded reply must not fail the group read: %v", err)
	}
	if len(res.Primary) != 2 {
		t.Fatalf("expected the 2 valid records as primary evidence, got %#v", res.Primary)
	}
	if !strings.Contains(res.Primary[0], "first line") || !strings.Contains(res.Primary[1], "second line") {
		t.Fatalf("the records around the malformed line must survive: %#v", res.Primary)
	}
}

// TestFetchBackendLogsNoRecordReplyIsStatedGap pins the fetch-level half of
// #349: a reply that parses but carries no log record is a fact about the
// reply, not a failed read. The group read ends without an error and without
// lines, and the fact travels with the result so the caller can state the
// gap instead of claiming the scope had no lines.
func TestFetchBackendLogsNoRecordReplyIsStatedGap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = io.WriteString(w, "{\"error\":\"unauthorized\"}\n")
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		flavor: "victorialogs",
		limit:  50,
		hc:     srv.Client(),
	}
	g := Group{
		Namespaces: []string{"ns-a"},
		Alerts: []Alert{
			{Labels: map[string]string{"pod": "p1", "namespace": "ns-a", "alertname": "KubePodNotReady"}},
		},
	}
	res, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, targetPodsFromAlerts(g.Alerts))
	if err != nil {
		t.Fatalf("a reply carrying no log record must not fail the group read: %v", err)
	}
	if len(res.Primary) != 0 || len(res.Ambient) != 0 {
		t.Fatalf("expected no lines from a reply carrying no log record, got %#v", res)
	}
	if !res.NoRecords {
		t.Fatalf("a reply carrying no log record must be reported as such")
	}
	if res.SkippedRefused {
		t.Fatalf("a reply carrying no log record is not a refused scope")
	}
}

// TestFetchBackendLogsNoRecordReplyKeepsOtherScope pins that a no-record
// reply does not abort the read and does not hide the other scope's records:
// one namespace answers with something that is not a log record, the other
// answers with a record, and the group read ends with that record as primary
// evidence plus the no-record fact.
func TestFetchBackendLogsNoRecordReplyKeepsOtherScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		if strings.Contains(r.URL.Query().Get("query"), `"ns-a"`) {
			_, _ = io.WriteString(w, "{\"error\":\"unauthorized\"}\n")
			return
		}
		_, _ = io.WriteString(w, "{\"_msg\":\"second scope line\"}\n")
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		flavor: "victorialogs",
		limit:  50,
		hc:     srv.Client(),
	}
	g := Group{
		Namespaces: []string{"ns-a", "ns-b"},
		Alerts: []Alert{
			{Labels: map[string]string{"pod": "p1", "namespace": "ns-a", "alertname": "KubePodNotReady"}},
			{Labels: map[string]string{"pod": "p2", "namespace": "ns-b", "alertname": "KubePodNotReady"}},
		},
	}
	res, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, targetPodsFromAlerts(g.Alerts))
	if err != nil {
		t.Fatalf("a no-record reply must not fail the group read: %v", err)
	}
	if len(res.Primary) != 1 || !strings.Contains(res.Primary[0], "second scope line") {
		t.Fatalf("expected the other scope's record as primary evidence, got %#v", res.Primary)
	}
	if !res.NoRecords {
		t.Fatalf("the no-record reply must be reported as such")
	}
}

// TestFetchBackendLogsRecordReplyUnaffected pins the other half of #349: a
// reply that carries real records is unchanged by the no-record condition.
func TestFetchBackendLogsRecordReplyUnaffected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = io.WriteString(w, "{\"_msg\":\"real line\"}\n")
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		flavor: "victorialogs",
		limit:  50,
		hc:     srv.Client(),
	}
	g := Group{
		Namespaces: []string{"ns-a"},
		Alerts: []Alert{
			{Labels: map[string]string{"pod": "p1", "namespace": "ns-a", "alertname": "KubePodNotReady"}},
		},
	}
	res, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, targetPodsFromAlerts(g.Alerts))
	if err != nil {
		t.Fatalf("a reply carrying records must not fail the group read: %v", err)
	}
	if len(res.Primary) != 1 || !strings.Contains(res.Primary[0], "real line") {
		t.Fatalf("expected the record as primary evidence, got %#v", res.Primary)
	}
	if res.NoRecords {
		t.Fatalf("a reply carrying records must not be reported as carrying none")
	}
}

// TestNoRecordsBackendStateRendersAsGap pins the render-level half of #349:
// a reply that carried no log record must read as a gap, not as the explicit
// negative that there were no lines. Both surfaces say what is known, and
// neither reuses the empty wording. A reply that carried real records is
// unaffected: the line still renders and the gap wording stays away.
func TestNoRecordsBackendStateRendersAsGap(t *testing.T) {
	g := Group{
		Key:        "sig-norecords",
		Namespaces: []string{"ns1"},
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "KubePodNotReady", "namespace": "ns1"}}},
	}
	en := Enrichment{BackendState: "norecords", BackendScoped: true}

	model := renderEvidence(Report{Group: g, Enrichment: en})
	if !strings.Contains(model, "carried no log records") {
		t.Errorf("model prompt must state that the reply carried no log record:\n%s", model)
	}
	if strings.Contains(model, "returned no lines") {
		t.Errorf("model prompt must not claim the scope had no lines:\n%s", model)
	}

	discord := discordDescription(&Config{}, Report{Group: g, Enrichment: en})
	if !strings.Contains(discord, "carried no log records") {
		t.Errorf("discord must state that the reply carried no log record:\n%s", discord)
	}
	if strings.Contains(discord, "returned no lines") {
		t.Errorf("discord must not claim the scope had no lines:\n%s", discord)
	}

	// A reply that carried real records renders as before.
	ok := Enrichment{BackendState: "ok", BackendLogs: []string{"subject backend log line"}}
	model = renderEvidence(Report{Group: g, Enrichment: ok})
	if !strings.Contains(model, "subject backend log line") {
		t.Errorf("model prompt must still render the backend log line:\n%s", model)
	}
	if strings.Contains(model, "carried no log records") {
		t.Errorf("model prompt must not state the no-record gap when lines came back:\n%s", model)
	}

	discord = discordDescription(&Config{}, Report{Group: g, Enrichment: ok})
	if !strings.Contains(discord, "subject backend log line") {
		t.Errorf("discord must still render the backend log line:\n%s", discord)
	}
	if strings.Contains(discord, "carried no log records") {
		t.Errorf("discord must not state the no-record gap when lines came back:\n%s", discord)
	}
}

// TestBuildQuery asserts the exact query string per flavor: VictoriaLogs
// takes LogsQL `field:"value"` filters joined by AND, Loki takes a LogQL
// stream selector — the two backends do not share a query language.
func TestBuildQuery(t *testing.T) {
	cases := []struct {
		flavor string
		pod    string
		want   string
	}{
		{"victorialogs", "", `namespace:"ns-a"`},
		{"victorialogs", "p1", `namespace:"ns-a" AND pod:"p1"`},
		{"loki", "", `{namespace="ns-a"}`},
		{"loki", "p1", `{namespace="ns-a",pod="p1"}`},
	}
	for _, tc := range cases {
		b := &logsBackend{flavor: tc.flavor}
		if got := b.buildQuery("ns-a", tc.pod); got != tc.want {
			t.Errorf("flavor %q pod %q: buildQuery = %q, want %q", tc.flavor, tc.pod, got, tc.want)
		}
	}
}

// TestBuildQueryEscapesValues ensures a `"` or `\` in a namespace or pod
// value cannot break out of the quoted literal in either dialect.
func TestBuildQueryEscapesValues(t *testing.T) {
	ns := `ns"a\b`
	pod := `p"x\y`
	cases := []struct {
		flavor string
		pod    string
		want   string
	}{
		{"victorialogs", "", `namespace:"ns\"a\\b"`},
		{"victorialogs", pod, `namespace:"ns\"a\\b" AND pod:"p\"x\\y"`},
		{"loki", "", `{namespace="ns\"a\\b"}`},
		{"loki", pod, `{namespace="ns\"a\\b",pod="p\"x\\y"}`},
	}
	for _, tc := range cases {
		b := &logsBackend{flavor: tc.flavor}
		if got := b.buildQuery(ns, tc.pod); got != tc.want {
			t.Errorf("flavor %q pod %q: buildQuery = %q, want %q", tc.flavor, tc.pod, got, tc.want)
		}
	}
}

func TestQueryLokiStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/loki/api/v1/query_range") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"error","data":{"result":[]}}`))
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		flavor: "loki",
		limit:  50,
		hc:     srv.Client(),
	}
	if _, err := b.query(context.Background(), "ns-a", "", time.Now().Add(-time.Minute), time.Now()); err == nil {
		t.Fatalf("expected error for non-success loki status")
	}
}

// TestFetchBackendLogsDedup verifies the per-(namespace,pod) query dedup:
// N alerts sharing the same pod in the same namespace must result in exactly
// one pod-scoped query, not N. (The unconditional namespace-only query is
// dropped when subjects are resolved.)
func TestFetchBackendLogsDedup(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"result":[]}}`)
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		flavor: "loki",
		limit:  50,
		hc:     srv.Client(),
	}
	g := Group{
		Namespaces: []string{"ns-a"},
		Alerts: []Alert{
			{Labels: map[string]string{"pod": "p1", "namespace": "ns-a", "alertname": "x"}},
			{Labels: map[string]string{"pod": "p1", "namespace": "ns-a", "alertname": "y"}},
			{Labels: map[string]string{"pod": "p1", "namespace": "ns-a", "alertname": "z"}},
		},
	}
	if _, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, targetPodsFromAlerts(g.Alerts)); err != nil {
		t.Fatalf("fetchBackendLogsResult: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected exactly 1 pod-scoped query after dedup, got %d", got)
	}
}

// TestFetchBackendLogsTargetPodsIsPrimary verifies that when a concrete
// subject is known (via the enrichment's resolved target-pod set), the
// namespace-only query is not issued at all and no namespace-wide lines leak
// into the primary evidence.
func TestFetchBackendLogsTargetPodsIsPrimary(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		queries = append(queries, q)
		w.Header().Set("Content-Type", "application/json")
		if q == `{namespace="ns-a",pod="p1"}` {
			_, _ = io.WriteString(w, `{"status":"success","data":{"result":[{"stream":{"pod":"p1","namespace":"ns-a"},"values":[["1","target pod failure line"]]}]}}`)
			return
		}
		// Namespace-wide query: unrelated controller chatter must never appear.
		_, _ = io.WriteString(w, `{"status":"success","data":{"result":[{"stream":{"pod":"flux-controller","namespace":"ns-a"},"values":[["1","unrelated flux chatter"]]}]}}`)
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		flavor: "loki",
		limit:  50,
		hc:     srv.Client(),
	}
	// The alert carries no pod label; the resolved target set does.
	g := Group{
		Namespaces: []string{"ns-a"},
		Alerts:     []Alert{{Labels: map[string]string{"alertname": "KubeJobFailed"}}},
	}
	targetPods := map[string]bool{"ns-a/p1": true}
	res, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, targetPods)
	if err != nil {
		t.Fatalf("fetchBackendLogsResult: %v", err)
	}
	if len(res.Primary) == 0 || !strings.Contains(res.Primary[0], "target pod failure line") {
		t.Fatalf("expected the target pod's line as primary evidence, got %#v", res.Primary)
	}
	for _, line := range res.Primary {
		if strings.Contains(line, "unrelated flux chatter") {
			t.Fatalf("namespace-wide line entered primary evidence: %#v", res.Primary)
		}
	}
	if len(res.Ambient) != 0 {
		t.Fatalf("no ambient context expected when a subject is resolved, got %#v", res.Ambient)
	}
	if len(queries) != 1 {
		t.Fatalf("expected exactly one (pod-scoped) query, got %d: %v", len(queries), queries)
	}
	if !strings.Contains(queries[0], `pod="p1"`) {
		t.Fatalf("the only query must be pod-scoped, got %q", queries[0])
	}
}

// TestFetchBackendLogsTargetDedup verifies multiple alerts resolving to
// different target pods issue one query per distinct (namespace,pod), and
// never a namespace-only query.
func TestFetchBackendLogsTargetDedup(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Query().Get("query"), `pod="`) {
			t.Errorf("unexpected non-pod-scoped query %q", r.URL.RawQuery)
		}
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"result":[]}}`)
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		flavor: "loki",
		limit:  50,
		hc:     srv.Client(),
	}
	g := Group{
		Namespaces: []string{"ns-a"},
		Alerts: []Alert{
			{Labels: map[string]string{"pod": "p1", "namespace": "ns-a", "alertname": "x"}},
			{Labels: map[string]string{"pod": "p1", "namespace": "ns-a", "alertname": "y"}},
			{Labels: map[string]string{"pod": "p2", "namespace": "ns-a", "alertname": "z"}},
		},
	}
	if _, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, targetPodsFromAlerts(g.Alerts)); err != nil {
		t.Fatalf("fetchBackendLogsResult: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected exactly 2 pod-scoped queries (one per distinct pod), got %d", got)
	}
}

// TestFetchBackendLogsRefusedNamespaceSendsNoQuery pins #311's rule on the
// last raw consumer of the alert namespace: a namespace that is not one path
// segment sends no backend-log request, including the namespace-wide fallback
// issued when no concrete subject survived. The skip must surface to the
// caller as SkippedRefused so an empty result cannot render as "the backend
// has no lines for that namespace" (#331).
func TestFetchBackendLogsRefusedNamespaceSendsNoQuery(t *testing.T) {
	const hostile = "ns/../../other"
	cases := []struct {
		name        string
		namespaces  []string
		targetPods  map[string]bool
		wantQueries []string
	}{
		{
			name:        "no-subject fallback skips the refused sibling",
			namespaces:  []string{"ns-ok", hostile},
			targetPods:  map[string]bool{},
			wantQueries: []string{`{namespace="ns-ok"}`},
		},
		{
			name:        "every namespace refused sends nothing",
			namespaces:  []string{hostile, "ns%2Fesc"},
			targetPods:  map[string]bool{},
			wantQueries: nil,
		},
		{
			name:        "concrete target in a refused namespace sends nothing",
			namespaces:  []string{hostile},
			targetPods:  map[string]bool{hostile + "/p1": true},
			wantQueries: nil,
		},
		{
			// A whitespace-only entry names no namespace. Enrich's
			// refusal rule (the one that gates the apiserver reads)
			// treats it as refused, so the backend must state the same
			// gap rather than render it as an empty scope.
			name:        "whitespace-only namespace is refused, not silently empty",
			namespaces:  []string{" "},
			targetPods:  map[string]bool{},
			wantQueries: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var queries []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				queries = append(queries, r.URL.Query().Get("query"))
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"status":"success","data":{"result":[]}}`)
			}))
			t.Cleanup(srv.Close)

			b := &logsBackend{
				url:    srv.URL,
				flavor: "loki",
				limit:  50,
				hc:     srv.Client(),
			}
			g := Group{
				Namespaces: tc.namespaces,
				Alerts:     []Alert{{Labels: map[string]string{"alertname": "SomeAlert"}}},
			}
			res, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, tc.targetPods)
			if err != nil {
				t.Fatalf("fetchBackendLogsResult: %v", err)
			}
			if len(queries) != len(tc.wantQueries) {
				t.Fatalf("queries = %v, want %v", queries, tc.wantQueries)
			}
			for i, q := range queries {
				if q != tc.wantQueries[i] {
					t.Errorf("query %d = %q, want %q", i, q, tc.wantQueries[i])
				}
			}
			if !res.SkippedRefused {
				t.Errorf("SkippedRefused must be set when a namespace was refused")
			}
		})
	}
}

// TestFetchBackendLogsUnresolvedNamespaceSurfaced pins #339, the branch of
// the #331 rule that fix did not cover: once the group resolved any subject,
// only resolved pods are queried, so a valid second namespace with no
// resolved pod sends no request at all. The gap must reach the caller as
// SkippedUnresolved — whether or not the queried scope returned lines — so
// an uninspected namespace can never render as "the backend has no lines for
// it". The no-subject fallback queries every valid namespace, so it must
// claim no such gap.
func TestFetchBackendLogsUnresolvedNamespaceSurfaced(t *testing.T) {
	cases := []struct {
		name           string
		targetPods     map[string]bool
		withLines      bool
		wantQueries    []string
		wantUnresolved []string
	}{
		{
			name:           "subject-scoped query skips the subject-less namespace",
			targetPods:     map[string]bool{"ns-a/p1": true},
			wantQueries:    []string{`{namespace="ns-a",pod="p1"}`},
			wantUnresolved: []string{"ns-b"},
		},
		{
			// The gap is a fact about the queries sent, not about the
			// result size: it must survive alongside real lines.
			name:           "gap surfaced even when the queried namespace returns lines",
			targetPods:     map[string]bool{"ns-a/p1": true},
			withLines:      true,
			wantQueries:    []string{`{namespace="ns-a",pod="p1"}`},
			wantUnresolved: []string{"ns-b"},
		},
		{
			name:        "no-subject fallback queries every namespace and claims no gap",
			targetPods:  map[string]bool{},
			wantQueries: []string{`{namespace="ns-a"}`, `{namespace="ns-b"}`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var queries []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query().Get("query")
				queries = append(queries, q)
				w.Header().Set("Content-Type", "application/json")
				if tc.withLines && q == `{namespace="ns-a",pod="p1"}` {
					_, _ = io.WriteString(w, `{"status":"success","data":{"result":[{"stream":{"pod":"p1","namespace":"ns-a"},"values":[["1","subject line"]]}]}}`)
					return
				}
				_, _ = io.WriteString(w, `{"status":"success","data":{"result":[]}}`)
			}))
			t.Cleanup(srv.Close)

			b := &logsBackend{
				url:    srv.URL,
				flavor: "loki",
				limit:  50,
				hc:     srv.Client(),
			}
			g := Group{
				Namespaces: []string{"ns-a", "ns-b"},
				Alerts: []Alert{
					{Status: "firing", Labels: map[string]string{"alertname": "KubePodNotReady", "namespace": "ns-a", "pod": "p1"}},
					{Status: "firing", Labels: map[string]string{"alertname": "KubePodNotReady", "namespace": "ns-b"}},
				},
			}
			res, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, tc.targetPods)
			if err != nil {
				t.Fatalf("fetchBackendLogsResult: %v", err)
			}
			if len(queries) != len(tc.wantQueries) {
				t.Fatalf("queries = %v, want %v", queries, tc.wantQueries)
			}
			for i, q := range queries {
				if q != tc.wantQueries[i] {
					t.Errorf("query %d = %q, want %q", i, q, tc.wantQueries[i])
				}
			}
			if tc.withLines && len(res.Primary) == 0 {
				t.Errorf("the queried namespace's lines must still come back as primary")
			}
			if len(res.SkippedUnresolved) != len(tc.wantUnresolved) {
				t.Fatalf("SkippedUnresolved = %#v, want %#v", res.SkippedUnresolved, tc.wantUnresolved)
			}
			for i, ns := range res.SkippedUnresolved {
				if ns != tc.wantUnresolved[i] {
					t.Errorf("SkippedUnresolved[%d] = %q, want %q", i, ns, tc.wantUnresolved[i])
				}
			}
			if res.SkippedRefused {
				t.Errorf("a valid subject-less namespace is a distinct gap from a refused one")
			}
		})
	}
}

// TestFetchBackendLogsNoSubjectIsAmbient verifies the fallback: with no
// concrete subject the namespace-wide lookup still runs, but its result is
// explicitly marked ambient and never placed in the primary evidence.
func TestFetchBackendLogsNoSubjectIsAmbient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if q != `{namespace="ns-a"}` {
			t.Errorf("exact namespace-only selector expected, got %q", q)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"result":[{"stream":{"pod":"other","namespace":"ns-a"},"values":[["1","namespace chatter"]]}]}}`)
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		flavor: "loki",
		limit:  50,
		hc:     srv.Client(),
	}
	g := Group{
		Namespaces: []string{"ns-a"},
		Alerts:     []Alert{{Labels: map[string]string{"alertname": "SomeAlert"}}},
	}
	res, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, map[string]bool{})
	if err != nil {
		t.Fatalf("fetchBackendLogsResult: %v", err)
	}
	if len(res.Primary) != 0 {
		t.Fatalf("expected no primary evidence without a subject, got %#v", res.Primary)
	}
	if len(res.Ambient) != 1 || !strings.Contains(res.Ambient[0], "(ambient, namespace-wide)") {
		t.Fatalf("expected exactly one explicitly-ambient line, got %#v", res.Ambient)
	}
}

// TestFetchBackendLogsLokiSelectors asserts the exact LogQL stream selector
// on the wire for both the pod-scoped primary path and the namespace-only
// ambient fallback: Loki's query_range endpoint does not accept the
// VictoriaLogs `pod:"..."` filter syntax.
func TestFetchBackendLogsLokiSelectors(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		queries = append(queries, q)
		w.Header().Set("Content-Type", "application/json")
		switch q {
		case `{namespace="ns-a",pod="p1"}`:
			_, _ = io.WriteString(w, `{"status":"success","data":{"result":[{"stream":{"pod":"p1","namespace":"ns-a"},"values":[["1","resolved pod line"]]}]}}`)
		case `{namespace="ns-a"}`:
			_, _ = io.WriteString(w, `{"status":"success","data":{"result":[{"stream":{"pod":"other","namespace":"ns-a"},"values":[["1","namespace chatter"]]}]}}`)
		default:
			t.Errorf("unexpected query %q", q)
		}
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		flavor: "loki",
		limit:  50,
		hc:     srv.Client(),
	}
	g := Group{Namespaces: []string{"ns-a"}}

	// Resolved subject: the pod-scoped selector must be what hits the wire
	// and its line must be primary evidence.
	res, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, map[string]bool{"ns-a/p1": true})
	if err != nil {
		t.Fatalf("fetchBackendLogsResult: %v", err)
	}
	if len(res.Primary) != 1 || !strings.Contains(res.Primary[0], "resolved pod line") {
		t.Fatalf("expected the resolved pod's line as primary, got %#v", res.Primary)
	}
	if len(res.Ambient) != 0 {
		t.Fatalf("no ambient expected with a resolved subject, got %#v", res.Ambient)
	}

	// No subject: only the namespace-only selector may be issued and its
	// line must be ambient.
	res, err = b.fetchBackendLogsResult(context.Background(), g, time.Minute, map[string]bool{})
	if err != nil {
		t.Fatalf("fetchBackendLogsResult: %v", err)
	}
	if len(res.Primary) != 0 {
		t.Fatalf("no primary expected without a subject, got %#v", res.Primary)
	}
	if len(res.Ambient) != 1 || !strings.Contains(res.Ambient[0], "namespace chatter") {
		t.Fatalf("expected the namespace chatter as ambient, got %#v", res.Ambient)
	}

	want := []string{`{namespace="ns-a",pod="p1"}`, `{namespace="ns-a"}`}
	if len(queries) != 2 {
		t.Fatalf("expected exactly 2 queries, got %d: %v", len(queries), queries)
	}
	for i, w := range want {
		if queries[i] != w {
			t.Errorf("query[%d] = %q, want %q", i, queries[i], w)
		}
	}
}

// TestTargetPodsByNamespace verifies the namespace/pod key split. The first
// "/" separates namespace from pod, so extra slashes belong to the pod name;
// keys missing either half are dropped rather than turned into bogus queries.
func TestTargetPodsByNamespace(t *testing.T) {
	got := targetPodsByNamespace(map[string]bool{
		"ns-a/p1": true,
		"ns-a/p2": true,
		"ns-b/p1": true,
		"/p":      true, // no namespace
		"ns/":     true, // no pod
		"noSlash": true, // not a key
		"ns/p/od": true, // extra slash is part of the pod name
	})
	if len(got) != 3 {
		t.Fatalf("expected 3 namespaces, got %#v", got)
	}
	if len(got["ns-a"]) != 2 || got["ns-a"][0] != "p1" || got["ns-a"][1] != "p2" {
		t.Fatalf("ns-a = %#v, want [p1 p2] sorted", got["ns-a"])
	}
	if len(got["ns-b"]) != 1 || got["ns-b"][0] != "p1" {
		t.Fatalf("ns-b = %#v", got["ns-b"])
	}
	if len(got["ns"]) != 1 || got["ns"][0] != "p/od" {
		t.Fatalf("extra slashes belong to the pod name, got %#v", got["ns"])
	}
	if _, ok := got[""]; ok {
		t.Fatalf("blank namespace key must be dropped, got %#v", got)
	}
}

// TestFetchBackendLogsEmptyNamespace verifies the short-circuit when the
// group has no namespaces — the backend should not be hit at all.
func TestFetchBackendLogsEmptyNamespace(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"result":[]}}`)
	}))
	t.Cleanup(srv.Close)

	b := &logsBackend{
		url:    srv.URL,
		flavor: "loki",
		limit:  50,
		hc:     srv.Client(),
	}
	g := Group{Alerts: []Alert{{Labels: map[string]string{"alertname": "x"}}}}
	lines, err := b.fetchBackendLogsResult(context.Background(), g, time.Minute, targetPodsFromAlerts(g.Alerts))
	if err != nil {
		t.Fatalf("fetchBackendLogsResult: %v", err)
	}
	if lines.Primary != nil {
		t.Fatalf("expected nil primary for empty namespace, got %v", lines.Primary)
	}
	if lines.Ambient != nil {
		t.Fatalf("expected no ambient for empty namespace, got %v", lines.Ambient)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("expected zero backend hits for empty-namespace short-circuit, got %d", got)
	}
}

// TestFetchBackendLogsNilReceiver ensures the nil-receiver guard works.
func TestFetchBackendLogsNilReceiver(t *testing.T) {
	var b *logsBackend
	res, err := b.fetchBackendLogsResult(context.Background(), Group{}, time.Minute, nil)
	if err != nil {
		t.Fatalf("nil receiver should be a no-op, got err=%v", err)
	}
	if res.Primary != nil || res.Ambient != nil {
		t.Fatalf("nil receiver should return empty results, got %#v", res)
	}
}
