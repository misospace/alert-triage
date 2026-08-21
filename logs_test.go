package main

import (
	"strings"
	"testing"
)

func TestParseVictoriaLogsSuccess(t *testing.T) {
	body := strings.Join([]string{
		`{"_msg":"first line","_stream":"{namespace=\"ns\",pod=\"p1\"}"}`,
		`{"_msg":"second line","_stream":"{namespace=\"ns\",pod=\"p2\"}"}`,
		``, // trailing empty line preserved
	}, "\n")
	lines, err := parseVictoriaLogs(body)
	if err != nil {
		t.Fatalf("parseVictoriaLogs: %v", err)
	}
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines, got %d (%q)", len(lines), lines)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "first line") || !strings.Contains(joined, "second line") {
		t.Fatalf("missing messages: %s", joined)
	}
}

func TestParseVictoriaLogsMalformed(t *testing.T) {
	body := "this is not json\nand neither is this"
	if _, err := parseVictoriaLogs(body); err == nil {
		t.Fatalf("expected error for malformed JSONL")
	}
}

func TestParseVictoriaLogsEmpty(t *testing.T) {
	lines, err := parseVictoriaLogs("")
	if err != nil {
		t.Fatalf("empty input should not error: %v", err)
	}
	if len(lines) != 0 {
		t.Fatalf("empty input should produce no lines, got %v", lines)
	}
}

func TestParseLokiSuccess(t *testing.T) {
	body := `{
	  "status": "success",
	  "data": {
	    "result": [
	      {"stream": {"pod": "p1", "namespace": "ns"}, "values": [["1","line A"], ["2","line B"]]}
	    ]
	  }
	}`
	lines, err := parseLoki(body)
	if err != nil {
		t.Fatalf("parseLoki: %v", err)
	}
	if len(lines) == 0 {
		t.Fatalf("expected parsed lines, got 0")
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "line A") || !strings.Contains(joined, "line B") {
		t.Fatalf("missing log lines: %s", joined)
	}
	if !strings.Contains(joined, "namespace") || !strings.Contains(joined, "pod") {
		t.Fatalf("missing stream labels: %s", joined)
	}
	// streamLabels is sorted so namespace should appear before pod.
	nsIdx := strings.Index(joined, "namespace")
	podIdx := strings.Index(joined, "pod=")
	if nsIdx < 0 || podIdx < 0 || nsIdx >= podIdx {
		t.Fatalf("expected sorted stream labels (namespace before pod): %s", joined)
	}
}

func TestParseLokiStatusError(t *testing.T) {
	body := `{"status":"error","data":{"resultType":"","result":[]}}`
	if _, err := parseLoki(body); err == nil {
		t.Fatalf("expected error for non-success status")
	}
}

func TestParseLokiMalformed(t *testing.T) {
	body := `not json at all`
	if _, err := parseLoki(body); err == nil {
		t.Fatalf("expected error for malformed JSON")
	}
}

func TestParseLokiEmptyResult(t *testing.T) {
	body := `{"status":"success","data":{"result":[]}}`
	lines, err := parseLoki(body)
	if err != nil {
		t.Fatalf("empty result should not error: %v", err)
	}
	if len(lines) != 0 {
		t.Fatalf("expected 0 lines, got %d", len(lines))
	}
}

func TestStreamLabelsSorted(t *testing.T) {
	got := streamLabels(map[string]string{"zebra": "z", "alpha": "a", "beta": "b"})
	if got != "alpha=a beta=b zebra=z" {
		t.Fatalf("streamLabels sorted = %q", got)
	}
}

func TestStreamLabelsNil(t *testing.T) {
	if got := streamLabels(nil); got != "" {
		t.Fatalf("streamLabels(nil) = %q", got)
	}
}

func TestStreamLabelsEmpty(t *testing.T) {
	if got := streamLabels(map[string]string{}); got != "" {
		t.Fatalf("streamLabels(empty) = %q", got)
	}
}

func TestStreamLabelsSkipsBlank(t *testing.T) {
	got := streamLabels(map[string]string{"k": "v", "blank": "", "blank2": "   "})
	if got != "k=v" {
		t.Fatalf("streamLabels should skip blank values, got %q", got)
	}
}

func TestCollapseAndCapDistinct(t *testing.T) {
	lines := []string{"alpha", "beta", "gamma"}
	got := collapseAndCap(lines, 5)
	if len(got) != 3 {
		t.Fatalf("expected 3 lines, got %d: %v", len(got), got)
	}
	if got[0] != "alpha" || got[1] != "beta" || got[2] != "gamma" {
		t.Fatalf("distinct lines should pass through unchanged: %v", got)
	}
}

func TestCollapseAndCapRepeats(t *testing.T) {
	lines := []string{"foo", "foo", "foo", "bar"}
	got := collapseAndCap(lines, 10)
	if len(got) != 2 {
		t.Fatalf("expected 2 collapsed entries, got %d: %v", len(got), got)
	}
	if got[0] != "foo [x3]" {
		t.Fatalf("expected 'foo [x3]' prefix, got %q", got[0])
	}
	if got[1] != "bar" {
		t.Fatalf("expected 'bar' second, got %q", got[1])
	}
}

func TestCollapseAndCapOverflow(t *testing.T) {
	lines := []string{"a", "b", "c", "d", "e", "f", "g"}
	got := collapseAndCap(lines, 5)
	// cap=5 -> 5 distinct lines + overflow marker
	if len(got) != 6 {
		t.Fatalf("expected 6 entries (5 + overflow), got %d: %v", len(got), got)
	}
	if !strings.HasPrefix(got[5], "+") {
		t.Fatalf("expected overflow marker on last line, got %q", got[5])
	}
}

func TestCollapseAndCapZeroFallback(t *testing.T) {
	lines := []string{"only"}
	got := collapseAndCap(lines, 0)
	if len(got) != 1 || got[0] != "only" {
		t.Fatalf("cap=0 should fall back to default behaviour, got %v", got)
	}
}

func TestQueryString(t *testing.T) {
	// query builds a backend-specific query string; ensure neither panics nor returns empty.
	got := query("loki", 10*1_000_000_000, 20*1_000_000_000, "ns-a")
	if got == "" {
		t.Fatalf("query(loki) should not be empty")
	}
}
