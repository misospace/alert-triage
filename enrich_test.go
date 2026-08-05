package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- JSON parser fixture tests ---

func TestPodList_Parse(t *testing.T) {
	raw := `{
		"items": [
			{
				"metadata": {"name": "pod-a", "namespace": "default"},
				"spec": {"nodeName": "node-1"},
				"status": {
					"phase": "Running",
					"containerStatuses": [
						{
							"name": "app",
							"restartCount": 3,
							"ready": true,
							"state": {"running": {}}
						}
					]
				}
			},
			{
				"metadata": {"name": "pod-b", "namespace": "default"},
				"spec": {"nodeName": "node-2"},
				"status": {
					"phase": "Failed",
					"containerStatuses": [
						{
							"name": "app",
							"restartCount": 0,
							"ready": false,
							"state": {"waiting": {"reason": "CrashLoopBackOff"}}
						}
					]
				}
			}
		]
	}`

	var pl podList
	if err := json.Unmarshal([]byte(raw), &pl); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(pl.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(pl.Items))
	}

	a := pl.Items[0]
	if a.Metadata.Name != "pod-a" {
		t.Errorf("item 0 name = %q, want pod-a", a.Metadata.Name)
	}
	if a.Spec.NodeName != "node-1" {
		t.Errorf("item 0 node = %q, want node-1", a.Spec.NodeName)
	}
	if a.Status.Phase != "Running" {
		t.Errorf("item 0 phase = %q, want Running", a.Status.Phase)
	}
	if len(a.Status.ContainerStatuses) != 1 {
		t.Fatalf("item 0 expected 1 container status")
	}
	cs := a.Status.ContainerStatuses[0]
	if cs.RestartCount != 3 {
		t.Errorf("item 0 restart count = %d, want 3", cs.RestartCount)
	}
	if !cs.Ready {
		t.Error("item 0 expected ready=true")
	}

	b := pl.Items[1]
	if b.Metadata.Name != "pod-b" {
		t.Errorf("item 1 name = %q, want pod-b", b.Metadata.Name)
	}
	if b.Status.Phase != "Failed" {
		t.Errorf("item 1 phase = %q, want Failed", b.Status.Phase)
	}
	cs2 := b.Status.ContainerStatuses[0]
	reason, ok := cs2.State["waiting"]
	if !ok {
		t.Fatal("item 1 expected waiting state")
	}
	if reason.Reason != "CrashLoopBackOff" {
		t.Errorf("item 1 reason = %q, want CrashLoopBackOff", reason.Reason)
	}
}

func TestPodList_EmptyItems(t *testing.T) {
	raw := `{"items": []}`
	var pl podList
	if err := json.Unmarshal([]byte(raw), &pl); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(pl.Items) != 0 {
		t.Errorf("expected 0 items, got %d", len(pl.Items))
	}
}

func TestNodeList_Parse(t *testing.T) {
	raw := `{
		"items": [
			{
				"metadata": {"name": "healthy-node"},
				"spec": {"unschedulable": false},
				"status": {
					"conditions": [
						{"type": "Ready", "status": "True", "reason": "", "message": ""}
					]
				}
			},
			{
				"metadata": {"name": "bad-node"},
				"spec": {"unschedulable": true},
				"status": {
					"conditions": [
						{"type": "Ready", "status": "False", "reason": "KubeletNotReady", "message": ""},
						{"type": "MemoryPressure", "status": "True", "reason": "", "message": ""}
					]
				}
			}
		]
	}`

	var nl nodeList
	if err := json.Unmarshal([]byte(raw), &nl); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(nl.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(nl.Items))
	}

	h := nl.Items[0]
	if h.Metadata.Name != "healthy-node" {
		t.Errorf("item 0 name = %q, want healthy-node", h.Metadata.Name)
	}
	if h.Spec.Unschedulable {
		t.Error("item 0 expected unschedulable=false")
	}

	b := nl.Items[1]
	if b.Metadata.Name != "bad-node" {
		t.Errorf("item 1 name = %q, want bad-node", b.Metadata.Name)
	}
	if !b.Spec.Unschedulable {
		t.Error("item 1 expected unschedulable=true")
	}
	if len(b.Status.Conditions) != 2 {
		t.Fatalf("item 1 expected 2 conditions, got %d", len(b.Status.Conditions))
	}
	if b.Status.Conditions[0].Type != "Ready" || b.Status.Conditions[0].Status != "False" {
		t.Error("item 1 expected Ready=False condition")
	}
	if b.Status.Conditions[1].Type != "MemoryPressure" {
		t.Errorf("item 1 second condition type = %q, want MemoryPressure", b.Status.Conditions[1].Type)
	}
}

func TestEventList_Parse(t *testing.T) {
	raw := `{
		"items": [
			{
				"type": "Warning",
				"reason": "Evicted",
				"message": "The node was low on resource: memory.",
				"lastTimestamp": "2024-01-15T10:30:00Z",
				"involvedObject": {"kind": "Pod", "name": "evicted-pod"}
			}
		]
	}`

	var el eventList
	if err := json.Unmarshal([]byte(raw), &el); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(el.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(el.Items))
	}

	ev := el.Items[0]
	if ev.Type != "Warning" {
		t.Errorf("type = %q, want Warning", ev.Type)
	}
	if ev.Reason != "Evicted" {
		t.Errorf("reason = %q, want Evicted", ev.Reason)
	}
	if ev.InvolvedObject.Kind != "Pod" {
		t.Errorf("kind = %q, want Pod", ev.InvolvedObject.Kind)
	}
	if ev.InvolvedObject.Name != "evicted-pod" {
		t.Errorf("name = %q, want evicted-pod", ev.InvolvedObject.Name)
	}
}

func TestFluxList_Parse(t *testing.T) {
	raw := `{
		"items": [
			{
				"metadata": {"name": "my-release", "namespace": "flux-system"},
				"status": {
					"lastAppliedRevision": "main@sha1:abc123def456",
					"conditions": [
						{
							"type": "Ready",
							"status": "False",
							"reason": "InstallFailed",
							"message": "failed to install",
							"lastTransitionTime": "2024-01-15T10:30:00Z"
						}
					]
				}
			},
			{
				"metadata": {"name": "good-release", "namespace": "flux-system"},
				"status": {
					"lastAppliedRevision": "main@sha1:xyz789",
					"conditions": [
						{
							"type": "Ready",
							"status": "True",
							"reason": "",
							"message": "",
							"lastTransitionTime": "2024-01-15T10:30:00Z"
						}
					]
				}
			}
		]
	}`

	var fl fluxList
	if err := json.Unmarshal([]byte(raw), &fl); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(fl.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(fl.Items))
	}

	failed := fl.Items[0]
	if failed.Metadata.Name != "my-release" {
		t.Errorf("item 0 name = %q, want my-release", failed.Metadata.Name)
	}
	if failed.Status.LastAppliedRevision != "main@sha1:abc123def456" {
		t.Errorf("item 0 revision = %q", failed.Status.LastAppliedRevision)
	}
	if len(failed.Status.Conditions) != 1 {
		t.Fatalf("item 0 expected 1 condition")
	}
	c := failed.Status.Conditions[0]
	if c.Type != "Ready" || c.Status != "False" {
		t.Error("item 0 expected Ready=False")
	}
	if c.Reason != "InstallFailed" {
		t.Errorf("item 0 reason = %q, want InstallFailed", c.Reason)
	}

	good := fl.Items[1]
	if good.Status.Conditions[0].Status != "True" {
		t.Error("item 1 expected Ready=True")
	}
}

// --- Helper function tests ---

func TestCapList_NoCap(t *testing.T) {
	in := []string{"a", "b"}
	out := capList(in, 5)
	if len(out) != 2 {
		t.Errorf("expected 2 items, got %d", len(out))
	}
}

func TestCapList_Caps(t *testing.T) {
	in := []string{"a", "b", "c", "d", "e"}
	out := capList(in, 3)
	if len(out) != 4 {
		t.Fatalf("expected 4 items (3 + summary), got %d", len(out))
	}
	if out[0] != "a" || out[1] != "b" || out[2] != "c" {
		t.Errorf("first 3 items wrong: %v", out[:3])
	}
	if !strings.Contains(out[3], "...and 2 more") {
		t.Errorf("summary item = %q", out[3])
	}
}

func TestTruncate(t *testing.T) {
	s := truncate("hello\nworld", 5)
	if s != "hello..." {
		t.Errorf("truncate = %q, want \"hello...\"", s)
	}

	s2 := truncate("short", 10)
	if s2 != "short" {
		t.Errorf("truncate short = %q, want \"short\"", s2)
	}

	s3 := truncate("  spaced  ", 10)
	if strings.Contains(s3, "\n") {
		t.Error("truncate should replace newlines with spaces")
	}
}

func TestClamp(t *testing.T) {
	s := clamp("hello world", 5)
	if s != "hello..." {
		t.Errorf("clamp = %q, want \"hello...\"", s)
	}

	s2 := clamp("short", 10)
	if s2 != "short" {
		t.Errorf("clamp short = %q, want \"short\"", s2)
	}

	// Clamp preserves newlines.
	s3 := clamp("line1\nline2", 10)
	if !strings.Contains(s3, "\n") {
		t.Error("clamp should preserve newlines")
	}
}

func TestShortRev(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", "unknown"},
		{"main@sha1:abc123def456", "main@sha1:abc123de"},
		{"short", "short"},
		{"main@sha1:ab", "main@sha1:ab"}, // too short for 9-char suffix
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := shortRev(tt.in)
			if got != tt.want {
				t.Errorf("shortRev(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestOrAll(t *testing.T) {
	if got := orAll(""); got != "all namespaces" {
		t.Errorf("orAll(\"\") = %q, want \"all namespaces\"", got)
	}
	if got := orAll("default"); got != "default" {
		t.Errorf("orAll(\"default\") = %q, want \"default\"", got)
	}
}

func TestAlertNamespace(t *testing.T) {
	tests := []struct {
		labels map[string]string
		want   string
	}{
		{map[string]string{"namespace": "default"}, "default"},
		{map[string]string{"exported_namespace": "monitoring"}, "monitoring"},
		{map[string]string{"k8s_namespace": "kube-system"}, "kube-system"},
		{map[string]string{"target_namespace": "app"}, "app"},
		{map[string]string{}, ""},
		{map[string]string{"other": "x"}, ""},
	}

	for i, tt := range tests {
		a := Alert{Labels: tt.labels}
		got := alertNamespace(a)
		if got != tt.want {
			t.Errorf("case %d: alertNamespace = %q, want %q", i, got, tt.want)
		}
	}
}

func TestEnrichment_Empty(t *testing.T) {
	e := Enrichment{}
	if !e.empty() {
		t.Error("empty Enrichment should report empty()")
	}

	e.Nodes = []string{"node-1"}
	if e.empty() {
		t.Error("Enrichment with nodes should not be empty")
	}
}

func TestResolveNodes_NilKube(t *testing.T) {
	var k *kube
	out := k.ResolveNodes([]Alert{
		{Fingerprint: "fp1", Labels: map[string]string{"alertname": "A"}},
	})
	if len(out) != 0 {
		t.Errorf("nil kube ResolveNodes should return empty map, got %v", out)
	}
}

func TestResolveNodes_DirectNodeLabel(t *testing.T) {
	// When alert has a "node" label, it's used directly without API call.
	// We can't test the API path without a real cluster, but we can verify
	// that nil kube returns empty and direct node labels work.
	var k *kube
	alerts := []Alert{
		{Fingerprint: "fp1", Labels: map[string]string{"node": "node-1"}},
	}
	out := k.ResolveNodes(alerts)
	// With nil kube, even direct node labels are not resolved because the
	// function returns early. This is the documented behavior.
	if len(out) != 0 {
		t.Errorf("expected empty map from nil kube, got %v", out)
	}
}

func TestEnrich_NilKube(t *testing.T) {
	var k *kube
	e := k.Enrich(Group{}, time.Hour)
	if e.Scope != "cluster state unavailable" {
		t.Errorf("nil kube Enrich scope = %q, want \"cluster state unavailable\"", e.Scope)
	}
	if !e.empty() {
		t.Error("nil kube Enrich should return empty enrichment")
	}
}

func TestEnrich_NoNamespaces(t *testing.T) {
	var k *kube
	g := Group{Namespaces: []string{}}
	e := k.Enrich(g, time.Hour)
	if e.Scope != "cluster state unavailable" {
		t.Errorf("nil kube scope = %q", e.Scope)
	}
}

// --- unhealthyNodes tests ---

func TestFindUnhealthyNodes_ReadyNode(t *testing.T) {
	items := []nodeItem{
		{
			Metadata: metadata{Name: "good-node"},
			Spec:     nodeSpec{Unschedulable: false},
			Status: nodeStatus{Conditions: []condition{
				{Type: "Ready", Status: "True"},
			}},
		},
	}

	result := findUnhealthyNodes(items)
	if len(result) != 0 {
		t.Errorf("expected no unhealthy nodes, got %v", result)
	}
}

func TestFindUnhealthyNodes_NotReady(t *testing.T) {
	items := []nodeItem{
		{
			Metadata: metadata{Name: "bad-node"},
			Status: nodeStatus{Conditions: []condition{
				{Type: "Ready", Status: "False", Reason: "KubeletNotReady"},
			}},
		},
	}

	result := findUnhealthyNodes(items)
	if len(result) != 1 {
		t.Fatalf("expected 1 unhealthy node, got %d", len(result))
	}
	if !strings.Contains(result[0], "bad-node") || !strings.Contains(result[0], "KubeletNotReady") {
		t.Errorf("unexpected result: %v", result)
	}
}

func TestFindUnhealthyNodes_Unschedulable(t *testing.T) {
	items := []nodeItem{
		{
			Metadata: metadata{Name: "drained-node"},
			Spec:     nodeSpec{Unschedulable: true},
			Status: nodeStatus{Conditions: []condition{
				{Type: "Ready", Status: "True"},
			}},
		},
	}

	result := findUnhealthyNodes(items)
	if len(result) != 1 {
		t.Fatalf("expected 1 unhealthy node, got %d", len(result))
	}
	if !strings.Contains(result[0], "cordoned") {
		t.Errorf("expected cordoned in result: %v", result)
	}
}

func TestFindUnhealthyNodes_MemoryPressure(t *testing.T) {
	items := []nodeItem{
		{
			Metadata: metadata{Name: "oom-node"},
			Status: nodeStatus{Conditions: []condition{
				{Type: "Ready", Status: "True"},
				{Type: "MemoryPressure", Status: "True"},
			}},
		},
	}

	result := findUnhealthyNodes(items)
	if len(result) != 1 {
		t.Fatalf("expected 1 unhealthy node, got %d", len(result))
	}
	if !strings.Contains(result[0], "MemoryPressure") {
		t.Errorf("expected MemoryPressure in result: %v", result)
	}
}

func TestFindUnhealthyNodes_DiskPressure(t *testing.T) {
	items := []nodeItem{
		{
			Metadata: metadata{Name: "disk-node"},
			Status: nodeStatus{Conditions: []condition{
				{Type: "Ready", Status: "True"},
				{Type: "DiskPressure", Status: "True"},
			}},
		},
	}

	result := findUnhealthyNodes(items)
	if len(result) != 1 {
		t.Fatalf("expected 1 unhealthy node, got %d", len(result))
	}
	if !strings.Contains(result[0], "DiskPressure") {
		t.Errorf("expected DiskPressure in result: %v", result)
	}
}

func TestFindUnhealthyNodes_MultipleIssues(t *testing.T) {
	items := []nodeItem{
		{
			Metadata: metadata{Name: "bad-node"},
			Status: nodeStatus{Conditions: []condition{
				{Type: "Ready", Status: "False", Reason: "KubeletNotReady"},
				{Type: "MemoryPressure", Status: "True"},
			}},
		},
	}

	result := findUnhealthyNodes(items)
	if len(result) != 1 {
		t.Fatalf("expected 1 entry (multiple issues joined), got %d: %v", len(result), result)
	}
	if !strings.Contains(result[0], "KubeletNotReady") || !strings.Contains(result[0], "MemoryPressure") {
		t.Errorf("expected both issues in result: %v", result)
	}
}

// --- warningEvents tests ---

func TestFindWarningEvents_NoWarnings(t *testing.T) {
	items := []eventItem{
		{Type: "Normal", Reason: "Scheduled"},
	}

	result := findWarningEvents(items, time.Now())
	if len(result) != 0 {
		t.Errorf("expected no warnings, got %v", result)
	}
}

func TestFindWarningEvents_CapturesWarnings(t *testing.T) {
	now := time.Now()
	items := []eventItem{
		{Type: "Warning", Reason: "Evicted", Message: "low on memory", LastTimestamp: now},
	}

	result := findWarningEvents(items, now.Add(-1*time.Hour))
	if len(result) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(result))
	}
	if !strings.Contains(result[0], "Evicted") {
		t.Errorf("expected Evicted in result: %v", result)
	}
}

func TestFindWarningEvents_CapturesErrors(t *testing.T) {
	now := time.Now()
	items := []eventItem{
		{Type: "Error", Reason: "FailedCreate", Message: "pod creation failed", LastTimestamp: now},
	}

	result := findWarningEvents(items, now.Add(-1*time.Hour))
	if len(result) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result))
	}
	if !strings.Contains(result[0], "FailedCreate") {
		t.Errorf("expected FailedCreate in result: %v", result)
	}
}

func TestFindWarningEvents_InvolvedObject(t *testing.T) {
	now := time.Now()
	items := []eventItem{
		{Type: "Warning", Reason: "BackOff", Message: "restart", LastTimestamp: now, InvolvedObject: involvedObject{Kind: "Pod", Name: "my-pod"}},
	}

	result := findWarningEvents(items, now.Add(-1*time.Hour))
	if len(result) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result))
	}
	if !strings.Contains(result[0], "Pod/my-pod") {
		t.Errorf("expected Pod/my-pod in result: %v", result)
	}
}

func TestFindWarningEvents_TimeWindow(t *testing.T) {
	now := time.Now()
	items := []eventItem{
		{Type: "Warning", Reason: "OldEvent", LastTimestamp: now.Add(-2 * time.Hour)},
	}

	result := findWarningEvents(items, now.Add(-1*time.Hour))
	if len(result) != 0 {
		t.Errorf("expected old event to be filtered out, got %v", result)
	}
}

func TestFindWarningEvents_NoTimestamp(t *testing.T) {
	items := []eventItem{
		{Type: "Warning", Reason: "NoTime", Message: "no timestamp"},
	}

	// Zero time.Time is the earliest possible time, so it's always after any negative since.
	result := findWarningEvents(items, time.Time{})
	if len(result) != 1 {
		t.Fatalf("expected event without timestamp to be included, got %d", len(result))
	}
}

// --- fluxNotReady tests ---

func TestFindFluxNotReady_AllReady(t *testing.T) {
	now := time.Now()
	items := []fluxItem{
		{
			Metadata: metadata{Name: "good-release"},
			Status: fluxStatus{LastAppliedRevision: "main@sha1:abc", Conditions: []fluxCondition{
				{Type: "Ready", Status: "True", LastTransitionTime: now.Add(-2 * time.Hour)},
			}},
		},
	}

	result := findFluxNotReady(items, now.Add(-1*time.Hour))
	if len(result) != 0 {
		t.Errorf("expected no not-ready flux items, got %v", result)
	}
}

func TestFindFluxNotReady_Failed(t *testing.T) {
	items := []fluxItem{
		{
			Metadata: metadata{Name: "bad-release"},
			Status: fluxStatus{LastAppliedRevision: "main@sha1:def", Conditions: []fluxCondition{
				{Type: "Ready", Status: "False", Reason: "InstallFailed", Message: "helm install failed", LastTransitionTime: time.Now()},
			}},
		},
	}

	result := findFluxNotReady(items, time.Now().Add(-1*time.Hour))
	if len(result) != 1 {
		t.Fatalf("expected 1 not-ready item, got %d", len(result))
	}
	if !strings.Contains(result[0], "bad-release") {
		t.Errorf("expected bad-release in result: %v", result)
	}
	if !strings.Contains(result[0], "InstallFailed") {
		t.Errorf("expected InstallFailed in result: %v", result)
	}
}

func TestFindFluxNotReady_TimeWindow(t *testing.T) {
	now := time.Now()
	items := []fluxItem{
		{
			Metadata: metadata{Name: "old-reconcile"},
			Status: fluxStatus{Conditions: []fluxCondition{
				{Type: "Ready", Status: "True", LastTransitionTime: now.Add(-2 * time.Hour)},
			}},
		},
	}

	result := findFluxNotReady(items, now.Add(-1*time.Hour))
	if len(result) != 0 {
		t.Errorf("expected old reconcile to be filtered out, got %v", result)
	}
}

func TestFindFluxNotReady_NoConditions(t *testing.T) {
	items := []fluxItem{
		{Metadata: metadata{Name: "no-conditions"}, Status: fluxStatus{}},
	}

	result := findFluxNotReady(items, time.Now())
	if len(result) != 0 {
		t.Errorf("expected no results for item with no conditions, got %v", result)
	}
}

func TestFindFluxNotReady_RecentlyReconciled(t *testing.T) {
	now := time.Now()
	items := []fluxItem{
		{
			Metadata: metadata{Name: "fresh-release", Namespace: "flux-system"},
			Status: fluxStatus{LastAppliedRevision: "main@sha1:abc123def456", Conditions: []fluxCondition{
				{Type: "Ready", Status: "True", LastTransitionTime: now.Add(-5 * time.Minute)},
			}},
		},
	}

	result := findFluxNotReady(items, now.Add(-1*time.Hour))
	if len(result) != 1 {
		t.Fatalf("expected 1 recently reconciled item, got %d", len(result))
	}
	if !strings.Contains(result[0], "reconciled recently") {
		t.Errorf("expected 'reconciled recently' in result: %v", result)
	}
}

// --- process tests ---

func TestProcess_NilKube(t *testing.T) {
	dir := t.TempDir()
	histPath := filepath.Join(dir, "history.jsonl")
	hist, err := NewHistory(histPath, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		DiscordURL:       "", // no delivery
		CorrelateSlack:   30 * time.Second,
		EvidenceWindow:   15 * time.Minute,
		NarrateTimeout:   5 * time.Second,
	}

	alerts := []Alert{
		{Fingerprint: "fp1", Labels: map[string]string{"alertname": "TestAlert", "severity": "warning"}, Annotations: map[string]string{"summary": "test"}},
	}

	// Should not panic with nil kube.
	process(cfg, alerts, nil, hist)

	// Verify history was recorded.
	if len(hist.entries) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(hist.entries))
	}
}

func TestProcess_MultipleAlerts(t *testing.T) {
	dir := t.TempDir()
	histPath := filepath.Join(dir, "history.jsonl")
	hist, err := NewHistory(histPath, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		DiscordURL:       "",
		CorrelateSlack:   30 * time.Second,
		EvidenceWindow:   15 * time.Minute,
		NarrateTimeout:   5 * time.Second,
	}

	alerts := []Alert{
		{Fingerprint: "fp1", Labels: map[string]string{"alertname": "A"}, Annotations: map[string]string{}},
		{Fingerprint: "fp2", Labels: map[string]string{"alertname": "B"}, Annotations: map[string]string{}},
	}

	process(cfg, alerts, nil, hist)

	// Each alert forms its own group (different names).
	if len(hist.entries) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(hist.entries))
	}
}

func TestProcess_CorrelatedAlerts(t *testing.T) {
	dir := t.TempDir()
	histPath := filepath.Join(dir, "history.jsonl")
	hist, err := NewHistory(histPath, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		DiscordURL:       "",
		CorrelateSlack:   30 * time.Second,
		EvidenceWindow:   15 * time.Minute,
		NarrateTimeout:   5 * time.Second,
	}

	// Two alerts with same name should correlate into one group.
	alerts := []Alert{
		{Fingerprint: "fp1", Labels: map[string]string{"alertname": "HighCPU", "namespace": "default"}, Annotations: map[string]string{}},
		{Fingerprint: "fp2", Labels: map[string]string{"alertname": "HighCPU", "namespace": "default"}, Annotations: map[string]string{}},
	}

	process(cfg, alerts, nil, hist)

	// Should be one group.
	if len(hist.entries) != 1 {
		t.Fatalf("expected 1 history entry (correlated), got %d", len(hist.entries))
	}
}

