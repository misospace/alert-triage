package main

import (
	"strings"
	"testing"
)

const multiContainerManifest = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: api
          image: ghcr.io/example/api:1.2.3
          resources:
            limits:
              cpu: 250m
              memory: 64Mi
            requests:
              cpu: 100m
              memory: 64Mi
        - name: sidecar
          image: ghcr.io/example/sidecar:9.9.9
          resources:
            limits:
              cpu: 100m
              memory: 32Mi
            requests:
              cpu: 50m
              memory: 32Mi
`

// oomAlerts is a minimal group of alerts that passes the memory-pressure
// gate: one OOMKilled alert.
func oomAlerts() []Alert {
	return []Alert{{Labels: map[string]string{"alertname": "OOMKilled", "severity": "warning"}}}
}

func TestProposeRaisesOnlyTheOomKilledContainer(t *testing.T) {
	triage := Triage{FixLocation: "git", Confidence: "high"}
	diff := Propose(oomAlerts(), triage, "k8s/web.yaml", multiContainerManifest)
	if diff == "" {
		t.Fatalf("expected a non-empty diff")
	}
	if !contains(diff, "api") {
		t.Fatalf("diff did not mention the api container; got %q", diff)
	}
	if contains(diff, "sidecar: 64Mi") {
		// The proposal must not bump the sidecar's identical 32Mi block.
		t.Fatalf("diff touched the sidecar block; got %q", diff)
	}
	// The proposed value must exceed the original 64Mi for the api container.
	if !contains(diff, "128Mi") {
		t.Fatalf("diff did not raise api memory; got %q", diff)
	}
}

func TestProposeRefusesLowConfidence(t *testing.T) {
	triage := Triage{FixLocation: "git", Confidence: "low"}
	if got := Propose(oomAlerts(), triage, "k8s/web.yaml", multiContainerManifest); got != "" {
		t.Fatalf("expected no proposal for low confidence, got %q", got)
	}
}

func TestProposeRefusesNonGitFixLocation(t *testing.T) {
	triage := Triage{FixLocation: "cluster", Confidence: "high"}
	if got := Propose(oomAlerts(), triage, "k8s/web.yaml", multiContainerManifest); got != "" {
		t.Fatalf("expected no proposal for non-git fix_location, got %q", got)
	}
}

func TestProposeRefusesEmptyPath(t *testing.T) {
	triage := Triage{FixLocation: "git", Confidence: "high"}
	if got := Propose(oomAlerts(), triage, "", multiContainerManifest); got != "" {
		t.Fatalf("expected no proposal when path is missing, got %q", got)
	}
}

// The alert-type gate: a high-confidence git triage is not enough on its own;
// the group must actually be about a container killed for memory.
func TestProposeRefusesNonMemoryPressureAlert(t *testing.T) {
	triage := Triage{FixLocation: "git", Confidence: "high"}
	alerts := []Alert{
		{Labels: map[string]string{"alertname": "KubeNodeNotReady", "severity": "critical"}},
	}
	if got := Propose(alerts, triage, "k8s/web.yaml", multiContainerManifest); got != "" {
		t.Fatalf("expected no proposal for a non-memory-pressure alert, got %q", got)
	}
}

func TestProposeRefusesNoAlerts(t *testing.T) {
	triage := Triage{FixLocation: "git", Confidence: "high"}
	if got := Propose(nil, triage, "k8s/web.yaml", multiContainerManifest); got != "" {
		t.Fatalf("expected no proposal when the group carries no alerts, got %q", got)
	}
}

// The gate is a per-alert check over the group: one memory-pressure alert
// among other noise makes the group eligible.
func TestProposeAcceptsGroupContainingOOMKilled(t *testing.T) {
	triage := Triage{FixLocation: "git", Confidence: "high"}
	alerts := []Alert{
		{Labels: map[string]string{"alertname": "KubePodNotReady", "severity": "warning"}},
		{Labels: map[string]string{"alertname": "OOMKilled", "severity": "warning"}},
	}
	diff := Propose(alerts, triage, "k8s/web.yaml", multiContainerManifest)
	if diff == "" {
		t.Fatalf("expected a proposal when the group contains an OOMKilled alert")
	}
}

// ContainerOOMKilled is the kube-state-metrics spelling of the same fault.
func TestProposeAcceptsContainerOOMKilled(t *testing.T) {
	triage := Triage{FixLocation: "git", Confidence: "high"}
	alerts := []Alert{{Labels: map[string]string{"alertname": "ContainerOOMKilled", "severity": "warning"}}}
	diff := Propose(alerts, triage, "k8s/web.yaml", multiContainerManifest)
	if diff == "" {
		t.Fatalf("expected a proposal for ContainerOOMKilled")
	}
}

// KubeStateMetrics rules report the fault through the terminated-reason
// label rather than an alertname of OOMKilled; the gate recognises it.
func TestProposeAcceptsTerminatedReasonLabel(t *testing.T) {
	triage := Triage{FixLocation: "git", Confidence: "high"}
	for _, k := range []string{
		"kube_pod_container_status_terminated_reason",
		"kube_pod_container_status_last_terminated_reason",
	} {
		alerts := []Alert{{Labels: map[string]string{"alertname": "PodTerminated", k: "OOMKilled"}}}
		if got := Propose(alerts, triage, "k8s/web.yaml", multiContainerManifest); got == "" {
			t.Fatalf("expected a proposal for %s=OOMKilled", k)
		}
	}
	// A terminated-reason label with any other reason is not memory pressure.
	alerts := []Alert{{Labels: map[string]string{"alertname": "PodTerminated", "kube_pod_container_status_terminated_reason": "Error"}}}
	if got := Propose(alerts, triage, "k8s/web.yaml", multiContainerManifest); got != "" {
		t.Fatalf("expected no proposal for a non-OOMKilled terminated reason, got %q", got)
	}
}

func TestScaleWithinBounds(t *testing.T) {
	if got := scaleWithinBounds(64*1024*1024, 8); got != 64*1024*1024*2 {
		t.Fatalf("expected 2x bump, got %v", got)
	}
	// If the smallest candidate trips maxMultiplier, we fall back to current.
	if got := scaleWithinBounds(64*1024*1024, 1.5); got != 64*1024*1024 {
		t.Fatalf("expected fallback to current, got %v", got)
	}
}

// Every suffix decimalRe advertises must decode to its Kubernetes-quantity
// scale, decimal P and E included (#204: they used to fall through to 1).
func TestDecodeQuantitySuffixes(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"1Ki", 1024},
		{"1Mi", 1024 * 1024},
		{"1Gi", 1024 * 1024 * 1024},
		{"1Ti", 1024 * 1024 * 1024 * 1024},
		{"1Pi", 1024 * 1024 * 1024 * 1024 * 1024},
		{"1Ei", 1024 * 1024 * 1024 * 1024 * 1024 * 1024},
		{"1K", 1000},
		{"1M", 1000 * 1000},
		{"1G", 1000 * 1000 * 1000},
		{"1T", 1000 * 1000 * 1000 * 1000},
		{"1P", 1000 * 1000 * 1000 * 1000 * 1000},
		{"1E", 1000 * 1000 * 1000 * 1000 * 1000 * 1000},
		{"2P", 2 * 1000 * 1000 * 1000 * 1000 * 1000},
		{"1.5Gi", 1.5 * 1024 * 1024 * 1024},
		{" 64Mi ", 64 * 1024 * 1024},
		{"1024", 1024},
		{"0.5", 0.5},
	}
	for _, c := range cases {
		got, ok := decodeQuantity(c.in)
		if !ok || got != c.want {
			t.Errorf("decodeQuantity(%q) = %v, %v; want %v, true", c.in, got, ok, c.want)
		}
	}
}

func TestDecodeQuantityRejects(t *testing.T) {
	// A 400-digit run matches the regexes but overflows float64, so it must
	// be rejected rather than decoded to +Inf.
	huge := strings.Repeat("9", 400)
	for _, in := range []string{"", "   ", "abc", "Mi", "1Qi", "1mi", "-1Mi", "1.2.3", "1e3", "64MiB", huge, huge + "Mi"} {
		if got, ok := decodeQuantity(in); ok {
			t.Errorf("decodeQuantity(%q) = %v, true; want rejected", in, got)
		}
	}
}

// The fall-through multiplier is unreachable through decodeQuantity as long as
// decimalRe and this switch agree; pin it so a regex widening stays visible.
func TestMultiplierUnknownUnit(t *testing.T) {
	if got := multiplier("Qi"); got != 1 {
		t.Fatalf("multiplier(Qi) = %v; want 1", got)
	}
}

func TestQuantityRoundTrip(t *testing.T) {
	for _, in := range []string{"128Mi", "2Gi", "512Mi"} {
		v, ok := decodeQuantity(in)
		if !ok {
			t.Fatalf("decodeQuantity(%q) rejected", in)
		}
		if got := encodeQuantity(v); got != in {
			t.Errorf("round trip of %q = %q", in, got)
		}
	}
	if got := encodeQuantity(999); got != "999" {
		t.Errorf("encodeQuantity(999) = %q; want 999", got)
	}
}

func contains(s, sub string) bool { return indexOf(s, sub) >= 0 }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
