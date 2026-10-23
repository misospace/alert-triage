package main

import (
	"math"
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

// A finite value near math.MaxFloat64 overflows on the first doubled
// candidate; scaleWithinBounds must skip the overflowed candidates and return
// current unchanged rather than hand back +Inf (#255).
func TestScaleWithinBoundsSkipsOverflow(t *testing.T) {
	nearMax, ok := decodeQuantity(strings.Repeat("9", 290) + "Ei")
	if !ok || math.IsInf(nearMax, 0) || math.IsNaN(nearMax) {
		t.Fatalf("fixture must decode to a finite value, got %v ok=%v", nearMax, ok)
	}
	if got := scaleWithinBounds(nearMax, maxMultiplier); got != nearMax {
		t.Fatalf("expected current returned when every candidate overflows, got %v", got)
	}
	if got := scaleWithinBounds(nearMax, 1.5); math.IsInf(got, 0) || math.IsNaN(got) {
		t.Fatalf("expected a finite result, got %v", got)
	}
}

func TestEncodeQuantityRejectsNonFinite(t *testing.T) {
	for _, v := range []float64{math.Inf(1), math.Inf(-1), math.NaN()} {
		if got, ok := encodeQuantity(v); ok || got != "" {
			t.Fatalf("expected no encoding for %v, got %q ok=%v", v, got, ok)
		}
	}
	if got, ok := encodeQuantity(128 * 1024 * 1024); !ok || got != "128Mi" {
		t.Fatalf("expected 128Mi, got %q ok=%v", got, ok)
	}
}

// End to end: a memory value that decodes finite but overflows when doubled
// must kill the proposal, not render "+InfEi" as if it were a real bump.
func TestProposeRefusesOverflowingMemory(t *testing.T) {
	manifest := strings.Replace(multiContainerManifest,
		"memory: 64Mi", "memory: "+strings.Repeat("9", 290)+"Ei", 1)
	triage := Triage{FixLocation: "git", Confidence: "high"}
	diff := Propose(oomAlerts(), triage, "k8s/web.yaml", manifest)
	if diff != "" {
		t.Fatalf("expected no proposal when the bump overflows, got %q", diff)
	}
}

// A larger mantissa still parses finite but decodeQuantity's product with the
// suffix overflows to +Inf, which the proposal guards must also drop rather
// than compare past (NaN-safe: +Inf <= +Inf is true).
func TestProposeRefusesMemoryDecodingToInfinity(t *testing.T) {
	if v, ok := decodeQuantity(strings.Repeat("9", 300) + "Ei"); !ok || !math.IsInf(v, 1) {
		t.Fatalf("fixture must decode to +Inf, got %v ok=%v", v, ok)
	}
	if got := scaleWithinBounds(math.Inf(1), maxMultiplier); !math.IsInf(got, 1) {
		t.Fatalf("expected +Inf passed through unchanged for the not-greater guard, got %v", got)
	}
	manifest := strings.Replace(multiContainerManifest,
		"memory: 64Mi", "memory: "+strings.Repeat("9", 300)+"Ei", 1)
	triage := Triage{FixLocation: "git", Confidence: "high"}
	if diff := Propose(oomAlerts(), triage, "k8s/web.yaml", manifest); diff != "" {
		t.Fatalf("expected no proposal when the value decodes to +Inf, got %q", diff)
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
