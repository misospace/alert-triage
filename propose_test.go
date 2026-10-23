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
	// A finite mantissa that only overflows once the suffix is applied must
	// be rejected too: an infinite byte count is not a usable memory limit.
	finiteMantissa := strings.Repeat("9", 291) + "Ei"
	overflowing := []string{
		strings.Repeat("9", 300) + "Ei",
		strings.Repeat("9", 300) + "E",
		finiteMantissa,
	}
	for _, in := range overflowing {
		if got, ok := decodeQuantity(in); ok {
			t.Errorf("decodeQuantity(%q) = %v, true; want rejected", in, got)
		}
	}
}

// An unknown unit falls through to a multiplier of 1, i.e. raw bytes. The set
// of suffixes the regex accepts is pinned by TestDecimalSuffixesMatchMultiplier.
func TestMultiplierUnknownUnit(t *testing.T) {
	if got := multiplier("Qi"); got != 1 {
		t.Fatalf("multiplier(Qi) = %v; want 1", got)
	}
}

// The suffixes decimalRe accepts must be exactly the ones the multiplier
// switch knows: a suffix the regex admits but the switch does not would decode
// a petabyte-scale limit as raw bytes (#204). The accepted set is derived from
// the regex over a candidate list that includes multi-letter suffixes, so
// widening or narrowing the regex fails this test.
func TestDecimalSuffixesMatchMultiplier(t *testing.T) {
	want := map[string]float64{
		"K":  1000,
		"Ki": 1024,
		"M":  1000 * 1000,
		"Mi": 1024 * 1024,
		"G":  1000 * 1000 * 1000,
		"Gi": 1024 * 1024 * 1024,
		"T":  1000 * 1000 * 1000 * 1000,
		"Ti": 1024 * 1024 * 1024 * 1024,
		"P":  1000 * 1000 * 1000 * 1000 * 1000,
		"Pi": 1024 * 1024 * 1024 * 1024 * 1024,
		"E":  1000 * 1000 * 1000 * 1000 * 1000 * 1000,
		"Ei": 1024 * 1024 * 1024 * 1024 * 1024 * 1024,
	}
	derived := map[string]bool{}
	for _, suffix := range candidateSuffixes() {
		if decimalRe.MatchString("1" + suffix) {
			derived[suffix] = true
		}
	}
	if len(derived) != len(want) {
		t.Fatalf("decimalRe accepts %d suffixes %v; want %d", len(derived), derived, len(want))
	}
	for suffix, wantScale := range want {
		if !derived[suffix] {
			t.Errorf("decimalRe rejects %q; want it accepted", suffix)
			continue
		}
		if got := multiplier(suffix); got != wantScale {
			t.Errorf("multiplier(%q) = %v; want %v", suffix, got, wantScale)
			continue
		}
		v, ok := decodeQuantity("1" + suffix)
		if !ok || v != multiplier(suffix) {
			t.Errorf("decodeQuantity(%q) = %v, %v; want %v, true", "1"+suffix, v, ok, multiplier(suffix))
		}
	}
}

// plainRe must stay suffix-free: a suffix it accepted would fall through the
// multiplier switch and decode as raw bytes, the same mis-scale #204 is about.
func TestPlainReAcceptsNoSuffix(t *testing.T) {
	for _, suffix := range candidateSuffixes() {
		if plainRe.MatchString("1" + suffix) {
			t.Errorf("plainRe accepts %q; a suffix there decodes as raw bytes", suffix)
		}
	}
}

// candidateSuffixes lists the suffix strings worth probing against the
// quantity regexes: every ASCII letter run of one or two characters, with and
// without a trailing "i".
func candidateSuffixes() []string {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var out []string
	add := func(s string) {
		out = append(out, s, s+"i")
	}
	for _, a := range letters {
		add(string(a))
	}
	for _, a := range letters {
		for _, b := range letters {
			add(string(a) + string(b))
		}
	}
	return out
}

func TestQuantityRoundTrip(t *testing.T) {
	for _, in := range []string{"128Mi", "2Gi", "512Mi"} {
		v, ok := decodeQuantity(in)
		if !ok {
			t.Fatalf("decodeQuantity(%q) rejected", in)
		}
		got, ok := encodeQuantity(v)
		if !ok || got != in {
			t.Errorf("round trip of %q = %q (ok=%v)", in, got, ok)
		}
	}
	if got, ok := encodeQuantity(999); !ok || got != "999" {
		t.Errorf("encodeQuantity(999) = %q (ok=%v); want 999", got, ok)
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

// A mantissa that parses finite but overflows once the suffix is applied is
// rejected by the decoder (#204), so the proposal guards never see an infinite
// byte count. A caller that handed one over anyway must still have it dropped
// rather than compared past (NaN-safe: +Inf <= +Inf is true).
func TestProposeRefusesMemoryOverflowingToInfinity(t *testing.T) {
	if v, ok := decodeQuantity(strings.Repeat("9", 300) + "Ei"); ok {
		t.Fatalf("expected the overflowing value to be rejected, got %v ok=%v", v, ok)
	}
	if got := scaleWithinBounds(math.Inf(1), maxMultiplier); !math.IsInf(got, 1) {
		t.Fatalf("expected +Inf passed through unchanged for the not-greater guard, got %v", got)
	}
	manifest := strings.Replace(multiContainerManifest,
		"memory: 64Mi", "memory: "+strings.Repeat("9", 300)+"Ei", 1)
	triage := Triage{FixLocation: "git", Confidence: "high"}
	if diff := Propose(oomAlerts(), triage, "k8s/web.yaml", manifest); diff != "" {
		t.Fatalf("expected no proposal when the value overflows to infinity, got %q", diff)
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
