package main

import (
	"math"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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
// must kill the proposal. scaleWithinBounds skips the overflowed candidate and
// hands the current value back, so the must-be-larger guard drops the
// proposal; encodeQuantity refusing a non-finite value is the last line of
// defence behind it. No diff is emitted and no "+InfEi" reaches the manifest.
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
// byte count. scaleWithinBounds still returns an infinite current unchanged;
// the proposal path stops earlier, at the decoder, but the passthrough is what
// keeps the must-be-larger guard from comparing past such a value.
func TestProposeRefusesMemoryThatOverflowsOnDecode(t *testing.T) {
	if v, ok := decodeQuantity(strings.Repeat("9", 300) + "Ei"); ok {
		t.Fatalf("expected the overflowing value to be rejected, got %v ok=%v", v, ok)
	}
	if got := scaleWithinBounds(math.Inf(1), maxMultiplier); !math.IsInf(got, 1) {
		t.Fatalf("expected +Inf passed through unchanged, got %v", got)
	}
	manifest := strings.Replace(multiContainerManifest,
		"memory: 64Mi", "memory: "+strings.Repeat("9", 300)+"Ei", 1)
	triage := Triage{FixLocation: "git", Confidence: "high"}
	if diff := Propose(oomAlerts(), triage, "k8s/web.yaml", manifest); diff != "" {
		t.Fatalf("expected no proposal when the value overflows to infinity, got %q", diff)
	}
}

// fourSpaceManifest is a valid manifest whose indentation differs from the
// two-space form yaml.v3 re-encodes to. Every indented line — before and
// after the memory scalar — is a difference against the re-encoded text, so
// a generator that emits only the first changed region produces a
// formatting-only patch that applies cleanly with no memory increase (#274).
const fourSpaceManifest = `apiVersion: apps/v1
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
`

// applyProposed applies a proposal's own diff the way the PR write arm does.
func applyProposed(t *testing.T, manifest, diff string) string {
	t.Helper()
	patched, ok := applyDiff(manifest, diff)
	if !ok {
		t.Fatalf("applyDiff rejected the emitted diff:\n%s", diff)
	}
	return patched
}

// assertOneChangedLine requires patched to differ from original on exactly
// one line — every other byte, including indentation, quoting, comments and
// any further document, must survive untouched — and returns that line.
func assertOneChangedLine(t *testing.T, original, patched string) (int, []string) {
	t.Helper()
	o := strings.Split(original, "\n")
	p := strings.Split(patched, "\n")
	if len(o) != len(p) {
		t.Fatalf("patched has %d lines, original has %d", len(p), len(o))
	}
	changed := -1
	for i := range o {
		if o[i] != p[i] {
			if changed >= 0 {
				t.Fatalf("more than one line changed:\nline %d: %q -> %q\nline %d: %q -> %q",
					changed, o[changed], p[changed], i, o[i], p[i])
			}
			changed = i
		}
	}
	if changed < 0 {
		t.Fatal("patched content is identical to the original")
	}
	return changed, p
}

// containerMemory reads spec.template.spec.containers[<name>].resources.<block>.memory.
func containerMemory(t *testing.T, manifest, container, block string) string {
	t.Helper()
	var root map[string]any
	if err := yaml.Unmarshal([]byte(manifest), &root); err != nil {
		t.Fatalf("manifest does not parse: %v", err)
	}
	podSpec, _ := root["spec"].(map[string]any)
	tpl, _ := podSpec["template"].(map[string]any)
	tplSpec, _ := tpl["spec"].(map[string]any)
	list, _ := tplSpec["containers"].([]any)
	for _, c := range list {
		cm, _ := c.(map[string]any)
		if cm["name"] != container {
			continue
		}
		res, _ := cm["resources"].(map[string]any)
		blk, _ := res[block].(map[string]any)
		m, _ := blk["memory"].(string)
		return m
	}
	return ""
}

// The #274 regression: a four-space manifest used to yield a nonempty
// formatting-only diff (the first difference is metadata.name, far above the
// memory field) that applyDiff accepted, so the write arm could open a
// "memory fix" PR that changed no memory. Applying the proposal must now
// raise the api limit while leaving every other line byte-identical.
func TestProposeRaisesMemoryWhenReencodingWouldReshuffleFormatting(t *testing.T) {
	triage := Triage{FixLocation: "git", Confidence: "high"}
	diff := Propose(oomAlerts(), triage, "apps/web.yaml", fourSpaceManifest)
	if diff == "" {
		t.Fatalf("expected a proposal for a four-space manifest")
	}
	patched := applyProposed(t, fourSpaceManifest, diff)
	changed, lines := assertOneChangedLine(t, fourSpaceManifest, patched)
	if !strings.Contains(lines[changed], "memory: 128Mi") {
		t.Fatalf("the single changed line is not the memory increase: %q", lines[changed])
	}
	if got := containerMemory(t, patched, "api", "limits"); got != "128Mi" {
		t.Errorf("api limits.memory = %q, want 128Mi", got)
	}
	if got := containerMemory(t, patched, "api", "requests"); got != "64Mi" {
		t.Errorf("api requests.memory = %q, want 64Mi untouched", got)
	}
	if got := containerMemory(t, patched, "sidecar", "limits"); got != "32Mi" {
		t.Errorf("sidecar limits.memory = %q, want 32Mi untouched", got)
	}
}

// Separated differences before and after the target scalar, this time with
// the target itself quoted and carrying a trailing comment: the rewrite must
// keep the quoting style and the comment and raise only the value.
func TestProposeRaisesQuotedMemoryWithForeignFormatting(t *testing.T) {
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
    name: web
spec:
    template:
        spec:
            containers:
                - name: api
                  resources:
                      limits:
                          memory: "64Mi" # lowered during the drill
                      requests:
                          memory: '64Mi'
`
	triage := Triage{FixLocation: "git", Confidence: "high"}
	diff := Propose(oomAlerts(), triage, "apps/web.yaml", manifest)
	if diff == "" {
		t.Fatalf("expected a proposal")
	}
	patched := applyProposed(t, manifest, diff)
	changed, lines := assertOneChangedLine(t, manifest, patched)
	if want := `                          memory: "128Mi" # lowered during the drill`; lines[changed] != want {
		t.Fatalf("changed line = %q, want %q", lines[changed], want)
	}
	if got := containerMemory(t, patched, "api", "requests"); got != "64Mi" {
		t.Errorf("api requests.memory = %q, want 64Mi untouched", got)
	}
}

// A Kubernetes manifest may carry several YAML documents; the proposal may
// only rewrite the memory scalar in the first and must leave every later
// document byte-identical rather than dropping them the way a re-encode of
// the first parsed document would.
func TestProposePreservesAdditionalDocuments(t *testing.T) {
	manifest := multiContainerManifest + "---\napiVersion: v1\nkind: Service\nmetadata:\n  name: web\nspec:\n  selector:\n    app: web\n"
	triage := Triage{FixLocation: "git", Confidence: "high"}
	diff := Propose(oomAlerts(), triage, "k8s/web.yaml", manifest)
	if diff == "" {
		t.Fatalf("expected a proposal")
	}
	patched := applyProposed(t, manifest, diff)
	changed, lines := assertOneChangedLine(t, manifest, patched)
	if !strings.Contains(lines[changed], "memory: 128Mi") {
		t.Fatalf("the single changed line is not the memory increase: %q", lines[changed])
	}
	if !strings.Contains(patched, "kind: Service") {
		t.Fatalf("the second document was not preserved:\n%s", patched)
	}
}

// CRLF line endings must survive in place: the rewrite is line-local, so a
// CRLF manifest keeps its carriage returns and still gets the bump.
func TestProposeRaisesMemoryInCRLFManifest(t *testing.T) {
	manifest := strings.ReplaceAll(multiContainerManifest, "\n", "\r\n")
	triage := Triage{FixLocation: "git", Confidence: "high"}
	diff := Propose(oomAlerts(), triage, "k8s/web.yaml", manifest)
	if diff == "" {
		t.Fatalf("expected a proposal for a CRLF manifest")
	}
	patched := applyProposed(t, manifest, diff)
	changed, lines := assertOneChangedLine(t, manifest, patched)
	if !strings.Contains(lines[changed], "memory: 128Mi") {
		t.Fatalf("the single changed line is not the memory increase: %q", lines[changed])
	}
	if !strings.Contains(patched, "\r\n") {
		t.Fatalf("CRLF endings were not preserved:\n%q", patched)
	}
}

// yaml.v3 counts columns in runes while text is indexed in bytes: a flow
// line with multi-byte characters before the memory token used to offset
// the recorded column by one byte per rune and silently refuse a valid
// manifest. The rewrite must land on the token and touch nothing else.
func TestProposeRaisesMemoryOnLineWithMultiByteCharacters(t *testing.T) {
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers: [{name: café-api, resources: {limits: {memory: 64Mi}, requests: {memory: 64Mi}}}]
`
	triage := Triage{FixLocation: "git", Confidence: "high"}
	diff := Propose(oomAlerts(), triage, "apps/web.yaml", manifest)
	if diff == "" {
		t.Fatalf("expected a proposal despite multi-byte characters before the token")
	}
	patched := applyProposed(t, manifest, diff)
	changed, lines := assertOneChangedLine(t, manifest, patched)
	if !strings.Contains(lines[changed], "memory: 128Mi") {
		t.Fatalf("the single changed line is not the memory increase: %q", lines[changed])
	}
	if got := containerMemory(t, patched, "café-api", "limits"); got != "128Mi" {
		t.Errorf("limits.memory = %q, want 128Mi", got)
	}
	if got := containerMemory(t, patched, "café-api", "requests"); got != "64Mi" {
		t.Errorf("requests.memory = %q, want 64Mi untouched", got)
	}
}

// Scalars whose source text cannot be proven equal to the parsed value at
// the recorded position — a tag, a block scalar, an alias — are refused
// outright instead of being rewritten or re-encoded (#274's fail-closed
// branch: no diff rather than a wrong one).
func TestProposeRefusesScalarItCannotRewriteInPlace(t *testing.T) {
	triage := Triage{FixLocation: "git", Confidence: "high"}
	cases := map[string]string{
		"tagged scalar": strings.Replace(multiContainerManifest,
			"memory: 64Mi", "memory: !!str 64Mi", 1),
		"block scalar": strings.Replace(multiContainerManifest,
			"memory: 64Mi", "memory: |-\n                64Mi", 1),
		"alias value": `defaults: &defaultmem 64Mi
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: api
          resources:
            limits:
              memory: *defaultmem
`,
	}
	for name, manifest := range cases {
		if got := Propose(oomAlerts(), triage, "k8s/web.yaml", manifest); got != "" {
			t.Errorf("%s: expected no proposal, got %q", name, got)
		}
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
