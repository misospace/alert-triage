package main

import (
	"strings"
	"testing"
	"time"
)

// The LiteLLM alert is the case that misled the model in production: the word
// "Deployment" reads as a Kubernetes Deployment, when the subject is a routing
// target named by a label the model never used to see.
func liteLLMAlert() Alert {
	return Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname":          "LiteLLMDeploymentOutage",
			"cluster":            "main",
			"litellm_model_name": "self-hosted",
			"prometheus":         "observability/kube-prometheus-stack",
			"severity":           "warning",
		},
		Annotations: map[string]string{
			"summary": "LiteLLM self-hosted out of rotation (deployment_state >= 2)",
		},
		Fingerprint: "llm-1",
	}
}

func TestEvidenceExposesDisambiguatingLabels(t *testing.T) {
	g := Correlate([]Alert{liteLLMAlert()}, nil, DefaultSignatures(), time.Minute)[0]
	out := renderEvidence(Report{Group: g, Enrichment: Enrichment{Scope: "cluster-wide"}})

	if !strings.Contains(out, "litellm_model_name=self-hosted") {
		t.Errorf("the label naming the real subject is missing:\n%s", out)
	}
	if !strings.Contains(out, "cluster=main") {
		t.Error("context labels not rendered")
	}
}

func TestEvidenceOmitsBoilerplateLabels(t *testing.T) {
	g := Correlate([]Alert{liteLLMAlert()}, nil, DefaultSignatures(), time.Minute)[0]
	out := renderEvidence(Report{Group: g})

	for _, noise := range []string{"prometheus=observability", "severity=warning", "alertname="} {
		if strings.Contains(out, noise) {
			t.Errorf("boilerplate label %q should not be rendered", noise)
		}
	}
}

func TestEmptyEvidenceRendersAsFindings(t *testing.T) {
	g := Correlate([]Alert{liteLLMAlert()}, nil, DefaultSignatures(), time.Minute)[0]
	out := renderEvidence(Report{Group: g, Enrichment: Enrichment{Scope: "cluster-wide"}})

	// Absence must read as a ruled-out cause, never as missing data.
	for _, want := range []string{"all nodes Ready", "no warning events", "no Flux reconciles or failures in the window"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected explicit negative %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "No supporting cluster evidence") {
		t.Error("evidence block still implies nothing was checked")
	}
}

// Ambient context must be fenced off from findings. A digest once ended with
// "dozens of PVs are attached to node eula, so if any model backends run there
// it is worth verifying" - a coincidence offered as a cause.
func TestAmbientContextIsFencedOff(t *testing.T) {
	g := Correlate([]Alert{liteLLMAlert()}, nil, DefaultSignatures(), time.Minute)[0]
	out := renderEvidence(Report{Group: g, Enrichment: Enrichment{
		Scope:   "cluster-wide",
		Ambient: []string{"VolumeFailedDelete PersistentVolume/pvc-123: still attached to node eula"},
	}})

	if !strings.Contains(out, "BACKGROUND") {
		t.Fatalf("ambient items must be under their own heading:\n%s", out)
	}
	if !strings.Contains(out, "NOT known to involve the alert") {
		t.Error("ambient section must disclaim relevance")
	}
	idx := strings.Index(out, "BACKGROUND")
	if strings.Index(out, "node eula") < idx {
		t.Error("ambient item leaked into the findings section")
	}
}

// A single stuck condition emits the same event against dozens of objects.
// A digest once listed 43 VolumeFailedDelete lines and 157 Flux reconciles for
// an alert about an upstream API quota.
func TestRepeatedEventsCollapse(t *testing.T) {
	var items []string
	for i := 0; i < 43; i++ {
		items = append(items, "VolumeFailedDelete x43 on PersistentVolume (e.g. pvc-2b8b): still attached to node eula")
	}
	got := capList(dedupe(items), 5)
	if len(got) != 1 {
		t.Fatalf("identical events must collapse to one line, got %d", len(got))
	}
	if !strings.Contains(got[0], "x43") {
		t.Errorf("collapsed line should carry the count, got %q", got[0])
	}
}

// TestAmbientBackendStateDoesNotClaimNoLines is the render-level regression
// the reviewer called out: when the no-subject fallback fires, the backend did
// return lines — they are deliberately routed to Ambient. The state is
// "ambient", and neither the model prompt nor the chat may print the "empty"
// finding ("returned no lines for this window") beside the very lines we
// routed to BACKGROUND.
func TestAmbientBackendStateDoesNotClaimNoLines(t *testing.T) {
	g := Group{
		Key:        "sig-amb",
		Namespaces: []string{"ns1"},
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "KubeJobFailed", "namespace": "ns1"}}},
	}
	en := Enrichment{
		BackendState: "ambient",
		Ambient:      []string{"(ambient, namespace-wide) namespace chatter line"},
	}

	model := renderEvidence(Report{Group: g, Enrichment: en})
	if strings.Contains(model, "returned no lines for this window") {
		t.Errorf("model prompt: must not claim the backend returned no lines when namespace-wide lines were returned:\n%s", model)
	}
	if !strings.Contains(model, "namespace chatter line") {
		t.Errorf("model prompt: the namespace-wide line must be rendered (under BACKGROUND):\n%s", model)
	}

	// Ambient never reaches Discord, so the chat only has to avoid the false
	// "no lines" claim, not to carry the line itself.
	discord := discordDescription(&Config{}, Report{Group: g, Enrichment: en})
	if strings.Contains(discord, "returned no lines for this window") {
		t.Errorf("discord: must not claim the backend returned no lines when namespace-wide lines were returned:\n%s", discord)
	}

	// And the true empty case still renders the negative, scoped to the subject.
	en2 := Enrichment{BackendState: "empty"}
	if !strings.Contains(renderEvidence(Report{Group: g, Enrichment: en2}), "returned no lines for this subject in the window") {
		t.Error("genuinely empty state must still render the explicit negative")
	}
}

func TestParseTriageTolerance(t *testing.T) {
	want := `{"narrative":"n","fix_location":"git","what_to_change":"w","confidence":"high"}`
	for name, raw := range map[string]string{
		"bare":       want,
		"fenced":     "```json\n" + want + "\n```",
		"prefixed":   "Here is my answer:\n" + want,
		"suffixed":   want + "\n\nHope that helps.",
		"whitespace": "\n\n  " + want + "  \n",
	} {
		got, ok := parseTriage(raw)
		if !ok {
			t.Errorf("%s: expected a successful parse, got ok=false", name)
		}
		if got.FixLocation != "git" || got.Narrative != "n" {
			t.Errorf("%s: parsed as %+v", name, got)
		}
	}
}

func TestParseTriageRejectsUnknownLocation(t *testing.T) {
	got, _ := parseTriage(`{"narrative":"n","fix_location":"somewhere-else"}`)
	if got.FixLocation != "unknown" {
		t.Errorf("unrecognised location must fall back to unknown, got %q", got.FixLocation)
	}
}

// A model that ignores the format must still yield a readable digest.
func TestParseTriageKeepsProseOnFailure(t *testing.T) {
	got, ok := parseTriage("The job is stuck because the volume never mounted.")
	if ok {
		t.Errorf("prose reply must not parse as structured, got ok=true")
	}
	if got.Narrative == "" || got.FixLocation != "unknown" {
		t.Errorf("prose reply should survive as the narrative, got %+v", got)
	}
	if got.Actionable() {
		t.Error("an unparsed reply must never be treated as actionable")
	}
}
