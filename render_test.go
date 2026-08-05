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
	for _, want := range []string{"all nodes Ready", "no warning events", "recent deploy is unlikely"} {
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
