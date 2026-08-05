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
