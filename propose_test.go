package main

import "testing"

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

func TestProposeRaisesOnlyTheOomKilledContainer(t *testing.T) {
	triage := Triage{FixLocation: "git", Confidence: "high"}
	diff := Propose(triage, "k8s/web.yaml", multiContainerManifest)
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
	if got := Propose(triage, "k8s/web.yaml", multiContainerManifest); got != "" {
		t.Fatalf("expected no proposal for low confidence, got %q", got)
	}
}

func TestProposeRefusesNonGitFixLocation(t *testing.T) {
	triage := Triage{FixLocation: "cluster", Confidence: "high"}
	if got := Propose(triage, "k8s/web.yaml", multiContainerManifest); got != "" {
		t.Fatalf("expected no proposal for non-git fix_location, got %q", got)
	}
}

func TestProposeRefusesEmptyPath(t *testing.T) {
	triage := Triage{FixLocation: "git", Confidence: "high"}
	if got := Propose(triage, "", multiContainerManifest); got != "" {
		t.Fatalf("expected no proposal when path is missing, got %q", got)
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

func contains(s, sub string) bool { return indexOf(s, sub) >= 0 }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
