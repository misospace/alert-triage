package main

import (
	"testing"
	"time"
)

var base = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

func alert(name, ns, sev string, offset time.Duration, ann ...string) Alert {
	a := Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": name, "namespace": ns, "severity": sev},
		Annotations: map[string]string{},
		StartsAt:    base.Add(offset),
		Fingerprint: name + "/" + ns + "/" + offset.String(),
	}
	if len(ann) > 0 {
		a.Annotations["summary"] = ann[0]
	}
	return a
}

func groupFor(t *testing.T, groups []Group, fingerprint string) Group {
	t.Helper()
	for _, g := range groups {
		for _, a := range g.Alerts {
			if a.Fingerprint == fingerprint {
				return g
			}
		}
	}
	t.Fatalf("no group contains %s", fingerprint)
	return Group{}
}

func TestCorrelateEmpty(t *testing.T) {
	if got := Correlate(nil, nil, DefaultSignatures(), time.Minute); got != nil {
		t.Fatalf("want nil, got %v", got)
	}
}

func TestSignatureGroupsStorageAcrossNamespaces(t *testing.T) {
	alerts := []Alert{
		alert("NFSMountFailed", "media", "critical", 0, "nfs export unreachable"),
		alert("PodCrashLooping", "downloads", "warning", time.Minute, "volume mount failed"),
		alert("KubePersistentVolumeErrors", "llm", "warning", 2*time.Minute, "pvc pending"),
		alert("LiteLLMHighLatency", "llm", "warning", time.Minute, "p99 latency high"),
	}
	groups := Correlate(alerts, nil, DefaultSignatures(), 5*time.Minute)

	storage := groupFor(t, groups, alerts[0].Fingerprint)
	if len(storage.Alerts) != 3 {
		t.Fatalf("want 3 storage alerts grouped, got %d (%s)", len(storage.Alerts), storage.Key)
	}
	if storage.Key != "signature/nfs" {
		t.Errorf("want signature/nfs, got %s", storage.Key)
	}

	// The unrelated latency alert must not be swept into the storage story.
	latency := groupFor(t, groups, alerts[3].Fingerprint)
	if latency.Key == storage.Key {
		t.Error("unrelated alert absorbed into storage group")
	}
}

func TestNodeBeatsNamespace(t *testing.T) {
	a := alert("DiskPressure", "llm", "warning", 0)
	b := alert("PodEvicted", "media", "warning", time.Minute)
	nodeOf := map[string]string{a.Fingerprint: "node-a", b.Fingerprint: "node-a"}

	groups := Correlate([]Alert{a, b}, nodeOf, nil, 5*time.Minute)
	if len(groups) != 1 {
		t.Fatalf("want 1 node group, got %d", len(groups))
	}
	if groups[0].Key != "node/node-a" {
		t.Errorf("want node/node-a, got %s", groups[0].Key)
	}
	if groups[0].Node != "node-a" {
		t.Errorf("want node attribution, got %q", groups[0].Node)
	}
}

func TestNamespaceGroupingRequiresOverlap(t *testing.T) {
	a := alert("A", "llm", "warning", 0)
	b := alert("B", "llm", "warning", 6*time.Hour)

	groups := Correlate([]Alert{a, b}, nil, nil, time.Minute)
	if len(groups) != 2 {
		t.Fatalf("alerts hours apart must not group; got %d groups", len(groups))
	}
}

func TestSingletonIsIsolated(t *testing.T) {
	a := alert("Lonely", "llm", "warning", 0)
	groups := Correlate([]Alert{a}, nil, DefaultSignatures(), time.Minute)
	if len(groups) != 1 || groups[0].Key != "single/Lonely" {
		t.Fatalf("want single/Lonely, got %+v", groups)
	}
}

func TestEveryAlertLandsInExactlyOneGroup(t *testing.T) {
	alerts := []Alert{
		alert("NFSMountFailed", "media", "critical", 0, "nfs unreachable"),
		alert("PodCrashLooping", "downloads", "warning", time.Minute, "mount failed"),
		alert("CoreDNSDown", "kube-system", "critical", 0, "dns failing"),
		alert("HTTPTimeout", "llm", "warning", time.Minute, "connection timeout"),
		alert("Random", "utility", "info", 30*time.Second),
	}
	groups := Correlate(alerts, nil, DefaultSignatures(), 5*time.Minute)

	seen := map[string]int{}
	for _, g := range groups {
		for _, a := range g.Alerts {
			seen[a.Fingerprint]++
		}
	}
	for _, a := range alerts {
		if seen[a.Fingerprint] != 1 {
			t.Errorf("%s appeared in %d groups, want exactly 1", a.Labels["alertname"], seen[a.Fingerprint])
		}
	}
}

func TestNodeSignatureDoesNotAbsorbUnrelatedAlerts(t *testing.T) {
	// Regression: bare "node" substring must not trigger the node signature.
	// An alert like NodeFilesystemSpaceFillingUp or a summary mentioning a
	// hostname such as "node-03" should NOT sweep unrelated alerts into a
	// signature/node group.
	alerts := []Alert{
		alert("NodeFilesystemSpaceFillingUp", "llm", "warning", 0, "disk usage high on node-03"),
		alert("PodCrashLooping", "media", "warning", time.Minute, "OOM killed"),
		alert("HTTPTimeout", "utility", "info", 30*time.Second, "connection timeout"),
	}
	groups := Correlate(alerts, nil, DefaultSignatures(), 5*time.Minute)

	for _, g := range groups {
		if g.Key == "signature/node" {
			t.Fatalf("node signature must not trigger on bare 'node' substring; got group %s with alerts: %v",
				g.Key, func() []string {
					names := make([]string, len(g.Alerts))
					for i, a := range g.Alerts {
						names[i] = a.name()
					}
					return names
				}())
		}
	}

	// Verify unrelated alerts are not grouped together.
	seen := map[string][]string{}
	for _, g := range groups {
		for _, a := range g.Alerts {
			seen[g.Key] = append(seen[g.Key], a.name())
		}
	}
	// NodeFilesystemSpaceFillingUp and PodCrashLooping must be in separate groups.
	for key, names := range seen {
		if len(names) > 1 {
			hasNodeFS := false
			hasPodCrash := false
			for _, n := range names {
				if n == "NodeFilesystemSpaceFillingUp" {
					hasNodeFS = true
				}
				if n == "PodCrashLooping" {
					hasPodCrash = true
				}
			}
			if hasNodeFS && hasPodCrash {
				t.Errorf("unrelated alerts merged into group %s: %v", key, names)
			}
		}
	}
}

func TestNodeSignatureMatchesRealNodeFailure(t *testing.T) {
	// Verify the node signature still fires on actual node-unhealth signals.
	alerts := []Alert{
		alert("KubeNodeNotReady", "kube-system", "critical", 0, "node not ready"),
		alert("PodEvicted", "llm", "warning", time.Minute, "evicted due to pressure"),
	}
	groups := Correlate(alerts, nil, DefaultSignatures(), 5*time.Minute)

	var nodeGroup *Group
	for i, g := range groups {
		if g.Key == "signature/node" {
			nodeGroup = &groups[i]
			break
		}
	}
	if nodeGroup == nil {
		t.Fatal("node signature should trigger on KubeNodeNotReady")
	}
	if len(nodeGroup.Alerts) < 1 {
		t.Fatal("node group should contain at least the triggering alert")
	}
}

func TestSignatureIsStableAcrossFirings(t *testing.T) {
	mk := func(offset time.Duration) Group {
		return Correlate([]Alert{
			alert("A", "llm", "warning", offset),
			alert("B", "llm", "warning", offset+time.Minute),
		}, nil, nil, 5*time.Minute)[0]
	}
	if a, b := mk(0).Signature(), mk(48*time.Hour).Signature(); a != b {
		t.Errorf("signature changed across firings: %s vs %s", a, b)
	}
}

func TestSeverityTakesMostUrgent(t *testing.T) {
	g := Group{Alerts: []Alert{
		alert("A", "llm", "info", 0),
		alert("B", "llm", "critical", 0),
		alert("C", "llm", "warning", 0),
	}}
	if got := g.Severity(); got != "critical" {
		t.Errorf("want critical, got %s", got)
	}
}

func TestTitleSummarisesMultiple(t *testing.T) {
	g := Group{Alerts: []Alert{alert("A", "x", "warning", 0), alert("B", "x", "warning", 0)}}
	if got := g.Title(); got != "A +1 more" {
		t.Errorf("want 'A +1 more', got %q", got)
	}
}
