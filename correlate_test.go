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

// Claiming used to compare fingerprints, so alerts sharing one — copies, or a
// replayed payload where every fingerprint is empty — could be marked claimed
// without joining a group, and then went unreported entirely.
func TestAlertExcludedForNoOverlapIsStillReported(t *testing.T) {
	strip := func(a Alert) Alert { a.Fingerprint = ""; return a }
	alerts := []Alert{
		strip(alert("A", "llm", "warning", 0)),
		strip(alert("B", "llm", "warning", time.Minute)),
		strip(alert("C", "llm", "warning", 6*time.Hour)),
	}
	groups := Correlate(alerts, nil, DefaultSignatures(), 5*time.Minute)

	seen := map[string]int{}
	for _, g := range groups {
		for _, a := range g.Alerts {
			seen[a.name()]++
		}
	}
	for _, name := range []string{"A", "B", "C"} {
		if seen[name] != 1 {
			t.Errorf("%s appeared in %d groups, want exactly 1", name, seen[name])
		}
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
	if got := g.Title(); got != "[default] A + 1 more" {
		t.Errorf("want '[default] A + 1 more', got %q", got)
	}
}

// Regression: the node signature once triggered on any alert whose text merely
// contained "node" (KubePodNotReady, CephNodeDiskspaceWarning) and then scoped
// to everything, fusing an entire window of unrelated alerts into one incident.
// Replays the shape of a real 24h window.
func TestNoSignatureSwallowsUnrelatedAlerts(t *testing.T) {
	alerts := []Alert{
		alert("KubePodNotReady", "media", "warning", 0),
		alert("CephNodeDiskspaceWarning", "observability", "warning", time.Minute),
		alert("etcdDatabaseHighFragmentationRatio", "kube-system", "warning", time.Minute),
		alert("TalosUpgradeStuck", "kube-tools", "warning", 2*time.Minute),
		alert("LiteLLMDeploymentOutage", "", "warning", 2*time.Minute),
	}
	groups := Correlate(alerts, nil, DefaultSignatures(), 5*time.Minute)

	for _, g := range groups {
		if len(g.Alerts) > 2 {
			t.Errorf("group %s fused %d unrelated alerts: %s", g.Key, len(g.Alerts), g.Title())
		}
	}
	if len(groups) < 4 {
		t.Errorf("expected these alerts to stay mostly separate, got %d groups", len(groups))
	}
}

// A node signature must key on the node label, not on the word "node".
func TestNodeSignatureScopesToItsNode(t *testing.T) {
	a := alert("KubeNodeNotReady", "", "critical", 0, "node not ready")
	a.Labels["node"] = "node-a"
	b := alert("KubePodCrashLooping", "llm", "warning", time.Minute)
	b.Labels["node"] = "node-a"
	c := alert("KubePodCrashLooping", "media", "warning", time.Minute)
	c.Labels["node"] = "node-b"

	groups := Correlate([]Alert{a, b, c}, nil, DefaultSignatures(), 5*time.Minute)
	g := groupFor(t, groups, a.Fingerprint)
	if g.Key != "signature/node" {
		t.Fatalf("want signature/node, got %s", g.Key)
	}
	if len(g.Alerts) != 2 {
		t.Errorf("want only same-node alerts grouped, got %d", len(g.Alerts))
	}
	for _, m := range g.Alerts {
		if m.Fingerprint == c.Fingerprint {
			t.Error("alert from a different node was pulled in")
		}
	}
}

// The same alert across namespaces is one story about a shared cause.
func TestSameAlertAcrossNamespacesGroups(t *testing.T) {
	var alerts []Alert
	for i, ns := range []string{"media", "downloads", "storage", "llm"} {
		alerts = append(alerts, alert("KubeHpaMaxedOut", ns, "warning", time.Duration(i)*time.Minute))
	}
	groups := Correlate(alerts, nil, DefaultSignatures(), 5*time.Minute)
	if len(groups) != 1 {
		t.Fatalf("want 1 group for one alert across namespaces, got %d", len(groups))
	}
	if groups[0].Key != "alert/KubeHpaMaxedOut" {
		t.Errorf("want alert/KubeHpaMaxedOut, got %s", groups[0].Key)
	}
}

// Regression: alerts from different clusters must never fuse into one group.
// Namespace names collide across clusters (kube-system, observability, etc.)
// so the cluster label must be part of grouping identity.
func TestDifferentClustersStaySeparate(t *testing.T) {
	mk := func(name, ns, cluster string) Alert {
		return Alert{
			Status: "firing",
			Labels: map[string]string{
				"alertname": name,
				"namespace": ns,
				"cluster":   cluster,
				"severity":  "warning",
			},
			Annotations: map[string]string{},
			StartsAt:    base,
			Fingerprint: cluster + "/" + name,
		}
	}

	alerts := []Alert{
		// Cluster "primary" — two alerts that would group by namespace
		mk("KubePodCrashLooping", "kube-system", "primary"),
		mk("KubeDeploymentReplicasMismatch", "kube-system", "primary"),
		// Cluster "utility" — same namespace name, different cluster
		mk("KubePodCrashLooping", "kube-system", "utility"),
		mk("KubeDeploymentReplicasMismatch", "kube-system", "utility"),
	}

	groups := Correlate(alerts, nil, DefaultSignatures(), 5*time.Minute)

	// Check that no group contains alerts from both clusters.
	for _, g := range groups {
		clusters := map[string]bool{}
		for _, a := range g.Alerts {
			clusters[a.Labels["cluster"]] = true
		}
		if len(clusters) > 1 {
			t.Errorf("group %s fused alerts from multiple clusters: %v", g.Key, clusters)
		}
	}

	// Each cluster should have its own group(s).
	primaryGroups := 0
	utilityGroups := 0
	for _, g := range groups {
		if g.Cluster == "primary" {
			primaryGroups++
		} else if g.Cluster == "utility" {
			utilityGroups++
		}
	}
	if primaryGroups < 1 {
		t.Error("expected at least one group for cluster 'primary'")
	}
	if utilityGroups < 1 {
		t.Error("expected at least one group for cluster 'utility'")
	}
}

// Group.Signature must include the cluster so history dedup does not merge
// identical incidents from different clusters.
func TestSignatureIncludesCluster(t *testing.T) {
	a := alert("KubePodCrashLooping", "kube-system", "warning", 0)
	a.Labels["cluster"] = "primary"
	b := alert("KubePodCrashLooping", "kube-system", "warning", 0)
	b.Labels["cluster"] = "utility"

	gA := Group{Cluster: "primary", Key: "single/KubePodCrashLooping", Alerts: []Alert{a}}
	gB := Group{Cluster: "utility", Key: "single/KubePodCrashLooping", Alerts: []Alert{b}}

	if sigA, sigB := gA.Signature(), gB.Signature(); sigA == sigB {
		t.Errorf("signatures for different clusters must differ; got %s for both", sigA)
	}
}

// TestLabelBasedGrouping verifies that alerts from the same subsystem (shared
// job or service label) but with different names, namespaces, and nodes are
// grouped together — and that unrelated subsystems are NOT fused.
func TestLabelBasedGrouping(t *testing.T) {
	// Three LiteLLM alerts: different names, different namespaces, no shared node.
	// They share the "job" label, so they should be one group.
	liteAuth := alert("LiteLLMAuthOrQuotaFailures", "llm-auth", "critical", 0)
	liteAuth.Labels["job"] = "litellm"
	liteOutage := alert("LiteLLMDeploymentOutage", "llm-inference", "critical", time.Minute)
	liteOutage.Labels["job"] = "litellm"
	liteFailover := alert("LiteLLMModelFailover", "llm-routing", "warning", 2*time.Minute)
	liteFailover.Labels["job"] = "litellm"

	// Unrelated alerts that happen to fire in the same window.
	// Different job label — must NOT fuse with LiteLLM group.
	prometheus := alert("PrometheusTargetDown", "monitoring", "warning", time.Minute)
	prometheus.Labels["job"] = "prometheus"

	// No shared label at all — singleton.
	orphan := alert("RandomAlert", "default", "info", 3*time.Minute)

	alerts := []Alert{liteAuth, liteOutage, liteFailover, prometheus, orphan}
	groups := Correlate(alerts, nil, DefaultSignatures(), 5*time.Minute)

	// LiteLLM alerts should be in one group.
	liteGroup := groupFor(t, groups, liteAuth.Fingerprint)
	if len(liteGroup.Alerts) != 3 {
		t.Errorf("LiteLLM group has %d alerts, want 3", len(liteGroup.Alerts))
	}

	// Prometheus alert must be in its own group (different job).
	promGroup := groupFor(t, groups, prometheus.Fingerprint)
	if len(promGroup.Alerts) != 1 {
		t.Errorf("Prometheus group has %d alerts, want 1 (should not fuse with LiteLLM)", len(promGroup.Alerts))
	}

	// Orphan must be a singleton.
	orphanGroup := groupFor(t, groups, orphan.Fingerprint)
	if len(orphanGroup.Alerts) != 1 {
		t.Errorf("Orphan group has %d alerts, want 1", len(orphanGroup.Alerts))
	}

	// Total: 3 groups (LiteLLM, Prometheus, Orphan).
	if got := len(groups); got != 3 {
		t.Errorf("got %d groups, want 3", got)
	}
}

// TestServiceLabelGrouping verifies grouping on the "service" label when
// "job" is not present.
func TestServiceLabelGrouping(t *testing.T) {
	a := alert("HighErrorRate", "frontend", "critical", 0)
	a.Labels["service"] = "checkout"
	b := alert("HighLatency", "frontend", "warning", time.Minute)
	b.Labels["service"] = "checkout"
	c := alert("PodCrashLooping", "backend", "warning", 2*time.Minute)
	c.Labels["service"] = "inventory"

	alerts := []Alert{a, b, c}
	groups := Correlate(alerts, nil, DefaultSignatures(), 5*time.Minute)

	checkoutGroup := groupFor(t, groups, a.Fingerprint)
	if len(checkoutGroup.Alerts) != 2 {
		t.Errorf("checkout service group has %d alerts, want 2", len(checkoutGroup.Alerts))
	}

	inventoryGroup := groupFor(t, groups, c.Fingerprint)
	if len(inventoryGroup.Alerts) != 1 {
		t.Errorf("inventory service group has %d alerts, want 1", len(inventoryGroup.Alerts))
	}
}
