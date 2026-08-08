package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Alert is one alert as delivered by Alertmanager's webhook (v4 payload).
type Alert struct {
	Status      string            `json:"status"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"startsAt"`
	EndsAt      time.Time         `json:"endsAt"`
	Fingerprint string            `json:"fingerprint"`
}

// Payload is the Alertmanager webhook envelope.
type Payload struct {
	Receiver string  `json:"receiver"`
	Status   string  `json:"status"`
	Alerts   []Alert `json:"alerts"`
}

func (a Alert) name() string      { return a.Labels["alertname"] }
func (a Alert) namespace() string { return alertNamespace(a) }
func (a Alert) severity() string  { return a.Labels["severity"] }
func (a Alert) cluster() string   { return a.Labels["cluster"] }

// identity distinguishes one alert from another. Alertmanager sends a
// fingerprint, but replayed and hand-built payloads routinely omit it, and an
// empty fingerprint shared by every alert would make unrelated alerts look like
// copies of one. Fall back to the labels, which are what a fingerprint hashes.
func (a Alert) identity() string {
	if a.Fingerprint != "" {
		return a.Fingerprint
	}
	keys := make([]string, 0, len(a.Labels))
	for k := range a.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(a.Labels[k])
		b.WriteString("\x00")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "labels:" + hex.EncodeToString(sum[:8])
}

// Group is a set of alerts believed to share a root cause.
type Group struct {
	Key        string
	Cluster    string
	Reason     string
	Node       string
	Namespaces []string
	Alerts     []Alert
}

// Signature is a known failure mode: when Trigger matches an alert, every other
// alert that Scope accepts joins the same group. These encode root causes that
// label matching alone cannot infer.
//
// Scope receives the alert that triggered the signature so it can bound itself
// to that subject. A scope that ignores the trigger and accepts everything will
// swallow a whole window of unrelated alerts, which is exactly what the first
// version of the node signature did.
type Signature struct {
	Name    string
	Reason  string
	Trigger func(Alert) bool
	Scope   func(trigger, candidate Alert) bool
}

func labelContains(a Alert, key, substr string) bool {
	return strings.Contains(strings.ToLower(a.Labels[key]), substr)
}

func textContains(a Alert, substr string) bool {
	for _, k := range []string{"summary", "message", "description"} {
		if strings.Contains(strings.ToLower(a.Annotations[k]), substr) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(a.name()), substr)
}

// DefaultSignatures encodes the shared-infrastructure failures where one fault
// fans out into unrelated-looking alerts across namespaces.
func DefaultSignatures() []Signature {
	storage := func(a Alert) bool {
		return textContains(a, "volume") || textContains(a, "mount") ||
			textContains(a, "pvc") || textContains(a, "persistentvolume") ||
			labelContains(a, "alertname", "ceph")
	}
	ignoreTrigger := func(f func(Alert) bool) func(Alert, Alert) bool {
		return func(_, candidate Alert) bool { return f(candidate) }
	}
	return []Signature{
		{
			Name:    "nfs",
			Reason:  "NFS export unreachable; dependent workloads fail to mount",
			Trigger: func(a Alert) bool { return textContains(a, "nfs") },
			Scope:   ignoreTrigger(storage),
		},
		{
			Name:    "ceph",
			Reason:  "Ceph degraded; RWO/RWX consumers stall on IO",
			Trigger: func(a Alert) bool { return labelContains(a, "alertname", "ceph") },
			Scope:   ignoreTrigger(storage),
		},
		{
			// Only a genuine node-health alert triggers this, and only alerts on
			// the same node are collateral. Matching on the word "node" anywhere
			// caught KubePodNotReady and CephNodeDiskspaceWarning, and an
			// unbounded scope then absorbed every other alert in the window.
			Name:   "node",
			Reason: "Node unhealthy; workloads on it are collateral",
			Trigger: func(a Alert) bool {
				return a.Labels["node"] != "" &&
					(textContains(a, "kubenode") || textContains(a, "node not ready") ||
						textContains(a, "nodenotready") || textContains(a, "node unreachable"))
			},
			Scope: func(trigger, candidate Alert) bool {
				return candidate.Labels["node"] == trigger.Labels["node"]
			},
		},
		{
			Name:    "dns",
			Reason:  "DNS resolution failing; unrelated services report connection errors",
			Trigger: func(a Alert) bool { return textContains(a, "dns") || textContains(a, "coredns") },
			Scope: ignoreTrigger(func(a Alert) bool {
				return textContains(a, "dns") || textContains(a, "connection") ||
					textContains(a, "timeout") || textContains(a, "unreachable")
			}),
		},
	}
}

// overlaps reports whether two alerts were active at the same time, allowing
// slack for a cascade that takes a while to propagate.
func overlaps(a, b Alert, slack time.Duration) bool {
	aEnd, bEnd := a.EndsAt, b.EndsAt
	if aEnd.IsZero() {
		aEnd = a.StartsAt.Add(slack)
	}
	if bEnd.IsZero() {
		bEnd = b.StartsAt.Add(slack)
	}
	return a.StartsAt.Add(-slack).Before(bEnd) && b.StartsAt.Add(-slack).Before(aEnd)
}

// Correlate groups alerts that plausibly share a root cause. It is pure: node
// attribution must already be resolved into nodeOf, keyed by fingerprint.
//
// Alerts are first partitioned by their "cluster" label so that incidents from
// different clusters never fuse together (namespace names collide across
// clusters). Within each cluster partition, precedence is signature, then node,
// then alert name, then namespace, then shared labels (job, service). A
// signature beats a node match because shared-storage and DNS faults cross node
// boundaries, and splitting them by node would report one incident as several.
// Label-based grouping catches alerts from the same subsystem that share no
// namespace or name — different alert names firing together from the same job
// or service are one story about one subsystem.
func Correlate(alerts []Alert, nodeOf map[string]string, sigs []Signature, slack time.Duration) []Group {
	if len(alerts) == 0 {
		return nil
	}

	// Partition alerts by cluster label so correlation never crosses clusters.
	byCluster := map[string][]Alert{}
	for _, a := range alerts {
		byCluster[a.cluster()] = append(byCluster[a.cluster()], a)
	}

	var groups []Group
	for _, clusterAlerts := range byCluster {
		groups = append(groups, correlateCluster(clusterAlerts, nodeOf, sigs, slack)...)
	}
	return groups
}

// correlateCluster runs the correlation algorithm on alerts from a single
// cluster partition.
func correlateCluster(alerts []Alert, nodeOf map[string]string, sigs []Signature, slack time.Duration) []Group {
	claimed := make([]bool, len(alerts))
	var groups []Group

	for _, sig := range sigs {
		var trigger *Alert
		for i := range alerts {
			if !claimed[i] && sig.Trigger(alerts[i]) {
				trigger = &alerts[i]
				break
			}
		}
		if trigger == nil {
			continue
		}
		var members []Alert
		var chosen []int
		for i, a := range alerts {
			if !claimed[i] && sig.Scope(*trigger, a) {
				members = append(members, a)
				chosen = append(chosen, i)
			}
		}
		// A signature that matched only its own trigger explains nothing, so
		// leave the alert for a later rule rather than reporting a one-alert
		// "root cause". Claiming happens only once the group is kept, so there
		// is nothing to undo.
		if len(members) > 1 {
			for _, i := range chosen {
				claimed[i] = true
			}
			groups = append(groups, newGroup("signature/"+sig.Name, sig.Reason, members, nodeOf))
		}
	}

	groups = append(groups, groupBy(alerts, claimed, slack, "node", nodeOf, func(a Alert) string {
		return nodeOf[a.Fingerprint]
	})...)
	// The same alert firing across several namespaces is one story about a
	// shared cause, not one story per namespace.
	groups = append(groups, groupBy(alerts, claimed, slack, "alert", nodeOf, func(a Alert) string {
		return a.name()
	})...)
	groups = append(groups, groupBy(alerts, claimed, slack, "namespace", nodeOf, func(a Alert) string {
		return a.namespace()
	})...)
	// Group alerts from the same subsystem that share no namespace or name.
	// Different alert names firing together from the same job or service are
	// one story about one subsystem.
	for _, label := range []string{"job", "service"} {
		groups = append(groups, groupBy(alerts, claimed, slack, "label/"+label, nodeOf, func(a Alert) string {
			return a.Labels[label]
		})...)
	}

	for i, a := range alerts {
		if !claimed[i] {
			claimed[i] = true
			groups = append(groups, newGroup("single/"+a.name(), "Isolated alert", []Alert{a}, nodeOf))
		}
	}
	return groups
}

// groupBy collects unclaimed alerts sharing a non-empty key and an overlapping
// active window. Singletons are left unclaimed so a later rule can try.
func groupBy(alerts []Alert, claimed []bool, slack time.Duration, kind string, nodeOf map[string]string, keyOf func(Alert) string) []Group {
	buckets := map[string][]int{}
	var order []string
	for i, a := range alerts {
		if claimed[i] {
			continue
		}
		k := keyOf(a)
		if k == "" {
			continue
		}
		if _, ok := buckets[k]; !ok {
			order = append(order, k)
		}
		buckets[k] = append(buckets[k], i)
	}

	var out []Group
	for _, k := range order {
		idx := buckets[k]
		if len(idx) < 2 {
			continue
		}
		var members []Alert
		var chosen []int
		for _, i := range idx {
			if len(members) > 0 && !overlaps(members[0], alerts[i], slack) {
				continue
			}
			members = append(members, alerts[i])
			chosen = append(chosen, i)
		}
		if len(members) < 2 {
			continue
		}
		// Claim by index, not by fingerprint: an alert excluded above for not
		// overlapping must stay unclaimed so a later rule or the isolated-alert
		// fallback still reports it.
		for _, i := range chosen {
			claimed[i] = true
		}
		out = append(out, newGroup(kind+"/"+k, "Alerts share "+kind+" "+k+" within one window", members, nodeOf))
	}
	return out
}

func newGroup(key, reason string, members []Alert, nodeOf map[string]string) Group {
	g := Group{Key: key, Reason: reason, Alerts: members}
	seenNS := map[string]bool{}
	for _, a := range members {
		if ns := a.namespace(); ns != "" && !seenNS[ns] {
			seenNS[ns] = true
			g.Namespaces = append(g.Namespaces, ns)
		}
		if g.Node == "" && nodeOf != nil {
			g.Node = nodeOf[a.Fingerprint]
		}
		if g.Cluster == "" {
			g.Cluster = a.cluster()
		}
	}
	sort.Strings(g.Namespaces)
	return g
}

// Signature is the stable identity of a group across firings, used to look up
// how often this same shape has been seen before. It deliberately excludes
// timestamps and instance labels so a recurrence matches its predecessor.
// The cluster label is included so that identical incidents on different
// clusters are tracked separately.
func (g Group) Signature() string {
	cluster := g.Cluster
	if cluster == "" {
		cluster = "default"
	}
	names := make([]string, 0, len(g.Alerts))
	for _, a := range g.Alerts {
		names = append(names, a.name())
	}
	sort.Strings(names)
	names = dedupe(names)
	sum := sha256.Sum256([]byte(cluster + ":" + strings.Join(names, "|") + "@" + g.Node))
	return hex.EncodeToString(sum[:8])
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	}
	return 0
}

// Severity returns the most urgent severity present in the group.
func (g Group) Severity() string {
	best, bestRank := "info", 0
	for _, a := range g.Alerts {
		if r := severityRank(a.severity()); r > bestRank {
			best, bestRank = a.severity(), r
		}
	}
	return best
}

// Title summarises the group for a message header.
func (g Group) Title() string {
	cluster := g.Cluster
	if cluster == "" {
		cluster = "default"
	}
	names := make([]string, 0, len(g.Alerts))
	for _, a := range g.Alerts {
		names = append(names, a.name())
	}
	names = dedupe(names)
	sort.Strings(names)
	if len(names) == 1 {
		return fmt.Sprintf("[%s] %s", cluster, names[0])
	}
	return fmt.Sprintf("[%s] %s + %d more", cluster, names[0], len(names)-1)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
