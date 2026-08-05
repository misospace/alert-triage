package main

import (
	"crypto/sha256"
	"encoding/hex"
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

// Group is a set of alerts believed to share a root cause.
type Group struct {
	Key        string
	Reason     string
	Node       string
	Namespaces []string
	Alerts     []Alert
}

// Signature is a known failure mode: when trigger matches an alert, every alert
// in the window matching scope is pulled into the same group. These encode
// root causes that label-matching alone cannot infer.
type Signature struct {
	Name    string
	Reason  string
	Trigger func(Alert) bool
	Scope   func(Alert) bool
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
	return []Signature{
		{
			Name:    "nfs",
			Reason:  "NFS export unreachable; dependent workloads fail to mount",
			Trigger: func(a Alert) bool { return textContains(a, "nfs") },
			Scope:   storage,
		},
		{
			Name:    "ceph",
			Reason:  "Ceph degraded; RWO/RWX consumers stall on IO",
			Trigger: func(a Alert) bool { return labelContains(a, "alertname", "ceph") },
			Scope:   storage,
		},
		{
			Name:    "node",
			Reason:  "Node unhealthy; its workloads are collateral",
			Trigger: func(a Alert) bool { return textContains(a, "notready") || textContains(a, "node") },
			Scope:   func(a Alert) bool { return true },
		},
		{
			Name:    "dns",
			Reason:  "DNS resolution failing; unrelated services report connection errors",
			Trigger: func(a Alert) bool { return textContains(a, "dns") || textContains(a, "coredns") },
			Scope: func(a Alert) bool {
				return textContains(a, "dns") || textContains(a, "connection") ||
					textContains(a, "timeout") || textContains(a, "unreachable")
			},
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
// Precedence is signature, then node, then namespace. A signature beats a node
// match because shared-storage and DNS faults cross node boundaries, and
// splitting them by node would report one incident as several.
func Correlate(alerts []Alert, nodeOf map[string]string, sigs []Signature, slack time.Duration) []Group {
	if len(alerts) == 0 {
		return nil
	}

	claimed := make([]bool, len(alerts))
	var groups []Group

	for _, sig := range sigs {
		triggered := false
		for i, a := range alerts {
			if !claimed[i] && sig.Trigger(a) {
				triggered = true
				break
			}
		}
		if !triggered {
			continue
		}
		var members []Alert
		for i, a := range alerts {
			if !claimed[i] && sig.Scope(a) {
				claimed[i] = true
				members = append(members, a)
			}
		}
		if len(members) > 0 {
			groups = append(groups, newGroup("signature/"+sig.Name, sig.Reason, members, nodeOf))
		}
	}

	groups = append(groups, groupBy(alerts, claimed, slack, "node", nodeOf, func(a Alert) string {
		return nodeOf[a.Fingerprint]
	})...)
	groups = append(groups, groupBy(alerts, claimed, slack, "namespace", nodeOf, func(a Alert) string {
		return a.namespace()
	})...)

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
		for _, i := range idx {
			if len(members) > 0 && !overlaps(members[0], alerts[i], slack) {
				continue
			}
			members = append(members, alerts[i])
		}
		if len(members) < 2 {
			continue
		}
		for _, i := range idx {
			for _, m := range members {
				if alerts[i].Fingerprint == m.Fingerprint {
					claimed[i] = true
				}
			}
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
	}
	sort.Strings(g.Namespaces)
	return g
}

// Signature is the stable identity of a group across firings, used to look up
// how often this same shape has been seen before. It deliberately excludes
// timestamps and instance labels so a recurrence matches its predecessor.
func (g Group) Signature() string {
	names := make([]string, 0, len(g.Alerts))
	for _, a := range g.Alerts {
		names = append(names, a.name())
	}
	sort.Strings(names)
	names = dedupe(names)
	sum := sha256.Sum256([]byte(strings.Join(names, "|") + "@" + g.Node))
	return hex.EncodeToString(sum[:8])
}

// Severity returns the most urgent severity present in the group.
func (g Group) Severity() string {
	rank := map[string]int{"critical": 3, "warning": 2, "info": 1}
	best, bestRank := "info", 0
	for _, a := range g.Alerts {
		if r := rank[a.severity()]; r > bestRank {
			best, bestRank = a.severity(), r
		}
	}
	return best
}

// Title summarises the group for a message header.
func (g Group) Title() string {
	names := make([]string, 0, len(g.Alerts))
	for _, a := range g.Alerts {
		names = append(names, a.name())
	}
	names = dedupe(names)
	sort.Strings(names)
	if len(names) == 1 {
		return names[0]
	}
	return names[0] + " +" + itoa(len(names)-1) + " more"
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
