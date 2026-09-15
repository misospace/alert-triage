package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"regexp"
	"sort"
	"strings"
	"time"
)

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// kube is a minimal read-only Kubernetes client. client-go would pull in a very
// large dependency tree for what amounts to four GETs, so this talks to the
// apiserver directly with the in-cluster ServiceAccount credentials.
type kube struct {
	base    string
	token   string
	hc      *http.Client
	logs    *logsBackend
	cluster string // cluster label this client belongs to (empty = local/default)
}

// newKube builds the read-only client. cluster names the cluster this instance
// serves, matching the `cluster` label the local Prometheus stamps on alerts.
// Leaving it empty means the instance enriches whatever it is given, which is
// right for the single-cluster case and wrong the moment one instance receives
// alerts from elsewhere — see the invariant in AGENTS.md.
func newKube(cluster string) (*kube, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return nil, fmt.Errorf("not running in-cluster")
	}
	token, err := os.ReadFile(saDir + "/token")
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("bad service account CA")
	}
	return &kube{
		cluster: cluster,
		base:    fmt.Sprintf("https://%s:%s", host, port),
		token:   strings.TrimSpace(string(token)),
		hc: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
		logs: newLogsBackend(),
	}, nil
}

func (k *kube) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")
	resp, err := k.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type podList struct {
	Items []struct {
		Metadata struct {
			Name            string            `json:"name"`
			Namespace       string            `json:"namespace"`
			Labels          map[string]string `json:"labels"`
			Annotations     map[string]string `json:"annotations"`
			OwnerReferences []ownerRef        `json:"ownerReferences"`
		} `json:"metadata"`
		Spec struct {
			NodeName string `json:"nodeName"`
		} `json:"spec"`
		Status struct {
			Phase             string `json:"phase"`
			ContainerStatuses []struct {
				Name         string `json:"name"`
				RestartCount int    `json:"restartCount"`
				Ready        bool   `json:"ready"`
				State        map[string]struct {
					Reason string `json:"reason"`
				} `json:"state"`
				LastTerminationState struct {
					Terminated struct {
						FinishedAt time.Time `json:"finishedAt"`
					} `json:"terminated"`
				} `json:"lastState"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

type eventItem struct {
	Type           string    `json:"type"`
	Reason         string    `json:"reason"`
	Message        string    `json:"message"`
	LastTimestamp  time.Time `json:"lastTimestamp"`
	InvolvedObject struct {
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"involvedObject"`
}

type eventList struct {
	Items []eventItem `json:"items"`
}

type fluxList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Status struct {
			LastAppliedRevision string `json:"lastAppliedRevision"`
			Conditions          []struct {
				Type               string    `json:"type"`
				Status             string    `json:"status"`
				Reason             string    `json:"reason"`
				Message            string    `json:"message"`
				LastTransitionTime time.Time `json:"lastTransitionTime"`
			} `json:"conditions"`
		} `json:"status"`
	} `json:"items"`
}

type nodeList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Unschedulable bool `json:"unschedulable"`
		} `json:"spec"`
		Status struct {
			Conditions []struct {
				Type    string `json:"type"`
				Status  string `json:"status"`
				Reason  string `json:"reason"`
				Message string `json:"message"`
			} `json:"conditions"`
		} `json:"status"`
	} `json:"items"`
}

// ownerRef is one entry of a Kubernetes object's metadata.ownerReferences. It
// identifies the owner of this object; a pod created by a Job carries a
// reference with Kind "Job" whose UID and Name match the job's metadata, which
// is how the service confirms a pod is owned by a job it resolved.
type ownerRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	UID  string `json:"uid"`
}

// jobObj is the subset of the batch/v1 Job shape this service reads for a
// single GET /apis/batch/v1/namespaces/<ns>/jobs/<name>. The job's UID
// identifies the pods it created (their ownerReferences point at it), and the
// controller label the controller manager copies from the job's pod template
// onto each pod (job-name=<name>) is what a listing fallback keys on when
// ownership cannot otherwise be established.
type jobObj struct {
	Metadata struct {
		Name            string     `json:"name"`
		Namespace       string     `json:"namespace"`
		UID             string     `json:"uid"`
		OwnerReferences []ownerRef `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		Template struct {
			ObjectMeta struct {
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
		} `json:"template"`
	} `json:"spec"`
}

// jobRef is a job named by an alert in a group that was resolved (read) from
// this client's cluster. The controller label it stamps on its pods
// (ControllerKey/LabelValue) is the listing fallback used to attribute pods
// when ownership cannot otherwise be established.
type jobRef struct {
	Namespace     string
	Name          string
	UID           string
	ControllerKey string // the controller label key the job stamps on its pods
	LabelValue    string // its value, usually the job name
}

// Enrichment is the evidence gathered for one group.
type Enrichment struct {
	Nodes         []string
	UnhealthyPods []string
	PodLogs       map[string]string // pod key -> tail of previous container log
	// BackendLogs are workload-authored and untrusted. BackendState is
	// "off", "empty", or "error" so missing configuration is not confused with
	// a successful query that returned no lines.
	BackendLogs  []string
	BackendState string
	// Events contains warning events attached to the resolved alert subject graph.
	// Namespace warnings not attached to those subjects remain Ambient context.
	Events       []string
	EventsScoped bool
	// FluxActivity lists recent transitions of Flux resources in the alert's
	// namespace. A Ready transition only proves the resource synced its source
	// to a revision; it does not show what changed in that revision, so the
	// entries must never be phrased as a deploy or a change.
	FluxActivity []string
	// RecentRestarts flags pods whose containers restarted inside the alert
	// window. A restart that left the current container healthy is still
	// evidence the alert is about, so it is surfaced as its own finding rather
	// than only mentioned inside UnhealthyPods.
	RecentRestarts []string
	// Ambient is context not known to concern the alert: cluster-wide findings
	// when no namespace is named, and namespace events outside a resolved subject
	// graph. It is kept apart so a coincidence is not read as a cause.
	Ambient []string
	// InspectedJobs names the Jobs whose existence and state were read directly
	// because an alert in the group named them (e.g. a kube-state-metrics
	// KubeJobFailed carrying job_name). It is the "the failed Job was inspected"
	// half of the scope statement, kept apart from the namespace listing a
	// failed backup job's own pod can only be reached through.
	InspectedJobs []string
	// Scope records what was actually inspected, so the narrative can
	// distinguish "nothing is wrong" from "nothing was looked at".
	Scope string
	// RepoPaths is the GitOps-managed location of the workload(s) an alert
	// names, resolved from Flux Kustomizations or Argo Applications the pods
	// carry annotations for. Entries are "repoURL + path/to/dir". Empty when
	// nothing resolves; the prose must degrade gracefully in that case.
	RepoPaths []string
}

func (e Enrichment) empty() bool {
	return len(e.Nodes) == 0 && len(e.UnhealthyPods) == 0 &&
		len(e.PodLogs) == 0 && len(e.BackendLogs) == 0 && (e.BackendState == "" || e.BackendState == "off") &&
		len(e.Events) == 0 && len(e.FluxActivity) == 0 && len(e.Ambient) == 0 && len(e.InspectedJobs) == 0
}

// namespaceLabels are the label keys that carry a namespace in practice.
// Exporters and recording rules rarely use the canonical one.
var namespaceLabels = []string{"namespace", "exported_namespace", "k8s_namespace", "target_namespace"}

func alertNamespace(a Alert) string {
	for _, k := range namespaceLabels {
		if v := a.Labels[k]; v != "" {
			return v
		}
	}
	return ""
}

// ResolveNodes maps alert fingerprints to the node their pod runs on, so
// correlation can group by node even though most alerts only carry pod labels.
func (k *kube) ResolveNodes(ctx context.Context, alerts []Alert) map[string]string {
	out := map[string]string{}
	if k == nil {
		return out
	}
	byNS := map[string][]Alert{}
	for _, a := range alerts {
		if a.Labels["node"] != "" {
			out[a.Fingerprint] = a.Labels["node"]
			continue
		}
		if a.namespace() != "" && a.Labels["pod"] != "" {
			byNS[a.namespace()] = append(byNS[a.namespace()], a)
		}
	}
	for ns, list := range byNS {
		var pods podList
		if err := k.get(ctx, "/api/v1/namespaces/"+url.PathEscape(ns)+"/pods", &pods); err != nil {
			logf("enrich: pods in %s: %v", ns, err)
			continue
		}
		node := map[string]string{}
		for _, p := range pods.Items {
			node[p.Metadata.Name] = p.Spec.NodeName
		}
		for _, a := range list {
			if n := node[a.Labels["pod"]]; n != "" {
				out[a.Fingerprint] = n
			}
		}
	}
	return out
}

// Enrich gathers cluster state and recent Flux transitions for a group.
// Failures degrade the digest rather than block it: a partial story beats none.
//
// When the group's cluster label does not match this client's cluster, the
// enrichment is skipped and Scope reports "cluster state unavailable" to avoid
// producing wrong evidence from a foreign API server.
func (k *kube) Enrich(ctx context.Context, g Group, window time.Duration, cfg *Config) Enrichment {
	var e Enrichment
	if k == nil {
		e.Scope = "cluster state unavailable"
		return e
	}

	// Skip only when both identities are known and disagree. The check is
	// deliberately one-sided: an unset CLUSTER means this instance does not know
	// which cluster it serves, and refusing on that basis empties every evidence
	// block while the narrative still reads as though the cluster was inspected.
	// That shipped in 0.1.8 and ran unnoticed for three days, because a
	// confident story told over no evidence looks exactly like a good one.
	if k.cluster != "" && g.Cluster != "" && k.cluster != g.Cluster {
		e.Scope = fmt.Sprintf("cluster state unavailable (group is from cluster %q, this client serves %q)", g.Cluster, k.cluster)
		e.BackendState = "unavailable"
		return e
	}

	since := time.Now().Add(-window)

	// Node health is reported as a direct finding regardless of scope: a node in
	// trouble plausibly explains almost any alert, and healthy nodes rule that out.
	e.Nodes = k.unhealthyNodes(ctx)

	if len(g.Namespaces) == 0 {
		// Nothing namespace-scoped to inspect, so widen to the whole cluster
		// rather than reporting no evidence. What comes back is context, not
		// findings about this alert, and is kept separate so it cannot be
		// mistaken for one.
		e.Ambient = append(e.Ambient, k.warningEvents(ctx, "", since)...)
		e.Ambient = append(e.Ambient, k.fluxActivity(ctx, "", since)...)
		e.Scope = "cluster-wide; this alert names no namespace, so nothing below is known to concern it"
	} else {
		e.Scope = "namespaces " + strings.Join(g.Namespaces, ", ") + " plus cluster node health"
	}

	// Collect the pods the alerts actually name, so we can still fetch their
	// previous-container logs when the current container has already recovered
	// (e.g. an OOMKilled container that has been replaced by a healthy one).
	targetPods := map[string]bool{}
	for _, a := range g.Alerts {
		if a.Labels["pod"] != "" && a.namespace() != "" {
			targetPods[a.namespace()+"/"+a.Labels["pod"]] = true
		}
	}

	// A KubeJobFailed alert names the failed Job, not a pod, so the pod-label
	// pass above finds nothing. Resolve each namespaced job the group's alerts
	// name; the job's UID identifies the pods it created (their ownerReferences
	// point at it), and those become direct targets too.
	jobTargets := k.resolveJobs(ctx, g)
	for _, j := range jobTargets {
		e.InspectedJobs = append(e.InspectedJobs, j.Namespace+"/"+j.Name)
	}
	// jobTargets is a map, so preserve a stable scope statement across runs.
	sort.Strings(e.InspectedJobs)
	if len(e.InspectedJobs) > 0 {
		// Name only Jobs read directly, distinguishing them from a namespace listing.
		e.Scope += "; jobs " + strings.Join(e.InspectedJobs, ", ") + " were inspected"
	}

	resolvedSubjects := map[subjectKey]bool{}
	for _, a := range g.Alerts {
		ns := a.namespace()
		if ns == "" {
			continue
		}
		if pod := a.Labels["pod"]; pod != "" {
			resolvedSubjects[subjectKey{kind: "Pod", name: pod, namespace: ns}] = true
		}
	}
	for _, j := range jobTargets {
		resolvedSubjects[subjectKey{kind: "Job", name: j.Name, namespace: j.Namespace}] = true
	}
	e.EventsScoped = len(resolvedSubjects) > 0

	var seenPods []podRef
	for _, ns := range g.Namespaces {
		esc := url.PathEscape(ns)

		var pods podList
		if err := k.get(ctx, "/api/v1/namespaces/"+esc+"/pods", &pods); err != nil {
			logf("enrich: pods in %s: %v", ns, err)
		}
		type scoredPod struct {
			desc    string
			score   int // higher = worse health
			restart int // restart count, surfaced as a finding on its own
			key     string
		}
		var unhealthy []scoredPod
		for _, p := range pods.Items {
			seenPods = append(seenPods, podRef{
				Name:        p.Metadata.Name,
				Namespace:   p.Metadata.Namespace,
				Annotations: p.Metadata.Annotations,
			})
			key := p.Metadata.Namespace + "/" + p.Metadata.Name
			for _, cs := range p.Status.ContainerStatuses {
				reason := ""
				for state, s := range cs.State {
					if state != "running" && s.Reason != "" {
						reason = s.Reason
					}
				}
				restartedRecently := cs.RestartCount > 0 && !cs.LastTerminationState.Terminated.FinishedAt.IsZero() &&
					cs.LastTerminationState.Terminated.FinishedAt.After(since)
				if p.Status.Phase == "Running" && cs.Ready && reason == "" {
					// A recovered pod that the alert named still matters: its
					// previous container's log is the evidence we want.
					if !targetPods[key] && !restartedRecently {
						continue
					}
				}
				if p.Status.Phase == "Succeeded" {
					continue
				}
				desc := fmt.Sprintf("%s %s", key, p.Status.Phase)
				if reason != "" {
					desc += " (" + reason + ")"
				}
				if cs.RestartCount > 0 {
					desc += fmt.Sprintf(" restarts=%d", cs.RestartCount)
				}
				unhealthy = append(unhealthy, scoredPod{desc: desc, score: podHealthScore(p.Status.Phase, reason, cs.Ready, cs.RestartCount), restart: cs.RestartCount, key: key})
				if restartedRecently {
					e.RecentRestarts = append(e.RecentRestarts, fmt.Sprintf("%s container %s restarted %d time(s) since %s", key, cs.Name, cs.RestartCount, since.Format(time.RFC3339)))
				}
				break
			}
		}
		// Promote the pods owned by a job the group's alerts named into the
		// direct-target set, so they survive namespace noise and list
		// truncation exactly as a pod-labelled alert's own pod does.
		for _, j := range jobTargets {
			if j.Namespace != ns {
				continue
			}
			for _, p := range pods.Items {
				owner := podOwner{Labels: p.Metadata.Labels, OwnerReferences: p.Metadata.OwnerReferences}
				if jobOwnedBy(*j, owner) {
					targetPods[p.Metadata.Namespace+"/"+p.Metadata.Name] = true
					resolvedSubjects[subjectKey{kind: "Pod", name: p.Metadata.Name, namespace: p.Metadata.Namespace}] = true
				}
			}
		}
		// Pull the pods the alert actually names to the front, so they survive
		// truncation ahead of unrelated noise in the same namespace.
		sort.SliceStable(unhealthy, func(i, j int) bool {
			iTarget := targetPods[unhealthy[i].key]
			jTarget := targetPods[unhealthy[j].key]
			if iTarget != jTarget {
				return iTarget
			}
			return unhealthy[i].score > unhealthy[j].score
		})
		for _, sp := range unhealthy {
			e.UnhealthyPods = append(e.UnhealthyPods, sp.desc)
		}

		if items, err := k.fetchEvents(ctx, ns); err == nil {
			e.Events = append(e.Events, aggregateEvents(items, since, func(subject subjectKey) bool {
				return resolvedSubjects[subject]
			})...)
			e.Ambient = append(e.Ambient, aggregateEvents(items, since, func(subject subjectKey) bool {
				return !resolvedSubjects[subject]
			})...)
		}
		e.FluxActivity = append(e.FluxActivity, k.fluxActivity(ctx, esc, since)...)
	}

	e.Nodes = capList(e.Nodes, 6)
	e.UnhealthyPods = capList(e.UnhealthyPods, 8)
	e.RecentRestarts = capList(dedupe(e.RecentRestarts), 6)
	e.PodLogs = k.fetchPodLogs(ctx, e.UnhealthyPods)
	if k.logs != nil {
		var err error
		e.BackendLogs, err = k.logs.fetchBackendLogsResult(ctx, g, window)
		if err != nil {
			e.BackendState = "error"
			logf("enrich: backend logs: %v", err)
		} else if len(e.BackendLogs) == 0 {
			e.BackendState = "empty"
		} else {
			e.BackendState = "ok"
		}
	} else {
		e.BackendState = "off"
	}
	e.Events = capList(dedupe(e.Events), 8)
	e.FluxActivity = capList(dedupe(e.FluxActivity), 6)
	// Ambient only has to be enough for the model to rule things out.
	e.Ambient = capList(dedupe(e.Ambient), 5)
	e.RepoPaths = k.resolveRepoPaths(ctx, seenPods, cfg)
	return e
}

// resolveJobs fetches, from this client's cluster, every distinct job that an
// alert in the group names, keyed by "namespace/job". KubeJobFailed alerts from
// kube-state-metrics identify the failed workload with a `job_name` label (and
// the alert's own namespace labels), so they do not carry a `pod` label and
// would otherwise leave the enrichment to list the whole namespace and report
// "no unhealthy pods in scope" without ever inspecting the failed job's own
// pod as the subject. A job that is missing or whose read fails is simply not
// returned; the digest still ships on the namespace listing.
func (k *kube) resolveJobs(ctx context.Context, g Group) map[string]*jobRef {
	out := map[string]*jobRef{}
	for _, a := range g.Alerts {
		ns, name := a.namespace(), a.Labels["job_name"]
		if ns == "" || name == "" {
			continue
		}
		if _, ok := out[ns+"/"+name]; ok {
			continue
		}
		var job jobObj
		if err := k.get(ctx, "/apis/batch/v1/namespaces/"+url.PathEscape(ns)+"/jobs/"+url.PathEscape(name), &job); err != nil {
			// A missing or unreadable job degrades to the namespace listing
			// rather than blocking the digest: this is the same fail-open
			// rule the rest of enrichment follows.
			logf("enrich: job %s/%s: %v", ns, name, err)
			continue
		}
		out[ns+"/"+name] = &jobRef{
			Namespace:     ns,
			Name:          name,
			UID:           job.Metadata.UID,
			ControllerKey: "job-name",
			LabelValue:    job.Spec.Template.ObjectMeta.Labels["job-name"],
		}
	}
	return out
}

// podOwner is the subset of a pod's metadata the job-ownership check reads:
// the ownerReferences (primary signal) and labels (listing fallback).
type podOwner struct {
	Labels          map[string]string
	OwnerReferences []ownerRef
}

// jobOwnedBy reports whether pod p is owned by job j. Primary signal is
// ownership: a Job owner reference naming this job (by name, and by uid where
// both are present) is proof of ownership. The label-selector fallback
// (job-name=<name>) is used only when ownership cannot be established — the
// pod carries no Job owner reference at all — because a bare label match can
// collide across jobs that share a controller-label value, and a pod owned by
// another job must never be claimed on that basis.
func jobOwnedBy(j jobRef, p podOwner) bool {
	hasJobOwner := false
	for _, o := range p.OwnerReferences {
		if o.Kind != "Job" {
			continue
		}
		hasJobOwner = true
		if o.Name != j.Name {
			continue
		}
		if j.UID != "" && o.UID != "" && o.UID != j.UID {
			continue
		}
		return true
	}
	if hasJobOwner {
		// Ownership is known but points at another Job, so labels cannot override it.
		return false
	}
	// Without a Job owner reference, the controller label is the best fallback.
	if j.ControllerKey != "" && j.LabelValue != "" {
		return p.Labels[j.ControllerKey] == j.LabelValue
	}
	return false
}

// unhealthyNodes reports nodes that are not Ready, are under pressure, or have
// been cordoned. A healthy cluster returns nothing, which is itself evidence.
func (k *kube) unhealthyNodes(ctx context.Context) []string {
	var nodes nodeList
	if err := k.get(ctx, "/api/v1/nodes", &nodes); err != nil {
		logf("enrich: nodes: %v", err)
		return nil
	}
	var out []string
	for _, n := range nodes.Items {
		var problems []string
		for _, c := range n.Status.Conditions {
			switch {
			case c.Type == "Ready" && c.Status != "True":
				problems = append(problems, "NotReady: "+c.Reason)
			case c.Type != "Ready" && c.Status == "True":
				problems = append(problems, c.Type)
			}
		}
		if n.Spec.Unschedulable {
			problems = append(problems, "cordoned")
		}
		if len(problems) > 0 {
			out = append(out, n.Metadata.Name+" "+strings.Join(problems, ", "))
		}
	}
	return out
}

type subjectKey struct {
	kind      string
	name      string
	namespace string
}

func (k *kube) fetchEvents(ctx context.Context, namespace string) ([]eventItem, error) {
	path := "/api/v1/events?fieldSelector=type!=Normal"
	if namespace != "" {
		path = "/api/v1/namespaces/" + url.PathEscape(namespace) + "/events?fieldSelector=type!=Normal"
	}
	var events eventList
	if err := k.get(ctx, path, &events); err != nil {
		logf("enrich: events (%s): %v", orAll(namespace), err)
		return nil, err
	}
	return events.Items, nil
}

// aggregateEvents collapses repeated warning events by reason and object kind.
// keep filters event subjects so callers can split direct evidence from ambient context.
func aggregateEvents(items []eventItem, since time.Time, keep func(subjectKey) bool) []string {
	// One stuck condition emits the same event against many objects; report its count.
	type agg struct {
		count   int
		kind    string
		sample  string
		example string
	}
	seen := map[string]*agg{}
	var order []string
	for _, ev := range items {
		if ev.LastTimestamp.Before(since) {
			continue
		}
		if keep != nil && !keep(subjectKey{
			kind:      ev.InvolvedObject.Kind,
			name:      ev.InvolvedObject.Name,
			namespace: ev.InvolvedObject.Namespace,
		}) {
			continue
		}
		key := ev.Reason + "/" + ev.InvolvedObject.Kind
		if _, ok := seen[key]; !ok {
			seen[key] = &agg{kind: ev.InvolvedObject.Kind, sample: truncate(ev.Message, 160), example: ev.InvolvedObject.Name}
			order = append(order, key)
		}
		seen[key].count++
	}

	out := make([]string, 0, len(order))
	for _, key := range order {
		a := seen[key]
		if a.count == 1 {
			out = append(out, fmt.Sprintf("%s %s/%s: %s", strings.SplitN(key, "/", 2)[0], a.kind, a.example, a.sample))
			continue
		}
		out = append(out, fmt.Sprintf("%s x%d on %s (e.g. %s): %s",
			strings.SplitN(key, "/", 2)[0], a.count, a.kind, a.example, a.sample))
	}
	return out
}

// warningEvents returns all recent non-Normal events in scope. An empty
// namespace widens the query to the whole cluster.
func (k *kube) warningEvents(ctx context.Context, namespace string, since time.Time) []string {
	items, err := k.fetchEvents(ctx, namespace)
	if err != nil {
		return nil
	}
	return aggregateEvents(items, since, nil)
}

// podLogTail is the maximum number of lines to fetch per unhealthy pod.
const podLogTail = 20

// secretPatterns are common patterns that likely contain secrets in logs.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+`),
	regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*\S+`),
	regexp.MustCompile(`(?i)(token|bearer)\s*[=:]\s*\S+`),
	regexp.MustCompile(`(?i)(secret|credential)\s*[=:]\s*\S+`),
	regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*\S+`),
}

// stripSecrets replaces obvious secrets in log lines with [REDACTED].
func stripSecrets(s string) string {
	for _, re := range secretPatterns {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

// fetchPodLogs retrieves the tail of the previous container log for each
// unhealthy pod. Returns a map keyed by "namespace/name".
func (k *kube) fetchPodLogs(ctx context.Context, pods []string) map[string]string {
	if len(pods) == 0 || k.hc == nil {
		return nil
	}

	logs := make(map[string]string)
	for _, podKey := range pods {
		parts := strings.SplitN(podKey, "/", 2)
		if len(parts) != 2 {
			continue
		}
		ns, name := parts[0], parts[1]

		path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log?previous=true&tailLines=%d", ns, name, podLogTail)
		req, err := http.NewRequestWithContext(ctx, "GET", k.base+path, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+k.token)
		resp, err := k.hc.Do(req)
		if err != nil {
			logf("enrich: pod logs (%s): %v", podKey, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if err != nil {
			continue
		}
		logs[podKey] = stripSecrets(strings.TrimSpace(string(data)))
	}

	return logs
}

// fluxActivity reports Flux resources that are failing, and - only when
// scoped to a namespace - ones whose Ready condition transitioned inside the
// window.
//
// Cluster-wide reconciles are worthless: a routine sync of the whole repo
// transitions every resource at once, so a healthy-reconcile listing turns
// into 150 lines of noise. A transition is a signal only when it happened in
// the namespace the alert is about.
//
// The wording of a healthy transition must stay neutral. "reconciled at
// revision X" says only that Flux applied a sync at revision X; whether any
// file affecting the workload changed in that revision is not known from the
// revision number alone, so this function must not call a sync a deploy or a
// change. A NotReady transition is a failure, and it keeps the resource's own
// reason and revision verbatim.
func (k *kube) fluxActivity(ctx context.Context, namespace string, since time.Time) []string {
	scoped := namespace != ""
	apis := []string{
		"/apis/helm.toolkit.fluxcd.io/v2/helmreleases",
		"/apis/kustomize.toolkit.fluxcd.io/v1/kustomizations",
	}
	if namespace != "" {
		apis = []string{
			"/apis/helm.toolkit.fluxcd.io/v2/namespaces/" + namespace + "/helmreleases",
			"/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/" + namespace + "/kustomizations",
		}
	}
	var out []string
	for _, api := range apis {
		var fl fluxList
		if err := k.get(ctx, api, &fl); err != nil {
			continue
		}
		for _, item := range fl.Items {
			for _, c := range item.Status.Conditions {
				if c.Type != "Ready" {
					continue
				}
				if c.Status == "True" && (!scoped || !c.LastTransitionTime.After(since)) {
					continue
				}
				rev := shortRev(item.Status.LastAppliedRevision)
				if c.Status != "True" {
					// NotReady: a failed sync. Keep the resource's own reason
					// and revision verbatim - strong primary evidence.
					out = append(out, fmt.Sprintf("%s/%s NOT READY: %s rev=%s",
						item.Metadata.Namespace, item.Metadata.Name, c.Reason, rev))
					continue
				}
				// Ready: a healthy sync of the latest revision. Neutral
				// wording - it proves the source was applied, not that this
				// workload changed.
				out = append(out, fmt.Sprintf("%s/%s reconciled at revision %s",
					item.Metadata.Namespace, item.Metadata.Name, rev))
			}
		}
	}
	return out
}

func orAll(ns string) string {
	if ns == "" {
		return "all namespaces"
	}
	return ns
}

func capList(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return append(in[:n:n], fmt.Sprintf("...and %d more", len(in)-n))
}

// truncate flattens and clamps a string, for single-line contexts such as event
// messages. Use clamp where line structure is meaningful.
func truncate(s string, n int) string {
	return clamp(strings.ReplaceAll(strings.TrimSpace(s), "\n", " "), n)
}

// clamp shortens a string without disturbing its line breaks.
func clamp(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func shortRev(rev string) string {
	if rev == "" {
		return "unknown"
	}
	if i := strings.LastIndex(rev, ":"); i >= 0 && len(rev) > i+9 {
		return rev[:i+9]
	}
	return truncate(rev, 24)
}

// podHealthScore ranks a pod's health so the worst pods surface before the
// cap truncates. Higher score = worse health.
func podHealthScore(phase, reason string, ready bool, restarts int) int {
	score := 0
	switch phase {
	case "Failed":
		score += 100
	case "Pending":
		score += 80
	case "Unknown":
		score += 70
	case "Running":
		if !ready {
			score += 50
		}
	default:
		// CrashLoopBackOff, OOMKilled, etc. are already captured by reason.
	}
	if reason != "" {
		switch reason {
		case "OOMKilled", "CrashLoopBackOff":
			score += 200
		default:
			score += 50
		}
	}
	score += restarts * 10
	return score
}

// resolveRepoPaths walks the pods already gathered and, for each, looks up
// the GitOps tool that owns it. Flux-managed pods carry
// kustomize.toolkit.fluxcd.io/name+namespace pointing at a Kustomization;
// its spec.sourceRef names a GitRepository with the repo URL, and its
// spec.path gives the directory. Argo-managed pods carry
// argocd.argoproj.io/instance naming an Application whose spec.source
// carries repoURL and path directly. When neither annotation is present,
// the call falls back to GITOPS_REPO + GITOPS_PATH from cfg. Results are
// de-duplicated; unresolved entries are dropped silently so a missing
// mapping degrades to today's prose rather than to a fabricated path.
func (k *kube) resolveRepoPaths(ctx context.Context, pods []podRef, cfg *Config) []string {
	seen := map[string]bool{}
	var out []string
	add := func(repo, path string) {
		repo = strings.TrimRight(repo, "/")
		path = strings.TrimLeft(path, "/")
		if repo == "" {
			return
		}
		// Defense in depth: the path component originates either from
		// the apiserver response (Flux Kustomization / Argo Application
		// spec) or from operator-controlled config (GitOpsRepo /
		// GitOpsPath fallback). Three classes of input must be dropped
		// outright before any sanitisation:
		//
		//   - NUL (\x00), which truncates a URL on some renderers and
		//     would smuggle a second URL segment into a Discord
		//     clickable link.
		//   - `\` (backslash), which Go's path.Clean (a Unix-style
		//     package) treats as text. A path like `podinfo\..\..`
		//     would pass through path.Clean untouched and route to a
		//     404, but the operator did not configure it either way.
		//     GitHub URLs use forward slashes; backslashes in a path
		//     can only be an error or an attack.
		//   - `%` (percent), used for percent-encoded traversal such
		//     as `%2F..%2F` that path.Clean does not decode and that
		//     some URL consumers decode before routing. Legitimate
		//     GitHub paths do not contain `%`. Note: this value is
		//     only ever rendered as a clickable Discord link and
		//     never passed to os.Open, so symlink resolution is not
		//     a concern here — the only attack surface is the URL
		//     string the consumer sees before clicking.
		//     Flux / Argo paths are file paths, not URLs, and a `%`
		//     can only have appeared as a percent-encoding attempt.
		//
		// After rejection, collapse `..` traversal with path.Clean
		// against a leading slash so leading `..` segments collapse
		// against the root rather than resolving relative to the
		// caller's CWD. The leading-slash wrapper is load-bearing:
		// path.Clean("/../../etc") returns "/etc" (the desired
		// behaviour here) only because Clean treats leading `..` as
		// relative to the root. Removing the wrapper would turn
		// "../../etc" into "../../etc" unchanged. Do not simplify.
		if strings.ContainsAny(path, "\x00\\%") {
			return
		}
		if path != "" {
			cleaned := pathpkg.Clean("/" + path)
			if cleaned == "/" {
				path = ""
			} else {
				path = strings.TrimLeft(cleaned, "/")
			}
		}
		var entry string
		if path == "" {
			entry = repo
		} else {
			entry = repo + "/" + path
		}
		if seen[entry] {
			return
		}
		seen[entry] = true
		out = append(out, entry)
	}

	for _, p := range pods {
		if kustom := p.Annotations["kustomize.toolkit.fluxcd.io/name"]; kustom != "" {
			kuzNs := p.Annotations["kustomize.toolkit.fluxcd.io/namespace"]
			if kuzNs == "" {
				kuzNs = p.Namespace
			}
			if repo, path, ok := k.fluxPath(ctx, kuzNs, kustom); ok {
				add(repo, path)
				continue
			}
		}
		if app := p.Annotations["argocd.argoproj.io/instance"]; app != "" {
			if repo, path, ok := k.argocdPath(ctx, app); ok {
				add(repo, path)
				continue
			}
		}
	}
	if len(out) == 0 && cfg.GitOpsRepo != "" {
		add(cfg.GitOpsRepo, cfg.GitOpsPath)
	}
	return out
}

// podRef is the minimal pod shape resolveRepoPaths needs; the project does
// not depend on client-go, so we carry only name, namespace, and the
// annotations the GitOps tools use to identify their owner.
type podRef struct {
	Name        string
	Namespace   string
	Annotations map[string]string
}

func (k *kube) fluxPath(ctx context.Context, ns, name string) (string, string, bool) {
	var kuz struct {
		Spec struct {
			Path      string `json:"path"`
			SourceRef struct {
				Name string `json:"name"`
				Kind string `json:"kind"`
			} `json:"sourceRef"`
		} `json:"spec"`
	}
	if err := k.get(ctx, "/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/"+ns+"/kustomizations/"+name, &kuz); err != nil || kuz.Spec.Path == "" {
		return "", "", false
	}
	srcKind := kuz.Spec.SourceRef.Kind
	if srcKind == "" {
		srcKind = "GitRepository"
	}
	var src struct {
		Spec struct {
			URL string `json:"url"`
		} `json:"spec"`
	}
	srcPath := "/apis/source.toolkit.fluxcd.io/v1/namespaces/" + ns + "/" + pluralLower(srcKind) + "/" + kuz.Spec.SourceRef.Name
	if err := k.get(ctx, srcPath, &src); err != nil || src.Spec.URL == "" {
		return "", "", false
	}
	return src.Spec.URL, kuz.Spec.Path, true
}

func (k *kube) argocdPath(ctx context.Context, instance string) (string, string, bool) {
	var app struct {
		Spec struct {
			Source struct {
				RepoURL string `json:"repoURL"`
				Path    string `json:"path"`
			} `json:"source"`
		} `json:"spec"`
	}
	for _, ns := range []string{"argocd", ""} {
		p := "/apis/argoproj.io/v1alpha1/"
		if ns != "" {
			p += "namespaces/" + ns + "/"
		}
		p += "applications/" + instance
		if err := k.get(ctx, p, &app); err == nil && app.Spec.Source.RepoURL != "" {
			return app.Spec.Source.RepoURL, app.Spec.Source.Path, true
		}
	}
	return "", "", false
}

func pluralLower(kind string) string {
	switch kind {
	case "GitRepository":
		return "gitrepositories"
	case "OCIRepository":
		return "ocirepositories"
	case "Bucket":
		return "buckets"
	case "HelmChart":
		return "helmcharts"
	case "HelmRelease":
		return "helmreleases"
	}
	return strings.ToLower(kind) + "s"
}
