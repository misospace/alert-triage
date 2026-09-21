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
	"strconv"
	"strings"
	"sync"
	"time"
)

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// kube is a minimal read-only Kubernetes client. client-go would pull in a very
// large dependency tree for what amounts to four GETs, so this talks to the
// apiserver directly with the in-cluster ServiceAccount credentials.
//
// logConcurrency used to live on this struct and was rewritten by every
// Enrich call. The shared-write/read pattern races when shutdown's
// drainBuffer runs while a canceled runFlushLoop process is still
// unwinding — both paths invoke Enrich on the same *kube and the
// goroutines spawned by fetchPodLogs read k.logConcurrency under no
// synchronisation. The value now lives only on the per-call path so it
// never needs to be written here.
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
			Phase             string            `json:"phase"`
			ContainerStatuses []containerStatus `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

// containerStatus is the subset of a pod's containerStatuses this service
// reads. The current state and the last state are the same Kubernetes union
// (running | waiting | terminated), so one type models both.
type containerStatus struct {
	Name         string         `json:"name"`
	RestartCount int            `json:"restartCount"`
	Ready        bool           `json:"ready"`
	State        containerState `json:"state"`
	LastState    containerState `json:"lastState"`
}

// containerState is the union of the three mutually exclusive container
// states. Each member is a pointer so the zero value (nil) means "absent from
// the JSON", which is how the apiserver signals which of the three states a
// container is actually in: exactly one is non-nil.
type containerState struct {
	Running    *runningState    `json:"running"`
	Waiting    *waitingState    `json:"waiting"`
	Terminated *terminatedState `json:"terminated"`
}

type runningState struct {
	StartedAt time.Time `json:"startedAt"`
}

type waitingState struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// terminatedState is the subset of the "terminated" state that tells an
// operator why a container ended: the exit code, reason, any message the
// container left, and when it finished. For a one-shot Job container that
// terminated once and never restarted, this is state.terminated and the
// pod's current log is the evidence; for a restarted (CrashLoop) container
// the last failed run lives in lastState.terminated instead.
type terminatedState struct {
	ExitCode   int       `json:"exitCode"`
	Reason     string    `json:"reason"`
	Message    string    `json:"message"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
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
// is how the service confirms a pod is owned by a job it resolved. apiVersion
// and controller are carried so an ownership chain can tell a controller
// owner (the real one) from a non-controller owner on the same object.
type ownerRef struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller *bool  `json:"controller"`
}

// jobObj is the subset of the batch/v1 Job shape this service reads for a
// single GET /apis/batch/v1/namespaces/<ns>/jobs/<name>. The job's UID
// identifies the pods it created (their ownerReferences point at it), and the
// controller label the controller manager copies from the job's pod template
// onto each pod (job-name=<name>) is what a listing fallback keys on when
// ownership cannot otherwise be established. The job's own ownerReferences
// and labels say what the job *is* - a Job generated by a backup or
// migration controller is owned by that controller even when its name is
// derived from the application it serves.
type jobObj struct {
	Metadata struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		UID             string            `json:"uid"`
		Labels          map[string]string `json:"labels"`
		Annotations     map[string]string `json:"annotations"`
		OwnerReferences []ownerRef        `json:"ownerReferences"`
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
// when ownership cannot otherwise be established. OwnerRefs and Identity
// carry the job's own ownership and identifying labels, which say what the
// job is (its controller) rather than only that it exists; they feed the
// ownership chain the model is shown.
type jobRef struct {
	Namespace     string
	Name          string
	UID           string
	ControllerKey string // the controller label key the job stamps on its pods
	LabelValue    string // its value, usually the job name
	OwnerRefs     []ownerRef
	Identity      string // selected identifying labels/annotations, see identityTags
}

// Enrichment is the evidence gathered for one group.
type Enrichment struct {
	Nodes         []string
	UnhealthyPods []string
	// PodLogs maps a pod key ("namespace/name") to the tail of the log stream
	// that holds the failure evidence. The stream is chosen per container, not
	// per pod: a container that never restarted (a one-shot Job) carries its
	// failure in its *current* log, while a restarted one (a CrashLoop) carries
	// it in the previous instance, and the container itself is named in the
	// request so a multi-container pod is not answered by a default choice.
	PodLogs map[string]string
	// PodLogProvenance tells the renderer which container and which stream
	// each PodLogs entry came from, so a "previous-container tail" label
	// does not silently mislabel a one-shot Job's current log as a previous
	// one. Keys match PodLogs.
	PodLogProvenance map[string]podLogProvenance
	// ContainerDiagnostics are the structured readings this service made
	// itself about the containers of the pods above: the exit code,
	// termination reason and finish time of the failed container run.
	// Rendered outside the untrusted fence, like pod phases and node
	// conditions — fencing this service's own reading would tell the model to
	// distrust it (AGENTS.md). The container's own termination message is
	// carried separately and fenced.
	ContainerDiagnostics []string
	// ContainerTerminationMessages are the workload-authored termination
	// messages of the failed container runs above. They are the container's
	// own words, so the renderer fences them, like event messages, rather
	// than trusting them as a service reading.
	ContainerTerminationMessages []string
	// BackendLogs are workload-authored and untrusted. BackendState is
	// "off", "empty", "ambient", or "error" so missing configuration is not
	// confused with a successful query that returned no lines. "empty" means
	// the queries issued returned no lines; "ambient" means no concrete subject
	// could be resolved, the namespace-wide fallback did return lines, and those
	// lines were routed to Ambient — the source is configured and answered.
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
	// Ownership is the compact subject relationship of the group's named
	// workloads, built only from ownerReferences the API actually returned
	// (see ownershipChain). "Pod/x -> Job/y -> Kind/z" tells the model who
	// made the failed job; an ownerless job renders with no parent, so a
	// generated maintenance job is never mistaken for the application it
	// shares a name with. Entries are workload-authored metadata and are
	// rendered to the model inside the untrusted fence.
	Ownership []string
	// Scope records what was actually inspected, so the narrative can
	// distinguish "nothing is wrong" from "nothing was looked at".
	Scope string
	// RepoPaths is the GitOps-managed location of the workload(s) an alert
	// names, resolved from Flux Kustomizations or Argo Applications the pods
	// carry annotations for. Entries are "repoURL + path/to/dir". Empty when
	// nothing resolves; the prose must degrade gracefully in that case.
	RepoPaths []string
	// CommitRelevance classifies the most recent Flux Kustomization revision
	// for the affected workload against the workload's Git surface: one entry
	// per resolved Kustomization, populated only when the Git source is GitHub
	// and the GITHUB_TOKEN client is configured. A healthy Flux reconcile is
	// not by itself evidence of a change (see fluxActivity); checking the
	// commit that produced the revision lets the renderer say whether the
	// reconciled commit actually touched the workload or one of its component
	// paths, without having to fetch the diff.
	//
	// Empty when no Kustomization resolved, when the source is not GitHub,
	// when the GITHUB_TOKEN env is unset, or when the lookup itself failed;
	// each non-empty State carries the matching paths or a Reason explaining
	// the degradation. See CommitRelevance for the three-state contract.
	CommitRelevance []CommitRelevance
}

func (e Enrichment) empty() bool {
	return len(e.Nodes) == 0 && len(e.UnhealthyPods) == 0 &&
		len(e.PodLogs) == 0 && len(e.BackendLogs) == 0 &&
		(e.BackendState == "" || e.BackendState == "off" || e.BackendState == "ambient") &&
		len(e.Events) == 0 && len(e.FluxActivity) == 0 && len(e.Ambient) == 0 &&
		len(e.InspectedJobs) == 0 && len(e.Ownership) == 0 &&
		len(e.ContainerDiagnostics) == 0 &&
		len(e.ContainerTerminationMessages) == 0
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
//
// gh is the optional GitHub client used to classify the most recent
// reconciled commit against the workload's Git surface (issue #135). It is
// passed through here so the lookup sits alongside the rest of the
// enrichment (one cluster read per Kustomization, no duplicate fetches);
// nil is the common case (no GITHUB_REPO/GITHUB_TOKEN env), and the
// CommitRelevance slice is left empty in that case.
func (k *kube) Enrich(ctx context.Context, g Group, window time.Duration, cfg *Config, gh *gitHubClient) Enrichment {
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
	var podLogSpecs []podLogSpec
	for _, ns := range g.Namespaces {
		esc := url.PathEscape(ns)

		var pods podList
		if err := k.get(ctx, "/api/v1/namespaces/"+esc+"/pods", &pods); err != nil {
			logf("enrich: pods in %s: %v", ns, err)
		}
		type scoredPod struct {
			desc      string
			score     int // higher = worse health
			restart   int // restart count, surfaced as a finding on its own
			key       string
			container string
			mode      string // log stream to fetch: "current", "previous", or "" to skip
		}
		var unhealthy []scoredPod
		for _, p := range pods.Items {
			seenPods = append(seenPods, podRef{
				Name:        p.Metadata.Name,
				Namespace:   p.Metadata.Namespace,
				Annotations: p.Metadata.Annotations,
				Labels:      p.Metadata.Labels,
				OwnerRefs:   p.Metadata.OwnerReferences,
			})
			key := p.Metadata.Namespace + "/" + p.Metadata.Name
			if p.Status.Phase == "Succeeded" {
				// A completed one-shot job: its container's terminated state is
				// a clean exit, not failure evidence, so neither a diagnostic
				// line nor a log stream is worth shipping for it.
				continue
			}
			for i := range p.Status.ContainerStatuses {
				cs := &p.Status.ContainerStatuses[i]
				if recentlyRestarted(*cs, since) {
					e.RecentRestarts = append(e.RecentRestarts, fmt.Sprintf("%s container %s restarted %d time(s) since %s", key, cs.Name, cs.RestartCount, since.Format(time.RFC3339)))
				}
			}
			unhealthyPod, cs := podEvidence(targetPods[key], p.Status.ContainerStatuses, since)
			if !unhealthyPod {
				continue
			}
			mode := podLogMode(cs)
			reason := stateReason(cs)
			desc := fmt.Sprintf("%s %s", key, p.Status.Phase)
			if reason != "" {
				desc += " (" + reason + ")"
			}
			if cs.RestartCount > 0 {
				desc += fmt.Sprintf(" restarts=%d", cs.RestartCount)
			}
			unhealthy = append(unhealthy, scoredPod{desc: desc, score: podHealthScore(p.Status.Phase, reason, cs.Ready, cs.RestartCount), restart: cs.RestartCount, key: key, container: cs.Name, mode: mode})
			if d := containerReadingLine(key, *cs); d != "" {
				e.ContainerDiagnostics = append(e.ContainerDiagnostics, d)
			}
			if m := containerMessageLine(key, *cs); m != "" {
				e.ContainerTerminationMessages = append(e.ContainerTerminationMessages, m)
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
			if sp.mode != "" {
				parts := strings.SplitN(sp.key, "/", 2)
				podLogSpecs = append(podLogSpecs, podLogSpec{
					Namespace: parts[0],
					Name:      parts[1],
					Container: sp.container,
					Previous:  sp.mode == "previous",
				})
			}
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
	e.ContainerDiagnostics = capList(dedupe(e.ContainerDiagnostics), 8)
	e.ContainerTerminationMessages = capList(dedupe(e.ContainerTerminationMessages), 8)
	// The per-pod concurrency lives on the stack, not on *kube: the SIGTERM
	// shutdown path calls drainBuffer while runFlushLoop's canceled process
	// may still be unwinding, and both paths run Enrich on the same *kube.
	// Writing the value into k would race with fetchPodLogs's goroutines
	// reading it. Passing the normalised value keeps the shared struct
	// immutable across concurrent callers (issue #146).
	logConcurrency := normalizePodLogConcurrency(cfg.PodLogConcurrency)
	e.PodLogs, e.PodLogProvenance = k.fetchPodLogs(ctx, podLogSpecs, logConcurrency)
	if k.logs != nil {
		var res backendLogResult
		var err error
		res, err = k.logs.fetchBackendLogsResult(ctx, g, window, targetPods)
		if err != nil {
			e.BackendState = "error"
			logf("enrich: backend logs: %v", err)
		} else {
			e.BackendLogs = res.Primary
			// Namespace-wide lines (present only when no concrete subject was
			// resolved) are ambient context for ruling things out, never evidence
			// about the failing resource, so they go to Ambient, not BackendLogs.
			e.Ambient = append(e.Ambient, res.Ambient...)
			switch {
			case len(res.Primary) > 0:
				e.BackendState = "ok"
			case len(res.Ambient) > 0:
				// The backend did return lines — it is the no-subject
				// fallback. Rendering this as "empty" would put a false
				// negative in the prompt next to the very lines we just
				// routed to BACKGROUND.
				e.BackendState = "ambient"
			default:
				e.BackendState = "empty"
			}
		}
	} else {
		e.BackendState = "off"
	}
	e.Events = capList(dedupe(e.Events), 8)
	e.FluxActivity = capList(dedupe(e.FluxActivity), 6)
	// Ambient only has to be enough for the model to rule things out.
	e.Ambient = capList(dedupe(e.Ambient), 5)
	// Ownership is built only from data read in this call: the jobs the
	// alerts named and the pods the listing returned. Nothing is derived from
	// names, so a job that merely shares its name with the application it
	// serves is not reported as owned by it.
	jobKeys := make([]string, 0, len(jobTargets))
	for key := range jobTargets {
		jobKeys = append(jobKeys, key)
	}
	sort.Strings(jobKeys)
	for _, key := range jobKeys {
		j := jobTargets[key]
		jkey := j.Namespace + "/" + j.Name
		// The job's parent tail is repeated on each pod it owns so every line
		// describes a complete relationship, even when a group resolves jobs.
		tail := ""
		if o, ok := controllerOwnerRef(j.OwnerRefs); ok {
			tail = " -> " + o.Kind + "/" + o.Name
		}
		e.Ownership = append(e.Ownership, ownershipChain("Job", jkey, j.OwnerRefs, j.Identity))
		for _, p := range seenPods {
			if !jobOwnedBy(*j, podOwner{Labels: p.Labels, OwnerReferences: p.OwnerRefs}) {
				continue
			}
			entry := "Pod/" + p.Namespace + "/" + p.Name
			if id := identityTags(p.Labels, p.Annotations); id != "" {
				entry += " [" + id + "]"
			}
			e.Ownership = append(e.Ownership, entry+" -> Job/"+jkey+tail)
		}
	}
	e.RepoPaths = k.resolveRepoPaths(ctx, seenPods, cfg)
	if gh != nil {
		e.CommitRelevance = k.resolveCommitRelevance(ctx, gh, seenPods)
	}
	return e
}

// resolveCommitRelevance checks, for every Flux Kustomization the pods
// resolved to, whether the commit the Kustomization is currently reconciled
// at actually touches the workload's Git surface. The result is one
// CommitRelevance per unique Kustomization; non-Flux owners (Argo, a
// fallback GITOPS_REPO) are skipped because the GitHub commit API only
// answers the question when the source is GitHub.
//
// The lookup is best-effort and never blocks the digest: a nil gh, a
// non-GitHub URL, an unparseable revision, or any API error degrades to
// State == "unknown" with a one-line Reason, leaving RepoPaths and the
// rest of the evidence intact. The function does not touch RepoPaths
// itself — it only reads the pods' annotations to find the Kustomizations
// they belong to, so a future KustomizationTopology lookup (#134) can
// populate ComponentPaths from the same Kustomization read.
//
// Component paths default to nil because the topology signal is not yet
// available in this branch; once #134 lands, the caller can read the
// spec.components out of the same Kustomization read and pass them in.
func (k *kube) resolveCommitRelevance(ctx context.Context, gh *gitHubClient, seenPods []podRef) []CommitRelevance {
	if gh == nil {
		return nil
	}
	if len(seenPods) == 0 {
		return nil
	}
	type key struct{ ns, name string }
	seen := map[key]bool{}
	var out []CommitRelevance
	for _, p := range seenPods {
		kustom := p.Annotations["kustomize.toolkit.fluxcd.io/name"]
		if kustom == "" {
			continue
		}
		ns := p.Annotations["kustomize.toolkit.fluxcd.io/namespace"]
		if ns == "" {
			ns = p.Namespace
		}
		kk := key{ns: ns, name: kustom}
		if seen[kk] {
			continue
		}
		seen[kk] = true
		out = append(out, k.fluxKustomizationRelevance(ctx, gh, ns, kustom))
	}
	return out
}

// fluxKustomizationRelevance reads one Flux Kustomization, resolves its
// GitRepository + path, and (when the source is GitHub) classifies the
// commit it is currently reconciled at against the workload's path. The
// returned CommitRelevance always carries enough context to render even
// when the lookup degraded to "unknown".
func (k *kube) fluxKustomizationRelevance(ctx context.Context, gh *gitHubClient, ns, name string) CommitRelevance {
	rel := CommitRelevance{State: commitRelevanceUnknown}
	if k == nil {
		rel.Reason = "no Kubernetes client available for this cluster"
		return rel
	}
	var kuz struct {
		Spec struct {
			Path      string `json:"path"`
			SourceRef struct {
				Name string `json:"name"`
				Kind string `json:"kind"`
			} `json:"sourceRef"`
			Components []string `json:"components"`
		} `json:"spec"`
		Status struct {
			LastAppliedRevision string `json:"lastAppliedRevision"`
		} `json:"status"`
	}
	p := "/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/" + ns + "/kustomizations/" + name
	if err := k.get(ctx, p, &kuz); err != nil {
		rel.Reason = "Flux Kustomization not found: " + truncate(err.Error(), 160)
		return rel
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
		rel.Reason = "Flux GitRepository not readable: " + truncate(safeErr(err), 160)
		return rel
	}
	rel.RepoURL = src.Spec.URL
	rel.WorkloadPath = kuz.Spec.Path
	rel.ComponentPaths = kuz.Spec.Components
	rel.Revision = kuz.Status.LastAppliedRevision
	return classifyCommit(ctx, gh, rel.RepoURL, rel.Revision, rel.WorkloadPath, rel.ComponentPaths)
}

// safeErr renders an err as a string without panicking on nil.
func safeErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
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
			OwnerRefs:     job.Metadata.OwnerReferences,
			Identity:      identityTags(job.Metadata.Labels, job.Metadata.Annotations),
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
		// Ownership was determinable but no reference pointed at this job.
		return false
	}
	// No Job owner reference at all, so ownership cannot be established.
	if j.ControllerKey != "" && j.LabelValue != "" {
		return p.Labels[j.ControllerKey] == j.LabelValue
	}
	return false
}

// controllerOwnerRef picks the owner reference to chain from. A reference
// whose controller flag is set is the owner the API means: when an object
// carries both a controller and a non-controller reference, the non-
// controller one is a secondary association (e.g. a pod listed under the job
// it is a backup of) and chaining from it would misreport the parent. If
// none is flagged, the first reference is the only claim we have and is used.
func controllerOwnerRef(refs []ownerRef) (ownerRef, bool) {
	var fallback ownerRef
	fbSet := false
	for _, r := range refs {
		if r.Kind == "" && r.Name == "" {
			continue
		}
		if r.Controller != nil && *r.Controller {
			return r, true
		}
		if !fbSet {
			fallback, fbSet = r, true
		}
	}
	return fallback, fbSet
}

// identityTags selects the labels/annotations that identify what an object is,
// in preference order, and renders them as "key=value" pairs. A whitelist,
// not a dump: high-cardinality keys (instance hashes, owner UIDs, hash
// suffixes) would add noise without telling the model what the object is, so
// they are never shown. Values are workload-authored; callers render them
// untrusted.
var identityLabelKeys = []string{
	"app.kubernetes.io/managed-by", "app.kubernetes.io/name", "app.kubernetes.io/component",
	"app.kubernetes.io/part-of", "app.kubernetes.io/instance", "app.kubernetes.io/version",
	"app", "component", "controller", "role",
}

var identityAnnotationKeys = []string{
	"kustomize.toolkit.fluxcd.io/name", "kustomize.toolkit.fluxcd.io/namespace",
	"argocd.argoproj.io/instance",
}

func identityTags(labels, annotations map[string]string) string {
	var out []string
	seen := map[string]bool{}
	add := func(k, v string) {
		if v == "" || seen[k] {
			return
		}
		seen[k] = true
		out = append(out, k+"="+v)
	}
	for _, k := range identityLabelKeys {
		add(k, labels[k])
	}
	for _, k := range identityAnnotationKeys {
		add(k, annotations[k])
	}
	return strings.Join(out, ",")
}

// ownershipChain builds one compact subject-relationship entry,
// "Kind/ns/name" optionally followed by " -> <owner kind>/<owner name>" when
// the object carries a controller owner reference, and a bracketed identity
// string when curated identifying labels/annotations are present. An object
// with no owner references produces no parent hop: nothing is fabricated, and
// a job that shares a name with its application is not claimed to be owned by
// it.
func ownershipChain(kind, nsName string, refs []ownerRef, identity string) string {
	s := kind + "/" + nsName
	if o, ok := controllerOwnerRef(refs); ok {
		s += " -> " + o.Kind + "/" + o.Name
	}
	if identity != "" {
		s += " [" + identity + "]"
	}
	return s
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

// DefaultPodLogConcurrency caps how many per-pod log GETs run at once inside
// a single fetchPodLogs call. The reads run in parallel so one stalled
// apiserver cannot serialise the remaining reads of a flush (issue #146);
// the cap keeps the blast radius bounded to what the API server should
// absorb during one Enrich. Exported so main.go can derive its envInt
// default from the same constant — bumping one without the other would
// drift silently.
const DefaultPodLogConcurrency = 4

// normalizePodLogConcurrency normalises the configured value: unset or
// non-positive falls back to the default, and it is clamped to the 8-pod cap
// so a misconfiguration can never open more concurrent log reads than a group
// can name.
func normalizePodLogConcurrency(n int) int {
	if n <= 0 {
		n = DefaultPodLogConcurrency
	}
	if n > 8 {
		n = 8
	}
	return n
}

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

// podLogMode picks the log stream that holds the failure evidence for one
// container, or "" when no log stream is worth fetching:
//
//   - a terminated container that has not restarted (the one-shot Job case)
//     carries its failure in its *current* log — no previous instance ever
//     existed for it, so previous=true would 404;
//   - a container whose previous instance actually exists (restartCount > 0)
//     — a CrashLoop or a recovered one — has its last failed run in the
//     previous instance, so previous=true is the relevant failure evidence;
//   - a container that is still running (a live process, ready or not) has
//     only a current log, so it is fetched as current;
//   - anything else (a clean exit, a container that is waiting or has not
//     started a run yet) has no failure log to fetch, so "" — previous is
//     never the fallback, because a previous instance may not exist at all.
func podLogMode(cs *containerStatus) string {
	switch {
	case cs.State.Terminated != nil && cs.State.Terminated.ExitCode != 0:
		return "current"
	case cs.RestartCount > 0:
		return "previous"
	case cs.State.Terminated != nil:
		// A clean (exit 0) terminated run is not failure evidence.
		return ""
	case cs.State.Running != nil:
		return "current"
	}
	return ""
}

// recentlyRestarted reports whether a container's last restart happened
// inside the window. lastState is the container's previous instance, so its
// finishedAt stamps the restart; a zero time means no restart has occurred.
func recentlyRestarted(cs containerStatus, since time.Time) bool {
	t := cs.LastState.Terminated
	return cs.RestartCount > 0 && t != nil && !t.FinishedAt.IsZero() && t.FinishedAt.After(since)
}

// stateReason returns the reason of a container's current state if it is
// waiting or terminated; a running state carries no reason.
func stateReason(cs *containerStatus) string {
	if cs.State.Waiting != nil {
		return cs.State.Waiting.Reason
	}
	if cs.State.Terminated != nil {
		return cs.State.Terminated.Reason
	}
	return ""
}

// podEvidence reports whether a pod is unhealthy and which of its containers
// to describe and log. Every container is scanned — not just the first, and
// not the apiserver's default container — and the most conclusive is
// returned, so a multi-container pod is diagnosed through the one that
// actually failed:
//
//   - a terminated container with a non-zero exit code: a one-shot failure,
//     the Job case this issue is about. Without this branch a failed Job pod
//     that terminated once and never restarted has no waiting state and no
//     restart, and would be read as healthy;
//   - a waiting (stuck) container: the CrashLoop and image-pull shapes;
//   - a container that is not ready in its current run: the pod is not
//     actually healthy, whether or not the alert named it;
//   - a container with a previous instance (restartCount > 0): its previous
//     run's log is the evidence — listed for a pod the alert named, or one
//     that restarted inside the window; an unrelated recovered pod is not
//     fished out, which keeps the recovered-pod rule the old first-container
//     loop applied.
//
// A pod whose containers are all healthy, reason-free and un-restarted is
// not unhealthy; a Succeeded pod never gets here (the caller skips it).
func podEvidence(isTarget bool, statuses []containerStatus, since time.Time) (bool, *containerStatus) {
	var failed, waiting, unready, restarted *containerStatus
	for i := range statuses {
		cs := &statuses[i]
		switch {
		case cs.State.Terminated != nil && cs.State.Terminated.ExitCode != 0:
			if failed == nil {
				failed = cs
			}
		case cs.State.Waiting != nil:
			if waiting == nil {
				waiting = cs
			}
		case !cs.Ready:
			if unready == nil {
				unready = cs
			}
		case cs.RestartCount > 0 && (isTarget || recentlyRestarted(*cs, since)):
			if restarted == nil {
				restarted = cs
			}
		}
	}
	switch {
	case failed != nil:
		return true, failed
	case waiting != nil:
		return true, waiting
	case unready != nil:
		return true, unready
	case restarted != nil:
		return true, restarted
	}
	return false, nil
}

// terminatedEvidence returns the terminated state that is the failure
// evidence for a container, or nil when none is a failure:
//
//   - a terminated current run (the one-shot Job case) is the evidence
//     directly;
//   - a container that is stuck waiting (a CrashLoop) whose previous
//     instance terminated is the evidence — the last failed run is the
//     failure, not the current waiting state.
//
// A clean exit (exit code 0) is not a failure, so it yields no line; the
// caller checks the exit code.
func terminatedEvidence(cs containerStatus) *terminatedState {
	if cs.State.Terminated != nil {
		return cs.State.Terminated
	}
	if cs.State.Waiting != nil && cs.LastState.Terminated != nil {
		return cs.LastState.Terminated
	}
	return nil
}

// containerReadingLine renders the structured reading this service makes
// itself for a failed container: the exit code, termination reason and
// finish time. It is deliberately message-free: the container's own
// termination message is workload-authored and travels in
// ContainerTerminationMessages, where the renderer fences it (the split
// issue #128's review asked for). Rendered outside the untrusted fence,
// like pod phases and node conditions, because it is this service's reading
// rather than a quote — fencing it would tell the model to distrust it.
// A clean exit (exit code 0) is not a failure, so it produces no line.
func containerReadingLine(key string, cs containerStatus) string {
	t := terminatedEvidence(cs)
	if t == nil || t.ExitCode == 0 {
		return ""
	}
	line := fmt.Sprintf("%s: container %s terminated exit=%d", key, cs.Name, t.ExitCode)
	if t.Reason != "" {
		line += " reason=" + t.Reason
	}
	if !t.FinishedAt.IsZero() {
		line += " at " + t.FinishedAt.Format(time.RFC3339)
	}
	return line
}

// containerMessageLine renders a failed container's own termination message
// for the fenced block. It repeats the pod key and container name so the
// fenced quote stands on its own: a line of workload text with no
// attribution would read as the service's own assertion. It produces no
// line when the container left no message — a clean exit (exit code 0) is
// not a failure, and a failed run that said nothing has nothing to fence.
func containerMessageLine(key string, cs containerStatus) string {
	t := terminatedEvidence(cs)
	if t == nil || t.ExitCode == 0 || t.Message == "" {
		return ""
	}
	return fmt.Sprintf("%s: container %s message: %s", key, cs.Name, truncate(t.Message, 160))
}

// podLogSpec is one log fetch: the pod, the container whose log is wanted,
// and which stream. A container is named explicitly rather than left to the
// apiserver's default-container choice, so a multi-container pod is always
// logged through the container that actually failed.
type podLogSpec struct {
	Namespace string
	Name      string
	Container string
	Previous  bool
}

// podLogProvenance tells renderEvidence and Discord delivery which container
// produced the log and which stream it came from. Without this a one-shot
// Job's current log would be mislabelled "previous container tail" — the
// motivating bug of issue #128's review.
type podLogProvenance struct {
	Container string
	Stream    string // "current" or "previous"
}

// fetchPodLogs retrieves the tail of each pod's failure-evidence log. It
// returns a map keyed by "namespace/name" and a parallel provenance map
// describing the container and stream ("current"/"previous") each came
// from. The container and stream that hold the failure evidence are
// carried per-entry, so a multi-container pod is answered by the
// container that failed rather than the apiserver's default, and the
// renderer does not falsely label a current log as "previous container
// tail". A failure to fetch one pod's log is non-fatal: the rest of the
// evidence, and the digest, still ship.
//
// The per-pod GETs run under a bounded semaphore rather than strictly in
// series: one stalled apiserver on pod 1 must not serialise the remaining
// reads of a flush and hold the flush loop — and any SIGTERM drain —
// behind the worst pod times up-to-8. Bounded parallelism keeps the
// API-server-pressure trade-off the serial per-group Enrich ordering makes;
// it is a within-group cap, not a reason to fetch one log at a time
// (issue #146).
//
// The semaphore caps the number of reads in flight; one goroutine per pod
// is still spawned, and any excess sit parked inside the semaphore's
// acquire until an in-flight read releases. Acquiring the slot inside the
// goroutine (rather than on the dispatcher's stack) means a goroutine that
// never reaches its release cannot deadlock the dispatcher — the worst
// case is that goroutine leaks until ctx fires, and the others proceed
// once the cap frees up. The cap is clamped here, not just in Enrich:
// direct callers (tests, future paths) must not be able to opt out of the
// 8-pod upper bound the file-level invariant promises.
//
// concurrency is taken by value so the caller can normalise the configured
// cap once and pass it in — keeping *kube immutable across concurrent
// Enrich calls. The SIGTERM drain path runs while a canceled runFlushLoop
// process may still be unwinding; both paths share the same *kube and the
// goroutines spawned here read concurrency, so any writeable field would
// race with itself.
func (k *kube) fetchPodLogs(ctx context.Context, specs []podLogSpec, concurrency int) (map[string]string, map[string]podLogProvenance) {
	if len(specs) == 0 || k.hc == nil {
		return nil, nil
	}

	concurrency = normalizePodLogConcurrency(concurrency)

	logs := make(map[string]string)
	prov := make(map[string]podLogProvenance)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for _, spec := range specs {
		key := spec.Namespace + "/" + spec.Name
		stream := "current"
		if spec.Previous {
			stream = "previous"
		}
		query := url.Values{}
		query.Set("tailLines", strconv.Itoa(podLogTail))
		if spec.Container != "" {
			query.Set("container", spec.Container)
		}
		if spec.Previous {
			query.Set("previous", "true")
		}
		path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log?%s", spec.Namespace, spec.Name, query.Encode())

		wg.Add(1)
		go func(key, path string) {
			defer wg.Done()
			// Acquire inside the goroutine: a leaked slot here can't
			// stall the dispatcher, and the wait error path returns
			// without writing to logs so the bounded count still holds.
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			req, err := http.NewRequestWithContext(ctx, "GET", k.base+path, nil)
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+k.token)
			resp, err := k.hc.Do(req)
			if err != nil {
				logf("enrich: pod logs (%s): %v", key, err)
				return
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				return
			}
			data, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if err != nil {
				return
			}
			// Write to the shared map under the lock: only the dispatch is
			// concurrent, the 4096-byte cap and secret stripping are
			// unchanged from the serial walk.
			mu.Lock()
			logs[key] = stripSecrets(strings.TrimSpace(string(data)))
			mu.Unlock()
		}(key, path)
		// Provenance is derived from the spec, so it is recorded before
		// the read returns. If the read fails the entry is simply absent
		// from logs and the renderer never sees it.
		prov[key] = podLogProvenance{Container: spec.Container, Stream: stream}
	}
	wg.Wait()
	return logs, prov
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
// annotations the GitOps tools use to identify their owner. Labels and
// OwnerRefs are carried for the ownership chain.
type podRef struct {
	Name        string
	Namespace   string
	Annotations map[string]string
	Labels      map[string]string
	OwnerRefs   []ownerRef
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
