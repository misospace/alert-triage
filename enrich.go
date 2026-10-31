package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
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
	body, err := readCappedBody(resp.Body, kubeBodyCap)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// kubeBodyCap bounds how much of an apiserver GET response (pods, events,
// nodes, PVs) we'll buffer before failing the read. It aliases metricsBodyCap
// (4 MiB) so the bulk read paths share one ceiling that cannot drift. An
// uncapped list from a misbehaving API server or proxy would otherwise force
// the whole body into memory on whichever goroutine gathered evidence.
const kubeBodyCap = metricsBodyCap

// podList is the pod collection for a namespace, carrying everything a
// permission or storage hypothesis can be grounded in: the declared execution
// identity (pod- and container-level securityContext) and which
// PersistentVolumeClaims each container mounts. Only read access to pod
// metadata is used; this is spec/status as the API served it — the API does
// not expose on-disk file ownership or mode, and nothing here claims to.
type podList struct {
	Items []podItem `json:"items"`
}

// podItem is one pod as the apiserver returns it. The declared identity and
// mounts live under spec (spec.securityContext, spec.containers[].securityContext
// and spec.containers[].volumeMounts), while runtime state lives under
// status.containerStatuses; reading either from the other yields an empty shape
// the API never returns.
type podItem struct {
	Metadata struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		Labels          map[string]string `json:"labels"`
		Annotations     map[string]string `json:"annotations"`
		OwnerReferences []ownerRef        `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		NodeName   string          `json:"nodeName"`
		Security   *containerID    `json:"securityContext"`
		Containers []containerSpec `json:"containers"`
		Volumes    []podVolumeItem `json:"volumes"`
	} `json:"spec"`
	Status struct {
		Phase             string            `json:"phase"`
		ContainerStatuses []containerStatus `json:"containerStatuses"`
	} `json:"status"`
}

// containerSpec is the declared half of a container: its name, the
// securityContext the spec declares, and the volumeMounts it references. The
// runtime half stays in containerStatus.
type containerSpec struct {
	Name         string            `json:"name"`
	Security     *containerID      `json:"securityContext"`
	VolumeMounts []volumeMountItem `json:"volumeMounts"`
}

// podVolumeItem maps a volume name to its PVC claim, the only volume kind that
// matters for permission hypotheses. Non-PVC volumes carry no claim and are
// dropped, so a pod with only emptyDir mounts has an empty map, not a claim
// that was guessed.
type podVolumeItem struct {
	Name string `json:"name"`
	PVC  *struct {
		ClaimName string `json:"claimName"`
	} `json:"persistentVolumeClaim"`
}

// volumeMountItem is one spec.containers[].volumeMounts entry: the volume name
// (matched against the pod's volumes) and where it lands.
type volumeMountItem struct {
	VolumeName string `json:"name"`
	MountPath  string `json:"mountPath"`
	ReadOnly   bool   `json:"readOnly"`
}

// containerID holds the declared execution identity fields relevant to file
// access. Fields are pointer-typed so an absent value reads as "unset" rather
// than 0 (root) — a pod that never declared runAsUser must not be reported as
// running as root.
type containerID struct {
	RunAsUser    *int64 `json:"runAsUser"`
	RunAsGroup   *int64 `json:"runAsGroup"`
	FSGroup      *int64 `json:"fsGroup"`
	RunAsNonRoot *bool  `json:"runAsNonRoot"`
}

func idInt(v *int64) string {
	if v == nil {
		return "unset"
	}
	return strconv.Itoa(int(*v))
}

// idBool keeps the three-state value of a pointer bool: unset, true, false.
// Collapsing unset to "false" would invent a declared value the spec never set.
func idBool(v *bool) string {
	if v == nil {
		return "unset"
	}
	if *v {
		return "true"
	}
	return "false"
}

func (c *containerID) format() (runAsUser, runAsGroup, fsGroup, runAsNonRoot string) {
	if c == nil {
		return "unset", "unset", "unset", "unset"
	}
	return idInt(c.RunAsUser), idInt(c.RunAsGroup), idInt(c.FSGroup), idBool(c.RunAsNonRoot)
}

// effective returns the identity a container actually declares, following the
// Kubernetes precedence: the container's securityContext overrides the pod's
// field by field, and a field neither sets stays unset. It is the declared
// identity only — the API says nothing about what the image runs as when no
// value is set, so nothing is guessed. A nil container (the spec container the
// alert named was not found) still yields the pod-level identity.
func (c *containerSpec) effective(pod *containerID) containerID {
	e := containerID{}
	var sec, podID *containerID
	if c != nil {
		sec = c.Security
	}
	podID = pod
	if sec != nil && sec.RunAsUser != nil {
		e.RunAsUser = sec.RunAsUser
	} else if podID != nil {
		e.RunAsUser = podID.RunAsUser
	}
	if sec != nil && sec.RunAsGroup != nil {
		e.RunAsGroup = sec.RunAsGroup
	} else if podID != nil {
		e.RunAsGroup = podID.RunAsGroup
	}
	if podID != nil {
		e.FSGroup = podID.FSGroup
	}
	if sec != nil && sec.RunAsNonRoot != nil {
		e.RunAsNonRoot = sec.RunAsNonRoot
	} else if podID != nil {
		e.RunAsNonRoot = podID.RunAsNonRoot
	}
	return e
}

// podMount is one container's mount of a claim: the path and whether the mount
// is read-only. The claim name is the map key on containerMounts' and mount's
// results.
type podMount struct {
	Container string
	Path      string
	ReadOnly  bool
}

// pvcVolumes maps the pod's volume names to their PVC claim. Only PVC volumes
// carry a claim; every other volume kind (emptyDir, hostPath, ...) is dropped,
// so a pod with only emptyDir mounts has no claim, not one that was guessed.
func (p podItem) pvcVolumes() map[string]string {
	out := map[string]string{}
	for _, v := range p.Spec.Volumes {
		if v.PVC != nil && v.PVC.ClaimName != "" {
			out[v.Name] = v.PVC.ClaimName
		}
	}
	return out
}

// containerMounts maps one spec container's volumeMounts to the PVC claims it
// references, keyed by claim name. Unknown volume names yield no entry.
func (p podItem) containerMounts(name string) map[string]podMount {
	vols := p.pvcVolumes()
	out := map[string]podMount{}
	for _, c := range p.Spec.Containers {
		if c.Name != name {
			continue
		}
		for _, m := range c.VolumeMounts {
			if claim, ok := vols[m.VolumeName]; ok {
				out[claim] = podMount{Container: c.Name, Path: m.MountPath, ReadOnly: m.ReadOnly}
			}
		}
	}
	return out
}

// mount is the union of all containers' claim mounts, keyed by claim name; the
// first container that mounts a claim wins. It backs claims, which is what
// sibling discovery matches on.
func (p podItem) mount() map[string]podMount {
	out := map[string]podMount{}
	for _, c := range p.Spec.Containers {
		for claim, m := range p.containerMounts(c.Name) {
			if _, ok := out[claim]; !ok {
				out[claim] = m
			}
		}
	}
	return out
}

// claims returns the set of PVC claims the pod's containers mount.
func (p podItem) claims() map[string]bool {
	out := map[string]bool{}
	for claim := range p.mount() {
		out[claim] = true
	}
	return out
}

// failing reports the containers that are not currently in the running state.
// For a non-Succeeded pod every non-running container state (CrashLoopBackOff,
// OOMKilled, ImagePullBackOff, a terminated crash, ...) is a failing container;
// a healthy container in a Running pod is in the running state and is not
// reported. Succeeded pods are never failing.
func (p podItem) failing() map[string]bool {
	if p.Status.Phase == "Succeeded" {
		return nil
	}
	out := map[string]bool{}
	for _, cs := range p.Status.ContainerStatuses {
		if cs.State.Running == nil {
			out[cs.Name] = true
		}
	}
	return out
}

// ready summarizes the pod's container readiness in one string.
func (p podItem) ready() string {
	var running, ready, total int
	for _, cs := range p.Status.ContainerStatuses {
		total++
		if cs.State.Running != nil {
			running++
		}
		if cs.Ready {
			ready++
		}
	}
	return fmt.Sprintf("%d/%d ready, %d running", ready, total, running)
}

// containerSpec returns the declared spec entry for a container name, or nil
// when the spec does not carry it. The runtime status may name a container the
// spec read did not return, in which case there is no declared identity to read.
func (p podItem) containerSpec(name string) *containerSpec {
	for i := range p.Spec.Containers {
		if p.Spec.Containers[i].Name == name {
			return &p.Spec.Containers[i]
		}
	}
	return nil
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
	// PodID carries the declared execution identity and PVC mount
	// relationships of the pods the alerts resolved to (a named pod, or a pod
	// owned by a named Job), so permission hypotheses can be grounded in live
	// spec data. The identity is what the pod declared — the API does not
	// expose on-disk file ownership or mode, and nothing here claims to.
	// Entries are keyed "ns/pod" so the digest names the subject.
	PodID map[string]string
	// PVCSiblings is comparison context: other pods in the alert's namespaces
	// that mount a claim one of the alert's target pods also mounts, with their
	// phase/readiness. It lets a healthy same-claim sibling distinguish "the
	// mover failed" from "the serving workload is also unhealthy", without
	// claiming the sibling is the application — a same-claim mount is a
	// relationship, not proof of what the claim serves. Claim names are
	// namespace-local, so a sibling is only matched inside its own namespace.
	PVCSiblings []string
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
	// BackendScoped records whether the backend-log query was bounded to a
	// resolved subject pod rather than falling back to the namespace. It keeps
	// the "empty" state honest: only a subject-scoped query may claim it
	// returned no lines for the subject (issue #136 review).
	BackendScoped bool
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
	// SubjectPods is the subset of UnhealthyPods that belongs to a resolved
	// alert subject: a pod an alert named, or a pod owned by a Job an alert
	// named. Only this subset is guaranteed subject-scoped, so only it may be
	// presented as DIRECT SUBJECT EVIDENCE. UnhealthyPods is the full
	// namespace scan and is context.
	SubjectPods []string
	// ContextPods is UnhealthyPods minus SubjectPods: namespace-wide pod
	// failure state not known to concern the alert.
	ContextPods []string
	// SubjectPodObserved records whether at least one resolved subject pod was
	// actually found in the namespace listing. When false, the Subject* fields
	// are empty because no subject pod was inspected, not because the subject
	// was healthy; the renderer must say so rather than emit a health negative
	// scoped to a subject it never saw (issue #136 review).
	SubjectPodObserved bool
	// SubjectRestarts and ContextRestarts split RecentRestarts the same way.
	SubjectRestarts []string
	ContextRestarts []string
	// SubjectContainerDiagnostics and ContextContainerDiagnostics split
	// ContainerDiagnostics the same way: only a resolved subject's structured
	// container reading is direct evidence.
	SubjectContainerDiagnostics []string
	ContextContainerDiagnostics []string
	// SubjectContainerTerminationMessages and ContextContainerTerminationMessages
	// split ContainerTerminationMessages the same way.
	SubjectContainerTerminationMessages []string
	ContextContainerTerminationMessages []string
	// SubjectPodLogs and ContextPodLogs split PodLogs the same way: only a
	// resolved subject's logs are direct evidence. Keys match PodLogs, and the
	// matching Subject/ContextPodLogProvenance carries the container and stream.
	SubjectPodLogs          map[string]string
	ContextPodLogs          map[string]string
	SubjectPodLogProvenance map[string]podLogProvenance
	ContextPodLogProvenance map[string]podLogProvenance
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
	// KustomizationTopology is the composition evidence for the Flux
	// Kustomizations those pods resolved to: one compact record per
	// Kustomization carrying its name, source, spec.path, the
	// spec.components paths as declared, and spec.dependsOn. The record is
	// evidence of the composition, not of its contents: component file
	// contents are not read, a missing section renders as an explicit
	// "none", and a record is attached only to the Kustomization the pod
	// resolved to, never to every Kustomization in the namespace.
	KustomizationTopology []string
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

// sameClaimSibMax bounds the same-claim sibling list. A healthy sibling on the
// same claim is the comparison that tells the operator whose failure it is,
// but listing the whole namespace is exactly the namespace dump this evidence
// is meant to avoid.
const sameClaimSibMax = 3

// identityFields renders a declared identity as the key=value list the prompt
// and evidence use, preserving "unset" for fields neither the pod nor the
// container declared.
func identityFields(id containerID) string {
	u, gr, fg, nr := id.format()
	return fmt.Sprintf("runAsUser=%s runAsGroup=%s fsGroup=%s runAsNonRoot=%s", u, gr, fg, nr)
}

// podIdentities assembles the Enrichment.PodID lines. It works from the pods
// already gathered for the group, so it adds no requests and no permissions:
// the same read-only GETs as the rest of Enrich. For each target pod, one line
// per failing container: the container, its effective declared securityContext
// (Kubernetes precedence: the container's securityContext overrides the pod's
// field by field, unset stays unset), and the PVC claims its containers mount
// with the mount paths. The identity is the declared identity only — the
// Kubernetes API does not expose on-disk file ownership or mode, and no line
// claims to know it.
func podIdentities(targetPods map[string]*podItem) map[string]string {
	out := map[string]string{}
	keys := sortedKeys(targetPods)
	for _, key := range keys {
		p := targetPods[key]
		if p == nil {
			continue // the alert named a pod the namespace list never returned
		}
		failing := p.failing()
		names := sortedKeys(failing)
		if len(names) == 0 {
			continue
		}
		var b strings.Builder
		b.WriteString(key)
		for i, n := range names {
			if i > 0 {
				b.WriteString("; ")
			}
			id := p.containerSpec(n).effective(p.Spec.Security)
			fmt.Fprintf(&b, "container %s (declared: %s)", n, identityFields(id))
			claims := p.containerMounts(n)
			claimNames := sortedKeys(claims)
			var mounts []string
			for _, c := range claimNames {
				m := claims[c]
				mode := "read-write"
				if m.ReadOnly {
					mode = "read-only"
				}
				mounts = append(mounts, c+" at "+m.Path+" ("+mode+")")
			}
			if len(mounts) > 0 {
				b.WriteString(", mounts " + strings.Join(mounts, ", "))
			}
		}
		out[key] = b.String()
	}
	return out
}

// sameClaimTargets is the set of PVC claims mounted by the target pods in one
// namespace. Claim names are namespace-local, so matching must be scoped to the
// namespace a pod lives in; a claim named "data" in ns-a and one named "data"
// in ns-b are unrelated objects and must not be conflated.
func sameClaimTargets(targetPods map[string]*podItem, namespace string) map[string]bool {
	out := map[string]bool{}
	for _, p := range targetPods {
		if p == nil || p.Metadata.Namespace != namespace {
			continue
		}
		for claim := range p.claims() {
			out[claim] = true
		}
	}
	return out
}

// siblingClaimDetail describes the containers of a same-claim sibling that
// actually mount the matched claim: each container's effective declared
// identity and its mount path/read-only state. It is the comparison the
// permission hypothesis needs — the mover's declared UID/GID/mount beside the
// serving workload's on the same claim — and only containers that mount the
// claim are listed, so a multi-container sibling does not imply the others
// touch the volume. Returns "" when the spec read carried no matching mount.
func siblingClaimDetail(p *podItem, claim string) string {
	var parts []string
	for i := range p.Spec.Containers {
		c := &p.Spec.Containers[i]
		m, ok := p.containerMounts(c.Name)[claim]
		if !ok {
			continue
		}
		mode := "read-write"
		if m.ReadOnly {
			mode = "read-only"
		}
		parts = append(parts, fmt.Sprintf("container %s (declared: %s), %s at %s (%s)",
			c.Name, identityFields(c.effective(p.Spec.Security)), claim, m.Path, mode))
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (e Enrichment) empty() bool {
	return len(e.Nodes) == 0 && len(e.UnhealthyPods) == 0 &&
		len(e.PodID) == 0 && len(e.PVCSiblings) == 0 &&
		len(e.PodLogs) == 0 && len(e.BackendLogs) == 0 &&
		(e.BackendState == "" || e.BackendState == "off" || e.BackendState == "ambient") &&
		len(e.Events) == 0 && len(e.FluxActivity) == 0 && len(e.Ambient) == 0 &&
		len(e.InspectedJobs) == 0 && len(e.Ownership) == 0 &&
		len(e.ContainerDiagnostics) == 0 &&
		len(e.ContainerTerminationMessages) == 0 &&
		len(e.KustomizationTopology) == 0
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
	// targetPodItems carries the full pod object for every target, filled from
	// the namespace listings below. It is what the declared identity and PVC
	// relationships are read from; a target the listing never returned stays
	// nil and contributes no identity line rather than a guessed one.
	targetPodItems := map[string]*podItem{}
	for _, a := range g.Alerts {
		if a.Labels["pod"] != "" && a.namespace() != "" {
			key := a.namespace() + "/" + a.Labels["pod"]
			targetPods[key] = true
			targetPodItems[key] = nil
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
	// sibSeen dedupes same-claim siblings across namespaces by claim+pod key;
	// the cap is global so a group spanning many namespaces does not turn the
	// sibling list into a namespace dump.
	sibSeen := map[string]bool{}
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
		// Promote the pods owned by a job the group's alerts named into the
		// direct-target set before scoring, so a job-owned pod is recognised as
		// a subject while its state, logs and termination are recorded — not
		// only when the post-scan sort decides which pods survive truncation.
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
		var unhealthy []scoredPod
		for pi := range pods.Items {
			p := &pods.Items[pi]
			seenPods = append(seenPods, podRef{
				Name:        p.Metadata.Name,
				Namespace:   p.Metadata.Namespace,
				Annotations: p.Metadata.Annotations,
				Labels:      p.Metadata.Labels,
				OwnerRefs:   p.Metadata.OwnerReferences,
			})
			key := p.Metadata.Namespace + "/" + p.Metadata.Name
			if targetPods[key] {
				targetPodItems[key] = p
			}
			// Record that a resolved subject was actually seen, before the
			// Succeeded skip: a completed one-shot pod is still a subject we
			// inspected, and its absence from the Subject* findings is then a
			// true negative rather than "nothing was looked at".
			if targetPods[key] {
				e.SubjectPodObserved = true
			}
			if p.Status.Phase == "Succeeded" {
				// A completed one-shot job: its container's terminated state is
				// a clean exit, not failure evidence, so neither a diagnostic
				// line nor a log stream is worth shipping for it.
				continue
			}
			// Only a pod an alert named, or a pod owned by a Job an alert
			// named, is a resolved subject. Everything else in the namespace is
			// context, so the renderer never promotes namespace noise to
			// DIRECT SUBJECT EVIDENCE (issue #136 review).
			isSubject := targetPods[key]
			for i := range p.Status.ContainerStatuses {
				cs := &p.Status.ContainerStatuses[i]
				if recentlyRestarted(*cs, since) {
					line := fmt.Sprintf("%s container %s restarted %d time(s) since %s", key, cs.Name, cs.RestartCount, since.Format(time.RFC3339))
					e.RecentRestarts = append(e.RecentRestarts, line)
					if isSubject {
						e.SubjectRestarts = append(e.SubjectRestarts, line)
					} else {
						e.ContextRestarts = append(e.ContextRestarts, line)
					}
				}
			}
			unhealthyPod, cs := podEvidence(isSubject, p.Status.ContainerStatuses, since)
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
				if isSubject {
					e.SubjectContainerDiagnostics = append(e.SubjectContainerDiagnostics, d)
				} else {
					e.ContextContainerDiagnostics = append(e.ContextContainerDiagnostics, d)
				}
			}
			if m := containerMessageLine(key, *cs); m != "" {
				e.ContainerTerminationMessages = append(e.ContainerTerminationMessages, m)
				if isSubject {
					e.SubjectContainerTerminationMessages = append(e.SubjectContainerTerminationMessages, m)
				} else {
					e.ContextContainerTerminationMessages = append(e.ContextContainerTerminationMessages, m)
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
			if targetPods[sp.key] {
				e.SubjectPods = append(e.SubjectPods, sp.desc)
			} else {
				e.ContextPods = append(e.ContextPods, sp.desc)
			}
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

		// Same-claim siblings: other pods in this namespace that mount a claim
		// one of the alert's target pods in the same namespace mounts. The
		// comparison is the diagnostic for permission failures: a mover that
		// ran as a non-root UID against a claim whose data an application wrote
		// as root is a hypothesis the spec alone supports, and a healthy
		// sibling on the same claim tells the operator the failure is the
		// mover, not the storage.
		//
		// Siblings are never labelled as the application. They mount the same
		// claim; what workloads live on it is a relationship only the operator
		// knows, and the prompt says so. Claims are namespace-local, so the
		// target set is scoped to this namespace.
		targetClaims := sameClaimTargets(targetPodItems, ns)
		for pi := range pods.Items {
			p := &pods.Items[pi]
			if targetPods[p.Metadata.Namespace+"/"+p.Metadata.Name] {
				continue
			}
			claims := sortedKeys(p.claims())
			for _, claim := range claims {
				if !targetClaims[claim] {
					continue
				}
				k2 := claim + "\x00" + p.Metadata.Namespace + "/" + p.Metadata.Name
				if sibSeen[k2] || len(e.PVCSiblings) >= sameClaimSibMax {
					continue
				}
				sibSeen[k2] = true
				line := fmt.Sprintf("same-claim %s: %s %s (%s)", claim, p.Metadata.Namespace+"/"+p.Metadata.Name, p.Status.Phase, p.ready())
				if d := siblingClaimDetail(p, claim); d != "" {
					line += "; " + d
				}
				e.PVCSiblings = append(e.PVCSiblings, line)
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

	// Read the declared identity and PVC relationships of every resolved target
	// (a pod an alert named, or a pod owned by a Job an alert named) from the
	// live spec objects gathered above. Same-claim siblings are comparison
	// context and are capped; the identity lines are the direct finding.
	e.PodID = podIdentities(targetPodItems)
	e.PVCSiblings = dedupe(e.PVCSiblings)
	e.Nodes = capList(e.Nodes, 6)
	e.UnhealthyPods = capList(e.UnhealthyPods, 8)
	e.SubjectPods = capList(e.SubjectPods, 8)
	e.ContextPods = capList(e.ContextPods, 8)
	e.RecentRestarts = capList(dedupe(e.RecentRestarts), 6)
	e.SubjectRestarts = capList(dedupe(e.SubjectRestarts), 6)
	e.ContextRestarts = capList(dedupe(e.ContextRestarts), 6)
	e.ContainerDiagnostics = capList(dedupe(e.ContainerDiagnostics), 8)
	e.SubjectContainerDiagnostics = capList(dedupe(e.SubjectContainerDiagnostics), 8)
	e.ContextContainerDiagnostics = capList(dedupe(e.ContextContainerDiagnostics), 8)
	e.ContainerTerminationMessages = capList(dedupe(e.ContainerTerminationMessages), 8)
	e.SubjectContainerTerminationMessages = capList(dedupe(e.SubjectContainerTerminationMessages), 8)
	e.ContextContainerTerminationMessages = capList(dedupe(e.ContextContainerTerminationMessages), 8)
	// The per-pod concurrency lives on the stack, not on *kube: the SIGTERM
	// shutdown path calls drainBuffer while runFlushLoop's canceled process
	// may still be unwinding, and both paths run Enrich on the same *kube.
	// Writing the value into k would race with fetchPodLogs's goroutines
	// reading it. Passing the normalised value keeps the shared struct
	// immutable across concurrent callers (issue #146).
	logConcurrency := normalizePodLogConcurrency(cfg.PodLogConcurrency)
	e.PodLogs, e.PodLogProvenance = k.fetchPodLogs(ctx, podLogSpecs, logConcurrency)
	// Split the log map by subject membership so the renderer can present only
	// a resolved subject's logs as direct evidence and everything else as
	// context. Keys are "namespace/name", the same form targetPods uses.
	if len(e.PodLogs) > 0 {
		e.SubjectPodLogs = map[string]string{}
		e.ContextPodLogs = map[string]string{}
		e.SubjectPodLogProvenance = map[string]podLogProvenance{}
		e.ContextPodLogProvenance = map[string]podLogProvenance{}
		for key, log := range e.PodLogs {
			if targetPods[key] {
				e.SubjectPodLogs[key] = log
				e.SubjectPodLogProvenance[key] = e.PodLogProvenance[key]
			} else {
				e.ContextPodLogs[key] = log
				e.ContextPodLogProvenance[key] = e.PodLogProvenance[key]
			}
		}
	}
	if k.logs != nil {
		var res backendLogResult
		var err error
		// The query is subject-scoped exactly when a resolved subject existed;
		// otherwise fetchBackendLogsResult falls back to the namespace.
		e.BackendScoped = len(targetPods) > 0
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
	jobKeys := sortedKeys(jobTargets)
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
	e.KustomizationTopology = k.resolveKustomizationTopology(ctx, seenPods)
	if gh != nil {
		e.CommitRelevance = k.resolveCommitRelevance(ctx, gh, seenPods)
	}
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
