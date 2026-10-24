package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
	keys := make([]string, 0, len(targetPods))
	for k := range targetPods {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		p := targetPods[key]
		if p == nil {
			continue // the alert named a pod the namespace list never returned
		}
		failing := p.failing()
		names := make([]string, 0, len(failing))
		for n := range failing {
			names = append(names, n)
		}
		sort.Strings(names)
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
			claimNames := make([]string, 0, len(claims))
			for c := range claims {
				claimNames = append(claimNames, c)
			}
			sort.Strings(claimNames)
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
			claims := make([]string, 0, len(p.claims()))
			for claim := range p.claims() {
				claims = append(claims, claim)
			}
			sort.Strings(claims)
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
	e.KustomizationTopology = k.resolveKustomizationTopology(ctx, seenPods)
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
	kuz, revision, err := k.fluxKustomization(ctx, ns, name)
	if err != nil {
		rel.Reason = "Flux Kustomization not found: " + truncate(err.Error(), 160)
		return rel
	}
	srcURL, err := k.fluxSourceURL(ctx, ns, kuz.SourceRef.Kind, kuz.SourceRef.Name)
	if err != nil || srcURL == "" {
		rel.Reason = "Flux GitRepository not readable: " + truncate(safeErr(err), 160)
		return rel
	}
	rel.RepoURL = srcURL
	rel.WorkloadPath = kuz.Path
	rel.ComponentPaths = kuz.Components
	rel.Revision = revision
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
// Each entry carries its own replacement template and an optional guard.
// Most consume the whole match; RE2 has no lookbehind, so a pattern that
// must keep a leading key visible for the operator captures it instead and
// re-emits it in repl. A non-nil guard vetoes individual matches of its
// pattern (stripSecrets falls back to per-match filtering for those).
var secretPatterns = []struct {
	re    *regexp.Regexp
	repl  string
	guard func(match string) bool
}{
	// JSON/structured logs quote the key — {"password": "hunter2"} — which
	// the bare keyword[=:] forms below cannot reach, so this runs first and
	// owns that shape. Real-world keys are usually prefixed ("access_token",
	// "client_secret", "db_password"), so the captured key may carry a
	// prefix segment ending in "_" or "-" and is re-emitted intact. That
	// also over-redacts innocent keys like "note_password"; fail-safe beats
	// leak. The value must be quoted; a bare word after the key is prose,
	// not a secret. Escaped quotes inside the value are consumed too,
	// otherwise a value containing \" leaves a half-redacted remnant.
	{
		regexp.MustCompile(`(?i)"((?:[a-z0-9_.\-]+[_\-])?(?:password|passwd|pwd|token|bearer|secret|credential|api[_\-]?key|aws_access_key_id|aws_secret_access_key))"(\s*:\s*)"(?:[^"\\]|\\.)*"`),
		`"$1"$2"[REDACTED]"`,
		nil,
	},
	{regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+`), "[REDACTED]", nil},
	{regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*\S+`), "[REDACTED]", nil},
	{regexp.MustCompile(`(?i)(token|bearer)\s*[=:]\s*\S+`), "[REDACTED]", nil},
	{regexp.MustCompile(`(?i)(secret|credential)\s*[=:]\s*\S+`), "[REDACTED]", nil},
	{regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*\S+`), "[REDACTED]", nil},
	// Authorization header lines separate "Bearer" from the token with a
	// space, which the keyword[=:] forms above cannot match. The token is
	// consumed but the "authorization:" name stays so operators can see
	// what was stripped. Percent-encoding (%3D padding and the like) is
	// part of the token class so it cannot leave a remnant after the
	// match. The floor is eight characters: short enough that digit- or
	// separator-bearing credentials are caught, while lone short words
	// ("bearer 401") are untouched. The guard then rejects what is
	// certainly not a credential: runs of letters and hyphens that reach
	// beyond the hex alphabet ("token-expiry-validation-failed-check-logs"
	// is a message, not a credential, and redacting it would delete
	// evidence). Hex runs are the exception — "deadbeefdeadbeef" is all
	// letters but is token material, so it is redacted even though no
	// digit or separator appears. The accepted residual under-redaction is
	// a letters-and-hyphens run that is not pure hex, e.g. "Bearer
	// mysecretpassword" or the hyphenated hex "Bearer dead-beef-cafe-babe";
	// leaking that is rarer in real logs than the evidence loss full
	// redaction would cause. The floor conversely over-redacts values that
	// are not credentials: a timestamp, IP address or version string
	// directly after "bearer" goes too.
	{
		regexp.MustCompile(`(?i)bearer\s+[a-z0-9\-._~+/=%]{8,}=*`),
		"[REDACTED]",
		func(match string) bool {
			// The match is "bearer" + a whitespace run + the token; only
			// the token part is judged.
			token := match
			if i := strings.IndexAny(match, " \t\n\v\f\r"); i >= 0 {
				token = strings.TrimLeft(match[i+1:], " \t\n\v\f\r")
			}
			return isHexRun(token) || strings.ContainsAny(token, "0123456789._~+/=%")
		},
	},
}

// isHexRun reports whether s consists only of hexadecimal digits. Hex
// credentials need not contain a digit: an all-letter run such as
// "deadbeefdeadbeef" reads like prose to a letters-and-hyphens veto but is
// token material, while ordinary prose almost always uses letters outside
// [a-fA-F].
func isHexRun(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// pctEncodedSeparator matches the percent-encoded forms of the separators
// the Basic-scheme interstitial accepts — space, colon, equals — because
// URL- and query-encoded auth values logged by proxies and web apps arrive
// with the scheme word glued to the credential ("Basic%20<credential>").
// It is spliced into patterns compiled with (?i), so both hex cases match.
const pctEncodedSeparator = `(?:%20|%3a|%3d)+`

// schemeWordLeftBoundary matches what may precede the Basic scheme word: the
// start of the text, a non-letter, or a percent-encoded token. A word
// boundary is the wrong rule there. A percent-encoded separator ends in a hex
// digit ("%3Dbasic") and a digit can abut the scheme word ("0basic"), so \b
// never fired on either shape and the credential behind the scheme word
// survived. A letter still disqualifies the scheme word ("subbasic" is
// prose), which is what the word boundary was there for.
// The start-of-text alternative is what a scan that resumes mid-line sees:
// the resume point follows a separator, so it is a valid left boundary even
// when the character before it is a letter (the hex digit of a
// percent-encoded separator).
const schemeWordLeftBoundary = `(?:^|[^A-Za-z]|%[0-9A-Fa-f]{2})`

// basicAuthHeaderPattern matches an Authorization-style header and the
// credential it carries. The credential is base64("user-id:password")
// (RFC 7617) and has no keyword[=:] shape, so no entry in secretPatterns can
// reach it. The value is captured in the base64 alphabet, so the credential
// is separated from whatever follows it in the same token. The header name
// is captured and re-emitted so the operator can still see what was
// stripped, which is why this needs a replacement template instead of the
// slice's fixed "[REDACTED]".
//
// A strict base64 class stops at "." and "%", which left a JWT's later
// segments or a percent-encoded fragment sitting right next to
// "[REDACTED]". The optional tail consumes a glued "." or "%" and the token
// characters that follow, but only when redaction fires and only up to a
// token character, so a sentence-final "." after a credential survives. The
// decode test sees the core only, because the tail is not base64.
//
// The separator between the header name and the value may be missing: a log
// line that lost its colon still names the header, and the emitted tail of a
// credential chain ("<cred>.authorization <cred>") is such a line. Without
// it the chain's second credential kept its plaintext, because the tail
// says which scheme the value belongs to but the header pass could not read
// it back. The value still has to decode to a credential in that form, so
// prose around the header word survives; a header that kept its separator
// may also be redacted on the scheme word alone.
var basicAuthHeaderPattern = regexp.MustCompile(`(?i)((?:proxy-)?authorization"?\s*(?:[:=]\s*)?\s*"?)\s*((basic)(?:\s+|` + pctEncodedSeparator + `))?([A-Za-z0-9+/=_-]+)([.%][A-Za-z0-9+/=_.%-]*[A-Za-z0-9+/_-])?`)

// basicAuthSchemePattern finds a Basic-scheme credential that no header name
// basicAuthSchemePattern finds a Basic-scheme credential that no header name
// introduces. The interlude between the scheme and the credential — the
// separators (group 1) plus the tolerated words ("basic auth: <payload>",
// group 2) — is captured so every credential-shaped run in the word chain can
// face the decode gate itself, judged leftmost first: the leftmost run sits
// right after the scheme separators, so the strict form "basic <credential>"
// is tested before any word further back. That ordering is what issue #224
// needed. The greedy word group used to swallow the credential itself —
// "basic dXNlcjpwYXNz in request" — and judge the word behind it, which left
// the credential in plaintext. Prose still survives, because words like "auth
// failed for" never decode to a user:password pair, and a redacted run
// carries no base64 material, so the fixed-point loop in stripBasicAuth still
// converges. The leading separators are captured apart from the word chain,
// and only the chain is split into judged runs: percent-encoded separators
// carry digits ("%20"), and splitting across them would glue "20" onto the
// leftmost credential — "basic%20dXNlcjpwYXNz in request" — and break its
// decode, while a word chain can never hold separator residue because its
// words are letters and hyphens. The separators between the tolerated words
// do not come in percent-encoded forms, because there the greedy word group
// would eat a real credential's "%3D" padding as a separator. The core
// (group 3) is the base64 alphabet; a glued "." or "%" tail (group 4) is
// consumed too, for the same reason as in the header pattern — a strict
// base64 class stops at those and left JWT segments and percent-encoded
// fragments next to "[REDACTED]". The tail ends on a token character, so
// sentence punctuation after a credential survives, and the decode test sees
// the core only. The scheme word starts on the left boundary above, which
// admits the percent-encoded and digit-glued shapes a word boundary rejected.
var basicAuthSchemePattern = regexp.MustCompile(`(?i)` + schemeWordLeftBoundary + `basic\b((?:[\s:=]|` + pctEncodedSeparator + `)*)((?:[A-Za-z][A-Za-z-]*[\s:=]+)*)([A-Za-z0-9+/=_-]+)([.%][A-Za-z0-9+/=_.%-]*[A-Za-z0-9+/_-])?`)

// basicAuthCredentialRun splits the word-chain part of the interlude into
// credential-shaped runs so each one can face the decode gate itself. The
// class omits "=": there it is a separator the word group placed between
// runs, not credential padding, so a run must stop at it. Keeping it in the
// class glued a credential to that separator, and on the next fixed-point
// pass the run decoded via the raw-base64 trim and the redaction swallowed
// the separator, dropping a "key=value" join (issue #224).
var basicAuthCredentialRun = regexp.MustCompile(`[A-Za-z0-9+/_-]+`)

// tailEndsInSchemeWord reports a tail that stops on a scheme or header word
// ("core.basic <cred>"): a pass cannot rescan what it emitted, so
// consuming that tail strips the NEXT credential's context and it survives.
// Emitting the tail instead lets the fixed-point pass below redact it.
// The glue counts in its percent-encoded form as well: a percent-encoded
// separator ends in a hex digit ("core%3Dbasic"), which the literal glue
// alone did not recognise, so the tail was consumed and the credential
// behind it kept its plaintext. The token arm must accept ANY percent token,
// not just the encoded separators, because the two rules read the same word:
// schemeWordLeftBoundary recognises a scheme word after any percent token,
// so a tail ending in a word behind an unenumerated one ("%3fbasic", the
// encoding of "?") is context the next pass will honour, and consuming it
// orphans the credential behind that word just as the literal glue did.
// The scheme word has to start where the scheme pass looks for one — after a
// non-letter, or after a percent-encoded token — so a word glued to letters
// is not a scheme word ("core.subbasic"). The match starts at the glue,
// which is the context the next pass reads the credential with.
var tailEndsInSchemeWord = regexp.MustCompile(`(?i)(?:(?:%[0-9A-Fa-f]{2})+[^A-Za-z]?|[^A-Za-z])(?:basic|authorization)$`)

// embeddedSchemeWord is a scheme word found inside a credential run rather
// than before it. The base64 alphabet admits "+", "/", "_", "-" and digits,
// so a scheme word can be glued to a credential with no separator, and the
// word's letters decode along with the credential. A run that passes the
// decode gate may therefore carry a scheme word inside it; that word is the
// context the credential behind it needs, so it is cut out and re-emitted.
var embeddedSchemeWord = regexp.MustCompile(`(?i)basic|authorization`)

// safeTail returns a captured tail that is safe to re-emit (issue #217). A
// tail that stops on a scheme word is emitted rather than consumed, because
// consuming it strips the next credential's context and the credential
// survives; the trailing scheme word therefore stays, since it is the
// context the next credential needs.
// Material ahead of that scheme word is redacted WHOLESALE, not selectively:
// inside a tail a credential cannot be told apart from a file name, a version
// string or a pod name, so picking out the segments that look like
// credentials would leak the ones that do not. The cost is that this deletes
// operator-visible evidence the previous code kept — a version string or a
// pod name inside a tail is gone with the credential.
// A tail that does not stop on a scheme word carries material too, so it is
// redacted whole; the callers consume such a tail rather than emit it, which
// makes that arm defensive.
func safeTail(tail string) string {
	loc := tailEndsInSchemeWord.FindStringIndex(tail)
	if loc == nil {
		return "[REDACTED]"
	}
	if loc[0] == 0 {
		return tail
	}
	interior := tail[:loc[0]]
	if interior[0] == '.' || interior[0] == '%' {
		return interior[:1] + "[REDACTED]" + tail[loc[0]:]
	}
	return "[REDACTED]" + tail[loc[0]:]
}

// gluedSchemeWordSuffix matches a run that ends on a scheme or header word,
// the shape splitGluedSchemeWord cuts. The word list must stay in step with
// tailEndsInSchemeWord, which reads the same words at a tail's end.
var gluedSchemeWordSuffix = regexp.MustCompile(`(?i)(?:basic|authorization)$`)

// splitGluedSchemeWord cuts a credential-alphabet run into a credential and
// a scheme or header word glued to its end ("dXVpZDpwYXNzbasic",
// "dXVpZDpwYXNz=basic"), returning the index where the word starts. The core
// class of both Basic patterns stops at "." but not at "=", "_" or a letter,
// so the word is swallowed into the core, the decode gate fails on the
// combined run, and the credential survived next to the word (issue #227).
// Callers redact the decodable part before the index; the word is kept,
// because "[REDACTED]" ends on a non-letter, the boundary
// schemeWordLeftBoundary requires, so the next pass still reads the word as
// the context of whatever follows it. Whether the glue between the
// credential and the word survives is the call site's judgement: the judged
// word chain drops it with the redaction, the core and header arms keep it
// so the shape of the join the line carried does not move. Words are cut
// from the right one at a time so a chain of glued words
// ("cred basicbasic") cuts at the leftmost word behind which the remainder
// still decodes. A run that is only scheme words never cuts: there is no
// credential ahead of the word, and prose ("subbasic", the word chain's own
// "basic") must survive the gate.
func splitGluedSchemeWord(run string) (int, bool) {
	end := len(run)
	for {
		loc := gluedSchemeWordSuffix.FindStringIndex(run[:end])
		if loc == nil || loc[0] == 0 {
			return 0, false
		}
		if decodesToBasicCredential(strings.TrimRight(run[:loc[0]], "=_-")) {
			return loc[0], true
		}
		end = loc[0]
	}
}

// cutGluedSchemeWord splits a gate-passing credential run at a scheme word
// glued inside it, so the word survives as the context the credential behind
// it needs. Wholesale redaction would swallow the word with the run and
// orphan that credential.
//
// The head before the word must itself decode to a credential: that is what
// separates "dXVpZDpwYXNz+basic" (head "dXVpZDpwYXNz" is "uuid:pass") from
// prose ("subbasic": head "sub" decodes to nothing), and it keeps a word that
// merely shares a prefix with a scheme word out of the cut. Glue around the
// word is base64-alphabet glue ("+/_-="), not a separator the next pass can
// read, so it is trimmed: the glue before the head is tested away, the glue
// after the word is consumed, and the word is re-emitted with a real space.
// A word followed by a letter is not a scheme word ("dXVpZDpwYXNzbasically"),
// so that occurrence is skipped and the run keeps its wholesale redaction.
// The remainder behind the word must itself decode to a credential: a
// remainder that does not decode can never earn redaction behind the
// re-emitted word, so cutting there would ship it in plaintext and the run
// keeps its wholesale redaction instead.
func cutGluedSchemeWord(run string) (word, rest string, ok bool) {
	for _, m := range embeddedSchemeWord.FindAllStringIndex(run, -1) {
		if m[1] < len(run) {
			c := run[m[1]]
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				continue
			}
		}
		head := strings.TrimRight(run[:m[0]], "+/=-_")
		if head == "" || !decodesToBasicCredential(head) {
			continue
		}
		remainder := strings.TrimLeft(run[m[1]:], "+/=-_")
		if remainder != "" && !decodesToBasicCredential(remainder) {
			continue
		}
		return run[m[0]:m[1]], remainder, true
	}
	return "", "", false
}

// judgeTail redacts the credential material a captured tail carries
// (#226). A match the decode test declines leaves its tail in play raw,
// and no later pass can read a credential that sits before the scheme
// word the pass looks for first, so the tail's material survived every
// pass and reached the digest. Judging it on the way out replaces every
// piece of credential alphabet that decodes to a user:password pair with
// "[REDACTED]". Inside a tail a piece that decodes to a credential cannot
// be told apart from a file name that decodes to one, so the piece goes
// whole — the trade-off #217 accepted for the re-emission path, at piece
// granularity. The glue between pieces (dots, equals signs, percent
// tokens) and the pieces that decode to nothing survive: prose, file
// names and the separator context later passes may still need stay readable, which is
// why the pieces are judged instead of redacting the interior wholesale.
// The pieces are split by hand, not with basicAuthCredentialRun, for the
// same reason the scheme pass captures the encoded separators apart from
// its word chain: a token's hex digits would glue onto the run behind a
// percent-encoded separator ("%3DdXNlcjpwYXNz" reads as one run) and
// break the candidate's decode, so material behind a percent-encoded
// glue survived.
func judgeTail(tail string) string {
	var out strings.Builder
	for i := 0; i < len(tail); {
		if c := tail[i]; c == '.' || c == '%' || c == '=' {
			// Glue: a dot and an equals sign separate tokens (the latter
			// is a separator a key=value join placed before the piece
			// behind it, not padding — the word chain stops at one for
			// the same reason, issue #224), and a token's hex digits are
			// what a percent-encoded separator looks like to the next
			// pass ("%3D" names "="); all are copied verbatim and start
			// no piece, so the pieces behind them keep their own decode.
			if c == '%' && i+2 < len(tail) && isHexDigit(tail[i+1]) && isHexDigit(tail[i+2]) {
				out.WriteString(tail[i : i+3])
				i += 3
				continue
			}
			out.WriteByte(c)
			i++
			continue
		}
		end := i
		for end < len(tail) {
			if c := tail[end]; c == '.' || c == '%' || c == '=' {
				break
			}
			end++
		}
		if decodesToBasicCredential(tail[i:end]) {
			out.WriteString("[REDACTED]")
		} else {
			out.WriteString(tail[i:end])
		}
		i = end
	}
	return out.String()
}

// isHexDigit reports whether c is one of the hex digits a
// percent-encoded token's second and third bytes are made of.
func isHexDigit(c byte) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'F' || 'a' <= c && c <= 'f'
}

// stripBasicAuth redacts HTTP basic-auth credentials. A header that names
// the Basic scheme is redacted on its context: RFC 7235 puts the credential
// right after the scheme, so whatever sits there goes even when it is too
// mangled to decode, because half a credential still authenticates as much
// as a whole one does. A value without the scheme word, and a bare "basic
// <token>" outside any header, carry no such context, so they are redacted
// only when they decode to a credential. Prose survives: "basic
// authentication failed" is not a credential and must stay readable.
func stripBasicAuth(s string) string {
	// A consumed tail can stop exactly on the next credential's scheme word;
	// a pass cannot rescan what it emitted, so run to a fixed point.
	// It converges: every mutating pass replaces at least one credential-
	// alphabet run — a core in either pass, a word-chain run in the scheme
	// pass — with "[REDACTED]", whose brackets match neither pattern's
	// classes and cannot join runs, so the amount of credential material
	// strictly drops and no pass can splice new credential material together.
	// Re-emitted material is context, not credential: a safeTail re-emits a
	// redacted substring of its tail, splitGluedSchemeWord re-emits only the
	// glue and the trailing scheme word it refused to redact (also for the
	// join-segment cuts redactJoinSegments takes), the leading glue a join
	// segment sheds stays where the line carried it, and the
	// cutGluedSchemeWord arm re-emits only the split word plus a strict
	// subset of the consumed run — a non-empty head that decoded is dropped
	// and never restored — so the credential material outside the inert
	// "[REDACTED]" tokens strictly drops on every mutating pass and no pass
	// can re-create work. Declined-match tails are also judged by
	// judgeTail before any credential-bearing pieces can be re-emitted.
	for {
		once := s
		s = redactBasicHeader(s)
		s = redactBasicScheme(s)
		if s == once {
			return s
		}
	}
}

// redactBasicHeader redacts the credential an Authorization-style header
// carries. The scan is by hand for the same reason as the scheme scan: a
// match that fails the decode gate must not swallow the text behind it,
// because that text can hold a header of its own with a credential in it
// ("Authorization-foo.Authorization:<credential>"). The scan continues from
// the value, so the later header is still read.
func redactBasicHeader(s string) string {
	var out strings.Builder
	pos := 0
	for pos < len(s) {
		loc := basicAuthHeaderPattern.FindStringSubmatchIndex(s[pos:])
		if loc == nil {
			break
		}
		// Groups: 1 = the prefix, 2 = the scheme group, 3 = the scheme
		// word, 4 = the value, 5 = the tail.
		prefix := s[pos+loc[2] : pos+loc[3]]
		scheme := ""
		if loc[6] >= 0 {
			scheme = s[pos+loc[6] : pos+loc[7]]
		}
		value := s[pos+loc[8] : pos+loc[9]]
		tail := ""
		if loc[10] >= 0 {
			tail = s[pos+loc[10] : pos+loc[11]]
		}
		// A header that kept its separator says the value is a header
		// value, so the scheme word may speak for it: a mangled credential
		// still authenticates as much as a whole one. A header separated
		// from its value by whitespace alone says less — "Authorization
		// Basic scheme is deprecated" is prose — so that form has to earn
		// the redaction on the value alone. The header name is a fixed
		// literal, so a ":" or "=" in the prefix can only be the separator
		// that was kept.
		if !decodesToBasicCredential(value) &&
			(scheme == "" || !strings.ContainsAny(prefix, ":=")) {
			// The value can be a credential joined to the token after it
			// by "=": an interior "=" is no valid base64, the gate failed
			// on the joined run, and the credential kept its plaintext
			// (issue #230). Without a scheme word in the match the
			// scheme pass cannot read the same slot, so every join
			// segment faces the shared judge here — a credential in
			// either slot goes, and a gate-failing segment still loses
			// the glued scheme word or the leading glue it carries
			// (issue #259). The join stays readable for
			// the same reason the scheme pass keeps it. A match that
			// carries the scheme word stays in play instead: the scheme
			// pass sees the same slot and its passes keep the following
			// credential's context alive.
			if scheme == "" {
				if joined, ok := redactJoinSegments(value); ok {
					out.WriteString(s[pos : pos+loc[8]])
					out.WriteString(joined)
					if tail != "" && tailEndsInSchemeWord.MatchString(tail) {
						out.WriteString(safeTail(tail))
					}
					pos += loc[1]
					continue
				}
				if cut, ok := splitGluedSchemeWord(value); ok {
					// The value is a credential with a scheme or header
					// word glued to its end: the value class swallowed
					// both, the gate failed on the combined run, and the
					// credential survived (#227). Redact the credential
					// part and keep the glue and the word, which keeps
					// the context of whatever follows it.
					head := strings.TrimRight(value[:cut], "=_-")
					out.WriteString(s[pos : pos+loc[8]])
					out.WriteString("[REDACTED]")
					out.WriteString(value[len(head):])
					if tail != "" && tailEndsInSchemeWord.MatchString(tail) {
						out.WriteString(safeTail(tail))
					}
					pos += loc[1]
					continue
				}
			}
			// Not a credential: the value is prose, a file name or the
			// value another scheme gave the header, and it stays
			// readable. The tail, though, its character class swallows
			// whole credential segments, and a declined match leaves its
			// tail in play raw — no later pass can read a credential that
			// sits before the scheme word it looks for first, so the tail
			// is judged before it stays (#226). The match is then
			// consumed, because the tail has been written already.
			if tail != "" {
				if judged := judgeTail(tail); judged != tail {
					out.WriteString(s[pos : pos+loc[8]])
					out.WriteString(value)
					out.WriteString(judged)
					pos += loc[1]
					continue
				}
			}
			// A tail with nothing to redact changes nothing, so the value
			// and the tail stay in play: a later header can hide in them.
			out.WriteString(s[pos : pos+loc[8]])
			pos += loc[8]
			continue
		}
		// The text before the match and the prefix itself stay: the
		// header name is what tells the operator that a credential was
		// stripped.
		out.WriteString(s[pos : pos+loc[3]])
		if word, rest, ok := cutGluedSchemeWord(value); ok {
			out.WriteString("[REDACTED] " + word)
			if rest != "" {
				out.WriteString(" " + rest)
			}
		} else {
			out.WriteString("[REDACTED]")
		}
		// A tail that stops on a scheme word is emitted, so the next
		// credential keeps its context, but only once safeTail has
		// redacted the credential material it carries (#217). A tail
		// that stops on no scheme word goes with the credential.
		if tail != "" && tailEndsInSchemeWord.MatchString(tail) {
			out.WriteString(safeTail(tail))
		}
		pos += loc[1]
	}
	out.WriteString(s[pos:])
	return out.String()
}

// redactBasicScheme redacts a Basic-scheme credential that no header name
// introduces. The scan is by hand because a match that fails the decode gate
// must not swallow the tail behind it: the tail can carry the next
// credential's scheme word ("basic <not-a-credential>.basic <credential>"),
// and a swallowed scheme word orphans that credential, because the
// fixed-point pass cannot see it any more — the line looks unchanged, so
// the loop stops. The tail is therefore kept in play when the core is no
// credential, and the scan continues from it.
func redactBasicScheme(s string) string {
	var out strings.Builder
	pos := 0
	for pos < len(s) {
		loc := basicAuthSchemePattern.FindStringSubmatchIndex(s[pos:])
		if loc == nil {
			break
		}
		// Groups: 1 = the separators after the scheme word, 2 = the
		// tolerated word chain, 3 = the core, 4 = the tail.
		words := s[pos+loc[4] : pos+loc[5]]
		core := s[pos+loc[6] : pos+loc[7]]
		tail := ""
		if loc[8] >= 0 {
			tail = s[pos+loc[8] : pos+loc[9]]
		}
		// Every credential-shaped run in the word chain faces the gate
		// itself, leftmost first, so the strict form "basic <credential>"
		// is judged before any word behind it — the greedy chain used to
		// swallow the credential and judge the word after it (#224).
		judged := basicAuthCredentialRun.ReplaceAllStringFunc(words, func(run string) string {
			if decodesToBasicCredential(run) {
				return "[REDACTED]"
			}
			if cut, ok := splitGluedSchemeWord(run); ok {
				// The run is a credential with a scheme word glued to
				// its end: the gate fails on the combined run, so redact
				// the credential part and re-emit the word, which the
				// next pass reads as context (#227).
				return "[REDACTED]" + run[cut:]
			}
			return run
		})
		if !decodesToBasicCredential(core) {
			// A credential joined to a key by "=" could not decode as a
			// whole (interior "=" is not valid base64), so the core reached
			// here undecoded and its credential kept plaintext (issue #238).
			// Judge each join segment on its own: a credential in either
			// slot goes, the key and the join stay readable, and a segment
			// that is no credential is untouched. This also judges the slot
			// before the first "=", so the key-slot contract of #230 holds
			// which is already merged in #237. The tail follows
			// the rule of a redacted core, not a surviving one.
			if joined, ok := redactJoinSegments(core); ok {
				out.WriteString(s[pos : pos+loc[4]])
				out.WriteString(judged)
				out.WriteString(joined)
				if tail != "" && tailEndsInSchemeWord.MatchString(tail) {
					out.WriteString(safeTail(tail))
				}
				pos += loc[1]
				continue
			} else if cut, ok := splitGluedSchemeWord(core); ok {
				// The core is a credential with a scheme word glued to its
				// end — no "=" the branch above could cut on, or a word
				// hanging on a letter the word chain could not catch
				// (issue #227). Redact the credential part and keep the
				// glue and the word: the glue is the join the line
				// carried (the "="-join above keeps its "="), and the
				// word stays because it is the context the next pass
				// reads the following credential with.
				head := strings.TrimRight(core[:cut], "=_-")
				out.WriteString(s[pos : pos+loc[4]])
				out.WriteString(judged)
				out.WriteString("[REDACTED]")
				out.WriteString(core[len(head):])
				if tail != "" && tailEndsInSchemeWord.MatchString(tail) {
					out.WriteString(safeTail(tail))
				}
				pos += loc[1]
				continue
			}
			// The scheme word alone does not say that what follows it is
			// a credential; the decode test decides that. The core stays
			// unread and in play: it can be the next credential's own
			// scheme word ("basic Basic%3D<cred>"), and a swallowed one
			// orphans that credential. A word run that did decode is
			// written redacted; the rest of the chain stays behind the
			// resume point untouched.
			if judged != words {
				out.WriteString(s[pos : pos+loc[4]])
				out.WriteString(judged)
			} else {
				out.WriteString(s[pos : pos+loc[6]])
			}
			// The tail a declined match leaves in play raw carries
			// credentials no later pass can reach, so it is judged
			// (#226) first; the core was written along the match and the
			// match is consumed. A tail with nothing to redact keeps the
			// core in play, as it can be the next credential's own scheme
			// word (see above).
			if tail != "" {
				if judged := judgeTail(tail); judged != tail {
					out.WriteString(core)
					out.WriteString(judged)
					pos += loc[1]
					continue
				}
			}
			pos += loc[6]
			continue
		}
		// The scheme word stays visible: outside a header it is the only
		// context that says a credential was here. A tail that stops on
		// a scheme word is emitted only once safeTail has redacted the
		// material it carries (#217); a tail that stops on no scheme
		// word goes with the credential.
		out.WriteString(s[pos : pos+loc[4]])
		out.WriteString(judged)
		if word, rest, ok := cutGluedSchemeWord(core); ok {
			out.WriteString("[REDACTED] " + word)
			if rest != "" {
				out.WriteString(" " + rest)
			}
		} else {
			out.WriteString("[REDACTED]")
		}
		if tail != "" && tailEndsInSchemeWord.MatchString(tail) {
			out.WriteString(safeTail(tail))
		}
		pos += loc[1]
	}
	out.WriteString(s[pos:])
	return out.String()
}

// redactJoinSegments judges the "=" -separated segments of a core that
// already failed to decode as a whole, and reports that core with every
// segment decoding to a basic-auth credential replaced by "[REDACTED]". An
// interior "=" is not valid base64, so a credential joined to a key
// ("key=<credential>") or two credentials joined together
// ("<credential>=<credential>") cannot decode as a whole and the whole-core
// gate rejects them, keeping their plaintext (issue #238). Each segment
// faces the gate on its own, so the credential goes while a non-credential
// key or value stays readable. A segment that fails the gate on its own is
// not re-emitted verbatim either: a scheme or header word glued to its end
// is cut the way splitGluedSchemeWord cuts (#227), and a leading glue run
// the gate fails on is trimmed away before the gate is faced again, the
// glue staying where the line carried it so the join's shape does not move
// (issue #259). It reports false when the core carries no "=" or when no
// segment produces a redaction, so a plain prose "key=value" is returned
// unchanged and the caller leaves it in play.
func redactJoinSegments(core string) (string, bool) {
	if !strings.Contains(core, "=") {
		return core, false
	}
	parts := strings.Split(core, "=")
	redacted := false
	for i, part := range parts {
		if decodesToBasicCredential(part) {
			// The part decodes, but a scheme word may be glued inside it
			// and be the context a following credential is read with:
			// cutting it the way the gate-passing value and core arms cut
			// (#242) keeps that context, and redacting the part wholesale
			// would orphan the credential behind the word.
			if word, rest, ok := cutGluedSchemeWord(part); ok {
				parts[i] = "[REDACTED] " + word
				if rest != "" {
					parts[i] += " " + rest
				}
			} else {
				parts[i] = "[REDACTED]"
			}
			redacted = true
			continue
		}
		if cut, ok := splitGluedSchemeWord(part); ok {
			head := strings.TrimRight(part[:cut], "=_-")
			parts[i] = "[REDACTED]" + part[len(head):]
			redacted = true
			continue
		}
		if word, rest, ok := cutGluedSchemeWord(part); ok {
			// A word the "=_-" trim cannot reach — glue like "+" or "/"
			// leads it, and the glue-only decode test in
			// splitGluedSchemeWord refuses the head. The #242 cut drops
			// the glue and re-emits the word with a real space, the
			// context the credential behind it is read with on the next
			// pass; redacting the part wholesale would swallow that word
			// and orphan the credential.
			parts[i] = "[REDACTED] " + word
			if rest != "" {
				parts[i] += " " + rest
			}
			redacted = true
			continue
		}
		if trimmed := strings.TrimLeft(part, "+/=-_"); trimmed != "" && decodesToBasicCredential(trimmed) {
			// The glue ran before the gate, but the part behind it may
			// still carry a glued scheme word a following credential is
			// read with: cut the way the decodable arm cuts before
			// redacting the trimmed part wholesale, or the word goes with
			// the redaction and the credential behind it is orphaned.
			glue := part[:len(part)-len(trimmed)]
			if word, rest, ok := cutGluedSchemeWord(trimmed); ok {
				parts[i] = glue + "[REDACTED] " + word
				if rest != "" {
					parts[i] += " " + rest
				}
			} else {
				parts[i] = glue + "[REDACTED]"
			}
			redacted = true
		}
	}
	if !redacted {
		return core, false
	}
	return strings.Join(parts, "="), true
}

// decodesToBasicCredential reports whether cand is base64 of a
// "user-id:password" pair, which is what RFC 7617 basic credentials are.
// The decoded bytes must read like that pair — a printable user-id, then a
// colon, then a password — because ordinary words also decode to bytes
// holding a colon ("open" decodes to bytes that start with one), and
// redacting prose would delete evidence.
func decodesToBasicCredential(cand string) bool {
	b, ok := decodeBase64(cand)
	if !ok {
		return false
	}
	i := bytes.IndexByte(b, ':')
	if i <= 0 {
		return false
	}
	for _, c := range b[:i] {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	for _, c := range b[i+1:] {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// decodeBase64 decodes a candidate in any of the alphabets a client may have
// used, padded or not.
func decodeBase64(cand string) ([]byte, bool) {
	if b, err := base64.StdEncoding.DecodeString(cand); err == nil {
		return b, true
	}
	trimmed := strings.TrimRight(cand, "=")
	if b, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil {
		return b, true
	}
	if b, err := base64.RawURLEncoding.DecodeString(trimmed); err == nil {
		return b, true
	}
	return nil, false
}

// stripSecrets replaces obvious secrets in log lines with [REDACTED].
func stripSecrets(s string) string {
	s = stripBasicAuth(s)
	for _, p := range secretPatterns {
		if p.guard == nil {
			s = p.re.ReplaceAllString(s, p.repl)
			continue
		}
		s = p.re.ReplaceAllStringFunc(s, func(m string) string {
			if !p.guard(m) {
				return m
			}
			return p.re.ReplaceAllString(m, p.repl)
		})
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

// resolveKustomizationTopology reads the Flux Kustomization each pod resolved
// to and renders its composition as one compact record: the Kustomization
// name, its source and spec.path, the spec.components paths exactly as
// declared, and the spec.dependsOn names. It is the half of the GitOps
// evidence resolveRepoPaths leaves out: which composition the workload gets
// its behaviour from, not just where its manifests live.
//
// Boundaries this keeps:
//   - The record is attached only to the Kustomization the pod's annotations
//     resolved to, never to the other Kustomizations in the namespace.
//   - A record is emitted only for a Kustomization that actually exists: a
//     failed lookup degrades to no record, so a missing object never reads
//     as an empty composition (a bare "none" would claim the spec was read
//     and found nothing).
//   - Component paths are quoted from the object and travel verbatim; the
//     contents of the files they name are not read, so the record never
//     claims to have. A component that is not a relative path (an
//     OCI-style reference) is rendered as-is under its own label.
//   - Path-like values (spec.path, each component, each dependsOn name and
//     namespace, the sourceRef name and namespace) that carry NUL,
//     backslash, or percent are refused before rendering — the same
//     rejection set resolveRepoPaths applies to the same class of value.
//     A refused singular field (spec.path, the sourceRef name) renders an
//     explicit "refused" marker so it never reads as an absent one; refused
//     list entries are dropped, leaving their subsection saying "none safe".
//     No path.Clean here, unlike resolveRepoPaths: components legitimately
//     carry `..` segments (`../base/common`) and OCI references that a
//     Unix-style cleaner would mangle, so only the hostile character
//     classes are refused and the value is never rewritten.
//   - A subsection whose declared values were all refused renders "none
//     safe", not "none declared": declaring nothing and declaring only
//     refused values are different findings.
//   - The assembled record passes untrusted() at construction, so the
//     prompt and Discord render paths inherit flattened, dash-run-broken
//     text from a single enforcement point and a hostile value can never
//     forge a line or a fence out of it.
func (k *kube) resolveKustomizationTopology(ctx context.Context, pods []podRef) []string {
	seen := map[string]bool{}
	var out []string
	// Parity with the resolveRepoPaths rejection rule: refuse, do not rewrite.
	safe := func(v string) bool { return !strings.ContainsAny(v, "\x00\\%") }
	for _, p := range pods {
		kustom := p.Annotations["kustomize.toolkit.fluxcd.io/name"]
		if kustom == "" {
			continue
		}
		ns := p.Annotations["kustomize.toolkit.fluxcd.io/namespace"]
		if ns == "" {
			ns = p.Namespace
		}
		key := ns + "/" + kustom
		if seen[key] {
			continue
		}
		seen[key] = true
		spec, _, err := k.fluxKustomization(ctx, ns, kustom)
		if err != nil {
			continue
		}
		var src string
		switch {
		case spec.SourceRef.Name == "":
		case !safe(spec.SourceRef.Name):
			// A refused name must not read as an absent one.
			src = "refused"
		default:
			src = spec.SourceRef.Name
			if spec.SourceRef.Kind != "" && safe(spec.SourceRef.Kind) {
				src = spec.SourceRef.Kind + "/" + src
			}
			if spec.SourceRef.Namespace != "" && safe(spec.SourceRef.Namespace) {
				src += " (" + spec.SourceRef.Namespace + ")"
			}
		}
		var rec []string
		head := "kustomization " + ns + "/" + kustom
		switch {
		case spec.Path == "":
		case !safe(spec.Path):
			// A refused path must not read as an absent one.
			head += " (path: refused)"
		default:
			head += " (path: " + spec.Path + ")"
		}
		if src != "" {
			head += ", source: " + src
		}
		rec = append(rec, head)
		if len(spec.Components) > 0 {
			var comps []string
			for _, c := range spec.Components {
				if safe(c) {
					comps = append(comps, c)
				}
			}
			if len(comps) > 0 {
				rec = append(rec, "components: "+strings.Join(comps, ", "))
			} else {
				// "none safe", not "none declared": an empty spec and a spec
				// of only refused values are different findings.
				rec = append(rec, "components: none safe")
			}
		} else {
			rec = append(rec, "components: none declared")
		}
		if len(spec.DependsOn) > 0 {
			var deps []string
			for _, d := range spec.DependsOn {
				if !safe(d.Name) || !safe(d.Namespace) {
					continue
				}
				if d.Namespace != "" && d.Namespace != ns {
					deps = append(deps, d.Namespace+"/"+d.Name)
				} else {
					deps = append(deps, d.Name)
				}
			}
			if len(deps) > 0 {
				rec = append(rec, "dependsOn: "+strings.Join(deps, ", "))
			} else {
				rec = append(rec, "dependsOn: none safe")
			}
		} else {
			rec = append(rec, "dependsOn: none declared")
		}
		out = append(out, untrusted(strings.Join(rec, "; ")))
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

// kustomizationSpec is the subset of a Flux Kustomization read for the
// resolved workload: where it lives (spec.path, spec.sourceRef) and how it is
// composed (spec.components, spec.dependsOn). The composition fields are the
// behaviour source the issue cares about; the path fields are what
// fluxPath has always needed.
type kustomizationSpec struct {
	SourceRef struct {
		Name      string `json:"name"`
		Kind      string `json:"kind"`
		Group     string `json:"group"`
		Namespace string `json:"namespace"`
	} `json:"sourceRef"`
	Path string `json:"path"`
	// Components are paths relative to the source (or absolute repo paths);
	// they are quoted from the object, so they travel as declared.
	Components []string `json:"components"`
	// DependsOn names the Kustomizations this one composes from, with the
	// namespace of each (empty = the Kustomization's own namespace).
	DependsOn []struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"dependsOn"`
}

// fluxKustomization reads one Flux Kustomization and returns its spec plus
// the status revision it currently reconciles at. Callers that only want the
// repo+path pair should go through fluxPath, so a failed lookup is never
// re-issued as a second identical kustomization GET.
func (k *kube) fluxKustomization(ctx context.Context, ns, name string) (kustomizationSpec, string, error) {
	var kuz struct {
		Spec   kustomizationSpec `json:"spec"`
		Status struct {
			LastAppliedRevision string `json:"lastAppliedRevision"`
		} `json:"status"`
	}
	if err := k.get(ctx, "/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/"+ns+"/kustomizations/"+name, &kuz); err != nil {
		return kustomizationSpec{}, "", err
	}
	return kuz.Spec, kuz.Status.LastAppliedRevision, nil
}

// fluxSourceURL reads the source object a Kustomization's sourceRef names and
// returns its spec.url. An empty kind defaults to GitRepository, matching the
// sourceRef default Flux applies. The empty-URL case is left to callers: for
// relevance it degrades to "not readable", for repo+path lookups to no path.
func (k *kube) fluxSourceURL(ctx context.Context, ns, srcKind, srcName string) (string, error) {
	if srcKind == "" {
		srcKind = "GitRepository"
	}
	var src struct {
		Spec struct {
			URL string `json:"url"`
		} `json:"spec"`
	}
	p := "/apis/source.toolkit.fluxcd.io/v1/namespaces/" + ns + "/" + pluralLower(srcKind) + "/" + srcName
	if err := k.get(ctx, p, &src); err != nil {
		return "", err
	}
	return src.Spec.URL, nil
}

func (k *kube) fluxPath(ctx context.Context, ns, name string) (string, string, bool) {
	kuz, _, err := k.fluxKustomization(ctx, ns, name)
	if err != nil || kuz.Path == "" {
		return "", "", false
	}
	srcURL, err := k.fluxSourceURL(ctx, ns, kuz.SourceRef.Kind, kuz.SourceRef.Name)
	if err != nil || srcURL == "" {
		return "", "", false
	}
	return srcURL, kuz.Path, true
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
