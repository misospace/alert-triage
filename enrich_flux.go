package main

import (
	"context"
	"errors"
	"fmt"
	pathpkg "path"
	"strings"
	"time"
)

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
		rel.Reason = kustomizationFailureReason(err)
		return rel
	}
	srcURL, err := k.fluxSourceURL(ctx, fluxSourceNamespace(kuz, ns), kuz.SourceRef.Kind, kuz.SourceRef.Name)
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

// fluxActivity reports Flux resources that are failing, and - only when
// scoped to a namespace - ones whose Ready condition transitioned inside the
// window. The second result records whether the scope was read: a failed
// read returns the findings gathered so far and false, and a namespace
// refused as not one path segment returns false with nothing read at all,
// so an empty slice is only a quiet window when the caller knows the lists
// were read (issue #300).
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
func (k *kube) fluxActivity(ctx context.Context, namespace string, since time.Time) ([]string, bool) {
	scoped := namespace != ""
	apis := []string{
		"/apis/helm.toolkit.fluxcd.io/v2/helmreleases",
		"/apis/kustomize.toolkit.fluxcd.io/v1/kustomizations",
	}
	if namespace != "" {
		if !fluxPathSegment(namespace) {
			// The namespace is interpolated into the request path, so a
			// value that is not one path segment must never be sent: the
			// request would address a different namespace than the one
			// the alert names. Refusing it yields inspected=false, which
			// is what makes the digest say the Flux state is unavailable
			// instead of asserting the false quiet-window negative "no
			// Flux reconciles or failures in the window" (report.go). A
			// window that was never read was never established, and a
			// wrong confident sentence is worse than a vague one (issue
			// #300).
			//
			// The value arriving here is already percent-escaped by the
			// caller: enrich.go escapes the namespace with
			// url.PathEscape before calling. The escape turns '/' into
			// '%2F' and leaves '.' alone, so a hostile namespace arrives
			// as e.g. "ns%2F..%2F..%2Fother" and the segment check
			// refuses it on '%' and on "..". A value that survives the
			// check is one path segment, whether or not it names a
			// namespace that exists, and no legitimate namespace is
			// refused: a Kubernetes namespace is a DNS-1123 label, so
			// lowercase alphanumeric and '-' only.
			logf("enrich: flux namespace is not a valid path segment; skipping the Flux list read")
			return nil, false
		}
		apis = []string{
			"/apis/helm.toolkit.fluxcd.io/v2/namespaces/" + namespace + "/helmreleases",
			"/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/" + namespace + "/kustomizations",
		}
	}
	var out []string
	// Both lists must read for the empty result to mean "quiet window": a
	// cluster without Flux 404s both, and a forbidden or timed-out list hides
	// exactly the failures this section exists to surface, so either failure
	// leaves the read uninspected (issue #300).
	inspected := true
	for _, api := range apis {
		var fl fluxList
		if err := k.get(ctx, api, &fl); err != nil {
			logf("enrich: flux %s: %v", api, err)
			inspected = false
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
	return out, inspected
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

// argoInstanceRefusal is the fixed marker resolveRepoPaths returns when a
// pod's argocd.argoproj.io/instance value is refused as not one path
// segment. It names the refused field and the reason and never repeats the
// value: the annotation is workload-authored text, and issue #308
// established that a refused value must not reach the digest. The renderer
// prints it alongside RepoPaths so a pod that declares an Argo Application
// the service would not read does not read as one that declares none
// (issue #312).
const argoInstanceRefusal = "argocd.argoproj.io/instance refused: value is not one path segment (value not shown)"

// fluxSourceNamespaceRefusal and fluxSourceNameRefusal are the fixed
// markers resolveRepoPaths records when a Kustomization's
// spec.sourceRef.namespace or spec.sourceRef.name is refused as not one
// path segment. They mirror argoInstanceRefusal for the Flux side (issue
// #318): the Kustomization does declare a source, the service just would
// not read it, and that must not read as a workload that declares no
// GitOps source. The markers name the refused field and never repeat the
// value: it comes from Kustomization spec text, which is object-authored
// and stays out of the digest like the Argo instance value (issue #308).
const (
	fluxSourceNamespaceRefusal = "flux Kustomization spec.sourceRef.namespace refused: value is not one path segment (value not shown)"
	fluxSourceNameRefusal      = "flux Kustomization spec.sourceRef.name refused: value is not one path segment (value not shown)"
)

// fluxSourceRefusal maps a fluxPath failure to the marker of the refused
// field, or "" when the failure is not a refusal of a value the service
// actually read — a missing object, an empty spec.path or spec.url, a
// sourceRef that declares no source, or a source read error. Only a
// refusal is this service's own decision about a declared source, so only
// a refusal earns a digest line; every other failure keeps degrading to
// silence plus the GITOPS_REPO fallback.
func fluxSourceRefusal(err error) string {
	switch {
	case errors.Is(err, errFluxSourceNamespaceRefused):
		return fluxSourceNamespaceRefusal
	case errors.Is(err, errFluxSourceNameRefused):
		return fluxSourceNameRefusal
	}
	return ""
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
// The one exception is a refused owner reference: an Argo instance that
// is not one path segment, or a Flux Kustomization whose declared
// sourceRef namespace or name is not one path segment. The pod does
// declare an owner, the service just would not read it, so that refusal
// is not silence — it comes back in the second result as a fixed marker
// naming the field, never the refused value (issues #312, #318).
func (k *kube) resolveRepoPaths(ctx context.Context, pods []podRef, cfg *Config) ([]string, []string) {
	seen := map[string]bool{}
	var out []string
	// Refusal markers are de-duplicated by their fixed text, the same way
	// paths are: a ten-replica deployment with one hostile annotation is
	// one line in the digest, not ten.
	seenRefusal := map[string]bool{}
	var refusals []string
	refuse := func(marker string) {
		if seenRefusal[marker] {
			return
		}
		seenRefusal[marker] = true
		refusals = append(refusals, marker)
	}
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
			repo, path, err := k.fluxPath(ctx, kuzNs, kustom)
			if err == nil {
				add(repo, path)
				continue
			}
			if marker := fluxSourceRefusal(err); marker != "" {
				// The Kustomization exists and declares a source; the
				// service refused to address it. The fall-through below
				// is unchanged from any other lookup failure — a second
				// GitOps annotation can still resolve, and GITOPS_REPO
				// can still replace the missing path — but the refusal
				// is a decision by this service, so the digest states it
				// (issue #318). Fixed message: the refused value is
				// object-authored text and stays out of the logs for the
				// same reason it stays out of the digest.
				logf("enrich: flux kustomization sourceRef is not a valid path segment; skipping the Flux source lookup")
				refuse(marker)
			}
		}
		if app := p.Annotations["argocd.argoproj.io/instance"]; app != "" {
			if !fluxPathSegment(app) {
				// The same segment check argocdPath applies at the sender,
				// applied here so the refusal is visible: argocdPath can
				// only report "no path", which is also what a pod with no
				// Application at all yields. A refused value must record
				// its own marker (issue #312). The logged message is
				// fixed — the value is author-controlled text and stays
				// out of the logs for the same reason it stays out of the
				// digest.
				logf("enrich: argo application instance is not a valid path segment; skipping the Argo Application lookup")
				refuse(argoInstanceRefusal)
				continue
			}
			if repo, path, ok := k.argocdPath(ctx, app); ok {
				add(repo, path)
				continue
			}
		}
	}
	if len(out) == 0 && cfg.GitOpsRepo != "" {
		add(cfg.GitOpsRepo, cfg.GitOpsPath)
	}
	return out, refusals
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
//     A refused singular field (spec.path, the sourceRef name, a declared
//     sourceRef group, a declared sourceRef kind) renders an explicit
//     "refused" marker so it never reads as an absent one; refused
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
		case spec.SourceRef.Group != "" && !safe(spec.SourceRef.Group):
			// The group disambiguates same-named sources across API
			// groups (#307): with it declared but refused, the fragment
			// cannot honestly name one object, so the whole fragment is
			// refused rather than presenting an ambiguous reference as
			// identified.
			src = "refused"
		case spec.SourceRef.Kind != "" && !safe(spec.SourceRef.Kind):
			// The kind is only quoted into the fragment here — this
			// record never builds an apiserver path from it — but a
			// declared kind that fails the same character check cannot
			// just drop out: composing the fragment without it reads as
			// a kind-less reference, as if no kind had been declared.
			// Like a refused name or group, the whole fragment is
			// refused (#326).
			src = "refused"
		default:
			src = spec.SourceRef.Name
			if spec.SourceRef.Kind != "" && safe(spec.SourceRef.Kind) {
				src = spec.SourceRef.Kind + "/" + src
			}
			if spec.SourceRef.Group != "" {
				src = spec.SourceRef.Group + "/" + src
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

// The refused values get their own errors so that a caller can tell a
// refused value from an object that is genuinely absent: the read failed
// before the request was built, so nothing is known about the Kustomization
// itself. The messages are fixed and never repeat the refused value, which
// is author-controlled text that must not reach the digest.
var (
	errKustomizationNamespaceRefused = errors.New("kustomization namespace is not a valid path segment")
	errKustomizationNameRefused      = errors.New("kustomization name is not a valid path segment")
)

// kustomizationFailureReason renders why a Kustomization read failed.
//
// A refused namespace or name is reported as "not read": the value was
// rejected before the request was built, so claiming the Kustomization is
// absent would state something the service never checked. Every other
// failure keeps the "not found" shape the other failed reads use.
func kustomizationFailureReason(err error) string {
	if errors.Is(err, errKustomizationNamespaceRefused) || errors.Is(err, errKustomizationNameRefused) {
		return "Flux Kustomization not read: " + truncate(err.Error(), 160)
	}
	return "Flux Kustomization not found: " + truncate(err.Error(), 160)
}

// fluxKustomization reads one Flux Kustomization and returns its spec plus
// the status revision it currently reconciles at. Callers that only want the
// repo+path pair should go through fluxPath, so a failed lookup is never
// re-issued as a second identical kustomization GET.
//
// The namespace and the name are interpolated into an apiserver path, and
// both can come from a pod annotation, so each is validated as one path
// segment before use: a value carrying a separator addresses a different
// object than the one the pod names. A refused value fails the read outright
// and no request is sent, so every caller degrades to no Kustomization
// rather than to evidence about some other object.
func (k *kube) fluxKustomization(ctx context.Context, ns, name string) (kustomizationSpec, string, error) {
	if !fluxPathSegment(ns) {
		return kustomizationSpec{}, "", errKustomizationNamespaceRefused
	}
	if !fluxPathSegment(name) {
		return kustomizationSpec{}, "", errKustomizationNameRefused
	}
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

// fluxSourceNamespace returns the namespace the source object a Kustomization
// names in spec.sourceRef lives in.
//
// Flux resolves a sourceRef that carries no namespace against the
// Kustomization's own namespace, so an absent spec.sourceRef.namespace means
// "the local namespace". An explicit namespace names a different object and is
// honoured as written: falling back to the local namespace would resolve a
// same-named source the Kustomization does not use, and the digest would then
// name the wrong repository and classify a commit against its files.
func fluxSourceNamespace(spec kustomizationSpec, kustomNS string) string {
	if spec.SourceRef.Namespace != "" {
		return spec.SourceRef.Namespace
	}
	return kustomNS
}

// fluxPathSegment reports whether v can be interpolated into an apiserver
// path as one segment.
//
// The allow-list is narrow on purpose: a namespace is a lowercase DNS label
// and an object name a lowercase DNS subdomain, so nothing outside the
// lowercase-alphanumeric, '-' and '.' set can occur in one. An Argo
// Application name is also a DNS subdomain, so the same check serves it.
// Refusing the complement rather than searching for the dangerous
// characters is what makes the check impossible to slip past with an
// encoded form: '%' would smuggle a separator past a check on the literal
// characters, and '?' or '#' would end the path at the value instead of
// being part of it. A leading or trailing separator is refused because no
// label or subdomain has one, and ".." is refused because two separators in
// a row is a traversal pair.
func fluxPathSegment(v string) bool {
	if v == "" || len(v) > 253 || strings.Contains(v, "..") {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '.':
			if i == 0 || i == len(v)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// errFluxSourceNamespaceRefused and errFluxSourceNameRefused are the
// refusals issued below. The messages are fixed and never echo the
// offending value, which is author-controlled text that must not reach
// the digest. They are sentinels so a caller can tell "this value was
// refused" from "the object could not be read" with errors.Is; only the
// refusals earn a digest marker (issue #318).
var (
	errFluxSourceNamespaceRefused = errors.New("flux source namespace is not a valid path segment")
	errFluxSourceNameRefused      = errors.New("flux source name is not a valid path segment")
)

// errFluxPathUnresolved marks a fluxPath lookup whose values were all
// readable but whose repo+path pair is simply not there: an empty
// spec.path or an empty source spec.url. It is not a refusal and never
// yields a marker. A sourceRef that declares no source to read keeps the
// plain error the segment checks returned before issue #318, so its
// output stays the absence it always was.
var errFluxPathUnresolved = errors.New("flux kustomization does not resolve to a repo path")

// fluxSourceURL reads the source object a Kustomization's sourceRef names and
// returns its spec.url. An empty kind defaults to GitRepository, matching the
// sourceRef default Flux applies. The empty-URL case is left to callers: for
// relevance it degrades to "not readable", for repo+path lookups to no path.
//
// The namespace and the name are interpolated into an apiserver path, and
// the namespace may now come from spec.sourceRef.namespace rather than only
// from the Kustomization's own namespace, so both are validated as one path
// segment before use: a value carrying a separator would address a different
// object than the one declared. A refused value fails the lookup outright —
// there is no second namespace to fall back to, because falling back is how a
// same-named source the Kustomization does not use gets resolved. The
// refusal errors are the sentinel vars above, so resolveRepoPaths can mark
// the refused field without re-deriving why the lookup failed (issue #318).
//
// An absent value is told apart from a refused one before any refusal
// sentinel is assigned: a sourceRef that declares no name (or no namespace
// to address) has no value to refuse, and reporting it as refused would
// state a decision about a value the object never declared. Only a refusal
// earns a marker. An absence is not a new classification either — it
// returns the exact errors the segment checks returned before issue #318,
// so a Kustomization that simply declares no source keeps its previous
// output: the same commit-relevance reason, no path and no marker.
func (k *kube) fluxSourceURL(ctx context.Context, ns, srcKind, srcName string) (string, error) {
	// The refusals are decided before the absences, so a declared value
	// this service refuses is still reported when the other value is
	// absent: an absence must not mask a refusal.
	if ns != "" && !fluxPathSegment(ns) {
		return "", errFluxSourceNamespaceRefused
	}
	if srcName != "" && !fluxPathSegment(srcName) {
		return "", errFluxSourceNameRefused
	}
	if ns == "" {
		return "", errors.New("flux source namespace is not a valid path segment")
	}
	if srcName == "" {
		return "", errors.New("flux source name is not a valid path segment")
	}
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

// fluxPath resolves the repo+path pair of one Flux Kustomization. The
// error says why a pair did not resolve, and the distinction is only for
// the caller that renders evidence: errFluxSourceNamespaceRefused and
// errFluxSourceNameRefused mark a sourceRef value refused as not one path
// segment — a decision this service made about a value it had read —
// while every other failure (missing object or source, empty spec.path or
// spec.url, a sourceRef that declares no source) means the pair simply
// could not be read. A namespace refusal for a sourceRef that declares no
// namespace is folded into errFluxPathUnresolved, because the refused value
// is then the inherited Kustomization namespace — the service's own lookup
// key, not an object-declared field. Callers that do not distinguish treat
// err != nil exactly as the old false and degrade as before (issue #318).
func (k *kube) fluxPath(ctx context.Context, ns, name string) (string, string, error) {
	kuz, _, err := k.fluxKustomization(ctx, ns, name)
	if err != nil {
		return "", "", err
	}
	if kuz.Path == "" {
		return "", "", errFluxPathUnresolved
	}
	srcURL, err := k.fluxSourceURL(ctx, fluxSourceNamespace(kuz, ns), kuz.SourceRef.Kind, kuz.SourceRef.Name)
	if err != nil {
		if errors.Is(err, errFluxSourceNamespaceRefused) && kuz.SourceRef.Namespace == "" {
			// The refused value is not a namespace the object declared but
			// the Kustomization's own namespace, inherited from the pod's
			// annotation. A Kustomization read through that value already
			// succeeded, so no apiserver that served this object can have
			// treated the value as two segments; if something on the way
			// collapsed it, the locator was hostile rather than canonical.
			// Either way this is a refusal of the service's own lookup key,
			// not of an object-declared source field, and only a declared
			// field earns a digest line naming it (issue #318).
			return "", "", errFluxPathUnresolved
		}
		return "", "", err
	}
	if srcURL == "" {
		return "", "", errFluxPathUnresolved
	}
	return srcURL, kuz.Path, nil
}

func (k *kube) argocdPath(ctx context.Context, instance string) (string, string, bool) {
	// The instance is interpolated into the Application path, so a value
	// that is not one path segment must never be sent: the request would
	// address a different Application than the one the pod declares. An
	// Argo Application name is a DNS subdomain, so the same segment check
	// covers it. resolveRepoPaths pre-checks the annotation and records a
	// refusal marker before calling (issue #312); this guard is what keeps
	// "never send a refused value" an invariant of the sender itself, not
	// of one caller. The message is fixed and does not echo the value,
	// which is author-controlled text that must not reach the digest.
	if !fluxPathSegment(instance) {
		logf("enrich: argo application instance is not a valid path segment; skipping the Argo Application lookup")
		return "", "", false
	}
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
