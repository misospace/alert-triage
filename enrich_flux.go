package main

import (
	"context"
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

func shortRev(rev string) string {
	if rev == "" {
		return "unknown"
	}
	if i := strings.LastIndex(rev, ":"); i >= 0 && len(rev) > i+9 {
		return rev[:i+9]
	}
	return truncate(rev, 24)
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
