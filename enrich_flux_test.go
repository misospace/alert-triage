package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFluxList(t *testing.T) {
	data := []byte(`{"items":[{"metadata":{"name":"f1","namespace":"flux"},"status":{"conditions":[{"type":"Ready","status":"False"}]}}]}`)
	var got fluxList
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Metadata.Name != "f1" {
		t.Errorf("unexpected result: %v", got)
	}
}

func TestFluxListEmpty(t *testing.T) {
	var got fluxList
	if err := json.Unmarshal([]byte(`{"items":[]}`), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

// TestResolveRepoPathsFluxKustomization exercises the Flux Kustomization
// → GitRepository path. The kube is wired to a test server that returns
// matching Kustomization and GitRepository specs.
func TestResolveRepoPathsFluxKustomization(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/"):
			_, _ = io.WriteString(w, `{"spec":{"path":"clusters/staging","sourceRef":{"name":"flux-system","kind":"GitRepository"}}}`)
		case strings.Contains(r.URL.Path, "/gitrepositories/"):
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/example/staging-repo"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	pods := []podRef{{
		Name:      "p1",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "flux-system",
			"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
		},
	}}
	cfg := &Config{}
	got, _ := k.resolveRepoPaths(context.Background(), pods, cfg)
	if len(got) != 1 {
		t.Fatalf("expected 1 resolved path, got %#v", got)
	}
	if got[0] != "https://github.com/example/staging-repo/clusters/staging" {
		t.Fatalf("unexpected entry: %q", got[0])
	}
}

// TestResolveRepoPathsFluxPath exercises the fluxPath branch via
// resolveRepoPaths: the pod carries both the kustomize.toolkit.fluxcd.io/name
// and the kustomize.toolkit.fluxcd.io/namespace annotations, so resolveRepoPaths
// routes the lookup through k.fluxPath(annotation-ns, kustomization-name) and
// resolves the repo+path from the Kustomization + GitRepository pair.
func TestResolveRepoPathsFluxPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/"):
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/payments","sourceRef":{"name":"payments-repo","kind":"GitRepository"}}}`)
		case strings.Contains(r.URL.Path, "/gitrepositories/"):
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/example/payments"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	pods := []podRef{{
		Name:      "p2",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "payments",
			"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
		},
	}}
	got, _ := k.resolveRepoPaths(context.Background(), pods, &Config{})
	if len(got) != 1 || got[0] != "https://github.com/example/payments/apps/payments" {
		t.Fatalf("unexpected paths: %#v", got)
	}
}

// TestResolveRepoPathsFluxSourceRefNamespace covers the cross-namespace
// sourceRef (issue #296): the Kustomization names a source that lives in
// another namespace, so the source must be read there. A same-named source
// in the Kustomization's own namespace must never be read — resolving it
// would put the wrong repository in the digest.
func TestResolveRepoPathsFluxSourceRefNamespace(t *testing.T) {
	var localHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/namespaces/workloads/kustomizations/demo"):
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/demo","sourceRef":{"kind":"GitRepository","name":"config","namespace":"sources"}}}`)
		case strings.HasSuffix(r.URL.Path, "/namespaces/sources/gitrepositories/config"):
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/example/right"}}`)
		case strings.HasSuffix(r.URL.Path, "/namespaces/workloads/gitrepositories/config"):
			// The same-named local source: reading it would resolve the
			// wrong repository.
			localHits.Add(1)
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/example/wrong"}}`)
		default:
			t.Errorf("unexpected API hit for %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	pods := []podRef{{
		Name:      "p1",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "demo",
			"kustomize.toolkit.fluxcd.io/namespace": "workloads",
		},
	}}
	got, _ := k.resolveRepoPaths(context.Background(), pods, &Config{})
	if len(got) != 1 || got[0] != "https://github.com/example/right/apps/demo" {
		t.Fatalf("unexpected paths: %#v", got)
	}
	if localHits.Load() != 0 {
		t.Fatalf("the same-named local source must not be read, got %d hits", localHits.Load())
	}
}

// TestResolveRepoPathsFluxSourceRefNamespaceMissingSource covers the
// degraded case: the referenced source does not exist in the namespace the
// Kustomization declares. The lookup must fail rather than fall back to a
// same-named source in the Kustomization's own namespace, because that
// source is not the one the Kustomization uses (issue #296).
func TestResolveRepoPathsFluxSourceRefNamespaceMissingSource(t *testing.T) {
	var localHits, kuzHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/namespaces/workloads/kustomizations/demo"):
			kuzHits.Add(1)
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/demo","sourceRef":{"kind":"GitRepository","name":"config","namespace":"sources"}}}`)
		case strings.HasSuffix(r.URL.Path, "/namespaces/sources/gitrepositories/config"):
			// The declared source is absent.
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, "/namespaces/workloads/gitrepositories/config"):
			localHits.Add(1)
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/example/wrong"}}`)
		default:
			t.Errorf("unexpected API hit for %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	pods := []podRef{{
		Name:      "p1",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "demo",
			"kustomize.toolkit.fluxcd.io/namespace": "workloads",
		},
	}}
	got, _ := k.resolveRepoPaths(context.Background(), pods, &Config{})
	if len(got) != 0 {
		t.Fatalf("expected no GitOps path when the declared source is missing, got %#v", got)
	}
	if localHits.Load() != 0 {
		t.Fatalf("must not fall back to the same-named local source, got %d hits", localHits.Load())
	}
	// The Kustomization itself must have been read: without this the test
	// would also pass if the lookup stopped at the Kustomization, which is a
	// different failure than the one it pins.
	if kuzHits.Load() == 0 {
		t.Fatalf("expected the Kustomization to be read before the source lookup")
	}
}

// TestResolveRepoPathsFluxSourceRefNamespaceOmitted pins the default: a
// sourceRef without a namespace is resolved in the Kustomization's own
// namespace, as Flux does (issue #296).
func TestResolveRepoPathsFluxSourceRefNamespaceOmitted(t *testing.T) {
	var localHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/namespaces/workloads/kustomizations/demo"):
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/demo","sourceRef":{"kind":"GitRepository","name":"config"}}}`)
		case strings.HasSuffix(r.URL.Path, "/namespaces/workloads/gitrepositories/config"):
			localHits.Add(1)
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/example/local"}}`)
		default:
			t.Errorf("unexpected API hit for %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	pods := []podRef{{
		Name:      "p1",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "demo",
			"kustomize.toolkit.fluxcd.io/namespace": "workloads",
		},
	}}
	got, _ := k.resolveRepoPaths(context.Background(), pods, &Config{})
	if len(got) != 1 || got[0] != "https://github.com/example/local/apps/demo" {
		t.Fatalf("unexpected paths: %#v", got)
	}
	if localHits.Load() == 0 {
		t.Fatalf("expected the source in the Kustomization's own namespace to be read")
	}
}

// TestFluxSourceNamespaceHostile pins the guard on the declared source
// namespace: it is interpolated into an apiserver path, so a value carrying
// a separator must be refused outright rather than addressed as something
// else. The refusal is fixed text — the hostile value must not travel into
// the digest.
func TestFluxSourceNamespaceHostile(t *testing.T) {
	const hostile = "sources/../workloads"
	var sourceHits, kuzHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/namespaces/workloads/kustomizations/demo"):
			kuzHits.Add(1)
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/demo","sourceRef":{"kind":"GitRepository","name":"config","namespace":"`+hostile+`"}}}`)
		case strings.Contains(r.URL.Path, "/gitrepositories/"):
			sourceHits.Add(1)
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/example/wrong"}}`)
		default:
			t.Errorf("unexpected API hit for %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	pods := []podRef{{
		Name:      "p1",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "demo",
			"kustomize.toolkit.fluxcd.io/namespace": "workloads",
		},
	}}
	got, _ := k.resolveRepoPaths(context.Background(), pods, &Config{})
	if len(got) != 0 {
		t.Fatalf("expected no GitOps path for a refused source namespace, got %#v", got)
	}
	if sourceHits.Load() != 0 {
		t.Fatalf("a refused source namespace must not be requested, got %d hits", sourceHits.Load())
	}
	if kuzHits.Load() == 0 {
		t.Fatalf("expected the Kustomization to be read before the source lookup")
	}
	// The relevance path degrades to "unknown" with a one-line reason that
	// does not carry the refused value.
	gh := &gitHubClient{token: "t", repo: "owner/repo", hc: &http.Client{}, apiURL: "http://unused.invalid"}
	rel := k.resolveCommitRelevance(context.Background(), gh, pods)
	if len(rel) != 1 {
		t.Fatalf("expected 1 CommitRelevance, got %d", len(rel))
	}
	if rel[0].State != commitRelevanceUnknown {
		t.Fatalf("state = %q, want %q", rel[0].State, commitRelevanceUnknown)
	}
	if strings.Contains(rel[0].Reason, hostile) {
		t.Fatalf("reason must not echo the refused namespace: %q", rel[0].Reason)
	}
	if strings.Contains(rel[0].Reason, "\n") {
		t.Fatalf("reason must be one line: %q", rel[0].Reason)
	}
	// The reason must name the source lookup, not the Kustomization read:
	// "Kustomization not found" would satisfy the assertions above for the
	// wrong reason, since a Kustomization that is never read fails the same way.
	if !strings.Contains(rel[0].Reason, "not readable") {
		t.Fatalf("reason must name the unreadable source: %q", rel[0].Reason)
	}
}

// TestFluxPathSegment pins the segment check that guards the values
// interpolated into an apiserver path. The refused set is what keeps a
// request aimed at the object the Kustomization declares.
func TestFluxPathSegment(t *testing.T) {
	valid := []string{"sources", "flux-system", "config", "config.prod", "a1", "s0urces-2"}
	for _, v := range valid {
		if !fluxPathSegment(v) {
			t.Errorf("fluxPathSegment(%q) = false, want true", v)
		}
	}
	invalid := []string{
		"",
		".",
		"..",
		"a..b",
		"a b",
		"a\tb",
		"a/b",
		`a\b`,
		"a%2f",
		"a?b",
		"a#b",
		"Sources",
		"-sources",
		"sources-",
		".sources",
		"sources.",
		"sources\x00",
	}
	for _, v := range invalid {
		if fluxPathSegment(v) {
			t.Errorf("fluxPathSegment(%q) = true, want false", v)
		}
	}
}

// TestResolveRepoPathsMissingKustomization asserts that when a pod carries
// the Flux annotations but the referenced Kustomization is missing (the
// API returns 404), resolveRepoPaths still ships (returns cleanly
// without error) and no spurious GitOps path is attached. This is the
// regression test for #92: the now-removed fluxHelmPath "Helm release"
// rescue branch would have re-issued an identical fluxPath call against
// the same kustomization+namespace, fabricating a hit count of two for
// the kustomization lookup and masking the failure.
func TestResolveRepoPathsMissingKustomization(t *testing.T) {
	var kuzHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/ghost-payments"):
			// Simulate the Kustomization being absent.
			kuzHits++
			http.NotFound(w, r)
		default:
			t.Errorf("unexpected API hit for %s; resolveRepoPaths must not retry after a 404", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	// Pod carries the Flux annotations, but the Kustomization does not
	// exist in the cluster (404). The digest must still ship and the
	// function must return without attaching a fabricated GitOps path.
	pods := []podRef{{
		Name:      "p2",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "ghost-payments",
			"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
		},
	}}
	got, _ := k.resolveRepoPaths(context.Background(), pods, &Config{})
	if len(got) != 0 {
		t.Fatalf("expected no GitOps paths when Kustomization is missing, got: %#v", got)
	}
	// fluxHelmPath used to make a second, identical kustomization lookup
	// that always failed identically. Pin this contract: the
	// kustomization endpoint is hit at most once.
	if kuzHits > 1 {
		t.Fatalf("expected at most one kustomization lookup after 404, got %d", kuzHits)
	}
	if kuzHits == 0 {
		t.Fatalf("expected the kustomization lookup to be attempted once, got 0")
	}
}

// TestResolveRepoPathsArgoApplication exercises the ArgoCD branch: the
// pod carries an argocd.argoproj.io/instance annotation, and the API
// returns a matching Application spec.
func TestResolveRepoPathsArgoApplication(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"spec":{"source":{"repoURL":"https://github.com/example/argo","path":"manifests/web"}}}`)
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	pods := []podRef{{
		Name:      "p3",
		Namespace: "ns-b",
		Annotations: map[string]string{
			"argocd.argoproj.io/instance": "guestbook",
		},
	}}
	got, refusals := k.resolveRepoPaths(context.Background(), pods, &Config{})
	if len(got) != 1 || got[0] != "https://github.com/example/argo/manifests/web" {
		t.Fatalf("unexpected paths: %#v", got)
	}
	if len(refusals) != 0 {
		t.Fatalf("a resolved Application must yield no refusal marker, got %#v", refusals)
	}
}

// TestResolveRepoPathsArgoMissingApplicationNoMarker pins that an
// Application which does not exist (every lookup 404s) keeps today's
// output: no path and no refusal marker. The service refused nothing —
// the pod's declaration was honoured and simply found no object, which
// must stay distinguishable from a refused reference (issue #312).
func TestResolveRepoPathsArgoMissingApplicationNoMarker(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
	pods := []podRef{{
		Name:      "p3",
		Namespace: "ns-b",
		Annotations: map[string]string{
			"argocd.argoproj.io/instance": "guestbook",
		},
	}}
	got, refusals := k.resolveRepoPaths(context.Background(), pods, &Config{})
	if len(got) != 0 {
		t.Fatalf("expected no paths for a missing Application, got %#v", got)
	}
	if len(refusals) != 0 {
		t.Fatalf("a missing Application is not a refusal and must carry no marker, got %#v", refusals)
	}
	if hits.Load() == 0 {
		t.Fatalf("a valid instance must still be looked up, got 0 hits")
	}
}

// TestResolveRepoPathsArgoInstanceHostile pins the guard on the Argo
// Application instance: the instance is interpolated into the Application
// path, so a value carrying a separator must be refused outright rather
// than addressed as a different Application. Nothing may be requested - not
// even the cluster-wide retry - and the result degrades to "no path from
// this annotation", so the caller can fall back to the configured GitOps
// repository. The refusal is a decision by the service, so it is reported:
// exactly one fixed marker line naming the field, never repeating the
// workload-authored value (issue #312).
func TestResolveRepoPathsArgoInstanceHostile(t *testing.T) {
	const hostile = "demo/../../other"
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// The path is not echoed: a hit would carry the refused value
		// into the test output.
		t.Errorf("unexpected API hit; a refused instance must not be requested")
		http.NotFound(w, r)
	}))
	defer srv.Close()
	k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
	// Two pods of the same deployment carry the same hostile annotation and
	// a third carries a different refused value: the marker names the
	// field, not the value, so every refusal of this field collapses to one
	// line — never one per replica, never one per distinct value.
	pods := []podRef{
		{
			Name:      "p1",
			Namespace: "ns-a",
			Annotations: map[string]string{
				"argocd.argoproj.io/instance": hostile,
			},
		},
		{
			Name:      "p2",
			Namespace: "ns-a",
			Annotations: map[string]string{
				"argocd.argoproj.io/instance": hostile,
			},
		},
		{
			Name:      "p3",
			Namespace: "ns-a",
			Annotations: map[string]string{
				"argocd.argoproj.io/instance": "api%2Felsewhere",
			},
		},
	}
	got, refusals := k.resolveRepoPaths(context.Background(), pods, &Config{})
	if len(got) != 0 {
		t.Fatalf("expected no GitOps path for a refused instance, got %#v", got)
	}
	if hits.Load() != 0 {
		t.Fatalf("a refused instance must not be requested, got %d hits", hits.Load())
	}
	if len(refusals) != 1 || refusals[0] != argoInstanceRefusal {
		t.Fatalf("expected exactly the fixed refusal marker, got %#v", refusals)
	}
	// The refused value is workload-authored annotation text; issue #308
	// keeps it out of the digest, so the marker repeats neither the whole
	// value nor any recognisable piece of it.
	if strings.Contains(refusals[0], hostile) || strings.Contains(refusals[0], "demo") {
		t.Fatalf("the marker must never repeat the refused value, got %q", refusals[0])
	}
	// The lookup itself reports "no GitOps path", so the caller keeps
	// whatever else it knows about the workload's source.
	if repo, path, ok := k.argocdPath(context.Background(), hostile); ok || repo != "" || path != "" {
		t.Fatalf("a refused instance must yield no path, got %q %q", repo, path)
	}
	if hits.Load() != 0 {
		t.Fatalf("a refused instance must not be requested, got %d hits", hits.Load())
	}
	// With a fallback configured the refusal degrades to that fallback,
	// which is what "no path from this annotation" means — and the marker
	// travels alongside it, because a fallback path does not make the
	// refused declaration disappear.
	cfg := &Config{GitOpsRepo: "https://github.com/example/fallback", GitOpsPath: "deploy/staging"}
	got, refusals = k.resolveRepoPaths(context.Background(), pods, cfg)
	if len(got) != 1 || got[0] != "https://github.com/example/fallback/deploy/staging" {
		t.Fatalf("expected the configured fallback, got %#v", got)
	}
	if len(refusals) != 1 || refusals[0] != argoInstanceRefusal {
		t.Fatalf("the marker must survive the fallback, got %#v", refusals)
	}
	if hits.Load() != 0 {
		t.Fatalf("a refused instance must not be requested, got %d hits", hits.Load())
	}
}

// TestResolveRepoPathsFluxResolvedHidesArgoRefusal pins that a pod whose
// Flux annotation resolves never reaches the Argo branch: its (hostile)
// argocd.argoproj.io/instance is neither requested nor marked. The pod's
// GitOps owner was found; a second annotation the service never consulted
// is not a refusal the digest should announce.
func TestResolveRepoPathsFluxResolvedHidesArgoRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/applications/"):
			t.Errorf("a pod whose Flux annotation resolved must not trigger an Application lookup: %s", r.URL.Path)
			http.NotFound(w, r)
		case strings.Contains(r.URL.Path, "/kustomizations/"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/web","sourceRef":{"name":"web-repo","kind":"GitRepository"}}}`)
		case strings.Contains(r.URL.Path, "/gitrepositories/"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/example/web"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
	pods := []podRef{{
		Name:      "p6",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name": "web",
			"argocd.argoproj.io/instance":      "web/../../other",
		},
	}}
	got, refusals := k.resolveRepoPaths(context.Background(), pods, &Config{})
	if len(got) != 1 || got[0] != "https://github.com/example/web/apps/web" {
		t.Fatalf("expected the Flux-resolved path, got %#v", got)
	}
	if len(refusals) != 0 {
		t.Fatalf("a consulted-and-refused reference is the marker's subject; an unconsulted one must not mark, got %#v", refusals)
	}
}

// TestResolveRepoPathsGitOpsFallback exercises the GITOPS_REPO +
// GITOPS_PATH fallback: pods without GitOps annotations but with the
// fallback configured should still resolve to a repo path.
func TestResolveRepoPathsGitOpsFallback(t *testing.T) {
	// No server should be hit for this branch — the API would 404 but
	// we'd notice.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected API hit for %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	pods := []podRef{{Name: "plain", Namespace: "ns", Annotations: map[string]string{}}}
	cfg := &Config{GitOpsRepo: "https://github.com/example/fallback", GitOpsPath: "deploy/staging"}
	got, _ := k.resolveRepoPaths(context.Background(), pods, cfg)
	if len(got) != 1 || got[0] != "https://github.com/example/fallback/deploy/staging" {
		t.Fatalf("unexpected fallback paths: %#v", got)
	}
}

// TestResolveRepoPathsEmpty exercises the empty-result case: no pods, or
// pods with no annotations and no fallback configured.
func TestResolveRepoPathsEmpty(t *testing.T) {
	k := &kube{}
	if got, refusals := k.resolveRepoPaths(context.Background(), nil, &Config{}); got != nil || refusals != nil {
		t.Fatalf("expected nil, got %#v / %#v", got, refusals)
	}
	cfg := &Config{}
	// A pod with no GitOps annotations declares nothing, so it gets no
	// refusal marker either: the marker is only for a reference that was
	// present and refused (issue #312).
	if got, refusals := k.resolveRepoPaths(context.Background(), []podRef{{Annotations: map[string]string{}}}, cfg); got != nil || refusals != nil {
		t.Fatalf("expected nil when nothing resolves and no fallback configured, got %#v / %#v", got, refusals)
	}
}

// fluxKustomizationAPIHarness serves one Kustomization (by name, when
// kuzJSON is non-empty) and one GitRepository (when repoJSON is non-empty).
// A null Kustomization simulates the object being absent.
func fluxKustomizationAPIHarness(t *testing.T, kuzName, kuzJSON, repoJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/kustomizations/") {
			if kuzJSON == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, kuzJSON)
			return
		}
		if strings.Contains(r.URL.Path, "/gitrepositories/") {
			if repoJSON == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, repoJSON)
			return
		}
		http.NotFound(w, r)
	}))
}

func fluxAnnotatedPod(name, ns, kuz, kuzNs string) []podRef {
	ann := map[string]string{"kustomize.toolkit.fluxcd.io/name": kuz}
	if kuzNs != "" {
		ann["kustomize.toolkit.fluxcd.io/namespace"] = kuzNs
	}
	return []podRef{{Name: name, Namespace: ns, Annotations: ann}}
}

// TestResolveKustomizationTopologyWithComponentsAndDependencies is the
// motivating case: the resolved Kustomization pulls in a reusable component
// and a dependency, so the topology record must surface all three: the
// Kustomization name, its source/path, the component paths as declared, and
// the dependsOn names (with any foreign namespace made explicit).
func TestResolveKustomizationTopologyWithComponentsAndDependencies(t *testing.T) {
	srv := fluxKustomizationAPIHarness(t, "web",
		`{"spec":{"path":"apps/web","sourceRef":{"kind":"GitRepository","name":"main","namespace":"flux-system"},
		 "components":["../base/common"],
		 "dependsOn":[{"name":"base-common"},{"name":"db","namespace":"databases"}]}}`,
		`{"spec":{"url":"https://github.com/example/web"}}`)
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	got := k.resolveKustomizationTopology(context.Background(), fluxAnnotatedPod("web-0", "apps", "web", ""))
	if len(got) != 1 {
		t.Fatalf("expected exactly one topology record, got %#v", got)
	}
	rec := got[0]
	for _, want := range []string{
		"kustomization apps/web (path: apps/web)",
		"GitRepository/main (flux-system)",
		"components: ../base/common",
		"dependsOn: base-common, databases/db",
	} {
		if !strings.Contains(rec, want) {
			t.Errorf("record missing %q: %s", want, rec)
		}
	}
}

// TestResolveKustomizationTopologyNoComposition covers a Kustomization with
// no spec.components and no spec.dependsOn: both subsections render as an
// explicit "none declared" rather than being silently dropped, and the
// sourceRef without an explicit kind renders under its default kind.
func TestResolveKustomizationTopologyNoComposition(t *testing.T) {
	srv := fluxKustomizationAPIHarness(t, "bare",
		`{"spec":{"path":"apps/bare","sourceRef":{"kind":"GitRepository","name":"main"}}}`,
		`{"spec":{"url":"https://github.com/example/bare"}}`)
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	got := k.resolveKustomizationTopology(context.Background(), fluxAnnotatedPod("bare-0", "apps", "bare", ""))
	if len(got) != 1 {
		t.Fatalf("expected exactly one topology record, got %#v", got)
	}
	rec := got[0]
	for _, want := range []string{"kustomization apps/bare (path: apps/bare)", "components: none declared", "dependsOn: none declared"} {
		if !strings.Contains(rec, want) {
			t.Errorf("record missing %q: %s", want, rec)
		}
	}
}

// TestResolveKustomizationTopologyFailedLookup is the lookup-failure case:
// the pod carries the Flux annotations but the Kustomization does not exist
// (404). The function must return no record at all — not a record with "none"
// subsections, which would claim the spec was read and found nothing.
func TestResolveKustomizationTopologyFailedLookup(t *testing.T) {
	srv := fluxKustomizationAPIHarness(t, "ghost", "", "")
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	got := k.resolveKustomizationTopology(context.Background(), fluxAnnotatedPod("p", "ns", "ghost", ""))
	if len(got) != 0 {
		t.Fatalf("expected no topology record when the Kustomization is missing, got %#v", got)
	}
}

// TestResolveKustomizationTopologyScopedToResolvedWorkload asserts the record
// follows the pod's own Kustomization annotation: other Kustomizations in the
// namespace are never read, and two pods resolving to the same Kustomization
// yield one record, not two.
func TestResolveKustomizationTopologyScopedToResolvedWorkload(t *testing.T) {
	var kuzGets []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/kustomizations/") {
			name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			kuzGets = append(kuzGets, name)
			if name == "web" {
				_, _ = io.WriteString(w, `{"spec":{"path":"apps/web","sourceRef":{"kind":"GitRepository","name":"main"}},"components":null,"dependsOn":null}`)
				return
			}
			http.NotFound(w, r)
			return
		}
		if strings.Contains(r.URL.Path, "/gitrepositories/") {
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/example/web"}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	pods := []podRef{
		{Name: "web-0", Namespace: "apps", Annotations: map[string]string{"kustomize.toolkit.fluxcd.io/name": "web"}},
		// A second pod resolving to the same Kustomization.
		{Name: "web-1", Namespace: "apps", Annotations: map[string]string{"kustomize.toolkit.fluxcd.io/name": "web"}},
		// A third pod whose annotations name a Kustomization that does not
		// exist in the cluster.
		{Name: "stray", Namespace: "apps", Annotations: map[string]string{"kustomize.toolkit.fluxcd.io/name": "unrelated"}},
	}
	got := k.resolveKustomizationTopology(context.Background(), pods)
	if len(got) != 1 {
		t.Fatalf("expected exactly one record (deduped), got %#v", got)
	}
	if !strings.Contains(got[0], "kustomization apps/web") {
		t.Fatalf("record must be for the resolved Kustomization, got %q", got[0])
	}
	// Only the Kustomizations the pods actually resolved to may be read,
	// and at most once each (deduped): two pods resolving to "web" cost
	// one GET, and "unrelated" costs the single failed GET it always will.
	counts := map[string]int{}
	for _, n := range kuzGets {
		counts[n]++
	}
	if len(kuzGets) != 2 || counts["web"] != 1 || counts["unrelated"] != 1 {
		t.Fatalf("kustomization GETs = %v, want web=1 and unrelated=1", kuzGets)
	}
}

// TestResolveKustomizationTopologyOciComponent covers a component that is not
// a relative path: the value is quoted as-is under its own label, so the
// record never presents it as a path this service resolved or read.
func TestResolveKustomizationTopologyOciComponent(t *testing.T) {
	srv := fluxKustomizationAPIHarness(t, "oci",
		`{"spec":{"path":"apps/oci","sourceRef":{"kind":"GitRepository","name":"main"},"components":["oci://registry.example.com/base"]}}`,
		`{"spec":{"url":"https://github.com/example/oci"}}`)
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	got := k.resolveKustomizationTopology(context.Background(), fluxAnnotatedPod("oci-0", "apps", "oci", ""))
	if len(got) != 1 {
		t.Fatalf("expected exactly one topology record, got %#v", got)
	}
	if !strings.Contains(got[0], "components: oci://registry.example.com/base") {
		t.Errorf("component must be rendered verbatim under its own label: %s", got[0])
	}
}

// TestResolveKustomizationTopologyRejectsUnsafePaths asserts sanitiser
// parity with resolveRepoPaths: the same class of value (a path-like field
// quoted from a cluster object) is dropped on the same hostile character set
// — NUL, backslash, percent — the survivors render verbatim, and the record
// is flattened and fence-inert at construction. Unlike resolveRepoPaths, no
// path.Clean runs here, so a legitimate `..` segment in a surviving
// component is preserved.
func TestResolveKustomizationTopologyRejectsUnsafePaths(t *testing.T) {
	// The JSON is a raw string so the hostile bytes arrive through JSON
	// escapes: \u0000 decodes to NUL, \\ to a single backslash, % is
	// literal.
	srv := fluxKustomizationAPIHarness(t, "web",
		`{"spec":{"path":"apps\\web","sourceRef":{"kind":"GitRepository","name":"main","namespace":"flux-system"},
		 "components":["../base/common","pods\u0000evil","pods\\..\\..","pods%2F..%2F"],
		 "dependsOn":[{"name":"base-common"},{"name":"evil\\name","namespace":"apps"}]}}`,
		`{"spec":{"url":"https://github.com/example/web"}}`)
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	got := k.resolveKustomizationTopology(context.Background(), fluxAnnotatedPod("web-0", "apps", "web", ""))
	if len(got) != 1 {
		t.Fatalf("expected exactly one topology record, got %#v", got)
	}
	rec := got[0]
	// (b) The safe values survive verbatim, including the `..` segment a
	// path.Clean (deliberately not applied here) would have collapsed.
	for _, want := range []string{
		"components: ../base/common",
		"dependsOn: base-common",
	} {
		if !strings.Contains(rec, want) {
			t.Errorf("record missing %q: %s", want, rec)
		}
	}
	// (c) The unsafe spec.path renders an explicit refused marker instead of
	// vanishing: a refused path must not read as an absent one, and the
	// hostile value itself must not appear.
	if !strings.Contains(rec, "(path: refused)") {
		t.Errorf("refused spec.path must render a refused marker: %s", rec)
	}
	if strings.Contains(rec, `apps\web`) {
		t.Errorf("unsafe spec.path value leaked into the record: %s", rec)
	}
	// (c,d) Every hostile byte class, the percent-encoding forms
	// (case-insensitive), a newline, and a triple-dash run are absent.
	for _, hostile := range []string{"\x00", `\`, "\n", "---"} {
		if strings.Contains(rec, hostile) {
			t.Errorf("record carries hostile value %q: %s", hostile, rec)
		}
	}
	if lower := strings.ToLower(rec); strings.Contains(lower, "%2f") || strings.Contains(lower, "%2e") {
		t.Errorf("percent-encoded traversal survived: %s", rec)
	}
	if strings.Contains(rec, "pods") {
		t.Errorf("unsafe component values leaked into the record: %s", rec)
	}
	if strings.Contains(rec, "evil") {
		t.Errorf("unsafe dependency name leaked into the record: %s", rec)
	}
}

// TestResolveKustomizationTopologyNoneSafeVersusNoneDeclared pins the
// explicit negative: a subsection whose declared values were all refused
// reads "none safe", while an empty spec reads "none declared" — two
// different findings that a shared "none" would collapse.
func TestResolveKustomizationTopologyNoneSafeVersusNoneDeclared(t *testing.T) {
	run := func(t *testing.T, kuzJSON string) string {
		t.Helper()
		srv := fluxKustomizationAPIHarness(t, "kuz", kuzJSON,
			`{"spec":{"url":"https://github.com/example/kuz"}}`)
		defer srv.Close()

		k := &kube{hc: srv.Client(), base: srv.URL}
		got := k.resolveKustomizationTopology(context.Background(), fluxAnnotatedPod("p-0", "apps", "kuz", ""))
		if len(got) != 1 {
			t.Fatalf("expected exactly one topology record, got %#v", got)
		}
		return got[0]
	}
	t.Run("all components unsafe", func(t *testing.T) {
		rec := run(t, `{"spec":{"path":"apps/kuz","sourceRef":{"kind":"GitRepository","name":"main"},
			"components":["pods\u0000evil","pods\\..\\..","pods%2F..%2F"]}}`)
		if !strings.Contains(rec, "components: none safe") {
			t.Errorf("record must say none safe when every component was refused: %s", rec)
		}
		if strings.Contains(rec, "components: none declared") {
			t.Errorf("refused components must not read as undeclared: %s", rec)
		}
	})
	t.Run("none declared", func(t *testing.T) {
		rec := run(t, `{"spec":{"path":"apps/kuz","sourceRef":{"kind":"GitRepository","name":"main"}}}`)
		if !strings.Contains(rec, "components: none declared") {
			t.Errorf("record must say none declared for an empty components list: %s", rec)
		}
		if strings.Contains(rec, "components: none safe") {
			t.Errorf("an empty spec must not read as refused: %s", rec)
		}
	})
	t.Run("all dependencies unsafe", func(t *testing.T) {
		rec := run(t, `{"spec":{"path":"apps/kuz","sourceRef":{"kind":"GitRepository","name":"main"},
			"dependsOn":[{"name":"evil\\name"},{"name":"ok","namespace":"bad\\ns"}]}}`)
		if !strings.Contains(rec, "dependsOn: none safe") {
			t.Errorf("record must say none safe when every dependency was refused: %s", rec)
		}
		if strings.Contains(rec, "dependsOn: none declared") {
			t.Errorf("refused dependencies must not read as undeclared: %s", rec)
		}
	})
}

// TestResolveKustomizationTopologyRefusedSingularFields pins the singular
// half of the refused-value rule: a sourceRef name or a spec.path that
// fails the safe() check renders an explicit "refused" marker in its
// fragment, so a refused value is never indistinguishable from an absent
// one — the same distinction the list subsections already make with
// "none safe". A safe value keeps its exact composed fragment.
func TestResolveKustomizationTopologyRefusedSingularFields(t *testing.T) {
	run := func(t *testing.T, kuzJSON string) string {
		t.Helper()
		srv := fluxKustomizationAPIHarness(t, "kuz", kuzJSON,
			`{"spec":{"url":"https://github.com/example/kuz"}}`)
		defer srv.Close()

		k := &kube{hc: srv.Client(), base: srv.URL}
		got := k.resolveKustomizationTopology(context.Background(), fluxAnnotatedPod("p-0", "apps", "kuz", ""))
		if len(got) != 1 {
			t.Fatalf("expected exactly one topology record, got %#v", got)
		}
		return got[0]
	}
	// The JSON is a raw string so the hostile bytes arrive through JSON
	// escapes: \u0000 decodes to NUL, \\ to a single backslash.
	t.Run("refused sourceRef name", func(t *testing.T) {
		rec := run(t, `{"spec":{"path":"apps/kuz","sourceRef":{"kind":"GitRepository","name":"main\u0000evil"}}}`)
		if !strings.Contains(rec, "source: refused") {
			t.Errorf("refused sourceRef name must render source: refused: %s", rec)
		}
		if strings.Contains(rec, "main") {
			t.Errorf("refused sourceRef name leaked into the record: %s", rec)
		}
		if strings.Contains(rec, "GitRepository/main") {
			t.Errorf("refused sourceRef must not compose a source fragment: %s", rec)
		}
		if strings.Contains(rec, "\x00") {
			t.Errorf("record carries a NUL byte: %s", rec)
		}
	})
	t.Run("refused spec.path", func(t *testing.T) {
		rec := run(t, `{"spec":{"path":"apps\\web","sourceRef":{"kind":"GitRepository","name":"main"}}}`)
		if !strings.Contains(rec, "(path: refused)") {
			t.Errorf("refused spec.path must render (path: refused): %s", rec)
		}
		if strings.Contains(rec, `apps\web`) {
			t.Errorf("refused spec.path value leaked into the record: %s", rec)
		}
	})
	t.Run("safe values render verbatim", func(t *testing.T) {
		rec := run(t, `{"spec":{"path":"apps/kuz","sourceRef":{"kind":"GitRepository","name":"main","namespace":"flux-system"}}}`)
		for _, want := range []string{"(path: apps/kuz)", "source: GitRepository/main (flux-system)"} {
			if !strings.Contains(rec, want) {
				t.Errorf("record missing %q: %s", want, rec)
			}
		}
	})
}

// TestResolveRepoPathsEdgeCaseInputs exercises the elevated must-check
// for edge-case inputs that could lead to path injection if a future
// regression lets annotation values or GitOps config flow unchecked into
// the kube URL builder. Each case asserts the call does not panic and
// that the resulting entries do not smuggle a `..` traversal segment or
// a null byte into the URL that becomes a clickable Discord link.
func TestResolveRepoPathsEdgeCaseInputs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Distinguish the Kustomization lookup from the GitRepository
		// lookup so fluxPath receives both `spec.path` (from the
		// Kustomization) and `spec.url` (from the GitRepository) — the
		// only combination that makes fluxPath return (url, path, true).
		if strings.Contains(r.URL.Path, "/gitrepositories/") {
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/example/flux-helm"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"spec":{"path":"clusters/staging","sourceRef":{"name":"podinfo","kind":"GitRepository"}}}`)
	}))
	defer srv.Close()

	cases := []struct {
		name string
		ann  map[string]string
	}{
		{"dotdot", map[string]string{"kustomize.toolkit.fluxcd.io/name": "podinfo", "kustomize.toolkit.fluxcd.io/namespace": "../../etc"}},
		{"nullbyte", map[string]string{"kustomize.toolkit.fluxcd.io/name": "podinfo\x00evil", "kustomize.toolkit.fluxcd.io/namespace": "flux-system"}},
		{"absnamespace", map[string]string{"kustomize.toolkit.fluxcd.io/name": "podinfo", "kustomize.toolkit.fluxcd.io/namespace": "/etc/passwd"}},
		{"percentencoded", map[string]string{"kustomize.toolkit.fluxcd.io/name": "podinfo%2F..%2F..", "kustomize.toolkit.fluxcd.io/namespace": "flux-system"}},
		{"backslash", map[string]string{"kustomize.toolkit.fluxcd.io/name": "podinfo\\..\\..", "kustomize.toolkit.fluxcd.io/namespace": "flux-system"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("resolveRepoPaths panicked on %s: %v", tc.name, r)
				}
			}()
			k := &kube{hc: srv.Client(), base: srv.URL}
			pods := []podRef{{Name: "p", Namespace: "ns", Annotations: tc.ann}}
			got, _ := k.resolveRepoPaths(context.Background(), pods, &Config{})
			t.Logf("%s -> %#v", tc.name, got)
			assertRepoURLsSafe(t, tc.name, got)
		})
	}

	t.Run("gitops_fallback_traversal", func(t *testing.T) {
		// GITOPS_PATH with `..` segments is a common misconfiguration.
		// The fallback must not panic, and the produced URL must not
		// contain an unescaped `..` segment — a clickable Discord link
		// that resolved to a directory the operator did not configure
		// would be a user-visible bug at 03:00. resolveRepoPaths
		// sanitises with path.Clean, so `../../etc/secrets` collapses
		// to `etc/secrets`.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("resolveRepoPaths panicked on traversal fallback: %v", r)
			}
		}()
		k := &kube{}
		cfg := &Config{GitOpsRepo: "https://github.com/example/fallback", GitOpsPath: "../../etc/secrets"}
		got, _ := k.resolveRepoPaths(context.Background(), []podRef{{Name: "p", Namespace: "ns", Annotations: map[string]string{}}}, cfg)
		t.Logf("fallback -> %#v", got)
		assertRepoURLsSafe(t, "gitops_fallback_traversal", got)
		if len(got) != 1 {
			t.Fatalf("expected exactly one fallback entry, got %#v", got)
		}
		if got[0] != "https://github.com/example/fallback/etc/secrets" {
			t.Fatalf("traversal segments not collapsed: got %q", got[0])
		}
	})

	t.Run("gitops_fallback_nullbyte", func(t *testing.T) {
		// A null byte in GITOPS_PATH must not produce an entry at all;
		// the result would otherwise be a clickable link with a NUL
		// smuggled into the rendered URL.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("resolveRepoPaths panicked on null-byte fallback: %v", r)
			}
		}()
		k := &kube{}
		cfg := &Config{GitOpsRepo: "https://github.com/example/fallback", GitOpsPath: "pods\x00evil"}
		got, _ := k.resolveRepoPaths(context.Background(), []podRef{{Name: "p", Namespace: "ns", Annotations: map[string]string{}}}, cfg)
		t.Logf("nullbyte fallback -> %#v", got)
		assertRepoURLsSafe(t, "gitops_fallback_nullbyte", got)
		if len(got) != 0 {
			t.Fatalf("gitops_fallback_nullbyte: expected entry to be omitted when GitOpsPath contains NUL, got %#v", got)
		}
	})

	t.Run("gitops_fallback_percentencoded", func(t *testing.T) {
		// Percent-encoded traversal such as `%2F..%2F` is not collapsed
		// by path.Clean and would be emitted verbatim. The sanitiser
		// must drop the entry rather than render an unsafe URL.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("resolveRepoPaths panicked on percent-encoded fallback: %v", r)
			}
		}()
		k := &kube{}
		cfg := &Config{GitOpsRepo: "https://github.com/example/fallback", GitOpsPath: "podinfo%2F..%2F.."}
		got, _ := k.resolveRepoPaths(context.Background(), []podRef{{Name: "p", Namespace: "ns", Annotations: map[string]string{}}}, cfg)
		t.Logf("percentencoded fallback -> %#v", got)
		assertRepoURLsSafe(t, "gitops_fallback_percentencoded", got)
		if len(got) != 0 {
			t.Fatalf("gitops_fallback_percentencoded: expected entry to be omitted when GitOpsPath contains '%%', got %#v", got)
		}
	})

	t.Run("gitops_fallback_backslash", func(t *testing.T) {
		// Backslashes are Windows separators that path.Clean (a
		// Unix-style package) leaves untouched. The sanitiser must
		// drop the entry rather than emit a URL GitHub will 404.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("resolveRepoPaths panicked on backslash fallback: %v", r)
			}
		}()
		k := &kube{}
		cfg := &Config{GitOpsRepo: "https://github.com/example/fallback", GitOpsPath: `podinfo\..\..`}
		got, _ := k.resolveRepoPaths(context.Background(), []podRef{{Name: "p", Namespace: "ns", Annotations: map[string]string{}}}, cfg)
		t.Logf("backslash fallback -> %#v", got)
		assertRepoURLsSafe(t, "gitops_fallback_backslash", got)
		if len(got) != 0 {
			t.Fatalf("gitops_fallback_backslash: expected entry to be omitted when GitOpsPath contains backslash, got %#v", got)
		}
	})

	// Absolute paths (e.g. `/etc/secrets`) — GitOpsPath is operator-supplied
	// and an absolute path would normally be a misconfiguration, but the
	// sanitiser must not emit a URL like `https://github.com/example/etc/secrets`
	// because that would route the operator to the wrong repo subtree. The
	// contract: leading slashes are stripped (joining onto the repo's
	// subtree), so the resulting URL lands on the same default branch
	// root as an operator who left GitOpsPath empty.
	t.Run("gitops_fallback_absolutepath", func(t *testing.T) {
		k := &kube{}
		cfg := &Config{GitOpsRepo: "https://github.com/example/fallback"}
		cfg.GitOpsPath = "/etc/secrets"
		pods := []podRef{{Namespace: "ns", Name: "pod"}}
		got, _ := k.resolveRepoPaths(context.Background(), pods, cfg)
		if len(got) != 1 {
			t.Fatalf("gitops_fallback_absolutepath: want one entry, got %#v", got)
		}
		const want = "https://github.com/example/fallback/etc/secrets"
		if got[0] != want {
			t.Fatalf("gitops_fallback_absolutepath: leading-slash not stripped, want %q got %q", want, got[0])
		}
		assertRepoURLsSafe(t, "gitops_fallback_absolutepath", got)
	})
}

// assertRepoURLsSafe fails the test if any entry contains a null byte,
// an unescaped `..` traversal segment, a percent-encoded traversal
// segment (the literal substring `%2F` or `%2E` after percent-decoding
// by a URL consumer), or a backslash separator. These are the safety
// invariants the resolveRepoPaths sanitiser is responsible for: the
// output is rendered as a clickable link in the digest, and any of
// these would render a link the operator did not intend.
func assertRepoURLsSafe(t *testing.T, name string, entries []string) {
	t.Helper()
	for _, e := range entries {
		if strings.Contains(e, "\x00") {
			t.Fatalf("%s: entry contains null byte: %q", name, e)
		}
		if strings.Contains(e, `\`) {
			t.Fatalf("%s: entry contains backslash separator: %q", name, e)
		}
		// Reject percent-encoded traversal segments such as `%2F..%2F`
		// or `%2E%2E`. A consumer that decodes the URL before routing
		// would see `..` segments after decoding, which the link the
		// operator intended did not contain.
		lower := strings.ToLower(e)
		if strings.Contains(lower, "%2f") || strings.Contains(lower, "%2e") {
			t.Fatalf("%s: entry contains percent-encoded traversal: %q", name, e)
		}
		// Split on `/` and reject any segment that is `..`. The path
		// part of a GitHub URL is what path.Clean collapses against the
		// leading-slash wrapper; any unescaped `..` surviving here
		// means the sanitiser let an operator-controlled traversal
		// slip through.
		for _, seg := range strings.Split(e, "/") {
			if seg == ".." {
				t.Fatalf("%s: entry contains unescaped `..` segment: %q", name, e)
			}
		}
	}
}

// fluxItem is one Flux object in a test apiserver. kind routes it to the
// helmreleases or kustomizations endpoint; status is the Ready condition's
// status value.
func fluxItem(t *testing.T, ns, name, kind, rev, transition, status string) map[string]any {
	t.Helper()
	return map[string]any{
		"kind":     kind,
		"metadata": map[string]any{"name": name, "namespace": ns},
		"status": map[string]any{
			"lastAppliedRevision": rev,
			"conditions": []map[string]any{{
				"type":               "Ready",
				"status":             status,
				"reason":             "Succeeded",
				"lastTransitionTime": transition,
			}},
		},
	}
}

// fluxServer builds a test apiserver that serves one Flux list for each of
// the helmreleases and kustomizations endpoints, routing each item to the
// endpoint named by its "kind" (as the real apiserver would).
func fluxServer(t *testing.T, items ...map[string]any) *httptest.Server {
	t.Helper()
	helm, kust := []map[string]any{}, []map[string]any{}
	for _, it := range items {
		if it["kind"] == "helmreleases" {
			helm = append(helm, it)
		} else {
			kust = append(kust, it)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		items := kust
		if strings.Contains(r.URL.Path, "helmreleases") {
			items = helm
		} else if !strings.Contains(r.URL.Path, "kustomizations") {
			http.NotFound(w, r)
			return
		}
		payload, _ := json.Marshal(map[string]any{"items": items})
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A healthy (Ready=True) Flux transition inside the window must be surfaced
// with neutral wording - "reconciled at revision ..." - never as a deploy,
// change or trigger. A new repo SHA does not prove the workload changed.
func TestFluxActivityHealthyReconcileIsNeutral(t *testing.T) {
	rev := "main@0982756e1a2b3c4d5e6f"
	srv := fluxServer(t,
		fluxItem(t, "llm", "kustomization-llm", "kustomizations", rev, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), "True"),
	)
	k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
	got, inspected := k.fluxActivity(context.Background(), "llm", time.Now().Add(-time.Hour))
	if !inspected {
		t.Fatalf("a successful read must report inspected")
	}
	if len(got) != 1 {
		t.Fatalf("expected one healthy-reconcile line, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "reconciled at revision") {
		t.Errorf("healthy reconcile should be neutrally worded, got %q", got[0])
	}
	for _, word := range []string{"deploy", "change", "trigger"} {
		if strings.Contains(strings.ToLower(got[0]), word) {
			t.Errorf("healthy reconcile must not claim a %q, got %q", word, got[0])
		}
	}
}

// A healthy reconcile that happened outside the window must not be surfaced
// at all, even when the alert names a namespace.
func TestFluxActivityHealthyReconcileOutsideWindowIsDropped(t *testing.T) {
	rev := "main@0982756e1a2b3c4d5e6f"
	old := time.Now().Add(-10 * time.Hour).UTC().Format(time.RFC3339)
	srv := fluxServer(t, fluxItem(t, "llm", "kustomization-llm", "kustomizations", rev, old, "True"))
	k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
	got, inspected := k.fluxActivity(context.Background(), "llm", time.Now().Add(-time.Hour))
	if !inspected {
		t.Fatalf("a successful read must report inspected")
	}
	if len(got) != 0 {
		t.Fatalf("a healthy reconcile outside the window must not surface, got %v", got)
	}
}

// A NotReady Flux resource is strong primary evidence: the reason and the
// revision must be kept verbatim, and the failure must survive even in the
// cluster-wide (ambient) scope.
func TestFluxActivityNotReadyIsFailureSignal(t *testing.T) {
	rev := "main@0982756e1a2b3c4d5e6f"
	now := time.Now().UTC().Format(time.RFC3339)
	srv := fluxServer(t, fluxItem(t, "llm", "kustomization-llm", "kustomizations", rev, now, "False"))
	k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
	got, inspected := k.fluxActivity(context.Background(), "llm", time.Now().Add(-time.Hour))
	if !inspected {
		t.Fatalf("a successful read must report inspected")
	}
	if len(got) != 1 {
		t.Fatalf("expected one NotReady line, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "NOT READY: Succeeded") {
		t.Errorf("NotReady must keep its reason, got %q", got[0])
	}
	if !strings.Contains(got[0], "rev="+shortRev(rev)) {
		t.Errorf("NotReady must keep its revision, got %q", got[0])
	}

	// NotReady must also survive in the cluster-wide (ambient) scope: a
	// healthy sync is noise there, a failure is not.
	srv2 := fluxServer(t,
		fluxItem(t, "llm", "kustomization-llm", "kustomizations", rev, now, "False"),
		fluxItem(t, "llm", "kustomization-healthy", "kustomizations", "main@11112222333344445555", now, "True"),
	)
	k2 := &kube{base: srv2.URL, token: "tok", hc: srv2.Client()}
	ambient, inspected := k2.fluxActivity(context.Background(), "", time.Now().Add(-time.Hour))
	if !inspected {
		t.Fatalf("a successful cluster-wide read must report inspected")
	}
	if len(ambient) != 1 {
		t.Fatalf("cluster-wide scope must keep only the NotReady line, got %v", ambient)
	}
	if !strings.Contains(ambient[0], "NOT READY") {
		t.Errorf("cluster-wide scope must keep the failure, got %q", ambient[0])
	}
}

// Issue #300: a forbidden, canceled, malformed or oversized Flux list read
// returned an empty findings slice identical to a quiet window's, and the
// renderer asserted "no Flux reconciles or failures in the window" from it.
// Read success is now a separate fact, so a failed read cannot masquerade as
// a ruled-out cause — and a 404 from a cluster without Flux installed counts
// as a failed read, not a quiet one.
func TestFluxActivityCarriesReadSuccess(t *testing.T) {
	const emptyList = `{"items":[]}`
	notReadyLLMWeb := func(w http.ResponseWriter) {
		io.WriteString(w, `{"items":[{"metadata":{"name":"web","namespace":"llm"},"status":{"lastAppliedRevision":"main@0982756e1a2b3c4d5e6f","conditions":[{"type":"Ready","status":"False","reason":"ReconciliationFailed","lastTransitionTime":"`+time.Now().UTC().Format(time.RFC3339)+`"}]}}]}`)
	}
	tests := []struct {
		name          string
		writeHelm     func(http.ResponseWriter)
		writeKust     func(http.ResponseWriter)
		cancelCtx     bool
		wantInspected bool
		wantFinding   string // non-empty: a finding the partially-read lists must still carry
	}{
		{
			name:          "both lists read empty is a quiet, inspected window",
			writeHelm:     func(w http.ResponseWriter) { io.WriteString(w, emptyList) },
			writeKust:     func(w http.ResponseWriter) { io.WriteString(w, emptyList) },
			wantInspected: true,
		},
		{
			name:          "window with transitions is inspected and carries the finding",
			writeHelm:     notReadyLLMWeb,
			writeKust:     func(w http.ResponseWriter) { io.WriteString(w, emptyList) },
			wantInspected: true,
			wantFinding:   "llm/web NOT READY: ReconciliationFailed",
		},
		{
			name:      "forbidden helmrelease list is not inspected",
			writeHelm: func(w http.ResponseWriter) { http.Error(w, "nope", http.StatusForbidden) },
			writeKust: func(w http.ResponseWriter) { io.WriteString(w, emptyList) },
		},
		{
			name:      "forbidden kustomization list is not inspected",
			writeHelm: func(w http.ResponseWriter) { io.WriteString(w, emptyList) },
			writeKust: func(w http.ResponseWriter) { http.Error(w, "nope", http.StatusForbidden) },
		},
		{
			name:      "404 on both lists (no Flux installed) is not inspected",
			writeHelm: func(w http.ResponseWriter) { http.NotFound(w, nil) },
			writeKust: func(w http.ResponseWriter) { http.NotFound(w, nil) },
		},
		{
			name:      "malformed body is not inspected",
			writeHelm: func(w http.ResponseWriter) { io.WriteString(w, emptyList) },
			writeKust: func(w http.ResponseWriter) { io.WriteString(w, `{"items":`) },
		},
		{
			// One byte past kubeBodyCap is enough: readCappedBody fails the
			// read without buffering the rest of the body.
			name:      "oversized body is not inspected",
			writeHelm: func(w http.ResponseWriter) { io.WriteString(w, emptyList) },
			writeKust: func(w http.ResponseWriter) { w.Write(make([]byte, kubeBodyCap+1)) },
		},
		{
			name:      "canceled read is not inspected",
			writeHelm: func(w http.ResponseWriter) { io.WriteString(w, emptyList) },
			writeKust: func(w http.ResponseWriter) { io.WriteString(w, emptyList) },
			cancelCtx: true,
		},
		{
			// The list that did read keeps its findings — the failure
			// suppresses the quiet-window negative, never the evidence.
			name:        "partial read is not inspected but keeps its findings",
			writeHelm:   func(w http.ResponseWriter) { http.Error(w, "nope", http.StatusForbidden) },
			writeKust:   notReadyLLMWeb,
			wantFinding: "llm/web NOT READY: ReconciliationFailed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "helmreleases"):
					tt.writeHelm(w)
				case strings.Contains(r.URL.Path, "kustomizations"):
					tt.writeKust(w)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
			ctx := context.Background()
			if tt.cancelCtx {
				// Cancelled before the call: the apiserver never answers,
				// which is the timed-out read this regression is about.
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got, inspected := k.fluxActivity(ctx, "llm", time.Now().Add(-time.Hour))
			if inspected != tt.wantInspected {
				t.Errorf("inspected = %v, want %v (findings: %v)", inspected, tt.wantInspected, got)
			}
			if tt.wantFinding != "" {
				if len(got) == 0 || !strings.Contains(strings.Join(got, "; "), tt.wantFinding) {
					t.Errorf("want finding %q in %v", tt.wantFinding, got)
				}
			}
		})
	}
}

// The Enrich wiring must carry the flag through both scope paths — the
// namespace-scoped read and the cluster-wide fallback — so the renderer can
// tell a quiet window from a read that never succeeded (#300). A nil client
// never reads at all and must stay uninspected.
func TestEnrichFluxCarriesReadSuccess(t *testing.T) {
	const emptyList = `{"items":[]}`
	newServer := func(helmCode, kustCode int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			code, body := http.StatusOK, emptyList
			switch {
			case strings.Contains(r.URL.Path, "helmreleases"):
				code = helmCode
			case strings.Contains(r.URL.Path, "kustomizations"):
				code = kustCode
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			if code == http.StatusOK {
				_, _ = io.WriteString(w, body)
			}
		}))
	}
	namespaced := Group{Key: "single/A", Alerts: []Alert{
		{Labels: map[string]string{"alertname": "A", "namespace": "llm"}},
	}}
	clusterWide := Group{Key: "single/A", Alerts: []Alert{
		{Labels: map[string]string{"alertname": "A"}},
	}}

	t.Run("successful quiet namespace read is inspected", func(t *testing.T) {
		srv := newServer(http.StatusOK, http.StatusOK)
		defer srv.Close()
		k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
		g := namespaced
		g.Namespaces = []string{"llm"}
		e := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)
		if !e.FluxInspected {
			t.Errorf("FluxInspected = false, want true after a successful read")
		}
		if len(e.FluxActivity) != 0 {
			t.Errorf("FluxActivity = %v, want none in a quiet window", e.FluxActivity)
		}
	})
	t.Run("failed namespace read is not inspected", func(t *testing.T) {
		srv := newServer(http.StatusForbidden, http.StatusOK)
		defer srv.Close()
		k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
		g := namespaced
		g.Namespaces = []string{"llm"}
		e := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)
		if e.FluxInspected {
			t.Errorf("FluxInspected = true, want false after a failed list read")
		}
	})
	t.Run("successful cluster-wide read is inspected", func(t *testing.T) {
		srv := newServer(http.StatusOK, http.StatusOK)
		defer srv.Close()
		k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
		e := k.Enrich(context.Background(), clusterWide, time.Minute, &Config{}, nil)
		if !e.FluxInspected {
			t.Errorf("FluxInspected = false, want true after a successful cluster-wide read")
		}
	})
	t.Run("404 cluster-wide read (no Flux installed) is not inspected", func(t *testing.T) {
		srv := newServer(http.StatusNotFound, http.StatusNotFound)
		defer srv.Close()
		k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
		e := k.Enrich(context.Background(), clusterWide, time.Minute, &Config{}, nil)
		if e.FluxInspected {
			t.Errorf("FluxInspected = true, want false when both lists 404")
		}
	})
	t.Run("nil client is not inspected", func(t *testing.T) {
		var k *kube
		e := k.Enrich(context.Background(), clusterWide, time.Minute, &Config{}, nil)
		if e.FluxInspected || len(e.FluxActivity) != 0 {
			t.Errorf("nil client must not claim Flux state: inspected=%v activity=%v", e.FluxInspected, e.FluxActivity)
		}
	})
}

// TestFluxActivityNamespaceHostile pins the guard on the namespace the Flux
// lists are scoped to: the namespace is interpolated into the request path,
// so a value that is not one path segment must be refused before any request
// is built. The refusal must leave the read uninspected rather than empty,
// because an empty result is read as a quiet window and a quiet window that
// was never established is a false negative (issue #300).
func TestFluxActivityNamespaceHostile(t *testing.T) {
	tests := []struct {
		name          string
		namespace     string
		wantInspected bool
	}{
		// The raw form: a separator would address a different namespace
		// than the one the alert names.
		{name: "raw traversal is refused", namespace: "ns/../../other"},
		// The form the production caller passes: enrich.go escapes the
		// namespace with url.PathEscape before calling, so a hostile
		// value arrives percent-encoded.
		{name: "escaped traversal is refused", namespace: url.PathEscape("ns/../../other")},
		{name: "double dot is refused", namespace: "ns..other"},
		{name: "plain namespace is read", namespace: "llm", wantInspected: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hits atomic.Int32
			var wrongScope atomic.Bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if !strings.Contains(r.URL.Path, "/namespaces/llm/") {
					wrongScope.Store(true)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"items":[]}`)
			}))
			defer srv.Close()
			k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
			got, inspected := k.fluxActivity(context.Background(), tt.namespace, time.Now().Add(-time.Hour))
			if inspected != tt.wantInspected {
				t.Errorf("inspected = %v, want %v", inspected, tt.wantInspected)
			}
			if len(got) != 0 {
				t.Errorf("expected no Flux lines, got %v", got)
			}
			if !tt.wantInspected {
				if hits.Load() != 0 {
					t.Errorf("a refused namespace must not be requested, got %d hits", hits.Load())
				}
				return
			}
			// A plain namespace is still read, and read in the namespace
			// it names - the guard must not narrow the legitimate scope.
			if hits.Load() == 0 {
				t.Fatalf("a plain namespace must still be requested")
			}
			if wrongScope.Load() {
				t.Errorf("the Flux lists were read outside the requested namespace")
			}
		})
	}
}

// TestEnrichFluxNamespaceHostile walks the whole enrichment path with a
// group whose namespace carries a separator. The Flux lists must never be
// requested, the digest must report the Flux state as unavailable instead of
// as a quiet window, and the rest of the enrichment must still run: a
// refused namespace must cost the digest its Flux evidence, not its digest.
func TestEnrichFluxNamespaceHostile(t *testing.T) {
	const hostile = "ns/../../other"
	var fluxHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "helmreleases"), strings.Contains(r.URL.Path, "kustomizations"):
			fluxHits.Add(1)
			// The path is not echoed: a hit would carry the refused
			// namespace into the test output.
			t.Errorf("unexpected Flux API hit; a refused namespace must not be requested")
			http.NotFound(w, r)
		case strings.Contains(r.URL.Path, "/pods"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		case strings.Contains(r.URL.Path, "/events"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		case strings.HasSuffix(r.URL.Path, "/nodes"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		default:
			t.Errorf("unexpected API hit")
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
	g := Group{
		Key:        "single/A",
		Namespaces: []string{hostile},
		Alerts:     []Alert{{Labels: map[string]string{"alertname": "A", "namespace": hostile}}},
	}
	e := k.Enrich(context.Background(), g, time.Minute, &Config{}, nil)
	if fluxHits.Load() != 0 {
		t.Errorf("a refused namespace must not reach the Flux list endpoint, got %d hits", fluxHits.Load())
	}
	if e.FluxInspected {
		t.Errorf("FluxInspected = true, want false: the Flux lists were never read")
	}
	if len(e.FluxActivity) != 0 {
		t.Errorf("FluxActivity = %v, want none", e.FluxActivity)
	}
	// The rest of the enrichment still ran: the digest is produced with
	// the evidence that could be read, and only the Flux section is
	// marked unavailable.
	if !e.NodesInspected {
		t.Errorf("the node read must still succeed, got %+v", e)
	}
	if e.Scope == "" {
		t.Errorf("expected the enrichment to carry a scope, got %+v", e)
	}
}

// A healthy reconcile at a new revision must not be labelled a "change": the
// Enrichment field carrying these findings must not use change-encoding names
// in its rendered form either.
func TestEnrichmentFluxActivityNotChanges(t *testing.T) {
	rev := "main@0982756e1a2b3c4d5e6f"
	srv := fluxServer(t, fluxItem(t, "llm", "kustomization-llm", "kustomizations", rev, time.Now().UTC().Format(time.RFC3339), "True"))
	k := &kube{base: srv.URL, token: "tok", hc: srv.Client()}
	g := Group{
		Key:        "single/A",
		Namespaces: []string{"llm"},
		Alerts:     []Alert{{Labels: map[string]string{"alertname": "A", "namespace": "llm"}}},
	}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{}, nil)
	if len(en.FluxActivity) == 0 {
		t.Fatalf("expected a FluxActivity entry, got %+v", en)
	}
	if !en.FluxInspected {
		t.Errorf("a successful Flux read must report inspected")
	}
	joined := strings.ToLower(strings.Join(en.FluxActivity, " "))
	for _, word := range []string{"deploy", "change", "trigger"} {
		if strings.Contains(joined, word) {
			t.Errorf("FluxActivity must not claim a %q, got %q", word, joined)
		}
	}
}

// TestResolveCommitRelevanceFluxAndGitHub is the end-to-end test for issue
// #135: a pod with the Flux kustomize annotations, a Kustomization with a
// github.com GitRepository, and a GitHub commit whose files DO touch the
// workload path must produce a CommitRelevance with State == "touches".
// The test wires up three servers — the kube API, the github.com API —
// and asserts the renderer surfaces the matching files (inside the
// untrusted fence) and the commit message.
func TestResolveCommitRelevanceFluxAndGitHub(t *testing.T) {
	const validSHA = "0123456789abcdef0123456789abcdef01234567"
	var kubeHits, ghHits atomic.Int32
	kubeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kubeHits.Add(1)
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/payments"):
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/payments","sourceRef":{"name":"payments","kind":"GitRepository"}},"status":{"lastAppliedRevision":"refs/heads/main@sha1:`+validSHA+`"}}`)
		case strings.Contains(r.URL.Path, "/gitrepositories/payments"):
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/owner/repo"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer kubeSrv.Close()
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ghHits.Add(1)
		// Path: /repos/owner/repo/commits/<sha>
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 5 || parts[4] != validSHA {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"sha":"`+validSHA+`","commit":{"message":"bump image tag"},"files":[{"filename":"apps/payments/kustomization.yaml"},{"filename":"apps/payments/deployment.yaml"}]}`)
	}))
	defer ghSrv.Close()

	k := &kube{hc: kubeSrv.Client(), base: kubeSrv.URL}
	gh := &gitHubClient{token: "t", repo: "owner/repo", hc: ghSrv.Client(), apiURL: ghSrv.URL}
	pods := []podRef{{
		Name:      "p",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "payments",
			"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
		},
	}}
	got := k.resolveCommitRelevance(context.Background(), gh, pods)
	if len(got) != 1 {
		t.Fatalf("expected 1 CommitRelevance, got %d", len(got))
	}
	rel := got[0]
	if rel.State != commitRelevanceTouches {
		t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceTouches, rel.Reason)
	}
	if rel.WorkloadPath != "apps/payments" {
		t.Errorf("workload path = %q, want %q", rel.WorkloadPath, "apps/payments")
	}
	if rel.Revision != "refs/heads/main@sha1:"+validSHA {
		t.Errorf("revision = %q", rel.Revision)
	}
	if len(rel.MatchingPaths) != 2 {
		t.Errorf("matching paths = %v, want 2 entries", rel.MatchingPaths)
	}
	if rel.CommitMessage != "bump image tag" {
		t.Errorf("commit message = %q, want %q", rel.CommitMessage, "bump image tag")
	}
	if kubeHits.Load() == 0 || ghHits.Load() == 0 {
		t.Errorf("expected both kube and github hits, got kube=%d github=%d", kubeHits.Load(), ghHits.Load())
	}

	// And the renderer must fence the matching files (they are quoted from
	// a third-party commit) while leaving the State line outside the fence.
	en := Enrichment{CommitRelevance: got}
	evidence := renderEvidence(Report{Enrichment: en})
	if !strings.Contains(evidence, "Recent reconciled commit (GitHub):") {
		t.Errorf("evidence missing header:\n%s", evidence)
	}
	if !strings.Contains(evidence, "touches workload: apps/payments") {
		t.Errorf("evidence missing state line:\n%s", evidence)
	}
	if strings.Count(evidence, untrustedBegin) < 2 {
		// one for alerts, one for matching files
		t.Errorf("expected matching files inside untrusted fence:\n%s", evidence)
	}
}

// TestResolveCommitRelevanceFluxSourceRefNamespace covers the relevance
// half of #296: the Kustomization names a source in another namespace, and
// that source points at a different repository than the same-named local
// one. The commit must be looked up in, and classified against, the
// repository the Kustomization actually uses.
func TestResolveCommitRelevanceFluxSourceRefNamespace(t *testing.T) {
	const validSHA = "0123456789abcdef0123456789abcdef01234567"
	var localHits atomic.Int32
	var ghRepo atomic.Value
	kubeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/demo"):
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/demo","sourceRef":{"name":"config","kind":"GitRepository","namespace":"sources"}},"status":{"lastAppliedRevision":"refs/heads/main@sha1:`+validSHA+`"}}`)
		case strings.HasSuffix(r.URL.Path, "/namespaces/sources/gitrepositories/config"):
			// The declared source lives in another namespace and points at
			// another repository than the local same-named source.
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/other/intended"}}`)
		case strings.HasSuffix(r.URL.Path, "/namespaces/workloads/gitrepositories/config"):
			localHits.Add(1)
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/owner/repo"}}`)
		default:
			t.Errorf("unexpected API hit for %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer kubeSrv.Close()
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Path: /repos/<owner>/<name>/commits/<sha>
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 5 || parts[1] != "other" || parts[2] != "intended" || parts[4] != validSHA {
			http.NotFound(w, r)
			return
		}
		ghRepo.Store(parts[1] + "/" + parts[2])
		_, _ = io.WriteString(w, `{"sha":"`+validSHA+`","commit":{"message":"bump demo image"},"files":[{"filename":"apps/demo/kustomization.yaml"}]}`)
	}))
	defer ghSrv.Close()

	k := &kube{hc: kubeSrv.Client(), base: kubeSrv.URL}
	gh := &gitHubClient{token: "t", repo: "owner/repo", hc: ghSrv.Client(), apiURL: ghSrv.URL}
	pods := []podRef{{
		Name:      "p",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "demo",
			"kustomize.toolkit.fluxcd.io/namespace": "workloads",
		},
	}}
	got := k.resolveCommitRelevance(context.Background(), gh, pods)
	if len(got) != 1 {
		t.Fatalf("expected 1 CommitRelevance, got %d", len(got))
	}
	rel := got[0]
	if rel.RepoURL != "https://github.com/other/intended" {
		t.Fatalf("repo URL = %q, want the source in the declared namespace", rel.RepoURL)
	}
	gotRepo, _ := ghRepo.Load().(string)
	if gotRepo != "other/intended" {
		t.Fatalf("commit lookup went to repo %q, want %q", gotRepo, "other/intended")
	}
	if rel.State != commitRelevanceTouches {
		t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceTouches, rel.Reason)
	}
	if len(rel.MatchingPaths) != 1 || rel.MatchingPaths[0] != "apps/demo/kustomization.yaml" {
		t.Fatalf("matching paths = %v, want [apps/demo/kustomization.yaml]", rel.MatchingPaths)
	}
	if localHits.Load() != 0 {
		t.Fatalf("the same-named local source must not be read, got %d hits", localHits.Load())
	}
}

// TestResolveCommitRelevanceFluxSourceRefNamespaceMissingSource covers the
// degraded relevance path: the source the Kustomization declares is missing
// or forbidden in the namespace it names. The lookup must degrade to
// "unknown" with a one-line reason, must not fall back to the same-named
// source in the Kustomization's own namespace, and must not classify the
// commit against a repository it never resolved.
func TestResolveCommitRelevanceFluxSourceRefNamespaceMissingSource(t *testing.T) {
	const validSHA = "0123456789abcdef0123456789abcdef01234567"
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var localHits, ghHits atomic.Int32
			kubeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/kustomizations/demo"):
					_, _ = io.WriteString(w, `{"spec":{"path":"apps/demo","sourceRef":{"name":"config","kind":"GitRepository","namespace":"sources"}},"status":{"lastAppliedRevision":"refs/heads/main@sha1:`+validSHA+`"}}`)
				case strings.HasSuffix(r.URL.Path, "/namespaces/sources/gitrepositories/config"):
					// The declared source cannot be read.
					w.WriteHeader(status)
				case strings.HasSuffix(r.URL.Path, "/namespaces/workloads/gitrepositories/config"):
					localHits.Add(1)
					_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/example/wrong"}}`)
				default:
					t.Errorf("unexpected API hit for %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer kubeSrv.Close()
			ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ghHits.Add(1)
				_, _ = io.WriteString(w, `{"sha":"`+validSHA+`","commit":{"message":"bump demo image"},"files":[{"filename":"apps/demo/kustomization.yaml"}]}`)
			}))
			defer ghSrv.Close()

			k := &kube{hc: kubeSrv.Client(), base: kubeSrv.URL}
			gh := &gitHubClient{token: "t", repo: "owner/repo", hc: ghSrv.Client(), apiURL: ghSrv.URL}
			pods := []podRef{{
				Name:      "p",
				Namespace: "ns-a",
				Annotations: map[string]string{
					"kustomize.toolkit.fluxcd.io/name":      "demo",
					"kustomize.toolkit.fluxcd.io/namespace": "workloads",
				},
			}}
			got := k.resolveCommitRelevance(context.Background(), gh, pods)
			if len(got) != 1 {
				t.Fatalf("expected 1 CommitRelevance, got %d", len(got))
			}
			rel := got[0]
			if rel.State != commitRelevanceUnknown {
				t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceUnknown, rel.Reason)
			}
			if !strings.Contains(rel.Reason, "not readable") {
				t.Fatalf("reason must name the unreadable source: %q", rel.Reason)
			}
			if strings.Contains(rel.Reason, "\n") {
				t.Fatalf("reason must be one line: %q", rel.Reason)
			}
			if localHits.Load() != 0 {
				t.Fatalf("must not fall back to the same-named local source, got %d hits", localHits.Load())
			}
			if ghHits.Load() != 0 {
				t.Fatalf("no commit may be classified without a resolved repository, got %d github hits", ghHits.Load())
			}
		})
	}
}

// TestResolveCommitRelevanceDoesNotTouch covers the motivating case for
// #135 end-to-end: the commit the Kustomization is reconciled at only
// touches an unrelated workload, so the digest must say so explicitly
// rather than hinting at a deploy.
func TestResolveCommitRelevanceDoesNotTouch(t *testing.T) {
	const validSHA = "0123456789abcdef0123456789abcdef01234567"
	kubeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/payments"):
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/payments","sourceRef":{"name":"payments","kind":"GitRepository"}},"status":{"lastAppliedRevision":"refs/heads/main@sha1:`+validSHA+`"}}`)
		case strings.Contains(r.URL.Path, "/gitrepositories/payments"):
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/owner/repo"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer kubeSrv.Close()
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 5 || parts[4] != validSHA {
			http.NotFound(w, r)
			return
		}
		// A commit that touches an unrelated path.
		_, _ = io.WriteString(w, `{"sha":"`+validSHA+`","commit":{"message":"bump orders image"},"files":[{"filename":"apps/orders/kustomization.yaml"}]}`)
	}))
	defer ghSrv.Close()

	k := &kube{hc: kubeSrv.Client(), base: kubeSrv.URL}
	gh := &gitHubClient{token: "t", repo: "owner/repo", hc: ghSrv.Client(), apiURL: ghSrv.URL}
	pods := []podRef{{
		Name:      "p",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "payments",
			"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
		},
	}}
	got := k.resolveCommitRelevance(context.Background(), gh, pods)
	if len(got) != 1 {
		t.Fatalf("expected 1 CommitRelevance, got %d", len(got))
	}
	rel := got[0]
	if rel.State != commitRelevanceDoesNotTouch {
		t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceDoesNotTouch, rel.Reason)
	}
	if len(rel.MatchingPaths) != 0 {
		t.Errorf("expected no matching paths, got %v", rel.MatchingPaths)
	}
	if rel.CommitMessage != "bump orders image" {
		t.Errorf("commit message = %q, want %q", rel.CommitMessage, "bump orders image")
	}

	// The renderer must say "does NOT touch" — never phrase it as a
	// likely trigger.
	en := Enrichment{CommitRelevance: got}
	evidence := renderEvidence(Report{Enrichment: en})
	if !strings.Contains(evidence, "does NOT touch workload") {
		t.Errorf("evidence should explicitly say 'does NOT touch', got:\n%s", evidence)
	}
	joined := strings.ToLower(evidence)
	for _, w := range []string{"trigger", "deploy", "rolled out"} {
		if strings.Contains(joined, w) {
			t.Errorf("evidence must not call a non-touching commit a %q, got:\n%s", w, evidence)
		}
	}
}

// TestResolveCommitRelevanceComponentRelativeToPath is the integration
// regression for the Flux Kustomization components contract: spec.components
// are relative to the Kustomization's spec.path, not to the repo root. A
// component "../shared" under path "apps/payments/prod" resolves to
// "apps/payments/shared", and a commit touching that resolved path must be
// classified as "touches" the workload.
func TestResolveCommitRelevanceComponentRelativeToPath(t *testing.T) {
	const validSHA = "0123456789abcdef0123456789abcdef01234567"
	kubeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/payments"):
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/payments/prod","sourceRef":{"name":"payments","kind":"GitRepository"},"components":["../shared"]},"status":{"lastAppliedRevision":"refs/heads/main@sha1:`+validSHA+`"}}`)
		case strings.Contains(r.URL.Path, "/gitrepositories/payments"):
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/owner/repo"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer kubeSrv.Close()
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 5 || parts[4] != validSHA {
			http.NotFound(w, r)
			return
		}
		// The commit touches only the shared component's directory, which
		// is a sibling of the workload path: resolved it is
		// apps/payments/shared, not "shared" and not
		// apps/payments/prod/shared.
		_, _ = io.WriteString(w, `{"sha":"`+validSHA+`","commit":{"message":"tune shared config"},"files":[{"filename":"apps/payments/shared/tuning.yaml"}]}`)
	}))
	defer ghSrv.Close()

	k := &kube{hc: kubeSrv.Client(), base: kubeSrv.URL}
	gh := &gitHubClient{token: "t", repo: "owner/repo", hc: ghSrv.Client(), apiURL: ghSrv.URL}
	pods := []podRef{{
		Name:      "p",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "payments",
			"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
		},
	}}
	got := k.resolveCommitRelevance(context.Background(), gh, pods)
	if len(got) != 1 {
		t.Fatalf("expected 1 CommitRelevance, got %d", len(got))
	}
	rel := got[0]
	if rel.State != commitRelevanceTouches {
		t.Fatalf("state = %q, want %q (reason=%q)", rel.State, commitRelevanceTouches, rel.Reason)
	}
	if len(rel.ComponentPaths) != 1 || rel.ComponentPaths[0] != "apps/payments/shared" {
		t.Fatalf("component paths = %v, want [apps/payments/shared]", rel.ComponentPaths)
	}
	if len(rel.MatchingPaths) != 1 || rel.MatchingPaths[0] != "apps/payments/shared/tuning.yaml" {
		t.Fatalf("matching paths = %v, want [apps/payments/shared/tuning.yaml]", rel.MatchingPaths)
	}
}

// TestResolveCommitRelevanceNonGitHubRepo: a workload whose GitRepository
// is hosted outside GitHub must degrade to State == "unknown" so the
// digest never claims a non-GitHub lookup produced a result.
func TestResolveCommitRelevanceNonGitHubRepo(t *testing.T) {
	const validSHA = "0123456789abcdef0123456789abcdef01234567"
	kubeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/payments"):
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/payments","sourceRef":{"name":"payments","kind":"GitRepository"}},"status":{"lastAppliedRevision":"refs/heads/main@sha1:`+validSHA+`"}}`)
		case strings.Contains(r.URL.Path, "/gitrepositories/payments"):
			_, _ = io.WriteString(w, `{"spec":{"url":"https://gitlab.example.com/owner/repo"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer kubeSrv.Close()

	k := &kube{hc: kubeSrv.Client(), base: kubeSrv.URL}
	gh := &gitHubClient{token: "t", repo: "owner/repo", hc: &http.Client{}, apiURL: "http://unused.invalid"}
	pods := []podRef{{
		Name:      "p",
		Namespace: "ns-a",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "payments",
			"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
		},
	}}
	got := k.resolveCommitRelevance(context.Background(), gh, pods)
	if len(got) != 1 {
		t.Fatalf("expected 1 CommitRelevance, got %d", len(got))
	}
	if got[0].State != commitRelevanceUnknown {
		t.Fatalf("state = %q, want %q (reason=%q)", got[0].State, commitRelevanceUnknown, got[0].Reason)
	}
	if !strings.Contains(strings.ToLower(got[0].Reason), "github") {
		t.Errorf("unknown reason should mention the host check, got %q", got[0].Reason)
	}
}

// TestEnrichWiringGitHubEndToEnd exercises the full Enrich path: pass
// a gitHubClient in, get a CommitRelevance out, with the kube API and
// the GitHub API both stubbed.
func TestEnrichWiringGitHubEndToEnd(t *testing.T) {
	const validSHA = "0123456789abcdef0123456789abcdef01234567"
	kubeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/kustomizations/payments"):
			_, _ = io.WriteString(w, `{"spec":{"path":"apps/payments","sourceRef":{"name":"payments","kind":"GitRepository"}},"status":{"lastAppliedRevision":"refs/heads/main@sha1:`+validSHA+`"}}`)
		case strings.Contains(r.URL.Path, "/gitrepositories/payments"):
			_, _ = io.WriteString(w, `{"spec":{"url":"https://github.com/owner/repo"}}`)
		case strings.HasSuffix(r.URL.Path, "/pods"):
			_, _ = io.WriteString(w, `{"items":[{"metadata":{"name":"p","namespace":"ns-a","annotations":{"kustomize.toolkit.fluxcd.io/name":"payments","kustomize.toolkit.fluxcd.io/namespace":"flux-system"}},"spec":{"nodeName":"n1"},"status":{"phase":"Failed","containerStatuses":[{"name":"c","ready":false,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer kubeSrv.Close()
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 5 || parts[4] != validSHA {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"sha":"`+validSHA+`","commit":{"message":"bump image"},"files":[{"filename":"apps/payments/kustomization.yaml"}]}`)
	}))
	defer ghSrv.Close()

	k := &kube{hc: kubeSrv.Client(), base: kubeSrv.URL, cluster: "default"}
	gh := &gitHubClient{token: "t", repo: "owner/repo", hc: ghSrv.Client(), apiURL: ghSrv.URL}
	g := Group{
		Key:        "KubePodCrashLooping",
		Cluster:    "default",
		Namespaces: []string{"ns-a"},
		Alerts: []Alert{{
			Labels:   map[string]string{"alertname": "KubePodCrashLooping", "namespace": "ns-a", "pod": "p"},
			StartsAt: time.Now().Add(-time.Minute),
		}},
	}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{}, gh)
	if len(en.CommitRelevance) != 1 {
		t.Fatalf("expected 1 CommitRelevance from Enrich, got %d (enrichment=%+v)", len(en.CommitRelevance), en)
	}
	if en.CommitRelevance[0].State != commitRelevanceTouches {
		t.Fatalf("state = %q, want %q", en.CommitRelevance[0].State, commitRelevanceTouches)
	}
}

// TestEnrichNoGitHubClientLeavesRelevanceEmpty verifies that the common
// case (GITHUB_REPO/GITHUB_TOKEN unset) leaves CommitRelevance empty so
// the renderer does not pretend a check happened.
func TestEnrichNoGitHubClientLeavesRelevanceEmpty(t *testing.T) {
	kubeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Pod listing returns a pod with Flux annotations.
		if strings.HasSuffix(r.URL.Path, "/pods") {
			_, _ = io.WriteString(w, `{"items":[{"metadata":{"name":"p","namespace":"ns-a","annotations":{"kustomize.toolkit.fluxcd.io/name":"payments","kustomize.toolkit.fluxcd.io/namespace":"flux-system"}},"spec":{"nodeName":"n1"},"status":{"phase":"Failed","containerStatuses":[{"name":"c","ready":false,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer kubeSrv.Close()

	k := &kube{hc: kubeSrv.Client(), base: kubeSrv.URL, cluster: "default"}
	g := Group{
		Key:        "KubePodCrashLooping",
		Cluster:    "default",
		Namespaces: []string{"ns-a"},
		Alerts: []Alert{{
			Labels:   map[string]string{"alertname": "KubePodCrashLooping", "namespace": "ns-a", "pod": "p"},
			StartsAt: time.Now().Add(-time.Minute),
		}},
	}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{}, nil)
	if len(en.CommitRelevance) != 0 {
		t.Fatalf("expected CommitRelevance to be empty without gh, got %d entries: %+v", len(en.CommitRelevance), en.CommitRelevance)
	}
}

// TestRenderEvidenceRepoPathRefusal pins the digest shape for a refused
// Argo instance (issue #312): the RepoPaths section renders with one
// explicit marker line naming the refused field, with or without resolved
// paths present, and the refused value never appears. Silence for a
// refused reference is the bug; no-annotation and missing-Application
// pods render no section at all (pinned by TestResolveRepoPathsEmpty and
// TestResolveRepoPathsArgoMissingApplicationNoMarker).
func TestRenderEvidenceRepoPathRefusal(t *testing.T) {
	// Only a refusal: the section must still render. "no GitOps path at
	// all" is exactly what must stop reading like "declares none".
	en := Enrichment{RepoPathRefusals: []string{argoInstanceRefusal}}
	evidence := renderEvidence(Report{Enrichment: en})
	if !strings.Contains(evidence, "RepoPaths:\n- "+argoInstanceRefusal+"\n") {
		t.Errorf("refusal-only evidence missing the marker line:\n%s", evidence)
	}
	if strings.Count(evidence, "RepoPaths:") != 1 {
		t.Errorf("expected exactly one RepoPaths section:\n%s", evidence)
	}

	// Refusal alongside a resolved (fallback) path: both render, the path
	// first, and the marker still does not carry the refused value.
	en = Enrichment{
		RepoPaths:        []string{"https://github.com/example/fallback/deploy/staging"},
		RepoPathRefusals: []string{argoInstanceRefusal},
	}
	evidence = renderEvidence(Report{Enrichment: en})
	i := strings.Index(evidence, "https://github.com/example/fallback/deploy/staging")
	j := strings.Index(evidence, argoInstanceRefusal)
	if i < 0 || j < 0 || i > j {
		t.Errorf("expected the path then the marker under RepoPaths:\n%s", evidence)
	}

	// Nothing resolved and nothing refused: no section, unchanged.
	evidence = renderEvidence(Report{Enrichment: Enrichment{}})
	if strings.Contains(evidence, "RepoPaths:") {
		t.Errorf("empty enrichment must render no RepoPaths section:\n%s", evidence)
	}
}

// TestEnrichReportsRefusedArgoInstance wires the marker through the full
// enrichment path: a listed pod whose argocd.argoproj.io/instance is
// refused must land in Enrichment.RepoPathRefusals without any Application
// request, so the digest states the refusal instead of showing no GitOps
// path at all (issue #312).
func TestEnrichReportsRefusedArgoInstance(t *testing.T) {
	var appHits atomic.Int32
	kubeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/applications/") {
			appHits.Add(1)
			t.Errorf("a refused instance must not be requested: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/pods") {
			_, _ = io.WriteString(w, `{"items":[{"metadata":{"name":"p","namespace":"ns-a","annotations":{"argocd.argoproj.io/instance":"web/../../other"}},"spec":{"nodeName":"n1"},"status":{"phase":"Failed","containerStatuses":[{"name":"c","ready":false,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer kubeSrv.Close()

	k := &kube{hc: kubeSrv.Client(), base: kubeSrv.URL, cluster: "default"}
	g := Group{
		Key:        "KubePodCrashLooping",
		Cluster:    "default",
		Namespaces: []string{"ns-a"},
		Alerts: []Alert{{
			Labels:   map[string]string{"alertname": "KubePodCrashLooping", "namespace": "ns-a", "pod": "p"},
			StartsAt: time.Now().Add(-time.Minute),
		}},
	}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{}, nil)
	if len(en.RepoPathRefusals) != 1 || en.RepoPathRefusals[0] != argoInstanceRefusal {
		t.Fatalf("expected the refusal to reach the enrichment, got %#v", en.RepoPathRefusals)
	}
	for _, m := range en.RepoPathRefusals {
		if strings.Contains(m, "web") {
			t.Errorf("the marker must not repeat the refused value, got %q", m)
		}
	}
	if appHits.Load() != 0 {
		t.Fatalf("a refused instance must not be requested, got %d hits", appHits.Load())
	}
}

// TestEvidenceArgoRefusalKeepsRefusedValueFenced pins the boundary the
// marker design relies on end to end (Enrich → renderEvidence). The claim
// "the refused value never appears" is deliberately two-sided, because
// identityTags whitelists argocd.argoproj.io/instance: the very pod whose
// reference was refused echoes the raw annotation into its Ownership chain
// as workload-authored text. The service's own text (the marker, headings,
// logs) must never carry the refused value; author text carrying it may
// appear only inside the untrusted fence. A job-owned pod exercises both
// sides in one digest so a fence regression is caught at render level, not
// only at lookup.
func TestEvidenceArgoRefusalKeepsRefusedValueFenced(t *testing.T) {
	// No whitespace runs and no dash runs, so untrusted() leaves the value
	// verbatim and containment checks compare against the raw annotation.
	const refused = "sneaky/../../elsewhere"
	kubeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/applications/"):
			t.Errorf("a refused instance must not be requested: %s", r.URL.Path)
			http.NotFound(w, r)
		case strings.Contains(r.URL.Path, "/jobs/"):
			_, _ = io.WriteString(w, `{"metadata":{"name":"backup","namespace":"ns-a","uid":"u1"}}`)
		case strings.HasSuffix(r.URL.Path, "/pods"):
			_, _ = io.WriteString(w, `{"items":[{"metadata":{"name":"p","namespace":"ns-a","annotations":{"argocd.argoproj.io/instance":"`+refused+`"},"ownerReferences":[{"apiVersion":"batch/v1","kind":"Job","name":"backup","uid":"u1"}]},"spec":{"nodeName":"n1"},"status":{"phase":"Failed"}}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer kubeSrv.Close()

	k := &kube{hc: kubeSrv.Client(), base: kubeSrv.URL, cluster: "default"}
	g := Group{
		Key:        "KubeJobFailed",
		Cluster:    "default",
		Namespaces: []string{"ns-a"},
		Alerts: []Alert{{
			Labels:   map[string]string{"alertname": "KubeJobFailed", "namespace": "ns-a", "job_name": "backup"},
			StartsAt: time.Now().Add(-time.Minute),
		}},
	}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{}, nil)
	evidence := renderEvidence(Report{Group: g, Enrichment: en})

	// Both channels must have run, or the fence assertions below would
	// pass vacuously: the marker for the refusal, and the identityTags
	// echo that makes a blanket "never appears" claim false.
	if len(en.RepoPathRefusals) != 1 || en.RepoPathRefusals[0] != argoInstanceRefusal {
		t.Fatalf("expected one fixed refusal marker, got %#v", en.RepoPathRefusals)
	}
	if !strings.Contains(strings.Join(en.Ownership, "\n"), refused) {
		t.Fatalf("expected identityTags to echo the annotation into Ownership, got %#v", en.Ownership)
	}

	// The marker is the service's own finding: it renders outside the
	// fence and names the field, not the value.
	if !strings.Contains(evidence, "RepoPaths:\n- "+argoInstanceRefusal) {
		t.Fatalf("refusal marker missing from RepoPaths:\n%s", evidence)
	}
	at := strings.Index(evidence, argoInstanceRefusal)
	if strings.LastIndex(evidence[:at], untrustedBegin) > strings.LastIndex(evidence[:at], untrustedEnd) {
		t.Errorf("the refusal marker was rendered inside an untrusted fence:\n%s", evidence)
	}
	// The refused value must appear nowhere outside the fence...
	if stripped := stripFences(evidence); strings.Contains(stripped, refused) {
		t.Errorf("the refused value escaped the untrusted fence:\nstripped=%q\nfull=\n%s", stripped, evidence)
	}
	// ...and must actually be fenced, not merely dropped: it is the
	// annotation echo in the Ownership chain, author text like every
	// other identityTags value.
	if !messageInsideFence(evidence, refused) {
		t.Errorf("expected the annotation echo inside the untrusted fence:\n%s", evidence)
	}
	if strings.Count(evidence, untrustedBegin) != strings.Count(evidence, untrustedEnd) {
		t.Fatalf("unbalanced fences:\n%s", evidence)
	}
}
