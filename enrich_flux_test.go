package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
	got := k.resolveRepoPaths(context.Background(), pods, cfg)
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
	got := k.resolveRepoPaths(context.Background(), pods, &Config{})
	if len(got) != 1 || got[0] != "https://github.com/example/payments/apps/payments" {
		t.Fatalf("unexpected paths: %#v", got)
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
	got := k.resolveRepoPaths(context.Background(), pods, &Config{})
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
	got := k.resolveRepoPaths(context.Background(), pods, &Config{})
	if len(got) != 1 || got[0] != "https://github.com/example/argo/manifests/web" {
		t.Fatalf("unexpected paths: %#v", got)
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
	got := k.resolveRepoPaths(context.Background(), pods, cfg)
	if len(got) != 1 || got[0] != "https://github.com/example/fallback/deploy/staging" {
		t.Fatalf("unexpected fallback paths: %#v", got)
	}
}

// TestResolveRepoPathsEmpty exercises the empty-result case: no pods, or
// pods with no annotations and no fallback configured.
func TestResolveRepoPathsEmpty(t *testing.T) {
	k := &kube{}
	if got := k.resolveRepoPaths(context.Background(), nil, &Config{}); got != nil {
		t.Fatalf("expected nil, got %#v", got)
	}
	cfg := &Config{}
	if got := k.resolveRepoPaths(context.Background(), []podRef{{Annotations: map[string]string{}}}, cfg); got != nil {
		t.Fatalf("expected nil when nothing resolves and no fallback configured, got %#v", got)
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
			got := k.resolveRepoPaths(context.Background(), pods, &Config{})
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
		got := k.resolveRepoPaths(context.Background(), []podRef{{Name: "p", Namespace: "ns", Annotations: map[string]string{}}}, cfg)
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
		got := k.resolveRepoPaths(context.Background(), []podRef{{Name: "p", Namespace: "ns", Annotations: map[string]string{}}}, cfg)
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
		got := k.resolveRepoPaths(context.Background(), []podRef{{Name: "p", Namespace: "ns", Annotations: map[string]string{}}}, cfg)
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
		got := k.resolveRepoPaths(context.Background(), []podRef{{Name: "p", Namespace: "ns", Annotations: map[string]string{}}}, cfg)
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
		got := k.resolveRepoPaths(context.Background(), pods, cfg)
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
	got := k.fluxActivity(context.Background(), "llm", time.Now().Add(-time.Hour))
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
	got := k.fluxActivity(context.Background(), "llm", time.Now().Add(-time.Hour))
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
	got := k.fluxActivity(context.Background(), "llm", time.Now().Add(-time.Hour))
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
	ambient := k2.fluxActivity(context.Background(), "", time.Now().Add(-time.Hour))
	if len(ambient) != 1 {
		t.Fatalf("cluster-wide scope must keep only the NotReady line, got %v", ambient)
	}
	if !strings.Contains(ambient[0], "NOT READY") {
		t.Errorf("cluster-wide scope must keep the failure, got %q", ambient[0])
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
