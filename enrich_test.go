package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPodList(t *testing.T) {
	data := []byte(`{"items":[{"metadata":{"name":"p1","namespace":"ns1"},"status":{"phase":"Failed"}}]}`)
	var got podList
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Metadata.Name != "p1" {
		t.Errorf("unexpected result: %v", got)
	}
}

func TestPodListEmpty(t *testing.T) {
	var got podList
	if err := json.Unmarshal([]byte(`{"items":[]}`), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestNodeList(t *testing.T) {
	data := []byte(`{"items":[{"metadata":{"name":"n1"},"status":{"conditions":[{"type":"Ready","status":"False"}]}}]}`)
	var got nodeList
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Metadata.Name != "n1" {
		t.Errorf("unexpected result: %v", got)
	}
}

func TestEventList(t *testing.T) {
	data := []byte(`{"items":[{"reason":"NodeNotReady","message":"node n1 not ready"}]}`)
	var got eventList
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Reason != "NodeNotReady" {
		t.Errorf("unexpected result: %v", got)
	}
}

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

func TestStripSecrets(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"api_key=abc123", "api_key=[REDACTED]"},
		{"password: mysecret", "password: [REDACTED]"},
		{"token = xyz789", "token = [REDACTED]"},
		{"no secrets here", "no secrets here"},
		{"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY_ID=[REDACTED]"},
	}
	for _, tt := range tests {
		got := stripSecrets(tt.in)
		if strings.Contains(got, "abc123") || strings.Contains(got, "mysecret") || strings.Contains(got, "xyz789") || strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("stripSecrets(%q) = %q; secret not redacted", tt.in, got)
		}
	}
}

func TestFetchPodLogs_empty(t *testing.T) {
	k := &kube{}
	got := k.fetchPodLogs(context.Background(), nil)
	if got != nil {
		t.Errorf("expected nil for empty pods, got %v", got)
	}
	got = k.fetchPodLogs(context.Background(), []string{})
	if got != nil {
		t.Errorf("expected nil for empty slice, got %v", got)
	}
}

func TestFetchPodLogs_badKey(t *testing.T) {
	k := &kube{}
	got := k.fetchPodLogs(context.Background(), []string{"no-slash"})
	if len(got) != 0 {
		t.Errorf("expected empty map for bad key, got %v", got)
	}
}

func TestFetchPodLogs_noServer(t *testing.T) {
	k := &kube{base: "http://127.0.0.1:1"}
	got := k.fetchPodLogs(context.Background(), []string{"ns/pod"})
	if len(got) != 0 {
		t.Errorf("expected empty map when server unreachable, got %v", got)
	}
}

func TestFetchPodLogs_success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/log") {
			http.Error(w, "not found", 404)
			return
		}
		q := r.URL.Query()
		if q.Get("previous") != "true" {
			http.Error(w, "expected previous=true", 400)
			return
		}
		w.Write([]byte("line1\nline2\nline3\n"))
	}))
	defer srv.Close()

	k := &kube{base: srv.URL + "/", token: "tok", hc: http.DefaultClient}
	got := k.fetchPodLogs(context.Background(), []string{"ns/pod"})
	if len(got) != 1 {
		t.Fatalf("expected 1 log, got %d", len(got))
	}
	if !strings.Contains(got["ns/pod"], "line1") {
		t.Errorf("log missing expected content: %q", got["ns/pod"])
	}
}

func TestFetchPodLogs_stripsSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("api_key=supersecret\nok line\n"))
	}))
	defer srv.Close()

	k := &kube{base: srv.URL + "/", token: "tok", hc: http.DefaultClient}
	got := k.fetchPodLogs(context.Background(), []string{"ns/pod"})
	if len(got) != 1 {
		t.Fatalf("expected 1 log, got %d", len(got))
	}
	if strings.Contains(got["ns/pod"], "supersecret") {
		t.Errorf("secret not stripped: %q", got["ns/pod"])
	}
}

func TestFetchPodLogs_capped(t *testing.T) {
	big := strings.Repeat("x\n", 100)
	var gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.RawQuery
		w.Write([]byte(big))
	}))
	defer srv.Close()

	k := &kube{base: srv.URL + "/", token: "tok", hc: http.DefaultClient}
	got := k.fetchPodLogs(context.Background(), []string{"ns/pod"})
	if len(got) != 1 {
		t.Fatalf("expected 1 log, got %d", len(got))
	}
	if !strings.Contains(gotURL, "tailLines=20") {
		t.Errorf("expected tailLines=20 in request, got: %s", gotURL)
	}
}

// Regression: 0.1.8 compared the group's cluster against a client cluster that
// was never assigned, so every group looked foreign and enrichment was skipped
// on every instance. 77 digests shipped narrating alert text alone while
// claiming the cluster was healthy. An unknown client cluster must enrich, not
// refuse.
func TestEnrichSkipsOnlyWhenBothClustersAreKnownAndDiffer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()

	tests := []struct {
		name          string
		clientCluster string
		groupCluster  string
		wantSkipped   bool
	}{
		{"client cluster unknown enriches", "", "main", false},
		{"alert carries no cluster label enriches", "main", "", false},
		{"neither known enriches", "", "", false},
		{"same cluster enriches", "main", "main", false},
		{"known and different is skipped", "main", "utility", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &kube{cluster: tt.clientCluster, base: srv.URL, token: "tok", hc: srv.Client()}
			g := Group{Key: "single/A", Cluster: tt.groupCluster, Alerts: []Alert{
				{Labels: map[string]string{"alertname": "A", "namespace": "llm"}},
			}}
			got := k.Enrich(context.Background(), g, time.Minute, &Config{})

			skipped := strings.Contains(got.Scope, "cluster state unavailable")
			if skipped != tt.wantSkipped {
				t.Errorf("skipped = %v, want %v (scope: %q)", skipped, tt.wantSkipped, got.Scope)
			}
		})
	}
}

func TestEnrichment_empty(t *testing.T) {
	got := Enrichment{}.empty()
	if !got {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestEnrich_skipsSucceededPodsAndSortsByScore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.Contains(r.URL.Path, "/pods") || strings.Contains(r.URL.Path, "/log") {
			_, _ = io.WriteString(w, `{}`)
			return
		}
		_, _ = io.WriteString(w, `{"items":[
			{"metadata":{"name":"job-finished","namespace":"ns1"},
			 "status":{"phase":"Succeeded",
			   "containerStatuses":[{"ready":false,"restartCount":0,
			     "state":{"terminated":{"reason":"Completed"}}}]}},
			{"metadata":{"name":"flaky-restart","namespace":"ns1"},
			 "status":{"phase":"Running",
			   "containerStatuses":[{"ready":false,"restartCount":1,
			     "state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}},
			{"metadata":{"name":"pending-pod","namespace":"ns1"},
			 "status":{"phase":"Pending",
			   "containerStatuses":[{"ready":false,"restartCount":0,
			     "state":{"waiting":{"reason":"ImagePullBackOff"}}}]}},
			{"metadata":{"name":"job-finished-2","namespace":"ns1"},
			 "status":{"phase":"Succeeded",
			   "containerStatuses":[{"ready":false,"restartCount":0,
			     "state":{"terminated":{"reason":"Completed"}}}]}}
		]}`)
	}))
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "KubePodNotReady", "namespace": "ns1"}}},
		Namespaces: []string{"ns1"},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{})

	for _, p := range en.UnhealthyPods {
		if strings.Contains(p, "job-finished") {
			t.Errorf("Succeeded pod should be skipped, got %q", p)
		}
	}
	if len(en.UnhealthyPods) != 2 {
		t.Fatalf("expected 2 unhealthy pods (CrashLoopBackOff + Pending), got %d: %v", len(en.UnhealthyPods), en.UnhealthyPods)
	}
	if !strings.Contains(en.UnhealthyPods[0], "flaky-restart") {
		t.Errorf("expected worst pod (CrashLoopBackOff) first, got %v", en.UnhealthyPods)
	}
	if !strings.Contains(en.UnhealthyPods[1], "pending-pod") {
		t.Errorf("expected Pending pod second, got %v", en.UnhealthyPods)
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

// TestResolveNodesPodLabelNoNodeLabel forces the pods-list lookup branch
// of ResolveNodes: the alert has a pod label but no node label, so the
// function must query the pods API to find the node.
func TestResolveNodesPodLabelNoNodeLabel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/pods") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"items":[{"metadata":{"name":"p1"},"spec":{"nodeName":"worker-1"}},{"metadata":{"name":"p2"},"spec":{"nodeName":"worker-2"}}]}`)
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	alerts := []Alert{
		{Fingerprint: "fp-1", Labels: map[string]string{"pod": "p1", "namespace": "ns-a"}},
		{Fingerprint: "fp-2", Labels: map[string]string{"pod": "p2", "namespace": "ns-a"}},
	}
	got := k.ResolveNodes(context.Background(), alerts)
	if got["fp-1"] != "worker-1" {
		t.Fatalf("expected fp-1 -> worker-1, got %q", got["fp-1"])
	}
	if got["fp-2"] != "worker-2" {
		t.Fatalf("expected fp-2 -> worker-2, got %q", got["fp-2"])
	}
}

// TestResolveNodesNodeLabelShortCircuit exercises the fast path: alerts
// that already carry a node label should not trigger the pods API.
func TestResolveNodesNodeLabelShortCircuit(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	k := &kube{hc: srv.Client(), base: srv.URL}
	alerts := []Alert{
		{Fingerprint: "fp-3", Labels: map[string]string{"node": "ctrl-1"}},
	}
	got := k.ResolveNodes(context.Background(), alerts)
	if got["fp-3"] != "ctrl-1" {
		t.Fatalf("expected fp-3 -> ctrl-1, got %q", got["fp-3"])
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("unexpected API hits when alert already has node label: %d", hits)
	}
}

// TestResolveNodesNilReceiver ensures the nil-receiver guard works.
func TestResolveNodesNilReceiver(t *testing.T) {
	var k *kube
	got := k.ResolveNodes(context.Background(), []Alert{{Fingerprint: "fp", Labels: map[string]string{"node": "x"}}})
	// Nil receiver on a node-labelled alert is allowed to return either
	// an empty map (the simple guard) or a populated map. Either is fine.
	if got["fp"] != "" && got["fp"] != "x" {
		t.Fatalf("nil receiver returned unexpected entry: %#v", got)
	}
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

// TestKubeGetContextCancelled verifies that a stalled apiserver call is
// cancelled promptly when the caller's context is cancelled, rather than
// blocking for the full http.Client.Timeout (15s).
func TestKubeGetContextCancelled(t *testing.T) {
	// Server that blocks on the read until the request's context is
	// cancelled, simulating a stalled apiserver.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	k := &kube{
		base: srv.URL,
		hc:   &http.Client{Timeout: 15 * time.Second},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		var out nodeList
		done <- k.get(ctx, "/api/v1/nodes", &out)
	}()

	// Give the request a moment to reach the server, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from cancelled context, got nil")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("get did not return promptly after context cancellation")
	}
}

// TestFetchPodLogsContextCancelled verifies that fetchPodLogs also honours
// context cancellation.
func TestFetchPodLogsContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	k := &kube{
		base: srv.URL,
		hc:   &http.Client{Timeout: 15 * time.Second},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan map[string]string, 1)
	go func() {
		done <- k.fetchPodLogs(ctx, []string{"ns/pod"})
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case got := <-done:
		if len(got) != 0 {
			t.Errorf("expected empty map after cancellation, got %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fetchPodLogs did not return promptly after context cancellation")
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
	en := k.Enrich(context.Background(), g, time.Hour, &Config{})
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

// jobAPIHarness is an httptest server that stands in for the apiserver
// endpoints Enrich touches: node health, the per-namespace pod list, warning
// events, Flux state, and the batch/v1 Job read. jobs is keyed by job name; a
// spec with missing=true makes the Job read 404. The pods list is served
// verbatim for any namespace.
func jobAPIHarness(t *testing.T, podsJSON string, jobs map[string]jobSpec) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/nodes"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		case strings.HasSuffix(path, "/pods") || strings.Contains(path, "/pods/"):
			// The per-namespace pod list and the (fetched) pod log both land
			// here; the list is the one that ends in "/pods".
			if strings.HasSuffix(path, "/pods") {
				_, _ = io.WriteString(w, podsJSON)
			} else {
				// previous=true log tail; serve an empty body so no content
				// is attached to the test's assertions.
			}
		case strings.Contains(path, "/events"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		case strings.Contains(path, "/helmreleases") || strings.Contains(path, "/kustomizations"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		case strings.Contains(path, "/jobs/"):
			name := path[strings.LastIndex(path, "/")+1:]
			if j, ok := jobs[name]; ok {
				if j.missing {
					http.NotFound(w, r)
					return
				}
				_, _ = io.WriteString(w, j.json)
				return
			}
			http.NotFound(w, r)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
}

type jobSpec struct {
	missing bool
	json    string
}

// TestEnrichJobFailedResolvesOwnedPod is the core case: a KubeJobFailed alert
// names a job via job_name (and its own namespace) but carries no pod label.
// The job's one owned pod failed, and there is an unrelated healthy pod in the
// same namespace. Enrich must resolve the job, promote the owned failed pod
// into the direct-target set (so it is reported), and record the job in
// Enrichment.InspectedJobs / Scope so the narrative can say the failed job was
// inspected rather than merely the namespace.
func TestEnrichJobFailedResolvesOwnedPod(t *testing.T) {
	pods := `{
		"items":[
			{"metadata":{"name":"backup-0","namespace":"ns1",
				"ownerReferences":[{"kind":"Job","name":"backup","uid":"job-uid-1"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}},
			{"metadata":{"name":"unrelated","namespace":"ns1",
				"ownerReferences":[{"kind":"ReplicaSet","name":"svc-0","uid":"rs-1"}]},
				"status":{"phase":"Running",
					"containerStatuses":[{"name":"c","ready":true,"restartCount":0,
						"state":{"running":{"reason":""}}}]}}
		]}`
	jobs := map[string]jobSpec{
		"backup": {json: `{"metadata":{"name":"backup","namespace":"ns1","uid":"job-uid-1"},
			"spec":{"template":{"metadata":{"labels":{"job-name":"backup"}}}}}`},
	}
	srv := jobAPIHarness(t, pods, jobs)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{})

	// The job is represented in enrichment scope.
	if len(en.InspectedJobs) != 1 || en.InspectedJobs[0] != "ns1/backup" {
		t.Fatalf("InspectedJobs = %v, want [ns1/backup]", en.InspectedJobs)
	}
	if !strings.Contains(en.Scope, "jobs ns1/backup were inspected") {
		t.Errorf("scope %q does not record that the job was inspected", en.Scope)
	}
	// The owned failed pod is a direct target and is reported.
	if !podInList(t, en.UnhealthyPods, "ns1/backup-0") {
		t.Fatalf("owned failed pod ns1/backup-0 not in UnhealthyPods: %v", en.UnhealthyPods)
	}
	// The unrelated healthy pod is not reported.
	if podInList(t, en.UnhealthyPods, "ns1/unrelated") {
		t.Errorf("unrelated healthy pod should not be unhealthy: %v", en.UnhealthyPods)
	}
}

// TestEnrichJobFailedMultipleOwnedPods covers a job that created more than one
// pod (retries / parallelism): every owned failed pod is promoted, not just the
// first one the listing happens to return.
func TestEnrichJobFailedMultipleOwnedPods(t *testing.T) {
	pods := `{
		"items":[
			{"metadata":{"name":"backup-0","namespace":"ns1",
				"ownerReferences":[{"kind":"Job","name":"backup","uid":"job-uid-1"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}},
			{"metadata":{"name":"backup-1","namespace":"ns1",
				"ownerReferences":[{"kind":"Job","name":"backup","uid":"job-uid-1"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":3,
						"state":{"error":{"reason":"CrashLoopBackOff"}}}]}}
		]}`
	jobs := map[string]jobSpec{
		"backup": {json: `{"metadata":{"name":"backup","namespace":"ns1","uid":"job-uid-1"},
			"spec":{"template":{"metadata":{"labels":{"job-name":"backup"}}}}}`},
	}
	srv := jobAPIHarness(t, pods, jobs)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{})

	if !podInList(t, en.UnhealthyPods, "ns1/backup-0") {
		t.Errorf("owned pod ns1/backup-0 missing: %v", en.UnhealthyPods)
	}
	if !podInList(t, en.UnhealthyPods, "ns1/backup-1") {
		t.Errorf("owned pod ns1/backup-1 missing: %v", en.UnhealthyPods)
	}
}

// TestEnrichJobFailedUnrelatedPod verifies that an unrelated pod in the same
// namespace (owned by something else) is not confused with the job's pod: the
// job-owned pod is promoted to the front of the unhealthy list ahead of a
// higher-scoring unrelated pod, so it survives truncation.
func TestEnrichJobFailedUnrelatedPod(t *testing.T) {
	pods := `{
		"items":[
			{"metadata":{"name":"backup-0","namespace":"ns1",
				"ownerReferences":[{"kind":"Job","name":"backup","uid":"job-uid-1"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}},
			{"metadata":{"name":"noisy","namespace":"ns1",
				"ownerReferences":[{"kind":"DaemonSet","name":"ds-0","uid":"ds-1"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":5,
						"state":{"error":{"reason":"OOMKilled"}}}]}}
		]}`
	jobs := map[string]jobSpec{
		"backup": {json: `{"metadata":{"name":"backup","namespace":"ns1","uid":"job-uid-1"},
			"spec":{"template":{"metadata":{"labels":{"job-name":"backup"}}}}}`},
	}
	srv := jobAPIHarness(t, pods, jobs)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{})

	iOwned, iNoisy := -1, -1
	for i, p := range en.UnhealthyPods {
		if strings.Contains(p, "ns1/backup-0") {
			iOwned = i
		}
		if strings.Contains(p, "ns1/noisy") {
			iNoisy = i
		}
	}
	if iOwned < 0 || iNoisy < 0 {
		t.Fatalf("expected both owned and unrelated pods, got %v", en.UnhealthyPods)
	}
	if iOwned > iNoisy {
		t.Errorf("job-owned pod must come before the unrelated pod (iOwned=%d, iNoisy=%d): %v", iOwned, iNoisy, en.UnhealthyPods)
	}
}

// TestEnrichJobFailedMissingJob covers a job that is gone (404): enrichment
// must degrade gracefully — no job in InspectedJobs, no job in the scope
// string — and must still ship the namespace listing it gathered.
func TestEnrichJobFailedMissingJob(t *testing.T) {
	pods := `{
		"items":[
			{"metadata":{"name":"stray","namespace":"ns1",
				"ownerReferences":[{"kind":"ReplicaSet","name":"svc-0","uid":"rs-1"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}}
		]}`
	jobs := map[string]jobSpec{"backup": {missing: true}}
	srv := jobAPIHarness(t, pods, jobs)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{})

	if len(en.InspectedJobs) != 0 {
		t.Fatalf("missing job should not be recorded as inspected, got %v", en.InspectedJobs)
	}
	if strings.Contains(en.Scope, "jobs ") {
		t.Errorf("scope should not name a job when the job is missing: %q", en.Scope)
	}
	// The namespace listing still runs, so a genuinely unhealthy pod is still
	// reported even though the job could not be resolved.
	if !podInList(t, en.UnhealthyPods, "ns1/stray") {
		t.Fatalf("expected the namespace listing to still surface the unhealthy pod, got %v", en.UnhealthyPods)
	}
}

// TestEnrichPodLabelUnchanged is a regression guard: an alert that names its
// subject with a `pod` label (no `job_name`) must behave exactly as before —
// no job is fetched, nothing is recorded in InspectedJobs — and the pod it
// names is a direct target.
func TestEnrichPodLabelUnchanged(t *testing.T) {
	var jobHits int
	pods := `{
		"items":[
			{"metadata":{"name":"web-0","namespace":"ns1",
				"ownerReferences":[{"kind":"ReplicaSet","name":"web-0","uid":"rs-1"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}}
		]}`
	counting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case strings.Contains(path, "/jobs/"):
			jobHits++
			http.NotFound(w, r)
		case strings.HasSuffix(path, "/nodes"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		case strings.HasSuffix(path, "/pods"):
			_, _ = io.WriteString(w, pods)
		case strings.Contains(path, "/events") || strings.Contains(path, "/helmreleases") || strings.Contains(path, "/kustomizations"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	defer counting.Close()

	k := &kube{base: counting.URL, hc: counting.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{{Labels: map[string]string{
			"alertname": "KubePodNotReady", "namespace": "ns1", "pod": "web-0",
		}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{})

	if jobHits != 0 {
		t.Fatalf("a pod-labelled alert with no job_name must not fetch any job, got %d job hit(s)", jobHits)
	}
	if len(en.InspectedJobs) != 0 {
		t.Fatalf("no job was named, so InspectedJobs must be empty, got %v", en.InspectedJobs)
	}
	// The pod the alert names is still a direct target and is reported.
	if !podInList(t, en.UnhealthyPods, "ns1/web-0") {
		t.Fatalf("pod-labelled alert's own pod should be a direct target, got %v", en.UnhealthyPods)
	}
}

// podInList reports whether any entry of got names the given "ns/name" pod
// (the enriched list is a slice of "ns/name <phase> ..." strings).
func podInList(t *testing.T, got []string, key string) bool {
	t.Helper()
	for _, s := range got {
		if strings.Contains(s, key) {
			return true
		}
	}
	return false
}

// TestEnrichJobFailedMultipleJobs pins the scope statement for a group whose
// alerts name more than one job: the resolved jobs are recorded in
// InspectedJobs in a stable (sorted) order and the scope names all of them, so
// "jobs ns1/b, ns1/a were inspected" is the same string on every run.
func TestEnrichJobFailedMultipleJobs(t *testing.T) {
	pods := `{
		"items":[
			{"metadata":{"name":"a-0","namespace":"ns1",
				"ownerReferences":[{"kind":"Job","name":"a","uid":"ua"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}},
			{"metadata":{"name":"b-0","namespace":"ns1",
				"ownerReferences":[{"kind":"Job","name":"b","uid":"ub"}]},
				"status":{"phase":"Failed",
					"containerStatuses":[{"name":"c","ready":false,"restartCount":0,
						"state":{"error":{"reason":"Error"}}}]}}
		]}`
	jobs := map[string]jobSpec{
		"a": {json: `{"metadata":{"name":"a","namespace":"ns1","uid":"ua"},"spec":{"template":{"metadata":{"labels":{"job-name":"a"}}}}}`},
		"b": {json: `{"metadata":{"name":"b","namespace":"ns1","uid":"ub"},"spec":{"template":{"metadata":{"labels":{"job-name":"b"}}}}}`},
	}
	srv := jobAPIHarness(t, pods, jobs)
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{
			{Labels: map[string]string{"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "a"}},
			{Labels: map[string]string{"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "b"}},
		},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{})

	if len(en.InspectedJobs) != 2 || en.InspectedJobs[0] != "ns1/a" || en.InspectedJobs[1] != "ns1/b" {
		t.Fatalf("InspectedJobs not sorted, got %v", en.InspectedJobs)
	}
	if !strings.Contains(en.Scope, "jobs ns1/a, ns1/b were inspected") {
		t.Errorf("scope should name both jobs in sorted order: %q", en.Scope)
	}
	// Both jobs' owned failed pods are promoted into the direct-target set.
	if !podInList(t, en.UnhealthyPods, "ns1/a-0") || !podInList(t, en.UnhealthyPods, "ns1/b-0") {
		t.Fatalf("both owned failed pods should be reported, got %v", en.UnhealthyPods)
	}
}

// TestJobOwnedByFallback covers the ownership rule: a pod with a Job owner
// reference is attributed by that reference (name + uid), and the
// job-name=<name> label fallback is used only when no Job owner reference is
// present at all. A pod owned by a different job must never be claimed.
func TestJobOwnedByFallback(t *testing.T) {
	job := jobRef{Namespace: "ns1", Name: "backup", UID: "job-uid-1", ControllerKey: "job-name", LabelValue: "backup"}

	cases := []struct {
		name string
		pod  podOwner
		want bool
	}{
		{"owned by uid and name", podOwner{OwnerReferences: []ownerRef{{Kind: "Job", Name: "backup", UID: "job-uid-1"}}}, true},
		{"owned by name, uid missing", podOwner{OwnerReferences: []ownerRef{{Kind: "Job", Name: "backup"}}}, true},
		{"owned by a different job", podOwner{OwnerReferences: []ownerRef{{Kind: "Job", Name: "other", UID: "x"}}, Labels: map[string]string{"job-name": "backup"}}, false},
		{"no owner ref, label fallback matches", podOwner{Labels: map[string]string{"job-name": "backup"}}, true},
		{"no owner ref, label fallback misses", podOwner{Labels: map[string]string{"job-name": "other"}}, false},
	}
	for _, tc := range cases {
		if got := jobOwnedBy(job, tc.pod); got != tc.want {
			t.Errorf("jobOwnedBy(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestEnrichScopesResolvedJobAndOwnedPodEvents(t *testing.T) {
	eventTime := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	var eventHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/nodes"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		case strings.HasSuffix(r.URL.Path, "/pods"):
			_, _ = io.WriteString(w, `{"items":[
				{"metadata":{"name":"backup-0","namespace":"ns1","labels":{"job-name":"backup"}},"status":{"phase":"Failed","containerStatuses":[{"name":"job","ready":false,"state":{"terminated":{"reason":"Error"}}}]}},
				{"metadata":{"name":"notifier-0","namespace":"ns1"},"status":{"phase":"Running","containerStatuses":[{"name":"notifier","ready":true,"state":{"running":{}}}]}}
			]}`)
		case strings.Contains(r.URL.Path, "/jobs/"):
			_, _ = io.WriteString(w, `{"metadata":{"name":"backup","namespace":"ns1","uid":"job-uid-1"},"spec":{"template":{"metadata":{"labels":{"job-name":"backup"}}}}}`)
		case strings.Contains(r.URL.Path, "/events"):
			eventHits++
			_, _ = io.WriteString(w, `{"items":[
				{"reason":"BackoffLimitExceeded","message":"job failed","lastTimestamp":"`+eventTime+`","involvedObject":{"kind":"Job","name":"backup","namespace":"ns1"}},
				{"reason":"BackoffLimitExceeded","message":"job failed","lastTimestamp":"`+eventTime+`","involvedObject":{"kind":"Job","name":"backup","namespace":"ns1"}},
				{"reason":"Failed","message":"pod failed","lastTimestamp":"`+eventTime+`","involvedObject":{"kind":"Pod","name":"backup-0","namespace":"ns1"}},
				{"reason":"FailedMount","message":"unrelated pvc","lastTimestamp":"`+eventTime+`","involvedObject":{"kind":"PersistentVolumeClaim","name":"data","namespace":"ns1"}},
				{"reason":"Failed","message":"unrelated pod","lastTimestamp":"`+eventTime+`","involvedObject":{"kind":"Pod","name":"notifier-0","namespace":"ns1"}},
				{"reason":"AlertFiring","message":"unrelated alert","lastTimestamp":"`+eventTime+`","involvedObject":{"kind":"Alert","name":"other","namespace":"ns1"}}
			]}`)
		default:
			_, _ = io.WriteString(w, `{"items":[]}`)
		}
	}))
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts: []Alert{
			{Labels: map[string]string{"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup"}},
			{Labels: map[string]string{"alertname": "KubeJobFailed", "namespace": "ns1", "job_name": "backup"}},
		},
	}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{})

	if !en.EventsScoped {
		t.Fatal("resolved job should scope events")
	}
	if eventHits != 1 {
		t.Fatalf("expected one event fetch for the namespace, got %d", eventHits)
	}
	if len(en.Events) != 2 || !strings.Contains(en.Events[0], "BackoffLimitExceeded x2") || !strings.Contains(en.Events[1], "backup-0") {
		t.Fatalf("expected aggregated Job and owned Pod evidence, got %v", en.Events)
	}
	if len(en.Ambient) != 3 {
		t.Fatalf("expected unrelated PVC, Pod, and Alert events in ambient, got %v", en.Ambient)
	}
	for _, item := range en.Events {
		if strings.Contains(item, "data") || strings.Contains(item, "notifier-0") || strings.Contains(item, "other") {
			t.Errorf("unrelated event became primary evidence: %q", item)
		}
	}
}

func TestRenderScopedEventNegative(t *testing.T) {
	got := renderEvidence(Report{Enrichment: Enrichment{EventsScoped: true}})
	if !strings.Contains(got, "no warning events on the resolved subject in the window") {
		t.Fatalf("missing scoped event negative: %s", got)
	}
}

func TestEnrichNoSubjectEventsAreAmbient(t *testing.T) {
	eventTime := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/events") {
			_, _ = io.WriteString(w, `{"items":[{"reason":"FailedMount","message":"background pvc","lastTimestamp":"`+eventTime+`","involvedObject":{"kind":"PersistentVolumeClaim","name":"data","namespace":"ns1"}}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"items":[]}`)
	}))
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{Namespaces: []string{"ns1"}, Alerts: []Alert{{Labels: map[string]string{"alertname": "KubePodNotReady", "namespace": "ns1"}}}}
	en := k.Enrich(context.Background(), g, time.Hour, &Config{})
	if en.EventsScoped || len(en.Events) != 0 {
		t.Fatalf("no resolved subject must not have primary events: scoped=%v events=%v", en.EventsScoped, en.Events)
	}
	if len(en.Ambient) != 1 || !strings.Contains(en.Ambient[0], "PersistentVolumeClaim") {
		t.Fatalf("namespace event should be ambient background, got %v", en.Ambient)
	}
	got := renderEvidence(Report{Group: g, Enrichment: en})
	if !strings.Contains(got, "BACKGROUND") || strings.Contains(got, "no warning events on the resolved subject in the window") {
		t.Fatalf("fallback evidence should be broad/background, got %s", got)
	}
}
