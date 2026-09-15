package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// podItemFromJSON decodes a single-item pod list into one podItem, for tests
// that only need one pod.
func podItemFromJSON(t *testing.T, raw string) podItem {
	t.Helper()
	var list podList
	if err := json.Unmarshal([]byte(`{"items":[`+raw+`]}`), &list); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(list.Items))
	}
	return list.Items[0]
}

// A pod that declares its execution identity at the pod level (not the
// container level) must have those fields captured, so a permission hypothesis
// can be grounded in what the pod declared.
func TestPodItemPodLevelSecurityContext(t *testing.T) {
	p := podItemFromJSON(t, `{
		"metadata":{"name":"mover","namespace":"ns1"},
		"spec":{"securityContext":{"runAsUser":1000,"runAsGroup":2000,"fsGroup":3000,"runAsNonRoot":true}},
		"status":{"phase":"Failed","containerStatuses":[
			{"name":"mover","ready":false,"restartCount":2,
			 "state":{"crashLoopBackOff":{"reason":"CrashLoopBackOff"}}}
		]}
	}`)
	if p.Spec.Security == nil {
		t.Fatal("expected a pod-level securityContext, got nil")
	}
	u, g, fg, nr := p.Spec.Security.format()
	if u != "1000" || g != "2000" || fg != "3000" || !nr {
		t.Errorf("pod securityContext = (%q,%q,%q,%v), want (1000,2000,3000,true)", u, g, fg, nr)
	}
}

// A container's securityContext must be captured and, per Kubernetes
// precedence, override the pod's field by field; a field only the pod sets
// still comes from the pod.
func TestPodItemContainerOverridesPodIdentity(t *testing.T) {
	p := podItemFromJSON(t, `{
		"metadata":{"name":"mover","namespace":"ns1"},
		"spec":{"securityContext":{"runAsUser":1000,"runAsGroup":2000,"fsGroup":3000,"runAsNonRoot":true}},
		"status":{"phase":"Failed","containerStatuses":[
			{"name":"mover","ready":false,"restartCount":1,
			 "state":{"crashLoopBackOff":{"reason":"CrashLoopBackOff"}},
			 "securityContext":{"runAsUser":4000,"runAsNonRoot":false},
			 "volumeMounts":[{"name":"data","mountPath":"/data","readOnly":false}]}
		]}
	}`)
	cs := &p.Status.ContainerStatuses[0]
	eff := cs.effective(p.Spec.Security)
	u, g, fg, nr := eff.format()
	// runAsUser overridden by the container (4000), runAsGroup/fsGroup inherited
	// from the pod (2000/3000), runAsNonRoot overridden to false.
	if u != "4000" || g != "2000" || fg != "3000" || nr {
		t.Errorf("effective = (%q,%q,%q,%v), want (4000,2000,3000,false)", u, g, fg, nr)
	}
}

// When a container declares nothing, every field reads "unset" - it must not
// be guessed as root from the image.
func TestPodItemAllIdentityUnset(t *testing.T) {
	p := podItemFromJSON(t, `{
		"metadata":{"name":"mover","namespace":"ns1"},
		"status":{"phase":"Failed","containerStatuses":[
			{"name":"mover","ready":false,"state":{"terminated":{"reason":"Error"}}}
		]}
	}`)
	if p.Spec.Security != nil {
		t.Fatalf("expected no pod securityContext, got %v", *p.Spec.Security)
	}
	cs := &p.Status.ContainerStatuses[0]
	eff := cs.effective(p.Spec.Security)
	u, g, fg, nr := eff.format()
	if u != "unset" || g != "unset" || fg != "unset" || nr {
		t.Errorf("unset pod = (%q,%q,%q,%v), want (unset,unset,unset,false)", u, g, fg, nr)
	}
}

// A container securityContext present but with a single field must still
// leave the unset fields unset rather than defaulting them.
func TestPodItemPartialContainerIdentity(t *testing.T) {
	p := podItemFromJSON(t, `{
		"metadata":{"name":"mover","namespace":"ns1"},
		"status":{"phase":"Failed","containerStatuses":[
			{"name":"mover","ready":false,"state":{"terminated":{"reason":"Error"}},
			 "securityContext":{"runAsUser":100}}
		]}
	}`)
	eff := p.Status.ContainerStatuses[0].effective(p.Spec.Security)
	u, g, fg, nr := eff.format()
	if u != "100" || g != "unset" || fg != "unset" || nr {
		t.Errorf("partial = (%q,%q,%q,%v), want (100,unset,unset,false)", u, g, fg, nr)
	}
}

// A volume that references a PVC must be mapped to its claim name; a
// non-PVC volume (emptyDir) must not fabricate a claim.
func TestPodItemVolumeToClaim(t *testing.T) {
	p := podItemFromJSON(t, `{
		"metadata":{"name":"mover","namespace":"ns1"},
		"spec":{"volumes":[
			{"name":"data","persistentVolumeClaim":{"claimName":"data-claim"}},
			{"name":"tmp","emptyDir":{}}
		]},
		"status":{"phase":"Failed","containerStatuses":[
			{"name":"mover","ready":false,"state":{"terminated":{"reason":"Error"}},
			 "volumeMounts":[
				{"name":"data","mountPath":"/data","readOnly":false},
				{"name":"tmp","mountPath":"/tmp","readOnly":false}
			 ]}
		]}
	}`)
	mounts := p.mount()
	if len(mounts) != 1 {
		t.Fatalf("expected exactly the PVC claim, got %v", mounts)
	}
	m, ok := mounts["data-claim"]
	if !ok {
		t.Fatalf("missing data-claim in %v", mounts)
	}
	if m.Container != "mover" || m.Path != "/data" || m.ReadOnly {
		t.Errorf("mount = %+v, want container=mover path=/data read-only=false", m)
	}
}

// A pod with only non-PVC volumes has no claim, so it is not a same-claim
// sibling of anything.
func TestPodItemNoPVCNoClaim(t *testing.T) {
	p := podItemFromJSON(t, `{
		"metadata":{"name":"mover","namespace":"ns1"},
		"spec":{"volumes":[{"name":"tmp","emptyDir":{}}]},
		"status":{"phase":"Failed","containerStatuses":[
			{"name":"mover","ready":false,"state":{"terminated":{"reason":"Error"}},
			 "volumeMounts":[{"name":"tmp","mountPath":"/tmp","readOnly":false}]}
		]}
	}`)
	if len(p.claims()) != 0 {
		t.Errorf("expected no claims, got %v", p.claims())
	}
}

// A container that is in the running state is not failing; a container whose
// only state is non-running is failing. Succeeded pods are never failing.
func TestPodItemFailing(t *testing.T) {
	failing := podItemFromJSON(t, `{
		"metadata":{"name":"a","namespace":"ns1"},
		"status":{"phase":"Failed","containerStatuses":[
			{"name":"mover","ready":false,"state":{"crashLoopBackOff":{"reason":"CrashLoopBackOff"}}},
			{"name":"sidecar","ready":false,"state":{"terminated":{"reason":"Error"}}}
		]}
	}`)
	if !failing.failing()["mover"] || !failing.failing()["sidecar"] {
		t.Errorf("expected both containers failing, got %v", failing.failing())
	}

	healthy := podItemFromJSON(t, `{
		"metadata":{"name":"b","namespace":"ns1"},
		"status":{"phase":"Running","containerStatuses":[
			{"name":"app","ready":true,"state":{"running":{}}}
		]}
	}`)
	if len(healthy.failing()) != 0 {
		t.Errorf("expected no failing container in a healthy Running pod, got %v", healthy.failing())
	}

	succeeded := podItemFromJSON(t, `{
		"metadata":{"name":"c","namespace":"ns1"},
		"status":{"phase":"Succeeded","containerStatuses":[
			{"name":"job","ready":false,"state":{"terminated":{"reason":"Completed"}}}
		]}
	}`)
	if len(succeeded.failing()) != 0 {
		t.Errorf("a Succeeded pod is never failing, got %v", succeeded.failing())
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

// enrichPodsServer returns an httptest server that answers the pods endpoint
// for the given namespaces with the given raw pod lists, and everything else
// (nodes, events, flux, logs) with empty or 404 responses so the enrichment
// degrades to the pod evidence only.
func enrichPodsServer(t *testing.T, podsByNS map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/pods") && !strings.Contains(r.URL.Path, "/log") {
			for ns, body := range podsByNS {
				if strings.Contains(r.URL.Path, "/namespaces/"+ns+"/pods") {
					_, _ = io.WriteString(w, body)
					return
				}
			}
			_, _ = io.WriteString(w, `{"items":[]}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
}

// A same-claim sibling must be reported with its phase/readiness, while a pod
// on a different claim must not appear. This is the case that lets the
// operator tell "the mover failed" from "the serving workload is also
// unhealthy".
func TestEnrichSameClaimSibling(t *testing.T) {
	const mover = `{"items":[
		{"metadata":{"name":"mover-abc","namespace":"ns1"},
		 "spec":{"securityContext":{"runAsUser":1000,"runAsGroup":2000,"fsGroup":3000,"runAsNonRoot":true},
			    "volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-claim"}}]},
		 "status":{"phase":"Failed","containerStatuses":[
			 {"name":"mover","ready":false,"restartCount":1,
			  "state":{"crashLoopBackOff":{"reason":"CrashLoopBackOff"}},
			  "securityContext":{"runAsUser":4000,"runAsNonRoot":false},
			  "volumeMounts":[{"name":"data","mountPath":"/data","readOnly":false}]}]}}
	]}`
	const sibling = `{"items":[
		{"metadata":{"name":"mover-abc","namespace":"ns1"},
		 "spec":{"securityContext":{"runAsUser":1000,"runAsGroup":2000,"fsGroup":3000,"runAsNonRoot":true},
			    "volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-claim"}}]},
		 "status":{"phase":"Failed","containerStatuses":[
			 {"name":"mover","ready":false,"restartCount":1,
			  "state":{"crashLoopBackOff":{"reason":"CrashLoopBackOff"}},
			  "securityContext":{"runAsUser":4000,"runAsNonRoot":false},
			  "volumeMounts":[{"name":"data","mountPath":"/data","readOnly":false}]}]}},
		{"metadata":{"name":"app-xyz","namespace":"ns1"},
		 "spec":{"securityContext":{"runAsUser":0,"runAsGroup":0,"fsGroup":1000,"runAsNonRoot":false},
			    "volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-claim"}}]},
		 "status":{"phase":"Running","containerStatuses":[
			 {"name":"app","ready":true,"restartCount":0,
			  "state":{"running":{}},
			  "volumeMounts":[{"name":"data","mountPath":"/data","readOnly":false}]}]}},
		{"metadata":{"name":"unrelated-1","namespace":"ns1"},
		 "spec":{"volumes":[{"name":"other","persistentVolumeClaim":{"claimName":"other-claim"}}]},
		 "status":{"phase":"Running","containerStatuses":[
			 {"name":"u","ready":true,"state":{"running":{}},
			  "volumeMounts":[{"name":"other","mountPath":"/u","readOnly":false}]}]}}
	]}`

	srv := enrichPodsServer(t, map[string]string{"ns1": sibling})
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "JobFailed", "namespace": "ns1", "pod": "mover-abc"}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{})

	// The target pod's failing container, with its effective declared identity
	// (container runAsUser=4000/runAsNonRoot=false override the pod's 1000/true)
	// and the PVC claim it mounts.
	id := en.PodID["ns1/mover-abc"]
	if !strings.Contains(id, "ns1/mover-abc") {
		t.Fatalf("target identity line missing/other key: %q", id)
	}
	for _, want := range []string{
		"container mover",
		"runAsUser=4000",  // container override, not the pod's 1000
		"runAsGroup=2000", // inherited from the pod (container did not set it)
		"fsGroup=3000",
		"runAsNonRoot=false", // container override, not the pod's true
		"data-claim at /data (read-write)",
	} {
		if !strings.Contains(id, want) {
			t.Errorf("target identity %q missing %q:\n%s", id, want, id)
		}
	}

	// A healthy same-claim sibling is reported so the model can distinguish
	// the mover from the serving workload; it must carry its declared
	// identity and readiness.
	var foundSibling bool
	for _, s := range en.PVCSiblings {
		if strings.Contains(s, "app-xyz") {
			foundSibling = true
			if !strings.Contains(s, "same-claim data-claim") {
				t.Errorf("sibling %q does not name the shared claim", s)
			}
			if !strings.Contains(s, "Running") || !strings.Contains(s, "1/1 ready") {
				t.Errorf("sibling %q missing phase/readiness", s)
			}
		}
	}
	if !foundSibling {
		t.Fatalf("expected the same-claim sibling app-xyz in PVCSiblings, got %v", en.PVCSiblings)
	}
	// A pod on a different claim is not a same-claim sibling.
	for _, s := range en.PVCSiblings {
		if strings.Contains(s, "unrelated-1") {
			t.Errorf("unrelated-claim pod must not be a same-claim sibling: %q", s)
		}
	}
}

// The same-claim sibling list is capped so a namespace with many claim
// consumers does not produce a dump.
func TestEnrichSiblingCap(t *testing.T) {
	var items []string
	for i := 0; i < 10; i++ {
		items = append(items, fmt.Sprintf(
			`{"metadata":{"name":"sib-%d","namespace":"ns1"},
		 "spec":{"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-claim"}}]},
		 "status":{"phase":"Running","containerStatuses":[
			 {"name":"c","ready":true,"state":{"running":{}},
			  "volumeMounts":[{"name":"data","mountPath":"/data","readOnly":false}]}]}}`, i))
	}
	body := `{"items":[
		{"metadata":{"name":"mover","namespace":"ns1"},
		 "spec":{"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-claim"}}]},
		 "status":{"phase":"Failed","containerStatuses":[
			 {"name":"m","ready":false,"state":{"crashLoopBackOff":{"reason":"CrashLoopBackOff"}}}]}},` +
		strings.Join(items, ",") + `]}`

	srv := enrichPodsServer(t, map[string]string{"ns1": body})
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "A", "namespace": "ns1", "pod": "mover"}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{})
	if len(en.PVCSiblings) > sameClaimSibMax {
		t.Errorf("expected at most %d same-claim siblings, got %d: %v", sameClaimSibMax, len(en.PVCSiblings), en.PVCSiblings)
	}
}

// When the target pod's containers declare no identity, the evidence line
// must report "unset" for every field rather than guessing root.
func TestEnrichAllIdentityUnset(t *testing.T) {
	const body = `{"items":[
		{"metadata":{"name":"mover","namespace":"ns1"},
		 "spec":{"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-claim"}}]},
		 "status":{"phase":"Failed","containerStatuses":[
			 {"name":"mover","ready":false,"state":{"crashLoopBackOff":{"reason":"CrashLoopBackOff"}},
			  "volumeMounts":[{"name":"data","mountPath":"/data","readOnly":false}]}]}}
	]}`
	srv := enrichPodsServer(t, map[string]string{"ns1": body})
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "A", "namespace": "ns1", "pod": "mover"}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{})
	id := en.PodID["ns1/mover"]
	for _, want := range []string{"runAsUser=unset", "runAsGroup=unset", "fsGroup=unset", "runAsNonRoot=false"} {
		if !strings.Contains(id, want) {
			t.Errorf("expected %q in %q", want, id)
		}
	}
	if !strings.Contains(id, "data-claim at /data (read-write)") {
		t.Errorf("expected the PVC mount in %q", id)
	}
}

// A pod that has no failing container (healthy, in the running state) is not
// a target for identity evidence even if the alert named it.
func TestEnrichHealthyTargetNoIdentity(t *testing.T) {
	const body = `{"items":[
		{"metadata":{"name":"mover","namespace":"ns1"},
		 "spec":{"securityContext":{"runAsUser":1000,"runAsGroup":2000,"fsGroup":3000,"runAsNonRoot":true},
			    "volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-claim"}}]},
		 "status":{"phase":"Running","containerStatuses":[
			 {"name":"mover","ready":true,"restartCount":0,
			  "state":{"running":{}}}]}}
	]}`
	srv := enrichPodsServer(t, map[string]string{"ns1": body})
	defer srv.Close()

	k := &kube{base: srv.URL, hc: srv.Client()}
	g := Group{
		Namespaces: []string{"ns1"},
		Alerts:     []Alert{{Status: "firing", Labels: map[string]string{"alertname": "A", "namespace": "ns1", "pod": "mover"}}},
	}
	en := k.Enrich(context.Background(), g, time.Minute, &Config{})
	if _, ok := en.PodID["ns1/mover"]; ok {
		t.Errorf("a healthy target with no failing container must not carry an identity line, got %v", en.PodID)
	}
}
