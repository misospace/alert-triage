package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// kube is a minimal read-only Kubernetes client. client-go would pull in a very
// large dependency tree for what amounts to four GETs, so this talks to the
// apiserver directly with the in-cluster ServiceAccount credentials.
type kube struct {
	base  string
	token string
	hc    *http.Client
}

func newKube() (*kube, error) {
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
		base:  fmt.Sprintf("https://%s:%s", host, port),
		token: strings.TrimSpace(string(token)),
		hc: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

func (k *kube) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, k.base+path, nil)
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
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
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
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

type eventList struct {
	Items []struct {
		Type           string    `json:"type"`
		Reason         string    `json:"reason"`
		Message        string    `json:"message"`
		LastTimestamp  time.Time `json:"lastTimestamp"`
		InvolvedObject struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"involvedObject"`
	} `json:"items"`
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

// Enrichment is the evidence gathered for one group.
type Enrichment struct {
	Nodes         []string
	UnhealthyPods []string
	Events        []string
	RecentChanges []string
	// Scope records what was actually inspected, so the narrative can
	// distinguish "nothing is wrong" from "nothing was looked at".
	Scope string
}

func (e Enrichment) empty() bool {
	return len(e.Nodes) == 0 && len(e.UnhealthyPods) == 0 &&
		len(e.Events) == 0 && len(e.RecentChanges) == 0
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
func (k *kube) ResolveNodes(alerts []Alert) map[string]string {
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
		if err := k.get("/api/v1/namespaces/"+url.PathEscape(ns)+"/pods", &pods); err != nil {
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

// Enrich gathers cluster state and recent GitOps changes for a group. Failures
// degrade the digest rather than block it: a partial story beats none.
//
// Cluster-level signals are always collected, because most alerts carry no
// namespace label at all (node, exporter and recording-rule alerts especially)
// and would otherwise yield an empty evidence block.
func (k *kube) Enrich(g Group, window time.Duration) Enrichment {
	var e Enrichment
	if k == nil {
		e.Scope = "cluster state unavailable"
		return e
	}
	since := time.Now().Add(-window)

	e.Nodes = k.unhealthyNodes()
	e.RecentChanges = append(e.RecentChanges, k.fluxNotReady("", since)...)

	if len(g.Namespaces) == 0 {
		// Nothing namespace-scoped to look at, so widen to recent cluster-wide
		// warnings rather than reporting no evidence.
		e.Events = append(e.Events, k.warningEvents("", since)...)
		e.Scope = "cluster-wide (alert carries no namespace)"
	} else {
		e.Scope = "namespaces " + strings.Join(g.Namespaces, ", ") + " plus cluster state"
	}

	for _, ns := range g.Namespaces {
		esc := url.PathEscape(ns)

		var pods podList
		if err := k.get("/api/v1/namespaces/"+esc+"/pods", &pods); err != nil {
			logf("enrich: pods in %s: %v", ns, err)
		}
		for _, p := range pods.Items {
			for _, cs := range p.Status.ContainerStatuses {
				reason := ""
				for state, s := range cs.State {
					if state != "running" && s.Reason != "" {
						reason = s.Reason
					}
				}
				if p.Status.Phase == "Running" && cs.Ready && reason == "" {
					continue
				}
				desc := fmt.Sprintf("%s/%s %s", ns, p.Metadata.Name, p.Status.Phase)
				if reason != "" {
					desc += " (" + reason + ")"
				}
				if cs.RestartCount > 0 {
					desc += fmt.Sprintf(" restarts=%d", cs.RestartCount)
				}
				e.UnhealthyPods = append(e.UnhealthyPods, desc)
				break
			}
		}

		e.Events = append(e.Events, k.warningEvents(esc, since)...)
	}

	e.Nodes = capList(e.Nodes, 6)
	e.UnhealthyPods = capList(e.UnhealthyPods, 8)
	e.Events = capList(dedupe(e.Events), 8)
	e.RecentChanges = capList(dedupe(e.RecentChanges), 6)
	return e
}

// unhealthyNodes reports nodes that are not Ready, are under pressure, or have
// been cordoned. A healthy cluster returns nothing, which is itself evidence.
func (k *kube) unhealthyNodes() []string {
	var nodes nodeList
	if err := k.get("/api/v1/nodes", &nodes); err != nil {
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

// warningEvents returns recent non-Normal events. An empty namespace widens the
// query to the whole cluster.
func (k *kube) warningEvents(namespace string, since time.Time) []string {
	path := "/api/v1/events?fieldSelector=type!=Normal"
	if namespace != "" {
		path = "/api/v1/namespaces/" + namespace + "/events?fieldSelector=type!=Normal"
	}
	var events eventList
	if err := k.get(path, &events); err != nil {
		logf("enrich: events (%s): %v", orAll(namespace), err)
		return nil
	}
	var out []string
	for _, ev := range events.Items {
		if ev.LastTimestamp.Before(since) {
			continue
		}
		out = append(out, fmt.Sprintf("%s %s/%s: %s",
			ev.Reason, ev.InvolvedObject.Kind, ev.InvolvedObject.Name, truncate(ev.Message, 160)))
	}
	return out
}

// fluxNotReady reports Flux resources that are failing or that reconciled
// inside the window, which is how "did a deploy cause this?" gets answered.
func (k *kube) fluxNotReady(namespace string, since time.Time) []string {
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
		if err := k.get(api, &fl); err != nil {
			continue
		}
		for _, item := range fl.Items {
			for _, c := range item.Status.Conditions {
				if c.Type != "Ready" {
					continue
				}
				if c.Status == "True" && !c.LastTransitionTime.After(since) {
					continue
				}
				state := "reconciled recently"
				if c.Status != "True" {
					state = "NOT READY: " + c.Reason
				}
				out = append(out, fmt.Sprintf("%s/%s %s rev=%s",
					item.Metadata.Namespace, item.Metadata.Name, state, shortRev(item.Status.LastAppliedRevision)))
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
