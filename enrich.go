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

// Enrichment is the evidence gathered for one group.
type Enrichment struct {
	UnhealthyPods []string
	Events        []string
	RecentChanges []string
}

func (e Enrichment) empty() bool {
	return len(e.UnhealthyPods) == 0 && len(e.Events) == 0 && len(e.RecentChanges) == 0
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
func (k *kube) Enrich(g Group, window time.Duration) Enrichment {
	var e Enrichment
	if k == nil {
		return e
	}
	since := time.Now().Add(-window)

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

		var events eventList
		if err := k.get("/api/v1/namespaces/"+esc+"/events?fieldSelector=type!=Normal", &events); err != nil {
			logf("enrich: events in %s: %v", ns, err)
		}
		for _, ev := range events.Items {
			if ev.LastTimestamp.Before(since) {
				continue
			}
			e.Events = append(e.Events, fmt.Sprintf("%s %s/%s: %s",
				ev.Reason, ev.InvolvedObject.Kind, ev.InvolvedObject.Name, truncate(ev.Message, 160)))
		}

		for _, api := range []string{
			"/apis/helm.toolkit.fluxcd.io/v2/namespaces/" + esc + "/helmreleases",
			"/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/" + esc + "/kustomizations",
		} {
			var fl fluxList
			if err := k.get(api, &fl); err != nil {
				continue
			}
			for _, item := range fl.Items {
				for _, c := range item.Status.Conditions {
					if c.Type != "Ready" {
						continue
					}
					changed := c.LastTransitionTime.After(since)
					if !changed && c.Status == "True" {
						continue
					}
					state := "reconciled"
					if c.Status != "True" {
						state = "NOT READY: " + c.Reason
					}
					e.RecentChanges = append(e.RecentChanges, fmt.Sprintf("%s/%s %s rev=%s",
						ns, item.Metadata.Name, state, shortRev(item.Status.LastAppliedRevision)))
				}
			}
		}
	}

	e.UnhealthyPods = capList(e.UnhealthyPods, 8)
	e.Events = capList(e.Events, 8)
	e.RecentChanges = capList(e.RecentChanges, 6)
	return e
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
