package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

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
