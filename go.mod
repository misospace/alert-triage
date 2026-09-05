module github.com/misospace/alert-triage

go 1.27

// yaml.v3 is the sole non-stdlib dependency (see AGENTS.md). It is pinned at
// v3.0.1; go.sum also carries its transitive test dep gopkg.in/check.v1 so the
// full module graph is reproducible (go list -u -m all, Renovate). Any future
// yaml.v3 bump must regenerate go.sum via `go mod tidy`.
require gopkg.in/yaml.v3 v3.0.1
