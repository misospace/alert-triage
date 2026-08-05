# alert-triage

[![CI](https://github.com/misospace/alert-triage/actions/workflows/ci.yaml/badge.svg)](https://github.com/misospace/alert-triage/actions/workflows/ci.yaml)

Correlates Alertmanager alerts into incidents, attaches cluster evidence, and
posts a short digest to Discord.

Alertmanager already groups identical alerts by `alertname`. What it cannot do
is recognise that an NFS export going away, five pods crashlooping, and a Ceph
warning are one event. This service fills that gap: it buffers a burst, groups
the alerts by probable root cause, gathers supporting evidence from the cluster,
and asks a model to explain what happened in a couple of sentences.

It is deliberately cluster-local — it reads only its own API server and keeps
its own history — so a second instance in another cluster needs no shared
credentials or state.

## Pipeline

1. **Ingest** — `POST /webhook` accepts the Alertmanager v4 payload and returns
   `202` immediately. Resolved alerts are dropped.
2. **Window** — alerts buffer for `FLUSH_DELAY` after the first arrival, capped
   at `MAX_WINDOW` so a slow cascade still reports.
3. **Correlate** — a pure function groups alerts by, in order of precedence:
   a known failure signature (NFS, Ceph, node, DNS), a shared node, or a shared
   namespace with overlapping active windows. Signatures win because shared
   storage and DNS faults cross node boundaries.
4. **Enrich** — unhealthy pods, recent warning events, and recent Flux
   HelmRelease/Kustomization transitions for the involved namespaces.
5. **History** — every group is recorded to a JSONL file so the digest can say
   whether an incident is novel or routine.
6. **Narrate** — one chat completion per group via LiteLLM.
7. **Deliver** — one Discord embed per group.

Enrichment and narration are both optional: if the API server or the model is
unreachable, the digest still ships with whatever is available.

## Configuration

| Variable              | Default              | Purpose                                        |
| --------------------- | -------------------- | ---------------------------------------------- |
| `LISTEN_ADDR`         | `:8080`              | HTTP listen address                            |
| `LITELLM_URL`         | —                    | LiteLLM base URL, e.g. `http://litellm.llm:4000/v1` |
| `LITELLM_API_KEY`     | —                    | Scoped LiteLLM key                             |
| `MODEL`               | `dsv4f`              | Model alias used for the narrative             |
| `DISCORD_WEBHOOK_URL` | —                    | Digest channel webhook                         |
| `HISTORY_PATH`        | `/data/history.jsonl`| History file (persist this)                    |
| `FLUSH_DELAY`         | `3m`                 | Quiet period before reporting a burst          |
| `MAX_WINDOW`          | `10m`                | Hard cap on buffering                          |
| `CORRELATE_SLACK`     | `5m`                 | Overlap tolerance when grouping                |
| `EVIDENCE_WINDOW`     | `30m`                | How far back to look for events and changes    |
| `RETENTION`           | `168h`               | History retention                              |
| `NARRATE_TIMEOUT`     | `120s`               | Model call timeout                             |

## Deploying

Images are published to `ghcr.io/misospace/alert-triage` on tag push. Point an
Alertmanager webhook receiver at `/webhook` and give the pod a ServiceAccount
with the RBAC below.

## RBAC

Read-only, cluster-wide: `pods` and `events` in `""`, `helmreleases` in
`helm.toolkit.fluxcd.io`, `kustomizations` in `kustomize.toolkit.fluxcd.io`.

## Endpoints

- `POST /webhook` — Alertmanager receiver
- `GET /healthz` — liveness
- `GET /recent` — the last 20 delivered digests as JSON, including the evidence
  the model was given and the narrative it wrote

## Reviewing what it said

Judging triage quality means reading the narratives, which otherwise only exist
in a chat client. Two ways to get at them without one:

```sh
kubectl port-forward -n observability svc/alert-triage 8080:8080
curl -s localhost:8080/recent | jq '.[] | {key, title, narrative}'
```

Each digest is also logged as a single line (`digest <key> [severity] <title> |
<narrative>`), so the history survives a restart wherever logs are shipped.
