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
| `WEBHOOK_TOKEN`       | *(empty)*            | Shared secret for `/webhook`; when set, clients must send `X-Webhook-Token` header with this value or receive `401` |
| `MAX_BUFFERED`        | `10000`              | Maximum alerts held in the flush buffer; oldest are dropped when exceeded |

### Webhook Authentication

When `WEBHOOK_TOKEN` is set, every POST to `/webhook` must include the header:

```
X-Webhook-Token: <your-secret>
```

Requests without the header or with a wrong value receive HTTP 401.

In Alertmanager, configure the receiver like this:

```yaml
receivers:
  - name: 'alert-triage'
    webhook_configs:
      - url: 'http://alert-triage:8080/webhook'
        send_resolved: false
        http_config:
          headers:
            X-Webhook-Token: '<your-secret>'
```

### NetworkPolicy (recommended)

Limit `/webhook` access to Alertmanager pods only:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: alert-triage-webhook-policy
spec:
  podSelector:
    matchLabels:
      app: alert-triage
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: alertmanager
      ports:
        - protocol: TCP
          port: 8080
```

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
