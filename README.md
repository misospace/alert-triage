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
6. **Narrate** — one chat completion per group via LiteLLM, which also judges
   where a fix would have to be made: `git`, `partial`, `cluster`, `external` or
   `unknown`. Only `git` and `partial` are actionable by editing the repository,
   which is the gate a future issue sink would use.
7. **Deliver** — one Discord embed per group.

Enrichment and narration are both optional: if the API server or the model is
unreachable, the digest still ships with whatever is available.

## Configuration

| Variable              | Default              | Purpose                                        |
| --------------------- | -------------------- | ---------------------------------------------- |
| `LISTEN_ADDR`         | `:8080`              | HTTP listen address                            |
| `WEBHOOK_TOKEN`       | —                    | Shared secret required on `/webhook`. Unset accepts everything |
| `MAX_ALERTS`          | `500`                | Cap on alerts buffered in one window           |
| `MAX_GROUPS`          | `12`                 | Cap on groups narrated per flush               |
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
| `TRIAGE_LABEL`        | —                    | When set, only alerts whose `<label>="true"` is buffered. Empty triages everything. |

## Opt-in triage

Triage costs a model call and a Discord message. Alerts that nobody reading
this cluster can act on — upstream API quotas, third-party vendor outages,
informational notices — still cost those today. The principle is that the
alerting rules know whether a fire is worth investigating, so opt-in is by
label: only PrometheusRules carrying `<TRIAGE_LABEL>="true"` get triaged.

The contract is enforced in two places:

- **Alertmanager route** (lives in `joryirving/home-ops`, not here): match on
  the label and route those alerts to the `/webhook` receiver. This is the
  primary contract — the filter below is a backstop for misroutes.
- **Webhook** (this service): when `TRIAGE_LABEL` is set, the handler drops
  any alert whose label is not exactly `"true"` and logs a single line per
  delivery with the cumulative drop count, so a label-rule typo is visible
  without checking metrics.

`TRIAGE_LABEL` defaults to empty (fail-open, matching `WEBHOOK_TOKEN`), so a
fresh image triages every alert. Leave it unset until the rules in `home-ops`
are labelled; flipping it on beforehand silently drops everything.

Rollout ordering:

1. Ship this code with `TRIAGE_LABEL` unset so behaviour is unchanged.
2. Label the PrometheusRules you want triaged in `home-ops`.
3. Add an Alertmanager route matcher for `<label> = "true"`.
4. Set `TRIAGE_LABEL` on the deployment. The webhook filter then backstops
   anything the route missed.

Example rule with the opt-in label:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: home-cluster
spec:
  groups:
    - name: critical
      rules:
        - alert: NodeDown
          labels:
            triage: "true"
            severity: critical
```

The value is matched literally: `triage="True"`, `triage="yes"`, or an absent
label are all dropped. This is deliberate — a typo on the rule side is what
the backstop is for, and the cumulative drop log line is how you notice it.

## Deploying

Images are published to `ghcr.io/misospace/alert-triage` on tag push. Point an
Alertmanager webhook receiver at `/webhook` and give the pod a ServiceAccount
with the RBAC below.

### Securing the webhook

Set `WEBHOOK_TOKEN` and have Alertmanager send it. `AlertmanagerConfig` cannot
set arbitrary headers on a webhook receiver, so use `httpConfig.authorization`,
which sends `Authorization: Bearer <token>`; `X-Webhook-Token` is accepted too
and is easier to send by hand.

```yaml
- name: triage
  webhookConfigs:
    - url: http://alert-triage.observability.svc.cluster.local:8080/webhook
      sendResolved: false
      httpConfig:
        authorization:
          credentials:
            name: alert-triage-secret
            key: WEBHOOK_TOKEN
```

Leaving `WEBHOOK_TOKEN` unset accepts every request and logs a warning once, so
that a new image cannot silently reject alerts before the receiver has the
secret. Set the receiver up first, then the token.

A token is not a perimeter on its own: anything that can reach the pod can spend
model budget and post to the digest channel. Pair it with a NetworkPolicy that
admits only Alertmanager to port 8080.

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
