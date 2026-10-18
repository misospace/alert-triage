---
name: alert-pipeline-invariants
description: Review or change alert correlation, multi-cluster enrichment, evidence rendering, alert history, webhook authentication, and triage filtering in alert-triage.
---

## Invariants

**Multi-cluster support.** The service can triage alerts from multiple clusters
in a single instance. Alerts are partitioned by their `cluster` label before
correlation so that incidents from different clusters never fuse together
(namespace names collide across clusters). Each group is enriched against its
own cluster's API server; if no client is available for the group's cluster,
enrichment reports "cluster state unavailable" rather than producing wrong
evidence from a foreign API server.

The cluster identity comes from `CLUSTER`, and **the mismatch check skips only
when both sides are known and disagree**. An unset `CLUSTER` enriches
everything, which is correct for one instance per cluster and is the same
fail-open rule `WEBHOOK_TOKEN` and `TRIAGE_LABEL` follow. Failing closed here
was a real bug: 0.1.8 compared the group's cluster against a client cluster
that was never assigned, so every group looked foreign, enrichment was skipped
on every instance, and 77 digests shipped narrating alert text alone while
asserting the cluster was healthy. Nothing caught it because a confident story
told over no evidence reads exactly like a good one. Anything that gates
evidence on configuration must fail open and say so.

The digest names the cluster it came from
so operators can distinguish incidents when multiple clusters share one Discord
channel. Originally the service was deliberately cluster-local: a second
instance needed no shared credentials or state. That invariant was replaced
because running one instance per cluster doubles what has to be watched and
there are no metrics yet (#17), so a dead instance looks like a quiet cluster.

**Stdlib plus one YAML library.** No `client-go`, no SDKs. The Kubernetes client is plain HTTP
against the apiserver using the in-cluster ServiceAccount token; four GETs do
not justify the dependency tree (if you need a new resource, add a struct and a
path, not a library).

**YAML dependency carve-out:** `gopkg.in/yaml.v3` is the sole allowed non-stdlib import. It exists so `propose.go` can round-trip a Kubernetes manifest before and after an edit instead of replacing by regex — a regex against a three-container manifest silently rewrites the wrong container and reconciles as if nothing happened. The dep is direct in `go.mod` and pinned in `go.sum`; do not add a second YAML library, and do not import its transitive tree. Anything richer than parse/encode must stay in stdlib.

**`Signature.Scope` must bound itself to its trigger.** A scope that ignores the
triggering alert and accepts everything swallows an entire window. This was a
real bug: the `node` signature matched the word "node" anywhere — catching
`KubePodNotReady` and `CephNodeDiskspaceWarning` — and its scope returned true,
fusing 20 unrelated alerts into 2 groups. Triggers must be specific and scopes
must key on something concrete, usually a label. `TestNoSignatureSwallowsUnrelatedAlerts`
guards this.

**A signature matching only its own trigger forms no group.** A one-alert "root
cause" explains nothing; leave the alert for a later rule.

**Never delete evidence to reduce noise.** Discord has no way to fold content, so
volume was once managed by dropping data. Collapse, aggregate or count instead:
repeated events aggregate with a count, and cluster-wide Flux reconciles are
dropped because a routine sync transitions everything at once — that is noise,
not signal, which is different from useful data being inconvenient.

**Ambient context is fenced off.** Cluster-wide findings gathered when an alert
names no namespace, and namespace warning events outside the resolved alert
subject graph, go in `Enrichment.Ambient`, render under `BACKGROUND`, and never
reach Discord. They exist so the model can rule things out. Without the fence it
offers coincidences as causes.

**Absence is a finding.** Empty sections render as explicit negatives ("all nodes
Ready"), never as silence. Silence reads to a model as missing data and produces
hedging about not having checked the cluster.

**Alert labels go to the model.** Alert names use the vocabulary of whatever
emitted them. Without labels the model reads "deployment" as a Kubernetes
Deployment when it meant an upstream routing target.

**Alert text is quoted, not trusted.** Annotations, labels, event messages and
ambient findings are written by whoever emitted them, so they are fenced between
`untrustedBegin` and `untrustedEnd` and passed through `untrusted()`, which
flattens line structure and breaks up dash runs. The system prompt names that
fence as a data boundary. Anything derived from an alert or from an object's own
message belongs inside it; readings this service makes itself — node conditions,
pod phases, Flux states, and the explicit negatives — stay outside, because
fencing our own findings would tell the model to distrust them.

**Webhook auth fails open when unconfigured.** An unset `WEBHOOK_TOKEN` accepts
every request and warns once. Requiring it unconditionally would mean a new
image silently 401s every alert until the receiver carries the secret, and
silent triage failure is indistinguishable from a quiet week. `AlertmanagerConfig`
cannot set arbitrary headers, so the token arrives via `httpConfig.authorization`
as a bearer token.

**Triage is opt-in by label and defaults to failing open.** The webhook drops
any alert whose `<TRIAGE_LABEL>` label is not exactly `"true"` *only when*
`TRIAGE_LABEL` is set; an empty value is a no-op and the service triages
everything, matching the `WEBHOOK_TOKEN` convention. Reasoning: no cluster
labels its PrometheusRules today, so deploying with the filter on would drop
every alert — silent failure indistinguishable from a quiet week. The
rollout ordering is to ship the code, label the rules in the GitOps repo, and
only then set `TRIAGE_LABEL`. The web counter `Config.DroppedByLabel` is
logged on every batch that drops anything, so a label-rule typo is visible
in `journalctl` before metrics land (#17). The primary contract lives in the
Alertmanager route; the service-side filter is a backstop for misrouted
alerts and the deployment must hold both.

## Focused review procedure

- Trace the whole ingest → window → correlate → enrich → history → narrate → deliver path for behavioral changes. Verify optional enrichment/model failures degrade gracefully rather than suppressing the digest.
- For correlation changes, test both intended grouping and unrelated-alert separation. A signature must be specific, its scope must honor the trigger, and a single matching alert must not form a group.
- For evidence changes, distinguish direct subject evidence from ambient context, preserve explicit negative findings, keep cluster identity attached to each group, and keep alert-supplied text fenced as untrusted data.
- For auth or triage-filter changes, verify the documented fail-open defaults and rollout order; do not introduce a configuration that silently drops every alert.
- Add or update tests for the failure path and replay real captured alerts when prompt, correlation, or evidence behavior changes. Report what could not be verified rather than claiming healthy behavior from missing evidence.
