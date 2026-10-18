# AGENTS.md

Operating notes for anyone — human or agent — changing this service.

## What it is

A webhook receiver that turns a burst of Alertmanager alerts into a small number
of explained incidents. Alertmanager already groups identical alerts by name;
this exists to recognise that several *different* alerts are one event, attach
evidence from the cluster, and say what happened in a few sentences.

It runs unattended. Correctness matters more than cleverness, and a wrong
confident sentence is worse than a vague one.

## Commands

```sh
go build ./...          # must build
gofmt -l .              # must print nothing
go vet ./...            # must pass
go test ./...           # must pass
go test -race ./...     # what CI runs
```

CI runs fmt, vet and `go test -race`, plus a Docker build. A tag `v*` publishes
a multi-arch image to `ghcr.io/misospace/alert-triage`.

## Layout

| File | Responsibility |
| --- | --- |
| `correlate.go` | Pure grouping. No I/O. The riskiest logic, so it is the most testable. |
| `enrich.go` | Read-only Kubernetes client and evidence gathering. |
| `history.go` | JSONL record of every group reported, for "seen N times". |
| `report.go` | Prompt, model call, evidence rendering, Discord delivery. |
| `main.go` | Config, HTTP server, windowing buffer, pipeline wiring. |

Pipeline: ingest → window → correlate → enrich → history → narrate → deliver.
Enrichment and narration are both optional; if the API server or the model is
unreachable the digest still ships with whatever is available. Keep it that way.

## Pipeline invariants

The detailed invariant contract and focused review checklist live in
[.agents/skills/alert-pipeline-invariants/SKILL.md](.agents/skills/alert-pipeline-invariants/SKILL.md).
Load it before changing correlation, enrichment, history, reporting, webhook
authentication, or triage filtering. It is also the review checklist for those
areas.

## Testing against real data

Unit tests cover correlation and rendering. For anything touching evidence or the
prompt, replay real alerts — synthetic fixtures lack the variety that exposes
grouping bugs.

```sh
# Capture what is actually firing
kubectl exec -n observability alertmanager-... -c alertmanager -- \
  wget -qO- 'http://localhost:9093/api/v2/alerts?active=true' > alerts.json

# Run locally with a sink instead of Discord, short window
DISCORD_WEBHOOK_URL=http://127.0.0.1:9911/ FLUSH_DELAY=2s LISTEN_ADDR=:9912 ./alert-triage
curl -XPOST localhost:9912/webhook -d @payload.json
```

`GET /recent` returns the last 20 digests with the evidence the model was given
and what it wrote. That is the fastest way to judge a prompt change, and it works
without access to wherever digests are delivered.

## Conventions

- This repository is public. Use neutral placeholders in tests and docs — no real
  hostnames, internal domains or private service names.
- Comments explain constraints and the reason a thing is not the obvious thing.
  They do not narrate what the next line does.
- Deployment bumps live in a separate GitOps repository and are raised by
  Renovate. Do not edit deployment manifests from here.

## Filing issues for the autonomous loop

Issues here are picked up by an autonomous coding loop (dispatch → foreman), and two
parts of the body feed deterministic reviewer rails. Agents filing issues in this repo
must include both.

**1. State the ask in one imperative sentence.** The reviewer quotes it verbatim to
prove it actually read the issue. If it can only paraphrase, its GO is demoted to NO-GO
unless the rail below vouches — costing a revision cycle and an escalation review.

**2. Name the concrete file paths the fix is expected to touch** (backticks are fine).
The scope-overlap rail vouches for a diff that touches a named file, and that vouch is
what survives a paraphrased ask.

Name only paths you are confident about. An issue that names files the diff does *not*
touch is read as scope drift and also gets the change rejected — so when unsure, name
none rather than guessing.
