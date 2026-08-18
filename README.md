# Reachset

Reachset ingests identity, credential, grant, and activity data from multiple
SaaS apps, normalizes it into one canonical Postgres schema, and computes the
**effective reachability set** of every identity: which resources each
principal can actually reach, with which capability, via which derivation
path. The focus is non-human identities — service accounts, OAuth apps, AI
agents — because their granted scopes badly understate what they can touch.

An agent holding `repo` on a GitHub org, or a Vault token bound to a broad
policy, reaches far more than its scope string suggests, because access flows
through delegation chains: credential → scope → role → resource. Nobody
enumerates those chains by hand across a dozen apps, so the blast radius of a
compromised integration is unknown at exactly the moment it matters. Reachset
computes the chains explicitly, keeps them recomputed, and can explain every
edge it claims.

## Architecture

```
  ┌─────────────┐   ┌─────────────┐   ┌──────────────┐
  │ Connectors  │──▶│ Normalizer  │──▶│  Postgres    │
  │ (transport  │   │ (extractors │   │  canonical   │
  │  + extract) │   │  + linker)  │   │  schema      │
  └─────────────┘   └─────────────┘   └──────┬───────┘
        │                                    │
   Redis queue                       Reachability engine
   + watermarks                      (recursive CTE)
        │                                    │
   Worker pool                        ┌──────▼───────┐
   (docker-compose)                   │  Detections  │
                                      └──────┬───────┘
                                             │
                                      FastAPI  +  MCP server
                                             │
                              Analyst → Adversary → Adjudicator
```

Every connector splits into a **transport** (does I/O; real HTTP, committed
fixtures, or seeded chaos injection) and an **extractor** (pure functions from
API JSON to canonical records). That split is why the whole pipeline is
testable offline, and why the chaos suite can prove no-loss/no-duplicate
behavior under 429 storms, connection resets, truncated bodies, and pagination
pathologies. The reasoning behind the bigger decisions — including why
reachability is a recursive CTE in Postgres and not a graph database — is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quickstart

Needs Docker, `uv`, and Python 3.12.

```
make install    # uv sync
make up         # postgres + redis + vault (dev mode) via docker-compose
make migrate    # alembic upgrade head
make test       # full suite incl. live-Vault integration tests
make bench      # writes measured numbers to bench/results.json
make seed       # small synthetic tenant for poking around
```

`make test` points the suite at the compose stack; without those env vars the
suite falls back to testcontainers. CI runs the same tests against service
containers, including a real `vault server -dev`.

## A worked example

Why can `jortega`, a GitHub user, read a Vault production secret he has no
Vault grant for? This is real output from the pipeline running over the
committed GitHub fixtures plus a Vault entity — computed, not drawn:

```json
{
  "principal": {
    "app": "github",
    "external_id": "user:502",
    "display_name": "Julián Ortega"
  },
  "resource": "secret/data/prod/payments",
  "capability": "read",
  "confidence": 0.95,
  "path": [
    {
      "step": "identity_link",
      "method": "email_exact",
      "from": "user:502",
      "to": "entity-jortega",
      "confidence": 0.95
    },
    {
      "step": "grant",
      "principal": "entity-jortega",
      "scope": "policy:payments-ro",
      "selector": "secret/data/prod/*",
      "resource": "secret/data/prod/payments",
      "capability": "read"
    }
  ]
}
```

His GitHub profile email is `j.ortega+gh@acme.io`; his Vault entity's is
`j.ortega@acme.io`. Email normalization links the two accounts
(`email_exact`, 0.95), the Vault entity holds a policy whose selector matches
the secret, and confidence multiplies along the path. Every edge Reachset
materializes carries a derivation like this one; an edge it can't explain is a
bug by definition. Had the link been a fuzzy name match instead, it would not
have expanded reach at all — fuzzy links only flag for review.

## Benchmarks

Measured 2026-08-18 on an Apple M4 Pro (14 cores, 24 GB RAM), macOS 26.5,
Python 3.12.11, Postgres 16 in Docker, scale profile `medium`:

**Ingest throughput** (50,000 audit events, idempotent upserts, asyncio workers
sharing one connection pool):

| workers | events/sec |
| ---: | ---: |
| 1 | 494 |
| 2 | 876 |
| 4 | 890 |
| 8 | 886 |

Throughput doubles from one to two workers and then flattens: the shared
connection pool and Postgres round-trips are the bottleneck, not Python.

**Reachability** (synthetic tenants, long-tail grant distribution):

| tenant scale | materialized edges | full recompute | incremental (50 origins) | query p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 500 principals / 2k grants | 21,528 | 1.2 s | 6.0 s | 114.7 ms | 124.4 ms | 128.6 ms |
| 1,500 / 6k | 197,914 | 9.3 s | 2.3 s | 27.2 ms | 54.5 ms | 112.2 ms |
| 5,000 / 20k | 2,037,994 | 112.8 s | 14.3 s | 233.7 ms | 280.4 ms | 448.6 ms |

Two honest footnotes. First, incremental recompute only beats full recompute
once tenants get big — at the smallest scale, looping 50 single-origin queries
costs more than one set-based pass. Second, the latency inversion between the
two smaller tenants (114 ms vs 27 ms p50) is planner/statistics noise measured
right after bulk writes, not a real scaling effect; I report what was measured
rather than smoothing it.

Peak process RSS during the run was ~4.9 GB (dominated by holding the 2M-edge
result set in Python during materialization — streaming that insert is an
obvious next optimization).

Numbers are measured, not targeted. Every figure above is reproducible with
`make bench` (`BENCH_SCALE=medium` for this table) and comes from
[bench/results.json](bench/results.json), which records the machine and the
scale that actually ran. The PRD's target scales go up to 10M edges; this
table is the scale I have actually run on this machine, stated as such.

## Detections

Six rules over the graph, each shipping with a positive and a negative test
fixture, each emitting the exact rows and derivation paths that triggered it:

1. **Dormant privileged NHI** — service/agent with write/admin/delete reach,
   idle > 90 days against its own recorded history.
2. **Orphaned grant** — the granting principal is deactivated or deleted.
3. **Scope expansion** — a grant's capability set widened between syncs with no
   corroborating event in the app's own audit stream.
4. **Cross-app concentration** — one NHI reaching sensitivity ≥ 2 resources in
   ≥ 3 apps.
5. **Shadow AI integration** — app principal matching a declarative known-AI-
   vendor list, holding read reach on sensitivity ≥ 2 resources.
6. **Off-hours bulk read** — read volume above the principal's own 28-day
   baseline, outside its own historical active hours.

## Agent triage

MCP tools return conclusions, not rows: `assess_principal` gives a reach
summary, top risks, and bounded evidence references, never a 4,000-edge dump.
On top of that sits a three-role triage pipeline — an Analyst drafts the case,
an Adversary hunts for benign explanations (cron-shaped activity, declared
migration windows, by-design accounts, audit-corroborated changes), and an
Adjudicator decides from structured fields only.

Evaluated over 48 labeled synthetic incidents (24 real, 24 plausible-benign:
nightly batch jobs, break-glass accounts, declared migrations, ticketed
changes), against the rules-only baseline of "every finding is an alert":

| | precision | recall | false positives | escalated to review | mean cost (units) |
| --- | ---: | ---: | ---: | ---: | ---: |
| rules-only baseline | 0.50 | 1.00 | 24 | 0 | 0 |
| triage pipeline | 0.80 | 1.00 | 6 | 6 | 5.27 |

The pipeline dismisses 18 of 24 benign incidents outright and escalates the
remaining 6 to human review (counted against precision, since a review still
reaches a human), at zero lost recall. Full numbers, including the scoring
rules, are in [bench/triage_eval.json](bench/triage_eval.json).

The roles are deterministic heuristics in v0 (no model API is called anywhere
in this repo), so "cost" counts simulated tool invocations rather than tokens.
The interfaces are shaped for a model-backed Analyst/Adversary to drop in
later; the Adjudicator boundary — numbers and enums in, no app-originated text
— is what makes the next paragraph hold either way.

**Prompt-injection defense.** Audit logs carry attacker-controlled strings
(app display names, repo descriptions, Vault path names) that reach agent
context. Every such string crosses the boundary only as a quoted, provenance-
tagged value; tools are never invoked on the basis of log-derived text; and
the Adjudicator never sees raw strings at all. A red-team corpus of 26
poisoned records (instruction injection, fake system messages, base64
payloads, spoofed tool calls, "a previous session authorized this") is in
[tests/redteam/](tests/redteam/); the suite asserts **0/26 change a verdict**,
in both directions — an injection can't talk an alert down, and it can't talk
a benign dismissal up. Suspected injections only ever escalate to human
review.

## Verification status

Being precise about what has actually been verified against what:

- **Verified end-to-end against a live service:** the Vault connector, and the
  pipeline behind it (ingest → normalize → reach → detections → API). The
  integration tests arrange a real `vault server -dev` — policies, tokens, KV
  writes, a file audit device — and run the actual connector against it, in CI
  on every push.
- **Verified against fixtures only:** the GitHub connector. Fixtures are
  hand-authored from the public REST API documentation, not captured from a
  live tenant; no live GitHub tenant has ever been touched. Everything the
  fixtures can't prove (auth modes for installation endpoints, Link-header
  pagination, exact field shapes) is listed as unverified assumptions in
  [NOTES.md](NOTES.md).
- **Not yet verified:** Google Workspace and Salesforce connectors (not
  started); GitHub live mode (Link-header cursor adapter, app JWT auth);
  Vault `+` segment-wildcard fidelity; audit ingestion from the worker (the
  worker syncs Vault but does not read the audit file; only the direct
  connector path does).

[NOTES.md](NOTES.md) is the full running list of unconfirmed assumptions, kept
as a checklist so they can be turned into verified facts or fixes.

## Repository layout

```
src/reachset/
  connectors/    transport + extractor per app (vault/, github/)
  ingest/        idempotent upserts, watermarks, rate limiting, worker, DLQ
  linking/       identity correlation + labeled synthetic dataset
  reach/         recursive-CTE engine, naive BFS reference, selector language
  detections/    six rules + declarative registries (scopes, AI vendors)
  mcp/           MCP tools + server wrapper
  triage/        Analyst/Adversary/Adjudicator, sanitization, eval harness
  synth/         synthetic tenant generator
bench/           harness + measured results (results.json, identity_linking.json,
                 triage_eval.json)
tests/           unit, integration (incl. live Vault), chaos, redteam
```

## Engineering notes

Python 3.12, `uv`, FastAPI, Postgres 16, Redis 7, SQLAlchemy 2 (asyncpg),
Alembic, structlog. `ruff` and `mypy --strict` clean; coverage floor 85%
enforced in CI; `gitleaks` runs in the pre-commit hook and in CI. The single
most important test in the repo is the Hypothesis property test asserting the
reachability CTE agrees exactly with a naive Python BFS on random graphs — see
[tests/integration/test_reach_property.py](tests/integration/test_reach_property.py).
