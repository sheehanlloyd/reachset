# Reachset

Reachset ingests identity, credential, grant, and activity data from multiple
SaaS apps, normalizes it into one canonical Postgres schema, and computes the
**effective reachability set** of every identity: which resources each
principal can actually reach, with which capability, via which derivation
path. The focus is non-human identities: service accounts, OAuth apps, AI
agents. Their granted scopes badly understate what they can touch.

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
   Worker pool                 ┌──────────────┴──────────────┐
   (docker-compose)            │                             │
                        ┌──────▼───────┐            ┌────────▼────────┐
                        │  Detections  │            │    Analyses     │
                        │   (6 rules)  │            │  blast radius,  │
                        └──────┬───────┘            │ what-if revoke, │
                               │                    │ least privilege,│
                               │                    │  reach drift,   │
                               │                    │  invariants     │
                               │                    └────────┬────────┘
                               └─────────────┬───────────────┘
                                             │
                       CLI   ·   FastAPI (+ /metrics, /readyz)   ·   MCP
                                             │
                              Analyst → Adversary → Adjudicator
```

Every connector splits into a **transport** (does I/O; real HTTP, committed
fixtures, or seeded chaos injection) and an **extractor** (pure functions from
API JSON to canonical records). That split is why the whole pipeline is
testable offline, and why the chaos suite can prove no-loss/no-duplicate
behavior under 429 storms, connection resets, truncated bodies, and pagination
pathologies. The reasoning behind the bigger decisions, including why
reachability is a recursive CTE in Postgres and not a graph database, is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quickstart

Needs Docker, `uv`, and Python 3.12.

```
make install    # uv sync
make up         # postgres + redis + vault (dev mode) via docker-compose
make migrate    # alembic upgrade head
make demo       # load both fixture connectors and show what they surface
make test       # full suite incl. live-Vault integration tests
make bench      # writes measured numbers to bench/results.json
make seed       # larger synthetic tenant for poking around
```

`make demo` is the thirty-second version: it ingests the committed Vault and
GitHub fixtures into a `demo` tenant, prints the blast radius of the Vault
admin token, and runs every detection over the result. On the fixture data that
turns up a shadow-AI integration reading production repositories and three
dormant privileged non-human identities.

`make test` points the suite at the compose stack; without those env vars the
suite falls back to testcontainers. CI runs the same tests against service
containers, including a real `vault server -dev`.

Installing the package puts a `reachset` command on your path. That's what
`make demo` drives, and there's more of it than the demo shows:

```
reachset sync             --tenant T --app vault --fixtures DIR
reachset reach            --tenant T --principal EXT_ID [--format table|mermaid|dot]
reachset explain          --tenant T --principal EXT_ID --resource PATH --capability read [--format table|mermaid|dot]
reachset blast-radius     --tenant T [--principal EXT_ID | --credential EXT_ID]
reachset simulate-revoke  --tenant T --grant UUID [--grant UUID ...]
reachset recommend        --tenant T [--window DAYS]
reachset snapshot         --tenant T --label NAME | --list
reachset diff             --tenant T --from NAME --to NAME
reachset detect           --tenant T
reachset check-invariants --tenant T --config rules.toml [--sarif PATH] [--fail-on-violation]
```

Every subcommand takes `--json` for machine-readable output. `detect
--fail-on-findings`, `diff --fail-on-change`, and `check-invariants
--fail-on-violation` exit `2` instead of `0`, which is what makes them usable
as a CI gate. `reach --format mermaid` and `explain --format mermaid` render
the fan-out or the single derivation path as a graph instead of a table. Paste
the output straight into a GitHub markdown block and it renders inline.

## A worked example

Why can `jortega`, a GitHub user, read a Vault production secret he has no
Vault grant for? This is real, computed output (not drawn) from
`test_cross_app_reach_via_deterministic_link` in
[tests/integration/test_github_fixtures.py](tests/integration/test_github_fixtures.py),
run over the committed GitHub fixtures plus one Vault entity seeded directly
in the test. That entity isn't in `tests/fixtures/vault/`: the Vault connector
only reads token-accessor lookups today, never entity metadata, so no
committed Vault fixture carries an entity email at all (tracked in
[NOTES.md](NOTES.md)). `make demo`'s two-command sync won't reproduce this
example on its own for that reason; run the test above to see it live.

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
have expanded reach at all; fuzzy links only flag for review.

## Answering the three questions people actually ask

The PRD names three users. Each one gets a query rather than a data dump.

**"Credential X is compromised: what is reachable through it?"** Blast radius
ranks by capability first and sensitivity second, because being able to delete
a sensitivity-2 resource is worse than reading a sensitivity-3 one. Ask it
about a principal, or about one specific credential. `--credential` counts
only the edges whose derivation actually runs through that credential's
grants, since holding one Vault token doesn't hand you the reach of every
other token its owner happens to hold:

```
$ reachset blast-radius --tenant demo --principal token:acc-null-display --limit 4
token:acc-null-display reaches 6 resource(s) across 1 app(s) (vault); 4 of them
are sensitive and writable.

SCORE  RESOURCE                   APP    SENS  CAPABILITIES
-----  -------------------------  -----  ----  -----------------------
20     auth/approle               vault  3     admin,delete,read,write
20     auth/token                 vault  3     admin,delete,read,write
20     secret/data/prod/api-keys  vault  3     admin,delete,read,write
20     secret/data/prod/db        vault  3     admin,delete,read,write

(+2 more resources; raise --limit to see them)
```

That token holds Vault's `admin-sudo` policy, so it reaches the auth mounts as
well as the secrets, and it reaches *only* Vault, because a grant never
escapes the app that issued it.

The inverse question, "if I revoke this, what actually breaks?", is the same
engine run with those grants suppressed and the results diffed. It is a
read-only query; nothing is written and there is no transaction to remember to
roll back. The interesting part of the output is usually the collateral: which
*other* principals were quietly borrowing that grant through a delegation
chain, and which resources stay reachable anyway by a second path.

**"Which non-human identities are over-granted?"** Least-privilege analysis
joins what a principal can reach against what it actually touched over a
window, and proposes a narrowed selector derived from the longest common
prefix of the paths it really used:

```
$ reachset recommend --tenant demo
SEVERITY  PRINCIPAL                GRANTED  USED  UNUSED CAPS              SUGGESTED SELECTOR
--------  -----------------------  -------  ----  -----------------------  ------------------
high      token:acc-null-display         6     0  admin,delete,read,write  (revoke)
high      ci-deployer                    2     0  read,write               (revoke)
high      legacy-deploy@prod             1     0  read,write               (revoke)
medium    summarize-ai                   4     0  read                     (revoke)
```

A principal that has touched nothing in the window gets `(revoke)` rather than
a narrower scope, because there is nothing to justify keeping. Nothing here
revokes anything on its own; Reachset reports, it doesn't remediate.

**"What changed since Friday?"** A detection tells you what is wrong now,
which means a nightly report re-lists the same 400 known edges forever.
Snapshots capture a tenant's reach under a label; the diff is a `FULL OUTER
JOIN` between two of them, reporting added, removed, and confidence-changed
edges. Snapshot rows denormalize paths and external ids rather than
referencing live rows, so a diff still reads correctly after the upstream
principal has been deleted, which is exactly when you most want to read it.

```
$ reachset diff --tenant demo --from before --to after --fail-on-change
4 edge(s) added (3 on sensitive resources), 0 removed, 0 changed between
'before' and 'after'.

   PRINCIPAL        RESOURCE           CAP    SENS
-  ---------------  -----------------  -----  ----
+  installation:42  acme/payments-api  write  3
+  installation:42  acme/prod-infra    write  3
+  installation:42  acme/data-tools    write  2
+  installation:42  acme/website       write  1

$ echo $?
2
```

Installation 42 is `summarize-ai`, the AI integration in the fixtures. Between
the two snapshots its `contents` permission went from `read` to `write`, and
the diff shows precisely what that bought it: write access to every repository
in the org, three of them sensitive. That is the report worth waking up to,
and the non-zero exit is what lets a nightly job page someone about it.

**"Has anyone violated a policy we've already decided on?"** A detection
flags a pattern for a human to judge; an invariant is a rule someone already
signed off on: no triage step, a match is a violation. `check-invariants`
reads a declarative TOML file ([examples/invariants.toml](examples/invariants.toml))
and evaluates it against materialized reach:

```
$ reachset check-invariants --tenant demo --config examples/invariants.toml --fail-on-violation
SEVERITY  RULE                         DETAIL
--------  ---------------------------  --------------------------------------------------------------
error     no-ai-vendor-sensitive-read  summarize-ai holds 'read' on 3 resource(s) at sensitivity >= 2

$ echo $?
2
```

Same `summarize-ai` integration, same underlying fact as the diff above, but
framed as a standing policy rather than a point-in-time change. This fires
every run until the grant is actually narrowed, which is the point. `--sarif
PATH` writes the same violations as SARIF 2.1.0, ready for GitHub code
scanning to ingest as a check run.

## Operations

`/healthz` is liveness and deliberately touches nothing. A liveness probe
that queried the database would restart the API every time Postgres hiccups.
`/readyz` is readiness: it actually exercises the dependency, returns `503` so
a load balancer drains the instance instead of routing into errors, and names
the check that failed rather than saying only "not ready".

`/metrics` serves Prometheus text: ingest counts and durations, dead letters,
materialized edges per tenant, recompute time by mode, findings by rule and
severity, and HTTP latency. Request metrics are labeled with the *route
template*, not the path, so a tenant with 10,000 principals produces one time
series instead of 10,000, which is the cardinality mistake that eventually
takes a Prometheus instance down. The registry itself is hand-written in
[observability.py](src/reachset/observability.py): counters, gauges, and
cumulative histograms with labels, deliberately nothing else. No exemplars, no
native histograms, no multiprocess collection. Taking `prometheus_client`
instead would have been perfectly defensible; I wrote it because the
exposition format is small enough to own and I wanted the label and bucket
semantics under test. The call sites are shaped so the library drops in
unchanged the day any of those missing features matter.

## Benchmarks

Measured 2026-08-28 on an Apple M4 Pro (14 cores, 24 GB RAM),
macOS 26.5, Python 3.12.11, Postgres 16 in Docker, scale profile `medium`,
against a freshly created database (`docker compose down -v && make up` first).
This is a re-run after the exact/glob selector split and streaming
materialization landed (below); the numbers moved enough from the previous
table that it's worth saying so rather than quietly swapping them in.

**Ingest throughput** (50,000 audit events, idempotent upserts, asyncio workers
sharing one connection pool):

| workers | events/sec |
| ---: | ---: |
| 1 | 636 |
| 2 | 894 |
| 4 | 892 |
| 8 | 885 |

Throughput climbs from one worker to two and then flattens. The bottleneck is
Postgres round-trips and the shared pool, not Python, so adding workers past
that buys nothing. An earlier run on a database that had absorbed a full test
session showed eight workers collapsing to a third of that; it did not
reproduce on a clean database, so I am recording it as contention rather than
as a scaling property.

**Reachability** (synthetic tenants, long-tail grant distribution, 300
single-origin queries per row):

| tenant scale | materialized edges | full recompute | incremental (50 origins) | p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 500 / 2,000 | 26,324 | 1.0 s | 0.5 s | 3 ms | 9 ms | 12 ms |
| 1,500 / 6,000 | 198,998 | 7.0 s | 0.7 s | 4 ms | 15 ms | 59 ms |
| 5,000 / 20,000 | 2,069,138 | 94.4 s | 2.7 s | 6 ms | 26 ms | 266 ms |

Peak process RSS was **126.5 MB**, down from 4.3 GB in the previous run of
this same benchmark. That drop is `materialize()` streaming the CTE's result
through a server-side cursor in bounded chunks instead of buffering the whole
2M-row result set in Python first. That's the fix flagged as "obvious next" in
the previous version of this table, now landed
(`reach/engine.py::_stream_materialize`).

The largest full-recompute figure also dropped, from 154.8 s to 94.4 s (about
39%), and single-origin p50/p95 both improved at every scale, because the
exact/glob selector split (below) reduces the cost of the reachability query
itself, not just its memory profile. p99 at the largest scale is noisy (266 ms
here vs. 543 ms previously; both are one-run numbers, not averages, so read
the overall direction rather than the single figure).

Two things in that table are worth reading carefully rather than skimming.
Incremental recompute only beats a full pass once tenants get large: at the
smallest scale, looping 50 single-origin queries costs more than one set-based
sweep, which is why the CLI doesn't quietly "optimize" small tenants into the
incremental path. And the largest row has moved twice now during this
project's life. Before the `hops` CTE was marked `MATERIALIZED`, the same
benchmark reported 341 s and a p50 of 1,529 ms; after that fix it was 154.8 s;
after streaming materialization and the exact/glob selector split (which
eliminates the impersonation arm's cross join for every selector that isn't an
actual glob, see [NOTES.md](NOTES.md), "Reach engine performance") it's
94.4 s. Reading the query plan was worth more than any amount of guessing
about it each time.

Numbers are measured, not targeted. Every figure above is reproducible with
`BENCH_SCALE=medium make bench` and comes from
[bench/results.json](bench/results.json), which records the machine and the
scale that actually ran. The PRD's target scales go up to 10M edges; this table
is the scale I have actually run on this machine, stated as such.

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
On top of that sits a three-role triage pipeline: an Analyst drafts the case,
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
later; the Adjudicator boundary (numbers and enums in, no app-originated text)
is what makes the next paragraph hold either way.

**Prompt-injection defense.** Audit logs carry attacker-controlled strings
(app display names, repo descriptions, Vault path names) that reach agent
context. Every such string crosses the boundary only as a quoted, provenance-
tagged value; tools are never invoked on the basis of log-derived text; and
the Adjudicator never sees raw strings at all. A red-team corpus of 26
poisoned records (instruction injection, fake system messages, base64
payloads, spoofed tool calls, "a previous session authorized this") is in
[tests/redteam/](tests/redteam/); the suite asserts **0/26 change a verdict**,
in both directions: an injection can't talk an alert down, and it can't talk a
benign dismissal up. Suspected injections only ever escalate to human review.

## Verification status

Being precise about what has actually been verified against what:

- **Verified end-to-end against a live service:** the Vault connector, and the
  pipeline behind it (ingest → normalize → reach → detections → API). The
  integration tests arrange a real `vault server -dev` (policies, tokens, KV
  writes, a file audit device) and run the actual connector against it, in CI
  on every push.
- **Verified against fixtures only:** the GitHub connector. Fixtures are
  hand-authored from the public REST API documentation, not captured from a
  live tenant; no live GitHub tenant has ever been touched. Everything the
  fixtures can't prove (auth modes for installation endpoints, Link-header
  pagination, exact field shapes) is listed as unverified assumptions in
  [NOTES.md](NOTES.md).
- **Verified locally, against real infrastructure but not a real tenant:** the
  HTTP transport (driven against a throwaway localhost server that produces
  429s with `Retry-After`, HTTP-date `Retry-After`, 5xx, connections dropped
  mid-body, and timeouts, plus one live call against the Vault dev server); the
  CLI, the analyses, and the operational endpoints, all exercised against a real
  Postgres; the Redis-backed distributed rate limiter, exercised against a real
  Redis with genuinely concurrent workers and real wall-clock timing (not a
  fake clock), because the bug it fixes only shows up under real concurrency.
- **Not yet verified:** Google Workspace and Salesforce connectors (not
  started); GitHub live mode (Link-header cursor adapter, app JWT auth);
  audit ingestion from the worker (the worker syncs Vault but does not read
  the audit file; only the direct connector path does); metrics under more
  than one API replica (they are per-process and in-memory, so each replica
  must be scraped separately); `RedisBucketRegistry` wired into the actual
  worker sync path (`StreamSyncer`, the class it plugs into, isn't called
  anywhere in the worker yet; see NOTES.md).

[NOTES.md](NOTES.md) is the full running list of unconfirmed assumptions, kept
as a checklist so they can be turned into verified facts or fixes.

## Repository layout

```
src/reachset/
  connectors/    transport + extractor per app (vault/, github/)
  ingest/        idempotent upserts, watermarks, rate limiting, worker, DLQ
  linking/       identity correlation + labeled synthetic dataset
  reach/         recursive-CTE engine, naive BFS reference, selector language,
                 Mermaid/DOT graph rendering
  analysis/      blast radius, what-if revocation, least privilege, snapshots,
                 policy-as-code invariants (TOML rules, SARIF output)
  detections/    six rules + declarative registries (scopes, AI vendors)
  mcp/           MCP tools + server wrapper
  triage/        Analyst/Adversary/Adjudicator, sanitization, eval harness
  synth/         synthetic tenant generator
  cli.py         the `reachset` command
  observability.py  metrics registry + Prometheus exposition
bench/           harness + measured results (results.json, identity_linking.json,
                 triage_eval.json)
tests/           unit, integration (incl. live Vault), chaos, redteam
```

## Engineering notes

Python 3.12, `uv`, FastAPI, Postgres 16, Redis 7, SQLAlchemy 2 (asyncpg),
Alembic, structlog. `ruff` and `mypy --strict` clean, `gitleaks` in both the
pre-commit hook and CI.

413 tests cover 100% of lines and branches in `src/` on a typical run. The CI
gate is set at 99% rather than 100% deliberately: the reachability property test
generates a fresh random graph set every run, and about one run in ten leaves a
single data-dependent branch unexercised. Pinning the seed would make the gate
exact and would also stop the test exploring new graphs, which is the whole
reason it exists, so the randomness stays and the floor gives way by a point.

Seven `# pragma: no cover` markers exist: four on `Protocol` class/method
bodies that structurally never execute (`Transport`, `Detection`, and the two
methods of the rate limiter's `Bucket`/`BucketSource` protocols), and three on
lines that are genuinely untestable rather than merely inconvenient:
interactive-only `KeyboardInterrupt` handling, the `if __name__ ==
"__main__"` entry point, and a FastAPI dependency the test fixture always
overrides. (An earlier draft of this file claimed "three, all on Protocol
bodies." That was untrue even before this round of changes, since the three
non-Protocol ones already existed; a grep-and-count pass during a polish
session found the discrepancy.) Everything else is covered by a test rather
than excused.

Coverage is configured with `concurrency = ["thread", "greenlet"]`, without
which every endpoint that resolves a database session through a FastAPI
dependency reports as uncovered despite being exercised. That measurement bug
was understating the project by about five points until I chased down why
tested endpoints were showing red.

The single most important test in the repo is the Hypothesis property test
asserting the reachability CTE agrees exactly with a naive Python BFS on
random graphs (see
[tests/integration/test_reach_property.py](tests/integration/test_reach_property.py)).
It has now caught two real bugs: a recursive CTE shape Postgres rejects, and a
`%` escaping error that made selectors containing LIKE metacharacters match
paths they shouldn't. Both times a mutation check confirmed the test fails when
the semantics drift.
