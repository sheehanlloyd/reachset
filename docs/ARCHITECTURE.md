# Architecture

This document explains the three decisions that shape the codebase: the
transport/extractor split, the canonical schema, and doing reachability as a
recursive CTE in Postgres instead of adding a graph database.

## The transport/extractor split

Every connector is two halves that never blur:

- **Transport** — does I/O and nothing else. Three implementations share one
  interface: `HttpTransport` (real HTTP, live mode only), `FixtureTransport`
  (replays committed JSON from `tests/fixtures/<app>/` off a `routes.json`
  manifest), and `ChaosTransport` (wraps any other transport and injects
  faults deterministically from a seed).
- **Extractor** — pure functions from raw API JSON to canonical records. No
  I/O, no clock, no randomness, no globals.

The reason is testability without live tenants. Every parsing decision, every
ugly payload (null display names, deleted principals still referenced by
grants, unicode-and-SQL-looking display names) is exercised offline against
fixtures that look exactly like documented API responses. The transport is the
only part that changes between a test run and a live run, so the pipeline the
tests exercise is byte-for-byte the pipeline production would run.

ChaosTransport is where the interesting guarantees get proven. It injects 429s
with Retry-After, 5xx, connection resets, truncated JSON bodies, empty pages,
repeated cursors, out-of-order pages, and timestamp skew — reproducibly, from
a seed, so a chaos failure is an ordinary red test you can rerun. One design
rule matters: chaos may delay, repeat, or disorder data, but the mock itself
never destroys it. Losing data must always be a pipeline bug the test can
catch, never an artifact of the fault injector.

## Ingest invariants

Two invariants carry all the failure-handling weight:

1. **Idempotent writes.** Every table has an explicit idempotency key
   (principals/resources on `(tenant, app, external_id)`, credentials on
   `(tenant, kind, external_id)`, grants on a content-derived dedupe key,
   events on a payload hash) and every write is `ON CONFLICT` against it.
   Replaying any page, any number of times, cannot create a duplicate row.
2. **Watermarks advance transactionally with their page.** A page upserts and
   its cursor advances in the same commit, or neither happens. A crash or a
   dead-lettered page leaves the cursor pointing at unfetched data.

Given those two, retries become boring: the rate limiter (token bucket per
tenant×app) plus jittered exponential backoff (Retry-After respected as a
floor, five attempts, then a dead letter) can be as aggressive or as lazy as it
likes without correctness consequences. The chaos suite asserts the end state
equals a clean run's end state — same rows, same counts — under every fault
profile.

## The canonical schema

Nine tables, all carrying `tenant_id`: principals, credentials, resources,
grants, events, identity_links, reach_edges (materialized), sync_watermarks,
dead_letters. Two choices worth defending:

**Grants store selectors, not resource foreign keys.** A Vault policy grants
`secret/data/prod/*`, not a list of secrets — the list changes as secrets are
created. Storing the selector keeps the grant faithful to the source system
and moves matching into the reachability computation, where new resources are
picked up on the next materialization without touching grants.

**Scope-to-capability mapping is a versioned table, not code.** Each app has a
declarative table mapping observed scope strings (`sudo`, `repo`,
`contents:write`, `permission:admin`, …) to the five canonical capabilities.
An unrecognized scope raises; there is a test asserting nothing silently
defaults to `read`, because silently understating what a credential can do is
the one failure mode this project exists to prevent.

## Reachability as a recursive CTE

The question "what can this principal actually touch" is transitive: principal
→ grants → selector-matched resources, plus `impersonate` grants that recurse
into the target principal's own grants, plus identity links that carry reach
across apps. That is a graph problem, and the reflex answer is a graph
database. I didn't add one, for three reasons:

1. **The data already lives in Postgres.** The graph is derived — rebuilt from
   grants/resources/links on every sync. Mirroring it into a second store
   means a consistency protocol between two databases for a graph that
   Postgres can traverse in one statement.
2. **The traversal is bounded and shaped like SQL.** Depth is capped, cycles
   are cut with a visited array, and the expensive part is selector matching,
   which is `LIKE` with a computed pattern — something Postgres does fine.
   The fan-out that makes CTEs painful (unbounded social-graph traversals)
   doesn't apply: identity graphs are shallow.
3. **Every edge must be explainable.** The CTE builds `path_json` as it walks:
   every hop (impersonation, identity link, grant) is recorded with its ids
   and confidence. An unexplainable edge is a bug by definition. That
   requirement is easier to enforce in one SQL statement than across a graph
   query language boundary.

Postgres allows exactly one recursive term per CTE, so the engine first builds
a non-recursive `hops` relation (impersonation edges + identity links in both
directions), then a single recursive term walks it: base = every principal,
step = one hop, terminal join = non-impersonate grants matched against
resources. Confidence multiplies along the path; a fuzzy link caps it at 0.6
and fuzzy links are excluded entirely from materialization — fuzzy correlation
flags for review, it never expands reach.

The correctness anchor is `reach/bfs.py`: a deliberately naive Python
enumeration of simple paths that serves as the executable specification. A
Hypothesis property test generates random graphs — glob selectors, LIKE
metacharacters, impersonation chains, cycles, mixed link methods — and asserts
the CTE and the BFS produce identical edge sets with identical confidences.
When they disagree, the BFS is right. This test caught a real bug during
development (the three-arm recursive CTE Postgres rejects) and a mutation
check confirms it fails when semantics drift.

`reach_edges` is materialized per tenant (full rebuild, or per-origin
incremental) so detections and the API read a table, not a traversal.

## Detections

Rules over the graph, each returning findings that carry the exact rows and
derivation paths that triggered them. The one non-obvious design: scope
expansion. Grant history isn't kept as snapshots; instead the ingest pipeline
emits an inferred `reachset.grant_widened` event (idempotent, content-hashed)
whenever an upsert strictly widens a capability set. The detection then looks
for widenings with no corroborating change event in the app's own audit
stream — turning "diff two syncs" into "join two event streams", which is both
cheaper and easier to explain.

## Agent layer

MCP tools return conclusions sized for a context window (`assess_principal` is
a summary + top risks + bounded evidence refs, never an edge dump). The triage
pipeline is three roles: an Analyst that drafts the case, an Adversary that
hunts for benign explanations (cron-shaped periodicity, declared migration
windows, by-design accounts, audit-corroborated changes), and an Adjudicator
that decides.

The prompt-injection defense is structural, in three layers:

1. Every app-originated string (display names, paths, user agents) crosses
   into agent context only as a tagged value with provenance
   (`<untrusted provenance="...">`, fence characters neutralized inside).
2. No tool is ever invoked on the basis of log-derived instructions — tool
   sequencing is code, not model output.
3. The Adjudicator consumes `AdjudicatorInput`: numbers and enums only, no
   app-originated text at all. A red-team corpus of 26 poisoned records
   (instruction injection, fake system messages, base64 payloads, spoofed tool
   calls, "a previous session authorized this") asserts 0/26 change a verdict.
   Suspected injections can only make the outcome more conservative — a benign
   auto-close escalates to human review, never the reverse.

In v0 the roles are deterministic heuristics (no model API exists under this
repo's constraints). The interfaces are shaped so a model-backed Analyst or
Adversary drops in without touching the Adjudicator boundary, which is where
the safety property lives.
