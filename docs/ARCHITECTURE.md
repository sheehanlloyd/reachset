# Architecture

This document covers the decisions that shape the codebase: the
transport/extractor split, the canonical schema, doing reachability as a
recursive CTE in Postgres instead of adding a graph database, what a grant is
allowed to reach, the analyses layered on the graph, and the operational
surface.

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

The token bucket ships in two implementations behind one protocol
(`ingest/ratelimit.py`). `BucketRegistry` keeps bucket state in process
memory — correct for one worker, wrong for N of them, because N worker
processes each get their own independent allowance and draw N times the
configured rate against whatever they're calling. `RedisBucketRegistry`
keeps the same state in Redis instead, refilled and decremented by one
atomic Lua script per `acquire()` call so every process sharing that Redis
instance draws from one real rate; the clock authority is Redis's own `TIME`
command rather than each worker's wall clock, so clock skew between workers
can't distort refill timing. `StreamSyncer` takes either through a
`BucketSource` protocol, so the choice is a constructor argument, not a code
path — though nothing in this repo wires `StreamSyncer` into the live worker
yet (the worker's Vault sync is a direct one-shot call with no
`StreamSyncer` involved at all; see NOTES.md), so `RedisBucketRegistry` is
correct and tested but not yet load-bearing in production code.

## The canonical schema

Eleven tables, all carrying `tenant_id`: principals, credentials, resources,
grants, events, identity_links, reach_edges (materialized), sync_watermarks,
dead_letters, and the two that back reach snapshots. Three choices worth
defending:

**Grants store selectors, not resource foreign keys.** A Vault policy grants
`secret/data/prod/*`, not a list of secrets — the list changes as secrets are
created. Storing the selector keeps the grant faithful to the source system
and moves matching into the reachability computation, where new resources are
picked up on the next materialization without touching grants.

**Foreign keys are indexed explicitly.** Postgres creates an index for a
primary key but not for a foreign key, so an unindexed FK column turns every
parent delete into a sequential scan of the child table for the cascade check.
Five columns here needed one — `reach_edges.principal_id` most of all, since
the unique constraint covering it leads with `tenant_id` and cannot serve a
lookup by principal alone. The symptom was the benchmark's own cleanup running
for twenty minutes; the fix is a migration full of one-line `create_index`
calls.

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
incremental) so detections and the API read a table, not a traversal. A full
rebuild streams the CTE's result through a server-side cursor and inserts it
in bounded-size chunks (`reach/engine.py`'s `_stream_materialize`) instead of
buffering the whole result set in Python first — the earlier buffered version
was what drove peak process RSS to 4.3 GB on a 2M-edge tenant (see
[NOTES.md](../NOTES.md)).

Two performance details are worth calling out because they are invisible
until you read a plan. First: `hops` is declared `MATERIALIZED`. It is
referenced exactly once, from inside the recursive term, which means
Postgres inlines it by default and re-derives the whole relation on every
iteration of the walk. One keyword cut single-origin latency by about 30% on
a 5,000-principal tenant. Second: both the impersonation hop and the
resource-selector grant join split into an exact-match arm and a glob-match
arm — a selector with none of `*`, `?`, `+` joins by equality against an
index instead of paying for a pattern match, and only genuine globs pay for
one. Before the split, the impersonation arm was a full cross join of every
impersonation grant against every principal in the tenant regardless of
whether the selector even used glob syntax; on the profiled 5,000-principal
tenant that discarded 894,821 rows per query, the single most expensive node
in the plan. `EXPLAIN (ANALYZE, BUFFERS)` on that same tenant shape shows the
split cutting single-origin query time roughly 3x (see NOTES.md for the
before/after numbers) — this was measured as promising once already and left
unlanded because the first attempt at it didn't converge; the version that
landed is the exact/glob split described above, not the earlier attempt.

Glob matching itself moved from LIKE to Postgres's `~` (POSIX ERE) operator,
because the selector language now supports a third wildcard: `+`, mirroring
Vault's own single-path-segment wildcard exactly (`secret/data/+/state`
matches one segment, not zero and not more than one). LIKE can express `*`
and `?` but has no way to express "one or more characters that are not a
`/`" — that needs a negated character class, a regex feature LIKE doesn't
have. `reach/selectors.py` builds the ERE translation with the same
escape-then-substitute discipline the old LIKE translation used, and the
Vault extractor now stores a policy's `+` selector verbatim instead of
widening it to `*`, which is the one place this project was previously
choosing to overstate reach on purpose.

## What a grant is allowed to reach

One rule is load-bearing enough to state on its own: **a grant only reaches
resources belonging to the app that issued it.** A Vault policy of
`path "*"` is sudo over Vault, not over every repository in the GitHub org that
happens to share a path shape. Cross-app reach exists, but it comes from
identity links — the same person or service correlated across two apps — and
never from a selector that coincidentally matches another app's namespace.

I got this wrong in the first cut, and the way it surfaced is worth recording.
The blast-radius output for a Vault admin token listed GitHub repositories.
That looked alarming enough to be suspicious, and `reachset explain` settled
it in one line: a single grant step, no identity link, straight from a Vault
policy to `acme/payments-api`. The fix was one join predicate in the CTE and
one guard in the BFS reference. The more useful part was extending the property
test to generate two-app graphs, so the rule is now enforced by the same
CTE-equals-BFS check as everything else rather than by my memory of it.

That is the argument for keeping an executable specification around: the
property test could not have caught this before, because every graph it
generated used a single app. Once the generator knew about apps, the rule
became checkable.

## Analyses on top of the graph

The reach graph is the substrate; the questions people actually ask are one
layer up, and each is a query rather than a dump.

**Blast radius** answers "credential X is compromised, what does it reach?" It
ranks by capability weight × sensitivity — deleting a moderately sensitive
resource outranks reading a highly sensitive one — collapses per-capability
edges into per-resource exposure, and bounds the evidence it returns. Scoping
to a *credential* rather than to its owning principal matters: holding one
Vault token does not hand you the reach of every other token that principal
owns, so the query filters to edges whose derivation actually traverses that
credential's grants.

**What-if revocation** is the same engine with a set of grants suppressed,
diffed against the live result. Implementing it as an exclusion parameter on
the CTE rather than as delete-then-rollback keeps it a read-only query: there
is no transaction anyone has to remember to unwind, and a test asserts the row
counts are unchanged afterwards. The output people care about is the
collateral — which *other* principals were borrowing that grant through a
delegation chain, and which resources stay reachable by a second path anyway.

**Least privilege** joins granted reach against exercised reach over a window
and proposes a narrowed selector built from the longest common prefix of the
paths actually touched. The honest edge case drove the design: a principal that
touched nothing gets `(revoke)`, not a smaller scope, because there is nothing
to justify keeping. Unrecognized action verbs contribute no capability rather
than a guessed one, which biases the analysis toward reporting more unused
reach than there is — the safe direction for something a human will act on.

**Snapshots and diffs** exist because a detection reports what is wrong now,
and a nightly run of "what is wrong now" re-lists the same known findings
forever. A snapshot captures a tenant's reach under a label; the diff is a
`FULL OUTER JOIN` between two snapshots, yielding added, removed, and
confidence-changed edges in one pass. Snapshot rows denormalize paths and
external ids rather than referencing live rows: a diff has to stay readable
after the upstream principal is deleted, which is precisely the moment it is
most worth reading.

**Policy-as-code invariants** answer a different kind of question than a
detection does. A detection says "this pattern is worth a human looking at";
an invariant says "this exact thing must never be true, full stop" — the
kind of rule a security team has already agreed on and wants enforced every
run without a human re-judging it each time. Rules live in a TOML file, not
code (`analysis/invariants.py`), evaluated by two rule kinds so far
(`vendor_capability_sensitivity`, `max_apps_per_principal`); a config that
doesn't validate against the real capability/principal-kind/severity
vocabulary fails at load time rather than silently matching nothing forever.
`check-invariants --sarif PATH` writes the same violations as SARIF 2.1.0 —
GitHub code scanning's native format — with each result's location pointing
at the invariants config itself, since a Reachset violation has no source
line to point at; that is the same convention other non-code SARIF producers
(dependency and IaC scanners) use.

## Operational surface

The health endpoints follow the split that makes them useful rather than the
one that makes them symmetrical. `/healthz` is liveness and touches nothing —
a liveness probe that queried Postgres would restart the API every time the
database hiccuped, converting a brief dependency problem into an outage.
`/readyz` is readiness, actually exercises the dependency, returns 503 so a
load balancer drains the instance, and names the failing check rather than
reporting a bare status.

Metrics are exposed in Prometheus text format from a hand-written registry
implementing counters, gauges, and cumulative histograms with labels, and
deliberately nothing else — no exemplars, no native histograms, no multiprocess
collection. This is the one place in the codebase where I'd call the decision a
close one: `prometheus_client` would have been a reasonable choice and is the
choice I'd make on a team. I wrote it out because the exposition format is
small enough to own outright and because it puts the label and bucket semantics
under test rather than trusting them. The call sites are shaped so the library
drops in unchanged the day any of the missing features matter.

The one non-obvious detail is label cardinality. HTTP metrics are labeled with
the route *template* (`/tenants/{tenant_id}/principals/{principal_id}/reach`),
not the request
path, so a tenant with 10,000 principals produces one time series rather than
10,000. That mistake is easy to make and expensive to undo once a Prometheus
instance is already carrying the series, so there is a test asserting the
concrete id never appears in the exposition output.

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
