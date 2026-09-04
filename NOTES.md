# NOTES

Running list of assumptions, deviations, and open questions. Anything here has
*not* been confirmed against a live tenant unless it says otherwise. Treat each
unchecked box as a to-do: verify against a real tenant, then either check it off
or fix the code.

## Vault (live-verified in CI, but with caveats)

- [ ] Policy documents are parsed with a regex that handles the plain
  `path "..." { capabilities = [...] }` form. Templated policies
  (`{{identity.entity.id}}`), `allowed_parameters`, `denied_parameters`,
  `required_parameters`, and `min_wrapping_ttl` blocks are not interpreted. A
  policy using those will parse but the extra constraints are ignored, which
  *overstates* reach. Overstating is the safer direction for this tool, but it
  should be explicit in any report.
- [x] Vault's `+` wildcard matches exactly one path segment; the selector
  language now has a real `+` operator (`[^/]+` in the BFS regex, an
  anchored POSIX ERE via `~` in the CTE) instead of widening `+` to `*`. The
  Vault extractor stores a policy's `+` selector verbatim
  (`connectors/vault/extractor.py`). Verified by extending the CTE-vs-BFS
  property test's selector generator to draw `+` patterns; see
  `reach/selectors.py` and "Reach engine performance" below for the SQL side.
- [x] The `root` policy has no document. I synthesize it as sudo-over-`*`.
  Verified live: root tokens list it and no document endpoint exists for it.
- [x] Token display names come back prefixed (`token-<name>`). Learned this
  from the live test failing, which is exactly what the live test is for.
- [ ] `creation_time` is epoch seconds and `issue_time` is ISO in the same
  payload. My parser accepts both everywhere rather than pinning which field
  uses which format per Vault version.
- [x] Audit device: file backend, `mode=0644`, and `hmac_accessor=false` so the
  test can correlate audit lines to token accessors. A production deployment
  should keep the HMAC and correlate through `entity_id` instead; accessors in
  plaintext in an audit log are a secondary credential-ish artifact.
- [ ] Only `type == "response"` audit entries become events (the request entry
  would double-count every operation). Assumes every completed operation writes
  a response entry; true in dev-mode testing, unverified under audit backpressure.
- [ ] KV v2 assumed mounted at `secret/`. KV v1 (no `/data/` in paths) is not
  handled. A v1 mount would make policy selectors and resource paths disagree.
- [ ] Secret-path sensitivity is a naive heuristic (`sys/`+`auth/` and
  anything containing "prod" → 3, else 1). Real deployments need an operator-
  supplied classification, not string sniffing.
- [ ] The worker's Vault syncer does not ingest the audit stream (it has no
  file access); only the direct connector path does. A deployed worker needs
  the audit file mounted, or a socket/syslog audit device.
- [ ] The connector never reads Vault entity metadata (`identity/entity/id/...`),
  only token-accessor lookups (`extract_token` in
  `connectors/vault/extractor.py`). Vault entities carry an `email` in their
  metadata in a real deployment, and identity linking depends on it. The
  README's "why can jortega read a Vault secret" worked example demonstrates
  the resulting cross-app link, but has to seed a Vault entity by hand in the
  test that produces it, because no committed Vault fixture has an email at
  all. Found while trying to reproduce that example from a plain `reachset
  sync` + `reachset sync` (the two-command version `make demo` runs) and
  getting "no read edge" instead of the documented output. Reading entities
  is the fix; it's a new Vault API call this connector doesn't make yet.

## GitHub (fixture-verified only, no live tenant exists)

All GitHub shapes were hand-authored from the public REST docs. None of this
has met a real org.

- [ ] Fine-grained PAT grants API (`/orgs/{org}/personal-access-tokens`):
  field names (`repository_selection` ∈ none/all/subset, `permissions.repository`,
  `permissions.organization`, `token_last_used_at`) taken from docs.
- [ ] Selected-repo PATs and installations are expanded via their
  `/repositories` sub-endpoints. For installations that endpoint really wants a
  JWT-authenticated app credential, not the org token; the connector assumes
  one transport credential can see everything. Almost certainly wrong live;
  needs an auth-mode split per endpoint.
- [ ] Org audit log: live GitHub returns a bare JSON array with the cursor in
  the `Link` header. My fixtures wrap it as `{"entries": [...], "after": ...}`
  because the sync engine consumes object pages. An HttpTransport adapter that
  lifts Link-header cursors into that envelope is required before live use.
- [ ] `@timestamp` is epoch milliseconds.
- [ ] The members list returns login/id only, so the connector fetches
  `/users/{login}` per member for name/email. Public emails are usually null;
  the identity linker degrades to SSO/fuzzy in that case.
- [ ] Deploy keys: `added_by` is a login string, not an id, so deploy-key
  grants have no `granted_by_principal_id`. Orphaned-grant detection therefore
  can't fire for deploy keys yet.
- [ ] Bot detection: `type == "Bot"` or login ending in `[bot]`.
- [ ] Repo sensitivity heuristic: name contains prod/infra/secrets/payments →
  3, else private → 2, public → 1. Same caveat as the Vault heuristic.

## Canonical schema decisions (deviations worth knowing)

- Credentials are idempotent on `(tenant_id, kind, external_id)`. They carry
  no `app_id`, unlike the other tables. A Vault accessor or PAT id is unique
  within its kind. If two apps ever emit colliding external ids for the same
  credential kind, this breaks; I took the narrower key on purpose to keep
  cross-referencing simple.
- Grants have no upstream id in most APIs, so idempotency is a SHA-256 dedupe
  key over (principal, credential, selector, scope, source app). Capabilities
  are deliberately *excluded* so a widened grant updates the same row. That
  update is what emits the inferred `reachset.grant_widened` event the
  scope-expansion detection feeds on.
- Events are idempotent on `(tenant, app, raw_ref)` where raw_ref is a content
  hash. Re-reading an audit log is a no-op by construction.
- Grants/events referencing principals the API no longer returns produce
  deleted stub principals (kind defaults to `human`, which is a guess). The
  reference and the orphaned-grant signal survive; the kind may be wrong.
- Stream watermarks reset to NULL when a stream completes, so list-shaped
  streams re-walk from the top next sync. Safe because upserts are idempotent;
  wasteful for very large orgs. Event streams keep their cursor.

## Reachability semantics

- A grant only reaches resources belonging to the app that issued it. This was
  wrong in the first cut: a Vault policy of `path "*"` was matching GitHub repo
  paths, so a Vault admin token appeared to reach the whole GitHub org through
  a single grant step. Cross-app reach is supposed to come from identity links
  and nothing else. Found it by reading `reachset blast-radius` output that
  looked too alarming to be true, confirmed with `reachset explain` (one grant
  step, no link), fixed in the CTE and the BFS reference, and extended the
  property test to generate multi-app graphs so it stays fixed.
- Deterministic identity links (external_id_exact, email_exact, sso_subject)
  expand reach across apps; `fuzzy_name` links never do. Fuzzy links only exist
  for review, and if you ask the engine to include them (`include_fuzzy=True`)
  the path confidence is capped at 0.6 and nothing is materialized from them.
- [ ] `normalize_email` strips a `+tag` unconditionally, on every domain, but
  only folds dots on the two Gmail domains (`linking/linker.py`). That's
  inconsistent on purpose right now, not an oversight I've fixed: dot-folding
  is a Gmail-specific quirk, but plus-addressing is close enough to universal
  (every major consumer and Workspace/365 provider supports it) that gating it
  the same way would silently miss the common case. The cost is a real one
  though: on a domain where `+` is a literal character rather than an alias
  separator, this produces a false `email_exact` match at 0.95 confidence,
  which is deterministic and therefore trusted unconditionally by
  `materialize()`, unlike a fuzzy match. A per-domain allowlist (or a "treat
  plus as literal unless the domain is known to support sub-addressing"
  default) is the fix if this ever ingests a real tenant; not built because
  every domain in the fixtures and the synthetic generator does support it,
  so there's no test that would catch the regression either way.
- Deterministic matches (external_id_exact, email_exact, sso_subject) have no
  secondary check before they expand reach. A well-formed but wrong match
  (two people sharing a recycled `external_id`, the plus-address case above)
  is trusted exactly as much as a real one; only `fuzzy_name` gets the
  review-only treatment. Requiring two independent deterministic signals to
  agree before a link expands reach would close this, at the cost of missing
  legitimate single-signal links.
- Confidence is multiplicative along a path; grant hops are 1.0; only the best
  (confidence, then shortest, then lexicographic) path per
  (principal, resource, capability) is materialized.
- Impersonation is a Reachset-internal selector namespace
  (`principal:<glob>`). Mapping Vault's `sudo` to the `impersonate` capability
  is an interpretation: sudo over `auth/token/*` does let you mint tokens as
  other roles, but the mapping is coarse. The scope table pins it down in one
  place if it needs changing.

## Reach engine performance

Profiled with `EXPLAIN (ANALYZE, BUFFERS)` on a synthetic 5,000-principal /
20,000-grant tenant, single-origin query.

- The `hops` CTE is now `MATERIALIZED`. It is referenced exactly once, from
  inside the recursive term, so Postgres inlined it by default and re-derived
  the entire relation on every iteration of the walk. Adding the keyword cut
  median single-origin latency from ~3,456 ms to ~2,434 ms (about 30%) with no
  semantic change; the property test was re-run against random seeds to
  confirm that.
- [x] The previous bottleneck was the impersonation arm of `hops`: it was a
  cross join of every impersonation grant against every principal in the
  tenant, with a five-deep `replace()` + `LIKE` evaluated per pair. On the
  profiled tenant that was 179 grants × 5,000 principals ≈ 895k comparisons,
  with 894,821 rows discarded by the join filter, the single most expensive
  node in the plan. Fixed by splitting that arm (and the resource-selector
  grant join, same shape) into an exact-match arm and a glob-match arm:
  selectors with none of `*`/`?`/`+` join by equality against an index on
  `principals (tenant_id, external_id)` (migration `4552a499c0af`); only
  selectors that actually use glob syntax pay for a pattern match, now via
  Postgres's `~` (POSIX ERE) instead of `LIKE`, because supporting `+`
  requires a negated character class LIKE can't express. See `reach/engine.py`
  and `reach/selectors.py::sql_glob_to_ere`.

  I had previously prototyped this exact split and reported here that it
  "did not converge in a reasonable time." That was true of the earlier
  attempt, not of this one. Measured with `EXPLAIN (ANALYZE, BUFFERS)` on
  the same synthetic 5,000-principal/20,000-grant shape (`ANALYZE`d after
  generation, since a freshly bulk-loaded table has no statistics until
  autovacuum catches up, and querying it before that gives the planner
  wildly wrong row estimates on *both* the old and new query, which hides
  the real delta rather than measuring it): single-origin query time dropped
  from ~272-379 ms to ~55-251 ms across five runs (roughly a 3x median
  improvement), and the impersonation hop specifically went from 894,821
  rows discarded by a join filter (~238 ms of the ~288 ms total) to an exact
  index lookup with zero rows discarded (~2 ms). The synth generator's
  impersonation grants are all exact selectors (`principal:<external_id>`,
  never a glob), so this profiled shape is the realistic one, not a
  best case constructed to flatter the fix.
- [ ] `DISTINCT ON ... ORDER BY ... path::text` sorts on the serialized
  derivation to break ties deterministically. On the largest tenant that spills
  to disk (`external merge`, ~11 MB). A cheaper deterministic tie-break, the
  grant id rather than the whole path, would avoid it, at the cost of a
  slightly less obvious "shortest, then smallest path" rule.
- [x] Full materialization used to buffer the entire result set as
  `ReachRow` objects in Python before a single bulk insert. That's the reason
  peak RSS hit 4.3 GB on the 2M-edge benchmark tenant. `materialize()` now
  streams the CTE's result through `session.stream(...).partitions(...)` (a
  server-side cursor) and inserts each bounded-size chunk before fetching the
  next one, so process memory no longer scales with tenant size. `compute_reach()`
  itself is unchanged and still buffers; it's used for single-origin queries
  (blast radius, what-if revocation), which are bounded by one principal's
  reach and don't have this problem. Re-run `make bench` after this change and
  update the RSS figure in README with the measured number, not this note.
- Ingest throughput flattens after two workers: Postgres round-trips and the
  shared pool are the limit, not Python. One run on a database that had
  absorbed a whole test session showed eight workers collapsing to 273 ev/s
  (a third of the four-worker figure); it did not reproduce on a clean
  database, so it goes down as contention rather than a scaling property. If it
  ever shows up again, pool sizing per worker count is the first thing to test.
- Benchmark hygiene: run `make bench` against a freshly created database. A
  database carrying test churn measured the largest reach tenant about three
  times slower, which is enough to draw entirely wrong conclusions from.
- Five foreign-key columns had no index whose leading column was the key:
  `reach_edges.principal_id`, `identity_links.principal_b`,
  `grants.granted_by_principal_id`, `grants.credential_id`, and
  `events.target_resource_id`. Postgres does not index foreign keys
  automatically, so every cascade or `SET NULL` check on a parent delete was a
  sequential scan of the child table. I found this when `make bench`'s own
  cleanup (deleting a few thousand synthetic principals) ran for twenty
  minutes against a two-million-row `reach_edges`. Migration
  `171cb07e2ed3` adds all five. Measured on a clean database, deleting 600
  principals with ~30k edges went from 0.45 s to 0.02 s; the gap widens with
  table size, because the unindexed version is linear in the child table per
  deleted row.
  A `pg_constraint`/`pg_index` query for uncovered foreign keys is worth
  keeping around. It is in the git history of this file if it is needed again.

## Detections

- Scope-expansion corroboration matches against a small declarative list of
  audit actions per app. The real audit vocabularies are certainly larger;
  false positives here mean "I didn't know that action name", and the fix is a
  table entry, not code.
- Off-hours uses UTC hours-of-day against the principal's own 28-day history.
  No timezone inference beyond what the principal's own rhythm encodes.
- The AI-vendor list for shadow-AI detection is a short glob table. It will
  miss vendors it doesn't name; it's a starting point, not coverage.

## Agent layer

- Analyst/Adversary/Adjudicator are deterministic heuristics behind role-shaped
  interfaces. There is no LLM call anywhere in this repo (a hard constraint:
  no live API credentials exist). The interfaces are the point: a model-backed
  Analyst can replace the heuristic one without touching the safety property,
  because the Adjudicator consumes only `AdjudicatorInput`, numbers and enums,
  no app-originated text. Eval "cost units" are simulated tool invocations, not
  tokens, and the README table says so.
- `looks_injected` is a best-effort pattern list. The 0/26 injection result
  does **not** depend on it: verdict integrity comes from the structured-fields
  boundary. The detector only adds a conservative escalate-to-review bias.

## Analyses layered on the graph

- **Least privilege** compares granted reach against events in a window. The
  action-verb → capability mapping is a small declarative table; a verb it does
  not recognize contributes *nothing* rather than being guessed at, so "unused"
  stays honest. The consequence is that an app whose audit vocabulary I have not
  mapped will look entirely unused. Check the table before acting on a
  recommendation for a newly added connector.
- [ ] The suggested selector is the longest common path prefix of what was
  actually touched. That is the right shape for Vault paths, GitHub repo globs,
  and S3 prefixes; it is not right for an app whose selectors are not
  path-shaped, and there is no such app in scope yet.
- Usage is attributed through `events.target_resource_id`. Any event the
  connector could not resolve to a resource is invisible to this analysis, which
  biases it toward reporting *more* unused reach than there really is.
- **Blast radius** ranks by capability weight × (sensitivity + 1). The weights
  are a judgement call, not a measurement; they are in one dict at the top of
  `analysis/blast.py` so they can be argued with in one place.
- **What-if revocation** recomputes with grants suppressed rather than deleting
  and rolling back. It is read-only by construction, and there is a test that
  asserts the row counts are unchanged afterwards.
- [ ] `simulate_revocation` calls `compute_reach()` twice (before/after) with no
  origin, which computes reach for every principal in the tenant, and
  `compute_reach()` buffers its whole result set in Python. The CLI's
  `simulate-revoke` subcommand never passes a principal, so every real
  invocation is exactly the unbounded, unstreamed case that `materialize()`
  was rewritten to stream away from (see "Reach engine performance" above,
  the 4.8 GB RSS this project used to see before that fix). This is a real
  gap, not just a documentation one: it contradicts the assumption stated
  elsewhere that single-origin operations are bounded by one principal's
  reach. Fix is the same one `materialize()` already got, a streaming path
  through `simulate_revocation`; not done yet.
- [ ] Snapshots store a full copy of the edge set. At the 2M-edge scale in the
  benchmark table that is a lot of rows per snapshot; retention/pruning is not
  implemented, and `reachset snapshot` will happily fill a disk if you run it
  nightly against a large tenant and never delete anything.
- **Policy-as-code invariants** (`analysis/invariants.py`) are the newest
  analysis and deliberately narrow: two rule kinds
  (`vendor_capability_sensitivity`, `max_apps_per_principal`), not a general
  expression language. A richer DSL was tempting but would have meant writing
  and defending a parser for a language with no users yet; two concrete rule
  kinds that map directly onto the two example invariants in the feature
  request are easier to trust and easier to extend later with a third kind
  than to get an abstract rule grammar right on the first try.
  - [ ] The example config's two rules (`examples/invariants.toml`) are
    exercised end-to-end against the GitHub fixtures in tests, but no SARIF
    output from this tool has ever actually been uploaded to GitHub code
    scanning and confirmed to render as a check. The SARIF shape follows the
    spec and points `physicalLocation` at the config file (the same
    convention other non-code SARIF producers use when they have no line to
    report), but "GitHub actually ingests it and shows results" is unverified.
  - [ ] Severity is constrained to SARIF's own three levels (`error`/
    `warning`/`note`) rather than a separate severity vocabulary translated
    through. Simpler, but it means a rules file authored before knowing
    about SARIF would need updating if this project ever added a fourth
    internal severity tier.

## Distributed rate limiting

- `ingest/ratelimit.py` has two token-bucket implementations behind one
  `BucketSource` protocol: `BucketRegistry` (in-process, existing) and
  `RedisBucketRegistry` (new). The bug the new one fixes: N worker processes
  each holding their own `BucketRegistry` get N independent allowances, so N
  workers racing the same tenant/app draw N times the configured rate against
  whatever they're calling. Nothing enforces the *aggregate* rate across
  processes when the state lives in one process's memory.
- The Redis version refills and decrements atomically in one Lua script per
  `acquire()` call, keyed on Redis's own `TIME` command rather than each
  worker's wall clock, so clock skew between workers can't distort refill
  timing. Verified with a real concurrency test
  (`tests/integration/test_distributed_ratelimit.py`) against a real Redis:
  N independent `RedisBucketRegistry` instances (standing in for N worker
  processes, no shared Python object between them, only the same Redis key)
  race the same bucket, and the test asserts the *aggregate* acquisition rate
  across all of them tracks the single configured rate rather than N times it.
  This needed real wall-clock time and real concurrency to be honest; a fake
  clock in a single-process unit test can't exercise the actual race the bug
  lives in.
- [ ] **Not wired into anything yet.** `StreamSyncer` (`ingest/engine.py`) is
  what actually takes a `BucketSource`, and nothing in this repo constructs a
  `StreamSyncer` outside of tests. The worker's Vault sync
  (`ingest/worker.py::vault_syncer`) calls `VaultConnector(transport).sync()`
  directly, no rate limiting of any kind, local or distributed. This was true
  before this change too (found while looking for where to wire the Redis
  registry in). GitHub live mode, which is what `StreamSyncer` was actually
  built for, was never implemented (see "Not implemented" below), so the
  class it serves has stayed unused. Whoever implements live-mode GitHub sync
  should default to `RedisBucketRegistry`, not `BucketRegistry`, once a
  worker fleet exists; that is the whole point of building it now rather
  than later.

## Attack-path visualization

- `reach/graphs.py` renders a single derivation path (`explain --format
  mermaid|dot`) or a principal's whole reach (`reach --format mermaid|dot`)
  as Mermaid or DOT. Pure string formatting over data the engine and CLI
  already produce: no new query, and rendering can't disagree with the table
  it's an alternate view of, because it consumes the same rows.
- The whole-reach renderer deliberately does *not* draw one subgraph per
  distinct derivation path. At real tenant scale (thousands of edges) that
  would be an unreadable tangle rather than something worth pasting into an
  incident doc. It fans out from the origin to each resource once, grouped by
  app, edge labeled with the deduplicated capability set: "what does this
  identity touch," which is what `reach` already reports, just as a picture.
  "How does this *one* edge derive" is `explain`'s job, and that renderer
  does draw every hop, because a single path is never too large to read.
- [ ] No visual testing. The tests assert the generated text is structurally
  correct (right node count, right escaping, starts/ends with the right
  tokens) but nothing renders the Mermaid/DOT output through an actual
  renderer and checks the picture looks right. I eyeballed real output from
  `reachset reach --format mermaid` and `--format dot` against the demo
  tenant while building this and it looked correct, but that is not the same
  as a test.

## Operational surface

- [ ] `/readyz` checks Postgres only. Redis is not checked, because the API
  does not use it; the worker does. If the API ever grows a queue dependency,
  that check needs adding or the probe becomes a lie.
- The metrics registry is hand-written (~297 lines). It implements counters,
  gauges, and cumulative histograms in the Prometheus text format, and nothing
  else: no exemplars, no native histograms, no multiprocess collection. If any
  of those become necessary, replace it with `prometheus_client` rather than
  growing this.
- [ ] Metrics are per-process and in-memory. Running more than one API replica
  means scraping each of them; there is no aggregation and no persistence
  across restarts.

## Not implemented (explicitly)

- Google Workspace and Salesforce connectors (stretch goals; never started).
- Live-mode GitHub transport (Link-header pagination adapter, app JWT auth).
- `RedisBucketRegistry` wired into a live sync path. It exists and is
  tested, but `StreamSyncer` (the only thing that takes a `BucketSource`)
  is never constructed outside tests, because live-mode GitHub sync (above)
  was never implemented either. See "Distributed rate limiting".
- Vault entity metadata (email, etc.). The connector only reads token
  accessors. See the Vault section above.
- `TransportBase.request` raises NotImplementedError by design (abstract).

There are currently no `xfail` tests and no silently stubbed functions.

## Testing notes

- Coverage is measured with `concurrency = ["thread", "greenlet"]`. Without it,
  every API endpoint that resolves a SQLAlchemy session through a FastAPI
  dependency reports as uncovered even though the tests exercise it, because
  the execution happens inside a greenlet coverage was not tracing. That
  silently understated the whole project's coverage by about five points
  until I went looking for why tested endpoints showed red.
- Seven `# pragma: no cover` markers exist: four on `Protocol` class/method
  bodies (`Transport`, `Detection`, and the rate limiter's `Bucket.acquire`
  and `BucketSource.bucket`), which are structural declarations never
  executed, and three on genuinely untestable lines: interactive-only
  `KeyboardInterrupt` handling in the CLI, the `if __name__ == "__main__"`
  entry point, and a FastAPI dependency the test fixture always overrides.
  This file used to claim "three, all on Protocol bodies," which was already
  wrong before this round of work (the three non-Protocol ones predate it).
  Found by grepping and counting during a polish pass rather than trusting
  the existing claim. Everything else is covered by a test rather than
  excused by a pragma.
- The suite reaches 100% of lines and branches on a typical run, but the
  enforced floor is 99%. The property test draws fresh random graphs each run
  and roughly one run in ten misses a single data-dependent branch. I chased it
  across a dozen runs without pinning it down to one line, and decided a gate
  that fails at random is worse than a gate with a point of slack. The
  alternative, `derandomize=True` on the Hypothesis profile, would make
  coverage exact at the cost of the test only ever seeing the same graphs,
  which defeats its purpose.
- [ ] If that branch is ever identified, cover it deterministically and put the
  floor back to 100.

## Local dev quirks (macOS)

- If the repo lives in an iCloud-synced folder (Desktop/Documents), iCloud can
  set the macOS `hidden` flag on files inside `.venv`, and Python ≥3.11 skips
  hidden `.pth` files, so imports of the editable install then fail with
  `ModuleNotFoundError`. Fix: `chflags -R nohidden .venv`, or keep the venv
  outside the synced tree (`UV_PROJECT_ENVIRONMENT=~/.venvs/reachset`).
- `make test` points tests at the compose stack from `make up` (same shape as
  CI's service containers). Unset the `REACHSET_TEST_*` variables to let
  testcontainers manage throwaway containers instead.
- Don't run `make bench` and the test suite at the same time against the same
  database. The test fixtures truncate tables and will eat the benchmark's
  tenants mid-run. I did this once so you don't have to.
