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
- [ ] Vault's `+` wildcard matches exactly one path segment; my selector
  language only has `*` and `?`, so `+` is widened to `*`. Again overstates
  reach; a segment-aware matcher would fix it.
- [x] The `root` policy has no document. I synthesize it as sudo-over-`*`.
  Verified live: root tokens list it and no document endpoint exists for it.
- [x] Token display names come back prefixed (`token-<name>`). Learned this
  from the live test failing, which is exactly what the live test is for.
- [ ] `creation_time` is epoch seconds and `issue_time` is ISO in the same
  payload. My parser accepts both everywhere rather than pinning which field
  uses which format per Vault version.
- [x] Audit device: file backend, `mode=0644`, and `hmac_accessor=false` so the
  test can correlate audit lines to token accessors. A production deployment
  should keep the HMAC and correlate through `entity_id` instead — accessors in
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

## GitHub (fixture-verified only — no live tenant exists)

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

- Credentials are idempotent on `(tenant_id, kind, external_id)` — they carry
  no `app_id`, unlike the other tables. A Vault accessor or PAT id is unique
  within its kind. If two apps ever emit colliding external ids for the same
  credential kind, this breaks; I took the narrower key on purpose to keep
  cross-referencing simple.
- Grants have no upstream id in most APIs, so idempotency is a SHA-256 dedupe
  key over (principal, credential, selector, scope, source app). Capabilities
  are deliberately *excluded* so a widened grant updates the same row — that
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

- Deterministic identity links (external_id_exact, email_exact, sso_subject)
  expand reach across apps; `fuzzy_name` links never do. Fuzzy links only exist
  for review, and if you ask the engine to include them (`include_fuzzy=True`)
  the path confidence is capped at 0.6 and nothing is materialized from them.
- Confidence is multiplicative along a path; grant hops are 1.0; only the best
  (confidence, then shortest, then lexicographic) path per
  (principal, resource, capability) is materialized.
- Impersonation is a Reachset-internal selector namespace
  (`principal:<glob>`). Mapping Vault's `sudo` to the `impersonate` capability
  is an interpretation: sudo over `auth/token/*` does let you mint tokens as
  other roles, but the mapping is coarse. The scope table pins it down in one
  place if it needs changing.

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
  interfaces. There is no LLM call anywhere in this repo (a hard constraint —
  no live API credentials exist). The interfaces are the point: a model-backed
  Analyst can replace the heuristic one without touching the safety property,
  because the Adjudicator consumes only `AdjudicatorInput` — numbers and enums,
  no app-originated text. Eval "cost units" are simulated tool invocations, not
  tokens, and the README table says so.
- `looks_injected` is a best-effort pattern list. The 0/26 injection result
  does **not** depend on it: verdict integrity comes from the structured-fields
  boundary. The detector only adds a conservative escalate-to-review bias.

## Not implemented (explicitly)

- Google Workspace and Salesforce connectors (stretch goals; never started).
- Live-mode GitHub transport (Link-header pagination adapter, app JWT auth).
- Segment-aware `+` wildcard matching for Vault selectors.
- `TransportBase.request` raises NotImplementedError by design (abstract).

There are currently no `xfail` tests and no silently stubbed functions.

## Local dev quirks (macOS)

- If the repo lives in an iCloud-synced folder (Desktop/Documents), iCloud can
  set the macOS `hidden` flag on files inside `.venv`, and Python ≥3.11 skips
  hidden `.pth` files — imports of the editable install then fail with
  `ModuleNotFoundError`. Fix: `chflags -R nohidden .venv`, or keep the venv
  outside the synced tree (`UV_PROJECT_ENVIRONMENT=~/.venvs/reachset`).
- `make test` points tests at the compose stack from `make up` (same shape as
  CI's service containers). Unset the `REACHSET_TEST_*` variables to let
  testcontainers manage throwaway containers instead.
- Don't run `make bench` and the test suite at the same time against the same
  database — the test fixtures truncate tables and will eat the benchmark's
  tenants mid-run. I did this once so you don't have to.
