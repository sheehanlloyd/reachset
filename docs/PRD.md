# Reachset — Product Requirements Document

**Repo:** `reachset`
**One-line:** Reachset ingests identity, credential, and activity data from multiple SaaS apps, normalizes it into a canonical graph, and computes the *effective reachability set* of every identity — especially non-human ones — so you can answer "what can this agent actually touch, and what did it touch?"

**Status:** v0 spec. Author: Sheehan Lloyd.

---

## 1. Problem

Granted OAuth scopes are not effective permissions. An AI agent holding `repo` on a GitHub org, or a Vault token bound to a broad policy, reaches far more than its scope string suggests, because access flows through delegation chains: credential → scope → role → resource → data. Nobody can enumerate those chains by hand across a dozen apps, so the blast radius of a single compromised integration is unknown at exactly the moment it matters.

Reachset computes those chains explicitly and continuously.

## 2. Non-goals

- Not a SIEM. No log storage at retention scale, no alert routing.
- Not a remediation tool in v0. Reachset reports; it does not revoke.
- No production SaaS tenants. Dev/free tenants owned by the operator only.
- Not a Neo4j project. Reachability is computed in Postgres with recursive CTEs; adding a graph database is a v3 question, not a v0 one.

## 3. Users

| User | Needs |
| --- | --- |
| Security engineer | "Which non-human identities can write to sensitive resources in more than one app?" |
| IR responder | "Credential X is compromised. What is reachable through it, ranked by sensitivity?" |
| Platform engineer | "Adding a new SaaS app should take hours, not weeks." |

## 4. Architecture

```
  ┌─────────────┐   ┌─────────────┐   ┌──────────────┐
  │ Connectors  │──▶│ Normalizer  │──▶│  Postgres    │
  │ (transport  │   │ (extractors │   │  canonical   │
  │  + extract) │   │  + linker)  │   │  schema      │
  └─────────────┘   └─────────────┘   └──────┬───────┘
        │                                     │
   Redis queue                        Reachability engine
   + watermarks                       (recursive CTE)
        │                                     │
   Worker pool                         ┌──────▼───────┐
   (docker-compose,                    │  Detections  │
    HPA-ready)                         └──────┬───────┘
                                              │
                                       FastAPI  +  MCP server
```

### 4.1 Connector contract

Every connector implements two independently testable halves.

```python
class Transport(Protocol):
    async def get(self, path: str, params: Mapping) -> Response: ...

class Extractor(Protocol):
    def principals(self, payload: dict) -> list[Principal]: ...
    def credentials(self, payload: dict) -> list[Credential]: ...
    def grants(self, payload: dict) -> list[Grant]: ...
    def resources(self, payload: dict) -> list[Resource]: ...
    def events(self, payload: dict) -> list[Event]: ...
```

Extractors are **pure functions over JSON**. No I/O, no clock, no randomness. This is what makes the system testable without live tenants.

Transports are one of three:
- `HttpTransport` — real, used in `live` mode only.
- `FixtureTransport` — replays committed JSON fixtures in `tests/fixtures/<app>/`.
- `ChaosTransport` — wraps a fixture transport and injects: HTTP 429 with `Retry-After`, 500s, 503s, connection resets, empty pages, repeated cursors, out-of-order pages, truncated JSON, clock skew on timestamps.

### 4.2 Connectors in scope

| App | Why | Live-testable in CI |
| --- | --- | --- |
| **HashiCorp Vault** (dev mode) | Auth methods, policies, token accessors, audit device. Self-hostable. | **Yes** — `vault server -dev` as a CI service |
| **GitHub** (org) | App installations, PATs, deploy keys, audit log, repo permissions | No — fixtures only |
| **Google Workspace** (stretch, phase 4) | Admin SDK Reports API, OAuth token list | No — fixtures only |
| **Salesforce Developer Edition** (stretch, phase 4) | Connected apps, login history, Setup Audit Trail | No — fixtures only |

Vault is deliberately first: it is the only one with true end-to-end integration tests, so it validates the whole pipeline shape before fixture-only connectors are added.

## 5. Canonical schema

All tables carry `tenant_id`. All ingest is idempotent on `(tenant_id, app_id, external_id)`.

**principals** — `id, tenant_id, app_id, external_id, kind ∈ {human, service, agent, app}, display_name, email, status, created_at, last_active_at, first_seen_at, last_seen_at`

**credentials** — `id, tenant_id, principal_id, kind ∈ {oauth_token, pat, api_key, vault_token, session, ssh_key}, external_id, issued_at, last_used_at, expires_at, revoked_at`

**resources** — `id, tenant_id, app_id, external_id, kind ∈ {repo, sobject, secret_path, drive_file, channel, mailbox}, path, sensitivity ∈ 0..3`

**grants** — `id, tenant_id, principal_id, credential_id (nullable), resource_selector (glob/pattern), scope_raw, capabilities (set), granted_by_principal_id, granted_at, source_app_id`

**capabilities** — enum: `read, write, admin, delete, impersonate`. Scope-to-capability mapping lives in a per-app declarative table, versioned, with a test asserting every observed scope string maps to something (unknown scopes fail loudly rather than silently mapping to `read`).

**events** — `id, tenant_id, app_id, actor_principal_id, action, target_resource_id, ts, ip, user_agent, raw_ref, provenance ∈ {api, audit_log, inferred}`

**identity_links** — `principal_a, principal_b, method ∈ {email_exact, sso_subject, external_id_exact, fuzzy_name}, confidence ∈ 0..1, evidence_json`

**reach_edges** (materialized) — `principal_id, resource_id, capability, path_json, confidence, computed_at`

**sync_watermarks** — `tenant_id, app_id, stream, cursor, last_success_at, consecutive_failures`

**dead_letters** — `id, tenant_id, app_id, stream, payload, error, attempts, first_failed_at`

## 6. Identity correlation

Deterministic first, fuzzy last, never silent:

1. `external_id_exact` — same IdP subject across apps → confidence 1.0
2. `email_exact` — normalized (lowercase, strip dots for gmail, strip `+tags`) → 0.95
3. `sso_subject` — SAML NameID match → 0.95
4. `fuzzy_name` — token-set ratio ≥ 0.9 **and** same tenant **and** no conflicting email → 0.6, and never used to expand reachability, only to flag for review

Requirement: a labeled synthetic dataset with known ground-truth links, and a test asserting precision ≥ 0.98 and recall reported (not asserted) in `bench/identity_linking.json`.

## 7. Reachability engine

Given a principal, expand transitively: `principal → grants → resource_selector` matched against `resources`, plus `impersonate` edges which recurse into the target principal's own grants (this is where the interesting depth comes from, and where cycles must be handled).

- Implemented as a recursive CTE with an explicit depth cap and a visited-set to terminate cycles.
- `path_json` records the derivation so every edge is explainable — no unexplained results.
- Confidence multiplies along the path; any `fuzzy_name` link in the path caps confidence at 0.6.
- Must be correct before it is fast. Property test: for hand-built small graphs, the CTE result equals a naive BFS in Python.

## 8. Detections

Rules over the graph, each with a synthetic positive and negative fixture:

1. **Dormant privileged NHI** — service/agent principal with `write|admin|delete` reach, `last_used_at` > 90d.
2. **Orphaned grant** — `granted_by_principal_id` is deactivated or deleted.
3. **Scope expansion** — grant's capability set widened between syncs with no corresponding change event in the audit stream.
4. **Cross-app concentration** — one NHI reaching `sensitivity ≥ 2` resources in ≥ 3 distinct apps.
5. **Shadow AI integration** — app principal matched against a declarative known-AI-vendor list holding read reach on `sensitivity ≥ 2`.
6. **Off-hours bulk read** — NHI read volume above its own 28-day baseline outside its own historical active window.

Every detection emits: rule id, principal, evidence paths, severity, and the exact rows that triggered it.

## 9. Scale

Synthetic tenant generator: configurable to 50k principals, 200k grants, 5M events, with realistic distributions (long-tail activity, most principals inert).

Benchmark harness writes **measured** output to `bench/results.json` and a plot to `bench/`:
- Ingest throughput (events/sec) at 1, 2, 4, 8 workers
- p50/p95/p99 reachability query latency at 1M / 5M / 10M edges
- Full-recompute wall time vs. incremental
- Memory high-water per worker

Numbers are recorded, not targeted. Any number in the README must be reproducible by `make bench` on the reader's own machine, and the README states the machine spec it was measured on.

Rate limiting: per-`(tenant, app)` token bucket, honors `Retry-After`, jittered exponential backoff, max 5 attempts, then dead-letter. Chaos tests assert no data loss and no duplicate rows across 429/500 storms.

## 10. Agent layer (phase 3)

MCP server exposing graph tools that return **conclusions, not rows** — e.g. `assess_principal(id) -> {reach_summary, top_risks, evidence_refs}` rather than dumping 4000 edges into a context window.

Triage pipeline:
- **Analyst** — gathers context via MCP tools, drafts a finding.
- **Adversary** — attempts to falsify it; searches for benign explanations (scheduled job, known migration, service account by design).
- **Adjudicator** — decides, cites evidence, assigns confidence.

Eval harness over a labeled set of ≥ 40 synthetic incidents (mixed true and false positives). Reports precision, recall, mean cost, p95 latency, versus a rules-only baseline. If the pipeline doesn't beat the baseline, the README says so.

### 10.1 Prompt-injection defense (required, not optional)

Audit logs contain attacker-controlled strings: OAuth app display names, repo descriptions, channel topics, Vault path names. These reach the agent.

- Red-team corpus of ≥ 25 poisoned records in `tests/redteam/` — instruction injection, fake system messages, encoded payloads, tool-call spoofing, "prior session authorized this."
- Mitigations: all log-derived content passed as tagged, quoted data with explicit provenance; agents cannot invoke tools on the basis of log-derived instructions; the Adjudicator sees structured fields, never raw strings, for its decision.
- Test asserts 0/25 injections change a verdict.

## 11. Milestones

| Phase | Deliverable | Done when |
| --- | --- | --- |
| **M0** | Repo skeleton, schema, migrations, docker-compose, CI | `make up && make test` green on a clean clone |
| **M1** | Vault connector, full pipeline, 1 detection | Vault integration test green in CI against `vault server -dev` |
| **M2** | GitHub connector (fixtures), identity linking, reachability CTE | Linker precision test ≥ 0.98; CTE == BFS property test green |
| **M3** | All 6 detections, synthetic generator, benchmark harness | `bench/results.json` populated with measured numbers |
| **M4** | MCP server, triage pipeline, eval harness, red-team suite | Eval table in README; 0/25 injections succeed |

Stretch: Google Workspace + Salesforce connectors; Kubernetes manifests with HPA and a scaling curve.

## 12. Engineering standards

- Python 3.12, `uv` for dependency management
- `ruff` (lint + format), `mypy --strict`, no `# type: ignore` without a reason comment
- `pytest`, `pytest-asyncio`, `hypothesis` for property tests, `testcontainers` for Postgres/Redis/Vault
- Coverage floor 85% on `src/`, enforced in CI
- Structured logging (`structlog`), no `print`
- Every module has a docstring stating what it owns
- Conventional commits
- No secrets in the repo, ever. `.env.example` only. Pre-commit hook running `gitleaks`.

## 13. Honesty requirements

The README must contain a section titled **Verification status** distinguishing:

- **Verified end-to-end against a live service** — Vault only.
- **Verified against recorded fixtures** — GitHub, and any other fixture-only connector, with a note that fixtures were hand-authored from public API documentation, not captured from a live tenant.
- **Not yet verified** — anything untested, listed explicitly.

`NOTES.md` maintains a running list of assumptions made about API behavior that have not been confirmed against a live tenant, so they can be checked later and turned into real findings.
