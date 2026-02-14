# Runtime Alignment Checklist (Local, Not for Commit)

Date: 2026-02-06
Purpose: Track gaps between locked runtime design and current `card-fraud-rule-engine` code/docs.

## 1) Current Alignment Summary

Implemented and aligned:
- AUTH and MONITORING are separated by execution mode (`FIRST_MATCH` vs `ALL_MATCHING`).
- AUTH default decision is APPROVE on no match / handled evaluation failures.
- Ruleset loading uses compiled artifacts (`ruleset.json`) via `manifest.json`.
- AUTH request thread is decoupled from Kafka using Redis Streams outbox + worker (ADR-0014).

In progress (this session, 2026-02-06):
- Scope bucket narrowing wired into evaluators via EvaluationContext.candidateRules (ADR-0015).
- Scope-aware comparator: specificity -> priority -> APPROVE-first tie-breaker (ADR-0015).
- Country-partitioned ruleset resolution on hot path with global fallback (ADR-0016).
- Velocity snapshot deferred to outbox worker (ADR-0017).
- Hot-path logging downgraded from INFO to DEBUG.
- EventPublishException returns HTTP 200 + DEGRADED per ADR-0003 (not 503).
- Observability counters: fail_open_total, degraded_response_total, hot_reload_success/failure.

Not aligned (deferred to future sessions):
- No Positive/Negative list stage exists in runtime (allowlist/blocklist compiled within AUTH by rule-management, not separate runtime artifacts).
- Startup does not load all countries/artifacts by region before READY.
- Ruleset storage path does not include `{region}/{country}/{artifact}`.
- Scope dimensions are hardcoded in runtime (not configurable from published contract).

## 2) Locked Design vs Code Gaps

### A. Evaluation Order (Pre-Auth)
Locked:
1. Allowlist / Positive List (`card_id`)  
2. Blocklist / Negative List (`card_id`)  
3. Scoped AUTH rules (specificity buckets, then priority)  
4. Default APPROVE

Business intent lock:
- Precedence is order-driven: allowlist is checked first and wins if matched.
- AUTH rules are APPROVE-first by design intent from fraud ops.
- AUTH scoped traversal order is locked as:
  - scope bucket order first (most specific to least specific, country-only last)
  - priority order second (higher priority first)
  - decision precedence third as tie-breaker (`APPROVE` before non-approve for equal priority)
- MONITORING rules are review/pattern-matching only; no APPROVE/DECLINE decision precedence applies.

Current:
- AUTH evaluator iterates `getRulesByPriority()` over ruleset and exits first match.
- No PN list lookup stage.
- `RuleEvaluator` computes `getApplicableRules(...)` but evaluators ignore that result.

Action:
- Introduce deterministic pipeline: `Allowlist -> Blocklist -> ScopedAuthEvaluator`.
- Add explicit comparator for AUTH rule traversal:
  - scope bucket order first
  - priority second
  - decision precedence third (`APPROVE` first for equal priority)
- Wire scoped candidate rules into AUTH and MONITORING evaluators.

### B. Scope Semantics
Locked:
- Exact enumerated values.
- OR inside a scope dimension array.
- AND across dimensions.
- Scope wins over priority; priority only within bucket.
- Country-only rules evaluated last.

Current:
- Runtime model supports OR/AND semantics and combined scope matching.
- Runtime does not enforce scope-first traversal in evaluator execution path.
- Runtime priority is numeric-only global ordering, not bucket-local ordering.

Action:
- Build/consume explicit bucket traversal order at evaluation time:
  - Most specific bucket to least specific, then country-only/global last.
  - Apply priority inside each bucket only.

### C. Country/Region Partitioning
Locked:
- One transaction maps to exactly one country ruleset context.
- Runtime deploys per region and may cache multiple countries.
- No cross-country evaluation.

Current:
- `RulesetKeyResolver` returns only `CARD_AUTH` / `CARD_MONITORING` (no country dimension).
- `EvaluationResource` fetches ruleset using global lookup (`getRuleset(key)`).
- `RulesetLoader` path prefix is `rulesets/{env}/{ruleset_key}/...` (no region/country partition).

Action:
- Introduce country-aware resolver and registry lookup on hot path:
  - `getRuleset(country, CARD_AUTH|CARD_MONITORING|POSITIVE_LIST|NEGATIVE_LIST)`.
- Extend loader path and manifest contract to include region+country.

### D. Startup / Readiness
Locked:
- At startup load all countries under configured region, all 4 artifacts per country.
- Validate checksum, schema version, and country consistency.
- READY only after full load succeeds.

Current:
- Startup ruleset list is static key list (`CARD_AUTH,CARD_MONITORING`), defaults disabled in local/test.
- No discovery/listing of countries under region.
- No country consistency validation from manifest/artifact.

Action:
- Add startup region scanner + full country context preload.
- Block readiness until full preload success for required countries.

### E. Hot Reload
Locked:
- Reload country-isolated.
- On failure, keep last-known-good and alert high severity.

Current:
- Registry supports country namespaces, but loader fetch path is not country-specific.
- Hot reload checks are key-centric and effectively global for artifact retrieval.

Action:
- Make reload path country-aware in manifest/object lookup.
- Emit structured incident logs/metrics with `country`, `artifact_type`, `version`.

### F. Observability Contract
Locked:
- Required metrics include startup/hot-reload/fail-open/degraded counters.

Current:
- Management metrics endpoint exposes JVM/cache/storage status, not full locked metric set.

Action:
- Add counters/histograms:
  - `startup_ruleset_load_time`
  - `startup_ruleset_failures`
  - `hot_reload_success_total`
  - `hot_reload_failure_total`
  - `fail_open_total`
  - `degraded_response_total`

## 3) ADR / Docs Alignment Work Required

Needs ADR updates (or new ADRs):
- Runtime country+region partitioning and four-artifact contract.
- PN list precedence and conflict policy (`allowlist wins` by stage order; also emit governance warning if card exists in both).
- Scope bucket traversal contract (scope then priority then decision tie-breaker).
- Startup full preload and readiness gate semantics.

Now locked for implementation:
- Scope dimensions v1: `network`, `bin`, `mcc`, `logo` only.
- Scope semantics:
  - OR within each dimension array.
  - AND across dimensions.
  - No wildcard scope values.
- Monitoring semantics:
  - MONITORING does not produce APPROVE/DECLINE outcomes from monitoring rules.
  - MONITORING collects review/pattern matches; caller decision is carried separately.
- Manifest/publish contract (runtime consumption):
  - Required manifest fields: `schema_version`, `environment`, `region`, `country`, `artifact_type`, `ruleset_key`, `ruleset_version`, `artifact_uri`, `checksum`, `published_at`.
  - Runtime object layout target: `rulesets/{env}/{region}/{country}/{artifact_type}/manifest.json` and immutable `v{n}/ruleset.json`.

Docs to update with implementation:
- `README.md`
- `AGENTS.md`
- `docs/README.md`
- `docs/codemap.md`
- `openapi/openapi.yaml` (if API contract changes)
- Relevant ADR files in `docs/07-reference/`

## 4) Proposed Implementation Sequence (Next Session)

1. Finalize ADRs and manifest contract (`region`, `country`, `artifact_type`).
2. Introduce `CountryRuleContext` and country-aware loader/registry.
3. Add PN list runtime artifacts and card_id lookup stage.
4. Refactor evaluators to consume scoped candidate buckets (not global sorted rules).
5. Add startup full-preload + readiness gate.
6. Add country-isolated hot reload + structured alerts/metrics.
7. Expand unit/integration/load tests for ordering, country isolation, and failure semantics.

## 5) Guardrails

- Keep AUTH hot path free of S3 and DB I/O.
- Keep outbox durability semantics from ADR-0014 unless explicitly superseded.
- Do not add wildcard scope behavior.
- Do not introduce dead ruleset namespaces beyond locked artifact set.
