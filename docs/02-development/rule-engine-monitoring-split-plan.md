# Two-Service Split Execution Plan (AUTH + MONITORING)

Date: 2026-02-13
Status: Ready for separate execution session
Audience: Engineering owners for `card-fraud-rule-engine-auth`, `card-fraud-rule-engine-monitoring`, and `card-fraud-platform`

Runtime baseline for split:
- Quarkus `3.31.2`
- Java `25` (primary), Java `21` compatibility verified

## 0) Preflight decisions (lock before first code cut)

1. AUTH -> MONITORING handoff for approve flow
- Decision: **Kafka (Redpanda)** is canonical transport.
- Why: durable, replay-friendly, existing platform path, cleaner decoupling than Redis outbox for cross-service handoff.
- Rule: AUTH service publishes `authDecision` event; MONITORING service consumes and processes.

2. Direct decline flow contract
- Decision: caller invokes MONITORING endpoint directly on decline path.
- Rule: keep payload schema aligned with current monitoring contract and transaction-management expectations.

3. Split acceptance baseline profile
- Decision: use distributed Locust runs as acceptance source:
  - users: `50`, `100`, `200`
  - mode: `master + 3 workers`
  - duration: `2m`
  - source-of-truth: `rule-engine-distributed_stats.csv` aggregated row
- Rule: reject runs with worker heartbeat/spawn mismatch warnings.

4. Async durability toggles and comparability
- Decision: pin async mode explicitly per run and record it in run notes/metadata.
- Rule: no mixed/implicit defaults for acceptance comparisons.

5. Platform routing ownership
- Decision: explicit gateway path map in `card-fraud-platform`:
  - `/v1/evaluate/auth` -> `card-fraud-rule-engine-auth`
  - `/v1/evaluate/monitoring` -> `card-fraud-rule-engine-monitoring`
- Rule: preserve existing local port conventions unless an explicit migration change is approved.

6. Repo execution model for split
- Decision: **create two repos from the same baseline snapshot**; do not rename current repo in place.
- Rule:
  - keep current `card-fraud-rule-engine` as historical baseline/reference until split is stable
  - execute removals independently in each new repo
  - tag all three repos with `split-baseline-2026-02-13`

## 1) Objective

Split the current combined runtime into two deployable services:

- `card-fraud-rule-engine-auth` (latency-critical AUTH path)
- `card-fraud-rule-engine-monitoring` (monitoring/analytics path)

Primary goal:
- Isolate AUTH latency from monitoring-side workload and reduce operational coupling.

Secondary goals:
- Keep current decision/event contracts compatible.
- Accept short-term duplication to accelerate delivery and reduce migration risk.

## 2) Decision on duplication and ADRs

Short answer: yes, duplication is acceptable for phase 1.

Rules for duplication:
- Copy shared code into both repos initially (no shared library in split phase).
- Copy ADRs into both repos, preserving ADR numbers/titles/content.
- Add a small banner at top of copied ADRs indicating "mirrored from split baseline on 2026-02-13".
- During split phase, any ADR change must be applied to both repos in the same working day.

Rationale:
- Avoids blocking on shared-module design.
- Keeps split small and reversible.
- Makes performance attribution cleaner.

## 3) Target architecture

### 3.1 `card-fraud-rule-engine-auth`

Keep:
- `POST /v1/evaluate/auth`
- AUTH ruleset load/eval path
- AUTH fail-open semantics
- AUTH-specific async durability only if still required downstream
- Management/health endpoints required by operations

Remove:
- `POST /v1/evaluate/monitoring`
- Monitoring evaluator pipeline
- Monitoring-only worker/publisher code
- Monitoring-only route wiring/tests/docs

### 3.2 `card-fraud-rule-engine-monitoring`

Keep:
- `POST /v1/evaluate/monitoring`
- Monitoring evaluator and event pipeline
- Replay/simulate/management paths needed by monitoring workflows

Remove:
- AUTH endpoint logic that is not required for monitoring
- AUTH-only response optimization code

## 4) Repository bootstrap plan

## 4.1 Create repos

1. Create two new repos:
   - `card-fraud-rule-engine-auth`
   - `card-fraud-rule-engine-monitoring`
2. Seed both from the same baseline commit from current `card-fraud-rule-engine`.
3. Tag that baseline in all three repos:
   - `split-baseline-2026-02-13`

## 4.2 Mandatory initial file checks in both repos

- `AGENTS.md` exists and is canonical.
- `CLAUDE.md` is thin pointer to `AGENTS.md`.
- `README.md`, `docs/README.md`, `docs/codemap.md` updated for service scope.
- `openapi/openapi.yaml` matches service-specific endpoints.

## 5) Work breakdown (phased)

## Phase A: Hard split of endpoint ownership

In AUTH repo:
- Delete monitoring resource methods and router mappings.
- Delete monitoring evaluator/service wiring.
- Remove monitoring-specific tests.

In MONITORING repo:
- Delete AUTH endpoint methods and AUTH-only response DTO/writer optimizations.
- Keep monitoring event pipeline and management paths.

Exit criteria:
- AUTH repo serves only `/v1/evaluate/auth`.
- MONITORING repo serves only `/v1/evaluate/monitoring`.

## Phase B: Configuration and dependency trim

AUTH repo:
- Keep only required dependencies for AUTH latency path.
- Disable/remove monitoring toggles and dead config keys.

MONITORING repo:
- Keep dependencies needed for monitoring replay/publish path.
- Remove AUTH-only tuning flags not used by monitoring.

Exit criteria:
- No dead config keys for removed path.
- App starts cleanly with no "unused path" warnings.

## Phase C: Platform routing and compose

In `card-fraud-platform`:
- Add separate service definitions for AUTH and MONITORING.
- Route gateway paths:
  - `/v1/evaluate/auth` -> AUTH service
  - `/v1/evaluate/monitoring` -> MONITORING service
- Preserve existing local port conventions unless migration is explicitly approved.

Exit criteria:
- `platform-up -- --apps` starts both services healthy.
- Smoke requests to both paths succeed through gateway route map.

## Phase D: Contract protection

- Freeze event schema snapshots before split.
- Add contract tests for downstream consumers (transaction-management/intelligence).
- Keep lowercase path casing in all tests/docs.

Exit criteria:
- No consumer contract regressions.
- No path-casing regressions.

## Phase E: Performance re-baseline

AUTH:
- Run clean distributed baselines at 50/100/200 users (AUTH-only).
- Acceptance source: Locust CSV aggregated row.

MONITORING:
- Define monitoring-specific load profile and capture baseline (latency + queue depth + publish success).

Exit criteria:
- New AUTH baseline documented and compared to pre-split baseline.
- Monitoring pipeline baseline documented for capacity planning.

## 6) Detailed task checklist

### 6.1 Code and API

- Remove unwanted endpoint handlers.
- Remove unused DTOs and serializers.
- Remove dead workers and startup hooks.
- Update OpenAPI in each repo to single-path ownership.

### 6.2 Testing

- Unit tests: remove path-specific irrelevant suites per repo.
- Integration tests: keep only endpoint-specific tests.
- E2E tests: split scenario sets by service.
- Load tests: separate auth-only and monitoring-only scenarios.

### 6.3 Documentation

In each repo update:
- `README.md`
- `AGENTS.md`
- `docs/README.md`
- `docs/codemap.md`
- ADR index in `docs/07-reference/README.md`

### 6.4 Operations

- Health endpoint checks per service.
- Metrics endpoint ownership clarified.
- Alerting thresholds separated for AUTH and MONITORING.

## 7) ADR and docs synchronization model

During split phase:
- Keep ADR files duplicated in both repos.
- Add `docs/07-reference/mirror-map.md` in both repos listing mirrored ADR files and last sync date.

After split stabilizes:
- Choose one model:
  - Model 1: continue mirrored ADRs with strict sync rule.
  - Model 2: shared docs repo for ADR source-of-truth.

Recommendation:
- Use Model 1 initially for speed; reconsider after 2-3 stable releases.

## 8) Risks and mitigations

Risk: logic divergence between repos
- Mitigation: weekly diff check of known shared packages until deliberate divergence plan exists.

Risk: accidental contract drift
- Mitigation: contract tests + OpenAPI diff gate in CI.

Risk: routing confusion in platform
- Mitigation: explicit gateway path test script in platform smoke suite.

Risk: duplicated bug fixes not backported
- Mitigation: split-change checklist requires dual-repo patch for shared logic.

## 9) Acceptance criteria (must-pass)

Functional:
- AUTH and MONITORING requests served by separate repos/services.

Performance:
- AUTH baseline is re-established with clean reruns and compared against pre-split.

Reliability:
- No increase in failure rates under baseline load.

Governance:
- ADR mirrors present in both repos and mirror map updated.
- Mandatory docs updated in same change set per repo.

## 10) Execution order for your separate session

1. Create both repos from same baseline tag.
2. Hard split endpoints and wiring (Phase A).
3. Trim config/dependencies (Phase B).
4. Wire platform routing (Phase C).
5. Run unit/integration/load gates in both repos.
6. Update docs + ADR mirrors + mirror map.
7. Lock new baselines and open follow-up optimization thread.

## 11) Out of scope in split session

- Language migration (Go/Rust)
- Shared library extraction
- Framework upgrade planning (already completed in baseline to Quarkus `3.31.2`)

Keep these as separate tracks to preserve causality of latency changes.
