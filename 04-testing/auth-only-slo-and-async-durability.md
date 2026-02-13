# AUTH-only SLO and Async Durability Plan

**Date:** 2026-02-13  
**Status:** In progress, SLA not met after controlled 50-user reruns  

This is the canonical testing-focused plan to achieve **AUTH-only** performance targets while preserving async durability for downstream analytics/audit.

For the full engineering plan (PR1/PR2 breakdown, risks, validation), see:
- [docs/02-development/performance-tuning-plan.md](../02-development/performance-tuning-plan.md)

---

## Current Status (2026-02-12)

- Clean baseline run after rule-engine image rebuild:
  - `uv run lt-rule-engine --users=100 --spawn-rate=10 --run-time=2m --scenario baseline --headless --skip-seed --skip-teardown`
- Result snapshot:
  - Requests: `88,144`
  - Failures: `0`
  - p50: `63 ms`
  - p95: `120 ms`
  - p99: `160 ms`
  - avg: `66.65 ms`
  - RPS: `~810.9`
  - Locust warning: load-generator CPU exceeded 90%
  - Artifacts:
    - `C:/Users/kanna/github/card-fraud-e2e-load-testing/html-reports/run-summary-20260210-184613.json`
    - `docs/04-testing/flight-20260210-1846-postfix.jfr`
- Latest distributed reruns (master + 2 workers, 2026-02-12):
  - 200 users OFF: `p50 120`, `p95 280`, `p99 460`, `93,067 req`, `0 failures`
  - 200 users ON: `p50 120`, `p95 290`, `p99 620`, `95,644 req`, `0 failures`
  - 100 users OFF (clean rerun): `p50 69`, `p95 180`, `p99 280`, `96,400 req`, `0 failures`
  - 100 users ON: `p50 60`, `p95 180`, `p99 300`, `103,151 req`, `0 failures`
  - 50 users OFF (clean rerun): `p50 21`, `p95 57`, `p99 95`, `123,076 req`, `0 failures`
  - 50 users ON: `p50 35`, `p95 88`, `p99 130`, `99,699 req`, `0 failures`
- Additional controlled reruns (2026-02-12 late-night):
  - 50 users OFF control rerun (2 workers): `p50 21`, `p95 54`, `p99 89`, `125,957 req`, `0 failures`
  - 50 users ON (3 workers, clean): `p50 25`, `p95 69`, `p99 110`, `130,659 req`, `0 failures`
  - 50 users OFF (3 workers, clean): `p50 26`, `p95 71`, `p99 110`, `131,676 req`, `0 failures`
- Decision:
  - Current implementation still does not meet AUTH SLO (`P50 < 10 ms`, `P95 < 20 ms`).
  - Lower concurrency substantially improves latency, but `p95` remains above target even at 50 users.
  - With clean 3-worker comparison at 50 users, ON/OFF are very close; earlier large ON/OFF deltas were influenced by load-generator quality warnings.
  - For manual distributed runs, use Locust CSV aggregated rows as source-of-truth (run-summary JSON can be incorrect).
  - Latest matrix and findings:
    - `docs/04-testing/load-testing-baseline.md`
    - `docs/04-testing/performance-findings-summary.md`
    - `docs/04-testing/powershell-load-testing-runbook.md`

---

## Targets

### SLO (AUTH-only)
- **P50 < 10ms**
- **P95 < 20ms**

Assumptions for SLO measurement:
- Load is generated from the host (or dedicated load generator) to the service.
- Authentication/authorization is handled by API Gateway; rule-engine benchmarks run without in-process token validation.
- Monitoring is not part of the performance target.

---

## What stays synchronous on AUTH

AUTH request thread MUST do:
- Parse request
- Ruleset lookup
- Rule evaluation
- **Velocity checks and counter updates (Redis)**
- Return slim response

AUTH request thread MUST NOT do:
- Redis Streams outbox write
- Kafka publish
- Monitoring evaluation

Rationale: any blocking durability side-effect couples caller latency to Redis/Kafka health and causes queueing under load.

---

## Async durability pipeline (background)

### High-level
- AUTH responds immediately.
- Async pipeline buffers and publishes an event downstream.

### Durable buffer
- Use **Redis Streams** as the durable buffer between AUTH and Kafka.

### Kafka publish semantics
- Background worker publishes to Kafka **with ack** (wait for completion) and only then `XACK`s the stream entry.

### Retry correctness requirement
Redis Streams consumer groups do not automatically “retry” pending messages when you only read `XREADGROUP ... >`.

To guarantee retries:
- Implement **pending recovery** via `XAUTOCLAIM` (preferred) or `XPENDING` + claim logic.

---

## Backpressure / overload behavior

If the in-memory queue feeding the background writer is full:
- Drop async event
- Increment metrics + sampled warnings
- Never block AUTH response

This is an explicit tradeoff: AUTH decision availability and latency are highest priority.

---

## Data contract (downstream requirements)

Downstream requires:
- Entire transaction context
- AUTH decision
- AUTH evaluation results (matched rules, velocity results, engine metadata)

Implementation intent:
- Persist `{TransactionContext, Decision}` into Redis Streams (off-thread).
- Before Kafka publish, ensure the payload includes:
  - `Decision.transaction_context` populated from `TransactionContext.toEvaluationContext()`
  - `Decision.matched_rules`, `Decision.velocity_results`, ruleset metadata

---

## How to validate

### Prereqs
- Run infra/services via platform compose (apps profile) for k8s-like behavior.

### AUTH-only load test
Run the load-testing repo with AUTH-only tasks.

Important: ensure the run summary uses **real percentiles** from Locust, not derived from per-endpoint averages.

### Expected results
- AUTH latency improves materially once Redis Streams outbox append is removed from the AUTH request thread.
- Redis velocity becomes the next dominant cost (and is the new floor).

---

## References

- Existing outbox ADR (to be superseded/updated):
  - [docs/07-reference/0014-auth-monitoring-redis-streams-outbox.md](../07-reference/0014-auth-monitoring-redis-streams-outbox.md)
- New ADRs (created in PR1):
  - [docs/07-reference/0018-auth-hot-path-auth-only-async-durability.md](../07-reference/0018-auth-hot-path-auth-only-async-durability.md)
  - [docs/07-reference/0019-redis-streams-pending-recovery-and-retries.md](../07-reference/0019-redis-streams-pending-recovery-and-retries.md)
