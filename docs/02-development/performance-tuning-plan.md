# Performance Tuning Plan (AUTH-only <10ms)

**Date:** 2026-02-13  
**Status:** In progress, SLA still not met after controlled 50-user reruns  
**Primary goal:** Bring AUTH-only latency to **single-digit ms P50** and keep **P95 < 20ms** under scale (same-host load test → service).  

This document captures the full, finalized plan and the two implementation PRs:
- **PR1 (Docs consolidation + ADRs)**
- **PR2 (Code + load-testing harness fixes)**

---

## 0) Current Status Snapshot (2026-02-13)

### Latest clean baseline (after rule-engine image rebuild)
- Rebuild command:
  - `doppler run -- docker compose -f docker-compose.yml -f docker-compose.apps.yml -p card-fraud-platform up -d --build --force-recreate rule-engine`
- Baseline command:
  - `uv run lt-rule-engine --users=100 --spawn-rate=10 --run-time=2m --scenario baseline --headless --skip-seed --skip-teardown`
- Result:
  - Requests: `88,144`
  - Failures: `0`
  - Median (p50): `63 ms`
  - P95: `120 ms`
  - P99: `160 ms`
  - Avg: `66.65 ms`
  - RPS: `~810.9`
  - Locust warning: load generator CPU exceeded 90% during the run
  - Artifacts:
    - `C:/Users/kanna/github/card-fraud-e2e-load-testing/html-reports/run-summary-20260210-184613.json`
    - `docs/04-testing/flight-20260210-1846-postfix.jfr`
- Verdict:
  - **SLA NOT MET** (`P50 < 10 ms`, `P95 < 20 ms` not achieved)

### 2026-02-13 quick validation (Quarkus `3.31.2` + Java `25`)
- Runtime:
  - rule-engine rebuilt on Quarkus `3.31.2` with Java `25` on host
- Baseline command:
  - `uv run lt-run --service rule-engine --users=50 --spawn-rate=10 --run-time=2m --scenario baseline --headless`
- Result:
  - Requests: `80,682`
  - Failures: `0`
  - `p50 36 ms`, `p95 64 ms`, `p99 96 ms`, `avg 37.77 ms`, `rps 629.8`
  - Locust warning: load-generator CPU crossed 90%
  - Artifact: `C:/Users/kanna/github/card-fraud-e2e-load-testing/html-reports/run-summary-20260213-093622.json`
- Comparison to current best clean 50-user control:
  - Best clean reference: `lt-dist-nextphase-async-off-poston-u50-20260212-211755` (`p50 21`, `p95 54`, `p99 89`, `rps 1066.61`)
  - Quick validation is slower and lower-throughput.
- Interpretation:
  - Framework/runtime upgrade is now in place and validated functionally.
  - No immediate latency gain is confirmed from this single-process quick rerun.
  - Continue using distributed clean reruns for acceptance decisions.

### 2026-02-13 distributed apples-to-apples rerun (50 users, master + 3 workers)
- Run ID:
  - `lt-dist-java25-u50-w3-20260213-114023`
- Source:
  - `rule-engine-distributed_stats.csv` aggregated row
- Result:
  - `p50 26 ms`, `p95 69 ms`, `p99 110 ms`, `avg 30.89 ms`, `rps 1147.43`, `134,517 req`, `0 failures`
- Artifact:
  - `C:/Users/kanna/github/card-fraud-e2e-load-testing/html-reports/runs/lt-dist-java25-u50-w3-20260213-114023/locust/rule-engine-distributed_stats.csv`
- Comparison vs prior clean distributed reference (`lt-dist-nextphase-async-off-u50-w3-20260212-212939`):
  - Prior: `p50 26`, `p95 71`, `p99 110`, `avg 31.21`, `rps 1093.03`
  - New: `p50 26`, `p95 69`, `p99 110`, `avg 30.89`, `rps 1147.43`
  - Verdict: neutral-to-slight improvement in distributed apples-to-apples conditions; SLO still not met.

### Distributed load matrix (master + 2 workers, AUTH-only)
- Repo:
  - `C:/Users/kanna/github/card-fraud-e2e-load-testing`
- Latest clean 2026-02-12 results (CSV aggregated rows):
  - Async OFF 200 users:
    - `lt-dist-lazyctx-lazytimestamp-async-off-u200-20260212-055446`
    - `p50 120 ms`, `p95 280 ms`, `p99 460 ms`, `93,067 req`, `0 failures`, `rps 787.04`
  - Async ON 200 users:
    - `lt-dist-lazyctx-lazytimestamp-async-on-u200-20260212-060144`
    - `p50 120 ms`, `p95 290 ms`, `p99 620 ms`, `95,644 req`, `0 failures`, `rps 802.81`
  - Async OFF 100 users (clean rerun):
    - `lt-dist-lazyctx-lazytimestamp-async-off-u100-rerun-20260212-064654`
    - `p50 69 ms`, `p95 180 ms`, `p99 280 ms`, `96,400 req`, `0 failures`, `rps 812.07`
  - Async ON 100 users:
    - `lt-dist-lazyctx-lazytimestamp-async-on-u100-20260212-061959`
    - `p50 60 ms`, `p95 180 ms`, `p99 300 ms`, `103,151 req`, `0 failures`, `rps 867.67`
  - Async OFF 50 users (clean rerun):
    - `lt-dist-lazyctx-lazytimestamp-async-off-u50-rerun-20260212-065122`
    - `p50 21 ms`, `p95 57 ms`, `p99 95 ms`, `123,076 req`, `0 failures`, `rps 1042.35`
  - Async ON 50 users:
    - `lt-dist-lazyctx-lazytimestamp-async-on-u50-20260212-063137`
    - `p50 35 ms`, `p95 88 ms`, `p99 130 ms`, `99,699 req`, `0 failures`, `rps 848.00`
- Notes:
  - Manual distributed runs can produce incorrect `run-summary-*.json`; acceptance metrics should use `rule-engine-distributed_stats.csv` aggregated rows.
  - Some early runs had worker/report mismatch warnings and were kept as diagnostics only.
  - A first `u50 async OFF` run (`...061403`) was a long-tail outlier and was replaced by the clean rerun above.
- 2026-02-12 late rerun note (scope-cache optimization pass):
  - Implemented bounded scope-tuple cache in `Ruleset.getApplicableRules(...)`.
  - Added `JAVA_JFR_OPTS=` to `testing/compose-auth-no-async.override.yml` to explicitly disable startup JFR during baseline runs.
  - Clean OFF reruns after this change were:
    - `lt-dist-scopecache-async-off-u50-rerun-20260212-192456`: `p50 36`, `p95 100`, `p99 190`, `72,275 req`, `0 failures`, `rps 608.73`
    - `lt-dist-scopecache-nojfr-async-off-u50-20260212-194613`: `p50 43`, `p95 130`, `p99 240`, `60,174 req`, `0 failures`, `rps 504.53`
  - Verdict: did not outperform existing best clean OFF baseline (`21/57/95` at that point).
- 2026-02-12 controlled reruns after environment stabilization:
  - OFF control rerun (2 workers):
    - `lt-dist-nextphase-async-off-poston-u50-20260212-211755`
    - `p50 21 ms`, `p95 54 ms`, `p99 89 ms`, `125,957 req`, `0 failures`, `rps 1066.61`
  - ON/OFF clean comparison (3 workers):
    - `lt-dist-nextphase-async-on-u50-w3-20260212-212352`
    - `p50 25 ms`, `p95 69 ms`, `p99 110 ms`, `130,659 req`, `0 failures`, `rps 1099.44`
    - `lt-dist-nextphase-async-off-u50-w3-20260212-212939`
    - `p50 26 ms`, `p95 71 ms`, `p99 110 ms`, `131,676 req`, `0 failures`, `rps 1093.03`
  - Interpretation:
    - At 50 users, ON vs OFF is near-equal in clean runs.
    - Earlier large ON/OFF gaps were strongly influenced by worker CPU-threshold warnings and run-quality variance.
- Artifacts:
  - Runs:
    - `C:/Users/kanna/github/card-fraud-e2e-load-testing/html-reports/runs/`
  - JFR ON:
    - `docs/04-testing/flight-20260210-2158-postfix-async-on-200-jfr.jfr`
  - JFR OFF:
    - `docs/04-testing/flight-20260210-2208-postfix-async-off-200-jfr.jfr`
  - Session runbook:
    - `docs/04-testing/powershell-load-testing-runbook.md`

### Completed vs pending (performance plan)
- Completed:
  - PR1 docs and ADRs completed and linked (`0018`, `0019`).
  - AUTH request thread decoupled from direct outbox append.
  - Async durability path implemented (enqueue, Redis Streams persistence, Kafka publish+ack, `XACK`).
  - Pending recovery implemented (`XAUTOCLAIM`) with pending metrics.
  - Gateway-auth model adopted; JWT validation removed from rule-engine hot path.
  - `card-fraud-rule-engine` load-testing compose path cleanup completed (2026-02-10):
    - removed residual JWT/Auth0 env wiring from `docker-compose.yml`
    - normalized health check to `/v1/evaluate/health`
  - Load-testing harness updates completed:
    - real Locust percentile API in summary
    - deterministic AUTH-only traffic mix
    - per-run metadata and artifact path persistence
  - Distributed load reruns completed (master + 2 workers) to reduce single-process Locust bottleneck.
  - AUTH lazy evaluation-context optimization completed (2026-02-10):
    - avoid eager `transaction.toEvaluationContext()` allocation on AUTH fast path
    - materialize map only for debug or uncompiled condition fallback paths
  - Async durability dispatcher throughput optimization completed (2026-02-11):
    - replaced fixed-delay single-item drain with a continuous worker loop
    - added burst draining (`MAX_DRAIN_BURST=64`) to keep up under sustained enqueue rates
    - preserved pending-retry semantics and existing config knobs (`enabled`, `queue-capacity`, `poll-interval-ms`)
- Pending:
  - Achieve SLO under scale (`P50 < 10 ms`, `P95 < 20 ms`).
  - Complete root-cause analysis for current latency floor and long-tail spikes.
  - Validate load generator bottlenecks under container CPU caps and/or multi-host load generators.
  - Reconcile environment drift between earlier clean run (`lt-dist-lazyctx-lazytimestamp-async-off-u50-rerun-20260212-065122`) and latest controlled reruns before attributing deltas to specific code changes.
  - Continue validating async dispatcher optimization with stable reruns that have no worker-report anomalies.
  - Prioritize and execute next optimization wave after outbox decoupling.
  - Complete remaining cross-repo compose cleanup for gateway-auth model:
    - `card-fraud-platform`: remove residual JWT/Auth0 env wiring for rule-engine load/perf paths
    - verify `card-fraud-e2e-load-testing` and platform load paths do not inject JWT/Auth0 for rule-engine requests

---

## 1) Problem Summary

### Observed
- Single request AUTH can be single-digit ms.
- Under load, latency rises dramatically (p50 tens of ms up to ~80–110ms depending on run mode/resources).

### Key root cause (historical vs current)
Historical root cause (before PR2): AUTH request path performed blocking Redis Streams outbox append with JSON serialization.

Current state (2026-02-10):
- AUTH request thread no longer performs direct outbox append.
- Request thread enqueues async durability work and returns slim AUTH response.
- Remaining latency floor/tail is now attributed to a mix of:
  - request parse + rule evaluation + velocity checks
  - async outbox writer JSON serialization cost (Jackson on `{transaction, authDecision}`)
  - Redis/client contention under concurrency
  - load generator saturation/local test topology effects

### Constraints
- Velocity is **always-on** for real transactions: the engine must check “N txns within M minutes” style rules and update counters synchronously via Redis.
- Authentication/authorization is handled at API Gateway; token verification is removed from rule-engine hot path.
- Monitoring flow is **not** required for the immediate performance target and can be disabled/removed from the hot path for now.

---

## 2) Locked Decisions

### D1: Scope of the SLO
- **SLO is for AUTH evaluation only**.
- Monitoring is out-of-scope for the performance target; we can reintroduce it later as a separate service.

### D2: AUTH request thread responsibilities
AUTH request thread should do only:
- Parse request
- Ruleset lookup
- Rule evaluation
- Velocity checks + counter updates (Redis)
- Return a slim response

AUTH request thread must **NOT** do:
- Redis Streams outbox write
- Kafka publish
- Any other durability/analytics side-effects

### D3: Async durability pipeline
We will implement:
- **AUTH: no outbox, no Kafka**
- **Background: durable buffer in Redis Streams** → **Kafka publish with ack** → **XACK**

### D4: Overflow / backpressure behavior
If the in-memory queue feeding the background outbox writer is full:
- **Drop the async event** (caller must still get decision)
- Record metrics + sample logs

### D5: Data contract to downstream
Downstream requires:
- Entire transaction context
- AUTH decision
- AUTH evaluation results (matched rules, velocity results, engine metadata)

We will ensure the event published downstream includes:
- TransactionContext data (from the original request)
- Decision data (including `matched_rules`, `velocity_results`)

---

## 3) Target Architecture (Option A)

### Flow A: Caller approves/authorizes → AUTH → async to downstream
1. Caller → `POST /v1/evaluate/auth`
2. Rule-engine AUTH evaluates and responds immediately.
3. Async pipeline persists the full payload to Redis Streams outbox (durable buffer).
4. Kafka publisher worker reads outbox, publishes to Kafka with ack, then XACKs.
5. Transaction-management consumes Kafka event and persists/audits.
6. (Future) Monitoring service can consume the same AUTH event (or a separate topic) and run monitoring rules.

### Flow B: Caller declines → monitoring analytics
- Out of scope for this perf plan. Documented as a future integration path:
  - Caller → Monitoring/analytics endpoint/service → Kafka → Transaction-management

### Rationale
- This isolates the AUTH SLO from Kafka health and from outbox serialization cost.
- Redis Streams acts as a durable buffer for Kafka outages without blocking AUTH.

---

## 4) Correctness and Reliability Semantics

### “Durable across Kafka outage”
- Yes: Redis Streams backlog grows while Kafka is unavailable.
- Worker retries until publish succeeds.

### “Durable across process crash”
- There is an accepted crash window if the process dies after returning 200 but before the background writer persists to Redis Streams.
- This is explicitly accepted because AUTH decision latency is the top priority.

### Redis Streams retry correctness (must-fix)
Current implementation risk: reading only `XREADGROUP ... >` does not guarantee retry of pending messages.
To make “no ack means retry” actually true:
- Implement **pending recovery** using `XAUTOCLAIM` (preferred) or `XPENDING` + claim.
- Track and publish metrics for pending/lag.

---

## 5) Load Testing Reality Check

Status as of 2026-02-10:
- Run summary percentile calculation now uses Locust percentile APIs.
- AUTH-only traffic mix is explicitly enforced by harness configuration.
- Per-run metadata and Locust artifacts are persisted.
- Latest measured baseline: `p50 63ms / p95 120ms / p99 160ms` (still above SLO target).

Remaining caveat:
- Local single-node Locust generator hit >90% CPU in baseline runs, so final acceptance baselines should be re-run with distributed load generation.

---

## 6) PR1 — Docs + ADRs + Consolidation

### PR1 Goals
- Create a single canonical, discoverable source of truth for the AUTH SLO plan.
- Encode decisions in ADRs using the existing numbering convention.
- Reduce docs churn by consolidating session notes into durable summaries.

### PR1 Changes (card-fraud-rule-engine)
1. Create canonical plan doc:
   - `docs/04-testing/auth-only-slo-and-async-durability.md`
   - Must match the locked decisions D1–D5.

2. Create ADRs:
   - `docs/07-reference/0018-auth-hot-path-auth-only-async-durability.md`
     - AUTH hot path must not block on outbox/Kafka.
     - Async durability; drop-on-overflow.
   - `docs/07-reference/0019-redis-streams-pending-recovery-and-retries.md`
     - Require `XAUTOCLAIM`/pending recovery to guarantee retries.

3. Update indices:
   - `docs/07-reference/README.md` add ADRs 0018/0019.
   - `docs/README.md` add canonical plan doc and ADRs.
   - `docs/codemap.md` update architecture statement to match Option A.
   - `docs/04-testing/README.md` include canonical plan in published files.

4. Consolidate performance notes:
   - Create `docs/04-testing/performance-findings-summary.md` summarizing:
     - JFR findings
     - What was tried
     - What was rejected
     - Why Option A was chosen

5. Cleanup guidance:
   - Remove or demote per-session “session-*” / “NEXT-SESSION-*” docs from curated lists.
   - Keep durable summaries instead.

### PR1 Changes (card-fraud-e2e-load-testing)
- Add a pointer doc (short):
  - `docs/04-testing/rule-engine-auth-only-perf.md`
  - How to run AUTH-only and where the canonical plan lives.

---

## 7) PR2 — Implementation (Code + Harness)

### PR2 Goals
- Make AUTH request thread free of outbox and Kafka.
- Implement background durable pipeline: queue → Redis Streams → Kafka publish/ack → XACK.
- Add pending recovery so failures truly retry.
- Fix load-testing percentiles and lock AUTH-only runs.

### PR2.A Rule-engine: remove outbox from AUTH request thread
Edit:
- `src/main/java/com/fraud/engine/resource/EvaluationResource.java`

Change:
- For AUTH, do not call `OutboxFacade.append(...)` in the request thread.

### PR2.B Rule-engine: add async dispatcher + workers
Add new components (names flexible but keep intent clear):

1) **Fast-path enqueue**
- `AuthDecisionAsyncDispatcher`
  - Method: `enqueue(TransactionContext tx, Decision authDecision)`
  - Uses bounded `ArrayBlockingQueue`.
  - If full: drop + metrics.
  - No JSON, no Redis, no Kafka in this method.

2) **Background outbox writer**
- `AuthOutboxWriterWorker`
  - Drains the queue.
  - Writes to Redis Streams.
  - Initial implementation may serialize off-thread (acceptable v1).
  - Prefer reducing/avoiding JSON where feasible.

3) **Background Kafka publisher**
- `AuthKafkaPublisherWorker`
  - `XREADGROUP` consumes.
  - Before publish: ensure the event includes full transaction context + decision results.
    - If publishing `DecisionEventCreate` via `DecisionPublisher`, populate:
      - `decision.setTransactionContext(tx.toEvaluationContext())`
  - Publish using `DecisionPublisher.publishDecisionAwait()`.
  - On success: `XACK`.

4) **Pending recovery**
- Implement `XAUTOCLAIM` loop (or XPENDING+claim) to reclaim stale pending messages and retry.

5) **Config knobs**
- Ensure each worker can be enabled/disabled with config.
- Ensure consumer name is unique per instance (don’t hardcode `worker-1` for all pods).

### PR2.C Rule-engine: disable monitoring for perf
- Use config flag to disable the existing monitoring worker.
- Ensure perf mode does not run monitoring evaluation or its worker.

### PR2.D Observability
Add metrics/timers (names flexible; must be present):
- enqueue_ok, enqueue_dropped
- queue_depth
- outbox_xadd_success/fail
- kafka_publish_success/fail
- kafka_publish_latency
- pending_reclaimed_count
- outbox_lag_seconds (or equivalent)

### PR2.E Load-testing harness fixes
Repo: card-fraud-e2e-load-testing

1) Fix run-summary percentiles
- `src/utilities/reporting.py`
  - Use Locust real percentiles instead of repeating averages.

2) Lock AUTH-only mix
- Ensure the wrapper can run AUTH-only deterministically.
- Do not rely on tags via the wrapper; prefer explicit weights/config.

3) Persist run artifacts + metadata
- Save per-run locust CSV/HTML and include:
  - users, spawn rate, runtime
  - auth strategy (`api-gateway`)
  - traffic mix
  - container cpu/mem limits

---

## 8) Validation Checklist

### Build/test gates (rule-engine)
- `uv run lint`
- `uv run test-unit`

Current verification results (2026-02-10):
- `uv run lint` -> FAIL (`program not found: lint`)
- `uv run test-unit` -> PASS (`Tests run: 501, Failures: 0, Errors: 0, Skipped: 3`)
- `uv run test-integration` -> PASS (`Tests run: 27, Failures: 0, Errors: 0, Skipped: 0`)

### Load test verification
- Run rule-engine in Docker compose apps profile (k8s-like).
- Run AUTH-only load test.
- Confirm:
  - AUTH p50/p95 meet targets using real percentiles. (**Current status: FAIL**)
  - AUTH response correctness.
  - Redis velocity correctness (counters increment as expected).
  - Kafka pipeline continues publishing in the background.
  - When Kafka is down:
    - Redis Streams backlog grows
    - After Kafka returns, publisher drains backlog
  - Pending recovery: a forced worker crash does not permanently strand messages.

---

## 9) Risks and Mitigations

### R1: Velocity becomes the dominant latency floor
- Expected: once outbox is removed, Redis velocity checks may dominate.
- Mitigation: pool sizing, Lua usage, bounded timeouts, avoid event-loop blocking.

### R2: Event loss under extreme overload
- Accepted by decision D4 (drop on overflow).
- Mitigation: metrics + alerting; tune queue capacity and worker throughput.

### R3: Pending messages stuck forever (if pending recovery is not implemented)
- Must implement ADR-0019 requirements.

### R4: Documentation drift
- PR1 updates ADRs + codemap + docs indices.

---

## 10) References (key code paths)

- AUTH endpoint:
  - `src/main/java/com/fraud/engine/resource/EvaluationResource.java`
- Redis Streams outbox client:
  - `src/main/java/com/fraud/engine/outbox/RedisStreamsOutboxClient.java`
- Monitoring worker (to disable for perf):
  - `src/main/java/com/fraud/engine/outbox/MonitoringOutboxWorker.java`
- Velocity service (always-on):
  - `src/main/java/com/fraud/engine/velocity/VelocityService.java`
- Decision model (matched rules, velocity results):
  - `src/main/java/com/fraud/engine/domain/Decision.java`
- Kafka publisher + schema:
  - `src/main/java/com/fraud/engine/kafka/DecisionPublisher.java`
  - `src/main/java/com/fraud/engine/kafka/DecisionEventCreate.java`
- Load test task (AUTH):
  - `card-fraud-e2e-load-testing/src/tasksets/rule_engine/auth.py`
- Load test reporting (percentiles fix):
  - `card-fraud-e2e-load-testing/src/utilities/reporting.py`

