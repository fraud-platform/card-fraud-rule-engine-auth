# Performance Findings Summary (AUTH-only)

**Date:** 2026-02-13

This document consolidates verified performance findings after the AUTH async-durability redesign, distributed load reruns, and JFR review.

---

## What we observed

- Single-request AUTH remains single-digit ms.
- Under sustained concurrent load on the current local topology, latency remains far above SLO.
- 2026-02-12 clean distributed reruns (AUTH-only):
  - `200 users, async OFF`: `p50 120`, `p95 280`, `p99 460`, `93,067 req`, `0 failures`
  - `200 users, async ON`: `p50 120`, `p95 290`, `p99 620`, `95,644 req`, `0 failures`
  - `100 users, async OFF`: `p50 69`, `p95 180`, `p99 280`, `96,400 req`, `0 failures`
  - `100 users, async ON`: `p50 60`, `p95 180`, `p99 300`, `103,151 req`, `0 failures`
  - `50 users, async OFF`: `p50 21`, `p95 57`, `p99 95`, `123,076 req`, `0 failures`
  - `50 users, async ON`: `p50 35`, `p95 88`, `p99 130`, `99,699 req`, `0 failures`
- 2026-02-12 scope-cache optimization reruns (AUTH-only, OFF) did not beat the existing best clean 50-user OFF baseline:
  - `lt-dist-scopecache-async-off-u50-rerun-20260212-192456`: `p50 36`, `p95 100`, `p99 190`, `72,275 req`, `0 failures`
  - `lt-dist-scopecache-nojfr-async-off-u50-20260212-194613`: `p50 43`, `p95 130`, `p99 240`, `60,174 req`, `0 failures`
- 2026-02-12 controlled reruns after environment stabilization:
  - `lt-dist-nextphase-async-off-poston-u50-20260212-211755` (OFF, clean): `p50 21`, `p95 54`, `p99 89`, `125,957 req`, `0 failures`
  - `lt-dist-nextphase-async-on-u50-w3-20260212-212352` (ON, 3 workers, clean): `p50 25`, `p95 69`, `p99 110`, `130,659 req`, `0 failures`
  - `lt-dist-nextphase-async-off-u50-w3-20260212-212939` (OFF, 3 workers, clean): `p50 26`, `p95 71`, `p99 110`, `131,676 req`, `0 failures`
- Bottom line: performance improves at lower concurrency, but SLO (`P50 < 10`, `P95 < 20`) is still not met.
- Measurement note:
  - for manual distributed runs (`master + workers`), `run-summary-*.json` can be incorrect; use per-run Locust CSV aggregated rows as the authoritative source.

---

## Root causes (current, most impactful)

### 1) Async outbox writer JSON serialization still contributes under load
JFR continues to show Jackson and outbox write activity when async durability is enabled.

Practical impact:
- AUTH request thread is decoupled from outbox writes, but async path CPU/GC pressure still impacts total node behavior.

### 2) Request parse + rule evaluation + velocity remain the request-thread floor
JFR execution samples continue to show `StreamingTransactionReader.readFrom`, `EvaluationResource.evaluateAuth`, and `RuleEvaluator.evaluate` on hot request paths.

Practical impact:
- This is now the direct request-side latency floor after removing synchronous durability work.

### 3) Local test topology and run quality strongly influence measured tails
Observed issues in this session:
- one fully invalid run due Docker engine outage (`ConnectionRefusedError`)
- partial distributed runs where Locust reported incomplete worker spawn/reporting.
- some distributed points showed long-tail outliers that disappeared on rerun.
- one accepted rerun emitted a worker CPU-threshold warning, indicating generator headroom should still be validated.
- late-night reruns confirmed that CPU-threshold warnings on workers can invert ON/OFF interpretation and must be treated as non-acceptance.

Practical impact:
- single-host runs are useful for trend and regression checks, but not final acceptance evidence.
- runs with worker/report anomalies should be excluded from acceptance metrics.

### 4) At 50 users, clean ON/OFF difference is currently small
When both modes are re-run under clean conditions (including `3-worker` comparison), ON and OFF are close on p50/p95/p99.

Practical impact:
- The major remaining issue is overall p95 floor (still far above `<20ms`), not a stable ON-vs-OFF gap at 50 users.
- Future analysis should focus on request-path parse/eval/velocity cost and infrastructure saturation effects, not only async mode toggles.

---

## What was optimized in latest pass

- AUTH evaluation context map creation was made lazy:
  - Avoid eager `transaction.toEvaluationContext()` allocation on AUTH path.
  - Materialize only for debug paths or non-compiled condition fallback.
- Measured delta versus previous 2026-02-10 baseline:
  - p50: `120 -> 63 ms` (`-47.5%`)
  - p95: `250 -> 120 ms` (`-52.0%`)
  - p99: `370 -> 160 ms` (`-56.8%`)
  - avg: `126.69 -> 66.65 ms` (`-47.4%`)
  - requests: `47,660 -> 88,144` (`+84.9%`)

### Incremental optimization applied on 2026-02-11 (validated)

- `AsyncOutboxDispatcher` was refactored from fixed-delay polling (`1 event / tick`) to a continuous worker loop.
- Burst draining was added (`MAX_DRAIN_BURST=64`) so async durability can consume queue backlog faster under sustained load.
- Retry semantics are unchanged: failed persist keeps a pending event and retries after backoff.
- Validation status:
  - async OFF continues to outperform async ON at 200 users.
  - latency reduction from this change exists versus some earlier ON/OFF runs, but SLO is still not met.

---

## JFR evidence (pre vs post)

- JFR files:
  - pre: `docs/04-testing/flight-20260210-1829.jfr`
  - post: `docs/04-testing/flight-20260210-1846-postfix.jfr`
- Notable event-count changes:
  - `jdk.ThreadPark`: `13,767 -> 9,296` (down)
  - `jdk.JavaMonitorWait`: `3,787 -> 855` (down)
  - `jdk.JavaMonitorEnter`: `150 -> 35` (down)
- Remaining dominant CPU signature:
  - Jackson serialization methods in outbox writer thread
  - request parse/eval on Vert.x event-loop threads

---

## Distributed + JFR Pair Findings (2026-02-10 Evening)

### 200-user distributed summary

- Best async OFF run:
  - `lt-dist-postfix-async-off-u200-20260210-203236`
  - `p50 86`, `p95 180`, `p99 310`, `avg 94.11`, `rps 1061.88`, `0 failures`
- Async ON remained worse and unstable at 200 users:
  - `lt-dist-postfix-async-on-u200-20260210-214225`: `p50 170`, `p95 390`, `p99 680`
  - `lt-dist-postfix-async-on-u200-rerun-20260210-215531`: `p50 110`, `p95 260`, `p99 410`
  - `lt-dist-postfix-async-on-u200-jfr-20260210-215913`: `p50 150`, `p95 470`, `p99 770`
- Async OFF JFR-coupled 200-user run also degraded vs best non-JFR OFF:
  - `lt-dist-postfix-async-off-u200-jfr-20260210-220821`: `p50 100`, `p95 280`, `p99 520`

### JFR ON vs OFF (postfix, 200-user recordings)

Compared files:
- ON: `docs/04-testing/flight-20260210-2158-postfix-async-on-200-jfr.jfr`
- OFF: `docs/04-testing/flight-20260210-2208-postfix-async-off-200-jfr.jfr`

Execution-sample pattern counts:
- `AsyncOutboxDispatcher.drainOnce`: `7` (ON) vs `0` (OFF)
- `RedisStreamsOutboxClient.append`: `16` (ON) vs `0` (OFF)
- `ObjectWriter.writeValueAsString`: `15` (ON) vs `0` (OFF)
- `RedisAPI.xadd`: `3` (ON) vs `0` (OFF)
- `StreamingTransactionReader.readFrom`: `72` (ON) vs `50` (OFF)
- `RuleEvaluator.evaluate`: `22` (ON) vs `8` (OFF)

GC comparison (from `jdk.GarbageCollection` event durations):
- ON: `count 65`, `avg 105.31 ms`, `p95 624 ms`, `max 860 ms`
- OFF: `count 49`, `avg 84.14 ms`, `p95 392 ms`, `max 477 ms`

Interpretation:
- Async durability ON increases background serialization/Redis stream activity and correlates with higher GC pause severity.
- Even with async durability OFF, parse/evaluation/velocity path still dominates request-side latency floor under high concurrency.
- `jdk.VirtualThread*` events are absent in these recordings, so this profile does not indicate virtual-thread scheduling overhead.

---

## Next actions

- Stabilize run quality first:
  - reject runs with worker heartbeat/spawn mismatches
  - reject outlier runs when immediate rerun under same setup gives materially lower tail
  - keep 2-3 clean reruns per load point.
- Treat `rule-engine-distributed_stats.csv` as acceptance source for distributed manual runs.
- Continue hot-path optimization:
  - request parsing and field extraction
  - rule evaluation and velocity hot path allocations.
- Keep async durability ON/OFF comparison in every matrix to isolate async tax.
- Use the runbook updates for Windows/Docker reliability:
  - hidden worker windows
  - Docker engine recovery workflow
  - distributed run failure criteria.

---

## Related docs

- Canonical plan:
  - [docs/04-testing/auth-only-slo-and-async-durability.md](auth-only-slo-and-async-durability.md)
- Engineering plan (PR1/PR2):
  - [docs/02-development/performance-tuning-plan.md](../02-development/performance-tuning-plan.md)
- JFR and baseline docs:
  - [docs/04-testing/load-testing-baseline.md](load-testing-baseline.md)
  - [docs/04-testing/jfr-profiling-guide.md](jfr-profiling-guide.md)
