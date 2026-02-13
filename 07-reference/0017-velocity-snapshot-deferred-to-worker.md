# ADR-0017: Velocity Snapshot Deferred to Outbox Worker

**Status:** Accepted
**Date:** 2026-02-06
**Owners:** Rule Engine Team

## Context

The AUTH hot path previously captured a velocity snapshot asynchronously via `CompletableFuture.runAsync()` and mutated the `Decision` object after returning it to the caller. This created a data race: the response could be serialized to JSON while the async thread was setting the `velocitySnapshot` field, producing null/partial snapshots or a `ConcurrentModificationException`.

Additionally, the async velocity snapshot added unpredictable latency to the AUTH response and Redis connection pool pressure on the hot path.

## Decision

- **Remove** velocity snapshot capture from `RuleEvaluator.evaluate()` on the AUTH request thread
- **Defer** velocity snapshot capture to the `MonitoringOutboxWorker`
- The worker captures velocity snapshot on its own thread (not the AUTH hot path) and includes it in both AUTH and MONITORING Kafka decision events

### AUTH Response

The AUTH HTTP response no longer includes `velocity_snapshot`. This field will be `null` in the API response.

### Kafka Events

Both AUTH and MONITORING decision events published to Kafka by the outbox worker will include `velocity_snapshot` captured at worker processing time (typically within seconds of the AUTH evaluation).

## Rationale

- Eliminates the data race on the AUTH hot path
- Reduces AUTH latency by removing Redis reads from the request thread
- Velocity snapshot data is still available in Kafka events for downstream consumers (transaction-management)
- Worker thread has its own timing and connection pool, so Redis reads don't affect AUTH SLA

## Trade-offs

- Velocity snapshot in Kafka events reflects state at worker processing time, not exactly at AUTH evaluation time. Given the worker processes within seconds, this temporal gap is acceptable for fraud analytics.
- API consumers that previously relied on `velocity_snapshot` in the AUTH response must now consume from Kafka events instead.

## Consequences

- `RuleEvaluator` no longer calls `scheduleVelocitySnapshot()`
- `MonitoringOutboxWorker.processEntry()` captures velocity snapshot before Kafka publish
- Tests that asserted on `decision.getVelocitySnapshot()` from `RuleEvaluator.evaluate()` are updated
