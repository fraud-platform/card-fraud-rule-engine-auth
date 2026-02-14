# ADR-0014: Auth-to-Monitoring Orchestration via Redis Streams Outbox

**Status:** Accepted  
**Date:** 2026-02-05  
**Implemented:** 2026-02-06  
**Owners:** Rule Engine Team

## Context

AUTH response latency must stay low while decision-event durability remains strict.  
Direct Kafka publishing on the AUTH request thread couples caller latency and availability to broker health.

## Decision

- Keep one rule engine implementation with two modes:
`AUTH_FIRST_MATCH` and `MONITORING_ALL_MATCH`.
- Keep ruleset resolution deterministic:
`CARD_AUTH` is used for AUTH and `CARD_MONITORING` for MONITORING.
- AUTH endpoint evaluates and appends `{transaction, authDecision}` to Redis Streams outbox.
- Background worker consumes the outbox, runs MONITORING evaluation, then publishes events to Kafka.
- Worker publishes two events per outbox record:
one AUTH decision event and one MONITORING decision event.

## Architecture

Auth request thread:

- `RuleEvaluator.evaluate(tx, AUTH_FIRST_MATCH)`
- `XADD fraud:outbox * payload=<tx + authDecision>`
- Return decision to caller

Monitoring worker:

- `XREADGROUP GROUP auth-monitoring-worker ... COUNT 50 BLOCK 2000`
- Publish AUTH decision event to Kafka
- `RuleEvaluator.evaluate(tx, MONITORING_ALL_MATCH)` using auth decision on transaction context
- Publish MONITORING decision event to Kafka
- `XACK` only after successful Kafka publishes

Direct MONITORING endpoint (unchanged path):

- Evaluates MONITORING directly
- Publishes MONITORING event synchronously on request path

## Redis Requirements

- `appendonly yes`
- `appendfsync everysec` (or `always` where required by policy)
- `replica-serve-stale-data no`
- `min-replicas-to-write 1`
- `min-replicas-max-lag 2`
- stream key: `fraud:outbox`
- consumer group: `auth-monitoring-worker`

## Failure Semantics

- Kafka outage: outbox backlog grows in Redis; worker retries.
- Worker crash: pending entries remain and are retried; no `XACK` before publish success.
- Redis/outbox unavailable during AUTH: request fails fast with HTTP `503` and `OUTBOX_UNAVAILABLE` (durability over blind success).
- Duplicate sends: mitigated with Kafka idempotent producer settings.

## Payload and Sizing

- Outbox payload contains transaction and AUTH decision.
- Typical payload target is small (about 1-2 KB/event).
- Backlog sizing example at 1k TPS and 60s buffer is on the order of tens to low hundreds of MB.

## Alternatives Considered

- Fire-and-forget Kafka on AUTH thread: rejected (possible message loss during broker issues).
- StatefulSet/PVC WAL-first pattern: rejected for this phase due operational complexity.
- Redis List: rejected in favor of Streams consumer-group semantics and visibility.

## Implications

- AUTH no longer publishes to Kafka directly.
- MONITORING processing for AUTH traffic is asynchronous via worker.
- Observability must track:
`redis.pending.entries`, `redis.oldest.pending.age`, worker publish failures, and AUTH outbox write failures.
