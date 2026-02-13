# ADR-0018: AUTH Hot Path Must Not Block on Durability

**Status:** Accepted  
**Date:** 2026-02-09  
**Owners:** Rule Engine Team  

---

## Context

AUTH is latency-critical and must meet a strict SLO under scale.

The prior design appended a Redis Streams outbox record on the AUTH request thread. That couples AUTH latency and availability to:
- JSON serialization cost
- Redis client pool saturation
- Redis availability

Monitoring and downstream analytics/audit are important but must not degrade AUTH latency.

---

## Decision

- The AUTH request thread performs only:
  - request parse
  - ruleset lookup
  - rule evaluation
  - velocity checks/counter updates (Redis)
  - response

- The AUTH request thread MUST NOT:
  - write to Redis Streams outbox
  - publish to Kafka
  - run monitoring evaluation

- Async durability is provided by background components:
  - A fast in-memory enqueue on the request thread
  - A background writer that persists to a durable buffer (Redis Streams)
  - A background publisher that publishes to Kafka with ack and then `XACK`s

---

## Backpressure

If the in-memory queue is full:
- Drop the async event
- Increment metrics and emit sampled warnings
- Never block AUTH response

This is a deliberate tradeoff: AUTH decision availability/latency is the highest priority.

---

## Failure semantics

- Kafka outage: Redis Streams backlog grows; publisher retries.
- Redis outage (async pipeline): async pipeline errors are visible via metrics/logs, but AUTH can still respond.
- Crash window: if the process crashes after responding but before the background writer persists the event, the event may be lost. This is accepted for the AUTH SLO.

---

## Consequences

- AUTH SLO becomes primarily a function of evaluation + velocity latency.
- Downstream eventing/monitoring becomes eventually consistent.
- Observability must track async pipeline health (drops, lag, publish failures).

---

## Related

- Prior outbox ADR (superseded by this ADR for AUTH hot-path behavior):
  - [docs/07-reference/0014-auth-monitoring-redis-streams-outbox.md](0014-auth-monitoring-redis-streams-outbox.md)
- Retry correctness ADR:
  - [docs/07-reference/0019-redis-streams-pending-recovery-and-retries.md](0019-redis-streams-pending-recovery-and-retries.md)
